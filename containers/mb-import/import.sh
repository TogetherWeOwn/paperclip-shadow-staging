#!/usr/bin/env bash
# mbdump dumps -> Postgres COPY into nntunev2-mb (idempotent, resumable).
# Usage: DATABASE_URL=<url> [DUMP_SEQ=<n>] ./import.sh <dump-dir>
# Never echo $DATABASE_URL; pass it only via env/secret store.
# DUMP_SEQ (optional): replication sequence the dump corresponds to. When
# set, mb_import_state.last_packet is seeded forward-only (only when
# DUMP_SEQ > current last_packet) so the hourly replicate.sh gate
# (PACKET_SEQ = last_packet + 1) accepts the first real packet. The seed
# never touches last_applied_at/lag_seconds (apply-step columns) and an
# older dump never rewinds the cursor. When unset, state is left untouched
# and the operator must seed it before replication (see README).
#
# Input contract (curated TSVs, NOT raw MusicBrainz dumps):
#   <dump-dir>/mbdump-artist.tsv     mb_artist    (mbid, name, sort_name, type, country, updated_at)
#   <dump-dir>/mbdump-release.tsv    mb_release   (mbid, artist_mbid, title, release_type, year, caa_url, updated_at)
#   <dump-dir>/mbdump-recording.tsv  mb_recording (mbid, release_mbid, title, track_no, duration_ms, updated_at)
# Produce them from an official mbdump/ extract (mbdump/artist, mbdump/release,
# mbdump/recording with the full upstream column layout) by projecting the
# curated columns in dump order, e.g. with a small ETL step that SELECTs the
# columns above and writes tab-separated rows. Missing input is fatal: a
# silent skip would report "import: done" with zero rows loaded.
set -euo pipefail

if [[ "${1:-}" == "--help" || $# -lt 1 ]]; then
  cat <<'USAGE'
Usage: DATABASE_URL=<postgres-url> ./import.sh <dump-dir>

Imports curated mbdump TSV dumps (artist, release, recording) with COPY ...
FROM STDIN, staging per file so a rerun resumes cleanly. See the header
comment for the curated TSV contract and how to project it from official
mbdump/ extracts.
Requires: psql on PATH, DATABASE_URL in env (never as argv).
USAGE
  exit 0
fi

dump_dir="$1"
: "${DATABASE_URL:?set DATABASE_URL via secret store, never on the command line}"

for table in artist release recording; do
  tsv="$dump_dir/mbdump-$table.tsv"
  if [[ ! -f "$tsv" ]]; then
    echo "import: missing $tsv (expected curated TSV; see header comment)" >&2
    exit 1
  fi
  case "$table" in
    artist)
      columns="mbid, name, sort_name, \"type\", country, updated_at"
      upsert="name = EXCLUDED.name, sort_name = EXCLUDED.sort_name, \"type\" = EXCLUDED.\"type\", country = EXCLUDED.country, updated_at = EXCLUDED.updated_at"
      ;;
    release)
      columns="mbid, artist_mbid, title, release_type, year, caa_url, updated_at"
      upsert="artist_mbid = EXCLUDED.artist_mbid, title = EXCLUDED.title, release_type = EXCLUDED.release_type, year = EXCLUDED.year, caa_url = EXCLUDED.caa_url, updated_at = EXCLUDED.updated_at"
      ;;
    recording)
      columns="mbid, release_mbid, title, track_no, duration_ms, updated_at"
      upsert="release_mbid = EXCLUDED.release_mbid, title = EXCLUDED.title, track_no = EXCLUDED.track_no, duration_ms = EXCLUDED.duration_ms, updated_at = EXCLUDED.updated_at"
      ;;
  esac
  echo "import: loading $table from $tsv"
  # Single psql session + single transaction: the TEMP stage table is
  # session-scoped, so create, COPY and upsert must share one connection.
  # The WHERE guard makes reruns move rows forward only: an older dump
  # never rolls back a row that replication (or a newer dump) moved ahead.
  psql "$DATABASE_URL" -v ON_ERROR_STOP=1 <<SQL
BEGIN;
CREATE TEMP TABLE stage (LIKE mb_${table}) ON COMMIT DROP;
\copy stage ($columns) FROM '$tsv' WITH (FORMAT text)
INSERT INTO mb_${table} ($columns) SELECT $columns FROM stage
ON CONFLICT (mbid) DO UPDATE SET $upsert
WHERE mb_${table}.updated_at < EXCLUDED.updated_at;
COMMIT;
SQL
done

# Record the dump's replication sequence so replicate.sh accepts the first
# real packet. Forward-only seed: advances last_packet only when
# DUMP_SEQ > current last_packet, and never touches last_applied_at /
# lag_seconds (those are written only by the replicate apply step). An
# older-dump rerun (DUMP_SEQ <= last_packet) warns and leaves state
# untouched so the cursor never rewinds. Unset DUMP_SEQ leaves state
# untouched (fresh DBs stay at the migration seed 0); the operator then
# seeds last_packet before replication.
if [[ -n "${DUMP_SEQ:-}" ]]; then
  if [[ ! "$DUMP_SEQ" =~ ^[0-9]+$ ]]; then
    echo "import: refusing non-integer DUMP_SEQ '$DUMP_SEQ'" >&2
    exit 1
  fi
  current_last_packet="$(psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -tAX -c "SELECT last_packet FROM mb_import_state WHERE id = 1;")"
  if [[ ! "$current_last_packet" =~ ^[0-9]+$ ]]; then
    echo "import: unexpected last_packet '$current_last_packet' in mb_import_state" >&2
    exit 1
  fi
  if (( 10#$DUMP_SEQ <= 10#$current_last_packet )); then
    echo "import: DUMP_SEQ=$DUMP_SEQ <= current last_packet=$current_last_packet; leaving state untouched (older dump never rewinds the replication cursor)" >&2
  else
    psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -c "UPDATE mb_import_state SET last_packet = $DUMP_SEQ, updated_at = now() WHERE id = 1 AND last_packet < $DUMP_SEQ;"
    echo "import: seeded mb_import_state.last_packet=$DUMP_SEQ"
  fi
else
  echo "import: DUMP_SEQ unset; leaving mb_import_state untouched (seed last_packet before running replicate.sh)" >&2
fi

echo "import: done"
