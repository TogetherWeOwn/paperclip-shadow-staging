#!/usr/bin/env bash
# Hourly replication packets -> nntunev2-mb. SLO: lag < 2 h.
# Usage: DATABASE_URL=<url> PACKET_SEQ=<n> PACKET_URL=<url> ./replicate.sh
# Never marks a packet applied until its deletes/upserts actually land.
# mb_import_state.last_packet is seeded forward-only by import.sh (DUMP_SEQ,
# only when it advances the cursor) and advanced by the future apply step;
# last_applied_at/lag_seconds are written only by the apply step, which must
# validate PACKET_SEQ as an integer, require PACKET_SEQ = last_packet + 1,
# and set lag_seconds from the packet's publication timestamp.
set -euo pipefail

: "${DATABASE_URL:?set DATABASE_URL via secret store}"
: "${PACKET_SEQ:?set PACKET_SEQ (replication packet number)}"
: "${PACKET_URL:?set PACKET_URL (packet download URL)}"

if [[ ! "$PACKET_SEQ" =~ ^[0-9]+$ ]]; then
  echo "replicate: refusing non-integer PACKET_SEQ '$PACKET_SEQ'" >&2
  exit 1
fi

started="$(date +%s)"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

echo "replicate: fetching packet $PACKET_SEQ"
curl -sSfL -o "$tmp/packet.tar.gz" "$PACKET_URL"

last_packet="$(psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -tAX -c "SELECT last_packet FROM mb_import_state WHERE id = 1;")"
if [[ ! "$last_packet" =~ ^[0-9]+$ ]]; then
  echo "replicate: unexpected last_packet '$last_packet' in mb_import_state" >&2
  exit 1
fi
if [[ "$PACKET_SEQ" -ne $((last_packet + 1)) ]]; then
  echo "replicate: refusing packet $PACKET_SEQ (expected $((last_packet + 1)); gaps and replays are never skipped silently)" >&2
  exit 1
fi

# Apply step (unpack + deletes/upserts + state update with lag_seconds) lands
# in the full-importer slice. Until then, exit non-zero WITHOUT touching
# mb_import_state so the mirror never reports a healthy lag it did not earn.
ended="$(date +%s)"
echo "replicate: packet $PACKET_SEQ downloaded in $((ended - started))s but NOT applied (apply step pending); leaving mb_import_state at $last_packet" >&2
exit 2
