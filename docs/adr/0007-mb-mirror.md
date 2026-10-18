# ADR 0007: Our Own MusicBrainz Mirror (PlanetScale Postgres + Cloudflare Compute)

- **Status:** Accepted
- **Date:** 2026-10-13

## Context

Library matching needs fast, local MusicBrainz lookups (artist / release /
recording + fuzzy search) without depending on `musicbrainz.org` at request
time (rate limits, availability). Core MusicBrainz data is CC0; the Cover Art
Archive (CAA) has its own terms. All relational data lives in PlanetScale
Postgres via Hyperdrive (ADR 0001/0002); interactive traffic stays
serverless; batch runs in Containers.

## Decision

1. **One Postgres database `nntunev2-mb`** holds a curated mirror subset:
   `mb_artist`, `mb_release`, `mb_recording` (+ `mb_import_state` for
   replication bookkeeping). Full 30+ table MusicBrainz schema is out of
   scope; the mirror stores what lookup + search need.
2. **Initial import** runs as a Cloudflare Container batch job (`mbdump`
   dumps → Postgres `COPY`). It is idempotent and resumable by dump file.
3. **Hourly replication** applies MusicBrainz replication packets via a
   scheduled Container/Workflow. SLO: **replication lag < 2 h** (packet
   applied within 2 h of publication); lag is recorded per packet.
4. **Read API** lives in `workers/mb` (Rust `workers-rs`): MBID lookup for
   artist / release / recording plus trigram search, over Hyperdrive, with
   KV / Cache API caching. See `workers/mb/README.md`.
5. **Cover art** is cached in R2 bucket `nntunev2-art` (derived renditions
   per ADR 0003); the mirror stores only CAA URLs/hashes, never hotlinks
   at request time without cache.
6. **Terms:** core data is CC0 (no attribution required, credit given
   anyway); commercial use notes the MetaBrainz support tier. CAA images
   follow upstream licence terms per image.

## Consequences

- `migrations/0001_mb_mirror.sql` is the source of truth for the mirror
  schema, including `pg_trgm` indexes for search.
- `workers/mb` documents its lookup + search p95 methodology; numbers land
  in its README once staging measures exist.
- Replication lag is a monitored SLO (< 2 h); missed packets page, they
  never silently skip.
