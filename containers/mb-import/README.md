# mb-import — dump import + hourly replication (batch only)

Container image for the two batch jobs behind `nntunev2-mb`
(ADR 0007). Interactive traffic never runs here.

## Jobs

| Job | Trigger | Script | SLO |
|---|---|---|---|
| Initial import | manual Container run | `import.sh <dump-dir>` (curated `mbdump-<table>.tsv`; missing input is fatal; optional `DUMP_SEQ=<n>` seeds `mb_import_state.last_packet` forward-only) | reruns are idempotent and move rows and the replication cursor forward only (`WHERE updated_at < EXCLUDED.updated_at`; `DUMP_SEQ` seeds `last_packet` only when it advances the cursor, never touches `last_applied_at`/`lag_seconds`, so an older dump never rolls back newer rows or rewinds replication); seed `last_packet` via `DUMP_SEQ` (or manually) before replication or `replicate.sh` keeps refusing packets |
| Replication | hourly schedule (Container / Workflow cron) | `replicate.sh` with `PACKET_SEQ` + `PACKET_URL` | **lag < 2 h** via `mb_import_state.lag_seconds`; state is written only when a packet is actually applied, packets must arrive in sequence, and the pending apply step exits non-zero without touching state |

## Secrets

`DATABASE_URL` comes from the secret store (GitHub Actions secrets /
Cloudflare / `~/secure-drop`) — never committed, never logged. Scripts
read it from env only.

## Rollback

Import and replication are additive upserts; rollback is "stop the job,
keep serving the previous packet" (`mb_import_state.last_packet` shows
the last good one). No destructive migrations in this path.
