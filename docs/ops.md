# NNTune v2 operations

Provisioned resource metadata for staging + prod, as of 2026-10-13.
**Never commit tokens, passwords, database URLs, or personal login identities.**
Secret values live in GitHub Actions secrets, Cloudflare, and the host's secure
credential storage. Resource IDs below are non-credential binding metadata;
the full account ID stays in `CLOUDFLARE_ACCOUNT_ID`, not this public document.
The `gitleaks` gate scans credentials but is not a personal-data policy check.

Every UNDO block is a rollback reference only. **No deletion, credential revocation,
resource mutation, or spend increase is authorized by this documentation update.**
An authorized executor must satisfy the applicable approval/retention gates first.

## Cloudflare

- Account: owner account (short prefix `209cf7dd`).
- Workers Paid + R2 Paid entitlements: confirmed by the host executor on
  2026-10-13; not independently billing-verified by the operator MCP token.

### R2 buckets (created 2026-10-13)

The provisioned layout is **one bucket per concern per environment**, not one
shared bucket. Object key prefixes describe cache scope *within* those buckets;
they do not replace the environment boundary. Worker configs and cache/MusicBrainz
ADRs must use the exact names below. There is no bucket named `nntunev2-art`.
Alignment is **not yet complete** on the sibling branches. Known integration
prerequisites identified across the provisioning review rounds:

| Owning PR | Required reconciliation |
|---|---|
| [#2](https://github.com/TogetherWeOwn/nntunev2/pull/2), cache ADR | Physical audio/art buckets are separate per environment; prefixes live inside them. |
| [#4](https://github.com/TogetherWeOwn/nntunev2/pull/4), MB docs/example | Replace nonexistent `nntunev2-art` with the appropriate art bucket below. |
| [#14](https://github.com/TogetherWeOwn/nntunev2/pull/14), scaffold | Replace placeholders only when activating the correct consumer bindings. |
| [#8](https://github.com/TogetherWeOwn/nntunev2/pull/8), stream | `workers/stream/wrangler.toml` uses `nntune-audio-cache` without environment sections; bind `AUDIO_CACHE` to `nntunev2-audio-staging` / `nntunev2-audio-prod`. |
| [#10](https://github.com/TogetherWeOwn/nntunev2/pull/10), ingest | Both producer and consumer in `workers/ingest/wrangler.toml.example` use `nntune-ingest-jobs`; use `nntunev2-ingest-staging` / `nntunev2-ingest-prod`. |
| [#11](https://github.com/TogetherWeOwn/nntunev2/pull/11), E2E | Supply the two pending Access client secrets before enabling the staging URL; see the Access section. |

Their owners must coordinate these fixes at the next permitted review round and
recheck actual bindings before deployment. This runbook does not change those
branches, certify a deploy, or choose where the cache ADR's `tmp/` scratch prefix
will live. Archive buckets are not implicitly scratch storage.

| Bucket | Env | Intended consumer |
|---|---|---|
| `nntunev2-audio-staging` | staging | stream Worker audio cache |
| `nntunev2-audio-prod` | prod | stream Worker audio cache |
| `nntunev2-art-staging` | staging | MusicBrainz Worker artwork cache |
| `nntunev2-art-prod` | prod | MusicBrainz Worker artwork cache |
| `nntunev2-archive-staging` | staging | reserved archive capacity; no Worker consumer configured |
| `nntunev2-archive-prod` | prod | reserved archive capacity; no Worker consumer configured |

The archive buckets were requested at provisioning time. They are not evidence
of an implemented archival pipeline and must not be bound to a Worker by default.
Do not create unsuffixed replacement buckets or delete these resources to reconcile
an example config; align the examples with this inventory instead.

UNDO (decommissioning reference, not an instruction to execute):
`DELETE /accounts/<acct>/r2/buckets/<name>`, one per bucket, only after authorized
consumer removal and data-retention checks. Never delete cached/archive data as
part of a documentation fix.

### Queues (created 2026-10-13)

| Queue | ID | Env |
|---|---|---|
| `nntunev2-ingest-staging` | `c9e6afdea0ca487c8d20f799a052b045` | staging |
| `nntunev2-ingest-prod` | `2bf7e1a0edd347c9aada2afbc0c24ae5` | prod |

UNDO: API `DELETE /accounts/<acct>/queues/<queue_id>` after authorized
consumer removal and pending-message checks.

### KV namespaces (created 2026-10-13)

| Namespace | ID | Env |
|---|---|---|
| `nntunev2-config-staging` | `1d4f21508a214ebfa8ff7b594989d6f6` | staging |
| `nntunev2-config-prod` | `9664ceed71464521bb6baae2d9374006` | prod |

UNDO: API `DELETE /accounts/<acct>/storage/kv/namespaces/<id>` after authorized
consumer removal and data-retention checks.

### DNS (zone `nntune.com`, id `97e268d5c1d540d42545ed8ab386b9c4`)

- `v2-staging.nntune.com` → `AAAA 100::`, proxied, TTL auto.
  Record ID `97670fbad3e38106c28f71d1df89175e`.
  Placeholder address (`100::` is reserved discard space). The staging deploy
  owner must remove the placeholder when claiming the hostname through a Workers
  custom domain. Provisioning does not establish that the application is deployed.
  v1 `staging.nntune.com` is untouched.
- Prod hostname: not created yet — decided at launch.

UNDO: API `DELETE /zones/<zone>/dns_records/<record_id>` for this placeholder
only; preserve the v1 hostname and any later Worker-owned record.

### Cloudflare Access (staging)

- App: `NNTune v2 staging (nntunev2-staging)`, self-hosted.
- App ID: `785bf815-f579-4768-a1d2-4de7ce19d086`.
- Domain: `v2-staging.nntune.com`; session duration `24h`.
- Owner OTP via IdP `a290d6fa-9235-4ce3-921f-0c9a67916c20`.
  Owner email remains private. Allow policy ID:
  `c2b44297-bab4-4117-a486-57c9421d6a73`.
- Agent QA service-token policy (`non_identity`):
  `3333d7dd-3c14-4b54-8cd2-abc2f4a827f6`, referencing existing service token
  `efe71168-f5e9-4f42-83bf-340473e76e01` (ID only, not credentials).
  Reused at provisioning; no existing key was rotated.
- Created by the host executor; app metadata and both policy types independently
  GET-verified on 2026-10-13. This is configuration verification, not an end-to-end
  login or staging application smoke test.
- **E2E wiring is pending:** [PR #11](https://github.com/TogetherWeOwn/nntunev2/pull/11)
  consumes `CF_ACCESS_CLIENT_ID` and `CF_ACCESS_CLIENT_SECRET`. Neither name is
  present in the repository-secret inventory checked on 2026-10-13. Referencing
  the QA token's resource ID above does not provide its client credentials.
  Before enabling `STAGING_BASE_URL` for that workflow, its owner must arrange
  authorized secure injection and verify both credentials are available to the
  job. Do not bypass Access, publish values, or rotate the shared token for this
  docs correction; credential distribution remains a separate gated operation.

UNDO: delete only this Access app during authorized decommissioning. Do not delete
or rotate the shared QA service token, and never remove the gate from a live app.

### CI API token + GitHub secrets

- Account-owned token `nntunev2-ci`, created fresh by the host executor.
- Account-scoped Edit/Write groups: Workers Scripts, Workers R2 Storage, Queues,
  Workers KV Storage, Hyperdrive. Workers Routes is scoped to `nntune.com` only.
  No D1 or Pages permissions.
- Host executor verified the account-token metadata as `active` with exactly
  those six groups. `/user/tokens/verify` is not the verification path used for
  this account-owned token. Operator MCP did not independently recheck token IAM.
- Repo secrets `CLOUDFLARE_API_TOKEN` + `CLOUDFLARE_ACCOUNT_ID` set on 2026-10-13
  at `18:46:25Z`; secret-name/update-time metadata independently re-listed.
  No secret value was read for this documentation update.

UNDO: revoke only token `nntunev2-ci` and remove its two repo secrets during
authorized decommissioning, after removing dependent deploy workflows.

## PlanetScale Postgres

The host executor's **2026-10-13 ~19:40Z consolidation receipt supersedes** the
original separate staging branch and the earlier PS-10/PS-40 allocations.
Sizing, billing, branch deletion, and SQL privilege tests below are host-reported,
not independently checked against PlanetScale by this documentation update.
Existing TWO databases were not touched.

- Organization: `togetherweown`; region: AWS `us-east-1`; Postgres `18.6` as
  recorded at initial provisioning.
- `nntunev2` / `main`: shared **PS-5 single-node** cluster. Staging now uses the
  PostgreSQL database **`nntunev2_staging`** on this branch, not a separate branch.
- The separate PlanetScale `staging` branch was deleted by the host executor.
  The host reports it was empty (zero tables) and required no data migration;
  this update did not independently inventory schema objects. The latest receipt records
  that removed PS-DEV branch as $5/month, correcting the earlier $0 statement.
- `nntunev2-mb` / `main`: separate MusicBrainz cluster, now reported as $5/month
  compute. The latest receipt does not specify its final SKU/replica count;
  do not carry forward the earlier PS-10 CPU/RAM/HA claims as current facts.
- Monthly cluster compute: **$10** ($5 app main, including staging, + $5 MB).
  Metered storage, backups, and egress are additional; $10 is not an all-in bill.
- The ~100 GB MB import remains a capacity target, not already-imported data.
  Initial storage was gp3 autoscale 10 GB–4 TB; verify current storage, connection
  allowance, and import performance on the reduced allocation before importing.
- **Launch remains gated:** prod will get its own clean PostgreSQL database on
  the main cluster, with resize/split assessed then. The current prod Hyperdrive
  still targets `postgres`; it is not evidence that the clean launch database
  has been created or approved for migration. Do not enable the production app
  binding or write application data to this current `postgres` target. Before
  launch use, the authorized workflow must create the clean database, apply and
  re-test its grants/isolation, and verify the prod config is repointed to it.

### Database roles and migrator wiring

The latest host receipt reports database-level app isolation: staging roles
cannot CONNECT to the prod database and prod roles cannot CONNECT to staging;
negative cross-connect tests returned `permission denied`. It also reports
runtime = CRUD without DDL, read-only = SELECT only, and migrator owns schema
`public`. These are **host-tested app-role properties**, not fresh SQL tests by
this documentation update, nor evidence of separate compute/failure domains.

- Staging uses new runtime/migrator roles for `nntunev2_staging` on `main`.
  The old staging-branch role names and URL-file inventory are superseded;
  use the authorized secure wiring, not credentials from the deleted branch.
  Exact replacement role names were not included in the receipt, and this
  update does not attest to old credential revocation or secure-store retirement.
- Repo secret `PLANETSCALE_MIGRATOR_URL_STAGING` was updated to the new migrator
  URL. GitHub name/update-time metadata was independently re-listed:
  **2026-10-13 `19:37:40Z`**. No secret value was read.
- **Production migrator secret intentionally not set.** Its deployment remains
  deferred to the gated production workflow. This is not a missing-credentials
  blocker and does not authorize a production migration or creation of the
  clean launch database.
- The migration owner must preserve and re-test the role matrix as schemas and
  tables are added and whenever the clean launch database is created, including
  default privileges, runtime DDL denial, read-only
  write denial, and bidirectional cross-database CONNECT denial. The earlier
  seven-role `select 1` probe predates consolidation and is not current proof.
- MB migrator/runtime/read-only roles were provisioned separately. The latest
  app-isolation receipt does not prove MB read-only enforcement; verify MB grants
  before application use. Never copy database URLs into this repo, issues, or logs.

### Hyperdrive bindings

| Config | ID / GitHub variable | Current PostgreSQL database | Intended binding |
|---|---|---|---|
| `nntunev2-staging` | `61c87403f119430bbc3a7f571df47002` / `HYPERDRIVE_ID_STAGING` | `nntunev2_staging` on app `main` | staging app, new runtime role (host-reported) |
| `nntunev2-prod` | `d38a229748f6452bb417c6d33d277a8d` / `HYPERDRIVE_ID_PROD` | `postgres` on app `main` | reserved prod app; clean launch DB deferred |
| `nntunev2-mb` | `1c6460d5112448888031973c87f671bc` / `HYPERDRIVE_ID_MB` | `postgres` on MB `main` | shared read-oriented MB mirror |

All three configs independently GET-resolved on 2026-10-13 after consolidation.
IDs are unchanged and match the repo variables set at `18:59:44Z`. Staging's
config was modified at `19:37:25Z`; its database is `nntunev2_staging`. Prod and MB
metadata retain their original `18:58:55Z` and `18:58:57Z` modification times. Fresh
metadata confirms app staging/prod share an origin host but use different origin
users and databases. A metadata GET is not an ongoing SQL connectivity or
privilege test; no hostnames, usernames, or credentials need publishing here.

There are **three** configs, not separate MB staging/prod configs. The MB origin
uses its read-only role per the original host receipt, subject to the MB grant
check above. The MB import uses its migrator role, not this read-oriented binding.
Staging and prod MB reads share one MB config/cluster: load, cache behavior, and
outages are coupled. The import competes for that same MB connection/compute
allowance even though it uses a separate role.

All three configs still report caching enabled and `origin_connection_limit = 60`.
The two app pools now share one PS-5 single-node cluster, alongside direct
migrator/admin connections; they do **not** have independent branch allowances.
Before deploy/import, the owning lanes must validate the combined connection
budget and cache freshness against the actual origin limits. Database CONNECT
isolation does not isolate CPU, connections, storage/I/O, maintenance, or outages, and the
app single-node allocation must not be described as highly available.

UNDO: consolidation is not reversed by reusing the deleted branch's URLs or by
blindly restoring the old PS-40 resize command. The authorized host executor's
consolidation receipt records per-step rollback; consult it with current data,
backup/retention requirements, credential-version fences, and spend authority.
No resize, split, role change, branch recreation, deletion, or credential rotation
is authorized here. Decommissioning would require consumer removal and the
applicable data-retention gate before deleting configs, roles, or databases.

## Environments matrix

Binding names are chosen in Worker configs; resource names must match this table.

| Concern / intended consumer | staging | prod |
|---|---|---|
| R2 audio / stream Worker | `nntunev2-audio-staging` | `nntunev2-audio-prod` |
| R2 artwork / MB Worker | `nntunev2-art-staging` | `nntunev2-art-prod` |
| R2 archive / reserved, no consumer | `nntunev2-archive-staging` | `nntunev2-archive-prod` |
| Ingest Queue | `nntunev2-ingest-staging` | `nntunev2-ingest-prod` |
| Config KV | `nntunev2-config-staging` | `nntunev2-config-prod` |
| Hostname | `v2-staging.nntune.com` (+ Access; deployment pending) | TBD at launch |
| App Hyperdrive variable | `HYPERDRIVE_ID_STAGING` | `HYPERDRIVE_ID_PROD` |
| App PlanetScale branch / PostgreSQL database | `nntunev2` / `main` / `nntunev2_staging` | same `main` cluster / currently `postgres`; clean launch DB deferred |
| MB Hyperdrive variable | `HYPERDRIVE_ID_MB` (shared mirror) | `HYPERDRIVE_ID_MB` (shared mirror) |
| Migration secret | `PLANETSCALE_MIGRATOR_URL_STAGING` | intentionally deferred to gated workflow |
