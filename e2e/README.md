# NNTune v2 — E2E + staging smoke harness

Playwright suite covering the venture slice on **staging**: signup → BYOP
wizard (synthetic NNTP endpoint) → NZB ingest → playback with Range seeks →
usage meter → plan-limit enforcement. Plus a fast synthetic smoke
(`health.spec.ts`) that doubles as the post-deploy monitor.

Public repo: **secret names only, never values.** Values live in GitHub
Actions secrets (CI) or shell exports (local).

## Activation progression

1. **Pre-deploy (now):** `STAGING_BASE_URL` is unset. Every spec skips with a
   notice. PRs and `main` stay green; the `e2e-lint` CI job still typechecks
   and lists the specs so the harness cannot rot silently.
2. **Activation hold:** keep the Actions secret `STAGING_BASE_URL` unset until
   deployment exists and the authorized Operator provides a value-free delivery
   receipt for the existing QA Access pair through an approved secure source and
   repository-scoped contract. An Access policy or token resource ID is not
   delivery of `CF_ACCESS_CLIENT_ID` and `CF_ACCESS_CLIENT_SECRET`. Provisioning
   alone does not authorize distributing credentials. Name-only availability
   must then be rechecked; names and a receipt do not prove authentication.
   NNTP and QA-auth prerequisites remain separate and must also be verified.
3. **Staging live:** after the prerequisites are met, setting `STAGING_BASE_URL`
   activates fail-closed checks. QA must verify the deployed head with Access
   intact. Production promotion still requires exact-head staging evidence and
   the deployment lane's promotion gate; neither is established by this harness.
4. **Contract drift:** a renamed `data-testid` or reshaped JSON body fails
   with the contract key named. Update app + `helpers/contract.ts` together.

## Contract drift (current app, 2026-10-14)

`origin/main` now ships the SvelteKit app (PR #12), so the harness is
checked against its real contract for the first time. The smoke stays green
on the current app; the items below are future contract, documented here so
the activation checklist is accurate:

- `GET /api/health` returns exactly `{ok:true}`
  (`apps/web/src/routes/api/health/+server.ts`, pinned by
  `apps/web/tests/smoke.spec.ts` `toEqual({ok:true})`). `health.spec.ts`
  requires `ok === true` and asserts `version` only when the app ships it.
- `GET /api/ready` does not exist yet (staging answers 404). The smoke
  tolerates 404 as "not yet implemented" and pins the 200/503 + Retry-After
  shape once the route lands.
- `apps/web/src` has no `data-testid` hooks yet. The app-shell smoke accepts
  `data-testid="app-root"` when present and otherwise falls back to the
  landing's `NNTune` heading; signup/BYOP/library/player/meter hooks
  (`helpers/contract.ts` `TESTIDS`) and `/signup`'s real form, the BYOP
  wizard, ingest/library/stream/usage endpoints arrive with the venture
  slices that own them. The journey specs (`signup-byop`, `ingest-play-meter`)
  therefore remain red until those slices land — that failure is the signal,
  not noise.

## Run locally

```sh
cd e2e
npm ci
npx playwright install chromium
STAGING_BASE_URL=https://staging.example \
  CF_ACCESS_CLIENT_ID='<from ~/secure-drop>' \
  CF_ACCESS_CLIENT_SECRET='<from ~/secure-drop>' \
  SYNTHETIC_NNTP_HOST='<synthetic fixture host>' \
  SYNTHETIC_NNTP_PORT='563' \
  SYNTHETIC_NNTP_USER='<test user>' \
  SYNTHETIC_NNTP_PASS='<from ~/secure-drop>' \
  npm run e2e:staging
```

Smoke only: `npm run e2e:smoke`. Validate without staging: `npm run typecheck`,
`npm run test:unit`, and `npm run e2e:list`.

If `NODE_ENV=production` is exported in your shell, install with
`npm install --include=dev` — otherwise npm silently omits the dev
dependencies this harness needs.

## Environment

| Name | Required | Purpose |
|---|---|---|
| `STAGING_BASE_URL` | yes (post-deploy) | `https://` staging origin. Unset → skip with notice. |
| `CF_ACCESS_CLIENT_ID` / `CF_ACCESS_CLIENT_SECRET` | whenever staging is configured | QA service-token pair. Both absent or either absent → fail closed before requests. |
| `QA_AUTH_TOKEN` | optional | Bearer for `POST /api/test-accounts` (staging-only seam). Absent → UI signup fallback. |
| `SYNTHETIC_NNTP_HOST` / `_PORT` / `_USER` / `_TLS` | for BYOP spec | Hosted fixture server or test provider (defaults: `synthetic-nntp`, `563`, `e2e`, TLS on). |
| `SYNTHETIC_NNTP_PASS` | for BYOP spec | No default — fail closed when missing. |

How the suite uses them:

- Configured staging requires both Access values before any request:
  `playwright.config.ts` validates the URL and pair at startup. Browser pages
  attach them ONLY to the staging origin via an origin-checked
  `context.route` (`applyAccountToPage` + `isStagingOrigin`): cross-origin
  subresources (fonts, analytics, stream/store URLs) never receive the
  service token or session bearer, and staging 302 redirects to another
  origin are followed WITHOUT the headers (no-redirect fetch + fulfill, so
  the follow-up request re-enters the scope check clean). API clients attach
  them per request through `apiGet`/`apiPost` (`helpers/accounts.ts`), which
  fetch with `maxRedirects: 0`: a staging 302 to another origin is never
  followed with credentials — the foreign origin receives zero requests and
  the 3xx fails by name (status + location, values never logged). Any raw
  `request.*` / `page.request.*` / `context.request.*` call
  (`get`/`post`/`put`/`patch`/`delete`/`head`/`fetch`) is banned in live
  specs — a headers-conditioned `get`/`post` pin is bypassable by nested-paren
  stream URLs and `fetch`.
  Both missing or either
  missing fails closed;
  offline checks remain usable with no staging URL and no Access pair. An Access wall (wall status + Access markers, including
  302s to the Access login) fails closed with a remediation message instead
  of masquerading as an app failure; plain app 4xx responses pass through.
- Test-account sessions minted by the seam travel as
  `Authorization: Bearer <session>` (contract owned by the auth card —
  `helpers/accounts.ts` names it; cookie sessions would update the helper +
  specs together).
- Test accounts are throwaway (`e2e+<stamp>@example.test`); the API seam is
  tried first, a fully-implemented UI signup second (each journey file signs
  up its own identity — Playwright isolates module state per file, so there
  is no cross-file account sharing). Once `QA_AUTH_TOKEN` is set the seam is
  required infrastructure: transport errors, non-2xx and non-JSON mint
  responses throw instead of collapsing into a silent skip, and API-driven
  steps (`requireApiAccount`) refuse to run anonymously. The identity that
  ingests always completes the BYOP wizard first (shared
  `completeByopWizard` helper), because the ingest worker probes through the
  user's provider connection. The over-limit check needs the seam to support
  `{plan:"overlimit"}` (metering card); when the capped account's library is
  empty the harness ingests the fixture as that account, so no pre-seeded
  track is required. On CI an unavailable over-limit seam fails instead of
  skipping, so plan-limit enforcement can never pass unexercised.

## CI

- `.github/workflows/e2e-staging.yml` — full suite on `push` to `main`,
  manual dispatch, and a 6-hour synthetic schedule. The deployment lane must
  sequence execution after staging deploy; a push alone is not deploy proof.
  Missing `STAGING_BASE_URL` → step-level skip with notice (pre-deploy).
  Both jobs require the Access pair in preflight before activating tests;
  configured staging never skips for missing credentials. Failure artifacts
  are kept 7 days.
- `e2e-lint` inside `ci.yml` (part of `ci-ok`) — `npm ci`, `tsc --noEmit`,
  helper/workflow self-tests, and `playwright test --list`. Runs on every PR
  with no staging needed. Offline tests execute both checked-in preflights
  and the aggregate gate with dummy inputs; failures, cancellations and skips
  of required jobs make `ci-ok` red.
- **Prod promotion gate (required integration):** the deployment lane must
  require the `e2e-staging` result on the deployed SHA and block promotion on
  failure. Wiring and live enforcement are still acceptance prerequisites,
  not a verified result of this PR.

## Evidence

On failure CI sanitizes then uploads `test-results/` only (7 days, junit).
Raw traces and screenshots are disabled: tracing records request
headers/bodies and screenshots can expose account/provider information. CI
uses the junit reporter only — the html reporter embeds step fill values
(including the BYOP password) as a base64 zip in
`playwright-report/index.html`, so it is never published. Sanitization is
still required with traces off: Playwright 1.55 writes
`test-results/**/error-context.md` (an ARIA snapshot rendering filled input
values, including the BYOP password) — the workflow deletes
error-context.md plus the whole `playwright-report/` dir before upload, and
offline self-tests run a real failing fill under the CI reporter config,
apply the exact checked-in sanitize blocks, and assert the marker password
is absent from every uploaded file including base64-decoded payloads. Do not
enable traces/screenshots or the html reporter for credential-bearing runs
without a verified redaction path. A QA PASS verdict cites the green
`e2e-staging` run URL + deployed head SHA; NEEDS WORK cites the failing
spec + step.
