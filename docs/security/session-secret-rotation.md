# Session-Secret Rotation (F-HARD-01 item 3)

Owner: CISO · Status: normative runbook (the HTTP slice verifies
`verify_session_dual` against this procedure; deviations need a new CISO
decision with expiry).

## 0. Goal

The session HMAC secret (`SESSION_SECRET_BASE64`) cannot rotate by
replacement: swapping the secret in one deploy invalidates every live
session at once, with no dual-accept window. This runbook makes rotation
routine: **two secrets during a bounded window, `created_at`-bounded
expiry of the old secret, single-secret steady state.** No downtime, no
mass logout, no step that widens the signing scope.

Routine rotation here is **key aging, not incident response**: accepting
the previous secret during the window does NOT contain a secret exposure
(anyone holding the old secret still mints valid sessions until it is
removed). A suspected or confirmed `SESSION_SECRET` exposure follows the
compromise path in §6 — revoke all rows in `sessions`, rotate, and end
the window immediately — never routine rotation alone.

## 1. Secrets (scope is fixed — this runbook never broadens it)

| Secret | Lifetime | Purpose |
|---|---|---|
| `SESSION_SECRET_BASE64` | permanent | Primary HMAC key: mints and verifies. |
| `SESSION_SECRET_PREVIOUS_BASE64` | rotation window only | Verifies tokens minted before cutover. Never mints. Deleted at window end. |

Rules:

- Exactly one previous secret, ever. No lists, no version chains.
- The previous secret is verify-only: `issue_session` and
  `rotate_session` always sign with the primary. Code path:
  `session::SessionKeys::rotation(primary, previous)` threaded through
  `verify_session_dual`, `verify_stored_session` and `rotate_session`
  (steady state is `SessionKeys::single(primary)`).
- An unset previous secret is `None`, never an empty slice: every
  signing/verification key shorter than 32 bytes (`MIN_SECRET_LEN`)
  fails closed with `invalid session`, so a misconfigured empty secret
  can neither mint nor verify.
- Both failures map to the same generic `invalid session`; there is no
  oracle for which secret matched.
- Secrets live only in Cloudflare Worker secrets (`wrangler secret put`)
  per environment. Never in repo, logs, or comments.

## 2. Why the window is bounded by `created_at`

Every token carries an immutable `created_at`, and `verify_session`
rejects anything with `now >= created_at + MAX_SESSION_SECS` (one day)
— including rotated tokens, whose expiry clamps to the same cap. So the
previous secret is useless to an attacker (and unnecessary for users)
once every token it could have signed has aged out:

```text
window_end = cutover_time + MAX_SESSION_SECS (86_400) + CLOCK_SKEW_SECS (60)
```

After `window_end`, deleting `SESSION_SECRET_PREVIOUS_BASE64` logs out
nobody: any token still presented would already fail the `created_at`
bound under either secret.

## 3. Procedure

1. Generate unpadded base64url (256 bits, 43 chars, decodes via
   `nntune_api::b64::decode`): `openssl rand 32 | basenc --base64url | tr -d '='`
   on the operator machine. Do not reuse a KEK, password, or any other secret.
2. Stage the current primary as previous:
   `wrangler secret put SESSION_SECRET_PREVIOUS_BASE64` (paste current
   primary value), then `wrangler secret put SESSION_SECRET_BASE64`
   (paste the new value). Staging first, bake ≥24h, then prod. Never
   both at once.
3. Deploy the Worker. From cutover, new sessions sign with the primary;
   pre-cutover sessions verify via the previous secret through
   `verify_session_dual`. Confirm: fresh login works, pre-cutover cookie
   still authenticates (one synthetic check each — never a real user
   session).
4. Wait until `window_end` (§2). No action needed during the wait; the
   bound is enforced by token verification, not by a sweeper.
5. Delete the previous secret (`wrangler secret delete
   SESSION_SECRET_PREVIOUS_BASE64`), deploy, confirm the Worker starts
   with no previous configured. Steady state is single-secret again.
6. Record the rotation (date, environments, cutover time, operator) in
   the audit log. Stragglers presenting pre-cutover tokens after the
   window re-authenticate via magic link — expected, not an incident.

## 4. What the HTTP slice MUST enforce

- Verification during a window uses
  `verify_stored_session(&SessionKeys::rotation(primary, previous), …)`
  against the current `sessions` row (dual-signature check first, then
  row/counter/revocation — never signature-only). Rotation of the
  secret never bypasses the row check, the counter, or revocation.
- Refresh uses `rotate_session` with the same keys: it verifies through
  the dual path and re-signs with the primary, migrating pre-cutover
  sessions onto the new secret.
- The Worker builds `SessionKeys` from env as: previous = `Some` ONLY
  when `SESSION_SECRET_PREVIOUS_BASE64` is set AND a rotation is
  recorded; unset means `SessionKeys::single(primary)`. A set-but-short
  previous fails every verification closed (code-enforced).
- The Worker MUST fail closed when `SESSION_SECRET_PREVIOUS_BASE64` is
  set outside a recorded rotation (unexpected second secret = alert).
- `Set-Cookie` emission is unchanged (`__Host-nntune-session`, `Path=/`,
  `HttpOnly; Secure; SameSite=Lax`).

## 5. Review

Next review: 2027-04-14 or after the first real rotation, whichever is
earlier. Revisit the window arithmetic if `MAX_SESSION_SECS` changes.

## 6. Compromise procedure (secret exposure — NOT routine rotation)

A dual-accept window does NOT contain an exposure: anyone holding the old
secret mints valid sessions until it is removed. On suspected or confirmed
`SESSION_SECRET*` exposure, do NOT run §§2–4 and call it contained:

1. Provision a fresh primary (unpadded base64url, 43 chars, decodes via
   `nntune_api::b64::decode`: `openssl rand 32 | basenc --base64url | tr -d '='`
   in the operator store; `wrangler secret put SESSION_SECRET_BASE64`),
   one environment at a time, staging first.
2. Deploy with `SessionKeys::single(new)` — NO previous secret. A
   compromised secret must never be dual-accepted: the window would
   honor attacker-minted tokens.
3. Revoke every row: `UPDATE sessions SET revoked = TRUE` (all users,
   all environments affected). Outstanding magic links are consumed or
   expired, never honored after this point.
4. Delete the exposed secret from the Worker immediately
   (`wrangler secret delete SESSION_SECRET_PREVIOUS_BASE64` if set).
   An HMAC secret pins no data, so nothing needs it retained.
5. Users re-authenticate via passkey or magic link (expected mass
   re-login — announce it, not an incident on top of the incident).
6. Audit-log entry (env, exposure→replacement, operator, date);
   post-incident review tracks why the secret left its boundary.
