# nntune-api: accounts, auth, sessions, BYOP vault

Rust core for NNTune v2 accounts/auth (passkey challenges + email magic
link), signed-cookie sessions, and the BYOP credential vault. Compiles to
native (tests) and `wasm32` (Cloudflare Worker).

## Layout

```text
workers/api/
  src/lib.rs      # crate root (native + wasm32, no Worker runtime imports)
  src/session.rs  # HMAC-signed cookies: issue / verify / rotate
  src/auth.rs     # magic links, passkey challenge lifecycle, invite codes
  src/vault.rs    # envelope encryption, validation, SSRF guard, redaction
  tests/api_tests.rs  # acceptance tests (TDD)
  wrangler.toml.example  # Worker config template (no secrets)
```

`migrations/0002_auth_vault.sql` is the Postgres schema (PlanetScale via
Hyperdrive). The HTTP + Hyperdrive wiring (Worker entry) lands in the
follow-up slice once staging secrets are provisioned; this crate is the
security-critical logic with tests.

## Security contract (threat-model §3–§4)

- **Envelope encryption:** per-user random 256-bit DEK, wrapped by the KEK
  (Cloudflare Worker secret, versioned). AES-256-GCM, random 96-bit nonces,
  AAD binds `user_id` (+ KEK version for the wrap). Row-swap between users
  fails to decrypt. Rotation via `rewrap_dek` without touching ciphertext.
- **Never logged, never returned:** reads return booleans only
  (`redacted_summary`); `test connection` returns a boolean, never provider
  banners; audit events carry ids/results only — there is no field for
  secret material anywhere in the API or schema.
- **Sessions:** `__Host-nntune-session` (`__Host-` prefix: `Path=/`, `Secure`,
  no `Domain=` by construction); `HttpOnly; SameSite=Lax`; immutable `created_at`
  caps the lifetime at one day even across refreshes. Secret rotation runs a
  bounded dual-accept window — see `docs/security/session-secret-rotation.md`
  (`SessionKeys::rotation` verifies through `verify_stored_session` and
  re-signs with the primary; verify-only previous secret,
  `created_at`-bounded window, single-secret steady state; keys under 32
  bytes fail closed). `verify_session`
  checks only signatures/time and is not request authentication. Require
  `verify_stored_session` against the current `sessions` row on every
  request: owner, expiry, counter and revocation must match. Refresh must
  conditionally update the matching row/counter and commit before sending
  the cookie; a superseded cookie then fails. Privilege changes require
  reauthentication, revoking the old row and issuing a new session id.
- **Magic links:** 256-bit random tokens, SHA-256 hash at rest, 15-minute
  expiry. HTTP callers must use `consume_magic_link_atomically`, not the
  pure record-preparation helper. Magic links, passkey challenges and
  invites use `SingleUseStore`: one parameterized conditional UPDATE,
  requiring exactly one returned row and a committed transaction before
  any session/signup response. Zero rows, multiple rows and store errors
  fail closed. Never SELECT then unconditionally persist a used flag.
  All failures return one generic message (no user-enumeration oracle).
- **Passkeys:** RP ID equals the exact origin host (cross-subdomain RP
  suffixes are intentionally unsupported). Configuration must be a canonical
  serialized origin: https, or http with the host exactly `localhost`,
  `127.0.0.1` or `::1` for development, no userinfo/path/query/fragment.
  Five-minute challenges must be consumed through
  `consume_challenge_atomically`; signature verification still must finish
  before authentication. Monotonic `sign_count` storage and full WebAuthn
  attestation/assertion verification wire to the follow-up Worker slice.
- **SSRF guard:** provider hosts are hostile input. Shape check (never a
  URL), resolve ALL DNS records, reject loopback/link-local/private/
  unique-local/multicast/reserved (v4+v6); literal IPs checked directly.
  IPv6 is limited to native global unicast minus transition/special-use
  space: NAT64, mapped/translated IPv4, 6to4, Teredo, site-local, discard,
  ORCHID and documentation ranges are rejected conservatively.
  `validate` returns a `ValidatedTarget` with vetted addresses. Revalidate
  at every dial/fetch and pin the transport to that address set without
  another DNS lookup; retain the original hostname for TLS SNI/certificate
  checks and HTTP Host. Save-time validation is not a fetch authorization.
  Indexer fetches forbid redirects; dial/total timeouts and per-user
  concurrency caps are constants in `vault.rs`.

## Test

```sh
cargo test --manifest-path workers/api/Cargo.toml
cargo clippy --manifest-path workers/api/Cargo.toml --all-targets -- -D warnings
cargo fmt --manifest-path workers/api/Cargo.toml -- --check
```

Fixtures use synthetic credentials only (`news.example.com`, `203.0.113.7`).
