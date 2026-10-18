-- NNTune v2 migration 0002: accounts, auth, sessions, BYOP vault.
--
-- PlanetScale Postgres via Hyperdrive. All access uses parameterized
-- queries only (never string-interpolated). No secret defaults, no
-- plaintext backfills: vault columns hold envelope-encrypted blobs only.
-- Vault reads return booleans (see workers/api); the ciphertext here is
-- never logged, never returned after save.

CREATE TABLE IF NOT EXISTS users (
    id          TEXT PRIMARY KEY,
    email       TEXT NOT NULL UNIQUE,
    created_at  BIGINT NOT NULL,
    -- Optional invite gate: NULL when invites are disabled.
    invite_code_hash TEXT
);

-- WebAuthn credentials: public keys only, never private material.
CREATE TABLE IF NOT EXISTS webauthn_credentials (
    cred_id     TEXT PRIMARY KEY,
    user_id     TEXT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    public_key  BYTEA NOT NULL,
    sign_count  BIGINT NOT NULL DEFAULT 0,
    registered_at BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_webauthn_user ON webauthn_credentials (user_id);

-- Passkey / magic-link challenges: single-use, short expiry. The challenge
-- secret itself is random; only its id + expiry live here.
CREATE TABLE IF NOT EXISTS auth_challenges (
    id          TEXT PRIMARY KEY,
    user_id     TEXT,
    rp_id       TEXT NOT NULL,
    origin      TEXT NOT NULL,
    expires_at  BIGINT NOT NULL,
    consumed    BOOLEAN NOT NULL DEFAULT FALSE
);

-- Email magic links: SHA-256 hash at rest, single-use, <=15-min expiry.
-- The plaintext token is emailed once and never stored.
CREATE TABLE IF NOT EXISTS magic_link_tokens (
    token_hash  TEXT PRIMARY KEY,
    user_id     TEXT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    email       TEXT NOT NULL,
    issued_at   BIGINT NOT NULL,
    expires_at  BIGINT NOT NULL,
    used        BOOLEAN NOT NULL DEFAULT FALSE
);
CREATE INDEX IF NOT EXISTS idx_magic_user ON magic_link_tokens (user_id);

-- Server-side sessions: the revocation source. Cookie is the HMAC-signed
-- token (see workers/api/src/session.rs); this row decides revocation.
CREATE TABLE IF NOT EXISTS sessions (
    id              TEXT PRIMARY KEY,
    user_id         TEXT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    created_at      BIGINT NOT NULL,
    expires_at      BIGINT NOT NULL,
    rotation_counter INTEGER NOT NULL DEFAULT 0,
    revoked         BOOLEAN NOT NULL DEFAULT FALSE
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions (user_id);

-- BYOP vault: one row per user. Envelope encryption: per-user DEK wrapped
-- by the KEK (Worker secret). KEK version column for rotation; staging and
-- prod KEKs never shared. Ciphertext only — no plaintext credential column
-- exists in this schema by design.
CREATE TABLE IF NOT EXISTS provider_vaults (
    user_id                 TEXT PRIMARY KEY REFERENCES users (id) ON DELETE CASCADE,
    kek_version             INTEGER NOT NULL,
    dek_wrapped_nonce       TEXT NOT NULL,
    dek_wrapped             TEXT NOT NULL,
    payload_nonce           TEXT NOT NULL,
    payload                 TEXT NOT NULL,
    indexer_configured      BOOLEAN NOT NULL DEFAULT FALSE,
    updated_at              BIGINT NOT NULL
);

-- Optional invite codes: hashes only, single-use.
CREATE TABLE IF NOT EXISTS invite_codes (
    code_hash   TEXT PRIMARY KEY,
    used        BOOLEAN NOT NULL DEFAULT FALSE,
    created_at  BIGINT NOT NULL
);

-- Audit log: who/when/source/result. NEVER secret material: there is no
-- column for credentials, tokens, keys, or banners by design.
CREATE TABLE IF NOT EXISTS audit_log (
    id          BIGSERIAL PRIMARY KEY,
    user_id     TEXT NOT NULL,
    action      TEXT NOT NULL,
    ok          BOOLEAN NOT NULL,
    source_ip   TEXT NOT NULL,
    at          BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_log (user_id);
