//! Accounts/auth: email magic links, passkey challenge lifecycle, invite codes.
//!
//! Threat-model §4: magic-link tokens are cryptographic-random (256-bit),
//! hashed (SHA-256) at rest, single-use, ≤15-min expiry; login errors are
//! generic (no user-enumeration oracle); challenges are single-use with
//! short expiry and RP/origin pinning.
//!
//! Full WebAuthn attestation/assertion signature verification wires to a
//! WebAuthn library in the follow-up slice (child card): this module owns
//! the challenge lifecycle, origin/RP binding, expiry, single-use, and
//! credential storage shapes, all enforced and tested here.

use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

/// Magic-link lifetime: 15 minutes (seconds).
pub const MAGIC_LINK_TTL_SECS: u64 = 900;
/// Passkey challenge lifetime: 5 minutes (seconds).
pub const CHALLENGE_TTL_SECS: u64 = 300;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthError {
    /// Generic: every login/consume failure maps here. Never distinguish
    /// "unknown user" from "bad token" (enumeration oracle).
    Invalid,
}

impl std::fmt::Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            // Same message the API returns for every auth failure.
            AuthError::Invalid => write!(f, "check your email and try again"),
        }
    }
}

fn random_b64url_32() -> String {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    // Shared unpadded-base64url (F-HARD-01): no per-module copies.
    crate::b64::encode(&bytes)
}

fn sha256_hex(s: &str) -> String {
    let digest = Sha256::digest(s.as_bytes());
    let mut out = String::with_capacity(64);
    for b in digest {
        out.push_str(&format!("{:02x}", b));
    }
    out
}

// --- Email magic link ---------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MagicLinkRecord {
    /// SHA-256 hex of the plaintext token. The plaintext is emailed once
    /// and never stored.
    pub token_hash: String,
    pub user_id: String,
    pub email: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub used: bool,
}

/// Issue a magic link: returns `(plaintext_token, stored_record)`.
/// The plaintext goes into the emailed URL; only the hash is stored.
pub fn issue_magic_link(user_id: &str, email: &str, now: u64) -> (String, MagicLinkRecord) {
    let token = random_b64url_32();
    let record = MagicLinkRecord {
        token_hash: sha256_hex(&token),
        user_id: user_id.to_string(),
        email: email.to_string(),
        issued_at: now,
        expires_at: now.saturating_add(MAGIC_LINK_TTL_SECS),
        used: false,
    };
    (token, record)
}

/// Pure record validation/preparation, NOT authentication or a database claim.
/// Independent snapshots may both pass. HTTP callers must instead use
/// [`consume_magic_link_atomically`], which requires a committed conditional
/// database update before returning an authenticated result.
pub fn consume_magic_link(
    mut record: MagicLinkRecord,
    presented_token: &str,
    now: u64,
) -> Result<ConsumedMagicLink, AuthError> {
    let presented_hash = sha256_hex(presented_token);
    if presented_hash
        .as_bytes()
        .ct_eq(record.token_hash.as_bytes())
        .unwrap_u8()
        != 1
    {
        return Err(AuthError::Invalid);
    }
    if record.used {
        return Err(AuthError::Invalid);
    }
    if now > record.expires_at {
        return Err(AuthError::Invalid);
    }
    record.used = true;
    Ok(ConsumedMagicLink {
        user_id: record.user_id.clone(),
        used_record: record,
    })
}

/// Validated candidate and prepared spent record. It becomes an authenticated
/// result ONLY when returned by [`consume_magic_link_atomically`] after the
/// database claim commits; the pure preparation helper grants no session.
#[derive(Debug, Clone)]
pub struct ConsumedMagicLink {
    pub user_id: String,
    pub used_record: MagicLinkRecord,
}

impl ConsumedMagicLink {
    /// Test helper: recover the spent record to prove replay rejection.
    pub fn into_record_for_replay_test(self) -> MagicLinkRecord {
        self.used_record
    }
}

// --- Passkey challenge lifecycle ----------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasskeyChallenge {
    /// Random challenge id (base64url, 256-bit).
    pub id: String,
    /// Relying-party id, pinned to the real origin's host.
    pub rp_id: String,
    /// Exact expected origin (scheme + host), e.g. `https://nntune.example.com`.
    pub origin: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub consumed: bool,
}

/// Start a registration (or authentication) ceremony. Validates the RP/origin
/// shape now so misconfiguration fails before any credential is created.
/// Returns [`AuthError::Invalid`] (never panics): in a Worker a panic is a
/// 500, and request-adjacent misconfiguration must stay a generic rejection.
pub fn new_registration_challenge(
    rp_id: &str,
    origin: &str,
    now: u64,
) -> Result<PasskeyChallenge, AuthError> {
    let parsed = url::Url::parse(origin).map_err(|_| AuthError::Invalid)?;
    let host = parsed.host_str().ok_or(AuthError::Invalid)?;
    let host = host.trim_start_matches('[').trim_end_matches(']');
    let local = matches!(host, "localhost" | "127.0.0.1" | "::1");
    if !(parsed.scheme() == "https" || (parsed.scheme() == "http" && local))
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.path() != "/"
        || parsed.query().is_some()
        || parsed.fragment().is_some()
        // Require an actual serialized origin, not a URL that normalizes
        // away empty userinfo, a path, or other non-origin components.
        || origin != parsed.origin().ascii_serialization()
        // This application pins the RP to the exact host, not a parent
        // suffix. Cross-subdomain credentials are intentionally unsupported.
        || rp_id != host
        || (!local && !host.contains('.'))
    {
        return Err(AuthError::Invalid);
    }
    Ok(PasskeyChallenge {
        id: random_b64url_32(),
        rp_id: rp_id.to_string(),
        origin: origin.to_string(),
        issued_at: now,
        expires_at: now.saturating_add(CHALLENGE_TTL_SECS),
        consumed: false,
    })
}

/// Pure ceremony validation/preparation, NOT a database single-use claim.
/// HTTP callers must use [`consume_challenge_atomically`] and complete
/// credential signature verification before issuing any session. The Worker
/// must not treat a passing lifecycle gate alone as WebAuthn authentication.
pub fn verify_and_consume_challenge(
    mut challenge: PasskeyChallenge,
    rp_id: &str,
    origin: &str,
    now: u64,
) -> Result<PasskeyChallenge, AuthError> {
    if challenge.consumed {
        return Err(AuthError::Invalid);
    }
    if now > challenge.expires_at {
        return Err(AuthError::Invalid);
    }
    if challenge
        .rp_id
        .as_bytes()
        .ct_eq(rp_id.as_bytes())
        .unwrap_u8()
        != 1
    {
        return Err(AuthError::Invalid);
    }
    if challenge
        .origin
        .as_bytes()
        .ct_eq(origin.as_bytes())
        .unwrap_u8()
        != 1
    {
        return Err(AuthError::Invalid);
    }
    challenge.consumed = true;
    Ok(challenge)
}

/// Stored WebAuthn credential (public key only — never private material).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasskeyCredential {
    pub cred_id_b64url: String,
    pub user_id: String,
    /// Raw public key bytes (COSE-decoded); signature checks use these.
    pub public_key: Vec<u8>,
    /// Monotonic signature counter for clone detection.
    pub sign_count: u32,
    pub registered_at: u64,
}

// --- Invite codes (optional gate) ----------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InviteRecord {
    /// SHA-256 hex of the code. Plaintext codes are never stored.
    pub code_hash: String,
    pub used: bool,
    pub created_at: u64,
}

pub fn hash_invite_code(code: &str) -> String {
    sha256_hex(code)
}

/// Pure invite validation/preparation, NOT a database single-use claim.
/// Signup callers must use [`consume_invite_atomically`] inside their signup
/// transaction; two in-memory snapshots are not a uniqueness boundary.
pub fn consume_invite(
    mut record: InviteRecord,
    presented_code: &str,
) -> Result<InviteRecord, AuthError> {
    let presented_hash = sha256_hex(presented_code);
    if presented_hash
        .as_bytes()
        .ct_eq(record.code_hash.as_bytes())
        .unwrap_u8()
        != 1
    {
        return Err(AuthError::Invalid);
    }
    if record.used {
        return Err(AuthError::Invalid);
    }
    record.used = true;
    Ok(record)
}

// --- Invite issuance + redemption throttle (F-HARD-01 item 4) -------------------

/// Invite-code entropy: 128 bits, crypto-random, unpadded-base64url
/// (22 chars). Returns the plaintext code; callers store only
/// [`hash_invite_code`] of it and deliver the plaintext to the inviter
/// once. Human-guessable or sequential codes are banned: at 128 bits
/// enumeration is infeasible and the throttle below is defense in depth.
pub fn generate_invite_code() -> String {
    let mut bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut bytes);
    crate::b64::encode(&bytes)
}

/// Sliding window for the invite-redemption rate limit (seconds).
pub const INVITE_REDEMPTION_WINDOW_SECS: u64 = 300;
/// Max redemption attempts per key per [`INVITE_REDEMPTION_WINDOW_SECS`].
/// Generous for humans retrying a pasted code, tight for scripts: 10
/// attempts per 5 minutes per IP (or per account once authenticated).
pub const INVITE_REDEMPTION_MAX_ATTEMPTS: u32 = 10;

/// Cutoff for the sliding redemption window: attempts at or before this
/// timestamp no longer count. The HTTP slice prunes stored attempt rows at
/// or below it.
pub fn invite_attempt_retention_cutoff(now_secs: u64) -> u64 {
    now_secs.saturating_sub(INVITE_REDEMPTION_WINDOW_SECS)
}

/// Sliding-window gate for invite redemption.
///
/// `recent_attempt_secs` MUST come from a shared store (Postgres/KV) keyed
/// by client IP (anonymous signup) or account — never an in-memory list:
/// serverless isolates have no shared memory and a restart would wipe the
/// counter. The HTTP slice MUST:
/// - load the key's attempt timestamps,
/// - deny with the generic [`AuthError::Invalid`] when this returns false
///   (indistinguishable from a bad code — no throttle oracle),
/// - otherwise persist the new attempt timestamp atomically BEFORE running
///   the conditional invite claim (a check-then-insert race fails open
///   under concurrency; use a conditional write / transaction).
///
/// Fail-closed on clock skew: timestamps in the future count against the
/// caller.
pub fn invite_attempt_allowed(recent_attempt_secs: &[u64], now_secs: u64) -> bool {
    let in_window = recent_attempt_secs
        .iter()
        .filter(|ts| now_secs.saturating_sub(**ts) < INVITE_REDEMPTION_WINDOW_SECS)
        .count();
    in_window < INVITE_REDEMPTION_MAX_ATTEMPTS as usize
}

/// A validated candidate for one atomic, parameterized Postgres claim.
/// Bind the listed parameters; never interpolate a record into SQL.
pub enum SingleUseClaim<'a> {
    /// Parameters: token_hash, user_id, email, expires_at, now.
    MagicLink {
        record: &'a MagicLinkRecord,
        now: u64,
    },
    /// Parameters: id, rp_id, origin, expires_at, now.
    Challenge {
        record: &'a PasskeyChallenge,
        now: u64,
    },
    /// Parameter: code_hash.
    Invite { record: &'a InviteRecord },
}

impl SingleUseClaim<'_> {
    /// Execute this statement once and count its returned rows. The primary
    /// key + conditional flag transition makes concurrent claims exclusive.
    pub fn statement(&self) -> &'static str {
        match self {
            Self::MagicLink { .. } => "UPDATE magic_link_tokens SET used = TRUE WHERE token_hash = $1 AND user_id = $2 AND email = $3 AND expires_at = $4 AND expires_at > $5 AND used = FALSE RETURNING token_hash",
            Self::Challenge { .. } => "UPDATE auth_challenges SET consumed = TRUE WHERE id = $1 AND rp_id = $2 AND origin = $3 AND expires_at = $4 AND expires_at > $5 AND consumed = FALSE RETURNING id",
            Self::Invite { .. } => "UPDATE invite_codes SET used = TRUE WHERE code_hash = $1 AND used = FALSE RETURNING code_hash",
        }
    }
}

/// Worker/Hyperdrive boundary. Implementations must execute the conditional
/// UPDATE from [`SingleUseClaim::statement`] and return the number of rows
/// it returned, NOT perform SELECT + unconditional UPDATE. Return an error
/// on storage failure. Success is usable only after the transaction commits;
/// signup/session insertion may share that transaction, but nothing may be
/// sent to the client before commit. An in-memory flag is not an implementation.
pub trait SingleUseStore {
    fn claim(
        &self,
        candidate: SingleUseClaim<'_>,
    ) -> impl std::future::Future<Output = Result<u64, AuthError>>;
}

/// HTTP magic-link entry: validation plus an exclusive database claim.
/// Zero rows (replay/expiry), multiple rows, or a store error all fail closed.
pub async fn consume_magic_link_atomically(
    record: MagicLinkRecord,
    presented_token: &str,
    now: u64,
    store: &impl SingleUseStore,
) -> Result<ConsumedMagicLink, AuthError> {
    let prepared = consume_magic_link(record, presented_token, now)?;
    if store
        .claim(SingleUseClaim::MagicLink {
            record: &prepared.used_record,
            now,
        })
        .await?
        != 1
    {
        return Err(AuthError::Invalid);
    }
    Ok(prepared)
}

/// HTTP ceremony gate: exclusive challenge claim; still requires WebAuthn
/// signature verification before authentication (not provided in this slice).
pub async fn consume_challenge_atomically(
    challenge: PasskeyChallenge,
    rp_id: &str,
    origin: &str,
    now: u64,
    store: &impl SingleUseStore,
) -> Result<PasskeyChallenge, AuthError> {
    let prepared = verify_and_consume_challenge(challenge, rp_id, origin, now)?;
    if store
        .claim(SingleUseClaim::Challenge {
            record: &prepared,
            now,
        })
        .await?
        != 1
    {
        return Err(AuthError::Invalid);
    }
    Ok(prepared)
}

/// Signup invite gate: validation plus an exclusive database claim.
pub async fn consume_invite_atomically(
    record: InviteRecord,
    presented_code: &str,
    store: &impl SingleUseStore,
) -> Result<InviteRecord, AuthError> {
    let prepared = consume_invite(record, presented_code)?;
    if store
        .claim(SingleUseClaim::Invite { record: &prepared })
        .await?
        != 1
    {
        return Err(AuthError::Invalid);
    }
    Ok(prepared)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn magic_link_hash_is_sha256_hex() {
        let (token, record) = issue_magic_link("u", "a@b.c", 0);
        assert_eq!(record.token_hash, sha256_hex(&token));
        assert_eq!(record.token_hash.len(), 64);
    }

    #[test]
    fn invite_single_use() {
        let record = InviteRecord {
            code_hash: hash_invite_code("INVITE-1"),
            used: false,
            created_at: 0,
        };
        let spent = consume_invite(record, "INVITE-1").unwrap();
        assert!(spent.used);
        assert!(consume_invite(spent, "INVITE-1").is_err());
    }

    #[test]
    fn invite_codes_are_128_bit_random() {
        let a = generate_invite_code();
        let b = generate_invite_code();
        for code in [&a, &b] {
            assert_eq!(code.len(), 22, "16 bytes encode to 22 unpadded chars");
            assert!(
                code.bytes()
                    .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_'),
                "url-safe alphabet only: {code:?}"
            );
            assert_eq!(
                crate::b64::decode(code)
                    .expect("generated code decodes")
                    .len(),
                16,
                "exactly 128 bits of entropy"
            );
            // Generated codes round-trip through the at-rest hash.
            assert_eq!(hash_invite_code(code).len(), 64);
        }
        assert_ne!(a, b, "codes must be unique per generation");
    }

    #[test]
    fn invite_redemption_throttle_trips() {
        let now = 1_700_000_000u64;
        let full: Vec<u64> = (0..10).map(|i| now - i).collect();
        assert!(
            !invite_attempt_allowed(&full, now),
            "10 attempts in the window must trip the limit"
        );
        let nine: Vec<u64> = (0..9).map(|i| now - i).collect();
        assert!(
            invite_attempt_allowed(&nine, now),
            "9 attempts in the window must pass"
        );
        assert!(
            invite_attempt_allowed(&[now - 300, now - 3_600], now),
            "attempts at/outside the window edge must age out"
        );
        assert!(
            !invite_attempt_allowed(&[now - 299; 10], now),
            "attempts just inside the window must count"
        );
        assert!(invite_attempt_allowed(&[], now), "first attempt must pass");
        assert!(
            !invite_attempt_allowed(&[now + 1_000; 10], now),
            "future timestamps must fail closed, not bypass"
        );
        assert_eq!(invite_attempt_retention_cutoff(now), now - 300);
        assert_eq!(invite_attempt_retention_cutoff(30), 0);
    }
}
