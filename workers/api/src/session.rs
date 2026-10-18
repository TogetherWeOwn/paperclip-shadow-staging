//! Signed-cookie sessions: HMAC-SHA256, server-secret from env, rotation.
//!
//! Threat-model §4: cookies are `HttpOnly; Secure; SameSite=Lax`, bounded
//! `Max-Age`, refreshed with a row counter and a fixed authentication-age
//! cap. Privilege changes require reauthentication and a new session id.
//! The server-side session row is authoritative: request authentication uses
//! `verify_stored_session`, not signature-only verification. Secret comes
//! from the Worker env, never code.

use hmac::{Hmac, Mac};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use subtle::ConstantTimeEq;

type HmacSha256 = Hmac<Sha256>;

/// Clock skew tolerated when checking `iat` (seconds).
pub const CLOCK_SKEW_SECS: u64 = 60;
/// Absolute lifetime from authentication, not refreshed by rotation (one day).
pub const MAX_SESSION_SECS: u64 = 86_400;
/// Cookie name for the web session.
///
/// The `__Host-` prefix locks out `Domain=` overrides by construction:
/// a `__Host-` cookie is only accepted with `Path=/`, `Secure` and no
/// `Domain` attribute — all of which [`set_cookie_header`] already emits.
/// Never add `Domain=` to this cookie: browsers would reject it outright.
pub const COOKIE_NAME: &str = "__Host-nntune-session";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionClaims {
    /// Random per-session id (`jti`): joins the token to its server-side
    /// `sessions` row so a single session can be revoked without killing
    /// every session the user holds.
    pub session_id: String,
    pub user_id: String,
    /// Immutable authentication time, preserved across rotations.
    pub created_at: u64,
    pub issued_at: u64,
    pub expires_at: u64,
    pub rotation_counter: u32,
}

fn new_session_id() -> String {
    let mut bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut bytes);
    crate::b64::encode(&bytes)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionError {
    Invalid,
}

impl std::fmt::Display for SessionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Generic: never leak why verification failed.
        write!(f, "invalid session")
    }
}

// Unpadded-base64url lives in one place: [`crate::b64`] over the `base64`
// crate (F-HARD-01). Decode errors map to [`SessionError::Invalid`] at each
// call site; nothing secret or distinguishing is ever echoed.

/// Minimum HMAC secret length (32 bytes / 256 bits). Every signing and
/// verification entry point enforces it and fails closed: an unset env var
/// that decodes to an empty slice, or any truncated secret, is
/// [`SessionError::Invalid`] — never a working weak key.
pub const MIN_SECRET_LEN: usize = 32;

fn check_secret_len(secret: &[u8]) -> Result<(), SessionError> {
    if secret.len() < MIN_SECRET_LEN {
        return Err(SessionError::Invalid);
    }
    Ok(())
}

/// Secrets accepted for one verification call: exactly one primary plus an
/// optional previous, never a list or version chain. The previous secret is
/// verify-only and exists only inside a recorded rotation window; steady
/// state is [`SessionKeys::single`]. See
/// `docs/security/session-secret-rotation.md`.
#[derive(Clone, Copy)]
pub struct SessionKeys<'a> {
    pub primary: &'a [u8],
    pub previous: Option<&'a [u8]>,
}

// Manual Debug impl: the HMAC secrets must never appear in `{:#?}`
// output, `dbg!`, tracing fields, or assert messages (threat-model §3:
// no log line may contain credential material; CI logs are
// attacker-readable). Only secret lengths and rotation presence print.
impl<'a> std::fmt::Debug for SessionKeys<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionKeys")
            .field("primary_len", &self.primary.len())
            .field("has_previous", &self.previous.is_some())
            .field("secret", &"<redacted>")
            .finish()
    }
}

impl<'a> SessionKeys<'a> {
    /// Steady state: one secret mints and verifies.
    pub fn single(primary: &'a [u8]) -> Self {
        SessionKeys {
            primary,
            previous: None,
        }
    }

    /// Rotation window: the primary mints; both verify. The caller passes
    /// `None` (via [`SessionKeys::single`]) when no rotation is recorded —
    /// an empty or short previous secret fails closed instead of silently
    /// widening or narrowing the window.
    pub fn rotation(primary: &'a [u8], previous: &'a [u8]) -> Self {
        SessionKeys {
            primary,
            previous: Some(previous),
        }
    }
}

fn sign(secret: &[u8], payload_b64: &str) -> Result<Vec<u8>, SessionError> {
    check_secret_len(secret)?;
    let mut mac = HmacSha256::new_from_slice(secret).map_err(|_| SessionError::Invalid)?;
    mac.update(payload_b64.as_bytes());
    Ok(mac.finalize().into_bytes().to_vec())
}

/// Issue a new session token for `user_id` valid for `ttl_secs` from `now`.
/// Fails closed on a short secret — callers surface the error, never a
/// token minted under a weak key.
pub fn issue_session(
    secret: &[u8],
    user_id: &str,
    now: u64,
    ttl_secs: u64,
) -> Result<String, SessionError> {
    let claims = SessionClaims {
        session_id: new_session_id(),
        user_id: user_id.to_string(),
        created_at: now,
        issued_at: now,
        expires_at: now.saturating_add(ttl_secs.min(MAX_SESSION_SECS)),
        rotation_counter: 0,
    };
    let payload = serde_json::to_vec(&claims).expect("claims serialize");
    let payload_b64 = crate::b64::encode(&payload);
    let sig = sign(secret, &payload_b64)?;
    Ok(format!("{}.{}", payload_b64, crate::b64::encode(&sig)))
}

/// Verify signature and time bounds only; this does NOT authenticate a
/// request. Use it to locate the session row, then require
/// [`verify_stored_session`] against that current row before authorization.
/// Short secrets fail closed (see [`MIN_SECRET_LEN`]).
pub fn verify_session(secret: &[u8], token: &str, now: u64) -> Result<SessionClaims, SessionError> {
    check_secret_len(secret)?;
    let (payload_b64, sig_b64) = token.split_once('.').ok_or(SessionError::Invalid)?;
    let sig = crate::b64::decode(sig_b64).map_err(|_| SessionError::Invalid)?;
    let expected = sign(secret, payload_b64)?;
    if sig.len() != expected.len() || sig.ct_eq(&expected).unwrap_u8() != 1 {
        return Err(SessionError::Invalid);
    }
    let payload = crate::b64::decode(payload_b64).map_err(|_| SessionError::Invalid)?;
    let claims: SessionClaims =
        serde_json::from_slice(&payload).map_err(|_| SessionError::Invalid)?;
    if claims.user_id.is_empty() || claims.session_id.is_empty() {
        return Err(SessionError::Invalid);
    }
    if now >= claims.expires_at
        || now >= claims.created_at.saturating_add(MAX_SESSION_SECS)
        || claims.expires_at > claims.created_at.saturating_add(MAX_SESSION_SECS)
        || claims.created_at > claims.issued_at
        || claims.expires_at <= claims.issued_at
    {
        return Err(SessionError::Invalid);
    }
    if claims.issued_at > now.saturating_add(CLOCK_SKEW_SECS) {
        return Err(SessionError::Invalid);
    }
    Ok(claims)
}

/// Rotation-window verification: accept tokens signed by the current
/// `primary` secret OR the superseded `previous` secret (see
/// `docs/security/session-secret-rotation.md`). Outside a rotation window
/// callers pass [`SessionKeys::single`] — a standing second secret would
/// needlessly broaden the signing scope. Both secrets are length-checked
/// up front, so a misconfigured short `previous` fails the whole call
/// closed instead of silently narrowing the window. Both failures map to
/// the same generic [`SessionError::Invalid`]; there is no oracle for
/// which secret matched.
pub fn verify_session_dual(
    keys: &SessionKeys<'_>,
    token: &str,
    now: u64,
) -> Result<SessionClaims, SessionError> {
    check_secret_len(keys.primary)?;
    if let Some(previous) = keys.previous {
        check_secret_len(previous)?;
    }
    verify_session(keys.primary, token, now).or_else(|_| match keys.previous {
        Some(previous) => verify_session(previous, token, now),
        None => Err(SessionError::Invalid),
    })
}

/// Current server-side row from `sessions`; absence of a row must reject.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionRecord {
    pub id: String,
    pub user_id: String,
    pub created_at: u64,
    pub expires_at: u64,
    pub rotation_counter: u32,
    pub revoked: bool,
}

/// Request authentication: reject revocation, stale rotations, mismatched
/// ownership and row expiry in addition to the signed-token lifetime cap.
pub fn verify_stored_session(
    keys: &SessionKeys<'_>,
    token: &str,
    now: u64,
    record: &SessionRecord,
) -> Result<SessionClaims, SessionError> {
    let claims = verify_session_dual(keys, token, now)?;
    if record.revoked
        || claims.session_id != record.id
        || claims.user_id != record.user_id
        || claims.created_at != record.created_at
        || claims.expires_at != record.expires_at
        || claims.rotation_counter != record.rotation_counter
        || now >= record.expires_at
    {
        return Err(SessionError::Invalid);
    }
    Ok(claims)
}

/// Prepare a refresh with `rotation_counter + 1`, without extending the
/// immutable authentication lifetime. This is NOT a database rotation:
/// first require [`verify_stored_session`], then atomically UPDATE the row
/// WHERE id/user_id/counter match AND revoked = FALSE, persisting the next
/// counter and expiry. Require exactly one row and commit before Set-Cookie.
/// Once committed, the previous token fails [`verify_stored_session`].
/// For privilege changes, revoke the old row and use [`issue_session`] after
/// reauthentication to create a NEW session id; never use refresh for that.
pub fn rotate_session(
    keys: &SessionKeys<'_>,
    token: &str,
    now: u64,
    ttl_secs: u64,
) -> Result<String, SessionError> {
    // Dual path: a pre-cutover token verifies here and is re-signed below
    // with the primary, so rotation migrates sessions onto the new secret.
    let claims = verify_session_dual(keys, token, now)?;
    let next = SessionClaims {
        session_id: claims.session_id,
        user_id: claims.user_id,
        created_at: claims.created_at,
        issued_at: now,
        expires_at: now
            .saturating_add(ttl_secs)
            .min(claims.created_at.saturating_add(MAX_SESSION_SECS)),
        rotation_counter: claims
            .rotation_counter
            .checked_add(1)
            .ok_or(SessionError::Invalid)?,
    };
    let payload = serde_json::to_vec(&next).expect("claims serialize");
    let payload_b64 = crate::b64::encode(&payload);
    // Always re-sign with the primary: rotation migrates, never mints
    // under the previous secret.
    let sig = sign(keys.primary, &payload_b64)?;
    Ok(format!("{}.{}", payload_b64, crate::b64::encode(&sig)))
}

/// `Set-Cookie` header value. Always HttpOnly + Secure + SameSite=Lax.
pub fn set_cookie_header(token: &str, max_age_secs: u64) -> String {
    format!(
        "{}={}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age={}",
        COOKIE_NAME, token, max_age_secs
    )
}

/// Expired-cookie header for logout / revoke.
pub fn clear_cookie_header() -> String {
    format!(
        "{}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0",
        COOKIE_NAME
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn malformed_tokens_rejected() {
        let secret = b"0123456789abcdef0123456789abcdef";
        assert!(verify_session(secret, "no-dot", 0).is_err());
        assert!(verify_session(secret, "!!!.@@@", 0).is_err());
        assert!(verify_session(secret, "", 0).is_err());
    }

    #[test]
    fn dual_secret_accepts_previous_only_in_rotation_window() {
        let primary = b"primary-secret-00000000000000000000";
        let previous = b"previous-secret-0000000000000000000";
        let now = 1_700_000_000u64;
        let window = SessionKeys::rotation(primary, previous);
        // Token minted under the superseded secret verifies while the
        // previous secret is still configured ...
        let old_token = issue_session(previous, "user-1", now, 3600).expect("issue");
        assert!(verify_session(primary, &old_token, now + 60).is_err());
        assert!(verify_session_dual(&window, &old_token, now + 60).is_ok());
        // ... new tokens verify under the primary alone ...
        let new_token = issue_session(primary, "user-1", now, 3600).expect("issue");
        assert!(verify_session_dual(&window, &new_token, now + 60).is_ok());
        // ... and dropping the previous secret ends the window: old tokens
        // fail under the primary with no oracle for which secret matched.
        assert!(verify_session(primary, &old_token, now + 60).is_err());
        let wrong = SessionKeys::rotation(
            b"wrong-1-00000000000000000000000",
            b"wrong-2-00000000000000000000000",
        );
        assert_eq!(
            verify_session_dual(&wrong, &new_token, now + 60),
            Err(SessionError::Invalid)
        );
    }

    fn record_for(claims: &SessionClaims) -> SessionRecord {
        SessionRecord {
            id: claims.session_id.clone(),
            user_id: claims.user_id.clone(),
            created_at: claims.created_at,
            expires_at: claims.expires_at,
            rotation_counter: claims.rotation_counter,
            revoked: false,
        }
    }

    #[test]
    fn rotation_window_end_to_end_through_row_check() {
        // The documented rotation flow: a pre-cutover token authenticates
        // through verify_stored_session, refreshes onto the primary via
        // rotate_session, and dies when the previous secret is dropped.
        let primary = b"primary-secret-00000000000000000000";
        let previous = b"previous-secret-0000000000000000000";
        let now = 1_700_000_000u64;
        let window = SessionKeys::rotation(primary, previous);

        let old_token = issue_session(previous, "user-1", now, 3600).expect("issue");
        let record =
            record_for(&verify_session_dual(&window, &old_token, now + 60).expect("dual verifies"));
        // Step 3 of the runbook: the pre-cutover cookie authenticates.
        let claims =
            verify_stored_session(&window, &old_token, now + 60, &record).expect("row check");
        assert_eq!(claims.rotation_counter, 0);
        // Refresh migrates the session onto the primary signature ...
        let rotated = rotate_session(&window, &old_token, now + 120, 3600).expect("rotate");
        let rotated_claims =
            verify_session(primary, &rotated, now + 180).expect("primary alone verifies");
        assert_eq!(rotated_claims.rotation_counter, 1);
        assert_eq!(rotated_claims.session_id, claims.session_id);
        // ... and dropping the previous secret ends the window: the old
        // token fails the row check under the primary alone.
        let steady = SessionKeys::single(primary);
        assert!(verify_stored_session(&steady, &old_token, now + 180, &record).is_err());
    }

    #[test]
    fn short_or_empty_secrets_fail_closed() {
        let primary = b"primary-secret-00000000000000000000";
        let now = 1_700_000_000u64;
        // Minting under a weak key is refused, never issued.
        assert!(issue_session(b"", "victim", now, 3600).is_err());
        assert!(issue_session(b"short", "victim", now, 3600).is_err());
        assert!(verify_session(b"", "x.y", now).is_err());
        // An unset previous secret (empty slice) fails the whole call:
        // a token minted under the empty key never verifies.
        let empty_prev = SessionKeys::rotation(primary, b"");
        assert!(verify_session_dual(&empty_prev, "x.y", now).is_err());
        // The primary itself is length-checked even when a previous exists.
        let short_primary = SessionKeys::rotation(b"short", b"");
        assert!(verify_session_dual(&short_primary, "x.y", now).is_err());
    }

    #[test]
    fn debug_redacts_session_secrets() {
        // Threat-model §3: no log line may contain credential material.
        // SessionKeys holds the raw session HMAC secrets; a `{:#?}`/
        // `dbg!`/assert dump must not carry the secret bytes.
        let primary = b"PRIMARY-SECRET-0123456789abcdef00";
        let previous = b"PREVIOUS-SECRET-0123456789abcdef0";
        for keys in [
            SessionKeys::single(primary),
            SessionKeys::rotation(primary, previous),
        ] {
            for dumped in [format!("{keys:?}"), format!("{keys:#?}")] {
                assert!(
                    !dumped.contains("PRIMARY-SECRET"),
                    "primary secret leaked: {dumped}"
                );
                assert!(
                    !dumped.contains("PREVIOUS-SECRET"),
                    "previous secret leaked: {dumped}"
                );
                assert!(
                    dumped.contains("<redacted>"),
                    "no redaction marker: {dumped}"
                );
            }
        }
    }
}
