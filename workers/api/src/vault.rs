//! BYOP credential vault: envelope encryption + validation + SSRF guard.
//!
//! Design (threat-model §3):
//! - Per-user DEK (random 256-bit), wrapped by a KEK from the Worker secret.
//!   KEK version column; staging and prod KEKs never shared; rotation via
//!   [`rewrap_dek`] without touching ciphertext.
//! - AEAD (AES-256-GCM) with per-row random 96-bit nonces. Associated data
//!   binds `user_id` (ciphertext swapped between rows fails to decrypt).
//! - Credentials are never logged and never returned after save: reads
//!   return [`redacted_summary`] (booleans only); `test connection`
//!   returns a boolean only, never provider banners.
//! - User-supplied provider hosts are hostile input: [`ProviderConfig::validate`]
//!   enforces shape + the SSRF guard (NNTP-port allowlist, resolve ALL
//!   records, reject loopback/link-local/private/unique-local/reserved)
//!   before any dial. [`authorize_pool_dial`] re-enforces the same invariant
//!   at the pool dial site on every connect (save-time checks go stale when
//!   DNS changes).
//! - Timeouts and caps: [`DIAL_TIMEOUT_MS`], [`TOTAL_TIMEOUT_MS`],
//!   [`MAX_TEST_CONCURRENCY`], [`MAX_CONNECTIONS_CEILING`]. `test connection`
//!   attempts are rate-limited per user over a shared store (see
//!   [`test_attempt_allowed`]) and bounded by [`TestConnectionBudget`].
//!   Neither the allowlist nor the limits live in memory on the edge.

use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Dial timeout for `test connection` (ms).
pub const DIAL_TIMEOUT_MS: u64 = 5_000;
/// Total timeout for `test connection` (ms).
pub const TOTAL_TIMEOUT_MS: u64 = 15_000;
/// Per-user concurrent `test connection` cap.
pub const MAX_TEST_CONCURRENCY: u32 = 2;
/// Sliding window for the per-user `test connection` rate limit (seconds).
pub const TEST_CONNECTION_WINDOW_SECS: u64 = 60;
/// Max `test connection` attempts per user per [`TEST_CONNECTION_WINDOW_SECS`].
pub const TEST_CONNECTION_MAX_ATTEMPTS: u32 = 5;
/// `max_connections` ceiling: the vault row value is a cap, not a target.
pub const MAX_CONNECTIONS_CEILING: u32 = 50;
/// Indexer fetches must never follow redirects (SSRF).
pub const INDEXER_ALLOW_REDIRECTS: bool = false;

/// NNTP(S) port allowlist (threat-model §3: "119/563 plus documented
/// alternates only"). The pool dials provider hosts supplied by users, so
/// any port outside this list turns `test connection` into a port-scan
/// primitive. To add an alternate: document it in the threat model, append
/// it here, and cover it in a regression test — code and docs change
/// together, never code alone.
pub const ALLOWED_NNTP_PORTS: &[u16] = &[119, 563];

/// True when `port` is on the NNTP allowlist. No other port may be saved,
/// tested, or dialed.
pub fn nntp_port_allowed(port: u16) -> bool {
    ALLOWED_NNTP_PORTS.contains(&port)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VaultError {
    Invalid,
    Crypto,
}

impl std::fmt::Display for VaultError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Generic: never echo hosts, secrets, or crypto details.
        write!(f, "vault unavailable")
    }
}

// --- Config shapes --------------------------------------------------------------

#[derive(Clone, Serialize, Deserialize)]
pub struct ProviderConfig {
    pub host: String,
    pub port: u16,
    pub tls: bool,
    pub username: String,
    pub password: String,
    pub max_connections: u32,
    /// Explicit opt-in to send the password over plaintext NNTP.
    /// Default (`false`) requires TLS for password auth. When `true` with
    /// `tls: false`, callers MUST surface a UI warning and record the
    /// opt-in in the audit log (see [`ProviderConfig::audit_action`]).
    /// Serde default keeps stored rows without this field on the secure
    /// setting.
    #[serde(default)]
    pub allow_insecure_plaintext: bool,
}

/// Audit action for a vault save carrying the plaintext opt-in. Callers
/// MUST emit this (not the plain `vault.update`) when
/// [`ProviderConfig::insecure_plaintext_acknowledged`] is true so the
/// acknowledgment is repudiation-safe.
pub const INSECURE_PLAINTEXT_AUDIT_ACTION: &str = "vault.update.insecure_plaintext";

#[derive(Clone, Serialize, Deserialize)]
pub struct IndexerConfig {
    pub url: String,
    pub api_key: String,
}

// Manual Debug impls: credential material (password, api_key) must never
// appear in `{:#?}` output, `dbg!`, tracing fields, or assert messages
// (threat-model §3: no log line may contain credential material; CI logs
// are attacker-readable). Only connection-routing fields print.
impl std::fmt::Debug for ProviderConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProviderConfig")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("tls", &self.tls)
            .field("max_connections", &self.max_connections)
            .field("password", &"<redacted>")
            .finish()
    }
}

impl std::fmt::Debug for IndexerConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IndexerConfig")
            .field("url", &self.url)
            .field("api_key", &"<redacted>")
            .finish()
    }
}

/// DNS resolution as a trait so tests use a fake and the Worker uses real DNS.
pub trait DnsResolver {
    fn resolve(&self, host: &str) -> Vec<IpAddr>;
}

fn host_shape_ok(host: &str) -> bool {
    if host.is_empty() || host.len() > 253 {
        return false;
    }
    // Never a URL: no scheme, no path, no userinfo, no port suffix.
    if host.contains("://")
        || host.contains('/')
        || host.contains('@')
        || host.contains(':')
        || host.contains(' ')
    {
        return false;
    }
    // DNS name labels or an IP literal.
    if host.parse::<IpAddr>().is_ok() {
        return true;
    }
    !host.starts_with('.')
        && !host.ends_with('.')
        && !host.contains("..")
        && host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.')
}

fn v4_is_forbidden(o: &[u8; 4]) -> bool {
    let v4 = Ipv4Addr::from(*o);
    v4.is_loopback()         // 127/8
        || v4.is_multicast() // 224.0.0.0/4
        || v4.is_link_local() // 169.254/16
        || v4.is_private() // 10/8, 172.16/12, 192.168/16
        || v4.is_broadcast()
        || v4.is_documentation() // 192.0.2/24, 198.51.100/24, 203.0.113/24
        || o[0] == 0 // 0.0.0.0/8 ("this network")
        || (o[0] == 100 && (o[1] & 0xC0) == 64) // 100.64/10 carrier-grade NAT
        || (o[0] == 192 && o[1] == 0 && o[2] == 0) // 192.0.0.0/24 (IETF protocol assignments)
        || (o[0] == 198 && (o[1] == 18 || o[1] == 19)) // 198.18.0.0/15 benchmarking
        || o[0] >= 240 // 240.0.0.0/4 reserved + 255.255.255.255 broadcast
}

fn ip_is_forbidden(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4_is_forbidden(&v4.octets()),
        IpAddr::V6(v6) => {
            let s = v6.segments();
            // Only native global unicast (2000::/3). This excludes NAT64,
            // mapped/translated/compatible IPv4, site-local and discard.
            // Also reject transition and special-use space inside that range
            // rather than trusting a translator's embedded IPv4 destination.
            (s[0] & 0xE000) != 0x2000
                || s[0] == 0x2002 // 6to4 (2002::/16)
                || (s[0] == 0x2001 && s[1] < 0x0200) // IETF special-use, incl. Teredo/ORCHID
                || (s[0] == 0x2001 && s[1] == 0x0DB8) // documentation
                || (s[0] == 0x3FFF && (s[1] & 0xF000) == 0) // documentation (3fff::/20)
        }
    }
}

/// Vetted destination for one immediate outbound connection. Do not store
/// this across requests: validate again at dial/fetch time, connect only to
/// an address from this set, and retain `host` for TLS SNI/certificate checks
/// and the HTTP Host header. Never let the transport re-resolve the hostname.
#[derive(Debug)]
pub struct ValidatedTarget {
    host: String,
    port: u16,
    addresses: Vec<IpAddr>,
}

impl ValidatedTarget {
    pub fn host(&self) -> &str {
        &self.host
    }

    /// The allowlisted port this target was vetted for. Dial exactly this
    /// port — never a caller-supplied substitute.
    pub fn port(&self) -> u16 {
        self.port
    }

    pub fn addresses(&self) -> &[IpAddr] {
        &self.addresses
    }
}

/// Shared resolve-ALL + reject-non-public guard. Stores `port` for dial
/// pinning but does NOT check the NNTP allowlist: NNTP callers
/// ([`ProviderConfig::validate`], [`authorize_pool_dial`]) must check
/// [`nntp_port_allowed`] first. The indexer path carries the URL port
/// (https default 443) and is covered by the https-only + public-host
/// rules instead.
fn resolve_public_target(
    host: &str,
    port: u16,
    dns: &impl DnsResolver,
) -> Result<ValidatedTarget, VaultError> {
    let addresses = match host.parse::<IpAddr>() {
        Ok(ip) => vec![ip],
        Err(_) => dns.resolve(host),
    };
    if addresses.is_empty() || addresses.iter().any(ip_is_forbidden) {
        return Err(VaultError::Invalid);
    }
    Ok(ValidatedTarget {
        host: host.to_string(),
        port,
        addresses,
    })
}

/// Dial-site guard: re-enforce the §3 SSRF invariant immediately before
/// every pool connect, even when the row was validated at save time (DNS
/// can change after the save; the save-time check alone is bypassable).
///
/// The caller MUST:
/// - resolve fresh (this function) and pin the transport dial/fetch to the
///   returned [`ValidatedTarget::addresses`] — never re-resolve the hostname
///   in the transport (no second DNS lookup);
/// - retain [`ValidatedTarget::host`] for TLS SNI/certificate checks;
/// - dial [`ValidatedTarget::port`] only;
/// - enforce [`TestConnectionBudget`] timeouts and the
///   [`test_attempt_allowed`] / [`concurrent_test_allowed`] gates before
///   dialing.
///
/// Every failure maps to generic [`VaultError::Invalid`].
pub fn authorize_pool_dial(
    host: &str,
    port: u16,
    dns: &impl DnsResolver,
) -> Result<ValidatedTarget, VaultError> {
    if !host_shape_ok(host) {
        return Err(VaultError::Invalid);
    }
    if !nntp_port_allowed(port) {
        return Err(VaultError::Invalid);
    }
    resolve_public_target(host, port, dns)
}

impl ProviderConfig {
    /// Validate shape + SSRF guard and retain ALL vetted addresses for a
    /// pinned dial. Call at save AND immediately before dial. Every failure
    /// maps to generic [`VaultError::Invalid`] (no target/existence oracle).
    ///
    /// Transport confidentiality (threat-model §2 "TLS-everywhere"):
    /// password auth without TLS is rejected unless the caller explicitly
    /// sets [`ProviderConfig::allow_insecure_plaintext`]. There is no
    /// STARTTLS upgrade path modeled here — `tls: false` means cleartext.
    pub fn validate(&self, dns: &impl DnsResolver) -> Result<ValidatedTarget, VaultError> {
        if !host_shape_ok(&self.host) {
            return Err(VaultError::Invalid);
        }
        if !nntp_port_allowed(self.port) {
            return Err(VaultError::Invalid);
        }
        if self.username.is_empty() || self.username.len() > 255 {
            return Err(VaultError::Invalid);
        }
        if self.password.is_empty() || self.password.len() > 1024 {
            return Err(VaultError::Invalid);
        }
        if self.max_connections == 0 || self.max_connections > MAX_CONNECTIONS_CEILING {
            return Err(VaultError::Invalid);
        }
        if !self.tls && !self.allow_insecure_plaintext {
            return Err(VaultError::Invalid);
        }
        resolve_public_target(&self.host, self.port, dns)
    }

    /// True when this config sends the password in cleartext with the
    /// user's explicit acknowledgment. The UI MUST surface a warning and
    /// the audit log MUST record [`INSECURE_PLAINTEXT_AUDIT_ACTION`].
    pub fn insecure_plaintext_acknowledged(&self) -> bool {
        !self.tls && self.allow_insecure_plaintext
    }

    /// Audit action for a vault save of this config: the insecure-opt-in
    /// action when [`ProviderConfig::insecure_plaintext_acknowledged`] is
    /// true, otherwise the plain `vault.update`.
    pub fn audit_action(&self) -> &'static str {
        if self.insecure_plaintext_acknowledged() {
            INSECURE_PLAINTEXT_AUDIT_ACTION
        } else {
            "vault.update"
        }
    }
}

impl IndexerConfig {
    /// Validate the indexer URL + key, including the same SSRF guard as
    /// providers: the URL host is user-supplied and later fetched, so
    /// non-public targets (metadata endpoints, loopback, RFC 1918) are
    /// rejected at save time AND immediately before fetch. Use the returned
    /// addresses for a pinned fetch; redirects stay forbidden
    /// ([`INDEXER_ALLOW_REDIRECTS`]).
    ///
    /// Transport confidentiality (threat-model §2 "TLS-everywhere"):
    /// https-only. An `http://` URL would send the indexer API key in
    /// cleartext, so it is rejected even for public hosts. There is no
    /// plaintext opt-in for indexers — a public indexer must serve TLS.
    pub fn validate(&self, dns: &impl DnsResolver) -> Result<ValidatedTarget, VaultError> {
        let parsed = url::Url::parse(&self.url).map_err(|_| VaultError::Invalid)?;
        if parsed.scheme() != "https" {
            return Err(VaultError::Invalid);
        }
        let host = parsed
            .host_str()
            .filter(|h| !h.is_empty())
            .ok_or(VaultError::Invalid)?;
        // URL hosts may carry brackets (IPv6) or a port — strip both, then
        // run the same shape + resolve-ALL + reject-non-public guard.
        // The pinned port is the URL port (https default 443); the NNTP
        // allowlist does not apply to indexer fetches.
        let bare = host.trim_start_matches('[').trim_end_matches(']');
        if !host_shape_ok(bare) {
            return Err(VaultError::Invalid);
        }
        if self.api_key.is_empty() || self.api_key.len() > 1024 {
            return Err(VaultError::Invalid);
        }
        let port = parsed.port_or_known_default().unwrap_or(443);
        resolve_public_target(bare, port, dns)
    }
}

// --- `test connection` rate limit + timeouts -----------------------------------------

// Cutoff for the sliding rate window: attempts at or before this timestamp
// no longer count. The Worker prunes stored attempt rows at or below it.
pub fn test_attempt_retention_cutoff(now_secs: u64) -> u64 {
    now_secs.saturating_sub(TEST_CONNECTION_WINDOW_SECS)
}

/// Sliding-window gate for `test connection` (threat-model §3 DoS row).
///
/// `recent_attempt_secs` MUST come from a shared store (Postgres/KV) keyed
/// by user — never an in-memory list: serverless isolates have no shared
/// memory and a restart would wipe the counter. The Worker MUST:
/// - load the user's attempt timestamps,
/// - deny when this returns false (and audit the denial),
/// - otherwise persist the new attempt timestamp atomically BEFORE dialing
///   (a check-then-insert race fails open under concurrency; use a
///   conditional write / transaction).
///
/// Fail-closed on clock skew: timestamps in the future count against the
/// caller.
pub fn test_attempt_allowed(recent_attempt_secs: &[u64], now_secs: u64) -> bool {
    let in_window = recent_attempt_secs
        .iter()
        .filter(|ts| now_secs.saturating_sub(**ts) < TEST_CONNECTION_WINDOW_SECS)
        .count();
    in_window < TEST_CONNECTION_MAX_ATTEMPTS as usize
}

/// Concurrency gate for `test connection`: `in_flight` MUST come from the
/// same shared store (leases with expiry, not a process-local counter).
pub fn concurrent_test_allowed(in_flight: u32) -> bool {
    in_flight < MAX_TEST_CONCURRENCY
}

/// Dial/total deadlines for one `test connection` attempt (threat-model §3:
/// "test-connection has dial + total timeouts").
///
/// The pool Worker/DO MUST abort the TCP/TLS handshake at
/// `dial_deadline_ms` and the whole attempt at `total_deadline_ms`,
/// returning [`TestConnectionResult`] with `ok: false` — never a banner or
/// error text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TestConnectionBudget {
    pub start_ms: u64,
    pub dial_deadline_ms: u64,
    pub total_deadline_ms: u64,
}

impl TestConnectionBudget {
    pub fn new(start_ms: u64) -> Self {
        Self {
            start_ms,
            dial_deadline_ms: start_ms.saturating_add(DIAL_TIMEOUT_MS),
            total_deadline_ms: start_ms.saturating_add(TOTAL_TIMEOUT_MS),
        }
    }

    /// True once the handshake must be abandoned.
    pub fn dial_expired(&self, now_ms: u64) -> bool {
        now_ms >= self.dial_deadline_ms
    }

    /// True once the whole attempt must be abandoned.
    pub fn total_expired(&self, now_ms: u64) -> bool {
        now_ms >= self.total_deadline_ms
    }
}

// --- Envelope encryption -----------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultBlob {
    pub kek_version: u32,
    pub dek_wrapped_nonce_b64url: String,
    pub dek_wrapped_b64url: String,
    pub payload_nonce_b64url: String,
    pub payload_b64url: String,
}

#[derive(Zeroize, ZeroizeOnDrop)]
struct Dek([u8; 32]);

fn random_nonce() -> [u8; 12] {
    let mut n = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut n);
    n
}

// Unpadded-base64url lives in one place: [`crate::b64`] over the `base64`
// crate (F-HARD-01). The per-module hand-rolled copies are deleted; decode
// errors map to generic [`VaultError::Invalid`] at each call site.
fn dek_aad(user_id: &str, kek_version: u32) -> String {
    format!("v1|dek|{}|{}", user_id, kek_version)
}

fn payload_aad(user_id: &str) -> String {
    format!("v1|vault|{}", user_id)
}

/// Encrypt `plaintext` (serialized provider+indexer secrets) for `user_id`.
pub fn encrypt_vault(
    kek: &[u8; 32],
    kek_version: u32,
    user_id: &str,
    plaintext: &[u8],
) -> Result<VaultBlob, VaultError> {
    let mut dek_bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut dek_bytes);
    let dek = Dek(dek_bytes);
    dek_bytes.zeroize();

    // Wrap the DEK with the KEK (AAD binds user + KEK version).
    let kek_cipher = Aes256Gcm::new_from_slice(kek).map_err(|_| VaultError::Crypto)?;
    let wrap_nonce = random_nonce();
    let wrapped = kek_cipher
        .encrypt(
            Nonce::from_slice(&wrap_nonce),
            Payload {
                msg: &dek.0,
                aad: dek_aad(user_id, kek_version).as_bytes(),
            },
        )
        .map_err(|_| VaultError::Crypto)?;

    // Encrypt the payload with the DEK (AAD binds user).
    let dek_cipher = Aes256Gcm::new_from_slice(&dek.0).map_err(|_| VaultError::Crypto)?;
    let payload_nonce = random_nonce();
    let payload = dek_cipher
        .encrypt(
            Nonce::from_slice(&payload_nonce),
            Payload {
                msg: plaintext,
                aad: payload_aad(user_id).as_bytes(),
            },
        )
        .map_err(|_| VaultError::Crypto)?;

    Ok(VaultBlob {
        kek_version,
        dek_wrapped_nonce_b64url: crate::b64::encode(&wrap_nonce),
        dek_wrapped_b64url: crate::b64::encode(&wrapped),
        payload_nonce_b64url: crate::b64::encode(&payload_nonce),
        payload_b64url: crate::b64::encode(&payload),
    })
}

/// Decrypt a vault row. The caller must have already enforced the owner
/// check (authorization precedes lookup: non-owners get the same response
/// for "no vault" as "not yours" — no existence oracle).
pub fn decrypt_vault(
    kek: &[u8; 32],
    user_id: &str,
    blob: &VaultBlob,
) -> Result<Vec<u8>, VaultError> {
    let kek_cipher = Aes256Gcm::new_from_slice(kek).map_err(|_| VaultError::Crypto)?;
    let wrap_nonce =
        crate::b64::decode(&blob.dek_wrapped_nonce_b64url).map_err(|_| VaultError::Invalid)?;
    let wrapped = crate::b64::decode(&blob.dek_wrapped_b64url).map_err(|_| VaultError::Invalid)?;
    if wrap_nonce.len() != 12 {
        return Err(VaultError::Invalid);
    }
    let mut dek_bytes = kek_cipher
        .decrypt(
            Nonce::from_slice(&wrap_nonce),
            Payload {
                msg: &wrapped,
                aad: dek_aad(user_id, blob.kek_version).as_bytes(),
            },
        )
        .map_err(|_| VaultError::Crypto)?;
    if dek_bytes.len() != 32 {
        dek_bytes.zeroize();
        return Err(VaultError::Crypto);
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&dek_bytes);
    // Clear the AES-GCM output buffer: the DEK now lives only in `dek`.
    dek_bytes.zeroize();
    let dek = Dek(arr);

    let dek_cipher = Aes256Gcm::new_from_slice(&dek.0).map_err(|_| VaultError::Crypto)?;
    let payload_nonce =
        crate::b64::decode(&blob.payload_nonce_b64url).map_err(|_| VaultError::Invalid)?;
    let payload = crate::b64::decode(&blob.payload_b64url).map_err(|_| VaultError::Invalid)?;
    if payload_nonce.len() != 12 {
        return Err(VaultError::Invalid);
    }
    dek_cipher
        .decrypt(
            Nonce::from_slice(&payload_nonce),
            Payload {
                msg: &payload,
                aad: payload_aad(user_id).as_bytes(),
            },
        )
        .map_err(|_| VaultError::Crypto)
}

/// Rotate the KEK: unwrap the DEK with the old KEK, re-wrap with the new
/// KEK at `new_version`. Payload ciphertext is untouched.
pub fn rewrap_dek(
    old_kek: &[u8; 32],
    new_kek: &[u8; 32],
    new_version: u32,
    user_id: &str,
    blob: &VaultBlob,
) -> Result<VaultBlob, VaultError> {
    // Unwrap with the old KEK (old AAD: old version).
    let old_cipher = Aes256Gcm::new_from_slice(old_kek).map_err(|_| VaultError::Crypto)?;
    let wrap_nonce =
        crate::b64::decode(&blob.dek_wrapped_nonce_b64url).map_err(|_| VaultError::Invalid)?;
    let wrapped = crate::b64::decode(&blob.dek_wrapped_b64url).map_err(|_| VaultError::Invalid)?;
    if wrap_nonce.len() != 12 {
        return Err(VaultError::Invalid);
    }
    let mut dek_bytes = old_cipher
        .decrypt(
            Nonce::from_slice(&wrap_nonce),
            Payload {
                msg: &wrapped,
                aad: dek_aad(user_id, blob.kek_version).as_bytes(),
            },
        )
        .map_err(|_| VaultError::Crypto)?;
    if dek_bytes.len() != 32 {
        dek_bytes.zeroize();
        return Err(VaultError::Crypto);
    }

    // Re-wrap with the new KEK (new AAD: new version).
    let new_cipher = Aes256Gcm::new_from_slice(new_kek).map_err(|_| VaultError::Crypto)?;
    let new_nonce = random_nonce();
    let wrap_result = new_cipher.encrypt(
        Nonce::from_slice(&new_nonce),
        Payload {
            msg: &dek_bytes,
            aad: dek_aad(user_id, new_version).as_bytes(),
        },
    );
    // Clear the unwrapped DEK regardless of the re-wrap outcome.
    dek_bytes.zeroize();
    let new_wrapped = wrap_result.map_err(|_| VaultError::Crypto)?;

    Ok(VaultBlob {
        kek_version: new_version,
        dek_wrapped_nonce_b64url: crate::b64::encode(&new_nonce),
        dek_wrapped_b64url: crate::b64::encode(&new_wrapped),
        payload_nonce_b64url: blob.payload_nonce_b64url.clone(),
        payload_b64url: blob.payload_b64url.clone(),
    })
}

// --- Redaction + audit (never secrets) --------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultSummary {
    pub provider_configured: bool,
    pub indexer_configured: bool,
    pub updated_at: u64,
}

/// The ONLY vault read shape: booleans, no host/user/pass/URL/key material.
pub fn redacted_summary(
    provider_configured: bool,
    indexer_configured: bool,
    updated_at: u64,
) -> VaultSummary {
    VaultSummary {
        provider_configured,
        indexer_configured,
        updated_at,
    }
}

/// `test connection` returns a boolean only — never provider banners.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestConnectionResult {
    pub ok: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    pub user_id: String,
    pub action: String,
    pub ok: bool,
    pub source_ip: String,
    pub at: u64,
}

/// Audit log event. By construction there is no field for secret material:
/// callers pass ids and results only. `now` is Unix epoch seconds — the
/// audit row's ordering depends on it, so it is a required parameter.
pub fn audit_event(user_id: &str, action: &str, ok: bool, source_ip: &str, now: u64) -> AuditEvent {
    AuditEvent {
        user_id: user_id.to_string(),
        action: action.to_string(),
        ok,
        source_ip: source_ip.to_string(),
        at: now,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct EmptyDns;
    impl DnsResolver for EmptyDns {
        fn resolve(&self, _host: &str) -> Vec<IpAddr> {
            vec![]
        }
    }

    #[test]
    fn unresolvable_host_rejected() {
        let c = ProviderConfig {
            host: "nope.example.com".into(),
            port: 119,
            tls: false,
            username: "u".into(),
            password: "p".into(),
            max_connections: 2,
            // Opt in so this test exercises the DNS guard, not the TLS gate.
            allow_insecure_plaintext: true,
        };
        assert!(c.validate(&EmptyDns).is_err());
    }

    #[test]
    fn ipv6_remote_blocked() {
        for host in ["::1", "fe80::1", "fc00::1", "ff02::1"] {
            let c = ProviderConfig {
                host: host.into(),
                port: 119,
                tls: false,
                username: "u".into(),
                password: "p".into(),
                max_connections: 2,
                // Opt in so this test exercises the SSRF guard, not the TLS gate.
                allow_insecure_plaintext: true,
            };
            assert!(c.validate(&EmptyDns).is_err(), "blocked: {host}");
        }
    }

    struct PublicDns;
    impl DnsResolver for PublicDns {
        fn resolve(&self, _host: &str) -> Vec<IpAddr> {
            vec!["93.184.216.34".parse().unwrap()]
        }
    }

    #[test]
    fn plaintext_password_rejected_without_explicit_opt_in() {
        // F-TRANS-01 Gap 2: password auth with `tls: false` must not pass
        // silently — it needs the explicit per-row opt-in.
        let denied = ProviderConfig {
            host: "news.example.com".into(),
            port: 119,
            tls: false,
            username: "u".into(),
            password: "p".into(),
            max_connections: 2,
            allow_insecure_plaintext: false,
        };
        assert!(denied.validate(&PublicDns).is_err());
        assert!(!denied.insecure_plaintext_acknowledged());
        assert_eq!(denied.audit_action(), "vault.update");

        // Explicit opt-in passes validation but stays flagged for the UI
        // warning and the audit log.
        let acknowledged = ProviderConfig {
            allow_insecure_plaintext: true,
            ..denied.clone()
        };
        assert!(acknowledged.validate(&PublicDns).is_ok());
        assert!(acknowledged.insecure_plaintext_acknowledged());
        assert_eq!(acknowledged.audit_action(), INSECURE_PLAINTEXT_AUDIT_ACTION);

        // TLS stays the default: accepted, never flagged.
        let tls = ProviderConfig {
            tls: true,
            allow_insecure_plaintext: false,
            ..denied.clone()
        };
        assert!(tls.validate(&PublicDns).is_ok());
        assert!(!tls.insecure_plaintext_acknowledged());
    }

    #[test]
    fn debug_redacts_credential_material() {
        // Threat-model §3: no log line may contain credential material.
        // A `{:#?}`/`dbg!`/assert dump of these configs must not carry
        // the password or API key.
        let provider = ProviderConfig {
            host: "news.example.com".into(),
            port: 563,
            tls: true,
            username: "u".into(),
            password: "super-secret-pw".into(),
            max_connections: 2,
            allow_insecure_plaintext: false,
        };
        let dumped = format!("{provider:?}");
        assert!(
            !dumped.contains("super-secret-pw"),
            "password leaked: {dumped}"
        );
        assert!(
            dumped.contains("<redacted>"),
            "no redaction marker: {dumped}"
        );

        let indexer = IndexerConfig {
            url: "https://news.example.com/api".into(),
            api_key: "super-secret-key".into(),
        };
        let dumped = format!("{indexer:?}");
        assert!(
            !dumped.contains("super-secret-key"),
            "api key leaked: {dumped}"
        );
        assert!(
            dumped.contains("<redacted>"),
            "no redaction marker: {dumped}"
        );
    }

    #[test]
    fn http_indexer_url_rejected_for_public_host() {
        // F-TRANS-01 Gap 1: `http://` would send the API key in cleartext.
        let plaintext = IndexerConfig {
            url: "http://news.example.com/api".into(),
            api_key: "idx-key".into(),
        };
        assert!(plaintext.validate(&PublicDns).is_err());
        let encrypted = IndexerConfig {
            url: "https://news.example.com/api".into(),
            api_key: "idx-key".into(),
        };
        assert!(encrypted.validate(&PublicDns).is_ok());
    }
}
