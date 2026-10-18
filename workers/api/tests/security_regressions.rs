//! Security regression acceptance tests for the auth/session/vault core.
//!
//! Expectations come from the security contract, not implementation helpers.
//! DNS and conditional storage are deterministic fakes; no network or database
//! is contacted. These tests do not verify HTTP adapters, database concurrency,
//! WebAuthn signatures, or connection-time DNS pinning.

use base64::Engine as _;
use hmac::{Hmac, Mac};
use nntune_api::{auth, session, vault};
use sha2::Sha256;
use std::{cell::RefCell, future::Future, net::IpAddr, task::Poll};

const NOW: u64 = 1_700_000_000;
const ONE_DAY: u64 = 86_400;
const SECRET: &[u8] = b"synthetic-session-secret-at-least-32-bytes";
const HOST: &str = "service.example.com";
const RP: &str = "nntune.example.com";
const ORIGIN: &str = "https://nntune.example.com";

struct FixedDns(Vec<IpAddr>);

impl vault::DnsResolver for FixedDns {
    fn resolve(&self, host: &str) -> Vec<IpAddr> {
        assert_eq!(host, HOST, "validation must resolve the original hostname");
        self.0.clone()
    }
}

fn dns(addresses: &[&str]) -> FixedDns {
    FixedDns(addresses.iter().map(|ip| ip.parse().unwrap()).collect())
}

fn provider() -> vault::ProviderConfig {
    vault::ProviderConfig {
        host: HOST.into(),
        port: 563,
        tls: true,
        username: "synthetic-user".into(),
        password: "synthetic-password".into(),
        max_connections: 4,
        allow_insecure_plaintext: false,
    }
}

fn indexer() -> vault::IndexerConfig {
    vault::IndexerConfig {
        url: format!("https://{HOST}/api"),
        api_key: "synthetic-indexer-key".into(),
    }
}

fn assert_rejected_targets(addresses: &[&str]) {
    let resolver = dns(addresses);
    assert!(
        provider().validate(&resolver).is_err(),
        "provider accepted forbidden DNS answers: {addresses:?}"
    );
    assert!(
        indexer().validate(&resolver).is_err(),
        "indexer accepted forbidden DNS answers: {addresses:?}"
    );
}

#[test]
fn targets_reject_six_to_four() {
    for address in ["2002::1", "2002:a00:1::1", "2002:ffff:ffff:ffff::1"] {
        assert_rejected_targets(&[address]);
    }
}

#[test]
fn targets_reject_teredo_and_orchid_special_use_block() {
    for address in [
        "2001::1",
        "2001:0:4136:e378:8000:63bf:3fff:fdd2",
        "2001:10::1",
        "2001:20::1",
        "2001:1ff:ffff:ffff::1",
    ] {
        assert_rejected_targets(&[address]);
    }
}

#[test]
fn targets_reject_other_ipv6_transition_and_special_use_ranges() {
    for address in [
        "64:ff9b::5db8:d822",   // NAT64 well-known prefix, public IPv4 payload.
        "64:ff9b:1::a00:1",     // NAT64 local-use prefix.
        "::ffff:93.184.216.34", // IPv4-mapped, even with a public payload.
        "::ffff:10.0.0.1",
        "::ffff:0:5db8:d822", // IPv4-translated.
        "::93.184.216.34",    // IPv4-compatible.
        "fec0::1",            // Deprecated site-local.
        "100::1",             // Discard-only.
        "2001:db8::1",        // Documentation.
        "3fff::1",            // Documentation.
        "::",
        "::1",
        "fc00::1",
        "fe80::1",
        "ff02::1",
    ] {
        assert_rejected_targets(&[address]);
    }
}

#[test]
fn targets_reject_mixed_public_and_private_dns_answers() {
    for addresses in [
        ["93.184.216.34", "10.0.0.5"],
        ["10.0.0.5", "93.184.216.34"],
        ["2606:4700:4700::1111", "fe80::1"],
        ["fe80::1", "2606:4700:4700::1111"],
        ["93.184.216.34", "2002:a00:1::1"],
    ] {
        assert_rejected_targets(&addresses);
    }
}

#[test]
fn targets_reject_empty_dns_answers() {
    assert_rejected_targets(&[]);
}

#[test]
fn nntp_port_allowlist_rejects_non_allowlisted_public_ports() {
    // F-VAULT-03 Gap 1: only 119/563 (plus documented alternates) may be
    // saved or dialed. A public-host answer on any other port is Invalid
    // at both save time (`validate`) and the pool dial site
    // (`authorize_pool_dial`) — otherwise `test connection` is a port-scan
    // primitive aimed at 22/25/3306/6379/....
    let public = dns(&["93.184.216.34"]);
    for port in [119u16, 563] {
        let cfg = vault::ProviderConfig { port, ..provider() };
        assert!(
            cfg.validate(&public).is_ok(),
            "allowlisted port rejected at save: {port}"
        );
        let target = vault::authorize_pool_dial(HOST, port, &public)
            .expect("allowlisted port rejected at dial");
        assert_eq!(target.port(), port, "dial pins the vetted port");
        assert_eq!(target.host(), HOST);
    }
    for port in [
        0u16, 1, 22, 25, 80, 443, 1190, 3306, 6379, 8080, 8443, 65535,
    ] {
        let cfg = vault::ProviderConfig { port, ..provider() };
        assert!(
            cfg.validate(&public).is_err(),
            "non-allowlisted port saved: {port}"
        );
        assert!(
            vault::authorize_pool_dial(HOST, port, &public).is_err(),
            "non-allowlisted port dialed: {port}"
        );
    }
}

#[test]
fn pool_dial_guard_rejects_bad_shape_and_private_targets_at_connect_time() {
    // The dial-site guard re-enforces the full invariant: DNS that changed
    // after save (now private) and malformed hosts fail even on allowlisted
    // ports.
    let public = dns(&["93.184.216.34"]);
    assert!(vault::authorize_pool_dial("https://service.example.com/", 563, &public).is_err());
    assert!(vault::authorize_pool_dial("", 563, &public).is_err());
    for private in [["10.0.0.5"], ["127.0.0.1"], ["::1"], ["2002:a00:1::1"]] {
        assert!(
            vault::authorize_pool_dial(HOST, 119, &dns(&private)).is_err(),
            "dial allowed a non-public target: {private:?}"
        );
    }
    let target = vault::authorize_pool_dial(HOST, 119, &public).unwrap();
    assert_eq!(target.addresses(), public.0);
}

#[test]
fn test_connection_rate_limit_and_concurrency_trip() {
    // F-VAULT-03 Gap 2: per-user sliding window + concurrency cap. The
    // timestamps here stand in for rows from the shared store (Postgres/KV);
    // the gate itself is pure so the Worker wiring stays thin.
    let recent: Vec<u64> = (0..5).map(|i| NOW - i).collect();
    assert!(
        !vault::test_attempt_allowed(&recent, NOW),
        "5 attempts in the window must trip the limit"
    );
    let four: Vec<u64> = (0..4).map(|i| NOW - i).collect();
    assert!(
        vault::test_attempt_allowed(&four, NOW),
        "4 attempts in the window must pass"
    );
    assert!(
        vault::test_attempt_allowed(&[NOW - 61, NOW - 3600], NOW),
        "attempts outside the window must age out"
    );
    assert!(
        vault::test_attempt_allowed(&[], NOW),
        "first attempt must pass"
    );
    assert!(
        !vault::test_attempt_allowed(&[NOW + 1000; 5], NOW),
        "future timestamps must fail closed, not bypass"
    );
    assert_eq!(vault::test_attempt_retention_cutoff(NOW), NOW - 60);
    assert_eq!(vault::test_attempt_retention_cutoff(30), 0);
    assert!(vault::concurrent_test_allowed(0));
    assert!(vault::concurrent_test_allowed(1));
    assert!(!vault::concurrent_test_allowed(2));
    assert!(!vault::concurrent_test_allowed(99));
}

#[test]
fn test_connection_budget_fires_dial_and_total_timeouts() {
    // F-VAULT-03 Gap 2: the dial/total constants must actually bound the
    // attempt. The pool aborts the handshake at the dial deadline and the
    // whole attempt at the total deadline.
    let budget = vault::TestConnectionBudget::new(1_000);
    assert_eq!(
        budget.dial_deadline_ms - budget.start_ms,
        vault::DIAL_TIMEOUT_MS
    );
    assert_eq!(
        budget.total_deadline_ms - budget.start_ms,
        vault::TOTAL_TIMEOUT_MS
    );
    assert!(!budget.dial_expired(1_000));
    assert!(!budget.dial_expired(5_999));
    assert!(budget.dial_expired(6_000));
    assert!(!budget.total_expired(15_999));
    assert!(budget.total_expired(16_000));
}

#[test]
fn targets_preserve_hostname_and_every_vetted_public_address() {
    let addresses = [
        "93.184.216.34",
        "8.8.8.8",
        "2001:4860:4860::8888",
        "2606:4700:4700::1111",
    ];
    let expected: Vec<IpAddr> = addresses.iter().map(|ip| ip.parse().unwrap()).collect();
    for target in [
        provider().validate(&dns(&addresses)).unwrap(),
        indexer().validate(&dns(&addresses)).unwrap(),
    ] {
        assert_eq!(target.host(), HOST, "retain hostname for TLS SNI/HTTP Host");
        assert_eq!(target.addresses(), expected, "no vetted address is dropped");
    }
}

// Independent HMAC fixture signer. It intentionally does not use the issuer,
// which clamps TTLs and therefore cannot produce the over-age regression token.
fn base64url(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

fn signed_session(created_at: u64, issued_at: u64, expires_at: u64) -> String {
    let payload = serde_json::json!({
        "session_id": "acceptance-session",
        "user_id": "user-acceptance",
        "created_at": created_at,
        "issued_at": issued_at,
        "expires_at": expires_at,
        "rotation_counter": 0
    });
    let encoded = base64url(&serde_json::to_vec(&payload).unwrap());
    let mut mac = Hmac::<Sha256>::new_from_slice(SECRET).unwrap();
    mac.update(encoded.as_bytes());
    format!("{encoded}.{}", base64url(&mac.finalize().into_bytes()))
}

#[test]
fn session_accepts_independently_signed_absolute_boundary_token() {
    let token = signed_session(NOW, NOW + ONE_DAY - 60, NOW + ONE_DAY);
    let claims = session::verify_session(SECRET, &token, NOW + ONE_DAY - 1)
        .expect("independent fixture is correctly signed and in bounds");
    assert_eq!(claims.created_at, NOW);
    assert_eq!(claims.expires_at, NOW + ONE_DAY);
    assert_eq!(claims.user_id, "user-acceptance");
}

#[test]
fn session_rejects_signed_expiry_beyond_authentication_age_limit() {
    // Issuance is fresh and its own TTL is only 61 seconds: authentication age,
    // not signature, current expiry, or issuance-relative TTL, must reject it.
    let token = signed_session(NOW, NOW + ONE_DAY - 60, NOW + ONE_DAY + 1);
    assert_eq!(
        session::verify_session(SECRET, &token, NOW + ONE_DAY - 30),
        Err(session::SessionError::Invalid)
    );
}

#[test]
fn session_expiry_boundary_is_exclusive() {
    let token = signed_session(NOW, NOW, NOW + ONE_DAY);
    assert!(session::verify_session(SECRET, &token, NOW + ONE_DAY - 1).is_ok());
    assert_eq!(
        session::verify_session(SECRET, &token, NOW + ONE_DAY),
        Err(session::SessionError::Invalid)
    );
    assert!(session::rotate_session(
        &session::SessionKeys::single(SECRET),
        &token,
        NOW + ONE_DAY,
        3600
    )
    .is_err());
}

#[test]
fn session_in_bounds_rotation_preserves_authentication_time() {
    let token = session::issue_session(SECRET, "user-acceptance", NOW, 3600).expect("issue");
    let original = session::verify_session(SECRET, &token, NOW).unwrap();
    let rotated = session::rotate_session(
        &session::SessionKeys::single(SECRET),
        &token,
        NOW + 60,
        3600,
    )
    .unwrap();
    let claims = session::verify_session(SECRET, &rotated, NOW + 60).unwrap();
    assert_eq!(claims.created_at, NOW);
    assert_eq!(claims.issued_at, NOW + 60);
    assert_eq!(claims.expires_at, NOW + 3660);
    assert_eq!(claims.rotation_counter, 1);
    assert_eq!(claims.session_id, original.session_id);
    assert_eq!(claims.user_id, "user-acceptance");
}

#[test]
fn session_rotation_clamps_expiry_to_absolute_lifetime() {
    let token = session::issue_session(SECRET, "user-acceptance", NOW, ONE_DAY).expect("issue");
    let rotated = session::rotate_session(
        &session::SessionKeys::single(SECRET),
        &token,
        NOW + ONE_DAY - 120,
        3600,
    )
    .unwrap();
    let verified = session::verify_session(SECRET, &rotated, NOW + ONE_DAY - 120);
    assert!(verified.is_ok(), "rotation must not emit an over-age token");
    let claims = verified.unwrap();
    assert_eq!(claims.created_at, NOW);
    assert_eq!(claims.expires_at, NOW + ONE_DAY);
}

#[test]
fn session_repeated_rotations_cannot_extend_one_day_lifetime() {
    let mut token = session::issue_session(SECRET, "user-acceptance", NOW, ONE_DAY).expect("issue");
    for (counter, offset) in [3600, 43_200, ONE_DAY - 1].into_iter().enumerate() {
        token = session::rotate_session(
            &session::SessionKeys::single(SECRET),
            &token,
            NOW + offset,
            ONE_DAY,
        )
        .unwrap();
        let verified = session::verify_session(SECRET, &token, NOW + offset);
        assert!(verified.is_ok(), "refresh must emit an in-bounds token");
        let claims = verified.unwrap();
        assert_eq!(claims.created_at, NOW, "authentication age never resets");
        assert_eq!(claims.expires_at, NOW + ONE_DAY);
        assert_eq!(claims.rotation_counter, counter as u32 + 1);
    }
    assert!(session::verify_session(SECRET, &token, NOW + ONE_DAY).is_err());
    assert!(session::rotate_session(
        &session::SessionKeys::single(SECRET),
        &token,
        NOW + ONE_DAY,
        ONE_DAY
    )
    .is_err());
}

fn active_session() -> (String, session::SessionRecord) {
    let token = session::issue_session(SECRET, "user-acceptance", NOW, 3600).expect("issue");
    let claims = session::verify_session(SECRET, &token, NOW).unwrap();
    let row = session::SessionRecord {
        id: claims.session_id,
        user_id: "user-acceptance".into(),
        created_at: NOW,
        expires_at: NOW + 3600,
        rotation_counter: 0,
        revoked: false,
    };
    (token, row)
}

#[test]
fn stored_session_accepts_matching_active_row() {
    let (token, row) = active_session();
    let claims = session::verify_stored_session(
        &session::SessionKeys::single(SECRET),
        &token,
        NOW + 60,
        &row,
    )
    .unwrap();
    assert_eq!(claims.user_id, "user-acceptance");
    assert_eq!(claims.expires_at, NOW + 3600);
}

#[test]
fn stored_session_rejects_stale_rotation_counter() {
    let (token, mut row) = active_session();
    row.rotation_counter = 1;
    assert_eq!(
        session::verify_stored_session(
            &session::SessionKeys::single(SECRET),
            &token,
            NOW + 60,
            &row
        ),
        Err(session::SessionError::Invalid)
    );
}

#[test]
fn stored_session_rejects_revoked_row() {
    let (token, mut row) = active_session();
    row.revoked = true;
    assert_eq!(
        session::verify_stored_session(
            &session::SessionKeys::single(SECRET),
            &token,
            NOW + 60,
            &row
        ),
        Err(session::SessionError::Invalid)
    );
}

#[test]
fn stored_session_rejects_mismatched_identity_and_expiry() {
    let (token, row) = active_session();
    for changed in [
        session::SessionRecord {
            user_id: "other-user".into(),
            ..row.clone()
        },
        session::SessionRecord {
            expires_at: NOW + 3599,
            ..row.clone()
        },
        session::SessionRecord {
            expires_at: NOW + 3601,
            ..row.clone()
        },
        session::SessionRecord {
            created_at: NOW - 1,
            ..row.clone()
        },
        session::SessionRecord {
            id: "other-session".into(),
            ..row.clone()
        },
    ] {
        assert_eq!(
            session::verify_stored_session(
                &session::SessionKeys::single(SECRET),
                &token,
                NOW + 60,
                &changed
            ),
            Err(session::SessionError::Invalid),
            "mismatched authoritative row: {changed:?}"
        );
    }
}

#[test]
fn stored_session_invalidates_pre_rotation_token_after_row_advances() {
    let (token, mut row) = active_session();
    let rotated = session::rotate_session(
        &session::SessionKeys::single(SECRET),
        &token,
        NOW + 60,
        3600,
    )
    .unwrap();
    row.rotation_counter = 1;
    row.expires_at = NOW + 3660;
    assert!(session::verify_stored_session(
        &session::SessionKeys::single(SECRET),
        &rotated,
        NOW + 60,
        &row
    )
    .is_ok());
    assert_eq!(
        session::verify_stored_session(
            &session::SessionKeys::single(SECRET),
            &token,
            NOW + 60,
            &row
        ),
        Err(session::SessionError::Invalid)
    );
    row.rotation_counter = 0;
    assert!(session::verify_stored_session(
        &session::SessionKeys::single(SECRET),
        &rotated,
        NOW + 60,
        &row
    )
    .is_err());
}

// Literal digests independently computed with SHA-256 over the UTF-8 fixtures.
const MAGIC_TOKEN: &str = "acceptance-magic-token";
const MAGIC_HASH: &str = "0b3af4fd85f42c8834c75383107f0b8cebf7e7acdce918cd1cf5b041b5ef22f6";
const INVITE_CODE: &str = "acceptance-invite-code";
const INVITE_HASH: &str = "b739f8df8d06f2e2ac37667f7d324d0852474ffa68d2c93ffd600e95049a1520";
const CHALLENGE_ID: &str = "synthetic-challenge-id";

fn magic_record() -> auth::MagicLinkRecord {
    auth::MagicLinkRecord {
        token_hash: MAGIC_HASH.into(),
        user_id: "user-acceptance".into(),
        email: "alice@example.com".into(),
        issued_at: NOW,
        expires_at: NOW + 900,
        used: false,
    }
}

fn challenge_record() -> auth::PasskeyChallenge {
    auth::PasskeyChallenge {
        id: CHALLENGE_ID.into(),
        rp_id: RP.into(),
        origin: ORIGIN.into(),
        issued_at: NOW,
        expires_at: NOW + 300,
        consumed: false,
    }
}

fn invite_record() -> auth::InviteRecord {
    auth::InviteRecord {
        code_hash: INVITE_HASH.into(),
        used: false,
        created_at: NOW,
    }
}

#[derive(Debug, PartialEq, Eq)]
enum CapturedClaim {
    MagicLink {
        digest: String,
        user: String,
        email: String,
        issued_at: u64,
        expires_at: u64,
        now: u64,
    },
    Challenge {
        id: String,
        rp: String,
        origin: String,
        issued_at: u64,
        expires_at: u64,
        now: u64,
    },
    Invite {
        digest: String,
        created_at: u64,
    },
}

struct RecordingStore {
    outcome: Result<u64, auth::AuthError>,
    claims: RefCell<Vec<CapturedClaim>>,
}

impl RecordingStore {
    fn new(outcome: Result<u64, auth::AuthError>) -> Self {
        Self {
            outcome,
            claims: RefCell::new(Vec::new()),
        }
    }
}

impl auth::SingleUseStore for RecordingStore {
    async fn claim(&self, candidate: auth::SingleUseClaim<'_>) -> Result<u64, auth::AuthError> {
        let captured = match candidate {
            auth::SingleUseClaim::MagicLink { record, now } => CapturedClaim::MagicLink {
                digest: record.token_hash.clone(),
                user: record.user_id.clone(),
                email: record.email.clone(),
                issued_at: record.issued_at,
                expires_at: record.expires_at,
                now,
            },
            auth::SingleUseClaim::Challenge { record, now } => CapturedClaim::Challenge {
                id: record.id.clone(),
                rp: record.rp_id.clone(),
                origin: record.origin.clone(),
                issued_at: record.issued_at,
                expires_at: record.expires_at,
                now,
            },
            auth::SingleUseClaim::Invite { record } => CapturedClaim::Invite {
                digest: record.code_hash.clone(),
                created_at: record.created_at,
            },
        };
        self.claims.borrow_mut().push(captured);
        self.outcome
    }
}

// The only awaited operation is our immediately-ready, in-memory store.
fn ready<F: Future>(future: F) -> F::Output {
    let mut future = std::pin::pin!(future);
    let mut context = std::task::Context::from_waker(std::task::Waker::noop());
    match future.as_mut().poll(&mut context) {
        Poll::Ready(result) => result,
        Poll::Pending => panic!("deterministic storage fake unexpectedly awaited external work"),
    }
}

#[test]
fn atomic_magic_link_requires_exactly_one_row_and_emits_bound_claim() {
    for outcome in [Ok(1), Ok(0), Ok(2), Err(auth::AuthError::Invalid)] {
        let store = RecordingStore::new(outcome);
        let result = ready(auth::consume_magic_link_atomically(
            magic_record(),
            MAGIC_TOKEN,
            NOW + 60,
            &store,
        ));
        if outcome == Ok(1) {
            let consumed = result.unwrap();
            assert_eq!(consumed.user_id, "user-acceptance");
            assert!(consumed.used_record.used);
        } else {
            assert!(result.is_err(), "claim must fail closed for {outcome:?}");
            assert_eq!(
                result.unwrap_err(),
                auth::AuthError::Invalid,
                "claim outcome: {outcome:?}"
            );
        }
        assert_eq!(
            *store.claims.borrow(),
            vec![CapturedClaim::MagicLink {
                digest: MAGIC_HASH.into(),
                user: "user-acceptance".into(),
                email: "alice@example.com".into(),
                issued_at: NOW,
                expires_at: NOW + 900,
                now: NOW + 60,
            }]
        );
    }
}

#[test]
fn atomic_challenge_requires_exactly_one_row_and_emits_bound_claim() {
    for outcome in [Ok(1), Ok(0), Ok(2), Err(auth::AuthError::Invalid)] {
        let store = RecordingStore::new(outcome);
        let result = ready(auth::consume_challenge_atomically(
            challenge_record(),
            RP,
            ORIGIN,
            NOW + 60,
            &store,
        ));
        if outcome == Ok(1) {
            assert!(result.unwrap().consumed);
        } else {
            assert!(result.is_err(), "claim must fail closed for {outcome:?}");
            assert_eq!(
                result.unwrap_err(),
                auth::AuthError::Invalid,
                "claim outcome: {outcome:?}"
            );
        }
        assert_eq!(
            *store.claims.borrow(),
            vec![CapturedClaim::Challenge {
                id: CHALLENGE_ID.into(),
                rp: RP.into(),
                origin: ORIGIN.into(),
                issued_at: NOW,
                expires_at: NOW + 300,
                now: NOW + 60,
            }]
        );
    }
}

#[test]
fn atomic_invite_requires_exactly_one_row_and_emits_digest_claim() {
    for outcome in [Ok(1), Ok(0), Ok(2), Err(auth::AuthError::Invalid)] {
        let store = RecordingStore::new(outcome);
        let result = ready(auth::consume_invite_atomically(
            invite_record(),
            INVITE_CODE,
            &store,
        ));
        if outcome == Ok(1) {
            assert!(result.unwrap().used);
        } else {
            assert!(result.is_err(), "claim must fail closed for {outcome:?}");
            assert_eq!(
                result.unwrap_err(),
                auth::AuthError::Invalid,
                "claim outcome: {outcome:?}"
            );
        }
        assert_eq!(
            *store.claims.borrow(),
            vec![CapturedClaim::Invite {
                digest: INVITE_HASH.into(),
                created_at: NOW
            }]
        );
    }
}

#[test]
fn claim_statements_are_conditional_parameterized_updates() {
    let magic = magic_record();
    let chal = challenge_record();
    let inv = invite_record();
    for (sql, flag, params) in [
        (
            auth::SingleUseClaim::MagicLink {
                record: &magic,
                now: NOW,
            }
            .statement(),
            "used = FALSE",
            5,
        ),
        (
            auth::SingleUseClaim::Challenge {
                record: &chal,
                now: NOW,
            }
            .statement(),
            "consumed = FALSE",
            5,
        ),
        (
            auth::SingleUseClaim::Invite { record: &inv }.statement(),
            "used = FALSE",
            1,
        ),
    ] {
        assert!(sql.starts_with("UPDATE "));
        let column = flag.trim_end_matches(" = FALSE");
        assert!(sql.contains(&format!("SET {column} = TRUE WHERE")), "{sql}");
        assert!(sql.contains(&format!("AND {flag} RETURNING")), "{sql}");
        for n in 1..=params {
            assert!(sql.contains(&format!("${n}")), "{sql}");
        }
        assert!(!sql.contains(&format!("${}", params + 1)), "{sql}");
    }
    assert!(auth::SingleUseClaim::MagicLink {
        record: &magic,
        now: NOW,
    }
    .statement()
    .contains("expires_at > $5"));
    assert!(auth::SingleUseClaim::Challenge {
        record: &chal,
        now: NOW,
    }
    .statement()
    .contains("rp_id = $2 AND origin = $3"));
}

#[test]
fn atomic_magic_link_invalid_inputs_never_reach_storage() {
    for (record, token, time) in [
        (magic_record(), "wrong-token", NOW + 60),
        (
            auth::MagicLinkRecord {
                used: true,
                ..magic_record()
            },
            MAGIC_TOKEN,
            NOW + 60,
        ),
        (magic_record(), MAGIC_TOKEN, NOW + 901),
    ] {
        let store = RecordingStore::new(Ok(1));
        let result = ready(auth::consume_magic_link_atomically(
            record, token, time, &store,
        ));
        assert_eq!(result.unwrap_err(), auth::AuthError::Invalid);
        assert!(
            store.claims.borrow().is_empty(),
            "invalid magic link reached storage"
        );
    }
}

#[test]
fn atomic_challenge_invalid_inputs_never_reach_storage() {
    for (record, rp, origin, time) in [
        (challenge_record(), "example.com", ORIGIN, NOW + 60),
        (challenge_record(), RP, "https://evil.example.com", NOW + 60),
        (
            challenge_record(),
            RP,
            "https://nntune.example.com/path",
            NOW + 60,
        ),
        (
            auth::PasskeyChallenge {
                consumed: true,
                ..challenge_record()
            },
            RP,
            ORIGIN,
            NOW + 60,
        ),
        (challenge_record(), RP, ORIGIN, NOW + 301),
    ] {
        let store = RecordingStore::new(Ok(1));
        let result = ready(auth::consume_challenge_atomically(
            record, rp, origin, time, &store,
        ));
        assert_eq!(result.unwrap_err(), auth::AuthError::Invalid);
        assert!(
            store.claims.borrow().is_empty(),
            "invalid challenge reached storage"
        );
    }
}

#[test]
fn atomic_invite_invalid_inputs_never_reach_storage() {
    for (record, code) in [
        (invite_record(), "wrong-code"),
        (
            auth::InviteRecord {
                used: true,
                ..invite_record()
            },
            INVITE_CODE,
        ),
    ] {
        let store = RecordingStore::new(Ok(1));
        let result = ready(auth::consume_invite_atomically(record, code, &store));
        assert_eq!(result.unwrap_err(), auth::AuthError::Invalid);
        assert!(
            store.claims.borrow().is_empty(),
            "invalid invite reached storage"
        );
    }
}

#[test]
fn origins_reject_noncanonical_forms_and_nonexact_rp_bindings() {
    for (rp, origin) in [
        (RP, "https://user@nntune.example.com"),
        (RP, "https://user:password@nntune.example.com"),
        (RP, "https://nntune.example.com/"),
        (RP, "https://nntune.example.com/path"),
        (RP, "https://nntune.example.com?query=yes"),
        (RP, "https://nntune.example.com#fragment"),
        (RP, "HTTPS://nntune.example.com"),
        (RP, "https://nntune.example.com:443"),
        ("example.com", ORIGIN),
        ("com", ORIGIN),
        ("nntune", "https://nntune"),
        ("", ORIGIN),
        ("localhost", "http://localhost:80"),
        (
            "localhost.evil.example.com",
            "http://localhost.evil.example.com:8787",
        ),
        ("localhost.evil.com", "http://localhost.evil.com"),
        ("evillocalhost", "http://evillocalhost:8787"),
        (
            "evil-localhost.example.com",
            "http://evil-localhost.example.com:8787",
        ),
        (
            "127.0.0.1.evil.example.com",
            "http://127.0.0.1.evil.example.com:8787",
        ),
        (RP, "http://nntune.example.com"),
    ] {
        assert_eq!(
            auth::new_registration_challenge(rp, origin, NOW).unwrap_err(),
            auth::AuthError::Invalid,
            "noncanonical origin/RP accepted: {rp:?}, {origin:?}"
        );
        // Present hostile origins/RP IDs against a valid, origin-bound
        // challenge; rejection must happen before a conditional storage claim.
        let record = challenge_record();
        let store = RecordingStore::new(Ok(1));
        assert_eq!(
            ready(auth::consume_challenge_atomically(
                record,
                rp,
                origin,
                NOW + 60,
                &store
            ))
            .unwrap_err(),
            auth::AuthError::Invalid
        );
        assert!(
            store.claims.borrow().is_empty(),
            "noncanonical origin reached storage"
        );
    }
}

#[test]
fn origins_accept_canonical_https_and_exact_loopback_http_hosts() {
    for (rp, origin) in [
        (RP, ORIGIN),
        (RP, "https://nntune.example.com:8443"),
        ("localhost", "http://localhost"),
        ("localhost", "http://localhost:8787"),
        ("127.0.0.1", "http://127.0.0.1"),
        ("127.0.0.1", "http://127.0.0.1:8787"),
        ("::1", "http://[::1]"),
        ("::1", "http://[::1]:8787"),
    ] {
        let challenge =
            auth::new_registration_challenge(rp, origin, NOW).expect("canonical origin accepted");
        assert_eq!(challenge.rp_id, rp);
        assert_eq!(challenge.origin, origin);
        let store = RecordingStore::new(Ok(1));
        let consumed = ready(auth::consume_challenge_atomically(
            challenge,
            rp,
            origin,
            NOW + 60,
            &store,
        ))
        .unwrap();
        assert!(consumed.consumed);
        match store.claims.borrow().as_slice() {
            [CapturedClaim::Challenge {
                rp: claimed_rp,
                origin: claimed_origin,
                now,
                ..
            }] => {
                assert_eq!(claimed_rp, rp);
                assert_eq!(claimed_origin, origin);
                assert_eq!(*now, NOW + 60);
            }
            other => panic!("expected exactly one origin-bound challenge claim, got {other:?}"),
        };
    }
}
