//! Acceptance tests for the accounts/auth/session/vault slice.
//!
//! Written first (TDD RED): these fail until `nntune_api` implements the
//! modules. Every test asserts real behavior; fixtures use synthetic
//! credentials only (public repo: never real secrets).

use nntune_api::{auth, session, vault};
use std::net::IpAddr;

// --- Sessions: signed cookies, rotation ------------------------------------

fn test_secret() -> Vec<u8> {
    b"test-session-secret-that-is-32-bytes!!".to_vec()
}

#[test]
fn session_roundtrip_and_cookie_attributes() {
    let secret = test_secret();
    let now = 1_700_000_000u64;
    let token = session::issue_session(&secret, "user-123", now, 3600).expect("issue");
    let claims = session::verify_session(&secret, &token, now + 60).expect("valid token");
    assert_eq!(claims.user_id, "user-123");
    assert_eq!(claims.rotation_counter, 0);
    // Revocation join key: every token carries a unique, non-empty session id.
    assert!(
        !claims.session_id.is_empty(),
        "jti present for row revocation"
    );
    let other = session::issue_session(&secret, "user-123", now, 3600).expect("issue");
    let other_claims = session::verify_session(&secret, &other, now + 60).expect("valid token");
    assert_ne!(
        claims.session_id, other_claims.session_id,
        "ids unique per session"
    );

    let header = session::set_cookie_header(&token, 3600);
    // F-HARD-01 item 2: `__Host-` prefix requirements — Path=/, Secure,
    // no Domain — are enforced by construction, not convention.
    assert!(
        header.starts_with("__Host-nntune-session="),
        "cookie must carry the __Host- prefix: {header}"
    );
    assert!(header.contains("HttpOnly"), "cookie must be HttpOnly");
    assert!(header.contains("Secure"), "cookie must be Secure");
    assert!(header.contains("Path=/"), "cookie must be Path=/");
    assert!(
        !header.contains("Domain="),
        "__Host- cookies must never carry Domain="
    );
    assert!(
        header.contains("SameSite=Lax"),
        "cookie must be SameSite=Lax"
    );
    assert!(!header.contains("SameSite=None"), "SameSite=None is banned");
    let cleared = session::clear_cookie_header();
    assert!(
        cleared.starts_with("__Host-nntune-session=;"),
        "logout must clear the same __Host- cookie: {cleared}"
    );
}

#[test]
fn session_tamper_rejected() {
    let secret = test_secret();
    let now = 1_700_000_000u64;
    let mut token = session::issue_session(&secret, "user-123", now, 3600).expect("issue");
    token.push('A');
    assert!(session::verify_session(&secret, &token, now + 60).is_err());
}

#[test]
fn session_wrong_secret_and_expiry_rejected() {
    let now = 1_700_000_000u64;
    let token = session::issue_session(&test_secret(), "user-123", now, 60).expect("issue");
    assert!(
        session::verify_session(b"wrong-secret-00000000000000000000", &token, now + 1).is_err()
    );
    assert!(session::verify_session(&test_secret(), &token, now + 61).is_err());
}

#[test]
fn session_rotation_bumps_counter_and_stays_valid() {
    let secret = test_secret();
    let now = 1_700_000_000u64;
    let token = session::issue_session(&secret, "user-123", now, 3600).expect("issue");
    let old_id = session::verify_session(&secret, &token, now + 5)
        .expect("valid token")
        .session_id;
    let rotated = session::rotate_session(
        &session::SessionKeys::single(&secret),
        &token,
        now + 10,
        3600,
    )
    .expect("rotation works");
    let claims = session::verify_session(&secret, &rotated, now + 20).expect("rotated valid");
    assert_eq!(claims.rotation_counter, 1);
    assert_eq!(claims.user_id, "user-123");
    assert_eq!(claims.session_id, old_id, "rotation keeps the row id");
}

// --- Auth: email magic link --------------------------------------------------

#[test]
fn magic_link_issue_consume_and_replay_rejected() {
    let now = 1_700_000_000u64;
    let (plaintext, record) = auth::issue_magic_link("user-1", "alice@example.com", now);
    // Hash at rest: the stored record must not contain the plaintext token.
    assert!(!record.token_hash.contains(&plaintext));
    let consumed = auth::consume_magic_link(record, &plaintext, now + 60).expect("first use works");
    assert_eq!(consumed.user_id, "user-1");
}

#[test]
fn magic_link_replay_rejected() {
    let now = 1_700_000_000u64;
    let (plaintext, record) = auth::issue_magic_link("user-1", "alice@example.com", now);
    let record2 = auth::consume_magic_link(record, &plaintext, now + 60)
        .expect("first use works")
        .into_record_for_replay_test();
    assert!(auth::consume_magic_link(record2, &plaintext, now + 61).is_err());
}

#[test]
fn magic_link_expired_and_wrong_token_rejected_with_generic_error() {
    let now = 1_700_000_000u64;
    let (plaintext, record) = auth::issue_magic_link("user-1", "alice@example.com", now);
    // >15 min: expired.
    let err = auth::consume_magic_link(record, &plaintext, now + 901).unwrap_err();
    assert_eq!(err, auth::AuthError::Invalid, "login errors stay generic");
    let (_, record2) = auth::issue_magic_link("user-1", "alice@example.com", now);
    let err2 = auth::consume_magic_link(record2, "wrong-token", now + 60).unwrap_err();
    assert_eq!(err2, auth::AuthError::Invalid, "no user-enumeration oracle");
}

// --- Auth: passkey challenge lifecycle ---------------------------------------

#[test]
fn passkey_challenge_origin_rp_expiry_single_use_enforced() {
    let now = 1_700_000_000u64;
    let c =
        auth::new_registration_challenge("nntune.example.com", "https://nntune.example.com", now)
            .expect("valid config");
    // Happy path: exact origin + rp match, fresh, first use.
    let c2 = auth::verify_and_consume_challenge(
        c,
        "nntune.example.com",
        "https://nntune.example.com",
        now + 60,
    )
    .expect("valid challenge");
    assert!(c2.consumed);
    // Replay: single-use.
    assert!(auth::verify_and_consume_challenge(
        c2,
        "nntune.example.com",
        "https://nntune.example.com",
        now + 61
    )
    .is_err());
    // Wrong origin / wrong rp rejected.
    let c3 =
        auth::new_registration_challenge("nntune.example.com", "https://nntune.example.com", now)
            .expect("valid config");
    assert!(auth::verify_and_consume_challenge(
        c3,
        "nntune.example.com",
        "https://evil.example.com",
        now + 60
    )
    .is_err());
    // Expired (5-min window).
    let c4 =
        auth::new_registration_challenge("nntune.example.com", "https://nntune.example.com", now)
            .expect("valid config");
    assert!(auth::verify_and_consume_challenge(
        c4,
        "nntune.example.com",
        "https://nntune.example.com",
        now + 301
    )
    .is_err());
}

#[test]
fn passkey_challenge_misconfiguration_rejected_without_panic() {
    let now = 1_700_000_000u64;
    // Empty RP id and non-https origins are generic rejections, never panics.
    assert!(auth::new_registration_challenge("", "https://nntune.example.com", now).is_err());
    assert!(
        auth::new_registration_challenge("nntune.example.com", "http://evil.example.com", now)
            .is_err()
    );
    assert!(auth::new_registration_challenge("nntune.example.com", "not-a-url", now).is_err());
    // Localhost http stays allowed for dev.
    assert!(auth::new_registration_challenge("localhost", "http://localhost:8787", now).is_ok());
}

// --- Vault: envelope encryption ----------------------------------------------

fn test_kek() -> [u8; 32] {
    [0x11u8; 32]
}

#[test]
fn vault_envelope_roundtrip() {
    let kek = test_kek();
    let plaintext = br#"{"host":"news.example.com","pass":"s3cret"}"#;
    let blob = vault::encrypt_vault(&kek, 1, "user-1", plaintext).expect("encrypt");
    assert_eq!(blob.kek_version, 1);
    let back = vault::decrypt_vault(&kek, "user-1", &blob).expect("decrypt");
    assert_eq!(back, plaintext);
}

#[test]
fn vault_user_binding_rejects_swapped_rows() {
    let kek = test_kek();
    let blob = vault::encrypt_vault(&kek, 1, "user-1", b"secret").expect("encrypt");
    // Ciphertext moved to another user's row must not decrypt (AAD binds user_id).
    assert!(vault::decrypt_vault(&kek, "user-2", &blob).is_err());
    // Wrong KEK must not decrypt.
    assert!(vault::decrypt_vault(&[0x22u8; 32], "user-1", &blob).is_err());
}

#[test]
fn vault_kek_rotation_rewraps_without_plaintext() {
    let old_kek = [0x11u8; 32];
    let new_kek = [0x33u8; 32];
    let blob = vault::encrypt_vault(&old_kek, 1, "user-1", b"secret").expect("encrypt");
    let rotated = vault::rewrap_dek(&old_kek, &new_kek, 2, "user-1", &blob).expect("rewrap");
    assert_eq!(rotated.kek_version, 2);
    assert_eq!(
        vault::decrypt_vault(&new_kek, "user-1", &rotated).expect("decrypt"),
        b"secret"
    );
    assert!(vault::decrypt_vault(&old_kek, "user-1", &rotated).is_err());
}

// --- Vault: validation + SSRF guard ------------------------------------------

struct FakeDns;
impl vault::DnsResolver for FakeDns {
    fn resolve(&self, host: &str) -> Vec<IpAddr> {
        match host {
            "news.example.com" => vec!["93.184.216.34".parse().unwrap()],
            "index.example.com" => vec!["93.184.216.34".parse().unwrap()],
            "internal.example.com" => vec!["10.0.0.5".parse().unwrap()],
            "loop.example.com" => vec!["127.0.0.1".parse().unwrap()],
            // Attacker-controlled name resolving to an IPv4-mapped IPv6
            // address hiding a private target: must still be rejected.
            "mapped.example.com" => vec!["::ffff:10.0.0.5".parse().unwrap()],
            "doc.example.com" => vec!["2001:db8::1".parse().unwrap()],
            _ => vec![],
        }
    }
}

#[test]
fn vault_config_validation() {
    let good = vault::ProviderConfig {
        host: "news.example.com".into(),
        port: 563,
        tls: true,
        username: "alice".into(),
        password: "s3cret".into(),
        max_connections: 10,
        allow_insecure_plaintext: false,
    };
    assert!(good.validate(&FakeDns).is_ok());
    let bad_port = vault::ProviderConfig {
        port: 0,
        ..good.clone()
    };
    assert!(bad_port.validate(&FakeDns).is_err());
    let bad_host = vault::ProviderConfig {
        host: "https://news.example.com/".into(),
        ..good.clone()
    };
    assert!(bad_host.validate(&FakeDns).is_err());
    let too_many = vault::ProviderConfig {
        max_connections: 500,
        ..good.clone()
    };
    assert!(too_many.validate(&FakeDns).is_err());
}

#[test]
fn vault_ssrf_guard_rejects_private_and_loopback() {
    let base = vault::ProviderConfig {
        host: "news.example.com".into(),
        port: 563,
        tls: true,
        username: "alice".into(),
        password: "s3cret".into(),
        max_connections: 4,
        allow_insecure_plaintext: false,
    };
    assert!(base.validate(&FakeDns).is_ok());
    for host in [
        "internal.example.com",
        "loop.example.com",
        "mapped.example.com",
        "doc.example.com",
        "10.1.2.3",
        "127.0.0.1",
        "169.254.169.254",
        "0.1.2.3",
        "100.64.0.1",
        "192.0.0.1",
        "198.18.0.1",
        "240.0.0.1",
        "::1",
        "",
        "evil.com/x",
        "http://evil.com",
    ] {
        let c = vault::ProviderConfig {
            host: host.into(),
            ..base.clone()
        };
        assert!(c.validate(&FakeDns).is_err(), "host rejected: {host}");
    }
}

#[test]
fn vault_indexer_url_has_ssrf_guard() {
    let good = vault::IndexerConfig {
        url: "https://index.example.com/api".into(),
        api_key: "idx-key".into(),
    };
    assert!(good.validate(&FakeDns).is_ok());
    for url in [
        "http://169.254.169.254/latest/meta-data/",
        "http://127.0.0.1:8080/",
        "http://10.0.0.5/",
        "http://[::ffff:127.0.0.1]/",
        "http://internal.example.com/",
        "ftp://index.example.com/",
        "not-a-url",
    ] {
        let c = vault::IndexerConfig {
            url: url.into(),
            api_key: "idx-key".into(),
        };
        assert!(c.validate(&FakeDns).is_err(), "indexer url rejected: {url}");
    }
}

#[test]
fn vault_indexer_requires_https_even_for_public_host() {
    // F-TRANS-01 Gap 1 (RED): `http://` to a public host must be Invalid —
    // the indexer API key would otherwise travel in cleartext.
    let plaintext = vault::IndexerConfig {
        url: "http://index.example.com/api".into(),
        api_key: "idx-key".into(),
    };
    assert!(
        plaintext.validate(&FakeDns).is_err(),
        "http indexer URL to a public host must be rejected"
    );
    let encrypted = vault::IndexerConfig {
        url: "https://index.example.com/api".into(),
        api_key: "idx-key".into(),
    };
    assert!(encrypted.validate(&FakeDns).is_ok());
}

#[test]
fn vault_provider_plaintext_password_requires_explicit_opt_in() {
    // F-TRANS-01 Gap 2: password auth with `tls: false` sends the password
    // in cleartext — rejected by default, accepted only with the explicit
    // per-row opt-in (flagged for the UI warning + audit log).
    let denied = vault::ProviderConfig {
        host: "news.example.com".into(),
        port: 119,
        tls: false,
        username: "alice".into(),
        password: "s3cret".into(),
        max_connections: 4,
        allow_insecure_plaintext: false,
    };
    assert!(
        denied.validate(&FakeDns).is_err(),
        "password auth without TLS must be rejected without the opt-in"
    );
    let acknowledged = vault::ProviderConfig {
        allow_insecure_plaintext: true,
        ..denied.clone()
    };
    assert!(
        acknowledged.validate(&FakeDns).is_ok(),
        "explicit opt-in passes validation"
    );
    assert!(acknowledged.insecure_plaintext_acknowledged());
    assert_eq!(
        acknowledged.audit_action(),
        vault::INSECURE_PLAINTEXT_AUDIT_ACTION
    );
    // TLS default stays unflagged.
    let tls = vault::ProviderConfig {
        tls: true,
        allow_insecure_plaintext: false,
        ..denied.clone()
    };
    assert!(tls.validate(&FakeDns).is_ok());
    assert!(!tls.insecure_plaintext_acknowledged());
}

#[test]
fn vault_responses_never_contain_secrets() {
    let summary = vault::redacted_summary(true, true, 1_700_000_000u64);
    let json = serde_json::to_string(&summary).unwrap();
    assert!(json.contains("provider_configured"));
    assert!(!json.contains("s3cret"), "no secret material in responses");
    // Audit events carry ids, results, and a real timestamp — never secrets.
    let now = 1_700_000_000u64;
    let ev = vault::audit_event("user-1", "vault.update", true, "203.0.113.7", now);
    assert_eq!(ev.at, now, "audit timestamp is the event time");
    let ev_json = serde_json::to_string(&ev).unwrap();
    assert!(!ev_json.contains("s3cret"));
}
