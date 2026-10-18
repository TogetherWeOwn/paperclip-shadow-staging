//! Enqueue-time dispatch: build [`QueueMsg`] values with user-bound idempotency.
//!
//! Routes validate the contract, then call the builders here and `send` the
//! result to the `INGEST_QUEUE` binding (see `wrangler.toml.example`). The
//! builders are pure so the idempotency story — same user + same content +
//! same source ref converges on one job — is unit-tested, not mocked.
//!
//! `user_id` is self-asserted until the accounts card authenticates callers;
//! the key format already binds the user so today's keys stay valid when
//! auth lands.

use sha2::{Digest, Sha256};

use crate::jobs::{derive_idempotency_key, JobSource, JobState};
use crate::newznab::{MAX_CATEGORIES, MAX_LIMIT, MAX_PAGE};
use crate::nzb_intake::estimate_nzb;
use crate::queue::{validate_indexer_ref, QueueMsg};

/// Queue binding name: must match `[[queues.producers]]` in
/// `wrangler.toml.example`.
pub const INGEST_QUEUE_BINDING: &str = "INGEST_QUEUE";
/// Queue name: must match `[[queues.producers]]` in `wrangler.toml.example`.
/// (The consumer entry stays commented out there until the Queue handler and
/// its dead-letter queue land.)
pub const INGEST_QUEUE_NAME: &str = "nntune-ingest-jobs";
/// KV binding holding uploaded NZB bytes keyed by [`payload_ref`](QueueMsg::payload_ref).
pub const PAYLOAD_KV_BINDING: &str = "INGEST_PAYLOADS";
/// Prefix for content-addressed upload payload keys (`nzb:sha256:<hex>`).
pub const PAYLOAD_KEY_PREFIX: &str = "nzb:sha256:";
/// Payload KV time-to-live: 30 days, comfortably longer than a full Queue
/// retention window plus consumer backoff. A payload stored before a failed
/// enqueue, or for a job that later fails or finishes, expires on its own —
/// and no consumer may delete on completion, because the key is shared by
/// every user and job that uploads the same bytes.
pub const PAYLOAD_TTL_SECS: u64 = 30 * 24 * 3_600;
/// Documented KV read lag the payload retry schedule must absorb: reads are
/// eventually consistent across locations (up to ~60 s), and a first-read
/// miss is cached at the edge for the `cacheTtl` window (default 60 s,
/// minimum 30 s) — a consumer that retries too fast keeps serving the cached
/// miss and fails a job whose bytes are stored.
pub const PAYLOAD_KV_READ_LAG_MS: u64 = 60_000;

/// Payload-fetch retries the consumer may spend: must match
/// `[[queues.consumers]] max_retries` in `wrangler.toml.example` (and
/// `jobs::MAX_ATTEMPTS - 1` redeliveries) so every retry has a slot.
pub const PAYLOAD_RETRY_ATTEMPTS: u32 = 4;

/// Ceiling for [`payload_retry_delay_ms`]: the longest single wait, equal to
/// [`PAYLOAD_KV_READ_LAG_MS`] so the tail retry lands after the cached miss
/// has expired.
pub const MAX_PAYLOAD_RETRY_DELAY_MS: u64 = 60_000;

/// Backoff for the Queue consumer's payload fetch: a KV miss right after the
/// route's write proves nothing (cross-location visibility lags and the miss
/// itself is edge-cached), so the consumer retries on this schedule instead
/// of failing the job: 5 s, 15 s, 30 s, 60 s (cumulative 110 s, covering the
/// documented ~60 s lag). Saturating, so any `u32` attempt maps to a sane
/// delay. Contract for the consumer card: fetch with the minimum `cacheTtl`
/// (30 s) so a cached miss expires before the later retries, and keep
/// `max_retries = PAYLOAD_RETRY_ATTEMPTS` so the full window is usable.
pub fn payload_retry_delay_ms(attempt: u32) -> u64 {
    match attempt {
        0 => 5_000,
        1 => 15_000,
        2 => 30_000,
        _ => MAX_PAYLOAD_RETRY_DELAY_MS,
    }
}

/// Self-asserted user handles are 1..=128 chars without `:` (the idempotency
/// key delimiter); the accounts card replaces this with the authenticated
/// subject without changing the key format.
pub fn validate_user_id(raw: &str) -> bool {
    !raw.is_empty() && raw.len() <= 128 && !raw.contains(':') && !raw.contains('\0')
}

/// Lowercase sha256 hex of canonical content bytes.
pub fn content_sha256_hex(canonical: &[u8]) -> String {
    hex::encode(Sha256::digest(canonical))
}

/// Deterministic job handle: `job_` + 16 hex chars of FNV-1a64 over the
/// idempotency material, so redelivered enqueues converge on one job row.
/// Provisional until Hyperdrive assigns row ids; always URL-safe.
pub fn make_job_id(user_id: &str, content_sha256_hex: &str, source_ref: &str) -> String {
    let mut h: u64 = 0xcbf29ce484222325;
    for b in user_id
        .bytes()
        .chain(content_sha256_hex.bytes())
        .chain(source_ref.bytes())
    {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    format!("job_{h:016x}")
}

fn dispatch(
    user_id: &str,
    content_sha: &str,
    source_ref: &str,
    source: JobSource,
) -> Result<QueueMsg, &'static str> {
    if !validate_user_id(user_id) {
        return Err("user id must be 1..=128 chars without ':'");
    }
    let idempotency_key = derive_idempotency_key(user_id, content_sha, source_ref)?;
    Ok(QueueMsg {
        job_id: make_job_id(user_id, content_sha, source_ref),
        user_id: user_id.to_string(),
        idempotency_key,
        source,
        state: JobState::Queued,
        attempt: 1,
        repair_rounds: 0,
        query: None,
        indexer_ref: None,
        categories: vec![],
        limit: None,
        page: None,
        payload_ref: None,
    })
}

/// Build the enqueue message for `POST /v1/ingest/search`.
///
/// The message carries the full search input (query, indexer handle,
/// categories, limit, page) so the consumer can run it with no second fetch.
/// The idempotency key and job id bind *all* of those: page 1 and page 2 of
/// one query — or one query in different categories — are different jobs.
///
/// The GUID is unknown until the workflow's `Searching` step runs, so the
/// source ref binds the indexer handle plus the request parameters (in
/// colon-free form); the workflow re-keys on the GUID before `Parsing`.
pub fn build_search_dispatch(
    user_id: &str,
    query: &str,
    indexer_ref: &str,
    categories: &[u32],
    limit: u32,
    page: u32,
) -> Result<QueueMsg, &'static str> {
    let q = query.trim();
    if q.is_empty() || q.len() > 200 {
        return Err("query must be 1..=200 chars");
    }
    if !validate_indexer_ref(indexer_ref) {
        return Err("indexer_ref must be a vault handle");
    }
    if categories.len() > MAX_CATEGORIES {
        return Err("too many categories (max 16)");
    }
    if limit == 0 || limit > MAX_LIMIT {
        return Err("limit must be 1..=100");
    }
    if page > MAX_PAGE {
        return Err("page out of range");
    }
    // Order-independent: the same set in a different order is the same job.
    let mut cats = categories.to_vec();
    cats.sort_unstable();
    let cats_str = cats
        .iter()
        .map(|c| c.to_string())
        .collect::<Vec<_>>()
        .join(",");
    let canonical = format!("search:{indexer_ref}:{q}:cats={cats_str}:limit={limit}:page={page}");
    let sha = content_sha256_hex(canonical.as_bytes());
    let source_ref = format!("search/{indexer_ref}/p{page}l{limit}/c{cats_str}");
    if source_ref.len() > 512 {
        return Err("source ref must be 1..=512 chars");
    }
    let mut msg = dispatch(user_id, &sha, &source_ref, JobSource::IndexerSearch)?;
    msg.query = Some(q.to_string());
    msg.indexer_ref = Some(indexer_ref.to_string());
    msg.categories = cats;
    msg.limit = Some(limit);
    msg.page = Some(page);
    Ok(msg)
}

/// Build the enqueue message for `POST /v1/ingest/nzb`.
///
/// Runs the intake guard first so oversize/non-NZB bytes never reach the
/// Queue, let alone provider connections. The message carries a
/// content-addressed [`payload_ref`](QueueMsg::payload_ref); the route
/// writes the bytes to the payload KV under that key before enqueueing
/// (the bytes cannot ride in the Queue message: 2 MiB vs the 128 KB limit).
///
/// An NZB with no files or segments is rejected here, not enqueued: it
/// yields zero probe batches, so no outcome would ever arrive and the job
/// would sit in `Probing` forever.
pub fn build_upload_dispatch(user_id: &str, nzb_xml: &str) -> Result<QueueMsg, &'static str> {
    let est = estimate_nzb(nzb_xml).map_err(|_| "nzb_xml failed the intake guard")?;
    if est.file_count == 0 || est.segment_count == 0 {
        return Err("nzb has no files or segments to probe");
    }
    let sha = content_sha256_hex(nzb_xml.as_bytes());
    let mut msg = dispatch(user_id, &sha, "upload", JobSource::NzbUpload)?;
    msg.payload_ref = Some(format!("{PAYLOAD_KEY_PREFIX}{sha}"));
    Ok(msg)
}

#[cfg(test)]
mod tests {
    use super::*;

    const USER: &str = "user_01";
    const INDEXER: &str = "vault_idx_01-ab";

    fn search(user: &str, query: &str, indexer: &str) -> QueueMsg {
        build_search_dispatch(user, query, indexer, &[], 25, 0).unwrap()
    }

    #[test]
    fn search_dispatch_binds_user_content_and_indexer() {
        let a = search(USER, "dark side", INDEXER);
        let b = search(USER, "dark side", INDEXER);
        assert_eq!(a, b);
        assert!(a.idempotency_key.starts_with("ingest:user_01:"));
        assert!(a.job_id.starts_with("job_"));
        assert_eq!(a.state, crate::jobs::JobState::Queued);
        assert_eq!(a.attempt, 1);
        assert_eq!(a.source, crate::jobs::JobSource::IndexerSearch);
        // The consumer can run the job from the message alone.
        assert_eq!(a.query.as_deref(), Some("dark side"));
        assert_eq!(a.indexer_ref.as_deref(), Some(INDEXER));
        assert_eq!((a.limit, a.page), (Some(25), Some(0)));
        assert!(a.payload_ref.is_none());
    }

    #[test]
    fn search_dispatch_separates_users_and_queries() {
        let a = search(USER, "dark side", INDEXER);
        let other_user = search("user_02", "dark side", INDEXER);
        let other_query = search(USER, "kind of blue", INDEXER);
        assert_ne!(a.idempotency_key, other_user.idempotency_key);
        assert_ne!(a.idempotency_key, other_query.idempotency_key);
        assert_ne!(a.job_id, other_user.job_id);
    }

    #[test]
    fn search_dispatch_separates_pages_categories_and_limits() {
        // Same query, different page: different jobs (no silent drop after
        // the first request). Same for categories and limit.
        let p0 = build_search_dispatch(USER, "dark side", INDEXER, &[], 25, 0).unwrap();
        let p1 = build_search_dispatch(USER, "dark side", INDEXER, &[], 25, 1).unwrap();
        assert_ne!(p0.idempotency_key, p1.idempotency_key);
        assert_ne!(p0.job_id, p1.job_id);
        let c0 = build_search_dispatch(USER, "dark side", INDEXER, &[], 25, 0).unwrap();
        let c1 = build_search_dispatch(USER, "dark side", INDEXER, &[3000], 25, 0).unwrap();
        assert_ne!(c0.idempotency_key, c1.idempotency_key);
        let l0 = build_search_dispatch(USER, "dark side", INDEXER, &[], 25, 0).unwrap();
        let l1 = build_search_dispatch(USER, "dark side", INDEXER, &[], 50, 0).unwrap();
        assert_ne!(l0.idempotency_key, l1.idempotency_key);
        // Category order is irrelevant: same set, same job.
        let o1 = build_search_dispatch(USER, "q", INDEXER, &[3040, 3000], 10, 0).unwrap();
        let o2 = build_search_dispatch(USER, "q", INDEXER, &[3000, 3040], 10, 0).unwrap();
        assert_eq!(o1, o2);
    }

    #[test]
    fn search_dispatch_rejects_bad_inputs() {
        let bad_user = |u: &str| build_search_dispatch(u, "q", INDEXER, &[], 10, 0).is_err();
        assert!(bad_user(""));
        assert!(build_search_dispatch(USER, "", INDEXER, &[], 10, 0).is_err());
        assert!(build_search_dispatch(USER, &"x".repeat(201), INDEXER, &[], 10, 0).is_err());
        assert!(
            build_search_dispatch(USER, "q", "https://indexer.example?apikey=x", &[], 10, 0)
                .is_err()
        );
        assert!(build_search_dispatch(USER, "q", "", &[], 10, 0).is_err());
        assert!(build_search_dispatch(USER, "q", INDEXER, &[0; 17], 10, 0).is_err());
        assert!(build_search_dispatch(USER, "q", INDEXER, &[], 0, 0).is_err());
        assert!(build_search_dispatch(USER, "q", INDEXER, &[], 101, 0).is_err());
        assert!(build_search_dispatch(USER, "q", INDEXER, &[], 10, 101).is_err());
        // ':' would collide idempotency fields.
        assert!(bad_user("user:01"));
    }

    #[test]
    fn upload_dispatch_binds_nzb_bytes() {
        let nzb = crate::fixtures::SMALL_NZB;
        let a = build_upload_dispatch(USER, nzb).unwrap();
        let b = build_upload_dispatch(USER, nzb).unwrap();
        assert_eq!(a, b);
        assert_eq!(a.source, crate::jobs::JobSource::NzbUpload);
        assert!(a.idempotency_key.starts_with("ingest:user_01:"));
        assert!(a.idempotency_key.ends_with(":upload"));
        // Content-addressed payload handle for the route's KV write; the
        // search input stays empty on upload jobs.
        let payload = a.payload_ref.expect("upload must carry a payload ref");
        assert!(payload.starts_with(PAYLOAD_KEY_PREFIX));
        assert!(a.query.is_none());
    }

    #[test]
    fn upload_dispatch_refuses_unguarded_bytes() {
        assert!(build_upload_dispatch(USER, "").is_err());
        assert!(build_upload_dispatch(USER, "<html>not nzb</html>").is_err());
        assert!(build_upload_dispatch("", crate::fixtures::SMALL_NZB).is_err());
    }

    #[test]
    fn job_id_is_url_safe_and_stable() {
        let sha = "a".repeat(64);
        let a = make_job_id(USER, &sha, "upload");
        let b = make_job_id(USER, &sha, "upload");
        assert_eq!(a, b);
        assert!(a.starts_with("job_"));
        assert!(crate::jobs::validate_job_id(&a));
        assert_ne!(a, make_job_id("user_02", &sha, "upload"));
    }

    #[test]
    fn payload_ttl_outlives_queue_retention() {
        // Payload bytes must survive a full Queue retention window plus
        // consumer backoff; otherwise the consumer fetches a miss for a
        // live job and fails work that was already accepted.
        const {
            assert!(PAYLOAD_TTL_SECS >= 7 * 24 * 3_600);
        }
    }

    #[test]
    fn payload_retry_backoff_is_bounded_and_increasing() {
        // The consumer retries a KV miss against this schedule instead of
        // failing the job: KV reads are eventually consistent across
        // locations (~60 s), and a first-read miss is cached at the edge for
        // the cacheTtl window, so the cumulative delay across the allowed
        // retries must cover the documented lag.
        assert_eq!(payload_retry_delay_ms(0), 5_000);
        assert_eq!(payload_retry_delay_ms(1), 15_000);
        assert_eq!(payload_retry_delay_ms(2), 30_000);
        assert_eq!(payload_retry_delay_ms(3), 60_000);
        let d0 = payload_retry_delay_ms(0);
        let d1 = payload_retry_delay_ms(1);
        let d2 = payload_retry_delay_ms(2);
        let d3 = payload_retry_delay_ms(3);
        assert!(d1 > d0);
        assert!(d2 > d1);
        assert!(d3 > d2);
        for attempt in 0..32 {
            assert!(payload_retry_delay_ms(attempt) <= MAX_PAYLOAD_RETRY_DELAY_MS);
        }
        assert_eq!(
            payload_retry_delay_ms(1_000_000),
            MAX_PAYLOAD_RETRY_DELAY_MS
        );
        // Retry budget matches the Queue consumer's max_retries and the
        // job-level attempt budget (MAX_ATTEMPTS - 1 redeliveries).
        assert_eq!(PAYLOAD_RETRY_ATTEMPTS, 4);
        assert_eq!(PAYLOAD_RETRY_ATTEMPTS, crate::jobs::MAX_ATTEMPTS - 1);
        // Cumulative delay across the allowed retries covers the documented
        // KV read lag, so a job whose bytes are stored is not failed on a
        // cached miss (5 + 15 + 30 + 60 = 110 s >= 60 s).
        let total: u64 = (0..PAYLOAD_RETRY_ATTEMPTS)
            .map(payload_retry_delay_ms)
            .sum();
        assert!(
            total >= PAYLOAD_KV_READ_LAG_MS,
            "payload retry window {total}ms must cover KV lag {PAYLOAD_KV_READ_LAG_MS}ms"
        );
    }

    #[test]
    fn upload_dispatch_rejects_zero_segment_nzb() {
        // An NZB with no files or segments yields zero probe batches, so no
        // outcome ever arrives and the job would sit in Probing forever.
        assert!(build_upload_dispatch(USER, "<nzb></nzb>").is_err());
        assert!(build_upload_dispatch(USER, "<nzb>  </nzb>").is_err());
    }

    #[test]
    fn binding_names_match_wrangler_example() {
        assert_eq!(INGEST_QUEUE_BINDING, "INGEST_QUEUE");
        assert_eq!(INGEST_QUEUE_NAME, "nntune-ingest-jobs");
        assert_eq!(PAYLOAD_KV_BINDING, "INGEST_PAYLOADS");
    }
}
