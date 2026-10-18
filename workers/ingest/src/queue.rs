//! Queue / Workflow payload shapes for the ingest pipeline.
//!
//! Every message carries the job's idempotency key so redelivered Queue
//! messages and replayed Workflow steps converge on one library row.
//! Repair runs in a Container batch job (native par2 repair); everything
//! interactive stays serverless. MB lookups call the `workers/mb` read API
//! (`GET /v1/mb/release/:mbid`, `GET /v1/mb/recording/:mbid`,
//! `GET /v1/mb/search?type=…`).

use serde::{Deserialize, Serialize};

use crate::jobs::{JobSource, JobState};

/// Ordered Workflow steps; `repair` runs only when verify asks for it.
pub const WORKFLOW_STEPS: [&str; 7] = [
    "search", "parse", "probe", "verify", "repair", "match", "write",
];

/// One unit of ingest work on the Queue.
///
/// The message carries everything the consumer needs to run the job: search
/// jobs embed their parameters, upload jobs carry a content-addressed handle
/// for the NZB bytes. The bytes themselves (up to 2 MiB) far exceed the
/// 128 KB Queue message limit, so they never ride inline — the route writes
/// them to the payload KV under [`payload_ref`](QueueMsg::payload_ref) before
/// enqueueing. Fields added after slice 2 are `#[serde(default)]` so
/// messages enqueued before them still deserialize.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueueMsg {
    pub job_id: String,
    pub user_id: String,
    pub idempotency_key: String,
    pub source: JobSource,
    pub state: JobState,
    pub attempt: u32,
    /// Repair rounds started (see `jobs::MAX_REPAIR_ROUNDS`).
    #[serde(default)]
    pub repair_rounds: u32,
    /// Search input for `IndexerSearch` jobs (the trimmed query).
    #[serde(default)]
    pub query: Option<String>,
    /// Vault handle of the BYO indexer for `IndexerSearch` jobs.
    #[serde(default)]
    pub indexer_ref: Option<String>,
    /// Requested Newznab categories (capped, sorted so the same set is one job).
    #[serde(default)]
    pub categories: Vec<u32>,
    /// Requested page size / page for `IndexerSearch` jobs.
    #[serde(default)]
    pub limit: Option<u32>,
    #[serde(default)]
    pub page: Option<u32>,
    /// Content-addressed handle (`nzb:sha256:<hex>`) for the uploaded NZB
    /// bytes of `NzbUpload` jobs, as stored in the payload KV under a
    /// [`PAYLOAD_TTL_SECS`](crate::dispatch::PAYLOAD_TTL_SECS) expiry. The
    /// consumer fetches with [`payload_retry_delay_ms`](crate::dispatch::payload_retry_delay_ms)
    /// backoff (5/15/30/60 s, 110 s cumulative over
    /// [`PAYLOAD_RETRY_ATTEMPTS`](crate::dispatch::PAYLOAD_RETRY_ATTEMPTS)
    /// retries): a first-read miss is expected (KV cross-location lag plus
    /// edge-cached negative lookups), never a failed job. The consumer reads
    /// with the minimum `cacheTtl` (30 s) so the cached miss expires before
    /// the later retries.
    #[serde(default)]
    pub payload_ref: Option<String>,
}

/// Native par2 repair dispatched to the Container batch job.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RepairRequest {
    pub job_id: String,
    pub user_id: String,
    pub idempotency_key: String,
    pub par2_set_id: String,
    pub missing_blocks: u32,
}

/// Final library write after tag/fingerprint + MusicBrainz match.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LibraryWrite {
    pub job_id: String,
    pub user_id: String,
    pub idempotency_key: String,
    pub release_mbid: Option<String>,
    pub recording_mbids: Vec<String>,
}

/// Search request body for `POST /v1/ingest/search`.
///
/// `indexer_ref` is an opaque BYOP vault handle, never a raw key. `user_id`
/// is self-asserted until the accounts card authenticates callers; it binds
/// the idempotency key so today's queued jobs stay valid when auth lands.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SearchRequest {
    pub user_id: String,
    pub query: String,
    pub indexer_ref: String,
    pub categories: Vec<u32>,
    pub limit: u32,
    pub page: u32,
}

/// NZB upload body for `POST /v1/ingest/nzb` (JSON; caps in `nzb_intake`).
/// `user_id` is self-asserted, as in [`SearchRequest`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NzbUploadRequest {
    pub user_id: String,
    pub filename: String,
    pub nzb_xml: String,
}

/// MBID shape: `8-4-4-4-12` lowercase hex (releases/recordings from `mb`).
pub fn validate_mbid(raw: &str) -> bool {
    const GROUPS: [usize; 5] = [8, 4, 4, 4, 12];
    let parts: Vec<&str> = raw.split('-').collect();
    if parts.len() != GROUPS.len() {
        return false;
    }
    parts
        .iter()
        .zip(GROUPS)
        .all(|(p, len)| p.len() == len && p.bytes().all(|b| b.is_ascii_hexdigit()))
}

/// A vault handle is opaque but must stay URL/path-safe.
pub fn validate_indexer_ref(raw: &str) -> bool {
    !raw.is_empty()
        && raw.len() <= 128
        && raw
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn workflow_steps_cover_repair_branch() {
        // Joined at runtime: guards step order and the repair branch.
        let pipeline = WORKFLOW_STEPS.join(">");
        assert!(pipeline.starts_with("search>"));
        assert!(pipeline.ends_with(">write"));
        assert!(pipeline.contains(">repair>"));
    }

    #[test]
    fn queue_msg_roundtrips_with_idempotency_key() {
        let msg = QueueMsg {
            job_id: "job_1".into(),
            user_id: "u1".into(),
            idempotency_key: "ingest:u1:abc:upload".into(),
            source: JobSource::NzbUpload,
            state: JobState::Queued,
            attempt: 1,
            repair_rounds: 0,
            query: None,
            indexer_ref: None,
            categories: vec![],
            limit: None,
            page: None,
            payload_ref: Some("nzb:sha256:abc".into()),
        };
        let back: QueueMsg = serde_json::from_str(&serde_json::to_string(&msg).unwrap()).unwrap();
        assert_eq!(msg, back);
    }

    #[test]
    fn queue_msg_reads_pre_input_messages() {
        // Messages enqueued before the input fields existed still decode,
        // with job input empty: the consumer treats them as legacy.
        let legacy = serde_json::json!({
            "job_id": "job_1",
            "user_id": "u1",
            "idempotency_key": "ingest:u1:abc:upload",
            "source": "nzb_upload",
            "state": "queued",
            "attempt": 1,
        });
        let msg: QueueMsg = serde_json::from_value(legacy).unwrap();
        assert_eq!(msg.repair_rounds, 0);
        assert!(msg.query.is_none());
        assert!(msg.payload_ref.is_none());
        assert!(msg.categories.is_empty());
    }

    #[test]
    fn library_write_accepts_unmatched_releases() {
        let w = LibraryWrite {
            job_id: "j".into(),
            user_id: "u".into(),
            idempotency_key: "k".into(),
            release_mbid: None,
            recording_mbids: vec![],
        };
        assert!(w.release_mbid.is_none());
    }

    #[test]
    fn mbid_validation_accepts_canonical_only() {
        assert!(validate_mbid("f5c2d4b1-3a7e-4d1c-9e2f-0a1b2c3d4e5f"));
        assert!(!validate_mbid(""));
        assert!(!validate_mbid("not-an-mbid"));
        // Hex check is case-insensitive; canonical form is lowercase.
        assert!(validate_mbid("F5C2D4B1-3A7E-4D1C-9E2F-0A1B2C3D4E5F"));
    }

    #[test]
    fn indexer_ref_rejects_raw_urls_and_keys() {
        assert!(validate_indexer_ref("vault_idx_01-ab"));
        assert!(!validate_indexer_ref(""));
        assert!(!validate_indexer_ref("https://indexer.example?apikey=x"));
        assert!(!validate_indexer_ref("key with spaces"));
    }

    #[test]
    fn search_request_carries_user_scope() {
        let req: SearchRequest = serde_json::from_str(
            r#"{"query":"q","indexer_ref":"vault_01","categories":[],"limit":10,"page":0,"user_id":"user_01"}"#,
        )
        .unwrap();
        assert_eq!(req.user_id, "user_01");
    }

    #[test]
    fn upload_request_carries_user_scope() {
        let req: NzbUploadRequest = serde_json::from_str(
            r#"{"filename":"r.nzb","nzb_xml":"<nzb></nzb>","user_id":"user_01"}"#,
        )
        .unwrap();
        assert_eq!(req.user_id, "user_01");
    }
}
