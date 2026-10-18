//! User-scoped ingest job state machine: idempotent and resumable.
//!
//! A job moves `Queued -> Searching|Parsing -> Probing -> Verifying
//! -> (Repairing -> Verifying)? -> Matching -> Writing -> Done`.
//! Any step may move to `Failed` with a reason; `Done`/`Failed` are
//! terminal. Workers persist the [`JobCheckpoint`] after every step, so a
//! crashed or evicted run resumes from the last checkpoint instead of
//! restarting (Queue redelivery + Workflow step replay both converge here).

use serde::{Deserialize, Serialize};

use crate::probe::ProbeTally;

/// How many times a single job may attempt a step before it is `Failed`.
pub const MAX_ATTEMPTS: u32 = 5;

/// How many `Verifying -> Repairing` rounds one job may start before a
/// still-failing verify fails the job instead of dispatching another paid
/// Container repair (see [`advance_checkpoint`]).
pub const MAX_REPAIR_ROUNDS: u32 = 3;

/// All ingest stages. Serialized snake_case for Queue/Workflow payloads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JobState {
    Queued,
    Searching,
    Parsing,
    Probing,
    Verifying,
    Repairing,
    Matching,
    Writing,
    Done,
    Failed,
}

/// How the job's NZB entered the pipeline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JobSource {
    IndexerSearch,
    NzbUpload,
}

/// Durable resume point written after every completed step.
///
/// `attempt` is the Queue-delivery attempt (1-based): the consumer increments
/// it on redelivery and [`can_retry`] gates another try. [`advance`] never
/// touches it, so per-state retries cannot silently reset the job-level
/// budget. `repair_rounds` counts started `Verifying -> Repairing` rounds and
/// bounds the verify↔repair loop (see [`advance_checkpoint`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobCheckpoint {
    pub job_id: String,
    pub user_id: String,
    pub idempotency_key: String,
    pub source: JobSource,
    pub state: JobState,
    pub attempt: u32,
    /// Repair rounds started so far. `#[serde(default)]` keeps checkpoints
    /// written before this field existed readable (they resume with 0).
    #[serde(default)]
    pub repair_rounds: u32,
    /// Probe answers collected while `Probing`, keyed by batch index (see
    /// [`ProbeTally`](crate::probe::ProbeTally)). `None` outside `Probing`;
    /// `#[serde(default)]` keeps pre-tally checkpoints readable (a crash
    /// before this field existed resumes probing from batch zero).
    #[serde(default)]
    pub probe_tally: Option<ProbeTally>,
    pub failure_reason: Option<String>,
}

/// Advance one step on success. `repair_needed` is only read in `Verifying`.
pub fn advance(state: JobState, source: JobSource, repair_needed: bool) -> JobState {
    match state {
        JobState::Queued => match source {
            JobSource::IndexerSearch => JobState::Searching,
            JobSource::NzbUpload => JobState::Parsing,
        },
        JobState::Searching => JobState::Parsing,
        JobState::Parsing => JobState::Probing,
        JobState::Probing => JobState::Verifying,
        JobState::Verifying => {
            if repair_needed {
                JobState::Repairing
            } else {
                JobState::Matching
            }
        }
        JobState::Repairing => JobState::Verifying,
        JobState::Matching => JobState::Writing,
        JobState::Writing => JobState::Done,
        JobState::Done => JobState::Done,
        JobState::Failed => JobState::Failed,
    }
}

/// Advance a checkpointed job one step, bounding the verify↔repair loop.
///
/// Every transition except `Verifying` with `repair_needed` delegates to
/// [`advance`]. A repair start increments `repair_rounds` and moves to
/// `Repairing` while `repair_rounds < MAX_REPAIR_ROUNDS`; once the budget is
/// spent the job moves to `Failed` with `failure_reason` set instead of
/// dispatching another Container repair. A par2 set with too few recovery
/// blocks therefore terminates instead of cycling forever. `attempt` is left
/// alone (it belongs to Queue redelivery, not to in-job loops).
pub fn advance_checkpoint(cp: &mut JobCheckpoint, repair_needed: bool) -> JobState {
    match cp.state {
        JobState::Verifying if repair_needed => {
            if cp.repair_rounds >= MAX_REPAIR_ROUNDS {
                cp.failure_reason = Some("repair budget exhausted".to_string());
                cp.state = JobState::Failed;
            } else {
                cp.repair_rounds += 1;
                cp.state = JobState::Repairing;
            }
        }
        _ => {
            cp.state = advance(cp.state, cp.source, repair_needed);
        }
    }
    cp.state
}

/// Move to `Failed`, unless already terminal (terminal states stick).
pub fn fail(state: JobState) -> JobState {
    match state {
        JobState::Done | JobState::Failed => state,
        _ => JobState::Failed,
    }
}

/// Terminal states need no further work and free the user's job slot.
pub fn is_terminal(state: JobState) -> bool {
    matches!(state, JobState::Done | JobState::Failed)
}

/// True when another attempt is allowed (`attempt` is 1-based).
pub fn can_retry(attempt: u32) -> bool {
    (1..MAX_ATTEMPTS).contains(&attempt)
}

/// Build the idempotency key for a job: `ingest:{user}:{sha}:{ref}`.
///
/// - `content_sha256_hex`: sha256 of the canonical NZB bytes (upload) or of
///   the indexer's GUID URL (search); 64 hex chars, case-insensitive on input
///   and normalised to lowercase in the key.
/// - `source_ref`: `"upload"` or the indexer-bound search ref, binding the key
///   to the exact release so a retry of the same content reuses the job row.
///
/// `:` is the field delimiter, so `user_id` and `source_ref` must not contain
/// it (nor NUL): without that check two different
/// `(user, sha, ref)` triples can format to the same key and two unrelated
/// jobs would converge on one library row.
pub fn derive_idempotency_key(
    user_id: &str,
    content_sha256_hex: &str,
    source_ref: &str,
) -> Result<String, &'static str> {
    if user_id.is_empty() || user_id.len() > 128 {
        return Err("user id must be 1..=128 chars");
    }
    if user_id.contains(':') || user_id.contains('\0') {
        return Err("user id must not contain ':'");
    }
    let hex_ok =
        content_sha256_hex.len() == 64 && content_sha256_hex.bytes().all(|b| b.is_ascii_hexdigit());
    if !hex_ok {
        return Err("content sha256 must be 64 hex chars");
    }
    if source_ref.is_empty() || source_ref.len() > 512 {
        return Err("source ref must be 1..=512 chars");
    }
    if source_ref.contains(':') || source_ref.contains('\0') {
        return Err("source ref must not contain ':'");
    }
    Ok(format!(
        "ingest:{user_id}:{}:{source_ref}",
        content_sha256_hex.to_ascii_lowercase()
    ))
}

/// Job ids travel in URLs (`GET /v1/ingest/jobs/:id`): keep them narrow.
pub fn validate_job_id(raw: &str) -> bool {
    !raw.is_empty()
        && raw.len() <= 64
        && raw
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn search_job_skips_nothing_upload_skips_search() {
        assert_eq!(
            advance(JobState::Queued, JobSource::IndexerSearch, false),
            JobState::Searching
        );
        assert_eq!(
            advance(JobState::Queued, JobSource::NzbUpload, false),
            JobState::Parsing
        );
    }

    #[test]
    fn happy_path_reaches_done() {
        let mut s = advance(JobState::Queued, JobSource::IndexerSearch, false);
        for _ in 0..10 {
            s = advance(s, JobSource::IndexerSearch, false);
        }
        assert_eq!(s, JobState::Done);
        assert!(is_terminal(s));
    }

    #[test]
    fn repair_loops_back_to_verify_then_matches() {
        assert_eq!(
            advance(JobState::Verifying, JobSource::NzbUpload, true),
            JobState::Repairing
        );
        assert_eq!(
            advance(JobState::Repairing, JobSource::NzbUpload, false),
            JobState::Verifying
        );
        assert_eq!(
            advance(JobState::Verifying, JobSource::NzbUpload, false),
            JobState::Matching
        );
    }

    #[test]
    fn fail_sticks_terminal_states() {
        assert_eq!(fail(JobState::Probing), JobState::Failed);
        assert!(is_terminal(JobState::Failed));
        assert_eq!(fail(JobState::Done), JobState::Done);
        assert_eq!(fail(JobState::Failed), JobState::Failed);
    }

    #[test]
    fn retry_budget_is_bounded() {
        assert!(can_retry(1));
        assert!(can_retry(MAX_ATTEMPTS - 1));
        assert!(!can_retry(0));
        assert!(!can_retry(MAX_ATTEMPTS));
        assert!(!can_retry(MAX_ATTEMPTS + 1));
    }

    #[test]
    fn idempotency_key_binds_user_content_and_source() {
        let sha = "a".repeat(64);
        let k1 = derive_idempotency_key("u1", &sha, "upload").unwrap();
        let k2 = derive_idempotency_key("u1", &sha, "upload").unwrap();
        assert_eq!(k1, k2);
        assert!(k1.starts_with("ingest:u1:"));
        assert_ne!(k1, derive_idempotency_key("u2", &sha, "upload").unwrap());
        assert_ne!(k1, derive_idempotency_key("u1", &sha, "guid-9").unwrap());
    }

    #[test]
    fn idempotency_key_rejects_bad_inputs() {
        let sha = "b".repeat(64);
        assert!(derive_idempotency_key("", &sha, "upload").is_err());
        assert!(derive_idempotency_key("u", "xyz", "upload").is_err());
        assert!(derive_idempotency_key("u", &sha, "").is_err());
        assert!(derive_idempotency_key("u", &"A".repeat(64), "upload").is_ok());
    }

    #[test]
    fn idempotency_key_rejects_delimiter_confusion() {
        // Two different triples must never format to the same key: ':' is the
        // field delimiter, so it is rejected in both variable fields.
        let s1 = "c".repeat(64);
        let s2 = "d".repeat(64);
        assert!(derive_idempotency_key("u", &s1, "x/y/S2/r").is_ok());
        assert!(derive_idempotency_key("u", &s1, "x:y").is_err());
        assert!(derive_idempotency_key("u:y:x", &s2, "r").is_err());
        assert!(derive_idempotency_key("u\0", &s1, "upload").is_err());
        assert!(derive_idempotency_key("u", &s1, "up\0load").is_err());
    }

    fn checkpoint_at(state: JobState) -> JobCheckpoint {
        JobCheckpoint {
            job_id: "job_0123456789abcdef".to_string(),
            user_id: "user_01".to_string(),
            idempotency_key: format!("ingest:user_01:{}:upload", "a".repeat(64)),
            source: JobSource::NzbUpload,
            state,
            attempt: 1,
            repair_rounds: 0,
            probe_tally: None,
            failure_reason: None,
        }
    }

    #[test]
    fn perpetual_repair_need_terminates_in_failed() {
        let mut cp = checkpoint_at(JobState::Verifying);
        for _ in 0..MAX_REPAIR_ROUNDS {
            assert_eq!(advance_checkpoint(&mut cp, true), JobState::Repairing);
            assert_eq!(advance_checkpoint(&mut cp, false), JobState::Verifying);
        }
        // Budget spent: the next failing verify fails the job, and attempt is
        // untouched (it belongs to Queue redelivery, not to this loop).
        assert_eq!(advance_checkpoint(&mut cp, true), JobState::Failed);
        assert_eq!(cp.attempt, 1);
        assert_eq!(cp.repair_rounds, MAX_REPAIR_ROUNDS);
        assert!(is_terminal(cp.state));
        assert_eq!(
            cp.failure_reason.as_deref(),
            Some("repair budget exhausted")
        );
    }

    #[test]
    fn checkpoint_advance_matches_pure_advance_off_the_repair_path() {
        let mut cp = checkpoint_at(JobState::Queued);
        assert_eq!(advance_checkpoint(&mut cp, false), JobState::Parsing);
        assert_eq!(cp.repair_rounds, 0);
        let mut cp = checkpoint_at(JobState::Verifying);
        assert_eq!(advance_checkpoint(&mut cp, false), JobState::Matching);
        assert_eq!(cp.repair_rounds, 0);
    }

    #[test]
    fn checkpoint_carries_the_probe_tally_with_legacy_default() {
        // The tally must survive a crash mid-Probing: it rides the
        // checkpoint, and checkpoints written before the field existed
        // still decode (tally empty, probing resumes from batch zero).
        use crate::probe::ProbeTally;

        let mut cp = checkpoint_at(JobState::Probing);
        assert!(cp.probe_tally.is_none());
        cp.probe_tally = Some(ProbeTally::new(2));
        let back: JobCheckpoint =
            serde_json::from_str(&serde_json::to_string(&cp).unwrap()).unwrap();
        assert_eq!(back, cp);

        let legacy = serde_json::json!({
            "job_id": "job_0123456789abcdef",
            "user_id": "user_01",
            "idempotency_key": format!("ingest:user_01:{}:upload", "a".repeat(64)),
            "source": "nzb_upload",
            "state": "probing",
            "attempt": 1,
            "failure_reason": null,
        });
        let legacy_cp: JobCheckpoint = serde_json::from_value(legacy).unwrap();
        assert!(legacy_cp.probe_tally.is_none());
        assert_eq!(legacy_cp.repair_rounds, 0);
    }

    #[test]
    fn job_id_validation_rejects_path_tricks() {
        assert!(validate_job_id("job_01-abc"));
        assert!(!validate_job_id(""));
        assert!(!validate_job_id("../../etc"));
        assert!(!validate_job_id("a/b"));
        assert!(!validate_job_id(&"x".repeat(65)));
    }
}
