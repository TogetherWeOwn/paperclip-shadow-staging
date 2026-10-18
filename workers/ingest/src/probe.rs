//! Segment probe: availability checks through the user's pool DO.
//!
//! The wire contract (pool routes, auth, per-credential caps) is owned by
//! the pool-DO card; this module owns the ingest side: the probe envelope
//! and how its outcome moves the checkpoint. Live calls stay behind the
//! checkpoint resume: a crash mid-`Probing` redelivers the same envelope,
//! and the mapping below converges on one `Verifying` entry.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::jobs::JobState;
use crate::queue::QueueMsg;

/// Upper bound on message-ids per probe call: keeps one pool round-trip
/// small and the checkpoint resume cheap.
pub const MAX_PROBE_SEGMENTS: usize = 500;

/// Availability check for one batch of segments.
///
/// `batch_index` is the batch's position in [`probe_batches`](crate::parse::probe_batches)
/// order (`0..total`). The pool echoes it on the outcome so the tally keys
/// redelivered answers instead of counting them twice.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProbeRequest {
    pub job_id: String,
    pub user_id: String,
    pub idempotency_key: String,
    pub batch_index: usize,
    pub segment_ids: Vec<String>,
}

/// Pool answer: which segments answered ARTICLE, which answered 430.
///
/// `batch_index` must echo the request's index; an answer for an unknown or
/// already-reported index is ignored by the tally (at-least-once delivery).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProbeOutcome {
    pub batch_index: usize,
    pub present: Vec<String>,
    pub missing: Vec<String>,
}

/// Validate one NZB message-id before it may leave this crate.
///
/// The pool DO interpolates ids into NNTP `STAT`/`ARTICLE <id>` lines on the
/// user's authenticated provider connection, so anything but a strict
/// message-id is command injection: CR/LF smuggles extra commands (`AUTHINFO`,
/// premature `QUIT`) and desyncs replies. Ids arrive from the NZB body (the
/// uploader or a BYO indexer controls them; XML character references decode
/// to real CR/LF in a conforming parser), hence the check runs both at the
/// parse cross-check and here at the envelope.
///
/// Rules (RFC 5536 `msg-id`, bracketless form — the protocol layer adds
/// `<…>`): 1..=512 bytes, printable ASCII (`0x21..=0x7E`) only, no `<`/`>`,
/// exactly one `@` with non-empty sides.
pub fn validate_message_id(id: &str) -> bool {
    if id.is_empty() || id.len() > 512 {
        return false;
    }
    if !id.bytes().all(|b| (0x21..=0x7E).contains(&b)) {
        return false;
    }
    if id.contains('<') || id.contains('>') {
        return false;
    }
    let mut parts = id.split('@');
    matches!((parts.next(), parts.next(), parts.next()), (Some(a), Some(b), None) if !a.is_empty() && !b.is_empty())
}

/// Build one probe envelope from the job and its parsed segment list.
///
/// `batch_index` is the batch's position in `probe_batches` order; the pool
/// echoes it on the outcome so redeliveries converge instead of advancing
/// the tally twice.
pub fn build_probe_request(
    msg: &QueueMsg,
    batch_index: usize,
    segment_ids: &[&str],
) -> Result<ProbeRequest, &'static str> {
    if segment_ids.is_empty() || segment_ids.len() > MAX_PROBE_SEGMENTS {
        return Err("probe batch must be 1..=500 segments");
    }
    if segment_ids.iter().any(|s| !validate_message_id(s)) {
        return Err("segment ids must be valid message-ids");
    }
    Ok(ProbeRequest {
        job_id: msg.job_id.clone(),
        user_id: msg.user_id.clone(),
        idempotency_key: msg.idempotency_key.clone(),
        batch_index,
        segment_ids: segment_ids.iter().map(|s| s.to_string()).collect(),
    })
}

/// Running tally across the probe batches of one job.
///
/// `probe_batches` splits large parses into 500-id envelopes; the checkpoint
/// must not advance until every batch has reported, or gaps found in one
/// batch are silently dropped when another batch lands clean. The tally lives
/// in the checkpoint while `Probing` and is folded by [`apply_probe_batch`].
///
/// Results are keyed by batch index: Queue/Workflow delivery is at-least-once
/// and a crash mid-`Probing` redelivers the same envelope, so [`record`](ProbeTally::record)
/// ignores an index it has already seen (and any index `>= total_batches`)
/// instead of completing early with half the NZB unprobed. A zero-batch job
/// never reaches the tally: intake rejects NZBs with no files or segments
/// (see [`build_upload_dispatch`](crate::dispatch::build_upload_dispatch)).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProbeTally {
    pub total_batches: usize,
    pub missing_by_batch: BTreeMap<usize, u32>,
}

impl ProbeTally {
    pub fn new(total_batches: usize) -> Self {
        Self {
            total_batches,
            missing_by_batch: BTreeMap::new(),
        }
    }

    /// Fold one batch answer. Returns true when the outcome was new (false
    /// for a redelivered or out-of-range index, which leaves the tally
    /// untouched). Missing counts are summed over the per-batch map, so a
    /// replay can never inflate them.
    pub fn record(&mut self, outcome: &ProbeOutcome) -> bool {
        if outcome.batch_index >= self.total_batches {
            return false;
        }
        if self.missing_by_batch.contains_key(&outcome.batch_index) {
            return false;
        }
        self.missing_by_batch
            .insert(outcome.batch_index, outcome.missing.len() as u32);
        true
    }

    /// Total missing segments reported so far (one entry per batch at most).
    pub fn missing_segments(&self) -> u32 {
        self.missing_by_batch.values().sum()
    }

    /// Complete only when every index in `0..total_batches` has reported.
    pub fn is_complete(&self) -> bool {
        self.missing_by_batch.len() == self.total_batches
    }
}

/// Move the checkpoint on a probe answer. Only `Probing` advances; every
/// other state passes through so replayed outcomes cannot drag a job
/// backwards.
///
/// This is the single-batch (or fully merged) mapping: the outcome covers
/// the whole parse, so the job always leaves `Probing` for `Verifying`,
/// carrying the total missing-*segment* count. Use [`apply_probe_batch`]
/// while batches are still in flight.
///
/// The count is missing *articles*, not par2 blocks: `Verifying` translates
/// it through the par2 metadata before [`decide_repair`](crate::repair::decide_repair).
pub fn apply_probe(state: JobState, outcome: &ProbeOutcome) -> (JobState, u32) {
    if state != JobState::Probing {
        return (state, 0);
    }
    (JobState::Verifying, outcome.missing.len() as u32)
}

/// Fold one batch outcome into the tally. Until every batch has reported the
/// job holds `Probing` (with the missing count so far); once complete this is
/// [`apply_probe`] on the merged result, so a gap in *any* batch — first,
/// middle, or last — survives to `Verifying`. A redelivered or out-of-range
/// outcome is ignored by the tally, so the job still holds `Probing`.
pub fn apply_probe_batch(
    state: JobState,
    tally: &mut ProbeTally,
    outcome: &ProbeOutcome,
) -> (JobState, u32) {
    if state != JobState::Probing {
        return (state, 0);
    }
    tally.record(outcome);
    if !tally.is_complete() {
        return (JobState::Probing, tally.missing_segments());
    }
    (JobState::Verifying, tally.missing_segments())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dispatch::build_upload_dispatch;
    use crate::fixtures::{GAPPED_PAR2_SET, SMALL_NZB, SMALL_NZB_SEGMENTS};
    use crate::jobs::JobState;

    #[test]
    fn probe_request_carries_idempotency_and_caps_segments() {
        let msg = build_upload_dispatch("user_01", SMALL_NZB).unwrap();
        let req = build_probe_request(&msg, 0, &SMALL_NZB_SEGMENTS).unwrap();
        assert_eq!(req.idempotency_key, msg.idempotency_key);
        assert_eq!(req.segment_ids.len(), 2);
        // Redelivery converges: same inputs, same envelope.
        assert_eq!(
            req,
            build_probe_request(&msg, 0, &SMALL_NZB_SEGMENTS).unwrap()
        );
    }

    #[test]
    fn probe_request_refuses_empty_and_oversize_batches() {
        let msg = build_upload_dispatch("user_01", SMALL_NZB).unwrap();
        assert!(build_probe_request(&msg, 0, &[]).is_err());
        let many = vec!["seg@synthetic.invalid"; MAX_PROBE_SEGMENTS + 1];
        assert!(build_probe_request(&msg, 0, &many).is_err());
        assert!(build_probe_request(&msg, 0, &[""]).is_err());
        let _ = GAPPED_PAR2_SET;
    }

    #[test]
    fn full_availability_advances_to_verify() {
        let outcome = ProbeOutcome {
            batch_index: 0,
            present: SMALL_NZB_SEGMENTS.iter().map(|s| s.to_string()).collect(),
            missing: vec![],
        };
        let (next, missing) = apply_probe(JobState::Probing, &outcome);
        assert_eq!(next, JobState::Verifying);
        assert_eq!(missing, 0);
    }

    #[test]
    fn gaps_advance_to_verify_with_a_missing_segment_count() {
        // Probe completion always leaves Probing for Verifying; Verifying
        // decides repair. The count is missing articles, not par2 blocks.
        let outcome = ProbeOutcome {
            batch_index: 0,
            present: vec!["gap-one@synthetic.invalid".into()],
            missing: vec!["gap-missing@synthetic.invalid".into()],
        };
        let (next, missing) = apply_probe(JobState::Probing, &outcome);
        assert_eq!(next, JobState::Verifying);
        assert_eq!(missing, 1);
    }

    #[test]
    fn message_id_validation_rejects_injection_shapes() {
        assert!(validate_message_id("seg-one@synthetic.invalid"));
        assert!(!validate_message_id(""));
        assert!(!validate_message_id(&"a".repeat(513)));
        assert!(!validate_message_id("has space@synthetic.invalid"));
        assert!(!validate_message_id(
            "x@y>\r\nAUTHINFO USER attacker\r\nQUIT\r\n<z"
        ));
        assert!(!validate_message_id("x@sy\nthetic.invalid"));
        assert!(!validate_message_id("x@sy\rthetic.invalid"));
        assert!(!validate_message_id("x\0@synthetic.invalid"));
        assert!(!validate_message_id("x@y@z"));
        assert!(!validate_message_id("@synthetic.invalid"));
        assert!(!validate_message_id("local@"));
        assert!(!validate_message_id("<seg@synthetic.invalid>"));
        assert!(!validate_message_id("seg@synthetic.invalid>"));
    }

    #[test]
    fn probe_request_refuses_injecting_ids() {
        let msg = build_upload_dispatch("user_01", SMALL_NZB).unwrap();
        assert!(build_probe_request(&msg, 0, &["x@y>\r\nQUIT\r\n<z"]).is_err());
        assert!(build_probe_request(&msg, 0, &["has space@x.invalid"]).is_err());
    }

    fn outcome_with_index(batch_index: usize, missing: &[&str]) -> ProbeOutcome {
        ProbeOutcome {
            batch_index,
            present: vec![],
            missing: missing.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn replayed_batch_outcome_neither_completes_nor_double_counts() {
        // Queue/Workflow delivery is at-least-once: folding batch 0's
        // outcome twice must hold Probing and count its gap once, or a
        // redelivered batch completes probing with half the NZB unprobed.
        let mut tally = ProbeTally::new(2);
        let mut state = JobState::Probing;
        let outcome = outcome_with_index(0, &["gap-missing@synthetic.invalid"]);
        (state, _) = apply_probe_batch(state, &mut tally, &outcome);
        assert_eq!(state, JobState::Probing);
        let (replayed, missing) = apply_probe_batch(state, &mut tally, &outcome);
        assert_eq!(replayed, JobState::Probing);
        assert_eq!(missing, 1);
        assert!(!tally.is_complete());
        // The genuinely missing batch still completes the job afterwards.
        let (done, missing) = apply_probe_batch(replayed, &mut tally, &outcome_with_index(1, &[]));
        assert_eq!((done, missing), (JobState::Verifying, 1));
    }

    #[test]
    fn out_of_range_batch_index_is_rejected() {
        let mut tally = ProbeTally::new(2);
        assert!(!tally.record(&outcome_with_index(2, &[])));
        assert!(!tally.record(&outcome_with_index(99, &["gap-missing@synthetic.invalid"])));
        assert!(!tally.is_complete());
        assert_eq!(tally.missing_segments(), 0);
    }

    #[test]
    fn tally_completes_only_when_every_batch_reported_once() {
        // Late/duplicate batches in any order converge on one Verifying
        // entry with the merged gap count.
        let mut tally = ProbeTally::new(2);
        let mut state = JobState::Probing;
        (state, _) = apply_probe_batch(
            state,
            &mut tally,
            &outcome_with_index(1, &["gap-missing@synthetic.invalid"]),
        );
        assert_eq!(state, JobState::Probing);
        let (done, missing) = apply_probe_batch(state, &mut tally, &outcome_with_index(0, &[]));
        assert_eq!((done, missing), (JobState::Verifying, 1));
        assert!(tally.is_complete());
    }

    #[test]
    fn probe_request_names_its_batch() {
        // The request and its answer share the index so the tally can key
        // redeliveries; same batch rebuilt twice carries the same index.
        let msg = build_upload_dispatch("user_01", SMALL_NZB).unwrap();
        let req = build_probe_request(&msg, 3, &SMALL_NZB_SEGMENTS).unwrap();
        assert_eq!(req.batch_index, 3);
        assert_eq!(
            req,
            build_probe_request(&msg, 3, &SMALL_NZB_SEGMENTS).unwrap()
        );
        assert_ne!(
            req,
            build_probe_request(&msg, 4, &SMALL_NZB_SEGMENTS).unwrap()
        );
    }

    #[test]
    fn batched_probe_keeps_gaps_from_any_position() {
        // Three batches; the gap sits in the first, middle, then last batch.
        // In every order the merged result reaches Verifying with the gap.
        for gap_at in 0..3 {
            let mut tally = ProbeTally::new(3);
            let mut state = JobState::Probing;
            let mut last_missing = 0;
            for batch in 0..3 {
                let outcome = if batch == gap_at {
                    outcome_with_index(batch, &["gap-missing@synthetic.invalid"])
                } else {
                    outcome_with_index(batch, &[])
                };
                (state, last_missing) = apply_probe_batch(state, &mut tally, &outcome);
                if batch < 2 {
                    assert_eq!(state, JobState::Probing, "gap_at={gap_at} batch={batch}");
                }
            }
            assert_eq!(state, JobState::Verifying, "gap_at={gap_at}");
            assert_eq!(last_missing, 1, "gap_at={gap_at}");
        }
    }

    #[test]
    fn batched_probe_clean_run_reaches_verify_with_zero() {
        let mut tally = ProbeTally::new(2);
        let (s1, _) = apply_probe_batch(JobState::Probing, &mut tally, &outcome_with_index(0, &[]));
        assert_eq!(s1, JobState::Probing);
        let (s2, missing) =
            apply_probe_batch(JobState::Probing, &mut tally, &outcome_with_index(1, &[]));
        assert_eq!((s2, missing), (JobState::Verifying, 0));
    }

    #[test]
    fn probe_mapping_leaves_other_states_alone() {
        let outcome = ProbeOutcome {
            batch_index: 0,
            present: vec![],
            missing: vec![],
        };
        let (next, _) = apply_probe(JobState::Verifying, &outcome);
        assert_eq!(next, JobState::Verifying);
    }
}
