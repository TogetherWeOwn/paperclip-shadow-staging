//! Pipeline E2E with synthetic fixtures (no live NNTP in CI).
//!
//! Walks the full ingest chain — intake → dispatch → parse check → probe
//! mapping → repair decision → state machine → library upsert → metering —
//! against the embedded synthetic corpus (`src/fixtures.rs`). The live-server
//! half (real pool DO, real `nntune-core` parse, synthetic NNTP fixture
//! server) is owned by the pool-DO, core-parse, and synthetic-server cards;
//! this test pins the ingest-side contract they must plug into.

use nntune_ingest::dispatch::build_upload_dispatch;
use nntune_ingest::fixtures::{GAPPED_NZB, GAPPED_PAR2_SET, SMALL_NZB, SMALL_NZB_SEGMENTS};
use nntune_ingest::jobs::{advance, JobSource, JobState};
use nntune_ingest::library::{upsert_library_sql, validate_library_write};
use nntune_ingest::metering::{meter_event, MeterOutcome};
use nntune_ingest::nzb_intake::estimate_nzb;
use nntune_ingest::parse::{check_parsed, probe_batches, ParsedNzb};
use nntune_ingest::probe::{
    apply_probe, apply_probe_batch, build_probe_request, ProbeOutcome, ProbeTally,
};
use nntune_ingest::queue::{LibraryWrite, WORKFLOW_STEPS};
use nntune_ingest::repair::decide_repair;

const MBID: &str = "f5c2d4b1-3a7e-4d1c-9e2f-0a1b2c3d4e5f";

fn parsed_from(ids: &[&str]) -> ParsedNzb {
    ParsedNzb {
        file_count: 1,
        segment_count: ids.len(),
        message_ids: ids.iter().map(|s| s.to_string()).collect(),
    }
}

#[test]
fn happy_path_reaches_done_with_one_library_row() {
    // Intake → dispatch.
    let est = estimate_nzb(SMALL_NZB).unwrap();
    let msg = build_upload_dispatch("user_01", SMALL_NZB).unwrap();

    // Parse check → probe batches → full availability → verify.
    let parsed = parsed_from(&SMALL_NZB_SEGMENTS);
    check_parsed(&est, &parsed).unwrap();
    let batches = probe_batches(&parsed);
    assert_eq!(batches.len(), 1);
    let req = build_probe_request(&msg, 0, &SMALL_NZB_SEGMENTS).unwrap();
    assert_eq!(req.idempotency_key, msg.idempotency_key);
    let outcome = ProbeOutcome {
        batch_index: 0,
        present: req.segment_ids.clone(),
        missing: vec![],
    };
    let (next, missing) = apply_probe(JobState::Probing, &outcome);
    assert_eq!((next, missing), (JobState::Verifying, 0));

    // No repair: walk the state machine to Done.
    assert!(
        decide_repair(&msg.job_id, &msg.user_id, &msg.idempotency_key, "", 0)
            .unwrap()
            .is_none()
    );
    let mut state = JobState::Queued;
    for _ in 0..10 {
        state = advance(state, JobSource::NzbUpload, false);
    }
    assert_eq!(state, JobState::Done);

    // Library write validates; the upsert converges on the idempotency key.
    let write = LibraryWrite {
        job_id: msg.job_id.clone(),
        user_id: msg.user_id.clone(),
        idempotency_key: msg.idempotency_key.clone(),
        release_mbid: Some(MBID.into()),
        recording_mbids: vec![MBID.into()],
    };
    validate_library_write(&write).unwrap();
    assert!(upsert_library_sql().contains("ON CONFLICT (idempotency_key)"));

    // Every workflow step meters.
    for step in WORKFLOW_STEPS {
        meter_event(&msg, step, MeterOutcome::Ok).unwrap();
    }
}

#[test]
fn gapped_set_repairs_then_reaches_done() {
    let est = estimate_nzb(GAPPED_NZB).unwrap();
    let msg = build_upload_dispatch("user_01", GAPPED_NZB).unwrap();
    let parsed = parsed_from(&["gap-one@synthetic.invalid", "gap-missing@synthetic.invalid"]);
    check_parsed(&est, &parsed).unwrap();

    // Pool reports the 430: probe completes into Verifying carrying the
    // missing-segment count, which Verifying translates (via par2) into the
    // repair dispatch below.
    let outcome = ProbeOutcome {
        batch_index: 0,
        present: vec!["gap-one@synthetic.invalid".into()],
        missing: vec!["gap-missing@synthetic.invalid".into()],
    };
    let (held, missing) = apply_probe(JobState::Probing, &outcome);
    assert_eq!((held, missing), (JobState::Verifying, 1));
    let repair = decide_repair(
        &msg.job_id,
        &msg.user_id,
        &msg.idempotency_key,
        GAPPED_PAR2_SET,
        missing,
    )
    .unwrap()
    .expect("gapped set must dispatch repair");
    assert_eq!(repair.missing_blocks, 1);

    // Repair loops back through verify, then matches and finishes.
    assert_eq!(
        advance(JobState::Verifying, JobSource::NzbUpload, true),
        JobState::Repairing
    );
    assert_eq!(
        advance(JobState::Repairing, JobSource::NzbUpload, false),
        JobState::Verifying
    );
    let mut state = JobState::Verifying;
    for _ in 0..10 {
        state = advance(state, JobSource::NzbUpload, false);
    }
    assert_eq!(state, JobState::Done);

    // Resume converges: redelivering the same bytes reuses job + key.
    let again = build_upload_dispatch("user_01", GAPPED_NZB).unwrap();
    assert_eq!(again.job_id, msg.job_id);
    assert_eq!(again.idempotency_key, msg.idempotency_key);
    meter_event(&msg, "repair", MeterOutcome::Ok).unwrap();
}

#[test]
fn multi_batch_probe_keeps_middle_gap_to_verify() {
    // A parse over the 500-segment probe cap splits into two batches; the gap
    // in the middle batch must survive the clean batch around it.
    let total = nntune_ingest::probe::MAX_PROBE_SEGMENTS + 1;
    let ids: Vec<String> = (0..total)
        .map(|i| format!("seg-{i:05}@synthetic.invalid"))
        .collect();
    let parsed = ParsedNzb {
        file_count: 1,
        segment_count: ids.len(),
        message_ids: ids,
    };
    let batches = probe_batches(&parsed);
    assert_eq!(batches.len(), 2);
    let mut tally = ProbeTally::new(batches.len());
    let mut state = JobState::Probing;
    let mut missing = 0;
    for (n, batch) in batches.iter().enumerate() {
        let batch_refs: Vec<&str> = batch.iter().map(|s| s.as_str()).collect();
        // Every id except one middle-batch id answers ARTICLE.
        let gap = &batches[1][0];
        let outcome = ProbeOutcome {
            batch_index: n,
            present: batch_refs
                .iter()
                .filter(|id| *id != gap)
                .map(|s| s.to_string())
                .collect(),
            missing: if n == 1 { vec![gap.clone()] } else { vec![] },
        };
        (state, missing) = apply_probe_batch(state, &mut tally, &outcome);
    }
    assert_eq!((state, missing), (JobState::Verifying, 1));
}
