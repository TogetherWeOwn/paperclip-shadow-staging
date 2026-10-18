//! Parse glue: the parsed shape the checkpoint stores.
//!
//! Full NZB parsing (subject decoding, yEnc segment maps) is owned by the
//! nntune-core card; this module owns the ingest side: the [`ParsedNzb`]
//! shape the `Parsing` step must produce, the cross-check that keeps a parse
//! disagreeing with the intake guard from spending provider connections, and
//! the batching into probe-sized envelopes.

use serde::{Deserialize, Serialize};

use crate::nzb_intake::IntakeEstimate;
use crate::probe::{validate_message_id, MAX_PROBE_SEGMENTS};

/// What the `Parsing` step stores in the checkpoint: the segment map the
/// pool probe walks. Produced by `nntune-core` once that card lands; until
/// then tests and the synthetic E2E construct it from fixtures.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParsedNzb {
    pub file_count: usize,
    pub segment_count: usize,
    pub message_ids: Vec<String>,
}

/// Cross-check a parse against the intake guard's estimate. Any disagreement
/// fails the job before a single provider connection is spent.
pub fn check_parsed(estimate: &IntakeEstimate, parsed: &ParsedNzb) -> Result<(), &'static str> {
    if parsed.file_count != estimate.file_count || parsed.segment_count != estimate.segment_count {
        return Err("parse disagrees with the intake guard");
    }
    if parsed.message_ids.len() != parsed.segment_count {
        return Err("message-id count must match the segment count");
    }
    // Ids flow into NNTP STAT/ARTICLE lines on the user's provider
    // connection: only strict message-ids pass, so a hostile NZB (or BYO
    // indexer) cannot inject CR/LF commands. Same bar as the probe envelope.
    if parsed.message_ids.iter().any(|id| !validate_message_id(id)) {
        return Err("message-ids must be valid msg-ids (printable ASCII, one @)");
    }
    Ok(())
}

/// Chunk message-ids into probe-sized batches, in NZB order.
pub fn probe_batches(parsed: &ParsedNzb) -> Vec<Vec<String>> {
    parsed
        .message_ids
        .chunks(MAX_PROBE_SEGMENTS)
        .map(|c| c.to_vec())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures::{SMALL_NZB, SMALL_NZB_SEGMENTS};
    use crate::nzb_intake::estimate_nzb;

    fn parsed_small() -> ParsedNzb {
        ParsedNzb {
            file_count: 1,
            segment_count: 2,
            message_ids: SMALL_NZB_SEGMENTS.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn parse_matching_intake_passes_the_cross_check() {
        let est = estimate_nzb(SMALL_NZB).unwrap();
        assert!(check_parsed(&est, &parsed_small()).is_ok());
    }

    #[test]
    fn parse_disagreeing_with_intake_fails_before_probe() {
        let est = estimate_nzb(SMALL_NZB).unwrap();
        let mut wrong_counts = parsed_small();
        wrong_counts.segment_count = 99;
        assert!(check_parsed(&est, &wrong_counts).is_err());
        let mut wrong_ids = parsed_small();
        wrong_ids.message_ids.pop();
        assert!(check_parsed(&est, &wrong_ids).is_err());
        let mut bad_id = parsed_small();
        bad_id.message_ids[0].clear();
        assert!(check_parsed(&est, &bad_id).is_err());
    }

    #[test]
    fn parse_rejects_command_injection_ids() {
        let est = estimate_nzb(SMALL_NZB).unwrap();
        let mut evil = parsed_small();
        evil.message_ids[1] = "x@y>\r\nAUTHINFO USER attacker\r\nQUIT\r\n<z".to_string();
        assert!(check_parsed(&est, &evil).is_err());
        let mut space = parsed_small();
        space.message_ids[0] = "has space@synthetic.invalid".to_string();
        assert!(check_parsed(&est, &space).is_err());
    }

    #[test]
    fn message_ids_chunk_into_probe_batches() {
        let batches = probe_batches(&parsed_small());
        assert_eq!(batches.len(), 1);
        assert_eq!(batches[0].len(), 2);
        let empty = ParsedNzb {
            file_count: 0,
            segment_count: 0,
            message_ids: vec![],
        };
        assert!(probe_batches(&empty).is_empty());
    }

    #[test]
    fn large_parses_respect_the_probe_cap() {
        let ids: Vec<String> = (0..(crate::probe::MAX_PROBE_SEGMENTS + 1))
            .map(|i| format!("seg-{i}@synthetic.invalid"))
            .collect();
        let parsed = ParsedNzb {
            file_count: 1,
            segment_count: ids.len(),
            message_ids: ids,
        };
        let batches = probe_batches(&parsed);
        assert_eq!(batches.len(), 2);
        assert!(batches
            .iter()
            .all(|b| b.len() <= crate::probe::MAX_PROBE_SEGMENTS));
    }
}
