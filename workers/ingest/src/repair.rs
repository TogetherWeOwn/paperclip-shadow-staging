//! Repair dispatch: `Verifying` hands off to the Container batch job.
//!
//! par2 verify itself runs serverless; only when blocks are actually missing
//! does the job leave the worker for native-par2 repair in the Container
//! (service binding `REPAIR_CONTAINER`, `POST /repair` with a
//! [`RepairRequest`] body). No par2 set + missing blocks means the job is
//! unrepairable: the caller fails it instead of dispatching.

use crate::queue::RepairRequest;

/// Service binding name for the repair Container (wrangler `[[services]]`).
pub const REPAIR_SERVICE_BINDING: &str = "REPAIR_CONTAINER";
/// Container route that accepts a [`RepairRequest`] JSON body.
pub const REPAIR_ENDPOINT: &str = "/repair";

/// Decide the `Verifying` handoff: `Ok(Some(_))` dispatches to the Container,
/// `Ok(None)` skips repair, `Err` means unrepairable (fail the job).
pub fn decide_repair(
    job_id: &str,
    user_id: &str,
    idempotency_key: &str,
    par2_set_id: &str,
    missing_blocks: u32,
) -> Result<Option<RepairRequest>, &'static str> {
    if missing_blocks == 0 {
        return Ok(None);
    }
    if par2_set_id.is_empty() || par2_set_id.len() > 256 {
        return Err("missing blocks but no par2 set covers them");
    }
    Ok(Some(RepairRequest {
        job_id: job_id.to_string(),
        user_id: user_id.to_string(),
        idempotency_key: idempotency_key.to_string(),
        par2_set_id: par2_set_id.to_string(),
        missing_blocks,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    const JOB: &str = "job_0123456789abcdef";
    const USER: &str = "user_01";
    const KEY: &str = "ingest:user_01:abc:upload";

    #[test]
    fn missing_blocks_with_par2_dispatches() {
        let req = decide_repair(JOB, USER, KEY, "par2-set-01", 7)
            .unwrap()
            .expect("must dispatch");
        assert_eq!(req.job_id, JOB);
        assert_eq!(req.par2_set_id, "par2-set-01");
        assert_eq!(req.missing_blocks, 7);
        assert_eq!(req.idempotency_key, KEY);
    }

    #[test]
    fn complete_sets_need_no_repair() {
        assert!(decide_repair(JOB, USER, KEY, "par2-set-01", 0)
            .unwrap()
            .is_none());
    }

    #[test]
    fn missing_blocks_without_par2_is_unrepairable() {
        assert!(decide_repair(JOB, USER, KEY, "", 7).is_err());
    }

    #[test]
    fn repair_request_serializes_for_the_container_post() {
        let req = decide_repair(JOB, USER, KEY, "par2-set-01", 1)
            .unwrap()
            .unwrap();
        let body = serde_json::to_value(&req).unwrap();
        assert_eq!(body["par2_set_id"], "par2-set-01");
        assert_eq!(REPAIR_ENDPOINT, "/repair");
        assert_eq!(REPAIR_SERVICE_BINDING, "REPAIR_CONTAINER");
    }
}
