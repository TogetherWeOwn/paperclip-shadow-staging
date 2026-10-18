//! Analytics Engine metering: one event per stage transition.
//!
//! Billing truth lives with the metering card; these events are the ingest
//! pipeline's usage signal (stage entered, outcome, attempt). The worker
//! writes them through the `INGEST_METER` dataset binding (see
//! `wrangler.toml.example`); workers-rs 0.3 has no Analytics Engine API, so
//! the runtime write goes through the binding's HTTP API at the edge while
//! this module owns the event shape.

use serde::{Deserialize, Serialize};

use crate::queue::{QueueMsg, WORKFLOW_STEPS};

/// Analytics Engine binding name: must match `[analytics_engine_datasets]`
/// in `wrangler.toml.example`.
pub const METER_DATASET_BINDING: &str = "INGEST_METER";
/// Analytics Engine dataset receiving ingest usage events.
pub const METER_DATASET: &str = "nntune_ingest_meter";

/// What happened when the job entered the stage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MeterOutcome {
    Ok,
    Retry,
    Failed,
}

/// One usage event: which job, which stage, what happened, which attempt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MeterEvent {
    pub job_id: String,
    pub user_id: String,
    pub stage: String,
    pub outcome: MeterOutcome,
    pub attempt: u32,
}

/// Build the event for a stage transition. `stage` must be one of
/// [`WORKFLOW_STEPS`] so metering can never invent a stage the pipeline
/// does not have.
pub fn meter_event(
    msg: &QueueMsg,
    stage: &str,
    outcome: MeterOutcome,
) -> Result<MeterEvent, &'static str> {
    if !WORKFLOW_STEPS.contains(&stage) {
        return Err("stage must be a pipeline workflow step");
    }
    Ok(MeterEvent {
        job_id: msg.job_id.clone(),
        user_id: msg.user_id.clone(),
        stage: stage.to_string(),
        outcome,
        attempt: msg.attempt,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dispatch::build_upload_dispatch;
    use crate::fixtures::SMALL_NZB;

    #[test]
    fn meter_event_roundtrips_with_stage_and_outcome() {
        let msg = build_upload_dispatch("user_01", SMALL_NZB).unwrap();
        let ev = meter_event(&msg, "probe", MeterOutcome::Ok).unwrap();
        let back: MeterEvent = serde_json::from_str(&serde_json::to_string(&ev).unwrap()).unwrap();
        assert_eq!(ev, back);
        assert_eq!(ev.stage, "probe");
        assert_eq!(ev.attempt, 1);
    }

    #[test]
    fn meter_event_rejects_unknown_stages() {
        let msg = build_upload_dispatch("user_01", SMALL_NZB).unwrap();
        assert!(meter_event(&msg, "teleport", MeterOutcome::Ok).is_err());
        // Every workflow step is a legal stage, including the repair branch.
        for step in crate::queue::WORKFLOW_STEPS {
            assert!(meter_event(&msg, step, MeterOutcome::Retry).is_ok());
        }
    }

    #[test]
    fn dataset_names_match_wrangler_example() {
        assert_eq!(METER_DATASET_BINDING, "INGEST_METER");
        assert_eq!(METER_DATASET, "nntune_ingest_meter");
    }
}
