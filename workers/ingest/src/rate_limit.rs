//! Per-plan rate limits for ingest (token buckets, no clock dependency).
//!
//! Limits are provisional launch tunables, not product promises: the README
//! plans section says exact numbers are set at launch. The metering card
//! owns billing truth; this module only protects provider connections and
//! indexer quotas inside the worker. Time is passed in as `now_s` (unix
//! seconds) so the logic is unit-testable without a clock.

use serde::{Deserialize, Serialize};

/// Quotas attached to one plan tier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlanLimits {
    /// Concurrent non-terminal jobs per user.
    pub max_concurrent_jobs: u32,
    /// Newznab search requests per minute per user.
    pub searches_per_min: u32,
    /// NZB uploads per hour per user.
    pub nzb_per_hour: u32,
}

/// Provisional tiers matching the base / 5x / 20x plan shape.
pub const PLAN_BASE: PlanLimits = PlanLimits {
    max_concurrent_jobs: 2,
    searches_per_min: 10,
    nzb_per_hour: 20,
};
pub const PLAN_5X: PlanLimits = PlanLimits {
    max_concurrent_jobs: 6,
    searches_per_min: 40,
    nzb_per_hour: 80,
};
pub const PLAN_20X: PlanLimits = PlanLimits {
    max_concurrent_jobs: 12,
    searches_per_min: 120,
    nzb_per_hour: 240,
};

/// Token bucket with explicit time: refill on every [`TokenBucket::take`].
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct TokenBucket {
    capacity: f64,
    tokens: f64,
    refill_per_sec: f64,
    last_tick_s: u64,
}

impl TokenBucket {
    /// `capacity`: burst size; `refill_per_sec`: sustained rate.
    /// The bucket starts full.
    pub fn new(capacity: f64, refill_per_sec: f64, now_s: u64) -> Self {
        Self {
            capacity: capacity.max(0.0),
            tokens: capacity.max(0.0),
            refill_per_sec: refill_per_sec.max(0.0),
            last_tick_s: now_s,
        }
    }

    /// Build from "N events per `window_s` seconds" (burst = N).
    pub fn per_window(n: u32, window_s: u64, now_s: u64) -> Self {
        let rate = if window_s == 0 {
            0.0
        } else {
            f64::from(n) / window_s as f64
        };
        Self::new(f64::from(n), rate, now_s)
    }

    /// Take `n` tokens if available. Clock skew backwards = no refill.
    pub fn take(&mut self, now_s: u64, n: f64) -> bool {
        if now_s > self.last_tick_s {
            let dt = (now_s - self.last_tick_s) as f64;
            self.tokens = (self.tokens + dt * self.refill_per_sec).min(self.capacity);
            self.last_tick_s = now_s;
        }
        if self.tokens >= n {
            self.tokens -= n;
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn higher_tiers_allow_bigger_bursts() {
        // Each tier's per-minute quota is spendable as one burst, then cut
        // off: exercises the bucket through its public API, not the consts.
        for tier in [PLAN_BASE, PLAN_5X, PLAN_20X] {
            let mut b = TokenBucket::per_window(tier.searches_per_min, 60, 0);
            for _ in 0..tier.searches_per_min {
                assert!(b.take(0, 1.0));
            }
            assert!(!b.take(0, 1.0));
        }
        // Tiers stay ordered base < 5x < 20x (collected at runtime).
        let searches: Vec<u32> = [PLAN_BASE, PLAN_5X, PLAN_20X]
            .iter()
            .map(|t| t.searches_per_min)
            .collect();
        assert!(searches.windows(2).all(|w| w[0] < w[1]));
        let jobs: Vec<u32> = [PLAN_BASE, PLAN_5X, PLAN_20X]
            .iter()
            .map(|t| t.max_concurrent_jobs)
            .collect();
        assert!(jobs.windows(2).all(|w| w[0] < w[1]));
    }

    #[test]
    fn bucket_exhausts_then_refills() {
        let mut b = TokenBucket::per_window(10, 60, 1_000);
        for _ in 0..10 {
            assert!(b.take(1_000, 1.0));
        }
        assert!(!b.take(1_000, 1.0));
        assert!(b.take(1_060, 1.0));
    }

    #[test]
    fn backwards_clock_never_grants_extra() {
        let mut b = TokenBucket::per_window(1, 60, 1_000);
        assert!(b.take(1_000, 1.0));
        assert!(!b.take(1_000, 1.0));
        assert!(!b.take(900, 1.0));
        assert!(b.take(1_060, 1.0));
    }
}
