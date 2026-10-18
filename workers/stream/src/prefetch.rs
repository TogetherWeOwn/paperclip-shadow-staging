//! Prefetch: when a play misses and the pool has spare capacity, queue the
//! next track on the [`Lane::Prefetch`](crate::pool::Lane) lane so the
//! following play is a cache hit. The pool enforces the guarantee: prefetch
//! may never take the last free connection, so the next playback always has
//! a slot.

use crate::pool::{Lane, Pool};

/// True when a prefetch may take a connection right now without starving
/// playback (the pool's lane rules, quarantine included).
pub fn should_prefetch<C>(pool: &Pool<C>) -> bool {
    pool.can_acquire(Lane::Prefetch)
}

/// The track after `current` in the play `queue`, if any.
pub fn next_track(queue: &[String], current: usize) -> Option<&str> {
    queue.get(current.checked_add(1)?).map(|s| s.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefetch_never_takes_the_last_connection() {
        let mut one = Pool::<()>::new(1);
        assert!(!should_prefetch(&one), "cap 1: the slot is playback's");
        one.try_acquire(Lane::Playback).expect("playback");
        assert!(!should_prefetch(&one));

        let mut four = Pool::<()>::new(4);
        assert!(should_prefetch(&four));
        // Bind the leases: dropping one frees its slot (drop-safe guard),
        // so temporaries would not hold anything.
        let _p1 = four.try_acquire(Lane::Playback).expect("playback");
        let _p2 = four.try_acquire(Lane::Playback).expect("playback");
        assert!(should_prefetch(&four), "2 of 4 in use leaves one spare");
        let _p3 = four.try_acquire(Lane::Playback).expect("playback");
        assert!(!should_prefetch(&four), "would take the last connection");
    }

    #[test]
    fn quarantined_pool_does_not_prefetch() {
        let mut pool = Pool::<()>::new(4);
        pool.record_provider_error();
        assert!(!should_prefetch(&pool));
    }

    #[test]
    fn next_track_walks_the_queue() {
        let queue = vec!["a".to_string(), "b".to_string(), "c".to_string()];
        assert_eq!(next_track(&queue, 0), Some("b"));
        assert_eq!(next_track(&queue, 1), Some("c"));
        assert_eq!(next_track(&queue, 2), None);
        assert_eq!(next_track(&queue, 9), None);
    }
}
