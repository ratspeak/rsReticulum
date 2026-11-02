use std::collections::HashMap;
use tracing::debug;

use crate::constants::MAX_RATE_TIMESTAMPS;
use rns_wire::types::DestHash;

/// Announces-per-second above which a destination is counted as violating.
pub const RATE_VIOLATION_THRESHOLD: f64 = 1.0;
/// Violation count at which `RateTable::record` first applies a penalty.
pub const RATE_VIOLATIONS_BEFORE_PENALTY: u32 = 3;
/// Base penalty in seconds; doubles with each additional violation.
pub const RATE_PENALTY_BASE: f64 = 60.0;
/// Maximum duration of each `RateTable::record` penalty (one hour). Later
/// violations can start another penalty.
pub const RATE_PENALTY_MAX: f64 = 3600.0;

#[derive(Debug, Clone)]
pub struct RateEntry {
    pub timestamps: Vec<f64>,
    /// Rate last computed by `record` across its timestamp window. It does
    /// not decay with elapsed time; `check_interface_rate` does not update it.
    pub rate: f64,
    /// Last accepted accounting timestamp (Unix seconds). Calls rejected
    /// during a penalty do not advance it.
    pub last: f64,
    pub violations: u32,
    /// Unix-seconds penalty deadline; zero is the initial value. An expired
    /// nonzero deadline can remain stored.
    pub blocked_until: f64,
}

/// Destination-keyed announce accounting using wall-clock time. Both rate
/// methods mutate the same entry even when interface-specific settings are
/// supplied. There is no automatic expiry or entry-count cap; use `cull`.
pub struct RateTable {
    entries: HashMap<DestHash, RateEntry>,
}

impl RateTable {
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    /// Record an announce and return the stored rate, computed over at most
    /// 16 timestamps when their span is positive. During an active penalty,
    /// return `f64::MAX` without updating timestamps. Violations accumulate;
    /// this method does not decay their count. Crossing the threshold starts
    /// a penalty but still returns the computed rate for that call.
    pub fn record(&mut self, dest_hash: impl Into<DestHash>) -> f64 {
        let dest_hash = dest_hash.into();
        let now = crate::now_f64();

        let entry = self.entries.entry(dest_hash).or_insert_with(|| RateEntry {
            timestamps: Vec::new(),
            rate: 0.0,
            last: 0.0,
            violations: 0,
            blocked_until: 0.0,
        });

        if entry.blocked_until > now {
            return f64::MAX;
        }

        entry.timestamps.push(now);
        entry.last = now;

        if entry.timestamps.len() > MAX_RATE_TIMESTAMPS {
            let drain_count = entry.timestamps.len() - MAX_RATE_TIMESTAMPS;
            entry.timestamps.drain(..drain_count);
        }

        if entry.timestamps.len() >= 2 {
            let span = entry.timestamps.last().unwrap() - entry.timestamps.first().unwrap();
            if span > 0.0 {
                entry.rate = (entry.timestamps.len() - 1) as f64 / span;
            }
        }

        if entry.rate > RATE_VIOLATION_THRESHOLD {
            entry.violations += 1;
            debug!(
                dest = hex::encode(dest_hash),
                rate = format!("{:.2}", entry.rate),
                violations = entry.violations,
                "rate limit violation detected"
            );
            if entry.violations >= RATE_VIOLATIONS_BEFORE_PENALTY {
                // Exponential back-off, clamped so a persistent offender
                // doesn't snowball into an effectively-permanent block.
                let penalty = (RATE_PENALTY_BASE
                    * 2.0_f64.powi((entry.violations - RATE_VIOLATIONS_BEFORE_PENALTY) as i32))
                .min(RATE_PENALTY_MAX);
                entry.blocked_until = now + penalty;
                debug!(
                    dest = hex::encode(dest_hash),
                    penalty_secs = format!("{:.1}", penalty),
                    "rate limit penalty applied"
                );
            }
        }

        entry.rate
    }

    pub fn is_blocked(&self, dest_hash: &[u8; 16]) -> bool {
        let now = crate::now_f64();
        self.entries
            .get(dest_hash)
            .is_some_and(|e| e.blocked_until > now)
    }

    pub fn get_rate(&self, dest_hash: &[u8; 16]) -> f64 {
        self.entries.get(dest_hash).map_or(0.0, |e| e.rate)
    }

    pub fn last_announce(&self, dest_hash: &[u8; 16]) -> Option<f64> {
        self.entries.get(dest_hash).map(|e| e.last)
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Remove entries whose stored `last` is at or before the Unix-seconds
    /// cutoff, even if a penalty is still active.
    pub fn cull(&mut self, cutoff: f64) {
        self.entries.retain(|_, e| e.last > cutoff);
    }

    pub fn iter(&self) -> impl Iterator<Item = (&DestHash, &RateEntry)> {
        self.entries.iter()
    }

    /// Apply interface-supplied announce interval settings to this destination.
    ///
    /// Uses the interface-level triplet `(rate_target, rate_grace, rate_penalty)`:
    /// any interval shorter than `rate_target` is a violation, violations
    /// decay by one when the interval is long enough, and exceeding the grace
    /// count sets a deadline at the previous `last + rate_target + rate_penalty`.
    /// Both durations are seconds. This call is suppressed when grace is
    /// exceeded, even if that calculated deadline has already passed.
    ///
    /// Returns `true` when rebroadcast should be suppressed. Path-table
    /// storage is unaffected by this helper; the actor uses the result to
    /// suppress rebroadcast. There is one entry per destination, not per
    /// interface, and this method shares state with [`Self::record`].
    pub fn check_interface_rate(
        &mut self,
        dest_hash: impl Into<DestHash>,
        rate_target: f64,
        rate_grace: u32,
        rate_penalty: f64,
    ) -> bool {
        let dest_hash = dest_hash.into();
        let now = crate::now_f64();

        let entry = match self.entries.entry(dest_hash) {
            std::collections::hash_map::Entry::Occupied(entry) => entry.into_mut(),
            std::collections::hash_map::Entry::Vacant(entry) => {
                entry.insert(RateEntry {
                    timestamps: vec![now],
                    rate: 0.0,
                    last: now,
                    violations: 0,
                    blocked_until: 0.0,
                });
                return false;
            }
        };

        if now <= entry.blocked_until {
            return true;
        }

        entry.timestamps.push(now);
        while entry.timestamps.len() > MAX_RATE_TIMESTAMPS {
            entry.timestamps.remove(0);
        }

        let current_rate = now - entry.last;

        if current_rate < rate_target {
            entry.violations += 1;
        } else {
            entry.violations = entry.violations.saturating_sub(1);
        }

        if entry.violations > rate_grace {
            entry.blocked_until = entry.last + rate_target + rate_penalty;
            // Leave `last` untouched so the penalty window is anchored to the
            // announce that originally tipped us over the grace threshold.
            return true;
        }

        entry.last = now;
        false
    }
}

impl Default for RateTable {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rate_recording() {
        let mut rt = RateTable::new();
        let hash = [0xAA; 16];
        let rate = rt.record(hash);
        assert_eq!(rate, 0.0);
    }

    #[test]
    fn test_rate_limit_bounds() {
        let mut rt = RateTable::new();
        let hash = [0xAA; 16];
        for _ in 0..MAX_RATE_TIMESTAMPS + 5 {
            rt.record(hash);
        }
        let entry = rt.entries.get(&hash).unwrap();
        assert!(entry.timestamps.len() <= MAX_RATE_TIMESTAMPS);
    }

    #[test]
    fn test_violation_tracking() {
        let mut rt = RateTable::new();
        let hash = [0xBB; 16];

        for _ in 0..20 {
            rt.record(hash);
        }

        let entry = rt.entries.get(&hash).unwrap();
        assert!(entry.violations > 0 || entry.rate > 0.0);
    }

    #[test]
    fn test_blocked_check() {
        let mut rt = RateTable::new();
        let hash = [0xCC; 16];

        assert!(!rt.is_blocked(&hash));

        rt.record(hash);
    }

    #[test]
    fn test_interface_rate_first_announce_not_blocked() {
        let mut rt = RateTable::new();
        let hash = [0xDD; 16];
        let blocked = rt.check_interface_rate(hash, 300.0, 3, 600.0);
        assert!(!blocked);
    }

    #[test]
    fn test_interface_rate_rapid_fire_triggers_block() {
        let mut rt = RateTable::new();
        let hash = [0xEE; 16];
        // Three back-to-back calls: first records, second violates, third
        // violates again — with grace=1 the running count hits 2 and trips.
        rt.check_interface_rate(hash, 300.0, 1, 600.0);
        rt.check_interface_rate(hash, 300.0, 1, 600.0);
        let blocked = rt.check_interface_rate(hash, 300.0, 1, 600.0);
        assert!(blocked);
    }
}
