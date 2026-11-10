use std::collections::HashMap;

use crate::constants::MAX_RATE_TIMESTAMPS;
use rns_wire::types::DestHash;

#[derive(Debug, Clone)]
pub struct RateEntry {
    /// The last `MAX_RATE_TIMESTAMPS` checks, blocked ones included.
    pub timestamps: Vec<f64>,
    /// Last accepted announce time (Unix seconds). Blocked checks do not
    /// advance it.
    pub last: f64,
    pub violations: u32,
    /// Unix-seconds penalty deadline; zero is the initial value.
    pub blocked_until: f64,
}

impl RateEntry {
    /// Announces per second over the stored timestamps, for display only.
    pub fn rate(&self) -> f64 {
        match (self.timestamps.first(), self.timestamps.last()) {
            (Some(first), Some(last)) if last > first => {
                (self.timestamps.len() - 1) as f64 / (last - first)
            }
            _ => 0.0,
        }
    }
}

/// Python's `AnnounceRateTable` (Storage.py): destination-keyed announce
/// accounting for interfaces with an `announce_rate_target`. Only
/// [`Self::check_interface_rate`] writes entries; [`Self::cull`] expires them.
pub struct RateTable {
    entries: HashMap<DestHash, RateEntry>,
}

impl RateTable {
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    pub fn is_blocked(&self, dest_hash: &[u8; 16]) -> bool {
        let now = crate::now_f64();
        self.entries
            .get(dest_hash)
            .is_some_and(|e| e.blocked_until > now)
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

    /// Remove entries whose `last` is older than `now - ttl` and whose penalty
    /// has expired (Storage.py `cull`). Returns the number removed.
    pub fn cull(&mut self, now: f64, ttl: f64) -> usize {
        let horizon = now - ttl;
        let before = self.entries.len();
        self.entries
            .retain(|_, e| !(e.last < horizon && e.blocked_until <= now));
        before - self.entries.len()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&DestHash, &RateEntry)> {
        self.entries.iter()
    }

    /// Python `AnnounceRateTable.check_and_update` with the interface's
    /// `(rate_target, rate_grace, rate_penalty)`. Every call after the first
    /// records its timestamp. Outside a penalty, an interval shorter than
    /// `rate_target` is a violation and a long enough one forgives one;
    /// exceeding the grace count blocks until `last + rate_target +
    /// rate_penalty`. Returns `true` when the announce is rate blocked.
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
                    last: now,
                    violations: 0,
                    blocked_until: 0.0,
                });
                return false;
            }
        };

        entry.timestamps.push(now);
        if entry.timestamps.len() > MAX_RATE_TIMESTAMPS {
            entry.timestamps.remove(0);
        }

        if now <= entry.blocked_until {
            return true;
        }

        let current_rate = now - entry.last;
        if current_rate < rate_target {
            entry.violations += 1;
        } else {
            entry.violations = entry.violations.saturating_sub(1);
        }

        if entry.violations > rate_grace {
            entry.blocked_until = entry.last + rate_target + rate_penalty;
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
        rt.check_interface_rate(hash, 300.0, 1, 600.0);
        rt.check_interface_rate(hash, 300.0, 1, 600.0);
        let blocked = rt.check_interface_rate(hash, 300.0, 1, 600.0);
        assert!(blocked);
        assert!(rt.is_blocked(&hash));
    }

    #[test]
    fn test_rate_timestamps_bounded() {
        let mut rt = RateTable::new();
        let hash = [0xAA; 16];
        for _ in 0..MAX_RATE_TIMESTAMPS + 5 {
            rt.check_interface_rate(hash, 300.0, 0, 0.0);
        }
        assert_eq!(
            rt.entries[&DestHash::from(hash)].timestamps.len(),
            MAX_RATE_TIMESTAMPS
        );
    }
}
