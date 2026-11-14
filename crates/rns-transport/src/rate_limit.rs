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

    #[cfg(test)]
    pub fn is_blocked(&self, dest_hash: &[u8; 16]) -> bool {
        let now = crate::now_f64();
        self.entries
            .get(dest_hash)
            .is_some_and(|e| e.blocked_until > now)
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

    /// Goldens from `tests/fixtures/announce_rate/gen_rate_table.py`, which
    /// calls upstream `AnnounceRateTable.check_and_update` and `cull`.
    fn golden() -> serde_json::Value {
        serde_json::from_str(include_str!(
            "../tests/fixtures/announce_rate/rate_table.json"
        ))
        .unwrap()
    }

    fn now() -> f64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs_f64()
    }

    /// When an interface configures `announce_rate_target` (e.g. minimum 1.0s
    /// between announces) and a destination floods past the grace window, the
    /// table flips to blocked. Mirrors Python Transport.py.
    #[test]
    fn rate_limit_per_interface_target_kicks_in_when_configured() {
        let mut rt = RateTable::new();
        let target = 1.0;
        let grace = 2;
        let penalty = 5.0;

        // First call seeds the entry — never blocks.
        let blocked = rt.check_interface_rate([0xAA; 16], target, grace, penalty);
        assert!(!blocked, "first announce must not be blocked");

        // Hammer the table fast enough that current_rate < target every time.
        // After grace + 1 violations it must flip to blocked.
        let mut blocked_anywhere = false;
        for _ in 0..6 {
            if rt.check_interface_rate([0xAA; 16], target, grace, penalty) {
                blocked_anywhere = true;
                break;
            }
        }
        assert!(
            blocked_anywhere,
            "after exceeding grace violations, check_interface_rate must return true (blocked)"
        );
    }

    /// Python appends the timestamp even
    /// when the announce is blocked (Storage.py).
    #[test]
    fn blocked_check_still_appends_timestamp() {
        let g = golden();
        let c = &g["blocked_appends_timestamp"];
        let (t, gr, p) = (
            c["target"].as_f64().unwrap(),
            c["grace"].as_u64().unwrap() as u32,
            c["penalty"].as_f64().unwrap(),
        );
        let d = [0x11u8; 16];
        let mut rt = RateTable::new();
        let mut got = Vec::new();
        for _ in c["steps"].as_array().unwrap() {
            let blocked = rt.check_interface_rate(d, t, gr, p);
            let e = rt.iter().find(|(h, _)| h.as_bytes() == &d).unwrap().1;
            got.push((blocked, e.timestamps.len(), e.violations));
        }
        let want: Vec<(bool, usize, u32)> = c["steps"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| {
                (
                    s["blocked"].as_bool().unwrap(),
                    s["n_timestamps"].as_u64().unwrap() as usize,
                    s["rate_violations"].as_u64().unwrap() as u32,
                )
            })
            .collect();
        assert_eq!(
            got, want,
            "(blocked, n_timestamps, violations) per step vs AnnounceRateTable 1.6.0"
        );
    }

    /// Cull removes only entries both older than the retain window and no longer
    /// blocked (Storage.py).
    #[test]
    fn cull_keeps_actively_blocked_entry() {
        let g = golden();
        let ttl = g["RATE_TABLE_RETAIN"].as_f64().unwrap();
        let d = [0x11u8; 16];
        let mut rt = RateTable::new();
        rt.check_interface_rate(d, 60.0, 0, 7200.0);
        assert!(
            rt.check_interface_rate(d, 60.0, 0, 7200.0),
            "precondition: blocked"
        );
        let later = now() + ttl + 100.0;
        rt.cull(later, ttl);
        assert_eq!(
            rt.iter().any(|(h, _)| h.as_bytes() == &d),
            g["cull_keeps_blocked"]["survives"].as_bool().unwrap(),
            "blocked entry past the retain window"
        );
        let mut unblocked = RateTable::new();
        unblocked.check_interface_rate(d, 60.0, 0, 7200.0);
        unblocked.cull(later, ttl);
        assert_eq!(
            unblocked.iter().any(|(h, _)| h.as_bytes() == &d),
            g["cull_removes_unblocked_stale"]["survives"]
                .as_bool()
                .unwrap(),
            "unblocked entry past the retain window"
        );
    }
}
