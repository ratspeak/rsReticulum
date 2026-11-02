//! Per-source scheduling state for distributed blackhole-list updates.
//!
//! The runtime owns waiting, Link establishment, `/list` requests and applying
//! the response. This module only compares caller-supplied timestamps and
//! records caller-reported successful updates; it performs no network I/O.

use std::collections::HashMap;
use std::time::Duration;

use rns_wire::types::IdentityHash;

/// Runtime delay before the first subscriber sweep (20 seconds).
pub const INITIAL_WAIT: Duration = Duration::from_secs(20);

/// Runtime scheduling interval (60 seconds), after processing the current
/// sweep's sources; request time can extend the observed interval.
pub const JOB_INTERVAL: Duration = Duration::from_secs(60);

/// Default minimum elapsed time after a source's last successful update
/// (one hour). [`SubscriberState::with_update_interval`] overrides it.
pub const UPDATE_INTERVAL: Duration = Duration::from_secs(60 * 60);

/// Timeout budget supplied by the runtime to each blackhole `/list` query
/// (25 seconds). This state machine itself does not enforce timeouts.
pub const SOURCE_TIMEOUT: Duration = Duration::from_secs(25);

/// In-memory per-source update cursors. Cloning copies the cursors and interval;
/// clones do not share subsequent updates. Use finite Unix-second timestamps
/// consistently; they are stored and compared without validation.
#[derive(Debug, Clone)]
pub struct SubscriberState {
    /// Unix-seconds timestamp of the most recent successful pull, keyed by
    /// source identity hash. Missing key ⇒ "never pulled".
    last_updates: HashMap<IdentityHash, f64>,
    /// Minimum gap between pulls from the same source. Defaults to
    /// [`UPDATE_INTERVAL`]; overridden by the `blackhole_update_interval`
    /// config key (Python 1.3.8 RNS.Reticulum.blackhole_update_interval()).
    update_interval: Duration,
}

impl Default for SubscriberState {
    fn default() -> Self {
        Self {
            last_updates: HashMap::new(),
            update_interval: UPDATE_INTERVAL,
        }
    }
}

impl SubscriberState {
    /// Start with no update cursors and the one-hour default interval.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the minimum elapsed time after each successful update. No minimum
    /// is enforced here; zero makes a source due whenever `now >= last_update`.
    pub fn with_update_interval(mut self, interval: Duration) -> Self {
        self.update_interval = interval;
        self
    }

    /// Return the currently configured interval.
    pub fn update_interval(&self) -> Duration {
        self.update_interval
    }

    /// Record caller-reported success at `now`, replacing any prior timestamp.
    /// This does not validate or apply the source's manifest.
    pub fn mark_updated(&mut self, source: IdentityHash, now: f64) {
        self.last_updates.insert(source, now);
    }

    /// Remove a source's cursor. Subsequent scheduling treats its last update
    /// as Unix time zero; no network request is issued by this method.
    pub fn forget(&mut self, source: &IdentityHash) {
        self.last_updates.remove(source);
    }

    /// Return configured sources for which `now - last_update >= interval`,
    /// sorted by identity hash and deduplicated. Missing cursors use zero, so
    /// they are due only once `now >= interval`.
    ///
    /// This does not advance cursors, reserve in-flight work, back off failures
    /// or stagger sources. Repeated calls can return the same due list until
    /// the caller records successful updates.
    pub fn due_sources(&self, configured: &[IdentityHash], now: f64) -> Vec<IdentityHash> {
        let mut due: Vec<IdentityHash> = configured
            .iter()
            .copied()
            .filter(|src| {
                let last = self.last_updates.get(src).copied().unwrap_or(0.0);
                now - last >= self.update_interval.as_secs_f64()
            })
            .collect();
        due.sort();
        due.dedup();
        due
    }

    /// Drop cursors whose identities are absent from `configured`. No source
    /// count limit is otherwise enforced by this state machine.
    pub fn prune(&mut self, configured: &[IdentityHash]) {
        self.last_updates
            .retain(|src, _| configured.iter().any(|c| c == src));
    }

    /// Snapshot the cursor map. Test-only surface.
    #[cfg(test)]
    pub fn snapshot(&self) -> HashMap<IdentityHash, f64> {
        self.last_updates.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(b: u8) -> IdentityHash {
        [b; 16].into()
    }

    #[test]
    fn no_sources_means_nothing_due() {
        let s = SubscriberState::new();
        assert!(s.due_sources(&[], 10_000.0).is_empty());
    }

    #[test]
    fn fresh_subscribers_are_due_immediately() {
        let s = SubscriberState::new();
        let sources = vec![h(0x11), h(0x22)];
        let due = s.due_sources(&sources, 10_000.0);
        assert_eq!(due, vec![h(0x11), h(0x22)]);
    }

    #[test]
    fn due_list_is_deterministic_sorted() {
        let s = SubscriberState::new();
        let sources = vec![h(0x33), h(0x11), h(0x22)];
        let due = s.due_sources(&sources, 10_000.0);
        assert_eq!(due, vec![h(0x11), h(0x22), h(0x33)]);
    }

    #[test]
    fn mark_updated_suppresses_source_until_interval_elapses() {
        let mut s = SubscriberState::new();
        s.mark_updated(h(0x11), 10_000.0);

        // 30 minutes later — still inside the 1h interval.
        let due = s.due_sources(&[h(0x11)], 10_000.0 + 1_800.0);
        assert!(due.is_empty());

        // Right at the interval boundary — due again.
        let due = s.due_sources(&[h(0x11)], 10_000.0 + UPDATE_INTERVAL.as_secs_f64());
        assert_eq!(due, vec![h(0x11)]);
    }

    #[test]
    fn mark_updated_does_not_affect_other_sources() {
        let mut s = SubscriberState::new();
        s.mark_updated(h(0x11), 10_000.0);

        let due = s.due_sources(&[h(0x11), h(0x22)], 10_000.0 + 30.0);
        assert_eq!(due, vec![h(0x22)]);
    }

    #[test]
    fn forget_forces_immediate_re_pull() {
        let mut s = SubscriberState::new();
        s.mark_updated(h(0x11), 10_000.0);
        s.forget(&h(0x11));

        let due = s.due_sources(&[h(0x11)], 10_000.0 + 10.0);
        assert_eq!(due, vec![h(0x11)]);
    }

    #[test]
    fn duplicate_source_entries_collapse() {
        let s = SubscriberState::new();
        let sources = vec![h(0x11), h(0x11), h(0x22), h(0x22), h(0x22)];
        let due = s.due_sources(&sources, 10_000.0);
        assert_eq!(due, vec![h(0x11), h(0x22)]);
    }

    #[test]
    fn prune_drops_cursors_for_removed_sources() {
        let mut s = SubscriberState::new();
        s.mark_updated(h(0x11), 10_000.0);
        s.mark_updated(h(0x22), 10_000.0);

        s.prune(&[h(0x22)]);

        assert!(s.snapshot().contains_key(&h(0x22)));
        assert!(!s.snapshot().contains_key(&h(0x11)));
    }

    #[test]
    fn prune_keeps_all_cursors_when_list_matches() {
        let mut s = SubscriberState::new();
        s.mark_updated(h(0x11), 10_000.0);
        s.mark_updated(h(0x22), 10_000.0);

        s.prune(&[h(0x11), h(0x22)]);

        assert_eq!(s.snapshot().len(), 2);
    }

    #[test]
    fn default_update_interval_matches_python_constant() {
        let s = SubscriberState::new();
        assert_eq!(s.update_interval(), UPDATE_INTERVAL);
    }

    #[test]
    fn configured_update_interval_overrides_default() {
        // 2 minutes — the Python config minimum after the parse-side clamp.
        let mut s = SubscriberState::new().with_update_interval(Duration::from_secs(120));
        s.mark_updated(h(0x11), 10_000.0);

        // Inside the configured window — not due, even though the default
        // 1h interval would also say not due; check the boundary instead.
        assert!(s.due_sources(&[h(0x11)], 10_000.0 + 119.0).is_empty());

        // At the configured boundary — due again, far before the 1h default.
        assert_eq!(s.due_sources(&[h(0x11)], 10_000.0 + 120.0), vec![h(0x11)]);
    }
}
