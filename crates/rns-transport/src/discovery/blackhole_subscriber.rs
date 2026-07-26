//! Pure-data subscriber state machine for the distributed blackhole list.
//!
//! Tracks per-source "last pulled at" timestamps and decides which sources
//! are due for a refresh on the current tick. The actual link
//! establishment + `/list` request lives in the runtime layer; this module
//! is intentionally free of tokio so the due-source logic can be unit
//! tested without timers or fakes.
//!
//! Mirrors the scheduling half of Python's `BlackholeUpdater.job()` loop
//! (RNS/Discovery.py:693) with the same constants:
//! `INITIAL_WAIT=20s`, `JOB_INTERVAL=60s`, `UPDATE_INTERVAL=3600s`.

use std::collections::HashMap;
use std::time::Duration;

use rns_wire::types::IdentityHash;

/// Python `BlackholeUpdater.INITIAL_WAIT` — delay before the first job tick.
pub const INITIAL_WAIT: Duration = Duration::from_secs(20);

/// Python `BlackholeUpdater.JOB_INTERVAL` — time between scheduling sweeps.
pub const JOB_INTERVAL: Duration = Duration::from_secs(60);

/// Python `BlackholeUpdater.UPDATE_INTERVAL` — default minimum gap between
/// successful pulls from the same source (1 hour). Python 1.3.8 makes this
/// configurable via `blackhole_update_interval` (Reticulum.py:593-596,
/// consumed at Discovery.py:749); the config-side minutes→seconds conversion
/// and 2-minute clamp live at the parse site, this module takes seconds.
pub const UPDATE_INTERVAL: Duration = Duration::from_secs(60 * 60);

/// Python `BlackholeUpdater.SOURCE_TIMEOUT` — kept here for parity but
/// currently unused; the runtime wrapper races it against the link
/// establishment / request when it lands.
pub const SOURCE_TIMEOUT: Duration = Duration::from_secs(25);

/// Per-process subscriber state. Cheap to clone for inspection; the runtime
/// owner holds the authoritative copy.
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
    pub fn new() -> Self {
        Self::default()
    }

    /// Override the per-source pull interval. The caller passes seconds
    /// already clamped at config parse (min 2 minutes, Reticulum.py:593-596).
    pub fn with_update_interval(mut self, interval: Duration) -> Self {
        self.update_interval = interval;
        self
    }

    pub fn update_interval(&self) -> Duration {
        self.update_interval
    }

    /// Record a successful pull from `source` at `now` (Unix seconds).
    pub fn mark_updated(&mut self, source: IdentityHash, now: f64) {
        self.last_updates.insert(source, now);
    }

    /// Clear the last-update cursor for `source`, forcing the next tick
    /// to re-pull even if `UPDATE_INTERVAL` has not elapsed. Useful when
    /// an operator edits `blackhole_sources` and wants an immediate
    /// refresh.
    pub fn forget(&mut self, source: &IdentityHash) {
        self.last_updates.remove(source);
    }

    /// Returns the list of sources that should be pulled on this tick,
    /// given the configured source list and the current time.
    ///
    /// Order is deterministic (sorted by identity hash) so the runtime
    /// does not accidentally thundering-herd one source ahead of another
    /// after a restart.
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

    /// Drop cursors for sources that no longer appear in `configured`.
    /// Keeps the table bounded when an operator rotates their source
    /// list.
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
