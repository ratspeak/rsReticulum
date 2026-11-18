//! Per-interface ingress/egress control for announce and path-request floods.
//!
//! A controller tracks explicitly recorded samples and provides limiter
//! decisions and a destination-keyed announce hold buffer. The actor applies
//! announce holding to unknown destinations, excluding local-client traffic
//! and replies to pending path requests. Held entries are released one at a
//! time by the caller, subject to a time gate, frequency and hop priority.
//!
//! New interfaces use lower default burst thresholds than established ones.
//! Ingress and optional outgoing path-request control have separate switches;
//! neither setting is a general packet bandwidth limit.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use bytes::Bytes;

use crate::constants::{
    AR_FREQ_DECAY, EC_BURST_MIN_SAMPLES, EC_PR_FREQ, EGRESS_CONTROL, IA_FREQ_SAMPLES,
    IC_BURST_FREQ, IC_BURST_FREQ_NEW, IC_BURST_HOLD, IC_BURST_PENALTY, IC_DEQUE_MIN_SAMPLE,
    IC_HELD_RELEASE_INTERVAL, IC_NEW_TIME, IC_PR_BURST_FREQ, IC_PR_BURST_FREQ_NEW, IP_FREQ_SAMPLES,
    MAX_HELD_ANNOUNCES, OA_FREQ_SAMPLES, OP_FREQ_SAMPLES, PATHFINDER_M, PR_FREQ_DECAY,
};

/// Extra qualifying calls before a path-request burst clears (Interface.py).
const PR_BURST_COOLDOWN: u8 = 3;

/// Per-interface limiter settings. `None` keeps the controller default.
/// Frequencies are events per second, durations are seconds, and `max_held`
/// limits destination count rather than bytes. Validation accepts zero;
/// disable ingress with `enabled = Some(false)`, not zero thresholds.
#[derive(Debug, Clone, Default)]
pub struct IngressOverrides {
    pub enabled: Option<bool>,
    pub burst_freq_new: Option<f64>,
    pub burst_freq: Option<f64>,
    pub pr_burst_freq_new: Option<f64>,
    pub pr_burst_freq: Option<f64>,
    pub new_time: Option<f64>,
    pub burst_hold: Option<f64>,
    pub burst_penalty: Option<f64>,
    pub max_held: Option<usize>,
    pub held_release_interval: Option<f64>,
    pub ec_pr_freq: Option<f64>,
    pub egress_control: Option<bool>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error(
    "invalid ingress override {field}: must be finite, and a duration nonnegative and representable"
)]
pub struct IngressOverrideError {
    pub field: &'static str,
}
// Interface.py only compares a frequency, so a negative one is kept and always trips.
fn valid_frequency(value: f64) -> bool {
    value.is_finite()
}
fn valid_time(value: f64) -> bool {
    Duration::try_from_secs_f64(value)
        .ok()
        .is_some_and(|duration| Instant::now().checked_add(duration).is_some())
}

impl IngressOverrides {
    /// Reject nonfinite frequencies and durations that cannot be added to the
    /// current monotonic clock. This does not cap `max_held` or
    /// establish a maximum memory budget.
    pub fn validate(&self) -> Result<(), IngressOverrideError> {
        for (field, value) in [
            ("ic_burst_freq_new", self.burst_freq_new),
            ("ic_burst_freq", self.burst_freq),
            ("ic_pr_burst_freq_new", self.pr_burst_freq_new),
            ("ic_pr_burst_freq", self.pr_burst_freq),
            ("ec_pr_freq", self.ec_pr_freq),
        ] {
            if value.is_some_and(|value| !valid_frequency(value)) {
                return Err(IngressOverrideError { field });
            }
        }
        for (field, value) in [
            ("ic_new_time", self.new_time),
            ("ic_burst_hold", self.burst_hold),
            ("ic_burst_penalty", self.burst_penalty),
            ("ic_held_release_interval", self.held_release_interval),
        ] {
            if value.is_some_and(|value| !valid_time(value)) {
                return Err(IngressOverrideError { field });
            }
        }
        Ok(())
    }

    pub fn is_empty(&self) -> bool {
        self.enabled.is_none()
            && self.burst_freq_new.is_none()
            && self.burst_freq.is_none()
            && self.pr_burst_freq_new.is_none()
            && self.pr_burst_freq.is_none()
            && self.new_time.is_none()
            && self.burst_hold.is_none()
            && self.burst_penalty.is_none()
            && self.max_held.is_none()
            && self.held_release_interval.is_none()
            && self.ec_pr_freq.is_none()
            && self.egress_control.is_none()
    }
}

/// An announce parked in the hold buffer, awaiting release.
#[derive(Debug, Clone)]
pub struct HeldAnnounce {
    pub raw: Bytes,
    pub destination_hash: [u8; 16],
    /// Hops at reception — lower values win release priority.
    pub hops: u8,
    pub receiving_interface_id: u64,
}

/// Monotonic-clock samples and limiter state for one interface. Record events
/// through the `received_*`/`sent_*` methods before consulting limiters. Every
/// frequency read, status getters included, drops at most one stale sample.
#[derive(Debug)]
pub struct IngressController {
    created: Instant,
    enabled: bool,
    /// Incoming announce timestamps; capped at `IA_FREQ_SAMPLES`.
    ia_freq_deque: VecDeque<Instant>,
    /// Outgoing announce timestamps; capped at `OA_FREQ_SAMPLES`.
    oa_freq_deque: VecDeque<Instant>,
    /// Incoming path-request timestamps; capped at `IP_FREQ_SAMPLES`.
    ip_freq_deque: VecDeque<Instant>,
    /// Outgoing path-request timestamps; capped at `OP_FREQ_SAMPLES`.
    op_freq_deque: VecDeque<Instant>,
    burst_active: bool,
    burst_activated: Instant,
    burst_sustained: Instant,
    pr_burst_active: bool,
    pr_burst_activated: Instant,
    pr_burst_sustained: Instant,
    pr_burst_cooldown: u8,
    /// Radio-class interfaces never hold announces; path requests still limit.
    announce_limit: bool,
    /// Earliest instant at which the next held announce may be released.
    held_release: Instant,
    /// One entry per destination, in insertion order.
    held_announces: Vec<HeldAnnounce>,
    /// Python `arxc`/`atxc`/`prxc`/`ptxc`: every sample, unbounded.
    announces_received: u64,
    announces_sent: u64,
    path_requests_received: u64,
    path_requests_sent: u64,
    /// Python `arxb`/`atxb`/`prxb`/`ptxb`, including spawned children's.
    announce_rx_bytes: u64,
    announce_tx_bytes: u64,
    path_request_rx_bytes: u64,
    path_request_tx_bytes: u64,

    burst_freq_new: f64,
    burst_freq: f64,
    pr_burst_freq_new: f64,
    pr_burst_freq: f64,
    new_time: f64,
    burst_hold: f64,
    burst_penalty: f64,
    max_held: usize,
    held_release_interval: f64,
    ec_pr_freq: f64,
    egress_control: bool,
}

impl IngressController {
    pub fn new() -> Self {
        let now = Instant::now();
        Self {
            created: now,
            enabled: true,
            ia_freq_deque: VecDeque::with_capacity(IA_FREQ_SAMPLES),
            oa_freq_deque: VecDeque::with_capacity(OA_FREQ_SAMPLES),
            ip_freq_deque: VecDeque::with_capacity(IP_FREQ_SAMPLES),
            op_freq_deque: VecDeque::with_capacity(OP_FREQ_SAMPLES),
            burst_active: false,
            burst_activated: now,
            burst_sustained: now,
            pr_burst_active: false,
            pr_burst_activated: now,
            pr_burst_sustained: now,
            pr_burst_cooldown: 0,
            announce_limit: true,
            held_release: now,
            held_announces: Vec::new(),
            announces_received: 0,
            announces_sent: 0,
            path_requests_received: 0,
            path_requests_sent: 0,
            announce_rx_bytes: 0,
            announce_tx_bytes: 0,
            path_request_rx_bytes: 0,
            path_request_tx_bytes: 0,
            burst_freq_new: IC_BURST_FREQ_NEW,
            burst_freq: IC_BURST_FREQ,
            pr_burst_freq_new: IC_PR_BURST_FREQ_NEW,
            pr_burst_freq: IC_PR_BURST_FREQ,
            new_time: IC_NEW_TIME,
            burst_hold: IC_BURST_HOLD,
            burst_penalty: IC_BURST_PENALTY,
            max_held: MAX_HELD_ANNOUNCES,
            held_release_interval: IC_HELD_RELEASE_INTERVAL,
            ec_pr_freq: EC_PR_FREQ,
            egress_control: EGRESS_CONTROL,
        }
    }

    /// Create default settings with ingress limiting disabled. Explicit sample
    /// recording still works; both inbound limiter checks return false. The
    /// default outgoing path-request limiter is also disabled.
    pub fn disabled() -> Self {
        let mut ctrl = Self::new();
        ctrl.enabled = false;
        ctrl
    }

    /// Validate and apply settings to a new controller. Unset fields keep
    /// defaults; ingress is enabled and outgoing path-request control is off.
    pub fn try_with_overrides(overrides: &IngressOverrides) -> Result<Self, IngressOverrideError> {
        overrides.validate()?;
        Ok(Self::apply_overrides(overrides))
    }

    /// Compatibility constructor that discards invalid frequency/duration
    /// overrides and keeps their defaults. Prefer [`Self::try_with_overrides`]
    /// when invalid configuration must be reported.
    #[deprecated(note = "use try_with_overrides for configuration validation")]
    pub fn with_overrides(overrides: &IngressOverrides) -> Self {
        let mut safe = overrides.clone();
        safe.burst_freq_new = safe.burst_freq_new.filter(|value| valid_frequency(*value));
        safe.burst_freq = safe.burst_freq.filter(|value| valid_frequency(*value));
        safe.pr_burst_freq_new = safe
            .pr_burst_freq_new
            .filter(|value| valid_frequency(*value));
        safe.pr_burst_freq = safe.pr_burst_freq.filter(|value| valid_frequency(*value));
        safe.ec_pr_freq = safe.ec_pr_freq.filter(|value| valid_frequency(*value));
        safe.new_time = safe.new_time.filter(|value| valid_time(*value));
        safe.burst_hold = safe.burst_hold.filter(|value| valid_time(*value));
        safe.burst_penalty = safe.burst_penalty.filter(|value| valid_time(*value));
        safe.held_release_interval = safe
            .held_release_interval
            .filter(|value| valid_time(*value));
        Self::apply_overrides(&safe)
    }

    fn apply_overrides(overrides: &IngressOverrides) -> Self {
        let mut ctrl = Self::new();
        if let Some(v) = overrides.enabled {
            ctrl.enabled = v;
        }
        if let Some(v) = overrides.burst_freq_new {
            ctrl.burst_freq_new = v;
        }
        if let Some(v) = overrides.burst_freq {
            ctrl.burst_freq = v;
        }
        if let Some(v) = overrides.pr_burst_freq_new {
            ctrl.pr_burst_freq_new = v;
        }
        if let Some(v) = overrides.pr_burst_freq {
            ctrl.pr_burst_freq = v;
        }
        if let Some(v) = overrides.new_time {
            ctrl.new_time = v;
        }
        if let Some(v) = overrides.burst_hold {
            ctrl.burst_hold = v;
        }
        if let Some(v) = overrides.burst_penalty {
            ctrl.burst_penalty = v;
        }
        if let Some(v) = overrides.max_held {
            ctrl.max_held = v;
        }
        if let Some(v) = overrides.held_release_interval {
            ctrl.held_release_interval = v;
        }
        if let Some(v) = overrides.ec_pr_freq {
            ctrl.ec_pr_freq = v;
        }
        if let Some(v) = overrides.egress_control {
            ctrl.egress_control = v;
        }
        ctrl
    }

    pub fn burst_freq(&self) -> f64 {
        self.burst_freq
    }

    pub fn burst_freq_new(&self) -> f64 {
        self.burst_freq_new
    }

    pub fn pr_burst_freq(&self) -> f64 {
        self.pr_burst_freq
    }

    pub fn pr_burst_freq_new(&self) -> f64 {
        self.pr_burst_freq_new
    }

    pub fn ec_pr_freq(&self) -> f64 {
        self.ec_pr_freq
    }

    pub fn is_egress_control_enabled(&self) -> bool {
        self.egress_control
    }

    pub fn held_release_interval(&self) -> f64 {
        self.held_release_interval
    }

    /// Time gate for the next held release, set on burst activation and after
    /// each release. Reaching this instant is insufficient by itself: release
    /// also requires the measured frequency to be below its threshold.
    pub fn held_release_at(&self) -> Instant {
        self.held_release
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Stop announce ingress limiting, as Python's Serial, KISS, AX.25 KISS
    /// and RNode interfaces do; path-request limiting is unaffected.
    pub fn exempt_announce_limit(&mut self) {
        self.announce_limit = false;
    }

    pub fn is_announce_limit_exempt(&self) -> bool {
        !self.announce_limit
    }

    pub fn age(&self) -> f64 {
        self.created.elapsed().as_secs_f64()
    }

    pub fn received_announce(&mut self) {
        self.received_announce_bytes(0);
    }

    pub fn sent_announce(&mut self) {
        self.sent_announce_bytes(0);
    }

    pub fn received_path_request(&mut self) {
        self.received_path_request_bytes(0);
    }

    pub fn sent_path_request(&mut self) {
        self.sent_path_request_bytes(0);
    }

    /// Python `received_announce(size)` (Interface.py).
    pub fn received_announce_bytes(&mut self, size: usize) {
        self.announces_received = self.announces_received.saturating_add(1);
        self.spawned_received_announce(size);
    }

    pub fn sent_announce_bytes(&mut self, size: usize) {
        self.announces_sent = self.announces_sent.saturating_add(1);
        self.spawned_sent_announce(size);
    }

    pub fn received_path_request_bytes(&mut self, size: usize) {
        self.path_requests_received = self.path_requests_received.saturating_add(1);
        self.spawned_received_path_request(size);
    }

    pub fn sent_path_request_bytes(&mut self, size: usize) {
        self.path_requests_sent = self.path_requests_sent.saturating_add(1);
        self.spawned_sent_path_request(size);
    }

    /// A spawned child's announce on its parent: a frequency sample and the
    /// bytes, but no count (`from_spawned=True`, TCPInterface.py).
    pub fn spawned_received_announce(&mut self, size: usize) {
        self.announce_rx_bytes = self.announce_rx_bytes.saturating_add(size as u64);
        push_sample(&mut self.ia_freq_deque, IA_FREQ_SAMPLES, Instant::now());
    }

    pub fn spawned_sent_announce(&mut self, size: usize) {
        self.announce_tx_bytes = self.announce_tx_bytes.saturating_add(size as u64);
        push_sample(&mut self.oa_freq_deque, OA_FREQ_SAMPLES, Instant::now());
    }

    pub fn spawned_received_path_request(&mut self, size: usize) {
        self.path_request_rx_bytes = self.path_request_rx_bytes.saturating_add(size as u64);
        push_sample(&mut self.ip_freq_deque, IP_FREQ_SAMPLES, Instant::now());
    }

    pub fn spawned_sent_path_request(&mut self, size: usize) {
        self.path_request_tx_bytes = self.path_request_tx_bytes.saturating_add(size as u64);
        push_sample(&mut self.op_freq_deque, OP_FREQ_SAMPLES, Instant::now());
    }

    /// Python `arxb`, `atxb`, `prxb` and `ptxb`.
    pub fn announce_and_path_request_bytes(&self) -> (u64, u64, u64, u64) {
        (
            self.announce_rx_bytes,
            self.announce_tx_bytes,
            self.path_request_rx_bytes,
            self.path_request_tx_bytes,
        )
    }

    pub fn announces_received(&self) -> u64 {
        self.announces_received
    }

    pub fn announces_sent(&self) -> u64 {
        self.announces_sent
    }

    pub fn path_requests_received(&self) -> u64 {
        self.path_requests_received
    }

    pub fn path_requests_sent(&self) -> u64 {
        self.path_requests_sent
    }

    pub fn incoming_announce_frequency(&mut self) -> f64 {
        frequency_from_deque_mut(
            &mut self.ia_freq_deque,
            IC_DEQUE_MIN_SAMPLE,
            Duration::from_secs_f64(AR_FREQ_DECAY),
            false,
        )
    }

    pub fn outgoing_announce_frequency(&mut self) -> f64 {
        frequency_from_deque_mut(
            &mut self.oa_freq_deque,
            1,
            Duration::from_secs_f64(AR_FREQ_DECAY),
            false,
        )
    }

    pub fn incoming_pr_frequency(&mut self) -> f64 {
        frequency_from_deque_mut(
            &mut self.ip_freq_deque,
            IC_DEQUE_MIN_SAMPLE,
            Duration::from_secs_f64(PR_FREQ_DECAY),
            false,
        )
    }

    /// With `preemptive`, the next request is counted as already sent.
    pub fn outgoing_pr_frequency(&mut self, preemptive: bool) -> f64 {
        frequency_from_deque_mut(
            &mut self.op_freq_deque,
            1,
            Duration::from_secs_f64(PR_FREQ_DECAY),
            preemptive,
        )
    }

    fn hold(&self) -> Duration {
        Duration::from_secs_f64(self.burst_hold)
    }

    /// Update announce burst state and return whether selected inbound announces
    /// should be held. While active, the burst clears once the frequency is
    /// below threshold, both activation and the last above-threshold sample are
    /// older than `burst_hold`, and at least `IC_DEQUE_MIN_SAMPLE` samples
    /// remain. The clearing call still returns true. Disabled or exempt
    /// controllers always return false.
    pub fn should_ingress_limit(&mut self) -> bool {
        if !self.enabled || !self.announce_limit {
            return false;
        }

        let freq_threshold = if self.age() < self.new_time {
            self.burst_freq_new
        } else {
            self.burst_freq
        };
        let ia_freq = self.incoming_announce_frequency();
        let now = Instant::now();
        let hold = self.hold();

        if self.burst_active {
            if ia_freq < freq_threshold
                && sample_age(now, self.burst_activated) > hold
                && sample_age(now, self.burst_sustained) > hold
            {
                if self.ia_freq_deque.len() >= IC_DEQUE_MIN_SAMPLE {
                    self.burst_active = false;
                }
            } else if ia_freq >= freq_threshold {
                self.burst_sustained = now;
            }
            true
        } else if ia_freq > freq_threshold {
            self.burst_active = true;
            self.burst_activated = now;
            self.burst_sustained = now;
            self.held_release = now
                .checked_add(Duration::from_secs_f64(self.burst_penalty))
                .unwrap_or(now);
            true
        } else {
            false
        }
    }

    /// Update the separate path-request burst state for unknown recursive
    /// discovery. Clearing needs the announce conditions plus three further
    /// qualifying calls; any non-qualifying call restarts that cooldown.
    /// Disabled ingress always returns false.
    pub fn should_ingress_limit_pr(&mut self) -> bool {
        if !self.enabled {
            return false;
        }

        let freq_threshold = if self.age() < self.new_time {
            self.pr_burst_freq_new
        } else {
            self.pr_burst_freq
        };
        let ip_freq = self.incoming_pr_frequency();
        let now = Instant::now();
        let hold = self.hold();

        if self.pr_burst_active {
            if ip_freq < freq_threshold
                && sample_age(now, self.pr_burst_activated) > hold
                && sample_age(now, self.pr_burst_sustained) > hold
            {
                if self.pr_burst_cooldown == 0 {
                    self.pr_burst_active = false;
                } else {
                    self.pr_burst_cooldown -= 1;
                }
            } else {
                self.pr_burst_cooldown = PR_BURST_COOLDOWN;
                if ip_freq >= freq_threshold {
                    self.pr_burst_sustained = now;
                }
            }
            true
        } else if ip_freq > freq_threshold {
            self.pr_burst_active = true;
            self.pr_burst_activated = now;
            self.pr_burst_sustained = now;
            self.pr_burst_cooldown = PR_BURST_COOLDOWN;
            true
        } else {
            false
        }
    }

    /// Whether sending one more path request would exceed `ec_pr_freq`, with
    /// at least `EC_BURST_MIN_SAMPLES` recorded. Controlled by
    /// `egress_control`, independently of inbound `enabled`; off by default.
    pub fn should_egress_limit_pr(&mut self) -> bool {
        if !self.egress_control {
            return false;
        }
        self.outgoing_pr_frequency(true) > self.ec_pr_freq
            && self.op_freq_deque.len() >= EC_BURST_MIN_SAMPLES
    }

    /// Store or replace an announce by destination hash, without validating
    /// its packet. Discard hop counts of 127 or more and new destinations when
    /// `max_held` is reached; existing destinations can still be replaced.
    /// This does not consult the enabled flag or a limiter decision.
    pub fn hold_announce(&mut self, announce: HeldAnnounce) {
        // Python 1.3.8 Interface.py: announces already at the hop cap
        // would be dropped by every receiver on release — don't hold them.
        if announce.hops >= PATHFINDER_M - 1 {
            return;
        }
        if let Some(held) = self
            .held_announces
            .iter_mut()
            .find(|held| held.destination_hash == announce.destination_hash)
        {
            *held = announce;
        } else if self.held_announces.len() < self.max_held {
            self.held_announces.push(announce);
        }
    }

    /// Release at most one held announce per call — the one with the lowest
    /// hop count, the earliest held among ties. Both the release time and a
    /// frequency strictly below the current threshold are required. It does
    /// not consult `should_ingress_limit` or the enabled flag, and can release
    /// while burst state remains set. The returned entry is removed; the caller
    /// must process it, since this helper does not send packets.
    pub fn try_release_held(&mut self) -> Option<HeldAnnounce> {
        if self.held_announces.is_empty() {
            return None;
        }

        let now = Instant::now();
        if now < self.held_release {
            return None;
        }

        let freq_threshold = if self.age() < self.new_time {
            self.burst_freq_new
        } else {
            self.burst_freq
        };

        if self.incoming_announce_frequency() >= freq_threshold {
            return None;
        }

        let mut best: Option<usize> = None;
        for (idx, held) in self.held_announces.iter().enumerate() {
            if best.is_none_or(|b| held.hops < self.held_announces[b].hops) {
                best = Some(idx);
            }
        }
        let announce = self.held_announces.remove(best?);
        self.held_release = now
            .checked_add(Duration::from_secs_f64(self.held_release_interval))
            .unwrap_or(now);
        Some(announce)
    }

    pub fn held_count(&self) -> usize {
        self.held_announces.len()
    }

    pub fn is_burst_active(&self) -> bool {
        self.burst_active
    }

    pub fn burst_activated(&self) -> Instant {
        self.burst_activated
    }

    pub fn is_pr_burst_active(&self) -> bool {
        self.pr_burst_active
    }

    pub fn pr_burst_activated(&self) -> Instant {
        self.pr_burst_activated
    }
}

impl Default for IngressController {
    fn default() -> Self {
        Self::new()
    }
}

fn push_sample(deque: &mut VecDeque<Instant>, cap: usize, now: Instant) {
    if deque.len() >= cap {
        deque.pop_front();
    }
    deque.push_back(now);
}

/// Upstream's frequency: drop one stale oldest sample when the window is older
/// than the decay horizon, then divide the pre-drop count by the oldest span.
fn frequency_from_deque_mut(
    deque: &mut VecDeque<Instant>,
    min_samples: usize,
    decay: Duration,
    preemptive: bool,
) -> f64 {
    if deque.len() <= min_samples {
        return 0.0;
    }
    let n = deque.len() + usize::from(preemptive);
    let now = Instant::now();
    let Some(oldest) = deque.front().copied() else {
        return 0.0;
    };
    if sample_age(now, oldest) > decay {
        deque.pop_front();
    }
    let span = sample_age(now, oldest).as_secs_f64();
    if span <= 0.0 { 0.0 } else { n as f64 / span }
}

fn sample_age(now: Instant, sample: Instant) -> Duration {
    now.checked_duration_since(sample)
        .unwrap_or_else(|| Duration::from_secs(0))
}

#[cfg(test)]
mod tests {
    #[test]
    #[allow(deprecated)]
    fn hostile_ingress_overrides_are_rejected_or_individually_defaulted() {
        for bad in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY, -1.0, f64::MAX] {
            let overrides = super::IngressOverrides {
                burst_penalty: Some(bad),
                burst_freq: Some(4.0),
                ..Default::default()
            };
            assert!(super::IngressController::try_with_overrides(&overrides).is_err());
            let safe = super::IngressController::with_overrides(&overrides);
            assert_eq!(safe.burst_freq, 4.0);
            assert_eq!(safe.burst_penalty, super::IC_BURST_PENALTY);
        }
        let zero = super::IngressOverrides {
            burst_penalty: Some(0.0),
            burst_freq: Some(0.0),
            ..Default::default()
        };
        assert!(super::IngressController::try_with_overrides(&zero).is_ok());
        let negative = super::IngressOverrides {
            burst_freq_new: Some(-1.0),
            burst_freq: Some(-1.0),
            ..Default::default()
        };
        let mut ctrl = super::IngressController::try_with_overrides(&negative).unwrap();
        assert!(ctrl.should_ingress_limit());
    }

    use super::*;

    fn push_samples(
        deque: &mut VecDeque<Instant>,
        cap: usize,
        count: usize,
        oldest_age: f64,
        spacing: f64,
    ) {
        let now = Instant::now();
        for i in 0..count {
            let age = oldest_age - (i as f64 * spacing);
            push_sample(deque, cap, now - Duration::from_secs_f64(age.max(0.0)));
        }
    }

    #[test]
    fn reticulum_125_control_constants_are_pinned() {
        assert_eq!(IA_FREQ_SAMPLES, 48);
        assert_eq!(OA_FREQ_SAMPLES, 48);
        assert_eq!(IP_FREQ_SAMPLES, 48);
        assert_eq!(OP_FREQ_SAMPLES, 48);
        assert_eq!(AR_FREQ_DECAY, 10.0);
        assert_eq!(PR_FREQ_DECAY, 10.0);
        assert_eq!(IC_DEQUE_MIN_SAMPLE, 2);
        assert_eq!(EC_BURST_MIN_SAMPLES, 2);
        assert_eq!(IC_BURST_FREQ_NEW, 3.0);
        assert_eq!(IC_BURST_FREQ, 10.0);
        assert_eq!(IC_PR_BURST_FREQ_NEW, 3.0);
        assert_eq!(IC_PR_BURST_FREQ, 8.0);
        assert_eq!(IC_BURST_HOLD, 15.0);
        assert_eq!(IC_BURST_PENALTY, 15.0);
        assert_eq!(IC_HELD_RELEASE_INTERVAL, 5.0);
        assert_eq!(EC_PR_FREQ, 5.0);
        const { assert!(!EGRESS_CONTROL) };
        // Interface.py 1.6.1, the `ic_max_held_announces` default.
        assert_eq!(MAX_HELD_ANNOUNCES, 64);
        assert_eq!(IngressController::new().max_held, 64);
    }

    #[test]
    fn ingress_controller_default_state() {
        let mut ctrl = IngressController::new();
        assert!(ctrl.is_enabled());
        assert!(!ctrl.is_burst_active());
        assert!(!ctrl.is_pr_burst_active());
        assert!(!ctrl.is_egress_control_enabled());
        assert_eq!(ctrl.pr_burst_freq_new(), IC_PR_BURST_FREQ_NEW);
        assert_eq!(ctrl.pr_burst_freq(), IC_PR_BURST_FREQ);
        assert_eq!(ctrl.ec_pr_freq(), EC_PR_FREQ);
        assert_eq!(ctrl.held_count(), 0);
        assert_eq!(ctrl.incoming_announce_frequency(), 0.0);
        assert_eq!(ctrl.incoming_pr_frequency(), 0.0);
        assert_eq!(ctrl.outgoing_pr_frequency(false), 0.0);
    }

    #[test]
    fn ingress_disabled_never_limits() {
        let mut ctrl = IngressController::disabled();
        for _ in 0..100 {
            ctrl.received_announce();
        }
        assert!(!ctrl.should_ingress_limit());
    }

    /// Python 1.5.5 counts every announce and path request it receives or
    /// sends (`arxc`/`atxc`/`prxc`/`ptxc`, Interface.py), past the
    /// bounded frequency windows and with ingress control off.
    #[test]
    fn announce_and_path_request_counts_outlast_the_sample_windows() {
        for mut ctrl in [IngressController::new(), IngressController::disabled()] {
            assert_eq!(
                (
                    ctrl.announces_received(),
                    ctrl.announces_sent(),
                    ctrl.path_requests_received(),
                    ctrl.path_requests_sent()
                ),
                (0, 0, 0, 0)
            );
            for _ in 0..IA_FREQ_SAMPLES + 2 {
                ctrl.received_announce();
            }
            for _ in 0..2 {
                ctrl.sent_announce();
            }
            ctrl.received_path_request();
            for _ in 0..OP_FREQ_SAMPLES + 3 {
                ctrl.sent_path_request();
            }
            assert_eq!(ctrl.announces_received(), IA_FREQ_SAMPLES as u64 + 2);
            assert_eq!(ctrl.announces_sent(), 2);
            assert_eq!(ctrl.path_requests_received(), 1);
            assert_eq!(ctrl.path_requests_sent(), OP_FREQ_SAMPLES as u64 + 3);
        }
    }

    #[test]
    fn disabled_ingress_control_keeps_frequency_stats() {
        let mut ctrl = IngressController::disabled();
        push_samples(&mut ctrl.ia_freq_deque, IA_FREQ_SAMPLES, 4, 1.0, 0.2);
        push_samples(&mut ctrl.ip_freq_deque, IP_FREQ_SAMPLES, 4, 1.0, 0.2);

        assert!(!ctrl.should_ingress_limit());
        assert!(!ctrl.should_ingress_limit_pr());
        assert!(ctrl.incoming_announce_frequency() > 0.0);
        assert!(ctrl.incoming_pr_frequency() > 0.0);
    }

    #[test]
    fn stale_status_frequency_decays_one_sample_per_read() {
        let mut ctrl = IngressController::new();
        push_samples(
            &mut ctrl.ia_freq_deque,
            IA_FREQ_SAMPLES,
            IC_DEQUE_MIN_SAMPLE + 2,
            AR_FREQ_DECAY + 2.0,
            0.1,
        );
        assert!(ctrl.incoming_announce_frequency() > 0.0);
        assert_eq!(ctrl.ia_freq_deque.len(), IC_DEQUE_MIN_SAMPLE + 1);
        assert!(ctrl.incoming_announce_frequency() > 0.0);
        assert_eq!(ctrl.incoming_announce_frequency(), 0.0);
    }

    #[test]
    fn announce_burst_clear_waits_for_sustained_hold() {
        let mut ctrl = IngressController::new();
        push_samples(&mut ctrl.ia_freq_deque, IA_FREQ_SAMPLES, 4, 1.0, 0.1);
        assert!(ctrl.should_ingress_limit());
        assert!(ctrl.is_burst_active());

        let past_hold = Instant::now() - Duration::from_secs_f64(IC_BURST_HOLD + 1.0);
        ctrl.burst_activated = past_hold;
        ctrl.ia_freq_deque.clear();
        push_samples(
            &mut ctrl.ia_freq_deque,
            IA_FREQ_SAMPLES,
            IC_DEQUE_MIN_SAMPLE + 1,
            AR_FREQ_DECAY + 1.0,
            0.1,
        );
        assert!(ctrl.should_ingress_limit());
        assert!(ctrl.is_burst_active(), "sustained timestamp is recent");

        ctrl.burst_sustained = past_hold;
        assert!(ctrl.should_ingress_limit());
        assert!(!ctrl.is_burst_active());
        assert!(!ctrl.should_ingress_limit());
    }

    #[test]
    fn held_release_poll_does_not_activate_burst_when_nothing_is_held() {
        let mut ctrl = IngressController::new();
        push_samples(&mut ctrl.ia_freq_deque, IA_FREQ_SAMPLES, 4, 1.0, 0.1);

        assert!(ctrl.try_release_held().is_none());
        assert!(!ctrl.is_burst_active());
    }

    #[test]
    fn held_announces_release_while_burst_state_is_still_held() {
        let mut ctrl = IngressController::new();
        push_samples(&mut ctrl.ia_freq_deque, IA_FREQ_SAMPLES, 4, 1.0, 0.1);
        assert!(ctrl.should_ingress_limit());
        assert!(ctrl.is_burst_active());

        ctrl.ia_freq_deque.clear();
        push_samples(
            &mut ctrl.ia_freq_deque,
            IA_FREQ_SAMPLES,
            IC_DEQUE_MIN_SAMPLE + 1,
            AR_FREQ_DECAY + 1.0,
            0.1,
        );
        assert!(ctrl.should_ingress_limit());
        assert!(ctrl.is_burst_active());

        ctrl.held_release = Instant::now() - Duration::from_secs(1);
        ctrl.hold_announce(HeldAnnounce {
            raw: Bytes::from_static(&[1, 2, 3]),
            destination_hash: [0xA5; 16],
            hops: 1,
            receiving_interface_id: 1,
        });

        let released = ctrl.try_release_held();
        assert!(released.is_some());
        assert!(ctrl.is_burst_active());
    }

    #[test]
    fn pr_ingress_burst_activates_and_clears() {
        let mut ctrl = IngressController::new();
        push_samples(&mut ctrl.ip_freq_deque, IP_FREQ_SAMPLES, 4, 1.0, 0.1);

        assert!(ctrl.should_ingress_limit_pr());
        assert!(ctrl.is_pr_burst_active());

        let past_hold = Instant::now() - Duration::from_secs_f64(IC_BURST_HOLD + 1.0);
        ctrl.pr_burst_activated = past_hold;
        ctrl.pr_burst_sustained = past_hold;
        ctrl.ip_freq_deque.clear();

        for _ in 0..PR_BURST_COOLDOWN {
            assert!(ctrl.should_ingress_limit_pr());
            assert!(ctrl.is_pr_burst_active(), "cooldown still running");
        }
        assert!(ctrl.should_ingress_limit_pr());
        assert!(!ctrl.is_pr_burst_active());
        assert!(!ctrl.should_ingress_limit_pr());
    }

    #[test]
    fn pr_egress_limiting_is_optional_and_counts_the_next_request() {
        let mut disabled = IngressController::new();
        push_samples(&mut disabled.op_freq_deque, OP_FREQ_SAMPLES, 8, 1.0, 0.1);
        assert!(!disabled.should_egress_limit_pr());

        let mut ctrl = IngressController::try_with_overrides(&IngressOverrides {
            egress_control: Some(true),
            ..Default::default()
        })
        .unwrap();
        push_samples(&mut ctrl.op_freq_deque, OP_FREQ_SAMPLES, 1, 0.1, 0.0);
        assert!(!ctrl.should_egress_limit_pr());

        // Two samples 0.5 s old: (2 + 1) / 0.5 = 6 Hz > 5 Hz only preemptively.
        ctrl.op_freq_deque.clear();
        push_samples(&mut ctrl.op_freq_deque, OP_FREQ_SAMPLES, 2, 0.5, 0.0);
        assert!(ctrl.outgoing_pr_frequency(false) < EC_PR_FREQ);
        assert!(ctrl.should_egress_limit_pr());
    }

    #[test]
    fn exempt_controller_never_holds_announces_but_limits_path_requests() {
        let mut ctrl = IngressController::new();
        ctrl.exempt_announce_limit();
        push_samples(&mut ctrl.ia_freq_deque, IA_FREQ_SAMPLES, 8, 1.0, 0.1);
        push_samples(&mut ctrl.ip_freq_deque, IP_FREQ_SAMPLES, 8, 1.0, 0.1);
        assert!(!ctrl.should_ingress_limit());
        assert!(!ctrl.is_burst_active());
        assert!(ctrl.should_ingress_limit_pr());
        assert!(ctrl.incoming_announce_frequency() > 0.0);
    }

    #[test]
    fn hold_announce_dedups_by_destination() {
        let mut ctrl = IngressController::new();
        let a = HeldAnnounce {
            raw: Bytes::from_static(&[1, 2, 3]),
            destination_hash: [0u8; 16],
            hops: 1,
            receiving_interface_id: 1,
        };
        ctrl.hold_announce(a);
        assert_eq!(ctrl.held_count(), 1);

        let a2 = HeldAnnounce {
            raw: Bytes::from_static(&[4, 5, 6]),
            destination_hash: [0u8; 16],
            hops: 2,
            receiving_interface_id: 1,
        };
        ctrl.hold_announce(a2);
        assert_eq!(ctrl.held_count(), 1);

        let a3 = HeldAnnounce {
            raw: Bytes::from_static(&[7, 8, 9]),
            destination_hash: [1u8; 16],
            hops: 0,
            receiving_interface_id: 1,
        };
        ctrl.hold_announce(a3);
        assert_eq!(ctrl.held_count(), 2);
    }

    #[test]
    fn hold_announce_ignores_max_hop_announces() {
        // Python 1.3.8 Interface.py: hops >= PATHFINDER_M-1 not held.
        let mut ctrl = IngressController::new();
        ctrl.hold_announce(HeldAnnounce {
            raw: Bytes::from_static(&[1, 2, 3]),
            destination_hash: [0xA1; 16],
            hops: PATHFINDER_M - 1,
            receiving_interface_id: 1,
        });
        assert_eq!(ctrl.held_count(), 0);

        ctrl.hold_announce(HeldAnnounce {
            raw: Bytes::from_static(&[4, 5, 6]),
            destination_hash: [0xA2; 16],
            hops: PATHFINDER_M - 2,
            receiving_interface_id: 1,
        });
        assert_eq!(ctrl.held_count(), 1);
    }

    #[test]
    fn hold_announce_capped_at_max() {
        let mut ctrl = IngressController::new();
        for i in 0..MAX_HELD_ANNOUNCES {
            let mut h = [0u8; 16];
            h[0] = (i & 0xFF) as u8;
            h[1] = ((i >> 8) & 0xFF) as u8;
            ctrl.hold_announce(HeldAnnounce {
                raw: Bytes::new(),
                destination_hash: h,
                hops: 0,
                receiving_interface_id: 1,
            });
        }
        assert_eq!(ctrl.held_count(), MAX_HELD_ANNOUNCES);

        ctrl.hold_announce(HeldAnnounce {
            raw: Bytes::new(),
            destination_hash: [0xFF; 16],
            hops: 0,
            receiving_interface_id: 1,
        });
        assert_eq!(ctrl.held_count(), MAX_HELD_ANNOUNCES);
    }
}
