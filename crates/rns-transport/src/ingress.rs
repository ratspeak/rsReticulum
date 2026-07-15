//! Per-interface ingress/egress control for announce and path-request floods.
//!
//! Each interface owns one `IngressController`. The inbound path consults it
//! on every announce — when the incoming rate crosses the burst threshold the
//! controller activates a hold state, shunts subsequent announces into a
//! per-destination hold buffer, and the maintenance tick releases them later
//! in hop-priority order. The split thresholds for freshly-seen vs. mature
//! interfaces (`IC_BURST_FREQ_NEW` vs. `IC_BURST_FREQ`) give newly-online
//! links time to catch up from the network backlog without triggering the
//! limiter on the first burst of announces.

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

use bytes::Bytes;

use crate::constants::{
    AR_FREQ_DECAY, EC_PR_FREQ, EGRESS_CONTROL, IA_FREQ_SAMPLES, IC_BURST_FREQ, IC_BURST_FREQ_NEW,
    IC_BURST_HOLD, IC_BURST_MIN_SAMPLES, IC_BURST_PENALTY, IC_DEQUE_MIN_SAMPLE,
    IC_HELD_RELEASE_INTERVAL, IC_NEW_TIME, IC_PR_BURST_FREQ, IC_PR_BURST_FREQ_NEW, IP_FREQ_SAMPLES,
    MAX_HELD_ANNOUNCES, OA_FREQ_SAMPLES, OP_FREQ_SAMPLES, PATHFINDER_M, PR_FREQ_DECAY,
};

/// Per-interface ingress overrides parsed from `[interface.<name>] ic_*` keys.
/// Any field left `None` falls back to the corresponding crate-level constant.
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

impl IngressOverrides {
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
    pr_burst_active: bool,
    pr_burst_activated: Instant,
    /// Earliest instant at which the next held announce may be released.
    held_release: Instant,
    held_announces: HashMap<[u8; 16], HeldAnnounce>,

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
            pr_burst_active: false,
            pr_burst_activated: now,
            held_release: now,
            held_announces: HashMap::new(),
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

    /// Always-permissive controller — use when ingress control is switched off
    /// at the transport or interface level. The state machine still compiles
    /// samples so operators can read frequency stats, but `should_ingress_limit`
    /// is hard-wired to `false`.
    pub fn disabled() -> Self {
        let mut ctrl = Self::new();
        ctrl.enabled = false;
        ctrl
    }

    /// Controller with per-interface overrides applied; unset fields keep
    /// their compile-time defaults.
    pub fn with_overrides(overrides: &IngressOverrides) -> Self {
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

    /// Earliest instant at which the next held announce may be released. The
    /// cooldown starts when burst mode activates (not deactivates) so a
    /// prolonged burst cannot starve existing holds.
    pub fn held_release_at(&self) -> Instant {
        self.held_release
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    pub fn age(&self) -> f64 {
        self.created.elapsed().as_secs_f64()
    }

    pub fn received_announce(&mut self) {
        push_sample(&mut self.ia_freq_deque, IA_FREQ_SAMPLES, Instant::now());
    }

    pub fn sent_announce(&mut self) {
        push_sample(&mut self.oa_freq_deque, OA_FREQ_SAMPLES, Instant::now());
    }

    pub fn received_path_request(&mut self) {
        push_sample(&mut self.ip_freq_deque, IP_FREQ_SAMPLES, Instant::now());
    }

    pub fn sent_path_request(&mut self) {
        push_sample(&mut self.op_freq_deque, OP_FREQ_SAMPLES, Instant::now());
    }

    pub fn incoming_announce_frequency(&self) -> f64 {
        frequency_from_deque(
            &self.ia_freq_deque,
            IC_DEQUE_MIN_SAMPLE,
            Duration::from_secs_f64(AR_FREQ_DECAY),
        )
    }

    pub fn outgoing_announce_frequency(&self) -> f64 {
        frequency_from_deque(
            &self.oa_freq_deque,
            1,
            Duration::from_secs_f64(AR_FREQ_DECAY),
        )
    }

    pub fn incoming_pr_frequency(&self) -> f64 {
        frequency_from_deque(
            &self.ip_freq_deque,
            IC_DEQUE_MIN_SAMPLE,
            Duration::from_secs_f64(PR_FREQ_DECAY),
        )
    }

    pub fn outgoing_pr_frequency(&self) -> f64 {
        frequency_from_deque(
            &self.op_freq_deque,
            1,
            Duration::from_secs_f64(PR_FREQ_DECAY),
        )
    }

    /// Whether inbound announces should currently be held. Also updates the
    /// internal burst state — an exit from burst only happens once the
    /// frequency has dropped *and* `burst_hold` seconds have passed since
    /// activation, preventing flapping on a noisy interface.
    pub fn should_ingress_limit(&mut self) -> bool {
        if !self.enabled {
            return false;
        }

        let freq_threshold = if self.age() < self.new_time {
            self.burst_freq_new
        } else {
            self.burst_freq
        };

        let ia_freq = frequency_from_deque_mut(
            &mut self.ia_freq_deque,
            IC_DEQUE_MIN_SAMPLE,
            Duration::from_secs_f64(AR_FREQ_DECAY),
        );
        let now = Instant::now();

        if self.burst_active {
            if ia_freq < freq_threshold
                && now.duration_since(self.burst_activated)
                    > Duration::from_secs_f64(self.burst_hold)
                && self.ia_freq_deque.len() >= IC_BURST_MIN_SAMPLES
            {
                self.burst_active = false;
            }
            true
        } else if ia_freq > freq_threshold {
            self.burst_active = true;
            self.burst_activated = now;
            self.held_release = now + Duration::from_secs_f64(self.burst_penalty);
            true
        } else {
            false
        }
    }

    /// Whether unknown recursive path-request discovery should be suppressed
    /// on this ingress interface.
    pub fn should_ingress_limit_pr(&mut self) -> bool {
        if !self.enabled {
            return false;
        }

        let freq_threshold = if self.age() < self.new_time {
            self.pr_burst_freq_new
        } else {
            self.pr_burst_freq
        };

        let ip_freq = frequency_from_deque_mut(
            &mut self.ip_freq_deque,
            IC_DEQUE_MIN_SAMPLE,
            Duration::from_secs_f64(PR_FREQ_DECAY),
        );
        let now = Instant::now();

        if self.pr_burst_active {
            if ip_freq < freq_threshold
                && now.duration_since(self.pr_burst_activated)
                    > Duration::from_secs_f64(self.burst_hold)
            {
                self.pr_burst_active = false;
            }
            true
        } else if ip_freq > freq_threshold {
            self.pr_burst_active = true;
            self.pr_burst_activated = now;
            true
        } else {
            false
        }
    }

    /// Whether outgoing path-request transmission should be skipped on this
    /// interface. This limiter is off by default in Reticulum 1.2.5.
    pub fn should_egress_limit_pr(&mut self) -> bool {
        if !self.egress_control {
            return false;
        }

        let op_freq = frequency_from_deque_mut(
            &mut self.op_freq_deque,
            1,
            Duration::from_secs_f64(PR_FREQ_DECAY),
        );
        op_freq > self.ec_pr_freq && self.op_freq_deque.len() >= IC_BURST_MIN_SAMPLES
    }

    pub fn hold_announce(&mut self, announce: HeldAnnounce) {
        // Python 1.3.8 Interface.py:221-222: announces already at the hop cap
        // would be dropped by every receiver on release — don't hold them.
        if announce.hops >= PATHFINDER_M - 1 {
            return;
        }
        if self.held_announces.contains_key(&announce.destination_hash)
            || self.held_announces.len() < self.max_held
        {
            self.held_announces
                .insert(announce.destination_hash, announce);
        }
    }

    /// Release at most one held announce per call — the one with the lowest
    /// hop count, so short-path announces win priority. This intentionally
    /// does not consult `should_ingress_limit()`: upstream releases held
    /// announces based on release time and current announce frequency, even if
    /// the displayed burst state has not cleared yet.
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

        let ia_freq = frequency_from_deque_mut(
            &mut self.ia_freq_deque,
            IC_DEQUE_MIN_SAMPLE,
            Duration::from_secs_f64(AR_FREQ_DECAY),
        );
        if ia_freq >= freq_threshold {
            return None;
        }

        let best_hash = self
            .held_announces
            .iter()
            .min_by_key(|(_, a)| a.hops)
            .map(|(hash, _)| *hash)?;

        let announce = self.held_announces.remove(&best_hash)?;
        self.held_release = now + Duration::from_secs_f64(self.held_release_interval);
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

/// Snapshot frequency over a timestamp deque. Stale samples are ignored for
/// observability without mutating the controller from read-only status paths.
fn frequency_from_deque(deque: &VecDeque<Instant>, min_samples: usize, decay: Duration) -> f64 {
    let now = Instant::now();
    let oldest = deque
        .iter()
        .find(|sample| sample_age(now, **sample) <= decay);
    let Some(oldest) = oldest else {
        return 0.0;
    };
    let n = deque
        .iter()
        .filter(|sample| sample_age(now, **sample) <= decay)
        .count();
    frequency_from_parts(n, now, *oldest, min_samples)
}

/// Mutable limiter frequency. Mirrors upstream's decay side effect by dropping
/// one stale oldest sample when the observed window is older than the decay
/// horizon, then calculating from the current sample count and oldest span.
fn frequency_from_deque_mut(
    deque: &mut VecDeque<Instant>,
    min_samples: usize,
    decay: Duration,
) -> f64 {
    let n = deque.len();
    if n <= min_samples {
        return 0.0;
    }
    let now = Instant::now();
    let Some(oldest) = deque.front().copied() else {
        return 0.0;
    };
    if sample_age(now, oldest) > decay {
        deque.pop_front();
    }
    frequency_from_parts(n, now, oldest, min_samples)
}

fn frequency_from_parts(n: usize, now: Instant, oldest: Instant, min_samples: usize) -> f64 {
    if n <= min_samples {
        return 0.0;
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
        assert_eq!(IC_BURST_MIN_SAMPLES, 6);
        assert_eq!(IC_BURST_FREQ_NEW, 3.0);
        assert_eq!(IC_BURST_FREQ, 10.0);
        assert_eq!(IC_PR_BURST_FREQ_NEW, 3.0);
        assert_eq!(IC_PR_BURST_FREQ, 8.0);
        assert_eq!(IC_BURST_HOLD, 15.0);
        assert_eq!(IC_BURST_PENALTY, 15.0);
        assert_eq!(IC_HELD_RELEASE_INTERVAL, 5.0);
        assert_eq!(EC_PR_FREQ, 5.0);
        const { assert!(!EGRESS_CONTROL) };
    }

    #[test]
    fn ingress_controller_default_state() {
        let ctrl = IngressController::new();
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
        assert_eq!(ctrl.outgoing_pr_frequency(), 0.0);
    }

    #[test]
    fn ingress_disabled_never_limits() {
        let mut ctrl = IngressController::disabled();
        for _ in 0..100 {
            ctrl.received_announce();
        }
        assert!(!ctrl.should_ingress_limit());
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
    fn announce_frequency_ignores_decayed_samples_for_stats() {
        let mut ctrl = IngressController::new();
        push_samples(
            &mut ctrl.ia_freq_deque,
            IA_FREQ_SAMPLES,
            IC_DEQUE_MIN_SAMPLE + 2,
            AR_FREQ_DECAY + 2.0,
            0.1,
        );

        assert_eq!(ctrl.incoming_announce_frequency(), 0.0);
    }

    #[test]
    fn pr_frequency_ignores_decayed_samples_for_stats() {
        let mut ctrl = IngressController::new();
        push_samples(
            &mut ctrl.ip_freq_deque,
            IP_FREQ_SAMPLES,
            IC_DEQUE_MIN_SAMPLE + 2,
            PR_FREQ_DECAY + 2.0,
            0.1,
        );

        assert_eq!(ctrl.incoming_pr_frequency(), 0.0);
    }

    #[test]
    fn announce_burst_clears_only_with_minimum_remaining_samples() {
        let mut ctrl = IngressController::new();
        push_samples(&mut ctrl.ia_freq_deque, IA_FREQ_SAMPLES, 4, 1.0, 0.1);
        assert!(ctrl.should_ingress_limit());
        assert!(ctrl.is_burst_active());

        ctrl.burst_activated = Instant::now() - Duration::from_secs_f64(IC_BURST_HOLD + 1.0);
        ctrl.ia_freq_deque.clear();
        push_samples(
            &mut ctrl.ia_freq_deque,
            IA_FREQ_SAMPLES,
            IC_BURST_MIN_SAMPLES,
            AR_FREQ_DECAY + 1.0,
            0.1,
        );
        assert!(ctrl.should_ingress_limit());
        assert!(ctrl.is_burst_active());

        ctrl.burst_activated = Instant::now() - Duration::from_secs_f64(IC_BURST_HOLD + 1.0);
        ctrl.ia_freq_deque.clear();
        push_samples(
            &mut ctrl.ia_freq_deque,
            IA_FREQ_SAMPLES,
            IC_BURST_MIN_SAMPLES + 1,
            AR_FREQ_DECAY + 1.0,
            0.1,
        );
        assert!(ctrl.should_ingress_limit());
        assert!(!ctrl.is_burst_active());
    }

    #[test]
    fn held_release_poll_does_not_activate_burst_when_nothing_is_held() {
        let mut ctrl = IngressController::new();
        push_samples(&mut ctrl.ia_freq_deque, IA_FREQ_SAMPLES, 4, 1.0, 0.1);

        assert!(ctrl.try_release_held().is_none());
        assert!(!ctrl.is_burst_active());
    }

    #[test]
    fn held_announces_release_even_if_burst_state_is_waiting_for_clear_samples() {
        let mut ctrl = IngressController::new();
        push_samples(&mut ctrl.ia_freq_deque, IA_FREQ_SAMPLES, 4, 1.0, 0.1);
        assert!(ctrl.should_ingress_limit());
        assert!(ctrl.is_burst_active());

        ctrl.burst_activated = Instant::now() - Duration::from_secs_f64(IC_BURST_HOLD + 1.0);
        ctrl.ia_freq_deque.clear();
        push_samples(
            &mut ctrl.ia_freq_deque,
            IA_FREQ_SAMPLES,
            IC_BURST_MIN_SAMPLES,
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

        ctrl.pr_burst_activated = Instant::now() - Duration::from_secs_f64(IC_BURST_HOLD + 1.0);
        ctrl.ip_freq_deque.clear();
        push_samples(
            &mut ctrl.ip_freq_deque,
            IP_FREQ_SAMPLES,
            IC_DEQUE_MIN_SAMPLE + 1,
            PR_FREQ_DECAY + 1.0,
            0.1,
        );

        assert!(ctrl.should_ingress_limit_pr());
        assert!(!ctrl.is_pr_burst_active());
        assert!(!ctrl.should_ingress_limit_pr());
    }

    #[test]
    fn pr_egress_limiting_is_optional_and_requires_six_samples() {
        let mut disabled = IngressController::new();
        push_samples(
            &mut disabled.op_freq_deque,
            OP_FREQ_SAMPLES,
            IC_BURST_MIN_SAMPLES + 2,
            1.0,
            0.1,
        );
        assert!(!disabled.should_egress_limit_pr());

        let mut ctrl = IngressController::with_overrides(&IngressOverrides {
            egress_control: Some(true),
            ec_pr_freq: Some(EC_PR_FREQ),
            ..Default::default()
        });
        push_samples(
            &mut ctrl.op_freq_deque,
            OP_FREQ_SAMPLES,
            IC_BURST_MIN_SAMPLES - 1,
            1.0,
            0.1,
        );
        assert!(!ctrl.should_egress_limit_pr());

        ctrl.op_freq_deque.clear();
        push_samples(
            &mut ctrl.op_freq_deque,
            OP_FREQ_SAMPLES,
            IC_BURST_MIN_SAMPLES,
            1.0,
            0.1,
        );
        assert!(ctrl.should_egress_limit_pr());
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
        // Python 1.3.8 Interface.py:221-222: hops >= PATHFINDER_M-1 not held.
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
