use std::time::{Duration, Instant};

use crate::constants::*;

/// Keepalive timing state for a single link.
///
/// Only the initiator side schedules keepalives; the responder simply echoes them.
#[derive(Debug, Clone)]
pub struct KeepaliveState {
    pub keepalive_interval: Duration,
    pub stale_time: Duration,
    pub is_initiator: bool,
    pub last_inbound: Instant,
    pub last_keepalive_sent: Option<Instant>,
    /// Last data packet received, excluding keepalives.
    pub last_data: Instant,
    pub last_outbound: Option<Instant>,
    pub last_proof: Option<Instant>,
    pub activated_at: Option<Instant>,
    /// Per-link ±10% random jitter so neighbouring links don't all fire at the same
    /// phase and cause synchronised bursts on shared media.
    jitter_offset: Duration,
    jitter_negative: bool,
}

impl KeepaliveState {
    pub fn new(is_initiator: bool) -> Self {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        let jitter_frac: f64 = rng.gen_range(-0.1..0.1);
        let now = Instant::now();
        Self {
            keepalive_interval: Duration::from_secs_f64(KEEPALIVE_DEFAULT),
            stale_time: Duration::from_secs_f64(STALE_TIME_DEFAULT),
            is_initiator,
            last_inbound: now,
            last_keepalive_sent: None,
            last_data: now,
            last_outbound: None,
            last_proof: None,
            activated_at: None,
            jitter_offset: Duration::from_secs_f64(jitter_frac.abs() * KEEPALIVE_DEFAULT),
            jitter_negative: jitter_frac < 0.0,
        }
    }

    /// Rescale the keepalive interval after a new RTT measurement.
    ///
    /// Interval scales linearly with RTT up to `KEEPALIVE_MAX_RTT`, then saturates.
    /// Jitter is re-rolled so the ±10% spread is relative to the new interval.
    pub fn update_from_rtt(&mut self, rtt: Duration) {
        let rtt_secs = rtt.as_secs_f64();
        let scale_factor = KEEPALIVE_MAX / KEEPALIVE_MAX_RTT;
        let interval = (rtt_secs * scale_factor).clamp(KEEPALIVE_MIN, KEEPALIVE_MAX);
        self.keepalive_interval = Duration::from_secs_f64(interval);
        self.stale_time = Duration::from_secs_f64(interval * STALE_FACTOR);

        use rand::Rng;
        let mut rng = rand::thread_rng();
        let jitter_frac: f64 = rng.gen_range(-0.1..0.1);
        self.jitter_offset = Duration::from_secs_f64(jitter_frac.abs() * interval);
        self.jitter_negative = jitter_frac < 0.0;
    }

    pub fn record_inbound(&mut self) {
        self.last_inbound = Instant::now();
    }

    /// Record an inbound data packet (distinct from a keepalive beat).
    pub fn record_data(&mut self) {
        let now = Instant::now();
        self.last_data = now;
        self.last_inbound = now;
    }

    pub fn record_outbound(&mut self) {
        self.last_outbound = Some(Instant::now());
    }

    pub fn record_proof(&mut self) {
        let now = Instant::now();
        self.last_proof = Some(now);
        self.last_inbound = now;
    }

    pub fn mark_activated(&mut self) {
        self.activated_at = Some(Instant::now());
    }

    /// Whether the initiator should emit a keepalive now (jitter applied).
    pub fn should_send_keepalive(&self) -> bool {
        self.should_send_keepalive_at(Instant::now())
    }

    pub(crate) fn should_send_keepalive_at(&self, now: Instant) -> bool {
        let jittered = if self.jitter_negative {
            self.keepalive_interval
                .saturating_sub(self.jitter_offset)
                .max(Duration::from_secs_f64(KEEPALIVE_MIN))
        } else {
            self.keepalive_interval + self.jitter_offset
        };

        let inbound_elapsed = now.saturating_duration_since(self.last_inbound);
        let outbound_elapsed = self
            .last_outbound
            .or(self.activated_at)
            .map(|baseline| now.saturating_duration_since(baseline))
            .unwrap_or(inbound_elapsed);
        let keepalive_elapsed = self
            .last_keepalive_sent
            .map(|last_keepalive| now.saturating_duration_since(last_keepalive))
            .unwrap_or(Duration::MAX);

        self.is_initiator
            && (inbound_elapsed >= jittered || outbound_elapsed >= jittered)
            && keepalive_elapsed >= jittered
    }

    pub(crate) fn should_respond_to_keepalive_at(&self, now: Instant) -> bool {
        !self.is_initiator
            && self
                .last_outbound
                .map(|last_outbound| {
                    now.saturating_duration_since(last_outbound) >= self.keepalive_interval
                })
                .unwrap_or(true)
    }

    /// Whether the link should transition to STALE.
    ///
    /// Uses only peer evidence — inbound traffic, proof, or activation — as the
    /// baseline. Local outbound traffic cannot prove that the peer remains alive.
    pub fn is_stale(&self) -> bool {
        self.is_stale_at(Instant::now())
    }

    pub(crate) fn is_stale_at(&self, now: Instant) -> bool {
        let mut latest = self.last_inbound;
        if let Some(proof) = self.last_proof {
            if proof > latest {
                latest = proof;
            }
        }
        if let Some(activated) = self.activated_at {
            if activated > latest {
                latest = activated;
            }
        }
        now.saturating_duration_since(latest) >= self.stale_time
    }

    /// How long to wait in STALE before tearing the link down.
    pub fn stale_grace_timeout(&self, rtt: Duration) -> Duration {
        rtt * KEEPALIVE_TIMEOUT_FACTOR as u32 + Duration::from_secs_f64(STALE_GRACE)
    }

    pub fn mark_keepalive_sent(&mut self) {
        self.last_keepalive_sent = Some(Instant::now());
    }

    pub(crate) fn mark_keepalive_sent_at(&mut self, now: Instant) {
        self.last_keepalive_sent = Some(now);
    }

    pub(crate) fn record_keepalive_outbound(&mut self) {
        let now = Instant::now();
        self.last_outbound = Some(now);
        self.last_keepalive_sent = Some(now);
    }

    pub fn since_inbound(&self) -> Duration {
        self.last_inbound.elapsed()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    fn instant_before_now(elapsed: Duration) -> Instant {
        if let Some(instant) = Instant::now().checked_sub(elapsed) {
            instant
        } else {
            thread::sleep(elapsed);
            Instant::now()
                .checked_sub(elapsed)
                .expect("elapsed duration should be representable after waiting")
        }
    }

    #[test]
    fn test_rtt_scaling() {
        let mut ks = KeepaliveState::new(true);

        // Very fast link saturates at the minimum interval.
        ks.update_from_rtt(Duration::from_millis(10));
        assert_eq!(
            ks.keepalive_interval,
            Duration::from_secs_f64(KEEPALIVE_MIN)
        );

        ks.update_from_rtt(Duration::from_millis(100));
        let expected = 0.1 * (KEEPALIVE_MAX / KEEPALIVE_MAX_RTT);
        let diff = (ks.keepalive_interval.as_secs_f64() - expected).abs();
        assert!(diff < 0.01);

        // Very slow link saturates at the maximum interval.
        ks.update_from_rtt(Duration::from_secs(2));
        assert_eq!(
            ks.keepalive_interval,
            Duration::from_secs_f64(KEEPALIVE_MAX)
        );
    }

    #[test]
    fn test_stale_time_follows_keepalive() {
        let mut ks = KeepaliveState::new(true);
        ks.update_from_rtt(Duration::from_millis(100));
        let expected_stale =
            Duration::from_secs_f64(ks.keepalive_interval.as_secs_f64() * STALE_FACTOR);
        // Tolerance absorbs sub-ns Duration round-trip drift.
        let diff = ks.stale_time.as_secs_f64() - expected_stale.as_secs_f64();
        assert!(
            diff.abs() < 1e-6,
            "stale_time {:?} should match recomputed expected {:?}",
            ks.stale_time,
            expected_stale
        );
    }

    #[test]
    fn test_should_send_keepalive_timing() {
        let mut ks = KeepaliveState::new(true);
        ks.keepalive_interval = Duration::from_millis(50);
        ks.jitter_offset = Duration::ZERO;
        ks.jitter_negative = false;

        assert!(!ks.should_send_keepalive());

        thread::sleep(Duration::from_millis(60));
        assert!(ks.should_send_keepalive());

        // Non-initiator side never emits keepalives.
        let mut ks2 = KeepaliveState::new(false);
        ks2.keepalive_interval = Duration::from_millis(1);
        ks2.jitter_offset = Duration::ZERO;
        thread::sleep(Duration::from_millis(5));
        assert!(!ks2.should_send_keepalive());
    }

    #[test]
    fn continuous_inbound_still_schedules_keepalive_when_outbound_is_quiet() {
        let now = Instant::now();
        let mut state = KeepaliveState::new(true);
        state.keepalive_interval = Duration::from_secs(5);
        state.jitter_offset = Duration::ZERO;
        state.jitter_negative = false;
        state.last_inbound = now;
        state.last_outbound = None;
        state.activated_at = Some(now - Duration::from_secs(6));
        state.last_keepalive_sent = Some(now - Duration::from_secs(6));

        assert!(state.should_send_keepalive_at(now));
    }

    #[test]
    fn recent_keepalive_suppresses_duplicate_at_exact_tick_time() {
        let now = Instant::now();
        let mut state = KeepaliveState::new(true);
        state.keepalive_interval = Duration::from_secs(5);
        state.jitter_offset = Duration::ZERO;
        state.jitter_negative = false;
        state.last_inbound = now - Duration::from_secs(6);
        state.last_outbound = Some(now - Duration::from_secs(6));
        state.last_keepalive_sent = Some(now - Duration::from_secs(4));

        assert!(!state.should_send_keepalive_at(now));
        assert!(state.should_send_keepalive_at(now + Duration::from_secs(1)));
    }

    #[test]
    fn local_outbound_traffic_does_not_mask_a_stale_peer() {
        let now = Instant::now();
        let mut state = KeepaliveState::new(true);
        state.stale_time = Duration::from_secs(5);
        state.last_inbound = now - Duration::from_secs(6);
        state.last_outbound = Some(now);
        state.last_proof = None;
        state.activated_at = None;

        assert!(state.is_stale_at(now));
    }

    #[test]
    fn responder_suppresses_keepalive_reply_after_recent_outbound() {
        let now = Instant::now();
        let mut state = KeepaliveState::new(false);
        state.keepalive_interval = Duration::from_secs(5);
        state.last_outbound = Some(now);

        assert!(!state.should_respond_to_keepalive_at(now));
        assert!(state.should_respond_to_keepalive_at(now + Duration::from_secs(5)));
    }

    #[test]
    fn test_stale_detection() {
        let mut ks = KeepaliveState::new(true);
        ks.stale_time = Duration::from_millis(50);

        assert!(!ks.is_stale());
        thread::sleep(Duration::from_millis(60));
        assert!(ks.is_stale());

        ks.record_inbound();
        assert!(!ks.is_stale());
    }

    #[test]
    fn test_jitter_desynchronizes_keepalives() {
        let links: Vec<KeepaliveState> = (0..20)
            .map(|i| {
                let mut ks = KeepaliveState::new(true);
                ks.keepalive_interval = Duration::from_secs_f64(KEEPALIVE_MIN);
                ks.jitter_offset = Duration::from_millis(500);
                ks.jitter_negative = i % 2 == 0;
                // Push last_inbound just past the interval boundary.
                ks.last_inbound = instant_before_now(ks.keepalive_interval);
                ks
            })
            .collect();

        let firing: usize = links.iter().filter(|ks| ks.should_send_keepalive()).count();

        let links_past: Vec<KeepaliveState> = (0..20)
            .map(|i| {
                let mut ks = KeepaliveState::new(true);
                ks.keepalive_interval = Duration::from_secs_f64(KEEPALIVE_MIN);
                ks.jitter_offset = Duration::from_millis(500);
                ks.jitter_negative = i % 2 == 0;
                ks.last_inbound = instant_before_now(Duration::from_secs(6));
                ks
            })
            .collect();
        let firing_past: usize = links_past
            .iter()
            .filter(|ks| ks.should_send_keepalive())
            .count();

        assert!(
            firing < 20,
            "jitter should prevent all links firing simultaneously"
        );
        assert_eq!(
            firing_past, 20,
            "all links should fire well past the interval"
        );
    }

    #[test]
    fn test_jitter_bounded() {
        for _ in 0..100 {
            let mut ks = KeepaliveState::new(true);
            ks.update_from_rtt(Duration::from_millis(500));
            let max_jitter = ks.keepalive_interval.as_secs_f64() * 0.1;
            assert!(
                ks.jitter_offset.as_secs_f64() <= max_jitter + 0.001,
                "jitter {:?} exceeds ±10% of interval {:?}",
                ks.jitter_offset,
                ks.keepalive_interval
            );
        }
    }

    #[test]
    fn test_option_sentinels() {
        let ks = KeepaliveState::new(true);
        assert!(ks.last_keepalive_sent.is_none());
        assert!(ks.last_outbound.is_none());
        assert!(ks.last_proof.is_none());
        assert!(ks.activated_at.is_none());
    }
}
