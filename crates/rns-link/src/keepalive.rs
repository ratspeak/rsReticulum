use std::time::{Duration, Instant};

use crate::constants::*;

/// Keepalive timing state for a single link.
///
/// Only the initiator schedules requests. The responder can suppress a reply
/// when it has sent other traffic within the keepalive interval. The owner
/// records activity and sends any required frames.
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
}

impl KeepaliveState {
    pub fn new(is_initiator: bool) -> Self {
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
        }
    }

    /// Rescale the keepalive interval after a new RTT measurement.
    ///
    /// Interval scales linearly with RTT, clamped to `KEEPALIVE_MIN` through
    /// `KEEPALIVE_MAX`; it reaches the upper limit at `KEEPALIVE_MAX_RTT`.
    pub fn update_from_rtt(&mut self, rtt: Duration) {
        let rtt_secs = rtt.as_secs_f64();
        let scale_factor = KEEPALIVE_MAX / KEEPALIVE_MAX_RTT;
        let interval = (rtt_secs * scale_factor).clamp(KEEPALIVE_MIN, KEEPALIVE_MAX);
        self.keepalive_interval = Duration::from_secs_f64(interval);
        self.stale_time = Duration::from_secs_f64(interval * STALE_FACTOR);
    }

    /// Record an inbound keepalive; it does not count as data.
    pub fn record_inbound(&mut self) {
        self.last_inbound = Instant::now();
    }

    /// Record an inbound packet other than a keepalive.
    pub fn record_data(&mut self) {
        let now = Instant::now();
        self.last_data = now;
        self.last_inbound = now;
    }

    /// Record an outbound packet other than a keepalive.
    pub fn record_outbound(&mut self) {
        let now = Instant::now();
        self.last_outbound = Some(now);
        self.last_data = now;
    }

    /// Record a validated proof for a packet sent on the link.
    pub fn record_proof(&mut self) {
        self.last_proof = Some(Instant::now());
    }

    pub fn mark_activated(&mut self) {
        self.activated_at = Some(Instant::now());
    }

    /// Whether the initiator should emit a keepalive now.
    pub fn should_send_keepalive(&self) -> bool {
        self.should_send_keepalive_at(Instant::now())
    }

    pub(crate) fn should_send_keepalive_at(&self, now: Instant) -> bool {
        // Upstream's responder answers only when a full interval has passed
        // since its own last packet (Link.py), which is its reply
        // to the previous keepalive: a request sent exactly on the interval
        // arrives a moment early by the responder's clock and gets no reply.
        let interval = self.keepalive_interval.mul_f64(1.0 + KEEPALIVE_SEND_MARGIN);
        let inbound_elapsed = now.saturating_duration_since(self.peer_evidence());
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
            && (inbound_elapsed >= interval || outbound_elapsed >= interval)
            && keepalive_elapsed >= interval
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
        // The initiator's watchdog runs on the stretched interval, so its second
        // keepalive and the STALE transition still share one pass (Link.py).
        let stale_time = if self.is_initiator {
            self.stale_time.mul_f64(1.0 + KEEPALIVE_SEND_MARGIN)
        } else {
            self.stale_time
        };
        now.saturating_duration_since(self.peer_evidence()) >= stale_time
    }

    /// Latest of inbound traffic, packet proof and activation (Link.py watchdog).
    fn peer_evidence(&self) -> Instant {
        let mut latest = self.last_inbound;
        if let Some(proof) = self.last_proof
            && proof > latest
        {
            latest = proof;
        }
        if let Some(activated) = self.activated_at
            && activated > latest
        {
            latest = activated;
        }
        latest
    }

    /// How long to wait in STALE before tearing the link down: Link.py's
    /// `rtt * KEEPALIVE_TIMEOUT_FACTOR + STALE_GRACE`, clamped like every
    /// watchdog sleep to `WATCHDOG_MAX_SLEEP`.
    pub fn stale_grace_timeout(&self, rtt: Duration) -> Duration {
        rtt.saturating_mul(KEEPALIVE_TIMEOUT_FACTOR as u32)
            .saturating_add(Duration::from_secs_f64(STALE_GRACE))
            .min(Duration::from_secs_f64(WATCHDOG_MAX_SLEEP))
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

        assert!(!ks.should_send_keepalive());

        thread::sleep(Duration::from_millis(60));
        assert!(ks.should_send_keepalive());

        // Non-initiator side never emits keepalives.
        let mut ks2 = KeepaliveState::new(false);
        ks2.keepalive_interval = Duration::from_millis(1);
        thread::sleep(Duration::from_millis(5));
        assert!(!ks2.should_send_keepalive());
    }

    #[test]
    fn continuous_inbound_still_schedules_keepalive_when_outbound_is_quiet() {
        let now = Instant::now();
        let mut state = KeepaliveState::new(true);
        state.keepalive_interval = Duration::from_secs(5);
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
        state.last_inbound = now - Duration::from_secs(6);
        state.last_outbound = Some(now - Duration::from_secs(6));
        state.last_keepalive_sent = Some(now - Duration::from_secs(4));

        assert!(!state.should_send_keepalive_at(now));
        assert!(!state.should_send_keepalive_at(now + Duration::from_secs(1)));
        assert!(state.should_send_keepalive_at(now + Duration::from_secs(2)));
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
    fn keepalive_waits_a_margin_past_the_interval() {
        let now = Instant::now();
        let mut state = KeepaliveState::new(true);
        state.update_from_rtt(Duration::from_millis(500));
        let interval = state.keepalive_interval;
        state.last_inbound = now;
        state.activated_at = Some(now);
        state.last_outbound = Some(now);
        state.last_keepalive_sent = Some(now);

        let margin = interval.mul_f64(KEEPALIVE_SEND_MARGIN);
        assert!(!state.should_send_keepalive_at(now + interval));
        assert!(
            !state.should_send_keepalive_at(now + interval + margin - Duration::from_millis(1))
        );
        assert!(state.should_send_keepalive_at(now + interval + margin));
        // The responder's reply check passes for a request that left a margin.
        let mut responder = KeepaliveState::new(false);
        responder.keepalive_interval = interval;
        responder.last_outbound = Some(now + Duration::from_millis(20));
        assert!(!responder.should_respond_to_keepalive_at(now + interval));
        assert!(responder.should_respond_to_keepalive_at(now + interval + margin));
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
