//! BLE central scan lifecycle. `PlatformUnavailable` rewinds starting or
//! scanning states to `StartingWaitingPlatform`. A later `PlatformReady` can
//! resume scanning; stopping states are not rewound.

use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::Instant;
use uuid::Uuid;

/// Which GATT service a peer advertises (adapter reports the primary it saw).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AdvertisedProtocol {
    Ratspeak,
    Columba,
}

/// `identifier` is a platform-provided scan identifier, such as an Apple UUID
/// or Bluetooth address. It is not a persistent authenticated peer identity.
#[derive(Debug, Clone)]
pub struct DiscoveryEvent {
    pub identifier: String,
    pub rssi: i16,
    pub services: Vec<Uuid>,
    pub protocol: AdvertisedProtocol,
    pub seen_at: Instant,
}

/// Classify ad services. Ratspeak beats Columba when both advertised.
pub fn classify_protocol(
    services: &[Uuid],
    ratspeak_uuid: Uuid,
    columba_uuid: Uuid,
) -> Option<AdvertisedProtocol> {
    if services.contains(&ratspeak_uuid) {
        Some(AdvertisedProtocol::Ratspeak)
    } else if services.contains(&columba_uuid) {
        Some(AdvertisedProtocol::Columba)
    } else {
        None
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CentralState {
    Idle,
    /// `start_scan` issued; awaiting `CBManagerState == PoweredOn` etc.
    StartingWaitingPlatform,
    Scanning,
    /// `stop_scan` issued; awaiting platform ack (synthetic on Apple where
    /// stopScan is synchronous, real on bluer).
    StoppingScan,
    /// Cleanly torn down. Distinct from `Idle` for telemetry.
    Stopped,
    /// A fatal platform error was reported; requires explicit `Reset`.
    Failed,
}

impl CentralState {
    pub fn is_active(self) -> bool {
        !matches!(self, Self::Idle | Self::Stopped | Self::Failed)
    }

    pub fn is_starting(self) -> bool {
        matches!(self, Self::StartingWaitingPlatform)
    }

    pub fn is_scanning(self) -> bool {
        matches!(self, Self::Scanning)
    }

    pub fn is_stopping(self) -> bool {
        matches!(self, Self::StoppingScan)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CentralEvent {
    StartRequested,
    /// Platform ready: adapter calls `scanForPeripheralsWithServices` here.
    PlatformReady,
    /// Starting and scanning states rewind to `StartingWaitingPlatform`.
    /// Stopping states reject this event.
    PlatformUnavailable {
        reason: String,
    },
    StopRequested,
    /// `stopScan` completed (synthetic on Apple where it's synchronous).
    ScanStopped,
    FatalError {
        reason: String,
    },
    Reset,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CentralTransitionError {
    pub from: CentralState,
    pub event: CentralEvent,
}

impl std::fmt::Display for CentralTransitionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "invalid BLE central lifecycle transition: event {:?} is not valid from state {:?}",
            self.event, self.from
        )
    }
}

impl std::error::Error for CentralTransitionError {}

/// Idempotent re-requests return `Ok` with state unchanged.
pub fn transition(
    state: CentralState,
    event: &CentralEvent,
) -> Result<CentralState, CentralTransitionError> {
    use CentralEvent::*;
    use CentralState::*;

    if let FatalError { .. } = event {
        return Ok(Failed);
    }

    let next = match (state, event) {
        (Idle, StartRequested) => StartingWaitingPlatform,
        (Stopped, StartRequested) => StartingWaitingPlatform,
        (StartingWaitingPlatform, PlatformReady) => Scanning,

        (Scanning, StopRequested) => StoppingScan,
        (StartingWaitingPlatform, StopRequested) => Stopped,
        (StoppingScan, ScanStopped) => Stopped,
        (Stopped, Reset) => Idle,

        (Scanning, PlatformUnavailable { .. }) => StartingWaitingPlatform,
        (StartingWaitingPlatform, PlatformUnavailable { .. }) => StartingWaitingPlatform,

        (Failed, Reset) => Idle,

        (StartingWaitingPlatform | Scanning, StartRequested) => state,
        (Idle | Stopped | StoppingScan, StopRequested) => state,
        (Idle, Reset) => Idle,

        _ => {
            return Err(CentralTransitionError {
                from: state,
                event: event.clone(),
            });
        }
    };

    Ok(next)
}

pub struct CentralLifecycle {
    state: Mutex<CentralState>,
}

impl CentralLifecycle {
    pub fn new() -> Self {
        Self {
            state: Mutex::new(CentralState::Idle),
        }
    }

    pub fn current(&self) -> CentralState {
        *self.lock().expect("poisoned")
    }

    pub fn apply(&self, event: CentralEvent) -> Result<CentralState, CentralTransitionError> {
        let mut guard = self.lock().expect("poisoned");
        let next = transition(*guard, &event)?;
        *guard = next;
        Ok(next)
    }

    pub fn is_scanning(&self) -> bool {
        matches!(self.current(), CentralState::Scanning)
    }

    fn lock(
        &self,
    ) -> Result<MutexGuard<'_, CentralState>, PoisonError<MutexGuard<'_, CentralState>>> {
        self.state.lock()
    }
}

impl Default for CentralLifecycle {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for CentralLifecycle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CentralLifecycle")
            .field("state", &self.current())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unavail(reason: &str) -> CentralEvent {
        CentralEvent::PlatformUnavailable {
            reason: reason.into(),
        }
    }

    fn fatal(reason: &str) -> CentralEvent {
        CentralEvent::FatalError {
            reason: reason.into(),
        }
    }

    fn drive(start: CentralState, events: &[CentralEvent]) -> CentralState {
        let lc = CentralLifecycle {
            state: Mutex::new(start),
        };
        for e in events {
            lc.apply(e.clone())
                .unwrap_or_else(|err| panic!("transition failed: {err}"));
        }
        lc.current()
    }

    // ---- Happy-path transitions ----

    #[test]
    fn full_start_cycle_reaches_scanning() {
        let final_state = drive(
            CentralState::Idle,
            &[CentralEvent::StartRequested, CentralEvent::PlatformReady],
        );
        assert_eq!(final_state, CentralState::Scanning);
    }

    #[test]
    fn full_stop_cycle_reaches_stopped() {
        let final_state = drive(
            CentralState::Scanning,
            &[CentralEvent::StopRequested, CentralEvent::ScanStopped],
        );
        assert_eq!(final_state, CentralState::Stopped);
    }

    #[test]
    fn stopped_can_start_again() {
        let final_state = drive(
            CentralState::Stopped,
            &[
                CentralEvent::Reset,
                CentralEvent::StartRequested,
                CentralEvent::PlatformReady,
            ],
        );
        assert_eq!(final_state, CentralState::Scanning);
    }

    // ---- Teardown sequencing ----

    #[test]
    fn stop_request_alone_does_not_reach_stopped_from_scanning() {
        // Apple's stopScan is synchronous, but the machine still requires
        // an explicit ScanStopped for symmetry with async backends.
        let lc = CentralLifecycle::new();
        lc.apply(CentralEvent::StartRequested).unwrap();
        lc.apply(CentralEvent::PlatformReady).unwrap();
        assert_eq!(lc.current(), CentralState::Scanning);
        lc.apply(CentralEvent::StopRequested).unwrap();
        assert_eq!(lc.current(), CentralState::StoppingScan);
        let err = lc.apply(CentralEvent::Reset);
        assert!(err.is_err());
        assert_eq!(lc.current(), CentralState::StoppingScan);
    }

    #[test]
    fn stop_before_platform_ready_reaches_stopped_immediately() {
        let final_state = drive(
            CentralState::StartingWaitingPlatform,
            &[CentralEvent::StopRequested],
        );
        assert_eq!(final_state, CentralState::Stopped);
    }

    // ---- Platform availability ----

    #[test]
    fn bluetooth_off_mid_scan_rewinds_to_waiting_platform() {
        let final_state = drive(CentralState::Scanning, &[unavail("bluetooth off")]);
        assert_eq!(final_state, CentralState::StartingWaitingPlatform);
    }

    #[test]
    fn bluetooth_recovery_cycle_returns_to_scanning() {
        let final_state = drive(
            CentralState::Scanning,
            &[unavail("bluetooth off"), CentralEvent::PlatformReady],
        );
        assert_eq!(final_state, CentralState::Scanning);
    }

    #[test]
    fn double_unavailable_while_waiting_is_idempotent() {
        let final_state = drive(
            CentralState::StartingWaitingPlatform,
            &[unavail("resetting"), unavail("resetting")],
        );
        assert_eq!(final_state, CentralState::StartingWaitingPlatform);
    }

    // ---- Idempotency ----

    #[test]
    fn double_start_from_scanning_is_noop() {
        let lc = CentralLifecycle::new();
        lc.apply(CentralEvent::StartRequested).unwrap();
        lc.apply(CentralEvent::PlatformReady).unwrap();
        lc.apply(CentralEvent::StartRequested).unwrap();
        assert_eq!(lc.current(), CentralState::Scanning);
    }

    #[test]
    fn double_stop_while_stopping_is_noop() {
        let lc = CentralLifecycle::new();
        lc.apply(CentralEvent::StartRequested).unwrap();
        lc.apply(CentralEvent::PlatformReady).unwrap();
        lc.apply(CentralEvent::StopRequested).unwrap();
        assert_eq!(lc.current(), CentralState::StoppingScan);
        lc.apply(CentralEvent::StopRequested).unwrap();
        assert_eq!(lc.current(), CentralState::StoppingScan);
    }

    #[test]
    fn reset_from_idle_is_noop() {
        let lc = CentralLifecycle::new();
        lc.apply(CentralEvent::Reset).unwrap();
        assert_eq!(lc.current(), CentralState::Idle);
    }

    // ---- Fatal ----

    #[test]
    fn fatal_from_any_state_reaches_failed() {
        for from in [
            CentralState::Idle,
            CentralState::StartingWaitingPlatform,
            CentralState::Scanning,
            CentralState::StoppingScan,
            CentralState::Stopped,
        ] {
            let final_state = drive(from, &[fatal("oom")]);
            assert_eq!(final_state, CentralState::Failed, "from {from:?}");
        }
    }

    #[test]
    fn failed_requires_reset_to_restart() {
        let lc = CentralLifecycle {
            state: Mutex::new(CentralState::Failed),
        };
        let err = lc
            .apply(CentralEvent::StartRequested)
            .expect_err("StartRequested from Failed must be rejected");
        assert_eq!(err.from, CentralState::Failed);
    }

    #[test]
    fn reset_from_failed_returns_to_idle() {
        let final_state = drive(CentralState::Failed, &[CentralEvent::Reset]);
        assert_eq!(final_state, CentralState::Idle);
    }

    // ---- Invalid transitions ----

    #[test]
    fn platform_ready_from_idle_is_rejected() {
        let lc = CentralLifecycle::new();
        let err = lc
            .apply(CentralEvent::PlatformReady)
            .expect_err("PlatformReady from Idle must be rejected");
        assert_eq!(err.from, CentralState::Idle);
        assert_eq!(lc.current(), CentralState::Idle);
    }

    #[test]
    fn scan_stopped_from_idle_is_rejected() {
        let lc = CentralLifecycle::new();
        assert!(lc.apply(CentralEvent::ScanStopped).is_err());
    }

    #[test]
    fn predicates_match_intuition() {
        assert!(!CentralState::Idle.is_active());
        assert!(CentralState::Scanning.is_active());
        assert!(CentralState::Scanning.is_scanning());
        assert!(CentralState::StartingWaitingPlatform.is_starting());
        assert!(CentralState::StoppingScan.is_stopping());

        let lc = CentralLifecycle::new();
        assert!(!lc.is_scanning());
        lc.apply(CentralEvent::StartRequested).unwrap();
        lc.apply(CentralEvent::PlatformReady).unwrap();
        assert!(lc.is_scanning());
    }

    // ---- End-to-end scenarios for the iOS / macOS adapter ----

    #[test]
    fn full_enable_disable_enable_cycle_ends_idle_ready_to_scan() {
        let lc = CentralLifecycle::new();
        lc.apply(CentralEvent::StartRequested).unwrap();
        lc.apply(CentralEvent::PlatformReady).unwrap();
        assert_eq!(lc.current(), CentralState::Scanning);
        lc.apply(CentralEvent::StopRequested).unwrap();
        lc.apply(CentralEvent::ScanStopped).unwrap();
        lc.apply(CentralEvent::Reset).unwrap();
        lc.apply(CentralEvent::StartRequested).unwrap();
        lc.apply(CentralEvent::PlatformReady).unwrap();
        assert_eq!(lc.current(), CentralState::Scanning);
    }

    // ---- Protocol classification ----

    fn ratspeak_uuid() -> Uuid {
        Uuid::from_u128(0xa1b2c3d4_e5f6_4a5b_8c9d_0e1f2a3b4c5d)
    }
    fn columba_uuid() -> Uuid {
        Uuid::from_u128(0x37145b00_442d_4a94_917f_8f42c5da28e3)
    }
    fn unrelated_uuid() -> Uuid {
        Uuid::from_u128(0xdead_dead_dead_dead_dead_dead_dead_dead)
    }

    #[test]
    fn classify_picks_ratspeak_over_columba_when_both_advertised() {
        let services = vec![ratspeak_uuid(), columba_uuid()];
        let got = classify_protocol(&services, ratspeak_uuid(), columba_uuid());
        assert_eq!(got, Some(AdvertisedProtocol::Ratspeak));
    }

    #[test]
    fn classify_returns_ratspeak_when_only_ratspeak_present() {
        let services = vec![ratspeak_uuid()];
        let got = classify_protocol(&services, ratspeak_uuid(), columba_uuid());
        assert_eq!(got, Some(AdvertisedProtocol::Ratspeak));
    }

    #[test]
    fn classify_returns_columba_when_only_columba_present() {
        let services = vec![columba_uuid()];
        let got = classify_protocol(&services, ratspeak_uuid(), columba_uuid());
        assert_eq!(got, Some(AdvertisedProtocol::Columba));
    }

    #[test]
    fn classify_returns_none_when_neither_present() {
        let services = vec![unrelated_uuid()];
        let got = classify_protocol(&services, ratspeak_uuid(), columba_uuid());
        assert_eq!(got, None);
    }

    #[test]
    fn classify_returns_none_on_empty_ad() {
        let got = classify_protocol(&[], ratspeak_uuid(), columba_uuid());
        assert_eq!(got, None);
    }

    #[test]
    fn classify_ignores_unrelated_services_mixed_in() {
        let services = vec![unrelated_uuid(), columba_uuid(), unrelated_uuid()];
        let got = classify_protocol(&services, ratspeak_uuid(), columba_uuid());
        assert_eq!(got, Some(AdvertisedProtocol::Columba));
    }

    #[test]
    fn platform_unavailable_during_scan_rewinds_and_recovers_automatically() {
        let lc = CentralLifecycle::new();
        lc.apply(CentralEvent::StartRequested).unwrap();
        lc.apply(CentralEvent::PlatformReady).unwrap();
        lc.apply(unavail("bluetooth off")).unwrap();
        assert_eq!(lc.current(), CentralState::StartingWaitingPlatform);
        lc.apply(unavail("resetting")).unwrap();
        assert_eq!(lc.current(), CentralState::StartingWaitingPlatform);
        lc.apply(CentralEvent::PlatformReady).unwrap();
        assert_eq!(lc.current(), CentralState::Scanning);
    }
}
