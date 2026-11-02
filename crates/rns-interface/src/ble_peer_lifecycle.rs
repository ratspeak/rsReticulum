//! BLE peripheral lifecycle state machine. Adapters report platform events
//! through [`PeripheralLifecycle::apply`] and perform side effects after the
//! transition returns.
//!
//! Teardown waits for advertising to stop before service removal. Starting
//! and advertising states rewind to `StartingWaitingPlatform` after
//! `PlatformUnavailable`; stopping states are not rewound. Invalid transitions
//! return an error rather than changing state.

use std::sync::{Mutex, MutexGuard, PoisonError};

/// Sub-states for `Starting` and `Stopping` are explicit so each can reject
/// events that don't belong to its phase.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PeripheralState {
    Idle,
    /// Awaiting `CBManagerState == PoweredOn` / `bluer` `Adapter.powered`.
    StartingWaitingPlatform,
    /// Registering GATT services; awaiting per-service add confirmation.
    StartingRegisteringServices,
    /// `startAdvertising` issued; awaiting platform confirmation.
    StartingAdvertising,
    Advertising,
    /// `stopAdvertising` issued; awaiting confirmation. iOS lacks a delegate
    /// callback for this — the adapter polls `isAdvertising`.
    StoppingAdvertisement,
    /// `removeAllServices` issued; awaiting confirmation.
    StoppingRemovingServices,
    /// Cleanly torn down. Distinct from `Idle` for telemetry.
    Stopped,
    /// Unrecoverable. Requires explicit [`LifecycleEvent::Reset`].
    Failed,
}

impl PeripheralState {
    /// True in starting, advertising, or stopping states. This classifies
    /// lifecycle state; it does not inspect platform resource ownership.
    pub fn is_active(self) -> bool {
        !matches!(self, Self::Idle | Self::Stopped | Self::Failed)
    }

    pub fn is_starting(self) -> bool {
        matches!(
            self,
            Self::StartingWaitingPlatform
                | Self::StartingRegisteringServices
                | Self::StartingAdvertising
        )
    }

    pub fn is_stopping(self) -> bool {
        matches!(
            self,
            Self::StoppingAdvertisement | Self::StoppingRemovingServices
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LifecycleEvent {
    StartRequested,
    /// Platform ready for service registration + advertising.
    PlatformReady,
    /// The platform became unavailable. Starting and advertising states rewind
    /// to `StartingWaitingPlatform`; stopping states reject this event.
    PlatformUnavailable {
        reason: String,
    },
    ServicesAdded,
    AdvertiseStarted,
    StopRequested,
    /// `stopAdvertising` completed. The Apple adapter reports this after
    /// checking `isAdvertising`; service removal follows this transition.
    AdvertiseStopped,
    ServicesRemoved,
    FatalError {
        reason: String,
    },
    Reset,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransitionError {
    pub from: PeripheralState,
    pub event: LifecycleEvent,
}

impl std::fmt::Display for TransitionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "invalid BLE peripheral lifecycle transition: event {:?} is not valid from state {:?}",
            self.event, self.from
        )
    }
}

impl std::error::Error for TransitionError {}

/// Caller performs the side-effect (calling `stopAdvertising` etc.) on the
/// returned next state. Idempotent re-requests return `Ok` with state
/// unchanged; genuine violations return [`TransitionError`].
pub fn transition(
    state: PeripheralState,
    event: &LifecycleEvent,
) -> Result<PeripheralState, TransitionError> {
    use LifecycleEvent::*;
    use PeripheralState::*;

    if let FatalError { .. } = event {
        return Ok(Failed);
    }

    let next = match (state, event) {
        // ---- Start path ----
        (Idle, StartRequested) => StartingWaitingPlatform,
        (Stopped, StartRequested) => StartingWaitingPlatform,
        (StartingWaitingPlatform, PlatformReady) => StartingRegisteringServices,
        (StartingRegisteringServices, ServicesAdded) => StartingAdvertising,
        (StartingAdvertising, AdvertiseStarted) => Advertising,

        // ---- Stop path ----
        (Advertising, StopRequested) => StoppingAdvertisement,
        // Stop while starting: skip ahead to the appropriate Stopping
        // sub-state so the in-flight platform calls unwind cleanly.
        (StartingAdvertising, StopRequested) => StoppingAdvertisement,
        (StartingRegisteringServices, StopRequested) => StoppingRemovingServices,
        (StartingWaitingPlatform, StopRequested) => Stopped, // nothing registered yet

        (StoppingAdvertisement, AdvertiseStopped) => StoppingRemovingServices,
        (StoppingRemovingServices, ServicesRemoved) => Stopped,
        (Stopped, Reset) => Idle,

        // Platform-unavailable from any active state rewinds to
        // WaitingPlatform so the next PlatformReady resumes automatically.
        (Advertising, PlatformUnavailable { .. }) => StartingWaitingPlatform,
        (StartingAdvertising, PlatformUnavailable { .. }) => StartingWaitingPlatform,
        (StartingRegisteringServices, PlatformUnavailable { .. }) => StartingWaitingPlatform,
        (StartingWaitingPlatform, PlatformUnavailable { .. }) => StartingWaitingPlatform,

        (Failed, Reset) => Idle,

        // ---- Idempotent no-ops ----
        (
            StartingWaitingPlatform
            | StartingRegisteringServices
            | StartingAdvertising
            | Advertising,
            StartRequested,
        ) => state,
        (Idle | Stopped | StoppingAdvertisement | StoppingRemovingServices, StopRequested) => state,
        (Idle, Reset) => Idle,

        _ => {
            return Err(TransitionError {
                from: state,
                event: event.clone(),
            });
        }
    };

    Ok(next)
}

/// Mutex is held only across the transition itself; side-effects run after
/// `apply` returns.
pub struct PeripheralLifecycle {
    state: Mutex<PeripheralState>,
}

impl PeripheralLifecycle {
    pub fn new() -> Self {
        Self {
            state: Mutex::new(PeripheralState::Idle),
        }
    }

    pub fn current(&self) -> PeripheralState {
        *self.lock().expect("poisoned")
    }

    pub fn apply(&self, event: LifecycleEvent) -> Result<PeripheralState, TransitionError> {
        let mut guard = self.lock().expect("poisoned");
        let next = transition(*guard, &event)?;
        *guard = next;
        Ok(next)
    }

    pub fn is_advertising(&self) -> bool {
        matches!(self.current(), PeripheralState::Advertising)
    }

    fn lock(
        &self,
    ) -> Result<MutexGuard<'_, PeripheralState>, PoisonError<MutexGuard<'_, PeripheralState>>> {
        self.state.lock()
    }
}

impl Default for PeripheralLifecycle {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for PeripheralLifecycle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PeripheralLifecycle")
            .field("state", &self.current())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn err(reason: &str) -> LifecycleEvent {
        LifecycleEvent::PlatformUnavailable {
            reason: reason.into(),
        }
    }

    fn fatal(reason: &str) -> LifecycleEvent {
        LifecycleEvent::FatalError {
            reason: reason.into(),
        }
    }

    fn drive(start: PeripheralState, events: &[LifecycleEvent]) -> PeripheralState {
        let lc = PeripheralLifecycle {
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
    fn full_start_cycle_reaches_advertising() {
        let final_state = drive(
            PeripheralState::Idle,
            &[
                LifecycleEvent::StartRequested,
                LifecycleEvent::PlatformReady,
                LifecycleEvent::ServicesAdded,
                LifecycleEvent::AdvertiseStarted,
            ],
        );
        assert_eq!(final_state, PeripheralState::Advertising);
    }

    #[test]
    fn full_stop_cycle_reaches_stopped() {
        let final_state = drive(
            PeripheralState::Advertising,
            &[
                LifecycleEvent::StopRequested,
                LifecycleEvent::AdvertiseStopped,
                LifecycleEvent::ServicesRemoved,
            ],
        );
        assert_eq!(final_state, PeripheralState::Stopped);
    }

    #[test]
    fn stopped_can_start_again() {
        let final_state = drive(
            PeripheralState::Stopped,
            &[
                LifecycleEvent::Reset,
                LifecycleEvent::StartRequested,
                LifecycleEvent::PlatformReady,
                LifecycleEvent::ServicesAdded,
                LifecycleEvent::AdvertiseStarted,
            ],
        );
        assert_eq!(final_state, PeripheralState::Advertising);
    }

    // ---- Teardown requires confirmation (the bug we are fixing) ----

    #[test]
    fn stop_request_alone_does_not_reach_stopped() {
        // Calling `stopAdvertising` without waiting for confirmation left
        // CoreBluetooth dirty in the previous implementation. The machine
        // must NOT allow StoppingAdvertisement → Stopped without
        // AdvertiseStopped first.
        let lc = PeripheralLifecycle::new();
        lc.apply(LifecycleEvent::StartRequested).unwrap();
        lc.apply(LifecycleEvent::PlatformReady).unwrap();
        lc.apply(LifecycleEvent::ServicesAdded).unwrap();
        lc.apply(LifecycleEvent::AdvertiseStarted).unwrap();
        lc.apply(LifecycleEvent::StopRequested).unwrap();
        assert_eq!(lc.current(), PeripheralState::StoppingAdvertisement);

        // Jumping straight to ServicesRemoved is invalid — we have not yet
        // seen AdvertiseStopped.
        let err = lc
            .apply(LifecycleEvent::ServicesRemoved)
            .expect_err("ServicesRemoved should be rejected in StoppingAdvertisement");
        assert_eq!(err.from, PeripheralState::StoppingAdvertisement);
        assert_eq!(lc.current(), PeripheralState::StoppingAdvertisement);
    }

    #[test]
    fn advertise_stopped_then_services_removed_reaches_stopped() {
        let final_state = drive(
            PeripheralState::StoppingAdvertisement,
            &[
                LifecycleEvent::AdvertiseStopped,
                LifecycleEvent::ServicesRemoved,
            ],
        );
        assert_eq!(final_state, PeripheralState::Stopped);
    }

    // ---- Platform availability transitions ----

    #[test]
    fn bluetooth_off_mid_advertising_rewinds_to_waiting_platform() {
        let final_state = drive(PeripheralState::Advertising, &[err("bluetooth off")]);
        assert_eq!(final_state, PeripheralState::StartingWaitingPlatform);
    }

    #[test]
    fn bluetooth_recovery_cycle_returns_to_advertising() {
        let final_state = drive(
            PeripheralState::Advertising,
            &[
                err("bluetooth off"),
                LifecycleEvent::PlatformReady,
                LifecycleEvent::ServicesAdded,
                LifecycleEvent::AdvertiseStarted,
            ],
        );
        assert_eq!(final_state, PeripheralState::Advertising);
    }

    #[test]
    fn platform_unavailable_while_waiting_platform_is_idempotent() {
        // iOS sometimes emits Resetting twice before PoweredOn.
        let final_state = drive(
            PeripheralState::StartingWaitingPlatform,
            &[err("resetting"), err("resetting")],
        );
        assert_eq!(final_state, PeripheralState::StartingWaitingPlatform);
    }

    // ---- Stop while starting ----

    #[test]
    fn stop_before_platform_ready_reaches_stopped_immediately() {
        // Nothing registered yet, nothing to tear down.
        let final_state = drive(
            PeripheralState::StartingWaitingPlatform,
            &[LifecycleEvent::StopRequested],
        );
        assert_eq!(final_state, PeripheralState::Stopped);
    }

    #[test]
    fn stop_mid_service_registration_skips_to_removing_services() {
        // Services need removing but there's no advertising to stop yet.
        let final_state = drive(
            PeripheralState::StartingRegisteringServices,
            &[LifecycleEvent::StopRequested],
        );
        assert_eq!(final_state, PeripheralState::StoppingRemovingServices);
    }

    #[test]
    fn stop_mid_advertise_enters_stopping_advertisement() {
        let final_state = drive(
            PeripheralState::StartingAdvertising,
            &[LifecycleEvent::StopRequested],
        );
        assert_eq!(final_state, PeripheralState::StoppingAdvertisement);
    }

    // ---- Idempotent events ----

    #[test]
    fn double_start_is_noop() {
        let lc = PeripheralLifecycle::new();
        lc.apply(LifecycleEvent::StartRequested).unwrap();
        lc.apply(LifecycleEvent::PlatformReady).unwrap();
        lc.apply(LifecycleEvent::ServicesAdded).unwrap();
        lc.apply(LifecycleEvent::AdvertiseStarted).unwrap();
        assert_eq!(lc.current(), PeripheralState::Advertising);

        lc.apply(LifecycleEvent::StartRequested).unwrap();
        assert_eq!(lc.current(), PeripheralState::Advertising);
    }

    #[test]
    fn double_stop_is_noop() {
        let lc = PeripheralLifecycle::new();
        lc.apply(LifecycleEvent::StopRequested).unwrap();
        assert_eq!(lc.current(), PeripheralState::Idle);
        lc.apply(LifecycleEvent::StopRequested).unwrap();
        assert_eq!(lc.current(), PeripheralState::Idle);
    }

    #[test]
    fn reset_from_idle_is_noop() {
        let lc = PeripheralLifecycle::new();
        lc.apply(LifecycleEvent::Reset).unwrap();
        assert_eq!(lc.current(), PeripheralState::Idle);
    }

    // ---- Fatal and recovery ----

    #[test]
    fn fatal_error_from_any_state_reaches_failed() {
        for from in [
            PeripheralState::Idle,
            PeripheralState::StartingWaitingPlatform,
            PeripheralState::StartingRegisteringServices,
            PeripheralState::StartingAdvertising,
            PeripheralState::Advertising,
            PeripheralState::StoppingAdvertisement,
            PeripheralState::StoppingRemovingServices,
            PeripheralState::Stopped,
        ] {
            let final_state = drive(from, &[fatal("oom")]);
            assert_eq!(final_state, PeripheralState::Failed, "from {from:?}");
        }
    }

    #[test]
    fn reset_from_failed_returns_to_idle() {
        let final_state = drive(PeripheralState::Failed, &[LifecycleEvent::Reset]);
        assert_eq!(final_state, PeripheralState::Idle);
    }

    #[test]
    fn failed_requires_reset_to_restart() {
        let lc = PeripheralLifecycle {
            state: Mutex::new(PeripheralState::Failed),
        };
        let err = lc
            .apply(LifecycleEvent::StartRequested)
            .expect_err("StartRequested from Failed should be rejected");
        assert_eq!(err.from, PeripheralState::Failed);
    }

    // ---- Invalid transitions ----

    #[test]
    fn advertise_started_from_idle_is_rejected() {
        let lc = PeripheralLifecycle::new();
        let err = lc
            .apply(LifecycleEvent::AdvertiseStarted)
            .expect_err("AdvertiseStarted from Idle should be rejected");
        assert_eq!(err.from, PeripheralState::Idle);
        assert_eq!(lc.current(), PeripheralState::Idle);
    }

    #[test]
    fn services_added_from_advertising_is_rejected() {
        let lc = PeripheralLifecycle {
            state: Mutex::new(PeripheralState::Advertising),
        };
        let err = lc
            .apply(LifecycleEvent::ServicesAdded)
            .expect_err("ServicesAdded from Advertising should be rejected");
        assert_eq!(err.from, PeripheralState::Advertising);
        assert_eq!(lc.current(), PeripheralState::Advertising);
    }

    #[test]
    fn advertise_stopped_from_idle_is_rejected() {
        let lc = PeripheralLifecycle::new();
        assert!(lc.apply(LifecycleEvent::AdvertiseStopped).is_err());
    }

    #[test]
    fn is_active_matches_intuition() {
        assert!(!PeripheralState::Idle.is_active());
        assert!(!PeripheralState::Stopped.is_active());
        assert!(!PeripheralState::Failed.is_active());
        assert!(PeripheralState::StartingWaitingPlatform.is_active());
        assert!(PeripheralState::StartingRegisteringServices.is_active());
        assert!(PeripheralState::StartingAdvertising.is_active());
        assert!(PeripheralState::Advertising.is_active());
        assert!(PeripheralState::StoppingAdvertisement.is_active());
        assert!(PeripheralState::StoppingRemovingServices.is_active());
    }

    #[test]
    fn is_starting_covers_all_starting_substates() {
        assert!(PeripheralState::StartingWaitingPlatform.is_starting());
        assert!(PeripheralState::StartingRegisteringServices.is_starting());
        assert!(PeripheralState::StartingAdvertising.is_starting());
        assert!(!PeripheralState::Advertising.is_starting());
        assert!(!PeripheralState::StoppingAdvertisement.is_starting());
    }

    #[test]
    fn is_stopping_covers_all_stopping_substates() {
        assert!(PeripheralState::StoppingAdvertisement.is_stopping());
        assert!(PeripheralState::StoppingRemovingServices.is_stopping());
        assert!(!PeripheralState::Advertising.is_stopping());
        assert!(!PeripheralState::StartingAdvertising.is_stopping());
    }

    #[test]
    fn is_advertising_helper_matches_current() {
        let lc = PeripheralLifecycle::new();
        assert!(!lc.is_advertising());
        lc.apply(LifecycleEvent::StartRequested).unwrap();
        lc.apply(LifecycleEvent::PlatformReady).unwrap();
        lc.apply(LifecycleEvent::ServicesAdded).unwrap();
        assert!(!lc.is_advertising());
        lc.apply(LifecycleEvent::AdvertiseStarted).unwrap();
        assert!(lc.is_advertising());
    }

    // ---- End-to-end scenarios exercised by the iOS / macOS adapter ----
    //
    // Locks in the toggle paths that are hard to hit reliably on a dev
    // machine (e.g. "disable fires before PoweredOn lands" races).

    #[test]
    fn full_enable_disable_enable_cycle_ends_idle_ready_to_advertise() {
        let lc = PeripheralLifecycle::new();
        lc.apply(LifecycleEvent::StartRequested).unwrap();
        lc.apply(LifecycleEvent::PlatformReady).unwrap();
        lc.apply(LifecycleEvent::ServicesAdded).unwrap();
        lc.apply(LifecycleEvent::AdvertiseStarted).unwrap();
        assert_eq!(lc.current(), PeripheralState::Advertising);
        lc.apply(LifecycleEvent::StopRequested).unwrap();
        lc.apply(LifecycleEvent::AdvertiseStopped).unwrap();
        lc.apply(LifecycleEvent::ServicesRemoved).unwrap();
        lc.apply(LifecycleEvent::Reset).unwrap();
        assert_eq!(lc.current(), PeripheralState::Idle);
        lc.apply(LifecycleEvent::StartRequested).unwrap();
        lc.apply(LifecycleEvent::PlatformReady).unwrap();
        lc.apply(LifecycleEvent::ServicesAdded).unwrap();
        lc.apply(LifecycleEvent::AdvertiseStarted).unwrap();
        assert_eq!(lc.current(), PeripheralState::Advertising);
    }

    #[test]
    fn quick_toggle_disable_before_platform_ready_ends_idle() {
        // User mashed Enable/Disable while CBManagerState was still Unknown.
        let lc = PeripheralLifecycle::new();
        lc.apply(LifecycleEvent::StartRequested).unwrap();
        lc.apply(LifecycleEvent::StopRequested).unwrap();
        assert_eq!(lc.current(), PeripheralState::Stopped);
        lc.apply(LifecycleEvent::Reset).unwrap();
        assert_eq!(lc.current(), PeripheralState::Idle);
    }

    #[test]
    fn stop_mid_service_registration_requires_services_removed_not_advertise_stopped() {
        // No advertising has started yet — the adapter must skip
        // `stopAdvertising` and go straight to `removeAllServices`.
        let lc = PeripheralLifecycle::new();
        lc.apply(LifecycleEvent::StartRequested).unwrap();
        lc.apply(LifecycleEvent::PlatformReady).unwrap();
        // Stop in the middle of registering, before either
        // `peripheralManagerDidAddService:error:` callback lands.
        lc.apply(LifecycleEvent::StopRequested).unwrap();
        assert_eq!(lc.current(), PeripheralState::StoppingRemovingServices);
        // `AdvertiseStopped` is nonsense here — reject it.
        let err = lc
            .apply(LifecycleEvent::AdvertiseStopped)
            .expect_err("AdvertiseStopped from StoppingRemovingServices should be rejected");
        assert_eq!(err.from, PeripheralState::StoppingRemovingServices);
        // `ServicesRemoved` is the correct continuation.
        lc.apply(LifecycleEvent::ServicesRemoved).unwrap();
        lc.apply(LifecycleEvent::Reset).unwrap();
        assert_eq!(lc.current(), PeripheralState::Idle);
    }

    #[test]
    fn redundant_services_added_after_advertise_start_is_ignored_not_fatal() {
        // Late `ServicesAdded` after AdvertiseStarted (radio bounce) must
        // be rejected without poisoning the machine — state unchanged.
        let lc = PeripheralLifecycle::new();
        lc.apply(LifecycleEvent::StartRequested).unwrap();
        lc.apply(LifecycleEvent::PlatformReady).unwrap();
        lc.apply(LifecycleEvent::ServicesAdded).unwrap();
        lc.apply(LifecycleEvent::AdvertiseStarted).unwrap();
        let err = lc.apply(LifecycleEvent::ServicesAdded);
        assert!(err.is_err());
        assert_eq!(lc.current(), PeripheralState::Advertising);
    }

    #[test]
    fn platform_unavailable_during_advertising_rewinds_and_recovers_automatically() {
        let lc = PeripheralLifecycle::new();
        lc.apply(LifecycleEvent::StartRequested).unwrap();
        lc.apply(LifecycleEvent::PlatformReady).unwrap();
        lc.apply(LifecycleEvent::ServicesAdded).unwrap();
        lc.apply(LifecycleEvent::AdvertiseStarted).unwrap();
        assert_eq!(lc.current(), PeripheralState::Advertising);

        lc.apply(LifecycleEvent::PlatformUnavailable {
            reason: "bluetooth off".into(),
        })
        .unwrap();
        assert_eq!(lc.current(), PeripheralState::StartingWaitingPlatform);

        // iOS sometimes emits Resetting twice — idempotent.
        lc.apply(LifecycleEvent::PlatformUnavailable {
            reason: "resetting".into(),
        })
        .unwrap();
        assert_eq!(lc.current(), PeripheralState::StartingWaitingPlatform);

        lc.apply(LifecycleEvent::PlatformReady).unwrap();
        lc.apply(LifecycleEvent::ServicesAdded).unwrap();
        lc.apply(LifecycleEvent::AdvertiseStarted).unwrap();
        assert_eq!(lc.current(), PeripheralState::Advertising);
    }

    #[test]
    fn stop_after_advertise_error_starts_from_waiting_platform_returns_to_idle() {
        // `peripheralManagerDidStartAdvertising:error:` with a non-nil error
        // surfaces as `PlatformUnavailable`; a stop from that rewound state
        // must still tear down cleanly.
        let lc = PeripheralLifecycle::new();
        lc.apply(LifecycleEvent::StartRequested).unwrap();
        lc.apply(LifecycleEvent::PlatformReady).unwrap();
        lc.apply(LifecycleEvent::ServicesAdded).unwrap();
        lc.apply(LifecycleEvent::PlatformUnavailable {
            reason: "advertising failed".into(),
        })
        .unwrap();
        assert_eq!(lc.current(), PeripheralState::StartingWaitingPlatform);
        lc.apply(LifecycleEvent::StopRequested).unwrap();
        assert_eq!(lc.current(), PeripheralState::Stopped);
        lc.apply(LifecycleEvent::Reset).unwrap();
        assert_eq!(lc.current(), PeripheralState::Idle);
    }

    #[test]
    fn concurrent_stop_requests_are_idempotent() {
        // BLE Mesh disable and app shutdown can race; a second
        // StopRequested from any Stopping* state must be a no-op.
        let lc = PeripheralLifecycle::new();
        lc.apply(LifecycleEvent::StartRequested).unwrap();
        lc.apply(LifecycleEvent::PlatformReady).unwrap();
        lc.apply(LifecycleEvent::ServicesAdded).unwrap();
        lc.apply(LifecycleEvent::AdvertiseStarted).unwrap();
        lc.apply(LifecycleEvent::StopRequested).unwrap();
        assert_eq!(lc.current(), PeripheralState::StoppingAdvertisement);
        lc.apply(LifecycleEvent::StopRequested).unwrap();
        assert_eq!(lc.current(), PeripheralState::StoppingAdvertisement);
        lc.apply(LifecycleEvent::AdvertiseStopped).unwrap();
        lc.apply(LifecycleEvent::ServicesRemoved).unwrap();
        assert_eq!(lc.current(), PeripheralState::Stopped);
    }
}
