//! Pure connection-generation ownership for the btleplug RNode transport.

use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use bytes::Bytes;
use futures::{Stream, StreamExt};

const STOP_POLL: Duration = Duration::from_millis(100);

#[derive(Clone, Copy, Debug, Default, Eq, Ord, PartialEq, PartialOrd)]
pub(super) struct BleGenerationId(u64);

impl BleGenerationId {
    pub(super) fn next(&mut self) -> Self {
        self.0 = self.0.wrapping_add(1).max(1);
        *self
    }

    pub(super) const fn get(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum BleOperationStage {
    Connect,
    ConnectedCheck,
    Discovery,
    PairingRead,
    Subscribe,
    NotificationAcquisition,
    Detect,
    Capability,
    Configure,
    ActiveWrite,
    Disconnect,
}

impl BleOperationStage {
    pub(super) const fn deadline(self) -> Duration {
        match self {
            Self::PairingRead => Duration::from_secs(60),
            Self::ActiveWrite => Duration::from_secs(5),
            Self::Disconnect => Duration::from_secs(3),
            Self::Connect
            | Self::ConnectedCheck
            | Self::Discovery
            | Self::Subscribe
            | Self::NotificationAcquisition
            | Self::Detect
            | Self::Capability
            | Self::Configure => Duration::from_secs(10),
        }
    }
}

impl fmt::Display for BleOperationStage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Connect => "connect",
            Self::ConnectedCheck => "connected check",
            Self::Discovery => "service discovery",
            Self::PairingRead => "pairing read",
            Self::Subscribe => "notification subscribe",
            Self::NotificationAcquisition => "notification acquisition",
            Self::Detect => "detect write",
            Self::Capability => "capability write",
            Self::Configure => "radio configuration write",
            Self::ActiveWrite => "application write",
            Self::Disconnect => "disconnect",
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum BleGenerationExit {
    TargetDisconnected {
        stage: BleOperationStage,
    },
    DeadlineElapsed {
        stage: BleOperationStage,
    },
    StopRequested {
        stage: BleOperationStage,
    },
    EventStreamEnded {
        stage: BleOperationStage,
    },
    StageFailed {
        stage: BleOperationStage,
        reason: String,
    },
}

impl fmt::Display for BleGenerationExit {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TargetDisconnected { stage } => {
                write!(formatter, "target disconnected during {stage}")
            }
            Self::DeadlineElapsed { stage } => write!(formatter, "{stage} timed out"),
            Self::StopRequested { stage } => write!(formatter, "stop requested during {stage}"),
            Self::EventStreamEnded { stage } => {
                write!(formatter, "adapter event stream ended during {stage}")
            }
            Self::StageFailed { stage, reason } => write!(formatter, "{stage}: {reason}"),
        }
    }
}

/// Run one platform future while the exact connection generation continues to
/// own target-disconnect and stop observation. Unrelated central events are
/// consumed but never end the operation.
pub(super) async fn run_generation_operation<T, E, F, S, I, P>(
    stage: BleOperationStage,
    future: F,
    events: &mut S,
    running: &AtomicBool,
    is_target_disconnect: P,
) -> Result<T, BleGenerationExit>
where
    E: fmt::Display,
    F: std::future::Future<Output = Result<T, E>>,
    S: Stream<Item = I> + Unpin,
    P: FnMut(&I) -> bool,
{
    run_generation_operation_with_timeout(
        stage,
        stage.deadline(),
        future,
        events,
        running,
        is_target_disconnect,
    )
    .await
}

async fn run_generation_operation_with_timeout<T, E, F, S, I, P>(
    stage: BleOperationStage,
    timeout: Duration,
    future: F,
    events: &mut S,
    running: &AtomicBool,
    mut is_target_disconnect: P,
) -> Result<T, BleGenerationExit>
where
    E: fmt::Display,
    F: std::future::Future<Output = Result<T, E>>,
    S: Stream<Item = I> + Unpin,
    P: FnMut(&I) -> bool,
{
    let deadline = tokio::time::Instant::now() + timeout;
    tokio::pin!(future);
    loop {
        if !running.load(Ordering::SeqCst) {
            return Err(BleGenerationExit::StopRequested { stage });
        }
        tokio::select! {
            biased;
            result = &mut future => return result.map_err(|error| BleGenerationExit::StageFailed {
                stage,
                reason: error.to_string(),
            }),
            event = events.next() => match event {
                Some(event) if is_target_disconnect(&event) => {
                    return Err(BleGenerationExit::TargetDisconnected { stage });
                }
                Some(_) => continue,
                None => return Err(BleGenerationExit::EventStreamEnded { stage }),
            },
            _ = tokio::time::sleep_until(deadline) => {
                return Err(BleGenerationExit::DeadlineElapsed { stage });
            }
            _ = tokio::time::sleep(STOP_POLL) => {}
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct PendingOutbound {
    payload: Bytes,
    station_id: bool,
}

impl PendingOutbound {
    pub(super) const fn new(payload: Bytes, station_id: bool) -> Self {
        Self {
            payload,
            station_id,
        }
    }

    pub(super) fn payload(&self) -> &Bytes {
        &self.payload
    }

    pub(super) const fn is_station_id(&self) -> bool {
        self.station_id
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::stream;

    #[tokio::test]
    async fn target_disconnect_preempts_platform_future_that_never_resolves() {
        for stage in [
            BleOperationStage::Connect,
            BleOperationStage::ConnectedCheck,
            BleOperationStage::Discovery,
            BleOperationStage::PairingRead,
            BleOperationStage::Subscribe,
            BleOperationStage::NotificationAcquisition,
            BleOperationStage::Detect,
            BleOperationStage::Capability,
            BleOperationStage::Configure,
            BleOperationStage::ActiveWrite,
        ] {
            let running = AtomicBool::new(true);
            let mut events = stream::iter(["other", "target"]);
            let outcome = run_generation_operation_with_timeout(
                stage,
                Duration::from_secs(1),
                std::future::pending::<Result<(), &'static str>>(),
                &mut events,
                &running,
                |event| *event == "target",
            )
            .await;
            assert_eq!(
                outcome,
                Err(BleGenerationExit::TargetDisconnected { stage })
            );
        }
    }

    #[tokio::test]
    async fn unrelated_disconnect_does_not_end_generation() {
        let running = AtomicBool::new(true);
        let mut events = stream::iter(["other"]).chain(stream::pending());
        let outcome = run_generation_operation_with_timeout(
            BleOperationStage::Subscribe,
            Duration::from_secs(1),
            async { Ok::<_, &'static str>(7) },
            &mut events,
            &running,
            |event| *event == "target",
        )
        .await;
        assert_eq!(outcome, Ok(7));
    }

    #[tokio::test]
    async fn every_stage_has_an_independent_deadline() {
        for stage in [
            BleOperationStage::Connect,
            BleOperationStage::ConnectedCheck,
            BleOperationStage::Discovery,
            BleOperationStage::PairingRead,
            BleOperationStage::Subscribe,
            BleOperationStage::NotificationAcquisition,
            BleOperationStage::Detect,
            BleOperationStage::Capability,
            BleOperationStage::Configure,
            BleOperationStage::ActiveWrite,
            BleOperationStage::Disconnect,
        ] {
            let running = AtomicBool::new(true);
            let mut events = stream::pending::<&'static str>();
            let outcome = run_generation_operation_with_timeout(
                stage,
                Duration::from_millis(2),
                std::future::pending::<Result<(), &'static str>>(),
                &mut events,
                &running,
                |_| false,
            )
            .await;
            assert_eq!(outcome, Err(BleGenerationExit::DeadlineElapsed { stage }));
        }
    }

    #[tokio::test]
    async fn stop_preempts_pending_operation() {
        let running = AtomicBool::new(false);
        let mut events = stream::pending::<&'static str>();
        let outcome = run_generation_operation_with_timeout(
            BleOperationStage::ActiveWrite,
            Duration::from_secs(1),
            std::future::pending::<Result<(), &'static str>>(),
            &mut events,
            &running,
            |_| false,
        )
        .await;
        assert_eq!(
            outcome,
            Err(BleGenerationExit::StopRequested {
                stage: BleOperationStage::ActiveWrite,
            })
        );
    }

    #[tokio::test]
    async fn event_stream_closure_is_not_success() {
        let running = AtomicBool::new(true);
        let mut events = stream::empty::<&'static str>();
        let outcome = run_generation_operation_with_timeout(
            BleOperationStage::Connect,
            Duration::from_secs(1),
            std::future::pending::<Result<(), &'static str>>(),
            &mut events,
            &running,
            |_| false,
        )
        .await;
        assert_eq!(
            outcome,
            Err(BleGenerationExit::EventStreamEnded {
                stage: BleOperationStage::Connect,
            })
        );
    }

    #[test]
    fn generation_ids_are_monotonic_and_pending_payload_is_stable() {
        let mut id = BleGenerationId::default();
        assert!(id.next() < id.next());
        let pending = PendingOutbound::new(Bytes::from_static(b"packet"), false);
        assert_eq!(pending.payload(), &Bytes::from_static(b"packet"));
        assert!(!pending.is_station_id());
    }
}
