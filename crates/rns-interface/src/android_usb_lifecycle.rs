//! JNI-free ownership core for Android USB serial.
//!
//! The Android adapter supplies the actual Java bulk-transfer and connection
//! operations. Keeping queueing, deadlines, worker joins, and lifecycle
//! ordering here makes those invariants executable on ordinary host CI.

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use bytes::Bytes;
use tokio::sync::{Notify, OwnedSemaphorePermit, Semaphore, mpsc, oneshot};
use tokio::task::JoinHandle;

use crate::kiss;
use crate::rnode::{
    self, RNodeCapabilityAdmissionError, RNodeRadioSettings, RNodeRuntimeReason,
    RNodeSnapshotPublisher,
};
use crate::rnode_capabilities::RNodeRadioAdmission;
use crate::rnode_capability_preflight::RNodeCapabilityPreflight;
use crate::rnode_protocol::{
    RNodeProtocolFrame, RNodeProtocolState, RNodeProtocolTarget, RNodeReadiness,
};
use crate::traits::InterfaceId;
use rns_transport::messages::TransportMessage;

const MIN_TRANSFER_TIMEOUT: Duration = Duration::from_millis(1);
const USB_READER_BOUNDARY_POLL_INTERVAL: Duration = Duration::from_millis(1);
const USB_PACKET_WRITE_DEADLINE: Duration = Duration::from_secs(2);
pub(crate) const USB_PROTOCOL_READINESS_DEADLINE: Duration = Duration::from_secs(10);

/// Stable identity retained across Android's transient `/dev/bus/usb` names.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct UsbDeviceSelector {
    pub(crate) legacy_device_name: String,
    pub(crate) vendor_id: Option<u16>,
    pub(crate) product_id: Option<u16>,
    pub(crate) serial_number: Option<String>,
}

/// Permission-safe device facts obtained from one UsbManager enumeration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct UsbDeviceCandidate {
    pub(crate) device_name: String,
    pub(crate) vendor_id: u16,
    pub(crate) product_id: u16,
    pub(crate) serial_number: Option<String>,
    pub(crate) has_permission: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum UsbDeviceResolutionError {
    NotFound,
    Ambiguous { matches: usize },
    PermissionRequired { device_name: String },
}

impl std::fmt::Display for UsbDeviceResolutionError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound => formatter.write_str("configured Android USB device is not attached"),
            Self::Ambiguous { matches } => write!(
                formatter,
                "configured Android USB selector matches {matches} devices; refusing ambiguous reopen"
            ),
            Self::PermissionRequired { .. } => {
                formatter.write_str("Android USB permission is required")
            }
        }
    }
}

/// Resolve one physical generation without ever guessing between devices.
/// A legacy path may identify the first generation exactly; the returned
/// selector learns VID/PID and an accessible serial for later path changes.
pub(crate) fn resolve_usb_device(
    selector: &UsbDeviceSelector,
    candidates: &[UsbDeviceCandidate],
) -> Result<(UsbDeviceCandidate, UsbDeviceSelector), UsbDeviceResolutionError> {
    let mut matches: Vec<&UsbDeviceCandidate> = match (selector.vendor_id, selector.product_id) {
        (Some(vendor_id), Some(product_id)) => {
            let product_matches: Vec<_> = candidates
                .iter()
                .filter(|candidate| {
                    candidate.vendor_id == vendor_id && candidate.product_id == product_id
                })
                .collect();
            if let Some(serial) = selector.serial_number.as_ref() {
                let exact: Vec<_> = product_matches
                    .iter()
                    .copied()
                    .filter(|candidate| candidate.serial_number.as_ref() == Some(serial))
                    .collect();
                if !exact.is_empty() {
                    exact
                } else {
                    let unreadable: Vec<_> = product_matches
                        .iter()
                        .copied()
                        .filter(|candidate| {
                            !candidate.has_permission && candidate.serial_number.is_none()
                        })
                        .collect();
                    match unreadable.as_slice() {
                        [candidate] => {
                            return Err(UsbDeviceResolutionError::PermissionRequired {
                                device_name: candidate.device_name.clone(),
                            });
                        }
                        [] => Vec::new(),
                        candidates => {
                            return Err(UsbDeviceResolutionError::Ambiguous {
                                matches: candidates.len(),
                            });
                        }
                    }
                }
            } else {
                product_matches
            }
        }
        _ => candidates
            .iter()
            .filter(|candidate| candidate.device_name == selector.legacy_device_name)
            .collect(),
    };
    if matches.is_empty() {
        return Err(UsbDeviceResolutionError::NotFound);
    }
    if matches.len() != 1 {
        return Err(UsbDeviceResolutionError::Ambiguous {
            matches: matches.len(),
        });
    }
    let candidate = matches.pop().expect("one USB match checked").clone();
    if !candidate.has_permission {
        return Err(UsbDeviceResolutionError::PermissionRequired {
            device_name: candidate.device_name,
        });
    }
    let learned = UsbDeviceSelector {
        legacy_device_name: candidate.device_name.clone(),
        vendor_id: Some(candidate.vendor_id),
        product_id: Some(candidate.product_id),
        serial_number: candidate.serial_number.clone(),
    };
    Ok((candidate, learned))
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum UsbLeaseKind {
    Opening,
    Active,
    Quarantined,
}

enum UsbLeaseState<R> {
    Opening,
    Active,
    Quarantined(Vec<R>),
}

/// Single authority for USB-device admission and permanent quarantine.
///
/// All transitions happen while the caller holds the surrounding mutex.
/// Quarantine is terminal and appends every retained physical session.
pub(crate) struct UsbLeaseTable<R> {
    devices: HashMap<String, UsbLeaseState<R>>,
}

impl<R> Default for UsbLeaseTable<R> {
    fn default() -> Self {
        Self {
            devices: HashMap::new(),
        }
    }
}

impl<R> UsbLeaseTable<R> {
    pub(crate) fn reserve_opening(&mut self, device_name: &str) -> Result<(), String> {
        if let Some(state) = self.devices.get(device_name) {
            let state = match state {
                UsbLeaseState::Opening => "already opening",
                UsbLeaseState::Active => "already active",
                UsbLeaseState::Quarantined(_) => "permanently quarantined",
            };
            return Err(format!("Android USB device is {state}"));
        }
        self.devices
            .insert(device_name.to_string(), UsbLeaseState::Opening);
        Ok(())
    }

    pub(crate) fn activate(&mut self, device_name: &str) -> Result<(), String> {
        match self.devices.get_mut(device_name) {
            Some(state @ UsbLeaseState::Opening) => {
                *state = UsbLeaseState::Active;
                Ok(())
            }
            Some(UsbLeaseState::Active) => Err("Android USB device is already active".into()),
            Some(UsbLeaseState::Quarantined(_)) => {
                Err("Android USB device is permanently quarantined".into())
            }
            None => Err("Android USB device has no opening reservation".into()),
        }
    }

    pub(crate) fn release_opening(&mut self, device_name: &str) -> Result<(), String> {
        match self.devices.get(device_name) {
            Some(UsbLeaseState::Opening) => {
                self.devices.remove(device_name);
                Ok(())
            }
            Some(UsbLeaseState::Active) => {
                Err("Android USB device became active before opening release".into())
            }
            Some(UsbLeaseState::Quarantined(_)) => {
                Err("Android USB device is permanently quarantined".into())
            }
            None => Err("Android USB device has no opening reservation".into()),
        }
    }

    pub(crate) fn release_active(&mut self, device_name: &str) -> Result<(), String> {
        match self.devices.get(device_name) {
            Some(UsbLeaseState::Active) => {
                self.devices.remove(device_name);
                Ok(())
            }
            Some(UsbLeaseState::Opening) => Err("Android USB device never became active".into()),
            Some(UsbLeaseState::Quarantined(_)) => {
                Err("Android USB device is permanently quarantined".into())
            }
            None => Err("Android USB device has no active lease".into()),
        }
    }

    pub(crate) fn quarantine(&mut self, device_name: &str, retained: R) {
        match self.devices.get_mut(device_name) {
            Some(UsbLeaseState::Quarantined(retained_sessions)) => {
                retained_sessions.push(retained);
            }
            Some(state) => {
                *state = UsbLeaseState::Quarantined(vec![retained]);
            }
            None => {
                self.devices.insert(
                    device_name.to_string(),
                    UsbLeaseState::Quarantined(vec![retained]),
                );
            }
        }
    }

    #[cfg(test)]
    fn state(&self, device_name: &str) -> Option<(UsbLeaseKind, usize)> {
        self.devices.get(device_name).map(|state| match state {
            UsbLeaseState::Opening => (UsbLeaseKind::Opening, 0),
            UsbLeaseState::Active => (UsbLeaseKind::Active, 0),
            UsbLeaseState::Quarantined(retained) => (UsbLeaseKind::Quarantined, retained.len()),
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum UsbWritePhase {
    Detect,
    Capability,
    Initialise,
    Packet,
    Detach,
}

impl UsbWritePhase {
    const fn label(self) -> &'static str {
        match self {
            Self::Detect => "detect",
            Self::Capability => "capability",
            Self::Initialise => "init",
            Self::Packet => "packet",
            Self::Detach => "detach",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum UsbTransferError {
    Backend(String),
    WrongReturnType,
}

pub(crate) trait UsbWriterBackend: Send + 'static {
    /// Perform one bulk transfer and return Java's signed byte count.
    fn transfer(&mut self, bytes: &[u8], timeout: Duration) -> Result<i32, UsbTransferError>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum UsbReadResult {
    Data(Vec<u8>),
    Idle,
}

pub(crate) trait UsbReaderBackend: Send + 'static {
    fn read(&mut self) -> Result<UsbReadResult, String>;
}

pub(crate) enum UsbConnectionCleanup<O> {
    Closed {
        release_interface: Result<(), String>,
    },
    Unclosed {
        owner: O,
        release_interface: Result<(), String>,
        close_connection: String,
    },
}

pub(crate) trait UsbConnectionLifecycle: Send + Sized + 'static {
    fn release_and_close(self) -> UsbConnectionCleanup<Self>;

    /// Permanently retain this physical session and make future opens fail.
    fn retain_quarantined(self);
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum UsbWriteFailureKind {
    Backend(String),
    WrongReturnType,
    ZeroLength,
    NegativeLength(i32),
    OversizedLength { returned: i32, remaining: usize },
    QueueClosed,
    AcknowledgementDropped,
    DeadlineElapsed,
    AdmissionClosed,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct UsbWriteFailure {
    pub(crate) phase: UsbWritePhase,
    pub(crate) kind: UsbWriteFailureKind,
}

impl std::fmt::Display for UsbWriteFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.kind {
            UsbWriteFailureKind::Backend(error) => {
                write!(formatter, "{} write: {error}", self.phase.label())
            }
            UsbWriteFailureKind::WrongReturnType => {
                write!(
                    formatter,
                    "{} write returned a non-integer JNI value",
                    self.phase.label()
                )
            }
            UsbWriteFailureKind::ZeroLength => {
                write!(formatter, "{} write made no progress", self.phase.label())
            }
            UsbWriteFailureKind::NegativeLength(returned) => {
                write!(
                    formatter,
                    "{} write returned {returned}",
                    self.phase.label()
                )
            }
            UsbWriteFailureKind::OversizedLength {
                returned,
                remaining,
            } => {
                write!(
                    formatter,
                    "{} write returned {returned} for {remaining} remaining bytes",
                    self.phase.label()
                )
            }
            UsbWriteFailureKind::QueueClosed => {
                write!(formatter, "{} writer queue closed", self.phase.label())
            }
            UsbWriteFailureKind::AcknowledgementDropped => {
                write!(
                    formatter,
                    "{} writer acknowledgement dropped",
                    self.phase.label()
                )
            }
            UsbWriteFailureKind::DeadlineElapsed => {
                write!(
                    formatter,
                    "{} queue-to-transfer deadline elapsed",
                    self.phase.label()
                )
            }
            UsbWriteFailureKind::AdmissionClosed => {
                write!(
                    formatter,
                    "{} protocol/flow admission closed",
                    self.phase.label()
                )
            }
        }
    }
}

struct UsbWriteRequest {
    phase: UsbWritePhase,
    bytes: Vec<u8>,
    deadline: Option<Instant>,
    acknowledgement: Option<oneshot::Sender<Result<(), UsbWriteFailure>>>,
    await_terminal_detach_on_failure: bool,
    packet: Option<UsbPacketWrite>,
    _permit: Option<OwnedSemaphorePermit>,
}

struct UsbPacketWrite {
    transmitted_bytes: Arc<AtomicU64>,
    payload_len: u64,
    gate: Option<Arc<UsbTxGate>>,
    completed: Arc<AtomicBool>,
}

/// Operational state belongs to one physical generation, never to an observer
/// snapshot. The shared online flag describes typed protocol readiness; READY
/// is an independent, saturating one-packet permission when configured.
pub(crate) struct UsbTxGate {
    state: Mutex<UsbTxGateState>,
    flow_control: bool,
    online: Arc<AtomicBool>,
    changed: Notify,
}

struct UsbTxGateState {
    ready: bool,
    permit: bool,
    closed: bool,
    readiness_deadline: tokio::time::Instant,
}

impl UsbTxGate {
    pub(crate) fn new(flow_control: bool, online: Arc<AtomicBool>) -> Arc<Self> {
        online.store(false, Ordering::Release);
        Arc::new(Self {
            state: Mutex::new(UsbTxGateState {
                ready: false,
                permit: true,
                closed: false,
                readiness_deadline: tokio::time::Instant::now() + USB_PROTOCOL_READINESS_DEADLINE,
            }),
            flow_control,
            online,
            changed: Notify::new(),
        })
    }

    fn observe(&self, protocol: &RNodeProtocolState, command: u8, frame: &[u8]) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.closed {
            return;
        }
        let ready = protocol.readiness() == RNodeReadiness::Ready;
        if state.ready && !ready {
            // A later loss of RF readiness owns a new bounded recovery
            // episode, even after hours of healthy idle time. Repeated bad
            // evidence must not extend that episode or preserve an old grant.
            state.readiness_deadline =
                tokio::time::Instant::now() + USB_PROTOCOL_READINESS_DEADLINE;
            state.permit = false;
        }
        state.ready = ready;
        // Decode every valid READY, including an identical repeated positive
        // response: the diagnostic reducer may call it NoChange after we used
        // the prior permit. Malformed widths never grant or revoke permission.
        match RNodeProtocolFrame::decode(command, frame) {
            Ok(RNodeProtocolFrame::FlowPermission(permitted)) => state.permit = permitted,
            Ok(RNodeProtocolFrame::Reset) => state.permit = false,
            _ => {}
        }
        self.online.store(state.ready, Ordering::Release);
        drop(state);
        self.changed.notify_one();
    }

    fn can_send(&self) -> bool {
        let state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        !state.closed && state.ready && (!self.flow_control || state.permit)
    }

    #[cfg(test)]
    fn is_ready(&self) -> bool {
        let state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        !state.closed && state.ready
    }

    fn readiness_deadline(&self) -> Option<tokio::time::Instant> {
        let state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        (!state.closed && !state.ready).then_some(state.readiness_deadline)
    }

    fn readiness_expired(&self) -> bool {
        self.readiness_deadline()
            .is_some_and(|deadline| tokio::time::Instant::now() >= deadline)
    }

    fn take_permit(&self) -> bool {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.closed || !state.ready || (self.flow_control && !state.permit) {
            return false;
        }
        if self.flow_control {
            state.permit = false;
        }
        true
    }

    pub(crate) fn close(&self) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.closed = true;
        state.ready = false;
        state.permit = false;
        self.online.store(false, Ordering::Release);
        drop(state);
        self.changed.notify_one();
    }
}

struct UsbWriteQueueState {
    requests: VecDeque<UsbWriteRequest>,
    accepting: bool,
    cancelled: bool,
    worker_closed: bool,
}

struct UsbWriteQueueInner {
    state: Mutex<UsbWriteQueueState>,
    wake: Condvar,
    slots: Arc<Semaphore>,
}

#[derive(Clone)]
struct UsbWriteQueue {
    inner: Arc<UsbWriteQueueInner>,
}

impl UsbWriteQueue {
    fn new(capacity: usize) -> Self {
        Self {
            inner: Arc::new(UsbWriteQueueInner {
                state: Mutex::new(UsbWriteQueueState {
                    requests: VecDeque::new(),
                    accepting: true,
                    cancelled: false,
                    worker_closed: false,
                }),
                wake: Condvar::new(),
                slots: Arc::new(Semaphore::new(capacity)),
            }),
        }
    }

    async fn enqueue_with_failure_policy(
        &self,
        phase: UsbWritePhase,
        bytes: Vec<u8>,
        deadline: Option<Instant>,
        acknowledgement: Option<oneshot::Sender<Result<(), UsbWriteFailure>>>,
        await_terminal_detach_on_failure: bool,
        packet: Option<UsbPacketWrite>,
    ) -> Result<(), UsbWriteFailure> {
        let permit = self
            .inner
            .slots
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| UsbWriteFailure {
                phase,
                kind: UsbWriteFailureKind::QueueClosed,
            })?;
        let mut state = self
            .inner
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !state.accepting || state.cancelled || state.worker_closed {
            return Err(UsbWriteFailure {
                phase,
                kind: UsbWriteFailureKind::QueueClosed,
            });
        }
        state.requests.push_back(UsbWriteRequest {
            phase,
            bytes,
            deadline,
            acknowledgement,
            await_terminal_detach_on_failure,
            packet,
            _permit: Some(permit),
        });
        drop(state);
        self.inner.wake.notify_one();
        Ok(())
    }

    fn begin_detach(
        &self,
        bytes: Vec<u8>,
        deadline: Instant,
    ) -> Result<oneshot::Receiver<Result<(), UsbWriteFailure>>, UsbWriteFailure> {
        let phase = UsbWritePhase::Detach;
        let (acknowledgement, result) = oneshot::channel();
        let mut state = self
            .inner
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.cancelled || state.worker_closed {
            return Err(UsbWriteFailure {
                phase,
                kind: UsbWriteFailureKind::QueueClosed,
            });
        }

        // Atomically stop admissions and discard every queued pre-detach
        // packet before making the terminal request visible to the worker.
        state.accepting = false;
        self.inner.slots.close();
        state.requests.clear();
        state.requests.push_back(UsbWriteRequest {
            phase,
            bytes,
            deadline: Some(deadline),
            acknowledgement: Some(acknowledgement),
            await_terminal_detach_on_failure: false,
            packet: None,
            _permit: None,
        });
        drop(state);
        self.inner.wake.notify_all();
        Ok(result)
    }

    fn recv(&self) -> Option<UsbWriteRequest> {
        let mut state = self
            .inner
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        loop {
            if state.cancelled {
                return None;
            }
            if let Some(request) = state.requests.pop_front() {
                return Some(request);
            }
            if state.worker_closed {
                return None;
            }
            state = self
                .inner
                .wake
                .wait(state)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
        }
    }

    fn cancel_and_wake(&self) {
        let mut state = self
            .inner
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.accepting = false;
        state.cancelled = true;
        state.requests.clear();
        self.inner.slots.close();
        drop(state);
        self.inner.wake.notify_all();
    }

    fn mark_worker_closed(&self) {
        let mut state = self
            .inner
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.worker_closed = true;
        state.accepting = false;
        state.requests.clear();
        self.inner.slots.close();
        drop(state);
        self.inner.wake.notify_all();
    }
}

struct UsbWriteWorkerGuard {
    queue: UsbWriteQueue,
}

impl Drop for UsbWriteWorkerGuard {
    fn drop(&mut self) {
        self.queue.mark_worker_closed();
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum UsbWriterExit {
    Detached,
    Stopped,
    Failed(String),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum UsbReaderExit {
    Stopped,
    ConsumerClosed,
    Failed(String),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum UsbIoEvent {
    Read(Vec<u8>),
    Writer(UsbWriterExit),
    Reader(UsbReaderExit),
}

pub(crate) struct UsbInboundState {
    deframer: kiss::RawKissDeframer,
    last_rssi: Option<f32>,
    last_snr: Option<f32>,
    projection: Option<UsbRNodeProjection>,
    tx_gate: Option<Arc<UsbTxGate>>,
}

struct UsbRNodeProjection {
    protocol: RNodeProtocolState,
    publisher: RNodeSnapshotPublisher,
}

impl UsbInboundState {
    pub(crate) fn new() -> Self {
        Self {
            deframer: kiss::RawKissDeframer::new(),
            last_rssi: None,
            last_snr: None,
            projection: None,
            tx_gate: None,
        }
    }

    #[cfg(test)]
    pub(crate) fn projected(
        target: RNodeProtocolTarget,
        publisher: RNodeSnapshotPublisher,
    ) -> Self {
        Self::projected_with_protocol_state(RNodeProtocolState::new(target), publisher)
    }

    /// Begin active processing from a capability-admitted protocol seed.
    ///
    /// Only DETECT and supported-firmware evidence can cross this boundary;
    /// [`RNodeCapabilityPreflight::into_protocol_state`] deliberately drops
    /// every pre-init RF echo and any partial framing. Fresh init responses
    /// must still satisfy readiness after this state becomes active.
    pub(crate) fn projected_with_protocol_state(
        protocol: RNodeProtocolState,
        publisher: RNodeSnapshotPublisher,
    ) -> Self {
        Self {
            projection: Some(UsbRNodeProjection {
                protocol,
                publisher,
            }),
            ..Self::new()
        }
    }

    fn project_frame(&mut self, command: u8, frame: &[u8]) {
        let Some(projection) = self.projection.as_mut() else {
            return;
        };
        let effect = projection.protocol.apply_frame(command, frame);
        if let Some(gate) = &self.tx_gate {
            gate.observe(&projection.protocol, command, frame);
        }
        projection
            .publisher
            .protocol_effect(&projection.protocol, effect);
    }

    pub(crate) fn attach_tx_gate(&mut self, gate: Arc<UsbTxGate>) {
        // A gate is never seeded from retained diagnostics. Fresh protocol
        // frames in this exact physical generation own its admission state.
        self.tx_gate = Some(gate);
    }

    pub(crate) fn shutting_down(&self, reason: RNodeRuntimeReason) {
        if let Some(gate) = &self.tx_gate {
            gate.close();
        }
        if let Some(projection) = &self.projection {
            projection.publisher.shutting_down(reason);
        }
    }

    pub(crate) fn stopped(&mut self, reason: RNodeRuntimeReason) {
        if let Some(gate) = &self.tx_gate {
            gate.close();
        }
        if let Some(projection) = self.projection.as_mut() {
            projection.publisher.stopped(reason);
        }
    }

    /// Return the lifecycle publisher after one physical USB generation ends.
    ///
    /// Framing and protocol evidence are intentionally generation-local, but
    /// the privacy-safe observation stream belongs to the stable logical
    /// interface and must survive an unplug/replug cycle.
    #[cfg_attr(not(target_os = "android"), allow(dead_code))]
    pub(crate) fn into_publisher(mut self) -> Option<RNodeSnapshotPublisher> {
        self.projection
            .take()
            .map(|projection| projection.publisher)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum UsbInboundOutcome {
    Complete,
    StopRequested,
    TransportClosed,
    DeadlineElapsed,
}

/// Deframe and forward one raw USB chunk. Normal reads and post-reader-exit
/// draining both use this path so buffered packets retain identical handling.
pub(crate) async fn forward_usb_read_chunk(
    state: &mut UsbInboundState,
    bytes: &[u8],
    id: InterfaceId,
    received_bytes: &AtomicU64,
    transport_tx: &mpsc::Sender<TransportMessage>,
    stop_rx: &mut mpsc::Receiver<()>,
) -> UsbInboundOutcome {
    forward_usb_read_chunk_inner(
        state,
        bytes,
        id,
        received_bytes,
        transport_tx,
        stop_rx,
        None,
    )
    .await
}

async fn forward_usb_read_chunk_inner(
    state: &mut UsbInboundState,
    bytes: &[u8],
    id: InterfaceId,
    received_bytes: &AtomicU64,
    transport_tx: &mpsc::Sender<TransportMessage>,
    stop_rx: &mut mpsc::Receiver<()>,
    deadline: Option<tokio::time::Instant>,
) -> UsbInboundOutcome {
    if bytes.is_empty() {
        return UsbInboundOutcome::Complete;
    }
    for (command, frame) in state.deframer.feed(bytes) {
        state.project_frame(command, &frame);
        match rnode::process_rnode_response(
            command,
            &frame,
            id,
            &mut state.last_rssi,
            &mut state.last_snr,
        ) {
            rnode::RNodeResponse::Packet(message) => {
                // Preserve legacy Android USB/BLE accounting: a recognized
                // LoRa payload counts before transport forwarding is awaited.
                received_bytes.fetch_add(frame.len() as u64, Ordering::Relaxed);
                let sent = if let Some(deadline) = deadline {
                    tokio::select! {
                        biased;
                        _ = stop_rx.recv() => {
                            return UsbInboundOutcome::StopRequested;
                        }
                        _ = tokio::time::sleep_until(deadline) => {
                            return UsbInboundOutcome::DeadlineElapsed;
                        }
                        result = transport_tx.send(message) => result,
                    }
                } else {
                    tokio::select! {
                        biased;
                        _ = stop_rx.recv() => {
                            return UsbInboundOutcome::StopRequested;
                        }
                        result = transport_tx.send(message) => result,
                    }
                };
                if sent.is_err() {
                    return UsbInboundOutcome::TransportClosed;
                }
            }
            rnode::RNodeResponse::Ready(_) | rnode::RNodeResponse::None => {}
        }
    }
    UsbInboundOutcome::Complete
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum UsbReadDrainOutcome {
    Drained,
    StopRequested,
    TransportClosed,
    DeadlineElapsed,
}

/// After writer failure, consume the ordered reader tail through its exit
/// marker. The caller first cancels the live reader, and this absolute
/// deadline prevents an uncooperative backend from stalling teardown.
pub(crate) async fn drain_usb_reader_tail(
    events: &mut mpsc::Receiver<UsbIoEvent>,
    state: &mut UsbInboundState,
    id: InterfaceId,
    received_bytes: &AtomicU64,
    transport_tx: &mpsc::Sender<TransportMessage>,
    stop_rx: &mut mpsc::Receiver<()>,
    deadline: tokio::time::Instant,
) -> UsbReadDrainOutcome {
    loop {
        tokio::select! {
            biased;
            _ = stop_rx.recv() => {
                return UsbReadDrainOutcome::StopRequested;
            }
            _ = tokio::time::sleep_until(deadline) => {
                return UsbReadDrainOutcome::DeadlineElapsed;
            }
            event = events.recv() => {
                let Some(event) = event else {
                    return UsbReadDrainOutcome::Drained;
                };
                match event {
                    UsbIoEvent::Read(bytes) => {
                        match forward_usb_read_chunk_inner(
                            state,
                            &bytes,
                            id,
                            received_bytes,
                            transport_tx,
                            stop_rx,
                            Some(deadline),
                        ).await {
                            UsbInboundOutcome::Complete => {}
                            UsbInboundOutcome::StopRequested => {
                                return UsbReadDrainOutcome::StopRequested;
                            }
                            UsbInboundOutcome::TransportClosed => {
                                return UsbReadDrainOutcome::TransportClosed;
                            }
                            UsbInboundOutcome::DeadlineElapsed => {
                                return UsbReadDrainOutcome::DeadlineElapsed;
                            }
                        }
                    }
                    UsbIoEvent::Reader(_) => return UsbReadDrainOutcome::Drained,
                    UsbIoEvent::Writer(_) => {}
                }
            }
        }
    }
}

fn transfer_timeout(
    deadline: Option<Instant>,
    default_timeout: Duration,
    phase: UsbWritePhase,
) -> Result<Duration, UsbWriteFailure> {
    let Some(deadline) = deadline else {
        return Ok(default_timeout);
    };
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining < MIN_TRANSFER_TIMEOUT {
        return Err(UsbWriteFailure {
            phase,
            kind: UsbWriteFailureKind::DeadlineElapsed,
        });
    }
    Ok(default_timeout.min(remaining))
}

fn write_request<W>(
    backend: &mut W,
    request: &UsbWriteRequest,
    default_timeout: Duration,
) -> Result<(), UsbWriteFailure>
where
    W: UsbWriterBackend,
{
    let mut offset = 0;
    while offset < request.bytes.len() {
        let timeout = transfer_timeout(request.deadline, default_timeout, request.phase)?;
        let remaining = &request.bytes[offset..];
        let transferred =
            backend
                .transfer(remaining, timeout)
                .map_err(|error| UsbWriteFailure {
                    phase: request.phase,
                    kind: match error {
                        UsbTransferError::Backend(error) => UsbWriteFailureKind::Backend(error),
                        UsbTransferError::WrongReturnType => UsbWriteFailureKind::WrongReturnType,
                    },
                })?;
        if transferred < 0 {
            return Err(UsbWriteFailure {
                phase: request.phase,
                kind: UsbWriteFailureKind::NegativeLength(transferred),
            });
        }
        if transferred == 0 {
            return Err(UsbWriteFailure {
                phase: request.phase,
                kind: UsbWriteFailureKind::ZeroLength,
            });
        }
        if transferred as usize > remaining.len() {
            return Err(UsbWriteFailure {
                phase: request.phase,
                kind: UsbWriteFailureKind::OversizedLength {
                    returned: transferred,
                    remaining: remaining.len(),
                },
            });
        }
        offset += transferred as usize;
    }
    // Positive completion evidence is independent of the caller's deadline.
    // A final bulkTransfer may return all bytes just after its waiter timed
    // out. Publish exactly this physical result before classifying the late
    // acknowledgement, so the logical queue will not replay a known-complete
    // payload after the old physical generation has been fully joined.
    if let Some(packet) = &request.packet {
        packet
            .transmitted_bytes
            .fetch_add(packet.payload_len, Ordering::Relaxed);
        packet.completed.store(true, Ordering::Release);
    }
    if request
        .deadline
        .is_some_and(|deadline| Instant::now() > deadline)
    {
        return Err(UsbWriteFailure {
            phase: request.phase,
            kind: UsbWriteFailureKind::DeadlineElapsed,
        });
    }
    Ok(())
}

fn run_usb_writer<W>(
    mut backend: W,
    queue: UsbWriteQueue,
    running: Arc<AtomicBool>,
    online: Arc<AtomicBool>,
    default_timeout: Duration,
) -> UsbWriterExit
where
    W: UsbWriterBackend,
{
    let _worker_guard = UsbWriteWorkerGuard {
        queue: queue.clone(),
    };
    let mut terminal_detach_only = false;
    while running.load(Ordering::Acquire) {
        let Some(request) = queue.recv() else {
            return UsbWriterExit::Stopped;
        };
        if !running.load(Ordering::Acquire) {
            return UsbWriterExit::Stopped;
        }
        let phase = request.phase;
        if terminal_detach_only && phase != UsbWritePhase::Detach {
            let failure = UsbWriteFailure {
                phase,
                kind: UsbWriteFailureKind::QueueClosed,
            };
            if let Some(acknowledgement) = request.acknowledgement {
                let _ = acknowledgement.send(Err(failure));
            }
            online.store(false, Ordering::Release);
            return UsbWriterExit::Failed(
                "non-detach write followed an ambiguous USB init failure".into(),
            );
        }
        debug_assert!(
            !request.await_terminal_detach_on_failure || phase == UsbWritePhase::Initialise
        );
        let await_terminal_detach_on_failure = request.await_terminal_detach_on_failure;
        let result = if request
            .packet
            .as_ref()
            .and_then(|packet| packet.gate.as_ref())
            .is_some_and(|gate| !gate.take_permit())
        {
            Err(UsbWriteFailure {
                phase,
                kind: UsbWriteFailureKind::AdmissionClosed,
            })
        } else {
            write_request(&mut backend, &request, default_timeout)
        };
        // write_request publishes known complete packet writes even if the
        // async waiter disappeared or its deadline elapsed. This is USB
        // completion, never proof of RF TX or recipient delivery.
        if let Some(acknowledgement) = request.acknowledgement {
            let _ = acknowledgement.send(result.clone());
        }
        if let Err(failure) = result {
            online.store(false, Ordering::Release);
            if await_terminal_detach_on_failure {
                terminal_detach_only = true;
                continue;
            }
            return UsbWriterExit::Failed(failure.to_string());
        }
        if phase == UsbWritePhase::Detach {
            return UsbWriterExit::Detached;
        }
    }
    UsbWriterExit::Stopped
}

fn send_usb_read_chunk(sender: &mpsc::Sender<UsbIoEvent>, bytes: Vec<u8>) -> bool {
    sender.blocking_send(UsbIoEvent::Read(bytes)).is_ok()
}

/// One-shot receive-side barrier used only around strict Init admission.
///
/// A pause is acknowledged only after the reader observes an idle physical
/// read. Every completed pre-boundary data read is therefore enqueued first,
/// and continuous traffic fails the bounded barrier instead of being mistaken
/// for fresh post-init evidence.
struct UsbReaderBoundary {
    pause_requested: AtomicBool,
    paused_after_idle: AtomicBool,
}

impl UsbReaderBoundary {
    fn new() -> Self {
        Self {
            pause_requested: AtomicBool::new(false),
            paused_after_idle: AtomicBool::new(false),
        }
    }

    fn request_pause(&self) {
        self.paused_after_idle.store(false, Ordering::Release);
        self.pause_requested.store(true, Ordering::Release);
    }

    fn is_paused_after_idle(&self) -> bool {
        self.paused_after_idle.load(Ordering::Acquire)
    }

    fn resume(&self) {
        self.pause_requested.store(false, Ordering::Release);
    }

    fn pause_after_idle_if_requested(&self, running: &AtomicBool) {
        if !self.pause_requested.load(Ordering::Acquire) {
            return;
        }
        self.paused_after_idle.store(true, Ordering::Release);
        while self.pause_requested.load(Ordering::Acquire) && running.load(Ordering::Acquire) {
            std::thread::sleep(USB_READER_BOUNDARY_POLL_INTERVAL);
        }
        self.paused_after_idle.store(false, Ordering::Release);
    }
}

fn run_usb_reader<R>(
    mut backend: R,
    event_tx: mpsc::Sender<UsbIoEvent>,
    running: Arc<AtomicBool>,
    online: Arc<AtomicBool>,
    boundary: Arc<UsbReaderBoundary>,
) -> UsbReaderExit
where
    R: UsbReaderBackend,
{
    while running.load(Ordering::Acquire) {
        match backend.read() {
            Ok(UsbReadResult::Data(bytes)) => {
                // A backend read that has already completed owns a real chunk.
                // Preserve it ahead of Reader exit even if writer failure has
                // just cancelled the next read iteration.
                if !bytes.is_empty() && !send_usb_read_chunk(&event_tx, bytes) {
                    return if running.load(Ordering::Acquire) {
                        UsbReaderExit::ConsumerClosed
                    } else {
                        UsbReaderExit::Stopped
                    };
                }
            }
            // Android bulkTransfer uses -1 for an ordinary finite read
            // timeout. The adapter maps every non-positive count here.
            Ok(UsbReadResult::Idle) => boundary.pause_after_idle_if_requested(&running),
            Err(error) => {
                online.store(false, Ordering::Release);
                return UsbReaderExit::Failed(error);
            }
        }
    }
    UsbReaderExit::Stopped
}

#[derive(Clone)]
pub(crate) struct UsbWriterHandle {
    queue: UsbWriteQueue,
}

impl UsbWriterHandle {
    pub(crate) async fn request_before(
        &self,
        phase: UsbWritePhase,
        bytes: Vec<u8>,
        timeout: Duration,
    ) -> Result<(), UsbWriteFailure> {
        self.request_before_with_failure_policy(phase, bytes, timeout, false)
            .await
    }

    async fn request_initialise_before_terminal_detach(
        &self,
        bytes: Vec<u8>,
        timeout: Duration,
    ) -> Result<(), UsbWriteFailure> {
        self.request_before_with_failure_policy(UsbWritePhase::Initialise, bytes, timeout, true)
            .await
    }

    async fn request_before_with_failure_policy(
        &self,
        phase: UsbWritePhase,
        bytes: Vec<u8>,
        timeout: Duration,
        await_terminal_detach_on_failure: bool,
    ) -> Result<(), UsbWriteFailure> {
        let deadline = Instant::now() + timeout;
        let (acknowledgement, result) = oneshot::channel();
        tokio::time::timeout_at(
            tokio::time::Instant::from_std(deadline),
            self.queue.enqueue_with_failure_policy(
                phase,
                bytes,
                Some(deadline),
                Some(acknowledgement),
                await_terminal_detach_on_failure,
                None,
            ),
        )
        .await
        .map_err(|_| UsbWriteFailure {
            phase,
            kind: UsbWriteFailureKind::DeadlineElapsed,
        })??;
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(UsbWriteFailure {
                phase,
                kind: UsbWriteFailureKind::DeadlineElapsed,
            });
        }
        tokio::time::timeout(remaining, result)
            .await
            .map_err(|_| UsbWriteFailure {
                phase,
                kind: UsbWriteFailureKind::DeadlineElapsed,
            })?
            .map_err(|_| UsbWriteFailure {
                phase,
                kind: UsbWriteFailureKind::AcknowledgementDropped,
            })?
    }

    #[cfg(test)]
    async fn queue_packet_and_account(
        &self,
        bytes: Vec<u8>,
        transmitted_bytes: &Arc<AtomicU64>,
    ) -> Result<oneshot::Receiver<Result<(), UsbWriteFailure>>, UsbWriteFailure> {
        let length = bytes.len() as u64;
        self.queue_packet(
            bytes,
            length,
            transmitted_bytes.clone(),
            None,
            None,
            Arc::new(AtomicBool::new(false)),
        )
        .await
    }

    async fn queue_packet(
        &self,
        bytes: Vec<u8>,
        payload_len: u64,
        transmitted_bytes: Arc<AtomicU64>,
        gate: Option<Arc<UsbTxGate>>,
        deadline: Option<Instant>,
        completed: Arc<AtomicBool>,
    ) -> Result<oneshot::Receiver<Result<(), UsbWriteFailure>>, UsbWriteFailure> {
        let (acknowledgement, result) = oneshot::channel();
        self.queue
            .enqueue_with_failure_policy(
                UsbWritePhase::Packet,
                bytes,
                deadline,
                Some(acknowledgement),
                false,
                Some(UsbPacketWrite {
                    transmitted_bytes,
                    payload_len,
                    gate,
                    completed,
                }),
            )
            .await?;
        Ok(result)
    }

    async fn write_application_packet(
        &self,
        payload: &Bytes,
        transmitted_bytes: Arc<AtomicU64>,
        gate: Arc<UsbTxGate>,
        completed: Arc<AtomicBool>,
    ) -> Result<(), UsbWriteFailure> {
        // One absolute bound includes queue admission, all short transfers and
        // the completion acknowledgement. A timed-out generation must be joined
        // before its retained logical payload can be offered to another writer.
        let deadline = Instant::now() + USB_PACKET_WRITE_DEADLINE;
        tokio::time::timeout(USB_PACKET_WRITE_DEADLINE, async {
            self.queue_packet(
                kiss::frame(payload),
                payload.len() as u64,
                transmitted_bytes,
                Some(gate),
                Some(deadline),
                completed,
            )
            .await?
            .await
            .map_err(|_| UsbWriteFailure {
                phase: UsbWritePhase::Packet,
                kind: UsbWriteFailureKind::AcknowledgementDropped,
            })?
        })
        .await
        .map_err(|_| UsbWriteFailure {
            phase: UsbWritePhase::Packet,
            kind: UsbWriteFailureKind::DeadlineElapsed,
        })?
    }
}

/// Complete the two acknowledged RNode startup phases in strict wire order.
///
/// Each phase gets its own queue-to-transfer deadline. These are control
/// writes, so they intentionally bypass application-payload accounting.
pub(crate) async fn run_usb_rnode_startup<O: UsbConnectionLifecycle>(
    usb: &mut OwnedUsbIo<O>,
    target: RNodeProtocolTarget,
    detect_bytes: Vec<u8>,
    init_bytes: Vec<u8>,
    phase_timeout: Duration,
) -> Result<RNodeProtocolState, UsbWriteFailure> {
    usb.writer
        .request_before(UsbWritePhase::Detect, detect_bytes, phase_timeout)
        .await?;

    // Close the same pre-init freshness boundary used by strict capability
    // admission, without making ROM availability a normal-startup requirement.
    // Preserve only detect/firmware evidence; queued RF echoes, READY permits,
    // DATA and partial framing cannot establish post-init operational readiness.
    let mut protocol = RNodeProtocolState::new(target);
    let mut deframer = kiss::RawKissDeframer::new();
    let mut observe = |event| -> Result<(), UsbWriteFailure> {
        let UsbIoEvent::Read(bytes) = event else {
            return Err(UsbWriteFailure {
                phase: UsbWritePhase::Detect,
                kind: UsbWriteFailureKind::QueueClosed,
            });
        };
        for (command, frame) in deframer.feed(&bytes) {
            if matches!(command, rnode::CMD_DETECT | rnode::CMD_FW_VERSION) {
                protocol.apply_frame(command, &frame);
            }
        }
        Ok(())
    };
    usb.request_reader_boundary();
    let deadline = tokio::time::Instant::now() + phase_timeout;
    while !usb.reader_boundary_reached() {
        tokio::select! {
            biased;
            _ = tokio::time::sleep_until(deadline) => {
                return Err(UsbWriteFailure { phase: UsbWritePhase::Detect,
                    kind: UsbWriteFailureKind::DeadlineElapsed });
            }
            event = usb.events.recv() => {
                observe(event.ok_or(UsbWriteFailure { phase: UsbWritePhase::Detect,
                    kind: UsbWriteFailureKind::QueueClosed })?)?;
            }
            _ = tokio::time::sleep(USB_READER_BOUNDARY_POLL_INTERVAL) => {}
        }
    }
    while let Ok(event) = usb.events.try_recv() {
        observe(event)?;
    }
    usb.writer
        .request_initialise_before_terminal_detach(init_bytes, phase_timeout)
        .await?;
    usb.resume_reader();
    Ok(protocol)
}

/// Successful strict startup evidence retained for the active USB session.
#[cfg_attr(not(target_os = "android"), allow(dead_code))]
pub(crate) struct UsbRNodeCapabilityAdmission {
    pub(crate) protocol_state: RNodeProtocolState,
    pub(crate) admission: RNodeRadioAdmission,
}

/// Failure classes from strict USB startup before an interface is published.
///
/// Capability failures remain typed for the options-aware public API. Worker
/// and acknowledged-write failures remain transport/interface failures.
#[derive(Debug)]
#[cfg_attr(not(target_os = "android"), allow(dead_code))]
pub(crate) enum UsbRNodeCapabilityStartupError {
    Write(UsbWriteFailure),
    Initialise(UsbWriteFailure),
    Capability(RNodeCapabilityAdmissionError),
    Transport(String),
}

fn observe_usb_capability_event(
    preflight: &mut RNodeCapabilityPreflight,
    event: UsbIoEvent,
) -> Result<Option<RNodeRadioAdmission>, UsbRNodeCapabilityStartupError> {
    match event {
        UsbIoEvent::Read(bytes) => preflight
            .observe_read(&bytes)
            .map_err(UsbRNodeCapabilityStartupError::Capability),
        UsbIoEvent::Writer(exit) => Err(UsbRNodeCapabilityStartupError::Transport(format!(
            "Android USB capability writer ended: {exit:?}"
        ))),
        UsbIoEvent::Reader(exit) => Err(UsbRNodeCapabilityStartupError::Transport(format!(
            "Android USB capability reader ended: {exit:?}"
        ))),
    }
}

/// Run capability admission on the already-owned USB session and event stream.
///
/// The strict wire order is Detect, one ROM_READ(0), bounded response
/// consumption, and only then Init. Reads are consumed from `usb.events`, so
/// there is no second reader and no ownership race. All preflight CMD_DATA and
/// partial KISS state are discarded by the shared preflight before this
/// function returns.
pub(crate) async fn run_usb_rnode_capability_startup<O>(
    usb: &mut OwnedUsbIo<O>,
    settings: RNodeRadioSettings,
    detect_bytes: Vec<u8>,
    init_bytes: Vec<u8>,
    phase_timeout: Duration,
    response_timeout: Duration,
) -> Result<UsbRNodeCapabilityAdmission, UsbRNodeCapabilityStartupError>
where
    O: UsbConnectionLifecycle,
{
    usb.writer
        .request_before(UsbWritePhase::Detect, detect_bytes, phase_timeout)
        .await
        .map_err(UsbRNodeCapabilityStartupError::Write)?;
    usb.writer
        .request_before(
            UsbWritePhase::Capability,
            crate::rnode_capability_preflight::build_rnode_capability_request(),
            phase_timeout,
        )
        .await
        .map_err(UsbRNodeCapabilityStartupError::Write)?;

    let deadline = tokio::time::Instant::now() + response_timeout;
    let mut preflight = RNodeCapabilityPreflight::new(settings);
    let admission = loop {
        let event = tokio::time::timeout_at(deadline, usb.events.recv())
            .await
            .map_err(|_| {
                UsbRNodeCapabilityStartupError::Capability(
                    RNodeCapabilityAdmissionError::ResponseTimedOut,
                )
            })?
            .ok_or_else(|| {
                UsbRNodeCapabilityStartupError::Transport(
                    "Android USB capability event stream closed".into(),
                )
            })?;

        if let Some(admission) = observe_usb_capability_event(&mut preflight, event)? {
            break admission;
        }
    };

    // Stop the sole reader only after it has drained every immediately
    // available pre-init physical read and observed an idle read. Consume the
    // ordered event tail while waiting so a full bounded queue cannot deadlock
    // the reader before it acknowledges the boundary.
    usb.request_reader_boundary();
    let boundary_deadline = tokio::time::Instant::now() + phase_timeout;
    while !usb.reader_boundary_reached() {
        if tokio::time::Instant::now() >= boundary_deadline {
            return Err(UsbRNodeCapabilityStartupError::Transport(
                "Android USB capability reader boundary timed out".into(),
            ));
        }
        tokio::select! {
            biased;
            event = usb.events.recv() => {
                let event = event.ok_or_else(|| {
                    UsbRNodeCapabilityStartupError::Transport(
                        "Android USB capability event stream closed at reader boundary".into(),
                    )
                })?;
                let _ = observe_usb_capability_event(&mut preflight, event)?;
            }
            _ = tokio::time::sleep(USB_READER_BOUNDARY_POLL_INTERVAL) => {}
        }
    }

    // The reader publishes `paused_after_idle` only after its last completed
    // pre-init read is enqueued. No producer can add another Read until resume,
    // so this finite drain closes the queue-side freshness race.
    loop {
        match usb.events.try_recv() {
            Ok(event) => {
                let _ = observe_usb_capability_event(&mut preflight, event)?;
            }
            Err(mpsc::error::TryRecvError::Empty) => break,
            Err(mpsc::error::TryRecvError::Disconnected) => {
                return Err(UsbRNodeCapabilityStartupError::Transport(
                    "Android USB capability event stream closed at reader boundary".into(),
                ));
            }
        }
    }

    let init_result = usb
        .writer
        .request_initialise_before_terminal_detach(init_bytes, phase_timeout)
        .await;
    match init_result {
        Ok(()) => usb.resume_reader(),
        Err(error) => return Err(UsbRNodeCapabilityStartupError::Initialise(error)),
    }

    Ok(UsbRNodeCapabilityAdmission {
        protocol_state: preflight.into_protocol_state(),
        admission,
    })
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum UsbTxPumpExit {
    StopRequested,
    ApplicationClosed,
    ReadinessTimedOut,
    WriterRejected(UsbWriteFailure),
}

pub(crate) struct UsbApplicationQueue {
    receiver: mpsc::Receiver<Bytes>,
    pending: Option<UsbPendingPacket>,
}

struct UsbPendingPacket {
    payload: Bytes,
    station_id: bool,
    completed: Arc<AtomicBool>,
}

impl UsbPendingPacket {
    fn new(payload: Bytes, station_id: bool) -> Self {
        Self {
            payload,
            station_id,
            completed: Arc::new(AtomicBool::new(false)),
        }
    }
}

impl UsbApplicationQueue {
    pub(crate) fn new(receiver: mpsc::Receiver<Bytes>) -> Self {
        Self {
            receiver,
            pending: None,
        }
    }
}

struct UsbTxPumpGateGuard(Arc<UsbTxGate>);

impl Drop for UsbTxPumpGateGuard {
    fn drop(&mut self) {
        self.0.close();
    }
}

/// Independent application-to-USB pump. Inbound transport backpressure cannot
/// stall writer admission, and a full writer queue cannot stall inbound
/// forwarding in the driver task.
pub(crate) async fn run_usb_tx_pump(
    application_rx: Arc<tokio::sync::Mutex<UsbApplicationQueue>>,
    writer: UsbWriterHandle,
    transmitted_bytes: Arc<AtomicU64>,
    beacon: Option<(Duration, Bytes)>,
    gate: Arc<UsbTxGate>,
    mut stop: oneshot::Receiver<()>,
) -> UsbTxPumpExit {
    // A fresh physical USB generation borrows the same application queue.
    // The lock is released when that generation's pump exits, preserving the
    // stable InterfaceHandle across reconnects without duplicating queues.
    let _gate_guard = UsbTxPumpGateGuard(gate.clone());
    let mut application_rx = tokio::select! {
        biased;
        _ = &mut stop => return UsbTxPumpExit::StopRequested,
        queue = application_rx.lock() => queue,
    };
    let mut first_tx: Option<tokio::time::Instant> = None;
    loop {
        if application_rx
            .pending
            .as_ref()
            .is_some_and(|packet| packet.completed.load(Ordering::Acquire))
        {
            // A cancelled waiter may have missed a later positive physical
            // completion. Reconnects reach here only after old workers join;
            // incomplete/unknown writes keep their original payload instead.
            let packet = application_rx.pending.take().expect("completed USB packet");
            if packet.station_id {
                first_tx = None;
            } else if first_tx.is_none() {
                first_tx = Some(tokio::time::Instant::now());
            }
        }
        if application_rx.pending.is_none()
            && application_rx.receiver.is_closed()
            && application_rx.receiver.is_empty()
        {
            return UsbTxPumpExit::ApplicationClosed;
        }
        let changed = gate.changed.notified();
        let readiness_deadline = gate.readiness_deadline();
        if !gate.can_send() {
            tokio::select! {
                biased;
                _ = &mut stop => return UsbTxPumpExit::StopRequested,
                // Invalid-frame notifications cannot starve this deadline.
                _ = async {
                    if let Some(deadline) = readiness_deadline {
                        tokio::time::sleep_until(deadline).await;
                    } else {
                        std::future::pending::<()>().await;
                    }
                } => {
                    // Readiness may have recovered since the timer snapshot;
                    // flow-permission waiting alone has no protocol timeout.
                    if gate.readiness_expired() {
                        return UsbTxPumpExit::ReadinessTimedOut;
                    }
                }
                _ = changed => {},
            };
            continue;
        }

        if application_rx.pending.is_none() {
            // A due beacon follows an already-pending application packet but
            // does not starve behind continuous later application traffic.
            if let Some((interval, ref callsign)) = beacon {
                if first_tx.is_some_and(|started| started.elapsed() >= interval) {
                    application_rx.pending = Some(UsbPendingPacket::new(callsign.clone(), true));
                }
            }
            if application_rx.pending.is_none() {
                let payload = tokio::select! {
                    biased;
                    _ = &mut stop => return UsbTxPumpExit::StopRequested,
                    _ = changed => continue,
                    payload = application_rx.receiver.recv() => payload,
                    _ = tokio::time::sleep(Duration::from_secs(1)), if first_tx.is_some() => continue,
                };
                let Some(payload) = payload else {
                    return UsbTxPumpExit::ApplicationClosed;
                };
                application_rx.pending = Some(UsbPendingPacket::new(payload, false));
                continue;
            }
        }

        let packet = application_rx.pending.as_ref().expect("pending USB packet");
        let written = tokio::select! {
            biased;
            _ = &mut stop => return UsbTxPumpExit::StopRequested,
            result = writer.write_application_packet(
                &packet.payload, transmitted_bytes.clone(), gate.clone(), packet.completed.clone()
            ) => result,
        };
        if let Err(error) = written {
            return UsbTxPumpExit::WriterRejected(error);
        }
        // The next iteration retires the positive completion token. Stop,
        // rejected admission and partial/unknown writes retain their payload;
        // the next generation cannot borrow it until physical workers join.
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum UsbJoinOutcome<T> {
    Joined(T),
    JoinFailed(String),
    NonQuiesced,
}

impl<T> UsbJoinOutcome<T> {
    fn quiesced(&self) -> bool {
        !matches!(self, Self::NonQuiesced)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum UsbCleanupDisposition {
    Released,
    Quarantined,
}

#[derive(Clone, Debug)]
pub(crate) struct UsbShutdownReport {
    pub(crate) detach: Option<Result<(), UsbWriteFailure>>,
    pub(crate) writer: UsbJoinOutcome<UsbWriterExit>,
    pub(crate) reader: UsbJoinOutcome<UsbReaderExit>,
    pub(crate) release_interface: Option<Result<(), String>>,
    pub(crate) close_connection: Option<Result<(), String>>,
    pub(crate) disposition: UsbCleanupDisposition,
}

impl UsbShutdownReport {
    pub(crate) fn is_quarantined(&self) -> bool {
        self.disposition == UsbCleanupDisposition::Quarantined
    }

    pub(crate) fn as_result(&self) -> Result<(), String> {
        let mut failures = Vec::new();
        if let Some(Err(error)) = &self.detach {
            failures.push(error.to_string());
        }
        match &self.writer {
            UsbJoinOutcome::Joined(UsbWriterExit::Failed(error)) => {
                failures.push(format!("writer: {error}"));
            }
            UsbJoinOutcome::Joined(_) => {}
            UsbJoinOutcome::JoinFailed(error) => failures.push(format!("writer join: {error}")),
            UsbJoinOutcome::NonQuiesced => failures.push("writer did not quiesce".into()),
        }
        match &self.reader {
            UsbJoinOutcome::Joined(UsbReaderExit::Failed(error)) => {
                failures.push(format!("reader: {error}"));
            }
            UsbJoinOutcome::Joined(_) => {}
            UsbJoinOutcome::JoinFailed(error) => failures.push(format!("reader join: {error}")),
            UsbJoinOutcome::NonQuiesced => failures.push("reader did not quiesce".into()),
        }
        if let Some(Err(error)) = &self.release_interface {
            failures.push(format!("releaseInterface: {error}"));
        }
        if let Some(Err(error)) = &self.close_connection {
            failures.push(format!("close: {error}"));
        }
        if self.disposition == UsbCleanupDisposition::Quarantined {
            failures.push("USB ownership quarantined because closure was unproven".into());
        }
        if failures.is_empty() {
            Ok(())
        } else {
            Err(failures.join("; "))
        }
    }
}

pub(crate) struct UsbShutdown {
    pub(crate) report: UsbShutdownReport,
}

pub(crate) struct OwnedUsbIo<O: UsbConnectionLifecycle> {
    pub(crate) writer: UsbWriterHandle,
    writer_task: Option<JoinHandle<UsbWriterExit>>,
    reader_task: Option<JoinHandle<UsbReaderExit>>,
    pub(crate) events: mpsc::Receiver<UsbIoEvent>,
    running: Arc<AtomicBool>,
    online: Arc<AtomicBool>,
    reader_boundary: Arc<UsbReaderBoundary>,
    owner: Option<O>,
}

pub(crate) fn spawn_owned_usb_io<W, R, O>(
    writer_backend: W,
    reader_backend: R,
    owner: O,
    online: Arc<AtomicBool>,
    write_queue_capacity: usize,
    read_queue_capacity: usize,
    default_write_timeout: Duration,
) -> OwnedUsbIo<O>
where
    W: UsbWriterBackend,
    R: UsbReaderBackend,
    O: UsbConnectionLifecycle,
{
    let running = Arc::new(AtomicBool::new(true));
    let reader_boundary = Arc::new(UsbReaderBoundary::new());
    let queue = UsbWriteQueue::new(write_queue_capacity);
    let (event_tx, events) = mpsc::channel(read_queue_capacity.max(1));

    let writer_running = running.clone();
    let writer_online = online.clone();
    let writer_events = event_tx.clone();
    let writer_queue = queue.clone();
    let writer_task = tokio::task::spawn_blocking(move || {
        let exit = run_usb_writer(
            writer_backend,
            writer_queue,
            writer_running,
            writer_online,
            default_write_timeout,
        );
        let _ = writer_events.blocking_send(UsbIoEvent::Writer(exit.clone()));
        exit
    });

    let reader_running = running.clone();
    let reader_online = online.clone();
    let reader_boundary_task = reader_boundary.clone();
    let reader_task = tokio::task::spawn_blocking(move || {
        let exit = run_usb_reader(
            reader_backend,
            event_tx.clone(),
            reader_running,
            reader_online,
            reader_boundary_task,
        );
        let _ = event_tx.blocking_send(UsbIoEvent::Reader(exit.clone()));
        exit
    });

    OwnedUsbIo {
        writer: UsbWriterHandle { queue },
        writer_task: Some(writer_task),
        reader_task: Some(reader_task),
        events,
        running,
        online,
        reader_boundary,
        owner: Some(owner),
    }
}

fn observe_worker_joins(
    writer_task: Option<JoinHandle<UsbWriterExit>>,
    reader_task: Option<JoinHandle<UsbReaderExit>>,
) {
    if let Ok(runtime) = tokio::runtime::Handle::try_current() {
        runtime.spawn(async move {
            match (writer_task, reader_task) {
                (Some(writer_task), Some(reader_task)) => {
                    let _ = tokio::join!(writer_task, reader_task);
                }
                (Some(writer_task), None) => {
                    let _ = writer_task.await;
                }
                (None, Some(reader_task)) => {
                    let _ = reader_task.await;
                }
                (None, None) => {}
            }
        });
    }
}

impl<O> OwnedUsbIo<O>
where
    O: UsbConnectionLifecycle,
{
    /// Stop write admission and ask both blocking workers to leave without
    /// closing the ordered event receiver. The driver can therefore consume
    /// the finite reader tail before ownership cleanup.
    pub(crate) fn request_worker_stop(&self) {
        self.running.store(false, Ordering::Release);
        self.online.store(false, Ordering::Release);
        self.reader_boundary.resume();
        self.writer.queue.cancel_and_wake();
    }

    fn request_reader_boundary(&self) {
        self.reader_boundary.request_pause();
    }

    fn reader_boundary_reached(&self) -> bool {
        self.reader_boundary.is_paused_after_idle()
    }

    fn resume_reader(&self) {
        self.reader_boundary.resume();
    }
}

impl<O> Drop for OwnedUsbIo<O>
where
    O: UsbConnectionLifecycle,
{
    fn drop(&mut self) {
        let Some(owner) = self.owner.take() else {
            return;
        };

        // Cancellation cannot synchronously await from Drop. Atomically stop
        // admissions, wake both workers, and quarantine the physical owner
        // before scheduling detached join observation. No release/close is
        // attempted from this fallback path.
        self.request_worker_stop();
        self.events.close();
        owner.retain_quarantined();
        observe_worker_joins(self.writer_task.take(), self.reader_task.take());
    }
}

async fn join_before<T>(
    task: &mut Option<JoinHandle<T>>,
    deadline: tokio::time::Instant,
) -> UsbJoinOutcome<T> {
    let Some(join_handle) = task.as_mut() else {
        return UsbJoinOutcome::JoinFailed("worker handle missing".into());
    };
    match tokio::time::timeout_at(deadline, join_handle).await {
        Ok(Ok(exit)) => {
            let _ = task.take();
            UsbJoinOutcome::Joined(exit)
        }
        Ok(Err(error)) => {
            let _ = task.take();
            UsbJoinOutcome::JoinFailed(error.to_string())
        }
        Err(_) => UsbJoinOutcome::NonQuiesced,
    }
}

impl<O> OwnedUsbIo<O>
where
    O: UsbConnectionLifecycle,
{
    pub(crate) async fn shutdown(
        mut self,
        detach_bytes: Option<Vec<u8>>,
        detach_deadline: Duration,
        worker_join_deadline: Duration,
    ) -> UsbShutdown {
        let detach = if let Some(detach_bytes) = detach_bytes {
            let deadline = Instant::now() + detach_deadline;
            match self.writer.queue.begin_detach(detach_bytes, deadline) {
                Ok(acknowledgement) => {
                    let remaining = deadline.saturating_duration_since(Instant::now());
                    Some(if remaining.is_zero() {
                        Err(UsbWriteFailure {
                            phase: UsbWritePhase::Detach,
                            kind: UsbWriteFailureKind::DeadlineElapsed,
                        })
                    } else {
                        tokio::time::timeout(remaining, acknowledgement)
                            .await
                            .map_err(|_| UsbWriteFailure {
                                phase: UsbWritePhase::Detach,
                                kind: UsbWriteFailureKind::DeadlineElapsed,
                            })
                            .and_then(|result| {
                                result.map_err(|_| UsbWriteFailure {
                                    phase: UsbWritePhase::Detach,
                                    kind: UsbWriteFailureKind::AcknowledgementDropped,
                                })
                            })
                            .and_then(std::convert::identity)
                    })
                }
                Err(error) => Some(Err(error)),
            }
        } else {
            None
        };

        // Wake/cancel is always before either join. No Java close operation is
        // used to interrupt an in-flight AOSP bulkTransfer.
        self.request_worker_stop();
        self.events.close();

        let join_deadline = tokio::time::Instant::now() + worker_join_deadline;
        let writer = join_before(&mut self.writer_task, join_deadline).await;
        let reader = join_before(&mut self.reader_task, join_deadline).await;

        if !writer.quiesced() || !reader.quiesced() {
            if let Some(owner) = self.owner.take() {
                owner.retain_quarantined();
            }
            observe_worker_joins(self.writer_task.take(), self.reader_task.take());
            return UsbShutdown {
                report: UsbShutdownReport {
                    detach,
                    writer,
                    reader,
                    release_interface: None,
                    close_connection: None,
                    disposition: UsbCleanupDisposition::Quarantined,
                },
            };
        }

        let owner = self.owner.take();
        let cleanup = match owner {
            // This contains only releaseInterface/close (no bulk transfer).
            // Keep it synchronous so cancellation cannot detach cleanup or
            // lose the owner between the two Java calls.
            Some(owner) => owner.release_and_close(),
            None => {
                return UsbShutdown {
                    report: UsbShutdownReport {
                        detach,
                        writer,
                        reader,
                        release_interface: Some(Err("USB owner missing during cleanup".into())),
                        close_connection: Some(Err("USB owner missing during cleanup".into())),
                        disposition: UsbCleanupDisposition::Released,
                    },
                };
            }
        };
        let (release_interface, close_connection) = match cleanup {
            UsbConnectionCleanup::Closed { release_interface } => {
                (Some(release_interface), Some(Ok(())))
            }
            UsbConnectionCleanup::Unclosed {
                owner,
                release_interface,
                close_connection,
            } => {
                owner.retain_quarantined();
                return UsbShutdown {
                    report: UsbShutdownReport {
                        detach,
                        writer,
                        reader,
                        release_interface: Some(release_interface),
                        close_connection: Some(Err(close_connection)),
                        disposition: UsbCleanupDisposition::Quarantined,
                    },
                };
            }
        };

        UsbShutdown {
            report: UsbShutdownReport {
                detach,
                writer,
                reader,
                release_interface,
                close_connection,
                disposition: UsbCleanupDisposition::Released,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn usb_candidate(
        device_name: &str,
        vendor_id: u16,
        product_id: u16,
        serial_number: Option<&str>,
        has_permission: bool,
    ) -> UsbDeviceCandidate {
        UsbDeviceCandidate {
            device_name: device_name.into(),
            vendor_id,
            product_id,
            serial_number: serial_number.map(str::to_string),
            has_permission,
        }
    }

    #[test]
    fn legacy_usb_path_learns_stable_identity_and_survives_path_change() {
        let legacy = UsbDeviceSelector {
            legacy_device_name: "/dev/bus/usb/001/002".into(),
            vendor_id: None,
            product_id: None,
            serial_number: None,
        };
        let first = usb_candidate("/dev/bus/usb/001/002", 0x303a, 0x1001, Some("ABC"), true);
        let (_, learned) = resolve_usb_device(&legacy, &[first]).expect("legacy first generation");
        let moved = usb_candidate("/dev/bus/usb/001/009", 0x303a, 0x1001, Some("ABC"), true);
        let (resolved, _) =
            resolve_usb_device(&learned, &[moved]).expect("stable selector after replug");
        assert_eq!(resolved.device_name, "/dev/bus/usb/001/009");
    }

    #[test]
    fn usb_selector_fails_closed_on_ambiguity_and_permission_loss() {
        let selector = UsbDeviceSelector {
            legacy_device_name: "old".into(),
            vendor_id: Some(0x303a),
            product_id: Some(0x1001),
            serial_number: None,
        };
        let a = usb_candidate("a", 0x303a, 0x1001, None, true);
        let b = usb_candidate("b", 0x303a, 0x1001, None, true);
        assert_eq!(
            resolve_usb_device(&selector, &[a.clone(), b]),
            Err(UsbDeviceResolutionError::Ambiguous { matches: 2 })
        );
        let denied = UsbDeviceCandidate {
            has_permission: false,
            ..a
        };
        assert_eq!(
            resolve_usb_device(&selector, &[denied]),
            Err(UsbDeviceResolutionError::PermissionRequired {
                device_name: "a".into()
            })
        );

        let serial_selector = UsbDeviceSelector {
            serial_number: Some("ABC".into()),
            ..selector
        };
        let moved_denied = usb_candidate("moved", 0x303a, 0x1001, None, false);
        assert_eq!(
            resolve_usb_device(&serial_selector, &[moved_denied]),
            Err(UsbDeviceResolutionError::PermissionRequired {
                device_name: "moved".into()
            })
        );
        let restored = usb_candidate("moved", 0x303a, 0x1001, Some("ABC"), true);
        let (resolved, learned) = resolve_usb_device(&serial_selector, &[restored])
            .expect("restored permission confirms saved serial");
        assert_eq!(resolved.device_name, "moved");
        assert_eq!(learned.serial_number.as_deref(), Some("ABC"));
    }
    use md5::{Digest, Md5};
    use std::collections::VecDeque;
    use std::sync::atomic::AtomicUsize;

    type RecordedWriteCalls = Arc<Mutex<Vec<(Vec<u8>, Duration)>>>;

    #[derive(Clone)]
    struct ScriptedWriter {
        script: Arc<Mutex<VecDeque<Result<i32, UsbTransferError>>>>,
        calls: RecordedWriteCalls,
        events: Option<Arc<Mutex<Vec<&'static str>>>>,
    }

    impl ScriptedWriter {
        fn new(script: impl IntoIterator<Item = Result<i32, UsbTransferError>>) -> Self {
            Self {
                script: Arc::new(Mutex::new(script.into_iter().collect())),
                calls: Arc::new(Mutex::new(Vec::new())),
                events: None,
            }
        }
    }

    impl UsbWriterBackend for ScriptedWriter {
        fn transfer(&mut self, bytes: &[u8], timeout: Duration) -> Result<i32, UsbTransferError> {
            self.calls
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push((bytes.to_vec(), timeout));
            self.script
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .pop_front()
                .unwrap_or(Ok(bytes.len() as i32))
        }
    }

    impl Drop for ScriptedWriter {
        fn drop(&mut self) {
            if let Some(events) = &self.events {
                events
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .push("writer_dropped");
            }
        }
    }

    struct GatedWriter {
        calls: RecordedWriteCalls,
        first_started: Arc<AtomicBool>,
        first_gate: Arc<(Mutex<bool>, Condvar)>,
    }

    impl UsbWriterBackend for GatedWriter {
        fn transfer(&mut self, bytes: &[u8], timeout: Duration) -> Result<i32, UsbTransferError> {
            self.calls
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push((bytes.to_vec(), timeout));
            if bytes == [0xAA] {
                self.first_started.store(true, Ordering::Release);
                let (lock, wake) = &*self.first_gate;
                let mut open = lock
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                while !*open {
                    open = wake
                        .wait(open)
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                }
            }
            Ok(bytes.len() as i32)
        }
    }

    struct IdleReader {
        polls: Arc<AtomicUsize>,
        events: Option<Arc<Mutex<Vec<&'static str>>>>,
    }

    impl UsbReaderBackend for IdleReader {
        fn read(&mut self) -> Result<UsbReadResult, String> {
            self.polls.fetch_add(1, Ordering::Relaxed);
            std::thread::sleep(Duration::from_millis(1));
            Ok(UsbReadResult::Idle)
        }
    }

    impl Drop for IdleReader {
        fn drop(&mut self) {
            if let Some(events) = &self.events {
                events
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .push("reader_dropped");
            }
        }
    }

    /// Delay a synthetic device response until both strict control writes
    /// have reached the same fake writer. This makes the test exercise the
    /// owned-session wire order instead of pre-buffering a response.
    struct CapabilityResponseReader {
        writer_calls: RecordedWriteCalls,
        responses: VecDeque<Vec<u8>>,
    }

    impl UsbReaderBackend for CapabilityResponseReader {
        fn read(&mut self) -> Result<UsbReadResult, String> {
            if self
                .writer_calls
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .len()
                < 2
            {
                std::thread::sleep(Duration::from_millis(1));
                return Ok(UsbReadResult::Idle);
            }
            if let Some(response) = self.responses.pop_front() {
                return Ok(UsbReadResult::Data(response));
            }
            std::thread::sleep(Duration::from_millis(1));
            Ok(UsbReadResult::Idle)
        }
    }

    struct RecordingOwner {
        events: Arc<Mutex<Vec<&'static str>>>,
        release_result: Result<(), String>,
    }

    impl UsbConnectionLifecycle for RecordingOwner {
        fn release_and_close(self) -> UsbConnectionCleanup<Self> {
            self.events
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push("release");
            self.events
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push("close");
            UsbConnectionCleanup::Closed {
                release_interface: self.release_result,
            }
        }

        fn retain_quarantined(self) {
            self.events
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push("quarantined");
        }
    }

    struct UnclosedOwner {
        events: Arc<Mutex<Vec<&'static str>>>,
    }

    impl UsbConnectionLifecycle for UnclosedOwner {
        fn release_and_close(self) -> UsbConnectionCleanup<Self> {
            self.events
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push("release");
            self.events
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push("close_failed");
            UsbConnectionCleanup::Unclosed {
                owner: self,
                release_interface: Ok(()),
                close_connection: "close unproven".into(),
            }
        }

        fn retain_quarantined(self) {
            self.events
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push("quarantined");
        }
    }

    fn test_io(
        writer: ScriptedWriter,
        events: Arc<Mutex<Vec<&'static str>>>,
    ) -> OwnedUsbIo<RecordingOwner> {
        spawn_owned_usb_io(
            writer,
            IdleReader {
                polls: Arc::new(AtomicUsize::new(0)),
                events: Some(events.clone()),
            },
            RecordingOwner {
                events,
                release_result: Ok(()),
            },
            Arc::new(AtomicBool::new(true)),
            8,
            8,
            Duration::from_millis(100),
        )
    }

    fn capability_test_io(
        writer: ScriptedWriter,
        response: Vec<u8>,
        events: Arc<Mutex<Vec<&'static str>>>,
    ) -> OwnedUsbIo<RecordingOwner> {
        let writer_calls = writer.calls.clone();
        spawn_owned_usb_io(
            writer,
            CapabilityResponseReader {
                writer_calls,
                responses: response.chunks(512).map(|chunk| chunk.to_vec()).collect(),
            },
            RecordingOwner {
                events,
                release_result: Ok(()),
            },
            Arc::new(AtomicBool::new(true)),
            8,
            8,
            Duration::from_millis(100),
        )
    }

    const USB_TEST_TARGET: RNodeProtocolTarget =
        RNodeProtocolTarget::new(915_000_000, 125_000, 7, 5, 17);

    fn projected_inbound() -> (UsbInboundState, rnode::RNodeDriverHandle) {
        let (mut publisher, driver) =
            rnode::new_rnode_driver_observation(rnode::RNodeTransportClass::Usb);
        publisher.connection_established();
        (
            UsbInboundState::projected(USB_TEST_TARGET, publisher),
            driver,
        )
    }

    fn ready_tx_gate(flow_control: bool) -> Arc<UsbTxGate> {
        let gate = UsbTxGate::new(flow_control, Arc::new(AtomicBool::new(false)));
        let mut protocol = RNodeProtocolState::new(USB_TEST_TARGET);
        for (command, frame) in required_protocol_frames(USB_TEST_TARGET) {
            protocol.apply_frame(command, &frame);
            gate.observe(&protocol, command, &frame);
        }
        assert!(gate.is_ready());
        gate
    }

    async fn wait_for_count(counter: &AtomicU64, expected: u64) {
        tokio::time::timeout(Duration::from_secs(1), async {
            while counter.load(Ordering::Relaxed) != expected {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("USB completed-write count did not converge");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn usb_packet_writes_require_fresh_protocol_and_configured_flow_permission() {
        for flow_control in [false, true] {
            let writer = ScriptedWriter::new([]);
            let calls = writer.calls.clone();
            let io = test_io(writer, Arc::new(Mutex::new(Vec::new())));
            let online = Arc::new(AtomicBool::new(false));
            let gate = UsbTxGate::new(flow_control, online.clone());
            let (mut inbound, _driver) = projected_inbound();
            inbound.attach_tx_gate(gate.clone());
            let (tx, rx) = mpsc::channel(2);
            let queue = Arc::new(tokio::sync::Mutex::new(UsbApplicationQueue::new(rx)));
            let counter = Arc::new(AtomicU64::new(0));
            let (stop_tx, stop_rx) = oneshot::channel();
            let pump = tokio::spawn(run_usb_tx_pump(
                queue,
                io.writer.clone(),
                counter.clone(),
                None,
                gate.clone(),
                stop_rx,
            ));
            tx.send(Bytes::from_static(&[kiss::FEND, kiss::FESC]))
                .await
                .unwrap();
            tx.send(Bytes::from_static(&[1, 2, 3])).await.unwrap();
            inbound.project_frame(rnode::CMD_READY, &[1]);
            tokio::time::sleep(Duration::from_millis(10)).await;
            assert!(!online.load(Ordering::Acquire));
            assert!(
                calls.lock().unwrap().is_empty(),
                "CMD_READY alone is not protocol Ready"
            );

            inbound.project_frame(rnode::CMD_READY, &[0]);
            let (_stop_tx, mut inbound_stop) = mpsc::channel(1);
            let (transport, _transport_rx) = mpsc::channel(1);
            let mut evidence = required_protocol_frames(USB_TEST_TARGET);
            evidence[2].1 = 100_000_000u32.to_be_bytes().to_vec();
            assert_eq!(
                forward_usb_read_chunk(
                    &mut inbound,
                    &framed_protocol_frames(evidence),
                    1,
                    &AtomicU64::new(0),
                    &transport,
                    &mut inbound_stop
                )
                .await,
                UsbInboundOutcome::Complete
            );
            assert!(
                !gate.can_send(),
                "mismatched RF evidence must not admit a packet"
            );
            inbound.project_frame(
                rnode::CMD_FREQUENCY,
                &USB_TEST_TARGET.frequency.to_be_bytes(),
            );
            assert!(online.load(Ordering::Acquire));
            if flow_control {
                tokio::time::sleep(Duration::from_millis(10)).await;
                assert_eq!(counter.load(Ordering::Relaxed), 0);
                inbound.project_frame(rnode::CMD_READY, &[1]);
                wait_for_count(&counter, 2).await;
                inbound.project_frame(rnode::CMD_READY, &[1, 1]);
                tokio::time::sleep(Duration::from_millis(10)).await;
                assert_eq!(
                    counter.load(Ordering::Relaxed),
                    2,
                    "malformed grant must not release packet two"
                );
                // Repeated valid READY=1 must replenish a consumed permit even
                // when the diagnostic reducer classifies it as NoChange.
                inbound.project_frame(rnode::CMD_READY, &[1]);
            }
            wait_for_count(&counter, 5).await;
            assert_eq!(
                calls
                    .lock()
                    .unwrap()
                    .iter()
                    .map(|(bytes, _)| bytes.clone())
                    .collect::<Vec<_>>(),
                vec![
                    kiss::frame(&[kiss::FEND, kiss::FESC]),
                    kiss::frame(&[1, 2, 3])
                ]
            );
            stop_tx.send(()).unwrap();
            assert_eq!(pump.await.unwrap(), UsbTxPumpExit::StopRequested);
            assert!(!online.load(Ordering::Acquire));
            let _ = io
                .shutdown(None, Duration::from_millis(20), Duration::from_secs(1))
                .await;
        }
    }

    #[tokio::test(start_paused = true)]
    async fn usb_absent_protocol_readiness_has_a_bounded_generation_deadline() {
        let (tx, rx) = mpsc::channel(1);
        tx.send(Bytes::from_static(b"held")).await.unwrap();
        let queue = Arc::new(tokio::sync::Mutex::new(UsbApplicationQueue::new(rx)));
        let writer = UsbWriterHandle {
            queue: UsbWriteQueue::new(1),
        };
        let gate = UsbTxGate::new(false, Arc::new(AtomicBool::new(false)));
        let counter = Arc::new(AtomicU64::new(0));
        let (_stop, stopped) = oneshot::channel();
        let pump = tokio::spawn(run_usb_tx_pump(
            queue.clone(),
            writer,
            counter.clone(),
            None,
            gate.clone(),
            stopped,
        ));
        tokio::task::yield_now().await;
        tokio::time::advance(USB_PROTOCOL_READINESS_DEADLINE + Duration::from_millis(1)).await;
        assert_eq!(pump.await.unwrap(), UsbTxPumpExit::ReadinessTimedOut);
        assert!(!gate.is_ready());
        assert_eq!(counter.load(Ordering::Relaxed), 0);
        assert_eq!(
            queue.lock().await.receiver.try_recv().unwrap(),
            Bytes::from_static(b"held")
        );
    }

    #[tokio::test(start_paused = true)]
    async fn usb_coverage_review_recovered_gate_outlives_an_already_ready_stale_timer() {
        use std::future::Future;
        use std::task::{Context, Poll, Waker};

        let (tx, rx) = mpsc::channel(1);
        tx.send(Bytes::from_static(b"held until new flow grant"))
            .await
            .unwrap();
        let queue = Arc::new(tokio::sync::Mutex::new(UsbApplicationQueue::new(rx)));
        let online = Arc::new(AtomicBool::new(false));
        let gate = UsbTxGate::new(true, online.clone());
        let (mut inbound, _driver) = projected_inbound();
        inbound.attach_tx_gate(gate.clone());
        inbound.project_frame(rnode::CMD_READY, &[0]);
        let counter = Arc::new(AtomicU64::new(0));
        let (stop_tx, stop_rx) = oneshot::channel();
        let mut pump = Box::pin(run_usb_tx_pump(
            queue.clone(),
            UsbWriterHandle {
                queue: UsbWriteQueue::new(1),
            },
            counter.clone(),
            None,
            gate.clone(),
            stop_rx,
        ));
        let mut context = Context::from_waker(Waker::noop());
        assert!(pump.as_mut().poll(&mut context).is_pending());

        // Poll the real pump ourselves so both its previously captured timer
        // and a new readiness notification are ready at the next actor turn.
        // No sleep/scheduler race decides which state this regression tests.
        tokio::time::advance(USB_PROTOCOL_READINESS_DEADLINE).await;
        for (command, frame) in required_protocol_frames(USB_TEST_TARGET) {
            inbound.project_frame(command, &frame);
        }
        assert!(gate.is_ready());
        assert!(online.load(Ordering::Acquire));
        // Recovery without a flow grant must neither write nor terminate.
        assert!(
            !gate.can_send(),
            "protocol recovery cannot invent a flow grant"
        );
        assert!(
            pump.as_mut().poll(&mut context).is_pending(),
            "an expired timer snapshot must re-check current protocol readiness"
        );
        tokio::time::advance(USB_PROTOCOL_READINESS_DEADLINE * 2).await;
        assert!(
            pump.as_mut().poll(&mut context).is_pending(),
            "flow-only waiting has no protocol readiness deadline"
        );
        assert_eq!(counter.load(Ordering::Relaxed), 0);
        stop_tx.send(()).unwrap();
        assert_eq!(
            pump.as_mut().poll(&mut context),
            Poll::Ready(UsbTxPumpExit::StopRequested)
        );
        drop(pump);
        assert!(!online.load(Ordering::Acquire));
        assert_eq!(
            queue.lock().await.receiver.try_recv().unwrap(),
            Bytes::from_static(b"held until new flow grant")
        );
    }

    #[tokio::test(start_paused = true)]
    async fn usb_coverage_review_stop_wins_simultaneous_timer_and_invalid_frame_notification() {
        use std::future::Future;
        use std::task::{Context, Poll, Waker};

        for stop_at_boundary in [false, true] {
            let (tx, rx) = mpsc::channel(1);
            tx.send(Bytes::from_static(b"never admitted"))
                .await
                .unwrap();
            let queue = Arc::new(tokio::sync::Mutex::new(UsbApplicationQueue::new(rx)));
            let gate = UsbTxGate::new(false, Arc::new(AtomicBool::new(false)));
            let (mut inbound, _driver) = projected_inbound();
            inbound.attach_tx_gate(gate.clone());
            let counter = Arc::new(AtomicU64::new(0));
            let (stop_tx, stop_rx) = oneshot::channel();
            let mut pump = Box::pin(run_usb_tx_pump(
                queue.clone(),
                UsbWriterHandle {
                    queue: UsbWriteQueue::new(1),
                },
                counter.clone(),
                None,
                gate.clone(),
                stop_rx,
            ));
            let mut context = Context::from_waker(Waker::noop());
            assert!(pump.as_mut().poll(&mut context).is_pending());
            let deadline = gate.readiness_deadline().unwrap();
            tokio::time::advance(USB_PROTOCOL_READINESS_DEADLINE).await;
            inbound.project_frame(rnode::CMD_FREQUENCY, &[1]);
            assert_eq!(gate.readiness_deadline(), Some(deadline));
            if stop_at_boundary {
                stop_tx.send(()).unwrap();
            }
            let expected = if stop_at_boundary {
                UsbTxPumpExit::StopRequested
            } else {
                UsbTxPumpExit::ReadinessTimedOut
            };
            assert_eq!(pump.as_mut().poll(&mut context), Poll::Ready(expected));
            drop(pump);
            assert_eq!(counter.load(Ordering::Relaxed), 0);
            assert!(!gate.can_send());
            assert_eq!(
                queue.lock().await.receiver.try_recv().unwrap(),
                Bytes::from_static(b"never admitted")
            );
        }
    }

    #[tokio::test(start_paused = true)]
    async fn usb_readiness_recovers_after_long_idle_without_reusing_a_flow_grant() {
        for fault in [rnode::CMD_RESET, rnode::CMD_FREQUENCY] {
            let (_tx, rx) = mpsc::channel(1);
            let queue = Arc::new(tokio::sync::Mutex::new(UsbApplicationQueue::new(rx)));
            let gate = UsbTxGate::new(true, Arc::new(AtomicBool::new(false)));
            let (mut inbound, _driver) = projected_inbound();
            inbound.attach_tx_gate(gate.clone());
            for (command, frame) in required_protocol_frames(USB_TEST_TARGET) {
                inbound.project_frame(command, &frame);
            }
            assert!(gate.can_send());
            let (stop_tx, stop_rx) = oneshot::channel();
            let pump = tokio::spawn(run_usb_tx_pump(
                queue,
                UsbWriterHandle {
                    queue: UsbWriteQueue::new(1),
                },
                Arc::new(AtomicU64::new(0)),
                None,
                gate.clone(),
                stop_rx,
            ));
            tokio::task::yield_now().await;
            tokio::time::advance(Duration::from_secs(60)).await;
            let frame = if fault == rnode::CMD_RESET {
                vec![0xF8]
            } else {
                100_000_000u32.to_be_bytes().to_vec()
            };
            inbound.project_frame(fault, &frame);
            assert!(
                !gate.take_permit(),
                "readiness loss fences the writer immediately"
            );
            tokio::task::yield_now().await;
            assert!(
                !pump.is_finished(),
                "idle startup age is not a new recovery deadline"
            );
            tokio::time::advance(Duration::from_secs(5)).await;
            for (command, frame) in required_protocol_frames(USB_TEST_TARGET) {
                inbound.project_frame(command, &frame);
            }
            assert!(gate.is_ready());
            assert!(
                !gate.can_send(),
                "a pre-fault flow permit must not survive recovery"
            );
            inbound.project_frame(rnode::CMD_READY, &[1]);
            assert!(gate.can_send());
            tokio::task::yield_now().await;
            tokio::time::advance(Duration::from_secs(20)).await;
            assert!(
                !pump.is_finished(),
                "successful recovery retires its deadline"
            );
            stop_tx.send(()).unwrap();
            assert_eq!(pump.await.unwrap(), UsbTxPumpExit::StopRequested);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn usb_readiness_loss_gets_one_fresh_bounded_episode_after_idle() {
        let (_tx, rx) = mpsc::channel(1);
        let queue = Arc::new(tokio::sync::Mutex::new(UsbApplicationQueue::new(rx)));
        let gate = UsbTxGate::new(false, Arc::new(AtomicBool::new(false)));
        let (mut inbound, _driver) = projected_inbound();
        inbound.attach_tx_gate(gate.clone());
        for (command, frame) in required_protocol_frames(USB_TEST_TARGET) {
            inbound.project_frame(command, &frame);
        }
        let (_stop_tx, stop_rx) = oneshot::channel();
        let pump = tokio::spawn(run_usb_tx_pump(
            queue,
            UsbWriterHandle {
                queue: UsbWriteQueue::new(1),
            },
            Arc::new(AtomicU64::new(0)),
            None,
            gate.clone(),
            stop_rx,
        ));
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(60)).await;
        inbound.project_frame(rnode::CMD_RESET, &[0xF8]);
        let deadline = gate.readiness_deadline().unwrap();
        tokio::task::yield_now().await;
        assert!(!pump.is_finished());
        tokio::time::advance(Duration::from_secs(9)).await;
        assert!(!pump.is_finished());
        inbound.project_frame(rnode::CMD_RESET, &[0xF8]);
        inbound.project_frame(rnode::CMD_FREQUENCY, &[1]); // Malformed evidence.
        assert_eq!(gate.readiness_deadline(), Some(deadline));
        tokio::time::advance(Duration::from_secs(2)).await;
        assert_eq!(pump.await.unwrap(), UsbTxPumpExit::ReadinessTimedOut);
        assert!(!gate.can_send());
    }

    #[tokio::test(start_paused = true)]
    async fn usb_readiness_episode_expires_even_while_rx_transport_is_backpressured() {
        let (_tx, rx) = mpsc::channel(1);
        let queue = Arc::new(tokio::sync::Mutex::new(UsbApplicationQueue::new(rx)));
        let gate = UsbTxGate::new(false, Arc::new(AtomicBool::new(false)));
        let (mut inbound, _driver) = projected_inbound();
        inbound.attach_tx_gate(gate.clone());
        for (command, frame) in required_protocol_frames(USB_TEST_TARGET) {
            inbound.project_frame(command, &frame);
        }
        let (_stop_tx, stop_rx) = oneshot::channel();
        let pump = tokio::spawn(run_usb_tx_pump(
            queue,
            UsbWriterHandle {
                queue: UsbWriteQueue::new(1),
            },
            Arc::new(AtomicU64::new(0)),
            None,
            gate.clone(),
            stop_rx,
        ));
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(60)).await;
        let (transport, _transport_rx) = mpsc::channel(1);
        transport.try_send(TransportMessage::Shutdown).unwrap();
        let (_inbound_stop_tx, mut inbound_stop_rx) = mpsc::channel(1);
        let mut bytes = Vec::new();
        kiss::frame_with_command_into(rnode::CMD_RESET, &[0xF8], &mut bytes);
        kiss::frame_with_command_into(kiss::CMD_DATA, &[1, 2, 3], &mut bytes);
        let received = AtomicU64::new(0);
        let episode_start = tokio::time::Instant::now();
        tokio::time::timeout(USB_PROTOCOL_READINESS_DEADLINE * 2, async {
            tokio::select! {
                exit = pump => assert_eq!(exit.unwrap(), UsbTxPumpExit::ReadinessTimedOut),
                result = forward_usb_read_chunk(
                    &mut inbound, &bytes, 1, &received, &transport, &mut inbound_stop_rx
                ) => panic!("full transport queue cannot conclude before pump expiry: {result:?}"),
            }
        })
        .await
        .expect("readiness episode did not expire while transport was backpressured");
        assert!(episode_start.elapsed() >= USB_PROTOCOL_READINESS_DEADLINE);
        assert!(episode_start.elapsed() < USB_PROTOCOL_READINESS_DEADLINE + Duration::from_secs(1));
        assert!(!gate.can_send());
    }

    #[tokio::test(start_paused = true)]
    async fn usb_control_deadline_includes_a_full_writer_queue() {
        let writer = UsbWriterHandle {
            queue: UsbWriteQueue::new(0),
        };
        let error = writer
            .request_before(UsbWritePhase::Detect, vec![1], Duration::from_millis(20))
            .await
            .expect_err("queue pressure must not escape the control deadline");
        assert_eq!(error.kind, UsbWriteFailureKind::DeadlineElapsed);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn usb_unadmitted_pending_packet_survives_stop_and_requires_new_generation_ready() {
        let (tx, rx) = mpsc::channel(2);
        tx.send(Bytes::from_static(b"first")).await.unwrap();
        tx.send(Bytes::from_static(b"second")).await.unwrap();
        let queue = Arc::new(tokio::sync::Mutex::new(UsbApplicationQueue::new(rx)));
        let counter = Arc::new(AtomicU64::new(0));
        let old_gate = ready_tx_gate(false);
        let (stop_tx, stop_rx) = oneshot::channel();
        let pump = tokio::spawn(run_usb_tx_pump(
            queue.clone(),
            UsbWriterHandle {
                queue: UsbWriteQueue::new(0),
            },
            counter.clone(),
            None,
            old_gate.clone(),
            stop_rx,
        ));
        tokio::time::sleep(Duration::from_millis(10)).await;
        stop_tx.send(()).unwrap();
        assert_eq!(pump.await.unwrap(), UsbTxPumpExit::StopRequested);
        assert_eq!(
            queue.lock().await.pending.as_ref().unwrap().payload,
            Bytes::from_static(b"first")
        );

        let writer = ScriptedWriter::new([]);
        let calls = writer.calls.clone();
        let io = test_io(writer, Arc::new(Mutex::new(Vec::new())));
        let gate = UsbTxGate::new(false, Arc::new(AtomicBool::new(false)));
        let (stop_tx, stop_rx) = oneshot::channel();
        let pump = tokio::spawn(run_usb_tx_pump(
            queue,
            io.writer.clone(),
            counter.clone(),
            None,
            gate.clone(),
            stop_rx,
        ));
        let mut fresh = RNodeProtocolState::new(USB_TEST_TARGET);
        for (command, frame) in required_protocol_frames(USB_TEST_TARGET) {
            fresh.apply_frame(command, &frame);
            old_gate.observe(&fresh, command, &frame);
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
        assert!(
            calls.lock().unwrap().is_empty(),
            "old generation evidence must not admit retained data"
        );
        assert!(!old_gate.is_ready());
        let (mut inbound, _driver) = projected_inbound();
        inbound.attach_tx_gate(gate);
        for (command, frame) in required_protocol_frames(USB_TEST_TARGET) {
            inbound.project_frame(command, &frame);
        }
        wait_for_count(&counter, 11).await;
        assert_eq!(
            calls
                .lock()
                .unwrap()
                .iter()
                .map(|(bytes, _)| bytes.clone())
                .collect::<Vec<_>>(),
            vec![kiss::frame(b"first"), kiss::frame(b"second")]
        );
        stop_tx.send(()).unwrap();
        assert_eq!(pump.await.unwrap(), UsbTxPumpExit::StopRequested);
        let _ = io
            .shutdown(None, Duration::from_millis(20), Duration::from_secs(1))
            .await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn usb_failed_packet_write_is_not_counted_and_retains_complete_payload() {
        let io = test_io(
            ScriptedWriter::new([
                Ok(2),
                Err(UsbTransferError::Backend("test write failed".into())),
            ]),
            Arc::new(Mutex::new(Vec::new())),
        );
        let (tx, rx) = mpsc::channel(1);
        tx.send(Bytes::from_static(b"retry")).await.unwrap();
        let queue = Arc::new(tokio::sync::Mutex::new(UsbApplicationQueue::new(rx)));
        let counter = Arc::new(AtomicU64::new(0));
        let (_stop_tx, stop_rx) = oneshot::channel();
        let result = run_usb_tx_pump(
            queue.clone(),
            io.writer.clone(),
            counter.clone(),
            None,
            ready_tx_gate(false),
            stop_rx,
        )
        .await;
        assert!(matches!(result, UsbTxPumpExit::WriterRejected(_)));
        assert_eq!(counter.load(Ordering::Relaxed), 0);
        assert_eq!(
            queue.lock().await.pending.as_ref().unwrap().payload,
            Bytes::from_static(b"retry")
        );
        assert!(
            !queue
                .lock()
                .await
                .pending
                .as_ref()
                .unwrap()
                .completed
                .load(Ordering::Acquire),
            "a partial failed write cannot claim physical completion"
        );
        let report = io
            .shutdown(None, Duration::from_millis(20), Duration::from_secs(1))
            .await;
        assert_eq!(report.report.disposition, UsbCleanupDisposition::Released);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn usb_writer_checks_generation_gate_at_physical_write_boundary() {
        let io = test_io(ScriptedWriter::new([]), Arc::new(Mutex::new(Vec::new())));
        let gate = ready_tx_gate(false);
        gate.close();
        let count = Arc::new(AtomicU64::new(0));
        let error = io
            .writer
            .write_application_packet(
                &Bytes::from_static(b"stale"),
                count.clone(),
                gate,
                Arc::new(AtomicBool::new(false)),
            )
            .await
            .expect_err("closed generation must reject writer-level packet admission");
        assert_eq!(error.kind, UsbWriteFailureKind::AdmissionClosed);
        assert_eq!(count.load(Ordering::Relaxed), 0);
        let _ = io
            .shutdown(None, Duration::from_millis(20), Duration::from_secs(1))
            .await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn usb_tx_counter_waits_for_complete_physical_write_even_if_ack_is_dropped() {
        let started = Arc::new(AtomicBool::new(false));
        let write_gate = Arc::new((Mutex::new(false), Condvar::new()));
        let events = Arc::new(Mutex::new(Vec::new()));
        let io = spawn_owned_usb_io(
            GatedWriter {
                calls: Arc::new(Mutex::new(Vec::new())),
                first_started: started.clone(),
                first_gate: write_gate.clone(),
            },
            IdleReader {
                polls: Arc::new(AtomicUsize::new(0)),
                events: Some(events.clone()),
            },
            RecordingOwner {
                events,
                release_result: Ok(()),
            },
            Arc::new(AtomicBool::new(true)),
            8,
            8,
            Duration::from_millis(100),
        );
        let counter = Arc::new(AtomicU64::new(0));
        let acknowledgement = io
            .writer
            .queue_packet(
                vec![0xAA],
                1,
                counter.clone(),
                Some(ready_tx_gate(false)),
                None,
                Arc::new(AtomicBool::new(false)),
            )
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(1), async {
            while !started.load(Ordering::Acquire) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(
            counter.load(Ordering::Relaxed),
            0,
            "active bulk transfer is not completion"
        );
        drop(acknowledgement);
        let (lock, wake) = &*write_gate;
        *lock.lock().unwrap() = true;
        wake.notify_all();
        wait_for_count(&counter, 1).await;
        let _ = io
            .shutdown(None, Duration::from_millis(20), Duration::from_secs(1))
            .await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn usb_late_complete_write_is_counted_once_and_not_replayed_after_join() {
        struct ReleaseOnDrop(Arc<(Mutex<bool>, Condvar)>);
        impl Drop for ReleaseOnDrop {
            fn drop(&mut self) {
                let (lock, wake) = &*self.0;
                *lock.lock().unwrap() = true;
                wake.notify_all();
            }
        }
        struct LatePacketWriter {
            started: Arc<AtomicBool>,
            release: Arc<(Mutex<bool>, Condvar)>,
        }
        impl UsbWriterBackend for LatePacketWriter {
            fn transfer(
                &mut self,
                bytes: &[u8],
                _timeout: Duration,
            ) -> Result<i32, UsbTransferError> {
                self.started.store(true, Ordering::Release);
                let (lock, wake) = &*self.release;
                let mut released = lock.lock().unwrap();
                while !*released {
                    released = wake.wait(released).unwrap();
                }
                // Deliberately model a backend reporting positive completion
                // later than its timeout, not an unknown/partial result.
                Ok(bytes.len() as i32)
            }
        }
        let started = Arc::new(AtomicBool::new(false));
        let release = Arc::new((Mutex::new(false), Condvar::new()));
        let _release_on_failure = ReleaseOnDrop(release.clone());
        let events = Arc::new(Mutex::new(Vec::new()));
        let old_io = spawn_owned_usb_io(
            LatePacketWriter {
                started: started.clone(),
                release: release.clone(),
            },
            IdleReader {
                polls: Arc::new(AtomicUsize::new(0)),
                events: Some(events.clone()),
            },
            RecordingOwner {
                events,
                release_result: Ok(()),
            },
            Arc::new(AtomicBool::new(true)),
            8,
            8,
            Duration::from_millis(100),
        );
        let (tx, rx) = mpsc::channel(2);
        tx.send(Bytes::from_static(b"first")).await.unwrap();
        tx.send(Bytes::from_static(b"second")).await.unwrap();
        let queue = Arc::new(tokio::sync::Mutex::new(UsbApplicationQueue::new(rx)));
        let counter = Arc::new(AtomicU64::new(0));
        let (_stop_tx, stop_rx) = oneshot::channel();
        let pump = tokio::spawn(run_usb_tx_pump(
            queue.clone(),
            old_io.writer.clone(),
            counter.clone(),
            None,
            ready_tx_gate(false),
            stop_rx,
        ));
        tokio::time::timeout(Duration::from_secs(1), async {
            while !started.load(Ordering::Acquire) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        let outcome =
            tokio::time::timeout(USB_PACKET_WRITE_DEADLINE + Duration::from_secs(1), pump)
                .await
                .expect("caller deadline must remain bounded")
                .unwrap();
        assert!(matches!(
            outcome,
            UsbTxPumpExit::WriterRejected(UsbWriteFailure {
                kind: UsbWriteFailureKind::DeadlineElapsed,
                ..
            })
        ));
        assert_eq!(counter.load(Ordering::Relaxed), 0);
        let completed = queue
            .lock()
            .await
            .pending
            .as_ref()
            .unwrap()
            .completed
            .clone();
        assert!(!completed.load(Ordering::Acquire));
        let (lock, wake) = &*release;
        *lock.lock().unwrap() = true;
        wake.notify_all();
        wait_for_count(&counter, 5).await;
        let old_shutdown = old_io
            .shutdown(None, Duration::from_millis(20), Duration::from_secs(1))
            .await;
        assert_eq!(
            old_shutdown.report.disposition,
            UsbCleanupDisposition::Released
        );
        assert!(completed.load(Ordering::Acquire));

        // Only the fully joined old owner can hand its logical queue to a new
        // generation. That generation must skip first, not transmit it twice.
        let writer = ScriptedWriter::new([]);
        let calls = writer.calls.clone();
        let new_io = test_io(writer, Arc::new(Mutex::new(Vec::new())));
        let gate = UsbTxGate::new(false, Arc::new(AtomicBool::new(false)));
        let (mut inbound, _driver) = projected_inbound();
        inbound.attach_tx_gate(gate.clone());
        let (stop_tx, stop_rx) = oneshot::channel();
        let pump = tokio::spawn(run_usb_tx_pump(
            queue,
            new_io.writer.clone(),
            counter.clone(),
            None,
            gate,
            stop_rx,
        ));
        tokio::task::yield_now().await;
        assert!(calls.lock().unwrap().is_empty());
        for (command, frame) in required_protocol_frames(USB_TEST_TARGET) {
            inbound.project_frame(command, &frame);
        }
        wait_for_count(&counter, 11).await;
        assert_eq!(
            calls
                .lock()
                .unwrap()
                .iter()
                .map(|(bytes, _)| bytes.clone())
                .collect::<Vec<_>>(),
            vec![kiss::frame(b"second")]
        );
        stop_tx.send(()).unwrap();
        assert_eq!(pump.await.unwrap(), UsbTxPumpExit::StopRequested);
        let _ = new_io
            .shutdown(None, Duration::from_millis(20), Duration::from_secs(1))
            .await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn ordinary_usb_startup_discards_preinit_rf_ready_and_partial_frames() {
        struct PreinitReader(Option<Vec<u8>>);
        impl UsbReaderBackend for PreinitReader {
            fn read(&mut self) -> Result<UsbReadResult, String> {
                if let Some(bytes) = self.0.take() {
                    return Ok(UsbReadResult::Data(bytes));
                }
                std::thread::sleep(Duration::from_millis(1));
                Ok(UsbReadResult::Idle)
            }
        }
        let mut stale = framed_protocol_frames(required_protocol_frames(USB_TEST_TARGET));
        kiss::frame_with_command_into(rnode::CMD_READY, &[1], &mut stale);
        stale.extend_from_slice(&[kiss::FEND, rnode::CMD_FREQUENCY, 0x36]);
        let events = Arc::new(Mutex::new(Vec::new()));
        let mut io = spawn_owned_usb_io(
            ScriptedWriter::new([]),
            PreinitReader(Some(stale)),
            RecordingOwner {
                events,
                release_result: Ok(()),
            },
            Arc::new(AtomicBool::new(true)),
            8,
            8,
            Duration::from_millis(100),
        );
        let seed = run_usb_rnode_startup(
            &mut io,
            USB_TEST_TARGET,
            vec![1],
            vec![2],
            Duration::from_secs(1),
        )
        .await
        .unwrap();
        assert!(seed.evidence().detected);
        assert!(seed.evidence().firmware.is_some());
        assert_eq!(seed.evidence().frequency, None);
        assert!(!seed.flow_permission_observed());
        assert_ne!(seed.readiness(), RNodeReadiness::Ready);
        let (mut publisher, _driver) =
            rnode::new_rnode_driver_observation(rnode::RNodeTransportClass::Usb);
        publisher.connection_established();
        let mut inbound = UsbInboundState::projected_with_protocol_state(seed, publisher);
        let gate = UsbTxGate::new(false, Arc::new(AtomicBool::new(false)));
        inbound.attach_tx_gate(gate.clone());
        assert!(!gate.can_send());
        for (command, frame) in required_protocol_frames(USB_TEST_TARGET)
            .into_iter()
            .skip(2)
        {
            inbound.project_frame(command, &frame);
        }
        assert!(
            gate.can_send(),
            "only fresh post-init RF echoes complete readiness"
        );
        let _ = io
            .shutdown(None, Duration::from_millis(20), Duration::from_secs(1))
            .await;
    }

    fn required_protocol_frames(target: RNodeProtocolTarget) -> [(u8, Vec<u8>); 8] {
        [
            (rnode::CMD_DETECT, vec![rnode::DETECT_RESP]),
            (
                rnode::CMD_FW_VERSION,
                vec![rnode::REQUIRED_FW_VER_MAJ, rnode::REQUIRED_FW_VER_MIN],
            ),
            (
                rnode::CMD_FREQUENCY,
                target.frequency.to_be_bytes().to_vec(),
            ),
            (
                rnode::CMD_BANDWIDTH,
                target.bandwidth.to_be_bytes().to_vec(),
            ),
            (rnode::CMD_SF, vec![target.spreading_factor]),
            (rnode::CMD_CR, vec![target.coding_rate]),
            (rnode::CMD_TXPOWER, vec![target.tx_power]),
            (rnode::CMD_RADIO_STATE, vec![rnode::RADIO_STATE_ON]),
        ]
    }

    fn framed_protocol_frames(frames: impl IntoIterator<Item = (u8, Vec<u8>)>) -> Vec<u8> {
        let mut wire = Vec::new();
        for (command, payload) in frames {
            kiss::frame_with_command_into(command, &payload, &mut wire);
        }
        wire
    }

    fn capability_eeprom(model: u8) -> Vec<u8> {
        let mut bytes = vec![0xFF; 1024];
        bytes[0] = 0x03;
        bytes[1] = model;
        bytes[2..11].copy_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8, 9]);
        let checksum: [u8; 16] = Md5::digest(&bytes[..11]).into();
        bytes[11..27].copy_from_slice(&checksum);
        bytes[0x9B] = 0x73;
        bytes
    }

    fn capability_response(model: u8) -> Vec<u8> {
        framed_protocol_frames([
            (rnode::CMD_DETECT, vec![rnode::DETECT_RESP]),
            (
                rnode::CMD_FW_VERSION,
                vec![rnode::REQUIRED_FW_VER_MAJ, rnode::REQUIRED_FW_VER_MIN],
            ),
            (rnode::CMD_ROM_READ, capability_eeprom(model)),
        ])
    }

    fn strict_settings() -> RNodeRadioSettings {
        RNodeRadioSettings::new(868_000_000, 125_000, 7, 5, 14)
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn rnode_startup_acknowledges_detect_then_exact_init_without_accounting() {
        let writer = ScriptedWriter::new([]);
        let calls = writer.calls.clone();
        let events = Arc::new(Mutex::new(Vec::new()));
        let mut io = test_io(writer, events);
        let transmitted = Arc::new(AtomicU64::new(0));

        let mut config = rnode::RNodeConfig::new("android-usb-test", "/dev/bus/usb/test");
        config.frequency = USB_TEST_TARGET.frequency;
        config.bandwidth = USB_TEST_TARGET.bandwidth;
        config.spreading_factor = USB_TEST_TARGET.spreading_factor;
        config.coding_rate = USB_TEST_TARGET.coding_rate;
        config.tx_power = USB_TEST_TARGET.tx_power;
        let detect = rnode::build_detect_sequence();
        let init = rnode::build_init_sequence(&config);

        run_usb_rnode_startup(
            &mut io,
            USB_TEST_TARGET,
            detect.clone(),
            init.clone(),
            Duration::from_secs(1),
        )
        .await
        .expect("both startup phases should be physically acknowledged");

        assert_eq!(
            transmitted.load(Ordering::Relaxed),
            0,
            "startup control bytes must never enter packet TX accounting"
        );

        let packet = vec![0xAA, 0xBB, 0xCC];
        io.writer
            .queue_packet_and_account(packet.clone(), &transmitted)
            .await
            .expect("packet should be admitted after startup")
            .await
            .expect("writer acknowledgement")
            .expect("packet write");
        assert_eq!(
            transmitted.load(Ordering::Relaxed),
            packet.len() as u64,
            "only the admitted packet should enter TX accounting"
        );
        tokio::time::timeout(Duration::from_secs(1), async {
            while calls
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .len()
                != 3
            {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("packet write did not complete");
        assert_eq!(
            calls
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .iter()
                .map(|(bytes, _)| bytes.clone())
                .collect::<Vec<_>>(),
            vec![detect, init, packet]
        );

        let _ = io
            .shutdown(None, Duration::from_millis(20), Duration::from_secs(1))
            .await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn strict_usb_startup_orders_one_capability_request_before_init() {
        let writer = ScriptedWriter::new([]);
        let calls = writer.calls.clone();
        let owner_events = Arc::new(Mutex::new(Vec::new()));
        let mut io = capability_test_io(writer, capability_response(0xB8), owner_events);
        let detect = rnode::build_detect_sequence();
        let capability = crate::rnode_capability_preflight::build_rnode_capability_request();
        let mut config = rnode::RNodeConfig::new("strict-usb", "test");
        let settings = strict_settings();
        config.frequency = settings.frequency;
        config.bandwidth = settings.bandwidth;
        config.spreading_factor = settings.spreading_factor;
        config.coding_rate = settings.coding_rate;
        config.tx_power = settings.tx_power;
        let init = rnode::build_init_sequence(&config);

        let admitted = run_usb_rnode_capability_startup(
            &mut io,
            settings,
            detect.clone(),
            init.clone(),
            Duration::from_secs(1),
            Duration::from_secs(1),
        )
        .await
        .expect("known model should pass strict USB admission");
        assert!(matches!(
            admitted.admission,
            RNodeRadioAdmission::Verified {
                model_code: 0xB8,
                ..
            }
        ));
        assert_eq!(
            calls
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .iter()
                .map(|(bytes, _)| bytes.clone())
                .collect::<Vec<_>>(),
            vec![detect, capability.clone(), init]
        );
        assert_eq!(
            calls
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .iter()
                .filter(|(bytes, _)| bytes == &capability)
                .count(),
            1,
            "strict startup must issue exactly one ROM_READ(0)"
        );

        let shutdown = io
            .shutdown(None, Duration::from_millis(20), Duration::from_secs(1))
            .await;
        assert_eq!(shutdown.report.disposition, UsbCleanupDisposition::Released);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn strict_usb_rejection_sends_no_init_or_detach_and_releases_owner() {
        let mut writer = ScriptedWriter::new([]);
        let calls = writer.calls.clone();
        let owner_events = Arc::new(Mutex::new(Vec::new()));
        writer.events = Some(owner_events.clone());
        let mut io = capability_test_io(writer, capability_response(0xB4), owner_events.clone());
        let result = run_usb_rnode_capability_startup(
            &mut io,
            strict_settings(),
            rnode::build_detect_sequence(),
            vec![0xA1, 0xA2],
            Duration::from_secs(1),
            Duration::from_secs(1),
        )
        .await;
        assert!(matches!(
            result,
            Err(UsbRNodeCapabilityStartupError::Capability(
                RNodeCapabilityAdmissionError::RadioSettings(
                    crate::rnode_capabilities::RNodeRadioAdmissionError::FrequencyOutOfRange { .. }
                )
            ))
        ));

        assert_eq!(
            calls
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .iter()
                .map(|(bytes, _)| bytes.clone())
                .collect::<Vec<_>>(),
            vec![
                rnode::build_detect_sequence(),
                crate::rnode_capability_preflight::build_rnode_capability_request(),
            ],
            "deterministic rejection must not send init or detach"
        );

        let shutdown = io
            .shutdown(None, Duration::from_millis(20), Duration::from_secs(1))
            .await;
        assert_eq!(shutdown.report.disposition, UsbCleanupDisposition::Released);
        let owner_events = owner_events
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        assert!(owner_events.contains(&"release"));
        assert!(owner_events.contains(&"close"));
        assert!(!owner_events.contains(&"quarantined"));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn strict_usb_ambiguous_init_failure_requests_ordered_detach_cleanup() {
        struct FailInitWriter {
            calls: RecordedWriteCalls,
            init: Vec<u8>,
        }

        impl UsbWriterBackend for FailInitWriter {
            fn transfer(
                &mut self,
                bytes: &[u8],
                timeout: Duration,
            ) -> Result<i32, UsbTransferError> {
                self.calls
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .push((bytes.to_vec(), timeout));
                if bytes == self.init {
                    Err(UsbTransferError::Backend("ambiguous init failure".into()))
                } else {
                    Ok(bytes.len() as i32)
                }
            }
        }

        let settings = strict_settings();
        let mut config = rnode::RNodeConfig::new("strict-usb-init-failure", "test");
        config.frequency = settings.frequency;
        config.bandwidth = settings.bandwidth;
        config.spreading_factor = settings.spreading_factor;
        config.coding_rate = settings.coding_rate;
        config.tx_power = settings.tx_power;
        let init = rnode::build_init_sequence(&config);
        let calls = Arc::new(Mutex::new(Vec::new()));
        let owner_events = Arc::new(Mutex::new(Vec::new()));
        let writer = FailInitWriter {
            calls: calls.clone(),
            init: init.clone(),
        };
        let writer_calls = calls.clone();
        let response = capability_response(0xB8);
        let mut io = spawn_owned_usb_io(
            writer,
            CapabilityResponseReader {
                writer_calls,
                responses: response.chunks(512).map(|chunk| chunk.to_vec()).collect(),
            },
            RecordingOwner {
                events: owner_events.clone(),
                release_result: Ok(()),
            },
            Arc::new(AtomicBool::new(true)),
            8,
            8,
            Duration::from_millis(100),
        );

        let detect = rnode::build_detect_sequence();
        let capability = crate::rnode_capability_preflight::build_rnode_capability_request();
        let detach = rnode::build_detach_sequence();
        let result = run_usb_rnode_capability_startup(
            &mut io,
            settings,
            detect.clone(),
            init.clone(),
            Duration::from_secs(1),
            Duration::from_secs(1),
        )
        .await;
        assert!(matches!(
            result,
            Err(UsbRNodeCapabilityStartupError::Initialise(
                UsbWriteFailure {
                    phase: UsbWritePhase::Initialise,
                    ..
                }
            ))
        ));
        assert_eq!(
            calls
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .last()
                .map(|(bytes, _)| bytes.as_slice()),
            Some(init.as_slice())
        );

        let shutdown = io
            .shutdown(
                Some(detach.clone()),
                Duration::from_millis(20),
                Duration::from_secs(1),
            )
            .await;
        assert_eq!(
            shutdown.report.detach,
            Some(Ok(())),
            "ambiguous init must physically acknowledge ordered detach cleanup"
        );
        assert_eq!(shutdown.report.disposition, UsbCleanupDisposition::Released);
        assert_eq!(
            calls
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .iter()
                .map(|(bytes, _)| bytes.clone())
                .collect::<Vec<_>>(),
            vec![detect, capability, init, detach]
        );
        let owner_events = owner_events
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        assert!(owner_events.contains(&"release"));
        assert!(owner_events.contains(&"close"));
        assert!(!owner_events.contains(&"quarantined"));
    }

    #[cfg(any(feature = "serial", feature = "rnode-tcp", feature = "ble"))]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn strict_usb_unknown_model_is_unverified_and_preflight_bytes_do_not_escape() {
        let settings = strict_settings();
        let target = RNodeProtocolTarget::new(
            settings.frequency,
            settings.bandwidth,
            settings.spreading_factor,
            settings.coding_rate,
            settings.tx_power,
        );
        let mut response = Vec::new();
        kiss::frame_with_command_into(kiss::CMD_DATA, b"preflight packet", &mut response);
        kiss::frame_with_command_into(
            rnode::CMD_FREQUENCY,
            &settings.frequency.to_be_bytes(),
            &mut response,
        );
        response.extend_from_slice(&capability_response(0xFE));
        response.extend_from_slice(&[kiss::FEND, kiss::CMD_DATA, 0xAA]);

        let writer = ScriptedWriter::new([]);
        let owner_events = Arc::new(Mutex::new(Vec::new()));
        let mut io = capability_test_io(writer, response, owner_events);
        let mut config = rnode::RNodeConfig::new("strict-usb", "test");
        config.frequency = settings.frequency;
        config.bandwidth = settings.bandwidth;
        config.spreading_factor = settings.spreading_factor;
        config.coding_rate = settings.coding_rate;
        config.tx_power = settings.tx_power;
        let admitted = run_usb_rnode_capability_startup(
            &mut io,
            settings,
            rnode::build_detect_sequence(),
            rnode::build_init_sequence(&config),
            Duration::from_secs(1),
            Duration::from_secs(1),
        )
        .await
        .expect("validated unknown model should be admitted as unverified");
        assert!(matches!(
            admitted.admission,
            RNodeRadioAdmission::Unverified {
                model_code: 0xFE,
                ..
            }
        ));
        let evidence = admitted.protocol_state.evidence();
        assert!(evidence.detected);
        assert!(evidence.firmware.is_some());
        assert_eq!(
            evidence.frequency, None,
            "pre-init RF evidence must be reset"
        );

        let (mut publisher, driver) =
            rnode::new_rnode_driver_observation(rnode::RNodeTransportClass::Usb);
        publisher.capability_connection_established(&admitted.protocol_state, admitted.admission);
        let seeded = driver.snapshot();
        assert_eq!(seeded.capability, rnode::RNodeCapabilityState::Unverified);
        assert_eq!(seeded.detection, rnode::RNodeDetectionState::Confirmed);
        assert_eq!(
            seeded.configuration,
            rnode::RNodeConfigurationState::Unknown
        );

        let mut inbound =
            UsbInboundState::projected_with_protocol_state(admitted.protocol_state, publisher);
        let (_stop_tx, mut stop_rx) = mpsc::channel(1);
        let (transport_tx, mut transport_rx) = mpsc::channel(1);
        let received = AtomicU64::new(0);
        assert_eq!(
            forward_usb_read_chunk(
                &mut inbound,
                &[0xBB, kiss::FEND],
                0x66,
                &received,
                &transport_tx,
                &mut stop_rx,
            )
            .await,
            UsbInboundOutcome::Complete
        );
        assert!(transport_rx.try_recv().is_err());
        assert_eq!(received.load(Ordering::Relaxed), 0);

        assert_eq!(
            forward_usb_read_chunk(
                &mut inbound,
                &framed_protocol_frames(required_protocol_frames(target)),
                0x66,
                &received,
                &transport_tx,
                &mut stop_rx,
            )
            .await,
            UsbInboundOutcome::Complete
        );
        let ready = driver.snapshot();
        assert_eq!(ready.phase, rnode::RNodeRuntimePhase::Ready);
        assert_eq!(ready.capability, rnode::RNodeCapabilityState::Unverified);
        assert_eq!(
            ready.configuration,
            rnode::RNodeConfigurationState::Verified
        );

        let shutdown = io
            .shutdown(None, Duration::from_millis(20), Duration::from_secs(1))
            .await;
        assert_eq!(shutdown.report.disposition, UsbCleanupDisposition::Released);
    }

    #[cfg(any(feature = "serial", feature = "rnode-tcp", feature = "ble"))]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn strict_usb_reader_boundary_drains_separately_queued_preinit_rf_evidence() {
        struct InitAfterStaleWriter {
            calls: RecordedWriteCalls,
            init: Vec<u8>,
            stale_enqueued: Arc<AtomicBool>,
        }

        impl UsbWriterBackend for InitAfterStaleWriter {
            fn transfer(
                &mut self,
                bytes: &[u8],
                _timeout: Duration,
            ) -> Result<i32, UsbTransferError> {
                self.calls
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .push((bytes.to_vec(), Duration::ZERO));
                if bytes == self.init {
                    let deadline = Instant::now() + Duration::from_secs(1);
                    while !self.stale_enqueued.load(Ordering::Acquire) {
                        if Instant::now() >= deadline {
                            return Err(UsbTransferError::Backend(
                                "stale pre-init test read was not enqueued".into(),
                            ));
                        }
                        std::thread::sleep(Duration::from_millis(1));
                    }
                }
                Ok(bytes.len() as i32)
            }
        }

        struct SeparateStaleReader {
            writer_calls: RecordedWriteCalls,
            capability_reads: VecDeque<Vec<u8>>,
            stale: Option<Vec<u8>>,
            post_init: Option<Vec<u8>>,
            stale_returned: bool,
            stale_enqueued: Arc<AtomicBool>,
        }

        impl UsbReaderBackend for SeparateStaleReader {
            fn read(&mut self) -> Result<UsbReadResult, String> {
                if self
                    .writer_calls
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .len()
                    < 2
                {
                    std::thread::sleep(Duration::from_millis(1));
                    return Ok(UsbReadResult::Idle);
                }
                if let Some(bytes) = self.capability_reads.pop_front() {
                    return Ok(UsbReadResult::Data(bytes));
                }
                if let Some(stale) = self.stale.take() {
                    self.stale_returned = true;
                    return Ok(UsbReadResult::Data(stale));
                }
                if self.stale_returned {
                    let init_was_sent = self
                        .writer_calls
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .len()
                        >= 3;
                    if init_was_sent {
                        if let Some(post_init) = self.post_init.take() {
                            return Ok(UsbReadResult::Data(post_init));
                        }
                    }
                    // `run_usb_reader` can call us again only after its prior
                    // blocking_send of the stale read completed.
                    self.stale_enqueued.store(true, Ordering::Release);
                }
                std::thread::sleep(Duration::from_millis(1));
                Ok(UsbReadResult::Idle)
            }
        }

        let settings = strict_settings();
        let target = RNodeProtocolTarget::new(
            settings.frequency,
            settings.bandwidth,
            settings.spreading_factor,
            settings.coding_rate,
            settings.tx_power,
        );
        let mut config = rnode::RNodeConfig::new("strict-usb-boundary", "test");
        config.frequency = settings.frequency;
        config.bandwidth = settings.bandwidth;
        config.spreading_factor = settings.spreading_factor;
        config.coding_rate = settings.coding_rate;
        config.tx_power = settings.tx_power;
        let init = rnode::build_init_sequence(&config);
        let calls = Arc::new(Mutex::new(Vec::new()));
        let stale_enqueued = Arc::new(AtomicBool::new(false));
        let response = capability_response(0xB8);
        let stale_rf = framed_protocol_frames(required_protocol_frames(target).into_iter().skip(2));
        let post_init =
            framed_protocol_frames(required_protocol_frames(target).into_iter().skip(2));
        let reader = SeparateStaleReader {
            writer_calls: calls.clone(),
            capability_reads: response.chunks(512).map(|chunk| chunk.to_vec()).collect(),
            stale: Some(stale_rf),
            post_init: Some(post_init.clone()),
            stale_returned: false,
            stale_enqueued: stale_enqueued.clone(),
        };
        let owner_events = Arc::new(Mutex::new(Vec::new()));
        let mut io = spawn_owned_usb_io(
            InitAfterStaleWriter {
                calls,
                init: init.clone(),
                stale_enqueued: stale_enqueued.clone(),
            },
            reader,
            RecordingOwner {
                events: owner_events,
                release_result: Ok(()),
            },
            Arc::new(AtomicBool::new(true)),
            8,
            8,
            Duration::from_millis(100),
        );

        let admitted = run_usb_rnode_capability_startup(
            &mut io,
            settings,
            rnode::build_detect_sequence(),
            init,
            Duration::from_secs(1),
            Duration::from_secs(1),
        )
        .await
        .expect("reader boundary should drain queued pre-init evidence");
        assert!(stale_enqueued.load(Ordering::Acquire));
        assert_eq!(admitted.protocol_state.evidence().frequency, None);

        let (mut publisher, driver) =
            rnode::new_rnode_driver_observation(rnode::RNodeTransportClass::Usb);
        publisher.capability_connection_established(&admitted.protocol_state, admitted.admission);
        let mut inbound =
            UsbInboundState::projected_with_protocol_state(admitted.protocol_state, publisher);
        let snapshot = driver.snapshot();
        assert_eq!(
            snapshot.phase,
            rnode::RNodeRuntimePhase::AwaitingReadiness,
            "queued pre-init RF evidence must not make the admitted session ready"
        );
        assert_eq!(
            snapshot.configuration,
            rnode::RNodeConfigurationState::Unknown
        );

        let event = tokio::time::timeout(Duration::from_secs(1), io.events.recv())
            .await
            .expect("fresh init response should be read after resume")
            .expect("USB event stream should remain open");
        let UsbIoEvent::Read(bytes) = event else {
            panic!("expected fresh post-init read");
        };
        assert_eq!(
            bytes, post_init,
            "the first active read must be the response obtained after Init, not queued stale RF"
        );
        let (_stop_tx, mut stop_rx) = mpsc::channel(1);
        let (transport_tx, _transport_rx) = mpsc::channel(1);
        assert_eq!(
            forward_usb_read_chunk(
                &mut inbound,
                &bytes,
                0x77,
                &AtomicU64::new(0),
                &transport_tx,
                &mut stop_rx,
            )
            .await,
            UsbInboundOutcome::Complete
        );
        assert_eq!(driver.snapshot().phase, rnode::RNodeRuntimePhase::Ready);

        let shutdown = io
            .shutdown(None, Duration::from_millis(20), Duration::from_secs(1))
            .await;
        assert_eq!(shutdown.report.disposition, UsbCleanupDisposition::Released);
    }

    #[tokio::test]
    async fn projected_ready_frames_preserve_the_following_packet_and_accounting() {
        let (mut inbound, driver) = projected_inbound();
        let payload = vec![0xAA, kiss::FEND, kiss::FESC, 0x55];
        let mut wire = framed_protocol_frames(required_protocol_frames(USB_TEST_TARGET));
        kiss::frame_with_command_into(kiss::CMD_DATA, &payload, &mut wire);
        let split = wire.len() / 2;
        let (_stop_tx, mut stop_rx) = mpsc::channel(1);
        let (transport_tx, mut transport_rx) = mpsc::channel(1);
        let received = AtomicU64::new(0);

        for chunk in [&wire[..split], &wire[split..]] {
            assert_eq!(
                forward_usb_read_chunk(
                    &mut inbound,
                    chunk,
                    0x55,
                    &received,
                    &transport_tx,
                    &mut stop_rx,
                )
                .await,
                UsbInboundOutcome::Complete
            );
        }

        let snapshot = driver.snapshot();
        assert_eq!(snapshot.transport, rnode::RNodeTransportClass::Usb);
        assert_eq!(snapshot.phase, rnode::RNodeRuntimePhase::Ready);
        assert_eq!(
            snapshot.configuration,
            rnode::RNodeConfigurationState::Verified
        );
        match transport_rx.recv().await.expect("projected packet") {
            TransportMessage::Inbound(packet) => {
                assert_eq!(packet.raw.as_ref(), payload);
                assert_eq!(packet.interface_id, 0x55);
            }
            _ => panic!("unexpected transport message"),
        }
        assert_eq!(received.load(Ordering::Relaxed), payload.len() as u64);
    }

    #[tokio::test]
    async fn malformed_and_unknown_control_frames_do_not_change_usb_observation() {
        let (mut inbound, driver) = projected_inbound();
        let before = driver.snapshot();
        let malformed = [
            (0xE7, vec![0xDE, 0xAD]),
            (rnode::CMD_DETECT, Vec::new()),
            (rnode::CMD_FW_VERSION, vec![rnode::REQUIRED_FW_VER_MAJ]),
            (rnode::CMD_FREQUENCY, vec![1, 2, 3]),
            (rnode::CMD_RADIO_STATE, vec![2]),
            (rnode::CMD_READY, vec![1, 0]),
            (rnode::CMD_RESET, vec![0]),
            (rnode::CMD_ERROR, vec![0x7F]),
        ];
        let wire = framed_protocol_frames(malformed);
        let (_stop_tx, mut stop_rx) = mpsc::channel(1);
        let (transport_tx, mut transport_rx) = mpsc::channel(1);
        let received = AtomicU64::new(0);

        assert_eq!(
            forward_usb_read_chunk(
                &mut inbound,
                &wire,
                7,
                &received,
                &transport_tx,
                &mut stop_rx,
            )
            .await,
            UsbInboundOutcome::Complete
        );
        assert_eq!(driver.snapshot().as_ref(), before.as_ref());
        assert!(transport_rx.try_recv().is_err());
        assert_eq!(received.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn cmd_ready_diagnostics_do_not_substitute_for_protocol_readiness() {
        let (mut inbound, driver) = projected_inbound();
        let gate = UsbTxGate::new(false, Arc::new(AtomicBool::new(false)));
        inbound.attach_tx_gate(gate.clone());
        let mut ready_blocked = Vec::new();
        kiss::frame_with_command_into(rnode::CMD_READY, &[0], &mut ready_blocked);
        let (_stop_tx, mut stop_rx) = mpsc::channel(1);
        let (transport_tx, _transport_rx) = mpsc::channel(1);

        assert_eq!(
            forward_usb_read_chunk(
                &mut inbound,
                &ready_blocked,
                8,
                &AtomicU64::new(0),
                &transport_tx,
                &mut stop_rx,
            )
            .await,
            UsbInboundOutcome::Complete
        );
        assert_eq!(
            driver.snapshot().transmit_flow,
            rnode::RNodeTransmitFlowState::Blocked
        );

        assert!(
            !gate.can_send(),
            "flow-control off still requires typed readiness"
        );
    }

    #[tokio::test]
    async fn reader_tail_drain_projects_protocol_frames_before_exit() {
        let (mut inbound, driver) = projected_inbound();
        inbound.shutting_down(RNodeRuntimeReason::ConnectionLost);
        let (event_tx, mut events) = mpsc::channel(2);
        event_tx
            .send(UsbIoEvent::Read(framed_protocol_frames(
                required_protocol_frames(USB_TEST_TARGET),
            )))
            .await
            .expect("buffer protocol frames");
        event_tx
            .send(UsbIoEvent::Reader(UsbReaderExit::Stopped))
            .await
            .expect("reader exit");
        drop(event_tx);
        let (_stop_tx, mut stop_rx) = mpsc::channel(1);
        let (transport_tx, mut transport_rx) = mpsc::channel(1);

        assert_eq!(
            drain_usb_reader_tail(
                &mut events,
                &mut inbound,
                9,
                &AtomicU64::new(0),
                &transport_tx,
                &mut stop_rx,
                tokio::time::Instant::now() + Duration::from_secs(1),
            )
            .await,
            UsbReadDrainOutcome::Drained
        );
        let snapshot = driver.snapshot();
        assert_eq!(snapshot.phase, rnode::RNodeRuntimePhase::ShuttingDown);
        assert_eq!(
            snapshot.reason,
            Some(RNodeRuntimeReason::ConnectionLost),
            "late reducer evidence must not overwrite the shutdown cause"
        );
        assert_eq!(
            snapshot.configuration,
            rnode::RNodeConfigurationState::Verified,
            "the shutdown invariant must not hide bounded late evidence"
        );
        assert!(transport_rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn usb_observation_has_one_generation_then_closed_terminal_zero_without_reconnects() {
        let (mut publisher, driver) =
            rnode::new_rnode_driver_observation(rnode::RNodeTransportClass::Usb);
        let initial = driver.snapshot();
        assert_eq!(initial.connection_generation, 0);

        publisher.connection_established();
        let connected = driver.snapshot();
        assert_eq!(connected.connection_generation, 1);
        assert_eq!(connected.reconnect_attempt, 0);
        assert_eq!(connected.reconnect_total, 0);
        assert_eq!(connected.disconnect_total, 0);

        let mut inbound = UsbInboundState::projected(USB_TEST_TARGET, publisher);
        inbound.shutting_down(RNodeRuntimeReason::StopRequested);
        let shutting_down = driver.snapshot();
        assert_eq!(shutting_down.phase, rnode::RNodeRuntimePhase::ShuttingDown);
        assert_eq!(shutting_down.connection_generation, 1);
        assert_eq!(
            shutting_down.reason,
            Some(RNodeRuntimeReason::StopRequested)
        );

        let mut closed = driver.watch();
        inbound.stopped(RNodeRuntimeReason::StopRequested);
        let stopped = driver.snapshot();
        assert_eq!(stopped.phase, rnode::RNodeRuntimePhase::Stopped);
        assert_eq!(stopped.connection_generation, 0);
        assert_eq!(stopped.reconnect_attempt, 0);
        assert_eq!(stopped.reconnect_total, 0);
        assert_eq!(stopped.disconnect_total, 0);
        assert_eq!(stopped.reason, Some(RNodeRuntimeReason::StopRequested));

        let mut late_detect = Vec::new();
        kiss::frame_with_command_into(rnode::CMD_DETECT, &[rnode::DETECT_RESP], &mut late_detect);
        let (_stop_tx, mut stop_rx) = mpsc::channel(1);
        let (transport_tx, _transport_rx) = mpsc::channel(1);
        assert_eq!(
            forward_usb_read_chunk(
                &mut inbound,
                &late_detect,
                10,
                &AtomicU64::new(0),
                &transport_tx,
                &mut stop_rx,
            )
            .await,
            UsbInboundOutcome::Complete
        );
        assert_eq!(
            driver.snapshot().as_ref(),
            stopped.as_ref(),
            "terminal observations must ignore later protocol effects"
        );

        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), closed.changed())
                .await
                .expect("terminal publication should be immediate")
                .expect("terminal publication must precede closure")
                .phase,
            rnode::RNodeRuntimePhase::Stopped
        );
        drop(inbound);
        assert!(
            tokio::time::timeout(Duration::from_secs(1), closed.changed())
                .await
                .expect("publisher closure should be immediate")
                .is_none()
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn positive_short_writes_advance_until_the_full_request_is_acked() {
        let writer = ScriptedWriter::new([Ok(2), Ok(1), Ok(2)]);
        let calls = writer.calls.clone();
        let events = Arc::new(Mutex::new(Vec::new()));
        let io = test_io(writer, events);
        assert!(!io.events.is_closed());

        io.writer
            .request_before(
                UsbWritePhase::Initialise,
                vec![1, 2, 3, 4, 5],
                Duration::from_secs(1),
            )
            .await
            .expect("full short-write sequence should be acknowledged");
        assert_eq!(
            calls
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .iter()
                .map(|(bytes, _)| bytes.clone())
                .collect::<Vec<_>>(),
            vec![vec![1, 2, 3, 4, 5], vec![3, 4, 5], vec![4, 5]]
        );

        let shutdown = io
            .shutdown(None, Duration::from_millis(20), Duration::from_secs(1))
            .await;
        assert_eq!(shutdown.report.disposition, UsbCleanupDisposition::Released);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn application_packet_queue_preserves_fifo() {
        let writer = ScriptedWriter::new([]);
        let calls = writer.calls.clone();
        let events = Arc::new(Mutex::new(Vec::new()));
        let io = test_io(writer, events);
        let transmitted = Arc::new(AtomicU64::new(0));
        for packet in [vec![1], vec![2, 2], vec![3, 3, 3]] {
            io.writer
                .queue_packet_and_account(packet, &transmitted)
                .await
                .expect("packet queue")
                .await
                .expect("writer acknowledgement")
                .expect("packet write");
        }
        assert_eq!(transmitted.load(Ordering::Relaxed), 6);
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if calls
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .len()
                    == 3
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("packet writes did not complete");
        assert_eq!(
            calls
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .iter()
                .map(|(bytes, _)| bytes.clone())
                .collect::<Vec<_>>(),
            vec![vec![1], vec![2, 2], vec![3, 3, 3]]
        );
        let _ = io
            .shutdown(None, Duration::from_millis(20), Duration::from_secs(1))
            .await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn invalid_transfer_results_fail_without_false_acknowledgement() {
        let cases = [
            (Ok(0), UsbWriteFailureKind::ZeroLength),
            (Ok(-1), UsbWriteFailureKind::NegativeLength(-1)),
            (
                Ok(4),
                UsbWriteFailureKind::OversizedLength {
                    returned: 4,
                    remaining: 3,
                },
            ),
            (
                Err(UsbTransferError::WrongReturnType),
                UsbWriteFailureKind::WrongReturnType,
            ),
            (
                Err(UsbTransferError::Backend("jni".into())),
                UsbWriteFailureKind::Backend("jni".into()),
            ),
        ];

        for (result, expected) in cases {
            let events = Arc::new(Mutex::new(Vec::new()));
            let io = test_io(ScriptedWriter::new([result]), events);
            let error = io
                .writer
                .request_before(
                    UsbWritePhase::Initialise,
                    vec![1, 2, 3],
                    Duration::from_secs(1),
                )
                .await
                .expect_err("invalid transfer result must fail");
            assert_eq!(error.kind, expected);
            let shutdown = io
                .shutdown(None, Duration::from_millis(20), Duration::from_secs(1))
                .await;
            assert_eq!(shutdown.report.detach, None);
            assert!(matches!(
                shutdown.report.writer,
                UsbJoinOutcome::Joined(UsbWriterExit::Failed(_))
            ));
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn ambiguous_init_writer_still_quiesces_when_cleanup_has_no_detach() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let io = test_io(
            ScriptedWriter::new([Err(UsbTransferError::Backend("init".into()))]),
            events,
        );
        let error = io
            .writer
            .request_initialise_before_terminal_detach(vec![1, 2, 3], Duration::from_secs(1))
            .await
            .expect_err("synthetic init failure must be acknowledged");
        assert_eq!(error.phase, UsbWritePhase::Initialise);

        let shutdown = io
            .shutdown(None, Duration::from_millis(20), Duration::from_secs(1))
            .await;
        assert_eq!(shutdown.report.detach, None);
        assert!(matches!(
            shutdown.report.writer,
            UsbJoinOutcome::Joined(UsbWriterExit::Stopped)
        ));
        assert_eq!(shutdown.report.disposition, UsbCleanupDisposition::Released);
    }

    #[tokio::test]
    async fn dropped_worker_acknowledgement_is_an_explicit_failure() {
        let queue = UsbWriteQueue::new(1);
        let handle = UsbWriterHandle {
            queue: queue.clone(),
        };
        let closer = queue.clone();
        tokio::spawn(async move {
            loop {
                let queued = closer
                    .inner
                    .state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .requests
                    .len();
                if queued == 1 {
                    closer.mark_worker_closed();
                    break;
                }
                tokio::task::yield_now().await;
            }
        });
        let error = handle
            .request_before(UsbWritePhase::Initialise, vec![1], Duration::from_secs(1))
            .await
            .expect_err("dropped acknowledgement must fail");
        assert_eq!(error.kind, UsbWriteFailureKind::AcknowledgementDropped);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn detach_cancels_queued_packets_is_terminal_and_caps_timeout() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let first_started = Arc::new(AtomicBool::new(false));
        let first_gate = Arc::new((Mutex::new(false), Condvar::new()));
        let events = Arc::new(Mutex::new(Vec::new()));
        let io = spawn_owned_usb_io(
            GatedWriter {
                calls: calls.clone(),
                first_started: first_started.clone(),
                first_gate: first_gate.clone(),
            },
            IdleReader {
                polls: Arc::new(AtomicUsize::new(0)),
                events: Some(events.clone()),
            },
            RecordingOwner {
                events,
                release_result: Ok(()),
            },
            Arc::new(AtomicBool::new(true)),
            8,
            8,
            Duration::from_millis(100),
        );
        let transmitted = Arc::new(AtomicU64::new(0));
        io.writer
            .queue_packet_and_account(vec![0xAA], &transmitted)
            .await
            .expect("first packet queue");
        tokio::time::timeout(Duration::from_secs(1), async {
            while !first_started.load(Ordering::Acquire) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("first packet transfer did not start");
        io.writer
            .queue_packet_and_account(vec![0xBB], &transmitted)
            .await
            .expect("second packet queue");

        let release_gate = first_gate.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(10)).await;
            let (lock, wake) = &*release_gate;
            *lock
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = true;
            wake.notify_all();
        });
        let shutdown = io
            .shutdown(
                Some(vec![0xC0, 0x0A, 0xC0]),
                Duration::from_millis(500),
                Duration::from_secs(1),
            )
            .await;
        assert_eq!(shutdown.report.detach, Some(Ok(())));
        let calls = calls
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        assert_eq!(
            calls.last().map(|(bytes, _)| bytes.as_slice()),
            Some([0xC0, 0x0A, 0xC0].as_slice())
        );
        assert!(calls.last().expect("detach call").1 <= Duration::from_millis(500));
        assert_eq!(
            calls
                .iter()
                .filter(|(bytes, _)| bytes.as_slice() == [0xBB])
                .count(),
            0,
            "queued backlog must not follow stop admission"
        );
        assert_eq!(
            calls
                .iter()
                .map(|(bytes, _)| bytes.clone())
                .collect::<Vec<_>>(),
            vec![vec![0xAA], vec![0xC0, 0x0A, 0xC0]]
        );
    }

    #[test]
    fn completed_transfer_after_absolute_deadline_is_not_acknowledged() {
        struct SlowWriter {
            observed_timeout: Arc<Mutex<Option<Duration>>>,
        }

        impl UsbWriterBackend for SlowWriter {
            fn transfer(
                &mut self,
                bytes: &[u8],
                timeout: Duration,
            ) -> Result<i32, UsbTransferError> {
                *self
                    .observed_timeout
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(timeout);
                std::thread::sleep(Duration::from_millis(25));
                Ok(bytes.len() as i32)
            }
        }

        let observed_timeout = Arc::new(Mutex::new(None));
        let request = UsbWriteRequest {
            phase: UsbWritePhase::Detach,
            bytes: vec![1, 2, 3],
            deadline: Some(Instant::now() + Duration::from_millis(15)),
            acknowledgement: None,
            await_terminal_detach_on_failure: false,
            packet: None,
            _permit: None,
        };
        let error = write_request(
            &mut SlowWriter {
                observed_timeout: observed_timeout.clone(),
            },
            &request,
            Duration::from_secs(1),
        )
        .expect_err("late completion must not be acknowledged");
        assert_eq!(error.kind, UsbWriteFailureKind::DeadlineElapsed);
        assert!(
            observed_timeout
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .is_some_and(|timeout| timeout <= Duration::from_millis(15))
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn idle_reads_do_not_mark_the_connection_offline() {
        let online = Arc::new(AtomicBool::new(true));
        let polls = Arc::new(AtomicUsize::new(0));
        let io = spawn_owned_usb_io(
            ScriptedWriter::new([]),
            IdleReader {
                polls: polls.clone(),
                events: None,
            },
            RecordingOwner {
                events: Arc::new(Mutex::new(Vec::new())),
                release_result: Ok(()),
            },
            online.clone(),
            2,
            2,
            Duration::from_millis(100),
        );
        tokio::time::timeout(Duration::from_secs(1), async {
            while polls.load(Ordering::Relaxed) < 3 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("reader did not poll");
        assert!(online.load(Ordering::Acquire));
        let _ = io
            .shutdown(None, Duration::from_millis(20), Duration::from_secs(1))
            .await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn data_reads_reach_the_owned_receiver() {
        struct OneDataReader {
            sent: bool,
        }

        impl UsbReaderBackend for OneDataReader {
            fn read(&mut self) -> Result<UsbReadResult, String> {
                if self.sent {
                    std::thread::sleep(Duration::from_millis(1));
                    Ok(UsbReadResult::Idle)
                } else {
                    self.sent = true;
                    Ok(UsbReadResult::Data(vec![1, 2, 3]))
                }
            }
        }

        let mut io = spawn_owned_usb_io(
            ScriptedWriter::new([]),
            OneDataReader { sent: false },
            RecordingOwner {
                events: Arc::new(Mutex::new(Vec::new())),
                release_result: Ok(()),
            },
            Arc::new(AtomicBool::new(true)),
            2,
            2,
            Duration::from_millis(100),
        );
        let bytes = tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                match io.events.recv().await {
                    Some(UsbIoEvent::Read(bytes)) => break Some(bytes),
                    Some(UsbIoEvent::Writer(_) | UsbIoEvent::Reader(_)) => {}
                    None => break None,
                }
            }
        })
        .await
        .expect("data read timed out");
        assert_eq!(bytes, Some(vec![1, 2, 3]));
        let _ = io
            .shutdown(None, Duration::from_millis(20), Duration::from_secs(1))
            .await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn blocked_inbound_transport_does_not_stall_the_independent_tx_pump() {
        use rns_transport::messages::InboundPacket;

        let (transport_tx, _transport_rx) = mpsc::channel(1);
        transport_tx
            .send(TransportMessage::Inbound(InboundPacket {
                raw: Bytes::new(),
                interface_id: 0,
                rssi: None,
                snr: None,
                q: None,
            }))
            .await
            .expect("fill transport channel");
        let (forward_stop_tx, mut forward_stop_rx) = mpsc::channel(1);
        let forward_transport = transport_tx.clone();
        let forward_task = tokio::spawn(async move {
            forward_usb_read_chunk(
                &mut UsbInboundState::new(),
                &kiss::frame(&[1, 2, 3]),
                1,
                &AtomicU64::new(0),
                &forward_transport,
                &mut forward_stop_rx,
            )
            .await
        });

        let (application_tx, application_rx) = mpsc::channel(1);
        let application_rx = Arc::new(tokio::sync::Mutex::new(UsbApplicationQueue::new(
            application_rx,
        )));
        let (pump_stop_tx, pump_stop_rx) = oneshot::channel();
        let transmitted = Arc::new(AtomicU64::new(0));
        let expected_frame_length = 3;
        let io = test_io(ScriptedWriter::new([]), Arc::new(Mutex::new(Vec::new())));
        let pump = tokio::spawn(run_usb_tx_pump(
            application_rx,
            io.writer.clone(),
            transmitted.clone(),
            None,
            ready_tx_gate(false),
            pump_stop_rx,
        ));
        application_tx
            .send(Bytes::from_static(&[4, 5, 6]))
            .await
            .expect("pending outbound");

        tokio::time::timeout(Duration::from_secs(1), async {
            while transmitted.load(Ordering::Relaxed) != expected_frame_length {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("TX pump was stalled by inbound transport backpressure");
        assert!(!forward_task.is_finished());

        forward_stop_tx.send(()).await.expect("stop forwarding");
        assert_eq!(
            forward_task.await.expect("forward join"),
            UsbInboundOutcome::StopRequested
        );
        let _ = pump_stop_tx.send(());
        assert_eq!(pump.await.expect("pump join"), UsbTxPumpExit::StopRequested);
        let _ = io
            .shutdown(None, Duration::from_millis(20), Duration::from_secs(1))
            .await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn application_queue_survives_sequential_usb_generations() {
        let (application_tx, application_rx) = mpsc::channel(2);
        let application_rx = Arc::new(tokio::sync::Mutex::new(UsbApplicationQueue::new(
            application_rx,
        )));
        let transmitted = Arc::new(AtomicU64::new(0));

        let (first_stop_tx, first_stop_rx) = oneshot::channel();
        let first_pump = tokio::spawn(run_usb_tx_pump(
            application_rx.clone(),
            UsbWriterHandle {
                queue: UsbWriteQueue::new(1),
            },
            transmitted.clone(),
            None,
            ready_tx_gate(false),
            first_stop_rx,
        ));
        first_stop_tx.send(()).expect("stop first generation");
        assert_eq!(
            first_pump.await.expect("first pump join"),
            UsbTxPumpExit::StopRequested
        );

        let payload = Bytes::from_static(&[4, 2, 4, 2]);
        let expected_frame_length = payload.len() as u64;
        application_tx
            .send(payload)
            .await
            .expect("queue payload between generations");

        let (second_stop_tx, second_stop_rx) = oneshot::channel();
        let io = test_io(ScriptedWriter::new([]), Arc::new(Mutex::new(Vec::new())));
        let second_pump = tokio::spawn(run_usb_tx_pump(
            application_rx,
            io.writer.clone(),
            transmitted.clone(),
            None,
            ready_tx_gate(false),
            second_stop_rx,
        ));
        tokio::time::timeout(Duration::from_secs(1), async {
            while transmitted.load(Ordering::Relaxed) != expected_frame_length {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("second generation did not receive the queued payload");

        second_stop_tx.send(()).expect("stop second generation");
        assert_eq!(
            second_pump.await.expect("second pump join"),
            UsbTxPumpExit::StopRequested
        );
        let _ = io
            .shutdown(None, Duration::from_millis(20), Duration::from_secs(1))
            .await;
    }

    #[tokio::test]
    async fn android_usb_station_id_is_armed_only_after_application_tx() {
        let (application_tx, application_rx) = mpsc::channel(1);
        let application_rx = Arc::new(tokio::sync::Mutex::new(UsbApplicationQueue::new(
            application_rx,
        )));
        let transmitted = Arc::new(AtomicU64::new(0));
        let (stop_tx, stop_rx) = oneshot::channel();
        let payload = Bytes::from_static(b"payload");
        let callsign = Bytes::from_static(b"N0CALL");
        let expected = (payload.len() + callsign.len()) as u64;
        let io = test_io(ScriptedWriter::new([]), Arc::new(Mutex::new(Vec::new())));
        let pump = tokio::spawn(run_usb_tx_pump(
            application_rx,
            io.writer.clone(),
            transmitted.clone(),
            Some((Duration::ZERO, callsign)),
            ready_tx_gate(false),
            stop_rx,
        ));
        assert_eq!(transmitted.load(Ordering::Relaxed), 0);
        application_tx.send(payload).await.expect("application tx");
        tokio::time::timeout(Duration::from_secs(2), async {
            while transmitted.load(Ordering::Relaxed) != expected {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("station ID did not follow application TX");
        let _ = stop_tx.send(());
        assert_eq!(pump.await.expect("pump join"), UsbTxPumpExit::StopRequested);
        let _ = io
            .shutdown(None, Duration::from_millis(20), Duration::from_secs(1))
            .await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn blocked_tx_admission_does_not_stall_inbound_forwarding() {
        let (application_tx, application_rx) = mpsc::channel(1);
        let application_rx = Arc::new(tokio::sync::Mutex::new(UsbApplicationQueue::new(
            application_rx,
        )));
        let (pump_stop_tx, pump_stop_rx) = oneshot::channel();
        let transmitted = Arc::new(AtomicU64::new(0));
        let pump = tokio::spawn(run_usb_tx_pump(
            application_rx,
            UsbWriterHandle {
                queue: UsbWriteQueue::new(0),
            },
            transmitted.clone(),
            None,
            ready_tx_gate(false),
            pump_stop_rx,
        ));
        application_tx
            .send(Bytes::from_static(&[9, 8, 7]))
            .await
            .expect("pending outbound");
        tokio::task::yield_now().await;
        assert_eq!(transmitted.load(Ordering::Relaxed), 0);
        assert!(!pump.is_finished());

        let (_stop_tx, mut stop_rx) = mpsc::channel(1);
        let (transport_tx, mut transport_rx) = mpsc::channel(1);
        assert_eq!(
            tokio::time::timeout(
                Duration::from_secs(1),
                forward_usb_read_chunk(
                    &mut UsbInboundState::new(),
                    &kiss::frame(&[1, 3, 5]),
                    2,
                    &AtomicU64::new(0),
                    &transport_tx,
                    &mut stop_rx,
                ),
            )
            .await
            .expect("inbound forwarding was stalled by TX admission"),
            UsbInboundOutcome::Complete
        );
        assert!(matches!(
            transport_rx.recv().await,
            Some(TransportMessage::Inbound(_))
        ));

        let _ = pump_stop_tx.send(());
        assert_eq!(pump.await.expect("pump join"), UsbTxPumpExit::StopRequested);
    }

    #[tokio::test]
    async fn writer_event_ahead_of_reader_tail_still_forwards_every_buffered_chunk() {
        let payload = vec![0xAA, kiss::FEND, 0xBB];
        let wire = kiss::frame(&payload);
        let split = wire.len() / 2;
        let (event_tx, mut events) = mpsc::channel(8);
        event_tx
            .send(UsbIoEvent::Writer(UsbWriterExit::Failed(
                "writer failed first".into(),
            )))
            .await
            .expect("writer exit");
        event_tx
            .send(UsbIoEvent::Read(wire[..split].to_vec()))
            .await
            .expect("first buffered chunk");
        event_tx
            .send(UsbIoEvent::Read(wire[split..].to_vec()))
            .await
            .expect("second buffered chunk");
        event_tx
            .send(UsbIoEvent::Reader(UsbReaderExit::Stopped))
            .await
            .expect("reader exit");
        drop(event_tx);

        let (_stop_tx, mut stop_rx) = mpsc::channel(1);
        let (transport_tx, mut transport_rx) = mpsc::channel(1);
        let received = AtomicU64::new(0);
        let mut inbound = UsbInboundState::new();

        assert_eq!(
            drain_usb_reader_tail(
                &mut events,
                &mut inbound,
                77,
                &received,
                &transport_tx,
                &mut stop_rx,
                tokio::time::Instant::now() + Duration::from_secs(1),
            )
            .await,
            UsbReadDrainOutcome::Drained
        );
        match transport_rx.recv().await.expect("forwarded packet") {
            TransportMessage::Inbound(packet) => {
                assert_eq!(packet.raw.as_ref(), payload);
                assert_eq!(packet.interface_id, 77);
            }
            _ => panic!("unexpected transport message"),
        }
        assert_eq!(received.load(Ordering::Relaxed), payload.len() as u64);

        drop(transport_rx);
        let second_payload = vec![1, 2, 3, 4];
        assert_eq!(
            forward_usb_read_chunk(
                &mut inbound,
                &kiss::frame(&second_payload),
                77,
                &received,
                &transport_tx,
                &mut stop_rx,
            )
            .await,
            UsbInboundOutcome::TransportClosed
        );
        assert_eq!(
            received.load(Ordering::Relaxed),
            (payload.len() + second_payload.len()) as u64,
            "legacy RX accounting occurs before transport send succeeds"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn full_transport_channel_cannot_extend_reader_drain_past_deadline() {
        use rns_transport::messages::InboundPacket;

        let payload = [4, 3, 2, 1];
        let (event_tx, mut events) = mpsc::channel(2);
        event_tx
            .send(UsbIoEvent::Read(kiss::frame(&payload)))
            .await
            .expect("reader data");
        event_tx
            .send(UsbIoEvent::Reader(UsbReaderExit::Stopped))
            .await
            .expect("reader exit");
        let (_stop_tx, mut stop_rx) = mpsc::channel(1);
        let (transport_tx, _transport_rx) = mpsc::channel(1);
        transport_tx
            .send(TransportMessage::Inbound(InboundPacket {
                raw: Bytes::new(),
                interface_id: 0,
                rssi: None,
                snr: None,
                q: None,
            }))
            .await
            .expect("fill transport channel");
        let received = AtomicU64::new(0);
        let deadline = tokio::time::Instant::now() + Duration::from_millis(250);

        assert_eq!(
            drain_usb_reader_tail(
                &mut events,
                &mut UsbInboundState::new(),
                77,
                &received,
                &transport_tx,
                &mut stop_rx,
                deadline,
            )
            .await,
            UsbReadDrainOutcome::DeadlineElapsed
        );
        assert_eq!(tokio::time::Instant::now(), deadline);
        assert_eq!(
            received.load(Ordering::Relaxed),
            payload.len() as u64,
            "legacy RX accounting still occurs before bounded transport send"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn completed_read_survives_writer_stop_with_capacity_one_event_stream() {
        struct CompletedRead {
            started: Arc<AtomicBool>,
            gate: Arc<(Mutex<bool>, Condvar)>,
        }

        impl UsbReaderBackend for CompletedRead {
            fn read(&mut self) -> Result<UsbReadResult, String> {
                self.started.store(true, Ordering::Release);
                let (lock, wake) = &*self.gate;
                let mut open = lock
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                while !*open {
                    open = wake
                        .wait(open)
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                }
                Ok(UsbReadResult::Data(vec![6, 7, 8]))
            }
        }

        let (event_tx, mut events) = mpsc::channel(1);
        event_tx
            .send(UsbIoEvent::Writer(UsbWriterExit::Failed(
                "writer failed".into(),
            )))
            .await
            .expect("fill capacity-one event stream");
        let running = Arc::new(AtomicBool::new(true));
        let started = Arc::new(AtomicBool::new(false));
        let gate = Arc::new((Mutex::new(false), Condvar::new()));
        let started_for_wait = started.clone();
        let gate_for_release = gate.clone();
        let reader_running = running.clone();
        let reader_events = event_tx.clone();
        let reader_task = tokio::task::spawn_blocking(move || {
            let exit = run_usb_reader(
                CompletedRead { started, gate },
                reader_events.clone(),
                reader_running,
                Arc::new(AtomicBool::new(true)),
                Arc::new(UsbReaderBoundary::new()),
            );
            let _ = reader_events.blocking_send(UsbIoEvent::Reader(exit.clone()));
            exit
        });

        tokio::time::timeout(Duration::from_secs(1), async {
            while !started_for_wait.load(Ordering::Acquire) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("reader did not begin completed read");

        running.store(false, Ordering::Release);
        let (lock, wake) = &*gate_for_release;
        *lock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = true;
        wake.notify_all();

        assert!(matches!(events.recv().await, Some(UsbIoEvent::Writer(_))));
        assert_eq!(events.recv().await, Some(UsbIoEvent::Read(vec![6, 7, 8])));
        assert_eq!(
            events.recv().await,
            Some(UsbIoEvent::Reader(UsbReaderExit::Stopped))
        );
        assert_eq!(
            reader_task.await.expect("reader join"),
            UsbReaderExit::Stopped
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn simultaneous_worker_completion_preserves_the_reader_tail() {
        struct SimultaneousWriter {
            barrier: Arc<std::sync::Barrier>,
        }

        impl UsbWriterBackend for SimultaneousWriter {
            fn transfer(
                &mut self,
                _bytes: &[u8],
                _timeout: Duration,
            ) -> Result<i32, UsbTransferError> {
                self.barrier.wait();
                Err(UsbTransferError::Backend("simultaneous writer exit".into()))
            }
        }

        struct SimultaneousReader {
            barrier: Arc<std::sync::Barrier>,
            sent: bool,
        }

        impl UsbReaderBackend for SimultaneousReader {
            fn read(&mut self) -> Result<UsbReadResult, String> {
                if !self.sent {
                    self.sent = true;
                    return Ok(UsbReadResult::Data(kiss::frame(&[7, 8, 9])));
                }
                self.barrier.wait();
                Err("simultaneous reader exit".into())
            }
        }

        let barrier = Arc::new(std::sync::Barrier::new(2));
        let events = Arc::new(Mutex::new(Vec::new()));
        let mut io = spawn_owned_usb_io(
            SimultaneousWriter {
                barrier: barrier.clone(),
            },
            SimultaneousReader {
                barrier,
                sent: false,
            },
            RecordingOwner {
                events,
                release_result: Ok(()),
            },
            Arc::new(AtomicBool::new(true)),
            2,
            8,
            Duration::from_millis(100),
        );
        io.writer
            .queue_packet_and_account(vec![0xAA], &Arc::new(AtomicU64::new(0)))
            .await
            .expect("writer admission");

        let (_stop_tx, mut stop_rx) = mpsc::channel(1);
        let (transport_tx, mut transport_rx) = mpsc::channel(1);
        let received = AtomicU64::new(0);
        let mut inbound = UsbInboundState::new();
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                match io.events.recv().await.expect("worker event stream") {
                    UsbIoEvent::Read(bytes) => {
                        assert_eq!(
                            forward_usb_read_chunk(
                                &mut inbound,
                                &bytes,
                                91,
                                &received,
                                &transport_tx,
                                &mut stop_rx,
                            )
                            .await,
                            UsbInboundOutcome::Complete
                        );
                    }
                    UsbIoEvent::Writer(_) => {
                        io.request_worker_stop();
                        assert_eq!(
                            drain_usb_reader_tail(
                                &mut io.events,
                                &mut inbound,
                                91,
                                &received,
                                &transport_tx,
                                &mut stop_rx,
                                tokio::time::Instant::now() + Duration::from_secs(1),
                            )
                            .await,
                            UsbReadDrainOutcome::Drained
                        );
                        break;
                    }
                    UsbIoEvent::Reader(_) => break,
                }
            }
        })
        .await
        .expect("simultaneous completion did not settle");

        match transport_rx.recv().await.expect("forwarded reader tail") {
            TransportMessage::Inbound(packet) => assert_eq!(packet.raw.as_ref(), [7, 8, 9]),
            _ => panic!("unexpected transport message"),
        }
        assert_eq!(received.load(Ordering::Relaxed), 3);
        let _ = io
            .shutdown(None, Duration::from_millis(20), Duration::from_secs(1))
            .await;
    }

    #[tokio::test]
    async fn explicit_stop_preempts_buffered_reader_drain() {
        let (event_tx, mut events) = mpsc::channel(2);
        event_tx
            .send(UsbIoEvent::Read(kiss::frame(&[1, 2, 3])))
            .await
            .expect("buffered frame");
        event_tx
            .send(UsbIoEvent::Reader(UsbReaderExit::Stopped))
            .await
            .expect("reader exit");
        drop(event_tx);
        let (stop_tx, mut stop_rx) = mpsc::channel(1);
        stop_tx.send(()).await.expect("stop signal");
        let (transport_tx, mut transport_rx) = mpsc::channel(1);
        let received = AtomicU64::new(0);

        assert_eq!(
            drain_usb_reader_tail(
                &mut events,
                &mut UsbInboundState::new(),
                9,
                &received,
                &transport_tx,
                &mut stop_rx,
                tokio::time::Instant::now() + Duration::from_secs(1),
            )
            .await,
            UsbReadDrainOutcome::StopRequested
        );
        assert!(transport_rx.try_recv().is_err());
        assert_eq!(received.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn rejected_or_stop_preempted_packet_admission_does_not_count_tx() {
        let rejected_queue = UsbWriteQueue::new(1);
        rejected_queue.cancel_and_wake();
        let rejected_writer = UsbWriterHandle {
            queue: rejected_queue,
        };
        let rejected_bytes = Arc::new(AtomicU64::new(0));
        assert!(
            rejected_writer
                .queue_packet_and_account(vec![1, 2, 3], &rejected_bytes)
                .await
                .is_err()
        );
        assert_eq!(rejected_bytes.load(Ordering::Relaxed), 0);

        let blocked_writer = UsbWriterHandle {
            queue: UsbWriteQueue::new(0),
        };
        let preempted_bytes = Arc::new(AtomicU64::new(0));
        let (stop_tx, mut stop_rx) = mpsc::channel(1);
        stop_tx.send(()).await.expect("stop signal");
        let admitted = tokio::select! {
            biased;
            _ = stop_rx.recv() => false,
            result = blocked_writer.queue_packet_and_account(
                vec![4, 5, 6],
                &preempted_bytes,
            ) => result.is_ok(),
        };
        assert!(!admitted);
        assert_eq!(preempted_bytes.load(Ordering::Relaxed), 0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn workers_are_joined_before_release_and_release_failure_still_closes() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let mut writer = ScriptedWriter::new([Ok(3)]);
        writer.events = Some(events.clone());
        let io = spawn_owned_usb_io(
            writer,
            IdleReader {
                polls: Arc::new(AtomicUsize::new(0)),
                events: Some(events.clone()),
            },
            RecordingOwner {
                events: events.clone(),
                release_result: Err("release false".into()),
            },
            Arc::new(AtomicBool::new(true)),
            4,
            4,
            Duration::from_millis(100),
        );
        let shutdown = io
            .shutdown(
                Some(vec![1, 2, 3]),
                Duration::from_millis(500),
                Duration::from_secs(1),
            )
            .await;
        let events = events
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        let release = events.iter().position(|event| *event == "release").unwrap();
        let close = events.iter().position(|event| *event == "close").unwrap();
        assert!(
            events
                .iter()
                .position(|event| *event == "writer_dropped")
                .unwrap()
                < release
        );
        assert!(
            events
                .iter()
                .position(|event| *event == "reader_dropped")
                .unwrap()
                < release
        );
        assert!(release < close);
        assert!(shutdown.report.release_interface.as_ref().unwrap().is_err());
        assert!(shutdown.report.close_connection.as_ref().unwrap().is_ok());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn unproven_close_retains_owner_and_reports_quarantine() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let io = spawn_owned_usb_io(
            ScriptedWriter::new([]),
            IdleReader {
                polls: Arc::new(AtomicUsize::new(0)),
                events: None,
            },
            UnclosedOwner {
                events: events.clone(),
            },
            Arc::new(AtomicBool::new(true)),
            2,
            2,
            Duration::from_millis(100),
        );
        let shutdown = io
            .shutdown(None, Duration::from_millis(20), Duration::from_secs(1))
            .await;
        assert_eq!(
            shutdown.report.disposition,
            UsbCleanupDisposition::Quarantined
        );
        assert!(shutdown.report.is_quarantined());
        assert!(shutdown.report.as_result().is_err());
        assert_eq!(
            *events
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
            vec!["release", "close_failed", "quarantined"]
        );
    }

    struct BlockingReader {
        gate: Arc<(Mutex<bool>, Condvar)>,
        started: Arc<AtomicBool>,
        dropped: Option<Arc<AtomicBool>>,
    }

    impl UsbReaderBackend for BlockingReader {
        fn read(&mut self) -> Result<UsbReadResult, String> {
            self.started.store(true, Ordering::Release);
            let (lock, wake) = &*self.gate;
            let mut open = lock
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            while !*open {
                open = wake
                    .wait(open)
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
            }
            Ok(UsbReadResult::Idle)
        }
    }

    impl Drop for BlockingReader {
        fn drop(&mut self) {
            if let Some(dropped) = &self.dropped {
                dropped.store(true, Ordering::Release);
            }
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn missed_join_deadline_quarantines_without_release_or_close() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let gate = Arc::new((Mutex::new(false), Condvar::new()));
        let started = Arc::new(AtomicBool::new(false));
        let io = spawn_owned_usb_io(
            ScriptedWriter::new([]),
            BlockingReader {
                gate: gate.clone(),
                started: started.clone(),
                dropped: None,
            },
            RecordingOwner {
                events: events.clone(),
                release_result: Ok(()),
            },
            Arc::new(AtomicBool::new(true)),
            2,
            2,
            Duration::from_millis(100),
        );
        tokio::time::timeout(Duration::from_secs(1), async {
            while !started.load(Ordering::Acquire) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("blocking reader did not start");
        let shutdown = io
            .shutdown(None, Duration::from_millis(10), Duration::from_millis(20))
            .await;
        assert_eq!(
            shutdown.report.disposition,
            UsbCleanupDisposition::Quarantined
        );
        assert_eq!(
            *events
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
            vec!["quarantined"]
        );
        let (lock, wake) = &*gate;
        *lock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = true;
        wake.notify_all();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn outer_owner_cancellation_wakes_joins_and_quarantines_without_cleanup() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let gate = Arc::new((Mutex::new(false), Condvar::new()));
        let started = Arc::new(AtomicBool::new(false));
        let dropped = Arc::new(AtomicBool::new(false));
        let io = spawn_owned_usb_io(
            ScriptedWriter::new([]),
            BlockingReader {
                gate: gate.clone(),
                started: started.clone(),
                dropped: Some(dropped.clone()),
            },
            RecordingOwner {
                events: events.clone(),
                release_result: Ok(()),
            },
            Arc::new(AtomicBool::new(true)),
            2,
            2,
            Duration::from_millis(100),
        );
        tokio::time::timeout(Duration::from_secs(1), async {
            while !started.load(Ordering::Acquire) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("blocking reader did not start");

        let (task_started_tx, task_started_rx) = oneshot::channel();
        let owner_task = tokio::spawn(async move {
            let _io = io;
            let _ = task_started_tx.send(());
            std::future::pending::<()>().await;
        });
        task_started_rx.await.expect("owner task did not start");
        owner_task.abort();
        let _ = owner_task.await;
        assert_eq!(
            *events
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
            vec!["quarantined"]
        );
        let (lock, wake) = &*gate;
        *lock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = true;
        wake.notify_all();
        tokio::time::timeout(Duration::from_secs(1), async {
            while !dropped.load(Ordering::Acquire) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("cancelled reader worker was not joined");
        assert!(
            !events
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .iter()
                .any(|event| matches!(*event, "release" | "close"))
        );
    }

    #[test]
    fn lease_table_serialises_open_activate_release_and_permanent_quarantine() {
        let mut leases = UsbLeaseTable::default();
        leases.reserve_opening("device").expect("opening lease");
        assert_eq!(leases.state("device"), Some((UsbLeaseKind::Opening, 0)));
        assert!(leases.reserve_opening("device").is_err());
        leases
            .release_opening("device")
            .expect("proven setup close releases Opening");
        assert_eq!(leases.state("device"), None);

        leases.reserve_opening("device").expect("second opening");
        leases.activate("device").expect("activate");
        assert_eq!(leases.state("device"), Some((UsbLeaseKind::Active, 0)));
        assert!(leases.reserve_opening("device").is_err());
        leases
            .release_active("device")
            .expect("proven runtime close releases Active");
        assert_eq!(leases.state("device"), None);

        leases.reserve_opening("device").expect("third opening");
        leases.quarantine("device", "first owner");
        leases.quarantine("device", "second owner");
        assert_eq!(leases.state("device"), Some((UsbLeaseKind::Quarantined, 2)));
        assert!(leases.reserve_opening("device").is_err());
        assert!(leases.release_opening("device").is_err());
        assert!(leases.release_active("device").is_err());
    }
}
