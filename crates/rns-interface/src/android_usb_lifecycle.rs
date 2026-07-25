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
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc, oneshot};
use tokio::task::JoinHandle;

use crate::kiss;
use crate::rnode;
use crate::traits::InterfaceId;
use rns_transport::messages::TransportMessage;

const MIN_TRANSFER_TIMEOUT: Duration = Duration::from_millis(1);

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
            return Err(format!("Android USB device {device_name} is {state}"));
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
            Some(UsbLeaseState::Active) => Err(format!(
                "Android USB device {device_name} is already active"
            )),
            Some(UsbLeaseState::Quarantined(_)) => Err(format!(
                "Android USB device {device_name} is permanently quarantined"
            )),
            None => Err(format!(
                "Android USB device {device_name} has no opening reservation"
            )),
        }
    }

    pub(crate) fn release_opening(&mut self, device_name: &str) -> Result<(), String> {
        match self.devices.get(device_name) {
            Some(UsbLeaseState::Opening) => {
                self.devices.remove(device_name);
                Ok(())
            }
            Some(UsbLeaseState::Active) => Err(format!(
                "Android USB device {device_name} became active before opening release"
            )),
            Some(UsbLeaseState::Quarantined(_)) => Err(format!(
                "Android USB device {device_name} is permanently quarantined"
            )),
            None => Err(format!(
                "Android USB device {device_name} has no opening reservation"
            )),
        }
    }

    pub(crate) fn release_active(&mut self, device_name: &str) -> Result<(), String> {
        match self.devices.get(device_name) {
            Some(UsbLeaseState::Active) => {
                self.devices.remove(device_name);
                Ok(())
            }
            Some(UsbLeaseState::Opening) => Err(format!(
                "Android USB device {device_name} never became active"
            )),
            Some(UsbLeaseState::Quarantined(_)) => Err(format!(
                "Android USB device {device_name} is permanently quarantined"
            )),
            None => Err(format!(
                "Android USB device {device_name} has no active lease"
            )),
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
    Initialise,
    Packet,
    Detach,
}

impl UsbWritePhase {
    const fn label(self) -> &'static str {
        match self {
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
        }
    }
}

struct UsbWriteRequest {
    phase: UsbWritePhase,
    bytes: Vec<u8>,
    deadline: Option<Instant>,
    acknowledgement: Option<oneshot::Sender<Result<(), UsbWriteFailure>>>,
    _permit: Option<OwnedSemaphorePermit>,
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

    async fn enqueue(
        &self,
        phase: UsbWritePhase,
        bytes: Vec<u8>,
        deadline: Option<Instant>,
        acknowledgement: Option<oneshot::Sender<Result<(), UsbWriteFailure>>>,
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
}

impl UsbInboundState {
    pub(crate) fn new() -> Self {
        Self {
            deframer: kiss::RawKissDeframer::new(),
            last_rssi: None,
            last_snr: None,
        }
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
    while running.load(Ordering::Acquire) {
        let Some(request) = queue.recv() else {
            return UsbWriterExit::Stopped;
        };
        if !running.load(Ordering::Acquire) {
            return UsbWriterExit::Stopped;
        }
        let phase = request.phase;
        let result = write_request(&mut backend, &request, default_timeout);
        if let Some(acknowledgement) = request.acknowledgement {
            let _ = acknowledgement.send(result.clone());
        }
        if let Err(failure) = result {
            online.store(false, Ordering::Release);
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

fn run_usb_reader<R>(
    mut backend: R,
    event_tx: mpsc::Sender<UsbIoEvent>,
    running: Arc<AtomicBool>,
    online: Arc<AtomicBool>,
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
            Ok(UsbReadResult::Idle) => {}
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
        let deadline = Instant::now() + timeout;
        let (acknowledgement, result) = oneshot::channel();
        self.queue
            .enqueue(phase, bytes, Some(deadline), Some(acknowledgement))
            .await?;
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

    pub(crate) async fn queue_packet_and_account(
        &self,
        bytes: Vec<u8>,
        transmitted_bytes: &AtomicU64,
    ) -> Result<(), UsbWriteFailure> {
        let length = bytes.len() as u64;
        self.queue
            .enqueue(UsbWritePhase::Packet, bytes, None, None)
            .await?;
        transmitted_bytes.fetch_add(length, Ordering::Relaxed);
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum UsbTxPumpExit {
    StopRequested,
    ApplicationClosed,
    WriterRejected(UsbWriteFailure),
}

/// Independent application-to-USB pump. Inbound transport backpressure cannot
/// stall writer admission, and a full writer queue cannot stall inbound
/// forwarding in the driver task.
pub(crate) async fn run_usb_tx_pump(
    mut application_rx: mpsc::Receiver<Bytes>,
    writer: UsbWriterHandle,
    transmitted_bytes: Arc<AtomicU64>,
    mut stop: oneshot::Receiver<()>,
) -> UsbTxPumpExit {
    loop {
        let payload = tokio::select! {
            biased;
            _ = &mut stop => return UsbTxPumpExit::StopRequested,
            payload = application_rx.recv() => payload,
        };
        let Some(payload) = payload else {
            return UsbTxPumpExit::ApplicationClosed;
        };
        let frame = kiss::frame(&payload);
        let queued = tokio::select! {
            biased;
            _ = &mut stop => return UsbTxPumpExit::StopRequested,
            result = writer.queue_packet_and_account(frame, transmitted_bytes.as_ref()) => result,
        };
        if let Err(error) = queued {
            return UsbTxPumpExit::WriterRejected(error);
        }
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
    let reader_task = tokio::task::spawn_blocking(move || {
        let exit = run_usb_reader(
            reader_backend,
            event_tx.clone(),
            reader_running,
            reader_online,
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
        self.writer.queue.cancel_and_wake();
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
        let transmitted = AtomicU64::new(0);
        for packet in [vec![1], vec![2, 2], vec![3, 3, 3]] {
            io.writer
                .queue_packet_and_account(packet, &transmitted)
                .await
                .expect("packet queue");
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
            let _ = io
                .shutdown(None, Duration::from_millis(20), Duration::from_secs(1))
                .await;
        }
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
        let transmitted = AtomicU64::new(0);
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
        let (pump_stop_tx, pump_stop_rx) = oneshot::channel();
        let transmitted = Arc::new(AtomicU64::new(0));
        let expected_frame_length = kiss::frame(&[4, 5, 6]).len() as u64;
        let pump = tokio::spawn(run_usb_tx_pump(
            application_rx,
            UsbWriterHandle {
                queue: UsbWriteQueue::new(1),
            },
            transmitted.clone(),
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
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn blocked_tx_admission_does_not_stall_inbound_forwarding() {
        let (application_tx, application_rx) = mpsc::channel(1);
        let (pump_stop_tx, pump_stop_rx) = oneshot::channel();
        let transmitted = Arc::new(AtomicU64::new(0));
        let pump = tokio::spawn(run_usb_tx_pump(
            application_rx,
            UsbWriterHandle {
                queue: UsbWriteQueue::new(0),
            },
            transmitted.clone(),
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
            .queue_packet_and_account(vec![0xAA], &AtomicU64::new(0))
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
        let rejected_bytes = AtomicU64::new(0);
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
        let preempted_bytes = AtomicU64::new(0);
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
