//! Reticulum runtime singleton, init and lifecycle. Three operating modes:
//! **Shared** owns hardware and serves RPC to siblings; **Client** connects
//! to a Shared instance over a local socket; **Standalone** owns its
//! interfaces and exposes no IPC. Python: `RNS/Reticulum.py`.

use std::collections::HashMap;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};

use std::time::Duration;

use bytes::Bytes;
use tokio::sync::{Mutex, Notify, mpsc, oneshot, watch};

use crate::config::{Config, ConfigError, ConfigSection};
use crate::constants::*;
use crate::interface_factory;
use crate::interface_registry::{
    DrainStart, ExactShutdownStart, InterfaceKind, InterfaceRegistration,
    InterfaceRegistrationRejection, InterfaceRegistry, InterfaceShutdown,
    InterfaceShutdownStrategy, InterfaceSpawnPermit, RNodeObservationLookupError, ShutdownStart,
};
use crate::jobs::{Job, JobScheduler};
use crate::lifecycle::ShutdownSignal;
use crate::link_client::LinkClient;
use crate::link_manager::LinkManager;
use crate::link_session::{LinkSession, LinkSessionConfig, LinkSessionError};
use crate::platform::{StoragePaths, resolve_config_dir};
use rns_identity::destination::{
    DestType, Destination, DestinationError, DestinationPacketError, DestinationPacketOptions,
    Direction,
};
use rns_identity::identity::Identity;
use rns_transport::await_path::{AwaitPathError, await_path};
use rns_transport::constants::DESTINATION_TIMEOUT;
use rns_transport::discovery::{
    Announcer, BLACKHOLE_INITIAL_WAIT, BLACKHOLE_JOB_INTERVAL, BLACKHOLE_SOURCE_TIMEOUT,
    BLACKHOLE_UPDATE_INTERVAL, BlackholeSubscriberState, DiscoveredInterface, DiscoveryDecryptor,
    DiscoveryInterfaceConfig, DiscoveryStamper, DiscoveryStore, ReceiverConfig, discovery_hash,
};
use rns_transport::messages::{
    AnnounceHandlerEvent, AnnounceHandlerId, OutboundDispatchResult, OutboundRequest,
    PathRequestOptions, RecalledDestinationRpcEntry, ReceiptUpdate, TrackedReceiptRegistration,
    TransportMessage, TransportQuery, TransportQueryResponse,
};

static INSTANCE: OnceLock<ReticulumHandle> = OnceLock::new();
pub const DEFAULT_ANNOUNCE_SUBSCRIPTION_CAPACITY: usize = 128;

#[derive(Clone)]
struct InterfaceControlMetadata {
    registry_owner: u64,
    role: rns_transport::messages::InterfaceRole,
    ingress_overrides: rns_transport::ingress::IngressOverrides,
    // Parent IFAC, inherited by accepted child connections (Python parity:
    // spawned interfaces copy the listener's ifac_size/netname/netkey).
    ifac_key: Option<[u8; 64]>,
    ifac_size: usize,
}

type InterfaceControlMap = Arc<std::sync::Mutex<HashMap<u64, InterfaceControlMetadata>>>;

#[derive(Default)]
struct TransportCompletion {
    stopped: AtomicBool,
    notify: Notify,
}

const RUNTIME_INTERFACE_DRAIN_DEADLINE: Duration = Duration::from_secs(10);

/// One cancellation-independent shutdown operation shared by explicit API
/// callers and the process-signal watcher. The coordinator intentionally owns
/// the accepted-child pump and all runtime-local interface ownership; callers
/// only wait on its completion and cannot cancel the cleanup by disappearing.
#[derive(Clone)]
struct RuntimeShutdownCoordinator {
    inner: Arc<RuntimeShutdownInner>,
}

struct RuntimeShutdownInner {
    started: AtomicBool,
    completed: AtomicBool,
    notify: Notify,
    shutdown: ShutdownSignal,
    transport_tx: mpsc::Sender<TransportMessage>,
    transport_completion: Arc<TransportCompletion>,
    interface_controls: InterfaceControlMap,
    interface_registry: InterfaceRegistry,
    accepted_child_pump: std::sync::Mutex<Option<tokio::task::JoinHandle<()>>>,
}

impl RuntimeShutdownCoordinator {
    fn new(
        shutdown: ShutdownSignal,
        transport_tx: mpsc::Sender<TransportMessage>,
        transport_completion: Arc<TransportCompletion>,
        interface_controls: InterfaceControlMap,
        interface_registry: InterfaceRegistry,
    ) -> Self {
        Self {
            inner: Arc::new(RuntimeShutdownInner {
                started: AtomicBool::new(false),
                completed: AtomicBool::new(false),
                notify: Notify::new(),
                shutdown,
                transport_tx,
                transport_completion,
                interface_controls,
                interface_registry,
                accepted_child_pump: std::sync::Mutex::new(None),
            }),
        }
    }

    fn install_accepted_child_pump(&self, pump: tokio::task::JoinHandle<()>) {
        let mut slot = self
            .inner
            .accepted_child_pump
            .lock()
            .expect("accepted child pump mutex poisoned");
        debug_assert!(slot.is_none(), "accepted child pump installed twice");
        *slot = Some(pump);
    }

    fn is_started(&self) -> bool {
        self.inner.started.load(Ordering::Acquire)
    }

    fn start(&self) {
        self.inner.shutdown.trigger();
        if self
            .inner
            .started
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            let coordinator = self.clone();
            tokio::spawn(async move {
                coordinator.run().await;
            });
        }
    }

    async fn start_and_wait(&self) {
        self.start();
        self.wait().await;
    }

    async fn wait(&self) {
        loop {
            let notified = self.inner.notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.inner.completed.load(Ordering::Acquire) {
                return;
            }
            notified.await;
        }
    }

    async fn run(&self) {
        let drain = match self.inner.interface_registry.begin_drain() {
            DrainStart::Acquired(drain) => drain,
            DrainStart::AlreadyDraining | DrainStart::Closed => {
                self.inner.transport_completion.wait().await;
                self.mark_completed();
                return;
            }
        };
        // The signal also stops interface producers and makes the retained
        // accepted-child pump close its receiver. Joining that exact pump
        // prevents a late accepted socket from entering registration after
        // admission has closed.
        self.inner.shutdown.trigger();
        let pump = self
            .inner
            .accepted_child_pump
            .lock()
            .expect("accepted child pump mutex poisoned")
            .take();
        if let Some(pump) = pump {
            let _ = pump.await;
        }

        // A physical spawn begins before it has a registry record. Permits
        // bridge that gap and remain held through registration or exact
        // rejection cleanup, so shutdown cannot complete ahead of a late
        // spawned interface.
        self.inner.interface_registry.wait_for_spawn_permits().await;

        let (mut shutdowns, waiters, mut abandoned_registrations) = drain.into_parts();
        // Exact device owners are all signalled before any sequential join,
        // so a slow first device cannot delay another device's detach path.
        for shutdown in &shutdowns {
            shutdown.request_driver_shutdown();
        }

        #[cfg(feature = "ble")]
        if shutdowns
            .iter()
            .any(|shutdown| shutdown.kind() == InterfaceKind::BlePeer)
        {
            // BLE Peer remains a process singleton. Stop it exactly once for
            // this runtime drain, then join each registry-owned façade below.
            rns_interface::ble_peer::stop_ble_peer_interface().await;
        }

        // The shared absolute deadline applies to registry-owned interface
        // task joins. Process-singleton BLE teardown above is a distinct
        // producer stop phase and must finish rather than be cancellation-
        // truncated half way through platform cleanup.
        let deadline = tokio::time::Instant::now() + RUNTIME_INTERFACE_DRAIN_DEADLINE;

        for shutdown in &mut shutdowns {
            shutdown.mark_offline();
            let _ = shutdown.stop_task_until(deadline).await;
        }
        for (id, owner) in waiters {
            if let Some(abandoned) = self
                .inner
                .interface_registry
                .wait_or_claim_abandoned(id, owner)
                .await
            {
                abandoned_registrations.push(abandoned);
            }
        }

        // Abandoned Pending/Stopping owners have completed their task join
        // but may have published an actor entry before their transaction was
        // cancelled or unwound. Admission is already closed, so order a
        // conservative exact-ID rollback before releasing each tombstone.
        for (id, owner) in abandoned_registrations {
            remove_interface_control_if_owner(&self.inner.interface_controls, id, owner);
            if !self
                .inner
                .transport_completion
                .stopped
                .load(Ordering::Acquire)
            {
                let _ = self
                    .inner
                    .transport_tx
                    .send(TransportMessage::DeregisterInterface { id })
                    .await;
            }
            self.inner.interface_registry.finish_abandoned(id, owner);
        }

        // Do not deregister active interfaces here. Transport shutdown owns
        // the synchronous persistence snapshot; retaining offline interface
        // bindings until that snapshot preserves route/tunnel state. Pending
        // registration rollback may still enqueue its own ordered deregister.
        if !self
            .inner
            .transport_completion
            .stopped
            .load(Ordering::Acquire)
        {
            let _ = self
                .inner
                .transport_tx
                .send(TransportMessage::Shutdown)
                .await;
        }
        self.inner.transport_completion.wait().await;

        // Once persistence is complete the runtime is permanently closed;
        // exact-owner leases and shutdown-only tombstones can be discarded
        // without opening an ABA window.
        let shutdown_tokens: Vec<_> = shutdowns.iter().map(InterfaceShutdown::token).collect();
        self.inner
            .interface_registry
            .finish_drain_when_owned(&shutdown_tokens)
            .await;
        self.inner
            .interface_controls
            .lock()
            .expect("interface_controls mutex poisoned")
            .clear();
        drop(shutdowns);
        self.mark_completed();
    }

    fn mark_completed(&self) {
        self.inner.completed.store(true, Ordering::Release);
        self.inner.notify.notify_waiters();
    }
}

struct InitShutdownGuard {
    coordinator: Option<RuntimeShutdownCoordinator>,
}

impl InitShutdownGuard {
    fn disarm(mut self) {
        self.coordinator.take();
    }
}

impl Drop for InitShutdownGuard {
    fn drop(&mut self) {
        if let Some(coordinator) = self.coordinator.take() {
            coordinator.start();
        }
    }
}

impl TransportCompletion {
    fn mark_stopped(&self) {
        self.stopped.store(true, Ordering::Release);
        self.notify.notify_waiters();
    }

    async fn wait(&self) {
        loop {
            let notified = self.notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.stopped.load(Ordering::Acquire) {
                return;
            }
            notified.await;
        }
    }
}

/// Guarantees completion signalling even if `TransportActor::run` exits or
/// unwinds. An exit not initiated by the runtime coordinator also begins the
/// same ownership drain used for explicit and process-signal shutdown.
struct TransportActorCompletionGuard {
    completion: Arc<TransportCompletion>,
    coordinator: RuntimeShutdownCoordinator,
}

impl Drop for TransportActorCompletionGuard {
    fn drop(&mut self) {
        let unexpected = !self.coordinator.is_started();
        self.completion.mark_stopped();
        if unexpected {
            if std::thread::panicking() {
                tracing::error!("transport actor unwound; draining runtime ownership");
            } else {
                // Dropping the last runtime handle closes the actor's command
                // channel and is a normal RAII shutdown path for short-lived
                // CLI tools. Keep it observable without polluting stderr at
                // the default log level.
                tracing::debug!("transport command channel closed; draining runtime ownership");
            }
            self.coordinator.start();
        }
    }
}

#[derive(Clone)]
pub struct ReticulumHandle {
    pub transport_tx: mpsc::Sender<TransportMessage>,
    pub config_dir: PathBuf,
    pub instance_mode: InstanceMode,
    pub interface_configs: Vec<interface_factory::InterfaceConfig>,
    /// ID allocator for interfaces spawned dynamically after init.
    pub id_gen: Arc<AtomicU64>,
    /// Used by server-style interfaces to register per-client sub-handles.
    pub handle_tx: mpsc::Sender<rns_interface::traits::InterfaceHandle>,
    interface_controls: InterfaceControlMap,
    interface_registry: InterfaceRegistry,
    pub socket_base: PathBuf,
    pub config: ReticulumConfig,
    /// Mobile builds throttle tick rates when the app is backgrounded.
    pub is_foreground: Arc<AtomicBool>,
    pub shutdown: ShutdownSignal,
    /// Wire-facing transport identity (Python `Transport.identity`): on
    /// non-transport nodes this is a fresh per-boot identity unless
    /// `static_transport_identity` is set (Transport.py:234-238); RPC-key
    /// derivation stays on the persisted identity.
    pub transport_identity: Arc<Identity>,
    pub network_identity: Option<Arc<Identity>>,
    /// Present even when `discover_interfaces = No` so a downstream can
    /// still install a stamper and start publishing.
    pub discovery: Arc<DiscoveryRuntime>,
    startup_rnode_runtimes: Vec<StartupRNodeRuntime>,
    shutdown_coordinator: RuntimeShutdownCoordinator,
    started_at: std::time::Instant,
}

/// Identity and announce metadata recalled from the live transport cache.
#[derive(Clone)]
pub struct RecalledDestination {
    pub destination_hash: [u8; 16],
    pub identity: Identity,
    pub app_data: Option<Vec<u8>>,
    pub ratchet: Option<[u8; 32]>,
    pub hops: u8,
    pub last_heard: std::time::SystemTime,
}

/// Owned, bounded stream of validated announce-handler events.
///
/// Dropping the subscription requests exact deregistration. If the transport
/// command queue is full, the closed event receiver is reaped on the next
/// announce dispatch.
pub struct AnnounceSubscription {
    id: Option<AnnounceHandlerId>,
    events: mpsc::Receiver<AnnounceHandlerEvent>,
    dropped_events: Arc<AtomicU64>,
    transport_tx: mpsc::Sender<TransportMessage>,
}

impl AnnounceSubscription {
    pub fn events(&mut self) -> &mut mpsc::Receiver<AnnounceHandlerEvent> {
        &mut self.events
    }

    pub async fn recv(&mut self) -> Option<AnnounceHandlerEvent> {
        self.events.recv().await
    }

    /// Number of matching announces omitted because this subscription's
    /// bounded event channel was full.
    pub fn dropped_events(&self) -> u64 {
        self.dropped_events.load(Ordering::Relaxed)
    }

    /// Deterministically deregister this subscription.
    pub async fn close(&mut self) -> Result<bool, AnnounceSubscriptionError> {
        let Some(id) = self.id else {
            return Ok(false);
        };
        let (result_tx, result_rx) = tokio::sync::oneshot::channel();
        self.transport_tx
            .send(TransportMessage::DeregisterAnnounceSubscription {
                id,
                result_tx: Some(result_tx),
            })
            .await
            .map_err(|_| AnnounceSubscriptionError::TransportUnavailable)?;
        self.id = None;
        result_rx
            .await
            .map_err(|_| AnnounceSubscriptionError::TransportUnavailable)
    }
}

impl Drop for AnnounceSubscription {
    fn drop(&mut self) {
        if let Some(id) = self.id.take() {
            let _ = self
                .transport_tx
                .try_send(TransportMessage::DeregisterAnnounceSubscription {
                    id,
                    result_tx: None,
                });
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum AnnounceSubscriptionError {
    #[error("announce subscription capacity must be greater than zero")]
    InvalidCapacity,
    #[error("transport channel is unavailable")]
    TransportUnavailable,
}

/// Typed snapshot of Reticulum interface and aggregate traffic state.
#[derive(Debug, Clone)]
pub struct InterfaceStats {
    pub interfaces: Vec<rns_transport::messages::InterfaceStatRpcEntry>,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_rate: u64,
    pub tx_rate: u64,
    pub transport_id: Option<[u8; 16]>,
    pub network_id: Option<[u8; 16]>,
    pub transport_uptime: Option<Duration>,
    pub probe_responder: Option<[u8; 16]>,
    pub rss_bytes: Option<u64>,
}

/// Observation-only capability for one exact runtime-owned RNode driver.
///
/// The subscription is captured from one exact driver (either at its
/// successful registration transaction or from its active registry record)
/// and never resolves the interface ID again. It therefore cannot follow a
/// later same-ID replacement and carries no shutdown or configuration
/// authority.
#[derive(Clone, Debug)]
pub struct RNodeRuntimeObserver {
    interface_id: rns_interface::traits::InterfaceId,
    state: rns_interface::rnode::RNodeDriverSubscription,
}

/// Exact observation returned atomically with a newly registered RNode.
///
/// `online` is the legacy shared online/enabled flag retained for compatibility.
/// It is not authoritative physical state or protocol readiness. Use `observer`
/// for protocol state and [`RNodeRuntimeObserver::await_ready`] when readiness
/// is required.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct SpawnedRNodeRuntime {
    pub interface_id: rns_interface::traits::InterfaceId,
    pub online: Arc<AtomicBool>,
    pub observer: RNodeRuntimeObserver,
}

/// Observation-only record for one RNode created from startup configuration.
///
/// Records are captured from the exact successful registration transaction;
/// they never resolve through an interface name or a later stats snapshot.
/// Duplicate configured names therefore remain distinct exact registrations.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct StartupRNodeRuntime {
    /// Interface section name from the Reticulum configuration.
    pub configured_name: String,
    /// Runtime-local ID returned by the successful registration transaction.
    pub interface_id: rns_interface::traits::InterfaceId,
    /// Observer permanently bound to that registration's RNode driver.
    pub observer: RNodeRuntimeObserver,
}

impl RNodeRuntimeObserver {
    /// Runtime-local interface ID associated with this exact observation.
    pub fn interface_id(&self) -> rns_interface::traits::InterfaceId {
        self.interface_id
    }

    /// Return the latest privacy-safe snapshot without waiting.
    pub fn snapshot(&self) -> Arc<rns_interface::rnode::RNodeRuntimeSnapshot> {
        self.state.snapshot()
    }

    /// Wait for the next publication from this exact driver's observation.
    ///
    /// This is a latest-state watch, not a lossless event stream: if multiple
    /// snapshots are published before the caller polls again, they may be
    /// coalesced and the returned [`Arc`] contains the newest observed state.
    /// Each cloned observer has an independent seen-version cursor. `None`
    /// means the exact driver's publisher has closed; [`Self::snapshot`] still
    /// returns the last published state after closure.
    ///
    /// Waiting for, cancelling, or dropping this observation has no effect on
    /// the driver or registry and grants no shutdown or configuration authority.
    pub async fn changed(&mut self) -> Option<Arc<rns_interface::rnode::RNodeRuntimeSnapshot>> {
        self.state.changed().await
    }

    /// Wait up to `timeout` for complete protocol readiness.
    ///
    /// One absolute deadline spans reconnects. Dropping this future has no
    /// effect on the driver or registry.
    pub async fn await_ready(
        &self,
        timeout: Duration,
    ) -> Result<Arc<rns_interface::rnode::RNodeRuntimeSnapshot>, RNodeReadinessError> {
        let deadline = tokio::time::Instant::now().checked_add(timeout);
        let mut state = self.state.clone();
        loop {
            let snapshot = state.snapshot();
            if let Some(result) = rnode_readiness_result(snapshot) {
                return result;
            }

            let Some(changed) = await_before_rnode_deadline(deadline, state.changed()).await else {
                // Once the absolute deadline wins, a concurrent late Ready
                // publication remains visible in `last` but cannot turn this
                // bounded wait into success.
                return Err(RNodeReadinessError::Timeout {
                    last: state.snapshot(),
                });
            };
            if changed.is_none() {
                let last = state.snapshot();
                if let Some(result) = rnode_readiness_result(last.clone()) {
                    return result;
                }
                return Err(RNodeReadinessError::ObservationClosed { last });
            }
        }
    }
}

async fn await_before_rnode_deadline<F>(
    deadline: Option<tokio::time::Instant>,
    future: F,
) -> Option<F::Output>
where
    F: Future,
{
    match deadline {
        Some(deadline) => {
            tokio::select! {
                biased;
                _ = tokio::time::sleep_until(deadline) => None,
                output = future => Some(output),
            }
        }
        None => Some(future.await),
    }
}

fn rnode_readiness_result(
    snapshot: Arc<rns_interface::rnode::RNodeRuntimeSnapshot>,
) -> Option<Result<Arc<rns_interface::rnode::RNodeRuntimeSnapshot>, RNodeReadinessError>> {
    use rns_interface::rnode::RNodeRuntimePhase;

    match snapshot.phase {
        RNodeRuntimePhase::Ready if snapshot.connection_generation != 0 => Some(Ok(snapshot)),
        RNodeRuntimePhase::ShuttingDown => {
            Some(Err(RNodeReadinessError::ShuttingDown { last: snapshot }))
        }
        RNodeRuntimePhase::Stopped => Some(Err(RNodeReadinessError::Stopped { last: snapshot })),
        _ => None,
    }
}

/// Failure to acquire an observation of the current runtime-owned RNode.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[non_exhaustive]
pub enum RNodeRuntimeLookupError {
    #[error("interface {interface_id} is not owned by this shared-instance client")]
    NotOwned {
        interface_id: rns_interface::traits::InterfaceId,
    },
    #[error("interface {interface_id} is not registered")]
    NotFound {
        interface_id: rns_interface::traits::InterfaceId,
    },
    #[error("interface {interface_id} is not an observable RNode")]
    NotRNode {
        interface_id: rns_interface::traits::InterfaceId,
    },
    #[error("RNode interface {interface_id} is not active")]
    NotActive {
        interface_id: rns_interface::traits::InterfaceId,
    },
}

/// Terminal outcome while waiting for one exact RNode to become ready.
#[derive(Clone, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum RNodeReadinessError {
    #[error("RNode readiness timed out")]
    Timeout {
        last: Arc<rns_interface::rnode::RNodeRuntimeSnapshot>,
    },
    #[error("RNode began shutting down before becoming ready")]
    ShuttingDown {
        last: Arc<rns_interface::rnode::RNodeRuntimeSnapshot>,
    },
    #[error("RNode stopped before becoming ready")]
    Stopped {
        last: Arc<rns_interface::rnode::RNodeRuntimeSnapshot>,
    },
    #[error("RNode observation closed before readiness concluded")]
    ObservationClosed {
        last: Arc<rns_interface::rnode::RNodeRuntimeSnapshot>,
    },
}

/// Failure to validate, spawn, or atomically register a runtime-owned RNode.
///
/// Options-aware entry points preserve the lower typed RNode startup failure,
/// including capability-admission rejection. Compatibility entry points keep
/// returning their historical strings by formatting this error.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum RNodeRuntimeSpawnError {
    #[error("{0}")]
    RuntimeAdmission(String),
    #[error("{0}")]
    InvalidConfiguration(String),
    #[error("RNode spawn failed: {0}")]
    RNodeSpawn(#[source] rns_interface::rnode::RNodeSpawnError),
    #[error("BLE RNode spawn failed: {0}")]
    BleRNodeSpawn(#[source] rns_interface::rnode::RNodeSpawnError),
    #[error("BLE RNode native spawn failed: {0}")]
    NativeBleRNodeSpawn(#[source] rns_interface::rnode::RNodeSpawnError),
    #[cfg(target_os = "android")]
    #[error("Android USB spawn failed: {0}")]
    AndroidUsbSpawn(#[source] rns_interface::rnode::RNodeSpawnError),
    #[error("{0}")]
    Registration(String),
}

impl RNodeReadinessError {
    /// Latest privacy-safe state associated with the terminal outcome.
    pub fn last_snapshot(&self) -> Arc<rns_interface::rnode::RNodeRuntimeSnapshot> {
        match self {
            Self::Timeout { last }
            | Self::ShuttingDown { last }
            | Self::Stopped { last }
            | Self::ObservationClosed { last } => last.clone(),
        }
    }
}

/// Options for [`ReticulumHandle::send_to`].
#[derive(Debug, Clone)]
pub struct SendOptions {
    /// Track the packet until a proof arrives or its receipt expires.
    pub create_receipt: bool,
    /// Override the route-derived receipt timeout.
    pub timeout: Option<Duration>,
    /// Restrict dispatch to one interface.
    pub attached_interface: Option<rns_transport::messages::InterfaceId>,
}

impl Default for SendOptions {
    fn default() -> Self {
        Self {
            create_receipt: true,
            timeout: None,
            attached_interface: None,
        }
    }
}

/// Immediate result of a successful packet dispatch.
#[derive(Debug, Clone)]
pub struct SendResult {
    pub packet_hash: [u8; 32],
    pub receipt: Option<PacketReceiptHandle>,
}

/// Stateful non-Link application packet that can be sent and re-sent.
///
/// Re-sending runs the normal destination encryption path again, producing
/// fresh ciphertext, a new packet hash, and a new receipt when requested.
pub struct OutboundPacket<'a> {
    runtime: &'a ReticulumHandle,
    destination: &'a Destination,
    data: &'a [u8],
    options: SendOptions,
    sent: bool,
}

impl std::fmt::Debug for OutboundPacket<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("OutboundPacket")
            .field("destination_hash", &hex::encode(self.destination.hash))
            .field("data_len", &self.data.len())
            .field("sent", &self.sent)
            .finish()
    }
}

impl OutboundPacket<'_> {
    pub fn is_sent(&self) -> bool {
        self.sent
    }

    /// Send this packet for the first time.
    pub async fn send(&mut self) -> Result<SendResult, SendError> {
        if self.sent {
            return Err(SendError::AlreadySent);
        }
        let result = self
            .runtime
            .send_to(self.destination, self.data, self.options.clone())
            .await?;
        self.sent = true;
        Ok(result)
    }

    /// Re-send a previously-sent packet with fresh destination encryption.
    pub async fn resend(&mut self) -> Result<SendResult, SendError> {
        if !self.sent {
            return Err(SendError::NotSent);
        }
        match self
            .runtime
            .send_to(self.destination, self.data, self.options.clone())
            .await
        {
            Ok(result) => Ok(result),
            Err(error) => {
                self.sent = false;
                Err(error)
            }
        }
    }
}

/// Current lifecycle state of a tracked packet.
pub type PacketReceiptStatus = ReceiptUpdate;

/// Readable, cloneable handle for one non-Link packet receipt.
#[derive(Clone)]
pub struct PacketReceiptHandle {
    pub packet_hash: [u8; 32],
    pub truncated_hash: [u8; 16],
    status_rx: watch::Receiver<ReceiptUpdate>,
    transport_tx: mpsc::Sender<TransportMessage>,
}

impl std::fmt::Debug for PacketReceiptHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PacketReceiptHandle")
            .field("packet_hash", &hex::encode(self.packet_hash))
            .field("status", &self.status())
            .finish()
    }
}

impl PacketReceiptHandle {
    /// Return the latest receipt state without waiting.
    pub fn status(&self) -> PacketReceiptStatus {
        *self.status_rx.borrow()
    }

    /// Subscribe to future receipt state changes.
    pub fn watch(&self) -> watch::Receiver<PacketReceiptStatus> {
        self.status_rx.clone()
    }

    /// Change the timeout of this receipt while it is still pending.
    ///
    /// The new duration is measured from the original send time, matching
    /// Python `PacketReceipt.set_timeout`.
    pub async fn set_timeout(&self, timeout: Duration) -> Result<(), ReceiptError> {
        if self.status() != ReceiptUpdate::Sent {
            return Err(ReceiptError::NoLongerTracked);
        }
        let (result_tx, result_rx) = tokio::sync::oneshot::channel();
        self.transport_tx
            .send(TransportMessage::SetReceiptTimeout {
                truncated_hash: self.truncated_hash,
                timeout,
                result_tx,
            })
            .await
            .map_err(|_| ReceiptError::TransportClosed)?;
        if result_rx.await.map_err(|_| ReceiptError::TransportClosed)? {
            Ok(())
        } else {
            Err(ReceiptError::NoLongerTracked)
        }
    }

    /// Wait until the packet is delivered or reaches another terminal state.
    pub async fn delivered(mut self) -> Result<Duration, ReceiptError> {
        loop {
            match self.status() {
                ReceiptUpdate::Sent => {
                    self.status_rx
                        .changed()
                        .await
                        .map_err(|_| ReceiptError::TransportClosed)?;
                }
                ReceiptUpdate::Delivered { rtt } => return Ok(rtt),
                ReceiptUpdate::TimedOut => return Err(ReceiptError::TimedOut),
                ReceiptUpdate::Failed => return Err(ReceiptError::Failed),
                ReceiptUpdate::Culled => return Err(ReceiptError::Culled),
            }
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ReceiptError {
    #[error("packet receipt timed out")]
    TimedOut,
    #[error("packet receipt failed")]
    Failed,
    #[error("packet receipt was culled")]
    Culled,
    #[error("packet receipt is no longer pending")]
    NoLongerTracked,
    #[error("transport closed before the receipt concluded")]
    TransportClosed,
}

#[derive(Debug, thiserror::Error)]
pub enum SendError {
    #[error("destination must be outbound")]
    InboundDestination,
    #[error("Link destinations must use LinkSession")]
    LinkDestination,
    #[error("no validated identity is known for destination {0}")]
    IdentityUnavailable(String),
    #[error("payload is {actual} bytes; encrypted SINGLE-packet MDU is {max}")]
    PayloadTooLarge { actual: usize, max: usize },
    #[error("destination encryption failed: {0}")]
    Encryption(#[from] DestinationError),
    #[error("packet construction failed: {0}")]
    Packet(#[from] rns_wire::packet::PacketError),
    #[error("destination-aware packet construction failed: {0}")]
    PacketBuild(#[from] DestinationPacketError),
    #[error("transport channel is unavailable")]
    TransportUnavailable,
    #[error("no outbound interface accepted the packet")]
    NoInterface,
    #[error("another in-flight receipt has the same truncated packet hash")]
    ReceiptCollision,
    #[error("packet was already sent; use resend")]
    AlreadySent,
    #[error("packet has not been sent yet")]
    NotSent,
    #[error("transport control failed: {0}")]
    Control(#[from] ControlError),
}

/// Options for opening a persistent application Link.
#[derive(Debug, Clone)]
pub struct LinkConnectOptions {
    /// How long path discovery may run when no validated announce is cached.
    pub path_timeout: Duration,
    /// Explicit deadline for the Link handshake itself.
    ///
    /// When omitted, the runtime derives Python-compatible timing from the
    /// destination's first-hop timeout and current path hop count.
    /// `Some(Duration::ZERO)` deliberately requests an immediate deadline.
    pub establishment_timeout: Option<Duration>,
    /// Registration label used for the temporary Link destination.
    pub client_label: String,
    /// Send the local identity over the Link after establishment.
    pub identify: bool,
    /// Retain RSSI, SNR and quality measurements reported by interfaces.
    pub track_phy_stats: bool,
}

impl Default for LinkConnectOptions {
    fn default() -> Self {
        Self {
            path_timeout: Duration::from_secs(15),
            establishment_timeout: None,
            client_label: "rns-runtime.link".to_string(),
            identify: false,
            track_phy_stats: false,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum LinkConnectError {
    #[error("transport control failed: {0}")]
    Control(#[from] ControlError),
    #[error("path discovery failed: {0}")]
    Path(#[from] AwaitPathError),
    #[error("no validated identity is known for destination {0}")]
    IdentityUnavailable(String),
    #[error("Link session failed: {0}")]
    Session(#[from] LinkSessionError),
}

fn link_establishment_timeout(
    first_hop_timeout: Duration,
    hops: u8,
) -> Result<Duration, ControlError> {
    let per_hop_timeout = Duration::try_from_secs_f64(
        rns_wire::constants::DEFAULT_PER_HOP_TIMEOUT * f64::from(hops.max(1)),
    )
    .map_err(|_| ControlError::UnexpectedResponse {
        operation: "Link establishment timeout derivation",
    })?;
    first_hop_timeout
        .checked_add(per_hop_timeout)
        .ok_or(ControlError::UnexpectedResponse {
            operation: "Link establishment timeout derivation",
        })
}

impl std::fmt::Debug for RecalledDestination {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RecalledDestination")
            .field("destination_hash", &hex::encode(self.destination_hash))
            .field("identity_hash", &hex::encode(self.identity.hash))
            .field("app_data_len", &self.app_data.as_ref().map(Vec::len))
            .field("ratchet_present", &self.ratchet.is_some())
            .field("hops", &self.hops)
            .field("last_heard", &self.last_heard)
            .finish()
    }
}

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ControlError {
    #[error("not connected to the shared Reticulum instance")]
    NotConnectedToSharedInstance,
    #[error("shared-instance RPC authentication failed")]
    RpcAuth,
    #[error("shared-instance RPC failed: {0}")]
    Rpc(String),
    #[error("control query is not supported by the shared-instance RPC")]
    UnsupportedBySharedInstance,
    #[error("transport query channel closed")]
    ChannelClosed,
    #[error("transport query timed out after {0:?}")]
    Timeout(Duration),
    #[error("transport returned an unexpected response to {operation}")]
    UnexpectedResponse { operation: &'static str },
    #[error("cached identity is invalid: {0}")]
    InvalidIdentity(#[from] rns_identity::identity::IdentityError),
}

/// Shared discovery state behind one `Arc` so cloning [`ReticulumHandle`]
/// doesn't proliferate state. Holds inputs for the eventual announce tick /
/// subscriber loop.
pub struct DiscoveryRuntime {
    stamper: Mutex<Option<Arc<dyn DiscoveryStamper + Send + Sync>>>,
    store: Mutex<Option<Arc<DiscoveryStore>>>,
    receiver_started: Mutex<bool>,
    announcer_started: Mutex<bool>,
    subscriber_started: Mutex<bool>,
    local_interfaces: Mutex<Vec<LocalDiscoveryInterface>>,
    autoconnected: Mutex<HashMap<[u8; 32], u64>>,
    bootstrap_interfaces: Mutex<Vec<u64>>,
}

impl Default for DiscoveryRuntime {
    fn default() -> Self {
        Self {
            stamper: Mutex::new(None),
            store: Mutex::new(None),
            receiver_started: Mutex::new(false),
            announcer_started: Mutex::new(false),
            subscriber_started: Mutex::new(false),
            local_interfaces: Mutex::new(Vec::new()),
            autoconnected: Mutex::new(HashMap::new()),
            bootstrap_interfaces: Mutex::new(Vec::new()),
        }
    }
}

#[derive(Debug, Clone)]
struct LocalDiscoveryInterface {
    id: u64,
    config: DiscoveryInterfaceConfig,
}

impl ReticulumHandle {
    /// Register and own an inbound SINGLE destination on this runtime.
    pub async fn register_destination(
        &self,
        identity: Identity,
        app_name: impl Into<String>,
        options: crate::destination_runtime::DestinationRuntimeOptions,
    ) -> Result<
        crate::destination_runtime::RegisteredDestination,
        crate::destination_runtime::DestinationRuntimeError,
    > {
        crate::destination_runtime::RegisteredDestination::register(
            self.transport_tx.clone(),
            identity,
            app_name,
            options,
        )
        .await
    }

    /// Register and own a persistent-ratcheted inbound SINGLE destination.
    pub async fn register_ratcheted_destination(
        &self,
        identity: Identity,
        app_name: impl Into<String>,
        options: crate::destination_runtime::DestinationRuntimeOptions,
        ratchet_options: crate::destination_runtime::DestinationRatchetOptions,
    ) -> Result<
        crate::destination_runtime::RegisteredDestination,
        crate::destination_runtime::DestinationRuntimeError,
    > {
        crate::destination_runtime::RegisteredDestination::register_ratcheted(
            self.transport_tx.clone(),
            identity,
            app_name,
            options,
            ratchet_options,
        )
        .await
    }

    pub fn transport_enabled(&self) -> bool {
        self.config.enable_transport
    }

    pub fn should_use_implicit_proof(&self) -> bool {
        self.config.use_implicit_proof
    }

    pub fn remote_management_enabled(&self) -> bool {
        self.config.enable_remote_management
    }

    /// Observe the current exact RNode registered under `interface_id`.
    ///
    /// Shared-instance clients do not own physical interfaces and fail
    /// closed. The returned observer remains bound to this registry record
    /// even if the numeric ID is later reused.
    pub fn rnode_runtime(
        &self,
        interface_id: rns_interface::traits::InterfaceId,
    ) -> Result<RNodeRuntimeObserver, RNodeRuntimeLookupError> {
        if self.instance_mode == InstanceMode::Client {
            return Err(RNodeRuntimeLookupError::NotOwned { interface_id });
        }
        let state = self
            .interface_registry
            .observe_active_rnode(interface_id)
            .map_err(|error| match error {
                RNodeObservationLookupError::NotFound => {
                    RNodeRuntimeLookupError::NotFound { interface_id }
                }
                RNodeObservationLookupError::NotRNode => {
                    RNodeRuntimeLookupError::NotRNode { interface_id }
                }
                RNodeObservationLookupError::NotActive => {
                    RNodeRuntimeLookupError::NotActive { interface_id }
                }
            })?;
        Ok(RNodeRuntimeObserver {
            interface_id,
            state,
        })
    }

    /// Return exact observers for single RNodes successfully registered from
    /// startup configuration, in configuration/registration order.
    ///
    /// The returned records are owned clones and carry no lifecycle or
    /// configuration authority. Runtime-spawned RNodes, RNodeMulti children,
    /// disabled or failed entries, and shared-instance client hardware are
    /// intentionally absent. In [`InstanceMode::Client`], an empty result is
    /// an ownership statement, not permission to respawn hardware locally.
    pub fn startup_rnode_runtimes(&self) -> Vec<StartupRNodeRuntime> {
        self.startup_rnode_runtimes.clone()
    }

    pub fn link_mtu_discovery(&self) -> bool {
        self.config.link_mtu_discovery
    }

    /// Trigger orderly runtime shutdown and wait until the transport actor has
    /// synchronously flushed its persisted state. Dropping this future does
    /// not cancel the runtime-owned drain operation.
    pub async fn shutdown_and_wait(&self) {
        self.shutdown_coordinator.start_and_wait().await;
    }

    /// Wait up to `timeout` for the transport actor to resolve a path.
    /// Python: `Transport.await_path` (RNS/Transport.py:2524).
    pub async fn await_path(
        &self,
        destination_hash: [u8; 16],
        timeout: Duration,
    ) -> Result<(), AwaitPathError> {
        await_path(&self.transport_tx, destination_hash, timeout).await
    }

    /// Resolve a destination and open a persistent encrypted Link.
    ///
    /// This is the app-facing counterpart to Python's `Link(destination)`:
    /// it uses the validated announce cache for the remote public key, starts
    /// path discovery when necessary, and then hands ownership to
    /// [`LinkSession`].
    pub async fn connect_link(
        &self,
        destination_hash: [u8; 16],
        local_identity: Identity,
        options: LinkConnectOptions,
    ) -> Result<LinkSession, LinkConnectError> {
        let config = self
            .resolve_link_session_config(destination_hash, &options)
            .await?;
        LinkSession::connect(self.transport_tx.clone(), local_identity, config)
            .await
            .map_err(LinkConnectError::Session)
    }

    async fn resolve_link_session_config(
        &self,
        destination_hash: [u8; 16],
        options: &LinkConnectOptions,
    ) -> Result<LinkSessionConfig, LinkConnectError> {
        let mut recalled = self.recall(destination_hash).await?;
        if recalled.is_none() {
            self.await_path(destination_hash, options.path_timeout)
                .await?;
            recalled = self.recall(destination_hash).await?;
        }
        let recalled = recalled
            .ok_or_else(|| LinkConnectError::IdentityUnavailable(hex::encode(destination_hash)))?;
        let (establishment_timeout, hops) = match options.establishment_timeout {
            Some(timeout) => (timeout, recalled.hops),
            None => {
                let hops = self.hops_to(destination_hash).await?;
                let first_hop_timeout = self.first_hop_timeout(destination_hash).await?;
                (link_establishment_timeout(first_hop_timeout, hops)?, hops)
            }
        };

        Ok(LinkSessionConfig {
            destination_hash,
            remote_public_key: recalled.identity.get_public_key(),
            hops,
            establishment_timeout,
            client_label: options.client_label.clone(),
            identify: options.identify,
            track_phy_stats: options.track_phy_stats,
        })
    }

    pub async fn subscribe_announces(
        &self,
        aspect_filter: Option<String>,
        receive_path_responses: bool,
    ) -> Result<AnnounceSubscription, AnnounceSubscriptionError> {
        self.subscribe_announces_with_capacity(
            aspect_filter,
            receive_path_responses,
            DEFAULT_ANNOUNCE_SUBSCRIPTION_CAPACITY,
        )
        .await
    }

    pub async fn subscribe_announces_with_capacity(
        &self,
        aspect_filter: Option<String>,
        receive_path_responses: bool,
        capacity: usize,
    ) -> Result<AnnounceSubscription, AnnounceSubscriptionError> {
        if capacity == 0 {
            return Err(AnnounceSubscriptionError::InvalidCapacity);
        }
        let (callback_tx, events) = mpsc::channel(capacity);
        let dropped_events = Arc::new(AtomicU64::new(0));
        let (result_tx, result_rx) = tokio::sync::oneshot::channel();
        self.transport_tx
            .send(TransportMessage::RegisterAnnounceSubscription {
                aspect_filter,
                receive_path_responses,
                callback_tx,
                dropped_events: Arc::clone(&dropped_events),
                result_tx,
            })
            .await
            .map_err(|_| AnnounceSubscriptionError::TransportUnavailable)?;
        let id = result_rx
            .await
            .map_err(|_| AnnounceSubscriptionError::TransportUnavailable)?;
        Ok(AnnounceSubscription {
            id: Some(id),
            events,
            dropped_events,
            transport_tx: self.transport_tx.clone(),
        })
    }

    /// Prepare one stateful non-Link application packet.
    ///
    /// [`OutboundPacket::send`] performs the same validated destination
    /// resolution, encryption, receipt registration, and dispatch as
    /// [`Self::send_to`]. [`OutboundPacket::resend`] repeats that complete
    /// path so each attempt receives fresh ciphertext and receipt state.
    pub fn outbound_packet<'a>(
        &'a self,
        destination: &'a Destination,
        data: &'a [u8],
        options: SendOptions,
    ) -> OutboundPacket<'a> {
        OutboundPacket {
            runtime: self,
            destination,
            data,
            options,
            sent: false,
        }
    }

    /// Encrypt and dispatch one non-Link application packet.
    ///
    /// Call [`Self::outbound_packet`] when the same logical packet may need
    /// to be re-sent with fresh ciphertext.
    pub async fn send_to(
        &self,
        destination: &Destination,
        data: &[u8],
        options: SendOptions,
    ) -> Result<SendResult, SendError> {
        if destination.direction != Direction::Out {
            return Err(SendError::InboundDestination);
        }
        if destination.dest_type == DestType::Link {
            return Err(SendError::LinkDestination);
        }
        if destination.dest_type == DestType::Single
            && data.len() > rns_wire::constants::SINGLE_PACKET_ENCRYPTED_MDU
        {
            return Err(SendError::PayloadTooLarge {
                actual: data.len(),
                max: rns_wire::constants::SINGLE_PACKET_ENCRYPTED_MDU,
            });
        }

        // Python does not create receipts for PLAIN packets.
        let create_receipt = options.create_receipt && destination.dest_type != DestType::Plain;
        let recalled = if destination.dest_type == DestType::Single || create_receipt {
            Some(
                self.recall(destination.hash)
                    .await?
                    .ok_or_else(|| SendError::IdentityUnavailable(hex::encode(destination.hash)))?,
            )
        } else {
            None
        };
        let encryption_identity = recalled
            .as_ref()
            .map(|entry| &entry.identity)
            .unwrap_or(self.transport_identity.as_ref());
        let ratchet = destination
            .remote_ratchet_pub
            .as_ref()
            .or_else(|| recalled.as_ref().and_then(|entry| entry.ratchet.as_ref()));
        let packet = destination
            .pack_packet(
                data,
                Some(encryption_identity),
                ratchet,
                DestinationPacketOptions::default(),
            )?
            .packet;
        let packet_hash = packet.packet_hash;
        let truncated_hash = packet.truncated_hash;

        let (receipt, registration) = if create_receipt {
            let recalled = recalled
                .as_ref()
                .expect("tracked destination recall completed above");
            let timeout = match options.timeout {
                Some(timeout) => timeout,
                None => self.default_packet_receipt_timeout(destination.hash).await,
            };
            let (status_tx, status_rx) = watch::channel(ReceiptUpdate::Sent);
            (
                Some(PacketReceiptHandle {
                    packet_hash,
                    truncated_hash,
                    status_rx,
                    transport_tx: self.transport_tx.clone(),
                }),
                Some(TrackedReceiptRegistration {
                    truncated_hash,
                    full_hash: packet_hash,
                    destination_hash: destination.hash,
                    destination_public_key: recalled.identity.get_public_key(),
                    timeout: Some(timeout),
                    status_tx,
                }),
            )
        } else {
            (None, None)
        };

        let (result_tx, result_rx) = tokio::sync::oneshot::channel();
        self.transport_tx
            .send(TransportMessage::SendPacket {
                request: OutboundRequest {
                    raw: Bytes::from(packet.raw),
                    destination_hash: destination.hash,
                },
                attached_interface: options.attached_interface,
                receipt: registration,
                result_tx,
            })
            .await
            .map_err(|_| SendError::TransportUnavailable)?;

        match result_rx
            .await
            .map_err(|_| SendError::TransportUnavailable)?
        {
            OutboundDispatchResult::Sent => Ok(SendResult {
                packet_hash,
                receipt,
            }),
            OutboundDispatchResult::NoInterface => Err(SendError::NoInterface),
            OutboundDispatchResult::ReceiptCollision => Err(SendError::ReceiptCollision),
        }
    }

    async fn default_packet_receipt_timeout(&self, destination_hash: [u8; 16]) -> Duration {
        let first_hop = match self.first_hop_timeout(destination_hash).await {
            Ok(timeout) => timeout.as_secs_f64(),
            Err(_) => return Duration::from_secs(180),
        };
        let hops = match self.hops_to(destination_hash).await {
            Ok(hops) => hops,
            Err(_) => return Duration::from_secs(180),
        };
        Duration::try_from_secs_f64(
            first_hop + f64::from(hops) * rns_wire::constants::DEFAULT_PER_HOP_TIMEOUT,
        )
        .unwrap_or(Duration::from_secs(180))
    }

    /// Query this process' transport actor directly.
    pub async fn query_transport(&self, query: TransportQuery) -> Option<TransportQueryResponse> {
        self.query_transport_result(query).await.ok()
    }

    async fn query_transport_result(
        &self,
        query: TransportQuery,
    ) -> Result<TransportQueryResponse, ControlError> {
        self.query_transport_result_with_timeout(query, Duration::from_secs(5))
            .await
    }

    async fn query_transport_result_with_timeout(
        &self,
        query: TransportQuery,
        timeout: Duration,
    ) -> Result<TransportQueryResponse, ControlError> {
        let variant = format!("{query:?}");
        let started = std::time::Instant::now();
        let (tx, rx) = tokio::sync::oneshot::channel();
        let mut send_elapsed = None;
        let transaction = async {
            self.transport_tx
                .send(TransportMessage::Rpc {
                    query,
                    response_tx: tx,
                })
                .await
                .map_err(|_| ControlError::ChannelClosed)?;
            send_elapsed = Some(started.elapsed());
            rx.await.map_err(|_| ControlError::ChannelClosed)
        };
        let result = match tokio::time::timeout(timeout, transaction).await {
            Ok(result) => result,
            Err(_) => Err(ControlError::Timeout(timeout)),
        };
        let total = started.elapsed();
        if result.is_err() || total > Duration::from_millis(1000) {
            tracing::warn!(
                query = %variant,
                send_ms = send_elapsed.unwrap_or(total).as_millis() as u64,
                total_ms = total.as_millis() as u64,
                timed_out = matches!(&result, Err(ControlError::Timeout(_))),
                "transport query slow or failed"
            );
        }
        result
    }

    /// Recall the identity and latest announce metadata for `destination_hash`.
    ///
    /// This reads this process' live, validated replicated announce cache in
    /// O(1) without extending the entry's lifetime. In shared-instance client
    /// mode it intentionally remains a process-local cache lookup, not an
    /// authoritative control-plane query. It mirrors
    /// `Identity.recall(destination_hash, _no_use=True)` and returns `None`
    /// when no identity-bearing announce is known.
    pub async fn recall(
        &self,
        destination_hash: [u8; 16],
    ) -> Result<Option<RecalledDestination>, ControlError> {
        let response = self
            .query_transport_result(TransportQuery::RecallDestination {
                dest: destination_hash,
            })
            .await?;
        match response {
            TransportQueryResponse::RecalledDestination(entry) => {
                entry.map(recalled_destination_from_rpc).transpose()
            }
            _ => Err(ControlError::UnexpectedResponse {
                operation: "destination recall",
            }),
        }
    }

    /// Return whether a non-expired path is known for `destination_hash`.
    pub async fn has_path(&self, destination_hash: [u8; 16]) -> Result<bool, ControlError> {
        if self.instance_mode == InstanceMode::Client {
            return Ok(self
                .path_table(None)
                .await?
                .iter()
                .any(|entry| entry.hash == destination_hash));
        }

        match self
            .query_control_result(TransportQuery::HasPath {
                dest: destination_hash,
            })
            .await?
        {
            TransportQueryResponse::BoolResult(has_path) => Ok(has_path),
            _ => Err(ControlError::UnexpectedResponse {
                operation: "path presence query",
            }),
        }
    }

    /// Return the path hop count, or `PATHFINDER_M` when no path is known.
    pub async fn hops_to(&self, destination_hash: [u8; 16]) -> Result<u8, ControlError> {
        if self.instance_mode == InstanceMode::Client {
            return Ok(self
                .path_table(None)
                .await?
                .into_iter()
                .find(|entry| entry.hash == destination_hash)
                .map(|entry| entry.hops)
                .unwrap_or(rns_transport::constants::PATHFINDER_M));
        }

        match self
            .query_control_result(TransportQuery::HopsTo {
                dest: destination_hash,
            })
            .await?
        {
            TransportQueryResponse::IntResult(hops) => {
                u8::try_from(hops).map_err(|_| ControlError::UnexpectedResponse {
                    operation: "path hop query",
                })
            }
            _ => Err(ControlError::UnexpectedResponse {
                operation: "path hop query",
            }),
        }
    }

    /// Return the effective bitrate of the next-hop interface.
    pub async fn next_hop_bitrate(
        &self,
        destination_hash: [u8; 16],
    ) -> Result<Option<u64>, ControlError> {
        if self.instance_mode == InstanceMode::Client {
            return Ok(self
                .shared_next_hop_interface(destination_hash)
                .await?
                .map(|interface| interface.bitrate));
        }

        match self
            .query_control_result(TransportQuery::GetNextHopBitrate {
                dest: destination_hash,
            })
            .await?
        {
            TransportQueryResponse::FloatResult(None) => Ok(None),
            TransportQueryResponse::FloatResult(Some(bitrate))
                if bitrate.is_finite()
                    && bitrate >= 0.0
                    && bitrate.fract() == 0.0
                    && bitrate <= u64::MAX as f64 =>
            {
                Ok(Some(bitrate as u64))
            }
            _ => Err(ControlError::UnexpectedResponse {
                operation: "next-hop bitrate query",
            }),
        }
    }

    /// Return the effective MTU of the next-hop interface.
    ///
    /// Rust interfaces normalize fixed and auto-configured hardware MTUs into
    /// one concrete value, so this is the counterpart to Python's
    /// `next_hop_interface_hw_mtu()`.
    pub async fn next_hop_hardware_mtu(
        &self,
        destination_hash: [u8; 16],
    ) -> Result<Option<u32>, ControlError> {
        if self.instance_mode == InstanceMode::Client {
            return Ok(self
                .shared_next_hop_interface(destination_hash)
                .await?
                .and_then(|interface| (interface.mtu != 0).then_some(interface.mtu)));
        }

        match self
            .query_control_result(TransportQuery::GetNextHopHardwareMtu {
                dest: destination_hash,
            })
            .await?
        {
            TransportQueryResponse::IntResult(-1) => Ok(None),
            TransportQueryResponse::IntResult(mtu) => {
                u32::try_from(mtu)
                    .map(Some)
                    .map_err(|_| ControlError::UnexpectedResponse {
                        operation: "next-hop hardware MTU query",
                    })
            }
            _ => Err(ControlError::UnexpectedResponse {
                operation: "next-hop hardware MTU query",
            }),
        }
    }

    /// Return the next-hop transmission latency for one bit, in seconds.
    pub async fn next_hop_per_bit_latency(
        &self,
        destination_hash: [u8; 16],
    ) -> Result<Option<f64>, ControlError> {
        Ok(self
            .next_hop_bitrate(destination_hash)
            .await?
            .filter(|bitrate| *bitrate > 0)
            .map(|bitrate| 1.0 / bitrate as f64))
    }

    /// Return the next-hop transmission latency for one byte, in seconds.
    pub async fn next_hop_per_byte_latency(
        &self,
        destination_hash: [u8; 16],
    ) -> Result<Option<f64>, ControlError> {
        Ok(self
            .next_hop_per_bit_latency(destination_hash)
            .await?
            .map(|latency| latency * 8.0))
    }

    /// Return the first-hop transmission timeout for `destination_hash`.
    ///
    /// Shared-instance clients include the configured simulated local-link
    /// latency from `force_shared_instance_bitrate`, matching Python.
    pub async fn first_hop_timeout(
        &self,
        destination_hash: [u8; 16],
    ) -> Result<Duration, ControlError> {
        match self
            .query_control_result(TransportQuery::FirstHopTimeout {
                dest: destination_hash,
            })
            .await?
        {
            TransportQueryResponse::FloatResult(Some(seconds))
                if seconds.is_finite() && seconds >= 0.0 =>
            {
                Duration::try_from_secs_f64(seconds).map_err(|_| ControlError::UnexpectedResponse {
                    operation: "first-hop timeout query",
                })
            }
            _ => Err(ControlError::UnexpectedResponse {
                operation: "first-hop timeout query",
            }),
        }
    }

    /// Request a network path, optionally on one interface with an explicit tag.
    pub async fn request_path(
        &self,
        destination_hash: [u8; 16],
        options: PathRequestOptions,
    ) -> Result<(), ControlError> {
        self.transport_tx
            .send(TransportMessage::RequestPathWithOptions {
                destination_hash,
                options,
            })
            .await
            .map_err(|_| ControlError::ChannelClosed)
    }

    /// Return the authoritative path table, optionally limited by hop count.
    pub async fn path_table(
        &self,
        max_hops: Option<u8>,
    ) -> Result<Vec<rns_transport::messages::PathTableRpcEntry>, ControlError> {
        match self
            .query_control_result(TransportQuery::GetPathTable)
            .await?
        {
            TransportQueryResponse::PathTable(mut entries) => {
                if let Some(max_hops) = max_hops {
                    entries.retain(|entry| entry.hops <= max_hops);
                }
                Ok(entries)
            }
            _ => Err(ControlError::UnexpectedResponse {
                operation: "path table query",
            }),
        }
    }

    /// Return a normalized interface-stat snapshot.
    ///
    /// Aggregate counters are calculated with saturating sums. Metadata that
    /// the current runtime or a shared-instance RPC cannot supply remains
    /// `None` rather than being replaced with sentinel values.
    pub async fn interface_stats(&self) -> Result<InterfaceStats, ControlError> {
        let interfaces = match self
            .query_control_result(TransportQuery::GetInterfaceStats)
            .await?
        {
            TransportQueryResponse::InterfaceStats(entries) => entries,
            _ => {
                return Err(ControlError::UnexpectedResponse {
                    operation: "interface stats query",
                });
            }
        };
        let sum = |select: fn(&rns_transport::messages::InterfaceStatRpcEntry) -> u64| {
            interfaces
                .iter()
                .map(select)
                .fold(0_u64, u64::saturating_add)
        };
        let local_transport =
            self.instance_mode != InstanceMode::Client && self.config.enable_transport;
        Ok(InterfaceStats {
            rx_bytes: sum(|entry| entry.rx_bytes),
            tx_bytes: sum(|entry| entry.tx_bytes),
            rx_rate: sum(|entry| entry.rx_rate),
            tx_rate: sum(|entry| entry.tx_rate),
            transport_id: local_transport.then_some(self.transport_identity.hash),
            network_id: local_transport
                .then(|| self.network_identity.as_ref().map(|identity| identity.hash))
                .flatten(),
            transport_uptime: local_transport.then(|| self.started_at.elapsed()),
            // The responder uses a separate persisted identity that is not
            // currently retained by ReticulumHandle.
            probe_responder: None,
            // std does not expose portable resident-set accounting.
            rss_bytes: None,
            interfaces,
        })
    }

    fn apply_shared_instance_latency(
        &self,
        query: &TransportQuery,
        mut response: TransportQueryResponse,
    ) -> TransportQueryResponse {
        if self.instance_mode == InstanceMode::Client
            && matches!(query, TransportQuery::FirstHopTimeout { .. })
        {
            if let Some(bitrate) = self
                .config
                .force_shared_instance_bitrate
                .filter(|bitrate| *bitrate > 0)
            {
                if let TransportQueryResponse::FloatResult(Some(seconds)) = &mut response {
                    *seconds += (rns_wire::constants::MTU as f64 * 8.0) / bitrate as f64;
                }
            }
        }
        response
    }

    async fn shared_next_hop_interface(
        &self,
        destination_hash: [u8; 16],
    ) -> Result<Option<rns_transport::messages::InterfaceStatRpcEntry>, ControlError> {
        let interface_name = match self
            .query_control_result(TransportQuery::GetNextHopIfName {
                dest: destination_hash,
            })
            .await?
        {
            TransportQueryResponse::StringResult(interface_name) => interface_name,
            _ => {
                return Err(ControlError::UnexpectedResponse {
                    operation: "next-hop interface query",
                });
            }
        };
        let Some(interface_name) = interface_name else {
            return Ok(None);
        };
        let interfaces = match self
            .query_control_result(TransportQuery::GetInterfaceStats)
            .await?
        {
            TransportQueryResponse::InterfaceStats(interfaces) => interfaces,
            _ => {
                return Err(ControlError::UnexpectedResponse {
                    operation: "interface stats query",
                });
            }
        };
        let mut matches = interfaces
            .into_iter()
            .filter(|interface| interface.name == interface_name);
        let matched = matches.next();
        if matches.next().is_some() {
            return Ok(None);
        }
        Ok(matched)
    }

    /// Result-returning control-plane query used by the typed facade.
    ///
    /// In client mode, a failed or unsupported shared-instance request never
    /// falls back to this process' local actor.
    async fn query_control_result(
        &self,
        query: TransportQuery,
    ) -> Result<TransportQueryResponse, ControlError> {
        if self.instance_mode != InstanceMode::Client {
            return self.query_transport_result(query).await;
        }

        let Some(request) = transport_query_to_rpc_request(&query) else {
            return Err(ControlError::UnsupportedBySharedInstance);
        };
        let Some(rpc_key) = self.config.rpc_key.as_deref() else {
            return Err(ControlError::NotConnectedToSharedInstance);
        };
        let timeout = Duration::from_secs(5);
        let rpc_result = match self.config.shared_rpc_endpoint(&self.socket_base) {
            SharedInstanceRpcEndpoint::Tcp(port) => {
                crate::rpc::connect_and_request(port, rpc_key, &request, timeout).await
            }
            SharedInstanceRpcEndpoint::Unix(socket_path) => {
                crate::rpc::connect_unix_and_request(&socket_path, rpc_key, &request, timeout).await
            }
        }
        .map_err(|error| control_error_from_rpc(error, timeout))?;
        if let crate::rpc::RpcResponse::Error(error) = rpc_result {
            return Err(ControlError::Rpc(error));
        }
        let response = rpc_response_to_transport_response(rpc_result).ok_or(
            ControlError::UnexpectedResponse {
                operation: "shared-instance control query",
            },
        )?;
        Ok(self.apply_shared_instance_latency(&query, response))
    }

    /// Query the authoritative control plane.
    ///
    /// In client mode, Python proxies Reticulum control methods to the local
    /// shared instance over the RPC listener. Only operations exposed by that
    /// listener are available here; failures and unsupported queries return
    /// `None` without consulting this process' local actor. Use
    /// [`Self::query_transport`] for explicit process-local access.
    pub async fn query_control(&self, query: TransportQuery) -> Option<TransportQueryResponse> {
        self.query_control_result(query).await.ok()
    }

    /// Install a [`DiscoveryStamper`] so this node can emit PoW-stamped
    /// discovery announces. Inverts Python's hard `LXMF.LXStamper` import
    /// (RNS/Discovery.py:41) — downstream apps install at startup. Idempotent;
    /// without a stamper, discovery stays silently inert.
    pub async fn enable_on_network_discovery(
        &self,
        stamper: Arc<dyn DiscoveryStamper + Send + Sync>,
    ) {
        *self.discovery.stamper.lock().await = Some(stamper);
        start_on_network_discovery(self.clone()).await;
    }

    pub async fn discovery_enabled(&self) -> bool {
        self.discovery.stamper.lock().await.is_some()
    }

    /// Snapshot of currently-known interfaces. Stale + disallowed entries
    /// are purged on read. Python: `discovered_interfaces()`.
    pub async fn discovered_interfaces(&self) -> Vec<DiscoveredInterface> {
        let store = self.discovery.store.lock().await.clone();
        let Some(store) = store else {
            return Vec::new();
        };
        let sources = if self.config.interface_discovery_sources.is_empty() {
            None
        } else {
            Some(self.config.interface_discovery_sources.as_slice())
        };
        store.list(sources).unwrap_or_default()
    }

    /// Identity hashes whose blackhole manifest this node subscribes to.
    /// Python: `Reticulum.blackhole_sources()`.
    pub fn blackhole_sources(&self) -> &[[u8; 16]] {
        &self.config.blackhole_sources
    }

    pub fn publish_blackhole_enabled(&self) -> bool {
        self.config.publish_blackhole
    }

    #[cfg(test)]
    pub(crate) async fn install_discovery_store_for_tests(&self, store: Arc<DiscoveryStore>) {
        *self.discovery.store.lock().await = Some(store);
    }
}

fn recalled_destination_from_rpc(
    entry: RecalledDestinationRpcEntry,
) -> Result<RecalledDestination, ControlError> {
    let identity = Identity::from_public_key(&entry.public_key)?;
    let last_heard = Duration::try_from_secs_f64(entry.timestamp)
        .ok()
        .and_then(|elapsed| std::time::UNIX_EPOCH.checked_add(elapsed))
        .unwrap_or(std::time::UNIX_EPOCH);
    Ok(RecalledDestination {
        destination_hash: entry.dest_hash,
        identity,
        app_data: entry.app_data,
        ratchet: entry.ratchet,
        hops: entry.hops,
        last_heard,
    })
}

fn control_error_from_rpc(error: crate::rpc::RpcError, timeout: Duration) -> ControlError {
    match error {
        crate::rpc::RpcError::AuthFailed => ControlError::RpcAuth,
        crate::rpc::RpcError::Io(error) if error.kind() == std::io::ErrorKind::TimedOut => {
            ControlError::Timeout(timeout)
        }
        crate::rpc::RpcError::Io(_) | crate::rpc::RpcError::Connection(_) => {
            ControlError::NotConnectedToSharedInstance
        }
        other => ControlError::Rpc(other.to_string()),
    }
}

fn transport_query_to_rpc_request(query: &TransportQuery) -> Option<crate::rpc::RpcRequest> {
    use crate::rpc::RpcRequest;
    Some(match query {
        TransportQuery::GetPathTable => RpcRequest::GetPathTable { max_hops: None },
        TransportQuery::GetInterfaceStats => RpcRequest::GetInterfaceStats,
        TransportQuery::GetRateTable => RpcRequest::GetRateTable,
        TransportQuery::GetLinkCount => RpcRequest::GetLinkCount,
        TransportQuery::GetNextHopIfName { dest } => RpcRequest::GetNextHopIfName {
            destination_hash: dest.to_vec(),
        },
        TransportQuery::GetNextHop { dest } => RpcRequest::GetNextHop {
            destination_hash: dest.to_vec(),
        },
        TransportQuery::FirstHopTimeout { dest } => RpcRequest::GetFirstHopTimeout {
            destination_hash: dest.to_vec(),
        },
        TransportQuery::GetPacketRssi { packet_hash } => RpcRequest::GetPacketRssi {
            packet_hash: packet_hash.to_vec(),
        },
        TransportQuery::GetPacketSnr { packet_hash } => RpcRequest::GetPacketSnr {
            packet_hash: packet_hash.to_vec(),
        },
        TransportQuery::GetPacketQ { packet_hash } => RpcRequest::GetPacketQ {
            packet_hash: packet_hash.to_vec(),
        },
        TransportQuery::GetBlackholedIdentities => RpcRequest::GetBlackholedIdentities,
        // Python 1.3.8 is_blackholed() proxies to the shared instance
        // (Reticulum.py:1655-1659).
        TransportQuery::IsBlackholed { hash } => RpcRequest::IsBlackholed {
            identity_hash: hash.to_vec(),
        },
        TransportQuery::DropPath { dest } => RpcRequest::DropPath {
            destination_hash: dest.to_vec(),
        },
        TransportQuery::DropAllVia { next_hop } => RpcRequest::DropAllVia {
            transport_hash: next_hop.to_vec(),
        },
        TransportQuery::DropAnnounceQueues => RpcRequest::DropAnnounceQueues,
        TransportQuery::BlackholeIdentity {
            hash,
            ttl,
            reason,
            reason_label,
        } => RpcRequest::BlackholeIdentity {
            identity_hash: hash.to_vec(),
            until: ttl.map(|ttl| unix_now() + ttl),
            reason: Some(
                reason_label
                    .clone()
                    .unwrap_or_else(|| reason.as_str().to_string()),
            ),
        },
        TransportQuery::UnblackholeIdentity { hash } => RpcRequest::UnblackholeIdentity {
            identity_hash: hash.to_vec(),
        },
        TransportQuery::RetainDestination { dest } => RpcRequest::RetainDestination {
            destination_hash: dest.to_vec(),
        },
        TransportQuery::RetainIdentity { identity_hash } => RpcRequest::RetainIdentity {
            identity_hash: identity_hash.to_vec(),
        },
        TransportQuery::UseDestination { dest } => RpcRequest::UseDestination {
            destination_hash: dest.to_vec(),
        },
        TransportQuery::UnretainDestination { dest } => RpcRequest::UnretainDestination {
            destination_hash: dest.to_vec(),
        },
        _ => return None,
    })
}

fn rpc_response_to_transport_response(
    response: crate::rpc::RpcResponse,
) -> Option<TransportQueryResponse> {
    use crate::rpc::RpcResponse;
    use rns_transport::messages::{
        BlackholeRpcEntry, InterfaceStatRpcEntry, PathTableRpcEntry, RateTableRpcEntry,
    };

    Some(match response {
        RpcResponse::PathTable(entries) => {
            let entries = entries
                .into_iter()
                .filter_map(|entry| {
                    Some(PathTableRpcEntry {
                        hash: vec_to_16(&entry.hash)?,
                        timestamp: entry.timestamp,
                        via: entry.via.as_deref().and_then(vec_to_16),
                        hops: entry.hops,
                        expires: entry.expires,
                        interface: entry.interface,
                        interface_id: 0,
                        interface_mode: rns_transport::constants::InterfaceMode::Full,
                        interface_role: rns_transport::messages::InterfaceRole::Normal,
                    })
                })
                .collect();
            TransportQueryResponse::PathTable(entries)
        }
        RpcResponse::InterfaceStats(entries) => {
            let entries = entries
                .into_iter()
                .map(|entry| InterfaceStatRpcEntry {
                    id: entry.id,
                    name: entry.name,
                    rx_bytes: entry.rx_bytes,
                    tx_bytes: entry.tx_bytes,
                    rx_rate: entry.rx_rate,
                    tx_rate: entry.tx_rate,
                    online: entry.online,
                    bitrate: entry.bitrate,
                    mtu: entry.mtu,
                    mode: entry.mode,
                    role: entry.role,
                    announce_queue: entry.announce_queue,
                    held_announces: entry.held_announces,
                    incoming_announce_frequency: entry.incoming_announce_frequency,
                    outgoing_announce_frequency: entry.outgoing_announce_frequency,
                    incoming_pr_frequency: entry.incoming_pr_frequency,
                    outgoing_pr_frequency: entry.outgoing_pr_frequency,
                    burst_active: entry.burst_active,
                    burst_activated: entry.burst_activated,
                    pr_burst_active: entry.pr_burst_active,
                    pr_burst_activated: entry.pr_burst_activated,
                    clients: entry.clients,
                    blocked_ips: entry.blocked_ips,
                    announce_rate_target: entry.announce_rate_target,
                    announce_rate_grace: entry.announce_rate_grace,
                    announce_rate_penalty: entry.announce_rate_penalty,
                    announce_cap: entry.announce_cap,
                    ifac_size: entry.ifac_size,
                    tx_drops: entry.tx_drops,
                })
                .collect();
            TransportQueryResponse::InterfaceStats(entries)
        }
        RpcResponse::RateTable(entries) => {
            let entries = entries
                .into_iter()
                .filter_map(|entry| {
                    Some(RateTableRpcEntry {
                        hash: vec_to_16(&entry.hash)?,
                        rate: entry.rate,
                        last: entry.last,
                        rate_violations: entry.rate_violations,
                        blocked_until: entry.blocked_until,
                        timestamps: entry.timestamps,
                    })
                })
                .collect();
            TransportQueryResponse::RateTable(entries)
        }
        RpcResponse::StringResult(v) => TransportQueryResponse::StringResult(v),
        RpcResponse::HashResult(v) => {
            TransportQueryResponse::HashResult(v.as_deref().and_then(vec_to_16))
        }
        RpcResponse::FloatResult(v) => TransportQueryResponse::FloatResult(v),
        RpcResponse::IntResult(v) => TransportQueryResponse::IntResult(v),
        RpcResponse::BoolResult(v) => TransportQueryResponse::BoolResult(v),
        RpcResponse::BlackholeList(entries) => {
            let now = unix_now();
            let entries = entries
                .into_iter()
                .filter_map(|entry| {
                    Some(BlackholeRpcEntry {
                        identity_hash: vec_to_16(&entry.identity_hash)?,
                        source: entry.source.as_deref().and_then(vec_to_16),
                        created: now,
                        ttl: entry.until.map(|until| (until - now).max(0.0)),
                        reason: entry
                            .reason
                            .as_deref()
                            .map(rns_transport::blackhole::BlackholeReason::parse)
                            .unwrap_or_default(),
                        reason_label: entry.reason,
                        // Verification is computed against the *local* actor's
                        // recent_announces, which a remote-RPC bridge cannot
                        // see. Default to false; the local-actor path sets it
                        // correctly.
                        verified: false,
                    })
                })
                .collect();
            TransportQueryResponse::BlackholeList(entries)
        }
        RpcResponse::Ok => TransportQueryResponse::Ok,
        RpcResponse::Error(e) => TransportQueryResponse::Error(e),
    })
}

fn vec_to_16(bytes: &[u8]) -> Option<[u8; 16]> {
    if bytes.len() < 16 {
        return None;
    }
    let mut out = [0u8; 16];
    out.copy_from_slice(&bytes[..16]);
    Some(out)
}

fn unix_now() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstanceMode {
    Shared,
    Client,
    Standalone,
}

/// Shared-instance transport: TCP loopback or AF_UNIX socket. Python uses
/// AF_UNIX only on Linux/Android and TCP elsewhere. Python config key:
/// `shared_instance_type`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SharedInstanceType {
    /// TCP loopback on [`ReticulumConfig::shared_instance_port`].
    Tcp,
    /// AF_UNIX socket; Linux/Android use Python-compatible abstract names.
    Unix,
}

impl SharedInstanceType {
    fn platform_default() -> Self {
        if cfg!(any(target_os = "linux", target_os = "android")) {
            Self::Unix
        } else {
            Self::Tcp
        }
    }
}

/// Per-construction overrides for [`init_with_options`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct InitOptions {
    /// Attach only to an already-running shared instance. The runtime will not
    /// claim the shared-instance listener when none exists.
    pub require_shared_instance: bool,
    /// Override the configured shared-instance transport for this process.
    pub shared_instance_type: Option<SharedInstanceType>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SharedInstanceRpcEndpoint {
    Tcp(u16),
    Unix(String),
}

impl SharedInstanceRpcEndpoint {
    pub fn display(&self) -> String {
        match self {
            Self::Tcp(port) => format!("127.0.0.1:{port}"),
            Self::Unix(path) => socket_path_display(path),
        }
    }
}

fn shared_unix_socket_path(instance_name: &str, socket_base: &Path) -> String {
    if cfg!(any(target_os = "linux", target_os = "android")) {
        rns_interface::local::python_shared_socket_name(instance_name)
    } else {
        socket_base
            .join(format!("reticulum_rs_{instance_name}.sock"))
            .to_string_lossy()
            .to_string()
    }
}

fn shared_unix_rpc_socket_path(instance_name: &str, socket_base: &Path) -> String {
    if cfg!(any(target_os = "linux", target_os = "android")) {
        format!("\0rns/{instance_name}/rpc")
    } else {
        socket_base
            .join(format!("reticulum_rs_{instance_name}.rpc.sock"))
            .to_string_lossy()
            .to_string()
    }
}

pub fn shared_instance_rpc_socket_path(instance_name: &str, socket_base: &Path) -> String {
    shared_unix_rpc_socket_path(instance_name, socket_base)
}

fn shared_tcp_client_config(port: u16) -> rns_interface::tcp::TcpClientConfig {
    rns_interface::tcp::TcpClientConfig::new("SharedInstanceClient", "127.0.0.1", port)
}

async fn detect_shared_tcp_server(port: u16) -> bool {
    let addr = format!("127.0.0.1:{port}");
    tokio::time::timeout(
        Duration::from_millis(250),
        tokio::net::TcpStream::connect(&addr),
    )
    .await
    .is_ok_and(|r| r.is_ok())
}

fn socket_path_display(path: &str) -> String {
    if path.as_bytes().first() == Some(&0) {
        format!("\\0{}", &path[1..])
    } else {
        path.to_string()
    }
}

#[derive(Debug, Clone)]
pub struct ReticulumConfig {
    pub share_instance: bool,
    pub instance_name: String,
    pub shared_instance_type: SharedInstanceType,
    pub shared_instance_port: u16,
    pub control_port: u16,
    pub enable_transport: bool,
    /// Python 1.3.8 `static_transport_identity` (Reticulum.py:255,502-504,
    /// default false): opts a non-transport node out of the per-boot
    /// ephemeral wire-facing transport identity.
    pub static_transport_identity: bool,
    /// Python 1.3.8 `local_hops_delta` (Reticulum.py:256,506-508, default
    /// false): apply a per-boot random 2..=7 hop offset to locally-originated
    /// packets (Transport.py:240,1356-1365).
    pub local_hops_delta: bool,
    pub respond_to_probes: bool,
    pub use_implicit_proof: bool,
    pub panic_on_interface_error: bool,
    pub link_mtu_discovery: bool,
    pub enable_remote_management: bool,
    pub remote_management_allowed: Vec<Vec<u8>>,
    pub rpc_key: Option<Vec<u8>>,
    /// Python `force_shared_instance_bitrate` (bps). Caps announce rate /
    /// token bucket regardless of real link bitrate.
    pub force_shared_instance_bitrate: Option<u64>,
    pub default_ar_target: Option<u64>,
    pub default_ar_penalty: Option<u64>,
    pub default_ar_grace: Option<u32>,
    /// Global Reticulum defaults for per-interface ingress/egress control.
    pub ingress_overrides: rns_transport::ingress::IngressOverrides,
    pub loglevel: i32,

    /// Optional "network identity" file: discovery announce app_data is
    /// encrypted to this identity's pubkey. Python `network_identity`.
    pub network_identity_path: Option<PathBuf>,
    /// Publish periodic discovery announces. Python `discover_interfaces`.
    pub discover_interfaces: bool,
    /// Maximum number of discovered interfaces to auto-connect to. Python
    /// `autoconnect_discovered_interfaces`.
    pub autoconnect_discovered_interfaces: usize,
    /// Minimum stamp value (leading-zero bits). Default 16 (LXStamper
    /// `DEFAULT_STAMP_VALUE`). Python `required_discovery_value`.
    pub discover_interfaces_required_value: u8,
    /// Accepted discovery publisher identities. Python
    /// `interface_discovery_sources`.
    pub interface_discovery_sources: Vec<[u8; 16]>,

    /// Identity hashes whose `rnstransport.info.blackhole` manifests this
    /// node subscribes to. Python `blackhole_sources`.
    pub blackhole_sources: Vec<[u8; 16]>,
    /// Publish this node's local blackhole table on
    /// `rnstransport.info.blackhole`. Python `publish_blackhole`.
    pub publish_blackhole: bool,
    /// Seconds between blackhole-source pulls. Python 1.3.8
    /// `blackhole_update_interval` (Reticulum.py:266,593-596): parsed as
    /// float minutes, clamped to min 2, stored as seconds; default 3600.
    pub blackhole_update_interval: f64,
    /// Python 1.3.8 `[logging] logtimestamps` (Reticulum.py:459-461,
    /// RNS/__init__.py:85 default True): log lines carry a timestamp prefix.
    pub log_timestamps: bool,

    /// Bootstrap config files loaded on startup. Python `bootstrap_configs`.
    pub bootstrap_configs: Vec<PathBuf>,
}

impl Default for ReticulumConfig {
    fn default() -> Self {
        Self {
            share_instance: true,
            instance_name: DEFAULT_INSTANCE_NAME.to_string(),
            shared_instance_type: SharedInstanceType::platform_default(),
            shared_instance_port: LOCAL_INTERFACE_PORT,
            control_port: LOCAL_CONTROL_PORT,
            enable_transport: false,
            static_transport_identity: false,
            local_hops_delta: false,
            respond_to_probes: false,
            use_implicit_proof: true,
            panic_on_interface_error: false,
            link_mtu_discovery: true,
            enable_remote_management: false,
            remote_management_allowed: Vec::new(),
            rpc_key: None,
            force_shared_instance_bitrate: None,
            default_ar_target: None,
            default_ar_penalty: None,
            default_ar_grace: None,
            ingress_overrides: rns_transport::ingress::IngressOverrides::default(),
            loglevel: 4,
            network_identity_path: None,
            discover_interfaces: false,
            autoconnect_discovered_interfaces: 0,
            discover_interfaces_required_value: rns_transport::discovery::DEFAULT_STAMP_VALUE,
            interface_discovery_sources: Vec::new(),
            blackhole_sources: Vec::new(),
            publish_blackhole: false,
            blackhole_update_interval:
                rns_transport::discovery::blackhole_subscriber::UPDATE_INTERVAL.as_secs_f64(),
            log_timestamps: true,
            bootstrap_configs: Vec::new(),
        }
    }
}

impl ReticulumConfig {
    pub fn shared_rpc_endpoint(&self, socket_base: &Path) -> SharedInstanceRpcEndpoint {
        match self.shared_instance_type {
            SharedInstanceType::Tcp => SharedInstanceRpcEndpoint::Tcp(self.control_port),
            SharedInstanceType::Unix => SharedInstanceRpcEndpoint::Unix(
                shared_instance_rpc_socket_path(&self.instance_name, socket_base),
            ),
        }
    }
}

fn invalid_config_value(section: &str, key: &str, message: impl Into<String>) -> ConfigError {
    ConfigError::InvalidValue {
        section: section.to_string(),
        key: key.to_string(),
        message: message.into(),
    }
}

fn config_bool(
    section_name: &str,
    section: &ConfigSection,
    key: &str,
) -> Result<Option<bool>, ConfigError> {
    if !section.has(key) {
        return Ok(None);
    }
    section
        .get_bool(key)
        .map(Some)
        .ok_or_else(|| invalid_config_value(section_name, key, "value is neither True nor False"))
}

fn config_int(
    section_name: &str,
    section: &ConfigSection,
    key: &str,
) -> Result<Option<i64>, ConfigError> {
    if !section.has(key) {
        return Ok(None);
    }
    section
        .get_int(key)
        .map(Some)
        .ok_or_else(|| invalid_config_value(section_name, key, "value is not an integer"))
}

fn config_uint(
    section_name: &str,
    section: &ConfigSection,
    key: &str,
) -> Result<Option<u64>, ConfigError> {
    if !section.has(key) {
        return Ok(None);
    }
    section
        .get_uint(key)
        .map(Some)
        .ok_or_else(|| invalid_config_value(section_name, key, "value is not an unsigned integer"))
}

fn config_float(
    section_name: &str,
    section: &ConfigSection,
    key: &str,
) -> Result<Option<f64>, ConfigError> {
    if !section.has(key) {
        return Ok(None);
    }
    section
        .get_float(key)
        .map(Some)
        .ok_or_else(|| invalid_config_value(section_name, key, "value is not a float"))
}

fn config_u16(
    section_name: &str,
    section: &ConfigSection,
    key: &str,
) -> Result<Option<u16>, ConfigError> {
    let Some(value) = config_uint(section_name, section, key)? else {
        return Ok(None);
    };
    let value = u16::try_from(value)
        .map_err(|_| invalid_config_value(section_name, key, "value is outside u16 range"))?;
    Ok(Some(value))
}

fn parse_ingress_overrides(
    section_name: &str,
    section: &ConfigSection,
) -> Result<rns_transport::ingress::IngressOverrides, ConfigError> {
    Ok(rns_transport::ingress::IngressOverrides {
        burst_freq_new: config_float(section_name, section, "ic_burst_freq_new")?,
        burst_freq: config_float(section_name, section, "ic_burst_freq")?,
        pr_burst_freq_new: config_float(section_name, section, "ic_pr_burst_freq_new")?,
        pr_burst_freq: config_float(section_name, section, "ic_pr_burst_freq")?,
        new_time: config_float(section_name, section, "ic_new_time")?,
        burst_hold: config_float(section_name, section, "ic_burst_hold")?,
        burst_penalty: config_float(section_name, section, "ic_burst_penalty")?,
        max_held: config_uint(section_name, section, "ic_max_held_announces")?.map(|v| v as usize),
        held_release_interval: config_float(section_name, section, "ic_held_release_interval")?,
        ec_pr_freq: config_float(section_name, section, "ec_pr_freq")?,
        egress_control: config_bool(section_name, section, "egress_control")?,
        ..Default::default()
    })
}

fn merge_ingress_overrides(
    base: &rns_transport::ingress::IngressOverrides,
    overlay: &rns_transport::ingress::IngressOverrides,
) -> rns_transport::ingress::IngressOverrides {
    rns_transport::ingress::IngressOverrides {
        enabled: overlay.enabled.or(base.enabled),
        burst_freq_new: overlay.burst_freq_new.or(base.burst_freq_new),
        burst_freq: overlay.burst_freq.or(base.burst_freq),
        pr_burst_freq_new: overlay.pr_burst_freq_new.or(base.pr_burst_freq_new),
        pr_burst_freq: overlay.pr_burst_freq.or(base.pr_burst_freq),
        new_time: overlay.new_time.or(base.new_time),
        burst_hold: overlay.burst_hold.or(base.burst_hold),
        burst_penalty: overlay.burst_penalty.or(base.burst_penalty),
        max_held: overlay.max_held.or(base.max_held),
        held_release_interval: overlay.held_release_interval.or(base.held_release_interval),
        ec_pr_freq: overlay.ec_pr_freq.or(base.ec_pr_freq),
        egress_control: overlay.egress_control.or(base.egress_control),
    }
}

fn parse_autoconnect_limit(sec: &ConfigSection) -> Result<Option<usize>, ConfigError> {
    if let Some(v) = config_uint("reticulum", sec, "autoconnect_discovered_interfaces")? {
        return Ok(Some(v as usize));
    }

    // Rust retained this pre-1.2.1 alias while adding the upstream integer
    // key above. Keep bool support only for the alias so the Python key still
    // rejects `Yes`/`No` like ConfigObj `as_int()`.
    let key = "discover_interfaces_autoconnect";
    if sec.has(key) {
        if let Some(v) = sec.get_uint(key) {
            return Ok(Some(v as usize));
        }
        if let Some(v) = sec.get_bool(key) {
            return Ok(Some(usize::from(v)));
        }
        return Err(invalid_config_value(
            "reticulum",
            key,
            "value is not an integer or boolean",
        ));
    }

    Ok(None)
}

fn parse_hash16_list(key: &str, list: Option<Vec<String>>) -> Result<Vec<[u8; 16]>, ConfigError> {
    let mut parsed = Vec::new();
    for value in list.unwrap_or_default() {
        let hexhash = value.trim();
        let bytes = hex_decode(hexhash)
            .ok_or_else(|| invalid_config_value("reticulum", key, "invalid identity hash"))?;
        if bytes.len() != 16 {
            return Err(invalid_config_value(
                "reticulum",
                key,
                "identity hash must be 32 hexadecimal characters (16 bytes)",
            ));
        }
        let mut hash = [0u8; 16];
        hash.copy_from_slice(&bytes);
        parsed.push(hash);
    }
    Ok(parsed)
}

fn expand_home_path(path: &str) -> PathBuf {
    if path == "~" || path.starts_with("~/") {
        if let Ok(home) = std::env::var("HOME") {
            return PathBuf::from(format!("{home}{}", &path[1..]));
        }
    }
    PathBuf::from(path)
}

impl ReticulumConfig {
    pub fn try_from_config(config: &Config) -> Result<Self, ConfigError> {
        let mut rc = ReticulumConfig::default();

        if let Some(sec) = config.section("reticulum") {
            if let Some(value) = config_bool("reticulum", sec, "share_instance")? {
                rc.share_instance = value;
            }
            if let Some(name) = sec.get("instance_name") {
                rc.instance_name = name.to_string();
            }
            if let Some(kind) = sec.get("shared_instance_type") {
                match kind.trim().to_lowercase().as_str() {
                    "tcp" => rc.shared_instance_type = SharedInstanceType::Tcp,
                    "unix" => rc.shared_instance_type = SharedInstanceType::Unix,
                    _ => {}
                }
            }
            if let Some(port) = config_u16("reticulum", sec, "shared_instance_port")? {
                rc.shared_instance_port = port;
            }
            if let Some(port) = config_u16("reticulum", sec, "instance_control_port")? {
                rc.control_port = port;
            }
            if let Some(value) = config_bool("reticulum", sec, "enable_transport")? {
                rc.enable_transport = value;
            }
            if let Some(value) = config_bool("reticulum", sec, "static_transport_identity")? {
                rc.static_transport_identity = value;
            }
            if let Some(value) = config_bool("reticulum", sec, "local_hops_delta")? {
                rc.local_hops_delta = value;
            }
            if let Some(value) = config_bool("reticulum", sec, "respond_to_probes")? {
                rc.respond_to_probes = value;
            }
            if let Some(value) = config_bool("reticulum", sec, "use_implicit_proof")? {
                rc.use_implicit_proof = value;
            }
            if let Some(value) = config_bool("reticulum", sec, "panic_on_interface_error")? {
                rc.panic_on_interface_error = value;
            }
            if let Some(value) = config_bool("reticulum", sec, "link_mtu_discovery")? {
                rc.link_mtu_discovery = value;
            }
            if let Some(value) = config_bool("reticulum", sec, "enable_remote_management")? {
                rc.enable_remote_management = value;
            }
            rc.force_shared_instance_bitrate =
                config_uint("reticulum", sec, "force_shared_instance_bitrate")?;
            if let Some(v) = config_uint("reticulum", sec, "default_ar_target")? {
                rc.default_ar_target = (v > 0).then_some(v);
            }
            if let Some(v) = config_uint("reticulum", sec, "default_ar_penalty")? {
                rc.default_ar_penalty = Some(v);
            }
            if let Some(v) = config_uint("reticulum", sec, "default_ar_grace")? {
                rc.default_ar_grace = Some(v.min(u32::MAX as u64) as u32);
            }
            rc.ingress_overrides = parse_ingress_overrides("reticulum", sec)?;

            if let Some(list) = sec.get_list("remote_management_allowed") {
                rc.remote_management_allowed =
                    parse_hash16_list("remote_management_allowed", Some(list))?
                        .into_iter()
                        .map(|hash| hash.to_vec())
                        .collect();
            }
            if let Some(key) = sec.get_hex("rpc_key") {
                rc.rpc_key = Some(key);
            }

            if let Some(path) = sec.get("network_identity") {
                let trimmed = path.trim();
                if !trimmed.is_empty() {
                    rc.network_identity_path = Some(expand_home_path(trimmed));
                }
            }
            if let Some(value) = config_bool("reticulum", sec, "discover_interfaces")? {
                rc.discover_interfaces = value;
            }
            rc.autoconnect_discovered_interfaces =
                parse_autoconnect_limit(sec)?.unwrap_or(rc.autoconnect_discovered_interfaces);
            if let Some(v) = config_uint("reticulum", sec, "required_discovery_value")?.or(
                config_uint("reticulum", sec, "discover_interfaces_required_value")?,
            ) {
                rc.discover_interfaces_required_value = v.min(u8::MAX as u64) as u8;
            }
            rc.interface_discovery_sources = parse_hash16_list(
                "interface_discovery_sources",
                sec.get_list("interface_discovery_sources"),
            )?;
            if let Some(value) = config_bool("reticulum", sec, "publish_blackhole")? {
                rc.publish_blackhole = value;
            }

            if let Some(list) = sec.get_list("blackhole_sources") {
                rc.blackhole_sources = parse_hash16_list("blackhole_sources", Some(list))?;
            }
            // Reticulum.py:593-596: float minutes, clamped to min 2, stored ×60.
            if let Some(v) = config_float("reticulum", sec, "blackhole_update_interval")? {
                rc.blackhole_update_interval = v.max(2.0) * 60.0;
            }
            if let Some(list) = sec.get_list("bootstrap_configs") {
                rc.bootstrap_configs = list.iter().map(|s| PathBuf::from(s.trim())).collect();
            }
        }

        if let Some(sec) = config.section("logging") {
            if let Some(level) = config_int("logging", sec, "loglevel")? {
                rc.loglevel = (level as i32).clamp(0, 7);
            }
            if let Some(value) = config_bool("logging", sec, "logtimestamps")? {
                rc.log_timestamps = value;
            }
        }

        Ok(rc)
    }

    pub fn from_config(config: &Config) -> Self {
        Self::try_from_config(config).expect("valid Reticulum configuration")
    }
}

/// Python 1.3.8 Transport.py:234-238: the wire-facing transport identity is
/// ephemeral per boot exactly when transport is disabled and
/// `static_transport_identity` is unset.
fn uses_ephemeral_transport_identity(rc: &ReticulumConfig) -> bool {
    !rc.enable_transport && !rc.static_transport_identity
}

/// Python 1.3.8 Transport.py:240: per-boot random hop delta,
/// `(ord(os.urandom(1)) % 6) + 2` = 2..=7.
fn generate_local_hops_delta() -> u8 {
    (rns_crypto::random::random_bytes(1)[0] % 6) + 2
}

/// Bring up the Reticulum runtime: config dir, transport actor, interfaces,
/// instance mode, jobs runner, and optional RPC / remote-management / probe.
pub async fn init(
    configdir: Option<&str>,
    socket_dir: Option<PathBuf>,
    shutdown: ShutdownSignal,
    is_foreground: Arc<AtomicBool>,
) -> Result<ReticulumHandle, ReticulumError> {
    init_with_options(
        configdir,
        socket_dir,
        shutdown,
        is_foreground,
        InitOptions::default(),
    )
    .await
}

/// Bring up Reticulum with explicit construction-time instance options.
pub async fn init_with_options(
    configdir: Option<&str>,
    socket_dir: Option<PathBuf>,
    shutdown: ShutdownSignal,
    is_foreground: Arc<AtomicBool>,
    options: InitOptions,
) -> Result<ReticulumHandle, ReticulumError> {
    init_with_options_and_rnode_startup_options(
        configdir,
        socket_dir,
        shutdown,
        is_foreground,
        options,
        rns_interface::rnode::RNodeStartupOptions::default(),
    )
    .await
}

/// Bring up Reticulum with explicit instance and configured-RNode startup
/// policies.
///
/// The RNode policy applies only to configured `RNodeInterface` and
/// `RNodeInterface_BLE` entries. Other interface kinds, including RNodeMulti,
/// retain their established startup behavior.
pub async fn init_with_options_and_rnode_startup_options(
    configdir: Option<&str>,
    socket_dir: Option<PathBuf>,
    shutdown: ShutdownSignal,
    is_foreground: Arc<AtomicBool>,
    options: InitOptions,
    rnode_startup_options: rns_interface::rnode::RNodeStartupOptions,
) -> Result<ReticulumHandle, ReticulumError> {
    let started_at = std::time::Instant::now();
    let config_dir = resolve_config_dir(configdir);
    let paths = StoragePaths::from_config_dir(&config_dir);
    paths.ensure_dirs().map_err(ReticulumError::Io)?;

    let config_path = config_dir.join("config");
    let (config, config_created) = load_or_create_config(&config_path)?;
    if config_created {
        tracing::info!(
            path = %config_path.display(),
            "created default Reticulum config; continuing after first-run grace period"
        );
        tokio::time::sleep(Duration::from_millis(1500)).await;
    }
    let mut rc = ReticulumConfig::try_from_config(&config).map_err(ReticulumError::Config)?;
    if let Some(shared_instance_type) = options.shared_instance_type {
        rc.shared_instance_type = shared_instance_type;
    }

    let (mut actor, transport_tx) = rns_transport::actor::TransportActor::new();
    let persistence_trigger = actor.persistence_trigger();
    actor.is_foreground = is_foreground.clone();
    actor.initialize_storage(paths.storage_dir.clone());
    // Python 1.3.8 Transport.py:234-238: non-transport nodes get a fresh
    // per-boot wire-facing transport identity unless static_transport_identity
    // is set. Pre-seed the actor's hash so runtime-side wire consumers
    // (discovery announcer, blackhole publisher/subscriber) share the value.
    actor.static_transport_identity = rc.static_transport_identity;
    // Python 1.3.8 Transport.py:240: one random 2..=7 delta per boot;
    // should_apply_delta gates actual application.
    if rc.local_hops_delta {
        actor.local_hops_delta = generate_local_hops_delta();
    }
    let ephemeral_transport_identity =
        uses_ephemeral_transport_identity(&rc).then(rns_identity::identity::Identity::new);
    if let Some(ephemeral) = &ephemeral_transport_identity {
        actor.ephemeral_identity_hash = Some(ephemeral.hash);
    }

    let transport_completion = Arc::new(TransportCompletion::default());
    let id_gen = Arc::new(AtomicU64::new(1));
    // Sub-interface sink (e.g. TCP per-client). The receiver task is retained
    // by the shutdown coordinator instead of being detached.
    let (handle_tx, handle_rx) = mpsc::channel::<rns_interface::traits::InterfaceHandle>(64);
    let interface_controls: InterfaceControlMap = Arc::new(std::sync::Mutex::new(HashMap::new()));
    let interface_registry = InterfaceRegistry::default();
    let shutdown_coordinator = RuntimeShutdownCoordinator::new(
        shutdown.clone(),
        transport_tx.clone(),
        transport_completion.clone(),
        interface_controls.clone(),
        interface_registry.clone(),
    );
    let init_shutdown_guard = InitShutdownGuard {
        coordinator: Some(shutdown_coordinator.clone()),
    };
    let accepted_child_pump = tokio::spawn(run_accepted_child_registration_pump(
        handle_rx,
        transport_tx.clone(),
        interface_controls.clone(),
        interface_registry.clone(),
        shutdown.clone(),
        rc.force_shared_instance_bitrate,
    ));
    shutdown_coordinator.install_accepted_child_pump(accepted_child_pump);
    {
        let coordinator = shutdown_coordinator.clone();
        let shutdown_watcher = shutdown.clone();
        tokio::spawn(async move {
            shutdown_watcher.wait().await;
            coordinator.start();
        });
    }
    {
        let completion_guard = TransportActorCompletionGuard {
            completion: transport_completion.clone(),
            coordinator: shutdown_coordinator.clone(),
        };
        tokio::spawn(async move {
            let _completion_guard = completion_guard;
            actor.run().await;
        });
    }

    // Persistent transport identity (Python 1.3.8 Transport._identity /
    // internal_identity()): the actor keeps it for RPC-key parity and swaps
    // in the ephemeral hash itself when the policy applies.
    let transport_identity_path = paths.storage_dir.join("transport_identity");
    let transport_identity = match rns_identity::identity::Identity::from_file(
        &transport_identity_path,
    ) {
        Ok(id) => id,
        Err(_) => {
            let id = rns_identity::identity::Identity::new();
            if let Err(e) = id.to_file(&transport_identity_path) {
                tracing::warn!(path = %transport_identity_path.display(), error = %e,
                    "failed to persist transport identity — path request identity will change on restart");
            }
            id
        }
    };
    let _ = transport_tx.try_send(TransportMessage::SetTransportIdentity {
        identity_hash: transport_identity.hash,
    });
    let _ = transport_tx.try_send(TransportMessage::SetBlackholeSources {
        sources: rc.blackhole_sources.clone(),
    });

    // Python defaults the local shared-instance RPC key to a hash of the
    // PERSISTENT transport identity (internal_identity(), Reticulum.py:352),
    // so RPC auth stays stable across the per-boot ephemeral rotation.
    if rc.rpc_key.is_none() {
        if let Some(private_key) = transport_identity.get_private_key() {
            rc.rpc_key = Some(crate::rpc::derive_rpc_key(&*private_key).to_vec());
        }
    }
    let transport_identity = Arc::new(transport_identity);
    // Wire-facing identity for runtime consumers (Python Transport.identity):
    // ephemeral when the non-transport default policy is active.
    let wire_transport_identity = match ephemeral_transport_identity {
        Some(ephemeral) => Arc::new(ephemeral),
        None => transport_identity.clone(),
    };

    let network_identity = rc
        .network_identity_path
        .as_ref()
        .map(|path| load_or_create_network_identity(path))
        .transpose()?;

    let socket_base = socket_dir.clone().unwrap_or_else(std::env::temp_dir);
    let mut shared_spawn_permit = Some(match interface_registry.acquire_spawn_permit() {
        Ok(permit) => permit,
        Err(_) => {
            shutdown_coordinator.wait().await;
            return Err(ReticulumError::Interface(
                "runtime shutdown during interface initialization".to_string(),
            ));
        }
    });
    let instance_mode = if rc.share_instance {
        if rc.shared_instance_type == SharedInstanceType::Tcp {
            let live_server_detected = detect_shared_tcp_server(rc.shared_instance_port).await;

            if live_server_detected {
                let client_config = shared_tcp_client_config(rc.shared_instance_port);
                let client_id = next_id(&id_gen);
                match rns_interface::tcp::spawn_tcp_client(
                    client_config,
                    client_id,
                    transport_tx.clone(),
                )
                .await
                {
                    Ok(client_handle) => {
                        adopt_shared_instance_client(
                            client_handle,
                            &transport_tx,
                            &interface_controls,
                            &interface_registry,
                            &shutdown,
                            rc.force_shared_instance_bitrate,
                            shared_spawn_permit.take(),
                        )
                        .await
                    }
                    Err(_) => InstanceMode::Standalone,
                }
            } else if options.require_shared_instance {
                InstanceMode::Standalone
            } else {
                let server_config = rns_interface::tcp::TcpServerConfig::new(
                    "SharedInstanceServer",
                    "127.0.0.1",
                    rc.shared_instance_port,
                );
                let server_id = next_id(&id_gen);
                match rns_interface::tcp::spawn_tcp_server(
                    server_config,
                    server_id,
                    id_gen.clone(),
                    transport_tx.clone(),
                    handle_tx.clone(),
                )
                .await
                {
                    Ok(server_handle) => {
                        let mut server_handle = server_handle;
                        apply_forced_shared_instance_bitrate(
                            &mut server_handle,
                            rc.force_shared_instance_bitrate,
                        );
                        match register_interface_handle_with_role_and_spawn_permit(
                            &transport_tx,
                            server_handle,
                            rns_transport::messages::InterfaceRole::SharedServer,
                            &interface_controls,
                            &interface_registry,
                            shared_spawn_permit.take(),
                        )
                        .await
                        {
                            Ok(()) => InstanceMode::Shared,
                            Err(error) => {
                                tracing::warn!(
                                    error = %error,
                                    "failed to register shared TCP server interface"
                                );
                                InstanceMode::Standalone
                            }
                        }
                    }
                    Err(_) => {
                        if detect_shared_tcp_server(rc.shared_instance_port).await {
                            let client_config = shared_tcp_client_config(rc.shared_instance_port);
                            let client_id = next_id(&id_gen);
                            match rns_interface::tcp::spawn_tcp_client(
                                client_config,
                                client_id,
                                transport_tx.clone(),
                            )
                            .await
                            {
                                Ok(client_handle) => {
                                    adopt_shared_instance_client(
                                        client_handle,
                                        &transport_tx,
                                        &interface_controls,
                                        &interface_registry,
                                        &shutdown,
                                        rc.force_shared_instance_bitrate,
                                        shared_spawn_permit.take(),
                                    )
                                    .await
                                }
                                Err(_) => InstanceMode::Standalone,
                            }
                        } else {
                            InstanceMode::Standalone
                        }
                    }
                }
            }
        } else {
            let socket_path = shared_unix_socket_path(&rc.instance_name, &socket_base);
            // Probe before binding: spawn_local_server unconditionally removes
            // the socket, which would otherwise hijack a live sibling's listener.
            #[cfg(unix)]
            let mut live_server_detected = false;
            #[cfg(not(unix))]
            let live_server_detected = false;
            #[cfg(unix)]
            {
                let is_abstract = socket_path.as_bytes().first() == Some(&0);
                if is_abstract || std::path::Path::new(&socket_path).exists() {
                    match tokio::net::UnixStream::connect(&socket_path).await {
                        Ok(_) => {
                            tracing::info!(
                                "existing shared instance detected on {}",
                                socket_path_display(&socket_path)
                            );
                            live_server_detected = true;
                        }
                        Err(_) => {
                            if !is_abstract {
                                tracing::info!(
                                    "removing stale shared instance socket: {}",
                                    socket_path_display(&socket_path)
                                );
                                std::fs::remove_file(&socket_path).ok();
                            }
                        }
                    }
                }
            }

            if live_server_detected {
                let client_config = rns_interface::local::LocalClientConfig {
                    socket_path,
                    name: "SharedInstanceClient".to_string(),
                };
                let client_id = next_id(&id_gen);
                match rns_interface::local::spawn_local_client(
                    client_config,
                    client_id,
                    transport_tx.clone(),
                )
                .await
                {
                    Ok(client_handle) => {
                        adopt_shared_instance_client(
                            client_handle,
                            &transport_tx,
                            &interface_controls,
                            &interface_registry,
                            &shutdown,
                            rc.force_shared_instance_bitrate,
                            shared_spawn_permit.take(),
                        )
                        .await
                    }
                    Err(_) => InstanceMode::Standalone,
                }
            } else if options.require_shared_instance {
                InstanceMode::Standalone
            } else {
                let server_config = rns_interface::local::LocalServerConfig {
                    socket_path: socket_path.clone(),
                    name: "SharedInstanceServer".to_string(),
                };
                match rns_interface::local::spawn_local_server(
                    server_config,
                    id_gen.clone(),
                    transport_tx.clone(),
                    handle_tx.clone(),
                )
                .await
                {
                    Ok(server_handle) => {
                        let mut server_handle = server_handle;
                        apply_forced_shared_instance_bitrate(
                            &mut server_handle,
                            rc.force_shared_instance_bitrate,
                        );
                        match register_interface_handle_with_role_and_spawn_permit(
                            &transport_tx,
                            server_handle,
                            rns_transport::messages::InterfaceRole::SharedServer,
                            &interface_controls,
                            &interface_registry,
                            shared_spawn_permit.take(),
                        )
                        .await
                        {
                            Ok(()) => InstanceMode::Shared,
                            Err(error) => {
                                tracing::warn!(
                                    error = %error,
                                    "failed to register shared local server interface"
                                );
                                InstanceMode::Standalone
                            }
                        }
                    }
                    Err(_) => {
                        let client_config = rns_interface::local::LocalClientConfig {
                            socket_path,
                            name: "SharedInstanceClient".to_string(),
                        };
                        let client_id = next_id(&id_gen);
                        match rns_interface::local::spawn_local_client(
                            client_config,
                            client_id,
                            transport_tx.clone(),
                        )
                        .await
                        {
                            Ok(client_handle) => {
                                adopt_shared_instance_client(
                                    client_handle,
                                    &transport_tx,
                                    &interface_controls,
                                    &interface_registry,
                                    &shutdown,
                                    rc.force_shared_instance_bitrate,
                                    shared_spawn_permit.take(),
                                )
                                .await
                            }
                            Err(_) => InstanceMode::Standalone,
                        }
                    }
                }
            }
        }
    } else {
        InstanceMode::Standalone
    };
    drop(shared_spawn_permit);

    if !interface_registry.is_open() {
        shutdown_coordinator.wait().await;
        return Err(ReticulumError::Interface(
            "runtime shutdown during interface initialization".to_string(),
        ));
    }

    if options.require_shared_instance && instance_mode != InstanceMode::Client {
        shutdown_coordinator.start_and_wait().await;
        return Err(ReticulumError::RequiredSharedInstanceUnavailable);
    }

    if instance_mode == InstanceMode::Client {
        if rc.enable_transport
            || rc.enable_remote_management
            || rc.respond_to_probes
            || rc.discover_interfaces
            || rc.autoconnect_discovered_interfaces > 0
            || rc.publish_blackhole
            || !rc.blackhole_sources.is_empty()
        {
            tracing::info!(
                "shared-instance client mode suppresses local transport, management and discovery features"
            );
        }
        rc.enable_transport = false;
        rc.enable_remote_management = false;
        rc.respond_to_probes = false;
        rc.discover_interfaces = false;
        rc.autoconnect_discovered_interfaces = 0;
        rc.publish_blackhole = false;
        rc.blackhole_sources.clear();
    }

    // Rebroadcast / path forwarding / reverse-path proof routing requires
    // explicit opt-in; otherwise rnsd behaves as a leaf. Shared-instance
    // clients leave transport duties to their shared sibling.
    if rc.enable_transport {
        let _ = transport_tx.try_send(TransportMessage::SetTransportEnabled { enabled: true });
        tracing::info!("transport node mode enabled");
    }

    let mut interfaces = match synthesize_interfaces(&config, rc.panic_on_interface_error) {
        Ok(interfaces) => interfaces,
        Err(e) => {
            shutdown_coordinator.start_and_wait().await;
            return Err(e);
        }
    };
    if !interfaces.is_empty() {
        tracing::info!("synthesized {} interfaces from config", interfaces.len());
    }
    for iface_config in &mut interfaces {
        apply_discovery_mode_autocorrect(&config, iface_config);
    }
    let interfaces = interfaces;

    let discovery_runtime = Arc::new(DiscoveryRuntime::default());
    if let Ok(store) = DiscoveryStore::open(&paths.storage_dir) {
        *discovery_runtime.store.lock().await = Some(Arc::new(store));
    }
    let mut startup_rnode_runtimes = Vec::new();

    // Client mode leaves hardware to the Shared sibling.
    if instance_mode != InstanceMode::Client {
        for iface_config in &interfaces {
            let spawn_permit = match interface_registry.acquire_spawn_permit() {
                Ok(permit) => permit,
                Err(_) => {
                    shutdown_coordinator.wait().await;
                    return Err(ReticulumError::Interface(
                        "runtime shutdown during interface initialization".to_string(),
                    ));
                }
            };
            let iface_id = next_id(&id_gen);
            let mut post_init = get_post_init_for_config(&config, iface_config);
            finalize_post_init(&mut post_init, &rc);
            let discovery_config = discovery_config_for_interface(
                &config,
                iface_config,
                &post_init,
                rc.enable_transport,
            );
            let bootstrap_only = interface_bootstrap_only(&config, iface_config);
            let ifac_key = derive_ifac_key_from_post_init(&post_init);

            match spawn_interface_with_rnode_startup_options(
                iface_config,
                iface_id,
                transport_tx.clone(),
                id_gen.clone(),
                handle_tx.clone(),
                &socket_base,
                is_foreground.clone(),
                rnode_startup_options,
            )
            .await
            {
                Ok(iface_handles) => {
                    let pending_rnode =
                        pending_configured_rnode_runtime(iface_config, &iface_handles);
                    match register_interfaces_with_post_init_batch(
                        &transport_tx,
                        iface_handles,
                        &post_init,
                        ifac_key,
                        &interface_controls,
                        &interface_registry,
                        interface_kind_for_config(iface_config),
                        Some(spawn_permit),
                    )
                    .await
                    {
                        Ok(registered_ids) => {
                            if let Some(runtime) =
                                pending_rnode.and_then(|pending| pending.commit(&registered_ids))
                            {
                                startup_rnode_runtimes.push(runtime);
                            }
                            for registered_id in registered_ids {
                                if let Some(ref cfg) = discovery_config {
                                    discovery_runtime.local_interfaces.lock().await.push(
                                        LocalDiscoveryInterface {
                                            id: registered_id,
                                            config: cfg.clone(),
                                        },
                                    );
                                }
                                if bootstrap_only {
                                    discovery_runtime
                                        .bootstrap_interfaces
                                        .lock()
                                        .await
                                        .push(registered_id);
                                }
                            }
                        }
                        Err(error) if rc.panic_on_interface_error => {
                            shutdown_coordinator.start_and_wait().await;
                            return Err(ReticulumError::Interface(error.to_string()));
                        }
                        Err(error) => {
                            tracing::warn!("failed to register interface: {error}");
                        }
                    }
                }
                Err(e) => {
                    if rc.panic_on_interface_error {
                        drop(spawn_permit);
                        shutdown_coordinator.start_and_wait().await;
                        return Err(ReticulumError::Interface(e));
                    } else {
                        drop(spawn_permit);
                        tracing::warn!("failed to spawn interface: {}", e);
                    }
                }
            }
        }
    }

    let handle = ReticulumHandle {
        transport_tx: transport_tx.clone(),
        config_dir: config_dir.clone(),
        instance_mode,
        interface_configs: interfaces,
        id_gen: id_gen.clone(),
        handle_tx: handle_tx.clone(),
        interface_controls: interface_controls.clone(),
        interface_registry: interface_registry.clone(),
        socket_base: socket_base.clone(),
        config: rc.clone(),
        is_foreground,
        shutdown: shutdown.clone(),
        transport_identity: wire_transport_identity,
        network_identity: network_identity.clone(),
        discovery: discovery_runtime,
        startup_rnode_runtimes,
        shutdown_coordinator: shutdown_coordinator.clone(),
        started_at,
    };

    if !interface_registry.is_open() {
        shutdown_coordinator.wait().await;
        return Err(ReticulumError::Interface(
            "runtime shutdown during interface initialization".to_string(),
        ));
    }

    if instance_mode != InstanceMode::Client && rc.publish_blackhole {
        match start_blackhole_publisher(&handle).await {
            Ok(dest) => tracing::info!(dest = %hex::encode(dest), "blackhole publisher started"),
            Err(e) => tracing::warn!("failed to start blackhole publisher: {}", e),
        }
    }
    if instance_mode != InstanceMode::Client && !rc.blackhole_sources.is_empty() {
        start_blackhole_subscriber(handle.clone()).await;
    }

    if instance_mode != InstanceMode::Client {
        let cache_dir = paths.cache_dir.clone();
        let resource_dir = paths.resource_dir.clone();
        let job_shutdown = shutdown.clone();
        tokio::spawn(async move {
            run_jobs(persistence_trigger, cache_dir, resource_dir, job_shutdown).await;
        });
    }

    // RPC server runs only on Shared; CLI clients authenticate against `rpc_key`.
    if instance_mode == InstanceMode::Shared {
        if let Some(rpc_key) = rc.rpc_key.clone() {
            let rpc_tx = transport_tx.clone();
            let rpc_shutdown = shutdown.clone();
            if rc.shared_instance_type == SharedInstanceType::Unix {
                let rpc_socket = shared_unix_rpc_socket_path(&rc.instance_name, &socket_base);
                tokio::spawn(async move {
                    if let Err(e) = crate::rpc_server::run_unix_rpc_server(
                        &rpc_socket,
                        rpc_key,
                        rpc_tx,
                        rpc_shutdown,
                    )
                    .await
                    {
                        tracing::warn!("Unix RPC server error: {}", e);
                    }
                });
            } else {
                let rpc_port = rc.control_port;
                tokio::spawn(async move {
                    if let Err(e) =
                        crate::rpc_server::run_rpc_server(rpc_port, rpc_key, rpc_tx, rpc_shutdown)
                            .await
                    {
                        tracing::warn!("RPC server error: {}", e);
                    }
                });
            }
        }
    }

    if instance_mode != InstanceMode::Client && rc.enable_remote_management {
        // Persist so the destination hash stays stable across restarts.
        let mgmt_path = paths.storage_dir.join("remote_management_identity");
        let mgmt_identity = match rns_identity::identity::Identity::from_file(&mgmt_path) {
            Ok(id) => id,
            Err(_) => {
                let id = rns_identity::identity::Identity::new();
                if let Err(e) = id.to_file(&mgmt_path) {
                    tracing::warn!(path = %mgmt_path.display(), error = %e,
                        "failed to persist remote management identity — destination hash will change on restart");
                }
                id
            }
        };

        // Drop wrong-length entries with a warning so a single typo doesn't disable management.
        let allowed: Vec<[u8; 16]> = rc
            .remote_management_allowed
            .iter()
            .filter_map(|v| <[u8; 16]>::try_from(v.as_slice()).ok())
            .collect();
        if allowed.len() < rc.remote_management_allowed.len() {
            tracing::warn!(
                ignored = rc.remote_management_allowed.len() - allowed.len(),
                "remote_management_allowed: ignored entries with wrong hash length"
            );
        }
        if allowed.is_empty() {
            tracing::warn!(
                "remote management enabled with an empty allow-list; all remote management requests will be denied"
            );
        }

        match crate::remote_management::start_remote_management(
            transport_tx.clone(),
            &mgmt_identity,
            allowed,
        )
        .await
        {
            Ok(dest) => {
                tracing::info!(dest = %hex::encode(dest), "remote management started");
            }
            Err(e) => {
                tracing::warn!("failed to start remote management: {}", e);
            }
        }
    }

    // `respond_to_probes = Yes` registers `rnstransport.probe` (PROVE_ALL).
    if instance_mode != InstanceMode::Client && rc.respond_to_probes {
        let probe_path = paths.storage_dir.join("probe_identity");
        let probe_identity = match rns_identity::identity::Identity::from_file(&probe_path) {
            Ok(id) => id,
            Err(_) => {
                let id = rns_identity::identity::Identity::new();
                if let Err(e) = id.to_file(&probe_path) {
                    tracing::warn!(path = %probe_path.display(), error = %e,
                        "failed to persist probe identity — destination hash will change on restart");
                }
                id
            }
        };
        match crate::probe::spawn_probe_responder(
            transport_tx.clone(),
            probe_identity,
            crate::probe::default_probe_app_name(),
        )
        .await
        {
            Ok(dest) => {
                tracing::info!(dest = %hex::encode(dest), "probe responder started");
            }
            Err(e) => {
                tracing::warn!("failed to start probe responder: {}", e);
            }
        }
    }

    let _ = INSTANCE.set(handle.clone());

    init_shutdown_guard.disarm();
    Ok(handle)
}

async fn run_accepted_child_registration_pump(
    mut handle_rx: mpsc::Receiver<rns_interface::traits::InterfaceHandle>,
    transport_tx: mpsc::Sender<TransportMessage>,
    interface_controls: InterfaceControlMap,
    interface_registry: InterfaceRegistry,
    shutdown: ShutdownSignal,
    forced_shared_bitrate: Option<u64>,
) {
    loop {
        let next = tokio::select! {
            biased;
            _ = shutdown.wait() => {
                handle_rx.close();
                None
            }
            handle = handle_rx.recv() => handle,
        };
        let Some(mut sub_handle) = next else {
            break;
        };
        let (role, ingress_overrides, ifac_key, ifac_size) =
            child_registration_from_parent(&interface_controls, sub_handle.parent_id);
        if role == rns_transport::messages::InterfaceRole::LocalClient {
            apply_forced_shared_instance_bitrate(&mut sub_handle, forced_shared_bitrate);
        }
        // The coordinator retains and joins this pump before waiting producer
        // permits, so accepted children do not need a separate spawn permit.
        if let Err(error) = register_interface_handle_with_role_and_overrides(
            &transport_tx,
            sub_handle,
            role,
            ingress_overrides,
            ifac_key,
            ifac_size,
            &interface_controls,
            &interface_registry,
            InterfaceKind::Standard,
            false,
        )
        .await
        {
            tracing::warn!(error = %error, "failed to register accepted child interface");
            if matches!(
                error,
                InterfaceRegistrationError::TransportClosed { .. }
                    | InterfaceRegistrationError::RuntimeUnavailable { .. }
            ) {
                break;
            }
        }
    }

    // Closing the receiver rejects new children; anything already queued was
    // never published and is reclaimed directly.
    handle_rx.close();
    while let Some(handle) = handle_rx.recv().await {
        handle.online.store(false, Ordering::SeqCst);
        crate::interface_registry::stop_unregistered_task(handle.read_task, None).await;
    }
}

fn child_registration_from_parent(
    interface_controls: &InterfaceControlMap,
    parent_id: Option<u64>,
) -> (
    rns_transport::messages::InterfaceRole,
    rns_transport::ingress::IngressOverrides,
    Option<[u8; 64]>,
    usize,
) {
    let parent_control = parent_id.and_then(|parent_id| {
        interface_controls
            .lock()
            .expect("interface_controls mutex poisoned")
            .get(&parent_id)
            .cloned()
    });
    let role = if parent_control
        .as_ref()
        .is_some_and(|control| control.role == rns_transport::messages::InterfaceRole::SharedServer)
    {
        rns_transport::messages::InterfaceRole::LocalClient
    } else {
        rns_transport::messages::InterfaceRole::Normal
    };
    let (ingress_overrides, ifac_key, ifac_size) = parent_control
        .map(|control| {
            (
                control.ingress_overrides,
                control.ifac_key,
                control.ifac_size,
            )
        })
        .unwrap_or_default();
    (role, ingress_overrides, ifac_key, ifac_size)
}

fn discovered_backbone_client_mode(
    config: &ReticulumConfig,
) -> rns_interface::traits::InterfaceMode {
    if config.enable_transport {
        rns_interface::traits::InterfaceMode::Gateway
    } else {
        rns_interface::traits::InterfaceMode::Full
    }
}

fn next_id(id_gen: &Arc<AtomicU64>) -> u64 {
    id_gen.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
}

fn interface_kind_for_config(config: &interface_factory::InterfaceConfig) -> InterfaceKind {
    match config {
        #[cfg(any(feature = "serial", feature = "rnode-tcp"))]
        interface_factory::InterfaceConfig::RNode(_) => InterfaceKind::RNode,
        #[cfg(feature = "serial")]
        interface_factory::InterfaceConfig::RNodeMulti(_) => InterfaceKind::RNodeMulti,
        #[cfg(feature = "ble")]
        interface_factory::InterfaceConfig::BleRNode(_) => InterfaceKind::BleRNode,
        _ => InterfaceKind::Standard,
    }
}

struct OwnedInterfaceHandle {
    interface: rns_interface::traits::InterfaceHandle,
    driver: Option<rns_interface::rnode::RNodeDriverHandle>,
}

/// Startup-only observation captured before ownership moves into the
/// registration worker. It becomes public only if that exact interface ID is
/// returned by the successful registration transaction.
struct PendingConfiguredRNodeRuntime {
    configured_name: String,
    spawned_interface_id: rns_interface::traits::InterfaceId,
    state: rns_interface::rnode::RNodeDriverSubscription,
}

impl PendingConfiguredRNodeRuntime {
    fn commit(
        self,
        registered_ids: &[rns_interface::traits::InterfaceId],
    ) -> Option<StartupRNodeRuntime> {
        let interface_id = registered_ids
            .iter()
            .copied()
            .find(|registered_id| *registered_id == self.spawned_interface_id)?;
        Some(StartupRNodeRuntime {
            configured_name: self.configured_name,
            interface_id,
            observer: RNodeRuntimeObserver {
                interface_id,
                state: self.state,
            },
        })
    }
}

#[cfg(any(feature = "serial", feature = "rnode-tcp", feature = "ble"))]
fn pending_configured_rnode_runtime(
    config: &interface_factory::InterfaceConfig,
    handles: &[OwnedInterfaceHandle],
) -> Option<PendingConfiguredRNodeRuntime> {
    let configured_name = match config {
        #[cfg(any(feature = "serial", feature = "rnode-tcp"))]
        interface_factory::InterfaceConfig::RNode(config) => config.name.clone(),
        #[cfg(feature = "ble")]
        interface_factory::InterfaceConfig::BleRNode(config) => config.name.clone(),
        _ => return None,
    };

    // Both supported startup variants are single-interface factories. Refuse
    // an unexpected shape rather than accidentally associating one observer
    // with another registration in the same batch.
    let [owned] = handles else {
        return None;
    };
    let driver = owned.driver.as_ref()?;
    Some(PendingConfiguredRNodeRuntime {
        configured_name,
        spawned_interface_id: owned.interface.id,
        state: driver.watch(),
    })
}

#[cfg(not(any(feature = "serial", feature = "rnode-tcp", feature = "ble")))]
fn pending_configured_rnode_runtime(
    _config: &interface_factory::InterfaceConfig,
    _handles: &[OwnedInterfaceHandle],
) -> Option<PendingConfiguredRNodeRuntime> {
    None
}

impl From<rns_interface::traits::InterfaceHandle> for OwnedInterfaceHandle {
    fn from(interface: rns_interface::traits::InterfaceHandle) -> Self {
        Self {
            interface,
            driver: None,
        }
    }
}

impl From<rns_interface::rnode::SpawnedRNodeInterface> for OwnedInterfaceHandle {
    fn from(spawned: rns_interface::rnode::SpawnedRNodeInterface) -> Self {
        Self {
            interface: spawned.interface,
            driver: Some(spawned.driver),
        }
    }
}

fn apply_forced_shared_instance_bitrate(
    handle: &mut rns_interface::traits::InterfaceHandle,
    forced_bitrate: Option<u64>,
) {
    let Some(bitrate) = forced_bitrate.filter(|bitrate| *bitrate > 0) else {
        return;
    };
    handle.bitrate = bitrate;
    handle.mtu =
        rns_interface::traits::optimise_mtu(bitrate).unwrap_or(rns_wire::constants::MTU as u32);
}

/// Register a freshly connected shared-instance client (TCP or local socket)
/// as the SharedInstancePeer and start its reconnect monitor.
async fn adopt_shared_instance_client(
    mut client_handle: rns_interface::traits::InterfaceHandle,
    transport_tx: &mpsc::Sender<TransportMessage>,
    interface_controls: &InterfaceControlMap,
    interface_registry: &InterfaceRegistry,
    shutdown: &ShutdownSignal,
    forced_bitrate: Option<u64>,
    spawn_permit: Option<InterfaceSpawnPermit>,
) -> InstanceMode {
    apply_forced_shared_instance_bitrate(&mut client_handle, forced_bitrate);
    let client_iface_id = client_handle.id;
    let client_online = client_handle.online.clone();
    if let Err(error) = register_interface_handle_with_role_and_spawn_permit(
        transport_tx,
        client_handle,
        rns_transport::messages::InterfaceRole::SharedInstancePeer,
        interface_controls,
        interface_registry,
        spawn_permit,
    )
    .await
    {
        tracing::warn!(error = %error, "failed to register shared-instance client");
        return InstanceMode::Standalone;
    }
    spawn_shared_peer_monitor(
        transport_tx.clone(),
        client_iface_id,
        client_online,
        shutdown.clone(),
    );
    InstanceMode::Client
}

fn spawn_shared_peer_monitor(
    transport_tx: mpsc::Sender<TransportMessage>,
    interface_id: u64,
    online: Arc<AtomicBool>,
    shutdown: ShutdownSignal,
) {
    tokio::spawn(async move {
        let mut was_online = false;
        let mut interval = tokio::time::interval(Duration::from_millis(100));
        loop {
            tokio::select! {
                _ = shutdown.wait() => break,
                _ = interval.tick() => {
                    let is_online = online.load(std::sync::atomic::Ordering::SeqCst);
                    if is_online == was_online {
                        continue;
                    }
                    was_online = is_online;
                    let message = if is_online {
                        TransportMessage::SharedConnectionRestored { interface_id }
                    } else {
                        TransportMessage::SharedConnectionLost
                    };
                    if transport_tx.send(message).await.is_err() {
                        break;
                    }
                }
            }
        }
    });
}

fn ingress_for_role(
    role: rns_transport::messages::InterfaceRole,
    ingress_overrides: &rns_transport::ingress::IngressOverrides,
) -> rns_transport::ingress::IngressController {
    match role {
        rns_transport::messages::InterfaceRole::LocalClient
        | rns_transport::messages::InterfaceRole::SharedInstancePeer => {
            rns_transport::ingress::IngressController::disabled()
        }
        _ if ingress_overrides.is_empty() => rns_transport::ingress::IngressController::new(),
        _ => rns_transport::ingress::IngressController::with_overrides(ingress_overrides),
    }
}

/// Preserve Python Reticulum's interface modes in the transport actor.
/// Full and point-to-point currently share gateway's forwarding policy, but
/// retaining the variants keeps stats/RPC and future policy changes honest.
fn convert_mode(
    mode: rns_interface::traits::InterfaceMode,
) -> rns_transport::constants::InterfaceMode {
    match mode {
        rns_interface::traits::InterfaceMode::AccessPoint => {
            rns_transport::constants::InterfaceMode::AccessPoint
        }
        rns_interface::traits::InterfaceMode::Roaming => {
            rns_transport::constants::InterfaceMode::Roaming
        }
        rns_interface::traits::InterfaceMode::Boundary => {
            rns_transport::constants::InterfaceMode::Boundary
        }
        rns_interface::traits::InterfaceMode::Gateway => {
            rns_transport::constants::InterfaceMode::Gateway
        }
        rns_interface::traits::InterfaceMode::Full => rns_transport::constants::InterfaceMode::Full,
        rns_interface::traits::InterfaceMode::PointToPoint => {
            rns_transport::constants::InterfaceMode::PointToPoint
        }
        rns_interface::traits::InterfaceMode::Internal => {
            rns_transport::constants::InterfaceMode::Internal
        }
    }
}

/// Must use `send().await`, not `try_send`: dropping the registration on a
/// full channel leaves a spawned interface that never receives traffic.
#[cfg(test)]
async fn register_interface_handle(
    transport_tx: &mpsc::Sender<TransportMessage>,
    handle: rns_interface::traits::InterfaceHandle,
    interface_controls: &InterfaceControlMap,
    interface_registry: &InterfaceRegistry,
) -> Result<(), InterfaceRegistrationError> {
    register_owned_interface_handle_with_role_and_overrides(
        transport_tx,
        handle.into(),
        rns_transport::messages::InterfaceRole::Normal,
        rns_transport::ingress::IngressOverrides::default(),
        None,
        0,
        interface_controls,
        interface_registry,
        InterfaceKind::Standard,
        false,
        None,
    )
    .await
}

async fn register_interface_handle_with_spawn_permit(
    transport_tx: &mpsc::Sender<TransportMessage>,
    handle: rns_interface::traits::InterfaceHandle,
    interface_controls: &InterfaceControlMap,
    interface_registry: &InterfaceRegistry,
    spawn_permit: InterfaceSpawnPermit,
) -> Result<(), InterfaceRegistrationError> {
    register_owned_interface_handle_with_role_and_overrides(
        transport_tx,
        handle.into(),
        rns_transport::messages::InterfaceRole::Normal,
        rns_transport::ingress::IngressOverrides::default(),
        None,
        0,
        interface_controls,
        interface_registry,
        InterfaceKind::Standard,
        false,
        Some(spawn_permit),
    )
    .await
}

#[cfg(all(test, feature = "rnode-tcp"))]
async fn register_observed_rnode_handle_with_kind(
    transport_tx: &mpsc::Sender<TransportMessage>,
    spawned: rns_interface::rnode::SpawnedRNodeInterface,
    interface_controls: &InterfaceControlMap,
    interface_registry: &InterfaceRegistry,
    kind: InterfaceKind,
) -> Result<(), InterfaceRegistrationError> {
    register_owned_interface_handle_with_role_and_overrides(
        transport_tx,
        spawned.into(),
        rns_transport::messages::InterfaceRole::Normal,
        rns_transport::ingress::IngressOverrides::default(),
        None,
        0,
        interface_controls,
        interface_registry,
        kind,
        false,
        None,
    )
    .await
}

#[cfg(any(
    feature = "serial",
    feature = "rnode-tcp",
    feature = "ble",
    target_os = "android"
))]
async fn register_observed_rnode_handle_with_kind_and_spawn_permit(
    transport_tx: &mpsc::Sender<TransportMessage>,
    spawned: rns_interface::rnode::SpawnedRNodeInterface,
    interface_controls: &InterfaceControlMap,
    interface_registry: &InterfaceRegistry,
    kind: InterfaceKind,
    spawn_permit: InterfaceSpawnPermit,
) -> Result<(), InterfaceRegistrationError> {
    register_owned_interface_handle_with_role_and_overrides(
        transport_tx,
        spawned.into(),
        rns_transport::messages::InterfaceRole::Normal,
        rns_transport::ingress::IngressOverrides::default(),
        None,
        0,
        interface_controls,
        interface_registry,
        kind,
        false,
        Some(spawn_permit),
    )
    .await
}

async fn register_interface_handle_with_role_and_spawn_permit(
    transport_tx: &mpsc::Sender<TransportMessage>,
    handle: rns_interface::traits::InterfaceHandle,
    role: rns_transport::messages::InterfaceRole,
    interface_controls: &InterfaceControlMap,
    interface_registry: &InterfaceRegistry,
    spawn_permit: Option<InterfaceSpawnPermit>,
) -> Result<(), InterfaceRegistrationError> {
    register_owned_interface_handle_with_role_and_overrides(
        transport_tx,
        handle.into(),
        role,
        rns_transport::ingress::IngressOverrides::default(),
        None,
        0,
        interface_controls,
        interface_registry,
        InterfaceKind::Standard,
        false,
        spawn_permit,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn register_interface_handle_with_role_and_overrides(
    transport_tx: &mpsc::Sender<TransportMessage>,
    handle: rns_interface::traits::InterfaceHandle,
    role: rns_transport::messages::InterfaceRole,
    ingress_overrides: rns_transport::ingress::IngressOverrides,
    ifac_key: Option<[u8; 64]>,
    ifac_size: usize,
    interface_controls: &InterfaceControlMap,
    interface_registry: &InterfaceRegistry,
    kind: InterfaceKind,
    multipoint: bool,
) -> Result<(), InterfaceRegistrationError> {
    register_owned_interface_handle_with_role_and_overrides(
        transport_tx,
        handle.into(),
        role,
        ingress_overrides,
        ifac_key,
        ifac_size,
        interface_controls,
        interface_registry,
        kind,
        multipoint,
        None,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
#[cfg(feature = "ble")]
async fn register_interface_handle_with_role_and_overrides_and_spawn_permit(
    transport_tx: &mpsc::Sender<TransportMessage>,
    handle: rns_interface::traits::InterfaceHandle,
    role: rns_transport::messages::InterfaceRole,
    ingress_overrides: rns_transport::ingress::IngressOverrides,
    ifac_key: Option<[u8; 64]>,
    ifac_size: usize,
    interface_controls: &InterfaceControlMap,
    interface_registry: &InterfaceRegistry,
    kind: InterfaceKind,
    multipoint: bool,
    spawn_permit: InterfaceSpawnPermit,
) -> Result<(), InterfaceRegistrationError> {
    register_owned_interface_handle_with_role_and_overrides(
        transport_tx,
        handle.into(),
        role,
        ingress_overrides,
        ifac_key,
        ifac_size,
        interface_controls,
        interface_registry,
        kind,
        multipoint,
        Some(spawn_permit),
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn register_owned_interface_handle_with_role_and_overrides(
    transport_tx: &mpsc::Sender<TransportMessage>,
    owned: OwnedInterfaceHandle,
    role: rns_transport::messages::InterfaceRole,
    ingress_overrides: rns_transport::ingress::IngressOverrides,
    ifac_key: Option<[u8; 64]>,
    ifac_size: usize,
    interface_controls: &InterfaceControlMap,
    interface_registry: &InterfaceRegistry,
    kind: InterfaceKind,
    multipoint: bool,
    spawn_permit: Option<InterfaceSpawnPermit>,
) -> Result<(), InterfaceRegistrationError> {
    run_single_registration_worker(
        transport_tx.clone(),
        interface_controls.clone(),
        interface_registry.clone(),
        SingleRegistrationSpec::Direct {
            owned,
            role,
            ingress_overrides,
            ifac_key,
            ifac_size,
            kind,
            multipoint,
        },
        spawn_permit,
    )
    .await
    .map(|_| ())
}

#[allow(clippy::too_many_arguments)]
async fn prepare_interface_with_role_and_overrides(
    owned: OwnedInterfaceHandle,
    role: rns_transport::messages::InterfaceRole,
    ingress_overrides: rns_transport::ingress::IngressOverrides,
    ifac_key: Option<[u8; 64]>,
    ifac_size: usize,
    interface_controls: &InterfaceControlMap,
    interface_registry: &InterfaceRegistry,
    kind: InterfaceKind,
    multipoint: bool,
) -> Result<PreparedInterfaceRegistration, InterfaceRegistrationError> {
    let OwnedInterfaceHandle { interface, driver } = owned;
    let handle = interface;
    let name = handle.name.clone();
    let id = handle.id;
    let ingress = ingress_for_role(role, &ingress_overrides);
    let online = handle.online.clone();
    let registration = match interface_registry.reserve_with_online(
        id,
        kind,
        handle.read_task,
        driver,
        Some(online.clone()),
    ) {
        Ok(registration) => registration,
        Err(rejected) => {
            let rejection = rejected.reason();
            online.store(false, Ordering::SeqCst);
            if matches!(
                rejection,
                InterfaceRegistrationRejection::Duplicate
                    | InterfaceRegistrationRejection::Draining
                    | InterfaceRegistrationRejection::Closed
            ) {
                stop_special_interface_before_abort(kind).await;
            }
            rejected.stop_and_wait().await;
            return Err(match rejection {
                InterfaceRegistrationRejection::Duplicate => {
                    InterfaceRegistrationError::Duplicate { id }
                }
                InterfaceRegistrationRejection::InvalidDriverOwnership => {
                    InterfaceRegistrationError::InvalidDriverOwnership { id }
                }
                InterfaceRegistrationRejection::Draining
                | InterfaceRegistrationRejection::Closed => {
                    InterfaceRegistrationError::RuntimeUnavailable { id }
                }
            });
        }
    };
    let registry_owner = registration.owner();
    interface_controls
        .lock()
        .expect("interface_controls mutex poisoned")
        .insert(
            id,
            InterfaceControlMetadata {
                registry_owner,
                role,
                ingress_overrides: ingress_overrides.clone(),
                ifac_key,
                ifac_size,
            },
        );
    let entry = rns_transport::messages::InterfaceEntry {
        name: handle.name.clone(),
        mode: convert_mode(handle.mode),
        role,
        direction: rns_transport::constants::InterfaceDirection {
            inbound: handle.direction.inbound,
            outbound: handle.direction.outbound,
        },
        bitrate: handle.bitrate,
        mtu: handle.mtu,
        tx: handle.tx,
        ifac_key,
        ifac_size,
        announce_cap: ANNOUNCE_CAP,
        announce_allowed_at: 0.0,
        announce_rate_target: None,
        announce_rate_grace: None,
        announce_rate_penalty: None,
        online: Some(online.clone()),
        rxb: handle.rxb,
        txb: handle.txb,
        inspection: handle.inspection,
        tx_drops: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
        ingress,
        announce_queue: Vec::new(),
        multipoint,
        // Interface.py class defaults; Python spawned sub-interfaces do not
        // inherit recursive_prs/announces_from_internal (TCPInterface.py:579+).
        recursive_prs: false,
        announces_from_internal: true,
    };
    Ok(PreparedInterfaceRegistration {
        id,
        name,
        kind,
        online,
        registry_owner,
        registration: Some(registration),
        entry: Some(entry),
    })
}

/// See [`register_interface_handle`] for `send().await` rationale.
#[cfg(test)]
async fn register_interface_with_post_init(
    transport_tx: &mpsc::Sender<TransportMessage>,
    handle: rns_interface::traits::InterfaceHandle,
    post_init: &interface_factory::InterfacePostInit,
    ifac_key: Option<[u8; 64]>,
    interface_controls: &InterfaceControlMap,
    interface_registry: &InterfaceRegistry,
    kind: InterfaceKind,
) -> Result<(), InterfaceRegistrationError> {
    register_owned_interface_with_post_init(
        transport_tx,
        handle.into(),
        post_init,
        ifac_key,
        interface_controls,
        interface_registry,
        kind,
        None,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn register_interface_with_post_init_and_spawn_permit(
    transport_tx: &mpsc::Sender<TransportMessage>,
    handle: rns_interface::traits::InterfaceHandle,
    post_init: &interface_factory::InterfacePostInit,
    ifac_key: Option<[u8; 64]>,
    interface_controls: &InterfaceControlMap,
    interface_registry: &InterfaceRegistry,
    kind: InterfaceKind,
    spawn_permit: InterfaceSpawnPermit,
) -> Result<(), InterfaceRegistrationError> {
    register_owned_interface_with_post_init(
        transport_tx,
        handle.into(),
        post_init,
        ifac_key,
        interface_controls,
        interface_registry,
        kind,
        Some(spawn_permit),
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn register_owned_interface_with_post_init(
    transport_tx: &mpsc::Sender<TransportMessage>,
    owned: OwnedInterfaceHandle,
    post_init: &interface_factory::InterfacePostInit,
    ifac_key: Option<[u8; 64]>,
    interface_controls: &InterfaceControlMap,
    interface_registry: &InterfaceRegistry,
    kind: InterfaceKind,
    spawn_permit: Option<InterfaceSpawnPermit>,
) -> Result<(), InterfaceRegistrationError> {
    run_single_registration_worker(
        transport_tx.clone(),
        interface_controls.clone(),
        interface_registry.clone(),
        SingleRegistrationSpec::PostInit {
            owned,
            post_init: clone_interface_post_init(post_init),
            ifac_key,
            kind,
        },
        spawn_permit,
    )
    .await
    .map(|_| ())
}

fn clone_interface_post_init(
    post_init: &interface_factory::InterfacePostInit,
) -> interface_factory::InterfacePostInit {
    interface_factory::InterfacePostInit {
        outgoing: post_init.outgoing,
        bitrate: post_init.bitrate,
        announce_cap: post_init.announce_cap,
        announce_rate_target: post_init.announce_rate_target,
        announce_rate_grace: post_init.announce_rate_grace,
        announce_rate_penalty: post_init.announce_rate_penalty,
        ifac_network_name: post_init.ifac_network_name.clone(),
        ifac_passphrase: post_init.ifac_passphrase.clone(),
        ifac_size: post_init.ifac_size,
        default_ifac_size: post_init.default_ifac_size,
        ingress_control: post_init.ingress_control,
        ingress_overrides: post_init.ingress_overrides.clone(),
        recursive_prs: post_init.recursive_prs,
        announces_from_internal: post_init.announces_from_internal,
    }
}

async fn prepare_interface_with_post_init(
    owned: OwnedInterfaceHandle,
    post_init: &interface_factory::InterfacePostInit,
    ifac_key: Option<[u8; 64]>,
    interface_controls: &InterfaceControlMap,
    interface_registry: &InterfaceRegistry,
    kind: InterfaceKind,
) -> Result<PreparedInterfaceRegistration, InterfaceRegistrationError> {
    let OwnedInterfaceHandle { interface, driver } = owned;
    let handle = interface;
    // Outbound = physical capability AND `outgoing` config flag.
    let direction = rns_transport::constants::InterfaceDirection {
        inbound: handle.direction.inbound,
        outbound: handle.direction.outbound && post_init.outgoing,
    };
    let ingress = if post_init.ingress_overrides.is_empty() {
        rns_transport::ingress::IngressController::new()
    } else {
        rns_transport::ingress::IngressController::with_overrides(&post_init.ingress_overrides)
    };
    let name = handle.name.clone();
    let id = handle.id;
    let online = handle.online.clone();
    let registration = match interface_registry.reserve_with_online(
        id,
        kind,
        handle.read_task,
        driver,
        Some(online.clone()),
    ) {
        Ok(registration) => registration,
        Err(rejected) => {
            let rejection = rejected.reason();
            online.store(false, Ordering::SeqCst);
            if matches!(
                rejection,
                InterfaceRegistrationRejection::Duplicate
                    | InterfaceRegistrationRejection::Draining
                    | InterfaceRegistrationRejection::Closed
            ) {
                stop_special_interface_before_abort(kind).await;
            }
            rejected.stop_and_wait().await;
            return Err(match rejection {
                InterfaceRegistrationRejection::Duplicate => {
                    InterfaceRegistrationError::Duplicate { id }
                }
                InterfaceRegistrationRejection::InvalidDriverOwnership => {
                    InterfaceRegistrationError::InvalidDriverOwnership { id }
                }
                InterfaceRegistrationRejection::Draining
                | InterfaceRegistrationRejection::Closed => {
                    InterfaceRegistrationError::RuntimeUnavailable { id }
                }
            });
        }
    };
    let registry_owner = registration.owner();
    interface_controls
        .lock()
        .expect("interface_controls mutex poisoned")
        .insert(
            id,
            InterfaceControlMetadata {
                registry_owner,
                role: rns_transport::messages::InterfaceRole::Normal,
                ingress_overrides: post_init.ingress_overrides.clone(),
                ifac_key,
                ifac_size: post_init.ifac_size.unwrap_or(post_init.default_ifac_size),
            },
        );
    let entry = rns_transport::messages::InterfaceEntry {
        name: handle.name.clone(),
        mode: convert_mode(handle.mode),
        role: rns_transport::messages::InterfaceRole::Normal,
        direction,
        bitrate: post_init.bitrate.unwrap_or(handle.bitrate),
        mtu: handle.mtu,
        tx: handle.tx,
        ifac_key,
        ifac_size: post_init.ifac_size.unwrap_or(post_init.default_ifac_size),
        announce_cap: post_init.announce_cap.unwrap_or(ANNOUNCE_CAP),
        announce_allowed_at: 0.0,
        announce_rate_target: post_init.announce_rate_target.map(|v| v as f64),
        announce_rate_grace: post_init.announce_rate_grace,
        announce_rate_penalty: post_init.announce_rate_penalty.map(|v| v as f64),
        online: Some(online.clone()),
        rxb: handle.rxb,
        txb: handle.txb,
        inspection: handle.inspection,
        tx_drops: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
        ingress,
        announce_queue: Vec::new(),
        multipoint: false,
        recursive_prs: post_init.recursive_prs,
        announces_from_internal: post_init.announces_from_internal,
    };
    Ok(PreparedInterfaceRegistration {
        id,
        name,
        kind,
        online,
        registry_owner,
        registration: Some(registration),
        entry: Some(entry),
    })
}

#[derive(Debug)]
enum InterfaceRegistrationError {
    Duplicate { id: u64 },
    InvalidDriverOwnership { id: u64 },
    RuntimeUnavailable { id: u64 },
    TransportClosed { id: u64 },
    ReservationLost { id: u64 },
    WorkerStopped { id: u64 },
}

impl std::fmt::Display for InterfaceRegistrationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Duplicate { id } => write!(formatter, "duplicate interface ID {id}"),
            Self::InvalidDriverOwnership { id } => {
                write!(
                    formatter,
                    "interface {id} has inconsistent exact-driver ownership"
                )
            }
            Self::RuntimeUnavailable { id } => {
                write!(
                    formatter,
                    "runtime is draining; interface {id} was not admitted"
                )
            }
            Self::TransportClosed { id } => {
                write!(
                    formatter,
                    "transport closed while registering interface {id}"
                )
            }
            Self::ReservationLost { id } => {
                write!(formatter, "interface {id} lost its runtime reservation")
            }
            Self::WorkerStopped { id } => {
                write!(formatter, "interface {id} registration worker stopped")
            }
        }
    }
}

enum SingleRegistrationSpec {
    Direct {
        owned: OwnedInterfaceHandle,
        role: rns_transport::messages::InterfaceRole,
        ingress_overrides: rns_transport::ingress::IngressOverrides,
        ifac_key: Option<[u8; 64]>,
        ifac_size: usize,
        kind: InterfaceKind,
        multipoint: bool,
    },
    PostInit {
        owned: OwnedInterfaceHandle,
        post_init: interface_factory::InterfacePostInit,
        ifac_key: Option<[u8; 64]>,
        kind: InterfaceKind,
    },
}

impl SingleRegistrationSpec {
    fn id(&self) -> u64 {
        match self {
            Self::Direct { owned, .. } | Self::PostInit { owned, .. } => owned.interface.id,
        }
    }
}

struct RegistrationCancelGuard {
    sender: Option<oneshot::Sender<()>>,
}

impl RegistrationCancelGuard {
    fn disarm(mut self) {
        self.sender.take();
    }
}

impl Drop for RegistrationCancelGuard {
    fn drop(&mut self) {
        if let Some(sender) = self.sender.take() {
            let _ = sender.send(());
        }
    }
}

struct RegistrationCancellation {
    receiver: oneshot::Receiver<()>,
}

impl RegistrationCancellation {
    async fn send_register(
        &mut self,
        transport_tx: &mpsc::Sender<TransportMessage>,
        message: TransportMessage,
        interface_registry: &InterfaceRegistry,
        reservation_tokens: &[(u64, u64)],
    ) -> Result<(), RegistrationSendError> {
        tokio::select! {
            biased;
            _ = &mut self.receiver => Err(RegistrationSendError::Cancelled),
            _ = interface_registry.wait_for_any_cancel_requested(reservation_tokens) => {
                Err(RegistrationSendError::Cancelled)
            }
            result = transport_tx.send(message) => {
                result.map_err(|_| RegistrationSendError::TransportClosed)
            }
        }
    }

    fn is_cancelled(&mut self) -> bool {
        match self.receiver.try_recv() {
            Ok(()) | Err(oneshot::error::TryRecvError::Closed) => true,
            Err(oneshot::error::TryRecvError::Empty) => false,
        }
    }
}

enum RegistrationSendError {
    Cancelled,
    TransportClosed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CommittedInterfaceToken {
    id: u64,
    registry_owner: u64,
}

struct RegistrationWorkerReply {
    result: Result<Vec<CommittedInterfaceToken>, InterfaceRegistrationError>,
    acknowledgement: Option<oneshot::Sender<()>>,
}

struct PreparedInterfaceRegistration {
    id: u64,
    name: String,
    kind: InterfaceKind,
    online: Arc<AtomicBool>,
    registry_owner: u64,
    registration: Option<InterfaceRegistration>,
    entry: Option<rns_transport::messages::InterfaceEntry>,
}

async fn run_single_registration_worker(
    transport_tx: mpsc::Sender<TransportMessage>,
    interface_controls: InterfaceControlMap,
    interface_registry: InterfaceRegistry,
    spec: SingleRegistrationSpec,
    spawn_permit: Option<InterfaceSpawnPermit>,
) -> Result<Vec<u64>, InterfaceRegistrationError> {
    let id = spec.id();
    let (cancel_tx, cancel_rx) = oneshot::channel();
    let cancel_guard = RegistrationCancelGuard {
        sender: Some(cancel_tx),
    };
    let (reply_tx, reply_rx) = oneshot::channel();
    tokio::spawn(single_registration_worker(
        transport_tx,
        interface_controls,
        interface_registry,
        spec,
        RegistrationCancellation {
            receiver: cancel_rx,
        },
        reply_tx,
        spawn_permit,
    ));

    let mut reply = match reply_rx.await {
        Ok(reply) => reply,
        Err(_) => return Err(InterfaceRegistrationError::WorkerStopped { id }),
    };
    let result = reply.result;
    if let Some(acknowledgement) = reply.acknowledgement.take() {
        let _ = acknowledgement.send(());
    }
    cancel_guard.disarm();
    result.map(|tokens| tokens.into_iter().map(|token| token.id).collect())
}

async fn single_registration_worker(
    transport_tx: mpsc::Sender<TransportMessage>,
    interface_controls: InterfaceControlMap,
    interface_registry: InterfaceRegistry,
    spec: SingleRegistrationSpec,
    mut cancellation: RegistrationCancellation,
    reply_tx: oneshot::Sender<RegistrationWorkerReply>,
    spawn_permit: Option<InterfaceSpawnPermit>,
) {
    let result = match spec {
        SingleRegistrationSpec::Direct {
            owned,
            role,
            ingress_overrides,
            ifac_key,
            ifac_size,
            kind,
            multipoint,
        } => {
            match prepare_interface_with_role_and_overrides(
                owned,
                role,
                ingress_overrides,
                ifac_key,
                ifac_size,
                &interface_controls,
                &interface_registry,
                kind,
                multipoint,
            )
            .await
            {
                Ok(prepared) => publish_prepared_interface(
                    &transport_tx,
                    &interface_controls,
                    &interface_registry,
                    prepared,
                    &mut cancellation,
                )
                .await
                .map(|token| vec![token]),
                Err(error) => Err(error),
            }
        }
        SingleRegistrationSpec::PostInit {
            owned,
            post_init,
            ifac_key,
            kind,
        } => {
            match prepare_interface_with_post_init(
                owned,
                &post_init,
                ifac_key,
                &interface_controls,
                &interface_registry,
                kind,
            )
            .await
            {
                Ok(prepared) => publish_prepared_interface(
                    &transport_tx,
                    &interface_controls,
                    &interface_registry,
                    prepared,
                    &mut cancellation,
                )
                .await
                .map(|token| vec![token]),
                Err(error) => Err(error),
            }
        }
    };
    // The registration transaction does not resolve until either the task is
    // Active under registry ownership or rejection/rollback has joined it.
    // Release the producer permit at that ownership boundary. Holding it
    // while waiting for the caller acknowledgement would deadlock a drain
    // that has already leased the Active record and is waiting on permits.
    drop(spawn_permit);
    finish_registration_worker(
        result,
        transport_tx,
        interface_controls,
        interface_registry,
        cancellation,
        reply_tx,
    )
    .await;
}

async fn finish_registration_worker(
    result: Result<Vec<CommittedInterfaceToken>, InterfaceRegistrationError>,
    transport_tx: mpsc::Sender<TransportMessage>,
    interface_controls: InterfaceControlMap,
    interface_registry: InterfaceRegistry,
    mut cancellation: RegistrationCancellation,
    reply_tx: oneshot::Sender<RegistrationWorkerReply>,
) {
    let Ok(ids) = result else {
        let _ = reply_tx.send(RegistrationWorkerReply {
            result,
            acknowledgement: None,
        });
        return;
    };

    let cleanup_ids = ids.clone();
    let (ack_tx, mut ack_rx) = oneshot::channel();
    if reply_tx
        .send(RegistrationWorkerReply {
            result: Ok(ids),
            acknowledgement: Some(ack_tx),
        })
        .is_err()
    {
        cleanup_committed_interfaces(
            &transport_tx,
            &interface_controls,
            &interface_registry,
            cleanup_ids,
        )
        .await;
        return;
    }

    let acknowledged = tokio::select! {
        biased;
        result = &mut ack_rx => result.is_ok(),
        _ = &mut cancellation.receiver => false,
    };
    if !acknowledged {
        cleanup_committed_interfaces(
            &transport_tx,
            &interface_controls,
            &interface_registry,
            cleanup_ids,
        )
        .await;
    }
}

async fn publish_prepared_interface(
    transport_tx: &mpsc::Sender<TransportMessage>,
    interface_controls: &InterfaceControlMap,
    interface_registry: &InterfaceRegistry,
    mut prepared: PreparedInterfaceRegistration,
    cancellation: &mut RegistrationCancellation,
) -> Result<CommittedInterfaceToken, InterfaceRegistrationError> {
    let id = prepared.id;
    let reservation_token = [(prepared.id, prepared.registry_owner)];
    let entry = prepared
        .entry
        .take()
        .expect("prepared interface owns an entry");
    match cancellation
        .send_register(
            transport_tx,
            TransportMessage::RegisterInterface { id, entry },
            interface_registry,
            &reservation_token,
        )
        .await
    {
        Ok(()) => {}
        Err(RegistrationSendError::Cancelled) => {
            rollback_prepared_interface(interface_controls, prepared).await;
            return Err(InterfaceRegistrationError::ReservationLost { id });
        }
        Err(RegistrationSendError::TransportClosed) => {
            tracing::error!(
                name = %prepared.name,
                id,
                "RegisterInterface failed — transport actor gone"
            );
            rollback_prepared_interface(interface_controls, prepared).await;
            return Err(InterfaceRegistrationError::TransportClosed { id });
        }
    }

    let registration = prepared
        .registration
        .take()
        .expect("prepared interface owns a reservation");
    if cancellation.is_cancelled() {
        prepared.registration = Some(registration);
        rollback_published_interfaces(transport_tx, interface_controls, vec![prepared]).await;
        return Err(InterfaceRegistrationError::ReservationLost { id });
    }
    if let Err(registration) = registration.commit() {
        prepared.registration = Some(registration);
        rollback_published_interfaces(transport_tx, interface_controls, vec![prepared]).await;
        return Err(InterfaceRegistrationError::ReservationLost { id });
    }
    Ok(CommittedInterfaceToken {
        id,
        registry_owner: prepared.registry_owner,
    })
}

async fn rollback_prepared_interface(
    interface_controls: &InterfaceControlMap,
    mut prepared: PreparedInterfaceRegistration,
) {
    prepared.online.store(false, Ordering::SeqCst);
    remove_interface_control_if_owner(interface_controls, prepared.id, prepared.registry_owner);
    stop_special_interface_before_abort(prepared.kind).await;
    if let Some(registration) = prepared.registration.take() {
        registration.rollback().await;
    }
}

async fn rollback_published_interfaces(
    transport_tx: &mpsc::Sender<TransportMessage>,
    interface_controls: &InterfaceControlMap,
    mut prepared: Vec<PreparedInterfaceRegistration>,
) {
    // Stop and join every exact task before the actor can observe a
    // deregistration for a potentially reusable ID.
    for interface in &mut prepared {
        interface.online.store(false, Ordering::SeqCst);
        remove_interface_control_if_owner(
            interface_controls,
            interface.id,
            interface.registry_owner,
        );
        stop_special_interface_before_abort(interface.kind).await;
        if let Some(registration) = interface.registration.as_mut() {
            registration.stop_task_and_wait().await;
        }
    }

    for mut interface in prepared {
        let deregistered = transport_tx
            .send(TransportMessage::DeregisterInterface { id: interface.id })
            .await
            .is_ok();
        if deregistered {
            if let Some(registration) = interface.registration.take() {
                registration.release();
            }
        }
        // A closed actor leaves the Pending cancellation tombstone in place;
        // same-ID reuse is unsafe because the stale registration cannot be
        // ordered before a replacement.
    }
}

#[allow(clippy::too_many_arguments)]
async fn register_interfaces_with_post_init_batch(
    transport_tx: &mpsc::Sender<TransportMessage>,
    handles: Vec<OwnedInterfaceHandle>,
    post_init: &interface_factory::InterfacePostInit,
    ifac_key: Option<[u8; 64]>,
    interface_controls: &InterfaceControlMap,
    interface_registry: &InterfaceRegistry,
    kind: InterfaceKind,
    spawn_permit: Option<InterfaceSpawnPermit>,
) -> Result<Vec<u64>, InterfaceRegistrationError> {
    let fallback_id = handles.first().map_or(0, |owned| owned.interface.id);
    let (cancel_tx, cancel_rx) = oneshot::channel();
    let cancel_guard = RegistrationCancelGuard {
        sender: Some(cancel_tx),
    };
    let (reply_tx, reply_rx) = oneshot::channel();
    tokio::spawn(batch_registration_worker(
        transport_tx.clone(),
        handles,
        clone_interface_post_init(post_init),
        ifac_key,
        interface_controls.clone(),
        interface_registry.clone(),
        kind,
        RegistrationCancellation {
            receiver: cancel_rx,
        },
        reply_tx,
        spawn_permit,
    ));

    let mut reply = match reply_rx.await {
        Ok(reply) => reply,
        Err(_) => {
            return Err(InterfaceRegistrationError::WorkerStopped { id: fallback_id });
        }
    };
    let result = reply.result;
    if let Some(acknowledgement) = reply.acknowledgement.take() {
        let _ = acknowledgement.send(());
    }
    cancel_guard.disarm();
    result.map(|tokens| tokens.into_iter().map(|token| token.id).collect())
}

#[allow(clippy::too_many_arguments)]
async fn batch_registration_worker(
    transport_tx: mpsc::Sender<TransportMessage>,
    handles: Vec<OwnedInterfaceHandle>,
    post_init: interface_factory::InterfacePostInit,
    ifac_key: Option<[u8; 64]>,
    interface_controls: InterfaceControlMap,
    interface_registry: InterfaceRegistry,
    kind: InterfaceKind,
    mut cancellation: RegistrationCancellation,
    reply_tx: oneshot::Sender<RegistrationWorkerReply>,
    spawn_permit: Option<InterfaceSpawnPermit>,
) {
    let result = register_interfaces_with_post_init_batch_transaction(
        &transport_tx,
        handles,
        &post_init,
        ifac_key,
        &interface_controls,
        &interface_registry,
        kind,
        &mut cancellation,
    )
    .await;
    // As above, batch commit transfers every task to registry ownership;
    // every error path has already completed exact rollback before returning.
    drop(spawn_permit);
    finish_registration_worker(
        result,
        transport_tx,
        interface_controls,
        interface_registry,
        cancellation,
        reply_tx,
    )
    .await;
}

#[allow(clippy::too_many_arguments)]
async fn register_interfaces_with_post_init_batch_transaction(
    transport_tx: &mpsc::Sender<TransportMessage>,
    handles: Vec<OwnedInterfaceHandle>,
    post_init: &interface_factory::InterfacePostInit,
    ifac_key: Option<[u8; 64]>,
    interface_controls: &InterfaceControlMap,
    interface_registry: &InterfaceRegistry,
    kind: InterfaceKind,
    cancellation: &mut RegistrationCancellation,
) -> Result<Vec<CommittedInterfaceToken>, InterfaceRegistrationError> {
    let mut prepared = Vec::with_capacity(handles.len());
    let mut handles = handles.into_iter();
    while let Some(owned) = handles.next() {
        match prepare_interface_with_post_init(
            owned,
            post_init,
            ifac_key,
            interface_controls,
            interface_registry,
            kind,
        )
        .await
        {
            Ok(registration) => prepared.push(registration),
            Err(error) => {
                for registration in prepared {
                    rollback_prepared_interface(interface_controls, registration).await;
                }
                for owned in handles {
                    rollback_unreserved_interface(owned, kind).await;
                }
                return Err(error);
            }
        }
    }

    if cancellation.is_cancelled() {
        for registration in prepared {
            rollback_prepared_interface(interface_controls, registration).await;
        }
        return Err(InterfaceRegistrationError::ReservationLost { id: 0 });
    }

    let reservation_tokens: Vec<(u64, u64)> = prepared
        .iter()
        .map(|interface| (interface.id, interface.registry_owner))
        .collect();
    let mut sent_ids = Vec::with_capacity(prepared.len());
    for registration in &mut prepared {
        let entry = registration
            .entry
            .take()
            .expect("prepared interface owns an entry");
        let send_result = cancellation
            .send_register(
                transport_tx,
                TransportMessage::RegisterInterface {
                    id: registration.id,
                    entry,
                },
                interface_registry,
                &reservation_tokens,
            )
            .await;
        if let Err(send_error) = send_result {
            let failed_id = registration.id;
            rollback_batch_interfaces(transport_tx, interface_controls, prepared, &sent_ids).await;
            return Err(match send_error {
                RegistrationSendError::Cancelled => {
                    InterfaceRegistrationError::ReservationLost { id: failed_id }
                }
                RegistrationSendError::TransportClosed => {
                    InterfaceRegistrationError::TransportClosed { id: failed_id }
                }
            });
        }
        sent_ids.push(registration.id);
    }

    if cancellation.is_cancelled() {
        let failed_id = sent_ids.first().copied().unwrap_or(0);
        rollback_batch_interfaces(transport_tx, interface_controls, prepared, &sent_ids).await;
        return Err(InterfaceRegistrationError::ReservationLost { id: failed_id });
    }

    let committed_tokens: Vec<CommittedInterfaceToken> = prepared
        .iter()
        .map(|interface| CommittedInterfaceToken {
            id: interface.id,
            registry_owner: interface.registry_owner,
        })
        .collect();
    let reservations = prepared
        .iter_mut()
        .map(|registration| {
            registration
                .registration
                .take()
                .expect("prepared interface owns a reservation")
        })
        .collect();
    if let Err(reservations) = interface_registry.commit_batch(reservations) {
        for (prepared, reservation) in prepared.iter_mut().zip(reservations) {
            prepared.registration = Some(reservation);
        }
        let failed_id = prepared.first().map_or(0, |registration| registration.id);
        rollback_batch_interfaces(transport_tx, interface_controls, prepared, &sent_ids).await;
        return Err(InterfaceRegistrationError::ReservationLost { id: failed_id });
    }

    Ok(committed_tokens)
}

async fn rollback_batch_interfaces(
    transport_tx: &mpsc::Sender<TransportMessage>,
    interface_controls: &InterfaceControlMap,
    mut prepared: Vec<PreparedInterfaceRegistration>,
    published_ids: &[u64],
) {
    for interface in &mut prepared {
        interface.online.store(false, Ordering::SeqCst);
        remove_interface_control_if_owner(
            interface_controls,
            interface.id,
            interface.registry_owner,
        );
        stop_special_interface_before_abort(interface.kind).await;
        if let Some(registration) = interface.registration.as_mut() {
            registration.stop_task_and_wait().await;
        }
    }

    for mut interface in prepared {
        let published = published_ids.contains(&interface.id);
        let safe_to_release = !published
            || transport_tx
                .send(TransportMessage::DeregisterInterface { id: interface.id })
                .await
                .is_ok();
        if safe_to_release {
            if let Some(registration) = interface.registration.take() {
                registration.release();
            }
        }
    }
}

async fn rollback_unreserved_interface(owned: OwnedInterfaceHandle, kind: InterfaceKind) {
    let OwnedInterfaceHandle {
        interface: handle,
        driver,
    } = owned;
    handle.online.store(false, Ordering::SeqCst);
    stop_special_interface_before_abort(kind).await;
    crate::interface_registry::stop_unregistered_task(handle.read_task, driver).await;
}

async fn stop_special_interface_before_abort(kind: InterfaceKind) {
    match kind.shutdown_strategy() {
        InterfaceShutdownStrategy::Abort => {}
        #[cfg(any(
            feature = "serial",
            feature = "rnode-tcp",
            feature = "ble",
            target_os = "android"
        ))]
        InterfaceShutdownStrategy::ExactRNodeDriver => {}
        #[cfg(feature = "ble")]
        InterfaceShutdownStrategy::StopBlePeer => {
            rns_interface::ble_peer::stop_ble_peer_interface().await;
        }
    }
}

fn remove_interface_control_if_owner(
    interface_controls: &InterfaceControlMap,
    id: u64,
    registry_owner: u64,
) {
    let mut controls = interface_controls
        .lock()
        .expect("interface_controls mutex poisoned");
    if controls
        .get(&id)
        .is_some_and(|control| control.registry_owner == registry_owner)
    {
        controls.remove(&id);
    }
}

fn derive_ifac_key_from_post_init(
    post_init: &interface_factory::InterfacePostInit,
) -> Option<[u8; 64]> {
    if post_init.ifac_network_name.is_some() || post_init.ifac_passphrase.is_some() {
        rns_identity::ifac::derive_ifac_key(
            post_init.ifac_network_name.as_deref(),
            post_init.ifac_passphrase.as_deref(),
        )
        .ok()
    } else {
        None
    }
}

#[derive(Clone, Debug, Default)]
pub struct RuntimeInterfaceIfacConfig {
    pub network_name: Option<String>,
    pub passphrase: Option<String>,
    pub ifac_size: Option<usize>,
}

#[derive(Clone, Debug)]
pub struct RuntimeBackboneClientConfig<'a> {
    pub name: &'a str,
    pub host: &'a str,
    pub port: u16,
    pub prefer_ipv6: bool,
    pub connect_timeout: Option<u64>,
    pub max_reconnect_tries: Option<usize>,
    pub ifac: Option<RuntimeInterfaceIfacConfig>,
}

fn runtime_ifac_post_init(
    ifac: Option<RuntimeInterfaceIfacConfig>,
    default_ifac_size: usize,
) -> Result<Option<interface_factory::InterfacePostInit>, String> {
    let Some(ifac) = ifac else {
        return Ok(None);
    };

    if let Some(size) = ifac.ifac_size {
        if !(1..=64).contains(&size) {
            return Err(format!("Invalid IFAC size {size}; expected 1..=64 bytes"));
        }
    }

    let network_name = ifac.network_name.filter(|s| !s.is_empty());
    let passphrase = ifac.passphrase.filter(|s| !s.is_empty());
    if network_name.is_none() && passphrase.is_none() {
        return Ok(None);
    }

    let mut post_init = interface_factory::InterfacePostInit::from_section(&ConfigSection::new())
        .with_default_ifac_size(default_ifac_size);
    post_init.ifac_network_name = network_name;
    post_init.ifac_passphrase = passphrase;
    post_init.ifac_size = ifac.ifac_size;
    Ok(Some(post_init))
}

fn get_post_init_for_config(
    config: &Config,
    iface_config: &interface_factory::InterfaceConfig,
) -> interface_factory::InterfacePostInit {
    let name = interface_config_name(iface_config);
    let default_ifac_size = interface_factory::default_ifac_size_for(iface_config);
    if let Some(section) = config.subsection("interfaces", name) {
        return interface_factory::InterfacePostInit::from_section(section)
            .with_default_ifac_size(default_ifac_size);
    }
    interface_factory::InterfacePostInit::from_section(&crate::config::ConfigSection::new())
        .with_default_ifac_size(default_ifac_size)
}

fn apply_default_announce_rate(
    post_init: &mut interface_factory::InterfacePostInit,
    config: &ReticulumConfig,
) {
    if !config.enable_transport {
        return;
    }
    if post_init.announce_rate_target.is_none() {
        post_init.announce_rate_target = Some(
            config
                .default_ar_target
                .unwrap_or(rns_interface::traits::DEFAULT_AR_TARGET),
        );
    }
    if post_init.announce_rate_penalty.is_none() {
        post_init.announce_rate_penalty = Some(
            config
                .default_ar_penalty
                .unwrap_or(rns_interface::traits::DEFAULT_AR_PENALTY),
        );
    }
    if post_init.announce_rate_grace.is_none() {
        post_init.announce_rate_grace = Some(
            config
                .default_ar_grace
                .unwrap_or(rns_interface::traits::DEFAULT_AR_GRACE),
        );
    }
}

fn apply_reticulum_ingress_defaults(
    post_init: &mut interface_factory::InterfacePostInit,
    config: &ReticulumConfig,
) {
    post_init.ingress_overrides =
        merge_ingress_overrides(&config.ingress_overrides, &post_init.ingress_overrides);
}

fn finalize_post_init(
    post_init: &mut interface_factory::InterfacePostInit,
    config: &ReticulumConfig,
) {
    apply_default_announce_rate(post_init, config);
    apply_reticulum_ingress_defaults(post_init, config);
}

fn interface_config_name(iface_config: &interface_factory::InterfaceConfig) -> &str {
    match iface_config {
        interface_factory::InterfaceConfig::TcpClient(c) => &c.name,
        interface_factory::InterfaceConfig::TcpServer(c) => &c.name,
        interface_factory::InterfaceConfig::Udp(c) => &c.name,
        #[cfg(feature = "serial")]
        interface_factory::InterfaceConfig::Serial(c) => &c.name,
        #[cfg(feature = "serial")]
        interface_factory::InterfaceConfig::KissSerial(c) => &c.name,
        interface_factory::InterfaceConfig::Auto(c) => &c.name,
        #[cfg(any(feature = "serial", feature = "rnode-tcp"))]
        interface_factory::InterfaceConfig::RNode(c) => &c.name,
        interface_factory::InterfaceConfig::Local(c) => &c.name,
        interface_factory::InterfaceConfig::I2P(c) => &c.name,
        interface_factory::InterfaceConfig::Pipe(c) => &c.name,
        #[cfg(feature = "serial")]
        interface_factory::InterfaceConfig::RNodeMulti(c) => &c.name,
        #[cfg(feature = "serial")]
        interface_factory::InterfaceConfig::AX25KISS(c) => &c.name,
        interface_factory::InterfaceConfig::Backbone(c) => &c.name,
        #[cfg(feature = "ble")]
        interface_factory::InterfaceConfig::BleRNode(c) => &c.name,
    }
}

fn interface_section<'a>(
    config: &'a Config,
    iface_config: &interface_factory::InterfaceConfig,
) -> Option<&'a ConfigSection> {
    let name = interface_config_name(iface_config);
    config.subsection("interfaces", name)
}

fn interface_config_mode_mut(
    iface_config: &mut interface_factory::InterfaceConfig,
) -> &mut rns_interface::traits::InterfaceMode {
    match iface_config {
        interface_factory::InterfaceConfig::TcpClient(c) => &mut c.mode,
        interface_factory::InterfaceConfig::TcpServer(c) => &mut c.mode,
        interface_factory::InterfaceConfig::Udp(c) => &mut c.mode,
        #[cfg(feature = "serial")]
        interface_factory::InterfaceConfig::Serial(c) => &mut c.mode,
        #[cfg(feature = "serial")]
        interface_factory::InterfaceConfig::KissSerial(c) => &mut c.mode,
        interface_factory::InterfaceConfig::Auto(c) => &mut c.mode,
        #[cfg(any(feature = "serial", feature = "rnode-tcp"))]
        interface_factory::InterfaceConfig::RNode(c) => &mut c.mode,
        interface_factory::InterfaceConfig::Local(c) => &mut c.mode,
        interface_factory::InterfaceConfig::I2P(c) => &mut c.mode,
        interface_factory::InterfaceConfig::Pipe(c) => &mut c.mode,
        #[cfg(feature = "serial")]
        interface_factory::InterfaceConfig::RNodeMulti(c) => &mut c.mode,
        #[cfg(feature = "serial")]
        interface_factory::InterfaceConfig::AX25KISS(c) => &mut c.mode,
        interface_factory::InterfaceConfig::Backbone(c) => &mut c.mode,
        #[cfg(feature = "ble")]
        interface_factory::InterfaceConfig::BleRNode(c) => &mut c.mode,
    }
}

/// Python Reticulum.py:841-848: a `discoverable` interface must run in
/// Gateway, Internal, or Access Point mode for discovery to be useful, so
/// other modes are auto-corrected (AP for RNode radios, Gateway otherwise)
/// with a notice.
/// `ignore_config_warnings = yes` opts out and keeps the configured mode.
fn apply_discovery_mode_autocorrect(
    config: &Config,
    iface_config: &mut interface_factory::InterfaceConfig,
) {
    use rns_interface::traits::InterfaceMode;

    let Some(section) = interface_section(config, iface_config) else {
        return;
    };
    if !section.get_bool("discoverable").unwrap_or(false)
        || section.get_bool("ignore_config_warnings").unwrap_or(false)
    {
        return;
    }

    let is_rnode = {
        #[allow(unused_mut)]
        let mut rnode = false;
        #[cfg(any(feature = "serial", feature = "rnode-tcp"))]
        {
            rnode |= matches!(iface_config, interface_factory::InterfaceConfig::RNode(_));
        }
        #[cfg(feature = "serial")]
        {
            rnode |= matches!(
                iface_config,
                interface_factory::InterfaceConfig::RNodeMulti(_)
            );
        }
        #[cfg(feature = "ble")]
        {
            rnode |= matches!(
                iface_config,
                interface_factory::InterfaceConfig::BleRNode(_)
            );
        }
        rnode
    };

    let name = interface_config_name(iface_config).to_string();
    let mode = interface_config_mode_mut(iface_config);
    if matches!(
        *mode,
        InterfaceMode::Gateway | InterfaceMode::Internal | InterfaceMode::AccessPoint
    ) {
        return;
    }
    *mode = if is_rnode {
        InterfaceMode::AccessPoint
    } else {
        InterfaceMode::Gateway
    };
    tracing::warn!(
        interface = %name,
        mode = ?*mode,
        "discovery enabled without gateway or AP mode — auto-configured; \
         set ignore_config_warnings to keep the configured mode"
    );
}

fn interface_bootstrap_only(
    config: &Config,
    iface_config: &interface_factory::InterfaceConfig,
) -> bool {
    interface_section(config, iface_config)
        .and_then(|s| s.get_bool("bootstrap_only"))
        .unwrap_or(false)
}

fn discovery_config_for_interface(
    config: &Config,
    iface_config: &interface_factory::InterfaceConfig,
    post_init: &interface_factory::InterfacePostInit,
    transport_enabled: bool,
) -> Option<DiscoveryInterfaceConfig> {
    let section = interface_section(config, iface_config)?;
    if !section.get_bool("discoverable").unwrap_or(false) {
        return None;
    }

    let name = section
        .get("discovery_name")
        .unwrap_or_else(|| interface_config_name(iface_config))
        .to_string();

    let (interface_type, reachable_on, port, frequency, bandwidth, spreading_factor, coding_rate) =
        match iface_config {
            interface_factory::InterfaceConfig::TcpServer(c) => (
                "TCPServerInterface",
                configured_reachable_on(section).or_else(|| usable_listen_addr(&c.listen_ip)),
                Some(c.listen_port),
                None,
                None,
                None,
                None,
            ),
            interface_factory::InterfaceConfig::TcpClient(c) if c.kiss_framing => (
                "TCPClientInterface",
                configured_reachable_on(section).or_else(|| Some(c.target_host.clone())),
                Some(c.target_port),
                None,
                None,
                None,
                None,
            ),
            interface_factory::InterfaceConfig::Backbone(c) => (
                "BackboneInterface",
                configured_reachable_on(section).or_else(|| {
                    c.listen_on
                        .as_ref()
                        .and_then(|addr| usable_listen_addr(addr))
                        .or_else(|| c.target_host.clone())
                }),
                Some(c.port),
                None,
                None,
                None,
                None,
            ),
            interface_factory::InterfaceConfig::I2P(c) => (
                "I2PInterface",
                configured_reachable_on(section).or_else(|| {
                    if c.connectable {
                        c.peers.first().cloned()
                    } else {
                        None
                    }
                }),
                None,
                None,
                None,
                None,
                None,
            ),
            #[cfg(any(feature = "serial", feature = "rnode-tcp"))]
            interface_factory::InterfaceConfig::RNode(c) => (
                "RNodeInterface",
                configured_reachable_on(section),
                None,
                Some(c.frequency as u64),
                Some(c.bandwidth as u64),
                Some(c.spreading_factor),
                Some(c.coding_rate),
            ),
            #[cfg(feature = "ble")]
            interface_factory::InterfaceConfig::BleRNode(c) => (
                "RNodeInterface",
                configured_reachable_on(section),
                None,
                Some(c.frequency as u64),
                Some(c.bandwidth as u64),
                Some(c.spreading_factor),
                Some(c.coding_rate),
            ),
            #[cfg(feature = "serial")]
            interface_factory::InterfaceConfig::KissSerial(_c) => (
                "KISSInterface",
                configured_reachable_on(section),
                None,
                section.get_uint("discovery_frequency"),
                section.get_uint("discovery_bandwidth"),
                section
                    .get_uint("discovery_spreading_factor")
                    .map(|v| v.min(u8::MAX as u64) as u8),
                section
                    .get_uint("discovery_coding_rate")
                    .map(|v| v.min(u8::MAX as u64) as u8),
            ),
            #[cfg(feature = "serial")]
            interface_factory::InterfaceConfig::AX25KISS(_c) => (
                "KISSInterface",
                configured_reachable_on(section),
                None,
                section.get_uint("discovery_frequency"),
                section.get_uint("discovery_bandwidth"),
                section
                    .get_uint("discovery_spreading_factor")
                    .map(|v| v.min(u8::MAX as u64) as u8),
                section
                    .get_uint("discovery_coding_rate")
                    .map(|v| v.min(u8::MAX as u64) as u8),
            ),
            _ => return None,
        };

    let publish_ifac = section
        .get_bool("discovery_publish_ifac")
        .or_else(|| section.get_bool("publish_ifac"))
        .unwrap_or(false);

    Some(DiscoveryInterfaceConfig {
        interface_type: interface_type.to_string(),
        discoverable: true,
        name,
        transport_enabled,
        announce_interval_secs: discovery_announce_interval_secs(section),
        stamp_value: section
            .get_uint("discovery_stamp_value")
            .or_else(|| section.get_uint("stamp_value"))
            .map(|v| v.min(u8::MAX as u64) as u8)
            .unwrap_or(rns_transport::discovery::DEFAULT_STAMP_VALUE),
        reachable_on,
        port,
        ifac_netname: publish_ifac
            .then(|| post_init.ifac_network_name.clone())
            .flatten(),
        ifac_netkey: publish_ifac
            .then(|| post_init.ifac_passphrase.clone())
            .flatten(),
        frequency: section.get_uint("discovery_frequency").or(frequency),
        bandwidth: section.get_uint("discovery_bandwidth").or(bandwidth),
        spreading_factor: section
            .get_uint("discovery_spreading_factor")
            .map(|v| v.min(u8::MAX as u64) as u8)
            .or(spreading_factor),
        coding_rate: section
            .get_uint("discovery_coding_rate")
            .map(|v| v.min(u8::MAX as u64) as u8)
            .or(coding_rate),
        modulation: section.get("discovery_modulation").map(ToString::to_string),
        channel: section
            .get_uint("discovery_channel")
            .map(|v| v.min(u16::MAX as u64) as u16),
        latitude: section
            .get_float("discovery_latitude")
            .or_else(|| section.get_float("latitude"))
            .unwrap_or(0.0),
        longitude: section
            .get_float("discovery_longitude")
            .or_else(|| section.get_float("longitude"))
            .unwrap_or(0.0),
        height: section
            .get_float("discovery_height")
            .or_else(|| section.get_float("height"))
            .unwrap_or(0.0),
        encrypt: section.get_bool("discovery_encrypt").unwrap_or(false),
        signed: false,
    })
}

fn configured_reachable_on(section: &ConfigSection) -> Option<String> {
    section
        .get("discovery_reachable_on")
        .or_else(|| section.get("reachable_on"))
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

fn usable_listen_addr(addr: &str) -> Option<String> {
    let trimmed = addr.trim();
    if trimmed.is_empty() || trimmed == "0.0.0.0" || trimmed == "::" {
        None
    } else {
        Some(trimmed.to_string())
    }
}

fn discovery_announce_interval_secs(section: &ConfigSection) -> u64 {
    if let Some(seconds) = section.get_uint("discovery_announce_interval_secs") {
        return seconds.max(1);
    }
    section
        .get_float("discovery_announce_interval")
        .or_else(|| section.get_float("announce_interval"))
        .map(|minutes| (minutes.max(0.0) * 60.0).round().max(1.0) as u64)
        .unwrap_or(6 * 60 * 60)
}

struct IdentityDiscoveryDecryptor {
    identity: Arc<Identity>,
}

impl DiscoveryDecryptor for IdentityDiscoveryDecryptor {
    fn decrypt(&self, ciphertext: &[u8]) -> Option<Vec<u8>> {
        self.identity.decrypt(ciphertext, None, false).ok()
    }
}

async fn start_on_network_discovery(handle: ReticulumHandle) {
    let stamper = handle.discovery.stamper.lock().await.clone();
    let Some(stamper) = stamper else {
        return;
    };
    let store = handle.discovery.store.lock().await.clone();
    let Some(store) = store else {
        return;
    };

    if handle.config.discover_interfaces {
        let mut started = handle.discovery.receiver_started.lock().await;
        if !*started {
            *started = true;
            drop(started);

            let (observer_tx, observer_rx) = if handle.config.autoconnect_discovered_interfaces > 0
            {
                let (tx, rx) = mpsc::channel(128);
                (Some(tx), Some(rx))
            } else {
                (None, None)
            };
            let decryptor = handle.network_identity.as_ref().map(|identity| {
                Arc::new(IdentityDiscoveryDecryptor {
                    identity: identity.clone(),
                }) as Arc<dyn DiscoveryDecryptor>
            });
            let receiver_config = ReceiverConfig {
                stamper: stamper.clone(),
                store: store.clone(),
                required_value: handle.config.discover_interfaces_required_value,
                discovery_sources: (!handle.config.interface_discovery_sources.is_empty())
                    .then(|| handle.config.interface_discovery_sources.clone()),
                decryptor,
                observer: observer_tx,
            };
            let (_join, callback_tx) = rns_transport::discovery::receiver::spawn(receiver_config);
            let _ = handle
                .transport_tx
                .send(TransportMessage::RegisterAnnounceHandler {
                    aspect_filter: Some(
                        rns_transport::discovery::DISCOVERY_ASPECT_FILTER.to_string(),
                    ),
                    receive_path_responses: false,
                    callback_tx,
                })
                .await;

            if let Some(rx) = observer_rx {
                let observer_handle = handle.clone();
                tokio::spawn(async move {
                    run_discovery_autoconnect(observer_handle, rx).await;
                });
            }
        }
    }

    let locals = handle.discovery.local_interfaces.lock().await.clone();
    if !locals.is_empty() {
        let mut started = handle.discovery.announcer_started.lock().await;
        if !*started {
            *started = true;
            drop(started);
            tokio::spawn(async move {
                run_discovery_announcer(handle, stamper, locals).await;
            });
        }
    }
}

async fn run_discovery_announcer(
    handle: ReticulumHandle,
    stamper: Arc<dyn DiscoveryStamper + Send + Sync>,
    locals: Vec<LocalDiscoveryInterface>,
) {
    let mut announcer = Announcer::new(stamper);
    for local in locals {
        announcer.register(local.id, handle.transport_identity.hash, local.config);
    }

    let announce_identity = handle
        .network_identity
        .clone()
        .unwrap_or_else(|| handle.transport_identity.clone());
    let encrypt_identity = handle.network_identity.clone();
    let tick_interval = Duration::from_secs(rns_transport::discovery::ANNOUNCE_JOB_INTERVAL_SECS);

    loop {
        let encrypt = |plaintext: &[u8]| {
            encrypt_identity
                .as_ref()
                .and_then(|identity| identity.encrypt(plaintext, None).ok())
        };
        let (requests, _skips) = announcer.tick(unix_now(), Some(&encrypt));
        for request in requests {
            match build_announce_packet(
                &announce_identity,
                rns_transport::discovery::DISCOVERY_ASPECT_FILTER,
                Some(&request.app_data),
            ) {
                Ok(raw) => {
                    let _ = handle
                        .transport_tx
                        .send(TransportMessage::Outbound(OutboundRequest {
                            raw: Bytes::from(raw),
                            destination_hash:
                                rns_identity::destination::Destination::hash_from_name_and_identity(
                                    rns_transport::discovery::DISCOVERY_ASPECT_FILTER,
                                    Some(&announce_identity.hash),
                                ),
                        }))
                        .await;
                }
                Err(e) => {
                    tracing::warn!(error = %e, "failed to build discovery announce");
                }
            }
        }

        tokio::select! {
            _ = handle.shutdown.wait() => break,
            _ = tokio::time::sleep(tick_interval) => {}
        }
    }
}

async fn run_discovery_autoconnect(
    handle: ReticulumHandle,
    mut rx: mpsc::Receiver<DiscoveredInterface>,
) {
    if let Some(store) = handle.discovery.store.lock().await.clone() {
        let sources = if handle.config.interface_discovery_sources.is_empty() {
            None
        } else {
            Some(handle.config.interface_discovery_sources.as_slice())
        };
        for record in store.list(sources).unwrap_or_default() {
            maybe_autoconnect_discovered(&handle, record).await;
        }
    }

    loop {
        tokio::select! {
            Some(record) = rx.recv() => {
                maybe_autoconnect_discovered(&handle, record).await;
            }
            _ = handle.shutdown.wait() => break,
        }
    }
}

async fn maybe_autoconnect_discovered(handle: &ReticulumHandle, record: DiscoveredInterface) {
    if !handle.interface_registry.is_open() {
        return;
    }
    let limit = handle.config.autoconnect_discovered_interfaces;
    if limit == 0 {
        return;
    }
    if !matches!(
        record.info.interface_type.as_str(),
        "BackboneInterface" | "TCPServerInterface"
    ) {
        return;
    }
    let Some(host) = record.info.reachable_on.clone() else {
        return;
    };
    if is_yggdrasil_ipv6(&host) {
        tracing::debug!(host = %host, "skipping Yggdrasil IPv6 discovery autoconnect");
        return;
    }
    let Some(port) = record.info.port else {
        return;
    };

    let key = discovery_hash(&record.info.transport_id, &record.info.name);
    {
        let mut connected = handle.discovery.autoconnected.lock().await;
        if connected.contains_key(&key) || connected.len() >= limit {
            return;
        }
        connected.insert(key, u64::MAX);
    }

    match spawn_discovered_backbone_client(handle, &record, &host, port).await {
        Ok(id) => {
            handle.discovery.autoconnected.lock().await.insert(key, id);
            maybe_teardown_bootstrap_interfaces(handle).await;
        }
        Err(e) => {
            handle.discovery.autoconnected.lock().await.remove(&key);
            tracing::warn!(
                name = %record.info.name,
                endpoint = %format!("{host}:{port}"),
                error = %e,
                "failed to auto-connect discovered interface"
            );
        }
    }
}

async fn spawn_discovered_backbone_client(
    handle: &ReticulumHandle,
    record: &DiscoveredInterface,
    host: &str,
    port: u16,
) -> Result<u64, String> {
    let spawn_permit = ensure_runtime_interface_admission(handle)?;
    let id = next_id(&handle.id_gen);
    let name = format!(
        "Discovered/{}",
        record
            .info
            .name
            .chars()
            .map(|c| if c == '/' { '_' } else { c })
            .collect::<String>()
    );
    let mut config = rns_interface::backbone::BackboneClientConfig::new(&name, host, port);
    config.mode = discovered_backbone_client_mode(&handle.config);
    let iface_handle =
        rns_interface::backbone::spawn_backbone_client(config, id, handle.transport_tx.clone())
            .await
            .map_err(|e| format!("Backbone client spawn failed: {e}"))?;

    let mut post_init = interface_factory::InterfacePostInit::from_section(&ConfigSection::new())
        .with_default_ifac_size(16);
    finalize_post_init(&mut post_init, &handle.config);
    post_init.ifac_network_name = record.info.ifac_netname.clone();
    post_init.ifac_passphrase = record.info.ifac_netkey.clone();
    let ifac_key = derive_ifac_key_from_post_init(&post_init);
    register_interface_with_post_init_and_spawn_permit(
        &handle.transport_tx,
        iface_handle,
        &post_init,
        ifac_key,
        &handle.interface_controls,
        &handle.interface_registry,
        InterfaceKind::Standard,
        spawn_permit,
    )
    .await
    .map_err(|error| format!("Backbone client registration failed: {error}"))?;
    tracing::info!(name = %name, id, endpoint = %format!("{host}:{port}"), "auto-connected discovered interface");
    Ok(id)
}

fn is_yggdrasil_ipv6(host: &str) -> bool {
    let Ok(std::net::IpAddr::V6(addr)) = host.parse() else {
        return false;
    };
    let first = addr.octets()[0];
    first == 0x02 || first == 0x03
}

async fn maybe_teardown_bootstrap_interfaces(handle: &ReticulumHandle) {
    let limit = handle.config.autoconnect_discovered_interfaces;
    let connected = handle.discovery.autoconnected.lock().await.len();
    if limit == 0 || connected < limit {
        return;
    }
    let ids = {
        let mut bootstrap = handle.discovery.bootstrap_interfaces.lock().await;
        if bootstrap.is_empty() {
            return;
        }
        std::mem::take(&mut *bootstrap)
    };
    for id in ids {
        teardown_interface(handle, id).await;
    }
}

fn build_announce_packet(
    identity: &Identity,
    app_name: &str,
    app_data: Option<&[u8]>,
) -> Result<Vec<u8>, String> {
    let announce = rns_identity::announce::AnnounceData::create(identity, app_name, app_data, None)
        .map_err(|e| e.to_string())?;
    let dest_hash = rns_identity::destination::Destination::hash_from_name_and_identity(
        app_name,
        Some(&identity.hash),
    );
    let flags = rns_wire::flags::PacketFlags {
        header_type: rns_wire::flags::HeaderType::Header1,
        context_flag: false,
        transport_type: rns_wire::flags::TransportType::Broadcast,
        destination_type: rns_wire::flags::DestinationType::Single,
        packet_type: rns_wire::flags::PacketType::Announce,
    };
    let header = rns_wire::header::PacketHeader {
        flags,
        hops: 0,
        transport_id: None,
        destination_hash: dest_hash,
        context: rns_wire::context::PacketContext::None,
    };
    let mut raw = header.pack();
    raw.extend_from_slice(&announce.pack());
    Ok(raw)
}

async fn start_blackhole_publisher(handle: &ReticulumHandle) -> Result<[u8; 16], String> {
    let identity = handle.transport_identity.clone();
    let signing_key = identity
        .get_signing_key()
        .ok_or_else(|| "No signing key available for blackhole publisher".to_string())?;
    let app_name = rns_transport::discovery::BLACKHOLE_ASPECT_FILTER;
    let dest_hash = rns_identity::destination::Destination::hash_from_name_and_identity(
        app_name,
        Some(&identity.hash),
    );
    let event_rx =
        crate::link_manager::register_destination(&handle.transport_tx, dest_hash, app_name);
    let mut lm = LinkManager::with_destination(
        handle.transport_tx.clone(),
        event_rx,
        &identity,
        app_name,
        Some(signing_key),
    );

    let list_hash = rns_crypto::sha::truncated_hash(b"/list");
    let publisher = identity.hash;
    let query_tx = handle.transport_tx.clone();
    lm.set_request_handler(move |_link_id, path_hash, _data| {
        if path_hash != list_hash {
            return None;
        }
        match blocking_transport_query(
            &query_tx,
            TransportQuery::BuildBlackholeManifest { publisher },
        ) {
            Some(TransportQueryResponse::Data(payload)) => Some(payload),
            Some(TransportQueryResponse::Error(e)) => {
                tracing::warn!(error = %e, "blackhole manifest build failed");
                None
            }
            _ => None,
        }
    });

    let announce_tx = handle.transport_tx.clone();
    let announce_identity = identity.clone();
    lm.set_announce_handler(move || {
        send_announce_try(&announce_tx, &announce_identity, app_name, None);
    });

    tokio::spawn(async move {
        lm.run().await;
    });

    send_announce_try(&handle.transport_tx, &identity, app_name, None);
    Ok(dest_hash)
}

async fn start_blackhole_subscriber(handle: ReticulumHandle) {
    let mut started = handle.discovery.subscriber_started.lock().await;
    if *started {
        return;
    }
    *started = true;
    drop(started);

    let identity = match clone_identity(&handle.transport_identity) {
        Some(identity) => identity,
        None => {
            tracing::warn!("blackhole subscriber requires a local identity with private keys");
            return;
        }
    };

    tokio::spawn(async move {
        let client = LinkClient::new(handle.transport_tx.clone(), identity);
        tokio::select! {
            _ = handle.shutdown.wait() => return,
            _ = tokio::time::sleep(BLACKHOLE_INITIAL_WAIT) => {}
        }

        let mut state = BlackholeSubscriberState::new().with_update_interval(
            Duration::from_secs_f64(handle.config.blackhole_update_interval),
        );
        loop {
            let sources: Vec<rns_wire::types::IdentityHash> = handle
                .config
                .blackhole_sources
                .iter()
                .copied()
                .map(Into::into)
                .collect();
            state.prune(&sources);
            let now = unix_now();
            for source in state.due_sources(&sources, now) {
                let source_hash = source.into_bytes();
                match client
                    .query(
                        source_hash,
                        rns_transport::discovery::BLACKHOLE_ASPECT_FILTER,
                        "/list",
                        Vec::new(),
                        8,
                        BLACKHOLE_SOURCE_TIMEOUT,
                    )
                    .await
                {
                    Ok(payload) => {
                        match handle
                            .query_transport(TransportQuery::ApplyBlackholeManifest { payload })
                            .await
                        {
                            Some(TransportQueryResponse::IntResult(applied)) => {
                                state.mark_updated(source, unix_now());
                                tracing::debug!(
                                    source = %hex::encode(source_hash),
                                    applied,
                                    "blackhole manifest applied"
                                );
                            }
                            Some(TransportQueryResponse::Error(e)) => {
                                tracing::warn!(
                                    source = %hex::encode(source_hash),
                                    error = %e,
                                    "blackhole manifest rejected"
                                );
                            }
                            _ => {}
                        }
                    }
                    Err(e) => {
                        tracing::debug!(
                            source = %hex::encode(source_hash),
                            error = %e,
                            "blackhole manifest pull failed"
                        );
                    }
                }
            }

            tokio::select! {
                _ = handle.shutdown.wait() => break,
                _ = tokio::time::sleep(BLACKHOLE_JOB_INTERVAL.min(BLACKHOLE_UPDATE_INTERVAL)) => {}
            }
        }
    });
}

fn clone_identity(identity: &Identity) -> Option<Identity> {
    // Preserve a hardware backend (shared Arc); software identities copy key material.
    if identity.has_private_key() || identity.has_backend() {
        Some(identity.clone())
    } else {
        None
    }
}

fn send_announce_try(
    tx: &mpsc::Sender<TransportMessage>,
    identity: &Identity,
    app_name: &str,
    app_data: Option<&[u8]>,
) {
    let raw = match build_announce_packet(identity, app_name, app_data) {
        Ok(raw) => raw,
        Err(e) => {
            tracing::warn!(error = %e, app_name, "failed to build announce");
            return;
        }
    };
    let dest_hash = rns_identity::destination::Destination::hash_from_name_and_identity(
        app_name,
        Some(&identity.hash),
    );
    let _ = tx.try_send(TransportMessage::Outbound(OutboundRequest {
        raw: Bytes::from(raw),
        destination_hash: dest_hash,
    }));
}

fn blocking_transport_query(
    tx: &mpsc::Sender<TransportMessage>,
    query: TransportQuery,
) -> Option<TransportQueryResponse> {
    let (resp_tx, resp_rx) = tokio::sync::oneshot::channel();
    if tx
        .try_send(TransportMessage::Rpc {
            query,
            response_tx: resp_tx,
        })
        .is_err()
    {
        return None;
    }
    tokio::task::block_in_place(|| resp_rx.blocking_recv().ok())
}

fn ensure_runtime_interface_admission(
    handle: &ReticulumHandle,
) -> Result<InterfaceSpawnPermit, String> {
    handle
        .interface_registry
        .acquire_spawn_permit()
        .map_err(|_| "runtime is shutting down; interface spawn rejected".to_string())
}

/// Spawn a TCP client interface at runtime; returns the interface ID.
pub async fn spawn_tcp_client_runtime(
    handle: &ReticulumHandle,
    name: &str,
    host: &str,
    port: u16,
) -> Result<u64, String> {
    spawn_tcp_client_runtime_with_ifac(handle, name, host, port, None).await
}

/// Spawn a TCP client interface at runtime with optional IFAC settings.
pub async fn spawn_tcp_client_runtime_with_ifac(
    handle: &ReticulumHandle,
    name: &str,
    host: &str,
    port: u16,
    ifac: Option<RuntimeInterfaceIfacConfig>,
) -> Result<u64, String> {
    let spawn_permit = ensure_runtime_interface_admission(handle)?;
    let id = handle
        .id_gen
        .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let post_init = runtime_ifac_post_init(ifac, 16)?;
    let config = rns_interface::tcp::TcpClientConfig::new(name, host, port);
    let iface_handle =
        rns_interface::tcp::spawn_tcp_client(config, id, handle.transport_tx.clone())
            .await
            .map_err(|e| format!("TCP client spawn failed: {e}"))?;

    if let Some(post_init) = post_init {
        let ifac_key = derive_ifac_key_from_post_init(&post_init);
        register_interface_with_post_init_and_spawn_permit(
            &handle.transport_tx,
            iface_handle,
            &post_init,
            ifac_key,
            &handle.interface_controls,
            &handle.interface_registry,
            InterfaceKind::Standard,
            spawn_permit,
        )
        .await
        .map_err(|error| format!("TCP client registration failed: {error}"))?;
    } else {
        register_interface_handle_with_spawn_permit(
            &handle.transport_tx,
            iface_handle,
            &handle.interface_controls,
            &handle.interface_registry,
            spawn_permit,
        )
        .await
        .map_err(|error| format!("TCP client registration failed: {error}"))?;
    }
    tracing::info!(name = %name, id, "runtime TCP client interface spawned");
    Ok(id)
}

/// Spawn a TCP server interface at runtime.
pub async fn spawn_tcp_server_runtime(
    handle: &ReticulumHandle,
    name: &str,
    listen_ip: &str,
    port: u16,
) -> Result<u64, String> {
    spawn_tcp_server_runtime_with_ifac(handle, name, listen_ip, port, None).await
}

/// Spawn a TCP server interface at runtime with optional IFAC settings.
/// Accepted client connections inherit the listener's IFAC.
pub async fn spawn_tcp_server_runtime_with_ifac(
    handle: &ReticulumHandle,
    name: &str,
    listen_ip: &str,
    port: u16,
    ifac: Option<RuntimeInterfaceIfacConfig>,
) -> Result<u64, String> {
    let spawn_permit = ensure_runtime_interface_admission(handle)?;
    let id = next_id(&handle.id_gen);
    let post_init = runtime_ifac_post_init(ifac, 16)?;
    let config = rns_interface::tcp::TcpServerConfig::new(name, listen_ip, port);
    let iface_handle = rns_interface::tcp::spawn_tcp_server(
        config,
        id,
        handle.id_gen.clone(),
        handle.transport_tx.clone(),
        handle.handle_tx.clone(),
    )
    .await
    .map_err(|e| format!("TCP server spawn failed: {e}"))?;

    if let Some(post_init) = post_init {
        let ifac_key = derive_ifac_key_from_post_init(&post_init);
        register_interface_with_post_init_and_spawn_permit(
            &handle.transport_tx,
            iface_handle,
            &post_init,
            ifac_key,
            &handle.interface_controls,
            &handle.interface_registry,
            InterfaceKind::Standard,
            spawn_permit,
        )
        .await
        .map_err(|error| format!("TCP server registration failed: {error}"))?;
    } else {
        register_interface_handle_with_spawn_permit(
            &handle.transport_tx,
            iface_handle,
            &handle.interface_controls,
            &handle.interface_registry,
            spawn_permit,
        )
        .await
        .map_err(|error| format!("TCP server registration failed: {error}"))?;
    }
    tracing::info!(name = %name, id, "runtime TCP server interface spawned");
    Ok(id)
}

/// Spawn a Backbone (HDLC-over-TCP) client interface at runtime.
pub async fn spawn_backbone_client_runtime(
    handle: &ReticulumHandle,
    name: &str,
    host: &str,
    port: u16,
    prefer_ipv6: bool,
    connect_timeout: Option<u64>,
    max_reconnect_tries: Option<usize>,
) -> Result<u64, String> {
    spawn_backbone_client_runtime_with_ifac(
        handle,
        RuntimeBackboneClientConfig {
            name,
            host,
            port,
            prefer_ipv6,
            connect_timeout,
            max_reconnect_tries,
            ifac: None,
        },
    )
    .await
}

/// Spawn a Backbone (HDLC-over-TCP) client interface at runtime with optional IFAC settings.
pub async fn spawn_backbone_client_runtime_with_ifac(
    handle: &ReticulumHandle,
    runtime_config: RuntimeBackboneClientConfig<'_>,
) -> Result<u64, String> {
    let spawn_permit = ensure_runtime_interface_admission(handle)?;
    let id = handle
        .id_gen
        .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let post_init = runtime_ifac_post_init(runtime_config.ifac, 16)?;
    let mut config = rns_interface::backbone::BackboneClientConfig::new(
        runtime_config.name,
        runtime_config.host,
        runtime_config.port,
    );
    config.prefer_ipv6 = runtime_config.prefer_ipv6;
    if let Some(t) = runtime_config.connect_timeout {
        config.connect_timeout_secs = t;
    }
    config.max_reconnect_tries = runtime_config.max_reconnect_tries;

    let iface_handle =
        rns_interface::backbone::spawn_backbone_client(config, id, handle.transport_tx.clone())
            .await
            .map_err(|e| format!("Backbone client spawn failed: {e}"))?;

    if let Some(post_init) = post_init {
        let ifac_key = derive_ifac_key_from_post_init(&post_init);
        register_interface_with_post_init_and_spawn_permit(
            &handle.transport_tx,
            iface_handle,
            &post_init,
            ifac_key,
            &handle.interface_controls,
            &handle.interface_registry,
            InterfaceKind::Standard,
            spawn_permit,
        )
        .await
        .map_err(|error| format!("Backbone client registration failed: {error}"))?;
    } else {
        register_interface_handle_with_spawn_permit(
            &handle.transport_tx,
            iface_handle,
            &handle.interface_controls,
            &handle.interface_registry,
            spawn_permit,
        )
        .await
        .map_err(|error| format!("Backbone client registration failed: {error}"))?;
    }
    tracing::info!(name = %runtime_config.name, id, "runtime Backbone client interface spawned");
    Ok(id)
}

/// Spawn a Backbone (HDLC-over-TCP) server interface at runtime.
pub async fn spawn_backbone_server_runtime(
    handle: &ReticulumHandle,
    name: &str,
    listen_ip: &str,
    port: u16,
    prefer_ipv6: bool,
    device: Option<&str>,
) -> Result<u64, String> {
    spawn_backbone_server_runtime_with_ifac(
        handle,
        name,
        listen_ip,
        port,
        prefer_ipv6,
        device,
        None,
    )
    .await
}

/// Spawn a Backbone server interface at runtime with optional IFAC settings.
/// Accepted client connections inherit the listener's IFAC.
pub async fn spawn_backbone_server_runtime_with_ifac(
    handle: &ReticulumHandle,
    name: &str,
    listen_ip: &str,
    port: u16,
    prefer_ipv6: bool,
    device: Option<&str>,
    ifac: Option<RuntimeInterfaceIfacConfig>,
) -> Result<u64, String> {
    let spawn_permit = ensure_runtime_interface_admission(handle)?;
    let id = next_id(&handle.id_gen);
    let post_init = runtime_ifac_post_init(ifac, 16)?;
    let mut config = rns_interface::backbone::BackboneServerConfig::new(name, listen_ip, port);
    config.prefer_ipv6 = prefer_ipv6;
    config.device = device.map(ToString::to_string);

    let iface_handle = rns_interface::backbone::spawn_backbone_server(
        config,
        id,
        handle.id_gen.clone(),
        handle.transport_tx.clone(),
        handle.handle_tx.clone(),
    )
    .await
    .map_err(|e| format!("Backbone server spawn failed: {e}"))?;

    if let Some(post_init) = post_init {
        let ifac_key = derive_ifac_key_from_post_init(&post_init);
        register_interface_with_post_init_and_spawn_permit(
            &handle.transport_tx,
            iface_handle,
            &post_init,
            ifac_key,
            &handle.interface_controls,
            &handle.interface_registry,
            InterfaceKind::Standard,
            spawn_permit,
        )
        .await
        .map_err(|error| format!("Backbone server registration failed: {error}"))?;
    } else {
        register_interface_handle_with_spawn_permit(
            &handle.transport_tx,
            iface_handle,
            &handle.interface_controls,
            &handle.interface_registry,
            spawn_permit,
        )
        .await
        .map_err(|error| format!("Backbone server registration failed: {error}"))?;
    }
    tracing::info!(name = %name, id, "runtime Backbone server interface spawned");
    Ok(id)
}

/// Settings for a runtime-spawned BLE RNode interface.
#[cfg(feature = "ble")]
pub struct BleRnodeRuntimeArgs<'a> {
    /// Interface name registered with the transport actor.
    pub name: &'a str,
    /// BLE device path or address.
    pub port: &'a str,
    /// Radio frequency in Hz.
    pub frequency: u32,
    /// Radio bandwidth in Hz.
    pub bandwidth: u32,
    /// LoRa spreading factor.
    pub spreading_factor: u8,
    /// LoRa coding rate denominator.
    pub coding_rate: u8,
    /// Transmit power in dBm.
    pub tx_power: i8,
    /// Reticulum interface routing/announce propagation mode.
    pub mode: rns_interface::traits::InterfaceMode,
    /// Short-term airtime limit in percent (0.0..=100.0), None = no limit.
    pub st_alock: Option<f32>,
    /// Long-term airtime limit in percent (0.0..=100.0), None = no limit.
    pub lt_alock: Option<f32>,
    /// Enable KISS flow control.
    pub flow_control: bool,
}

/// Returns `(interface_id, online_flag)`; `online_flag` flips to `true`
/// after the first successful connect.
#[cfg(feature = "ble")]
pub async fn spawn_ble_rnode_runtime(
    handle: &ReticulumHandle,
    args: BleRnodeRuntimeArgs<'_>,
) -> Result<(u64, std::sync::Arc<std::sync::atomic::AtomicBool>), String> {
    let spawned = spawn_ble_rnode_runtime_observed(handle, args).await?;
    Ok((spawned.interface_id, spawned.online))
}

/// Spawn and register a BLE RNode, returning an observer bound to that exact
/// registration. Successful return does not imply protocol readiness; call
/// [`RNodeRuntimeObserver::await_ready`] when readiness is required.
#[cfg(feature = "ble")]
pub async fn spawn_ble_rnode_runtime_observed(
    handle: &ReticulumHandle,
    args: BleRnodeRuntimeArgs<'_>,
) -> Result<SpawnedRNodeRuntime, String> {
    spawn_ble_rnode_runtime_observed_with_options(
        handle,
        args,
        rns_interface::rnode::RNodeStartupOptions::default(),
    )
    .await
    .map_err(|error| error.to_string())
}

/// Spawn and register a BLE RNode with an explicit startup policy.
///
/// BLE connection work remains asynchronous, so post-return capability state
/// and deterministic rejection are observed through the returned exact driver.
#[cfg(feature = "ble")]
pub async fn spawn_ble_rnode_runtime_observed_with_options(
    handle: &ReticulumHandle,
    args: BleRnodeRuntimeArgs<'_>,
    rnode_startup_options: rns_interface::rnode::RNodeStartupOptions,
) -> Result<SpawnedRNodeRuntime, RNodeRuntimeSpawnError> {
    let spawn_permit = ensure_runtime_interface_admission(handle)
        .map_err(RNodeRuntimeSpawnError::RuntimeAdmission)?;
    let BleRnodeRuntimeArgs {
        name,
        port,
        frequency,
        bandwidth,
        spreading_factor,
        coding_rate,
        tx_power,
        mode,
        st_alock,
        lt_alock,
        flow_control,
    } = args;

    let mut config = rns_interface::ble_rnode::BleRNodeConfig::new(name, port);
    config.frequency = frequency;
    config.bandwidth = bandwidth;
    config.spreading_factor = spreading_factor;
    config.coding_rate = coding_rate;
    config.tx_power = u8::try_from(tx_power).map_err(|_| {
        RNodeRuntimeSpawnError::InvalidConfiguration(format!(
            "invalid value for '{name}.txpower': {tx_power} is below 0 dBm"
        ))
    })?;
    config.mode = mode;
    config.st_alock = st_alock;
    config.lt_alock = lt_alock;
    config.flow_control = flow_control;
    config.validate().map_err(|error| {
        RNodeRuntimeSpawnError::InvalidConfiguration(format!(
            "invalid value for '{name}.{}': {error}",
            error.field()
        ))
    })?;

    let id = handle
        .id_gen
        .fetch_add(1, std::sync::atomic::Ordering::SeqCst);

    let spawned = rns_interface::ble_rnode::spawn_ble_rnode_interface_with_driver_and_options(
        config,
        id,
        handle.transport_tx.clone(),
        rnode_startup_options,
    )
    .await
    .map_err(RNodeRuntimeSpawnError::BleRNodeSpawn)?;

    let online = spawned.interface.online.clone();
    let state = spawned.driver.watch();
    register_observed_rnode_handle_with_kind_and_spawn_permit(
        &handle.transport_tx,
        spawned,
        &handle.interface_controls,
        &handle.interface_registry,
        InterfaceKind::BleRNode,
        spawn_permit,
    )
    .await
    .map_err(|error| {
        RNodeRuntimeSpawnError::Registration(format!("BLE RNode registration failed: {error}"))
    })?;
    tracing::info!(name = %name, id, "runtime BLE RNode interface spawned");
    Ok(SpawnedRNodeRuntime {
        interface_id: id,
        online,
        observer: RNodeRuntimeObserver {
            interface_id: id,
            state,
        },
    })
}

/// Runtime-spawned RNode over USB serial or TCP (`tcp://host[:port]`).
#[cfg(any(feature = "serial", feature = "rnode-tcp"))]
pub struct RnodeRuntimeArgs<'a> {
    /// Interface name registered with the transport actor.
    pub name: &'a str,
    /// Serial device path or TCP URL.
    pub port: &'a str,
    /// Radio frequency in Hz.
    pub frequency: u32,
    /// Radio bandwidth in Hz.
    pub bandwidth: u32,
    /// LoRa spreading factor.
    pub spreading_factor: u8,
    /// LoRa coding rate denominator.
    pub coding_rate: u8,
    /// Transmit power in dBm.
    pub tx_power: i8,
    /// Reticulum interface routing/announce propagation mode.
    pub mode: rns_interface::traits::InterfaceMode,
    /// Short-term airtime limit in percent (0.0..=100.0), None = no limit.
    pub st_alock: Option<f32>,
    /// Long-term airtime limit in percent (0.0..=100.0), None = no limit.
    pub lt_alock: Option<f32>,
    /// Enable KISS flow control.
    pub flow_control: bool,
}

#[cfg(any(feature = "serial", feature = "rnode-tcp"))]
pub async fn spawn_rnode_runtime(
    handle: &ReticulumHandle,
    args: RnodeRuntimeArgs<'_>,
) -> Result<(u64, std::sync::Arc<std::sync::atomic::AtomicBool>), String> {
    let spawned = spawn_rnode_runtime_observed(handle, args).await?;
    Ok((spawned.interface_id, spawned.online))
}

/// Spawn a serial/TCP RNode and return an observer bound to that exact
/// registration. Successful return does not imply protocol readiness; call
/// [`RNodeRuntimeObserver::await_ready`] when readiness is required.
#[cfg(any(feature = "serial", feature = "rnode-tcp"))]
pub async fn spawn_rnode_runtime_observed(
    handle: &ReticulumHandle,
    args: RnodeRuntimeArgs<'_>,
) -> Result<SpawnedRNodeRuntime, String> {
    spawn_rnode_runtime_observed_with_options(
        handle,
        args,
        rns_interface::rnode::RNodeStartupOptions::default(),
    )
    .await
    .map_err(|error| error.to_string())
}

/// Spawn and register a serial/TCP RNode with an explicit startup policy.
#[cfg(any(feature = "serial", feature = "rnode-tcp"))]
pub async fn spawn_rnode_runtime_observed_with_options(
    handle: &ReticulumHandle,
    args: RnodeRuntimeArgs<'_>,
    rnode_startup_options: rns_interface::rnode::RNodeStartupOptions,
) -> Result<SpawnedRNodeRuntime, RNodeRuntimeSpawnError> {
    let spawn_permit = ensure_runtime_interface_admission(handle)
        .map_err(RNodeRuntimeSpawnError::RuntimeAdmission)?;
    let RnodeRuntimeArgs {
        name,
        port,
        frequency,
        bandwidth,
        spreading_factor,
        coding_rate,
        tx_power,
        mode,
        st_alock,
        lt_alock,
        flow_control,
    } = args;

    let mut config = rns_interface::rnode::RNodeConfig::new(name, port);
    config.frequency = frequency;
    config.bandwidth = bandwidth;
    config.spreading_factor = spreading_factor;
    config.coding_rate = coding_rate;
    config.tx_power = u8::try_from(tx_power).map_err(|_| {
        RNodeRuntimeSpawnError::InvalidConfiguration(format!(
            "invalid value for '{name}.txpower': {tx_power} is below 0 dBm"
        ))
    })?;
    config.mode = mode;
    config.st_alock = st_alock;
    config.lt_alock = lt_alock;
    config.flow_control = flow_control;
    config.validate().map_err(|error| {
        RNodeRuntimeSpawnError::InvalidConfiguration(format!(
            "invalid value for '{name}.{}': {error}",
            error.field()
        ))
    })?;

    let id = handle
        .id_gen
        .fetch_add(1, std::sync::atomic::Ordering::SeqCst);

    let spawned = rns_interface::rnode::spawn_rnode_interface_with_driver_and_options(
        config,
        id,
        handle.transport_tx.clone(),
        rnode_startup_options,
    )
    .await
    .map_err(RNodeRuntimeSpawnError::RNodeSpawn)?;

    let online = spawned.interface.online.clone();
    let state = spawned.driver.watch();
    register_observed_rnode_handle_with_kind_and_spawn_permit(
        &handle.transport_tx,
        spawned,
        &handle.interface_controls,
        &handle.interface_registry,
        InterfaceKind::RNode,
        spawn_permit,
    )
    .await
    .map_err(|error| {
        RNodeRuntimeSpawnError::Registration(format!("RNode registration failed: {error}"))
    })?;
    tracing::info!(name = %name, id, "runtime RNode interface spawned");
    Ok(SpawnedRNodeRuntime {
        interface_id: id,
        online,
        observer: RNodeRuntimeObserver {
            interface_id: id,
            state,
        },
    })
}

/// Android bridge variant: Kotlin owns GATT, Rust connects via a local TCP socket.
#[cfg(feature = "ble")]
pub async fn spawn_ble_rnode_runtime_native(
    handle: &ReticulumHandle,
    args: BleRnodeRuntimeArgs<'_>,
    tcp_port: u16,
) -> Result<(u64, std::sync::Arc<std::sync::atomic::AtomicBool>), String> {
    let spawned = spawn_ble_rnode_runtime_native_observed(handle, args, tcp_port).await?;
    Ok((spawned.interface_id, spawned.online))
}

/// Spawn a native-bridge BLE RNode and return an observer bound to that exact
/// registration. Successful return does not imply protocol readiness; call
/// [`RNodeRuntimeObserver::await_ready`] when readiness is required.
#[cfg(feature = "ble")]
pub async fn spawn_ble_rnode_runtime_native_observed(
    handle: &ReticulumHandle,
    args: BleRnodeRuntimeArgs<'_>,
    tcp_port: u16,
) -> Result<SpawnedRNodeRuntime, String> {
    spawn_ble_rnode_runtime_native_observed_with_options(
        handle,
        args,
        tcp_port,
        rns_interface::rnode::RNodeStartupOptions::default(),
    )
    .await
    .map_err(|error| error.to_string())
}

/// Spawn and register a native-bridge BLE RNode with an explicit startup
/// policy. Post-return admission state is reported by the exact observer.
#[cfg(feature = "ble")]
pub async fn spawn_ble_rnode_runtime_native_observed_with_options(
    handle: &ReticulumHandle,
    args: BleRnodeRuntimeArgs<'_>,
    tcp_port: u16,
    rnode_startup_options: rns_interface::rnode::RNodeStartupOptions,
) -> Result<SpawnedRNodeRuntime, RNodeRuntimeSpawnError> {
    let spawn_permit = ensure_runtime_interface_admission(handle)
        .map_err(RNodeRuntimeSpawnError::RuntimeAdmission)?;
    let BleRnodeRuntimeArgs {
        name,
        port,
        frequency,
        bandwidth,
        spreading_factor,
        coding_rate,
        tx_power,
        mode,
        st_alock,
        lt_alock,
        flow_control,
    } = args;

    let mut config = rns_interface::ble_rnode::BleRNodeConfig::new(name, port);
    config.frequency = frequency;
    config.bandwidth = bandwidth;
    config.spreading_factor = spreading_factor;
    config.coding_rate = coding_rate;
    config.tx_power = u8::try_from(tx_power).map_err(|_| {
        RNodeRuntimeSpawnError::InvalidConfiguration(format!(
            "invalid value for '{name}.txpower': {tx_power} is below 0 dBm"
        ))
    })?;
    config.mode = mode;
    config.st_alock = st_alock;
    config.lt_alock = lt_alock;
    config.flow_control = flow_control;
    config.validate().map_err(|error| {
        RNodeRuntimeSpawnError::InvalidConfiguration(format!(
            "invalid value for '{name}.{}': {error}",
            error.field()
        ))
    })?;

    let id = handle
        .id_gen
        .fetch_add(1, std::sync::atomic::Ordering::SeqCst);

    let spawned =
        rns_interface::ble_rnode::spawn_ble_rnode_interface_native_with_driver_and_options(
            config,
            id,
            handle.transport_tx.clone(),
            tcp_port,
            rnode_startup_options,
        )
        .await
        .map_err(RNodeRuntimeSpawnError::NativeBleRNodeSpawn)?;

    let online = spawned.interface.online.clone();
    let state = spawned.driver.watch();
    register_observed_rnode_handle_with_kind_and_spawn_permit(
        &handle.transport_tx,
        spawned,
        &handle.interface_controls,
        &handle.interface_registry,
        InterfaceKind::BleRNode,
        spawn_permit,
    )
    .await
    .map_err(|error| {
        RNodeRuntimeSpawnError::Registration(format!(
            "BLE RNode native registration failed: {error}"
        ))
    })?;
    tracing::info!(name = %name, id, tcp_port, "runtime BLE RNode interface spawned (native bridge)");
    Ok(SpawnedRNodeRuntime {
        interface_id: id,
        online,
        observer: RNodeRuntimeObserver {
            interface_id: id,
            state,
        },
    })
}

/// Spawn an AutoInterface (local-network discovery) with a resolved config.
pub async fn spawn_auto_interface_runtime_with_config(
    handle: &ReticulumHandle,
    config: rns_interface::auto::AutoInterfaceConfig,
) -> Result<u64, String> {
    let spawn_permit = ensure_runtime_interface_admission(handle)?;
    let id = handle
        .id_gen
        .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let name = config.name.clone();
    let iface_handle = rns_interface::auto::spawn_auto_interface(
        config,
        id,
        handle.transport_tx.clone(),
        handle.is_foreground.clone(),
    )
    .await
    .map_err(|e| format!("Auto interface spawn failed: {e}"))?;

    register_interface_handle_with_spawn_permit(
        &handle.transport_tx,
        iface_handle,
        &handle.interface_controls,
        &handle.interface_registry,
        spawn_permit,
    )
    .await
    .map_err(|error| format!("Auto interface registration failed: {error}"))?;
    tracing::info!(name = %name, id, "runtime Auto interface spawned");
    Ok(id)
}

/// Spawns an AutoInterface with defaults (Link scope, Temporary address,
/// no NIC filter, 10 Mbps bitrate); only the four positional knobs differ.
pub async fn spawn_auto_interface_runtime(
    handle: &ReticulumHandle,
    name: &str,
    group_id: &str,
    discovery_port: u16,
    data_port: u16,
) -> Result<u64, String> {
    let config = rns_interface::auto::AutoInterfaceConfig {
        name: name.to_string(),
        group_id: group_id.to_string(),
        discovery_port,
        data_port,
        ..rns_interface::auto::AutoInterfaceConfig::default()
    };
    spawn_auto_interface_runtime_with_config(handle, config).await
}

/// `event_tx` is a process-singleton dispatcher; each call replaces the prior sender.
#[cfg(feature = "ble")]
pub async fn spawn_ble_peer_runtime(
    handle: &ReticulumHandle,
    name: &str,
    identity_hash: Vec<u8>,
    event_tx: Option<tokio::sync::mpsc::Sender<rns_interface::ble_peer::BlePeerEvent>>,
    foreground_wake: std::sync::Arc<tokio::sync::Notify>,
    seed_addresses: Vec<String>,
) -> Result<u64, String> {
    let spawn_permit = ensure_runtime_interface_admission(handle)?;
    let id = handle
        .id_gen
        .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let config = rns_interface::ble_peer::BlePeerConfig::new(name, identity_hash);

    // Install before start so initial scan/connect events aren't dropped.
    if let Some(tx) = event_tx {
        rns_interface::ble_peer::install_event_dispatcher(tx);
    }

    let iface_handle = rns_interface::ble_peer::spawn_ble_peer_interface(
        config,
        id,
        handle.transport_tx.clone(),
        handle.is_foreground.clone(),
        foreground_wake,
        seed_addresses,
    )
    .await
    .map_err(|e| {
        // Clear the dispatcher so a retry doesn't leak the orphaned channel.
        rns_interface::ble_peer::clear_event_dispatcher();
        format!("BLE Peer spawn failed: {e}")
    })?;

    // multipoint = true: BLE peers can't hear each other, so the transport must
    // relay announces back out this interface to reach its other peers.
    register_interface_handle_with_role_and_overrides_and_spawn_permit(
        &handle.transport_tx,
        iface_handle,
        rns_transport::messages::InterfaceRole::Normal,
        rns_transport::ingress::IngressOverrides::default(),
        None,
        0,
        &handle.interface_controls,
        &handle.interface_registry,
        InterfaceKind::BlePeer,
        true,
        spawn_permit,
    )
    .await
    .map_err(|error| format!("BLE Peer registration failed: {error}"))?;
    tracing::info!(name = %name, id, "runtime BLE Peer mesh interface spawned");
    Ok(id)
}

#[cfg(feature = "ble")]
pub fn teardown_ble_peer_events() {
    rns_interface::ble_peer::clear_event_dispatcher();
}

/// Stop peripheral (advertising + GATT server), clear dispatcher, deregister.
#[cfg(feature = "ble")]
pub async fn teardown_ble_peer_interface(handle: &ReticulumHandle, id: u64) {
    teardown_interface(handle, id).await;
}

/// Stop per-id reconnect loop, then deregister. Per-id (multiple BLE RNode
/// interfaces coexist, each with its own `AtomicBool`); idempotent.
#[cfg(feature = "ble")]
pub async fn teardown_ble_rnode_interface(handle: &ReticulumHandle, id: u64) {
    teardown_interface(handle, id).await;
}

/// Stop the exact serial/TCP RNode driver before generic deregistration.
#[cfg(any(feature = "serial", feature = "rnode-tcp"))]
pub async fn teardown_rnode_interface(handle: &ReticulumHandle, id: u64) {
    teardown_interface(handle, id).await;
}

#[cfg(target_os = "android")]
#[allow(clippy::too_many_arguments)]
pub async fn spawn_android_usb_rnode_runtime(
    handle: &ReticulumHandle,
    name: &str,
    device_name: &str,
    frequency: u32,
    bandwidth: u32,
    spreading_factor: u8,
    coding_rate: u8,
    tx_power: i8,
    mode: rns_interface::traits::InterfaceMode,
    st_alock: Option<f32>,
    lt_alock: Option<f32>,
    flow_control: bool,
) -> Result<u64, String> {
    let spawned = spawn_android_usb_rnode_runtime_observed(
        handle,
        name,
        device_name,
        frequency,
        bandwidth,
        spreading_factor,
        coding_rate,
        tx_power,
        mode,
        st_alock,
        lt_alock,
        flow_control,
    )
    .await?;
    Ok(spawned.interface_id)
}

/// Spawn an Android USB RNode and return an observer bound to that exact
/// registration. Successful return does not imply protocol readiness; call
/// [`RNodeRuntimeObserver::await_ready`] when readiness is required.
#[cfg(target_os = "android")]
#[allow(clippy::too_many_arguments)]
pub async fn spawn_android_usb_rnode_runtime_observed(
    handle: &ReticulumHandle,
    name: &str,
    device_name: &str,
    frequency: u32,
    bandwidth: u32,
    spreading_factor: u8,
    coding_rate: u8,
    tx_power: i8,
    mode: rns_interface::traits::InterfaceMode,
    st_alock: Option<f32>,
    lt_alock: Option<f32>,
    flow_control: bool,
) -> Result<SpawnedRNodeRuntime, String> {
    spawn_android_usb_rnode_runtime_observed_with_options(
        handle,
        name,
        device_name,
        frequency,
        bandwidth,
        spreading_factor,
        coding_rate,
        tx_power,
        mode,
        st_alock,
        lt_alock,
        flow_control,
        rns_interface::rnode::RNodeStartupOptions::default(),
    )
    .await
    .map_err(|error| error.to_string())
}

/// Spawn and register an Android USB RNode with an explicit startup policy.
#[cfg(target_os = "android")]
#[allow(clippy::too_many_arguments)]
pub async fn spawn_android_usb_rnode_runtime_observed_with_options(
    handle: &ReticulumHandle,
    name: &str,
    device_name: &str,
    frequency: u32,
    bandwidth: u32,
    spreading_factor: u8,
    coding_rate: u8,
    tx_power: i8,
    mode: rns_interface::traits::InterfaceMode,
    st_alock: Option<f32>,
    lt_alock: Option<f32>,
    flow_control: bool,
    rnode_startup_options: rns_interface::rnode::RNodeStartupOptions,
) -> Result<SpawnedRNodeRuntime, RNodeRuntimeSpawnError> {
    let spawn_permit = ensure_runtime_interface_admission(handle)
        .map_err(RNodeRuntimeSpawnError::RuntimeAdmission)?;
    let mut config = rns_interface::android_usb::AndroidUsbConfig::new(name, device_name);
    config.frequency = frequency;
    config.bandwidth = bandwidth;
    config.spreading_factor = spreading_factor;
    config.coding_rate = coding_rate;
    config.tx_power = u8::try_from(tx_power).map_err(|_| {
        RNodeRuntimeSpawnError::InvalidConfiguration(format!(
            "invalid value for '{name}.txpower': {tx_power} is below 0 dBm"
        ))
    })?;
    config.mode = mode;
    config.st_alock = st_alock;
    config.lt_alock = lt_alock;
    config.flow_control = flow_control;
    config.validate().map_err(|error| {
        RNodeRuntimeSpawnError::InvalidConfiguration(format!(
            "invalid value for '{name}.{}': {error}",
            error.field()
        ))
    })?;

    let id = handle
        .id_gen
        .fetch_add(1, std::sync::atomic::Ordering::SeqCst);

    let spawned =
        rns_interface::android_usb::spawn_android_usb_rnode_interface_with_driver_and_options(
            config,
            id,
            handle.transport_tx.clone(),
            rnode_startup_options,
        )
        .await
        .map_err(RNodeRuntimeSpawnError::AndroidUsbSpawn)?;

    let online = spawned.interface.online.clone();
    let state = spawned.driver.watch();
    register_observed_rnode_handle_with_kind_and_spawn_permit(
        &handle.transport_tx,
        spawned,
        &handle.interface_controls,
        &handle.interface_registry,
        InterfaceKind::AndroidUsbRNode,
        spawn_permit,
    )
    .await
    .map_err(|error| {
        RNodeRuntimeSpawnError::Registration(format!("Android USB registration failed: {error}"))
    })?;
    tracing::info!(name = %name, id, "runtime Android USB RNode interface spawned");
    Ok(SpawnedRNodeRuntime {
        interface_id: id,
        online,
        observer: RNodeRuntimeObserver {
            interface_id: id,
            state,
        },
    })
}

#[cfg(target_os = "android")]
pub async fn teardown_android_usb_rnode_interface(handle: &ReticulumHandle, id: u64) {
    teardown_interface(handle, id).await;
}

pub async fn teardown_interface(handle: &ReticulumHandle, id: u64) {
    let transport_tx = handle.transport_tx.clone();
    let interface_controls = handle.interface_controls.clone();
    let interface_registry = handle.interface_registry.clone();
    let (done_tx, done_rx) = oneshot::channel();
    tokio::spawn(async move {
        teardown_interface_transaction(&transport_tx, &interface_controls, &interface_registry, id)
            .await;
        let _ = done_tx.send(());
    });
    let _ = done_rx.await;
}

async fn cleanup_committed_interfaces(
    transport_tx: &mpsc::Sender<TransportMessage>,
    interface_controls: &InterfaceControlMap,
    interface_registry: &InterfaceRegistry,
    tokens: Vec<CommittedInterfaceToken>,
) {
    for token in tokens {
        teardown_interface_exact_transaction(
            transport_tx,
            interface_controls,
            interface_registry,
            token,
        )
        .await;
    }
}

async fn teardown_interface_exact_transaction(
    transport_tx: &mpsc::Sender<TransportMessage>,
    interface_controls: &InterfaceControlMap,
    interface_registry: &InterfaceRegistry,
    token: CommittedInterfaceToken,
) {
    let shutdown = match interface_registry.begin_shutdown_exact(token.id, token.registry_owner) {
        ExactShutdownStart::Acquired(shutdown) => shutdown,
        ExactShutdownStart::AlreadyStopping => {
            interface_registry
                .wait_until_not_owner(token.id, token.registry_owner)
                .await;
            return;
        }
        ExactShutdownStart::NotOwned => return,
    };
    finish_interface_shutdown(transport_tx, interface_controls, token.id, shutdown).await;
}

async fn teardown_interface_transaction(
    transport_tx: &mpsc::Sender<TransportMessage>,
    interface_controls: &InterfaceControlMap,
    interface_registry: &InterfaceRegistry,
    id: u64,
) {
    let shutdown = match interface_registry.begin_shutdown(id) {
        ShutdownStart::Acquired(shutdown) => shutdown,
        ShutdownStart::RegistrationPending { owner } => {
            tracing::debug!(
                id,
                "interface registration is pending; waiting for cancellation rollback"
            );
            interface_registry.wait_until_not_owner(id, owner).await;
            return;
        }
        ShutdownStart::AlreadyStopping { owner } => {
            tracing::debug!(id, "interface teardown is in progress; waiting");
            interface_registry.wait_until_not_owner(id, owner).await;
            return;
        }
        ShutdownStart::RegistryDraining => {
            tracing::debug!(id, "runtime drain already owns interface teardown");
            return;
        }
    };
    finish_interface_shutdown(transport_tx, interface_controls, id, shutdown).await;
}

async fn finish_interface_shutdown(
    transport_tx: &mpsc::Sender<TransportMessage>,
    interface_controls: &InterfaceControlMap,
    id: u64,
    mut shutdown: InterfaceShutdown,
) {
    tracing::debug!(id, kind = ?shutdown.kind(), "stopping owned interface");
    shutdown.mark_offline();
    match shutdown.strategy() {
        InterfaceShutdownStrategy::Abort => {}
        #[cfg(any(
            feature = "serial",
            feature = "rnode-tcp",
            feature = "ble",
            target_os = "android"
        ))]
        InterfaceShutdownStrategy::ExactRNodeDriver => {}
        #[cfg(feature = "ble")]
        InterfaceShutdownStrategy::StopBlePeer => {
            rns_interface::ble_peer::stop_ble_peer_interface().await;
        }
    }

    // Exact RNode ownership is retained in the registry. Request its local
    // shutdown primitive and join that exact task before deregistering;
    // same-ID compatibility lookups cannot redirect teardown.
    shutdown.stop_task_and_wait().await;
    if let Some(control_owner) = shutdown.control_owner() {
        remove_interface_control_if_owner(interface_controls, id, control_owner);
    } else {
        // An orphan tombstone cannot share the stale control's owner token.
        // The tombstone blocks replacement until this deregistration is
        // ordered, so unconditional removal is safe in this branch.
        interface_controls
            .lock()
            .expect("interface_controls mutex poisoned")
            .remove(&id);
    }
    let deregistered = transport_tx
        .send(TransportMessage::DeregisterInterface { id })
        .await
        .is_ok();
    if deregistered {
        shutdown.finish();
        tracing::info!(id, "interface deregistered");
    } else {
        tracing::warn!(
            id,
            "transport closed before interface deregistration; retaining ID tombstone"
        );
    }
}

#[allow(clippy::too_many_arguments)]
async fn spawn_interface_with_rnode_startup_options(
    iface_config: &interface_factory::InterfaceConfig,
    id: u64,
    transport_tx: mpsc::Sender<TransportMessage>,
    id_gen: Arc<AtomicU64>,
    handle_tx: mpsc::Sender<rns_interface::traits::InterfaceHandle>,
    socket_base: &Path,
    is_foreground: Arc<AtomicBool>,
    rnode_startup_options: rns_interface::rnode::RNodeStartupOptions,
) -> Result<Vec<OwnedInterfaceHandle>, String> {
    #[cfg(not(any(feature = "serial", feature = "rnode-tcp", feature = "ble")))]
    let _ = rnode_startup_options;

    match iface_config {
        interface_factory::InterfaceConfig::TcpClient(c) => {
            rns_interface::tcp::spawn_tcp_client(c.clone(), id, transport_tx)
                .await
                .map(|h| vec![h.into()])
                .map_err(|e| format!("TCP client: {e}"))
        }
        interface_factory::InterfaceConfig::TcpServer(c) => {
            rns_interface::tcp::spawn_tcp_server(c.clone(), id, id_gen, transport_tx, handle_tx)
                .await
                .map(|h| vec![h.into()])
                .map_err(|e| format!("TCP server: {e}"))
        }
        interface_factory::InterfaceConfig::Udp(c) => {
            rns_interface::udp::spawn_udp_interface(c.clone(), id, transport_tx)
                .await
                .map(|h| vec![h.into()])
                .map_err(|e| format!("UDP: {e}"))
        }
        #[cfg(feature = "serial")]
        interface_factory::InterfaceConfig::Serial(c) => {
            let mut serial_config = rns_interface::serial::SerialConfig::new(&c.name, &c.port);
            serial_config.baud_rate = c.baud_rate;
            serial_config.mode = c.mode;
            let (data, parity, stop) =
                rns_interface::serial::serial_params_from(c.data_bits, &c.parity, c.stop_bits);
            serial_config.data_bits = data;
            serial_config.parity = parity;
            serial_config.stop_bits = stop;
            rns_interface::serial::spawn_serial_interface(serial_config, id, transport_tx)
                .await
                .map(|h| vec![h.into()])
                .map_err(|e| format!("Serial: {e}"))
        }
        #[cfg(feature = "serial")]
        interface_factory::InterfaceConfig::KissSerial(c) => {
            let mut kiss_config =
                rns_interface::kiss_iface::KissInterfaceConfig::new(&c.name, &c.port, c.baud_rate);
            kiss_config.mode = c.mode;
            let (data, parity, stop) =
                rns_interface::serial::serial_params_from(c.data_bits, &c.parity, c.stop_bits);
            kiss_config.data_bits = data;
            kiss_config.parity = parity;
            kiss_config.stop_bits = stop;
            // Wire units are 10 ms steps for the timing commands; persistence
            // is the raw 0-255 CSMA p-value (Python setPreamble etc.).
            let to_wire = |ms: u32| ((ms / 10).min(255)) as u8;
            kiss_config.txdelay = Some(to_wire(c.preamble_ms));
            kiss_config.txtail = Some(to_wire(c.txtail_ms));
            kiss_config.slottime = Some(to_wire(c.slottime_ms));
            kiss_config.persistence = Some(c.persistence);
            kiss_config.flow_control = c.flow_control;
            kiss_config.id_interval = c.id_interval;
            kiss_config.id_callsign = c.id_callsign.as_ref().map(|s| s.as_bytes().to_vec());
            rns_interface::kiss_iface::spawn_kiss_interface(kiss_config, id, transport_tx)
                .await
                .map(|h| vec![h.into()])
                .map_err(|e| format!("KISS: {e}"))
        }
        interface_factory::InterfaceConfig::Auto(c) => {
            let auto_config = rns_interface::auto::AutoInterfaceConfig {
                name: c.name.clone(),
                group_id: c.group_id.clone(),
                discovery_scope: c.discovery_scope,
                discovery_port: c.discovery_port,
                data_port: c.data_port,
                multicast_address_type: c.multicast_address_type,
                devices: c.devices.clone(),
                ignored_devices: c.ignored_devices.clone(),
                configured_bitrate: c.configured_bitrate,
                mode: c.mode,
            };
            rns_interface::auto::spawn_auto_interface(auto_config, id, transport_tx, is_foreground)
                .await
                .map(|h| vec![h.into()])
                .map_err(|e| format!("Auto: {e}"))
        }
        #[cfg(any(feature = "serial", feature = "rnode-tcp"))]
        interface_factory::InterfaceConfig::RNode(c) => {
            let rnode_config = c
                .to_rnode_config()
                .map_err(|error| format!("RNode: {error}"))?;
            rns_interface::rnode::spawn_rnode_interface_with_driver_and_options(
                rnode_config,
                id,
                transport_tx,
                rnode_startup_options,
            )
            .await
            .map(|spawned| vec![spawned.into()])
            .map_err(|e| format!("RNode: {e}"))
        }
        interface_factory::InterfaceConfig::Local(c) => {
            let local_config = rns_interface::local::LocalClientConfig {
                socket_path: socket_base
                    .join(format!("reticulum_rs_{}.sock", c.name))
                    .to_string_lossy()
                    .to_string(),
                name: c.name.clone(),
            };
            rns_interface::local::spawn_local_client(local_config, id, transport_tx)
                .await
                .map(|h| vec![h.into()])
                .map_err(|e| format!("Local: {e}"))
        }
        interface_factory::InterfaceConfig::I2P(c) => {
            if c.connectable {
                let mut server_config = rns_interface::i2p::I2PServerConfig::new(&c.name);
                server_config.sam_host = c.i2p_sam_host.clone();
                server_config.sam_port = c.i2p_sam_port;
                server_config.mode = c.mode;
                rns_interface::i2p::spawn_i2p_server(server_config, id_gen, transport_tx, handle_tx)
                    .await
                    .map(|h| vec![h.into()])
                    .map_err(|e| format!("I2P server: {e}"))
            } else if let Some(peer) = c.peers.first() {
                let mut client_config = rns_interface::i2p::I2PClientConfig::new(&c.name, peer);
                client_config.sam_host = c.i2p_sam_host.clone();
                client_config.sam_port = c.i2p_sam_port;
                client_config.mode = c.mode;
                rns_interface::i2p::spawn_i2p_client(client_config, id, transport_tx)
                    .await
                    .map(|h| vec![h.into()])
                    .map_err(|e| format!("I2P client: {e}"))
            } else {
                Err(format!(
                    "I2PInterface '{}': requires 'connectable' or 'peers'",
                    c.name
                ))
            }
        }
        interface_factory::InterfaceConfig::Pipe(c) => {
            let pipe_config = rns_interface::pipe::PipeInterfaceConfig {
                name: c.name.clone(),
                command: c.command.clone(),
                respawn_delay: c.respawn_delay as f64,
                mode: c.mode,
            };
            rns_interface::pipe::spawn_pipe_interface(pipe_config, id, transport_tx)
                .await
                .map(|h| vec![h.into()])
                .map_err(|e| format!("Pipe: {e}"))
        }
        #[cfg(feature = "serial")]
        interface_factory::InterfaceConfig::RNodeMulti(c) => {
            let mut multi_config =
                rns_interface::rnode_multi::RNodeMultiConfig::new(&c.name, &c.port);
            multi_config.baud_rate = c.baud_rate;
            multi_config.flow_control = c.flow_control;
            multi_config.id_interval = c.id_interval;
            multi_config.id_callsign = c.id_callsign.as_ref().map(|s| s.as_bytes().to_vec());
            for sub in &c.subinterfaces {
                let mut sub_config = rns_interface::rnode_multi::SubInterfaceConfig::new(
                    &sub.name,
                    sub.vport,
                    sub.frequency,
                );
                sub_config.bandwidth = sub.bandwidth;
                sub_config.spreading_factor = sub.spreading_factor;
                sub_config.coding_rate = sub.coding_rate;
                sub_config.tx_power = sub.tx_power;
                sub_config.mode = sub.mode;
                sub_config.flow_control = sub.flow_control;
                sub_config.outgoing = sub.outgoing;
                sub_config.st_alock = sub.st_alock;
                sub_config.lt_alock = sub.lt_alock;
                multi_config.subinterfaces.push(sub_config);
            }
            if multi_config.subinterfaces.is_empty() {
                return Err(format!(
                    "RNodeMultiInterface '{}': no sub-interfaces configured",
                    c.name
                ));
            }
            let mut sub_ids = Vec::with_capacity(multi_config.subinterfaces.len());
            sub_ids.push(id);
            for _ in 1..multi_config.subinterfaces.len() {
                sub_ids.push(id_gen.fetch_add(1, std::sync::atomic::Ordering::SeqCst));
            }
            rns_interface::rnode_multi::spawn_rnode_multi_interface(
                multi_config,
                &sub_ids,
                transport_tx,
            )
            .await
            .map(|handles| handles.into_iter().map(Into::into).collect())
            .map_err(|e| format!("RNodeMulti: {e}"))
        }
        #[cfg(feature = "serial")]
        interface_factory::InterfaceConfig::AX25KISS(c) => {
            let ax25_config =
                rns_interface::ax25kiss::AX25KISSConfig::new(&c.name, &c.port, &c.callsign, c.ssid);
            let mut ax25_config = ax25_config;
            ax25_config.baud_rate = c.baud_rate;
            ax25_config.data_bits = c.data_bits;
            ax25_config.parity = c.parity.clone();
            ax25_config.stop_bits = c.stop_bits;
            ax25_config.preamble = c.preamble as u16;
            ax25_config.txtail = c.txtail as u16;
            ax25_config.persistence = c.persistence as u8;
            ax25_config.slottime = c.slottime as u16;
            ax25_config.flow_control = c.flow_control;
            ax25_config.mode = c.mode;
            rns_interface::ax25kiss::spawn_ax25kiss_interface(ax25_config, id, transport_tx)
                .await
                .map(|h| vec![h.into()])
                .map_err(|e| format!("AX25KISS: {e}"))
        }
        #[cfg(feature = "ble")]
        interface_factory::InterfaceConfig::BleRNode(c) => {
            let mut config = rns_interface::ble_rnode::BleRNodeConfig::new(&c.name, &c.port);
            config.frequency = c.frequency;
            config.bandwidth = c.bandwidth;
            config.spreading_factor = c.spreading_factor;
            config.coding_rate = c.coding_rate;
            config.tx_power = c.tx_power as u8;
            config.mode = c.mode;
            config.flow_control = c.flow_control;
            config.st_alock = c.st_alock;
            config.lt_alock = c.lt_alock;
            config.id_interval = c.id_interval;
            config.id_callsign = c.id_callsign.as_ref().map(|s| s.as_bytes().to_vec());
            rns_interface::ble_rnode::spawn_ble_rnode_interface_with_driver_and_options(
                config,
                id,
                transport_tx,
                rnode_startup_options,
            )
            .await
            .map(|spawned| vec![spawned.into()])
            .map_err(|e| format!("BLE RNode: {e}"))
        }
        interface_factory::InterfaceConfig::Backbone(c) => {
            // `target_host` selects client mode; otherwise listen.
            if let Some(host) = c.target_host.as_deref() {
                let mut config =
                    rns_interface::backbone::BackboneClientConfig::new(&c.name, host, c.port);
                config.mode = c.mode;
                config.prefer_ipv6 = c.prefer_ipv6;
                config.connect_timeout_secs = c.connect_timeout;
                config.max_reconnect_tries = c.max_reconnect_tries;
                rns_interface::backbone::spawn_backbone_client(config, id, transport_tx)
                    .await
                    .map(|h| vec![h.into()])
                    .map_err(|e| format!("Backbone client: {e}"))
            } else {
                let listen_ip = c.listen_on.as_deref().unwrap_or("0.0.0.0");
                let mut config =
                    rns_interface::backbone::BackboneServerConfig::new(&c.name, listen_ip, c.port);
                config.mode = c.mode;
                config.prefer_ipv6 = c.prefer_ipv6;
                config.device = c.device.clone();
                config.block_fast_flapping = c.block_fast_flapping;
                config.fast_flapping_threshold = c.fast_flapping_threshold;
                config.fast_flapping_grace = c.fast_flapping_grace;
                config.fast_flapping_block_time = c.fast_flapping_block_time;
                rns_interface::backbone::spawn_backbone_server(
                    config,
                    id,
                    id_gen,
                    transport_tx,
                    handle_tx,
                )
                .await
                .map(|h| vec![h.into()])
                .map_err(|e| format!("Backbone server: {e}"))
            }
        }
    }
}

pub fn get_instance() -> Option<&'static ReticulumHandle> {
    INSTANCE.get()
}

fn load_or_create_config(path: &Path) -> Result<(Config, bool), ReticulumError> {
    if path.exists() {
        Config::from_file(path)
            .map(|config| (config, false))
            .map_err(ReticulumError::Config)
    } else {
        Config::write_default(path).map_err(ReticulumError::Config)?;
        Config::parse(Config::default_config())
            .map(|config| (config, true))
            .map_err(ReticulumError::Config)
    }
}

fn load_or_create_network_identity(path: &Path) -> Result<Arc<Identity>, ReticulumError> {
    let identity = if path.is_file() {
        Identity::from_file(path).map_err(|e| {
            ReticulumError::Config(ConfigError::InvalidValue {
                section: "reticulum".to_string(),
                key: "network_identity".to_string(),
                message: format!("could not load {}: {e}", path.display()),
            })
        })?
    } else {
        let identity = Identity::new();
        identity.to_file(path).map_err(|e| {
            ReticulumError::Config(ConfigError::InvalidValue {
                section: "reticulum".to_string(),
                key: "network_identity".to_string(),
                message: format!("could not generate {}: {e}", path.display()),
            })
        })?;
        identity
    };

    Ok(Arc::new(identity))
}

fn synthesize_interfaces(
    config: &Config,
    panic_on_interface_error: bool,
) -> Result<Vec<interface_factory::InterfaceConfig>, ReticulumError> {
    let mut interfaces = Vec::new();

    for (name, section) in config.subsections("interfaces") {
        match interface_factory::synthesize_interface(name, section) {
            Ok(iface) => {
                tracing::info!("configured interface: {name}");
                interfaces.push(iface);
            }
            Err(interface_factory::InterfaceFactoryError::Disabled(_)) => {
                tracing::debug!("interface {name} is disabled");
            }
            Err(e) => {
                if panic_on_interface_error {
                    return Err(ReticulumError::Interface(format!(
                        "failed to synthesize interface {name}: {e}"
                    )));
                } else {
                    tracing::warn!("failed to synthesize interface {name}: {e}");
                }
            }
        }
    }

    Ok(interfaces)
}

async fn run_jobs(
    persistence_trigger: rns_transport::actor::PersistenceTrigger,
    cache_dir: PathBuf,
    resource_dir: PathBuf,
    shutdown: ShutdownSignal,
) {
    let mut scheduler = JobScheduler::new();
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(JOB_INTERVAL));

    loop {
        tokio::select! {
            _ = interval.tick() => {
                let jobs = scheduler.tick();
                for job in jobs {
                    match job {
                        Job::CleanCache => {
                            tracing::debug!("running cache cleanup");
                            clean_cache_dir(
                                &resource_dir,
                                std::time::Duration::from_secs(RESOURCE_CACHE),
                            );
                            clean_cache_dir(
                                &cache_dir,
                                std::time::Duration::from_secs(DESTINATION_TIMEOUT),
                            );
                        }
                        Job::PersistData => {
                            tracing::debug!("persisting data");
                            let _ = persistence_trigger.request().await;
                        }
                    }
                }
            }
            _ = shutdown.wait() => {
                tracing::info!("background jobs shutting down");
                break;
            }
        }
    }
}

fn clean_cache_dir(cache_dir: &Path, ttl: std::time::Duration) {
    clean_cache_dir_at(cache_dir, ttl, std::time::SystemTime::now());
}

fn clean_cache_dir_at(cache_dir: &Path, ttl: std::time::Duration, now: std::time::SystemTime) {
    if let Ok(entries) = std::fs::read_dir(cache_dir) {
        for entry in entries.flatten() {
            let file_name = entry.file_name();
            if file_name.as_encoded_bytes().len() != 32 {
                continue;
            }
            if let Ok(metadata) = entry.metadata() {
                if metadata.is_file() {
                    if let Ok(modified) = metadata.modified() {
                        if let Ok(age) = now.duration_since(modified) {
                            if age > ttl {
                                let path = entry.path();
                                if std::fs::remove_file(&path).is_ok() {
                                    tracing::trace!("cleaned cache entry: {}", path.display());
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

#[derive(Debug, thiserror::Error)]
pub enum ReticulumError {
    #[error("config error: {0}")]
    Config(#[from] ConfigError),
    #[error("I/O error: {0}")]
    Io(std::io::Error),
    #[error("already initialized")]
    AlreadyInitialized,
    #[error("no existing shared instance is available")]
    RequiredSharedInstanceUnavailable,
    #[error("transport error: {0}")]
    Transport(String),
    #[error("interface error: {0}")]
    Interface(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn wait_for_registry_len(registry: &InterfaceRegistry, expected: usize) {
        tokio::time::timeout(Duration::from_secs(2), async {
            while registry.len() != expected {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap_or_else(|_| {
            panic!(
                "registry did not reach length {expected}; current length {}",
                registry.len()
            )
        });
    }

    #[tokio::test(start_paused = true)]
    async fn rnode_readiness_deadline_wins_a_tied_publication() {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
        let publication = async {
            tokio::time::sleep_until(deadline).await;
            "late-ready"
        };
        assert_eq!(
            await_before_rnode_deadline(Some(deadline), publication).await,
            None
        );
    }

    #[tokio::test]
    async fn runtime_shutdown_is_single_cancellation_independent_and_persistence_ordered() {
        struct TaskDrop(Arc<AtomicBool>);
        impl Drop for TaskDrop {
            fn drop(&mut self) {
                self.0.store(true, Ordering::Release);
            }
        }

        let (transport_tx, mut transport_rx) = mpsc::channel::<TransportMessage>(8);
        let completion = Arc::new(TransportCompletion::default());
        let shutdown = ShutdownSignal::new();
        let controls: InterfaceControlMap = Arc::new(std::sync::Mutex::new(HashMap::new()));
        let registry = InterfaceRegistry::default();
        let coordinator = RuntimeShutdownCoordinator::new(
            shutdown.clone(),
            transport_tx,
            completion.clone(),
            controls.clone(),
            registry.clone(),
        );

        let id = 930_001;
        let online = Arc::new(AtomicBool::new(true));
        let task_stopped = Arc::new(AtomicBool::new(false));
        let (task_started_tx, task_started_rx) = oneshot::channel();
        let task_stopped_in_task = task_stopped.clone();
        let task = tokio::spawn(async move {
            let _drop = TaskDrop(task_stopped_in_task);
            let _ = task_started_tx.send(());
            std::future::pending::<()>().await;
        });
        task_started_rx.await.expect("interface task started");
        let registration = registry
            .reserve_with_online(
                id,
                InterfaceKind::Standard,
                task,
                None,
                Some(online.clone()),
            )
            .expect("reserve interface");
        let owner = registration.owner();
        assert!(registration.commit().is_ok());
        controls.lock().unwrap().insert(
            id,
            InterfaceControlMetadata {
                registry_owner: owner,
                role: rns_transport::messages::InterfaceRole::Normal,
                ingress_overrides: rns_transport::ingress::IngressOverrides::default(),
                ifac_key: None,
                ifac_size: 0,
            },
        );

        let (shutdown_seen_tx, shutdown_seen_rx) = oneshot::channel();
        let (persist_release_tx, persist_release_rx) = oneshot::channel();
        let actor_completion = completion.clone();
        let actor_online = online.clone();
        let actor_task_stopped = task_stopped.clone();
        let actor_controls = controls.clone();
        let actor = tokio::spawn(async move {
            let mut shutdown_count = 0usize;
            let mut saw_deregister = false;
            while let Some(message) = transport_rx.recv().await {
                match message {
                    TransportMessage::Shutdown => {
                        shutdown_count += 1;
                        assert!(!actor_online.load(Ordering::SeqCst));
                        assert!(actor_task_stopped.load(Ordering::Acquire));
                        assert!(
                            actor_controls.lock().unwrap().contains_key(&id),
                            "controls remain through the persistence boundary"
                        );
                        let _ = shutdown_seen_tx.send(());
                        let _ = persist_release_rx.await;
                        actor_completion.mark_stopped();
                        break;
                    }
                    TransportMessage::DeregisterInterface { .. } => saw_deregister = true,
                    _ => {}
                }
            }
            (shutdown_count, saw_deregister)
        });

        let first_coordinator = coordinator.clone();
        let first = tokio::spawn(async move {
            first_coordinator.start_and_wait().await;
        });
        shutdown_seen_rx.await.expect("actor received shutdown");
        first.abort();
        let _ = first.await;

        let second_coordinator = coordinator.clone();
        let second = tokio::spawn(async move {
            second_coordinator.start_and_wait().await;
        });
        let third_coordinator = coordinator.clone();
        let third = tokio::spawn(async move {
            third_coordinator.start_and_wait().await;
        });
        persist_release_tx.send(()).expect("release persistence");
        tokio::time::timeout(Duration::from_secs(1), async {
            second.await.unwrap();
            third.await.unwrap();
        })
        .await
        .expect("remaining shutdown callers complete");

        let (shutdown_count, saw_deregister) = actor.await.unwrap();
        assert_eq!(shutdown_count, 1);
        assert!(!saw_deregister, "global drain must preserve actor bindings");
        assert!(controls.lock().unwrap().is_empty());
        assert_eq!(
            registry.admission_for_test(),
            crate::interface_registry::RegistryAdmission::Closed
        );
        assert!(shutdown.is_triggered());
    }

    #[tokio::test]
    async fn transport_actor_panic_guard_completes_and_triggers_runtime_drain() {
        let (transport_tx, mut transport_rx) = mpsc::channel::<TransportMessage>(2);
        let completion = Arc::new(TransportCompletion::default());
        let shutdown = ShutdownSignal::new();
        let controls: InterfaceControlMap = Arc::new(std::sync::Mutex::new(HashMap::new()));
        let registry = InterfaceRegistry::default();
        let coordinator = RuntimeShutdownCoordinator::new(
            shutdown.clone(),
            transport_tx,
            completion.clone(),
            controls,
            registry.clone(),
        );
        let guard = TransportActorCompletionGuard {
            completion: completion.clone(),
            coordinator: coordinator.clone(),
        };
        let actor = tokio::spawn(async move {
            let _guard = guard;
            panic!("deterministic actor panic");
        });
        assert!(actor.await.is_err());

        tokio::time::timeout(Duration::from_secs(1), coordinator.wait())
            .await
            .expect("panic-triggered coordinator completed");
        completion.wait().await;
        assert!(shutdown.is_triggered());
        assert_eq!(
            registry.admission_for_test(),
            crate::interface_registry::RegistryAdmission::Closed
        );
        assert!(
            transport_rx.try_recv().is_err(),
            "already-stopped actor must not receive a redundant Shutdown"
        );
    }

    #[tokio::test]
    async fn actor_closed_pending_registration_cannot_strand_runtime_drain() {
        let (transport_tx, transport_rx) = mpsc::channel::<TransportMessage>(1);
        drop(transport_rx);
        let completion = Arc::new(TransportCompletion::default());
        completion.mark_stopped();
        let shutdown = ShutdownSignal::new();
        let controls: InterfaceControlMap = Arc::new(std::sync::Mutex::new(HashMap::new()));
        let registry = InterfaceRegistry::default();
        let coordinator = RuntimeShutdownCoordinator::new(
            shutdown,
            transport_tx,
            completion,
            controls.clone(),
            registry.clone(),
        );

        let id = 930_002;
        let registration = registry
            .reserve(
                id,
                InterfaceKind::Standard,
                tokio::spawn(std::future::pending()),
                None,
            )
            .expect("pending reservation");
        let owner = registration.owner();
        controls.lock().unwrap().insert(
            id,
            InterfaceControlMetadata {
                registry_owner: owner,
                role: rns_transport::messages::InterfaceRole::Normal,
                ingress_overrides: rns_transport::ingress::IngressOverrides::default(),
                ifac_key: None,
                ifac_size: 0,
            },
        );
        drop(registration);

        tokio::time::timeout(Duration::from_secs(1), coordinator.start_and_wait())
            .await
            .expect("closed-actor Pending cleanup must not strand drain");
        assert!(controls.lock().unwrap().is_empty());
        assert_eq!(registry.len(), 0);
        assert_eq!(
            registry.admission_for_test(),
            crate::interface_registry::RegistryAdmission::Closed
        );
    }

    #[tokio::test]
    async fn announce_subscription_close_is_exact_and_idempotent() {
        let (actor, transport_tx) = rns_transport::actor::TransportActor::new();
        let actor_task = tokio::spawn(actor.run());
        let (callback_tx, events) = mpsc::channel(1);
        let dropped_events = Arc::new(AtomicU64::new(0));
        let (result_tx, result_rx) = tokio::sync::oneshot::channel();
        transport_tx
            .send(TransportMessage::RegisterAnnounceSubscription {
                aspect_filter: Some("test.subscription".into()),
                receive_path_responses: false,
                callback_tx,
                dropped_events: Arc::clone(&dropped_events),
                result_tx,
            })
            .await
            .unwrap();
        let id = result_rx.await.unwrap();
        let mut subscription = AnnounceSubscription {
            id: Some(id),
            events,
            dropped_events,
            transport_tx: transport_tx.clone(),
        };

        assert!(subscription.close().await.unwrap());
        assert!(!subscription.close().await.unwrap());
        transport_tx.send(TransportMessage::Shutdown).await.unwrap();
        actor_task.await.unwrap();
        assert!(subscription.recv().await.is_none());
    }

    fn make_plain_data_packet(dest_hash: [u8; 16], body: &[u8]) -> bytes::Bytes {
        let flags = rns_wire::flags::PacketFlags {
            header_type: rns_wire::flags::HeaderType::Header1,
            context_flag: false,
            transport_type: rns_wire::flags::TransportType::Broadcast,
            destination_type: rns_wire::flags::DestinationType::Plain,
            packet_type: rns_wire::flags::PacketType::Data,
        };
        let header = rns_wire::header::PacketHeader {
            flags,
            hops: 0,
            transport_id: None,
            destination_hash: dest_hash,
            context: rns_wire::context::PacketContext::None,
        };
        let mut raw = header.pack();
        raw.extend_from_slice(body);
        bytes::Bytes::from(raw)
    }

    #[test]
    fn runtime_ifac_post_init_ignores_blank_fields() {
        let post_init = runtime_ifac_post_init(
            Some(RuntimeInterfaceIfacConfig {
                network_name: Some(String::new()),
                passphrase: Some(String::new()),
                ifac_size: None,
            }),
            16,
        )
        .unwrap();

        assert!(post_init.is_none());
    }

    #[test]
    fn runtime_ifac_post_init_uses_tcp_default_size() {
        let post_init = runtime_ifac_post_init(
            Some(RuntimeInterfaceIfacConfig {
                network_name: Some("testnet".to_string()),
                passphrase: Some("secret".to_string()),
                ifac_size: None,
            }),
            16,
        )
        .unwrap()
        .unwrap();

        assert_eq!(post_init.ifac_network_name.as_deref(), Some("testnet"));
        assert_eq!(post_init.ifac_passphrase.as_deref(), Some("secret"));
        assert_eq!(post_init.ifac_size, None);
        assert_eq!(post_init.default_ifac_size, 16);
    }

    #[test]
    fn runtime_ifac_post_init_rejects_invalid_size() {
        let result = runtime_ifac_post_init(
            Some(RuntimeInterfaceIfacConfig {
                network_name: Some("testnet".to_string()),
                passphrase: None,
                ifac_size: Some(0),
            }),
            16,
        );

        match result {
            Ok(_) => panic!("expected invalid IFAC size to be rejected"),
            Err(err) => assert!(err.contains("Invalid IFAC size")),
        }
    }

    #[tokio::test]
    async fn shared_peer_monitor_emits_connection_lifecycle_events() {
        let (tx, mut rx) = mpsc::channel(4);
        let online = Arc::new(AtomicBool::new(false));
        let shutdown = ShutdownSignal::new();

        spawn_shared_peer_monitor(tx, 7, online.clone(), shutdown.clone());
        tokio::time::sleep(std::time::Duration::from_millis(120)).await;
        assert!(
            rx.try_recv().is_err(),
            "offline initial state should not emit a lost event"
        );

        online.store(true, std::sync::atomic::Ordering::SeqCst);
        let restored = tokio::time::timeout(std::time::Duration::from_millis(300), rx.recv())
            .await
            .expect("restored event timed out")
            .expect("monitor channel closed");
        match restored {
            TransportMessage::SharedConnectionRestored { interface_id } => {
                assert_eq!(interface_id, 7)
            }
            other => panic!("expected SharedConnectionRestored, got {other:?}"),
        }

        online.store(false, std::sync::atomic::Ordering::SeqCst);
        let lost = tokio::time::timeout(std::time::Duration::from_millis(300), rx.recv())
            .await
            .expect("lost event timed out")
            .expect("monitor channel closed");
        match lost {
            TransportMessage::SharedConnectionLost => {}
            other => panic!("expected SharedConnectionLost, got {other:?}"),
        }

        shutdown.trigger();
    }

    fn write_stale_python_destination_table(storage_dir: &Path, entries: usize) {
        std::fs::create_dir_all(storage_dir).unwrap();

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs_f64();
        let mut table = rns_transport::path_table::PathTable::new();
        for i in 0..entries {
            let mut dest = [0u8; 16];
            dest[..8].copy_from_slice(&(i as u64).to_be_bytes());
            dest[8..].copy_from_slice(&(!i as u64).to_be_bytes());

            let mut packet_hash = [0u8; 32];
            packet_hash[..8].copy_from_slice(&(i as u64).to_be_bytes());
            packet_hash[8..16].copy_from_slice(&(entries as u64).to_be_bytes());
            packet_hash[16..24].copy_from_slice(&(0xA5A5_A5A5_A5A5_A5A5u64).to_be_bytes());
            packet_hash[24..].copy_from_slice(&(!i as u64).to_be_bytes());

            let mut entry = rns_transport::path_table::PathEntry::new(
                None,
                1,
                7,
                rns_transport::constants::InterfaceMode::Gateway,
            );
            entry.timestamp = now;
            entry.expires = now + 3600.0;
            entry.packet_hash = Some(packet_hash);
            table.insert(dest, entry);
        }

        let mut names = std::collections::HashMap::new();
        names.insert(7u64, "Border_TCP".to_string());
        rns_transport::persistence::save_python_destination_table(
            &table,
            &names,
            &storage_dir.join("destination_table"),
        )
        .unwrap();
    }

    async fn free_tcp_port_pair() -> (u16, u16) {
        let first = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let second = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let first_port = first.local_addr().unwrap().port();
        let second_port = second.local_addr().unwrap().port();
        (first_port, second_port)
    }

    fn test_interface_handle(
        id: u64,
        parent_id: Option<u64>,
        name: &str,
    ) -> rns_interface::traits::InterfaceHandle {
        let (tx, _rx) = mpsc::channel(4);
        rns_interface::traits::InterfaceHandle {
            id,
            parent_id,
            name: name.to_string(),
            mode: rns_interface::traits::InterfaceMode::Gateway,
            direction: rns_interface::traits::InterfaceDirection {
                inbound: true,
                outbound: true,
                forward: false,
                repeat: false,
            },
            bitrate: 115_200,
            mtu: 500,
            online: Arc::new(AtomicBool::new(true)),
            rxb: None,
            txb: None,
            inspection: None,
            tx,
            read_task: tokio::spawn(async {}),
        }
    }

    #[tokio::test]
    async fn rnode_runtime_lookup_is_local_and_classifies_missing_and_non_rnode_records() {
        let id = 920_198;
        let mut client = dummy_handle();
        client.instance_mode = InstanceMode::Client;
        assert!(matches!(
            client.rnode_runtime(id),
            Err(RNodeRuntimeLookupError::NotOwned {
                interface_id
            }) if interface_id == id
        ));

        let runtime = dummy_handle();
        assert!(matches!(
            runtime.rnode_runtime(id),
            Err(RNodeRuntimeLookupError::NotFound {
                interface_id
            }) if interface_id == id
        ));

        let registration = runtime
            .interface_registry
            .reserve(
                id,
                InterfaceKind::Standard,
                tokio::spawn(std::future::pending()),
                None,
            )
            .expect("reserve standard interface");
        assert!(registration.commit().is_ok(), "commit standard interface");
        assert!(matches!(
            runtime.rnode_runtime(id),
            Err(RNodeRuntimeLookupError::NotRNode {
                interface_id
            }) if interface_id == id
        ));

        let ShutdownStart::Acquired(mut shutdown) = runtime.interface_registry.begin_shutdown(id)
        else {
            panic!("active standard interface must yield shutdown ownership");
        };
        shutdown.stop_task_and_wait().await;
        shutdown.finish();
    }

    #[cfg(feature = "rnode-tcp")]
    fn test_rnode_tcp_peer_with_gated_responses(
        responses: Vec<u8>,
    ) -> (
        String,
        std::sync::mpsc::Sender<()>,
        std::sync::mpsc::Receiver<Vec<u8>>,
        std::thread::JoinHandle<()>,
    ) {
        use std::io::{Read, Write};

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = format!("tcp://{}", listener.local_addr().unwrap());
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let (closed_tx, closed_rx) = std::sync::mpsc::channel();
        let peer = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            release_rx
                .recv_timeout(Duration::from_secs(5))
                .expect("timed out waiting to release RNode peer responses");
            if !responses.is_empty() {
                stream.write_all(&responses).unwrap();
            }
            let mut observed = Vec::new();
            let mut buffer = [0u8; 512];
            loop {
                match stream.read(&mut buffer) {
                    Ok(0) => break,
                    Ok(read) => observed.extend_from_slice(&buffer[..read]),
                    Err(error)
                        if matches!(
                            error.kind(),
                            std::io::ErrorKind::Interrupted
                                | std::io::ErrorKind::WouldBlock
                                | std::io::ErrorKind::TimedOut
                        ) =>
                    {
                        panic!("timed out waiting for exact RNode shutdown: {error}");
                    }
                    Err(error) => panic!("RNode peer read failed: {error}"),
                }
            }
            closed_tx.send(observed).unwrap();
        });
        (port, release_tx, closed_rx, peer)
    }

    #[cfg(feature = "rnode-tcp")]
    fn test_rnode_tcp_peer_with_responses(
        responses: Vec<u8>,
    ) -> (
        String,
        std::sync::mpsc::Receiver<Vec<u8>>,
        std::thread::JoinHandle<()>,
    ) {
        let (port, release_tx, closed_rx, peer) =
            test_rnode_tcp_peer_with_gated_responses(responses);
        release_tx.send(()).unwrap();
        (port, closed_rx, peer)
    }

    #[cfg(feature = "rnode-tcp")]
    fn test_rnode_tcp_peer() -> (
        String,
        std::sync::mpsc::Receiver<Vec<u8>>,
        std::thread::JoinHandle<()>,
    ) {
        test_rnode_tcp_peer_with_responses(Vec::new())
    }

    #[cfg(feature = "rnode-tcp")]
    fn test_ready_rnode_tcp_responses(
        settings: rns_interface::rnode::RNodeRadioSettings,
    ) -> Vec<u8> {
        use rns_interface::{kiss, rnode};

        let mut responses = Vec::new();
        for (command, payload) in [
            (rnode::CMD_DETECT, vec![rnode::DETECT_RESP]),
            (
                rnode::CMD_FW_VERSION,
                vec![rnode::REQUIRED_FW_VER_MAJ, rnode::REQUIRED_FW_VER_MIN],
            ),
            (
                rnode::CMD_FREQUENCY,
                settings.frequency.to_be_bytes().to_vec(),
            ),
            (
                rnode::CMD_BANDWIDTH,
                settings.bandwidth.to_be_bytes().to_vec(),
            ),
            (rnode::CMD_SF, vec![settings.spreading_factor]),
            (rnode::CMD_CR, vec![settings.coding_rate]),
            (rnode::CMD_TXPOWER, vec![settings.tx_power]),
            (rnode::CMD_RADIO_STATE, vec![rnode::RADIO_STATE_ON]),
        ] {
            kiss::frame_with_command_into(command, &payload, &mut responses);
        }
        responses
    }

    #[cfg(feature = "rnode-tcp")]
    fn test_ready_rnode_tcp_peer(
        settings: rns_interface::rnode::RNodeRadioSettings,
    ) -> (
        String,
        std::sync::mpsc::Receiver<Vec<u8>>,
        std::thread::JoinHandle<()>,
    ) {
        test_rnode_tcp_peer_with_responses(test_ready_rnode_tcp_responses(settings))
    }

    #[cfg(feature = "rnode-tcp")]
    fn strict_test_capability_eeprom() -> Vec<u8> {
        let mut bytes = vec![0xFF; 296];
        bytes[0] = 0x03;
        bytes[1] = 0xB8;
        bytes[2..11].copy_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8, 9]);
        bytes[11..27].copy_from_slice(&[
            0x7B, 0x80, 0x24, 0xF3, 0xDE, 0xB6, 0xA8, 0x31, 0x7C, 0xCA, 0x6F, 0xA5, 0x7A, 0x56,
            0x8E, 0x41,
        ]);
        bytes[100] = rns_interface::kiss::FEND;
        bytes[101] = rns_interface::kiss::FESC;
        bytes[0x9B] = 0x73;
        bytes
    }

    #[cfg(feature = "rnode-tcp")]
    fn test_strict_ready_rnode_tcp_peer(
        config: rns_interface::rnode::RNodeConfig,
    ) -> (
        String,
        std::sync::mpsc::Receiver<Vec<u8>>,
        std::thread::JoinHandle<()>,
    ) {
        use rns_interface::{kiss, rnode};
        use std::io::{Read, Write};

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = format!("tcp://{}", listener.local_addr().unwrap());
        let (closed_tx, closed_rx) = std::sync::mpsc::channel();
        let peer = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let detect = rnode::build_detect_sequence();
            let capability_request = kiss::frame_with_command(rnode::CMD_ROM_READ, &[0]);
            let init = rnode::build_init_sequence(&config);
            let mut observed = Vec::new();

            for expected in [&detect, &capability_request] {
                let mut bytes = vec![0; expected.len()];
                stream.read_exact(&mut bytes).unwrap();
                assert_eq!(&bytes, expected);
                observed.extend_from_slice(&bytes);
            }

            let mut capability = Vec::new();
            kiss::frame_with_command_into(
                rnode::CMD_DETECT,
                &[rnode::DETECT_RESP],
                &mut capability,
            );
            kiss::frame_with_command_into(
                rnode::CMD_FW_VERSION,
                &[rnode::REQUIRED_FW_VER_MAJ, rnode::REQUIRED_FW_VER_MIN],
                &mut capability,
            );
            kiss::frame_with_command_into(
                rnode::CMD_ROM_READ,
                &strict_test_capability_eeprom(),
                &mut capability,
            );
            stream.write_all(&capability).unwrap();

            let mut init_bytes = vec![0; init.len()];
            stream.read_exact(&mut init_bytes).unwrap();
            assert_eq!(init_bytes, init);
            observed.extend_from_slice(&init_bytes);

            let settings = rnode::RNodeRadioSettings::from(&config);
            let mut echoes = Vec::new();
            for (command, payload) in [
                (
                    rnode::CMD_FREQUENCY,
                    settings.frequency.to_be_bytes().to_vec(),
                ),
                (
                    rnode::CMD_BANDWIDTH,
                    settings.bandwidth.to_be_bytes().to_vec(),
                ),
                (rnode::CMD_SF, vec![settings.spreading_factor]),
                (rnode::CMD_CR, vec![settings.coding_rate]),
                (rnode::CMD_TXPOWER, vec![settings.tx_power]),
                (rnode::CMD_RADIO_STATE, vec![rnode::RADIO_STATE_ON]),
            ] {
                kiss::frame_with_command_into(command, &payload, &mut echoes);
            }
            stream.write_all(&echoes).unwrap();

            let mut buffer = [0u8; 512];
            loop {
                match stream.read(&mut buffer) {
                    Ok(0) => break,
                    Ok(read) => observed.extend_from_slice(&buffer[..read]),
                    Err(error)
                        if matches!(
                            error.kind(),
                            std::io::ErrorKind::Interrupted
                                | std::io::ErrorKind::WouldBlock
                                | std::io::ErrorKind::TimedOut
                        ) =>
                    {
                        panic!("timed out waiting for exact strict RNode shutdown: {error}");
                    }
                    Err(error) => panic!("strict RNode peer read failed: {error}"),
                }
            }
            closed_tx.send(observed).unwrap();
        });
        (port, closed_rx, peer)
    }

    #[cfg(feature = "rnode-tcp")]
    fn test_rnode_runtime_args<'a>(name: &'a str, port: &'a str) -> RnodeRuntimeArgs<'a> {
        let defaults = rns_interface::rnode::RNodeConfig::new(name, port);
        RnodeRuntimeArgs {
            name,
            port,
            frequency: defaults.frequency,
            bandwidth: defaults.bandwidth,
            spreading_factor: defaults.spreading_factor,
            coding_rate: defaults.coding_rate,
            tx_power: i8::try_from(defaults.tx_power).expect("default RNode power fits i8"),
            mode: defaults.mode,
            st_alock: defaults.st_alock,
            lt_alock: defaults.lt_alock,
            flow_control: defaults.flow_control,
        }
    }

    #[cfg(feature = "rnode-tcp")]
    #[tokio::test]
    async fn rnode_options_wrapper_preserves_legacy_validation_text() {
        let legacy_runtime = dummy_handle();
        let mut legacy_args = test_rnode_runtime_args("invalid-runtime-rnode", "tcp://127.0.0.1:1");
        legacy_args.tx_power = -1;
        let legacy = spawn_rnode_runtime_observed(&legacy_runtime, legacy_args)
            .await
            .expect_err("legacy wrapper must reject negative transmit power");

        let typed_runtime = dummy_handle();
        let mut typed_args = test_rnode_runtime_args("invalid-runtime-rnode", "tcp://127.0.0.1:1");
        typed_args.tx_power = -1;
        let typed = spawn_rnode_runtime_observed_with_options(
            &typed_runtime,
            typed_args,
            rns_interface::rnode::RNodeStartupOptions::require_capability_admission(),
        )
        .await
        .expect_err("options wrapper must reject negative transmit power");

        assert!(matches!(
            typed,
            RNodeRuntimeSpawnError::InvalidConfiguration(_)
        ));
        assert_eq!(legacy, typed.to_string());
        assert_eq!(legacy_runtime.id_gen.load(Ordering::SeqCst), 0);
        assert_eq!(typed_runtime.id_gen.load(Ordering::SeqCst), 0);
    }

    #[cfg(feature = "rnode-tcp")]
    #[tokio::test]
    async fn rnode_options_wrapper_preserves_typed_lower_spawn_failure() {
        let runtime = dummy_handle();
        let error = spawn_rnode_runtime_observed_with_options(
            &runtime,
            test_rnode_runtime_args("strict-runtime-rnode", "tcp://127.0.0.1:0"),
            rns_interface::rnode::RNodeStartupOptions::require_capability_admission(),
        )
        .await
        .expect_err("port zero cannot accept the strict startup connection");

        assert!(matches!(
            error,
            RNodeRuntimeSpawnError::RNodeSpawn(rns_interface::rnode::RNodeSpawnError::Interface(_))
        ));
        assert!(error.to_string().starts_with("RNode spawn failed: "));
        assert_eq!(runtime.interface_registry.len(), 0);
    }

    #[cfg(feature = "rnode-tcp")]
    #[tokio::test]
    async fn rnode_options_wrapper_routes_strict_capability_rejection() {
        use rns_interface::{kiss, rnode};

        let mut responses = Vec::new();
        kiss::frame_with_command_into(rnode::CMD_DETECT, &[rnode::DETECT_RESP], &mut responses);
        kiss::frame_with_command_into(
            rnode::CMD_FW_VERSION,
            &[rnode::REQUIRED_FW_VER_MAJ, rnode::REQUIRED_FW_VER_MIN],
            &mut responses,
        );
        kiss::frame_with_command_into(rnode::CMD_ROM_READ, &[0], &mut responses);
        let (port, closed_rx, peer) = test_rnode_tcp_peer_with_responses(responses);
        let runtime = dummy_handle();

        let error = spawn_rnode_runtime_observed_with_options(
            &runtime,
            test_rnode_runtime_args("strict-capability-runtime-rnode", &port),
            rnode::RNodeStartupOptions::require_capability_admission(),
        )
        .await
        .expect_err("empty EEPROM response must be a typed capability rejection");

        assert!(
            matches!(
                &error,
                RNodeRuntimeSpawnError::RNodeSpawn(rnode::RNodeSpawnError::CapabilityAdmission(
                    rnode::RNodeCapabilityAdmissionError::CapabilityImage(_)
                ))
            ),
            "unexpected strict runtime error: {error:?}"
        );
        assert_eq!(runtime.interface_registry.len(), 0);
        let observed = closed_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("strict rejected RNode connection did not close");
        let detect = rnode::build_detect_sequence();
        assert!(
            observed
                .windows(detect.len())
                .any(|window| window == detect.as_slice()),
            "strict startup must send detection"
        );
        let capability_request = kiss::frame_with_command(rnode::CMD_ROM_READ, &[0]);
        assert_eq!(
            observed
                .windows(capability_request.len())
                .filter(|window| *window == capability_request.as_slice())
                .count(),
            1,
            "strict startup must request exactly one capability image"
        );
        peer.join().unwrap();
    }

    #[cfg(feature = "ble")]
    fn test_ble_rnode_runtime_args<'a>(name: &'a str, port: &'a str) -> BleRnodeRuntimeArgs<'a> {
        let defaults = rns_interface::ble_rnode::BleRNodeConfig::new(name, port);
        BleRnodeRuntimeArgs {
            name,
            port,
            frequency: defaults.frequency,
            bandwidth: defaults.bandwidth,
            spreading_factor: defaults.spreading_factor,
            coding_rate: defaults.coding_rate,
            tx_power: i8::try_from(defaults.tx_power).expect("default RNode power fits i8"),
            mode: defaults.mode,
            st_alock: defaults.st_alock,
            lt_alock: defaults.lt_alock,
            flow_control: defaults.flow_control,
        }
    }

    #[cfg(feature = "ble")]
    #[tokio::test]
    async fn ble_runtime_spawns_validate_before_allocating_interface_ids() {
        let runtime = dummy_handle();

        let mut direct = test_ble_rnode_runtime_args("invalid-direct", "ble://RNode");
        direct.tx_power = -1;
        let direct_error = spawn_ble_rnode_runtime_observed(&runtime, direct)
            .await
            .expect_err("negative BLE transmit power must be rejected");
        assert!(direct_error.contains("txpower"));
        assert_eq!(runtime.id_gen.load(Ordering::SeqCst), 0);

        let mut typed_direct = test_ble_rnode_runtime_args("invalid-direct", "ble://RNode");
        typed_direct.tx_power = -1;
        let typed_direct_error = spawn_ble_rnode_runtime_observed_with_options(
            &runtime,
            typed_direct,
            rns_interface::rnode::RNodeStartupOptions::require_capability_admission(),
        )
        .await
        .expect_err("typed BLE spawn must reject negative transmit power");
        assert!(matches!(
            typed_direct_error,
            RNodeRuntimeSpawnError::InvalidConfiguration(_)
        ));
        assert_eq!(direct_error, typed_direct_error.to_string());
        assert_eq!(runtime.id_gen.load(Ordering::SeqCst), 0);

        let mut native = test_ble_rnode_runtime_args("invalid-native", "ble://RNode");
        native.frequency = 0;
        let native_error = spawn_ble_rnode_runtime_native_observed(&runtime, native, 1)
            .await
            .expect_err("invalid native BLE frequency must be rejected");
        assert!(native_error.contains("frequency"));
        assert_eq!(runtime.id_gen.load(Ordering::SeqCst), 0);

        let mut typed_native = test_ble_rnode_runtime_args("invalid-native", "ble://RNode");
        typed_native.frequency = 0;
        let typed_native_error = spawn_ble_rnode_runtime_native_observed_with_options(
            &runtime,
            typed_native,
            1,
            rns_interface::rnode::RNodeStartupOptions::require_capability_admission(),
        )
        .await
        .expect_err("typed native BLE spawn must reject invalid frequency");
        assert!(matches!(
            typed_native_error,
            RNodeRuntimeSpawnError::InvalidConfiguration(_)
        ));
        assert_eq!(native_error, typed_native_error.to_string());
        assert_eq!(runtime.id_gen.load(Ordering::SeqCst), 0);
        assert_eq!(runtime.interface_registry.len(), 0);
        assert!(
            runtime
                .interface_controls
                .lock()
                .expect("interface_controls mutex poisoned")
                .is_empty()
        );
    }

    #[cfg(feature = "rnode-tcp")]
    #[tokio::test]
    async fn observed_rnode_spawn_returns_its_exact_registered_driver() {
        let defaults =
            rns_interface::rnode::RNodeConfig::new("atomic-observer-template", "tcp://127.0.0.1:1");
        let settings = rns_interface::rnode::RNodeRadioSettings::from(&defaults);
        let (port, closed_rx, peer) = test_ready_rnode_tcp_peer(settings);
        let (transport_tx, mut transport_rx) = mpsc::channel::<TransportMessage>(4);
        let mut runtime = dummy_handle();
        runtime.transport_tx = transport_tx;

        let spawned = spawn_rnode_runtime_observed(
            &runtime,
            test_rnode_runtime_args("atomic-observer", &port),
        )
        .await
        .expect("spawn observed runtime RNode");
        assert_eq!(spawned.interface_id, 0);
        assert_eq!(spawned.observer.interface_id(), spawned.interface_id);
        let registered = runtime
            .rnode_runtime(spawned.interface_id)
            .expect("registered exact RNode observer");
        assert!(matches!(
            transport_rx.recv().await,
            Some(TransportMessage::RegisterInterface {
                id: registered_id,
                ..
            }) if registered_id == spawned.interface_id
        ));

        let ready = spawned
            .observer
            .await_ready(Duration::from_secs(2))
            .await
            .expect("exact spawned RNode readiness");
        assert_eq!(ready.phase, rns_interface::rnode::RNodeRuntimePhase::Ready);
        let registered_ready = registered
            .await_ready(Duration::ZERO)
            .await
            .expect("registered observer shares exact ready publication");
        assert!(
            Arc::ptr_eq(&ready, &registered_ready),
            "spawn result and registry lookup must share the exact driver publication"
        );
        assert!(spawned.online.load(Ordering::SeqCst));

        teardown_rnode_interface(&runtime, spawned.interface_id).await;
        assert!(matches!(
            transport_rx.recv().await,
            Some(TransportMessage::DeregisterInterface {
                id: deregistered_id
            }) if deregistered_id == spawned.interface_id
        ));
        let observed = closed_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("exact spawned RNode did not close");
        assert!(observed.ends_with(&rns_interface::rnode::build_detach_sequence()));
        peer.join().unwrap();
    }

    #[cfg(feature = "rnode-tcp")]
    #[tokio::test]
    async fn strict_observed_rnode_spawn_registers_exact_admitted_driver() {
        use rns_interface::{kiss, rnode};

        let template =
            rnode::RNodeConfig::new("strict-atomic-observer-template", "tcp://127.0.0.1:1");
        let (port, closed_rx, peer) = test_strict_ready_rnode_tcp_peer(template.clone());
        let (transport_tx, mut transport_rx) = mpsc::channel::<TransportMessage>(4);
        let mut runtime = dummy_handle();
        runtime.transport_tx = transport_tx;

        let spawned = spawn_rnode_runtime_observed_with_options(
            &runtime,
            test_rnode_runtime_args("strict-atomic-observer", &port),
            rnode::RNodeStartupOptions::require_capability_admission(),
        )
        .await
        .expect("spawn strict observed runtime RNode");
        let registered = runtime
            .rnode_runtime(spawned.interface_id)
            .expect("registered exact strict RNode observer");
        assert!(matches!(
            transport_rx.recv().await,
            Some(TransportMessage::RegisterInterface {
                id: registered_id,
                ..
            }) if registered_id == spawned.interface_id
        ));

        let ready = spawned
            .observer
            .await_ready(Duration::from_secs(2))
            .await
            .expect("strict spawned RNode readiness");
        assert_eq!(ready.capability, rnode::RNodeCapabilityState::Verified);
        let registered_ready = registered
            .await_ready(Duration::ZERO)
            .await
            .expect("registered strict observer shares ready publication");
        assert!(Arc::ptr_eq(&ready, &registered_ready));

        teardown_rnode_interface(&runtime, spawned.interface_id).await;
        assert!(matches!(
            transport_rx.recv().await,
            Some(TransportMessage::DeregisterInterface {
                id: deregistered_id
            }) if deregistered_id == spawned.interface_id
        ));
        let observed = closed_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("strict spawned RNode did not close");
        let capability_request = kiss::frame_with_command(rnode::CMD_ROM_READ, &[0]);
        let init = rnode::build_init_sequence(&template);
        let capability_positions: Vec<_> = observed
            .windows(capability_request.len())
            .enumerate()
            .filter_map(|(index, window)| {
                (window == capability_request.as_slice()).then_some(index)
            })
            .collect();
        assert_eq!(capability_positions.len(), 1);
        let init_position = observed
            .windows(init.len())
            .position(|window| window == init.as_slice())
            .expect("strict startup init sequence missing");
        assert!(capability_positions[0] < init_position);
        assert!(observed.ends_with(&rnode::build_detach_sequence()));
        peer.join().unwrap();
    }

    #[cfg(feature = "rnode-tcp")]
    #[tokio::test]
    async fn legacy_rnode_spawn_preserves_id_and_online_result() {
        let (port, closed_rx, peer) = test_rnode_tcp_peer();
        let (transport_tx, mut transport_rx) = mpsc::channel::<TransportMessage>(4);
        let mut runtime = dummy_handle();
        runtime.transport_tx = transport_tx;

        let (id, online) =
            spawn_rnode_runtime(&runtime, test_rnode_runtime_args("legacy-spawn", &port))
                .await
                .expect("legacy RNode spawn");
        assert_eq!(id, 0);
        assert!(online.load(Ordering::SeqCst));
        assert!(
            runtime.rnode_runtime(id).is_ok(),
            "legacy spawn must still register an observable RNode"
        );
        assert!(matches!(
            transport_rx.recv().await,
            Some(TransportMessage::RegisterInterface {
                id: registered_id,
                ..
            }) if registered_id == id
        ));

        teardown_rnode_interface(&runtime, id).await;
        assert!(matches!(
            transport_rx.recv().await,
            Some(TransportMessage::DeregisterInterface {
                id: deregistered_id
            }) if deregistered_id == id
        ));
        let observed = closed_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("legacy spawned RNode did not close");
        assert!(observed.ends_with(&rns_interface::rnode::build_detach_sequence()));
        peer.join().unwrap();
    }

    #[cfg(feature = "rnode-tcp")]
    #[tokio::test]
    async fn cancelled_observed_rnode_spawn_rolls_back_without_publishing() {
        let (port, closed_rx, peer) = test_rnode_tcp_peer();
        let (transport_tx, mut transport_rx) = mpsc::channel::<TransportMessage>(1);
        transport_tx
            .send(TransportMessage::Shutdown)
            .await
            .expect("fill transport channel");
        let mut runtime = dummy_handle();
        runtime.transport_tx = transport_tx;
        let registry = runtime.interface_registry.clone();
        let controls = runtime.interface_controls.clone();

        let caller = tokio::spawn(async move {
            spawn_rnode_runtime_observed(
                &runtime,
                test_rnode_runtime_args("cancelled-observed-spawn", &port),
            )
            .await
        });
        wait_for_registry_len(&registry, 1).await;
        caller.abort();
        let _ = caller.await;
        wait_for_registry_len(&registry, 0).await;

        assert!(
            controls
                .lock()
                .expect("interface_controls mutex poisoned")
                .is_empty()
        );
        assert!(matches!(
            transport_rx.recv().await,
            Some(TransportMessage::Shutdown)
        ));
        assert!(
            transport_rx.try_recv().is_err(),
            "cancelled observed spawn must never publish RegisterInterface"
        );
        let observed = closed_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("cancelled observed spawn did not close its exact RNode");
        assert!(observed.ends_with(&rns_interface::rnode::build_detach_sequence()));
        peer.join().unwrap();
    }

    #[cfg(feature = "rnode-tcp")]
    #[tokio::test]
    async fn observed_rnode_spawn_registration_failure_stops_exact_driver() {
        let (port, closed_rx, peer) = test_rnode_tcp_peer();
        let (transport_tx, transport_rx) = mpsc::channel::<TransportMessage>(1);
        drop(transport_rx);
        let mut runtime = dummy_handle();
        runtime.transport_tx = transport_tx;

        let result = spawn_rnode_runtime_observed(
            &runtime,
            test_rnode_runtime_args("failed-observed-spawn", &port),
        )
        .await;
        assert!(
            result
                .expect_err("closed transport must reject observed spawn registration")
                .contains("RNode registration failed"),
            "public spawn error must preserve registration context"
        );
        assert_eq!(runtime.interface_registry.len(), 0);
        assert!(
            runtime
                .interface_controls
                .lock()
                .expect("interface_controls mutex poisoned")
                .is_empty()
        );
        let observed = closed_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("failed observed spawn did not close its exact RNode");
        assert!(observed.ends_with(&rns_interface::rnode::build_detach_sequence()));
        peer.join().unwrap();
    }

    #[cfg(feature = "rnode-tcp")]
    #[tokio::test]
    async fn rnode_runtime_observer_waits_for_exact_protocol_readiness_and_terminal_stop() {
        let id = 920_199;
        let template =
            rns_interface::rnode::RNodeConfig::new("ready-observer-template", "tcp://127.0.0.1:1");
        let settings = rns_interface::rnode::RNodeRadioSettings::from(&template);
        let (port, release_responses, closed_rx, peer) =
            test_rnode_tcp_peer_with_gated_responses(test_ready_rnode_tcp_responses(settings));
        let config = rns_interface::rnode::RNodeConfig::new("ready-observer", &port);
        assert_eq!(
            rns_interface::rnode::RNodeRadioSettings::from(&config),
            settings
        );

        let (transport_tx, _transport_rx) = mpsc::channel::<TransportMessage>(8);
        let controls: InterfaceControlMap = Arc::new(std::sync::Mutex::new(HashMap::new()));
        let registry = InterfaceRegistry::default();
        let spawned = rns_interface::rnode::spawn_rnode_interface_with_driver(
            config,
            id,
            transport_tx.clone(),
        )
        .await
        .expect("spawn ready observed RNode");
        register_observed_rnode_handle_with_kind(
            &transport_tx,
            spawned,
            &controls,
            &registry,
            InterfaceKind::RNode,
        )
        .await
        .expect("register ready observed RNode");

        let mut runtime = dummy_handle();
        runtime.transport_tx = transport_tx;
        runtime.interface_controls = controls;
        runtime.interface_registry = registry;
        let observer = runtime.rnode_runtime(id).expect("active RNode observer");
        assert_eq!(observer.interface_id(), id);
        assert_ne!(
            observer.snapshot().phase,
            rns_interface::rnode::RNodeRuntimePhase::Ready,
            "the gated peer must not publish readiness before release"
        );

        let readiness_observer = observer.clone();
        let (readiness_started_tx, readiness_started_rx) = oneshot::channel();
        let readiness = tokio::spawn(async move {
            let _ = readiness_started_tx.send(());
            readiness_observer.await_ready(Duration::from_secs(2)).await
        });
        let mut update_observer = observer.clone();
        let (updates_started_tx, updates_started_rx) = oneshot::channel();
        let updates = tokio::spawn(async move {
            let _ = updates_started_tx.send(());
            loop {
                let snapshot = update_observer
                    .changed()
                    .await
                    .expect("RNode observation closed before readiness");
                if snapshot.phase == rns_interface::rnode::RNodeRuntimePhase::Ready {
                    return (update_observer, snapshot);
                }
            }
        });
        readiness_started_rx
            .await
            .expect("readiness waiter did not start");
        updates_started_rx
            .await
            .expect("update observer did not start");
        tokio::task::yield_now().await;
        assert!(!readiness.is_finished());
        assert!(!updates.is_finished());
        release_responses
            .send(())
            .expect("release gated RNode peer responses");

        let ready = readiness
            .await
            .expect("readiness task panicked")
            .expect("RNode protocol readiness");
        let (mut update_observer, streamed_ready) =
            updates.await.expect("update observer task panicked");
        assert_eq!(ready.phase, rns_interface::rnode::RNodeRuntimePhase::Ready);
        assert_ne!(ready.connection_generation, 0);
        assert!(
            Arc::ptr_eq(&ready, &streamed_ready),
            "changed and await_ready clones must observe the same latest publication"
        );
        assert!(
            observer.await_ready(Duration::ZERO).await.is_ok(),
            "consuming updates on a clone must not consume readiness"
        );

        teardown_interface(&runtime, id).await;
        let streamed_stopped = tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                let snapshot = update_observer
                    .changed()
                    .await
                    .expect("RNode observation closed before terminal publication");
                if snapshot.phase == rns_interface::rnode::RNodeRuntimePhase::Stopped {
                    return snapshot;
                }
            }
        })
        .await
        .expect("update observer did not receive terminal publication");
        assert_eq!(
            streamed_stopped.reason,
            Some(rns_interface::rnode::RNodeRuntimeReason::StopRequested)
        );
        assert!(
            tokio::time::timeout(Duration::from_secs(1), update_observer.changed())
                .await
                .expect("closed observation did not resolve")
                .is_none(),
            "changed must return None after the exact publisher closes"
        );
        assert!(Arc::ptr_eq(&streamed_stopped, &update_observer.snapshot()));
        let stopped = observer
            .await_ready(Duration::from_secs(1))
            .await
            .expect_err("stopped RNode cannot become ready");
        assert!(matches!(stopped, RNodeReadinessError::Stopped { .. }));
        assert_eq!(
            stopped.last_snapshot().phase,
            rns_interface::rnode::RNodeRuntimePhase::Stopped
        );

        let observed = closed_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("exact teardown did not close ready RNode peer");
        assert!(observed.ends_with(&rns_interface::rnode::build_detach_sequence()));
        peer.join().unwrap();
    }

    #[cfg(feature = "rnode-tcp")]
    #[tokio::test]
    async fn rnode_runtime_wait_timeout_and_cancellation_are_observation_only() {
        let id = 920_200;
        let (port, closed_rx, peer) = test_rnode_tcp_peer();
        let (transport_tx, _transport_rx) = mpsc::channel::<TransportMessage>(8);
        let controls: InterfaceControlMap = Arc::new(std::sync::Mutex::new(HashMap::new()));
        let registry = InterfaceRegistry::default();
        let spawned = rns_interface::rnode::spawn_rnode_interface_with_driver(
            rns_interface::rnode::RNodeConfig::new("waiting-observer", &port),
            id,
            transport_tx.clone(),
        )
        .await
        .expect("spawn waiting observed RNode");
        register_observed_rnode_handle_with_kind(
            &transport_tx,
            spawned,
            &controls,
            &registry,
            InterfaceKind::RNode,
        )
        .await
        .expect("register waiting observed RNode");

        let mut runtime = dummy_handle();
        runtime.transport_tx = transport_tx;
        runtime.interface_controls = controls;
        runtime.interface_registry = registry;
        let observer = runtime
            .rnode_runtime(id)
            .expect("active waiting RNode observer");

        let timeout = observer
            .await_ready(Duration::from_millis(50))
            .await
            .expect_err("incomplete protocol evidence must time out");
        assert!(matches!(timeout, RNodeReadinessError::Timeout { .. }));
        assert_ne!(
            timeout.last_snapshot().phase,
            rns_interface::rnode::RNodeRuntimePhase::Ready
        );

        let cancelled_observer = observer.clone();
        let waiter = tokio::spawn(async move {
            cancelled_observer
                .await_ready(Duration::from_secs(30))
                .await
        });
        tokio::task::yield_now().await;
        waiter.abort();
        let _ = waiter.await;
        assert!(
            runtime.rnode_runtime(id).is_ok(),
            "cancelling a readiness waiter must not mutate registry ownership"
        );
        assert!(!matches!(
            observer.snapshot().phase,
            rns_interface::rnode::RNodeRuntimePhase::ShuttingDown
                | rns_interface::rnode::RNodeRuntimePhase::Stopped
        ));

        assert!(
            tokio::time::timeout(
                Duration::from_millis(20),
                observer.await_ready(Duration::MAX),
            )
            .await
            .is_err(),
            "an overflowing public timeout must remain pending instead of panicking"
        );

        teardown_interface(&runtime, id).await;
        let observed = closed_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("exact teardown did not close waiting RNode peer");
        assert!(observed.ends_with(&rns_interface::rnode::build_detach_sequence()));
        peer.join().unwrap();
    }

    #[cfg(feature = "rnode-tcp")]
    #[tokio::test]
    async fn rnode_runtime_observer_never_follows_same_id_replacement() {
        let id = 920_201;
        let (transport_tx, _transport_rx) = mpsc::channel::<TransportMessage>(8);
        let controls: InterfaceControlMap = Arc::new(std::sync::Mutex::new(HashMap::new()));
        let registry = InterfaceRegistry::default();
        let mut runtime = dummy_handle();
        runtime.transport_tx = transport_tx.clone();
        runtime.interface_controls = controls.clone();
        runtime.interface_registry = registry.clone();
        runtime.id_gen = Arc::new(AtomicU64::new(id));

        let (first_port, first_closed_rx, first_peer) = test_rnode_tcp_peer();
        let first = spawn_rnode_runtime_observed(
            &runtime,
            test_rnode_runtime_args("observer-owner-a", &first_port),
        )
        .await
        .expect("spawn first RNode owner");
        assert_eq!(first.interface_id, id);
        let first_observer = first.observer;

        teardown_interface(&runtime, id).await;
        let first_terminal = first_observer
            .await_ready(Duration::from_secs(1))
            .await
            .expect_err("retired first owner cannot become ready");
        assert!(matches!(
            first_terminal,
            RNodeReadinessError::Stopped { .. }
        ));
        let first_closed = first_closed_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("first RNode owner did not close");
        assert!(first_closed.ends_with(&rns_interface::rnode::build_detach_sequence()));
        first_peer.join().unwrap();

        let template = rns_interface::rnode::RNodeConfig::new(
            "observer-owner-b-template",
            "tcp://127.0.0.1:1",
        );
        let settings = rns_interface::rnode::RNodeRadioSettings::from(&template);
        let (second_port, second_closed_rx, second_peer) = test_ready_rnode_tcp_peer(settings);
        runtime.id_gen.store(id, Ordering::SeqCst);
        let second = spawn_rnode_runtime_observed(
            &runtime,
            test_rnode_runtime_args("observer-owner-b", &second_port),
        )
        .await
        .expect("spawn replacement RNode owner");
        assert_eq!(second.interface_id, id);
        let second_observer = second.observer;
        let second_ready = second_observer
            .await_ready(Duration::from_secs(2))
            .await
            .expect("replacement RNode readiness");
        assert_eq!(
            second_ready.phase,
            rns_interface::rnode::RNodeRuntimePhase::Ready
        );
        assert_eq!(
            first_observer.snapshot().phase,
            rns_interface::rnode::RNodeRuntimePhase::Stopped,
            "the retired observer must remain bound to owner A"
        );
        assert!(matches!(
            first_observer.await_ready(Duration::ZERO).await,
            Err(RNodeReadinessError::Stopped { .. })
        ));

        teardown_interface(&runtime, id).await;
        let second_closed = second_closed_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("replacement RNode owner did not close");
        assert!(second_closed.ends_with(&rns_interface::rnode::build_detach_sequence()));
        second_peer.join().unwrap();
    }

    #[cfg(feature = "rnode-tcp")]
    fn assert_exact_rnode_stopped(driver: &rns_interface::rnode::RNodeDriverSubscription) {
        let snapshot = driver.snapshot();
        assert_eq!(
            snapshot.phase,
            rns_interface::rnode::RNodeRuntimePhase::Stopped
        );
        assert_eq!(
            snapshot.reason,
            Some(rns_interface::rnode::RNodeRuntimeReason::StopRequested)
        );
    }

    #[cfg(feature = "rnode-tcp")]
    async fn wait_for_exact_rnode_stop(driver: &mut rns_interface::rnode::RNodeDriverSubscription) {
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if driver.snapshot().phase == rns_interface::rnode::RNodeRuntimePhase::Stopped {
                    return;
                }
                driver
                    .changed()
                    .await
                    .expect("RNode observation closed before terminal snapshot");
            }
        })
        .await
        .expect("exact RNode driver did not publish its terminal snapshot");
        assert_exact_rnode_stopped(driver);
    }

    #[test]
    fn test_default_config() {
        let rc = ReticulumConfig::default();
        assert!(rc.share_instance);
        assert_eq!(rc.instance_name, "default");
        assert_eq!(rc.shared_instance_port, 37428);
        assert_eq!(rc.control_port, 37429);
        assert!(!rc.enable_transport);
        assert!(rc.use_implicit_proof);
        assert_eq!(rc.loglevel, 4);
    }

    #[test]
    fn test_config_from_default_file() {
        let config = Config::parse(Config::default_config()).unwrap();
        let rc = ReticulumConfig::from_config(&config);
        assert!(rc.share_instance);
        assert_eq!(rc.shared_instance_port, 37428);
        assert_eq!(rc.loglevel, 4);
    }

    #[test]
    fn test_config_custom_values() {
        let input = r#"
[reticulum]
share_instance = No
instance_name = testnode
shared_instance_port = 12345
instance_control_port = 12346
enable_transport = Yes
respond_to_probes = Yes
use_implicit_proof = No

[logging]
loglevel = 7
"#;
        let config = Config::parse(input).unwrap();
        let rc = ReticulumConfig::from_config(&config);
        assert!(!rc.share_instance);
        assert_eq!(rc.instance_name, "testnode");
        assert_eq!(rc.shared_instance_port, 12345);
        assert_eq!(rc.control_port, 12346);
        assert!(rc.enable_transport);
        assert!(rc.respond_to_probes);
        assert!(!rc.use_implicit_proof);
        assert_eq!(rc.loglevel, 7);
    }

    #[test]
    fn test_shared_instance_type_explicit_tcp() {
        let input = "[reticulum]\nshared_instance_type = tcp\n";
        let config = Config::parse(input).unwrap();
        let rc = ReticulumConfig::from_config(&config);
        assert_eq!(rc.shared_instance_type, SharedInstanceType::Tcp);
    }

    #[test]
    fn test_shared_instance_type_explicit_unix() {
        let input = "[reticulum]\nshared_instance_type = Unix\n";
        let config = Config::parse(input).unwrap();
        let rc = ReticulumConfig::from_config(&config);
        assert_eq!(rc.shared_instance_type, SharedInstanceType::Unix);
    }

    #[test]
    fn test_shared_instance_type_invalid_keeps_default() {
        let input = "[reticulum]\nshared_instance_type = bogus\n";
        let config = Config::parse(input).unwrap();
        let rc = ReticulumConfig::from_config(&config);
        assert_eq!(
            rc.shared_instance_type,
            SharedInstanceType::platform_default()
        );
    }

    #[test]
    fn test_shared_tcp_client_config_has_no_reconnect_cap() {
        let config = shared_tcp_client_config(12345);
        assert_eq!(config.name, "SharedInstanceClient");
        assert_eq!(config.target_host, "127.0.0.1");
        assert_eq!(config.target_port, 12345);
        assert_eq!(config.max_reconnect_tries, None);
    }

    #[test]
    fn test_force_shared_instance_bitrate_parsed() {
        let input = "[reticulum]\nforce_shared_instance_bitrate = 1000000\n";
        let config = Config::parse(input).unwrap();
        let rc = ReticulumConfig::from_config(&config);
        assert_eq!(rc.force_shared_instance_bitrate, Some(1_000_000));
    }

    #[test]
    fn test_force_shared_instance_bitrate_absent() {
        let input = "[reticulum]\nshare_instance = Yes\n";
        let config = Config::parse(input).unwrap();
        let rc = ReticulumConfig::from_config(&config);
        assert_eq!(rc.force_shared_instance_bitrate, None);
    }

    #[tokio::test]
    async fn forced_shared_instance_bitrate_updates_interface_metadata() {
        let mut handle = test_interface_handle(1, None, "shared");
        apply_forced_shared_instance_bitrate(&mut handle, Some(1_000_000));
        assert_eq!(handle.bitrate, 1_000_000);
        assert_eq!(
            handle.mtu,
            rns_interface::traits::optimise_mtu(1_000_000).unwrap()
        );

        apply_forced_shared_instance_bitrate(&mut handle, Some(0));
        assert_eq!(handle.bitrate, 1_000_000, "zero is not a usable bitrate");
    }

    #[tokio::test]
    async fn forced_shared_instance_bitrate_adds_client_first_hop_latency() {
        let mut handle = dummy_handle();
        handle.instance_mode = InstanceMode::Client;
        handle.config.force_shared_instance_bitrate = Some(1_000);
        let adjusted = handle.apply_shared_instance_latency(
            &TransportQuery::FirstHopTimeout { dest: [0x42; 16] },
            TransportQueryResponse::FloatResult(Some(6.0)),
        );
        let TransportQueryResponse::FloatResult(Some(seconds)) = adjusted else {
            panic!("expected first-hop timeout");
        };
        let simulated = (rns_wire::constants::MTU as f64 * 8.0) / 1_000.0;
        assert_eq!(seconds, 6.0 + simulated);
        assert_eq!(
            link_establishment_timeout(Duration::from_secs_f64(seconds), 2).unwrap(),
            Duration::from_secs_f64(6.0 + simulated + 12.0),
            "Link timing must retain both master and simulated client latency"
        );
    }

    #[test]
    fn test_instance_mode_variants() {
        assert_ne!(InstanceMode::Shared, InstanceMode::Client);
        assert_ne!(InstanceMode::Client, InstanceMode::Standalone);
    }

    fn dummy_handle() -> ReticulumHandle {
        let (tx, _rx) = mpsc::channel::<TransportMessage>(1);
        let (htx, _hrx) = mpsc::channel::<rns_interface::traits::InterfaceHandle>(1);
        let shutdown = ShutdownSignal::new();
        let interface_controls = Arc::new(std::sync::Mutex::new(HashMap::new()));
        let interface_registry = InterfaceRegistry::default();
        let transport_completion = Arc::new(TransportCompletion {
            stopped: AtomicBool::new(true),
            notify: Notify::new(),
        });
        let shutdown_coordinator = RuntimeShutdownCoordinator::new(
            shutdown.clone(),
            tx.clone(),
            transport_completion.clone(),
            interface_controls.clone(),
            interface_registry.clone(),
        );
        ReticulumHandle {
            transport_tx: tx,
            config_dir: PathBuf::from("/tmp/dummy"),
            instance_mode: InstanceMode::Standalone,
            interface_configs: Vec::new(),
            id_gen: Arc::new(AtomicU64::new(0)),
            handle_tx: htx,
            interface_controls,
            interface_registry,
            socket_base: PathBuf::from("/tmp/dummy"),
            config: ReticulumConfig::default(),
            is_foreground: Arc::new(AtomicBool::new(true)),
            shutdown,
            transport_identity: Arc::new(Identity::new()),
            network_identity: None,
            discovery: Arc::new(DiscoveryRuntime::default()),
            startup_rnode_runtimes: Vec::new(),
            shutdown_coordinator,
            started_at: std::time::Instant::now(),
        }
    }

    #[tokio::test]
    async fn recall_returns_typed_identity_and_metadata() {
        let (transport_tx, mut transport_rx) = mpsc::channel::<TransportMessage>(1);
        let identity = Identity::new();
        let public_key = identity.get_public_key();
        let destination_hash = [0x42; 16];
        let timestamp = 1_700_000_000.5;
        let responder = tokio::spawn(async move {
            let TransportMessage::Rpc { query, response_tx } =
                transport_rx.recv().await.expect("recall query")
            else {
                panic!("expected transport RPC");
            };
            assert!(matches!(
                query,
                TransportQuery::RecallDestination { dest } if dest == destination_hash
            ));
            response_tx
                .send(TransportQueryResponse::RecalledDestination(Some(
                    RecalledDestinationRpcEntry {
                        dest_hash: destination_hash,
                        public_key,
                        app_data: Some(b"display name".to_vec()),
                        ratchet: Some([0xA5; 32]),
                        hops: 4,
                        timestamp,
                    },
                )))
                .expect("recall response receiver");
        });

        let mut handle = dummy_handle();
        handle.transport_tx = transport_tx;
        let recalled = handle
            .recall(destination_hash)
            .await
            .expect("recall query succeeds")
            .expect("destination is known");
        assert_eq!(recalled.destination_hash, destination_hash);
        assert_eq!(recalled.identity.hash, identity.hash);
        assert_eq!(
            recalled.app_data.as_deref(),
            Some(b"display name".as_slice())
        );
        assert_eq!(recalled.ratchet, Some([0xA5; 32]));
        assert_eq!(recalled.hops, 4);
        assert_eq!(
            recalled
                .last_heard
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs_f64(),
            timestamp
        );
        responder.await.unwrap();
    }

    #[tokio::test]
    async fn send_to_builds_encrypted_packet_and_resolves_receipt() {
        let (transport_tx, mut transport_rx) = mpsc::channel::<TransportMessage>(2);
        let remote_identity = Identity::new();
        let destination = Destination::new(
            Some(&remote_identity),
            Direction::Out,
            DestType::Single,
            "send.test",
        )
        .unwrap();
        let destination_hash = destination.hash;
        let public_key = remote_identity.get_public_key();
        let decrypt_identity = remote_identity.clone();
        let responder = tokio::spawn(async move {
            let TransportMessage::Rpc { query, response_tx } =
                transport_rx.recv().await.expect("recall query")
            else {
                panic!("expected recall query");
            };
            assert!(matches!(
                query,
                TransportQuery::RecallDestination { dest } if dest == destination_hash
            ));
            response_tx
                .send(TransportQueryResponse::RecalledDestination(Some(
                    RecalledDestinationRpcEntry {
                        dest_hash: destination_hash,
                        public_key,
                        app_data: None,
                        ratchet: None,
                        hops: 1,
                        timestamp: 1.0,
                    },
                )))
                .unwrap();

            let TransportMessage::SendPacket {
                request,
                attached_interface,
                receipt: Some(receipt),
                result_tx,
            } = transport_rx.recv().await.expect("packet send")
            else {
                panic!("expected tracked packet send");
            };
            assert_eq!(attached_interface, None);
            assert_eq!(request.destination_hash, destination_hash);
            assert_eq!(receipt.timeout, Some(Duration::from_secs(9)));
            let packet = rns_wire::packet::Packet::from_raw(&request.raw).unwrap();
            assert_eq!(
                packet.header.flags.destination_type,
                rns_wire::flags::DestinationType::Single
            );
            let inbound = Destination::new(
                Some(&decrypt_identity),
                Direction::In,
                DestType::Single,
                "send.test",
            )
            .unwrap();
            assert_eq!(
                inbound.decrypt(packet.data(), &decrypt_identity).unwrap(),
                b"hello"
            );
            result_tx.send(OutboundDispatchResult::Sent).unwrap();

            let TransportMessage::SetReceiptTimeout {
                truncated_hash,
                timeout,
                result_tx,
            } = transport_rx.recv().await.expect("receipt timeout update")
            else {
                panic!("expected receipt timeout update");
            };
            assert_eq!(truncated_hash, receipt.truncated_hash);
            assert_eq!(timeout, Duration::from_secs(3));
            result_tx.send(true).unwrap();
            receipt.status_tx.send_replace(ReceiptUpdate::Delivered {
                rtt: Duration::from_millis(42),
            });
        });

        let mut handle = dummy_handle();
        handle.transport_tx = transport_tx;
        let sent = handle
            .send_to(
                &destination,
                b"hello",
                SendOptions {
                    timeout: Some(Duration::from_secs(9)),
                    ..SendOptions::default()
                },
            )
            .await
            .unwrap();
        let receipt = sent.receipt.expect("receipt requested");
        assert_eq!(receipt.packet_hash, sent.packet_hash);
        receipt.set_timeout(Duration::from_secs(3)).await.unwrap();
        assert_eq!(
            receipt.delivered().await.unwrap(),
            Duration::from_millis(42)
        );
        responder.await.unwrap();
    }

    #[tokio::test]
    async fn outbound_packet_resend_uses_fresh_ciphertext_and_enforces_state() {
        let (transport_tx, mut transport_rx) = mpsc::channel::<TransportMessage>(4);
        let (raw_tx, mut raw_rx) = mpsc::channel::<Bytes>(2);
        let remote_identity = Identity::new();
        let destination = Destination::new(
            Some(&remote_identity),
            Direction::Out,
            DestType::Single,
            "resend.test",
        )
        .unwrap();
        let destination_hash = destination.hash;
        let public_key = remote_identity.get_public_key();
        let responder = tokio::spawn(async move {
            for _ in 0..2 {
                let TransportMessage::Rpc { query, response_tx } =
                    transport_rx.recv().await.expect("recall query")
                else {
                    panic!("expected recall query");
                };
                assert!(matches!(
                    query,
                    TransportQuery::RecallDestination { dest } if dest == destination_hash
                ));
                response_tx
                    .send(TransportQueryResponse::RecalledDestination(Some(
                        RecalledDestinationRpcEntry {
                            dest_hash: destination_hash,
                            public_key,
                            app_data: None,
                            ratchet: None,
                            hops: 1,
                            timestamp: 1.0,
                        },
                    )))
                    .unwrap();

                let TransportMessage::SendPacket {
                    request,
                    receipt,
                    result_tx,
                    ..
                } = transport_rx.recv().await.expect("packet send")
                else {
                    panic!("expected packet send");
                };
                assert!(receipt.is_none());
                raw_tx.send(request.raw).await.unwrap();
                result_tx.send(OutboundDispatchResult::Sent).unwrap();
            }
        });

        let mut handle = dummy_handle();
        handle.transport_tx = transport_tx;
        let options = SendOptions {
            create_receipt: false,
            ..SendOptions::default()
        };
        let mut packet = handle.outbound_packet(&destination, b"again", options);
        assert!(matches!(packet.resend().await, Err(SendError::NotSent)));

        let first = packet.send().await.unwrap();
        assert!(packet.is_sent());
        assert!(matches!(packet.send().await, Err(SendError::AlreadySent)));
        let second = packet.resend().await.unwrap();
        assert_ne!(first.packet_hash, second.packet_hash);

        let first_raw = raw_rx.recv().await.unwrap();
        let second_raw = raw_rx.recv().await.unwrap();
        assert_ne!(first_raw, second_raw);
        let inbound = Destination::new(
            Some(&remote_identity),
            Direction::In,
            DestType::Single,
            "resend.test",
        )
        .unwrap();
        for raw in [first_raw, second_raw] {
            let packed = rns_wire::packet::Packet::from_raw(&raw).unwrap();
            assert_eq!(
                inbound.decrypt(packed.data(), &remote_identity).unwrap(),
                b"again"
            );
        }
        responder.await.unwrap();
    }

    #[tokio::test]
    async fn send_to_reports_no_interface_without_returning_a_receipt() {
        let (transport_tx, mut transport_rx) = mpsc::channel::<TransportMessage>(2);
        let remote_identity = Identity::new();
        let destination = Destination::new(
            Some(&remote_identity),
            Direction::Out,
            DestType::Single,
            "send.none",
        )
        .unwrap();
        let destination_hash = destination.hash;
        let public_key = remote_identity.get_public_key();
        let responder = tokio::spawn(async move {
            let TransportMessage::Rpc { response_tx, .. } =
                transport_rx.recv().await.expect("recall query")
            else {
                panic!("expected recall query");
            };
            response_tx
                .send(TransportQueryResponse::RecalledDestination(Some(
                    RecalledDestinationRpcEntry {
                        dest_hash: destination_hash,
                        public_key,
                        app_data: None,
                        ratchet: None,
                        hops: 1,
                        timestamp: 1.0,
                    },
                )))
                .unwrap();
            let TransportMessage::SendPacket { result_tx, .. } =
                transport_rx.recv().await.expect("packet send")
            else {
                panic!("expected packet send");
            };
            result_tx.send(OutboundDispatchResult::NoInterface).unwrap();
        });

        let mut handle = dummy_handle();
        handle.transport_tx = transport_tx;
        assert!(matches!(
            handle
                .send_to(
                    &destination,
                    b"hello",
                    SendOptions {
                        timeout: Some(Duration::from_secs(1)),
                        ..SendOptions::default()
                    },
                )
                .await,
            Err(SendError::NoInterface)
        ));
        responder.await.unwrap();
    }

    #[tokio::test]
    async fn link_connect_config_preserves_explicit_override_and_recall_metadata() {
        let (transport_tx, mut transport_rx) = mpsc::channel::<TransportMessage>(1);
        let remote_identity = Identity::new();
        let remote_public_key = remote_identity.get_public_key();
        let destination_hash = [0x43; 16];
        let responder = tokio::spawn(async move {
            let TransportMessage::Rpc { query, response_tx } =
                transport_rx.recv().await.expect("recall query")
            else {
                panic!("expected transport RPC");
            };
            assert!(matches!(
                query,
                TransportQuery::RecallDestination { dest } if dest == destination_hash
            ));
            response_tx
                .send(TransportQueryResponse::RecalledDestination(Some(
                    RecalledDestinationRpcEntry {
                        dest_hash: destination_hash,
                        public_key: remote_public_key,
                        app_data: None,
                        ratchet: None,
                        hops: 7,
                        timestamp: 1_700_000_000.0,
                    },
                )))
                .expect("recall response receiver");
        });

        let mut handle = dummy_handle();
        handle.transport_tx = transport_tx;
        let options = LinkConnectOptions {
            path_timeout: Duration::from_secs(4),
            establishment_timeout: Some(Duration::ZERO),
            client_label: "example.client".to_string(),
            identify: true,
            track_phy_stats: true,
        };
        let config = handle
            .resolve_link_session_config(destination_hash, &options)
            .await
            .unwrap();
        assert_eq!(config.destination_hash, destination_hash);
        assert_eq!(config.remote_public_key, remote_public_key);
        assert_eq!(config.hops, 7);
        assert_eq!(config.establishment_timeout, Duration::ZERO);
        assert_eq!(config.client_label, "example.client");
        assert!(config.track_phy_stats);
        assert!(config.identify);
        responder.await.unwrap();
    }

    #[tokio::test]
    async fn link_connect_config_discovers_path_before_retrying_recall() {
        let (transport_tx, mut transport_rx) = mpsc::channel::<TransportMessage>(5);
        let remote_identity = Identity::new();
        let remote_public_key = remote_identity.get_public_key();
        let destination_hash = [0x44; 16];
        let responder = tokio::spawn(async move {
            let TransportMessage::Rpc { response_tx, .. } =
                transport_rx.recv().await.expect("first recall")
            else {
                panic!("expected transport RPC");
            };
            response_tx
                .send(TransportQueryResponse::RecalledDestination(None))
                .expect("first recall response");

            let TransportMessage::AwaitPath { dest, reply } =
                transport_rx.recv().await.expect("path discovery")
            else {
                panic!("expected path discovery");
            };
            assert_eq!(dest, destination_hash);
            reply.send(true).expect("path waiter");

            let TransportMessage::Rpc { response_tx, .. } =
                transport_rx.recv().await.expect("second recall")
            else {
                panic!("expected transport RPC");
            };
            response_tx
                .send(TransportQueryResponse::RecalledDestination(Some(
                    RecalledDestinationRpcEntry {
                        dest_hash: destination_hash,
                        public_key: remote_public_key,
                        app_data: None,
                        ratchet: None,
                        hops: 7,
                        timestamp: 1_700_000_001.0,
                    },
                )))
                .expect("second recall response");

            let TransportMessage::Rpc { query, response_tx } =
                transport_rx.recv().await.expect("hop query")
            else {
                panic!("expected transport RPC");
            };
            assert!(matches!(
                query,
                TransportQuery::HopsTo { dest } if dest == destination_hash
            ));
            response_tx
                .send(TransportQueryResponse::IntResult(2))
                .expect("hop response");

            let TransportMessage::Rpc { query, response_tx } =
                transport_rx.recv().await.expect("first-hop query")
            else {
                panic!("expected transport RPC");
            };
            assert!(matches!(
                query,
                TransportQuery::FirstHopTimeout { dest } if dest == destination_hash
            ));
            response_tx
                .send(TransportQueryResponse::FloatResult(Some(2.5)))
                .expect("first-hop response");
        });

        let mut handle = dummy_handle();
        handle.transport_tx = transport_tx;
        let config = handle
            .resolve_link_session_config(destination_hash, &LinkConnectOptions::default())
            .await
            .unwrap();
        assert_eq!(config.remote_public_key, remote_public_key);
        assert_eq!(
            config.hops, 2,
            "current authoritative hops must replace stale recalled metadata"
        );
        assert_eq!(config.establishment_timeout, Duration::from_secs_f64(14.5));
        responder.await.unwrap();
    }

    #[test]
    fn link_establishment_timeout_matches_python_hop_floor_and_scaling() {
        assert_eq!(
            link_establishment_timeout(Duration::from_secs_f64(1.25), 0).unwrap(),
            Duration::from_secs_f64(7.25)
        );
        assert_eq!(
            link_establishment_timeout(Duration::from_secs_f64(1.25), 1).unwrap(),
            Duration::from_secs_f64(7.25)
        );
        assert_eq!(
            link_establishment_timeout(Duration::from_secs_f64(1.25), 4).unwrap(),
            Duration::from_secs_f64(25.25)
        );
        assert_eq!(
            link_establishment_timeout(
                Duration::from_secs_f64(1.25),
                rns_transport::constants::PATHFINDER_M,
            )
            .unwrap(),
            Duration::from_secs_f64(769.25)
        );
        assert!(matches!(
            link_establishment_timeout(Duration::MAX, 1),
            Err(ControlError::UnexpectedResponse {
                operation: "Link establishment timeout derivation"
            })
        ));
    }

    #[tokio::test]
    async fn derived_link_timeout_propagates_control_failure() {
        let (transport_tx, mut transport_rx) = mpsc::channel::<TransportMessage>(1);
        let remote_identity = Identity::new();
        let remote_public_key = remote_identity.get_public_key();
        let destination_hash = [0x45; 16];
        let responder = tokio::spawn(async move {
            let TransportMessage::Rpc { response_tx, .. } =
                transport_rx.recv().await.expect("recall query")
            else {
                panic!("expected transport RPC");
            };
            response_tx
                .send(TransportQueryResponse::RecalledDestination(Some(
                    RecalledDestinationRpcEntry {
                        dest_hash: destination_hash,
                        public_key: remote_public_key,
                        app_data: None,
                        ratchet: None,
                        hops: 2,
                        timestamp: 1_700_000_002.0,
                    },
                )))
                .expect("recall response receiver");
        });

        let mut handle = dummy_handle();
        handle.transport_tx = transport_tx;
        assert!(matches!(
            handle
                .resolve_link_session_config(destination_hash, &LinkConnectOptions::default())
                .await,
            Err(LinkConnectError::Control(ControlError::ChannelClosed))
        ));
        responder.await.unwrap();
    }

    #[tokio::test]
    async fn send_to_rejects_oversized_single_payload_before_transport_work() {
        let destination_identity = Identity::new();
        let destination = Destination::new(
            Some(&destination_identity),
            Direction::Out,
            DestType::Single,
            "send.large",
        )
        .unwrap();
        let handle = dummy_handle();
        let payload = vec![0u8; rns_wire::constants::SINGLE_PACKET_ENCRYPTED_MDU + 1];

        assert!(matches!(
            handle
                .send_to(&destination, &payload, SendOptions::default())
                .await,
            Err(SendError::PayloadTooLarge { actual, max })
                if actual == payload.len()
                    && max == rns_wire::constants::SINGLE_PACKET_ENCRYPTED_MDU
        ));
    }

    #[tokio::test]
    async fn typed_path_queries_validate_and_filter_actor_responses() {
        let (transport_tx, mut transport_rx) = mpsc::channel::<TransportMessage>(7);
        let destination_hash = [0x51; 16];
        let responder = tokio::spawn(async move {
            for response in [
                TransportQueryResponse::BoolResult(true),
                TransportQueryResponse::IntResult(6),
                TransportQueryResponse::FloatResult(Some(1_000.0)),
                TransportQueryResponse::FloatResult(Some(1_000.0)),
                TransportQueryResponse::FloatResult(Some(1_000.0)),
                TransportQueryResponse::IntResult(1_024),
                TransportQueryResponse::PathTable(vec![
                    rns_transport::messages::PathTableRpcEntry {
                        hash: [0x61; 16],
                        timestamp: 1.0,
                        via: None,
                        hops: 2,
                        expires: 2.0,
                        interface: "short".to_string(),
                        interface_id: 1,
                        interface_mode: rns_transport::constants::InterfaceMode::Full,
                        interface_role: rns_transport::messages::InterfaceRole::Normal,
                    },
                    rns_transport::messages::PathTableRpcEntry {
                        hash: [0x62; 16],
                        timestamp: 1.0,
                        via: None,
                        hops: 8,
                        expires: 2.0,
                        interface: "long".to_string(),
                        interface_id: 2,
                        interface_mode: rns_transport::constants::InterfaceMode::Gateway,
                        interface_role: rns_transport::messages::InterfaceRole::Normal,
                    },
                ]),
            ] {
                let TransportMessage::Rpc { response_tx, .. } =
                    transport_rx.recv().await.expect("typed path query")
                else {
                    panic!("expected transport RPC");
                };
                response_tx.send(response).expect("path query receiver");
            }
        });

        let mut handle = dummy_handle();
        handle.transport_tx = transport_tx;
        assert!(handle.has_path(destination_hash).await.unwrap());
        assert_eq!(handle.hops_to(destination_hash).await.unwrap(), 6);
        assert_eq!(
            handle.next_hop_bitrate(destination_hash).await.unwrap(),
            Some(1_000)
        );
        assert_eq!(
            handle
                .next_hop_per_bit_latency(destination_hash)
                .await
                .unwrap(),
            Some(0.001)
        );
        assert_eq!(
            handle
                .next_hop_per_byte_latency(destination_hash)
                .await
                .unwrap(),
            Some(0.008)
        );
        assert_eq!(
            handle
                .next_hop_hardware_mtu(destination_hash)
                .await
                .unwrap(),
            Some(1_024)
        );
        let paths = handle.path_table(Some(4)).await.unwrap();
        assert_eq!(paths.len(), 1);
        assert_eq!(paths[0].hash, [0x61; 16]);
        responder.await.unwrap();
    }

    #[tokio::test]
    async fn local_transport_query_deadline_includes_channel_submission() {
        let timeout = Duration::from_millis(40);
        let (transport_tx, transport_rx) = mpsc::channel::<TransportMessage>(1);
        transport_tx
            .send(TransportMessage::Shutdown)
            .await
            .expect("prefill actor channel");

        let mut handle = dummy_handle();
        handle.transport_tx = transport_tx;
        let started = std::time::Instant::now();
        let result = handle
            .query_transport_result_with_timeout(TransportQuery::GetPathTable, timeout)
            .await;

        assert!(matches!(result, Err(ControlError::Timeout(t)) if t == timeout));
        assert!(started.elapsed() < Duration::from_secs(1));
        drop(transport_rx);
    }

    #[tokio::test]
    async fn local_transport_query_deadline_includes_response_wait() {
        let timeout = Duration::from_millis(40);
        let (transport_tx, mut transport_rx) = mpsc::channel::<TransportMessage>(1);
        let responder = tokio::spawn(async move {
            let TransportMessage::Rpc { response_tx, .. } =
                transport_rx.recv().await.expect("transport query")
            else {
                panic!("expected transport RPC");
            };
            std::future::pending::<()>().await;
            drop(response_tx);
        });

        let mut handle = dummy_handle();
        handle.transport_tx = transport_tx;
        let result = handle
            .query_transport_result_with_timeout(TransportQuery::GetPathTable, timeout)
            .await;

        assert!(matches!(result, Err(ControlError::Timeout(t)) if t == timeout));
        responder.abort();
    }

    #[tokio::test]
    async fn request_path_forwards_explicit_transport_options() {
        let (transport_tx, mut transport_rx) = mpsc::channel::<TransportMessage>(1);
        let mut handle = dummy_handle();
        handle.transport_tx = transport_tx;
        let destination_hash = [0x63; 16];
        let options = PathRequestOptions {
            on_interface: Some(7),
            tag: Some(vec![0xAA; 16]),
            recursive: true,
        };

        handle
            .request_path(destination_hash, options.clone())
            .await
            .unwrap();

        let TransportMessage::RequestPathWithOptions {
            destination_hash: received_hash,
            options: received_options,
        } = transport_rx.try_recv().unwrap()
        else {
            panic!("expected path request command");
        };
        assert_eq!(received_hash, destination_hash);
        assert_eq!(received_options, options);
    }

    #[tokio::test]
    async fn typed_interface_stats_normalize_totals_and_optional_metadata() {
        let (transport_tx, mut transport_rx) = mpsc::channel::<TransportMessage>(1);
        let first = rns_transport::messages::InterfaceStatRpcEntry {
            id: 1,
            name: "one".to_string(),
            rx_bytes: 10,
            tx_bytes: 20,
            rx_rate: 2,
            tx_rate: 3,
            online: true,
            bitrate: 115_200,
            mtu: 500,
            mode: "Full".to_string(),
            role: "normal".to_string(),
            announce_queue: Some(0),
            held_announces: 0,
            incoming_announce_frequency: 0.0,
            outgoing_announce_frequency: 0.0,
            incoming_pr_frequency: 0.0,
            outgoing_pr_frequency: 0.0,
            burst_active: false,
            burst_activated: 0.0,
            pr_burst_active: false,
            pr_burst_activated: 0.0,
            clients: None,
            blocked_ips: None,
            announce_rate_target: None,
            announce_rate_grace: None,
            announce_rate_penalty: None,
            announce_cap: 0.02,
            ifac_size: 0,
            tx_drops: 0,
        };
        let mut second = first.clone();
        second.id = 2;
        second.name = "two".to_string();
        second.rx_bytes = 30;
        second.tx_bytes = 40;
        second.rx_rate = 4;
        second.tx_rate = 5;
        let responder = tokio::spawn(async move {
            let TransportMessage::Rpc { response_tx, .. } =
                transport_rx.recv().await.expect("interface stats query")
            else {
                panic!("expected transport RPC");
            };
            response_tx
                .send(TransportQueryResponse::InterfaceStats(vec![first, second]))
                .expect("interface stats receiver");
        });

        let mut handle = dummy_handle();
        handle.transport_tx = transport_tx;
        handle.config.enable_transport = true;
        handle.network_identity = Some(Arc::new(Identity::new()));
        handle.started_at = std::time::Instant::now() - Duration::from_secs(2);
        let expected_transport_id = handle.transport_identity.hash;
        let expected_network_id = handle.network_identity.as_ref().unwrap().hash;

        let stats = handle.interface_stats().await.unwrap();
        assert_eq!(stats.interfaces.len(), 2);
        assert_eq!(stats.rx_bytes, 40);
        assert_eq!(stats.tx_bytes, 60);
        assert_eq!(stats.rx_rate, 6);
        assert_eq!(stats.tx_rate, 8);
        assert_eq!(stats.transport_id, Some(expected_transport_id));
        assert_eq!(stats.network_id, Some(expected_network_id));
        assert!(stats.transport_uptime.unwrap() >= Duration::from_secs(2));
        assert_eq!(stats.probe_responder, None);
        assert_eq!(stats.rss_bytes, None);
        responder.await.unwrap();
    }

    #[tokio::test]
    async fn client_control_failures_never_enqueue_local_actor_work() {
        let (transport_tx, mut transport_rx) = mpsc::channel::<TransportMessage>(1);
        let mut handle = dummy_handle();
        handle.transport_tx = transport_tx;
        handle.instance_mode = InstanceMode::Client;
        handle.config.shared_instance_type = SharedInstanceType::Tcp;
        handle.config.control_port = 0;
        handle.config.rpc_key = Some(vec![0xA5; 32]);

        let read = tokio::time::timeout(
            Duration::from_secs(1),
            handle.query_control(TransportQuery::GetInterfaceStats),
        )
        .await
        .expect("failed shared read must be bounded");
        assert!(read.is_none());
        let mutation = tokio::time::timeout(
            Duration::from_secs(1),
            handle.query_control(TransportQuery::DropPath { dest: [0x52; 16] }),
        )
        .await
        .expect("failed shared mutation must be bounded");
        assert!(mutation.is_none());
        assert!(
            transport_rx.try_recv().is_err(),
            "failed mapped client queries must not enqueue local actor work"
        );
    }

    #[tokio::test]
    async fn strict_client_control_rejects_unmapped_queries_without_local_work() {
        let (transport_tx, mut transport_rx) = mpsc::channel::<TransportMessage>(1);
        let mut handle = dummy_handle();
        handle.transport_tx = transport_tx;
        handle.instance_mode = InstanceMode::Client;

        for query in [
            TransportQuery::GetRecentAnnounces,
            TransportQuery::DropPathTable,
            TransportQuery::DropRecentAnnounces,
        ] {
            assert!(matches!(
                handle.query_control_result(query).await,
                Err(ControlError::UnsupportedBySharedInstance)
            ));
        }
        assert!(
            transport_rx.try_recv().is_err(),
            "unsupported strict client query must not enqueue local actor work"
        );
    }

    #[tokio::test]
    async fn typed_client_path_metrics_use_authoritative_shared_data() {
        let (port, _) = free_tcp_port_pair().await;
        let rpc_key = vec![0xA6; 32];
        let destination_hash = [0x53; 16];
        let missing_mtu_destination = [0x55; 16];
        let ambiguous_destination = [0x56; 16];
        let interface_name = "authoritative-link".to_string();
        let missing_mtu_interface_name = "python-interface-without-mtu".to_string();
        let ambiguous_interface_name = "duplicate-name".to_string();
        let master_path = rns_transport::messages::PathTableRpcEntry {
            hash: destination_hash,
            timestamp: 1.0,
            via: Some([0x54; 16]),
            hops: 6,
            expires: 2.0,
            interface: interface_name.clone(),
            interface_id: 81,
            interface_mode: rns_transport::constants::InterfaceMode::Full,
            interface_role: rns_transport::messages::InterfaceRole::Normal,
        };
        let master_interface = rns_transport::messages::InterfaceStatRpcEntry {
            id: 81,
            name: interface_name.clone(),
            rx_bytes: 0,
            tx_bytes: 0,
            rx_rate: 0,
            tx_rate: 0,
            online: true,
            bitrate: 128_000,
            mtu: 1_200,
            mode: "Full".to_string(),
            role: "normal".to_string(),
            announce_queue: Some(0),
            held_announces: 0,
            incoming_announce_frequency: 0.0,
            outgoing_announce_frequency: 0.0,
            incoming_pr_frequency: 0.0,
            outgoing_pr_frequency: 0.0,
            burst_active: false,
            burst_activated: 0.0,
            pr_burst_active: false,
            pr_burst_activated: 0.0,
            clients: None,
            blocked_ips: None,
            announce_rate_target: None,
            announce_rate_grace: None,
            announce_rate_penalty: None,
            announce_cap: 0.02,
            ifac_size: 0,
            tx_drops: 0,
        };
        let mut missing_mtu_interface = master_interface.clone();
        missing_mtu_interface.id = 82;
        missing_mtu_interface.name = missing_mtu_interface_name.clone();
        missing_mtu_interface.mtu = 0;
        let mut ambiguous_interface_a = master_interface.clone();
        ambiguous_interface_a.id = 83;
        ambiguous_interface_a.name = ambiguous_interface_name.clone();
        ambiguous_interface_a.bitrate = 64_000;
        ambiguous_interface_a.mtu = 900;
        let mut ambiguous_interface_b = ambiguous_interface_a.clone();
        ambiguous_interface_b.id = 84;
        ambiguous_interface_b.bitrate = 32_000;
        ambiguous_interface_b.mtu = 800;
        let master_interfaces = vec![
            master_interface,
            missing_mtu_interface,
            ambiguous_interface_a,
            ambiguous_interface_b,
        ];

        let (master_tx, mut master_rx) = mpsc::channel::<TransportMessage>(4);
        let master_responder = tokio::spawn(async move {
            while let Some(message) = master_rx.recv().await {
                let TransportMessage::Rpc { query, response_tx } = message else {
                    panic!("shared control server sent non-RPC actor work");
                };
                let response = match query {
                    TransportQuery::GetPathTable => {
                        TransportQueryResponse::PathTable(vec![master_path.clone()])
                    }
                    TransportQuery::GetNextHopIfName { dest } => {
                        let name = if dest == destination_hash {
                            interface_name.clone()
                        } else if dest == missing_mtu_destination {
                            missing_mtu_interface_name.clone()
                        } else if dest == ambiguous_destination {
                            ambiguous_interface_name.clone()
                        } else {
                            panic!("unexpected next-hop destination")
                        };
                        TransportQueryResponse::StringResult(Some(name))
                    }
                    TransportQuery::GetInterfaceStats => {
                        TransportQueryResponse::InterfaceStats(master_interfaces.clone())
                    }
                    other => panic!("unexpected authoritative query: {other:?}"),
                };
                response_tx
                    .send(response)
                    .expect("shared control response receiver");
            }
        });
        let rpc_shutdown = ShutdownSignal::new();
        let server_shutdown = rpc_shutdown.clone();
        let server_key = rpc_key.clone();
        let server = tokio::spawn(async move {
            crate::rpc_server::run_rpc_server(port, server_key, master_tx, server_shutdown).await
        });

        let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        loop {
            match tokio::net::TcpStream::connect(("127.0.0.1", port)).await {
                Ok(stream) => {
                    drop(stream);
                    break;
                }
                Err(_) if tokio::time::Instant::now() < deadline => {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
                Err(error) => panic!("shared control server did not start: {error}"),
            }
        }

        let (local_tx, mut local_rx) = mpsc::channel::<TransportMessage>(4);
        let local_query_count = Arc::new(AtomicU64::new(0));
        let observed_local_queries = Arc::clone(&local_query_count);
        let local_responder = tokio::spawn(async move {
            while let Some(message) = local_rx.recv().await {
                let TransportMessage::Rpc { query, response_tx } = message else {
                    continue;
                };
                observed_local_queries.fetch_add(1, Ordering::Relaxed);
                let response = match query {
                    TransportQuery::HasPath { .. } => TransportQueryResponse::BoolResult(false),
                    TransportQuery::HopsTo { .. } => TransportQueryResponse::IntResult(99),
                    TransportQuery::GetNextHopBitrate { .. } => {
                        TransportQueryResponse::FloatResult(Some(9.0))
                    }
                    TransportQuery::GetNextHopHardwareMtu { .. } => {
                        TransportQueryResponse::IntResult(9)
                    }
                    other => panic!("unexpected local query: {other:?}"),
                };
                response_tx
                    .send(response)
                    .expect("local control response receiver");
            }
        });

        let mut handle = dummy_handle();
        handle.transport_tx = local_tx;
        handle.instance_mode = InstanceMode::Client;
        handle.config.shared_instance_type = SharedInstanceType::Tcp;
        handle.config.control_port = port;
        handle.config.rpc_key = Some(rpc_key);

        assert!(handle.has_path(destination_hash).await.unwrap());
        assert_eq!(handle.hops_to(destination_hash).await.unwrap(), 6);
        assert_eq!(
            handle.next_hop_bitrate(destination_hash).await.unwrap(),
            Some(128_000)
        );
        assert_eq!(
            handle
                .next_hop_hardware_mtu(destination_hash)
                .await
                .unwrap(),
            Some(1_200)
        );
        assert_eq!(
            handle
                .next_hop_per_bit_latency(destination_hash)
                .await
                .unwrap(),
            Some(1.0 / 128_000.0)
        );
        assert_eq!(
            handle
                .next_hop_per_byte_latency(destination_hash)
                .await
                .unwrap(),
            Some(8.0 / 128_000.0)
        );
        assert_eq!(
            handle
                .next_hop_hardware_mtu(missing_mtu_destination)
                .await
                .unwrap(),
            None,
            "Python-compatible stats without MTU must remain unknown"
        );
        assert_eq!(
            handle
                .next_hop_bitrate(ambiguous_destination)
                .await
                .unwrap(),
            None,
            "duplicate interface names must not select an arbitrary bitrate"
        );
        assert_eq!(
            handle
                .next_hop_hardware_mtu(ambiguous_destination)
                .await
                .unwrap(),
            None,
            "duplicate interface names must not select an arbitrary MTU"
        );
        assert_eq!(
            handle
                .next_hop_per_bit_latency(ambiguous_destination)
                .await
                .unwrap(),
            None,
            "duplicate interface names must not select an arbitrary latency"
        );
        assert_eq!(
            local_query_count.load(Ordering::Relaxed),
            0,
            "typed client metrics must ignore divergent local actor state"
        );

        rpc_shutdown.trigger();
        server.await.unwrap().unwrap();
        master_responder.abort();
        local_responder.abort();
    }

    struct StaticStamper;
    impl DiscoveryStamper for StaticStamper {
        fn generate(&self, _infohash: &[u8; 32], _target_value: u8) -> Option<Vec<u8>> {
            Some(vec![0xAB; 32])
        }
        fn value(&self, _infohash: &[u8; 32], _stamp: &[u8]) -> u8 {
            16
        }
        fn valid(&self, _infohash: &[u8; 32], _stamp: &[u8], required_value: u8) -> bool {
            required_value <= 16
        }
    }

    #[tokio::test]
    async fn discovery_disabled_by_default() {
        let h = dummy_handle();
        assert!(!h.discovery_enabled().await);
        assert!(h.discovered_interfaces().await.is_empty());
        assert!(h.blackhole_sources().is_empty());
    }

    #[tokio::test]
    async fn enable_on_network_discovery_installs_stamper() {
        let h = dummy_handle();
        h.enable_on_network_discovery(Arc::new(StaticStamper)).await;
        assert!(h.discovery_enabled().await);
    }

    #[tokio::test]
    async fn enable_overrides_previous_stamper_without_error() {
        let h = dummy_handle();
        h.enable_on_network_discovery(Arc::new(StaticStamper)).await;
        h.enable_on_network_discovery(Arc::new(StaticStamper)).await;
        assert!(h.discovery_enabled().await);
    }

    #[tokio::test]
    async fn discovered_interfaces_reads_from_installed_store() {
        let dir = std::env::temp_dir().join(format!(
            "reticulum_rs_runtime_discovery_store_{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let store = Arc::new(DiscoveryStore::open(&dir).unwrap());
        let h = dummy_handle();
        h.install_discovery_store_for_tests(store.clone()).await;

        let v = h.discovered_interfaces().await;
        assert_eq!(v.len(), 0);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn blackhole_sources_surfaces_config_value() {
        let mut h = dummy_handle();
        h.config.blackhole_sources = vec![[0xAA; 16], [0xBB; 16]];
        assert_eq!(h.blackhole_sources().len(), 2);
        assert_eq!(h.blackhole_sources()[0], [0xAA; 16]);
    }

    #[test]
    fn test_discovery_defaults_are_off() {
        let rc = ReticulumConfig::default();
        assert!(!rc.discover_interfaces);
        assert_eq!(rc.autoconnect_discovered_interfaces, 0);
        assert_eq!(
            rc.discover_interfaces_required_value,
            rns_transport::discovery::DEFAULT_STAMP_VALUE
        );
        assert_eq!(rc.network_identity_path, None);
        assert!(rc.interface_discovery_sources.is_empty());
        assert!(rc.blackhole_sources.is_empty());
        assert!(!rc.publish_blackhole);
        assert!(rc.bootstrap_configs.is_empty());
    }

    #[test]
    fn test_discovery_keys_parsed() {
        let input = "[reticulum]\n\
                     discover_interfaces = Yes\n\
                     autoconnect_discovered_interfaces = 2\n\
                     required_discovery_value = 16\n\
                     interface_discovery_sources = 521c87a83afb8f29e4455e77930b973b\n\
                     default_ar_target = 7200\n\
                     default_ar_penalty = 30\n\
                     default_ar_grace = 9\n\
                     publish_blackhole = Yes\n\
                     network_identity = /opt/rnsd/network.identity\n";
        let config = Config::parse(input).unwrap();
        let rc = ReticulumConfig::from_config(&config);
        assert!(rc.discover_interfaces);
        assert_eq!(rc.autoconnect_discovered_interfaces, 2);
        assert_eq!(rc.discover_interfaces_required_value, 16);
        assert_eq!(rc.interface_discovery_sources.len(), 1);
        assert_eq!(rc.default_ar_target, Some(7200));
        assert_eq!(rc.default_ar_penalty, Some(30));
        assert_eq!(rc.default_ar_grace, Some(9));
        assert!(rc.publish_blackhole);
        assert_eq!(
            rc.network_identity_path,
            Some(PathBuf::from("/opt/rnsd/network.identity"))
        );
    }

    #[test]
    fn test_global_ingress_control_keys_parsed() {
        let input = "[reticulum]\n\
                     ic_max_held_announces = 64\n\
                     ic_burst_hold = 11.5\n\
                     ic_burst_freq_new = 2.5\n\
                     ic_burst_freq = 12.5\n\
                     ic_pr_burst_freq_new = 4.5\n\
                     ic_pr_burst_freq = 9.5\n\
                     ec_pr_freq = 6.5\n\
                     egress_control = Yes\n\
                     ic_new_time = 1234\n\
                     ic_burst_penalty = 17.5\n\
                     ic_held_release_interval = 3.5\n";
        let config = Config::parse(input).unwrap();
        let rc = ReticulumConfig::from_config(&config);

        assert_eq!(rc.ingress_overrides.max_held, Some(64));
        assert_eq!(rc.ingress_overrides.burst_hold, Some(11.5));
        assert_eq!(rc.ingress_overrides.burst_freq_new, Some(2.5));
        assert_eq!(rc.ingress_overrides.burst_freq, Some(12.5));
        assert_eq!(rc.ingress_overrides.pr_burst_freq_new, Some(4.5));
        assert_eq!(rc.ingress_overrides.pr_burst_freq, Some(9.5));
        assert_eq!(rc.ingress_overrides.ec_pr_freq, Some(6.5));
        assert_eq!(rc.ingress_overrides.egress_control, Some(true));
        assert_eq!(rc.ingress_overrides.new_time, Some(1234.0));
        assert_eq!(rc.ingress_overrides.burst_penalty, Some(17.5));
        assert_eq!(rc.ingress_overrides.held_release_interval, Some(3.5));
    }

    /// Python Reticulum.py:841-848 parity: discoverable interfaces are
    /// auto-corrected to Gateway/AP mode unless already Internal or
    /// `ignore_config_warnings` is enabled.
    #[test]
    fn discovery_mode_autocorrect_matches_python() {
        use rns_interface::traits::InterfaceMode;

        let input = "[interfaces]\n\
                     [[upstream]]\n\
                     type = TCPServerInterface\n\
                     listen_ip = 0.0.0.0\n\
                     listen_port = 4242\n\
                     discoverable = yes\n";
        let config = Config::parse(input).unwrap();
        let mut interfaces = synthesize_interfaces(&config, false).unwrap();
        apply_discovery_mode_autocorrect(&config, &mut interfaces[0]);
        match &interfaces[0] {
            interface_factory::InterfaceConfig::TcpServer(c) => {
                assert_eq!(c.mode, InterfaceMode::Gateway);
            }
            _ => panic!("expected TcpServer"),
        }

        let opted_out = "[interfaces]\n\
                         [[upstream]]\n\
                         type = TCPServerInterface\n\
                         listen_ip = 0.0.0.0\n\
                         listen_port = 4242\n\
                         discoverable = yes\n\
                         ignore_config_warnings = yes\n";
        let config = Config::parse(opted_out).unwrap();
        let mut interfaces = synthesize_interfaces(&config, false).unwrap();
        apply_discovery_mode_autocorrect(&config, &mut interfaces[0]);
        match &interfaces[0] {
            interface_factory::InterfaceConfig::TcpServer(c) => {
                assert_eq!(c.mode, InterfaceMode::Full, "opt-out keeps configured mode");
            }
            _ => panic!("expected TcpServer"),
        }
    }

    #[test]
    fn ingress_control_precedence_global_then_interface() {
        let input = r#"
[reticulum]
ic_burst_freq = 12
ic_pr_burst_freq = 9
ec_pr_freq = 7
egress_control = No

[interfaces]

[[Test TCP]]
type = TCPClientInterface
target_host = 127.0.0.1
target_port = 4242
ic_pr_burst_freq = 5
egress_control = Yes
"#;
        let config = Config::parse(input).unwrap();
        let rc = ReticulumConfig::from_config(&config);
        let interfaces = synthesize_interfaces(&config, false).unwrap();
        let mut post_init = get_post_init_for_config(&config, &interfaces[0]);

        finalize_post_init(&mut post_init, &rc);

        assert_eq!(post_init.ingress_overrides.burst_freq, Some(12.0));
        assert_eq!(post_init.ingress_overrides.ec_pr_freq, Some(7.0));
        assert_eq!(post_init.ingress_overrides.pr_burst_freq, Some(5.0));
        assert_eq!(post_init.ingress_overrides.egress_control, Some(true));
    }

    #[test]
    fn test_network_identity_path_follows_python_expanduser_only_policy() {
        let config = Config::parse("[reticulum]\nnetwork_identity = network.identity\n").unwrap();
        let rc = ReticulumConfig::from_config(&config);
        assert_eq!(
            rc.network_identity_path,
            Some(PathBuf::from("network.identity"))
        );

        if let Ok(home) = std::env::var("HOME") {
            let config =
                Config::parse("[reticulum]\nnetwork_identity = ~/network.identity\n").unwrap();
            let rc = ReticulumConfig::from_config(&config);
            assert_eq!(
                rc.network_identity_path,
                Some(PathBuf::from(home).join("network.identity"))
            );
        }
    }

    #[test]
    fn static_transport_identity_key_parses_with_python_default() {
        let rc = ReticulumConfig::from_config(&Config::parse("[reticulum]\n").unwrap());
        assert!(!rc.static_transport_identity);
        assert!(uses_ephemeral_transport_identity(&rc));

        let rc = ReticulumConfig::from_config(
            &Config::parse("[reticulum]\nstatic_transport_identity = yes\n").unwrap(),
        );
        assert!(rc.static_transport_identity);
        assert!(!uses_ephemeral_transport_identity(&rc));

        // Python Transport.py:234-238: transport nodes never rotate.
        let rc = ReticulumConfig::from_config(
            &Config::parse("[reticulum]\nenable_transport = yes\n").unwrap(),
        );
        assert!(!uses_ephemeral_transport_identity(&rc));

        let rc = ReticulumConfig::from_config(
            &Config::parse(
                "[reticulum]\nenable_transport = yes\nstatic_transport_identity = yes\n",
            )
            .unwrap(),
        );
        assert!(!uses_ephemeral_transport_identity(&rc));
    }

    #[test]
    fn local_hops_delta_key_parses_with_python_default() {
        let rc = ReticulumConfig::from_config(&Config::parse("[reticulum]\n").unwrap());
        assert!(!rc.local_hops_delta);

        let rc = ReticulumConfig::from_config(
            &Config::parse("[reticulum]\nlocal_hops_delta = yes\n").unwrap(),
        );
        assert!(rc.local_hops_delta);
    }

    #[test]
    fn local_hops_delta_value_stays_in_python_range() {
        // Python Transport.py:240: (rand_byte % 6) + 2 = 2..=7.
        for _ in 0..256 {
            let delta = generate_local_hops_delta();
            assert!((2..=7).contains(&delta), "delta {delta} out of range");
        }
    }

    #[test]
    fn blackhole_update_interval_parses_minutes_with_two_minute_clamp() {
        let rc = ReticulumConfig::from_config(&Config::parse("[reticulum]\n").unwrap());
        assert_eq!(rc.blackhole_update_interval, 3600.0);

        // Reticulum.py:593-596: minutes ×60 into seconds.
        let rc = ReticulumConfig::from_config(
            &Config::parse("[reticulum]\nblackhole_update_interval = 30\n").unwrap(),
        );
        assert_eq!(rc.blackhole_update_interval, 1800.0);

        let rc = ReticulumConfig::from_config(
            &Config::parse("[reticulum]\nblackhole_update_interval = 2.5\n").unwrap(),
        );
        assert_eq!(rc.blackhole_update_interval, 150.0);

        // Sub-2-minute values clamp to the 2-minute floor.
        let rc = ReticulumConfig::from_config(
            &Config::parse("[reticulum]\nblackhole_update_interval = 1\n").unwrap(),
        );
        assert_eq!(rc.blackhole_update_interval, 120.0);
    }

    #[test]
    fn logtimestamps_key_parses_with_python_default() {
        let rc = ReticulumConfig::from_config(&Config::parse("[logging]\n").unwrap());
        assert!(rc.log_timestamps);

        let rc = ReticulumConfig::from_config(
            &Config::parse("[logging]\nlogtimestamps = no\n").unwrap(),
        );
        assert!(!rc.log_timestamps);

        let rc = ReticulumConfig::from_config(
            &Config::parse("[logging]\nlogtimestamps = yes\n").unwrap(),
        );
        assert!(rc.log_timestamps);
    }

    #[test]
    fn post_init_parses_recursive_prs_and_announces_from_internal() {
        let post_init = interface_factory::InterfacePostInit::from_section(&ConfigSection::new());
        assert!(!post_init.recursive_prs);
        assert!(post_init.announces_from_internal);

        let mut section = ConfigSection::new();
        section.set("recursive_prs", "yes");
        section.set("announces_from_internal", "no");
        let post_init = interface_factory::InterfacePostInit::from_section(&section);
        assert!(post_init.recursive_prs);
        assert!(!post_init.announces_from_internal);
    }

    #[test]
    fn internal_interface_mode_parses_and_discovery_autocorrects() {
        // Python 1.3.8 Reticulum.py:721,737-738: mode = internal → MODE_INTERNAL.
        let base = "[interfaces]\n\n[[Test TCP]]\ntype = TCPClientInterface\n\
                    target_host = 127.0.0.1\ntarget_port = 4242\nmode = internal\n";
        let config = Config::parse(base).unwrap();
        let mut interfaces = synthesize_interfaces(&config, false).unwrap();
        assert_eq!(
            *interface_config_mode_mut(&mut interfaces[0]),
            rns_interface::traits::InterfaceMode::Internal
        );

        // Reticulum.py:856-863 in RNS 1.4.0: Internal is a supported
        // discovery mode and must not be auto-corrected.
        let config = Config::parse(&format!("{base}discoverable = yes\n")).unwrap();
        let mut interfaces = synthesize_interfaces(&config, false).unwrap();
        apply_discovery_mode_autocorrect(&config, &mut interfaces[0]);
        assert_eq!(
            *interface_config_mode_mut(&mut interfaces[0]),
            rns_interface::traits::InterfaceMode::Internal
        );

        let config = Config::parse(&format!(
            "{base}discoverable = yes\nignore_config_warnings = yes\n"
        ))
        .unwrap();
        let mut interfaces = synthesize_interfaces(&config, false).unwrap();
        apply_discovery_mode_autocorrect(&config, &mut interfaces[0]);
        assert_eq!(
            *interface_config_mode_mut(&mut interfaces[0]),
            rns_interface::traits::InterfaceMode::Internal
        );
    }

    #[tokio::test]
    async fn failed_registration_rolls_back_task_control_and_online_state() {
        let (transport_tx, transport_rx) = mpsc::channel::<TransportMessage>(1);
        drop(transport_rx);
        let interface_controls: InterfaceControlMap =
            Arc::new(std::sync::Mutex::new(HashMap::new()));
        let interface_registry = InterfaceRegistry::default();
        let handle = test_interface_handle(920_090, None, "rollback");
        let online = handle.online.clone();

        let result = register_interface_handle(
            &transport_tx,
            handle,
            &interface_controls,
            &interface_registry,
        )
        .await;
        assert!(matches!(
            result,
            Err(InterfaceRegistrationError::TransportClosed { id: 920_090 })
        ));
        assert!(!online.load(Ordering::SeqCst));
        assert!(
            interface_controls
                .lock()
                .expect("interface_controls mutex poisoned")
                .is_empty()
        );

        let replacement = interface_registry
            .reserve(
                920_090,
                InterfaceKind::Standard,
                tokio::spawn(std::future::pending()),
                None,
            )
            .expect("rollback must release the exact reservation");
        replacement.rollback().await;
    }

    #[tokio::test]
    async fn batch_duplicate_rolls_back_prepared_and_unprocessed_handles() {
        let (transport_tx, mut transport_rx) = mpsc::channel::<TransportMessage>(4);
        let interface_controls: InterfaceControlMap =
            Arc::new(std::sync::Mutex::new(HashMap::new()));
        let interface_registry = InterfaceRegistry::default();
        let first = test_interface_handle(920_091, None, "batch-first");
        let duplicate = test_interface_handle(920_091, None, "batch-duplicate");
        let remaining = test_interface_handle(920_092, None, "batch-remaining");
        let online = [
            first.online.clone(),
            duplicate.online.clone(),
            remaining.online.clone(),
        ];
        let post_init = interface_factory::InterfacePostInit::from_section(&ConfigSection::new());

        let result = register_interfaces_with_post_init_batch(
            &transport_tx,
            vec![first.into(), duplicate.into(), remaining.into()],
            &post_init,
            None,
            &interface_controls,
            &interface_registry,
            InterfaceKind::Standard,
            None,
        )
        .await;
        assert!(matches!(
            result,
            Err(InterfaceRegistrationError::Duplicate { id: 920_091 })
        ));
        assert!(online.iter().all(|flag| !flag.load(Ordering::SeqCst)));
        assert!(
            interface_controls
                .lock()
                .expect("interface_controls mutex poisoned")
                .is_empty()
        );
        assert!(transport_rx.try_recv().is_err());

        for id in [920_091, 920_092] {
            let replacement = interface_registry
                .reserve(
                    id,
                    InterfaceKind::Standard,
                    tokio::spawn(std::future::pending()),
                    None,
                )
                .expect("batch rollback must release every reservation");
            replacement.rollback().await;
        }
    }

    #[tokio::test]
    async fn teardown_stops_exact_task_before_deregister_and_allows_reuse() {
        struct Dropped(Arc<AtomicBool>);
        impl Drop for Dropped {
            fn drop(&mut self) {
                self.0.store(true, Ordering::Release);
            }
        }

        let id = 920_093;
        let (transport_tx, mut transport_rx) = mpsc::channel::<TransportMessage>(4);
        let interface_controls: InterfaceControlMap =
            Arc::new(std::sync::Mutex::new(HashMap::new()));
        let interface_registry = InterfaceRegistry::default();
        let stopped = Arc::new(AtomicBool::new(false));
        let stopped_task = stopped.clone();
        let mut interface = test_interface_handle(id, None, "teardown");
        interface.read_task = tokio::spawn(async move {
            let _dropped = Dropped(stopped_task);
            std::future::pending::<()>().await;
        });
        tokio::task::yield_now().await;

        register_interface_handle(
            &transport_tx,
            interface,
            &interface_controls,
            &interface_registry,
        )
        .await
        .unwrap();
        assert!(matches!(
            transport_rx.recv().await,
            Some(TransportMessage::RegisterInterface {
                id: registered_id,
                ..
            }) if registered_id == id
        ));

        let mut runtime = dummy_handle();
        runtime.transport_tx = transport_tx;
        runtime.interface_controls = interface_controls.clone();
        runtime.interface_registry = interface_registry.clone();
        teardown_interface(&runtime, id).await;

        assert!(stopped.load(Ordering::Acquire));
        assert!(matches!(
            transport_rx.recv().await,
            Some(TransportMessage::DeregisterInterface {
                id: deregistered_id
            }) if deregistered_id == id
        ));
        assert!(
            interface_controls
                .lock()
                .expect("interface_controls mutex poisoned")
                .is_empty()
        );
        let replacement = interface_registry
            .reserve(
                id,
                InterfaceKind::Standard,
                tokio::spawn(std::future::pending()),
                None,
            )
            .expect("completed teardown must release the exact reservation");
        replacement.rollback().await;
    }

    #[cfg(feature = "rnode-tcp")]
    #[tokio::test]
    async fn observed_rnode_registration_rollback_requests_exact_driver_shutdown() {
        let id = 920_193;
        let (port, closed_rx, peer) = test_rnode_tcp_peer();
        let config = rns_interface::rnode::RNodeConfig::new("rollback-rnode", &port);
        let (transport_tx, transport_rx) = mpsc::channel::<TransportMessage>(1);
        drop(transport_rx);
        let spawned = rns_interface::rnode::spawn_rnode_interface_with_driver(
            config,
            id,
            transport_tx.clone(),
        )
        .await
        .expect("spawn observed RNode");
        let driver = spawned.driver.watch();
        let interface_controls: InterfaceControlMap =
            Arc::new(std::sync::Mutex::new(HashMap::new()));
        let interface_registry = InterfaceRegistry::default();

        let result = register_observed_rnode_handle_with_kind(
            &transport_tx,
            spawned,
            &interface_controls,
            &interface_registry,
            InterfaceKind::RNode,
        )
        .await;
        assert!(matches!(
            result,
            Err(InterfaceRegistrationError::TransportClosed { id: failed_id })
                if failed_id == id
        ));
        assert_exact_rnode_stopped(&driver);
        let observed = closed_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("exact rollback did not close the RNode peer");
        assert!(
            observed.ends_with(&rns_interface::rnode::build_detach_sequence()),
            "exact rollback must send the RNode detach sequence"
        );
        peer.join().unwrap();
        assert_eq!(interface_registry.len(), 0);
        assert!(
            interface_controls
                .lock()
                .expect("interface_controls mutex poisoned")
                .is_empty()
        );
    }

    #[cfg(feature = "rnode-tcp")]
    #[tokio::test]
    async fn same_id_observed_rnode_teardown_is_registry_local() {
        let id = 920_194;
        let (first_port, first_closed_rx, first_peer) = test_rnode_tcp_peer();
        let (second_port, second_closed_rx, second_peer) = test_rnode_tcp_peer();
        let (first_transport_tx, mut first_transport_rx) = mpsc::channel::<TransportMessage>(4);
        let (second_transport_tx, mut second_transport_rx) = mpsc::channel::<TransportMessage>(4);
        let first_spawned = rns_interface::rnode::spawn_rnode_interface_with_driver(
            rns_interface::rnode::RNodeConfig::new("same-id-first", &first_port),
            id,
            first_transport_tx.clone(),
        )
        .await
        .expect("spawn first observed RNode");
        let first_driver = first_spawned.driver.watch();
        let second_spawned = rns_interface::rnode::spawn_rnode_interface_with_driver(
            rns_interface::rnode::RNodeConfig::new("same-id-second", &second_port),
            id,
            second_transport_tx.clone(),
        )
        .await
        .expect("spawn second observed RNode");
        let second_driver = second_spawned.driver.watch();
        let first_controls: InterfaceControlMap = Arc::new(std::sync::Mutex::new(HashMap::new()));
        let second_controls: InterfaceControlMap = Arc::new(std::sync::Mutex::new(HashMap::new()));
        let first_registry = InterfaceRegistry::default();
        let second_registry = InterfaceRegistry::default();

        register_observed_rnode_handle_with_kind(
            &first_transport_tx,
            first_spawned,
            &first_controls,
            &first_registry,
            InterfaceKind::RNode,
        )
        .await
        .unwrap();
        register_observed_rnode_handle_with_kind(
            &second_transport_tx,
            second_spawned,
            &second_controls,
            &second_registry,
            InterfaceKind::RNode,
        )
        .await
        .unwrap();
        assert!(matches!(
            first_transport_rx.recv().await,
            Some(TransportMessage::RegisterInterface { id: registered, .. })
                if registered == id
        ));
        assert!(matches!(
            second_transport_rx.recv().await,
            Some(TransportMessage::RegisterInterface { id: registered, .. })
                if registered == id
        ));

        let mut first_runtime = dummy_handle();
        first_runtime.transport_tx = first_transport_tx;
        first_runtime.interface_controls = first_controls;
        first_runtime.interface_registry = first_registry;
        teardown_interface(&first_runtime, id).await;
        assert_exact_rnode_stopped(&first_driver);
        assert_ne!(
            second_driver.snapshot().phase,
            rns_interface::rnode::RNodeRuntimePhase::Stopped,
            "same-ID teardown in one runtime must not stop another runtime's driver"
        );
        assert!(
            matches!(
                second_closed_rx.try_recv(),
                Err(std::sync::mpsc::TryRecvError::Empty)
            ),
            "second same-ID peer closed during first runtime teardown"
        );
        assert!(matches!(
            first_transport_rx.recv().await,
            Some(TransportMessage::DeregisterInterface { id: deregistered })
                if deregistered == id
        ));

        let mut second_runtime = dummy_handle();
        second_runtime.transport_tx = second_transport_tx;
        second_runtime.interface_controls = second_controls;
        second_runtime.interface_registry = second_registry;
        teardown_interface(&second_runtime, id).await;
        assert_exact_rnode_stopped(&second_driver);
        assert!(matches!(
            second_transport_rx.recv().await,
            Some(TransportMessage::DeregisterInterface { id: deregistered })
                if deregistered == id
        ));

        for (closed_rx, peer) in [
            (first_closed_rx, first_peer),
            (second_closed_rx, second_peer),
        ] {
            let observed = closed_rx
                .recv_timeout(Duration::from_secs(2))
                .expect("exact teardown did not close the RNode peer");
            assert!(observed.ends_with(&rns_interface::rnode::build_detach_sequence()));
            peer.join().unwrap();
        }
    }

    #[cfg(feature = "rnode-tcp")]
    #[tokio::test]
    async fn dropped_exact_shutdown_requests_driver_and_keeps_tombstone() {
        let id = 920_195;
        let (port, closed_rx, peer) = test_rnode_tcp_peer();
        let (transport_tx, _transport_rx) = mpsc::channel::<TransportMessage>(4);
        let spawned = rns_interface::rnode::spawn_rnode_interface_with_driver(
            rns_interface::rnode::RNodeConfig::new("dropped-shutdown", &port),
            id,
            transport_tx,
        )
        .await
        .expect("spawn observed RNode");
        let mut observer = spawned.driver.watch();
        let interface = spawned.interface;
        let _keep_application_sender = interface.tx.clone();
        let online = interface.online.clone();
        let registry = InterfaceRegistry::default();
        let registration = registry
            .reserve_with_online(
                id,
                InterfaceKind::RNode,
                interface.read_task,
                Some(spawned.driver),
                Some(online),
            )
            .expect("reserve exact RNode");
        assert!(registration.commit().is_ok(), "commit exact RNode");

        let ShutdownStart::Acquired(shutdown) = registry.begin_shutdown(id) else {
            panic!("active exact RNode must yield shutdown ownership");
        };
        drop(shutdown);

        wait_for_exact_rnode_stop(&mut observer).await;
        let observed = closed_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("dropped exact shutdown did not close the RNode peer");
        assert!(observed.ends_with(&rns_interface::rnode::build_detach_sequence()));
        peer.join().unwrap();
        assert_eq!(
            registry.len(),
            1,
            "unjoined dropped shutdown must retain its Stopping tombstone"
        );
        let duplicate = match registry.reserve(
            id,
            InterfaceKind::Standard,
            tokio::spawn(std::future::pending()),
            None,
        ) {
            Ok(_) => panic!("Stopping tombstone must block same-ID reuse"),
            Err(rejected) => rejected,
        };
        assert_eq!(
            duplicate.reason(),
            InterfaceRegistrationRejection::Duplicate
        );
        duplicate.stop_and_wait().await;
    }

    #[cfg(feature = "rnode-tcp")]
    #[tokio::test]
    async fn registration_rejects_both_driver_ownership_mismatches() {
        let (transport_tx, mut transport_rx) = mpsc::channel::<TransportMessage>(4);
        let controls: InterfaceControlMap = Arc::new(std::sync::Mutex::new(HashMap::new()));
        let registry = InterfaceRegistry::default();
        let plain = test_interface_handle(920_196, None, "plain-as-rnode");
        let plain_online = plain.online.clone();
        let result = register_owned_interface_handle_with_role_and_overrides(
            &transport_tx,
            plain.into(),
            rns_transport::messages::InterfaceRole::Normal,
            rns_transport::ingress::IngressOverrides::default(),
            None,
            0,
            &controls,
            &registry,
            InterfaceKind::RNode,
            false,
            None,
        )
        .await;
        assert!(matches!(
            result,
            Err(InterfaceRegistrationError::InvalidDriverOwnership { id: 920_196 })
        ));
        assert!(!plain_online.load(Ordering::SeqCst));

        let (port, closed_rx, peer) = test_rnode_tcp_peer();
        let spawned = rns_interface::rnode::spawn_rnode_interface_with_driver(
            rns_interface::rnode::RNodeConfig::new("rnode-as-standard", &port),
            920_197,
            transport_tx.clone(),
        )
        .await
        .expect("spawn observed RNode");
        let mut observer = spawned.driver.watch();
        let result = register_owned_interface_handle_with_role_and_overrides(
            &transport_tx,
            spawned.into(),
            rns_transport::messages::InterfaceRole::Normal,
            rns_transport::ingress::IngressOverrides::default(),
            None,
            0,
            &controls,
            &registry,
            InterfaceKind::Standard,
            false,
            None,
        )
        .await;
        assert!(matches!(
            result,
            Err(InterfaceRegistrationError::InvalidDriverOwnership { id: 920_197 })
        ));
        wait_for_exact_rnode_stop(&mut observer).await;
        let observed = closed_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("invalid driver ownership cleanup did not close the RNode peer");
        assert!(observed.ends_with(&rns_interface::rnode::build_detach_sequence()));
        peer.join().unwrap();
        assert_eq!(registry.len(), 0);
        assert!(controls.lock().unwrap().is_empty());
        assert!(
            transport_rx.try_recv().is_err(),
            "ownership mismatch must never publish an actor registration"
        );
    }

    #[tokio::test]
    async fn cancelled_blocked_single_registration_fully_rolls_back() {
        let id = 920_094;
        let (transport_tx, mut transport_rx) = mpsc::channel::<TransportMessage>(1);
        transport_tx
            .send(TransportMessage::Shutdown)
            .await
            .expect("fill transport channel");
        let interface_controls: InterfaceControlMap =
            Arc::new(std::sync::Mutex::new(HashMap::new()));
        let interface_registry = InterfaceRegistry::default();
        let handle = test_interface_handle(id, None, "cancelled-single");
        let online = handle.online.clone();
        let worker_tx = transport_tx.clone();
        let worker_controls = interface_controls.clone();
        let worker_registry = interface_registry.clone();
        let caller = tokio::spawn(async move {
            register_interface_handle(&worker_tx, handle, &worker_controls, &worker_registry).await
        });

        wait_for_registry_len(&interface_registry, 1).await;
        caller.abort();
        let _ = caller.await;
        wait_for_registry_len(&interface_registry, 0).await;

        assert!(!online.load(Ordering::SeqCst));
        assert!(
            interface_controls
                .lock()
                .expect("interface_controls mutex poisoned")
                .is_empty()
        );
        assert!(matches!(
            transport_rx.recv().await,
            Some(TransportMessage::Shutdown)
        ));
        assert!(
            transport_rx.try_recv().is_err(),
            "cancelled blocked send must never publish RegisterInterface"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn cancelled_caller_before_worker_poll_keeps_drain_blocked_until_cleanup() {
        struct TaskDrop(Arc<AtomicBool>);
        impl Drop for TaskDrop {
            fn drop(&mut self) {
                self.0.store(true, Ordering::Release);
            }
        }

        let id = 920_104;
        let (transport_tx, mut transport_rx) = mpsc::channel::<TransportMessage>(4);
        let interface_controls: InterfaceControlMap =
            Arc::new(std::sync::Mutex::new(HashMap::new()));
        let interface_registry = InterfaceRegistry::default();
        let spawn_permit = interface_registry
            .acquire_spawn_permit()
            .expect("runtime admission is open");

        let task_stopped = Arc::new(AtomicBool::new(false));
        let (task_started_tx, task_started_rx) = oneshot::channel();
        let task_stopped_in_task = task_stopped.clone();
        let mut handle = test_interface_handle(id, None, "cancel-before-worker-poll");
        handle.read_task = tokio::spawn(async move {
            let _drop = TaskDrop(task_stopped_in_task);
            let _ = task_started_tx.send(());
            std::future::pending::<()>().await;
        });
        task_started_rx
            .await
            .expect("physical interface task started");
        let online = handle.online.clone();

        let mut caller = Box::pin(register_interface_handle_with_spawn_permit(
            &transport_tx,
            handle,
            &interface_controls,
            &interface_registry,
            spawn_permit,
        ));
        // Poll exactly through detached-worker creation. On a current-thread
        // runtime, the spawned worker cannot poll until this task yields.
        tokio::select! {
            biased;
            result = &mut caller => panic!("registration unexpectedly completed: {result:?}"),
            _ = std::future::ready(()) => {}
        }
        drop(caller);

        let drain = match interface_registry.begin_drain() {
            DrainStart::Acquired(drain) => drain,
            _ => panic!("first drain must acquire ownership"),
        };
        let (shutdowns, waiters, abandoned) = drain.into_parts();
        assert!(shutdowns.is_empty());
        assert!(waiters.is_empty());
        assert!(abandoned.is_empty());

        let mut permits_released = Box::pin(interface_registry.wait_for_spawn_permits());
        tokio::select! {
            biased;
            _ = &mut permits_released => {
                panic!("drain crossed a detached registration worker before it polled")
            }
            _ = std::future::ready(()) => {}
        }

        tokio::time::timeout(Duration::from_secs(2), &mut permits_released)
            .await
            .expect("registration worker did not finish exact rejection cleanup");
        assert!(task_stopped.load(Ordering::Acquire));
        assert!(!online.load(Ordering::SeqCst));
        assert!(interface_controls.lock().unwrap().is_empty());
        assert_eq!(interface_registry.len(), 0);
        assert!(transport_rx.try_recv().is_err());

        interface_registry.finish_drain_when_owned(&[]).await;
        assert_eq!(
            interface_registry.admission_for_test(),
            crate::interface_registry::RegistryAdmission::Closed
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn committed_unacknowledged_registration_does_not_deadlock_drain() {
        struct TaskDrop(Arc<AtomicBool>);
        impl Drop for TaskDrop {
            fn drop(&mut self) {
                self.0.store(true, Ordering::Release);
            }
        }

        let id = 920_105;
        let (transport_tx, mut transport_rx) = mpsc::channel::<TransportMessage>(4);
        let interface_controls: InterfaceControlMap =
            Arc::new(std::sync::Mutex::new(HashMap::new()));
        let interface_registry = InterfaceRegistry::default();
        let spawn_permit = interface_registry
            .acquire_spawn_permit()
            .expect("runtime admission is open");

        let task_stopped = Arc::new(AtomicBool::new(false));
        let (task_started_tx, task_started_rx) = oneshot::channel();
        let task_stopped_in_task = task_stopped.clone();
        let mut handle = test_interface_handle(id, None, "committed-without-ack");
        handle.read_task = tokio::spawn(async move {
            let _drop = TaskDrop(task_stopped_in_task);
            let _ = task_started_tx.send(());
            std::future::pending::<()>().await;
        });
        task_started_rx
            .await
            .expect("physical interface task started");

        let (cancel_tx, cancel_rx) = oneshot::channel();
        let (reply_tx, reply_rx) = oneshot::channel();
        let worker = tokio::spawn(single_registration_worker(
            transport_tx.clone(),
            interface_controls.clone(),
            interface_registry.clone(),
            SingleRegistrationSpec::Direct {
                owned: handle.into(),
                role: rns_transport::messages::InterfaceRole::Normal,
                ingress_overrides: rns_transport::ingress::IngressOverrides::default(),
                ifac_key: None,
                ifac_size: 0,
                kind: InterfaceKind::Standard,
                multipoint: false,
            },
            RegistrationCancellation {
                receiver: cancel_rx,
            },
            reply_tx,
            Some(spawn_permit),
        ));

        let mut reply = tokio::time::timeout(Duration::from_secs(2), reply_rx)
            .await
            .expect("registration worker did not reply")
            .expect("registration worker dropped its reply");
        let committed = reply.result.expect("registration must commit");
        assert_eq!(committed.len(), 1);
        assert_eq!(committed[0].id, id);
        let _withheld_acknowledgement = reply
            .acknowledgement
            .take()
            .expect("committed registration must require acknowledgement");
        assert!(matches!(
            transport_rx.recv().await,
            Some(TransportMessage::RegisterInterface {
                id: registered_id,
                ..
            }) if registered_id == id
        ));

        let drain = match interface_registry.begin_drain() {
            DrainStart::Acquired(drain) => drain,
            _ => panic!("first drain must acquire ownership"),
        };
        let (mut shutdowns, waiters, abandoned) = drain.into_parts();
        assert_eq!(shutdowns.len(), 1, "drain must lease the Active record");
        assert!(waiters.is_empty());
        assert!(abandoned.is_empty());

        // Once the transaction commits, the registry owns the task. Permit
        // release must not depend on the caller acknowledging the reply.
        tokio::time::timeout(
            Duration::from_secs(2),
            interface_registry.wait_for_spawn_permits(),
        )
        .await
        .expect("committed worker retained its producer permit across acknowledgement");

        drop(cancel_tx);
        tokio::task::yield_now().await;
        assert!(
            !worker.is_finished(),
            "cancelled worker must wait for the drain's exact Active lease"
        );

        for shutdown in &mut shutdowns {
            shutdown.mark_offline();
            shutdown.stop_task_and_wait().await;
        }
        let shutdown_tokens: Vec<_> = shutdowns.iter().map(InterfaceShutdown::token).collect();
        interface_registry
            .finish_drain_when_owned(&shutdown_tokens)
            .await;
        interface_controls.lock().unwrap().clear();
        drop(shutdowns);

        tokio::time::timeout(Duration::from_secs(2), worker)
            .await
            .expect("registration worker deadlocked with runtime drain")
            .expect("registration worker panicked");
        assert!(task_stopped.load(Ordering::Acquire));
        assert_eq!(
            interface_registry.admission_for_test(),
            crate::interface_registry::RegistryAdmission::Closed
        );
        assert!(interface_controls.lock().unwrap().is_empty());
        assert!(transport_rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn cancelled_partially_published_batch_removes_actor_entry_and_tasks() {
        let ids = [920_095, 920_096];
        let (transport_tx, mut transport_rx) = mpsc::channel::<TransportMessage>(1);
        let interface_controls: InterfaceControlMap =
            Arc::new(std::sync::Mutex::new(HashMap::new()));
        let interface_registry = InterfaceRegistry::default();
        let first = test_interface_handle(ids[0], None, "batch-cancel-first");
        let second = test_interface_handle(ids[1], None, "batch-cancel-second");
        let online = [first.online.clone(), second.online.clone()];
        let post_init = interface_factory::InterfacePostInit::from_section(&ConfigSection::new());
        let spawn_permit = interface_registry
            .acquire_spawn_permit()
            .expect("runtime admission is open");
        let worker_tx = transport_tx.clone();
        let worker_controls = interface_controls.clone();
        let worker_registry = interface_registry.clone();
        let caller = tokio::spawn(async move {
            register_interfaces_with_post_init_batch(
                &worker_tx,
                vec![first.into(), second.into()],
                &post_init,
                None,
                &worker_controls,
                &worker_registry,
                InterfaceKind::Standard,
                Some(spawn_permit),
            )
            .await
        });

        wait_for_registry_len(&interface_registry, 2).await;
        while transport_tx.capacity() != 0 {
            tokio::task::yield_now().await;
        }
        caller.abort();
        let _ = caller.await;
        tokio::task::yield_now().await;
        assert!(online.iter().all(|flag| !flag.load(Ordering::SeqCst)));
        assert!(
            interface_controls
                .lock()
                .expect("interface_controls mutex poisoned")
                .is_empty()
        );

        assert!(matches!(
            transport_rx.recv().await,
            Some(TransportMessage::RegisterInterface { id, .. }) if id == ids[0]
        ));
        assert!(matches!(
            transport_rx.recv().await,
            Some(TransportMessage::DeregisterInterface { id }) if id == ids[0]
        ));
        wait_for_registry_len(&interface_registry, 0).await;
        interface_registry.wait_for_spawn_permits().await;
        assert!(transport_rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn successful_registration_with_undeliverable_result_is_torn_down() {
        let id = 920_097;
        let (transport_tx, mut transport_rx) = mpsc::channel::<TransportMessage>(4);
        let interface_controls: InterfaceControlMap =
            Arc::new(std::sync::Mutex::new(HashMap::new()));
        let interface_registry = InterfaceRegistry::default();
        let handle = test_interface_handle(id, None, "undeliverable-result");
        let online = handle.online.clone();
        let (cancel_tx, cancel_rx) = oneshot::channel();
        let (reply_tx, reply_rx) = oneshot::channel();
        drop(reply_rx);

        single_registration_worker(
            transport_tx.clone(),
            interface_controls.clone(),
            interface_registry.clone(),
            SingleRegistrationSpec::Direct {
                owned: handle.into(),
                role: rns_transport::messages::InterfaceRole::Normal,
                ingress_overrides: rns_transport::ingress::IngressOverrides::default(),
                ifac_key: None,
                ifac_size: 0,
                kind: InterfaceKind::Standard,
                multipoint: false,
            },
            RegistrationCancellation {
                receiver: cancel_rx,
            },
            reply_tx,
            None,
        )
        .await;
        drop(cancel_tx);

        assert!(matches!(
            transport_rx.recv().await,
            Some(TransportMessage::RegisterInterface {
                id: registered_id,
                ..
            }) if registered_id == id
        ));
        assert!(matches!(
            transport_rx.recv().await,
            Some(TransportMessage::DeregisterInterface {
                id: deregistered_id
            }) if deregistered_id == id
        ));
        assert!(!online.load(Ordering::SeqCst));
        assert!(interface_controls.lock().unwrap().is_empty());
        assert_eq!(interface_registry.len(), 0);
    }

    #[tokio::test]
    async fn stale_committed_cleanup_token_cannot_teardown_reused_id() {
        let id = 920_103;
        let (transport_tx, mut transport_rx) = mpsc::channel::<TransportMessage>(4);
        let interface_controls: InterfaceControlMap =
            Arc::new(std::sync::Mutex::new(HashMap::new()));
        let interface_registry = InterfaceRegistry::default();
        let first = test_interface_handle(id, None, "stale-owner-a");
        let prepared = prepare_interface_with_role_and_overrides(
            first.into(),
            rns_transport::messages::InterfaceRole::Normal,
            rns_transport::ingress::IngressOverrides::default(),
            None,
            0,
            &interface_controls,
            &interface_registry,
            InterfaceKind::Standard,
            false,
        )
        .await
        .expect("prepare owner A");
        let (cancel_tx, cancel_rx) = oneshot::channel();
        let mut cancellation = RegistrationCancellation {
            receiver: cancel_rx,
        };
        let stale_token = publish_prepared_interface(
            &transport_tx,
            &interface_controls,
            &interface_registry,
            prepared,
            &mut cancellation,
        )
        .await
        .expect("commit owner A");
        assert!(matches!(
            transport_rx.recv().await,
            Some(TransportMessage::RegisterInterface {
                id: registered_id,
                ..
            }) if registered_id == id
        ));

        teardown_interface_transaction(&transport_tx, &interface_controls, &interface_registry, id)
            .await;
        assert!(matches!(
            transport_rx.recv().await,
            Some(TransportMessage::DeregisterInterface {
                id: deregistered_id
            }) if deregistered_id == id
        ));

        let second = test_interface_handle(id, None, "stale-owner-b");
        let second_online = second.online.clone();
        register_interface_handle(
            &transport_tx,
            second,
            &interface_controls,
            &interface_registry,
        )
        .await
        .expect("register owner B");
        assert!(matches!(
            transport_rx.recv().await,
            Some(TransportMessage::RegisterInterface {
                id: registered_id,
                ..
            }) if registered_id == id
        ));

        cleanup_committed_interfaces(
            &transport_tx,
            &interface_controls,
            &interface_registry,
            vec![stale_token],
        )
        .await;
        assert!(second_online.load(Ordering::SeqCst));
        assert_eq!(interface_registry.len(), 1);
        assert!(interface_controls.lock().unwrap().contains_key(&id));
        assert!(
            transport_rx.try_recv().is_err(),
            "stale owner cleanup must not enqueue deregistration for owner B"
        );

        teardown_interface_transaction(&transport_tx, &interface_controls, &interface_registry, id)
            .await;
        assert!(matches!(
            transport_rx.recv().await,
            Some(TransportMessage::DeregisterInterface {
                id: deregistered_id
            }) if deregistered_id == id
        ));
        drop(cancel_tx);
    }

    #[tokio::test]
    async fn missing_teardown_tombstone_blocks_reuse_until_deregister_is_enqueued() {
        let id = 920_098;
        let (transport_tx, mut transport_rx) = mpsc::channel::<TransportMessage>(1);
        transport_tx
            .send(TransportMessage::Shutdown)
            .await
            .expect("fill transport channel");
        let interface_registry = InterfaceRegistry::default();
        let mut runtime = dummy_handle();
        runtime.transport_tx = transport_tx;
        runtime.interface_registry = interface_registry.clone();
        let teardown = tokio::spawn(async move {
            teardown_interface(&runtime, id).await;
        });

        wait_for_registry_len(&interface_registry, 1).await;
        let rejected = match interface_registry.reserve(
            id,
            InterfaceKind::Standard,
            tokio::spawn(std::future::pending()),
            None,
        ) {
            Ok(_) => panic!("orphan cleanup must hold a same-ID tombstone"),
            Err(rejected) => rejected,
        };
        rejected.stop_and_wait().await;

        assert!(matches!(
            transport_rx.recv().await,
            Some(TransportMessage::Shutdown)
        ));
        assert!(matches!(
            transport_rx.recv().await,
            Some(TransportMessage::DeregisterInterface {
                id: deregistered_id
            }) if deregistered_id == id
        ));
        teardown.await.expect("teardown caller");
        let replacement = interface_registry
            .reserve(
                id,
                InterfaceKind::Standard,
                tokio::spawn(std::future::pending()),
                None,
            )
            .expect("ID may be reused after deregistration is enqueued");
        replacement.rollback().await;
    }

    #[tokio::test]
    async fn pending_teardown_forces_commit_failure_and_complete_rollback() {
        let id = 920_099;
        let (transport_tx, mut transport_rx) = mpsc::channel::<TransportMessage>(1);
        transport_tx
            .send(TransportMessage::Shutdown)
            .await
            .expect("fill transport channel");
        let interface_controls: InterfaceControlMap =
            Arc::new(std::sync::Mutex::new(HashMap::new()));
        let interface_registry = InterfaceRegistry::default();
        let handle = test_interface_handle(id, None, "pending-teardown");
        let online = handle.online.clone();
        let worker_tx = transport_tx.clone();
        let worker_controls = interface_controls.clone();
        let worker_registry = interface_registry.clone();
        let registration = tokio::spawn(async move {
            register_interface_handle(&worker_tx, handle, &worker_controls, &worker_registry).await
        });
        wait_for_registry_len(&interface_registry, 1).await;

        let mut runtime = dummy_handle();
        runtime.transport_tx = transport_tx;
        runtime.interface_controls = interface_controls.clone();
        runtime.interface_registry = interface_registry.clone();
        let teardown = tokio::spawn(async move {
            teardown_interface(&runtime, id).await;
        });

        let registration_result = tokio::time::timeout(Duration::from_secs(2), registration)
            .await
            .expect("pending registration must wake without actor-channel progress")
            .expect("registration caller");
        assert!(matches!(
            registration_result,
            Err(InterfaceRegistrationError::ReservationLost {
                id: failed_id
            }) if failed_id == id
        ));
        tokio::time::timeout(Duration::from_secs(2), teardown)
            .await
            .expect("teardown must finish while the actor channel remains full")
            .expect("teardown caller");
        assert!(!online.load(Ordering::SeqCst));
        assert!(interface_controls.lock().unwrap().is_empty());
        assert_eq!(interface_registry.len(), 0);
        assert!(matches!(
            transport_rx.recv().await,
            Some(TransportMessage::Shutdown)
        ));
        assert!(
            transport_rx.try_recv().is_err(),
            "cancelled pending registration must not queue actor work"
        );
    }

    #[tokio::test]
    async fn naturally_completed_task_is_explicitly_joined_and_released() {
        let id = 920_100;
        let (transport_tx, mut transport_rx) = mpsc::channel::<TransportMessage>(4);
        let interface_controls: InterfaceControlMap =
            Arc::new(std::sync::Mutex::new(HashMap::new()));
        let interface_registry = InterfaceRegistry::default();
        let mut handle = test_interface_handle(id, None, "natural-completion");
        handle.read_task = tokio::spawn(async {});
        register_interface_handle(
            &transport_tx,
            handle,
            &interface_controls,
            &interface_registry,
        )
        .await
        .expect("register completed task");
        assert!(matches!(
            transport_rx.recv().await,
            Some(TransportMessage::RegisterInterface {
                id: registered_id,
                ..
            }) if registered_id == id
        ));

        let mut runtime = dummy_handle();
        runtime.transport_tx = transport_tx;
        runtime.interface_controls = interface_controls;
        runtime.interface_registry = interface_registry.clone();
        teardown_interface(&runtime, id).await;
        assert!(matches!(
            transport_rx.recv().await,
            Some(TransportMessage::DeregisterInterface {
                id: deregistered_id
            }) if deregistered_id == id
        ));
        let replacement = interface_registry
            .reserve(
                id,
                InterfaceKind::Standard,
                tokio::spawn(std::future::pending()),
                None,
            )
            .expect("explicit cleanup releases naturally completed task ID");
        replacement.rollback().await;
    }

    #[tokio::test]
    async fn cancelled_teardown_caller_does_not_cancel_owned_cleanup() {
        let id = 920_102;
        let (transport_tx, mut transport_rx) = mpsc::channel::<TransportMessage>(1);
        let interface_controls: InterfaceControlMap =
            Arc::new(std::sync::Mutex::new(HashMap::new()));
        let interface_registry = InterfaceRegistry::default();
        let handle = test_interface_handle(id, None, "cancelled-teardown");
        let online = handle.online.clone();
        register_interface_handle(
            &transport_tx,
            handle,
            &interface_controls,
            &interface_registry,
        )
        .await
        .expect("registration");
        assert!(matches!(
            transport_rx.recv().await,
            Some(TransportMessage::RegisterInterface {
                id: registered_id,
                ..
            }) if registered_id == id
        ));
        transport_tx
            .send(TransportMessage::Shutdown)
            .await
            .expect("block teardown deregistration");

        let mut runtime = dummy_handle();
        runtime.transport_tx = transport_tx;
        runtime.interface_controls = interface_controls.clone();
        runtime.interface_registry = interface_registry.clone();
        let caller = tokio::spawn(async move {
            teardown_interface(&runtime, id).await;
        });
        tokio::time::timeout(Duration::from_secs(2), async {
            while online.load(Ordering::SeqCst) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("teardown worker must take ownership and mark offline");
        caller.abort();
        let _ = caller.await;

        assert!(matches!(
            transport_rx.recv().await,
            Some(TransportMessage::Shutdown)
        ));
        assert!(matches!(
            transport_rx.recv().await,
            Some(TransportMessage::DeregisterInterface {
                id: deregistered_id
            }) if deregistered_id == id
        ));
        wait_for_registry_len(&interface_registry, 0).await;
        assert!(interface_controls.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn registration_applies_parsed_interface_flags_and_internal_mode() {
        let (transport_tx, mut transport_rx) = mpsc::channel::<TransportMessage>(4);
        let interface_controls: InterfaceControlMap =
            Arc::new(std::sync::Mutex::new(HashMap::new()));
        let interface_registry = InterfaceRegistry::default();

        let mut section = ConfigSection::new();
        section.set("recursive_prs", "yes");
        section.set("announces_from_internal", "no");
        let post_init = interface_factory::InterfacePostInit::from_section(&section);
        let mut handle = test_interface_handle(920_101, None, "internal-mode");
        handle.mode = rns_interface::traits::InterfaceMode::Internal;
        register_interface_with_post_init(
            &transport_tx,
            handle,
            &post_init,
            None,
            &interface_controls,
            &interface_registry,
            InterfaceKind::Standard,
        )
        .await
        .unwrap();
        let TransportMessage::RegisterInterface { entry, .. } =
            transport_rx.recv().await.expect("registration")
        else {
            panic!("expected RegisterInterface");
        };
        assert_eq!(
            entry.mode,
            rns_transport::constants::InterfaceMode::Internal
        );
        assert!(entry.recursive_prs);
        assert!(!entry.announces_from_internal);
    }

    #[test]
    fn default_announce_rate_applies_only_when_transport_enabled() {
        let mut post_init =
            interface_factory::InterfacePostInit::from_section(&ConfigSection::new());
        let mut rc = ReticulumConfig {
            enable_transport: false,
            default_ar_target: Some(7200),
            default_ar_penalty: Some(30),
            default_ar_grace: Some(9),
            ..ReticulumConfig::default()
        };

        apply_default_announce_rate(&mut post_init, &rc);
        assert_eq!(post_init.announce_rate_target, None);
        assert_eq!(post_init.announce_rate_penalty, None);
        assert_eq!(post_init.announce_rate_grace, None);

        rc.enable_transport = true;
        apply_default_announce_rate(&mut post_init, &rc);
        assert_eq!(post_init.announce_rate_target, Some(7200));
        assert_eq!(post_init.announce_rate_penalty, Some(30));
        assert_eq!(post_init.announce_rate_grace, Some(9));
    }

    #[tokio::test]
    async fn runtime_registration_uses_fractional_announce_cap() {
        let (transport_tx, mut transport_rx) = mpsc::channel::<TransportMessage>(4);
        let interface_controls: InterfaceControlMap =
            Arc::new(std::sync::Mutex::new(HashMap::new()));
        let interface_registry = InterfaceRegistry::default();

        let post_init = interface_factory::InterfacePostInit::from_section(&ConfigSection::new());
        register_interface_with_post_init(
            &transport_tx,
            test_interface_handle(920_001, None, "default-cap"),
            &post_init,
            None,
            &interface_controls,
            &interface_registry,
            InterfaceKind::Standard,
        )
        .await
        .unwrap();
        let TransportMessage::RegisterInterface { entry, .. } =
            transport_rx.recv().await.expect("default cap registration")
        else {
            panic!("expected RegisterInterface");
        };
        assert!((entry.announce_cap - ANNOUNCE_CAP).abs() < f64::EPSILON);

        let mut section = ConfigSection::new();
        section.set("announce_cap", "5.0");
        let post_init = interface_factory::InterfacePostInit::from_section(&section);
        register_interface_with_post_init(
            &transport_tx,
            test_interface_handle(920_002, None, "custom-cap"),
            &post_init,
            None,
            &interface_controls,
            &interface_registry,
            InterfaceKind::Standard,
        )
        .await
        .unwrap();
        let TransportMessage::RegisterInterface { entry, .. } =
            transport_rx.recv().await.expect("custom cap registration")
        else {
            panic!("expected RegisterInterface");
        };
        assert!((entry.announce_cap - 0.05).abs() < f64::EPSILON);
    }

    #[tokio::test]
    async fn dynamic_child_inherits_parent_control_settings() {
        let parent_id = 910_001;
        let child_id = 910_002;
        let (transport_tx, mut transport_rx) = mpsc::channel::<TransportMessage>(4);
        let interface_controls: InterfaceControlMap =
            Arc::new(std::sync::Mutex::new(HashMap::new()));
        let interface_registry = InterfaceRegistry::default();

        let mut section = ConfigSection::new();
        section.set("ic_pr_burst_freq_new", "4.0");
        section.set("ic_pr_burst_freq", "9.0");
        section.set("ec_pr_freq", "6.0");
        section.set("egress_control", "Yes");
        let post_init = interface_factory::InterfacePostInit::from_section(&section);

        register_interface_with_post_init(
            &transport_tx,
            test_interface_handle(parent_id, None, "parent"),
            &post_init,
            None,
            &interface_controls,
            &interface_registry,
            InterfaceKind::Standard,
        )
        .await
        .unwrap();
        let _ = transport_rx.recv().await.expect("parent registration");

        let (role, inherited, ifac_key, ifac_size) =
            child_registration_from_parent(&interface_controls, Some(parent_id));
        assert_eq!(role, rns_transport::messages::InterfaceRole::Normal);
        register_interface_handle_with_role_and_overrides(
            &transport_tx,
            test_interface_handle(child_id, Some(parent_id), "child"),
            role,
            inherited,
            ifac_key,
            ifac_size,
            &interface_controls,
            &interface_registry,
            InterfaceKind::Standard,
            false,
        )
        .await
        .unwrap();

        let msg = transport_rx.recv().await.expect("child registration");
        let TransportMessage::RegisterInterface { entry, .. } = msg else {
            panic!("expected child RegisterInterface");
        };
        assert_eq!(entry.ingress.pr_burst_freq_new(), 4.0);
        assert_eq!(entry.ingress.pr_burst_freq(), 9.0);
        assert_eq!(entry.ingress.ec_pr_freq(), 6.0);
        assert!(entry.ingress.is_egress_control_enabled());
    }

    #[tokio::test]
    async fn shared_instance_interface_roles_disable_ingress_control() {
        let (transport_tx, mut transport_rx) = mpsc::channel::<TransportMessage>(4);
        let interface_controls: InterfaceControlMap =
            Arc::new(std::sync::Mutex::new(HashMap::new()));
        let interface_registry = InterfaceRegistry::default();

        let overrides = rns_transport::ingress::IngressOverrides {
            enabled: Some(true),
            burst_freq_new: Some(1.0),
            ..Default::default()
        };

        for (id, role) in [
            (910_201, rns_transport::messages::InterfaceRole::LocalClient),
            (
                910_202,
                rns_transport::messages::InterfaceRole::SharedInstancePeer,
            ),
        ] {
            register_interface_handle_with_role_and_overrides(
                &transport_tx,
                test_interface_handle(id, None, role.as_str()),
                role,
                overrides.clone(),
                None,
                0,
                &interface_controls,
                &interface_registry,
                InterfaceKind::Standard,
                false,
            )
            .await
            .unwrap();

            let msg = transport_rx.recv().await.expect("registration");
            let TransportMessage::RegisterInterface { entry, .. } = msg else {
                panic!("expected RegisterInterface");
            };
            assert_eq!(entry.role, role);
            assert!(!entry.ingress.is_enabled());
        }
    }

    #[test]
    fn shared_server_child_role_uses_parent_metadata_not_name_prefix() {
        let parent_id = 910_101;
        let interface_controls: InterfaceControlMap =
            Arc::new(std::sync::Mutex::new(HashMap::new()));
        interface_controls
            .lock()
            .expect("interface_controls mutex poisoned")
            .insert(
                parent_id,
                InterfaceControlMetadata {
                    registry_owner: 1,
                    role: rns_transport::messages::InterfaceRole::SharedServer,
                    ingress_overrides: rns_transport::ingress::IngressOverrides::default(),
                    ifac_key: None,
                    ifac_size: 0,
                },
            );

        let (role, _, _, _) = child_registration_from_parent(&interface_controls, Some(parent_id));

        assert_eq!(role, rns_transport::messages::InterfaceRole::LocalClient);
    }

    #[tokio::test]
    async fn server_children_inherit_parent_ifac() {
        let parent_id = 930_001;
        let child_id = 930_002;
        let (transport_tx, mut transport_rx) = mpsc::channel::<TransportMessage>(4);
        let interface_controls: InterfaceControlMap =
            Arc::new(std::sync::Mutex::new(HashMap::new()));
        let interface_registry = InterfaceRegistry::default();

        let mut section = ConfigSection::new();
        section.set("networkname", "testnet");
        section.set("passphrase", "password");
        let post_init =
            interface_factory::InterfacePostInit::from_section(&section).with_default_ifac_size(16);
        let ifac_key = derive_ifac_key_from_post_init(&post_init);
        assert!(ifac_key.is_some());

        register_interface_with_post_init(
            &transport_tx,
            test_interface_handle(parent_id, None, "ifac-parent"),
            &post_init,
            ifac_key,
            &interface_controls,
            &interface_registry,
            InterfaceKind::Standard,
        )
        .await
        .unwrap();
        let TransportMessage::RegisterInterface {
            entry: parent_entry,
            ..
        } = transport_rx.recv().await.expect("parent registration")
        else {
            panic!("expected parent RegisterInterface");
        };
        assert_eq!(parent_entry.ifac_key, ifac_key);
        assert_eq!(parent_entry.ifac_size, 16);

        let (role, inherited, child_key, child_size) =
            child_registration_from_parent(&interface_controls, Some(parent_id));
        assert_eq!(child_key, ifac_key);
        assert_eq!(child_size, 16);

        register_interface_handle_with_role_and_overrides(
            &transport_tx,
            test_interface_handle(child_id, Some(parent_id), "ifac-child"),
            role,
            inherited,
            child_key,
            child_size,
            &interface_controls,
            &interface_registry,
            InterfaceKind::Standard,
            false,
        )
        .await
        .unwrap();
        let TransportMessage::RegisterInterface { entry, .. } =
            transport_rx.recv().await.expect("child registration")
        else {
            panic!("expected child RegisterInterface");
        };
        assert_eq!(entry.ifac_key, ifac_key);
        assert_eq!(entry.ifac_size, 16);
    }

    #[test]
    fn discovered_backbone_autoconnect_mode_tracks_transport_setting() {
        let leaf = ReticulumConfig::default();
        assert_eq!(
            discovered_backbone_client_mode(&leaf),
            rns_interface::traits::InterfaceMode::Full
        );

        let transport = ReticulumConfig {
            enable_transport: true,
            ..ReticulumConfig::default()
        };
        assert_eq!(
            discovered_backbone_client_mode(&transport),
            rns_interface::traits::InterfaceMode::Gateway
        );
    }

    #[test]
    fn yggdrasil_ipv6_detection_matches_200_prefix() {
        assert!(is_yggdrasil_ipv6("200::1"));
        assert!(is_yggdrasil_ipv6("3ff:ffff::1"));
        assert!(!is_yggdrasil_ipv6("400::1"));
        assert!(!is_yggdrasil_ipv6("relay.example.org"));
    }

    #[test]
    fn test_network_identity_is_created_during_runtime_apply() {
        let dir = std::env::temp_dir().join(format!(
            "reticulum_rs_network_identity_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let identity_path = dir.join("network.identity");

        let identity = load_or_create_network_identity(&identity_path).unwrap();
        assert!(identity_path.is_file());
        let loaded = load_or_create_network_identity(&identity_path).unwrap();
        assert_eq!(identity.hash, loaded.hash);

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn test_discovery_legacy_aliases_parsed() {
        let input = "[reticulum]\n\
                     discover_interfaces_autoconnect = Yes\n\
                     discover_interfaces_required_value = 16\n";
        let config = Config::parse(input).unwrap();
        let rc = ReticulumConfig::from_config(&config);
        assert_eq!(rc.autoconnect_discovered_interfaces, 1);
        assert_eq!(rc.discover_interfaces_required_value, 16);
    }

    #[test]
    fn test_blackhole_sources_parsed() {
        let input = "[reticulum]\n\
                     blackhole_sources = 521c87a83afb8f29e4455e77930b973b, 11111111111111111111111111111111\n";
        let config = Config::parse(input).unwrap();
        let rc = ReticulumConfig::from_config(&config);
        assert_eq!(rc.blackhole_sources.len(), 2);
        assert_eq!(
            rc.blackhole_sources[0],
            [
                0x52, 0x1c, 0x87, 0xa8, 0x3a, 0xfb, 0x8f, 0x29, 0xe4, 0x45, 0x5e, 0x77, 0x93, 0x0b,
                0x97, 0x3b,
            ]
        );
    }

    #[test]
    fn test_invalid_typed_config_values_fail_like_configobj() {
        for (key, value) in [
            ("share_instance", "maybe"),
            ("shared_instance_port", "notaport"),
            ("autoconnect_discovered_interfaces", "Yes"),
            ("blackhole_sources", "deadbeef"),
            ("egress_control", "maybe"),
            ("ic_pr_burst_freq", "fast"),
        ] {
            let input = format!("[reticulum]\n{key} = {value}\n");
            let config = Config::parse(&input).unwrap();
            assert!(
                ReticulumConfig::try_from_config(&config).is_err(),
                "{key} = {value} should be rejected"
            );
        }

        let config = Config::parse("[logging]\nloglevel = fish\n").unwrap();
        assert!(ReticulumConfig::try_from_config(&config).is_err());
    }

    #[test]
    fn test_bootstrap_configs_parsed() {
        let input = "[reticulum]\nbootstrap_configs = interfaces/bootstrap1.conf, interfaces/bootstrap2.conf\n";
        let config = Config::parse(input).unwrap();
        let rc = ReticulumConfig::from_config(&config);
        assert_eq!(
            rc.bootstrap_configs,
            vec![
                PathBuf::from("interfaces/bootstrap1.conf"),
                PathBuf::from("interfaces/bootstrap2.conf"),
            ]
        );
    }

    #[test]
    fn test_discover_required_value_clamped_to_u8() {
        let input = "[reticulum]\ndiscover_interfaces_required_value = 999\n";
        let config = Config::parse(input).unwrap();
        let rc = ReticulumConfig::from_config(&config);
        assert_eq!(rc.discover_interfaces_required_value, 255);
    }

    #[test]
    fn test_convert_mode_all_variants() {
        use rns_interface::traits::InterfaceMode as IM;
        use rns_transport::constants::InterfaceMode as TM;

        assert_eq!(convert_mode(IM::AccessPoint), TM::AccessPoint);
        assert_eq!(convert_mode(IM::Roaming), TM::Roaming);
        assert_eq!(convert_mode(IM::Boundary), TM::Boundary);
        assert_eq!(convert_mode(IM::Gateway), TM::Gateway);
        assert_eq!(convert_mode(IM::Full), TM::Full);
        assert_eq!(convert_mode(IM::PointToPoint), TM::PointToPoint);
        assert_eq!(convert_mode(IM::Internal), TM::Internal);
    }

    #[test]
    fn test_synthesize_interfaces_from_config() {
        let input = r#"
[interfaces]

[[Test TCP Client]]
type = TCPClientInterface
target_host = 127.0.0.1
target_port = 4242
enabled = yes

[[Disabled Interface]]
type = UDPInterface
enabled = no

[[Test UDP]]
type = UDPInterface
listen_port = 5555
"#;
        let config = Config::parse(input).unwrap();
        let interfaces = synthesize_interfaces(&config, false).unwrap();
        assert_eq!(interfaces.len(), 2);
    }

    #[test]
    fn test_panic_on_interface_error_fails_bad_config() {
        let input = r#"
[interfaces]

[[Broken Interface]]
enabled = yes
"#;
        let config = Config::parse(input).unwrap();
        let err = synthesize_interfaces(&config, true).unwrap_err();
        assert!(
            matches!(err, ReticulumError::Interface(_)),
            "panic_on_interface_error should fail interface synthesis"
        );
    }

    #[tokio::test]
    async fn test_init_and_shutdown() {
        let dir = std::env::temp_dir().join("reticulum_rs_test_init");
        let _ = std::fs::remove_dir_all(&dir);

        let shutdown = ShutdownSignal::new();
        let is_foreground = Arc::new(AtomicBool::new(true));
        let result = init(
            Some(dir.to_str().unwrap()),
            None,
            shutdown.clone(),
            is_foreground,
        )
        .await;
        assert!(result.is_ok());

        let handle = result.unwrap();
        assert_eq!(handle.interface_configs.len(), 1);
        match &handle.interface_configs[0] {
            interface_factory::InterfaceConfig::Auto(config) => {
                assert_eq!(config.name, "Default Interface");
            }
            other => panic!("expected default AutoInterface, got {other:?}"),
        }
        assert!(
            handle.config.rpc_key.is_some(),
            "shared-instance RPC key should derive from transport identity by default"
        );

        shutdown.trigger();
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(feature = "rnode-tcp")]
    #[tokio::test]
    async fn init_exposes_exact_successfully_registered_configured_rnode() {
        let template =
            rns_interface::rnode::RNodeConfig::new("Configured RNode", "tcp://127.0.0.1:1");
        let settings = rns_interface::rnode::RNodeRadioSettings::from(&template);
        let (port, closed_rx, peer) = test_ready_rnode_tcp_peer(settings);
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir =
            std::env::temp_dir().join(format!("reticulum_rs_configured_rnode_observer_{nonce}"));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("config"),
            format!(
                "[reticulum]\nshare_instance = No\nenable_transport = No\npanic_on_interface_error = Yes\n\n[interfaces]\n\n[[Configured RNode]]\ntype = RNodeInterface\nenabled = Yes\nport = {port}\nfrequency = {}\nbandwidth = {}\nspreadingfactor = {}\ncodingrate = {}\ntxpower = {}\n",
                template.frequency,
                template.bandwidth,
                template.spreading_factor,
                template.coding_rate,
                template.tx_power,
            ),
        )
        .unwrap();

        let handle = init(
            Some(dir.to_str().unwrap()),
            None,
            ShutdownSignal::new(),
            Arc::new(AtomicBool::new(true)),
        )
        .await
        .expect("configured RNode init");

        let configured = handle.startup_rnode_runtimes();
        assert_eq!(configured.len(), 1);
        let runtime = &configured[0];
        assert_eq!(runtime.configured_name, "Configured RNode");
        assert_eq!(runtime.interface_id, runtime.observer.interface_id());

        let ready = runtime
            .observer
            .await_ready(Duration::from_secs(2))
            .await
            .expect("configured observer should reach exact readiness");
        let registry_ready = handle
            .rnode_runtime(runtime.interface_id)
            .expect("same exact registry record")
            .await_ready(Duration::ZERO)
            .await
            .expect("registry observer should share ready publication");
        assert!(
            Arc::ptr_eq(&ready, &registry_ready),
            "startup and registry observers must share the exact driver publication"
        );

        // A candidate can only become public when its own ID appears in the
        // successful registration result; a different ID cannot redirect it.
        let unmatched = PendingConfiguredRNodeRuntime {
            configured_name: runtime.configured_name.clone(),
            spawned_interface_id: runtime.interface_id,
            state: runtime.observer.state.clone(),
        };
        assert!(unmatched.commit(&[runtime.interface_id + 1]).is_none());

        handle.shutdown_and_wait().await;
        let observed = closed_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("configured RNode did not close");
        assert!(observed.ends_with(&rns_interface::rnode::build_detach_sequence()));
        peer.join().unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(feature = "rnode-tcp")]
    #[tokio::test]
    async fn strict_init_exposes_exact_successfully_registered_configured_rnode() {
        use rns_interface::{kiss, rnode};

        let template = rnode::RNodeConfig::new("Strict Configured RNode", "tcp://127.0.0.1:1");
        let (port, closed_rx, peer) = test_strict_ready_rnode_tcp_peer(template.clone());
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "reticulum_rs_configured_strict_rnode_observer_{nonce}"
        ));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("config"),
            format!(
                "[reticulum]\nshare_instance = No\nenable_transport = No\npanic_on_interface_error = Yes\n\n[interfaces]\n\n[[Strict Configured RNode]]\ntype = RNodeInterface\nenabled = Yes\nport = {port}\nfrequency = {}\nbandwidth = {}\nspreadingfactor = {}\ncodingrate = {}\ntxpower = {}\n",
                template.frequency,
                template.bandwidth,
                template.spreading_factor,
                template.coding_rate,
                template.tx_power,
            ),
        )
        .unwrap();

        let handle = init_with_options_and_rnode_startup_options(
            Some(dir.to_str().unwrap()),
            None,
            ShutdownSignal::new(),
            Arc::new(AtomicBool::new(true)),
            InitOptions::default(),
            rnode::RNodeStartupOptions::require_capability_admission(),
        )
        .await
        .expect("strict configured RNode init");

        let configured = handle.startup_rnode_runtimes();
        assert_eq!(configured.len(), 1);
        let runtime = &configured[0];
        assert_eq!(runtime.configured_name, "Strict Configured RNode");
        let ready = runtime
            .observer
            .await_ready(Duration::from_secs(2))
            .await
            .expect("strict configured observer readiness");
        assert_eq!(ready.capability, rnode::RNodeCapabilityState::Verified);
        let registry_ready = handle
            .rnode_runtime(runtime.interface_id)
            .expect("same exact strict configured registry record")
            .await_ready(Duration::ZERO)
            .await
            .expect("strict registry observer shares ready publication");
        assert!(Arc::ptr_eq(&ready, &registry_ready));

        handle.shutdown_and_wait().await;
        let observed = closed_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("strict configured RNode did not close");
        let capability_request = kiss::frame_with_command(rnode::CMD_ROM_READ, &[0]);
        let init = rnode::build_init_sequence(&template);
        let capability_positions: Vec<_> = observed
            .windows(capability_request.len())
            .enumerate()
            .filter_map(|(index, window)| {
                (window == capability_request.as_slice()).then_some(index)
            })
            .collect();
        assert_eq!(capability_positions.len(), 1);
        let init_position = observed
            .windows(init.len())
            .position(|window| window == init.as_slice())
            .expect("strict configured init sequence missing");
        assert!(capability_positions[0] < init_position);
        assert!(observed.ends_with(&rnode::build_detach_sequence()));
        peer.join().unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(feature = "rnode-tcp")]
    #[tokio::test]
    async fn configured_rnode_init_routes_explicit_strict_startup_policy() {
        use rns_interface::{kiss, rnode};

        let template = rnode::RNodeConfig::new("Strict Configured RNode", "tcp://127.0.0.1:1");
        let mut responses = Vec::new();
        kiss::frame_with_command_into(rnode::CMD_DETECT, &[rnode::DETECT_RESP], &mut responses);
        kiss::frame_with_command_into(
            rnode::CMD_FW_VERSION,
            &[rnode::REQUIRED_FW_VER_MAJ, rnode::REQUIRED_FW_VER_MIN],
            &mut responses,
        );
        kiss::frame_with_command_into(rnode::CMD_ROM_READ, &[0], &mut responses);
        let (port, closed_rx, peer) = test_rnode_tcp_peer_with_responses(responses);
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir =
            std::env::temp_dir().join(format!("reticulum_rs_configured_strict_rnode_{nonce}"));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("config"),
            format!(
                "[reticulum]\nshare_instance = No\nenable_transport = No\npanic_on_interface_error = Yes\n\n[interfaces]\n\n[[Strict Configured RNode]]\ntype = RNodeInterface\nenabled = Yes\nport = {port}\nfrequency = {}\nbandwidth = {}\nspreadingfactor = {}\ncodingrate = {}\ntxpower = {}\n",
                template.frequency,
                template.bandwidth,
                template.spreading_factor,
                template.coding_rate,
                template.tx_power,
            ),
        )
        .unwrap();

        let result = init_with_options_and_rnode_startup_options(
            Some(dir.to_str().unwrap()),
            None,
            ShutdownSignal::new(),
            Arc::new(AtomicBool::new(true)),
            InitOptions::default(),
            rnode::RNodeStartupOptions::require_capability_admission(),
        )
        .await;

        match result {
            Err(ReticulumError::Interface(message)) => assert!(
                message.contains("EEPROM capability image"),
                "unexpected strict configured error: {message}"
            ),
            Err(error) => panic!("unexpected strict configured error: {error}"),
            Ok(handle) => {
                handle.shutdown_and_wait().await;
                panic!("strict configured startup accepted an invalid capability image");
            }
        }
        let observed = closed_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("strict configured RNode connection did not close");
        let capability_request = kiss::frame_with_command(rnode::CMD_ROM_READ, &[0]);
        assert!(
            observed
                .windows(capability_request.len())
                .any(|window| window == capability_request.as_slice()),
            "strict configured startup must request capability admission"
        );
        peer.join().unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn configured_rnode_results_exclude_non_rnode() {
        let handle = dummy_handle();
        let standard = interface_factory::InterfaceConfig::TcpClient(
            rns_interface::tcp::TcpClientConfig::new("ordinary", "127.0.0.1", 1),
        );
        let handles = vec![test_interface_handle(41, None, "ordinary").into()];
        assert!(pending_configured_rnode_runtime(&standard, &handles).is_none());
        assert!(handle.startup_rnode_runtimes().is_empty());
    }

    #[tokio::test]
    async fn init_can_require_an_existing_shared_instance() {
        let (port, control_port) = free_tcp_port_pair().await;
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("reticulum_rs_require_shared_{nonce}_{port}"));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("config"),
            format!(
                "[reticulum]\nshare_instance = Yes\nshared_instance_type = unix\nshared_instance_port = {port}\ninstance_control_port = {control_port}\nenable_transport = No\n\n[interfaces]\n"
            ),
        )
        .unwrap();

        let result = init_with_options(
            Some(dir.to_str().unwrap()),
            None,
            ShutdownSignal::new(),
            Arc::new(AtomicBool::new(true)),
            InitOptions {
                require_shared_instance: true,
                shared_instance_type: Some(SharedInstanceType::Tcp),
            },
        )
        .await;

        assert!(matches!(
            result,
            Err(ReticulumError::RequiredSharedInstanceUnavailable)
        ));

        // Requiring a peer must not claim the listener while probing.
        let shutdown = ShutdownSignal::new();
        let handle = init_with_options(
            Some(dir.to_str().unwrap()),
            None,
            shutdown.clone(),
            Arc::new(AtomicBool::new(true)),
            InitOptions {
                require_shared_instance: false,
                shared_instance_type: Some(SharedInstanceType::Tcp),
            },
        )
        .await
        .unwrap();
        assert_eq!(handle.instance_mode, InstanceMode::Shared);
        handle.shutdown_and_wait().await;

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn test_init_shared_instance_tcp_server_then_client() {
        let (port, control_port) = free_tcp_port_pair().await;

        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir_a = std::env::temp_dir().join(format!("reticulum_rs_tcp_shared_a_{nonce}"));
        let dir_b = std::env::temp_dir().join(format!("reticulum_rs_tcp_shared_b_{nonce}"));
        let dir_c = std::env::temp_dir().join(format!("reticulum_rs_tcp_shared_c_{nonce}"));
        std::fs::create_dir_all(&dir_a).unwrap();
        std::fs::create_dir_all(&dir_b).unwrap();
        std::fs::create_dir_all(&dir_c).unwrap();
        let rpc_key_hex = "4242424242424242424242424242424242424242424242424242424242424242";
        let cfg = format!(
            "[reticulum]\nshare_instance = Yes\nshared_instance_type = tcp\nshared_instance_port = {port}\ninstance_control_port = {control_port}\nrpc_key = {rpc_key_hex}\nenable_transport = No\n\n[interfaces]\n"
        );
        std::fs::write(dir_a.join("config"), &cfg).unwrap();
        std::fs::write(dir_b.join("config"), &cfg).unwrap();
        std::fs::write(dir_c.join("config"), &cfg).unwrap();

        let shutdown_a = ShutdownSignal::new();
        let shutdown_b = ShutdownSignal::new();
        let shutdown_c = ShutdownSignal::new();
        let foreground_a = Arc::new(AtomicBool::new(true));
        let foreground_b = Arc::new(AtomicBool::new(true));
        let foreground_c = Arc::new(AtomicBool::new(true));

        let handle_a = init(
            Some(dir_a.to_str().unwrap()),
            None,
            shutdown_a.clone(),
            foreground_a,
        )
        .await
        .unwrap();
        assert_eq!(handle_a.instance_mode, InstanceMode::Shared);

        let handle_b = init(
            Some(dir_b.to_str().unwrap()),
            None,
            shutdown_b.clone(),
            foreground_b,
        )
        .await
        .unwrap();
        assert_eq!(handle_b.instance_mode, InstanceMode::Client);

        let handle_c = init(
            Some(dir_c.to_str().unwrap()),
            None,
            shutdown_c.clone(),
            foreground_c,
        )
        .await
        .unwrap();
        assert_eq!(handle_c.instance_mode, InstanceMode::Client);

        let server_entries = {
            let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(3);
            loop {
                let (stats_tx, stats_rx) = tokio::sync::oneshot::channel();
                handle_a
                    .transport_tx
                    .send(TransportMessage::Rpc {
                        query: rns_transport::messages::TransportQuery::GetInterfaceStats,
                        response_tx: stats_tx,
                    })
                    .await
                    .unwrap();
                let server_stats = stats_rx.await.unwrap();
                let entries = match server_stats {
                    rns_transport::messages::TransportQueryResponse::InterfaceStats(entries) => {
                        entries
                    }
                    other => panic!("unexpected stats response: {other:?}"),
                };
                let local_clients: Vec<_> = entries
                    .iter()
                    .filter(|entry| entry.role == "local_client")
                    .collect();
                if entries.iter().any(|entry| entry.role == "shared_server")
                    && local_clients.len() == 2
                    && local_clients.iter().all(|entry| entry.online)
                    && local_clients.iter().all(|entry| entry.tx_drops == 0)
                {
                    break entries;
                }
                if tokio::time::Instant::now() >= deadline {
                    break entries;
                }
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
        };
        let roles: Vec<String> = server_entries
            .iter()
            .map(|entry| entry.role.clone())
            .collect();
        assert!(
            roles.iter().any(|role| role == "shared_server"),
            "shared instance must mark the listener"
        );
        let local_clients: Vec<_> = server_entries
            .iter()
            .filter(|entry| entry.role == "local_client")
            .collect();
        assert_eq!(
            local_clients.len(),
            2,
            "transient shared-instance detection sockets must not remain registered"
        );
        assert!(
            local_clients.iter().all(|entry| entry.online),
            "accepted shared clients must be online"
        );
        assert!(
            local_clients.iter().all(|entry| entry.tx_drops == 0),
            "accepted shared clients must not accumulate TX drops"
        );

        let shared_control_stats = handle_b
            .query_control(rns_transport::messages::TransportQuery::GetInterfaceStats)
            .await
            .expect("client control query should reach shared instance");
        let shared_control_roles: Vec<String> = match shared_control_stats {
            rns_transport::messages::TransportQueryResponse::InterfaceStats(entries) => {
                entries.into_iter().map(|entry| entry.role).collect()
            }
            other => panic!("unexpected shared control stats response: {other:?}"),
        };
        assert!(
            shared_control_roles
                .iter()
                .any(|role| role == "shared_server"),
            "client control queries must proxy to the authoritative shared instance"
        );
        assert!(
            shared_control_roles
                .iter()
                .filter(|role| *role == "local_client")
                .count()
                >= 2,
            "proxied shared control stats must include accepted local clients"
        );

        let client_stats = handle_b
            .query_transport(rns_transport::messages::TransportQuery::GetInterfaceStats)
            .await
            .expect("client local stats should respond");
        let client_roles: Vec<String> = match client_stats {
            rns_transport::messages::TransportQueryResponse::InterfaceStats(entries) => {
                entries.into_iter().map(|entry| entry.role).collect()
            }
            other => panic!("unexpected client stats response: {other:?}"),
        };
        assert!(
            client_roles
                .iter()
                .any(|role| role == "shared_instance_peer"),
            "client mode must mark the interface to the shared instance"
        );

        let dest_hash = [0x42; 16];
        let (delivery_tx, mut delivery_rx) =
            tokio::sync::mpsc::channel::<rns_transport::link_messages::DestinationEvent>(8);
        handle_c
            .transport_tx
            .send(TransportMessage::RegisterDestination {
                hash: dest_hash,
                app_name: "reticulum.test.shared".to_string(),
                delivery_tx: Some(delivery_tx),
            })
            .await
            .unwrap();

        let raw = make_plain_data_packet(dest_hash, b"shared plain fanout");
        handle_b
            .transport_tx
            .send(TransportMessage::Outbound(
                rns_transport::messages::OutboundRequest {
                    raw: raw.clone(),
                    destination_hash: dest_hash,
                },
            ))
            .await
            .unwrap();

        let received = tokio::time::timeout(std::time::Duration::from_secs(2), async {
            loop {
                match delivery_rx.recv().await {
                    Some(rns_transport::link_messages::DestinationEvent::InboundPacket {
                        raw,
                        ..
                    }) => break raw,
                    Some(rns_transport::link_messages::DestinationEvent::AnnounceRequested(_)) => {
                        continue;
                    }
                    Some(other) => panic!("expected inbound shared packet, got {other:?}"),
                    None => panic!("destination channel closed"),
                }
            }
        })
        .await
        .expect("shared instance did not forward local-client plain packet");
        assert_eq!(received.as_ref(), raw.as_ref());

        let post_forward_stats = handle_b
            .query_control(rns_transport::messages::TransportQuery::GetInterfaceStats)
            .await
            .expect("post-forward control query should reach shared instance");
        let post_forward_entries = match post_forward_stats {
            rns_transport::messages::TransportQueryResponse::InterfaceStats(entries) => entries,
            other => panic!("unexpected post-forward stats response: {other:?}"),
        };
        let post_forward_local_clients: Vec<_> = post_forward_entries
            .iter()
            .filter(|entry| entry.role == "local_client")
            .collect();
        assert_eq!(
            post_forward_local_clients.len(),
            2,
            "forwarding through shared instance must not retain stale local clients"
        );
        assert!(
            post_forward_local_clients
                .iter()
                .all(|entry| entry.tx_drops == 0),
            "forwarding through shared instance must not report TX drops"
        );

        shutdown_c.trigger();
        shutdown_b.trigger();
        shutdown_a.trigger();
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        let _ = std::fs::remove_dir_all(&dir_a);
        let _ = std::fs::remove_dir_all(&dir_b);
        let _ = std::fs::remove_dir_all(&dir_c);
    }

    #[tokio::test]
    async fn init_with_stale_python_destination_table_serves_interface_stats_rpc() {
        let (port, control_port) = free_tcp_port_pair().await;

        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("reticulum_rs_stale_python_table_{nonce}"));
        std::fs::create_dir_all(&dir).unwrap();
        let storage_dir = dir.join("storage");
        write_stale_python_destination_table(&storage_dir, 512);

        let rpc_key_hex = "5353535353535353535353535353535353535353535353535353535353535353";
        let cfg = format!(
            "[reticulum]\nshare_instance = Yes\nshared_instance_type = tcp\nshared_instance_port = {port}\ninstance_control_port = {control_port}\nrpc_key = {rpc_key_hex}\nenable_transport = Yes\n\n[interfaces]\n"
        );
        std::fs::write(dir.join("config"), &cfg).unwrap();

        let shutdown = ShutdownSignal::new();
        let foreground = Arc::new(AtomicBool::new(true));
        let handle = init(
            Some(dir.to_str().unwrap()),
            None,
            shutdown.clone(),
            foreground,
        )
        .await
        .unwrap();
        assert_eq!(handle.instance_mode, InstanceMode::Shared);

        let rpc_key = hex::decode(rpc_key_hex).unwrap();
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(2);
        let response = loop {
            match crate::rpc::connect_and_request(
                control_port,
                &rpc_key,
                &crate::rpc::RpcRequest::GetInterfaceStats,
                std::time::Duration::from_secs(2),
            )
            .await
            {
                Ok(response) => break response,
                Err(crate::rpc::RpcError::Io(e))
                    if e.kind() == std::io::ErrorKind::ConnectionRefused
                        && tokio::time::Instant::now() < deadline =>
                {
                    tokio::time::sleep(std::time::Duration::from_millis(25)).await;
                }
                Err(e) => panic!("interface stats RPC should succeed: {e:?}"),
            }
        };

        let crate::rpc::RpcResponse::InterfaceStats(stats) = response else {
            panic!("unexpected interface stats response: {response:?}");
        };
        assert!(
            stats.iter().any(|entry| entry.role == "shared_server"),
            "rnstatus-style local RPC should see the shared server interface"
        );

        shutdown.trigger();
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    #[ignore = "requires network access to a public Reticulum TCP peer"]
    async fn live_tcp_public_testnet_interface_status_smoke() {
        let host = std::env::var("RSRETICULUM_LIVE_TCP_HOST")
            .unwrap_or_else(|_| "rns.ratspeak.org".to_string());
        let port = std::env::var("RSRETICULUM_LIVE_TCP_PORT")
            .ok()
            .and_then(|value| value.parse::<u16>().ok())
            .unwrap_or(4242);

        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("reticulum_rs_live_tcp_testnet_{nonce}"));
        std::fs::create_dir_all(&dir).unwrap();
        let cfg = format!(
            "[reticulum]\nshare_instance = No\nenable_transport = No\n\n[interfaces]\n\n[[Public TCP]]\ntype = TCPClientInterface\nenabled = Yes\ntarget_host = {host}\ntarget_port = {port}\n"
        );
        std::fs::write(dir.join("config"), &cfg).unwrap();

        let shutdown = ShutdownSignal::new();
        let foreground = Arc::new(AtomicBool::new(true));
        let handle = init(
            Some(dir.to_str().unwrap()),
            None,
            shutdown.clone(),
            foreground,
        )
        .await
        .unwrap();

        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
        let mut saw_online = false;
        while tokio::time::Instant::now() < deadline {
            let Some(rns_transport::messages::TransportQueryResponse::InterfaceStats(stats)) =
                handle
                    .query_transport(rns_transport::messages::TransportQuery::GetInterfaceStats)
                    .await
            else {
                tokio::time::sleep(std::time::Duration::from_millis(250)).await;
                continue;
            };

            if stats
                .iter()
                .any(|entry| entry.name == "Public TCP" && entry.online)
            {
                saw_online = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(250)).await;
        }

        shutdown.trigger();
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        let _ = std::fs::remove_dir_all(&dir);

        assert!(
            saw_online,
            "Public TCP interface did not come online for {host}:{port}"
        );
    }

    #[cfg(feature = "serial")]
    #[test]
    fn test_synthesize_interfaces_with_new_types() {
        let input = r#"
[interfaces]

[[Serial Port]]
type = SerialInterface
port = /dev/ttyUSB0
speed = 115200

[[KISS TNC]]
type = KISSInterface
port = /dev/ttyUSB1
speed = 57600

[[Auto Discovery]]
type = AutoInterface
group_id = testgroup

[[LoRa Radio]]
type = RNodeInterface
port = /dev/ttyACM0
frequency = 868000000
bandwidth = 125000
spreadingfactor = 7
codingrate = 5
txpower = 17

[[OpenCom XL]]
type = RNodeMultiInterface
port = /dev/ttyACM1
baud_rate = 230400

[[[High Datarate]]]
enabled = yes
vport = 1
frequency = 2400000000
bandwidth = 1625000
txpower = 0
spreadingfactor = 5
codingrate = 5

[[[Low Datarate]]]
enabled = yes
vport = 0
frequency = 865600000
bandwidth = 125000
txpower = 14
spreadingfactor = 7
codingrate = 5

[[Local]]
type = LocalInterface
port = 37428
"#;
        let config = Config::parse(input).unwrap();
        let interfaces = synthesize_interfaces(&config, false).unwrap();
        assert_eq!(interfaces.len(), 6);
        let rnode_multi = interfaces.iter().find_map(|iface| match iface {
            interface_factory::InterfaceConfig::RNodeMulti(c) => Some(c),
            _ => None,
        });
        let rnode_multi = rnode_multi.expect("RNodeMultiInterface synthesized");
        assert_eq!(rnode_multi.baud_rate, 230400);
        assert_eq!(rnode_multi.subinterfaces.len(), 2);
        assert_eq!(rnode_multi.subinterfaces[0].vport, 0);
        assert_eq!(rnode_multi.subinterfaces[1].vport, 1);
    }

    #[test]
    fn test_clean_cache_empty_dir() {
        let dir = std::env::temp_dir().join("reticulum_rs_test_clean_cache");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        clean_cache_dir(&dir, std::time::Duration::from_secs(DESTINATION_TIMEOUT));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_cache_cleanup_uses_python_ttls_and_hash_named_files() {
        use std::fs;

        let dir = std::env::temp_dir().join("reticulum_rs_test_clean_old");
        let _ = fs::remove_dir_all(&dir);
        let cache_dir = dir.join("cache");
        let resource_dir = dir.join("resources");
        fs::create_dir_all(&cache_dir).unwrap();
        fs::create_dir_all(&resource_dir).unwrap();

        let hash_name = "0123456789abcdef0123456789abcdef";
        let packet_path = cache_dir.join(hash_name);
        let resource_path = resource_dir.join(hash_name);
        let unrelated_path = resource_dir.join("unrelated");
        fs::write(&packet_path, b"packet").unwrap();
        fs::write(&resource_path, b"resource").unwrap();
        fs::write(&unrelated_path, b"keep").unwrap();
        let modified = fs::metadata(&resource_path).unwrap().modified().unwrap();

        let after_resource_ttl = modified + std::time::Duration::from_secs(RESOURCE_CACHE + 1);
        clean_cache_dir_at(
            &resource_dir,
            std::time::Duration::from_secs(RESOURCE_CACHE),
            after_resource_ttl,
        );
        clean_cache_dir_at(
            &cache_dir,
            std::time::Duration::from_secs(DESTINATION_TIMEOUT),
            after_resource_ttl,
        );
        assert!(!resource_path.exists(), "Resources expire after one day");
        assert!(
            packet_path.exists(),
            "packet cache entries live for seven days"
        );
        assert!(
            unrelated_path.exists(),
            "non-hash files are not cache entries"
        );

        let packet_modified = fs::metadata(&packet_path).unwrap().modified().unwrap();
        clean_cache_dir_at(
            &cache_dir,
            std::time::Duration::from_secs(DESTINATION_TIMEOUT),
            packet_modified + std::time::Duration::from_secs(DESTINATION_TIMEOUT + 1),
        );
        assert!(!packet_path.exists());

        let _ = fs::remove_dir_all(dir);
    }
}
