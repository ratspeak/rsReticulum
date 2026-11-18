//! Runtime construction, application operations and interface lifecycle.
//! Shared mode owns interfaces and serves local packet IPC and control RPC;
//! Client mode uses an existing shared owner; Standalone owns its interfaces
//! without serving shared-instance IPC.
//!
//! Start with [`init`] or [`init_with_policy`], retain the returned handle and
//! call [`ReticulumHandle::shutdown_and_wait`] before stopping Tokio. Configure
//! receivers before sending application traffic. Runtime interface creation
//! is rejected in Client mode and once shutdown begins. Successful interface
//! registration does not promise a connected peer or RNode protocol readiness,
//! and runtime-spawned interfaces are not written back to the config file.

use rns_identity::ifac::IfacKey;
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
use crate::shared_instance::{
    BoundControlListener, InstancePolicy, InstanceStartupError, SharedInstanceError,
    SharedInstanceState, spawn_authenticated_client,
};
use rns_identity::destination::{
    DestType, Destination, DestinationError, DestinationPacketError, DestinationPacketOptions,
    Direction,
};
use rns_identity::identity::Identity;
use rns_transport::actor::StorageRole;
use rns_transport::await_path::{AwaitPathError, await_path};
use rns_transport::constants::ANNOUNCE_CAP;
use rns_transport::constants::DESTINATION_TIMEOUT;
use rns_transport::discovery::constants::{
    BLACKHOLE_INITIAL_WAIT, BLACKHOLE_JOB_INTERVAL, BLACKHOLE_SOURCE_TIMEOUT,
    BLACKHOLE_UPDATE_INTERVAL,
};
use rns_transport::discovery::{
    Announcer, BlackholeSubscriberState, DiscoveredInterface, DiscoveryDecryptor,
    DiscoveryInterfaceConfig, DiscoveryStamper, DiscoveryStore, ReceiverConfig,
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
    transport_owner: rns_transport::messages::InterfaceOwner,
    registry_owner: u64,
    role: rns_transport::messages::InterfaceRole,
    ingress_overrides: rns_transport::ingress::IngressOverrides,
    // Parent IFAC, inherited by accepted child connections (Python parity:
    // spawned interfaces copy the listener's ifac_size/netname/netkey).
    ifac_key: Option<IfacKey>,
    ifac_size: usize,
    ifac_netname: Option<String>,
    /// The host and port a client interface connects to (Python
    /// `target_ip`, `target_port`), which auto-connect checks.
    client_target: Option<(String, u16)>,
    // Per-interface stamp costs, copied raw to spawned children (TCPInterface.py).
    destination_cost: Option<f64>,
    pr_cost: Option<f64>,
    /// What a connection this interface accepts takes from it.
    spawn: Option<SpawnInheritance>,
}

/// The listener settings Python copies to each accepted connection
/// (TCPInterface.py, BackboneInterface.py, I2PInterface.py).
#[derive(Clone)]
struct SpawnInheritance {
    mode: rns_interface::traits::InterfaceMode,
    outgoing: bool,
    bitrate: u64,
    mtu: u32,
    packet_capacity: rns_transport::messages::InterfacePacketCapacity,
    announce_cap: f64,
    announce_rate_target: Option<f64>,
    announce_rate_grace: Option<u32>,
    announce_rate_penalty: Option<f64>,
    recursive_prs: bool,
    announces_from_internal: bool,
    announces_to_internal: Option<bool>,
    gravity: i64,
    hop_limiter: Option<u8>,
}

impl SpawnInheritance {
    fn apply(&self, child: &mut rns_interface::traits::InterfaceHandle) {
        child.mode = self.mode;
        child.bitrate = self.bitrate;
        child.mtu = self.mtu;
        child.packet_capacity = self.packet_capacity;
        child.direction.outbound &= self.outgoing;
    }
}

type InterfaceControlMap = Arc<std::sync::Mutex<HashMap<u64, InterfaceControlMetadata>>>;

#[derive(Default)]
struct TransportCompletion {
    stopped: AtomicBool,
    notify: Notify,
}

const RUNTIME_INTERFACE_DRAIN_DEADLINE: Duration = Duration::from_secs(10);

/// Python `Transport.application_identity.hash`: one random requester per
/// process for destination type requests (Transport.py).
fn application_requester() -> [u8; 16] {
    static REQUESTER: OnceLock<[u8; 16]> = OnceLock::new();
    *REQUESTER.get_or_init(|| Identity::new().hash)
}

/// A shared instance's control RPC endpoint and key.
#[derive(Clone)]
struct SharedRpcTarget {
    endpoint: SharedInstanceRpcEndpoint,
    rpc_key: Vec<u8>,
}

impl SharedRpcTarget {
    const TIMEOUT: Duration = Duration::from_secs(5);

    async fn request(
        &self,
        request: &crate::rpc::RpcRequest,
    ) -> Result<crate::rpc::RpcResponse, crate::rpc::RpcError> {
        match &self.endpoint {
            SharedInstanceRpcEndpoint::Tcp(port) => {
                crate::rpc::connect_and_request(*port, &self.rpc_key, request, Self::TIMEOUT).await
            }
            SharedInstanceRpcEndpoint::Unix(socket_path) => {
                crate::rpc::connect_unix_and_request(
                    socket_path,
                    &self.rpc_key,
                    request,
                    Self::TIMEOUT,
                )
                .await
            }
        }
    }
}

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
    owned_control_task: std::sync::Mutex<Option<tokio::task::JoinHandle<()>>>,
    interface_panic: Arc<std::sync::OnceLock<String>>,
    exit_unwants: std::sync::Mutex<Option<SharedRpcTarget>>,
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
                owned_control_task: std::sync::Mutex::new(None),
                interface_panic: Arc::default(),
                exit_unwants: std::sync::Mutex::new(None),
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

    /// Python's exit handler deregisters this process's destination types
    /// from the shared instance first (Reticulum.py).
    fn install_exit_unwants(&self, target: SharedRpcTarget) {
        *self
            .inner
            .exit_unwants
            .lock()
            .expect("exit unwants mutex poisoned") = Some(target);
    }

    fn is_started(&self) -> bool {
        self.inner.started.load(Ordering::Acquire)
    }

    // Strict startup holds a spawn permit through installation, so shutdown
    // cannot pass wait_for_spawn_permits before this listener is retained.
    fn install_owned_control_task(&self, task: tokio::task::JoinHandle<()>) {
        *self
            .inner
            .owned_control_task
            .lock()
            .expect("control task mutex poisoned") = Some(task);
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
        let exit_unwants = self
            .inner
            .exit_unwants
            .lock()
            .expect("exit unwants mutex poisoned")
            .take();
        if let Some(target) = exit_unwants {
            let request = crate::rpc::RpcRequest::UnwantsAllDestinationTypes {
                requester: application_requester().to_vec(),
                signature: None,
            };
            if let Err(error) = target.request(&request).await {
                tracing::debug!(%error, "shared instance RPC failed while deregistering destination types");
            }
        }
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

        let control = self
            .inner
            .owned_control_task
            .lock()
            .expect("control task mutex poisoned")
            .take();
        if let Some(control) = control {
            let _ = control.await;
        }

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
            let transport_owner =
                remove_interface_control_if_owner(&self.inner.interface_controls, id, owner);
            if let Some(transport_owner) = transport_owner
                && !self
                    .inner
                    .transport_completion
                    .stopped
                    .load(Ordering::Acquire)
            {
                let _ = rns_transport::messages::InterfaceTransportSender::bind(
                    id,
                    transport_owner,
                    self.inner.transport_tx.clone(),
                )
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
/// Cloneable access to one running runtime. Clones share actor and interface
/// ownership; configuration fields are snapshots, not a general live
/// reconfiguration API. Dropping handles alone does not stop a runtime;
/// use `shutdown_and_wait` while Tokio is still running.
pub struct ReticulumHandle {
    pub transport_tx: mpsc::Sender<TransportMessage>,
    path_recovery: rns_transport::path_recovery::PathRecoveryHandle,
    link_endpoint_dispatch: rns_transport::link_endpoint_dispatch::LinkEndpointDispatchHandle,
    announce_dispatch: rns_transport::announce_dispatch::AnnounceDispatchHandle,
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
    /// Wire-facing identity. A non-transport node gets a fresh identity on
    /// startup unless `static_transport_identity` is enabled. The default
    /// local RPC key is derived from the separate persisted identity.
    pub transport_identity: Arc<Identity>,
    pub network_identity: Option<Arc<Identity>>,
    /// Present even when `discover_interfaces = No` so a downstream can
    /// still install a stamper and start publishing.
    pub discovery: Arc<DiscoveryRuntime>,
    startup_rnode_runtimes: Vec<StartupRNodeRuntime>,
    startup_interface_failures: Vec<(String, String)>,
    #[cfg(feature = "ble")]
    deferred_android_ble_rnodes: Vec<interface_factory::BleRNodeInterfaceConfig>,
    shutdown_coordinator: RuntimeShutdownCoordinator,
    shared_instance_status: Option<watch::Receiver<SharedInstanceState>>,
    started_at: std::time::Instant,
}

/// Identity and announce metadata from this process's transport cache.
/// Entries can have been restored from storage; this value does not establish
/// fresh signature verification or current reachability.
#[derive(Clone)]
pub struct RecalledDestination {
    pub destination_hash: [u8; 16],
    pub identity: Identity,
    pub app_data: Option<Vec<u8>>,
    pub ratchet: Option<[u8; 32]>,
    pub hops: u8,
    pub last_heard: std::time::SystemTime,
    /// Python `Identity.recall_stamp_value`: 0 for a known unstamped destination.
    pub stamp_value: Option<f64>,
    /// Python `Identity.recall_link_cost`: the announced link-request cost, if any.
    pub link_cost: Option<f64>,
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
    paused: Arc<AtomicBool>,
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

    /// Stop delivering matching announces until [`Self::resume`]. Announces
    /// arriving meanwhile are skipped, not queued; path learning is unaffected.
    pub fn pause(&self) {
        self.paused.store(true, Ordering::Relaxed);
    }

    pub fn resume(&self) {
        self.paused.store(false, Ordering::Relaxed);
    }

    pub fn is_paused(&self) -> bool {
        self.paused.load(Ordering::Relaxed)
    }

    /// Request exact deregistration and wait for the actor's acknowledgment.
    /// False means already closed or no matching subscription. This has no
    /// whole-call timeout and does not consume events already in the queue.
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
/// `online` is the shared interface projection retained for compatibility.
/// Serial/TCP drivers publish exact protocol readiness through it; other
/// transports may expose a narrower transport-specific state. Use `observer`
/// and [`RNodeRuntimeObserver::await_ready`] whenever exact cross-transport
/// protocol readiness is required.
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

    /// Wait for this driver's current `Ready` phase with a nonzero connection
    /// generation. One absolute deadline spans reconnects; dropping the future
    /// does not affect the driver. A currently ready snapshot returns immediately.
    /// A duration too large for Tokio's deadline representation waits without
    /// a timeout. Readiness does not attest to RF range or peer reachability.
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

    /// The typed capability admission failure class, when the driver stopped
    /// because a capability admission was rejected.
    pub fn capability_admission_failure(
        &self,
    ) -> Option<rns_interface::rnode::RNodeCapabilityAdmissionFailureClass> {
        match self {
            Self::Timeout { last }
            | Self::ShuttingDown { last }
            | Self::Stopped { last }
            | Self::ObservationClosed { last } => last.capability_admission_failure,
        }
    }
}

/// Options for [`ReticulumHandle::send_to`].
#[derive(Debug, Clone)]
pub struct SendOptions {
    /// Request a receipt for a non-PLAIN packet. PLAIN ignores this option;
    /// tracked destinations must have identity metadata in the local cache.
    pub create_receipt: bool,
    /// Override the receipt's proof timeout, not the duration of `send_to`.
    /// `None` uses route timing, with a 180-second fallback if lookup fails.
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

/// Local dispatch result: an interface queue accepted the packet. This is
/// not on-air confirmation or a peer-delivery proof; inspect `receipt` when
/// present for a terminal protocol outcome.
#[derive(Debug, Clone)]
pub struct SendResult {
    pub packet_hash: [u8; 32],
    pub receipt: Option<PacketReceiptHandle>,
}

/// Stateful non-Link application packet that can be sent and re-sent.
/// Re-sending repeats destination packet construction. Encrypted destinations
/// produce fresh ciphertext; PLAIN data is not encrypted and can retain its
/// packet hash. A new receipt is requested only when the options and
/// destination type support one.
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
    /// Whether the wrapper's latest send state is successful local dispatch.
    /// This is not peer delivery; a failed `resend` resets the flag.
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

    /// Repeat a previously successful send using destination packet construction.
    /// On failure this wrapper resets its sent flag; call `send` for the next
    /// attempt. Success still means local dispatch, not remote delivery.
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

    /// Change the timeout while the receipt remains pending, measured from
    /// its original actor-side receipt creation time. This does not restart
    /// the clock. Admission and acknowledgment have no timeout of their own.
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

    /// Wait for a valid destination-signed proof or another terminal receipt
    /// state. Delivery does not attest to application processing or persistence.
    /// This waiter relies on the actor's receipt timer; it adds no outer deadline.
    pub async fn delivered(mut self) -> Result<Duration, ReceiptError> {
        loop {
            match self.status() {
                ReceiptUpdate::Sent => {
                    self.status_rx
                        .changed()
                        .await
                        .map_err(|_| ReceiptError::TransportClosed)?;
                }
                ReceiptUpdate::Delivered { rtt, .. } => return Ok(rtt),
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

/// Largest payload whose HEADER_1 packet fits the MTU for a destination type.
fn max_header1_payload(dest_type: DestType) -> usize {
    use rns_wire::constants::{AES128_BLOCKSIZE, HEADER_MINSIZE, KEYSIZE, MTU, TOKEN_OVERHEAD};
    let room = MTU - HEADER_MINSIZE;
    match dest_type {
        DestType::Single => {
            (room - KEYSIZE / 16 - TOKEN_OVERHEAD) / AES128_BLOCKSIZE * AES128_BLOCKSIZE - 1
        }
        DestType::Group => (room - TOKEN_OVERHEAD) / AES128_BLOCKSIZE * AES128_BLOCKSIZE - 1,
        DestType::Plain | DestType::Link => room,
    }
}

#[derive(Debug, thiserror::Error)]
pub enum SendError {
    #[error("destination must be outbound")]
    InboundDestination,
    #[error("Link destinations must use LinkSession")]
    LinkDestination,
    #[error("no validated identity is known for destination {0}")]
    IdentityUnavailable(String),
    #[error("payload is {actual} bytes; the largest payload that fits the MTU is {max}")]
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
    /// Path-resolution budget when required identity/path metadata is absent.
    /// A cache hit need not trigger fresh discovery or signature verification.
    pub path_timeout: Duration,
    /// Timeout for Link request admission and proof waiting, not the entire
    /// connection call. When omitted, it is first-hop timeout plus the default
    /// per-hop timeout times at least one hop. `Some(Duration::ZERO)` selects
    /// zero for this phase; other setup/cleanup work can still take time.
    pub establishment_timeout: Option<Duration>,
    /// Registration label used for the temporary Link destination.
    pub client_label: String,
    /// Send the local identity over the Link after establishment.
    pub identify: bool,
    /// Retain RSSI, SNR and quality measurements reported by interfaces.
    pub track_phy_stats: bool,
    /// Largest advertised total size of an inbound Resource the session
    /// reassembles in memory; `None` reassembles any size. A Resource
    /// accepted to a file is not bound by it. See
    /// [`rns_protocol::resource::DEFAULT_INBOUND_REASSEMBLY_LIMIT`].
    pub inbound_reassembly_limit: Option<usize>,
}

impl Default for LinkConnectOptions {
    fn default() -> Self {
        Self {
            path_timeout: Duration::from_secs(15),
            establishment_timeout: None,
            client_label: "rns-runtime.link".to_string(),
            identify: false,
            track_phy_stats: false,
            inbound_reassembly_limit: Some(
                rns_protocol::resource::DEFAULT_INBOUND_REASSEMBLY_LIMIT,
            ),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum LinkConnectError {
    #[error("transport control failed: {0}")]
    Control(#[from] ControlError),
    #[error("path discovery failed: {0}")]
    Path(#[from] AwaitPathError),
    #[error("destination resolution failed: {0}")]
    Resolve(#[from] crate::destination_resolver::DestinationResolveError),
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
            .field("stamp_value", &self.stamp_value)
            .field("link_cost", &self.link_cost)
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

/// Discovery state shared by cloned runtime handles. Install a
/// [`DiscoveryStamper`] through [`ReticulumHandle::enable_on_network_discovery`]
/// to start configured receiving and publication; constructing this state
/// alone does not start either service.
pub struct DiscoveryRuntime {
    stamper: Mutex<Option<Arc<dyn DiscoveryStamper + Send + Sync>>>,
    store: Mutex<Option<Arc<DiscoveryStore>>>,
    receiver_started: Mutex<bool>,
    announcer_started: Mutex<bool>,
    subscriber_started: Mutex<bool>,
    local_interfaces: Mutex<Vec<LocalDiscoveryInterface>>,
    /// Any configured section is discoverable, enabled or not (Reticulum.py).
    announcer_configured: AtomicBool,
    autoconnected: Mutex<HashMap<[u8; 32], AutoconnectedInterface>>,
    bootstrap_interfaces: Mutex<Vec<u64>>,
    /// Configs of `bootstrap_only` interfaces, re-spawned when no
    /// auto-connected interface is online (Reticulum.py).
    bootstrap_configs: Mutex<Vec<BootstrapConfig>>,
    /// A bootstrap-only I2P interface stays attached (Reticulum.py), so
    /// Python never re-enables bootstrap interfaces beside it.
    i2p_bootstrap: AtomicBool,
    autoconnect_lock: Mutex<()>,
    autoconnect_monitor_started: AtomicBool,
    initial_autoconnect_ran: AtomicBool,
}

/// An auto-connected interface under the monitor (Discovery.py).
struct AutoconnectedInterface {
    /// `None` while the interface is still being spawned.
    id: Option<u64>,
    online: Option<Arc<AtomicBool>>,
    down_since: Option<std::time::Instant>,
}

struct BootstrapConfig {
    config: interface_factory::InterfaceConfig,
    post_init: interface_factory::InterfacePostInit,
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
            announcer_configured: AtomicBool::new(false),
            autoconnected: Mutex::new(HashMap::new()),
            bootstrap_interfaces: Mutex::new(Vec::new()),
            bootstrap_configs: Mutex::new(Vec::new()),
            i2p_bootstrap: AtomicBool::new(false),
            autoconnect_lock: Mutex::new(()),
            autoconnect_monitor_started: AtomicBool::new(false),
            initial_autoconnect_ran: AtomicBool::new(false),
        }
    }
}

#[derive(Debug, Clone)]
struct LocalDiscoveryInterface {
    id: u64,
    config: DiscoveryInterfaceConfig,
    online: Option<Arc<AtomicBool>>,
    /// Overrides `config.reachable_on` once the interface learns its address.
    reachable_on: Option<tokio::sync::watch::Receiver<Option<String>>>,
    /// Python `location_cmd` (Reticulum.py).
    location_cmd: Option<String>,
}

impl ReticulumHandle {
    /// Obtain bounded failed-Link route recovery for this local transport
    /// generation. Shared clients recover only their local actor's route;
    /// discovery traverses normal shared packet IPC, never a private owner-RPC
    /// extension or permission to mutate the owner's interfaces.
    pub fn path_recovery_handle(&self) -> rns_transport::path_recovery::PathRecoveryHandle {
        self.path_recovery.clone()
    }

    /// Obtain bounded generation-bound Link packet dispatch on this runtime's
    /// local actor. Completion reports interface-driver or shared-IPC admission,
    /// not radio transmission or remote delivery.
    pub fn link_endpoint_dispatch_handle(
        &self,
    ) -> rns_transport::link_endpoint_dispatch::LinkEndpointDispatchHandle {
        self.link_endpoint_dispatch.clone()
    }

    /// Recorded non-fatal failures after interface configuration synthesis,
    /// as `(name, reason)`. Other interfaces can remain usable. Earlier parsing
    /// or synthesis failures may be logged without appearing here. Shared
    /// clients do not spawn configured interfaces and return an empty slice.
    pub fn startup_interface_failures(&self) -> &[(String, String)] {
        &self.startup_interface_failures
    }

    /// Last authenticated shared-client state. Generic automatic clients do
    /// not opt into this policy and return `None`.
    pub fn shared_instance_state(&self) -> Option<SharedInstanceState> {
        self.shared_instance_status.as_ref().map(|status| {
            if self.shutdown_coordinator.is_started() || status.has_changed().is_err() {
                SharedInstanceState::Stopped
            } else {
                *status.borrow()
            }
        })
    }

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

    /// Return the exact enabled BLE RNode configurations deferred to Android's
    /// Kotlin-owned native GATT bridge during startup.
    ///
    /// This config-order snapshot is inventory only. It grants no registration,
    /// reconnect, or teardown authority; the application must use the native
    /// runtime spawn APIs and retain the returned exact owner. It is empty on
    /// non-Android platforms and in shared-instance client mode.
    #[cfg(feature = "ble")]
    pub fn deferred_android_ble_rnodes(&self) -> Vec<interface_factory::BleRNodeInterfaceConfig> {
        self.deferred_android_ble_rnodes.clone()
    }

    pub fn link_mtu_discovery(&self) -> bool {
        self.config.link_mtu_discovery
    }

    /// Start runtime-owned shutdown and wait for interface ownership cleanup
    /// and transport termination. Normal transport shutdown attempts synchronous
    /// state persistence; this API returns no persistence error or durability
    /// receipt. Dropping the future does not cancel cleanup. Some stop/transport
    /// waits are outside the interface-task join deadline; there is no whole-call
    /// timeout.
    pub async fn shutdown_and_wait(&self) {
        self.shutdown_coordinator.start_and_wait().await;
    }

    /// The interface whose hardware failure shut this runtime down under
    /// `panic_on_interface_error`, where Python calls `RNS.panic()`.
    pub fn interface_panic(&self) -> Option<&str> {
        self.shutdown_coordinator
            .inner
            .interface_panic
            .get()
            .map(String::as_str)
    }

    /// Wait for the local actor to confirm a current path, requesting one if
    /// needed. One deadline covers mailbox admission and reply waiting. Success
    /// is a routing observation, not proof that the destination application
    /// will respond.
    pub async fn await_path(
        &self,
        destination_hash: [u8; 16],
        timeout: Duration,
    ) -> Result<(), AwaitPathError> {
        await_path(&self.transport_tx, destination_hash, timeout).await
    }

    /// Resolve cached identity/path metadata and open a persistent encrypted
    /// [`LinkSession`], requesting a path when needed. Cache data is trusted
    /// without fresh announce-signature verification. The Link proof is checked
    /// against the resolved signing key.
    ///
    /// Path and establishment options bound particular phases, not the complete
    /// call. Use a caller deadline when needed, and keep draining the returned
    /// session's events.
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
        let recalled = crate::destination_resolver::resolve_destination_on_transport(
            &self.transport_tx,
            destination_hash,
            crate::destination_resolver::DestinationResolveOptions::new(options.path_timeout),
        )
        .await?;
        let recalled = recalled_destination_from_rpc(recalled)?;
        // Link.py takes the hop count from `Transport.hops_to`, the path, never
        // from the remembered announce, whose hop count may be older or unknown.
        let hops = self.hops_to(destination_hash).await?;
        let establishment_timeout = match options.establishment_timeout {
            Some(timeout) => timeout,
            None => {
                let first_hop_timeout = self.first_hop_timeout(destination_hash).await?;
                link_establishment_timeout(first_hop_timeout, hops)?
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
            proof_strategy: rns_identity::destination::ProofStrategy::ProveNone,
            resource_dir: Some(StoragePaths::from_config_dir(&self.config_dir).resource_dir),
            inbound_reassembly_limit: options.inbound_reassembly_limit,
        })
    }

    /// Subscribe to matching validated announce events with capacity 128.
    /// Use the returned stream's dropped counter to detect capacity loss.
    /// Registration waits for acknowledgment without a whole-call deadline.
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

    /// Register an announce subscription with nonzero capacity. The actor
    /// verifies matching announces before dispatch; a full receiver drops events
    /// and increments its counter. Registration waits for actor acknowledgment
    /// without an outer timeout. Drop or close the subscription when finished.
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
        let paused = Arc::new(AtomicBool::new(false));
        let (result_tx, result_rx) = tokio::sync::oneshot::channel();
        self.transport_tx
            .send(TransportMessage::RegisterAnnounceSubscription {
                aspect_filter,
                receive_path_responses,
                callback_tx,
                dropped_events: Arc::clone(&dropped_events),
                paused: Arc::clone(&paused),
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
            paused,
            transport_tx: self.transport_tx.clone(),
        })
    }

    /// Prepare a stateful wrapper around [`Self::send_to`]. No packet is sent
    /// until `send` or `resend` is called. Each attempt repeats cache lookup and
    /// packet construction; only encrypted destinations get fresh ciphertext.
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

    /// Build and dispatch a non-Link packet for an outbound destination.
    /// SINGLE always needs identity metadata in this process's announce cache;
    /// other tracked destinations also need it. This method does not discover a
    /// missing identity. PLAIN is unencrypted and never gets a receipt.
    ///
    /// Success means an interface queue accepted the packet. The optional receipt
    /// reports a later peer proof, not application consumption. `options.timeout`
    /// applies to that receipt; transport submission and dispatch reply have no
    /// whole-call deadline. Use [`Self::outbound_packet`] for explicit resend state.
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

        // Python does not create receipts for PLAIN packets.
        let create_receipt = options.create_receipt && destination.dest_type != DestType::Plain;
        let recalled = if destination.dest_type == DestType::Single || create_receipt {
            Some(
                self.recall_identity(destination.hash)
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
        // Like the reference `Packet.pack`, only the packed size is limited.
        let packet = match destination.pack_packet(
            data,
            Some(encryption_identity),
            ratchet,
            DestinationPacketOptions::default(),
        ) {
            Ok(packed) => packed.packet,
            Err(DestinationPacketError::Packet(rns_wire::packet::PacketError::ExceedsMtu(_))) => {
                return Err(SendError::PayloadTooLarge {
                    actual: data.len(),
                    max: max_header1_payload(destination.dest_type),
                });
            }
            Err(error) => return Err(error.into()),
        };
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
        // Reticulum.py and Transport.py fallbacks.
        let first_hop =
            self.first_hop_timeout(destination_hash)
                .await
                .unwrap_or(Duration::from_secs_f64(
                    rns_wire::constants::DEFAULT_PER_HOP_TIMEOUT,
                ));
        let hops = self
            .hops_to(destination_hash)
            .await
            .unwrap_or(rns_transport::constants::PATHFINDER_M);
        rns_wire::receipt::receipt_timeout_for_route(first_hop, hops)
    }

    /// Query this process's actor with a five-second admission-and-reply budget.
    /// Errors become `None`; even in Client mode this does not query the shared
    /// owner. Use `query_control_result` for typed control errors.
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

    /// Read identity and announce metadata from this process's transport cache
    /// and mark the destination used, like Python's `Identity.recall`. The
    /// lookup stays local in Client mode; the use mark goes to the shared owner
    /// over RPC, as Python's `_used_destination_data` does. A failed use mark
    /// does not fail the recall.
    ///
    /// The helper does not verify a fresh signature or check current presence.
    /// Stored cache metadata can be restored with structural checks alone; keep
    /// its storage within the application's trust boundary. `None` means no
    /// identity-bearing entry, not a failed on-network lookup.
    pub async fn recall(
        &self,
        destination_hash: [u8; 16],
    ) -> Result<Option<RecalledDestination>, ControlError> {
        let recalled = self.recall_without_use(destination_hash).await?;
        if recalled.is_some() {
            let _ = self
                .query_control_result(TransportQuery::UseDestination {
                    dest: destination_hash,
                })
                .await;
        }
        Ok(recalled)
    }

    /// `recall` without marking the destination used (Python `_no_use=True`),
    /// for displays and internal lookups that must not extend retention.
    pub async fn recall_without_use(
        &self,
        destination_hash: [u8; 16],
    ) -> Result<Option<RecalledDestination>, ControlError> {
        let mut recalled = self.recall_identity(destination_hash).await?;
        if let Some(recalled) = recalled.as_mut() {
            recalled.stamp_value = self.recall_stamp_value(destination_hash).await?;
            recalled.link_cost = self.recall_link_cost(destination_hash).await?;
        }
        Ok(recalled)
    }

    /// `recall` without the stamp fields, for callers that need only the identity.
    async fn recall_identity(
        &self,
        destination_hash: [u8; 16],
    ) -> Result<Option<RecalledDestination>, ControlError> {
        match self
            .query_transport_result(TransportQuery::RecallDestination {
                dest: destination_hash,
            })
            .await?
        {
            TransportQueryResponse::RecalledDestination(entry) => {
                entry.map(recalled_destination_from_rpc).transpose()
            }
            _ => Err(ControlError::UnexpectedResponse {
                operation: "destination recall",
            }),
        }
    }

    /// Python `Identity.recall_stamp_value`: the last heard announce stamp
    /// value, 0 when the destination announced without a stamp, `None` when
    /// it is unknown. Local to this process, like `recall`.
    pub async fn recall_stamp_value(
        &self,
        destination_hash: [u8; 16],
    ) -> Result<Option<f64>, ControlError> {
        match self
            .query_transport_result(TransportQuery::RecallStampValue {
                dest: destination_hash,
            })
            .await?
        {
            TransportQueryResponse::FloatResult(value) => Ok(value),
            _ => Err(ControlError::UnexpectedResponse {
                operation: "stamp value recall",
            }),
        }
    }

    /// Python `Identity.recall_link_cost`: the link-request stamp cost the
    /// destination announced, `None` when unknown or not announced.
    pub async fn recall_link_cost(
        &self,
        destination_hash: [u8; 16],
    ) -> Result<Option<f64>, ControlError> {
        match self
            .query_transport_result(TransportQuery::RecallLinkCost {
                dest: destination_hash,
            })
            .await?
        {
            TransportQueryResponse::FloatResult(value) => Ok(value),
            _ => Err(ControlError::UnexpectedResponse {
                operation: "link cost recall",
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

    /// Return the next-hop interface MTU in bytes, when available. A Client's
    /// next hop is its own local shared-instance interface (Transport.py,
    /// 3517-3524). This interface value is not a negotiated Link payload
    /// budget or the MTU of every hop on the path.
    pub async fn next_hop_hardware_mtu(
        &self,
        destination_hash: [u8; 16],
    ) -> Result<Option<u32>, ControlError> {
        match self
            .query_transport_result(TransportQuery::GetNextHopHardwareMtu {
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

    /// Return the first-hop timeout estimate. In Client mode, a positive
    /// `force_shared_instance_bitrate` adds the estimated transmission time
    /// of one Reticulum MTU over the shared link. This is a protocol timing
    /// input, not a measured or guaranteed transmission duration.
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

    /// Enqueue a path request, optionally restricted to an interface and tag.
    /// Success means mailbox admission, not path resolution. This method has
    /// no submission timeout; use `await_path` to wait with a deadline.
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

    /// Return the control-plane path snapshot, optionally limited by hop count.
    /// Client mode queries the shared owner, but its RPC format omits local
    /// interface id/mode/role: these fields become `0`, `Full` and `Normal`.
    /// Do not treat those fallback fields as observed owner configuration.
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

    /// Return interface statistics from the local actor or shared owner's RPC.
    /// Aggregate traffic counters use saturating sums of returned interface records.
    ///
    /// Transport identity/uptime metadata is available here only for a local
    /// transport node; probe and process-memory fields are `None`. Entries read
    /// from a shared instance carry what its RPC reply carries: the parent's
    /// name without its id, and no driver radio keys.
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
            && let Some(bitrate) = self
                .config
                .force_shared_instance_bitrate
                .filter(|bitrate| *bitrate > 0)
            && let TransportQueryResponse::FloatResult(Some(seconds)) = &mut response
        {
            *seconds += (rns_wire::constants::MTU as f64 * 8.0) / bitrate as f64;
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

    /// Query the local actor, or the shared owner's authenticated control RPC
    /// in Client mode. A failed or unsupported shared request does not fall back
    /// to the local actor. Local queries have one five-second deadline; shared
    /// RPC uses per-operation timeouts, not one whole-call deadline.
    pub async fn query_control_result(
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

    fn shared_rpc_target(&self) -> Option<SharedRpcTarget> {
        Some(SharedRpcTarget {
            endpoint: self.config.shared_rpc_endpoint(&self.socket_base),
            rpc_key: self.config.rpc_key.clone()?,
        })
    }

    async fn local_filter_query(&self, query: TransportQuery) -> bool {
        matches!(
            self.query_transport_result(query).await,
            Ok(TransportQueryResponse::BoolResult(true))
        )
    }

    /// A destination type request: registered locally, and on a shared-instance
    /// client also with the shared instance, whose answer is returned. A failed
    /// RPC answers false (Reticulum.py).
    async fn destination_type_request(
        &self,
        local: TransportQuery,
        remote: crate::rpc::RpcRequest,
    ) -> bool {
        if self.instance_mode != InstanceMode::Client {
            return self.local_filter_query(local).await;
        }
        self.local_filter_query(local).await;
        let Some(target) = self.shared_rpc_target() else {
            return false;
        };
        match target.request(&remote).await {
            Ok(crate::rpc::RpcResponse::BoolResult(v)) => v,
            Ok(other) => {
                tracing::debug!(
                    ?other,
                    "unexpected shared instance reply to a destination type request"
                );
                false
            }
            Err(error) => {
                tracing::debug!(%error, "shared instance RPC failed while setting destination type filters");
                false
            }
        }
    }

    /// Python `Reticulum.attach_interface`: brings up a configured interface
    /// that is not running, even one disabled in its section. True, false, or
    /// `None` when the configuration has no such section. A shared-instance
    /// client forwards the call to the instance (Reticulum.py).
    pub async fn attach_interface(&self, name: &str) -> Result<Option<bool>, ControlError> {
        if self.instance_mode == InstanceMode::Client {
            return self
                .forward_manage(crate::rpc::ManageOperation::Attach, name)
                .await;
        }
        if !self.config.enable_interface_management {
            return Ok(Some(false));
        }
        Ok(self.attach_configured_interface(name).await)
    }

    /// Python `Reticulum.detach_interface`: stops and removes a running
    /// interface and the connections it spawned. `None` when no interface has
    /// that name (Reticulum.py).
    pub async fn detach_interface(&self, name: &str) -> Result<Option<bool>, ControlError> {
        if self.instance_mode == InstanceMode::Client {
            return self
                .forward_manage(crate::rpc::ManageOperation::Detach, name)
                .await;
        }
        if !self.config.enable_interface_management {
            return Ok(Some(false));
        }
        Ok(self.detach_running_interface(name).await)
    }

    /// Python `Reticulum.reload_interface`: detaches a running interface and
    /// attaches it again from the current configuration (Reticulum.py).
    pub async fn reload_interface(&self, name: &str) -> Result<Option<bool>, ControlError> {
        if self.instance_mode == InstanceMode::Client {
            return self
                .forward_manage(crate::rpc::ManageOperation::Reload, name)
                .await;
        }
        if !self.config.enable_interface_management {
            return Ok(Some(false));
        }
        if self.running_interface(name).await.is_none() {
            return Ok(None);
        }
        let reloaded = self.detach_running_interface(name).await == Some(true)
            && self.attach_configured_interface(name).await == Some(true);
        if reloaded {
            rns_transport::notice!("Interface \"{name}\" was reloaded");
        } else {
            rns_transport::notice!("Could not reload interface \"{name}\"");
        }
        Ok(Some(reloaded))
    }

    async fn forward_manage(
        &self,
        operation: crate::rpc::ManageOperation,
        name: &str,
    ) -> Result<Option<bool>, ControlError> {
        let target = self
            .shared_rpc_target()
            .ok_or(ControlError::NotConnectedToSharedInstance)?;
        let request = crate::rpc::RpcRequest::ManageInterface {
            operation,
            name: name.to_string(),
        };
        match target
            .request(&request)
            .await
            .map_err(|error| control_error_from_rpc(error, SharedRpcTarget::TIMEOUT))?
        {
            crate::rpc::RpcResponse::BoolResult(v) => Ok(Some(v)),
            crate::rpc::RpcResponse::StringResult(None) => Ok(None),
            crate::rpc::RpcResponse::Error(error) => Err(ControlError::Rpc(error)),
            _ => Err(ControlError::UnexpectedResponse {
                operation: "interface management request",
            }),
        }
    }

    /// The last running interface with this name, as Python's name map keeps
    /// the last of `Transport.interfaces`, with every interface it spawned.
    async fn running_interface(
        &self,
        name: &str,
    ) -> Option<(
        rns_transport::messages::InterfaceStatRpcEntry,
        Vec<rns_transport::messages::InterfaceId>,
    )> {
        let Ok(TransportQueryResponse::InterfaceStats(entries)) = self
            .query_transport_result(TransportQuery::GetInterfaceStats)
            .await
        else {
            return None;
        };
        let entry = entries
            .iter()
            .rfind(|entry| {
                entry
                    .identity
                    .as_ref()
                    .map_or(entry.name.as_str(), |identity| identity.short_name.as_str())
                    == name
            })?
            .clone();
        let spawned = entries
            .iter()
            .filter(|child| child.parent_id == Some(entry.id))
            .map(|child| child.id)
            .collect();
        Some((entry, spawned))
    }

    async fn detach_running_interface(&self, name: &str) -> Option<bool> {
        let Some((entry, spawned)) = self.running_interface(name).await else {
            tracing::warn!("Attempt to detach non-existing interface \"{name}\"");
            return None;
        };
        if !self.detach_entry(&entry, spawned).await {
            return Some(false);
        }
        // Upstream's detach is synchronous: a reload attaches straight after it.
        let gone_by = tokio::time::Instant::now() + Duration::from_secs(5);
        while self.running_interface(name).await.is_some() && tokio::time::Instant::now() < gone_by
        {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        rns_transport::notice!("Interface \"{name}\" was detached");
        Some(true)
    }

    /// Python `_detach_interface(..., internal_forced=True)`, which transport
    /// calls for a bad or blackholed tunnel peer: it ignores
    /// `enable_interface_management`, and a client so detached stays down until
    /// restart or attach (Reticulum.py:976-1015).
    pub(crate) async fn detach_interface_by_id(
        &self,
        id: rns_transport::messages::InterfaceId,
    ) -> Option<bool> {
        let Ok(TransportQueryResponse::InterfaceStats(entries)) = self
            .query_transport_result(TransportQuery::GetInterfaceStats)
            .await
        else {
            return None;
        };
        let entry = entries.iter().find(|entry| entry.id == id)?.clone();
        let spawned = entries
            .iter()
            .filter(|child| child.parent_id == Some(id))
            .map(|child| child.id)
            .collect();
        if !self.detach_entry(&entry, spawned).await {
            return Some(false);
        }
        let name = entry
            .identity
            .as_ref()
            .map_or(entry.name.as_str(), |identity| identity.name.as_str());
        rns_transport::notice!("Interface {name} was detached");
        Some(true)
    }

    /// Tear down an interface and those it spawned; I2P listeners and local
    /// interfaces refuse (Reticulum.py).
    async fn detach_entry(
        &self,
        entry: &rns_transport::messages::InterfaceStatRpcEntry,
        spawned: Vec<rns_transport::messages::InterfaceId>,
    ) -> bool {
        use rns_transport::messages::InterfaceRole;
        let i2p = entry
            .identity
            .as_ref()
            .is_some_and(|identity| identity.class_name == "I2PInterface");
        let local = [
            InterfaceRole::SharedServer,
            InterfaceRole::LocalClient,
            InterfaceRole::SharedInstancePeer,
        ]
        .iter()
        .any(|role| role.as_str() == entry.role);
        if i2p || local {
            return false;
        }
        self.discovery
            .bootstrap_interfaces
            .lock()
            .await
            .retain(|id| *id != entry.id && !spawned.contains(id));
        self.discovery
            .local_interfaces
            .lock()
            .await
            .retain(|local| local.id != entry.id && !spawned.contains(&local.id));
        for id in spawned {
            teardown_interface(self, id).await;
        }
        teardown_interface(self, entry.id).await;
        true
    }

    async fn attach_configured_interface(&self, name: &str) -> Option<bool> {
        if self.running_interface(name).await.is_some() {
            tracing::warn!("Attempt to attach existing interface \"{name}\"");
            return Some(false);
        }
        let config = match Config::from_file(&self.config_dir.join("config")) {
            Ok(config) => config,
            Err(error) => {
                tracing::error!(
                    %error,
                    "Could not parse the configuration during interface attach"
                );
                return None;
            }
        };
        if config.section("interfaces").is_none() {
            return Some(false);
        }
        let Some(section) = config.subsection("interfaces", name) else {
            tracing::error!("Cannot attach interface \"{name}\", no configuration entry exists");
            return None;
        };
        // Python's `force_attach` ignores the section's own flags; subinterfaces still read `enabled`.
        let mut forced = section.clone();
        forced.set("interface_enabled", "yes");
        match attach_interface_section(self, &config, name, &forced).await {
            Ok(_) => {
                rns_transport::notice!("Interface \"{name}\" was attached");
                Some(true)
            }
            Err(error) => {
                tracing::error!("Error while attaching interface \"{name}\": {error}");
                Some(false)
            }
        }
    }

    /// Python `Reticulum.required_announces_only`: only shared-instance
    /// clients may restrict their own announce ingress (Reticulum.py).
    pub async fn required_announces_only(&self, enabled: bool) -> bool {
        if self.instance_mode != InstanceMode::Client {
            return false;
        }
        self.local_filter_query(TransportQuery::SetRequiredOnly { enabled })
            .await
    }

    /// Python `Reticulum.wants_destination_type` with this process's requester.
    pub async fn wants_destination_type(&self, full_name: &str) -> bool {
        self.wants_destination_type_as(full_name, &application_requester(), None)
            .await
    }

    /// Python `Reticulum.wants_destination_type` with an explicit requester;
    /// the signature is forwarded but, as upstream, never verified.
    pub async fn wants_destination_type_as(
        &self,
        full_name: &str,
        requester: &[u8],
        signature: Option<&[u8]>,
    ) -> bool {
        self.destination_type_request(
            TransportQuery::WantsDestinationType {
                full_name: full_name.to_string(),
                requester: requester.to_vec(),
            },
            crate::rpc::RpcRequest::WantsDestinationType {
                full_name: full_name.to_string(),
                requester: requester.to_vec(),
                signature: signature.map(<[u8]>::to_vec),
            },
        )
        .await
    }

    /// Python `Reticulum.unwants_destination_type` with this process's requester.
    pub async fn unwants_destination_type(&self, full_name: &str) -> bool {
        self.unwants_destination_type_as(full_name, &application_requester(), None)
            .await
    }

    /// Python `Reticulum.unwants_destination_type` with an explicit requester.
    pub async fn unwants_destination_type_as(
        &self,
        full_name: &str,
        requester: &[u8],
        signature: Option<&[u8]>,
    ) -> bool {
        self.destination_type_request(
            TransportQuery::UnwantsDestinationType {
                full_name: full_name.to_string(),
                requester: requester.to_vec(),
            },
            crate::rpc::RpcRequest::UnwantsDestinationType {
                full_name: full_name.to_string(),
                requester: requester.to_vec(),
                signature: signature.map(<[u8]>::to_vec),
            },
        )
        .await
    }

    /// Python `Reticulum.unwants_all_destination_types` with this process's
    /// requester. Runtime shutdown also does this on a shared-instance client.
    pub async fn unwants_all_destination_types(&self) -> bool {
        self.unwants_all_destination_types_as(&application_requester(), None)
            .await
    }

    /// Python `Reticulum.unwants_all_destination_types` with an explicit requester.
    pub async fn unwants_all_destination_types_as(
        &self,
        requester: &[u8],
        signature: Option<&[u8]>,
    ) -> bool {
        self.destination_type_request(
            TransportQuery::UnwantsAllDestinationTypes {
                requester: requester.to_vec(),
            },
            crate::rpc::RpcRequest::UnwantsAllDestinationTypes {
                requester: requester.to_vec(),
                signature: signature.map(<[u8]>::to_vec),
            },
        )
        .await
    }

    /// Query the local actor or shared-owner control plane, converting all errors
    /// to `None`. Client mode supports only queries exposed by the RPC mapping.
    /// Use [`Self::query_control_result`] to distinguish failures and
    /// [`Self::query_transport`] for explicit process-local access.
    pub async fn query_control(&self, query: TransportQuery) -> Option<TransportQueryResponse> {
        self.query_control_result(query).await.ok()
    }

    /// Install a [`DiscoveryStamper`] and start the configured discovery workers.
    /// `discover_interfaces` enables receiving; discoverable local interfaces
    /// can publish independently of that flag. Both need the stamp provider and
    /// an available discovery store. Repeated calls do not duplicate running
    /// workers, but replacing the provider does not replace their captured copy.
    /// This method returns no worker-startup or publication acknowledgment.
    pub async fn enable_on_network_discovery(
        &self,
        stamper: Arc<dyn DiscoveryStamper + Send + Sync>,
    ) {
        *self.discovery.stamper.lock().await = Some(stamper);
        start_on_network_discovery(self.clone()).await;
    }

    /// Return whether a stamp provider is installed. True does not mean a
    /// receiver/publisher started successfully or that any interface was found.
    pub async fn discovery_enabled(&self) -> bool {
        self.discovery.stamper.lock().await.is_some()
    }

    /// List stored discovery records. Listing removes corrupt, expired,
    /// unlisted-type and disallowed-publisher records from disk; merely stale
    /// records remain until the removal threshold. Missing storage or a listing
    /// error returns an empty vector. This is not a live reachability probe.
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
        let blackholed = self.blackholed_identity_set().await;
        store
            .list_filtered(sources, &blackholed)
            .unwrap_or_default()
    }

    /// Blackholed identity hashes, which listing discovered interfaces culls
    /// (Discovery.py); empty when the query fails.
    async fn blackholed_identity_set(&self) -> std::collections::HashSet<[u8; 16]> {
        match self
            .query_control_result(TransportQuery::GetBlackholedIdentities)
            .await
        {
            Ok(TransportQueryResponse::BlackholeList(entries)) => {
                entries.into_iter().map(|e| e.identity_hash).collect()
            }
            _ => std::collections::HashSet::new(),
        }
    }

    /// Configured publisher identity hashes for blackhole-manifest pulls.
    /// This slice does not establish whether a pull succeeded.
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
        stamp_value: None,
        link_cost: None,
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
        // (Reticulum.py).
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
            // Reticulum.py forwards the caller's reason, None when unlabelled.
            reason: reason_label.clone().or_else(|| {
                (*reason != rns_transport::blackhole::BlackholeReason::Manual)
                    .then(|| reason.as_str().to_string())
            }),
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
    use rns_transport::messages::{BlackholeRpcEntry, PathTableRpcEntry, RateTableRpcEntry};

    Some(match response {
        RpcResponse::PathTable(entries) => {
            let entries = entries
                .into_iter()
                .filter_map(|entry| {
                    Some({
                        let mut out = PathTableRpcEntry::default();
                        out.hash = vec_to_16(&entry.hash)?;
                        out.timestamp = entry.timestamp;
                        out.via = entry.via.as_deref().and_then(vec_to_16);
                        out.hops = entry.hops;
                        out.expires = entry.expires;
                        out.value = entry.value;
                        out.used = entry.used;
                        out.lr_cost = entry.lr_cost;
                        // Before 1.6.1 the hash is upstream's, of `str(interface)`.
                        out.interface_hash = entry
                            .interface_hash
                            .as_deref()
                            .and_then(|hash| hash.try_into().ok())
                            .unwrap_or_else(|| rns_crypto::sha::sha256(entry.interface.as_bytes()));
                        out.state = match entry.state {
                            Some(1) => rns_transport::constants::PathState::Unresponsive,
                            Some(2) => rns_transport::constants::PathState::Responsive,
                            _ => rns_transport::constants::PathState::Unknown,
                        };
                        out.interface = entry.interface;
                        out.interface_id = 0;
                        out.interface_mode = rns_transport::constants::InterfaceMode::Full;
                        out.interface_role = rns_transport::messages::InterfaceRole::Normal;
                        out
                    })
                })
                .collect();
            TransportQueryResponse::PathTable(entries)
        }
        RpcResponse::InterfaceStats(entries) => TransportQueryResponse::InterfaceStats(entries),
        RpcResponse::RateTable(entries) => {
            let entries = entries
                .into_iter()
                .filter_map(|entry| {
                    Some({
                        let mut out = RateTableRpcEntry::default();
                        out.hash = vec_to_16(&entry.hash)?;
                        out.rate = entry.rate;
                        out.last = entry.last;
                        out.rate_violations = entry.rate_violations;
                        out.blocked_until = entry.blocked_until;
                        out.timestamps = entry.timestamps;
                        out
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
        RpcResponse::OptBoolResult(v) => TransportQueryResponse::OptBoolResult(v),
        RpcResponse::BlackholeList(entries) => {
            let now = unix_now();
            let entries = entries
                .into_iter()
                .filter_map(|entry| {
                    Some({
                        let mut out = BlackholeRpcEntry::default();
                        out.identity_hash = vec_to_16(&entry.identity_hash)?;
                        out.source = entry.source.as_deref().and_then(vec_to_16);
                        out.created = now;
                        out.ttl = entry.until.map(|until| (until - now).max(0.0));
                        out.reason = entry
                            .reason
                            .as_deref()
                            .map(rns_transport::blackhole::BlackholeReason::parse)
                            .unwrap_or_default();
                        out.reason_label = entry.reason;
                        // Verification is computed against the *local* actor's
                        // recent_announces, which a remote-RPC bridge cannot
                        // see. Default to false; the local-actor path sets it
                        // correctly.
                        out.verified = false;
                        out
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

/// Shared-instance transport. As in Python, it is AF_UNIX on Linux/Android
/// unless TCP is requested, and TCP loopback everywhere else, where a Unix
/// request is served over TCP.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SharedInstanceType {
    /// TCP loopback on [`ReticulumConfig::shared_instance_port`].
    Tcp,
    /// AF_UNIX socket with Python-compatible abstract names.
    Unix,
}

impl SharedInstanceType {
    fn platform_default() -> Self {
        Self::Unix.on_this_platform()
    }

    /// Python forces TCP wherever `platformutils.use_af_unix()` is false
    /// (Reticulum.py): only Linux and Android have abstract sockets.
    fn on_this_platform(self) -> Self {
        if cfg!(target_os = "linux") || rns_interface::local::is_android() {
            self
        } else {
            Self::Tcp
        }
    }
}

/// Per-construction overrides for [`init_with_options`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct InitOptions {
    /// Python `require_shared_instance`: fail startup rather than become the shared instance.
    pub require_shared_instance: bool,
    /// Override the configured shared-instance transport for this process.
    /// A Unix request still becomes TCP off Linux/Android.
    pub shared_instance_type: Option<SharedInstanceType>,
    /// Python `Reticulum(enable_stamping=True)`: stamp emitted announces, path
    /// requests and link requests. `false` never clears a configured switch.
    pub enable_stamping: bool,
    /// Python `Reticulum(enforce_stamps=True)`: enforce announce, path request
    /// and link request stamps. `false` never clears a configured switch.
    pub enforce_stamps: bool,
    /// Embedder choice: an interface that fails to build or start is recorded
    /// in [`ReticulumHandle::startup_interface_failures`] and the rest start.
    /// Off, startup stops as upstream does (Reticulum.py).
    pub keep_starting_after_interface_failure: bool,
    /// Embedder choice: configured interfaces start at the same time, so a
    /// slow one (an unreachable TCP server) does not hold up the rest. Ids,
    /// listing order, and failure handling are those of the one-at-a-time
    /// start upstream does (Reticulum.py), which stays the default.
    pub start_interfaces_concurrently: bool,
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

/// Build the RPC Unix-socket name. Linux/Android names begin with a NUL
/// byte for the abstract namespace; other hosts use a path under `socket_base`.
/// This function neither creates nor validates a socket.
pub fn shared_instance_rpc_socket_path(instance_name: &str, socket_base: &Path) -> String {
    shared_unix_rpc_socket_path(instance_name, socket_base)
}

fn shared_tcp_client_config(
    port: u16,
    force_bitrate: Option<u64>,
) -> rns_interface::local::LocalClientConfig {
    rns_interface::local::LocalClientConfig {
        socket_path: rns_interface::local::tcp_socket_path(port),
        name: "SharedInstanceClient".to_string(),
        force_bitrate,
    }
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

/// Binds without listening; upstream learns the same by binding its server (Reticulum.py).
fn shared_tcp_port_is_free(port: u16) -> bool {
    let Ok(socket) = tokio::net::TcpSocket::new_v4() else {
        return false;
    };
    // The listener binds with SO_REUSEADDR off Windows.
    #[cfg(not(windows))]
    let _ = socket.set_reuseaddr(true);
    socket
        .bind(std::net::SocketAddr::from(([127, 0, 0, 1], port)))
        .is_ok()
}

/// Reticulum.py: an unreachable shared instance leaves this process standalone.
/// Starts the transport's storage once this process knows whether it owns its
/// directory or is the client of a shared instance. Reticulum.py binds or
/// connects the local interface before `Identity.load_known_destinations` and
/// `Transport.start`; the first call here does the same, before the local
/// interface is registered with the transport.
struct TransportStorageStart<'a> {
    transport_tx: &'a mpsc::Sender<TransportMessage>,
    storage_dir: &'a Path,
    started: bool,
}

impl TransportStorageStart<'_> {
    async fn start(&mut self, role: StorageRole) {
        if std::mem::replace(&mut self.started, true) {
            return;
        }
        let (done, loaded) = tokio::sync::oneshot::channel();
        let message = TransportMessage::SetStoragePaths {
            storage_dir: self.storage_dir.to_path_buf(),
            role,
            done: Some(done),
        };
        if self.transport_tx.send(message).await.is_ok() {
            let _ = loaded.await;
        }
    }
}

fn shared_instance_unreachable(error: &dyn std::fmt::Display) -> InstanceMode {
    tracing::error!("Local shared instance appears to be running, but it could not be connected");
    tracing::error!("The contained exception was: {error}");
    InstanceMode::Standalone
}

fn socket_path_display(path: &str) -> String {
    if path.as_bytes().first() == Some(&0) {
        format!("\\0{}", &path[1..])
    } else {
        path.to_string()
    }
}

pub use rns_transport::inbound_queues::InboundQueueLengths;

#[derive(Debug, Clone)]
#[non_exhaustive]
/// Parsed runtime settings. `Default` supplies values; `try_from_config`
/// overlays supported keys. Editing this struct after initialization does
/// not reconfigure already-running actors or interface tasks.
pub struct ReticulumConfig {
    pub share_instance: bool,
    pub instance_name: String,
    pub shared_instance_type: SharedInstanceType,
    pub shared_instance_port: u16,
    pub control_port: u16,
    pub enable_transport: bool,
    /// Keep the persisted wire-facing transport identity on a non-transport
    /// node instead of creating a fresh one at startup. Default false.
    pub static_transport_identity: bool,
    /// Use a per-startup random hop offset of 2..=7 for eligible locally
    /// originated packets. PLAIN/GROUP and shared-instance edges are excluded;
    /// this is not a general anonymity guarantee. Default false.
    pub local_hops_delta: bool,
    pub respond_to_probes: bool,
    pub use_implicit_proof: bool,
    pub panic_on_interface_error: bool,
    pub link_mtu_discovery: bool,
    pub enable_remote_management: bool,
    /// Whether the `manage` RPC may attach, detach or reload interfaces.
    pub enable_interface_management: bool,
    pub remote_management_allowed: Vec<Vec<u8>>,
    pub rpc_key: Option<Vec<u8>>,
    /// Simulated shared-link bitrate in bits per second. A positive value
    /// replaces the reported bitrate/derived MTU and affects announce pacing
    /// and first-hop timeout estimates; it does not throttle all socket traffic.
    pub force_shared_instance_bitrate: Option<u64>,
    pub default_ar_target: Option<u64>,
    pub default_ar_penalty: Option<u64>,
    pub default_ar_grace: Option<u32>,
    /// `[reticulum] default_gravity`, for interfaces without a `gravity` key.
    pub default_gravity: Option<i64>,
    /// Global Reticulum defaults for per-interface ingress/egress control.
    pub ingress_overrides: rns_transport::ingress::IngressOverrides,
    /// `[logging] loglevel`, 0 (critical) to 8 (extreme). Python's module
    /// default is 3 (notice) when the key is absent.
    pub loglevel: i32,
    /// `qlen_in_*` inbound queue lengths per traffic class.
    pub inbound_queue_lengths: InboundQueueLengths,

    /// Optional identity file, loaded or created at startup. It signs discovery
    /// announces and supplies the key for per-interface `discovery_encrypt`.
    /// Providing this path alone does not encrypt every discovery announce.
    pub network_identity_path: Option<PathBuf>,
    /// Receive on-network interface discovery when a stamper is installed.
    /// Publication is controlled separately by each interface's `discoverable`.
    pub discover_interfaces: bool,
    /// Maximum discovered Backbone connections to retain; zero disables
    /// auto-connect. Receiving discovery and installing a stamper are also
    /// required. Other discovered interface types are not auto-connected.
    pub autoconnect_discovered_interfaces: usize,
    /// Permit Backbone auto-connect for any advertised implementation/version.
    /// Without it only `RNS` 1.5.7 and `rsRNS` 1.5.0 or later qualify. The
    /// default check is metadata matching, not software attestation.
    pub autoconnect_unverified_implementations: bool,
    /// Python `autoconnect_interface_mode`. Unset gives auto-connected
    /// interfaces Gateway mode on transport nodes and Full mode otherwise.
    pub autoconnect_interface_mode: Option<rns_interface::traits::InterfaceMode>,
    /// Python `autoconnect_interface_gravity`; unset gives auto-connected interfaces gravity 0.
    pub autoconnect_interface_gravity: Option<i64>,
    /// Python `autoconnect_announces_to_internal`; only `Some(true)` is ever stored.
    pub autoconnect_announces_to_internal: Option<bool>,
    /// Minimum fractional stamp value for received discovery announces
    /// (`required_discovery_value`); unset or not positive means 16. This does
    /// not set generation cost, which comes from each interface's
    /// `discovery_stamp_value`.
    pub discover_interfaces_required_value: f64,
    /// Accepted discovery publisher identity hashes. An empty list permits
    /// any publisher that otherwise passes receiver checks.
    pub interface_discovery_sources: Vec<[u8; 16]>,

    /// Identity hashes whose `rnstransport.info.blackhole` manifests this
    /// node subscribes to. Python `blackhole_sources`.
    pub blackhole_sources: Vec<[u8; 16]>,
    /// Publish this node's local blackhole table on
    /// `rnstransport.info.blackhole`. Python `publish_blackhole`.
    pub publish_blackhole: bool,
    /// Seconds between blackhole-source pulls. The configuration-file value
    /// `blackhole_update_interval` is in minutes, clamped to at least two and
    /// converted to seconds. The default is 3600 seconds.
    pub blackhole_update_interval: f64,
    /// Parsed `[logging] logtimestamps` preference, default true. The
    /// application or CLI must apply it when configuring its logging subscriber.
    pub log_timestamps: bool,

    /// Parsed `bootstrap_configs` paths, retained in configuration. The current
    /// runtime does not load or merge these files; declare active interfaces
    /// in the primary configuration.
    pub bootstrap_configs: Vec<PathBuf>,

    /// Network stamp policy from the `[stamps]` section.
    pub stamps: rns_transport::stamps::StampPolicy,
    /// `[stamps] max_workers` and `worker_niceness`, installed process-wide at init.
    pub stamp_workers: rns_identity::stamps::StampWorkers,
    /// Destination-type filter and hop limiter from the `[filter]` section.
    pub filter: rns_transport::destination_filter::FilterPolicy,
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
            enable_interface_management: true,
            remote_management_allowed: Vec::new(),
            rpc_key: None,
            force_shared_instance_bitrate: None,
            default_ar_target: None,
            default_ar_penalty: None,
            default_ar_grace: None,
            default_gravity: None,
            ingress_overrides: rns_transport::ingress::IngressOverrides::default(),
            loglevel: 3,
            inbound_queue_lengths: InboundQueueLengths::default(),
            network_identity_path: None,
            discover_interfaces: false,
            autoconnect_discovered_interfaces: 0,
            autoconnect_unverified_implementations: false,
            autoconnect_interface_mode: None,
            autoconnect_interface_gravity: None,
            autoconnect_announces_to_internal: None,
            discover_interfaces_required_value:
                rns_transport::discovery::constants::DEFAULT_STAMP_VALUE,
            interface_discovery_sources: Vec::new(),
            blackhole_sources: Vec::new(),
            publish_blackhole: false,
            blackhole_update_interval:
                rns_transport::discovery::constants::BLACKHOLE_UPDATE_INTERVAL.as_secs_f64(),
            log_timestamps: true,
            bootstrap_configs: Vec::new(),
            stamps: rns_transport::stamps::StampPolicy::default(),
            stamp_workers: rns_identity::stamps::StampWorkers::default(),
            filter: rns_transport::destination_filter::FilterPolicy::default(),
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

/// Python `Reticulum.__apply_config` `[stamps]` keys. Booleans only switch
/// features on; unknown keys are ignored.
fn apply_stamps_section(
    policy: &mut rns_transport::stamps::StampPolicy,
    sec: &ConfigSection,
) -> Result<(), ConfigError> {
    use rns_transport::stamps::StampPolicy;
    const S: &str = "stamps";
    if config_bool(S, sec, "enforce_stamps")? == Some(true) {
        policy.enforce();
    }
    if config_bool(S, sec, "stamp_destinations")? == Some(true) {
        policy.stamp_destinations = true;
    }
    if config_bool(S, sec, "stamp_prs")? == Some(true) {
        policy.stamp_prs = true;
    }
    if config_bool(S, sec, "always_stamp_lrs")? == Some(true) {
        policy.always_stamp_lrs = true;
    }
    if let Some(v) = config_float(S, sec, "destination_cost")? {
        policy.destination_cost = StampPolicy::clamp_cost(v);
    }
    if let Some(v) = config_float(S, sec, "destination_value")? {
        policy.destination_value = StampPolicy::clamp_cost(v);
    }
    if let Some(v) = config_float(S, sec, "pr_cost")? {
        policy.pr_cost = StampPolicy::clamp_cost(v);
    }
    if let Some(v) = config_float(S, sec, "pr_value")? {
        policy.pr_value = StampPolicy::clamp_cost(v);
    }
    if let Some(v) = config_float(S, sec, "lr_cost")? {
        policy.lr_cost = StampPolicy::clamp_link_cost(v);
    }
    if let Some(v) = config_float(S, sec, "lr_stamp_timeout")? {
        policy.lr_stamp_timeout = StampPolicy::clamp_timeout(v);
    }
    if let Some(v) = config_float(S, sec, "pr_stamp_timeout")? {
        policy.pr_stamp_timeout = StampPolicy::clamp_timeout(v);
    }
    Ok(())
}

/// Python `[stamps] max_workers` and `worker_niceness`: `as_int`, then clamped.
fn apply_stamp_workers(
    workers: &mut rns_identity::stamps::StampWorkers,
    sec: &ConfigSection,
) -> Result<(), ConfigError> {
    use rns_identity::stamps::StampWorkers;
    if let Some(v) = config_int("stamps", sec, "max_workers")? {
        workers.max_workers = Some(StampWorkers::clamp_max_workers(v));
    }
    if let Some(v) = config_int("stamps", sec, "worker_niceness")? {
        workers.niceness = StampWorkers::clamp_niceness(v);
    }
    Ok(())
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

/// `[reticulum]` ingress defaults: zero or negative values leave the class default.
fn parse_global_ingress_overrides(
    section: &ConfigSection,
) -> Result<rns_transport::ingress::IngressOverrides, ConfigError> {
    let positive = |key| -> Result<Option<f64>, ConfigError> {
        Ok(config_float("reticulum", section, key)?.filter(|v| *v > 0.0))
    };
    Ok(rns_transport::ingress::IngressOverrides {
        burst_freq_new: positive("ic_burst_freq_new")?,
        burst_freq: positive("ic_burst_freq")?,
        pr_burst_freq_new: positive("ic_pr_burst_freq_new")?,
        pr_burst_freq: positive("ic_pr_burst_freq")?,
        new_time: positive("ic_new_time")?,
        burst_hold: positive("ic_burst_hold")?,
        burst_penalty: positive("ic_burst_penalty")?,
        max_held: config_int("reticulum", section, "ic_max_held_announces")?
            .filter(|v| *v > 0)
            .map(|v| usize::try_from(v).unwrap_or(usize::MAX)),
        held_release_interval: positive("ic_held_release_interval")?,
        ec_pr_freq: positive("ec_pr_freq")?,
        egress_control: config_bool("reticulum", section, "egress_control")?.filter(|v| *v),
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

fn warn_deprecated_alias(alias: &str, key: &str) {
    tracing::warn!("The configuration option {alias} is deprecated, use {key} instead");
}

/// The aliases Python accepts for `autoconnect_interface_mode`; any other
/// value is ignored (Reticulum.py).
fn parse_autoconnect_interface_mode(value: &str) -> Option<rns_interface::traits::InterfaceMode> {
    use rns_interface::traits::InterfaceMode;
    match value.to_lowercase().as_str() {
        "full" => Some(InterfaceMode::Full),
        "access_point" | "accesspoint" | "ap" => Some(InterfaceMode::AccessPoint),
        "pointtopoint" | "ptp" => Some(InterfaceMode::PointToPoint),
        "roaming" => Some(InterfaceMode::Roaming),
        "boundary" => Some(InterfaceMode::Boundary),
        "gateway" | "gw" => Some(InterfaceMode::Gateway),
        "internal" => Some(InterfaceMode::Internal),
        _ => None,
    }
}

/// Python 1.6.1 `__autoconnect_cap` and `__autoconnect_warn` (Reticulum.py).
const AUTOCONNECT_CAP: usize = 12;
const AUTOCONNECT_WARN: usize = 6;

/// Python caps the auto-connect target at 12 and warns above 6, unless
/// `autoconnect_discovered_interfaces_disable_caps` is set (Reticulum.py:743-768).
fn cap_autoconnect_limit(limit: usize, caps_disabled: bool) -> usize {
    let mut limit = limit;
    if !caps_disabled && limit > AUTOCONNECT_CAP {
        limit = AUTOCONNECT_CAP;
        tracing::warn!("Auto-connect interface target was capped to {limit}");
        tracing::warn!(
            "Using large numbers of auto-connected interfaces will not lead to better \
             connectivity or redundancy. If you really know what you're doing, and are \
             certain that you need this, you will also know how to get around this check."
        );
    }
    if limit > AUTOCONNECT_WARN {
        tracing::warn!(
            "You have configured more than {AUTOCONNECT_WARN} auto-connect interfaces. In almost \
             all situations, this is excessive, and should be avoided. For a normal home or \
             office node, 2-3 autoconnects will be sufficient."
        );
        tracing::warn!(
            "If you're running a fast, well-connected transport node that can actually provide \
             additional capacity and transport to the network, you can consider raising this \
             number to {AUTOCONNECT_WARN}-{}. Only in the rarest of cases will going beyond this \
             actually provide any benefit.",
            AUTOCONNECT_WARN + 3
        );
    }
    limit
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
        warn_deprecated_alias(key, "autoconnect_discovered_interfaces");
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
    if let Some(rest) = path.strip_prefix('~')
        && (rest.is_empty() || rest.starts_with(std::path::is_separator))
        && let Some(home) = crate::platform::home_dir()
        && let Ok(home) = home.into_os_string().into_string()
    {
        return PathBuf::from(format!("{home}{rest}"));
    }
    PathBuf::from(path)
}

impl ReticulumConfig {
    /// Overlay supported configuration keys onto defaults. Typed value errors
    /// can fail parsing; unknown keys and unrecognized shared-instance transport
    /// names are not rejected universally. No interfaces or services are started.
    pub fn try_from_config(config: &Config) -> Result<Self, ConfigError> {
        let mut rc = ReticulumConfig::default();

        if let Some(sec) = config.section("stamps") {
            apply_stamps_section(&mut rc.stamps, sec)?;
            apply_stamp_workers(&mut rc.stamp_workers, sec)?;
        }
        rc.filter = config.filter_policy()?;

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
                    "unix" => {
                        rc.shared_instance_type = SharedInstanceType::Unix.on_this_platform();
                    }
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
            if let Some(value) = config_bool("reticulum", sec, "enable_interface_management")? {
                rc.enable_interface_management = value;
            }
            rc.force_shared_instance_bitrate =
                config_uint("reticulum", sec, "force_shared_instance_bitrate")?;
            // Zero or negative falls back to the interface class default, as upstream's getters do.
            let positive = |key| -> Result<Option<u64>, ConfigError> {
                Ok(config_int("reticulum", sec, key)?
                    .filter(|v| *v > 0)
                    .map(|v| v as u64))
            };
            rc.default_ar_target = positive("default_ar_target")?;
            rc.default_ar_penalty = positive("default_ar_penalty")?;
            rc.default_ar_grace =
                positive("default_ar_grace")?.map(|v| u32::try_from(v).unwrap_or(u32::MAX));
            rc.default_gravity = config_int("reticulum", sec, "default_gravity")?;
            rc.ingress_overrides = parse_global_ingress_overrides(sec)?;
            let queues = &mut rc.inbound_queue_lengths;
            for (key, length) in [
                ("qlen_in_data", &mut queues.data),
                ("qlen_in_announce", &mut queues.announce),
                ("qlen_in_pr", &mut queues.pr),
                ("qlen_in_il", &mut queues.il),
            ] {
                if let Some(v) = config_int("reticulum", sec, key)?.filter(|v| *v > 0) {
                    *length = usize::try_from(v).unwrap_or(usize::MAX);
                }
            }

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
            // Python honours the switch only above the count in the file; it
            // applies here wherever it appears.
            let caps_disabled = config_bool(
                "reticulum",
                sec,
                "autoconnect_discovered_interfaces_disable_caps",
            )?
            .unwrap_or(false);
            if let Some(limit) = parse_autoconnect_limit(sec)? {
                rc.autoconnect_discovered_interfaces = cap_autoconnect_limit(limit, caps_disabled);
            }
            if let Some(value) =
                config_bool("reticulum", sec, "autoconnect_unverified_implementations")?
            {
                rc.autoconnect_unverified_implementations = value;
            }
            if let Some(mode) = sec.get("autoconnect_interface_mode") {
                rc.autoconnect_interface_mode = parse_autoconnect_interface_mode(mode);
            }
            if let Some(gravity) = config_int("reticulum", sec, "autoconnect_interface_gravity")? {
                rc.autoconnect_interface_gravity = Some(gravity);
            }
            if config_bool("reticulum", sec, "autoconnect_announces_to_internal")? == Some(true) {
                rc.autoconnect_announces_to_internal = Some(true);
            }
            if sec.has("discover_interfaces_required_value") {
                warn_deprecated_alias(
                    "discover_interfaces_required_value",
                    "required_discovery_value",
                );
            }
            // Reticulum.py keeps only a positive value; Discovery.py defaults the rest.
            if let Some(v) = config_float("reticulum", sec, "required_discovery_value")?.or(
                config_float("reticulum", sec, "discover_interfaces_required_value")?,
            ) {
                rc.discover_interfaces_required_value = if v > 0.0 {
                    v
                } else {
                    rns_transport::discovery::constants::DEFAULT_STAMP_VALUE
                };
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
            // Reticulum.py: float minutes, clamped to min 2, stored ×60.
            if let Some(v) = config_float("reticulum", sec, "blackhole_update_interval")? {
                rc.blackhole_update_interval = v.max(2.0) * 60.0;
            }
            if let Some(list) = sec.get_list("bootstrap_configs") {
                rc.bootstrap_configs = list.iter().map(|s| PathBuf::from(s.trim())).collect();
            }
        }

        // Python promotes the identity while synthesizing a discoverable
        // interface (Reticulum.py).
        if !rc.enable_transport
            && !rc.static_transport_identity
            && config
                .subsections("interfaces")
                .iter()
                .any(|(_, section)| section.get_bool("discoverable") == Some(true))
        {
            tracing::warn!(
                "Discoverable interface was configured, enabling static transport identity on non-transport instance"
            );
            rc.static_transport_identity = true;
        }

        if let Some(sec) = config.section("logging") {
            if let Some(level) = config_int("logging", sec, "loglevel")? {
                rc.loglevel = level.clamp(0, 8) as i32;
            }
            if let Some(value) = config_bool("logging", sec, "logtimestamps")? {
                rc.log_timestamps = value;
            }
        }

        Ok(rc)
    }

    /// Apply constructor overrides after the configuration file, in Python's
    /// order (Reticulum.py).
    pub fn apply_init_options(&mut self, options: &InitOptions) {
        if options.enable_stamping {
            tracing::debug!("Network stamp generation activated");
            self.stamps.enable_stamping();
        }
        if options.enforce_stamps {
            tracing::debug!("Network stamp enforcement activated");
            self.stamps.enforce();
        }
        if let Some(shared_instance_type) = options.shared_instance_type {
            self.shared_instance_type = shared_instance_type.on_this_platform();
        }
    }

    /// Parse configuration, panicking on a value error. Use `try_from_config`
    /// when configuration comes from users or requires recoverable validation.
    pub fn from_config(config: &Config) -> Self {
        Self::try_from_config(config).expect("valid Reticulum configuration")
    }
}

/// Python 1.3.8 Transport.py: the wire-facing transport identity is
/// ephemeral per boot exactly when transport is disabled and
/// `static_transport_identity` is unset.
fn uses_ephemeral_transport_identity(rc: &ReticulumConfig) -> bool {
    !rc.enable_transport && !rc.static_transport_identity
}

/// Python 1.3.8 Transport.py: per-boot random hop delta,
/// `(ord(os.urandom(1)) % 6) + 2` = 2..=7.
fn generate_local_hops_delta() -> u8 {
    (rns_crypto::random::random_bytes(1)[0] % 6) + 2
}

/// Create a runtime from the selected configuration directory, creating
/// default configuration, storage and identities as needed. Startup chooses
/// shared-owner, client or standalone mode and starts configured services.
/// A successful return does not mean every configured interface is online;
/// inspect startup failures and use RNode observers when readiness matters.
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
    init_with_policy(
        configdir,
        socket_dir,
        shutdown,
        is_foreground,
        options,
        rnode_startup_options,
        InstancePolicy::Configured,
    )
    .await
    .map_err(|error| match error {
        InstanceStartupError::Runtime(error) => error,
        InstanceStartupError::Shared(error) => ReticulumError::Interface(error.to_string()),
    })
}

/// Bring up Reticulum with an explicit ownership policy. Existing init entry
/// points retain config-driven automatic sharing. Strict clients authenticate
/// before admission and every reconnect; strict owners never adopt a listener
/// that they failed to bind. This does not authenticate the packet IPC protocol.
pub async fn init_with_policy(
    configdir: Option<&str>,
    socket_dir: Option<PathBuf>,
    shutdown: ShutdownSignal,
    is_foreground: Arc<AtomicBool>,
    options: InitOptions,
    rnode_startup_options: rns_interface::rnode::RNodeStartupOptions,
    policy: InstancePolicy,
) -> Result<ReticulumHandle, InstanceStartupError> {
    let started_at = std::time::Instant::now();
    let config_dir = resolve_config_dir(configdir);
    let paths = StoragePaths::from_config_dir(&config_dir);
    paths.ensure_dirs().map_err(ReticulumError::Io)?;

    let config_path = config_dir.join("config");
    let (config, config_created) = load_or_create_config(&config_path)?;
    if config_created {
        rns_transport::notice!(
            path = %config_path.display(),
            "created default Reticulum config; continuing after first-run grace period"
        );
        tokio::time::sleep(Duration::from_millis(1500)).await;
    }
    let mut rc = ReticulumConfig::try_from_config(&config).map_err(ReticulumError::Config)?;
    rc.apply_init_options(&options);
    load_config_dir_lists(&config_dir, &mut rc);
    match &policy {
        InstancePolicy::Configured => {}
        InstancePolicy::Standalone => rc.share_instance = false,
        InstancePolicy::SharedOwner => rc.share_instance = true,
        InstancePolicy::SharedOwnerAt(endpoint) => {
            endpoint.validate()?;
            endpoint.apply(&mut rc);
        }
        InstancePolicy::SharedClient(credentials) => credentials.apply(&mut rc),
    }

    let ephemeral_transport_identity =
        uses_ephemeral_transport_identity(&rc).then(rns_identity::identity::Identity::new);
    let mut actor_options = rns_transport::actor::TransportActorOptions::default();
    actor_options.is_foreground = Some(is_foreground.clone());
    // Python 1.3.8 Transport.py: non-transport nodes get a fresh
    // per-boot wire-facing transport identity unless static_transport_identity
    // is set. Pre-seed the actor's hash so runtime-side wire consumers
    // (discovery announcer, blackhole publisher/subscriber) share the value.
    actor_options.static_transport_identity = rc.static_transport_identity;
    actor_options.ephemeral_identity_hash = ephemeral_transport_identity
        .as_ref()
        .map(|identity| identity.hash);
    // Python 1.3.8 Transport.py: one random 2..=7 delta per boot;
    // should_apply_delta gates actual application.
    if rc.local_hops_delta {
        actor_options.local_hops_delta = generate_local_hops_delta();
    }
    let (mut actor, transport_tx) = rns_transport::actor::TransportActor::new_with_options(
        4096,
        rns_transport::constants::HASHLIST_MAXSIZE,
        rc.inbound_queue_lengths,
        actor_options,
    );
    let inbound_queues = actor.inbound_queues();
    let persistence_trigger = actor.persistence_trigger();
    let path_recovery = actor.path_recovery_handle();
    let link_endpoint_dispatch = actor.link_endpoint_dispatch_handle();
    let announce_dispatch = actor.announce_dispatch_handle();

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
    let transport_identity =
        load_or_create_transport_identity(&paths.storage_dir.join("transport_identity"));
    let _ = transport_tx.try_send(TransportMessage::SetTransportIdentity {
        identity_hash: transport_identity.hash,
    });
    let _ = transport_tx.try_send(TransportMessage::SetBlackholeSources {
        sources: rc.blackhole_sources.clone(),
    });
    rc.stamp_workers.install();
    let _ = transport_tx.try_send(TransportMessage::SetStampPolicy {
        policy: rc.stamps.clone(),
    });
    crate::destination_stamper::configure(rc.stamps.clone(), Some(paths.storage_dir.clone()));
    let _ = transport_tx.try_send(TransportMessage::SetFilterPolicy {
        policy: rc.filter.clone(),
    });

    // Python defaults the local shared-instance RPC key to a hash of the
    // PERSISTENT transport identity (internal_identity(), Reticulum.py),
    // so RPC auth stays stable across the per-boot ephemeral rotation.
    if rc.rpc_key.is_none()
        && let Some(private_key) = transport_identity.get_private_key()
    {
        rc.rpc_key = Some(crate::rpc::derive_rpc_key(&*private_key).to_vec());
    }
    let transport_identity = Arc::new(transport_identity);
    // Wire-facing identity for runtime consumers (Python Transport.identity):
    // ephemeral when the non-transport default policy is active.
    let wire_transport_identity = match ephemeral_transport_identity {
        Some(ephemeral) => Arc::new(ephemeral),
        None => transport_identity.clone(),
    };
    let _ = transport_tx.try_send(TransportMessage::SetTunnelIdentity {
        identity: wire_transport_identity.clone(),
    });
    let (interface_control_tx, interface_control_rx) = mpsc::unbounded_channel();
    let _ = transport_tx.try_send(TransportMessage::SetInterfaceControl {
        tx: interface_control_tx,
    });

    let network_identity = rc
        .network_identity_path
        .as_ref()
        .map(|path| load_or_create_network_identity(path))
        .transpose()?;
    let transport_stats = rc.enable_transport.then(|| {
        crate::rpc_server::TransportStatsSource::new(
            wire_transport_identity.hash,
            network_identity.as_ref().map(|identity| identity.hash),
            started_at,
        )
    });

    let socket_base = socket_dir.clone().unwrap_or_else(std::env::temp_dir);
    let mut shared_spawn_permit = Some(match interface_registry.acquire_spawn_permit() {
        Ok(permit) => permit,
        Err(_) => {
            shutdown_coordinator.wait().await;
            return Err(ReticulumError::Interface(
                "runtime shutdown during interface initialization".to_string(),
            )
            .into());
        }
    });
    let mut shared_instance_status = None;
    let interface_manager = Arc::new(OnceLock::new());
    let mut storage = TransportStorageStart {
        transport_tx: &transport_tx,
        storage_dir: &paths.storage_dir,
        started: false,
    };
    let configured_policy = matches!(policy, InstancePolicy::Configured);
    let mut would_own_shared_instance = false;
    let instance_mode = if matches!(
        policy,
        InstancePolicy::SharedOwner
            | InstancePolicy::SharedOwnerAt(_)
            | InstancePolicy::SharedClient(_)
    ) {
        // This extra permit covers control-listener installation after packet
        // registration consumes its own permit.
        let control_permit = interface_registry.acquire_spawn_permit();
        let result: Result<InstanceMode, InstanceStartupError> = async {
            if control_permit.is_err() {
                return Err(SharedInstanceError::Cancelled.into());
            }
            if let InstancePolicy::SharedClient(credentials) = policy {
                let (client, status) = spawn_authenticated_client(
                    credentials,
                    next_id(&id_gen),
                    transport_tx.clone(),
                    shutdown.clone(),
                )
                .await?;
                storage.start(StorageRole::SharedInstanceClient).await;
                let mode = adopt_shared_instance_client(
                    client,
                    &transport_tx,
                    &interface_controls,
                    &interface_registry,
                    &shutdown,
                    rc.force_shared_instance_bitrate,
                    shared_spawn_permit.take(),
                )
                .await?;
                if mode != InstanceMode::Client {
                    return Err(SharedInstanceError::Cancelled.into());
                }
                shared_instance_status = Some(status);
                return Ok(mode);
            }
            let control = BoundControlListener::bind(&rc, &socket_base).await?;
            let socket_path = if rc.shared_instance_type == SharedInstanceType::Tcp {
                rns_interface::local::tcp_socket_path(rc.shared_instance_port)
            } else {
                shared_unix_socket_path(&rc.instance_name, &socket_base)
            };
            let mut server = rns_interface::local::spawn_local_server(
                rns_interface::local::LocalServerConfig {
                    socket_path,
                    name: "SharedInstanceServer".to_string(),
                    force_bitrate: rc.force_shared_instance_bitrate,
                },
                next_id(&id_gen),
                id_gen.clone(),
                transport_tx.clone(),
                handle_tx.clone(),
            )
            .await
            .map_err(|_| SharedInstanceError::PacketBindFailed)?;
            storage.start(StorageRole::Owner).await;
            apply_forced_shared_instance_bitrate(&mut server, rc.force_shared_instance_bitrate);
            register_interface_handle_with_role_and_spawn_permit(
                &transport_tx,
                server,
                rns_transport::messages::InterfaceRole::SharedServer,
                &interface_controls,
                &interface_registry,
                shared_spawn_permit.take(),
            )
            .await
            .map_err(|_| SharedInstanceError::Cancelled)?;
            let rpc_key = rc.rpc_key.clone().ok_or(SharedInstanceError::InvalidKey)?;
            shutdown_coordinator.install_owned_control_task(tokio::spawn(
                control.run(
                    rpc_key,
                    crate::rpc_server::RpcBackend::new(transport_tx.clone())
                        .with_transport(transport_stats.clone())
                        .with_inbound_queues(inbound_queues.clone())
                        .with_interface_manager(interface_manager.clone()),
                    shutdown.clone(),
                ),
            ));
            Ok(InstanceMode::Shared)
        }
        .await;
        drop(control_permit);
        match result {
            Ok(mode) => mode,
            Err(error) => {
                drop(shared_spawn_permit);
                shutdown_coordinator.start_and_wait().await;
                return Err(error);
            }
        }
    } else if rc.share_instance {
        if rc.shared_instance_type == SharedInstanceType::Tcp {
            let live_server_detected = detect_shared_tcp_server(rc.shared_instance_port).await;

            if live_server_detected {
                let client_config = shared_tcp_client_config(
                    rc.shared_instance_port,
                    rc.force_shared_instance_bitrate,
                );
                let client_id = next_id(&id_gen);
                match rns_interface::local::spawn_local_client(
                    client_config,
                    client_id,
                    transport_tx.clone(),
                )
                .await
                {
                    Ok(client_handle) => {
                        storage.start(StorageRole::SharedInstanceClient).await;
                        adopt_shared_instance_client(
                            client_handle,
                            &transport_tx,
                            &interface_controls,
                            &interface_registry,
                            &shutdown,
                            rc.force_shared_instance_bitrate,
                            shared_spawn_permit.take(),
                        )
                        .await?
                    }
                    Err(error) => shared_instance_unreachable(&error),
                }
            } else if options.require_shared_instance
                && shared_tcp_port_is_free(rc.shared_instance_port)
            {
                would_own_shared_instance = true;
                InstanceMode::Standalone
            } else {
                let server_config = rns_interface::local::LocalServerConfig {
                    socket_path: rns_interface::local::tcp_socket_path(rc.shared_instance_port),
                    name: "SharedInstanceServer".to_string(),
                    force_bitrate: rc.force_shared_instance_bitrate,
                };
                let server_id = next_id(&id_gen);
                match rns_interface::local::spawn_local_server(
                    server_config,
                    server_id,
                    id_gen.clone(),
                    transport_tx.clone(),
                    handle_tx.clone(),
                )
                .await
                {
                    Ok(server_handle) => {
                        if !options.require_shared_instance {
                            storage.start(StorageRole::Owner).await;
                        }
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
                    Err(bind_error) => {
                        if detect_shared_tcp_server(rc.shared_instance_port).await {
                            let client_config = shared_tcp_client_config(
                                rc.shared_instance_port,
                                rc.force_shared_instance_bitrate,
                            );
                            let client_id = next_id(&id_gen);
                            match rns_interface::local::spawn_local_client(
                                client_config,
                                client_id,
                                transport_tx.clone(),
                            )
                            .await
                            {
                                Ok(client_handle) => {
                                    storage.start(StorageRole::SharedInstanceClient).await;
                                    adopt_shared_instance_client(
                                        client_handle,
                                        &transport_tx,
                                        &interface_controls,
                                        &interface_registry,
                                        &shutdown,
                                        rc.force_shared_instance_bitrate,
                                        shared_spawn_permit.take(),
                                    )
                                    .await?
                                }
                                Err(error) => shared_instance_unreachable(&error),
                            }
                        } else {
                            shared_instance_unreachable(&bind_error)
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
                            tracing::debug!(
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
                    force_bitrate: rc.force_shared_instance_bitrate,
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
                        storage.start(StorageRole::SharedInstanceClient).await;
                        adopt_shared_instance_client(
                            client_handle,
                            &transport_tx,
                            &interface_controls,
                            &interface_registry,
                            &shutdown,
                            rc.force_shared_instance_bitrate,
                            shared_spawn_permit.take(),
                        )
                        .await?
                    }
                    Err(error) => shared_instance_unreachable(&error),
                }
            } else if options.require_shared_instance {
                // No bind probe: a Unix socket nobody answers on can be claimed.
                would_own_shared_instance = true;
                InstanceMode::Standalone
            } else {
                let server_config = rns_interface::local::LocalServerConfig {
                    socket_path: socket_path.clone(),
                    name: "SharedInstanceServer".to_string(),
                    force_bitrate: rc.force_shared_instance_bitrate,
                };
                match rns_interface::local::spawn_local_server(
                    server_config,
                    next_id(&id_gen),
                    id_gen.clone(),
                    transport_tx.clone(),
                    handle_tx.clone(),
                )
                .await
                {
                    Ok(server_handle) => {
                        if !options.require_shared_instance {
                            storage.start(StorageRole::Owner).await;
                        }
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
                            force_bitrate: rc.force_shared_instance_bitrate,
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
                                storage.start(StorageRole::SharedInstanceClient).await;
                                adopt_shared_instance_client(
                                    client_handle,
                                    &transport_tx,
                                    &interface_controls,
                                    &interface_registry,
                                    &shutdown,
                                    rc.force_shared_instance_bitrate,
                                    shared_spawn_permit.take(),
                                )
                                .await?
                            }
                            Err(error) => shared_instance_unreachable(&error),
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
        )
        .into());
    }

    // Reticulum.py: only becoming the shared instance fails the requirement.
    if options.require_shared_instance
        && (would_own_shared_instance || instance_mode == InstanceMode::Shared)
    {
        tracing::debug!(
            "Existing shared instance required, but this instance started as shared instance. Aborting startup."
        );
        shutdown_coordinator.start_and_wait().await;
        return Err(ReticulumError::RequiredSharedInstanceUnavailable.into());
    }
    // A standalone instance, and one whose shared socket could not be used, owns its directory.
    storage.start(StorageRole::Owner).await;

    if instance_mode == InstanceMode::Client {
        if rc.enable_transport
            || rc.enable_remote_management
            || rc.respond_to_probes
            || rc.discover_interfaces
            || rc.autoconnect_discovered_interfaces > 0
            || rc.publish_blackhole
            || !rc.blackhole_sources.is_empty()
        {
            tracing::debug!(
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
        if let Some(rpc_key) = rc.rpc_key.clone() {
            shutdown_coordinator.install_exit_unwants(SharedRpcTarget {
                endpoint: rc.shared_rpc_endpoint(&socket_base),
                rpc_key,
            });
        }
    }

    // Rebroadcast / path forwarding / reverse-path proof routing requires
    // explicit opt-in; otherwise rnsd behaves as a leaf. Shared-instance
    // clients leave transport duties to their shared sibling.
    if rc.enable_transport {
        let _ = transport_tx.try_send(TransportMessage::SetTransportEnabled { enabled: true });
        tracing::info!("transport node mode enabled");
    }

    if instance_mode != InstanceMode::Client {
        for (name, section) in config.subsections("interfaces") {
            if let Err(e) = interface_factory::validate_stamp_costs(name, section) {
                shutdown_coordinator.start_and_wait().await;
                return Err(ReticulumError::Interface(format!(
                    "failed to synthesize interface {name}: {e}"
                ))
                .into());
            }
        }
    }
    let mut startup_interface_failures = Vec::new();
    let mut interfaces = match synthesize_interfaces(
        &config,
        options
            .keep_starting_after_interface_failure
            .then_some(&mut startup_interface_failures),
    ) {
        Ok(interfaces) => interfaces,
        Err(e) => {
            shutdown_coordinator.start_and_wait().await;
            return Err(e.into());
        }
    };
    if !interfaces.is_empty() {
        tracing::debug!("synthesized {} interfaces from config", interfaces.len());
    }
    for iface_config in &mut interfaces {
        apply_discovery_mode_autocorrect(&config, iface_config);
    }
    let interfaces = interfaces;

    let discovery_runtime = Arc::new(DiscoveryRuntime::default());
    discovery_runtime.announcer_configured.store(
        config
            .subsections("interfaces")
            .iter()
            .any(|(_, section)| section.get_bool("discoverable") == Some(true)),
        Ordering::Release,
    );
    if let Ok(store) = DiscoveryStore::open(&paths.storage_dir) {
        *discovery_runtime.store.lock().await = Some(Arc::new(store));
    }
    let mut startup_rnode_runtimes = Vec::new();
    #[cfg(feature = "ble")]
    let deferred_android_ble_rnodes = collect_deferred_android_ble_rnodes(
        &interfaces,
        cfg!(target_os = "android") && instance_mode != InstanceMode::Client,
    );

    // Client mode leaves hardware to the Shared sibling.
    if instance_mode != InstanceMode::Client {
        let starter = InterfaceStarter {
            config: &config,
            rc: &rc,
            transport_tx: &transport_tx,
            id_gen: &id_gen,
            handle_tx: &handle_tx,
            socket_base: &socket_base,
            storage_dir: &paths.storage_dir,
            is_foreground: &is_foreground,
            rnode_startup_options,
            tunnel_identity: rns_interface::traits::TunnelIdentity(wire_transport_identity.clone()),
            interface_controls: &interface_controls,
            interface_registry: &interface_registry,
            shutdown: &shutdown,
            shutdown_coordinator: &shutdown_coordinator,
        };
        // Upstream starts one interface at a time (Reticulum.py); an embedder
        // may have them all start together.
        let together = if options.start_interfaces_concurrently {
            interfaces.len().max(1)
        } else {
            1
        };
        for batch in interfaces.chunks(together) {
            let mut prepared = Vec::with_capacity(batch.len());
            let mut permits = Vec::with_capacity(batch.len());
            let mut abort = None;
            for iface_config in batch {
                #[cfg(feature = "ble")]
                if should_defer_android_ble_rnode(iface_config, cfg!(target_os = "android")) {
                    tracing::info!(
                        interface = %interface_config_name(iface_config),
                        "deferring configured BLE RNode to Android native GATT owner"
                    );
                    continue;
                }
                match starter.prepare(iface_config) {
                    Ok((start, spawn_permit)) => {
                        prepared.push(start);
                        permits.push(spawn_permit);
                    }
                    // Interfaces ahead of this one still start and report first.
                    Err(reason) => {
                        abort = Some(reason);
                        break;
                    }
                }
            }
            let outcomes = join_in_order(
                prepared
                    .iter()
                    .zip(permits)
                    .map(|(start, spawn_permit)| starter.start_and_register(start, spawn_permit)),
            )
            .await;
            for (start, outcome) in prepared.iter().zip(outcomes) {
                let iface_config = start.iface_config;
                match outcome {
                    InterfaceStartOutcome::Interrupted => {
                        shutdown_coordinator.start_and_wait().await;
                        return Err(ReticulumError::Interface(
                            "runtime shutdown during interface initialization".to_string(),
                        )
                        .into());
                    }
                    InterfaceStartOutcome::Registered {
                        registered_ids,
                        rnode_runtime,
                        discovery_online,
                        discovery_addresses,
                    } => {
                        startup_rnode_runtimes.extend(rnode_runtime);
                        if let Some((host, port)) = configured_client_target(iface_config) {
                            for &registered_id in &registered_ids {
                                record_client_target(
                                    &interface_controls,
                                    registered_id,
                                    &host,
                                    port,
                                );
                            }
                        }
                        // Python announces an I2P interface itself, never its
                        // peers (Discovery.py); without a server the
                        // first peer stands in.
                        let announced = match iface_config {
                            interface_factory::InterfaceConfig::I2P(_) => {
                                &registered_ids[..registered_ids.len().min(1)]
                            }
                            _ => &registered_ids[..],
                        };
                        for &registered_id in announced {
                            if let Some(ref cfg) = start.discovery_config {
                                discovery_runtime.local_interfaces.lock().await.push(
                                    LocalDiscoveryInterface {
                                        id: registered_id,
                                        config: cfg.clone(),
                                        online: discovery_online.get(&registered_id).cloned(),
                                        reachable_on: discovery_addresses
                                            .get(&registered_id)
                                            .cloned(),
                                        location_cmd: interface_section(&config, iface_config)
                                            .and_then(|section| section.get("location_cmd"))
                                            .map(ToString::to_string),
                                    },
                                );
                            }
                            // Python never detaches an I2PInterface
                            // (Reticulum.py).
                            if start.bootstrap_only
                                && !matches!(
                                    iface_config,
                                    interface_factory::InterfaceConfig::I2P(_)
                                )
                            {
                                discovery_runtime
                                    .bootstrap_interfaces
                                    .lock()
                                    .await
                                    .push(registered_id);
                            }
                        }
                        if start.bootstrap_only {
                            if matches!(iface_config, interface_factory::InterfaceConfig::I2P(_)) {
                                discovery_runtime
                                    .i2p_bootstrap
                                    .store(true, Ordering::Release);
                            } else {
                                discovery_runtime.bootstrap_configs.lock().await.push(
                                    BootstrapConfig {
                                        config: iface_config.clone(),
                                        post_init: clone_interface_post_init(&start.post_init),
                                    },
                                );
                            }
                        }
                    }
                    InterfaceStartOutcome::RegistrationFailed(error)
                        if rc.panic_on_interface_error =>
                    {
                        shutdown_coordinator.start_and_wait().await;
                        return Err(ReticulumError::Interface(error.to_string()).into());
                    }
                    InterfaceStartOutcome::RegistrationFailed(error) => {
                        startup_interface_failures.push((
                            interface_config_name(iface_config).to_string(),
                            error.to_string(),
                        ));
                        tracing::warn!("failed to register interface: {error}");
                    }
                    InterfaceStartOutcome::StartFailed(e)
                        if options.keep_starting_after_interface_failure =>
                    {
                        tracing::warn!("failed to start interface: {e}");
                        startup_interface_failures
                            .push((interface_config_name(iface_config).to_string(), e));
                    }
                    // Upstream panics when a constructor raises, e.g. on an occupied port.
                    InterfaceStartOutcome::StartFailed(e) => {
                        shutdown_coordinator.start_and_wait().await;
                        return Err(ReticulumError::Interface(e).into());
                    }
                }
            }
            match abort {
                None => {}
                Some(InterfaceStartupAbort::ShuttingDown) => {
                    shutdown_coordinator.wait().await;
                    return Err(ReticulumError::Interface(
                        "runtime shutdown during interface initialization".to_string(),
                    )
                    .into());
                }
                Some(InterfaceStartupAbort::Failed(error)) => {
                    shutdown_coordinator.start_and_wait().await;
                    return Err(error.into());
                }
                Some(InterfaceStartupAbort::Unwound(error)) => return Err(error.into()),
            }
        }
    }

    let handle = ReticulumHandle {
        transport_tx: transport_tx.clone(),
        path_recovery,
        link_endpoint_dispatch,
        announce_dispatch,
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
        startup_interface_failures,
        #[cfg(feature = "ble")]
        deferred_android_ble_rnodes,
        shutdown_coordinator: shutdown_coordinator.clone(),
        shared_instance_status,
        started_at,
    };

    if !interface_registry.is_open() {
        shutdown_coordinator.wait().await;
        return Err(ReticulumError::Interface(
            "runtime shutdown during interface initialization".to_string(),
        )
        .into());
    }
    let _ = interface_manager.set(handle.clone());
    tokio::spawn(run_interface_control(handle.clone(), interface_control_rx));

    let mut management_announces = Vec::new();
    let mut blackhole_announce = None;
    if instance_mode != InstanceMode::Client && rc.publish_blackhole {
        match start_blackhole_publisher(&handle).await {
            Ok((dest, announce)) => {
                blackhole_announce = Some(announce);
                rns_transport::notice!(dest = %hex::encode(dest), "blackhole publisher started")
            }
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
    if instance_mode == InstanceMode::Shared
        && configured_policy
        && let Some(rpc_key) = rc.rpc_key.clone()
    {
        let rpc_backend = crate::rpc_server::RpcBackend::new(transport_tx.clone())
            .with_transport(transport_stats.clone())
            .with_inbound_queues(inbound_queues.clone())
            .with_interface_manager(interface_manager.clone());
        let rpc_shutdown = shutdown.clone();
        if rc.shared_instance_type == SharedInstanceType::Unix {
            let rpc_socket = shared_unix_rpc_socket_path(&rc.instance_name, &socket_base);
            tokio::spawn(async move {
                if let Err(e) = crate::rpc_server::serve_unix_rpc(
                    &rpc_socket,
                    rpc_key,
                    rpc_backend,
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
                    crate::rpc_server::serve_rpc_port(rpc_port, rpc_key, rpc_backend, rpc_shutdown)
                        .await
                {
                    tracing::warn!("RPC server error: {}", e);
                }
            });
        }
    }

    if instance_mode != InstanceMode::Client && rc.enable_remote_management {
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

        // Python serves remote management on Transport.identity
        // (Transport.py), the hash `rnstatus -R` and `rnpath -R` take.
        match crate::remote_management::start_remote_management_with_stats(
            transport_tx.clone(),
            &handle.transport_identity,
            allowed,
            transport_stats.clone(),
            Some(inbound_queues.clone()),
        )
        .await
        {
            Ok((dest, announce)) => {
                management_announces.push(announce);
                rns_transport::notice!(
                    dest = %hex::encode(dest),
                    transport_identity = %hex::encode(handle.transport_identity.hash),
                    "remote management started"
                );
            }
            Err(e) => {
                tracing::warn!("failed to start remote management: {}", e);
            }
        }
    }

    management_announces.extend(blackhole_announce);
    if instance_mode != InstanceMode::Client
        && let Some(network_identity) = handle.network_identity.as_ref()
    {
        management_announces.extend(start_network_destinations(&transport_tx, network_identity));
    }

    // Transport.py: only a transport instance has a probe destination,
    // and it is built on Transport.identity.
    if instance_mode != InstanceMode::Client && rc.enable_transport && rc.respond_to_probes {
        match crate::probe::spawn_announced_probe_responder(
            transport_tx.clone(),
            (*handle.transport_identity).clone(),
            crate::probe::default_probe_app_name(),
        )
        .await
        {
            Ok((dest, announce)) => {
                management_announces.push(announce);
                if let Some(transport_stats) = &transport_stats {
                    transport_stats.set_probe_responder(dest);
                }
                rns_transport::notice!(
                    dest = %hex::encode(dest),
                    "Transport Instance will respond to probe requests"
                );
            }
            Err(e) => {
                tracing::warn!("failed to start probe responder: {}", e);
            }
        }
    }

    if !management_announces.is_empty() {
        tokio::spawn(run_management_announcer(
            management_announces,
            shutdown.clone(),
        ));
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
        // LocalInterface.py: a spawned client copies the bitrate, not the MTU.
        if role == rns_transport::messages::InterfaceRole::LocalClient
            && let Some(bitrate) = forced_shared_bitrate.filter(|bitrate| *bitrate > 0)
        {
            sub_handle.bitrate = bitrate;
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
    Option<IfacKey>,
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
                control.ifac_key.clone(),
                control.ifac_size,
            )
        })
        .unwrap_or_default();
    (role, ingress_overrides, ifac_key, ifac_size)
}

fn discovered_backbone_client_mode(
    config: &ReticulumConfig,
) -> rns_interface::traits::InterfaceMode {
    if let Some(mode) = config.autoconnect_interface_mode {
        mode
    } else if config.enable_transport {
        rns_interface::traits::InterfaceMode::Gateway
    } else {
        rns_interface::traits::InterfaceMode::Full
    }
}

fn next_id(id_gen: &Arc<AtomicU64>) -> u64 {
    id_gen.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
}

#[cfg(feature = "ble")]
fn should_defer_android_ble_rnode(
    config: &interface_factory::InterfaceConfig,
    android_native_gatt_owner: bool,
) -> bool {
    android_native_gatt_owner && matches!(config, interface_factory::InterfaceConfig::BleRNode(_))
}

#[cfg(feature = "ble")]
fn collect_deferred_android_ble_rnodes(
    configs: &[interface_factory::InterfaceConfig],
    owns_android_hardware: bool,
) -> Vec<interface_factory::BleRNodeInterfaceConfig> {
    if !owns_android_hardware {
        return Vec::new();
    }
    configs
        .iter()
        .filter_map(|config| match config {
            interface_factory::InterfaceConfig::BleRNode(config) => Some(config.clone()),
            _ => None,
        })
        .collect()
}

/// An interface's own id, then one for each further interface it starts with
/// (I2P peers, RNodeMulti subinterfaces): taken before the start, so ids
/// follow config order however long each start takes.
fn reserve_interface_ids(
    config: &interface_factory::InterfaceConfig,
    id_gen: &Arc<AtomicU64>,
) -> (u64, Vec<u64>) {
    let further = match config {
        interface_factory::InterfaceConfig::I2P(c) => {
            (usize::from(c.connectable) + c.peers.len()).saturating_sub(1)
        }
        #[cfg(feature = "serial")]
        interface_factory::InterfaceConfig::RNodeMulti(c) => c.subinterfaces.len(),
        _ => 0,
    };
    let id = next_id(id_gen);
    (id, (0..further).map(|_| next_id(id_gen)).collect())
}

/// Drive every future on this task at once; outputs keep the input order.
async fn join_in_order<F: Future>(futures: impl IntoIterator<Item = F>) -> Vec<F::Output> {
    let mut futures: Vec<_> = futures.into_iter().map(Box::pin).collect();
    let mut outputs: Vec<Option<F::Output>> = futures.iter().map(|_| None).collect();
    std::future::poll_fn(|cx| {
        let mut pending = false;
        for (future, output) in futures.iter_mut().zip(&mut outputs) {
            if output.is_none() {
                match future.as_mut().poll(cx) {
                    std::task::Poll::Ready(value) => *output = Some(value),
                    std::task::Poll::Pending => pending = true,
                }
            }
        }
        if pending {
            std::task::Poll::Pending
        } else {
            std::task::Poll::Ready(())
        }
    })
    .await;
    outputs.into_iter().flatten().collect()
}

/// What starting one configured interface needs from `init`.
struct InterfaceStarter<'a> {
    config: &'a Config,
    rc: &'a ReticulumConfig,
    transport_tx: &'a mpsc::Sender<TransportMessage>,
    id_gen: &'a Arc<AtomicU64>,
    handle_tx: &'a mpsc::Sender<rns_interface::traits::InterfaceHandle>,
    socket_base: &'a Path,
    storage_dir: &'a Path,
    is_foreground: &'a Arc<AtomicBool>,
    rnode_startup_options: rns_interface::rnode::RNodeStartupOptions,
    tunnel_identity: rns_interface::traits::TunnelIdentity,
    interface_controls: &'a InterfaceControlMap,
    interface_registry: &'a InterfaceRegistry,
    shutdown: &'a ShutdownSignal,
    shutdown_coordinator: &'a RuntimeShutdownCoordinator,
}

/// A configured interface with its ids taken and its settings validated.
struct PreparedInterfaceStart<'a> {
    iface_config: &'a interface_factory::InterfaceConfig,
    id: u64,
    further_ids: Vec<u64>,
    post_init: interface_factory::InterfacePostInit,
    ifac_key: Option<IfacKey>,
    discovery_config: Option<DiscoveryInterfaceConfig>,
    bootstrap_only: bool,
}

/// Why start-up stops before an interface starts.
enum InterfaceStartupAbort {
    /// The registry is closed: a shutdown is already running.
    ShuttingDown,
    /// The interface's settings are refused; start-up shuts down and fails.
    Failed(ReticulumError),
    /// Returned without waiting for the shutdown the init guard starts.
    Unwound(ReticulumError),
}

enum InterfaceStartOutcome {
    /// Shutdown arrived while a client waited for its first connect.
    Interrupted,
    StartFailed(String),
    RegistrationFailed(InterfaceRegistrationError),
    Registered {
        registered_ids: Vec<u64>,
        rnode_runtime: Option<StartupRNodeRuntime>,
        discovery_online: HashMap<u64, Arc<AtomicBool>>,
        discovery_addresses: HashMap<u64, watch::Receiver<Option<String>>>,
    },
}

impl<'a> InterfaceStarter<'a> {
    fn prepare(
        &self,
        iface_config: &'a interface_factory::InterfaceConfig,
    ) -> Result<(PreparedInterfaceStart<'a>, InterfaceSpawnPermit), InterfaceStartupAbort> {
        let spawn_permit = self
            .interface_registry
            .acquire_spawn_permit()
            .map_err(|_| InterfaceStartupAbort::ShuttingDown)?;
        let (id, further_ids) = reserve_interface_ids(iface_config, self.id_gen);
        let refused = |error: interface_factory::InterfaceFactoryError| {
            InterfaceStartupAbort::Failed(ReticulumError::Interface(error.to_string()))
        };
        let mut post_init = get_post_init_for_config(self.config, iface_config).map_err(refused)?;
        finalize_post_init(&mut post_init, self.rc);
        interface_factory::validate_config_capacity(iface_config, &post_init).map_err(refused)?;
        let discovery_config = discovery_config_for_interface(
            self.config,
            iface_config,
            &post_init,
            self.rc.enable_transport,
            &self.rc.stamps,
        )
        .map_err(|error| InterfaceStartupAbort::Unwound(ReticulumError::Config(error)))?;
        let prepared = PreparedInterfaceStart {
            iface_config,
            id,
            further_ids,
            ifac_key: derive_ifac_key_from_post_init(&post_init),
            post_init,
            discovery_config,
            bootstrap_only: interface_bootstrap_only(self.config, iface_config),
        };
        Ok((prepared, spawn_permit))
    }

    /// Start the interface and register it as soon as it has started, so no
    /// interface waits on another between the two.
    async fn start_and_register(
        &self,
        start: &PreparedInterfaceStart<'_>,
        spawn_permit: InterfaceSpawnPermit,
    ) -> InterfaceStartOutcome {
        let iface_config = start.iface_config;
        let spawning = spawn_interface_with_rnode_startup_options(
            iface_config,
            start.id,
            &start.further_ids,
            self.transport_tx.clone(),
            self.id_gen.clone(),
            self.handle_tx.clone(),
            self.socket_base,
            self.storage_dir,
            self.is_foreground.clone(),
            self.rnode_startup_options,
            &self.tunnel_identity,
        );
        let spawned = tokio::select! {
            biased;
            _ = self.shutdown.wait(), if spawn_awaits_first_connect(iface_config) => None,
            spawned = spawning => Some(spawned),
        };
        let mut iface_handles = match spawned {
            None => return InterfaceStartOutcome::Interrupted,
            Some(Err(error)) => return InterfaceStartOutcome::StartFailed(error),
            Some(Ok(iface_handles)) => iface_handles,
        };
        apply_configured_bitrate_mtu(iface_config, &start.post_init, &mut iface_handles);
        let pending_rnode = pending_configured_rnode_runtime(iface_config, &iface_handles);
        let hardware_failures: Vec<_> = iface_handles
            .iter()
            .filter_map(|owned| owned.hardware_failures.clone())
            .collect();
        let discovery_online: HashMap<_, _> = iface_handles
            .iter()
            .map(|owned| (owned.interface.id, owned.interface.online.clone()))
            .collect();
        let discovery_addresses: HashMap<_, _> = iface_handles
            .iter()
            .filter_map(|owned| Some((owned.interface.id, owned.discovery_address.clone()?)))
            .collect();
        match register_interfaces_with_post_init_batch(
            self.transport_tx,
            iface_handles,
            &start.post_init,
            start.ifac_key.clone(),
            self.interface_controls,
            self.interface_registry,
            interface_kind_for_config(iface_config),
            Some(spawn_permit),
        )
        .await
        {
            Ok(registered_ids) => {
                if self.rc.panic_on_interface_error {
                    for failures in hardware_failures {
                        spawn_interface_panic_monitor(
                            interface_config_name(iface_config).to_string(),
                            failures,
                            self.shutdown_coordinator,
                        );
                    }
                }
                InterfaceStartOutcome::Registered {
                    rnode_runtime: pending_rnode
                        .and_then(|pending| pending.commit(&registered_ids)),
                    registered_ids,
                    discovery_online,
                    discovery_addresses,
                }
            }
            Err(error) => InterfaceStartOutcome::RegistrationFailed(error),
        }
    }
}

/// TCP and Backbone clients spawn nothing before their first connect returns,
/// so a shutdown may drop the spawn while it waits (up to 5 s).
fn spawn_awaits_first_connect(config: &interface_factory::InterfaceConfig) -> bool {
    match config {
        interface_factory::InterfaceConfig::TcpClient(_) => true,
        interface_factory::InterfaceConfig::Backbone(c) => c.target_host.is_some(),
        _ => false,
    }
}

fn interface_kind_for_config(config: &interface_factory::InterfaceConfig) -> InterfaceKind {
    match config {
        #[cfg(any(feature = "serial", feature = "rnode-tcp", target_os = "android"))]
        interface_factory::InterfaceConfig::RNode(_config) => {
            #[cfg(target_os = "android")]
            if _config.port.starts_with("androidusb://") {
                return InterfaceKind::AndroidUsbRNode;
            }
            #[cfg(any(feature = "serial", feature = "rnode-tcp"))]
            {
                InterfaceKind::RNode
            }
            #[cfg(not(any(feature = "serial", feature = "rnode-tcp")))]
            {
                InterfaceKind::Standard
            }
        }
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
    /// The address a discoverable interface learns at runtime (I2P b32).
    discovery_address: Option<tokio::sync::watch::Receiver<Option<String>>>,
    hardware_failures: Option<InterfaceFailureWatch>,
    /// A peer Python spawns for its configured interface (I2PInterface.py).
    configured_peer: bool,
}

/// A driver's failures Python answers with `RNS.panic()` when
/// `panic_on_interface_error` is set.
#[derive(Clone)]
enum InterfaceFailureWatch {
    #[cfg(any(feature = "serial", feature = "rnode-tcp", target_os = "android"))]
    RNode(rns_interface::rnode::RNodeDriverSubscription),
    #[cfg(feature = "serial")]
    RNodeMulti(rns_interface::rnode_multi::RNodeMultiFailures),
    /// TCP or Backbone client teardown (TCPInterface.py).
    ClientTeardown(rns_interface::tcp::ClientTeardown),
    /// Serial, KISS or AX.25 KISS runtime port error (SerialInterface.py).
    #[cfg(feature = "serial")]
    Serial(rns_interface::serial::SerialFailures),
}

impl InterfaceFailureWatch {
    /// True at the first failure, false if the driver ends without one.
    async fn failed(&mut self) -> bool {
        match self {
            #[cfg(any(feature = "serial", feature = "rnode-tcp", target_os = "android"))]
            Self::RNode(state) => loop {
                if state.snapshot().hardware_failure_total > 0 {
                    return true;
                }
                if state.changed().await.is_none() {
                    return false;
                }
            },
            #[cfg(feature = "serial")]
            Self::RNodeMulti(failures) => loop {
                if failures.total() > 0 {
                    return true;
                }
                if failures.changed().await.is_none() {
                    return false;
                }
            },
            Self::ClientTeardown(teardown) => teardown.torn_down().await,
            #[cfg(feature = "serial")]
            Self::Serial(failures) => loop {
                if failures.total() > 0 {
                    return true;
                }
                if failures.changed().await.is_none() {
                    return false;
                }
            },
        }
    }
}

fn client_with_teardown(
    spawned: rns_interface::tcp::SpawnedClientInterface,
) -> Vec<OwnedInterfaceHandle> {
    vec![OwnedInterfaceHandle {
        hardware_failures: Some(InterfaceFailureWatch::ClientTeardown(spawned.teardown)),
        ..spawned.interface.into()
    }]
}

#[cfg(feature = "serial")]
fn serial_with_failures(
    spawned: rns_interface::serial::SpawnedSerialInterface,
) -> Vec<OwnedInterfaceHandle> {
    vec![OwnedInterfaceHandle {
        hardware_failures: Some(InterfaceFailureWatch::Serial(spawned.failures)),
        ..spawned.interface.into()
    }]
}

fn spawn_interface_panic_monitor(
    name: String,
    mut failures: InterfaceFailureWatch,
    coordinator: &RuntimeShutdownCoordinator,
) {
    let shutdown = coordinator.inner.shutdown.clone();
    let interface_panic = coordinator.inner.interface_panic.clone();
    tokio::spawn(async move {
        let failed = tokio::select! {
            biased;
            _ = shutdown.wait() => false,
            failed = failures.failed() => failed,
        };
        if failed {
            tracing::error!(
                interface = %name,
                "interface failed and panic_on_interface_error is set, shutting down"
            );
            let _ = interface_panic.set(name);
            shutdown.trigger();
        }
    });
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

#[cfg(any(
    feature = "serial",
    feature = "rnode-tcp",
    feature = "ble",
    target_os = "android"
))]
fn pending_configured_rnode_runtime(
    config: &interface_factory::InterfaceConfig,
    handles: &[OwnedInterfaceHandle],
) -> Option<PendingConfiguredRNodeRuntime> {
    let configured_name = match config {
        #[cfg(any(feature = "serial", feature = "rnode-tcp", target_os = "android"))]
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

#[cfg(not(any(
    feature = "serial",
    feature = "rnode-tcp",
    feature = "ble",
    target_os = "android"
)))]
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
            discovery_address: None,
            hardware_failures: None,
            configured_peer: false,
        }
    }
}

impl From<rns_interface::rnode::SpawnedRNodeInterface> for OwnedInterfaceHandle {
    fn from(spawned: rns_interface::rnode::SpawnedRNodeInterface) -> Self {
        Self {
            interface: spawned.interface,
            driver: Some(spawned.driver),
            discovery_address: None,
            hardware_failures: None,
            configured_peer: false,
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
    // HDLC.py ReceiveBuffer and Transport.py bound frames by the optimised HW_MTU.
    handle.packet_capacity = rns_transport::messages::InterfacePacketCapacity::new(
        handle.mtu,
        handle.mtu,
        handle.packet_capacity.link_mtu_upgrade,
    );
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
) -> Result<InstanceMode, ReticulumError> {
    apply_forced_shared_instance_bitrate(&mut client_handle, forced_bitrate);
    let client_iface_id = client_handle.id;
    let interface_sender = rns_transport::messages::InterfaceTransportSender::bind(
        client_iface_id,
        client_handle.owner.clone(),
        transport_tx.clone(),
    );
    let client_online = client_handle.online.clone();
    // Retain the registration's exact owner for rollback if initial actor
    // attachment fails; looking up an ID later could select a replacement.
    let registered = run_single_registration_worker(
        transport_tx.clone(),
        interface_controls.clone(),
        interface_registry.clone(),
        SingleRegistrationSpec::Direct {
            owned: client_handle.into(),
            role: rns_transport::messages::InterfaceRole::SharedInstancePeer,
            ingress_overrides: rns_transport::ingress::IngressOverrides::default(),
            ifac_key: None,
            // LocalInterface.py bounds frames at HW_MTU + DEFAULT_IFAC_SIZE.
            ifac_size: rns_interface::tcp::DEFAULT_IFAC_SIZE,
            kind: InterfaceKind::Standard,
            multipoint: false,
        },
        spawn_permit,
    )
    .await;
    let token = match registered {
        Ok(tokens) => tokens[0],
        Err(error) => {
            tracing::warn!(error = %error, "failed to register shared-instance client");
            return Ok(InstanceMode::Standalone);
        }
    };
    let initial_online = client_online.load(Ordering::SeqCst);
    let owner = [(token.id, token.registry_owner)];
    let attachment = tokio::select! {
        biased;
        _ = interface_registry.wait_for_any_cancel_requested(&owner) => {
            Err("shared-instance registration owner retired")
        }
        result = apply_initial_shared_peer_state(
            &interface_sender,
            client_iface_id,
            initial_online,
            shutdown,
        ) => result,
    };
    if let Err(error) = attachment {
        tracing::warn!(
            error,
            "failed to attach shared-instance client to transport"
        );
        let rollback = teardown_interface_exact_transaction(
            transport_tx,
            interface_controls,
            interface_registry,
            token,
        );
        if tokio::time::timeout(Duration::from_secs(5), rollback)
            .await
            .is_err()
        {
            // Exact teardown has already stopped this client's task before
            // its ordered deregistration send. If that send is wedged, Drop
            // retains the registry tombstone. Stop this initializing runtime;
            // never publish a configured Standalone fallback for it. The
            // enclosing InitShutdownGuard retains whole-runtime cleanup.
            shutdown.trigger();
            return Err(ReticulumError::Interface(
                "shared-instance attachment rollback timed out; runtime shutting down".into(),
            ));
        }
        return Ok(InstanceMode::Standalone);
    }
    spawn_shared_peer_monitor(
        interface_sender,
        client_iface_id,
        client_online,
        initial_online,
        shutdown.clone(),
    );
    Ok(InstanceMode::Client)
}

/// Publish Client only after its initial attachment has actually been applied
/// by this actor. Merely queueing Restored permits a caller's separate recovery
/// lane to run first and then be erased by this initial state reset.
async fn apply_initial_shared_peer_state(
    transport_tx: &rns_transport::messages::InterfaceTransportSender,
    interface_id: u64,
    initial_online: bool,
    shutdown: &ShutdownSignal,
) -> Result<(), &'static str> {
    let attach = async {
        let initial_state = if initial_online {
            TransportMessage::SharedConnectionRestored { interface_id }
        } else {
            TransportMessage::SharedConnectionLost
        };
        transport_tx
            .send(initial_state)
            .await
            .map_err(|_| "transport closed before initial shared attachment")?;
        // An existing cheap read-only query is a same-mailbox FIFO barrier.
        // No new exhaustive mailbox variant or public startup API is needed.
        let (response_tx, response_rx) = oneshot::channel();
        transport_tx
            .send(TransportMessage::Rpc {
                query: TransportQuery::GetLinkCount,
                response_tx,
            })
            .await
            .map_err(|_| "transport closed before shared attachment barrier")?;
        response_rx
            .await
            .map_err(|_| "transport closed during shared attachment barrier")?;
        Ok(())
    };
    tokio::select! {
        biased;
        _ = shutdown.wait() => Err("runtime shut down during shared attachment"),
        result = tokio::time::timeout(Duration::from_secs(5), attach) => {
            result.map_err(|_| "shared attachment barrier timed out")?
        }
    }
}

fn spawn_shared_peer_monitor(
    transport_tx: rns_transport::messages::InterfaceTransportSender,
    interface_id: u64,
    online: Arc<AtomicBool>,
    initial_online: bool,
    shutdown: ShutdownSignal,
) {
    tokio::spawn(async move {
        // Initial state was applied before Client was published. The monitor
        // owns only later edges, not a delayed duplicate initialization.
        let mut was_online = initial_online;
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
) -> Result<rns_transport::ingress::IngressController, rns_transport::ingress::IngressOverrideError>
{
    ingress_overrides.validate()?;
    Ok(match role {
        rns_transport::messages::InterfaceRole::LocalClient
        | rns_transport::messages::InterfaceRole::SharedInstancePeer => {
            rns_transport::ingress::IngressController::disabled()
        }
        _ if ingress_overrides.is_empty() => rns_transport::ingress::IngressController::new(),
        _ => rns_transport::ingress::IngressController::try_with_overrides(ingress_overrides)?,
    })
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
    ifac_key: Option<IfacKey>,
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
    ifac_key: Option<IfacKey>,
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
    ifac_key: Option<IfacKey>,
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
    mut owned: OwnedInterfaceHandle,
    role: rns_transport::messages::InterfaceRole,
    ingress_overrides: rns_transport::ingress::IngressOverrides,
    ifac_key: Option<IfacKey>,
    ifac_size: usize,
    interface_controls: &InterfaceControlMap,
    interface_registry: &InterfaceRegistry,
    kind: InterfaceKind,
    multipoint: bool,
) -> Result<PreparedInterfaceRegistration, InterfaceRegistrationError> {
    let inherited = owned.interface.parent_id.and_then(|parent| {
        interface_controls
            .lock()
            .expect("interface_controls mutex poisoned")
            .get(&parent)
            .and_then(|parent| parent.spawn.clone())
    });
    if let Some(parent) = &inherited {
        parent.apply(&mut owned.interface);
    }
    let ingress = match ingress_for_role(role, &ingress_overrides) {
        Ok(ingress) => ingress,
        Err(error) => {
            rollback_unreserved_interface(owned, kind).await;
            return Err(InterfaceRegistrationError::InvalidIngress { field: error.field });
        }
    };
    if ifac_key.is_some() && !(1..=64).contains(&ifac_size) {
        rollback_unreserved_interface(owned, kind).await;
        return Err(InterfaceRegistrationError::InvalidCapacity(
            "active IFAC size must be 1..=64".into(),
        ));
    }
    if let Err(error) = owned
        .interface
        .packet_capacity
        .effective_clear_mtu(if ifac_key.is_some() { ifac_size } else { 0 })
    {
        rollback_unreserved_interface(owned, kind).await;
        return Err(InterfaceRegistrationError::InvalidCapacity(
            error.to_string(),
        ));
    }
    let OwnedInterfaceHandle {
        interface, driver, ..
    } = owned;
    let handle = interface;
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
    let child_stamp_costs;
    let child_ifac_netname;
    {
        let mut controls = interface_controls
            .lock()
            .expect("interface_controls mutex poisoned");
        // A spawned child's IFAC is its parent's, network name included.
        let ifac_netname = ifac_key
            .as_ref()
            .and(handle.parent_id)
            .and_then(|parent| controls.get(&parent))
            .and_then(|parent| parent.ifac_netname.clone());
        let (destination_cost, pr_cost) = handle
            .parent_id
            .and_then(|parent| controls.get(&parent))
            .map(|parent| (parent.destination_cost, parent.pr_cost))
            .unwrap_or_default();
        child_stamp_costs = (destination_cost, pr_cost);
        child_ifac_netname = ifac_netname.clone();
        controls.insert(
            id,
            InterfaceControlMetadata {
                transport_owner: handle.owner.clone(),
                registry_owner,
                role,
                ingress_overrides: ingress_overrides.clone(),
                ifac_key: ifac_key.clone(),
                ifac_size,
                ifac_netname,
                client_target: None,
                destination_cost,
                pr_cost,
                spawn: None,
            },
        );
    }
    let mut entry = rns_transport::messages::InterfaceEntry::new(
        handle.name.clone(),
        convert_mode(handle.mode),
        rns_transport::constants::InterfaceDirection {
            inbound: handle.direction.inbound,
            outbound: handle.direction.outbound,
        },
        handle.bitrate,
        handle.mtu,
        handle.tx,
    );
    entry.owner = handle.owner.clone();
    entry.packet_capacity = handle.packet_capacity;
    entry.role = role;
    entry.parent_id = handle.parent_id;
    entry.accepted = handle.parent_id.is_some();
    entry.ifac_key = ifac_key;
    entry.ifac_size = ifac_size;
    entry.ifac_netname = child_ifac_netname;
    entry.online = Some(online.clone());
    entry.rxb = handle.rxb;
    entry.txb = handle.txb;
    entry.inspection = handle.inspection;
    entry.ingress = ingress;
    entry.multipoint = multipoint;
    entry.shared_medium = kind.shared_medium();
    if let Some(parent) = inherited.as_ref() {
        entry.announce_cap = parent.announce_cap;
        entry.announce_rate_target = parent.announce_rate_target;
        entry.announce_rate_grace = parent.announce_rate_grace;
        entry.announce_rate_penalty = parent.announce_rate_penalty;
        entry.recursive_prs = parent.recursive_prs;
        entry.announces_from_internal = parent.announces_from_internal;
        entry.announces_to_internal = parent.announces_to_internal;
        entry.gravity = parent.gravity;
        entry.hop_limiter = parent.hop_limiter;
    }
    entry.destination_cost = child_stamp_costs.0;
    entry.pr_cost = child_stamp_costs.1;
    Ok(PreparedInterfaceRegistration {
        transport_owner: handle.owner.clone(),
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
    ifac_key: Option<IfacKey>,
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
    ifac_key: Option<IfacKey>,
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
    ifac_key: Option<IfacKey>,
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
            post_init: Box::new(clone_interface_post_init(post_init)),
            ifac_key,
            kind,
        },
        spawn_permit,
    )
    .await
    .map(|_| ())
}

/// Python's configured `bitrate`, which counts from `MINIMUM_BITRATE` (Reticulum.py).
fn configured_bitrate(post_init: &interface_factory::InterfacePostInit) -> Option<u64> {
    post_init
        .bitrate
        .filter(|bitrate| *bitrate >= MINIMUM_BITRATE)
}

/// Python's post-init `optimise_mtu` after a configured bitrate (Reticulum.py),
/// for the interface classes with `AUTOCONFIGURE_MTU`.
fn apply_configured_bitrate_mtu(
    iface_config: &interface_factory::InterfaceConfig,
    post_init: &interface_factory::InterfacePostInit,
    handles: &mut [OwnedInterfaceHandle],
) {
    let autoconfigures = match iface_config {
        interface_factory::InterfaceConfig::TcpClient(c) => c.fixed_mtu.is_none(),
        interface_factory::InterfaceConfig::TcpServer(_)
        | interface_factory::InterfaceConfig::Backbone(_) => true,
        _ => false,
    };
    let Some(bitrate) = configured_bitrate(post_init).filter(|_| autoconfigures) else {
        return;
    };
    for owned in handles {
        rns_interface::traits::apply_autoconfigured_mtu(&mut owned.interface, bitrate);
    }
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
        announce_ingress_exempt: post_init.announce_ingress_exempt,
        shared_medium: post_init.shared_medium,
        ingress_overrides: post_init.ingress_overrides.clone(),
        recursive_prs: post_init.recursive_prs,
        announces_from_internal: post_init.announces_from_internal,
        announces_to_internal: post_init.announces_to_internal,
        gravity: post_init.gravity,
        hop_limiter: post_init.hop_limiter,
        spawned_hop_limiter: post_init.spawned_hop_limiter,
        destination_cost: post_init.destination_cost,
        pr_cost: post_init.pr_cost,
        autoconnect_source: post_init.autoconnect_source.clone(),
    }
}

/// Python's I2P key file for an interface: the old name when that file
/// exists, else one bound to the transport identity (I2PInterface.py).
fn i2p_key_path(storage_dir: &Path, name: &str, transport_identity_hash: &[u8; 16]) -> PathBuf {
    let dir = storage_dir.join("i2p");
    let name_hash = rns_crypto::sha::sha256(name.as_bytes());
    let old_format = dir.join(format!(
        "{}.i2p",
        hex::encode(rns_crypto::sha::sha256(&name_hash))
    ));
    if old_format.is_file() {
        return old_format;
    }
    let mut material = name_hash.to_vec();
    material.extend_from_slice(&rns_crypto::sha::sha256(transport_identity_hash));
    dir.join(format!(
        "{}.i2p",
        hex::encode(rns_crypto::sha::sha256(&material))
    ))
}

async fn prepare_interface_with_post_init(
    owned: OwnedInterfaceHandle,
    post_init: &interface_factory::InterfacePostInit,
    ifac_key: Option<IfacKey>,
    interface_controls: &InterfaceControlMap,
    interface_registry: &InterfaceRegistry,
    kind: InterfaceKind,
) -> Result<PreparedInterfaceRegistration, InterfaceRegistrationError> {
    let mut ingress = if post_init.ingress_overrides.is_empty() {
        rns_transport::ingress::IngressController::new()
    } else {
        match rns_transport::ingress::IngressController::try_with_overrides(
            &post_init.ingress_overrides,
        ) {
            Ok(ingress) => ingress,
            Err(error) => {
                rollback_unreserved_interface(owned, kind).await;
                return Err(InterfaceRegistrationError::InvalidIngress { field: error.field });
            }
        }
    };
    // RNodeMulti subinterfaces receive the traffic and keep the base limiter.
    if post_init.announce_ingress_exempt && owned.interface.parent_id.is_none() {
        ingress.exempt_announce_limit();
    }
    if ifac_key.is_some()
        && !(1..=64).contains(&post_init.ifac_size.unwrap_or(post_init.default_ifac_size))
    {
        rollback_unreserved_interface(owned, kind).await;
        return Err(InterfaceRegistrationError::InvalidCapacity(
            "active IFAC size must be 1..=64".into(),
        ));
    }
    if let Err(error) = owned
        .interface
        .packet_capacity
        .effective_clear_mtu(if ifac_key.is_some() {
            post_init.ifac_size.unwrap_or(post_init.default_ifac_size)
        } else {
            0
        })
    {
        rollback_unreserved_interface(owned, kind).await;
        return Err(InterfaceRegistrationError::InvalidCapacity(
            error.to_string(),
        ));
    }
    let OwnedInterfaceHandle {
        interface,
        driver,
        configured_peer,
        ..
    } = owned;
    let handle = interface;
    // Outbound = physical capability AND `outgoing` config flag. An
    // RNodeMulti section's `outgoing` applies to its parent only.
    let rnode_multi_child = {
        #[cfg(feature = "serial")]
        {
            kind == InterfaceKind::RNodeMulti && handle.parent_id.is_some()
        }
        #[cfg(not(feature = "serial"))]
        {
            false
        }
    };
    let direction = rns_transport::constants::InterfaceDirection {
        inbound: handle.direction.inbound,
        outbound: handle.direction.outbound && (post_init.outgoing || rnode_multi_child),
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
    let bitrate = configured_bitrate(post_init).unwrap_or(handle.bitrate);
    let announce_cap = post_init.announce_cap.unwrap_or(ANNOUNCE_CAP);
    let announce_rate_target = post_init.announce_rate_target.map(|v| v as f64);
    let announce_rate_penalty = post_init.announce_rate_penalty.map(|v| v as f64);
    interface_controls
        .lock()
        .expect("interface_controls mutex poisoned")
        .insert(
            id,
            InterfaceControlMetadata {
                transport_owner: handle.owner.clone(),
                registry_owner,
                role: rns_transport::messages::InterfaceRole::Normal,
                ingress_overrides: post_init.ingress_overrides.clone(),
                ifac_netname: ifac_key.as_ref().and(post_init.ifac_network_name.clone()),
                ifac_key: ifac_key.clone(),
                ifac_size: post_init.ifac_size.unwrap_or(post_init.default_ifac_size),
                client_target: None,
                destination_cost: post_init.destination_cost,
                pr_cost: post_init.pr_cost,
                spawn: Some(SpawnInheritance {
                    mode: handle.mode,
                    outgoing: post_init.outgoing,
                    bitrate,
                    mtu: handle.mtu,
                    packet_capacity: handle.packet_capacity,
                    announce_cap,
                    announce_rate_target,
                    announce_rate_grace: post_init.announce_rate_grace,
                    announce_rate_penalty,
                    recursive_prs: post_init.recursive_prs,
                    announces_from_internal: post_init.announces_from_internal,
                    announces_to_internal: post_init.announces_to_internal,
                    gravity: post_init.gravity.unwrap_or(0),
                    hop_limiter: post_init
                        .hop_limiter
                        .filter(|_| post_init.spawned_hop_limiter),
                }),
            },
        );
    let mut entry = rns_transport::messages::InterfaceEntry::new(
        handle.name.clone(),
        convert_mode(handle.mode),
        direction,
        bitrate,
        handle.mtu,
        handle.tx,
    );
    entry.owner = handle.owner.clone();
    entry.packet_capacity = handle.packet_capacity;
    entry.parent_id = handle.parent_id;
    entry.ifac_netname = ifac_key.as_ref().and(post_init.ifac_network_name.clone());
    entry.ifac_key = ifac_key;
    entry.ifac_size = post_init.ifac_size.unwrap_or(post_init.default_ifac_size);
    entry.autoconnect_source = post_init.autoconnect_source.clone();
    entry.announce_cap = announce_cap;
    entry.announce_rate_target = announce_rate_target;
    entry.announce_rate_grace = post_init.announce_rate_grace;
    entry.announce_rate_penalty = announce_rate_penalty;
    entry.online = Some(online.clone());
    entry.rxb = handle.rxb;
    entry.txb = handle.txb;
    entry.inspection = handle.inspection;
    entry.ingress = ingress;
    entry.recursive_prs = post_init.recursive_prs;
    entry.announces_from_internal = post_init.announces_from_internal;
    entry.announces_to_internal = post_init.announces_to_internal;
    entry.gravity = post_init.gravity.unwrap_or(0);
    entry.shared_medium = post_init.shared_medium;
    // Reticulum.py sets it on the configured interface, not on an RNodeMulti
    // subinterface or an I2P peer.
    entry.hop_limiter = post_init
        .hop_limiter
        .filter(|_| handle.parent_id.is_none() && !configured_peer);
    entry.destination_cost = post_init.destination_cost;
    entry.pr_cost = post_init.pr_cost;
    Ok(PreparedInterfaceRegistration {
        transport_owner: handle.owner.clone(),
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
    InvalidCapacity(String),
    InvalidIngress { field: &'static str },
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
            Self::InvalidCapacity(error) => {
                write!(formatter, "invalid interface capacity: {error}")
            }
            Self::InvalidIngress { field } => write!(formatter, "invalid ingress override {field}"),
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
        ifac_key: Option<IfacKey>,
        ifac_size: usize,
        kind: InterfaceKind,
        multipoint: bool,
    },
    PostInit {
        owned: OwnedInterfaceHandle,
        post_init: Box<interface_factory::InterfacePostInit>,
        ifac_key: Option<IfacKey>,
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
    transport_owner: rns_transport::messages::InterfaceOwner,
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
) -> Result<Vec<CommittedInterfaceToken>, InterfaceRegistrationError> {
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
    result
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
            .send(
                rns_transport::messages::InterfaceTransportSender::bind(
                    interface.id,
                    interface.transport_owner.clone(),
                    transport_tx.clone(),
                )
                .event(TransportMessage::DeregisterInterface { id: interface.id }),
            )
            .await
            .is_ok();
        if deregistered && let Some(registration) = interface.registration.take() {
            registration.release();
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
    ifac_key: Option<IfacKey>,
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
    ifac_key: Option<IfacKey>,
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
    ifac_key: Option<IfacKey>,
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
            ifac_key.clone(),
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
                .send(
                    rns_transport::messages::InterfaceTransportSender::bind(
                        interface.id,
                        interface.transport_owner.clone(),
                        transport_tx.clone(),
                    )
                    .event(TransportMessage::DeregisterInterface { id: interface.id }),
                )
                .await
                .is_ok();
        if safe_to_release && let Some(registration) = interface.registration.take() {
            registration.release();
        }
    }
}

async fn rollback_unreserved_interface(owned: OwnedInterfaceHandle, kind: InterfaceKind) {
    let OwnedInterfaceHandle {
        interface: handle,
        driver,
        ..
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
) -> Option<rns_transport::messages::InterfaceOwner> {
    let mut controls = interface_controls
        .lock()
        .expect("interface_controls mutex poisoned");
    if controls
        .get(&id)
        .is_some_and(|control| control.registry_owner == registry_owner)
    {
        return controls.remove(&id).map(|control| control.transport_owner);
    }
    None
}

fn derive_ifac_key_from_post_init(
    post_init: &interface_factory::InterfacePostInit,
) -> Option<IfacKey> {
    if post_init.ifac_network_name.is_some() || post_init.ifac_passphrase.is_some() {
        IfacKey::derive(
            post_init.ifac_network_name.as_deref(),
            post_init.ifac_passphrase.as_deref().map(String::as_str),
        )
        .ok()
    } else {
        None
    }
}

#[derive(Clone, Default)]
/// Optional IFAC settings for runtime-spawned TCP/Backbone interfaces.
/// `ifac_size` is bytes (1..=64), default 16 when active. An empty or "None" name or
/// passphrase is ignored, as in config files. IFAC restricts interface access; it does not
/// provide application end-to-end encryption. `Debug` redacts the passphrase,
/// but the owned `String` is not itself a zeroizing container.
pub struct RuntimeInterfaceIfacConfig {
    pub network_name: Option<String>,
    pub passphrase: Option<String>,
    pub ifac_size: Option<usize>,
}

// The passphrase is the interface's secret; debug output names only its presence.
impl std::fmt::Debug for RuntimeInterfaceIfacConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RuntimeInterfaceIfacConfig")
            .field("network_name", &self.network_name)
            .field(
                "passphrase",
                &self.passphrase.as_ref().map(|_| "<redacted>"),
            )
            .field("ifac_size", &self.ifac_size)
            .finish()
    }
}

#[derive(Clone, Debug)]
/// Runtime Backbone client options. `connect_timeout` is seconds for a
/// connection attempt, not the lifetime of the reconnect loop or this whole
/// registration call. Optional IFAC uses a 16-byte default tag.
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

    if let Some(size) = ifac.ifac_size
        && !(1..=64).contains(&size)
    {
        return Err(format!("Invalid IFAC size {size}; expected 1..=64 bytes"));
    }

    let network_name = ifac.network_name.filter(|s| !s.is_empty() && s != "None");
    let passphrase = ifac.passphrase.filter(|s| !s.is_empty() && s != "None");
    if network_name.is_none() && passphrase.is_none() {
        return Ok(None);
    }

    let mut post_init =
        interface_factory::InterfacePostInit::try_from_section(&ConfigSection::new())
            .expect("empty interface defaults are valid")
            .with_default_ifac_size(default_ifac_size);
    post_init.ifac_network_name = network_name;
    post_init.ifac_passphrase = passphrase.map(zeroize::Zeroizing::new);
    post_init.ifac_size = ifac.ifac_size;
    Ok(Some(post_init))
}

fn get_post_init_for_config(
    config: &Config,
    iface_config: &interface_factory::InterfaceConfig,
) -> Result<interface_factory::InterfacePostInit, interface_factory::InterfaceFactoryError> {
    let name = interface_config_name(iface_config);
    let default_ifac_size = interface_factory::default_ifac_size_for(iface_config);
    if let Some(section) = config.subsection("interfaces", name) {
        return interface_factory::InterfacePostInit::try_from_section(section)
            .map(|post_init| post_init.with_default_ifac_size(default_ifac_size));
    }
    interface_factory::InterfacePostInit::try_from_section(&crate::config::ConfigSection::new())
        .map(|post_init| post_init.with_default_ifac_size(default_ifac_size))
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
    if post_init.gravity.is_none() {
        post_init.gravity = Some(config.default_gravity.unwrap_or(0));
    }
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
        #[cfg(any(feature = "serial", feature = "rnode-tcp", target_os = "android"))]
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
        #[cfg(any(feature = "serial", feature = "rnode-tcp", target_os = "android"))]
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

/// Python Reticulum.py: a `discoverable` interface must run in
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
        #[cfg(any(feature = "serial", feature = "rnode-tcp", target_os = "android"))]
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
    rns_transport::notice!(
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
    stamps: &rns_transport::stamps::StampPolicy,
) -> Result<Option<DiscoveryInterfaceConfig>, ConfigError> {
    let Some(section) = interface_section(config, iface_config) else {
        return Ok(None);
    };
    let iface_name = interface_config_name(iface_config);
    // Upstream parses these only for a discoverable interface, and a bad value
    // stops startup (Reticulum.py).
    let key_error = |key: &str, what: &str| {
        invalid_config_value(&format!("interfaces.{iface_name}"), key, what)
    };
    let bool_key = |key: &str| config_bool(&format!("interfaces.{iface_name}"), section, key);
    let float_key = |key: &str| config_float(&format!("interfaces.{iface_name}"), section, key);
    let uint_key = |key: &str| {
        section
            .has(key)
            .then(|| {
                section
                    .get_uint(key)
                    .ok_or_else(|| key_error(key, "value is not an integer"))
            })
            .transpose()
    };
    if bool_key("discoverable")? != Some(true) {
        return Ok(None);
    }

    let name = section.get("discovery_name").map(sanitize_discovery_value);

    let (interface_type, reachable_on, port, frequency, bandwidth, spreading_factor, coding_rate) =
        match iface_config {
            interface_factory::InterfaceConfig::TcpServer(c) => (
                "TCPServerInterface",
                match server_reachable_on(section, iface_config) {
                    Some(reachable_on) => Some(reachable_on),
                    None => return Ok(None),
                },
                Some(c.listen_port),
                None,
                None,
                None,
                None,
            ),
            // Python announces a KISS-framed TCP client as a KISS interface
            // (Discovery.py).
            interface_factory::InterfaceConfig::TcpClient(c) if c.kiss_framing => {
                ("KISSInterface", None, None, None, None, None, None)
            }
            // A target host makes a BackboneClientInterface, which Python never
            // announces (Reticulum.py, BackboneInterface.py).
            interface_factory::InterfaceConfig::Backbone(c) if c.target_host.is_some() => {
                return Ok(None);
            }
            interface_factory::InterfaceConfig::Backbone(c) => (
                "BackboneInterface",
                match server_reachable_on(section, iface_config) {
                    Some(reachable_on) => Some(reachable_on),
                    None => return Ok(None),
                },
                Some(c.port),
                None,
                None,
                None,
                None,
            ),
            // The server announces its own b32 once SAM assigns it
            // (Discovery.py).
            interface_factory::InterfaceConfig::I2P(_) => {
                ("I2PInterface", None, None, None, None, None, None)
            }
            #[cfg(any(feature = "serial", feature = "rnode-tcp", target_os = "android"))]
            interface_factory::InterfaceConfig::RNode(c) => (
                "RNodeInterface",
                None,
                None,
                Some(c.frequency as u64),
                Some(c.bandwidth as u64),
                Some(c.spreading_factor),
                Some(c.coding_rate),
            ),
            #[cfg(feature = "ble")]
            interface_factory::InterfaceConfig::BleRNode(c) => (
                "RNodeInterface",
                None,
                None,
                Some(c.frequency as u64),
                Some(c.bandwidth as u64),
                Some(c.spreading_factor),
                Some(c.coding_rate),
            ),
            _ => return Ok(None),
        };

    let publish_ifac = bool_key("discovery_publish_ifac")?
        .or(bool_key("publish_ifac")?)
        .unwrap_or(false);
    let modulation = if section.has("discovery_modulation") {
        let value = section
            .get_int("discovery_modulation")
            .ok_or_else(|| key_error("discovery_modulation", "value is not an integer"))?;
        (interface_type == "KISSInterface")
            .then_some(rns_transport::discovery::app_data::DiscoveryModulation::Int(value))
    } else {
        None
    };
    let operator_lxmf_address = section.get("discovery_lxmf_address").and_then(|hex| {
        let address = (hex.len() == 32).then(|| hex_to_16(hex)).flatten();
        if address.is_none() {
            tracing::error!(interface = %iface_name, address = %hex, "invalid interface discovery LXMF address");
        }
        address
    });
    // Only KISS announces the discovery_* radio keys; RNode sends its own (Discovery.py).
    let discovery_frequency = uint_key("discovery_frequency")?;
    let discovery_bandwidth = uint_key("discovery_bandwidth")?;
    let (frequency, bandwidth) = if interface_type == "KISSInterface" {
        (discovery_frequency, discovery_bandwidth)
    } else {
        (frequency, bandwidth)
    };
    let latitude = float_key("discovery_latitude")?.or(float_key("latitude")?);
    let longitude = float_key("discovery_longitude")?.or(float_key("longitude")?);
    let height = float_key("discovery_height")?.or(float_key("height")?);
    let encrypt = bool_key("discovery_encrypt")?.unwrap_or(false);
    let announce_interval_secs = discovery_announce_interval_secs(section, &key_error)?;
    let stamp_value = discovery_stamp_value(&float_key)?;

    Ok(Some(DiscoveryInterfaceConfig {
        interface_type: interface_type.to_string(),
        discoverable: true,
        name,
        transport_enabled,
        announce_interval_secs,
        stamp_value,
        dst_cost: Some(stamps.interface_destination_cost(post_init.destination_cost)),
        pr_cost: Some(stamps.interface_pr_cost(post_init.pr_cost)),
        reachable_on,
        port,
        ifac_netname: publish_ifac
            .then(|| post_init.ifac_network_name.clone())
            .flatten(),
        ifac_netkey: publish_ifac
            .then(|| post_init.ifac_passphrase.as_deref().cloned())
            .flatten(),
        frequency,
        bandwidth,
        spreading_factor,
        coding_rate,
        modulation,
        channel: None,
        operator_lxmf_address,
        latitude,
        longitude,
        height,
        encrypt,
        signed: false,
    }))
}

/// Upstream's announcer `sanitize`: drop CR and LF, then strip (Discovery.py).
fn sanitize_discovery_value(value: &str) -> String {
    value.replace(['\n', '\r'], "").trim().to_string()
}

fn hex_to_16(hex: &str) -> Option<[u8; 16]> {
    let mut out = [0u8; 16];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(hex.get(i * 2..i * 2 + 2)?, 16).ok()?;
    }
    Some(out)
}

/// Python reads `discovery_stamp_value` with `as_float` and generates at 16
/// when it is unset or 0 (Reticulum.py, Discovery.py).
fn discovery_stamp_value(
    float_key: &dyn Fn(&str) -> Result<Option<f64>, ConfigError>,
) -> Result<f64, ConfigError> {
    if let Some(value) = float_key("discovery_stamp_value")? {
        return Ok(value);
    }
    let legacy = float_key("stamp_value")?;
    if legacy.is_some() {
        tracing::warn!("interface key stamp_value is deprecated, use discovery_stamp_value");
    }
    Ok(legacy.unwrap_or(0.0))
}

/// Upstream announces only an IP address or hostname and logs an error for
/// anything else (Discovery.py).
fn configured_reachable_on(section: &ConfigSection) -> Option<String> {
    let reachable_on = sanitize_discovery_value(section.get("reachable_on")?);
    if rns_transport::discovery::address::is_valid_address(&reachable_on) == Some(true) {
        Some(reachable_on)
    } else {
        tracing::error!(
            reachable_on = %reachable_on,
            "the configured reachable_on is not a valid IP address or hostname, not announcing it for discovery"
        );
        None
    }
}

/// Python announces a server only with a configured `reachable_on`, and logs
/// an error at each announce it skips (Discovery.py).
fn server_reachable_on(
    section: &ConfigSection,
    iface_config: &interface_factory::InterfaceConfig,
) -> Option<String> {
    let reachable_on = configured_reachable_on(section);
    if reachable_on.is_none() {
        tracing::warn!(
            interface = %interface_config_name(iface_config),
            "discoverable interface has no reachable_on, so it is not announced for discovery"
        );
    }
    reachable_on
}

fn discovery_announce_interval_secs(
    section: &ConfigSection,
    key_error: &dyn Fn(&str, &str) -> ConfigError,
) -> Result<u64, ConfigError> {
    if let Some(seconds) = section.get_uint("discovery_announce_interval_secs") {
        return Ok(seconds.max(1));
    }
    if let Some(minutes) = section.get_float("discovery_announce_interval") {
        return Ok((minutes.max(0.0) * 60.0).round().max(1.0) as u64);
    }
    // Upstream: whole minutes, at least five, six hours when unset (Reticulum.py).
    match section.get("announce_interval") {
        None => Ok(6 * 60 * 60),
        Some(value) => value
            .trim()
            .parse::<i64>()
            .map(|minutes| minutes.saturating_mul(60).max(5 * 60) as u64)
            .map_err(|_| key_error("announce_interval", "value is not an integer")),
    }
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
            // InterfaceDiscovery registers its announce type (Discovery.py).
            handle
                .wants_destination_type(
                    rns_transport::discovery::constants::DISCOVERY_ASPECT_FILTER,
                )
                .await;

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
            let subscription = handle
                .subscribe_announces_with_capacity(
                    Some(rns_transport::discovery::constants::DISCOVERY_ASPECT_FILTER.to_string()),
                    false,
                    128,
                )
                .await;
            match subscription {
                Ok(subscription) => {
                    let (receiver_join, callback_tx) =
                        rns_transport::discovery::receiver::spawn(receiver_config);
                    let shutdown = handle.shutdown.clone();
                    tokio::spawn(run_discovery_subscription(
                        subscription,
                        callback_tx,
                        receiver_join,
                        shutdown,
                    ));
                }
                Err(error) => {
                    tracing::warn!(
                        error = %error,
                        "failed to install exact interface-discovery announce subscription"
                    );
                    *handle.discovery.receiver_started.lock().await = false;
                }
            }

            if let Some(rx) = observer_rx {
                let observer_handle = handle.clone();
                tokio::spawn(async move {
                    run_discovery_autoconnect(observer_handle, rx).await;
                });
            }
        }
    }

    let announcing = handle
        .discovery
        .announcer_configured
        .load(Ordering::Acquire)
        || !handle.discovery.local_interfaces.lock().await.is_empty();
    if handle.instance_mode != InstanceMode::Client && announcing {
        let mut started = handle.discovery.announcer_started.lock().await;
        if !*started {
            *started = true;
            drop(started);
            tokio::spawn(async move {
                run_discovery_announcer(handle, stamper).await;
            });
        }
    }
}

async fn run_discovery_subscription(
    mut subscription: AnnounceSubscription,
    callback_tx: mpsc::Sender<AnnounceHandlerEvent>,
    receiver_join: tokio::task::JoinHandle<()>,
    shutdown: ShutdownSignal,
) {
    loop {
        tokio::select! {
            _ = shutdown.wait() => break,
            event = subscription.recv() => match event {
                Some(event) => {
                    if callback_tx.send(event).await.is_err() {
                        break;
                    }
                }
                None => break,
            },
        }
    }
    let dropped_events = subscription.dropped_events();
    if let Err(error) = subscription.close().await {
        tracing::debug!(error = %error, "interface-discovery subscription close failed");
    }
    drop(callback_tx);
    let _ = receiver_join.await;
    if dropped_events > 0 {
        tracing::warn!(
            dropped_events,
            "interface-discovery announces dropped by bounded subscription"
        );
    }
}

async fn run_discovery_announcer(
    handle: ReticulumHandle,
    stamper: Arc<dyn DiscoveryStamper + Send + Sync>,
) {
    run_discovery_publisher(&handle, stamper).await;
    *handle.discovery.announcer_started.lock().await = false;
}

async fn run_discovery_publisher(
    handle: &ReticulumHandle,
    stamper: Arc<dyn DiscoveryStamper + Send + Sync>,
) {
    use rns_transport::announce_dispatch::AnnounceDispatchResult;
    use rns_transport::discovery::announcer::PreparedAnnounce;

    let announce_identity = handle
        .network_identity
        .as_ref()
        .unwrap_or(&handle.transport_identity);
    let registration = tokio::select! {
        _ = handle.shutdown.wait() => return,
        registration = handle.register_destination(
            (**announce_identity).clone(),
            rns_transport::discovery::constants::DISCOVERY_ASPECT_FILTER,
            crate::destination_runtime::DestinationRuntimeOptions {
                accepts_links: false,
                ..Default::default()
            },
        ) => match registration {
            Ok(registration) => registration,
            Err(error) => {
                tracing::warn!(%error, "failed to register discovery destination");
                return;
            }
        },
    };

    struct Publication {
        prepared: PreparedAnnounce,
        pending: Option<oneshot::Receiver<AnnounceDispatchResult>>,
        last_failure: Option<AnnounceDispatchResult>,
        retry_at: tokio::time::Instant,
    }
    let mut publications: HashMap<u64, Publication> = HashMap::new();
    struct CancelOnDrop(Arc<AtomicBool>);
    impl Drop for CancelOnDrop {
        fn drop(&mut self) {
            self.0.store(true, Ordering::Relaxed);
        }
    }
    // A blocking thread owns the announcer while it generates stamps.
    let announcer = Announcer::new(stamper);
    let cancel_generation = CancelOnDrop(announcer.stamp_control().cancel.clone());
    let mut announcer = Some(announcer);
    let mut preparing: Option<tokio::task::JoinHandle<(Announcer, Vec<PreparedAnnounce>)>> = None;
    let mut deferred_commits: Vec<(PreparedAnnounce, f64)> = Vec::new();
    let mut discovery_destination = match rns_identity::destination::Destination::new(
        Some(announce_identity),
        rns_identity::destination::Direction::In,
        rns_identity::destination::DestType::Single,
        rns_transport::discovery::constants::DISCOVERY_ASPECT_FILTER,
    ) {
        Ok(destination) => destination,
        Err(error) => {
            tracing::warn!(%error, "failed to build discovery destination");
            return;
        }
    };
    crate::destination_stamper::load_stored_stamp(&mut discovery_destination, announce_identity);
    let mut discovery_stamps = crate::destination_stamper::DestinationStamps::<()>::new();
    let mut registered: HashMap<u64, Option<String>> = HashMap::new();
    // Python's last_discovery_announce and job sleep (Discovery.py).
    let mut last_announce: HashMap<u64, tokio::time::Instant> = HashMap::new();
    let mut next_prepare = tokio::time::Instant::now()
        + Duration::from_secs(rns_transport::discovery::constants::ANNOUNCE_JOB_INTERVAL_SECS);
    let mut tick = tokio::time::interval(Duration::from_secs(1));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            biased;
            _ = handle.shutdown.wait() => break,
            _ = handle.transport_tx.closed() => break,
            _ = tick.tick() => {}
        }
        // Python walks the live interface list on every pass (Discovery.py).
        let locals = handle.discovery.local_interfaces.lock().await.clone();
        publications.retain(|id, _| locals.iter().any(|local| local.id == *id));
        if let Some(announcer) = announcer.as_mut() {
            registered.retain(|id, _| {
                let live = locals.iter().any(|local| local.id == *id);
                if !live {
                    announcer.deregister(*id);
                    last_announce.remove(id);
                }
                live
            });
        }
        let now = tokio::time::Instant::now();
        if preparing.as_ref().is_some_and(|job| job.is_finished()) {
            let job = preparing.take().expect("checked above");
            match job.await {
                Ok((mut returned, prepared)) => {
                    // Python sleeps a full job interval after each pass's work.
                    next_prepare = now
                        + Duration::from_secs(
                            rns_transport::discovery::constants::ANNOUNCE_JOB_INTERVAL_SECS,
                        );
                    // The job saw these as unsent; they must not go out again.
                    let mut committed = Vec::new();
                    for (prepared, at) in deferred_commits.drain(..) {
                        if returned.commit(&prepared, at) {
                            committed.push(prepared.request().interface_id);
                        }
                    }
                    announcer = Some(returned);
                    for prepared in prepared {
                        let id = prepared.request().interface_id;
                        if committed.contains(&id) || !locals.iter().any(|local| local.id == id) {
                            continue;
                        }
                        publications.entry(id).or_insert(Publication {
                            prepared,
                            pending: None,
                            last_failure: None,
                            retry_at: now,
                        });
                    }
                }
                Err(error) => {
                    tracing::error!(%error, "discovery announce preparation failed");
                    break;
                }
            }
        }
        for local in &locals {
            let Some(announcer) = announcer.as_mut() else {
                break;
            };
            let online = local
                .online
                .as_ref()
                .is_none_or(|online| online.load(Ordering::Acquire));
            let reachable_on = local
                .reachable_on
                .as_ref()
                .map(|reachable_on| reachable_on.borrow().clone());
            let moved = reachable_on
                .as_ref()
                .is_some_and(|reachable_on| registered.get(&local.id) != Some(reachable_on));
            if online && (!registered.contains_key(&local.id) || moved) {
                let mut config = local.config.clone();
                if let Some(reachable_on) = reachable_on.clone() {
                    config.reachable_on = reachable_on;
                }
                // The runtime picks what is due; the announcer only builds it.
                config.discoverable = false;
                config.announce_interval_secs = 0;
                if registered
                    .insert(local.id, reachable_on.flatten())
                    .is_none()
                {
                    announcer.register(local.id, handle.transport_identity.hash, config);
                } else {
                    // A new address goes out with the next due announce, as
                    // Python announces discovery only on its interval.
                    publications.remove(&local.id);
                    announcer.reconfigure(local.id, config);
                }
            }
        }
        if now >= next_prepare && announcer.is_some() {
            next_prepare = now
                + Duration::from_secs(
                    rns_transport::discovery::constants::ANNOUNCE_JOB_INTERVAL_SECS,
                );
            // Python announces only the most overdue due interface per pass.
            let selected = locals
                .iter()
                .filter(|local| registered.contains_key(&local.id))
                .filter(|local| {
                    last_announce.get(&local.id).is_none_or(|last| {
                        now.duration_since(*last).as_secs_f64()
                            > local.config.announce_interval_secs as f64
                    })
                })
                // First of the most overdue, as Python's stable sort keeps.
                .min_by_key(|local| {
                    std::cmp::Reverse(
                        last_announce
                            .get(&local.id)
                            .map_or(Duration::MAX, |last| now.duration_since(*last)),
                    )
                });
            if let Some(local) = selected {
                last_announce.insert(local.id, now);
                let mut config = local.config.clone();
                if let Some(reachable_on) = &local.reachable_on {
                    config.reachable_on = reachable_on.borrow().clone();
                }
                let resolved = tokio::select! {
                    _ = handle.shutdown.wait() => break,
                    resolved = resolve_discovery_inputs(config, local.location_cmd.as_deref()) => resolved,
                };
                next_prepare = tokio::time::Instant::now()
                    + Duration::from_secs(
                        rns_transport::discovery::constants::ANNOUNCE_JOB_INTERVAL_SECS,
                    );
                if let (Some(mut config), Some(mut owned)) = (resolved, announcer.take()) {
                    for other in &locals {
                        if other.id != local.id && registered.contains_key(&other.id) {
                            let mut idle = other.config.clone();
                            if let Some(reachable_on) = &other.reachable_on {
                                idle.reachable_on = reachable_on.borrow().clone();
                            }
                            idle.discoverable = false;
                            idle.announce_interval_secs = 0;
                            owned.reconfigure(other.id, idle);
                        }
                    }
                    config.discoverable = true;
                    config.announce_interval_secs = 0;
                    owned.reconfigure(local.id, config);
                    let network_identity = handle.network_identity.clone();
                    preparing = Some(tokio::task::spawn_blocking(move || {
                        let encrypt = |plaintext: &[u8]| {
                            network_identity
                                .as_ref()
                                .and_then(|identity| identity.encrypt(plaintext, None).ok())
                        };
                        let (prepared, _) = owned.prepare(unix_now(), Some(&encrypt));
                        (owned, prepared)
                    }));
                } else {
                    tracing::error!(
                        interface_id = local.id,
                        "Could not generate interface discovery announce data"
                    );
                }
            }
        }
        let mut admitted = Vec::new();
        for local in &locals {
            let Some(publication) = publications.get_mut(&local.id) else {
                continue;
            };
            let online = local
                .online
                .as_ref()
                .is_none_or(|online| online.load(Ordering::Acquire));
            if let Some(pending) = publication.pending.as_mut() {
                match pending.try_recv() {
                    Ok(AnnounceDispatchResult::Admitted) => {
                        match announcer.as_mut() {
                            Some(announcer) => {
                                announcer.commit(&publication.prepared, unix_now());
                            }
                            None => {
                                deferred_commits.push((publication.prepared.clone(), unix_now()))
                            }
                        }
                        admitted.push(local.id);
                        continue;
                    }
                    Ok(result) => {
                        if publication.last_failure != Some(result) {
                            tracing::debug!(
                                interface_id = local.id,
                                ?result,
                                "discovery publication not admitted"
                            );
                            publication.last_failure = Some(result);
                        }
                        publication.pending = None;
                    }
                    Err(oneshot::error::TryRecvError::Empty) => {
                        if !online {
                            // Recall unadmitted work for a service that went
                            // offline. Preserve its prepared payload for recovery;
                            // an already reported admission was handled above.
                            publication.pending = None;
                        }
                        continue;
                    }
                    Err(_) => {
                        publication.pending = None;
                    }
                }
            }
            if !online || now < publication.retry_at {
                continue;
            }
            if let Some(outcome) = discovery_stamps.try_recv() {
                discovery_stamps.complete(&mut discovery_destination, announce_identity, outcome);
            }
            // Wait for the destination stamp on later ticks without blocking the loop.
            let stamp_ext = match discovery_stamps.admit(
                &discovery_destination,
                announce_identity,
                false,
                (),
            ) {
                crate::destination_stamper::Admission::Ready((), ext) => ext,
                crate::destination_stamper::Admission::Queued
                | crate::destination_stamper::Admission::Dropped(()) => continue,
            };
            let request = publication.prepared.request();
            let wire_now = unix_now();
            match rns_identity::destination::AnnounceTime::new(wire_now as u64, wire_now).and_then(
                |time| {
                    discovery_destination.announce_packet_with_ext_at(
                        announce_identity,
                        Some(&request.app_data),
                        None,
                        false,
                        None,
                        time,
                        stamp_ext.as_ref(),
                    )
                },
            ) {
                Ok(raw) => {
                    // A full admission lane is retried on the next bounded
                    // tick without repeating proof-of-work or logging each poll.
                    if let Ok(pending) = handle.announce_dispatch.try_dispatch(
                        Bytes::from(raw),
                        None,
                        Duration::from_secs(120),
                    ) {
                        publication.pending = Some(pending);
                    }
                }
                Err(error) => {
                    tracing::warn!(%error, "failed to build discovery announce");
                    publication.retry_at = now
                        + Duration::from_secs(
                            rns_transport::discovery::constants::ANNOUNCE_JOB_INTERVAL_SECS,
                        );
                }
            }
        }
        for id in admitted {
            publications.remove(&id);
        }
    }
    drop(cancel_generation);
    if let Some(job) = preparing {
        let _ = job.await;
    }
    // Stop unacknowledged dispatch before retiring its local destination.
    drop(publications);
    if let Err(error) = registration.close().await {
        tracing::debug!(%error, "discovery destination close failed");
    }
}

/// Evaluate executable `reachable_on` and `location_cmd` values and validate
/// the address before an announce, as Python does; `None` aborts this
/// announce (Discovery.py).
async fn resolve_discovery_inputs(
    mut config: DiscoveryInterfaceConfig,
    location_cmd: Option<&str>,
) -> Option<DiscoveryInterfaceConfig> {
    let sanitize = |value: &str| value.replace(['\n', '\r'], "").trim().to_string();
    #[cfg(unix)]
    if let Some(location_cmd) = location_cmd {
        let path = expand_home_path(&sanitize(location_cmd));
        if is_executable_file(&path) {
            tracing::debug!(path = %path.display(), "Evaluating discovery location from executable");
            match run_discovery_command(&path)
                .await
                .and_then(|output| parse_discovery_location(&sanitize(&output)))
            {
                Ok((lat, lon, height)) => {
                    config.latitude = Some(lat);
                    config.longitude = Some(lon);
                    config.height = Some(height);
                }
                Err(error) => {
                    tracing::error!(%error, "Error while getting discovery location from executable, aborting discovery announce");
                    return None;
                }
            }
        }
    }
    #[cfg(not(unix))]
    let _ = location_cmd;

    if matches!(
        config.interface_type.as_str(),
        "BackboneInterface" | "TCPServerInterface"
    ) {
        #[cfg_attr(not(unix), allow(unused_mut))]
        let mut reachable_on = sanitize(config.reachable_on.as_deref()?);
        #[cfg(unix)]
        {
            let path = expand_home_path(&reachable_on);
            if is_executable_file(&path) {
                tracing::debug!(path = %path.display(), "Evaluating reachable_on from executable");
                match run_discovery_command(&path).await {
                    Ok(output) => reachable_on = sanitize(&output),
                    Err(error) => {
                        tracing::error!(%error, "Error while getting reachable_on from executable, aborting discovery announce");
                        return None;
                    }
                }
            }
        }
        if !(is_ip_address(&reachable_on) || is_hostname(&reachable_on)) {
            tracing::error!(
                "The configured reachable_on parameter \"{reachable_on}\" is not a valid IP address or hostname, aborting discovery announce"
            );
            return None;
        }
        config.reachable_on = Some(reachable_on);
    }
    Some(config)
}

/// Python's `lat,lon,height` checks for `location_cmd` output
/// (Discovery.py).
// Plain comparisons let NaN through, as upstream's do.
#[allow(clippy::manual_range_contains)]
#[cfg_attr(not(unix), allow(dead_code))]
fn parse_discovery_location(output: &str) -> Result<(f64, f64, f64), String> {
    let output = output.replace(' ', "");
    let parts: Vec<&str> = output.split(',').collect();
    if parts.len() != 3 {
        return Err(format!("Invalid location component count: {}", parts.len()));
    }
    let number = |part: &str| {
        part.parse::<f64>()
            .map_err(|_| format!("could not convert string to float: '{part}'"))
    };
    let (lat, lon, height) = (number(parts[0])?, number(parts[1])?, number(parts[2])?);
    if lat < -90.0 || lat > 90.0 {
        return Err(format!("Invalid latitude: {lat}"));
    }
    // Upstream tests the latitude, not the longitude, against 180.
    if lon < -180.0 || lat > 180.0 {
        return Err(format!("Invalid longitude: {lon}"));
    }
    if height < -4000.0 || height > 1e6 {
        return Err(format!("Invalid height: {height}"));
    }
    Ok((lat, lon, height))
}

#[cfg(unix)]
fn is_executable_file(path: &Path) -> bool {
    path.is_file() && nix::unistd::access(path, nix::unistd::AccessFlags::X_OK).is_ok()
}

#[cfg(unix)]
async fn run_discovery_command(path: &Path) -> Result<String, String> {
    let output = tokio::process::Command::new(path)
        .stderr(std::process::Stdio::inherit())
        .output()
        .await
        .map_err(|error| error.to_string())?;
    let stdout = String::from_utf8(output.stdout).map_err(|error| error.to_string())?;
    if !output.status.success() {
        return Err("Non-zero exit code from subprocess".to_string());
    }
    Ok(stdout)
}

/// Python's `is_ip_address` (Discovery.py).
fn is_ip_address(value: &str) -> bool {
    value.parse::<std::net::IpAddr>().is_ok()
}

/// Python's `is_hostname` (Discovery.py).
fn is_hostname(hostname: &str) -> bool {
    let hostname = hostname.strip_suffix('.').unwrap_or(hostname);
    if hostname.len() > 253 {
        return false;
    }
    let last = hostname.rsplit('.').next().unwrap_or_default();
    if !last.is_empty() && last.bytes().all(|b| b.is_ascii_digit()) {
        return false;
    }
    hostname.split('.').all(|label| {
        (1..=63).contains(&label.len())
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
            && !label.starts_with('-')
            && !label.ends_with('-')
    })
}

/// Python's `connect_discovered` (Discovery.py): one pass over the
/// stored transport records, then each new discovery.
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
        let blackholed = handle.blackholed_identity_set().await;
        for record in store
            .list_filtered(sources, &blackholed)
            .unwrap_or_default()
        {
            if !record.info.transport_enabled {
                continue;
            }
            if handle.discovery.autoconnected.lock().await.len()
                >= handle.config.autoconnect_discovered_interfaces
            {
                break;
            }
            maybe_autoconnect_discovered(&handle, record).await;
        }
    }
    handle
        .discovery
        .initial_autoconnect_ran
        .store(true, Ordering::Release);

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
    if limit == 0
        || handle.discovery.autoconnected.lock().await.len() >= limit
        || !autoconnect_admits(&record, &handle.config)
        || !autoconnect_costs_acceptable(&record, &handle.config.stamps)
    {
        return;
    }
    let Some(host) = record.info.reachable_on.clone() else {
        return;
    };
    let Some(port) = record.info.port else {
        return;
    };
    if discovered_endpoint_exists(handle, &host, port).await {
        tracing::debug!(endpoint = %format!("{host}:{port}"), "discovered interface already exists, not auto-connecting");
        return;
    }
    if is_yggdrasil_ipv6(&host) {
        tracing::debug!(host = %host, "skipping Yggdrasil IPv6 discovery autoconnect");
        return;
    }
    if refused_autoconnect_host(&host) {
        tracing::debug!(host = %host, "not auto-connecting a discovered onion or local address");
        return;
    }

    let _autoconnecting = handle.discovery.autoconnect_lock.lock().await;
    if discovered_endpoint_exists(handle, &host, port).await {
        return;
    }
    // Python's `endpoint_hash` (Discovery.py).
    let key = rns_crypto::sha::sha256(format!("{host}:{port}").as_bytes());
    {
        let mut connected = handle.discovery.autoconnected.lock().await;
        if connected.contains_key(&key) || connected.len() >= limit {
            return;
        }
        connected.insert(
            key,
            AutoconnectedInterface {
                id: None,
                online: None,
                down_since: None,
            },
        );
    }

    let name = autoconnect_interface_name(handle, &record.info.name).await;
    match spawn_discovered_backbone_client(handle, &record, &name, &host, port).await {
        Ok((id, online)) => {
            if let Some(entry) = handle.discovery.autoconnected.lock().await.get_mut(&key) {
                entry.id = Some(id);
                entry.online = Some(online);
            }
            if !handle
                .discovery
                .autoconnect_monitor_started
                .swap(true, Ordering::AcqRel)
            {
                tokio::spawn(run_autoconnect_monitor(handle.clone()));
            }
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

/// Auto-connects only Backbone interfaces of a transport node running a
/// trusted stack and release (Python's, plus rsRNS), unless unverified stacks
/// are allowed; the transport requirement holds either way (Discovery.py).
fn autoconnect_admits(record: &DiscoveredInterface, config: &ReticulumConfig) -> bool {
    let admitted = rns_transport::discovery::autoconnect::qualifies(
        &record.info,
        config.autoconnect_unverified_implementations,
    );
    if !admitted {
        tracing::debug!(
            name = %record.info.name,
            interface_type = %record.info.interface_type,
            implementation = ?record.info.impl_name,
            version = ?record.info.impl_version,
            "not auto-connecting discovered interface, auto-connect criteria not satisfied"
        );
    }
    admitted
}

/// Older nodes published the literal "None"; like an empty value it sets no credential.
fn discovered_ifac_value(value: &Option<String>) -> Option<String> {
    value
        .as_deref()
        .filter(|v| !v.is_empty() && *v != "None")
        .map(str::to_string)
}

/// Python refuses an interface whose advertised costs exceed the stamp values
/// this node generates (Discovery.py).
fn autoconnect_costs_acceptable(
    record: &DiscoveredInterface,
    stamps: &rns_transport::stamps::StampPolicy,
) -> bool {
    let quantize = |cost: f64| rns_identity::stamps::quantize_cost(cost).unwrap_or(0.0);
    let dst_value = quantize(stamps.destination_value);
    let pr_value = quantize(stamps.pr_value);
    let dst_cost = quantize(record.info.dst_cost.unwrap_or(0.0));
    let pr_cost = quantize(record.info.pr_cost.unwrap_or(0.0));
    if dst_cost > dst_value {
        tracing::debug!(
            name = %record.info.name,
            "Destination cost {dst_cost} higher than configured value {dst_value}, not auto-connecting"
        );
    }
    if pr_cost > pr_value {
        tracing::debug!(
            name = %record.info.name,
            "Path request cost {pr_cost} higher than configured value {pr_value}, not auto-connecting"
        );
    }
    dst_cost <= dst_value && pr_cost <= pr_value
}

/// Python's `autoconnect_interface_name` (Discovery.py).
async fn autoconnect_interface_name(handle: &ReticulumHandle, name: &str) -> String {
    let names: std::collections::HashSet<String> = match handle
        .query_transport(TransportQuery::GetInterfaceStats)
        .await
    {
        Some(TransportQueryResponse::InterfaceStats(entries)) => {
            entries.into_iter().map(|entry| entry.name).collect()
        }
        _ => Default::default(),
    };
    let chosen = unique_interface_name(&names, name);
    if chosen != name {
        tracing::info!("Auto-connect name collision for \"{name}\", connecting as \"{chosen}\"");
    }
    chosen
}

fn unique_interface_name(names: &std::collections::HashSet<String>, name: &str) -> String {
    if !names.contains(name) {
        return name.to_string();
    }
    (2..)
        .map(|n| format!("{name} ({n})"))
        .find(|candidate| !names.contains(candidate))
        .expect("an unused suffix exists")
}

async fn spawn_discovered_backbone_client(
    handle: &ReticulumHandle,
    record: &DiscoveredInterface,
    name: &str,
    host: &str,
    port: u16,
) -> Result<(u64, Arc<AtomicBool>), String> {
    let spawn_permit = ensure_runtime_interface_admission(handle)?;
    let id = next_id(&handle.id_gen);
    let mut config = rns_interface::backbone::BackboneClientConfig::new(name, host, port);
    config.mode = discovered_backbone_client_mode(&handle.config);
    config.tunnel_identity = Some(rns_interface::traits::TunnelIdentity(
        handle.transport_identity.clone(),
    ));
    // Discovery.py adds the interface with configured_bitrate=5E6.
    config.bitrate = 5_000_000;
    let spawned = rns_interface::backbone::spawn_backbone_client_observed(
        config,
        id,
        handle.transport_tx.clone(),
    )
    .await
    .map_err(|e| format!("Backbone client spawn failed: {e}"))?;
    let iface_handle = spawned.interface;
    let online = iface_handle.online.clone();

    let mut post_init =
        interface_factory::InterfacePostInit::try_from_section(&ConfigSection::new())
            .expect("empty interface defaults are valid")
            .with_default_ifac_size(16);
    finalize_post_init(&mut post_init, &handle.config);
    // Python's `configured_bitrate=5E6` (Discovery.py).
    post_init.bitrate = Some(5_000_000);
    // Discovery.py: autoconnect_interface_gravity, else AC_GRAVITY (0).
    post_init.gravity = Some(handle.config.autoconnect_interface_gravity.unwrap_or(0));
    // Discovery.py: True when configured, otherwise None.
    post_init.announces_to_internal = handle.config.autoconnect_announces_to_internal;
    post_init.ifac_network_name = discovered_ifac_value(&record.info.ifac_netname);
    post_init.ifac_passphrase =
        discovered_ifac_value(&record.info.ifac_netkey).map(zeroize::Zeroizing::new);
    post_init.autoconnect_source = Some(hex::encode(record.network_id));
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
    record_client_target(&handle.interface_controls, id, host, port);
    watch_runtime_client_teardown(handle, name, spawned.teardown);
    rns_transport::notice!(name = %name, id, endpoint = %format!("{host}:{port}"), "auto-connected discovered interface");
    Ok((id, online))
}

/// Python's `__monitor_job` (Discovery.py): detach interfaces that
/// stay down, forget ones detached elsewhere, trade bootstrap interfaces for
/// online auto-connected ones and refill free slots.
async fn run_autoconnect_monitor(handle: ReticulumHandle) {
    let interval = Duration::from_secs(rns_transport::discovery::constants::MONITOR_INTERVAL_SECS);
    loop {
        tokio::select! {
            _ = handle.shutdown.wait() => break,
            _ = tokio::time::sleep(interval) => {}
        }
        if !handle.interface_registry.is_open() {
            break;
        }
        autoconnect_monitor_tick(&handle).await;
    }
}

async fn autoconnect_monitor_tick(handle: &ReticulumHandle) {
    // Upstream DETACH_THRESHOLD is in seconds (Discovery.py).
    let threshold =
        Duration::from_secs(rns_transport::discovery::constants::DETACH_THRESHOLD_TICKS);
    let limit = handle.config.autoconnect_discovered_interfaces;
    let registered: std::collections::HashSet<u64> = handle
        .interface_controls
        .lock()
        .expect("interface_controls mutex poisoned")
        .keys()
        .copied()
        .collect();
    let mut detached = Vec::new();
    let mut online = 0;
    let autoconnected_count = {
        let now = std::time::Instant::now();
        let mut connected = handle.discovery.autoconnected.lock().await;
        for (key, entry) in connected.iter_mut() {
            let Some(id) = entry.id else {
                continue;
            };
            if !registered.contains(&id) {
                tracing::debug!(
                    "A monitored auto-connected interface was manually detached, removing from monitoring"
                );
                detached.push((*key, None));
            } else if entry
                .online
                .as_ref()
                .is_none_or(|flag| flag.load(Ordering::Acquire))
            {
                online += 1;
                if entry.down_since.take().is_some() {
                    tracing::info!(id, "Auto-discovered interface reconnected");
                }
            } else if let Some(since) = entry.down_since {
                if now.duration_since(since) >= threshold {
                    tracing::debug!(
                        id,
                        "Auto-discovered interface has been down too long, detaching"
                    );
                    detached.push((*key, Some(id)));
                }
            } else {
                tracing::debug!(id, "Auto-discovered interface disconnected");
                entry.down_since = Some(now);
            }
        }
        connected.len()
    };

    let free_slots = limit.saturating_sub(autoconnected_count);
    let reserved_slots = limit / 4;
    let bootstrap: Vec<u64> = handle
        .discovery
        .bootstrap_interfaces
        .lock()
        .await
        .iter()
        .copied()
        .filter(|id| registered.contains(id))
        .collect();
    let teardown_bootstrap = online >= limit;
    if teardown_bootstrap && !bootstrap.is_empty() {
        tracing::info!(
            "Tearing down bootstrap-only interfaces since target connected auto-discovered interface count has been reached"
        );
    }
    if online == 0
        && bootstrap.is_empty()
        && !handle.discovery.i2p_bootstrap.load(Ordering::Acquire)
    {
        respawn_bootstrap_interfaces(handle).await;
    }

    if handle
        .discovery
        .initial_autoconnect_ran
        .load(Ordering::Acquire)
        && free_slots > reserved_slots
        && let Some(store) = handle.discovery.store.lock().await.clone()
    {
        let sources = (!handle.config.interface_discovery_sources.is_empty())
            .then_some(handle.config.interface_discovery_sources.as_slice());
        let blackholed = handle.blackholed_identity_set().await;
        let candidates: Vec<DiscoveredInterface> = store
            .list_filtered(sources, &blackholed)
            .unwrap_or_default()
            .into_iter()
            .filter(|record| {
                record.info.transport_enabled
                    && record.status == Some(rns_transport::discovery::DiscoveryStatus::Available)
            })
            .collect();
        if !candidates.is_empty() {
            let mut random = [0u8; 8];
            random.copy_from_slice(&rns_crypto::random::random_bytes(8));
            let pick = (u64::from_le_bytes(random) % candidates.len() as u64) as usize;
            let selected = candidates.into_iter().nth(pick).expect("index in range");
            autoconnect_from_monitor(handle, selected).await;
        }
    }

    for (key, id) in detached {
        if let Some(id) = id {
            teardown_interface(handle, id).await;
        }
        handle.discovery.autoconnected.lock().await.remove(&key);
    }
    if teardown_bootstrap && !bootstrap.is_empty() {
        handle
            .discovery
            .bootstrap_interfaces
            .lock()
            .await
            .retain(|id| !bootstrap.contains(id));
        for id in bootstrap {
            teardown_interface(handle, id).await;
        }
    }
}

// Boxed to break the type cycle with the monitor that auto-connecting starts.
fn autoconnect_from_monitor(
    handle: &ReticulumHandle,
    record: DiscoveredInterface,
) -> std::pin::Pin<Box<dyn Future<Output = ()> + Send + '_>> {
    Box::pin(maybe_autoconnect_discovered(handle, record))
}

/// Python re-synthesizes every bootstrap-only interface config once no
/// auto-connected interface is online (Discovery.py).
async fn respawn_bootstrap_interfaces(handle: &ReticulumHandle) {
    let configs: Vec<(
        interface_factory::InterfaceConfig,
        interface_factory::InterfacePostInit,
    )> = handle
        .discovery
        .bootstrap_configs
        .lock()
        .await
        .iter()
        .map(|bootstrap| {
            (
                bootstrap.config.clone(),
                clone_interface_post_init(&bootstrap.post_init),
            )
        })
        .collect();
    if configs.is_empty() {
        return;
    }
    tracing::info!("No auto-discovered interfaces connected, re-enabling bootstrap interfaces");
    for (config, post_init) in configs {
        match spawn_configured_interface(handle, &config, &post_init).await {
            Ok(ids) => handle
                .discovery
                .bootstrap_interfaces
                .lock()
                .await
                .extend(ids),
            Err(error) => tracing::warn!(
                interface = %interface_config_name(&config),
                %error,
                "failed to re-enable bootstrap interface"
            ),
        }
    }
}

/// Spawn and register an interface from its configuration after startup.
async fn spawn_configured_interface(
    handle: &ReticulumHandle,
    config: &interface_factory::InterfaceConfig,
    post_init: &interface_factory::InterfacePostInit,
) -> Result<Vec<u64>, String> {
    spawn_configured_interface_for_discovery(handle, config, post_init)
        .await
        .map(|spawned| spawned.into_iter().map(|(id, _, _)| id).collect())
}

/// Each registered id with its online flag and runtime-learned address.
type SpawnedForDiscovery = Vec<(
    u64,
    Arc<AtomicBool>,
    Option<tokio::sync::watch::Receiver<Option<String>>>,
)>;

async fn spawn_configured_interface_for_discovery(
    handle: &ReticulumHandle,
    config: &interface_factory::InterfaceConfig,
    post_init: &interface_factory::InterfacePostInit,
) -> Result<SpawnedForDiscovery, String> {
    let spawn_permit = ensure_runtime_interface_admission(handle)?;
    let (id, further_ids) = reserve_interface_ids(config, &handle.id_gen);
    let storage_dir = StoragePaths::from_config_dir(&handle.config_dir).storage_dir;
    let tunnel_identity = rns_interface::traits::TunnelIdentity(handle.transport_identity.clone());
    let handles = spawn_interface_with_rnode_startup_options(
        config,
        id,
        &further_ids,
        handle.transport_tx.clone(),
        handle.id_gen.clone(),
        handle.handle_tx.clone(),
        &handle.socket_base,
        &storage_dir,
        handle.is_foreground.clone(),
        Default::default(),
        &tunnel_identity,
    )
    .await?;
    let mut handles = handles;
    apply_configured_bitrate_mtu(config, post_init, &mut handles);
    let mut discovery: HashMap<_, _> = handles
        .iter()
        .map(|owned| {
            (
                owned.interface.id,
                (
                    owned.interface.online.clone(),
                    owned.discovery_address.clone(),
                ),
            )
        })
        .collect();
    let ids = register_interfaces_with_post_init_batch(
        &handle.transport_tx,
        handles,
        post_init,
        derive_ifac_key_from_post_init(post_init),
        &handle.interface_controls,
        &handle.interface_registry,
        interface_kind_for_config(config),
        Some(spawn_permit),
    )
    .await
    .map_err(|error| error.to_string())?;
    if let Some((host, port)) = configured_client_target(config) {
        for &id in &ids {
            record_client_target(&handle.interface_controls, id, &host, port);
        }
    }
    Ok(ids
        .into_iter()
        .filter_map(|id| {
            let (online, address) = discovery.remove(&id)?;
            Some((id, online, address))
        })
        .collect())
}

/// Synthesize and start one interface section after startup, as the startup
/// loop does for each enabled section.
async fn attach_interface_section(
    handle: &ReticulumHandle,
    config: &Config,
    name: &str,
    section: &ConfigSection,
) -> Result<Vec<u64>, String> {
    interface_factory::validate_stamp_costs(name, section).map_err(|e| e.to_string())?;
    let mut iface_config =
        interface_factory::synthesize_interface(name, section).map_err(|e| e.to_string())?;
    apply_discovery_mode_autocorrect(config, &mut iface_config);
    let mut post_init =
        get_post_init_for_config(config, &iface_config).map_err(|e| e.to_string())?;
    finalize_post_init(&mut post_init, &handle.config);
    interface_factory::validate_config_capacity(&iface_config, &post_init)
        .map_err(|e| e.to_string())?;
    let discovery_config = discovery_config_for_interface(
        config,
        &iface_config,
        &post_init,
        handle.config.enable_transport,
        &handle.config.stamps,
    )
    .map_err(|e| e.to_string())?;
    let spawned =
        spawn_configured_interface_for_discovery(handle, &iface_config, &post_init).await?;
    if let Some(discovery_config) = discovery_config {
        // As at startup, an I2P interface is announced itself, never its peers.
        let announced = match iface_config {
            interface_factory::InterfaceConfig::I2P(_) => &spawned[..spawned.len().min(1)],
            _ => &spawned[..],
        };
        let location_cmd = section.get("location_cmd").map(ToString::to_string);
        handle
            .discovery
            .local_interfaces
            .lock()
            .await
            .extend(
                announced
                    .iter()
                    .map(|(id, online, address)| LocalDiscoveryInterface {
                        id: *id,
                        config: discovery_config.clone(),
                        online: Some(online.clone()),
                        reachable_on: address.clone(),
                        location_cmd: location_cmd.clone(),
                    }),
            );
    }
    let ids: Vec<u64> = spawned.into_iter().map(|(id, _, _)| id).collect();
    // Python never detaches an I2PInterface (Reticulum.py).
    if interface_bootstrap_only(config, &iface_config)
        && !matches!(iface_config, interface_factory::InterfaceConfig::I2P(_))
    {
        handle
            .discovery
            .bootstrap_interfaces
            .lock()
            .await
            .extend(&ids);
    }
    Ok(ids)
}

/// Python's `interface_exists` (Discovery.py): a client interface
/// already aimed at this host and port, or an I2P interface at this address.
async fn discovered_endpoint_exists(handle: &ReticulumHandle, host: &str, port: u16) -> bool {
    let aimed = handle
        .interface_controls
        .lock()
        .expect("interface_controls mutex poisoned")
        .values()
        .any(|control| {
            control
                .client_target
                .as_ref()
                .is_some_and(|(target_host, target_port)| {
                    target_host == host && *target_port == port
                })
        });
    aimed
        || handle
            .discovery
            .local_interfaces
            .lock()
            .await
            .iter()
            .filter_map(|local| local.reachable_on.as_ref())
            .any(|b32| b32.borrow().as_deref() == Some(host))
}

/// Python never auto-connects to an onion address, nor to the literal
/// addresses 127.0.0.1 and 0.0.0.0 (Discovery.py).
fn refused_autoconnect_host(host: &str) -> bool {
    host.to_lowercase().ends_with(".onion") || ["127.0.0.1", "0.0.0.0"].contains(&host)
}

/// The host and port a configured client interface connects to.
fn configured_client_target(config: &interface_factory::InterfaceConfig) -> Option<(String, u16)> {
    match config {
        interface_factory::InterfaceConfig::TcpClient(c) => {
            Some((c.target_host.clone(), c.target_port))
        }
        interface_factory::InterfaceConfig::Backbone(c) => {
            c.target_host.clone().map(|host| (host, c.port))
        }
        _ => None,
    }
}

/// Record where a client interface connects, which Python keeps as its
/// `target_ip` and `target_port`.
fn record_client_target(controls: &InterfaceControlMap, id: u64, host: &str, port: u16) {
    update_interface_control(controls, id, |control| {
        control.client_target = Some((host.to_string(), port));
    });
}

fn update_interface_control(
    controls: &InterfaceControlMap,
    id: u64,
    update: impl FnOnce(&mut InterfaceControlMetadata),
) {
    if let Some(control) = controls
        .lock()
        .expect("interface_controls mutex poisoned")
        .get_mut(&id)
    {
        update(control);
    }
}

fn is_yggdrasil_ipv6(host: &str) -> bool {
    let Ok(std::net::IpAddr::V6(addr)) = host.parse() else {
        return false;
    };
    let first = addr.octets()[0];
    first == 0x02 || first == 0x03
}

/// Link-request cost of the blackhole list destination.
pub const BLACKHOLE_LINK_COST: f64 = 5.25;

async fn start_blackhole_publisher(
    handle: &ReticulumHandle,
) -> Result<([u8; 16], ManagementAnnounce), String> {
    let identity = handle.transport_identity.clone();
    let signing_key = identity
        .get_signing_key()
        .ok_or_else(|| "No signing key available for blackhole publisher".to_string())?;
    let app_name = rns_transport::discovery::constants::BLACKHOLE_ASPECT_FILTER;
    let dest_hash = rns_identity::destination::Destination::hash_from_name_and_identity(
        app_name,
        Some(&identity.hash),
    );
    let (event_rx, announce) =
        register_management_destination(&handle.transport_tx, dest_hash, app_name);
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

    // Transport.py
    if let Some(destination) = lm.destination_mut() {
        destination.set_link_cost(BLACKHOLE_LINK_COST);
    }
    let (command_tx, command_rx) = mpsc::channel(8);
    let shutdown = handle.shutdown.clone();
    tokio::spawn(async move {
        shutdown.wait().await;
        drop(command_tx);
    });
    tokio::spawn(async move {
        lm.run_with_commands(command_rx).await;
    });

    Ok((dest_hash, announce))
}

/// Interval between management announces (Transport.py).
const MGMT_ANNOUNCE_INTERVAL: Duration =
    Duration::from_secs(rns_transport::constants::MGMT_ANNOUNCE_INTERVAL as u64);
/// Delay before the first management announce (Transport.py).
const MGMT_ANNOUNCE_FIRST_DELAY: Duration = Duration::from_secs(15);

/// Asks one of the transport's management destinations to announce itself.
#[derive(Clone)]
pub(crate) struct ManagementAnnounce {
    // Weak, so the destination's event channel still closes with transport.
    delivery_tx: mpsc::WeakSender<rns_transport::link_messages::DestinationEvent>,
    app_name: String,
}

impl ManagementAnnounce {
    pub(crate) fn new(
        delivery_tx: &mpsc::Sender<rns_transport::link_messages::DestinationEvent>,
        app_name: &str,
    ) -> Self {
        Self {
            delivery_tx: delivery_tx.downgrade(),
            app_name: app_name.to_string(),
        }
    }

    fn announce(&self) {
        let Some(delivery_tx) = self.delivery_tx.upgrade() else {
            return;
        };
        let request = rns_transport::link_messages::AnnounceRequest::normal(self.app_name.clone());
        if let Err(e) = delivery_tx
            .try_send(rns_transport::link_messages::DestinationEvent::AnnounceRequested(request))
        {
            tracing::warn!(app_name = %self.app_name, error = %e, "management announce not sent");
        }
    }
}

/// Register a management destination with transport, keeping a handle that
/// can ask it to announce.
pub(crate) fn register_management_destination(
    transport_tx: &mpsc::Sender<TransportMessage>,
    dest_hash: [u8; 16],
    app_name: &str,
) -> (
    mpsc::Receiver<rns_transport::link_messages::DestinationEvent>,
    ManagementAnnounce,
) {
    let (tx, rx) = mpsc::channel(256);
    if let Err(e) = transport_tx.try_send(TransportMessage::RegisterDestination {
        hash: dest_hash,
        app_name: app_name.to_string(),
        delivery_tx: Some(tx.clone()),
    }) {
        tracing::warn!(dest = hex::encode(dest_hash), err = %e,
            "failed to register management destination with transport");
    }
    (rx, ManagementAnnounce::new(&tx, app_name))
}

/// The `rnstransport.network.instance.<hash>` and `rnstransport.network`
/// destinations on the network identity (Transport.py).
fn start_network_destinations(
    transport_tx: &mpsc::Sender<TransportMessage>,
    network_identity: &Identity,
) -> Vec<ManagementAnnounce> {
    let instance_name = format!(
        "rnstransport.network.instance.{}",
        hex::encode(network_identity.hash)
    );
    let mut announces = Vec::new();
    for app_name in [instance_name.as_str(), "rnstransport.network"] {
        let dest_hash = rns_identity::destination::Destination::hash_from_name_and_identity(
            app_name,
            Some(&network_identity.hash),
        );
        let (event_rx, announce) =
            register_management_destination(transport_tx, dest_hash, app_name);
        let lm = LinkManager::with_destination(
            transport_tx.clone(),
            event_rx,
            network_identity,
            app_name,
            network_identity.get_signing_key(),
        );
        tokio::spawn(lm.run());
        announces.push(announce);
    }
    announces
}

/// Announce every management destination 15 s after start and then every
/// two hours (Transport.py).
async fn run_management_announcer(destinations: Vec<ManagementAnnounce>, shutdown: ShutdownSignal) {
    let mut wait = MGMT_ANNOUNCE_FIRST_DELAY;
    loop {
        tokio::select! {
            _ = shutdown.wait() => return,
            _ = tokio::time::sleep(wait) => {}
        }
        for destination in &destinations {
            destination.announce();
        }
        wait = MGMT_ANNOUNCE_INTERVAL;
    }
}

async fn start_blackhole_subscriber(handle: ReticulumHandle) {
    let mut started = handle.discovery.subscriber_started.lock().await;
    if *started {
        return;
    }
    *started = true;
    drop(started);
    // BlackholeUpdater.start registers its announce type (Discovery.py).
    handle
        .wants_destination_type("rnstransport.info.blackhole")
        .await;

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
                let destination_hash =
                    rns_identity::destination::Destination::hash_from_name_and_identity(
                        rns_transport::discovery::constants::BLACKHOLE_ASPECT_FILTER,
                        Some(&source_hash),
                    );
                // Discovery.py: without a path, retry on the next job
                // run; once a path exists the source waits a full interval.
                if handle
                    .await_path(
                        destination_hash,
                        Duration::from_secs_f64(rns_transport::constants::PATH_REQUEST_TIMEOUT),
                    )
                    .await
                    .is_err()
                {
                    tracing::debug!(
                        source = %hex::encode(source_hash),
                        "no path for blackhole list update, retrying later"
                    );
                    continue;
                }
                state.mark_updated(source, unix_now());
                match client
                    .query(
                        source_hash,
                        rns_transport::discovery::constants::BLACKHOLE_ASPECT_FILTER,
                        "/list",
                        Vec::new(),
                        8,
                        BLACKHOLE_SOURCE_TIMEOUT,
                    )
                    .await
                {
                    Ok(payload) => {
                        match handle
                            .query_transport(TransportQuery::ApplyBlackholeManifest {
                                publisher: source_hash,
                                payload,
                            })
                            .await
                        {
                            Some(TransportQueryResponse::IntResult(added)) => {
                                tracing::debug!(
                                    source = %hex::encode(source_hash),
                                    added,
                                    "blackhole list update completed"
                                );
                            }
                            Some(TransportQueryResponse::Error(e)) => {
                                tracing::debug!(
                                    source = %hex::encode(source_hash),
                                    error = %e,
                                    "blackhole list reply is not a list"
                                );
                            }
                            _ => {}
                        }
                    }
                    Err(e) => {
                        tracing::debug!(
                            source = %hex::encode(source_hash),
                            error = %e,
                            "blackhole list update failed"
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
    if handle.instance_mode == InstanceMode::Client {
        return Err("interfaces are owned by the existing shared instance; switch to managed mode to add local interfaces".to_string());
    }
    handle
        .interface_registry
        .acquire_spawn_permit()
        .map_err(|_| "runtime is shutting down; interface spawn rejected".to_string())
}

/// Any initiator that gives up panics the instance (TCPInterface.py).
fn watch_runtime_client_teardown(
    handle: &ReticulumHandle,
    name: &str,
    teardown: rns_interface::tcp::ClientTeardown,
) {
    if handle.config.panic_on_interface_error {
        spawn_interface_panic_monitor(
            name.to_string(),
            InterfaceFailureWatch::ClientTeardown(teardown),
            &handle.shutdown_coordinator,
        );
    }
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
    let mut config = rns_interface::tcp::TcpClientConfig::new(name, host, port);
    config.tunnel_identity = Some(rns_interface::traits::TunnelIdentity(
        handle.transport_identity.clone(),
    ));
    if let Some(post_init) = &post_init {
        config.ifac_size = post_init.ifac_size.unwrap_or(post_init.default_ifac_size);
    }
    if let Some(post_init) = &post_init {
        interface_factory::validate_config_capacity(
            &interface_factory::InterfaceConfig::TcpClient(config.clone()),
            post_init,
        )
        .map_err(|e| e.to_string())?;
    }

    let spawned =
        rns_interface::tcp::spawn_tcp_client_observed(config, id, handle.transport_tx.clone())
            .await
            .map_err(|e| format!("TCP client spawn failed: {e}"))?;
    let iface_handle = spawned.interface;

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
    record_client_target(&handle.interface_controls, id, host, port);
    watch_runtime_client_teardown(handle, name, spawned.teardown);
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
    let mut config = rns_interface::tcp::TcpServerConfig::new(name, listen_ip, port);
    if let Some(post_init) = &post_init {
        config.ifac_size = post_init.ifac_size.unwrap_or(post_init.default_ifac_size);
    }
    if let Some(post_init) = &post_init {
        interface_factory::validate_config_capacity(
            &interface_factory::InterfaceConfig::TcpServer(config.clone()),
            post_init,
        )
        .map_err(|e| e.to_string())?;
    }

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
    config.tunnel_identity = Some(rns_interface::traits::TunnelIdentity(
        handle.transport_identity.clone(),
    ));
    if let Some(post_init) = &post_init {
        config.ifac_size = post_init.ifac_size.unwrap_or(post_init.default_ifac_size);
    }

    let spawned = rns_interface::backbone::spawn_backbone_client_observed(
        config,
        id,
        handle.transport_tx.clone(),
    )
    .await
    .map_err(|e| format!("Backbone client spawn failed: {e}"))?;
    let iface_handle = spawned.interface;

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
    record_client_target(
        &handle.interface_controls,
        id,
        runtime_config.host,
        runtime_config.port,
    );
    watch_runtime_client_teardown(handle, runtime_config.name, spawned.teardown);
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
    if let Some(post_init) = &post_init {
        config.ifac_size = post_init.ifac_size.unwrap_or(post_init.default_ifac_size);
    }

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
    /// BLE platform identifier, address or advertised name used by the driver.
    /// This selector is not cryptographic device authentication.
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
    /// Short-term airtime limit in percent (0.0..=100.0). `None` sends no
    /// limit command and does not clear a limit retained on the radio.
    pub st_alock: Option<f64>,
    /// Long-term airtime limit in percent (0.0..=100.0). `None` sends no
    /// limit command and does not clear a limit retained on the radio.
    pub lt_alock: Option<f64>,
    /// Enable KISS flow control.
    pub flow_control: bool,
}

/// Return the interface id and compatibility online flag. This flag alone
/// is not a cross-transport protocol-readiness contract; use the observed
/// variant and [`RNodeRuntimeObserver::await_ready`] when readiness matters.
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
    /// Short-term airtime limit in percent (0.0..=100.0). `None` sends no
    /// limit command and does not clear a limit retained on the radio.
    pub st_alock: Option<f64>,
    /// Long-term airtime limit in percent (0.0..=100.0). `None` sends no
    /// limit command and does not clear a limit retained on the radio.
    pub lt_alock: Option<f64>,
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
    if handle.config.panic_on_interface_error {
        spawn_interface_panic_monitor(
            name.to_string(),
            InterfaceFailureWatch::RNode(state.clone()),
            &handle.shutdown_coordinator,
        );
    }
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

    spawn_ble_rnode_runtime_native_with_config_and_options(
        handle,
        interface_factory::BleRNodeInterfaceConfig {
            name: name.to_string(),
            port: port.to_string(),
            frequency,
            bandwidth,
            spreading_factor,
            coding_rate,
            tx_power,
            mode,
            flow_control,
            st_alock,
            lt_alock,
            id_interval: None,
            id_callsign: None,
            pair_unbonded: false,
        },
        tcp_port,
        rnode_startup_options,
    )
    .await
}

#[cfg(feature = "ble")]
fn native_ble_driver_config(
    source: interface_factory::BleRNodeInterfaceConfig,
) -> Result<rns_interface::ble_rnode::BleRNodeConfig, RNodeRuntimeSpawnError> {
    let name = source.name.clone();
    let mut config = rns_interface::ble_rnode::BleRNodeConfig::new(&source.name, &source.port);
    config.frequency = source.frequency;
    config.bandwidth = source.bandwidth;
    config.spreading_factor = source.spreading_factor;
    config.coding_rate = source.coding_rate;
    config.tx_power = u8::try_from(source.tx_power).map_err(|_| {
        RNodeRuntimeSpawnError::InvalidConfiguration(format!(
            "invalid value for '{name}.txpower': {} is below 0 dBm",
            source.tx_power
        ))
    })?;
    config.mode = source.mode;
    config.st_alock = source.st_alock;
    config.lt_alock = source.lt_alock;
    config.flow_control = source.flow_control;
    config.id_interval = source.id_interval;
    config.id_callsign = source.id_callsign.map(String::into_bytes);
    config.pair_unbonded = source.pair_unbonded;
    config.validate().map_err(|error| {
        RNodeRuntimeSpawnError::InvalidConfiguration(format!(
            "invalid value for '{name}.{}': {error}",
            error.field()
        ))
    })?;
    Ok(config)
}

/// Spawn and register a native-bridge BLE RNode from the lossless typed
/// interface configuration returned by [`ReticulumHandle::deferred_android_ble_rnodes`].
///
/// Kotlin remains the physical GATT owner. This entry point preserves every
/// configured radio, airtime, flow-control, mode, and station-ID field while
/// Rust owns the stable loopback KISS session and Reticulum registration.
#[cfg(feature = "ble")]
pub async fn spawn_ble_rnode_runtime_native_with_config_and_options(
    handle: &ReticulumHandle,
    config: interface_factory::BleRNodeInterfaceConfig,
    tcp_port: u16,
    rnode_startup_options: rns_interface::rnode::RNodeStartupOptions,
) -> Result<SpawnedRNodeRuntime, RNodeRuntimeSpawnError> {
    let spawn_permit = ensure_runtime_interface_admission(handle)
        .map_err(RNodeRuntimeSpawnError::RuntimeAdmission)?;
    let name = config.name.clone();
    let config = native_ble_driver_config(config)?;

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
        handle.id_gen.clone(),
        handle.transport_tx.clone(),
        handle.handle_tx.clone(),
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

/// Spawn AutoInterface with Link scope, Temporary multicast address type,
/// no explicit NIC allow-list, and the default 10 Mbps bitrate estimate.
/// Platform NIC exclusions still apply. Name, group id and ports come from
/// the arguments.
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

/// Spawn BLE Peer using the process-wide driver. `Some(event_tx)` replaces
/// the global event dispatcher; `None` leaves the existing dispatcher in
/// place. Registration success does not establish a connected peer.
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

/// Tear down the current registration at `id` through [`teardown_interface`].
/// For a BLE Peer registration this stops the process-wide peripheral and
/// clears its event dispatcher, affecting the singleton's users.
#[cfg(feature = "ble")]
pub async fn teardown_ble_peer_interface(handle: &ReticulumHandle, id: u64) {
    teardown_interface(handle, id).await;
}

/// Tear down the current registration at `id` through [`teardown_interface`].
/// Once acquired, cleanup stays bound to that driver rather than looking up
/// a later replacement. Keep the runtime's own id, not an id from a different
/// runtime or a stale registration.
#[cfg(feature = "ble")]
pub async fn teardown_ble_rnode_interface(handle: &ReticulumHandle, id: u64) {
    teardown_interface(handle, id).await;
}

/// Stop the current serial/TCP RNode registration through
/// [`teardown_interface`], joining its captured driver before enqueuing
/// deregistration.
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
    st_alock: Option<f64>,
    lt_alock: Option<f64>,
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
    st_alock: Option<f64>,
    lt_alock: Option<f64>,
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
    st_alock: Option<f64>,
    lt_alock: Option<f64>,
    flow_control: bool,
    rnode_startup_options: rns_interface::rnode::RNodeStartupOptions,
) -> Result<SpawnedRNodeRuntime, RNodeRuntimeSpawnError> {
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
    spawn_android_usb_rnode_runtime_with_config_and_options(handle, config, rnode_startup_options)
        .await
}

/// Spawn and register Android USB from one lossless typed configuration.
///
/// Applications that persist stable VID/PID/serial selectors or station-ID
/// settings should use this form. The historical argument-list facade above
/// remains source-compatible but can only express a legacy transient path.
#[cfg(target_os = "android")]
pub async fn spawn_android_usb_rnode_runtime_with_config_and_options(
    handle: &ReticulumHandle,
    config: rns_interface::android_usb::AndroidUsbConfig,
    rnode_startup_options: rns_interface::rnode::RNodeStartupOptions,
) -> Result<SpawnedRNodeRuntime, RNodeRuntimeSpawnError> {
    let spawn_permit = ensure_runtime_interface_admission(handle)
        .map_err(RNodeRuntimeSpawnError::RuntimeAdmission)?;
    let name = config.name.clone();
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

/// Start retained cleanup for the current registration selected by `id`.
/// Driver shutdown/join precedes the deregistration command. Cancelling this
/// waiter does not cancel cleanup; the function has no whole-call timeout and
/// returns no cleanup error. If the whole runtime already owns the drain,
/// this can return before that drain finishes; use `shutdown_and_wait` for it.
/// Numeric ids are runtime-local and can be reused; a stale id is not an
/// exact ownership capability.
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
    let transport_owner = if let Some(control_owner) = shutdown.control_owner() {
        remove_interface_control_if_owner(interface_controls, id, control_owner)
    } else {
        interface_controls
            .lock()
            .expect("interface_controls mutex poisoned")
            .remove(&id)
            .map(|control| control.transport_owner)
    };
    let deregistered = if let Some(owner) = transport_owner {
        rns_transport::messages::InterfaceTransportSender::bind(id, owner, transport_tx.clone())
            .send(TransportMessage::DeregisterInterface { id })
            .await
            .is_ok()
    } else {
        // No exact published registration remains in runtime ownership. Do not
        // fabricate authority over a current actor entry with the same ID.
        true
    };
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

type InterfaceSpawnFuture<'a> =
    std::pin::Pin<Box<dyn Future<Output = Result<Vec<OwnedInterfaceHandle>, String>> + Send + 'a>>;

/// Type-erased so the spawn arms compile once, here, rather than again in every
/// crate that awaits a caller.
#[allow(clippy::too_many_arguments)]
fn spawn_interface_with_rnode_startup_options<'a>(
    iface_config: &'a interface_factory::InterfaceConfig,
    id: u64,
    further_ids: &'a [u64],
    transport_tx: mpsc::Sender<TransportMessage>,
    id_gen: Arc<AtomicU64>,
    handle_tx: mpsc::Sender<rns_interface::traits::InterfaceHandle>,
    socket_base: &'a Path,
    storage_dir: &'a Path,
    is_foreground: Arc<AtomicBool>,
    rnode_startup_options: rns_interface::rnode::RNodeStartupOptions,
    tunnel_identity: &'a rns_interface::traits::TunnelIdentity,
) -> InterfaceSpawnFuture<'a> {
    Box::pin(spawn_configured_interface_driver(
        iface_config,
        id,
        further_ids,
        transport_tx,
        id_gen,
        handle_tx,
        socket_base,
        storage_dir,
        is_foreground,
        rnode_startup_options,
        tunnel_identity,
    ))
}

#[allow(clippy::too_many_arguments)]
async fn spawn_configured_interface_driver(
    iface_config: &interface_factory::InterfaceConfig,
    id: u64,
    further_ids: &[u64],
    transport_tx: mpsc::Sender<TransportMessage>,
    id_gen: Arc<AtomicU64>,
    handle_tx: mpsc::Sender<rns_interface::traits::InterfaceHandle>,
    socket_base: &Path,
    storage_dir: &Path,
    is_foreground: Arc<AtomicBool>,
    rnode_startup_options: rns_interface::rnode::RNodeStartupOptions,
    tunnel_identity: &rns_interface::traits::TunnelIdentity,
) -> Result<Vec<OwnedInterfaceHandle>, String> {
    #[cfg(not(any(
        feature = "serial",
        feature = "rnode-tcp",
        feature = "ble",
        target_os = "android"
    )))]
    let _ = rnode_startup_options;

    match iface_config {
        interface_factory::InterfaceConfig::TcpClient(c) => {
            let mut config = c.clone();
            config.tunnel_identity = Some(tunnel_identity.clone());
            rns_interface::tcp::spawn_tcp_client_observed(config, id, transport_tx)
                .await
                .map(client_with_teardown)
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
            rns_interface::serial::spawn_serial_interface_observed(serial_config, id, transport_tx)
                .await
                .map(serial_with_failures)
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
            rns_interface::kiss_iface::spawn_kiss_interface_observed(kiss_config, id, transport_tx)
                .await
                .map(serial_with_failures)
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
            rns_interface::auto::spawn_auto_interface(
                auto_config,
                id,
                id_gen,
                transport_tx,
                handle_tx,
                is_foreground,
            )
            .await
            .map(|h| vec![h.into()])
            .map_err(|e| format!("Auto: {e}"))
        }
        #[cfg(any(feature = "serial", feature = "rnode-tcp", target_os = "android"))]
        interface_factory::InterfaceConfig::RNode(c) => {
            #[cfg(target_os = "android")]
            if let Some(device_name) = c.port.strip_prefix("androidusb://") {
                if device_name.is_empty() {
                    return Err(format!(
                        "Android USB RNode '{}': empty USB device name",
                        c.name
                    ));
                }
                let tx_power = u8::try_from(c.tx_power)
                    .map_err(|_| format!("Android USB RNode '{}': invalid TX power", c.name))?;
                let mut config =
                    rns_interface::android_usb::AndroidUsbConfig::new(&c.name, device_name);
                config.device_vendor_id = c.usb_vendor_id;
                config.device_product_id = c.usb_product_id;
                config.device_serial_number = c.usb_serial_number.clone();
                config.baud_rate = c.baud_rate;
                config.frequency = c.frequency;
                config.bandwidth = c.bandwidth;
                config.spreading_factor = c.spreading_factor;
                config.coding_rate = c.coding_rate;
                config.tx_power = tx_power;
                config.mode = c.mode;
                config.flow_control = c.flow_control;
                config.st_alock = c.st_alock;
                config.lt_alock = c.lt_alock;
                config.id_interval = c.id_interval;
                config.id_callsign = c
                    .id_callsign
                    .as_ref()
                    .map(|callsign| callsign.as_bytes().to_vec());
                return rns_interface::android_usb::spawn_android_usb_rnode_interface_with_driver_and_options(
                    config,
                    id,
                    transport_tx,
                    rnode_startup_options,
                )
                .await
                .map(|spawned| {
                    let failures = InterfaceFailureWatch::RNode(spawned.driver.watch());
                    vec![OwnedInterfaceHandle {
                        hardware_failures: Some(failures),
                        ..spawned.into()
                    }]
                })
                .map_err(|error| format!("Android USB RNode: {error}"));
            }

            #[cfg(any(feature = "serial", feature = "rnode-tcp"))]
            {
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
                .map(|spawned| {
                    let failures = InterfaceFailureWatch::RNode(spawned.driver.watch());
                    vec![OwnedInterfaceHandle {
                        hardware_failures: Some(failures),
                        ..spawned.into()
                    }]
                })
                .map_err(|e| format!("RNode: {e}"))
            }

            #[cfg(not(any(feature = "serial", feature = "rnode-tcp")))]
            {
                Err(format!(
                    "RNodeInterface '{}': non-Android port requires serial or rnode-tcp support",
                    c.name
                ))
            }
        }
        interface_factory::InterfaceConfig::Local(c) => {
            let local_config = rns_interface::local::LocalClientConfig {
                socket_path: socket_base
                    .join(format!("reticulum_rs_{}.sock", c.name))
                    .to_string_lossy()
                    .to_string(),
                name: c.name.clone(),
                force_bitrate: None,
            };
            rns_interface::local::spawn_local_client(local_config, id, transport_tx)
                .await
                .map(|h| vec![h.into()])
                .map_err(|e| format!("Local: {e}"))
        }
        interface_factory::InterfaceConfig::I2P(c) => {
            if !c.connectable && c.peers.is_empty() {
                return Err(format!(
                    "I2PInterface '{}': requires 'connectable' or 'peers'",
                    c.name
                ));
            }
            // Python runs the server and one peer interface per configured
            // peer, each named "<name> to <peer>" (I2PInterface.py).
            let mut handles = Vec::new();
            let mut ids = std::iter::once(id).chain(further_ids.iter().copied());
            if c.connectable {
                let mut server_config = rns_interface::i2p::I2PServerConfig::new(&c.name);
                server_config.sam_host = c.i2p_sam_host.clone();
                server_config.sam_port = c.i2p_sam_port;
                server_config.mode = c.mode;
                server_config.key_path =
                    Some(i2p_key_path(storage_dir, &c.name, &tunnel_identity.0.hash));
                let (b32_tx, b32_rx) = tokio::sync::watch::channel(None);
                server_config.b32 = Some(b32_tx);
                let server_id = ids.next().unwrap_or_else(|| next_id(&id_gen));
                let server = rns_interface::i2p::spawn_i2p_server(
                    server_config,
                    server_id,
                    id_gen.clone(),
                    transport_tx.clone(),
                    handle_tx,
                )
                .await
                .map_err(|e| format!("I2P server: {e}"))?;
                handles.push(OwnedInterfaceHandle {
                    discovery_address: Some(b32_rx),
                    ..server.into()
                });
            }
            for peer in &c.peers {
                let mut client_config = rns_interface::i2p::I2PClientConfig::new(
                    &format!("{} to {peer}", c.name),
                    peer,
                );
                client_config.sam_host = c.i2p_sam_host.clone();
                client_config.sam_port = c.i2p_sam_port;
                client_config.mode = c.mode;
                client_config.tunnel_identity = Some(tunnel_identity.clone());
                let peer_id = ids.next().unwrap_or_else(|| next_id(&id_gen));
                match rns_interface::i2p::spawn_i2p_client(
                    client_config,
                    peer_id,
                    transport_tx.clone(),
                )
                .await
                {
                    Ok(client) => handles.push(OwnedInterfaceHandle {
                        configured_peer: true,
                        ..client.into()
                    }),
                    Err(e) => {
                        for spawned in handles {
                            rollback_unreserved_interface(spawned, InterfaceKind::Standard).await;
                        }
                        return Err(format!("I2P client: {e}"));
                    }
                }
            }
            Ok(handles)
        }
        interface_factory::InterfaceConfig::Pipe(c) => {
            let pipe_config = rns_interface::pipe::PipeInterfaceConfig {
                name: c.name.clone(),
                command: c.command.clone(),
                respawn_delay: c.respawn_delay,
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
            multi_config.mode = c.mode;
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
            // The parent takes `id`, then one reserved ID per subinterface.
            let mut reserved = further_ids.iter().copied();
            let mut sub_ids = Vec::with_capacity(multi_config.subinterfaces.len() + 1);
            sub_ids.push(id);
            for _ in 0..multi_config.subinterfaces.len() {
                sub_ids.push(reserved.next().unwrap_or_else(|| next_id(&id_gen)));
            }
            rns_interface::rnode_multi::spawn_rnode_multi_interface_observed(
                multi_config,
                &sub_ids,
                transport_tx,
            )
            .await
            .map(|spawned| {
                let mut handles: Vec<OwnedInterfaceHandle> =
                    spawned.handles.into_iter().map(Into::into).collect();
                handles[0].hardware_failures =
                    Some(InterfaceFailureWatch::RNodeMulti(spawned.failures));
                handles
            })
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
            rns_interface::ax25kiss::spawn_ax25kiss_interface_observed(
                ax25_config,
                id,
                transport_tx,
            )
            .await
            .map(serial_with_failures)
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
            config.pair_unbonded = c.pair_unbonded;
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
                config.tunnel_identity = Some(tunnel_identity.clone());
                config.bitrate = c.bitrate;
                config.ifac_size = c.ifac_size;
                rns_interface::backbone::spawn_backbone_client_observed(config, id, transport_tx)
                    .await
                    .map(client_with_teardown)
                    .map_err(|e| format!("Backbone client: {e}"))
            } else {
                let mut config =
                    rns_interface::backbone::BackboneServerConfig::new(&c.name, "", c.port);
                config.listen_ip = c.listen_on.clone();
                config.mode = c.mode;
                config.prefer_ipv6 = c.prefer_ipv6;
                config.device = c.device.clone();
                config.block_fast_flapping = c.block_fast_flapping;
                config.fast_flapping_threshold = c.fast_flapping_threshold;
                config.fast_flapping_grace = c.fast_flapping_grace;
                config.fast_flapping_block_time = c.fast_flapping_block_time;
                config.client_limit = c.client_limit;
                config.bitrate = c.bitrate;
                config.ifac_size = c.ifac_size;
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

/// Carry out the transport actor's interface requests until it stops or the
/// runtime shuts down.
async fn run_interface_control(
    handle: ReticulumHandle,
    mut requests: mpsc::UnboundedReceiver<rns_transport::messages::InterfaceControl>,
) {
    use rns_transport::messages::InterfaceControl;
    let shutdown = handle.shutdown.clone();
    loop {
        let request = tokio::select! {
            request = requests.recv() => request,
            () = shutdown.wait() => None,
        };
        match request {
            Some(InterfaceControl::Detach {
                interface_id,
                reason,
            }) => {
                tracing::debug!(interface_id, ?reason, "transport asked for a detach");
                let _ = handle.detach_interface_by_id(interface_id).await;
            }
            Some(_) => {}
            None => return,
        }
    }
}

/// Return the first successfully initialized runtime retained in the
/// process-wide cell. Later `init` calls still construct separate runtimes;
/// this reference is not replaced or cleared on shutdown. Prefer the handle
/// returned by the initialization call that owns your runtime.
pub fn get_instance() -> Option<&'static ReticulumHandle> {
    INSTANCE.get()
}

/// The list files beside `config` (Reticulum.py), read before any interface
/// starts; a file that cannot be read is logged and skipped, as upstream does.
fn load_config_dir_lists(config_dir: &Path, rc: &mut ReticulumConfig) {
    let read = |name: &str| match crate::config::read_list_file(&config_dir.join(name)) {
        Ok(lines) => lines,
        Err(error) => {
            tracing::error!(file = name, %error, "could not load config directory list");
            None
        }
    };
    if let Some(names) = read("known_destination_types") {
        rc.filter.known_types = names;
    }
    if let Some(names) = read("flagged_destination_types") {
        rc.filter.flagged_types = names;
    }
    let blocked = read("blocked_ips").map_or_else(Vec::new, |lines| parse_blocked_ips(&lines));
    let count = rns_interface::backbone::set_blocked_ips(blocked);
    if count > 0 {
        tracing::debug!(count, "loaded blocked IPs");
    }
}

/// `blocked_ips` lines that `ipaddress.ip_address` accepts: no CIDR, no
/// hostnames, no inline comments (Discovery.py).
fn parse_blocked_ips(lines: &[String]) -> Vec<std::net::IpAddr> {
    lines.iter().filter_map(|line| line.parse().ok()).collect()
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

/// The persistent transport identity, created when absent. Creation is
/// exclusive: a daemon and a tool starting together on a fresh directory must
/// end with one identity, or the RPC key each derives from it differs.
fn load_or_create_transport_identity(path: &Path) -> Identity {
    if let Ok(identity) = Identity::from_file(path) {
        return identity;
    }
    let identity = Identity::new();
    let warn = |error: &dyn std::fmt::Display| {
        tracing::warn!(path = %path.display(), %error,
            "failed to persist transport identity — path request identity will change on restart");
    };
    if path.exists() {
        // An unreadable file is replaced.
        if let Err(e) = identity.to_file(path) {
            warn(&e);
        }
        return identity;
    }
    // Unique per call, so two creators never share a staged file.
    static STAGED: AtomicU64 = AtomicU64::new(0);
    let staged = path.with_extension(format!(
        "new.{}.{}",
        std::process::id(),
        STAGED.fetch_add(1, Ordering::Relaxed)
    ));
    let created = match identity.to_file(&staged) {
        // A hard link fails when the name exists, so only one creator wins.
        Ok(()) => std::fs::hard_link(&staged, path),
        Err(e) => Err(std::io::Error::other(e.to_string())),
    };
    let _ = std::fs::remove_file(&staged);
    match created {
        Ok(()) => identity,
        Err(e) => Identity::from_file(path).unwrap_or_else(|_| {
            warn(&e);
            identity
        }),
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

/// A section that fails to build stops startup whatever
/// `panic_on_interface_error` says (Reticulum.py); an unknown type
/// is only logged, as upstream does for a missing external module. With
/// `failures`, a failed section is recorded there and the rest are built.
fn synthesize_interfaces(
    config: &Config,
    mut failures: Option<&mut Vec<(String, String)>>,
) -> Result<Vec<interface_factory::InterfaceConfig>, ReticulumError> {
    let mut interfaces = Vec::new();

    for (name, section) in config.subsections("interfaces") {
        match interface_factory::synthesize_interface(name, section) {
            Ok(iface) => {
                tracing::debug!("configured interface: {name}");
                interfaces.push(iface);
            }
            Err(interface_factory::InterfaceFactoryError::Disabled(_)) => {
                tracing::debug!("interface {name} is disabled");
            }
            Err(e @ interface_factory::InterfaceFactoryError::UnknownType(_)) => {
                tracing::error!("failed to synthesize interface {name}: {e}");
            }
            Err(e) => match failures.as_deref_mut() {
                Some(failures) => {
                    tracing::warn!("failed to synthesize interface {name}: {e}");
                    failures.push((name.to_string(), e.to_string()));
                }
                None => {
                    return Err(ReticulumError::Interface(format!(
                        "The interface \"{name}\" could not be created: {e}"
                    )));
                }
            },
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
            // Python matches names of full-hash hex length, (HASHLENGTH//8)*2.
            // A Resource spool a crash left behind is cleaned the same way.
            let name = file_name.as_encoded_bytes();
            if name.len() != 64 && !crate::resource_spool::is_spool_name(name) {
                continue;
            }
            if let Ok(metadata) = entry.metadata()
                && metadata.is_file()
                && let Ok(modified) = metadata.modified()
                && let Ok(age) = now.duration_since(modified)
                && age > ttl
            {
                let path = entry.path();
                if std::fs::remove_file(&path).is_ok() {
                    tracing::trace!("cleaned cache entry: {}", path.display());
                }
            }
        }
    }
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
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
    #[error("No shared instance available, but application that started Reticulum required it")]
    RequiredSharedInstanceUnavailable,
    #[error("transport error: {0}")]
    Transport(String),
    #[error("interface error: {0}")]
    Interface(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    mod autoconnect;
    mod concurrent_start;
    mod interface_stats;
    mod manage_interfaces;
    mod paths_and_filters;
    mod tunnels;

    // These shadow the entry points for every test here: each start writes the
    // process destination-stamp settings (destination_stamper::test_settings).
    async fn init(
        configdir: Option<&str>,
        socket_dir: Option<PathBuf>,
        shutdown: ShutdownSignal,
        is_foreground: Arc<AtomicBool>,
    ) -> Result<ReticulumHandle, ReticulumError> {
        crate::destination_stamper::test_settings::around_init(super::init(
            configdir,
            socket_dir,
            shutdown,
            is_foreground,
        ))
        .await
    }

    async fn init_with_options(
        configdir: Option<&str>,
        socket_dir: Option<PathBuf>,
        shutdown: ShutdownSignal,
        is_foreground: Arc<AtomicBool>,
        options: InitOptions,
    ) -> Result<ReticulumHandle, ReticulumError> {
        crate::destination_stamper::test_settings::around_init(super::init_with_options(
            configdir,
            socket_dir,
            shutdown,
            is_foreground,
            options,
        ))
        .await
    }

    #[cfg(feature = "rnode-tcp")]
    async fn init_with_options_and_rnode_startup_options(
        configdir: Option<&str>,
        socket_dir: Option<PathBuf>,
        shutdown: ShutdownSignal,
        is_foreground: Arc<AtomicBool>,
        options: InitOptions,
        rnode_startup_options: rns_interface::rnode::RNodeStartupOptions,
    ) -> Result<ReticulumHandle, ReticulumError> {
        crate::destination_stamper::test_settings::around_init(
            super::init_with_options_and_rnode_startup_options(
                configdir,
                socket_dir,
                shutdown,
                is_foreground,
                options,
                rnode_startup_options,
            ),
        )
        .await
    }

    #[test]
    fn processes_starting_together_end_with_one_transport_identity() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("transport_identity");
        let start = std::sync::Barrier::new(8);
        let hashes: Vec<_> = std::thread::scope(|scope| {
            let racers: Vec<_> = (0..8)
                .map(|_| {
                    scope.spawn(|| {
                        start.wait();
                        load_or_create_transport_identity(&path).hash
                    })
                })
                .collect();
            racers.into_iter().map(|r| r.join().unwrap()).collect()
        });
        let stored = Identity::from_file(&path).unwrap().hash;
        assert!(hashes.iter().all(|hash| *hash == stored), "{hashes:?}");
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    async fn wait_for_registry_len(registry: &InterfaceRegistry, expected: usize) {
        // An RNode registers only after its 2 s post-open settle.
        tokio::time::timeout(Duration::from_secs(5), async {
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
                transport_owner: rns_transport::InterfaceOwner::new(),
                registry_owner: owner,
                role: rns_transport::messages::InterfaceRole::Normal,
                ingress_overrides: rns_transport::ingress::IngressOverrides::default(),
                ifac_key: None,
                ifac_size: 0,
                ifac_netname: None,
                client_target: None,
                destination_cost: None,
                pr_cost: None,
                spawn: None,
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
                transport_owner: rns_transport::InterfaceOwner::new(),
                registry_owner: owner,
                role: rns_transport::messages::InterfaceRole::Normal,
                ingress_overrides: rns_transport::ingress::IngressOverrides::default(),
                ifac_key: None,
                ifac_size: 0,
                ifac_netname: None,
                client_target: None,
                destination_cost: None,
                pr_cost: None,
                spawn: None,
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
                paused: Arc::new(AtomicBool::new(false)),
                result_tx,
            })
            .await
            .unwrap();
        let id = result_rx.await.unwrap();
        let mut subscription = AnnounceSubscription {
            id: Some(id),
            events,
            dropped_events,
            paused: Arc::new(AtomicBool::new(false)),
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
    fn discovered_ifac_values_drop_blank_and_none() {
        for (value, expected) in [
            (None, None),
            (Some(""), None),
            (Some("None"), None),
            (Some("net"), Some("net")),
        ] {
            assert_eq!(
                discovered_ifac_value(&value.map(str::to_string)).as_deref(),
                expected
            );
        }
    }

    #[test]
    fn runtime_ifac_post_init_ignores_none_fields() {
        let post_init = runtime_ifac_post_init(
            Some(RuntimeInterfaceIfacConfig {
                network_name: Some("None".to_string()),
                passphrase: Some("None".to_string()),
                ifac_size: None,
            }),
            16,
        )
        .unwrap();
        assert!(post_init.is_none());

        let post_init = runtime_ifac_post_init(
            Some(RuntimeInterfaceIfacConfig {
                network_name: Some("None".to_string()),
                passphrase: Some("pw".to_string()),
                ifac_size: None,
            }),
            16,
        )
        .unwrap()
        .unwrap();
        assert_eq!(post_init.ifac_network_name, None);
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
        assert_eq!(
            post_init.ifac_passphrase.as_deref().map(String::as_str),
            Some("secret")
        );
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

        spawn_shared_peer_monitor(
            registered_test_sender(7, tx),
            7,
            online.clone(),
            false,
            shutdown.clone(),
        );
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
        match unwrap_owned_event(restored) {
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
        match unwrap_owned_event(lost) {
            TransportMessage::SharedConnectionLost => {}
            other => panic!("expected SharedConnectionLost, got {other:?}"),
        }

        shutdown.trigger();
    }

    #[tokio::test(start_paused = true)]
    async fn shared_peer_initial_attachment_waits_for_actor_applied_barrier() {
        for initial_online in [false, true] {
            let (tx, mut rx) = mpsc::channel(4);
            let shutdown = ShutdownSignal::new();
            let caller = tokio::spawn(async move {
                apply_initial_shared_peer_state(
                    &registered_test_sender(7, tx.clone()),
                    7,
                    initial_online,
                    &shutdown,
                )
                .await
            });
            let event = unwrap_owned_event(rx.recv().await.unwrap());
            assert!(matches!(
                (initial_online, event),
                (
                    true,
                    TransportMessage::SharedConnectionRestored { interface_id: 7 }
                ) | (false, TransportMessage::SharedConnectionLost)
            ));
            let TransportMessage::Rpc { query, response_tx } =
                unwrap_owned_event(rx.recv().await.unwrap())
            else {
                panic!("expected same-mailbox actor barrier");
            };
            assert!(matches!(query, TransportQuery::GetLinkCount));
            tokio::task::yield_now().await;
            assert!(
                !caller.is_finished(),
                "queueing the initial state is not completion"
            );
            response_tx
                .send(TransportQueryResponse::IntResult(0))
                .unwrap();
            assert_eq!(caller.await.unwrap(), Ok(()));
        }
    }

    #[tokio::test(start_paused = true)]
    async fn shared_peer_seeded_monitor_emits_only_later_connection_edges() {
        let (tx, mut rx) = mpsc::channel(4);
        let online = Arc::new(AtomicBool::new(true));
        let shutdown = ShutdownSignal::new();
        spawn_shared_peer_monitor(
            registered_test_sender(7, tx),
            7,
            online.clone(),
            true,
            shutdown.clone(),
        );
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_millis(120)).await;
        tokio::task::yield_now().await;
        assert!(
            rx.try_recv().is_err(),
            "initial attached state must not be replayed"
        );
        online.store(false, Ordering::SeqCst);
        tokio::time::advance(Duration::from_millis(100)).await;
        assert!(matches!(
            unwrap_owned_event(rx.recv().await.unwrap()),
            TransportMessage::SharedConnectionLost
        ));
        online.store(true, Ordering::SeqCst);
        tokio::time::advance(Duration::from_millis(100)).await;
        assert!(matches!(
            unwrap_owned_event(rx.recv().await.unwrap()),
            TransportMessage::SharedConnectionRestored { interface_id: 7 }
        ));
        shutdown.trigger();
    }

    #[tokio::test(start_paused = true)]
    async fn shared_peer_initial_attachment_timeout_rolls_back_exact_registration() {
        let (tx, mut rx) = mpsc::channel(8);
        let controls: InterfaceControlMap = Arc::new(std::sync::Mutex::new(HashMap::new()));
        let registry = InterfaceRegistry::default();
        let handle = test_interface_handle(7, None, "unresponsive attachment");
        let online = handle.online.clone();
        let caller_controls = controls.clone();
        let caller_registry = registry.clone();
        let caller = tokio::spawn(async move {
            adopt_shared_instance_client(
                handle,
                &tx,
                &caller_controls,
                &caller_registry,
                &ShutdownSignal::new(),
                None,
                None,
            )
            .await
        });
        assert!(matches!(
            unwrap_owned_event(rx.recv().await.unwrap()),
            TransportMessage::RegisterInterface { id: 7, .. }
        ));
        assert!(matches!(
            unwrap_owned_event(rx.recv().await.unwrap()),
            TransportMessage::SharedConnectionRestored { interface_id: 7 }
        ));
        let TransportMessage::Rpc {
            response_tx: held_barrier,
            ..
        } = unwrap_owned_event(rx.recv().await.unwrap())
        else {
            panic!("expected attachment barrier");
        };
        assert_eq!(registry.len(), 1);
        tokio::time::advance(Duration::from_secs(5)).await;
        assert_eq!(caller.await.unwrap().unwrap(), InstanceMode::Standalone);
        assert!(matches!(
            unwrap_owned_event(rx.recv().await.unwrap()),
            TransportMessage::DeregisterInterface { id: 7 }
        ));
        assert_eq!(registry.len(), 0);
        assert!(controls.lock().unwrap().is_empty());
        assert!(!online.load(Ordering::SeqCst));
        assert!(
            held_barrier
                .send(TransportQueryResponse::IntResult(0))
                .is_err()
        );
        assert!(
            rx.try_recv().is_err(),
            "a failed attachment must not start a monitor"
        );
    }

    #[tokio::test]
    async fn shared_peer_initial_attachment_closed_actor_and_shutdown_fail_closed() {
        let (tx, rx) = mpsc::channel(1);
        drop(rx);
        assert!(
            apply_initial_shared_peer_state(
                &registered_test_sender(7, tx.clone()),
                7,
                true,
                &ShutdownSignal::new()
            )
            .await
            .is_err()
        );
        let (tx, mut rx) = mpsc::channel(1);
        let shutdown = ShutdownSignal::new();
        shutdown.trigger();
        assert!(
            apply_initial_shared_peer_state(
                &registered_test_sender(7, tx.clone()),
                7,
                true,
                &shutdown
            )
            .await
            .is_err()
        );
        assert!(rx.try_recv().is_err());
    }

    #[tokio::test(start_paused = true)]
    async fn shared_peer_initial_attachment_full_mailbox_rollback_is_bounded_and_fail_closed() {
        struct TaskStopped(Arc<AtomicBool>);
        impl Drop for TaskStopped {
            fn drop(&mut self) {
                self.0.store(true, Ordering::SeqCst);
            }
        }

        let (tx, mut rx) = mpsc::channel(1);
        let controls: InterfaceControlMap = Arc::new(std::sync::Mutex::new(HashMap::new()));
        let registry = InterfaceRegistry::default();
        let shutdown = ShutdownSignal::new();
        let mut handle = test_interface_handle(7, None, "wedged attachment");
        let stopped = Arc::new(AtomicBool::new(false));
        let stopped_guard = TaskStopped(stopped.clone());
        handle.read_task = tokio::spawn(async move {
            let _stopped_guard = stopped_guard;
            std::future::pending::<()>().await;
        });
        let online = handle.online.clone();
        let caller_controls = controls.clone();
        let caller_registry = registry.clone();
        let caller_shutdown = shutdown.clone();
        let caller_tx = tx.clone();
        let started = tokio::time::Instant::now();
        let caller = tokio::spawn(async move {
            adopt_shared_instance_client(
                handle,
                &caller_tx,
                &caller_controls,
                &caller_registry,
                &caller_shutdown,
                None,
                None,
            )
            .await
        });
        assert!(matches!(
            unwrap_owned_event(rx.recv().await.unwrap()),
            TransportMessage::RegisterInterface { id: 7, .. }
        ));
        // Leave initial Restored occupying the only slot: both the actor
        // barrier and later exact DeregisterInterface must wait on this queue.
        while tx.capacity() != 0 {
            tokio::task::yield_now().await;
        }
        let registry_owner = controls.lock().unwrap()[&7].registry_owner;
        tokio::time::advance(Duration::from_secs(5)).await;
        tokio::task::yield_now().await;
        assert!(
            !caller.is_finished(),
            "exact rollback owns the second bounded wait"
        );
        // Let the stop-and-join complete and reach its blocked deregistration.
        while !controls.lock().unwrap().is_empty() {
            tokio::task::yield_now().await;
        }
        assert!(stopped.load(Ordering::SeqCst));
        tokio::time::advance(Duration::from_secs(5)).await;
        let error = caller
            .await
            .unwrap()
            .expect_err("wedged rollback must not return Standalone");
        assert!(error.to_string().contains("rollback timed out"));
        assert_eq!(started.elapsed(), Duration::from_secs(10));
        assert!(shutdown.is_triggered());
        assert!(!online.load(Ordering::SeqCst));
        assert_eq!(
            registry.len(),
            1,
            "exact tombstone remains until runtime drain"
        );
        assert!(controls.lock().unwrap().is_empty());

        let replacement = test_interface_handle(7, None, "must not replace tombstone");
        assert!(matches!(
            register_interface_handle(&tx, replacement, &controls, &registry).await,
            Err(InterfaceRegistrationError::Duplicate { id: 7 })
        ));
        assert_eq!(registry.len(), 1);
        assert!(controls.lock().unwrap().is_empty());
        assert!(matches!(
            unwrap_owned_event(rx.try_recv().unwrap()),
            TransportMessage::SharedConnectionRestored { interface_id: 7 }
        ));
        assert!(
            rx.try_recv().is_err(),
            "no blind deregistration or replacement was admitted"
        );
        // Confirm this is the original generation, not a newly admitted owner.
        assert_eq!(
            registry.wait_or_claim_abandoned(7, registry_owner).await,
            Some((7, registry_owner))
        );
        registry.finish_abandoned(7, registry_owner);
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

    fn registered_test_sender(
        id: u64,
        tx: mpsc::Sender<TransportMessage>,
    ) -> rns_transport::InterfaceTransportSender {
        let sender = rns_transport::InterfaceTransportSender::new(id, tx);
        sender.owner().mark_registered();
        sender
    }

    fn unwrap_owned_event(event: TransportMessage) -> TransportMessage {
        match event {
            TransportMessage::RegisterInterface { id, entry } => {
                entry.owner.mark_registered();
                TransportMessage::RegisterInterface { id, entry }
            }
            TransportMessage::InterfaceEvent {
                interface_id,
                owner,
                message,
            } => {
                assert!(owner.is_current());
                if let TransportMessage::DeregisterInterface { id } = &*message {
                    assert_eq!(*id, interface_id, "cleanup must retain its exact interface");
                }
                *message
            }
            other => other,
        }
    }

    /// Stand in for the transport actor: acknowledge each registration so owned
    /// senders, teardown's deregistration included, can proceed.
    #[cfg(feature = "rnode-tcp")]
    fn acknowledging_transport(
        capacity: usize,
    ) -> (
        mpsc::Sender<TransportMessage>,
        mpsc::UnboundedReceiver<TransportMessage>,
    ) {
        let (tx, mut rx) = mpsc::channel(capacity);
        let (seen_tx, seen_rx) = mpsc::unbounded_channel();
        tokio::spawn(async move {
            while let Some(message) = rx.recv().await {
                let _ = seen_tx.send(unwrap_owned_event(message));
            }
        });
        (tx, seen_rx)
    }

    fn test_interface_handle(
        id: u64,
        parent_id: Option<u64>,
        name: &str,
    ) -> rns_interface::traits::InterfaceHandle {
        let (tx, _rx) = mpsc::channel(4);
        rns_interface::traits::InterfaceHandle {
            id,
            owner: rns_transport::InterfaceOwner::new(),
            packet_capacity: rns_transport::InterfacePacketCapacity::base(500),
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
    async fn invalid_ifac_capacity_registration_stops_owned_driver_before_returning() {
        for configured in [false, true] {
            for size in [0, 65] {
                let mut handle = test_interface_handle(920_299, None, "invalid-ifac");
                handle.read_task = tokio::spawn(std::future::pending());
                let task = handle.read_task.abort_handle();
                let online = handle.online.clone();
                let controls: InterfaceControlMap = Arc::new(std::sync::Mutex::new(HashMap::new()));
                let registry = InterfaceRegistry::default();
                let result = if configured {
                    let mut post_init = interface_factory::InterfacePostInit::try_from_section(
                        &ConfigSection::default(),
                    )
                    .unwrap();
                    post_init.ifac_size = Some(size);
                    prepare_interface_with_post_init(
                        handle.into(),
                        &post_init,
                        Some([1; 64].into()),
                        &controls,
                        &registry,
                        InterfaceKind::Standard,
                    )
                    .await
                } else {
                    prepare_interface_with_role_and_overrides(
                        handle.into(),
                        rns_transport::messages::InterfaceRole::Normal,
                        Default::default(),
                        Some([1; 64].into()),
                        size,
                        &controls,
                        &registry,
                        InterfaceKind::Standard,
                        false,
                    )
                    .await
                };
                assert!(matches!(
                    result,
                    Err(InterfaceRegistrationError::InvalidCapacity(_))
                ));
                assert!(task.is_finished());
                assert!(!online.load(Ordering::SeqCst));
                assert!(controls.lock().unwrap().is_empty());
                assert_eq!(registry.len(), 0);
            }
        }
    }

    #[tokio::test]
    async fn invalid_ingress_registration_stops_owned_driver_before_returning() {
        for configured in [false, true] {
            let mut handle = test_interface_handle(920_199, None, "invalid-ingress");
            handle.read_task = tokio::spawn(std::future::pending());
            let task = handle.read_task.abort_handle();
            let online = handle.online.clone();
            let controls: InterfaceControlMap = Arc::new(std::sync::Mutex::new(HashMap::new()));
            let registry = InterfaceRegistry::default();
            let overrides = rns_transport::ingress::IngressOverrides {
                burst_hold: Some(f64::INFINITY),
                ..Default::default()
            };
            let result = if configured {
                let mut post_init = interface_factory::InterfacePostInit::try_from_section(
                    &ConfigSection::default(),
                )
                .unwrap();
                post_init.ingress_overrides = overrides;
                prepare_interface_with_post_init(
                    handle.into(),
                    &post_init,
                    None,
                    &controls,
                    &registry,
                    InterfaceKind::Standard,
                )
                .await
            } else {
                prepare_interface_with_role_and_overrides(
                    handle.into(),
                    rns_transport::messages::InterfaceRole::Normal,
                    overrides,
                    None,
                    0,
                    &controls,
                    &registry,
                    InterfaceKind::Standard,
                    false,
                )
                .await
            };
            assert!(matches!(
                result,
                Err(InterfaceRegistrationError::InvalidIngress {
                    field: "ic_burst_hold"
                })
            ));
            assert!(task.is_finished());
            assert!(!online.load(Ordering::SeqCst));
            assert!(controls.lock().unwrap().is_empty());
            assert_eq!(registry.len(), 0);
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
            // Settings re-asserted while on echo their effective values.
            (
                rnode::CMD_FREQUENCY,
                settings.frequency.to_be_bytes().to_vec(),
            ),
            (
                rnode::CMD_BANDWIDTH,
                settings.bandwidth.to_be_bytes().to_vec(),
            ),
            (rnode::CMD_TXPOWER, vec![settings.tx_power]),
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
                // Settings re-asserted while on echo their effective values.
                (
                    rnode::CMD_FREQUENCY,
                    settings.frequency.to_be_bytes().to_vec(),
                ),
                (
                    rnode::CMD_BANDWIDTH,
                    settings.bandwidth.to_be_bytes().to_vec(),
                ),
                (rnode::CMD_TXPOWER, vec![settings.tx_power]),
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
        // An unreachable radio is retried by the driver, but a malformed port
        // remains a typed spawn failure.
        let error = spawn_rnode_runtime_observed_with_options(
            &runtime,
            test_rnode_runtime_args("strict-runtime-rnode", "tcp://"),
            rns_interface::rnode::RNodeStartupOptions::require_capability_admission(),
        )
        .await
        .expect_err("a port without a host cannot be spawned");

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
    #[test]
    fn native_ble_typed_config_preserves_every_driver_field() {
        let config = native_ble_driver_config(interface_factory::BleRNodeInterfaceConfig {
            name: "native-lossless".into(),
            port: "ble://AA:BB:CC:DD:EE:FF".into(),
            frequency: 915_125_000,
            bandwidth: 62_500,
            spreading_factor: 9,
            coding_rate: 7,
            tx_power: 17,
            mode: rns_interface::traits::InterfaceMode::Roaming,
            flow_control: true,
            st_alock: Some(12.5),
            lt_alock: Some(3.25),
            id_interval: Some(900),
            id_callsign: Some("N0CALL".into()),
            pair_unbonded: false,
        })
        .expect("valid typed native BLE config");

        assert_eq!(config.name, "native-lossless");
        assert_eq!(config.ble_uri, "ble://AA:BB:CC:DD:EE:FF");
        assert_eq!(config.frequency, 915_125_000);
        assert_eq!(config.bandwidth, 62_500);
        assert_eq!(config.spreading_factor, 9);
        assert_eq!(config.coding_rate, 7);
        assert_eq!(config.tx_power, 17);
        assert_eq!(config.mode, rns_interface::traits::InterfaceMode::Roaming);
        assert!(config.flow_control);
        assert_eq!(config.st_alock, Some(12.5));
        assert_eq!(config.lt_alock, Some(3.25));
        assert_eq!(config.id_interval, Some(900));
        assert_eq!(config.id_callsign.as_deref(), Some(b"N0CALL".as_slice()));
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
        let (transport_tx, mut transport_rx) = acknowledging_transport(4);
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
        let (transport_tx, mut transport_rx) = acknowledging_transport(4);
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
    async fn legacy_rnode_spawn_preserves_id_and_reports_unready_radio() {
        let (port, closed_rx, peer) = test_rnode_tcp_peer();
        let (transport_tx, mut transport_rx) = acknowledging_transport(4);
        let mut runtime = dummy_handle();
        runtime.transport_tx = transport_tx;

        let (id, online) =
            spawn_rnode_runtime(&runtime, test_rnode_runtime_args("legacy-spawn", &port))
                .await
                .expect("legacy RNode spawn");
        assert_eq!(id, 0);
        assert!(
            !online.load(Ordering::SeqCst),
            "an open socket without typed radio Ready is not an online RNode"
        );
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

        let (transport_tx, _transport_rx) = acknowledging_transport(8);
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
        let (transport_tx, _transport_rx) = acknowledging_transport(8);
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
        let (transport_tx, _transport_rx) = acknowledging_transport(8);
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
        assert_eq!(rc.loglevel, 3);
        assert_eq!(rc.inbound_queue_lengths, InboundQueueLengths::default());
    }

    #[test]
    fn test_loglevel_clamps_to_extreme() {
        for (raw, expected) in [("8", 8), ("9", 8), ("-1", 0), ("7", 7)] {
            let config = Config::parse(&format!("[logging]\nloglevel = {raw}\n")).unwrap();
            assert_eq!(
                ReticulumConfig::from_config(&config).loglevel,
                expected,
                "{raw}"
            );
        }
    }

    #[test]
    fn test_inbound_queue_lengths_apply_only_positive_values() {
        let config = Config::parse(
            "[reticulum]\nqlen_in_data = 10\nqlen_in_announce = 0\nqlen_in_pr = -1\nqlen_in_il = 3\n",
        )
        .unwrap();
        let q = ReticulumConfig::from_config(&config).inbound_queue_lengths;
        assert_eq!((q.data, q.announce, q.pr, q.il), (10, 128, 128, 3));
        let config = Config::parse("[reticulum]\nqlen_in_il = abc\n").unwrap();
        assert!(ReticulumConfig::try_from_config(&config).is_err());
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

    /// Python Reticulum.py: Unix sockets serve the shared instance
    /// only where `platformutils.use_af_unix()` holds, whatever was requested.
    fn python_unix_request() -> SharedInstanceType {
        if cfg!(target_os = "linux") || rns_interface::local::is_android() {
            SharedInstanceType::Unix
        } else {
            SharedInstanceType::Tcp
        }
    }

    #[test]
    fn test_shared_instance_type_explicit_unix() {
        let input = "[reticulum]\nshared_instance_type = Unix\n";
        let config = Config::parse(input).unwrap();
        let rc = ReticulumConfig::from_config(&config);
        assert_eq!(rc.shared_instance_type, python_unix_request());
    }

    #[test]
    fn test_shared_instance_type_absent_is_the_platform_carrier() {
        let config = Config::parse("[reticulum]\ninstance_name = other\n").unwrap();
        let rc = ReticulumConfig::from_config(&config);
        assert_eq!(rc.shared_instance_type, python_unix_request());
    }

    #[test]
    fn test_shared_instance_type_option_follows_the_platform_rule() {
        let config = Config::parse("[reticulum]\nshared_instance_type = tcp\n").unwrap();
        let mut rc = ReticulumConfig::from_config(&config);
        rc.apply_init_options(&InitOptions {
            shared_instance_type: Some(SharedInstanceType::Unix),
            ..InitOptions::default()
        });
        assert_eq!(rc.shared_instance_type, python_unix_request());
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
    fn test_shared_tcp_client_config_uses_local_interface() {
        let config = shared_tcp_client_config(12345, None);
        assert_eq!(config.name, "SharedInstanceClient");
        assert_eq!(config.socket_path, "tcp://127.0.0.1:12345");
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

        assert_eq!(handle.packet_capacity.max_wire_packet_bytes, handle.mtu);

        apply_forced_shared_instance_bitrate(&mut handle, Some(0));
        assert_eq!(handle.bitrate, 1_000_000, "zero is not a usable bitrate");

        apply_forced_shared_instance_bitrate(&mut handle, Some(1_000_000_000));
        assert_eq!(handle.mtu, 524_288);
        assert_eq!(handle.packet_capacity.max_clear_packet_bytes, 524_288);
        assert_eq!(handle.packet_capacity.max_wire_packet_bytes, 524_288);
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
            path_recovery: rns_transport::actor::TransportActor::new()
                .0
                .path_recovery_handle(),
            link_endpoint_dispatch: rns_transport::actor::TransportActor::new()
                .0
                .link_endpoint_dispatch_handle(),
            announce_dispatch: rns_transport::actor::TransportActor::new()
                .0
                .announce_dispatch_handle(),
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
            startup_interface_failures: Vec::new(),
            #[cfg(feature = "ble")]
            deferred_android_ble_rnodes: Vec::new(),
            shutdown_coordinator,
            shared_instance_status: None,
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
                .send(TransportQueryResponse::RecalledDestination(Some({
                    let mut entry = RecalledDestinationRpcEntry::default();
                    entry.dest_hash = destination_hash;
                    entry.public_key = public_key;
                    entry.app_data = Some(b"display name".to_vec());
                    entry.ratchet = Some([0xA5; 32]);
                    entry.hops = 4;
                    entry.timestamp = timestamp;
                    entry
                })))
                .expect("recall response receiver");
            for expected in ["stamp value", "link cost"] {
                let TransportMessage::Rpc { query, response_tx } =
                    transport_rx.recv().await.expect("stamp query")
                else {
                    panic!("expected transport RPC");
                };
                let value = match (expected, query) {
                    ("stamp value", TransportQuery::RecallStampValue { dest })
                        if dest == destination_hash =>
                    {
                        Some(25.5)
                    }
                    ("link cost", TransportQuery::RecallLinkCost { dest })
                        if dest == destination_hash =>
                    {
                        Some(12.5)
                    }
                    (_, other) => panic!("expected {expected} query, got {other:?}"),
                };
                response_tx
                    .send(TransportQueryResponse::FloatResult(value))
                    .expect("stamp response receiver");
            }
            let TransportMessage::Rpc { query, response_tx } =
                transport_rx.recv().await.expect("use query")
            else {
                panic!("expected transport RPC");
            };
            assert!(matches!(
                query,
                TransportQuery::UseDestination { dest } if dest == destination_hash
            ));
            response_tx
                .send(TransportQueryResponse::BoolResult(true))
                .expect("use response receiver");
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
        assert_eq!(recalled.stamp_value, Some(25.5));
        assert_eq!(recalled.link_cost, Some(12.5));
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
                .send(TransportQueryResponse::RecalledDestination(Some({
                    let mut entry = RecalledDestinationRpcEntry::default();
                    entry.dest_hash = destination_hash;
                    entry.public_key = public_key;
                    entry.app_data = None;
                    entry.ratchet = None;
                    entry.hops = 1;
                    entry.timestamp = 1.0;
                    entry
                })))
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
                proof_hash: None,
                metrics: Default::default(),
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
                    .send(TransportQueryResponse::RecalledDestination(Some({
                        let mut entry = RecalledDestinationRpcEntry::default();
                        entry.dest_hash = destination_hash;
                        entry.public_key = public_key;
                        entry.app_data = None;
                        entry.ratchet = None;
                        entry.hops = 1;
                        entry.timestamp = 1.0;
                        entry
                    })))
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
                .send(TransportQueryResponse::RecalledDestination(Some({
                    let mut entry = RecalledDestinationRpcEntry::default();
                    entry.dest_hash = destination_hash;
                    entry.public_key = public_key;
                    entry.app_data = None;
                    entry.ratchet = None;
                    entry.hops = 1;
                    entry.timestamp = 1.0;
                    entry
                })))
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
                .send(TransportQueryResponse::RecalledDestination(Some({
                    let mut entry = RecalledDestinationRpcEntry::default();
                    entry.dest_hash = destination_hash;
                    entry.public_key = remote_public_key;
                    entry.app_data = None;
                    entry.ratchet = None;
                    entry.hops = 7;
                    entry.timestamp = 1_700_000_000.0;
                    entry
                })))
                .expect("recall response receiver");

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
                .send(TransportQueryResponse::IntResult(3))
                .expect("hop response");
        });

        let mut handle = dummy_handle();
        handle.transport_tx = transport_tx;
        let options = LinkConnectOptions {
            path_timeout: Duration::from_secs(4),
            establishment_timeout: Some(Duration::ZERO),
            client_label: "example.client".to_string(),
            identify: true,
            track_phy_stats: true,
            inbound_reassembly_limit: Some(7),
        };
        let config = handle
            .resolve_link_session_config(destination_hash, &options)
            .await
            .unwrap();
        assert_eq!(config.destination_hash, destination_hash);
        assert_eq!(config.remote_public_key, remote_public_key);
        assert_eq!(config.hops, 3, "the path's hops, not the announce's");
        assert_eq!(config.establishment_timeout, Duration::ZERO);
        assert_eq!(config.client_label, "example.client");
        assert!(config.track_phy_stats);
        assert!(config.identify);
        assert_eq!(config.inbound_reassembly_limit, Some(7));
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

            let TransportMessage::RequestPath {
                destination_hash: dest,
            } = transport_rx.recv().await.expect("path discovery")
            else {
                panic!("expected explicit path request");
            };
            assert_eq!(dest, destination_hash);

            let TransportMessage::Rpc { response_tx, .. } =
                transport_rx.recv().await.expect("second recall")
            else {
                panic!("expected transport RPC");
            };
            response_tx
                .send(TransportQueryResponse::RecalledDestination(Some({
                    let mut entry = RecalledDestinationRpcEntry::default();
                    entry.dest_hash = destination_hash;
                    entry.public_key = remote_public_key;
                    entry.app_data = None;
                    entry.ratchet = None;
                    entry.hops = 7;
                    entry.timestamp = 1_700_000_001.0;
                    entry
                })))
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
                .send(TransportQueryResponse::RecalledDestination(Some({
                    let mut entry = RecalledDestinationRpcEntry::default();
                    entry.dest_hash = destination_hash;
                    entry.public_key = remote_public_key;
                    entry.app_data = None;
                    entry.ratchet = None;
                    entry.hops = 2;
                    entry.timestamp = 1_700_000_002.0;
                    entry
                })))
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
                    {
                        let mut entry = rns_transport::messages::PathTableRpcEntry::default();
                        entry.hash = [0x61; 16];
                        entry.timestamp = 1.0;
                        entry.via = None;
                        entry.hops = 2;
                        entry.expires = 2.0;
                        entry.value = None;
                        entry.used = 0.0;
                        entry.lr_cost = None;
                        entry.interface = "short".to_string();
                        entry.interface_id = 1;
                        entry.interface_mode = rns_transport::constants::InterfaceMode::Full;
                        entry.interface_role = rns_transport::messages::InterfaceRole::Normal;
                        entry
                    },
                    {
                        let mut entry = rns_transport::messages::PathTableRpcEntry::default();
                        entry.hash = [0x62; 16];
                        entry.timestamp = 1.0;
                        entry.via = None;
                        entry.hops = 8;
                        entry.expires = 2.0;
                        entry.value = None;
                        entry.used = 0.0;
                        entry.lr_cost = None;
                        entry.interface = "long".to_string();
                        entry.interface_id = 2;
                        entry.interface_mode = rns_transport::constants::InterfaceMode::Gateway;
                        entry.interface_role = rns_transport::messages::InterfaceRole::Normal;
                        entry
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
        let mut first = rns_transport::messages::InterfaceStatRpcEntry::default();
        first.id = 1;
        first.name = "one".to_string();
        first.rx_bytes = 10;
        first.tx_bytes = 20;
        first.rx_rate = 2;
        first.tx_rate = 3;
        first.online = true;
        first.bitrate = 115_200;
        first.mtu = 500;
        first.mode = "Full".to_string();
        first.role = "normal".to_string();
        first.announce_queue = Some(0);
        first.held_announces = 0;
        first.incoming_announce_frequency = 0.0;
        first.outgoing_announce_frequency = 0.0;
        first.incoming_pr_frequency = 0.0;
        first.outgoing_pr_frequency = 0.0;
        first.burst_active = false;
        first.burst_activated = 0.0;
        first.pr_burst_active = false;
        first.pr_burst_activated = 0.0;
        first.clients = None;
        first.blocked_ips = None;
        first.announce_rate_target = None;
        first.announce_rate_grace = None;
        first.announce_rate_penalty = None;
        first.announce_cap = 0.02;
        first.ifac_size = None;
        first.tx_drops = 0;
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
    async fn receipt_timeout_without_transport_answers_uses_upstream_fallbacks() {
        let handle = dummy_handle();
        assert_eq!(
            handle.default_packet_receipt_timeout([0x41; 16]).await,
            Duration::from_secs_f64(
                rns_wire::constants::DEFAULT_PER_HOP_TIMEOUT
                    * (1.0 + f64::from(rns_transport::constants::PATHFINDER_M))
            )
        );
    }

    #[test]
    fn client_blackhole_forwards_no_reason_for_an_unlabelled_entry() {
        use rns_transport::blackhole::BlackholeReason;
        let reason_of = |reason, reason_label: Option<&str>| match transport_query_to_rpc_request(
            &TransportQuery::BlackholeIdentity {
                hash: [0x31; 16],
                ttl: None,
                reason,
                reason_label: reason_label.map(str::to_string),
            },
        ) {
            Some(crate::rpc::RpcRequest::BlackholeIdentity { reason, .. }) => reason,
            other => panic!("unexpected request: {other:?}"),
        };
        assert_eq!(reason_of(BlackholeReason::Manual, None), None);
        assert_eq!(
            reason_of(BlackholeReason::Manual, Some("spam")).as_deref(),
            Some("spam")
        );
        assert_eq!(
            reason_of(BlackholeReason::RateLimit, None).as_deref(),
            Some("rate_limit")
        );
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
        let mut master_path = rns_transport::messages::PathTableRpcEntry::default();
        master_path.hash = destination_hash;
        master_path.timestamp = 1.0;
        master_path.via = Some([0x54; 16]);
        master_path.hops = 6;
        master_path.expires = 2.0;
        master_path.value = None;
        master_path.used = 0.0;
        master_path.lr_cost = None;
        master_path.interface = interface_name.clone();
        master_path.interface_id = 81;
        master_path.interface_mode = rns_transport::constants::InterfaceMode::Full;
        master_path.interface_role = rns_transport::messages::InterfaceRole::Normal;
        let mut master_interface = rns_transport::messages::InterfaceStatRpcEntry::default();
        master_interface.id = 81;
        master_interface.name = interface_name.clone();
        master_interface.rx_bytes = 0;
        master_interface.tx_bytes = 0;
        master_interface.rx_rate = 0;
        master_interface.tx_rate = 0;
        master_interface.online = true;
        master_interface.bitrate = 128_000;
        master_interface.mtu = 1_200;
        master_interface.mode = "Full".to_string();
        master_interface.role = "normal".to_string();
        master_interface.announce_queue = Some(0);
        master_interface.held_announces = 0;
        master_interface.incoming_announce_frequency = 0.0;
        master_interface.outgoing_announce_frequency = 0.0;
        master_interface.incoming_pr_frequency = 0.0;
        master_interface.outgoing_pr_frequency = 0.0;
        master_interface.burst_active = false;
        master_interface.burst_activated = 0.0;
        master_interface.pr_burst_active = false;
        master_interface.pr_burst_activated = 0.0;
        master_interface.clients = None;
        master_interface.blocked_ips = None;
        master_interface.announce_rate_target = None;
        master_interface.announce_rate_grace = None;
        master_interface.announce_rate_penalty = None;
        master_interface.announce_cap = 0.02;
        master_interface.ifac_size = None;
        master_interface.tx_drops = 0;
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
                    TransportQuery::GetTrafficTotals => {
                        TransportQueryResponse::TrafficTotals(Default::default())
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
                .next_hop_bitrate(ambiguous_destination)
                .await
                .unwrap(),
            None,
            "duplicate interface names must not select an arbitrary bitrate"
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
        assert_eq!(
            handle
                .next_hop_hardware_mtu(destination_hash)
                .await
                .unwrap(),
            Some(9),
            "a client's next hop is its own shared-instance interface"
        );

        rpc_shutdown.trigger();
        server.await.unwrap().unwrap();
        master_responder.abort();
        local_responder.abort();
    }

    struct StaticStamper;
    impl DiscoveryStamper for StaticStamper {
        fn generate(
            &self,
            _infohash: &[u8; 32],
            _target_value: f64,
            _ctl: &rns_identity::stamps::StampControl,
        ) -> Option<Vec<u8>> {
            Some(vec![0xAB; 32])
        }
        fn value(&self, _infohash: &[u8; 32], _stamp: &[u8]) -> f64 {
            16.0
        }
        fn valid(&self, _infohash: &[u8; 32], _stamp: &[u8], required_value: f64) -> bool {
            required_value <= 16.0
        }
    }

    fn discovery_actor() -> (ReticulumHandle, tokio::task::JoinHandle<()>) {
        let mut handle = dummy_handle();
        let mut options = rns_transport::actor::TransportActorOptions::default();
        options.static_transport_identity = true;
        let (actor, tx) = rns_transport::actor::TransportActor::new_with_options(
            4096,
            rns_transport::constants::HASHLIST_MAXSIZE,
            Default::default(),
            options,
        );
        tx.try_send(TransportMessage::SetTransportIdentity {
            identity_hash: handle.transport_identity.hash,
        })
        .unwrap();
        handle.transport_tx = tx;
        handle.announce_dispatch = actor.announce_dispatch_handle();
        (handle, tokio::spawn(actor.run()))
    }

    async fn discovery_egress(
        handle: &ReticulumHandle,
        id: u64,
        mode: rns_interface::traits::InterfaceMode,
        capacity: usize,
    ) -> (mpsc::Sender<Bytes>, mpsc::Receiver<Bytes>) {
        let (tx, rx) = mpsc::channel(capacity);
        let mut interface = test_interface_handle(id, None, "discovery-test-egress");
        interface.mode = mode;
        interface.tx = tx.clone();
        register_interface_handle(
            &handle.transport_tx,
            interface,
            &handle.interface_controls,
            &handle.interface_registry,
        )
        .await
        .unwrap();
        (tx, rx)
    }

    async fn run_discovery_announcer_with(
        handle: ReticulumHandle,
        stamper: Arc<dyn DiscoveryStamper + Send + Sync>,
        locals: Vec<LocalDiscoveryInterface>,
    ) {
        *handle.discovery.local_interfaces.lock().await = locals;
        run_discovery_announcer(handle, stamper).await;
    }

    fn advertised_service(id: u64, encrypted: bool) -> LocalDiscoveryInterface {
        let mut config = DiscoveryInterfaceConfig::backbone(
            Some(format!("service-{id}")),
            "relay.example.org".into(),
            4242,
        );
        config.encrypt = encrypted;
        LocalDiscoveryInterface {
            id,
            config,
            online: None,
            reachable_on: None,
            location_cmd: None,
        }
    }

    /// The link manager paces its tick on the std clock and spins under a
    /// paused clock, so the runtime never idles into auto-advance; step it.
    fn drive_paused_clock() -> tokio::task::JoinHandle<()> {
        tokio::spawn(async {
            loop {
                tokio::time::advance(Duration::from_millis(250)).await;
                // Lets blocking stamp jobs finish within a step of tokio time.
                std::thread::sleep(Duration::from_millis(1));
            }
        })
    }

    fn read_discovery_packet(
        raw: &[u8],
        handle: &ReticulumHandle,
    ) -> rns_transport::discovery::app_data::DiscoveryInfo {
        let (header, offset) = rns_wire::header::PacketHeader::unpack(raw).unwrap();
        let announce =
            rns_identity::announce::AnnounceData::unpack(&raw[offset..], header.flags.context_flag)
                .unwrap();
        let signer = announce.validate(&header.destination_hash).unwrap();
        assert_eq!(
            signer.hash,
            handle
                .network_identity
                .as_ref()
                .unwrap_or(&handle.transport_identity)
                .hash
        );
        let blob = announce.app_data.unwrap();
        let body = if blob[0] & rns_transport::discovery::constants::FLAG_ENCRYPTED != 0 {
            handle
                .network_identity
                .as_ref()
                .unwrap()
                .decrypt(&blob[1..], None, false)
                .unwrap()
        } else {
            blob[1..].to_vec()
        };
        let info =
            rns_transport::discovery::app_data::decode_info(&body[..body.len() - 32]).unwrap();
        assert_eq!(info.transport_id, handle.transport_identity.hash);
        assert_eq!([info.latitude, info.longitude, info.height], [None; 3]);
        info
    }

    #[tokio::test(start_paused = true)]
    async fn discovery_publisher_registers_selected_signer_and_multiple_services() {
        let _stamps = crate::destination_stamper::test_settings::unstamped().await;
        let _clock = drive_paused_clock();
        use rns_interface::traits::InterfaceMode;
        let mut runs = Vec::new();
        for (mode, network, encrypted) in [
            (InterfaceMode::Full, false, false),
            (InterfaceMode::Gateway, true, false),
            (InterfaceMode::Boundary, true, true),
        ] {
            runs.push(tokio::spawn(async move {
                let (mut handle, actor) = discovery_actor();
                if network {
                    handle.network_identity = Some(Arc::new(Identity::new()));
                }
                let (_, mut sink) = discovery_egress(&handle, 1, mode, 8).await;
                let mut radio = advertised_service(43, encrypted);
                radio.config.interface_type = "RNodeInterface".into();
                radio.config.reachable_on = None;
                radio.config.port = None;
                radio.config.frequency = Some(915_000_000);
                radio.config.bandwidth = Some(125_000);
                radio.config.spreading_factor = Some(8);
                radio.config.coding_rate = Some(5);
                let publisher = tokio::spawn(run_discovery_announcer_with(
                    handle.clone(),
                    Arc::new(StaticStamper),
                    vec![advertised_service(42, encrypted), radio],
                ));
                // Python waits one job interval, then announces one interface per pass.
                let started = tokio::time::Instant::now();
                let mut names = HashSet::new();
                let mut arrivals = Vec::new();
                for _ in 0..2 {
                    let raw = tokio::time::timeout(Duration::from_secs(70), sink.recv())
                        .await
                        .unwrap()
                        .unwrap();
                    arrivals.push(started.elapsed());
                    names.insert(read_discovery_packet(&raw, &handle).name);
                }
                assert!(arrivals[0] >= Duration::from_secs(60), "{arrivals:?}");
                assert!(
                    arrivals[1] - arrivals[0] >= Duration::from_secs(60),
                    "{arrivals:?}"
                );
                assert_eq!(
                    names,
                    HashSet::from(["service-42".to_string(), "service-43".to_string()])
                );
                assert!(
                    tokio::time::timeout(Duration::from_millis(1200), sink.recv())
                        .await
                        .is_err(),
                    "admitted services must not replay"
                );
                handle.shutdown.trigger();
                tokio::time::timeout(Duration::from_secs(2), publisher)
                    .await
                    .unwrap()
                    .unwrap();
                handle
                    .transport_tx
                    .send(TransportMessage::Shutdown)
                    .await
                    .unwrap();
                actor.await.unwrap();
            }));
        }
        for run in runs {
            run.await.unwrap();
        }
    }

    /// An interface announces the address it learns at runtime
    /// (Discovery.py); a later change waits for the interval instead
    /// of announcing at once, so a flapping address cannot flood announces.
    #[tokio::test(start_paused = true)]
    async fn discovery_publisher_announces_a_learned_address_on_its_interval() {
        let _stamps = crate::destination_stamper::test_settings::unstamped().await;
        let _clock = drive_paused_clock();
        use rns_interface::traits::InterfaceMode;
        let (handle, actor) = discovery_actor();
        let (_, mut sink) = discovery_egress(&handle, 1, InterfaceMode::Full, 8).await;
        let (address, reachable_on) = tokio::sync::watch::channel(Some("a".repeat(52)));
        let mut i2p = advertised_service(44, false);
        i2p.config.interface_type = "I2PInterface".into();
        i2p.config.reachable_on = None;
        i2p.config.port = None;
        i2p.reachable_on = Some(reachable_on);
        let publisher = tokio::spawn(run_discovery_announcer_with(
            handle.clone(),
            Arc::new(StaticStamper),
            vec![i2p],
        ));
        let raw = tokio::time::timeout(Duration::from_secs(70), sink.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            read_discovery_packet(&raw, &handle).reachable_on,
            Some("a".repeat(52))
        );
        address.send_replace(Some("b".repeat(52)));
        assert!(
            tokio::time::timeout(Duration::from_millis(1500), sink.recv())
                .await
                .is_err(),
            "a changed address waits for the announce interval"
        );
        handle.shutdown.trigger();
        tokio::time::timeout(Duration::from_secs(2), publisher)
            .await
            .unwrap()
            .unwrap();
        handle
            .transport_tx
            .send(TransportMessage::Shutdown)
            .await
            .unwrap();
        actor.await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn discovery_publisher_recovers_eligibility_fifo_and_services_attached_path_requests() {
        let _stamps = crate::destination_stamper::test_settings::unstamped().await;
        let _clock = drive_paused_clock();
        use rns_interface::traits::InterfaceMode;
        let (mut handle, actor) = discovery_actor();
        handle.network_identity = Some(Arc::new(Identity::new()));
        let (ap_tx, mut ap) = discovery_egress(&handle, 1, InterfaceMode::AccessPoint, 1).await;
        let online = Arc::new(AtomicBool::new(false));
        let mut local = advertised_service(42, false);
        local.online = Some(online.clone());
        let publisher = tokio::spawn(run_discovery_announcer_with(
            handle.clone(),
            Arc::new(StaticStamper),
            vec![local],
        ));
        assert!(
            tokio::time::timeout(Duration::from_millis(1100), ap.recv())
                .await
                .is_err()
        );
        online.store(true, Ordering::Release);
        assert!(
            tokio::time::timeout(Duration::from_millis(1100), ap.recv())
                .await
                .is_err(),
            "AP is never general discovery egress"
        );
        let (full_tx, mut full) = discovery_egress(&handle, 2, InterfaceMode::Full, 1).await;
        full_tx.send(Bytes::from_static(b"busy")).await.unwrap();
        tokio::time::sleep(Duration::from_secs(61)).await;
        assert_eq!(full.recv().await.unwrap(), Bytes::from_static(b"busy"));
        let raw = tokio::time::timeout(Duration::from_secs(3), full.recv())
            .await
            .unwrap()
            .unwrap();
        read_discovery_packet(&raw, &handle);
        let (header, _) = rns_wire::header::PacketHeader::unpack(&raw).unwrap();
        assert!(
            matches!(handle.query_transport(TransportQuery::GetNextHop { dest: header.destination_hash }).await, Some(TransportQueryResponse::HashResult(Some(hash))) if hash == handle.transport_identity.hash)
        );

        // Reply ownership must survive a full *attached* AP channel too.
        ap_tx.send(Bytes::from_static(b"busy-path")).await.unwrap();
        let path_destination = rns_identity::destination::Destination::hash_from_name_and_identity(
            "rnstransport.path.request",
            None,
        );
        let mut body = header.destination_hash.to_vec();
        body.extend_from_slice(&[0xA7; 16]);
        let ap_owner = handle.interface_controls.lock().unwrap()[&1]
            .transport_owner
            .clone();
        rns_transport::InterfaceTransportSender::bind(1, ap_owner, handle.transport_tx.clone())
            .send(TransportMessage::Inbound(
                rns_transport::messages::InboundPacket {
                    raw: make_plain_data_packet(path_destination, &body),
                    interface_id: 1,
                    rssi: None,
                    snr: None,
                    q: None,
                },
            ))
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(250)).await;
        assert_eq!(ap.recv().await.unwrap(), Bytes::from_static(b"busy-path"));
        let response = tokio::time::timeout(Duration::from_secs(3), ap.recv())
            .await
            .unwrap()
            .unwrap();
        let (reply_header, offset) = rns_wire::header::PacketHeader::unpack(&response).unwrap();
        assert_eq!(reply_header.destination_hash, header.destination_hash);
        assert_eq!(
            reply_header.context,
            rns_wire::context::PacketContext::PathResponse
        );
        let reply = rns_identity::announce::AnnounceData::unpack(
            &response[offset..],
            reply_header.flags.context_flag,
        )
        .unwrap();
        assert_eq!(
            reply.validate(&reply_header.destination_hash).unwrap().hash,
            handle.network_identity.as_ref().unwrap().hash
        );
        assert!(
            reply.app_data.is_none(),
            "one service must not become arbitrary path-response metadata"
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(1100), full.recv())
                .await
                .is_err()
        );
        handle.shutdown.trigger();
        tokio::time::timeout(Duration::from_secs(2), publisher)
            .await
            .unwrap()
            .unwrap();
        assert!(
            matches!(
                handle
                    .query_transport(TransportQuery::GetNextHop {
                        dest: header.destination_hash
                    })
                    .await,
                Some(TransportQueryResponse::HashResult(None))
            ),
            "publisher close must deregister the destination"
        );
        handle
            .transport_tx
            .send(TransportMessage::Shutdown)
            .await
            .unwrap();
        actor.await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn discovery_publisher_recalls_pending_service_when_it_goes_offline() {
        let _stamps = crate::destination_stamper::test_settings::unstamped().await;
        let _clock = drive_paused_clock();
        struct CountedStamper(AtomicU64);
        impl DiscoveryStamper for CountedStamper {
            fn generate(
                &self,
                hash: &[u8; 32],
                value: f64,
                ctl: &rns_identity::stamps::StampControl,
            ) -> Option<Vec<u8>> {
                self.0.fetch_add(1, Ordering::Relaxed);
                StaticStamper.generate(hash, value, ctl)
            }
            fn value(&self, hash: &[u8; 32], stamp: &[u8]) -> f64 {
                StaticStamper.value(hash, stamp)
            }
            fn valid(&self, hash: &[u8; 32], stamp: &[u8], value: f64) -> bool {
                StaticStamper.valid(hash, stamp, value)
            }
        }
        let (handle, actor) = discovery_actor();
        let (tx, mut sink) =
            discovery_egress(&handle, 1, rns_interface::traits::InterfaceMode::Full, 1).await;
        tx.send(Bytes::from_static(b"busy")).await.unwrap();
        let online = Arc::new(AtomicBool::new(true));
        let mut local = advertised_service(42, false);
        local.online = Some(online.clone());
        let stamper = Arc::new(CountedStamper(AtomicU64::new(0)));
        let publisher = tokio::spawn(run_discovery_announcer_with(
            handle.clone(),
            stamper.clone(),
            vec![local],
        ));
        tokio::time::sleep(Duration::from_secs(61)).await;
        real_time_until("the search runs", || stamper.0.load(Ordering::Relaxed) == 1).await;
        online.store(false, Ordering::Release);
        tokio::time::sleep(Duration::from_millis(1100)).await;
        assert_eq!(sink.recv().await.unwrap(), Bytes::from_static(b"busy"));
        assert!(
            tokio::time::timeout(Duration::from_millis(1100), sink.recv())
                .await
                .is_err(),
            "a freed egress must not publish an offline service"
        );
        online.store(true, Ordering::Release);
        let raw = tokio::time::timeout(Duration::from_secs(3), sink.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(read_discovery_packet(&raw, &handle).name, "service-42");
        assert_eq!(
            stamper.0.load(Ordering::Relaxed),
            1,
            "recovery reuses prepared work"
        );
        handle.shutdown.trigger();
        tokio::time::timeout(Duration::from_secs(2), publisher)
            .await
            .unwrap()
            .unwrap();
        handle
            .transport_tx
            .send(TransportMessage::Shutdown)
            .await
            .unwrap();
        actor.await.unwrap();
    }

    /// Waits in real time on a blocking stamp thread: the driven paused clock
    /// would lapse a tokio timeout before the thread's next poll.
    async fn real_time_until(what: &str, done: impl Fn() -> bool) {
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while !done() {
            assert!(std::time::Instant::now() < deadline, "{what}");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    /// Holds every search after the first `free` until released or cancelled.
    struct GatedStamper {
        free: u64,
        calls: AtomicU64,
        release: AtomicBool,
        resumed: AtomicBool,
        cancelled: AtomicBool,
    }

    impl GatedStamper {
        fn new(free: u64) -> Arc<Self> {
            Arc::new(Self {
                free,
                calls: AtomicU64::new(0),
                release: AtomicBool::new(false),
                resumed: AtomicBool::new(false),
                cancelled: AtomicBool::new(false),
            })
        }
    }

    impl DiscoveryStamper for GatedStamper {
        fn generate(
            &self,
            hash: &[u8; 32],
            value: f64,
            ctl: &rns_identity::stamps::StampControl,
        ) -> Option<Vec<u8>> {
            if self.calls.fetch_add(1, Ordering::Relaxed) >= self.free {
                while !self.release.load(Ordering::Relaxed) {
                    if ctl.cancel.load(Ordering::Relaxed) {
                        self.cancelled.store(true, Ordering::Relaxed);
                        return None;
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
                self.resumed.store(true, Ordering::Relaxed);
            }
            StaticStamper.generate(hash, value, ctl)
        }
        fn value(&self, hash: &[u8; 32], stamp: &[u8]) -> f64 {
            StaticStamper.value(hash, stamp)
        }
        fn valid(&self, hash: &[u8; 32], stamp: &[u8], value: f64) -> bool {
            StaticStamper.valid(hash, stamp, value)
        }
    }

    #[tokio::test(start_paused = true)]
    async fn discovery_publisher_sends_once_when_admitted_during_generation() {
        let _stamps = crate::destination_stamper::test_settings::unstamped().await;
        let _clock = drive_paused_clock();
        let (handle, actor) = discovery_actor();
        let (tx, mut sink) =
            discovery_egress(&handle, 1, rns_interface::traits::InterfaceMode::Full, 1).await;
        tx.send(Bytes::from_static(b"busy")).await.unwrap();
        let second_online = Arc::new(AtomicBool::new(false));
        let mut second = advertised_service(43, false);
        second.online = Some(second_online.clone());
        let stamper = GatedStamper::new(1);
        let publisher = tokio::spawn(run_discovery_announcer_with(
            handle.clone(),
            stamper.clone(),
            vec![advertised_service(42, false), second],
        ));
        // The first service is prepared and waits behind the full egress.
        tokio::time::sleep(Duration::from_secs(61)).await;
        second_online.store(true, Ordering::Release);
        // The next pass picks the never-announced second service.
        tokio::time::sleep(Duration::from_secs(65)).await;
        real_time_until("the second search starts", || {
            stamper.calls.load(Ordering::Relaxed) == 2
        })
        .await;
        // It is admitted while the second service's stamp is still generating.
        assert_eq!(sink.recv().await.unwrap(), Bytes::from_static(b"busy"));
        let raw = tokio::time::timeout(Duration::from_secs(3), sink.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(read_discovery_packet(&raw, &handle).name, "service-42");
        // Generation outlasts the job interval; Python sleeps a full interval after it.
        tokio::time::sleep(Duration::from_secs(70)).await;
        stamper.release.store(true, Ordering::Relaxed);
        real_time_until("the held search resumes", || {
            stamper.resumed.load(Ordering::Relaxed)
        })
        .await;
        let raw = tokio::time::timeout(Duration::from_secs(4), sink.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(read_discovery_packet(&raw, &handle).name, "service-43");
        assert!(
            tokio::time::timeout(Duration::from_secs(55), sink.recv())
                .await
                .is_err(),
            "an admitted service must not be sent again"
        );
        handle.shutdown.trigger();
        tokio::time::timeout(Duration::from_secs(2), publisher)
            .await
            .unwrap()
            .unwrap();
        handle
            .transport_tx
            .send(TransportMessage::Shutdown)
            .await
            .unwrap();
        actor.await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn discovery_publisher_cancels_generation_when_it_stops() {
        let _clock = drive_paused_clock();
        for abort in [false, true] {
            let (handle, actor) = discovery_actor();
            let stamper = GatedStamper::new(0);
            let publisher = tokio::spawn(run_discovery_announcer_with(
                handle.clone(),
                stamper.clone(),
                vec![advertised_service(42, false)],
            ));
            tokio::time::sleep(Duration::from_secs(61)).await;
            real_time_until("the search starts", || {
                stamper.calls.load(Ordering::Relaxed) == 1
            })
            .await;
            if abort {
                publisher.abort();
            } else {
                handle.shutdown.trigger();
            }
            real_time_until("the search is cancelled", || {
                stamper.cancelled.load(Ordering::Relaxed)
            })
            .await;
            let stopped = tokio::time::timeout(Duration::from_secs(2), publisher)
                .await
                .unwrap();
            if abort {
                assert!(stopped.unwrap_err().is_cancelled());
            } else {
                stopped.unwrap();
            }
            handle
                .transport_tx
                .send(TransportMessage::Shutdown)
                .await
                .unwrap();
            actor.await.unwrap();
        }
    }

    #[tokio::test(start_paused = true)]
    async fn discovery_enable_is_single_owner_and_clients_do_not_publish() {
        let _stamps = crate::destination_stamper::test_settings::unstamped().await;
        let _clock = drive_paused_clock();
        use rns_interface::traits::InterfaceMode;
        let (mut handle, actor) = discovery_actor();
        let (_, mut sink) = discovery_egress(&handle, 1, InterfaceMode::Full, 8).await;
        let dir = std::env::temp_dir().join(format!(
            "discovery-owner-{}-{}",
            std::process::id(),
            unix_now()
        ));
        handle
            .install_discovery_store_for_tests(Arc::new(DiscoveryStore::open(&dir).unwrap()))
            .await;
        handle
            .discovery
            .local_interfaces
            .lock()
            .await
            .push(advertised_service(42, false));
        handle.instance_mode = InstanceMode::Client;
        handle
            .enable_on_network_discovery(Arc::new(StaticStamper))
            .await;
        assert!(!*handle.discovery.announcer_started.lock().await);
        assert!(sink.try_recv().is_err());
        handle.instance_mode = InstanceMode::Standalone;
        handle
            .enable_on_network_discovery(Arc::new(StaticStamper))
            .await;
        handle
            .enable_on_network_discovery(Arc::new(StaticStamper))
            .await;
        read_discovery_packet(
            &tokio::time::timeout(Duration::from_secs(70), sink.recv())
                .await
                .unwrap()
                .unwrap(),
            &handle,
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(1100), sink.recv())
                .await
                .is_err()
        );
        handle.shutdown.trigger();
        tokio::time::timeout(Duration::from_secs(2), async {
            while *handle.discovery.announcer_started.lock().await {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        handle
            .transport_tx
            .send(TransportMessage::Shutdown)
            .await
            .unwrap();
        actor.await.unwrap();
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn network_discovery_requires_explicit_reachable_on() {
        for endpoint in [
            "type = TCPServerInterface\nlisten_ip = 192.0.2.10\nlisten_port = 4242\n",
            "type = BackboneInterface\nlisten_on = 192.0.2.10\nport = 4242\n",
            "type = BackboneInterface\ntarget_host = relay.example.org\nport = 4242\n",
        ] {
            let config = Config::parse(&format!(
                "[interfaces]\n[[relay]]\nenabled = yes\ndiscoverable = yes\n{endpoint}"
            ))
            .unwrap();
            let interfaces = synthesize_interfaces(&config, None).unwrap();
            let post_init = get_post_init_for_config(&config, &interfaces[0]).unwrap();
            assert!(
                discovery_config_for_interface(
                    &config,
                    &interfaces[0],
                    &post_init,
                    true,
                    &rns_transport::stamps::StampPolicy::default(),
                )
                .unwrap()
                .is_none()
            );
        }
    }

    /// Python reads only `reachable_on` (Reticulum.py), and a Backbone
    /// client is a `BackboneClientInterface`, which never supports discovery
    /// (Reticulum.py, Discovery.py, BackboneInterface.py).
    #[test]
    fn network_discovery_uses_the_configured_reachable_on() {
        let discovery = |endpoint: &str, key: &str| {
            let config = Config::parse(&format!(
                "[interfaces]\n[[relay]]\nenabled = yes\ndiscoverable = yes\n{endpoint}{key} = published.example.org\n"
            ))
            .unwrap();
            let interfaces = synthesize_interfaces(&config, None).unwrap();
            let post_init = get_post_init_for_config(&config, &interfaces[0]).unwrap();
            discovery_config_for_interface(
                &config,
                &interfaces[0],
                &post_init,
                true,
                &rns_transport::stamps::StampPolicy::default(),
            )
            .unwrap()
        };
        for server in [
            "type = TCPServerInterface\nlisten_ip = 192.0.2.10\nlisten_port = 4242\n",
            "type = BackboneInterface\nlisten_on = 192.0.2.10\nport = 4242\n",
        ] {
            let announced = discovery(server, "reachable_on").unwrap();
            assert_eq!(
                announced.reachable_on.as_deref(),
                Some("published.example.org")
            );
            assert_eq!(announced.port, Some(4242));
            assert!(discovery(server, "discovery_reachable_on").is_none());
        }
        let client = "type = BackboneInterface\ntarget_host = relay.example.org\nport = 4242\n";
        assert!(discovery(client, "reachable_on").is_none());
    }

    #[test]
    fn discovery_config_preserves_independent_location_presence_and_precedence() {
        for (extra, expected) in [
            ("", [None, None, None]),
            ("latitude = 0\nheight = 0\n", [Some(0.0), None, Some(0.0)]),
            (
                "longitude = -2\ndiscovery_longitude = 0\n",
                [None, Some(0.0), None],
            ),
        ] {
            let config = Config::parse(&format!("[interfaces]\n[[relay]]\ntype = TCPServerInterface\nenabled = yes\nlisten_ip = 127.0.0.1\nlisten_port = 4242\ndiscoverable = yes\nreachable_on = relay.example.org\n{extra}")).unwrap();
            let interfaces = synthesize_interfaces(&config, None).unwrap();
            let post_init = get_post_init_for_config(&config, &interfaces[0]).unwrap();
            let discovery = discovery_config_for_interface(
                &config,
                &interfaces[0],
                &post_init,
                true,
                &rns_transport::stamps::StampPolicy::default(),
            )
            .unwrap()
            .unwrap();
            assert_eq!(
                [discovery.latitude, discovery.longitude, discovery.height],
                expected
            );
        }
    }

    /// Upstream sends a nil name without `discovery_name`, announces only a
    /// valid `reachable_on`, and fails startup on a discovery key it cannot
    /// parse (Reticulum.py, Discovery.py).
    #[test]
    fn discovery_keys_parse_like_upstream() {
        let discovery = |extra: &str| {
            let config = Config::parse(&format!("[interfaces]\n[[relay]]\ntype = TCPServerInterface\nenabled = yes\nlisten_ip = 127.0.0.1\nlisten_port = 4242\ndiscoverable = yes\n{extra}")).unwrap();
            let interfaces = synthesize_interfaces(&config, None).unwrap();
            let post_init = get_post_init_for_config(&config, &interfaces[0]).unwrap();
            discovery_config_for_interface(
                &config,
                &interfaces[0],
                &post_init,
                true,
                &rns_transport::stamps::StampPolicy::default(),
            )
        };
        let unnamed = discovery("reachable_on = relay.example.org\n")
            .unwrap()
            .unwrap();
        assert_eq!(unnamed.name, None);
        assert_eq!(unnamed.announce_interval_secs, 6 * 60 * 60);
        let named = discovery("reachable_on = relay.example.org.\ndiscovery_name =  Relay \nannounce_interval = 1\ndiscovery_lxmf_address = 000102030405060708090a0b0c0d0e0f\n").unwrap().unwrap();
        assert_eq!(named.name.as_deref(), Some("Relay"));
        assert_eq!(named.reachable_on.as_deref(), Some("relay.example.org."));
        assert_eq!(named.announce_interval_secs, 5 * 60);
        assert_eq!(
            named.operator_lxmf_address,
            Some(std::array::from_fn(|i| i as u8))
        );
        for invalid in ["1.2.3.999", "my_host.example.org", "not a host"] {
            let skipped = discovery(&format!("reachable_on = {invalid}\n")).unwrap();
            assert!(skipped.is_none(), "{invalid}");
        }
        for bad in [
            "discovery_stamp_value = abc",
            "discovery_modulation = AFSK",
            "discovery_frequency = 868e6",
            "latitude = north",
            "announce_interval = 1.5",
            "discovery_encrypt = maybe",
            "publish_ifac = sometimes",
        ] {
            assert!(
                discovery(&format!("reachable_on = relay.example.org\n{bad}\n")).is_err(),
                "{bad}"
            );
        }
    }

    /// Python announces a KISS-framed TCP client as a KISS interface with its
    /// discovery radio parameters and no address (Discovery.py).
    #[test]
    fn a_kiss_framed_tcp_client_is_discovered_as_a_kiss_interface() {
        let config = Config::parse("[interfaces]\n[[kiss tnc]]\ntype = TCPClientInterface\nenabled = yes\nkiss_framing = yes\ntarget_host = 10.0.0.2\ntarget_port = 8001\ndiscoverable = yes\ndiscovery_frequency = 433775000\ndiscovery_modulation = 2\ndiscovery_spreading_factor = 7\ndiscovery_coding_rate = 5\ndiscovery_channel = 3\nreachable_on = 10.0.0.2\n").unwrap();
        let interfaces = synthesize_interfaces(&config, None).unwrap();
        let post_init = get_post_init_for_config(&config, &interfaces[0]).unwrap();
        let discovery = discovery_config_for_interface(
            &config,
            &interfaces[0],
            &post_init,
            true,
            &rns_transport::stamps::StampPolicy::default(),
        )
        .unwrap()
        .unwrap();
        assert_eq!(discovery.interface_type, "KISSInterface");
        assert_eq!((discovery.reachable_on, discovery.port), (None, None));
        assert_eq!(discovery.frequency, Some(433_775_000));
        assert_eq!(
            discovery.modulation,
            Some(rns_transport::discovery::app_data::DiscoveryModulation::Int(2))
        );
        assert_eq!(
            (
                discovery.spreading_factor,
                discovery.coding_rate,
                discovery.channel
            ),
            (None, None, None)
        );
    }

    /// Serial KISS/AX.25 never announce; RNode announces its own radio, no address (Interface.py).
    #[cfg(feature = "serial")]
    #[test]
    fn only_upstream_discoverable_radio_types_announce() {
        let discovery = |iface: &str| {
            let config = Config::parse(&format!("[interfaces]\n[[radio]]\nenabled = yes\ndiscoverable = yes\nreachable_on = 10.0.0.2\ndiscovery_frequency = 1\ndiscovery_spreading_factor = 12\ndiscovery_modulation = 2\n{iface}")).unwrap();
            let interfaces = synthesize_interfaces(&config, None).unwrap();
            let post_init = get_post_init_for_config(&config, &interfaces[0]).unwrap();
            discovery_config_for_interface(
                &config,
                &interfaces[0],
                &post_init,
                true,
                &rns_transport::stamps::StampPolicy::default(),
            )
            .unwrap()
        };
        for kiss in [
            "type = KISSInterface\nport = /dev/null\n",
            "type = AX25KISSInterface\nport = /dev/null\ncallsign = NOCALL\nssid = 0\n",
        ] {
            assert!(discovery(kiss).is_none(), "{kiss}");
        }
        let rnode = discovery("type = RNodeInterface\nport = /dev/null\nfrequency = 868000000\nbandwidth = 125000\nspreadingfactor = 8\ncodingrate = 5\ntxpower = 7\n").unwrap();
        assert_eq!(rnode.reachable_on, None);
        assert_eq!(
            (rnode.frequency, rnode.spreading_factor, rnode.modulation),
            (Some(868_000_000), Some(8), None)
        );
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

    /// Python's `autoconnect_unverified_implementations` (Reticulum.py).
    #[test]
    fn autoconnect_unverified_implementations_is_parsed_and_off_by_default() {
        assert!(!ReticulumConfig::default().autoconnect_unverified_implementations);
        let rc = ReticulumConfig::from_config(
            &Config::parse("[reticulum]\nautoconnect_unverified_implementations = Yes\n").unwrap(),
        );
        assert!(rc.autoconnect_unverified_implementations);
    }

    /// Only Backbone interfaces from RNS 1.5.7 or rsRNS 1.5.0 or later, unless
    /// unverified stacks are allowed (Discovery.py; rsRNS is ours).
    #[test]
    fn discovered_interfaces_auto_connect_by_stack_and_release() {
        let record = |interface_type: &str, impl_name: Option<&str>, version: Option<&str>| {
            DiscoveredInterface {
                info: rns_transport::discovery::app_data::DiscoveryInfo {
                    interface_type: interface_type.into(),
                    impl_name: impl_name.map(str::to_string),
                    impl_version: version.map(str::to_string),
                    transport_enabled: true,
                    reachable_on: Some("192.0.2.10".into()),
                    port: Some(4242),
                    ..Default::default()
                },
                network_id: [0x51; 16],
                hops: 1,
                stamp_value: 16.0,
                stamp: vec![0; 32],
                discovered: 0.0,
                last_heard: 0.0,
                heard_count: 1,
                status: None,
            }
        };
        let mut config = ReticulumConfig::default();
        for admitted in [
            record("BackboneInterface", Some("RNS"), Some("1.6.0")),
            record(
                "BackboneInterface",
                Some("rsRNS"),
                Some(rns_transport::discovery::constants::IMPLEMENTATION_VERSION),
            ),
        ] {
            assert!(
                autoconnect_admits(&admitted, &config),
                "{:?}",
                admitted.info
            );
        }
        for rejected in [
            record("TCPServerInterface", Some("RNS"), Some("1.5.5")),
            record("BackboneInterface", Some("RNS"), Some("1.5.6")),
            record("BackboneInterface", Some("rsRNS"), Some("1.4.0")),
            record("BackboneInterface", Some("MeshChatX"), Some("9.9.9")),
            record("BackboneInterface", None, None),
        ] {
            assert!(
                !autoconnect_admits(&rejected, &config),
                "{:?}",
                rejected.info
            );
        }
        config.autoconnect_unverified_implementations = true;
        for admitted in [
            record("BackboneInterface", Some("RNS"), Some("1.5.6")),
            record("BackboneInterface", Some("rsRNS"), Some("1.4.0")),
            record("BackboneInterface", Some("MeshChatX"), Some("9.9.9")),
            record("BackboneInterface", None, None),
        ] {
            assert!(
                autoconnect_admits(&admitted, &config),
                "{:?}",
                admitted.info
            );
        }
        assert!(!autoconnect_admits(
            &record("TCPServerInterface", None, None),
            &config
        ));
    }

    #[test]
    fn test_discovery_defaults_are_off() {
        let rc = ReticulumConfig::default();
        assert!(!rc.discover_interfaces);
        assert_eq!(rc.autoconnect_discovered_interfaces, 0);
        assert_eq!(
            rc.discover_interfaces_required_value,
            rns_transport::discovery::constants::DEFAULT_STAMP_VALUE
        );
        assert_eq!(rc.network_identity_path, None);
        assert!(rc.interface_discovery_sources.is_empty());
        assert!(rc.blackhole_sources.is_empty());
        assert!(!rc.publish_blackhole);
        assert!(rc.bootstrap_configs.is_empty());
    }

    #[test]
    fn autoconnect_targets_above_twelve_are_capped_unless_caps_are_disabled() {
        for (keys, expected) in [
            ("autoconnect_discovered_interfaces = 6\n", 6),
            ("autoconnect_discovered_interfaces = 9\n", 9),
            ("autoconnect_discovered_interfaces = 13\n", 12),
            ("discover_interfaces_autoconnect = 40\n", 12),
            (
                "autoconnect_discovered_interfaces = 40\n\
                 autoconnect_discovered_interfaces_disable_caps = Yes\n",
                40,
            ),
            (
                "autoconnect_discovered_interfaces_disable_caps = No\n\
                 autoconnect_discovered_interfaces = 40\n",
                12,
            ),
        ] {
            let config = Config::parse(&format!("[reticulum]\n{keys}")).unwrap();
            let rc = ReticulumConfig::from_config(&config);
            assert_eq!(rc.autoconnect_discovered_interfaces, expected, "{keys}");
        }
        assert_eq!(cap_autoconnect_limit(0, false), 0);
        assert_eq!(cap_autoconnect_limit(12, false), 12);
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
                     autoconnect_announces_to_internal = Yes\n\
                     publish_blackhole = Yes\n\
                     network_identity = /opt/rnsd/network.identity\n";
        let config = Config::parse(input).unwrap();
        let rc = ReticulumConfig::from_config(&config);
        assert!(rc.discover_interfaces);
        assert_eq!(rc.autoconnect_discovered_interfaces, 2);
        assert_eq!(rc.discover_interfaces_required_value, 16.0);
        assert_eq!(rc.interface_discovery_sources.len(), 1);
        assert_eq!(rc.default_ar_target, Some(7200));
        assert_eq!(rc.default_ar_penalty, Some(30));
        assert_eq!(rc.default_ar_grace, Some(9));
        assert_eq!(rc.autoconnect_announces_to_internal, Some(true));
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

    /// Python Reticulum.py parity: discoverable interfaces are
    /// auto-corrected to Gateway/AP mode unless already Internal or
    /// `ignore_config_warnings` is enabled.
    #[test]
    fn discovery_mode_autocorrect_matches_python() {
        use rns_interface::traits::InterfaceMode;

        let input = "[interfaces]\n\
                     [[upstream]]\n\
                     type = TCPServerInterface\n\
                     enabled = yes\n\
                     listen_ip = 0.0.0.0\n\
                     listen_port = 4242\n\
                     discoverable = yes\n";
        let config = Config::parse(input).unwrap();
        let mut interfaces = synthesize_interfaces(&config, None).unwrap();
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
                         enabled = yes\n\
                         listen_ip = 0.0.0.0\n\
                         listen_port = 4242\n\
                         discoverable = yes\n\
                         ignore_config_warnings = yes\n";
        let config = Config::parse(opted_out).unwrap();
        let mut interfaces = synthesize_interfaces(&config, None).unwrap();
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
enabled = yes
target_host = 127.0.0.1
target_port = 4242
ic_pr_burst_freq = 5
egress_control = Yes
"#;
        let config = Config::parse(input).unwrap();
        let rc = ReticulumConfig::from_config(&config);
        let interfaces = synthesize_interfaces(&config, None).unwrap();
        let mut post_init = get_post_init_for_config(&config, &interfaces[0]).unwrap();

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

        // Python Transport.py: transport nodes never rotate.
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
        // Python Transport.py: (rand_byte % 6) + 2 = 2..=7.
        for _ in 0..256 {
            let delta = generate_local_hops_delta();
            assert!((2..=7).contains(&delta), "delta {delta} out of range");
        }
    }

    #[test]
    fn blackhole_update_interval_parses_minutes_with_two_minute_clamp() {
        let rc = ReticulumConfig::from_config(&Config::parse("[reticulum]\n").unwrap());
        assert_eq!(rc.blackhole_update_interval, 3600.0);

        // Reticulum.py: minutes ×60 into seconds.
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
        let post_init =
            interface_factory::InterfacePostInit::try_from_section(&ConfigSection::new())
                .expect("empty interface defaults are valid");
        assert!(!post_init.recursive_prs);
        assert!(post_init.announces_from_internal);
        assert_eq!(post_init.announces_to_internal, None);

        let mut section = ConfigSection::new();
        section.set("recursive_prs", "yes");
        section.set("announces_from_internal", "no");
        section.set("announces_to_internal", "yes");
        let post_init = interface_factory::InterfacePostInit::try_from_section(&section).unwrap();
        assert!(post_init.recursive_prs);
        assert!(!post_init.announces_from_internal);
        assert_eq!(post_init.announces_to_internal, Some(true));
    }

    #[test]
    fn internal_interface_mode_parses_and_discovery_autocorrects() {
        // Python 1.3.8 Reticulum.py: mode = internal → MODE_INTERNAL.
        let base = "[interfaces]\n\n[[Test TCP]]\ntype = TCPClientInterface\nenabled = yes\n\
                    target_host = 127.0.0.1\ntarget_port = 4242\nmode = internal\n";
        let config = Config::parse(base).unwrap();
        let mut interfaces = synthesize_interfaces(&config, None).unwrap();
        assert_eq!(
            *interface_config_mode_mut(&mut interfaces[0]),
            rns_interface::traits::InterfaceMode::Internal
        );

        // Reticulum.py in RNS 1.4.0: Internal is a supported
        // discovery mode and must not be auto-corrected.
        let config = Config::parse(&format!("{base}discoverable = yes\n")).unwrap();
        let mut interfaces = synthesize_interfaces(&config, None).unwrap();
        apply_discovery_mode_autocorrect(&config, &mut interfaces[0]);
        assert_eq!(
            *interface_config_mode_mut(&mut interfaces[0]),
            rns_interface::traits::InterfaceMode::Internal
        );

        let config = Config::parse(&format!(
            "{base}discoverable = yes\nignore_config_warnings = yes\n"
        ))
        .unwrap();
        let mut interfaces = synthesize_interfaces(&config, None).unwrap();
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
        let post_init =
            interface_factory::InterfacePostInit::try_from_section(&ConfigSection::new())
                .expect("empty interface defaults are valid");

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
            transport_rx.recv().await.map(unwrap_owned_event),
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
            transport_rx.recv().await.map(unwrap_owned_event),
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
            first_transport_rx.recv().await.map(unwrap_owned_event),
            Some(TransportMessage::RegisterInterface { id: registered, .. })
                if registered == id
        ));
        assert!(matches!(
            second_transport_rx.recv().await.map(unwrap_owned_event),
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
            first_transport_rx.recv().await.map(unwrap_owned_event),
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
            second_transport_rx.recv().await.map(unwrap_owned_event),
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
            transport_rx.recv().await.map(unwrap_owned_event),
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
            transport_rx.recv().await.map(unwrap_owned_event),
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
        let post_init =
            interface_factory::InterfacePostInit::try_from_section(&ConfigSection::new())
                .expect("empty interface defaults are valid");
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
            transport_rx.recv().await.map(unwrap_owned_event),
            Some(TransportMessage::RegisterInterface { id, .. }) if id == ids[0]
        ));
        assert!(matches!(
            transport_rx.recv().await.map(unwrap_owned_event),
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
            None,
        ));

        assert!(matches!(
            transport_rx.recv().await.map(unwrap_owned_event),
            Some(TransportMessage::RegisterInterface {
                id: registered_id,
                ..
            }) if registered_id == id
        ));
        assert!(matches!(
            transport_rx.recv().await.map(unwrap_owned_event),
            Some(TransportMessage::DeregisterInterface {
                id: deregistered_id
            }) if deregistered_id == id
        ));
        worker.await.unwrap();
        drop(cancel_tx);
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
            transport_rx.recv().await.map(unwrap_owned_event),
            Some(TransportMessage::RegisterInterface {
                id: registered_id,
                ..
            }) if registered_id == id
        ));

        teardown_interface_transaction(&transport_tx, &interface_controls, &interface_registry, id)
            .await;
        assert!(matches!(
            transport_rx.recv().await.map(unwrap_owned_event),
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
            transport_rx.recv().await.map(unwrap_owned_event),
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
            transport_rx.recv().await.map(unwrap_owned_event),
            Some(TransportMessage::DeregisterInterface {
                id: deregistered_id
            }) if deregistered_id == id
        ));
        drop(cancel_tx);
    }

    #[tokio::test]
    async fn teardown_without_owned_registration_cannot_deregister_replacement() {
        let id = 920_098;
        let (transport_tx, mut transport_rx) = mpsc::channel::<TransportMessage>(1);
        transport_tx.send(TransportMessage::Shutdown).await.unwrap();
        let interface_registry = InterfaceRegistry::default();
        let mut runtime = dummy_handle();
        runtime.transport_tx = transport_tx;
        runtime.interface_registry = interface_registry.clone();
        tokio::time::timeout(Duration::from_secs(1), teardown_interface(&runtime, id))
            .await
            .expect("missing ownership must not wait for actor capacity");
        assert_eq!(interface_registry.len(), 0);
        assert!(matches!(
            transport_rx.recv().await,
            Some(TransportMessage::Shutdown)
        ));
        assert!(
            transport_rx.try_recv().is_err(),
            "bare ID must not authorize deregistration"
        );
        let replacement = interface_registry
            .reserve(
                id,
                InterfaceKind::Standard,
                tokio::spawn(std::future::pending()),
                None,
            )
            .unwrap();
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
            transport_rx.recv().await.map(unwrap_owned_event),
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
            transport_rx.recv().await.map(unwrap_owned_event),
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
            transport_rx.recv().await.map(unwrap_owned_event),
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
            transport_rx.recv().await.map(unwrap_owned_event),
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
            transport_rx.recv().await.map(unwrap_owned_event),
            Some(TransportMessage::Shutdown)
        ));
        assert!(matches!(
            transport_rx.recv().await.map(unwrap_owned_event),
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
        let post_init = interface_factory::InterfacePostInit::try_from_section(&section).unwrap();
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
        let TransportMessage::RegisterInterface { entry, .. } = transport_rx
            .recv()
            .await
            .map(unwrap_owned_event)
            .expect("registration")
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
            interface_factory::InterfacePostInit::try_from_section(&ConfigSection::new())
                .expect("empty interface defaults are valid");
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

        let post_init =
            interface_factory::InterfacePostInit::try_from_section(&ConfigSection::new())
                .expect("empty interface defaults are valid");
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
        let TransportMessage::RegisterInterface { entry, .. } = transport_rx
            .recv()
            .await
            .map(unwrap_owned_event)
            .expect("default cap registration")
        else {
            panic!("expected RegisterInterface");
        };
        assert!((entry.announce_cap - ANNOUNCE_CAP).abs() < f64::EPSILON);

        let mut section = ConfigSection::new();
        section.set("announce_cap", "5.0");
        let post_init = interface_factory::InterfacePostInit::try_from_section(&section).unwrap();
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
        let TransportMessage::RegisterInterface { entry, .. } = transport_rx
            .recv()
            .await
            .map(unwrap_owned_event)
            .expect("custom cap registration")
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
        let post_init = interface_factory::InterfacePostInit::try_from_section(&section).unwrap();

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
        let _ = transport_rx
            .recv()
            .await
            .map(unwrap_owned_event)
            .expect("parent registration");

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

        let msg = transport_rx
            .recv()
            .await
            .map(unwrap_owned_event)
            .expect("child registration");
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

            let msg = transport_rx
                .recv()
                .await
                .map(unwrap_owned_event)
                .expect("registration");
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
                    transport_owner: rns_transport::InterfaceOwner::new(),
                    registry_owner: 1,
                    role: rns_transport::messages::InterfaceRole::SharedServer,
                    ingress_overrides: rns_transport::ingress::IngressOverrides::default(),
                    ifac_key: None,
                    ifac_size: 0,
                    ifac_netname: None,
                    client_target: None,
                    destination_cost: None,
                    pr_cost: None,
                    spawn: None,
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
        let post_init = interface_factory::InterfacePostInit::try_from_section(&section)
            .unwrap()
            .with_default_ifac_size(16);
        let ifac_key = derive_ifac_key_from_post_init(&post_init);
        assert!(ifac_key.is_some());

        register_interface_with_post_init(
            &transport_tx,
            test_interface_handle(parent_id, None, "ifac-parent"),
            &post_init,
            ifac_key.clone(),
            &interface_controls,
            &interface_registry,
            InterfaceKind::Standard,
        )
        .await
        .unwrap();
        let TransportMessage::RegisterInterface {
            entry: parent_entry,
            ..
        } = transport_rx
            .recv()
            .await
            .map(unwrap_owned_event)
            .expect("parent registration")
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
        let TransportMessage::RegisterInterface { entry, .. } = transport_rx
            .recv()
            .await
            .map(unwrap_owned_event)
            .expect("child registration")
        else {
            panic!("expected child RegisterInterface");
        };
        assert_eq!(entry.ifac_key, ifac_key);
        assert_eq!(entry.ifac_size, 16);

        // Stats report Python's IFAC fields for the listener and its child.
        let signature = rns_identity::ifac::ifac_signature(&ifac_key.unwrap());
        assert!(signature.is_some());
        let stats = transport_stats(vec![(parent_id, parent_entry), (child_id, entry)]).await;
        assert_eq!(stats.len(), 2);
        for stat in stats {
            assert_eq!(
                stat.ifac_signature,
                signature.map(Vec::from),
                "{}",
                stat.name
            );
            assert_eq!(stat.ifac_size, Some(16), "{}", stat.name);
            assert_eq!(
                stat.ifac_netname.as_deref(),
                Some("testnet"),
                "{}",
                stat.name
            );
        }
    }

    /// What a transport reports for interfaces registered as `entries`.
    async fn transport_stats(
        entries: Vec<(u64, rns_transport::messages::InterfaceEntry)>,
    ) -> Vec<rns_transport::messages::InterfaceStatRpcEntry> {
        let (actor, tx) = rns_transport::actor::TransportActor::new();
        for (id, entry) in entries {
            tx.send(TransportMessage::RegisterInterface { id, entry })
                .await
                .unwrap();
        }
        let running = tokio::spawn(actor.run());
        let (response_tx, response_rx) = tokio::sync::oneshot::channel();
        tx.send(TransportMessage::Rpc {
            query: TransportQuery::GetInterfaceStats,
            response_tx,
        })
        .await
        .unwrap();
        let TransportQueryResponse::InterfaceStats(stats) = response_rx.await.unwrap() else {
            panic!("unexpected interface stats response");
        };
        tx.send(TransportMessage::Shutdown).await.unwrap();
        running.await.unwrap();
        stats
    }

    #[tokio::test]
    async fn server_children_inherit_parent_stamp_costs_unresolved() {
        let parent_id = 930_011;
        let (transport_tx, mut transport_rx) = mpsc::channel::<TransportMessage>(8);
        let interface_controls: InterfaceControlMap =
            Arc::new(std::sync::Mutex::new(HashMap::new()));
        let interface_registry = InterfaceRegistry::default();

        let mut section = ConfigSection::new();
        section.set("destination_cost", "150");
        let post_init = interface_factory::InterfacePostInit::try_from_section(&section).unwrap();
        assert_eq!(post_init.destination_cost, Some(100.0));
        assert_eq!(post_init.pr_cost, None);
        register_interface_with_post_init(
            &transport_tx,
            test_interface_handle(parent_id, None, "cost-parent"),
            &post_init,
            None,
            &interface_controls,
            &interface_registry,
            InterfaceKind::Standard,
        )
        .await
        .unwrap();
        let Some(TransportMessage::RegisterInterface { entry, .. }) =
            transport_rx.recv().await.map(unwrap_owned_event)
        else {
            panic!("expected parent RegisterInterface");
        };
        assert_eq!((entry.destination_cost, entry.pr_cost), (Some(100.0), None));

        let (role, inherited, key, size) =
            child_registration_from_parent(&interface_controls, Some(parent_id));
        register_interface_handle_with_role_and_overrides(
            &transport_tx,
            test_interface_handle(930_012, Some(parent_id), "cost-child"),
            role,
            inherited,
            key,
            size,
            &interface_controls,
            &interface_registry,
            InterfaceKind::Standard,
            false,
        )
        .await
        .unwrap();
        let Some(TransportMessage::RegisterInterface { entry, .. }) =
            transport_rx.recv().await.map(unwrap_owned_event)
        else {
            panic!("expected child RegisterInterface");
        };
        // None stays None so the child keeps following the global pr_cost.
        assert_eq!((entry.destination_cost, entry.pr_cost), (Some(100.0), None));
    }

    #[test]
    fn stamps_section_booleans_only_switch_on() {
        let config = Config::parse("[stamps]\nstamp_prs = no\nenforce_stamps = no\n").unwrap();
        let mut policy = rns_transport::stamps::StampPolicy {
            stamp_prs: true,
            stamps_enforced: true,
            ..Default::default()
        };
        apply_stamps_section(&mut policy, config.section("stamps").unwrap()).unwrap();
        assert!(policy.stamp_prs);
        assert!(policy.stamps_enforced);
        assert!(!policy.lr_stamps_enforced);
    }

    #[test]
    fn stamps_section_bad_values_fail_config() {
        for body in ["stamp_prs = maybe", "pr_cost = abc", "lr_stamp_timeout = "] {
            let config = Config::parse(&format!("[stamps]\n{body}\n")).unwrap();
            assert!(
                matches!(
                    ReticulumConfig::try_from_config(&config),
                    Err(ConfigError::InvalidValue { ref section, .. }) if section == "stamps"
                ),
                "{body}"
            );
        }
    }

    #[test]
    fn stamps_section_worker_keys_clamp_as_python() {
        let parse = |body: &str| {
            let config = Config::parse(&format!("[stamps]\n{body}\n")).unwrap();
            ReticulumConfig::try_from_config(&config).map(|rc| rc.stamp_workers)
        };
        let workers = parse("max_workers = 3\nworker_niceness = 7").unwrap();
        assert_eq!(workers.max_workers.map(usize::from), Some(3));
        assert_eq!(workers.niceness, 7);
        let workers = parse("max_workers = 0\nworker_niceness = 25").unwrap();
        assert_eq!(
            (workers.max_workers.map(usize::from), workers.niceness),
            (Some(1), 20)
        );
        let workers = parse("max_workers = -3\nworker_niceness = -3").unwrap();
        assert_eq!(
            (workers.max_workers.map(usize::from), workers.niceness),
            (Some(1), 0)
        );
        let workers = parse("destination_cost = 20").unwrap();
        assert_eq!(workers, rns_identity::stamps::StampWorkers::default());
        for body in [
            "max_workers = x",
            "max_workers = 2.5",
            "worker_niceness = high",
        ] {
            assert!(
                matches!(
                    parse(body),
                    Err(ConfigError::InvalidValue { ref key, .. })
                        if key == body.split(' ').next().unwrap()
                ),
                "{body}"
            );
        }
    }

    #[test]
    fn default_config_parses_to_default_stamp_policy() {
        let config = Config::parse(Config::default_config()).unwrap();
        assert!(config.section("stamps").is_some());
        let rc = ReticulumConfig::try_from_config(&config).unwrap();
        assert_eq!(rc.stamps, rns_transport::stamps::StampPolicy::default());
    }

    #[tokio::test]
    async fn interfaces_without_ifac_report_none_despite_a_configured_size() {
        let id = 930_101;
        let (transport_tx, mut transport_rx) = mpsc::channel::<TransportMessage>(4);
        let interface_controls: InterfaceControlMap =
            Arc::new(std::sync::Mutex::new(HashMap::new()));
        let post_init =
            interface_factory::InterfacePostInit::try_from_section(&ConfigSection::new())
                .unwrap()
                .with_default_ifac_size(8);
        register_interface_with_post_init(
            &transport_tx,
            test_interface_handle(id, None, "plain-radio"),
            &post_init,
            derive_ifac_key_from_post_init(&post_init),
            &interface_controls,
            &InterfaceRegistry::default(),
            InterfaceKind::Standard,
        )
        .await
        .unwrap();
        let Some(TransportMessage::RegisterInterface { entry, .. }) =
            transport_rx.recv().await.map(unwrap_owned_event)
        else {
            panic!("expected RegisterInterface");
        };
        assert_eq!(entry.ifac_size, 8, "the size is configured all the same");
        let stat = transport_stats(vec![(id, entry)]).await.remove(0);
        assert_eq!(
            (stat.ifac_signature, stat.ifac_size, stat.ifac_netname),
            (None, None, None)
        );
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
        assert_eq!(rc.discover_interfaces_required_value, 16.0);
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
    fn required_discovery_value_is_fractional_and_not_positive_means_default() {
        for (raw, expected) in [("14.5", 14.5), ("999", 999.0), ("0", 16.0), ("-1", 16.0)] {
            let config =
                Config::parse(&format!("[reticulum]\nrequired_discovery_value = {raw}\n")).unwrap();
            let rc = ReticulumConfig::try_from_config(&config).unwrap();
            assert_eq!(rc.discover_interfaces_required_value, expected, "{raw}");
        }
        let config = Config::parse("[reticulum]\nrequired_discovery_value = abc\n").unwrap();
        assert!(ReticulumConfig::try_from_config(&config).is_err());
    }

    #[test]
    fn discovery_stamp_value_is_fractional_and_zero_generates_at_default() {
        for (line, expected) in [
            ("discovery_stamp_value = 17.5", 17.5),
            ("discovery_stamp_value = 0", 16.0),
            ("", 16.0),
            ("stamp_value = 18.25", 18.25),
            ("discovery_stamp_value = 150", 150.0),
        ] {
            let mut section = ConfigSection::new();
            if let Some((k, v)) = line.split_once(" = ") {
                section.set(k, v);
            }
            let cfg = DiscoveryInterfaceConfig {
                stamp_value: discovery_stamp_value(&|k| config_float("i", &section, k)).unwrap(),
                ..DiscoveryInterfaceConfig::backbone(None, "127.0.0.1".into(), 1)
            };
            assert_eq!(cfg.effective_stamp_value(), expected, "{line}");
        }
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
interface_enabled = yes
listen_port = 5555

[[No Flag]]
type = UDPInterface
listen_port = 5556
"#;
        let config = Config::parse(input).unwrap();
        let interfaces = synthesize_interfaces(&config, None).unwrap();
        // Upstream skips a section with neither `enabled` nor `interface_enabled`.
        assert_eq!(interfaces.len(), 2);
    }

    #[cfg(feature = "ble")]
    #[test]
    fn android_native_ble_manifest_is_ordered_lossless_and_inventory_only() {
        let make_ble = |name: &str, port: &str, frequency: u32| {
            interface_factory::InterfaceConfig::BleRNode(
                interface_factory::BleRNodeInterfaceConfig {
                    name: name.into(),
                    port: port.into(),
                    frequency,
                    bandwidth: 62_500,
                    spreading_factor: 9,
                    coding_rate: 7,
                    tx_power: 14,
                    mode: rns_interface::traits::InterfaceMode::Roaming,
                    flow_control: true,
                    st_alock: Some(12.5),
                    lt_alock: Some(3.25),
                    id_interval: Some(900),
                    id_callsign: Some("N0CALL".into()),
                    pair_unbonded: false,
                },
            )
        };
        let configs = vec![
            make_ble("first", "ble://AA:BB:CC:DD:EE:01", 915_000_000),
            interface_factory::InterfaceConfig::TcpClient(
                rns_interface::tcp::TcpClientConfig::new("not-rnode", "127.0.0.1", 4242),
            ),
            make_ble("second", "ble://Custom RNode", 868_000_000),
        ];

        let deferred = collect_deferred_android_ble_rnodes(&configs, true);
        assert_eq!(deferred.len(), 2);
        assert_eq!(deferred[0].name, "first");
        assert_eq!(deferred[0].port, "ble://AA:BB:CC:DD:EE:01");
        assert_eq!(deferred[0].frequency, 915_000_000);
        assert_eq!(deferred[0].bandwidth, 62_500);
        assert_eq!(deferred[0].spreading_factor, 9);
        assert_eq!(deferred[0].coding_rate, 7);
        assert_eq!(deferred[0].tx_power, 14);
        assert_eq!(
            deferred[0].mode,
            rns_interface::traits::InterfaceMode::Roaming
        );
        assert!(deferred[0].flow_control);
        assert_eq!(deferred[0].st_alock, Some(12.5));
        assert_eq!(deferred[0].lt_alock, Some(3.25));
        assert_eq!(deferred[0].id_interval, Some(900));
        assert_eq!(deferred[0].id_callsign.as_deref(), Some("N0CALL"));
        assert_eq!(deferred[1].name, "second");
        assert_eq!(deferred[1].port, "ble://Custom RNode");

        assert!(should_defer_android_ble_rnode(&configs[0], true));
        assert!(!should_defer_android_ble_rnode(&configs[1], true));
        assert!(!should_defer_android_ble_rnode(&configs[0], false));
        assert!(collect_deferred_android_ble_rnodes(&configs, false).is_empty());
    }

    #[cfg(feature = "ble")]
    #[test]
    fn android_native_ble_manifest_excludes_disabled_sections_without_duplicates() {
        let input = r#"
[interfaces]

[[Enabled BLE]]
type = RNodeInterface
enabled = yes
port = ble://Enabled
frequency = 915000000
bandwidth = 125000
spreadingfactor = 8
codingrate = 6
txpower = 17

[[Disabled BLE]]
type = RNodeInterface
enabled = no
port = ble://Disabled
frequency = 868000000
bandwidth = 125000
spreadingfactor = 8
codingrate = 6
txpower = 17
"#;
        let config = Config::parse(input).unwrap();
        let interfaces = synthesize_interfaces(&config, None).unwrap();
        let deferred = collect_deferred_android_ble_rnodes(&interfaces, true);
        assert_eq!(deferred.len(), 1);
        assert_eq!(deferred[0].name, "Enabled BLE");
        assert_eq!(deferred[0].port, "ble://Enabled");
    }

    #[test]
    fn interface_build_error_fails_synthesis_without_panic_on_interface_error() {
        let broken = Config::parse(
            "[reticulum]\npanic_on_interface_error = no\n\n[interfaces]\n\n[[Broken Interface]]\nenabled = yes\n",
        )
        .unwrap();
        assert!(matches!(
            synthesize_interfaces(&broken, None),
            Err(ReticulumError::Interface(_))
        ));
        let mut failures = Vec::new();
        assert!(
            synthesize_interfaces(&broken, Some(&mut failures))
                .unwrap()
                .is_empty()
        );
        assert_eq!(failures.len(), 1);
        assert_eq!(failures[0].0, "Broken Interface");
        let unknown =
            Config::parse("[interfaces]\n\n[[External]]\ntype = FooInterface\nenabled = yes\n")
                .unwrap();
        assert!(synthesize_interfaces(&unknown, None).unwrap().is_empty());
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

    /// Start a runtime on one RNode that reports a radio fault once it is up.
    #[cfg(feature = "rnode-tcp")]
    async fn init_with_faulting_rnode(
        panic_on_interface_error: &str,
    ) -> (ReticulumHandle, ShutdownSignal, PathBuf) {
        use rns_interface::{kiss, rnode};

        let template = rnode::RNodeConfig::new("Faulting RNode", "tcp://127.0.0.1:1");
        let settings = rnode::RNodeRadioSettings::from(&template);
        let mut responses = test_ready_rnode_tcp_responses(settings);
        kiss::frame_with_command_into(rnode::CMD_ERROR, &[rnode::ERROR_INITRADIO], &mut responses);
        let (port, _closed_rx, _peer) = test_rnode_tcp_peer_with_responses(responses);
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("reticulum_rs_faulting_rnode_{nonce}"));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("config"),
            format!(
                "[reticulum]\nshare_instance = No\nenable_transport = No\npanic_on_interface_error = {panic_on_interface_error}\n\n[interfaces]\n\n[[Faulting RNode]]\ntype = RNodeInterface\nenabled = Yes\nport = {port}\nfrequency = {}\nbandwidth = {}\nspreadingfactor = {}\ncodingrate = {}\ntxpower = {}\n",
                template.frequency,
                template.bandwidth,
                template.spreading_factor,
                template.coding_rate,
                template.tx_power,
            ),
        )
        .unwrap();

        let shutdown = ShutdownSignal::new();
        let handle = init(
            Some(dir.to_str().unwrap()),
            None,
            shutdown.clone(),
            Arc::new(AtomicBool::new(true)),
        )
        .await
        .expect("faulting RNode init");
        (handle, shutdown, dir)
    }

    #[cfg(feature = "rnode-tcp")]
    #[tokio::test]
    async fn rnode_hardware_failure_stops_the_runtime_when_panic_on_interface_error_is_set() {
        let (handle, shutdown, dir) = init_with_faulting_rnode("Yes").await;

        tokio::time::timeout(Duration::from_secs(5), shutdown.wait())
            .await
            .expect("an RNode hardware failure must take the runtime down");
        handle.shutdown_and_wait().await;
        assert_eq!(handle.interface_panic(), Some("Faulting RNode"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(feature = "rnode-tcp")]
    #[tokio::test]
    async fn rnode_hardware_failure_only_reconnects_without_panic_on_interface_error() {
        use rns_interface::rnode::RNodeRuntimePhase;

        let (handle, shutdown, dir) = init_with_faulting_rnode("No").await;
        let mut observer = handle.startup_rnode_runtimes().remove(0).observer;

        let failed = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let snapshot = observer.snapshot();
                if snapshot.hardware_failure_total == 1 {
                    return snapshot;
                }
                observer.changed().await.expect("RNode driver ended");
            }
        })
        .await
        .expect("the RNode hardware failure was not observed");
        assert_eq!(failed.phase, RNodeRuntimePhase::ReconnectBackoff);
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(!shutdown.is_triggered());
        assert_eq!(handle.interface_panic(), None);

        handle.shutdown_and_wait().await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// TCPInterface.py: a client that spends its retry budget panics
    /// the instance when `panic_on_interface_error` is set.
    #[tokio::test]
    async fn tcp_client_teardown_stops_the_runtime_when_panic_on_interface_error_is_set() {
        let refused = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = refused.local_addr().unwrap().port();
        drop(refused);
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("config"),
            format!(
                "[reticulum]\nshare_instance = No\nenable_transport = No\npanic_on_interface_error = Yes\n\n[interfaces]\n\n[[Unreachable]]\ntype = TCPClientInterface\nenabled = Yes\ntarget_host = 127.0.0.1\ntarget_port = {port}\nmax_reconnect_tries = 0\n"
            ),
        )
        .unwrap();
        let shutdown = ShutdownSignal::new();
        let handle = init(
            Some(dir.path().to_str().unwrap()),
            None,
            shutdown.clone(),
            Arc::new(AtomicBool::new(true)),
        )
        .await
        .expect("TCP client init");

        tokio::time::timeout(
            Duration::from_secs(rns_interface::tcp::RECONNECT_WAIT + 5),
            shutdown.wait(),
        )
        .await
        .expect("a torn-down TCP client must take the runtime down");
        handle.shutdown_and_wait().await;
        assert_eq!(handle.interface_panic(), Some("Unreachable"));
    }

    /// TCPInterface.py / BackboneInterface.py: a client
    /// added at runtime that gives up also panics the instance.
    #[tokio::test]
    async fn runtime_backbone_client_teardown_stops_the_runtime_when_panic_on_interface_error_is_set()
     {
        let refused = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = refused.local_addr().unwrap().port();
        drop(refused);
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("config"),
            "[reticulum]\nshare_instance = No\nenable_transport = No\npanic_on_interface_error = Yes\n\n[interfaces]\n",
        )
        .unwrap();
        let shutdown = ShutdownSignal::new();
        let handle = init(
            Some(dir.path().to_str().unwrap()),
            None,
            shutdown.clone(),
            Arc::new(AtomicBool::new(true)),
        )
        .await
        .expect("init");
        spawn_backbone_client_runtime(
            &handle,
            "Runtime Unreachable",
            "127.0.0.1",
            port,
            false,
            Some(1),
            Some(0),
        )
        .await
        .expect("runtime backbone client");

        tokio::time::timeout(
            Duration::from_secs(rns_interface::tcp::RECONNECT_WAIT + 10),
            shutdown.wait(),
        )
        .await
        .expect("a torn-down runtime client must take the runtime down");
        handle.shutdown_and_wait().await;
        assert_eq!(handle.interface_panic(), Some("Runtime Unreachable"));
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
                ..InitOptions::default()
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
                ..InitOptions::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(handle.instance_mode, InstanceMode::Shared);
        handle.shutdown_and_wait().await;

        let _ = std::fs::remove_dir_all(&dir);
    }

    async fn init_requiring_shared_instance(
        label: &str,
        config: String,
    ) -> (Result<ReticulumHandle, ReticulumError>, PathBuf) {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("reticulum_rs_require_{label}_{nonce}"));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("config"), config).unwrap();
        let result = init_with_options(
            Some(dir.to_str().unwrap()),
            None,
            ShutdownSignal::new(),
            Arc::new(AtomicBool::new(true)),
            InitOptions {
                require_shared_instance: true,
                ..InitOptions::default()
            },
        )
        .await;
        (result, dir)
    }

    // Reticulum.py: neither bindable nor connectable means standalone, required or not.
    #[tokio::test]
    async fn required_shared_instance_falls_back_to_standalone_when_unreachable() {
        let holder = tokio::net::TcpSocket::new_v4().unwrap();
        holder.bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let port = holder.local_addr().unwrap().port();
        let (control_port, _) = free_tcp_port_pair().await;

        let (result, dir) = init_requiring_shared_instance(
            "unreachable",
            format!(
                "[reticulum]\nshare_instance = Yes\nshared_instance_type = tcp\nshared_instance_port = {port}\ninstance_control_port = {control_port}\nenable_transport = No\n\n[interfaces]\n"
            ),
        )
        .await;

        let handle = result.expect("an unreachable shared instance is not a startup failure");
        assert_eq!(handle.instance_mode, InstanceMode::Standalone);
        handle.shutdown_and_wait().await;
        drop(holder);
        let _ = std::fs::remove_dir_all(&dir);
    }

    // Reticulum.py: without sharing there is no shared instance to require.
    #[tokio::test]
    async fn required_shared_instance_is_not_enforced_without_sharing() {
        let (result, dir) = init_requiring_shared_instance(
            "unshared",
            "[reticulum]\nshare_instance = No\nenable_transport = No\n\n[interfaces]\n".to_string(),
        )
        .await;

        let handle = result.expect("a non-sharing instance starts standalone");
        assert_eq!(handle.instance_mode, InstanceMode::Standalone);
        handle.shutdown_and_wait().await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn required_shared_instance_attaches_to_a_running_one() {
        let (port, control_port) = free_tcp_port_pair().await;
        let config = format!(
            "[reticulum]\nshare_instance = Yes\nshared_instance_type = tcp\nshared_instance_port = {port}\ninstance_control_port = {control_port}\nrpc_key = 4242424242424242424242424242424242424242424242424242424242424242\nenable_transport = No\n\n[interfaces]\n"
        );
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let owner_dir = std::env::temp_dir().join(format!("reticulum_rs_require_owner_{nonce}"));
        std::fs::create_dir_all(&owner_dir).unwrap();
        std::fs::write(owner_dir.join("config"), &config).unwrap();
        let owner = init(
            Some(owner_dir.to_str().unwrap()),
            None,
            ShutdownSignal::new(),
            Arc::new(AtomicBool::new(true)),
        )
        .await
        .unwrap();
        assert_eq!(owner.instance_mode, InstanceMode::Shared);

        let (result, client_dir) = init_requiring_shared_instance("client", config).await;
        let client = result.expect("a running shared instance satisfies the requirement");
        assert_eq!(client.instance_mode, InstanceMode::Client);
        let Some(TransportQueryResponse::InterfaceStats(stats)) = client
            .query_transport(TransportQuery::GetInterfaceStats)
            .await
        else {
            panic!("client interface stats");
        };
        let peer = stats
            .iter()
            .find(|entry| entry.role == "shared_instance_peer")
            .expect("shared-instance peer interface");
        assert_eq!(
            client.interface_controls.lock().unwrap()[&peer.id].ifac_size,
            16,
            "the local interface admits HW_MTU plus the default IFAC size"
        );
        assert_eq!(peer.ifac_size, None, "it has no IFAC to report");

        client.shutdown_and_wait().await;
        owner.shutdown_and_wait().await;
        let _ = std::fs::remove_dir_all(&owner_dir);
        let _ = std::fs::remove_dir_all(&client_dir);
    }

    #[tokio::test]
    async fn unix_shared_instance_request_uses_the_platform_carrier() {
        use crate::rpc::{RpcRequest, RpcResponse};

        let (port, control_port) = free_tcp_port_pair().await;
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir_a = std::env::temp_dir().join(format!("reticulum_rs_unix_request_a_{nonce}"));
        let dir_b = std::env::temp_dir().join(format!("reticulum_rs_unix_request_b_{nonce}"));
        std::fs::create_dir_all(&dir_a).unwrap();
        std::fs::create_dir_all(&dir_b).unwrap();
        let rpc_key = [0x42u8; 32];
        let cfg = format!(
            "[reticulum]\nshare_instance = Yes\ninstance_name = unixreq{nonce}\nshared_instance_type = unix\nshared_instance_port = {port}\ninstance_control_port = {control_port}\nrpc_key = {}\nenable_transport = No\n\n[interfaces]\n",
            hex::encode(rpc_key)
        );
        std::fs::write(dir_a.join("config"), &cfg).unwrap();
        std::fs::write(dir_b.join("config"), &cfg).unwrap();

        let owner = init(
            Some(dir_a.to_str().unwrap()),
            None,
            ShutdownSignal::new(),
            Arc::new(AtomicBool::new(true)),
        )
        .await
        .unwrap();
        assert_eq!(owner.instance_mode, InstanceMode::Shared);
        assert_eq!(owner.config.shared_instance_type, python_unix_request());

        let client = init(
            Some(dir_b.to_str().unwrap()),
            None,
            ShutdownSignal::new(),
            Arc::new(AtomicBool::new(true)),
        )
        .await
        .unwrap();
        assert_eq!(client.instance_mode, InstanceMode::Client);

        // A tool reading the same file must reach the owner's control socket.
        let tool = ReticulumConfig::from_config(&Config::parse(&cfg).unwrap());
        let request = RpcRequest::GetInterfaceStats;
        let timeout = Duration::from_secs(3);
        let on_tcp = python_unix_request() == SharedInstanceType::Tcp;
        let response = match tool.shared_rpc_endpoint(&std::env::temp_dir()) {
            SharedInstanceRpcEndpoint::Tcp(tool_port) => {
                assert!(on_tcp);
                assert_eq!(tool_port, control_port);
                crate::rpc::connect_and_request(tool_port, &rpc_key, &request, timeout).await
            }
            SharedInstanceRpcEndpoint::Unix(path) => {
                assert!(!on_tcp);
                crate::rpc::connect_unix_and_request(&path, &rpc_key, &request, timeout).await
            }
        };
        assert!(matches!(response, Ok(RpcResponse::InterfaceStats(_))));
        assert_eq!(
            tokio::net::TcpStream::connect(("127.0.0.1", port))
                .await
                .is_ok(),
            on_tcp,
            "the packet socket is TCP exactly where Python's is"
        );

        client.shutdown_and_wait().await;
        owner.shutdown_and_wait().await;
        let _ = std::fs::remove_dir_all(&dir_a);
        let _ = std::fs::remove_dir_all(&dir_b);
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
                .any(|role| role == "LocalServerInterface"),
            "client control queries must proxy to the authoritative shared instance"
        );
        assert!(
            shared_control_roles
                .iter()
                .filter(|role| *role == "LocalClientInterface")
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
            .filter(|entry| entry.role == "LocalClientInterface")
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
            stats
                .iter()
                .any(|entry| entry.role == "LocalServerInterface"),
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
enabled = yes
port = /dev/ttyUSB0
speed = 115200

[[KISS TNC]]
type = KISSInterface
enabled = yes
port = /dev/ttyUSB1
speed = 57600

[[Auto Discovery]]
type = AutoInterface
enabled = yes
group_id = testgroup

[[LoRa Radio]]
type = RNodeInterface
enabled = yes
port = /dev/ttyACM0
frequency = 868000000
bandwidth = 125000
spreadingfactor = 7
codingrate = 5
txpower = 17

[[OpenCom XL]]
type = RNodeMultiInterface
enabled = yes
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
enabled = yes
port = 37428
"#;
        let config = Config::parse(input).unwrap();
        let interfaces = synthesize_interfaces(&config, None).unwrap();
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

        let hash_name = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let short_name = "0123456789abcdef0123456789abcdef";
        let short_path = resource_dir.join(short_name);
        fs::write(&short_path, b"keep").unwrap();
        let packet_path = cache_dir.join(hash_name);
        let resource_path = resource_dir.join(hash_name);
        let unrelated_path = resource_dir.join("unrelated");
        let spool_path = resource_dir.join(format!("{hash_name}-0123456789abcdef"));
        fs::write(&spool_path, b"spool").unwrap();
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
            !spool_path.exists(),
            "an abandoned Resource spool expires after one day"
        );
        assert!(
            packet_path.exists(),
            "packet cache entries live for seven days"
        );
        assert!(
            unrelated_path.exists(),
            "non-hash files are not cache entries"
        );
        assert!(
            short_path.exists(),
            "names shorter than a full hash are not cache entries"
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
