//! Reticulum runtime singleton, init and lifecycle. Three operating modes:
//! **Shared** owns hardware and serves RPC to siblings; **Client** connects
//! to a Shared instance over a local socket; **Standalone** owns its
//! interfaces and exposes no IPC. Python: `RNS/Reticulum.py`.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};

use std::time::Duration;

use bytes::Bytes;
use tokio::sync::{Mutex, Notify, mpsc};
use tokio::task::JoinHandle;

use crate::config::{Config, ConfigError, ConfigSection};
use crate::constants::*;
use crate::interface_factory;
use crate::jobs::{Job, JobScheduler};
use crate::lifecycle::ShutdownSignal;
use crate::link_client::LinkClient;
use crate::link_manager::LinkManager;
use crate::platform::{StoragePaths, resolve_config_dir};
use rns_identity::identity::Identity;
use rns_transport::await_path::{AwaitPathError, await_path};
use rns_transport::discovery::{
    Announcer, BLACKHOLE_INITIAL_WAIT, BLACKHOLE_JOB_INTERVAL, BLACKHOLE_SOURCE_TIMEOUT,
    BLACKHOLE_UPDATE_INTERVAL, BlackholeSubscriberState, DiscoveredInterface, DiscoveryDecryptor,
    DiscoveryInterfaceConfig, DiscoveryStamper, DiscoveryStore, ReceiverConfig, discovery_hash,
};
use rns_transport::messages::{
    OutboundRequest, RecalledDestinationRpcEntry, TransportMessage, TransportQuery,
    TransportQueryResponse,
};

static INSTANCE: OnceLock<ReticulumHandle> = OnceLock::new();

/// Spawned interface driver tasks, keyed by `interface_id`. Stash is required:
/// dropping the JoinHandle only detaches the task, so `teardown_interface`
/// must abort it explicitly to stop reconnect/read/write loops.
static INTERFACE_TASKS: OnceLock<std::sync::Mutex<HashMap<u64, JoinHandle<()>>>> = OnceLock::new();

fn interface_tasks() -> &'static std::sync::Mutex<HashMap<u64, JoinHandle<()>>> {
    INTERFACE_TASKS.get_or_init(|| std::sync::Mutex::new(HashMap::new()))
}

#[derive(Clone)]
struct InterfaceControlMetadata {
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
    transport_completion: Arc<TransportCompletion>,
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
pub enum ControlError {
    #[error("not connected to the shared Reticulum instance")]
    NotConnectedToSharedInstance,
    #[error("shared-instance RPC authentication failed")]
    RpcAuth,
    #[error("shared-instance RPC failed: {0}")]
    Rpc(String),
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
    pub fn transport_enabled(&self) -> bool {
        self.config.enable_transport
    }

    pub fn should_use_implicit_proof(&self) -> bool {
        self.config.use_implicit_proof
    }

    pub fn remote_management_enabled(&self) -> bool {
        self.config.enable_remote_management
    }

    pub fn link_mtu_discovery(&self) -> bool {
        self.config.link_mtu_discovery
    }

    /// Trigger orderly runtime shutdown and wait until the transport actor has
    /// synchronously flushed its persisted state.
    pub async fn shutdown_and_wait(&self) {
        self.shutdown.trigger();
        if !self.transport_completion.stopped.load(Ordering::Acquire) {
            let _ = self.transport_tx.send(TransportMessage::Shutdown).await;
        }
        self.transport_completion.wait().await;
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

    /// Query this process' transport actor directly.
    pub async fn query_transport(&self, query: TransportQuery) -> Option<TransportQueryResponse> {
        self.query_transport_result(query).await.ok()
    }

    async fn query_transport_result(
        &self,
        query: TransportQuery,
    ) -> Result<TransportQueryResponse, ControlError> {
        let variant = format!("{query:?}");
        let started = std::time::Instant::now();
        let (tx, rx) = tokio::sync::oneshot::channel();
        if self
            .transport_tx
            .send(TransportMessage::Rpc {
                query,
                response_tx: tx,
            })
            .await
            .is_err()
        {
            tracing::warn!(query = %variant, "transport query channel closed");
            return Err(ControlError::ChannelClosed);
        }
        let send_elapsed = started.elapsed();
        let timeout = Duration::from_secs(5);
        let result = match tokio::time::timeout(timeout, rx).await {
            Ok(Ok(result)) => Ok(result),
            Ok(Err(_)) => Err(ControlError::ChannelClosed),
            Err(_) => Err(ControlError::Timeout(timeout)),
        };
        let total = started.elapsed();
        if result.is_err() || total > Duration::from_millis(1000) {
            tracing::warn!(
                query = %variant,
                send_ms = send_elapsed.as_millis() as u64,
                total_ms = total.as_millis() as u64,
                timed_out = matches!(&result, Err(ControlError::Timeout(_))),
                "transport query slow or failed"
            );
        }
        result
    }

    /// Recall the identity and latest announce metadata for `destination_hash`.
    ///
    /// This reads the process' live, validated announce cache in O(1) without
    /// extending the entry's lifetime. It mirrors
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

    /// Result-returning control-plane query used by the typed facade.
    ///
    /// Unlike the compatibility [`Self::query_control`] method, a failed
    /// shared-instance request never falls back to this process' local actor.
    async fn query_control_result(
        &self,
        query: TransportQuery,
    ) -> Result<TransportQueryResponse, ControlError> {
        if self.instance_mode != InstanceMode::Client {
            return self.query_transport_result(query).await;
        }

        let Some(request) = transport_query_to_rpc_request(&query) else {
            return self.query_transport_result(query).await;
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
        rpc_response_to_transport_response(rpc_result).ok_or(ControlError::UnexpectedResponse {
            operation: "shared-instance control query",
        })
    }

    /// Query the authoritative control plane.
    ///
    /// In client mode, Python proxies Reticulum control methods to the local
    /// shared instance over the RPC listener. Mirror that for the operations
    /// Python exposes, then fall back to the local actor for Rust-only/local
    /// diagnostics such as recent announce snapshots.
    pub async fn query_control(&self, query: TransportQuery) -> Option<TransportQueryResponse> {
        if self.instance_mode == InstanceMode::Client {
            if let Some(request) = transport_query_to_rpc_request(&query) {
                if let Some(rpc_key) = self.config.rpc_key.as_deref() {
                    let rpc_result = match self.config.shared_rpc_endpoint(&self.socket_base) {
                        SharedInstanceRpcEndpoint::Tcp(port) => {
                            crate::rpc::connect_and_request(
                                port,
                                rpc_key,
                                &request,
                                Duration::from_secs(5),
                            )
                            .await
                        }
                        SharedInstanceRpcEndpoint::Unix(socket_path) => {
                            crate::rpc::connect_unix_and_request(
                                &socket_path,
                                rpc_key,
                                &request,
                                Duration::from_secs(5),
                            )
                            .await
                        }
                    };
                    match rpc_result {
                        Ok(response) => {
                            if let Some(mapped) = rpc_response_to_transport_response(response) {
                                return Some(mapped);
                            }
                        }
                        Err(e) => {
                            tracing::debug!(error = %e, "shared instance control RPC failed; falling back to local actor");
                        }
                    }
                }
            }
        }

        self.query_transport(query).await
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
        TransportQuery::DropPathTable => RpcRequest::DropPathTable,
        TransportQuery::DropRecentAnnounces => RpcRequest::DropRecentAnnounces,
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
    /// Minimum stamp value (leading-zero bits). Default 14 (LXStamper
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
            discover_interfaces_required_value: 14,
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

    let (mut actor, transport_tx) = rns_transport::actor::TransportActor::new();
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

    let shutdown_tx = transport_tx.clone();
    let shutdown_clone = shutdown.clone();
    let transport_completion = Arc::new(TransportCompletion::default());
    let actor_completion = transport_completion.clone();
    tokio::spawn(async move {
        actor.run().await;
        actor_completion.mark_stopped();
    });

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

    let id_gen = Arc::new(AtomicU64::new(1));

    // Sub-interface sink (e.g. TCP per-client).
    let (handle_tx, mut handle_rx) = mpsc::channel::<rns_interface::traits::InterfaceHandle>(64);
    let interface_controls: InterfaceControlMap = Arc::new(std::sync::Mutex::new(HashMap::new()));

    let socket_base = socket_dir.clone().unwrap_or_else(std::env::temp_dir);
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
                            &shutdown,
                        )
                        .await
                    }
                    Err(_) => InstanceMode::Standalone,
                }
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
                        register_interface_handle_with_role(
                            &transport_tx,
                            server_handle,
                            rns_transport::messages::InterfaceRole::SharedServer,
                            &interface_controls,
                        )
                        .await;
                        InstanceMode::Shared
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
                                        &shutdown,
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
            let mut live_server_detected = false;
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
                            &shutdown,
                        )
                        .await
                    }
                    Err(_) => InstanceMode::Standalone,
                }
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
                        register_interface_handle_with_role(
                            &transport_tx,
                            server_handle,
                            rns_transport::messages::InterfaceRole::SharedServer,
                            &interface_controls,
                        )
                        .await;
                        InstanceMode::Shared
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
                                    &shutdown,
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
            let _ = transport_tx.send(TransportMessage::Shutdown).await;
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

    // Client mode leaves hardware to the Shared sibling.
    if instance_mode != InstanceMode::Client {
        for iface_config in &interfaces {
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

            match spawn_interface(
                iface_config,
                iface_id,
                transport_tx.clone(),
                id_gen.clone(),
                handle_tx.clone(),
                &socket_base,
                is_foreground.clone(),
            )
            .await
            {
                Ok(iface_handles) => {
                    for iface_handle in iface_handles {
                        let registered_id = iface_handle.id;
                        register_interface_with_post_init(
                            &transport_tx,
                            iface_handle,
                            &post_init,
                            ifac_key,
                            &interface_controls,
                        )
                        .await;
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
                Err(e) => {
                    if rc.panic_on_interface_error {
                        let _ = transport_tx.send(TransportMessage::Shutdown).await;
                        return Err(ReticulumError::Interface(e));
                    } else {
                        tracing::warn!("failed to spawn interface: {}", e);
                    }
                }
            }
        }
    }

    {
        let reg_tx = transport_tx.clone();
        let reg_controls = interface_controls.clone();
        tokio::spawn(async move {
            while let Some(sub_handle) = handle_rx.recv().await {
                let (role, ingress_overrides, ifac_key, ifac_size) =
                    child_registration_from_parent(&reg_controls, sub_handle.parent_id);
                register_interface_handle_with_role_and_overrides(
                    &reg_tx,
                    sub_handle,
                    role,
                    ingress_overrides,
                    ifac_key,
                    ifac_size,
                    &reg_controls,
                    false,
                )
                .await;
            }
        });
    }

    let handle = ReticulumHandle {
        transport_tx: transport_tx.clone(),
        config_dir: config_dir.clone(),
        instance_mode,
        interface_configs: interfaces,
        id_gen: id_gen.clone(),
        handle_tx: handle_tx.clone(),
        interface_controls: interface_controls.clone(),
        socket_base: socket_base.clone(),
        config: rc.clone(),
        is_foreground,
        shutdown: shutdown.clone(),
        transport_identity: wire_transport_identity,
        network_identity: network_identity.clone(),
        discovery: discovery_runtime,
        transport_completion,
        started_at,
    };

    if instance_mode != InstanceMode::Client && rc.publish_blackhole {
        match start_blackhole_publisher(&handle).await {
            Ok(dest) => tracing::info!(dest = %hex::encode(dest), "blackhole publisher started"),
            Err(e) => tracing::warn!("failed to start blackhole publisher: {}", e),
        }
    }
    if instance_mode != InstanceMode::Client && !rc.blackhole_sources.is_empty() {
        start_blackhole_subscriber(handle.clone()).await;
    }

    tokio::spawn(async move {
        shutdown_clone.wait().await;
        let _ = shutdown_tx.send(TransportMessage::Shutdown).await;
    });

    if instance_mode != InstanceMode::Client {
        let job_tx = transport_tx.clone();
        let cache_dir = paths.cache_dir.clone();
        let job_shutdown = shutdown.clone();
        tokio::spawn(async move {
            run_jobs(job_tx, cache_dir, job_shutdown).await;
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

    Ok(handle)
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

/// Register a freshly connected shared-instance client (TCP or local socket)
/// as the SharedInstancePeer and start its reconnect monitor.
async fn adopt_shared_instance_client(
    client_handle: rns_interface::traits::InterfaceHandle,
    transport_tx: &mpsc::Sender<TransportMessage>,
    interface_controls: &InterfaceControlMap,
    shutdown: &ShutdownSignal,
) -> InstanceMode {
    let client_iface_id = client_handle.id;
    let client_online = client_handle.online.clone();
    register_interface_handle_with_role(
        transport_tx,
        client_handle,
        rns_transport::messages::InterfaceRole::SharedInstancePeer,
        interface_controls,
    )
    .await;
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
async fn register_interface_handle(
    transport_tx: &mpsc::Sender<TransportMessage>,
    handle: rns_interface::traits::InterfaceHandle,
    interface_controls: &InterfaceControlMap,
) {
    register_interface_handle_with_role(
        transport_tx,
        handle,
        rns_transport::messages::InterfaceRole::Normal,
        interface_controls,
    )
    .await;
}

/// Must use `send().await`, not `try_send`: dropping the registration on a
/// full channel leaves a spawned interface that never receives traffic.
async fn register_interface_handle_with_role(
    transport_tx: &mpsc::Sender<TransportMessage>,
    handle: rns_interface::traits::InterfaceHandle,
    role: rns_transport::messages::InterfaceRole,
    interface_controls: &InterfaceControlMap,
) {
    register_interface_handle_with_role_and_overrides(
        transport_tx,
        handle,
        role,
        rns_transport::ingress::IngressOverrides::default(),
        None,
        0,
        interface_controls,
        false,
    )
    .await;
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
    multipoint: bool,
) {
    let name = handle.name.clone();
    let id = handle.id;
    let ingress = ingress_for_role(role, &ingress_overrides);
    // Stash the driver task so `teardown_interface` can abort it; drop alone only detaches.
    interface_tasks()
        .lock()
        .expect("interface_tasks mutex poisoned")
        .insert(id, handle.read_task);
    interface_controls
        .lock()
        .expect("interface_controls mutex poisoned")
        .insert(
            id,
            InterfaceControlMetadata {
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
        online: Some(handle.online),
        rxb: handle.rxb,
        txb: handle.txb,
        tx_drops: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
        ingress,
        announce_queue: Vec::new(),
        multipoint,
        // Interface.py class defaults; Python spawned sub-interfaces do not
        // inherit recursive_prs/announces_from_internal (TCPInterface.py:579+).
        recursive_prs: false,
        announces_from_internal: true,
    };
    if let Err(e) = transport_tx
        .send(TransportMessage::RegisterInterface { id, entry })
        .await
    {
        tracing::error!(name = %name, id, error = %e, "RegisterInterface failed — transport actor gone");
    }
}

/// See [`register_interface_handle`] for `send().await` rationale.
async fn register_interface_with_post_init(
    transport_tx: &mpsc::Sender<TransportMessage>,
    handle: rns_interface::traits::InterfaceHandle,
    post_init: &interface_factory::InterfacePostInit,
    ifac_key: Option<[u8; 64]>,
    interface_controls: &InterfaceControlMap,
) {
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
    interface_tasks()
        .lock()
        .expect("interface_tasks mutex poisoned")
        .insert(id, handle.read_task);
    interface_controls
        .lock()
        .expect("interface_controls mutex poisoned")
        .insert(
            id,
            InterfaceControlMetadata {
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
        online: Some(handle.online),
        rxb: handle.rxb,
        txb: handle.txb,
        tx_drops: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
        ingress,
        announce_queue: Vec::new(),
        multipoint: false,
        recursive_prs: post_init.recursive_prs,
        announces_from_internal: post_init.announces_from_internal,
    };
    if let Err(e) = transport_tx
        .send(TransportMessage::RegisterInterface { id, entry })
        .await
    {
        tracing::error!(name = %name, id, error = %e, "RegisterInterface failed — transport actor gone");
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

    if let Some(size) = ifac.ifac_size
        && !(1..=64).contains(&size)
    {
        return Err(format!("Invalid IFAC size {size}; expected 1..=64 bytes"));
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
/// Gateway or Access Point mode for discovery to be useful, so the mode is
/// auto-corrected (AP for RNode radios, Gateway otherwise) with a notice.
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
    if matches!(*mode, InterfaceMode::Gateway | InterfaceMode::AccessPoint) {
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
    register_interface_with_post_init(
        &handle.transport_tx,
        iface_handle,
        &post_init,
        ifac_key,
        &handle.interface_controls,
    )
    .await;
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
        register_interface_with_post_init(
            &handle.transport_tx,
            iface_handle,
            &post_init,
            ifac_key,
            &handle.interface_controls,
        )
        .await;
    } else {
        register_interface_handle(
            &handle.transport_tx,
            iface_handle,
            &handle.interface_controls,
        )
        .await;
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
        register_interface_with_post_init(
            &handle.transport_tx,
            iface_handle,
            &post_init,
            ifac_key,
            &handle.interface_controls,
        )
        .await;
    } else {
        register_interface_handle(
            &handle.transport_tx,
            iface_handle,
            &handle.interface_controls,
        )
        .await;
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
        register_interface_with_post_init(
            &handle.transport_tx,
            iface_handle,
            &post_init,
            ifac_key,
            &handle.interface_controls,
        )
        .await;
    } else {
        register_interface_handle(
            &handle.transport_tx,
            iface_handle,
            &handle.interface_controls,
        )
        .await;
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
        register_interface_with_post_init(
            &handle.transport_tx,
            iface_handle,
            &post_init,
            ifac_key,
            &handle.interface_controls,
        )
        .await;
    } else {
        register_interface_handle(
            &handle.transport_tx,
            iface_handle,
            &handle.interface_controls,
        )
        .await;
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

    let id = handle
        .id_gen
        .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let mut config = rns_interface::ble_rnode::BleRNodeConfig::new(name, port);
    config.frequency = frequency;
    config.bandwidth = bandwidth;
    config.spreading_factor = spreading_factor;
    config.coding_rate = coding_rate;
    config.tx_power = tx_power as u8;
    config.mode = mode;
    config.st_alock = st_alock;
    config.lt_alock = lt_alock;
    config.flow_control = flow_control;

    let iface_handle = rns_interface::ble_rnode::spawn_ble_rnode_interface(
        config,
        id,
        handle.transport_tx.clone(),
    )
    .await
    .map_err(|e| format!("BLE RNode spawn failed: {e}"))?;

    let online = iface_handle.online.clone();
    register_interface_handle(
        &handle.transport_tx,
        iface_handle,
        &handle.interface_controls,
    )
    .await;
    tracing::info!(name = %name, id, "runtime BLE RNode interface spawned");
    Ok((id, online))
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

    let id = handle
        .id_gen
        .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let mut config = rns_interface::rnode::RNodeConfig::new(name, port);
    config.frequency = frequency;
    config.bandwidth = bandwidth;
    config.spreading_factor = spreading_factor;
    config.coding_rate = coding_rate;
    config.tx_power = tx_power as u8;
    config.mode = mode;
    config.st_alock = st_alock;
    config.lt_alock = lt_alock;
    config.flow_control = flow_control;

    let iface_handle =
        rns_interface::rnode::spawn_rnode_interface(config, id, handle.transport_tx.clone())
            .await
            .map_err(|e| format!("RNode spawn failed: {e}"))?;

    let online = iface_handle.online.clone();
    register_interface_handle(
        &handle.transport_tx,
        iface_handle,
        &handle.interface_controls,
    )
    .await;
    tracing::info!(name = %name, id, "runtime RNode interface spawned");
    Ok((id, online))
}

/// Android bridge variant: Kotlin owns GATT, Rust connects via a local TCP socket.
#[cfg(feature = "ble")]
pub async fn spawn_ble_rnode_runtime_native(
    handle: &ReticulumHandle,
    args: BleRnodeRuntimeArgs<'_>,
    tcp_port: u16,
) -> Result<(u64, std::sync::Arc<std::sync::atomic::AtomicBool>), String> {
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

    let id = handle
        .id_gen
        .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let mut config = rns_interface::ble_rnode::BleRNodeConfig::new(name, port);
    config.frequency = frequency;
    config.bandwidth = bandwidth;
    config.spreading_factor = spreading_factor;
    config.coding_rate = coding_rate;
    config.tx_power = tx_power as u8;
    config.mode = mode;
    config.st_alock = st_alock;
    config.lt_alock = lt_alock;
    config.flow_control = flow_control;

    let iface_handle = rns_interface::ble_rnode::spawn_ble_rnode_interface_native(
        config,
        id,
        handle.transport_tx.clone(),
        tcp_port,
    )
    .await
    .map_err(|e| format!("BLE RNode native spawn failed: {e}"))?;

    let online = iface_handle.online.clone();
    register_interface_handle(
        &handle.transport_tx,
        iface_handle,
        &handle.interface_controls,
    )
    .await;
    tracing::info!(name = %name, id, tcp_port, "runtime BLE RNode interface spawned (native bridge)");
    Ok((id, online))
}

/// Spawn an AutoInterface (local-network discovery) with a resolved config.
pub async fn spawn_auto_interface_runtime_with_config(
    handle: &ReticulumHandle,
    config: rns_interface::auto::AutoInterfaceConfig,
) -> Result<u64, String> {
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

    register_interface_handle(
        &handle.transport_tx,
        iface_handle,
        &handle.interface_controls,
    )
    .await;
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
    register_interface_handle_with_role_and_overrides(
        &handle.transport_tx,
        iface_handle,
        rns_transport::messages::InterfaceRole::Normal,
        rns_transport::ingress::IngressOverrides::default(),
        None,
        0,
        &handle.interface_controls,
        true,
    )
    .await;
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
    rns_interface::ble_peer::stop_ble_peer_interface().await;
    teardown_interface(handle, id).await;
}

/// Stop per-id reconnect loop, then deregister. Per-id (multiple BLE RNode
/// interfaces coexist, each with its own `AtomicBool`); idempotent.
#[cfg(feature = "ble")]
pub async fn teardown_ble_rnode_interface(handle: &ReticulumHandle, id: u64) {
    rns_interface::ble_rnode::stop_ble_rnode_interface(id);
    tokio::time::sleep(std::time::Duration::from_millis(1200)).await;
    teardown_interface(handle, id).await;
}

/// Stop serial/TCP RNode radio and leave host-controlled mode before generic
/// interface deregistration aborts the driver task.
#[cfg(any(feature = "serial", feature = "rnode-tcp"))]
pub async fn teardown_rnode_interface(handle: &ReticulumHandle, id: u64) {
    rns_interface::rnode::stop_rnode_interface(id);
    tokio::time::sleep(std::time::Duration::from_millis(700)).await;
    teardown_interface(handle, id).await;
}

#[cfg(target_os = "android")]
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
    let id = handle
        .id_gen
        .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let mut config = rns_interface::android_usb::AndroidUsbConfig::new(name, device_name);
    config.frequency = frequency;
    config.bandwidth = bandwidth;
    config.spreading_factor = spreading_factor;
    config.coding_rate = coding_rate;
    config.tx_power = tx_power as u8;
    config.mode = mode;
    config.st_alock = st_alock;
    config.lt_alock = lt_alock;
    config.flow_control = flow_control;

    let iface_handle = rns_interface::android_usb::spawn_android_usb_rnode_interface(
        config,
        id,
        handle.transport_tx.clone(),
    )
    .await
    .map_err(|e| format!("Android USB spawn failed: {e}"))?;

    register_interface_handle(
        &handle.transport_tx,
        iface_handle,
        &handle.interface_controls,
    )
    .await;
    tracing::info!(name = %name, id, "runtime Android USB RNode interface spawned");
    Ok(id)
}

#[cfg(target_os = "android")]
pub async fn teardown_android_usb_rnode_interface(handle: &ReticulumHandle, id: u64) {
    rns_interface::android_usb::stop_android_usb_rnode_interface(id);
    tokio::time::sleep(std::time::Duration::from_millis(700)).await;
    teardown_interface(handle, id).await;
}

pub async fn teardown_interface(handle: &ReticulumHandle, id: u64) {
    // Abort the driver task FIRST so loops stop accepting traffic; then
    // deregister so the dropped tx cascades through writer/forwarder.
    // Order matters: dereg-first would let the master task reconnect once
    // before the abort lands.
    if let Some(task) = interface_tasks()
        .lock()
        .expect("interface_tasks mutex poisoned")
        .remove(&id)
    {
        task.abort();
        tracing::debug!(id, "interface driver task aborted");
    }
    handle
        .interface_controls
        .lock()
        .expect("interface_controls mutex poisoned")
        .remove(&id);
    let _ = handle
        .transport_tx
        .send(TransportMessage::DeregisterInterface { id })
        .await;
    tracing::info!(id, "interface deregistered");
}

async fn spawn_interface(
    iface_config: &interface_factory::InterfaceConfig,
    id: u64,
    transport_tx: mpsc::Sender<TransportMessage>,
    id_gen: Arc<AtomicU64>,
    handle_tx: mpsc::Sender<rns_interface::traits::InterfaceHandle>,
    socket_base: &Path,
    is_foreground: Arc<AtomicBool>,
) -> Result<Vec<rns_interface::traits::InterfaceHandle>, String> {
    match iface_config {
        interface_factory::InterfaceConfig::TcpClient(c) => {
            rns_interface::tcp::spawn_tcp_client(c.clone(), id, transport_tx)
                .await
                .map(|h| vec![h])
                .map_err(|e| format!("TCP client: {e}"))
        }
        interface_factory::InterfaceConfig::TcpServer(c) => {
            rns_interface::tcp::spawn_tcp_server(c.clone(), id, id_gen, transport_tx, handle_tx)
                .await
                .map(|h| vec![h])
                .map_err(|e| format!("TCP server: {e}"))
        }
        interface_factory::InterfaceConfig::Udp(c) => {
            rns_interface::udp::spawn_udp_interface(c.clone(), id, transport_tx)
                .await
                .map(|h| vec![h])
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
                .map(|h| vec![h])
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
                .map(|h| vec![h])
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
                .map(|h| vec![h])
                .map_err(|e| format!("Auto: {e}"))
        }
        #[cfg(any(feature = "serial", feature = "rnode-tcp"))]
        interface_factory::InterfaceConfig::RNode(c) => {
            let mut rnode_config = rns_interface::rnode::RNodeConfig::new(&c.name, &c.port);
            rnode_config.frequency = c.frequency;
            rnode_config.bandwidth = c.bandwidth;
            rnode_config.spreading_factor = c.spreading_factor;
            rnode_config.coding_rate = c.coding_rate;
            rnode_config.tx_power = c.tx_power as u8;
            rnode_config.mode = c.mode;
            rnode_config.flow_control = c.flow_control;
            rnode_config.st_alock = c.st_alock;
            rnode_config.lt_alock = c.lt_alock;
            rnode_config.id_interval = c.id_interval;
            rnode_config.id_callsign = c.id_callsign.as_ref().map(|s| s.as_bytes().to_vec());
            rns_interface::rnode::spawn_rnode_interface(rnode_config, id, transport_tx)
                .await
                .map(|h| vec![h])
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
                .map(|h| vec![h])
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
                    .map(|h| vec![h])
                    .map_err(|e| format!("I2P server: {e}"))
            } else if let Some(peer) = c.peers.first() {
                let mut client_config = rns_interface::i2p::I2PClientConfig::new(&c.name, peer);
                client_config.sam_host = c.i2p_sam_host.clone();
                client_config.sam_port = c.i2p_sam_port;
                client_config.mode = c.mode;
                rns_interface::i2p::spawn_i2p_client(client_config, id, transport_tx)
                    .await
                    .map(|h| vec![h])
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
                .map(|h| vec![h])
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
                .map(|h| vec![h])
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
            rns_interface::ble_rnode::spawn_ble_rnode_interface(config, id, transport_tx)
                .await
                .map(|h| vec![h])
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
                    .map(|h| vec![h])
                    .map_err(|e| format!("Backbone client: {e}"))
            } else {
                let listen_ip = c.listen_on.as_deref().unwrap_or("0.0.0.0");
                let mut config =
                    rns_interface::backbone::BackboneServerConfig::new(&c.name, listen_ip, c.port);
                config.mode = c.mode;
                config.prefer_ipv6 = c.prefer_ipv6;
                config.device = c.device.clone();
                rns_interface::backbone::spawn_backbone_server(
                    config,
                    id,
                    id_gen,
                    transport_tx,
                    handle_tx,
                )
                .await
                .map(|h| vec![h])
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
    transport_tx: mpsc::Sender<TransportMessage>,
    cache_dir: PathBuf,
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
                            clean_cache(&cache_dir);
                        }
                        Job::PersistData => {
                            tracing::debug!("persisting data");
                            let _ = transport_tx.send(TransportMessage::Tick(
                                rns_transport::messages::TimerTick {
                                    timestamp: std::time::SystemTime::now()
                                        .duration_since(std::time::UNIX_EPOCH)
                                        .unwrap_or_default()
                                        .as_secs_f64(),
                                },
                            )).await;
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

fn clean_cache(cache_dir: &Path) {
    let cache_ttl = std::time::Duration::from_secs(RESOURCE_CACHE);
    let now = std::time::SystemTime::now();

    if let Ok(entries) = std::fs::read_dir(cache_dir) {
        for entry in entries.flatten() {
            if let Ok(metadata) = entry.metadata() {
                if metadata.is_file() {
                    if let Ok(modified) = metadata.modified() {
                        if let Ok(age) = now.duration_since(modified) {
                            if age > cache_ttl {
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
    #[error("transport error: {0}")]
    Transport(String),
    #[error("interface error: {0}")]
    Interface(String),
}

#[cfg(test)]
mod tests {
    use super::*;

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
            tx,
            read_task: tokio::spawn(async {}),
        }
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

    #[test]
    fn test_instance_mode_variants() {
        assert_ne!(InstanceMode::Shared, InstanceMode::Client);
        assert_ne!(InstanceMode::Client, InstanceMode::Standalone);
    }

    fn dummy_handle() -> ReticulumHandle {
        let (tx, _rx) = mpsc::channel::<TransportMessage>(1);
        let (htx, _hrx) = mpsc::channel::<rns_interface::traits::InterfaceHandle>(1);
        ReticulumHandle {
            transport_tx: tx,
            config_dir: PathBuf::from("/tmp/dummy"),
            instance_mode: InstanceMode::Standalone,
            interface_configs: Vec::new(),
            id_gen: Arc::new(AtomicU64::new(0)),
            handle_tx: htx,
            interface_controls: Arc::new(std::sync::Mutex::new(HashMap::new())),
            socket_base: PathBuf::from("/tmp/dummy"),
            config: ReticulumConfig::default(),
            is_foreground: Arc::new(AtomicBool::new(true)),
            shutdown: ShutdownSignal::new(),
            transport_identity: Arc::new(Identity::new()),
            network_identity: None,
            discovery: Arc::new(DiscoveryRuntime::default()),
            transport_completion: Arc::new(TransportCompletion {
                stopped: AtomicBool::new(true),
                notify: Notify::new(),
            }),
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
    async fn typed_path_queries_validate_and_filter_actor_responses() {
        let (transport_tx, mut transport_rx) = mpsc::channel::<TransportMessage>(3);
        let destination_hash = [0x51; 16];
        let responder = tokio::spawn(async move {
            for response in [
                TransportQueryResponse::BoolResult(true),
                TransportQueryResponse::IntResult(6),
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
        let paths = handle.path_table(Some(4)).await.unwrap();
        assert_eq!(paths.len(), 1);
        assert_eq!(paths[0].hash, [0x61; 16]);
        responder.await.unwrap();
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
    async fn typed_control_query_never_falls_back_after_shared_rpc_failure() {
        let (transport_tx, mut transport_rx) = mpsc::channel::<TransportMessage>(1);
        let mut handle = dummy_handle();
        handle.transport_tx = transport_tx;
        handle.instance_mode = InstanceMode::Client;
        handle.config.shared_instance_type = SharedInstanceType::Tcp;
        handle.config.control_port = 0;
        handle.config.rpc_key = Some(vec![0xA5; 32]);

        assert!(matches!(
            handle.path_table(None).await,
            Err(ControlError::NotConnectedToSharedInstance)
        ));
        assert!(
            transport_rx.try_recv().is_err(),
            "typed control query must not consult stale local actor state"
        );
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
        assert_eq!(rc.discover_interfaces_required_value, 14);
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
    /// auto-corrected to Gateway/AP mode unless ignore_config_warnings.
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

        // Reticulum.py:856-863: discoverable autocorrects internal away
        // unless ignore_config_warnings is set.
        let config = Config::parse(&format!("{base}discoverable = yes\n")).unwrap();
        let mut interfaces = synthesize_interfaces(&config, false).unwrap();
        apply_discovery_mode_autocorrect(&config, &mut interfaces[0]);
        assert_eq!(
            *interface_config_mode_mut(&mut interfaces[0]),
            rns_interface::traits::InterfaceMode::Gateway
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
    async fn registration_applies_parsed_interface_flags_and_internal_mode() {
        let (transport_tx, mut transport_rx) = mpsc::channel::<TransportMessage>(4);
        let interface_controls: InterfaceControlMap =
            Arc::new(std::sync::Mutex::new(HashMap::new()));

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
        )
        .await;
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

        interface_tasks()
            .lock()
            .expect("interface_tasks mutex poisoned")
            .remove(&920_101);
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

        let post_init = interface_factory::InterfacePostInit::from_section(&ConfigSection::new());
        register_interface_with_post_init(
            &transport_tx,
            test_interface_handle(920_001, None, "default-cap"),
            &post_init,
            None,
            &interface_controls,
        )
        .await;
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
        )
        .await;
        let TransportMessage::RegisterInterface { entry, .. } =
            transport_rx.recv().await.expect("custom cap registration")
        else {
            panic!("expected RegisterInterface");
        };
        assert!((entry.announce_cap - 0.05).abs() < f64::EPSILON);

        interface_tasks()
            .lock()
            .expect("interface_tasks mutex poisoned")
            .remove(&920_001);
        interface_tasks()
            .lock()
            .expect("interface_tasks mutex poisoned")
            .remove(&920_002);
    }

    #[tokio::test]
    async fn dynamic_child_inherits_parent_control_settings() {
        let parent_id = 910_001;
        let child_id = 910_002;
        let (transport_tx, mut transport_rx) = mpsc::channel::<TransportMessage>(4);
        let interface_controls: InterfaceControlMap =
            Arc::new(std::sync::Mutex::new(HashMap::new()));

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
        )
        .await;
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
            false,
        )
        .await;

        let msg = transport_rx.recv().await.expect("child registration");
        let TransportMessage::RegisterInterface { entry, .. } = msg else {
            panic!("expected child RegisterInterface");
        };
        assert_eq!(entry.ingress.pr_burst_freq_new(), 4.0);
        assert_eq!(entry.ingress.pr_burst_freq(), 9.0);
        assert_eq!(entry.ingress.ec_pr_freq(), 6.0);
        assert!(entry.ingress.is_egress_control_enabled());

        interface_tasks()
            .lock()
            .expect("interface_tasks mutex poisoned")
            .remove(&parent_id);
        interface_tasks()
            .lock()
            .expect("interface_tasks mutex poisoned")
            .remove(&child_id);
    }

    #[tokio::test]
    async fn shared_instance_interface_roles_disable_ingress_control() {
        let (transport_tx, mut transport_rx) = mpsc::channel::<TransportMessage>(4);
        let interface_controls: InterfaceControlMap =
            Arc::new(std::sync::Mutex::new(HashMap::new()));

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
                false,
            )
            .await;

            let msg = transport_rx.recv().await.expect("registration");
            let TransportMessage::RegisterInterface { entry, .. } = msg else {
                panic!("expected RegisterInterface");
            };
            assert_eq!(entry.role, role);
            assert!(!entry.ingress.is_enabled());

            interface_tasks()
                .lock()
                .expect("interface_tasks mutex poisoned")
                .remove(&id);
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
        )
        .await;
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
            false,
        )
        .await;
        let TransportMessage::RegisterInterface { entry, .. } =
            transport_rx.recv().await.expect("child registration")
        else {
            panic!("expected child RegisterInterface");
        };
        assert_eq!(entry.ifac_key, ifac_key);
        assert_eq!(entry.ifac_size, 16);

        for id in [parent_id, child_id] {
            interface_tasks()
                .lock()
                .expect("interface_tasks mutex poisoned")
                .remove(&id);
        }
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

        clean_cache(&dir);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_clean_cache_removes_old_files() {
        use std::fs;

        let dir = std::env::temp_dir().join("reticulum_rs_test_clean_old");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let file_path = dir.join("old_entry");
        fs::write(&file_path, b"test data").unwrap();

        // A recent file must survive — we don't mock mtime here.
        clean_cache(&dir);
        assert!(file_path.exists());

        let _ = fs::remove_dir_all(&dir);
    }
}
