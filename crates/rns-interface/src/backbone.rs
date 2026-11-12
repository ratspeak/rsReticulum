//! HDLC-over-TCP backbone. The server creates an [`InterfaceHandle`] for each
//! accepted peer; the client reconnects after connection loss.
//! Per-peer socket tuning requests keepalive, NODELAY, and large buffers, with
//! TCP_USER_TIMEOUT where supported. The shared HDLC deframer caps each
//! encoded frame; this is not a bound on total connection memory.

use rns_transport::messages::InterfaceTransportSender;
use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use bytes::Bytes;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;

use crate::hdlc;
use crate::socket_tuning::{set_keepalive_tuned, set_socket_buffers};
use crate::traits::{
    ByteCounter, InterfaceDirection, InterfaceHandle, InterfaceId, InterfaceMode, TunnelIdentity,
    handoff_accepted_interface, open_client_connection, python_address_name, python_host,
};
use rns_transport::messages::{
    InboundPacket, InterfaceIdentity, InterfaceInspectionSnapshot, InterfaceInspectionSource,
    TransportMessage,
};

/// 1 MiB ceiling for MTU selection and requested socket buffer size.
/// Peer packet capacity is selected separately from the per-peer bitrate and
/// the interface wire budget; the kernel may clamp the socket buffer request.
pub const HW_MTU: u32 = 1_048_576;

/// Python `BackboneInterface.BITRATE_GUESS` and `BackboneClientInterface.BITRATE_GUESS`.
pub const BITRATE_GUESS: u64 = 100_000_000;

pub const RECONNECT_WAIT: u64 = 5;
pub const INITIAL_CONNECT_TIMEOUT: u64 = 5;

pub const TCP_PROBE_AFTER: u32 = 5;
pub const TCP_PROBE_INTERVAL: u32 = 2;
pub const TCP_PROBES: u32 = 12;
/// TCP_USER_TIMEOUT budget in seconds, applied best effort on supported platforms.
pub const TCP_USER_TIMEOUT: u32 = 24;

pub const BLOCK_FAST_FLAPPING: bool = true;
pub const FAST_FLAPPING_THRESHOLD: Duration = Duration::from_secs(20);
pub const FAST_FLAPPING_GRACE: u64 = 5;
pub const FAST_FLAPPING_BLOCK_TIME: Duration = Duration::from_secs(12 * 60 * 60);

const TX_CHANNEL_DEPTH: usize = 1024;

/// Dataplane egress control (BackboneInterface.py DP_EC_*, Interface.py tx_hwm).
pub const DP_EC_INTERVAL: Duration = Duration::from_secs(1);
pub const DP_EC_MID_WM: u64 = 128 * 1024;
pub const DP_EC_HIGH_WM: u64 = 4 * 1024 * 1024;
pub const DP_EC_STALL_TICKS: u32 = 3;
pub const DP_EC_MAX_ETA: f64 = 10.0;
pub const DP_EC_RELEASE_ETA: f64 = 5.0;
pub const DP_EC_DEAD_TIME: f64 = 12.0;
/// Per-connection transmit high-water mark in framed bytes.
pub const TX_HWM: u64 = 4 * 1024 * 1024;
/// Receive buffer requested on accepted sockets (BackboneInterface.py DP_IC_RCVBUF).
pub const DP_IC_RCVBUF: usize = 32768;

/// Bounds process-global fast-flap state to a conservative few hundred KiB.
///
/// Once full, unexpired tracked (including blocked) IPs retain their state and
/// new IPs remain admissible but are not tracked. Strictly expired entries can
/// be reclaimed. This prevents an address spray from turning the abuse
/// safeguard itself into an unbounded allocation.
const MAX_TRACKED_FAST_FLAP_IPS: usize = 4096;

#[derive(Debug, Clone)]
pub struct BackboneServerConfig {
    pub name: String,
    /// Host to bind; required unless `device` is set (BackboneInterface.py).
    pub listen_ip: Option<String>,
    pub listen_port: u16,
    pub prefer_ipv6: bool,
    pub mode: InterfaceMode,
    /// Optional kernel ifname; binds to its current IP. A device without an
    /// address is an error, as upstream.
    pub device: Option<String>,
    /// Reject a tracked IP after more than `fast_flapping_grace` short connections.
    /// The process-wide tracking table is bounded; a new IP is not tracked when
    /// that table is full.
    pub block_fast_flapping: bool,
    /// Connections shorter than this duration count as fast flaps.
    pub fast_flapping_threshold: Duration,
    /// Number of short connections tolerated before blocking starts.
    pub fast_flapping_grace: u64,
    /// Time since the latest short connection before its state expires.
    pub fast_flapping_block_time: Duration,
    /// Bitrate the hardware MTU is optimised for; accepted peers inherit it.
    pub bitrate: u64,
    /// IFAC size in bytes; accepted peers inherit it.
    pub ifac_size: usize,
}

impl BackboneServerConfig {
    pub fn new(name: &str, ip: &str, port: u16) -> Self {
        Self {
            name: name.to_string(),
            listen_ip: Some(ip.to_string()),
            listen_port: port,
            prefer_ipv6: false,
            mode: InterfaceMode::Full,
            device: None,
            block_fast_flapping: BLOCK_FAST_FLAPPING,
            fast_flapping_threshold: FAST_FLAPPING_THRESHOLD,
            fast_flapping_grace: FAST_FLAPPING_GRACE,
            fast_flapping_block_time: FAST_FLAPPING_BLOCK_TIME,
            bitrate: BITRATE_GUESS,
            ifac_size: crate::tcp::DEFAULT_IFAC_SIZE,
        }
    }
}

#[derive(Debug, Clone)]
pub struct BackboneClientConfig {
    pub name: String,
    pub target_host: String,
    pub target_port: u16,
    pub prefer_ipv6: bool,
    /// Parsed like Python, which stores it but connects with
    /// [`INITIAL_CONNECT_TIMEOUT`] (BackboneInterface.py).
    pub connect_timeout_secs: u64,
    /// Retries allowed within one outage; `None` retries forever.
    pub max_reconnect_tries: Option<usize>,
    pub mode: InterfaceMode,
    /// Identity used to request a signed tunnel synthesis for each connection.
    /// `None`, or an identity without signing material, sends no synthesis.
    pub tunnel_identity: Option<TunnelIdentity>,
    /// Bitrate the hardware MTU is optimised for.
    pub bitrate: u64,
    /// IFAC size in bytes; frames may exceed the hardware MTU by this much.
    pub ifac_size: usize,
}

impl BackboneClientConfig {
    pub fn new(name: &str, host: &str, port: u16) -> Self {
        Self {
            name: name.to_string(),
            target_host: host.to_string(),
            target_port: port,
            prefer_ipv6: false,
            connect_timeout_secs: INITIAL_CONNECT_TIMEOUT,
            max_reconnect_tries: None,
            mode: InterfaceMode::Full,
            tunnel_identity: None,
            bitrate: BITRATE_GUESS,
            ifac_size: crate::tcp::DEFAULT_IFAC_SIZE,
        }
    }

    /// Python `str(BackboneClientInterface)` (BackboneInterface.py).
    pub fn python_name(&self) -> String {
        format!(
            "BackboneInterface[{}/{}:{}]",
            self.name,
            python_host(&self.target_host),
            self.target_port
        )
    }
}

#[derive(Debug, Clone, Copy)]
struct FastFlapPolicy {
    enabled: bool,
    threshold: Duration,
    grace: u64,
    block_time: Duration,
}

impl From<&BackboneServerConfig> for FastFlapPolicy {
    fn from(config: &BackboneServerConfig) -> Self {
        Self {
            enabled: config.block_fast_flapping,
            threshold: config.fast_flapping_threshold,
            grace: config.fast_flapping_grace,
            block_time: config.fast_flapping_block_time,
        }
    }
}

trait MonotonicClock: Send + Sync {
    fn now(&self) -> Duration;
}

struct SystemMonotonicClock;

impl MonotonicClock for SystemMonotonicClock {
    fn now(&self) -> Duration {
        static EPOCH: OnceLock<Instant> = OnceLock::new();
        EPOCH.get_or_init(Instant::now).elapsed()
    }
}

#[derive(Debug, Clone, Copy)]
struct FastFlapEntry {
    last_flap: Duration,
    flaps: u64,
}

struct FastFlapTable {
    entries: HashMap<IpAddr, FastFlapEntry>,
    capacity: usize,
}

impl FastFlapTable {
    fn new(capacity: usize) -> Self {
        Self {
            entries: HashMap::new(),
            capacity,
        }
    }

    fn prune_expired(&mut self, now: Duration, block_time: Duration) {
        self.entries
            .retain(|_, entry| now.saturating_sub(entry.last_flap) <= block_time);
    }
}

#[derive(Clone)]
struct FastFlapRuntime {
    clock: Arc<dyn MonotonicClock>,
    table: Arc<Mutex<FastFlapTable>>,
}

impl FastFlapRuntime {
    fn production() -> Self {
        static TABLE: OnceLock<Arc<Mutex<FastFlapTable>>> = OnceLock::new();
        Self {
            clock: Arc::new(SystemMonotonicClock),
            table: Arc::clone(TABLE.get_or_init(|| {
                Arc::new(Mutex::new(FastFlapTable::new(MAX_TRACKED_FAST_FLAP_IPS)))
            })),
        }
    }

    fn admit(&self, remote_ip: IpAddr, policy: FastFlapPolicy) -> FastFlapAdmission {
        let started_at = self.clock.now();
        if !policy.enabled {
            return FastFlapAdmission::Allowed(FastFlapConnection {
                remote_ip,
                started_at: Some(started_at),
                policy,
                runtime: self.clone(),
            });
        }

        let mut table = self.table.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(entry) = table.entries.get(&remote_ip).copied() {
            if started_at.saturating_sub(entry.last_flap) > policy.block_time {
                table.entries.remove(&remote_ip);
            } else if entry.flaps > policy.grace {
                return FastFlapAdmission::Rejected { flaps: entry.flaps };
            }
        } else if table.entries.len() >= table.capacity {
            table.prune_expired(started_at, policy.block_time);
        }
        drop(table);

        FastFlapAdmission::Allowed(FastFlapConnection {
            remote_ip,
            started_at: Some(started_at),
            policy,
            runtime: self.clone(),
        })
    }

    fn record_disconnect(&self, remote_ip: IpAddr, started_at: Duration, policy: FastFlapPolicy) {
        if !policy.enabled {
            return;
        }

        let now = self.clock.now();
        if now.saturating_sub(started_at) >= policy.threshold {
            return;
        }

        let mut table = self.table.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(entry) = table.entries.get_mut(&remote_ip) {
            entry.last_flap = now;
            entry.flaps = entry.flaps.saturating_add(1);
            return;
        }
        if table.entries.len() >= table.capacity {
            table.prune_expired(now, policy.block_time);
        }
        if table.entries.len() >= table.capacity {
            tracing::debug!(
                remote_ip = %remote_ip,
                capacity = table.capacity,
                "backbone fast-flap table is full; declining to track new IP",
            );
            return;
        }
        table.entries.insert(
            remote_ip,
            FastFlapEntry {
                last_flap: now,
                flaps: 1,
            },
        );
    }

    fn inspection_snapshot(
        &self,
        policy: FastFlapPolicy,
        active_clients: &AtomicU64,
    ) -> InterfaceInspectionSnapshot {
        let blocked_ips = if policy.enabled {
            let now = self.clock.now();
            let mut table = self.table.lock().unwrap_or_else(|e| e.into_inner());
            table.prune_expired(now, policy.block_time);
            table
                .entries
                .values()
                .filter(|entry| entry.flaps > policy.grace)
                .count() as u64
        } else {
            0
        };

        InterfaceInspectionSnapshot {
            active_clients: Some(active_clients.load(Ordering::Relaxed)),
            blocked_ips: Some(blocked_ips),
            ..InterfaceInspectionSnapshot::default()
        }
    }
}

enum FastFlapAdmission {
    Allowed(FastFlapConnection),
    Rejected { flaps: u64 },
}

struct FastFlapConnection {
    remote_ip: IpAddr,
    started_at: Option<Duration>,
    policy: FastFlapPolicy,
    runtime: FastFlapRuntime,
}

impl FastFlapConnection {
    fn record_disconnect(&mut self) {
        if let Some(started_at) = self.started_at.take() {
            self.runtime
                .record_disconnect(self.remote_ip, started_at, self.policy);
        }
    }

    fn disconnected(mut self) {
        self.record_disconnect();
    }
}

impl Drop for FastFlapConnection {
    fn drop(&mut self) {
        // The guard lives in the child read-task future, so cancellation and
        // panic exits account for the connection just like normal EOF/errors.
        self.record_disconnect();
    }
}

struct ActiveClientGuard {
    active_clients: Arc<AtomicU64>,
}

impl ActiveClientGuard {
    fn new(active_clients: Arc<AtomicU64>) -> Self {
        active_clients.fetch_add(1, Ordering::Relaxed);
        Self { active_clients }
    }
}

impl Drop for ActiveClientGuard {
    fn drop(&mut self) {
        self.active_clients.fetch_sub(1, Ordering::Relaxed);
    }
}

fn keepalive_durations() -> (Duration, Duration, u32, Duration) {
    (
        Duration::from_secs(TCP_PROBE_AFTER as u64),
        Duration::from_secs(TCP_PROBE_INTERVAL as u64),
        TCP_PROBES,
        Duration::from_secs(TCP_USER_TIMEOUT as u64),
    )
}

fn tune_stream(stream: &TcpStream) {
    let _ = stream.set_nodelay(true);
    let (idle, intvl, retries, user_timeout) = keepalive_durations();
    set_keepalive_tuned(stream, idle, intvl, retries, user_timeout);
    set_socket_buffers(stream, HW_MTU as usize);
}

fn tune_accepted_stream(stream: &TcpStream) {
    tune_stream(stream);
    let _ = socket2::SockRef::from(stream).set_recv_buffer_size(DP_IC_RCVBUF);
}

async fn backbone_read_loop(
    mut reader: tokio::net::tcp::OwnedReadHalf,
    interface_id: InterfaceId,
    transport_tx: InterfaceTransportSender,
    online: Arc<AtomicBool>,
    rxb: ByteCounter,
    (bitrate, ifac_size): (u64, usize),
) {
    // ReceiveBuffer(HW_MTU, HEADER_MINSIZE, HW_MTU + ifac_size) (BackboneInterface.py).
    let hw_mtu = crate::tcp::hardware_mtu(bitrate, None) as usize;
    let mut deframer = hdlc::HdlcDeframer::with_limits(
        hw_mtu,
        rns_wire::constants::HEADER_MINSIZE,
        Some(hw_mtu + ifac_size),
    );
    // Large buffer to amortise syscalls.
    let mut buf = vec![0u8; 65536];
    loop {
        match reader.read(&mut buf).await {
            Ok(0) => {
                tracing::info!(interface_id, "backbone read: EOF");
                break;
            }
            Ok(n) => {
                for frame in deframer.feed(&buf[..n]) {
                    if frame.is_empty() {
                        continue;
                    }
                    rxb.add(frame.len());
                    let msg = TransportMessage::Inbound(InboundPacket {
                        raw: Bytes::from(frame),
                        interface_id,
                        rssi: None,
                        snr: None,
                        q: None,
                    });
                    if transport_tx.send(msg).await.is_err() {
                        tracing::warn!(interface_id, "transport channel closed");
                        online.store(false, Ordering::SeqCst);
                        return;
                    }
                }
            }
            Err(e) => {
                tracing::warn!(interface_id, error = %e, "backbone read error");
                break;
            }
        }
    }
    online.store(false, Ordering::SeqCst);
}

/// Per-connection dataplane egress control state (Python `_dp_ec_*`).
///
/// Times are seconds on any monotonic clock; the driver evaluates once per
/// [`DP_EC_INTERVAL`] with the connection's cumulative sent and buffered bytes.
#[derive(Debug, Clone, PartialEq)]
struct EgressControl {
    prev_sent: u64,
    zero_ticks: u32,
    last_drain: f64,
    stalled: bool,
}

impl EgressControl {
    fn new(now: f64) -> Self {
        Self {
            prev_sent: 0,
            zero_ticks: 0,
            last_drain: now,
            stalled: false,
        }
    }

    /// Whether outbound frames are currently gated (Python `tx_stalled`).
    fn stalled(&self) -> bool {
        self.stalled
    }

    /// One evaluation tick; `true` means the connection must be torn down.
    fn evaluate(&mut self, tx_sent: u64, buffered: u64, sendable: u64, now: f64) -> bool {
        let drained = tx_sent.saturating_sub(self.prev_sent);
        self.prev_sent = tx_sent;

        if buffered == 0 || sendable == 0 {
            self.zero_ticks = 0;
            self.last_drain = now;
            self.stalled = false;
            return false;
        }

        if now - self.last_drain >= DP_EC_DEAD_TIME {
            *self = Self::new(now);
            return true;
        }

        if drained > 0 {
            self.last_drain = now;
            self.zero_ticks = 0;
            let drain_rate = drained as f64 / DP_EC_INTERVAL.as_secs_f64();
            let clear_eta = buffered as f64 / drain_rate;
            if buffered > DP_EC_MID_WM && clear_eta > DP_EC_MAX_ETA {
                if !self.stalled {
                    tracing::debug!(
                        clear_eta,
                        "egress control drain ETA exceeds maximum, gating outbound"
                    );
                }
                self.stalled = true;
            } else if clear_eta < DP_EC_RELEASE_ETA || buffered <= DP_EC_MID_WM {
                if self.stalled {
                    tracing::debug!("egress control drain recovered, resuming outbound");
                }
                self.stalled = false;
            }
        } else if buffered > DP_EC_MID_WM {
            self.zero_ticks += 1;
            if self.zero_ticks >= DP_EC_STALL_TICKS {
                if !self.stalled {
                    tracing::debug!("no egress control drain progress, gating outbound");
                }
                self.stalled = true;
            }
        } else {
            self.zero_ticks = 0;
            self.stalled = false;
        }
        false
    }
}

/// Python `tx_stalled` and `len(transmit_buffer)` of one connection, read by stats.
#[derive(Debug, Default)]
struct EgressState {
    stalled: AtomicBool,
    buffered: AtomicU64,
}

impl EgressState {
    fn inspection(state: Arc<Self>) -> InterfaceInspectionSource {
        InterfaceInspectionSource::new(move || InterfaceInspectionSnapshot {
            tx_stalled: state.stalled.load(Ordering::Relaxed),
            tx_buffered: state.buffered.load(Ordering::Relaxed),
            ..InterfaceInspectionSnapshot::default()
        })
    }
}

/// HDLC-frames outbound packets into a byte-bounded transmit queue drained to
/// the socket, applying egress control. Returns when the connection must close.
async fn backbone_write_loop(
    writer: &mut tokio::net::tcp::OwnedWriteHalf,
    rx: &mut mpsc::Receiver<Bytes>,
    txb: &ByteCounter,
    name: &str,
    state: &EgressState,
) {
    let started = tokio::time::Instant::now();
    let mut control = EgressControl::new(0.0);
    let mut tick = tokio::time::interval_at(started + DP_EC_INTERVAL, DP_EC_INTERVAL);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut queue: VecDeque<Bytes> = VecDeque::new();
    let mut buffered: u64 = 0;
    let mut sent: u64 = 0;
    let mut tx_drops: u64 = 0;
    loop {
        let chunk = queue.front().cloned();
        tokio::select! {
            _ = tick.tick() => {
                let now = started.elapsed().as_secs_f64();
                let teardown = control.evaluate(sent, buffered, buffered, now);
                state.stalled.store(control.stalled(), Ordering::Relaxed);
                if teardown {
                    rns_transport::notice!(
                        name = %name,
                        "No egress control drain progress for {}s on {}, tearing down",
                        DP_EC_DEAD_TIME,
                        name,
                    );
                    return;
                }
            }
            result = async { writer.write(chunk.as_deref().unwrap_or_default()).await }, if chunk.is_some() => {
                match result {
                    Ok(0) => return,
                    Ok(n) => {
                        let written = n as u64;
                        sent += written;
                        buffered -= written;
                        state.buffered.store(buffered, Ordering::Relaxed);
                        txb.add(n);
                        if let Some(front) = queue.front_mut() {
                            if n >= front.len() {
                                queue.pop_front();
                            } else {
                                *front = front.slice(n..);
                            }
                        }
                    }
                    Err(e) => {
                        tracing::warn!(name = %name, error = %e, "backbone write error");
                        return;
                    }
                }
            }
            item = rx.recv() => {
                let Some(data) = item else { return };
                let frame = Bytes::from(hdlc::frame(&data));
                let len = frame.len() as u64;
                if control.stalled() || buffered + len > TX_HWM {
                    tx_drops += 1;
                    tracing::debug!(
                        name = %name,
                        frame_len = len,
                        tx_drops,
                        "egress control dropping outbound frame",
                    );
                } else {
                    buffered += len;
                    state.buffered.store(buffered, Ordering::Relaxed);
                    queue.push_back(frame);
                }
            }
        }
    }
}

/// Run one connection: the reader and the egress-controlled writer share a
/// task, so either side ending (or the task being aborted) closes the socket.
#[allow(clippy::too_many_arguments)]
async fn backbone_connection(
    stream: TcpStream,
    rx: &mut mpsc::Receiver<Bytes>,
    interface_id: InterfaceId,
    transport_tx: InterfaceTransportSender,
    online: Arc<AtomicBool>,
    rxb: ByteCounter,
    txb: ByteCounter,
    name: &str,
    state: &EgressState,
    sizing: (u64, usize),
) {
    let (reader, mut writer) = stream.into_split();
    tokio::select! {
        _ = backbone_read_loop(reader, interface_id, transport_tx, online.clone(), rxb, sizing) => {}
        _ = backbone_write_loop(&mut writer, rx, &txb, name, state) => {}
    }
    state.buffered.store(0, Ordering::Relaxed);
    online.store(false, Ordering::SeqCst);
}

/// Resolve `host:port` preferring the configured address family.
async fn resolve_target(
    host: &str,
    port: u16,
    prefer_ipv6: bool,
) -> std::io::Result<std::net::SocketAddr> {
    crate::tcp::resolve_host(host, port, prefer_ipv6).await
}

/// Spawn a backbone server; each accepted connection becomes an `InterfaceHandle`.
pub async fn spawn_backbone_server(
    config: BackboneServerConfig,
    id: InterfaceId,
    id_gen: Arc<AtomicU64>,
    transport_tx: mpsc::Sender<TransportMessage>,
    handle_tx: mpsc::Sender<InterfaceHandle>,
) -> Result<InterfaceHandle, crate::traits::InterfaceError> {
    spawn_backbone_server_with_runtime(
        config,
        id,
        id_gen,
        transport_tx,
        handle_tx,
        FastFlapRuntime::production(),
    )
    .await
}

async fn spawn_backbone_server_with_runtime(
    config: BackboneServerConfig,
    id: InterfaceId,
    id_gen: Arc<AtomicU64>,
    transport_tx: mpsc::Sender<TransportMessage>,
    handle_tx: mpsc::Sender<InterfaceHandle>,
    fast_flap_runtime: FastFlapRuntime,
) -> Result<InterfaceHandle, crate::traits::InterfaceError> {
    let bind_addr = crate::tcp::resolve_bind_address(
        config.listen_ip.as_deref(),
        config.device.as_deref(),
        config.listen_port,
        config.prefer_ipv6,
    )
    .await?;
    let listener = TcpListener::bind(&bind_addr).await?;
    spawn_backbone_server_on_listener(
        config,
        id,
        id_gen,
        transport_tx,
        handle_tx,
        fast_flap_runtime,
        listener,
    )
}

fn spawn_backbone_server_on_listener(
    config: BackboneServerConfig,
    id: InterfaceId,
    id_gen: Arc<AtomicU64>,
    transport_tx: mpsc::Sender<TransportMessage>,
    handle_tx: mpsc::Sender<InterfaceHandle>,
    fast_flap_runtime: FastFlapRuntime,
    listener: TcpListener,
) -> Result<InterfaceHandle, crate::traits::InterfaceError> {
    let transport_tx = InterfaceTransportSender::new(id, transport_tx);
    let owner = transport_tx.owner();
    let local_addr = listener.local_addr()?;
    tracing::info!(name = %config.name, addr = %local_addr, "backbone server listening");

    let online = Arc::new(AtomicBool::new(true));
    let online2 = online.clone();
    let name = config.name.clone();
    let mode = config.mode;
    let fast_flap_policy = FastFlapPolicy::from(&config);
    let sizing = (config.bitrate, config.ifac_size);
    let active_clients = Arc::new(AtomicU64::new(0));
    let inspection_runtime = fast_flap_runtime.clone();
    let inspection_active_clients = Arc::clone(&active_clients);
    let inspection = InterfaceInspectionSource::new(move || {
        inspection_runtime.inspection_snapshot(fast_flap_policy, inspection_active_clients.as_ref())
    });
    let task_active_clients = Arc::clone(&active_clients);
    let parent_rxb = Arc::new(AtomicU64::new(0));
    let parent_txb = Arc::new(AtomicU64::new(0));
    let task_parent_rxb = parent_rxb.clone();
    let task_parent_txb = parent_txb.clone();
    let listener_identity = InterfaceIdentity::new(
        python_address_name(
            "BackboneInterface",
            &config.name,
            &local_addr.ip().to_string(),
            local_addr.port(),
        ),
        &config.name,
        "BackboneInterface",
    );

    // Parent listener is inbound-only; drain task warns on stray writes.
    let (tx, mut listener_rx) = mpsc::channel::<Bytes>(1);
    let drain_name = name.clone();
    tokio::spawn(async move {
        while listener_rx.recv().await.is_some() {
            tracing::warn!(
                name = %drain_name,
                "backbone listener tx received unexpected outbound data; dropping",
            );
        }
    });

    let read_task = tokio::spawn(async move {
        // A child copies its parent's registration (IFAC, ingress control), so accept once it exists.
        if !transport_tx.ready().await {
            online2.store(false, Ordering::SeqCst);
            return;
        }
        loop {
            match listener.accept().await {
                Ok((stream, peer)) => {
                    let fast_flap_connection =
                        match fast_flap_runtime.admit(peer.ip(), fast_flap_policy) {
                            FastFlapAdmission::Allowed(connection) => connection,
                            FastFlapAdmission::Rejected { flaps } => {
                                tracing::debug!(target: "rns::pathing",
                                    remote_ip = %peer.ip(),
                                    flaps,
                                    "backbone: rejecting fast-flapping connection",
                                );
                                continue;
                            }
                        };

                    let client_id = id_gen.fetch_add(1, Ordering::SeqCst);
                    let client_name = format!("{}/client_{}", config.name, client_id);
                    tracing::debug!(target: "rns::pathing",
                        name = %client_name,
                        peer = %peer,
                        "backbone: accepted connection",
                    );

                    tune_accepted_stream(&stream);

                    let c_online = Arc::new(AtomicBool::new(true));
                    let c_rxb = Arc::new(AtomicU64::new(0));
                    let c_txb = Arc::new(AtomicU64::new(0));
                    let (c_tx, mut c_rx) = mpsc::channel::<Bytes>(TX_CHANNEL_DEPTH);

                    let c_online_r = c_online.clone();
                    let c_rxb_r = ByteCounter::new(c_rxb.clone(), Some(task_parent_rxb.clone()));
                    let c_txb_w = ByteCounter::new(c_txb.clone(), Some(task_parent_txb.clone()));
                    let transport_tx2 =
                        InterfaceTransportSender::new(client_id, transport_tx.actor_sender());
                    let child_owner = transport_tx2.owner();
                    let dereg_tx = transport_tx2.clone();
                    let cname = client_name.clone();
                    let active_client_guard =
                        ActiveClientGuard::new(Arc::clone(&task_active_clients));
                    let egress = Arc::new(EgressState::default());
                    let task_egress = egress.clone();
                    let read_handle = tokio::spawn(async move {
                        let _active_client_guard = active_client_guard;
                        backbone_connection(
                            stream,
                            &mut c_rx,
                            client_id,
                            transport_tx2,
                            c_online_r,
                            c_rxb_r,
                            c_txb_w,
                            &cname,
                            &task_egress,
                            sizing,
                        )
                        .await;
                        fast_flap_connection.disconnected();
                        tracing::debug!(target: "rns::pathing", name = %cname, "backbone client disconnected");
                        // Proactive notify so broadcasts don't target dead tx.
                        let _ = dereg_tx
                            .send(TransportMessage::DeregisterInterface { id: client_id })
                            .await;
                    });

                    let (child_mtu, packet_capacity) =
                        crate::tcp::hardware_capacity(sizing.0, None, sizing.1);
                    let spawned_name = format!("Client on {}", config.name);
                    let child_identity = InterfaceIdentity::new(
                        python_address_name(
                            "BackboneInterface",
                            &spawned_name,
                            &peer.ip().to_string(),
                            peer.port(),
                        ),
                        spawned_name,
                        "BackboneClientInterface",
                    );
                    let handle = InterfaceHandle {
                        id: client_id,
                        owner: child_owner,
                        packet_capacity,
                        parent_id: Some(id),
                        name: client_name,
                        mode,
                        direction: InterfaceDirection {
                            inbound: true,
                            outbound: true,
                            forward: false,
                            repeat: false,
                        },
                        bitrate: sizing.0,
                        mtu: child_mtu,
                        online: c_online,
                        rxb: Some(c_rxb),
                        txb: Some(c_txb),
                        inspection: Some(
                            EgressState::inspection(egress).with_identity(child_identity),
                        ),
                        tx: c_tx,
                        read_task: read_handle,
                    };
                    if handoff_accepted_interface(&handle_tx, handle)
                        .await
                        .is_err()
                    {
                        tracing::warn!("backbone handle registry closed");
                        break;
                    }
                }
                Err(e) => {
                    tracing::warn!(error = %e, "backbone accept error");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        }
        online2.store(false, Ordering::SeqCst);
    });

    let (mtu, packet_capacity) =
        crate::tcp::hardware_capacity(config.bitrate, None, config.ifac_size);
    Ok(InterfaceHandle {
        id,
        owner,
        packet_capacity,
        parent_id: None,
        name,
        mode,
        direction: InterfaceDirection {
            inbound: true,
            outbound: false,
            forward: false,
            repeat: false,
        },
        bitrate: config.bitrate,
        mtu,
        online,
        rxb: Some(parent_rxb),
        txb: Some(parent_txb),
        inspection: Some(inspection.with_identity(listener_identity)),
        tx,
        read_task,
    })
}

/// Resolve and connect, each step bounded by `timeout`.
async fn connect_backbone_target(
    config: &BackboneClientConfig,
    timeout: Duration,
) -> std::io::Result<TcpStream> {
    let target = tokio::time::timeout(
        timeout,
        resolve_target(&config.target_host, config.target_port, config.prefer_ipv6),
    )
    .await
    .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "resolve timed out"))??;
    tokio::time::timeout(timeout, TcpStream::connect(target))
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "connect timed out"))?
}

pub async fn spawn_backbone_client(
    config: BackboneClientConfig,
    id: InterfaceId,
    transport_tx: mpsc::Sender<TransportMessage>,
) -> Result<InterfaceHandle, crate::traits::InterfaceError> {
    spawn_backbone_client_observed(config, id, transport_tx)
        .await
        .map(|spawned| spawned.interface)
}

/// [`spawn_backbone_client`], also returning the client's teardown signal.
pub async fn spawn_backbone_client_observed(
    config: BackboneClientConfig,
    id: InterfaceId,
    transport_tx: mpsc::Sender<TransportMessage>,
) -> Result<crate::tcp::SpawnedClientInterface, crate::traits::InterfaceError> {
    let transport_tx = InterfaceTransportSender::new(id, transport_tx);
    let owner = transport_tx.owner();
    let online = Arc::new(AtomicBool::new(false));
    let online2 = online.clone();
    let (tx, rx) = mpsc::channel::<Bytes>(TX_CHANNEL_DEPTH);
    let name = config.name.clone();
    let mode = config.mode;
    let rx = Arc::new(tokio::sync::Mutex::new(rx));

    let shared_rxb = Arc::new(AtomicU64::new(0));
    let shared_txb = Arc::new(AtomicU64::new(0));
    let task_rxb = shared_rxb.clone();
    let task_txb = shared_txb.clone();

    let python_name = config.python_name();
    let sizing = (config.bitrate, config.ifac_size);
    let identity = InterfaceIdentity::new(&python_name, &config.name, "BackboneClientInterface");
    let egress = Arc::new(EgressState::default());
    let task_egress = egress.clone();
    let (teardown_tx, teardown) = crate::tcp::ClientTeardown::channel();
    // Python connects once, synchronously, before the interface is handed to
    // transport (BackboneInterface.py).
    let initial_timeout = Duration::from_secs(INITIAL_CONNECT_TIMEOUT);
    let mut initial_attempt = Some(
        tokio::time::timeout(
            initial_timeout,
            connect_backbone_target(&config, initial_timeout),
        )
        .await
        .unwrap_or_else(|_| Err(std::io::ErrorKind::TimedOut.into())),
    );
    if matches!(initial_attempt, Some(Ok(_))) {
        online.store(true, Ordering::SeqCst);
    }
    let read_task = tokio::spawn(async move {
        let max_tries = config.max_reconnect_tries;
        // Every attempt after the first follows a failure or an outage.
        let mut attempted = false;
        // Retries within the current outage (BackboneInterface.py).
        let mut attempts: usize = 0;

        loop {
            if attempted {
                tokio::time::sleep(Duration::from_secs(RECONNECT_WAIT)).await;
                attempts += 1;
                if max_tries.is_some_and(|max| attempts > max) {
                    tracing::warn!("Max reconnection attempts reached for {python_name}");
                    crate::tcp::hold_torn_down(&rx, &python_name, &teardown_tx).await;
                    return;
                }
            }
            attempted = true;
            let attempt = match initial_attempt.take() {
                Some(attempt) => attempt,
                None => connect_backbone_target(&config, initial_timeout).await,
            };
            let stream = match attempt {
                Ok(s) => s,
                Err(e) => {
                    tracing::warn!(name = %config.name, error = %e, "backbone connect failed");
                    continue;
                }
            };

            tune_stream(&stream);
            attempts = 0;
            // Python synthesizes on every connection (BackboneInterface.py,
            // :1019).
            let synthesis = config
                .tunnel_identity
                .as_ref()
                .and_then(|identity| identity.synthesis(&python_name));
            open_client_connection(&rx, &transport_tx, synthesis, &online2).await;

            {
                let mut outbound = rx.lock().await;
                backbone_connection(
                    stream,
                    &mut outbound,
                    id,
                    transport_tx.clone(),
                    online2.clone(),
                    ByteCounter::new(task_rxb.clone(), None),
                    ByteCounter::new(task_txb.clone(), None),
                    &python_name,
                    &task_egress,
                    sizing,
                )
                .await;
            }
            online2.store(false, Ordering::SeqCst);

            tracing::info!(
                name = %config.name,
                "backbone: reconnecting in {}s",
                RECONNECT_WAIT,
            );
        }
    });

    let (mtu, packet_capacity) = crate::tcp::hardware_capacity(sizing.0, None, sizing.1);
    Ok(crate::tcp::SpawnedClientInterface {
        interface: InterfaceHandle {
            id,
            owner,
            packet_capacity,
            parent_id: None,
            name,
            mode,
            direction: InterfaceDirection {
                inbound: true,
                outbound: true,
                forward: false,
                repeat: false,
            },
            bitrate: sizing.0,
            mtu,
            online,
            rxb: Some(shared_rxb),
            txb: Some(shared_txb),
            inspection: Some(EgressState::inspection(egress).with_identity(identity)),
            tx,
            read_task,
        },
        teardown,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddr};

    /// Replays the stub scenarios of the upstream `_dp_ec_evaluate` golden
    /// (RNS 1.6.0); expectations are its output.
    fn replay_egress(steps: &[(f64, u64, u64)]) -> Vec<(u64, bool, bool)> {
        let mut control = EgressControl::new(0.0);
        let (mut appended, mut sent) = (0u64, 0u64);
        steps
            .iter()
            .map(|&(t, append, drain)| {
                appended += append;
                sent += drain;
                let buffered = appended - sent;
                let teardown = control.evaluate(sent, buffered, buffered, t);
                if teardown {
                    appended = 0;
                    sent = 0;
                }
                (appended - sent, control.stalled(), teardown)
            })
            .collect()
    }

    const K: u64 = 1024;

    #[test]
    fn egress_slow_drain_above_mid_gates() {
        assert_eq!(
            replay_egress(&[(1.0, 64 * 16 * K, 0), (2.0, 0, 50 * K)]),
            [(1048576, false, false), (997376, true, false)]
        );
    }

    #[test]
    fn egress_three_zero_drain_ticks_above_mid_gate() {
        assert_eq!(
            replay_egress(&[(1.0, 256 * K, 0), (2.0, 0, 0), (3.0, 0, 0), (4.0, 0, 0)]),
            [
                (262144, false, false),
                (262144, false, false),
                (262144, true, false),
                (262144, true, false)
            ]
        );
    }

    #[test]
    fn egress_twelve_seconds_without_drain_tears_down() {
        let mut steps = vec![(0.5, 64 * K, 0)];
        steps.extend((1..14).map(|t| (t as f64, 0, 0)));
        let out = replay_egress(&steps);
        assert!(out[..12].iter().all(|&(b, s, d)| b == 65536 && !s && !d));
        assert_eq!(out[12], (0, false, true));
        assert_eq!(out[13], (0, false, false));
    }

    #[test]
    fn egress_fast_drain_releases_gate() {
        assert_eq!(
            replay_egress(&[(1.0, 1024 * K, 0), (2.0, 0, 50 * K), (3.0, 0, 400 * K)]),
            [
                (1048576, false, false),
                (997376, true, false),
                (587776, false, false)
            ]
        );
    }

    #[test]
    fn egress_drain_to_mid_unstalls() {
        assert_eq!(
            replay_egress(&[
                (1.0, 256 * K, 0),
                (2.0, 0, 0),
                (3.0, 0, 0),
                (4.0, 0, 160 * K)
            ]),
            [
                (262144, false, false),
                (262144, false, false),
                (262144, true, false),
                (98304, false, false)
            ]
        );
    }

    #[test]
    fn egress_empty_buffer_resets_gate_and_dead_clock() {
        assert_eq!(
            replay_egress(&[
                (1.0, 256 * K, 0),
                (2.0, 0, 0),
                (3.0, 0, 0),
                (4.0, 0, 256 * K),
                (15.0, K, 0)
            ]),
            [
                (262144, false, false),
                (262144, false, false),
                (262144, true, false),
                (0, false, false),
                (1024, false, false)
            ]
        );
    }

    async fn assert_peer_sees_close(peer: &mut TcpStream) {
        let mut buf = [0u8; 1024];
        let closed = tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                match peer.read(&mut buf).await {
                    Ok(0) | Err(_) => return,
                    Ok(_) => {}
                }
            }
        })
        .await;
        assert!(
            closed.is_ok(),
            "socket stayed open after the interface task was aborted"
        );
    }

    #[tokio::test]
    async fn client_is_online_when_spawn_returns_against_a_listening_server() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let (tx, _rx) = mpsc::channel(64);
        let handle = spawn_backbone_client(
            BackboneClientConfig::new("initial", "127.0.0.1", port),
            4,
            tx,
        )
        .await
        .unwrap();
        assert!(handle.online.load(Ordering::SeqCst));
        handle.read_task.abort();
    }

    #[tokio::test]
    async fn aborting_client_task_closes_its_socket() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let (tx, _rx) = mpsc::channel(64);
        let handle =
            spawn_backbone_client(BackboneClientConfig::new("abort", "127.0.0.1", port), 3, tx)
                .await
                .unwrap();
        handle.owner.mark_registered();
        let (mut peer, _) = listener.accept().await.unwrap();
        while !handle.online.load(Ordering::SeqCst) {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
        handle.read_task.abort();
        assert_peer_sees_close(&mut peer).await;
    }

    #[tokio::test]
    async fn aborting_accepted_child_task_closes_its_socket() {
        let (tx, _rx) = mpsc::channel(64);
        let (handle_tx, mut handle_rx) = mpsc::channel(4);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (runtime, _clock) = test_runtime(16);
        let parent = spawn_backbone_server_on_listener(
            BackboneServerConfig::new("abort-srv", "127.0.0.1", addr.port()),
            10,
            Arc::new(AtomicU64::new(11)),
            tx,
            handle_tx,
            runtime,
            listener,
        )
        .unwrap();
        parent.owner.mark_registered();
        let mut peer = TcpStream::connect(addr).await.unwrap();
        let child = handle_rx.recv().await.unwrap();
        child.read_task.abort();
        assert_peer_sees_close(&mut peer).await;
        parent.read_task.abort();
    }

    #[tokio::test]
    async fn accepted_socket_requests_small_receive_buffer() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let _client = TcpStream::connect(addr).await.unwrap();
        let (accepted, _) = listener.accept().await.unwrap();
        tune_accepted_stream(&accepted);
        let rcvbuf = socket2::SockRef::from(&accepted)
            .recv_buffer_size()
            .unwrap();
        // Linux doubles the request for bookkeeping overhead.
        assert!(rcvbuf <= 2 * DP_IC_RCVBUF, "rcvbuf {rcvbuf}");
    }

    #[test]
    fn client_python_names_match_python() {
        // Python 1.5.5 `str()` output for these interfaces.
        for (host, expected) in [
            (
                "10.0.0.1",
                "BackboneInterface[Golden Backbone/10.0.0.1:4243]",
            ),
            (
                "fd00::1",
                "BackboneInterface[Golden Backbone/[fd00::1]:4243]",
            ),
        ] {
            assert_eq!(
                BackboneClientConfig::new("Golden Backbone", host, 4243).python_name(),
                expected
            );
        }
    }

    #[derive(Clone)]
    struct TestClock {
        now: Arc<Mutex<Duration>>,
    }

    impl TestClock {
        fn new() -> Self {
            Self {
                now: Arc::new(Mutex::new(Duration::ZERO)),
            }
        }

        fn advance(&self, duration: Duration) {
            let mut now = self.now.lock().unwrap_or_else(|e| e.into_inner());
            *now = now
                .checked_add(duration)
                .expect("test monotonic clock overflow");
        }
    }

    impl MonotonicClock for TestClock {
        fn now(&self) -> Duration {
            *self.now.lock().unwrap_or_else(|e| e.into_inner())
        }
    }

    fn test_runtime(capacity: usize) -> (FastFlapRuntime, TestClock) {
        let clock = TestClock::new();
        (
            FastFlapRuntime {
                clock: Arc::new(clock.clone()),
                table: Arc::new(Mutex::new(FastFlapTable::new(capacity))),
            },
            clock,
        )
    }

    fn default_policy() -> FastFlapPolicy {
        FastFlapPolicy {
            enabled: BLOCK_FAST_FLAPPING,
            threshold: FAST_FLAPPING_THRESHOLD,
            grace: FAST_FLAPPING_GRACE,
            block_time: FAST_FLAPPING_BLOCK_TIME,
        }
    }

    fn allow_connection(
        runtime: &FastFlapRuntime,
        ip: IpAddr,
        policy: FastFlapPolicy,
    ) -> FastFlapConnection {
        match runtime.admit(ip, policy) {
            FastFlapAdmission::Allowed(connection) => connection,
            FastFlapAdmission::Rejected { flaps } => {
                panic!("expected connection from {ip} to be allowed, recorded flaps: {flaps}")
            }
        }
    }

    fn assert_rejected(runtime: &FastFlapRuntime, ip: IpAddr, policy: FastFlapPolicy) {
        assert!(matches!(
            runtime.admit(ip, policy),
            FastFlapAdmission::Rejected { .. }
        ));
    }

    fn record_short_connection(
        runtime: &FastFlapRuntime,
        clock: &TestClock,
        ip: IpAddr,
        policy: FastFlapPolicy,
    ) {
        let connection = allow_connection(runtime, ip, policy);
        clock.advance(Duration::from_millis(1));
        connection.disconnected();
    }

    fn tracked_flaps(runtime: &FastFlapRuntime, ip: IpAddr) -> Option<u64> {
        runtime
            .table
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .entries
            .get(&ip)
            .map(|entry| entry.flaps)
    }

    fn inspection_snapshot(handle: &InterfaceHandle) -> InterfaceInspectionSnapshot {
        handle
            .inspection
            .as_ref()
            .expect("backbone listener exposes aggregate inspection")
            .snapshot()
    }

    #[test]
    fn test_backbone_server_config() {
        let cfg = BackboneServerConfig::new("backbone0", "0.0.0.0", 4243);
        assert_eq!(cfg.listen_port, 4243);
        assert!(!cfg.prefer_ipv6);
        assert!(cfg.device.is_none());
        assert!(cfg.block_fast_flapping);
        assert_eq!(cfg.fast_flapping_threshold, Duration::from_secs(20));
        assert_eq!(cfg.fast_flapping_grace, 5);
        assert_eq!(
            cfg.fast_flapping_block_time,
            Duration::from_secs(12 * 60 * 60)
        );
    }

    #[test]
    fn test_backbone_client_config() {
        let cfg = BackboneClientConfig::new("bb-client", "10.0.0.1", 4243);
        assert_eq!(cfg.target_host, "10.0.0.1");
        assert_eq!(cfg.connect_timeout_secs, INITIAL_CONNECT_TIMEOUT);
    }

    #[test]
    fn test_constants() {
        assert_eq!(HW_MTU, 1_048_576);
        assert_eq!(BITRATE_GUESS, 100_000_000);
        assert_eq!(RECONNECT_WAIT, 5);
    }

    #[test]
    fn test_backbone_server_config_mode() {
        let cfg = BackboneServerConfig::new("bb-srv", "0.0.0.0", 4243);
        assert_eq!(cfg.mode, InterfaceMode::Full);
        assert_eq!(cfg.listen_ip.as_deref(), Some("0.0.0.0"));
        assert_eq!(cfg.name, "bb-srv");
    }

    #[test]
    fn test_backbone_client_config_defaults() {
        let cfg = BackboneClientConfig::new("bb-cli", "192.168.1.1", 4243);
        assert_eq!(cfg.target_host, "192.168.1.1");
        assert_eq!(cfg.target_port, 4243);
        assert_eq!(cfg.mode, InterfaceMode::Full);
        assert!(cfg.max_reconnect_tries.is_none());
    }

    #[test]
    fn test_backbone_config_ipv6() {
        let cfg = BackboneServerConfig::new("bb-v6", "::", 4243);
        assert!(!cfg.prefer_ipv6);
        let mut cfg = cfg;
        cfg.prefer_ipv6 = true;
        assert!(cfg.prefer_ipv6);
    }

    #[test]
    fn fast_flap_grace_is_strictly_greater_than_five() {
        let (runtime, clock) = test_runtime(16);
        let policy = default_policy();
        let ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));

        // Upstream's strict `flaps > grace` admits and records six short
        // connections for grace=5. The following (seventh) admission blocks.
        for _ in 0..=policy.grace {
            record_short_connection(&runtime, &clock, ip, policy);
        }
        assert_eq!(tracked_flaps(&runtime, ip), Some(6));
        assert_rejected(&runtime, ip, policy);
    }

    #[test]
    fn threshold_and_expiry_boundaries_are_strict() {
        let (runtime, clock) = test_runtime(16);
        let mut policy = default_policy();
        policy.grace = 0;
        let stable_ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2));
        let blocked_ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 3));

        let stable = allow_connection(&runtime, stable_ip, policy);
        clock.advance(policy.threshold);
        stable.disconnected();
        assert_eq!(tracked_flaps(&runtime, stable_ip), None);

        record_short_connection(&runtime, &clock, blocked_ip, policy);
        clock.advance(policy.block_time);
        assert_rejected(&runtime, blocked_ip, policy);
        clock.advance(Duration::from_nanos(1));
        let readmitted = allow_connection(&runtime, blocked_ip, policy);
        assert_eq!(tracked_flaps(&runtime, blocked_ip), None);
        readmitted.disconnected();
    }

    #[test]
    fn stable_connection_does_not_reset_existing_flaps() {
        let (runtime, clock) = test_runtime(16);
        let mut policy = default_policy();
        policy.grace = 1;
        let ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 4));

        record_short_connection(&runtime, &clock, ip, policy);
        let stable = allow_connection(&runtime, ip, policy);
        clock.advance(policy.threshold);
        stable.disconnected();
        assert_eq!(tracked_flaps(&runtime, ip), Some(1));

        record_short_connection(&runtime, &clock, ip, policy);
        assert_eq!(tracked_flaps(&runtime, ip), Some(2));
        assert_rejected(&runtime, ip, policy);
    }

    #[test]
    fn rejected_connection_does_not_refresh_expiry() {
        let (runtime, clock) = test_runtime(16);
        let mut policy = default_policy();
        policy.grace = 0;
        let ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 5));

        record_short_connection(&runtime, &clock, ip, policy);
        clock.advance(policy.block_time - Duration::from_nanos(1));
        assert_rejected(&runtime, ip, policy);
        clock.advance(Duration::from_nanos(2));
        let readmitted = allow_connection(&runtime, ip, policy);
        assert_eq!(tracked_flaps(&runtime, ip), None);
        readmitted.disconnected();
    }

    #[test]
    fn disabled_policy_neither_tracks_nor_blocks() {
        let (runtime, clock) = test_runtime(16);
        let mut policy = default_policy();
        policy.enabled = false;
        policy.grace = 0;
        let ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 6));

        for _ in 0..10 {
            record_short_connection(&runtime, &clock, ip, policy);
        }
        assert_eq!(tracked_flaps(&runtime, ip), None);
        let admitted = allow_connection(&runtime, ip, policy);
        admitted.disconnected();
        let active_clients = AtomicU64::new(0);
        assert_eq!(
            runtime.inspection_snapshot(policy, &active_clients),
            InterfaceInspectionSnapshot {
                active_clients: Some(0),
                blocked_ips: Some(0),
                ..Default::default()
            }
        );
    }

    #[test]
    fn inspection_uses_strict_grace_and_expiry_boundaries() {
        let (runtime, clock) = test_runtime(16);
        let policy = default_policy();
        let ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 12));
        let active_clients = AtomicU64::new(3);

        for _ in 0..policy.grace {
            record_short_connection(&runtime, &clock, ip, policy);
        }
        assert_eq!(
            runtime.inspection_snapshot(policy, &active_clients),
            InterfaceInspectionSnapshot {
                active_clients: Some(3),
                blocked_ips: Some(0),
                ..Default::default()
            }
        );

        record_short_connection(&runtime, &clock, ip, policy);
        assert_eq!(
            runtime
                .inspection_snapshot(policy, &active_clients)
                .blocked_ips,
            Some(1)
        );
        clock.advance(policy.block_time);
        assert_eq!(
            runtime
                .inspection_snapshot(policy, &active_clients)
                .blocked_ips,
            Some(1)
        );
        clock.advance(Duration::from_nanos(1));
        assert_eq!(
            runtime
                .inspection_snapshot(policy, &active_clients)
                .blocked_ips,
            Some(0)
        );
    }

    #[test]
    fn repeated_inspection_snapshots_are_live_and_non_destructive() {
        let (runtime, clock) = test_runtime(16);
        let mut policy = default_policy();
        policy.grace = 0;
        let ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 13));
        let active_clients = AtomicU64::new(1);
        record_short_connection(&runtime, &clock, ip, policy);

        let first = runtime.inspection_snapshot(policy, &active_clients);
        let second = runtime.inspection_snapshot(policy, &active_clients);
        assert_eq!(first, second);
        assert_eq!(first.active_clients, Some(1));
        assert_eq!(first.blocked_ips, Some(1));

        active_clients.store(2, Ordering::Relaxed);
        assert_eq!(
            runtime
                .inspection_snapshot(policy, &active_clients)
                .active_clients,
            Some(2)
        );
    }

    #[test]
    fn blocking_is_ip_scoped() {
        let (runtime, clock) = test_runtime(16);
        let mut policy = default_policy();
        policy.grace = 0;
        let blocked_ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7));
        let other_ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 8));

        record_short_connection(&runtime, &clock, blocked_ip, policy);
        assert_rejected(&runtime, blocked_ip, policy);
        let other = allow_connection(&runtime, other_ip, policy);
        other.disconnected();
    }

    #[test]
    fn listeners_share_one_process_global_ip_keyspace() {
        let clock = TestClock::new();
        let table = Arc::new(Mutex::new(FastFlapTable::new(16)));
        let first_listener = FastFlapRuntime {
            clock: Arc::new(clock.clone()),
            table: Arc::clone(&table),
        };
        let second_listener = FastFlapRuntime {
            clock: Arc::new(clock.clone()),
            table,
        };
        let policy = default_policy();
        let ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 9));

        for index in 0..=policy.grace {
            let listener = if index.is_multiple_of(2) {
                &first_listener
            } else {
                &second_listener
            };
            record_short_connection(listener, &clock, ip, policy);
        }
        assert_rejected(&first_listener, ip, policy);
        assert_rejected(&second_listener, ip, policy);
    }

    #[test]
    fn full_table_preserves_unexpired_entries_and_reuses_expired_slots() {
        let (runtime, clock) = test_runtime(1);
        let mut policy = default_policy();
        policy.grace = 0;
        let tracked_ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));
        let untracked_ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 11));

        record_short_connection(&runtime, &clock, tracked_ip, policy);
        record_short_connection(&runtime, &clock, untracked_ip, policy);

        assert_eq!(tracked_flaps(&runtime, tracked_ip), Some(1));
        assert_eq!(tracked_flaps(&runtime, untracked_ip), None);
        assert_rejected(&runtime, tracked_ip, policy);
        let untracked = allow_connection(&runtime, untracked_ip, policy);
        untracked.disconnected();

        clock.advance(policy.block_time + Duration::from_nanos(1));
        record_short_connection(&runtime, &clock, untracked_ip, policy);
        assert_eq!(tracked_flaps(&runtime, tracked_ip), None);
        assert_eq!(tracked_flaps(&runtime, untracked_ip), Some(1));
    }

    #[tokio::test]
    async fn aborted_child_read_task_records_short_connection() {
        let (runtime, clock) = test_runtime(16);
        let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .await
            .unwrap();
        let listen_addr = listener.local_addr().unwrap();
        let config =
            BackboneServerConfig::new("abort-accounting-test", "127.0.0.1", listen_addr.port());
        let id_gen = Arc::new(AtomicU64::new(100));
        let (transport_tx, _transport_rx) = mpsc::channel(8);
        let (handle_tx, mut handle_rx) = mpsc::channel(8);
        let parent = spawn_backbone_server_on_listener(
            config,
            1,
            id_gen,
            transport_tx,
            handle_tx,
            runtime.clone(),
            listener,
        )
        .unwrap();
        parent.owner.mark_registered();
        assert_eq!(inspection_snapshot(&parent).active_clients, Some(0));

        let _stream = TcpStream::connect(listen_addr).await.unwrap();
        let child = tokio::time::timeout(Duration::from_secs(1), handle_rx.recv())
            .await
            .expect("accepted child handle timed out")
            .expect("child handle channel closed");
        child.owner.mark_registered();
        assert_eq!(inspection_snapshot(&parent).active_clients, Some(1));
        clock.advance(Duration::from_millis(1));
        child.read_task.abort();
        let _ = child.read_task.await;

        assert_eq!(inspection_snapshot(&parent).active_clients, Some(0));
        assert_eq!(
            tracked_flaps(&runtime, IpAddr::V4(Ipv4Addr::LOCALHOST)),
            Some(1)
        );
        parent.read_task.abort();
    }

    #[tokio::test]
    async fn rejected_admission_does_not_consume_child_id_or_handle() {
        let (runtime, clock) = test_runtime(16);
        let mut policy = default_policy();
        policy.grace = 0;
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        record_short_connection(&runtime, &clock, ip, policy);

        let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .await
            .unwrap();
        let listen_addr = listener.local_addr().unwrap();
        let mut config =
            BackboneServerConfig::new("blocked-id-test", "127.0.0.1", listen_addr.port());
        config.fast_flapping_grace = 0;
        let id_gen = Arc::new(AtomicU64::new(100));
        let (transport_tx, _transport_rx) = mpsc::channel(8);
        let (handle_tx, mut handle_rx) = mpsc::channel(8);
        let parent = spawn_backbone_server_on_listener(
            config,
            1,
            Arc::clone(&id_gen),
            transport_tx,
            handle_tx,
            runtime,
            listener,
        )
        .unwrap();
        parent.owner.mark_registered();
        assert_eq!(inspection_snapshot(&parent).active_clients, Some(0));

        let mut stream = TcpStream::connect(listen_addr).await.unwrap();
        let mut byte = [0u8; 1];
        let closed = tokio::time::timeout(Duration::from_secs(1), stream.read(&mut byte))
            .await
            .expect("blocked connection was not closed");
        assert!(matches!(closed, Ok(0) | Err(_)));
        assert_eq!(id_gen.load(Ordering::SeqCst), 100);
        assert!(handle_rx.try_recv().is_err());
        assert_eq!(inspection_snapshot(&parent).active_clients, Some(0));
        assert_eq!(inspection_snapshot(&parent).blocked_ips, Some(1));

        parent.read_task.abort();
    }

    /// Spending the retry budget tears the client down like Python's
    /// initiator: registered, offline, never deregistered.
    #[tokio::test]
    async fn give_up_keeps_interface_registered_and_offline() {
        let mut cfg = BackboneClientConfig::new("bb-giveup", "127.0.0.1", 1);
        cfg.max_reconnect_tries = Some(0);

        let (tx, mut rx) = mpsc::channel::<TransportMessage>(8);
        let handle = spawn_backbone_client(cfg, 99, tx).await.unwrap();
        handle.owner.mark_registered();
        let early = tokio::time::timeout(Duration::from_secs(RECONNECT_WAIT + 3), rx.recv()).await;
        assert!(early.is_err(), "no message expected, got {early:?}");
        assert!(!handle.read_task.is_finished());
        assert!(!handle.online.load(Ordering::SeqCst));
        handle.read_task.abort();
    }

    #[tokio::test]
    async fn test_resolve_target_loopback_v4() {
        let addr = resolve_target("127.0.0.1", 1234, false).await.unwrap();
        assert!(addr.is_ipv4());
        assert_eq!(addr.port(), 1234);
    }
}
