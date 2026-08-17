//! High-throughput HDLC-over-TCP backbone. Server accepts many peers
//! (each its own [`InterfaceHandle`]); client auto-reconnects.
//! Per-peer tuning: TCP keepalive + TCP_USER_TIMEOUT + NODELAY + large
//! buffers. Inbound deframer is capped (vs Python's unbounded) to avoid
//! malformed-peer memory blow-up.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use bytes::Bytes;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;

use crate::hdlc;
use crate::socket_tuning::{iface_addr_for, set_keepalive_tuned, set_socket_buffers};
use crate::traits::{
    InterfaceDirection, InterfaceHandle, InterfaceId, InterfaceMode, handoff_accepted_interface,
};
use rns_transport::messages::{
    InboundPacket, InterfaceInspectionSnapshot, InterfaceInspectionSource, TransportMessage,
};

/// 1 MiB MTU — also the SO_RCVBUF/SNDBUF target (kernel clamps).
pub const HW_MTU: u32 = 1_048_576;

/// Listener-side bitrate guess advertised on the parent handle.
pub const BITRATE_GUESS: u64 = 1_000_000_000;

/// Per-peer guess (100 Mbps) — drives [`crate::traits::optimise_mtu`] → 64 KiB MTU.
pub const CHILD_BITRATE_GUESS: u64 = 100_000_000;

pub const RECONNECT_WAIT: u64 = 5;
pub const INITIAL_CONNECT_TIMEOUT: u64 = 5;

pub const TCP_PROBE_AFTER: u32 = 5;
pub const TCP_PROBE_INTERVAL: u32 = 2;
pub const TCP_PROBES: u32 = 12;
/// Linux TCP_USER_TIMEOUT — drops stuck conns when peer goes silent without RST.
pub const TCP_USER_TIMEOUT: u32 = 24;

pub const BLOCK_FAST_FLAPPING: bool = true;
pub const FAST_FLAPPING_THRESHOLD: Duration = Duration::from_secs(20);
pub const FAST_FLAPPING_GRACE: u64 = 5;
pub const FAST_FLAPPING_BLOCK_TIME: Duration = Duration::from_secs(12 * 60 * 60);

const TX_CHANNEL_DEPTH: usize = 1024;

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
    pub listen_ip: String,
    pub listen_port: u16,
    pub prefer_ipv6: bool,
    pub mode: InterfaceMode,
    /// Optional kernel ifname; binds to its current IP (falls back to `listen_ip`).
    pub device: Option<String>,
    /// Reject an IP after more than `fast_flapping_grace` short connections.
    pub block_fast_flapping: bool,
    /// Connections shorter than this duration count as fast flaps.
    pub fast_flapping_threshold: Duration,
    /// Number of short connections tolerated before blocking starts.
    pub fast_flapping_grace: u64,
    /// Time since the latest short connection before its state expires.
    pub fast_flapping_block_time: Duration,
}

impl BackboneServerConfig {
    pub fn new(name: &str, ip: &str, port: u16) -> Self {
        Self {
            name: name.to_string(),
            listen_ip: ip.to_string(),
            listen_port: port,
            prefer_ipv6: false,
            mode: InterfaceMode::Full,
            device: None,
            block_fast_flapping: BLOCK_FAST_FLAPPING,
            fast_flapping_threshold: FAST_FLAPPING_THRESHOLD,
            fast_flapping_grace: FAST_FLAPPING_GRACE,
            fast_flapping_block_time: FAST_FLAPPING_BLOCK_TIME,
        }
    }
}

#[derive(Debug, Clone)]
pub struct BackboneClientConfig {
    pub name: String,
    pub target_host: String,
    pub target_port: u16,
    pub prefer_ipv6: bool,
    pub connect_timeout_secs: u64,
    pub max_reconnect_tries: Option<usize>,
    pub mode: InterfaceMode,
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
        }
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

fn child_mtu() -> u32 {
    crate::traits::optimise_mtu(CHILD_BITRATE_GUESS)
        .map(|m| m.min(HW_MTU))
        .unwrap_or(rns_wire::constants::MTU as u32)
}

async fn backbone_read_loop(
    mut reader: tokio::net::tcp::OwnedReadHalf,
    interface_id: InterfaceId,
    transport_tx: mpsc::Sender<TransportMessage>,
    online: Arc<AtomicBool>,
    rxb: Arc<AtomicU64>,
) {
    let mut deframer = hdlc::HdlcDeframer::new();
    // Large buffer to amortise syscalls; inbound capped by HdlcDeframer::MAX_FRAME_SIZE.
    let mut buf = vec![0u8; 65536];
    loop {
        match reader.read(&mut buf).await {
            Ok(0) => {
                tracing::info!(interface_id, "backbone read: EOF");
                break;
            }
            Ok(n) => {
                rxb.fetch_add(n as u64, Ordering::Relaxed);
                for frame in deframer.feed(&buf[..n]) {
                    if frame.is_empty() {
                        continue;
                    }
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

async fn backbone_write_loop(
    mut writer: tokio::net::tcp::OwnedWriteHalf,
    mut rx: mpsc::Receiver<Bytes>,
    online: Arc<AtomicBool>,
    txb: Arc<AtomicU64>,
) {
    while let Some(data) = rx.recv().await {
        let framed = hdlc::frame(&data);
        txb.fetch_add(framed.len() as u64, Ordering::Relaxed);
        if let Err(e) = writer.write_all(&framed).await {
            tracing::warn!(error = %e, "backbone write error");
            break;
        }
    }
    online.store(false, Ordering::SeqCst);
}

/// `device` takes precedence over `listen_ip` when its lookup succeeds.
fn resolve_listen_addr(config: &BackboneServerConfig) -> String {
    if let Some(name) = config.device.as_deref() {
        match iface_addr_for(name, config.prefer_ipv6) {
            Some(IpAddr::V4(v4)) => return v4.to_string(),
            Some(IpAddr::V6(v6)) => return format!("[{}]", v6),
            None => {
                tracing::warn!(
                    device = %name,
                    listen_ip = %config.listen_ip,
                    "backbone: device lookup failed, falling back to listen_ip",
                );
            }
        }
    }
    config.listen_ip.clone()
}

/// Resolve `host:port` preferring the configured address family.
async fn resolve_target(
    host: &str,
    port: u16,
    prefer_ipv6: bool,
) -> std::io::Result<std::net::SocketAddr> {
    let mut addrs: Vec<std::net::SocketAddr> =
        tokio::net::lookup_host((host, port)).await?.collect();
    if addrs.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::AddrNotAvailable,
            format!("no addresses resolved for {host}:{port}"),
        ));
    }
    // Prefer the requested family; else first resolved.
    let preferred = if prefer_ipv6 {
        addrs.iter().find(|a| a.is_ipv6()).copied()
    } else {
        addrs.iter().find(|a| a.is_ipv4()).copied()
    };
    Ok(preferred.unwrap_or_else(|| addrs.remove(0)))
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
    let listen_ip = resolve_listen_addr(&config);
    let bind_addr = if listen_ip.starts_with('[') {
        format!("{}:{}", listen_ip, config.listen_port)
    } else if listen_ip.contains(':') && !listen_ip.contains('.') {
        format!("[{}]:{}", listen_ip, config.listen_port)
    } else {
        format!("{}:{}", listen_ip, config.listen_port)
    };
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
    let local_addr = listener.local_addr()?;
    tracing::info!(name = %config.name, addr = %local_addr, "backbone server listening");

    let online = Arc::new(AtomicBool::new(true));
    let online2 = online.clone();
    let name = config.name.clone();
    let mode = config.mode;
    let fast_flap_policy = FastFlapPolicy::from(&config);
    let active_clients = Arc::new(AtomicU64::new(0));
    let inspection_runtime = fast_flap_runtime.clone();
    let inspection_active_clients = Arc::clone(&active_clients);
    let inspection = InterfaceInspectionSource::new(move || {
        inspection_runtime.inspection_snapshot(fast_flap_policy, inspection_active_clients.as_ref())
    });
    let task_active_clients = Arc::clone(&active_clients);

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
        loop {
            match listener.accept().await {
                Ok((stream, peer)) => {
                    let fast_flap_connection =
                        match fast_flap_runtime.admit(peer.ip(), fast_flap_policy) {
                            FastFlapAdmission::Allowed(connection) => connection,
                            FastFlapAdmission::Rejected { flaps } => {
                                tracing::warn!(
                                    remote_ip = %peer.ip(),
                                    flaps,
                                    "backbone: rejecting fast-flapping connection",
                                );
                                continue;
                            }
                        };

                    let client_id = id_gen.fetch_add(1, Ordering::SeqCst);
                    let client_name = format!("{}/client_{}", config.name, client_id);
                    tracing::info!(
                        name = %client_name,
                        peer = %peer,
                        "backbone: accepted connection",
                    );

                    tune_stream(&stream);

                    let c_online = Arc::new(AtomicBool::new(true));
                    let c_rxb = Arc::new(AtomicU64::new(0));
                    let c_txb = Arc::new(AtomicU64::new(0));
                    let (c_tx, c_rx) = mpsc::channel::<Bytes>(TX_CHANNEL_DEPTH);
                    let (reader, writer) = stream.into_split();

                    let c_online_w = c_online.clone();
                    let c_txb_w = c_txb.clone();
                    tokio::spawn(backbone_write_loop(writer, c_rx, c_online_w, c_txb_w));

                    let c_online_r = c_online.clone();
                    let c_rxb_r = c_rxb.clone();
                    let transport_tx2 = transport_tx.clone();
                    let dereg_tx = transport_tx.clone();
                    let cname = client_name.clone();
                    let active_client_guard =
                        ActiveClientGuard::new(Arc::clone(&task_active_clients));
                    let read_handle = tokio::spawn(async move {
                        let _active_client_guard = active_client_guard;
                        backbone_read_loop(reader, client_id, transport_tx2, c_online_r, c_rxb_r)
                            .await;
                        fast_flap_connection.disconnected();
                        tracing::info!(name = %cname, "backbone client disconnected");
                        // Proactive notify so broadcasts don't target dead tx.
                        let _ = dereg_tx
                            .send(TransportMessage::DeregisterInterface { id: client_id })
                            .await;
                    });

                    let handle = InterfaceHandle {
                        id: client_id,
                        parent_id: Some(id),
                        name: client_name,
                        mode,
                        direction: InterfaceDirection {
                            inbound: true,
                            outbound: true,
                            forward: false,
                            repeat: false,
                        },
                        bitrate: CHILD_BITRATE_GUESS,
                        mtu: child_mtu(),
                        online: c_online,
                        rxb: Some(c_rxb),
                        txb: Some(c_txb),
                        inspection: None,
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

    Ok(InterfaceHandle {
        id,
        parent_id: None,
        name,
        mode,
        direction: InterfaceDirection {
            inbound: true,
            outbound: false,
            forward: false,
            repeat: false,
        },
        bitrate: BITRATE_GUESS,
        mtu: rns_wire::constants::MTU as u32,
        online,
        rxb: Some(Arc::new(AtomicU64::new(0))),
        txb: Some(Arc::new(AtomicU64::new(0))),
        inspection: Some(inspection),
        tx,
        read_task,
    })
}

pub async fn spawn_backbone_client(
    config: BackboneClientConfig,
    id: InterfaceId,
    transport_tx: mpsc::Sender<TransportMessage>,
) -> Result<InterfaceHandle, crate::traits::InterfaceError> {
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

    let read_task = tokio::spawn(async move {
        let max_tries = config.max_reconnect_tries;
        let mut tries: usize = 0;

        loop {
            let target = match tokio::time::timeout(
                Duration::from_secs(config.connect_timeout_secs),
                resolve_target(&config.target_host, config.target_port, config.prefer_ipv6),
            )
            .await
            {
                Ok(Ok(addr)) => addr,
                Ok(Err(e)) => {
                    tracing::warn!(name = %config.name, error = %e, "backbone resolve failed");
                    if let Some(max) = max_tries {
                        tries += 1;
                        if tries >= max {
                            let _ = transport_tx
                                .send(TransportMessage::DeregisterInterface { id })
                                .await;
                            return;
                        }
                    }
                    tokio::time::sleep(Duration::from_secs(RECONNECT_WAIT)).await;
                    continue;
                }
                Err(_) => {
                    tracing::warn!(name = %config.name, "backbone resolve timed out");
                    if let Some(max) = max_tries {
                        tries += 1;
                        if tries >= max {
                            let _ = transport_tx
                                .send(TransportMessage::DeregisterInterface { id })
                                .await;
                            return;
                        }
                    }
                    tokio::time::sleep(Duration::from_secs(RECONNECT_WAIT)).await;
                    continue;
                }
            };

            let stream = match tokio::time::timeout(
                Duration::from_secs(config.connect_timeout_secs),
                TcpStream::connect(target),
            )
            .await
            {
                Ok(Ok(s)) => s,
                Ok(Err(e)) => {
                    tracing::warn!(name = %config.name, error = %e, "backbone connect failed");
                    if let Some(max) = max_tries {
                        tries += 1;
                        if tries >= max {
                            let _ = transport_tx
                                .send(TransportMessage::DeregisterInterface { id })
                                .await;
                            return;
                        }
                    }
                    tokio::time::sleep(Duration::from_secs(RECONNECT_WAIT)).await;
                    continue;
                }
                Err(_) => {
                    tracing::warn!(name = %config.name, "backbone connect timed out");
                    if let Some(max) = max_tries {
                        tries += 1;
                        if tries >= max {
                            let _ = transport_tx
                                .send(TransportMessage::DeregisterInterface { id })
                                .await;
                            return;
                        }
                    }
                    tokio::time::sleep(Duration::from_secs(RECONNECT_WAIT)).await;
                    continue;
                }
            };

            tune_stream(&stream);
            online2.store(true, Ordering::SeqCst);
            tries = 0;

            let c_online = Arc::new(AtomicBool::new(true));
            let (reader, writer) = stream.into_split();

            let (conn_tx, conn_rx) = mpsc::channel::<Bytes>(TX_CHANNEL_DEPTH);
            let c_online_w = c_online.clone();
            let c_txb = task_txb.clone();
            let write_handle =
                tokio::spawn(backbone_write_loop(writer, conn_rx, c_online_w, c_txb));

            let rx_ref = rx.clone();
            let fwd_handle = tokio::spawn(async move {
                let mut guard = rx_ref.lock().await;
                while let Some(data) = guard.recv().await {
                    if conn_tx.send(data).await.is_err() {
                        break;
                    }
                }
            });

            let c_online_r = c_online.clone();
            let c_rxb = task_rxb.clone();
            backbone_read_loop(reader, id, transport_tx.clone(), c_online_r, c_rxb).await;

            online2.store(false, Ordering::SeqCst);
            fwd_handle.abort();
            let _ = fwd_handle.await;
            write_handle.abort();
            let _ = write_handle.await;

            if let Some(max) = max_tries {
                tries += 1;
                if tries >= max {
                    let _ = transport_tx
                        .send(TransportMessage::DeregisterInterface { id })
                        .await;
                    return;
                }
            }
            tracing::info!(
                name = %config.name,
                "backbone: reconnecting in {}s",
                RECONNECT_WAIT,
            );
            tokio::time::sleep(Duration::from_secs(RECONNECT_WAIT)).await;
        }
    });

    Ok(InterfaceHandle {
        id,
        parent_id: None,
        name,
        mode,
        direction: InterfaceDirection {
            inbound: true,
            outbound: true,
            forward: false,
            repeat: false,
        },
        bitrate: CHILD_BITRATE_GUESS,
        mtu: child_mtu(),
        online,
        rxb: Some(shared_rxb),
        txb: Some(shared_txb),
        inspection: None,
        tx,
        read_task,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddr};

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
        assert_eq!(BITRATE_GUESS, 1_000_000_000);
        assert_eq!(CHILD_BITRATE_GUESS, 100_000_000);
        assert_eq!(RECONNECT_WAIT, 5);
    }

    #[test]
    fn test_backbone_server_config_mode() {
        let cfg = BackboneServerConfig::new("bb-srv", "0.0.0.0", 4243);
        assert_eq!(cfg.mode, InterfaceMode::Full);
        assert_eq!(cfg.listen_ip, "0.0.0.0");
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
    fn test_child_mtu_uses_100mbps_curve() {
        // optimise_mtu(100 Mbps) is one of the step values; verify the
        // result lands inside the HW_MTU ceiling.
        let mtu = child_mtu();
        assert!(mtu <= HW_MTU);
        assert!(mtu >= rns_wire::constants::MTU as u32 / 2);
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
        assert_eq!(inspection_snapshot(&parent).active_clients, Some(0));

        let _stream = TcpStream::connect(listen_addr).await.unwrap();
        let child = tokio::time::timeout(Duration::from_secs(1), handle_rx.recv())
            .await
            .expect("accepted child handle timed out")
            .expect("child handle channel closed");
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

    #[tokio::test]
    async fn test_backbone_max_reconnect_dereg() {
        // Connect attempts to a port nobody is listening on; with
        // max_reconnect_tries = Some(1) we get one connect attempt, one
        // failure, then DeregisterInterface and exit.
        let mut cfg = BackboneClientConfig::new("bb-dereg", "127.0.0.1", 1);
        cfg.connect_timeout_secs = 1;
        cfg.max_reconnect_tries = Some(1);

        let (tx, mut rx) = mpsc::channel::<TransportMessage>(8);
        let handle = spawn_backbone_client(cfg, 99, tx).await.unwrap();
        // Wait for the read_task to finish — guarded by a generous timeout
        // to absorb the one RECONNECT_WAIT sleep + connect attempt.
        let dereg = tokio::time::timeout(Duration::from_secs(15), async {
            loop {
                match rx.recv().await {
                    Some(TransportMessage::DeregisterInterface { id }) => return Some(id),
                    Some(_) => continue,
                    None => return None,
                }
            }
        })
        .await
        .ok()
        .flatten();
        assert_eq!(dereg, Some(99));
        // Drop the handle (aborts read_task if still alive).
        drop(handle);
    }

    #[tokio::test]
    async fn test_resolve_target_loopback_v4() {
        let addr = resolve_target("127.0.0.1", 1234, false).await.unwrap();
        assert!(addr.is_ipv4());
        assert_eq!(addr.port(), 1234);
    }
}
