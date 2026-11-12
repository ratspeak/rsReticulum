use rns_transport::messages::{InterfacePacketCapacity, InterfaceTransportSender};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use bytes::Bytes;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;

use crate::hdlc;
use crate::kiss;
use crate::traits::{
    ClientCountGuard, InterfaceDirection, InterfaceHandle, InterfaceId, InterfaceMode,
    TunnelIdentity, handoff_accepted_interface, open_client_connection, python_address_name,
    python_host,
};
use rns_transport::messages::{
    InboundPacket, InterfaceIdentity, InterfaceInspectionSnapshot, InterfaceInspectionSource,
    TransportMessage,
};

/// Python `TCPClientInterface.RECONNECT_WAIT`: fixed wait before every retry.
pub const RECONNECT_WAIT: u64 = 5;
/// Python `TCPClientInterface.INITIAL_CONNECT_TIMEOUT`, used for every connect.
pub const INITIAL_CONNECT_TIMEOUT: u64 = 5;
pub const DEFAULT_CONNECT_TIMEOUT: u64 = INITIAL_CONNECT_TIMEOUT;
pub const DEFAULT_TCP_USER_TIMEOUT: u32 = 24;

/// Python `TCPInterface.HW_MTU`. Also the largest packet the drivers carry:
/// its worst-case HDLC escaping fills the shared deframer.
pub const TCP_HW_MTU: u32 = 262144;

/// Python `TCPClientInterface.BITRATE_GUESS` and `TCPServerInterface.BITRATE_GUESS`.
pub const BITRATE_GUESS: u64 = 10_000_000;

/// Python `Interface.DEFAULT_IFAC_SIZE` for TCP, the IFAC size when none is configured.
pub const DEFAULT_IFAC_SIZE: usize = 16;

/// The hardware MTU after `optimise_mtu()` (Interface.py), or a
/// fixed MTU. Upstream leaves `HW_MTU = None` below 62.5 kbps; that is the base MTU here.
pub(crate) fn hardware_mtu(bitrate: u64, fixed_mtu: Option<u32>) -> u32 {
    fixed_mtu
        .or_else(|| crate::traits::optimise_mtu(bitrate))
        .unwrap_or(rns_wire::constants::MTU as u32)
}

/// Reported MTU and packet capacity: packets up to the hardware MTU, frames up
/// to the hardware MTU plus the IFAC size (TCPInterface.py).
pub(crate) fn hardware_capacity(
    bitrate: u64,
    fixed_mtu: Option<u32>,
    ifac_size: usize,
) -> (u32, InterfacePacketCapacity) {
    let hw_mtu = fixed_mtu.or_else(|| crate::traits::optimise_mtu(bitrate));
    let wire = hardware_mtu(bitrate, fixed_mtu).saturating_add(ifac_size as u32);
    crate::traits::hardware_mtu_capacity(hw_mtu, wire)
}

// Python TCPClientInterface: TCP_PROBE_AFTER / TCP_PROBE_INTERVAL / TCP_PROBES.
// Dead-peer detection: 5s idle + 12 probes × 2s ≈ 29s.
pub const TCP_KEEPIDLE: u32 = 5;
pub const TCP_KEEPINTVL: u32 = 2;
pub const TCP_KEEPCNT: u32 = 12;

/// Python's per-platform TCP timeouts (TCPInterface.py): the full
/// set on Linux (and Android), keepalive with the idle time on Apple
/// platforms, nothing elsewhere. `i2p_tunneled` selects the longer I2P values.
pub(crate) fn set_tcp_keepalive_tuned(stream: &TcpStream, i2p_tunneled: bool) {
    let (idle, interval, count, user_timeout) = if i2p_tunneled {
        (
            crate::i2p::I2P_PROBE_AFTER,
            crate::i2p::I2P_PROBE_INTERVAL,
            crate::i2p::I2P_PROBES as u32,
            crate::i2p::I2P_TCP_USER_TIMEOUT,
        )
    } else {
        (
            TCP_KEEPIDLE as u64,
            TCP_KEEPINTVL as u64,
            TCP_KEEPCNT,
            DEFAULT_TCP_USER_TIMEOUT,
        )
    };
    #[cfg(any(target_os = "linux", target_os = "android"))]
    crate::socket_tuning::set_keepalive_tuned(
        stream,
        std::time::Duration::from_secs(idle),
        std::time::Duration::from_secs(interval),
        count,
        std::time::Duration::from_secs(user_timeout as u64),
    );
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    {
        let _ = (interval, count, user_timeout);
        let keepalive =
            socket2::TcpKeepalive::new().with_time(std::time::Duration::from_secs(idle));
        if let Err(e) = socket2::SockRef::from(stream).set_tcp_keepalive(&keepalive) {
            tracing::warn!(error = %e, "set_tcp_keepalive failed");
        }
    }
    #[cfg(not(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "ios"
    )))]
    let _ = (stream, idle, interval, count, user_timeout);
}

/// Python `get_address_for_if` / `get_address_for_host` of the TCP and
/// Backbone listeners (TCPInterface.py): `device` wins over
/// `listen_ip`, neither is an error, and nothing falls back to a wildcard.
pub async fn resolve_bind_address(
    listen_ip: Option<&str>,
    device: Option<&str>,
    port: u16,
    prefer_ipv6: bool,
) -> std::io::Result<std::net::SocketAddr> {
    use std::io::{Error, ErrorKind};
    use std::net::{IpAddr, SocketAddr, SocketAddrV6};
    if let Some(device) = device {
        let no_address = || {
            Error::new(
                ErrorKind::AddrNotAvailable,
                format!("No addresses available on specified kernel interface \"{device}\""),
            )
        };
        let on_device: Vec<if_addrs::Interface> = if_addrs::get_if_addrs()?
            .into_iter()
            .filter(|a| a.name == device)
            .collect();
        let v4 = on_device.iter().find(|a| a.ip().is_ipv4());
        let v6 = on_device.iter().find(|a| a.ip().is_ipv6());
        return match (v4, v6) {
            (v4, Some(v6)) if prefer_ipv6 || v4.is_none() => {
                let IpAddr::V6(ip) = v6.ip() else {
                    unreachable!()
                };
                if (ip.segments()[0] & 0xffc0) == 0xfe80 {
                    let scope = v6.index.ok_or_else(no_address)?;
                    Ok(SocketAddr::V6(SocketAddrV6::new(ip, port, 0, scope)))
                } else {
                    resolve_host(&ip.to_string(), port, prefer_ipv6).await
                }
            }
            (Some(v4), _) => Ok(SocketAddr::new(v4.ip(), port)),
            _ => Err(no_address()),
        };
    }
    match listen_ip {
        Some(host) => resolve_host(host, port, prefer_ipv6).await,
        None => Err(Error::new(
            ErrorKind::InvalidInput,
            "No TCP bind IP configured",
        )),
    }
}

/// First resolved address of the preferred family, else the first one.
pub(crate) async fn resolve_host(
    host: &str,
    port: u16,
    prefer_ipv6: bool,
) -> std::io::Result<std::net::SocketAddr> {
    let addrs: Vec<std::net::SocketAddr> = tokio::net::lookup_host((host, port)).await?.collect();
    addrs
        .iter()
        .find(|a| a.is_ipv6() == prefer_ipv6)
        .or_else(|| addrs.first())
        .copied()
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::AddrNotAvailable,
                format!("no addresses resolved for {host}:{port}"),
            )
        })
}

#[derive(Debug, Clone)]
pub struct TcpClientConfig {
    pub name: String,
    pub target_host: String,
    pub target_port: u16,
    pub kiss_framing: bool,
    /// Use the longer socket timeouts for a TCP connection tunneled over I2P.
    pub i2p_tunneled: bool,
    /// Parsed like Python, which stores it but connects with
    /// [`INITIAL_CONNECT_TIMEOUT`] (TCPInterface.py).
    pub connect_timeout_secs: u64,
    pub max_reconnect_tries: Option<usize>,
    pub mode: InterfaceMode,
    /// Fixed hardware MTU instead of the bitrate-derived one; at least 500.
    pub fixed_mtu: Option<u32>,
    /// Bitrate the hardware MTU is optimised for: the configured `bitrate`, else [`BITRATE_GUESS`].
    pub bitrate: u64,
    /// IFAC size in bytes; frames may exceed the hardware MTU by this much.
    pub ifac_size: usize,
    /// Identity used to request a signed tunnel synthesis for each non-KISS
    /// connection. `None`, or an identity without signing material, sends none.
    pub tunnel_identity: Option<TunnelIdentity>,
}

impl TcpClientConfig {
    pub fn new(name: &str, host: &str, port: u16) -> Self {
        Self {
            name: name.to_string(),
            target_host: host.to_string(),
            target_port: port,
            kiss_framing: false,
            i2p_tunneled: false,
            connect_timeout_secs: DEFAULT_CONNECT_TIMEOUT,
            max_reconnect_tries: None,
            mode: InterfaceMode::Full,
            fixed_mtu: None,
            bitrate: BITRATE_GUESS,
            ifac_size: DEFAULT_IFAC_SIZE,
            tunnel_identity: None,
        }
    }

    /// Python `str(TCPClientInterface)` (TCPInterface.py).
    pub fn python_name(&self) -> String {
        format!(
            "TCPInterface[{}/{}:{}]",
            self.name,
            python_host(&self.target_host),
            self.target_port
        )
    }
}

#[derive(Debug, Clone)]
pub struct TcpServerConfig {
    pub name: String,
    /// Host to bind; required unless `device` is set (TCPInterface.py).
    pub listen_ip: Option<String>,
    pub listen_port: u16,
    pub kiss_framing: bool,
    pub prefer_ipv6: bool,
    pub mode: InterfaceMode,
    /// Bind to this network device's address instead of `listen_ip`
    /// (Python `device =` option).
    pub device: Option<String>,
    /// Accepted clients take the I2P socket timeouts (TCPInterface.py).
    pub i2p_tunneled: bool,
    /// Bitrate the hardware MTU is optimised for; accepted clients inherit it.
    pub bitrate: u64,
    /// IFAC size in bytes; accepted clients inherit it.
    pub ifac_size: usize,
}

impl TcpServerConfig {
    pub fn new(name: &str, ip: &str, port: u16) -> Self {
        Self {
            name: name.to_string(),
            listen_ip: Some(ip.to_string()),
            listen_port: port,
            kiss_framing: false,
            prefer_ipv6: false,
            mode: InterfaceMode::Full,
            device: None,
            i2p_tunneled: false,
            bitrate: BITRATE_GUESS,
            ifac_size: DEFAULT_IFAC_SIZE,
        }
    }
}

pub struct TcpInterfaceState {
    pub online: AtomicBool,
    pub detached: AtomicBool,
    pub rx_bytes: AtomicU64,
    pub tx_bytes: AtomicU64,
    pub rx_packets: AtomicU64,
    pub tx_packets: AtomicU64,
    /// Aggregate counters that persist across reconnections.
    pub shared_rxb: Option<Arc<AtomicU64>>,
    pub shared_txb: Option<Arc<AtomicU64>>,
    /// The listener's counters, for a connection a TCP server accepted.
    pub parent_rxb: Option<Arc<AtomicU64>>,
    pub parent_txb: Option<Arc<AtomicU64>>,
}

impl TcpInterfaceState {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub fn with_shared_counters(rxb: Arc<AtomicU64>, txb: Arc<AtomicU64>) -> Arc<Self> {
        Arc::new(Self {
            shared_rxb: Some(rxb),
            shared_txb: Some(txb),
            ..Self::default()
        })
    }

    pub fn record_rx(&self, bytes: usize) {
        self.rx_bytes.fetch_add(bytes as u64, Ordering::Relaxed);
        self.rx_packets.fetch_add(1, Ordering::Relaxed);
        if let Some(shared) = &self.shared_rxb {
            shared.fetch_add(bytes as u64, Ordering::Relaxed);
        }
        if let Some(parent) = &self.parent_rxb {
            parent.fetch_add(bytes as u64, Ordering::Relaxed);
        }
    }

    pub fn record_tx(&self, bytes: usize) {
        self.tx_bytes.fetch_add(bytes as u64, Ordering::Relaxed);
        self.tx_packets.fetch_add(1, Ordering::Relaxed);
        if let Some(shared) = &self.shared_txb {
            shared.fetch_add(bytes as u64, Ordering::Relaxed);
        }
        if let Some(parent) = &self.parent_txb {
            parent.fetch_add(bytes as u64, Ordering::Relaxed);
        }
    }
}

impl Default for TcpInterfaceState {
    fn default() -> Self {
        Self {
            online: AtomicBool::new(false),
            detached: AtomicBool::new(false),
            rx_bytes: AtomicU64::new(0),
            tx_bytes: AtomicU64::new(0),
            rx_packets: AtomicU64::new(0),
            tx_packets: AtomicU64::new(0),
            shared_rxb: None,
            shared_txb: None,
            parent_rxb: None,
            parent_txb: None,
        }
    }
}

pub fn frame_for_tcp(data: &[u8], kiss_framing: bool) -> Vec<u8> {
    if kiss_framing {
        crate::kiss::frame(data)
    } else {
        hdlc::frame(data)
    }
}

use crate::socket_tuning::set_socket_buffers;

async fn tcp_read_loop(
    mut reader: tokio::net::tcp::OwnedReadHalf,
    interface_id: InterfaceId,
    transport_tx: InterfaceTransportSender,
    state: Arc<TcpInterfaceState>,
    kiss_framing: bool,
    hw_mtu: usize,
    ifac_size: usize,
) {
    let mut buf = [0u8; 32768];

    if kiss_framing {
        let mut deframer = kiss::KissByteDeframer::new(hw_mtu);
        loop {
            match reader.read(&mut buf).await {
                Ok(0) => {
                    tracing::info!(interface_id, "TCP read: EOF");
                    break;
                }
                Ok(n) => {
                    for event in deframer.feed(&buf[..n]) {
                        let kiss::KissEvent::Data(frame) = event else {
                            continue;
                        };
                        state.record_rx(frame.len());
                        let msg = TransportMessage::Inbound(InboundPacket {
                            raw: Bytes::from(frame),
                            interface_id,
                            rssi: None,
                            snr: None,
                            q: None,
                        });
                        if transport_tx.send(msg).await.is_err() {
                            tracing::warn!(interface_id, "transport channel closed");
                            return;
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!(interface_id, error = %e, "TCP read error");
                    break;
                }
            }
        }
    } else {
        let mut deframer = hdlc::HdlcDeframer::with_limits(
            hw_mtu,
            rns_wire::constants::HEADER_MINSIZE,
            Some(hw_mtu + ifac_size),
        );
        loop {
            match reader.read(&mut buf).await {
                Ok(0) => {
                    tracing::info!(interface_id, "TCP read: EOF");
                    break;
                }
                Ok(n) => {
                    for frame in deframer.feed(&buf[..n]) {
                        if frame.is_empty() {
                            continue;
                        }
                        tracing::debug!(
                            interface_id,
                            frame_len = frame.len(),
                            first_byte = format!("0x{:02x}", frame.first().copied().unwrap_or(0)),
                            "TCP read: deframed packet"
                        );
                        state.record_rx(frame.len());
                        let msg = TransportMessage::Inbound(InboundPacket {
                            raw: Bytes::from(frame),
                            interface_id,
                            rssi: None,
                            snr: None,
                            q: None,
                        });
                        if transport_tx.send(msg).await.is_err() {
                            tracing::warn!(interface_id, "transport channel closed");
                            return;
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!(interface_id, error = %e, "TCP read error");
                    break;
                }
            }
        }
    }
    state.online.store(false, Ordering::SeqCst);
}

async fn tcp_write_loop(
    mut writer: tokio::net::tcp::OwnedWriteHalf,
    mut rx: mpsc::Receiver<Bytes>,
    state: Arc<TcpInterfaceState>,
    kiss_framing: bool,
) {
    while let Some(data) = rx.recv().await {
        let framed = frame_for_tcp(&data, kiss_framing);
        tracing::debug!(
            raw_len = data.len(),
            framed_len = framed.len(),
            first_byte = format!("0x{:02x}", data.first().copied().unwrap_or(0)),
            "TCP write: sending frame"
        );
        if let Err(e) = writer.write_all(&framed).await {
            tracing::warn!(error = %e, "TCP write error");
            break;
        }
        state.record_tx(framed.len());
    }
    state.online.store(false, Ordering::SeqCst);
}

/// Python's initiator `teardown()` (TCPInterface.py): the interface
/// stays registered and offline, and queued outbound packets are discarded
/// until the runtime stops it.
pub(crate) async fn hold_torn_down(
    outbound: &tokio::sync::Mutex<mpsc::Receiver<Bytes>>,
    name: &str,
    teardown: &tokio::sync::watch::Sender<bool>,
) {
    tracing::error!(
        "The interface {name} experienced an unrecoverable error and is being torn down. Restart Reticulum to attempt to open this interface again."
    );
    teardown.send_replace(true);
    let mut queued = outbound.lock().await;
    while queued.recv().await.is_some() {}
}

/// Resolves when a client spends its retry budget and is torn down.
#[derive(Clone, Debug)]
pub struct ClientTeardown(tokio::sync::watch::Receiver<bool>);

impl ClientTeardown {
    pub(crate) fn channel() -> (tokio::sync::watch::Sender<bool>, Self) {
        let (tx, rx) = tokio::sync::watch::channel(false);
        (tx, Self(rx))
    }

    /// True at teardown, false if the driver ends without one.
    pub async fn torn_down(&mut self) -> bool {
        self.0.wait_for(|torn_down| *torn_down).await.is_ok()
    }
}

/// A reconnecting client handle paired with its teardown signal.
#[non_exhaustive]
pub struct SpawnedClientInterface {
    pub interface: InterfaceHandle,
    pub teardown: ClientTeardown,
}

/// Spawn an auto-reconnecting TCP client interface. `max_reconnect_tries`
/// bounds the retries of each outage. IFAC masking, when
/// configured, is applied by the transport actor, not the driver.
pub async fn spawn_tcp_client(
    config: TcpClientConfig,
    id: InterfaceId,
    transport_tx: mpsc::Sender<TransportMessage>,
) -> Result<InterfaceHandle, crate::traits::InterfaceError> {
    spawn_tcp_client_observed(config, id, transport_tx)
        .await
        .map(|spawned| spawned.interface)
}

/// [`spawn_tcp_client`], also returning the client's teardown signal.
pub async fn spawn_tcp_client_observed(
    config: TcpClientConfig,
    id: InterfaceId,
    transport_tx: mpsc::Sender<TransportMessage>,
) -> Result<SpawnedClientInterface, crate::traits::InterfaceError> {
    let transport_tx = InterfaceTransportSender::new(id, transport_tx);
    let owner = transport_tx.owner();
    if config.fixed_mtu.is_some_and(|mtu| mtu < 500) {
        return Err(crate::traits::InterfaceError::SendFailed(
            "fixed_mtu must be at least 500 bytes".into(),
        ));
    }
    let online = Arc::new(AtomicBool::new(false));
    let online2 = online.clone();
    let (tx, rx) = mpsc::channel::<Bytes>(1024);
    let name = config.name.clone();
    let mode = config.mode;
    let kiss_framing = config.kiss_framing;
    let fixed_mtu = config.fixed_mtu;
    let receive_mtu = hardware_mtu(config.bitrate, fixed_mtu) as usize;
    let ifac_size = config.ifac_size;

    // Wrap rx so it survives reconnects; forwarder task feeds per-connection channel.
    let rx = Arc::new(tokio::sync::Mutex::new(rx));

    let shared_rxb = Arc::new(AtomicU64::new(0));
    let shared_txb = Arc::new(AtomicU64::new(0));
    let task_rxb = shared_rxb.clone();
    let task_txb = shared_txb.clone();

    let python_name = config.python_name();
    let identity = InterfaceIdentity::new(&python_name, &config.name, "TCPClientInterface");
    let (teardown_tx, teardown) = ClientTeardown::channel();
    // Python connects once, synchronously, before the interface is handed to
    // transport (TCPInterface.py).
    let mut initial_attempt = Some(
        tokio::time::timeout(
            std::time::Duration::from_secs(INITIAL_CONNECT_TIMEOUT),
            TcpStream::connect(format!("{}:{}", config.target_host, config.target_port)),
        )
        .await,
    );
    if matches!(initial_attempt, Some(Ok(Ok(_)))) {
        online.store(true, Ordering::SeqCst);
    }
    let read_task = tokio::spawn(async move {
        let max_tries = config.max_reconnect_tries;
        let addr = format!("{}:{}", config.target_host, config.target_port);
        // Every attempt after the first follows a failure or an outage.
        let mut attempted = false;
        // Retries within the current outage (TCPInterface.py).
        let mut attempts: usize = 0;

        loop {
            if attempted {
                tokio::time::sleep(std::time::Duration::from_secs(RECONNECT_WAIT)).await;
                attempts += 1;
                if max_tries.is_some_and(|max| attempts > max) {
                    tracing::error!("Max reconnection attempts reached for {python_name}");
                    hold_torn_down(&rx, &python_name, &teardown_tx).await;
                    return;
                }
            }
            attempted = true;
            let attempt = match initial_attempt.take() {
                Some(attempt) => attempt,
                None => {
                    tokio::time::timeout(
                        std::time::Duration::from_secs(INITIAL_CONNECT_TIMEOUT),
                        TcpStream::connect(&addr),
                    )
                    .await
                }
            };
            let stream = match attempt {
                Ok(Ok(s)) => s,
                Ok(Err(e)) => {
                    tracing::warn!(name = %config.name, error = %e, "TCP connect failed");
                    continue;
                }
                Err(_) => {
                    tracing::warn!(name = %config.name, "TCP connect timed out");
                    continue;
                }
            };

            set_tcp_keepalive_tuned(&stream, config.i2p_tunneled);

            // Nagle off for low-latency packets; larger buffers for bulk transfers.
            let _ = stream.set_nodelay(true);
            set_socket_buffers(&stream, 131072);

            let state = TcpInterfaceState::with_shared_counters(task_rxb.clone(), task_txb.clone());
            state.online.store(true, Ordering::SeqCst);
            attempts = 0;
            // Python synthesizes on every non-KISS connection
            // (TCPInterface.py).
            let synthesis = config
                .tunnel_identity
                .as_ref()
                .filter(|_| !kiss_framing)
                .and_then(|identity| identity.synthesis(&python_name));
            open_client_connection(&rx, &transport_tx, synthesis, &online2).await;

            let (reader, writer) = stream.into_split();

            let (conn_tx, conn_rx) = mpsc::channel::<Bytes>(1024);
            let state_w = state.clone();
            let write_handle = tokio::spawn(tcp_write_loop(writer, conn_rx, state_w, kiss_framing));

            let rx_ref = rx.clone();
            let fwd_handle = tokio::spawn(async move {
                let mut guard = rx_ref.lock().await;
                while let Some(data) = guard.recv().await {
                    if conn_tx.send(data).await.is_err() {
                        break;
                    }
                }
            });

            tcp_read_loop(
                reader,
                id,
                transport_tx.clone(),
                state.clone(),
                kiss_framing,
                receive_mtu,
                ifac_size,
            )
            .await;

            online2.store(false, Ordering::SeqCst);

            fwd_handle.abort();
            let _ = fwd_handle.await;
            write_handle.abort();
            let _ = write_handle.await;

            tracing::info!(name = %config.name, "reconnecting in {}s", RECONNECT_WAIT);
        }
    });

    let (mtu, packet_capacity) = hardware_capacity(config.bitrate, fixed_mtu, ifac_size);
    Ok(SpawnedClientInterface {
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
            bitrate: config.bitrate,
            mtu,
            online,
            rxb: Some(shared_rxb),
            txb: Some(shared_txb),
            inspection: Some(InterfaceInspectionSource::identified(identity)),
            tx,
            read_task,
        },
        teardown,
    })
}

/// Wrap an accepted TCP stream as an interface; no reconnect on disconnect.
#[allow(clippy::too_many_arguments)]
#[tracing::instrument(
    level = "debug",
    name = "tcp.server.accept",
    skip_all,
    fields(client_id = id, name = %name),
)]
async fn spawn_tcp_accepted(
    stream: TcpStream,
    id: InterfaceId,
    parent_id: InterfaceId,
    parent_counters: (Arc<AtomicU64>, Arc<AtomicU64>),
    client_count: ClientCountGuard,
    identity: InterfaceIdentity,
    name: String,
    transport_tx: mpsc::Sender<TransportMessage>,
    kiss_framing: bool,
    i2p_tunneled: bool,
    mode: InterfaceMode,
    (bitrate, ifac_size): (u64, usize),
) -> InterfaceHandle {
    let transport_tx = InterfaceTransportSender::new(id, transport_tx);
    let owner = transport_tx.owner();
    let online = Arc::new(AtomicBool::new(true));
    let online2 = online.clone();
    let (tx, conn_rx) = mpsc::channel::<Bytes>(1024);

    let shared_rxb = Arc::new(AtomicU64::new(0));
    let shared_txb = Arc::new(AtomicU64::new(0));
    let state = Arc::new(TcpInterfaceState {
        shared_rxb: Some(shared_rxb.clone()),
        shared_txb: Some(shared_txb.clone()),
        parent_rxb: Some(parent_counters.0),
        parent_txb: Some(parent_counters.1),
        ..TcpInterfaceState::default()
    });
    state.online.store(true, Ordering::SeqCst);

    set_tcp_keepalive_tuned(&stream, i2p_tunneled);
    let _ = stream.set_nodelay(true);
    set_socket_buffers(&stream, 131072);

    let (reader, writer) = stream.into_split();

    let state_w = state.clone();
    tokio::spawn(tcp_write_loop(writer, conn_rx, state_w, kiss_framing));

    let handle_name = name.clone();
    let dereg_tx = transport_tx.clone();
    let read_task = tokio::spawn(async move {
        let _client_count = client_count;
        tcp_read_loop(
            reader,
            id,
            transport_tx,
            state,
            kiss_framing,
            hardware_mtu(bitrate, None) as usize,
            ifac_size,
        )
        .await;
        online2.store(false, Ordering::SeqCst);
        tracing::info!(name = %handle_name, "accepted TCP client disconnected");
        // Proactively notify transport so broadcasts stop targeting this dead tx.
        let _ = dereg_tx
            .send(TransportMessage::DeregisterInterface { id })
            .await;
    });

    let (mtu, packet_capacity) = hardware_capacity(bitrate, None, ifac_size);
    InterfaceHandle {
        id,
        owner,
        packet_capacity,
        parent_id: Some(parent_id),
        name,
        mode,
        direction: InterfaceDirection {
            inbound: true,
            outbound: true,
            forward: false,
            repeat: false,
        },
        bitrate,
        mtu,
        online,
        rxb: Some(shared_rxb),
        txb: Some(shared_txb),
        inspection: Some(InterfaceInspectionSource::identified(identity)),
        tx,
        read_task,
    }
}

/// Spawn a TCP server. Each accepted connection becomes its own
/// `InterfaceHandle`, delivered via `handle_tx` for caller registration.
pub async fn spawn_tcp_server(
    config: TcpServerConfig,
    id: InterfaceId,
    id_gen: Arc<AtomicU64>,
    transport_tx: mpsc::Sender<TransportMessage>,
    handle_tx: mpsc::Sender<InterfaceHandle>,
) -> Result<InterfaceHandle, crate::traits::InterfaceError> {
    let transport_tx = InterfaceTransportSender::new(id, transport_tx);
    let owner = transport_tx.owner();
    let addr = resolve_bind_address(
        config.listen_ip.as_deref(),
        config.device.as_deref(),
        config.listen_port,
        config.prefer_ipv6,
    )
    .await?;
    let listener = TcpListener::bind(&addr).await?;
    let local_addr = listener.local_addr()?;
    tracing::info!(name = %config.name, addr = %local_addr, "TCP server listening");

    let online = Arc::new(AtomicBool::new(true));
    let online2 = online.clone();
    let name = config.name.clone();
    let mode = config.mode;
    let kiss_framing = config.kiss_framing;

    // Server handle tx is unused; only accepted connections send.
    let (tx, _rx) = mpsc::channel::<Bytes>(1);
    let parent_rxb = Arc::new(AtomicU64::new(0));
    let parent_txb = Arc::new(AtomicU64::new(0));
    let task_parent_counters = (parent_rxb.clone(), parent_txb.clone());
    let clients = Arc::new(AtomicU64::new(0));
    let task_clients = clients.clone();
    let server_identity = InterfaceIdentity::new(
        python_address_name(
            "TCPServerInterface",
            &config.name,
            &local_addr.ip().to_string(),
            config.listen_port,
        ),
        &config.name,
        "TCPServerInterface",
    );

    let read_task = tokio::spawn(async move {
        // A child copies its parent's registration (IFAC, ingress control), so accept once it exists.
        if !transport_tx.ready().await {
            online2.store(false, Ordering::SeqCst);
            return;
        }
        loop {
            match listener.accept().await {
                Ok((stream, peer)) => {
                    let client_id = id_gen.fetch_add(1, Ordering::SeqCst);
                    let client_name = format!("{}/client_{}", config.name, client_id);
                    tracing::info!(name = %client_name, peer = %peer, "accepted TCP connection");
                    let spawned_name = format!("Client on {}", config.name);
                    let identity = InterfaceIdentity::new(
                        python_address_name(
                            "TCPInterface",
                            &spawned_name,
                            &peer.ip().to_string(),
                            peer.port(),
                        ),
                        spawned_name,
                        "TCPClientInterface",
                    );
                    let handle = spawn_tcp_accepted(
                        stream,
                        client_id,
                        id,
                        task_parent_counters.clone(),
                        ClientCountGuard::new(task_clients.clone()),
                        identity,
                        client_name,
                        transport_tx.actor_sender(),
                        kiss_framing,
                        config.i2p_tunneled,
                        mode,
                        (config.bitrate, config.ifac_size),
                    )
                    .await;
                    if handoff_accepted_interface(&handle_tx, handle)
                        .await
                        .is_err()
                    {
                        tracing::warn!("handle registry channel closed, stopping accept loop");
                        break;
                    }
                }
                Err(e) => {
                    tracing::warn!(error = %e, "TCP accept error");
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                }
            }
        }
        online2.store(false, Ordering::SeqCst);
    });

    let (mtu, packet_capacity) = hardware_capacity(config.bitrate, None, config.ifac_size);
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
        inspection: Some(
            InterfaceInspectionSource::new(move || InterfaceInspectionSnapshot {
                active_clients: Some(clients.load(Ordering::Relaxed)),
                ..InterfaceInspectionSnapshot::default()
            })
            .with_identity(server_identity),
        ),
        tx,
        read_task,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_python_names_match_python() {
        // Python 1.5.5 `str()` output for these interfaces.
        for (host, expected) in [
            ("127.0.0.1", "TCPInterface[Golden Uplink/127.0.0.1:4242]"),
            ("::1", "TCPInterface[Golden Uplink/[::1]:4242]"),
            (
                "hub.example.org",
                "TCPInterface[Golden Uplink/hub.example.org:4242]",
            ),
        ] {
            assert_eq!(
                TcpClientConfig::new("Golden Uplink", host, 4242).python_name(),
                expected
            );
        }
    }

    #[test]
    fn test_tcp_client_config() {
        let config = TcpClientConfig::new("test", "127.0.0.1", 4242);
        assert_eq!(config.target_port, 4242);
        assert!(!config.kiss_framing);
        assert_eq!(config.connect_timeout_secs, DEFAULT_CONNECT_TIMEOUT);
    }

    #[test]
    fn test_tcp_server_config() {
        let config = TcpServerConfig::new("server", "0.0.0.0", 4242);
        assert_eq!(config.listen_port, 4242);
        assert!(!config.prefer_ipv6);
    }

    /// Read back Python's Linux timeout values applied by the shared Rust
    /// socket tuner for ordinary TCP and I2P-tunneled connections.
    #[cfg(unix)]
    #[tokio::test]
    async fn tuned_keepalive_applies_python_probe_values() {
        use std::os::fd::AsRawFd;

        fn get_opt(fd: i32, level: i32, name: i32) -> i32 {
            let mut val: libc::c_int = 0;
            let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
            let rc = unsafe {
                libc::getsockopt(
                    fd,
                    level,
                    name,
                    &mut val as *mut _ as *mut libc::c_void,
                    &mut len,
                )
            };
            assert_eq!(rc, 0, "getsockopt({level},{name}) failed");
            val
        }

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (accepted, client) = tokio::join!(listener.accept(), TcpStream::connect(addr));
        let client = client.unwrap();
        let (server, _) = accepted.unwrap();

        for (i2p_tunneled, _expected) in [(false, [5, 2, 12, 24]), (true, [10, 9, 5, 45])] {
            for stream in [&client, &server] {
                set_tcp_keepalive_tuned(stream, i2p_tunneled);
                let fd = stream.as_ref().as_raw_fd();
                // BSD getsockopt returns the option bit, not 1 — assert enabled.
                assert_ne!(get_opt(fd, libc::SOL_SOCKET, libc::SO_KEEPALIVE), 0);

                #[cfg(target_os = "linux")]
                let idle = get_opt(fd, libc::IPPROTO_TCP, libc::TCP_KEEPIDLE);
                #[cfg(target_os = "macos")]
                let idle = get_opt(fd, libc::IPPROTO_TCP, libc::TCP_KEEPALIVE);
                #[cfg(any(target_os = "linux", target_os = "macos"))]
                assert_eq!(idle, _expected[0]);
                // Darwin sets only the idle time, as upstream's set_timeouts_osx does.
                #[cfg(target_os = "linux")]
                {
                    assert_eq!(
                        get_opt(fd, libc::IPPROTO_TCP, libc::TCP_KEEPINTVL),
                        _expected[1]
                    );
                    assert_eq!(
                        get_opt(fd, libc::IPPROTO_TCP, libc::TCP_KEEPCNT),
                        _expected[2]
                    );
                }
                #[cfg(target_os = "linux")]
                assert_eq!(
                    get_opt(fd, libc::IPPROTO_TCP, libc::TCP_USER_TIMEOUT),
                    _expected[3] * 1000
                );
            }
        }
    }

    /// Python's initiator teardown keeps the interface registered and
    /// offline after the retry budget is spent (TCPInterface.py).
    #[tokio::test]
    async fn give_up_keeps_interface_registered_and_offline() {
        let (transport_tx, mut transport_rx) = mpsc::channel::<TransportMessage>(8);

        // Bind-then-drop: the port refuses connections immediately.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);

        let mut config = TcpClientConfig::new("tcp-giveup", &addr.ip().to_string(), addr.port());
        config.max_reconnect_tries = Some(0);

        let handle = spawn_tcp_client(config, 77, transport_tx).await.unwrap();
        handle.owner.mark_registered();

        // One attempt, one RECONNECT_WAIT, then teardown.
        let early = tokio::time::timeout(
            std::time::Duration::from_secs(RECONNECT_WAIT + 3),
            transport_rx.recv(),
        )
        .await;
        assert!(early.is_err(), "no message expected, got {early:?}");
        assert!(!handle.read_task.is_finished());
        assert!(!handle.online.load(Ordering::SeqCst));
        handle
            .tx
            .send(Bytes::from_static(b"dropped"))
            .await
            .unwrap();
        handle.read_task.abort();
    }

    #[test]
    fn test_frame_for_tcp_hdlc() {
        let data = b"test packet";
        let framed = frame_for_tcp(data, false);
        assert_eq!(framed[0], hdlc::FLAG);
        assert_eq!(framed[framed.len() - 1], hdlc::FLAG);
    }

    #[test]
    fn test_frame_for_tcp_kiss() {
        let data = b"test packet";
        let framed = frame_for_tcp(data, true);
        assert_eq!(framed[0], crate::kiss::FEND);
        assert_eq!(framed[framed.len() - 1], crate::kiss::FEND);
    }

    #[test]
    fn test_interface_state() {
        let state = TcpInterfaceState::new();
        state.record_rx(100);
        state.record_tx(200);
        assert_eq!(state.rx_bytes.load(Ordering::Relaxed), 100);
        assert_eq!(state.tx_bytes.load(Ordering::Relaxed), 200);
        assert_eq!(state.rx_packets.load(Ordering::Relaxed), 1);
        assert_eq!(state.tx_packets.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn server_accepts_children_only_after_parent_registration() {
        let (transport_tx, _transport_rx) = mpsc::channel::<TransportMessage>(8);
        let (handle_tx, mut handle_rx) = mpsc::channel::<InterfaceHandle>(8);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let server = spawn_tcp_server(
            TcpServerConfig::new("gated-server", "127.0.0.1", port),
            700,
            Arc::new(AtomicU64::new(701)),
            transport_tx,
            handle_tx,
        )
        .await
        .unwrap();
        let _peer = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(200), handle_rx.recv())
                .await
                .is_err(),
            "a child must not be handed off before its parent is registered"
        );
        server.owner.mark_registered();
        let child = tokio::time::timeout(std::time::Duration::from_secs(3), handle_rx.recv())
            .await
            .expect("child after parent registration")
            .unwrap();
        assert_eq!(child.parent_id, Some(700));
    }

    /// TCP loopback: spawn server + client on localhost:0, roundtrip a packet.
    #[tokio::test]
    async fn test_tcp_loopback_roundtrip() {
        let (transport_tx, mut transport_rx) = mpsc::channel::<TransportMessage>(64);
        let (handle_tx, mut handle_rx) = mpsc::channel::<InterfaceHandle>(8);
        let id_gen = Arc::new(AtomicU64::new(100));

        // Bind-then-drop to grab a free port for the server config.
        let server_cfg = TcpServerConfig::new("test-server", "127.0.0.1", 0);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);

        let mut server_cfg2 = server_cfg;
        server_cfg2.listen_port = port;

        let server_handle =
            spawn_tcp_server(server_cfg2, 99, id_gen, transport_tx.clone(), handle_tx)
                .await
                .unwrap();
        server_handle.owner.mark_registered();
        assert_eq!(server_handle.id, 99);

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let client_cfg = TcpClientConfig {
            name: "test-client".into(),
            target_host: "127.0.0.1".into(),
            target_port: port,
            kiss_framing: false,
            i2p_tunneled: false,
            connect_timeout_secs: 5,
            max_reconnect_tries: Some(1),
            mode: InterfaceMode::Full,
            fixed_mtu: None,
            bitrate: BITRATE_GUESS,
            ifac_size: DEFAULT_IFAC_SIZE,
            tunnel_identity: None,
        };
        let client_handle = spawn_tcp_client(client_cfg, 1, transport_tx.clone())
            .await
            .unwrap();
        client_handle.owner.mark_registered();

        let accepted = tokio::time::timeout(std::time::Duration::from_secs(3), handle_rx.recv())
            .await
            .expect("timeout waiting for accepted handle")
            .expect("handle channel closed");

        assert_ne!(accepted.owner, server_handle.owner);
        assert_ne!(accepted.owner, client_handle.owner);
        assert_eq!(accepted.packet_capacity.max_wire_packet_bytes, 16384 + 16);
        let payload = Bytes::from_static(b"hello from client packet payload");
        client_handle.tx.send(payload.clone()).await.unwrap();
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(20), transport_rx.recv())
                .await
                .is_err(),
            "the first packet waits for accepted-child registration"
        );
        accepted.owner.mark_registered();

        let msg = tokio::time::timeout(std::time::Duration::from_secs(3), transport_rx.recv())
            .await
            .expect("timeout waiting for transport message")
            .expect("transport channel closed");

        match crate::traits::test_event_for_handle(msg, &accepted) {
            TransportMessage::Inbound(pkt) => {
                assert_eq!(pkt.raw, payload);
                assert_eq!(pkt.interface_id, accepted.id);
            }
            other => panic!("unexpected message: {:?}", other),
        }

        let reply = Bytes::from_static(b"hello from server packet payload");
        accepted.tx.send(reply.clone()).await.unwrap();

        let msg2 = tokio::time::timeout(std::time::Duration::from_secs(3), transport_rx.recv())
            .await
            .expect("timeout waiting for reply")
            .expect("transport channel closed");

        match crate::traits::test_event_for_handle(msg2, &client_handle) {
            TransportMessage::Inbound(pkt) => {
                assert_eq!(pkt.raw, reply);
                assert_eq!(pkt.interface_id, 1);
            }
            other => panic!("unexpected reply message: {:?}", other),
        }

        server_handle.read_task.abort();
        client_handle.read_task.abort();
    }

    /// HDLC streaming: feed partial frames and verify correct reassembly.
    #[test]
    fn test_hdlc_streaming_partial_feeds() {
        let mut deframer = hdlc::HdlcDeframer::new();

        let data1 = b"packet one";
        let data2 = b"packet two";
        let framed1 = hdlc::frame(data1);
        let framed2 = hdlc::frame(data2);

        let mut combined = Vec::new();
        combined.extend_from_slice(&framed1);
        combined.extend_from_slice(&framed2);

        let mut all_frames = Vec::new();
        for &b in &combined {
            all_frames.extend(deframer.feed(&[b]));
        }

        assert_eq!(all_frames.len(), 2);
        assert_eq!(all_frames[0], data1);
        assert_eq!(all_frames[1], data2);
    }

    /// Server's per-client read_task must DeregisterInterface on EOF
    /// so transport stops targeting the dead tx channel.
    #[tokio::test]
    async fn test_tcp_server_deregisters_on_client_disconnect() {
        let (transport_tx, mut transport_rx) = mpsc::channel::<TransportMessage>(64);
        let (handle_tx, mut handle_rx) = mpsc::channel::<InterfaceHandle>(8);
        let id_gen = Arc::new(AtomicU64::new(800));

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);

        let mut server_cfg = TcpServerConfig::new("dereg-server", "127.0.0.1", 0);
        server_cfg.listen_port = port;

        let server_handle =
            spawn_tcp_server(server_cfg, 88, id_gen, transport_tx.clone(), handle_tx)
                .await
                .unwrap();
        server_handle.owner.mark_registered();

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let client_cfg = TcpClientConfig {
            name: "dereg-client".into(),
            target_host: "127.0.0.1".into(),
            target_port: port,
            kiss_framing: false,
            i2p_tunneled: false,
            connect_timeout_secs: 5,
            max_reconnect_tries: Some(1),
            mode: InterfaceMode::Full,
            fixed_mtu: None,
            bitrate: BITRATE_GUESS,
            ifac_size: DEFAULT_IFAC_SIZE,
            tunnel_identity: None,
        };
        let client_handle = spawn_tcp_client(client_cfg, 321, transport_tx.clone())
            .await
            .unwrap();
        client_handle.owner.mark_registered();

        let accepted = tokio::time::timeout(std::time::Duration::from_secs(3), handle_rx.recv())
            .await
            .expect("timeout waiting for accepted handle")
            .expect("handle channel closed");
        accepted.owner.mark_registered();
        let server_side_client_id = accepted.id;

        // Abort client-side tasks; server's per-client reader sees EOF and exits.
        client_handle.read_task.abort();
        drop(client_handle.tx);

        let mut saw_dereg = false;
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(3);
        while tokio::time::Instant::now() < deadline {
            match tokio::time::timeout(std::time::Duration::from_millis(500), transport_rx.recv())
                .await
                .map(|message| {
                    message.map(|event| crate::traits::test_event_for_handle(event, &accepted))
                }) {
                Ok(Some(TransportMessage::DeregisterInterface { id }))
                    if id == server_side_client_id =>
                {
                    saw_dereg = true;
                    break;
                }
                Ok(Some(_)) => continue,
                Ok(None) => break,
                Err(_) => continue,
            }
        }

        assert!(
            saw_dereg,
            "server must emit DeregisterInterface for disconnected client id {server_side_client_id}"
        );

        server_handle.read_task.abort();
    }
}
