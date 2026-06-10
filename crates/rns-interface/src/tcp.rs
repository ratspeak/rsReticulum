use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use bytes::Bytes;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;

use crate::hdlc;
use crate::kiss;
use crate::traits::{InterfaceDirection, InterfaceHandle, InterfaceId, InterfaceMode};
use rns_transport::messages::{InboundPacket, TransportMessage};

pub const RECONNECT_WAIT_INITIAL: u64 = 5;
pub const RECONNECT_WAIT_MAX: u64 = 300;
pub const DEFAULT_CONNECT_TIMEOUT: u64 = 5;
pub const DEFAULT_TCP_USER_TIMEOUT: u32 = 24;

pub const TCP_HW_MTU: u32 = 262144;

// Python TCPClientInterface: TCP_PROBE_AFTER / TCP_PROBE_INTERVAL / TCP_PROBES.
// Dead-peer detection: 5s idle + 12 probes × 2s ≈ 29s.
pub const TCP_KEEPIDLE: u32 = 5;
pub const TCP_KEEPINTVL: u32 = 2;
pub const TCP_KEEPCNT: u32 = 12;

/// Tuned keepalive (idle/interval/count + Linux `TCP_USER_TIMEOUT`) for plain
/// TCP client and accepted sockets, matching Python `set_timeouts_linux`.
pub(crate) fn set_tcp_keepalive_tuned(stream: &TcpStream) {
    crate::socket_tuning::set_keepalive_tuned(
        stream,
        std::time::Duration::from_secs(TCP_KEEPIDLE as u64),
        std::time::Duration::from_secs(TCP_KEEPINTVL as u64),
        TCP_KEEPCNT,
        std::time::Duration::from_secs(DEFAULT_TCP_USER_TIMEOUT as u64),
    );
}

#[derive(Debug, Clone)]
pub struct TcpClientConfig {
    pub name: String,
    pub target_host: String,
    pub target_port: u16,
    pub kiss_framing: bool,
    pub connect_timeout_secs: u64,
    pub max_reconnect_tries: Option<usize>,
    pub mode: InterfaceMode,
    /// Override HW MTU for link MTU discovery (Python `fixed_mtu`, >= 500).
    pub fixed_mtu: Option<u32>,
}

impl TcpClientConfig {
    pub fn new(name: &str, host: &str, port: u16) -> Self {
        Self {
            name: name.to_string(),
            target_host: host.to_string(),
            target_port: port,
            kiss_framing: false,
            connect_timeout_secs: DEFAULT_CONNECT_TIMEOUT,
            max_reconnect_tries: None,
            mode: InterfaceMode::Full,
            fixed_mtu: None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct TcpServerConfig {
    pub name: String,
    pub listen_ip: String,
    pub listen_port: u16,
    pub kiss_framing: bool,
    pub prefer_ipv6: bool,
    pub mode: InterfaceMode,
    /// Bind to this network device's address instead of `listen_ip`
    /// (Python `device =` option).
    pub device: Option<String>,
}

impl TcpServerConfig {
    pub fn new(name: &str, ip: &str, port: u16) -> Self {
        Self {
            name: name.to_string(),
            listen_ip: ip.to_string(),
            listen_port: port,
            kiss_framing: false,
            prefer_ipv6: false,
            mode: InterfaceMode::Full,
            device: None,
        }
    }
}

/// First usable address on `device`, honouring `prefer_ipv6`. Python
/// `TCPServerInterface.get_address_for_if` equivalent.
fn address_for_device(device: &str, prefer_ipv6: bool) -> Option<std::net::IpAddr> {
    let addrs = if_addrs::get_if_addrs().ok()?;
    let on_dev: Vec<std::net::IpAddr> = addrs
        .iter()
        .filter(|a| a.name == device)
        .map(|a| a.ip())
        .collect();
    if prefer_ipv6 && let Some(v6) = on_dev.iter().find(|ip| ip.is_ipv6()) {
        return Some(*v6);
    }
    on_dev
        .iter()
        .find(|ip| ip.is_ipv4())
        .or_else(|| on_dev.first())
        .copied()
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
}

impl TcpInterfaceState {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            online: AtomicBool::new(false),
            detached: AtomicBool::new(false),
            rx_bytes: AtomicU64::new(0),
            tx_bytes: AtomicU64::new(0),
            rx_packets: AtomicU64::new(0),
            tx_packets: AtomicU64::new(0),
            shared_rxb: None,
            shared_txb: None,
        })
    }

    pub fn with_shared_counters(rxb: Arc<AtomicU64>, txb: Arc<AtomicU64>) -> Arc<Self> {
        Arc::new(Self {
            online: AtomicBool::new(false),
            detached: AtomicBool::new(false),
            rx_bytes: AtomicU64::new(0),
            tx_bytes: AtomicU64::new(0),
            rx_packets: AtomicU64::new(0),
            tx_packets: AtomicU64::new(0),
            shared_rxb: Some(rxb),
            shared_txb: Some(txb),
        })
    }

    pub fn record_rx(&self, bytes: usize) {
        self.rx_bytes.fetch_add(bytes as u64, Ordering::Relaxed);
        self.rx_packets.fetch_add(1, Ordering::Relaxed);
        if let Some(shared) = &self.shared_rxb {
            shared.fetch_add(bytes as u64, Ordering::Relaxed);
        }
    }

    pub fn record_tx(&self, bytes: usize) {
        self.tx_bytes.fetch_add(bytes as u64, Ordering::Relaxed);
        self.tx_packets.fetch_add(1, Ordering::Relaxed);
        if let Some(shared) = &self.shared_txb {
            shared.fetch_add(bytes as u64, Ordering::Relaxed);
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
    transport_tx: mpsc::Sender<TransportMessage>,
    state: Arc<TcpInterfaceState>,
    kiss_framing: bool,
) {
    let mut buf = [0u8; 32768];

    if kiss_framing {
        let mut deframer = kiss::KissDeframer::new();
        loop {
            match reader.read(&mut buf).await {
                Ok(0) => {
                    tracing::info!(interface_id, "TCP read: EOF");
                    break;
                }
                Ok(n) => {
                    for (_cmd, frame) in deframer.feed(&buf[..n]) {
                        if frame.is_empty() {
                            continue;
                        }
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
        let mut deframer = hdlc::HdlcDeframer::new();
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
        state.record_tx(data.len());
        if let Err(e) = writer.write_all(&framed).await {
            tracing::warn!(error = %e, "TCP write error");
            break;
        }
    }
    state.online.store(false, Ordering::SeqCst);
}

/// Spawn an auto-reconnecting TCP client interface.
pub async fn spawn_tcp_client(
    config: TcpClientConfig,
    id: InterfaceId,
    transport_tx: mpsc::Sender<TransportMessage>,
    _ifac: Option<crate::traits::IfacConfig>,
) -> Result<InterfaceHandle, crate::traits::InterfaceError> {
    let online = Arc::new(AtomicBool::new(false));
    let online2 = online.clone();
    let (tx, rx) = mpsc::channel::<Bytes>(1024);
    let name = config.name.clone();
    let mode = config.mode;
    let kiss_framing = config.kiss_framing;
    let fixed_mtu = config.fixed_mtu;

    // Wrap rx so it survives reconnects; forwarder task feeds per-connection channel.
    let rx = Arc::new(tokio::sync::Mutex::new(rx));

    let shared_rxb = Arc::new(AtomicU64::new(0));
    let shared_txb = Arc::new(AtomicU64::new(0));
    let task_rxb = shared_rxb.clone();
    let task_txb = shared_txb.clone();

    let read_task = tokio::spawn(async move {
        let max_tries = config.max_reconnect_tries;
        let mut tries: usize = 0;
        let mut backoff = RECONNECT_WAIT_INITIAL;

        loop {
            let addr = format!("{}:{}", config.target_host, config.target_port);
            let stream = match tokio::time::timeout(
                std::time::Duration::from_secs(config.connect_timeout_secs),
                TcpStream::connect(&addr),
            )
            .await
            {
                Ok(Ok(s)) => s,
                Ok(Err(e)) => {
                    tracing::warn!(name = %config.name, error = %e, "TCP connect failed");
                    if let Some(max) = max_tries {
                        tries += 1;
                        if tries >= max {
                            tracing::warn!(name = %config.name, "max reconnect tries reached");
                            // Same dereg as the post-connect give-up below —
                            // otherwise the actor keeps a zombie entry.
                            let _ = transport_tx
                                .send(TransportMessage::DeregisterInterface { id })
                                .await;
                            return;
                        }
                    }
                    tokio::time::sleep(std::time::Duration::from_secs(backoff)).await;
                    backoff = (backoff * 2).min(RECONNECT_WAIT_MAX);
                    continue;
                }
                Err(_) => {
                    tracing::warn!(name = %config.name, "TCP connect timed out");
                    if let Some(max) = max_tries {
                        tries += 1;
                        if tries >= max {
                            tracing::warn!(name = %config.name, "max reconnect tries reached");
                            let _ = transport_tx
                                .send(TransportMessage::DeregisterInterface { id })
                                .await;
                            return;
                        }
                    }
                    tokio::time::sleep(std::time::Duration::from_secs(backoff)).await;
                    backoff = (backoff * 2).min(RECONNECT_WAIT_MAX);
                    continue;
                }
            };

            set_tcp_keepalive_tuned(&stream);

            // Nagle off for low-latency packets; larger buffers for bulk transfers.
            let _ = stream.set_nodelay(true);
            set_socket_buffers(&stream, 131072);

            let state = TcpInterfaceState::with_shared_counters(task_rxb.clone(), task_txb.clone());
            state.online.store(true, Ordering::SeqCst);
            online2.store(true, Ordering::SeqCst);
            tries = 0;
            backoff = RECONNECT_WAIT_INITIAL;

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
            )
            .await;

            online2.store(false, Ordering::SeqCst);

            fwd_handle.abort();
            let _ = fwd_handle.await;
            write_handle.abort();
            let _ = write_handle.await;

            if let Some(max) = max_tries {
                tries += 1;
                if tries >= max {
                    tracing::warn!(name = %config.name, "max reconnect tries reached");
                    // Notify transport immediately rather than waiting for auto-drop.
                    let _ = transport_tx
                        .send(TransportMessage::DeregisterInterface { id })
                        .await;
                    return;
                }
            }
            tracing::info!(name = %config.name, "reconnecting in {}s", backoff);
            tokio::time::sleep(std::time::Duration::from_secs(backoff)).await;
            backoff = (backoff * 2).min(RECONNECT_WAIT_MAX);
        }
    });

    let bitrate: u64 = 10_000_000;
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
        bitrate,
        mtu: fixed_mtu
            .unwrap_or_else(|| crate::traits::optimise_mtu(bitrate).unwrap_or(TCP_HW_MTU)),
        online,
        rxb: Some(shared_rxb),
        txb: Some(shared_txb),
        tx,
        read_task,
    })
}

/// Wrap an accepted TCP stream as an interface; no reconnect on disconnect.
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
    name: String,
    transport_tx: mpsc::Sender<TransportMessage>,
    kiss_framing: bool,
    mode: InterfaceMode,
) -> InterfaceHandle {
    let online = Arc::new(AtomicBool::new(true));
    let online2 = online.clone();
    let (tx, conn_rx) = mpsc::channel::<Bytes>(1024);

    let shared_rxb = Arc::new(AtomicU64::new(0));
    let shared_txb = Arc::new(AtomicU64::new(0));
    let state = TcpInterfaceState::with_shared_counters(shared_rxb.clone(), shared_txb.clone());
    state.online.store(true, Ordering::SeqCst);

    set_tcp_keepalive_tuned(&stream);
    let _ = stream.set_nodelay(true);
    set_socket_buffers(&stream, 131072);

    let (reader, writer) = stream.into_split();

    let state_w = state.clone();
    tokio::spawn(tcp_write_loop(writer, conn_rx, state_w, kiss_framing));

    let handle_name = name.clone();
    let dereg_tx = transport_tx.clone();
    let read_task = tokio::spawn(async move {
        tcp_read_loop(reader, id, transport_tx, state, kiss_framing).await;
        online2.store(false, Ordering::SeqCst);
        tracing::info!(name = %handle_name, "accepted TCP client disconnected");
        // Proactively notify transport so broadcasts stop targeting this dead tx.
        let _ = dereg_tx
            .send(TransportMessage::DeregisterInterface { id })
            .await;
    });

    let bitrate: u64 = 10_000_000;
    InterfaceHandle {
        id,
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
        mtu: crate::traits::optimise_mtu(bitrate).unwrap_or(TCP_HW_MTU),
        online,
        rxb: Some(shared_rxb),
        txb: Some(shared_txb),
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
    let addr = match config.device.as_deref() {
        Some(device) => {
            let ip = address_for_device(device, config.prefer_ipv6).ok_or_else(|| {
                crate::traits::InterfaceError::SendFailed(format!(
                    "no usable address on device '{device}'"
                ))
            })?;
            std::net::SocketAddr::new(ip, config.listen_port).to_string()
        }
        None => format!("{}:{}", config.listen_ip, config.listen_port),
    };
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

    let read_task = tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((stream, peer)) => {
                    let client_id = id_gen.fetch_add(1, Ordering::SeqCst);
                    let client_name = format!("{}/client_{}", config.name, client_id);
                    tracing::info!(name = %client_name, peer = %peer, "accepted TCP connection");
                    let handle = spawn_tcp_accepted(
                        stream,
                        client_id,
                        id,
                        client_name,
                        transport_tx.clone(),
                        kiss_framing,
                        mode,
                    )
                    .await;
                    if handle_tx.send(handle).await.is_err() {
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

    let bitrate: u64 = 10_000_000;
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
        bitrate,
        mtu: crate::traits::optimise_mtu(bitrate).unwrap_or(TCP_HW_MTU),
        online,
        rxb: Some(Arc::new(AtomicU64::new(0))),
        txb: Some(Arc::new(AtomicU64::new(0))),
        tx,
        read_task,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

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

    /// T1-2 regression: the client/accept paths must apply the TUNED keepalive
    /// (idle 5s + 12 probes × 2s ≈ 29s dead-peer parity with Python), not just
    /// SO_KEEPALIVE. Reads the options back via getsockopt.
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

        for stream in [&client, &server] {
            set_tcp_keepalive_tuned(stream);
            let fd = stream.as_ref().as_raw_fd();
            // BSD getsockopt returns the option bit, not 1 — assert enabled.
            assert_ne!(get_opt(fd, libc::SOL_SOCKET, libc::SO_KEEPALIVE), 0);

            #[cfg(target_os = "linux")]
            let idle = get_opt(fd, libc::IPPROTO_TCP, libc::TCP_KEEPIDLE);
            #[cfg(target_os = "macos")]
            let idle = get_opt(fd, libc::IPPROTO_TCP, libc::TCP_KEEPALIVE);
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            {
                assert_eq!(idle, TCP_KEEPIDLE as i32);
                assert_eq!(
                    get_opt(fd, libc::IPPROTO_TCP, libc::TCP_KEEPINTVL),
                    TCP_KEEPINTVL as i32
                );
                assert_eq!(
                    get_opt(fd, libc::IPPROTO_TCP, libc::TCP_KEEPCNT),
                    TCP_KEEPCNT as i32
                );
            }
            #[cfg(target_os = "linux")]
            assert_eq!(
                get_opt(fd, libc::IPPROTO_TCP, libc::TCP_USER_TIMEOUT),
                (DEFAULT_TCP_USER_TIMEOUT * 1000) as i32
            );
        }
    }

    /// T1-11: exhausting max_reconnect_tries before the FIRST successful
    /// connect must send DeregisterInterface, same as the post-connect path —
    /// otherwise the actor keeps a zombie entry forever.
    #[tokio::test]
    async fn test_initial_connect_give_up_sends_deregister() {
        let (transport_tx, mut transport_rx) = mpsc::channel::<TransportMessage>(8);

        // Bind-then-drop: the port refuses connections immediately.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);

        let mut config = TcpClientConfig::new("tcp-giveup", &addr.ip().to_string(), addr.port());
        config.max_reconnect_tries = Some(1);
        config.connect_timeout_secs = 2;

        let handle = spawn_tcp_client(config, 77, transport_tx, None)
            .await
            .unwrap();

        let msg = tokio::time::timeout(std::time::Duration::from_secs(10), transport_rx.recv())
            .await
            .expect("expected DeregisterInterface before timeout")
            .expect("transport channel closed");
        match msg {
            TransportMessage::DeregisterInterface { id } => assert_eq!(id, 77),
            other => panic!("expected DeregisterInterface, got {other:?}"),
        }
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
        assert_eq!(server_handle.id, 99);

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let client_cfg = TcpClientConfig {
            name: "test-client".into(),
            target_host: "127.0.0.1".into(),
            target_port: port,
            kiss_framing: false,
            connect_timeout_secs: 5,
            max_reconnect_tries: Some(1),
            mode: InterfaceMode::Full,
            fixed_mtu: None,
        };
        let client_handle = spawn_tcp_client(client_cfg, 1, transport_tx.clone(), None)
            .await
            .unwrap();

        let accepted = tokio::time::timeout(std::time::Duration::from_secs(3), handle_rx.recv())
            .await
            .expect("timeout waiting for accepted handle")
            .expect("handle channel closed");

        let payload = Bytes::from_static(b"hello from client");
        client_handle.tx.send(payload.clone()).await.unwrap();

        let msg = tokio::time::timeout(std::time::Duration::from_secs(3), transport_rx.recv())
            .await
            .expect("timeout waiting for transport message")
            .expect("transport channel closed");

        match msg {
            TransportMessage::Inbound(pkt) => {
                assert_eq!(pkt.raw, payload);
                assert_eq!(pkt.interface_id, accepted.id);
            }
            other => panic!("unexpected message: {:?}", other),
        }

        let reply = Bytes::from_static(b"hello from server");
        accepted.tx.send(reply.clone()).await.unwrap();

        let msg2 = tokio::time::timeout(std::time::Duration::from_secs(3), transport_rx.recv())
            .await
            .expect("timeout waiting for reply")
            .expect("transport channel closed");

        match msg2 {
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

    /// TCP reconnection: client retries after connection failure.
    #[tokio::test]
    async fn test_tcp_client_reconnection_max_tries() {
        let (transport_tx, _transport_rx) = mpsc::channel::<TransportMessage>(8);

        // Port 1 is closed, forcing every connect to fail.
        let config = TcpClientConfig {
            name: "reconnect-test".into(),
            target_host: "127.0.0.1".into(),
            target_port: 1,
            kiss_framing: false,
            connect_timeout_secs: 1,
            max_reconnect_tries: Some(2),
            mode: InterfaceMode::Full,
            fixed_mtu: None,
        };

        let handle = spawn_tcp_client(config, 99, transport_tx, None)
            .await
            .unwrap();

        // Two failed tries with 5s waits each; 20s headroom.
        let result =
            tokio::time::timeout(std::time::Duration::from_secs(20), handle.read_task).await;

        assert!(result.is_ok(), "task should have finished within timeout");
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

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let client_cfg = TcpClientConfig {
            name: "dereg-client".into(),
            target_host: "127.0.0.1".into(),
            target_port: port,
            kiss_framing: false,
            connect_timeout_secs: 5,
            max_reconnect_tries: Some(1),
            mode: InterfaceMode::Full,
            fixed_mtu: None,
        };
        let client_handle = spawn_tcp_client(client_cfg, 321, transport_tx.clone(), None)
            .await
            .unwrap();

        let accepted = tokio::time::timeout(std::time::Duration::from_secs(3), handle_rx.recv())
            .await
            .expect("timeout waiting for accepted handle")
            .expect("handle channel closed");
        let server_side_client_id = accepted.id;

        // Abort client-side tasks; server's per-client reader sees EOF and exits.
        client_handle.read_task.abort();
        drop(client_handle.tx);

        let mut saw_dereg = false;
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(3);
        while tokio::time::Instant::now() < deadline {
            match tokio::time::timeout(std::time::Duration::from_millis(500), transport_rx.recv())
                .await
            {
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
