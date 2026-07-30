//! Shared-instance IPC. Unix domain sockets where available, TCP on
//! 127.0.0.1 as fallback. HDLC-framed.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use bytes::Bytes;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;

use crate::hdlc;
use crate::traits::{
    InterfaceDirection, InterfaceHandle, InterfaceId, InterfaceMode, handoff_accepted_interface,
};
use rns_transport::messages::{InboundPacket, TransportMessage};

pub const LOCAL_MTU: u32 = 262_144;

/// Default filesystem socket path for non-Linux fallback use.
pub const DEFAULT_SOCKET_PATH: &str = "/tmp/rns_reticulum.sock";

/// On Android `/tmp` isn't writable; falls back to caller's data directory.
pub fn socket_path(data_dir: Option<&std::path::Path>) -> std::path::PathBuf {
    if cfg!(target_os = "android") {
        if let Some(dir) = data_dir {
            return dir.join("cache").join("rns_reticulum.sock");
        }
    }
    std::path::PathBuf::from(DEFAULT_SOCKET_PATH)
}

pub const FALLBACK_TCP_PORT: u16 = 37428;
#[cfg(unix)]
const LOCAL_RECONNECT_WAIT_SECS: u64 = 8;

#[cfg(all(unix, not(test)))]
fn local_reconnect_wait() -> std::time::Duration {
    std::time::Duration::from_secs(LOCAL_RECONNECT_WAIT_SECS)
}

#[cfg(all(unix, test))]
fn local_reconnect_wait() -> std::time::Duration {
    std::time::Duration::from_millis(50)
}

pub fn socket_path_for(instance_name: &str) -> String {
    format!("/tmp/rns_{}.sock", instance_name)
}

pub fn python_shared_socket_name(instance_name: &str) -> String {
    if cfg!(any(target_os = "linux", target_os = "android")) {
        format!("\0rns/{instance_name}")
    } else {
        socket_path_for(instance_name)
    }
}

#[cfg(unix)]
fn is_abstract_socket_path(path: &str) -> bool {
    path.as_bytes().first() == Some(&0)
}

#[cfg(unix)]
fn display_socket_path(path: &str) -> String {
    if is_abstract_socket_path(path) {
        format!("\\0{}", &path[1..])
    } else {
        path.to_string()
    }
}

#[derive(Debug, Clone)]
pub struct LocalServerConfig {
    /// Unix socket path (ignored on non-Unix).
    pub socket_path: String,
    pub name: String,
}

impl Default for LocalServerConfig {
    fn default() -> Self {
        Self {
            socket_path: DEFAULT_SOCKET_PATH.to_string(),
            name: "LocalServer".to_string(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct LocalClientConfig {
    pub socket_path: String,
    pub name: String,
}

impl Default for LocalClientConfig {
    fn default() -> Self {
        Self {
            socket_path: DEFAULT_SOCKET_PATH.to_string(),
            name: "LocalClient".to_string(),
        }
    }
}

async fn local_read_loop<R: AsyncReadExt + Unpin>(
    mut reader: R,
    interface_id: InterfaceId,
    transport_tx: mpsc::Sender<TransportMessage>,
    online: Arc<AtomicBool>,
    rxb: Arc<AtomicU64>,
) {
    let mut buf = [0u8; 8192];
    let mut deframer = hdlc::HdlcDeframer::new();

    loop {
        match reader.read(&mut buf).await {
            Ok(0) => {
                tracing::info!(interface_id, "local read: EOF");
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
                tracing::warn!(interface_id, error = %e, "local read error");
                break;
            }
        }
    }
    online.store(false, Ordering::SeqCst);
}

async fn local_write_loop<W: AsyncWriteExt + Unpin>(
    mut writer: W,
    mut rx: mpsc::Receiver<Bytes>,
    online: Arc<AtomicBool>,
    txb: Arc<AtomicU64>,
) {
    while let Some(data) = rx.recv().await {
        let framed = hdlc::frame(&data);
        if let Err(e) = writer.write_all(&framed).await {
            tracing::warn!(error = %e, "local write error");
            break;
        }
        txb.fetch_add(framed.len() as u64, Ordering::Relaxed);
    }
    online.store(false, Ordering::SeqCst);
}

#[cfg(unix)]
enum LocalClientConnectionEnd {
    Disconnected,
    Detached,
}

/// Drive both halves of one initiating local-client connection in a single
/// task. Keeping the persistent outbound receiver here lets the Unix client
/// retain one stable `InterfaceHandle` while replacing only the socket after a
/// shared-instance restart.
#[cfg(unix)]
async fn run_local_client_connection<R, W>(
    mut reader: R,
    mut writer: W,
    rx: &mut mpsc::Receiver<Bytes>,
    interface_id: InterfaceId,
    transport_tx: &mpsc::Sender<TransportMessage>,
    rxb: &AtomicU64,
    txb: &AtomicU64,
) -> LocalClientConnectionEnd
where
    R: AsyncReadExt + Unpin,
    W: AsyncWriteExt + Unpin,
{
    let mut buf = [0u8; 8192];
    let mut deframer = hdlc::HdlcDeframer::new();

    loop {
        tokio::select! {
            read = reader.read(&mut buf) => {
                match read {
                    Ok(0) => {
                        tracing::info!(interface_id, "local client read: EOF");
                        return LocalClientConnectionEnd::Disconnected;
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
                                return LocalClientConnectionEnd::Detached;
                            }
                        }
                    }
                    Err(error) => {
                        tracing::warn!(interface_id, %error, "local client read error");
                        return LocalClientConnectionEnd::Disconnected;
                    }
                }
            }
            outbound = rx.recv() => {
                let Some(data) = outbound else {
                    return LocalClientConnectionEnd::Detached;
                };
                let framed = hdlc::frame(&data);
                if let Err(error) = writer.write_all(&framed).await {
                    tracing::warn!(interface_id, %error, "local client write error");
                    return LocalClientConnectionEnd::Disconnected;
                }
                txb.fetch_add(framed.len() as u64, Ordering::Relaxed);
            }
        }
    }
}

/// Per-stream wiring shared by both platform variants: write loop, read task,
/// and the connection's `InterfaceHandle`. `dereg_on_disconnect` is set for
/// accepted server-side clients so transport drops them immediately on EOF.
fn wire_local_stream<R, W>(
    id: InterfaceId,
    name: String,
    parent_id: Option<InterfaceId>,
    reader: R,
    writer: W,
    transport_tx: mpsc::Sender<TransportMessage>,
    dereg_on_disconnect: bool,
) -> InterfaceHandle
where
    R: AsyncReadExt + Unpin + Send + 'static,
    W: AsyncWriteExt + Unpin + Send + 'static,
{
    let online = Arc::new(AtomicBool::new(true));
    let rxb = Arc::new(AtomicU64::new(0));
    let txb = Arc::new(AtomicU64::new(0));
    let (tx, rx) = mpsc::channel::<Bytes>(256);

    tokio::spawn(local_write_loop(writer, rx, online.clone(), txb.clone()));

    let online_r = online.clone();
    let rxb_r = rxb.clone();
    let task_name = name.clone();
    let dereg_tx = transport_tx.clone();
    let read_task = tokio::spawn(async move {
        local_read_loop(reader, id, transport_tx, online_r, rxb_r).await;
        if dereg_on_disconnect {
            tracing::info!(name = %task_name, "local client disconnected");
            // Proactively notify so transport drops immediately.
            let _ = dereg_tx
                .send(TransportMessage::DeregisterInterface { id })
                .await;
        }
    });

    InterfaceHandle {
        id,
        parent_id,
        name,
        mode: InterfaceMode::Full,
        direction: InterfaceDirection {
            inbound: true,
            outbound: true,
            forward: false,
            repeat: false,
        },
        bitrate: 1_000_000_000,
        mtu: crate::traits::optimise_mtu(1_000_000_000).unwrap_or(LOCAL_MTU),
        online,
        rxb: Some(rxb),
        txb: Some(txb),
        inspection: None,
        tx,
        read_task,
    }
}

/// Handle for the listener pseudo-interface (id 0): inbound-only, no
/// per-byte counters of its own.
fn server_listener_handle(
    name: String,
    online: Arc<AtomicBool>,
    tx: mpsc::Sender<Bytes>,
    read_task: tokio::task::JoinHandle<()>,
) -> InterfaceHandle {
    InterfaceHandle {
        id: 0,
        parent_id: None,
        name,
        mode: InterfaceMode::Full,
        direction: InterfaceDirection {
            inbound: true,
            outbound: false,
            forward: false,
            repeat: false,
        },
        bitrate: 1_000_000_000,
        mtu: crate::traits::optimise_mtu(1_000_000_000).unwrap_or(LOCAL_MTU),
        online,
        rxb: Some(Arc::new(AtomicU64::new(0))),
        txb: Some(Arc::new(AtomicU64::new(0))),
        inspection: None,
        tx,
        read_task,
    }
}

#[cfg(unix)]
mod platform {
    use super::*;
    use tokio::net::{UnixListener, UnixStream};

    fn bind_unix_listener(socket_path: &str) -> std::io::Result<UnixListener> {
        if let Some(abstract_name) = socket_path.strip_prefix('\0') {
            return bind_abstract_unix_listener(abstract_name);
        }

        let _ = std::fs::remove_file(socket_path);
        UnixListener::bind(socket_path)
    }

    async fn connect_unix_stream(socket_path: &str) -> std::io::Result<UnixStream> {
        if let Some(abstract_name) = socket_path.strip_prefix('\0') {
            return connect_abstract_unix_stream(abstract_name);
        }

        UnixStream::connect(socket_path).await
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn bind_abstract_unix_listener(name: &str) -> std::io::Result<UnixListener> {
        use std::os::unix::net::{SocketAddr, UnixListener as StdUnixListener};

        #[cfg(target_os = "android")]
        use std::os::android::net::SocketAddrExt as _;
        #[cfg(target_os = "linux")]
        use std::os::linux::net::SocketAddrExt as _;

        let addr = SocketAddr::from_abstract_name(name.as_bytes())?;
        let listener = StdUnixListener::bind_addr(&addr)?;
        listener.set_nonblocking(true)?;
        UnixListener::from_std(listener)
    }

    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    fn bind_abstract_unix_listener(_name: &str) -> std::io::Result<UnixListener> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "abstract Unix sockets are only available on Linux/Android",
        ))
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn connect_abstract_unix_stream(name: &str) -> std::io::Result<UnixStream> {
        use std::os::unix::net::{SocketAddr, UnixStream as StdUnixStream};

        #[cfg(target_os = "android")]
        use std::os::android::net::SocketAddrExt as _;
        #[cfg(target_os = "linux")]
        use std::os::linux::net::SocketAddrExt as _;

        let addr = SocketAddr::from_abstract_name(name.as_bytes())?;
        let stream = StdUnixStream::connect_addr(&addr)?;
        stream.set_nonblocking(true)?;
        UnixStream::from_std(stream)
    }

    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    fn connect_abstract_unix_stream(_name: &str) -> std::io::Result<UnixStream> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "abstract Unix sockets are only available on Linux/Android",
        ))
    }

    pub async fn spawn_local_server_impl(
        config: LocalServerConfig,
        id_gen: Arc<AtomicU64>,
        transport_tx: mpsc::Sender<TransportMessage>,
        handle_tx: mpsc::Sender<InterfaceHandle>,
    ) -> Result<InterfaceHandle, crate::traits::InterfaceError> {
        let listener = bind_unix_listener(&config.socket_path)?;
        tracing::info!(name = %config.name, path = %display_socket_path(&config.socket_path), "local server listening");

        let online = Arc::new(AtomicBool::new(true));
        let online2 = online.clone();
        let name = config.name.clone();
        let (tx, _rx) = mpsc::channel::<Bytes>(1);

        let read_task = tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((stream, _addr)) => {
                        let client_id = id_gen.fetch_add(1, Ordering::SeqCst);
                        let client_name = format!("{}/client_{}", config.name, client_id);
                        tracing::info!(name = %client_name, "local client connected");

                        let (reader, writer) = stream.into_split();
                        let handle = wire_local_stream(
                            client_id,
                            client_name,
                            Some(0),
                            reader,
                            writer,
                            transport_tx.clone(),
                            true,
                        );
                        if handoff_accepted_interface(&handle_tx, handle)
                            .await
                            .is_err()
                        {
                            tracing::warn!("local handle registry closed");
                            break;
                        }
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "local accept error");
                        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                    }
                }
            }
            online2.store(false, Ordering::SeqCst);
        });

        Ok(server_listener_handle(name, online, tx, read_task))
    }

    pub async fn spawn_local_client_impl(
        config: LocalClientConfig,
        id: InterfaceId,
        transport_tx: mpsc::Sender<TransportMessage>,
    ) -> Result<InterfaceHandle, crate::traits::InterfaceError> {
        let initial_stream = connect_unix_stream(&config.socket_path).await?;
        tracing::info!(name = %config.name, path = %display_socket_path(&config.socket_path), "local client connected");

        let online = Arc::new(AtomicBool::new(true));
        let rxb = Arc::new(AtomicU64::new(0));
        let txb = Arc::new(AtomicU64::new(0));
        let (tx, mut rx) = mpsc::channel::<Bytes>(256);

        let task_online = online.clone();
        let task_rxb = rxb.clone();
        let task_txb = txb.clone();
        let task_name = config.name.clone();
        let task_socket_path = config.socket_path.clone();
        let read_task = tokio::spawn(async move {
            let mut stream = initial_stream;
            loop {
                let (reader, writer) = stream.into_split();
                let end = run_local_client_connection(
                    reader,
                    writer,
                    &mut rx,
                    id,
                    &transport_tx,
                    &task_rxb,
                    &task_txb,
                )
                .await;
                task_online.store(false, Ordering::SeqCst);

                if matches!(end, LocalClientConnectionEnd::Detached)
                    || transport_tx.is_closed()
                    || rx.is_closed()
                {
                    return;
                }

                tracing::warn!(
                    name = %task_name,
                    path = %display_socket_path(&task_socket_path),
                    wait_seconds = LOCAL_RECONNECT_WAIT_SECS,
                    "local shared-instance connection lost; reconnecting"
                );
                loop {
                    tokio::time::sleep(local_reconnect_wait()).await;
                    if transport_tx.is_closed() || rx.is_closed() {
                        return;
                    }
                    match connect_unix_stream(&task_socket_path).await {
                        Ok(connected) => {
                            stream = connected;
                            task_online.store(true, Ordering::SeqCst);
                            tracing::info!(
                                name = %task_name,
                                path = %display_socket_path(&task_socket_path),
                                "local shared-instance client reconnected"
                            );
                            break;
                        }
                        Err(error) => {
                            tracing::debug!(
                                name = %task_name,
                                path = %display_socket_path(&task_socket_path),
                                %error,
                                "local shared-instance reconnect failed"
                            );
                        }
                    }
                }
            }
        });

        Ok(InterfaceHandle {
            id,
            parent_id: None,
            name: config.name,
            mode: InterfaceMode::Full,
            direction: InterfaceDirection {
                inbound: true,
                outbound: true,
                forward: false,
                repeat: false,
            },
            bitrate: 1_000_000_000,
            mtu: crate::traits::optimise_mtu(1_000_000_000).unwrap_or(LOCAL_MTU),
            online,
            rxb: Some(rxb),
            txb: Some(txb),
            inspection: None,
            tx,
            read_task,
        })
    }
}

#[cfg(not(unix))]
mod platform {
    use super::*;
    use tokio::net::{TcpListener, TcpStream};

    fn fallback_tcp_addr(socket_path: &str) -> String {
        if let Some(addr) = socket_path
            .strip_prefix("tcp://")
            .filter(|addr| !addr.is_empty())
        {
            addr.to_string()
        } else {
            format!("127.0.0.1:{FALLBACK_TCP_PORT}")
        }
    }

    pub async fn spawn_local_server_impl(
        config: LocalServerConfig,
        id_gen: Arc<AtomicU64>,
        transport_tx: mpsc::Sender<TransportMessage>,
        handle_tx: mpsc::Sender<InterfaceHandle>,
    ) -> Result<InterfaceHandle, crate::traits::InterfaceError> {
        let addr = fallback_tcp_addr(&config.socket_path);
        let listener = TcpListener::bind(&addr).await?;
        let local_addr = listener.local_addr()?;
        tracing::info!(name = %config.name, addr = %local_addr, "local server (TCP fallback) listening");

        let online = Arc::new(AtomicBool::new(true));
        let online2 = online.clone();
        let name = config.name.clone();
        let (tx, _rx) = mpsc::channel::<Bytes>(1);

        let read_task = tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((stream, peer)) => {
                        let client_id = id_gen.fetch_add(1, Ordering::SeqCst);
                        let client_name = format!("{}/client_{}", config.name, client_id);
                        tracing::info!(name = %client_name, peer = %peer, "local client connected (TCP)");

                        let (reader, writer) = stream.into_split();
                        let handle = wire_local_stream(
                            client_id,
                            client_name,
                            Some(0),
                            reader,
                            writer,
                            transport_tx.clone(),
                            true,
                        );
                        if handoff_accepted_interface(&handle_tx, handle)
                            .await
                            .is_err()
                        {
                            tracing::warn!("local handle registry closed");
                            break;
                        }
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "local accept error");
                        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                    }
                }
            }
            online2.store(false, Ordering::SeqCst);
        });

        Ok(server_listener_handle(name, online, tx, read_task))
    }

    pub async fn spawn_local_client_impl(
        config: LocalClientConfig,
        id: InterfaceId,
        transport_tx: mpsc::Sender<TransportMessage>,
    ) -> Result<InterfaceHandle, crate::traits::InterfaceError> {
        let addr = fallback_tcp_addr(&config.socket_path);
        let stream = TcpStream::connect(&addr).await?;
        tracing::info!(name = %config.name, addr = %addr, "local client connected (TCP fallback)");

        let (reader, writer) = stream.into_split();
        Ok(wire_local_stream(
            id,
            config.name.clone(),
            None,
            reader,
            writer,
            transport_tx,
            false,
        ))
    }
}

#[tracing::instrument(
    level = "debug",
    name = "local.server.accept",
    skip_all,
    fields(name = %config.name, socket_path = %config.socket_path),
)]
pub async fn spawn_local_server(
    config: LocalServerConfig,
    id_gen: Arc<AtomicU64>,
    transport_tx: mpsc::Sender<TransportMessage>,
    handle_tx: mpsc::Sender<InterfaceHandle>,
) -> Result<InterfaceHandle, crate::traits::InterfaceError> {
    platform::spawn_local_server_impl(config, id_gen, transport_tx, handle_tx).await
}

#[tracing::instrument(
    level = "debug",
    name = "local.client.connect",
    skip_all,
    fields(name = %config.name, client_id = id, socket_path = %config.socket_path),
)]
pub async fn spawn_local_client(
    config: LocalClientConfig,
    id: InterfaceId,
    transport_tx: mpsc::Sender<TransportMessage>,
) -> Result<InterfaceHandle, crate::traits::InterfaceError> {
    platform::spawn_local_client_impl(config, id, transport_tx).await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unique_test_socket_path(prefix: &str) -> String {
        #[cfg(unix)]
        {
            format!(
                "/tmp/{prefix}_{}_{}.sock",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            )
        }

        #[cfg(not(unix))]
        {
            let listener =
                std::net::TcpListener::bind("127.0.0.1:0").expect("reserve local test port");
            let port = listener.local_addr().expect("read local test port").port();
            drop(listener);
            format!("tcp://127.0.0.1:{port}")
        }
    }

    #[test]
    fn test_local_mtu() {
        assert_eq!(LOCAL_MTU, 262_144);
    }

    #[test]
    fn test_local_server_config() {
        let cfg = LocalServerConfig {
            socket_path: "/tmp/test_rns.sock".to_string(),
            name: "TestServer".to_string(),
        };
        assert_eq!(cfg.socket_path, "/tmp/test_rns.sock");
        assert_eq!(cfg.name, "TestServer");
    }

    #[test]
    fn test_local_client_config() {
        let cfg = LocalClientConfig {
            socket_path: "/tmp/test_rns.sock".to_string(),
            name: "TestClient".to_string(),
        };
        assert_eq!(cfg.socket_path, "/tmp/test_rns.sock");
        assert_eq!(cfg.name, "TestClient");
    }

    #[tokio::test]
    async fn test_local_ipc_roundtrip() {
        let (transport_tx, mut transport_rx) = mpsc::channel::<TransportMessage>(64);
        let (handle_tx, mut handle_rx) = mpsc::channel::<InterfaceHandle>(8);
        let id_gen = Arc::new(AtomicU64::new(500));

        let socket_path = unique_test_socket_path("reticulum_test");

        let server_cfg = LocalServerConfig {
            socket_path: socket_path.clone(),
            name: "test-local-server".to_string(),
        };

        let server_handle = spawn_local_server(server_cfg, id_gen, transport_tx.clone(), handle_tx)
            .await
            .unwrap();

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let client_cfg = LocalClientConfig {
            socket_path: socket_path.clone(),
            name: "test-local-client".to_string(),
        };

        let client_handle = spawn_local_client(client_cfg, 42, transport_tx.clone())
            .await
            .unwrap();

        let accepted = tokio::time::timeout(std::time::Duration::from_secs(3), handle_rx.recv())
            .await
            .expect("timeout waiting for accepted handle")
            .expect("handle channel closed");

        let payload = Bytes::from_static(b"local ipc test");
        client_handle.tx.send(payload.clone()).await.unwrap();

        let msg = tokio::time::timeout(std::time::Duration::from_secs(3), transport_rx.recv())
            .await
            .expect("timeout")
            .expect("channel closed");

        match msg {
            TransportMessage::Inbound(pkt) => {
                assert_eq!(pkt.raw, payload);
                assert_eq!(pkt.interface_id, accepted.id);
            }
            other => panic!("unexpected: {:?}", other),
        }

        let reply = Bytes::from_static(b"local ipc reply");
        accepted.tx.send(reply.clone()).await.unwrap();

        let msg2 = tokio::time::timeout(std::time::Duration::from_secs(3), transport_rx.recv())
            .await
            .expect("timeout")
            .expect("channel closed");

        match msg2 {
            TransportMessage::Inbound(pkt) => {
                assert_eq!(pkt.raw, reply);
                assert_eq!(pkt.interface_id, 42);
            }
            other => panic!("unexpected: {:?}", other),
        }

        server_handle.read_task.abort();
        client_handle.read_task.abort();
        let _ = std::fs::remove_file(&socket_path);
    }

    /// Server-side read loop must DeregisterInterface on EOF (no zombie leak).
    #[tokio::test]
    async fn test_local_server_deregisters_on_client_disconnect() {
        let (transport_tx, mut transport_rx) = mpsc::channel::<TransportMessage>(64);
        let (handle_tx, mut handle_rx) = mpsc::channel::<InterfaceHandle>(8);
        let id_gen = Arc::new(AtomicU64::new(700));

        let socket_path = unique_test_socket_path("reticulum_dereg_test");
        let _ = std::fs::remove_file(&socket_path);

        let server_cfg = LocalServerConfig {
            socket_path: socket_path.clone(),
            name: "dereg-server".to_string(),
        };
        let server_handle = spawn_local_server(server_cfg, id_gen, transport_tx.clone(), handle_tx)
            .await
            .unwrap();

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let client_cfg = LocalClientConfig {
            socket_path: socket_path.clone(),
            name: "dereg-client".to_string(),
        };
        let client_handle = spawn_local_client(client_cfg, 77, transport_tx.clone())
            .await
            .unwrap();

        let accepted = tokio::time::timeout(std::time::Duration::from_secs(3), handle_rx.recv())
            .await
            .expect("timeout waiting for accepted handle")
            .expect("handle channel closed");
        let server_side_client_id = accepted.id;

        // Abort client; server's per-client read_loop sees EOF and exits.
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
                Ok(Some(_)) => continue, // inbound frames etc.
                Ok(None) => break,
                Err(_) => continue,
            }
        }

        assert!(
            saw_dereg,
            "server must emit DeregisterInterface for disconnected client id {server_side_client_id}"
        );

        server_handle.read_task.abort();
        let _ = std::fs::remove_file(&socket_path);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn test_local_client_reconnects_after_server_restart() {
        let (transport_tx, mut transport_rx) = mpsc::channel::<TransportMessage>(64);
        let (handle_tx, mut handle_rx) = mpsc::channel::<InterfaceHandle>(8);
        let id_gen = Arc::new(AtomicU64::new(900));
        let socket_path = unique_test_socket_path("reticulum_reconnect_test");

        let server_config = || LocalServerConfig {
            socket_path: socket_path.clone(),
            name: "restartable-local-server".to_string(),
        };
        let server_handle = spawn_local_server(
            server_config(),
            id_gen.clone(),
            transport_tx.clone(),
            handle_tx.clone(),
        )
        .await
        .unwrap();
        let client_handle = spawn_local_client(
            LocalClientConfig {
                socket_path: socket_path.clone(),
                name: "persistent-local-client".to_string(),
            },
            88,
            transport_tx.clone(),
        )
        .await
        .unwrap();
        let first_accepted =
            tokio::time::timeout(std::time::Duration::from_secs(3), handle_rx.recv())
                .await
                .expect("timeout waiting for first accepted client")
                .expect("handle channel closed");

        server_handle.read_task.abort();
        first_accepted.read_task.abort();
        drop(first_accepted.tx);
        tokio::time::timeout(std::time::Duration::from_secs(3), async {
            while client_handle.online.load(Ordering::SeqCst) {
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("client did not observe server shutdown");

        let restarted_server =
            spawn_local_server(server_config(), id_gen, transport_tx.clone(), handle_tx)
                .await
                .unwrap();
        let second_accepted =
            tokio::time::timeout(std::time::Duration::from_secs(3), handle_rx.recv())
                .await
                .expect("client did not reconnect to restarted server")
                .expect("handle channel closed");
        assert!(
            client_handle.online.load(Ordering::SeqCst),
            "stable client handle must return online after reconnect"
        );

        let payload = Bytes::from_static(b"after shared restart");
        second_accepted.tx.send(payload.clone()).await.unwrap();
        let inbound = tokio::time::timeout(std::time::Duration::from_secs(3), transport_rx.recv())
            .await
            .expect("timeout waiting for post-restart frame")
            .expect("transport channel closed");
        match inbound {
            TransportMessage::Inbound(packet) => {
                assert_eq!(packet.interface_id, 88);
                assert_eq!(packet.raw, payload);
            }
            other => panic!("unexpected post-restart message: {other:?}"),
        }

        restarted_server.read_task.abort();
        second_accepted.read_task.abort();
        drop(second_accepted.tx);
        client_handle.read_task.abort();
        let _ = std::fs::remove_file(&socket_path);
    }
}
