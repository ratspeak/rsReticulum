//! Shared-instance IPC with HDLC framing, matching upstream
//! `LocalServerInterface`/`LocalClientInterface`. A `socket_path` of the form
//! `tcp://host:port` selects a loopback TCP socket on every platform; any
//! other value is a Unix socket path (abstract when it starts with NUL). On
//! non-Unix platforms non-TCP values fall back to the loopback default.

use rns_transport::messages::{InterfaceOwner, InterfacePacketCapacity, InterfaceTransportSender};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use bytes::Bytes;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;

use crate::hdlc;
use crate::traits::{
    InterfaceDirection, InterfaceHandle, InterfaceId, InterfaceMode, handoff_accepted_interface,
};
use rns_transport::messages::{InboundPacket, TransportMessage};

pub const LOCAL_MTU: u32 = 262_144;
const LOCAL_HW_MTU: usize = LOCAL_MTU as usize;
pub const LOCAL_BITRATE: u64 = 1_000_000_000;
pub const RECONNECT_WAIT: Duration = Duration::from_secs(8);
pub const CLIENT_SLEEP_PAUSE_TIMEOUT: Duration = Duration::from_secs(12);
/// Upstream sends keepalives from the transport interface jobs, every 5 s.
pub const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(5);

const TCP_SCHEME: &str = "tcp://";

/// Default filesystem socket path for local IPC.
pub const DEFAULT_SOCKET_PATH: &str = "/tmp/rns_reticulum.sock";

/// Return `data_dir/cache/rns_reticulum.sock` on Android when `data_dir` is
/// provided; otherwise return [`DEFAULT_SOCKET_PATH`]. This helper creates no
/// directories and does not check whether the returned path is writable.
pub fn socket_path(data_dir: Option<&std::path::Path>) -> std::path::PathBuf {
    if cfg!(target_os = "android")
        && let Some(dir) = data_dir
    {
        return dir.join("cache").join("rns_reticulum.sock");
    }
    std::path::PathBuf::from(DEFAULT_SOCKET_PATH)
}

pub const FALLBACK_TCP_PORT: u16 = 37428;

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

/// `socket_path` value for a loopback TCP shared instance on `port`.
pub fn tcp_socket_path(port: u16) -> String {
    format!("{TCP_SCHEME}127.0.0.1:{port}")
}

/// Upstream `platformutils.is_android()`: an Android build, or a process
/// started with Android's runtime environment.
pub fn is_android() -> bool {
    cfg!(target_os = "android")
        || std::env::var_os("ANDROID_ARGUMENT").is_some()
        || std::env::var_os("ANDROID_ROOT").is_some()
}

/// Upstream `platformutils.use_epoll()`; the forced-bitrate send delay only
/// exists on the other (thread-per-socket) backend.
fn uses_epoll_backend() -> bool {
    cfg!(any(target_os = "linux", target_os = "android")) || is_android()
}

/// Simulated transmission time for `len` payload bytes at `bitrate`.
pub fn forced_bitrate_delay(len: usize, bitrate: u64) -> Duration {
    Duration::from_secs_f64(len as f64 * 8.0 / bitrate as f64)
}

fn send_delay(len: usize, force_bitrate: Option<u64>) -> Option<Duration> {
    if uses_epoll_backend() {
        return None;
    }
    force_bitrate
        .filter(|bitrate| *bitrate > 0)
        .map(|bitrate| forced_bitrate_delay(len, bitrate))
}

#[cfg(unix)]
fn display_socket_path(path: &str) -> String {
    if let Some(name) = path.strip_prefix('\0') {
        format!("\\0{name}")
    } else {
        path.to_string()
    }
}

#[derive(Debug, Clone)]
pub struct LocalServerConfig {
    /// Unix socket path, or `tcp://host:port` for a TCP listener.
    pub socket_path: String,
    pub name: String,
    /// `force_shared_instance_bitrate`; accepted clients inherit it.
    pub force_bitrate: Option<u64>,
}

impl Default for LocalServerConfig {
    fn default() -> Self {
        Self {
            socket_path: DEFAULT_SOCKET_PATH.to_string(),
            name: "LocalServer".to_string(),
            force_bitrate: None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct LocalClientConfig {
    /// Unix socket path, or `tcp://host:port` for a TCP shared instance.
    pub socket_path: String,
    pub name: String,
    /// `force_shared_instance_bitrate`.
    pub force_bitrate: Option<u64>,
}

impl Default for LocalClientConfig {
    fn default() -> Self {
        Self {
            socket_path: DEFAULT_SOCKET_PATH.to_string(),
            name: "LocalClient".to_string(),
            force_bitrate: None,
        }
    }
}

type LocalReader = Box<dyn AsyncRead + Unpin + Send>;
type LocalWriter = Box<dyn AsyncWrite + Unpin + Send>;

#[derive(Debug, Clone)]
enum LocalEndpoint {
    #[cfg(unix)]
    Unix(String),
    Tcp(String),
}

impl LocalEndpoint {
    fn parse(socket_path: &str) -> Self {
        if let Some(addr) = socket_path
            .strip_prefix(TCP_SCHEME)
            .filter(|addr| !addr.is_empty())
        {
            return Self::Tcp(addr.to_string());
        }
        #[cfg(unix)]
        {
            Self::Unix(socket_path.to_string())
        }
        #[cfg(not(unix))]
        {
            Self::Tcp(format!("127.0.0.1:{FALLBACK_TCP_PORT}"))
        }
    }

    fn display(&self) -> String {
        match self {
            #[cfg(unix)]
            Self::Unix(path) => display_socket_path(path),
            Self::Tcp(addr) => format!("{TCP_SCHEME}{addr}"),
        }
    }

    async fn connect(&self) -> std::io::Result<(LocalReader, LocalWriter)> {
        match self {
            #[cfg(unix)]
            Self::Unix(path) => {
                let (reader, writer) = unix::connect(path).await?.into_split();
                Ok((Box::new(reader), Box::new(writer)))
            }
            Self::Tcp(addr) => {
                let stream = tokio::net::TcpStream::connect(addr).await?;
                let _ = stream.set_nodelay(true);
                let (reader, writer) = stream.into_split();
                Ok((Box::new(reader), Box::new(writer)))
            }
        }
    }

    async fn bind(&self) -> std::io::Result<LocalListener> {
        match self {
            #[cfg(unix)]
            Self::Unix(path) => Ok(LocalListener::Unix(unix::bind(path)?)),
            Self::Tcp(addr) => Ok(LocalListener::Tcp(
                tokio::net::TcpListener::bind(addr).await?,
            )),
        }
    }
}

enum LocalListener {
    #[cfg(unix)]
    Unix(tokio::net::UnixListener),
    Tcp(tokio::net::TcpListener),
}

impl LocalListener {
    async fn accept(&self) -> std::io::Result<(LocalReader, LocalWriter, String)> {
        match self {
            #[cfg(unix)]
            Self::Unix(listener) => {
                let (stream, _) = listener.accept().await?;
                let (reader, writer) = stream.into_split();
                Ok((Box::new(reader), Box::new(writer), "unix".to_string()))
            }
            Self::Tcp(listener) => {
                let (stream, peer) = listener.accept().await?;
                let _ = stream.set_nodelay(true);
                let (reader, writer) = stream.into_split();
                Ok((Box::new(reader), Box::new(writer), peer.to_string()))
            }
        }
    }
}

#[cfg(unix)]
mod unix {
    use tokio::net::{UnixListener, UnixStream};

    pub(super) fn bind(socket_path: &str) -> std::io::Result<UnixListener> {
        if let Some(abstract_name) = socket_path.strip_prefix('\0') {
            return bind_abstract(abstract_name);
        }
        let _ = std::fs::remove_file(socket_path);
        UnixListener::bind(socket_path)
    }

    pub(super) async fn connect(socket_path: &str) -> std::io::Result<UnixStream> {
        if let Some(abstract_name) = socket_path.strip_prefix('\0') {
            return connect_abstract(abstract_name);
        }
        UnixStream::connect(socket_path).await
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn bind_abstract(name: &str) -> std::io::Result<UnixListener> {
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
    fn bind_abstract(_name: &str) -> std::io::Result<UnixListener> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "abstract Unix sockets are only available on Linux/Android",
        ))
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn connect_abstract(name: &str) -> std::io::Result<UnixStream> {
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
    fn connect_abstract(_name: &str) -> std::io::Result<UnixStream> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "abstract Unix sockets are only available on Linux/Android",
        ))
    }
}

/// Upstream Android owners stop sending to an accepted client that has been
/// silent for [`CLIENT_SLEEP_PAUSE_TIMEOUT`]; any received data re-arms it.
struct ClientSleepPause {
    deadline: std::sync::Mutex<tokio::time::Instant>,
}

impl ClientSleepPause {
    fn new() -> Self {
        Self {
            deadline: std::sync::Mutex::new(
                tokio::time::Instant::now() + CLIENT_SLEEP_PAUSE_TIMEOUT,
            ),
        }
    }

    fn refresh(&self) {
        *self.deadline.lock().expect("pause mutex poisoned") =
            tokio::time::Instant::now() + CLIENT_SLEEP_PAUSE_TIMEOUT;
    }

    fn paused(&self) -> bool {
        tokio::time::Instant::now() > *self.deadline.lock().expect("pause mutex poisoned")
    }
}

async fn write_local_frame<W: AsyncWrite + Unpin>(
    writer: &mut W,
    data: &[u8],
    force_bitrate: Option<u64>,
) -> std::io::Result<usize> {
    if let Some(delay) = send_delay(data.len(), force_bitrate) {
        tokio::time::sleep(delay).await;
    }
    let framed = hdlc::frame(data);
    writer.write_all(&framed).await?;
    Ok(framed.len())
}

async fn accepted_read_loop(
    mut reader: LocalReader,
    interface_id: InterfaceId,
    transport_tx: InterfaceTransportSender,
    online: Arc<AtomicBool>,
    rxb: Arc<AtomicU64>,
    pause: Option<Arc<ClientSleepPause>>,
) {
    let mut buf = [0u8; 8192];
    let mut deframer = hdlc::HdlcDeframer::with_limits(
        LOCAL_HW_MTU,
        rns_wire::constants::HEADER_MINSIZE,
        Some(LOCAL_HW_MTU),
    );

    loop {
        match reader.read(&mut buf).await {
            Ok(0) => {
                tracing::info!(interface_id, "local read: EOF");
                break;
            }
            Ok(n) => {
                if let Some(pause) = &pause {
                    pause.refresh();
                }
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

async fn accepted_write_loop(
    mut writer: LocalWriter,
    mut rx: mpsc::Receiver<Bytes>,
    online: Arc<AtomicBool>,
    txb: Arc<AtomicU64>,
    pause: Option<Arc<ClientSleepPause>>,
    force_bitrate: Option<u64>,
) {
    while let Some(data) = rx.recv().await {
        if pause.as_ref().is_some_and(|pause| pause.paused()) {
            tracing::debug!("TX paused for local client, dropping outbound packet");
            continue;
        }
        match write_local_frame(&mut writer, &data, force_bitrate).await {
            Ok(written) => {
                txb.fetch_add(written as u64, Ordering::Relaxed);
            }
            Err(e) => {
                tracing::warn!(error = %e, "local write error");
                break;
            }
        }
    }
    online.store(false, Ordering::SeqCst);
}

enum LocalClientConnectionEnd {
    /// EOF or a socket error: the client reconnects.
    Disconnected,
    Detached,
}

struct LocalClientIo<'a> {
    interface_id: InterfaceId,
    transport_tx: &'a InterfaceTransportSender,
    rxb: &'a AtomicU64,
    txb: &'a AtomicU64,
    force_bitrate: Option<u64>,
}

/// Drive both halves of one initiating local-client connection in a single
/// task. Keeping the persistent outbound receiver here lets the client retain
/// one stable `InterfaceHandle` while replacing only the socket after a
/// shared-instance restart.
async fn run_local_client_connection(
    mut reader: LocalReader,
    mut writer: LocalWriter,
    rx: &mut mpsc::Receiver<Bytes>,
    io: &LocalClientIo<'_>,
    phy_keepalive: bool,
) -> LocalClientConnectionEnd {
    let interface_id = io.interface_id;
    let mut buf = [0u8; 8192];
    let mut deframer = hdlc::HdlcDeframer::with_limits(
        LOCAL_HW_MTU,
        rns_wire::constants::HEADER_MINSIZE,
        Some(LOCAL_HW_MTU),
    );
    let mut keepalive = phy_keepalive.then(|| {
        let mut interval = tokio::time::interval_at(
            tokio::time::Instant::now() + KEEPALIVE_INTERVAL,
            KEEPALIVE_INTERVAL,
        );
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        interval
    });

    loop {
        tokio::select! {
            read = reader.read(&mut buf) => {
                match read {
                    Ok(0) => {
                        tracing::info!(interface_id, "local client read: EOF");
                        return LocalClientConnectionEnd::Disconnected;
                    }
                    Ok(n) => {
                        io.rxb.fetch_add(n as u64, Ordering::Relaxed);
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
                            if io.transport_tx.send(msg).await.is_err() {
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
                match write_local_frame(&mut writer, &data, io.force_bitrate).await {
                    Ok(written) => {
                        io.txb.fetch_add(written as u64, Ordering::Relaxed);
                    }
                    Err(error) => {
                        tracing::warn!(interface_id, %error, "local client write error");
                        return LocalClientConnectionEnd::Disconnected;
                    }
                }
            }
            _ = async {
                match keepalive.as_mut() {
                    Some(interval) => {
                        interval.tick().await;
                    }
                    None => std::future::pending::<()>().await,
                }
            } => {
                // Upstream only logs keepalive send failures.
                if let Err(error) = writer.write_all(&[hdlc::FLAG, hdlc::FLAG]).await {
                    tracing::error!(interface_id, %error, "local client keepalive error");
                }
            }
        }
    }
}

/// Wire one accepted server-side client: write loop, read task, and its
/// `InterfaceHandle`. Transport is told to drop it as soon as it disconnects.
fn wire_accepted_stream(
    id: InterfaceId,
    name: String,
    parent_id: InterfaceId,
    reader: LocalReader,
    writer: LocalWriter,
    transport_tx: mpsc::Sender<TransportMessage>,
    force_bitrate: Option<u64>,
) -> InterfaceHandle {
    let transport_tx = InterfaceTransportSender::new(id, transport_tx);
    let owner = transport_tx.owner();
    let online = Arc::new(AtomicBool::new(true));
    let rxb = Arc::new(AtomicU64::new(0));
    let txb = Arc::new(AtomicU64::new(0));
    let (tx, rx) = mpsc::channel::<Bytes>(256);
    let pause = is_android().then(|| Arc::new(ClientSleepPause::new()));

    tokio::spawn(accepted_write_loop(
        writer,
        rx,
        online.clone(),
        txb.clone(),
        pause.clone(),
        force_bitrate,
    ));

    let online_r = online.clone();
    let rxb_r = rxb.clone();
    let task_name = name.clone();
    let dereg_tx = transport_tx.clone();
    let read_task = tokio::spawn(async move {
        accepted_read_loop(reader, id, transport_tx, online_r, rxb_r, pause).await;
        tracing::info!(name = %task_name, "local client disconnected");
        // Proactively notify so transport drops immediately.
        let _ = dereg_tx
            .send(TransportMessage::DeregisterInterface { id })
            .await;
    });

    local_handle(
        id,
        owner,
        name,
        Some(parent_id),
        true,
        online,
        rxb,
        txb,
        tx,
        read_task,
    )
}

#[allow(clippy::too_many_arguments)]
fn local_handle(
    id: InterfaceId,
    owner: InterfaceOwner,
    name: String,
    parent_id: Option<InterfaceId>,
    outbound: bool,
    online: Arc<AtomicBool>,
    rxb: Arc<AtomicU64>,
    txb: Arc<AtomicU64>,
    tx: mpsc::Sender<Bytes>,
    read_task: tokio::task::JoinHandle<()>,
) -> InterfaceHandle {
    InterfaceHandle {
        id,
        owner,
        packet_capacity: InterfacePacketCapacity::new(LOCAL_MTU, LOCAL_MTU, true),
        parent_id,
        name,
        mode: InterfaceMode::Full,
        direction: InterfaceDirection {
            inbound: true,
            outbound,
            forward: false,
            repeat: false,
        },
        bitrate: LOCAL_BITRATE,
        mtu: LOCAL_MTU,
        online,
        rxb: Some(rxb),
        txb: Some(txb),
        inspection: None,
        tx,
        read_task,
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
    id: InterfaceId,
    id_gen: Arc<AtomicU64>,
    transport_tx: mpsc::Sender<TransportMessage>,
    handle_tx: mpsc::Sender<InterfaceHandle>,
) -> Result<InterfaceHandle, crate::traits::InterfaceError> {
    let endpoint = LocalEndpoint::parse(&config.socket_path);
    let listener = endpoint.bind().await?;
    tracing::info!(name = %config.name, endpoint = %endpoint.display(), "local server listening");

    let owner = InterfaceOwner::new();
    let online = Arc::new(AtomicBool::new(true));
    let online2 = online.clone();
    let name = config.name.clone();
    let (tx, _rx) = mpsc::channel::<Bytes>(1);

    let read_task = tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((reader, writer, peer)) => {
                    let client_id = id_gen.fetch_add(1, Ordering::SeqCst);
                    let client_name = format!("{}/client_{}", config.name, client_id);
                    tracing::info!(name = %client_name, %peer, "local client connected");

                    let handle = wire_accepted_stream(
                        client_id,
                        client_name,
                        id,
                        reader,
                        writer,
                        transport_tx.clone(),
                        config.force_bitrate,
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
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        }
        online2.store(false, Ordering::SeqCst);
    });

    Ok(local_handle(
        id,
        owner,
        name,
        None,
        false,
        online,
        Arc::new(AtomicU64::new(0)),
        Arc::new(AtomicU64::new(0)),
        tx,
        read_task,
    ))
}

/// Connect to a shared instance. The returned handle survives owner restarts:
/// after a disconnect the client retries every [`RECONNECT_WAIT`], forever,
/// dropping traffic queued while offline.
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
    let transport_tx = InterfaceTransportSender::new(id, transport_tx);
    let owner = transport_tx.owner();
    let endpoint = LocalEndpoint::parse(&config.socket_path);
    let initial = endpoint.connect().await?;
    tracing::debug!(name = %config.name, endpoint = %endpoint.display(), "local client connected");

    let online = Arc::new(AtomicBool::new(true));
    let rxb = Arc::new(AtomicU64::new(0));
    let txb = Arc::new(AtomicU64::new(0));
    let (tx, mut rx) = mpsc::channel::<Bytes>(256);

    let task_online = online.clone();
    let task_rxb = rxb.clone();
    let task_txb = txb.clone();
    let task_name = config.name.clone();
    let force_bitrate = config.force_bitrate;
    let read_task = tokio::spawn(async move {
        let io = LocalClientIo {
            interface_id: id,
            transport_tx: &transport_tx,
            rxb: &task_rxb,
            txb: &task_txb,
            force_bitrate,
        };
        let (mut reader, mut writer) = initial;
        loop {
            let end = run_local_client_connection(reader, writer, &mut rx, &io, is_android()).await;
            task_online.store(false, Ordering::SeqCst);

            if matches!(end, LocalClientConnectionEnd::Detached)
                || transport_tx.is_closed()
                || rx.is_closed()
            {
                return;
            }
            tracing::warn!(
                name = %task_name,
                endpoint = %endpoint.display(),
                wait_seconds = RECONNECT_WAIT.as_secs(),
                "local shared-instance connection lost; reconnecting"
            );
            loop {
                tokio::time::sleep(RECONNECT_WAIT).await;
                if transport_tx.is_closed() || rx.is_closed() {
                    return;
                }
                match endpoint.connect().await {
                    Ok(connected) => {
                        (reader, writer) = connected;
                        // Upstream drops traffic while offline.
                        while rx.try_recv().is_ok() {}
                        task_online.store(true, Ordering::SeqCst);
                        tracing::info!(
                            name = %task_name,
                            endpoint = %endpoint.display(),
                            "local shared-instance client reconnected"
                        );
                        break;
                    }
                    Err(error) => {
                        tracing::debug!(
                            name = %task_name,
                            endpoint = %endpoint.display(),
                            %error,
                            "local shared-instance reconnect failed"
                        );
                    }
                }
            }
        }
    });

    Ok(local_handle(
        id,
        owner,
        config.name,
        None,
        true,
        online,
        rxb,
        txb,
        tx,
        read_task,
    ))
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
            let _ = prefix;
            let listener =
                std::net::TcpListener::bind("127.0.0.1:0").expect("reserve local test port");
            let port = listener.local_addr().expect("read local test port").port();
            drop(listener);
            format!("tcp://127.0.0.1:{port}")
        }
    }

    /// The client's real reconnect wait, plus one missed attempt on a loaded host.
    #[cfg(unix)]
    const RECONNECT_DEADLINE: std::time::Duration =
        std::time::Duration::from_secs(2 * RECONNECT_WAIT.as_secs());

    /// The server hands off an accepted client before that client has
    /// necessarily published itself online, so wait for the flag itself.
    #[cfg(unix)]
    async fn wait_until_online(online: &AtomicBool) {
        tokio::time::timeout(std::time::Duration::from_secs(3), async {
            while !online.load(Ordering::SeqCst) {
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("stable client handle must return online after reconnect");
    }

    #[test]
    fn forced_bitrate_delay_is_payload_airtime() {
        // Upstream sleeps len / bitrate * 8 (LocalInterface.py:228-236).
        assert_eq!(forced_bitrate_delay(400, 1000), Duration::from_millis(3200));
    }

    #[tokio::test(start_paused = true)]
    async fn client_sleep_pause_trips_after_timeout_and_rearms_on_receive() {
        let pause = ClientSleepPause::new();
        assert!(!pause.paused());
        tokio::time::advance(CLIENT_SLEEP_PAUSE_TIMEOUT + Duration::from_millis(1)).await;
        assert!(pause.paused());
        pause.refresh();
        assert!(!pause.paused());
    }

    #[tokio::test(start_paused = true)]
    async fn phy_keepalive_writes_two_flags_every_interval() {
        let (transport_tx, _transport_rx) = mpsc::channel::<TransportMessage>(8);
        let transport_tx = crate::traits::test_registered_sender(7, transport_tx);
        let (client, mut server) = tokio::io::duplex(64);
        let (reader, writer) = tokio::io::split(client);
        let (_tx, mut rx) = mpsc::channel::<Bytes>(1);
        let (rxb, txb) = (AtomicU64::new(0), AtomicU64::new(0));
        let task = async {
            let io = LocalClientIo {
                interface_id: 7,
                transport_tx: &transport_tx,
                rxb: &rxb,
                txb: &txb,
                force_bitrate: None,
            };
            run_local_client_connection(Box::new(reader), Box::new(writer), &mut rx, &io, true)
                .await
        };
        let check = async {
            let mut buf = [0u8; 4];
            let started = tokio::time::Instant::now();
            server.read_exact(&mut buf[..2]).await.unwrap();
            assert_eq!(&buf[..2], &[hdlc::FLAG, hdlc::FLAG]);
            assert_eq!(started.elapsed(), KEEPALIVE_INTERVAL);
            server.read_exact(&mut buf[..2]).await.unwrap();
            assert_eq!(started.elapsed(), 2 * KEEPALIVE_INTERVAL);
        };
        tokio::select! {
            _ = task => panic!("connection ended"),
            _ = check => {}
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
            force_bitrate: None,
        };
        assert_eq!(cfg.socket_path, "/tmp/test_rns.sock");
        assert_eq!(cfg.name, "TestServer");
    }

    #[test]
    fn test_local_client_config() {
        let cfg = LocalClientConfig {
            socket_path: "/tmp/test_rns.sock".to_string(),
            name: "TestClient".to_string(),
            force_bitrate: None,
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
            force_bitrate: None,
        };

        let server_handle =
            spawn_local_server(server_cfg, 499, id_gen, transport_tx.clone(), handle_tx)
                .await
                .unwrap();
        server_handle.owner.mark_registered();
        assert_eq!(server_handle.id, 499);

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let client_cfg = LocalClientConfig {
            socket_path: socket_path.clone(),
            name: "test-local-client".to_string(),
            force_bitrate: None,
        };

        let client_handle = spawn_local_client(client_cfg, 42, transport_tx.clone())
            .await
            .unwrap();
        client_handle.owner.mark_registered();

        let accepted = tokio::time::timeout(std::time::Duration::from_secs(3), handle_rx.recv())
            .await
            .expect("timeout waiting for accepted handle")
            .expect("handle channel closed");
        accepted.owner.mark_registered();

        assert_ne!(accepted.owner, server_handle.owner);
        assert_ne!(accepted.owner, client_handle.owner);
        assert_eq!(accepted.parent_id, Some(server_handle.id));
        assert_eq!(
            accepted.packet_capacity,
            InterfacePacketCapacity::new(262144, 262144, true)
        );
        let payload = Bytes::from_static(b"local ipc test packet payload");
        client_handle.tx.send(payload.clone()).await.unwrap();

        let msg = tokio::time::timeout(std::time::Duration::from_secs(3), transport_rx.recv())
            .await
            .expect("timeout")
            .expect("channel closed");

        match crate::traits::test_event_for_handle(msg, &accepted) {
            TransportMessage::Inbound(pkt) => {
                assert_eq!(pkt.raw, payload);
                assert_eq!(pkt.interface_id, accepted.id);
            }
            other => panic!("unexpected: {:?}", other),
        }

        let reply = Bytes::from_static(b"local ipc reply packet payload");
        accepted.tx.send(reply.clone()).await.unwrap();

        let msg2 = tokio::time::timeout(std::time::Duration::from_secs(3), transport_rx.recv())
            .await
            .expect("timeout")
            .expect("channel closed");

        match crate::traits::test_event_for_handle(msg2, &client_handle) {
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
            force_bitrate: None,
        };
        let server_handle =
            spawn_local_server(server_cfg, 599, id_gen, transport_tx.clone(), handle_tx)
                .await
                .unwrap();
        server_handle.owner.mark_registered();

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let client_cfg = LocalClientConfig {
            socket_path: socket_path.clone(),
            name: "dereg-client".to_string(),
            force_bitrate: None,
        };
        let client_handle = spawn_local_client(client_cfg, 77, transport_tx.clone())
            .await
            .unwrap();
        client_handle.owner.mark_registered();

        let accepted = tokio::time::timeout(std::time::Duration::from_secs(3), handle_rx.recv())
            .await
            .expect("timeout waiting for accepted handle")
            .expect("handle channel closed");
        accepted.owner.mark_registered();
        let server_side_client_id = accepted.id;

        // Abort client; server's per-client read_loop sees EOF and exits.
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
            force_bitrate: None,
        };
        let server_handle = spawn_local_server(
            server_config(),
            699,
            id_gen.clone(),
            transport_tx.clone(),
            handle_tx.clone(),
        )
        .await
        .unwrap();
        server_handle.owner.mark_registered();
        let client_handle = spawn_local_client(
            LocalClientConfig {
                socket_path: socket_path.clone(),
                name: "persistent-local-client".to_string(),
                force_bitrate: None,
            },
            88,
            transport_tx.clone(),
        )
        .await
        .unwrap();
        client_handle.owner.mark_registered();
        let first_accepted =
            tokio::time::timeout(std::time::Duration::from_secs(3), handle_rx.recv())
                .await
                .expect("timeout waiting for first accepted client")
                .expect("handle channel closed");
        first_accepted.owner.mark_registered();

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

        let restarted_server = spawn_local_server(
            server_config(),
            699,
            id_gen,
            transport_tx.clone(),
            handle_tx,
        )
        .await
        .unwrap();
        restarted_server.owner.mark_registered();
        let second_accepted = tokio::time::timeout(RECONNECT_DEADLINE, handle_rx.recv())
            .await
            .expect("client did not reconnect to restarted server")
            .expect("handle channel closed");
        second_accepted.owner.mark_registered();
        wait_until_online(&client_handle.online).await;

        let payload = Bytes::from_static(b"after shared restart");
        second_accepted.tx.send(payload.clone()).await.unwrap();
        let inbound = tokio::time::timeout(std::time::Duration::from_secs(3), transport_rx.recv())
            .await
            .expect("timeout waiting for post-restart frame")
            .expect("transport channel closed");
        match crate::traits::test_event_for_handle(inbound, &client_handle) {
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

    /// Python's `LocalClientInterface` drops outgoing traffic while offline
    /// (LocalInterface.py:218), so nothing queued during an outage reaches
    /// the restarted shared instance.
    #[cfg(unix)]
    #[tokio::test]
    async fn test_local_client_drops_traffic_queued_while_disconnected() {
        let (transport_tx, mut transport_rx) = mpsc::channel::<TransportMessage>(64);
        let (handle_tx, mut handle_rx) = mpsc::channel::<InterfaceHandle>(8);
        let id_gen = Arc::new(AtomicU64::new(950));
        let socket_path = unique_test_socket_path("reticulum_offline_queue_test");
        let server_config = || LocalServerConfig {
            socket_path: socket_path.clone(),
            name: "restartable-local-server".to_string(),
            force_bitrate: None,
        };
        let server_handle = spawn_local_server(
            server_config(),
            698,
            id_gen.clone(),
            transport_tx.clone(),
            handle_tx.clone(),
        )
        .await
        .unwrap();
        server_handle.owner.mark_registered();
        let client_handle = spawn_local_client(
            LocalClientConfig {
                socket_path: socket_path.clone(),
                name: "offline-local-client".to_string(),
                force_bitrate: None,
            },
            89,
            transport_tx.clone(),
        )
        .await
        .unwrap();
        client_handle.owner.mark_registered();
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
        client_handle
            .tx
            .send(Bytes::from_static(b"queued while offline"))
            .await
            .unwrap();

        let restarted_server = spawn_local_server(
            server_config(),
            698,
            id_gen,
            transport_tx.clone(),
            handle_tx,
        )
        .await
        .unwrap();
        restarted_server.owner.mark_registered();
        let second_accepted = tokio::time::timeout(RECONNECT_DEADLINE, handle_rx.recv())
            .await
            .expect("client did not reconnect to restarted server")
            .expect("handle channel closed");
        second_accepted.owner.mark_registered();
        // Online is published only after the offline queue is dropped.
        wait_until_online(&client_handle.online).await;
        let after = Bytes::from_static(b"after reconnect packet payload");
        client_handle.tx.send(after.clone()).await.unwrap();

        let first_frame = tokio::time::timeout(std::time::Duration::from_secs(3), async {
            loop {
                match transport_rx.recv().await.expect("transport channel closed") {
                    TransportMessage::InterfaceEvent {
                        interface_id,
                        message,
                        ..
                    } if interface_id == second_accepted.id => {
                        if let TransportMessage::Inbound(packet) = *message {
                            return packet.raw;
                        }
                    }
                    _ => {}
                }
            }
        })
        .await
        .expect("the reconnected client's traffic reaches the shared instance");
        assert_eq!(
            first_frame, after,
            "traffic queued while disconnected is dropped"
        );

        restarted_server.read_task.abort();
        second_accepted.read_task.abort();
        client_handle.read_task.abort();
        let _ = std::fs::remove_file(&socket_path);
    }
}
