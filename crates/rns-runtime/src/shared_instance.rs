//! Explicit local shared-instance admission for applications that require RPC.
//!
//! This is an opt-in application policy, not a change to Python-compatible
//! automatic sharing. Packet IPC is not authenticated by upstream's protocol;
//! RPC authenticates the control endpoint, not the identity of a packet socket.
//! Both endpoints must be selected by the caller. Every reconnect revalidates
//! RPC before resuming packet traffic. No local interface fallback is performed.

use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use bytes::Bytes;
use rns_interface::hdlc::{self, HdlcDeframer};
use rns_interface::traits::{InterfaceDirection, InterfaceHandle, InterfaceMode};
use rns_transport::messages::{InboundPacket, TransportMessage};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{mpsc, watch};
use zeroize::Zeroizing;

use crate::lifecycle::ShutdownSignal;
use crate::reticulum::{
    ReticulumConfig, ReticulumError, SharedInstanceRpcEndpoint, SharedInstanceType,
};
use crate::rpc::{RpcError, RpcRequest, RpcResponse};

const ADMISSION_TIMEOUT: Duration = Duration::from_secs(5);
const CONTROL_CHECK_INTERVAL: Duration = Duration::from_secs(10);

/// A local shared-service selector. TCP never accepts a remote host address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SharedInstanceEndpoint {
    Tcp {
        packet_port: u16,
        control_port: u16,
    },
    /// Upstream abstract Unix socket name; supported on Linux and Android.
    Unix {
        instance_name: String,
    },
}

impl SharedInstanceEndpoint {
    pub fn validate(&self) -> Result<(), SharedInstanceError> {
        match self {
            Self::Tcp {
                packet_port,
                control_port,
            } if *packet_port == 0 || *control_port == 0 || packet_port == control_port => {
                Err(SharedInstanceError::InvalidEndpoint)
            }
            Self::Unix { instance_name } => {
                if instance_name.is_empty()
                    || instance_name.len() > 64
                    || !instance_name
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
                {
                    return Err(SharedInstanceError::InvalidEndpoint);
                }
                if !cfg!(any(target_os = "linux", target_os = "android")) {
                    return Err(SharedInstanceError::UnsupportedCarrier);
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }

    pub(crate) fn apply(&self, config: &mut ReticulumConfig) {
        config.share_instance = true;
        match self {
            Self::Tcp {
                packet_port,
                control_port,
            } => {
                config.shared_instance_type = SharedInstanceType::Tcp;
                config.shared_instance_port = *packet_port;
                config.control_port = *control_port;
            }
            Self::Unix { instance_name } => {
                config.shared_instance_type = SharedInstanceType::Unix;
                config.instance_name = instance_name.clone();
            }
        }
    }

    pub(crate) fn from_config(config: &ReticulumConfig) -> Self {
        match config.shared_instance_type {
            SharedInstanceType::Tcp => Self::Tcp {
                packet_port: config.shared_instance_port,
                control_port: config.control_port,
            },
            SharedInstanceType::Unix => Self::Unix {
                instance_name: config.instance_name.clone(),
            },
        }
    }
}

/// In-memory authorization material. Debug output deliberately excludes keys.
#[derive(Clone)]
pub struct SharedInstanceCredentials {
    endpoint: SharedInstanceEndpoint,
    rpc_key: Zeroizing<Vec<u8>>,
}

impl std::fmt::Debug for SharedInstanceCredentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SharedInstanceCredentials")
            .field("endpoint", &self.endpoint)
            .field("rpc_key", &"[redacted]")
            .finish()
    }
}

impl SharedInstanceCredentials {
    /// Keys are opaque HMAC bytes, not necessarily the default 32-byte hash.
    pub fn new(
        endpoint: SharedInstanceEndpoint,
        rpc_key: Vec<u8>,
    ) -> Result<Self, SharedInstanceError> {
        let rpc_key = Zeroizing::new(rpc_key);
        endpoint.validate()?;
        if rpc_key.is_empty() || rpc_key.len() > 1024 {
            return Err(SharedInstanceError::InvalidKey);
        }
        Ok(Self { endpoint, rpc_key })
    }

    pub fn endpoint(&self) -> &SharedInstanceEndpoint {
        &self.endpoint
    }

    pub(crate) fn apply(&self, config: &mut ReticulumConfig) {
        self.endpoint.apply(config);
        config.rpc_key = Some(self.rpc_key.to_vec());
    }

    /// Test packet availability and authenticated interface-status RPC without
    /// starting a Reticulum runtime or persisting the credential.
    pub async fn test(&self) -> Result<(), SharedInstanceError> {
        self.connect().await.map(|_| ())
    }

    async fn check_control(&self) -> Result<(), SharedInstanceError> {
        let request = RpcRequest::GetInterfaceStats;
        let result = match &self.endpoint {
            SharedInstanceEndpoint::Tcp { control_port, .. } => {
                crate::rpc::connect_and_request(
                    *control_port,
                    &self.rpc_key,
                    &request,
                    ADMISSION_TIMEOUT,
                )
                .await
            }
            SharedInstanceEndpoint::Unix { instance_name } => {
                crate::rpc::connect_unix_and_request(
                    &format!("\0rns/{instance_name}/rpc"),
                    &self.rpc_key,
                    &request,
                    ADMISSION_TIMEOUT,
                )
                .await
            }
        };
        match result {
            Ok(RpcResponse::InterfaceStats(_)) => Ok(()),
            Ok(_) => Err(SharedInstanceError::UnsupportedControl),
            Err(RpcError::AuthFailed) => Err(SharedInstanceError::AuthenticationRejected),
            Err(_) => Err(SharedInstanceError::ControlUnavailable),
        }
    }

    async fn connect(&self) -> Result<PacketStream, SharedInstanceError> {
        self.endpoint.validate()?;
        tokio::time::timeout(ADMISSION_TIMEOUT, async {
            let stream: PacketStream = match &self.endpoint {
                SharedInstanceEndpoint::Tcp { packet_port, .. } => {
                    let stream = tokio::net::TcpStream::connect((
                        std::net::Ipv4Addr::LOCALHOST,
                        *packet_port,
                    ))
                    .await
                    .map_err(|_| SharedInstanceError::PacketUnavailable)?;
                    stream
                        .set_nodelay(true)
                        .map_err(|_| SharedInstanceError::PacketUnavailable)?;
                    Box::new(stream)
                }
                SharedInstanceEndpoint::Unix { instance_name } => {
                    #[cfg(unix)]
                    {
                        Box::new(
                            crate::rpc::connect_unix_stream(&format!("\0rns/{instance_name}"))
                                .await
                                .map_err(|_| SharedInstanceError::PacketUnavailable)?,
                        )
                    }
                    #[cfg(not(unix))]
                    {
                        let _ = instance_name;
                        return Err(SharedInstanceError::UnsupportedCarrier);
                    }
                }
            };
            self.check_control().await?;
            Ok(stream)
        })
        .await
        .map_err(|_| SharedInstanceError::TimedOut)?
    }
}

/// Opt-in ownership policy. `Configured` preserves existing library behavior.
#[derive(Debug, Clone, Default)]
pub enum InstancePolicy {
    #[default]
    Configured,
    Standalone,
    /// Bind both configured local listeners or fail; never become a client.
    SharedOwner,
    /// Bind an explicitly selected local endpoint pair, without rewriting config.
    SharedOwnerAt(SharedInstanceEndpoint),
    /// Require both selected endpoints; never start local interfaces.
    SharedClient(SharedInstanceCredentials),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SharedInstanceState {
    Ready,
    Reconnecting,
    AuthenticationRejected,
    ControlUnavailable,
    Stopped,
}

/// Bounded, credential-free shared admission failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SharedInstanceError {
    #[error("invalid local shared-instance endpoint")]
    InvalidEndpoint,
    #[error("RPC key must contain 1 to 1024 bytes")]
    InvalidKey,
    #[error("this shared-instance carrier is not supported on this platform")]
    UnsupportedCarrier,
    #[error("the shared packet service is unavailable")]
    PacketUnavailable,
    #[error("the shared control service is unavailable")]
    ControlUnavailable,
    #[error("the shared instance rejected the RPC key")]
    AuthenticationRejected,
    #[error("the shared instance cannot supply interface status")]
    UnsupportedControl,
    #[error("shared-instance connection timed out")]
    TimedOut,
    #[error("shared-instance startup was cancelled")]
    Cancelled,
    #[error("the shared packet endpoint is already occupied or cannot be bound")]
    PacketBindFailed,
    #[error("the shared control endpoint is already occupied or cannot be bound")]
    ControlBindFailed,
}

/// Policy startup errors are additive; the existing `ReticulumError` stays intact.
#[derive(Debug, thiserror::Error)]
pub enum InstanceStartupError {
    #[error(transparent)]
    Runtime(#[from] ReticulumError),
    #[error(transparent)]
    Shared(#[from] SharedInstanceError),
}

trait AsyncPacketStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> AsyncPacketStream for T {}
type PacketStream = Box<dyn AsyncPacketStream>;

pub(crate) async fn spawn_authenticated_client(
    credentials: SharedInstanceCredentials,
    id: u64,
    transport: mpsc::Sender<TransportMessage>,
    shutdown: ShutdownSignal,
) -> Result<(InterfaceHandle, watch::Receiver<SharedInstanceState>), SharedInstanceError> {
    let initial = tokio::select! {
        biased;
        _ = shutdown.wait() => return Err(SharedInstanceError::Cancelled),
        result = credentials.connect() => result?,
    };
    let online = Arc::new(AtomicBool::new(true));
    let rxb = Arc::new(AtomicU64::new(0));
    let txb = Arc::new(AtomicU64::new(0));
    let (tx, mut rx) = mpsc::channel::<Bytes>(64);
    let (status_tx, status) = watch::channel(SharedInstanceState::Ready);
    let task_online = online.clone();
    let task_rxb = rxb.clone();
    let task_txb = txb.clone();
    let read_task = tokio::spawn(async move {
        let mut stream = initial;
        loop {
            let failure = tokio::select! {
                biased;
                _ = shutdown.wait() => break,
                _ = packet_loop(&mut stream, &mut rx, id, &transport, &task_rxb, &task_txb) => SharedInstanceError::PacketUnavailable,
                error = control_watchdog(&credentials) => error,
            };
            drop(stream);
            task_online.store(false, Ordering::SeqCst);
            let mut last_failure = failure;
            let mut delay = 1;
            loop {
                let state = match last_failure {
                    SharedInstanceError::AuthenticationRejected => {
                        SharedInstanceState::AuthenticationRejected
                    }
                    SharedInstanceError::ControlUnavailable
                    | SharedInstanceError::UnsupportedControl => {
                        SharedInstanceState::ControlUnavailable
                    }
                    _ => SharedInstanceState::Reconnecting,
                };
                status_tx.send_replace(state);
                // No stale outbound packets may cross an owner restart. Higher
                // protocol layers own retry; keep bounded backpressure while offline.
                let wait = tokio::time::sleep(Duration::from_secs(delay));
                tokio::pin!(wait);
                loop {
                    tokio::select! {
                        biased;
                        _ = shutdown.wait() => return finish_client(&task_online, &status_tx),
                        _ = &mut wait => break,
                        data = rx.recv() => if data.is_none() { return finish_client(&task_online, &status_tx); },
                    }
                }
                while rx.try_recv().is_ok() {}
                let result = tokio::select! {
                    biased;
                    _ = shutdown.wait() => return finish_client(&task_online, &status_tx),
                    result = credentials.connect() => result,
                };
                match result {
                    Ok(connected) => {
                        while rx.try_recv().is_ok() {}
                        stream = connected;
                        task_online.store(true, Ordering::SeqCst);
                        status_tx.send_replace(SharedInstanceState::Ready);
                        break;
                    }
                    Err(error) => {
                        last_failure = error;
                        delay = (delay * 2).min(30);
                    }
                }
            }
        }
        finish_client(&task_online, &status_tx);
    });
    Ok((
        InterfaceHandle {
            id,
            parent_id: None,
            name: "Authenticated shared instance".to_string(),
            mode: InterfaceMode::Full,
            direction: InterfaceDirection {
                inbound: true,
                outbound: true,
                forward: false,
                repeat: false,
            },
            bitrate: 1_000_000_000,
            mtu: rns_interface::traits::optimise_mtu(1_000_000_000).unwrap_or(262_144),
            online,
            rxb: Some(rxb),
            txb: Some(txb),
            inspection: None,
            tx,
            read_task,
        },
        status,
    ))
}

fn finish_client(online: &AtomicBool, status: &watch::Sender<SharedInstanceState>) {
    online.store(false, Ordering::SeqCst);
    status.send_replace(SharedInstanceState::Stopped);
}

async fn control_watchdog(credentials: &SharedInstanceCredentials) -> SharedInstanceError {
    loop {
        tokio::time::sleep(CONTROL_CHECK_INTERVAL).await;
        match tokio::time::timeout(ADMISSION_TIMEOUT, credentials.check_control()).await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => return error,
            Err(_) => return SharedInstanceError::ControlUnavailable,
        }
    }
}

async fn packet_loop(
    stream: &mut PacketStream,
    outbound: &mut mpsc::Receiver<Bytes>,
    id: u64,
    transport: &mpsc::Sender<TransportMessage>,
    rxb: &AtomicU64,
    txb: &AtomicU64,
) -> std::io::Result<()> {
    let (mut reader, mut writer) = tokio::io::split(stream);
    let mut buf = [0; 8192];
    let mut deframer = HdlcDeframer::new();
    loop {
        tokio::select! {
            read = reader.read(&mut buf) => {
                let size = read?;
                if size == 0 { return Ok(()); }
                rxb.fetch_add(size as u64, Ordering::Relaxed);
                for frame in deframer.feed(&buf[..size]) {
                    if transport.send(TransportMessage::Inbound(InboundPacket {
                        raw: Bytes::from(frame), interface_id: id, rssi: None, snr: None, q: None,
                    })).await.is_err() { return Ok(()); }
                }
            }
            data = outbound.recv() => {
                let Some(data) = data else { return Ok(()); };
                let framed = hdlc::frame(&data);
                writer.write_all(&framed).await?;
                txb.fetch_add(framed.len() as u64, Ordering::Relaxed);
            }
        }
    }
}

pub(crate) enum BoundControlListener {
    Tcp(tokio::net::TcpListener),
    #[cfg(unix)]
    Unix(tokio::net::UnixListener, String),
}

impl BoundControlListener {
    pub(crate) async fn bind(
        config: &ReticulumConfig,
        socket_base: &Path,
    ) -> Result<Self, SharedInstanceError> {
        SharedInstanceEndpoint::from_config(config).validate()?;
        match config.shared_rpc_endpoint(socket_base) {
            SharedInstanceRpcEndpoint::Tcp(port) => {
                tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, port))
                    .await
                    .map(Self::Tcp)
                    .map_err(|_| SharedInstanceError::ControlBindFailed)
            }
            SharedInstanceRpcEndpoint::Unix(path) => {
                #[cfg(unix)]
                {
                    crate::rpc_server::bind_unix_rpc_listener(&path)
                        .map(|listener| Self::Unix(listener, path))
                        .map_err(|_| SharedInstanceError::ControlBindFailed)
                }
                #[cfg(not(unix))]
                {
                    let _ = path;
                    Err(SharedInstanceError::UnsupportedCarrier)
                }
            }
        }
    }

    pub(crate) async fn run(
        self,
        key: Vec<u8>,
        transport: mpsc::Sender<TransportMessage>,
        shutdown: ShutdownSignal,
    ) {
        let result = match self {
            Self::Tcp(listener) => {
                crate::rpc_server::run_rpc_server_with_listener(listener, key, transport, shutdown)
                    .await
            }
            #[cfg(unix)]
            Self::Unix(listener, path) => {
                crate::rpc_server::run_unix_rpc_server_with_listener(
                    listener, path, key, transport, shutdown,
                )
                .await
            }
        };
        if result.is_err() {
            tracing::warn!("owned shared control listener stopped");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reticulum::{self, InitOptions, InstanceMode, ReticulumHandle};
    use rns_transport::messages::{TransportQuery, TransportQueryResponse};

    struct TestConfig(std::path::PathBuf);
    impl TestConfig {
        fn new(packet: u16, control: u16, key: u8) -> Self {
            let dir = std::env::temp_dir().join(format!(
                "rns-strict-sharing-{}-{}",
                std::process::id(),
                hex::encode(rns_crypto::random::random_bytes(12))
            ));
            std::fs::create_dir(&dir).unwrap();
            std::fs::write(dir.join("config"), format!(
                "[reticulum]\nshare_instance = Yes\nshared_instance_type = tcp\nshared_instance_port = {packet}\ninstance_control_port = {control}\nrpc_key = {}\n[interfaces]\n",
                hex::encode([key; 32]))).unwrap();
            Self(dir)
        }
        async fn start(
            &self,
            policy: InstancePolicy,
        ) -> Result<ReticulumHandle, InstanceStartupError> {
            reticulum::init_with_policy(
                self.0.to_str(),
                None,
                ShutdownSignal::new(),
                Arc::new(AtomicBool::new(true)),
                InitOptions::default(),
                Default::default(),
                policy,
            )
            .await
        }
    }
    impl Drop for TestConfig {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    fn ports() -> (u16, u16) {
        let a = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let b = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        (
            a.local_addr().unwrap().port(),
            b.local_addr().unwrap().port(),
        )
    }
    fn credentials(packet_port: u16, control_port: u16, key: u8) -> SharedInstanceCredentials {
        SharedInstanceCredentials::new(
            SharedInstanceEndpoint::Tcp {
                packet_port,
                control_port,
            },
            vec![key; 32],
        )
        .unwrap()
    }
    async fn await_state(handle: &ReticulumHandle, expected: SharedInstanceState) {
        tokio::time::timeout(Duration::from_secs(12), async {
            while handle.shared_instance_state() != Some(expected) {
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await
        .unwrap();
    }

    #[test]
    fn strict_endpoint_and_secret_validation() {
        assert_eq!(
            SharedInstanceEndpoint::Tcp {
                packet_port: 0,
                control_port: 1
            }
            .validate(),
            Err(SharedInstanceError::InvalidEndpoint)
        );
        assert_eq!(
            SharedInstanceEndpoint::Tcp {
                packet_port: 1,
                control_port: 1
            }
            .validate(),
            Err(SharedInstanceError::InvalidEndpoint)
        );
        assert_eq!(
            SharedInstanceEndpoint::Unix {
                instance_name: "../other".into()
            }
            .validate(),
            Err(SharedInstanceError::InvalidEndpoint)
        );
        let key = SharedInstanceCredentials::new(
            SharedInstanceEndpoint::Tcp {
                packet_port: 1,
                control_port: 2,
            },
            vec![0x8a; 17],
        )
        .unwrap();
        assert!(format!("{key:?}").contains("[redacted]"));
        assert!(!format!("{key:?}").contains("138"));
    }

    #[tokio::test]
    async fn strict_owner_packet_conflict_releases_control_and_never_joins() {
        let packet = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let (_, control) = ports();
        let config = TestConfig::new(packet.local_addr().unwrap().port(), control, 1);
        assert!(matches!(
            config.start(InstancePolicy::SharedOwner).await,
            Err(InstanceStartupError::Shared(
                SharedInstanceError::PacketBindFailed
            ))
        ));
        let _control = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, control))
            .await
            .unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(50), packet.accept())
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn strict_owner_control_conflict_does_not_open_packet_listener() {
        let control = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let (packet, _) = ports();
        let config = TestConfig::new(packet, control.local_addr().unwrap().port(), 1);
        assert!(matches!(
            config.start(InstancePolicy::SharedOwner).await,
            Err(InstanceStartupError::Shared(
                SharedInstanceError::ControlBindFailed
            ))
        ));
        let _packet = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, packet))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn strict_auth_failure_never_returns_client_or_starts_interfaces() {
        let (packet, control) = ports();
        let owner_config = TestConfig::new(packet, control, 1);
        let owner = owner_config
            .start(InstancePolicy::SharedOwner)
            .await
            .unwrap();
        let client_config = TestConfig::new(packet, control, 2);
        let error = client_config
            .start(InstancePolicy::SharedClient(credentials(
                packet, control, 2,
            )))
            .await;
        assert!(matches!(
            error,
            Err(InstanceStartupError::Shared(
                SharedInstanceError::AuthenticationRejected
            ))
        ));
        // An ordinary managed node remains usable after rejecting the shared key.
        let standalone = client_config
            .start(InstancePolicy::Standalone)
            .await
            .unwrap();
        assert_eq!(standalone.instance_mode, InstanceMode::Standalone);
        standalone.shutdown_and_wait().await;
        owner.shutdown_and_wait().await;
    }

    #[tokio::test]
    async fn strict_client_reauthenticates_restart_and_rejects_runtime_spawns() {
        let (packet, control) = ports();
        let owner_config = TestConfig::new(packet, control, 1);
        let owner = owner_config
            .start(InstancePolicy::SharedOwner)
            .await
            .unwrap();
        let client_config = TestConfig::new(packet, control, 2);
        let client = client_config
            .start(InstancePolicy::SharedClient(credentials(
                packet, control, 1,
            )))
            .await
            .unwrap();
        assert_eq!(client.instance_mode, InstanceMode::Client);
        assert_eq!(
            client.shared_instance_state(),
            Some(SharedInstanceState::Ready)
        );
        assert!(matches!(
            client
                .query_control_result(TransportQuery::GetInterfaceStats)
                .await,
            Ok(TransportQueryResponse::InterfaceStats(_))
        ));
        let tcp_error = reticulum::spawn_tcp_client_runtime(&client, "forbidden", "127.0.0.1", 9)
            .await
            .unwrap_err();
        assert!(tcp_error.contains("owned by the existing shared instance"));
        let auto_error = reticulum::spawn_auto_interface_runtime(
            &client,
            "forbidden",
            "reticulum",
            29716,
            42671,
        )
        .await
        .unwrap_err();
        assert!(auto_error.contains("owned by the existing shared instance"));
        owner.shutdown_and_wait().await;
        let wrong_config = TestConfig::new(packet, control, 3);
        let wrong_owner = wrong_config
            .start(InstancePolicy::SharedOwner)
            .await
            .unwrap();
        await_state(&client, SharedInstanceState::AuthenticationRejected).await;
        wrong_owner.shutdown_and_wait().await;
        let restored_owner = owner_config
            .start(InstancePolicy::SharedOwner)
            .await
            .unwrap();
        await_state(&client, SharedInstanceState::Ready).await;
        client.shutdown_and_wait().await;
        restored_owner.shutdown_and_wait().await;
        // Both owner listeners are gone when shutdown returns.
        let _packet = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, packet))
            .await
            .unwrap();
        let _control = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, control))
            .await
            .unwrap();
    }

    fn read_reports_closed_connection(result: std::io::Result<usize>) -> bool {
        match result {
            Ok(0) => true,
            // Windows can report abortive peer closure as WSAECONNRESET rather
            // than EOF. Both prove closure; data, timeouts and other errors do not.
            Err(error) => error.kind() == std::io::ErrorKind::ConnectionReset,
            Ok(_) => false,
        }
    }

    async fn assert_connection_closed(stream: &mut tokio::net::TcpStream) {
        let result = tokio::time::timeout(Duration::from_secs(2), stream.read(&mut [0]))
            .await
            .expect("unauthenticated connection must close promptly");
        assert!(read_reports_closed_connection(result));
    }

    #[test]
    fn connection_closure_assertion_rejects_data_and_unrelated_errors() {
        assert!(read_reports_closed_connection(Ok(0)));
        assert!(read_reports_closed_connection(Err(
            std::io::ErrorKind::ConnectionReset.into()
        )));
        assert!(!read_reports_closed_connection(Ok(1)));
        for kind in [
            std::io::ErrorKind::TimedOut,
            std::io::ErrorKind::WouldBlock,
            std::io::ErrorKind::PermissionDenied,
        ] {
            assert!(!read_reports_closed_connection(Err(kind.into())));
        }
    }

    #[tokio::test]
    async fn missing_or_silent_rpc_drops_unauthenticated_packet_connection() {
        let packet = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let (_, control_port) = ports();
        let credentials = credentials(packet.local_addr().unwrap().port(), control_port, 1);
        assert_eq!(
            credentials.test().await,
            Err(SharedInstanceError::ControlUnavailable)
        );
        let (mut stream, _) = packet.accept().await.unwrap();
        assert_connection_closed(&mut stream).await;

        let control = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, control_port))
            .await
            .unwrap();
        let test = tokio::spawn(async move { credentials.test().await });
        let (mut stream, _) = packet.accept().await.unwrap();
        let (mut silent_control, _) = control.accept().await.unwrap();
        assert!(matches!(
            test.await.unwrap(),
            Err(SharedInstanceError::TimedOut | SharedInstanceError::ControlUnavailable)
        ));
        assert_connection_closed(&mut stream).await;
        assert_connection_closed(&mut silent_control).await;
    }

    #[tokio::test]
    async fn cancelled_admission_closes_both_connections() {
        let packet = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let control = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let credentials = credentials(
            packet.local_addr().unwrap().port(),
            control.local_addr().unwrap().port(),
            1,
        );
        let shutdown = ShutdownSignal::new();
        let task_shutdown = shutdown.clone();
        let (tx, _rx) = mpsc::channel(8);
        let task = tokio::spawn(async move {
            spawn_authenticated_client(credentials, 1, tx, task_shutdown).await
        });
        let (mut packet, _) = packet.accept().await.unwrap();
        let (mut control, _) = control.accept().await.unwrap();
        shutdown.trigger();
        assert!(matches!(
            task.await.unwrap(),
            Err(SharedInstanceError::Cancelled)
        ));
        assert_connection_closed(&mut packet).await;
        assert_connection_closed(&mut control).await;
    }

    #[tokio::test]
    async fn explicit_owner_selectors_are_in_memory_and_reusable_after_shutdown() {
        let (packet_port, control_port) = ports();
        let config = TestConfig::new(1, 2, 1);
        let original = std::fs::read(config.0.join("config")).unwrap();
        let endpoint = SharedInstanceEndpoint::Tcp {
            packet_port,
            control_port,
        };
        let owner = config
            .start(InstancePolicy::SharedOwnerAt(endpoint.clone()))
            .await
            .unwrap();
        SharedInstanceCredentials::new(endpoint, vec![1; 32])
            .unwrap()
            .test()
            .await
            .unwrap();
        assert_eq!(std::fs::read(config.0.join("config")).unwrap(), original);
        owner.shutdown_and_wait().await;
        let _packet = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, packet_port))
            .await
            .unwrap();
        let _control = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, control_port))
            .await
            .unwrap();
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[tokio::test]
    async fn abstract_unix_owner_and_authenticated_client_roundtrip() {
        let config = TestConfig::new(1, 2, 1);
        let endpoint = SharedInstanceEndpoint::Unix {
            instance_name: format!(
                "strict-test-{}",
                hex::encode(rns_crypto::random::random_bytes(12))
            ),
        };
        let owner = config
            .start(InstancePolicy::SharedOwnerAt(endpoint.clone()))
            .await
            .unwrap();
        let client_config = TestConfig::new(3, 4, 9);
        let credentials = SharedInstanceCredentials::new(endpoint, vec![1; 32]).unwrap();
        credentials.test().await.unwrap();
        let client = client_config
            .start(InstancePolicy::SharedClient(credentials))
            .await
            .unwrap();
        assert_eq!(
            client.shared_instance_state(),
            Some(SharedInstanceState::Ready)
        );
        assert!(matches!(
            client
                .query_control_result(TransportQuery::GetInterfaceStats)
                .await,
            Ok(TransportQueryResponse::InterfaceStats(_))
        ));
        client.shutdown_and_wait().await;
        owner.shutdown_and_wait().await;
    }

    #[tokio::test]
    async fn occupied_auto_port_is_reported_without_breaking_tcp() {
        let auto = std::net::UdpSocket::bind("[::]:0").unwrap();
        let data_port = auto.local_addr().unwrap().port();
        let (tcp_port, _) = ports();
        let config = TestConfig::new(1, 2, 1);
        std::fs::write(config.0.join("config"), format!(
            "[reticulum]\nshare_instance = No\n[interfaces]\n[[LAN]]\ntype = AutoInterface\nenabled = Yes\ndata_port = {data_port}\n[[TCP]]\ntype = TCPServerInterface\nenabled = Yes\nlisten_ip = 127.0.0.1\nlisten_port = {tcp_port}\n"
        )).unwrap();
        let runtime = config.start(InstancePolicy::Standalone).await.unwrap();
        assert_eq!(runtime.startup_interface_failures().len(), 1);
        assert_eq!(runtime.startup_interface_failures()[0].0, "LAN");
        assert!(
            runtime.startup_interface_failures()[0]
                .1
                .contains("socket bind")
        );
        let _tcp = tokio::net::TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, tcp_port))
            .await
            .unwrap();
        assert_eq!(auto.local_addr().unwrap().port(), data_port);
        runtime.shutdown_and_wait().await;
    }
}
