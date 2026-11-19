//! Remote command sessions over encrypted Reticulum Links and Channels.
//! Listeners execute processes with the host process's account and filesystem
//! access; they do not create a sandbox. Interactive PTYs require Unix; fully
//! piped stdin/stdout/stderr do not require a PTY.

use std::collections::{HashMap, HashSet, VecDeque};
#[cfg(unix)]
use std::fs::File;
#[cfg(unix)]
use std::io;
#[cfg(unix)]
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::path::PathBuf;
use std::process::Stdio;
use std::time::{Duration, Instant};

use bytes::Bytes;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::process::Command;
use tokio::sync::{mpsc, oneshot};

use rns_crypto::ed25519::Ed25519PublicKey;
use rns_identity::destination::{DestType, Destination, Direction};
use rns_identity::identity::Identity;
use rns_link::link::{CloseReason, Link, LinkAction};
use rns_protocol::buffer::{MAX_CHUNK_LEN, StreamWriter};
use rns_protocol::channel::{ChannelError, LinkChannel};
use rns_protocol::channel_message::MessageBase;
use rns_protocol::rnsh::{
    CommandExitedMessage, ErrorMessage, ExecuteCommandMessage, MESSAGE_TYPES, NoopMessage,
    PROTOCOL_VERSION, RnshMessage, RnshStreamDataMessage, STREAM_ID_STDERR, STREAM_ID_STDIN,
    STREAM_ID_STDOUT, VersionInfoMessage, WindowSizeMessage,
};
use rns_transport::link_messages::DestinationEvent;
use rns_transport::messages::{
    AnnounceRpcEntry, InterfaceId, LinkEndpointLifecycleEvent, LinkEndpointRole, OutboundRequest,
    TransportMessage, TransportQuery, TransportQueryResponse,
};

use crate::lifecycle::ShutdownSignal;
use crate::link_manager::{
    ChannelSendError, LinkChannelMessage, LinkManager, LinkManagerCommand, register_destination,
};

pub const RNSH_APP_NAME: &str = "rnsh";
pub const RNSH_SOFTWARE_VERSION: &str = "0.3.0";
const CHANNEL_SEND_RETRY: Duration = Duration::from_millis(20);
const SIGTERM_NUM: i32 = 15;
const SIGKILL_NUM: i32 = 9;
const SIGHUP_NUM: i32 = 1;
/// `StreamDataMessage.HEADER_LEN` in RNS.Buffer.
const STREAM_HEADER_LEN: usize = 2;
/// Process output read size (`tty_read` reads 4096 bytes in rnsh/process.py).
const PROCESS_READ_LEN: usize = 4096;
/// Session prune delay floor: `max(rtt*3, PROCESS_PIPE_TIME+5)` in rnsh/session.py.
const LISTENER_PRUNE_DELAY: Duration = Duration::from_secs(6);
const LISTENER_PRUNE_RTT_FACTOR: f64 = 3.0;
/// Post-CommandExited check floor: `max(rtt*5, 10)` in rnsh/session.py.
const COMMAND_EXITED_TIMEOUT: Duration = Duration::from_secs(10);
const COMMAND_EXITED_RTT_FACTOR: f64 = 5.0;
/// Grace between "Shutting down" and link teardown in rnsh/listener.py.
const LISTENER_SHUTDOWN_GRACE: Duration = Duration::from_secs(1);
/// Version reply floor: `max(rtt*20, 5)` in rnsh/initiator.py.
const CLIENT_VERSION_TIMEOUT_MIN: Duration = Duration::from_secs(5);
const CLIENT_VERSION_TIMEOUT_RTT_FACTOR: f64 = 20.0;
/// Window-size updates are rate limited to one per `rtt*25` in rnsh/initiator.py.
const CLIENT_WINCH_RTT_FACTOR: f64 = 25.0;
/// Hold piped-stdin EOF until the remote exits or this long has passed. A
/// Python listener kills the child 50 ms after EOF and can then lose its exit
/// status (rnsh/process.py ECHILD race), so a prompt EOF can hang the session.
const CLIENT_PRE_EOF_DRAIN: Duration = Duration::from_secs(3);

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum RnshError {
    #[error("link request admission failed: {0}")]
    RequestDispatch(#[from] rns_transport::link_messages::LinkRequestDispatchError),
    #[error("link request stamp failed: {0}")]
    StampFailure(#[from] rns_link::stamp::LinkStampError),
    #[error("transport channel unavailable")]
    TransportUnavailable,
    #[error("timed out waiting for {0}")]
    Timeout(&'static str),
    #[error("path not found")]
    PathTimeout,
    #[error("destination identity has not been announced")]
    NoIdentity,
    #[error("invalid destination hash")]
    InvalidDestination,
    #[error("link proof validation failed: {0}")]
    ProofInvalid(String),
    #[error("link handshake failed: {0}")]
    HandshakeFailed(String),
    #[error("link crypto error: {0}")]
    LinkCrypto(String),
    #[error("channel error: {0}")]
    Channel(String),
    #[error("remote error: {0}")]
    Remote(String),
    #[error("local process error: {0}")]
    Process(String),
    #[error("local identity has no signing key")]
    NoSigningKey,
    /// The listener answered the version exchange with an error message.
    #[error("remote error: {0}")]
    Denied(String),
    #[error("Protocol error")]
    ProtocolError,
    #[error("session terminated locally")]
    Terminated,
    /// The established link closed or timed out.
    #[error("link closed: {0}")]
    LinkClosed(String),
    /// A local failure after the command was started.
    #[error("{0}")]
    ClientException(String),
}

/// Client setup progress, reported through `RnshClientConfig::progress_tx`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RnshClientProgress {
    /// No path was known; a path request was sent.
    RequestingPath,
    /// A link request was sent.
    EstablishingLink,
    /// The link proof was validated.
    LinkEstablished,
}

impl From<ChannelError> for RnshError {
    fn from(value: ChannelError) -> Self {
        Self::Channel(value.to_string())
    }
}

/// Client command, input/output channels and terminal options. `command` is
/// an argument vector interpreted under the listener's command policy. `no_id`
/// suppresses LinkIdentify, but this implementation still requires a signing
/// identity locally.
///
/// When `stdin_rx` is supplied, it replaces `stdin_data`; an empty chunk or
/// channel close means EOF. Without it, `stdin_data` is sent only with
/// `pipe_stdin`. Drain supplied output channels: they apply backpressure, and
/// all received stdout/stderr bytes are also retained in the returned outcome.
/// `timeout` bounds the path wait and the link establishment wait, each in full.
pub struct RnshClientConfig {
    pub identity: Identity,
    pub destination_hash: [u8; 16],
    pub command: Vec<String>,
    pub no_id: bool,
    pub timeout: Duration,
    pub stdin_data: Vec<u8>,
    pub stdin_rx: Option<mpsc::Receiver<Vec<u8>>>,
    pub stdout_tx: Option<mpsc::Sender<Vec<u8>>>,
    pub stderr_tx: Option<mpsc::Sender<Vec<u8>>>,
    pub window_rx: Option<mpsc::Receiver<RnshWindowSize>>,
    pub pipe_stdin: bool,
    pub pipe_stdout: bool,
    pub pipe_stderr: bool,
    pub term: Option<String>,
    pub rows: Option<u32>,
    pub cols: Option<u32>,
    pub hpix: Option<u32>,
    pub vpix: Option<u32>,
    /// Terminal attributes in `termios.tcgetattr` list form, sent in ExecuteCommand.
    pub tcflags: Option<rmpv::Value>,
    /// Resolving (or dropping the sender) ends the session and tears the link down.
    pub terminate_rx: Option<oneshot::Receiver<()>>,
    pub progress_tx: Option<mpsc::UnboundedSender<RnshClientProgress>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RnshWindowSize {
    pub rows: Option<u32>,
    pub cols: Option<u32>,
    pub hpix: Option<u32>,
    pub vpix: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RnshClientOutcome {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub return_code: i64,
}

/// Command and admission policy for a remote shell listener. With `allow_all`
/// false, a session must identify with a hash in `allowed` or in an identity
/// file before commands are accepted. Identity files are reread for every new
/// link and replace the previous file entries; a valid line is exactly 32 hex
/// characters. Unreadable files and invalid lines are ignored. `allow_all` also
/// admits unidentified sessions.
///
/// `command` contains the executable and arguments; no implicit shell is used.
/// `allow_remote_command` permits a client-supplied argument vector to replace
/// it. With `remote_command_as_args`, that vector is appended to the configured
/// command instead, and still requires `allow_remote_command`.
///
/// `announce_period` is in seconds. `None` disables initial/periodic announces;
/// `Some(0)` sends only the initial one, and positive values enable an interval.
/// Path-request announce responses are independent of that setting.
pub struct RnshListenerConfig {
    pub identity: Identity,
    pub command: Vec<String>,
    pub allow_all: bool,
    pub allowed: Vec<[u8; 16]>,
    pub allowed_identity_files: Vec<PathBuf>,
    pub allow_remote_command: bool,
    pub remote_command_as_args: bool,
    pub announce_period: Option<u64>,
}

/// Run a remote command listener until its event streams close or an error
/// occurs. Use `run_rnsh_listener_with_shutdown` for an explicit stop signal.
/// Authorized commands run with this process's privileges.
pub async fn run_rnsh_listener(
    transport_tx: mpsc::Sender<TransportMessage>,
    cfg: RnshListenerConfig,
) -> Result<(), RnshError> {
    run_rnsh_listener_inner(transport_tx, cfg, None).await
}

/// Run a listener that also observes `shutdown` in its event loop. On that
/// path it requests manager shutdown and joins the manager, then drops sessions
/// to signal child cleanup. It does not wait for every child cleanup task or
/// guarantee a shutdown deadline; an awaited handler can delay signal handling.
pub async fn run_rnsh_listener_with_shutdown(
    transport_tx: mpsc::Sender<TransportMessage>,
    cfg: RnshListenerConfig,
    shutdown: ShutdownSignal,
) -> Result<(), RnshError> {
    run_rnsh_listener_inner(transport_tx, cfg, Some(shutdown)).await
}

async fn run_rnsh_listener_inner(
    transport_tx: mpsc::Sender<TransportMessage>,
    cfg: RnshListenerConfig,
    shutdown: Option<ShutdownSignal>,
) -> Result<(), RnshError> {
    let signing_key = cfg
        .identity
        .get_signing_key()
        .ok_or(RnshError::NoSigningKey)?;
    let destination = Destination::new(
        Some(&cfg.identity),
        Direction::In,
        DestType::Single,
        RNSH_APP_NAME,
    )
    .map_err(|e| RnshError::HandshakeFailed(format!("destination: {e:?}")))?;
    let destination_hash = destination.hash;
    let event_rx = register_destination(&transport_tx, destination_hash, RNSH_APP_NAME);

    let mut link_mgr = LinkManager::with_destination(
        transport_tx.clone(),
        event_rx,
        &cfg.identity,
        RNSH_APP_NAME,
        Some(signing_key),
    );
    for msg_type in MESSAGE_TYPES {
        link_mgr.register_channel_message_type(msg_type)?;
    }

    let (command_tx, command_rx) = mpsc::channel::<LinkManagerCommand>(256);
    let (channel_tx, mut channel_rx) = mpsc::channel::<LinkChannelMessage>(256);
    let (established_tx, mut established_rx) = mpsc::channel::<[u8; 16]>(64);
    let (identified_tx, mut identified_rx) = mpsc::channel::<([u8; 16], [u8; 16])>(64);
    let (closed_tx, mut closed_rx) = mpsc::channel::<[u8; 16]>(64);
    link_mgr.set_channel_message_channel(channel_tx);
    link_mgr.set_link_established_channel(established_tx);
    link_mgr.set_link_identified_channel(identified_tx);
    link_mgr.set_link_closed_channel(closed_tx);

    let manager_task = tokio::spawn(async move {
        link_mgr.run_with_commands(command_rx).await;
    });

    if cfg.announce_period.is_some() {
        send_announce(&command_tx).await?;
    }
    let mut announce_interval = cfg
        .announce_period
        .filter(|period| *period > 0)
        .map(|period| {
            let period = Duration::from_secs(period);
            tokio::time::interval_at(tokio::time::Instant::now() + period, period)
        });

    let (exited_tx, mut exited_rx) = mpsc::unbounded_channel::<[u8; 16]>();
    let mut sessions: HashMap<[u8; 16], ListenerSession> = HashMap::new();
    let mut file_allowed = read_allowed_identity_files(&cfg.allowed_identity_files);
    if !cfg.allow_all && cfg.allowed.is_empty() && file_allowed.is_empty() {
        tracing::warn!(
            "Warning: No allowed identities configured, rnsh will not accept any connections!"
        );
    }

    loop {
        tokio::select! {
            maybe_link = established_rx.recv() => {
                let Some(link_id) = maybe_link else { break };
                on_link_established(&cfg, &mut sessions, &mut file_allowed, link_id);
            }
            maybe_identified = identified_rx.recv() => {
                let Some((link_id, identity_hash)) = maybe_identified else { break };
                on_link_identified(&command_tx, &cfg, &mut sessions, &file_allowed, link_id, identity_hash).await;
            }
            maybe_closed = closed_rx.recv() => {
                let Some(link_id) = maybe_closed else { break };
                sessions.remove(&link_id);
            }
            maybe_msg = channel_rx.recv() => {
                let Some(msg) = maybe_msg else { break };
                apply_queued_link_events(
                    &command_tx,
                    &cfg,
                    &mut sessions,
                    &mut file_allowed,
                    &mut established_rx,
                    &mut identified_rx,
                )
                .await;
                let link_id = msg.link_id;
                match handle_listener_channel_message(
                    &command_tx,
                    &cfg,
                    &mut sessions,
                    msg,
                    &exited_tx,
                ).await {
                    Ok(()) => {}
                    Err(RnshError::TransportUnavailable) => return Err(RnshError::TransportUnavailable),
                    Err(error) => {
                        tracing::warn!(link_id = %hex::encode(link_id), %error, "rnsh session message handling failed");
                    }
                }
            }
            Some(link_id) = exited_rx.recv() => {
                if let Some(session) = sessions.get_mut(&link_id)
                    && session.state == ListenerState::Running
                {
                    terminate_session(
                        &command_tx,
                        link_id,
                        session,
                        Some("Protocol timeout error: CommandExitedMessage"),
                    )
                    .await;
                }
            }
            _ = async {
                if let Some(interval) = announce_interval.as_mut() {
                    interval.tick().await;
                } else {
                    std::future::pending::<()>().await;
                }
            } => {
                send_announce(&command_tx).await?;
            }
            _ = async {
                if let Some(shutdown) = shutdown.as_ref() {
                    shutdown.wait().await;
                } else {
                    std::future::pending::<()>().await;
                }
            } => {
                rns_transport::notice!("Shutting down");
                for (link_id, session) in sessions.iter_mut() {
                    send_manager_message_once(
                        &command_tx,
                        *link_id,
                        ErrorMessage::new(Some("Shutting down".into()), true, None),
                    )
                    .await;
                    session.close();
                }
                tokio::time::sleep(LISTENER_SHUTDOWN_GRACE).await;
                for link_id in sessions.keys() {
                    let _ = command_tx
                        .send(LinkManagerCommand::CloseLink {
                            link_id: *link_id,
                            reason: CloseReason::DestinationClosed,
                            send_teardown: true,
                        })
                        .await;
                }
                break;
            }
        }
    }

    let _ = command_tx.send(LinkManagerCommand::Shutdown).await;
    let _ = manager_task.await;
    Ok(())
}

fn on_link_established(
    cfg: &RnshListenerConfig,
    sessions: &mut HashMap<[u8; 16], ListenerSession>,
    file_allowed: &mut HashSet<[u8; 16]>,
    link_id: [u8; 16],
) {
    *file_allowed = read_allowed_identity_files(&cfg.allowed_identity_files);
    // or_insert (not insert) so a rare identification processed ahead
    // of this establishment event is never clobbered.
    sessions
        .entry(link_id)
        .or_insert_with(|| ListenerSession::new(cfg.allow_all));
}

async fn on_link_identified(
    command_tx: &mpsc::Sender<LinkManagerCommand>,
    cfg: &RnshListenerConfig,
    sessions: &mut HashMap<[u8; 16], ListenerSession>,
    file_allowed: &HashSet<[u8; 16]>,
    link_id: [u8; 16],
    identity_hash: [u8; 16],
) {
    // Identification may race ahead of the establishment event.
    let session = sessions
        .entry(link_id)
        .or_insert_with(|| ListenerSession::new(cfg.allow_all));
    if session.state == ListenerState::Closed {
        return;
    }
    if !matches!(
        session.state,
        ListenerState::WaitIdent | ListenerState::WaitVersion
    ) {
        terminate_session(
            command_tx,
            link_id,
            session,
            Some("Protocol error (LSSTATE_WAIT_IDENT)"),
        )
        .await;
    } else if cfg.allow_all
        || cfg.allowed.contains(&identity_hash)
        || file_allowed.contains(&identity_hash)
    {
        session.authorized = true;
        session.remote_identity_hash = Some(identity_hash);
        session.state = ListenerState::WaitVersion;
    } else {
        session.authorized = false;
        terminate_session(command_tx, link_id, session, Some("Identity not allowed")).await;
        tracing::info!(identity = %hex::encode(identity_hash), "rnsh identity not allowed");
    }
}

/// The link manager queues a link's establishment and identification before its
/// later channel messages; upstream handles all three in arrival order on one
/// thread (`Link.py` LINKIDENTIFY, `Channel._run_callbacks`). Apply them before a
/// channel message, or a VersionInfo sent right behind LINKIDENTIFY overtakes it.
async fn apply_queued_link_events(
    command_tx: &mpsc::Sender<LinkManagerCommand>,
    cfg: &RnshListenerConfig,
    sessions: &mut HashMap<[u8; 16], ListenerSession>,
    file_allowed: &mut HashSet<[u8; 16]>,
    established_rx: &mut mpsc::Receiver<[u8; 16]>,
    identified_rx: &mut mpsc::Receiver<([u8; 16], [u8; 16])>,
) {
    while let Ok(link_id) = established_rx.try_recv() {
        on_link_established(cfg, sessions, file_allowed, link_id);
    }
    while let Ok((link_id, identity_hash)) = identified_rx.try_recv() {
        on_link_identified(
            command_tx,
            cfg,
            sessions,
            file_allowed,
            link_id,
            identity_hash,
        )
        .await;
    }
}

/// End one listener session as `ListenerSession.terminate` does: report a fatal
/// error if given, stop the process, and tear the link down after the prune delay.
async fn terminate_session(
    command_tx: &mpsc::Sender<LinkManagerCommand>,
    link_id: [u8; 16],
    session: &mut ListenerSession,
    error: Option<&str>,
) {
    tracing::debug!(link_id = %hex::encode(link_id), error, "terminating rnsh session");
    if let Some(error) = error {
        send_manager_message_once(
            command_tx,
            link_id,
            ErrorMessage::new(Some(error.to_string()), true, None),
        )
        .await;
    }
    session.close();
    let delay = rtt_scaled(
        command_tx,
        link_id,
        LISTENER_PRUNE_RTT_FACTOR,
        LISTENER_PRUNE_DELAY,
    )
    .await;
    close_link_after(command_tx.clone(), link_id, delay);
}

/// `max(link.rtt * factor, floor)`, the rnsh/session.py timer form.
async fn rtt_scaled(
    command_tx: &mpsc::Sender<LinkManagerCommand>,
    link_id: [u8; 16],
    factor: f64,
    floor: Duration,
) -> Duration {
    let (result_tx, result_rx) = oneshot::channel();
    if command_tx
        .send(LinkManagerCommand::LinkRtt { link_id, result_tx })
        .await
        .is_err()
    {
        return floor;
    }
    result_rx
        .await
        .ok()
        .flatten()
        .and_then(|rtt| Duration::try_from_secs_f64(rtt * factor).ok())
        .map_or(floor, |scaled| scaled.max(floor))
}

/// Open a Link, negotiate rnsh and execute one remote command session. Return
/// captured stdout/stderr and the remote exit code; a nonzero exit code is still
/// an `Ok` outcome. Optional output channels receive the same bytes while the
/// received output is retained in memory.
///
/// As in upstream rnsh, `timeout` bounds the path wait and the link
/// establishment wait separately; the version exchange waits `max(rtt*20, 5 s)`
/// and the running session has no deadline. Once the link is established, every
/// exit path tears it down. An error or cancellation is not an acknowledgment
/// that the remote process has stopped.
pub async fn rnsh_client_execute(
    transport_tx: mpsc::Sender<TransportMessage>,
    mut cfg: RnshClientConfig,
) -> Result<RnshClientOutcome, RnshError> {
    let destination_hash = cfg.destination_hash;
    let mut terminate_rx = cfg.terminate_rx.take();
    let progress_tx = cfg.progress_tx.take();
    let progress = |step: RnshClientProgress| {
        if let Some(tx) = progress_tx.as_ref() {
            let _ = tx.send(step);
        }
    };

    let pubkey = tokio::select! {
        result = discover_pubkey(&transport_tx, destination_hash, cfg.timeout, &progress) => result?,
        _ = wait_terminate(&mut terminate_rx) => return Err(RnshError::Terminated),
    };

    progress(RnshClientProgress::EstablishingLink);
    let link_deadline = Some(Instant::now() + cfg.timeout);
    let (hops, first_hop_timeout) =
        crate::link_endpoint::initiator_path_timing(&transport_tx, destination_hash)
            .await
            .map_err(|_| RnshError::TransportUnavailable)?;
    let (mut link, request_data) =
        crate::link_stamp::new_initiator(&transport_tx, destination_hash, hops).await?;
    let _ = link.try_extend_establishment_timeout(first_hop_timeout);
    let link_id = link.link_id;
    let (lpkt_tx, mut lpkt_rx) = mpsc::channel::<DestinationEvent>(256);
    transport_tx
        .send(TransportMessage::RegisterDestination {
            hash: link_id,
            app_name: "rnsh.client".to_string(),
            delivery_tx: Some(lpkt_tx),
        })
        .await
        .map_err(|_| RnshError::TransportUnavailable)?;
    let mut registration = crate::link_endpoint::LinkEndpointCleanupGuard::new(
        transport_tx.clone(),
        link_id,
        LinkEndpointRole::Initiator,
    );

    let link_req_pkt = build_link_request_packet(destination_hash, &request_data);
    tokio::time::timeout(
        remaining(link_deadline),
        rns_transport::link_messages::dispatch_link_request(
            &transport_tx,
            OutboundRequest {
                raw: link_req_pkt,
                destination_hash,
            },
        ),
    )
    .await
    .map_err(|_| RnshError::Timeout("link request admission"))??;

    let identity_ed25519_pub: [u8; 32] = pubkey[32..64]
        .try_into()
        .map_err(|_| RnshError::ProofInvalid("remote public key length".into()))?;
    let verify_key = Ed25519PublicKey::from_bytes(&identity_ed25519_pub)
        .map_err(|e| RnshError::ProofInvalid(format!("verify key: {e}")))?;
    let proof = tokio::select! {
        result = wait_for_valid_link_proof(
            &mut lpkt_rx,
            &mut link,
            &verify_key,
            &identity_ed25519_pub,
            link_deadline,
        ) => result?,
        _ = wait_terminate(&mut terminate_rx) => return Err(RnshError::Terminated),
    };
    progress(RnshClientProgress::LinkEstablished);
    cfg.terminate_rx = terminate_rx;
    let attached_interface = proof.interface_id;
    let interface_owner = proof.interface_owner;
    let rtt_data = proof.rtt_data;
    let mut endpoint_lifecycle_rx = crate::link_endpoint::bind(
        &transport_tx,
        link_id,
        attached_interface,
        interface_owner,
        LinkEndpointRole::Initiator,
    )
    .await
    .map_err(|_| RnshError::TransportUnavailable)?;
    registration.endpoint_bound();
    let mut endpoint = ClientLinkEndpoint {
        attached_interface,
        interface_owner,
        lifecycle_rx: &mut endpoint_lifecycle_rx,
        packet_rx: &mut lpkt_rx,
    };

    let result =
        run_client_session(&transport_tx, &mut endpoint, &mut link, &mut cfg, &rtt_data).await;

    let endpoint_closing = if let Some(close_pkt) = build_link_close(&mut link) {
        crate::link_endpoint::send_and_unbind(
            &transport_tx,
            link_id,
            LinkEndpointRole::Initiator,
            close_pkt,
        )
        .await
        .is_ok()
    } else {
        false
    };
    if !endpoint_closing {
        let _ = registration.cleanup().await;
    } else {
        registration.disarm();
    }

    result
}

/// Resolves when `rx` fires or its sender is dropped; never without a receiver.
async fn wait_terminate(rx: &mut Option<oneshot::Receiver<()>>) {
    match rx.as_mut() {
        Some(rx) => {
            let _ = rx.await;
        }
        None => std::future::pending::<()>().await,
    }
}

async fn run_client_session(
    transport_tx: &mpsc::Sender<TransportMessage>,
    endpoint: &mut ClientLinkEndpoint<'_>,
    link: &mut Link,
    cfg: &mut RnshClientConfig,
    rtt_data: &[u8],
) -> Result<RnshClientOutcome, RnshError> {
    let link_id = link.link_id;
    let rtt_pkt = build_data_packet(link_id, rns_wire::context::PacketContext::Lrrtt, rtt_data);
    send_client_endpoint_packet(transport_tx, link_id, rtt_pkt).await?;

    let signing_key = cfg
        .identity
        .get_signing_key()
        .ok_or(RnshError::NoSigningKey)?;
    if !cfg.no_id {
        let identify_delay = (link.rtt_secs() * 1.1 + 0.05).min(1.0);
        let post_identify_delay = identify_delay.clamp(0.25, 1.0);
        tokio::time::sleep(Duration::from_secs_f64(post_identify_delay)).await;
        let identify_data = link
            .identify(&cfg.identity.get_public_key(), &signing_key)
            .map_err(|e| RnshError::LinkCrypto(format!("identify: {e:?}")))?;
        let identify_pkt = build_data_packet(
            link_id,
            rns_wire::context::PacketContext::LinkIdentify,
            &identify_data,
        );
        send_client_endpoint_packet(transport_tx, link_id, identify_pkt).await?;
        link.record_tx(identify_data.len());
        tokio::time::sleep(Duration::from_secs_f64(post_identify_delay)).await;
    }

    let session_keys = link
        .session_keys()
        .ok_or_else(|| RnshError::LinkCrypto("no session keys".into()))?;
    let mut channel =
        LinkChannel::new_encrypted_with_mdu(link_id, link.rtt_secs(), link.mdu, session_keys);
    register_rnsh_message_types(&mut channel)?;
    link.mark_channel_created();
    let mut pending_messages = VecDeque::new();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    let version_timeout =
        Duration::from_secs_f64(link.rtt_secs() * CLIENT_VERSION_TIMEOUT_RTT_FACTOR)
            .max(CLIENT_VERSION_TIMEOUT_MIN);
    let version_deadline = Some(Instant::now() + version_timeout);
    let version_result: Result<(), RnshError> = async {
        send_client_message_when_ready(
            transport_tx,
            endpoint,
            link,
            &mut channel,
            &mut pending_messages,
            VersionInfoMessage::new(RNSH_SOFTWARE_VERSION),
            version_deadline,
        )
        .await?;
        loop {
            if let Some(message) = pop_or_receive_client_message(
                transport_tx,
                endpoint,
                link,
                &mut channel,
                &mut pending_messages,
                version_deadline,
            )
            .await?
            {
                match message {
                    RnshMessage::VersionInfo(version) => {
                        if version.protocol_version != PROTOCOL_VERSION {
                            return Err(RnshError::Remote("incompatible rnsh protocol".into()));
                        }
                        return Ok(());
                    }
                    RnshMessage::Error(err) => {
                        return Err(RnshError::Denied(
                            err.msg.unwrap_or_else(|| "remote error".into()),
                        ));
                    }
                    _ => {}
                }
            }
        }
    }
    .await;
    match version_result {
        Ok(()) => {}
        // Upstream only notices a link closed during the version wait as a timeout.
        Err(RnshError::Timeout(_) | RnshError::LinkClosed(_)) => {
            return Err(RnshError::ProtocolError);
        }
        Err(error) => return Err(error),
    }
    tokio::time::sleep(Duration::from_millis(75)).await;

    let execute = ExecuteCommandMessage::new(
        Some(cfg.command.clone()),
        cfg.pipe_stdin,
        cfg.pipe_stdout,
        cfg.pipe_stderr,
        cfg.tcflags.clone(),
        cfg.term.clone(),
        cfg.rows,
        cfg.cols,
        cfg.hpix,
        cfg.vpix,
    );
    send_client_message_when_ready(
        transport_tx,
        endpoint,
        link,
        &mut channel,
        &mut pending_messages,
        execute,
        None,
    )
    .await?;

    let return_code = run_client_io_loop(
        transport_tx,
        endpoint,
        link,
        &mut channel,
        &mut pending_messages,
        ClientIoState {
            stdout: &mut stdout,
            stderr: &mut stderr,
            cfg,
        },
    )
    .await
    .map_err(|error| match error {
        RnshError::Remote(_) | RnshError::LinkClosed(_) | RnshError::Terminated => error,
        other => RnshError::ClientException(other.to_string()),
    })?;

    Ok(RnshClientOutcome {
        stdout,
        stderr,
        return_code,
    })
}

struct ClientLinkEndpoint<'a> {
    attached_interface: InterfaceId,
    interface_owner: Option<rns_transport::messages::InterfaceOwnerId>,
    lifecycle_rx: &'a mut mpsc::UnboundedReceiver<LinkEndpointLifecycleEvent>,
    packet_rx: &'a mut mpsc::Receiver<DestinationEvent>,
}

async fn send_client_endpoint_packet(
    transport_tx: &mpsc::Sender<TransportMessage>,
    link_id: [u8; 16],
    raw: Bytes,
) -> Result<(), RnshError> {
    crate::link_endpoint::send(transport_tx, link_id, LinkEndpointRole::Initiator, raw)
        .await
        .map_err(|_| RnshError::TransportUnavailable)
}

fn register_rnsh_message_types(channel: &mut LinkChannel) -> Result<(), ChannelError> {
    for msg_type in MESSAGE_TYPES {
        channel.register_message_type(msg_type)?;
    }
    Ok(())
}

fn pending_has_remote_terminal(pending_messages: &VecDeque<RnshMessage>) -> bool {
    pending_messages.iter().any(|message| {
        matches!(
            message,
            RnshMessage::CommandExited(_) | RnshMessage::Error(_)
        )
    })
}

struct ClientIoState<'a> {
    stdout: &'a mut Vec<u8>,
    stderr: &'a mut Vec<u8>,
    cfg: &'a mut RnshClientConfig,
}

async fn run_client_io_loop(
    transport_tx: &mpsc::Sender<TransportMessage>,
    endpoint: &mut ClientLinkEndpoint<'_>,
    link: &mut Link,
    channel: &mut LinkChannel,
    pending_messages: &mut VecDeque<RnshMessage>,
    io: ClientIoState<'_>,
) -> Result<i64, RnshError> {
    let ClientIoState {
        stdout,
        stderr,
        cfg,
    } = io;

    let mut stdin_rx = cfg.stdin_rx.take();
    let mut stdin_buffer = Vec::new();
    let mut stdin_eof = false;
    if stdin_rx.is_none() && cfg.pipe_stdin {
        stdin_buffer = std::mem::take(&mut cfg.stdin_data);
        stdin_eof = true;
    }
    let mut stdin_eof_sent = stdin_rx.is_none() && !stdin_eof;
    let stdout_tx = cfg.stdout_tx.take();
    let stderr_tx = cfg.stderr_tx.take();
    let mut window_rx = cfg.window_rx.take();
    let mut terminate_rx = cfg.terminate_rx.take();
    let mut pending_window: Option<RnshWindowSize> = None;
    let mut last_winch = Instant::now();
    let mut eof_due: Option<Instant> = None;

    loop {
        while let Some(message) = pending_messages.pop_front() {
            if let Some(return_code) = handle_client_message(
                ClientMessageOutput {
                    stdout,
                    stderr,
                    stdout_tx: stdout_tx.as_ref(),
                    stderr_tx: stderr_tx.as_ref(),
                },
                message,
            )
            .await?
            {
                return Ok(return_code);
            }
        }

        service_client_link(transport_tx, link, channel).await?;

        if !stdin_buffer.is_empty() && !pending_has_remote_terminal(pending_messages) {
            let max_data_len = channel.mdu().saturating_sub(STREAM_HEADER_LEN).max(1);
            let (compressed, consumed, data) = compress_adaptive(&stdin_buffer, max_data_len);
            let mut message = RnshStreamDataMessage::new(STREAM_ID_STDIN, data, false);
            message.compressed = compressed;
            send_client_message_when_ready(
                transport_tx,
                endpoint,
                link,
                channel,
                pending_messages,
                message,
                None,
            )
            .await?;
            stdin_buffer.drain(..consumed);
            continue;
        }
        if stdin_eof && !stdin_eof_sent && stdin_buffer.is_empty() && eof_due.is_none() {
            eof_due = Some(Instant::now() + CLIENT_PRE_EOF_DRAIN);
        }
        if !stdin_eof_sent
            && eof_due.is_some_and(|due| Instant::now() >= due)
            && !pending_has_remote_terminal(pending_messages)
        {
            send_client_message_when_ready(
                transport_tx,
                endpoint,
                link,
                channel,
                pending_messages,
                RnshStreamDataMessage::new(STREAM_ID_STDIN, Vec::new(), true),
                None,
            )
            .await?;
            stdin_eof_sent = true;
            continue;
        }

        let winch_interval = Duration::from_secs_f64(link.rtt_secs() * CLIENT_WINCH_RTT_FACTOR);
        if let Some(window) = pending_window
            && last_winch.elapsed() > winch_interval
        {
            last_winch = Instant::now();
            pending_window = None;
            send_client_message_when_ready(
                transport_tx,
                endpoint,
                link,
                channel,
                pending_messages,
                WindowSizeMessage::new(window.rows, window.cols, window.hpix, window.vpix),
                None,
            )
            .await?;
            continue;
        }

        let mut wait = channel
            .next_timeout_duration()
            .unwrap_or(Duration::from_secs(1))
            .min(Duration::from_secs(1));
        if let Some(due) = eof_due.filter(|_| !stdin_eof_sent) {
            wait =
                wait.min(due.saturating_duration_since(Instant::now()) + Duration::from_millis(1));
        }
        if pending_window.is_some() {
            let due = (last_winch + winch_interval).saturating_duration_since(Instant::now())
                + Duration::from_millis(1);
            wait = wait.min(due);
        }

        tokio::select! {
            maybe_event = endpoint.packet_rx.recv() => {
                let Some(event) = maybe_event else {
                    return Err(RnshError::LinkClosed("link channel closed".into()));
                };
                process_client_destination_event(
                    transport_tx,
                    link,
                    channel,
                    pending_messages,
                    event,
                    endpoint.attached_interface,
                    endpoint.interface_owner,
                ).await?;
            }
            terminal = endpoint.lifecycle_rx.recv() => {
                return Err(RnshError::LinkClosed(format!(
                    "link endpoint terminated: {terminal:?}"
                )));
            }
            maybe_chunk = recv_optional_stdin_chunk(&mut stdin_rx), if !stdin_eof => {
                match maybe_chunk {
                    Some(data) if !data.is_empty() => {
                        stdin_buffer.extend_from_slice(&data);
                        // Fill whole chunks from input that is already queued.
                        while stdin_buffer.len() < MAX_CHUNK_LEN {
                            match stdin_rx.as_mut().map(|rx| rx.try_recv()) {
                                Some(Ok(more)) if !more.is_empty() => stdin_buffer.extend_from_slice(&more),
                                Some(Ok(_)) | Some(Err(mpsc::error::TryRecvError::Disconnected)) => {
                                    stdin_eof = true;
                                    break;
                                }
                                _ => break,
                            }
                        }
                    }
                    Some(_) | None => stdin_eof = true,
                }
            }
            maybe_window = recv_optional_window_size(&mut window_rx) => {
                match maybe_window {
                    Some(window) => pending_window = Some(window),
                    None => window_rx = None,
                }
            }
            _ = async {
                match terminate_rx.as_mut() {
                    Some(rx) => {
                        let _ = rx.await;
                    }
                    None => std::future::pending::<()>().await,
                }
            } => {
                return Err(RnshError::Terminated);
            }
            _ = tokio::time::sleep(wait) => {}
        }
    }
}

async fn recv_optional_stdin_chunk(rx: &mut Option<mpsc::Receiver<Vec<u8>>>) -> Option<Vec<u8>> {
    match rx {
        Some(rx) => rx.recv().await,
        None => std::future::pending::<Option<Vec<u8>>>().await,
    }
}

async fn recv_optional_window_size(
    rx: &mut Option<mpsc::Receiver<RnshWindowSize>>,
) -> Option<RnshWindowSize> {
    match rx {
        Some(rx) => rx.recv().await,
        None => std::future::pending::<Option<RnshWindowSize>>().await,
    }
}

struct ClientMessageOutput<'a> {
    stdout: &'a mut Vec<u8>,
    stderr: &'a mut Vec<u8>,
    stdout_tx: Option<&'a mpsc::Sender<Vec<u8>>>,
    stderr_tx: Option<&'a mpsc::Sender<Vec<u8>>>,
}

async fn handle_client_message(
    output: ClientMessageOutput<'_>,
    message: RnshMessage,
) -> Result<Option<i64>, RnshError> {
    let ClientMessageOutput {
        stdout,
        stderr,
        stdout_tx,
        stderr_tx,
    } = output;

    match message {
        RnshMessage::StreamData(stream) => match stream.stream_id {
            STREAM_ID_STDOUT => {
                stdout.extend_from_slice(&stream.data);
                if let Some(tx) = stdout_tx
                    && !stream.data.is_empty()
                {
                    tx.send(stream.data)
                        .await
                        .map_err(|_| RnshError::Process("stdout stream receiver closed".into()))?;
                }
                Ok(None)
            }
            STREAM_ID_STDERR => {
                stderr.extend_from_slice(&stream.data);
                if let Some(tx) = stderr_tx
                    && !stream.data.is_empty()
                {
                    tx.send(stream.data)
                        .await
                        .map_err(|_| RnshError::Process("stderr stream receiver closed".into()))?;
                }
                Ok(None)
            }
            _ => Ok(None),
        },
        RnshMessage::CommandExited(exited) => Ok(Some(exited.return_code)),
        RnshMessage::Error(err) => Err(RnshError::Remote(
            err.msg.unwrap_or_else(|| "remote error".into()),
        )),
        // The initiator ignores Noop; only the listener echoes it.
        _ => Ok(None),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ListenerState {
    WaitIdent,
    WaitVersion,
    WaitCommand,
    Running,
    /// Terminal: the session was denied or torn down. No message can advance it.
    Closed,
}

struct ListenerSession {
    authorized: bool,
    remote_identity_hash: Option<[u8; 16]>,
    state: ListenerState,
    stdin: Option<ProcessInput>,
    window: Option<PtyWindowTarget>,
    process_cleanup: Option<ListenerProcessCleanup>,
    /// Pipe-in/TTY-out sessions echo stdin into the stdout stream.
    stdin_echo: Option<mpsc::Sender<ProcessOutput>>,
}

impl ListenerSession {
    fn new(allow_all: bool) -> Self {
        Self {
            authorized: allow_all,
            remote_identity_hash: None,
            state: if allow_all {
                ListenerState::WaitVersion
            } else {
                ListenerState::WaitIdent
            },
            stdin: None,
            window: None,
            process_cleanup: None,
            stdin_echo: None,
        }
    }

    /// Mark the session terminal and stop its process.
    fn close(&mut self) {
        self.state = ListenerState::Closed;
        self.stdin = None;
        self.window = None;
        self.process_cleanup = None;
        self.stdin_echo = None;
    }

    async fn receive_stdin(&mut self, data: Vec<u8>, eof: bool) {
        if !data.is_empty()
            && let Some(stdin) = self.stdin.as_mut()
        {
            match stdin.write_all(&data).await {
                Ok(()) => {
                    if let Some(echo) = self.stdin_echo.as_ref()
                        && data != [0x03]
                        && data != [0x04]
                    {
                        let _ = echo.send(ProcessOutput::Data(STREAM_ID_STDOUT, data)).await;
                    }
                }
                Err(error) => {
                    tracing::debug!(%error, "rnsh process stdin closed");
                    self.stdin = None;
                }
            }
        }
        if eof {
            if let Some(stdin) = self.stdin.as_mut()
                && let Err(error) = stdin.eof().await
            {
                tracing::debug!(%error, "rnsh process stdin eof failed");
                self.stdin = None;
            }
            if self
                .stdin
                .as_ref()
                .is_some_and(|stdin| matches!(stdin, ProcessInput::Pipe(_)))
            {
                self.stdin.take();
            }
        }
    }
}

enum ProcessInput {
    Pipe(tokio::process::ChildStdin),
    #[cfg(unix)]
    Pty(tokio::fs::File),
}

impl ProcessInput {
    async fn write_all(&mut self, data: &[u8]) -> Result<(), RnshError> {
        match self {
            Self::Pipe(stdin) => stdin
                .write_all(data)
                .await
                .map_err(|e| RnshError::Process(format!("write stdin: {e}"))),
            #[cfg(unix)]
            Self::Pty(master) => master
                .write_all(data)
                .await
                .map_err(|e| RnshError::Process(format!("write pty: {e}"))),
        }
    }

    async fn eof(&mut self) -> Result<(), RnshError> {
        match self {
            Self::Pipe(_) => Ok(()),
            #[cfg(unix)]
            Self::Pty(master) => master
                .write_all(&[0x04])
                .await
                .map_err(|e| RnshError::Process(format!("write pty eof: {e}"))),
        }
    }
}

struct PtyWindowTarget {
    #[cfg(unix)]
    file: File,
}

impl PtyWindowTarget {
    #[cfg(unix)]
    fn set_size(
        &self,
        rows: Option<u32>,
        cols: Option<u32>,
        hpix: Option<u32>,
        vpix: Option<u32>,
    ) -> Result<(), RnshError> {
        let winsize = libc_winsize(rows, cols, hpix, vpix);
        let rc =
            unsafe { nix::libc::ioctl(self.file.as_raw_fd(), nix::libc::TIOCSWINSZ, &winsize) };
        if rc == -1 {
            return Err(RnshError::Process(format!(
                "set pty window size: {}",
                std::io::Error::last_os_error()
            )));
        }
        Ok(())
    }

    #[cfg(not(unix))]
    fn set_size(
        &self,
        _rows: Option<u32>,
        _cols: Option<u32>,
        _hpix: Option<u32>,
        _vpix: Option<u32>,
    ) -> Result<(), RnshError> {
        Ok(())
    }
}

struct ListenerProcess {
    stdin: Option<ProcessInput>,
    window: Option<PtyWindowTarget>,
    cleanup: ListenerProcessCleanup,
    stdin_echo: Option<mpsc::Sender<ProcessOutput>>,
}

struct ListenerProcessCleanup {
    stop_tx: Option<oneshot::Sender<()>>,
}

impl Drop for ListenerProcessCleanup {
    fn drop(&mut self) {
        if let Some(tx) = self.stop_tx.take() {
            let _ = tx.send(());
        }
    }
}

#[cfg(unix)]
struct ProcessPty {
    master: File,
    slave: OwnedFd,
}

#[cfg(not(unix))]
struct ProcessPty;

#[cfg(unix)]
fn libc_winsize(
    rows: Option<u32>,
    cols: Option<u32>,
    hpix: Option<u32>,
    vpix: Option<u32>,
) -> nix::libc::winsize {
    nix::libc::winsize {
        ws_row: rows.unwrap_or(0).min(u16::MAX as u32) as u16,
        ws_col: cols.unwrap_or(0).min(u16::MAX as u32) as u16,
        ws_xpixel: hpix.unwrap_or(0).min(u16::MAX as u32) as u16,
        ws_ypixel: vpix.unwrap_or(0).min(u16::MAX as u32) as u16,
    }
}

#[cfg(unix)]
fn open_process_pty(
    rows: Option<u32>,
    cols: Option<u32>,
    hpix: Option<u32>,
    vpix: Option<u32>,
) -> Result<ProcessPty, RnshError> {
    let winsize = nix::pty::Winsize {
        ws_row: rows.unwrap_or(0).min(u16::MAX as u32) as u16,
        ws_col: cols.unwrap_or(0).min(u16::MAX as u32) as u16,
        ws_xpixel: hpix.unwrap_or(0).min(u16::MAX as u32) as u16,
        ws_ypixel: vpix.unwrap_or(0).min(u16::MAX as u32) as u16,
    };
    let pty = nix::pty::openpty(Some(&winsize), None)
        .map_err(|e| RnshError::Process(format!("open pty: {e}")))?;
    Ok(ProcessPty {
        master: File::from(pty.master),
        slave: pty.slave,
    })
}

#[cfg(not(unix))]
fn open_process_pty(
    _rows: Option<u32>,
    _cols: Option<u32>,
    _hpix: Option<u32>,
    _vpix: Option<u32>,
) -> Result<ProcessPty, RnshError> {
    Err(RnshError::Process(
        "PTY-backed local process mode is only supported on Unix".into(),
    ))
}

#[cfg(unix)]
fn pty_stdio(pty: &ProcessPty) -> Result<Stdio, RnshError> {
    let fd = nix::unistd::dup(pty.slave.as_raw_fd())
        .map_err(|e| RnshError::Process(format!("dup pty: {e}")))?;
    let owned = unsafe { OwnedFd::from_raw_fd(fd) };
    Ok(Stdio::from(File::from(owned)))
}

#[cfg(not(unix))]
fn pty_stdio(_pty: &ProcessPty) -> Result<Stdio, RnshError> {
    Err(RnshError::Process(
        "PTY-backed local process mode is only supported on Unix".into(),
    ))
}

#[cfg(unix)]
fn configure_pty_child(cmd: &mut Command, pty: &ProcessPty) {
    let slave_fd = pty.slave.as_raw_fd();
    unsafe {
        cmd.pre_exec(move || {
            if nix::libc::setsid() == -1 {
                return Err(io::Error::last_os_error());
            }
            // The request parameter type differs between glibc, musl, bionic and Darwin.
            if nix::libc::ioctl(slave_fd, nix::libc::TIOCSCTTY as _, 0) == -1 {
                return Err(io::Error::last_os_error());
            }
            let pid = nix::libc::getpid();
            if nix::libc::tcsetpgrp(slave_fd, pid) == -1 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
}

#[cfg(not(unix))]
fn configure_pty_child(_cmd: &mut Command, _pty: &ProcessPty) {}

#[cfg(unix)]
fn pty_input(pty: &ProcessPty) -> Result<ProcessInput, RnshError> {
    let file = pty
        .master
        .try_clone()
        .map_err(|e| RnshError::Process(format!("clone pty stdin: {e}")))?;
    Ok(ProcessInput::Pty(tokio::fs::File::from_std(file)))
}

#[cfg(not(unix))]
fn pty_input(_pty: &ProcessPty) -> Result<ProcessInput, RnshError> {
    Err(RnshError::Process(
        "PTY-backed local process mode is only supported on Unix".into(),
    ))
}

#[cfg(unix)]
fn pty_reader_file(pty: &ProcessPty) -> Result<tokio::fs::File, RnshError> {
    let file = pty
        .master
        .try_clone()
        .map_err(|e| RnshError::Process(format!("clone pty output: {e}")))?;
    Ok(tokio::fs::File::from_std(file))
}

#[cfg(not(unix))]
fn pty_reader_file(_pty: &ProcessPty) -> Result<tokio::fs::File, RnshError> {
    Err(RnshError::Process(
        "PTY-backed local process mode is only supported on Unix".into(),
    ))
}

#[cfg(unix)]
fn pty_window_target(pty: ProcessPty) -> PtyWindowTarget {
    PtyWindowTarget { file: pty.master }
}

#[cfg(not(unix))]
fn pty_window_target(_pty: ProcessPty) -> PtyWindowTarget {
    PtyWindowTarget {}
}

async fn handle_listener_channel_message(
    command_tx: &mpsc::Sender<LinkManagerCommand>,
    cfg: &RnshListenerConfig,
    sessions: &mut HashMap<[u8; 16], ListenerSession>,
    msg: LinkChannelMessage,
    exited_tx: &mpsc::UnboundedSender<[u8; 16]>,
) -> Result<(), RnshError> {
    let link_id = msg.link_id;
    // Sessions are created only on link establishment or identification; a
    // stray channel message must never fabricate one.
    let Some(session) = sessions.get_mut(&link_id) else {
        return Ok(());
    };
    // Messages are ignored until identification, and dropped once terminated.
    if matches!(
        session.state,
        ListenerState::WaitIdent | ListenerState::Closed
    ) {
        return Ok(());
    }
    if !session.authorized {
        terminate_session(command_tx, link_id, session, Some("Invalid state")).await;
        return Ok(());
    }

    let decoded = RnshMessage::decode(msg.msg_type, &msg.payload)
        .map_err(|e| RnshError::Channel(e.to_string()))?;

    match session.state {
        ListenerState::WaitIdent | ListenerState::Closed => {}
        ListenerState::WaitVersion => match decoded {
            RnshMessage::VersionInfo(version) => {
                if version.protocol_version != PROTOCOL_VERSION {
                    terminate_session(command_tx, link_id, session, Some("Incompatible protocol"))
                        .await;
                    return Ok(());
                }
                send_manager_message(
                    command_tx,
                    link_id,
                    VersionInfoMessage::new(RNSH_SOFTWARE_VERSION),
                )
                .await?;
                session.state = ListenerState::WaitCommand;
            }
            _ => {
                terminate_session(
                    command_tx,
                    link_id,
                    session,
                    Some("Protocol error (LSSTATE_WAIT_VERS)"),
                )
                .await;
            }
        },
        ListenerState::WaitCommand => match decoded {
            RnshMessage::ExecuteCommand(execute) => {
                session.state = ListenerState::Running;
                let command = match select_listener_command(
                    &cfg.command,
                    execute.cmdline.as_deref(),
                    cfg.allow_remote_command,
                    cfg.remote_command_as_args,
                ) {
                    Ok(command) => command,
                    Err(reason) => {
                        terminate_session(command_tx, link_id, session, Some(&reason)).await;
                        return Ok(());
                    }
                };
                let process = match start_listener_process(
                    command_tx.clone(),
                    link_id,
                    ListenerProcessRequest {
                        command: &command,
                        pipe_stdin: execute.pipe_stdin,
                        pipe_stdout: execute.pipe_stdout,
                        pipe_stderr: execute.pipe_stderr,
                        term: execute.term.as_deref(),
                        rows: execute.rows,
                        cols: execute.cols,
                        hpix: execute.hpix,
                        vpix: execute.vpix,
                        remote_identity_hash: session.remote_identity_hash,
                        exited_tx: exited_tx.clone(),
                    },
                )
                .await
                {
                    Ok(process) => process,
                    Err(error) => {
                        tracing::error!(link_id = %hex::encode(link_id), %error, "unable to start rnsh process");
                        terminate_session(
                            command_tx,
                            link_id,
                            session,
                            Some("Unable to start process"),
                        )
                        .await;
                        return Ok(());
                    }
                };
                session.stdin = process.stdin;
                session.window = process.window;
                session.process_cleanup = Some(process.cleanup);
                session.stdin_echo = process.stdin_echo;
            }
            _ => {
                terminate_session(
                    command_tx,
                    link_id,
                    session,
                    Some("Protocol error (LSSTATE_WAIT_CMD)"),
                )
                .await;
            }
        },
        ListenerState::Running => match decoded {
            RnshMessage::StreamData(stream) => {
                if stream.stream_id != STREAM_ID_STDIN {
                    terminate_session(
                        command_tx,
                        link_id,
                        session,
                        Some("Protocol error (LSSTATE_RUNNING)"),
                    )
                    .await;
                    return Ok(());
                }
                session.receive_stdin(stream.data, stream.eof).await;
            }
            RnshMessage::WindowSize(window) => {
                if let Some(target) = session.window.as_ref()
                    && let Err(error) =
                        target.set_size(window.rows, window.cols, window.hpix, window.vpix)
                {
                    tracing::debug!(%error, "rnsh window size not applied");
                }
            }
            RnshMessage::Noop(_) => {
                send_manager_message(command_tx, link_id, NoopMessage).await?;
            }
            _ => {}
        },
    }
    Ok(())
}

struct ListenerProcessRequest<'a> {
    command: &'a [String],
    pipe_stdin: bool,
    pipe_stdout: bool,
    pipe_stderr: bool,
    term: Option<&'a str>,
    rows: Option<u32>,
    cols: Option<u32>,
    hpix: Option<u32>,
    vpix: Option<u32>,
    remote_identity_hash: Option<[u8; 16]>,
    exited_tx: mpsc::UnboundedSender<[u8; 16]>,
}

enum ProcessOutput {
    Data(u16, Vec<u8>),
    Closed,
}

async fn start_listener_process(
    command_tx: mpsc::Sender<LinkManagerCommand>,
    link_id: [u8; 16],
    request: ListenerProcessRequest<'_>,
) -> Result<ListenerProcess, RnshError> {
    let ListenerProcessRequest {
        command,
        pipe_stdin,
        pipe_stdout,
        pipe_stderr,
        term,
        rows,
        cols,
        hpix,
        vpix,
        remote_identity_hash,
        exited_tx,
    } = request;

    if command.is_empty() {
        return Err(RnshError::Process("no command specified".into()));
    }

    let uses_pty = !(pipe_stdin && pipe_stdout && pipe_stderr);
    let mut cmd = Command::new(&command[0]);
    cmd.args(&command[1..])
        .env(
            "TERM",
            term.map(str::to_string)
                .or_else(|| std::env::var("TERM").ok().filter(|t| !t.is_empty()))
                .unwrap_or_else(|| "xterm".to_string()),
        )
        .env(
            "RNS_REMOTE_IDENTITY",
            remote_identity_hash
                .map(|hash| format!("<{}>", hex::encode(hash)))
                .unwrap_or_default(),
        );

    let mut pty = if uses_pty {
        Some(open_process_pty(rows, cols, hpix, vpix)?)
    } else {
        None
    };

    if pipe_stdin {
        cmd.stdin(Stdio::piped());
    } else {
        let Some(ref pty) = pty else {
            return Err(RnshError::Process("pty unavailable".into()));
        };
        cmd.stdin(pty_stdio(pty)?);
    }
    if pipe_stdout {
        cmd.stdout(Stdio::piped());
    } else {
        let Some(ref pty) = pty else {
            return Err(RnshError::Process("pty unavailable".into()));
        };
        cmd.stdout(pty_stdio(pty)?);
    }
    if pipe_stderr {
        cmd.stderr(Stdio::piped());
    } else {
        let Some(ref pty) = pty else {
            return Err(RnshError::Process("pty unavailable".into()));
        };
        cmd.stderr(pty_stdio(pty)?);
    }
    if let Some(ref pty) = pty {
        configure_pty_child(&mut cmd, pty);
    }

    let (output_tx, output_rx) = mpsc::channel::<ProcessOutput>(16);
    let (stop_tx, stop_rx) = oneshot::channel();
    let cleanup = ListenerProcessCleanup {
        stop_tx: Some(stop_tx),
    };

    let mut child = match cmd.spawn() {
        Ok(child) => child,
        Err(error) => {
            // Upstream reports exec failure from the forked child: a line on
            // stdout and exit status 255.
            let _ = output_tx
                .send(ProcessOutput::Data(
                    STREAM_ID_STDOUT,
                    format!("Unable to start {}: {error}\n", command[0]).into_bytes(),
                ))
                .await;
            drop(output_tx);
            tokio::spawn(pump_listener_process(
                command_tx, link_id, None, None, output_rx, 0, stop_rx, exited_tx,
            ));
            return Ok(ListenerProcess {
                stdin: None,
                window: None,
                cleanup,
                stdin_echo: None,
            });
        }
    };

    let stdin = if pipe_stdin {
        ProcessInput::Pipe(
            child
                .stdin
                .take()
                .ok_or_else(|| RnshError::Process("could not open process stdin".into()))?,
        )
    } else {
        let pty = pty
            .as_ref()
            .ok_or_else(|| RnshError::Process("pty unavailable".into()))?;
        pty_input(pty)?
    };

    let mut readers = 0usize;
    if pipe_stdout {
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| RnshError::Process("could not open process stdout".into()))?;
        tokio::spawn(process_output_reader(
            output_tx.clone(),
            STREAM_ID_STDOUT,
            stdout,
        ));
        readers += 1;
    }
    if pipe_stderr {
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| RnshError::Process("could not open process stderr".into()))?;
        tokio::spawn(process_output_reader(
            output_tx.clone(),
            STREAM_ID_STDERR,
            stderr,
        ));
        readers += 1;
    }
    if let Some(ref pty) = pty
        && (!pipe_stdout || !pipe_stderr)
    {
        let stream_id = if !pipe_stdout {
            STREAM_ID_STDOUT
        } else {
            STREAM_ID_STDERR
        };
        tokio::spawn(process_output_reader(
            output_tx.clone(),
            stream_id,
            pty_reader_file(pty)?,
        ));
        readers += 1;
    }
    let stdin_echo = (pipe_stdin && !pipe_stdout).then(|| output_tx.clone());
    drop(output_tx);

    let window = pty.take().map(pty_window_target);
    let child_pid = if uses_pty { child.id() } else { None };
    tokio::spawn(pump_listener_process(
        command_tx,
        link_id,
        Some(child),
        child_pid,
        output_rx,
        readers,
        stop_rx,
        exited_tx,
    ));

    Ok(ListenerProcess {
        stdin: Some(stdin),
        window,
        cleanup,
        stdin_echo,
    })
}

async fn process_output_reader<R>(tx: mpsc::Sender<ProcessOutput>, stream_id: u16, mut reader: R)
where
    R: AsyncRead + Unpin,
{
    let mut buf = vec![0u8; PROCESS_READ_LEN];
    loop {
        match reader.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                if tx
                    .send(ProcessOutput::Data(stream_id, buf[..n].to_vec()))
                    .await
                    .is_err()
                {
                    return;
                }
            }
        }
    }
    let _ = tx.send(ProcessOutput::Closed).await;
}

/// Port of `ListenerSession.pump`: drain stderr before stdout in adaptively
/// compressed chunks, then send `CommandExited` once output is flushed, and
/// arm the post-exit check.
#[allow(clippy::too_many_arguments)]
async fn pump_listener_process(
    command_tx: mpsc::Sender<LinkManagerCommand>,
    link_id: [u8; 16],
    mut child: Option<tokio::process::Child>,
    child_pid: Option<u32>,
    mut output_rx: mpsc::Receiver<ProcessOutput>,
    mut open_readers: usize,
    mut stop_rx: oneshot::Receiver<()>,
    exited_tx: mpsc::UnboundedSender<[u8; 16]>,
) {
    let mut stdout_buf = Vec::new();
    let mut stderr_buf = Vec::new();
    let mut return_code: Option<i64> = if child.is_none() { Some(255) } else { None };
    let mut pipes_deadline: Option<tokio::time::Instant> = None;
    let mut writer = ManagerStreamWriter::new(command_tx.clone(), link_id);
    let mut output_open = true;

    loop {
        while output_open && stdout_buf.len() + stderr_buf.len() < MAX_CHUNK_LEN {
            match output_rx.try_recv() {
                Ok(ProcessOutput::Data(STREAM_ID_STDERR, data)) => stderr_buf.extend(data),
                Ok(ProcessOutput::Data(_, data)) => stdout_buf.extend(data),
                Ok(ProcessOutput::Closed) => open_readers = open_readers.saturating_sub(1),
                Err(mpsc::error::TryRecvError::Empty) => break,
                Err(mpsc::error::TryRecvError::Disconnected) => {
                    output_open = false;
                    open_readers = 0;
                }
            }
        }

        let next = if !stderr_buf.is_empty() {
            Some((STREAM_ID_STDERR, &mut stderr_buf))
        } else if !stdout_buf.is_empty() {
            Some((STREAM_ID_STDOUT, &mut stdout_buf))
        } else {
            None
        };
        if let Some((stream_id, buf)) = next {
            tokio::select! {
                biased;
                _ = &mut stop_rx => break,
                sent = writer.send(stream_id, buf) => {
                    if sent.is_err() {
                        break;
                    }
                }
            }
            continue;
        }

        if let Some(code) = return_code
            && (open_readers == 0
                || pipes_deadline.is_some_and(|deadline| tokio::time::Instant::now() >= deadline))
        {
            let _ =
                send_manager_message(&command_tx, link_id, CommandExitedMessage::new(code)).await;
            let exited_timeout = rtt_scaled(
                &command_tx,
                link_id,
                COMMAND_EXITED_RTT_FACTOR,
                COMMAND_EXITED_TIMEOUT,
            )
            .await;
            tokio::select! {
                _ = &mut stop_rx => {}
                _ = tokio::time::sleep(exited_timeout) => {
                    let _ = exited_tx.send(link_id);
                }
            }
            return;
        }

        let pipes_wait = async {
            match pipes_deadline {
                Some(deadline) => tokio::time::sleep_until(deadline).await,
                None => std::future::pending::<()>().await,
            }
        };
        let child_wait = async {
            match child.as_mut() {
                Some(child) if return_code.is_none() => child.wait().await,
                _ => std::future::pending().await,
            }
        };
        tokio::select! {
            _ = &mut stop_rx => break,
            event = output_rx.recv(), if output_open => match event {
                Some(ProcessOutput::Data(STREAM_ID_STDERR, data)) => stderr_buf.extend(data),
                Some(ProcessOutput::Data(_, data)) => stdout_buf.extend(data),
                Some(ProcessOutput::Closed) => open_readers = open_readers.saturating_sub(1),
                None => {
                    output_open = false;
                    open_readers = 0;
                }
            },
            status = child_wait => {
                return_code = Some(match status {
                    Ok(status) => status.code().unwrap_or(255) as i64,
                    Err(_) => 255,
                });
                // Upstream closes the process pipes PROCESS_PIPE_TIME after exit.
                pipes_deadline = Some(tokio::time::Instant::now() + Duration::from_secs(1));
            }
            _ = pipes_wait => {}
        }
    }

    // Session terminated: stop the process without reporting an exit.
    if let Some(mut child) = child
        && return_code.is_none()
    {
        // CallbackSubprocess.terminate: SIGTERM, then SIGHUP and SIGKILL after 1 s.
        signal_child(child.id(), child_pid, SIGTERM_NUM);
        if tokio::time::timeout(Duration::from_secs(1), child.wait())
            .await
            .is_err()
        {
            signal_child(child.id(), child_pid, SIGHUP_NUM);
            terminate_child_process_group(child_pid, SIGKILL_NUM);
            let _ = child.kill().await;
        }
    }
}

/// Stream writer over a LinkManager channel; chunks fill `channel.mdu - HEADER_LEN`.
struct ManagerStreamWriter {
    command_tx: mpsc::Sender<LinkManagerCommand>,
    link_id: [u8; 16],
    max_data_len: Option<usize>,
}

impl ManagerStreamWriter {
    fn new(command_tx: mpsc::Sender<LinkManagerCommand>, link_id: [u8; 16]) -> Self {
        Self {
            command_tx,
            link_id,
            max_data_len: None,
        }
    }

    async fn send(&mut self, stream_id: u16, buf: &mut Vec<u8>) -> Result<(), RnshError> {
        let max_data_len = match self.max_data_len {
            Some(max) => max,
            None => {
                let (result_tx, result_rx) = oneshot::channel();
                self.command_tx
                    .send(LinkManagerCommand::ChannelMdu {
                        link_id: self.link_id,
                        result_tx,
                    })
                    .await
                    .map_err(|_| RnshError::TransportUnavailable)?;
                let channel_mdu = result_rx
                    .await
                    .map_err(|_| RnshError::TransportUnavailable)?
                    .ok_or_else(|| RnshError::Channel("link closed".into()))?;
                let max = channel_mdu.saturating_sub(STREAM_HEADER_LEN).max(1);
                self.max_data_len = Some(max);
                max
            }
        };
        let (compressed, consumed, data) = compress_adaptive(buf, max_data_len);
        let mut message = RnshStreamDataMessage::new(stream_id, data, false);
        message.compressed = compressed;
        match send_manager_message_result(&self.command_tx, self.link_id, message).await? {
            Ok(()) => {
                buf.drain(..consumed);
                Ok(())
            }
            Err(error) => Err(RnshError::Channel(error.to_string())),
        }
    }
}

/// rnsh's `compress_adaptive`, which is `RawChannelWriter.write`'s chunking.
/// Returns `(compressed, consumed, data)`.
fn compress_adaptive(buf: &[u8], max_data_len: usize) -> (bool, usize, Vec<u8>) {
    match StreamWriter::new(0, max_data_len).write_once(buf) {
        Ok(Some((frame, consumed))) => (frame.compressed, consumed, frame.data),
        _ => (false, 0, Vec::new()),
    }
}

#[cfg(unix)]
fn terminate_child_process_group(child_pid: Option<u32>, signal: i32) {
    let Some(pid) = child_pid else {
        return;
    };
    let pgid = -(pid as i32);
    unsafe {
        nix::libc::kill(pgid, signal);
    }
}

#[cfg(not(unix))]
fn terminate_child_process_group(_child_pid: Option<u32>, _signal: i32) {}

/// Signal the child itself and, for PTY sessions, its process group.
fn signal_child(pid: Option<u32>, group_pid: Option<u32>, signal: i32) {
    #[cfg(unix)]
    if let Some(pid) = pid {
        unsafe {
            nix::libc::kill(pid as i32, signal);
        }
    }
    #[cfg(not(unix))]
    let _ = pid;
    terminate_child_process_group(group_pid, signal);
}

fn close_link_after(
    command_tx: mpsc::Sender<LinkManagerCommand>,
    link_id: [u8; 16],
    delay: Duration,
) {
    tokio::spawn(async move {
        tokio::time::sleep(delay).await;
        let _ = command_tx
            .send(LinkManagerCommand::CloseLink {
                link_id,
                reason: CloseReason::DestinationClosed,
                send_teardown: true,
            })
            .await;
    });
}

/// Send one channel message, retrying while the channel window is full. The
/// outer error means the LinkManager is gone; the inner one is the send result.
async fn send_manager_message_result<M>(
    command_tx: &mpsc::Sender<LinkManagerCommand>,
    link_id: [u8; 16],
    message: M,
) -> Result<Result<(), ChannelSendError>, RnshError>
where
    M: MessageBase + Clone + 'static,
{
    loop {
        let (result_tx, result_rx) = oneshot::channel();
        command_tx
            .send(LinkManagerCommand::SendChannelMessage {
                link_id,
                message: Box::new(message.clone()),
                result_tx: Some(result_tx),
            })
            .await
            .map_err(|_| RnshError::TransportUnavailable)?;
        match result_rx
            .await
            .map_err(|_| RnshError::TransportUnavailable)?
        {
            Ok(_) => return Ok(Ok(())),
            Err(ChannelSendError::Channel(ChannelError::NotReady)) => {
                tokio::time::sleep(CHANNEL_SEND_RETRY).await;
            }
            Err(error) => return Ok(Err(error)),
        }
    }
}

async fn send_manager_message<M>(
    command_tx: &mpsc::Sender<LinkManagerCommand>,
    link_id: [u8; 16],
    message: M,
) -> Result<(), RnshError>
where
    M: MessageBase + Clone + 'static,
{
    send_manager_message_result(command_tx, link_id, message)
        .await?
        .map_err(|error| RnshError::Channel(error.to_string()))
}

/// Best-effort single send, as `channel.send` under `contextlib.suppress`.
async fn send_manager_message_once<M>(
    command_tx: &mpsc::Sender<LinkManagerCommand>,
    link_id: [u8; 16],
    message: M,
) where
    M: MessageBase + 'static,
{
    let (result_tx, result_rx) = oneshot::channel();
    if command_tx
        .send(LinkManagerCommand::SendChannelMessage {
            link_id,
            message: Box::new(message),
            result_tx: Some(result_tx),
        })
        .await
        .is_ok()
    {
        let _ = result_rx.await;
    }
}

async fn send_client_message_when_ready<M>(
    transport_tx: &mpsc::Sender<TransportMessage>,
    endpoint: &mut ClientLinkEndpoint<'_>,
    link: &mut Link,
    channel: &mut LinkChannel,
    pending_messages: &mut VecDeque<RnshMessage>,
    message: M,
    deadline: Option<Instant>,
) -> Result<(), RnshError>
where
    M: MessageBase,
{
    loop {
        match channel.prepare_send_tracked(&message) {
            Ok(prepared) => {
                return send_client_channel_data(
                    transport_tx,
                    link,
                    channel,
                    prepared.sequence,
                    &prepared.data,
                )
                .await;
            }
            Err(ChannelError::NotReady) => {
                let _ = receive_client_messages(
                    transport_tx,
                    endpoint,
                    link,
                    channel,
                    pending_messages,
                    deadline,
                    Duration::from_millis(100),
                )
                .await?;
            }
            Err(e) => return Err(e.into()),
        }
    }
}

async fn send_client_channel_data(
    transport_tx: &mpsc::Sender<TransportMessage>,
    link: &mut Link,
    channel: &mut LinkChannel,
    sequence: u16,
    data: &[u8],
) -> Result<(), RnshError> {
    let link_id = *channel.link_id();
    let channel_header = rns_wire::header::PacketHeader {
        flags: rns_wire::flags::PacketFlags {
            header_type: rns_wire::flags::HeaderType::Header1,
            context_flag: false,
            transport_type: rns_wire::flags::TransportType::Broadcast,
            destination_type: rns_wire::flags::DestinationType::Link,
            packet_type: rns_wire::flags::PacketType::Data,
        },
        hops: 0,
        transport_id: None,
        destination_hash: link_id,
        context: rns_wire::context::PacketContext::Channel,
    };
    let mut raw = channel_header.pack();
    raw.extend_from_slice(data);
    let packet_hash = rns_wire::hash::packet_hash(&raw, channel_header.flags.header_type);
    channel.track_outbound_packet_hash(packet_hash, sequence);
    link.record_tx(data.len());
    send_client_endpoint_packet(transport_tx, link_id, Bytes::from(raw)).await
}

/// Retransmit timed-out channel messages and drive the Link watchdog, which
/// sends the initiator keepalives and closes a stale link.
async fn service_client_link(
    transport_tx: &mpsc::Sender<TransportMessage>,
    link: &mut Link,
    channel: &mut LinkChannel,
) -> Result<(), RnshError> {
    channel.update_rtt(link.rtt_secs());
    for sequence in channel.timed_out_sequences() {
        let Some(data) = channel.timeout(sequence)? else {
            continue;
        };
        send_client_channel_data(transport_tx, link, channel, sequence, &data).await?;
    }
    let link_id = link.link_id;
    match link.tick() {
        LinkAction::SendKeepalive | LinkAction::TransitionedToStale => {
            let raw = build_data_packet(
                link_id,
                rns_wire::context::PacketContext::Keepalive,
                &[rns_link::constants::KEEPALIVE_REQUEST],
            );
            send_client_endpoint_packet(transport_tx, link_id, raw).await?;
            link.record_tx_keepalive(1);
        }
        LinkAction::SendTeardownAndClose(data) => {
            let raw =
                build_data_packet(link_id, rns_wire::context::PacketContext::LinkClose, &data);
            let _ = send_client_endpoint_packet(transport_tx, link_id, raw).await;
            return Err(RnshError::LinkClosed("link timed out".into()));
        }
        LinkAction::Closed(_) => {
            return Err(RnshError::LinkClosed("link timed out".into()));
        }
        LinkAction::None => {}
    }
    Ok(())
}

async fn pop_or_receive_client_message(
    transport_tx: &mpsc::Sender<TransportMessage>,
    endpoint: &mut ClientLinkEndpoint<'_>,
    link: &mut Link,
    channel: &mut LinkChannel,
    pending_messages: &mut VecDeque<RnshMessage>,
    deadline: Option<Instant>,
) -> Result<Option<RnshMessage>, RnshError> {
    if let Some(message) = pending_messages.pop_front() {
        return Ok(Some(message));
    }
    receive_client_messages(
        transport_tx,
        endpoint,
        link,
        channel,
        pending_messages,
        deadline,
        Duration::from_secs(1),
    )
    .await?;
    Ok(pending_messages.pop_front())
}

async fn receive_client_messages(
    transport_tx: &mpsc::Sender<TransportMessage>,
    endpoint: &mut ClientLinkEndpoint<'_>,
    link: &mut Link,
    channel: &mut LinkChannel,
    pending_messages: &mut VecDeque<RnshMessage>,
    deadline: Option<Instant>,
    wait: Duration,
) -> Result<bool, RnshError> {
    if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
        return Err(RnshError::Timeout("rnsh channel"));
    }
    service_client_link(transport_tx, link, channel).await?;
    let wait = wait
        .min(Duration::from_secs(1))
        .min(channel.next_timeout_duration().unwrap_or(wait))
        .min(remaining(deadline));
    let event = match tokio::time::timeout(wait, async {
        tokio::select! {
            event = endpoint.packet_rx.recv() => event.ok_or_else(|| {
                RnshError::LinkClosed("link channel closed".into())
            }),
            terminal = endpoint.lifecycle_rx.recv() => Err(RnshError::LinkClosed(
                format!("link endpoint terminated: {terminal:?}")
            )),
        }
    })
    .await
    {
        Ok(Ok(event)) => event,
        Ok(Err(error)) => return Err(error),
        Err(_) => {
            service_client_link(transport_tx, link, channel).await?;
            return Ok(false);
        }
    };

    process_client_destination_event(
        transport_tx,
        link,
        channel,
        pending_messages,
        event,
        endpoint.attached_interface,
        endpoint.interface_owner,
    )
    .await
}

async fn process_client_destination_event(
    transport_tx: &mpsc::Sender<TransportMessage>,
    link: &mut Link,
    channel: &mut LinkChannel,
    pending_messages: &mut VecDeque<RnshMessage>,
    event: DestinationEvent,
    attached_interface: InterfaceId,
    interface_owner: Option<rns_transport::messages::InterfaceOwnerId>,
) -> Result<bool, RnshError> {
    let DestinationEvent::InboundPacket {
        raw,
        interface_id,
        interface_owner: event_owner,
        ..
    } = event
    else {
        return Ok(false);
    };
    if interface_id != attached_interface || event_owner != interface_owner {
        return Ok(false);
    }
    let (header, data_offset) = match rns_wire::header::PacketHeader::unpack(&raw) {
        Ok(parsed) => parsed,
        Err(_) => return Ok(false),
    };
    if header.destination_hash != *channel.link_id() {
        return Ok(false);
    }
    crate::link_endpoint::record_initiator_inbound(link, &raw);
    let body = &raw[data_offset..];
    match header.flags.packet_type {
        rns_wire::flags::PacketType::Proof if body.len() >= 96 => {
            let mut packet_hash = [0u8; 32];
            packet_hash.copy_from_slice(&body[..32]);
            if link.validate_peer_packet_proof(&packet_hash, body).is_ok()
                && channel
                    .delivered_by_packet_hash(&packet_hash, link.rtt_secs())
                    .is_some()
            {
                link.keepalive.record_proof();
            }
        }
        rns_wire::flags::PacketType::Data => match header.context {
            rns_wire::context::PacketContext::Keepalive
                if body.first() == Some(&rns_link::constants::KEEPALIVE_REQUEST) =>
            {
                send_keepalive_response(transport_tx, *channel.link_id()).await?;
            }
            rns_wire::context::PacketContext::LinkClose if link.receive_teardown(body) => {
                return Err(RnshError::LinkClosed("link closed by remote".into()));
            }
            rns_wire::context::PacketContext::Channel => {
                let packet_hash = rns_wire::hash::packet_hash(&raw, header.flags.header_type);
                if let Ok(proof_data) = link.prove_packet_with_local_signer(&packet_hash) {
                    send_link_packet_proof(
                        transport_tx,
                        *channel.link_id(),
                        &proof_data,
                        rns_wire::context::PacketContext::None,
                    )
                    .await?;
                }
                for (msg_type, payload) in channel.receive_data(body)? {
                    let decoded = RnshMessage::decode(msg_type, &payload)
                        .map_err(|e| RnshError::Channel(e.to_string()))?;
                    pending_messages.push_back(decoded);
                }
                return Ok(true);
            }
            _ => {}
        },
        _ => {}
    }
    Ok(false)
}

async fn discover_pubkey(
    transport_tx: &mpsc::Sender<TransportMessage>,
    dest_hash: [u8; 16],
    path_wait: Duration,
    progress: &impl Fn(RnshClientProgress),
) -> Result<[u8; 64], RnshError> {
    if let Some(pk) = lookup_pubkey(transport_tx, dest_hash).await? {
        return Ok(pk);
    }
    progress(RnshClientProgress::RequestingPath);

    transport_tx
        .send(TransportMessage::RequestPath {
            destination_hash: dest_hash,
        })
        .await
        .map_err(|_| RnshError::TransportUnavailable)?;
    let (await_tx, await_rx) = oneshot::channel();
    transport_tx
        .send(TransportMessage::AwaitPath {
            dest: dest_hash,
            reply: await_tx,
        })
        .await
        .map_err(|_| RnshError::TransportUnavailable)?;
    let found = tokio::time::timeout(path_wait, await_rx)
        .await
        .map_err(|_| RnshError::PathTimeout)?
        .unwrap_or(false);
    if !found {
        return Err(RnshError::PathTimeout);
    }
    lookup_pubkey(transport_tx, dest_hash)
        .await?
        .ok_or(RnshError::NoIdentity)
}

async fn lookup_pubkey(
    transport_tx: &mpsc::Sender<TransportMessage>,
    dest_hash: [u8; 16],
) -> Result<Option<[u8; 64]>, RnshError> {
    let (resp_tx, resp_rx) = oneshot::channel();
    transport_tx
        .send(TransportMessage::Rpc {
            query: TransportQuery::GetRecentAnnounces,
            response_tx: resp_tx,
        })
        .await
        .map_err(|_| RnshError::TransportUnavailable)?;
    let resp = resp_rx.await.map_err(|_| RnshError::TransportUnavailable)?;
    let announces: Vec<AnnounceRpcEntry> = match resp {
        TransportQueryResponse::Announces(v) => v,
        _ => Vec::new(),
    };
    Ok(announces
        .into_iter()
        .find(|a| a.dest_hash == dest_hash)
        .and_then(|a| a.public_key))
}

async fn wait_for_valid_link_proof(
    rx: &mut mpsc::Receiver<DestinationEvent>,
    link: &mut Link,
    verify_key: &Ed25519PublicKey,
    identity_ed25519_pub: &[u8; 32],
    deadline: Option<Instant>,
) -> Result<crate::link_endpoint::ValidatedLinkProof, RnshError> {
    tokio::time::timeout(
        remaining(deadline),
        crate::link_endpoint::wait_for_valid_proof(rx, link, verify_key, identity_ed25519_pub),
    )
    .await
    .map_err(|_| RnshError::Timeout("link proof"))?
    .map_err(|error| match error {
        crate::link_endpoint::LinkProofWaitError::LinkClosed => {
            RnshError::HandshakeFailed("link closed".into())
        }
        crate::link_endpoint::LinkProofWaitError::DeliveryClosed => {
            RnshError::HandshakeFailed("channel closed".into())
        }
    })
}

async fn send_keepalive_response(
    transport_tx: &mpsc::Sender<TransportMessage>,
    link_id: [u8; 16],
) -> Result<(), RnshError> {
    let raw = build_data_packet(
        link_id,
        rns_wire::context::PacketContext::Keepalive,
        &[rns_link::constants::KEEPALIVE_RESPONSE],
    );
    send_client_endpoint_packet(transport_tx, link_id, raw).await
}

async fn send_link_packet_proof(
    transport_tx: &mpsc::Sender<TransportMessage>,
    link_id: [u8; 16],
    proof_data: &[u8],
    context: rns_wire::context::PacketContext,
) -> Result<(), RnshError> {
    let header = rns_wire::header::PacketHeader {
        flags: rns_wire::flags::PacketFlags {
            header_type: rns_wire::flags::HeaderType::Header1,
            context_flag: false,
            transport_type: rns_wire::flags::TransportType::Broadcast,
            destination_type: rns_wire::flags::DestinationType::Link,
            packet_type: rns_wire::flags::PacketType::Proof,
        },
        hops: 0,
        transport_id: None,
        destination_hash: link_id,
        context,
    };
    let mut raw = header.pack();
    raw.extend_from_slice(proof_data);
    send_client_endpoint_packet(transport_tx, link_id, Bytes::from(raw)).await
}

fn build_link_close(link: &mut Link) -> Option<Bytes> {
    let link_id = link.link_id;
    let teardown_data = link.teardown(CloseReason::InitiatorClosed)?;
    Some(build_data_packet(
        link_id,
        rns_wire::context::PacketContext::LinkClose,
        &teardown_data,
    ))
}

fn build_link_request_packet(dest_hash: [u8; 16], request_data: &[u8]) -> Bytes {
    let header = rns_wire::header::PacketHeader {
        flags: rns_wire::flags::PacketFlags {
            header_type: rns_wire::flags::HeaderType::Header1,
            context_flag: false,
            transport_type: rns_wire::flags::TransportType::Broadcast,
            destination_type: rns_wire::flags::DestinationType::Single,
            packet_type: rns_wire::flags::PacketType::LinkRequest,
        },
        hops: 0,
        transport_id: None,
        destination_hash: dest_hash,
        context: rns_wire::context::PacketContext::None,
    };
    let mut raw = header.pack();
    raw.extend_from_slice(request_data);
    Bytes::from(raw)
}

fn build_data_packet(
    link_id: [u8; 16],
    context: rns_wire::context::PacketContext,
    body: &[u8],
) -> Bytes {
    let header = rns_wire::header::PacketHeader {
        flags: rns_wire::flags::PacketFlags {
            header_type: rns_wire::flags::HeaderType::Header1,
            context_flag: false,
            transport_type: rns_wire::flags::TransportType::Broadcast,
            destination_type: rns_wire::flags::DestinationType::Link,
            packet_type: rns_wire::flags::PacketType::Data,
        },
        hops: 0,
        transport_id: None,
        destination_hash: link_id,
        context,
    };
    let mut raw = header.pack();
    raw.extend_from_slice(body);
    Bytes::from(raw)
}

// Each announce is fresh and carries the destination stamp when the policy stamps destinations.
async fn send_announce(command_tx: &mpsc::Sender<LinkManagerCommand>) -> Result<(), RnshError> {
    command_tx
        .send(LinkManagerCommand::Announce)
        .await
        .map_err(|_| RnshError::TransportUnavailable)
}

fn remaining(deadline: Option<Instant>) -> Duration {
    deadline.map_or(Duration::MAX, |deadline| {
        deadline.saturating_duration_since(Instant::now())
    })
}

fn select_listener_command(
    default_command: &[String],
    remote_command: Option<&[String]>,
    allow_remote_command: bool,
    remote_command_as_args: bool,
) -> Result<Vec<String>, String> {
    let remote_command = remote_command.unwrap_or(&[]);
    let has_remote_command = !remote_command.is_empty();

    if !allow_remote_command && has_remote_command {
        return Err("Remote command line not allowed by listener".to_string());
    }

    if default_command.is_empty() && (!has_remote_command || remote_command_as_args) {
        return Err("no command configured for listener".to_string());
    }

    if remote_command_as_args && has_remote_command {
        let mut command = default_command.to_vec();
        command.extend_from_slice(remote_command);
        return Ok(command);
    }

    if has_remote_command {
        Ok(remote_command.to_vec())
    } else {
        Ok(default_command.to_vec())
    }
}

/// Read the allowed identity files as `_reload_allowed_file` does: drop `\r`,
/// split on `\n`, and accept only lines of exactly 32 hex characters.
fn read_allowed_identity_files(paths: &[PathBuf]) -> HashSet<[u8; 16]> {
    let mut allowed = HashSet::new();
    for path in paths {
        let Ok(content) = std::fs::read_to_string(path) else {
            continue;
        };
        for line in content.replace('\r', "").split('\n') {
            if let Some(hash) = parse_identity_hash16(line) {
                allowed.insert(hash);
            }
        }
    }
    allowed
}

fn parse_identity_hash16(input: &str) -> Option<[u8; 16]> {
    if input.len() != 32 {
        return None;
    }
    let decoded = hex::decode(input).ok()?;
    let mut hash = [0u8; 16];
    hash.copy_from_slice(decoded.get(..16)?);
    Some(hash)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    #[tokio::test]
    async fn session_timers_scale_with_link_rtt_above_their_floors() {
        let (command_tx, mut command_rx) = mpsc::channel(4);
        let floor = Duration::from_secs(6);
        for (rtt, expected) in [(4.0, Duration::from_secs(12)), (0.5, floor)] {
            let answer = async {
                match command_rx.recv().await {
                    Some(LinkManagerCommand::LinkRtt { result_tx, .. }) => {
                        let _ = result_tx.send(Some(rtt));
                    }
                    _ => panic!("expected a link RTT query"),
                }
            };
            let (scaled, ()) = tokio::join!(rtt_scaled(&command_tx, [1; 16], 3.0, floor), answer);
            assert_eq!(scaled, expected);
        }
    }

    #[test]
    fn rnsh_channel_registration_accepts_every_protocol_type() {
        let mut channel = LinkChannel::new([0xA2; 16], 0.1);
        register_rnsh_message_types(&mut channel).unwrap();

        for (sequence, msg_type) in MESSAGE_TYPES.into_iter().enumerate() {
            let mut envelope = Vec::with_capacity(6);
            envelope.extend_from_slice(&msg_type.to_be_bytes());
            envelope.extend_from_slice(&(sequence as u16).to_be_bytes());
            envelope.extend_from_slice(&0u16.to_be_bytes());
            let received = channel.receive_data(&envelope).unwrap();
            assert_eq!(received, vec![(msg_type, Vec::new())]);
        }
    }

    fn spawn_ack_manager(
        mut rx: mpsc::Receiver<LinkManagerCommand>,
        messages: Arc<Mutex<Vec<RnshMessage>>>,
    ) {
        tokio::spawn(async move {
            let mut sequence = 0u16;
            while let Some(command) = rx.recv().await {
                match command {
                    LinkManagerCommand::SendChannelMessage {
                        link_id,
                        message,
                        result_tx,
                    } => {
                        if let Ok(decoded) =
                            RnshMessage::decode(message.msg_type(), &message.pack())
                        {
                            messages.lock().unwrap().push(decoded);
                        }
                        if let Some(tx) = result_tx {
                            let _ = tx.send(Ok(crate::link_manager::ChannelSendReceipt {
                                link_id,
                                sequence,
                                packet_hash: [0; 32],
                            }));
                            sequence = sequence.wrapping_add(1);
                        }
                    }
                    LinkManagerCommand::ChannelMdu { result_tx, .. } => {
                        let _ = result_tx.send(Some(rns_protocol::channel::Channel::channel_mdu(
                            rns_wire::constants::LINK_MDU,
                        )));
                    }
                    LinkManagerCommand::Shutdown => break,
                    _ => {}
                }
            }
        });
    }

    async fn wait_for_stream_text(messages: &Arc<Mutex<Vec<RnshMessage>>>, needle: &str) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            let text = messages
                .lock()
                .unwrap()
                .iter()
                .filter_map(|message| match message {
                    RnshMessage::StreamData(stream) => {
                        Some(String::from_utf8_lossy(&stream.data).into_owned())
                    }
                    _ => None,
                })
                .collect::<String>();
            if text.replace('\r', "").contains(needle) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        panic!("stream text did not contain {needle:?}");
    }

    async fn wait_for_exit_code(messages: &Arc<Mutex<Vec<RnshMessage>>>, code: i64) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            if messages.lock().unwrap().iter().any(|message| {
                matches!(message, RnshMessage::CommandExited(exited) if exited.return_code == code)
            }) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        panic!("command exit code {code} was not observed");
    }

    fn process_exists(pid: i32) -> bool {
        let rc = unsafe { nix::libc::kill(pid, 0) };
        rc == 0 || std::io::Error::last_os_error().raw_os_error() == Some(nix::libc::EPERM)
    }

    #[tokio::test]
    async fn unix_pty_stdin_stdout_and_ctrl_d() {
        let (command_tx, command_rx) = mpsc::channel(64);
        let messages = Arc::new(Mutex::new(Vec::new()));
        spawn_ack_manager(command_rx, messages.clone());
        let command = vec![
            "/bin/sh".to_string(),
            "-c".to_string(),
            "if test -t 0 && test -t 1; then cat >/dev/null; printf 'eof-ok\\n'; else printf 'tty-missing\\n'; exit 44; fi".to_string(),
        ];

        let mut process = start_listener_process(
            command_tx,
            [0x11; 16],
            ListenerProcessRequest {
                command: &command,
                pipe_stdin: false,
                pipe_stdout: false,
                pipe_stderr: true,
                term: Some("xterm"),
                rows: Some(24),
                cols: Some(80),
                hpix: None,
                vpix: None,
                remote_identity_hash: None,
                exited_tx: mpsc::unbounded_channel().0,
            },
        )
        .await
        .expect("start pty process");

        process
            .stdin
            .as_mut()
            .unwrap()
            .write_all(&[0x04])
            .await
            .expect("send ctrl-d");
        wait_for_stream_text(&messages, "eof-ok\n").await;
        wait_for_exit_code(&messages, 0).await;
    }

    #[tokio::test]
    async fn unix_pty_ctrl_c_reaches_foreground_process_group() {
        let (command_tx, command_rx) = mpsc::channel(64);
        let messages = Arc::new(Mutex::new(Vec::new()));
        spawn_ack_manager(command_rx, messages.clone());
        let command = vec![
            "python3".to_string(),
            "-c".to_string(),
            "import signal, sys, time; signal.signal(signal.SIGINT, lambda s, f: (print('interrupted', flush=True), sys.exit(23))); print('ready', flush=True); time.sleep(30)".to_string(),
        ];

        let mut process = start_listener_process(
            command_tx,
            [0x22; 16],
            ListenerProcessRequest {
                command: &command,
                pipe_stdin: false,
                pipe_stdout: false,
                pipe_stderr: true,
                term: Some("xterm"),
                rows: Some(24),
                cols: Some(80),
                hpix: None,
                vpix: None,
                remote_identity_hash: None,
                exited_tx: mpsc::unbounded_channel().0,
            },
        )
        .await
        .expect("start pty process");

        wait_for_stream_text(&messages, "ready\n").await;
        process
            .stdin
            .as_mut()
            .unwrap()
            .write_all(&[0x03])
            .await
            .expect("send ctrl-c");
        wait_for_stream_text(&messages, "interrupted\n").await;
        wait_for_exit_code(&messages, 23).await;
    }

    #[tokio::test]
    async fn unix_pty_process_is_cleaned_up_on_session_drop() {
        let (command_tx, command_rx) = mpsc::channel(64);
        let messages = Arc::new(Mutex::new(Vec::new()));
        spawn_ack_manager(command_rx, messages);
        let pid_path = std::env::temp_dir().join(format!(
            "rnsh-cleanup-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let command = vec![
            "/bin/sh".to_string(),
            "-c".to_string(),
            format!(
                "echo $$ > '{}'; while :; do sleep 1; done",
                pid_path.display()
            ),
        ];

        let process = start_listener_process(
            command_tx,
            [0x33; 16],
            ListenerProcessRequest {
                command: &command,
                pipe_stdin: false,
                pipe_stdout: true,
                pipe_stderr: true,
                term: Some("xterm"),
                rows: Some(24),
                cols: Some(80),
                hpix: None,
                vpix: None,
                remote_identity_hash: None,
                exited_tx: mpsc::unbounded_channel().0,
            },
        )
        .await
        .expect("start pty process");

        let deadline = Instant::now() + Duration::from_secs(3);
        let pid: i32 = loop {
            if Instant::now() >= deadline {
                panic!("child pid file was not populated at {}", pid_path.display());
            }
            match std::fs::read_to_string(&pid_path) {
                Ok(contents) => match contents.trim().parse() {
                    Ok(pid) => break pid,
                    Err(_) if contents.trim().is_empty() => {}
                    Err(e) => panic!("parse child pid from {contents:?}: {e}"),
                },
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => panic!("read child pid file {}: {e}", pid_path.display()),
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        };
        assert!(process_exists(pid), "child process should be running");

        drop(process);
        let deadline = Instant::now() + Duration::from_secs(3);
        while Instant::now() < deadline && process_exists(pid) {
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        let _ = std::fs::remove_file(&pid_path);
        assert!(!process_exists(pid), "child process survived session drop");
    }

    fn unique_marker(tag: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "rnsh-adv-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    // Authenticated listener whose default command creates `marker` if it ever
    // reaches process spawn. The attacker identity is absent from the allow-list.
    fn marker_listener_config(marker: &std::path::Path) -> RnshListenerConfig {
        RnshListenerConfig {
            identity: Identity::new(),
            command: vec![
                "/bin/sh".to_string(),
                "-c".to_string(),
                format!("touch '{}'", marker.display()),
            ],
            allow_all: false,
            allowed: Vec::new(),
            allowed_identity_files: Vec::new(),
            allow_remote_command: false,
            remote_command_as_args: false,
            announce_period: None,
        }
    }

    fn version_channel_msg(link_id: [u8; 16]) -> LinkChannelMessage {
        let msg = VersionInfoMessage::new(RNSH_SOFTWARE_VERSION);
        LinkChannelMessage {
            link_id,
            msg_type: msg.msg_type(),
            payload: msg.pack(),
        }
    }

    fn execute_command_channel_msg(link_id: [u8; 16]) -> LinkChannelMessage {
        // Empty cmdline + headless pipes: selects the listener's default command.
        let msg =
            ExecuteCommandMessage::new(None, true, true, true, None, None, None, None, None, None);
        LinkChannelMessage {
            link_id,
            msg_type: msg.msg_type(),
            payload: msg.pack(),
        }
    }

    // The 1.3.9 rnsh flaw: a rejected identity ignores the fatal error, then
    // sends VersionInfo + ExecuteCommand and reaches command execution. A denied
    // (terminal Closed) session must drop both and never spawn the command.
    #[tokio::test]
    async fn adversarial_denied_session_never_runs_command() {
        let marker = unique_marker("denied");
        let _ = std::fs::remove_file(&marker);
        let cfg = marker_listener_config(&marker);
        let (command_tx, command_rx) = mpsc::channel(64);
        let messages = Arc::new(Mutex::new(Vec::new()));
        spawn_ack_manager(command_rx, messages.clone());

        let link_id = [0x55; 16];
        let mut sessions = HashMap::new();
        let mut denied = ListenerSession::new(false);
        denied.state = ListenerState::Closed; // denial marks the session terminal
        sessions.insert(link_id, denied);

        handle_listener_channel_message(
            &command_tx,
            &cfg,
            &mut sessions,
            version_channel_msg(link_id),
            &mpsc::unbounded_channel().0,
        )
        .await
        .expect("handler ok");
        handle_listener_channel_message(
            &command_tx,
            &cfg,
            &mut sessions,
            execute_command_channel_msg(link_id),
            &mpsc::unbounded_channel().0,
        )
        .await
        .expect("handler ok");

        tokio::time::sleep(Duration::from_millis(300)).await;

        assert!(
            !marker.exists(),
            "denied session must never run the listener command"
        );
        assert_eq!(sessions.get(&link_id).unwrap().state, ListenerState::Closed);
        assert!(
            !messages
                .lock()
                .unwrap()
                .iter()
                .any(|m| matches!(m, RnshMessage::VersionInfo(_))),
            "denied session must not answer VersionInfo"
        );
        let _ = std::fs::remove_file(&marker);
    }

    // Same attack against a session that identified with an unallowed identity but
    // was never authorized (still WaitIdent). Every message is dropped at the gate.
    #[tokio::test]
    async fn adversarial_unauthorized_session_never_runs_command() {
        let marker = unique_marker("unauth");
        let _ = std::fs::remove_file(&marker);
        let cfg = marker_listener_config(&marker);
        let (command_tx, command_rx) = mpsc::channel(64);
        let messages = Arc::new(Mutex::new(Vec::new()));
        spawn_ack_manager(command_rx, messages.clone());

        let link_id = [0x56; 16];
        let mut sessions = HashMap::new();
        // Unauthorized authenticated session: authorized=false, WaitIdent.
        sessions.insert(link_id, ListenerSession::new(false));

        handle_listener_channel_message(
            &command_tx,
            &cfg,
            &mut sessions,
            version_channel_msg(link_id),
            &mpsc::unbounded_channel().0,
        )
        .await
        .expect("handler ok");
        handle_listener_channel_message(
            &command_tx,
            &cfg,
            &mut sessions,
            execute_command_channel_msg(link_id),
            &mpsc::unbounded_channel().0,
        )
        .await
        .expect("handler ok");

        tokio::time::sleep(Duration::from_millis(300)).await;

        assert!(
            !marker.exists(),
            "unauthorized session must never run the listener command"
        );
        let session = sessions.get(&link_id).unwrap();
        assert!(!session.authorized);
        assert_eq!(session.state, ListenerState::WaitIdent);
        let _ = std::fs::remove_file(&marker);
    }

    // An upstream initiator sends VersionInfo right behind LINKIDENTIFY, so both
    // can be queued when the listener wakes. Identification goes first, with and
    // without an allow list; otherwise the session ends with a protocol error or
    // drops the VersionInfo while it still waits for identification.
    #[tokio::test]
    async fn identification_queued_ahead_of_version_info_is_applied_first() {
        let identity_hash = [0xAB; 16];
        for allow_all in [true, false] {
            let mut cfg = marker_listener_config(&unique_marker("order"));
            cfg.allow_all = allow_all;
            cfg.allowed = vec![identity_hash];
            let (command_tx, command_rx) = mpsc::channel(64);
            let messages = Arc::new(Mutex::new(Vec::new()));
            spawn_ack_manager(command_rx, messages.clone());
            let (established_tx, mut established_rx) = mpsc::channel(4);
            let (identified_tx, mut identified_rx) = mpsc::channel(4);
            let link_id = [0x58; 16];
            established_tx.try_send(link_id).unwrap();
            identified_tx.try_send((link_id, identity_hash)).unwrap();

            let mut sessions = HashMap::new();
            let mut file_allowed = HashSet::new();
            apply_queued_link_events(
                &command_tx,
                &cfg,
                &mut sessions,
                &mut file_allowed,
                &mut established_rx,
                &mut identified_rx,
            )
            .await;
            handle_listener_channel_message(
                &command_tx,
                &cfg,
                &mut sessions,
                version_channel_msg(link_id),
                &mpsc::unbounded_channel().0,
            )
            .await
            .expect("handler ok");

            let session = &sessions[&link_id];
            assert_eq!(
                session.state,
                ListenerState::WaitCommand,
                "allow_all={allow_all}"
            );
            assert_eq!(session.remote_identity_hash, Some(identity_hash));
            let messages = messages.lock().unwrap();
            assert!(
                messages
                    .iter()
                    .any(|m| matches!(m, RnshMessage::VersionInfo(_)))
            );
            assert!(!messages.iter().any(|m| matches!(m, RnshMessage::Error(_))));
        }
    }

    // Positive control: an authorized session in WaitCommand DOES run the command,
    // proving the harness can reach process spawn — so the negative results above
    // are due to authorization, not an impotent test setup.
    #[tokio::test]
    async fn positive_control_authorized_session_runs_command() {
        let marker = unique_marker("authed");
        let _ = std::fs::remove_file(&marker);
        let cfg = marker_listener_config(&marker);
        let (command_tx, command_rx) = mpsc::channel(64);
        let messages = Arc::new(Mutex::new(Vec::new()));
        spawn_ack_manager(command_rx, messages.clone());

        let link_id = [0x57; 16];
        let mut sessions = HashMap::new();
        let mut authed = ListenerSession::new(false);
        authed.authorized = true;
        authed.remote_identity_hash = Some([0xAB; 16]);
        authed.state = ListenerState::WaitCommand;
        sessions.insert(link_id, authed);

        handle_listener_channel_message(
            &command_tx,
            &cfg,
            &mut sessions,
            execute_command_channel_msg(link_id),
            &mpsc::unbounded_channel().0,
        )
        .await
        .expect("handler ok");

        let deadline = Instant::now() + Duration::from_secs(3);
        while Instant::now() < deadline && !marker.exists() {
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        assert!(
            marker.exists(),
            "authorized session must run the listener command (positive control)"
        );
        assert_eq!(
            sessions.get(&link_id).unwrap().state,
            ListenerState::Running
        );

        drop(sessions); // reap the spawned child
        let _ = std::fs::remove_file(&marker);
    }

    fn lcg(n: usize) -> Vec<u8> {
        let mut x: u64 = 1;
        (0..n)
            .map(|_| {
                x = (x * 1103515245 + 12345) & 0x7fff_ffff;
                ((x >> 16) & 0xff) as u8
            })
            .collect()
    }

    /// Cases generated by `tests/fixtures/rnsh_compress_adaptive/generate.py` from upstream
    /// `RawChannelWriter.write`, the same algorithm as rnsh's `compress_adaptive`.
    #[test]
    fn adaptive_compression_matches_upstream_chunking() {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../tests/fixtures/rnsh_compress_adaptive/cases.json"
        ))
        .unwrap();
        let max = fixture["meta"]["channel_mdu"].as_u64().unwrap() as usize - STREAM_HEADER_LEN;
        for case in fixture["cases"].as_array().unwrap() {
            let name = case["name"].as_str().unwrap();
            let input = match name {
                "lcg_20" => lcg(20),
                "lcg_33" => lcg(33),
                "lcg_1000" => lcg(1000),
                "lcg_20000" => lcg(20000),
                "a_33" => vec![b'A'; 33],
                "a_20000" => vec![b'A'; 20000],
                "a600_lcg600" => [vec![b'A'; 600], lcg(600)].concat(),
                "lcg600_a600" => [lcg(600), vec![b'A'; 600]].concat(),
                other => panic!("unknown case {other}"),
            };
            let expect = &case["expect"];
            let (c, n, data) = compress_adaptive(&input, max);
            assert_eq!(
                (n as u64, c, data.len() as u64),
                (
                    expect[0].as_u64().unwrap(),
                    expect[1].as_bool().unwrap(),
                    expect[2].as_u64().unwrap()
                ),
                "{name}: {}",
                case["rule"]
            );
            if c {
                assert_eq!(
                    &data[..4],
                    b"BZh9",
                    "{name}: bz2.compress defaults to level 9"
                );
                let plain =
                    rns_protocol::compression::bz2_decompress(&data, MAX_CHUNK_LEN).unwrap();
                assert_eq!(plain, input[..n], "{name}");
            }
        }
    }

    #[test]
    fn allowed_identity_file_accepts_only_exact_hash_lines() {
        let path = unique_marker("allowed");
        std::fs::write(
            &path,
            "00112233445566778899aabbccddeeff\r\n ffeeddccbbaa99887766554433221100\n11112222333344445555666677778888 \nzz112233445566778899aabbccddeeff\n",
        )
        .unwrap();
        let allowed = read_allowed_identity_files(std::slice::from_ref(&path));
        let _ = std::fs::remove_file(&path);
        assert_eq!(allowed.len(), 1);
        assert!(
            allowed.contains(&parse_identity_hash16("00112233445566778899aabbccddeeff").unwrap())
        );
    }

    fn error_texts(messages: &Arc<Mutex<Vec<RnshMessage>>>) -> Vec<String> {
        messages
            .lock()
            .unwrap()
            .iter()
            .filter_map(|m| match m {
                RnshMessage::Error(e) if e.fatal => e.msg.clone(),
                _ => None,
            })
            .collect()
    }

    #[tokio::test]
    async fn incompatible_protocol_terminates_only_that_session() {
        let cfg = marker_listener_config(&unique_marker("proto"));
        let (command_tx, command_rx) = mpsc::channel(64);
        let messages = Arc::new(Mutex::new(Vec::new()));
        spawn_ack_manager(command_rx, messages.clone());
        let mut sessions = HashMap::new();
        sessions.insert([1; 16], ListenerSession::new(true));
        sessions.insert([2; 16], ListenerSession::new(true));
        let mut version = VersionInfoMessage::new(RNSH_SOFTWARE_VERSION);
        version.protocol_version = 2;
        let msg = LinkChannelMessage {
            link_id: [1; 16],
            msg_type: version.msg_type(),
            payload: version.pack(),
        };
        handle_listener_channel_message(
            &command_tx,
            &cfg,
            &mut sessions,
            msg,
            &mpsc::unbounded_channel().0,
        )
        .await
        .expect("session error stays in the session");
        assert_eq!(
            error_texts(&messages),
            vec!["Incompatible protocol".to_string()]
        );
        assert_eq!(sessions[&[1; 16]].state, ListenerState::Closed);
        assert_eq!(sessions[&[2; 16]].state, ListenerState::WaitVersion);
    }

    #[tokio::test]
    async fn wrong_state_message_closes_session_and_link_after_prune_delay() {
        tokio::time::pause();
        let cfg = marker_listener_config(&unique_marker("state"));
        let (command_tx, mut command_rx) = mpsc::channel(64);
        let link_id = [3; 16];
        let mut sessions = HashMap::new();
        sessions.insert(link_id, ListenerSession::new(true));
        let (exited_tx, _exited_rx) = mpsc::unbounded_channel();
        let handler = handle_listener_channel_message(
            &command_tx,
            &cfg,
            &mut sessions,
            execute_command_channel_msg(link_id),
            &exited_tx,
        );
        let manager = async {
            match command_rx.recv().await {
                Some(LinkManagerCommand::SendChannelMessage {
                    message, result_tx, ..
                }) => {
                    let decoded = RnshMessage::decode(message.msg_type(), &message.pack()).unwrap();
                    let _ = result_tx
                        .unwrap()
                        .send(Ok(crate::link_manager::ChannelSendReceipt {
                            link_id,
                            sequence: 0,
                            packet_hash: [0; 32],
                        }));
                    match command_rx.recv().await {
                        Some(LinkManagerCommand::LinkRtt { result_tx, .. }) => {
                            let _ = result_tx.send(Some(0.1));
                        }
                        _ => panic!("expected a link RTT query"),
                    }
                    decoded
                }
                _ => panic!("expected an ErrorMessage"),
            }
        };
        let (result, sent) = tokio::join!(handler, manager);
        result.unwrap();
        assert!(
            matches!(sent, RnshMessage::Error(e) if e.msg.as_deref() == Some("Protocol error (LSSTATE_WAIT_VERS)") && e.fatal)
        );
        assert_eq!(sessions[&link_id].state, ListenerState::Closed);
        let started = tokio::time::Instant::now();
        match command_rx.recv().await {
            Some(LinkManagerCommand::CloseLink {
                link_id: closed,
                send_teardown,
                ..
            }) => {
                assert_eq!(closed, link_id);
                assert!(send_teardown);
            }
            _ => panic!("expected CloseLink"),
        }
        assert!(started.elapsed() >= LISTENER_PRUNE_DELAY);
    }

    #[tokio::test]
    async fn spawn_failure_reports_on_stdout_and_exits_255() {
        let (command_tx, command_rx) = mpsc::channel(64);
        let messages = Arc::new(Mutex::new(Vec::new()));
        spawn_ack_manager(command_rx, messages.clone());
        let command = vec!["/nonexistent/rnsh-test-command".to_string()];
        let _process = start_listener_process(
            command_tx,
            [0x44; 16],
            ListenerProcessRequest {
                command: &command,
                pipe_stdin: true,
                pipe_stdout: true,
                pipe_stderr: true,
                term: None,
                rows: None,
                cols: None,
                hpix: None,
                vpix: None,
                remote_identity_hash: None,
                exited_tx: mpsc::unbounded_channel().0,
            },
        )
        .await
        .expect("spawn failure is reported in-band");
        wait_for_stream_text(
            &messages,
            "Unable to start /nonexistent/rnsh-test-command: ",
        )
        .await;
        wait_for_exit_code(&messages, 255).await;
    }

    #[tokio::test]
    async fn command_exited_arms_post_exit_session_check() {
        let (command_tx, command_rx) = mpsc::channel(64);
        let messages = Arc::new(Mutex::new(Vec::new()));
        spawn_ack_manager(command_rx, messages.clone());
        let (exited_tx, mut exited_rx) = mpsc::unbounded_channel();
        let command = vec![
            "/bin/sh".to_string(),
            "-c".to_string(),
            "exit 0".to_string(),
        ];
        let _process = start_listener_process(
            command_tx,
            [0x45; 16],
            ListenerProcessRequest {
                command: &command,
                pipe_stdin: true,
                pipe_stdout: true,
                pipe_stderr: true,
                term: None,
                rows: None,
                cols: None,
                hpix: None,
                vpix: None,
                remote_identity_hash: None,
                exited_tx,
            },
        )
        .await
        .unwrap();
        wait_for_exit_code(&messages, 0).await;
        let exited_at = Instant::now();
        let link_id = tokio::time::timeout(Duration::from_secs(15), exited_rx.recv())
            .await
            .expect("post-exit check fires")
            .unwrap();
        assert_eq!(link_id, [0x45; 16]);
        assert!(exited_at.elapsed() >= COMMAND_EXITED_TIMEOUT - Duration::from_millis(100));
    }

    #[tokio::test]
    async fn client_ignores_noop() {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let result = handle_client_message(
            ClientMessageOutput {
                stdout: &mut stdout,
                stderr: &mut stderr,
                stdout_tx: None,
                stderr_tx: None,
            },
            RnshMessage::Noop(NoopMessage),
        )
        .await
        .unwrap();
        assert_eq!(result, None);
    }
}
