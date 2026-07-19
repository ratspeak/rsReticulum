//! Runtime support for `rnsh`, the Reticulum remote shell utility.

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
use rns_link::link::{CloseReason, Link};
use rns_protocol::channel::{ChannelError, LinkChannel};
use rns_protocol::channel_message::MessageBase;
use rns_protocol::rnsh::{
    CommandExitedMessage, ErrorMessage, ExecuteCommandMessage, NoopMessage, PROTOCOL_VERSION,
    RnshMessage, RnshStreamDataMessage, STREAM_ID_STDERR, STREAM_ID_STDIN, STREAM_ID_STDOUT,
    VersionInfoMessage, WindowSizeMessage,
};
use rns_transport::link_messages::DestinationEvent;
use rns_transport::messages::{
    AnnounceRpcEntry, OutboundRequest, TransportMessage, TransportQuery, TransportQueryResponse,
};

use crate::lifecycle::ShutdownSignal;
use crate::link_manager::{
    ChannelSendError, LinkChannelMessage, LinkManager, LinkManagerCommand, register_destination,
};

pub const RNSH_APP_NAME: &str = "rnsh";
pub const RNSH_SOFTWARE_VERSION: &str = "0.2.0";
const CLIENT_CHUNK_LEN: usize = 240;
const CHANNEL_SEND_RETRY: Duration = Duration::from_millis(20);
const CLIENT_PRE_EOF_DRAIN_MIN: Duration = Duration::from_secs(3);
const CLIENT_PRE_EOF_DRAIN_MAX: Duration = Duration::from_secs(3);
const CLIENT_PRE_EOF_DRAIN_POLL: Duration = Duration::from_millis(25);
const SIGTERM_NUM: i32 = 15;
const SIGKILL_NUM: i32 = 9;

#[derive(Debug, thiserror::Error)]
pub enum RnshError {
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
    #[error("listener denied the connection")]
    Denied,
}

impl From<ChannelError> for RnshError {
    fn from(value: ChannelError) -> Self {
        Self::Channel(value.to_string())
    }
}

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

pub async fn run_rnsh_listener(
    transport_tx: mpsc::Sender<TransportMessage>,
    cfg: RnshListenerConfig,
) -> Result<(), RnshError> {
    run_rnsh_listener_inner(transport_tx, cfg, None).await
}

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

    let announce_tx = transport_tx.clone();
    let announce_packet = build_announce_packet(&cfg.identity, RNSH_APP_NAME)?;
    link_mgr.set_announce_handler(move || {
        let _ = announce_tx.try_send(TransportMessage::Outbound(OutboundRequest {
            raw: Bytes::from(announce_packet.clone()),
            destination_hash,
        }));
    });

    let (command_tx, command_rx) = mpsc::channel::<LinkManagerCommand>(256);
    let (channel_tx, mut channel_rx) = mpsc::channel::<LinkChannelMessage>(256);
    let (established_tx, mut established_rx) = mpsc::channel::<[u8; 16]>(64);
    let (identified_tx, mut identified_rx) = mpsc::channel::<([u8; 16], [u8; 16])>(64);
    let (closed_tx, mut closed_rx) = mpsc::channel::<[u8; 16]>(64);
    link_mgr.set_channel_message_channel(channel_tx);
    link_mgr.set_link_established_channel(established_tx);
    link_mgr.set_link_identified_channel(identified_tx);
    link_mgr.set_link_closed_channel(closed_tx);

    // Defense in depth: in authenticated mode, reject unallowed identities
    // synchronously at the link layer (as rncp does), so the manager tears the
    // link down at identify time in addition to the handler-level allow-check
    // below. allow_all installs no gate.
    if !cfg.allow_all {
        let allowed = listener_allowed_identities(&cfg);
        link_mgr.set_link_identity_gate(move |_link_id, identity_hash| {
            allowed.contains(&identity_hash)
        });
    }

    let manager_task = tokio::spawn(async move {
        link_mgr.run_with_commands(command_rx).await;
    });

    if cfg.announce_period.is_some() {
        send_announce(&transport_tx, &cfg.identity, RNSH_APP_NAME).await?;
    }
    let mut announce_interval = cfg
        .announce_period
        .filter(|period| *period > 0)
        .map(|period| tokio::time::interval(Duration::from_secs(period.max(1))));

    let mut sessions: HashMap<[u8; 16], ListenerSession> = HashMap::new();

    loop {
        tokio::select! {
            maybe_link = established_rx.recv() => {
                let Some(link_id) = maybe_link else { break };
                // or_insert (not insert) so a rare identification processed ahead
                // of this establishment event is never clobbered.
                sessions.entry(link_id).or_insert_with(|| ListenerSession::new(cfg.allow_all));
            }
            maybe_identified = identified_rx.recv() => {
                let Some((link_id, identity_hash)) = maybe_identified else { break };
                let allowed = listener_allowed_identities(&cfg);
                if cfg.allow_all || allowed.contains(&identity_hash) {
                    // Identification is a legitimate session creator (it may race
                    // ahead of the establishment event), so create-or-get here.
                    let session = sessions
                        .entry(link_id)
                        .or_insert_with(|| ListenerSession::new(cfg.allow_all));
                    // First-identification-wins: only a freshly-established
                    // (WaitIdent) authenticated session may be authorized and
                    // advanced — a repeat identification cannot regress a session
                    // that has already moved on.
                    if session.state == ListenerState::WaitIdent {
                        session.authorized = true;
                        session.remote_identity_hash = Some(identity_hash);
                        session.state = ListenerState::WaitVersion;
                    } else if cfg.allow_all && session.remote_identity_hash.is_none() {
                        // allow_all sessions start authorized in WaitVersion;
                        // record the first identity without regressing state.
                        session.remote_identity_hash = Some(identity_hash);
                    }
                } else {
                    // Denial is terminal: mark the session Closed so a message that
                    // lands before CloseLink completes cannot resurrect it.
                    let session = sessions
                        .entry(link_id)
                        .or_insert_with(|| ListenerSession::new(cfg.allow_all));
                    session.authorized = false;
                    session.state = ListenerState::Closed;
                    send_manager_message(
                        &command_tx,
                        link_id,
                        ErrorMessage::new(Some("Identity is not allowed.".into()), true, None),
                    ).await?;
                    let _ = command_tx.send(LinkManagerCommand::CloseLink {
                        link_id,
                        reason: CloseReason::DestinationClosed,
                        send_teardown: true,
                    }).await;
                }
            }
            maybe_closed = closed_rx.recv() => {
                let Some(link_id) = maybe_closed else { break };
                sessions.remove(&link_id);
            }
            maybe_msg = channel_rx.recv() => {
                let Some(msg) = maybe_msg else { break };
                handle_listener_channel_message(
                    &command_tx,
                    &cfg,
                    &mut sessions,
                    msg,
                ).await?;
            }
            _ = async {
                if let Some(interval) = announce_interval.as_mut() {
                    interval.tick().await;
                } else {
                    std::future::pending::<()>().await;
                }
            } => {
                send_announce(&transport_tx, &cfg.identity, RNSH_APP_NAME).await?;
            }
            _ = async {
                if let Some(shutdown) = shutdown.as_ref() {
                    shutdown.wait().await;
                } else {
                    std::future::pending::<()>().await;
                }
            } => {
                break;
            }
        }
    }

    let _ = command_tx.send(LinkManagerCommand::Shutdown).await;
    let _ = manager_task.await;
    Ok(())
}

pub async fn rnsh_client_execute(
    transport_tx: mpsc::Sender<TransportMessage>,
    mut cfg: RnshClientConfig,
) -> Result<RnshClientOutcome, RnshError> {
    let started = Instant::now();
    let deadline = started + cfg.timeout;
    let destination_hash = cfg.destination_hash;

    let pubkey = discover_pubkey(
        &transport_tx,
        destination_hash,
        remaining(deadline).min(cfg.timeout),
    )
    .await?;

    let (mut link, request_data) = Link::new_initiator(destination_hash, 1);
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

    let link_req_pkt = build_link_request_packet(destination_hash, &request_data);
    transport_tx
        .send(TransportMessage::Outbound(OutboundRequest {
            raw: link_req_pkt,
            destination_hash,
        }))
        .await
        .map_err(|_| RnshError::TransportUnavailable)?;

    let proof_body = match tokio::time::timeout(
        remaining(deadline),
        wait_for_link_proof(&mut lpkt_rx, link_id),
    )
    .await
    {
        Ok(Ok(body)) => body,
        Ok(Err(e)) => {
            cleanup_destination(&transport_tx, link_id).await;
            return Err(e);
        }
        Err(_) => {
            cleanup_destination(&transport_tx, link_id).await;
            return Err(RnshError::Timeout("link proof"));
        }
    };

    let identity_ed25519_pub: [u8; 32] = pubkey[32..64]
        .try_into()
        .map_err(|_| RnshError::ProofInvalid("remote public key length".into()))?;
    let verify_key = Ed25519PublicKey::from_bytes(&identity_ed25519_pub)
        .map_err(|e| RnshError::ProofInvalid(format!("verify key: {e}")))?;

    let rtt_data = link
        .validate_proof(&proof_body, &verify_key, &identity_ed25519_pub)
        .map_err(|e| RnshError::ProofInvalid(format!("{e:?}")))?;
    let rtt_pkt = build_data_packet(link_id, rns_wire::context::PacketContext::Lrrtt, &rtt_data);
    transport_tx
        .send(TransportMessage::Outbound(OutboundRequest {
            raw: rtt_pkt,
            destination_hash: link_id,
        }))
        .await
        .map_err(|_| RnshError::TransportUnavailable)?;

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
        transport_tx
            .send(TransportMessage::Outbound(OutboundRequest {
                raw: identify_pkt,
                destination_hash: link_id,
            }))
            .await
            .map_err(|_| RnshError::TransportUnavailable)?;
        tokio::time::sleep(Duration::from_secs_f64(post_identify_delay)).await;
    }

    let session_keys = link
        .session_keys()
        .ok_or_else(|| RnshError::LinkCrypto("no session keys".into()))?;
    let mut channel = LinkChannel::new_encrypted(link_id, link.rtt_secs(), session_keys);
    link.mark_channel_created();
    let mut pending_messages = VecDeque::new();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    send_client_message_when_ready(
        &transport_tx,
        &mut lpkt_rx,
        &mut link,
        &mut channel,
        &mut pending_messages,
        VersionInfoMessage::new(RNSH_SOFTWARE_VERSION),
        deadline,
    )
    .await?;

    loop {
        if let Some(message) = pop_or_receive_client_message(
            &transport_tx,
            &mut lpkt_rx,
            &mut link,
            &mut channel,
            &mut pending_messages,
            deadline,
        )
        .await?
        {
            match message {
                RnshMessage::VersionInfo(version) => {
                    if version.protocol_version != PROTOCOL_VERSION {
                        cleanup_destination(&transport_tx, link_id).await;
                        return Err(RnshError::Remote("incompatible rnsh protocol".into()));
                    }
                    tokio::time::sleep(Duration::from_millis(75)).await;
                    break;
                }
                RnshMessage::Error(err) => {
                    cleanup_destination(&transport_tx, link_id).await;
                    return Err(RnshError::Remote(
                        err.msg.unwrap_or_else(|| "remote error".into()),
                    ));
                }
                _ => {}
            }
        }
    }

    let execute = ExecuteCommandMessage::new(
        Some(cfg.command.clone()),
        cfg.pipe_stdin,
        cfg.pipe_stdout,
        cfg.pipe_stderr,
        None,
        cfg.term.clone(),
        cfg.rows,
        cfg.cols,
        cfg.hpix,
        cfg.vpix,
    );
    send_client_message_when_ready(
        &transport_tx,
        &mut lpkt_rx,
        &mut link,
        &mut channel,
        &mut pending_messages,
        execute,
        deadline,
    )
    .await?;

    let return_code = match run_client_io_loop(
        &transport_tx,
        &mut lpkt_rx,
        &mut link,
        &mut channel,
        &mut pending_messages,
        ClientIoState {
            stdout: &mut stdout,
            stderr: &mut stderr,
            cfg: &mut cfg,
        },
        deadline,
    )
    .await
    {
        Ok(return_code) => return_code,
        Err(error) => {
            cleanup_destination(&transport_tx, link_id).await;
            return Err(error);
        }
    };

    if let Some(close_pkt) = build_link_close(&mut link) {
        let _ = transport_tx
            .send(TransportMessage::Outbound(OutboundRequest {
                raw: close_pkt,
                destination_hash: link_id,
            }))
            .await;
    }
    cleanup_destination(&transport_tx, link_id).await;

    Ok(RnshClientOutcome {
        stdout,
        stderr,
        return_code,
    })
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
    lpkt_rx: &mut mpsc::Receiver<DestinationEvent>,
    link: &mut Link,
    channel: &mut LinkChannel,
    pending_messages: &mut VecDeque<RnshMessage>,
    io: ClientIoState<'_>,
    deadline: Instant,
) -> Result<i64, RnshError> {
    let ClientIoState {
        stdout,
        stderr,
        cfg,
    } = io;

    let mut stdin_rx = cfg.stdin_rx.take();
    if stdin_rx.is_none() && cfg.pipe_stdin {
        let (tx, rx) = mpsc::channel(16);
        let stdin_data = std::mem::take(&mut cfg.stdin_data);
        tokio::spawn(async move {
            for chunk in stdin_data.chunks(CLIENT_CHUNK_LEN) {
                if tx.send(chunk.to_vec()).await.is_err() {
                    return;
                }
            }
            let _ = tx.send(Vec::new()).await;
        });
        stdin_rx = Some(rx);
    }
    let mut stdin_eof_sent = stdin_rx.is_none();
    let stdout_tx = cfg.stdout_tx.take();
    let stderr_tx = cfg.stderr_tx.take();
    let mut window_rx = cfg.window_rx.take();

    loop {
        while let Some(message) = pending_messages.pop_front() {
            if let Some(return_code) = handle_client_message(
                transport_tx,
                link,
                channel,
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

        resend_timed_out_client_channel_messages(transport_tx, link, channel).await?;
        if Instant::now() >= deadline {
            return Err(RnshError::Timeout("rnsh channel"));
        }

        let retry_wait = channel
            .next_timeout_duration()
            .unwrap_or_else(|| Duration::from_secs(1))
            .min(Duration::from_secs(1))
            .min(remaining(deadline));
        let deadline_wait = remaining(deadline);

        tokio::select! {
            maybe_event = lpkt_rx.recv() => {
                let Some(event) = maybe_event else {
                    return Err(RnshError::HandshakeFailed("link channel closed".into()));
                };
                process_client_destination_event(
                    transport_tx,
                    link,
                    channel,
                    pending_messages,
                    event,
                ).await?;
            }
            maybe_chunk = recv_optional_stdin_chunk(&mut stdin_rx), if !stdin_eof_sent => {
                match maybe_chunk {
                    Some(data) if !data.is_empty() => {
                        for chunk in data.chunks(CLIENT_CHUNK_LEN) {
                            if pending_has_remote_terminal(pending_messages) {
                                break;
                            }
                            send_client_message_when_ready(
                                transport_tx,
                                lpkt_rx,
                                link,
                                channel,
                                pending_messages,
                                RnshStreamDataMessage::new(STREAM_ID_STDIN, chunk.to_vec(), false),
                                deadline,
                            ).await?;
                        }
                    }
                    Some(_) | None => {
                        if !pending_has_remote_terminal(pending_messages) {
                            drain_client_messages_before_stdin_eof(
                                transport_tx,
                                lpkt_rx,
                                link,
                                channel,
                                pending_messages,
                                deadline,
                            )
                            .await?;
                        }
                        if !pending_has_remote_terminal(pending_messages) {
                            send_client_message_when_ready(
                                transport_tx,
                                lpkt_rx,
                                link,
                                channel,
                                pending_messages,
                                RnshStreamDataMessage::new(STREAM_ID_STDIN, Vec::new(), true),
                                deadline,
                            ).await?;
                        }
                        stdin_eof_sent = true;
                    }
                }
            }
            maybe_window = recv_optional_window_size(&mut window_rx) => {
                match maybe_window {
                    Some(window) => {
                        send_client_message_when_ready(
                            transport_tx,
                            lpkt_rx,
                            link,
                            channel,
                            pending_messages,
                            WindowSizeMessage::new(window.rows, window.cols, window.hpix, window.vpix),
                            deadline,
                        ).await?;
                    }
                    None => {
                        window_rx = None;
                    }
                }
            }
            _ = tokio::time::sleep(retry_wait) => {}
            _ = tokio::time::sleep(deadline_wait) => {
                return Err(RnshError::Timeout("rnsh channel"));
            }
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
    transport_tx: &mpsc::Sender<TransportMessage>,
    link: &mut Link,
    channel: &mut LinkChannel,
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
                if let Some(tx) = stdout_tx {
                    if !stream.data.is_empty() {
                        tx.send(stream.data).await.map_err(|_| {
                            RnshError::Process("stdout stream receiver closed".into())
                        })?;
                    }
                }
                Ok(None)
            }
            STREAM_ID_STDERR => {
                stderr.extend_from_slice(&stream.data);
                if let Some(tx) = stderr_tx {
                    if !stream.data.is_empty() {
                        tx.send(stream.data).await.map_err(|_| {
                            RnshError::Process("stderr stream receiver closed".into())
                        })?;
                    }
                }
                Ok(None)
            }
            _ => Ok(None),
        },
        RnshMessage::CommandExited(exited) => Ok(Some(exited.return_code)),
        RnshMessage::Error(err) => Err(RnshError::Remote(
            err.msg.unwrap_or_else(|| "remote error".into()),
        )),
        RnshMessage::Noop(_) => {
            let _ = send_client_channel_message(transport_tx, link, channel, &NoopMessage).await;
            Ok(None)
        }
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
    stdin: ProcessInput,
    window: Option<PtyWindowTarget>,
    cleanup: ListenerProcessCleanup,
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
            #[cfg(target_os = "android")]
            let tiocsctty = nix::libc::TIOCSCTTY as nix::libc::c_int;
            #[cfg(not(target_os = "android"))]
            let tiocsctty = nix::libc::TIOCSCTTY as nix::libc::c_ulong;
            if nix::libc::ioctl(slave_fd, tiocsctty, 0) == -1 {
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
) -> Result<(), RnshError> {
    // Sessions are created only on link establishment or on an allowed
    // identification — a stray channel message must never fabricate one.
    let Some(session) = sessions.get_mut(&msg.link_id) else {
        return Ok(());
    };

    // Drop everything on an unauthorized or terminally-closed session.
    if !session.authorized || session.state == ListenerState::Closed {
        return Ok(());
    }

    let decoded = RnshMessage::decode(msg.msg_type, &msg.payload)
        .map_err(|e| RnshError::Channel(e.to_string()))?;

    match session.state {
        ListenerState::Closed => Ok(()),
        ListenerState::WaitIdent => Ok(()),
        ListenerState::WaitVersion => match decoded {
            RnshMessage::VersionInfo(version) => {
                if version.protocol_version != PROTOCOL_VERSION {
                    send_manager_message(
                        command_tx,
                        msg.link_id,
                        ErrorMessage::new(Some("Incompatible protocol".into()), true, None),
                    )
                    .await?;
                    return Err(RnshError::Remote("incompatible rnsh protocol".into()));
                }
                send_manager_message(
                    command_tx,
                    msg.link_id,
                    VersionInfoMessage::new(RNSH_SOFTWARE_VERSION),
                )
                .await?;
                session.state = ListenerState::WaitCommand;
                Ok(())
            }
            _ => {
                send_manager_message(
                    command_tx,
                    msg.link_id,
                    ErrorMessage::new(
                        Some("Protocol error (LSSTATE_WAIT_VERS)".into()),
                        true,
                        None,
                    ),
                )
                .await
            }
        },
        ListenerState::WaitCommand => match decoded {
            RnshMessage::ExecuteCommand(execute) => {
                let command = match select_listener_command(
                    &cfg.command,
                    execute.cmdline.as_deref(),
                    cfg.allow_remote_command,
                    cfg.remote_command_as_args,
                ) {
                    Ok(command) => command,
                    Err(reason) => {
                        send_manager_message(
                            command_tx,
                            msg.link_id,
                            ErrorMessage::new(Some(reason), true, None),
                        )
                        .await?;
                        close_link_after_error(command_tx.clone(), msg.link_id);
                        return Ok(());
                    }
                };
                let stdin = match start_listener_process(
                    command_tx.clone(),
                    msg.link_id,
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
                    },
                )
                .await
                {
                    Ok(stdin) => stdin,
                    Err(error) => {
                        send_manager_message(
                            command_tx,
                            msg.link_id,
                            ErrorMessage::new(Some(error.to_string()), true, None),
                        )
                        .await?;
                        close_link_after_error(command_tx.clone(), msg.link_id);
                        return Ok(());
                    }
                };
                session.stdin = Some(stdin.stdin);
                session.window = stdin.window;
                session.process_cleanup = Some(stdin.cleanup);
                session.state = ListenerState::Running;
                Ok(())
            }
            _ => {
                send_manager_message(
                    command_tx,
                    msg.link_id,
                    ErrorMessage::new(Some("Protocol error (LSSTATE_WAIT_CMD)".into()), true, None),
                )
                .await
            }
        },
        ListenerState::Running => match decoded {
            RnshMessage::StreamData(stream) => {
                if stream.stream_id != STREAM_ID_STDIN {
                    send_manager_message(
                        command_tx,
                        msg.link_id,
                        ErrorMessage::new(
                            Some("Protocol error (LSSTATE_RUNNING)".into()),
                            true,
                            None,
                        ),
                    )
                    .await?;
                    return Ok(());
                }
                if let Some(stdin) = session.stdin.as_mut() {
                    if !stream.data.is_empty() {
                        stdin.write_all(&stream.data).await?;
                    }
                }
                if stream.eof {
                    if let Some(stdin) = session.stdin.as_mut() {
                        stdin.eof().await?;
                    }
                    if session
                        .stdin
                        .as_ref()
                        .is_some_and(|stdin| matches!(stdin, ProcessInput::Pipe(_)))
                    {
                        session.stdin.take();
                    }
                }
                Ok(())
            }
            RnshMessage::WindowSize(window) => {
                if let Some(target) = session.window.as_ref() {
                    target.set_size(window.rows, window.cols, window.hpix, window.vpix)?;
                }
                Ok(())
            }
            RnshMessage::Noop(_) => {
                send_manager_message(command_tx, msg.link_id, NoopMessage).await
            }
            _ => Ok(()),
        },
    }
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
    } = request;

    if command.is_empty() {
        return Err(RnshError::Process("no command specified".into()));
    }

    let uses_pty = !(pipe_stdin && pipe_stdout && pipe_stderr);
    let mut cmd = Command::new(&command[0]);
    cmd.args(&command[1..])
        .env("TERM", term.unwrap_or("xterm"))
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

    let mut child = cmd
        .spawn()
        .map_err(|e| RnshError::Process(format!("could not start {}: {e}", command[0])))?;

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

    let mut reader_tasks = Vec::new();
    if pipe_stdout {
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| RnshError::Process("could not open process stdout".into()))?;
        reader_tasks.push(tokio::spawn(stream_reader_task(
            command_tx.clone(),
            link_id,
            STREAM_ID_STDOUT,
            stdout,
        )));
    }
    if pipe_stderr {
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| RnshError::Process("could not open process stderr".into()))?;
        reader_tasks.push(tokio::spawn(stream_reader_task(
            command_tx.clone(),
            link_id,
            STREAM_ID_STDERR,
            stderr,
        )));
    }
    if let Some(ref pty) = pty {
        if !pipe_stdout || !pipe_stderr {
            let stream_id = if !pipe_stdout {
                STREAM_ID_STDOUT
            } else {
                STREAM_ID_STDERR
            };
            reader_tasks.push(tokio::spawn(stream_reader_task(
                command_tx.clone(),
                link_id,
                stream_id,
                pty_reader_file(pty)?,
            )));
        }
    }

    let window = pty.take().map(pty_window_target);
    let child_pid = if uses_pty { child.id() } else { None };
    let (stop_tx, stop_rx) = oneshot::channel();
    tokio::spawn(async move {
        let mut stopped = false;
        let code = tokio::select! {
            status = child.wait() => {
                match status {
                    Ok(status) => status.code().unwrap_or(255) as i64,
                    Err(_) => 255,
                }
            }
            _ = stop_rx => {
                stopped = true;
                terminate_child_process_group(child_pid, SIGTERM_NUM);
                tokio::time::sleep(Duration::from_millis(200)).await;
                match tokio::time::timeout(Duration::from_millis(500), child.wait()).await {
                    Ok(Ok(status)) => status.code().unwrap_or(255) as i64,
                    _ => {
                        terminate_child_process_group(child_pid, SIGKILL_NUM);
                        let _ = child.kill().await;
                        255
                    }
                }
            }
        };
        for task in reader_tasks {
            let _ = task.await;
        }
        if !stopped {
            let _ =
                send_manager_message(&command_tx, link_id, CommandExitedMessage::new(code)).await;
        }
    });

    Ok(ListenerProcess {
        stdin,
        window,
        cleanup: ListenerProcessCleanup {
            stop_tx: Some(stop_tx),
        },
    })
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

fn close_link_after_error(command_tx: mpsc::Sender<LinkManagerCommand>, link_id: [u8; 16]) {
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(750)).await;
        let _ = command_tx
            .send(LinkManagerCommand::CloseLink {
                link_id,
                reason: CloseReason::DestinationClosed,
                send_teardown: true,
            })
            .await;
    });
}

async fn stream_reader_task<R>(
    command_tx: mpsc::Sender<LinkManagerCommand>,
    link_id: [u8; 16],
    stream_id: u16,
    mut reader: R,
) where
    R: AsyncRead + Unpin,
{
    let mut buf = [0u8; CLIENT_CHUNK_LEN];
    loop {
        match reader.read(&mut buf).await {
            Ok(0) => break,
            Ok(n) => {
                let msg = RnshStreamDataMessage::new(stream_id, buf[..n].to_vec(), false);
                if send_manager_message(&command_tx, link_id, msg)
                    .await
                    .is_err()
                {
                    return;
                }
            }
            Err(_) => break,
        }
    }
    let _ = send_manager_message(
        &command_tx,
        link_id,
        RnshStreamDataMessage::new(stream_id, Vec::new(), true),
    )
    .await;
}

async fn send_manager_message<M>(
    command_tx: &mpsc::Sender<LinkManagerCommand>,
    link_id: [u8; 16],
    message: M,
) -> Result<(), RnshError>
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
            Ok(_) => return Ok(()),
            Err(ChannelSendError::Channel(ChannelError::NotReady)) => {
                tokio::time::sleep(CHANNEL_SEND_RETRY).await;
            }
            Err(ChannelSendError::LinkNotFound) => {
                return Err(RnshError::Channel("link not found".into()));
            }
            Err(e) => return Err(RnshError::Channel(e.to_string())),
        }
    }
}

async fn send_client_message_when_ready<M>(
    transport_tx: &mpsc::Sender<TransportMessage>,
    lpkt_rx: &mut mpsc::Receiver<DestinationEvent>,
    link: &mut Link,
    channel: &mut LinkChannel,
    pending_messages: &mut VecDeque<RnshMessage>,
    message: M,
    deadline: Instant,
) -> Result<(), RnshError>
where
    M: MessageBase,
{
    loop {
        match send_client_channel_message(transport_tx, link, channel, &message).await {
            Ok(()) => return Ok(()),
            Err(RnshError::Channel(err)) if err.contains("not ready") => {
                let _ = receive_client_messages(
                    transport_tx,
                    lpkt_rx,
                    link,
                    channel,
                    pending_messages,
                    deadline,
                    Duration::from_millis(100),
                )
                .await?;
            }
            Err(e) => return Err(e),
        }
    }
}

async fn send_client_channel_message(
    transport_tx: &mpsc::Sender<TransportMessage>,
    link: &mut Link,
    channel: &mut LinkChannel,
    message: &dyn MessageBase,
) -> Result<(), RnshError> {
    let prepared = channel.prepare_send_tracked(message)?;
    send_client_channel_data(
        transport_tx,
        link,
        channel,
        prepared.sequence,
        &prepared.data,
    )
    .await
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
    transport_tx
        .send(TransportMessage::Outbound(OutboundRequest {
            raw: Bytes::from(raw),
            destination_hash: link_id,
        }))
        .await
        .map_err(|_| RnshError::TransportUnavailable)
}

async fn resend_timed_out_client_channel_messages(
    transport_tx: &mpsc::Sender<TransportMessage>,
    link: &mut Link,
    channel: &mut LinkChannel,
) -> Result<(), RnshError> {
    for sequence in channel.timed_out_sequences() {
        let Some(data) = channel.timeout(sequence)? else {
            continue;
        };
        send_client_channel_data(transport_tx, link, channel, sequence, &data).await?;
    }
    Ok(())
}

async fn pop_or_receive_client_message(
    transport_tx: &mpsc::Sender<TransportMessage>,
    lpkt_rx: &mut mpsc::Receiver<DestinationEvent>,
    link: &mut Link,
    channel: &mut LinkChannel,
    pending_messages: &mut VecDeque<RnshMessage>,
    deadline: Instant,
) -> Result<Option<RnshMessage>, RnshError> {
    if let Some(message) = pending_messages.pop_front() {
        return Ok(Some(message));
    }
    receive_client_messages(
        transport_tx,
        lpkt_rx,
        link,
        channel,
        pending_messages,
        deadline,
        remaining(deadline),
    )
    .await?;
    Ok(pending_messages.pop_front())
}

async fn drain_client_messages_before_stdin_eof(
    transport_tx: &mpsc::Sender<TransportMessage>,
    lpkt_rx: &mut mpsc::Receiver<DestinationEvent>,
    link: &mut Link,
    channel: &mut LinkChannel,
    pending_messages: &mut VecDeque<RnshMessage>,
    deadline: Instant,
) -> Result<(), RnshError> {
    let rtt_scaled = Duration::from_secs_f64((link.rtt_secs() * 5.0).max(0.0));
    let drain_for = rtt_scaled
        .max(CLIENT_PRE_EOF_DRAIN_MIN)
        .min(CLIENT_PRE_EOF_DRAIN_MAX)
        .min(remaining(deadline));
    let drain_until = Instant::now() + drain_for;

    while Instant::now() < drain_until && !pending_has_remote_terminal(pending_messages) {
        let wait =
            CLIENT_PRE_EOF_DRAIN_POLL.min(drain_until.saturating_duration_since(Instant::now()));
        if wait.is_zero() {
            break;
        }
        receive_client_messages(
            transport_tx,
            lpkt_rx,
            link,
            channel,
            pending_messages,
            deadline,
            wait,
        )
        .await?;
    }

    Ok(())
}

async fn receive_client_messages(
    transport_tx: &mpsc::Sender<TransportMessage>,
    lpkt_rx: &mut mpsc::Receiver<DestinationEvent>,
    link: &mut Link,
    channel: &mut LinkChannel,
    pending_messages: &mut VecDeque<RnshMessage>,
    deadline: Instant,
    wait: Duration,
) -> Result<bool, RnshError> {
    if Instant::now() >= deadline {
        return Err(RnshError::Timeout("rnsh channel"));
    }
    resend_timed_out_client_channel_messages(transport_tx, link, channel).await?;
    let wait = wait
        .min(channel.next_timeout_duration().unwrap_or(wait))
        .min(remaining(deadline));
    let event = match tokio::time::timeout(wait, lpkt_rx.recv()).await {
        Ok(Some(event)) => event,
        Ok(None) => return Err(RnshError::HandshakeFailed("link channel closed".into())),
        Err(_) => {
            resend_timed_out_client_channel_messages(transport_tx, link, channel).await?;
            return Ok(false);
        }
    };

    process_client_destination_event(transport_tx, link, channel, pending_messages, event).await
}

async fn process_client_destination_event(
    transport_tx: &mpsc::Sender<TransportMessage>,
    link: &mut Link,
    channel: &mut LinkChannel,
    pending_messages: &mut VecDeque<RnshMessage>,
    event: DestinationEvent,
) -> Result<bool, RnshError> {
    let DestinationEvent::InboundPacket { raw, .. } = event else {
        return Ok(false);
    };
    let (header, data_offset) = match rns_wire::header::PacketHeader::unpack(&raw) {
        Ok(parsed) => parsed,
        Err(_) => return Ok(false),
    };
    if header.destination_hash != *channel.link_id() {
        return Ok(false);
    }
    let body = &raw[data_offset..];
    match header.flags.packet_type {
        rns_wire::flags::PacketType::Proof if body.len() >= 96 => {
            let mut packet_hash = [0u8; 32];
            packet_hash.copy_from_slice(&body[..32]);
            if link.validate_packet_proof(&packet_hash, body) {
                channel.delivered_by_packet_hash(&packet_hash, link.rtt_secs());
            }
        }
        rns_wire::flags::PacketType::Data => match header.context {
            rns_wire::context::PacketContext::Keepalive
                if body.first() == Some(&rns_link::constants::KEEPALIVE_REQUEST) =>
            {
                send_keepalive_response(transport_tx, *channel.link_id()).await?;
            }
            rns_wire::context::PacketContext::LinkClose if link.receive_teardown(body) => {
                return Err(RnshError::HandshakeFailed("link closed by remote".into()));
            }
            rns_wire::context::PacketContext::Channel => {
                link.record_inbound();
                let packet_hash = rns_wire::hash::packet_hash(&raw, header.flags.header_type);
                if let Ok(proof_data) = link.prove_packet_with_link_key(&packet_hash) {
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
) -> Result<[u8; 64], RnshError> {
    if let Some(pk) = lookup_pubkey(transport_tx, dest_hash).await? {
        return Ok(pk);
    }

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

async fn wait_for_link_proof(
    rx: &mut mpsc::Receiver<DestinationEvent>,
    link_id: [u8; 16],
) -> Result<Vec<u8>, RnshError> {
    while let Some(event) = rx.recv().await {
        let DestinationEvent::InboundPacket { raw, .. } = event else {
            continue;
        };
        let Ok((header, data_offset)) = rns_wire::header::PacketHeader::unpack(&raw) else {
            continue;
        };
        if header.flags.packet_type == rns_wire::flags::PacketType::Proof
            && header.destination_hash == link_id
            && raw.len() > data_offset
        {
            return Ok(raw[data_offset..].to_vec());
        }
    }
    Err(RnshError::HandshakeFailed("channel closed".into()))
}

async fn cleanup_destination(transport_tx: &mpsc::Sender<TransportMessage>, link_id: [u8; 16]) {
    let _ = transport_tx.try_send(TransportMessage::DeregisterDestination { hash: link_id });
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
    transport_tx
        .send(TransportMessage::Outbound(OutboundRequest {
            raw,
            destination_hash: link_id,
        }))
        .await
        .map_err(|_| RnshError::TransportUnavailable)
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
    transport_tx
        .send(TransportMessage::Outbound(OutboundRequest {
            raw: Bytes::from(raw),
            destination_hash: link_id,
        }))
        .await
        .map_err(|_| RnshError::TransportUnavailable)
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

async fn send_announce(
    tx: &mpsc::Sender<TransportMessage>,
    identity: &Identity,
    app_name: &str,
) -> Result<(), RnshError> {
    let raw = build_announce_packet(identity, app_name)?;
    let dest_hash = Destination::hash_from_name_and_identity(app_name, Some(&identity.hash));
    tx.send(TransportMessage::Outbound(OutboundRequest {
        raw: Bytes::from(raw),
        destination_hash: dest_hash,
    }))
    .await
    .map_err(|_| RnshError::TransportUnavailable)
}

fn build_announce_packet(identity: &Identity, app_name: &str) -> Result<Vec<u8>, RnshError> {
    let announce = rns_identity::announce::AnnounceData::create(identity, app_name, None, None)
        .map_err(|e| RnshError::LinkCrypto(format!("announce: {e}")))?;
    let dest_hash = Destination::hash_from_name_and_identity(app_name, Some(&identity.hash));
    let header = rns_wire::header::PacketHeader {
        flags: rns_wire::flags::PacketFlags {
            header_type: rns_wire::flags::HeaderType::Header1,
            context_flag: false,
            transport_type: rns_wire::flags::TransportType::Broadcast,
            destination_type: rns_wire::flags::DestinationType::Single,
            packet_type: rns_wire::flags::PacketType::Announce,
        },
        hops: 0,
        transport_id: None,
        destination_hash: dest_hash,
        context: rns_wire::context::PacketContext::None,
    };
    let mut raw = header.pack();
    raw.extend_from_slice(&announce.pack());
    Ok(raw)
}

fn remaining(deadline: Instant) -> Duration {
    deadline.saturating_duration_since(Instant::now())
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

fn listener_allowed_identities(cfg: &RnshListenerConfig) -> HashSet<[u8; 16]> {
    let mut allowed: HashSet<[u8; 16]> = cfg.allowed.iter().copied().collect();
    for path in &cfg.allowed_identity_files {
        let Ok(content) = std::fs::read_to_string(path) else {
            continue;
        };
        for line in content.replace('\r', "").lines() {
            if let Some(hash) = parse_identity_hash16(line.trim()) {
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
            },
        )
        .await
        .expect("start pty process");

        process.stdin.write_all(&[0x04]).await.expect("send ctrl-d");
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
            },
        )
        .await
        .expect("start pty process");

        wait_for_stream_text(&messages, "ready\n").await;
        process.stdin.write_all(&[0x03]).await.expect("send ctrl-c");
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
        )
        .await
        .expect("handler ok");
        handle_listener_channel_message(
            &command_tx,
            &cfg,
            &mut sessions,
            execute_command_channel_msg(link_id),
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
        )
        .await
        .expect("handler ok");
        handle_listener_channel_message(
            &command_tx,
            &cfg,
            &mut sessions,
            execute_command_channel_msg(link_id),
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
}
