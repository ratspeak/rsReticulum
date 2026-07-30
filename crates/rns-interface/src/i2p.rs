//! Reticulum-over-I2P via SAM v3.1 bridge (default 127.0.0.1:7656).
//! Handshake: HELLO → SESSION CREATE → STREAM CONNECT/ACCEPT;
//! stream then carries HDLC-framed packets.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use bytes::Bytes;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

use crate::hdlc;
use crate::traits::{
    InterfaceDirection, InterfaceHandle, InterfaceId, InterfaceMode, handoff_accepted_interface,
};
use rns_transport::messages::{InboundPacket, TransportMessage};

pub const DEFAULT_SAM_ADDRESS: &str = "127.0.0.1";
pub const DEFAULT_SAM_PORT: u16 = 7656;

pub const BITRATE_GUESS: u64 = 256_000;
pub const HW_MTU: u32 = 1064;

pub const I2P_TCP_USER_TIMEOUT: u32 = 45;
pub const I2P_PROBE_AFTER: u64 = 10;
pub const I2P_PROBE_INTERVAL: u64 = 9;
pub const I2P_PROBES: u64 = 5;

/// 2× full probe cycle for safety margin.
pub const I2P_READ_TIMEOUT: u64 = (I2P_PROBE_INTERVAL * I2P_PROBES + I2P_PROBE_AFTER) * 2;

pub const TUNNEL_KEEPALIVE: u64 = 300;
pub const RECONNECT_WAIT: u64 = 15;
pub const RECONNECT_WAIT_MAX: u64 = 300;

pub const SAM_VERSION: &str = "3.1";

#[derive(Debug, thiserror::Error)]
pub enum SamError {
    #[error("SAM I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("SAM handshake failed: {0}")]
    HandshakeFailed(String),
    #[error("SAM session creation failed: {0}")]
    SessionFailed(String),
    #[error("SAM stream connect failed: {0}")]
    StreamFailed(String),
    #[error("SAM stream accept failed: {0}")]
    AcceptFailed(String),
    #[error("unexpected SAM reply: {0}")]
    UnexpectedReply(String),
}

/// Parse SAM reply; bare tokens (no `=`) get empty value.
pub fn parse_sam_reply(line: &str) -> Vec<(String, String)> {
    let mut pairs = Vec::new();
    for token in line.split_whitespace() {
        if let Some(eq_pos) = token.find('=') {
            let key = token[..eq_pos].to_string();
            let value = token[eq_pos + 1..].to_string();
            pairs.push((key, value));
        } else {
            pairs.push((token.to_string(), String::new()));
        }
    }
    pairs
}

pub fn sam_reply_get<'a>(pairs: &'a [(String, String)], key: &str) -> Option<&'a str> {
    pairs
        .iter()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.as_str())
}

pub fn sam_reply_has_token(pairs: &[(String, String)], token: &str) -> bool {
    pairs.iter().any(|(k, v)| k == token && v.is_empty())
}

async fn read_sam_reply(
    reader: &mut BufReader<tokio::net::tcp::OwnedReadHalf>,
) -> Result<String, SamError> {
    let mut line = String::new();
    let n = reader.read_line(&mut line).await?;
    if n == 0 {
        return Err(SamError::Io(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "SAM connection closed during handshake",
        )));
    }
    Ok(line.trim_end().to_string())
}

async fn sam_hello(
    writer: &mut tokio::net::tcp::OwnedWriteHalf,
    reader: &mut BufReader<tokio::net::tcp::OwnedReadHalf>,
) -> Result<(), SamError> {
    let hello_msg = format!("HELLO VERSION MIN={} MAX={}\n", SAM_VERSION, SAM_VERSION);
    writer.write_all(hello_msg.as_bytes()).await?;
    writer.flush().await?;

    let reply = read_sam_reply(reader).await?;
    let pairs = parse_sam_reply(&reply);

    if !sam_reply_has_token(&pairs, "HELLO") || !sam_reply_has_token(&pairs, "REPLY") {
        return Err(SamError::HandshakeFailed(format!(
            "expected HELLO REPLY, got: {}",
            reply
        )));
    }

    match sam_reply_get(&pairs, "RESULT") {
        Some("OK") => Ok(()),
        Some(other) => Err(SamError::HandshakeFailed(format!(
            "HELLO RESULT={}, expected OK",
            other
        ))),
        None => Err(SamError::HandshakeFailed(format!(
            "no RESULT in HELLO reply: {}",
            reply
        ))),
    }
}

/// Returns the destination (base64). `private_key=None` = transient.
async fn sam_session_create(
    writer: &mut tokio::net::tcp::OwnedWriteHalf,
    reader: &mut BufReader<tokio::net::tcp::OwnedReadHalf>,
    session_id: &str,
    private_key: Option<&str>,
) -> Result<String, SamError> {
    let dest_param = match private_key {
        Some(key) => key.to_string(),
        None => "TRANSIENT".to_string(),
    };
    let create_msg = format!(
        "SESSION CREATE STYLE=STREAM ID={} DESTINATION={}\n",
        session_id, dest_param
    );
    writer.write_all(create_msg.as_bytes()).await?;
    writer.flush().await?;

    let reply = read_sam_reply(reader).await?;
    let pairs = parse_sam_reply(&reply);

    if !sam_reply_has_token(&pairs, "SESSION") || !sam_reply_has_token(&pairs, "STATUS") {
        return Err(SamError::SessionFailed(format!(
            "expected SESSION STATUS, got: {}",
            reply
        )));
    }

    match sam_reply_get(&pairs, "RESULT") {
        Some("OK") => {}
        Some(other) => {
            let msg_detail = sam_reply_get(&pairs, "MESSAGE").unwrap_or("no details");
            return Err(SamError::SessionFailed(format!(
                "SESSION RESULT={}: {}",
                other, msg_detail
            )));
        }
        None => {
            return Err(SamError::SessionFailed(format!(
                "no RESULT in SESSION STATUS: {}",
                reply
            )));
        }
    }

    match sam_reply_get(&pairs, "DESTINATION") {
        Some(dest) => Ok(dest.to_string()),
        None => Err(SamError::SessionFailed(
            "SESSION STATUS OK but no DESTINATION returned".to_string(),
        )),
    }
}

/// SAM STREAM CONNECT — needs its own TCP connection (SAM forbids sharing
/// the session control socket). On OK the socket becomes the data stream.
async fn sam_stream_connect(
    writer: &mut tokio::net::tcp::OwnedWriteHalf,
    reader: &mut BufReader<tokio::net::tcp::OwnedReadHalf>,
    session_id: &str,
    peer_destination: &str,
) -> Result<(), SamError> {
    let connect_msg = format!(
        "STREAM CONNECT ID={} DESTINATION={} SILENT=false\n",
        session_id, peer_destination
    );
    writer.write_all(connect_msg.as_bytes()).await?;
    writer.flush().await?;

    let reply = read_sam_reply(reader).await?;
    let pairs = parse_sam_reply(&reply);

    if !sam_reply_has_token(&pairs, "STREAM") || !sam_reply_has_token(&pairs, "STATUS") {
        return Err(SamError::StreamFailed(format!(
            "expected STREAM STATUS, got: {}",
            reply
        )));
    }

    match sam_reply_get(&pairs, "RESULT") {
        Some("OK") => Ok(()),
        Some(other) => {
            let msg_detail = sam_reply_get(&pairs, "MESSAGE").unwrap_or("no details");
            Err(SamError::StreamFailed(format!(
                "STREAM CONNECT RESULT={}: {}",
                other, msg_detail
            )))
        }
        None => Err(SamError::StreamFailed(format!(
            "no RESULT in STREAM STATUS: {}",
            reply
        ))),
    }
}

/// SAM STREAM ACCEPT (separate socket; same requirement as connect).
/// Returns the remote peer's destination after the status line.
async fn sam_stream_accept(
    writer: &mut tokio::net::tcp::OwnedWriteHalf,
    reader: &mut BufReader<tokio::net::tcp::OwnedReadHalf>,
    session_id: &str,
) -> Result<String, SamError> {
    let accept_msg = format!("STREAM ACCEPT ID={} SILENT=false\n", session_id);
    writer.write_all(accept_msg.as_bytes()).await?;
    writer.flush().await?;

    let reply = read_sam_reply(reader).await?;
    let pairs = parse_sam_reply(&reply);

    if !sam_reply_has_token(&pairs, "STREAM") || !sam_reply_has_token(&pairs, "STATUS") {
        return Err(SamError::AcceptFailed(format!(
            "expected STREAM STATUS, got: {}",
            reply
        )));
    }

    match sam_reply_get(&pairs, "RESULT") {
        Some("OK") => {}
        Some(other) => {
            let msg_detail = sam_reply_get(&pairs, "MESSAGE").unwrap_or("no details");
            return Err(SamError::AcceptFailed(format!(
                "STREAM ACCEPT RESULT={}: {}",
                other, msg_detail
            )));
        }
        None => {
            return Err(SamError::AcceptFailed(format!(
                "no RESULT in STREAM STATUS: {}",
                reply
            )));
        }
    }

    // SAM writes peer destination on its own line before raw data.
    let dest_line = read_sam_reply(reader).await?;
    Ok(dest_line.trim().to_string())
}

async fn connect_to_sam(sam_host: &str, sam_port: u16) -> Result<TcpStream, SamError> {
    let addr = format!("{}:{}", sam_host, sam_port);
    let stream = TcpStream::connect(&addr).await.map_err(SamError::Io)?;
    let _ = stream.set_nodelay(true);
    // Python i2p_tunneled tuning: longer probes/timeout to absorb I2P latency.
    crate::socket_tuning::set_keepalive_tuned(
        &stream,
        std::time::Duration::from_secs(I2P_PROBE_AFTER),
        std::time::Duration::from_secs(I2P_PROBE_INTERVAL),
        I2P_PROBES as u32,
        std::time::Duration::from_secs(I2P_TCP_USER_TIMEOUT as u64),
    );
    Ok(stream)
}

fn generate_session_id() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let id: u64 = rng.r#gen();
    format!("reticulum_{:016x}", id)
}

#[derive(Debug, Clone)]
pub struct I2PServerConfig {
    pub name: String,
    pub sam_host: String,
    pub sam_port: u16,
    /// Base64 private key for a persistent destination; `None` = transient.
    pub keyfile: Option<String>,
    pub reconnect_delay: u64,
    pub mode: InterfaceMode,
}

impl I2PServerConfig {
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            sam_host: DEFAULT_SAM_ADDRESS.to_string(),
            sam_port: DEFAULT_SAM_PORT,
            keyfile: None,
            reconnect_delay: RECONNECT_WAIT,
            mode: InterfaceMode::Full,
        }
    }
}

#[derive(Debug, Clone)]
pub struct I2PClientConfig {
    pub name: String,
    pub sam_host: String,
    pub sam_port: u16,
    /// Peer I2P destination (base64).
    pub peer_destination: String,
    /// Reconnect attempt cap; `None` = unlimited.
    pub max_reconnect_tries: Option<usize>,
    pub reconnect_delay: u64,
    pub mode: InterfaceMode,
}

impl I2PClientConfig {
    pub fn new(name: &str, peer_dest: &str) -> Self {
        Self {
            name: name.to_string(),
            sam_host: DEFAULT_SAM_ADDRESS.to_string(),
            sam_port: DEFAULT_SAM_PORT,
            peer_destination: peer_dest.to_string(),
            max_reconnect_tries: None,
            reconnect_delay: RECONNECT_WAIT,
            mode: InterfaceMode::Full,
        }
    }
}

/// Connect via SAM streaming session, run HDLC-framed I/O; exponential reconnect.
pub async fn spawn_i2p_client(
    config: I2PClientConfig,
    id: InterfaceId,
    transport_tx: mpsc::Sender<TransportMessage>,
) -> Result<InterfaceHandle, crate::traits::InterfaceError> {
    let online = Arc::new(AtomicBool::new(false));
    let shared_rxb = Arc::new(AtomicU64::new(0));
    let shared_txb = Arc::new(AtomicU64::new(0));
    let (tx, rx) = mpsc::channel::<Bytes>(256);
    let name = config.name.clone();
    let mode = config.mode;

    // rx survives reconnects; per-connection writer leases it each cycle.
    let rx = Arc::new(tokio::sync::Mutex::new(rx));

    let online_task = online.clone();
    let task_rxb = shared_rxb.clone();
    let task_txb = shared_txb.clone();

    let read_task = tokio::spawn(async move {
        let mut pacer = ReconnectPacer::new(config.reconnect_delay, config.max_reconnect_tries);

        loop {
            let session_id = generate_session_id();

            let session_stream = match connect_to_sam(&config.sam_host, config.sam_port).await {
                Ok(s) => s,
                Err(e) => {
                    tracing::warn!(
                        name = %config.name,
                        error = %e,
                        "I2P client: failed to connect to SAM bridge"
                    );
                    if pacer.give_up() {
                        tracing::warn!(name = %config.name, "I2P client: max reconnect tries reached");
                        let _ = transport_tx
                            .send(TransportMessage::DeregisterInterface { id })
                            .await;
                        return;
                    }
                    pacer.wait().await;
                    continue;
                }
            };

            let (session_reader, mut session_writer) = session_stream.into_split();
            let mut session_buf_reader = BufReader::new(session_reader);

            if let Err(e) = sam_hello(&mut session_writer, &mut session_buf_reader).await {
                tracing::warn!(
                    name = %config.name,
                    error = %e,
                    "I2P client: SAM HELLO failed"
                );
                if pacer.give_up() {
                    tracing::warn!(name = %config.name, "I2P client: max reconnect tries reached");
                    let _ = transport_tx
                        .send(TransportMessage::DeregisterInterface { id })
                        .await;
                    return;
                }
                pacer.wait().await;
                continue;
            }

            let _our_dest = match sam_session_create(
                &mut session_writer,
                &mut session_buf_reader,
                &session_id,
                None,
            )
            .await
            {
                Ok(d) => {
                    tracing::info!(
                        name = %config.name,
                        session = %session_id,
                        "I2P client: session created"
                    );
                    d
                }
                Err(e) => {
                    tracing::warn!(
                        name = %config.name,
                        error = %e,
                        "I2P client: SESSION CREATE failed"
                    );
                    if pacer.give_up() {
                        tracing::warn!(name = %config.name, "I2P client: max reconnect tries reached");
                        let _ = transport_tx
                            .send(TransportMessage::DeregisterInterface { id })
                            .await;
                        return;
                    }
                    pacer.wait().await;
                    continue;
                }
            };

            // SAM forbids running the data stream on the session socket.
            let stream_conn = match connect_to_sam(&config.sam_host, config.sam_port).await {
                Ok(s) => s,
                Err(e) => {
                    tracing::warn!(
                        name = %config.name,
                        error = %e,
                        "I2P client: failed to open stream connection to SAM"
                    );
                    if pacer.give_up() {
                        tracing::warn!(name = %config.name, "I2P client: max reconnect tries reached");
                        let _ = transport_tx
                            .send(TransportMessage::DeregisterInterface { id })
                            .await;
                        return;
                    }
                    pacer.wait().await;
                    continue;
                }
            };

            let (stream_reader, mut stream_writer) = stream_conn.into_split();
            let mut stream_buf_reader = BufReader::new(stream_reader);

            if let Err(e) = sam_hello(&mut stream_writer, &mut stream_buf_reader).await {
                tracing::warn!(
                    name = %config.name,
                    error = %e,
                    "I2P client: SAM HELLO on stream socket failed"
                );
                if pacer.give_up() {
                    tracing::warn!(name = %config.name, "I2P client: max reconnect tries reached");
                    let _ = transport_tx
                        .send(TransportMessage::DeregisterInterface { id })
                        .await;
                    return;
                }
                pacer.wait().await;
                continue;
            }

            if let Err(e) = sam_stream_connect(
                &mut stream_writer,
                &mut stream_buf_reader,
                &session_id,
                &config.peer_destination,
            )
            .await
            {
                tracing::warn!(
                    name = %config.name,
                    peer = %config.peer_destination,
                    error = %e,
                    "I2P client: STREAM CONNECT failed"
                );
                if pacer.give_up() {
                    tracing::warn!(name = %config.name, "I2P client: max reconnect tries reached");
                    let _ = transport_tx
                        .send(TransportMessage::DeregisterInterface { id })
                        .await;
                    return;
                }
                pacer.wait().await;
                continue;
            }

            tracing::info!(
                name = %config.name,
                peer = %config.peer_destination,
                "I2P client: stream connected"
            );

            online_task.store(true, Ordering::SeqCst);
            pacer.reset();

            // BufReader may have prefetched past the handshake; flush its tail first.
            let buffered = stream_buf_reader.buffer().to_vec();
            let raw_reader = stream_buf_reader.into_inner();

            let (conn_tx, mut conn_rx) = mpsc::channel::<Bytes>(256);
            let online_w = online_task.clone();
            let txb_w = task_txb.clone();
            let write_handle = tokio::spawn(async move {
                while let Some(data) = conn_rx.recv().await {
                    if !online_w.load(Ordering::SeqCst) {
                        break;
                    }
                    let framed = hdlc::frame(&data);
                    txb_w.fetch_add(framed.len() as u64, Ordering::Relaxed);
                    if let Err(e) = stream_writer.write_all(&framed).await {
                        tracing::warn!(error = %e, "I2P client: write error");
                        break;
                    }
                }
                online_w.store(false, Ordering::SeqCst);
            });

            let rx_ref = rx.clone();
            let fwd_handle = tokio::spawn(async move {
                let mut guard = rx_ref.lock().await;
                while let Some(data) = guard.recv().await {
                    if conn_tx.send(data).await.is_err() {
                        break;
                    }
                }
            });

            let online_r = online_task.clone();
            let rxb_r = task_rxb.clone();
            i2p_read_loop(raw_reader, &buffered, id, &transport_tx, &online_r, &rxb_r).await;

            online_task.store(false, Ordering::SeqCst);

            fwd_handle.abort();
            let _ = fwd_handle.await;
            write_handle.abort();
            let _ = write_handle.await;

            if pacer.give_up() {
                tracing::warn!(name = %config.name, "I2P client: max reconnect tries reached");
                let _ = transport_tx
                    .send(TransportMessage::DeregisterInterface { id })
                    .await;
                return;
            }
            tracing::info!(
                name = %config.name,
                delay = pacer.backoff,
                "I2P client: reconnecting"
            );
            pacer.wait().await;
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
        bitrate: BITRATE_GUESS,
        mtu: HW_MTU,
        online,
        rxb: Some(shared_rxb),
        txb: Some(shared_txb),
        inspection: None,
        tx,
        read_task,
    })
}

/// Accept SAM streams; each becomes a sub-interface via `handle_tx`. Session
/// is recreated if the control socket drops.
pub async fn spawn_i2p_server(
    config: I2PServerConfig,
    id_gen: Arc<AtomicU64>,
    transport_tx: mpsc::Sender<TransportMessage>,
    handle_tx: mpsc::Sender<InterfaceHandle>,
) -> Result<InterfaceHandle, crate::traits::InterfaceError> {
    let online = Arc::new(AtomicBool::new(false));
    let name = config.name.clone();
    let mode = config.mode;

    // Server handle tx is unused; per-peer handles carry traffic.
    let (tx, _rx) = mpsc::channel::<Bytes>(1);

    let online_task = online.clone();

    let read_task = tokio::spawn(async move {
        loop {
            let session_id = generate_session_id();

            let session_stream = match connect_to_sam(&config.sam_host, config.sam_port).await {
                Ok(s) => s,
                Err(e) => {
                    tracing::warn!(
                        name = %config.name,
                        error = %e,
                        "I2P server: failed to connect to SAM bridge"
                    );
                    tokio::time::sleep(std::time::Duration::from_secs(config.reconnect_delay))
                        .await;
                    continue;
                }
            };

            let (session_reader, mut session_writer) = session_stream.into_split();
            let mut session_buf_reader = BufReader::new(session_reader);

            if let Err(e) = sam_hello(&mut session_writer, &mut session_buf_reader).await {
                tracing::warn!(name = %config.name, error = %e, "I2P server: SAM HELLO failed");
                tokio::time::sleep(std::time::Duration::from_secs(config.reconnect_delay)).await;
                continue;
            }

            let private_key = config.keyfile.as_deref();
            let our_dest = match sam_session_create(
                &mut session_writer,
                &mut session_buf_reader,
                &session_id,
                private_key,
            )
            .await
            {
                Ok(d) => d,
                Err(e) => {
                    tracing::warn!(
                        name = %config.name,
                        error = %e,
                        "I2P server: SESSION CREATE failed"
                    );
                    tokio::time::sleep(std::time::Duration::from_secs(config.reconnect_delay))
                        .await;
                    continue;
                }
            };

            tracing::info!(
                name = %config.name,
                session = %session_id,
                dest_len = our_dest.len(),
                "I2P server: session created, accepting streams"
            );
            online_task.store(true, Ordering::SeqCst);

            // Each STREAM ACCEPT needs its own SAM TCP connection.
            loop {
                let accept_conn = match connect_to_sam(&config.sam_host, config.sam_port).await {
                    Ok(s) => s,
                    Err(e) => {
                        tracing::warn!(
                            name = %config.name,
                            error = %e,
                            "I2P server: failed to open accept connection"
                        );
                        // Session likely died; break to recreate.
                        break;
                    }
                };

                let (accept_reader, mut accept_writer) = accept_conn.into_split();
                let mut accept_buf_reader = BufReader::new(accept_reader);

                if let Err(e) = sam_hello(&mut accept_writer, &mut accept_buf_reader).await {
                    tracing::warn!(
                        name = %config.name,
                        error = %e,
                        "I2P server: SAM HELLO on accept socket failed"
                    );
                    break;
                }

                let peer_dest = match sam_stream_accept(
                    &mut accept_writer,
                    &mut accept_buf_reader,
                    &session_id,
                )
                .await
                {
                    Ok(d) => d,
                    Err(e) => {
                        tracing::warn!(
                            name = %config.name,
                            error = %e,
                            "I2P server: STREAM ACCEPT failed"
                        );
                        break;
                    }
                };

                let client_id = id_gen.fetch_add(1, Ordering::SeqCst);
                let truncated_dest = if peer_dest.len() > 16 {
                    format!("{}...", &peer_dest[..16])
                } else {
                    peer_dest.clone()
                };
                let client_name = format!("{}/peer_{}", config.name, truncated_dest);

                tracing::info!(
                    name = %client_name,
                    client_id,
                    "I2P server: accepted incoming stream"
                );

                let buffered = accept_buf_reader.buffer().to_vec();
                let raw_reader = accept_buf_reader.into_inner();

                let c_online = Arc::new(AtomicBool::new(true));
                let c_rxb = Arc::new(AtomicU64::new(0));
                let c_txb = Arc::new(AtomicU64::new(0));
                let (c_tx, c_rx) = mpsc::channel::<Bytes>(256);

                let c_online_w = c_online.clone();
                let c_txb_w = c_txb.clone();
                tokio::spawn(async move {
                    let mut rx = c_rx;
                    while let Some(data) = rx.recv().await {
                        let framed = hdlc::frame(&data);
                        c_txb_w.fetch_add(framed.len() as u64, Ordering::Relaxed);
                        if let Err(e) = accept_writer.write_all(&framed).await {
                            tracing::warn!(error = %e, "I2P server peer: write error");
                            break;
                        }
                    }
                    c_online_w.store(false, Ordering::SeqCst);
                });

                let c_online_r = c_online.clone();
                let c_rxb_r = c_rxb.clone();
                let transport_tx2 = transport_tx.clone();
                let peer_name = client_name.clone();
                let c_read_task = tokio::spawn(async move {
                    i2p_read_loop(
                        raw_reader,
                        &buffered,
                        client_id,
                        &transport_tx2,
                        &c_online_r,
                        &c_rxb_r,
                    )
                    .await;
                    tracing::info!(name = %peer_name, "I2P server: peer disconnected");
                });

                let handle = InterfaceHandle {
                    id: client_id,
                    parent_id: Some(0),
                    name: client_name,
                    mode: config.mode,
                    direction: InterfaceDirection {
                        inbound: true,
                        outbound: true,
                        forward: false,
                        repeat: false,
                    },
                    bitrate: BITRATE_GUESS,
                    mtu: HW_MTU,
                    online: c_online,
                    rxb: Some(c_rxb),
                    txb: Some(c_txb),
                    inspection: None,
                    tx: c_tx,
                    read_task: c_read_task,
                };

                if handoff_accepted_interface(&handle_tx, handle)
                    .await
                    .is_err()
                {
                    tracing::warn!("I2P server: handle registry channel closed");
                    online_task.store(false, Ordering::SeqCst);
                    return;
                }
            }

            online_task.store(false, Ordering::SeqCst);
            tracing::info!(
                name = %config.name,
                delay = config.reconnect_delay,
                "I2P server: session lost, recreating"
            );
            tokio::time::sleep(std::time::Duration::from_secs(config.reconnect_delay)).await;
        }
    });

    Ok(InterfaceHandle {
        id: 0,
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
        mtu: HW_MTU,
        online,
        rxb: Some(Arc::new(AtomicU64::new(0))),
        txb: Some(Arc::new(AtomicU64::new(0))),
        inspection: None,
        tx,
        read_task,
    })
}

/// HDLC read loop.
///
/// `initial_data` seeds the deframer with bytes the `BufReader` prefetched
/// past the SAM handshake replies before the raw reader was taken.
async fn i2p_read_loop(
    mut reader: tokio::net::tcp::OwnedReadHalf,
    initial_data: &[u8],
    interface_id: InterfaceId,
    transport_tx: &mpsc::Sender<TransportMessage>,
    online: &AtomicBool,
    rxb: &AtomicU64,
) {
    let mut deframer = hdlc::HdlcDeframer::new();
    let mut buf = [0u8; 4096];

    if !initial_data.is_empty() {
        rxb.fetch_add(initial_data.len() as u64, Ordering::Relaxed);
        for frame in deframer.feed(initial_data) {
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
                tracing::warn!(interface_id, "I2P: transport channel closed");
                online.store(false, Ordering::SeqCst);
                return;
            }
        }
    }

    loop {
        match reader.read(&mut buf).await {
            Ok(0) => {
                tracing::info!(interface_id, "I2P read: EOF");
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
                        tracing::warn!(interface_id, "I2P: transport channel closed");
                        online.store(false, Ordering::SeqCst);
                        return;
                    }
                }
            }
            Err(e) => {
                tracing::warn!(interface_id, error = %e, "I2P read error");
                break;
            }
        }
    }
    online.store(false, Ordering::SeqCst);
}

/// Reconnect pacing for the SAM client loop: bounded tries + exponential
/// backoff, reset on every successful connect.
struct ReconnectPacer {
    tries: usize,
    backoff: u64,
    initial: u64,
    max_tries: Option<usize>,
}

impl ReconnectPacer {
    fn new(initial: u64, max_tries: Option<usize>) -> Self {
        Self {
            tries: 0,
            backoff: initial,
            initial,
            max_tries,
        }
    }

    /// Count a failure; `true` means the bounded try cap was hit.
    fn give_up(&mut self) -> bool {
        if let Some(limit) = self.max_tries {
            self.tries += 1;
            self.tries >= limit
        } else {
            false
        }
    }

    /// Current delay, advancing the doubling (capped) for the next failure.
    fn next_backoff(&mut self) -> u64 {
        let current = self.backoff;
        self.backoff = (self.backoff * 2).min(RECONNECT_WAIT_MAX);
        current
    }

    /// Sleep the current backoff, then double it (capped).
    async fn wait(&mut self) {
        let delay = self.next_backoff();
        tokio::time::sleep(std::time::Duration::from_secs(delay)).await;
    }

    fn reset(&mut self) {
        self.tries = 0;
        self.backoff = self.initial;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_i2p_client_config() {
        let cfg = I2PClientConfig::new("i2p0", "ABCDEF1234.b32.i2p");
        assert_eq!(cfg.sam_host, DEFAULT_SAM_ADDRESS);
        assert_eq!(cfg.sam_port, DEFAULT_SAM_PORT);
        assert_eq!(cfg.peer_destination, "ABCDEF1234.b32.i2p");
        assert_eq!(cfg.reconnect_delay, RECONNECT_WAIT);
        assert!(cfg.max_reconnect_tries.is_none());
    }

    #[test]
    fn test_i2p_server_config() {
        let cfg = I2PServerConfig::new("i2p-server");
        assert_eq!(cfg.sam_port, DEFAULT_SAM_PORT);
        assert!(cfg.keyfile.is_none());
        assert_eq!(cfg.reconnect_delay, RECONNECT_WAIT);
    }

    #[test]
    fn test_constants() {
        assert_eq!(BITRATE_GUESS, 256_000);
        assert_eq!(HW_MTU, 1064);
        assert_eq!(I2P_TCP_USER_TIMEOUT, 45);
        assert_eq!(I2P_PROBE_AFTER, 10);
        assert_eq!(I2P_PROBE_INTERVAL, 9);
        assert_eq!(I2P_PROBES, 5);
        assert_eq!(I2P_READ_TIMEOUT, 110);
        assert_eq!(RECONNECT_WAIT, 15);
    }

    #[test]
    fn test_parse_sam_hello_reply_ok() {
        let reply = "HELLO REPLY RESULT=OK VERSION=3.1";
        let pairs = parse_sam_reply(reply);

        assert!(sam_reply_has_token(&pairs, "HELLO"));
        assert!(sam_reply_has_token(&pairs, "REPLY"));
        assert_eq!(sam_reply_get(&pairs, "RESULT"), Some("OK"));
        assert_eq!(sam_reply_get(&pairs, "VERSION"), Some("3.1"));
    }

    #[test]
    fn test_parse_sam_hello_reply_noversion() {
        let reply = "HELLO REPLY RESULT=NOVERSION";
        let pairs = parse_sam_reply(reply);
        assert_eq!(sam_reply_get(&pairs, "RESULT"), Some("NOVERSION"));
    }

    #[test]
    fn test_parse_sam_session_reply() {
        let dest = "AAAA1234BBBB5678==";
        let reply = format!("SESSION STATUS RESULT=OK DESTINATION={}", dest);
        let pairs = parse_sam_reply(&reply);

        assert!(sam_reply_has_token(&pairs, "SESSION"));
        assert!(sam_reply_has_token(&pairs, "STATUS"));
        assert_eq!(sam_reply_get(&pairs, "RESULT"), Some("OK"));
        assert_eq!(sam_reply_get(&pairs, "DESTINATION"), Some(dest));
    }

    #[test]
    fn test_parse_sam_session_error() {
        let reply = "SESSION STATUS RESULT=DUPLICATED_ID MESSAGE=session already exists";
        let pairs = parse_sam_reply(reply);
        assert_eq!(sam_reply_get(&pairs, "RESULT"), Some("DUPLICATED_ID"));
        // Whitespace tokenisation stops MESSAGE at the first space; the
        // machine-readable error code lives in RESULT.
        assert_eq!(sam_reply_get(&pairs, "MESSAGE"), Some("session"));
    }

    #[test]
    fn test_parse_sam_stream_reply() {
        let reply = "STREAM STATUS RESULT=OK";
        let pairs = parse_sam_reply(reply);

        assert!(sam_reply_has_token(&pairs, "STREAM"));
        assert!(sam_reply_has_token(&pairs, "STATUS"));
        assert_eq!(sam_reply_get(&pairs, "RESULT"), Some("OK"));
    }

    #[test]
    fn test_parse_sam_stream_cant_reach() {
        let reply = "STREAM STATUS RESULT=CANT_REACH_PEER MESSAGE=unreachable";
        let pairs = parse_sam_reply(reply);
        assert_eq!(sam_reply_get(&pairs, "RESULT"), Some("CANT_REACH_PEER"));
    }

    #[test]
    fn test_parse_empty_reply() {
        let pairs = parse_sam_reply("");
        assert!(pairs.is_empty());
    }

    #[test]
    fn test_sam_reply_get_missing_key() {
        let pairs = parse_sam_reply("HELLO REPLY RESULT=OK");
        assert_eq!(sam_reply_get(&pairs, "MISSING"), None);
    }

    #[test]
    fn test_sam_reply_has_token() {
        let pairs = parse_sam_reply("HELLO REPLY RESULT=OK");
        assert!(sam_reply_has_token(&pairs, "HELLO"));
        assert!(sam_reply_has_token(&pairs, "REPLY"));
        assert!(!sam_reply_has_token(&pairs, "RESULT"));
        assert!(!sam_reply_has_token(&pairs, "NONEXISTENT"));
    }

    #[test]
    fn test_generate_session_id() {
        let id1 = generate_session_id();
        let id2 = generate_session_id();

        assert!(id1.starts_with("reticulum_"));
        assert!(id2.starts_with("reticulum_"));
        assert_ne!(id1, id2);
        assert_eq!(id1.len(), 26);
    }

    #[test]
    fn test_pacer_unlimited_never_gives_up() {
        let mut pacer = ReconnectPacer::new(15, None);
        for _ in 0..100 {
            assert!(!pacer.give_up());
        }
        assert_eq!(pacer.tries, 0);
    }

    #[test]
    fn test_pacer_bounded_gives_up_at_cap() {
        let mut pacer = ReconnectPacer::new(15, Some(3));
        assert!(!pacer.give_up());
        assert!(!pacer.give_up());
        assert!(pacer.give_up());
        assert_eq!(pacer.tries, 3);
    }

    #[test]
    fn test_pacer_backoff_doubles_capped_and_resets() {
        let mut pacer = ReconnectPacer::new(15, Some(10));
        assert_eq!(pacer.next_backoff(), 15);
        assert_eq!(pacer.backoff, 30);
        for _ in 0..10 {
            pacer.next_backoff();
        }
        assert_eq!(pacer.backoff, RECONNECT_WAIT_MAX);

        let _ = pacer.give_up();
        pacer.reset();
        assert_eq!(pacer.tries, 0);
        assert_eq!(pacer.backoff, 15);
    }

    #[test]
    fn test_sam_error_display() {
        let e = SamError::HandshakeFailed("test error".to_string());
        assert_eq!(format!("{}", e), "SAM handshake failed: test error");

        let e = SamError::SessionFailed("dup id".to_string());
        assert_eq!(format!("{}", e), "SAM session creation failed: dup id");

        let e = SamError::StreamFailed("cant reach".to_string());
        assert_eq!(format!("{}", e), "SAM stream connect failed: cant reach");

        let e = SamError::AcceptFailed("timeout".to_string());
        assert_eq!(format!("{}", e), "SAM stream accept failed: timeout");

        let e = SamError::UnexpectedReply("garbage".to_string());
        assert_eq!(format!("{}", e), "unexpected SAM reply: garbage");
    }

    #[test]
    fn test_full_sam_handshake_sequence_parsing() {
        let hello_reply = "HELLO REPLY RESULT=OK VERSION=3.1";
        let pairs = parse_sam_reply(hello_reply);
        assert!(sam_reply_has_token(&pairs, "HELLO"));
        assert_eq!(sam_reply_get(&pairs, "RESULT"), Some("OK"));
        assert_eq!(sam_reply_get(&pairs, "VERSION"), Some("3.1"));

        let long_dest = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOP==";
        let session_reply = format!("SESSION STATUS RESULT=OK DESTINATION={}", long_dest);
        let pairs = parse_sam_reply(&session_reply);
        assert!(sam_reply_has_token(&pairs, "SESSION"));
        assert_eq!(sam_reply_get(&pairs, "RESULT"), Some("OK"));
        assert_eq!(sam_reply_get(&pairs, "DESTINATION"), Some(long_dest));

        let stream_reply = "STREAM STATUS RESULT=OK";
        let pairs = parse_sam_reply(stream_reply);
        assert!(sam_reply_has_token(&pairs, "STREAM"));
        assert_eq!(sam_reply_get(&pairs, "RESULT"), Some("OK"));
    }
}
