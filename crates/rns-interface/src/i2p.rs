//! Reticulum-over-I2P via SAM v3.1 bridge (default 127.0.0.1:7656).
//! Handshake: HELLO → SESSION CREATE → STREAM CONNECT/ACCEPT;
//! stream then carries HDLC-framed packets.

use rns_transport::messages::{InterfacePacketCapacity, InterfaceTransportSender};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use bytes::Bytes;
use rns_crypto::zeroize::Zeroizing;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

use crate::hdlc;
use crate::traits::{
    ByteCounter, InterfaceDirection, InterfaceHandle, InterfaceId, InterfaceMode, TunnelIdentity,
    handoff_accepted_interface, open_client_connection,
};
use rns_transport::messages::{
    InboundPacket, InterfaceIdentity, InterfaceInspectionSnapshot, InterfaceInspectionSource,
    TransportMessage,
};

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
/// Retry interval for SAM session (tunnel) setup (I2PInterface.py tunnel_job).
pub const TUNNEL_SETUP_RETRY: u64 = 8;

pub const TUNNEL_STATE_INIT: u8 = 0x00;
pub const TUNNEL_STATE_ACTIVE: u8 = 0x01;
pub const TUNNEL_STATE_STALE: u8 = 0x02;

pub const SAM_VERSION: &str = "3.1";

/// The longest SAM reply line read: the line limit of Python's asyncio SAM
/// client, far past a SESSION STATUS that carries a private key.
const SAM_REPLY_MAX_BYTES: usize = 64 * 1024;
/// An I2P key file holds one base64 SAM private key of a few kilobytes.
const I2P_KEY_FILE_MAX_BYTES: usize = 16 * 1024;

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

/// The value of `key` in a reply, borrowed from it.
fn reply_value<'a>(reply: &'a str, key: &str) -> Option<&'a str> {
    reply
        .split_whitespace()
        .find_map(|token| token.strip_prefix(key)?.strip_prefix('='))
}

/// Whether a reply holds `token` with no value.
fn reply_has_token(reply: &str, token: &str) -> bool {
    reply
        .split_whitespace()
        .any(|word| word == token || word.strip_suffix('=') == Some(token))
}

/// A reply for an error message, with any private key left out.
fn without_destination(reply: &str) -> String {
    reply
        .split_whitespace()
        .map(|token| {
            if token.starts_with("DESTINATION=") {
                "DESTINATION=<redacted>"
            } else {
                token
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// Read one reply line into a buffer reserved once and wiped on drop, since a
/// SESSION STATUS reply carries the session's private key. Bytes are read one
/// at a time, so nothing past the line is consumed.
async fn read_sam_reply<R: AsyncRead + Unpin>(
    reader: &mut R,
) -> Result<Zeroizing<String>, SamError> {
    let mut line = Zeroizing::new(Vec::with_capacity(SAM_REPLY_MAX_BYTES));
    loop {
        match reader.read_u8().await {
            Ok(b'\n') => break,
            Ok(_) if line.len() == SAM_REPLY_MAX_BYTES => {
                return Err(SamError::UnexpectedReply(format!(
                    "reply longer than {SAM_REPLY_MAX_BYTES} bytes"
                )));
            }
            Ok(byte) => line.push(byte),
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof && !line.is_empty() => break,
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                return Err(SamError::Io(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "SAM connection closed during handshake",
                )));
            }
            Err(e) => return Err(e.into()),
        }
    }
    let end = line
        .iter()
        .rposition(|byte| !byte.is_ascii_whitespace())
        .map_or(0, |last| last + 1);
    line.truncate(end);
    match String::from_utf8(std::mem::take(&mut *line)) {
        Ok(text) => Ok(Zeroizing::new(text)),
        Err(error) => {
            drop(Zeroizing::new(error.into_bytes()));
            Err(SamError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "SAM reply is not UTF-8",
            )))
        }
    }
}

async fn sam_hello<R: AsyncRead + Unpin>(
    writer: &mut tokio::net::tcp::OwnedWriteHalf,
    reader: &mut R,
) -> Result<(), SamError> {
    let hello_msg = format!("HELLO VERSION MIN={} MAX={}\n", SAM_VERSION, SAM_VERSION);
    writer.write_all(hello_msg.as_bytes()).await?;
    writer.flush().await?;

    let reply = read_sam_reply(reader).await?;
    let pairs = parse_sam_reply(&reply);

    if !sam_reply_has_token(&pairs, "HELLO") || !sam_reply_has_token(&pairs, "REPLY") {
        return Err(SamError::HandshakeFailed(format!(
            "expected HELLO REPLY, got: {}",
            reply.as_str()
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
            reply.as_str()
        ))),
    }
}

/// Returns the session's private key (base64), wiped on drop.
/// `private_key=None` = transient.
async fn sam_session_create<R: AsyncRead + Unpin>(
    writer: &mut tokio::net::tcp::OwnedWriteHalf,
    reader: &mut R,
    session_id: &str,
    private_key: Option<&str>,
    transient_signature_type: Option<u8>,
) -> Result<Zeroizing<String>, SamError> {
    let transient;
    let destination = match (private_key, transient_signature_type) {
        (Some(key), _) => key,
        (None, Some(signature_type)) => {
            transient = format!("TRANSIENT SIGNATURE_TYPE={signature_type}");
            &transient
        }
        (None, None) => "TRANSIENT",
    };
    // Sized up front: the command carries the private key.
    let mut create_msg = Zeroizing::new(String::with_capacity(
        64 + session_id.len() + destination.len(),
    ));
    for part in [
        "SESSION CREATE STYLE=STREAM ID=",
        session_id,
        " DESTINATION=",
        destination,
        "\n",
    ] {
        create_msg.push_str(part);
    }
    writer.write_all(create_msg.as_bytes()).await?;
    writer.flush().await?;

    let reply = read_sam_reply(reader).await?;

    if !reply_has_token(&reply, "SESSION") || !reply_has_token(&reply, "STATUS") {
        return Err(SamError::SessionFailed(format!(
            "expected SESSION STATUS, got: {}",
            without_destination(&reply)
        )));
    }

    match reply_value(&reply, "RESULT") {
        Some("OK") => {}
        Some(other) => {
            let msg_detail = reply_value(&reply, "MESSAGE").unwrap_or("no details");
            return Err(SamError::SessionFailed(format!(
                "SESSION RESULT={}: {}",
                other, msg_detail
            )));
        }
        None => {
            return Err(SamError::SessionFailed(format!(
                "no RESULT in SESSION STATUS: {}",
                without_destination(&reply)
            )));
        }
    }

    match reply_value(&reply, "DESTINATION") {
        Some(dest) => Ok(Zeroizing::new(dest.to_string())),
        None => Err(SamError::SessionFailed(
            "SESSION STATUS OK but no DESTINATION returned".to_string(),
        )),
    }
}

/// i2plib `stream_connect` resolves a destination ending in `.i2p` with
/// `NAMING LOOKUP` on its own SAM connection and connects to the full key
/// (RNS/vendor/i2plib/aiosam.py:34-50, :120-121).
async fn sam_resolve_destination(
    sam_host: &str,
    sam_port: u16,
    destination: &str,
) -> Result<String, SamError> {
    if !destination.ends_with(".i2p") {
        return Ok(destination.to_string());
    }
    let (mut reader, mut writer) = connect_to_sam(sam_host, sam_port).await?.into_split();
    sam_hello(&mut writer, &mut reader).await?;
    writer
        .write_all(format!("NAMING LOOKUP NAME={destination}\n").as_bytes())
        .await?;
    writer.flush().await?;
    let reply = read_sam_reply(&mut reader).await?;
    let pairs = parse_sam_reply(&reply);
    if !sam_reply_has_token(&pairs, "NAMING") || !sam_reply_has_token(&pairs, "REPLY") {
        return Err(SamError::UnexpectedReply(reply.to_string()));
    }
    match (
        sam_reply_get(&pairs, "RESULT"),
        sam_reply_get(&pairs, "VALUE"),
    ) {
        (Some("OK"), Some(value)) => Ok(value.to_string()),
        (result, _) => Err(SamError::StreamFailed(format!(
            "NAMING LOOKUP RESULT={}",
            result.unwrap_or("none")
        ))),
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
            reply.as_str()
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
            reply.as_str()
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
            reply.as_str()
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
                reply.as_str()
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
    // Python's per-platform I2P peer timeouts (I2PInterface.py:443-455).
    crate::tcp::set_tcp_keepalive_tuned(&stream, true);
    Ok(stream)
}

fn generate_session_id() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let id: u64 = rng.r#gen();
    format!("reticulum_{:016x}", id)
}

#[derive(Clone)]
pub struct I2PServerConfig {
    pub name: String,
    pub sam_host: String,
    pub sam_port: u16,
    /// Base64 private key for the server's destination, used before `key_path`.
    pub keyfile: Option<String>,
    /// Optional path for the server destination's private key, used when
    /// `keyfile` is absent. A missing or empty file is populated after session
    /// creation. Read failures leave the file untouched and use a transient
    /// destination; write failures can likewise change the next session's address.
    pub key_path: Option<std::path::PathBuf>,
    pub reconnect_delay: u64,
    pub mode: InterfaceMode,
    /// Receives the server's b32 address (Python `I2PInterface.b32`) whenever
    /// SAM creates its session.
    pub b32: Option<tokio::sync::watch::Sender<Option<String>>>,
}

// The key is the destination's secret; debug output names only its presence.
impl std::fmt::Debug for I2PServerConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("I2PServerConfig")
            .field("name", &self.name)
            .field("sam_host", &self.sam_host)
            .field("sam_port", &self.sam_port)
            .field("keyfile", &self.keyfile.as_ref().map(|_| "<redacted>"))
            .field("key_path", &self.key_path)
            .field("reconnect_delay", &self.reconnect_delay)
            .field("mode", &self.mode)
            .field("b32", &self.b32)
            .finish()
    }
}

impl I2PServerConfig {
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            sam_host: DEFAULT_SAM_ADDRESS.to_string(),
            sam_port: DEFAULT_SAM_PORT,
            keyfile: None,
            key_path: None,
            reconnect_delay: RECONNECT_WAIT,
            mode: InterfaceMode::Full,
            b32: None,
        }
    }
}

/// i2plib's signature type for new destinations, EdDSA-SHA512-Ed25519
/// (RNS/vendor/i2plib/sam.py:91-93).
const NEW_DESTINATION_SIGNATURE_TYPE: u8 = 7;

/// The stored key, `None` when there is none yet, read into buffers that are
/// wiped on drop. A file that cannot be read is an error, so it is never
/// replaced.
fn read_private_key(path: &std::path::Path) -> std::io::Result<Option<Zeroizing<String>>> {
    let data = match rns_identity::persistence::read_secret_file(path, I2P_KEY_FILE_MAX_BYTES) {
        Ok(data) => data,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    let key = std::str::from_utf8(&data)
        .map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "I2P key file is not UTF-8")
        })?
        .trim();
    Ok((!key.is_empty()).then(|| Zeroizing::new(key.to_string())))
}

/// Keep a session's private key readable by its owner only, replaced
/// atomically, as the other private keys are.
fn store_private_key(path: &std::path::Path, key: &str) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    rns_identity::persistence::atomic_write(path, key.as_bytes())
}

/// The b32 address of the destination in a SAM private key: the hash of its
/// first 387 bytes plus its certificate (i2plib `Destination.base32`,
/// RNS/vendor/i2plib/sam.py:113-129).
pub fn destination_b32(private_key: &str) -> Option<String> {
    let key = i2p_base64_decode(private_key)?;
    let certificate = usize::from(u16::from_be_bytes(key.get(385..387)?.try_into().ok()?));
    let hash = rns_crypto::sha::sha256(key.get(..387 + certificate)?);
    Some(base32_lowercase(&hash))
}

/// Base64 with I2P's `-~` alphabet (i2plib `i2p_b64decode`), into a buffer
/// sized up front and wiped on drop: the input is usually a private key.
fn i2p_base64_decode(text: &str) -> Option<Zeroizing<Vec<u8>>> {
    let mut bytes = Zeroizing::new(Vec::with_capacity(text.len() * 3 / 4));
    let (mut buffer, mut bits) = (0u32, 0u32);
    for c in text.trim_end_matches('=').bytes() {
        let value = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'-' => 62,
            b'~' => 63,
            _ => return None,
        };
        buffer = buffer << 6 | u32::from(value);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            bytes.push((buffer >> bits) as u8);
            buffer &= (1 << bits) - 1;
        }
    }
    Some(bytes)
}

/// RFC 4648 base32, lowercase and unpadded.
fn base32_lowercase(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";
    let mut text = String::with_capacity(bytes.len().div_ceil(5) * 8);
    let (mut buffer, mut bits) = (0u32, 0u32);
    for byte in bytes {
        buffer = buffer << 8 | u32::from(*byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            text.push(char::from(ALPHABET[(buffer >> bits) as usize & 31]));
        }
        buffer &= (1 << bits) - 1;
    }
    if bits > 0 {
        text.push(char::from(ALPHABET[(buffer << (5 - bits)) as usize & 31]));
    }
    text
}

#[derive(Debug, Clone)]
pub struct I2PClientConfig {
    pub name: String,
    pub sam_host: String,
    pub sam_port: u16,
    /// Peer destination passed verbatim as SAM STREAM CONNECT's `DESTINATION`
    /// value. This library does not perform a separate name lookup.
    pub peer_destination: String,
    /// Consecutive failure cap, including the initial connection attempt. A
    /// successful connection resets the count. `None` means unlimited retries.
    pub max_reconnect_tries: Option<usize>,
    pub reconnect_delay: u64,
    pub mode: InterfaceMode,
    /// Identity used to request a signed tunnel synthesis for each connection.
    /// `None`, or an identity without signing material, sends no synthesis.
    pub tunnel_identity: Option<TunnelIdentity>,
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
            tunnel_identity: None,
        }
    }

    /// Python `str(I2PInterfacePeer)` (I2PInterface.py:714-715).
    pub fn python_name(&self) -> String {
        format!("I2PInterfacePeer[{}]", self.name)
    }
}

/// Connect via SAM streaming session, run HDLC-framed I/O; reconnect at a fixed interval.
pub async fn spawn_i2p_client(
    config: I2PClientConfig,
    id: InterfaceId,
    transport_tx: mpsc::Sender<TransportMessage>,
) -> Result<InterfaceHandle, crate::traits::InterfaceError> {
    let transport_tx = InterfaceTransportSender::new(id, transport_tx);
    let owner = transport_tx.owner();
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

    let python_name = config.python_name();
    let tunnel_state = Arc::new(std::sync::atomic::AtomicU8::new(TUNNEL_STATE_INIT));
    let task_tunnel_state = tunnel_state.clone();
    let identity = InterfaceIdentity::new(&python_name, &config.name, "I2PInterfacePeer");
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
                    pacer.wait_tunnel().await;
                    continue;
                }
            };

            // Read unbuffered: a read buffer would keep SAM's reply, private key included.
            let (mut session_reader, mut session_writer) = session_stream.into_split();

            if let Err(e) = sam_hello(&mut session_writer, &mut session_reader).await {
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
                pacer.wait_tunnel().await;
                continue;
            }

            let _our_dest = match sam_session_create(
                &mut session_writer,
                &mut session_reader,
                &session_id,
                None,
                Some(NEW_DESTINATION_SIGNATURE_TYPE),
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
                    pacer.wait_tunnel().await;
                    continue;
                }
            };

            let peer_destination = match sam_resolve_destination(
                &config.sam_host,
                config.sam_port,
                &config.peer_destination,
            )
            .await
            {
                Ok(destination) => destination,
                Err(e) => {
                    tracing::warn!(
                        name = %config.name,
                        peer = %config.peer_destination,
                        error = %e,
                        "I2P client: NAMING LOOKUP failed"
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
                &peer_destination,
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

            pacer.reset();
            // Python synthesizes on every connection (I2PInterface.py:503,
            // :533).
            let synthesis = config
                .tunnel_identity
                .as_ref()
                .and_then(|identity| identity.synthesis(&python_name));
            open_client_connection(&rx, &transport_tx, synthesis, &online_task).await;

            // BufReader may have prefetched past the handshake; flush its tail first.
            let buffered = stream_buf_reader.buffer().to_vec();
            let raw_reader = stream_buf_reader.into_inner();
            {
                let mut outbound = rx.lock().await;
                i2p_connection(
                    raw_reader,
                    &buffered,
                    stream_writer,
                    &mut outbound,
                    id,
                    &transport_tx,
                    &online_task,
                    &ByteCounter::new(task_rxb.clone(), None),
                    &ByteCounter::new(task_txb.clone(), None),
                    &python_name,
                    &task_tunnel_state,
                )
                .await;
            }
            online_task.store(false, Ordering::SeqCst);

            if pacer.give_up() {
                tracing::warn!(name = %config.name, "I2P client: max reconnect tries reached");
                let _ = transport_tx
                    .send(TransportMessage::DeregisterInterface { id })
                    .await;
                return;
            }
            tracing::info!(
                name = %config.name,
                delay = pacer.delay,
                "I2P client: reconnecting"
            );
            pacer.wait().await;
        }
    });

    Ok(InterfaceHandle {
        id,
        owner,
        packet_capacity: InterfacePacketCapacity::new(500, 1064, false),
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
        inspection: Some(tunnel_inspection(tunnel_state).with_identity(identity)),
        tx,
        read_task,
    })
}

/// Accept SAM streams; each becomes a sub-interface via `handle_tx`.
/// The session is recreated after an accept-connection or SAM handshake
/// failure. The session control socket is not monitored independently.
pub async fn spawn_i2p_server(
    config: I2PServerConfig,
    id: InterfaceId,
    id_gen: Arc<AtomicU64>,
    transport_tx: mpsc::Sender<TransportMessage>,
    handle_tx: mpsc::Sender<InterfaceHandle>,
) -> Result<InterfaceHandle, crate::traits::InterfaceError> {
    let transport_tx = InterfaceTransportSender::new(id, transport_tx);
    let owner = transport_tx.owner();
    let online = Arc::new(AtomicBool::new(false));
    let name = config.name.clone();
    let mode = config.mode;

    // Server handle tx is unused; per-peer handles carry traffic.
    let (tx, _rx) = mpsc::channel::<Bytes>(1);
    let server_rxb = Arc::new(AtomicU64::new(0));
    let server_txb = Arc::new(AtomicU64::new(0));
    let parent_rxb = server_rxb.clone();
    let parent_txb = server_txb.clone();
    let server_identity = InterfaceIdentity::bracketed("I2PInterface", &name);
    let b32 = config.b32.as_ref().map(|b32| b32.subscribe());

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

            // Read unbuffered: a read buffer would keep SAM's reply, private key included.
            let (mut session_reader, mut session_writer) = session_stream.into_split();

            if let Err(e) = sam_hello(&mut session_writer, &mut session_reader).await {
                tracing::warn!(name = %config.name, error = %e, "I2P server: SAM HELLO failed");
                tokio::time::sleep(std::time::Duration::from_secs(config.reconnect_delay)).await;
                continue;
            }

            let (private_key, store_key) = match (&config.keyfile, config.key_path.as_deref()) {
                (Some(key), _) => (Some(Zeroizing::new(key.clone())), false),
                (None, None) => (None, false),
                (None, Some(path)) => match read_private_key(path) {
                    Ok(key) => {
                        let missing = key.is_none();
                        (key, missing)
                    }
                    Err(error) => {
                        tracing::warn!(
                            name = %config.name,
                            path = %path.display(),
                            %error,
                            "I2P server: cannot read its private key; this session's address is transient"
                        );
                        (None, false)
                    }
                },
            };
            let our_dest = match sam_session_create(
                &mut session_writer,
                &mut session_reader,
                &session_id,
                private_key.as_deref().map(String::as_str),
                Some(NEW_DESTINATION_SIGNATURE_TYPE),
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
            if store_key
                && let Some(path) = config.key_path.as_deref()
                && let Err(error) = store_private_key(path, &our_dest)
            {
                tracing::warn!(
                    name = %config.name,
                    path = %path.display(),
                    %error,
                    "I2P server: failed to store its private key; its address changes with the next session"
                );
            }
            if let Some(b32) = &config.b32 {
                b32.send_replace(destination_b32(&our_dest));
            }
            online_task.store(true, Ordering::SeqCst);

            // A child copies its parent's registration (IFAC, ingress control), so accept once it exists.
            if !transport_tx.ready().await {
                online_task.store(false, Ordering::SeqCst);
                return;
            }

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
                let client_name = format!("Connected peer on {}", config.name);

                tracing::info!(
                    name = %client_name,
                    client_id,
                    peer_len = peer_dest.len(),
                    "I2P server: accepted incoming stream"
                );

                let buffered = accept_buf_reader.buffer().to_vec();
                let raw_reader = accept_buf_reader.into_inner();

                let c_online = Arc::new(AtomicBool::new(true));
                let c_rxb = Arc::new(AtomicU64::new(0));
                let c_txb = Arc::new(AtomicU64::new(0));
                let (c_tx, mut c_rx) = mpsc::channel::<Bytes>(256);

                let c_online_r = c_online.clone();
                let c_rxb_r = ByteCounter::new(c_rxb.clone(), Some(parent_rxb.clone()));
                let c_txb_w = ByteCounter::new(c_txb.clone(), Some(parent_txb.clone()));
                let transport_tx2 =
                    InterfaceTransportSender::new(client_id, transport_tx.actor_sender());
                let child_owner = transport_tx2.owner();
                let peer_name = format!("I2PInterfacePeer[{client_name}]");
                let c_tunnel_state = Arc::new(std::sync::atomic::AtomicU8::new(TUNNEL_STATE_INIT));
                let task_c_tunnel_state = c_tunnel_state.clone();
                let child_identity =
                    InterfaceIdentity::new(&peer_name, &client_name, "I2PInterfacePeer");
                let c_read_task = tokio::spawn(async move {
                    i2p_connection(
                        raw_reader,
                        &buffered,
                        accept_writer,
                        &mut c_rx,
                        client_id,
                        &transport_tx2,
                        &c_online_r,
                        &c_rxb_r,
                        &c_txb_w,
                        &peer_name,
                        &task_c_tunnel_state,
                    )
                    .await;
                    tracing::info!(name = %peer_name, "I2P server: peer disconnected");
                    let _ = transport_tx2
                        .send(TransportMessage::DeregisterInterface { id: client_id })
                        .await;
                });

                let handle = InterfaceHandle {
                    id: client_id,
                    owner: child_owner,
                    packet_capacity: InterfacePacketCapacity::new(500, 1064, false),
                    parent_id: Some(id),
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
                    inspection: Some(
                        tunnel_inspection(c_tunnel_state).with_identity(child_identity),
                    ),
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
        id,
        owner,
        packet_capacity: InterfacePacketCapacity::new(500, 1064, false),
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
        rxb: Some(server_rxb),
        txb: Some(server_txb),
        // Rust runs the listener only when `connectable` is set.
        inspection: Some(
            InterfaceInspectionSource::new(move || InterfaceInspectionSnapshot {
                i2p_connectable: Some(true),
                i2p_b32: b32.as_ref().and_then(|b32| b32.borrow().clone()),
                ..InterfaceInspectionSnapshot::default()
            })
            .with_identity(server_identity),
        ),
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
    transport_tx: &InterfaceTransportSender,
    online: &AtomicBool,
    rxb: &ByteCounter,
    last_read: &std::sync::Mutex<tokio::time::Instant>,
) {
    let mut deframer = hdlc::HdlcByteDeframer::new(HW_MTU as usize);
    let mut buf = [0u8; 4096];

    if !initial_data.is_empty() {
        for frame in deframer.feed(initial_data) {
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
                *last_read.lock().unwrap_or_else(|e| e.into_inner()) = tokio::time::Instant::now();
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

/// HDLC writer plus the read watchdog (I2PInterface.py read_watchdog): every
/// second it updates the tunnel state, sends an empty-frame keepalive after
/// `I2P_PROBE_AFTER` s without an outbound packet, and returns (closing the
/// stream) after `I2P_READ_TIMEOUT` s without a read.
async fn i2p_write_loop(
    mut writer: tokio::net::tcp::OwnedWriteHalf,
    rx: &mut mpsc::Receiver<Bytes>,
    txb: &ByteCounter,
    last_read: &std::sync::Mutex<tokio::time::Instant>,
    name: &str,
    shown_state: &std::sync::atomic::AtomicU8,
) {
    let probe_after = std::time::Duration::from_secs(I2P_PROBE_AFTER);
    let read_timeout = std::time::Duration::from_secs(I2P_READ_TIMEOUT);
    let second = std::time::Duration::from_secs(1);
    let mut last_write = tokio::time::Instant::now();
    let mut tunnel_state = TUNNEL_STATE_INIT;
    let mut tick = tokio::time::interval_at(last_write + second, second);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            item = rx.recv() => {
                let Some(data) = item else { return };
                let framed = hdlc::frame(&data);
                if let Err(e) = writer.write_all(&framed).await {
                    tracing::warn!(name = %name, error = %e, "I2P: write error");
                    return;
                }
                txb.add(framed.len());
                last_write = tokio::time::Instant::now();
            }
            _ = tick.tick() => {
                let read_age = last_read.lock().unwrap_or_else(|e| e.into_inner()).elapsed();
                if read_age > probe_after * 2 {
                    if tunnel_state != TUNNEL_STATE_STALE {
                        tracing::debug!(name = %name, "I2P tunnel became unresponsive");
                    }
                    tunnel_state = TUNNEL_STATE_STALE;
                } else {
                    tunnel_state = TUNNEL_STATE_ACTIVE;
                }
                shown_state.store(tunnel_state, Ordering::Relaxed);
                // Keepalives do not count as writes, as upstream: they repeat every tick.
                if last_write.elapsed() > probe_after
                    && let Err(e) = writer.write_all(&[hdlc::FLAG, hdlc::FLAG]).await
                {
                    tracing::warn!(name = %name, error = %e, "I2P: error while sending keepalive");
                    return;
                }
                if read_age > read_timeout {
                    tracing::warn!(name = %name, "I2P socket is unresponsive, restarting...");
                    return;
                }
            }
        }
    }
}

/// Reports Python's `i2p_tunnel_state` for an I2P peer.
fn tunnel_inspection(state: Arc<std::sync::atomic::AtomicU8>) -> InterfaceInspectionSource {
    InterfaceInspectionSource::new(move || InterfaceInspectionSnapshot {
        i2p_tunnel_state: Some(state.load(Ordering::Relaxed)),
        ..InterfaceInspectionSnapshot::default()
    })
}

/// Run one I2P stream; the reader, writer and watchdog share a task, so either
/// side ending, or the task being aborted, closes the stream.
#[allow(clippy::too_many_arguments)]
async fn i2p_connection(
    reader: tokio::net::tcp::OwnedReadHalf,
    initial_data: &[u8],
    writer: tokio::net::tcp::OwnedWriteHalf,
    rx: &mut mpsc::Receiver<Bytes>,
    interface_id: InterfaceId,
    transport_tx: &InterfaceTransportSender,
    online: &AtomicBool,
    rxb: &ByteCounter,
    txb: &ByteCounter,
    name: &str,
    tunnel_state: &std::sync::atomic::AtomicU8,
) {
    let last_read = std::sync::Mutex::new(tokio::time::Instant::now());
    tokio::select! {
        _ = i2p_read_loop(reader, initial_data, interface_id, transport_tx, online, rxb, &last_read) => {}
        _ = i2p_write_loop(writer, rx, txb, &last_read, name, tunnel_state) => {}
    }
    online.store(false, Ordering::SeqCst);
}

/// Reconnect pacing for the SAM client loop: bounded tries and fixed waits,
/// reset on every successful connect.
struct ReconnectPacer {
    tries: usize,
    delay: u64,
    max_tries: Option<usize>,
}

impl ReconnectPacer {
    fn new(delay: u64, max_tries: Option<usize>) -> Self {
        Self {
            tries: 0,
            delay,
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

    /// Sleep the reconnect wait (I2PInterfacePeer.reconnect).
    async fn wait(&self) {
        tokio::time::sleep(std::time::Duration::from_secs(self.delay)).await;
    }

    /// Sleep the tunnel setup retry interval.
    async fn wait_tunnel(&self) {
        tokio::time::sleep(std::time::Duration::from_secs(TUNNEL_SETUP_RETRY)).await;
    }

    fn reset(&mut self) {
        self.tries = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peer_python_name_matches_python() {
        // Python 1.5.5 `str()` output for this interface.
        let peer = "abcdefghijklmnop.b32.i2p";
        assert_eq!(
            I2PClientConfig::new(&format!("Golden I2P to {peer}"), peer).python_name(),
            "I2PInterfacePeer[Golden I2P to abcdefghijklmnop.b32.i2p]"
        );
    }

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

    fn i2p_base64(bytes: &[u8]) -> String {
        const ALPHABET: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-~";
        let mut text = String::new();
        for chunk in bytes.chunks(3) {
            let bits = chunk.iter().enumerate().fold(0u32, |bits, (n, byte)| {
                bits | u32::from(*byte) << (16 - 8 * n)
            });
            for n in 0..=chunk.len() {
                text.push(char::from(ALPHABET[(bits >> (18 - 6 * n)) as usize & 63]));
            }
            text.extend(std::iter::repeat_n('=', 3 - chunk.len()));
        }
        text
    }

    fn private_key(certificate: &[u8], secret: u8) -> Vec<u8> {
        let mut key: Vec<u8> = (0..384).map(|n| n as u8).collect();
        key.extend_from_slice(certificate);
        key.extend(std::iter::repeat_n(secret, 288));
        key
    }

    /// Only the destination, keys plus certificate, names the address
    /// (i2plib sam.py:113-129); the golden is checked against i2plib in tests.
    #[test]
    fn the_b32_address_hashes_only_the_destination() {
        let ed25519 = [5, 0, 4, 0, 7, 0, 0];
        let b32 = destination_b32(&i2p_base64(&private_key(&ed25519, 0x42))).unwrap();
        assert_eq!(b32.len(), 52);
        assert!(b32.bytes().all(|c| matches!(c, b'a'..=b'z' | b'2'..=b'7')));
        assert_eq!(
            destination_b32(&i2p_base64(&private_key(&ed25519, 0x24))).as_ref(),
            Some(&b32)
        );
        assert_ne!(
            destination_b32(&i2p_base64(&private_key(&[0, 0, 0], 0x42))).as_ref(),
            Some(&b32)
        );
        assert_eq!(destination_b32("not+base64"), None);
        assert_eq!(destination_b32(&i2p_base64(&[0; 300])), None);
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

    #[tokio::test(start_paused = true)]
    async fn test_pacer_waits_are_fixed_and_reset_clears_tries() {
        let mut pacer = ReconnectPacer::new(RECONNECT_WAIT, Some(10));
        for _ in 0..4 {
            let start = tokio::time::Instant::now();
            pacer.wait().await;
            assert_eq!(start.elapsed().as_secs(), RECONNECT_WAIT);
            let start = tokio::time::Instant::now();
            pacer.wait_tunnel().await;
            assert_eq!(start.elapsed().as_secs(), TUNNEL_SETUP_RETRY);
            let _ = pacer.give_up();
        }
        pacer.reset();
        assert_eq!(pacer.tries, 0);
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
