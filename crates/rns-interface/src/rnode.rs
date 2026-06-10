//! LoRa radio control via RNode firmware's extended-KISS protocol.
//! Shared constants + transport-agnostic response handler. Serial:
//! [`spawn_rnode_interface`] (feature `serial`); BLE: [`crate::ble_rnode`].
//!
//! Transport selection is driven by the `port` string in [`RNodeConfig`]:
//!   - `/dev/ttyUSB0`, `COM3`, etc.  -> serial (feature `serial` required)
//!   - `tcp://192.168.1.1`           -> TCP, default port 7633
//!   - `tcp://192.168.1.1:9000`      -> TCP, explicit port

use bytes::Bytes;

use crate::kiss;
use crate::traits::{InterfaceId, InterfaceMode};
use rns_transport::messages::{InboundPacket, TransportMessage};

#[cfg(any(feature = "serial", feature = "rnode-tcp"))]
use crate::traits::{InterfaceDirection, InterfaceHandle};
#[cfg(any(feature = "serial", feature = "rnode-tcp"))]
use std::collections::HashMap;
#[cfg(any(feature = "serial", feature = "rnode-tcp"))]
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
#[cfg(any(feature = "serial", feature = "rnode-tcp"))]
use std::sync::{Arc, Mutex, OnceLock};
#[cfg(any(feature = "serial", feature = "rnode-tcp"))]
use std::time::Duration;
#[cfg(any(feature = "serial", feature = "rnode-tcp"))]
use tokio::sync::{mpsc, oneshot};

pub const CMD_FREQUENCY: u8 = 0x01;
pub const CMD_BANDWIDTH: u8 = 0x02;
pub const CMD_TXPOWER: u8 = 0x03;
pub const CMD_SF: u8 = 0x04;
pub const CMD_CR: u8 = 0x05;
pub const CMD_RADIO_STATE: u8 = 0x06;
pub const CMD_RADIO_LOCK: u8 = 0x07;
pub const CMD_DETECT: u8 = 0x08;
pub const CMD_IMPLICIT: u8 = 0x09;
pub const CMD_LEAVE: u8 = 0x0A;
pub const CMD_PROMISC: u8 = 0x0E;
pub const CMD_READY: u8 = 0x0F;

pub const CMD_STAT_RX: u8 = 0x21;
pub const CMD_STAT_TX: u8 = 0x22;
pub const CMD_STAT_RSSI: u8 = 0x23;
pub const CMD_STAT_SNR: u8 = 0x24;
pub const CMD_STAT_CHTM: u8 = 0x25;
pub const CMD_STAT_PHYPRM: u8 = 0x26;
pub const CMD_STAT_BAT: u8 = 0x27;
pub const CMD_STAT_EDROP: u8 = 0x28;

pub const CMD_STAT_TEMP: u8 = 0x29;
pub const CMD_ERROR: u8 = 0x90;

pub const CMD_BLINK: u8 = 0x30;
pub const CMD_RANDOM: u8 = 0x40;

pub const CMD_FB_EXT: u8 = 0x41;
pub const CMD_FB_READ: u8 = 0x42;
pub const CMD_FB_WRITE: u8 = 0x43;
pub const CMD_BT_CTRL: u8 = 0x46;

pub const CMD_BOARD: u8 = 0x47;
pub const CMD_PLATFORM: u8 = 0x48;
pub const CMD_MCU: u8 = 0x49;
pub const CMD_FW_VERSION: u8 = 0x50;
pub const CMD_ROM_READ: u8 = 0x51;
pub const CMD_ROM_WRITE: u8 = 0x52;
pub const CMD_CONF_SAVE: u8 = 0x53;
pub const CMD_CONF_DELETE: u8 = 0x54;
pub const CMD_DEV_HASH: u8 = 0x56;
pub const CMD_DEV_SIG: u8 = 0x57;
pub const CMD_FW_HASH: u8 = 0x58;
pub const CMD_ROM_WIPE: u8 = 0x59;
pub const CMD_HASHES: u8 = 0x60;
pub const CMD_FW_UPD: u8 = 0x61;
pub const CMD_BT_PIN: u8 = 0x62;

pub const CMD_ST_ALOCK: u8 = 0x0B;
pub const CMD_LT_ALOCK: u8 = 0x0C;

pub const CMD_RESET: u8 = 0x55;
pub const CMD_DISP_INT: u8 = 0x45;
pub const CMD_DISP_ADR: u8 = 0x63;
pub const CMD_DISP_BLNK: u8 = 0x64;
pub const CMD_NP_INT: u8 = 0x65;
pub const CMD_DISP_ROT: u8 = 0x67;
pub const CMD_DISP_RCND: u8 = 0x68;
pub const CMD_DIS_IA: u8 = 0x69;
pub const CMD_WIFI_MODE: u8 = 0x6A;
pub const CMD_WIFI_SSID: u8 = 0x6B;
pub const CMD_WIFI_PSK: u8 = 0x6C;
pub const CMD_CFG_READ: u8 = 0x6D;
pub const CMD_WIFI_CHN: u8 = 0x6E;
pub const CMD_WIFI_IP: u8 = 0x84;
pub const CMD_WIFI_NM: u8 = 0x85;

pub const DETECT_REQ: u8 = 0x73;
pub const DETECT_RESP: u8 = 0x46;

pub const REQUIRED_FW_VER_MAJ: u8 = 1;
pub const REQUIRED_FW_VER_MIN: u8 = 52;

pub const RSSI_OFFSET: i32 = 157;

pub const RECONNECT_WAIT: u64 = 5;
pub const MAX_RECONNECT_TRIES: usize = 3;

pub const RADIO_STATE_ON: u8 = 0x01;
pub const RADIO_STATE_OFF: u8 = 0x00;

/// Default TCP port for RNode-over-IP.
pub const DEFAULT_TCP_PORT: u16 = 7633;

#[cfg(any(feature = "serial", feature = "rnode-tcp"))]
const RNODE_READ_TIMEOUT_MS: u64 = 100;
#[cfg(any(feature = "serial", feature = "rnode-tcp"))]
const RNODE_TCP_CONNECT_TIMEOUT_SECS: u64 = 5;
#[cfg(any(feature = "serial", feature = "rnode-tcp"))]
const RNODE_TCP_KEEPIDLE_SECS: u64 = 5;
#[cfg(any(feature = "serial", feature = "rnode-tcp"))]
const RNODE_TCP_KEEPINTVL_SECS: u64 = 2;
#[cfg(any(feature = "serial", feature = "rnode-tcp"))]
const RNODE_TCP_KEEPCNT: u32 = 12;
#[cfg(any(feature = "serial", feature = "rnode-tcp"))]
const RNODE_TCP_USER_TIMEOUT_SECS: u64 = 24;
#[cfg(any(feature = "serial", feature = "rnode-tcp"))]
const RNODE_TCP_BUFFER_BYTES: usize = 131_072;

#[cfg(any(feature = "serial", feature = "rnode-tcp"))]
type RNodeStopRegistry = Mutex<HashMap<InterfaceId, mpsc::Sender<()>>>;

#[cfg(any(feature = "serial", feature = "rnode-tcp"))]
fn rnode_stop_registry() -> &'static RNodeStopRegistry {
    static REGISTRY: OnceLock<RNodeStopRegistry> = OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(HashMap::new()))
}

#[cfg(any(feature = "serial", feature = "rnode-tcp"))]
struct RNodeStopRegistryGuard {
    id: InterfaceId,
}

#[cfg(any(feature = "serial", feature = "rnode-tcp"))]
impl Drop for RNodeStopRegistryGuard {
    fn drop(&mut self) {
        rnode_stop_registry()
            .lock()
            .expect("rnode_stop_registry mutex poisoned")
            .remove(&self.id);
    }
}

#[cfg(any(feature = "serial", feature = "rnode-tcp"))]
fn register_rnode_stop(id: InterfaceId, stop_tx: mpsc::Sender<()>) -> RNodeStopRegistryGuard {
    rnode_stop_registry()
        .lock()
        .expect("rnode_stop_registry mutex poisoned")
        .insert(id, stop_tx);
    RNodeStopRegistryGuard { id }
}

/// Ask a serial/TCP RNode interface to send upstream's detach sequence before
/// runtime teardown aborts the task. Idempotent; unknown ids are ignored.
#[cfg(any(feature = "serial", feature = "rnode-tcp"))]
pub fn stop_rnode_interface(id: InterfaceId) {
    let stop_tx = rnode_stop_registry()
        .lock()
        .expect("rnode_stop_registry mutex poisoned")
        .get(&id)
        .cloned();
    let Some(stop_tx) = stop_tx else {
        tracing::debug!(id, "RNode stop requested for unknown interface");
        return;
    };
    match stop_tx.try_send(()) {
        Ok(()) => tracing::info!(id, "RNode stop signal sent"),
        Err(mpsc::error::TrySendError::Full(_)) => {
            tracing::debug!(id, "RNode stop signal already pending")
        }
        Err(mpsc::error::TrySendError::Closed(_)) => {
            tracing::debug!(id, "RNode stop signal receiver already closed")
        }
    }
}

#[cfg(any(feature = "serial", feature = "rnode-tcp"))]
enum RNodeWriteRequest {
    Packet(Bytes),
    Raw(Vec<u8>, oneshot::Sender<()>),
}

#[cfg(any(feature = "serial", feature = "rnode-tcp"))]
async fn send_detach_request(conn_tx: &mpsc::Sender<RNodeWriteRequest>, id: InterfaceId) {
    let (done_tx, done_rx) = oneshot::channel();
    if conn_tx
        .send(RNodeWriteRequest::Raw(build_detach_sequence(), done_tx))
        .await
        .is_err()
    {
        tracing::warn!(id, "RNode detach sequence could not be queued");
        return;
    }

    match tokio::time::timeout(Duration::from_millis(500), done_rx).await {
        Ok(Ok(())) => tracing::info!(id, "RNode detach sequence sent"),
        Ok(Err(_)) => tracing::warn!(id, "RNode detach writer dropped acknowledgement"),
        Err(_) => tracing::warn!(id, "RNode detach sequence timed out"),
    }
}

// Transport abstraction

/// Parsed representation of the `port` config field.
#[cfg(any(feature = "serial", feature = "rnode-tcp"))]
#[derive(Debug, Clone)]
pub enum PortConfig {
    /// A local serial device path, e.g. `/dev/ttyUSB0` or `COM3`.
    #[cfg(feature = "serial")]
    Serial { path: String, baud: u32 },
    /// A TCP endpoint, e.g. `tcp://192.168.1.1` or `tcp://192.168.1.1:9000`.
    Tcp { addr: String },
}

#[cfg(any(feature = "serial", feature = "rnode-tcp"))]
impl PortConfig {
    pub fn parse(port: &str, baud: u32) -> Result<Self, String> {
        #[cfg(not(feature = "serial"))]
        let _ = baud;

        if let Some(rest) = strip_tcp_scheme(port) {
            let addr = parse_tcp_endpoint(rest)?;
            Ok(Self::Tcp { addr })
        } else {
            #[cfg(feature = "serial")]
            {
                Ok(Self::Serial {
                    path: port.to_string(),
                    baud,
                })
            }
            #[cfg(not(feature = "serial"))]
            Err("RNode serial ports require the 'serial' feature; use tcp://host[:port] for TCP RNodes".to_string())
        }
    }
}

#[cfg(any(feature = "serial", feature = "rnode-tcp"))]
fn strip_tcp_scheme(port: &str) -> Option<&str> {
    const TCP_SCHEME: &str = "tcp://";
    port.get(..TCP_SCHEME.len())
        .filter(|prefix| prefix.eq_ignore_ascii_case(TCP_SCHEME))
        .and_then(|_| port.get(TCP_SCHEME.len()..))
}

#[cfg(any(feature = "serial", feature = "rnode-tcp"))]
fn parse_tcp_endpoint(endpoint: &str) -> Result<String, String> {
    if endpoint.is_empty() {
        return Err("missing TCP host".to_string());
    }

    if let Some(rest) = endpoint.strip_prefix('[') {
        let Some(closing) = rest.find(']') else {
            return Err("missing closing ']' in IPv6 TCP host".to_string());
        };
        let host = &rest[..closing];
        if host.is_empty() {
            return Err("missing TCP host".to_string());
        }

        let tail = &rest[closing + 1..];
        let port = if tail.is_empty() {
            DEFAULT_TCP_PORT
        } else if let Some(port) = tail.strip_prefix(':') {
            parse_tcp_port(port)?
        } else {
            return Err("unexpected text after bracketed TCP host".to_string());
        };

        return Ok(format!("[{host}]:{port}"));
    }

    let colon_count = endpoint.matches(':').count();
    match colon_count {
        0 => Ok(format!("{endpoint}:{DEFAULT_TCP_PORT}")),
        1 => {
            let (host, port) = endpoint
                .rsplit_once(':')
                .expect("colon_count guarantees a separator");
            if host.is_empty() {
                return Err("missing TCP host".to_string());
            }
            Ok(format!("{host}:{}", parse_tcp_port(port)?))
        }
        _ => Ok(format!("[{endpoint}]:{DEFAULT_TCP_PORT}")),
    }
}

#[cfg(any(feature = "serial", feature = "rnode-tcp"))]
fn parse_tcp_port(port: &str) -> Result<u16, String> {
    if port.is_empty() {
        return Err("missing TCP port".to_string());
    }
    port.parse::<u16>()
        .map_err(|_| format!("invalid TCP port: {port}"))
}

/// A unified sync I/O stream for either a serial port or a TCP socket.
///
/// Both variants support `Read + Write + Send + 'static` so the existing
/// `spawn_blocking` read/write loops require minimal changes.
#[cfg(any(feature = "serial", feature = "rnode-tcp"))]
pub enum RNodeStream {
    #[cfg(feature = "serial")]
    Serial(Box<dyn serialport::SerialPort>),
    Tcp(std::net::TcpStream),
}

#[cfg(any(feature = "serial", feature = "rnode-tcp"))]
impl RNodeStream {
    /// Open a serial port.
    #[cfg(feature = "serial")]
    pub fn open_serial(path: &str, baud: u32) -> std::io::Result<Self> {
        let port = serialport::new(path, baud)
            .timeout(Duration::from_millis(RNODE_READ_TIMEOUT_MS))
            .open()
            .map_err(std::io::Error::other)?;
        Ok(Self::Serial(port))
    }

    /// Connect to a TCP socket (blocking).
    pub fn connect_tcp(addr: &str) -> std::io::Result<Self> {
        Self::connect_tcp_with_timeout(addr, Duration::from_secs(RNODE_TCP_CONNECT_TIMEOUT_SECS))
    }

    fn connect_tcp_with_timeout(addr: &str, timeout: Duration) -> std::io::Result<Self> {
        use std::net::ToSocketAddrs;

        let mut last_error = None;
        for socket_addr in addr.to_socket_addrs()? {
            match std::net::TcpStream::connect_timeout(&socket_addr, timeout) {
                Ok(stream) => return Self::from_tcp_stream(stream),
                Err(e) => last_error = Some(e),
            }
        }

        Err(last_error.unwrap_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::AddrNotAvailable,
                format!("no socket addresses resolved for {addr}"),
            )
        }))
    }

    fn from_tcp_stream(stream: std::net::TcpStream) -> std::io::Result<Self> {
        // Mirror the serial timeout so the read loop doesn't block forever.
        stream.set_read_timeout(Some(Duration::from_millis(RNODE_READ_TIMEOUT_MS)))?;
        stream.set_nodelay(true)?;
        crate::socket_tuning::set_keepalive_tuned_std(
            &stream,
            Duration::from_secs(RNODE_TCP_KEEPIDLE_SECS),
            Duration::from_secs(RNODE_TCP_KEEPINTVL_SECS),
            RNODE_TCP_KEEPCNT,
            Duration::from_secs(RNODE_TCP_USER_TIMEOUT_SECS),
        );
        crate::socket_tuning::set_socket_buffers_std(&stream, RNODE_TCP_BUFFER_BYTES);
        Ok(Self::Tcp(stream))
    }

    /// Shallow-clone the stream for the write half.
    ///
    /// - Serial: uses `SerialPort::try_clone`.
    /// - TCP: uses `TcpStream::try_clone` (both halves share the same fd).
    pub fn try_clone(&self) -> std::io::Result<Self> {
        match self {
            #[cfg(feature = "serial")]
            Self::Serial(p) => Ok(Self::Serial(p.try_clone().map_err(std::io::Error::other)?)),
            Self::Tcp(s) => Ok(Self::Tcp(s.try_clone()?)),
        }
    }

    /// Human-readable description for log messages.
    pub fn description(&self) -> String {
        match self {
            #[cfg(feature = "serial")]
            Self::Serial(p) => p.name().unwrap_or_else(|| "<unknown serial>".to_string()),
            Self::Tcp(s) => s
                .peer_addr()
                .map(|a| a.to_string())
                .unwrap_or_else(|_| "<unknown tcp>".to_string()),
        }
    }

    fn is_tcp(&self) -> bool {
        matches!(self, Self::Tcp(_))
    }
}

#[cfg(any(feature = "serial", feature = "rnode-tcp"))]
impl std::io::Read for RNodeStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            #[cfg(feature = "serial")]
            Self::Serial(p) => p.read(buf),
            Self::Tcp(s) => s.read(buf),
        }
    }
}

#[cfg(any(feature = "serial", feature = "rnode-tcp"))]
impl std::io::Write for RNodeStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            #[cfg(feature = "serial")]
            Self::Serial(p) => p.write(buf),
            Self::Tcp(s) => s.write(buf),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            #[cfg(feature = "serial")]
            Self::Serial(p) => p.flush(),
            Self::Tcp(s) => s.flush(),
        }
    }
}

#[cfg(any(feature = "serial", feature = "rnode-tcp"))]
fn read_rnode_stream(
    mut stream: RNodeStream,
    mut buf: [u8; 1024],
) -> Result<(RNodeStream, [u8; 1024], usize), (RNodeStream, std::io::Error)> {
    use std::io::Read;

    match stream.read(&mut buf) {
        Ok(0) if stream.is_tcp() => Err((
            stream,
            std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "RNode TCP socket closed"),
        )),
        Ok(n) => Ok((stream, buf, n)),
        // Serial returns TimedOut; TCP returns WouldBlock on non-blocking
        // or TimedOut on a read-timeout. Treat both as "no data yet".
        Err(e)
            if e.kind() == std::io::ErrorKind::TimedOut
                || e.kind() == std::io::ErrorKind::WouldBlock =>
        {
            Ok((stream, buf, 0))
        }
        Err(e) => Err((stream, e)),
    }
}

#[cfg(any(feature = "serial", feature = "rnode-tcp"))]
async fn open_configured_rnode_stream(
    config: &RNodeConfig,
    port_cfg: &PortConfig,
) -> Result<RNodeStream, crate::traits::InterfaceError> {
    let port = match port_cfg {
        #[cfg(feature = "serial")]
        PortConfig::Serial { path, baud } => {
            tracing::info!(
                name = %config.name,
                port = %path,
                baud = baud,
                "RNode serial interface opening"
            );
            RNodeStream::open_serial(path, *baud).map_err(|e| {
                crate::traits::InterfaceError::SendFailed(format!("rnode serial open: {}", e))
            })?
        }
        PortConfig::Tcp { addr } => {
            tracing::info!(
                name = %config.name,
                addr = %addr,
                "RNode TCP interface connecting"
            );
            let addr = addr.clone();
            tokio::task::spawn_blocking(move || RNodeStream::connect_tcp(&addr))
                .await
                .map_err(|e| {
                    crate::traits::InterfaceError::SendFailed(format!("rnode tcp spawn: {}", e))
                })?
                .map_err(|e| {
                    crate::traits::InterfaceError::SendFailed(format!("rnode tcp connect: {}", e))
                })?
        }
    };

    tracing::info!(
        name = %config.name,
        endpoint = %port.description(),
        freq = config.frequency,
        bw = config.bandwidth,
        sf = config.spreading_factor,
        "RNode interface opened"
    );

    {
        let mut detect_port = port.try_clone().map_err(|e| {
            crate::traits::InterfaceError::SendFailed(format!("rnode clone: {}", e))
        })?;
        let detect_seq = build_detect_sequence();
        use std::io::Write;
        detect_port.write_all(&detect_seq).map_err(|e| {
            crate::traits::InterfaceError::SendFailed(format!("rnode detect write: {}", e))
        })?;
        detect_port.flush().map_err(|e| {
            crate::traits::InterfaceError::SendFailed(format!("rnode detect flush: {}", e))
        })?;
    }

    {
        let mut init_port = port.try_clone().map_err(|e| {
            crate::traits::InterfaceError::SendFailed(format!("rnode clone: {}", e))
        })?;
        let init_seq = build_init_sequence(config);
        use std::io::Write;
        init_port.write_all(&init_seq).map_err(|e| {
            crate::traits::InterfaceError::SendFailed(format!("rnode init write: {}", e))
        })?;
        init_port.flush().map_err(|e| {
            crate::traits::InterfaceError::SendFailed(format!("rnode init flush: {}", e))
        })?;
    }

    Ok(port)
}

#[cfg(any(feature = "serial", feature = "rnode-tcp"))]
fn reconnect_delay() -> Duration {
    #[cfg(test)]
    {
        Duration::from_millis(100)
    }
    #[cfg(not(test))]
    {
        Duration::from_secs(RECONNECT_WAIT)
    }
}

#[derive(Debug, Clone)]
pub struct RNodeConfig {
    pub name: String,
    /// Serial device path (`/dev/ttyUSB0`) **or** TCP URL (`tcp://host[:port]`).
    pub port: String,
    pub baud_rate: u32,
    /// Hz.
    pub frequency: u32,
    /// Hz.
    pub bandwidth: u32,
    pub spreading_factor: u8,
    pub coding_rate: u8,
    /// dBm.
    pub tx_power: u8,
    pub mode: InterfaceMode,
    pub flow_control: bool,
    /// Short-term airtime cap, percent (0.0..100.0). `None` = unlimited.
    pub st_alock: Option<f32>,
    /// Long-term airtime cap, percent (0.0..100.0). `None` = unlimited.
    pub lt_alock: Option<f32>,
    /// Station-ID beacon: seconds between IDs, armed by data TX
    /// (Python `id_interval`/`id_callsign`, callsign max 32 bytes).
    pub id_interval: Option<u64>,
    pub id_callsign: Option<Vec<u8>>,
}

/// Python `RNodeInterface.CALLSIGN_MAX_LEN`.
pub const CALLSIGN_MAX_LEN: usize = 32;

impl RNodeConfig {
    pub fn new(name: &str, port: &str) -> Self {
        Self {
            name: name.to_string(),
            port: port.to_string(),
            baud_rate: 115200,
            frequency: 868_000_000,
            bandwidth: 125_000,
            spreading_factor: 7,
            coding_rate: 5,
            tx_power: 14,
            mode: InterfaceMode::Full,
            // Python RNodeInterface defaults flow_control off.
            flow_control: false,
            st_alock: None,
            lt_alock: None,
            id_interval: None,
            id_callsign: None,
        }
    }
}

/// LoRa on-air bps via `SF * (4/CR) / (2^SF / BW_kHz) * 1000`. 0 on invalid.
pub fn calculate_bitrate(sf: u8, cr: u8, bandwidth_hz: u32) -> u64 {
    if sf == 0 || cr == 0 || bandwidth_hz == 0 {
        return 0;
    }
    let sf_f = sf as f64;
    let cr_f = cr as f64;
    let bw_khz = bandwidth_hz as f64 / 1000.0;
    let two_pow_sf = (2.0_f64).powf(sf_f);
    if two_pow_sf == 0.0 {
        return 0;
    }
    let bitrate = sf_f * (4.0 / cr_f) / (two_pow_sf / bw_khz) * 1000.0;
    if bitrate.is_finite() && bitrate > 0.0 {
        bitrate as u64
    } else {
        0
    }
}

pub fn build_detect_sequence() -> Vec<u8> {
    let mut out = Vec::with_capacity(32);
    kiss::frame_with_command_into(CMD_DETECT, &[DETECT_REQ], &mut out);
    kiss::frame_with_command_into(CMD_FW_VERSION, &[0x00], &mut out);
    kiss::frame_with_command_into(CMD_PLATFORM, &[0x00], &mut out);
    kiss::frame_with_command_into(CMD_MCU, &[0x00], &mut out);
    out
}

/// Airtime-lock commands. Percent is encoded as `(percent * 100)` big-endian u16.
pub fn build_airtime_sequence(config: &RNodeConfig) -> Vec<u8> {
    let mut out = Vec::with_capacity(16);
    if let Some(st) = config.st_alock {
        let at = (st * 100.0) as u16;
        let c1 = (at >> 8) as u8;
        let c2 = (at & 0xFF) as u8;
        kiss::frame_with_command_into(CMD_ST_ALOCK, &[c1, c2], &mut out);
    }
    if let Some(lt) = config.lt_alock {
        let at = (lt * 100.0) as u16;
        let c1 = (at >> 8) as u8;
        let c2 = (at & 0xFF) as u8;
        kiss::frame_with_command_into(CMD_LT_ALOCK, &[c1, c2], &mut out);
    }
    out
}

fn u32_to_bytes(val: u32) -> [u8; 4] {
    val.to_be_bytes()
}

/// KISS init sequence. Order matters: airtime locks precede RADIO_STATE=ON,
/// which must be last (Python `initRadio`, RNodeInterface.py:470-478).
pub fn build_init_sequence(config: &RNodeConfig) -> Vec<u8> {
    let mut out = Vec::with_capacity(64);
    kiss::frame_with_command_into(CMD_FREQUENCY, &u32_to_bytes(config.frequency), &mut out);
    kiss::frame_with_command_into(CMD_BANDWIDTH, &u32_to_bytes(config.bandwidth), &mut out);
    kiss::frame_with_command_into(CMD_SF, &[config.spreading_factor], &mut out);
    kiss::frame_with_command_into(CMD_CR, &[config.coding_rate], &mut out);
    kiss::frame_with_command_into(CMD_TXPOWER, &[config.tx_power], &mut out);
    out.extend_from_slice(&build_airtime_sequence(config));
    kiss::frame_with_command_into(CMD_RADIO_STATE, &[RADIO_STATE_ON], &mut out);
    out
}

/// KISS sequence for returning an RNode radio to idle before disconnecting.
pub fn build_radio_off_sequence() -> Vec<u8> {
    let mut out = Vec::with_capacity(4);
    kiss::frame_with_command_into(CMD_RADIO_STATE, &[RADIO_STATE_OFF], &mut out);
    out
}

/// KISS sequence matching upstream RNodeInterface.detach(): radio off, then
/// leave host-controlled mode so device UI state is reset before disconnect.
pub fn build_detach_sequence() -> Vec<u8> {
    let mut out = Vec::with_capacity(8);
    kiss::frame_with_command_into(CMD_RADIO_STATE, &[RADIO_STATE_OFF], &mut out);
    kiss::frame_with_command_into(CMD_LEAVE, &[0xFF], &mut out);
    out
}

// Hot-path interface adapters pass this enum around directly; boxing the
// packet variant would add allocation to every received frame.
#[allow(clippy::large_enum_variant)]
pub enum RNodeResponse {
    Packet(TransportMessage),
    Ready(bool),
    None,
}

/// Python: raw unsigned RSSI byte minus `RSSI_OFFSET` (157) → dBm.
pub fn decode_rssi_byte(byte: u8) -> f32 {
    byte as f32 - RSSI_OFFSET as f32
}

/// Python: signed SNR byte × 0.25 → dB.
pub fn decode_snr_byte(byte: u8) -> f32 {
    byte as i8 as f32 / 4.0
}

/// Dispatch decoded KISS frame; shared by serial and BLE transports.
pub fn process_rnode_response(
    cmd: u8,
    frame: &[u8],
    id: InterfaceId,
    last_rssi: &mut Option<f32>,
    last_snr: &mut Option<f32>,
) -> RNodeResponse {
    match cmd {
        kiss::CMD_DATA => {
            if frame.is_empty() {
                return RNodeResponse::None;
            }
            let msg = TransportMessage::Inbound(InboundPacket {
                raw: Bytes::copy_from_slice(frame),
                interface_id: id,
                rssi: *last_rssi,
                snr: *last_snr,
                q: None,
            });
            // RSSI/SNR stats attach to the next data frame; clear once consumed.
            *last_rssi = None;
            *last_snr = None;
            RNodeResponse::Packet(msg)
        }
        CMD_STAT_RSSI => {
            if !frame.is_empty() {
                *last_rssi = Some(decode_rssi_byte(frame[0]));
            }
            RNodeResponse::None
        }
        CMD_STAT_SNR => {
            if !frame.is_empty() {
                *last_snr = Some(decode_snr_byte(frame[0]));
            }
            RNodeResponse::None
        }
        CMD_READY => {
            let is_ready = frame.first().copied().unwrap_or(0) != 0;
            RNodeResponse::Ready(is_ready)
        }
        CMD_DETECT => {
            if frame.first().copied() == Some(DETECT_RESP) {
                tracing::info!(id, "RNode detected");
            }
            RNodeResponse::None
        }
        CMD_RADIO_STATE => {
            if frame.first().copied() == Some(RADIO_STATE_ON) {
                tracing::info!(id, "RNode radio online");
            } else {
                tracing::warn!(id, "RNode radio offline");
            }
            RNodeResponse::None
        }
        CMD_FW_VERSION => {
            if frame.len() >= 2 {
                let major = frame[0];
                let minor = frame[1];
                tracing::info!(
                    id,
                    major,
                    minor,
                    "RNode firmware version {}.{}",
                    major,
                    minor,
                );
                if major < REQUIRED_FW_VER_MAJ
                    || (major == REQUIRED_FW_VER_MAJ && minor < REQUIRED_FW_VER_MIN)
                {
                    tracing::warn!(
                        id,
                        "RNode firmware {}.{} below required {}.{}",
                        major,
                        minor,
                        REQUIRED_FW_VER_MAJ,
                        REQUIRED_FW_VER_MIN,
                    );
                }
            }
            RNodeResponse::None
        }
        CMD_ST_ALOCK => {
            if frame.len() >= 2 {
                let at = ((frame[0] as u16) << 8) | frame[1] as u16;
                let pct = at as f32 / 100.0;
                tracing::debug!(id, "RNode short-term airtime limit: {:.2}%", pct);
            }
            RNodeResponse::None
        }
        CMD_LT_ALOCK => {
            if frame.len() >= 2 {
                let at = ((frame[0] as u16) << 8) | frame[1] as u16;
                let pct = at as f32 / 100.0;
                tracing::debug!(id, "RNode long-term airtime limit: {:.2}%", pct);
            }
            RNodeResponse::None
        }
        CMD_STAT_BAT => {
            if frame.len() >= 2 {
                let batt = ((frame[0] as u16) << 8) | frame[1] as u16;
                tracing::debug!(id, battery_mv = batt, "RNode battery status");
            }
            RNodeResponse::None
        }
        CMD_STAT_TEMP => {
            if !frame.is_empty() {
                let temp = frame[0] as i8;
                tracing::debug!(id, temp_c = temp, "RNode temperature");
            }
            RNodeResponse::None
        }
        CMD_RADIO_LOCK => {
            let locked = frame.first().copied().unwrap_or(0) != 0;
            tracing::debug!(id, locked, "RNode radio lock state");
            RNodeResponse::None
        }
        CMD_ERROR => {
            tracing::warn!(
                id,
                error_code = frame.first().copied().unwrap_or(0),
                "RNode reported error"
            );
            RNodeResponse::None
        }
        _ => {
            tracing::debug!(id, cmd, "RNode: ignoring KISS command");
            RNodeResponse::None
        }
    }
}

#[cfg(any(feature = "serial", feature = "rnode-tcp"))]
pub async fn spawn_rnode_interface(
    config: RNodeConfig,
    id: InterfaceId,
    transport_tx: mpsc::Sender<TransportMessage>,
) -> Result<InterfaceHandle, crate::traits::InterfaceError> {
    let port_cfg = PortConfig::parse(&config.port, config.baud_rate).map_err(|e| {
        crate::traits::InterfaceError::SendFailed(format!("rnode port parse: {}", e))
    })?;

    let port = open_configured_rnode_stream(&config, &port_cfg).await?;

    let bitrate = calculate_bitrate(
        config.spreading_factor,
        config.coding_rate,
        config.bandwidth,
    );
    tracing::info!(
        bitrate_bps = bitrate,
        bitrate_kbps = format!("{:.2}", bitrate as f64 / 1000.0),
        "RNode on-air bitrate calculated"
    );

    let online = Arc::new(AtomicBool::new(true));
    let shared_rxb = Arc::new(AtomicU64::new(0));
    let shared_txb = Arc::new(AtomicU64::new(0));
    let (tx, rx) = mpsc::channel::<Bytes>(256);
    let rx = Arc::new(tokio::sync::Mutex::new(rx));
    let (stop_tx, mut stop_rx) = mpsc::channel::<()>(1);
    let stop_guard = register_rnode_stop(id, stop_tx);
    let name = config.name.clone();
    let mode = config.mode;
    let flow_control = config.flow_control;
    // Python RNodeInterface.py:333-343: oversized callsigns disable beaconing.
    let beacon: Option<(Duration, Bytes)> = config
        .id_interval
        .zip(config.id_callsign.clone())
        .filter(|(_, callsign)| {
            let ok = callsign.len() <= CALLSIGN_MAX_LEN;
            if !ok {
                tracing::error!(
                    name = %config.name,
                    len = callsign.len(),
                    "id_callsign exceeds {CALLSIGN_MAX_LEN} bytes, beaconing disabled"
                );
            }
            ok
        })
        .map(|(interval, callsign)| (Duration::from_secs(interval), Bytes::from(callsign)));

    let online_r = online.clone();
    let rxb_r = shared_rxb.clone();
    let txb_r = shared_txb.clone();
    let task_config = config.clone();
    let task_port_cfg = port_cfg.clone();
    let task_name = config.name.clone();
    let read_task = tokio::spawn(async move {
        let _stop_guard = stop_guard;
        let mut next_port = Some(port);

        loop {
            if stop_rx.try_recv().is_ok() {
                tracing::info!(name = %task_name, "RNode stop requested before reconnect");
                return;
            }
            let mut port_r = match next_port.take() {
                Some(port) => port,
                None => match open_configured_rnode_stream(&task_config, &task_port_cfg).await {
                    Ok(port) => port,
                    Err(e) => {
                        online_r.store(false, Ordering::SeqCst);
                        tracing::warn!(
                            name = %task_name,
                            error = %e,
                            "RNode reconnect failed"
                        );
                        tokio::select! {
                            _ = stop_rx.recv() => {
                                tracing::info!(name = %task_name, "RNode stop requested during reconnect backoff");
                                return;
                            }
                            _ = tokio::time::sleep(reconnect_delay()) => {}
                        }
                        continue;
                    }
                },
            };

            online_r.store(true, Ordering::SeqCst);
            let port_write = match port_r.try_clone() {
                Ok(port) => port,
                Err(e) => {
                    tracing::warn!(error = %e, "RNode clone failed before reconnect");
                    online_r.store(false, Ordering::SeqCst);
                    tokio::select! {
                        _ = stop_rx.recv() => {
                            tracing::info!(name = %task_name, "RNode stop requested during reconnect backoff");
                            return;
                        }
                        _ = tokio::time::sleep(reconnect_delay()) => {}
                    }
                    continue;
                }
            };

            let ready = Arc::new(AtomicBool::new(true));
            let (conn_tx, mut conn_rx) = mpsc::channel::<RNodeWriteRequest>(256);
            let conn_tx_for_stop = conn_tx.clone();

            let online_w = online_r.clone();
            let ready_w = ready.clone();
            let txb_w = txb_r.clone();
            let beacon_w = beacon.clone();
            let write_handle = tokio::spawn(async move {
                let mut port_w = port_write;
                // Python first_tx semantics: armed by data TX, cleared when
                // the callsign beacon goes out (RNodeInterface.py:712-718, 1142-1146).
                let mut first_tx: Option<tokio::time::Instant> = None;
                loop {
                    let request = if let Some((interval, ref callsign)) = beacon_w {
                        match tokio::time::timeout(Duration::from_secs(1), conn_rx.recv()).await {
                            Ok(Some(request)) => request,
                            Ok(None) => break,
                            Err(_) => {
                                if first_tx.is_none_or(|t| t.elapsed() < interval) {
                                    continue;
                                }
                                tracing::debug!("RNode transmitting station-ID beacon");
                                RNodeWriteRequest::Packet(callsign.clone())
                            }
                        }
                    } else {
                        match conn_rx.recv().await {
                            Some(request) => request,
                            None => break,
                        }
                    };
                    let (framed, is_packet, done_tx) = match request {
                        RNodeWriteRequest::Packet(data) => {
                            if let Some((_, ref callsign)) = beacon_w {
                                if data == *callsign {
                                    first_tx = None;
                                } else if first_tx.is_none() {
                                    first_tx = Some(tokio::time::Instant::now());
                                }
                            }
                            txb_w
                                .fetch_add(data.len() as u64, std::sync::atomic::Ordering::Relaxed);
                            (kiss::frame(&data), true, None)
                        }
                        RNodeWriteRequest::Raw(frame, done_tx) => (frame, false, Some(done_tx)),
                    };
                    if is_packet && flow_control {
                        while !ready_w.load(Ordering::SeqCst) {
                            tokio::time::sleep(Duration::from_millis(10)).await;
                            if !online_w.load(Ordering::SeqCst) {
                                return;
                            }
                        }
                    }
                    let online_ref = online_w.clone();
                    let result = tokio::task::spawn_blocking(move || {
                        use std::io::Write;
                        port_w.write_all(&framed)?;
                        port_w.flush()?;
                        Ok::<_, std::io::Error>(port_w)
                    })
                    .await;
                    if let Some(done_tx) = done_tx {
                        let _ = done_tx.send(());
                    }
                    match result {
                        Ok(Ok(p)) => {
                            port_w = p;
                        }
                        Ok(Err(e)) => {
                            tracing::warn!(error = %e, "RNode write error");
                            online_ref.store(false, Ordering::SeqCst);
                            break;
                        }
                        Err(e) => {
                            tracing::warn!(error = %e, "RNode write task panicked");
                            online_ref.store(false, Ordering::SeqCst);
                            break;
                        }
                    }
                }
            });

            let rx_ref = rx.clone();
            let fwd_handle = tokio::spawn(async move {
                let mut guard = rx_ref.lock().await;
                while let Some(data) = guard.recv().await {
                    if conn_tx.send(RNodeWriteRequest::Packet(data)).await.is_err() {
                        break;
                    }
                }
            });

            let mut deframer = kiss::RawKissDeframer::new();
            let mut buf = [0u8; 1024];
            let mut last_rssi: Option<f32> = None;
            let mut last_snr: Option<f32> = None;
            let mut transport_closed = false;
            let mut stop_requested = false;

            loop {
                if stop_rx.try_recv().is_ok() {
                    tracing::info!(name = %task_name, "RNode stop requested");
                    send_detach_request(&conn_tx_for_stop, id).await;
                    stop_requested = true;
                    break;
                }
                if !online_r.load(Ordering::SeqCst) {
                    break;
                }
                let result =
                    tokio::task::spawn_blocking(move || read_rnode_stream(port_r, buf)).await;

                match result {
                    Ok(Ok((p, b, n))) => {
                        port_r = p;
                        buf = b;
                        if n > 0 {
                            for (cmd, frame) in deframer.feed(&buf[..n]) {
                                match process_rnode_response(
                                    cmd,
                                    &frame,
                                    id,
                                    &mut last_rssi,
                                    &mut last_snr,
                                ) {
                                    RNodeResponse::Packet(msg) => {
                                        rxb_r.fetch_add(
                                            frame.len() as u64,
                                            std::sync::atomic::Ordering::Relaxed,
                                        );
                                        if transport_tx.send(msg).await.is_err() {
                                            tracing::warn!(id, "transport channel closed");
                                            transport_closed = true;
                                            break;
                                        }
                                    }
                                    RNodeResponse::Ready(is_ready) => {
                                        ready.store(is_ready, Ordering::SeqCst);
                                    }
                                    RNodeResponse::None => {}
                                }
                            }
                            if transport_closed {
                                break;
                            }
                        }
                    }
                    Ok(Err((_p, e))) => {
                        tracing::warn!(error = %e, "RNode read error");
                        break;
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "RNode read task panicked");
                        break;
                    }
                }
            }

            online_r.store(false, Ordering::SeqCst);
            fwd_handle.abort();
            let _ = fwd_handle.await;
            write_handle.abort();
            let _ = write_handle.await;

            if stop_requested || transport_closed {
                return;
            }

            tracing::info!(name = %task_name, "RNode reconnecting");
            tokio::select! {
                _ = stop_rx.recv() => {
                    tracing::info!(name = %task_name, "RNode stop requested during reconnect backoff");
                    return;
                }
                _ = tokio::time::sleep(reconnect_delay()) => {}
            }
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
        bitrate,
        mtu: 508,
        online,
        rxb: Some(shared_rxb),
        txb: Some(shared_txb),
        tx,
        read_task,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rnode_config() {
        let cfg = RNodeConfig::new("rnode0", "/dev/ttyACM0");
        assert_eq!(cfg.baud_rate, 115200);
        assert_eq!(cfg.frequency, 868_000_000);
        assert_eq!(cfg.spreading_factor, 7);
        assert!(
            !cfg.flow_control,
            "flow_control defaults off (Python parity)"
        );
        assert!(cfg.st_alock.is_none());
        assert!(cfg.lt_alock.is_none());
    }

    /// Python parity (RNodeInterface.py:878,880): RSSI = raw byte − 157,
    /// SNR = signed byte × 0.25.
    #[test]
    fn test_rssi_snr_decode_matches_python() {
        assert_eq!(decode_rssi_byte(67), -90.0);
        assert_eq!(decode_rssi_byte(157), 0.0);
        assert_eq!(decode_rssi_byte(0), -157.0);
        assert_eq!(decode_snr_byte(20), 5.0);
        assert_eq!(decode_snr_byte(0xF6), -2.5); // -10 as i8

        let mut rssi = None;
        let mut snr = None;
        let resp = process_rnode_response(CMD_STAT_RSSI, &[67], 0, &mut rssi, &mut snr);
        assert!(matches!(resp, RNodeResponse::None));
        assert_eq!(rssi, Some(-90.0));
    }

    #[test]
    fn test_init_sequence_parseable() {
        let cfg = RNodeConfig::new("rnode0", "/dev/ttyACM0");
        let seq = build_init_sequence(&cfg);
        assert!(!seq.is_empty());
        assert_eq!(seq[0], kiss::FEND);

        let mut deframer = kiss::RawKissDeframer::new();
        let frames = deframer.feed(&seq);
        assert_eq!(frames.len(), 6);
    }

    /// Byte-exact vs Python `setSTALock`/`setLTALock` (RNodeInterface.py:612-630):
    /// `at = int(pct * 100)` big-endian u16, KISS-escaped, framed per command.
    #[test]
    fn test_airtime_sequence_matches_python_encoding() {
        let mut cfg = RNodeConfig::new("rnode0", "/dev/ttyACM0");
        cfg.st_alock = Some(33.0);
        cfg.lt_alock = Some(3.3);
        let seq = build_airtime_sequence(&cfg);

        // st: 3300 = 0x0CE4, lt: 330 = 0x014A — no KISS-special bytes, framed verbatim.
        let expected = [
            kiss::FEND,
            CMD_ST_ALOCK,
            0x0C,
            0xE4,
            kiss::FEND,
            kiss::FEND,
            CMD_LT_ALOCK,
            0x01,
            0x4A,
            kiss::FEND,
        ];
        assert_eq!(seq, expected);

        cfg.st_alock = None;
        cfg.lt_alock = None;
        assert!(build_airtime_sequence(&cfg).is_empty());
    }

    /// Airtime frames are part of the radio init sequence when configured.
    #[test]
    fn test_init_sequence_includes_airtime_commands() {
        let mut cfg = RNodeConfig::new("rnode0", "/dev/ttyACM0");
        cfg.st_alock = Some(10.0);
        cfg.lt_alock = Some(1.0);
        let seq = build_init_sequence(&cfg);

        let mut deframer = kiss::RawKissDeframer::new();
        let frames = deframer.feed(&seq);
        let cmds: Vec<u8> = frames.iter().map(|(c, _)| *c).collect();
        assert!(cmds.contains(&CMD_ST_ALOCK), "init must send CMD_ST_ALOCK");
        assert!(cmds.contains(&CMD_LT_ALOCK), "init must send CMD_LT_ALOCK");
    }

    #[test]
    fn test_u32_to_bytes() {
        assert_eq!(u32_to_bytes(868_000_000), 868_000_000u32.to_be_bytes());
        assert_eq!(u32_to_bytes(0x01020304), [0x01, 0x02, 0x03, 0x04]);
    }

    #[test]
    fn test_calculate_bitrate() {
        // 7 * (4/5) / (2^7 / 125) * 1000 = 5468.75 bps -> 5468.
        let br = calculate_bitrate(7, 5, 125_000);
        assert_eq!(br, 5468);

        let br2 = calculate_bitrate(12, 8, 125_000);
        assert!(br2 > 0);
        assert!(br2 < br);

        assert_eq!(calculate_bitrate(0, 5, 125_000), 0);
        assert_eq!(calculate_bitrate(7, 0, 125_000), 0);
        assert_eq!(calculate_bitrate(7, 5, 0), 0);
    }

    #[test]
    fn test_detect_sequence() {
        let seq = build_detect_sequence();
        assert!(!seq.is_empty());
        let mut deframer = kiss::RawKissDeframer::new();
        let frames = deframer.feed(&seq);
        assert_eq!(frames.len(), 4);
        assert_eq!(frames[0].0, CMD_DETECT);
    }

    #[test]
    fn test_radio_off_sequence() {
        let seq = build_radio_off_sequence();
        let mut deframer = kiss::RawKissDeframer::new();
        let frames = deframer.feed(&seq);
        assert_eq!(frames, vec![(CMD_RADIO_STATE, vec![RADIO_STATE_OFF])]);
    }

    #[test]
    fn test_detach_sequence() {
        let seq = build_detach_sequence();
        let mut deframer = kiss::RawKissDeframer::new();
        let frames = deframer.feed(&seq);
        assert_eq!(
            frames,
            vec![
                (CMD_RADIO_STATE, vec![RADIO_STATE_OFF]),
                (CMD_LEAVE, vec![0xFF]),
            ]
        );
    }

    #[cfg(any(feature = "serial", feature = "rnode-tcp"))]
    #[test]
    fn test_stop_rnode_interface_signals_registered_driver() {
        let id = 0x0BAD_5700;
        let (stop_tx, mut stop_rx) = mpsc::channel::<()>(1);
        let guard = register_rnode_stop(id, stop_tx);

        stop_rnode_interface(id);

        assert!(stop_rx.try_recv().is_ok());
        drop(guard);
        stop_rnode_interface(id);
    }

    #[test]
    fn test_airtime_sequence() {
        let mut cfg = RNodeConfig::new("rnode0", "/dev/ttyACM0");
        assert!(build_airtime_sequence(&cfg).is_empty());

        cfg.st_alock = Some(15.0);
        cfg.lt_alock = Some(25.0);
        let seq = build_airtime_sequence(&cfg);
        assert!(!seq.is_empty());

        let mut deframer = kiss::RawKissDeframer::new();
        let frames = deframer.feed(&seq);
        assert_eq!(frames.len(), 2);
        assert_eq!(frames[0].0, CMD_ST_ALOCK);
        assert_eq!(frames[1].0, CMD_LT_ALOCK);
    }

    #[test]
    fn test_rnode_admin_constants_match_upstream() {
        assert_eq!(CMD_BOARD, 0x47);
        assert_eq!(CMD_BT_PIN, 0x62);
        assert_eq!(CMD_DISP_INT, 0x45);
        assert_eq!(CMD_DISP_ADR, 0x63);
        assert_eq!(CMD_WIFI_IP, 0x84);
        assert_eq!(CMD_WIFI_NM, 0x85);
    }

    #[cfg(feature = "serial")]
    #[test]
    fn test_port_config_serial() {
        let cfg = PortConfig::parse("/dev/ttyUSB0", 115200).unwrap();
        assert!(matches!(cfg, PortConfig::Serial { path, .. } if path == "/dev/ttyUSB0"));
    }

    #[cfg(any(feature = "serial", feature = "rnode-tcp"))]
    #[test]
    fn test_port_config_tcp_default_port() {
        let cfg = PortConfig::parse("tcp://192.168.1.1", 115200).unwrap();
        match cfg {
            PortConfig::Tcp { addr } => assert_eq!(addr, "192.168.1.1:7633"),
            #[cfg(feature = "serial")]
            _ => panic!("expected Tcp variant"),
        }
    }

    #[cfg(any(feature = "serial", feature = "rnode-tcp"))]
    #[test]
    fn test_port_config_tcp_explicit_port() {
        let cfg = PortConfig::parse("tcp://192.168.1.1:9000", 115200).unwrap();
        match cfg {
            PortConfig::Tcp { addr } => assert_eq!(addr, "192.168.1.1:9000"),
            #[cfg(feature = "serial")]
            _ => panic!("expected Tcp variant"),
        }
    }

    #[cfg(any(feature = "serial", feature = "rnode-tcp"))]
    #[test]
    fn test_port_config_tcp_hostname() {
        let cfg = PortConfig::parse("tcp://rnode.local", 115200).unwrap();
        match cfg {
            PortConfig::Tcp { addr } => assert_eq!(addr, "rnode.local:7633"),
            #[cfg(feature = "serial")]
            _ => panic!("expected Tcp variant"),
        }
    }

    #[cfg(any(feature = "serial", feature = "rnode-tcp"))]
    #[test]
    fn test_port_config_tcp_case_insensitive_scheme() {
        let cfg = PortConfig::parse("TCP://rnode.local", 115200).unwrap();
        match cfg {
            PortConfig::Tcp { addr } => assert_eq!(addr, "rnode.local:7633"),
            #[cfg(feature = "serial")]
            _ => panic!("expected Tcp variant"),
        }
    }

    #[cfg(any(feature = "serial", feature = "rnode-tcp"))]
    #[test]
    fn test_port_config_tcp_empty_host_rejected() {
        let err = PortConfig::parse("tcp://", 115200).unwrap_err();
        assert!(err.contains("missing TCP host"));
    }

    #[cfg(any(feature = "serial", feature = "rnode-tcp"))]
    #[test]
    fn test_port_config_tcp_invalid_port_rejected() {
        let err = PortConfig::parse("tcp://rnode.local:notaport", 115200).unwrap_err();
        assert!(err.contains("invalid TCP port"));
    }

    #[cfg(any(feature = "serial", feature = "rnode-tcp"))]
    #[test]
    fn test_port_config_tcp_missing_port_rejected() {
        let err = PortConfig::parse("tcp://rnode.local:", 115200).unwrap_err();
        assert!(err.contains("missing TCP port"));
    }

    #[cfg(any(feature = "serial", feature = "rnode-tcp"))]
    #[test]
    fn test_port_config_tcp_bracketed_ipv6_default_port() {
        let cfg = PortConfig::parse("tcp://[2001:db8::1]", 115200).unwrap();
        match cfg {
            PortConfig::Tcp { addr } => assert_eq!(addr, "[2001:db8::1]:7633"),
            #[cfg(feature = "serial")]
            _ => panic!("expected Tcp variant"),
        }
    }

    #[cfg(any(feature = "serial", feature = "rnode-tcp"))]
    #[test]
    fn test_port_config_tcp_bracketed_ipv6_explicit_port() {
        let cfg = PortConfig::parse("tcp://[2001:db8::1]:9000", 115200).unwrap();
        match cfg {
            PortConfig::Tcp { addr } => assert_eq!(addr, "[2001:db8::1]:9000"),
            #[cfg(feature = "serial")]
            _ => panic!("expected Tcp variant"),
        }
    }

    #[cfg(any(feature = "serial", feature = "rnode-tcp"))]
    #[test]
    fn test_port_config_tcp_unbracketed_ipv6_default_port() {
        let cfg = PortConfig::parse("tcp://2001:db8::1", 115200).unwrap();
        match cfg {
            PortConfig::Tcp { addr } => assert_eq!(addr, "[2001:db8::1]:7633"),
            #[cfg(feature = "serial")]
            _ => panic!("expected Tcp variant"),
        }
    }

    #[cfg(any(feature = "serial", feature = "rnode-tcp"))]
    #[test]
    fn test_port_config_tcp_malformed_bracketed_ipv6_rejected() {
        let err = PortConfig::parse("tcp://[2001:db8::1", 115200).unwrap_err();
        assert!(err.contains("missing closing"));
    }

    #[cfg(any(feature = "serial", feature = "rnode-tcp"))]
    #[test]
    fn test_tcp_eof_is_read_error() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let accept = std::thread::spawn(move || {
            let (_stream, _) = listener.accept().unwrap();
        });

        let stream = RNodeStream::connect_tcp(&addr.to_string()).unwrap();
        let _clone = stream.try_clone().unwrap();
        accept.join().unwrap();

        match read_rnode_stream(stream, [0u8; 1024]) {
            Ok(_) => panic!("closed TCP socket should be EOF"),
            Err((_stream, err)) => assert_eq!(err.kind(), std::io::ErrorKind::UnexpectedEof),
        }
    }

    #[cfg(any(feature = "serial", feature = "rnode-tcp"))]
    #[test]
    fn test_tcp_connect_accepts_timeout() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let accept = std::thread::spawn(move || {
            let (_stream, _) = listener.accept().unwrap();
        });

        let stream =
            RNodeStream::connect_tcp_with_timeout(&addr.to_string(), Duration::from_millis(500))
                .unwrap();
        assert!(stream.is_tcp());

        drop(stream);
        accept.join().unwrap();
    }

    #[cfg(any(feature = "serial", feature = "rnode-tcp"))]
    #[tokio::test]
    async fn test_rnode_tcp_reconnects_after_eof() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let config = RNodeConfig::new("rnode-tcp", &format!("tcp://{addr}"));
        let expected_init_len = build_detect_sequence().len()
            + build_init_sequence(&config).len()
            + build_airtime_sequence(&config).len();
        let (accepted_tx, mut accepted_rx) = tokio::sync::mpsc::unbounded_channel();

        let server = std::thread::spawn(move || {
            for attempt in 1..=2 {
                let (mut stream, _) = listener.accept().unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .unwrap();

                let mut buf = [0u8; 512];
                let mut total = 0usize;
                while total < expected_init_len {
                    match std::io::Read::read(&mut stream, &mut buf) {
                        Ok(0) => break,
                        Ok(n) => total += n,
                        Err(_) => break,
                    }
                }
                if attempt == 2 {
                    accepted_tx.send(attempt).unwrap();
                    std::thread::sleep(Duration::from_millis(500));
                } else {
                    let _ = stream.shutdown(std::net::Shutdown::Both);
                    accepted_tx.send(attempt).unwrap();
                }
            }
        });

        let (transport_tx, _transport_rx) = mpsc::channel::<TransportMessage>(8);
        let handle = spawn_rnode_interface(config, 77, transport_tx)
            .await
            .unwrap();

        assert_eq!(
            tokio::time::timeout(Duration::from_secs(2), accepted_rx.recv())
                .await
                .unwrap()
                .unwrap(),
            1
        );
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(7), accepted_rx.recv())
                .await
                .unwrap()
                .unwrap(),
            2
        );
        assert!(handle.online.load(Ordering::SeqCst));

        handle.read_task.abort();
        drop(handle.tx);
        server.join().unwrap();
    }
}
