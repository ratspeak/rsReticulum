//! LoRa radio control via RNode firmware's extended-KISS protocol.
//! Shared constants + transport-agnostic response handler. Serial:
//! [`spawn_rnode_interface`] (feature `serial`); BLE: [`crate::ble_rnode`].
//!
//! Transport selection is driven by the `port` string in [`RNodeConfig`]:
//!   - `/dev/ttyUSB0`, `COM3`, etc.  → serial (feature `serial` required)
//!   - `tcp://192.168.1.1`           → TCP, default port 7633
//!   - `tcp://192.168.1.1:9000`      → TCP, explicit port

use bytes::Bytes;

use crate::kiss;
use crate::traits::{InterfaceId, InterfaceMode};
use rns_transport::messages::{InboundPacket, TransportMessage};

#[cfg(feature = "serial")]
use crate::traits::{InterfaceDirection, InterfaceHandle};
#[cfg(feature = "serial")]
use std::sync::Arc;
#[cfg(feature = "serial")]
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
#[cfg(feature = "serial")]
use std::time::Duration;
#[cfg(feature = "serial")]
use tokio::sync::mpsc;

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

#[cfg(feature = "serial")]
const RNODE_READ_TIMEOUT_MS: u64 = 100;

// Transport abstraction

/// Parsed representation of the `port` config field.
#[cfg(feature = "serial")]
#[derive(Debug, Clone)]
pub enum PortConfig {
    /// A local serial device path, e.g. `/dev/ttyUSB0` or `COM3`.
    Serial { path: String, baud: u32 },
    /// A TCP endpoint, e.g. `tcp://192.168.1.1` or `tcp://192.168.1.1:9000`.
    Tcp { addr: String },
}

#[cfg(feature = "serial")]
impl PortConfig {
    pub fn parse(port: &str, baud: u32) -> Result<Self, String> {
        if let Some(rest) = port.strip_prefix("tcp://") {
            // Already has a port number?
            let addr = if rest.contains(':') {
                rest.to_string()
            } else {
                format!("{}:{}", rest, DEFAULT_TCP_PORT)
            };
            Ok(Self::Tcp { addr })
        } else {
            Ok(Self::Serial {
                path: port.to_string(),
                baud,
            })
        }
    }
}

/// A unified sync I/O stream for either a serial port or a TCP socket.
///
/// Both variants support `Read + Write + Send + 'static` so the existing
/// `spawn_blocking` read/write loops require minimal changes.
#[cfg(feature = "serial")]
pub enum RNodeStream {
    Serial(Box<dyn serialport::SerialPort>),
    Tcp(std::net::TcpStream),
}

#[cfg(feature = "serial")]
impl RNodeStream {
    /// Open a serial port.
    pub fn open_serial(path: &str, baud: u32) -> std::io::Result<Self> {
        let port = serialport::new(path, baud)
            .timeout(Duration::from_millis(RNODE_READ_TIMEOUT_MS))
            .open()
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        Ok(Self::Serial(port))
    }

    /// Connect to a TCP socket (blocking).
    pub fn connect_tcp(addr: &str) -> std::io::Result<Self> {
        let stream = std::net::TcpStream::connect(addr)?;
        // Mirror the serial timeout so the read loop doesn't block forever.
        stream.set_read_timeout(Some(Duration::from_millis(RNODE_READ_TIMEOUT_MS)))?;
        Ok(Self::Tcp(stream))
    }

    /// Shallow-clone the stream for the write half.
    ///
    /// - Serial: uses `SerialPort::try_clone`.
    /// - TCP: uses `TcpStream::try_clone` (both halves share the same fd).
    pub fn try_clone(&self) -> std::io::Result<Self> {
        match self {
            Self::Serial(p) => Ok(Self::Serial(
                p.try_clone()
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?,
            )),
            Self::Tcp(s) => Ok(Self::Tcp(s.try_clone()?)),
        }
    }

    /// Human-readable description for log messages.
    pub fn description(&self) -> String {
        match self {
            Self::Serial(p) => p
                .name()
                .unwrap_or_else(|| "<unknown serial>".to_string()),
            Self::Tcp(s) => s
                .peer_addr()
                .map(|a| a.to_string())
                .unwrap_or_else(|_| "<unknown tcp>".to_string()),
        }
    }
}

#[cfg(feature = "serial")]
impl std::io::Read for RNodeStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Self::Serial(p) => p.read(buf),
            Self::Tcp(s) => s.read(buf),
        }
    }
}

#[cfg(feature = "serial")]
impl std::io::Write for RNodeStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            Self::Serial(p) => p.write(buf),
            Self::Tcp(s) => s.write(buf),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            Self::Serial(p) => p.flush(),
            Self::Tcp(s) => s.flush(),
        }
    }
}

// Safety: TcpStream is Send; serialport's Box<dyn SerialPort> is Send on all
// platforms the crate targets.
#[cfg(feature = "serial")]
unsafe impl Send for RNodeStream {}

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
}

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
            flow_control: true,
            st_alock: None,
            lt_alock: None,
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

/// KISS init sequence. Order matters: RADIO_STATE=ON must be last.
pub fn build_init_sequence(config: &RNodeConfig) -> Vec<u8> {
    let mut out = Vec::with_capacity(48);
    kiss::frame_with_command_into(CMD_FREQUENCY, &u32_to_bytes(config.frequency), &mut out);
    kiss::frame_with_command_into(CMD_BANDWIDTH, &u32_to_bytes(config.bandwidth), &mut out);
    kiss::frame_with_command_into(CMD_SF, &[config.spreading_factor], &mut out);
    kiss::frame_with_command_into(CMD_CR, &[config.coding_rate], &mut out);
    kiss::frame_with_command_into(CMD_TXPOWER, &[config.tx_power], &mut out);
    kiss::frame_with_command_into(CMD_RADIO_STATE, &[RADIO_STATE_ON], &mut out);
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
                *last_rssi = Some(frame[0] as i8 as f32);
            }
            RNodeResponse::None
        }
        CMD_STAT_SNR => {
            if !frame.is_empty() {
                *last_snr = Some(frame[0] as i8 as f32 / 4.0);
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

#[cfg(feature = "serial")]
pub async fn spawn_rnode_interface(
    config: RNodeConfig,
    id: InterfaceId,
    transport_tx: mpsc::Sender<TransportMessage>,
) -> Result<InterfaceHandle, crate::traits::InterfaceError> {
    let port_cfg = PortConfig::parse(&config.port, config.baud_rate)
        .map_err(|e| crate::traits::InterfaceError::SendFailed(format!("rnode port parse: {}", e)))?;

    let port = match &port_cfg {
        PortConfig::Serial { path, baud } => {
            tracing::info!(
                name = %config.name,
                port = %path,
                baud = baud,
                "RNode serial interface opening"
            );
            RNodeStream::open_serial(path, *baud)
                .map_err(|e| crate::traits::InterfaceError::SendFailed(format!("rnode serial open: {}", e)))?
        }
        PortConfig::Tcp { addr } => {
            tracing::info!(
                name = %config.name,
                addr = %addr,
                "RNode TCP interface connecting"
            );
            // TcpStream::connect is blocking; run it off the async executor.
            let addr = addr.clone();
            tokio::task::spawn_blocking(move || RNodeStream::connect_tcp(&addr))
                .await
                .map_err(|e| crate::traits::InterfaceError::SendFailed(format!("rnode tcp spawn: {}", e)))?
                .map_err(|e| crate::traits::InterfaceError::SendFailed(format!("rnode tcp connect: {}", e)))?
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

    // Detect first so firmware version is known before init.
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
        let mut init_seq = build_init_sequence(&config);
        init_seq.extend_from_slice(&build_airtime_sequence(&config));
        use std::io::Write;
        init_port.write_all(&init_seq).map_err(|e| {
            crate::traits::InterfaceError::SendFailed(format!("rnode init write: {}", e))
        })?;
        init_port.flush().map_err(|e| {
            crate::traits::InterfaceError::SendFailed(format!("rnode init flush: {}", e))
        })?;
    }

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
    let (tx, mut rx) = mpsc::channel::<Bytes>(256);
    let name = config.name.clone();
    let mode = config.mode;
    let flow_control = config.flow_control;

    let port_write = port
        .try_clone()
        .map_err(|e| crate::traits::InterfaceError::SendFailed(format!("rnode clone: {}", e)))?;

    let ready = Arc::new(AtomicBool::new(true));

    let online_w = online.clone();
    let ready_w = ready.clone();
    let txb_w = shared_txb.clone();
    tokio::spawn(async move {
        let mut port_w = port_write;
        while let Some(data) = rx.recv().await {
            txb_w.fetch_add(data.len() as u64, std::sync::atomic::Ordering::Relaxed);
            if flow_control {
                while !ready_w.load(Ordering::SeqCst) {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                    if !online_w.load(Ordering::SeqCst) {
                        return;
                    }
                }
            }
            let framed = kiss::frame(&data);
            let online_ref = online_w.clone();
            let result = tokio::task::spawn_blocking(move || {
                use std::io::Write;
                port_w.write_all(&framed)?;
                port_w.flush()?;
                Ok::<_, std::io::Error>(port_w)
            })
            .await;
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
                    break;
                }
            }
        }
    });

    let online_r = online.clone();
    let ready_r = ready;
    let rxb_r = shared_rxb.clone();
    let read_task = tokio::spawn(async move {
        let mut port_r = port;
        let mut deframer = kiss::RawKissDeframer::new();
        let mut buf = [0u8; 1024];
        let mut last_rssi: Option<f32> = None;
        let mut last_snr: Option<f32> = None;

        loop {
            if !online_r.load(Ordering::SeqCst) {
                break;
            }
            let result = tokio::task::spawn_blocking(move || {
                use std::io::Read;
                match port_r.read(&mut buf) {
                    Ok(n) => Ok((port_r, buf, n)),
                    // Serial returns TimedOut; TCP returns WouldBlock on non-blocking
                    // or TimedOut on a read-timeout — treat both as "no data yet".
                    Err(e)
                        if e.kind() == std::io::ErrorKind::TimedOut
                            || e.kind() == std::io::ErrorKind::WouldBlock =>
                    {
                        Ok((port_r, buf, 0))
                    }
                    Err(e) => Err((port_r, e)),
                }
            })
            .await;

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
                                        online_r.store(false, Ordering::SeqCst);
                                        return;
                                    }
                                }
                                RNodeResponse::Ready(is_ready) => {
                                    ready_r.store(is_ready, Ordering::SeqCst);
                                }
                                RNodeResponse::None => {}
                            }
                        }
                    }
                }
                Ok(Err((_p, e))) => {
                    tracing::warn!(error = %e, "RNode read error");
                    online_r.store(false, Ordering::SeqCst);
                    return;
                }
                Err(e) => {
                    tracing::warn!(error = %e, "RNode read task panicked");
                    online_r.store(false, Ordering::SeqCst);
                    return;
                }
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
        assert!(cfg.flow_control);
        assert!(cfg.st_alock.is_none());
        assert!(cfg.lt_alock.is_none());
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

    #[cfg(feature = "serial")]
    #[test]
    fn test_port_config_tcp_default_port() {
        let cfg = PortConfig::parse("tcp://192.168.1.1", 115200).unwrap();
        match cfg {
            PortConfig::Tcp { addr } => assert_eq!(addr, "192.168.1.1:7633"),
            _ => panic!("expected Tcp variant"),
        }
    }

    #[cfg(feature = "serial")]
    #[test]
    fn test_port_config_tcp_explicit_port() {
        let cfg = PortConfig::parse("tcp://192.168.1.1:9000", 115200).unwrap();
        match cfg {
            PortConfig::Tcp { addr } => assert_eq!(addr, "192.168.1.1:9000"),
            _ => panic!("expected Tcp variant"),
        }
    }

    #[cfg(feature = "serial")]
    #[test]
    fn test_port_config_tcp_hostname() {
        let cfg = PortConfig::parse("tcp://rnode.local", 115200).unwrap();
        match cfg {
            PortConfig::Tcp { addr } => assert_eq!(addr, "rnode.local:7633"),
            _ => panic!("expected Tcp variant"),
        }
    }
}
