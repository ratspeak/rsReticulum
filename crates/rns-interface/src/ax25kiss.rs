//! AX.25-over-KISS — prepends a UI header (src/dst call+SSID) and strips on RX.

#[cfg(feature = "serial")]
use rns_transport::messages::{InterfacePacketCapacity, InterfaceTransportSender};
#[cfg(feature = "serial")]
use std::sync::Arc;
#[cfg(feature = "serial")]
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
#[cfg(feature = "serial")]
use std::time::Duration;

#[cfg(feature = "serial")]
use bytes::Bytes;
#[cfg(feature = "serial")]
use tokio::sync::mpsc;

use crate::kiss;
use crate::traits::InterfaceMode;

#[cfg(feature = "serial")]
use crate::traits::{InterfaceDirection, InterfaceHandle, InterfaceId};
#[cfg(feature = "serial")]
use rns_transport::messages::{InboundPacket, TransportMessage};

/// "No layer 3 protocol".
pub const AX25_PID_NOLAYER3: u8 = 0xF0;
/// Unnumbered Information control field.
pub const AX25_CTRL_UI: u8 = 0x03;
/// 2×7 (addresses) + 1 (control) + 1 (PID).
pub const AX25_HEADER_SIZE: usize = 16;

pub const HW_MTU: u16 = 564;

pub const BITRATE_GUESS: u64 = 1200;

pub const DEFAULT_DST_CALL: &[u8] = b"APZRNS";
pub const DEFAULT_DST_SSID: u8 = 0;

#[derive(Debug, Clone)]
pub struct AX25KISSConfig {
    pub name: String,
    pub port: String,
    pub baud_rate: u32,
    /// 3-6 uppercase ASCII.
    pub src_call: String,
    /// 0-15.
    pub src_ssid: u8,
    pub dst_call: String,
    pub dst_ssid: u8,
    /// ms (default 350).
    pub preamble: u16,
    /// ms (default 20).
    pub txtail: u16,
    /// CSMA persistence 0-255 (default 64).
    pub persistence: u8,
    /// CSMA slot time ms (default 20).
    pub slottime: u16,
    /// Honour CMD_READY from TNC.
    pub flow_control: bool,
    pub mode: InterfaceMode,
    /// Serial line params in Python config form (converted at open).
    pub data_bits: u8,
    pub parity: String,
    pub stop_bits: u8,
}

impl AX25KISSConfig {
    pub fn new(name: &str, port: &str, callsign: &str, ssid: u8) -> Self {
        Self {
            name: name.to_string(),
            port: port.to_string(),
            baud_rate: 9600,
            src_call: callsign.to_uppercase(),
            src_ssid: ssid,
            dst_call: String::from_utf8_lossy(DEFAULT_DST_CALL).to_string(),
            dst_ssid: DEFAULT_DST_SSID,
            preamble: 350,
            txtail: 20,
            persistence: 64,
            slottime: 20,
            flow_control: false,
            mode: InterfaceMode::Full,
            data_bits: 8,
            parity: "N".to_string(),
            stop_bits: 1,
        }
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.src_call.len() < 3 || self.src_call.len() > 6 {
            return Err(format!(
                "Invalid callsign '{}': must be 3-6 characters",
                self.src_call
            ));
        }
        if self.src_ssid > 15 {
            return Err(format!("Invalid SSID {}: must be 0-15", self.src_ssid));
        }
        Ok(())
    }
}

/// Build a 16-byte UI header:
/// `dst_call(6) | dst_ssid(1) | src_call(6) | src_ssid(1) | CTRL | PID`.
/// At most six input callsign bytes are copied and left-shifted by one; unused
/// positions are filled with literal `0x20`. SSID is `0x60 | (ssid << 1)`;
/// the source SSID also sets the end-of-address bit. This helper does not
/// validate callsigns or SSID ranges.
pub fn build_ax25_header(
    dst_call: &[u8],
    dst_ssid: u8,
    src_call: &[u8],
    src_ssid: u8,
) -> [u8; AX25_HEADER_SIZE] {
    let mut header = [0u8; AX25_HEADER_SIZE];

    for i in 0..6 {
        header[i] = if i < dst_call.len() {
            dst_call[i] << 1
        } else {
            0x20
        };
    }
    header[6] = 0x60 | (dst_ssid << 1);

    for i in 0..6 {
        header[7 + i] = if i < src_call.len() {
            src_call[i] << 1
        } else {
            0x20
        };
    }
    // End-of-address bit terminates the address field.
    header[13] = 0x60 | (src_ssid << 1) | 0x01;

    header[14] = AX25_CTRL_UI;
    header[15] = AX25_PID_NOLAYER3;

    header
}

pub fn frame_ax25_kiss(
    data: &[u8],
    dst_call: &[u8],
    dst_ssid: u8,
    src_call: &[u8],
    src_ssid: u8,
) -> Vec<u8> {
    let header = build_ax25_header(dst_call, dst_ssid, src_call, src_ssid);
    let mut payload = Vec::with_capacity(header.len() + data.len());
    payload.extend_from_slice(&header);
    payload.extend_from_slice(data);
    kiss::frame(&payload)
}

/// Return bytes after the fixed 16-byte header, or `None` for frames of
/// 16 bytes or fewer. Addresses, control, and PID are not validated.
pub fn strip_ax25_header(data: &[u8]) -> Option<&[u8]> {
    if data.len() > AX25_HEADER_SIZE {
        Some(&data[AX25_HEADER_SIZE..])
    } else {
        None
    }
}

/// preamble/txtail/slottime are ms→10ms units per KISS spec.
pub fn build_ax25_kiss_init(config: &AX25KISSConfig) -> Vec<u8> {
    let mut out = Vec::new();

    let preamble_val = (config.preamble / 10).min(255) as u8;
    out.extend_from_slice(&kiss::frame_with_command(
        kiss::CMD_TXDELAY,
        &[preamble_val],
    ));

    let txtail_val = (config.txtail / 10).min(255) as u8;
    out.extend_from_slice(&kiss::frame_with_command(kiss::CMD_TXTAIL, &[txtail_val]));

    out.extend_from_slice(&kiss::frame_with_command(
        kiss::CMD_P,
        &[config.persistence],
    ));

    let slottime_val = (config.slottime / 10).min(255) as u8;
    out.extend_from_slice(&kiss::frame_with_command(
        kiss::CMD_SLOTTIME,
        &[slottime_val],
    ));

    out.extend_from_slice(&kiss::frame_with_command(kiss::CMD_READY, &[0x01]));

    out
}

#[cfg(feature = "serial")]
const AX25_READ_TIMEOUT_MS: u64 = 100;

/// Parse `"CALL-SSID"` or `"CALL"`; uppercased call, SSID defaults to 0.
pub fn parse_callsign_ssid(input: &str) -> Result<(String, u8), String> {
    let (call_part, ssid) = if let Some(idx) = input.rfind('-') {
        let call = &input[..idx];
        let ssid_str = &input[idx + 1..];
        let ssid: u8 = ssid_str
            .parse()
            .map_err(|_| format!("Invalid SSID '{}': must be a number 0-15", ssid_str))?;
        (call, ssid)
    } else {
        (input, 0u8)
    };

    let call = call_part.to_uppercase();

    if call.len() < 3 || call.len() > 6 {
        return Err(format!(
            "Invalid callsign '{}': must be 3-6 characters",
            call
        ));
    }

    if !call.bytes().all(|b| b.is_ascii_alphanumeric()) {
        return Err(format!(
            "Invalid callsign '{}': must be ASCII alphanumeric",
            call
        ));
    }

    if ssid > 15 {
        return Err(format!("Invalid SSID {}: must be 0-15", ssid));
    }

    Ok((call, ssid))
}

/// Python `AX25KISSInterface.configure_device` sleeps this long after opening
/// the port, before reading and before sending the TNC configuration.
#[cfg(feature = "serial")]
const CONFIGURE_SETTLE: Duration = Duration::from_secs(2);

/// Spawn an AX.25 KISS interface. An unopenable port does not fail the spawn:
/// as in Python, the interface stays offline and the port is retried every
/// `RECONNECT_WAIT` seconds, also after a runtime port error.
#[cfg(feature = "serial")]
pub async fn spawn_ax25kiss_interface(
    config: AX25KISSConfig,
    id: InterfaceId,
    transport_tx: mpsc::Sender<TransportMessage>,
) -> Result<InterfaceHandle, crate::traits::InterfaceError> {
    Ok(spawn_ax25kiss_interface_observed(config, id, transport_tx)
        .await?
        .interface)
}

#[cfg(feature = "serial")]
pub async fn spawn_ax25kiss_interface_observed(
    config: AX25KISSConfig,
    id: InterfaceId,
    transport_tx: mpsc::Sender<TransportMessage>,
) -> Result<crate::serial::SpawnedSerialInterface, crate::traits::InterfaceError> {
    let transport_tx = InterfaceTransportSender::new(id, transport_tx);
    let owner = transport_tx.owner();
    config.validate().map_err(|e| {
        crate::traits::InterfaceError::SendFailed(format!("ax25kiss config: {}", e))
    })?;

    let (data_bits, parity, stop_bits) =
        crate::serial::serial_params_from(config.data_bits, &config.parity, config.stop_bits);
    let online = Arc::new(AtomicBool::new(false));
    let shared_rxb = Arc::new(AtomicU64::new(0));
    let shared_txb = Arc::new(AtomicU64::new(0));
    let (tx, rx) = mpsc::channel::<Bytes>(256);
    let background = crate::background_announce::register(&tx)?;
    let name = config.name.clone();
    let python_identity =
        rns_transport::messages::InterfaceIdentity::bracketed("AX25KISSInterface", &name);
    let mode = config.mode;
    let (failures_tx, failures) = crate::serial_io::SerialFailures::channel();

    let supervisor = crate::serial_io::Supervisor {
        identity: format!("AX25KISSInterface[{name}]"),
        opener: crate::serial::port_opener(
            &config.port,
            config.baud_rate,
            data_bits,
            parity,
            stop_bits,
            Duration::from_millis(AX25_READ_TIMEOUT_MS),
        ),
        settle: CONFIGURE_SETTLE,
        online: online.clone(),
        failures: failures_tx,
    };
    let generation = Ax25Generation {
        id,
        init_frames: build_ax25_kiss_init(&config),
        flow_control: config.flow_control,
        src_call: config.src_call.as_bytes().to_vec(),
        dst_call: config.dst_call.as_bytes().to_vec(),
        src_ssid: config.src_ssid,
        dst_ssid: config.dst_ssid,
        rx,
        background,
        transport_tx,
        online: online.clone(),
        rxb: shared_rxb.clone(),
        txb: shared_txb.clone(),
    };
    let read_task = tokio::spawn(supervisor.run(generation, None));

    Ok(crate::serial::SpawnedSerialInterface {
        interface: InterfaceHandle {
            id,
            owner,
            packet_capacity: InterfacePacketCapacity::new(500, 564, false),
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
            mtu: HW_MTU as u32,
            online,
            rxb: Some(shared_rxb),
            txb: Some(shared_txb),
            inspection: Some(
                rns_transport::messages::InterfaceInspectionSource::identified(python_identity),
            ),
            tx,
            read_task,
        },
        failures,
    })
}

#[cfg(feature = "serial")]
struct Ax25Generation {
    id: InterfaceId,
    init_frames: Vec<u8>,
    flow_control: bool,
    src_call: Vec<u8>,
    dst_call: Vec<u8>,
    src_ssid: u8,
    dst_ssid: u8,
    rx: mpsc::Receiver<Bytes>,
    background: crate::background_announce::BackgroundAnnounceReceiver,
    transport_tx: InterfaceTransportSender,
    online: Arc<AtomicBool>,
    rxb: Arc<AtomicU64>,
    txb: Arc<AtomicU64>,
}

#[cfg(feature = "serial")]
impl crate::serial_io::SerialGeneration for Ax25Generation {
    fn outbound(&mut self) -> &mut mpsc::Receiver<Bytes> {
        &mut self.rx
    }

    fn background(&self) -> &crate::background_announce::BackgroundAnnounceReceiver {
        &self.background
    }

    fn run(
        &mut self,
        port: crate::serial_io::Port,
    ) -> impl std::future::Future<Output = crate::serial_io::GenerationEnd> + Send {
        use crate::serial_io::GenerationEnd;
        let Self {
            id,
            init_frames,
            flow_control,
            src_call,
            dst_call,
            src_ssid,
            dst_ssid,
            rx,
            background,
            transport_tx,
            online,
            rxb,
            txb,
        } = self;
        let (id, flow_control, src_ssid, dst_ssid) = (*id, *flow_control, *src_ssid, *dst_ssid);
        async move {
            let port_write = match port.try_clone() {
                Ok(port) => port,
                Err(e) => return GenerationEnd::ReadFailed(e.into()),
            };
            let ready = AtomicBool::new(true);
            let writer = async {
                // Python starts the read loop and goes online before the TNC config.
                let mut port_w =
                    match crate::serial_io::blocking_write_all(port_write, init_frames.clone())
                        .await
                    {
                        Ok(p) => p,
                        Err(e) => return GenerationEnd::WriteFailed(e),
                    };
                let mut flow_control_locked = tokio::time::Instant::now();
                let take_permit = |locked: tokio::time::Instant| {
                    if ready
                        .compare_exchange(true, false, Ordering::SeqCst, Ordering::SeqCst)
                        .is_ok()
                    {
                        return true;
                    }
                    if locked.elapsed() > crate::kiss_iface::FLOW_CONTROL_TIMEOUT {
                        tracing::warn!(
                            "AX.25 KISS interface is unlocking flow control due to time-out. This should not happen. Your hardware might have missed a flow-control READY command, or maybe it does not support flow-control."
                        );
                        return true;
                    }
                    false
                };
                loop {
                    if !online.load(Ordering::SeqCst) {
                        return GenerationEnd::Closed;
                    }
                    let background_packet = if rx.is_empty() {
                        background.try_start_when(rns_transport::now_f64(), || {
                            !flow_control || take_permit(flow_control_locked)
                        })
                    } else {
                        None
                    };
                    let data = if let Some(packet) = &background_packet {
                        packet.raw().clone()
                    } else {
                        match tokio::time::timeout(Duration::from_millis(100), rx.recv()).await {
                            Ok(Some(data)) => data,
                            Ok(None) => return GenerationEnd::Closed,
                            Err(_) => continue,
                        }
                    };
                    if flow_control && background_packet.is_none() {
                        while !take_permit(flow_control_locked) {
                            tokio::time::sleep(Duration::from_millis(10)).await;
                            if !online.load(Ordering::SeqCst) {
                                return GenerationEnd::Closed;
                            }
                        }
                    }
                    if flow_control {
                        flow_control_locked = tokio::time::Instant::now();
                    }
                    let framed = frame_ax25_kiss(&data, dst_call, dst_ssid, src_call, src_ssid);
                    match crate::serial_io::blocking_write_all(port_w, framed).await {
                        Ok(p) => {
                            port_w = p;
                            // Python counts the payload without AX.25 header or framing.
                            txb.fetch_add(data.len() as u64, Ordering::Relaxed);
                        }
                        Err(e) => return GenerationEnd::WriteFailed(e),
                    }
                }
            };
            let reader = async {
                let mut port_r = port;
                let mut deframer = kiss::KissByteDeframer::new(HW_MTU as usize + AX25_HEADER_SIZE);
                let mut buf = [0u8; 1024];
                let mut last_read = std::time::Instant::now();
                loop {
                    if !online.load(Ordering::SeqCst) {
                        return GenerationEnd::Closed;
                    }
                    let (p, b, n) = match crate::serial_io::poll_read(port_r, buf).await {
                        Ok(read) => read,
                        Err(e) => return GenerationEnd::ReadFailed(e),
                    };
                    port_r = p;
                    buf = b;
                    if n == 0 {
                        if deframer.buffered() > 0
                            && last_read.elapsed() > Duration::from_millis(AX25_READ_TIMEOUT_MS)
                        {
                            deframer.reset();
                        }
                        continue;
                    }
                    last_read = std::time::Instant::now();
                    for event in deframer.feed(&buf[..n]) {
                        match event {
                            kiss::KissEvent::Data(frame) => {
                                let payload = match strip_ax25_header(&frame) {
                                    Some(p) if !p.is_empty() => p.to_vec(),
                                    _ => continue,
                                };
                                // Python counts the frame with its AX.25 header.
                                rxb.fetch_add(frame.len() as u64, Ordering::Relaxed);
                                let msg = TransportMessage::Inbound(InboundPacket {
                                    raw: Bytes::from(payload),
                                    interface_id: id,
                                    rssi: None,
                                    snr: None,
                                    q: None,
                                });
                                if transport_tx.send(msg).await.is_err() {
                                    tracing::warn!(id, "transport channel closed");
                                    return GenerationEnd::Closed;
                                }
                            }
                            kiss::KissEvent::Ready => {
                                ready.store(true, Ordering::SeqCst);
                                tracing::debug!(id, "AX.25 KISS flow control: ready");
                            }
                        }
                    }
                }
            };
            tokio::select! {
                end = writer => end,
                end = reader => end,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ax25_config() {
        let cfg = AX25KISSConfig::new("ax25-0", "/dev/ttyUSB0", "N0CALL", 7);
        assert_eq!(cfg.src_call, "N0CALL");
        assert_eq!(cfg.src_ssid, 7);
        assert_eq!(cfg.dst_call, "APZRNS");
        assert_eq!(cfg.preamble, 350);
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn test_ax25_config_validation() {
        let cfg = AX25KISSConfig::new("ax25", "/dev/ttyUSB0", "AB", 0);
        assert!(cfg.validate().is_err());

        let cfg = AX25KISSConfig::new("ax25", "/dev/ttyUSB0", "ABCDEFG", 0);
        assert!(cfg.validate().is_err());

        let mut cfg = AX25KISSConfig::new("ax25", "/dev/ttyUSB0", "N0CALL", 0);
        cfg.src_ssid = 16;
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn test_build_ax25_header() {
        let header = build_ax25_header(b"APZRNS", 0, b"N0CALL", 7);
        assert_eq!(header.len(), AX25_HEADER_SIZE);

        assert_eq!(header[0], b'A' << 1);
        assert_eq!(header[6], 0x60);
        assert_eq!(header[7], b'N' << 1);
        assert_eq!(header[13], 0x60 | (7 << 1) | 0x01);
        assert_eq!(header[14], AX25_CTRL_UI);
        assert_eq!(header[15], AX25_PID_NOLAYER3);
    }

    #[test]
    fn test_frame_ax25_kiss_roundtrip() {
        let data = b"hello ax25";
        let framed = frame_ax25_kiss(data, b"APZRNS", 0, b"N0CALL", 7);

        let mut deframer = kiss::KissDeframer::new();
        let frames = deframer.feed(&framed);
        assert_eq!(frames.len(), 1);
        let (cmd, payload) = &frames[0];
        assert_eq!(*cmd, kiss::CMD_DATA);

        let stripped = strip_ax25_header(payload).unwrap();
        assert_eq!(stripped, data);
    }

    #[test]
    fn test_strip_ax25_header_too_short() {
        let short_data = [0u8; AX25_HEADER_SIZE];
        assert!(strip_ax25_header(&short_data).is_none());
        assert!(strip_ax25_header(&[]).is_none());
    }

    #[test]
    fn test_ax25_kiss_init_parseable() {
        let cfg = AX25KISSConfig::new("ax25", "/dev/ttyUSB0", "N0CALL", 7);
        let init_seq = build_ax25_kiss_init(&cfg);
        let mut deframer = kiss::KissDeframer::new();
        let frames = deframer.feed(&init_seq);
        assert_eq!(frames.len(), 5);
    }

    #[test]
    fn test_parse_callsign_ssid_with_ssid() {
        let (call, ssid) = parse_callsign_ssid("N0CALL-7").unwrap();
        assert_eq!(call, "N0CALL");
        assert_eq!(ssid, 7);
    }

    #[test]
    fn test_parse_callsign_ssid_without_ssid() {
        let (call, ssid) = parse_callsign_ssid("N0CALL").unwrap();
        assert_eq!(call, "N0CALL");
        assert_eq!(ssid, 0);
    }

    #[test]
    fn test_parse_callsign_ssid_zero() {
        let (call, ssid) = parse_callsign_ssid("ABC-0").unwrap();
        assert_eq!(call, "ABC");
        assert_eq!(ssid, 0);
    }

    #[test]
    fn test_parse_callsign_ssid_max() {
        let (call, ssid) = parse_callsign_ssid("W1AW-15").unwrap();
        assert_eq!(call, "W1AW");
        assert_eq!(ssid, 15);
    }

    #[test]
    fn test_parse_callsign_ssid_lowercase() {
        let (call, ssid) = parse_callsign_ssid("n0call-3").unwrap();
        assert_eq!(call, "N0CALL");
        assert_eq!(ssid, 3);
    }

    #[test]
    fn test_parse_callsign_ssid_too_short() {
        assert!(parse_callsign_ssid("AB-1").is_err());
        assert!(parse_callsign_ssid("AB").is_err());
    }

    #[test]
    fn test_parse_callsign_ssid_too_long() {
        assert!(parse_callsign_ssid("ABCDEFG-1").is_err());
    }

    #[test]
    fn test_parse_callsign_ssid_invalid_ssid() {
        assert!(parse_callsign_ssid("N0CALL-16").is_err());
        assert!(parse_callsign_ssid("N0CALL-99").is_err());
        assert!(parse_callsign_ssid("N0CALL-abc").is_err());
    }

    #[test]
    fn test_parse_callsign_ssid_non_ascii() {
        assert!(parse_callsign_ssid("N0C@LL-1").is_err());
    }

    #[test]
    fn test_callsign_shift_and_padding() {
        let header = build_ax25_header(b"CQ", 0, b"ABC", 0);

        assert_eq!(header[0], b'C' << 1);
        assert_eq!(header[1], b'Q' << 1);
        assert_eq!(header[2], 0x20);
        assert_eq!(header[3], 0x20);
        assert_eq!(header[4], 0x20);
        assert_eq!(header[5], 0x20);

        assert_eq!(header[7], b'A' << 1);
        assert_eq!(header[8], b'B' << 1);
        assert_eq!(header[9], b'C' << 1);
        assert_eq!(header[10], 0x20);
        assert_eq!(header[11], 0x20);
        assert_eq!(header[12], 0x20);
    }

    #[test]
    fn test_header_ssid_encoding() {
        let header = build_ax25_header(b"DST", 0, b"SRC", 0);
        assert_eq!(header[6], 0x60);
        assert_eq!(header[13], 0x60 | 0x01);

        let header = build_ax25_header(b"DST", 15, b"SRC", 15);
        assert_eq!(header[6], 0x7E);
        assert_eq!(header[13], 0x7E | 0x01);
    }

    #[test]
    fn test_header_full_callsign() {
        let header = build_ax25_header(b"ABCDEF", 0, b"GHIJKL", 0);
        assert_eq!(header[0], b'A' << 1);
        assert_eq!(header[1], b'B' << 1);
        assert_eq!(header[2], b'C' << 1);
        assert_eq!(header[3], b'D' << 1);
        assert_eq!(header[4], b'E' << 1);
        assert_eq!(header[5], b'F' << 1);
        assert_eq!(header[7], b'G' << 1);
        assert_eq!(header[8], b'H' << 1);
        assert_eq!(header[9], b'I' << 1);
        assert_eq!(header[10], b'J' << 1);
        assert_eq!(header[11], b'K' << 1);
        assert_eq!(header[12], b'L' << 1);
    }

    #[test]
    fn test_ax25_kiss_init_values() {
        let cfg = AX25KISSConfig::new("ax25", "/dev/ttyUSB0", "N0CALL", 0);
        let init_seq = build_ax25_kiss_init(&cfg);
        let mut deframer = kiss::KissDeframer::new();
        let frames = deframer.feed(&init_seq);

        assert_eq!(frames[0].0, kiss::CMD_TXDELAY);
        assert_eq!(frames[0].1, &[35]);

        assert_eq!(frames[1].0, kiss::CMD_TXTAIL);
        assert_eq!(frames[1].1, &[2]);

        assert_eq!(frames[2].0, kiss::CMD_P);
        assert_eq!(frames[2].1, &[64]);

        assert_eq!(frames[3].0, kiss::CMD_SLOTTIME);
        assert_eq!(frames[3].1, &[2]);

        assert_eq!(frames[4].0, kiss::CMD_READY);
        assert_eq!(frames[4].1, &[0x01]);
    }

    #[test]
    fn test_strip_ax25_header_exact_payload() {
        let mut data = [0u8; AX25_HEADER_SIZE + 1];
        data[AX25_HEADER_SIZE] = 0x42;
        let payload = strip_ax25_header(&data).unwrap();
        assert_eq!(payload, &[0x42]);
    }

    #[test]
    fn test_frame_ax25_kiss_wire_vector() {
        // Byte-exact wire vector for APZRNS-0 <- N0CALL-7.
        let data = b"\x01\x02\x03";
        let framed = frame_ax25_kiss(data, b"APZRNS", 0, b"N0CALL", 7);

        let mut deframer = kiss::KissDeframer::new();
        let frames = deframer.feed(&framed);
        assert_eq!(frames.len(), 1);
        let inner = &frames[0].1;

        assert_eq!(inner[0], 0x82);
        assert_eq!(inner[1], 0xA0);
        assert_eq!(inner[2], 0xB4);
        assert_eq!(inner[3], 0xA4);
        assert_eq!(inner[4], 0x9C);
        assert_eq!(inner[5], 0xA6);
        assert_eq!(inner[6], 0x60);

        assert_eq!(inner[7], 0x9C);
        assert_eq!(inner[8], 0x60);
        assert_eq!(inner[9], 0x86);
        assert_eq!(inner[10], 0x82);
        assert_eq!(inner[11], 0x98);
        assert_eq!(inner[12], 0x98);
        assert_eq!(inner[13], 0x6F);

        assert_eq!(inner[14], AX25_CTRL_UI);
        assert_eq!(inner[15], AX25_PID_NOLAYER3);

        assert_eq!(&inner[16..], data);
    }

    #[test]
    fn test_config_from_parsed_callsign() {
        let (call, ssid) = parse_callsign_ssid("W1AW-12").unwrap();
        let cfg = AX25KISSConfig::new("ax25-0", "/dev/ttyUSB0", &call, ssid);
        assert_eq!(cfg.src_call, "W1AW");
        assert_eq!(cfg.src_ssid, 12);
        assert!(cfg.validate().is_ok());
    }
}
