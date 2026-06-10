//! Serial port + KISS framing; CMD_DATA + CMD_READY flow control.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use bytes::Bytes;
use tokio::sync::mpsc;

use crate::kiss;
use crate::traits::{InterfaceDirection, InterfaceHandle, InterfaceId, InterfaceMode};
use rns_transport::messages::{InboundPacket, TransportMessage};

const KISS_READ_TIMEOUT_MS: u64 = 100;

#[derive(Debug, Clone)]
pub struct KissInterfaceConfig {
    pub name: String,
    pub port: String,
    pub baud_rate: u32,
    pub data_bits: serialport::DataBits,
    pub parity: serialport::Parity,
    pub stop_bits: serialport::StopBits,
    pub mode: InterfaceMode,
    pub slottime: Option<u8>,
    pub persistence: Option<u8>,
    pub txdelay: Option<u8>,
    pub txtail: Option<u8>,
    /// Honour CMD_READY from TNC.
    pub flow_control: bool,
    /// Station-ID beacon: seconds between IDs, counted from the first data
    /// TX after the previous beacon (Python `id_interval`/`id_callsign`).
    pub id_interval: Option<u64>,
    pub id_callsign: Option<Vec<u8>>,
}

impl KissInterfaceConfig {
    pub fn new(name: &str, port: &str, baud: u32) -> Self {
        Self {
            name: name.to_string(),
            port: port.to_string(),
            baud_rate: baud,
            data_bits: serialport::DataBits::Eight,
            parity: serialport::Parity::None,
            stop_bits: serialport::StopBits::One,
            mode: InterfaceMode::Full,
            slottime: None,
            persistence: None,
            txdelay: None,
            txtail: None,
            flow_control: false,
            id_interval: None,
            id_callsign: None,
        }
    }
}

/// Beacon frame payload: callsign zero-padded to the 15-byte minimum
/// (Python KISSInterface.py:350-353).
pub fn beacon_frame_payload(id_callsign: &[u8]) -> Vec<u8> {
    let mut frame = id_callsign.to_vec();
    while frame.len() < 15 {
        frame.push(0x00);
    }
    frame
}

pub async fn spawn_kiss_interface(
    config: KissInterfaceConfig,
    id: InterfaceId,
    transport_tx: mpsc::Sender<TransportMessage>,
) -> Result<InterfaceHandle, crate::traits::InterfaceError> {
    let port = serialport::new(&config.port, config.baud_rate)
        .data_bits(config.data_bits)
        .parity(config.parity)
        .stop_bits(config.stop_bits)
        .timeout(Duration::from_millis(KISS_READ_TIMEOUT_MS))
        .open()
        .map_err(|e| {
            crate::traits::InterfaceError::SendFailed(format!("kiss serial open: {}", e))
        })?;

    tracing::info!(
        name = %config.name,
        port = %config.port,
        baud = config.baud_rate,
        "KISS interface opened"
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
        .map_err(|e| crate::traits::InterfaceError::SendFailed(format!("kiss clone: {}", e)))?;

    // Push TNC tuning before main loops so they take effect before first frame.
    {
        let mut init_port = port_write.try_clone().map_err(|e| {
            crate::traits::InterfaceError::SendFailed(format!("kiss init clone: {}", e))
        })?;
        let mut init_frames = Vec::with_capacity(16);
        if let Some(v) = config.txdelay {
            kiss::frame_with_command_into(kiss::CMD_TXDELAY, &[v], &mut init_frames);
        }
        if let Some(v) = config.persistence {
            kiss::frame_with_command_into(kiss::CMD_P, &[v], &mut init_frames);
        }
        if let Some(v) = config.slottime {
            kiss::frame_with_command_into(kiss::CMD_SLOTTIME, &[v], &mut init_frames);
        }
        if let Some(v) = config.txtail {
            kiss::frame_with_command_into(kiss::CMD_TXTAIL, &[v], &mut init_frames);
        }
        if !init_frames.is_empty() {
            use std::io::Write;
            let _ = init_port.write_all(&init_frames);
            let _ = init_port.flush();
        }
    }

    let ready = Arc::new(AtomicBool::new(true));

    let online_w = online.clone();
    let ready_w = ready.clone();
    let txb_w = shared_txb.clone();
    let beacon = config
        .id_interval
        .zip(config.id_callsign.clone())
        .map(|(interval, callsign)| (Duration::from_secs(interval), Bytes::from(callsign)));
    tokio::spawn(async move {
        let mut port_w = port_write;
        // Python first_tx semantics: armed by the first data TX after a
        // beacon; cleared when the beacon goes out.
        let mut first_tx: Option<tokio::time::Instant> = None;
        loop {
            let data = if let Some((interval, ref callsign)) = beacon {
                match tokio::time::timeout(Duration::from_secs(1), rx.recv()).await {
                    Ok(Some(data)) => data,
                    Ok(None) => break,
                    Err(_) => {
                        let due = first_tx.is_some_and(|t| t.elapsed() >= interval);
                        if !due {
                            continue;
                        }
                        tracing::debug!("KISS transmitting station-ID beacon");
                        Bytes::from(beacon_frame_payload(callsign))
                    }
                }
            } else {
                match rx.recv().await {
                    Some(data) => data,
                    None => break,
                }
            };

            // Python KISSInterface.py:267-271 compares the unpadded callsign,
            // so a padded (<15 byte) beacon re-arms the timer and beacons
            // repeat every id_interval once anything has been sent. Kept
            // bug-for-bug for parity.
            let is_beacon = beacon
                .as_ref()
                .is_some_and(|(_, callsign)| data == *callsign);
            if is_beacon {
                first_tx = None;
            } else if first_tx.is_none() {
                first_tx = Some(tokio::time::Instant::now());
            }

            txb_w.fetch_add(data.len() as u64, std::sync::atomic::Ordering::Relaxed);
            // Flow control: bounded wait so a stuck TNC can't hang transmit.
            if flow_control {
                let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
                while !ready_w.load(Ordering::SeqCst) {
                    if tokio::time::Instant::now() >= deadline {
                        tracing::warn!("KISS flow control timeout, proceeding anyway");
                        break;
                    }
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
                    tracing::warn!(error = %e, "KISS write error");
                    online_ref.store(false, Ordering::SeqCst);
                    break;
                }
                Err(e) => {
                    tracing::warn!(error = %e, "KISS write task panicked");
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
        let mut deframer = kiss::KissDeframer::new();
        let mut buf = [0u8; 1024];

        loop {
            if !online_r.load(Ordering::SeqCst) {
                break;
            }
            let result = tokio::task::spawn_blocking(move || {
                use std::io::Read;
                match port_r.read(&mut buf) {
                    Ok(n) => Ok((port_r, buf, n)),
                    Err(e) if e.kind() == std::io::ErrorKind::TimedOut => Ok((port_r, buf, 0)),
                    Err(e) => Err((port_r, e)),
                }
            })
            .await;

            match result {
                Ok(Ok((p, b, n))) => {
                    port_r = p;
                    buf = b;
                    if n > 0 {
                        rxb_r.fetch_add(n as u64, std::sync::atomic::Ordering::Relaxed);
                        for (cmd, frame) in deframer.feed(&buf[..n]) {
                            match cmd {
                                kiss::CMD_DATA => {
                                    if frame.is_empty() {
                                        continue;
                                    }
                                    let msg = TransportMessage::Inbound(InboundPacket {
                                        raw: Bytes::from(frame),
                                        interface_id: id,
                                        rssi: None,
                                        snr: None,
                                        q: None,
                                    });
                                    if transport_tx.send(msg).await.is_err() {
                                        tracing::warn!(id, "transport channel closed");
                                        online_r.store(false, Ordering::SeqCst);
                                        return;
                                    }
                                }
                                kiss::CMD_READY => {
                                    // Nonzero = TNC ready to accept data.
                                    let is_ready = frame.first().copied().unwrap_or(0) != 0;
                                    ready_r.store(is_ready, Ordering::SeqCst);
                                    tracing::debug!(id, ready = is_ready, "KISS flow control");
                                }
                                _ => {
                                    tracing::debug!(id, cmd, "ignoring KISS command");
                                }
                            }
                        }
                    }
                }
                Ok(Err((_p, e))) => {
                    tracing::warn!(error = %e, "KISS read error");
                    online_r.store(false, Ordering::SeqCst);
                    return;
                }
                Err(e) => {
                    tracing::warn!(error = %e, "KISS read task panicked");
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
        bitrate: config.baud_rate as u64,
        mtu: 564,
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
    fn test_kiss_iface_config() {
        let cfg = KissInterfaceConfig::new("kiss0", "/dev/ttyUSB0", 9600);
        assert_eq!(cfg.baud_rate, 9600);
        assert!(!cfg.flow_control);
        assert_eq!(cfg.mode, InterfaceMode::Full);
        assert!(cfg.id_interval.is_none() && cfg.id_callsign.is_none());
    }

    /// Python KISSInterface.py:350-353 — beacon payload is the callsign
    /// zero-padded to 15 bytes; longer callsigns pass through unchanged.
    #[test]
    fn test_beacon_frame_payload_padding() {
        let short = beacon_frame_payload(b"MYCALL-0");
        assert_eq!(short.len(), 15);
        assert_eq!(&short[..8], b"MYCALL-0");
        assert!(short[8..].iter().all(|&b| b == 0));

        let long = beacon_frame_payload(b"AVERYLONGCALLSIGN");
        assert_eq!(long, b"AVERYLONGCALLSIGN");
    }

    #[test]
    fn test_kiss_config_defaults() {
        let cfg = KissInterfaceConfig::new("kiss0", "/dev/ttyUSB0", 9600);
        assert_eq!(cfg.name, "kiss0");
        assert_eq!(cfg.port, "/dev/ttyUSB0");
        assert_eq!(cfg.data_bits, serialport::DataBits::Eight);
        assert_eq!(cfg.parity, serialport::Parity::None);
        assert_eq!(cfg.stop_bits, serialport::StopBits::One);
        assert!(cfg.slottime.is_none());
        assert!(cfg.persistence.is_none());
        assert!(cfg.txdelay.is_none());
        assert!(cfg.txtail.is_none());
    }

    #[test]
    fn test_kiss_config_custom() {
        let cfg = KissInterfaceConfig::new("kiss1", "/dev/ttyACM0", 57600);
        assert_eq!(cfg.port, "/dev/ttyACM0");
        assert_eq!(cfg.baud_rate, 57600);
    }

    #[test]
    fn test_kiss_config_mode() {
        let cfg = KissInterfaceConfig::new("kiss0", "/dev/ttyS0", 9600);
        assert_eq!(cfg.mode, InterfaceMode::Full);
    }
}
