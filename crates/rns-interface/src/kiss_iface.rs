//! KISS framing over a serial port or TCP socket; CMD_DATA + CMD_READY flow
//! control. Transport selection mirrors [`crate::rnode`]:
//!   - `/dev/ttyUSB0`, `COM3`, etc.  -> serial
//!   - `tcp://192.168.1.1`           -> TCP, default port 7633
//!   - `tcp://192.168.1.1:9000`      -> TCP, explicit port
//!
//! A TCP KISS interface reconnects automatically after the link drops.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use bytes::Bytes;
use tokio::sync::mpsc;

use crate::kiss;
use crate::serial_tcp_stream::{PortConfig, SerialTcpStream, read_stream, reconnect_delay};
use crate::traits::{InterfaceDirection, InterfaceHandle, InterfaceId, InterfaceMode};
use rns_transport::messages::{InboundPacket, TransportMessage};

#[derive(Debug, Clone)]
pub struct KissInterfaceConfig {
    pub name: String,
    /// Serial device path (`/dev/ttyUSB0`) **or** TCP URL (`tcp://host[:port]`).
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

/// Open the transport and push TNC tuning (TXDELAY/P/SLOTTIME/TXTAIL) before
/// the main loops start, so it takes effect before the first data frame.
/// Called again on every reconnect, since a fresh TNC session has forgotten
/// any previously pushed tuning.
async fn open_configured_kiss_stream(
    config: &KissInterfaceConfig,
    port_cfg: &PortConfig,
) -> Result<SerialTcpStream, crate::traits::InterfaceError> {
    let port = match port_cfg {
        #[cfg(feature = "serial")]
        PortConfig::Serial { path, baud } => {
            tracing::info!(
                name = %config.name,
                port = %path,
                baud = baud,
                "KISS serial interface opening"
            );
            SerialTcpStream::open_serial(path, *baud).map_err(|e| {
                crate::traits::InterfaceError::SendFailed(format!("kiss serial open: {}", e))
            })?
        }
        PortConfig::Tcp { addr } => {
            tracing::info!(
                name = %config.name,
                addr = %addr,
                "KISS TCP interface connecting"
            );
            let addr = addr.clone();
            tokio::task::spawn_blocking(move || SerialTcpStream::connect_tcp(&addr))
                .await
                .map_err(|e| {
                    crate::traits::InterfaceError::SendFailed(format!("kiss tcp spawn: {}", e))
                })?
                .map_err(|e| {
                    crate::traits::InterfaceError::SendFailed(format!("kiss tcp connect: {}", e))
                })?
        }
    };

    tracing::info!(
        name = %config.name,
        endpoint = %port.description(),
        "KISS interface opened"
    );

    {
        let mut init_port = port.try_clone().map_err(|e| {
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
            init_port.write_all(&init_frames).map_err(|e| {
                crate::traits::InterfaceError::SendFailed(format!("kiss init write: {}", e))
            })?;
            init_port.flush().map_err(|e| {
                crate::traits::InterfaceError::SendFailed(format!("kiss init flush: {}", e))
            })?;
        }
    }

    Ok(port)
}

pub async fn spawn_kiss_interface(
    config: KissInterfaceConfig,
    id: InterfaceId,
    transport_tx: mpsc::Sender<TransportMessage>,
) -> Result<InterfaceHandle, crate::traits::InterfaceError> {
    let port_cfg = PortConfig::parse(&config.port, config.baud_rate)
        .map_err(|e| crate::traits::InterfaceError::SendFailed(format!("kiss port parse: {}", e)))?;

    let port = open_configured_kiss_stream(&config, &port_cfg).await?;

    let online = Arc::new(AtomicBool::new(true));
    let shared_rxb = Arc::new(AtomicU64::new(0));
    let shared_txb = Arc::new(AtomicU64::new(0));
    // Outer channel: survives reconnects. Each connection attempt gets its
    // own inner `conn_tx`/write-task; a forwarding task bridges the two so
    // callers holding `tx` never notice a reconnect happened underneath.
    let (tx, rx) = mpsc::channel::<Bytes>(256);
    let rx = Arc::new(tokio::sync::Mutex::new(rx));
    let name = config.name.clone();
    let mode = config.mode;
    let flow_control = config.flow_control;
    let beacon: Option<(Duration, Bytes)> = config
        .id_interval
        .zip(config.id_callsign.clone())
        .map(|(interval, callsign)| (Duration::from_secs(interval), Bytes::from(callsign)));

    let online_r = online.clone();
    let rxb_r = shared_rxb.clone();
    let txb_r = shared_txb.clone();
    let task_config = config.clone();
    let task_port_cfg = port_cfg.clone();
    let task_name = config.name.clone();
    let read_task = tokio::spawn(async move {
        let mut next_port = Some(port);

        loop {
            let mut port_r = match next_port.take() {
                Some(port) => port,
                None => match open_configured_kiss_stream(&task_config, &task_port_cfg).await {
                    Ok(port) => port,
                    Err(e) => {
                        online_r.store(false, Ordering::SeqCst);
                        tracing::warn!(
                            name = %task_name,
                            error = %e,
                            "KISS reconnect failed"
                        );
                        tokio::time::sleep(reconnect_delay()).await;
                        continue;
                    }
                },
            };

            online_r.store(true, Ordering::SeqCst);
            let port_write = match port_r.try_clone() {
                Ok(port) => port,
                Err(e) => {
                    tracing::warn!(error = %e, "KISS clone failed before reconnect");
                    online_r.store(false, Ordering::SeqCst);
                    tokio::time::sleep(reconnect_delay()).await;
                    continue;
                }
            };

            let ready = Arc::new(AtomicBool::new(true));
            let (conn_tx, mut conn_rx) = mpsc::channel::<Bytes>(256);

            let online_w = online_r.clone();
            let ready_w = ready.clone();
            let txb_w = txb_r.clone();
            let beacon_w = beacon.clone();
            let write_handle = tokio::spawn(async move {
                let mut port_w = port_write;
                // Python first_tx semantics: armed by the first data TX after a
                // beacon; cleared when the beacon goes out.
                let mut first_tx: Option<tokio::time::Instant> = None;
                loop {
                    let data = if let Some((interval, ref callsign)) = beacon_w {
                        match tokio::time::timeout(Duration::from_secs(1), conn_rx.recv()).await {
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
                        match conn_rx.recv().await {
                            Some(data) => data,
                            None => break,
                        }
                    };

                    // Python KISSInterface.py:267-271 compares the unpadded
                    // callsign, so a padded (<15 byte) beacon re-arms the
                    // timer and beacons repeat every id_interval once
                    // anything has been sent. Kept bug-for-bug for parity.
                    let is_beacon = beacon_w
                        .as_ref()
                        .is_some_and(|(_, callsign)| data == *callsign);
                    if is_beacon {
                        first_tx = None;
                    } else if first_tx.is_none() {
                        first_tx = Some(tokio::time::Instant::now());
                    }

                    txb_w.fetch_add(data.len() as u64, Ordering::Relaxed);
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
                    match crate::serial_io::blocking_write_all(port_w, framed).await {
                        Ok(p) => {
                            port_w = p;
                        }
                        Err(e) => {
                            tracing::warn!(error = %e, "KISS write error");
                            online_w.store(false, Ordering::SeqCst);
                            break;
                        }
                    }
                }
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

            let mut deframer = kiss::KissDeframer::new();
            let mut buf = [0u8; 1024];
            let mut transport_closed = false;

            loop {
                if !online_r.load(Ordering::SeqCst) {
                    break;
                }
                let result = tokio::task::spawn_blocking(move || read_stream(port_r, buf)).await;

                match result {
                    Ok(Ok((p, b, n))) => {
                        port_r = p;
                        buf = b;
                        if n > 0 {
                            rxb_r.fetch_add(n as u64, Ordering::Relaxed);
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
                                            transport_closed = true;
                                            break;
                                        }
                                    }
                                    kiss::CMD_READY => {
                                        // Nonzero = TNC ready to accept data.
                                        let is_ready = frame.first().copied().unwrap_or(0) != 0;
                                        ready.store(is_ready, Ordering::SeqCst);
                                        tracing::debug!(id, ready = is_ready, "KISS flow control");
                                    }
                                    _ => {
                                        tracing::debug!(id, cmd, "ignoring KISS command");
                                    }
                                }
                            }
                            if transport_closed {
                                break;
                            }
                        }
                    }
                    Ok(Err((_p, e))) => {
                        tracing::warn!(error = %e, "KISS read error");
                        break;
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "KISS read task panicked");
                        break;
                    }
                }
            }

            online_r.store(false, Ordering::SeqCst);
            fwd_handle.abort();
            let _ = fwd_handle.await;
            write_handle.abort();
            let _ = write_handle.await;

            if transport_closed {
                return;
            }

            tracing::info!(name = %task_name, "KISS reconnecting");
            tokio::time::sleep(reconnect_delay()).await;
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

    #[test]
    fn test_kiss_port_config_tcp() {
        let cfg = PortConfig::parse("tcp://192.168.1.50", 9600).unwrap();
        match cfg {
            PortConfig::Tcp { addr } => assert_eq!(addr, "192.168.1.50:7633"),
            #[cfg(feature = "serial")]
            _ => panic!("expected Tcp variant"),
        }
    }

    #[test]
    fn test_kiss_port_config_serial() {
        let cfg = PortConfig::parse("/dev/ttyUSB0", 9600).unwrap();
        assert!(matches!(cfg, PortConfig::Serial { path, baud } if path == "/dev/ttyUSB0" && baud == 9600));
    }

    /// A TCP KISS interface reconnects instead of dying when the peer
    /// closes the connection.
    #[tokio::test]
    async fn test_kiss_tcp_reconnects_after_eof() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let config = KissInterfaceConfig::new("kiss-tcp", &format!("tcp://{addr}"), 9600);
        let (accepted_tx, mut accepted_rx) = tokio::sync::mpsc::unbounded_channel();

        let server = std::thread::spawn(move || {
            for attempt in 1..=2 {
                let (stream, _) = listener.accept().unwrap();
                if attempt == 1 {
                    let _ = stream.shutdown(std::net::Shutdown::Both);
                }
                accepted_tx.send(attempt).unwrap();
                if attempt == 2 {
                    std::thread::sleep(Duration::from_millis(500));
                }
            }
        });

        let (transport_tx, _transport_rx) = mpsc::channel::<TransportMessage>(8);
        let handle = spawn_kiss_interface(config, 99, transport_tx).await.unwrap();

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
