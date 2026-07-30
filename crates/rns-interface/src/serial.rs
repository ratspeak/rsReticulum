//! HDLC-framed data over a serial port. Uses `serialport` with
//! `spawn_blocking` because no mature async driver exists yet.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use bytes::Bytes;
use tokio::sync::mpsc;

use crate::hdlc;
use crate::traits::{InterfaceDirection, InterfaceHandle, InterfaceId, InterfaceMode};
use rns_transport::messages::{InboundPacket, TransportMessage};

pub const DEFAULT_BAUD: u32 = 9600;

const SERIAL_READ_TIMEOUT_MS: u64 = 100;

#[derive(Debug, Clone)]
pub struct SerialConfig {
    pub name: String,
    pub port: String,
    pub baud_rate: u32,
    pub data_bits: serialport::DataBits,
    pub parity: serialport::Parity,
    pub stop_bits: serialport::StopBits,
    pub mode: InterfaceMode,
}

impl SerialConfig {
    pub fn new(name: &str, port: &str) -> Self {
        Self {
            name: name.to_string(),
            port: port.to_string(),
            baud_rate: DEFAULT_BAUD,
            data_bits: serialport::DataBits::Eight,
            parity: serialport::Parity::None,
            stop_bits: serialport::StopBits::One,
            mode: InterfaceMode::Full,
        }
    }

    pub fn baud(mut self, baud: u32) -> Self {
        self.baud_rate = baud;
        self
    }
}

/// Map Python-style serial config values (`databits`/`parity`/`stopbits`)
/// to serialport enums. Parity accepts `e`/`even` and `o`/`odd`
/// (case-insensitive); anything else is none, matching the reference.
pub fn serial_params_from(
    data_bits: u8,
    parity: &str,
    stop_bits: u8,
) -> (
    serialport::DataBits,
    serialport::Parity,
    serialport::StopBits,
) {
    let data = match data_bits {
        5 => serialport::DataBits::Five,
        6 => serialport::DataBits::Six,
        7 => serialport::DataBits::Seven,
        _ => serialport::DataBits::Eight,
    };
    let parity = match parity.to_ascii_lowercase().as_str() {
        "e" | "even" => serialport::Parity::Even,
        "o" | "odd" => serialport::Parity::Odd,
        _ => serialport::Parity::None,
    };
    let stop = match stop_bits {
        2 => serialport::StopBits::Two,
        _ => serialport::StopBits::One,
    };
    (data, parity, stop)
}

pub async fn spawn_serial_interface(
    config: SerialConfig,
    id: InterfaceId,
    transport_tx: mpsc::Sender<TransportMessage>,
) -> Result<InterfaceHandle, crate::traits::InterfaceError> {
    let port = serialport::new(&config.port, config.baud_rate)
        .data_bits(config.data_bits)
        .parity(config.parity)
        .stop_bits(config.stop_bits)
        .timeout(Duration::from_millis(SERIAL_READ_TIMEOUT_MS))
        .open()
        .map_err(|e| crate::traits::InterfaceError::SendFailed(format!("serial open: {}", e)))?;

    tracing::info!(
        name = %config.name,
        port = %config.port,
        baud = config.baud_rate,
        "serial interface opened"
    );

    let online = Arc::new(AtomicBool::new(true));
    let shared_rxb = Arc::new(AtomicU64::new(0));
    let shared_txb = Arc::new(AtomicU64::new(0));
    let (tx, mut rx) = mpsc::channel::<Bytes>(256);
    let name = config.name.clone();
    let mode = config.mode;

    let port_write = port
        .try_clone()
        .map_err(|e| crate::traits::InterfaceError::SendFailed(format!("serial clone: {}", e)))?;

    let online_w = online.clone();
    let txb_w = shared_txb.clone();
    tokio::spawn(async move {
        let mut port_w = port_write;
        while let Some(data) = rx.recv().await {
            txb_w.fetch_add(data.len() as u64, std::sync::atomic::Ordering::Relaxed);
            let framed = hdlc::frame(&data);
            match crate::serial_io::blocking_write_all(port_w, framed).await {
                Ok(p) => {
                    port_w = p;
                }
                Err(e) => {
                    tracing::warn!(error = %e, "serial write error");
                    online_w.store(false, Ordering::SeqCst);
                    break;
                }
            }
        }
    });

    let online_r = online.clone();
    let rxb_r = shared_rxb.clone();
    let read_task = tokio::spawn(async move {
        let mut port_r = port;
        let mut deframer = hdlc::HdlcDeframer::new();
        let mut buf = [0u8; 1024];

        loop {
            if !online_r.load(Ordering::SeqCst) {
                break;
            }
            match crate::serial_io::poll_read(port_r, buf).await {
                Ok((p, b, n)) => {
                    port_r = p;
                    buf = b;
                    if n > 0 {
                        rxb_r.fetch_add(n as u64, std::sync::atomic::Ordering::Relaxed);
                        for frame in deframer.feed(&buf[..n]) {
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
                    }
                }
                Err(e) => {
                    tracing::warn!(error = %e, "serial read error");
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
        inspection: None,
        tx,
        read_task,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_serial_config() {
        let cfg = SerialConfig::new("serial0", "/dev/ttyUSB0").baud(115200);
        assert_eq!(cfg.baud_rate, 115200);
        assert_eq!(cfg.port, "/dev/ttyUSB0");
    }

    #[test]
    fn test_serial_config_custom_baud() {
        let cfg = SerialConfig::new("ser0", "/dev/ttyUSB0").baud(9600);
        assert_eq!(cfg.baud_rate, 9600);
    }

    #[test]
    fn test_serial_config_default_mode() {
        let cfg = SerialConfig::new("ser0", "/dev/ttyUSB0");
        assert_eq!(cfg.mode, InterfaceMode::Full);
    }

    #[test]
    fn test_serial_config_builder_chain() {
        let cfg = SerialConfig::new("serial0", "/dev/ttyACM0").baud(115200);
        assert_eq!(cfg.name, "serial0");
        assert_eq!(cfg.port, "/dev/ttyACM0");
        assert_eq!(cfg.baud_rate, 115200);
    }
}
