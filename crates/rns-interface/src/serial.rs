//! HDLC-framed data over a serial port. Requires feature `serial`. Blocking
//! `serialport` reads and writes run through Tokio's `spawn_blocking`.

use rns_transport::messages::{InterfacePacketCapacity, InterfaceTransportSender};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use bytes::Bytes;
use tokio::sync::mpsc;

use crate::hdlc;
use crate::traits::{InterfaceDirection, InterfaceHandle, InterfaceId, InterfaceMode};
use rns_transport::messages::{InboundPacket, TransportMessage};

pub use crate::serial_io::SerialFailures;

pub const DEFAULT_BAUD: u32 = 9600;

const SERIAL_READ_TIMEOUT_MS: u64 = 100;
const HW_MTU: usize = 564;

/// Open with DTR and RTS asserted, as POSIX `open()` and pyserial do. Windows
/// otherwise leaves both low, and TinyUSB CDC (nRF52 RNodes) sends nothing
/// until DTR is up. DTR rises first: RTS alone resets ESP32 auto-reset wiring.
pub fn open_port(
    builder: serialport::SerialPortBuilder,
) -> serialport::Result<Box<dyn serialport::SerialPort>> {
    let mut port = builder.dtr_on_open(true).open()?;
    // Best effort, like `dtr_on_open`: some adapters have no RTS line.
    let _ = port.write_request_to_send(true);
    Ok(port)
}

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

/// Seconds Python `SerialInterface.configure_device` sleeps before reading.
const CONFIGURE_SETTLE: Duration = Duration::from_millis(500);

/// The opener for a serial-family port. On Android the port names a USB
/// device (optionally `androidusb://`-prefixed), opened through `UsbManager`
/// as Python's Android interfaces do with usbserial4a; elsewhere it is a tty.
pub(crate) fn port_opener(
    port: &str,
    baud_rate: u32,
    data_bits: serialport::DataBits,
    parity: serialport::Parity,
    stop_bits: serialport::StopBits,
    read_timeout: Duration,
) -> crate::serial_io::PortOpener {
    #[cfg(target_os = "android")]
    {
        let _ = read_timeout;
        crate::android_usb::usb_serial_opener(port, baud_rate, data_bits, parity, stop_bits)
    }
    #[cfg(not(target_os = "android"))]
    {
        let builder = serialport::new(port, baud_rate)
            .data_bits(data_bits)
            .parity(parity)
            .stop_bits(stop_bits)
            .timeout(read_timeout);
        Arc::new(move || open_port(builder.clone()).map_err(std::io::Error::from))
    }
}

/// A serial-family interface handle paired with its runtime failure count.
#[non_exhaustive]
pub struct SpawnedSerialInterface {
    pub interface: InterfaceHandle,
    pub failures: SerialFailures,
}

/// Spawn a serial interface. An unopenable port does not fail the spawn: as in
/// Python, the interface stays offline and the port is retried every
/// `RECONNECT_WAIT` seconds, also after a runtime port error.
pub async fn spawn_serial_interface(
    config: SerialConfig,
    id: InterfaceId,
    transport_tx: mpsc::Sender<TransportMessage>,
) -> Result<InterfaceHandle, crate::traits::InterfaceError> {
    Ok(spawn_serial_interface_observed(config, id, transport_tx)
        .await?
        .interface)
}

pub async fn spawn_serial_interface_observed(
    config: SerialConfig,
    id: InterfaceId,
    transport_tx: mpsc::Sender<TransportMessage>,
) -> Result<SpawnedSerialInterface, crate::traits::InterfaceError> {
    let transport_tx = InterfaceTransportSender::new(id, transport_tx);
    let owner = transport_tx.owner();
    let online = Arc::new(AtomicBool::new(false));
    let shared_rxb = Arc::new(AtomicU64::new(0));
    let shared_txb = Arc::new(AtomicU64::new(0));
    let (tx, rx) = mpsc::channel::<Bytes>(256);
    let background = crate::background_announce::register(&tx)?;
    let name = config.name.clone();
    let python_identity =
        rns_transport::messages::InterfaceIdentity::bracketed("SerialInterface", &name);
    let mode = config.mode;
    let (failures_tx, failures) = crate::serial_io::SerialFailures::channel();

    let supervisor = crate::serial_io::Supervisor {
        identity: format!("SerialInterface[{name}]"),
        opener: port_opener(
            &config.port,
            config.baud_rate,
            config.data_bits,
            config.parity,
            config.stop_bits,
            Duration::from_millis(SERIAL_READ_TIMEOUT_MS),
        ),
        settle: CONFIGURE_SETTLE,
        online: online.clone(),
        failures: failures_tx,
    };
    let generation = SerialGeneration {
        id,
        rx,
        background,
        transport_tx,
        online: online.clone(),
        rxb: shared_rxb.clone(),
        txb: shared_txb.clone(),
    };
    let read_task = tokio::spawn(supervisor.run(generation, None));

    Ok(SpawnedSerialInterface {
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
            bitrate: config.baud_rate as u64,
            mtu: 564,
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

struct SerialGeneration {
    id: InterfaceId,
    rx: mpsc::Receiver<Bytes>,
    background: crate::background_announce::BackgroundAnnounceReceiver,
    transport_tx: InterfaceTransportSender,
    online: Arc<AtomicBool>,
    rxb: Arc<AtomicU64>,
    txb: Arc<AtomicU64>,
}

impl crate::serial_io::SerialGeneration for SerialGeneration {
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
            rx,
            background,
            transport_tx,
            online,
            rxb,
            txb,
        } = self;
        async move {
            let port_write = match port.try_clone() {
                Ok(port) => port,
                Err(e) => return GenerationEnd::ReadFailed(e.into()),
            };
            let writer = async {
                let mut port_w = port_write;
                loop {
                    if !online.load(Ordering::SeqCst) {
                        return GenerationEnd::Closed;
                    }
                    let background_packet = if rx.is_empty() {
                        background.try_start(rns_transport::now_f64())
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
                    let framed = hdlc::frame(&data);
                    let framed_len = framed.len() as u64;
                    match crate::serial_io::blocking_write_all(port_w, framed).await {
                        Ok(p) => {
                            port_w = p;
                            txb.fetch_add(framed_len, Ordering::Relaxed);
                        }
                        Err(e) => return GenerationEnd::WriteFailed(e),
                    }
                }
            };
            let reader = async {
                let mut port_r = port;
                let mut deframer = hdlc::HdlcByteDeframer::new(HW_MTU);
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
                            && last_read.elapsed() > Duration::from_millis(SERIAL_READ_TIMEOUT_MS)
                        {
                            deframer.reset();
                        }
                        continue;
                    }
                    last_read = std::time::Instant::now();
                    for frame in deframer.feed(&buf[..n]) {
                        if frame.is_empty() {
                            continue;
                        }
                        rxb.fetch_add(frame.len() as u64, Ordering::Relaxed);
                        let msg = TransportMessage::Inbound(InboundPacket {
                            raw: Bytes::from(frame),
                            interface_id: *id,
                            rssi: None,
                            snr: None,
                            q: None,
                        });
                        if transport_tx.send(msg).await.is_err() {
                            tracing::warn!(id, "transport channel closed");
                            return GenerationEnd::Closed;
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
