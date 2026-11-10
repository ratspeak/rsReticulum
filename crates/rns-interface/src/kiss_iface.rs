//! Serial port + KISS framing; CMD_DATA + CMD_READY flow control.

use rns_transport::messages::{InterfacePacketCapacity, InterfaceTransportSender};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use bytes::Bytes;
use tokio::sync::mpsc;

use crate::kiss;
use crate::traits::{InterfaceDirection, InterfaceHandle, InterfaceId, InterfaceMode};
use rns_transport::messages::{InboundPacket, TransportMessage};

const KISS_READ_TIMEOUT_MS: u64 = 100;
const HW_MTU: usize = 564;

/// Python `KISSInterface.BITRATE_GUESS`; `speed` is only the serial baud rate.
pub const BITRATE_GUESS: u64 = 1200;

/// Python `KISSInterface.flow_control_timeout`.
pub const FLOW_CONTROL_TIMEOUT: Duration = Duration::from_secs(5);

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
    /// Station-ID delay in seconds, armed by data transmission. Both this field
    /// and `id_callsign` must be set to enable automatic beacons.
    ///
    /// As in Python, a callsign shorter than 15 bytes is padded for transmission
    /// and so re-arms the timer: beacons then repeat every `id_interval`. A
    /// callsign of 15 bytes or more stops beaconing until the next data frame.
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

/// KISS TNC configuration frames in Python `configure_device` order:
/// TXDELAY, TXTAIL, P, SLOTTIME, then the flow-control enable `READY 0x01`,
/// which Python sends whether or not flow control is configured.
pub fn build_kiss_init(
    txdelay: Option<u8>,
    txtail: Option<u8>,
    persistence: Option<u8>,
    slottime: Option<u8>,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(20);
    for (cmd, value) in [
        (kiss::CMD_TXDELAY, txdelay),
        (kiss::CMD_TXTAIL, txtail),
        (kiss::CMD_P, persistence),
        (kiss::CMD_SLOTTIME, slottime),
    ] {
        if let Some(v) = value {
            kiss::frame_with_command_into(cmd, &[v], &mut out);
        }
    }
    kiss::frame_with_command_into(kiss::CMD_READY, &[0x01], &mut out);
    out
}

/// Beacon frame payload: callsign zero-padded to the 15-byte minimum
/// (Python `KISSInterface.read_loop`).
pub fn beacon_frame_payload(id_callsign: &[u8]) -> Vec<u8> {
    let mut frame = id_callsign.to_vec();
    while frame.len() < 15 {
        frame.push(0x00);
    }
    frame
}

/// Python `KISSInterface.configure_device` sleeps this long after opening the
/// port, before reading and before sending the TNC configuration.
const CONFIGURE_SETTLE: Duration = Duration::from_secs(2);

/// Spawn a KISS interface. An unopenable port does not fail the spawn: as in
/// Python, the interface stays offline and the port is retried every
/// `RECONNECT_WAIT` seconds, also after a runtime port error.
pub async fn spawn_kiss_interface(
    config: KissInterfaceConfig,
    id: InterfaceId,
    transport_tx: mpsc::Sender<TransportMessage>,
) -> Result<InterfaceHandle, crate::traits::InterfaceError> {
    Ok(spawn_kiss_interface_observed(config, id, transport_tx)
        .await?
        .interface)
}

pub async fn spawn_kiss_interface_observed(
    config: KissInterfaceConfig,
    id: InterfaceId,
    transport_tx: mpsc::Sender<TransportMessage>,
) -> Result<crate::serial::SpawnedSerialInterface, crate::traits::InterfaceError> {
    spawn_kiss_with_port(config, id, transport_tx, None).await
}

async fn spawn_kiss_with_port(
    config: KissInterfaceConfig,
    id: InterfaceId,
    transport_tx: mpsc::Sender<TransportMessage>,
    port: Option<crate::serial_io::Port>,
) -> Result<crate::serial::SpawnedSerialInterface, crate::traits::InterfaceError> {
    let transport_tx = InterfaceTransportSender::new(id, transport_tx);
    let owner = transport_tx.owner();
    let online = Arc::new(AtomicBool::new(false));
    let shared_rxb = Arc::new(AtomicU64::new(0));
    let shared_txb = Arc::new(AtomicU64::new(0));
    let (tx, rx) = mpsc::channel::<Bytes>(256);
    let background = crate::background_announce::register(&tx)?;
    let name = config.name.clone();
    let python_identity =
        rns_transport::messages::InterfaceIdentity::bracketed("KISSInterface", &name);
    let mode = config.mode;
    let (failures_tx, failures) = crate::serial_io::SerialFailures::channel();

    let supervisor = crate::serial_io::Supervisor {
        identity: format!("KISSInterface[{name}]"),
        opener: crate::serial::port_opener(
            &config.port,
            config.baud_rate,
            config.data_bits,
            config.parity,
            config.stop_bits,
            Duration::from_millis(KISS_READ_TIMEOUT_MS),
        ),
        settle: CONFIGURE_SETTLE,
        online: online.clone(),
        failures: failures_tx,
    };
    let beacon = config
        .id_interval
        .zip(config.id_callsign.clone())
        .map(|(interval, callsign)| (Duration::from_secs(interval), Bytes::from(callsign)));
    let generation = KissGeneration {
        id,
        init_frames: build_kiss_init(
            config.txdelay,
            config.txtail,
            config.persistence,
            config.slottime,
        ),
        flow_control: config.flow_control,
        beacon,
        rx,
        background,
        transport_tx,
        online: online.clone(),
        rxb: shared_rxb.clone(),
        txb: shared_txb.clone(),
    };
    let read_task = tokio::spawn(supervisor.run(generation, port));

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

struct KissGeneration {
    id: InterfaceId,
    init_frames: Vec<u8>,
    flow_control: bool,
    beacon: Option<(Duration, Bytes)>,
    rx: mpsc::Receiver<Bytes>,
    background: crate::background_announce::BackgroundAnnounceReceiver,
    transport_tx: InterfaceTransportSender,
    online: Arc<AtomicBool>,
    rxb: Arc<AtomicU64>,
    txb: Arc<AtomicU64>,
}

impl crate::serial_io::SerialGeneration for KissGeneration {
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
            beacon,
            rx,
            background,
            transport_tx,
            online,
            rxb,
            txb,
        } = self;
        let flow_control = *flow_control;
        let id = *id;
        async move {
            let port_write = match port.try_clone() {
                Ok(port) => port,
                Err(e) => return GenerationEnd::ReadFailed(e.into()),
            };
            // Python process_queue: a new generation starts with the radio ready.
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
                // Python first_tx semantics: armed by the first data TX after a
                // beacon; cleared when the beacon goes out.
                let mut first_tx: Option<tokio::time::Instant> = None;
                let mut flow_control_locked = tokio::time::Instant::now();
                let take_permit = |locked: tokio::time::Instant| {
                    if ready
                        .compare_exchange(true, false, Ordering::SeqCst, Ordering::SeqCst)
                        .is_ok()
                    {
                        return true;
                    }
                    if locked.elapsed() > FLOW_CONTROL_TIMEOUT {
                        tracing::warn!(
                            "KISS interface is unlocking flow control due to time-out. This should not happen. Your hardware might have missed a flow-control READY command, or maybe it does not support flow-control."
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
                    } else if let Some((interval, callsign)) = beacon.as_ref() {
                        match tokio::time::timeout(Duration::from_secs(1), rx.recv()).await {
                            Ok(Some(data)) => data,
                            Ok(None) => return GenerationEnd::Closed,
                            Err(_) => {
                                let due = first_tx.is_some_and(|t| t.elapsed() >= *interval);
                                if !due {
                                    continue;
                                }
                                tracing::debug!("KISS transmitting station-ID beacon");
                                first_tx = None;
                                Bytes::from(beacon_frame_payload(callsign))
                            }
                        }
                    } else {
                        match tokio::time::timeout(Duration::from_millis(100), rx.recv()).await {
                            Ok(Some(data)) => data,
                            Ok(None) => return GenerationEnd::Closed,
                            Err(_) => continue,
                        }
                    };

                    // Python compares against the unpadded callsign, so a padded beacon re-arms.
                    let is_beacon = beacon
                        .as_ref()
                        .is_some_and(|(_, callsign)| data == *callsign);
                    if is_beacon {
                        first_tx = None;
                    } else if first_tx.is_none() {
                        first_tx = Some(tokio::time::Instant::now());
                    }

                    if flow_control && background_packet.is_none() {
                        while !take_permit(flow_control_locked) {
                            tokio::time::sleep(Duration::from_millis(10)).await;
                            if !online.load(Ordering::SeqCst) {
                                return GenerationEnd::Closed;
                            }
                        }
                    }
                    if !online.load(Ordering::SeqCst) {
                        return GenerationEnd::Closed;
                    }
                    if flow_control {
                        flow_control_locked = tokio::time::Instant::now();
                    }
                    let framed = kiss::frame(&data);
                    match crate::serial_io::blocking_write_all(port_w, framed).await {
                        Ok(p) => {
                            port_w = p;
                            // Python counts the unframed payload here (KISSInterface.py:275).
                            txb.fetch_add(data.len() as u64, Ordering::Relaxed);
                        }
                        Err(e) => return GenerationEnd::WriteFailed(e),
                    }
                }
            };
            let reader = async {
                let mut port_r = port;
                let mut deframer = kiss::KissByteDeframer::new(HW_MTU);
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
                            && last_read.elapsed() > Duration::from_millis(KISS_READ_TIMEOUT_MS)
                        {
                            deframer.reset();
                        }
                        continue;
                    }
                    last_read = std::time::Instant::now();
                    for event in deframer.feed(&buf[..n]) {
                        match event {
                            kiss::KissEvent::Data(frame) => {
                                rxb.fetch_add(frame.len() as u64, Ordering::Relaxed);
                                let msg = TransportMessage::Inbound(InboundPacket {
                                    raw: Bytes::from(frame),
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
                                tracing::debug!(id, "KISS flow control: ready");
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
    #[cfg(unix)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn background_actor_kiss_pty_preserves_control_and_one_packet_ready() {
        use serialport::SerialPort;
        use std::io::{Read, Write};
        let (mut master, slave) = serialport::TTYPort::pair().unwrap();
        let name = slave.name().unwrap();
        master.set_timeout(Duration::from_millis(300)).unwrap();
        let (inbound, mut received) = mpsc::channel(4);
        let mut config = KissInterfaceConfig::new("arbitrary TNC", &name, 9600);
        config.flow_control = true;
        // macOS pseudo terminals cannot accept the hardware baud ioctl;
        // inject the already-open pair into the same production driver.
        // A macOS pty slave drains only as the master reads, so read the
        // configuration frames while the driver is still starting.
        let driver = spawn_kiss_with_port(config, 1, inbound, Some(Box::new(slave)))
            .await
            .unwrap()
            .interface;
        master.set_timeout(CONFIGURE_SETTLE * 2).unwrap();
        let init = build_kiss_init(None, None, None, None);
        let mut actual_init = vec![0; init.len()];
        master.read_exact(&mut actual_init).unwrap();
        assert_eq!(actual_init, init);
        master.set_timeout(Duration::from_millis(300)).unwrap();
        driver.owner.mark_registered();
        // The initial permit goes to the first packet; later ones wait for READY.
        driver.tx.send(Bytes::from_static(b"first")).await.unwrap();
        let expected = kiss::frame(b"first");
        let mut actual = vec![0; expected.len()];
        master.read_exact(&mut actual).unwrap();
        assert_eq!(actual, expected);
        master.write_all(&kiss::frame(b"read barrier")).unwrap();
        received.recv().await.unwrap();
        let (actor, control, raw) = crate::background_announce::scheduled_actor(driver.tx.clone());
        tokio::time::sleep(Duration::from_millis(300)).await;
        let mut probe = [0; 2048];
        assert!(
            master.read(&mut probe).is_err(),
            "no packet may go out before READY or the flow-control timeout"
        );
        driver
            .tx
            .send(Bytes::from_static(b"local control"))
            .await
            .unwrap();
        master
            .write_all(&kiss::frame_with_command(kiss::CMD_READY, &[1]))
            .unwrap();
        let expected = kiss::frame(b"local control");
        let mut actual = vec![0; expected.len()];
        master.read_exact(&mut actual).unwrap();
        assert_eq!(actual, expected);
        assert!(
            master.read(&mut probe).is_err(),
            "one READY cannot write two packets"
        );
        master
            .write_all(&kiss::frame_with_command(kiss::CMD_READY, &[1]))
            .unwrap();
        let expected = kiss::frame(&raw);
        let mut actual = vec![0; expected.len()];
        master.read_exact(&mut actual).unwrap();
        assert_eq!(actual, expected);
        driver.online.store(false, Ordering::SeqCst);
        control.send(TransportMessage::Shutdown).await.unwrap();
        actor.await.unwrap();
        driver.read_task.await.unwrap();
    }
}
