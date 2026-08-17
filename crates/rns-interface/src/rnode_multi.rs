//! Multi-radio RNode: up to 11 sub-interfaces on one serial connection.
//! One read task demuxes canonical `CMD_DATA` frames by the most recently
//! selected virtual port; one write task prepends `CMD_SEL_INT` so the device
//! picks the right radio.

use std::collections::HashSet;
use std::io::Write;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use bytes::Bytes;
use tokio::sync::mpsc;

use crate::kiss;
use crate::rnode;
use crate::traits::{
    InterfaceDirection, InterfaceError, InterfaceHandle, InterfaceId, InterfaceMode,
};
use rns_transport::messages::{InboundPacket, TransportMessage};

pub const MAX_SUBINTERFACES: usize = 11;

/// Minimum firmware supporting multi-interface mode.
pub const REQUIRED_FW_VER_MAJ: u8 = 1;
pub const REQUIRED_FW_VER_MIN: u8 = 74;

pub const CMD_SEL_INT: u8 = 0x1F;
pub const CMD_INTERFACES: u8 = 0x71;
pub const CMD_ERROR: u8 = 0x90;

pub const ERROR_INITRADIO: u8 = 0x01;
pub const ERROR_TXFAILED: u8 = 0x02;

/// Legacy per-interface constants exposed by the firmware protocol.
///
/// Live RNodeMulti traffic is not demultiplexed with this table. The canonical
/// wire form selects a vport with [`CMD_SEL_INT`] and then sends one ordinary
/// [`kiss::CMD_DATA`] frame. Treating these values as inbound data commands
/// makes `0x90` indistinguishable from [`CMD_ERROR`].
pub const CMD_INT_DATA: [u8; 12] = [
    0x00, 0x10, 0x20, 0x70, 0x75, 0x90, 0xA0, 0xB0, 0xC0, 0xD0, 0xE0, 0xF0,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RadioType {
    SX127X = 0x00,
    SX1276 = 0x01,
    SX1278 = 0x02,
    SX126X = 0x10,
    SX1262 = 0x11,
    SX128X = 0x20,
    SX1280 = 0x21,
}

impl RadioType {
    pub fn from_u8(val: u8) -> Option<Self> {
        match val {
            0x00 => Some(Self::SX127X),
            0x01 => Some(Self::SX1276),
            0x02 => Some(Self::SX1278),
            0x10 => Some(Self::SX126X),
            0x11 => Some(Self::SX1262),
            0x20 => Some(Self::SX128X),
            0x21 => Some(Self::SX1280),
            _ => None,
        }
    }

    pub fn family_name(&self) -> &'static str {
        match self {
            Self::SX127X | Self::SX1276 | Self::SX1278 => "SX127X",
            Self::SX126X | Self::SX1262 => "SX126X",
            Self::SX128X | Self::SX1280 => "SX128X",
        }
    }

    /// Sub-GHz: 137 MHz..1 GHz; SX128X: 2.2..2.6 GHz.
    pub fn validate_frequency(&self, freq_hz: u32) -> bool {
        match self {
            Self::SX127X | Self::SX1276 | Self::SX1278 | Self::SX126X | Self::SX1262 => {
                (137_000_000..=1_000_000_000).contains(&freq_hz)
            }
            Self::SX128X | Self::SX1280 => (2_200_000_000..=2_600_000_000).contains(&freq_hz),
        }
    }
}

#[derive(Debug, Clone)]
pub struct SubInterfaceConfig {
    pub name: String,
    /// vport index on RNode (`0..MAX_SUBINTERFACES`).
    pub vport: u8,
    pub frequency: u32,
    pub bandwidth: u32,
    pub spreading_factor: u8,
    pub coding_rate: u8,
    pub tx_power: u8,
    pub mode: InterfaceMode,
    pub flow_control: bool,
    pub outgoing: bool,
    /// Short-term airtime cap, percent of duty cycle.
    pub st_alock: Option<f32>,
    /// Long-term airtime cap, percent of duty cycle.
    pub lt_alock: Option<f32>,
}

impl SubInterfaceConfig {
    pub fn new(name: &str, vport: u8, frequency: u32) -> Self {
        Self {
            name: name.to_string(),
            vport,
            frequency,
            bandwidth: 125_000,
            spreading_factor: 7,
            coding_rate: 5,
            tx_power: 14,
            mode: InterfaceMode::Full,
            flow_control: false,
            outgoing: true,
            st_alock: None,
            lt_alock: None,
        }
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.tx_power > 37 {
            return Err(format!(
                "Invalid TX power {} for sub-interface {}",
                self.tx_power, self.name
            ));
        }
        if self.bandwidth < 7800 || self.bandwidth > 1_625_000 {
            return Err(format!(
                "Invalid bandwidth {} for sub-interface {}",
                self.bandwidth, self.name
            ));
        }
        if self.spreading_factor < 5 || self.spreading_factor > 12 {
            return Err(format!(
                "Invalid spreading factor {} for sub-interface {}",
                self.spreading_factor, self.name
            ));
        }
        if self.coding_rate < 5 || self.coding_rate > 8 {
            return Err(format!(
                "Invalid coding rate {} for sub-interface {}",
                self.coding_rate, self.name
            ));
        }
        if let Some(st) = self.st_alock {
            if !(0.0..=100.0).contains(&st) {
                return Err(format!(
                    "Invalid short-term airtime limit {} for sub-interface {}",
                    st, self.name
                ));
            }
        }
        if let Some(lt) = self.lt_alock {
            if !(0.0..=100.0).contains(&lt) {
                return Err(format!(
                    "Invalid long-term airtime limit {} for sub-interface {}",
                    lt, self.name
                ));
            }
        }
        if self.vport as usize >= MAX_SUBINTERFACES {
            return Err(format!(
                "Virtual port {} is outside 0..{} for sub-interface {}",
                self.vport,
                MAX_SUBINTERFACES - 1,
                self.name
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct RNodeMultiConfig {
    pub name: String,
    pub port: String,
    pub baud_rate: u32,
    pub flow_control: bool,
    /// Up to `MAX_SUBINTERFACES` radios on this device.
    pub subinterfaces: Vec<SubInterfaceConfig>,
    /// Station-ID beacon, parent-level: when due, the callsign is sent on
    /// all subinterfaces (Python RNodeMultiInterface.py:849-859).
    pub id_interval: Option<u64>,
    pub id_callsign: Option<Vec<u8>>,
}

impl RNodeMultiConfig {
    pub fn new(name: &str, port: &str) -> Self {
        Self {
            name: name.to_string(),
            port: port.to_string(),
            baud_rate: 115200,
            flow_control: false,
            subinterfaces: Vec::new(),
            id_interval: None,
            id_callsign: None,
        }
    }
}

/// SEL_INT, push params, then RADIO_STATE=ON last.
pub fn build_subinterface_init(index: u8, config: &SubInterfaceConfig) -> Vec<u8> {
    let mut out = Vec::with_capacity(80);

    kiss::frame_with_command_into(CMD_SEL_INT, &[index], &mut out);
    kiss::frame_with_command_into(
        rnode::CMD_FREQUENCY,
        &config.frequency.to_be_bytes(),
        &mut out,
    );
    kiss::frame_with_command_into(
        rnode::CMD_BANDWIDTH,
        &config.bandwidth.to_be_bytes(),
        &mut out,
    );
    kiss::frame_with_command_into(rnode::CMD_SF, &[config.spreading_factor], &mut out);
    kiss::frame_with_command_into(rnode::CMD_CR, &[config.coding_rate], &mut out);
    kiss::frame_with_command_into(rnode::CMD_TXPOWER, &[config.tx_power], &mut out);
    if let Some(st) = config.st_alock {
        let at = (st * 100.0) as u16;
        let c1 = (at >> 8) as u8;
        let c2 = (at & 0xFF) as u8;
        kiss::frame_with_command_into(rnode::CMD_ST_ALOCK, &[c1, c2], &mut out);
    }
    if let Some(lt) = config.lt_alock {
        let at = (lt * 100.0) as u16;
        let c1 = (at >> 8) as u8;
        let c2 = (at & 0xFF) as u8;
        kiss::frame_with_command_into(rnode::CMD_LT_ALOCK, &[c1, c2], &mut out);
    }
    kiss::frame_with_command_into(rnode::CMD_RADIO_STATE, &[rnode::RADIO_STATE_ON], &mut out);

    out
}

pub fn build_detect_sequence() -> Vec<u8> {
    let mut out = Vec::with_capacity(40);
    kiss::frame_with_command_into(rnode::CMD_DETECT, &[rnode::DETECT_REQ], &mut out);
    kiss::frame_with_command_into(rnode::CMD_FW_VERSION, &[0x00], &mut out);
    kiss::frame_with_command_into(rnode::CMD_PLATFORM, &[0x00], &mut out);
    kiss::frame_with_command_into(rnode::CMD_MCU, &[0x00], &mut out);
    kiss::frame_with_command_into(CMD_INTERFACES, &[0x00], &mut out);
    out
}

/// Wire form: `[FEND][CMD_SEL_INT][index][FEND][FEND][CMD_DATA][escaped_data][FEND]`.
pub fn build_subinterface_data_frame(index: u8, data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + data.len() + data.len() / 8);
    kiss::frame_with_command_into(CMD_SEL_INT, &[index], &mut out);
    kiss::frame_into(data, &mut out);
    out
}

/// Map a legacy `CMD_INTn_DATA` constant to its nominal vport.
///
/// This helper is retained for protocol inspection and compatibility only.
/// It must not be used to route live RNodeMulti input; use `CMD_SEL_INT`
/// followed by `CMD_DATA` instead.
#[deprecated(
    note = "legacy constants collide with control commands; route CMD_DATA by CMD_SEL_INT"
)]
pub fn command_to_subinterface(cmd_byte: u8) -> Option<usize> {
    for (i, &port_cmd) in CMD_INT_DATA.iter().enumerate() {
        if cmd_byte == port_cmd {
            return Some(i);
        }
    }
    None
}

const RNODE_HW_MTU: u32 = 508;
const RNODE_OPEN_SETTLE: Duration = Duration::from_secs(2);
const RNODE_SUBINTERFACE_SETTLE: Duration = Duration::from_secs(2);
const RNODE_SUBINTERFACE_READY_SETTLE: Duration = Duration::from_millis(300);
const RNODE_DISCOVERY_DEADLINE: Duration = Duration::from_secs(2);
const RNODE_CONFIGURATION_DEADLINE: Duration = Duration::from_secs(2);

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct RadioEvidence {
    frequency: Option<u32>,
    bandwidth: Option<u32>,
    spreading_factor: Option<u8>,
    coding_rate: Option<u8>,
    tx_power: Option<u8>,
    radio_state: Option<u8>,
}

impl RadioEvidence {
    fn complete(self) -> bool {
        self.frequency.is_some()
            && self.bandwidth.is_some()
            && self.spreading_factor.is_some()
            && self.coding_rate.is_some()
            && self.tx_power.is_some()
            && self.radio_state.is_some()
    }

    fn validate(self, config: &SubInterfaceConfig) -> Result<(), String> {
        let frequency = self
            .frequency
            .ok_or_else(|| format!("{} did not report frequency", config.name))?;
        if frequency.abs_diff(config.frequency) > crate::rnode_protocol::FREQUENCY_TOLERANCE_HZ {
            return Err(format!("{} reported a different frequency", config.name));
        }
        if self.bandwidth != Some(config.bandwidth) {
            return Err(format!("{} reported a different bandwidth", config.name));
        }
        if self.spreading_factor != Some(config.spreading_factor) {
            return Err(format!(
                "{} reported a different spreading factor",
                config.name
            ));
        }
        if self.coding_rate != Some(config.coding_rate) {
            return Err(format!("{} reported a different coding rate", config.name));
        }
        if self.tx_power != Some(config.tx_power) {
            return Err(format!("{} reported a different TX power", config.name));
        }
        if self.radio_state != Some(rnode::RADIO_STATE_ON) {
            return Err(format!("{} did not report its radio online", config.name));
        }
        Ok(())
    }
}

#[derive(Debug)]
struct StartupEvidence {
    detected: bool,
    firmware: Option<(u8, u8)>,
    interfaces: [Option<RadioType>; MAX_SUBINTERFACES],
    selected_vport: Option<u8>,
    radios: [RadioEvidence; MAX_SUBINTERFACES],
}

impl Default for StartupEvidence {
    fn default() -> Self {
        Self {
            detected: false,
            firmware: None,
            interfaces: [None; MAX_SUBINTERFACES],
            selected_vport: None,
            radios: [RadioEvidence::default(); MAX_SUBINTERFACES],
        }
    }
}

impl StartupEvidence {
    fn apply_frame(&mut self, command: u8, payload: &[u8]) -> Result<(), String> {
        match command {
            rnode::CMD_DETECT => {
                if payload.len() != 1 {
                    return Err("RNodeMulti returned malformed detection evidence".into());
                }
                self.detected = payload[0] == rnode::DETECT_RESP;
            }
            rnode::CMD_FW_VERSION => {
                if payload.len() != 2 {
                    return Err("RNodeMulti returned malformed firmware evidence".into());
                }
                self.firmware = Some((payload[0], payload[1]));
            }
            CMD_INTERFACES => {
                if payload.is_empty() {
                    return Ok(());
                }
                if !payload.len().is_multiple_of(2) {
                    return Err("RNodeMulti returned a malformed interface list".into());
                }
                for pair in payload.chunks_exact(2) {
                    let vport = pair[0] as usize;
                    if vport >= MAX_SUBINTERFACES {
                        return Err(format!(
                            "RNodeMulti reported unsupported virtual port {}",
                            pair[0]
                        ));
                    }
                    let radio_type = RadioType::from_u8(pair[1]).ok_or_else(|| {
                        format!(
                            "RNodeMulti reported unknown radio type 0x{:02X} on virtual port {}",
                            pair[1], pair[0]
                        )
                    })?;
                    if self.interfaces[vport].is_some_and(|known| known != radio_type) {
                        return Err(format!(
                            "RNodeMulti changed the radio type reported for virtual port {}",
                            pair[0]
                        ));
                    }
                    self.interfaces[vport] = Some(radio_type);
                }
            }
            CMD_SEL_INT => {
                if payload.len() != 1 || payload[0] as usize >= MAX_SUBINTERFACES {
                    self.selected_vport = None;
                    return Err("RNodeMulti returned an invalid virtual-port selection".into());
                }
                self.selected_vport = Some(payload[0]);
            }
            rnode::CMD_FREQUENCY => {
                if payload.len() != 4 {
                    return Err("RNodeMulti returned malformed frequency evidence".into());
                }
                if let Some(radio) = self.selected_radio_mut() {
                    radio.frequency = Some(u32::from_be_bytes(
                        payload.try_into().expect("length checked"),
                    ));
                }
            }
            rnode::CMD_BANDWIDTH => {
                if payload.len() != 4 {
                    return Err("RNodeMulti returned malformed bandwidth evidence".into());
                }
                if let Some(radio) = self.selected_radio_mut() {
                    radio.bandwidth = Some(u32::from_be_bytes(
                        payload.try_into().expect("length checked"),
                    ));
                }
            }
            rnode::CMD_SF => {
                let value = one_byte(payload, "spreading factor")?;
                if let Some(radio) = self.selected_radio_mut() {
                    radio.spreading_factor = Some(value);
                }
            }
            rnode::CMD_CR => {
                let value = one_byte(payload, "coding rate")?;
                if let Some(radio) = self.selected_radio_mut() {
                    radio.coding_rate = Some(value);
                }
            }
            rnode::CMD_TXPOWER => {
                let value = one_byte(payload, "TX power")?;
                if let Some(radio) = self.selected_radio_mut() {
                    radio.tx_power = Some(value);
                }
            }
            rnode::CMD_RADIO_STATE => {
                let value = one_byte(payload, "radio state")?;
                if let Some(radio) = self.selected_radio_mut() {
                    radio.radio_state = Some(value);
                }
            }
            CMD_ERROR => {
                let class = match payload.first().copied() {
                    Some(ERROR_INITRADIO) => "radio initialisation",
                    Some(ERROR_TXFAILED) => "radio transmission",
                    _ => "unknown hardware",
                };
                return Err(format!("RNodeMulti reported a {class} error"));
            }
            rnode::CMD_RESET if payload.first().copied() == Some(0xF8) => {
                return Err("RNodeMulti reset during startup".into());
            }
            _ => {}
        }
        Ok(())
    }

    fn selected_radio_mut(&mut self) -> Option<&mut RadioEvidence> {
        self.selected_vport
            .and_then(|vport| self.radios.get_mut(vport as usize))
    }

    fn discovery_complete(&self, config: &RNodeMultiConfig) -> bool {
        self.detected
            && self.firmware.is_some()
            && config
                .subinterfaces
                .iter()
                .all(|sub| self.interfaces[sub.vport as usize].is_some())
    }

    fn validate_discovery(&self, config: &RNodeMultiConfig) -> Result<(), String> {
        if !self.detected {
            return Err("RNodeMulti device did not answer detection".into());
        }
        let (major, minor) = self
            .firmware
            .ok_or_else(|| "RNodeMulti did not report its firmware version".to_string())?;
        if (major, minor) < (REQUIRED_FW_VER_MAJ, REQUIRED_FW_VER_MIN) {
            return Err(format!(
                "RNodeMulti firmware {major}.{minor} is below required {}.{}",
                REQUIRED_FW_VER_MAJ, REQUIRED_FW_VER_MIN
            ));
        }
        for sub in &config.subinterfaces {
            let radio_type = self.interfaces[sub.vport as usize].ok_or_else(|| {
                format!(
                    "virtual port {} for {} was not reported by the RNodeMulti device",
                    sub.vport, sub.name
                )
            })?;
            if !radio_type.validate_frequency(sub.frequency) {
                return Err(format!(
                    "frequency {} is outside the {} range reported for {}",
                    sub.frequency,
                    radio_type.family_name(),
                    sub.name
                ));
            }
        }
        Ok(())
    }

    fn reset_radio(&mut self, vport: u8) {
        self.radios[vport as usize] = RadioEvidence::default();
        self.selected_vport = None;
    }

    fn radio_complete(&self, vport: u8) -> bool {
        self.radios[vport as usize].complete()
    }
}

fn one_byte(payload: &[u8], field: &str) -> Result<u8, String> {
    if payload.len() != 1 {
        return Err(format!("RNodeMulti returned malformed {field} evidence"));
    }
    Ok(payload[0])
}

fn read_startup_until(
    port: &mut dyn serialport::SerialPort,
    deframer: &mut kiss::RawKissDeframer,
    evidence: &mut StartupEvidence,
    deadline: Instant,
    ready: impl Fn(&StartupEvidence) -> bool,
) -> Result<(), String> {
    let mut buffer = [0u8; 1024];
    while Instant::now() < deadline {
        match port.read(&mut buffer) {
            Ok(0) => {}
            Ok(read) => {
                for (command, payload) in deframer.feed(&buffer[..read]) {
                    evidence.apply_frame(command, &payload)?;
                    if ready(evidence) {
                        return Ok(());
                    }
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::TimedOut => {}
            Err(error) => return Err(format!("RNodeMulti startup read failed: {error}")),
        }
    }
    Err("RNodeMulti startup validation timed out".into())
}

fn initialise_rnode_multi(
    mut port: Box<dyn serialport::SerialPort>,
    config: &RNodeMultiConfig,
) -> Result<Box<dyn serialport::SerialPort>, String> {
    std::thread::sleep(RNODE_OPEN_SETTLE);
    let mut deframer = kiss::RawKissDeframer::new();
    let mut evidence = StartupEvidence::default();

    port.write_all(&build_detect_sequence())
        .map_err(|error| format!("RNodeMulti detect write failed: {error}"))?;
    port.flush()
        .map_err(|error| format!("RNodeMulti detect flush failed: {error}"))?;
    read_startup_until(
        port.as_mut(),
        &mut deframer,
        &mut evidence,
        Instant::now() + RNODE_DISCOVERY_DEADLINE,
        |state| state.discovery_complete(config),
    )?;
    evidence.validate_discovery(config)?;

    for sub in &config.subinterfaces {
        // RNode firmware configures one physical radio at a time. Match the
        // established RNodeMulti startup cadence and let the selected radio
        // settle before sending its reset/init sequence.
        std::thread::sleep(RNODE_SUBINTERFACE_SETTLE);
        evidence.reset_radio(sub.vport);
        port.write_all(&build_subinterface_init(sub.vport, sub))
            .map_err(|error| format!("RNodeMulti {} init write failed: {error}", sub.name))?;
        port.flush()
            .map_err(|error| format!("RNodeMulti {} init flush failed: {error}", sub.name))?;
        read_startup_until(
            port.as_mut(),
            &mut deframer,
            &mut evidence,
            Instant::now() + RNODE_CONFIGURATION_DEADLINE,
            |state| state.radio_complete(sub.vport),
        )?;
        evidence.radios[sub.vport as usize].validate(sub)?;
        // Match upstream's brief post-validation pause before exposing this
        // radio or beginning configuration of the next physical radio.
        std::thread::sleep(RNODE_SUBINTERFACE_READY_SETTLE);
    }

    Ok(port)
}

fn selected_data_target(
    command: u8,
    selected_vport: Option<u8>,
    vport_map: &[Option<usize>; MAX_SUBINTERFACES],
) -> Option<usize> {
    if command != kiss::CMD_DATA {
        return None;
    }
    selected_vport
        .and_then(|vport| vport_map.get(vport as usize))
        .copied()
        .flatten()
}

struct WriteRequest {
    index: u8,
    /// Raw payload, not yet KISS-escaped.
    data: Bytes,
    flow_control: bool,
}

#[derive(Default)]
struct SubInterfaceSignal {
    last_rssi: Option<f32>,
    last_snr: Option<f32>,
}

/// Device-level + per-sub online state shared by the writer and reader tasks.
#[derive(Clone)]
struct OnlineFlags {
    device: Arc<AtomicBool>,
    subs: Arc<Vec<Arc<AtomicBool>>>,
}

impl OnlineFlags {
    /// Device failure takes every sub-interface down with it.
    fn trip_device(&self) {
        self.device.store(false, Ordering::SeqCst);
        for sub in self.subs.iter() {
            sub.store(false, Ordering::SeqCst);
        }
    }

    /// True while the device is up and at least one sub remains registered —
    /// once false the shared reader exits and releases the serial port.
    fn device_running(&self) -> bool {
        self.device.load(Ordering::SeqCst) && self.subs.iter().any(|sub| sub.load(Ordering::SeqCst))
    }
}

const RNODE_READ_TIMEOUT_MS: u64 = 100;

/// Spawn one RNodeMulti over a single serial port.
///
/// Returns one `InterfaceHandle` per configured sub-interface. Each handle has
/// its own tx channel, `InterfaceId`, and online flag; all of them share one
/// serial connection. Tearing down one sub leaves the others running; the
/// shared reader exits (releasing the port) when the device fails or every
/// sub has been deregistered.
///
/// `ids.len()` must equal `config.subinterfaces.len()`.
pub async fn spawn_rnode_multi_interface(
    config: RNodeMultiConfig,
    ids: &[InterfaceId],
    transport_tx: mpsc::Sender<TransportMessage>,
) -> Result<Vec<InterfaceHandle>, InterfaceError> {
    if config.subinterfaces.is_empty() {
        return Err(InterfaceError::SendFailed(
            "RNodeMulti: no sub-interfaces configured".to_string(),
        ));
    }
    if ids.len() != config.subinterfaces.len() {
        return Err(InterfaceError::SendFailed(format!(
            "RNodeMulti: {} IDs provided but {} sub-interfaces configured",
            ids.len(),
            config.subinterfaces.len()
        )));
    }
    if config.subinterfaces.len() > MAX_SUBINTERFACES {
        return Err(InterfaceError::SendFailed(format!(
            "RNodeMulti: {} sub-interfaces exceeds max {}",
            config.subinterfaces.len(),
            MAX_SUBINTERFACES
        )));
    }

    for sub in &config.subinterfaces {
        sub.validate()
            .map_err(|e| InterfaceError::SendFailed(format!("RNodeMulti config: {}", e)))?;
    }
    let mut configured_vports = HashSet::with_capacity(config.subinterfaces.len());
    for sub in &config.subinterfaces {
        if !configured_vports.insert(sub.vport) {
            return Err(InterfaceError::SendFailed(format!(
                "RNodeMulti config: virtual port {} is configured more than once",
                sub.vport
            )));
        }
    }

    let port = serialport::new(&config.port, config.baud_rate)
        .timeout(Duration::from_millis(RNODE_READ_TIMEOUT_MS))
        .open()
        .map_err(|e| InterfaceError::SendFailed(format!("RNodeMulti open: {}", e)))?;

    tracing::info!(
        name = %config.name,
        port = %config.port,
        subinterfaces = config.subinterfaces.len(),
        "RNodeMulti interface opened"
    );

    let startup_config = config.clone();
    let port = tokio::task::spawn_blocking(move || initialise_rnode_multi(port, &startup_config))
        .await
        .map_err(|error| {
            InterfaceError::SendFailed(format!("RNodeMulti startup worker failed: {error}"))
        })?
        .map_err(|error| InterfaceError::SendFailed(format!("RNodeMulti startup: {error}")))?;

    let online = Arc::new(AtomicBool::new(true));

    let num_subs = config.subinterfaces.len();

    // Per-sub online flags: deregistering one sub must not kill the shared
    // device, but the reader must release the serial port once ALL subs are
    // gone; device-level failure trips every sub flag.
    let sub_onlines: Arc<Vec<Arc<AtomicBool>>> = Arc::new(
        (0..num_subs)
            .map(|_| Arc::new(AtomicBool::new(true)))
            .collect(),
    );
    let flags = OnlineFlags {
        device: online.clone(),
        subs: sub_onlines.clone(),
    };

    // All sub-interface handles funnel into one writer so CMD_SEL_INT framing
    // stays ordered relative to each data frame.
    let (write_tx, mut write_rx) = mpsc::channel::<WriteRequest>(256);

    let mut handles = Vec::with_capacity(num_subs);
    let mut sub_txb: Vec<Arc<AtomicU64>> = Vec::with_capacity(num_subs);
    let mut sub_rxb: Vec<Arc<AtomicU64>> = Vec::with_capacity(num_subs);

    for (i, sub_cfg) in config.subinterfaces.iter().enumerate() {
        let bitrate = rnode::calculate_bitrate(
            sub_cfg.spreading_factor,
            sub_cfg.coding_rate,
            sub_cfg.bandwidth,
        );

        let rxb = Arc::new(AtomicU64::new(0));
        let txb = Arc::new(AtomicU64::new(0));
        sub_rxb.push(rxb.clone());
        sub_txb.push(txb.clone());

        // Adapt the per-handle `Vec<u8>` channel into the shared WriteRequest
        // channel so the handle type stays symmetric with other interfaces.
        let (sub_tx, mut sub_rx) = mpsc::channel::<Bytes>(256);
        let write_tx_clone = write_tx.clone();
        let vport = sub_cfg.vport;
        let sub_flow_control = config.flow_control || sub_cfg.flow_control;
        let txb_fwd = txb.clone();

        tokio::spawn(async move {
            while let Some(data) = sub_rx.recv().await {
                txb_fwd.fetch_add(data.len() as u64, Ordering::Relaxed);
                if write_tx_clone
                    .send(WriteRequest {
                        index: vport,
                        data,
                        flow_control: sub_flow_control,
                    })
                    .await
                    .is_err()
                {
                    break;
                }
            }
        });

        let sub_name = format!("{}[{}]", config.name, sub_cfg.name);

        tracing::info!(
            name = %sub_name,
            vport = vport,
            freq = sub_cfg.frequency,
            bw = sub_cfg.bandwidth,
            sf = sub_cfg.spreading_factor,
            cr = sub_cfg.coding_rate,
            bitrate_bps = bitrate,
            "RNodeMulti sub-interface configured"
        );

        // The real read loop is shared by all sub-interfaces; each handle just
        // needs a JoinHandle that exits when its sub or the device goes offline.
        let online_sub = sub_onlines[i].clone();
        let device_sub = online.clone();
        let sub_read_task = tokio::spawn(async move {
            loop {
                if !online_sub.load(Ordering::SeqCst) || !device_sub.load(Ordering::SeqCst) {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
        });

        handles.push(InterfaceHandle {
            id: ids[i],
            parent_id: None,
            name: sub_name,
            mode: sub_cfg.mode,
            direction: InterfaceDirection {
                inbound: true,
                outbound: sub_cfg.outgoing,
                forward: false,
                repeat: false,
            },
            bitrate,
            mtu: RNODE_HW_MTU,
            online: sub_onlines[i].clone(),
            rxb: Some(rxb),
            txb: Some(txb),
            inspection: None,
            tx: sub_tx,
            read_task: sub_read_task,
        });
    }

    // Drop our clone so the writer exits once every sub-interface handle drops.
    drop(write_tx);

    let port_write = port
        .try_clone()
        .map_err(|e| InterfaceError::SendFailed(format!("RNodeMulti clone: {}", e)))?;
    let online_w = online.clone();
    let flags_w = flags.clone();
    let ready = Arc::new(AtomicBool::new(true));
    let ready_w = ready.clone();

    // Python RNodeMultiInterface.py:281-291 — oversized callsigns disable
    // beaconing; when due, the callsign goes out on all subinterfaces.
    let beacon: Option<(Duration, Bytes)> = config
        .id_interval
        .zip(config.id_callsign.clone())
        .filter(|(_, callsign)| {
            let ok = callsign.len() <= rnode::CALLSIGN_MAX_LEN;
            if !ok {
                tracing::error!(
                    name = %config.name,
                    len = callsign.len(),
                    "id_callsign exceeds {} bytes, beaconing disabled",
                    rnode::CALLSIGN_MAX_LEN
                );
            }
            ok
        })
        .map(|(interval, callsign)| (Duration::from_secs(interval), Bytes::from(callsign)));
    let beacon_vports: Vec<u8> = config.subinterfaces.iter().map(|s| s.vport).collect();

    tokio::spawn(async move {
        let mut port_w = port_write;
        let mut first_tx: Option<tokio::time::Instant> = None;
        loop {
            let req = if let Some((interval, ref callsign)) = beacon {
                match tokio::time::timeout(Duration::from_secs(1), write_rx.recv()).await {
                    Ok(Some(req)) => req,
                    Ok(None) => break,
                    Err(_) => {
                        if first_tx.is_none_or(|t| t.elapsed() < interval)
                            || !online_w.load(Ordering::SeqCst)
                        {
                            continue;
                        }
                        tracing::debug!(
                            "RNodeMulti transmitting station-ID beacon on all subinterfaces"
                        );
                        first_tx = None;
                        let mut frames = Vec::new();
                        for &vport in &beacon_vports {
                            frames
                                .extend_from_slice(&build_subinterface_data_frame(vport, callsign));
                        }
                        match crate::serial_io::blocking_write_all(port_w, frames).await {
                            Ok(p) => {
                                port_w = p;
                                continue;
                            }
                            Err(_) => {
                                flags_w.trip_device();
                                break;
                            }
                        }
                    }
                }
            } else {
                match write_rx.recv().await {
                    Some(req) => req,
                    None => break,
                }
            };
            if !online_w.load(Ordering::SeqCst) {
                break;
            }
            if let Some((_, ref callsign)) = beacon {
                if req.data == *callsign {
                    first_tx = None;
                } else if first_tx.is_none() {
                    first_tx = Some(tokio::time::Instant::now());
                }
            }

            if req.flow_control {
                // Bound CMD_READY wait at ~5 s so a stuck TNC can't block tx.
                let mut wait_count = 0;
                while !ready_w.load(Ordering::SeqCst) {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                    wait_count += 1;
                    if !online_w.load(Ordering::SeqCst) || wait_count > 500 {
                        break;
                    }
                }
            }

            let frame = build_subinterface_data_frame(req.index, &req.data);
            match crate::serial_io::blocking_write_all(port_w, frame).await {
                Ok(p) => {
                    port_w = p;
                }
                Err(e) => {
                    tracing::warn!(error = %e, "RNodeMulti write error");
                    flags_w.trip_device();
                    break;
                }
            }
        }
    });

    let flags_r = flags;
    let ready_r = ready;
    let parent_name = config.name.clone();

    // `vport_map[vport] -> Some(local_index)` for configured sub-interfaces.
    let mut vport_map: [Option<usize>; MAX_SUBINTERFACES] = [None; MAX_SUBINTERFACES];
    let mut sub_ids: Vec<InterfaceId> = Vec::with_capacity(num_subs);
    for (i, sub_cfg) in config.subinterfaces.iter().enumerate() {
        let vp = sub_cfg.vport as usize;
        vport_map[vp] = Some(i);
        sub_ids.push(ids[i]);
    }

    tokio::spawn(async move {
        let mut port_r = port;
        let mut deframer = kiss::RawKissDeframer::new();
        let mut buf = [0u8; 1024];

        let mut signals: Vec<SubInterfaceSignal> = (0..num_subs)
            .map(|_| SubInterfaceSignal::default())
            .collect();

        // Which sub-interface the device is currently addressing via
        // CMD_SEL_INT; status and canonical CMD_DATA frames target this vport.
        let mut selected_vport: Option<u8> = Some(0);

        loop {
            if !flags_r.device_running() {
                break;
            }

            match crate::serial_io::poll_read(port_r, buf).await {
                Ok((p, b, n)) => {
                    port_r = p;
                    buf = b;
                    if n == 0 {
                        continue;
                    }

                    for (raw_cmd, frame) in deframer.feed(&buf[..n]) {
                        if raw_cmd == kiss::CMD_DATA {
                            if frame.is_empty() {
                                continue;
                            }
                            if let Some(local_idx) =
                                selected_data_target(raw_cmd, selected_vport, &vport_map)
                            {
                                sub_rxb[local_idx].fetch_add(frame.len() as u64, Ordering::Relaxed);

                                let rssi = signals[local_idx].last_rssi.take();
                                let snr = signals[local_idx].last_snr.take();

                                let msg = TransportMessage::Inbound(InboundPacket {
                                    raw: Bytes::from(frame),
                                    interface_id: sub_ids[local_idx],
                                    rssi,
                                    snr,
                                    q: None,
                                });
                                if transport_tx.send(msg).await.is_err() {
                                    tracing::warn!(
                                        parent = %parent_name,
                                        "transport channel closed"
                                    );
                                    flags_r.trip_device();
                                    return;
                                }
                            } else {
                                tracing::debug!(
                                    parent = %parent_name,
                                    vport = ?selected_vport,
                                    "data for unconfigured sub-interface, dropping"
                                );
                            }
                            continue;
                        }

                        match raw_cmd {
                            CMD_SEL_INT => {
                                // Device echoes selection before emitting any
                                // status/config responses for that sub-interface.
                                if let Some(&idx) = frame.first() {
                                    selected_vport =
                                        ((idx as usize) < MAX_SUBINTERFACES).then_some(idx);
                                    if selected_vport.is_none() {
                                        tracing::warn!(
                                            parent = %parent_name,
                                            vport = idx,
                                            "RNodeMulti selected an invalid virtual port"
                                        );
                                    }
                                }
                            }

                            rnode::CMD_STAT_RSSI => {
                                if !frame.is_empty() {
                                    let rssi = rnode::decode_rssi_byte(frame[0]);
                                    if let Some(local_idx) =
                                        selected_vport.and_then(|vport| vport_map[vport as usize])
                                    {
                                        signals[local_idx].last_rssi = Some(rssi);
                                    }
                                }
                            }
                            rnode::CMD_STAT_SNR => {
                                if !frame.is_empty() {
                                    let snr = rnode::decode_snr_byte(frame[0]);
                                    if let Some(local_idx) =
                                        selected_vport.and_then(|vport| vport_map[vport as usize])
                                    {
                                        signals[local_idx].last_snr = Some(snr);
                                    }
                                }
                            }

                            rnode::CMD_READY => {
                                let is_ready = frame.first().copied().unwrap_or(0) != 0;
                                ready_r.store(is_ready, Ordering::SeqCst);
                            }

                            rnode::CMD_DETECT => {
                                if frame.first().copied() == Some(rnode::DETECT_RESP) {
                                    tracing::info!(
                                        parent = %parent_name,
                                        "RNodeMulti device detected"
                                    );
                                }
                            }

                            rnode::CMD_FW_VERSION => {
                                if frame.len() >= 2 {
                                    let major = frame[0];
                                    let minor = frame[1];
                                    tracing::info!(
                                        parent = %parent_name,
                                        major, minor,
                                        "RNodeMulti firmware version {}.{}",
                                        major, minor,
                                    );
                                    if major < REQUIRED_FW_VER_MAJ
                                        || (major == REQUIRED_FW_VER_MAJ
                                            && minor < REQUIRED_FW_VER_MIN)
                                    {
                                        tracing::warn!(
                                            parent = %parent_name,
                                            "RNodeMulti firmware {}.{} below required {}.{}",
                                            major, minor,
                                            REQUIRED_FW_VER_MAJ, REQUIRED_FW_VER_MIN,
                                        );
                                    }
                                }
                            }

                            rnode::CMD_RADIO_STATE => {
                                if let Some(local_idx) =
                                    selected_vport.and_then(|vport| vport_map[vport as usize])
                                {
                                    if frame.first().copied() == Some(rnode::RADIO_STATE_ON) {
                                        tracing::info!(
                                            parent = %parent_name,
                                            subinterface = local_idx,
                                            vport = ?selected_vport,
                                            "RNodeMulti sub-interface radio online"
                                        );
                                    } else {
                                        tracing::warn!(
                                            parent = %parent_name,
                                            subinterface = local_idx,
                                            vport = ?selected_vport,
                                            "RNodeMulti sub-interface radio offline"
                                        );
                                    }
                                }
                            }

                            rnode::CMD_FREQUENCY => {
                                if frame.len() >= 4 {
                                    let freq = u32::from_be_bytes([
                                        frame[0], frame[1], frame[2], frame[3],
                                    ]);
                                    tracing::debug!(
                                        parent = %parent_name,
                                        vport = ?selected_vport,
                                        freq_mhz = format!("{:.3}", freq as f64 / 1_000_000.0),
                                        "Radio reporting frequency"
                                    );
                                }
                            }

                            rnode::CMD_BANDWIDTH => {
                                if frame.len() >= 4 {
                                    let bw = u32::from_be_bytes([
                                        frame[0], frame[1], frame[2], frame[3],
                                    ]);
                                    tracing::debug!(
                                        parent = %parent_name,
                                        vport = ?selected_vport,
                                        bw_khz = format!("{:.1}", bw as f64 / 1000.0),
                                        "Radio reporting bandwidth"
                                    );
                                }
                            }

                            rnode::CMD_SF => {
                                if !frame.is_empty() {
                                    tracing::debug!(
                                        parent = %parent_name,
                                        vport = ?selected_vport,
                                        sf = frame[0],
                                        "Radio reporting spreading factor"
                                    );
                                }
                            }

                            rnode::CMD_CR => {
                                if !frame.is_empty() {
                                    tracing::debug!(
                                        parent = %parent_name,
                                        vport = ?selected_vport,
                                        cr = frame[0],
                                        "Radio reporting coding rate"
                                    );
                                }
                            }

                            rnode::CMD_TXPOWER => {
                                if !frame.is_empty() {
                                    let txp = frame[0] as i8;
                                    tracing::debug!(
                                        parent = %parent_name,
                                        vport = ?selected_vport,
                                        txpower_dbm = txp,
                                        "Radio reporting TX power"
                                    );
                                }
                            }

                            rnode::CMD_ST_ALOCK => {
                                if frame.len() >= 2 {
                                    let at = ((frame[0] as u16) << 8) | frame[1] as u16;
                                    let pct = at as f32 / 100.0;
                                    tracing::debug!(
                                        parent = %parent_name,
                                        vport = ?selected_vport,
                                        "RNodeMulti short-term airtime limit: {:.2}%", pct,
                                    );
                                }
                            }

                            rnode::CMD_LT_ALOCK => {
                                if frame.len() >= 2 {
                                    let at = ((frame[0] as u16) << 8) | frame[1] as u16;
                                    let pct = at as f32 / 100.0;
                                    tracing::debug!(
                                        parent = %parent_name,
                                        vport = ?selected_vport,
                                        "RNodeMulti long-term airtime limit: {:.2}%", pct,
                                    );
                                }
                            }

                            rnode::CMD_PLATFORM => {
                                if !frame.is_empty() {
                                    tracing::debug!(
                                        parent = %parent_name,
                                        platform = format!("0x{:02X}", frame[0]),
                                        "RNodeMulti platform"
                                    );
                                }
                            }

                            rnode::CMD_MCU => {
                                if !frame.is_empty() {
                                    tracing::debug!(
                                        parent = %parent_name,
                                        mcu = format!("0x{:02X}", frame[0]),
                                        "RNodeMulti MCU"
                                    );
                                }
                            }

                            CMD_INTERFACES => {
                                // Reply is one or more `[vport, radio_type]` pairs.
                                for pair in frame.chunks_exact(2) {
                                    let vp = pair[0];
                                    let rt = pair[1];
                                    let rtype = RadioType::from_u8(rt)
                                        .map(|r| r.family_name().to_string())
                                        .unwrap_or_else(|| format!("unknown(0x{:02X})", rt));
                                    tracing::info!(
                                        parent = %parent_name,
                                        vport = vp,
                                        radio_type = %rtype,
                                        "RNodeMulti radio module reported"
                                    );
                                }
                                if !frame.len().is_multiple_of(2) {
                                    tracing::warn!(
                                        parent = %parent_name,
                                        "RNodeMulti returned a malformed interface list"
                                    );
                                }
                            }

                            CMD_ERROR => {
                                let class = match frame.first().copied() {
                                    Some(ERROR_INITRADIO) => "radio initialisation",
                                    Some(ERROR_TXFAILED) => "radio transmission",
                                    _ => "unknown hardware",
                                };
                                tracing::error!(
                                    parent = %parent_name,
                                    class,
                                    "RNodeMulti hardware error"
                                );
                                flags_r.trip_device();
                                return;
                            }

                            rnode::CMD_RESET => {
                                if frame.first().copied() == Some(0xF8) {
                                    tracing::error!(
                                        parent = %parent_name,
                                        "RNodeMulti device reset detected"
                                    );
                                    flags_r.trip_device();
                                    return;
                                }
                            }

                            _ => {
                                tracing::debug!(
                                    parent = %parent_name,
                                    cmd = format!("0x{:02X}", raw_cmd),
                                    "RNodeMulti: ignoring KISS command"
                                );
                            }
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!(
                        parent = %parent_name,
                        error = %e,
                        "RNodeMulti read error"
                    );
                    flags_r.trip_device();
                    return;
                }
            }
        }
    });

    Ok(handles)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rnode_multi_config() {
        let mut cfg = RNodeMultiConfig::new("multi0", "/dev/ttyACM0");
        assert_eq!(cfg.baud_rate, 115200);
        assert!(!cfg.flow_control);
        assert!(cfg.subinterfaces.is_empty());

        cfg.subinterfaces
            .push(SubInterfaceConfig::new("radio0", 0, 868_000_000));
        cfg.subinterfaces
            .push(SubInterfaceConfig::new("radio1", 1, 915_000_000));
        assert_eq!(cfg.subinterfaces.len(), 2);
        assert!(cfg.subinterfaces.iter().all(|sub| sub.outgoing));
        assert!(cfg.subinterfaces.iter().all(|sub| !sub.flow_control));
    }

    /// T1-3: the shared serial reader runs while the device is up and at
    /// least one sub-interface remains registered. Deregistering one sub
    /// must NOT stop the device; deregistering all must (port release);
    /// device failure trips every sub flag.
    #[test]
    fn test_online_flags_reader_exit_semantics() {
        let flags = OnlineFlags {
            device: Arc::new(AtomicBool::new(true)),
            subs: Arc::new(vec![
                Arc::new(AtomicBool::new(true)),
                Arc::new(AtomicBool::new(true)),
            ]),
        };
        assert!(flags.device_running());

        // One sub deregistered (actor flips its flag): device keeps serving.
        flags.subs[0].store(false, Ordering::SeqCst);
        assert!(flags.device_running());

        // Last sub deregistered: reader must exit and release the port.
        flags.subs[1].store(false, Ordering::SeqCst);
        assert!(!flags.device_running());

        // Device failure path: every sub flag goes down with the device.
        let flags2 = OnlineFlags {
            device: Arc::new(AtomicBool::new(true)),
            subs: Arc::new(vec![Arc::new(AtomicBool::new(true))]),
        };
        flags2.trip_device();
        assert!(!flags2.device.load(Ordering::SeqCst));
        assert!(!flags2.subs[0].load(Ordering::SeqCst));
        assert!(!flags2.device_running());
    }

    /// The multi reader decodes STAT_RSSI/STAT_SNR via the shared rnode
    /// helpers — Python formula: RSSI = raw byte − 157, SNR = signed × 0.25.
    #[test]
    fn test_multi_rssi_snr_decode_matches_python() {
        assert_eq!(rnode::decode_rssi_byte(67), -90.0);
        assert_eq!(rnode::decode_snr_byte(0xF6), -2.5);
    }

    #[test]
    fn test_subinterface_init_sequence() {
        let sub_cfg = SubInterfaceConfig::new("radio0", 0, 868_000_000);
        let seq = build_subinterface_init(0, &sub_cfg);
        assert!(!seq.is_empty());

        let mut deframer = kiss::KissDeframer::new();
        let frames = deframer.feed(&seq);
        // sel_int + freq + bw + sf + cr + txpower + radio_state
        assert_eq!(frames.len(), 7);
    }

    #[test]
    fn test_subinterface_init_with_airtime() {
        let mut sub_cfg = SubInterfaceConfig::new("radio0", 0, 868_000_000);
        sub_cfg.st_alock = Some(15.0);
        sub_cfg.lt_alock = Some(25.0);

        let seq = build_subinterface_init(0, &sub_cfg);
        let mut deframer = kiss::KissDeframer::new();
        let frames = deframer.feed(&seq);
        // 7 base + 2 airtime limits
        assert_eq!(frames.len(), 9);
    }

    #[test]
    fn test_radio_type() {
        assert_eq!(RadioType::from_u8(0x00), Some(RadioType::SX127X));
        assert_eq!(RadioType::from_u8(0x11), Some(RadioType::SX1262));
        assert_eq!(RadioType::from_u8(0x21), Some(RadioType::SX1280));
        assert_eq!(RadioType::from_u8(0xFF), None);

        assert_eq!(RadioType::SX127X.family_name(), "SX127X");
        assert_eq!(RadioType::SX1262.family_name(), "SX126X");
        assert_eq!(RadioType::SX1280.family_name(), "SX128X");
    }

    #[test]
    fn test_radio_type_frequency_validation() {
        let sx127x = RadioType::SX127X;
        assert!(sx127x.validate_frequency(868_000_000));
        assert!(sx127x.validate_frequency(915_000_000));
        assert!(sx127x.validate_frequency(137_000_000));
        assert!(sx127x.validate_frequency(1_000_000_000));
        assert!(!sx127x.validate_frequency(136_999_999));
        assert!(!sx127x.validate_frequency(1_000_000_001));

        let sx1280 = RadioType::SX1280;
        assert!(sx1280.validate_frequency(2_400_000_000));
        assert!(!sx1280.validate_frequency(868_000_000));
    }

    #[test]
    fn test_max_subinterfaces() {
        assert_eq!(MAX_SUBINTERFACES, 11);
        assert_eq!(RNODE_HW_MTU, 508);

        let highest = SubInterfaceConfig::new("radio10", 10, 868_000_000);
        assert!(highest.validate().is_ok());
        let outside = SubInterfaceConfig::new("radio11", 11, 868_000_000);
        assert!(outside.validate().is_err());
    }

    #[test]
    fn test_detect_sequence() {
        let seq = build_detect_sequence();
        assert!(!seq.is_empty());
        let mut deframer = kiss::KissDeframer::new();
        let frames = deframer.feed(&seq);
        // DETECT + FW_VERSION + PLATFORM + MCU + INTERFACES
        assert_eq!(frames.len(), 5);
    }

    #[test]
    fn test_build_subinterface_data_frame() {
        let data = b"hello radio";
        let frame = build_subinterface_data_frame(2, data);
        assert!(!frame.is_empty());

        let mut deframer = kiss::RawKissDeframer::new();
        let frames = deframer.feed(&frame);
        // CMD_SEL_INT then CMD_DATA
        assert_eq!(frames.len(), 2);
        assert_eq!(frames[0].0, CMD_SEL_INT);
        assert_eq!(frames[0].1, &[2u8]);
        assert_eq!(frames[1].0, kiss::CMD_DATA);
        assert_eq!(frames[1].1, data);
    }

    #[test]
    fn test_raw_kiss_deframer_preserves_command() {
        // CMD_ERROR is 0x90. The raw deframer must retain that exact command
        // so it can never be mistaken for vport-5 packet data.
        let payload = &[ERROR_INITRADIO];
        let mut raw_frame = Vec::new();
        raw_frame.push(kiss::FEND);
        raw_frame.push(0x90);
        raw_frame.extend_from_slice(&kiss::escape(payload));
        raw_frame.push(kiss::FEND);

        let mut deframer = kiss::RawKissDeframer::new();
        let frames = deframer.feed(&raw_frame);
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].0, CMD_ERROR);
        assert_eq!(frames[0].1, payload);

        let mut vport_map = [None; MAX_SUBINTERFACES];
        vport_map[5] = Some(0);
        assert_eq!(selected_data_target(CMD_ERROR, Some(5), &vport_map), None);
    }

    #[test]
    fn test_raw_kiss_deframer_streaming() {
        let payload = b"streamed";
        let mut raw_frame = Vec::new();
        raw_frame.push(kiss::FEND);
        raw_frame.push(0xA0);
        raw_frame.extend_from_slice(&kiss::escape(payload));
        raw_frame.push(kiss::FEND);

        let mid = raw_frame.len() / 2;
        let mut deframer = kiss::RawKissDeframer::new();

        let f1 = deframer.feed(&raw_frame[..mid]);
        assert!(f1.is_empty());

        let f2 = deframer.feed(&raw_frame[mid..]);
        assert_eq!(f2.len(), 1);
        assert_eq!(f2[0].0, 0xA0);
        assert_eq!(f2[0].1, payload);
    }

    #[test]
    fn test_raw_kiss_deframer_multiple_frames() {
        let mut stream = vec![
            kiss::FEND,
            CMD_SEL_INT,
            3,
            kiss::FEND,
            kiss::FEND,
            rnode::CMD_STAT_RSSI,
            0x80,
            kiss::FEND,
            kiss::FEND,
            0x70,
        ];
        stream.extend_from_slice(b"packet");
        stream.push(kiss::FEND);

        let mut deframer = kiss::RawKissDeframer::new();
        let frames = deframer.feed(&stream);
        assert_eq!(frames.len(), 3);

        assert_eq!(frames[0].0, CMD_SEL_INT);
        assert_eq!(frames[0].1, &[3u8]);

        assert_eq!(frames[1].0, rnode::CMD_STAT_RSSI);
        assert_eq!(frames[1].1, &[0x80u8]);

        assert_eq!(frames[2].0, 0x70);
        assert_eq!(frames[2].1, b"packet");
    }

    #[test]
    fn test_raw_kiss_deframer_escape_handling() {
        let raw_frame = vec![
            kiss::FEND,
            0xB0,
            kiss::FESC,
            kiss::TFEND,
            kiss::FESC,
            kiss::TFESC,
            0x42,
            kiss::FEND,
        ];

        let mut deframer = kiss::RawKissDeframer::new();
        let frames = deframer.feed(&raw_frame);
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].0, 0xB0);
        assert_eq!(frames[0].1, &[kiss::FEND, kiss::FESC, 0x42]);
    }

    #[test]
    fn test_subinterface_config_validate() {
        let cfg = SubInterfaceConfig::new("radio0", 0, 868_000_000);
        assert!(cfg.validate().is_ok());

        let mut bad = SubInterfaceConfig::new("radio0", 0, 868_000_000);
        bad.spreading_factor = 13;
        assert!(bad.validate().is_err());

        let mut bad = SubInterfaceConfig::new("radio0", 0, 868_000_000);
        bad.coding_rate = 9;
        assert!(bad.validate().is_err());

        let mut bad = SubInterfaceConfig::new("radio0", 0, 868_000_000);
        bad.bandwidth = 1000;
        assert!(bad.validate().is_err());

        let mut bad = SubInterfaceConfig::new("radio0", 0, 868_000_000);
        bad.bandwidth = 2_000_000;
        assert!(bad.validate().is_err());

        let mut bad = SubInterfaceConfig::new("radio0", 0, 868_000_000);
        bad.st_alock = Some(101.0);
        assert!(bad.validate().is_err());

        let bad = SubInterfaceConfig::new("radio0", 11, 868_000_000);
        assert!(bad.validate().is_err());
    }

    #[test]
    fn test_subinterface_config_validate_edge_cases() {
        let mut cfg = SubInterfaceConfig::new("radio0", 0, 868_000_000);
        cfg.spreading_factor = 5;
        cfg.coding_rate = 5;
        cfg.bandwidth = 7800;
        assert!(cfg.validate().is_ok());

        cfg.spreading_factor = 12;
        cfg.coding_rate = 8;
        cfg.bandwidth = 1_625_000;
        cfg.st_alock = Some(100.0);
        cfg.lt_alock = Some(100.0);
        assert!(cfg.validate().is_ok());

        cfg.st_alock = Some(0.0);
        cfg.lt_alock = Some(0.0);
        assert!(cfg.validate().is_ok());

        cfg.st_alock = Some(-1.0);
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn test_multi_detect_sequence_includes_interfaces_query() {
        let seq = build_detect_sequence();
        let mut deframer = kiss::RawKissDeframer::new();
        let frames = deframer.feed(&seq);

        assert_eq!(frames.len(), 5);
        assert_eq!(frames[0].0, rnode::CMD_DETECT);
        assert_eq!(frames[1].0, rnode::CMD_FW_VERSION);
        assert_eq!(frames[2].0, rnode::CMD_PLATFORM);
        assert_eq!(frames[3].0, rnode::CMD_MCU);
        assert_eq!(frames[4].0, CMD_INTERFACES);
    }

    #[test]
    fn test_data_frame_roundtrip() {
        let payload = vec![0xAA, 0xBB, 0xCC, 0xDD];
        let frame = build_subinterface_data_frame(1, &payload);

        let mut deframer = kiss::RawKissDeframer::new();
        let frames = deframer.feed(&frame);
        assert_eq!(frames.len(), 2);

        assert_eq!(frames[0].0, CMD_SEL_INT);
        assert_eq!(frames[0].1, &[1u8]);

        assert_eq!(frames[1].0, kiss::CMD_DATA);
        assert_eq!(frames[1].1, payload);
    }

    #[test]
    fn test_data_frame_with_escape_chars() {
        let payload = vec![kiss::FEND, kiss::FESC, 0x42, kiss::FEND];
        let frame = build_subinterface_data_frame(0, &payload);

        let mut deframer = kiss::RawKissDeframer::new();
        let frames = deframer.feed(&frame);
        assert_eq!(frames.len(), 2);
        assert_eq!(frames[1].0, kiss::CMD_DATA);
        assert_eq!(frames[1].1, payload);
    }

    #[test]
    fn canonical_data_routing_uses_selected_vport_only() {
        let mut vport_map = [None; MAX_SUBINTERFACES];
        vport_map[0] = Some(0);
        vport_map[5] = Some(1);

        assert_eq!(
            selected_data_target(kiss::CMD_DATA, Some(5), &vport_map),
            Some(1)
        );
        assert_eq!(
            selected_data_target(kiss::CMD_DATA, Some(0), &vport_map),
            Some(0)
        );
        assert_eq!(
            selected_data_target(kiss::CMD_DATA, Some(4), &vport_map),
            None
        );
        assert_eq!(selected_data_target(CMD_ERROR, Some(5), &vport_map), None);
        assert_eq!(selected_data_target(0xA0, Some(5), &vport_map), None);
    }

    #[test]
    fn startup_discovery_validates_firmware_interface_types_and_ranges() {
        let mut config = RNodeMultiConfig::new("multi0", "/dev/null");
        config
            .subinterfaces
            .push(SubInterfaceConfig::new("low", 0, 868_000_000));
        config
            .subinterfaces
            .push(SubInterfaceConfig::new("high", 3, 2_400_000_000));

        let mut state = StartupEvidence::default();
        state
            .apply_frame(rnode::CMD_DETECT, &[rnode::DETECT_RESP])
            .unwrap();
        // Lexicographic comparison accepts newer major versions.
        state.apply_frame(rnode::CMD_FW_VERSION, &[2, 0]).unwrap();
        state
            .apply_frame(
                CMD_INTERFACES,
                &[0, RadioType::SX1276 as u8, 3, RadioType::SX1280 as u8],
            )
            .unwrap();

        assert!(state.discovery_complete(&config));
        assert!(state.validate_discovery(&config).is_ok());

        config.subinterfaces[1].frequency = 915_000_000;
        assert!(state.validate_discovery(&config).is_err());
    }

    #[test]
    fn startup_discovery_rejects_malformed_or_unknown_interfaces() {
        let mut state = StartupEvidence::default();
        assert!(state.apply_frame(CMD_INTERFACES, &[0]).is_err());
        assert!(state.apply_frame(CMD_INTERFACES, &[0, 0xFF]).is_err());
        assert!(
            state
                .apply_frame(CMD_INTERFACES, &[MAX_SUBINTERFACES as u8, 0x00])
                .is_err()
        );
        assert!(state.apply_frame(CMD_ERROR, &[ERROR_INITRADIO]).is_err());
    }

    #[test]
    fn startup_requires_matching_echoes_before_radio_is_ready() {
        let config = SubInterfaceConfig::new("radio0", 0, 868_000_000);
        let mut state = StartupEvidence::default();
        state.apply_frame(CMD_SEL_INT, &[0]).unwrap();
        state
            .apply_frame(rnode::CMD_FREQUENCY, &config.frequency.to_be_bytes())
            .unwrap();
        state
            .apply_frame(rnode::CMD_BANDWIDTH, &config.bandwidth.to_be_bytes())
            .unwrap();
        state
            .apply_frame(rnode::CMD_SF, &[config.spreading_factor])
            .unwrap();
        state
            .apply_frame(rnode::CMD_CR, &[config.coding_rate])
            .unwrap();
        state
            .apply_frame(rnode::CMD_TXPOWER, &[config.tx_power])
            .unwrap();
        assert!(!state.radio_complete(0));
        state
            .apply_frame(rnode::CMD_RADIO_STATE, &[rnode::RADIO_STATE_ON])
            .unwrap();

        assert!(state.radio_complete(0));
        assert!(state.radios[0].validate(&config).is_ok());

        let mut mismatch = state.radios[0];
        mismatch.coding_rate = Some(config.coding_rate + 1);
        assert!(mismatch.validate(&config).is_err());
    }

    #[tokio::test]
    async fn duplicate_vports_are_rejected_before_opening_serial() {
        let mut config = RNodeMultiConfig::new("multi0", "/does/not/exist");
        config
            .subinterfaces
            .push(SubInterfaceConfig::new("first", 0, 868_000_000));
        config
            .subinterfaces
            .push(SubInterfaceConfig::new("second", 0, 915_000_000));
        let (transport_tx, _transport_rx) = mpsc::channel(1);
        let result = spawn_rnode_multi_interface(config, &[1, 2], transport_tx).await;
        let error = match result {
            Ok(_) => panic!("duplicate vports must fail before serial open"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("configured more than once"));
    }
}
