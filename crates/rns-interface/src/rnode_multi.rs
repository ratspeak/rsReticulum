//! Multi-radio RNode: up to 11 sub-interfaces on one serial connection.
//! One read task demuxes canonical `CMD_DATA` frames by the most recently
//! selected virtual port; one write task prepends `CMD_SEL_INT` so the device
//! picks the right radio.

use rns_transport::messages::{InterfacePacketCapacity, InterfaceTransportSender};
use std::collections::HashSet;
use std::io::Write;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
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
    /// dBm, -9..=37; sent as a signed byte like Python `setTXPower`.
    pub tx_power: i8,
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
            flow_control: false,
            outgoing: true,
            st_alock: None,
            lt_alock: None,
        }
    }

    pub fn validate(&self) -> Result<(), String> {
        if !(-9..=37).contains(&self.tx_power) {
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
        if let Some(st) = self.st_alock
            && !(0.0..=100.0).contains(&st)
        {
            return Err(format!(
                "Invalid short-term airtime limit {} for sub-interface {}",
                st, self.name
            ));
        }
        if let Some(lt) = self.lt_alock
            && !(0.0..=100.0).contains(&lt)
        {
            return Err(format!(
                "Invalid long-term airtime limit {} for sub-interface {}",
                lt, self.name
            ));
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
    /// Interface mode of the parent; Python gives every subinterface this mode.
    pub mode: InterfaceMode,
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
            mode: InterfaceMode::Full,
            subinterfaces: Vec::new(),
            id_interval: None,
            id_callsign: None,
        }
    }
}

/// Select a subinterface, send its radio parameters and configured airtime
/// locks, then turn the radio on. Frequency, bandwidth and transmit power are
/// reasserted after radio-on.
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
    kiss::frame_with_command_into(rnode::CMD_TXPOWER, &[config.tx_power as u8], &mut out);
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
    kiss::frame_with_command_into(rnode::CMD_TXPOWER, &[config.tx_power as u8], &mut out);

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
    tx_power: Option<i8>,
    radio_state: Option<u8>,
    /// A TX power echo arrived while the radio was on, so the evidence holds
    /// the effective values.
    effective: bool,
}

impl RadioEvidence {
    fn complete(self) -> bool {
        self.frequency.is_some()
            && self.bandwidth.is_some()
            && self.spreading_factor.is_some()
            && self.coding_rate.is_some()
            && self.tx_power.is_some()
            && self.radio_state.is_some()
            && self.effective
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
    platform: Option<u8>,
    firmware: Option<(u8, u8)>,
    interfaces: [Option<RadioType>; MAX_SUBINTERFACES],
    selected_vport: Option<u8>,
    radios: [RadioEvidence; MAX_SUBINTERFACES],
}

impl Default for StartupEvidence {
    fn default() -> Self {
        Self {
            detected: false,
            platform: None,
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
                for pair in payload.as_chunks::<2>().0 {
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
                let value = one_byte(payload, "TX power")? as i8;
                if let Some(radio) = self.selected_radio_mut() {
                    radio.tx_power = Some(value);
                    radio.effective |= radio.radio_state == Some(rnode::RADIO_STATE_ON);
                }
            }
            rnode::CMD_RADIO_STATE => {
                let value = one_byte(payload, "radio state")?;
                if let Some(radio) = self.selected_radio_mut() {
                    radio.radio_state = Some(value);
                    radio.effective &= value == rnode::RADIO_STATE_ON;
                }
            }
            rnode::CMD_PLATFORM => {
                self.platform = Some(one_byte(payload, "platform")?);
            }
            // 0x90 (CMD_ERROR) is also CMD_INT5_DATA; Python decodes it as data,
            // and ignores a reset before the device is online.
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
) -> Result<StartedDevice, StartupFailure> {
    use StartupFailure::{Fatal, Retry};
    std::thread::sleep(RNODE_OPEN_SETTLE);
    let mut deframer = kiss::RawKissDeframer::new();
    let mut evidence = StartupEvidence::default();

    port.write_all(&build_detect_sequence())
        .and_then(|()| port.flush())
        .map_err(|error| Retry(format!("RNodeMulti detect write failed: {error}")))?;
    let discovered = read_startup_until(
        port.as_mut(),
        &mut deframer,
        &mut evidence,
        Instant::now() + RNODE_DISCOVERY_DEADLINE,
        |state| state.discovery_complete(config),
    );
    if let Some((major, minor)) = evidence.firmware
        && (major, minor) < (REQUIRED_FW_VER_MAJ, REQUIRED_FW_VER_MIN)
    {
        return Err(Fatal(format!(
            "RNodeMulti firmware {major}.{minor} is below required {}.{}",
            REQUIRED_FW_VER_MAJ, REQUIRED_FW_VER_MIN
        )));
    }
    discovered.map_err(Retry)?;
    evidence.validate_discovery(config).map_err(Retry)?;

    let mut configured = Vec::with_capacity(config.subinterfaces.len());
    for sub in &config.subinterfaces {
        // Python RNodeSubInterface.configure_device sleeps 2 s before initRadio.
        std::thread::sleep(RNODE_SUBINTERFACE_SETTLE);
        evidence.reset_radio(sub.vport);
        port.write_all(&build_subinterface_init(sub.vport, sub))
            .and_then(|()| port.flush())
            .map_err(|error| {
                Retry(format!(
                    "RNodeMulti {} init write failed: {error}",
                    sub.name
                ))
            })?;
        let validated = read_startup_until(
            port.as_mut(),
            &mut deframer,
            &mut evidence,
            Instant::now() + RNODE_CONFIGURATION_DEADLINE,
            |state| state.radio_complete(sub.vport),
        )
        .and_then(|()| evidence.radios[sub.vport as usize].validate(sub));
        // A mismatching radio stays offline; the others still come up.
        if let Err(error) = &validated {
            tracing::error!(
                name = %sub.name,
                error = %error,
                "RNodeMulti subinterface radio parameters did not match, aborting its startup"
            );
        }
        configured.push(validated.is_ok());
        std::thread::sleep(RNODE_SUBINTERFACE_READY_SETTLE);
    }

    Ok(StartedDevice {
        port,
        platform: evidence.platform,
        configured,
    })
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

/// Python keeps `r_stat_rssi/snr/q` on each subinterface across packets.
#[derive(Default)]
struct SubInterfaceSignal {
    last_rssi: Option<f32>,
    last_snr: Option<f32>,
    last_q: Option<f32>,
}

struct WriteRequest {
    /// Index into the configured subinterfaces.
    local: usize,
    /// Raw payload, not yet KISS-escaped.
    data: Bytes,
}

const RNODE_READ_TIMEOUT_MS: u64 = 100;
const RNODE_WRITER_POLL: Duration = Duration::from_millis(100);

/// Device state reachable from teardown, which may run outside the driver task.
struct DeviceShared {
    detached: AtomicBool,
    detach_port: Mutex<Option<Box<dyn serialport::SerialPort>>>,
    platform: Mutex<Option<u8>>,
    spawned_vports: Mutex<Vec<u8>>,
}

impl DeviceShared {
    /// Python `RNodeMultiInterface.detach()`; runs at most once.
    fn detach(&self) {
        if self.detached.swap(true, Ordering::SeqCst) {
            return;
        }
        let port = self.detach_port.lock().unwrap().take();
        if let Some(mut port) = port {
            let bytes = build_multi_detach_sequence(
                *self.platform.lock().unwrap(),
                &self.spawned_vports.lock().unwrap(),
            );
            let _ = port.write_all(&bytes);
            let _ = port.flush();
        }
    }
}

/// Upstream `detach()`: framebuffer off on display platforms, radio off for
/// each spawned subinterface, then leave host-controlled mode.
pub fn build_multi_detach_sequence(platform: Option<u8>, vports: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + vports.len() * 8);
    if matches!(
        platform,
        Some(rnode::PLATFORM_ESP32 | rnode::PLATFORM_NRF52)
    ) {
        kiss::frame_with_command_into(rnode::CMD_FB_EXT, &[0x00], &mut out);
    }
    for &vport in vports {
        kiss::frame_with_command_into(CMD_SEL_INT, &[vport], &mut out);
        kiss::frame_with_command_into(rnode::CMD_RADIO_STATE, &[rnode::RADIO_STATE_OFF], &mut out);
    }
    kiss::frame_with_command_into(rnode::CMD_LEAVE, &[0xFF], &mut out);
    out
}

/// Marks a handle retired when the registry aborts or drops its task.
struct RetireOnDrop {
    retired: Arc<AtomicBool>,
    detach: Option<Arc<DeviceShared>>,
}

impl Drop for RetireOnDrop {
    fn drop(&mut self) {
        self.retired.store(true, Ordering::SeqCst);
        if let Some(device) = &self.detach {
            device.detach();
        }
    }
}

fn spawn_retire_watch(
    retired: Arc<AtomicBool>,
    detach: Option<Arc<DeviceShared>>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let _guard = RetireOnDrop { retired, detach };
        std::future::pending::<()>().await
    })
}

struct SubRuntime {
    id: InterfaceId,
    vport: u8,
    spreading_factor: u8,
    flow_control: bool,
    online: Arc<AtomicBool>,
    retired: Arc<AtomicBool>,
    rxb: Arc<AtomicU64>,
    txb: Arc<AtomicU64>,
    transport: InterfaceTransportSender,
}

enum ReaderEvent {
    Ready,
    Failed(String),
}

enum StartupFailure {
    /// Python panics here; only this interface stops.
    Fatal(String),
    Retry(String),
}

struct StartedDevice {
    port: Box<dyn serialport::SerialPort>,
    platform: Option<u8>,
    /// Per configured subinterface: radio validated after configuration.
    configured: Vec<bool>,
}

fn open_rnode_multi_port(
    config: &RNodeMultiConfig,
) -> Result<Box<dyn serialport::SerialPort>, String> {
    crate::serial::open_port(
        serialport::new(&config.port, config.baud_rate)
            .timeout(Duration::from_millis(RNODE_READ_TIMEOUT_MS)),
    )
    .map_err(|e| format!("RNodeMulti open: {e}"))
}

async fn start_rnode_multi_generation(
    config: &RNodeMultiConfig,
) -> Result<StartedDevice, StartupFailure> {
    let port = open_rnode_multi_port(config).map_err(StartupFailure::Retry)?;
    let startup_config = config.clone();
    tokio::task::spawn_blocking(move || initialise_rnode_multi(port, &startup_config))
        .await
        .map_err(|error| StartupFailure::Retry(format!("startup worker failed: {error}")))?
}

/// Spawn one RNodeMulti over a single serial port.
///
/// Returns the parent handle first, then one handle per configured
/// subinterface, matching `ids` (`config.subinterfaces.len() + 1` IDs, parent
/// first). The parent never carries traffic, like Python's parent interface;
/// it reports the spawned subinterface count as `clients`. A failed device
/// is retried every `RECONNECT_WAIT` seconds, toggling the subinterfaces'
/// online flags. Tearing down the parent sends the detach sequence.
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
    if ids.len() != config.subinterfaces.len() + 1 {
        return Err(InterfaceError::SendFailed(format!(
            "RNodeMulti: {} IDs provided but {} sub-interfaces plus the parent configured",
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

    // Like Python's start(), the first attempt runs inline; a device that is
    // missing or fails to start is retried periodically.
    let initial = match start_rnode_multi_generation(&config).await {
        Ok(started) => Some(started),
        Err(StartupFailure::Fatal(error)) => {
            return Err(InterfaceError::SendFailed(format!(
                "RNodeMulti startup: {error}"
            )));
        }
        Err(StartupFailure::Retry(error)) => {
            tracing::warn!(
                name = %config.name,
                error = %error,
                "RNodeMulti startup failed, retrying periodically"
            );
            None
        }
    };

    let parent_id = ids[0];
    let parent_transport = InterfaceTransportSender::new(parent_id, transport_tx.clone());
    let parent_online = Arc::new(AtomicBool::new(false));
    let parent_retired = Arc::new(AtomicBool::new(false));
    let parent_txb = Arc::new(AtomicU64::new(0));
    let spawned_count = Arc::new(AtomicU64::new(0));
    let device = Arc::new(DeviceShared {
        detached: AtomicBool::new(false),
        detach_port: Mutex::new(None),
        platform: Mutex::new(None),
        spawned_vports: Mutex::new(Vec::new()),
    });

    let (write_tx, write_rx) = mpsc::channel::<WriteRequest>(256);
    let mut subs = Vec::with_capacity(config.subinterfaces.len());
    let mut lanes = Vec::with_capacity(config.subinterfaces.len());
    let mut handles = Vec::with_capacity(config.subinterfaces.len() + 1);

    for (local, sub_cfg) in config.subinterfaces.iter().enumerate() {
        let id = ids[local + 1];
        let bitrate = rnode::calculate_bitrate(
            sub_cfg.spreading_factor,
            sub_cfg.coding_rate,
            sub_cfg.bandwidth,
        );
        let online = Arc::new(AtomicBool::new(false));
        let retired = Arc::new(AtomicBool::new(false));
        let rxb = Arc::new(AtomicU64::new(0));
        let txb = Arc::new(AtomicU64::new(0));
        let transport = InterfaceTransportSender::new(id, transport_tx.clone());

        let (sub_tx, mut sub_rx) = mpsc::channel::<Bytes>(256);
        lanes.push(crate::background_announce::register(&sub_tx)?);
        let write_tx_clone = write_tx.clone();
        tokio::spawn(async move {
            while let Some(data) = sub_rx.recv().await {
                if write_tx_clone
                    .send(WriteRequest { local, data })
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
            vport = sub_cfg.vport,
            freq = sub_cfg.frequency,
            bw = sub_cfg.bandwidth,
            sf = sub_cfg.spreading_factor,
            cr = sub_cfg.coding_rate,
            bitrate_bps = bitrate,
            "RNodeMulti sub-interface configured"
        );

        handles.push(InterfaceHandle {
            id,
            owner: transport.owner(),
            packet_capacity: InterfacePacketCapacity::new(500, 508, false),
            parent_id: Some(ids[0]),
            name: sub_name,
            mode: config.mode,
            direction: InterfaceDirection {
                inbound: true,
                outbound: sub_cfg.outgoing,
                forward: false,
                repeat: false,
            },
            bitrate,
            mtu: RNODE_HW_MTU,
            online: online.clone(),
            rxb: Some(rxb.clone()),
            txb: Some(txb.clone()),
            inspection: None,
            tx: sub_tx,
            read_task: spawn_retire_watch(retired.clone(), None),
        });
        subs.push(SubRuntime {
            id,
            vport: sub_cfg.vport,
            spreading_factor: sub_cfg.spreading_factor,
            flow_control: sub_cfg.flow_control,
            online,
            retired,
            rxb,
            txb,
            transport,
        });
    }
    drop(write_tx);

    // Python's parent is registered with Transport but never transmits.
    let (parent_tx, mut parent_rx) = mpsc::channel::<Bytes>(16);
    tokio::spawn(async move { while parent_rx.recv().await.is_some() {} });
    let clients = spawned_count.clone();
    let parent = InterfaceHandle {
        id: parent_id,
        owner: parent_transport.owner(),
        packet_capacity: InterfacePacketCapacity::new(500, 508, false),
        parent_id: None,
        name: config.name.clone(),
        mode: config.mode,
        direction: InterfaceDirection {
            inbound: false,
            outbound: false,
            forward: false,
            repeat: false,
        },
        bitrate: 0,
        mtu: RNODE_HW_MTU,
        online: parent_online.clone(),
        rxb: Some(Arc::new(AtomicU64::new(0))),
        txb: Some(parent_txb.clone()),
        inspection: Some(rns_transport::messages::InterfaceInspectionSource::new(
            move || rns_transport::messages::InterfaceInspectionSnapshot {
                active_clients: Some(clients.load(Ordering::SeqCst)),
                blocked_ips: None,
            },
        )),
        tx: parent_tx,
        read_task: spawn_retire_watch(parent_retired.clone(), Some(device.clone())),
    };
    handles.insert(0, parent);

    // Python RNodeMultiInterface.py:281-291 — oversized callsigns disable beaconing.
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

    let driver = MultiDriver {
        config,
        device,
        parent_online,
        parent_retired,
        parent_txb,
        spawned_count,
        subs: Arc::new(subs),
        lanes,
        beacon,
        write_rx,
        ready: [false; MAX_SUBINTERFACES],
        queues: Default::default(),
        first_tx: None,
    };
    tokio::spawn(driver.run(initial));

    Ok(handles)
}

struct MultiDriver {
    config: RNodeMultiConfig,
    device: Arc<DeviceShared>,
    parent_online: Arc<AtomicBool>,
    parent_retired: Arc<AtomicBool>,
    parent_txb: Arc<AtomicU64>,
    spawned_count: Arc<AtomicU64>,
    subs: Arc<Vec<SubRuntime>>,
    lanes: Vec<crate::background_announce::BackgroundAnnounceReceiver>,
    beacon: Option<(Duration, Bytes)>,
    write_rx: mpsc::Receiver<WriteRequest>,
    /// Python per-subinterface `interface_ready` and `packet_queue`.
    ready: [bool; MAX_SUBINTERFACES],
    queues: [std::collections::VecDeque<Bytes>; MAX_SUBINTERFACES],
    first_tx: Option<tokio::time::Instant>,
}

enum GenerationEnd {
    Failed,
    Teardown,
}

impl MultiDriver {
    fn teardown_requested(&self) -> bool {
        self.device.detached.load(Ordering::SeqCst)
            || self.parent_retired.load(Ordering::SeqCst)
            || self
                .subs
                .iter()
                .all(|sub| sub.retired.load(Ordering::SeqCst))
    }

    async fn run(mut self, mut next: Option<StartedDevice>) {
        loop {
            let started = match next.take() {
                Some(started) => started,
                None => {
                    if self
                        .idle_wait(Duration::from_secs(rnode::RECONNECT_WAIT))
                        .await
                    {
                        break;
                    }
                    tracing::info!(name = %self.config.name, "attempting to reconnect RNodeMulti");
                    match start_rnode_multi_generation(&self.config).await {
                        Ok(started) => started,
                        Err(StartupFailure::Fatal(error)) => {
                            tracing::error!(name = %self.config.name, error = %error, "RNodeMulti stopped");
                            break;
                        }
                        Err(StartupFailure::Retry(error)) => {
                            tracing::warn!(name = %self.config.name, error = %error, "RNodeMulti reconnect failed");
                            continue;
                        }
                    }
                }
            };
            match self.run_generation(started).await {
                GenerationEnd::Teardown => break,
                GenerationEnd::Failed => {
                    tracing::error!(
                        name = %self.config.name,
                        "RNodeMulti is offline, reconnecting periodically"
                    );
                }
            }
        }
        self.device.detach();
        self.end_generation();
    }

    /// Wait while offline; writes are dropped like Python's offline subinterfaces.
    async fn idle_wait(&mut self, duration: Duration) -> bool {
        let deadline = tokio::time::Instant::now() + duration;
        loop {
            if self.teardown_requested() {
                return true;
            }
            tokio::select! {
                request = self.write_rx.recv() => {
                    if request.is_none() {
                        return true;
                    }
                }
                _ = tokio::time::sleep_until(deadline) => return false,
                _ = tokio::time::sleep(RNODE_WRITER_POLL) => {}
            }
        }
    }

    fn end_generation(&mut self) {
        for sub in self.subs.iter() {
            sub.online.store(false, Ordering::SeqCst);
        }
        self.parent_online.store(false, Ordering::SeqCst);
        self.spawned_count.store(0, Ordering::SeqCst);
        self.device.spawned_vports.lock().unwrap().clear();
        self.device.detach_port.lock().unwrap().take();
    }

    async fn run_generation(&mut self, started: StartedDevice) -> GenerationEnd {
        let StartedDevice {
            port,
            platform,
            configured,
        } = started;
        let (Ok(write_port), Ok(detach_port)) = (port.try_clone(), port.try_clone()) else {
            return GenerationEnd::Failed;
        };
        *self.device.platform.lock().unwrap() = platform;
        *self.device.detach_port.lock().unwrap() = Some(detach_port);
        *self.device.spawned_vports.lock().unwrap() =
            self.subs.iter().map(|sub| sub.vport).collect();
        self.spawned_count
            .store(self.subs.len() as u64, Ordering::SeqCst);
        for (local, sub) in self.subs.iter().enumerate() {
            let up = configured[local] && !sub.retired.load(Ordering::SeqCst);
            self.ready[local] = configured[local];
            self.queues[local].clear();
            sub.online.store(up, Ordering::SeqCst);
        }
        self.parent_online.store(true, Ordering::SeqCst);

        let stop = Arc::new(AtomicBool::new(false));
        let (event_tx, mut events) = mpsc::unbounded_channel();
        let reader = tokio::spawn(read_rnode_multi(
            port,
            self.subs.clone(),
            self.device.clone(),
            self.parent_online.clone(),
            stop.clone(),
            event_tx,
            self.config.name.clone(),
        ));
        let mut port_w = Some(write_port);

        let end = loop {
            if self.teardown_requested() {
                break GenerationEnd::Teardown;
            }
            if self.write_background(&mut port_w).await.is_err() {
                break GenerationEnd::Failed;
            }
            let result = tokio::select! {
                biased;
                event = events.recv() => match event {
                    Some(ReaderEvent::Ready) => self.process_queues(&mut port_w).await,
                    Some(ReaderEvent::Failed(reason)) => {
                        tracing::error!(name = %self.config.name, reason = %reason, "RNodeMulti device error");
                        Err(())
                    }
                    None => Err(()),
                },
                request = self.write_rx.recv() => match request {
                    Some(request) => self.submit(&mut port_w, request.local, request.data).await,
                    None => break GenerationEnd::Teardown,
                },
                _ = tokio::time::sleep(RNODE_WRITER_POLL) => self.beacon_tick(&mut port_w).await,
            };
            if result.is_err() {
                break GenerationEnd::Failed;
            }
        };

        if matches!(end, GenerationEnd::Teardown) {
            drop(port_w);
            self.device.detach();
        }
        stop.store(true, Ordering::SeqCst);
        let _ = reader.await;
        self.end_generation();
        end
    }

    /// Python `RNodeSubInterface.process_outgoing` for one subinterface.
    async fn submit(
        &mut self,
        port: &mut Option<Box<dyn serialport::SerialPort>>,
        local: usize,
        data: Bytes,
    ) -> Result<(), ()> {
        let sub = &self.subs[local];
        if !sub.online.load(Ordering::SeqCst) {
            return Ok(());
        }
        if sub.flow_control {
            if !self.ready[local] {
                self.queues[local].push_back(data);
                return Ok(());
            }
            self.ready[local] = false;
        }
        self.write(port, local, data).await
    }

    async fn write(
        &mut self,
        port: &mut Option<Box<dyn serialport::SerialPort>>,
        local: usize,
        data: Bytes,
    ) -> Result<(), ()> {
        if let Some((_, callsign)) = &self.beacon {
            if data == *callsign {
                self.first_tx = None;
            } else if self.first_tx.is_none() {
                self.first_tx = Some(tokio::time::Instant::now());
            }
        }
        let sub = &self.subs[local];
        sub.txb.fetch_add(data.len() as u64, Ordering::Relaxed);
        self.parent_txb
            .fetch_add(data.len() as u64, Ordering::Relaxed);
        let frame = build_subinterface_data_frame(sub.vport, &data);
        let Some(current) = port.take() else {
            return Err(());
        };
        match crate::serial_io::blocking_write_all(current, frame).await {
            Ok(p) => {
                *port = Some(p);
                Ok(())
            }
            Err(e) => {
                tracing::warn!(error = %e, "RNodeMulti write error");
                Err(())
            }
        }
    }

    /// Python `process_queue`: any READY lets every subinterface send one
    /// queued packet or become ready.
    async fn process_queues(
        &mut self,
        port: &mut Option<Box<dyn serialport::SerialPort>>,
    ) -> Result<(), ()> {
        for local in 0..self.subs.len() {
            self.ready[local] = true;
            if let Some(data) = self.queues[local].pop_front() {
                self.submit(port, local, data).await?;
            }
        }
        Ok(())
    }

    async fn write_background(
        &mut self,
        port: &mut Option<Box<dyn serialport::SerialPort>>,
    ) -> Result<(), ()> {
        if !self.write_rx.is_empty() {
            return Ok(());
        }
        for local in 0..self.subs.len() {
            let sub = &self.subs[local];
            if !sub.online.load(Ordering::SeqCst) || !self.queues[local].is_empty() {
                continue;
            }
            let lane = &self.lanes[local];
            if !lane.ordinary_is_empty() {
                continue;
            }
            let flow_control = sub.flow_control;
            let ready = &mut self.ready[local];
            let Some(packet) = lane.try_start_when(rns_transport::now_f64(), || {
                if !flow_control {
                    return true;
                }
                std::mem::replace(ready, false)
            }) else {
                continue;
            };
            let data = packet.raw().clone();
            let result = self.write(port, local, data).await;
            drop(packet);
            result?;
        }
        Ok(())
    }

    async fn beacon_tick(
        &mut self,
        port: &mut Option<Box<dyn serialport::SerialPort>>,
    ) -> Result<(), ()> {
        let Some((interval, callsign)) = self.beacon.clone() else {
            return Ok(());
        };
        if self.first_tx.is_none_or(|t| t.elapsed() < interval) {
            return Ok(());
        }
        tracing::debug!("RNodeMulti transmitting station-ID beacon on all subinterfaces");
        self.first_tx = None;
        for local in 0..self.subs.len() {
            if self.subs[local].online.load(Ordering::SeqCst) {
                self.submit(port, local, callsign.clone()).await?;
            }
        }
        Ok(())
    }
}

async fn read_rnode_multi(
    port: Box<dyn serialport::SerialPort>,
    subs: Arc<Vec<SubRuntime>>,
    device: Arc<DeviceShared>,
    parent_online: Arc<AtomicBool>,
    stop: Arc<AtomicBool>,
    events: mpsc::UnboundedSender<ReaderEvent>,
    parent_name: String,
) {
    let mut vport_map: [Option<usize>; MAX_SUBINTERFACES] = [None; MAX_SUBINTERFACES];
    for (local, sub) in subs.iter().enumerate() {
        vport_map[sub.vport as usize] = Some(local);
    }
    let mut signals: Vec<SubInterfaceSignal> = (0..subs.len())
        .map(|_| SubInterfaceSignal::default())
        .collect();
    let mut port_r = port;
    let mut deframer = kiss::RawKissDeframer::new();
    let mut buf = [0u8; 1024];
    let mut selected_vport: Option<u8> = Some(0);
    let selected_local = |selected: Option<u8>| {
        selected.and_then(|vport| vport_map.get(vport as usize).copied().flatten())
    };

    while !stop.load(Ordering::SeqCst) {
        let (p, b, n) = match crate::serial_io::poll_read(port_r, buf).await {
            Ok(read) => read,
            Err(e) => {
                let _ = events.send(ReaderEvent::Failed(format!("read error: {e}")));
                return;
            }
        };
        port_r = p;
        buf = b;
        for (command, frame) in deframer.feed(&buf[..n]) {
            match command {
                kiss::CMD_DATA => {
                    if frame.is_empty() {
                        continue;
                    }
                    let Some(local) = selected_data_target(command, selected_vport, &vport_map)
                    else {
                        tracing::debug!(
                            parent = %parent_name,
                            vport = ?selected_vport,
                            "data for unconfigured sub-interface, dropping"
                        );
                        continue;
                    };
                    let sub = &subs[local];
                    sub.rxb.fetch_add(frame.len() as u64, Ordering::Relaxed);
                    let msg = TransportMessage::Inbound(InboundPacket {
                        raw: Bytes::from(frame),
                        interface_id: sub.id,
                        rssi: signals[local].last_rssi,
                        snr: signals[local].last_snr,
                        q: signals[local].last_q,
                    });
                    if sub.transport.send(msg).await.is_err() {
                        let _ = events.send(ReaderEvent::Failed("transport channel closed".into()));
                        return;
                    }
                }
                CMD_SEL_INT => {
                    if let Some(&index) = frame.first() {
                        selected_vport = ((index as usize) < MAX_SUBINTERFACES).then_some(index);
                    }
                }
                rnode::CMD_STAT_RSSI => {
                    if let (Some(&byte), Some(local)) =
                        (frame.first(), selected_local(selected_vport))
                    {
                        signals[local].last_rssi = Some(rnode::decode_rssi_byte(byte));
                    }
                }
                rnode::CMD_STAT_SNR => {
                    if let (Some(&byte), Some(local)) =
                        (frame.first(), selected_local(selected_vport))
                    {
                        let snr = rnode::decode_snr_byte(byte);
                        signals[local].last_snr = Some(snr);
                        signals[local].last_q =
                            Some(rnode::signal_quality(snr, subs[local].spreading_factor));
                    }
                }
                rnode::CMD_READY => {
                    let _ = events.send(ReaderEvent::Ready);
                }
                rnode::CMD_PLATFORM => {
                    if let Some(&platform) = frame.first() {
                        *device.platform.lock().unwrap() = Some(platform);
                    }
                }
                rnode::CMD_RESET => {
                    // Python acts on a reset only from an online ESP32.
                    if frame.first() == Some(&0xF8)
                        && *device.platform.lock().unwrap() == Some(rnode::PLATFORM_ESP32)
                        && parent_online.load(Ordering::SeqCst)
                    {
                        let _ = events.send(ReaderEvent::Failed("ESP32 reset".into()));
                        return;
                    }
                }
                // 0x90 is CMD_INT5_DATA as well as CMD_ERROR; Python's read loop
                // takes the data branch first, so these frames are dropped.
                _ => {
                    tracing::debug!(
                        parent = %parent_name,
                        cmd = format!("0x{:02X}", command),
                        "RNodeMulti: ignoring KISS command"
                    );
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rnode_multi_config() {
        let mut cfg = RNodeMultiConfig::new("multi0", "/dev/ttyACM0");
        assert_eq!(cfg.baud_rate, 115200);
        assert_eq!(cfg.mode, InterfaceMode::Full);
        assert!(cfg.subinterfaces.is_empty());

        cfg.subinterfaces
            .push(SubInterfaceConfig::new("radio0", 0, 868_000_000));
        cfg.subinterfaces
            .push(SubInterfaceConfig::new("radio1", 1, 915_000_000));
        assert_eq!(cfg.subinterfaces.len(), 2);
        assert!(cfg.subinterfaces.iter().all(|sub| sub.outgoing));
        assert!(cfg.subinterfaces.iter().all(|sub| !sub.flow_control));
    }

    #[test]
    fn detach_sequence_follows_upstream_order() {
        let mut expected = Vec::new();
        kiss::frame_with_command_into(rnode::CMD_FB_EXT, &[0x00], &mut expected);
        for vport in [0u8, 2] {
            kiss::frame_with_command_into(CMD_SEL_INT, &[vport], &mut expected);
            kiss::frame_with_command_into(rnode::CMD_RADIO_STATE, &[0x00], &mut expected);
        }
        kiss::frame_with_command_into(rnode::CMD_LEAVE, &[0xFF], &mut expected);
        assert_eq!(
            build_multi_detach_sequence(Some(rnode::PLATFORM_ESP32), &[0, 2]),
            expected
        );
        assert_eq!(
            build_multi_detach_sequence(Some(rnode::PLATFORM_AVR), &[0, 2]),
            expected[4..]
        );
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
        // sel_int + freq + bw + sf + cr + txpower + radio_state + freq + bw + txpower
        assert_eq!(frames.len(), 10);
    }

    #[test]
    fn test_subinterface_init_with_airtime() {
        let mut sub_cfg = SubInterfaceConfig::new("radio0", 0, 868_000_000);
        sub_cfg.st_alock = Some(15.0);
        sub_cfg.lt_alock = Some(25.0);

        let seq = build_subinterface_init(0, &sub_cfg);
        let mut deframer = kiss::KissDeframer::new();
        let frames = deframer.feed(&seq);
        // 10 base + 2 airtime limits
        assert_eq!(frames.len(), 12);
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
        // 0x90 doubles as CMD_INT5_DATA, which Python's read loop decodes first.
        assert!(state.apply_frame(CMD_ERROR, &[ERROR_INITRADIO]).is_ok());
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
            .apply_frame(rnode::CMD_TXPOWER, &[config.tx_power as u8])
            .unwrap();
        assert!(!state.radio_complete(0));
        state
            .apply_frame(rnode::CMD_RADIO_STATE, &[rnode::RADIO_STATE_ON])
            .unwrap();
        // Pre-RADIO_ON echoes are the request, not what the radio will use.
        assert!(!state.radio_complete(0));
        state
            .apply_frame(rnode::CMD_TXPOWER, &[config.tx_power as u8])
            .unwrap();

        assert!(state.radio_complete(0));
        assert!(state.radios[0].validate(&config).is_ok());

        // An amplifier floor reported once on is a mismatch.
        state
            .apply_frame(rnode::CMD_TXPOWER, &[(config.tx_power + 3) as u8])
            .unwrap();
        assert!(state.radios[0].validate(&config).is_err());

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
        let result = spawn_rnode_multi_interface(config, &[1, 2, 3], transport_tx).await;
        let error = match result {
            Ok(_) => panic!("duplicate vports must fail before serial open"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("configured more than once"));
    }
}
