//! Mirrors `Reticulum._synthesize_interface` in the Python reference but
//! rejects external-program interfaces.

use crate::config::ConfigSection;
use rns_interface::tcp::{TcpClientConfig, TcpServerConfig};
use rns_interface::traits::InterfaceMode;
use rns_interface::udp::UdpInterfaceConfig;
use thiserror::Error;
use tracing::{debug, warn};

#[derive(Debug, Error)]
pub enum InterfaceFactoryError {
    #[error("unknown interface type: {0}")]
    UnknownType(String),
    #[error("missing required field '{field}' for interface '{name}'")]
    MissingField { name: String, field: String },
    #[error("invalid value for '{field}': {message}")]
    InvalidValue { field: String, message: String },
    #[error("interface disabled: {0}")]
    Disabled(String),
}

#[derive(Debug, Clone)]
pub enum InterfaceConfig {
    TcpClient(TcpClientConfig),
    TcpServer(TcpServerConfig),
    Udp(UdpInterfaceConfig),
    #[cfg(feature = "serial")]
    Serial(SerialInterfaceConfig),
    #[cfg(feature = "serial")]
    KissSerial(KissSerialConfig),
    Auto(AutoInterfaceConfig),
    #[cfg(any(feature = "serial", feature = "rnode-tcp"))]
    RNode(RNodeInterfaceConfig),
    Local(LocalInterfaceConfig),
    I2P(I2PInterfaceConfig),
    Pipe(PipeInterfaceConfig),
    #[cfg(feature = "serial")]
    RNodeMulti(RNodeMultiInterfaceConfig),
    #[cfg(feature = "serial")]
    AX25KISS(AX25KISSInterfaceConfig),
    Backbone(BackboneInterfaceConfig),
    #[cfg(feature = "ble")]
    BleRNode(BleRNodeInterfaceConfig),
}

#[cfg(feature = "serial")]
#[derive(Debug, Clone)]
pub struct SerialInterfaceConfig {
    pub name: String,
    pub port: String,
    pub baud_rate: u32,
    pub data_bits: u8,
    pub parity: String,
    pub stop_bits: u8,
    pub mode: InterfaceMode,
}

#[cfg(feature = "serial")]
#[derive(Debug, Clone)]
pub struct KissSerialConfig {
    pub name: String,
    pub port: String,
    pub baud_rate: u32,
    pub data_bits: u8,
    pub parity: String,
    pub stop_bits: u8,
    pub mode: InterfaceMode,
    /// TNC timing, config units are milliseconds (Python defaults 350/20/64/20;
    /// persistence is a raw 0-255 CSMA p-value, not ms).
    pub preamble_ms: u32,
    pub txtail_ms: u32,
    pub persistence: u8,
    pub slottime_ms: u32,
    pub flow_control: bool,
    /// Station-ID beacon: seconds between IDs, sent only after data TX.
    pub id_interval: Option<u64>,
    pub id_callsign: Option<String>,
}

#[derive(Debug, Clone)]
pub struct AutoInterfaceConfig {
    pub name: String,
    pub group_id: String,
    pub discovery_scope: rns_interface::auto::DiscoveryScope,
    pub discovery_port: u16,
    pub data_port: u16,
    pub multicast_address_type: rns_interface::auto::McastAddrType,
    pub devices: Option<Vec<String>>,
    pub ignored_devices: Vec<String>,
    pub configured_bitrate: Option<u64>,
    pub mode: InterfaceMode,
}

#[cfg(any(feature = "serial", feature = "rnode-tcp"))]
#[derive(Debug, Clone)]
pub struct RNodeInterfaceConfig {
    pub name: String,
    pub port: String,
    pub frequency: u32,
    pub bandwidth: u32,
    pub spreading_factor: u8,
    pub coding_rate: u8,
    pub tx_power: i8,
    pub mode: InterfaceMode,
    /// Gate each TX on the radio's CMD_READY. Python default: off.
    pub flow_control: bool,
    /// Short-term airtime cap, percent (0.0..=100.0). `None` = unlimited.
    pub st_alock: Option<f32>,
    /// Long-term airtime cap, percent (0.0..=100.0). `None` = unlimited.
    pub lt_alock: Option<f32>,
    /// Station-ID beacon: seconds between IDs, sent only after data TX.
    pub id_interval: Option<u64>,
    pub id_callsign: Option<String>,
}

/// LoRa RNode reached over Bluetooth LE.
#[cfg(feature = "ble")]
#[derive(Debug, Clone)]
pub struct BleRNodeInterfaceConfig {
    pub name: String,
    /// `ble://` URI: MAC, adapter-local name, or empty for any RNode.
    pub port: String,
    pub frequency: u32,
    pub bandwidth: u32,
    pub spreading_factor: u8,
    pub coding_rate: u8,
    pub tx_power: i8,
    pub mode: InterfaceMode,
    /// Gate each TX on the radio's CMD_READY. Python default: off.
    pub flow_control: bool,
    /// Short-term airtime cap, percent (0.0..=100.0). `None` = unlimited.
    pub st_alock: Option<f32>,
    /// Long-term airtime cap, percent (0.0..=100.0). `None` = unlimited.
    pub lt_alock: Option<f32>,
    /// Station-ID beacon: seconds between IDs, sent only after data TX.
    pub id_interval: Option<u64>,
    pub id_callsign: Option<String>,
}

#[derive(Debug, Clone)]
pub struct LocalInterfaceConfig {
    pub name: String,
    pub port: u16,
    pub mode: InterfaceMode,
}

/// Requires a local I2P router reachable via the SAM API.
#[derive(Debug, Clone)]
pub struct I2PInterfaceConfig {
    pub name: String,
    pub connectable: bool,
    pub peers: Vec<String>,
    pub i2p_sam_host: String,
    pub i2p_sam_port: u16,
    pub mode: InterfaceMode,
}

/// Subprocess; frames carried over its stdio.
#[derive(Debug, Clone)]
pub struct PipeInterfaceConfig {
    pub name: String,
    pub command: String,
    /// Respawn delay after EOF, seconds.
    pub respawn_delay: u64,
    pub mode: InterfaceMode,
}

/// Multi-transceiver RNode (e.g. OpenCom XL) with per-vport params.
#[cfg(feature = "serial")]
#[derive(Debug, Clone)]
pub struct RNodeMultiInterfaceConfig {
    pub name: String,
    pub port: String,
    pub baud_rate: u32,
    pub flow_control: bool,
    pub subinterfaces: Vec<RNodeSubInterfaceConfig>,
    pub mode: InterfaceMode,
    /// Parent-level station-ID beacon (sent on all subinterfaces when due).
    pub id_interval: Option<u64>,
    pub id_callsign: Option<String>,
}

#[cfg(feature = "serial")]
#[derive(Debug, Clone)]
pub struct RNodeSubInterfaceConfig {
    pub name: String,
    pub frequency: u32,
    pub bandwidth: u32,
    pub spreading_factor: u8,
    pub coding_rate: u8,
    pub tx_power: u8,
    pub vport: u8,
    pub enabled: bool,
    pub flow_control: bool,
    pub outgoing: bool,
    pub st_alock: Option<f32>,
    pub lt_alock: Option<f32>,
    pub mode: InterfaceMode,
}

/// KISS serial wrapped in AX.25 frames for amateur-radio compliance; prefer
/// plain `KISSInterface` when AX.25 isn't required.
#[cfg(feature = "serial")]
#[derive(Debug, Clone)]
pub struct AX25KISSInterfaceConfig {
    pub name: String,
    pub port: String,
    pub baud_rate: u32,
    pub data_bits: u8,
    pub parity: String,
    pub stop_bits: u8,
    pub callsign: String,
    pub ssid: u8,
    pub preamble: u32,
    pub txtail: u32,
    pub persistence: u32,
    pub slottime: u32,
    pub flow_control: bool,
    pub mode: InterfaceMode,
}

/// Wire-compatible with Python `BackboneInterface`. Per-peer TCP keepalive +
/// `TCP_USER_TIMEOUT` tuning matches Python `set_timeouts_linux()`.
#[derive(Debug, Clone)]
pub struct BackboneInterfaceConfig {
    pub name: String,
    pub listen_on: Option<String>,
    pub target_host: Option<String>,
    pub port: u16,
    pub device: Option<String>,
    pub prefer_ipv6: bool,
    pub mode: InterfaceMode,
    /// Initial connect timeout (seconds). Python default: 5.
    pub connect_timeout: u64,
    /// Client reconnection budget. `None` = retry forever (Python default).
    pub max_reconnect_tries: Option<usize>,
    /// Parsed for Python config compatibility; advisory only.
    pub i2p_tunneled: bool,
}

fn parse_interface_mode(s: &str) -> Option<InterfaceMode> {
    match s.to_lowercase().as_str() {
        "full" => Some(InterfaceMode::Full),
        "pointtopoint" | "point_to_point" => Some(InterfaceMode::PointToPoint),
        "access_point" | "accesspoint" | "ap" => Some(InterfaceMode::AccessPoint),
        "roaming" => Some(InterfaceMode::Roaming),
        "boundary" => Some(InterfaceMode::Boundary),
        "gateway" | "gw" => Some(InterfaceMode::Gateway),
        _ => None,
    }
}

pub fn synthesize_interface(
    name: &str,
    section: &ConfigSection,
) -> Result<InterfaceConfig, InterfaceFactoryError> {
    let enabled = section
        .get_bool("enabled")
        .or_else(|| section.get_bool("interface_enabled"))
        .unwrap_or(true);

    if !enabled {
        debug!(interface = %name, "interface disabled in config, skipping");
        return Err(InterfaceFactoryError::Disabled(name.to_string()));
    }

    let iface_type = section.get("type").ok_or_else(|| {
        warn!(interface = %name, "interface missing 'type' field");
        InterfaceFactoryError::MissingField {
            name: name.to_string(),
            field: "type".to_string(),
        }
    })?;

    debug!(interface = %name, kind = iface_type, "synthesizing interface");

    let mode = section
        .get("interface_mode")
        .or_else(|| section.get("mode"))
        .and_then(parse_interface_mode)
        .unwrap_or(InterfaceMode::Full);

    match iface_type {
        "TCPClientInterface" => synthesize_tcp_client(name, section, mode),
        "TCPServerInterface" => synthesize_tcp_server(name, section, mode),
        "UDPInterface" => synthesize_udp(name, section, mode),
        #[cfg(feature = "serial")]
        "SerialInterface" => synthesize_serial(name, section, mode),
        #[cfg(feature = "serial")]
        "KISSInterface" => synthesize_kiss_serial(name, section, mode),
        "AutoInterface" => synthesize_auto(name, section, mode),
        "RNodeInterface" => {
            let port = section
                .get("port")
                .ok_or_else(|| InterfaceFactoryError::MissingField {
                    name: name.to_string(),
                    field: "port".to_string(),
                })?;
            if port.starts_with("ble://") {
                #[cfg(feature = "ble")]
                {
                    return synthesize_ble_rnode(name, section, mode);
                }
                #[cfg(not(feature = "ble"))]
                {
                    return Err(InterfaceFactoryError::Disabled(format!(
                        "RNodeInterface '{name}' has ble:// port but 'ble' feature is not enabled"
                    )));
                }
            }
            // Android USB-OTG ports vanish on replug; add them at runtime after
            // the device is present.
            if port.starts_with("androidusb://") {
                return Err(InterfaceFactoryError::Disabled(format!(
                    "RNodeInterface '{name}' is an Android USB-OTG entry — skipped at startup; re-add from the UI after plugging the device in"
                )));
            }
            #[cfg(any(feature = "serial", feature = "rnode-tcp"))]
            {
                let is_tcp = port
                    .get(.."tcp://".len())
                    .is_some_and(|prefix| prefix.eq_ignore_ascii_case("tcp://"));
                if is_tcp || cfg!(feature = "serial") {
                    synthesize_rnode(name, section, mode)
                } else {
                    Err(InterfaceFactoryError::Disabled(format!(
                        "RNodeInterface '{name}' requires 'serial' feature for non-TCP ports"
                    )))
                }
            }
            #[cfg(not(any(feature = "serial", feature = "rnode-tcp")))]
            {
                Err(InterfaceFactoryError::Disabled(format!(
                    "RNodeInterface '{name}' requires 'serial' or 'rnode-tcp' feature"
                )))
            }
        }
        "LocalInterface" => synthesize_local(name, section, mode),
        "I2PInterface" => synthesize_i2p(name, section, mode),
        "PipeInterface" => synthesize_pipe(name, section, mode),
        #[cfg(feature = "serial")]
        "RNodeMultiInterface" => synthesize_rnode_multi(name, section, mode),
        #[cfg(feature = "serial")]
        "AX25KISSInterface" => synthesize_ax25kiss(name, section, mode),
        "BackboneInterface" => synthesize_backbone(name, section, mode),
        other => Err(InterfaceFactoryError::UnknownType(other.to_string())),
    }
}

fn synthesize_tcp_client(
    name: &str,
    section: &ConfigSection,
    mode: InterfaceMode,
) -> Result<InterfaceConfig, InterfaceFactoryError> {
    let host = section
        .get("target_host")
        .ok_or_else(|| InterfaceFactoryError::MissingField {
            name: name.to_string(),
            field: "target_host".to_string(),
        })?;

    let port =
        section
            .get_uint("target_port")
            .ok_or_else(|| InterfaceFactoryError::MissingField {
                name: name.to_string(),
                field: "target_port".to_string(),
            })? as u16;

    let mut config = TcpClientConfig::new(name, host, port);
    config.mode = mode;

    if let Some(kiss) = section.get_bool("kiss_framing") {
        config.kiss_framing = kiss;
    }
    if let Some(timeout) = section.get_uint("connect_timeout") {
        config.connect_timeout_secs = timeout;
    }
    if let Some(mtu) = section.get_uint("fixed_mtu") {
        // Python TCPInterface.py:112 — fixed MTU below protocol MTU is invalid.
        if (mtu as usize) < rns_wire::constants::MTU {
            return Err(InterfaceFactoryError::InvalidValue {
                field: format!("{name}.fixed_mtu"),
                message: format!("{mtu} is below the protocol MTU of 500"),
            });
        }
        config.fixed_mtu = Some(mtu as u32);
    }
    if let Some(retries) = section.get_uint("max_reconnect_tries") {
        config.max_reconnect_tries = Some(retries as usize);
    }

    Ok(InterfaceConfig::TcpClient(config))
}

fn synthesize_tcp_server(
    name: &str,
    section: &ConfigSection,
    mode: InterfaceMode,
) -> Result<InterfaceConfig, InterfaceFactoryError> {
    let ip = section.get("listen_ip").unwrap_or("0.0.0.0");

    let port =
        section
            .get_uint("listen_port")
            .ok_or_else(|| InterfaceFactoryError::MissingField {
                name: name.to_string(),
                field: "listen_port".to_string(),
            })? as u16;

    let mut config = TcpServerConfig::new(name, ip, port);
    config.mode = mode;

    if let Some(kiss) = section.get_bool("kiss_framing") {
        config.kiss_framing = kiss;
    }
    if let Some(ipv6) = section.get_bool("prefer_ipv6") {
        config.prefer_ipv6 = ipv6;
    }
    if let Some(device) = section.get("device") {
        config.device = Some(device.to_string());
    }

    Ok(InterfaceConfig::TcpServer(config))
}

fn synthesize_udp(
    name: &str,
    section: &ConfigSection,
    mode: InterfaceMode,
) -> Result<InterfaceConfig, InterfaceFactoryError> {
    let mut config = UdpInterfaceConfig::new(name);
    config.mode = mode;

    if let Some(ip) = section.get("listen_ip") {
        config.listen_ip = Some(ip.to_string());
    }
    if let Some(port) = section.get_uint("listen_port") {
        config.listen_port = Some(port as u16);
    }
    if let Some(ip) = section.get("forward_ip") {
        config.forward_ip = Some(ip.to_string());
    }
    if let Some(port) = section.get_uint("forward_port") {
        config.forward_port = Some(port as u16);
    }
    if let Some(device) = section.get("device") {
        config.device = Some(device.to_string());
    }

    Ok(InterfaceConfig::Udp(config))
}

#[cfg(feature = "serial")]
fn synthesize_serial(
    name: &str,
    section: &ConfigSection,
    mode: InterfaceMode,
) -> Result<InterfaceConfig, InterfaceFactoryError> {
    let port = section
        .get("port")
        .ok_or_else(|| InterfaceFactoryError::MissingField {
            name: name.to_string(),
            field: "port".to_string(),
        })?
        .to_string();

    let baud_rate = section
        .get_uint("speed")
        .or_else(|| section.get_uint("baud_rate"))
        .unwrap_or(9600) as u32;

    let data_bits = section
        .get_uint("databits")
        .or_else(|| section.get_uint("data_bits"))
        .unwrap_or(8) as u8;

    let parity = section.get("parity").unwrap_or("N").to_string();

    let stop_bits = section
        .get_uint("stopbits")
        .or_else(|| section.get_uint("stop_bits"))
        .unwrap_or(1) as u8;

    Ok(InterfaceConfig::Serial(SerialInterfaceConfig {
        name: name.to_string(),
        port,
        baud_rate,
        data_bits,
        parity,
        stop_bits,
        mode,
    }))
}

#[cfg(feature = "serial")]
fn synthesize_kiss_serial(
    name: &str,
    section: &ConfigSection,
    mode: InterfaceMode,
) -> Result<InterfaceConfig, InterfaceFactoryError> {
    let port = section
        .get("port")
        .ok_or_else(|| InterfaceFactoryError::MissingField {
            name: name.to_string(),
            field: "port".to_string(),
        })?
        .to_string();

    let baud_rate = section
        .get_uint("speed")
        .or_else(|| section.get_uint("baud_rate"))
        .unwrap_or(9600) as u32;

    // Python KISSInterface.py:86-97 — TNC timing defaults 350/20/64/20,
    // serial 8N1, flow_control off, optional station-ID beacon.
    Ok(InterfaceConfig::KissSerial(KissSerialConfig {
        name: name.to_string(),
        port,
        baud_rate,
        data_bits: section.get_uint("databits").unwrap_or(8) as u8,
        parity: section.get("parity").unwrap_or("N").to_string(),
        stop_bits: section.get_uint("stopbits").unwrap_or(1) as u8,
        mode,
        preamble_ms: section.get_uint("preamble").unwrap_or(350) as u32,
        txtail_ms: section.get_uint("txtail").unwrap_or(20) as u32,
        persistence: section.get_uint("persistence").unwrap_or(64) as u8,
        slottime_ms: section.get_uint("slottime").unwrap_or(20) as u32,
        flow_control: section.get_bool("flow_control").unwrap_or(false),
        id_interval: section.get_uint("id_interval"),
        id_callsign: section.get("id_callsign").map(|s| s.to_string()),
    }))
}

fn synthesize_auto(
    name: &str,
    section: &ConfigSection,
    mode: InterfaceMode,
) -> Result<InterfaceConfig, InterfaceFactoryError> {
    use std::str::FromStr;

    let group_id = section.get("group_id").unwrap_or("reticulum").to_string();

    let discovery_scope = match section.get("discovery_scope") {
        Some(s) => rns_interface::auto::DiscoveryScope::from_str(s).map_err(|message| {
            InterfaceFactoryError::InvalidValue {
                field: "discovery_scope".to_string(),
                message,
            }
        })?,
        None => rns_interface::auto::DiscoveryScope::Link,
    };

    let discovery_port = section.get_uint("discovery_port").unwrap_or(29716) as u16;
    let data_port = section.get_uint("data_port").unwrap_or(42671) as u16;

    let multicast_address_type = match section.get("multicast_address_type") {
        Some(s) => rns_interface::auto::McastAddrType::from_str(s).map_err(|message| {
            InterfaceFactoryError::InvalidValue {
                field: "multicast_address_type".to_string(),
                message,
            }
        })?,
        None => rns_interface::auto::McastAddrType::Temporary,
    };

    // Python: comma-separated `devices` (whitelist) and `ignored_devices` (blacklist).
    let devices = section.get("devices").map(|s| {
        s.split(',')
            .map(|n| n.trim().to_string())
            .filter(|n| !n.is_empty())
            .collect::<Vec<String>>()
    });
    let ignored_devices = section
        .get("ignored_devices")
        .map(|s| {
            s.split(',')
                .map(|n| n.trim().to_string())
                .filter(|n| !n.is_empty())
                .collect::<Vec<String>>()
        })
        .unwrap_or_default();

    let configured_bitrate = section
        .get_uint("configured_bitrate")
        .or_else(|| section.get_uint("bitrate"));

    Ok(InterfaceConfig::Auto(AutoInterfaceConfig {
        name: name.to_string(),
        group_id,
        discovery_scope,
        discovery_port,
        data_port,
        multicast_address_type,
        devices,
        ignored_devices,
        configured_bitrate,
        mode,
    }))
}

#[cfg(any(feature = "serial", feature = "rnode-tcp"))]
fn synthesize_rnode(
    name: &str,
    section: &ConfigSection,
    mode: InterfaceMode,
) -> Result<InterfaceConfig, InterfaceFactoryError> {
    let port = section
        .get("port")
        .ok_or_else(|| InterfaceFactoryError::MissingField {
            name: name.to_string(),
            field: "port".to_string(),
        })?
        .to_string();

    let (frequency, bandwidth, spreading_factor, coding_rate, tx_power) =
        require_rnode_radio_params(name, section)?;

    let (flow_control, st_alock, lt_alock) = parse_rnode_airtime(name, section)?;

    Ok(InterfaceConfig::RNode(RNodeInterfaceConfig {
        name: name.to_string(),
        port,
        frequency,
        bandwidth,
        spreading_factor,
        coding_rate,
        tx_power,
        mode,
        flow_control,
        st_alock,
        lt_alock,
        id_interval: section.get_uint("id_interval"),
        id_callsign: section.get("id_callsign").map(|s| s.to_string()),
    }))
}

/// Radio parameters are deliberately required: Python errors when they are
/// absent (RNodeInterface validation fails on the 0 fallbacks), and silently
/// inventing RF parameters — especially TX power — risks misconfigured
/// transmissions. Documented in fix-registry (final sweep decision items).
#[cfg(any(feature = "serial", feature = "rnode-tcp", feature = "ble"))]
fn require_rnode_radio_params(
    name: &str,
    section: &ConfigSection,
) -> Result<(u32, u32, u8, u8, i8), InterfaceFactoryError> {
    let missing = |field: &str| InterfaceFactoryError::MissingField {
        name: name.to_string(),
        field: field.to_string(),
    };
    let frequency = section
        .get_uint("frequency")
        .ok_or_else(|| missing("frequency"))? as u32;
    let bandwidth = section
        .get_uint("bandwidth")
        .ok_or_else(|| missing("bandwidth"))? as u32;
    let spreading_factor = section
        .get_uint("spreadingfactor")
        .or_else(|| section.get_uint("spreading_factor"))
        .ok_or_else(|| missing("spreadingfactor"))? as u8;
    let coding_rate = section
        .get_uint("codingrate")
        .or_else(|| section.get_uint("coding_rate"))
        .ok_or_else(|| missing("codingrate"))? as u8;
    let tx_power = section
        .get_int("txpower")
        .or_else(|| section.get_int("tx_power"))
        .ok_or_else(|| missing("txpower"))? as i8;
    Ok((
        frequency,
        bandwidth,
        spreading_factor,
        coding_rate,
        tx_power,
    ))
}

/// Shared RNode airtime/flow-control parsing. Python `RNodeInterface.py:156-160`:
/// `flow_control` defaults off, `airtime_limit_short`/`airtime_limit_long` are
/// duty-cycle percentages validated to 0..=100.
#[cfg(any(feature = "serial", feature = "rnode-tcp", feature = "ble"))]
fn parse_rnode_airtime(
    name: &str,
    section: &ConfigSection,
) -> Result<(bool, Option<f32>, Option<f32>), InterfaceFactoryError> {
    let flow_control = section.get_bool("flow_control").unwrap_or(false);
    let st_alock = section
        .get_float("airtime_limit_short")
        .or_else(|| section.get_float("st_alock"))
        .map(|v| v as f32);
    let lt_alock = section
        .get_float("airtime_limit_long")
        .or_else(|| section.get_float("lt_alock"))
        .map(|v| v as f32);
    if let Some(v) = st_alock
        && !(0.0..=100.0).contains(&v)
    {
        return Err(InterfaceFactoryError::InvalidValue {
            field: format!("{name}.airtime_limit_short"),
            message: format!("{v} is outside 0..=100 percent"),
        });
    }
    if let Some(v) = lt_alock
        && !(0.0..=100.0).contains(&v)
    {
        return Err(InterfaceFactoryError::InvalidValue {
            field: format!("{name}.airtime_limit_long"),
            message: format!("{v} is outside 0..=100 percent"),
        });
    }
    Ok((flow_control, st_alock, lt_alock))
}

#[cfg(feature = "ble")]
fn synthesize_ble_rnode(
    name: &str,
    section: &ConfigSection,
    mode: InterfaceMode,
) -> Result<InterfaceConfig, InterfaceFactoryError> {
    let port = section
        .get("port")
        .ok_or_else(|| InterfaceFactoryError::MissingField {
            name: name.to_string(),
            field: "port".to_string(),
        })?
        .to_string();

    let (frequency, bandwidth, spreading_factor, coding_rate, tx_power) =
        require_rnode_radio_params(name, section)?;

    let (flow_control, st_alock, lt_alock) = parse_rnode_airtime(name, section)?;

    Ok(InterfaceConfig::BleRNode(BleRNodeInterfaceConfig {
        name: name.to_string(),
        port,
        frequency,
        bandwidth,
        spreading_factor,
        coding_rate,
        tx_power,
        mode,
        flow_control,
        st_alock,
        lt_alock,
        id_interval: section.get_uint("id_interval"),
        id_callsign: section.get("id_callsign").map(|s| s.to_string()),
    }))
}

fn synthesize_local(
    name: &str,
    section: &ConfigSection,
    mode: InterfaceMode,
) -> Result<InterfaceConfig, InterfaceFactoryError> {
    let port = section
        .get_uint("port")
        .unwrap_or(crate::constants::LOCAL_INTERFACE_PORT as u64) as u16;

    Ok(InterfaceConfig::Local(LocalInterfaceConfig {
        name: name.to_string(),
        port,
        mode,
    }))
}

fn synthesize_i2p(
    name: &str,
    section: &ConfigSection,
    mode: InterfaceMode,
) -> Result<InterfaceConfig, InterfaceFactoryError> {
    let connectable = section.get_bool("connectable").unwrap_or(false);
    let peers = section
        .get("peers")
        .map(|s| {
            s.split(',')
                .map(|p| p.trim().to_string())
                .filter(|p| !p.is_empty())
                .collect()
        })
        .unwrap_or_default();
    let i2p_sam_host = section
        .get("i2p_sam_host")
        .unwrap_or("127.0.0.1")
        .to_string();
    let i2p_sam_port = section.get_uint("i2p_sam_port").unwrap_or(7656) as u16;

    Ok(InterfaceConfig::I2P(I2PInterfaceConfig {
        name: name.to_string(),
        connectable,
        peers,
        i2p_sam_host,
        i2p_sam_port,
        mode,
    }))
}

fn synthesize_pipe(
    name: &str,
    section: &ConfigSection,
    mode: InterfaceMode,
) -> Result<InterfaceConfig, InterfaceFactoryError> {
    let command = section
        .get("command")
        .ok_or_else(|| InterfaceFactoryError::MissingField {
            name: name.to_string(),
            field: "command".to_string(),
        })?
        .to_string();

    let respawn_delay = section.get_uint("respawn_delay").unwrap_or(5);

    Ok(InterfaceConfig::Pipe(PipeInterfaceConfig {
        name: name.to_string(),
        command,
        respawn_delay,
        mode,
    }))
}

#[cfg(feature = "serial")]
fn synthesize_rnode_multi(
    name: &str,
    section: &ConfigSection,
    mode: InterfaceMode,
) -> Result<InterfaceConfig, InterfaceFactoryError> {
    let port = section
        .get("port")
        .ok_or_else(|| InterfaceFactoryError::MissingField {
            name: name.to_string(),
            field: "port".to_string(),
        })?
        .to_string();

    let baud_rate = section
        .get_uint("speed")
        .or_else(|| section.get_uint("baud_rate"))
        .unwrap_or(115200) as u32;
    let parent_flow_control = section.get_bool("flow_control").unwrap_or(false);

    let mut subinterfaces = Vec::new();
    let mut seen_vports = std::collections::HashSet::new();
    for (sub_name, sub_section) in &section.subsections {
        let enabled = sub_section
            .get_bool("interface_enabled")
            .or_else(|| sub_section.get_bool("enabled"))
            .unwrap_or(true);
        if !enabled {
            continue;
        }

        let vport =
            sub_section
                .get_uint("vport")
                .ok_or_else(|| InterfaceFactoryError::MissingField {
                    name: format!("{name}/{sub_name}"),
                    field: "vport".to_string(),
                })? as u8;
        if vport as usize > rns_interface::rnode_multi::MAX_SUBINTERFACES {
            return Err(InterfaceFactoryError::InvalidValue {
                field: format!("{sub_name}.vport"),
                message: format!(
                    "virtual port {} exceeds max {}",
                    vport,
                    rns_interface::rnode_multi::MAX_SUBINTERFACES
                ),
            });
        }
        if !seen_vports.insert(vport) {
            return Err(InterfaceFactoryError::InvalidValue {
                field: format!("{sub_name}.vport"),
                message: format!("duplicate virtual port {vport}"),
            });
        }

        let sub_full_name = format!("{name}/{sub_name}");
        let (frequency, bandwidth, spreading_factor, coding_rate, tx_power) =
            require_rnode_radio_params(&sub_full_name, sub_section)?;
        let tx_power = tx_power as u8;
        let flow_control = sub_section
            .get_bool("flow_control")
            .unwrap_or(parent_flow_control);
        let outgoing = sub_section.get_bool("outgoing").unwrap_or(true);
        let st_alock = sub_section
            .get_float("airtime_limit_short")
            .or_else(|| sub_section.get_float("st_alock"))
            .map(|v| v as f32);
        let lt_alock = sub_section
            .get_float("airtime_limit_long")
            .or_else(|| sub_section.get_float("lt_alock"))
            .map(|v| v as f32);
        let sub_mode = sub_section
            .get("interface_mode")
            .or_else(|| sub_section.get("mode"))
            .and_then(parse_interface_mode)
            .unwrap_or(mode);

        let parsed = RNodeSubInterfaceConfig {
            name: sub_name.clone(),
            frequency,
            bandwidth,
            spreading_factor,
            coding_rate,
            tx_power,
            vport,
            enabled,
            flow_control,
            outgoing,
            st_alock,
            lt_alock,
            mode: sub_mode,
        };
        validate_rnode_multi_subinterface(name, &parsed)?;
        subinterfaces.push(parsed);
    }

    if subinterfaces.is_empty() {
        return Err(InterfaceFactoryError::InvalidValue {
            field: "subinterfaces".to_string(),
            message: format!("RNodeMultiInterface '{name}' has no enabled subinterfaces"),
        });
    }

    if subinterfaces.len() > rns_interface::rnode_multi::MAX_SUBINTERFACES {
        return Err(InterfaceFactoryError::InvalidValue {
            field: "subinterfaces".to_string(),
            message: format!(
                "{} enabled subinterfaces exceeds max {}",
                subinterfaces.len(),
                rns_interface::rnode_multi::MAX_SUBINTERFACES
            ),
        });
    }
    subinterfaces.sort_by_key(|sub| sub.vport);

    Ok(InterfaceConfig::RNodeMulti(RNodeMultiInterfaceConfig {
        name: name.to_string(),
        port,
        baud_rate,
        flow_control: parent_flow_control,
        subinterfaces,
        mode,
        id_interval: section.get_uint("id_interval"),
        id_callsign: section.get("id_callsign").map(|s| s.to_string()),
    }))
}

#[cfg(feature = "serial")]
fn validate_rnode_multi_subinterface(
    parent: &str,
    sub: &RNodeSubInterfaceConfig,
) -> Result<(), InterfaceFactoryError> {
    if sub.tx_power > 37 {
        return Err(InterfaceFactoryError::InvalidValue {
            field: format!("{}.txpower", sub.name),
            message: format!("{} exceeds max 37 dBm", sub.tx_power),
        });
    }
    if !(7_800..=1_625_000).contains(&sub.bandwidth) {
        return Err(InterfaceFactoryError::InvalidValue {
            field: format!("{}.bandwidth", sub.name),
            message: format!("{} is outside 7800..=1625000 Hz", sub.bandwidth),
        });
    }
    if !(5..=12).contains(&sub.spreading_factor) {
        return Err(InterfaceFactoryError::InvalidValue {
            field: format!("{}.spreadingfactor", sub.name),
            message: format!("{} is outside 5..=12", sub.spreading_factor),
        });
    }
    if !(5..=8).contains(&sub.coding_rate) {
        return Err(InterfaceFactoryError::InvalidValue {
            field: format!("{}.codingrate", sub.name),
            message: format!("{} is outside 5..=8", sub.coding_rate),
        });
    }
    if let Some(v) = sub.st_alock {
        if !(0.0..=100.0).contains(&v) {
            return Err(InterfaceFactoryError::InvalidValue {
                field: format!("{}.airtime_limit_short", sub.name),
                message: format!("{v} is outside 0..=100 percent"),
            });
        }
    }
    if let Some(v) = sub.lt_alock {
        if !(0.0..=100.0).contains(&v) {
            return Err(InterfaceFactoryError::InvalidValue {
                field: format!("{}.airtime_limit_long", sub.name),
                message: format!("{v} is outside 0..=100 percent"),
            });
        }
    }
    if sub.frequency == 0 {
        return Err(InterfaceFactoryError::InvalidValue {
            field: format!("{}.frequency", sub.name),
            message: format!(
                "RNodeMultiInterface '{parent}' subinterface frequency must be non-zero"
            ),
        });
    }
    Ok(())
}

#[cfg(feature = "serial")]
fn synthesize_ax25kiss(
    name: &str,
    section: &ConfigSection,
    mode: InterfaceMode,
) -> Result<InterfaceConfig, InterfaceFactoryError> {
    let port = section
        .get("port")
        .ok_or_else(|| InterfaceFactoryError::MissingField {
            name: name.to_string(),
            field: "port".to_string(),
        })?
        .to_string();

    let callsign = section
        .get("callsign")
        .ok_or_else(|| InterfaceFactoryError::MissingField {
            name: name.to_string(),
            field: "callsign".to_string(),
        })?
        .to_string();

    let baud_rate = section
        .get_uint("speed")
        .or_else(|| section.get_uint("baud_rate"))
        .unwrap_or(9600) as u32;

    // Python AX25KISSInterface requires an explicit 0..=15 SSID
    // (default -1 fails validation, AX25KISSInterface.py:138-139).
    let ssid_raw = section
        .get_int("ssid")
        .ok_or_else(|| InterfaceFactoryError::MissingField {
            name: name.to_string(),
            field: "ssid".to_string(),
        })?;
    if !(0..=15).contains(&ssid_raw) {
        return Err(InterfaceFactoryError::InvalidValue {
            field: format!("{name}.ssid"),
            message: format!("{ssid_raw} is outside 0..=15"),
        });
    }
    let ssid = ssid_raw as u8;

    // Python defaults: 350/20/64/20 (AX25KISSInterface.py:141-144).
    let preamble = section.get_uint("preamble").unwrap_or(350) as u32;
    let txtail = section.get_uint("txtail").unwrap_or(20) as u32;
    let persistence = section.get_uint("persistence").unwrap_or(64) as u32;
    let slottime = section.get_uint("slottime").unwrap_or(20) as u32;
    let flow_control = section.get_bool("flow_control").unwrap_or(false);

    Ok(InterfaceConfig::AX25KISS(AX25KISSInterfaceConfig {
        name: name.to_string(),
        port,
        baud_rate,
        data_bits: section.get_uint("databits").unwrap_or(8) as u8,
        parity: section.get("parity").unwrap_or("N").to_string(),
        stop_bits: section.get_uint("stopbits").unwrap_or(1) as u8,
        callsign,
        ssid,
        preamble,
        txtail,
        persistence,
        slottime,
        flow_control,
        mode,
    }))
}

// `target_host`/`remote` selects client mode; otherwise listen.
fn synthesize_backbone(
    name: &str,
    section: &ConfigSection,
    mode: InterfaceMode,
) -> Result<InterfaceConfig, InterfaceFactoryError> {
    let listen_on = section.get("listen_on").map(|s| s.to_string());
    let target_host = section
        .get("target_host")
        .or_else(|| section.get("remote"))
        .map(|s| s.to_string());
    // Python BackboneInterface.py:133-134 errors without an explicit port.
    let port = section
        .get_uint("port")
        .or_else(|| section.get_uint("listen_port"))
        .or_else(|| section.get_uint("target_port"))
        .ok_or_else(|| InterfaceFactoryError::MissingField {
            name: name.to_string(),
            field: "port".to_string(),
        })? as u16;
    let device = section.get("device").map(|s| s.to_string());
    let prefer_ipv6 = section.get_bool("prefer_ipv6").unwrap_or(false);
    let connect_timeout = section.get_uint("connect_timeout").unwrap_or(5);
    let max_reconnect_tries = section.get_uint("max_reconnect_tries").map(|v| v as usize);
    let i2p_tunneled = section.get_bool("i2p_tunneled").unwrap_or(false);

    Ok(InterfaceConfig::Backbone(BackboneInterfaceConfig {
        name: name.to_string(),
        listen_on,
        target_host,
        port,
        device,
        prefer_ipv6,
        mode,
        connect_timeout,
        max_reconnect_tries,
        i2p_tunneled,
    }))
}

/// Options shared across interface variants, applied post-construction.
pub struct InterfacePostInit {
    pub outgoing: bool,
    pub bitrate: Option<u64>,
    pub announce_cap: Option<f64>,
    pub announce_rate_target: Option<u64>,
    pub announce_rate_grace: Option<u32>,
    pub announce_rate_penalty: Option<u64>,
    pub ifac_network_name: Option<String>,
    pub ifac_passphrase: Option<String>,
    pub ifac_size: Option<usize>,
    /// Fallback when `ifac_size` is unset; per-class in Python.
    pub default_ifac_size: usize,
    pub ingress_control: bool,
    /// Per-interface overrides for Python `ic_*` ingress knobs.
    pub ingress_overrides: rns_transport::ingress::IngressOverrides,
}

impl InterfacePostInit {
    pub fn from_section(section: &ConfigSection) -> Self {
        let ingress_control = section.get_bool("ingress_control").unwrap_or(true);
        let announce_rate_target = section.get_uint("announce_rate_target");
        let ingress_overrides = rns_transport::ingress::IngressOverrides {
            enabled: if ingress_control { None } else { Some(false) },
            burst_freq_new: section.get_float("ic_burst_freq_new"),
            burst_freq: section.get_float("ic_burst_freq"),
            pr_burst_freq_new: section.get_float("ic_pr_burst_freq_new"),
            pr_burst_freq: section.get_float("ic_pr_burst_freq"),
            new_time: section.get_float("ic_new_time"),
            burst_hold: section.get_float("ic_burst_hold"),
            burst_penalty: section.get_float("ic_burst_penalty"),
            max_held: section
                .get_uint("ic_max_held_announces")
                .map(|v| v as usize),
            held_release_interval: section.get_float("ic_held_release_interval"),
            ec_pr_freq: section.get_float("ec_pr_freq"),
            egress_control: section.get_bool("egress_control"),
        };
        Self {
            outgoing: section.get_bool("outgoing").unwrap_or(true),
            bitrate: section.get_uint("bitrate"),
            announce_cap: section
                .get_float("announce_cap")
                .and_then(normalize_announce_cap_percent),
            announce_rate_target,
            announce_rate_grace: section
                .get_uint("announce_rate_grace")
                .map(|v| v as u32)
                .or_else(|| announce_rate_target.map(|_| 0)),
            announce_rate_penalty: section
                .get_uint("announce_rate_penalty")
                .or_else(|| announce_rate_target.map(|_| 0)),
            ifac_network_name: section
                .get("networkname")
                .or_else(|| section.get("network_name"))
                .map(|s| s.to_string()),
            ifac_passphrase: section
                .get("passphrase")
                .or_else(|| section.get("pass_phrase"))
                .map(|s| s.to_string()),
            ifac_size: section.get_uint("ifac_size").map(|v| v as usize),
            default_ifac_size: 8,
            ingress_control,
            ingress_overrides,
        }
    }

    pub fn with_default_ifac_size(mut self, size: usize) -> Self {
        self.default_ifac_size = size;
        self
    }
}

fn normalize_announce_cap_percent(value: f64) -> Option<f64> {
    if value > 0.0 && value <= 100.0 {
        Some(value / 100.0)
    } else {
        None
    }
}

/// Python `DEFAULT_IFAC_SIZE`: network interfaces 16 bytes, serial/packet-radio 8.
pub fn default_ifac_size_for(config: &InterfaceConfig) -> usize {
    match config {
        InterfaceConfig::TcpClient(_)
        | InterfaceConfig::TcpServer(_)
        | InterfaceConfig::Udp(_)
        | InterfaceConfig::Auto(_)
        | InterfaceConfig::I2P(_)
        | InterfaceConfig::Backbone(_) => 16,
        #[cfg(feature = "serial")]
        InterfaceConfig::Serial(_)
        | InterfaceConfig::KissSerial(_)
        | InterfaceConfig::RNodeMulti(_)
        | InterfaceConfig::AX25KISS(_) => 8,
        #[cfg(any(feature = "serial", feature = "rnode-tcp"))]
        InterfaceConfig::RNode(_) => 8,
        InterfaceConfig::Local(_) | InterfaceConfig::Pipe(_) => 8,
        #[cfg(feature = "ble")]
        InterfaceConfig::BleRNode(_) => 8,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_synthesize_tcp_client() {
        let mut section = ConfigSection::new();
        section.set("type", "TCPClientInterface");
        section.set("target_host", "127.0.0.1");
        section.set("target_port", "4242");

        let config = synthesize_interface("test_tcp", &section).unwrap();
        match config {
            InterfaceConfig::TcpClient(c) => {
                assert_eq!(c.target_host, "127.0.0.1");
                assert_eq!(c.target_port, 4242);
                assert!(!c.kiss_framing);
            }
            _ => panic!("expected TcpClient"),
        }
    }

    #[test]
    fn test_synthesize_tcp_server() {
        let mut section = ConfigSection::new();
        section.set("type", "TCPServerInterface");
        section.set("listen_port", "4242");

        let config = synthesize_interface("test_srv", &section).unwrap();
        match config {
            InterfaceConfig::TcpServer(c) => {
                assert_eq!(c.listen_ip, "0.0.0.0");
                assert_eq!(c.listen_port, 4242);
            }
            _ => panic!("expected TcpServer"),
        }
    }

    #[test]
    fn test_synthesize_udp() {
        let mut section = ConfigSection::new();
        section.set("type", "UDPInterface");
        section.set("listen_ip", "0.0.0.0");
        section.set("listen_port", "4242");
        section.set("forward_ip", "255.255.255.255");
        section.set("forward_port", "4242");

        let config = synthesize_interface("test_udp", &section).unwrap();
        match config {
            InterfaceConfig::Udp(c) => {
                assert_eq!(c.listen_ip.as_deref(), Some("0.0.0.0"));
                assert_eq!(c.listen_port, Some(4242));
                assert_eq!(c.forward_ip.as_deref(), Some("255.255.255.255"));
            }
            _ => panic!("expected Udp"),
        }
    }

    #[test]
    fn test_disabled_interface() {
        let mut section = ConfigSection::new();
        section.set("type", "TCPClientInterface");
        section.set("enabled", "no");
        section.set("target_host", "127.0.0.1");
        section.set("target_port", "4242");

        match synthesize_interface("disabled", &section) {
            Err(InterfaceFactoryError::Disabled(_)) => {}
            other => panic!("expected Disabled, got {other:?}"),
        }
    }

    #[test]
    fn test_unknown_type() {
        let mut section = ConfigSection::new();
        section.set("type", "FooInterface");

        match synthesize_interface("unknown", &section) {
            Err(InterfaceFactoryError::UnknownType(t)) => assert_eq!(t, "FooInterface"),
            other => panic!("expected UnknownType, got {other:?}"),
        }
    }

    #[test]
    fn test_missing_type() {
        let section = ConfigSection::new();
        match synthesize_interface("no_type", &section) {
            Err(InterfaceFactoryError::MissingField { field, .. }) => {
                assert_eq!(field, "type");
            }
            other => panic!("expected MissingField, got {other:?}"),
        }
    }

    #[test]
    fn test_interface_mode_parsing() {
        assert_eq!(parse_interface_mode("full"), Some(InterfaceMode::Full));
        assert_eq!(
            parse_interface_mode("access_point"),
            Some(InterfaceMode::AccessPoint)
        );
        assert_eq!(
            parse_interface_mode("accesspoint"),
            Some(InterfaceMode::AccessPoint)
        );
        assert_eq!(parse_interface_mode("ap"), Some(InterfaceMode::AccessPoint));
        assert_eq!(
            parse_interface_mode("pointtopoint"),
            Some(InterfaceMode::PointToPoint)
        );
        assert_eq!(
            parse_interface_mode("roaming"),
            Some(InterfaceMode::Roaming)
        );
        assert_eq!(
            parse_interface_mode("boundary"),
            Some(InterfaceMode::Boundary)
        );
        assert_eq!(
            parse_interface_mode("gateway"),
            Some(InterfaceMode::Gateway)
        );
        assert_eq!(parse_interface_mode("gw"), Some(InterfaceMode::Gateway));
        assert_eq!(parse_interface_mode("unknown"), None);
    }

    #[test]
    fn test_tcp_client_with_options() {
        let mut section = ConfigSection::new();
        section.set("type", "TCPClientInterface");
        section.set("target_host", "10.0.0.1");
        section.set("target_port", "5555");
        section.set("kiss_framing", "yes");
        section.set("connect_timeout", "10");
        section.set("max_reconnect_tries", "3");
        section.set("interface_mode", "gateway");

        let config = synthesize_interface("tcp_opts", &section).unwrap();
        match config {
            InterfaceConfig::TcpClient(c) => {
                assert!(c.kiss_framing);
                assert_eq!(c.connect_timeout_secs, 10);
                assert_eq!(c.max_reconnect_tries, Some(3));
                assert_eq!(c.mode, InterfaceMode::Gateway);
            }
            _ => panic!("expected TcpClient"),
        }
    }

    #[test]
    fn test_post_init_defaults() {
        let section = ConfigSection::new();
        let pi = InterfacePostInit::from_section(&section);
        assert!(pi.outgoing);
        assert!(pi.ingress_control);
        assert!(pi.bitrate.is_none());
        assert!(pi.ifac_network_name.is_none());
    }

    #[test]
    fn test_announce_rate_target_defaults_grace_and_penalty() {
        let mut section = ConfigSection::new();
        section.set("announce_rate_target", "2");

        let pi = InterfacePostInit::from_section(&section);

        assert_eq!(pi.announce_rate_target, Some(2));
        assert_eq!(pi.announce_rate_grace, Some(0));
        assert_eq!(pi.announce_rate_penalty, Some(0));
    }

    /// Python KISSInterface.py:86-97 defaults: 350/20/64/20, 8N1, no beacon.
    #[cfg(feature = "serial")]
    #[test]
    fn test_synthesize_kiss_defaults_match_python() {
        let mut section = ConfigSection::new();
        section.set("type", "KISSInterface");
        section.set("port", "/dev/ttyUSB1");

        match synthesize_interface("kiss_defaults", &section).unwrap() {
            InterfaceConfig::KissSerial(c) => {
                assert_eq!(c.preamble_ms, 350);
                assert_eq!(c.txtail_ms, 20);
                assert_eq!(c.persistence, 64);
                assert_eq!(c.slottime_ms, 20);
                assert_eq!((c.data_bits, c.parity.as_str(), c.stop_bits), (8, "N", 1));
                assert!(!c.flow_control);
                assert!(c.id_interval.is_none() && c.id_callsign.is_none());
            }
            _ => panic!("expected KissSerial"),
        }
    }

    #[cfg(feature = "serial")]
    #[test]
    fn test_synthesize_kiss_full_params_and_beacon() {
        let mut section = ConfigSection::new();
        section.set("type", "KISSInterface");
        section.set("port", "/dev/ttyUSB1");
        section.set("preamble", "150");
        section.set("txtail", "10");
        section.set("persistence", "200");
        section.set("slottime", "30");
        section.set("flow_control", "true");
        section.set("id_interval", "600");
        section.set("id_callsign", "MYCALL-0");

        match synthesize_interface("kiss_full", &section).unwrap() {
            InterfaceConfig::KissSerial(c) => {
                assert_eq!(c.preamble_ms, 150);
                assert_eq!(c.txtail_ms, 10);
                assert_eq!(c.persistence, 200);
                assert_eq!(c.slottime_ms, 30);
                assert!(c.flow_control);
                assert_eq!(c.id_interval, Some(600));
                assert_eq!(c.id_callsign.as_deref(), Some("MYCALL-0"));
            }
            _ => panic!("expected KissSerial"),
        }
    }

    /// Python AX25KISSInterface.py:141-144 defaults + 0..=15 SSID requirement.
    #[cfg(feature = "serial")]
    #[test]
    fn test_synthesize_ax25kiss_defaults_and_ssid() {
        let mut section = ConfigSection::new();
        section.set("type", "AX25KISSInterface");
        section.set("port", "/dev/ttyUSB2");
        section.set("callsign", "NO1CLL");
        section.set("ssid", "0");

        match synthesize_interface("ax25_defaults", &section).unwrap() {
            InterfaceConfig::AX25KISS(c) => {
                assert_eq!(c.preamble, 350);
                assert_eq!(c.txtail, 20);
                assert_eq!(c.persistence, 64);
                assert_eq!(c.slottime, 20);
            }
            _ => panic!("expected AX25KISS"),
        }

        let mut no_ssid = ConfigSection::new();
        no_ssid.set("type", "AX25KISSInterface");
        no_ssid.set("port", "/dev/ttyUSB2");
        no_ssid.set("callsign", "NO1CLL");
        assert!(matches!(
            synthesize_interface("ax25_no_ssid", &no_ssid),
            Err(InterfaceFactoryError::MissingField { field, .. }) if field == "ssid"
        ));

        section.set("ssid", "16");
        assert!(matches!(
            synthesize_interface("ax25_bad_ssid", &section),
            Err(InterfaceFactoryError::InvalidValue { field, .. }) if field.ends_with("ssid")
        ));
    }

    #[test]
    fn test_synthesize_tcp_fixed_mtu_and_device() {
        let mut client = ConfigSection::new();
        client.set("type", "TCPClientInterface");
        client.set("target_host", "example.com");
        client.set("target_port", "4242");
        client.set("fixed_mtu", "1064");
        match synthesize_interface("tcp_fixed", &client).unwrap() {
            InterfaceConfig::TcpClient(c) => assert_eq!(c.fixed_mtu, Some(1064)),
            _ => panic!("expected TcpClient"),
        }

        client.set("fixed_mtu", "400");
        assert!(matches!(
            synthesize_interface("tcp_small_mtu", &client),
            Err(InterfaceFactoryError::InvalidValue { field, .. }) if field.ends_with("fixed_mtu")
        ));

        let mut server = ConfigSection::new();
        server.set("type", "TCPServerInterface");
        server.set("listen_port", "4242");
        server.set("device", "eth0");
        match synthesize_interface("tcp_dev", &server).unwrap() {
            InterfaceConfig::TcpServer(c) => assert_eq!(c.device.as_deref(), Some("eth0")),
            _ => panic!("expected TcpServer"),
        }
    }

    #[cfg(feature = "serial")]
    #[test]
    fn test_synthesize_rnode_beacon_keys() {
        let mut section = ConfigSection::new();
        section.set("type", "RNodeInterface");
        section.set("port", "/dev/ttyACM0");
        section.set("frequency", "868000000");
        set_rnode_radio_params(&mut section);
        section.set("id_interval", "600");
        section.set("id_callsign", "MYCALL-0");

        match synthesize_interface("rnode_beacon", &section).unwrap() {
            InterfaceConfig::RNode(c) => {
                assert_eq!(c.id_interval, Some(600));
                assert_eq!(c.id_callsign.as_deref(), Some("MYCALL-0"));
            }
            _ => panic!("expected RNode"),
        }
    }

    #[cfg(feature = "serial")]
    #[test]
    fn test_synthesize_rnode_airtime_and_flow_control() {
        let mut section = ConfigSection::new();
        section.set("type", "RNodeInterface");
        section.set("port", "/dev/ttyACM0");
        section.set("frequency", "868000000");
        set_rnode_radio_params(&mut section);
        section.set("flow_control", "true");
        section.set("airtime_limit_short", "33");
        section.set("airtime_limit_long", "3.3");

        let config = synthesize_interface("rnode_airtime", &section).unwrap();
        match config {
            InterfaceConfig::RNode(c) => {
                assert!(c.flow_control);
                assert_eq!(c.st_alock, Some(33.0));
                assert_eq!(c.lt_alock, Some(3.3));
            }
            _ => panic!("expected RNode"),
        }
    }

    /// Python parity: flow_control defaults off, airtime limits unset.
    #[cfg(feature = "serial")]
    #[test]
    fn test_synthesize_rnode_airtime_defaults() {
        let mut section = ConfigSection::new();
        section.set("type", "RNodeInterface");
        section.set("port", "/dev/ttyACM0");
        section.set("frequency", "868000000");
        set_rnode_radio_params(&mut section);

        let config = synthesize_interface("rnode_defaults", &section).unwrap();
        match config {
            InterfaceConfig::RNode(c) => {
                assert!(!c.flow_control);
                assert!(c.st_alock.is_none());
                assert!(c.lt_alock.is_none());
            }
            _ => panic!("expected RNode"),
        }
    }

    #[cfg(feature = "serial")]
    #[test]
    fn test_synthesize_rnode_airtime_out_of_range() {
        let mut section = ConfigSection::new();
        section.set("type", "RNodeInterface");
        section.set("port", "/dev/ttyACM0");
        section.set("frequency", "868000000");
        set_rnode_radio_params(&mut section);
        section.set("airtime_limit_long", "101");

        match synthesize_interface("rnode_bad_alock", &section) {
            Err(InterfaceFactoryError::InvalidValue { field, .. }) => {
                assert!(field.ends_with("airtime_limit_long"));
            }
            other => panic!("expected InvalidValue, got {other:?}"),
        }
    }

    #[cfg(feature = "serial")]
    #[test]
    fn test_synthesize_serial() {
        let mut section = ConfigSection::new();
        section.set("type", "SerialInterface");
        section.set("port", "/dev/ttyUSB0");
        section.set("speed", "115200");
        section.set("databits", "8");
        section.set("parity", "N");
        section.set("stopbits", "1");

        let config = synthesize_interface("test_serial", &section).unwrap();
        match config {
            InterfaceConfig::Serial(c) => {
                assert_eq!(c.name, "test_serial");
                assert_eq!(c.port, "/dev/ttyUSB0");
                assert_eq!(c.baud_rate, 115200);
                assert_eq!(c.data_bits, 8);
                assert_eq!(c.parity, "N");
                assert_eq!(c.stop_bits, 1);
            }
            _ => panic!("expected Serial"),
        }
    }

    #[cfg(feature = "serial")]
    #[test]
    fn test_synthesize_serial_defaults() {
        let mut section = ConfigSection::new();
        section.set("type", "SerialInterface");
        section.set("port", "/dev/ttyS0");

        let config = synthesize_interface("serial_defaults", &section).unwrap();
        match config {
            InterfaceConfig::Serial(c) => {
                assert_eq!(c.baud_rate, 9600);
                assert_eq!(c.data_bits, 8);
                assert_eq!(c.parity, "N");
                assert_eq!(c.stop_bits, 1);
            }
            _ => panic!("expected Serial"),
        }
    }

    #[cfg(feature = "serial")]
    #[test]
    fn test_synthesize_serial_missing_port() {
        let mut section = ConfigSection::new();
        section.set("type", "SerialInterface");

        match synthesize_interface("serial_no_port", &section) {
            Err(InterfaceFactoryError::MissingField { field, .. }) => {
                assert_eq!(field, "port");
            }
            other => panic!("expected MissingField, got {other:?}"),
        }
    }

    #[cfg(feature = "serial")]
    #[test]
    fn test_synthesize_kiss_serial() {
        let mut section = ConfigSection::new();
        section.set("type", "KISSInterface");
        section.set("port", "/dev/ttyUSB1");
        section.set("speed", "57600");

        let config = synthesize_interface("test_kiss", &section).unwrap();
        match config {
            InterfaceConfig::KissSerial(c) => {
                assert_eq!(c.name, "test_kiss");
                assert_eq!(c.port, "/dev/ttyUSB1");
                assert_eq!(c.baud_rate, 57600);
            }
            _ => panic!("expected KissSerial"),
        }
    }

    #[cfg(feature = "serial")]
    #[test]
    fn test_synthesize_kiss_serial_defaults() {
        let mut section = ConfigSection::new();
        section.set("type", "KISSInterface");
        section.set("port", "/dev/ttyS0");

        let config = synthesize_interface("kiss_defaults", &section).unwrap();
        match config {
            InterfaceConfig::KissSerial(c) => {
                assert_eq!(c.baud_rate, 9600);
            }
            _ => panic!("expected KissSerial"),
        }
    }

    #[test]
    fn test_synthesize_auto() {
        let mut section = ConfigSection::new();
        section.set("type", "AutoInterface");
        section.set("group_id", "mygroup");
        section.set("discovery_port", "30000");
        section.set("data_port", "40000");

        let config = synthesize_interface("test_auto", &section).unwrap();
        match config {
            InterfaceConfig::Auto(c) => {
                assert_eq!(c.name, "test_auto");
                assert_eq!(c.group_id, "mygroup");
                assert_eq!(c.discovery_port, 30000);
                assert_eq!(c.data_port, 40000);
            }
            _ => panic!("expected Auto"),
        }
    }

    #[test]
    fn test_synthesize_auto_defaults() {
        let mut section = ConfigSection::new();
        section.set("type", "AutoInterface");

        let config = synthesize_interface("auto_defaults", &section).unwrap();
        match config {
            InterfaceConfig::Auto(c) => {
                assert_eq!(c.group_id, "reticulum");
                assert_eq!(c.discovery_port, 29716);
                assert_eq!(c.data_port, 42671);
                assert_eq!(c.discovery_scope, rns_interface::auto::DiscoveryScope::Link);
                assert_eq!(
                    c.multicast_address_type,
                    rns_interface::auto::McastAddrType::Temporary
                );
                assert!(c.devices.is_none());
                assert!(c.ignored_devices.is_empty());
                assert!(c.configured_bitrate.is_none());
            }
            _ => panic!("expected Auto"),
        }
    }

    #[test]
    fn test_synthesize_auto_advanced_options() {
        let mut section = ConfigSection::new();
        section.set("type", "AutoInterface");
        section.set("group_id", "campus");
        section.set("discovery_scope", "site");
        section.set("multicast_address_type", "permanent");
        section.set("devices", "eth0, wlan0 ,br-lan");
        section.set("ignored_devices", "vmnet1,docker0");
        section.set("configured_bitrate", "100000000");

        let config = synthesize_interface("campus_auto", &section).unwrap();
        match config {
            InterfaceConfig::Auto(c) => {
                assert_eq!(c.group_id, "campus");
                assert_eq!(c.discovery_scope, rns_interface::auto::DiscoveryScope::Site);
                assert_eq!(
                    c.multicast_address_type,
                    rns_interface::auto::McastAddrType::Permanent
                );
                let devices = c.devices.expect("devices set");
                assert_eq!(devices, vec!["eth0", "wlan0", "br-lan"]);
                assert_eq!(c.ignored_devices, vec!["vmnet1", "docker0"]);
                assert_eq!(c.configured_bitrate, Some(100_000_000));
            }
            _ => panic!("expected Auto"),
        }
    }

    #[cfg(feature = "serial")]
    #[test]
    fn test_synthesize_rnode() {
        let mut section = ConfigSection::new();
        section.set("type", "RNodeInterface");
        section.set("port", "/dev/ttyACM0");
        section.set("frequency", "868000000");
        set_rnode_radio_params(&mut section);
        section.set("bandwidth", "125000");
        section.set("spreadingfactor", "7");
        section.set("codingrate", "5");
        section.set("txpower", "14");
        section.set("interface_mode", "access_point");

        let config = synthesize_interface("test_rnode", &section).unwrap();
        match config {
            InterfaceConfig::RNode(c) => {
                assert_eq!(c.name, "test_rnode");
                assert_eq!(c.port, "/dev/ttyACM0");
                assert_eq!(c.frequency, 868000000);
                assert_eq!(c.bandwidth, 125000);
                assert_eq!(c.spreading_factor, 7);
                assert_eq!(c.coding_rate, 5);
                assert_eq!(c.tx_power, 14);
                assert_eq!(c.mode, InterfaceMode::AccessPoint);
            }
            _ => panic!("expected RNode"),
        }
    }

    #[cfg(any(feature = "serial", feature = "rnode-tcp"))]
    fn set_rnode_radio_params(section: &mut ConfigSection) {
        section.set("bandwidth", "125000");
        section.set("spreadingfactor", "7");
        section.set("codingrate", "5");
        section.set("txpower", "17");
    }

    /// Python parity: all radio params required — no invented defaults.
    #[cfg(feature = "serial")]
    #[test]
    fn test_synthesize_rnode_requires_radio_params() {
        let mut section = ConfigSection::new();
        section.set("type", "RNodeInterface");
        section.set("port", "/dev/ttyACM0");
        section.set("frequency", "915000000");

        assert!(matches!(
            synthesize_interface("rnode_missing", &section),
            Err(InterfaceFactoryError::MissingField { field, .. }) if field == "bandwidth"
        ));

        set_rnode_radio_params(&mut section);
        let config = synthesize_interface("rnode_full", &section).unwrap();
        match config {
            InterfaceConfig::RNode(c) => {
                assert_eq!(c.bandwidth, 125000);
                assert_eq!(c.spreading_factor, 7);
                assert_eq!(c.coding_rate, 5);
                assert_eq!(c.tx_power, 17);
            }
            _ => panic!("expected RNode"),
        }
    }

    #[cfg(any(feature = "serial", feature = "rnode-tcp"))]
    #[test]
    fn test_synthesize_rnode_tcp() {
        let mut section = ConfigSection::new();
        section.set("type", "RNodeInterface");
        section.set("port", "tcp://rnode.local");
        section.set("frequency", "915000000");
        set_rnode_radio_params(&mut section);

        let config = synthesize_interface("rnode_tcp", &section).unwrap();
        match config {
            InterfaceConfig::RNode(c) => {
                assert_eq!(c.name, "rnode_tcp");
                assert_eq!(c.port, "tcp://rnode.local");
                assert_eq!(c.frequency, 915000000);
            }
            _ => panic!("expected RNode"),
        }
    }

    #[cfg(any(feature = "serial", feature = "rnode-tcp"))]
    #[test]
    fn test_synthesize_rnode_missing_port() {
        let mut section = ConfigSection::new();
        section.set("type", "RNodeInterface");
        section.set("frequency", "868000000");

        match synthesize_interface("rnode_no_port", &section) {
            Err(InterfaceFactoryError::MissingField { field, .. }) => {
                assert_eq!(field, "port");
            }
            other => panic!("expected MissingField, got {other:?}"),
        }
    }

    #[cfg(any(feature = "serial", feature = "rnode-tcp"))]
    #[test]
    fn test_synthesize_rnode_missing_frequency() {
        let mut section = ConfigSection::new();
        section.set("type", "RNodeInterface");
        section.set("port", "tcp://rnode.local");

        match synthesize_interface("rnode_no_freq", &section) {
            Err(InterfaceFactoryError::MissingField { field, .. }) => {
                assert_eq!(field, "frequency");
            }
            other => panic!("expected MissingField, got {other:?}"),
        }
    }

    #[test]
    fn test_synthesize_local() {
        let mut section = ConfigSection::new();
        section.set("type", "LocalInterface");
        section.set("port", "12345");

        let config = synthesize_interface("test_local", &section).unwrap();
        match config {
            InterfaceConfig::Local(c) => {
                assert_eq!(c.name, "test_local");
                assert_eq!(c.port, 12345);
            }
            _ => panic!("expected Local"),
        }
    }

    #[test]
    fn test_synthesize_local_default_port() {
        let mut section = ConfigSection::new();
        section.set("type", "LocalInterface");

        let config = synthesize_interface("local_defaults", &section).unwrap();
        match config {
            InterfaceConfig::Local(c) => {
                assert_eq!(c.port, 37428);
                assert_eq!(c.mode, InterfaceMode::Full);
            }
            _ => panic!("expected Local"),
        }
    }

    #[cfg(feature = "serial")]
    #[test]
    fn test_interface_config_variants_construction() {
        let _tcp_client = InterfaceConfig::TcpClient(TcpClientConfig::new("tc", "127.0.0.1", 4242));
        let _tcp_server = InterfaceConfig::TcpServer(TcpServerConfig::new("ts", "0.0.0.0", 4242));
        let _udp = InterfaceConfig::Udp(UdpInterfaceConfig::new("udp"));
        let _serial = InterfaceConfig::Serial(SerialInterfaceConfig {
            name: "s".to_string(),
            port: "/dev/ttyS0".to_string(),
            baud_rate: 9600,
            data_bits: 8,
            parity: "N".to_string(),
            stop_bits: 1,
            mode: InterfaceMode::Full,
        });
        let _kiss = InterfaceConfig::KissSerial(KissSerialConfig {
            name: "k".to_string(),
            port: "/dev/ttyS0".to_string(),
            baud_rate: 9600,
            data_bits: 8,
            parity: "N".to_string(),
            stop_bits: 1,
            mode: InterfaceMode::Full,
            preamble_ms: 350,
            txtail_ms: 20,
            persistence: 64,
            slottime_ms: 20,
            flow_control: false,
            id_interval: None,
            id_callsign: None,
        });
        let _auto = InterfaceConfig::Auto(AutoInterfaceConfig {
            name: "a".to_string(),
            group_id: "test".to_string(),
            discovery_scope: rns_interface::auto::DiscoveryScope::Link,
            discovery_port: 29716,
            data_port: 42671,
            multicast_address_type: rns_interface::auto::McastAddrType::Temporary,
            devices: None,
            ignored_devices: Vec::new(),
            configured_bitrate: None,
            mode: InterfaceMode::Full,
        });
        let _rnode = InterfaceConfig::RNode(RNodeInterfaceConfig {
            name: "r".to_string(),
            port: "/dev/ttyACM0".to_string(),
            frequency: 868000000,
            bandwidth: 125000,
            spreading_factor: 7,
            coding_rate: 5,
            tx_power: 17,
            mode: InterfaceMode::Full,
            flow_control: false,
            st_alock: None,
            lt_alock: None,
            id_interval: None,
            id_callsign: None,
        });
        let _local = InterfaceConfig::Local(LocalInterfaceConfig {
            name: "l".to_string(),
            port: 37428,
            mode: InterfaceMode::Full,
        });
    }

    #[test]
    fn test_post_init_with_values() {
        let mut section = ConfigSection::new();
        section.set("outgoing", "no");
        section.set("bitrate", "115200");
        section.set("networkname", "testnet");
        section.set("passphrase", "secret");
        section.set("ifac_size", "16");
        section.set("ingress_control", "false");
        section.set("announce_cap", "5.0");
        section.set("ic_pr_burst_freq_new", "4.5");
        section.set("ic_pr_burst_freq", "9.5");
        section.set("ec_pr_freq", "6.5");
        section.set("egress_control", "Yes");

        let pi = InterfacePostInit::from_section(&section);
        assert!(!pi.outgoing);
        assert_eq!(pi.bitrate, Some(115200));
        assert_eq!(pi.ifac_network_name.as_deref(), Some("testnet"));
        assert_eq!(pi.ifac_passphrase.as_deref(), Some("secret"));
        assert_eq!(pi.ifac_size, Some(16));
        assert!(!pi.ingress_control);
        assert!((pi.announce_cap.unwrap() - 0.05).abs() < f64::EPSILON);
        assert_eq!(pi.ingress_overrides.enabled, Some(false));
        assert_eq!(pi.ingress_overrides.pr_burst_freq_new, Some(4.5));
        assert_eq!(pi.ingress_overrides.pr_burst_freq, Some(9.5));
        assert_eq!(pi.ingress_overrides.ec_pr_freq, Some(6.5));
        assert_eq!(pi.ingress_overrides.egress_control, Some(true));
    }

    #[test]
    fn announce_cap_config_uses_python_percent_shape() {
        let mut section = ConfigSection::new();
        section.set("announce_cap", "2");
        let pi = InterfacePostInit::from_section(&section);
        assert_eq!(pi.announce_cap, Some(0.02));

        section.set("announce_cap", "100");
        let pi = InterfacePostInit::from_section(&section);
        assert_eq!(pi.announce_cap, Some(1.0));

        section.set("announce_cap", "0");
        let pi = InterfacePostInit::from_section(&section);
        assert_eq!(pi.announce_cap, None);

        section.set("announce_cap", "101");
        let pi = InterfacePostInit::from_section(&section);
        assert_eq!(pi.announce_cap, None);
    }

    #[test]
    fn test_synthesize_i2p() {
        let mut section = ConfigSection::new();
        section.set("type", "I2PInterface");
        section.set("connectable", "yes");
        section.set("peers", "abc123.b32.i2p, def456.b32.i2p");

        let config = synthesize_interface("test_i2p", &section).unwrap();
        match config {
            InterfaceConfig::I2P(c) => {
                assert_eq!(c.name, "test_i2p");
                assert!(c.connectable);
                assert_eq!(c.peers.len(), 2);
                assert_eq!(c.peers[0], "abc123.b32.i2p");
                assert_eq!(c.peers[1], "def456.b32.i2p");
                assert_eq!(c.i2p_sam_host, "127.0.0.1");
                assert_eq!(c.i2p_sam_port, 7656);
            }
            _ => panic!("expected I2P"),
        }
    }

    #[test]
    fn test_synthesize_i2p_defaults() {
        let mut section = ConfigSection::new();
        section.set("type", "I2PInterface");

        let config = synthesize_interface("i2p_defaults", &section).unwrap();
        match config {
            InterfaceConfig::I2P(c) => {
                assert!(!c.connectable);
                assert!(c.peers.is_empty());
                assert_eq!(c.i2p_sam_host, "127.0.0.1");
                assert_eq!(c.i2p_sam_port, 7656);
            }
            _ => panic!("expected I2P"),
        }
    }

    #[test]
    fn test_synthesize_pipe() {
        let mut section = ConfigSection::new();
        section.set("type", "PipeInterface");
        section.set("command", "netcat -l 5757");
        section.set("respawn_delay", "10");

        let config = synthesize_interface("test_pipe", &section).unwrap();
        match config {
            InterfaceConfig::Pipe(c) => {
                assert_eq!(c.name, "test_pipe");
                assert_eq!(c.command, "netcat -l 5757");
                assert_eq!(c.respawn_delay, 10);
            }
            _ => panic!("expected Pipe"),
        }
    }

    #[test]
    fn test_synthesize_pipe_defaults() {
        let mut section = ConfigSection::new();
        section.set("type", "PipeInterface");
        section.set("command", "cat");

        let config = synthesize_interface("pipe_defaults", &section).unwrap();
        match config {
            InterfaceConfig::Pipe(c) => {
                assert_eq!(c.respawn_delay, 5);
            }
            _ => panic!("expected Pipe"),
        }
    }

    #[test]
    fn test_synthesize_pipe_missing_command() {
        let mut section = ConfigSection::new();
        section.set("type", "PipeInterface");

        match synthesize_interface("pipe_no_cmd", &section) {
            Err(InterfaceFactoryError::MissingField { field, .. }) => {
                assert_eq!(field, "command");
            }
            other => panic!("expected MissingField, got {other:?}"),
        }
    }

    #[test]
    fn test_synthesize_backbone_client() {
        let mut section = ConfigSection::new();
        section.set("type", "BackboneInterface");
        section.set("target_host", "amsterdam.connect.reticulum.network");
        section.set("target_port", "4251");

        let config = synthesize_interface("test_backbone", &section).unwrap();
        match config {
            InterfaceConfig::Backbone(c) => {
                assert_eq!(c.name, "test_backbone");
                assert_eq!(
                    c.target_host.as_deref(),
                    Some("amsterdam.connect.reticulum.network")
                );
                assert_eq!(c.port, 4251);
                assert!(c.listen_on.is_none());
            }
            _ => panic!("expected Backbone"),
        }
    }

    #[test]
    fn test_synthesize_backbone_listener() {
        let mut section = ConfigSection::new();
        section.set("type", "BackboneInterface");
        section.set("listen_on", "0.0.0.0");
        section.set("port", "4242");

        let config = synthesize_interface("backbone_listen", &section).unwrap();
        match config {
            InterfaceConfig::Backbone(c) => {
                assert_eq!(c.listen_on.as_deref(), Some("0.0.0.0"));
                assert_eq!(c.port, 4242);
                assert!(c.target_host.is_none());
            }
            _ => panic!("expected Backbone"),
        }
    }

    #[test]
    fn test_synthesize_backbone_with_remote() {
        let mut section = ConfigSection::new();
        section.set("type", "BackboneInterface");
        section.set("remote", "some.host.network");
        section.set("target_port", "4343");
        section.set("prefer_ipv6", "yes");

        let config = synthesize_interface("backbone_remote", &section).unwrap();
        match config {
            InterfaceConfig::Backbone(c) => {
                assert_eq!(c.target_host.as_deref(), Some("some.host.network"));
                assert_eq!(c.port, 4343);
                assert!(c.prefer_ipv6);
            }
            _ => panic!("expected Backbone"),
        }
    }

    #[test]
    fn test_synthesize_backbone_defaults() {
        let mut section = ConfigSection::new();
        section.set("type", "BackboneInterface");

        // Python BackboneInterface errors without an explicit port.
        assert!(matches!(
            synthesize_interface("backbone_no_port", &section),
            Err(InterfaceFactoryError::MissingField { field, .. }) if field == "port"
        ));

        section.set("port", "4242");
        let config = synthesize_interface("backbone_defaults", &section).unwrap();
        match config {
            InterfaceConfig::Backbone(c) => {
                assert_eq!(c.port, 4242);
                assert!(!c.prefer_ipv6);
                assert!(c.listen_on.is_none());
                assert!(c.target_host.is_none());
                assert!(c.device.is_none());
                assert_eq!(c.connect_timeout, 5);
                assert!(c.max_reconnect_tries.is_none());
                assert!(!c.i2p_tunneled);
            }
            _ => panic!("expected Backbone"),
        }
    }

    #[test]
    fn test_synthesize_backbone_connect_timeout() {
        let mut section = ConfigSection::new();
        section.set("type", "BackboneInterface");
        section.set("target_host", "host.example");
        section.set("target_port", "4242");
        section.set("connect_timeout", "12");

        let config = synthesize_interface("bb_to", &section).unwrap();
        match config {
            InterfaceConfig::Backbone(c) => assert_eq!(c.connect_timeout, 12),
            _ => panic!("expected Backbone"),
        }
    }

    #[test]
    fn test_synthesize_backbone_max_reconnect_tries() {
        let mut section = ConfigSection::new();
        section.set("type", "BackboneInterface");
        section.set("target_host", "host.example");
        section.set("target_port", "4242");
        section.set("max_reconnect_tries", "7");

        let config = synthesize_interface("bb_retries", &section).unwrap();
        match config {
            InterfaceConfig::Backbone(c) => assert_eq!(c.max_reconnect_tries, Some(7)),
            _ => panic!("expected Backbone"),
        }
    }

    #[test]
    fn test_synthesize_backbone_i2p_tunneled() {
        let mut section = ConfigSection::new();
        section.set("type", "BackboneInterface");
        section.set("target_host", "host.example");
        section.set("target_port", "4242");
        section.set("i2p_tunneled", "yes");

        let config = synthesize_interface("bb_i2p", &section).unwrap();
        match config {
            InterfaceConfig::Backbone(c) => assert!(c.i2p_tunneled),
            _ => panic!("expected Backbone"),
        }
    }

    #[test]
    fn test_synthesize_backbone_listen_port_alias() {
        let mut section = ConfigSection::new();
        section.set("type", "BackboneInterface");
        section.set("listen_on", "0.0.0.0");
        section.set("listen_port", "5151");

        let config = synthesize_interface("bb_listen_alias", &section).unwrap();
        match config {
            InterfaceConfig::Backbone(c) => assert_eq!(c.port, 5151),
            _ => panic!("expected Backbone"),
        }
    }

    #[cfg(feature = "serial")]
    #[test]
    fn test_synthesize_ax25kiss() {
        let mut section = ConfigSection::new();
        section.set("type", "AX25KISSInterface");
        section.set("port", "/dev/ttyUSB2");
        section.set("callsign", "NO1CLL");
        section.set("ssid", "0");
        section.set("speed", "115200");
        section.set("preamble", "150");
        section.set("txtail", "10");
        section.set("persistence", "200");
        section.set("slottime", "20");

        let config = synthesize_interface("test_ax25", &section).unwrap();
        match config {
            InterfaceConfig::AX25KISS(c) => {
                assert_eq!(c.name, "test_ax25");
                assert_eq!(c.port, "/dev/ttyUSB2");
                assert_eq!(c.callsign, "NO1CLL");
                assert_eq!(c.ssid, 0);
                assert_eq!(c.baud_rate, 115200);
                assert_eq!(c.preamble, 150);
                assert_eq!(c.txtail, 10);
                assert_eq!(c.persistence, 200);
                assert_eq!(c.slottime, 20);
                assert!(!c.flow_control);
            }
            _ => panic!("expected AX25KISS"),
        }
    }

    #[cfg(feature = "serial")]
    #[test]
    fn test_synthesize_ax25kiss_missing_callsign() {
        let mut section = ConfigSection::new();
        section.set("type", "AX25KISSInterface");
        section.set("port", "/dev/ttyUSB2");

        match synthesize_interface("ax25_no_call", &section) {
            Err(InterfaceFactoryError::MissingField { field, .. }) => {
                assert_eq!(field, "callsign");
            }
            other => panic!("expected MissingField, got {other:?}"),
        }
    }

    #[cfg(feature = "serial")]
    #[test]
    fn test_synthesize_rnode_multi() {
        let mut section = ConfigSection::new();
        section.set("type", "RNodeMultiInterface");
        section.set("port", "/dev/ttyACM0");
        section.set("baud_rate", "230400");
        section.set("flow_control", "yes");

        let mut high = ConfigSection::new();
        high.set("enabled", "yes");
        high.set("vport", "1");
        high.set("frequency", "2400000000");
        high.set("bandwidth", "1625000");
        high.set("txpower", "0");
        high.set("spreadingfactor", "5");
        high.set("codingrate", "5");
        high.set("flow_control", "no");
        high.set("outgoing", "no");
        high.set("airtime_limit_short", "33.5");
        high.set("airtime_limit_long", "88");
        section
            .subsections
            .insert("High Datarate".to_string(), high);

        let mut low = ConfigSection::new();
        low.set("enabled", "yes");
        low.set("vport", "0");
        low.set("frequency", "865600000");
        low.set("bandwidth", "125000");
        low.set("tx_power", "14");
        low.set("spreading_factor", "7");
        low.set("coding_rate", "5");
        section.subsections.insert("Low Datarate".to_string(), low);

        let config = synthesize_interface("test_rnodemulti", &section).unwrap();
        match config {
            InterfaceConfig::RNodeMulti(c) => {
                assert_eq!(c.name, "test_rnodemulti");
                assert_eq!(c.port, "/dev/ttyACM0");
                assert_eq!(c.baud_rate, 230400);
                assert!(c.flow_control);
                assert_eq!(c.subinterfaces.len(), 2);

                let low = &c.subinterfaces[0];
                assert_eq!(low.name, "Low Datarate");
                assert_eq!(low.vport, 0);
                assert_eq!(low.frequency, 865600000);
                assert_eq!(low.bandwidth, 125000);
                assert_eq!(low.spreading_factor, 7);
                assert_eq!(low.coding_rate, 5);
                assert_eq!(low.tx_power, 14);
                assert!(low.flow_control, "parent flow_control is inherited");
                assert!(low.outgoing);

                let high = &c.subinterfaces[1];
                assert_eq!(high.name, "High Datarate");
                assert_eq!(high.vport, 1);
                assert_eq!(high.frequency, 2400000000);
                assert_eq!(high.bandwidth, 1625000);
                assert_eq!(high.spreading_factor, 5);
                assert_eq!(high.coding_rate, 5);
                assert_eq!(high.tx_power, 0);
                assert!(
                    !high.flow_control,
                    "subinterface can override parent flow_control"
                );
                assert!(!high.outgoing);
                assert_eq!(high.st_alock, Some(33.5));
                assert_eq!(high.lt_alock, Some(88.0));
            }
            _ => panic!("expected RNodeMulti"),
        }
    }

    #[cfg(feature = "serial")]
    #[test]
    fn test_synthesize_rnode_multi_no_enabled_subinterfaces() {
        let mut section = ConfigSection::new();
        section.set("type", "RNodeMultiInterface");
        section.set("port", "/dev/ttyACM0");

        let mut disabled = ConfigSection::new();
        disabled.set("enabled", "no");
        disabled.set("vport", "0");
        disabled.set("frequency", "865600000");
        section.subsections.insert("Disabled".to_string(), disabled);

        match synthesize_interface("test_rnodemulti", &section) {
            Err(InterfaceFactoryError::InvalidValue { field, .. }) => {
                assert_eq!(field, "subinterfaces");
            }
            other => panic!("expected InvalidValue, got {other:?}"),
        }
    }

    #[cfg(feature = "serial")]
    #[test]
    fn test_synthesize_rnode_multi_duplicate_vport() {
        let mut section = ConfigSection::new();
        section.set("type", "RNodeMultiInterface");
        section.set("port", "/dev/ttyACM0");

        for name in ["a", "b"] {
            let mut sub = ConfigSection::new();
            sub.set("vport", "0");
            sub.set("frequency", "865600000");
            sub.set("bandwidth", "125000");
            sub.set("spreadingfactor", "7");
            sub.set("codingrate", "5");
            sub.set("txpower", "14");
            section.subsections.insert(name.to_string(), sub);
        }

        match synthesize_interface("test_rnodemulti", &section) {
            Err(InterfaceFactoryError::InvalidValue { field, message }) => {
                assert!(field.ends_with(".vport"));
                assert!(message.contains("duplicate"));
            }
            other => panic!("expected InvalidValue, got {other:?}"),
        }
    }

    #[cfg(feature = "serial")]
    #[test]
    fn test_synthesize_rnode_multi_missing_port() {
        let mut section = ConfigSection::new();
        section.set("type", "RNodeMultiInterface");

        match synthesize_interface("rnodemulti_no_port", &section) {
            Err(InterfaceFactoryError::MissingField { field, .. }) => {
                assert_eq!(field, "port");
            }
            other => panic!("expected MissingField, got {other:?}"),
        }
    }
}
