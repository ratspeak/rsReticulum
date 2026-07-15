//! Weave switching fabric — protocol primitives only.
//!
//! Wire format (WDCL inside HDLC):
//! ```text
//! [HDLC_FLAG] [escaped WDCL] [HDLC_FLAG]
//! WDCL = [ADDR u32][TYPE u8][PAYLOAD…]   ADDR 0xFFFFFFFF = broadcast
//! ```
//! Discovery: Ed25519 challenge-response over WDCL_T_DISCOVER / WDCL_T_CONNECT.
//! Runtime spawn (serial I/O, peer mgmt) not yet wired up.

use crate::traits::InterfaceMode;

pub const WDCL_T_DISCOVER: u8 = 0x00;
pub const WDCL_T_CONNECT: u8 = 0x01;
pub const WDCL_T_CMD: u8 = 0x02;
pub const WDCL_T_LOG: u8 = 0x03;
pub const WDCL_T_DISP: u8 = 0x04;
pub const WDCL_T_ENDPOINT_PKT: u8 = 0x05;
pub const WDCL_T_ENCAP_PROTO: u8 = 0x06;

pub const WDCL_BROADCAST: [u8; 4] = [0xFF, 0xFF, 0xFF, 0xFF];

pub const WDCL_HANDSHAKE_TIMEOUT: f64 = 2.0;

/// WDCL header = `ADDR(4) + TYPE(1)`.
pub const HEADER_MINSIZE: usize = 5;

pub const SWITCH_ID_LEN: usize = 4;
pub const ENDPOINT_ID_LEN: usize = 8;
pub const FLOWSEQ_LEN: usize = 2;
pub const HMAC_LEN: usize = 8;
pub const AUTH_LEN: usize = ENDPOINT_ID_LEN + HMAC_LEN;
pub const PUBKEY_SIZE: usize = 32;
pub const PRVKEY_SIZE: usize = 64;
pub const SIGNATURE_LEN: usize = 64;

pub const HW_MTU: u32 = 1024;
pub const FIXED_MTU: bool = true;
pub const DEFAULT_IFAC_SIZE: usize = 16;
pub const PEERING_TIMEOUT: f64 = 20.0;
pub const BITRATE_GUESS: u64 = 250_000;

pub const MULTI_IF_DEQUE_LEN: usize = 48;
pub const MULTI_IF_DEQUE_TTL: f64 = 0.75;

pub const STATLEN_MAX: usize = 120;
pub const STAT_UPDATE_THROTTLE: f64 = 0.5;

pub const ENDPOINT_QUEUE_LEN: usize = 1024;

pub const CMD_ENDPOINT_PKT: u16 = 0x0001;
pub const CMD_ENDPOINTS_LIST: u16 = 0x0100;
pub const CMD_REMOTE_DISPLAY: u16 = 0x0A00;
pub const CMD_REMOTE_INPUT: u16 = 0x0A01;

// LOG frame payload: [flags u8][ts_ms u32 BE][level u8][event u16 BE][data…]

pub const EVT_MSG: u16 = 0x0000;
pub const EVT_SYSTEM_BOOT: u16 = 0x0001;
pub const EVT_CORE_INIT: u16 = 0x0002;
// "Board hardware initialization" (1.3.8 WeaveInterface.py:342, newer firmware boot event)
pub const EVT_BOARD_INIT: u16 = 0x0003;

// Driver events (0x1xxx)
pub const EVT_DRV_UART_INIT: u16 = 0x1000;
pub const EVT_DRV_USB_CDC_INIT: u16 = 0x1010;
pub const EVT_DRV_USB_CDC_HOST_AVAIL: u16 = 0x1011;
pub const EVT_DRV_USB_CDC_HOST_SUSPEND: u16 = 0x1012;
pub const EVT_DRV_USB_CDC_HOST_RESUME: u16 = 0x1013;
pub const EVT_DRV_USB_CDC_CONNECTED: u16 = 0x1014;
pub const EVT_DRV_USB_CDC_READ_ERR: u16 = 0x1015;
pub const EVT_DRV_USB_CDC_OVERFLOW: u16 = 0x1016;
pub const EVT_DRV_USB_CDC_DROPPED: u16 = 0x1017;
pub const EVT_DRV_USB_CDC_TX_TIMEOUT: u16 = 0x1018;
pub const EVT_DRV_I2C_INIT: u16 = 0x1020;
pub const EVT_DRV_NVS_INIT: u16 = 0x1030;
pub const EVT_DRV_NVS_ERASE: u16 = 0x1031;
pub const EVT_DRV_CRYPTO_INIT: u16 = 0x1040;
pub const EVT_DRV_DISPLAY_INIT: u16 = 0x1050;
pub const EVT_DRV_DISPLAY_BUS_AVAILABLE: u16 = 0x1051;
pub const EVT_DRV_DISPLAY_IO_CONFIGURED: u16 = 0x1052;
pub const EVT_DRV_DISPLAY_PANEL_CREATED: u16 = 0x1053;
pub const EVT_DRV_DISPLAY_PANEL_RESET: u16 = 0x1054;
pub const EVT_DRV_DISPLAY_PANEL_INIT: u16 = 0x1055;
pub const EVT_DRV_DISPLAY_PANEL_ENABLE: u16 = 0x1056;
pub const EVT_DRV_DISPLAY_REMOTE_ENABLE: u16 = 0x1057;
pub const EVT_DRV_W80211_INIT: u16 = 0x1060;
pub const EVT_DRV_W80211_CHANNEL: u16 = 0x1062;
pub const EVT_DRV_W80211_POWER: u16 = 0x1063;

// Kernel events (0x2xxx)
pub const EVT_KRN_LOGGER_INIT: u16 = 0x2000;
pub const EVT_KRN_LOGGER_OUTPUT: u16 = 0x2001;
pub const EVT_KRN_UI_INIT: u16 = 0x2010;

// Protocol events (0x3xxx)
pub const EVT_PROTO_WDCL_INIT: u16 = 0x3000;
pub const EVT_PROTO_WDCL_RUNNING: u16 = 0x3001;
pub const EVT_PROTO_WDCL_CONNECTION: u16 = 0x3002;
pub const EVT_PROTO_WDCL_HOST_ENDPOINT: u16 = 0x3003;
pub const EVT_PROTO_WEAVE_INIT: u16 = 0x3100;
pub const EVT_PROTO_WEAVE_RUNNING: u16 = 0x3101;
pub const EVT_PROTO_WEAVE_EP_ALIVE: u16 = 0x3102;
pub const EVT_PROTO_WEAVE_EP_TIMEOUT: u16 = 0x3103;
pub const EVT_PROTO_WEAVE_EP_VIA: u16 = 0x3104;

// Service events
pub const EVT_SRVCTL_REMOTE_DISPLAY: u16 = 0xA000;
pub const EVT_INTERFACE_REGISTERED: u16 = 0xD000;

// Stats events (0xExxx)
pub const EVT_STAT_STATE: u16 = 0xE000;
pub const EVT_STAT_UPTIME: u16 = 0xE001;
pub const EVT_STAT_TIMEBASE: u16 = 0xE002;
pub const EVT_STAT_CPU: u16 = 0xE003;
pub const EVT_STAT_TASK_CPU: u16 = 0xE004;
// EVT_STAT_MEMORY data = [free u32 BE][total u32 BE] (1.3.8 WeaveInterface.py:760-761)
pub const EVT_STAT_MEMORY: u16 = 0xE005;
pub const EVT_STAT_STORAGE: u16 = 0xE006;

// Error events
pub const EVT_SYSERR_MEM_EXHAUSTED: u16 = 0xF000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PhysicalMedium {
    Usb = 0x01,
    Uart = 0x02,
    W80211 = 0x03,
    Ble = 0x04,
    Lora = 0x05,
    Ethernet = 0x06,
    Wifi = 0x07,
    Tcp = 0x08,
    Udp = 0x09,
    Ir = 0x0A,
    Afsk = 0x0B,
    Gpio = 0x0C,
    Spi = 0x0D,
    I2c = 0x0E,
    Can = 0x0F,
    Dma = 0x10,
}

impl PhysicalMedium {
    pub fn from_u8(val: u8) -> Option<Self> {
        match val {
            0x01 => Some(Self::Usb),
            0x02 => Some(Self::Uart),
            0x03 => Some(Self::W80211),
            0x04 => Some(Self::Ble),
            0x05 => Some(Self::Lora),
            0x06 => Some(Self::Ethernet),
            0x07 => Some(Self::Wifi),
            0x08 => Some(Self::Tcp),
            0x09 => Some(Self::Udp),
            0x0A => Some(Self::Ir),
            0x0B => Some(Self::Afsk),
            0x0C => Some(Self::Gpio),
            0x0D => Some(Self::Spi),
            0x0E => Some(Self::I2c),
            0x0F => Some(Self::Can),
            0x10 => Some(Self::Dma),
            _ => None,
        }
    }

    pub fn short_name(self) -> &'static str {
        match self {
            Self::Usb => "usb",
            Self::Uart => "uart",
            Self::W80211 => "mw",
            Self::Ble => "ble",
            Self::Lora => "lora",
            Self::Ethernet => "eth",
            Self::Wifi => "wifi",
            Self::Tcp => "tcp",
            Self::Udp => "udp",
            Self::Ir => "ir",
            Self::Afsk => "afsk",
            Self::Gpio => "gpio",
            Self::Spi => "spi",
            Self::I2c => "i2c",
            Self::Can => "can",
            Self::Dma => "dma",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DeviceLogLevel {
    Force = 0,
    Critical = 1,
    Error = 2,
    Warning = 3,
    Notice = 4,
    Info = 5,
    Verbose = 6,
    Debug = 7,
    Extreme = 8,
    System = 9,
}

impl DeviceLogLevel {
    pub fn from_u8(val: u8) -> Option<Self> {
        match val {
            0 => Some(Self::Force),
            1 => Some(Self::Critical),
            2 => Some(Self::Error),
            3 => Some(Self::Warning),
            4 => Some(Self::Notice),
            5 => Some(Self::Info),
            6 => Some(Self::Verbose),
            7 => Some(Self::Debug),
            8 => Some(Self::Extreme),
            9 => Some(Self::System),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WdclFrame {
    pub addr: [u8; 4],
    pub msg_type: u8,
    pub payload: Vec<u8>,
}

pub fn wdcl_frame(addr: [u8; 4], msg_type: u8, payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(HEADER_MINSIZE + payload.len());
    frame.extend_from_slice(&addr);
    frame.push(msg_type);
    frame.extend_from_slice(payload);
    frame
}

/// Parse WDCL after HDLC deframing; `None` if shorter than `HEADER_MINSIZE`.
pub fn wdcl_parse(data: &[u8]) -> Option<WdclFrame> {
    if data.len() < HEADER_MINSIZE {
        return None;
    }
    let mut addr = [0u8; 4];
    addr.copy_from_slice(&data[..4]);
    Some(WdclFrame {
        addr,
        msg_type: data[4],
        payload: data[5..].to_vec(),
    })
}

/// `WDCL_T_CMD` with big-endian u16 command ID prefix.
pub fn wdcl_command(dest: [u8; 4], command: u16, data: &[u8]) -> Vec<u8> {
    let mut payload = Vec::with_capacity(2 + data.len());
    payload.push((command >> 8) as u8);
    payload.push((command & 0xFF) as u8);
    payload.extend_from_slice(data);
    wdcl_frame(dest, WDCL_T_CMD, &payload)
}

#[derive(Debug, Clone)]
pub struct LogFrame {
    /// Milliseconds since device boot.
    pub timestamp_ms: u32,
    pub level: u8,
    pub event: u16,
    pub data: Vec<u8>,
}

pub fn parse_log_frame(payload: &[u8]) -> Option<LogFrame> {
    if payload.len() < 8 {
        return None;
    }
    let _flags = payload[0];
    let timestamp_ms = u32::from_be_bytes([payload[1], payload[2], payload[3], payload[4]]);
    let level = payload[5];
    let event = u16::from_be_bytes([payload[6], payload[7]]);
    let data = payload[8..].to_vec();
    Some(LogFrame {
        timestamp_ms,
        level,
        event,
        data,
    })
}

/// Weave interface config (runtime spawn not yet implemented).
#[derive(Debug, Clone)]
pub struct WeaveInterfaceConfig {
    pub name: String,
    pub port: String,
    pub configured_bitrate: Option<u64>,
    pub mode: InterfaceMode,
}

impl WeaveInterfaceConfig {
    pub fn new(name: &str, port: &str) -> Self {
        Self {
            name: name.to_string(),
            port: port.to_string(),
            configured_bitrate: None,
            mode: InterfaceMode::Full,
        }
    }
}

// Runtime spawn is not wired yet. A production path needs WDCL discovery and
// handshake over serial, Ed25519 verification, per-peer sub-interfaces with
// PEERING_TIMEOUT/MULTI_IF_DEQUE_*, and interface_factory wiring.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wdcl_message_types() {
        assert_eq!(WDCL_T_DISCOVER, 0x00);
        assert_eq!(WDCL_T_CONNECT, 0x01);
        assert_eq!(WDCL_T_CMD, 0x02);
        assert_eq!(WDCL_T_LOG, 0x03);
        assert_eq!(WDCL_T_DISP, 0x04);
        assert_eq!(WDCL_T_ENDPOINT_PKT, 0x05);
        assert_eq!(WDCL_T_ENCAP_PROTO, 0x06);
    }

    #[test]
    fn test_wdcl_broadcast() {
        assert_eq!(WDCL_BROADCAST, [0xFF, 0xFF, 0xFF, 0xFF]);
    }

    #[test]
    fn test_header_minsize() {
        assert_eq!(HEADER_MINSIZE, 5);
    }

    #[test]
    fn test_weave_constants() {
        assert_eq!(HW_MTU, 1024);
        const { assert!(FIXED_MTU) };
        assert_eq!(PEERING_TIMEOUT, 20.0);
        assert_eq!(BITRATE_GUESS, 250_000);
        assert_eq!(DEFAULT_IFAC_SIZE, 16);
    }

    #[test]
    fn test_identity_sizes() {
        assert_eq!(SWITCH_ID_LEN, 4);
        assert_eq!(ENDPOINT_ID_LEN, 8);
        assert_eq!(PUBKEY_SIZE, 32);
        assert_eq!(SIGNATURE_LEN, 64);
        assert_eq!(AUTH_LEN, ENDPOINT_ID_LEN + HMAC_LEN);
    }

    #[test]
    fn test_dedup_constants() {
        assert_eq!(MULTI_IF_DEQUE_LEN, 48);
        assert_eq!(MULTI_IF_DEQUE_TTL, 0.75);
    }

    #[test]
    fn test_wdcl_frame_encode() {
        let frame = wdcl_frame([0x01, 0x02, 0x03, 0x04], WDCL_T_ENDPOINT_PKT, b"hello");
        assert_eq!(frame.len(), 10);
        assert_eq!(&frame[..4], &[0x01, 0x02, 0x03, 0x04]);
        assert_eq!(frame[4], WDCL_T_ENDPOINT_PKT);
        assert_eq!(&frame[5..], b"hello");
    }

    #[test]
    fn test_wdcl_frame_broadcast() {
        let frame = wdcl_frame(WDCL_BROADCAST, WDCL_T_DISCOVER, &[0xAA]);
        assert_eq!(&frame[..4], &WDCL_BROADCAST);
        assert_eq!(frame[4], WDCL_T_DISCOVER);
        assert_eq!(&frame[5..], &[0xAA]);
    }

    #[test]
    fn test_wdcl_frame_empty_payload() {
        let frame = wdcl_frame([0; 4], WDCL_T_CMD, &[]);
        assert_eq!(frame.len(), 5);
    }

    #[test]
    fn test_wdcl_parse_valid() {
        let raw = [0x0A, 0x0B, 0x0C, 0x0D, WDCL_T_LOG, 0x01, 0x02];
        let parsed = wdcl_parse(&raw).unwrap();
        assert_eq!(parsed.addr, [0x0A, 0x0B, 0x0C, 0x0D]);
        assert_eq!(parsed.msg_type, WDCL_T_LOG);
        assert_eq!(parsed.payload, vec![0x01, 0x02]);
    }

    #[test]
    fn test_wdcl_parse_minimum() {
        let raw = [0x00, 0x00, 0x00, 0x00, WDCL_T_DISCOVER];
        let parsed = wdcl_parse(&raw).unwrap();
        assert_eq!(parsed.addr, [0; 4]);
        assert_eq!(parsed.msg_type, WDCL_T_DISCOVER);
        assert!(parsed.payload.is_empty());
    }

    #[test]
    fn test_wdcl_parse_too_short() {
        assert!(wdcl_parse(&[]).is_none());
        assert!(wdcl_parse(&[0x00]).is_none());
        assert!(wdcl_parse(&[0x00, 0x00, 0x00, 0x00]).is_none());
    }

    #[test]
    fn test_wdcl_frame_roundtrip() {
        let addr = [0xDE, 0xAD, 0xBE, 0xEF];
        let payload = b"test data";
        let encoded = wdcl_frame(addr, WDCL_T_ENDPOINT_PKT, payload);
        let decoded = wdcl_parse(&encoded).unwrap();
        assert_eq!(decoded.addr, addr);
        assert_eq!(decoded.msg_type, WDCL_T_ENDPOINT_PKT);
        assert_eq!(decoded.payload, payload);
    }

    #[test]
    fn test_wdcl_command() {
        let dest = [0x01, 0x02, 0x03, 0x04];
        let frame = wdcl_command(dest, CMD_ENDPOINT_PKT, &[0xFF]);
        let parsed = wdcl_parse(&frame).unwrap();
        assert_eq!(parsed.msg_type, WDCL_T_CMD);
        assert_eq!(parsed.payload, vec![0x00, 0x01, 0xFF]);
    }

    #[test]
    fn test_wdcl_command_remote_display() {
        let frame = wdcl_command([0; 4], CMD_REMOTE_DISPLAY, &[0x01]);
        let parsed = wdcl_parse(&frame).unwrap();
        assert_eq!(parsed.payload[0], 0x0A);
        assert_eq!(parsed.payload[1], 0x00);
        assert_eq!(parsed.payload[2], 0x01);
    }

    #[test]
    fn test_parse_log_frame() {
        // flags=0, ts=1000ms, level=INFO, event=EVT_SYSTEM_BOOT, data="ok"
        let payload = [0x00, 0x00, 0x00, 0x03, 0xE8, 0x05, 0x00, 0x01, b'o', b'k'];
        let frame = parse_log_frame(&payload).unwrap();
        assert_eq!(frame.timestamp_ms, 1000);
        assert_eq!(frame.level, 5);
        assert_eq!(frame.event, EVT_SYSTEM_BOOT);
        assert_eq!(frame.data, b"ok");
    }

    #[test]
    fn test_boot_event_codes() {
        assert_eq!(EVT_MSG, 0x0000);
        assert_eq!(EVT_SYSTEM_BOOT, 0x0001);
        assert_eq!(EVT_CORE_INIT, 0x0002);
        assert_eq!(EVT_BOARD_INIT, 0x0003);
    }

    #[test]
    fn test_parse_log_frame_board_init() {
        // flags=0, ts=42ms, level=NOTICE, event=EVT_BOARD_INIT, no data
        let payload = [0x00, 0x00, 0x00, 0x00, 0x2A, 0x04, 0x00, 0x03];
        let frame = parse_log_frame(&payload).unwrap();
        assert_eq!(frame.timestamp_ms, 42);
        assert_eq!(frame.event, EVT_BOARD_INIT);
        assert!(frame.data.is_empty());
    }

    #[test]
    fn test_parse_log_frame_too_short() {
        assert!(parse_log_frame(&[0; 7]).is_none());
        assert!(parse_log_frame(&[]).is_none());
    }

    #[test]
    fn test_parse_log_frame_no_data() {
        let payload = [0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x30, 0x00];
        let frame = parse_log_frame(&payload).unwrap();
        assert_eq!(frame.event, EVT_PROTO_WDCL_INIT);
        assert!(frame.data.is_empty());
    }

    #[test]
    fn test_physical_medium_from_u8() {
        assert_eq!(PhysicalMedium::from_u8(0x03), Some(PhysicalMedium::W80211));
        assert_eq!(PhysicalMedium::from_u8(0x05), Some(PhysicalMedium::Lora));
        assert_eq!(PhysicalMedium::from_u8(0x10), Some(PhysicalMedium::Dma));
        assert_eq!(PhysicalMedium::from_u8(0x00), None);
        assert_eq!(PhysicalMedium::from_u8(0xFF), None);
    }

    #[test]
    fn test_physical_medium_short_name() {
        assert_eq!(PhysicalMedium::W80211.short_name(), "mw");
        assert_eq!(PhysicalMedium::Lora.short_name(), "lora");
        assert_eq!(PhysicalMedium::Ethernet.short_name(), "eth");
    }

    #[test]
    fn test_device_log_level() {
        assert_eq!(DeviceLogLevel::from_u8(0), Some(DeviceLogLevel::Force));
        assert_eq!(DeviceLogLevel::from_u8(5), Some(DeviceLogLevel::Info));
        assert_eq!(DeviceLogLevel::from_u8(9), Some(DeviceLogLevel::System));
        assert_eq!(DeviceLogLevel::from_u8(10), None);
    }

    #[test]
    fn test_config_defaults() {
        let cfg = WeaveInterfaceConfig::new("weave0", "/dev/ttyUSB0");
        assert_eq!(cfg.name, "weave0");
        assert_eq!(cfg.port, "/dev/ttyUSB0");
        assert_eq!(cfg.mode, InterfaceMode::Full);
        assert!(cfg.configured_bitrate.is_none());
    }
}
