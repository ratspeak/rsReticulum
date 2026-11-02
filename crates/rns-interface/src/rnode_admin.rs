//! Extended-KISS administrative frame codecs and command builders used by
//! `rnodeconf`. These helpers construct or decode bytes; they perform no
//! transport I/O or device authorization.

use std::net::Ipv4Addr;

use crate::{kiss, rnode};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdminFrame {
    pub command: u8,
    pub payload: Vec<u8>,
}

pub fn encode_frame(command: u8, payload: &[u8]) -> Vec<u8> {
    kiss::frame_with_command(command, payload)
}

pub fn decode_frames(raw: &[u8]) -> Vec<AdminFrame> {
    let mut deframer = kiss::RawKissDeframer::new();
    deframer
        .feed(raw)
        .into_iter()
        .map(|(command, payload)| AdminFrame { command, payload })
        .collect()
}

pub fn u32_payload(value: u32) -> [u8; 4] {
    value.to_be_bytes()
}

pub fn parse_u32(payload: &[u8]) -> Option<u32> {
    let bytes: [u8; 4] = payload.try_into().ok()?;
    Some(u32::from_be_bytes(bytes))
}

pub fn parse_bt_pin(frame: &AdminFrame) -> Option<u32> {
    (frame.command == rnode::CMD_BT_PIN)
        .then(|| parse_u32(&frame.payload))
        .flatten()
}

pub fn bool_payload(enabled: bool) -> [u8; 1] {
    [u8::from(enabled)]
}

pub fn nullable_string_payload(value: Option<&str>) -> Vec<u8> {
    match value {
        Some(value) if !value.is_empty() => {
            let mut out = value.as_bytes().to_vec();
            out.push(0);
            out
        }
        _ => vec![0],
    }
}

pub fn ipv4_payload(addr: Ipv4Addr) -> [u8; 4] {
    addr.octets()
}

pub fn detect_sequence() -> Vec<AdminFrame> {
    vec![
        frame(rnode::CMD_DETECT, &[rnode::DETECT_REQ]),
        frame(rnode::CMD_FW_VERSION, &[0]),
        frame(rnode::CMD_PLATFORM, &[0]),
        frame(rnode::CMD_MCU, &[0]),
        frame(rnode::CMD_BOARD, &[0]),
        frame(rnode::CMD_DEV_HASH, &[1]),
        frame(rnode::CMD_HASHES, &[1]),
        frame(rnode::CMD_HASHES, &[2]),
    ]
}

pub fn eeprom_read_frame() -> AdminFrame {
    frame(rnode::CMD_ROM_READ, &[0])
}

pub fn eeprom_write_frame(address: u8, value: u8) -> AdminFrame {
    frame(rnode::CMD_ROM_WRITE, &[address, value])
}

pub fn eeprom_wipe_frame() -> AdminFrame {
    frame(rnode::CMD_ROM_WIPE, &[0xF8])
}

pub fn reset_frame() -> AdminFrame {
    frame(rnode::CMD_RESET, &[0xF8])
}

pub fn firmware_update_frame() -> AdminFrame {
    frame(rnode::CMD_FW_UPD, &[1])
}

pub fn firmware_hash_frame(hash: &[u8; 32]) -> AdminFrame {
    frame(rnode::CMD_FW_HASH, hash)
}

pub fn device_signature_frame(signature: &[u8; 64]) -> AdminFrame {
    frame(rnode::CMD_DEV_SIG, signature)
}

pub fn frame(command: u8, payload: &[u8]) -> AdminFrame {
    AdminFrame {
        command,
        payload: payload.to_vec(),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum WifiMode {
    Off = 0,
    Station = 1,
    AccessPoint = 2,
}

impl WifiMode {
    pub fn payload(self) -> [u8; 1] {
        [self as u8]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extended_commands_round_trip_without_masking() {
        let mut raw = Vec::new();
        raw.extend_from_slice(&encode_frame(rnode::CMD_WIFI_IP, &[192, 168, 1, 10]));
        raw.extend_from_slice(&encode_frame(rnode::CMD_WIFI_NM, &[255, 255, 255, 0]));
        raw.extend_from_slice(&encode_frame(rnode::CMD_BT_PIN, &123456u32.to_be_bytes()));

        let frames = decode_frames(&raw);
        assert_eq!(frames[0].command, 0x84);
        assert_eq!(frames[0].payload, vec![192, 168, 1, 10]);
        assert_eq!(frames[1].command, 0x85);
        assert_eq!(frames[2].command, 0x62);
        assert_eq!(parse_bt_pin(&frames[2]), Some(123456));
    }

    #[test]
    fn payload_helpers_match_upstream_shapes() {
        assert_eq!(u32_payload(868_000_000), [0x33, 0xBC, 0xA1, 0x00]);
        assert_eq!(bool_payload(true), [1]);
        assert_eq!(WifiMode::AccessPoint.payload(), [2]);
        assert_eq!(nullable_string_payload(None), vec![0]);
        assert_eq!(nullable_string_payload(Some("RNode")), b"RNode\0");
        assert_eq!(
            ipv4_payload(Ipv4Addr::new(192, 168, 1, 10)),
            [192, 168, 1, 10]
        );
    }

    #[test]
    fn admin_frame_builders_match_upstream_commands() {
        let sequence = detect_sequence();
        assert_eq!(
            sequence.iter().map(|f| f.command).collect::<Vec<_>>(),
            vec![0x08, 0x50, 0x48, 0x49, 0x47, 0x56, 0x60, 0x60]
        );
        assert_eq!(eeprom_read_frame(), frame(rnode::CMD_ROM_READ, &[0]));
        assert_eq!(
            eeprom_write_frame(0x9B, 0x73),
            frame(rnode::CMD_ROM_WRITE, &[0x9B, 0x73])
        );
        assert_eq!(eeprom_wipe_frame(), frame(rnode::CMD_ROM_WIPE, &[0xF8]));
        assert_eq!(reset_frame(), frame(rnode::CMD_RESET, &[0xF8]));
        assert_eq!(firmware_update_frame(), frame(rnode::CMD_FW_UPD, &[1]));
    }
}
