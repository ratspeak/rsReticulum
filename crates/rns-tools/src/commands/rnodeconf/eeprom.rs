//! RNode EEPROM layout helpers.

use super::model;

pub const EEPROM_SIZE: usize = 296;
pub const ADDR_PRODUCT: usize = 0x00;
pub const ADDR_MODEL: usize = 0x01;
pub const ADDR_HW_REV: usize = 0x02;
pub const ADDR_SERIAL: usize = 0x03;
pub const ADDR_MADE: usize = 0x07;
pub const ADDR_CHKSUM: usize = 0x0B;
pub const ADDR_SIGNATURE: usize = 0x1B;
pub const ADDR_INFO_LOCK: usize = 0x9B;
pub const ADDR_CONF_SF: usize = 0x9C;
pub const ADDR_CONF_CR: usize = 0x9D;
pub const ADDR_CONF_TXP: usize = 0x9E;
pub const ADDR_CONF_BW: usize = 0x9F;
pub const ADDR_CONF_FREQ: usize = 0xA3;
pub const ADDR_CONF_OK: usize = 0xA7;

pub const ADDR_CONF_BT: usize = 0xB0;
pub const ADDR_CONF_DSET: usize = 0xB1;
pub const ADDR_CONF_DINT: usize = 0xB2;
pub const ADDR_CONF_DADR: usize = 0xB3;
pub const ADDR_CONF_DBLK: usize = 0xB4;
pub const ADDR_CONF_PSET: usize = 0xB5;
pub const ADDR_CONF_PINT: usize = 0xB6;
pub const ADDR_CONF_BSET: usize = 0xB7;
pub const ADDR_CONF_DROT: usize = 0xB8;
pub const ADDR_CONF_DIA: usize = 0xB9;
pub const ADDR_CONF_WIFI: usize = 0xBA;
pub const ADDR_CONF_WCHN: usize = 0xBB;

pub const ADDR_CONF_SSID: usize = 0x00;
pub const ADDR_CONF_PSK: usize = 0x21;
pub const ADDR_CONF_IP: usize = 0x42;
pub const ADDR_CONF_NM: usize = 0x46;

pub const INFO_LOCK_BYTE: u8 = 0x73;
pub const CONF_OK_BYTE: u8 = 0x73;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityInfo {
    pub product: u8,
    pub model: u8,
    pub hw_rev: u8,
    pub serial: u32,
    pub made: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RadioConfig {
    pub spreading_factor: u8,
    pub coding_rate: u8,
    pub tx_power: u8,
    pub bandwidth: u32,
    pub frequency: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EepromImage {
    bytes: Vec<u8>,
}

impl EepromImage {
    pub fn new(bytes: Vec<u8>) -> Result<Self, String> {
        if bytes.len() < ADDR_CONF_OK + 1 {
            return Err(format!("EEPROM image too short: {} bytes", bytes.len()));
        }
        Ok(Self { bytes })
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn identity(&self) -> IdentityInfo {
        IdentityInfo {
            product: self.bytes[ADDR_PRODUCT],
            model: self.bytes[ADDR_MODEL],
            hw_rev: self.bytes[ADDR_HW_REV],
            serial: read_be_u32(&self.bytes, ADDR_SERIAL),
            made: read_be_u32(&self.bytes, ADDR_MADE),
        }
    }

    pub fn stored_checksum(&self) -> [u8; 16] {
        let mut out = [0u8; 16];
        out.copy_from_slice(&self.bytes[ADDR_CHKSUM..ADDR_CHKSUM + 16]);
        out
    }

    pub fn calculated_checksum(&self) -> [u8; 16] {
        identity_checksum(&self.identity())
    }

    pub fn checksum_valid(&self) -> bool {
        self.stored_checksum() == self.calculated_checksum()
    }

    pub fn info_locked(&self) -> bool {
        self.bytes[ADDR_INFO_LOCK] == INFO_LOCK_BYTE
    }

    pub fn radio_config(&self) -> Option<RadioConfig> {
        (self.bytes[ADDR_CONF_OK] == CONF_OK_BYTE).then(|| RadioConfig {
            spreading_factor: self.bytes[ADDR_CONF_SF],
            coding_rate: self.bytes[ADDR_CONF_CR],
            tx_power: self.bytes[ADDR_CONF_TXP],
            bandwidth: read_be_u32(&self.bytes, ADDR_CONF_BW),
            frequency: read_be_u32(&self.bytes, ADDR_CONF_FREQ),
        })
    }
}

/// Upstream `rnodeconf --config` summary (`main()`, args.config branch).
/// Returns the decode error lines and the block, each line as printed.
pub fn device_configuration_lines(
    eeprom: &[u8],
    cfg_sector: Option<&[u8]>,
    show_psk: bool,
) -> Vec<String> {
    let byte = |address: usize| eeprom.get(address).copied().unwrap_or(0xFF);
    let bt = byte(ADDR_CONF_BT);
    let dint = byte(ADDR_CONF_DINT);
    let dadr = byte(ADDR_CONF_DADR);
    let dblk = byte(ADDR_CONF_DBLK);
    let drot = byte(ADDR_CONF_DROT);
    let pset = byte(ADDR_CONF_PSET);
    let pint = byte(ADDR_CONF_PINT);
    let bset = byte(ADDR_CONF_BSET);
    let dia = byte(ADDR_CONF_DIA);
    let wifi = byte(ADDR_CONF_WIFI);
    let mut wchn = byte(ADDR_CONF_WCHN);
    let mut lines = Vec::new();
    let (mut ssid, mut psk, mut ip, mut nm) = (None, None, None, None);

    if !(1..=14).contains(&wchn) {
        wchn = 1;
    }
    if let Some(cfg) = cfg_sector.filter(|cfg| !cfg.is_empty()) {
        let cfg_byte = |address: usize| cfg.get(address).copied().unwrap_or(0x00);
        let string_at = |start: usize| -> Vec<u8> {
            (0..32)
                .map(|offset| cfg_byte(start + offset))
                .take_while(|&b| b != 0x00 && b != 0xFF)
                .collect()
        };
        let quad_at = |start: usize| -> Option<String> {
            let quad: Vec<u8> = (0..4).map(|offset| cfg_byte(start + offset)).collect();
            (quad != [255; 4] && quad != [0; 4])
                .then(|| format!("{}.{}.{}.{}", quad[0], quad[1], quad[2], quad[3]))
        };
        match String::from_utf8(string_at(ADDR_CONF_SSID)) {
            Ok(value) => ssid = Some(value),
            Err(_) => lines.push("Error: Could not decode WiFi SSID read from device".to_string()),
        }
        let psk_bytes = string_at(ADDR_CONF_PSK);
        ip = quad_at(ADDR_CONF_IP);
        nm = quad_at(ADDR_CONF_NM);
        if wifi == 0x02 {
            ip = Some("10.0.0.1".to_string());
            nm = Some("255.255.255.0".to_string());
        }
        match String::from_utf8(psk_bytes) {
            Ok(value) if !show_psk && !value.is_empty() => {
                psk = Some("*".repeat(value.chars().count()))
            }
            Ok(value) => psk = Some(value),
            Err(_) => lines.push("Error: Could not decode WiFi PSK read from device".to_string()),
        }
    }

    lines.push(String::new());
    lines.push("Device configuration:".to_string());
    lines.push(format!(
        "  Bluetooth              : {}",
        if bt == 0x73 { "Enabled" } else { "Disabled" }
    ));
    lines.push(format!(
        "  WiFi                   : {}",
        match wifi {
            0x01 => "Enabled (Station)",
            0x02 => "Enabled (AP)",
            _ => "Disabled",
        }
    ));
    if wifi == 0x01 || wifi == 0x02 {
        lines.push(format!("    Channel              : {wchn}"));
        lines.push(format!(
            "    SSID                 : {}",
            non_empty(&ssid).unwrap_or("Not set")
        ));
        lines.push(format!(
            "    PSK                  : {}",
            non_empty(&psk).unwrap_or("Not set")
        ));
        lines.push(format!(
            "    IP Address           : {}",
            non_empty(&ip).unwrap_or("DHCP")
        ));
        if let (Some(_), Some(nm)) = (non_empty(&ip), non_empty(&nm)) {
            lines.push(format!("    Network Mask         : {nm}"));
        }
    }
    lines.push(format!(
        "  Interference avoidance : {}",
        if dia == 0x00 { "Enabled" } else { "Disabled" }
    ));
    lines.push(format!("  Display brightness     : {dint}"));
    if dadr == 0xFF {
        lines.push("  Display address        : Default".to_string());
    } else {
        lines.push(format!("  Display address        : {dadr:02x}"));
    }
    if bset == 0x73 && dblk != 0x00 {
        lines.push(format!("  Display blanking       : {dblk}s"));
    } else {
        lines.push("  Display blanking       : Disabled".to_string());
    }
    let rotation = match drot {
        0x00 => "Landscape".to_string(),
        0x01 => "Portrait".to_string(),
        0x02 => "Landscape 180".to_string(),
        0x03 => "Portrait 180".to_string(),
        0xFF => "Default".to_string(),
        // Upstream raises on these values; show the stored byte instead.
        other => other.to_string(),
    };
    lines.push(format!("  Display rotation       : {rotation}"));
    if pset == 0x73 {
        lines.push(format!("  Neopixel Intensity     : {pint}"));
    }
    lines.push(String::new());
    lines
}

fn non_empty(value: &Option<String>) -> Option<&str> {
    value.as_deref().filter(|v| !v.is_empty())
}

pub fn identity_checksum(info: &IdentityInfo) -> [u8; 16] {
    md5_digest(&identity_checksum_input(info))
}

pub fn identity_checksum_input(info: &IdentityInfo) -> [u8; 11] {
    let mut input = [0u8; 11];
    input[0] = info.product;
    input[1] = model::normalize_eeprom_model(info.model);
    input[2] = info.hw_rev;
    input[3..7].copy_from_slice(&info.serial.to_be_bytes());
    input[7..11].copy_from_slice(&info.made.to_be_bytes());
    input
}

/// nRF52 info-block write: every byte, then up to three read-back passes that
/// rewrite the bytes that differ. `Ok(false)`: never matched, so no lock byte.
pub fn write_with_read_back<E>(
    info: &[u8],
    mut write: impl FnMut(usize, u8) -> Result<(), E>,
    mut read_back: impl FnMut() -> Result<Option<Vec<u8>>, E>,
) -> Result<bool, E> {
    let mut pending = unwritten_info_bytes(info, None);
    for _ in 0..=3 {
        for &(address, value) in &pending {
            write(address, value)?;
        }
        pending = unwritten_info_bytes(info, read_back()?.as_deref());
        if pending.is_empty() {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Info-block bytes (`(address, value)` from address 0) still to write: all of
/// them before the first write, else those the read-back image lacks.
fn unwritten_info_bytes(info: &[u8], read_back: Option<&[u8]>) -> Vec<(usize, u8)> {
    info.iter()
        .copied()
        .enumerate()
        .filter(|&(address, value)| {
            read_back.is_none_or(|image| image.get(address) != Some(&value))
        })
        .collect()
}

fn read_be_u32(bytes: &[u8], start: usize) -> u32 {
    u32::from_be_bytes(
        bytes[start..start + 4]
            .try_into()
            .expect("slice length checked"),
    )
}

pub fn md5_digest(input: &[u8]) -> [u8; 16] {
    const S: [u32; 64] = [
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5,
        9, 14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10,
        15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
    ];
    const K: [u32; 64] = [
        0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613,
        0xfd469501, 0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193,
        0xa679438e, 0x49b40821, 0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d,
        0x02441453, 0xd8a1e681, 0xe7d3fbc8, 0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
        0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a, 0xfffa3942, 0x8771f681, 0x6d9d6122,
        0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70, 0x289b7ec6, 0xeaa127fa,
        0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665, 0xf4292244,
        0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
        0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb,
        0xeb86d391,
    ];

    let bit_len = (input.len() as u64) * 8;
    let mut msg = input.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_le_bytes());

    let mut a0 = 0x67452301u32;
    let mut b0 = 0xefcdab89u32;
    let mut c0 = 0x98badcfeu32;
    let mut d0 = 0x10325476u32;

    for chunk in msg.as_chunks::<64>().0 {
        let mut m = [0u32; 16];
        for (i, word) in chunk.as_chunks::<4>().0.iter().enumerate() {
            m[i] = u32::from_le_bytes(*word);
        }

        let mut a = a0;
        let mut b = b0;
        let mut c = c0;
        let mut d = d0;

        for i in 0..64 {
            let (f, g) = if i < 16 {
                ((b & c) | ((!b) & d), i)
            } else if i < 32 {
                ((d & b) | ((!d) & c), (5 * i + 1) % 16)
            } else if i < 48 {
                (b ^ c ^ d, (3 * i + 5) % 16)
            } else {
                (c ^ (b | (!d)), (7 * i) % 16)
            };
            let next = b.wrapping_add(
                a.wrapping_add(f)
                    .wrapping_add(K[i])
                    .wrapping_add(m[g])
                    .rotate_left(S[i]),
            );
            a = d;
            d = c;
            c = b;
            b = next;
        }

        a0 = a0.wrapping_add(a);
        b0 = b0.wrapping_add(b);
        c0 = c0.wrapping_add(c);
        d0 = d0.wrapping_add(d);
    }

    let mut out = [0u8; 16];
    out[0..4].copy_from_slice(&a0.to_le_bytes());
    out[4..8].copy_from_slice(&b0.to_le_bytes());
    out[8..12].copy_from_slice(&c0.to_le_bytes());
    out[12..16].copy_from_slice(&d0.to_le_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn md5_vectors_match_reference() {
        assert_eq!(
            hex::encode(md5_digest(b"")),
            "d41d8cd98f00b204e9800998ecf8427e"
        );
        assert_eq!(
            hex::encode(md5_digest(b"abc")),
            "900150983cd24fb0d6963f7d28e17f72"
        );
    }

    #[test]
    fn identity_checksum_matches_python_hashlib_vector() {
        let info = IdentityInfo {
            product: model::PRODUCT_RNODE,
            model: 0xA4,
            hw_rev: 1,
            serial: 0x01020304,
            made: 0x6553F100,
        };
        assert_eq!(
            hex::encode(identity_checksum(&info)),
            "e5ee1a1964bfd72e7da9147942b6f9af"
        );
    }

    #[test]
    fn eeprom_image_parses_identity_and_radio_config() {
        let info = IdentityInfo {
            product: model::PRODUCT_RAK4631,
            model: 0x11,
            hw_rev: 2,
            serial: 0x12345678,
            made: 0x5F3759DF,
        };
        let mut bytes = vec![0u8; EEPROM_SIZE];
        bytes[ADDR_PRODUCT] = info.product;
        bytes[ADDR_MODEL] = info.model;
        bytes[ADDR_HW_REV] = info.hw_rev;
        bytes[ADDR_SERIAL..ADDR_SERIAL + 4].copy_from_slice(&info.serial.to_be_bytes());
        bytes[ADDR_MADE..ADDR_MADE + 4].copy_from_slice(&info.made.to_be_bytes());
        bytes[ADDR_CHKSUM..ADDR_CHKSUM + 16].copy_from_slice(&identity_checksum(&info));
        bytes[ADDR_INFO_LOCK] = INFO_LOCK_BYTE;
        bytes[ADDR_CONF_SF] = 7;
        bytes[ADDR_CONF_CR] = 5;
        bytes[ADDR_CONF_TXP] = 14;
        bytes[ADDR_CONF_BW..ADDR_CONF_BW + 4].copy_from_slice(&125000u32.to_be_bytes());
        bytes[ADDR_CONF_FREQ..ADDR_CONF_FREQ + 4].copy_from_slice(&868000000u32.to_be_bytes());
        bytes[ADDR_CONF_OK] = CONF_OK_BYTE;

        let image = EepromImage::new(bytes).unwrap();
        assert_eq!(image.identity(), info);
        assert!(image.checksum_valid());
        assert!(image.info_locked());
        assert_eq!(
            image.radio_config(),
            Some(RadioConfig {
                spreading_factor: 7,
                coding_rate: 5,
                tx_power: 14,
                bandwidth: 125000,
                frequency: 868000000,
            })
        );
    }

    #[test]
    fn nrf52_info_write_rewrites_dropped_bytes_and_gives_up_after_three_passes() {
        let info: Vec<u8> = (0..155).map(|i| i as u8 ^ 0x5A).collect();
        // A device that drops the bytes listed per pass, as a slow flash EEPROM does.
        let run = |drops: Vec<Vec<usize>>| {
            let image = std::cell::RefCell::new(vec![0xFF; EEPROM_SIZE]);
            let passes = std::cell::Cell::new(0);
            let mut writes = Vec::new();
            let matched = write_with_read_back::<()>(
                &info,
                |address, value| {
                    writes.push(address);
                    if !drops
                        .get(passes.get())
                        .is_some_and(|d| d.contains(&address))
                    {
                        image.borrow_mut()[address] = value;
                    }
                    Ok(())
                },
                || {
                    passes.set(passes.get() + 1);
                    Ok(Some(image.borrow().clone()))
                },
            )
            .unwrap();
            (matched, writes, passes.get())
        };

        let (matched, writes, passes) = run(vec![]);
        assert!(matched);
        assert_eq!(writes, (0..155).collect::<Vec<_>>());
        assert_eq!(passes, 1);

        // The signature tail dropped first, then one byte again: only those are rewritten.
        let (matched, writes, passes) = run(vec![(140..155).collect(), vec![154]]);
        assert!(matched);
        assert_eq!(
            writes[155..],
            [(140..155).collect::<Vec<_>>(), vec![154]].concat()
        );
        assert_eq!(passes, 3);

        // Still dropped after the third rewrite: no match, so the caller never locks.
        let (matched, writes, passes) = run(vec![vec![ADDR_MODEL]; 4]);
        assert!(!matched);
        assert_eq!(writes.len(), 155 + 3);
        assert_eq!(passes, 4);

        // No EEPROM reply counts as nothing written.
        let mut writes = 0;
        let matched = write_with_read_back::<()>(
            &info,
            |_, _| {
                writes += 1;
                Ok(())
            },
            || Ok(None),
        )
        .unwrap();
        assert!(!matched);
        assert_eq!(writes, 155 * 4);
    }
}
