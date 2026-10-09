//! Discovery announce app_data — msgpack encode/decode.
//!
//! Wire format (matches Python `Discovery.py` `get_interface_announce_data`
//! / `InterfaceAnnounceHandler.received_announce`):
//!
//! ```text
//! app_data = flags_byte(1) || payload
//!
//! payload = msgpack_info || stamp        (FLAG_ENCRYPTED clear)
//!         = encrypt(msgpack_info || stamp)  (FLAG_ENCRYPTED set)
//!
//! msgpack_info = msgpack map with numeric u8 keys — see `constants::key::*`
//! stamp = STAMP_SIZE (32) bytes, produced by the configured DiscoveryStamper
//! ```
//!
//! The map keys are byte values (not strings). Python encodes them via
//! `umsgpack.packb`, which uses fixint or uint8 depending on range; rmpv
//! produces the same bytes in both cases.

use std::io::Cursor;

use rmpv::Value;
use thiserror::Error;

use super::constants::{DISCOVERABLE_INTERFACE_TYPES, FLAG_ENCRYPTED, STAMP_SIZE, key};

/// A decoded discovery info payload. Mirrors the Python `info` dict.
///
/// Optional fields mirror Python's presence-or-absence of keys. Required
/// fields (NAME, TRANSPORT_ID, INTERFACE_TYPE, TRANSPORT, LATITUDE,
/// LONGITUDE, HEIGHT) are always present.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct DiscoveryInfo {
    /// Human-readable interface name (key `0xFF`).
    pub name: String,
    /// Transport identity hash of the announcer (key `0xFE`, 16 bytes).
    pub transport_id: [u8; 16],
    /// Interface type string, e.g. `"BackboneInterface"` (key `0x00`).
    pub interface_type: String,
    /// Whether the announcer has transport (routing) enabled (key `0x01`).
    pub transport_enabled: bool,
    /// Endpoint address (IP/hostname/b32 for I2P) — optional (key `0x02`).
    pub reachable_on: Option<String>,
    /// Geolocation (keys `0x03` / `0x04` / `0x05`).
    pub latitude: f64,
    pub longitude: f64,
    pub height: f64,
    /// TCP/Backbone bind port (key `0x06`).
    pub port: Option<u16>,
    /// IFAC virtual-network overlay (keys `0x07` / `0x08`).
    pub ifac_netname: Option<String>,
    pub ifac_netkey: Option<String>,
    /// Radio-link parameters (keys `0x09` / `0x0A` / `0x0B` / `0x0C`).
    pub frequency: Option<u64>,
    pub bandwidth: Option<u64>,
    pub spreading_factor: Option<u8>,
    pub coding_rate: Option<u8>,
    /// Modulation name for Weave / KISS (key `0x0D`).
    pub modulation: Option<String>,
    /// Weave channel number (key `0x0E`).
    pub channel: Option<u16>,
}

#[derive(Debug, Error)]
pub enum AppDataError {
    #[error("empty payload — missing flags byte")]
    Empty,
    #[error("payload too small for stamp (need at least {need} bytes, got {got})")]
    TooSmall { need: usize, got: usize },
    #[error("transport_id must be 16 bytes, got {0}")]
    BadTransportId(usize),
    #[error("missing required key 0x{0:02X}")]
    MissingKey(u8),
    #[error("type mismatch at key 0x{key:02X}: expected {expected}")]
    TypeMismatch { key: u8, expected: &'static str },
    #[error("msgpack decode: {0}")]
    Msgpack(String),
    #[error("top-level msgpack value must be a map")]
    NotAMap,
    #[error("unsupported interface type: {0}")]
    UnsupportedInterfaceType(String),
    #[error("invalid reachable_on value: {0}")]
    InvalidReachableOn(String),
}

/// Encoded payload — separates the stamp from the raw msgpack map so the
/// caller can stamp it separately (stamper wraps the info-hash, not the full
/// app_data). Call [`Encoded::assemble`] once a stamp is in hand.
pub struct Encoded {
    /// The msgpack-encoded info map.
    pub packed: Vec<u8>,
    /// SHA-256 of `packed` — used as the stamper's infohash input.
    pub infohash: [u8; 32],
}

impl Encoded {
    /// Combine `packed_info || stamp`, optionally encrypt, prefix flags byte.
    ///
    /// `encrypt` is a closure so discovery doesn't need to carry the network
    /// identity type — the caller composes with
    /// `Identity::encrypt(&self.network_identity, ...)` when
    /// `flag_encrypted` is set. When `encrypt` is `None` and
    /// `flag_encrypted` is true, the function returns `None`.
    pub fn assemble(
        self,
        stamp: &[u8],
        flag_encrypted: bool,
        flag_signed: bool,
        encrypt: Option<&DiscoveryEncryptor<'_>>,
    ) -> Option<Vec<u8>> {
        if stamp.len() != STAMP_SIZE {
            return None;
        }
        let mut body = self.packed;
        body.extend_from_slice(stamp);

        let body = if flag_encrypted {
            encrypt?(&body)?
        } else {
            body
        };

        let mut out = Vec::with_capacity(1 + body.len());
        let mut flags = 0u8;
        if flag_signed {
            flags |= super::constants::FLAG_SIGNED;
        }
        if flag_encrypted {
            flags |= FLAG_ENCRYPTED;
        }
        out.push(flags);
        out.extend_from_slice(&body);
        Some(out)
    }
}

/// Optional network-identity encryptor used when assembling discovery app-data.
pub type DiscoveryEncryptor<'a> = dyn Fn(&[u8]) -> Option<Vec<u8>> + 'a;

/// Serialize the info dict to the `(packed, infohash)` pair used by the
/// stamper. Matches Python `msgpack.packb(info)` + `Identity.full_hash(packed)`.
pub fn encode_info(info: &DiscoveryInfo) -> Result<Encoded, AppDataError> {
    let map = info_to_map(info);
    let value = Value::Map(map);
    let mut buf = Vec::new();
    rmpv::encode::write_value(&mut buf, &value)
        .map_err(|e| AppDataError::Msgpack(e.to_string()))?;
    let infohash = rns_crypto::sha::full_hash(&buf);
    Ok(Encoded {
        packed: buf,
        infohash,
    })
}

fn info_to_map(info: &DiscoveryInfo) -> Vec<(Value, Value)> {
    // Python-Discovery.py iteration order for required keys. Receivers do
    // not depend on ordering; we keep it stable for testability against
    // pinned vectors.
    let mut entries: Vec<(Value, Value)> = vec![
        (
            u8_key(key::INTERFACE_TYPE),
            Value::from(info.interface_type.clone()),
        ),
        (u8_key(key::TRANSPORT), Value::from(info.transport_enabled)),
        (
            u8_key(key::TRANSPORT_ID),
            Value::Binary(info.transport_id.to_vec()),
        ),
        (u8_key(key::NAME), Value::from(info.name.clone())),
        (u8_key(key::LATITUDE), Value::F64(info.latitude)),
        (u8_key(key::LONGITUDE), Value::F64(info.longitude)),
        (u8_key(key::HEIGHT), Value::F64(info.height)),
    ];

    if let Some(addr) = &info.reachable_on {
        entries.push((u8_key(key::REACHABLE_ON), Value::from(addr.clone())));
    }
    if let Some(port) = info.port {
        entries.push((u8_key(key::PORT), Value::from(port)));
    }
    if let Some(name) = &info.ifac_netname {
        entries.push((u8_key(key::IFAC_NETNAME), Value::from(name.clone())));
    }
    if let Some(k) = &info.ifac_netkey {
        entries.push((u8_key(key::IFAC_NETKEY), Value::from(k.clone())));
    }
    if let Some(f) = info.frequency {
        entries.push((u8_key(key::FREQUENCY), Value::from(f)));
    }
    if let Some(b) = info.bandwidth {
        entries.push((u8_key(key::BANDWIDTH), Value::from(b)));
    }
    if let Some(sf) = info.spreading_factor {
        entries.push((u8_key(key::SPREADING_FACTOR), Value::from(sf)));
    }
    if let Some(cr) = info.coding_rate {
        entries.push((u8_key(key::CODING_RATE), Value::from(cr)));
    }
    if let Some(mod_) = &info.modulation {
        entries.push((u8_key(key::MODULATION), Value::from(mod_.clone())));
    }
    if let Some(ch) = info.channel {
        entries.push((u8_key(key::CHANNEL), Value::from(ch)));
    }

    entries
}

fn u8_key(k: u8) -> Value {
    Value::from(k)
}

/// Split an inbound app_data blob into `(flags, payload_body)` where
/// `payload_body` is everything after the flags byte. The body is still
/// `msgpack_info || stamp` (optionally still-encrypted).
pub fn split_flags(app_data: &[u8]) -> Result<(u8, &[u8]), AppDataError> {
    let (first, rest) = app_data.split_first().ok_or(AppDataError::Empty)?;
    Ok((*first, rest))
}

/// Split the decrypted/cleartext body into `(packed_info, stamp)`. The
/// stamp is always the trailing [`STAMP_SIZE`] bytes.
pub fn split_stamp(body: &[u8]) -> Result<(&[u8], &[u8]), AppDataError> {
    if body.len() <= STAMP_SIZE {
        return Err(AppDataError::TooSmall {
            need: STAMP_SIZE + 1,
            got: body.len(),
        });
    }
    let split_at = body.len() - STAMP_SIZE;
    Ok((&body[..split_at], &body[split_at..]))
}

/// Decode a msgpack info map back into [`DiscoveryInfo`].
pub fn decode_info(packed: &[u8]) -> Result<DiscoveryInfo, AppDataError> {
    let value = rmpv::decode::read_value(&mut Cursor::new(packed))
        .map_err(|e| AppDataError::Msgpack(e.to_string()))?;
    let map = match value {
        Value::Map(m) => m,
        _ => return Err(AppDataError::NotAMap),
    };

    let mut info = DiscoveryInfo::default();
    let mut saw_interface_type = false;
    let mut saw_transport_id = false;

    for (k, v) in map {
        let Some(kb) = value_as_u8(&k) else {
            continue; // unknown/non-numeric keys are ignored for forward compat
        };
        match kb {
            key::NAME => {
                info.name = value_as_string(&v, kb)?;
            }
            key::TRANSPORT_ID => {
                let bytes = value_as_bytes(&v, kb)?;
                if bytes.len() != 16 {
                    return Err(AppDataError::BadTransportId(bytes.len()));
                }
                info.transport_id.copy_from_slice(&bytes);
                saw_transport_id = true;
            }
            key::INTERFACE_TYPE => {
                info.interface_type = value_as_string(&v, kb)?;
                saw_interface_type = true;
            }
            key::TRANSPORT => {
                info.transport_enabled = value_as_bool(&v, kb)?;
            }
            key::REACHABLE_ON => {
                info.reachable_on = Some(value_as_string(&v, kb)?);
            }
            key::LATITUDE => info.latitude = value_as_f64(&v, kb)?,
            key::LONGITUDE => info.longitude = value_as_f64(&v, kb)?,
            key::HEIGHT => info.height = value_as_f64(&v, kb)?,
            key::PORT => {
                let n = value_as_u64(&v, kb)?;
                info.port = Some(n.min(u16::MAX as u64) as u16);
            }
            key::IFAC_NETNAME => info.ifac_netname = Some(value_as_string(&v, kb)?),
            key::IFAC_NETKEY => info.ifac_netkey = Some(value_as_string(&v, kb)?),
            key::FREQUENCY => info.frequency = Some(value_as_u64(&v, kb)?),
            key::BANDWIDTH => info.bandwidth = Some(value_as_u64(&v, kb)?),
            key::SPREADING_FACTOR => {
                info.spreading_factor = Some(value_as_u64(&v, kb)?.min(u8::MAX as u64) as u8);
            }
            key::CODING_RATE => {
                info.coding_rate = Some(value_as_u64(&v, kb)?.min(u8::MAX as u64) as u8);
            }
            key::MODULATION => info.modulation = Some(value_as_string(&v, kb)?),
            key::CHANNEL => {
                info.channel = Some(value_as_u64(&v, kb)?.min(u16::MAX as u64) as u16);
            }
            _ => { /* unknown key: ignore for forward compat */ }
        }
    }

    if !saw_interface_type {
        return Err(AppDataError::MissingKey(key::INTERFACE_TYPE));
    }
    if !saw_transport_id {
        return Err(AppDataError::MissingKey(key::TRANSPORT_ID));
    }
    info.name = sanitize_name(&info.name);
    if !DISCOVERABLE_INTERFACE_TYPES.contains(&info.interface_type.as_str()) {
        return Err(AppDataError::UnsupportedInterfaceType(info.interface_type));
    }
    if let Some(reachable_on) = info.reachable_on.as_deref()
        && !valid_reachable_on(reachable_on)
    {
        return Err(AppDataError::InvalidReachableOn(reachable_on.to_string()));
    }
    Ok(info)
}

pub fn sanitize_name(name: &str) -> String {
    let ascii = name
        .chars()
        .filter(|c| c.is_ascii() && !c.is_ascii_control())
        .collect::<String>();
    let collapsed = ascii.split_whitespace().collect::<Vec<_>>().join(" ");
    let trimmed = collapsed.trim();
    let end = trimmed
        .char_indices()
        .rev()
        .find(|(_, c)| c.is_ascii_alphanumeric() || *c == ')')
        .map(|(idx, c)| idx + c.len_utf8())
        .unwrap_or(0);
    trimmed[..end].to_string()
}

fn valid_reachable_on(value: &str) -> bool {
    let value = value.trim();
    if value.is_empty() {
        return false;
    }
    if value.parse::<std::net::IpAddr>().is_ok() {
        return true;
    }
    value.len() <= 253
        && value.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
                && !label.starts_with('-')
                && !label.ends_with('-')
        })
}

fn value_as_u8(v: &Value) -> Option<u8> {
    v.as_u64().and_then(|n| u8::try_from(n).ok())
}

fn value_as_bool(v: &Value, kb: u8) -> Result<bool, AppDataError> {
    match v {
        Value::Boolean(b) => Ok(*b),
        _ => Err(AppDataError::TypeMismatch {
            key: kb,
            expected: "bool",
        }),
    }
}

fn value_as_string(v: &Value, kb: u8) -> Result<String, AppDataError> {
    match v {
        Value::String(s) => Ok(s.as_str().unwrap_or("").to_string()),
        Value::Binary(b) => Ok(String::from_utf8_lossy(b).into_owned()),
        _ => Err(AppDataError::TypeMismatch {
            key: kb,
            expected: "string",
        }),
    }
}

fn value_as_bytes(v: &Value, kb: u8) -> Result<Vec<u8>, AppDataError> {
    match v {
        Value::Binary(b) => Ok(b.clone()),
        Value::String(s) => Ok(s.as_bytes().to_vec()),
        _ => Err(AppDataError::TypeMismatch {
            key: kb,
            expected: "bytes",
        }),
    }
}

fn value_as_f64(v: &Value, kb: u8) -> Result<f64, AppDataError> {
    match v {
        Value::F64(f) => Ok(*f),
        Value::F32(f) => Ok(*f as f64),
        Value::Integer(n) => Ok(n.as_f64().unwrap_or(0.0)),
        _ => Err(AppDataError::TypeMismatch {
            key: kb,
            expected: "float",
        }),
    }
}

fn value_as_u64(v: &Value, kb: u8) -> Result<u64, AppDataError> {
    v.as_u64().ok_or(AppDataError::TypeMismatch {
        key: kb,
        expected: "uint",
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_backbone() -> DiscoveryInfo {
        DiscoveryInfo {
            name: "London Relay".into(),
            transport_id: [0x11; 16],
            interface_type: "BackboneInterface".into(),
            transport_enabled: true,
            reachable_on: Some("relay.example.org".into()),
            latitude: 51.5074,
            longitude: -0.1278,
            height: 35.0,
            port: Some(4965),
            ifac_netname: Some("mynet".into()),
            ifac_netkey: Some("hunter2".into()),
            ..Default::default()
        }
    }

    fn sample_rnode() -> DiscoveryInfo {
        DiscoveryInfo {
            name: "Berlin LoRa".into(),
            transport_id: [0x22; 16],
            interface_type: "RNodeInterface".into(),
            transport_enabled: false,
            latitude: 52.5200,
            longitude: 13.4050,
            height: 50.0,
            frequency: Some(869_525_000),
            bandwidth: Some(125_000),
            spreading_factor: Some(8),
            coding_rate: Some(5),
            ..Default::default()
        }
    }

    #[test]
    fn round_trip_backbone_info() {
        let info = sample_backbone();
        let encoded = encode_info(&info).expect("encode");
        let decoded = decode_info(&encoded.packed).expect("decode");
        assert_eq!(decoded, info);
    }

    #[test]
    fn decode_sanitizes_interface_name() {
        let mut info = sample_backbone();
        info.name = "  Relay\tΔ / !!  ".into();
        let encoded = encode_info(&info).expect("encode");
        let decoded = decode_info(&encoded.packed).expect("decode");
        assert_eq!(decoded.name, "Relay");
    }

    #[test]
    fn decode_rejects_unsupported_interface_type() {
        let mut info = sample_backbone();
        info.interface_type = "PipeInterface".into();
        let encoded = encode_info(&info).expect("encode");
        assert!(matches!(
            decode_info(&encoded.packed),
            Err(AppDataError::UnsupportedInterfaceType(_))
        ));
    }

    #[test]
    fn decode_rejects_invalid_reachable_on() {
        let mut info = sample_backbone();
        info.reachable_on = Some("bad host!".into());
        let encoded = encode_info(&info).expect("encode");
        assert!(matches!(
            decode_info(&encoded.packed),
            Err(AppDataError::InvalidReachableOn(_))
        ));
    }

    #[test]
    fn round_trip_rnode_info() {
        let info = sample_rnode();
        let encoded = encode_info(&info).expect("encode");
        let decoded = decode_info(&encoded.packed).expect("decode");
        assert_eq!(decoded, info);
    }

    #[test]
    fn assemble_and_split_unencrypted() {
        let info = sample_backbone();
        let encoded = encode_info(&info).expect("encode");
        let packed_clone = encoded.packed.clone();
        let infohash_clone = encoded.infohash;
        let stamp = vec![0x5A; STAMP_SIZE];
        let blob = encoded
            .assemble(&stamp, false, false, None)
            .expect("assemble");

        let (flags, body) = split_flags(&blob).expect("flags");
        assert_eq!(flags, 0);
        let (pinfo, pstamp) = split_stamp(body).expect("stamp split");
        assert_eq!(pinfo, packed_clone.as_slice());
        assert_eq!(pstamp, stamp.as_slice());

        let decoded = decode_info(pinfo).expect("decode");
        assert_eq!(decoded, info);

        let recomputed_hash = rns_crypto::sha::full_hash(pinfo);
        assert_eq!(recomputed_hash, infohash_clone);
    }

    #[test]
    fn assemble_encrypted_invokes_closure() {
        let info = sample_rnode();
        let encoded = encode_info(&info).expect("encode");
        let stamp = vec![0xA5; STAMP_SIZE];
        let blob = encoded
            .assemble(
                &stamp,
                true,
                false,
                Some(&|plaintext: &[u8]| {
                    // Pseudo-encrypt by XOR-ing with 0xFF so we can invert.
                    Some(plaintext.iter().map(|b| b ^ 0xFF).collect())
                }),
            )
            .expect("assemble");

        let (flags, body) = split_flags(&blob).expect("flags");
        assert_eq!(flags & FLAG_ENCRYPTED, FLAG_ENCRYPTED);

        let decrypted: Vec<u8> = body.iter().map(|b| b ^ 0xFF).collect();
        let (pinfo, pstamp) = split_stamp(&decrypted).expect("stamp split");
        assert_eq!(pstamp, stamp.as_slice());

        let decoded = decode_info(pinfo).expect("decode");
        assert_eq!(decoded, info);
    }

    #[test]
    fn assemble_rejects_wrong_stamp_length() {
        let encoded = encode_info(&sample_backbone()).unwrap();
        let short = vec![0; STAMP_SIZE - 1];
        assert!(encoded.assemble(&short, false, false, None).is_none());
    }

    #[test]
    fn split_flags_rejects_empty() {
        assert!(matches!(split_flags(&[]), Err(AppDataError::Empty)));
    }

    #[test]
    fn split_stamp_rejects_short_body() {
        let body = vec![0; STAMP_SIZE];
        assert!(matches!(
            split_stamp(&body),
            Err(AppDataError::TooSmall { .. })
        ));
    }

    #[test]
    fn decode_rejects_missing_transport_id() {
        // Build a minimal map missing TRANSPORT_ID.
        let map = vec![
            (Value::from(key::INTERFACE_TYPE), Value::from("X")),
            (Value::from(key::TRANSPORT), Value::from(false)),
            (Value::from(key::NAME), Value::from("n")),
            (Value::from(key::LATITUDE), Value::F64(0.0)),
            (Value::from(key::LONGITUDE), Value::F64(0.0)),
            (Value::from(key::HEIGHT), Value::F64(0.0)),
        ];
        let mut buf = Vec::new();
        rmpv::encode::write_value(&mut buf, &Value::Map(map)).unwrap();
        assert!(matches!(
            decode_info(&buf),
            Err(AppDataError::MissingKey(key::TRANSPORT_ID))
        ));
    }

    #[test]
    fn decode_tolerates_unknown_keys() {
        // Forward-compat: an unknown key (0x7F) must not break decoding.
        let info = sample_backbone();
        let mut map = info_to_map(&info);
        map.push((Value::from(0x7Fu8), Value::from("future-field")));
        let mut buf = Vec::new();
        rmpv::encode::write_value(&mut buf, &Value::Map(map)).unwrap();
        let decoded = decode_info(&buf).expect("decode");
        assert_eq!(decoded, info);
    }

    #[test]
    fn bad_transport_id_length_errors() {
        let map = vec![
            (Value::from(key::INTERFACE_TYPE), Value::from("X")),
            (Value::from(key::TRANSPORT_ID), Value::Binary(vec![0; 8])),
            (Value::from(key::TRANSPORT), Value::from(false)),
            (Value::from(key::NAME), Value::from("n")),
            (Value::from(key::LATITUDE), Value::F64(0.0)),
            (Value::from(key::LONGITUDE), Value::F64(0.0)),
            (Value::from(key::HEIGHT), Value::F64(0.0)),
        ];
        let mut buf = Vec::new();
        rmpv::encode::write_value(&mut buf, &Value::Map(map)).unwrap();
        assert!(matches!(
            decode_info(&buf),
            Err(AppDataError::BadTransportId(8))
        ));
    }
}
