//! Discovery announce app_data — msgpack encode/decode.
//!
//! Python-compatible discovery framing:
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
//! Map keys are unsigned integer values, not strings. These helpers perform
//! framing and field conversion; they do not validate the outer Reticulum
//! announce, its signature or the stamp. Callers must supply those checks.

use std::collections::HashMap;
use std::io::Cursor;

use rmpv::Value;
use thiserror::Error;

use super::address;
use super::constants::{DISCOVERABLE_INTERFACE_TYPES, FLAG_ENCRYPTED, STAMP_SIZE, key};

/// Advertised interface metadata, before any endpoint or identity trust decision.
///
/// Encoding always emits location keys, using `nil` for unknown components.
/// This type can hold out-of-range radio/location values; encoding is not
/// validation.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct DiscoveryInfo {
    /// Human-readable interface name (key `0xFF`). Decoding yields the
    /// sanitized name or `Discovered <type>`; an empty name encodes as nil.
    pub name: String,
    /// Claimed transport identity hash (key `0xFE`, 16 bytes). Decoding does
    /// not authenticate its association with the announce sender.
    pub transport_id: [u8; 16],
    /// The announcing stack and its version (keys `0xFD` / `0xFC`), when it
    /// names them as strings.
    pub impl_name: Option<String>,
    pub impl_version: Option<String>,
    /// Required announce and path-request stamp costs on the advertised
    /// interface (keys `0xFB` / `0xFA`), quantized to 1/256.
    pub dst_cost: Option<f64>,
    pub pr_cost: Option<f64>,
    /// Interface type string, e.g. `"BackboneInterface"` (key `0x00`).
    pub interface_type: String,
    /// Whether the announcer has transport (routing) enabled (key `0x01`).
    pub transport_enabled: bool,
    /// Endpoint address (IP/hostname/b32 for I2P) — optional (key `0x02`).
    pub reachable_on: Option<String>,
    /// Independent optional geolocation (keys `0x03` / `0x04` / `0x05`).
    /// `Some(0.0)` is a real coordinate; absence is `None`.
    pub latitude: Option<f64>,
    pub longitude: Option<f64>,
    pub height: Option<f64>,
    /// Advertised TCP/Backbone port (key `0x06`), not necessarily a local bind port.
    pub port: Option<u16>,
    /// Advertised IFAC network name (key `0x07`).
    pub ifac_netname: Option<String>,
    /// Advertised IFAC network passphrase (key `0x08`). It is serialized in
    /// the info map; use appropriate discovery encryption or omit it when
    /// it must not be disclosed to every recipient of the announce.
    pub ifac_netkey: Option<String>,
    /// Radio frequency in Hz (key `0x09`). Encoding does not validate RF settings.
    pub frequency: Option<u64>,
    /// Radio bandwidth in Hz (key `0x0A`).
    pub bandwidth: Option<u64>,
    /// LoRa spreading-factor value (key `0x0B`).
    pub spreading_factor: Option<u8>,
    /// LoRa coding-rate parameter (key `0x0C`).
    pub coding_rate: Option<u8>,
    /// Weave / KISS modulation (key `0x0D`).
    pub modulation: Option<DiscoveryModulation>,
    /// Weave channel number (key `0x0E`).
    pub channel: Option<u16>,
    /// Operator's LXMF delivery address (key `0xF0`).
    pub operator_lxmf_address: Option<[u8; 16]>,
}

/// Modulation as announced: upstream configures it as an integer and stores
/// whatever a receiver gets without a type check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiscoveryModulation {
    Int(i64),
    Str(String),
}

impl DiscoveryModulation {
    /// An integer or string value; anything else is not representable.
    pub fn from_value(v: &Value) -> Option<Self> {
        match v {
            Value::Integer(n) => n.as_i64().map(Self::Int),
            Value::String(s) => s.as_str().map(|s| Self::Str(s.to_string())),
            _ => None,
        }
    }

    pub fn to_value(&self) -> Value {
        match self {
            Self::Int(n) => Value::from(*n),
            Self::Str(s) => Value::from(s.as_str()),
        }
    }
}

impl std::fmt::Display for DiscoveryModulation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Int(n) => write!(f, "{n}"),
            Self::Str(s) => f.write_str(s),
        }
    }
}

impl serde::Serialize for DiscoveryModulation {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Int(n) => serializer.serialize_i64(*n),
            Self::Str(s) => serializer.serialize_str(s),
        }
    }
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

/// Serialized info bytes and their hash, ready for a separately generated
/// stamp. Call [`Encoded::assemble`] to add framing. The fields are public;
/// after changing `packed`, recompute its hash and stamp before assembling.
pub struct Encoded {
    /// The msgpack-encoded info map.
    pub packed: Vec<u8>,
    /// SHA-256 of `packed` — used as the stamper's infohash input.
    pub infohash: [u8; 32],
}

impl Encoded {
    /// Append a 32-byte stamp to `packed`, optionally encrypt that body, and
    /// prefix one flags byte. Returns `None` for another stamp length, a missing
    /// required encryptor or an encryptor returning `None`.
    ///
    /// `flag_signed` only sets a bit; it neither creates nor verifies a
    /// signature. The stamp's work value and `infohash` are not checked here.
    /// When encryption is disabled, the encryptor is not called and all info
    /// fields remain cleartext. The callback determines encryption semantics.
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

/// Optional body-encryption callback for discovery app-data. Receives
/// `packed_info || stamp`; return `None` to fail assembly.
pub type DiscoveryEncryptor<'a> = dyn Fn(&[u8]) -> Option<Vec<u8>> + 'a;

/// Serialize an info map and compute its full SHA-256 hash for stamping.
/// Unknown location components and unset parameters required by the selected
/// radio type are emitted as `nil`. Fields are not range-checked or sanitized;
/// this can encode metadata that [`decode_info`] would reject.
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
    // Insertion order of Python's info dict, so the packed bytes match.
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
    ];
    if let Some(impl_name) = &info.impl_name {
        entries.push((u8_key(key::TRANSPORT_IMPL), Value::from(impl_name.clone())));
    }
    if let Some(impl_version) = &info.impl_version {
        entries.push((
            u8_key(key::TRANSPORT_VERS),
            Value::from(impl_version.clone()),
        ));
    }
    for (k, cost) in [(key::DST_COST, info.dst_cost), (key::PR_COST, info.pr_cost)] {
        if let Some(cost) = cost.and_then(|c| rns_identity::stamps::quantize_cost(c).ok()) {
            entries.push((u8_key(k), Value::F64(cost)));
        }
    }
    entries.extend([
        (
            u8_key(key::NAME),
            if info.name.is_empty() {
                Value::Nil
            } else {
                Value::from(info.name.clone())
            },
        ),
        (
            u8_key(key::LATITUDE),
            info.latitude.map_or(Value::Nil, Value::F64),
        ),
        (
            u8_key(key::LONGITUDE),
            info.longitude.map_or(Value::Nil, Value::F64),
        ),
        (
            u8_key(key::HEIGHT),
            info.height.map_or(Value::Nil, Value::F64),
        ),
    ]);
    if let Some(addr) = info.operator_lxmf_address {
        entries.push((u8_key(key::OP_ADDR), Value::Binary(addr.to_vec())));
    }

    if let Some(addr) = &info.reachable_on {
        entries.push((u8_key(key::REACHABLE_ON), Value::from(addr.clone())));
    }
    if let Some(port) = info.port {
        entries.push((u8_key(key::PORT), Value::from(port)));
    }
    // Python always writes a radio type's parameters, unset ones as nil.
    let required: &[u8] = match info.interface_type.as_str() {
        "RNodeInterface" => &[
            key::FREQUENCY,
            key::BANDWIDTH,
            key::SPREADING_FACTOR,
            key::CODING_RATE,
        ],
        "WeaveInterface" => &[
            key::FREQUENCY,
            key::BANDWIDTH,
            key::CHANNEL,
            key::MODULATION,
        ],
        "KISSInterface" => &[key::FREQUENCY, key::BANDWIDTH, key::MODULATION],
        _ => &[],
    };
    let radio = [
        (key::FREQUENCY, info.frequency.map(Value::from)),
        (key::BANDWIDTH, info.bandwidth.map(Value::from)),
        (
            key::SPREADING_FACTOR,
            info.spreading_factor.map(Value::from),
        ),
        (key::CODING_RATE, info.coding_rate.map(Value::from)),
        (key::CHANNEL, info.channel.map(Value::from)),
        (
            key::MODULATION,
            info.modulation.as_ref().map(DiscoveryModulation::to_value),
        ),
    ];
    entries.extend(radio.into_iter().filter_map(|(k, value)| {
        value
            .or_else(|| required.contains(&k).then_some(Value::Nil))
            .map(|value| (u8_key(k), value))
    }));
    if let Some(name) = &info.ifac_netname {
        entries.push((u8_key(key::IFAC_NETNAME), Value::from(name.clone())));
    }
    if let Some(k) = &info.ifac_netkey {
        entries.push((u8_key(key::IFAC_NETKEY), Value::from(k.clone())));
    }

    entries
}

fn u8_key(k: u8) -> Value {
    Value::from(k)
}

/// Split an inbound app_data blob into `(flags, payload_body)` where
/// `payload_body` is everything after the flags byte. The body is still
/// `msgpack_info || stamp` (optionally encrypted). Only empty input fails;
/// flag bits and body contents are not validated.
pub fn split_flags(app_data: &[u8]) -> Result<(u8, &[u8]), AppDataError> {
    let (first, rest) = app_data.split_first().ok_or(AppDataError::Empty)?;
    Ok((*first, rest))
}

/// Split the decrypted/cleartext body into `(packed_info, stamp)`. The
/// stamp is always the trailing [`STAMP_SIZE`] bytes. At least one preceding
/// info byte is required; neither portion is decoded or authenticated here.
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

/// Decode the first MessagePack value as an info map, accepting exactly what
/// upstream's handler accepts (RNS/Discovery.py:338-466@1.6.0). Trailing bytes
/// after the first value are ignored, as upstream's unpacker does.
///
/// The name falls back to `Discovered <type>` when it is unset or sanitizes to
/// nothing. Unset or non-string IFAC fields are omitted rather than rejected.
/// This does not resolve the endpoint, authenticate the transport ID or verify
/// a stamp. Oversized port/channel and SF/CR integers are clamped.
pub fn decode_info(packed: &[u8]) -> Result<DiscoveryInfo, AppDataError> {
    let value = rmpv::decode::read_value(&mut Cursor::new(packed))
        .map_err(|e| AppDataError::Msgpack(e.to_string()))?;
    if !python_unpackable(&value) {
        return Err(AppDataError::Msgpack("map upstream cannot unpack".into()));
    }
    let map = match value {
        Value::Map(m) => m,
        _ => return Err(AppDataError::NotAMap),
    };
    let fields: HashMap<u8, Value> = map
        .into_iter()
        .filter_map(|(k, v)| value_as_u8(&k).map(|k| (k, v)))
        .collect();
    let get = |k: u8| fields.get(&k).ok_or(AppDataError::MissingKey(k));

    let mut info = DiscoveryInfo {
        interface_type: value_as_string(get(key::INTERFACE_TYPE)?, key::INTERFACE_TYPE)?,
        ..Default::default()
    };
    let name = get(key::NAME)?;
    let name = if is_falsy(name) {
        String::new()
    } else {
        sanitize_name(&value_as_string(name, key::NAME)?)
    };
    info.impl_name = fields
        .get(&key::TRANSPORT_IMPL)
        .and_then(|v| v.as_str().map(str::to_string));
    info.impl_version = fields
        .get(&key::TRANSPORT_VERS)
        .and_then(|v| v.as_str().map(str::to_string));
    if let Some(v) = fields.get(&key::DST_COST) {
        info.dst_cost = Some(value_as_cost(v, key::DST_COST)?);
    }
    if let Some(v) = fields.get(&key::PR_COST) {
        info.pr_cost = Some(value_as_cost(v, key::PR_COST)?);
    }
    info.transport_enabled = value_as_bool(get(key::TRANSPORT)?, key::TRANSPORT)?;
    info.latitude = value_as_f64(get(key::LATITUDE)?, key::LATITUDE)?;
    info.longitude = value_as_f64(get(key::LONGITUDE)?, key::LONGITUDE)?;
    info.height = value_as_f64(get(key::HEIGHT)?, key::HEIGHT)?;
    let transport_id = match get(key::TRANSPORT_ID)? {
        Value::Binary(b) => b,
        _ => {
            return Err(AppDataError::TypeMismatch {
                key: key::TRANSPORT_ID,
                expected: "bytes",
            });
        }
    };
    info.transport_id = transport_id
        .as_slice()
        .try_into()
        .map_err(|_| AppDataError::BadTransportId(transport_id.len()))?;
    if !DISCOVERABLE_INTERFACE_TYPES.contains(&info.interface_type.as_str()) {
        return Err(AppDataError::UnsupportedInterfaceType(info.interface_type));
    }
    let reachable_on = match fields.get(&key::REACHABLE_ON) {
        Some(v) => {
            let reachable_on = value_as_string(v, key::REACHABLE_ON)?;
            if address::is_valid_address(&reachable_on) != Some(true) {
                return Err(AppDataError::InvalidReachableOn(reachable_on));
            }
            Some(reachable_on)
        }
        None => None,
    };
    info.name = if name.is_empty() {
        format!("Discovered {}", info.interface_type)
    } else {
        name
    };
    info.ifac_netname = fields.get(&key::IFAC_NETNAME).and_then(ifac_value);
    info.ifac_netkey = fields.get(&key::IFAC_NETKEY).and_then(ifac_value);

    // Upstream indexes each type's own keys, so a missing one drops the
    // announce, but stores their values unchecked.
    for k in type_keys(&info.interface_type) {
        let v = get(*k)?;
        let n = v.as_u64();
        match *k {
            key::REACHABLE_ON => info.reachable_on = reachable_on.clone(),
            key::PORT => info.port = n.map(|n| n.min(u16::MAX as u64) as u16),
            key::FREQUENCY => info.frequency = n,
            key::BANDWIDTH => info.bandwidth = n,
            key::SPREADING_FACTOR => info.spreading_factor = n.map(|n| n.min(u8::MAX as u64) as u8),
            key::CODING_RATE => info.coding_rate = n.map(|n| n.min(u8::MAX as u64) as u8),
            key::CHANNEL => info.channel = n.map(|n| n.min(u16::MAX as u64) as u16),
            key::MODULATION => info.modulation = DiscoveryModulation::from_value(v),
            _ => {}
        }
    }

    if let Some(v) = fields.get(&key::OP_ADDR) {
        match v {
            Value::Nil => {}
            Value::Binary(b) => info.operator_lxmf_address = b.as_slice().try_into().ok(),
            _ => {
                return Err(AppDataError::TypeMismatch {
                    key: key::OP_ADDR,
                    expected: "bytes or nil",
                });
            }
        }
    }
    Ok(info)
}

/// The keys upstream's handler reads unconditionally for an interface type
/// (RNS/Discovery.py:380-455@1.6.0).
fn type_keys(interface_type: &str) -> &'static [u8] {
    match interface_type {
        "BackboneInterface" | "TCPServerInterface" => &[key::REACHABLE_ON, key::PORT],
        "I2PInterface" => &[key::REACHABLE_ON],
        "RNodeInterface" => &[
            key::FREQUENCY,
            key::BANDWIDTH,
            key::SPREADING_FACTOR,
            key::CODING_RATE,
        ],
        "WeaveInterface" => &[
            key::FREQUENCY,
            key::BANDWIDTH,
            key::CHANNEL,
            key::MODULATION,
        ],
        "KISSInterface" => &[key::FREQUENCY, key::BANDWIDTH, key::MODULATION],
        _ => &[],
    }
}

/// Upstream keeps an IFAC field only when it is a non-empty `str`.
fn ifac_value(v: &Value) -> Option<String> {
    v.as_str().filter(|s| !s.is_empty()).map(str::to_string)
}

/// Python truthiness of an unpacked value.
fn is_falsy(v: &Value) -> bool {
    match v {
        Value::Nil => true,
        Value::Boolean(b) => !b,
        Value::Integer(n) => n.as_i64() == Some(0) || n.as_u64() == Some(0),
        Value::F32(f) => *f == 0.0,
        Value::F64(f) => *f == 0.0,
        Value::String(s) => s.as_bytes().is_empty(),
        Value::Binary(b) => b.is_empty(),
        Value::Array(a) => a.is_empty(),
        Value::Map(m) => m.is_empty(),
        Value::Ext(..) => false,
    }
}

/// Upstream's unpacker rejects invalid UTF-8 strings, map keys that are maps,
/// and keys that compare equal in Python (so `1` and `true` collide).
fn python_unpackable(v: &Value) -> bool {
    #[derive(PartialEq, Eq, Hash)]
    enum PyKey {
        Int(i128),
        Float(u64),
        Str(Vec<u8>),
        Bin(Vec<u8>),
        Other(String),
    }
    fn py_key(k: &Value) -> PyKey {
        let int = |f: f64| (f.fract() == 0.0 && f.abs() < 1e30).then_some(f as i128);
        match k {
            Value::Integer(n) => PyKey::Int(
                n.as_i64()
                    .map(i128::from)
                    .or(n.as_u64().map(i128::from))
                    .unwrap_or(0),
            ),
            Value::Boolean(b) => PyKey::Int(i128::from(*b)),
            Value::F64(f) => int(*f).map_or(PyKey::Float(f.to_bits()), PyKey::Int),
            Value::F32(f) => {
                int(f64::from(*f)).map_or(PyKey::Float(f64::from(*f).to_bits()), PyKey::Int)
            }
            Value::String(s) => PyKey::Str(s.as_bytes().to_vec()),
            Value::Binary(b) => PyKey::Bin(b.clone()),
            other => PyKey::Other(format!("{other:?}")),
        }
    }
    match v {
        Value::String(s) => s.is_str(),
        Value::Array(items) => items.iter().all(python_unpackable),
        Value::Map(entries) => {
            let mut seen = std::collections::HashSet::new();
            entries.iter().all(|(k, v)| {
                !matches!(k, Value::Map(_))
                    && seen.insert(py_key(k))
                    && python_unpackable(k)
                    && python_unpackable(v)
            })
        }
        _ => true,
    }
}

/// Upstream `InterfaceAnnounceHandler.sanitize_name` (RNS/Discovery.py:272-279
/// @1.6.0) on a string: drop non-ASCII, strip whitespace, collapse runs of 5, 3
/// and then 2 spaces, then strip leading characters that are not ASCII letters
/// or digits and trailing ones that are not those or `)`. May return "".
pub fn sanitize_name(name: &str) -> String {
    let ascii: String = name.chars().filter(char::is_ascii).collect();
    let mut name = ascii
        .trim_matches(|c: char| {
            c.is_ascii_whitespace()
                || ('\x0b'..='\x0d').contains(&c)
                || ('\x1c'..='\x1f').contains(&c)
        })
        .to_string();
    for run in [5, 3, 2] {
        name = name.replace(&" ".repeat(run), " ");
    }
    name.trim_start_matches(|c: char| !c.is_ascii_alphanumeric())
        .trim_end_matches(|c: char| !(c.is_ascii_alphanumeric() || c == ')'))
        .to_string()
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
        Value::String(s) if s.is_str() => Ok(s.as_str().unwrap_or("").to_string()),
        _ => Err(AppDataError::TypeMismatch {
            key: kb,
            expected: "string",
        }),
    }
}

fn value_as_f64(v: &Value, kb: u8) -> Result<Option<f64>, AppDataError> {
    match v {
        Value::Nil => Ok(None),
        Value::F64(f) => Ok(Some(*f)),
        Value::F32(f) => Ok(Some(*f as f64)),
        _ => Err(AppDataError::TypeMismatch {
            key: kb,
            expected: "float or nil",
        }),
    }
}

/// Python `RNS.Stamps.quantize_cost` on a received cost.
fn value_as_cost(v: &Value, kb: u8) -> Result<f64, AppDataError> {
    let mismatch = AppDataError::TypeMismatch {
        key: kb,
        expected: "number",
    };
    let cost = match v {
        Value::F64(f) => *f,
        Value::F32(f) => f64::from(*f),
        Value::Integer(n) => n.as_f64().ok_or(mismatch)?,
        Value::Boolean(b) => f64::from(u8::from(*b)),
        // Python `float()` also takes a numeric string.
        Value::String(s) => s
            .as_str()
            .and_then(|s| s.trim().parse().ok())
            .ok_or(mismatch)?,
        _ => return Err(mismatch),
    };
    rns_identity::stamps::quantize_cost(cost).map_err(|_| AppDataError::TypeMismatch {
        key: kb,
        expected: "finite number",
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
            latitude: Some(51.5074),
            longitude: Some(-0.1278),
            height: Some(35.0),
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
            latitude: Some(52.5200),
            longitude: Some(13.4050),
            height: Some(50.0),
            frequency: Some(869_525_000),
            bandwidth: Some(125_000),
            spreading_factor: Some(8),
            coding_rate: Some(5),
            ..Default::default()
        }
    }

    /// Python 1.5.5 packs the implementation name and version right after
    /// the transport id (Discovery.py:170-178).
    #[test]
    fn implementation_keys_follow_the_transport_id_as_python_packs_them() {
        let mut info = sample_backbone();
        info.impl_name = Some("rsRNS".into());
        info.impl_version = Some("1.4.0".into());
        let encoded = encode_info(&info).unwrap();
        let Value::Map(map) = rmpv::decode::read_value(&mut Cursor::new(&encoded.packed)).unwrap()
        else {
            panic!("info is a map");
        };
        let keys: Vec<u8> = map.iter().map(|(k, _)| value_as_u8(k).unwrap()).collect();
        assert_eq!(
            keys[..6],
            [
                key::INTERFACE_TYPE,
                key::TRANSPORT,
                key::TRANSPORT_ID,
                key::TRANSPORT_IMPL,
                key::TRANSPORT_VERS,
                key::NAME
            ]
        );
        assert_eq!(map[3].1.as_str(), Some("rsRNS"));
        assert_eq!(map[4].1.as_str(), Some("1.4.0"));
        assert_eq!(decode_info(&encoded.packed).unwrap(), info);
    }

    /// Python reads the keys without checking their type (Discovery.py:348-349).
    #[test]
    fn an_implementation_that_is_not_a_string_is_ignored() {
        let mut map = info_to_map(&sample_backbone());
        map.push((u8_key(key::TRANSPORT_IMPL), Value::from(7u64)));
        map.push((u8_key(key::TRANSPORT_VERS), Value::Nil));
        let mut packed = Vec::new();
        rmpv::encode::write_value(&mut packed, &Value::Map(map)).unwrap();
        let decoded = decode_info(&packed).unwrap();
        assert_eq!((decoded.impl_name, decoded.impl_version), (None, None));
    }

    #[test]
    fn independent_nullable_coordinates_preserve_zero_and_hash() {
        let mut hashes = std::collections::HashSet::new();
        for mask in 0..8 {
            let mut info = sample_backbone();
            info.latitude = (mask & 1 != 0).then_some(0.0);
            info.longitude = (mask & 2 != 0).then_some(0.0);
            info.height = (mask & 4 != 0).then_some(0.0);
            let encoded = encode_info(&info).unwrap();
            assert!(hashes.insert(encoded.infohash));
            assert_eq!(decode_info(&encoded.packed).unwrap(), info);
        }
    }

    #[test]
    fn nullable_decoder_requires_locations_as_float_or_nil() {
        let info = sample_backbone();
        let encode_map = |coordinate: Option<Value>| {
            let mut entries = info_to_map(&info);
            entries.retain(|(k, _)| k.as_u64() != Some(key::LATITUDE.into()));
            if let Some(coordinate) = coordinate {
                entries.push((u8_key(key::LATITUDE), coordinate));
            }
            let mut bytes = Vec::new();
            rmpv::encode::write_value(&mut bytes, &Value::Map(entries)).unwrap();
            bytes
        };
        // Upstream requires the key and a float or nil (Discovery.py:349).
        assert!(matches!(
            decode_info(&encode_map(None)),
            Err(AppDataError::MissingKey(key::LATITUDE))
        ));
        assert_eq!(
            decode_info(&encode_map(Some(Value::Nil))).unwrap().latitude,
            None
        );
        for value in [
            Value::from(0),
            Value::Boolean(false),
            Value::from("0"),
            Value::Array(vec![]),
            Value::Map(vec![]),
        ] {
            assert!(matches!(
                decode_info(&encode_map(Some(value))),
                Err(AppDataError::TypeMismatch {
                    key: key::LATITUDE,
                    ..
                })
            ));
        }
        for value in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
            let decoded = decode_info(&encode_map(Some(Value::F64(value))))
                .unwrap()
                .latitude
                .unwrap();
            assert!(if value.is_nan() {
                decoded.is_nan()
            } else {
                decoded == value
            });
        }
    }

    #[test]
    fn default_locations_encode_nil() {
        let info = DiscoveryInfo {
            interface_type: "BackboneInterface".into(),
            ..Default::default()
        };
        let encoded = encode_info(&info).unwrap();
        let value = rmpv::decode::read_value(&mut Cursor::new(encoded.packed)).unwrap();
        for key in [key::LATITUDE, key::LONGITUDE, key::HEIGHT] {
            let coordinate = value
                .as_map()
                .unwrap()
                .iter()
                .find(|(k, _)| k.as_u64() == Some(key.into()))
                .unwrap();
            assert_eq!(coordinate.1, Value::Nil);
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

    /// Python's announcer always writes a radio type's parameters, unset ones
    /// as nil, and its receiver reads them unguarded (Discovery.py:218-234,
    /// :410-456).
    #[test]
    fn radio_types_carry_every_parameter_python_reads() {
        for (interface_type, keys) in [
            (
                "RNodeInterface",
                &[
                    key::FREQUENCY,
                    key::BANDWIDTH,
                    key::SPREADING_FACTOR,
                    key::CODING_RATE,
                ][..],
            ),
            (
                "WeaveInterface",
                &[
                    key::FREQUENCY,
                    key::BANDWIDTH,
                    key::CHANNEL,
                    key::MODULATION,
                ][..],
            ),
            (
                "KISSInterface",
                &[key::FREQUENCY, key::BANDWIDTH, key::MODULATION][..],
            ),
        ] {
            let info = DiscoveryInfo {
                name: "radio".into(),
                interface_type: interface_type.into(),
                transport_id: [0x33; 16],
                ..Default::default()
            };
            let packed = encode_info(&info).unwrap().packed;
            let Value::Map(map) = rmpv::decode::read_value(&mut Cursor::new(&packed)).unwrap()
            else {
                panic!("info is a map");
            };
            for k in keys {
                assert!(
                    map.iter()
                        .any(|(key, value)| value_as_u8(key) == Some(*k) && value.is_nil()),
                    "{interface_type} carries {k:#04x}"
                );
            }
            assert_eq!(decode_info(&packed).unwrap(), info, "{interface_type}");
        }
    }

    #[test]
    fn nil_or_empty_name_gets_the_upstream_default() {
        for name in [Value::Nil, Value::from("")] {
            let map = Value::Map(vec![
                (
                    u8_key(key::INTERFACE_TYPE),
                    Value::from("BackboneInterface"),
                ),
                (u8_key(key::TRANSPORT), Value::from(true)),
                (u8_key(key::TRANSPORT_ID), Value::Binary(vec![0x11; 16])),
                (u8_key(key::NAME), name),
                (u8_key(key::LATITUDE), Value::Nil),
                (u8_key(key::LONGITUDE), Value::Nil),
                (u8_key(key::HEIGHT), Value::Nil),
                (u8_key(key::REACHABLE_ON), Value::from("10.0.0.1")),
                (u8_key(key::PORT), Value::from(4242)),
            ]);
            let mut packed = Vec::new();
            rmpv::encode::write_value(&mut packed, &map).unwrap();
            assert_eq!(
                decode_info(&packed).unwrap().name,
                "Discovered BackboneInterface"
            );
        }
    }

    #[test]
    fn cost_keys_follow_transport_version_as_quantized_floats() {
        let mut info = sample_backbone();
        info.impl_name = Some("RNS".into());
        info.impl_version = Some("1.6.0".into());
        info.dst_cost = Some(23.5);
        info.pr_cost = Some(15.8);
        let packed = encode_info(&info).unwrap().packed;
        let Value::Map(map) = rmpv::decode::read_value(&mut Cursor::new(&packed)).unwrap() else {
            panic!("info is a map");
        };
        let keys: Vec<u8> = map.iter().filter_map(|(k, _)| value_as_u8(k)).collect();
        let at = |k| keys.iter().position(|x| *x == k).unwrap();
        assert_eq!(at(key::DST_COST), at(key::TRANSPORT_VERS) + 1);
        assert_eq!(at(key::PR_COST), at(key::DST_COST) + 1);
        assert_eq!(at(key::NAME), at(key::PR_COST) + 1);
        assert_eq!(map[at(key::DST_COST)].1, Value::F64(23.5));
        assert_eq!(map[at(key::PR_COST)].1, Value::F64(4045.0 / 256.0));
        let decoded = decode_info(&packed).unwrap();
        assert_eq!(decoded.dst_cost, Some(23.5));
        assert_eq!(decoded.pr_cost, Some(4045.0 / 256.0));
    }

    /// Key orders taken from upstream's `get_interface_announce_data`.
    #[test]
    fn radio_keys_precede_ifac_keys_in_upstream_order() {
        let keys = |info: &DiscoveryInfo| -> Vec<u8> {
            info_to_map(info)
                .iter()
                .filter_map(|(k, _)| value_as_u8(k))
                .collect()
        };
        let mut rnode = sample_rnode();
        rnode.ifac_netname = Some("mynet".into());
        rnode.ifac_netkey = Some("hunter2".into());
        assert_eq!(
            keys(&rnode),
            [
                0x00, 0x01, 0xFE, 0xFF, 0x03, 0x04, 0x05, 0x09, 0x0A, 0x0B, 0x0C, 0x07, 0x08
            ]
        );
        let weave = DiscoveryInfo {
            interface_type: "WeaveInterface".into(),
            channel: Some(6),
            modulation: Some(DiscoveryModulation::Int(1)),
            ..Default::default()
        };
        assert_eq!(
            keys(&weave),
            [
                0x00, 0x01, 0xFE, 0xFF, 0x03, 0x04, 0x05, 0x09, 0x0A, 0x0E, 0x0D
            ]
        );
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
