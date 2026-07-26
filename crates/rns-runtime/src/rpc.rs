//! Shared-instance control RPC over TCP.
//!
//! Python Reticulum uses `multiprocessing.connection.Listener/Client` for the
//! local control port. Keep the Rust control socket wire-compatible with that:
//! framed auth challenge (`#CHALLENGE#`), then framed msgpack request
//! dictionaries and responses, byte-exact with the vendored umsgpack
//! (Python >=1.3.4, commit a2ef9782 — hard cutover from pickle, no fallback).
//! Python 3.12+ uses tagged SHA-256 auth challenges, while Python 3.11 and
//! older use raw MD5 HMAC responses.

use serde::{Deserialize, Serialize};

pub(crate) const MP_CHALLENGE: &[u8] = b"#CHALLENGE#";
pub(crate) const MP_WELCOME: &[u8] = b"#WELCOME#";
pub(crate) const MP_FAILURE: &[u8] = b"#FAILURE#";
const MP_DIGEST_PREFIX: &[u8] = b"{sha256}";
const MP_CHALLENGE_RANDOM_LEN: usize = 40;
const MP_LEGACY_CHALLENGE_RANDOM_LEN: usize = 20;
const MAX_MP_FRAME_SIZE: usize = 16 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PythonAuthProtocol {
    LegacyMd5,
    Sha256,
}

pub(crate) fn detect_python_auth_protocol(challenge: &[u8]) -> PythonAuthProtocol {
    if challenge.starts_with(MP_DIGEST_PREFIX) {
        PythonAuthProtocol::Sha256
    } else {
        PythonAuthProtocol::LegacyMd5
    }
}

#[derive(Debug, Clone, PartialEq)]
enum PyValue {
    None,
    Bool(bool),
    Int(i128),
    Float(f64),
    Bytes(Vec<u8>),
    String(String),
    List(Vec<PyValue>),
    Dict(Vec<(PyDictKey, PyValue)>),
}

#[derive(Debug, Clone, PartialEq)]
enum PyDictKey {
    String(String),
    Bytes(Vec<u8>),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RpcRequest {
    GetPathTable {
        max_hops: Option<u8>,
    },
    GetInterfaceStats,
    GetRateTable,
    GetNextHopIfName {
        destination_hash: Vec<u8>,
    },
    GetNextHop {
        destination_hash: Vec<u8>,
    },
    RequestPath {
        destination_hash: Vec<u8>,
        timeout_secs: Option<f64>,
    },
    GetFirstHopTimeout {
        destination_hash: Vec<u8>,
    },
    GetLinkCount,
    GetPacketRssi {
        packet_hash: Vec<u8>,
    },
    GetPacketSnr {
        packet_hash: Vec<u8>,
    },
    GetPacketQ {
        packet_hash: Vec<u8>,
    },
    GetBlackholedIdentities,
    /// Python 1.3.8 `is_blackholed()` RPC verb (Reticulum.py:1649-1661).
    IsBlackholed {
        identity_hash: Vec<u8>,
    },
    DropPath {
        destination_hash: Vec<u8>,
    },
    DropAllVia {
        transport_hash: Vec<u8>,
    },
    DropPathTable,
    DropRecentAnnounces,
    DropAnnounceQueues,
    BlackholeIdentity {
        identity_hash: Vec<u8>,
        until: Option<f64>,
        reason: Option<String>,
    },
    UnblackholeIdentity {
        identity_hash: Vec<u8>,
    },
    UseDestination {
        destination_hash: Vec<u8>,
    },
    RetainDestination {
        destination_hash: Vec<u8>,
    },
    RetainIdentity {
        identity_hash: Vec<u8>,
    },
    UnretainDestination {
        destination_hash: Vec<u8>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RpcResponse {
    PathTable(Vec<PathTableEntry>),
    InterfaceStats(Vec<InterfaceStatEntry>),
    RateTable(Vec<RateTableEntry>),
    StringResult(Option<String>),
    HashResult(Option<Vec<u8>>),
    FloatResult(Option<f64>),
    IntResult(i64),
    BoolResult(bool),
    BlackholeList(Vec<BlackholeEntry>),
    Ok,
    Error(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathTableEntry {
    pub hash: Vec<u8>,
    pub timestamp: f64,
    pub via: Option<Vec<u8>>,
    pub hops: u8,
    pub expires: f64,
    pub interface: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterfaceStatEntry {
    pub id: u64,
    pub name: String,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_rate: u64,
    pub tx_rate: u64,
    pub online: bool,
    pub bitrate: u64,
    pub mtu: u32,
    pub mode: String,
    pub role: String,
    pub announce_queue: Option<u64>,
    pub held_announces: u64,
    pub incoming_announce_frequency: f64,
    pub outgoing_announce_frequency: f64,
    #[serde(default)]
    pub incoming_pr_frequency: f64,
    #[serde(default)]
    pub outgoing_pr_frequency: f64,
    #[serde(default)]
    pub burst_active: bool,
    #[serde(default)]
    pub burst_activated: f64,
    #[serde(default)]
    pub pr_burst_active: bool,
    #[serde(default)]
    pub pr_burst_activated: f64,
    pub clients: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blocked_ips: Option<u64>,
    pub announce_rate_target: Option<f64>,
    pub announce_rate_grace: Option<u32>,
    pub announce_rate_penalty: Option<f64>,
    pub announce_cap: f64,
    pub ifac_size: usize,
    pub tx_drops: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateTableEntry {
    pub hash: Vec<u8>,
    pub rate: f64,
    pub last: f64,
    pub rate_violations: u32,
    pub blocked_until: f64,
    pub timestamps: Vec<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlackholeEntry {
    pub identity_hash: Vec<u8>,
    pub source: Option<Vec<u8>>,
    pub until: Option<f64>,
    pub reason: Option<String>,
}

pub fn encode_request(req: &RpcRequest) -> Result<Vec<u8>, RpcError> {
    encode_umsgpack(&request_to_py_value(req))
}

pub fn decode_request(data: &[u8]) -> Result<RpcRequest, RpcError> {
    let value = decode_umsgpack(data)?;
    py_value_to_request(&value)
}

pub fn encode_response(resp: &RpcResponse) -> Result<Vec<u8>, RpcError> {
    encode_umsgpack(&response_to_py_value(resp))
}

pub fn decode_response(data: &[u8]) -> Result<RpcResponse, RpcError> {
    let value = decode_umsgpack(data)?;
    py_value_to_response(&value)
}

pub fn decode_response_for_request(
    data: &[u8],
    request: &RpcRequest,
) -> Result<RpcResponse, RpcError> {
    let value = decode_umsgpack(data)?;
    py_value_to_response_for_request(&value, request)
}

pub fn compute_auth_hmac(key: &[u8], challenge: &[u8]) -> [u8; 32] {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC key can be any length");
    mac.update(challenge);
    let result = mac.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result.into_bytes());
    out
}

pub fn compute_legacy_auth_hmac(key: &[u8], challenge: &[u8]) -> [u8; 16] {
    use hmac::{Hmac, Mac};
    use md5::Md5;

    let mut mac = Hmac::<Md5>::new_from_slice(key).expect("HMAC key can be any length");
    mac.update(challenge);
    let result = mac.finalize();
    let mut out = [0u8; 16];
    out.copy_from_slice(&result.into_bytes());
    out
}

/// Constant-time comparison; handshake MUST NOT leak via timing.
pub fn verify_auth_hmac(key: &[u8], challenge: &[u8], provided: &[u8; 32]) -> bool {
    use subtle::ConstantTimeEq;
    let expected = compute_auth_hmac(key, challenge);
    expected.ct_eq(provided).into()
}

/// Derived from the transport identity so server + local CLI share a secret
/// without extra on-disk state.
pub fn derive_rpc_key(identity_private_key: &[u8]) -> [u8; 32] {
    rns_crypto::sha::sha256(identity_private_key)
}

fn request_to_py_value(req: &RpcRequest) -> PyValue {
    match req {
        RpcRequest::GetPathTable { max_hops } => py_dict(vec![
            ("get", PyValue::String("path_table".to_string())),
            (
                "max_hops",
                max_hops
                    .map(|v| PyValue::Int(i128::from(v)))
                    .unwrap_or(PyValue::None),
            ),
        ]),
        RpcRequest::GetInterfaceStats => py_get("interface_stats"),
        RpcRequest::GetRateTable => py_get("rate_table"),
        RpcRequest::GetNextHopIfName { destination_hash } => py_dict(vec![
            ("get", PyValue::String("next_hop_if_name".to_string())),
            ("destination_hash", PyValue::Bytes(destination_hash.clone())),
        ]),
        RpcRequest::GetNextHop { destination_hash } => py_dict(vec![
            ("get", PyValue::String("next_hop".to_string())),
            ("destination_hash", PyValue::Bytes(destination_hash.clone())),
        ]),
        RpcRequest::RequestPath {
            destination_hash,
            timeout_secs,
        } => py_dict(vec![
            ("request", PyValue::String("path".to_string())),
            ("destination_hash", PyValue::Bytes(destination_hash.clone())),
            (
                "timeout",
                timeout_secs.map(PyValue::Float).unwrap_or(PyValue::None),
            ),
        ]),
        RpcRequest::GetFirstHopTimeout { destination_hash } => py_dict(vec![
            ("get", PyValue::String("first_hop_timeout".to_string())),
            ("destination_hash", PyValue::Bytes(destination_hash.clone())),
        ]),
        RpcRequest::GetLinkCount => py_get("link_count"),
        RpcRequest::GetPacketRssi { packet_hash } => py_dict(vec![
            ("get", PyValue::String("packet_rssi".to_string())),
            ("packet_hash", PyValue::Bytes(packet_hash.clone())),
        ]),
        RpcRequest::GetPacketSnr { packet_hash } => py_dict(vec![
            ("get", PyValue::String("packet_snr".to_string())),
            ("packet_hash", PyValue::Bytes(packet_hash.clone())),
        ]),
        RpcRequest::GetPacketQ { packet_hash } => py_dict(vec![
            ("get", PyValue::String("packet_q".to_string())),
            ("packet_hash", PyValue::Bytes(packet_hash.clone())),
        ]),
        RpcRequest::GetBlackholedIdentities => py_get("blackholed_identities"),
        RpcRequest::IsBlackholed { identity_hash } => py_dict(vec![
            ("get", PyValue::String("is_blackholed".to_string())),
            ("identity_hash", PyValue::Bytes(identity_hash.clone())),
        ]),
        RpcRequest::DropPath { destination_hash } => py_dict(vec![
            ("drop", PyValue::String("path".to_string())),
            ("destination_hash", PyValue::Bytes(destination_hash.clone())),
        ]),
        RpcRequest::DropAllVia { transport_hash } => py_dict(vec![
            ("drop", PyValue::String("all_via".to_string())),
            ("destination_hash", PyValue::Bytes(transport_hash.clone())),
        ]),
        RpcRequest::DropPathTable => {
            py_dict(vec![("drop", PyValue::String("path_table".to_string()))])
        }
        RpcRequest::DropRecentAnnounces => py_dict(vec![(
            "drop",
            PyValue::String("recent_announces".to_string()),
        )]),
        RpcRequest::DropAnnounceQueues => py_dict(vec![(
            "drop",
            PyValue::String("announce_queues".to_string()),
        )]),
        RpcRequest::BlackholeIdentity {
            identity_hash,
            until,
            reason,
        } => py_dict(vec![
            ("blackhole_identity", PyValue::Bytes(identity_hash.clone())),
            ("until", until.map(PyValue::Float).unwrap_or(PyValue::None)),
            (
                "reason",
                reason.clone().map(PyValue::String).unwrap_or(PyValue::None),
            ),
        ]),
        RpcRequest::UnblackholeIdentity { identity_hash } => py_dict(vec![(
            "unblackhole_identity",
            PyValue::Bytes(identity_hash.clone()),
        )]),
        RpcRequest::UseDestination { destination_hash } => py_dict(vec![
            ("destination_data", PyValue::String("used".to_string())),
            ("destination_hash", PyValue::Bytes(destination_hash.clone())),
        ]),
        RpcRequest::RetainDestination { destination_hash } => py_dict(vec![
            ("destination_data", PyValue::String("retain".to_string())),
            ("destination_hash", PyValue::Bytes(destination_hash.clone())),
        ]),
        RpcRequest::RetainIdentity { identity_hash } => py_dict(vec![
            ("identity_data", PyValue::String("retain".to_string())),
            ("identity_hash", PyValue::Bytes(identity_hash.clone())),
        ]),
        RpcRequest::UnretainDestination { destination_hash } => py_dict(vec![
            ("destination_data", PyValue::String("unretain".to_string())),
            ("destination_hash", PyValue::Bytes(destination_hash.clone())),
        ]),
    }
}

fn py_get(path: &str) -> PyValue {
    py_dict(vec![("get", PyValue::String(path.to_string()))])
}

fn py_dict(entries: Vec<(&str, PyValue)>) -> PyValue {
    PyValue::Dict(
        entries
            .into_iter()
            .map(|(k, v)| (PyDictKey::String(k.to_string()), v))
            .collect(),
    )
}

fn py_value_to_request(value: &PyValue) -> Result<RpcRequest, RpcError> {
    let entries = as_dict(value)?;
    if let Some(PyValue::String(path)) = dict_get(entries, "get") {
        return match path.as_str() {
            "path_table" => Ok(RpcRequest::GetPathTable {
                max_hops: dict_get(entries, "max_hops").and_then(py_u8),
            }),
            "interface_stats" => Ok(RpcRequest::GetInterfaceStats),
            "rate_table" => Ok(RpcRequest::GetRateTable),
            "next_hop_if_name" => Ok(RpcRequest::GetNextHopIfName {
                destination_hash: dict_bytes(entries, "destination_hash")?,
            }),
            "next_hop" => Ok(RpcRequest::GetNextHop {
                destination_hash: dict_bytes(entries, "destination_hash")?,
            }),
            "first_hop_timeout" => Ok(RpcRequest::GetFirstHopTimeout {
                destination_hash: dict_bytes(entries, "destination_hash")?,
            }),
            "link_count" => Ok(RpcRequest::GetLinkCount),
            "packet_rssi" => Ok(RpcRequest::GetPacketRssi {
                packet_hash: dict_bytes(entries, "packet_hash")?,
            }),
            "packet_snr" => Ok(RpcRequest::GetPacketSnr {
                packet_hash: dict_bytes(entries, "packet_hash")?,
            }),
            "packet_q" => Ok(RpcRequest::GetPacketQ {
                packet_hash: dict_bytes(entries, "packet_hash")?,
            }),
            "blackholed_identities" => Ok(RpcRequest::GetBlackholedIdentities),
            "is_blackholed" => Ok(RpcRequest::IsBlackholed {
                identity_hash: dict_bytes(entries, "identity_hash")?,
            }),
            other => Err(RpcError::Deserialize(format!(
                "unknown Python RPC get path: {other}"
            ))),
        };
    }

    if let Some(PyValue::String(path)) = dict_get(entries, "drop") {
        return match path.as_str() {
            "path" => Ok(RpcRequest::DropPath {
                destination_hash: dict_bytes(entries, "destination_hash")?,
            }),
            "all_via" => Ok(RpcRequest::DropAllVia {
                transport_hash: dict_bytes(entries, "destination_hash")?,
            }),
            "path_table" => Ok(RpcRequest::DropPathTable),
            "recent_announces" => Ok(RpcRequest::DropRecentAnnounces),
            "announce_queues" => Ok(RpcRequest::DropAnnounceQueues),
            other => Err(RpcError::Deserialize(format!(
                "unknown Python RPC drop path: {other}"
            ))),
        };
    }

    if let Some(PyValue::String(path)) = dict_get(entries, "request") {
        return match path.as_str() {
            "path" => Ok(RpcRequest::RequestPath {
                destination_hash: dict_bytes(entries, "destination_hash")?,
                timeout_secs: dict_get(entries, "timeout").and_then(py_f64),
            }),
            other => Err(RpcError::Deserialize(format!(
                "unknown Python RPC request path: {other}"
            ))),
        };
    }

    if let Some(PyValue::Bytes(identity_hash)) = dict_get(entries, "blackhole_identity") {
        return Ok(RpcRequest::BlackholeIdentity {
            identity_hash: identity_hash.clone(),
            until: dict_get(entries, "until").and_then(py_f64),
            reason: dict_get(entries, "reason").and_then(py_string),
        });
    }

    if let Some(PyValue::Bytes(identity_hash)) = dict_get(entries, "unblackhole_identity") {
        return Ok(RpcRequest::UnblackholeIdentity {
            identity_hash: identity_hash.clone(),
        });
    }

    if let Some(PyValue::String(operation)) = dict_get(entries, "destination_data") {
        let destination_hash = dict_bytes(entries, "destination_hash")?;
        return match operation.as_str() {
            "used" => Ok(RpcRequest::UseDestination { destination_hash }),
            "retain" => Ok(RpcRequest::RetainDestination { destination_hash }),
            "unretain" => Ok(RpcRequest::UnretainDestination { destination_hash }),
            other => Err(RpcError::Deserialize(format!(
                "unknown Python RPC destination_data operation: {other}"
            ))),
        };
    }

    if let Some(PyValue::String(operation)) = dict_get(entries, "identity_data") {
        let identity_hash = dict_bytes(entries, "identity_hash")?;
        return match operation.as_str() {
            "retain" => Ok(RpcRequest::RetainIdentity { identity_hash }),
            other => Err(RpcError::Deserialize(format!(
                "unknown Python RPC identity_data operation: {other}"
            ))),
        };
    }

    Err(RpcError::Deserialize(
        "Python RPC request dictionary has no known operation".to_string(),
    ))
}

fn response_to_py_value(resp: &RpcResponse) -> PyValue {
    match resp {
        RpcResponse::PathTable(entries) => PyValue::List(
            entries
                .iter()
                .map(|e| {
                    py_dict(vec![
                        ("hash", PyValue::Bytes(e.hash.clone())),
                        ("timestamp", PyValue::Float(e.timestamp)),
                        (
                            "via",
                            e.via.clone().map(PyValue::Bytes).unwrap_or(PyValue::None),
                        ),
                        ("hops", PyValue::Int(i128::from(e.hops))),
                        ("expires", PyValue::Float(e.expires)),
                        ("interface", PyValue::String(e.interface.clone())),
                    ])
                })
                .collect(),
        ),
        RpcResponse::InterfaceStats(entries) => {
            let interfaces = entries
                .iter()
                .map(|e| {
                    let mut fields = vec![
                        ("id", PyValue::Int(i128::from(e.id))),
                        ("name", PyValue::String(e.name.clone())),
                        ("short_name", PyValue::String(e.name.clone())),
                        ("type", PyValue::String(e.role.clone())),
                        ("rxb", PyValue::Int(i128::from(e.rx_bytes))),
                        ("txb", PyValue::Int(i128::from(e.tx_bytes))),
                        ("rxs", PyValue::Int(i128::from(e.rx_rate))),
                        ("txs", PyValue::Int(i128::from(e.tx_rate))),
                        ("status", PyValue::Bool(e.online)),
                        (
                            "mode",
                            PyValue::Int(i128::from(mode_to_python_int(&e.mode))),
                        ),
                        ("bitrate", PyValue::Int(i128::from(e.bitrate))),
                        ("mtu", PyValue::Int(i128::from(e.mtu))),
                        ("ifac_size", PyValue::Int(i128::from(e.ifac_size as u64))),
                        (
                            "announce_queue",
                            e.announce_queue
                                .map(|v| PyValue::Int(i128::from(v)))
                                .unwrap_or(PyValue::None),
                        ),
                        ("held_announces", PyValue::Int(i128::from(e.held_announces))),
                        (
                            "incoming_announce_frequency",
                            PyValue::Float(e.incoming_announce_frequency),
                        ),
                        (
                            "outgoing_announce_frequency",
                            PyValue::Float(e.outgoing_announce_frequency),
                        ),
                        (
                            "incoming_pr_frequency",
                            PyValue::Float(e.incoming_pr_frequency),
                        ),
                        (
                            "outgoing_pr_frequency",
                            PyValue::Float(e.outgoing_pr_frequency),
                        ),
                        ("burst_active", PyValue::Bool(e.burst_active)),
                        ("burst_activated", PyValue::Float(e.burst_activated)),
                        ("pr_burst_active", PyValue::Bool(e.pr_burst_active)),
                        ("pr_burst_activated", PyValue::Float(e.pr_burst_activated)),
                        (
                            "clients",
                            e.clients
                                .map(|v| PyValue::Int(i128::from(v)))
                                .unwrap_or(PyValue::None),
                        ),
                        ("tx_drops", PyValue::Int(i128::from(e.tx_drops))),
                    ];
                    if let Some(blocked_ips) = e.blocked_ips {
                        fields.push(("blocked_ips", PyValue::Int(i128::from(blocked_ips))));
                    }
                    py_dict(fields)
                })
                .collect();
            let rxb = entries.iter().map(|e| e.rx_bytes).sum::<u64>();
            let txb = entries.iter().map(|e| e.tx_bytes).sum::<u64>();
            let rxs = entries.iter().map(|e| e.rx_rate).sum::<u64>();
            let txs = entries.iter().map(|e| e.tx_rate).sum::<u64>();
            py_dict(vec![
                ("interfaces", PyValue::List(interfaces)),
                ("rxb", PyValue::Int(i128::from(rxb))),
                ("txb", PyValue::Int(i128::from(txb))),
                ("rxs", PyValue::Int(i128::from(rxs))),
                ("txs", PyValue::Int(i128::from(txs))),
                ("rss", PyValue::None),
            ])
        }
        RpcResponse::RateTable(entries) => PyValue::List(
            entries
                .iter()
                .map(|e| {
                    py_dict(vec![
                        ("hash", PyValue::Bytes(e.hash.clone())),
                        ("rate", PyValue::Float(e.rate)),
                        ("last", PyValue::Float(e.last)),
                        (
                            "rate_violations",
                            PyValue::Int(i128::from(e.rate_violations)),
                        ),
                        ("blocked_until", PyValue::Float(e.blocked_until)),
                        (
                            "timestamps",
                            PyValue::List(
                                e.timestamps.iter().copied().map(PyValue::Float).collect(),
                            ),
                        ),
                    ])
                })
                .collect(),
        ),
        RpcResponse::StringResult(v) => v.clone().map(PyValue::String).unwrap_or(PyValue::None),
        RpcResponse::HashResult(v) => v.clone().map(PyValue::Bytes).unwrap_or(PyValue::None),
        RpcResponse::FloatResult(v) => v.map(PyValue::Float).unwrap_or(PyValue::None),
        RpcResponse::IntResult(v) => PyValue::Int(i128::from(*v)),
        RpcResponse::BoolResult(v) => PyValue::Bool(*v),
        RpcResponse::BlackholeList(entries) => PyValue::Dict(
            entries
                .iter()
                .map(|e| {
                    (
                        PyDictKey::Bytes(e.identity_hash.clone()),
                        py_dict(vec![
                            (
                                "source",
                                e.source
                                    .clone()
                                    .map(PyValue::Bytes)
                                    .unwrap_or_else(|| PyValue::Bytes(e.identity_hash.clone())),
                            ),
                            (
                                "until",
                                e.until.map(PyValue::Float).unwrap_or(PyValue::None),
                            ),
                            (
                                "reason",
                                e.reason
                                    .clone()
                                    .map(PyValue::String)
                                    .unwrap_or(PyValue::None),
                            ),
                        ]),
                    )
                })
                .collect(),
        ),
        RpcResponse::Ok => PyValue::Bool(true),
        RpcResponse::Error(e) => py_dict(vec![("error", PyValue::String(e.clone()))]),
    }
}

fn py_value_to_response(value: &PyValue) -> Result<RpcResponse, RpcError> {
    match value {
        PyValue::Dict(entries) if dict_get(entries, "interfaces").is_some() => {
            Ok(RpcResponse::InterfaceStats(parse_interface_stats(value)?))
        }
        PyValue::Dict(entries) if dict_get(entries, "error").is_some() => Ok(RpcResponse::Error(
            dict_get(entries, "error")
                .and_then(py_string)
                .unwrap_or_else(|| "RPC error".to_string()),
        )),
        PyValue::List(values) => infer_list_response(values),
        PyValue::String(s) => Ok(RpcResponse::StringResult(Some(s.clone()))),
        PyValue::Bytes(b) => Ok(RpcResponse::HashResult(Some(b.clone()))),
        PyValue::Float(f) => Ok(RpcResponse::FloatResult(Some(*f))),
        PyValue::Int(i) => Ok(RpcResponse::IntResult(i64_from_i128(*i)?)),
        PyValue::Bool(b) => Ok(RpcResponse::BoolResult(*b)),
        PyValue::None => Ok(RpcResponse::StringResult(None)),
        PyValue::Dict(_) => Err(RpcError::Deserialize(
            "unrecognised Python RPC response dictionary".to_string(),
        )),
    }
}

fn py_value_to_response_for_request(
    value: &PyValue,
    request: &RpcRequest,
) -> Result<RpcResponse, RpcError> {
    if matches!(value, PyValue::Dict(entries) if dict_get(entries, "error").is_some()) {
        return py_value_to_response(value);
    }

    match request {
        RpcRequest::GetPathTable { .. } => Ok(RpcResponse::PathTable(parse_path_table(value)?)),
        RpcRequest::GetInterfaceStats => {
            Ok(RpcResponse::InterfaceStats(parse_interface_stats(value)?))
        }
        RpcRequest::GetRateTable => Ok(RpcResponse::RateTable(parse_rate_table(value)?)),
        RpcRequest::GetNextHopIfName { .. } => {
            Ok(RpcResponse::StringResult(py_optional_string(value)?))
        }
        RpcRequest::GetNextHop { .. } => Ok(RpcResponse::HashResult(py_optional_bytes(value)?)),
        RpcRequest::RequestPath { .. } => Ok(RpcResponse::BoolResult(match value {
            PyValue::Bool(v) => *v,
            PyValue::None => false,
            _ => py_required_int(value)? != 0,
        })),
        RpcRequest::GetFirstHopTimeout { .. }
        | RpcRequest::GetPacketRssi { .. }
        | RpcRequest::GetPacketSnr { .. }
        | RpcRequest::GetPacketQ { .. } => Ok(RpcResponse::FloatResult(py_optional_float(value)?)),
        RpcRequest::GetLinkCount
        | RpcRequest::DropAllVia { .. }
        | RpcRequest::DropPathTable
        | RpcRequest::DropRecentAnnounces => Ok(RpcResponse::IntResult(py_required_int(value)?)),
        RpcRequest::GetBlackholedIdentities => {
            Ok(RpcResponse::BlackholeList(parse_blackhole_list(value)?))
        }
        RpcRequest::DropPath { .. }
        | RpcRequest::DropAnnounceQueues
        | RpcRequest::BlackholeIdentity { .. }
        | RpcRequest::UnblackholeIdentity { .. } => Ok(RpcResponse::Ok),
        RpcRequest::IsBlackholed { .. }
        | RpcRequest::UseDestination { .. }
        | RpcRequest::RetainDestination { .. }
        | RpcRequest::RetainIdentity { .. }
        | RpcRequest::UnretainDestination { .. } => Ok(RpcResponse::BoolResult(match value {
            PyValue::Bool(v) => *v,
            PyValue::None => false,
            _ => py_required_int(value)? != 0,
        })),
    }
}

fn infer_list_response(values: &[PyValue]) -> Result<RpcResponse, RpcError> {
    let Some(PyValue::Dict(first)) = values.first() else {
        return Ok(RpcResponse::PathTable(Vec::new()));
    };
    if dict_get(first, "identity_hash").is_some() {
        Ok(RpcResponse::BlackholeList(parse_blackhole_list(
            &PyValue::List(values.to_vec()),
        )?))
    } else if dict_get(first, "rate_violations").is_some() {
        Ok(RpcResponse::RateTable(parse_rate_table(&PyValue::List(
            values.to_vec(),
        ))?))
    } else {
        Ok(RpcResponse::PathTable(parse_path_table(&PyValue::List(
            values.to_vec(),
        ))?))
    }
}

fn parse_path_table(value: &PyValue) -> Result<Vec<PathTableEntry>, RpcError> {
    let PyValue::List(entries) = value else {
        return Err(RpcError::Deserialize(
            "expected path table list".to_string(),
        ));
    };
    entries
        .iter()
        .map(|entry| {
            let m = as_dict(entry)?;
            Ok(PathTableEntry {
                hash: dict_bytes(m, "hash")?,
                timestamp: dict_get(m, "timestamp").and_then(py_f64).unwrap_or(0.0),
                via: match dict_get(m, "via") {
                    Some(PyValue::Bytes(v)) => Some(v.clone()),
                    _ => None,
                },
                hops: dict_get(m, "hops").and_then(py_u8).unwrap_or(0),
                expires: dict_get(m, "expires").and_then(py_f64).unwrap_or(0.0),
                interface: dict_get(m, "interface")
                    .and_then(py_string)
                    .unwrap_or_default(),
            })
        })
        .collect()
}

fn parse_interface_stats(value: &PyValue) -> Result<Vec<InterfaceStatEntry>, RpcError> {
    let list = match value {
        PyValue::Dict(entries) => match dict_get(entries, "interfaces") {
            Some(PyValue::List(v)) => v,
            _ => return Ok(Vec::new()),
        },
        PyValue::List(v) => v,
        _ => {
            return Err(RpcError::Deserialize(
                "expected interface stats dictionary".to_string(),
            ));
        }
    };
    list.iter()
        .enumerate()
        .map(|(idx, entry)| {
            let m = as_dict(entry)?;
            Ok(InterfaceStatEntry {
                id: dict_get(m, "id")
                    .and_then(py_u64)
                    .unwrap_or((idx as u64) + 1),
                name: dict_get(m, "name").and_then(py_string).unwrap_or_default(),
                rx_bytes: dict_get(m, "rxb")
                    .or_else(|| dict_get(m, "rx_bytes"))
                    .and_then(py_u64)
                    .unwrap_or(0),
                tx_bytes: dict_get(m, "txb")
                    .or_else(|| dict_get(m, "tx_bytes"))
                    .and_then(py_u64)
                    .unwrap_or(0),
                rx_rate: dict_get(m, "rxs").and_then(py_u64).unwrap_or(0),
                tx_rate: dict_get(m, "txs").and_then(py_u64).unwrap_or(0),
                online: dict_get(m, "status")
                    .or_else(|| dict_get(m, "online"))
                    .and_then(py_bool)
                    .unwrap_or(false),
                bitrate: dict_get(m, "bitrate").and_then(py_u64).unwrap_or(0),
                mtu: dict_get(m, "mtu").and_then(py_u32).unwrap_or(0),
                mode: dict_get(m, "mode")
                    .map(mode_from_py_value)
                    .unwrap_or_else(|| "Full".to_string()),
                role: dict_get(m, "role")
                    .or_else(|| dict_get(m, "type"))
                    .and_then(py_string)
                    .unwrap_or_else(|| "normal".to_string()),
                announce_queue: match dict_get(m, "announce_queue") {
                    Some(PyValue::None) | None => None,
                    Some(value) => py_u64(value),
                },
                held_announces: dict_get(m, "held_announces").and_then(py_u64).unwrap_or(0),
                incoming_announce_frequency: dict_get(m, "incoming_announce_frequency")
                    .and_then(py_f64)
                    .unwrap_or(0.0),
                outgoing_announce_frequency: dict_get(m, "outgoing_announce_frequency")
                    .and_then(py_f64)
                    .unwrap_or(0.0),
                incoming_pr_frequency: dict_get(m, "incoming_pr_frequency")
                    .and_then(py_f64)
                    .unwrap_or(0.0),
                outgoing_pr_frequency: dict_get(m, "outgoing_pr_frequency")
                    .and_then(py_f64)
                    .unwrap_or(0.0),
                burst_active: dict_get(m, "burst_active")
                    .and_then(py_bool)
                    .unwrap_or(false),
                burst_activated: dict_get(m, "burst_activated")
                    .and_then(py_f64)
                    .unwrap_or(0.0),
                pr_burst_active: dict_get(m, "pr_burst_active")
                    .and_then(py_bool)
                    .unwrap_or(false),
                pr_burst_activated: dict_get(m, "pr_burst_activated")
                    .and_then(py_f64)
                    .unwrap_or(0.0),
                clients: match dict_get(m, "clients") {
                    Some(PyValue::None) | None => None,
                    Some(value) => py_u64(value),
                },
                blocked_ips: match dict_get(m, "blocked_ips") {
                    Some(PyValue::None) | None => None,
                    Some(value) => py_u64(value),
                },
                announce_rate_target: dict_get(m, "announce_rate_target").and_then(py_f64),
                announce_rate_grace: dict_get(m, "announce_rate_grace").and_then(py_u32),
                announce_rate_penalty: dict_get(m, "announce_rate_penalty").and_then(py_f64),
                announce_cap: dict_get(m, "announce_cap").and_then(py_f64).unwrap_or(0.0),
                ifac_size: dict_get(m, "ifac_size")
                    .and_then(py_u64)
                    .map(|v| v as usize)
                    .unwrap_or(0),
                tx_drops: dict_get(m, "tx_drops").and_then(py_u64).unwrap_or(0),
            })
        })
        .collect()
}

fn parse_rate_table(value: &PyValue) -> Result<Vec<RateTableEntry>, RpcError> {
    let PyValue::List(entries) = value else {
        return Err(RpcError::Deserialize(
            "expected rate table list".to_string(),
        ));
    };
    entries
        .iter()
        .map(|entry| {
            let m = as_dict(entry)?;
            let timestamps = match dict_get(m, "timestamps") {
                Some(PyValue::List(v)) => v.iter().filter_map(py_f64).collect(),
                _ => Vec::new(),
            };
            Ok(RateTableEntry {
                hash: dict_bytes(m, "hash")?,
                rate: dict_get(m, "rate").and_then(py_f64).unwrap_or(0.0),
                last: dict_get(m, "last").and_then(py_f64).unwrap_or(0.0),
                rate_violations: dict_get(m, "rate_violations").and_then(py_u32).unwrap_or(0),
                blocked_until: dict_get(m, "blocked_until").and_then(py_f64).unwrap_or(0.0),
                timestamps,
            })
        })
        .collect()
}

fn parse_blackhole_list(value: &PyValue) -> Result<Vec<BlackholeEntry>, RpcError> {
    match value {
        PyValue::List(entries) => entries
            .iter()
            .map(|entry| {
                let m = as_dict(entry)?;
                Ok(BlackholeEntry {
                    identity_hash: dict_bytes(m, "identity_hash")?,
                    source: match dict_get(m, "source") {
                        Some(PyValue::Bytes(v)) => Some(v.clone()),
                        _ => None,
                    },
                    until: dict_get(m, "until").and_then(py_f64),
                    reason: dict_get(m, "reason").and_then(py_string),
                })
            })
            .collect(),
        PyValue::Dict(entries) => entries
            .iter()
            .map(|(key, entry)| {
                let identity_hash = match key {
                    PyDictKey::Bytes(bytes) => bytes.clone(),
                    PyDictKey::String(hex) => hex::decode(hex).map_err(|e| {
                        RpcError::Deserialize(format!("invalid blackhole identity hash key: {e}"))
                    })?,
                };
                let m = as_dict(entry)?;
                Ok(BlackholeEntry {
                    identity_hash,
                    source: match dict_get(m, "source") {
                        Some(PyValue::Bytes(v)) => Some(v.clone()),
                        _ => None,
                    },
                    until: dict_get(m, "until").and_then(py_f64),
                    reason: dict_get(m, "reason").and_then(py_string),
                })
            })
            .collect(),
        _ => Err(RpcError::Deserialize(
            "expected blackhole list or dictionary".to_string(),
        )),
    }
}

fn as_dict(value: &PyValue) -> Result<&[(PyDictKey, PyValue)], RpcError> {
    match value {
        PyValue::Dict(entries) => Ok(entries),
        _ => Err(RpcError::Deserialize("expected dictionary".to_string())),
    }
}

fn dict_get<'a>(entries: &'a [(PyDictKey, PyValue)], key: &str) -> Option<&'a PyValue> {
    entries
        .iter()
        .find(|(k, _)| matches!(k, PyDictKey::String(s) if s == key))
        .map(|(_, v)| v)
}

fn dict_bytes(entries: &[(PyDictKey, PyValue)], key: &str) -> Result<Vec<u8>, RpcError> {
    match dict_get(entries, key) {
        Some(PyValue::Bytes(v)) => Ok(v.clone()),
        Some(_) => Err(RpcError::Deserialize(format!("{key} is not bytes"))),
        None => Err(RpcError::Deserialize(format!("missing {key}"))),
    }
}

fn py_string(value: &PyValue) -> Option<String> {
    match value {
        PyValue::String(v) => Some(v.clone()),
        _ => None,
    }
}

fn py_bool(value: &PyValue) -> Option<bool> {
    match value {
        PyValue::Bool(v) => Some(*v),
        _ => None,
    }
}

fn py_f64(value: &PyValue) -> Option<f64> {
    match value {
        PyValue::Float(v) => Some(*v),
        PyValue::Int(v) => Some(*v as f64),
        _ => None,
    }
}

fn py_u8(value: &PyValue) -> Option<u8> {
    py_u64(value).and_then(|v| u8::try_from(v).ok())
}

fn py_u32(value: &PyValue) -> Option<u32> {
    py_u64(value).and_then(|v| u32::try_from(v).ok())
}

fn py_u64(value: &PyValue) -> Option<u64> {
    match value {
        PyValue::Int(v) => u64::try_from(*v).ok(),
        _ => None,
    }
}

fn py_optional_string(value: &PyValue) -> Result<Option<String>, RpcError> {
    match value {
        PyValue::None => Ok(None),
        PyValue::String(v) => Ok(Some(v.clone())),
        _ => Err(RpcError::Deserialize(
            "expected optional string".to_string(),
        )),
    }
}

fn py_optional_bytes(value: &PyValue) -> Result<Option<Vec<u8>>, RpcError> {
    match value {
        PyValue::None => Ok(None),
        PyValue::Bytes(v) => Ok(Some(v.clone())),
        _ => Err(RpcError::Deserialize("expected optional bytes".to_string())),
    }
}

fn py_optional_float(value: &PyValue) -> Result<Option<f64>, RpcError> {
    match value {
        PyValue::None => Ok(None),
        PyValue::Float(v) => Ok(Some(*v)),
        PyValue::Int(v) => Ok(Some(*v as f64)),
        _ => Err(RpcError::Deserialize("expected optional float".to_string())),
    }
}

fn py_required_int(value: &PyValue) -> Result<i64, RpcError> {
    match value {
        PyValue::Int(v) => i64_from_i128(*v),
        PyValue::Bool(v) => Ok(i64::from(*v)),
        _ => Err(RpcError::Deserialize("expected integer".to_string())),
    }
}

fn i64_from_i128(v: i128) -> Result<i64, RpcError> {
    i64::try_from(v).map_err(|_| RpcError::Deserialize(format!("integer out of range: {v}")))
}

fn mode_to_python_int(mode: &str) -> u8 {
    match mode {
        "Full" => 0x01,
        "PointToPoint" => 0x02,
        "Access" | "AccessPoint" => 0x03,
        "Roaming" => 0x04,
        "Boundary" => 0x05,
        "Gateway" => 0x06,
        // Python 1.3.8 MODE_INTERNAL (Interface.py:51).
        "Internal" => 0x07,
        _ => 0x01,
    }
}

fn mode_from_py_value(value: &PyValue) -> String {
    match value {
        PyValue::Int(1) => "Full",
        PyValue::Int(2) => "PointToPoint",
        PyValue::Int(3) => "AccessPoint",
        PyValue::Int(4) => "Roaming",
        PyValue::Int(5) => "Boundary",
        PyValue::Int(6) => "Gateway",
        PyValue::Int(7) => "Internal",
        PyValue::String(s) => s.as_str(),
        _ => "Full",
    }
    .to_string()
}

/// Nesting cap for inbound payloads; the recursive decoder must not let a
/// hostile local client blow the stack (umsgpack relies on Python's ~1000
/// recursion limit for the same purpose).
const MAX_MSGPACK_DEPTH: usize = 128;

/// Byte-exact with `RNS.vendor.umsgpack.packb` (1.3.8) for the value tree the
/// RPC vocabulary uses: nil/bool/int/float64/str/bin/array/map.
fn encode_umsgpack(value: &PyValue) -> Result<Vec<u8>, RpcError> {
    let mut out = Vec::new();
    encode_msgpack_value(value, &mut out)?;
    Ok(out)
}

fn encode_msgpack_value(value: &PyValue, out: &mut Vec<u8>) -> Result<(), RpcError> {
    match value {
        PyValue::None => out.push(0xc0),
        PyValue::Bool(true) => out.push(0xc3),
        PyValue::Bool(false) => out.push(0xc2),
        PyValue::Int(v) => encode_msgpack_int(*v, out)?,
        // umsgpack packs Python floats as float64 (`_float_precision = "double"`).
        PyValue::Float(v) => {
            out.push(0xcb);
            out.extend_from_slice(&v.to_be_bytes());
        }
        PyValue::Bytes(bytes) => encode_msgpack_bytes(bytes, out)?,
        PyValue::String(s) => encode_msgpack_string(s, out)?,
        PyValue::List(values) => {
            encode_msgpack_seq_header(values.len(), 0x90, 0xdc, "array", out)?;
            for value in values {
                encode_msgpack_value(value, out)?;
            }
        }
        PyValue::Dict(entries) => {
            encode_msgpack_seq_header(entries.len(), 0x80, 0xde, "map", out)?;
            for (key, value) in entries {
                match key {
                    PyDictKey::String(s) => encode_msgpack_string(s, out)?,
                    PyDictKey::Bytes(bytes) => encode_msgpack_bytes(bytes, out)?,
                }
                encode_msgpack_value(value, out)?;
            }
        }
    }
    Ok(())
}

/// Shared fixarray/fixmap + 16/32-bit header layout (`_pack_array`/`_pack_map`).
fn encode_msgpack_seq_header(
    len: usize,
    fix_base: u8,
    len16_code: u8,
    kind: &str,
    out: &mut Vec<u8>,
) -> Result<(), RpcError> {
    if len < 16 {
        out.push(fix_base | len as u8);
    } else if let Ok(v) = u16::try_from(len) {
        out.push(len16_code);
        out.extend_from_slice(&v.to_be_bytes());
    } else if let Ok(v) = u32::try_from(len) {
        out.push(len16_code + 1);
        out.extend_from_slice(&v.to_be_bytes());
    } else {
        return Err(RpcError::Serialize(format!("huge {kind}")));
    }
    Ok(())
}

/// umsgpack `_pack_integer`: values outside i64::MIN..=u64::MAX raise
/// UnsupportedTypeException — mirror the rejection exactly.
fn encode_msgpack_int(value: i128, out: &mut Vec<u8>) -> Result<(), RpcError> {
    if value < 0 {
        if value >= -32 {
            out.push(value as i8 as u8);
        } else if value >= i128::from(i8::MIN) {
            out.push(0xd0);
            out.push(value as i8 as u8);
        } else if value >= i128::from(i16::MIN) {
            out.push(0xd1);
            out.extend_from_slice(&(value as i16).to_be_bytes());
        } else if value >= i128::from(i32::MIN) {
            out.push(0xd2);
            out.extend_from_slice(&(value as i32).to_be_bytes());
        } else if value >= i128::from(i64::MIN) {
            out.push(0xd3);
            out.extend_from_slice(&(value as i64).to_be_bytes());
        } else {
            return Err(RpcError::Serialize("huge signed int".to_string()));
        }
    } else if value < 128 {
        out.push(value as u8);
    } else if value < 1 << 8 {
        out.push(0xcc);
        out.push(value as u8);
    } else if value < 1 << 16 {
        out.push(0xcd);
        out.extend_from_slice(&(value as u16).to_be_bytes());
    } else if value < 1 << 32 {
        out.push(0xce);
        out.extend_from_slice(&(value as u32).to_be_bytes());
    } else if value <= i128::from(u64::MAX) {
        out.push(0xcf);
        out.extend_from_slice(&(value as u64).to_be_bytes());
    } else {
        return Err(RpcError::Serialize("huge unsigned int".to_string()));
    }
    Ok(())
}

fn encode_msgpack_string(s: &str, out: &mut Vec<u8>) -> Result<(), RpcError> {
    let bytes = s.as_bytes();
    let len = bytes.len();
    if len < 32 {
        out.push(0xa0 | len as u8);
    } else if let Ok(v) = u8::try_from(len) {
        out.push(0xd9);
        out.push(v);
    } else if let Ok(v) = u16::try_from(len) {
        out.push(0xda);
        out.extend_from_slice(&v.to_be_bytes());
    } else if let Ok(v) = u32::try_from(len) {
        out.push(0xdb);
        out.extend_from_slice(&v.to_be_bytes());
    } else {
        return Err(RpcError::Serialize("huge string".to_string()));
    }
    out.extend_from_slice(bytes);
    Ok(())
}

fn encode_msgpack_bytes(bytes: &[u8], out: &mut Vec<u8>) -> Result<(), RpcError> {
    let len = bytes.len();
    if let Ok(v) = u8::try_from(len) {
        out.push(0xc4);
        out.push(v);
    } else if let Ok(v) = u16::try_from(len) {
        out.push(0xc5);
        out.extend_from_slice(&v.to_be_bytes());
    } else if let Ok(v) = u32::try_from(len) {
        out.push(0xc6);
        out.extend_from_slice(&v.to_be_bytes());
    } else {
        return Err(RpcError::Serialize("huge binary string".to_string()));
    }
    out.extend_from_slice(bytes);
    Ok(())
}

/// Like `umsgpack.unpackb`: decodes one object, ignores trailing bytes.
fn decode_umsgpack(data: &[u8]) -> Result<PyValue, RpcError> {
    let mut i = 0usize;
    decode_msgpack_value(data, &mut i, 0)
}

fn decode_msgpack_value(data: &[u8], i: &mut usize, depth: usize) -> Result<PyValue, RpcError> {
    if depth > MAX_MSGPACK_DEPTH {
        return Err(RpcError::Deserialize(
            "msgpack nesting too deep".to_string(),
        ));
    }
    let code = read_u8(data, i)?;
    match code {
        0x00..=0x7f => Ok(PyValue::Int(i128::from(code))),
        0xe0..=0xff => Ok(PyValue::Int(i128::from(code as i8))),
        0x80..=0x8f => decode_msgpack_map(data, i, usize::from(code & 0x0f), depth),
        0x90..=0x9f => decode_msgpack_array(data, i, usize::from(code & 0x0f), depth),
        0xa0..=0xbf => decode_msgpack_str(data, i, usize::from(code & 0x1f)),
        0xc0 => Ok(PyValue::None),
        0xc2 => Ok(PyValue::Bool(false)),
        0xc3 => Ok(PyValue::Bool(true)),
        0xc4 => {
            let len = read_u8(data, i)? as usize;
            Ok(PyValue::Bytes(read_exact(data, i, len)?.to_vec()))
        }
        0xc5 => {
            let len = read_u16_be(data, i)? as usize;
            Ok(PyValue::Bytes(read_exact(data, i, len)?.to_vec()))
        }
        0xc6 => {
            let len = read_u32_be(data, i)? as usize;
            Ok(PyValue::Bytes(read_exact(data, i, len)?.to_vec()))
        }
        0xca => {
            let bytes = read_exact(data, i, 4)?;
            let v = f32::from_be_bytes(bytes.try_into().unwrap());
            Ok(PyValue::Float(f64::from(v)))
        }
        0xcb => {
            let bytes = read_exact(data, i, 8)?;
            let v = f64::from_be_bytes(bytes.try_into().unwrap());
            Ok(PyValue::Float(v))
        }
        0xcc => Ok(PyValue::Int(i128::from(read_u8(data, i)?))),
        0xcd => Ok(PyValue::Int(i128::from(read_u16_be(data, i)?))),
        0xce => Ok(PyValue::Int(i128::from(read_u32_be(data, i)?))),
        0xcf => Ok(PyValue::Int(i128::from(read_u64_be(data, i)?))),
        0xd0 => Ok(PyValue::Int(i128::from(read_u8(data, i)? as i8))),
        0xd1 => Ok(PyValue::Int(i128::from(read_u16_be(data, i)? as i16))),
        0xd2 => Ok(PyValue::Int(i128::from(read_u32_be(data, i)? as i32))),
        0xd3 => Ok(PyValue::Int(i128::from(read_u64_be(data, i)? as i64))),
        0xd9 => {
            let len = read_u8(data, i)? as usize;
            decode_msgpack_str(data, i, len)
        }
        0xda => {
            let len = read_u16_be(data, i)? as usize;
            decode_msgpack_str(data, i, len)
        }
        0xdb => {
            let len = read_u32_be(data, i)? as usize;
            decode_msgpack_str(data, i, len)
        }
        0xdc => {
            let len = read_u16_be(data, i)? as usize;
            decode_msgpack_array(data, i, len, depth)
        }
        0xdd => {
            let len = read_u32_be(data, i)? as usize;
            decode_msgpack_array(data, i, len, depth)
        }
        0xde => {
            let len = read_u16_be(data, i)? as usize;
            decode_msgpack_map(data, i, len, depth)
        }
        0xdf => {
            let len = read_u32_be(data, i)? as usize;
            decode_msgpack_map(data, i, len, depth)
        }
        // Ext/timestamp families (0xc1 reserved, 0xc7-0xc9, 0xd4-0xd8) never
        // appear in the RPC vocabulary.
        other => Err(RpcError::Deserialize(format!(
            "unsupported msgpack type code 0x{other:02x}"
        ))),
    }
}

fn decode_msgpack_str(data: &[u8], i: &mut usize, len: usize) -> Result<PyValue, RpcError> {
    let bytes = read_exact(data, i, len)?;
    // umsgpack default: invalid UTF-8 raises InvalidStringException.
    let s = std::str::from_utf8(bytes)
        .map_err(|_| RpcError::Deserialize("unpacked string is invalid utf-8".to_string()))?;
    Ok(PyValue::String(s.to_string()))
}

fn decode_msgpack_array(
    data: &[u8],
    i: &mut usize,
    len: usize,
    depth: usize,
) -> Result<PyValue, RpcError> {
    let mut values = Vec::with_capacity(len.min(1024));
    for _ in 0..len {
        values.push(decode_msgpack_value(data, i, depth + 1)?);
    }
    Ok(PyValue::List(values))
}

fn decode_msgpack_map(
    data: &[u8],
    i: &mut usize,
    len: usize,
    depth: usize,
) -> Result<PyValue, RpcError> {
    let mut entries = Vec::with_capacity(len.min(1024));
    for _ in 0..len {
        let key = py_key(decode_msgpack_value(data, i, depth + 1)?)?;
        let value = decode_msgpack_value(data, i, depth + 1)?;
        entries.push((key, value));
    }
    Ok(PyValue::Dict(entries))
}

fn py_key(value: PyValue) -> Result<PyDictKey, RpcError> {
    match value {
        PyValue::String(s) => Ok(PyDictKey::String(s)),
        PyValue::Bytes(bytes) => Ok(PyDictKey::Bytes(bytes)),
        _ => Err(RpcError::Deserialize(
            "dictionary key is not a string or bytes".to_string(),
        )),
    }
}

fn read_exact<'a>(data: &'a [u8], index: &mut usize, len: usize) -> Result<&'a [u8], RpcError> {
    let end = index
        .checked_add(len)
        .ok_or_else(|| RpcError::Deserialize("msgpack length overflow".to_string()))?;
    if end > data.len() {
        return Err(RpcError::Deserialize("truncated msgpack".to_string()));
    }
    let out = &data[*index..end];
    *index = end;
    Ok(out)
}

fn read_u8(data: &[u8], index: &mut usize) -> Result<u8, RpcError> {
    Ok(read_exact(data, index, 1)?[0])
}

fn read_u16_be(data: &[u8], index: &mut usize) -> Result<u16, RpcError> {
    let bytes = read_exact(data, index, 2)?;
    Ok(u16::from_be_bytes(bytes.try_into().unwrap()))
}

fn read_u32_be(data: &[u8], index: &mut usize) -> Result<u32, RpcError> {
    let bytes = read_exact(data, index, 4)?;
    Ok(u32::from_be_bytes(bytes.try_into().unwrap()))
}

fn read_u64_be(data: &[u8], index: &mut usize) -> Result<u64, RpcError> {
    let bytes = read_exact(data, index, 8)?;
    Ok(u64::from_be_bytes(bytes.try_into().unwrap()))
}

pub fn compute_python_auth_response(key: &[u8], message: &[u8]) -> Vec<u8> {
    compute_python_auth_response_for(detect_python_auth_protocol(message), key, message)
}

pub(crate) fn compute_python_auth_response_for(
    protocol: PythonAuthProtocol,
    key: &[u8],
    message: &[u8],
) -> Vec<u8> {
    if protocol == PythonAuthProtocol::LegacyMd5 {
        return compute_legacy_auth_hmac(key, message).to_vec();
    }

    let mut response = Vec::with_capacity(MP_DIGEST_PREFIX.len() + 32);
    response.extend_from_slice(MP_DIGEST_PREFIX);
    response.extend_from_slice(&compute_auth_hmac(key, message));
    response
}

pub fn verify_python_auth_response(key: &[u8], message: &[u8], response: &[u8]) -> bool {
    let protocol = if response.starts_with(MP_DIGEST_PREFIX) {
        PythonAuthProtocol::Sha256
    } else {
        PythonAuthProtocol::LegacyMd5
    };
    verify_python_auth_response_for(protocol, key, message, response)
}

pub(crate) fn verify_python_auth_response_for(
    protocol: PythonAuthProtocol,
    key: &[u8],
    message: &[u8],
    response: &[u8],
) -> bool {
    use subtle::ConstantTimeEq;
    if protocol == PythonAuthProtocol::LegacyMd5 {
        let expected = compute_legacy_auth_hmac(key, message);
        return expected.as_slice().ct_eq(response).into();
    }

    if !response.starts_with(MP_DIGEST_PREFIX) {
        return false;
    }
    let mac = &response[MP_DIGEST_PREFIX.len()..];
    let expected = compute_auth_hmac(key, message);
    expected.as_slice().ct_eq(mac).into()
}

pub fn new_python_challenge() -> Vec<u8> {
    new_python_challenge_for(PythonAuthProtocol::Sha256)
}

pub(crate) fn new_python_challenge_for(protocol: PythonAuthProtocol) -> Vec<u8> {
    if protocol == PythonAuthProtocol::LegacyMd5 {
        return rns_crypto::random::random_bytes(MP_LEGACY_CHALLENGE_RANDOM_LEN);
    }

    let mut message = Vec::with_capacity(MP_DIGEST_PREFIX.len() + MP_CHALLENGE_RANDOM_LEN);
    message.extend_from_slice(MP_DIGEST_PREFIX);
    message.extend_from_slice(&rns_crypto::random::random_bytes(MP_CHALLENGE_RANDOM_LEN));
    message
}

pub async fn write_mp_frame<S>(stream: &mut S, data: &[u8]) -> Result<(), RpcError>
where
    S: tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::AsyncWriteExt;
    let len = i32::try_from(data.len())
        .map_err(|_| RpcError::Serialize("frame too large".to_string()))?;
    stream
        .write_all(&len.to_be_bytes())
        .await
        .map_err(RpcError::Io)?;
    stream.write_all(data).await.map_err(RpcError::Io)
}

pub async fn read_mp_frame<S>(stream: &mut S, max_size: usize) -> Result<Vec<u8>, RpcError>
where
    S: tokio::io::AsyncRead + Unpin,
{
    use tokio::io::AsyncReadExt;
    let mut len_buf = [0u8; 4];
    stream
        .read_exact(&mut len_buf)
        .await
        .map_err(RpcError::Io)?;
    let len = i32::from_be_bytes(len_buf);
    let len = if len == -1 {
        let mut long_buf = [0u8; 8];
        stream
            .read_exact(&mut long_buf)
            .await
            .map_err(RpcError::Io)?;
        usize::try_from(u64::from_be_bytes(long_buf))
            .map_err(|_| RpcError::Deserialize("frame length out of range".to_string()))?
    } else if len >= 0 {
        len as usize
    } else {
        return Err(RpcError::Deserialize(format!(
            "invalid multiprocessing frame length: {len}"
        )));
    };
    if len > max_size {
        return Err(RpcError::Deserialize(format!(
            "frame too large: {len} > {max_size}"
        )));
    }
    let mut data = vec![0u8; len];
    stream.read_exact(&mut data).await.map_err(RpcError::Io)?;
    Ok(data)
}

/// Every I/O step is bounded by `timeout` so a stuck daemon never hangs the CLI.
pub async fn connect_and_request(
    port: u16,
    rpc_key: &[u8],
    request: &RpcRequest,
    timeout: std::time::Duration,
) -> Result<RpcResponse, RpcError> {
    let addr = format!("127.0.0.1:{port}");

    let mut stream = tokio::time::timeout(timeout, tokio::net::TcpStream::connect(&addr))
        .await
        .map_err(|_| {
            RpcError::Io(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "connect timeout",
            ))
        })?
        .map_err(RpcError::Io)?;

    request_over_stream(&mut stream, rpc_key, request, timeout).await
}

#[cfg(unix)]
pub async fn connect_unix_and_request(
    socket_path: &str,
    rpc_key: &[u8],
    request: &RpcRequest,
    timeout: std::time::Duration,
) -> Result<RpcResponse, RpcError> {
    let mut stream = tokio::time::timeout(timeout, connect_unix_stream(socket_path))
        .await
        .map_err(|_| {
            RpcError::Io(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "connect timeout",
            ))
        })?
        .map_err(RpcError::Io)?;

    request_over_stream(&mut stream, rpc_key, request, timeout).await
}

#[cfg(unix)]
async fn connect_unix_stream(socket_path: &str) -> std::io::Result<tokio::net::UnixStream> {
    if let Some(abstract_name) = socket_path.strip_prefix('\0') {
        return connect_abstract_unix_stream(abstract_name);
    }

    tokio::net::UnixStream::connect(socket_path).await
}

#[cfg(all(unix, any(target_os = "linux", target_os = "android")))]
fn connect_abstract_unix_stream(name: &str) -> std::io::Result<tokio::net::UnixStream> {
    use std::os::unix::net::{SocketAddr, UnixStream};

    #[cfg(target_os = "android")]
    use std::os::android::net::SocketAddrExt as _;
    #[cfg(target_os = "linux")]
    use std::os::linux::net::SocketAddrExt as _;

    let addr = SocketAddr::from_abstract_name(name.as_bytes())?;
    let stream = UnixStream::connect_addr(&addr)?;
    stream.set_nonblocking(true)?;
    tokio::net::UnixStream::from_std(stream)
}

#[cfg(all(unix, not(any(target_os = "linux", target_os = "android"))))]
fn connect_abstract_unix_stream(_name: &str) -> std::io::Result<tokio::net::UnixStream> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "abstract Unix sockets are only available on Linux/Android",
    ))
}

#[cfg(not(unix))]
pub async fn connect_unix_and_request(
    _socket_path: &str,
    _rpc_key: &[u8],
    _request: &RpcRequest,
    _timeout: std::time::Duration,
) -> Result<RpcResponse, RpcError> {
    Err(RpcError::Io(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "Unix shared-instance RPC is not supported on this platform",
    )))
}

async fn request_over_stream<S>(
    mut stream: &mut S,
    rpc_key: &[u8],
    request: &RpcRequest,
    timeout: std::time::Duration,
) -> Result<RpcResponse, RpcError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let challenge_frame = tokio::time::timeout(timeout, read_mp_frame(&mut stream, 256))
        .await
        .map_err(|_| {
            RpcError::Io(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "challenge read timeout",
            ))
        })??;
    if !challenge_frame.starts_with(MP_CHALLENGE) {
        return Err(RpcError::AuthFailed);
    }
    let challenge = &challenge_frame[MP_CHALLENGE.len()..];
    let protocol = detect_python_auth_protocol(challenge);

    let response = compute_python_auth_response_for(protocol, rpc_key, challenge);
    tokio::time::timeout(timeout, write_mp_frame(&mut stream, &response))
        .await
        .map_err(|_| {
            RpcError::Io(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "hmac write timeout",
            ))
        })??;

    let welcome = tokio::time::timeout(timeout, read_mp_frame(&mut stream, 256))
        .await
        .map_err(|_| {
            RpcError::Io(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "welcome read timeout",
            ))
        })??;
    if welcome != MP_WELCOME {
        return Err(RpcError::AuthFailed);
    }

    let client_challenge = new_python_challenge_for(protocol);
    let mut client_challenge_frame =
        Vec::with_capacity(MP_CHALLENGE.len() + client_challenge.len());
    client_challenge_frame.extend_from_slice(MP_CHALLENGE);
    client_challenge_frame.extend_from_slice(&client_challenge);
    tokio::time::timeout(
        timeout,
        write_mp_frame(&mut stream, &client_challenge_frame),
    )
    .await
    .map_err(|_| {
        RpcError::Io(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "client challenge write timeout",
        ))
    })??;

    let server_response = tokio::time::timeout(timeout, read_mp_frame(&mut stream, 256))
        .await
        .map_err(|_| {
            RpcError::Io(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "server auth response read timeout",
            ))
        })??;
    if verify_python_auth_response_for(protocol, rpc_key, &client_challenge, &server_response) {
        tokio::time::timeout(timeout, write_mp_frame(&mut stream, MP_WELCOME))
            .await
            .map_err(|_| {
                RpcError::Io(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "client welcome write timeout",
                ))
            })??;
    } else {
        let _ = write_mp_frame(&mut stream, MP_FAILURE).await;
        return Err(RpcError::AuthFailed);
    }

    let req_bytes = encode_request(request)?;
    tokio::time::timeout(timeout, write_mp_frame(&mut stream, &req_bytes))
        .await
        .map_err(|_| {
            RpcError::Io(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "request write timeout",
            ))
        })??;

    let resp_buf = tokio::time::timeout(timeout, read_mp_frame(&mut stream, MAX_MP_FRAME_SIZE))
        .await
        .map_err(|_| {
            RpcError::Io(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "response read timeout",
            ))
        })??;

    decode_response_for_request(&resp_buf, request)
}

#[derive(Debug, thiserror::Error)]
pub enum RpcError {
    #[error("serialization error: {0}")]
    Serialize(String),
    #[error("deserialization error: {0}")]
    Deserialize(String),
    #[error("authentication failed")]
    AuthFailed,
    #[error("connection error: {0}")]
    Connection(String),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn contains_string_key(value: &PyValue, expected: &str) -> bool {
        match value {
            PyValue::List(values) => values
                .iter()
                .any(|value| contains_string_key(value, expected)),
            PyValue::Dict(entries) => entries.iter().any(|(key, value)| {
                matches!(key, PyDictKey::String(key) if key == expected)
                    || contains_string_key(value, expected)
            }),
            _ => false,
        }
    }

    #[test]
    fn test_request_roundtrip() {
        let req = RpcRequest::GetPathTable { max_hops: Some(8) };
        let encoded = encode_request(&req).unwrap();
        let decoded = decode_request(&encoded).unwrap();
        match decoded {
            RpcRequest::GetPathTable { max_hops } => assert_eq!(max_hops, Some(8)),
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn test_response_roundtrip() {
        let resp = RpcResponse::IntResult(42);
        let encoded = encode_response(&resp).unwrap();
        let decoded = decode_response(&encoded).unwrap();
        match decoded {
            RpcResponse::IntResult(n) => assert_eq!(n, 42),
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn test_path_table_response() {
        let entry = PathTableEntry {
            hash: vec![0xAA; 16],
            timestamp: 1234567890.0,
            via: Some(vec![0xBB; 16]),
            hops: 3,
            expires: 1234567890.0 + 604800.0,
            interface: "TCPInterface[test]".to_string(),
        };
        let resp = RpcResponse::PathTable(vec![entry]);
        let encoded = encode_response(&resp).unwrap();
        let decoded = decode_response(&encoded).unwrap();
        match decoded {
            RpcResponse::PathTable(entries) => {
                assert_eq!(entries.len(), 1);
                assert_eq!(entries[0].hops, 3);
            }
            _ => panic!("wrong variant"),
        }
    }

    fn interface_stat_entry() -> InterfaceStatEntry {
        InterfaceStatEntry {
            id: 7,
            name: "TestIf".to_string(),
            rx_bytes: 100,
            tx_bytes: 200,
            rx_rate: 10,
            tx_rate: 20,
            online: true,
            bitrate: 115_200,
            mtu: 500,
            mode: "Gateway".to_string(),
            role: "normal".to_string(),
            announce_queue: Some(2),
            held_announces: 3,
            incoming_announce_frequency: 4.0,
            outgoing_announce_frequency: 5.0,
            incoming_pr_frequency: 6.0,
            outgoing_pr_frequency: 7.0,
            burst_active: true,
            burst_activated: 1_700_000_001.0,
            pr_burst_active: true,
            pr_burst_activated: 1_700_000_002.0,
            clients: Some(4),
            blocked_ips: Some(2),
            announce_rate_target: Some(3600.0),
            announce_rate_grace: Some(5),
            announce_rate_penalty: Some(30.0),
            announce_cap: 0.02,
            ifac_size: 0,
            tx_drops: 1,
        }
    }

    #[test]
    fn test_interface_stats_response_roundtrip_includes_125_fields() {
        let resp = RpcResponse::InterfaceStats(vec![interface_stat_entry()]);
        let encoded = encode_response(&resp).unwrap();
        let decoded =
            decode_response_for_request(&encoded, &RpcRequest::GetInterfaceStats).unwrap();
        match decoded {
            RpcResponse::InterfaceStats(entries) => {
                assert_eq!(entries.len(), 1);
                let entry = &entries[0];
                assert_eq!(entry.incoming_pr_frequency, 6.0);
                assert_eq!(entry.outgoing_pr_frequency, 7.0);
                assert!(entry.burst_active);
                assert_eq!(entry.burst_activated, 1_700_000_001.0);
                assert!(entry.pr_burst_active);
                assert_eq!(entry.pr_burst_activated, 1_700_000_002.0);
                assert_eq!(entry.blocked_ips, Some(2));
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn test_interface_stats_parser_defaults_missing_125_fields() {
        let legacy = py_dict(vec![(
            "interfaces",
            PyValue::List(vec![py_dict(vec![
                ("name", PyValue::String("LegacyIf".to_string())),
                ("rxb", PyValue::Int(1)),
                ("txb", PyValue::Int(2)),
                ("status", PyValue::Bool(true)),
            ])]),
        )]);
        let encoded = encode_umsgpack(&legacy).unwrap();
        let decoded =
            decode_response_for_request(&encoded, &RpcRequest::GetInterfaceStats).unwrap();
        match decoded {
            RpcResponse::InterfaceStats(entries) => {
                assert_eq!(entries.len(), 1);
                let entry = &entries[0];
                assert_eq!(entry.incoming_pr_frequency, 0.0);
                assert_eq!(entry.outgoing_pr_frequency, 0.0);
                assert!(!entry.burst_active);
                assert_eq!(entry.burst_activated, 0.0);
                assert!(!entry.pr_burst_active);
                assert_eq!(entry.pr_burst_activated, 0.0);
                assert_eq!(entry.blocked_ips, None);
                assert_eq!(entry.mtu, 0, "Python stats omit MTU");
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn request_specific_decoder_preserves_rpc_errors() {
        let encoded = encode_response(&RpcResponse::Error("transport unavailable".to_string()))
            .expect("encode RPC error");
        for request in [
            RpcRequest::GetPathTable { max_hops: None },
            RpcRequest::DropPath {
                destination_hash: vec![0; 16],
            },
        ] {
            assert!(matches!(
                decode_response_for_request(&encoded, &request),
                Ok(RpcResponse::Error(message)) if message == "transport unavailable"
            ));
        }
    }

    #[test]
    fn interface_stats_omit_absent_blocked_ip_count() {
        let mut entry = interface_stat_entry();
        entry.blocked_ips = None;
        let encoded = encode_response(&RpcResponse::InterfaceStats(vec![entry])).unwrap();
        let raw = decode_umsgpack(&encoded).unwrap();
        assert!(!contains_string_key(&raw, "blocked_ips"));
    }

    #[test]
    fn interface_stats_ignore_blocked_ip_lists_and_never_reencode_them() {
        let upstream = py_dict(vec![(
            "interfaces",
            PyValue::List(vec![py_dict(vec![
                ("name", PyValue::String("Backbone".to_string())),
                ("rxb", PyValue::Int(1)),
                ("txb", PyValue::Int(2)),
                ("status", PyValue::Bool(true)),
                ("blocked_ips", PyValue::Int(3)),
                (
                    "blocked_ip_list",
                    PyValue::List(vec![PyValue::String("192.0.2.1".to_string())]),
                ),
            ])]),
        )]);
        let encoded = encode_umsgpack(&upstream).unwrap();
        let decoded =
            decode_response_for_request(&encoded, &RpcRequest::GetInterfaceStats).unwrap();
        let RpcResponse::InterfaceStats(entries) = &decoded else {
            panic!("unexpected interface stats response");
        };
        assert_eq!(entries[0].blocked_ips, Some(3));

        let reencoded = encode_response(&decoded).unwrap();
        let raw = decode_umsgpack(&reencoded).unwrap();
        assert!(contains_string_key(&raw, "blocked_ips"));
        assert!(!contains_string_key(&raw, "blocked_ip_list"));
    }

    #[test]
    fn test_python_blackhole_dict_response_shape() {
        let identity_hash = vec![0x42; 16];
        let value = PyValue::Dict(vec![(
            PyDictKey::Bytes(identity_hash.clone()),
            py_dict(vec![
                ("until", PyValue::Float(1234.0)),
                ("reason", PyValue::String("parity".to_string())),
                ("source", PyValue::Bytes(vec![0xAA; 16])),
            ]),
        )]);
        let encoded = encode_umsgpack(&value).unwrap();
        match decode_response_for_request(&encoded, &RpcRequest::GetBlackholedIdentities).unwrap() {
            RpcResponse::BlackholeList(entries) => {
                assert_eq!(entries.len(), 1);
                assert_eq!(entries[0].identity_hash, identity_hash);
                assert_eq!(entries[0].source.as_deref(), Some(&[0xAA; 16][..]));
                assert_eq!(entries[0].until, Some(1234.0));
                assert_eq!(entries[0].reason.as_deref(), Some("parity"));
            }
            other => panic!("wrong blackhole response variant: {other:?}"),
        }
    }

    #[test]
    fn test_auth_hmac() {
        let key = b"test_rpc_key";
        let challenge = b"random_challenge_bytes_32_bytes!";
        let hmac = compute_auth_hmac(key, challenge);
        assert!(verify_auth_hmac(key, challenge, &hmac));
    }

    #[test]
    fn test_auth_hmac_wrong_key() {
        let key = b"correct_key";
        let wrong_key = b"wrong_key_!";
        let challenge = b"random_challenge_bytes_32_bytes!";
        let hmac = compute_auth_hmac(key, challenge);
        assert!(!verify_auth_hmac(wrong_key, challenge, &hmac));
    }

    #[test]
    fn test_python_legacy_md5_auth_response() {
        let key = b"test_rpc_key";
        let challenge = b"python311challenge";
        let response = compute_python_auth_response(key, challenge);
        assert_eq!(response.len(), 16);
        assert!(verify_python_auth_response(key, challenge, &response));
        assert!(!verify_python_auth_response(
            b"wrong_key",
            challenge,
            &response
        ));
    }

    #[test]
    fn test_python_sha256_auth_response() {
        let key = b"test_rpc_key";
        let challenge = b"{sha256}python312pluschallenge";
        let response = compute_python_auth_response(key, challenge);
        assert!(response.starts_with(MP_DIGEST_PREFIX));
        assert!(verify_python_auth_response(key, challenge, &response));
        assert!(!verify_python_auth_response(
            b"wrong_key",
            challenge,
            &response
        ));
    }

    #[test]
    fn test_derive_rpc_key() {
        let private_key = [0x42u8; 64];
        let key1 = derive_rpc_key(&private_key);
        let key2 = derive_rpc_key(&private_key);
        assert_eq!(key1, key2);
        assert_ne!(key1, [0u8; 32]);
    }

    #[test]
    fn test_all_request_variants() {
        let requests = vec![
            RpcRequest::GetPathTable { max_hops: None },
            RpcRequest::GetInterfaceStats,
            RpcRequest::GetRateTable,
            RpcRequest::GetNextHopIfName {
                destination_hash: vec![0; 16],
            },
            RpcRequest::RequestPath {
                destination_hash: vec![0; 16],
                timeout_secs: Some(0.01),
            },
            RpcRequest::GetLinkCount,
            RpcRequest::DropPath {
                destination_hash: vec![0; 16],
            },
            RpcRequest::DropPathTable,
            RpcRequest::DropRecentAnnounces,
            RpcRequest::DropAnnounceQueues,
            RpcRequest::BlackholeIdentity {
                identity_hash: vec![0; 16],
                until: Some(99999.0),
                reason: Some("test".to_string()),
            },
            RpcRequest::UnblackholeIdentity {
                identity_hash: vec![0; 16],
            },
            RpcRequest::UseDestination {
                destination_hash: vec![0; 16],
            },
            RpcRequest::RetainDestination {
                destination_hash: vec![0; 16],
            },
            RpcRequest::RetainIdentity {
                identity_hash: vec![0; 16],
            },
            RpcRequest::UnretainDestination {
                destination_hash: vec![0; 16],
            },
            RpcRequest::IsBlackholed {
                identity_hash: vec![0; 16],
            },
        ];

        for req in &requests {
            let encoded = encode_request(req).unwrap();
            let _ = decode_request(&encoded).unwrap();
        }
    }

    // Fixtures generated by running the VERBATIM 1.3.8 vendored umsgpack
    // (git show 1.3.8:RNS/vendor/umsgpack.py, packb) over the RPC dict shapes
    // Python 1.3.8 Reticulum.py packs on the shared-instance control socket.
    const FX_REQ_PATH_TABLE_NONE: &str = "82a3676574aa706174685f7461626c65a86d61785f686f7073c0";
    const FX_REQ_PATH_TABLE_8: &str = "82a3676574aa706174685f7461626c65a86d61785f686f707308";
    const FX_REQ_INTERFACE_STATS: &str = "81a3676574af696e746572666163655f7374617473";
    const FX_REQ_IS_BLACKHOLED: &str = "82a3676574ad69735f626c61636b686f6c6564ad6964656e746974795f68617368c410000102030405060708090a0b0c0d0e0f";
    const FX_REQ_NEXT_HOP: &str = "82a3676574a86e6578745f686f70b064657374696e6174696f6e5f68617368c410aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const FX_REQ_DROP_PATH: &str = "82a464726f70a470617468b064657374696e6174696f6e5f68617368c410bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const FX_REQ_BLACKHOLE_IDENTITY: &str = "83b2626c61636b686f6c655f6964656e74697479c41042424242424242424242424242424242a5756e74696ccb41d26580b4a00000a6726561736f6ea474657374";
    const FX_REQ_BLACKHOLE_IDENTITY_NONE: &str = "83b2626c61636b686f6c655f6964656e74697479c41042424242424242424242424242424242a5756e74696cc0a6726561736f6ec0";
    const FX_REQ_DESTINATION_DATA_USED: &str = "82b064657374696e6174696f6e5f64617461a475736564b064657374696e6174696f6e5f68617368c410cccccccccccccccccccccccccccccccc";
    const FX_REQ_IDENTITY_DATA_RETAIN: &str = "82ad6964656e746974795f64617461a672657461696ead6964656e746974795f68617368c410dddddddddddddddddddddddddddddddd";
    const FX_RESP_PATH_TABLE: &str = "9186a468617368c410aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa974696d657374616d70cb41d26580b4800000a3766961c410bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbba4686f707303a765787069726573cb41d267cf54800000a9696e74657266616365b2544350496e746572666163655b746573745d";
    const FX_RESP_BLACKHOLE_DICT: &str = "81c4104242424242424242424242424242424283a6736f75726365c410aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa5756e74696ccb4093480000000000a6726561736f6ea6706172697479";
    const FX_INT_EDGES: &str = "dc0014007fcc80ccffcd0100cdffffce00010000ceffffffffcf0000000100000000cfffffffffffffffffffe0d0dfd080d1ff7fd18000d2ffff7fffd280000000d3ffffffff7fffffffd38000000000000000";
    const FX_STR_EDGES: &str = "93a0bf61616161616161616161616161616161616161616161616161616161616161d9206161616161616161616161616161616161616161616161616161616161616161";
    const FX_ARRAY_16: &str = "dc0010000102030405060708090a0b0c0d0e0f";

    fn assert_fixture(value: &PyValue, fixture_hex: &str) {
        let encoded = encode_umsgpack(value).unwrap();
        assert_eq!(hex::encode(&encoded), fixture_hex);
        let decoded = decode_umsgpack(&hex::decode(fixture_hex).unwrap()).unwrap();
        assert_eq!(&decoded, value);
    }

    #[test]
    fn requests_are_byte_exact_with_python_138_umsgpack() {
        for (req, fixture) in [
            (
                RpcRequest::GetPathTable { max_hops: None },
                FX_REQ_PATH_TABLE_NONE,
            ),
            (
                RpcRequest::GetPathTable { max_hops: Some(8) },
                FX_REQ_PATH_TABLE_8,
            ),
            (RpcRequest::GetInterfaceStats, FX_REQ_INTERFACE_STATS),
            (
                RpcRequest::IsBlackholed {
                    identity_hash: (0u8..16).collect(),
                },
                FX_REQ_IS_BLACKHOLED,
            ),
            (
                RpcRequest::GetNextHop {
                    destination_hash: vec![0xAA; 16],
                },
                FX_REQ_NEXT_HOP,
            ),
            (
                RpcRequest::DropPath {
                    destination_hash: vec![0xBB; 16],
                },
                FX_REQ_DROP_PATH,
            ),
            (
                RpcRequest::BlackholeIdentity {
                    identity_hash: vec![0x42; 16],
                    until: Some(1234567890.5),
                    reason: Some("test".to_string()),
                },
                FX_REQ_BLACKHOLE_IDENTITY,
            ),
            (
                RpcRequest::BlackholeIdentity {
                    identity_hash: vec![0x42; 16],
                    until: None,
                    reason: None,
                },
                FX_REQ_BLACKHOLE_IDENTITY_NONE,
            ),
            (
                RpcRequest::UseDestination {
                    destination_hash: vec![0xCC; 16],
                },
                FX_REQ_DESTINATION_DATA_USED,
            ),
            (
                RpcRequest::RetainIdentity {
                    identity_hash: vec![0xDD; 16],
                },
                FX_REQ_IDENTITY_DATA_RETAIN,
            ),
        ] {
            let encoded = encode_request(&req).unwrap();
            assert_eq!(hex::encode(&encoded), fixture, "request {req:?}");
            let _ = decode_request(&hex::decode(fixture).unwrap()).unwrap();
        }
    }

    #[test]
    fn scalar_responses_are_byte_exact_with_python_138_umsgpack() {
        assert_fixture(&PyValue::Bool(true), "c3");
        assert_fixture(&PyValue::Bool(false), "c2");
        assert_fixture(&PyValue::None, "c0");
        assert_fixture(&PyValue::Int(42), "2a");
        assert_fixture(&PyValue::Float(12.5), "cb4029000000000000");
    }

    #[test]
    fn path_table_response_is_byte_exact_with_python_138_umsgpack() {
        let resp = RpcResponse::PathTable(vec![PathTableEntry {
            hash: vec![0xAA; 16],
            timestamp: 1234567890.0,
            via: Some(vec![0xBB; 16]),
            hops: 3,
            expires: 1235172690.0,
            interface: "TCPInterface[test]".to_string(),
        }]);
        assert_eq!(
            hex::encode(encode_response(&resp).unwrap()),
            FX_RESP_PATH_TABLE
        );
        match decode_response_for_request(
            &hex::decode(FX_RESP_PATH_TABLE).unwrap(),
            &RpcRequest::GetPathTable { max_hops: None },
        )
        .unwrap()
        {
            RpcResponse::PathTable(entries) => {
                assert_eq!(entries.len(), 1);
                assert_eq!(entries[0].hops, 3);
                assert_eq!(entries[0].interface, "TCPInterface[test]");
            }
            other => panic!("wrong variant: {other:?}"),
        }
    }

    #[test]
    fn blackhole_dict_response_is_byte_exact_with_python_138_umsgpack() {
        let resp = RpcResponse::BlackholeList(vec![BlackholeEntry {
            identity_hash: vec![0x42; 16],
            source: Some(vec![0xAA; 16]),
            until: Some(1234.0),
            reason: Some("parity".to_string()),
        }]);
        assert_eq!(
            hex::encode(encode_response(&resp).unwrap()),
            FX_RESP_BLACKHOLE_DICT
        );
        match decode_response_for_request(
            &hex::decode(FX_RESP_BLACKHOLE_DICT).unwrap(),
            &RpcRequest::GetBlackholedIdentities,
        )
        .unwrap()
        {
            RpcResponse::BlackholeList(entries) => {
                assert_eq!(entries.len(), 1);
                assert_eq!(entries[0].identity_hash, vec![0x42; 16]);
                assert_eq!(entries[0].until, Some(1234.0));
            }
            other => panic!("wrong variant: {other:?}"),
        }
    }

    #[test]
    fn integer_width_boundaries_match_umsgpack() {
        let edges: Vec<i128> = vec![
            0,
            127,
            128,
            255,
            256,
            65535,
            65536,
            4294967295,
            4294967296,
            18446744073709551615,
            -1,
            -32,
            -33,
            -128,
            -129,
            -32768,
            -32769,
            -2147483648,
            -2147483649,
            -9223372036854775808,
        ];
        let value = PyValue::List(edges.into_iter().map(PyValue::Int).collect());
        assert_fixture(&value, FX_INT_EDGES);
    }

    #[test]
    fn string_and_array_length_boundaries_match_umsgpack() {
        let value = PyValue::List(vec![
            PyValue::String(String::new()),
            PyValue::String("a".repeat(31)),
            PyValue::String("a".repeat(32)),
        ]);
        assert_fixture(&value, FX_STR_EDGES);

        let value = PyValue::List((0..16).map(PyValue::Int).collect());
        assert_fixture(&value, FX_ARRAY_16);

        // bin8 → bin16 boundary (c4 ff / c5 0100), matching umsgpack _pack_binary.
        let mut expected = String::from("93c400c4ff");
        expected.push_str(&"01".repeat(255));
        expected.push_str("c50100");
        expected.push_str(&"02".repeat(256));
        let value = PyValue::List(vec![
            PyValue::Bytes(Vec::new()),
            PyValue::Bytes(vec![0x01; 255]),
            PyValue::Bytes(vec![0x02; 256]),
        ]);
        assert_fixture(&value, &expected);
    }

    #[test]
    fn huge_ints_are_rejected_like_umsgpack() {
        assert!(encode_umsgpack(&PyValue::Int(i128::from(u64::MAX) + 1)).is_err());
        assert!(encode_umsgpack(&PyValue::Int(i128::from(i64::MIN) - 1)).is_err());
        // Boundary values still encode.
        assert!(encode_umsgpack(&PyValue::Int(i128::from(u64::MAX))).is_ok());
        assert!(encode_umsgpack(&PyValue::Int(i128::from(i64::MIN))).is_ok());
    }

    #[test]
    fn pickle_frames_no_longer_decode() {
        // Python <=1.3.3 pickle frame for {"get": "link_count"} — the hard
        // cutover (a2ef9782) must reject it rather than fall back.
        let pickle = [
            0x80u8, 0x04, b'}', b'(', 0x8c, 0x03, b'g', b'e', b't', 0x8c, 0x0a, b'l', b'i', b'n',
            b'k', b'_', b'c', b'o', b'u', b'n', b't', b'u', b'.',
        ];
        assert!(decode_request(&pickle).is_err());
    }

    #[test]
    fn msgpack_depth_limit_rejects_hostile_nesting() {
        // 200 nested single-element arrays around a nil.
        let mut data = vec![0x91u8; 200];
        data.push(0xc0);
        assert!(decode_umsgpack(&data).is_err());
    }
}
