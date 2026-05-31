//! Shared-instance control RPC over TCP.
//!
//! Python Reticulum uses `multiprocessing.connection.Listener/Client` for the
//! local control port. Keep the Rust control socket wire-compatible with that:
//! framed auth challenge (`#CHALLENGE#`), framed pickle request dictionaries,
//! and framed pickle responses. Python 3.12+ uses tagged SHA-256 auth
//! challenges, while Python 3.11 and older use raw MD5 HMAC responses.

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
    encode_python_pickle(&request_to_py_value(req))
}

pub fn decode_request(data: &[u8]) -> Result<RpcRequest, RpcError> {
    let value = decode_python_pickle(data)?;
    py_value_to_request(&value)
}

pub fn encode_response(resp: &RpcResponse) -> Result<Vec<u8>, RpcError> {
    encode_python_pickle(&response_to_py_value(resp))
}

pub fn decode_response(data: &[u8]) -> Result<RpcResponse, RpcError> {
    let value = decode_python_pickle(data)?;
    py_value_to_response(&value)
}

pub fn decode_response_for_request(
    data: &[u8],
    request: &RpcRequest,
) -> Result<RpcResponse, RpcError> {
    let value = decode_python_pickle(data)?;
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
                    py_dict(vec![
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
                    ])
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
        RpcRequest::UseDestination { .. }
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
        PyValue::String(s) => s.as_str(),
        _ => "Full",
    }
    .to_string()
}

fn encode_python_pickle(value: &PyValue) -> Result<Vec<u8>, RpcError> {
    let mut out = vec![0x80, 0x04]; // PROTO 4, no FRAME needed for small control messages.
    encode_pickle_value(value, &mut out)?;
    out.push(b'.'); // STOP
    Ok(out)
}

fn encode_pickle_value(value: &PyValue, out: &mut Vec<u8>) -> Result<(), RpcError> {
    match value {
        PyValue::None => out.push(b'N'),
        PyValue::Bool(true) => out.push(0x88),
        PyValue::Bool(false) => out.push(0x89),
        PyValue::Int(v) => encode_pickle_int(*v, out)?,
        PyValue::Float(v) => {
            out.push(b'G');
            out.extend_from_slice(&v.to_be_bytes());
        }
        PyValue::Bytes(bytes) => encode_pickle_bytes(bytes, out)?,
        PyValue::String(s) => encode_pickle_string(s, out)?,
        PyValue::List(values) => {
            out.push(b']');
            if !values.is_empty() {
                out.push(b'(');
                for value in values {
                    encode_pickle_value(value, out)?;
                }
                out.push(b'e'); // APPENDS
            }
        }
        PyValue::Dict(entries) => {
            out.push(b'}');
            if !entries.is_empty() {
                out.push(b'(');
                for (key, value) in entries {
                    encode_pickle_key(key, out)?;
                    encode_pickle_value(value, out)?;
                }
                out.push(b'u'); // SETITEMS
            }
        }
    }
    Ok(())
}

fn encode_pickle_key(key: &PyDictKey, out: &mut Vec<u8>) -> Result<(), RpcError> {
    match key {
        PyDictKey::String(s) => encode_pickle_string(s, out),
        PyDictKey::Bytes(bytes) => encode_pickle_bytes(bytes, out),
    }
}

fn encode_pickle_string(s: &str, out: &mut Vec<u8>) -> Result<(), RpcError> {
    let bytes = s.as_bytes();
    if let Ok(len) = u8::try_from(bytes.len()) {
        out.push(0x8c); // SHORT_BINUNICODE
        out.push(len);
    } else {
        let len = u32::try_from(bytes.len())
            .map_err(|_| RpcError::Serialize("string too large for pickle".to_string()))?;
        out.push(b'X'); // BINUNICODE
        out.extend_from_slice(&len.to_le_bytes());
    }
    out.extend_from_slice(bytes);
    Ok(())
}

fn encode_pickle_bytes(bytes: &[u8], out: &mut Vec<u8>) -> Result<(), RpcError> {
    if let Ok(len) = u8::try_from(bytes.len()) {
        out.push(b'C'); // SHORT_BINBYTES
        out.push(len);
    } else {
        let len = u32::try_from(bytes.len())
            .map_err(|_| RpcError::Serialize("bytes too large for pickle".to_string()))?;
        out.push(b'B'); // BINBYTES
        out.extend_from_slice(&len.to_le_bytes());
    }
    out.extend_from_slice(bytes);
    Ok(())
}

fn encode_pickle_int(value: i128, out: &mut Vec<u8>) -> Result<(), RpcError> {
    if let Ok(v) = u8::try_from(value) {
        out.push(b'K'); // BININT1
        out.push(v);
    } else if let Ok(v) = u16::try_from(value) {
        out.push(b'M'); // BININT2
        out.extend_from_slice(&v.to_le_bytes());
    } else if let Ok(v) = i32::try_from(value) {
        out.push(b'J'); // BININT
        out.extend_from_slice(&v.to_le_bytes());
    } else if value >= 0 {
        let mut n = u128::try_from(value)
            .map_err(|_| RpcError::Serialize("negative big integers unsupported".to_string()))?;
        let mut bytes = Vec::new();
        while n > 0 {
            bytes.push((n & 0xff) as u8);
            n >>= 8;
        }
        if bytes.last().is_some_and(|b| b & 0x80 != 0) {
            bytes.push(0);
        }
        let len = u8::try_from(bytes.len())
            .map_err(|_| RpcError::Serialize("integer too large for pickle".to_string()))?;
        out.push(0x8a); // LONG1
        out.push(len);
        out.extend_from_slice(&bytes);
    } else {
        return Err(RpcError::Serialize(
            "negative big integers unsupported".to_string(),
        ));
    }
    Ok(())
}

#[derive(Debug, Clone)]
enum StackItem {
    Mark,
    Value(PyValue),
}

fn decode_python_pickle(data: &[u8]) -> Result<PyValue, RpcError> {
    let mut i = 0usize;
    let mut stack: Vec<StackItem> = Vec::new();
    let mut memo: Vec<PyValue> = Vec::new();

    while i < data.len() {
        let op = data[i];
        i += 1;
        match op {
            0x80 => {
                read_exact(data, &mut i, 1)?;
            }
            0x95 => {
                read_exact(data, &mut i, 8)?;
            }
            0x94 => {
                let value = stack_value(stack.last())?.clone();
                memo.push(value);
            }
            b'h' => {
                let idx = read_u8(data, &mut i)? as usize;
                let value = memo.get(idx).cloned().ok_or_else(|| {
                    RpcError::Deserialize(format!("pickle memo index out of range: {idx}"))
                })?;
                stack.push(StackItem::Value(value));
            }
            b'j' => {
                let idx = read_u32_le(data, &mut i)? as usize;
                let value = memo.get(idx).cloned().ok_or_else(|| {
                    RpcError::Deserialize(format!("pickle memo index out of range: {idx}"))
                })?;
                stack.push(StackItem::Value(value));
            }
            b'}' => stack.push(StackItem::Value(PyValue::Dict(Vec::new()))),
            b']' => stack.push(StackItem::Value(PyValue::List(Vec::new()))),
            b'(' => stack.push(StackItem::Mark),
            0x8c => {
                let len = read_u8(data, &mut i)? as usize;
                let bytes = read_exact(data, &mut i, len)?;
                let s = std::str::from_utf8(bytes)
                    .map_err(|e| RpcError::Deserialize(e.to_string()))?
                    .to_string();
                stack.push(StackItem::Value(PyValue::String(s)));
            }
            b'X' => {
                let len = read_u32_le(data, &mut i)? as usize;
                let bytes = read_exact(data, &mut i, len)?;
                let s = std::str::from_utf8(bytes)
                    .map_err(|e| RpcError::Deserialize(e.to_string()))?
                    .to_string();
                stack.push(StackItem::Value(PyValue::String(s)));
            }
            0x8d => {
                let len = read_u64_le(data, &mut i)? as usize;
                let bytes = read_exact(data, &mut i, len)?;
                let s = std::str::from_utf8(bytes)
                    .map_err(|e| RpcError::Deserialize(e.to_string()))?
                    .to_string();
                stack.push(StackItem::Value(PyValue::String(s)));
            }
            b'C' => {
                let len = read_u8(data, &mut i)? as usize;
                let bytes = read_exact(data, &mut i, len)?.to_vec();
                stack.push(StackItem::Value(PyValue::Bytes(bytes)));
            }
            b'B' => {
                let len = read_u32_le(data, &mut i)? as usize;
                let bytes = read_exact(data, &mut i, len)?.to_vec();
                stack.push(StackItem::Value(PyValue::Bytes(bytes)));
            }
            0x8e => {
                let len = read_u64_le(data, &mut i)? as usize;
                let bytes = read_exact(data, &mut i, len)?.to_vec();
                stack.push(StackItem::Value(PyValue::Bytes(bytes)));
            }
            b'N' => stack.push(StackItem::Value(PyValue::None)),
            0x88 => stack.push(StackItem::Value(PyValue::Bool(true))),
            0x89 => stack.push(StackItem::Value(PyValue::Bool(false))),
            b'K' => {
                let v = read_u8(data, &mut i)?;
                stack.push(StackItem::Value(PyValue::Int(i128::from(v))));
            }
            b'M' => {
                let v = read_u16_le(data, &mut i)?;
                stack.push(StackItem::Value(PyValue::Int(i128::from(v))));
            }
            b'J' => {
                let bytes = read_exact(data, &mut i, 4)?;
                let v = i32::from_le_bytes(bytes.try_into().unwrap());
                stack.push(StackItem::Value(PyValue::Int(i128::from(v))));
            }
            0x8a => {
                let len = read_u8(data, &mut i)? as usize;
                let bytes = read_exact(data, &mut i, len)?;
                stack.push(StackItem::Value(PyValue::Int(decode_pickle_long(bytes)?)));
            }
            0x8b => {
                let len = read_u32_le(data, &mut i)? as usize;
                let bytes = read_exact(data, &mut i, len)?;
                stack.push(StackItem::Value(PyValue::Int(decode_pickle_long(bytes)?)));
            }
            b'G' => {
                let bytes = read_exact(data, &mut i, 8)?;
                let v = f64::from_be_bytes(bytes.try_into().unwrap());
                stack.push(StackItem::Value(PyValue::Float(v)));
            }
            b's' => apply_setitem(&mut stack)?,
            b'u' => apply_setitems(&mut stack)?,
            b'a' => apply_append(&mut stack)?,
            b'e' => apply_appends(&mut stack)?,
            b'.' => {
                return match stack.pop() {
                    Some(StackItem::Value(value)) => Ok(value),
                    _ => Err(RpcError::Deserialize(
                        "pickle ended without value".to_string(),
                    )),
                };
            }
            other => {
                return Err(RpcError::Deserialize(format!(
                    "unsupported pickle opcode 0x{other:02x}"
                )));
            }
        }
    }

    Err(RpcError::Deserialize("pickle missing STOP".to_string()))
}

fn stack_value(item: Option<&StackItem>) -> Result<&PyValue, RpcError> {
    match item {
        Some(StackItem::Value(value)) => Ok(value),
        _ => Err(RpcError::Deserialize("expected pickle value".to_string())),
    }
}

fn pop_value(stack: &mut Vec<StackItem>) -> Result<PyValue, RpcError> {
    match stack.pop() {
        Some(StackItem::Value(value)) => Ok(value),
        _ => Err(RpcError::Deserialize("expected pickle value".to_string())),
    }
}

fn apply_setitem(stack: &mut Vec<StackItem>) -> Result<(), RpcError> {
    let value = pop_value(stack)?;
    let key = pop_value(stack)?;
    let Some(StackItem::Value(PyValue::Dict(entries))) = stack.last_mut() else {
        return Err(RpcError::Deserialize(
            "SETITEM target is not a dictionary".to_string(),
        ));
    };
    entries.push((py_key(key)?, value));
    Ok(())
}

fn apply_setitems(stack: &mut Vec<StackItem>) -> Result<(), RpcError> {
    let mark = find_mark(stack)?;
    let items = stack.split_off(mark + 1);
    stack.pop();
    let Some(StackItem::Value(PyValue::Dict(entries))) = stack.last_mut() else {
        return Err(RpcError::Deserialize(
            "SETITEMS target is not a dictionary".to_string(),
        ));
    };
    let mut values = items.into_iter().map(|item| match item {
        StackItem::Value(value) => Ok(value),
        StackItem::Mark => Err(RpcError::Deserialize("nested mark in SETITEMS".to_string())),
    });
    while let Some(key) = values.next() {
        let key = key?;
        let value = values
            .next()
            .ok_or_else(|| RpcError::Deserialize("odd SETITEMS count".to_string()))??;
        entries.push((py_key(key)?, value));
    }
    Ok(())
}

fn apply_append(stack: &mut Vec<StackItem>) -> Result<(), RpcError> {
    let value = pop_value(stack)?;
    let Some(StackItem::Value(PyValue::List(values))) = stack.last_mut() else {
        return Err(RpcError::Deserialize(
            "APPEND target is not a list".to_string(),
        ));
    };
    values.push(value);
    Ok(())
}

fn apply_appends(stack: &mut Vec<StackItem>) -> Result<(), RpcError> {
    let mark = find_mark(stack)?;
    let items = stack.split_off(mark + 1);
    stack.pop();
    let Some(StackItem::Value(PyValue::List(values))) = stack.last_mut() else {
        return Err(RpcError::Deserialize(
            "APPENDS target is not a list".to_string(),
        ));
    };
    for item in items {
        match item {
            StackItem::Value(value) => values.push(value),
            StackItem::Mark => {
                return Err(RpcError::Deserialize("nested mark in APPENDS".to_string()));
            }
        }
    }
    Ok(())
}

fn find_mark(stack: &[StackItem]) -> Result<usize, RpcError> {
    stack
        .iter()
        .rposition(|item| matches!(item, StackItem::Mark))
        .ok_or_else(|| RpcError::Deserialize("pickle mark not found".to_string()))
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

fn decode_pickle_long(bytes: &[u8]) -> Result<i128, RpcError> {
    if bytes.is_empty() {
        return Ok(0);
    }
    if bytes.len() > 16 {
        return Err(RpcError::Deserialize(
            "pickle LONG exceeds i128 range".to_string(),
        ));
    }
    let mut value = 0i128;
    for (shift, byte) in bytes.iter().enumerate() {
        value |= i128::from(*byte) << (shift * 8);
    }
    if bytes.last().is_some_and(|b| b & 0x80 != 0) {
        value -= 1i128 << (bytes.len() * 8);
    }
    Ok(value)
}

fn read_exact<'a>(data: &'a [u8], index: &mut usize, len: usize) -> Result<&'a [u8], RpcError> {
    let end = index
        .checked_add(len)
        .ok_or_else(|| RpcError::Deserialize("pickle length overflow".to_string()))?;
    if end > data.len() {
        return Err(RpcError::Deserialize("truncated pickle".to_string()));
    }
    let out = &data[*index..end];
    *index = end;
    Ok(out)
}

fn read_u8(data: &[u8], index: &mut usize) -> Result<u8, RpcError> {
    Ok(read_exact(data, index, 1)?[0])
}

fn read_u16_le(data: &[u8], index: &mut usize) -> Result<u16, RpcError> {
    let bytes = read_exact(data, index, 2)?;
    Ok(u16::from_le_bytes(bytes.try_into().unwrap()))
}

fn read_u32_le(data: &[u8], index: &mut usize) -> Result<u32, RpcError> {
    let bytes = read_exact(data, index, 4)?;
    Ok(u32::from_le_bytes(bytes.try_into().unwrap()))
}

fn read_u64_le(data: &[u8], index: &mut usize) -> Result<u64, RpcError> {
    let bytes = read_exact(data, index, 8)?;
    Ok(u64::from_le_bytes(bytes.try_into().unwrap()))
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
        let encoded = encode_python_pickle(&legacy).unwrap();
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
            }
            _ => panic!("wrong variant"),
        }
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
        let encoded = encode_python_pickle(&value).unwrap();
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
        ];

        for req in &requests {
            let encoded = encode_request(req).unwrap();
            let _ = decode_request(&encoded).unwrap();
        }
    }
}
