//! Msgpack wire schema for remote management; field names mirror Python
//! dict keys for `rnstatus -R` / `rnpath -R` interop.
//! See Transport.py:2591-2643, Reticulum.py:1090-1269.

use serde::{Serialize, Serializer};

// rmp_serde's default encodes `Vec<u8>` as array-of-ints; Python expects msgpack bin.
pub(crate) mod bytes_vec {
    use super::*;
    pub fn serialize<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(bytes)
    }
}

pub(crate) mod bytes_opt {
    use super::*;
    pub fn serialize<S: Serializer>(bytes: &Option<Vec<u8>>, s: S) -> Result<S::Ok, S::Error> {
        match bytes {
            Some(b) => s.serialize_bytes(b),
            None => s.serialize_none(),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct InterfaceStats {
    pub name: String,
    pub short_name: String,
    #[serde(skip_serializing_if = "Option::is_none", with = "bytes_opt")]
    pub hash: Option<Vec<u8>>,
    #[serde(rename = "type")]
    pub type_: String,
    pub rxb: u64,
    pub txb: u64,
    pub incoming_announce_frequency: f64,
    pub outgoing_announce_frequency: f64,
    pub incoming_pr_frequency: f64,
    pub outgoing_pr_frequency: f64,
    pub held_announces: u64,
    pub burst_active: bool,
    pub burst_activated: f64,
    pub pr_burst_active: bool,
    pub pr_burst_activated: f64,
    /// Python field name (not `online`).
    pub status: bool,
    /// Matches Python `Interface.MODE_*` integers.
    pub mode: u8,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bitrate: Option<u64>,
    pub rxs: u64,
    pub txs: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub announce_queue: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub clients: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blocked_ips: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none", with = "bytes_opt")]
    pub ifac_signature: Option<Vec<u8>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ifac_size: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ifac_netname: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct TransportStats {
    pub interfaces: Vec<InterfaceStats>,
    pub rxb: u64,
    pub txb: u64,
    pub rxs: u64,
    pub txs: u64,
    #[serde(skip_serializing_if = "Option::is_none", with = "bytes_opt")]
    pub transport_id: Option<Vec<u8>>,
    #[serde(skip_serializing_if = "Option::is_none", with = "bytes_opt")]
    pub network_id: Option<Vec<u8>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transport_uptime: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none", with = "bytes_opt")]
    pub probe_responder: Option<Vec<u8>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rss: Option<u64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PathEntry {
    #[serde(with = "bytes_vec")]
    pub hash: Vec<u8>,
    pub timestamp: f64,
    #[serde(with = "bytes_opt")]
    pub via: Option<Vec<u8>>,
    pub hops: u8,
    pub expires: f64,
    pub interface: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct RateEntry {
    #[serde(with = "bytes_vec")]
    pub hash: Vec<u8>,
    pub rate: f64,
}
