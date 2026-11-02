//! Local snapshots and Python-compatible cache formats for transport state.
//!
//! Table and hashlist writers use [`rns_identity::persistence::atomic_write`]:
//! a same-directory temporary file, file sync, readback checks and replacement.
//! Parent-directory sync is best-effort on Unix; this is not an unconditional
//! power-loss guarantee or a transaction across files. The per-announce cache
//! writer has a separate, unsynced temporary-file path.
//!
//! Loaders decode local storage, not authenticated network input. Most read the
//! whole file and have no size limit; decoded metadata still needs validation
//! before use. Loading a route does not establish that its peer is reachable.

use std::collections::{HashMap, HashSet};
use std::io::{BufReader, Read};
use std::path::Path;

use rmpv::Value;
use serde::{Deserialize, Serialize};

use crate::constants::PERSIST_RANDOM_BLOBS;
use crate::hashlist::PacketHashlist;
use crate::path_table::PathTable;

/// Rust path-snapshot fields. Byte-vector lengths and timestamp validity are not
/// checked by deserialization; callers must validate and rebind the interface
/// before installing a route.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistedPathEntry {
    pub destination_hash: Vec<u8>,
    pub timestamp: f64,
    pub next_hop: Option<Vec<u8>>,
    pub hops: u8,
    pub expires: f64,
    pub random_blobs: Vec<Vec<u8>>,
    pub interface_id: u64,
    /// Saved interface name for rebinding to a current interface. A stored
    /// `interface_id` alone is not a stable identity across actor instances.
    #[serde(default)]
    pub interface_name: Option<String>,
    /// Full SHA-256 of the saved interface name, as produced by
    /// [`interface_hash_from_name`]. This is a lookup key, not authentication.
    #[serde(default)]
    pub interface_hash: Option<Vec<u8>>,
    /// Optional full hash used to locate the cached announce packet.
    /// Deserializing this byte vector does not validate its length or contents.
    #[serde(default)]
    pub packet_hash: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistedPathTable {
    pub entries: Vec<PersistedPathEntry>,
    pub version: u32,
}

impl PersistedPathTable {
    pub const CURRENT_VERSION: u32 = 4;
    pub const SUPPORTED_VERSIONS: &'static [u32] = &[1, 2, 3, 4];
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistedHashlist {
    pub hashes: Vec<Vec<u8>>,
    pub version: u32,
}

/// Save a version-4 Rust path snapshot. Paths without a supplied interface name
/// are skipped, and at most the last 32 random blobs per path are retained.
/// Expired paths are not filtered here; cull the table first when needed.
pub fn save_path_table(
    table: &PathTable,
    interface_names: &HashMap<u64, String>,
    path: &Path,
) -> Result<(), PersistenceError> {
    let mut entries = Vec::new();
    for (hash, entry) in table.iter() {
        let interface_name = interface_names.get(&entry.interface_id).cloned();
        // Skip entries whose interface has already been deregistered — we
        // can't restore them safely (no name → no remap target on load).
        if interface_name.is_none() {
            continue;
        }
        let interface_hash = interface_name
            .as_deref()
            .map(interface_hash_from_name)
            .map(|h| h.to_vec());
        entries.push(PersistedPathEntry {
            destination_hash: hash.to_vec(),
            timestamp: entry.timestamp,
            next_hop: entry.next_hop.map(|h| h.to_vec()),
            hops: entry.hops,
            expires: entry.expires,
            random_blobs: entry
                .blobs_for_persist()
                .iter()
                .map(|b| b.to_vec())
                .collect(),
            interface_id: entry.interface_id,
            interface_name,
            interface_hash,
            packet_hash: entry.packet_hash.map(|h| h.to_vec()),
        });
    }

    let persisted = PersistedPathTable {
        entries,
        version: PersistedPathTable::CURRENT_VERSION,
    };

    atomic_write(path, &persisted)
}

/// Decode a Rust path snapshot with a supported version (1 through 4).
///
/// This returns stored entries without checking byte-vector lengths, expiry,
/// announce signatures or interface availability. Older entries may lack an
/// interface name; the caller must decide whether they can be rebound safely.
pub fn load_path_table(path: &Path) -> Result<Vec<PersistedPathEntry>, PersistenceError> {
    let data = std::fs::read(path).map_err(PersistenceError::Io)?;
    let persisted: PersistedPathTable =
        rmp_serde::from_slice(&data).map_err(|e| PersistenceError::Deserialize(e.to_string()))?;

    if !PersistedPathTable::SUPPORTED_VERSIONS.contains(&persisted.version) {
        return Err(PersistenceError::VersionMismatch {
            expected: PersistedPathTable::CURRENT_VERSION,
            found: persisted.version,
        });
    }

    Ok(persisted.entries)
}

#[derive(Debug, Clone)]
pub struct PythonDestinationEntry {
    pub destination_hash: [u8; 16],
    pub timestamp: f64,
    pub received_from: [u8; 16],
    pub hops: u8,
    pub expires: f64,
    pub random_blobs: Vec<[u8; 10]>,
    pub interface_hash: [u8; 32],
    pub packet_hash: [u8; 32],
}

#[derive(Debug, Clone)]
pub struct PythonCachedAnnounce {
    pub raw_packet: Vec<u8>,
    pub interface_reference: Option<String>,
}

#[derive(Debug, Clone)]
pub struct PythonTunnelEntry {
    pub tunnel_id: [u8; 32],
    pub interface_hash: Option<[u8; 32]>,
    pub paths: Vec<PythonTunnelPath>,
    pub expires: f64,
}

#[derive(Debug, Clone)]
pub struct PythonTunnelPath {
    pub destination_hash: [u8; 16],
    pub timestamp: f64,
    pub received_from: [u8; 16],
    pub hops: u8,
    pub expires: f64,
    pub random_blobs: Vec<[u8; 10]>,
    pub interface_hash: Option<[u8; 32]>,
    pub packet_hash: [u8; 32],
}

/// Hash the exact UTF-8 interface name with full SHA-256. No normalization or
/// identity authentication is performed.
pub fn interface_hash_from_name(name: &str) -> [u8; 32] {
    rns_crypto::sha::full_hash(name.as_bytes())
}

/// Save the Python-compatible eight-field destination rows. Entries without a
/// supplied interface name or cached announce hash are skipped; expired entries
/// are retained. Each row includes at most the last 32 random blobs.
pub fn save_python_destination_table(
    table: &PathTable,
    interface_names: &HashMap<u64, String>,
    path: &Path,
) -> Result<(), PersistenceError> {
    let mut entries = Vec::new();
    for (hash, entry) in table.iter() {
        let Some(interface_name) = interface_names.get(&entry.interface_id) else {
            continue;
        };
        let Some(packet_hash) = entry.packet_hash else {
            continue;
        };
        let received_from = entry.next_hop.unwrap_or(*hash.as_bytes());
        let random_blobs = entry
            .blobs_for_persist()
            .iter()
            .map(|b| Value::Binary(b.to_vec()))
            .collect();
        entries.push(Value::Array(vec![
            Value::Binary(hash.to_vec()),
            Value::F64(entry.timestamp),
            Value::Binary(received_from.to_vec()),
            Value::Integer((entry.hops as u64).into()),
            Value::F64(entry.expires),
            Value::Array(random_blobs),
            Value::Binary(interface_hash_from_name(interface_name).to_vec()),
            Value::Binary(packet_hash.to_vec()),
        ]));
    }

    let mut serialized = Vec::new();
    rmpv::encode::write_value(&mut serialized, &Value::Array(entries))
        .map_err(|e| PersistenceError::Serialize(e.to_string()))?;
    atomic_write_bytes(path, &serialized)
}

/// Decode Python-compatible destination rows from a local file.
///
/// The outer value must be an array. Non-array rows are skipped, but an array
/// row shorter than eight fields fails the load. Invalid fixed-length hashes or
/// hop counts skip that row; unsupported time encodings become zero, and invalid
/// random blobs are discarded. Valid blob lists are not length-capped here.
/// No announce signature, expiry or current-path check is performed.
pub fn load_python_destination_table(
    path: &Path,
) -> Result<Vec<PythonDestinationEntry>, PersistenceError> {
    let data = std::fs::read(path).map_err(PersistenceError::Io)?;
    let value = rmpv::decode::read_value(&mut std::io::Cursor::new(data))
        .map_err(|e| PersistenceError::Deserialize(e.to_string()))?;
    let entries = match value {
        Value::Array(entries) => entries,
        other => {
            return Err(PersistenceError::Deserialize(format!(
                "expected destination_table array, got {other:?}"
            )));
        }
    };

    let mut out = Vec::new();
    for entry in entries {
        let fields = match entry {
            Value::Array(fields) => fields,
            _ => continue,
        };
        if fields.len() < 8 {
            return Err(PersistenceError::Deserialize(
                "short destination_table entry".to_string(),
            ));
        }
        let Some(destination_hash) = value_bin_array::<16>(&fields[0]) else {
            continue;
        };
        let timestamp = value_f64(&fields[1]).unwrap_or(0.0);
        let Some(received_from) = value_bin_array::<16>(&fields[2]) else {
            continue;
        };
        let Some(hops) = value_u8(&fields[3]) else {
            continue;
        };
        let expires = value_f64(&fields[4]).unwrap_or(0.0);
        let random_blobs = match &fields[5] {
            Value::Array(values) => values
                .iter()
                .filter_map(value_bin_array::<10>)
                .collect::<Vec<_>>(),
            _ => Vec::new(),
        };
        let Some(interface_hash) = value_bin_array::<32>(&fields[6]) else {
            continue;
        };
        let Some(packet_hash) = value_bin_array::<32>(&fields[7]) else {
            continue;
        };
        out.push(PythonDestinationEntry {
            destination_hash,
            timestamp,
            received_from,
            hops,
            expires,
            random_blobs,
            interface_hash,
            packet_hash,
        });
    }
    Ok(out)
}

/// Write raw packet bytes and an optional interface reference under the
/// supplied packet hash in the Python-compatible announce cache.
///
/// An existing path is left untouched without validating its contents. This
/// helper does not compute the packet hash or verify the announce. It uses a
/// fixed sibling `.tmp` file and rename without fsync; serialize writers for
/// the same key. The existence check is not an exclusive create operation.
pub fn write_python_cached_announce_if_absent(
    announce_cache_dir: &Path,
    packet_hash: &[u8; 32],
    raw_packet: &[u8],
    interface_name: Option<&str>,
) -> Result<(), PersistenceError> {
    let path = announce_cache_dir.join(hex::encode(packet_hash));
    if path.exists() {
        return Ok(());
    }
    std::fs::create_dir_all(announce_cache_dir).map_err(PersistenceError::Io)?;
    let interface_reference = interface_name
        .map(|name| Value::String(name.into()))
        .unwrap_or(Value::Nil);
    let value = Value::Array(vec![
        Value::Binary(raw_packet.to_vec()),
        interface_reference,
    ]);
    let mut serialized = Vec::new();
    rmpv::encode::write_value(&mut serialized, &value)
        .map_err(|e| PersistenceError::Serialize(e.to_string()))?;
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, &serialized).map_err(PersistenceError::Io)?;
    std::fs::rename(&tmp, &path).map_err(PersistenceError::Io)
}

/// Read the cached packet for a supplied hash, returning `None` if absent.
///
/// The cache value must contain binary packet bytes; an invalid optional
/// interface-reference value becomes `None`. The filename hash, packet header,
/// signature and age are not checked. Validate the returned packet before use.
pub fn load_python_cached_announce(
    announce_cache_dir: &Path,
    packet_hash: &[u8; 32],
) -> Result<Option<PythonCachedAnnounce>, PersistenceError> {
    let path = announce_cache_dir.join(hex::encode(packet_hash));
    if !path.exists() {
        return Ok(None);
    }
    let data = std::fs::read(path).map_err(PersistenceError::Io)?;
    let value = rmpv::decode::read_value(&mut std::io::Cursor::new(data))
        .map_err(|e| PersistenceError::Deserialize(e.to_string()))?;
    let fields = match value {
        Value::Array(fields) if fields.len() >= 2 => fields,
        other => {
            return Err(PersistenceError::Deserialize(format!(
                "expected cached announce array, got {other:?}"
            )));
        }
    };
    let raw_packet = match &fields[0] {
        Value::Binary(bytes) => bytes.clone(),
        _ => {
            return Err(PersistenceError::Deserialize(
                "cached announce raw packet was not binary".to_string(),
            ));
        }
    };
    let interface_reference = match &fields[1] {
        Value::Nil => None,
        Value::String(value) => value.as_str().map(str::to_string),
        _ => None,
    };
    Ok(Some(PythonCachedAnnounce {
        raw_packet,
        interface_reference,
    }))
}

/// Save Python-compatible tunnel rows, retaining expired tunnels and paths.
/// Nested paths without a cached announce hash are omitted; each saved path
/// keeps at most the last 32 random blobs. An unknown interface has no hash.
pub fn save_python_tunnel_table(
    table: &crate::tunnel::TunnelTable,
    interface_names: &HashMap<u64, String>,
    path: &Path,
) -> Result<(), PersistenceError> {
    let mut tunnel_values = Vec::new();
    for (_, tunnel) in table.iter() {
        let interface_hash = tunnel
            .interface_id
            .and_then(|id| interface_names.get(&id))
            .map(|name| Value::Binary(interface_hash_from_name(name).to_vec()))
            .unwrap_or(Value::Nil);

        let mut path_values = Vec::new();
        for (dest_hash, tunnel_path) in &tunnel.tunnel_paths {
            let Some(packet_hash) = tunnel_path.packet_hash else {
                continue;
            };
            let received_from = tunnel_path.next_hop.unwrap_or(*dest_hash);
            let random_blob_start = tunnel_path
                .random_blobs
                .len()
                .saturating_sub(PERSIST_RANDOM_BLOBS);
            let random_blobs = tunnel_path
                .random_blobs
                .iter()
                .skip(random_blob_start)
                .map(|blob| Value::Binary(blob.to_vec()))
                .collect::<Vec<_>>();
            path_values.push(Value::Array(vec![
                Value::Binary(dest_hash.to_vec()),
                Value::F64(tunnel_path.timestamp),
                Value::Binary(received_from.to_vec()),
                Value::Integer((tunnel_path.hops as u64).into()),
                Value::F64(tunnel_path.expires),
                Value::Array(random_blobs),
                interface_hash.clone(),
                Value::Binary(packet_hash.to_vec()),
            ]));
        }

        tunnel_values.push(Value::Array(vec![
            Value::Binary(tunnel.tunnel_id.to_vec()),
            interface_hash,
            Value::Array(path_values),
            Value::F64(tunnel.expires),
        ]));
    }

    let mut serialized = Vec::new();
    rmpv::encode::write_value(&mut serialized, &Value::Array(tunnel_values))
        .map_err(|e| PersistenceError::Serialize(e.to_string()))?;
    atomic_write_bytes(path, &serialized)
}

/// Decode a local Python-compatible tunnel table. Malformed tunnel or path
/// rows are skipped; unsupported time encodings become zero and invalid random
/// blobs are discarded. Hash lengths are checked, but signatures, timestamp
/// finiteness, expiry and current reachability are not. Blob lists are not capped.
pub fn load_python_tunnel_table(path: &Path) -> Result<Vec<PythonTunnelEntry>, PersistenceError> {
    let data = std::fs::read(path).map_err(PersistenceError::Io)?;
    let value = rmpv::decode::read_value(&mut std::io::Cursor::new(data))
        .map_err(|e| PersistenceError::Deserialize(e.to_string()))?;
    let entries = match value {
        Value::Array(entries) => entries,
        other => {
            return Err(PersistenceError::Deserialize(format!(
                "expected tunnels array, got {other:?}"
            )));
        }
    };

    let mut out = Vec::new();
    for entry in entries {
        let fields = match entry {
            Value::Array(fields) => fields,
            _ => continue,
        };
        if fields.len() < 4 {
            continue;
        }
        let Some(tunnel_id) = value_bin_array::<32>(&fields[0]) else {
            continue;
        };
        let interface_hash = match &fields[1] {
            Value::Nil => None,
            value => value_bin_array::<32>(value),
        };
        let paths = match &fields[2] {
            Value::Array(path_entries) => path_entries
                .iter()
                .filter_map(|path_entry| {
                    let Value::Array(path_fields) = path_entry else {
                        return None;
                    };
                    if path_fields.len() < 8 {
                        return None;
                    }
                    let destination_hash = value_bin_array::<16>(&path_fields[0])?;
                    let timestamp = value_f64(&path_fields[1]).unwrap_or(0.0);
                    let received_from = value_bin_array::<16>(&path_fields[2])?;
                    let hops = value_u8(&path_fields[3])?;
                    let expires = value_f64(&path_fields[4]).unwrap_or(0.0);
                    let random_blobs = match &path_fields[5] {
                        Value::Array(values) => values
                            .iter()
                            .filter_map(value_bin_array::<10>)
                            .collect::<Vec<_>>(),
                        _ => Vec::new(),
                    };
                    let interface_hash = match &path_fields[6] {
                        Value::Nil => None,
                        value => value_bin_array::<32>(value),
                    };
                    let packet_hash = value_bin_array::<32>(&path_fields[7])?;
                    Some(PythonTunnelPath {
                        destination_hash,
                        timestamp,
                        received_from,
                        hops,
                        expires,
                        random_blobs,
                        interface_hash,
                        packet_hash,
                    })
                })
                .collect::<Vec<_>>(),
            _ => Vec::new(),
        };
        let expires = value_f64(&fields[3]).unwrap_or(0.0);
        out.push(PythonTunnelEntry {
            tunnel_id,
            interface_hash,
            paths,
            expires,
        });
    }

    Ok(out)
}

fn value_bin_array<const N: usize>(value: &Value) -> Option<[u8; N]> {
    let Value::Binary(bytes) = value else {
        return None;
    };
    let mut out = [0u8; N];
    if bytes.len() != N {
        return None;
    }
    out.copy_from_slice(bytes);
    Some(out)
}

fn value_f64(value: &Value) -> Option<f64> {
    match value {
        Value::F64(value) => Some(*value),
        Value::F32(value) => Some(*value as f64),
        Value::Integer(value) => value.as_i64().map(|v| v as f64),
        _ => None,
    }
}

fn value_u8(value: &Value) -> Option<u8> {
    match value {
        Value::Integer(value) => value.as_u64()?.try_into().ok(),
        _ => None,
    }
}

/// Result of streaming a canonical `packet_hashlist.raw` file.
///
/// Complete 32-byte hashes are returned in first-seen order, with duplicates
/// removed. A partial final record is ignored and reported separately. There
/// is no cap on the number of unique hashes loaded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawHashlistLoad {
    pub hashes: Vec<[u8; 32]>,
    /// Number of complete records that repeated an earlier hash.
    pub duplicate_count: usize,
    /// Bytes ignored after the last complete 32-byte record (0 through 31).
    pub partial_tail_bytes: usize,
}

/// Write only the current packet-hash generation as an unframed
/// concatenation of 32-byte hashes. The previous generation is omitted.
pub fn save_hashlist_raw(hashlist: &PacketHashlist, path: &Path) -> Result<(), PersistenceError> {
    let hashes = hashlist.current_hashes();
    save_raw_hashes(&hashes, path)
}

/// Select a hashlist format by the exact, case-sensitive `raw` extension.
///
/// Raw output saves only the current generation; every other extension uses
/// [`save_hashlist_legacy`] and saves both generations.
pub fn save_hashlist(hashlist: &PacketHashlist, path: &Path) -> Result<(), PersistenceError> {
    if path.extension().is_some_and(|extension| extension == "raw") {
        save_hashlist_raw(hashlist, path)
    } else {
        save_hashlist_legacy(hashlist, path)
    }
}

/// Write both in-memory generations as a legacy MessagePack array of binary
/// hashes. The file does not preserve the boundary between generations.
pub fn save_hashlist_legacy(
    hashlist: &PacketHashlist,
    path: &Path,
) -> Result<(), PersistenceError> {
    let hashes = hashlist
        .all_hashes()
        .iter()
        .map(|hash| Value::Binary(hash.to_vec()))
        .collect();
    let mut serialized = Vec::new();
    rmpv::encode::write_value(&mut serialized, &Value::Array(hashes))
        .map_err(|error| PersistenceError::Serialize(error.to_string()))?;
    atomic_write_bytes(path, &serialized)
}

/// Replace `path` with the supplied hashes concatenated as raw 32-byte records.
/// Input order and duplicates are preserved. The full output is allocated in
/// memory before writing through the shared atomic-file helper.
pub fn save_raw_hashes(hashes: &[[u8; 32]], path: &Path) -> Result<(), PersistenceError> {
    let mut serialized = Vec::with_capacity(hashes.len().saturating_mul(32));
    for hash in hashes {
        serialized.extend_from_slice(hash);
    }
    atomic_write_bytes(path, &serialized)
}

/// Load raw 32-byte hash records through a 64 KiB reader buffer.
///
/// Unique hashes are retained in both an output vector and a deduplication
/// set while reading, so total memory grows with the unique-record count.
/// A partial final record is ignored and reported in [`RawHashlistLoad`].
pub fn load_hashlist_raw(path: &Path) -> Result<RawHashlistLoad, PersistenceError> {
    const READ_BUFFER_SIZE: usize = 64 * 1024;

    let file = std::fs::File::open(path).map_err(PersistenceError::Io)?;
    let mut reader = BufReader::with_capacity(READ_BUFFER_SIZE, file);
    let mut hashes = Vec::new();
    let mut seen = HashSet::new();
    let mut duplicate_count = 0usize;

    loop {
        let mut hash = [0u8; 32];
        let mut read = 0usize;
        while read < hash.len() {
            match reader.read(&mut hash[read..]) {
                Ok(0) => {
                    return Ok(RawHashlistLoad {
                        hashes,
                        duplicate_count,
                        partial_tail_bytes: read,
                    });
                }
                Ok(count) => read += count,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(PersistenceError::Io(e)),
            }
        }

        if seen.insert(hash) {
            hashes.push(hash);
        } else {
            duplicate_count += 1;
        }
    }
}

/// Load either legacy msgpack shape:
///
/// - Python's `packet_hashlist`: a list of binary hashes.
/// - Rust's old `hashlist.msgpack`: `{ hashes, version }`.
///
/// The Rust wrapper's version value is not checked. Non-32-byte records are
/// discarded, and duplicates are removed in first-seen order. The entire
/// file is read into memory without a size bound.
pub fn load_hashlist_legacy(path: &Path) -> Result<Vec<[u8; 32]>, PersistenceError> {
    let data = std::fs::read(path).map_err(PersistenceError::Io)?;
    let raw_hashes = match rmp_serde::from_slice::<Vec<Vec<u8>>>(&data) {
        Ok(hashes) => hashes,
        Err(list_err) => {
            let persisted: PersistedHashlist = rmp_serde::from_slice(&data)
                .map_err(|e| PersistenceError::Deserialize(format!("{list_err}; {e}")))?;
            persisted.hashes
        }
    };

    let mut hashes = Vec::new();
    let mut seen = HashSet::new();
    for h in raw_hashes {
        if h.len() == 32 {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&h);
            if seen.insert(arr) {
                hashes.push(arr);
            }
        }
    }
    Ok(hashes)
}

/// Select a hashlist reader by the exact, case-sensitive `raw` extension.
///
/// Raw loads return only hashes, discarding duplicate and partial-tail
/// diagnostics. Call [`load_hashlist_raw`] directly when those counts matter.
/// Every other extension uses [`load_hashlist_legacy`].
pub fn load_hashlist(path: &Path) -> Result<Vec<[u8; 32]>, PersistenceError> {
    if path.extension().is_some_and(|extension| extension == "raw") {
        Ok(load_hashlist_raw(path)?.hashes)
    } else {
        load_hashlist_legacy(path)
    }
}

/// Write to a sibling `.tmp` file and rename on top of the target so a crash
/// mid-write cannot leave a half-written snapshot on disk.
fn atomic_write<T: Serialize>(path: &Path, data: &T) -> Result<(), PersistenceError> {
    let serialized =
        rmp_serde::to_vec(data).map_err(|e| PersistenceError::Serialize(e.to_string()))?;
    atomic_write_bytes(path, &serialized)
}

fn atomic_write_bytes(path: &Path, serialized: &[u8]) -> Result<(), PersistenceError> {
    // Single canonical atomic-write implementation (fsync + rename + dir
    // sync) lives in rns-identity; transport tables share it (AF-2026-04.2).
    rns_identity::persistence::atomic_write(path, serialized).map_err(PersistenceError::Io)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistedBlackholeEntry {
    pub identity_hash: Vec<u8>,
    pub created: f64,
    pub ttl: Option<f64>,
    #[serde(default)]
    pub reason: crate::blackhole::BlackholeReason,
    #[serde(default)]
    pub reason_label: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistedBlackholeTable {
    pub entries: Vec<PersistedBlackholeEntry>,
    pub version: u32,
}

impl PersistedBlackholeTable {
    pub const CURRENT_VERSION: u32 = 2;
    pub const SUPPORTED_VERSIONS: &'static [u32] = &[1, 2];
}

/// Save all entries as a version-2 Rust blackhole snapshot, including expired
/// entries. Publisher/source identity is not stored in this format; use
/// [`save_python_blackhole_files`] when source grouping must be preserved.
pub fn save_blackhole_table(
    table: &crate::blackhole::BlackholeTable,
    path: &Path,
) -> Result<(), PersistenceError> {
    let mut entries = Vec::new();
    for (hash, entry) in table.iter_entries() {
        entries.push(PersistedBlackholeEntry {
            identity_hash: hash.to_vec(),
            created: entry.created,
            ttl: entry.ttl,
            reason: entry.reason,
            reason_label: entry.reason_label.clone(),
        });
    }

    let persisted = PersistedBlackholeTable {
        entries,
        version: PersistedBlackholeTable::CURRENT_VERSION,
    };

    atomic_write(path, &persisted)
}

/// Decode a version-1 or version-2 Rust blackhole snapshot. Stored hash lengths,
/// timestamps and expiry are not validated. This format has no publisher/source
/// identity field; loading it cannot recover that provenance.
pub fn load_blackhole_table(path: &Path) -> Result<Vec<PersistedBlackholeEntry>, PersistenceError> {
    let data = std::fs::read(path).map_err(PersistenceError::Io)?;
    let persisted: PersistedBlackholeTable =
        rmp_serde::from_slice(&data).map_err(|e| PersistenceError::Deserialize(e.to_string()))?;

    if !PersistedBlackholeTable::SUPPORTED_VERSIONS.contains(&persisted.version) {
        return Err(PersistenceError::VersionMismatch {
            expected: PersistedBlackholeTable::CURRENT_VERSION,
            found: persisted.version,
        });
    }

    Ok(persisted.entries)
}

#[derive(Debug, Clone)]
pub struct PythonBlackholeEntry {
    pub identity_hash: [u8; 16],
    pub source: [u8; 16],
    pub created: f64,
    pub ttl: Option<f64>,
    pub reason: crate::blackhole::BlackholeReason,
    pub reason_label: Option<String>,
}

/// Write a `local` file and one file per remote source represented in the table.
///
/// Each file is replaced separately; this is not a multi-file transaction.
/// Obsolete source files are left in place, so the directory is not necessarily
/// an exact snapshot of this table after saving. Expired entries are included.
pub fn save_python_blackhole_files(
    table: &crate::blackhole::BlackholeTable,
    local_identity_hash: [u8; 16],
    blackhole_dir: &Path,
) -> Result<(), PersistenceError> {
    std::fs::create_dir_all(blackhole_dir).map_err(PersistenceError::Io)?;

    let mut local_entries = Vec::new();
    let mut remote_entries: HashMap<[u8; 16], Vec<(Value, Value)>> = HashMap::new();
    for (identity_hash, entry) in table.iter_entries() {
        let source = entry
            .source
            .map(|source| source.into_bytes())
            .unwrap_or(local_identity_hash);
        let until = entry.ttl.map(|ttl| entry.created + ttl);
        let value = blackhole_entry_value(source, until, entry.reason_str());
        let key = Value::Binary(identity_hash.to_vec());
        if source == local_identity_hash {
            local_entries.push((key, value));
        } else {
            remote_entries.entry(source).or_default().push((key, value));
        }
    }

    write_value_file(&blackhole_dir.join("local"), &Value::Map(local_entries))?;
    for (source, entries) in remote_entries {
        write_value_file(
            &blackhole_dir.join(hex::encode(source)),
            &Value::Map(entries),
        )?;
    }
    Ok(())
}

/// Load local blackholes and enabled remote-source files from a directory.
///
/// A missing directory gives an empty result; other directory-open errors fail.
/// Unreadable files, non-map records and invalid identity keys are skipped.
/// A map with a valid 16-byte identity can still omit `until`: missing, Nil or
/// nonnumeric values become a permanent entry (`ttl=None`). A missing or
/// nonstring reason becomes Manual; string reasons are also retained as labels.
/// Source identity comes from the filename (or `local_identity_hash` for
/// `local`), not an authenticated signature or stored `source`. Trust the directory.
///
/// Expired entries are omitted. Returned creation times are `now`, and finite
/// lifetimes become the remaining duration. Remote entries precede local entries;
/// ordering between remote files is unspecified.
pub fn load_python_blackhole_dir(
    blackhole_dir: &Path,
    local_identity_hash: [u8; 16],
    enabled_sources: &[[u8; 16]],
    now: f64,
) -> Result<Vec<PythonBlackholeEntry>, PersistenceError> {
    let mut remote_entries = Vec::new();
    let mut local_entries = Vec::new();
    let read_dir = match std::fs::read_dir(blackhole_dir) {
        Ok(read_dir) => read_dir,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(PersistenceError::Io(e)),
    };

    for item in read_dir {
        let Ok(item) = item else {
            continue;
        };
        let path = item.path();
        if !path.is_file() {
            continue;
        }
        let Some(filename) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        let source = if filename == "local" {
            local_identity_hash
        } else {
            let Ok(bytes) = hex::decode(filename) else {
                continue;
            };
            if bytes.len() != 16 {
                continue;
            }
            let mut source = [0u8; 16];
            source.copy_from_slice(&bytes);
            if !enabled_sources.contains(&source) {
                continue;
            }
            source
        };
        let is_local = source == local_identity_hash;

        let Ok(data) = std::fs::read(&path) else {
            continue;
        };
        let Ok(Value::Map(map)) = rmpv::decode::read_value(&mut std::io::Cursor::new(data)) else {
            continue;
        };

        for (identity_value, entry_value) in map {
            let Some(identity_hash) = value_bin_array::<16>(&identity_value) else {
                continue;
            };
            let Value::Map(entry_map) = entry_value else {
                continue;
            };
            let until = map_get(&entry_map, "until").and_then(value_f64);
            if until.is_some_and(|until| now >= until) {
                continue;
            }
            let reason = map_get(&entry_map, "reason")
                .and_then(Value::as_str)
                .map(crate::blackhole::BlackholeReason::parse)
                .unwrap_or(crate::blackhole::BlackholeReason::Manual);
            let reason_label = map_get(&entry_map, "reason")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned);
            let entry = PythonBlackholeEntry {
                identity_hash,
                source,
                created: now,
                ttl: until.map(|until| (until - now).max(0.0)),
                reason,
                reason_label,
            };
            if is_local {
                local_entries.push(entry);
            } else {
                remote_entries.push(entry);
            }
        }
    }

    // Python protects local blackholes from remote-source overrides. The actor
    // inserts entries in order, so load remote files first and local last.
    let mut entries = remote_entries;
    entries.extend(local_entries);
    Ok(entries)
}

fn blackhole_entry_value(source: [u8; 16], until: Option<f64>, reason: &str) -> Value {
    Value::Map(vec![
        (
            Value::String("source".into()),
            Value::Binary(source.to_vec()),
        ),
        (
            Value::String("until".into()),
            until.map(Value::F64).unwrap_or(Value::Nil),
        ),
        (Value::String("reason".into()), Value::String(reason.into())),
    ])
}

fn write_value_file(path: &Path, value: &Value) -> Result<(), PersistenceError> {
    let mut serialized = Vec::new();
    rmpv::encode::write_value(&mut serialized, value)
        .map_err(|e| PersistenceError::Serialize(e.to_string()))?;
    atomic_write_bytes(path, &serialized)
}

fn map_get<'a>(map: &'a [(Value, Value)], key: &str) -> Option<&'a Value> {
    map.iter()
        .find(|(candidate, _)| candidate.as_str() == Some(key))
        .map(|(_, value)| value)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistedAnnounceEntry {
    pub destination_hash: Vec<u8>,
    pub hops: u8,
    pub app_data: Option<Vec<u8>>,
    pub timestamp: f64,
    pub public_key: Option<Vec<u8>>,
    pub ratchet: Option<Vec<u8>>,
    /// Optional disk-cache key (`cache/announces/<hex>`). Version 6 stores
    /// metadata separately from raw packets; this value alone does not prove
    /// that a valid packet is present in the cache.
    #[serde(default)]
    pub packet_hash: Option<Vec<u8>>,
    /// Stored retention preference. Loading this record does not itself
    /// install the entry or run the actor's retention policy.
    pub retained: bool,
    /// Stored announce name hash from the destination's expanded hash name,
    /// which can include aspects and a generated-identity suffix. It should
    /// contain 10 bytes; deserialization does not validate its length or derivation.
    pub name_hash: Vec<u8>,
    #[serde(default)]
    pub is_path_response: bool,
    #[serde(default)]
    pub last_used: Option<f64>,
}

/// Version-5 on-disk entry shape with raw announce bytes inline, accepted by
/// [`load_announce_cache_legacy_v5`] for migration to separate packet files.
#[derive(Debug, Clone, Deserialize)]
pub struct LegacyPersistedAnnounceEntryV5 {
    pub destination_hash: Vec<u8>,
    pub hops: u8,
    pub app_data: Option<Vec<u8>>,
    pub timestamp: f64,
    pub public_key: Option<Vec<u8>>,
    pub ratchet: Option<Vec<u8>>,
    pub raw_packet: Vec<u8>,
    pub retained: bool,
    pub name_hash: Vec<u8>,
}

#[derive(Debug, Clone, Deserialize)]
struct LegacyPersistedAnnounceCacheV5 {
    entries: Vec<LegacyPersistedAnnounceEntryV5>,
    version: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistedAnnounceCache {
    pub entries: Vec<PersistedAnnounceEntry>,
    pub version: u32,
}

impl PersistedAnnounceCache {
    pub const CURRENT_VERSION: u32 = 6;
    pub const LEGACY_RAW_VERSION: u32 = 5;
}

/// Save version-6 announce metadata without raw packet bytes. Entries are
/// copied as supplied, without filtering expiry or validating their hashes.
pub fn save_announce_cache<'a, I>(announces: I, path: &Path) -> Result<(), PersistenceError>
where
    I: IntoIterator<Item = &'a crate::actor::RecentAnnounce>,
{
    let entries: Vec<PersistedAnnounceEntry> = announces
        .into_iter()
        .map(|a| PersistedAnnounceEntry {
            destination_hash: a.dest_hash.to_vec(),
            hops: a.hops,
            app_data: a.app_data.clone(),
            timestamp: a.timestamp,
            public_key: a.public_key.map(|k| k.to_vec()),
            ratchet: a.ratchet.map(|r| r.to_vec()),
            packet_hash: a.packet_hash.map(|h| h.to_vec()),
            retained: a.retained,
            name_hash: a.name_hash.to_vec(),
            is_path_response: a.is_path_response,
            last_used: a.last_used,
        })
        .collect();

    let persisted = PersistedAnnounceCache {
        entries,
        version: PersistedAnnounceCache::CURRENT_VERSION,
    };

    atomic_write(path, &persisted)
}

/// Decode version-6 announce metadata. Other versions are rejected; this does
/// not fall back to the legacy reader or validate field lengths, signatures,
/// expiry or the referenced packet files.
pub fn load_announce_cache(path: &Path) -> Result<Vec<PersistedAnnounceEntry>, PersistenceError> {
    let data = std::fs::read(path).map_err(PersistenceError::Io)?;
    let persisted: PersistedAnnounceCache =
        rmp_serde::from_slice(&data).map_err(|e| PersistenceError::Deserialize(e.to_string()))?;

    if persisted.version != PersistedAnnounceCache::CURRENT_VERSION {
        return Err(PersistenceError::VersionMismatch {
            expected: PersistedAnnounceCache::CURRENT_VERSION,
            found: persisted.version,
        });
    }

    Ok(persisted.entries)
}

/// Decode a version-5 announce cache with inline raw bytes. This reader rejects
/// other versions and does not validate the embedded packets. Call
/// [`migrate_legacy_announce_entries`] explicitly to create separate cache files.
pub fn load_announce_cache_legacy_v5(
    path: &Path,
) -> Result<Vec<LegacyPersistedAnnounceEntryV5>, PersistenceError> {
    let data = std::fs::read(path).map_err(PersistenceError::Io)?;
    let persisted: LegacyPersistedAnnounceCacheV5 =
        rmp_serde::from_slice(&data).map_err(|e| PersistenceError::Deserialize(e.to_string()))?;
    if persisted.version != PersistedAnnounceCache::LEGACY_RAW_VERSION {
        return Err(PersistenceError::VersionMismatch {
            expected: PersistedAnnounceCache::LEGACY_RAW_VERSION,
            found: persisted.version,
        });
    }
    Ok(persisted.entries)
}

/// Convert version-5 entries to version-6 metadata and attempt to cache their
/// raw packet bytes. This does not save the returned metadata or remove the
/// legacy file.
///
/// A parseable packet header supplies the hash inputs and path-response flag;
/// the packet type and announce signature are not validated. Empty or malformed
/// bytes, or a failed cache write, leave `packet_hash = None`. Cache-write
/// errors are not returned, and an existing cache file is not checked. All
/// other stored metadata is retained, with `last_used` unset.
pub fn migrate_legacy_announce_entries(
    legacy: Vec<LegacyPersistedAnnounceEntryV5>,
    announce_cache_dir: &Path,
) -> Vec<PersistedAnnounceEntry> {
    legacy
        .into_iter()
        .map(|e| {
            let mut packet_hash = None;
            let mut is_path_response = false;
            if !e.raw_packet.is_empty()
                && let Ok((header, _)) = rns_wire::header::PacketHeader::unpack(&e.raw_packet)
            {
                let hash = rns_wire::hash::packet_hash(&e.raw_packet, header.flags.header_type);
                is_path_response = header.context == rns_wire::context::PacketContext::PathResponse;
                if write_python_cached_announce_if_absent(
                    announce_cache_dir,
                    &hash,
                    &e.raw_packet,
                    None,
                )
                .is_ok()
                {
                    packet_hash = Some(hash.to_vec());
                }
            }
            PersistedAnnounceEntry {
                destination_hash: e.destination_hash,
                hops: e.hops,
                app_data: e.app_data,
                timestamp: e.timestamp,
                public_key: e.public_key,
                ratchet: e.ratchet,
                packet_hash,
                retained: e.retained,
                name_hash: e.name_hash,
                is_path_response,
                last_used: None,
            }
        })
        .collect()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistedTunnelEntry {
    pub tunnel_id: Vec<u8>,
    pub interface_id: u64,
    pub expires: f64,
    pub paths: Vec<PersistedTunnelPath>,
    /// Interface name recorded at save time. The loader returns this field
    /// without binding the tunnel to a current interface.
    #[serde(default)]
    pub interface_name: Option<String>,
    /// Full SHA-256 of the saved UTF-8 interface name, when available.
    #[serde(default)]
    pub interface_hash: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistedTunnelPath {
    pub destination_hash: Vec<u8>,
    #[serde(default)]
    pub next_hop: Option<Vec<u8>>,
    pub hops: u8,
    pub expires: f64,
    pub timestamp: f64,
    #[serde(default)]
    pub random_blobs: Vec<Vec<u8>>,
    #[serde(default)]
    pub packet_hash: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistedTunnelTable {
    pub entries: Vec<PersistedTunnelEntry>,
    pub version: u32,
}

impl PersistedTunnelTable {
    pub const CURRENT_VERSION: u32 = 3;
    pub const SUPPORTED_VERSIONS: &'static [u32] = &[1, 2, 3];
}

/// Save all tunnels and their paths as a version-3 Rust snapshot. Expired entries
/// are retained, and at most the last 32 random blobs per path are saved.
/// Interface names and hashes are included only when available.
pub fn save_tunnel_table(
    table: &crate::tunnel::TunnelTable,
    interface_names: &HashMap<u64, String>,
    path: &Path,
) -> Result<(), PersistenceError> {
    let entries: Vec<PersistedTunnelEntry> = table
        .iter()
        .map(|(_, entry)| {
            let interface_name = entry
                .interface_id
                .and_then(|id| interface_names.get(&id))
                .cloned();
            let paths: Vec<PersistedTunnelPath> = entry
                .tunnel_paths
                .iter()
                .map(|(dest, tp)| PersistedTunnelPath {
                    destination_hash: dest.to_vec(),
                    next_hop: tp.next_hop.map(|h| h.to_vec()),
                    hops: tp.hops,
                    expires: tp.expires,
                    timestamp: tp.timestamp,
                    random_blobs: {
                        let start = tp.random_blobs.len().saturating_sub(PERSIST_RANDOM_BLOBS);
                        tp.random_blobs
                            .iter()
                            .skip(start)
                            .map(|b| b.to_vec())
                            .collect()
                    },
                    packet_hash: tp.packet_hash.map(|h| h.to_vec()),
                })
                .collect();
            PersistedTunnelEntry {
                tunnel_id: entry.tunnel_id.to_vec(),
                interface_id: entry.interface_id.unwrap_or_default(),
                expires: entry.expires,
                paths,
                interface_hash: interface_name
                    .as_deref()
                    .map(|name| interface_hash_from_name(name).to_vec()),
                interface_name,
            }
        })
        .collect();

    let persisted = PersistedTunnelTable {
        entries,
        version: PersistedTunnelTable::CURRENT_VERSION,
    };

    atomic_write(path, &persisted)
}

/// Decode a supported Rust tunnel snapshot (versions 1 through 3). This returns
/// stored fields without checking hash lengths, expiry, announce signatures or
/// interface availability, and does not install or bind any tunnel.
pub fn load_tunnel_table(path: &Path) -> Result<Vec<PersistedTunnelEntry>, PersistenceError> {
    let data = std::fs::read(path).map_err(PersistenceError::Io)?;
    let persisted: PersistedTunnelTable =
        rmp_serde::from_slice(&data).map_err(|e| PersistenceError::Deserialize(e.to_string()))?;

    if !PersistedTunnelTable::SUPPORTED_VERSIONS.contains(&persisted.version) {
        return Err(PersistenceError::VersionMismatch {
            expected: PersistedTunnelTable::CURRENT_VERSION,
            found: persisted.version,
        });
    }

    Ok(persisted.entries)
}

#[derive(Debug, thiserror::Error)]
pub enum PersistenceError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("serialization error: {0}")]
    Serialize(String),
    #[error("deserialization error: {0}")]
    Deserialize(String),
    #[error("version mismatch: expected {expected}, found {found}")]
    VersionMismatch { expected: u32, found: u32 },
}

/// Remove old regular files from `storage/cache/announces` unless their hex
/// filename decodes to a hash in `keep`.
///
/// The caller supplies the complete keep-set; this function does not inspect
/// transport tables. Non-hex names are eligible too. Files younger than
/// `grace`, with unknown modification time, or dated after the sweep starts are kept.
///
/// Returns `(successfully_removed, maximum_files_seen_in_one_pass)`. Passes
/// repeat until one removes nothing. Directory and per-entry I/O errors are
/// tolerated, so a zero removal count does not establish an empty or fully
/// checked cache. Concurrent writers are not part of a transaction with this
/// sweep; use a dedicated, trusted cache directory.
pub fn sweep_announce_cache(
    storage_dir: &Path,
    keep: &std::collections::HashSet<[u8; 32]>,
    grace: std::time::Duration,
) -> (usize, usize) {
    let dir = storage_dir.join("cache").join("announces");
    let now = std::time::SystemTime::now();
    let mut removed = 0usize;
    let mut total = 0usize;
    // Unlinking during a lazy `read_dir` walk skips entries on common
    // filesystems (directory compaction moves them behind the cursor), so a
    // single pass leaves stragglers on large backlogs. Python avoids this by
    // materialising `os.listdir` up front; re-passing keeps memory constant
    // instead and terminates because entries only ever shrink — a pass that
    // removes nothing means every survivor is referenced or in-grace.
    loop {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            return (removed, total);
        };
        let mut seen = 0usize;
        let mut removed_this_pass = 0usize;
        for entry in entries.flatten() {
            let Ok(meta) = entry.metadata() else { continue };
            if !meta.is_file() {
                continue;
            }
            seen += 1;
            let name = entry.file_name();
            let referenced = name
                .to_str()
                .and_then(|s| {
                    let mut hash = [0u8; 32];
                    hex::decode_to_slice(s, &mut hash).ok()?;
                    Some(hash)
                })
                .is_some_and(|hash| keep.contains(&hash));
            if referenced {
                continue;
            }
            // Unparseable mtime (or mtime in the future) counts as fresh:
            // err on the side of keeping; a later sweep collects it.
            let fresh = meta
                .modified()
                .ok()
                .and_then(|modified| now.duration_since(modified).ok())
                .is_none_or(|age| age < grace);
            if fresh {
                continue;
            }
            if std::fs::remove_file(entry.path()).is_ok() {
                removed_this_pass += 1;
            }
        }
        total = total.max(seen);
        removed += removed_this_pass;
        if removed_this_pass == 0 {
            return (removed, total);
        }
    }
}

#[cfg(test)]
mod announce_sweep_tests {
    use super::sweep_announce_cache;
    use std::collections::HashSet;
    use std::time::Duration;

    fn setup(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "rns-announce-sweep-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(dir.join("cache").join("announces")).unwrap();
        dir
    }

    fn write_entry(storage: &std::path::Path, hash: [u8; 32]) -> std::path::PathBuf {
        let p = storage
            .join("cache")
            .join("announces")
            .join(hex::encode(hash));
        std::fs::write(&p, b"announce").unwrap();
        p
    }

    /// Decision-table parity with Python `Transport.clean_announce_cache`
    /// (upstream Transport.py:2521): referenced → keep, unreferenced → remove,
    /// non-hex name → remove. Grace column is the deliberate Rust extension.
    #[test]
    fn sweep_matrix_matches_python_semantics() {
        let storage = setup("matrix");
        let kept_hash = [0xAA; 32];
        let orphan_hash = [0xBB; 32];
        let kept = write_entry(&storage, kept_hash);
        let orphan = write_entry(&storage, orphan_hash);
        let non_hex = storage.join("cache").join("announces").join("not-a-hash");
        std::fs::write(&non_hex, b"junk").unwrap();

        let mut keep = HashSet::new();
        keep.insert(kept_hash);

        // Zero grace: age checks never protect anything.
        let (removed, total) = sweep_announce_cache(&storage, &keep, Duration::ZERO);
        assert_eq!(total, 3);
        assert_eq!(removed, 2);
        assert!(kept.exists(), "referenced announce must survive");
        assert!(!orphan.exists(), "unreferenced announce must be removed");
        assert!(!non_hex.exists(), "non-hex file must be removed");

        let _ = std::fs::remove_dir_all(&storage);
    }

    #[test]
    fn grace_window_protects_fresh_orphans() {
        let storage = setup("grace");
        let orphan = write_entry(&storage, [0xCC; 32]);

        let (removed, total) =
            sweep_announce_cache(&storage, &HashSet::new(), Duration::from_secs(3600));
        assert_eq!((removed, total), (0, 1));
        assert!(orphan.exists(), "fresh orphan inside grace must survive");

        // Same file, grace elapsed → collected.
        let (removed, _) = sweep_announce_cache(&storage, &HashSet::new(), Duration::ZERO);
        assert_eq!(removed, 1);
        assert!(!orphan.exists());

        let _ = std::fs::remove_dir_all(&storage);
    }

    #[test]
    fn missing_dir_is_a_noop() {
        let storage = std::env::temp_dir().join("rns-announce-sweep-missing-nonexistent");
        assert_eq!(
            sweep_announce_cache(&storage, &HashSet::new(), Duration::ZERO),
            (0, 0)
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::InterfaceMode;
    use crate::path_table::PathEntry;

    fn unique_temp_dir(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "reticulum-rs-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn test_save_load_path_table() {
        let mut table = PathTable::new();
        let hash = [0xAA; 16];
        let entry = PathEntry::new(Some([0xBB; 16]), 3, 1, InterfaceMode::Gateway);
        table.insert(hash, entry);

        let dir = std::env::temp_dir().join("reticulum_rs_test_persist");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("path_table.msgpack");

        let mut names = HashMap::new();
        names.insert(1u64, "test_iface".to_string());
        save_path_table(&table, &names, &path).unwrap();
        let loaded = load_path_table(&path).unwrap();

        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].destination_hash, hash.to_vec());
        assert_eq!(loaded[0].hops, 3);
        assert_eq!(loaded[0].interface_id, 1);
        assert_eq!(loaded[0].interface_name.as_deref(), Some("test_iface"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn atomic_write_bytes_uses_shared_fsync_helper() {
        // AF-2026-04.2: transport tables must go through the rns-identity
        // atomic_write (fsync before rename). The shared helper creates the
        // temp file with mode 0600 — observable proof of delegation, unlike
        // the old fs::write path (umask default).
        let dir = std::env::temp_dir().join("reticulum_rs_test_atomic_bytes");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("snapshot.msgpack");

        atomic_write_bytes(&path, b"first").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"first");
        // Overwrite must replace cleanly (rename on top).
        atomic_write_bytes(&path, b"second").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"second");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn save_skips_entries_with_no_interface_name() {
        let mut table = PathTable::new();
        let hash = [0xAA; 16];
        let entry = PathEntry::new(Some([0xBB; 16]), 3, 99, InterfaceMode::Gateway);
        table.insert(hash, entry);

        let dir = std::env::temp_dir().join("reticulum_rs_test_persist_skip");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("path_table.msgpack");

        // No name registered for interface_id=99 → entry should be skipped.
        let names: HashMap<u64, String> = HashMap::new();
        save_path_table(&table, &names, &path).unwrap();
        let loaded = load_path_table(&path).unwrap();
        assert!(loaded.is_empty());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn legacy_v2_path_table_loads_entries_with_name_none() {
        // Simulate a pre-v3 snapshot by writing v2 shape (no interface_name)
        // and verify it deserializes via serde(default).
        #[derive(Serialize)]
        struct V2Entry {
            destination_hash: Vec<u8>,
            timestamp: f64,
            next_hop: Option<Vec<u8>>,
            hops: u8,
            expires: f64,
            random_blobs: Vec<Vec<u8>>,
            interface_id: u64,
        }
        #[derive(Serialize)]
        struct V2Table {
            entries: Vec<V2Entry>,
            version: u32,
        }
        let v2 = V2Table {
            entries: vec![V2Entry {
                destination_hash: vec![0xAA; 16],
                timestamp: 1.0,
                next_hop: None,
                hops: 1,
                expires: 9999999999.0,
                random_blobs: vec![],
                interface_id: 1,
            }],
            version: 2,
        };
        let bytes = rmp_serde::to_vec(&v2).unwrap();

        let dir = std::env::temp_dir().join("reticulum_rs_test_v2_path");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("path_table.msgpack");
        std::fs::write(&path, &bytes).unwrap();

        let loaded = load_path_table(&path).unwrap();
        assert_eq!(loaded.len(), 1);
        assert!(loaded[0].interface_name.is_none());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn save_load_python_destination_table_and_announce_cache() {
        let destination_hash = [0xAA; 16];
        let next_hop = [0xBB; 16];
        let packet_hash = [0xCC; 32];
        let mut entry = PathEntry::new(Some(next_hop), 2, 7, InterfaceMode::Gateway);
        entry.timestamp = 1234.5;
        entry.expires = 9876.5;
        entry.packet_hash = Some(packet_hash);
        entry.add_random_blob([0x44; 10]);

        let mut table = PathTable::new();
        table.insert(destination_hash, entry);
        let mut names = HashMap::new();
        names.insert(7, "Interface[Test]".to_string());

        let dir = std::env::temp_dir().join("reticulum_rs_test_python_destination_table");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let destination_table_path = dir.join("destination_table");

        save_python_destination_table(&table, &names, &destination_table_path).unwrap();
        let loaded = load_python_destination_table(&destination_table_path).unwrap();

        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].destination_hash, destination_hash);
        assert_eq!(loaded[0].timestamp, 1234.5);
        assert_eq!(loaded[0].received_from, next_hop);
        assert_eq!(loaded[0].hops, 2);
        assert_eq!(loaded[0].expires, 9876.5);
        assert_eq!(loaded[0].random_blobs, vec![[0x44; 10]]);
        assert_eq!(
            loaded[0].interface_hash,
            interface_hash_from_name("Interface[Test]")
        );
        assert_eq!(loaded[0].packet_hash, packet_hash);

        let cache_dir = dir.join("cache").join("announces");
        write_python_cached_announce_if_absent(
            &cache_dir,
            &packet_hash,
            &[0xFE; 42],
            Some("Interface[Test]"),
        )
        .unwrap();
        let cached = load_python_cached_announce(&cache_dir, &packet_hash)
            .unwrap()
            .unwrap();
        assert_eq!(cached.raw_packet, vec![0xFE; 42]);
        assert_eq!(
            cached.interface_reference.as_deref(),
            Some("Interface[Test]")
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn cached_announce_write_if_absent_does_not_overwrite() {
        let dir = std::env::temp_dir().join("reticulum_rs_test_announce_if_absent");
        let _ = std::fs::remove_dir_all(&dir);
        let cache_dir = dir.join("cache").join("announces");
        let packet_hash = [0xCC; 32];

        write_python_cached_announce_if_absent(
            &cache_dir,
            &packet_hash,
            &[0xFE; 42],
            Some("Interface[First]"),
        )
        .unwrap();
        // Second write for the same packet hash is a no-op.
        write_python_cached_announce_if_absent(
            &cache_dir,
            &packet_hash,
            &[0x00; 8],
            Some("Interface[Second]"),
        )
        .unwrap();

        let cached = load_python_cached_announce(&cache_dir, &packet_hash)
            .unwrap()
            .unwrap();
        assert_eq!(cached.raw_packet, vec![0xFE; 42]);
        assert_eq!(
            cached.interface_reference.as_deref(),
            Some("Interface[First]")
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn save_load_python_tunnel_table_and_tunnel_announce_cache() {
        let destination_hash = [0xAB; 16];
        let next_hop = [0xBC; 16];
        let packet_hash = [0xCD; 32];
        let tunnel_id = [0xDE; 32];
        let mut paths = HashMap::new();
        paths.insert(
            destination_hash,
            crate::tunnel::TunnelPath {
                timestamp: 1234.5,
                next_hop: Some(next_hop),
                hops: 3,
                expires: 9876.5,
                random_blobs: vec![[0x44; 10]],
                packet_hash: Some(packet_hash),
            },
        );
        let mut tunnels = crate::tunnel::TunnelTable::new();
        tunnels.insert(crate::tunnel::TunnelEntry {
            tunnel_id,
            interface_id: Some(7),
            tunnel_paths: paths,
            expires: 9999.5,
        });
        let mut names = HashMap::new();
        names.insert(7, "Interface[Tunnel]".to_string());

        let dir = std::env::temp_dir().join("reticulum_rs_test_python_tunnels");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let tunnels_path = dir.join("tunnels");

        save_python_tunnel_table(&tunnels, &names, &tunnels_path).unwrap();
        let loaded = load_python_tunnel_table(&tunnels_path).unwrap();

        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].tunnel_id, tunnel_id);
        assert_eq!(
            loaded[0].interface_hash,
            Some(interface_hash_from_name("Interface[Tunnel]"))
        );
        assert_eq!(loaded[0].expires, 9999.5);
        assert_eq!(loaded[0].paths.len(), 1);
        assert_eq!(loaded[0].paths[0].destination_hash, destination_hash);
        assert_eq!(loaded[0].paths[0].received_from, next_hop);
        assert_eq!(loaded[0].paths[0].hops, 3);
        assert_eq!(loaded[0].paths[0].packet_hash, packet_hash);

        let cache_dir = dir.join("cache").join("announces");
        write_python_cached_announce_if_absent(
            &cache_dir,
            &packet_hash,
            &[0xFE; 42],
            Some("Interface[Tunnel]"),
        )
        .unwrap();
        let cached = load_python_cached_announce(&cache_dir, &packet_hash)
            .unwrap()
            .unwrap();
        assert_eq!(cached.raw_packet, vec![0xFE; 42]);
        assert_eq!(
            cached.interface_reference.as_deref(),
            Some("Interface[Tunnel]")
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn raw_hashlist_persists_only_current_generation() {
        let mut hashlist = PacketHashlist::new_with_capacity(4);
        let aa = [0xAA; 32];
        let bb = [0xBB; 32];
        let cc = [0xCC; 32];
        hashlist.insert(aa);
        hashlist.insert(bb);
        // Rotate aa/bb into the transient previous generation.
        hashlist.insert(cc);

        let dir = unique_temp_dir("raw-hashlist-current");
        let path = dir.join("packet_hashlist.raw");

        save_hashlist_raw(&hashlist, &path).unwrap();
        let raw = std::fs::read(&path).unwrap();
        assert_eq!(raw, cc);

        let loaded = load_hashlist_raw(&path).unwrap();
        assert_eq!(loaded.hashes, vec![cc]);
        assert_eq!(loaded.duplicate_count, 0);
        assert_eq!(loaded.partial_tail_bytes, 0);
        assert_eq!(load_hashlist(&path).unwrap(), vec![cc]);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn raw_hashlist_streaming_load_deduplicates_and_reports_partial_tail() {
        let aa = [0xAA; 32];
        let bb = [0xBB; 32];
        let dir = unique_temp_dir("raw-hashlist-dedup-tail");
        let path = dir.join("packet_hashlist.raw");
        let mut raw = Vec::new();
        raw.extend_from_slice(&aa);
        raw.extend_from_slice(&bb);
        raw.extend_from_slice(&aa);
        raw.extend_from_slice(&[0x42; 7]);
        std::fs::write(&path, raw).unwrap();

        let loaded = load_hashlist_raw(&path).unwrap();
        assert_eq!(loaded.hashes, vec![aa, bb]);
        assert_eq!(loaded.duplicate_count, 1);
        assert_eq!(loaded.partial_tail_bytes, 7);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn legacy_hashlist_loader_accepts_python_list_and_deduplicates() {
        let dir = unique_temp_dir("legacy-python-hashlist");
        let path = dir.join("packet_hashlist");
        let mut bytes = Vec::new();
        rmpv::encode::write_value(
            &mut bytes,
            &Value::Array(vec![
                Value::Binary(vec![0xAA; 32]),
                Value::Binary(vec![0x42; 31]),
                Value::Binary(vec![0xAA; 32]),
                Value::Binary(vec![0xBB; 32]),
            ]),
        )
        .unwrap();
        std::fs::write(&path, bytes).unwrap();

        let loaded = load_hashlist_legacy(&path).unwrap();
        assert_eq!(loaded, vec![[0xAA; 32], [0xBB; 32]]);
        assert_eq!(load_hashlist(&path).unwrap(), loaded);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn stable_hashlist_facade_round_trips_an_extensionless_legacy_path() {
        let dir = unique_temp_dir("stable-legacy-hashlist-facade");
        let path = dir.join("packet_hashlist");
        let mut hashlist = PacketHashlist::new_with_capacity(4);
        hashlist.insert([0xAA; 32]);
        hashlist.insert([0xBB; 32]);
        hashlist.insert([0xCC; 32]);

        save_hashlist(&hashlist, &path).unwrap();

        let loaded = load_hashlist(&path).unwrap();
        assert_eq!(loaded.len(), 3);
        assert!(loaded.contains(&[0xAA; 32]));
        assert!(loaded.contains(&[0xBB; 32]));
        assert!(loaded.contains(&[0xCC; 32]));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn legacy_hashlist_loader_accepts_rust_sidecar_shape() {
        let persisted = PersistedHashlist {
            hashes: vec![vec![0xAA; 32], vec![0x42; 31], vec![0xBB; 32]],
            version: 1,
        };
        let bytes = rmp_serde::to_vec(&persisted).unwrap();

        let dir = unique_temp_dir("legacy-rust-hashlist");
        let path = dir.join("hashlist.msgpack");
        std::fs::write(&path, bytes).unwrap();

        let loaded = load_hashlist_legacy(&path).unwrap();
        assert_eq!(loaded.len(), 2);
        assert!(loaded.contains(&[0xAA; 32]));
        assert!(loaded.contains(&[0xBB; 32]));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_atomic_write() {
        let dir = std::env::temp_dir().join("reticulum_rs_test_atomic");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("test.msgpack");

        let data = PersistedHashlist {
            hashes: Vec::new(),
            version: 1,
        };
        atomic_write(&path, &data).unwrap();

        assert!(path.exists());
        assert!(!path.with_extension("tmp").exists());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_version_mismatch() {
        let dir = std::env::temp_dir().join("reticulum_rs_test_version");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("path_table.msgpack");

        let bad = PersistedPathTable {
            entries: Vec::new(),
            version: 999,
        };
        atomic_write(&path, &bad).unwrap();

        let result = load_path_table(&path);
        assert!(result.is_err());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_persisted_path_entry_roundtrip() {
        let entry = PersistedPathEntry {
            destination_hash: vec![0xAA; 16],
            timestamp: 1234567890.0,
            next_hop: Some(vec![0xBB; 16]),
            hops: 5,
            expires: 1234567890.0 + 604800.0,
            random_blobs: vec![vec![0x42; 10]],
            interface_id: 42,
            interface_name: Some("test_iface".to_string()),
            interface_hash: Some(interface_hash_from_name("test_iface").to_vec()),
            packet_hash: Some(vec![0x11; 32]),
        };

        let serialized = rmp_serde::to_vec(&entry).unwrap();
        let deserialized: PersistedPathEntry = rmp_serde::from_slice(&serialized).unwrap();

        assert_eq!(deserialized.destination_hash, entry.destination_hash);
        assert_eq!(deserialized.hops, entry.hops);
        assert_eq!(deserialized.interface_id, entry.interface_id);
    }

    #[test]
    fn test_save_load_blackhole_table() {
        let mut table = crate::blackhole::BlackholeTable::new();
        table.add([0xAA; 16], None);
        table.add_with_reason(
            [0xBB; 16],
            Some(3600.0),
            crate::blackhole::BlackholeReason::RateLimit,
        );

        let dir = std::env::temp_dir().join("reticulum_rs_test_blackhole");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("blackhole_table.msgpack");

        save_blackhole_table(&table, &path).unwrap();
        let loaded = load_blackhole_table(&path).unwrap();

        assert_eq!(loaded.len(), 2);

        let aa = loaded
            .iter()
            .find(|e| e.identity_hash == vec![0xAA; 16])
            .unwrap();
        let bb = loaded
            .iter()
            .find(|e| e.identity_hash == vec![0xBB; 16])
            .unwrap();
        assert_eq!(aa.reason, crate::blackhole::BlackholeReason::Manual);
        assert_eq!(aa.ttl, None);
        assert_eq!(bb.reason, crate::blackhole::BlackholeReason::RateLimit);
        assert_eq!(bb.ttl, Some(3600.0));
        assert!(bb.created > 0.0);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn save_load_python_blackhole_files_preserves_source_rules() {
        let local_source = [0x11; 16];
        let remote_source = [0x22; 16];
        let shared_identity = [0xAA; 16];
        let remote_only_identity = [0xBB; 16];

        let mut table = crate::blackhole::BlackholeTable::new();
        table.insert_entry(
            shared_identity,
            crate::blackhole::BlackholeEntry {
                created: 1000.0,
                ttl: None,
                reason: crate::blackhole::BlackholeReason::Manual,
                reason_label: None,
                source: None,
            },
        );
        table.insert_entry(
            remote_only_identity,
            crate::blackhole::BlackholeEntry {
                created: 1000.0,
                ttl: Some(60.0),
                reason: crate::blackhole::BlackholeReason::RateLimit,
                reason_label: None,
                source: Some(remote_source.into()),
            },
        );

        let dir = std::env::temp_dir().join("reticulum_rs_test_python_blackhole");
        let _ = std::fs::remove_dir_all(&dir);
        save_python_blackhole_files(&table, local_source, &dir).unwrap();

        assert!(dir.join("local").exists());
        assert!(dir.join(hex::encode(remote_source)).exists());

        let loaded =
            load_python_blackhole_dir(&dir, local_source, &[remote_source], 1010.0).unwrap();
        assert_eq!(loaded.len(), 2);
        assert!(loaded.iter().any(|entry| {
            entry.identity_hash == shared_identity
                && entry.source == local_source
                && entry.reason == crate::blackhole::BlackholeReason::Manual
        }));
        let remote = loaded
            .iter()
            .find(|entry| entry.identity_hash == remote_only_identity)
            .unwrap();
        assert_eq!(remote.source, remote_source);
        assert_eq!(remote.reason, crate::blackhole::BlackholeReason::RateLimit);
        assert_eq!(remote.ttl, Some(50.0));

        let conflicting_remote = Value::Map(vec![(
            Value::Binary(shared_identity.to_vec()),
            blackhole_entry_value(
                remote_source,
                None,
                crate::blackhole::BlackholeReason::ProtocolViolation.as_str(),
            ),
        )]);
        write_value_file(&dir.join(hex::encode(remote_source)), &conflicting_remote).unwrap();
        let loaded =
            load_python_blackhole_dir(&dir, local_source, &[remote_source], 1010.0).unwrap();
        let final_shared = loaded
            .iter()
            .rev()
            .find(|entry| entry.identity_hash == shared_identity)
            .unwrap();
        assert_eq!(final_shared.source, local_source);
        assert_eq!(
            final_shared.reason,
            crate::blackhole::BlackholeReason::Manual
        );

        let disabled = load_python_blackhole_dir(&dir, local_source, &[], 1010.0).unwrap();
        assert!(disabled.iter().all(|entry| entry.source == local_source));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_load_v1_blackhole_table_falls_back_to_manual() {
        // v1 snapshots have no `reason` field; serde(default) fills in
        // Manual, which is correct — v1 predates auto-population.
        #[derive(Serialize)]
        struct V1Entry {
            identity_hash: Vec<u8>,
            created: f64,
            ttl: Option<f64>,
        }
        #[derive(Serialize)]
        struct V1Table {
            entries: Vec<V1Entry>,
            version: u32,
        }
        let v1 = V1Table {
            entries: vec![V1Entry {
                identity_hash: vec![0x77; 16],
                created: 1234.0,
                ttl: None,
            }],
            version: 1,
        };
        let bytes = rmp_serde::to_vec(&v1).unwrap();

        let dir = std::env::temp_dir().join("reticulum_rs_test_blackhole_v1");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("blackhole_table.msgpack");
        std::fs::write(&path, &bytes).unwrap();

        let loaded = load_blackhole_table(&path).unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].reason, crate::blackhole::BlackholeReason::Manual);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_save_load_announce_cache() {
        let announces = vec![crate::actor::RecentAnnounce {
            dest_hash: [0xCC; 16],
            hops: 3,
            app_data: Some(vec![10, 20, 30]),
            timestamp: 1000.0,
            public_key: None,
            ratchet: Some([0xDD; 32]),
            packet_hash: Some([0xEE; 32]),
            is_path_response: true,
            retained: false,
            last_used: Some(1234.0),
            name_hash: [0xAB; 10],
        }];

        let dir = std::env::temp_dir().join("reticulum_rs_test_announce_persist");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("announce_cache.msgpack");

        save_announce_cache(&announces, &path).unwrap();
        let loaded = load_announce_cache(&path).unwrap();

        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].destination_hash, [0xCC; 16].to_vec());
        assert_eq!(loaded[0].hops, 3);
        assert_eq!(loaded[0].ratchet, Some(vec![0xDD; 32]));
        assert_eq!(loaded[0].packet_hash, Some([0xEE; 32].to_vec()));
        assert!(loaded[0].is_path_response);
        assert_eq!(loaded[0].last_used, Some(1234.0));

        let _ = std::fs::remove_dir_all(&dir);
    }

    fn packed_test_announce(context: rns_wire::context::PacketContext, fill: u8) -> Vec<u8> {
        let header = rns_wire::header::PacketHeader {
            flags: rns_wire::flags::PacketFlags {
                header_type: rns_wire::flags::HeaderType::Header1,
                context_flag: false,
                transport_type: rns_wire::flags::TransportType::Broadcast,
                destination_type: rns_wire::flags::DestinationType::Single,
                packet_type: rns_wire::flags::PacketType::Announce,
            },
            hops: 1,
            transport_id: None,
            destination_hash: [fill; 16],
            context,
        };
        let mut raw = header.pack();
        raw.extend_from_slice(&[fill; 32]);
        raw
    }

    #[test]
    fn legacy_v5_announce_cache_migrates_raw_to_disk_cache() {
        // Exact v5 on-disk shape: raw announce bytes inline, no packet_hash /
        // is_path_response / last_used.
        #[derive(Serialize)]
        struct V5Entry {
            destination_hash: Vec<u8>,
            hops: u8,
            app_data: Option<Vec<u8>>,
            timestamp: f64,
            public_key: Option<Vec<u8>>,
            ratchet: Option<Vec<u8>>,
            raw_packet: Vec<u8>,
            retained: bool,
            name_hash: Vec<u8>,
        }
        #[derive(Serialize)]
        struct V5Cache {
            entries: Vec<V5Entry>,
            version: u32,
        }

        let plain_raw = packed_test_announce(rns_wire::context::PacketContext::None, 0xA1);
        let plain_hash =
            rns_wire::hash::packet_hash(&plain_raw, rns_wire::flags::HeaderType::Header1);
        let pr_raw = packed_test_announce(rns_wire::context::PacketContext::PathResponse, 0xB2);
        let pr_hash = rns_wire::hash::packet_hash(&pr_raw, rns_wire::flags::HeaderType::Header1);

        let entry = |dest: u8, raw: Vec<u8>, retained: bool| V5Entry {
            destination_hash: vec![dest; 16],
            hops: 1,
            app_data: None,
            timestamp: 1000.0,
            public_key: None,
            ratchet: None,
            raw_packet: raw,
            retained,
            name_hash: vec![0xAB; 10],
        };
        let v5 = V5Cache {
            entries: vec![
                entry(0xA1, plain_raw.clone(), true),
                entry(0xB2, pr_raw.clone(), false),
                // Too short for PacketHeader::unpack — must migrate as a miss.
                entry(0xC3, vec![0x01], false),
            ],
            version: 5,
        };
        let bytes = rmp_serde::to_vec(&v5).unwrap();

        let dir = std::env::temp_dir().join("reticulum_rs_test_announce_v5_migration");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("announce_cache.msgpack");
        std::fs::write(&path, &bytes).unwrap();

        assert!(
            load_announce_cache(&path).is_err(),
            "v6 loader must reject a v5 snapshot"
        );

        let legacy = load_announce_cache_legacy_v5(&path).unwrap();
        assert_eq!(legacy.len(), 3);
        let cache_dir = dir.join("cache").join("announces");
        let migrated = migrate_legacy_announce_entries(legacy, &cache_dir);

        assert_eq!(migrated.len(), 3);
        assert_eq!(migrated[0].destination_hash, vec![0xA1; 16]);
        assert_eq!(migrated[0].packet_hash, Some(plain_hash.to_vec()));
        assert!(!migrated[0].is_path_response);
        assert!(migrated[0].retained);
        assert_eq!(migrated[0].last_used, None);
        assert_eq!(migrated[1].packet_hash, Some(pr_hash.to_vec()));
        assert!(migrated[1].is_path_response);
        assert_eq!(migrated[2].packet_hash, None);

        // Raw bytes landed in the per-packet disk cache, byte-identical.
        let on_disk = load_python_cached_announce(&cache_dir, &plain_hash)
            .unwrap()
            .unwrap();
        assert_eq!(on_disk.raw_packet, plain_raw);
        let on_disk_pr = load_python_cached_announce(&cache_dir, &pr_hash)
            .unwrap()
            .unwrap();
        assert_eq!(on_disk_pr.raw_packet, pr_raw);

        let _ = std::fs::remove_dir_all(&dir);
    }
}
