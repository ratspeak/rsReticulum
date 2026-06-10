//! Atomic msgpack persistence for transport tables. `atomic_write` is
//! write-to-tmp + fsync + rename (via the shared rns-identity helper) so a
//! crash or power loss leaves either the old or the new file, never a torn one.

use std::collections::HashMap;
use std::path::Path;

use rmpv::Value;
use serde::{Deserialize, Serialize};

use crate::constants::PERSIST_RANDOM_BLOBS;
use crate::hashlist::PacketHashlist;
use crate::path_table::PathTable;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistedPathEntry {
    pub destination_hash: Vec<u8>,
    pub timestamp: f64,
    pub next_hop: Option<Vec<u8>>,
    pub hops: u8,
    pub expires: f64,
    pub random_blobs: Vec<Vec<u8>>,
    pub interface_id: u64,
    /// Stable identifier for the interface that learned this path. The load
    /// path uses it to remap the volatile `interface_id` (re-allocated from
    /// zero on every actor boot) once the matching interface registers.
    #[serde(default)]
    pub interface_name: Option<String>,
    /// Python's `destination_table` stores the full hash of `str(interface)`.
    /// Keep it in the Rust sidecar too so sidecar/canonical loads can share
    /// the same rebinding path.
    #[serde(default)]
    pub interface_hash: Option<Vec<u8>>,
    /// Full hash of the cached announce packet backing this path.
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

/// Loads a path-table snapshot. Entries without `interface_name` (v1/v2)
/// are dropped at the actor boundary since `interface_id` is volatile.
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

pub fn interface_hash_from_name(name: &str) -> [u8; 32] {
    rns_crypto::sha::full_hash(name.as_bytes())
}

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

pub fn save_python_announce_cache_for_paths<'a, I>(
    path_entries: &PathTable,
    announces: I,
    interface_names: &HashMap<u64, String>,
    announce_cache_dir: &Path,
) -> Result<(), PersistenceError>
where
    I: IntoIterator<Item = &'a crate::actor::RecentAnnounce>,
{
    save_python_announce_cache_for_paths_and_tunnels(
        path_entries,
        None,
        announces,
        interface_names,
        announce_cache_dir,
    )
}

pub fn save_python_announce_cache_for_paths_and_tunnels<'a, I>(
    path_entries: &PathTable,
    tunnel_table: Option<&crate::tunnel::TunnelTable>,
    announces: I,
    interface_names: &HashMap<u64, String>,
    announce_cache_dir: &Path,
) -> Result<(), PersistenceError>
where
    I: IntoIterator<Item = &'a crate::actor::RecentAnnounce>,
{
    std::fs::create_dir_all(announce_cache_dir).map_err(PersistenceError::Io)?;
    let announces_by_dest: HashMap<[u8; 16], &crate::actor::RecentAnnounce> =
        announces.into_iter().map(|a| (a.dest_hash, a)).collect();
    let mut written = std::collections::HashSet::new();

    for (dest_hash, path_entry) in path_entries.iter() {
        let Some(packet_hash) = path_entry.packet_hash else {
            continue;
        };
        let Some(announce) = announces_by_dest.get(dest_hash.as_bytes()) else {
            continue;
        };
        if announce.raw_packet.is_empty() {
            continue;
        }
        let interface_reference = interface_names
            .get(&path_entry.interface_id)
            .map(|name| Value::String(name.as_str().into()))
            .unwrap_or(Value::Nil);
        write_python_cached_announce(
            announce_cache_dir,
            &packet_hash,
            announce.raw_packet.clone(),
            interface_reference,
        )?;
        written.insert(packet_hash);
    }

    if let Some(tunnel_table) = tunnel_table {
        for tunnel in tunnel_table.iter().map(|(_, tunnel)| tunnel) {
            let interface_reference = interface_names
                .get(&tunnel.interface_id)
                .map(|name| Value::String(name.as_str().into()))
                .unwrap_or(Value::Nil);
            for (dest_hash, tunnel_path) in &tunnel.tunnel_paths {
                let Some(packet_hash) = tunnel_path.packet_hash else {
                    continue;
                };
                if written.contains(&packet_hash) {
                    continue;
                }
                let Some(announce) = announces_by_dest.get(dest_hash) else {
                    continue;
                };
                if announce.raw_packet.is_empty() {
                    continue;
                }
                write_python_cached_announce(
                    announce_cache_dir,
                    &packet_hash,
                    announce.raw_packet.clone(),
                    interface_reference.clone(),
                )?;
                written.insert(packet_hash);
            }
        }
    }
    Ok(())
}

fn write_python_cached_announce(
    announce_cache_dir: &Path,
    packet_hash: &[u8; 32],
    raw_packet: Vec<u8>,
    interface_reference: Value,
) -> Result<(), PersistenceError> {
    let value = Value::Array(vec![Value::Binary(raw_packet), interface_reference]);
    let mut serialized = Vec::new();
    rmpv::encode::write_value(&mut serialized, &value)
        .map_err(|e| PersistenceError::Serialize(e.to_string()))?;
    let path = announce_cache_dir.join(hex::encode(packet_hash));
    atomic_write_bytes(&path, &serialized)
}

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

pub fn save_python_tunnel_table(
    table: &crate::tunnel::TunnelTable,
    interface_names: &HashMap<u64, String>,
    path: &Path,
) -> Result<(), PersistenceError> {
    let mut tunnel_values = Vec::new();
    for (_, tunnel) in table.iter() {
        let interface_hash = interface_names
            .get(&tunnel.interface_id)
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

pub fn save_hashlist(hashlist: &PacketHashlist, path: &Path) -> Result<(), PersistenceError> {
    let hashes = hashlist
        .all_hashes()
        .iter()
        .map(|h| Value::Binary(h.to_vec()))
        .collect();
    let mut serialized = Vec::new();
    rmpv::encode::write_value(&mut serialized, &Value::Array(hashes))
        .map_err(|e| PersistenceError::Serialize(e.to_string()))?;
    atomic_write_bytes(path, &serialized)
}

pub fn load_hashlist(path: &Path) -> Result<Vec<[u8; 32]>, PersistenceError> {
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
    for h in raw_hashes {
        if h.len() == 32 {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&h);
            hashes.push(arr);
        }
    }
    Ok(hashes)
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
    /// Raw announce bytes so CacheRequest replays hit a byte-identical packet
    /// instead of re-serialising (which would disturb signatures).
    pub raw_packet: Vec<u8>,
    /// Pinned via `RetainDestination`; the maintenance sweep skips the
    /// entry regardless of age while this is `true`.
    pub retained: bool,
    /// `SHA-256(app_name)[:10]` of the announced aspect. Lets cache consumers
    /// retro-filter without re-parsing `raw_packet`.
    pub name_hash: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistedAnnounceCache {
    pub entries: Vec<PersistedAnnounceEntry>,
    pub version: u32,
}

impl PersistedAnnounceCache {
    pub const CURRENT_VERSION: u32 = 5;
}

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
            raw_packet: a.raw_packet.clone(),
            retained: a.retained,
            name_hash: a.name_hash.to_vec(),
        })
        .collect();

    let persisted = PersistedAnnounceCache {
        entries,
        version: PersistedAnnounceCache::CURRENT_VERSION,
    };

    atomic_write(path, &persisted)
}

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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistedTunnelEntry {
    pub tunnel_id: Vec<u8>,
    pub interface_id: u64,
    pub expires: f64,
    pub paths: Vec<PersistedTunnelPath>,
    /// Same role as `PersistedPathEntry::interface_name` — used to remap a
    /// stale `interface_id` once the matching interface registers.
    #[serde(default)]
    pub interface_name: Option<String>,
    /// Python-compatible stable interface hash for remapping canonical
    /// `tunnels` entries across restarts.
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

pub fn save_tunnel_table(
    table: &crate::tunnel::TunnelTable,
    interface_names: &HashMap<u64, String>,
    path: &Path,
) -> Result<(), PersistenceError> {
    let entries: Vec<PersistedTunnelEntry> = table
        .iter()
        .filter_map(|(_, entry)| {
            // Skip entries whose interface has already been deregistered.
            let interface_name = interface_names.get(&entry.interface_id).cloned()?;
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
            Some(PersistedTunnelEntry {
                tunnel_id: entry.tunnel_id.to_vec(),
                interface_id: entry.interface_id,
                expires: entry.expires,
                paths,
                interface_name: Some(interface_name),
                interface_hash: interface_names
                    .get(&entry.interface_id)
                    .map(|name| interface_hash_from_name(name).to_vec()),
            })
        })
        .collect();

    let persisted = PersistedTunnelTable {
        entries,
        version: PersistedTunnelTable::CURRENT_VERSION,
    };

    atomic_write(path, &persisted)
}

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::InterfaceMode;
    use crate::path_table::PathEntry;

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

        let announces = [crate::actor::RecentAnnounce {
            dest_hash: destination_hash,
            hops: 2,
            app_data: None,
            timestamp: 1234.5,
            public_key: None,
            ratchet: None,
            raw_packet: vec![0xFE; 42],
            retained: false,
            name_hash: [0xAB; 10],
        }];
        let cache_dir = dir.join("cache").join("announces");
        save_python_announce_cache_for_paths(&table, announces.iter(), &names, &cache_dir).unwrap();
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
            interface_id: 7,
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

        let announces = [crate::actor::RecentAnnounce {
            dest_hash: destination_hash,
            hops: 3,
            app_data: None,
            timestamp: 1234.5,
            public_key: None,
            ratchet: None,
            raw_packet: vec![0xFE; 42],
            retained: false,
            name_hash: [0xAB; 10],
        }];
        let empty_paths = PathTable::new();
        let cache_dir = dir.join("cache").join("announces");
        save_python_announce_cache_for_paths_and_tunnels(
            &empty_paths,
            Some(&tunnels),
            announces.iter(),
            &names,
            &cache_dir,
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
    fn test_save_load_hashlist() {
        let mut hashlist = PacketHashlist::new();
        let aa = [0xAA; 32];
        let bb = [0xBB; 32];
        hashlist.insert(aa);
        hashlist.insert(bb);

        let dir = std::env::temp_dir().join("reticulum_rs_test_hashlist");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("packet_hashlist");

        save_hashlist(&hashlist, &path).unwrap();
        let raw = std::fs::read(&path).unwrap();
        let mut python_shape: Vec<Vec<u8>> = rmp_serde::from_slice(&raw).unwrap();
        python_shape.sort();
        assert_eq!(python_shape, vec![aa.to_vec(), bb.to_vec()]);

        let loaded = load_hashlist(&path).unwrap();
        assert_eq!(loaded.len(), 2);
        assert!(loaded.contains(&aa));
        assert!(loaded.contains(&bb));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_hashlist_accepts_legacy_rust_sidecar_shape() {
        let persisted = PersistedHashlist {
            hashes: vec![vec![0xAA; 32], vec![0x42; 31], vec![0xBB; 32]],
            version: 1,
        };
        let bytes = rmp_serde::to_vec(&persisted).unwrap();

        let dir = std::env::temp_dir().join("reticulum_rs_test_hashlist_legacy");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("hashlist.msgpack");
        std::fs::write(&path, bytes).unwrap();

        let loaded = load_hashlist(&path).unwrap();
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
            raw_packet: vec![0xEE; 64],
            retained: false,
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

        let _ = std::fs::remove_dir_all(&dir);
    }
}
