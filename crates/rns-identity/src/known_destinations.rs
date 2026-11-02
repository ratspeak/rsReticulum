use std::collections::HashMap;
use std::io::Cursor;
use std::path::Path;

use crate::persistence;
use rmpv::Value;

/// Record intended for a destination learned from a validated announce.
/// Construction and file loading do not perform announce authentication.
#[derive(Debug, Clone)]
pub struct KnownDestination {
    /// Learn time as a Unix timestamp (seconds).
    pub timestamp: f64,
    /// Packet hash of the announce that introduced the destination.
    pub packet_hash: [u8; 32],
    /// Concatenated `X25519_pub || Ed25519_pub`.
    pub public_key: [u8; 64],
    pub app_data: Option<Vec<u8>>,
    /// Pinned via `retain()` — `cleanup()` skips this entry regardless of age.
    pub retained: bool,
}

/// Table of known destinations, keyed by 16-byte destination hash.
pub struct KnownDestinations {
    entries: HashMap<[u8; 16], KnownDestination>,
}

impl KnownDestinations {
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    /// Insert or refresh the entry for `dest_hash`. The `retained` flag is
    /// preserved on update so a fresh announce never un-pins an entry.
    /// The caller validates the announce, destination binding and key continuity;
    /// this method can replace an existing key without checking them.
    pub fn remember(
        &mut self,
        dest_hash: [u8; 16],
        timestamp: f64,
        packet_hash: [u8; 32],
        public_key: [u8; 64],
        app_data: Option<Vec<u8>>,
    ) {
        match self.entries.get_mut(&dest_hash) {
            Some(existing) => {
                existing.timestamp = timestamp;
                existing.packet_hash = packet_hash;
                existing.public_key = public_key;
                existing.app_data = app_data;
                // `retained` preserved across refresh.
            }
            None => {
                self.entries.insert(
                    dest_hash,
                    KnownDestination {
                        timestamp,
                        packet_hash,
                        public_key,
                        app_data,
                        retained: false,
                    },
                );
            }
        }
    }

    pub fn get(&self, dest_hash: &[u8; 16]) -> Option<&KnownDestination> {
        self.entries.get(dest_hash)
    }

    pub fn contains(&self, dest_hash: &[u8; 16]) -> bool {
        self.entries.contains_key(dest_hash)
    }

    pub fn recall_app_data(&self, dest_hash: &[u8; 16]) -> Option<Vec<u8>> {
        self.entries.get(dest_hash).and_then(|e| e.app_data.clone())
    }

    /// Linear scan for an entry whose `SHA-256(public_key)[:16]` matches `identity_hash`.
    pub fn recall_by_identity(
        &self,
        identity_hash: &[u8; 16],
    ) -> Option<(&[u8; 16], &KnownDestination)> {
        for (dest_hash, entry) in &self.entries {
            let computed_id_hash = rns_crypto::sha::truncated_hash(&entry.public_key);
            if &computed_id_hash == identity_hash {
                return Some((dest_hash, entry));
            }
        }
        None
    }

    /// Check membership across this table plus a set of locally-registered
    /// destination hashes (the fallback used by transport path resolution).
    pub fn is_known_or_registered(
        &self,
        dest_hash: &[u8; 16],
        registered: &std::collections::HashSet<[u8; 16]>,
    ) -> bool {
        self.entries.contains_key(dest_hash) || registered.contains(dest_hash)
    }

    pub fn remove(&mut self, dest_hash: &[u8; 16]) -> Option<KnownDestination> {
        self.entries.remove(dest_hash)
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&[u8; 16], &KnownDestination)> {
        self.entries.iter()
    }

    /// Pin `dest_hash` so `cleanup()` will never consider it stale.
    pub fn retain(&mut self, dest_hash: &[u8; 16]) {
        if let Some(entry) = self.entries.get_mut(dest_hash) {
            entry.retained = true;
        }
    }

    /// Pin every known destination announced by `identity_hash`. Returns the
    /// number of entries that matched.
    pub fn retain_identity(&mut self, identity_hash: &[u8; 16]) -> usize {
        let mut retained = 0usize;
        for entry in self.entries.values_mut() {
            let computed_id_hash = rns_crypto::sha::truncated_hash(&entry.public_key);
            if &computed_id_hash == identity_hash {
                entry.retained = true;
                retained += 1;
            }
        }
        retained
    }

    /// Release a pin set by `retain()`. The entry's `timestamp` (last-seen
    /// announce wall-clock) drives `cleanup()` from now on.
    pub fn unretain(&mut self, dest_hash: &[u8; 16]) {
        if let Some(entry) = self.entries.get_mut(dest_hash) {
            entry.retained = false;
        }
    }

    /// Drop stale entries past `destination_timeout_secs`. `has_path` is a
    /// caller-supplied path-table lookup (this crate doesn't depend on
    /// rns-transport). Pinned entries and entries with a current path are retained.
    /// Returns the hashes that were dropped.
    pub fn cleanup(
        &mut self,
        now: f64,
        destination_timeout_secs: f64,
        has_path: impl Fn(&[u8; 16]) -> bool,
    ) -> Vec<[u8; 16]> {
        let mut to_remove = Vec::new();

        for (dest_hash, entry) in &self.entries {
            // Keep: pinned, or currently routable.
            if entry.retained || has_path(dest_hash) {
                continue;
            }

            let age = now - entry.timestamp;
            if age > destination_timeout_secs {
                to_remove.push(*dest_hash);
            }
        }

        for hash in &to_remove {
            self.entries.remove(hash);
        }

        to_remove
    }

    /// Atomically write the table to `path` in Python Reticulum's canonical
    /// msgpack format. The loader still accepts older Rust `RNS\x03` files.
    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        let serialized = self.serialize();
        persistence::atomic_write(path, &serialized)
    }

    /// Load the table from `path`; returns an empty table on missing or
    /// unparseable input.
    pub fn load(path: &Path) -> std::io::Result<Self> {
        match persistence::read_file(path)? {
            Some(data) => Ok(Self::deserialize(&data).unwrap_or_else(|_| Self::new())),
            None => Ok(Self::new()),
        }
    }

    /// Merge `other` into self; existing entries win on key conflict.
    pub fn merge(&mut self, other: &KnownDestinations) {
        for (hash, entry) in &other.entries {
            self.entries.entry(*hash).or_insert_with(|| entry.clone());
        }
    }

    const MAGIC: &'static [u8] = b"RNS\x03";

    // Legacy Rust sidecar/on-disk format (little-endian):
    //   magic: b"RNS\x03"
    //   count: u32
    //   count × (dest_hash[16], timestamp: f64, packet_hash[32], public_key[64],
    //            has_app_data: u8, app_data_len: u32, app_data[app_data_len],
    //            retained: u8 (0|1))
    fn serialize(&self) -> Vec<u8> {
        let mut entries = Vec::with_capacity(self.entries.len());
        for (hash, entry) in &self.entries {
            let app_data = entry
                .app_data
                .as_ref()
                .map(|data| Value::Binary(data.clone()))
                .unwrap_or(Value::Nil);
            let last_use = if entry.retained { -1i64 } else { 0i64 };
            entries.push((
                Value::Binary(hash.to_vec()),
                Value::Array(vec![
                    Value::F64(entry.timestamp),
                    Value::Binary(entry.packet_hash.to_vec()),
                    Value::Binary(entry.public_key.to_vec()),
                    app_data,
                    Value::Integer(last_use.into()),
                ]),
            ));
        }

        let mut buf = Vec::new();
        rmpv::encode::write_value(&mut buf, &Value::Map(entries))
            .expect("writing msgpack to Vec cannot fail");
        buf
    }

    // Kept as a regression fixture for loading the legacy Rust sidecar format.
    #[allow(dead_code)]
    fn serialize_legacy_rust(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(Self::MAGIC);
        buf.extend_from_slice(&(self.entries.len() as u32).to_le_bytes());

        for (hash, entry) in &self.entries {
            buf.extend_from_slice(hash);
            buf.extend_from_slice(&entry.timestamp.to_le_bytes());
            buf.extend_from_slice(&entry.packet_hash);
            buf.extend_from_slice(&entry.public_key);
            match &entry.app_data {
                Some(ad) => {
                    buf.push(1);
                    buf.extend_from_slice(&(ad.len() as u32).to_le_bytes());
                    buf.extend_from_slice(ad);
                }
                None => {
                    buf.push(0);
                    buf.extend_from_slice(&0u32.to_le_bytes());
                }
            }
            buf.push(if entry.retained { 1 } else { 0 });
        }

        buf
    }

    fn deserialize(data: &[u8]) -> Result<Self, &'static str> {
        if !data.starts_with(Self::MAGIC) {
            return Self::deserialize_python_msgpack(data);
        }
        let data = &data[Self::MAGIC.len()..];
        if data.len() < 4 {
            return Err("too short");
        }
        let count =
            u32::from_le_bytes(data[..4].try_into().map_err(|_| "corrupt header")?) as usize;
        let mut pos = 4;
        let mut entries = HashMap::new();

        for _ in 0..count {
            if pos + 16 + 8 + 32 + 64 + 1 + 4 > data.len() {
                return Err("truncated entry");
            }
            let mut dest_hash = [0u8; 16];
            dest_hash.copy_from_slice(&data[pos..pos + 16]);
            pos += 16;

            let timestamp = f64::from_le_bytes(
                data[pos..pos + 8]
                    .try_into()
                    .map_err(|_| "corrupt timestamp")?,
            );
            pos += 8;

            let mut packet_hash = [0u8; 32];
            packet_hash.copy_from_slice(&data[pos..pos + 32]);
            pos += 32;

            let mut public_key = [0u8; 64];
            public_key.copy_from_slice(&data[pos..pos + 64]);
            pos += 64;

            let has_app_data = data[pos];
            pos += 1;

            let ad_len = u32::from_le_bytes(
                data[pos..pos + 4]
                    .try_into()
                    .map_err(|_| "corrupt app_data length")?,
            ) as usize;
            pos += 4;

            let app_data = if has_app_data == 1 {
                if pos + ad_len > data.len() {
                    return Err("truncated app_data");
                }
                let ad = data[pos..pos + ad_len].to_vec();
                pos += ad_len;
                Some(ad)
            } else {
                None
            };

            if pos + 1 > data.len() {
                return Err("truncated retained flag");
            }
            let retained = data[pos] != 0;
            pos += 1;

            entries.insert(
                dest_hash,
                KnownDestination {
                    timestamp,
                    packet_hash,
                    public_key,
                    app_data,
                    retained,
                },
            );
        }

        Ok(Self { entries })
    }

    /// Parse Python Reticulum's canonical `storage/known_destinations` file.
    ///
    /// Python writes msgpack as `{dest_hash: [timestamp, packet_hash,
    /// public_key, app_data, last_use]}` and transparently upgrades older
    /// four-field entries by treating `last_use` as `0`.
    fn deserialize_python_msgpack(data: &[u8]) -> Result<Self, &'static str> {
        let value = rmpv::decode::read_value(&mut Cursor::new(data))
            .map_err(|_| "invalid python known_destinations msgpack")?;
        let Value::Map(map) = value else {
            return Err("python known_destinations root is not a map");
        };

        let mut entries = HashMap::new();
        for (dest_value, entry_value) in map {
            let dest_bytes = Self::msgpack_bytes(&dest_value)?;
            if dest_bytes.len() != 16 {
                // Python ignores entries whose key is not a truncated hash.
                continue;
            }
            let mut dest_hash = [0u8; 16];
            dest_hash.copy_from_slice(&dest_bytes);

            let Value::Array(fields) = entry_value else {
                return Err("python known_destinations entry is not an array");
            };
            if fields.len() < 4 {
                return Err("python known_destinations entry is too short");
            }

            let timestamp = Self::msgpack_number(&fields[0])?;
            let packet_hash_bytes = Self::msgpack_bytes(&fields[1])?;
            let public_key_bytes = Self::msgpack_bytes(&fields[2])?;
            let app_data = match &fields[3] {
                Value::Nil => None,
                value => Some(Self::msgpack_bytes(value)?),
            };
            let last_use = fields
                .get(4)
                .map(Self::msgpack_number)
                .transpose()?
                .unwrap_or(0.0);

            if packet_hash_bytes.len() != 32 {
                return Err("python known_destinations packet hash has invalid length");
            }
            if public_key_bytes.len() != 64 {
                return Err("python known_destinations public key has invalid length");
            }

            let mut packet_hash = [0u8; 32];
            packet_hash.copy_from_slice(&packet_hash_bytes);
            let mut public_key = [0u8; 64];
            public_key.copy_from_slice(&public_key_bytes);

            entries.insert(
                dest_hash,
                KnownDestination {
                    timestamp,
                    packet_hash,
                    public_key,
                    app_data,
                    retained: last_use < 0.0,
                },
            );
        }

        Ok(Self { entries })
    }

    fn msgpack_bytes(value: &Value) -> Result<Vec<u8>, &'static str> {
        match value {
            Value::Binary(bytes) => Ok(bytes.clone()),
            Value::String(s) => s
                .as_str()
                .map(|s| s.as_bytes().to_vec())
                .ok_or("msgpack string is not valid utf-8"),
            _ => Err("msgpack value is not bytes"),
        }
    }

    fn msgpack_number(value: &Value) -> Result<f64, &'static str> {
        match value {
            Value::F64(value) => Ok(*value),
            Value::F32(value) => Ok((*value).into()),
            Value::Integer(value) => value
                .as_i64()
                .map(|value| value as f64)
                .or_else(|| value.as_u64().map(|value| value as f64))
                .ok_or("msgpack integer does not fit in f64"),
            _ => Err("msgpack value is not numeric"),
        }
    }
}

impl Default for KnownDestinations {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_remember_and_get() {
        let mut kd = KnownDestinations::new();
        let hash = [0xAA; 16];
        kd.remember(hash, 1234.5, [0xBB; 32], [0xCC; 64], Some(b"data".to_vec()));
        let entry = kd.get(&hash).unwrap();
        assert_eq!(entry.timestamp, 1234.5);
        assert_eq!(entry.app_data.as_deref(), Some(b"data".as_slice()));
        assert!(!entry.retained);
    }

    #[test]
    fn test_remember_preserves_retained_on_refresh() {
        let mut kd = KnownDestinations::new();
        let hash = [0xAA; 16];
        kd.remember(hash, 100.0, [0; 32], [0; 64], None);
        kd.retain(&hash);
        assert!(kd.get(&hash).unwrap().retained);

        kd.remember(hash, 200.0, [1; 32], [1; 64], Some(b"new".to_vec()));
        let entry = kd.get(&hash).unwrap();
        assert_eq!(entry.timestamp, 200.0);
        assert_eq!(entry.app_data.as_deref(), Some(b"new".as_slice()));
        assert!(entry.retained);
    }

    #[test]
    fn test_serialize_deserialize_round_trip() {
        let mut kd = KnownDestinations::new();
        kd.remember(
            [0x01; 16],
            100.0,
            [0x02; 32],
            [0x03; 64],
            Some(b"hello".to_vec()),
        );
        kd.remember([0x04; 16], 200.0, [0x05; 32], [0x06; 64], None);
        kd.retain(&[0x04; 16]);

        let serialized = kd.serialize();
        assert!(
            !serialized.starts_with(KnownDestinations::MAGIC),
            "public save format must remain Python-compatible msgpack"
        );
        let kd2 = KnownDestinations::deserialize(&serialized).unwrap();
        assert_eq!(kd2.len(), 2);

        let e1 = kd2.get(&[0x01; 16]).unwrap();
        assert_eq!(e1.timestamp, 100.0);
        assert_eq!(e1.app_data.as_deref(), Some(b"hello".as_slice()));
        assert!(!e1.retained);

        let e2 = kd2.get(&[0x04; 16]).unwrap();
        assert!(e2.app_data.is_none());
        assert!(e2.retained);
    }

    #[test]
    fn test_deserialize_rejects_unknown_magic() {
        let mut buf = b"OLD\x02".to_vec();
        buf.extend_from_slice(&0u32.to_le_bytes());
        assert!(KnownDestinations::deserialize(&buf).is_err());
    }

    #[test]
    fn test_deserialize_legacy_rust_format() {
        let mut kd = KnownDestinations::new();
        kd.remember(
            [0xAA; 16],
            42.0,
            [0xBB; 32],
            [0xCC; 64],
            Some(b"legacy".to_vec()),
        );
        kd.retain(&[0xAA; 16]);

        let serialized = kd.serialize_legacy_rust();
        assert!(serialized.starts_with(KnownDestinations::MAGIC));
        let loaded = KnownDestinations::deserialize(&serialized).unwrap();
        let entry = loaded.get(&[0xAA; 16]).unwrap();
        assert_eq!(entry.timestamp, 42.0);
        assert_eq!(entry.packet_hash, [0xBB; 32]);
        assert_eq!(entry.public_key, [0xCC; 64]);
        assert_eq!(entry.app_data.as_deref(), Some(b"legacy".as_slice()));
        assert!(entry.retained);
    }

    #[test]
    fn test_file_persistence() {
        let dir = std::env::temp_dir().join("reticulum_kd_test");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("known_destinations");

        let mut kd = KnownDestinations::new();
        kd.remember(
            [0xAA; 16],
            42.0,
            [0xBB; 32],
            [0xCC; 64],
            Some(b"test".to_vec()),
        );
        kd.save(&path).unwrap();
        assert!(
            !std::fs::read(&path)
                .unwrap()
                .starts_with(KnownDestinations::MAGIC)
        );

        let kd2 = KnownDestinations::load(&path).unwrap();
        assert_eq!(kd2.len(), 1);
        let entry = kd2.get(&[0xAA; 16]).unwrap();
        assert_eq!(entry.timestamp, 42.0);

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn test_merge() {
        let mut kd1 = KnownDestinations::new();
        kd1.remember([0x01; 16], 100.0, [0; 32], [0; 64], None);
        kd1.remember([0x02; 16], 200.0, [0; 32], [0; 64], None);

        let mut kd2 = KnownDestinations::new();
        // Same key as kd1, different payload, to probe conflict resolution.
        kd2.remember([0x02; 16], 300.0, [1; 32], [1; 64], None);
        kd2.remember([0x03; 16], 400.0, [0; 32], [0; 64], None);

        kd1.merge(&kd2);
        assert_eq!(kd1.len(), 3);
        let e2 = kd1.get(&[0x02; 16]).unwrap();
        assert_eq!(e2.timestamp, 200.0);
    }

    #[test]
    fn test_recall_app_data() {
        let mut kd = KnownDestinations::new();
        let hash1 = [0xAA; 16];
        let hash2 = [0xBB; 16];

        kd.remember(
            hash1,
            100.0,
            [0; 32],
            [0; 64],
            Some(b"my app data".to_vec()),
        );
        kd.remember(hash2, 200.0, [0; 32], [0; 64], None);

        assert_eq!(kd.recall_app_data(&hash1), Some(b"my app data".to_vec()));
        assert_eq!(kd.recall_app_data(&hash2), None);
        assert_eq!(kd.recall_app_data(&[0xCC; 16]), None);
    }

    #[test]
    fn test_retain_unretain_round_trip() {
        let mut kd = KnownDestinations::new();
        let hash = [0xAA; 16];
        kd.remember(hash, 100.0, [0; 32], [0; 64], None);
        assert!(!kd.get(&hash).unwrap().retained);

        kd.retain(&hash);
        assert!(kd.get(&hash).unwrap().retained);

        kd.unretain(&hash);
        assert!(!kd.get(&hash).unwrap().retained);
    }

    #[test]
    fn test_retain_identity_marks_matching_destinations() {
        let mut kd = KnownDestinations::new();
        let id = crate::identity::Identity::new();
        let public_key = id.get_public_key();
        let other_public_key = crate::identity::Identity::new().get_public_key();
        let dest_a = [0xA1; 16];
        let dest_b = [0xB2; 16];
        let dest_c = [0xC3; 16];

        kd.remember(dest_a, 1.0, [1u8; 32], public_key, None);
        kd.remember(dest_b, 1.0, [2u8; 32], public_key, None);
        kd.remember(dest_c, 1.0, [3u8; 32], other_public_key, None);

        assert_eq!(kd.retain_identity(&id.hash), 2);
        assert!(kd.get(&dest_a).unwrap().retained);
        assert!(kd.get(&dest_b).unwrap().retained);
        assert!(!kd.get(&dest_c).unwrap().retained);
    }

    #[test]
    fn test_cleanup_retains_pinned() {
        let mut kd = KnownDestinations::new();
        let hash = [0xAA; 16];
        // Timestamp far in the past, no path, but pinned.
        kd.remember(hash, 0.0, [0; 32], [0; 64], None);
        kd.retain(&hash);

        let removed = kd.cleanup(1_000_000.0, 7.0 * 24.0 * 3600.0, |_| false);
        assert!(removed.is_empty());
        assert!(kd.contains(&hash));
    }

    #[test]
    fn test_cleanup_keeps_pathed_entries() {
        let mut kd = KnownDestinations::new();
        let hash = [0xAA; 16];
        // Never used, but has a live path — must keep.
        kd.remember(hash, 0.0, [0; 32], [0; 64], None);

        let removed = kd.cleanup(1_000_000.0, 7.0 * 24.0 * 3600.0, |h| h == &hash);
        assert!(removed.is_empty());
        assert!(kd.contains(&hash));
    }

    #[test]
    fn test_cleanup_drops_pathless_past_destination_timeout() {
        let mut kd = KnownDestinations::new();
        let stale_never_used = [0xAA; 16];
        let stale_used = [0xBB; 16];
        let fresh = [0xCC; 16];
        let dest_timeout = 7.0 * 24.0 * 3600.0;

        kd.remember(stale_never_used, 0.0, [0; 32], [0; 64], None);
        kd.remember(stale_used, 0.0, [0; 32], [0; 64], None);
        kd.remember(fresh, dest_timeout - 60.0, [0; 32], [0; 64], None);

        // `now` sits one second past the timeout for the stale pair.
        let now = dest_timeout + 1.0;
        let removed = kd.cleanup(now, dest_timeout, |_| false);

        // Both stale arms are reaped under the uniform policy; the fresh
        // entry (only ~60 s old at `now`) survives.
        assert_eq!(removed.len(), 2);
        assert!(removed.contains(&stale_never_used));
        assert!(removed.contains(&stale_used));
        assert!(kd.contains(&fresh));
    }

    #[test]
    fn test_cleanup_keeps_pathless_well_below_destination_timeout() {
        let mut kd = KnownDestinations::new();
        let never_used = [0xAA; 16];
        let used = [0xBB; 16];

        kd.remember(never_used, 0.0, [0; 32], [0; 64], None);
        kd.remember(used, 0.0, [0; 32], [0; 64], None);

        let removed = kd.cleanup(10.0 * 60.0, 7.0 * 24.0 * 3600.0, |_| false);
        assert!(removed.is_empty());
        assert!(kd.contains(&never_used));
        assert!(kd.contains(&used));
    }
}
