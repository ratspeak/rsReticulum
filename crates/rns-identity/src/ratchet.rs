use rns_crypto::sha::full_hash;
use rns_crypto::x25519::X25519PrivateKey;
use rns_wire::constants::{NAME_HASH_LENGTH, RATCHET_COUNT, RATCHET_EXPIRY, RATCHET_INTERVAL};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::Zeroize;

use crate::persistence;

/// A bounded history of X25519 private ratchet keys for forward secrecy.
///
/// Index 0 is the most recent key; older keys are retained so decryption can
/// still succeed for in-flight ciphertexts. All key material is zeroised on
/// drop and on truncation.
pub struct RatchetRing {
    keys: Vec<[u8; 32]>,
    last_rotation: f64,
    retained_count: usize,
    rotation_interval: u64,
}

impl RatchetRing {
    pub fn new() -> Self {
        Self {
            keys: Vec::new(),
            last_rotation: 0.0,
            retained_count: RATCHET_COUNT,
            rotation_interval: RATCHET_INTERVAL,
        }
    }

    /// Generate a fresh ratchet key, push it to the front, and return its public key.
    ///
    /// Any keys evicted past `retained_count` are zeroised before drop.
    pub fn rotate(&mut self) -> [u8; 32] {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs_f64();

        let prv = X25519PrivateKey::generate();
        let pub_key = prv.public_key().to_bytes();

        self.keys.insert(0, prv.to_bytes());
        if self.keys.len() > self.retained_count {
            for key in &mut self.keys[self.retained_count..] {
                key.zeroize();
            }
            self.keys.truncate(self.retained_count);
        }
        self.last_rotation = now;

        pub_key
    }

    /// True when at least `rotation_interval` seconds have elapsed since the last rotate.
    pub fn needs_rotation(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs_f64();
        now - self.last_rotation >= self.rotation_interval as f64
    }

    /// Public key of the most recent ratchet, if the ring has been rotated at least once.
    pub fn current_public_key(&self) -> Option<[u8; 32]> {
        self.keys.first().map(|prv_bytes| {
            let prv = X25519PrivateKey::from_bytes(prv_bytes);
            prv.public_key().to_bytes()
        })
    }

    /// All retained private keys, newest first, for decryption attempts.
    pub fn private_keys(&self) -> &[[u8; 32]] {
        &self.keys
    }

    pub fn len(&self) -> usize {
        self.keys.len()
    }

    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// Set `retained_count`; returns `false` if `count == 0`.
    pub fn set_retained_ratchets(&mut self, count: usize) -> bool {
        if count > 0 {
            self.retained_count = count;
            self.clean();
            true
        } else {
            false
        }
    }

    pub fn retained_ratchets(&self) -> usize {
        self.retained_count
    }

    /// Set `rotation_interval` (seconds); returns `false` if `interval == 0`.
    pub fn set_ratchet_interval(&mut self, interval: u64) -> bool {
        if interval > 0 {
            self.rotation_interval = interval;
            true
        } else {
            false
        }
    }

    pub fn ratchet_interval(&self) -> u64 {
        self.rotation_interval
    }

    fn clean(&mut self) {
        if self.keys.len() > self.retained_count {
            self.keys.truncate(self.retained_count);
        }
    }

    /// Persist to `path` as a Python-compatible msgpack envelope.
    ///
    /// Python writes `{signature, ratchets}`. Rust also includes
    /// `last_rotation`, which Python ignores and Rust defaults when loading a
    /// Python-written file. `ratchets` is itself the msgpack-encoded key list
    /// signed by the owning identity.
    pub fn save(&self, path: &Path, signature: &[u8; 64]) -> std::io::Result<()> {
        let ratchets_packed =
            rmp_serde::to_vec(&self.keys).map_err(|e| std::io::Error::other(e.to_string()))?;

        let persisted = RatchetRingPersisted {
            signature: signature.to_vec(),
            ratchets: ratchets_packed,
            last_rotation: self.last_rotation,
        };
        let buf =
            rmp_serde::to_vec(&persisted).map_err(|e| std::io::Error::other(e.to_string()))?;
        persistence::atomic_write(path, &buf)
    }

    /// Load the ring, retrying with 1s/2s/4s backoff to ride out transient
    /// read errors while another process is rewriting the file.
    pub fn load(path: &Path) -> std::io::Result<(Self, [u8; 64])> {
        let mut last_err = None;
        let delays_ms = [0, 1000, 2000, 4000];

        for (attempt, delay) in delays_ms.iter().enumerate() {
            if *delay > 0 {
                std::thread::sleep(std::time::Duration::from_millis(*delay));
            }

            match Self::try_load(path) {
                Ok(result) => return Ok(result),
                Err(e) => {
                    if attempt < delays_ms.len() - 1 {
                        tracing::warn!(
                            attempt = attempt + 1,
                            path = %path.display(),
                            error = %e,
                            "ratchet load attempt failed, retrying"
                        );
                    }
                    last_err = Some(e);
                }
            }
        }

        Err(last_err.unwrap())
    }

    fn try_load(path: &Path) -> std::io::Result<(Self, [u8; 64])> {
        let data = std::fs::read(path)?;

        let persisted: RatchetRingPersisted =
            rmp_serde::from_slice(&data).map_err(|e| std::io::Error::other(e.to_string()))?;

        if persisted.signature.len() != 64 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid signature length in ratchet file",
            ));
        }

        let mut signature = [0u8; 64];
        signature.copy_from_slice(&persisted.signature);

        let keys: Vec<[u8; 32]> = rmp_serde::from_slice(&persisted.ratchets)
            .map_err(|e| std::io::Error::other(e.to_string()))?;

        Ok((
            Self {
                keys,
                last_rotation: persisted.last_rotation,
                retained_count: RATCHET_COUNT,
                rotation_interval: RATCHET_INTERVAL,
            },
            signature,
        ))
    }
}

#[derive(Serialize, Deserialize)]
struct RatchetRingPersisted {
    signature: Vec<u8>,
    ratchets: Vec<u8>,
    #[serde(default)]
    last_rotation: f64,
}

impl Zeroize for RatchetRing {
    fn zeroize(&mut self) {
        for key in &mut self.keys {
            key.zeroize();
        }
        self.keys.clear();
        self.last_rotation = 0.0;
    }
}

impl Drop for RatchetRing {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl Default for RatchetRing {
    fn default() -> Self {
        Self::new()
    }
}

/// Ratchet public key learned from a remote destination's announce, with
/// the local receive time used for expiry.
#[derive(Clone, Copy)]
pub struct ReceivedRatchet {
    pub ratchet_pub: [u8; 32],
    pub received_at: f64,
}

// On-disk shape shared with the Python reference: `{"ratchet": bytes, "received": float}`.
#[derive(Serialize, Deserialize)]
struct ReceivedRatchetPersisted {
    ratchet: Vec<u8>,
    received: f64,
}

impl ReceivedRatchet {
    pub fn new(ratchet_pub: [u8; 32]) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs_f64();
        Self {
            ratchet_pub,
            received_at: now,
        }
    }

    pub fn is_expired(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs_f64();
        now - self.received_at > RATCHET_EXPIRY as f64
    }

    pub fn ratchet_id(&self) -> Vec<u8> {
        get_ratchet_id(&self.ratchet_pub)
    }

    /// Persist to `{ratchetdir}/{hex(dest_hash)}` in the shared msgpack format.
    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        let persisted = ReceivedRatchetPersisted {
            ratchet: self.ratchet_pub.to_vec(),
            received: self.received_at,
        };
        let buf =
            rmp_serde::to_vec(&persisted).map_err(|e| std::io::Error::other(e.to_string()))?;

        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        persistence::atomic_write(path, &buf)
    }

    pub fn load(path: &Path) -> std::io::Result<Self> {
        let data = std::fs::read(path)?;
        let persisted: ReceivedRatchetPersisted =
            rmp_serde::from_slice(&data).map_err(|e| std::io::Error::other(e.to_string()))?;

        if persisted.ratchet.len() != 32 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid ratchet public key length",
            ));
        }
        let mut ratchet_pub = [0u8; 32];
        ratchet_pub.copy_from_slice(&persisted.ratchet);

        Ok(Self {
            ratchet_pub,
            received_at: persisted.received,
        })
    }
}

/// Compute the ratchet identifier: `full_hash(ratchet_pub)[..NAME_HASH_LENGTH]`.
pub fn get_ratchet_id(ratchet_pub: &[u8; 32]) -> Vec<u8> {
    let hash = full_hash(ratchet_pub);
    hash[..NAME_HASH_LENGTH].to_vec()
}

/// Derive the ratchet public key from its 32-byte private key.
pub fn ratchet_public_bytes(ratchet_prv: &[u8; 32]) -> [u8; 32] {
    let prv = X25519PrivateKey::from_bytes(ratchet_prv);
    prv.public_key().to_bytes()
}

/// Sweep `dir`, deleting expired and unparseable ratchet files. Returns the
/// number of files removed.
///
/// Only touches disk; pair with [`purge_expired_ratchets_in_memory`] when an
/// in-memory cache is also kept.
pub fn clean_received_ratchets_dir(dir: &Path) -> usize {
    let mut removed = 0usize;
    let Ok(entries) = std::fs::read_dir(dir) else {
        return 0;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let drop_it = match ReceivedRatchet::load(&path) {
            Ok(r) => r.is_expired(),
            Err(_) => true,
        };
        if drop_it {
            match std::fs::remove_file(&path) {
                Ok(()) => removed += 1,
                Err(e) => tracing::error!(
                    path = %path.display(),
                    error = %e,
                    "failed to remove expired/corrupt ratchet file"
                ),
            }
        }
    }
    removed
}

/// Drop expired entries from an in-memory received-ratchet map; returns the count removed.
pub fn purge_expired_ratchets_in_memory<K: Eq + std::hash::Hash>(
    map: &mut HashMap<K, ReceivedRatchet>,
) -> usize {
    let before = map.len();
    map.retain(|_, r| !r.is_expired());
    before - map.len()
}

/// Per-destination cache of remote ratchet public keys, with optional disk backing.
pub struct ReceivedRatchetStore {
    entries: HashMap<[u8; 16], ReceivedRatchet>,
    storage_dir: Option<PathBuf>,
}

impl ReceivedRatchetStore {
    /// In-memory only; no persistence.
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
            storage_dir: None,
        }
    }

    /// Store backed by `dir` (one file per destination hash).
    pub fn with_storage(dir: PathBuf) -> Self {
        Self {
            entries: HashMap::new(),
            storage_dir: Some(dir),
        }
    }

    /// Record `ratchet_pub` for `dest_hash`. Re-inserting the identical key is a no-op;
    /// any other value replaces the entry and is written to disk when backed.
    pub fn remember(&mut self, dest_hash: [u8; 16], ratchet_pub: [u8; 32]) {
        if let Some(existing) = self.entries.get(&dest_hash) {
            if existing.ratchet_pub == ratchet_pub {
                return;
            }
        }

        let received = ReceivedRatchet::new(ratchet_pub);

        if let Some(ref dir) = self.storage_dir {
            let hexhash = hex::encode(dest_hash);
            let path = dir.join(&hexhash);
            if let Err(e) = received.save(&path) {
                tracing::error!(
                    dest = hexhash,
                    error = %e,
                    "failed to persist received ratchet"
                );
            }
        }

        self.entries.insert(dest_hash, received);
    }

    /// Return the current ratchet public key for `dest_hash`, loading from
    /// disk on miss. Yields `None` if the entry is expired or absent.
    pub fn get(&mut self, dest_hash: &[u8; 16]) -> Option<[u8; 32]> {
        if !self.entries.contains_key(dest_hash) {
            if let Some(ref dir) = self.storage_dir {
                let hexhash = hex::encode(dest_hash);
                let path = dir.join(&hexhash);
                if path.exists() {
                    match ReceivedRatchet::load(&path) {
                        Ok(ratchet) => {
                            if !ratchet.is_expired() && ratchet.ratchet_pub.len() == 32 {
                                self.entries.insert(*dest_hash, ratchet);
                            } else {
                                return None;
                            }
                        }
                        Err(e) => {
                            tracing::error!(
                                dest = hexhash,
                                error = %e,
                                "failed to load ratchet from disk"
                            );
                            return None;
                        }
                    }
                }
            }
        }

        self.entries
            .get(dest_hash)
            .filter(|r| !r.is_expired())
            .map(|r| r.ratchet_pub)
    }

    /// Return the current ratchet ID for `dest_hash`, loading from disk on miss.
    pub fn current_ratchet_id(&mut self, dest_hash: &[u8; 16]) -> Option<Vec<u8>> {
        self.get(dest_hash)
            .map(|pub_bytes| get_ratchet_id(&pub_bytes))
    }

    pub fn clean_expired(&mut self) {
        self.entries.retain(|_, ratchet| !ratchet.is_expired());
        if let Some(ref dir) = self.storage_dir {
            clean_received_ratchets_dir(dir);
        }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl Default for ReceivedRatchetStore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ratchet_ring_rotate() {
        let mut ring = RatchetRing::new();
        assert!(ring.is_empty());

        let pub1 = ring.rotate();
        assert_eq!(ring.len(), 1);
        assert!(ring.current_public_key().is_some());

        let pub2 = ring.rotate();
        assert_eq!(ring.len(), 2);
        assert_ne!(pub1, pub2);
    }

    #[test]
    fn test_ratchet_ring_max_keys() {
        let mut ring = RatchetRing::new();
        for _ in 0..RATCHET_COUNT + 10 {
            ring.rotate();
        }
        assert_eq!(ring.len(), RATCHET_COUNT);
    }

    #[test]
    fn test_ratchet_ring_file_roundtrip() {
        let dir = std::env::temp_dir().join("reticulum_ratchet_test_msgpack");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("ratchets");

        let mut ring = RatchetRing::new();
        ring.rotate();
        ring.rotate();
        ring.rotate();
        let sig = [0xAA; 64];
        ring.save(&path, &sig).unwrap();

        let (ring2, sig2) = RatchetRing::load(&path).unwrap();
        assert_eq!(ring2.len(), 3);
        assert_eq!(sig2, sig);
        assert_eq!(ring.private_keys(), ring2.private_keys());

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn test_ratchet_ring_loads_python_shape_without_last_rotation() {
        #[derive(Serialize)]
        struct PythonRatchets {
            signature: Vec<u8>,
            ratchets: Vec<u8>,
        }

        let dir = std::env::temp_dir().join("reticulum_python_ratchet_test_msgpack");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("ratchets");

        let keys = vec![[0x11; 32], [0x22; 32]];
        let signature = vec![0xAA; 64];
        let ratchets = rmp_serde::to_vec(&keys).unwrap();
        let persisted = PythonRatchets {
            signature: signature.clone(),
            ratchets,
        };
        let buf = rmp_serde::to_vec(&persisted).unwrap();
        std::fs::write(&path, buf).unwrap();

        let (ring, loaded_signature) = RatchetRing::load(&path).unwrap();
        assert_eq!(ring.len(), 2);
        assert_eq!(ring.private_keys(), keys.as_slice());
        assert_eq!(loaded_signature.as_slice(), signature.as_slice());

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn test_set_retained_ratchets() {
        let mut ring = RatchetRing::new();
        for _ in 0..20 {
            ring.rotate();
        }
        assert_eq!(ring.len(), 20);

        assert!(ring.set_retained_ratchets(5));
        assert_eq!(ring.len(), 5);
        assert_eq!(ring.retained_ratchets(), 5);

        assert!(!ring.set_retained_ratchets(0));
        assert_eq!(ring.retained_ratchets(), 5);
    }

    #[test]
    fn test_set_ratchet_interval() {
        let mut ring = RatchetRing::new();
        assert_eq!(ring.ratchet_interval(), RATCHET_INTERVAL);

        assert!(ring.set_ratchet_interval(60));
        assert_eq!(ring.ratchet_interval(), 60);

        assert!(!ring.set_ratchet_interval(0));
        assert_eq!(ring.ratchet_interval(), 60);
    }

    #[test]
    fn test_received_ratchet_msgpack_roundtrip() {
        let dir = std::env::temp_dir().join("reticulum_recv_ratchet_test");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("test_ratchet");

        let ratchet_pub = rns_crypto::random::random_32();
        let received = ReceivedRatchet::new(ratchet_pub);

        received.save(&path).unwrap();
        let loaded = ReceivedRatchet::load(&path).unwrap();

        assert_eq!(loaded.ratchet_pub, ratchet_pub);
        assert!((loaded.received_at - received.received_at).abs() < 0.001);
        assert!(!loaded.is_expired());

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn test_received_ratchet_store() {
        let dir = std::env::temp_dir().join("reticulum_ratchet_store_test");
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::create_dir_all(&dir);

        let mut store = ReceivedRatchetStore::with_storage(dir.clone());
        let dest_hash = [0xAA; 16];
        let ratchet_pub = rns_crypto::random::random_32();

        store.remember(dest_hash, ratchet_pub);
        assert_eq!(store.len(), 1);

        assert_eq!(store.get(&dest_hash), Some(ratchet_pub));

        let rid = store.current_ratchet_id(&dest_hash);
        assert!(rid.is_some());

        // Fresh store re-reads the entry from disk.
        let mut store2 = ReceivedRatchetStore::with_storage(dir.clone());
        assert_eq!(store2.get(&dest_hash), Some(ratchet_pub));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_received_ratchet_store_dedup() {
        let mut store = ReceivedRatchetStore::new();
        let dest_hash = [0xBB; 16];
        let ratchet_pub = rns_crypto::random::random_32();

        store.remember(dest_hash, ratchet_pub);
        store.remember(dest_hash, ratchet_pub);
        assert_eq!(store.len(), 1);

        let ratchet_pub2 = rns_crypto::random::random_32();
        store.remember(dest_hash, ratchet_pub2);
        assert_eq!(store.len(), 1);
        assert_eq!(store.get(&dest_hash), Some(ratchet_pub2));
    }

    #[test]
    fn test_get_ratchet_id() {
        let pub_bytes = rns_crypto::random::random_32();
        let rid = get_ratchet_id(&pub_bytes);
        assert_eq!(rid.len(), NAME_HASH_LENGTH);
    }

    #[test]
    fn test_ratchet_public_bytes() {
        let prv = X25519PrivateKey::generate();
        let prv_bytes = prv.to_bytes();
        let pub_bytes = ratchet_public_bytes(&prv_bytes);
        assert_eq!(pub_bytes, prv.public_key().to_bytes());
    }
}
