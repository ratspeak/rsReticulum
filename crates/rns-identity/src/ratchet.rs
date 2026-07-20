use rns_crypto::sha::full_hash;
use rns_crypto::x25519::X25519PrivateKey;
use rns_wire::constants::{NAME_HASH_LENGTH, RATCHET_COUNT, RATCHET_EXPIRY, RATCHET_INTERVAL};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::{Zeroize, Zeroizing};

use crate::identity::Identity;
use crate::persistence;

const RATCHET_FILE_MAX_BYTES: usize = 64 * 1024;
const RATCHET_PACKED_MAX_BYTES: usize = 32 * 1024;
const RECEIVED_RATCHET_FILE_MAX_BYTES: usize = 1024;

fn wall_time_secs() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64()
}

fn invalid_data(message: impl Into<String>) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, message.into())
}

fn pack_ratchet_keys(keys: &[[u8; 32]]) -> std::io::Result<Zeroizing<Vec<u8>>> {
    let byte_keys: Vec<&serde_bytes::Bytes> = keys
        .iter()
        .map(|key| serde_bytes::Bytes::new(key))
        .collect();
    let packed = Zeroizing::new(
        rmp_serde::to_vec(&byte_keys).map_err(|e| std::io::Error::other(e.to_string()))?,
    );
    if packed.len() > RATCHET_PACKED_MAX_BYTES {
        return Err(invalid_data("packed ratchet ring exceeds size limit"));
    }
    Ok(packed)
}

fn unpack_ratchet_keys(packed: &[u8]) -> std::io::Result<Vec<[u8; 32]>> {
    if packed.len() > RATCHET_PACKED_MAX_BYTES {
        return Err(invalid_data("packed ratchet ring exceeds size limit"));
    }
    let mut encoded_keys: Vec<serde_bytes::ByteBuf> =
        rmp_serde::from_slice(packed).map_err(|e| std::io::Error::other(e.to_string()))?;
    if encoded_keys.len() > RATCHET_COUNT {
        for key in &mut encoded_keys {
            key.as_mut().zeroize();
        }
        return Err(invalid_data(format!(
            "ratchet ring contains {} keys; maximum is {RATCHET_COUNT}",
            encoded_keys.len()
        )));
    }

    if encoded_keys.iter().any(|key| key.len() != 32) {
        for key in &mut encoded_keys {
            key.as_mut().zeroize();
        }
        return Err(invalid_data("ratchet private key must be exactly 32 bytes"));
    }

    let mut keys = Vec::with_capacity(RATCHET_COUNT);
    for encoded in &mut encoded_keys {
        let mut key = [0u8; 32];
        key.copy_from_slice(encoded);
        keys.push(key);
        encoded.as_mut().zeroize();
    }
    Ok(keys)
}

/// On-disk format accepted by [`RatchetRing::load_verified`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RatchetRingFormat {
    /// Python-compatible `{signature, ratchets}` with a signature over the
    /// packed private-key list.
    Canonical,
    /// Historical Rust envelope whose signature covered only the current
    /// public ratchet and whose unsigned `last_rotation` field is ignored.
    LegacyRust,
}

/// A verified ratchet ring plus the format that was read from disk.
pub struct LoadedRatchetRing {
    ring: RatchetRing,
    format: RatchetRingFormat,
}

impl LoadedRatchetRing {
    pub fn ring(&self) -> &RatchetRing {
        &self.ring
    }

    pub fn format(&self) -> RatchetRingFormat {
        self.format
    }

    pub fn into_ring(self) -> RatchetRing {
        self.ring
    }
}

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
            keys: Vec::with_capacity(RATCHET_COUNT),
            last_rotation: 0.0,
            retained_count: RATCHET_COUNT,
            rotation_interval: RATCHET_INTERVAL,
        }
    }

    /// Generate a fresh ratchet key, push it to the front, and return its public key.
    ///
    /// Any keys evicted past `retained_count` are zeroised before drop.
    pub fn rotate(&mut self) -> [u8; 32] {
        self.rotate_at(wall_time_secs())
    }

    /// Generate a fresh ratchet while recording an explicit wall-clock time.
    ///
    /// Callers that need crash safety should use [`Self::prepare_rotation_at`],
    /// persist its candidate ring, and only then call
    /// [`Self::commit_prepared_rotation`].
    pub fn rotate_at(&mut self, now: f64) -> [u8; 32] {
        let prv = X25519PrivateKey::generate();
        let pub_key = prv.public_key().to_bytes();

        // Make room before insertion so a full ring never reallocates an
        // uncleared backing buffer containing every retained private key.
        while self.keys.len() >= self.retained_count {
            let last = self.keys.len() - 1;
            self.keys[last].zeroize();
            self.keys.truncate(last);
        }
        self.keys.insert(0, prv.to_bytes());
        self.last_rotation = if now.is_finite() && now >= 0.0 {
            now
        } else {
            0.0
        };

        pub_key
    }

    /// True when at least `rotation_interval` seconds have elapsed since the last rotate.
    pub fn needs_rotation(&self) -> bool {
        self.needs_rotation_at(wall_time_secs())
    }

    /// Test rotation age against an explicit wall-clock value.
    ///
    /// A missing age (`last_rotation == 0`) is due. A clock rollback is not:
    /// callers can anchor an unknown age with [`Self::anchor_rotation_at`] and
    /// wait one normal interval instead of rotating immediately.
    pub fn needs_rotation_at(&self, now: f64) -> bool {
        if !now.is_finite() || now < 0.0 {
            return false;
        }
        if self.last_rotation <= 0.0 {
            return true;
        }
        now >= self.last_rotation && now - self.last_rotation >= self.rotation_interval as f64
    }

    /// Set the age anchor without generating or discarding any key material.
    pub fn anchor_rotation_at(&mut self, now: f64) -> bool {
        if !now.is_finite() || now < 0.0 {
            return false;
        }
        self.last_rotation = now;
        true
    }

    pub fn last_rotation(&self) -> f64 {
        self.last_rotation
    }

    /// Prepare a candidate rotation without changing the live ring.
    pub fn prepare_rotation_at(&self, now: f64) -> PreparedRatchetRotation {
        let mut candidate = self.duplicate();
        let public_key = candidate.rotate_at(now);
        PreparedRatchetRotation {
            candidate,
            public_key,
        }
    }

    /// Replace the live ring with a previously persisted candidate.
    pub fn commit_prepared_rotation(&mut self, prepared: PreparedRatchetRotation) -> [u8; 32] {
        let PreparedRatchetRotation {
            mut candidate,
            public_key,
        } = prepared;
        std::mem::swap(self, &mut candidate);
        public_key
    }

    fn duplicate(&self) -> Self {
        let mut keys = Vec::with_capacity(RATCHET_COUNT);
        keys.extend_from_slice(&self.keys);
        Self {
            keys,
            last_rotation: self.last_rotation,
            retained_count: self.retained_count,
            rotation_interval: self.rotation_interval,
        }
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

    /// Set `retained_count`; returns `false` outside `1..=RATCHET_COUNT`.
    pub fn set_retained_ratchets(&mut self, count: usize) -> bool {
        if (1..=RATCHET_COUNT).contains(&count) {
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
            for key in &mut self.keys[self.retained_count..] {
                key.zeroize();
            }
            self.keys.truncate(self.retained_count);
        }
    }

    /// Persist to `path` as the exact Python-compatible msgpack envelope.
    ///
    /// `signature` must cover the packed `ratchets` list. Production callers
    /// should prefer [`Self::save_verified`], which cannot sign the wrong data.
    pub fn save(&self, path: &Path, signature: &[u8; 64]) -> std::io::Result<()> {
        let ratchets_packed = pack_ratchet_keys(&self.keys)?;

        let persisted = Zeroizing::new(RatchetRingPersistedWrite {
            signature: signature.to_vec(),
            ratchets: ratchets_packed.to_vec(),
        });
        let buf = Zeroizing::new(
            rmp_serde::to_vec_named(&*persisted)
                .map_err(|e| std::io::Error::other(e.to_string()))?,
        );
        if buf.len() > RATCHET_FILE_MAX_BYTES {
            return Err(invalid_data("ratchet ring file exceeds size limit"));
        }
        persistence::atomic_write(path, &buf)
    }

    /// Sign the packed key list with `identity`, persist it, and verify the
    /// final bytes before returning.
    pub fn save_verified(&self, path: &Path, identity: &Identity) -> std::io::Result<()> {
        let ratchets_packed = pack_ratchet_keys(&self.keys)?;
        let signature = identity.sign(&ratchets_packed).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "identity cannot sign ratchet ring",
            )
        })?;

        let persisted = Zeroizing::new(RatchetRingPersistedWrite {
            signature: signature.to_vec(),
            ratchets: ratchets_packed.to_vec(),
        });
        let buf = Zeroizing::new(
            rmp_serde::to_vec_named(&*persisted)
                .map_err(|e| std::io::Error::other(e.to_string()))?,
        );
        if buf.len() > RATCHET_FILE_MAX_BYTES {
            return Err(invalid_data("ratchet ring file exceeds size limit"));
        }
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
                Ok(decoded) => return Ok((decoded.ring, decoded.signature)),
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

    /// Load a bounded ring and verify that its signature belongs to `identity`.
    ///
    /// Canonical files are verified over the packed key list. Historical Rust
    /// files are accepted only when their old current-public-key signature is
    /// valid; their unsigned rotation timestamp is deliberately ignored.
    pub fn load_verified(path: &Path, identity: &Identity) -> std::io::Result<LoadedRatchetRing> {
        let decoded = Self::try_load(path)?;

        let format = if identity.verify(&decoded.packed, &decoded.signature) {
            RatchetRingFormat::Canonical
        } else if decoded.had_legacy_rotation
            && decoded
                .ring
                .current_public_key()
                .is_some_and(|public| identity.verify(&public, &decoded.signature))
        {
            RatchetRingFormat::LegacyRust
        } else {
            return Err(invalid_data("invalid ratchet ring signature"));
        };

        Ok(LoadedRatchetRing {
            ring: decoded.ring,
            format,
        })
    }

    fn try_load(path: &Path) -> std::io::Result<DecodedRatchetRing> {
        let data = Zeroizing::new(
            persistence::read_file_bounded(path, RATCHET_FILE_MAX_BYTES)?
                .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::NotFound))?,
        );

        let persisted: RatchetRingPersistedRead =
            rmp_serde::from_slice(&data).map_err(|e| std::io::Error::other(e.to_string()))?;

        if persisted.signature.len() != 64 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid signature length in ratchet file",
            ));
        }

        let mut signature = [0u8; 64];
        signature.copy_from_slice(&persisted.signature);

        let packed = Zeroizing::new(persisted.ratchets);
        let keys = unpack_ratchet_keys(&packed)?;
        let had_legacy_rotation = persisted.last_rotation.is_some();

        Ok(DecodedRatchetRing {
            ring: Self {
                keys,
                // Rotation age is control-plane metadata, not part of the
                // Python ring signature. Never trust the historical unsigned
                // value from disk.
                last_rotation: 0.0,
                retained_count: RATCHET_COUNT,
                rotation_interval: RATCHET_INTERVAL,
            },
            signature,
            had_legacy_rotation,
            packed,
        })
    }
}

struct DecodedRatchetRing {
    ring: RatchetRing,
    signature: [u8; 64],
    had_legacy_rotation: bool,
    packed: Zeroizing<Vec<u8>>,
}

/// A rotation candidate owns a duplicate secret ring and zeroises it on drop
/// unless it is committed into the live ring.
pub struct PreparedRatchetRotation {
    candidate: RatchetRing,
    public_key: [u8; 32],
}

impl PreparedRatchetRotation {
    pub fn ring(&self) -> &RatchetRing {
        &self.candidate
    }

    pub fn public_key(&self) -> [u8; 32] {
        self.public_key
    }
}

#[derive(Serialize, Zeroize)]
struct RatchetRingPersistedWrite {
    #[serde(with = "serde_bytes")]
    signature: Vec<u8>,
    #[serde(with = "serde_bytes")]
    ratchets: Vec<u8>,
}

#[derive(Deserialize)]
struct RatchetRingPersistedRead {
    #[serde(with = "serde_bytes")]
    signature: Vec<u8>,
    #[serde(with = "serde_bytes")]
    ratchets: Vec<u8>,
    #[serde(default)]
    last_rotation: Option<f64>,
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
    #[serde(with = "serde_bytes")]
    ratchet: Vec<u8>,
    received: f64,
}

impl ReceivedRatchet {
    pub fn new(ratchet_pub: [u8; 32]) -> Self {
        Self::new_at(ratchet_pub, wall_time_secs())
    }

    pub fn new_at(ratchet_pub: [u8; 32], received_at: f64) -> Self {
        Self {
            ratchet_pub,
            received_at: if received_at.is_finite() && received_at >= 0.0 {
                received_at
            } else {
                0.0
            },
        }
    }

    pub fn is_expired(&self) -> bool {
        self.is_expired_at(wall_time_secs())
    }

    pub fn is_expired_at(&self, now: f64) -> bool {
        now.is_finite() && now >= self.received_at && now - self.received_at > RATCHET_EXPIRY as f64
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
        let buf = rmp_serde::to_vec_named(&persisted)
            .map_err(|e| std::io::Error::other(e.to_string()))?;

        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        persistence::atomic_write(path, &buf)
    }

    pub fn load(path: &Path) -> std::io::Result<Self> {
        let data = persistence::read_file_bounded(path, RECEIVED_RATCHET_FILE_MAX_BYTES)?
            .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::NotFound))?;
        let persisted: ReceivedRatchetPersisted =
            rmp_serde::from_slice(&data).map_err(|e| std::io::Error::other(e.to_string()))?;

        if persisted.ratchet.len() != 32 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid ratchet public key length",
            ));
        }
        if !persisted.received.is_finite() || persisted.received < 0.0 {
            return Err(invalid_data("invalid received-ratchet timestamp"));
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
        self.remember_at(dest_hash, ratchet_pub, wall_time_secs());
    }

    /// Record a ratchet with an explicit local receive time. Re-inserting the
    /// same key remains a no-op and therefore cannot extend its lifetime.
    pub fn remember_at(&mut self, dest_hash: [u8; 16], ratchet_pub: [u8; 32], received_at: f64) {
        if let Some(existing) = self.entries.get(&dest_hash) {
            if existing.ratchet_pub == ratchet_pub {
                return;
            }
        }

        let received = ReceivedRatchet::new_at(ratchet_pub, received_at);

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
        self.get_at(dest_hash, wall_time_secs())
    }

    pub fn get_at(&mut self, dest_hash: &[u8; 16], now: f64) -> Option<[u8; 32]> {
        if !self.entries.contains_key(dest_hash) {
            if let Some(ref dir) = self.storage_dir {
                let hexhash = hex::encode(dest_hash);
                let path = dir.join(&hexhash);
                if path.exists() {
                    match ReceivedRatchet::load(&path) {
                        Ok(ratchet) => {
                            if !ratchet.is_expired_at(now) {
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
            .filter(|r| !r.is_expired_at(now))
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
    use std::io::Cursor;

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
    fn prepared_rotation_does_not_mutate_live_ring_until_commit() {
        let mut ring = RatchetRing::new();
        ring.rotate_at(100.0);
        let before = ring.private_keys().to_vec();

        let abandoned = ring.prepare_rotation_at(200.0);
        assert_eq!(ring.private_keys(), before);
        assert_eq!(abandoned.ring().len(), 2);
        drop(abandoned);
        assert_eq!(ring.private_keys(), before);

        let prepared = ring.prepare_rotation_at(200.0);
        let expected_public = prepared.public_key();
        let committed_public = ring.commit_prepared_rotation(prepared);
        assert_eq!(committed_public, expected_public);
        assert_eq!(ring.len(), 2);
        assert_eq!(ring.current_public_key(), Some(expected_public));
        assert_eq!(ring.last_rotation(), 200.0);
    }

    #[test]
    fn rotation_clock_rollback_never_looks_elapsed() {
        let mut ring = RatchetRing::new();
        ring.set_ratchet_interval(30);
        assert!(ring.needs_rotation_at(100.0));
        ring.rotate_at(100.0);
        assert!(!ring.needs_rotation_at(99.0));
        assert!(!ring.needs_rotation_at(129.999));
        assert!(ring.needs_rotation_at(130.0));

        let mut unknown_age = RatchetRing::new();
        assert!(unknown_age.needs_rotation_at(100.0));
        assert!(unknown_age.anchor_rotation_at(100.0));
        assert!(!unknown_age.needs_rotation_at(100.0));
    }

    #[test]
    fn test_ratchet_ring_max_keys() {
        let mut ring = RatchetRing::new();
        let initial_capacity = ring.keys.capacity();
        for _ in 0..RATCHET_COUNT + 10 {
            ring.rotate();
        }
        assert_eq!(ring.len(), RATCHET_COUNT);
        assert_eq!(
            ring.keys.capacity(),
            initial_capacity,
            "rotating a full secret ring must not reallocate uncleared storage"
        );
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
    fn verified_ring_file_is_python_map_of_signed_binary_keys() {
        let dir = std::env::temp_dir().join("reticulum_ratchet_python_wire");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("ratchets");
        let identity = Identity::new();
        let mut ring = RatchetRing::new();
        ring.rotate_at(100.0);
        ring.rotate_at(200.0);

        ring.save_verified(&path, &identity).unwrap();
        let data = std::fs::read(&path).unwrap();
        let envelope = rmpv::decode::read_value(&mut Cursor::new(&data)).unwrap();
        let map = envelope.as_map().expect("Python envelope must be a map");
        assert_eq!(map.len(), 2);
        let signature = map
            .iter()
            .find(|(key, _)| key.as_str() == Some("signature"))
            .and_then(|(_, value)| value.as_slice())
            .expect("signature must be MessagePack binary");
        let packed = map
            .iter()
            .find(|(key, _)| key.as_str() == Some("ratchets"))
            .and_then(|(_, value)| value.as_slice())
            .expect("ratchets must be MessagePack binary");
        let signature: [u8; 64] = signature.try_into().unwrap();
        assert!(identity.verify(packed, &signature));

        let packed_value = rmpv::decode::read_value(&mut Cursor::new(packed)).unwrap();
        let keys = packed_value.as_array().expect("ratchets must be a list");
        assert_eq!(keys.len(), 2);
        assert!(
            keys.iter()
                .all(|key| key.as_slice().is_some_and(|b| b.len() == 32))
        );

        let loaded = RatchetRing::load_verified(&path, &identity).unwrap();
        assert_eq!(loaded.format(), RatchetRingFormat::Canonical);
        assert_eq!(loaded.ring().private_keys(), ring.private_keys());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn verified_ring_rejects_wrong_identity_signature() {
        let dir = std::env::temp_dir().join("reticulum_ratchet_wrong_signature");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("ratchets");
        let owner = Identity::new();
        let wrong = Identity::new();
        let mut ring = RatchetRing::new();
        ring.rotate_at(100.0);
        ring.save_verified(&path, &owner).unwrap();

        let err = RatchetRing::load_verified(&path, &wrong)
            .err()
            .expect("wrong owner must be rejected");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        assert!(
            path.exists(),
            "a rejected key file must be preserved for recovery"
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn verified_ring_accepts_exact_legacy_rust_shape_but_ignores_age() {
        #[derive(Serialize)]
        struct LegacyRustRatchets {
            signature: Vec<u8>,
            ratchets: Vec<u8>,
            last_rotation: f64,
        }

        let dir = std::env::temp_dir().join("reticulum_ratchet_legacy_rust");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("ratchets");
        let identity = Identity::new();
        let keys = vec![[0x11; 32], [0x22; 32]];
        // This intentionally recreates the pre-fix Rust encoding: compact
        // struct, byte vectors as integer arrays, and signature over only the
        // current public ratchet.
        let ratchets = rmp_serde::to_vec(&keys).unwrap();
        let current_public = ratchet_public_bytes(&keys[0]);
        let signature = identity.sign(&current_public).unwrap();
        let legacy = LegacyRustRatchets {
            signature: signature.to_vec(),
            ratchets,
            last_rotation: f64::MAX,
        };
        std::fs::write(&path, rmp_serde::to_vec(&legacy).unwrap()).unwrap();

        let loaded = RatchetRing::load_verified(&path, &identity).unwrap();
        assert_eq!(loaded.format(), RatchetRingFormat::LegacyRust);
        assert_eq!(loaded.ring().private_keys(), keys);
        assert_eq!(loaded.ring().last_rotation(), 0.0);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn ring_load_rejects_oversize_and_overcount_without_retrying() {
        let dir = std::env::temp_dir().join("reticulum_ratchet_bounds");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("ratchets");
        let identity = Identity::new();

        std::fs::write(&path, vec![0u8; RATCHET_FILE_MAX_BYTES + 1]).unwrap();
        assert_eq!(
            RatchetRing::load_verified(&path, &identity)
                .err()
                .expect("oversize ring must fail")
                .kind(),
            std::io::ErrorKind::InvalidData
        );

        let keys = vec![[0x44; 32]; RATCHET_COUNT + 1];
        let packed = rmp_serde::to_vec(&keys).unwrap();
        let envelope = RatchetRingPersistedWrite {
            signature: vec![0u8; 64],
            ratchets: packed,
        };
        std::fs::write(&path, rmp_serde::to_vec_named(&envelope).unwrap()).unwrap();
        assert_eq!(
            RatchetRing::load_verified(&path, &identity)
                .err()
                .expect("overcount ring must fail")
                .kind(),
            std::io::ErrorKind::InvalidData
        );

        std::fs::remove_dir_all(dir).unwrap();
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

        let encoded = std::fs::read(&path).unwrap();
        let envelope = rmpv::decode::read_value(&mut Cursor::new(encoded)).unwrap();
        let map = envelope.as_map().expect("Python envelope must be a map");
        assert_eq!(map.len(), 2);
        assert!(
            map.iter()
                .find(|(key, _)| key.as_str() == Some("ratchet"))
                .and_then(|(_, value)| value.as_slice())
                .is_some_and(|ratchet| ratchet.len() == 32)
        );

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
    fn identical_received_ratchet_does_not_refresh_expiry() {
        let mut store = ReceivedRatchetStore::new();
        let dest_hash = [0xBC; 16];
        let ratchet = [0xCD; 32];
        store.remember_at(dest_hash, ratchet, 10.0);
        store.remember_at(dest_hash, ratchet, 20.0);

        assert_eq!(
            store.get_at(&dest_hash, 10.0 + RATCHET_EXPIRY as f64),
            Some(ratchet)
        );
        assert_eq!(
            store.get_at(&dest_hash, 10.0 + RATCHET_EXPIRY as f64 + 0.001),
            None,
            "same-key reannounce must not extend the original receive age"
        );
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
