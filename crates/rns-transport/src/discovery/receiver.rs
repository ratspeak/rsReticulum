//! Inbound discovery announce handler.
//!
//! Bridges [`AnnounceHandlerEvent`] (the transport-actor callback type) to
//! the discovery pipeline:
//!
//! 1. split the `app_data` payload into flags / body / stamp,
//! 2. (optionally) decrypt the body using a shared-network decryptor,
//! 3. validate the stamp against a [`DiscoveryStamper`],
//! 4. decode the info map, filter by `discovery_sources` if configured,
//! 5. upsert into [`DiscoveryStore`] and notify any observer.
//!
//! Mirrors Python `Discovery.InterfaceAnnounceHandler.received_announce`.
//! The spawned path uses a bounded blocking-worker set so slow stamp
//! validation cannot stall the transport actor or a Tokio runtime worker.

use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, TryLockError};

use tokio::sync::mpsc;
use tokio::task::{JoinHandle, JoinSet};
use tracing::{debug, trace, warn};

use crate::messages::AnnounceHandlerEvent;

use super::app_data::{self, DiscoveryInfo};
use super::constants::FLAG_ENCRYPTED;
use super::stamper::DiscoveryStamper;
use super::storage::{DiscoveredInterface, DiscoveryStore};

const VALID_CACHE_CAPACITY: usize = 2_048;
const INVALID_CACHE_CAPACITY: usize = 2_048;
const MAX_IN_FLIGHT_EVENTS: usize = 32;

/// Pluggable decryptor for discovery announces whose flags byte has
/// `FLAG_ENCRYPTED` set. The concrete impl wraps the `network_identity`
/// (Python `RNS.Identity.decrypt`).
///
/// Returning `None` means the ciphertext could not be decrypted with the
/// held identity — the receiver treats that as "not for us" and drops the
/// announce silently.
pub trait DiscoveryDecryptor: Send + Sync {
    fn decrypt(&self, ciphertext: &[u8]) -> Option<Vec<u8>>;
}

/// Configuration passed to [`spawn`]. Cheap to clone into the task.
pub struct ReceiverConfig {
    pub stamper: Arc<dyn DiscoveryStamper>,
    pub store: Arc<DiscoveryStore>,
    /// Minimum stamp value required to accept an announce. Mirrors Python
    /// `discover_interfaces_required_value`.
    pub required_value: u8,
    /// When `Some`, only announces whose source transport-id is in the
    /// list are accepted (Python `interface_discovery_sources`). `None`
    /// accepts any stamped source.
    pub discovery_sources: Option<Vec<[u8; 16]>>,
    /// Optional decryptor for `FLAG_ENCRYPTED` announces. `None` means
    /// encrypted announces are silently ignored.
    pub decryptor: Option<Arc<dyn DiscoveryDecryptor>>,
    /// Optional observer channel — every successful upsert is published.
    /// The sender is never blocked (uses `try_send`), so a slow consumer
    /// drops events rather than stalling the receiver.
    pub observer: Option<mpsc::Sender<DiscoveredInterface>>,
}

/// Result of a single announce classification. Returned by
/// [`ReceiverConfig::process_event`] so tests can assert on decisions without
/// needing a live tokio task.
#[derive(Debug, PartialEq)]
pub enum Outcome {
    /// Announce accepted and upserted.
    Accepted,
    /// Announce rejected before upsert. `Reason` carries the why.
    Rejected(Reason),
}

#[derive(Debug, PartialEq)]
pub enum Reason {
    /// No `app_data` on the announce — discovery announces always carry one.
    MissingAppData,
    /// `app_data` too small to even contain a flags byte + stamp.
    Malformed,
    /// `FLAG_ENCRYPTED` set without a configured decryptor.
    EncryptedWithoutKey,
    /// Decryptor returned `None` (ciphertext not addressed to us).
    DecryptFailed,
    /// Another ingress worker is already performing stamp validation.
    ValidationBusy,
    /// Stamp did not meet the required value.
    StampInvalid,
    /// Info map did not decode.
    DecodeFailed,
    /// Source (transport_id) not in the configured discovery_sources list.
    UnauthorizedSource,
    /// Upsert into the on-disk store failed (io error).
    StorageFailed,
}

/// Monotonic, payload-free counters for receiver cache and admission behavior.
///
/// Values saturate at `u64::MAX`. No announce bytes, hashes, identities, or
/// decrypted fields are retained in the metrics.
#[derive(Debug, Default)]
pub struct ReceiverMetrics {
    valid_cache_hits: AtomicU64,
    invalid_cache_hits: AtomicU64,
    validation_busy_drops: AtomicU64,
    valid_cache_evictions: AtomicU64,
    invalid_cache_evictions: AtomicU64,
}

/// Point-in-time snapshot of [`ReceiverMetrics`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ReceiverMetricsSnapshot {
    pub valid_cache_hits: u64,
    pub invalid_cache_hits: u64,
    pub validation_busy_drops: u64,
    pub valid_cache_evictions: u64,
    pub invalid_cache_evictions: u64,
}

impl ReceiverMetrics {
    pub fn snapshot(&self) -> ReceiverMetricsSnapshot {
        ReceiverMetricsSnapshot {
            valid_cache_hits: self.valid_cache_hits.load(Ordering::Relaxed),
            invalid_cache_hits: self.invalid_cache_hits.load(Ordering::Relaxed),
            validation_busy_drops: self.validation_busy_drops.load(Ordering::Relaxed),
            valid_cache_evictions: self.valid_cache_evictions.load(Ordering::Relaxed),
            invalid_cache_evictions: self.invalid_cache_evictions.load(Ordering::Relaxed),
        }
    }

    fn increment(counter: &AtomicU64) -> u64 {
        let previous = counter
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                Some(value.saturating_add(1))
            })
            .unwrap_or(u64::MAX);
        previous.saturating_add(1)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct CacheKey([u8; 32]);

#[derive(Clone)]
struct ValidatedMaterial {
    info: DiscoveryInfo,
    stamp: Vec<u8>,
    stamp_value: u8,
}

enum CacheLookup {
    Valid(Box<ValidatedMaterial>),
    Invalid,
    Miss,
}

struct ValidationCaches {
    valid: HashMap<CacheKey, ValidatedMaterial>,
    valid_order: VecDeque<CacheKey>,
    invalid: HashSet<CacheKey>,
    invalid_order: VecDeque<CacheKey>,
    valid_capacity: usize,
    invalid_capacity: usize,
}

impl ValidationCaches {
    fn new(valid_capacity: usize, invalid_capacity: usize) -> Self {
        Self {
            valid: HashMap::with_capacity(valid_capacity),
            valid_order: VecDeque::with_capacity(valid_capacity),
            invalid: HashSet::with_capacity(invalid_capacity),
            invalid_order: VecDeque::with_capacity(invalid_capacity),
            valid_capacity,
            invalid_capacity,
        }
    }

    fn lookup(&self, key: &CacheKey) -> CacheLookup {
        if let Some(material) = self.valid.get(key) {
            CacheLookup::Valid(Box::new(material.clone()))
        } else if self.invalid.contains(key) {
            CacheLookup::Invalid
        } else {
            CacheLookup::Miss
        }
    }

    fn insert_valid(&mut self, key: CacheKey, material: ValidatedMaterial) -> bool {
        if let Entry::Occupied(mut entry) = self.valid.entry(key) {
            entry.insert(material);
            return false;
        }

        if self.invalid.remove(&key) {
            self.invalid_order.retain(|queued| queued != &key);
        }
        self.valid.insert(key, material);
        self.valid_order.push_back(key);
        self.evict_valid_if_needed()
    }

    fn insert_invalid(&mut self, key: CacheKey) -> bool {
        if self.invalid.contains(&key) {
            return false;
        }

        if self.valid.remove(&key).is_some() {
            self.valid_order.retain(|queued| queued != &key);
        }
        self.invalid.insert(key);
        self.invalid_order.push_back(key);
        self.evict_invalid_if_needed()
    }

    fn evict_valid_if_needed(&mut self) -> bool {
        let mut evicted = false;
        while self.valid.len() > self.valid_capacity {
            if let Some(oldest) = self.valid_order.pop_front() {
                evicted |= self.valid.remove(&oldest).is_some();
            } else {
                break;
            }
        }
        evicted
    }

    fn evict_invalid_if_needed(&mut self) -> bool {
        let mut evicted = false;
        while self.invalid.len() > self.invalid_capacity {
            if let Some(oldest) = self.invalid_order.pop_front() {
                evicted |= self.invalid.remove(&oldest);
            } else {
                break;
            }
        }
        evicted
    }
}

struct ReceiverState {
    config: ReceiverConfig,
    caches: Mutex<ValidationCaches>,
    validation_lock: Mutex<()>,
    persistence_lock: Mutex<()>,
    metrics: Arc<ReceiverMetrics>,
}

impl ReceiverConfig {
    /// Classify a single announce event, upsert on accept, emit on observer.
    ///
    /// Synchronous so unit tests can drive it without a task. Returns an
    /// [`Outcome`] describing the decision.
    pub fn process_event(&self, event: &AnnounceHandlerEvent) -> Outcome {
        self.process_event_inner(event, None)
    }

    fn process_event_inner(
        &self,
        event: &AnnounceHandlerEvent,
        receiver: Option<&ReceiverState>,
    ) -> Outcome {
        let Some(raw) = event.app_data.as_ref() else {
            return Outcome::Rejected(Reason::MissingAppData);
        };

        let (flags, body) = match app_data::split_flags(raw) {
            Ok(p) => p,
            Err(_) => return Outcome::Rejected(Reason::Malformed),
        };

        let encrypted = flags & FLAG_ENCRYPTED != 0;
        if encrypted && self.decryptor.is_none() {
            return Outcome::Rejected(Reason::EncryptedWithoutKey);
        }

        // Hash the exact wire app_data, including flags and ciphertext. For
        // encrypted announces, bind the key to this receiver's decryptor
        // instance so plaintext validated under one network identity cannot
        // satisfy another identity's cache.
        let cache_key = receiver.map(|state| {
            let decryptor = if encrypted {
                Some(self.decryptor.as_ref().expect("checked above"))
            } else {
                None
            };
            state.cache_key(raw, decryptor)
        });

        if let (Some(state), Some(key)) = (receiver, cache_key) {
            match state.cache_lookup(&key) {
                CacheLookup::Valid(material) => {
                    return self.accept_material(event, *material, receiver);
                }
                CacheLookup::Invalid => {
                    return Outcome::Rejected(Reason::StampInvalid);
                }
                CacheLookup::Miss => {}
            }
        }

        // Decrypt body if FLAG_ENCRYPTED set. We own the bytes once we
        // decrypt, but keep a borrow when unencrypted.
        let decrypted: Vec<u8>;
        let working: &[u8] = if encrypted {
            let decryptor = self.decryptor.as_ref().expect("checked above");
            match decryptor.decrypt(body) {
                Some(pt) => {
                    decrypted = pt;
                    &decrypted
                }
                None => return Outcome::Rejected(Reason::DecryptFailed),
            }
        } else {
            body
        };

        let (packed_info, stamp) = match app_data::split_stamp(working) {
            Ok(p) => p,
            Err(_) => return Outcome::Rejected(Reason::Malformed),
        };

        let material = if let (Some(state), Some(key)) = (receiver, cache_key) {
            match state.validate_and_cache(key, packed_info, stamp) {
                Ok(material) => material,
                Err(reason) => return Outcome::Rejected(reason),
            }
        } else {
            match self.validate_material(packed_info, stamp) {
                Ok(material) => material,
                Err(reason) => return Outcome::Rejected(reason),
            }
        };

        self.accept_material(event, material, receiver)
    }

    fn validate_material(
        &self,
        packed_info: &[u8],
        stamp: &[u8],
    ) -> Result<ValidatedMaterial, Reason> {
        let infohash = rns_crypto::sha::full_hash(packed_info);
        if !self.stamper.valid(&infohash, stamp, self.required_value) {
            return Err(Reason::StampInvalid);
        }

        let info: DiscoveryInfo = match app_data::decode_info(packed_info) {
            Ok(i) => i,
            Err(err) => {
                trace!(?err, "discovery: info decode failed");
                return Err(Reason::DecodeFailed);
            }
        };

        Ok(ValidatedMaterial {
            info,
            stamp: stamp.to_vec(),
            stamp_value: self.stamper.value(&infohash, stamp),
        })
    }

    fn accept_material(
        &self,
        event: &AnnounceHandlerEvent,
        material: ValidatedMaterial,
        receiver: Option<&ReceiverState>,
    ) -> Outcome {
        // `DiscoveryStore::upsert` uses a deterministic sidecar name. Keep
        // concurrent cache hits from racing on that file while leaving stamp
        // validation independent.
        let _persistence_guard = receiver.map(|state| lock_unpoisoned(&state.persistence_lock));
        let ValidatedMaterial {
            info,
            stamp,
            stamp_value,
        } = material;
        let announced_identity = event.identity_hash.unwrap_or(info.transport_id);
        if let Some(sources) = self.discovery_sources.as_ref() {
            if !sources.iter().any(|s| s == &announced_identity) {
                return Outcome::Rejected(Reason::UnauthorizedSource);
            }
        }

        let now = now_unix();
        let record = DiscoveredInterface {
            info,
            network_id: announced_identity,
            hops: event.hops,
            stamp_value,
            stamp,
            discovered: now,
            last_heard: now,
            heard_count: 0, // overridden by upsert merge
            status: None,
        };

        if let Err(err) = self.store.upsert(record.clone()) {
            warn!(?err, "discovery: storage upsert failed");
            return Outcome::Rejected(Reason::StorageFailed);
        }

        if let Some(obs) = self.observer.as_ref() {
            // `try_send` keeps the receiver non-blocking; dropped events
            // are not a correctness bug — observer is advisory.
            let _ = obs.try_send(record);
        }

        Outcome::Accepted
    }
}

impl ReceiverState {
    fn new(config: ReceiverConfig, metrics: Arc<ReceiverMetrics>) -> Self {
        Self {
            config,
            caches: Mutex::new(ValidationCaches::new(
                VALID_CACHE_CAPACITY,
                INVALID_CACHE_CAPACITY,
            )),
            validation_lock: Mutex::new(()),
            persistence_lock: Mutex::new(()),
            metrics,
        }
    }

    fn process_event(&self, event: &AnnounceHandlerEvent) -> Outcome {
        self.config.process_event_inner(event, Some(self))
    }

    fn cache_key(
        &self,
        raw_app_data: &[u8],
        decryptor: Option<&Arc<dyn DiscoveryDecryptor>>,
    ) -> CacheKey {
        const PLAIN_DOMAIN: &[u8] = b"rns.discovery.cache.plain.v1";
        const ENCRYPTED_DOMAIN: &[u8] = b"rns.discovery.cache.encrypted.v1";

        let mut key_material = Vec::with_capacity(
            raw_app_data.len() + ENCRYPTED_DOMAIN.len() + std::mem::size_of::<usize>(),
        );
        if let Some(decryptor) = decryptor {
            key_material.extend_from_slice(ENCRYPTED_DOMAIN);
            let instance = Arc::as_ptr(decryptor) as *const () as usize;
            key_material.extend_from_slice(&instance.to_ne_bytes());
        } else {
            key_material.extend_from_slice(PLAIN_DOMAIN);
        }
        key_material.extend_from_slice(raw_app_data);
        CacheKey(rns_crypto::sha::full_hash(&key_material))
    }

    fn cache_lookup(&self, key: &CacheKey) -> CacheLookup {
        let result = lock_unpoisoned(&self.caches).lookup(key);
        match result {
            CacheLookup::Valid(_) => {
                let hits = ReceiverMetrics::increment(&self.metrics.valid_cache_hits);
                trace!(hits, "discovery: valid announce cache hit");
            }
            CacheLookup::Invalid => {
                let hits = ReceiverMetrics::increment(&self.metrics.invalid_cache_hits);
                trace!(hits, "discovery: invalid announce cache hit");
            }
            CacheLookup::Miss => {}
        }
        result
    }

    fn validate_and_cache(
        &self,
        key: CacheKey,
        packed_info: &[u8],
        stamp: &[u8],
    ) -> Result<ValidatedMaterial, Reason> {
        let _validation_guard = match self.validation_lock.try_lock() {
            Ok(guard) => guard,
            Err(TryLockError::Poisoned(err)) => err.into_inner(),
            Err(TryLockError::WouldBlock) => {
                let drops = ReceiverMetrics::increment(&self.metrics.validation_busy_drops);
                debug!(
                    drops,
                    "discovery: announce dropped while stamp validator is busy"
                );
                return Err(Reason::ValidationBusy);
            }
        };

        // Another worker may have completed validation between our initial
        // miss and acquiring the gate.
        match self.cache_lookup(&key) {
            CacheLookup::Valid(material) => return Ok(*material),
            CacheLookup::Invalid => return Err(Reason::StampInvalid),
            CacheLookup::Miss => {}
        }

        let infohash = rns_crypto::sha::full_hash(packed_info);
        if !self
            .config
            .stamper
            .valid(&infohash, stamp, self.config.required_value)
        {
            let evicted = lock_unpoisoned(&self.caches).insert_invalid(key);
            if evicted {
                ReceiverMetrics::increment(&self.metrics.invalid_cache_evictions);
            }
            return Err(Reason::StampInvalid);
        }

        let info = match app_data::decode_info(packed_info) {
            Ok(info) => info,
            Err(err) => {
                trace!(?err, "discovery: info decode failed");
                return Err(Reason::DecodeFailed);
            }
        };
        let material = ValidatedMaterial {
            info,
            stamp: stamp.to_vec(),
            stamp_value: self.config.stamper.value(&infohash, stamp),
        };
        let evicted = lock_unpoisoned(&self.caches).insert_valid(key, material.clone());
        if evicted {
            ReceiverMetrics::increment(&self.metrics.valid_cache_evictions);
        }
        Ok(material)
    }
}

fn lock_unpoisoned<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|err| err.into_inner())
}

/// Spawn the receiver task. Returns the sender to register with
/// `TransportMessage::RegisterAnnounceHandler { aspect_filter:
/// Some("rnstransport.discovery.interface"), callback_tx }` and the
/// [`JoinHandle`] for shutdown.
pub fn spawn(config: ReceiverConfig) -> (JoinHandle<()>, mpsc::Sender<AnnounceHandlerEvent>) {
    let (handle, tx, _metrics) = spawn_with_metrics(config);
    (handle, tx)
}

/// Spawn the receiver and retain a handle to its payload-free operational
/// counters.
pub fn spawn_with_metrics(
    config: ReceiverConfig,
) -> (
    JoinHandle<()>,
    mpsc::Sender<AnnounceHandlerEvent>,
    Arc<ReceiverMetrics>,
) {
    let (tx, mut rx) = mpsc::channel::<AnnounceHandlerEvent>(128);
    let metrics = Arc::new(ReceiverMetrics::default());
    let state = Arc::new(ReceiverState::new(config, metrics.clone()));
    let handle = tokio::spawn(async move {
        let mut workers = JoinSet::new();
        while let Some(event) = rx.recv().await {
            let worker_state = state.clone();
            workers.spawn_blocking(move || {
                let outcome = worker_state.process_event(&event);
                match outcome {
                    Outcome::Accepted => debug!(
                        dest = %hex::encode(event.destination_hash),
                        hops = event.hops,
                        "discovery announce accepted"
                    ),
                    Outcome::Rejected(ref reason) => trace!(
                        dest = %hex::encode(event.destination_hash),
                        ?reason,
                        "discovery announce rejected"
                    ),
                }
            });

            // Keep detached blocking work bounded while still admitting
            // concurrent callbacks. Stamp validation itself is serialized by
            // `validation_lock`; cache hits and persistence can proceed in
            // parallel.
            if workers.len() >= MAX_IN_FLIGHT_EVENTS {
                let _ = workers.join_next().await;
            }
            while workers.try_join_next().is_some() {}
        }

        while workers.join_next().await.is_some() {}
        debug!("discovery receiver task exiting");
    });
    (handle, tx, metrics)
}

fn now_unix() -> u64 {
    crate::now_f64() as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::discovery::app_data::{Encoded, encode_info};
    use crate::discovery::constants::STAMP_SIZE;

    /// Trivial stamper: `generate` returns a zero-filled stamp; `valid`
    /// accepts iff the caller's stamp matches `generate`. Used to drive
    /// receiver tests without pulling LXStamper into rns-transport.
    struct MockStamper {
        ok_stamp: Vec<u8>,
        value: u8,
    }

    impl MockStamper {
        fn new(stamp: Vec<u8>, value: u8) -> Self {
            assert_eq!(stamp.len(), STAMP_SIZE);
            Self {
                ok_stamp: stamp,
                value,
            }
        }
    }

    impl DiscoveryStamper for MockStamper {
        fn generate(&self, _ih: &[u8; 32], _tv: u8) -> Option<Vec<u8>> {
            Some(self.ok_stamp.clone())
        }
        fn value(&self, _ih: &[u8; 32], _s: &[u8]) -> u8 {
            self.value
        }
        fn valid(&self, _ih: &[u8; 32], stamp: &[u8], required: u8) -> bool {
            self.value >= required && stamp == self.ok_stamp.as_slice()
        }
    }

    struct XorDecryptor;
    impl DiscoveryDecryptor for XorDecryptor {
        fn decrypt(&self, ct: &[u8]) -> Option<Vec<u8>> {
            Some(ct.iter().map(|b| b ^ 0xFF).collect())
        }
    }

    struct FailingDecryptor;
    impl DiscoveryDecryptor for FailingDecryptor {
        fn decrypt(&self, _ct: &[u8]) -> Option<Vec<u8>> {
            None
        }
    }

    struct CountingStamper {
        valid_result: bool,
        value: u8,
        valid_calls: AtomicU64,
        value_calls: AtomicU64,
    }

    impl CountingStamper {
        fn new(valid_result: bool, value: u8) -> Self {
            Self {
                valid_result,
                value,
                valid_calls: AtomicU64::new(0),
                value_calls: AtomicU64::new(0),
            }
        }
    }

    impl DiscoveryStamper for CountingStamper {
        fn generate(&self, _ih: &[u8; 32], _tv: u8) -> Option<Vec<u8>> {
            None
        }

        fn value(&self, _ih: &[u8; 32], _stamp: &[u8]) -> u8 {
            self.value_calls.fetch_add(1, Ordering::Relaxed);
            self.value
        }

        fn valid(&self, _ih: &[u8; 32], _stamp: &[u8], _required: u8) -> bool {
            self.valid_calls.fetch_add(1, Ordering::Relaxed);
            self.valid_result
        }
    }

    struct MaskDecryptor {
        mask: u8,
    }

    impl DiscoveryDecryptor for MaskDecryptor {
        fn decrypt(&self, ciphertext: &[u8]) -> Option<Vec<u8>> {
            Some(ciphertext.iter().map(|byte| byte ^ self.mask).collect())
        }
    }

    fn sample_info() -> DiscoveryInfo {
        DiscoveryInfo {
            name: "unit-test-iface".into(),
            transport_id: [0x55; 16],
            interface_type: "BackboneInterface".into(),
            transport_enabled: true,
            latitude: 1.0,
            longitude: 2.0,
            height: 3.0,
            port: Some(4965),
            reachable_on: Some("127.0.0.1".into()),
            ..Default::default()
        }
    }

    fn stamped_blob(info: &DiscoveryInfo, stamp: &[u8]) -> (Vec<u8>, [u8; 32]) {
        let Encoded { packed, infohash } = encode_info(info).unwrap();
        let mut body = packed.clone();
        body.extend_from_slice(stamp);
        let mut out = Vec::with_capacity(1 + body.len());
        out.push(0); // flags
        out.extend_from_slice(&body);
        (out, infohash)
    }

    fn encrypted_blob(info: &DiscoveryInfo, stamp: &[u8]) -> (Vec<u8>, [u8; 32]) {
        let Encoded { packed, infohash } = encode_info(info).unwrap();
        let blob = Encoded { packed, infohash }
            .assemble(
                stamp,
                true,
                false,
                Some(&|pt: &[u8]| Some(pt.iter().map(|b| b ^ 0xFF).collect())),
            )
            .unwrap();
        (blob, infohash)
    }

    fn tmpdir(tag: &str) -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!(
            "reticulum_rs_discovery_recv_{}_{}_{}",
            tag,
            std::process::id(),
            rand::random::<u32>()
        ));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    fn make_cfg(
        stamper: Arc<dyn DiscoveryStamper>,
        store: Arc<DiscoveryStore>,
        sources: Option<Vec<[u8; 16]>>,
        decryptor: Option<Arc<dyn DiscoveryDecryptor>>,
    ) -> ReceiverConfig {
        ReceiverConfig {
            stamper,
            store,
            required_value: 14,
            discovery_sources: sources,
            decryptor,
            observer: None,
        }
    }

    fn event_with(app_data: Vec<u8>) -> AnnounceHandlerEvent {
        AnnounceHandlerEvent {
            destination_hash: [0xAA; 16],
            identity_hash: Some([0x11; 16]),
            announce_packet_hash: [0x22; 32],
            is_path_response: false,
            hops: 3,
            app_data: Some(app_data),
            public_key: None,
            ratchet: None,
            name_hash: [0u8; 10],
        }
    }

    #[test]
    fn accepts_valid_unencrypted_announce() {
        let dir = tmpdir("accept");
        let store = Arc::new(DiscoveryStore::open(&dir).unwrap());
        let stamp = vec![0xAB; STAMP_SIZE];
        let stamper = Arc::new(MockStamper::new(stamp.clone(), 20));
        let info = sample_info();
        let (blob, _ih) = stamped_blob(&info, &stamp);

        let cfg = make_cfg(stamper, store.clone(), None, None);
        let event = event_with(blob);
        assert_eq!(cfg.process_event(&event), Outcome::Accepted);

        let listed = store.list(None).unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].info, info);
        assert_eq!(listed[0].stamp_value, 20);
        assert_eq!(listed[0].hops, 3);
        assert_eq!(listed[0].network_id, [0x11; 16]);
    }

    #[test]
    fn rejects_invalid_stamp() {
        let dir = tmpdir("badstamp");
        let store = Arc::new(DiscoveryStore::open(&dir).unwrap());
        let good = vec![0xAB; STAMP_SIZE];
        let bad = vec![0xCD; STAMP_SIZE];
        let stamper = Arc::new(MockStamper::new(good, 20));
        let info = sample_info();
        let (blob, _) = stamped_blob(&info, &bad);

        let cfg = make_cfg(stamper, store.clone(), None, None);
        assert_eq!(
            cfg.process_event(&event_with(blob)),
            Outcome::Rejected(Reason::StampInvalid)
        );
        assert!(store.list(None).unwrap().is_empty());
    }

    #[test]
    fn rejects_below_required_value() {
        let dir = tmpdir("lowvalue");
        let store = Arc::new(DiscoveryStore::open(&dir).unwrap());
        let stamp = vec![0xAB; STAMP_SIZE];
        // value only 5, required 14
        let stamper = Arc::new(MockStamper::new(stamp.clone(), 5));
        let info = sample_info();
        let (blob, _) = stamped_blob(&info, &stamp);

        let cfg = make_cfg(stamper, store.clone(), None, None);
        assert_eq!(
            cfg.process_event(&event_with(blob)),
            Outcome::Rejected(Reason::StampInvalid)
        );
    }

    #[test]
    fn rejects_missing_app_data() {
        let dir = tmpdir("noapp");
        let store = Arc::new(DiscoveryStore::open(&dir).unwrap());
        let stamper = Arc::new(MockStamper::new(vec![0; STAMP_SIZE], 20));
        let cfg = make_cfg(stamper, store.clone(), None, None);

        let event = AnnounceHandlerEvent {
            destination_hash: [0; 16],
            identity_hash: None,
            announce_packet_hash: [0; 32],
            is_path_response: false,
            hops: 0,
            app_data: None,
            public_key: None,
            ratchet: None,
            name_hash: [0u8; 10],
        };
        assert_eq!(
            cfg.process_event(&event),
            Outcome::Rejected(Reason::MissingAppData)
        );
    }

    #[test]
    fn rejects_malformed_payload() {
        let dir = tmpdir("malformed");
        let store = Arc::new(DiscoveryStore::open(&dir).unwrap());
        let stamper = Arc::new(MockStamper::new(vec![0; STAMP_SIZE], 20));
        let cfg = make_cfg(stamper, store.clone(), None, None);

        // Flag byte present but body too small for a stamp.
        let mut tiny = vec![0u8; 8];
        tiny[0] = 0;
        assert_eq!(
            cfg.process_event(&event_with(tiny)),
            Outcome::Rejected(Reason::Malformed)
        );
    }

    #[test]
    fn rejects_encrypted_without_decryptor() {
        let dir = tmpdir("encnokey");
        let store = Arc::new(DiscoveryStore::open(&dir).unwrap());
        let stamp = vec![0xAB; STAMP_SIZE];
        let stamper = Arc::new(MockStamper::new(stamp.clone(), 20));
        let info = sample_info();
        let (blob, _) = encrypted_blob(&info, &stamp);

        let cfg = make_cfg(stamper, store.clone(), None, None);
        assert_eq!(
            cfg.process_event(&event_with(blob)),
            Outcome::Rejected(Reason::EncryptedWithoutKey)
        );
    }

    #[test]
    fn rejects_decrypt_failure() {
        let dir = tmpdir("decfail");
        let store = Arc::new(DiscoveryStore::open(&dir).unwrap());
        let stamp = vec![0xAB; STAMP_SIZE];
        let stamper = Arc::new(MockStamper::new(stamp.clone(), 20));
        let info = sample_info();
        let (blob, _) = encrypted_blob(&info, &stamp);

        let cfg = make_cfg(
            stamper,
            store.clone(),
            None,
            Some(Arc::new(FailingDecryptor)),
        );
        assert_eq!(
            cfg.process_event(&event_with(blob)),
            Outcome::Rejected(Reason::DecryptFailed)
        );
    }

    #[test]
    fn accepts_encrypted_with_decryptor() {
        let dir = tmpdir("encok");
        let store = Arc::new(DiscoveryStore::open(&dir).unwrap());
        let stamp = vec![0xAB; STAMP_SIZE];
        let stamper = Arc::new(MockStamper::new(stamp.clone(), 20));
        let info = sample_info();
        let (blob, _) = encrypted_blob(&info, &stamp);

        let cfg = make_cfg(stamper, store.clone(), None, Some(Arc::new(XorDecryptor)));
        assert_eq!(cfg.process_event(&event_with(blob)), Outcome::Accepted);
        assert_eq!(store.list(None).unwrap().len(), 1);
    }

    #[test]
    fn rejects_unauthorized_source() {
        let dir = tmpdir("unauth");
        let store = Arc::new(DiscoveryStore::open(&dir).unwrap());
        let stamp = vec![0xAB; STAMP_SIZE];
        let stamper = Arc::new(MockStamper::new(stamp.clone(), 20));
        let mut info = sample_info();
        info.transport_id = [0x55; 16];
        let (blob, _) = stamped_blob(&info, &stamp);

        // Allow list without our source.
        let sources = vec![[0x77; 16]];
        let cfg = make_cfg(stamper, store.clone(), Some(sources), None);
        assert_eq!(
            cfg.process_event(&event_with(blob)),
            Outcome::Rejected(Reason::UnauthorizedSource)
        );
    }

    #[test]
    fn accepts_authorized_source() {
        let dir = tmpdir("auth");
        let store = Arc::new(DiscoveryStore::open(&dir).unwrap());
        let stamp = vec![0xAB; STAMP_SIZE];
        let stamper = Arc::new(MockStamper::new(stamp.clone(), 20));
        let mut info = sample_info();
        info.transport_id = [0x55; 16];
        let (blob, _) = stamped_blob(&info, &stamp);

        let sources = vec![[0x11; 16]];
        let cfg = make_cfg(stamper, store.clone(), Some(sources), None);
        assert_eq!(cfg.process_event(&event_with(blob)), Outcome::Accepted);
    }

    #[test]
    fn rejects_decode_failure() {
        let dir = tmpdir("decode");
        let store = Arc::new(DiscoveryStore::open(&dir).unwrap());
        let stamp = vec![0xAB; STAMP_SIZE];
        // Stamper validates ANY stamp for this test; feed junk bytes as the
        // "info" so the decoder errors.
        struct PermissiveStamper(Vec<u8>);
        impl DiscoveryStamper for PermissiveStamper {
            fn generate(&self, _: &[u8; 32], _: u8) -> Option<Vec<u8>> {
                Some(self.0.clone())
            }
            fn value(&self, _: &[u8; 32], _: &[u8]) -> u8 {
                20
            }
            fn valid(&self, _: &[u8; 32], _: &[u8], _: u8) -> bool {
                true
            }
        }
        let stamper = Arc::new(PermissiveStamper(stamp.clone()));

        // Flags byte + junk info + stamp.
        let mut blob = vec![0u8; 1];
        blob.extend_from_slice(b"not-valid-msgpack");
        blob.extend_from_slice(&stamp);

        let cfg = make_cfg(stamper, store.clone(), None, None);
        assert_eq!(
            cfg.process_event(&event_with(blob)),
            Outcome::Rejected(Reason::DecodeFailed)
        );
    }

    #[test]
    fn observer_receives_on_accept() {
        let dir = tmpdir("obs");
        let store = Arc::new(DiscoveryStore::open(&dir).unwrap());
        let stamp = vec![0xAB; STAMP_SIZE];
        let stamper = Arc::new(MockStamper::new(stamp.clone(), 20));
        let info = sample_info();
        let (blob, _) = stamped_blob(&info, &stamp);

        let (obs_tx, mut obs_rx) = mpsc::channel::<DiscoveredInterface>(4);
        let cfg = ReceiverConfig {
            stamper,
            store: store.clone(),
            required_value: 14,
            discovery_sources: None,
            decryptor: None,
            observer: Some(obs_tx),
        };
        assert_eq!(cfg.process_event(&event_with(blob)), Outcome::Accepted);

        let received = obs_rx.try_recv().expect("observer should receive");
        assert_eq!(received.info.name, "unit-test-iface");
    }

    #[test]
    fn valid_cache_hit_runs_stamper_once() {
        let dir = tmpdir("valid-cache");
        let store = Arc::new(DiscoveryStore::open(&dir).unwrap());
        let stamp = vec![0xAB; STAMP_SIZE];
        let stamper = Arc::new(CountingStamper::new(true, 20));
        let (blob, _) = stamped_blob(&sample_info(), &stamp);
        let metrics = Arc::new(ReceiverMetrics::default());
        let state = ReceiverState::new(
            make_cfg(stamper.clone(), store, None, None),
            metrics.clone(),
        );
        let event = event_with(blob);

        assert_eq!(state.process_event(&event), Outcome::Accepted);
        assert_eq!(state.process_event(&event), Outcome::Accepted);
        assert_eq!(stamper.valid_calls.load(Ordering::Relaxed), 1);
        assert_eq!(stamper.value_calls.load(Ordering::Relaxed), 1);
        assert_eq!(metrics.snapshot().valid_cache_hits, 1);
    }

    #[test]
    fn invalid_cache_hit_runs_stamper_once() {
        let dir = tmpdir("invalid-cache");
        let store = Arc::new(DiscoveryStore::open(&dir).unwrap());
        let stamp = vec![0xAB; STAMP_SIZE];
        let stamper = Arc::new(CountingStamper::new(false, 0));
        let (blob, _) = stamped_blob(&sample_info(), &stamp);
        let metrics = Arc::new(ReceiverMetrics::default());
        let state = ReceiverState::new(
            make_cfg(stamper.clone(), store, None, None),
            metrics.clone(),
        );
        let event = event_with(blob);

        assert_eq!(
            state.process_event(&event),
            Outcome::Rejected(Reason::StampInvalid)
        );
        assert_eq!(
            state.process_event(&event),
            Outcome::Rejected(Reason::StampInvalid)
        );
        assert_eq!(stamper.valid_calls.load(Ordering::Relaxed), 1);
        assert_eq!(stamper.value_calls.load(Ordering::Relaxed), 0);
        assert_eq!(metrics.snapshot().invalid_cache_hits, 1);
    }

    #[test]
    fn validation_caches_evict_fifo() {
        assert_eq!(VALID_CACHE_CAPACITY, 2_048);
        assert_eq!(INVALID_CACHE_CAPACITY, 2_048);

        let material = ValidatedMaterial {
            info: sample_info(),
            stamp: vec![0; STAMP_SIZE],
            stamp_value: 20,
        };
        let one = CacheKey([1; 32]);
        let two = CacheKey([2; 32]);
        let three = CacheKey([3; 32]);

        let mut valid = ValidationCaches::new(2, 2);
        assert!(!valid.insert_valid(one, material.clone()));
        assert!(!valid.insert_valid(two, material.clone()));
        assert!(matches!(valid.lookup(&one), CacheLookup::Valid(_)));
        assert!(valid.insert_valid(three, material));
        assert!(matches!(valid.lookup(&one), CacheLookup::Miss));
        assert!(matches!(valid.lookup(&two), CacheLookup::Valid(_)));
        assert!(matches!(valid.lookup(&three), CacheLookup::Valid(_)));

        let mut invalid = ValidationCaches::new(2, 2);
        assert!(!invalid.insert_invalid(one));
        assert!(!invalid.insert_invalid(two));
        assert!(matches!(invalid.lookup(&one), CacheLookup::Invalid));
        assert!(invalid.insert_invalid(three));
        assert!(matches!(invalid.lookup(&one), CacheLookup::Miss));
        assert!(matches!(invalid.lookup(&two), CacheLookup::Invalid));
        assert!(matches!(invalid.lookup(&three), CacheLookup::Invalid));
    }

    #[test]
    fn busy_validator_drops_without_running_stamper() {
        let dir = tmpdir("busy-drop");
        let store = Arc::new(DiscoveryStore::open(&dir).unwrap());
        let stamp = vec![0xAB; STAMP_SIZE];
        let stamper = Arc::new(CountingStamper::new(true, 20));
        let (blob, _) = stamped_blob(&sample_info(), &stamp);
        let metrics = Arc::new(ReceiverMetrics::default());
        let state = ReceiverState::new(
            make_cfg(stamper.clone(), store, None, None),
            metrics.clone(),
        );
        let validation_guard = state.validation_lock.lock().unwrap();

        assert_eq!(
            state.process_event(&event_with(blob)),
            Outcome::Rejected(Reason::ValidationBusy)
        );
        assert_eq!(stamper.valid_calls.load(Ordering::Relaxed), 0);
        assert_eq!(metrics.snapshot().validation_busy_drops, 1);
        drop(validation_guard);
    }

    #[test]
    fn encrypted_cache_keys_are_isolated_by_decryptor() {
        let dir = tmpdir("encrypted-isolation");
        let store = Arc::new(DiscoveryStore::open(&dir).unwrap());
        let stamp = vec![0xAB; STAMP_SIZE];
        let stamper = Arc::new(MockStamper::new(stamp.clone(), 20));
        let (blob, _) = encrypted_blob(&sample_info(), &stamp);
        let decryptor_a: Arc<dyn DiscoveryDecryptor> = Arc::new(MaskDecryptor { mask: 0xFF });
        let decryptor_b: Arc<dyn DiscoveryDecryptor> = Arc::new(MaskDecryptor { mask: 0xFF });
        let metrics = Arc::new(ReceiverMetrics::default());
        let state = ReceiverState::new(
            make_cfg(stamper, store, None, Some(decryptor_a.clone())),
            metrics,
        );

        let key_a = state.cache_key(&blob, Some(&decryptor_a));
        let key_b = state.cache_key(&blob, Some(&decryptor_b));
        let plain_key = state.cache_key(&blob, None);
        assert_ne!(key_a, key_b);
        assert_ne!(key_a, plain_key);
    }

    #[tokio::test]
    async fn spawn_round_trip() {
        let dir = tmpdir("spawn");
        let store = Arc::new(DiscoveryStore::open(&dir).unwrap());
        let stamp = vec![0xAB; STAMP_SIZE];
        let stamper = Arc::new(MockStamper::new(stamp.clone(), 20));
        let info = sample_info();
        let (blob, _) = stamped_blob(&info, &stamp);

        let cfg = make_cfg(stamper, store.clone(), None, None);
        let (handle, tx) = spawn(cfg);

        tx.send(event_with(blob)).await.unwrap();
        // Drop tx so the task exits cleanly.
        drop(tx);
        // Wait for the task to complete processing + exit.
        handle.await.unwrap();

        let listed = store.list(None).unwrap();
        assert_eq!(listed.len(), 1);
    }
}
