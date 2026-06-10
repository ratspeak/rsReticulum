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
//! Runs as a dedicated Tokio task so slow stamp validation does not stall
//! the transport actor loop.

use std::sync::Arc;

use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tracing::{debug, trace, warn};

use crate::messages::AnnounceHandlerEvent;

use super::app_data::{self, DiscoveryInfo};
use super::constants::FLAG_ENCRYPTED;
use super::stamper::DiscoveryStamper;
use super::storage::{DiscoveredInterface, DiscoveryStore};

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
/// [`process_event`] so tests can assert on decisions without needing a
/// live tokio task.
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
    /// Stamp did not meet the required value.
    StampInvalid,
    /// Info map did not decode.
    DecodeFailed,
    /// Source (transport_id) not in the configured discovery_sources list.
    UnauthorizedSource,
    /// Upsert into the on-disk store failed (io error).
    StorageFailed,
}

impl ReceiverConfig {
    /// Classify a single announce event, upsert on accept, emit on observer.
    ///
    /// Synchronous so unit tests can drive it without a task. Returns an
    /// [`Outcome`] describing the decision.
    pub fn process_event(&self, event: &AnnounceHandlerEvent) -> Outcome {
        let Some(raw) = event.app_data.as_ref() else {
            return Outcome::Rejected(Reason::MissingAppData);
        };

        let (flags, body) = match app_data::split_flags(raw) {
            Ok(p) => p,
            Err(_) => return Outcome::Rejected(Reason::Malformed),
        };

        // Decrypt body if FLAG_ENCRYPTED set. We own the bytes once we
        // decrypt, but keep a borrow when unencrypted.
        let decrypted: Vec<u8>;
        let working: &[u8] = if flags & FLAG_ENCRYPTED != 0 {
            let Some(decryptor) = self.decryptor.as_ref() else {
                return Outcome::Rejected(Reason::EncryptedWithoutKey);
            };
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

        let infohash = rns_crypto::sha::full_hash(packed_info);
        if !self.stamper.valid(&infohash, stamp, self.required_value) {
            return Outcome::Rejected(Reason::StampInvalid);
        }

        let info: DiscoveryInfo = match app_data::decode_info(packed_info) {
            Ok(i) => i,
            Err(err) => {
                trace!(?err, "discovery: info decode failed");
                return Outcome::Rejected(Reason::DecodeFailed);
            }
        };

        let announced_identity = event.identity_hash.unwrap_or(info.transport_id);
        if let Some(sources) = self.discovery_sources.as_ref() {
            if !sources.iter().any(|s| s == &announced_identity) {
                return Outcome::Rejected(Reason::UnauthorizedSource);
            }
        }

        let stamp_value = self.stamper.value(&infohash, stamp);
        let now = now_unix();
        let record = DiscoveredInterface {
            info,
            network_id: announced_identity,
            hops: event.hops,
            stamp_value,
            stamp: stamp.to_vec(),
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

/// Spawn the receiver task. Returns the sender to register with
/// `TransportMessage::RegisterAnnounceHandler { aspect_filter:
/// Some("rnstransport.discovery.interface"), callback_tx }` and the
/// [`JoinHandle`] for shutdown.
pub fn spawn(config: ReceiverConfig) -> (JoinHandle<()>, mpsc::Sender<AnnounceHandlerEvent>) {
    let (tx, mut rx) = mpsc::channel::<AnnounceHandlerEvent>(128);
    let handle = tokio::spawn(async move {
        while let Some(event) = rx.recv().await {
            let outcome = config.process_event(&event);
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
        }
        debug!("discovery receiver task exiting");
    });
    (handle, tx)
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
