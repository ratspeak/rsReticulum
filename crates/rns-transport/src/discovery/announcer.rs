//! Periodic discovery announce scheduler. Pure-data: `tick(now)` returns
//! one [`AnnounceRequest`] per due interface. Runtime owners use `prepare` and
//! `commit` to advance the interval only after driver admission. The runtime owns the timer +
//! identity-signed emit. Memoises `(infohash, stamp)` per interface so an
//! unchanged info doesn't redo PoW.

use std::collections::HashMap;
use std::sync::Arc;

use tracing::{debug, trace};

use crate::messages::InterfaceId;

use super::app_data::{self, DiscoveryInfo, Encoded};
use super::constants::{
    ANNOUNCE_JOB_INTERVAL_SECS, DEFAULT_STAMP_VALUE, DISCOVERABLE_INTERFACE_TYPES, STAMP_SIZE,
};
use super::stamper::DiscoveryStamper;

/// Per-interface configuration that drives discovery announces.
#[derive(Debug, Clone)]
pub struct DiscoveryInterfaceConfig {
    /// Interface type — must be in [`DISCOVERABLE_INTERFACE_TYPES`].
    pub interface_type: String,
    pub discoverable: bool,
    /// Name advertised in the announce.
    pub name: String,
    pub transport_enabled: bool,
    /// Seconds between announces; defaults to [`ANNOUNCE_JOB_INTERVAL_SECS`].
    pub announce_interval_secs: u64,
    /// Stamp target value required by the receiver; defaults to [`DEFAULT_STAMP_VALUE`].
    pub stamp_value: u8,
    /// Endpoint address (IP / host / I2P b32) — optional.
    pub reachable_on: Option<String>,
    /// TCP/Backbone bind port, if applicable.
    pub port: Option<u16>,
    /// IFAC virtual-network overlay (name / key).
    pub ifac_netname: Option<String>,
    pub ifac_netkey: Option<String>,
    /// Radio-link parameters for RNode / KISS / Weave.
    pub frequency: Option<u64>,
    pub bandwidth: Option<u64>,
    pub spreading_factor: Option<u8>,
    pub coding_rate: Option<u8>,
    pub modulation: Option<String>,
    pub channel: Option<u16>,
    /// Independent optional geolocation (unknown by default).
    pub latitude: Option<f64>,
    pub longitude: Option<f64>,
    pub height: Option<f64>,
    /// Set the `FLAG_ENCRYPTED` bit; caller supplies `encrypt` closure at
    /// announce time via [`Announcer::tick`].
    pub encrypt: bool,
    /// Set the `FLAG_SIGNED` bit (independent of `encrypt`).
    pub signed: bool,
}

impl DiscoveryInterfaceConfig {
    /// Minimal config: discoverable backbone interface with default
    /// stamp + interval.
    pub fn backbone(name: String, reachable_on: String, port: u16) -> Self {
        Self {
            interface_type: "BackboneInterface".into(),
            discoverable: true,
            name,
            transport_enabled: true,
            announce_interval_secs: ANNOUNCE_JOB_INTERVAL_SECS,
            stamp_value: DEFAULT_STAMP_VALUE,
            reachable_on: Some(reachable_on),
            port: Some(port),
            ifac_netname: None,
            ifac_netkey: None,
            frequency: None,
            bandwidth: None,
            spreading_factor: None,
            coding_rate: None,
            modulation: None,
            channel: None,
            latitude: None,
            longitude: None,
            height: None,
            encrypt: false,
            signed: true,
        }
    }

    /// True iff `interface_type` is in [`DISCOVERABLE_INTERFACE_TYPES`].
    pub fn is_advertisable(&self) -> bool {
        DISCOVERABLE_INTERFACE_TYPES
            .iter()
            .any(|t| *t == self.interface_type)
    }
}

/// Per-interface running state (last-announce timestamp + stamp cache).
#[derive(Debug, Clone)]
struct InterfaceAnnounceState {
    config: DiscoveryInterfaceConfig,
    transport_id: [u8; 16],
    last_announce_at: Option<f64>,
    generation: u64,
    prepared: Option<PreparedAnnounce>,
    /// Cached `(infohash, stamp)` pair so a repeat announce doesn't
    /// redo proof-of-work when the info map is unchanged.
    stamp_cache: Option<([u8; 32], Vec<u8>)>,
}

/// One "interface wants to announce now" output from [`Announcer::tick`].
#[derive(Debug, Clone)]
pub struct AnnounceRequest {
    pub interface_id: InterfaceId,
    /// Fully assembled `app_data` bytes (flags followed by the optionally
    /// encrypted body).
    pub app_data: Vec<u8>,
    /// Stamp value actually achieved — useful for logging.
    pub stamp_value: u8,
}

/// One cached publication for an exact registered configuration. Its opaque
/// generation prevents a late admission from committing a replaced interface.
#[derive(Debug, Clone)]
pub struct PreparedAnnounce {
    owner: Arc<()>,
    request: AnnounceRequest,
    generation: u64,
}

impl PreparedAnnounce {
    pub fn request(&self) -> &AnnounceRequest {
        &self.request
    }
}

/// Why an interface was skipped on a given tick.
#[derive(Debug, Clone, PartialEq)]
pub enum SkipReason {
    /// `discoverable = false`.
    NotDiscoverable,
    /// Interface type not in [`DISCOVERABLE_INTERFACE_TYPES`].
    TypeNotAdvertisable,
    /// Too soon after the last announce.
    RateLimited { remaining_secs: u64 },
    /// Stamper refused to generate (LXStamper cancelled or missing key).
    StampGenerationFailed,
    /// `FLAG_ENCRYPTED` requested but no encryptor supplied to `tick`.
    EncryptorMissing,
    /// Encryptor returned `None` for this payload.
    EncryptionFailed,
}

/// Optional encryptor closure; the announcer holds no identity material.
pub type EncryptFn<'a> = &'a dyn Fn(&[u8]) -> Option<Vec<u8>>;

/// Pure-data scheduler. Not async, holds no timer — drive via `tick`.
pub struct Announcer {
    owner: Arc<()>,
    stamper: Arc<dyn DiscoveryStamper>,
    interfaces: HashMap<InterfaceId, InterfaceAnnounceState>,
    next_generation: u64,
}

impl Announcer {
    pub fn new(stamper: Arc<dyn DiscoveryStamper>) -> Self {
        Self {
            owner: Arc::new(()),
            stamper,
            interfaces: HashMap::new(),
            next_generation: 0,
        }
    }

    /// Register (or replace) an interface's discovery config.
    /// `transport_id` = 16-byte identity hash carried in `TRANSPORT_ID`.
    pub fn register(
        &mut self,
        interface_id: InterfaceId,
        transport_id: [u8; 16],
        config: DiscoveryInterfaceConfig,
    ) {
        self.next_generation = self
            .next_generation
            .checked_add(1)
            .expect("discovery generation exhausted");
        self.interfaces.insert(
            interface_id,
            InterfaceAnnounceState {
                config,
                transport_id,
                last_announce_at: None,
                generation: self.next_generation,
                prepared: None,
                stamp_cache: None,
            },
        );
    }

    /// Drop an interface from the announcer (called on deregister).
    pub fn deregister(&mut self, interface_id: InterfaceId) {
        self.interfaces.remove(&interface_id);
    }

    /// Inspect registered interfaces (for tests / introspection).
    pub fn len(&self) -> usize {
        self.interfaces.len()
    }

    pub fn is_empty(&self) -> bool {
        self.interfaces.is_empty()
    }

    /// Compatibility convenience: prepare and immediately commit every result.
    /// Runtime publishers should use [`Self::prepare`] and [`Self::commit`] so
    /// a failed egress does not consume the success interval.
    pub fn tick(
        &mut self,
        now: f64,
        encrypt: Option<EncryptFn<'_>>,
    ) -> (Vec<AnnounceRequest>, Vec<(InterfaceId, SkipReason)>) {
        let (prepared, skips) = self.prepare(now, encrypt);
        let requests = prepared
            .into_iter()
            .map(|prepared| {
                self.commit(&prepared, now);
                prepared.request
            })
            .collect();
        (requests, skips)
    }

    /// Prepare due publications without advancing their success interval.
    /// Repeated calls return the same bytes (including ciphertext) until commit
    /// or replacement; callers keep at most one dispatch per prepared result.
    pub fn prepare(
        &mut self,
        now: f64,
        encrypt: Option<EncryptFn<'_>>,
    ) -> (Vec<PreparedAnnounce>, Vec<(InterfaceId, SkipReason)>) {
        let mut out = Vec::new();
        let mut skips = Vec::new();

        for (id, state) in self.interfaces.iter_mut() {
            if !state.config.discoverable {
                skips.push((*id, SkipReason::NotDiscoverable));
                continue;
            }
            if !state.config.is_advertisable() {
                skips.push((*id, SkipReason::TypeNotAdvertisable));
                continue;
            }

            let interval = state.config.announce_interval_secs as f64;
            let elapsed = state.last_announce_at.map(|last| now - last);
            if let Some(elapsed) = elapsed.filter(|elapsed| *elapsed < interval) {
                let remaining_secs = (interval - elapsed).max(0.0) as u64;
                skips.push((*id, SkipReason::RateLimited { remaining_secs }));
                continue;
            }

            if let Some(prepared) = &state.prepared {
                out.push(prepared.clone());
                continue;
            }

            let info = config_to_info(&state.config, state.transport_id);
            let Ok(Encoded { packed, infohash }) = app_data::encode_info(&info) else {
                skips.push((*id, SkipReason::StampGenerationFailed));
                continue;
            };

            // Reuse cached stamp if the infohash is unchanged.
            let stamp = match &state.stamp_cache {
                Some((cached_ih, cached_stamp)) if cached_ih == &infohash => cached_stamp.clone(),
                _ => match self.stamper.generate(&infohash, state.config.stamp_value) {
                    Some(s) if s.len() == STAMP_SIZE => s,
                    _ => {
                        skips.push((*id, SkipReason::StampGenerationFailed));
                        continue;
                    }
                },
            };

            // Cache work before encryption as well: a missing key must not
            // make the next preparation repeat proof-of-work.
            state.stamp_cache = Some((infohash, stamp.clone()));
            let encoded = Encoded {
                packed: packed.clone(),
                infohash,
            };
            let flag_encrypted = state.config.encrypt;
            let flag_signed = state.config.signed;
            let blob = if flag_encrypted {
                let Some(enc) = encrypt else {
                    skips.push((*id, SkipReason::EncryptorMissing));
                    continue;
                };
                match encoded.assemble(&stamp, true, flag_signed, Some(enc)) {
                    Some(b) => b,
                    None => {
                        skips.push((*id, SkipReason::EncryptionFailed));
                        continue;
                    }
                }
            } else {
                match encoded.assemble(&stamp, false, flag_signed, None) {
                    Some(b) => b,
                    None => {
                        skips.push((*id, SkipReason::StampGenerationFailed));
                        continue;
                    }
                }
            };

            let stamp_value = self.stamper.value(&infohash, &stamp);
            trace!(
                interface_id = id,
                name = %state.config.name,
                stamp_value,
                "discovery announce prepared"
            );

            let prepared = PreparedAnnounce {
                owner: self.owner.clone(),
                request: AnnounceRequest {
                    interface_id: *id,
                    app_data: blob,
                    stamp_value,
                },
                generation: state.generation,
            };
            state.prepared = Some(prepared.clone());
            out.push(prepared);
        }

        debug!(
            due = out.len(),
            skipped = skips.len(),
            registered = self.interfaces.len(),
            "discovery announcer tick"
        );
        (out, skips)
    }

    /// Record first actual driver admission for this exact publication.
    /// A duplicate or replaced-generation result cannot restart the interval.
    pub fn commit(&mut self, prepared: &PreparedAnnounce, now: f64) -> bool {
        let Some(state) = self.interfaces.get_mut(&prepared.request.interface_id) else {
            return false;
        };
        if !Arc::ptr_eq(&self.owner, &prepared.owner)
            || state.generation != prepared.generation
            || state.prepared.is_none()
        {
            return false;
        }
        state.last_announce_at = Some(now);
        state.prepared = None;
        // A new publication, even with unchanged information, gets a new token.
        self.next_generation = self
            .next_generation
            .checked_add(1)
            .expect("discovery generation exhausted");
        state.generation = self.next_generation;
        true
    }
}

fn config_to_info(cfg: &DiscoveryInterfaceConfig, transport_id: [u8; 16]) -> DiscoveryInfo {
    DiscoveryInfo {
        name: cfg.name.clone(),
        transport_id,
        interface_type: cfg.interface_type.clone(),
        transport_enabled: cfg.transport_enabled,
        reachable_on: cfg.reachable_on.clone(),
        latitude: cfg.latitude,
        longitude: cfg.longitude,
        height: cfg.height,
        port: cfg.port,
        ifac_netname: cfg.ifac_netname.clone(),
        ifac_netkey: cfg.ifac_netkey.clone(),
        frequency: cfg.frequency,
        bandwidth: cfg.bandwidth,
        spreading_factor: cfg.spreading_factor,
        coding_rate: cfg.coding_rate,
        modulation: cfg.modulation.clone(),
        channel: cfg.channel,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::discovery::constants::{FLAG_ENCRYPTED, FLAG_SIGNED};

    struct StaticStamper {
        stamp: Vec<u8>,
        value: u8,
    }

    impl DiscoveryStamper for StaticStamper {
        fn generate(&self, _: &[u8; 32], _: u8) -> Option<Vec<u8>> {
            Some(self.stamp.clone())
        }
        fn value(&self, _: &[u8; 32], _: &[u8]) -> u8 {
            self.value
        }
        fn valid(&self, _: &[u8; 32], _: &[u8], required: u8) -> bool {
            self.value >= required
        }
    }

    struct RefusingStamper;
    impl DiscoveryStamper for RefusingStamper {
        fn generate(&self, _: &[u8; 32], _: u8) -> Option<Vec<u8>> {
            None
        }
        fn value(&self, _: &[u8; 32], _: &[u8]) -> u8 {
            0
        }
        fn valid(&self, _: &[u8; 32], _: &[u8], _: u8) -> bool {
            false
        }
    }

    fn sample_backbone() -> DiscoveryInterfaceConfig {
        DiscoveryInterfaceConfig::backbone("relay-a".into(), "10.0.0.1".into(), 4965)
    }

    fn static_stamper() -> Arc<dyn DiscoveryStamper> {
        Arc::new(StaticStamper {
            stamp: vec![0xBB; STAMP_SIZE],
            value: 16,
        })
    }

    #[test]
    fn preparation_retries_exact_bytes_until_admission_and_rejects_stale_commit() {
        let mut a = Announcer::new(static_stamper());
        let mut cfg = sample_backbone();
        cfg.encrypt = true;
        cfg.announce_interval_secs = 6 * 60 * 60;
        a.register(1, [0x11; 16], cfg.clone());
        let encrypted = std::cell::Cell::new(0);
        let encrypt = |pt: &[u8]| {
            encrypted.set(encrypted.get() + 1);
            Some(pt.to_vec())
        };
        let first = a.prepare(0.0, Some(&encrypt)).0.remove(0);
        let mut unrelated = Announcer::new(static_stamper());
        unrelated.register(1, [0x11; 16], cfg.clone());
        unrelated.prepare(0.0, Some(&|pt| Some(pt.to_vec())));
        assert!(
            !unrelated.commit(&first, 1.0),
            "tokens belong to one scheduler"
        );
        let retry = a.prepare(2.0, Some(&encrypt)).0.remove(0);
        assert_eq!(first.request().app_data, retry.request().app_data);
        assert_eq!(encrypted.get(), 1, "retries retain exact ciphertext");
        assert!(a.commit(&retry, 2.0));
        assert!(
            !a.commit(&first, 3.0),
            "late duplicate cannot restart interval"
        );
        assert!(a.prepare(3.0, Some(&encrypt)).0.is_empty());
        let next = a.prepare(21603.0, Some(&encrypt)).0.remove(0);
        cfg.latitude = Some(0.0);
        a.register(1, [0x11; 16], cfg);
        assert!(
            !a.commit(&next, 21604.0),
            "old config cannot consume new interval"
        );
        let replaced = a.prepare(21604.0, Some(&encrypt)).0.remove(0);
        assert_ne!(next.request().app_data, replaced.request().app_data);
        a.deregister(1);
        assert!(!a.commit(&replaced, 21605.0));
    }

    #[test]
    fn empty_tick_emits_nothing() {
        let mut a = Announcer::new(static_stamper());
        let (requests, skips) = a.tick(1000.0, None);
        assert!(requests.is_empty());
        assert!(skips.is_empty());
    }

    #[test]
    fn first_tick_emits_announce() {
        let mut a = Announcer::new(static_stamper());
        a.register(1, [0x11; 16], sample_backbone());
        let (requests, skips) = a.tick(1000.0, None);
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].interface_id, 1);
        assert_eq!(requests[0].stamp_value, 16);
        assert!(skips.is_empty());

        // Verify the blob round-trips.
        let (flags, body) = app_data::split_flags(&requests[0].app_data).unwrap();
        assert_eq!(flags & FLAG_SIGNED, FLAG_SIGNED);
        assert_eq!(flags & FLAG_ENCRYPTED, 0);
        let (info_bytes, stamp) = app_data::split_stamp(body).unwrap();
        assert_eq!(stamp, &[0xBB; STAMP_SIZE]);
        let info = app_data::decode_info(info_bytes).unwrap();
        assert_eq!(info.name, "relay-a");
        assert_eq!(info.transport_id, [0x11; 16]);
        assert_eq!(info.port, Some(4965));
    }

    #[test]
    fn subsequent_tick_within_interval_skips() {
        let mut a = Announcer::new(static_stamper());
        a.register(1, [0x11; 16], sample_backbone());
        let _ = a.tick(1000.0, None);
        let (requests, skips) = a.tick(1005.0, None);
        assert!(requests.is_empty());
        assert_eq!(skips.len(), 1);
        assert!(matches!(skips[0].1, SkipReason::RateLimited { .. }));
    }

    #[test]
    fn tick_after_interval_re_emits() {
        let mut a = Announcer::new(static_stamper());
        a.register(1, [0x11; 16], sample_backbone());
        let _ = a.tick(1000.0, None);
        let (requests, _) = a.tick(1000.0 + (ANNOUNCE_JOB_INTERVAL_SECS as f64) + 1.0, None);
        assert_eq!(requests.len(), 1);
    }

    #[test]
    fn non_discoverable_is_skipped() {
        let mut a = Announcer::new(static_stamper());
        let mut cfg = sample_backbone();
        cfg.discoverable = false;
        a.register(1, [0x11; 16], cfg);
        let (requests, skips) = a.tick(1000.0, None);
        assert!(requests.is_empty());
        assert_eq!(skips.len(), 1);
        assert_eq!(skips[0].1, SkipReason::NotDiscoverable);
    }

    #[test]
    fn unadvertisable_type_is_skipped() {
        let mut a = Announcer::new(static_stamper());
        let mut cfg = sample_backbone();
        cfg.interface_type = "LocalInterface".into(); // not in DISCOVERABLE_INTERFACE_TYPES
        a.register(1, [0x11; 16], cfg);
        let (requests, skips) = a.tick(1000.0, None);
        assert!(requests.is_empty());
        assert_eq!(skips[0].1, SkipReason::TypeNotAdvertisable);
    }

    #[test]
    fn stamper_refusal_is_skipped() {
        let mut a = Announcer::new(Arc::new(RefusingStamper));
        a.register(1, [0x11; 16], sample_backbone());
        let (requests, skips) = a.tick(1000.0, None);
        assert!(requests.is_empty());
        assert_eq!(skips[0].1, SkipReason::StampGenerationFailed);
    }

    #[test]
    fn stamp_is_cached_across_ticks() {
        // Count generate() calls — second tick with unchanged info must
        // reuse the cached stamp.
        struct CountingStamper {
            count: std::sync::Mutex<u32>,
            stamp: Vec<u8>,
        }
        impl DiscoveryStamper for CountingStamper {
            fn generate(&self, _: &[u8; 32], _: u8) -> Option<Vec<u8>> {
                *self.count.lock().unwrap() += 1;
                Some(self.stamp.clone())
            }
            fn value(&self, _: &[u8; 32], _: &[u8]) -> u8 {
                16
            }
            fn valid(&self, _: &[u8; 32], _: &[u8], _: u8) -> bool {
                true
            }
        }
        let stamper = Arc::new(CountingStamper {
            count: std::sync::Mutex::new(0),
            stamp: vec![0xCC; STAMP_SIZE],
        });
        let count_probe = Arc::clone(&stamper);
        let mut a = Announcer::new(stamper);
        a.register(1, [0x11; 16], sample_backbone());

        let _ = a.tick(1000.0, None);
        let _ = a.tick(2000.0, None);
        let _ = a.tick(3000.0, None);
        assert_eq!(*count_probe.count.lock().unwrap(), 1);

        let mut encrypted = sample_backbone();
        encrypted.encrypt = true;
        a.register(1, [0x11; 16], encrypted);
        assert_eq!(a.prepare(4000.0, None).1[0].1, SkipReason::EncryptorMissing);
        assert_eq!(a.prepare(4060.0, None).1[0].1, SkipReason::EncryptorMissing);
        assert_eq!(
            *count_probe.count.lock().unwrap(),
            2,
            "missing encryption key retains completed work"
        );
    }

    #[test]
    fn config_change_invalidates_stamp_cache() {
        // If the caller re-registers with a different info, the stamp
        // must be regenerated (infohash changed).
        struct CountingStamper {
            count: std::sync::Mutex<u32>,
            stamp: Vec<u8>,
        }
        impl DiscoveryStamper for CountingStamper {
            fn generate(&self, _: &[u8; 32], _: u8) -> Option<Vec<u8>> {
                *self.count.lock().unwrap() += 1;
                Some(self.stamp.clone())
            }
            fn value(&self, _: &[u8; 32], _: &[u8]) -> u8 {
                16
            }
            fn valid(&self, _: &[u8; 32], _: &[u8], _: u8) -> bool {
                true
            }
        }
        let stamper = Arc::new(CountingStamper {
            count: std::sync::Mutex::new(0),
            stamp: vec![0xDD; STAMP_SIZE],
        });
        let count_probe = Arc::clone(&stamper);
        let mut a = Announcer::new(stamper);
        a.register(1, [0x11; 16], sample_backbone());
        let _ = a.tick(1000.0, None);
        assert_eq!(*count_probe.count.lock().unwrap(), 1);

        // Re-register with a new name — different infohash.
        let mut cfg = sample_backbone();
        cfg.name = "relay-a-renamed".into();
        a.register(1, [0x11; 16], cfg);
        let _ = a.tick(2000.0 + ANNOUNCE_JOB_INTERVAL_SECS as f64, None);
        assert_eq!(*count_probe.count.lock().unwrap(), 2);
    }

    #[test]
    fn encrypt_true_without_encryptor_skips() {
        let mut a = Announcer::new(static_stamper());
        let mut cfg = sample_backbone();
        cfg.encrypt = true;
        a.register(1, [0x11; 16], cfg);
        let (requests, skips) = a.tick(1000.0, None);
        assert!(requests.is_empty());
        assert_eq!(skips[0].1, SkipReason::EncryptorMissing);
    }

    #[test]
    fn encrypt_true_with_encryptor_succeeds() {
        let mut a = Announcer::new(static_stamper());
        let mut cfg = sample_backbone();
        cfg.encrypt = true;
        a.register(1, [0x11; 16], cfg);
        let xor: &dyn Fn(&[u8]) -> Option<Vec<u8>> =
            &|pt: &[u8]| Some(pt.iter().map(|b| b ^ 0xFF).collect());
        let (requests, _) = a.tick(1000.0, Some(xor));
        assert_eq!(requests.len(), 1);
        let (flags, _) = app_data::split_flags(&requests[0].app_data).unwrap();
        assert_eq!(flags & FLAG_ENCRYPTED, FLAG_ENCRYPTED);
    }

    #[test]
    fn deregister_drops_interface() {
        let mut a = Announcer::new(static_stamper());
        a.register(1, [0x11; 16], sample_backbone());
        assert_eq!(a.len(), 1);
        a.deregister(1);
        assert!(a.is_empty());

        let (requests, skips) = a.tick(1000.0, None);
        assert!(requests.is_empty());
        assert!(skips.is_empty());
    }

    #[test]
    fn multiple_interfaces_each_tick_independently() {
        let mut a = Announcer::new(static_stamper());
        let mut cfg1 = sample_backbone();
        cfg1.name = "a".into();
        let mut cfg2 = sample_backbone();
        cfg2.name = "b".into();
        cfg2.announce_interval_secs = 30; // shorter interval
        a.register(1, [0x11; 16], cfg1);
        a.register(2, [0x22; 16], cfg2);

        let (first, _) = a.tick(1000.0, None);
        assert_eq!(first.len(), 2);

        // Only the shorter-interval interface is due at +40s.
        let (second, skips) = a.tick(1040.0, None);
        assert_eq!(second.len(), 1);
        assert_eq!(second[0].interface_id, 2);
        assert!(matches!(skips[0].1, SkipReason::RateLimited { .. }));
    }
}
