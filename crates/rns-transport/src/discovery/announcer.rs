//! Discovery publication scheduler, driven by caller-supplied timestamps.
//!
//! Use [`Announcer::prepare`] to obtain app-data, then [`Announcer::commit`]
//! when the caller's required admission condition is met. This module neither
//! sends a packet nor verifies driver admission. The caller supplies the timer,
//! outer signed announce and egress handling. Preparation may synchronously
//! generate proof of work; unchanged info bytes reuse a cached stamp. Run it
//! off async workers, and cancel a search through [`Announcer::stamp_control`].

use std::collections::HashMap;
use std::sync::Arc;

use rns_identity::stamps::{STAMP_COST_CAP, StampControl};
use tracing::{debug, trace};

use crate::messages::InterfaceId;

use super::app_data::{self, DiscoveryInfo, DiscoveryModulation, Encoded};
use super::constants::{
    ANNOUNCE_JOB_INTERVAL_SECS, DEFAULT_STAMP_VALUE, DISCOVERABLE_INTERFACE_TYPES,
    IMPLEMENTATION_NAME, IMPLEMENTATION_VERSION, STAMP_SIZE,
};
use super::stamper::DiscoveryStamper;

/// Per-interface configuration that drives discovery announces.
#[derive(Debug, Clone)]
pub struct DiscoveryInterfaceConfig {
    /// Interface type — must be in [`DISCOVERABLE_INTERFACE_TYPES`].
    pub interface_type: String,
    /// Whether preparation may publish this interface's metadata.
    pub discoverable: bool,
    /// Name advertised in the announce; `None` sends nil, as upstream does
    /// without `discovery_name`.
    pub name: Option<String>,
    /// Advertised routing state; this does not enable transport itself.
    pub transport_enabled: bool,
    /// Minimum seconds after the last successful commit. The backbone helper
    /// uses [`ANNOUNCE_JOB_INTERVAL_SECS`]; zero permits immediate preparation.
    pub announce_interval_secs: u64,
    /// Sender's generation target (`discovery_stamp_value`); 0 means
    /// [`DEFAULT_STAMP_VALUE`] (Discovery.py:134). A value outside `0..=100`
    /// cannot be generated and the interface is not announced. Raising this
    /// through `reconfigure` alone does not invalidate an unchanged stamp.
    pub stamp_value: f64,
    /// Announce and path-request costs required on this interface, advertised
    /// as `DST_COST` / `PR_COST` (Discovery.py:171-172).
    pub dst_cost: Option<f64>,
    pub pr_cost: Option<f64>,
    /// Endpoint address (IP / host / I2P b32) — optional.
    pub reachable_on: Option<String>,
    /// Advertised TCP/Backbone port, if applicable.
    pub port: Option<u16>,
    /// Advertised IFAC network name.
    pub ifac_netname: Option<String>,
    /// Advertised IFAC passphrase. Without discovery-body encryption this is
    /// cleartext in the announce; omit it when it must remain undisclosed.
    pub ifac_netkey: Option<String>,
    /// Radio-link parameters for RNode / KISS / Weave.
    pub frequency: Option<u64>,
    pub bandwidth: Option<u64>,
    pub spreading_factor: Option<u8>,
    pub coding_rate: Option<u8>,
    pub modulation: Option<DiscoveryModulation>,
    pub channel: Option<u16>,
    /// Operator LXMF delivery address, advertised as `OP_ADDR`.
    pub operator_lxmf_address: Option<[u8; 16]>,
    /// Independent optional geolocation (unknown by default).
    pub latitude: Option<f64>,
    pub longitude: Option<f64>,
    pub height: Option<f64>,
    /// Encrypt the info/stamp body and set `FLAG_ENCRYPTED`; the caller must
    /// supply an encryptor to [`Announcer::prepare`] or [`Announcer::tick`].
    pub encrypt: bool,
    /// Set `FLAG_SIGNED` independently of encryption. This flag does not
    /// create a signature; the caller constructs the outer signed announce.
    pub signed: bool,
}

impl DiscoveryInterfaceConfig {
    /// Build discoverable Backbone metadata: transport advertised as enabled,
    /// 60-second interval, stamp target 16, signed flag set and no body
    /// encryption. Optional IFAC, radio and location fields start absent.
    /// This does not open an interface or validate the endpoint.
    pub fn backbone(name: Option<String>, reachable_on: String, port: u16) -> Self {
        Self {
            interface_type: "BackboneInterface".into(),
            discoverable: true,
            name,
            transport_enabled: true,
            announce_interval_secs: ANNOUNCE_JOB_INTERVAL_SECS,
            stamp_value: DEFAULT_STAMP_VALUE,
            dst_cost: None,
            pr_cost: None,
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
            operator_lxmf_address: None,
            latitude: None,
            longitude: None,
            height: None,
            encrypt: false,
            signed: true,
        }
    }

    /// Check only whether the type is in [`DISCOVERABLE_INTERFACE_TYPES`].
    /// This does not check `discoverable`, endpoint fields or runtime support.
    pub fn is_advertisable(&self) -> bool {
        DISCOVERABLE_INTERFACE_TYPES
            .iter()
            .any(|t| *t == self.interface_type)
    }

    /// The value stamps are generated at (Discovery.py:134).
    pub fn effective_stamp_value(&self) -> f64 {
        if self.stamp_value == 0.0 {
            DEFAULT_STAMP_VALUE
        } else {
            self.stamp_value
        }
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

/// Prepared discovery app-data for one interface. The caller still needs to
/// construct and send the outer Reticulum announce.
#[derive(Debug, Clone)]
pub struct AnnounceRequest {
    /// Local interface whose metadata this publication describes.
    pub interface_id: InterfaceId,
    /// Fully assembled `app_data` bytes (flags followed by the optionally
    /// encrypted body).
    pub app_data: Vec<u8>,
    /// Stamp value actually achieved — useful for logging.
    pub stamp_value: f64,
}

/// One cached publication tied to its announcer instance and configuration
/// generation. Clones refer to the same publication; a stale or already
/// committed token cannot advance the current publication's interval.
#[derive(Debug, Clone)]
pub struct PreparedAnnounce {
    owner: Arc<()>,
    request: AnnounceRequest,
    generation: u64,
}

impl PreparedAnnounce {
    /// Read the cached publication bytes and achieved stamp value.
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
    /// Too soon after the last successful commit; remaining seconds truncate
    /// the fractional part of the computed interval.
    RateLimited { remaining_secs: u64 },
    /// Encoding failed, the stamper returned no result (including a cancelled
    /// search), or its stamp had the wrong length.
    StampGenerationFailed,
    /// The effective stamp value is outside `0..=100` or not a number, which
    /// upstream refuses to generate (Stamps.py:255).
    StampValueOutOfRange,
    /// Encryption requested but no encryptor supplied to preparation.
    EncryptorMissing,
    /// Encryptor returned `None` for this payload.
    EncryptionFailed,
}

/// Per-call body encryptor. Return `None` if encryption cannot be performed.
pub type EncryptFn<'a> = &'a dyn Fn(&[u8]) -> Option<Vec<u8>>;

/// Synchronous scheduler with no timer or network I/O. Drive publication with
/// [`Self::prepare`] and [`Self::commit`]; custom stamper/encryptor callbacks
/// may perform expensive work. Supply finite timestamps in one consistent
/// clock domain; they are not validated here.
pub struct Announcer {
    owner: Arc<()>,
    stamper: Arc<dyn DiscoveryStamper>,
    stamp_control: StampControl,
    interfaces: HashMap<InterfaceId, InterfaceAnnounceState>,
    next_generation: u64,
}

impl Announcer {
    /// Create an empty scheduler using the supplied stamp implementation.
    pub fn new(stamper: Arc<dyn DiscoveryStamper>) -> Self {
        Self {
            owner: Arc::new(()),
            stamper,
            stamp_control: StampControl::default(),
            interfaces: HashMap::new(),
            next_generation: 0,
        }
    }

    /// Stop conditions passed to every stamp search. Setting its cancel flag
    /// makes a running and every later search return no stamp.
    pub fn stamp_control(&self) -> &StampControl {
        &self.stamp_control
    }

    /// Register or replace an interface's metadata. `transport_id` is copied
    /// into the advertised info; its relationship to the outer signer is the
    /// caller's responsibility. Replacement clears the success timestamp,
    /// cached stamp and prepared publication, making this entry due immediately.
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

    /// Replace config while keeping the last successful commit time. The new
    /// interval determines when the replacement is due; any prepared token is
    /// invalidated. Returns `false` for an unregistered interface.
    ///
    /// The cached stamp is retained and reused if the encoded info is unchanged.
    /// Since the generation target is not in that info, raising only
    /// `stamp_value` can reuse a lower-work stamp. Use [`Self::register`] to
    /// clear the cache when changing that requirement; it also resets timing.
    pub fn reconfigure(
        &mut self,
        interface_id: InterfaceId,
        config: DiscoveryInterfaceConfig,
    ) -> bool {
        let Some(state) = self.interfaces.get_mut(&interface_id) else {
            return false;
        };
        self.next_generation = self
            .next_generation
            .checked_add(1)
            .expect("discovery generation exhausted");
        state.config = config;
        state.generation = self.next_generation;
        state.prepared = None;
        true
    }

    /// Remove the interface's scheduler state and invalidate its prepared token.
    /// This does not remove an actual network interface.
    pub fn deregister(&mut self, interface_id: InterfaceId) {
        self.interfaces.remove(&interface_id);
    }

    /// Number of registered configs, including entries not marked discoverable.
    pub fn len(&self) -> usize {
        self.interfaces.len()
    }

    /// Whether no interface configs are registered.
    pub fn is_empty(&self) -> bool {
        self.interfaces.is_empty()
    }

    /// Prepare and immediately commit every result before returning it.
    /// No transmission is attempted. Use [`Self::prepare`] and [`Self::commit`]
    /// separately when failed egress must not consume the success interval.
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
    /// Repeated calls return cached bytes, including ciphertext, until commit
    /// or replacement. A different encryptor alone does not replace cached
    /// ciphertext. Keep at most one active dispatch per prepared token.
    ///
    /// Stamp generation and encryption run synchronously here. Returned stamps
    /// are length-checked but not revalidated against the target; the stamper
    /// must honor its contract. Per-interface result ordering is unspecified.
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

            let target_value = state.config.effective_stamp_value();
            if !(0.0..=STAMP_COST_CAP).contains(&target_value) {
                // Upstream consumes the interval before generating, so this is
                // reported once per interval (Discovery.py:110-121).
                state.last_announce_at = Some(now);
                tracing::error!(
                    interface_id = id,
                    target_value,
                    "discovery stamp value cannot be generated, not announcing"
                );
                skips.push((*id, SkipReason::StampValueOutOfRange));
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
                _ => match self
                    .stamper
                    .generate(&infohash, target_value, &self.stamp_control)
                {
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
                name = ?state.config.name,
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

    /// Mark this exact publication successful at `now`. Returns `false` for
    /// another announcer's token, a removed/replaced entry, or a token already
    /// committed. A successful commit clears prepared bytes and advances the
    /// generation while retaining the stamp cache.
    ///
    /// This trusts the caller's admission decision; it does not check driver
    /// queues, dispatch or delivery. The timestamp is stored without validation.
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
        name: cfg.name.clone().unwrap_or_default(),
        transport_id,
        impl_name: Some(IMPLEMENTATION_NAME.to_string()),
        impl_version: Some(IMPLEMENTATION_VERSION.to_string()),
        dst_cost: cfg.dst_cost,
        pr_cost: cfg.pr_cost,
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
        operator_lxmf_address: cfg.operator_lxmf_address,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::discovery::constants::{FLAG_ENCRYPTED, FLAG_SIGNED};
    use rns_identity::stamps::StampControl;

    struct StaticStamper {
        stamp: Vec<u8>,
        value: f64,
    }

    impl DiscoveryStamper for StaticStamper {
        fn generate(&self, _: &[u8; 32], _: f64, _: &StampControl) -> Option<Vec<u8>> {
            Some(self.stamp.clone())
        }
        fn value(&self, _: &[u8; 32], _: &[u8]) -> f64 {
            self.value
        }
        fn valid(&self, _: &[u8; 32], _: &[u8], required: f64) -> bool {
            self.value >= required
        }
    }

    struct RefusingStamper;
    impl DiscoveryStamper for RefusingStamper {
        fn generate(&self, _: &[u8; 32], _: f64, _: &StampControl) -> Option<Vec<u8>> {
            None
        }
        fn value(&self, _: &[u8; 32], _: &[u8]) -> f64 {
            0.0
        }
        fn valid(&self, _: &[u8; 32], _: &[u8], _: f64) -> bool {
            false
        }
    }

    fn sample_backbone() -> DiscoveryInterfaceConfig {
        DiscoveryInterfaceConfig::backbone(Some("relay-a".into()), "10.0.0.1".into(), 4965)
    }

    fn static_stamper() -> Arc<dyn DiscoveryStamper> {
        Arc::new(StaticStamper {
            stamp: vec![0xBB; STAMP_SIZE],
            value: 16.0,
        })
    }

    struct TargetRecorder(std::sync::Mutex<Vec<f64>>);
    impl DiscoveryStamper for TargetRecorder {
        fn generate(&self, _: &[u8; 32], target: f64, _: &StampControl) -> Option<Vec<u8>> {
            self.0.lock().unwrap().push(target);
            Some(vec![0; STAMP_SIZE])
        }
        fn value(&self, _: &[u8; 32], _: &[u8]) -> f64 {
            0.0
        }
        fn valid(&self, _: &[u8; 32], _: &[u8], _: f64) -> bool {
            true
        }
    }

    #[test]
    fn zero_value_generates_at_default_and_fractional_value_is_kept() {
        let recorder = Arc::new(TargetRecorder(Default::default()));
        let mut a = Announcer::new(recorder.clone());
        for (id, value) in [(1, 0.0), (2, 16.5)] {
            let mut cfg = sample_backbone();
            cfg.name = Some(format!("relay-{id}"));
            cfg.stamp_value = value;
            a.register(id, [0x11; 16], cfg);
        }
        a.prepare(0.0, None);
        let mut targets = recorder.0.lock().unwrap().clone();
        targets.sort_by(f64::total_cmp);
        assert_eq!(targets, vec![16.0, 16.5]);
    }

    #[test]
    fn value_above_the_cap_skips_the_interface_without_generating() {
        let recorder = Arc::new(TargetRecorder(Default::default()));
        let mut a = Announcer::new(recorder.clone());
        let mut cfg = sample_backbone();
        cfg.stamp_value = 150.0;
        a.register(1, [0x11; 16], cfg);
        let (prepared, skips) = a.prepare(0.0, None);
        assert!(prepared.is_empty());
        assert_eq!(skips, vec![(1, SkipReason::StampValueOutOfRange)]);
        assert!(recorder.0.lock().unwrap().is_empty());
        // Reported once per announce interval, as upstream does.
        let (_, skips) = a.prepare(1.0, None);
        assert!(matches!(skips[..], [(1, SkipReason::RateLimited { .. })]));
    }

    #[test]
    fn cancelled_control_skips_generation() {
        let mut a = Announcer::new(Arc::new(crate::discovery::stamper::RnsDiscoveryStamper));
        a.stamp_control()
            .cancel
            .store(true, std::sync::atomic::Ordering::Relaxed);
        let mut cfg = sample_backbone();
        cfg.stamp_value = 60.0;
        a.register(1, [0x11; 16], cfg);
        let (prepared, skips) = a.prepare(0.0, None);
        assert!(prepared.is_empty());
        assert_eq!(skips, vec![(1, SkipReason::StampGenerationFailed)]);
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
        assert_eq!(requests[0].stamp_value, 16.0);
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

    /// The announcer names its own stack and version, as Python names "RNS"
    /// and its `__version__` (Discovery.py:46-47, :173-174).
    #[test]
    fn announces_name_the_rust_implementation_and_its_version() {
        let mut a = Announcer::new(static_stamper());
        a.register(1, [0x11; 16], sample_backbone());
        let (requests, _) = a.tick(1000.0, None);
        let (_, body) = app_data::split_flags(&requests[0].app_data).unwrap();
        let (info_bytes, _) = app_data::split_stamp(body).unwrap();
        let info = app_data::decode_info(info_bytes).unwrap();
        assert_eq!(info.impl_name.as_deref(), Some("rsRNS"));
        assert_eq!(
            info.impl_version.as_deref(),
            Some(env!("CARGO_PKG_VERSION"))
        );
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

    /// A new address waits for the interval like any other change, so an
    /// address that keeps changing cannot make the interface announce early.
    #[test]
    fn a_reconfigured_interface_keeps_its_announce_interval() {
        let mut a = Announcer::new(static_stamper());
        let mut config = sample_backbone();
        a.register(1, [0x11; 16], config.clone());
        assert_eq!(a.tick(1000.0, None).0.len(), 1);
        config.reachable_on = Some("10.0.0.2".into());
        assert!(a.reconfigure(1, config));
        assert!(!a.reconfigure(2, sample_backbone()));
        assert!(a.tick(1001.0, None).0.is_empty());

        let interval = sample_backbone().announce_interval_secs as f64;
        let (requests, _) = a.tick(1000.0 + interval + 1.0, None);
        let body = &requests[0].app_data[1..];
        let (info, _) = app_data::split_stamp(body).unwrap();
        assert_eq!(
            app_data::decode_info(info).unwrap().reachable_on.as_deref(),
            Some("10.0.0.2")
        );
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
            fn generate(&self, _: &[u8; 32], _: f64, _: &StampControl) -> Option<Vec<u8>> {
                *self.count.lock().unwrap() += 1;
                Some(self.stamp.clone())
            }
            fn value(&self, _: &[u8; 32], _: &[u8]) -> f64 {
                16.0
            }
            fn valid(&self, _: &[u8; 32], _: &[u8], _: f64) -> bool {
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
            fn generate(&self, _: &[u8; 32], _: f64, _: &StampControl) -> Option<Vec<u8>> {
                *self.count.lock().unwrap() += 1;
                Some(self.stamp.clone())
            }
            fn value(&self, _: &[u8; 32], _: &[u8]) -> f64 {
                16.0
            }
            fn valid(&self, _: &[u8; 32], _: &[u8], _: f64) -> bool {
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
        cfg.name = Some("relay-a-renamed".into());
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
        cfg1.name = Some("a".into());
        let mut cfg2 = sample_backbone();
        cfg2.name = Some("b".into());
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
