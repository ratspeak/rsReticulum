//! Proof-of-work stamper for discovery announces.
//!
//! [`RnsDiscoveryStamper`] is the stamp construction upstream uses
//! (`self.stamper = RNS.Stamps`, Discovery.py at 1.6.1): a 32-byte stamp over
//! a 20-round workblock of the info hash, with fractional values. Receivers
//! also accept a stamp over the info hash itself, the non-expanded form
//! upstream senders move to. The trait remains so embedders can substitute an
//! implementation; methods are synchronous and callers choose where expensive
//! generation runs.

use std::num::NonZeroUsize;

use rns_identity::stamps::{self, StampControl};

use super::constants::{STAMP_SIZE, WORKBLOCK_EXPAND_ROUNDS};

/// Upstream `POOLING_THRESHOLD_COST`: costs from here on search in parallel.
pub const POOLING_THRESHOLD_COST: f64 = 14.0;

/// Stamp interface consumed by the discovery subsystem.
///
/// Generation may search randomly and return different valid stamps for the
/// same inputs. Validation and value calculation must use the same algorithm:
/// the announcer caches a successful stamp for unchanged info bytes, and
/// receivers must be able to validate it independently.
pub trait DiscoveryStamper: Send + Sync {
    /// Generate a stamp meeting `target_value` for this info hash. Searches
    /// until success; returns `None` when `ctl` cancels or passes its deadline,
    /// or when the value cannot be generated (outside `0..=100`, not finite).
    fn generate(
        &self,
        infohash: &[u8; 32],
        target_value: f64,
        ctl: &StampControl,
    ) -> Option<Vec<u8>>;

    /// Fractional value of the stamp for this info hash.
    fn value(&self, infohash: &[u8; 32], stamp: &[u8]) -> f64;

    /// Whether the stamp meets `required_value` for this info hash.
    fn valid(&self, infohash: &[u8; 32], stamp: &[u8], required_value: f64) -> bool;

    /// The stamp's value when it meets `required_value`, else `None`. The
    /// value can depend on `required_value` when the stamper accepts more than
    /// one workblock.
    fn validate(&self, infohash: &[u8; 32], stamp: &[u8], required_value: f64) -> Option<f64> {
        self.valid(infohash, stamp, required_value)
            .then(|| self.value(infohash, stamp))
    }
}

/// Upstream `RNS.Stamps` discovery construction, built on
/// [`rns_identity::stamps`].
#[derive(Debug, Clone, Copy, Default)]
pub struct RnsDiscoveryStamper;

impl RnsDiscoveryStamper {
    fn workblock(infohash: &[u8; 32]) -> Vec<u8> {
        stamps::stamp_workblock(infohash, WORKBLOCK_EXPAND_ROUNDS)
    }
}

/// Upstream's worker count for a search: one per core up to 12 cores, else
/// half the cores, and a single worker below [`POOLING_THRESHOLD_COST`]
/// (Stamps.py).
pub(crate) fn generation_threads(target_value: f64) -> NonZeroUsize {
    // Upstream compares the fixed-point cost, so 13.999 already pools.
    let pooled = stamps::cost_to_fp(target_value)
        .is_ok_and(|fp| f64::from(fp) >= POOLING_THRESHOLD_COST * f64::from(stamps::COST_FP));
    if !pooled {
        return NonZeroUsize::MIN;
    }
    let cores = std::thread::available_parallelism().map_or(1, NonZeroUsize::get);
    let jobs = if cores <= 12 { cores } else { cores / 2 };
    NonZeroUsize::new(jobs).unwrap_or(NonZeroUsize::MIN)
}

impl DiscoveryStamper for RnsDiscoveryStamper {
    /// Uses `ctl`'s cancel flag and deadline; the worker count follows
    /// `generation_threads`.
    fn generate(
        &self,
        infohash: &[u8; 32],
        target_value: f64,
        ctl: &StampControl,
    ) -> Option<Vec<u8>> {
        let ctl = StampControl {
            threads: generation_threads(target_value),
            ..ctl.clone()
        };
        match stamps::generate_stamp(
            infohash,
            target_value,
            WORKBLOCK_EXPAND_ROUNDS,
            STAMP_SIZE,
            &ctl,
        ) {
            Ok(result) => result.map(|(stamp, _)| stamp),
            Err(error) => {
                tracing::error!(%error, target_value, "cannot generate discovery stamp");
                None
            }
        }
    }

    /// Value over the 20-round workblock, the form this stamper generates.
    fn value(&self, infohash: &[u8; 32], stamp: &[u8]) -> f64 {
        stamps::stamp_value(&Self::workblock(infohash), stamp)
    }

    fn valid(&self, infohash: &[u8; 32], stamp: &[u8], required_value: f64) -> bool {
        self.validate(infohash, stamp, required_value).is_some()
    }

    /// Upstream 1.6.1 order: the non-expanded workblock, then the 20-round
    /// one; the value comes from the workblock that passed.
    fn validate(&self, infohash: &[u8; 32], stamp: &[u8], required_value: f64) -> Option<f64> {
        let passes = |workblock: &[u8]| {
            stamps::stamp_valid(stamp, required_value, workblock).unwrap_or(false)
        };
        if passes(infohash) {
            return Some(stamps::stamp_value(infohash, stamp));
        }
        let workblock = Self::workblock(infohash);
        passes(&workblock).then(|| stamps::stamp_value(&workblock, stamp))
    }
}

/// Disabled stamper: generation always returns `None`, value is always zero,
/// and validation always returns `false`, including at a zero requirement.
pub struct NullStamper;

impl DiscoveryStamper for NullStamper {
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::Ordering;

    fn infohash(seed: &[u8]) -> [u8; 32] {
        rns_crypto::sha::full_hash(seed)
    }

    #[test]
    fn fractional_target_generates_a_stamp_that_meets_it() {
        let ih = infohash(b"fractional");
        let stamp = RnsDiscoveryStamper
            .generate(&ih, 8.5, &StampControl::default())
            .unwrap();
        assert_eq!(stamp.len(), STAMP_SIZE);
        let value = RnsDiscoveryStamper.value(&ih, &stamp);
        assert!(value >= 8.5, "{value}");
        assert!(RnsDiscoveryStamper.valid(&ih, &stamp, 8.5));
        assert!(RnsDiscoveryStamper.valid(&ih, &stamp, value));
        let above = stamps::quantize_cost(value + 1.0 / 256.0).unwrap();
        if above <= stamps::STAMP_COST_CAP {
            assert!(!RnsDiscoveryStamper.valid(&ih, &stamp, above));
        }
    }

    #[test]
    fn cost_zero_returns_a_random_stamp_with_its_real_value() {
        let ih = infohash(b"zero");
        let a = RnsDiscoveryStamper
            .generate(&ih, 0.0, &StampControl::default())
            .unwrap();
        let b = RnsDiscoveryStamper
            .generate(&ih, 0.0, &StampControl::default())
            .unwrap();
        assert_ne!(a, b);
        assert!(RnsDiscoveryStamper.valid(&ih, &a, 0.0));
    }

    #[test]
    fn cancelled_generation_returns_none() {
        let ctl = StampControl::default();
        ctl.cancel.store(true, Ordering::Relaxed);
        assert!(
            RnsDiscoveryStamper
                .generate(&infohash(b"cancel"), 60.0, &ctl)
                .is_none()
        );
    }

    #[test]
    fn value_outside_the_cap_is_not_generated() {
        let ctl = StampControl::default();
        for value in [100.5, -1.0, f64::NAN, f64::INFINITY] {
            assert!(
                RnsDiscoveryStamper
                    .generate(&infohash(b"cap"), value, &ctl)
                    .is_none()
            );
        }
    }

    #[test]
    fn pooling_starts_at_the_upstream_threshold() {
        assert_eq!(generation_threads(13.99).get(), 1);
        assert_eq!(generation_threads(f64::NAN).get(), 1);
        let cores = std::thread::available_parallelism().map_or(1, NonZeroUsize::get);
        let expected = if cores <= 12 { cores } else { cores / 2 };
        assert_eq!(generation_threads(14.0).get(), expected.max(1));
        assert_eq!(generation_threads(13.999).get(), expected.max(1));
    }

    // Upstream 1.6.1 `InterfaceAnnounceHandler.received_announce` verdicts and
    // values; generator in the K1 hand-back (gen_discovery_ne.py).
    const VECTOR_INFOHASH: &str =
        "bbfdbadfc3ed56d93f63b737078eed1ec59bc77d3096864f19f0689a7cc36964";
    const VECTOR_NE_STAMP: &str =
        "2dbee58b18b27cbb784a32d2c6c72c09b9ba53f3a49894e093473980ea4bf25e";
    const VECTOR_EXPANDED_STAMP: &str =
        "009b03b8a5195ee423480e7194f83441e875bbc67d96e46635be9c7c9b1143fe";

    #[test]
    fn both_workblock_forms_validate_as_upstream_reports() {
        let ih: [u8; 32] = hex::decode(VECTOR_INFOHASH).unwrap().try_into().unwrap();
        let ne = hex::decode(VECTOR_NE_STAMP).unwrap();
        let expanded = hex::decode(VECTOR_EXPANDED_STAMP).unwrap();
        let s = RnsDiscoveryStamper;
        assert_eq!(s.validate(&ih, &ne, 8.0), Some(8.265625));
        assert_eq!(s.validate(&ih, &expanded, 8.0), Some(12.15625));
        // At cost 0 the non-expanded check always passes first.
        assert_eq!(s.validate(&ih, &expanded, 0.0), Some(2.29296875));
        assert_eq!(s.validate(&ih, &ne, 8.26953125), None);
        assert!(s.valid(&ih, &ne, 8.0));
        assert!(!s.valid(&ih, &ne, 8.26953125));
    }

    #[test]
    fn short_or_foreign_stamps_do_not_validate_at_a_real_cost() {
        let ih = infohash(b"foreign");
        assert!(!RnsDiscoveryStamper.valid(&ih, &[0xFF; 32], 16.0));
        assert!(!NullStamper.valid(&ih, &[0; 32], 0.0));
    }
}
