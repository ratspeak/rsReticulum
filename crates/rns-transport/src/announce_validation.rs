//! The announce validation caches (Identity.py).

use std::collections::{HashMap, VecDeque};

use rns_identity::stamps::{NETWORK_STAMP_SIZE, cost_to_fp};

const VALID_CACHE_MAX: usize = 384;
const INVALID_CACHE_MAX: usize = 384;

/// Why an announce was rejected, as upstream signals it.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum InvalidAnnounce {
    NoStamp,
    /// Carries the stamp value so a cheaper interface can re-validate it.
    InvalidStamp(Option<f64>),
    Blackholed,
    /// Signature, binding or key-continuity failure.
    Invalid,
}

/// The fields upstream keeps in its validation result.
#[derive(Debug, Clone)]
pub struct ValidatedAnnounce {
    pub public_key: [u8; 64],
    /// Truncated hash of `public_key`, kept so a cache hit needs no key decoding.
    pub identity_hash: [u8; 16],
    pub app_data: Option<Vec<u8>>,
    // Upstream keeps it in the validation result; nothing reads it here yet.
    #[allow(dead_code)]
    pub ratchet: Option<[u8; 32]>,
    pub stamp: Option<[u8; NETWORK_STAMP_SIZE]>,
    pub stamp_value: Option<f64>,
    pub lr_cost: Option<f64>,
}

/// What a cache lookup decides for one received copy.
#[derive(Debug, Clone)]
pub enum CachedAnnounce {
    /// Not cached, or a cached `invalid_stamp` that may pass on this interface.
    Miss,
    Rejected(InvalidAnnounce),
    Valid(ValidatedAnnounce),
}

/// Insertion-ordered maps keyed by announce packet hash.
#[derive(Debug, Default)]
pub struct AnnounceValidationCache {
    valid: HashMap<[u8; 32], ValidatedAnnounce>,
    valid_order: VecDeque<[u8; 32]>,
    invalid: HashMap<[u8; 32], InvalidAnnounce>,
    invalid_order: VecDeque<[u8; 32]>,
}

fn below(cost_target: f64, value: f64) -> bool {
    match (cost_to_fp(cost_target), cost_to_fp(value)) {
        (Ok(target), Ok(value)) => target > value,
        _ => true,
    }
}

impl AnnounceValidationCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// Identity.py.
    pub fn lookup(
        &self,
        packet_hash: &[u8; 32],
        cost_target: f64,
        enforced: bool,
    ) -> CachedAnnounce {
        if let Some(invalid) = self.invalid.get(packet_hash) {
            match *invalid {
                InvalidAnnounce::InvalidStamp(Some(value)) => {
                    if below(cost_target, value) {
                        return CachedAnnounce::Rejected(*invalid);
                    }
                }
                InvalidAnnounce::InvalidStamp(None) => {
                    return CachedAnnounce::Rejected(InvalidAnnounce::Invalid);
                }
                other => return CachedAnnounce::Rejected(other),
            }
        }
        if let Some(valid) = self.valid.get(packet_hash) {
            if enforced {
                match valid.stamp_value {
                    None => return CachedAnnounce::Rejected(InvalidAnnounce::NoStamp),
                    Some(value) if below(cost_target, value) => {
                        return CachedAnnounce::Rejected(InvalidAnnounce::InvalidStamp(Some(
                            value,
                        )));
                    }
                    Some(_) => {}
                }
            }
            return CachedAnnounce::Valid(valid.clone());
        }
        CachedAnnounce::Miss
    }

    /// Identity.py: keeps the first result and clears any invalidation.
    pub fn insert_valid(&mut self, packet_hash: [u8; 32], result: ValidatedAnnounce) {
        if let std::collections::hash_map::Entry::Vacant(entry) = self.valid.entry(packet_hash) {
            entry.insert(result);
            self.valid_order.push_back(packet_hash);
        }
        if self.invalid.remove(&packet_hash).is_some() {
            self.invalid_order.retain(|hash| hash != &packet_hash);
        }
        while self.valid.len() > VALID_CACHE_MAX {
            let Some(oldest) = self.valid_order.pop_front() else {
                break;
            };
            self.valid.remove(&oldest);
        }
    }

    /// Identity.py: a newer invalidation replaces the old one in place.
    pub fn insert_invalid(&mut self, packet_hash: [u8; 32], reason: InvalidAnnounce) {
        if self.invalid.insert(packet_hash, reason).is_none() {
            self.invalid_order.push_back(packet_hash);
        }
        while self.invalid.len() > INVALID_CACHE_MAX {
            let Some(oldest) = self.invalid_order.pop_front() else {
                break;
            };
            self.invalid.remove(&oldest);
        }
    }

    /// Identity.py, called whenever the blackhole set changes.
    pub fn reset(&mut self) {
        self.valid.clear();
        self.valid_order.clear();
        self.invalid.clear();
        self.invalid_order.clear();
    }

    #[cfg(test)]
    pub fn valid_len(&self) -> usize {
        self.valid.len()
    }

    #[cfg(test)]
    pub fn invalid_len(&self) -> usize {
        self.invalid.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn result(stamp_value: Option<f64>) -> ValidatedAnnounce {
        ValidatedAnnounce {
            public_key: [1; 64],
            identity_hash: [2; 16],
            app_data: None,
            ratchet: None,
            stamp: None,
            stamp_value,
            lr_cost: None,
        }
    }

    #[test]
    fn invalid_stamp_revalidates_only_where_the_value_meets_the_cost() {
        let mut cache = AnnounceValidationCache::new();
        cache.insert_invalid([1; 32], InvalidAnnounce::InvalidStamp(Some(6.734375)));
        assert!(matches!(
            cache.lookup(&[1; 32], 23.5, false),
            CachedAnnounce::Rejected(InvalidAnnounce::InvalidStamp(_))
        ));
        assert!(matches!(
            cache.lookup(&[1; 32], 5.0, false),
            CachedAnnounce::Miss
        ));
    }

    #[test]
    fn other_invalidations_are_returned_directly() {
        let mut cache = AnnounceValidationCache::new();
        cache.insert_invalid([1; 32], InvalidAnnounce::NoStamp);
        cache.insert_invalid([2; 32], InvalidAnnounce::Blackholed);
        cache.insert_invalid([3; 32], InvalidAnnounce::Invalid);
        cache.insert_invalid([4; 32], InvalidAnnounce::InvalidStamp(None));
        for (hash, expected) in [
            ([1; 32], InvalidAnnounce::NoStamp),
            ([2; 32], InvalidAnnounce::Blackholed),
            ([3; 32], InvalidAnnounce::Invalid),
            ([4; 32], InvalidAnnounce::Invalid),
        ] {
            assert!(
                matches!(cache.lookup(&hash, 0.0, false), CachedAnnounce::Rejected(r) if r == expected)
            );
        }
    }

    #[test]
    fn valid_hit_rechecks_value_only_under_enforcement() {
        let mut cache = AnnounceValidationCache::new();
        cache.insert_valid([1; 32], result(None));
        cache.insert_valid([2; 32], result(Some(10.0)));
        cache.insert_valid([3; 32], result(Some(25.0)));
        for hash in [[1; 32], [2; 32], [3; 32]] {
            assert!(matches!(
                cache.lookup(&hash, 23.5, false),
                CachedAnnounce::Valid(_)
            ));
        }
        assert!(matches!(
            cache.lookup(&[1; 32], 23.5, true),
            CachedAnnounce::Rejected(InvalidAnnounce::NoStamp)
        ));
        assert!(matches!(
            cache.lookup(&[2; 32], 23.5, true),
            CachedAnnounce::Rejected(InvalidAnnounce::InvalidStamp(Some(_)))
        ));
        assert!(matches!(
            cache.lookup(&[3; 32], 23.5, true),
            CachedAnnounce::Valid(_)
        ));
    }

    #[test]
    fn valid_result_clears_invalidation_and_keeps_first_entry() {
        let mut cache = AnnounceValidationCache::new();
        cache.insert_invalid([1; 32], InvalidAnnounce::InvalidStamp(Some(6.0)));
        cache.insert_valid([1; 32], result(Some(6.0)));
        cache.insert_valid([1; 32], result(Some(99.0)));
        assert_eq!(cache.invalid_len(), 0);
        assert!(matches!(
            cache.lookup(&[1; 32], 0.0, false),
            CachedAnnounce::Valid(v) if v.stamp_value == Some(6.0)
        ));
    }

    #[test]
    fn caches_hold_384_entries_first_in_first_out() {
        let key = |i: u16| {
            let mut key = [0u8; 32];
            key[..2].copy_from_slice(&i.to_be_bytes());
            key
        };
        let mut cache = AnnounceValidationCache::new();
        for i in 0..=384u16 {
            cache.insert_valid(key(i), result(None));
            cache.insert_invalid(key(i), InvalidAnnounce::Invalid);
        }
        // Identity.py 1.6.1.
        assert_eq!(cache.valid_len(), 384);
        assert_eq!(cache.invalid_len(), 384);
        assert!(matches!(
            cache.lookup(&key(0), 0.0, false),
            CachedAnnounce::Miss
        ));
        assert!(matches!(
            cache.lookup(&key(1), 0.0, false),
            CachedAnnounce::Rejected(InvalidAnnounce::Invalid)
        ));
        cache.reset();
        assert_eq!((cache.valid_len(), cache.invalid_len()), (0, 0));
    }
}
