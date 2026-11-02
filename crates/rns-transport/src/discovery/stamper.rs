//! Pluggable proof-of-work stamper for discovery announces.
//!
//! Discovery accepts a trait object so transport does not depend on LXMF.
//! Embedding applications can install
//! `lxmf-core::discovery_stamper::LxmfDiscoveryStamper`, which supplies the
//! discovery workblock and stamp algorithm. These methods are synchronous;
//! callers choose where to run potentially expensive generation/validation.

/// Minimal PoW stamp interface consumed by the discovery subsystem.
///
/// Generation may search randomly and return different valid stamps for the
/// same inputs. Validation and value calculation must use the same discovery
/// algorithm: the announcer caches a successful stamp for unchanged info bytes,
/// and receivers must be able to validate it independently.
pub trait DiscoveryStamper: Send + Sync {
    /// Generate a 32-byte stamp meeting `target_value` for this info hash.
    /// The discovery algorithm hashes a derived workblock with the stamp;
    /// the target is the required number of leading zero bits.
    ///
    /// Return `None` when generation fails or its implementation-specific
    /// budget is exhausted. This trait supplies no cancellation or time limit.
    fn generate(&self, infohash: &[u8; 32], target_value: u8) -> Option<Vec<u8>>;

    /// Compute the stamp's value for this info hash, expressed as leading
    /// zero bits and limited to this method's `u8` range. This describes work
    /// quality, not the trustworthiness of the advertised endpoint.
    fn value(&self, infohash: &[u8; 32], stamp: &[u8]) -> u8;

    /// Decide whether the stamp meets the required work value for this info
    /// hash. Implementations define zero-cost and malformed-stamp handling;
    /// callers must still validate framing and the advertised fields.
    fn valid(&self, infohash: &[u8; 32], stamp: &[u8], required_value: u8) -> bool;
}

/// Disabled stamper: generation always returns `None`, value is always zero,
/// and validation always returns `false`, including at a zero requirement.
/// It supplies no usable stamp for publication or accepted inbound work.
pub struct NullStamper;

impl DiscoveryStamper for NullStamper {
    fn generate(&self, _infohash: &[u8; 32], _target_value: u8) -> Option<Vec<u8>> {
        None
    }

    fn value(&self, _infohash: &[u8; 32], _stamp: &[u8]) -> u8 {
        0
    }

    fn valid(&self, _infohash: &[u8; 32], _stamp: &[u8], _required_value: u8) -> bool {
        false
    }
}
