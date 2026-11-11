//! Link request stamps: the initiator's X25519 key is a stamp over the
//! destination hash and its Ed25519 key (RNS/Link.py:187-200, :344-382@1.6.0).

use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::{Duration, Instant};

use rns_crypto::ed25519::Ed25519PrivateKey;
use rns_crypto::x25519::X25519PrivateKey;
use rns_identity::stamps::{
    StampControl, StampError, generate_stamped_key, stamp_valid, stamp_value,
};

use crate::constants::{ECPUBSIZE, LINK_MTU_SIZE};
use crate::handshake::EphemeralKeys;

const KEYSTAMP_POOLING_THRESHOLD: f64 = 10.0;

/// The link request stamping switches an initiator reads (Transport.py:196-205@1.6.0).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct LinkStampPolicy {
    /// Python `STAMP_LRS`.
    pub stamp_lrs: bool,
    /// Python `ALWAYS_STAMP_LRS`.
    pub always_stamp_lrs: bool,
    /// Python `LR_COST`, used when no cost was announced and `always_stamp_lrs` is set.
    pub lr_cost: f64,
    /// Python `LINK_STAMP_TIMEOUT`.
    pub timeout: Duration,
}

impl Default for LinkStampPolicy {
    fn default() -> Self {
        Self {
            stamp_lrs: true,
            always_stamp_lrs: false,
            lr_cost: 12.5,
            timeout: Duration::from_secs(15),
        }
    }
}

impl LinkStampPolicy {
    /// The cost to stamp a request at, given the destination's recalled link
    /// cost; `None` means unstamped keys (Link.py:310-313).
    pub fn request_cost(&self, recalled: Option<f64>) -> Option<f64> {
        let cost = recalled.or(self.always_stamp_lrs.then_some(self.lr_cost))?;
        (cost != 0.0 && self.stamp_lrs).then_some(cost)
    }

    /// A stop control whose deadline is `timeout` from now. Costs from 10 up
    /// use every CPU, as Python pools keystamp work there (Stamps.py:336@1.6.0).
    pub fn control(&self, cost: f64) -> StampControl {
        let threads = if cost >= KEYSTAMP_POOLING_THRESHOLD {
            std::thread::available_parallelism().unwrap_or(NonZeroUsize::MIN)
        } else {
            NonZeroUsize::MIN
        };
        StampControl {
            deadline: Instant::now().checked_add(self.timeout),
            threads,
            ..StampControl::default()
        }
    }
}

/// Recalls the link request cost a destination announced (Python `Identity.recall_link_cost`).
pub type LinkCostRecall = Arc<dyn Fn(&[u8; 16]) -> Option<f64> + Send + Sync>;

/// Builds initiator Links for owners without async access to Transport: the
/// policy plus a synchronous source of announced link costs.
#[derive(Clone)]
pub struct LinkRequestStamper {
    pub policy: LinkStampPolicy,
    /// Python `Reticulum.link_mtu_discovery()`: whether requests signal the
    /// next hop's hardware MTU instead of the base MTU.
    pub link_mtu_discovery: bool,
    recall: LinkCostRecall,
}

impl std::fmt::Debug for LinkRequestStamper {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LinkRequestStamper")
            .field("policy", &self.policy)
            .field("link_mtu_discovery", &self.link_mtu_discovery)
            .finish_non_exhaustive()
    }
}

impl LinkRequestStamper {
    pub fn new(policy: LinkStampPolicy, recall: LinkCostRecall) -> Self {
        Self {
            policy,
            link_mtu_discovery: true,
            recall,
        }
    }

    /// Upstream default policy with no announced costs: requests are stamped
    /// only when `always_stamp_lrs` is set.
    pub fn without_recall(policy: LinkStampPolicy) -> Self {
        Self::new(policy, Arc::new(|_| None))
    }

    /// The cost a request to `destination_hash` is stamped at, if any.
    pub fn request_cost(&self, destination_hash: &[u8; 16]) -> Option<f64> {
        let recalled = self
            .policy
            .stamp_lrs
            .then(|| (self.recall)(destination_hash))
            .flatten();
        self.policy.request_cost(recalled)
    }

    /// Create an initiator Link with a stamped request where upstream stamps
    /// one, signalling `signalled_mtu` (Link.py:392-397@1.6.0). Blocks the
    /// calling thread while grinding, up to the policy timeout.
    pub fn new_initiator(
        &self,
        destination_hash: [u8; 16],
        hops: u8,
        signalled_mtu: u32,
    ) -> Result<(crate::link::Link, Vec<u8>), LinkStampError> {
        let cost = self.request_cost(&destination_hash);
        let ctl = self.policy.control(cost.unwrap_or(0.0));
        crate::link::Link::new_stamped_initiator(destination_hash, hops, cost, &ctl, signalled_mtu)
    }
}

/// Why stamped link request keys could not be generated.
#[derive(Debug, Clone, Copy, PartialEq, thiserror::Error)]
pub enum LinkStampError {
    #[error(transparent)]
    Cost(#[from] StampError),
    #[error("link request stamp generation was cancelled or timed out")]
    Stopped,
    #[error("stamped link request key did not round-trip")]
    Mismatch,
}

/// `destination.hash + sig_pub_bytes`, the material a link request key stamps.
pub fn link_stamp_material(destination_hash: &[u8; 16], ed25519_pub: &[u8; 32]) -> [u8; 48] {
    let mut material = [0u8; 48];
    material[..16].copy_from_slice(destination_hash);
    material[16..].copy_from_slice(ed25519_pub);
    material
}

/// Generate ephemeral keys whose X25519 public key meets `cost` for
/// `destination_hash`. Blocks the calling thread until found or `ctl` stops.
pub fn generate_stamped_ephemeral_keys(
    destination_hash: &[u8; 16],
    cost: f64,
    ctl: &StampControl,
) -> Result<EphemeralKeys, LinkStampError> {
    let ed25519_prv = Ed25519PrivateKey::generate();
    let material = link_stamp_material(destination_hash, &ed25519_prv.public_key().to_bytes());
    let stamped = generate_stamped_key(&material, cost, ctl)?.ok_or(LinkStampError::Stopped)?;
    let x25519_prv = X25519PrivateKey::from_bytes(&stamped.private.to_bytes());
    if x25519_prv.to_bytes() != stamped.private.to_bytes()
        || x25519_prv.public_key().to_bytes() != stamped.public
    {
        return Err(LinkStampError::Mismatch);
    }
    Ok(EphemeralKeys::from_parts(x25519_prv, ed25519_prv))
}

fn split_request(request_data: &[u8]) -> Option<(&[u8], &[u8; 32])> {
    if request_data.len() != ECPUBSIZE && request_data.len() != ECPUBSIZE + LINK_MTU_SIZE {
        return None;
    }
    let sig_pub = request_data[32..64].try_into().ok()?;
    Some((&request_data[..32], sig_pub))
}

/// The stamp value of a link request (Python `link.stamp_cost`), or `None`
/// when the payload is not a 64- or 67-byte link request.
pub fn link_request_stamp_value(destination_hash: &[u8; 16], request_data: &[u8]) -> Option<f64> {
    let (peer_pub, sig_pub) = split_request(request_data)?;
    Some(stamp_value(
        &link_stamp_material(destination_hash, sig_pub),
        peer_pub,
    ))
}

/// Whether a link request meets `cost`; a cost of 0 accepts every request.
pub fn link_request_stamp_valid(
    destination_hash: &[u8; 16],
    request_data: &[u8],
    cost: f64,
) -> bool {
    let Some((peer_pub, sig_pub)) = split_request(request_data) else {
        return false;
    };
    stamp_valid(
        peer_pub,
        cost,
        &link_stamp_material(destination_hash, sig_pub),
    )
    .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handshake::LinkRequestData;
    use crate::mtu_discovery::SignallingData;
    use std::sync::atomic::AtomicBool;

    #[test]
    fn stamped_keys_meet_the_cost_they_were_ground_for() {
        let dest = [0x5A; 16];
        let keys = generate_stamped_ephemeral_keys(&dest, 6.5, &StampControl::default()).unwrap();
        let request = LinkRequestData::pack(&keys, SignallingData::new(1, 500));
        assert!(link_request_stamp_valid(&dest, &request, 6.5));
        assert!(link_request_stamp_value(&dest, &request).unwrap() >= 6.5);
        assert!(link_request_stamp_valid(&dest, &request[..64], 6.5));
        assert!(!link_request_stamp_valid(&dest, &request[..63], 0.0));
    }

    #[test]
    fn stamper_initiator_signals_the_given_mtu() {
        let stamper = LinkRequestStamper::without_recall(LinkStampPolicy::default());
        for mtu in [500, 262_144] {
            let (_, request) = stamper.new_initiator([0x5A; 16], 1, mtu).unwrap();
            assert_eq!(
                LinkRequestData::unpack(&request).unwrap().signalling.mtu,
                mtu
            );
        }
    }

    #[test]
    fn stopped_generation_reports_failure() {
        let ctl = StampControl {
            cancel: Arc::new(AtomicBool::new(false)),
            deadline: Some(Instant::now() + Duration::from_millis(20)),
            ..StampControl::default()
        };
        let started = Instant::now();
        assert_eq!(
            generate_stamped_ephemeral_keys(&[1; 16], 60.0, &ctl).err(),
            Some(LinkStampError::Stopped)
        );
        assert!(started.elapsed() < Duration::from_secs(5));
        assert!(matches!(
            generate_stamped_ephemeral_keys(&[1; 16], 101.0, &StampControl::default()),
            Err(LinkStampError::Cost(_))
        ));
    }
}
