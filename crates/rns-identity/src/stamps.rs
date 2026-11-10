//! Proof-of-work stamps: fixed-point costs, values, validation and generation.
//!
//! Python reference: `RNS/Stamps.py` (1.6.0). Costs and values are fixed point
//! with 8 fractional bits; a cost of 1.0 is 256.

use std::num::NonZeroUsize;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

use rand::RngCore;
use rns_crypto::hkdf::hkdf_sha256;
use rns_crypto::sha::full_hash;
use rns_crypto::x25519::X25519PrivateKey;
use sha2::{Digest, Sha256};

pub const WORKBLOCK_EXPAND_CHUNK: usize = 256;
pub const WORKBLOCK_EXPAND_ROUNDS: usize = 3000;
pub const STAMP_SIZE: usize = 32;
/// Size of detached destination and path-request stamps (`Identity.STAMPLENGTH`).
pub const NETWORK_STAMP_SIZE: usize = 14;
pub const STOP_CHECK_INTERVAL: u32 = 64;
pub const MANTISSA_BITS: u32 = 33;
pub const COST_FP_BITS: u32 = 8;
pub const COST_FP: u32 = 1 << COST_FP_BITS;
pub const STAMP_COST_CAP: f64 = 100.0;
pub const STAMP_COST_CAP_FP: u16 = 100 * 256;
pub const LINK_COST_CAP: f64 = 40.0;
/// Fixed-point value of a stamp whose hash is zero.
pub const MAX_VALUE_FP: u32 = 256 * COST_FP;

pub const TAB_DIGEST: &str = "55ba3ce1df224895b0dfdc102eb4359fc2f5a7efefee68df0cc90c8a8ac24f48";
pub const PRM_DIGEST: &str = "21436fc98e76a12cad7c52ebeb6ab76c2ae93b4cd768949df7fdd4e2f98c378d";

/// `floor(2^33 * 2^(f/256))` for `f` in `0..256`, copied verbatim from
/// upstream. Never compute these: the table is the wire contract.
pub const TAB: [u64; 256] = [
    0x200000000,
    0x201635f4b,
    0x202c7b53f,
    0x2042d0287,
    0x2059347ce,
    0x206fa85c2,
    0x20862bd0d,
    0x209cbee5e,
    0x20b361a62,
    0x20ca141c7,
    0x20e0d653b,
    0x20f7a856e,
    0x210e8a30e,
    0x21257becc,
    0x213c7d958,
    0x21538f363,
    0x216ab0d9f,
    0x2181e28bc,
    0x21992456e,
    0x21b076467,
    0x21c7d865a,
    0x21df4abfb,
    0x21f6cd5ff,
    0x220e6051a,
    0x222603a02,
    0x223db756b,
    0x22557b80d,
    0x226d5029e,
    0x2285355d5,
    0x229d2b269,
    0x22b531914,
    0x22cd48a8e,
    0x22e57078f,
    0x22fda90d2,
    0x2315f2711,
    0x232e4cb06,
    0x2346b7d6d,
    0x235f33f02,
    0x2377c1080,
    0x23905f2a5,
    0x23a90e62d,
    0x23c1cebd6,
    0x23daa045f,
    0x23f383087,
    0x240c7710c,
    0x24257c6af,
    0x243e9322f,
    0x2457bb44f,
    0x2470f4dce,
    0x248a3ff70,
    0x24a39c9f6,
    0x24bd0ae23,
    0x24d68acbc,
    0x24f01c683,
    0x2509bfc3e,
    0x252374eb2,
    0x253d3bea3,
    0x255714cda,
    0x2570ffa1b,
    0x258afc72e,
    0x25a50b4dc,
    0x25bf2c3ec,
    0x25d95f527,
    0x25f3a4957,
    0x260dfc146,
    0x262865dbd,
    0x2642e1f89,
    0x265d70775,
    0x26781164c,
    0x2692c4cdc,
    0x26ad8abf2,
    0x26c86345b,
    0x26e34e6e7,
    0x26fe4c463,
    0x27195cda0,
    0x27348036e,
    0x274fb669c,
    0x276aff7fd,
    0x27865b862,
    0x27a1ca89d,
    0x27bd4c982,
    0x27d8e1be3,
    0x27f48a095,
    0x28104586c,
    0x282c1443e,
    0x2847f64e1,
    0x2863ebb2a,
    0x287ff47f0,
    0x289c10c0c,
    0x28b840854,
    0x28d483da3,
    0x28f0dacd1,
    0x290d456b8,
    0x2929c3c32,
    0x294655e1a,
    0x2962fbd4d,
    0x297fb5aa6,
    0x299c83702,
    0x29b96533f,
    0x29d65b03b,
    0x29f364ed3,
    0x2a1082fe8,
    0x2a2db5459,
    0x2a4afbd07,
    0x2a6856ad3,
    0x2a85c5e9e,
    0x2aa34994b,
    0x2ac0e1bbd,
    0x2ade8e6d6,
    0x2afc4fb7c,
    0x2b1a25a92,
    0x2b38104ff,
    0x2b560fba9,
    0x2b7423f75,
    0x2b924d14b,
    0x2bb08b213,
    0x2bcede2b5,
    0x2bed4641b,
    0x2c0bc372e,
    0x2c2a55cd9,
    0x2c48fd607,
    0x2c67ba3a3,
    0x2c868c699,
    0x2ca573fd7,
    0x2cc47104a,
    0x2ce3838e1,
    0x2d02aba89,
    0x2d21e9633,
    0x2d413cccf,
    0x2d60a5f4e,
    0x2d8024ea1,
    0x2d9fb9bba,
    0x2dbf6478c,
    0x2ddf2530b,
    0x2dfefbf2a,
    0x2e1ee8cde,
    0x2e3eebd1d,
    0x2e5f050dd,
    0x2e7f34914,
    0x2e9f7a6ba,
    0x2ebfd6ac8,
    0x2ee049635,
    0x2f00d29fb,
    0x2f2172715,
    0x2f4228e7d,
    0x2f62f612e,
    0x2f83da026,
    0x2fa4d4c5f,
    0x2fc5e66d9,
    0x2fe70f092,
    0x30084ea87,
    0x3029a55ba,
    0x304b13329,
    0x306c983d7,
    0x308e348c4,
    0x30afe82f3,
    0x30d1b3368,
    0x30f395b26,
    0x31158fb31,
    0x3137a148f,
    0x3159ca845,
    0x317c0b75a,
    0x319e642d6,
    0x31c0d4bc1,
    0x31e35d322,
    0x3205fda05,
    0x3228b6172,
    0x324b86a75,
    0x326e6f619,
    0x32917056b,
    0x32b489979,
    0x32d7bb34e,
    0x32fb053fb,
    0x331e67c8f,
    0x3341e2e19,
    0x3365769aa,
    0x338923054,
    0x33ace8329,
    0x33d0c633c,
    0x33f4bd1a0,
    0x3418ccf6b,
    0x343cf5db1,
    0x346137d89,
    0x348593008,
    0x34aa07647,
    0x34ce9515e,
    0x34f33c266,
    0x3517fca78,
    0x353cd6aaf,
    0x3561ca426,
    0x3586d77fa,
    0x35abfe747,
    0x35d13f32b,
    0x35f699cc4,
    0x361c0e531,
    0x36419cd93,
    0x366745709,
    0x368d082b6,
    0x36b2e51bc,
    0x36d8dc53e,
    0x36feede5f,
    0x372519e44,
    0x374b60614,
    0x3771c16f3,
    0x37983d209,
    0x37bed387e,
    0x37e584b7a,
    0x380c50c28,
    0x383337bb0,
    0x385a39b3f,
    0x388156bff,
    0x38a88ef1f,
    0x38cfe25ca,
    0x38f751131,
    0x391edb280,
    0x394680aea,
    0x396e41b9d,
    0x39961e5cd,
    0x39be16aab,
    0x39e62ab6b,
    0x3a0e5a940,
    0x3a36a6561,
    0x3a5f0e101,
    0x3a8791d59,
    0x3ab031b9f,
    0x3ad8edd0c,
    0x3b01c62d9,
    0x3b2abae3f,
    0x3b53cc07b,
    0x3b7cf9ac7,
    0x3ba643e60,
    0x3bcfaac83,
    0x3bf92e66f,
    0x3c22ced63,
    0x3c4c8c29e,
    0x3c7666762,
    0x3ca05dcf1,
    0x3cca7248c,
    0x3cf4a3f78,
    0x3d1ef2ef9,
    0x3d495f454,
    0x3d73e90cf,
    0x3d9e905b1,
    0x3dc955443,
    0x3df437dcc,
    0x3e1f38396,
    0x3e4a566ed,
    0x3e759291b,
    0x3ea0ecb6d,
    0x3ecc64f31,
    0x3ef7fb5b3,
    0x3f23b0044,
    0x3f4f83033,
    0x3f7b746d2,
    0x3fa784571,
    0x3fd3b2d65,
];

#[derive(Debug, Clone, Copy, PartialEq, thiserror::Error)]
pub enum StampError {
    #[error("stamp cost is not a finite number")]
    NonFiniteCost,
    #[error("stamp cost {0} is outside 0..=100")]
    InvalidCost(f64),
    #[error("fixed-point stamp cost {0} is outside 0..=25600")]
    FpOutOfRange(u16),
}

/// Round a cost to fixed point, clamped to `0..=100`.
pub fn cost_to_fp(cost: f64) -> Result<u16, StampError> {
    let scaled = (cost * f64::from(COST_FP) + 0.5).floor();
    if !scaled.is_finite() {
        return Err(StampError::NonFiniteCost);
    }
    Ok(scaled.clamp(0.0, f64::from(STAMP_COST_CAP_FP)) as u16)
}

/// Wire encoding: integer byte first.
pub fn fp_to_bytes(fp: u16) -> [u8; 2] {
    fp.to_be_bytes()
}

pub fn cost_to_bytes(cost: f64) -> Result<[u8; 2], StampError> {
    cost_to_fp(cost).map(fp_to_bytes)
}

/// Not clamped: wire bytes can carry up to 65535.
pub fn fp_from_bytes(bytes: [u8; 2]) -> u16 {
    u16::from_be_bytes(bytes)
}

pub fn cost_from_fp(fp: u32) -> f64 {
    f64::from(fp) / f64::from(COST_FP)
}

pub fn cost_from_bytes(bytes: [u8; 2]) -> f64 {
    cost_from_fp(u32::from(fp_from_bytes(bytes)))
}

pub fn quantize_cost(cost: f64) -> Result<f64, StampError> {
    cost_to_fp(cost).map(|fp| cost_from_fp(u32::from(fp)))
}

/// Largest stamp hash that meets a cost, as a 264-bit big-endian integer.
/// Cost 0 gives `2^256`, which is why 32 bytes are not enough.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StampTarget([u8; 33]);

impl StampTarget {
    /// A stamp meets the cost when its hash is at most the target.
    pub fn accepts(&self, hash: &[u8; 32]) -> bool {
        self.0[0] != 0 || hash[..] <= self.0[1..]
    }

    pub fn to_be_bytes(&self) -> [u8; 33] {
        self.0
    }
}

pub fn target_from_fp(fp: u16) -> Result<StampTarget, StampError> {
    if fp > STAMP_COST_CAP_FP {
        return Err(StampError::FpOutOfRange(fp));
    }
    let exponent = 256 * COST_FP - u32::from(fp);
    let (whole, fraction) = (exponent / COST_FP, exponent % COST_FP);
    // `(TAB[f] << i) >> 33`; `i` is at least 156, so no bits are lost.
    let shift = whole - MANTISSA_BITS;
    let mantissa = TAB[fraction as usize];
    let mut target = [0u8; 33];
    for bit in 0..=MANTISSA_BITS {
        if (mantissa >> bit) & 1 == 1 {
            let position = (shift + bit) as usize;
            target[32 - position / 8] |= 1 << (position % 8);
        }
    }
    Ok(StampTarget(target))
}

pub fn target_from_cost(cost: f64) -> Result<StampTarget, StampError> {
    target_from_fp(cost_to_fp(cost)?)
}

/// Expand `material` into a workblock. Zero rounds return the material
/// itself, which is how the detached network stamps are hashed.
pub fn stamp_workblock(material: &[u8], expand_rounds: usize) -> Vec<u8> {
    if expand_rounds == 0 {
        return material.to_vec();
    }
    let mut workblock = Vec::with_capacity(expand_rounds * WORKBLOCK_EXPAND_CHUNK);
    let mut salt_input = Vec::with_capacity(material.len() + 9);
    for round in 0..expand_rounds {
        salt_input.clear();
        salt_input.extend_from_slice(material);
        push_msgpack_uint(&mut salt_input, round as u64);
        let salt = full_hash(&salt_input);
        let chunk = hkdf_sha256(WORKBLOCK_EXPAND_CHUNK, material, Some(&salt), None)
            .expect("256 bytes is within the HKDF output limit");
        workblock.extend_from_slice(&chunk);
    }
    workblock
}

fn push_msgpack_uint(out: &mut Vec<u8>, value: u64) {
    match value {
        0..=0x7f => out.push(value as u8),
        0x80..=0xff => out.extend_from_slice(&[0xcc, value as u8]),
        0x100..=0xffff => {
            out.push(0xcd);
            out.extend_from_slice(&(value as u16).to_be_bytes());
        }
        0x1_0000..=0xffff_ffff => {
            out.push(0xce);
            out.extend_from_slice(&(value as u32).to_be_bytes());
        }
        _ => {
            out.push(0xcf);
            out.extend_from_slice(&value.to_be_bytes());
        }
    }
}

fn hash_with(workblock: &[u8], stamp: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(workblock);
    hasher.update(stamp);
    hasher.finalize().into()
}

/// Fixed-point value of a stamp hash, `0..=65536`.
pub fn stamp_value_fp_from_hash(hash: &[u8; 32]) -> u32 {
    let mut leading_zeros = 0usize;
    for byte in hash {
        if *byte == 0 {
            leading_zeros += 8;
        } else {
            leading_zeros += byte.leading_zeros() as usize;
            break;
        }
    }
    if leading_zeros == 256 {
        return MAX_VALUE_FP;
    }
    // The 34 bits from the leading one, zero-padded past the end of the hash.
    let mut mantissa = 0u64;
    for offset in 0..=MANTISSA_BITS as usize {
        let position = leading_zeros + offset;
        let bit = if position < 256 {
            (hash[position / 8] >> (7 - position % 8)) & 1
        } else {
            0
        };
        mantissa = (mantissa << 1) | u64::from(bit);
    }
    let not_above = TAB.partition_point(|entry| *entry <= mantissa) as u32;
    ((leading_zeros as u32 + 1) << COST_FP_BITS) - not_above
}

pub fn stamp_value_fp(workblock: &[u8], stamp: &[u8]) -> u32 {
    stamp_value_fp_from_hash(&hash_with(workblock, stamp))
}

/// Fractional stamp value, `0.0..=256.0`. Not clamped to the cost cap.
pub fn stamp_value(workblock: &[u8], stamp: &[u8]) -> f64 {
    cost_from_fp(stamp_value_fp(workblock, stamp))
}

/// Costs above 100 are checked as 100; a cost of 0 always passes.
pub fn stamp_valid(stamp: &[u8], target_cost: f64, workblock: &[u8]) -> Result<bool, StampError> {
    Ok(target_from_cost(target_cost)?.accepts(&hash_with(workblock, stamp)))
}

pub fn stamp_valid_fp(stamp: &[u8], target_fp: u16, workblock: &[u8]) -> Result<bool, StampError> {
    Ok(target_from_fp(target_fp)?.accepts(&hash_with(workblock, stamp)))
}

/// Stop conditions and parallelism for a stamp search.
#[derive(Debug, Clone)]
pub struct StampControl {
    pub cancel: Arc<AtomicBool>,
    pub deadline: Option<Instant>,
    pub threads: NonZeroUsize,
}

impl Default for StampControl {
    fn default() -> Self {
        Self {
            cancel: Arc::new(AtomicBool::new(false)),
            deadline: None,
            threads: NonZeroUsize::MIN,
        }
    }
}

impl StampControl {
    fn stopped(&self) -> bool {
        self.cancel.load(Ordering::Relaxed)
            || self
                .deadline
                .is_some_and(|deadline| Instant::now() >= deadline)
    }
}

fn generation_target(cost: f64) -> Result<StampTarget, StampError> {
    if cost.is_nan() {
        return Err(StampError::NonFiniteCost);
    }
    if !(0.0..=STAMP_COST_CAP).contains(&cost) {
        return Err(StampError::InvalidCost(cost));
    }
    target_from_cost(cost)
}

/// Run `worker` on `ctl.threads` threads until one returns a result or all stop.
fn search<T: Send>(
    ctl: &StampControl,
    worker: impl Fn(&AtomicBool) -> Option<T> + Sync,
) -> Option<T> {
    let found = AtomicBool::new(false);
    if ctl.threads.get() == 1 {
        return worker(&found);
    }
    let result = Mutex::new(None);
    std::thread::scope(|scope| {
        for _ in 0..ctl.threads.get() {
            scope.spawn(|| {
                if let Some(hit) = worker(&found) {
                    found.store(true, Ordering::Relaxed);
                    result
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .get_or_insert(hit);
                }
            });
        }
    });
    result.into_inner().unwrap_or_else(|e| e.into_inner())
}

/// Search for a detached stamp of `size` random bytes over `material`.
/// Returns the stamp and its real value, or `None` when cancelled or past
/// the deadline. A cost of 0 still returns a random stamp.
pub fn generate_stamp(
    material: &[u8],
    cost: f64,
    expand_rounds: usize,
    size: usize,
    ctl: &StampControl,
) -> Result<Option<(Vec<u8>, f64)>, StampError> {
    let target = generation_target(cost)?;
    let workblock = stamp_workblock(material, expand_rounds);
    let mut base = Sha256::new();
    base.update(&workblock);

    let stamp = search(ctl, |found| {
        let mut rng = rand::thread_rng();
        let mut candidate = vec![0u8; size];
        let mut since_check = 0u32;
        loop {
            since_check += 1;
            if since_check >= STOP_CHECK_INTERVAL {
                since_check = 0;
                if ctl.stopped() || found.load(Ordering::Relaxed) {
                    return None;
                }
            }
            rng.fill_bytes(&mut candidate);
            let mut hasher = base.clone();
            hasher.update(&candidate);
            if target.accepts(&hasher.finalize().into()) {
                return Some(candidate);
            }
        }
    });
    Ok(stamp.map(|stamp| {
        let value = stamp_value(&workblock, &stamp);
        (stamp, value)
    }))
}

/// An X25519 key whose public half is a stamp over some material.
pub struct StampedKey {
    pub private: X25519PrivateKey,
    pub public: [u8; 32],
    pub value: f64,
}

/// Search for an X25519 key whose public key stamps `material`. Only ever
/// use the result as an X25519 key.
pub fn generate_stamped_key(
    material: &[u8],
    cost: f64,
    ctl: &StampControl,
) -> Result<Option<StampedKey>, StampError> {
    let target = generation_target(cost)?;
    let mut base = Sha256::new();
    base.update(material);

    let key = search(ctl, |found| {
        loop {
            if ctl.stopped() || found.load(Ordering::Relaxed) {
                return None;
            }
            let private = X25519PrivateKey::generate();
            let public = private.public_key().to_bytes();
            let mut hasher = base.clone();
            hasher.update(public);
            if target.accepts(&hasher.finalize().into()) {
                return Some((private, public));
            }
        }
    });
    Ok(key.map(|(private, public)| StampedKey {
        value: stamp_value(material, &public),
        private,
        public,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rns_crypto::sha::sha256;

    fn sample_hash(index: u32) -> [u8; 32] {
        sha256(format!("stamp-sample-{index}").as_bytes())
    }

    #[test]
    fn table_matches_upstream_digests() {
        assert_eq!(TAB.len() as u32, COST_FP);
        assert_eq!(TAB[0], 1 << MANTISSA_BITS);
        assert!(TAB.windows(2).all(|pair| pair[1] > pair[0]));
        let joined = TAB.iter().map(u64::to_string).collect::<Vec<_>>().join(",");
        assert_eq!(hex::encode(sha256(joined.as_bytes())), TAB_DIGEST);
        let parameters = format!(
            "master|{TAB_DIGEST}|{MANTISSA_BITS}|{}|{COST_FP_BITS}|{COST_FP}|",
            TAB.len()
        );
        assert_eq!(hex::encode(sha256(parameters.as_bytes())), PRM_DIGEST);
    }

    #[test]
    fn integer_cost_target_is_a_power_of_two() {
        for cost in 0..=100u16 {
            let target = target_from_fp(cost * 256).unwrap().to_be_bytes();
            let position = 256 - cost as usize;
            let mut expected = [0u8; 33];
            expected[32 - position / 8] = 1 << (position % 8);
            assert_eq!(target, expected, "cost {cost}");
        }
    }

    #[test]
    fn cost_rounding_and_clamping() {
        assert_eq!(cost_to_fp(0.0), Ok(0));
        assert_eq!(cost_to_fp(0.5 / 256.0), Ok(1));
        assert_eq!(cost_to_fp(1.5 / 256.0), Ok(2));
        assert_eq!(cost_to_fp(12.5), Ok(3200));
        assert_eq!(cost_to_fp(150.0), Ok(STAMP_COST_CAP_FP));
        assert_eq!(cost_to_fp(-5.0), Ok(0));
        assert_eq!(cost_to_fp(f64::NAN), Err(StampError::NonFiniteCost));
        assert_eq!(cost_to_fp(f64::INFINITY), Err(StampError::NonFiniteCost));
        assert_eq!(fp_to_bytes(3200), [12, 128]);
        assert_eq!(fp_from_bytes([0xff, 0xff]), 65535);
        assert_eq!(target_from_fp(25601), Err(StampError::FpOutOfRange(25601)));
    }

    #[test]
    fn value_is_the_highest_cost_a_hash_meets() {
        for index in 0..2000 {
            let mut hash = sample_hash(index);
            // Spread the samples over a range of leading-zero counts.
            let zero_bits = (index % 40) as usize;
            for bit in 0..zero_bits {
                hash[bit / 8] &= !(0x80 >> (bit % 8));
            }
            let value = stamp_value_fp_from_hash(&hash);
            let capped = value.min(u32::from(STAMP_COST_CAP_FP)) as u16;
            assert!(target_from_fp(capped).unwrap().accepts(&hash), "{index}");
            if capped < STAMP_COST_CAP_FP {
                assert!(
                    !target_from_fp(capped + 1).unwrap().accepts(&hash),
                    "{index}"
                );
            }
        }
    }

    #[test]
    fn value_edges() {
        assert_eq!(stamp_value_fp_from_hash(&[0u8; 32]), 65536);
        let mut one = [0u8; 32];
        one[31] = 1;
        assert_eq!(stamp_value_fp_from_hash(&one), 65535);
        assert_eq!(stamp_value_fp_from_hash(&[0xff; 32]), 0);
        let mut top = [0u8; 32];
        top[0] = 0x80;
        assert_eq!(stamp_value_fp_from_hash(&top), 255);
    }

    #[test]
    fn workblock_without_rounds_is_the_material() {
        assert_eq!(stamp_workblock(b"material", 0), b"material");
        assert_eq!(stamp_workblock(b"material", 2).len(), 512);
        assert_eq!(stamp_workblock(b"", 1).len(), 256);
    }

    #[test]
    fn generated_stamp_meets_its_cost() {
        let ctl = StampControl::default();
        for (cost, size) in [(0.0, 14), (6.5, 14), (8.25, 32)] {
            let (stamp, value) = generate_stamp(b"material", cost, 0, size, &ctl)
                .unwrap()
                .unwrap();
            assert_eq!(stamp.len(), size);
            assert!(value >= quantize_cost(cost).unwrap());
            assert_eq!(stamp_valid(&stamp, cost, b"material"), Ok(true));
            assert_eq!(value, stamp_value(b"material", &stamp));
        }
    }

    #[test]
    fn generation_runs_on_several_threads() {
        let ctl = StampControl {
            threads: NonZeroUsize::new(4).unwrap(),
            ..StampControl::default()
        };
        let (stamp, _) = generate_stamp(b"material", 10.0, 2, 32, &ctl)
            .unwrap()
            .unwrap();
        let workblock = stamp_workblock(b"material", 2);
        assert_eq!(stamp_valid(&stamp, 10.0, &workblock), Ok(true));
    }

    #[test]
    fn generation_rejects_costs_python_rejects() {
        let ctl = StampControl::default();
        assert_eq!(
            generate_stamp(b"m", 100.5, 0, 14, &ctl).unwrap_err(),
            StampError::InvalidCost(100.5)
        );
        assert_eq!(
            generate_stamp(b"m", -0.5, 0, 14, &ctl).unwrap_err(),
            StampError::InvalidCost(-0.5)
        );
        assert_eq!(
            generate_stamp(b"m", f64::NAN, 0, 14, &ctl).unwrap_err(),
            StampError::NonFiniteCost
        );
        assert!(matches!(
            generate_stamped_key(b"m", 101.0, &ctl),
            Err(StampError::InvalidCost(_))
        ));
    }

    #[test]
    fn cancelled_generation_returns_none() {
        let ctl = StampControl::default();
        ctl.cancel.store(true, Ordering::Relaxed);
        assert_eq!(generate_stamp(b"m", 60.0, 0, 14, &ctl), Ok(None));
        assert!(generate_stamped_key(b"m", 60.0, &ctl).unwrap().is_none());
        let expired = StampControl {
            deadline: Some(Instant::now()),
            ..StampControl::default()
        };
        assert_eq!(generate_stamp(b"m", 60.0, 0, 14, &expired), Ok(None));
    }

    #[test]
    fn stamped_key_public_half_is_the_stamp() {
        let key = generate_stamped_key(b"material", 5.5, &StampControl::default())
            .unwrap()
            .unwrap();
        assert_eq!(key.private.public_key().to_bytes(), key.public);
        assert_eq!(stamp_valid(&key.public, 5.5, b"material"), Ok(true));
        assert_eq!(key.value, stamp_value(b"material", &key.public));
    }
}
