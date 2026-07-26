use rns_crypto::sha::truncated_hash;
use thiserror::Error;
use tracing::trace;

use crate::identity::Identity;
use crate::name_hash::name_hash;

// Announce field sizes, fixed by the wire format.
const PUBKEY_SIZE: usize = 64;
const NAME_HASH_SIZE: usize = 10;
const RANDOM_HASH_SIZE: usize = 10;
const SIGNATURE_SIZE: usize = 64;
const RATCHET_SIZE: usize = 32;

/// Maximum value carried in the low five bytes of an announce random hash.
pub const ANNOUNCE_TIME_MAX: u64 = (1u64 << 40) - 1;

const MIN_ANNOUNCE_SIZE: usize = PUBKEY_SIZE + NAME_HASH_SIZE + RANDOM_HASH_SIZE + SIGNATURE_SIZE;

#[derive(Debug, Error)]
pub enum AnnounceError {
    #[error("announce data too short: {0} bytes (minimum {MIN_ANNOUNCE_SIZE})")]
    TooShort(usize),
    #[error("signature verification failed")]
    SignatureInvalid,
    #[error("destination hash mismatch")]
    HashMismatch,
    #[error("identity has no private key for signing")]
    NoPrivateKey,
    #[error("invalid public key in announce")]
    InvalidPublicKey,
    #[error("hash collision detected for destination")]
    HashCollision,
    #[error("announce wire time exceeds 40-bit field: {0}")]
    InvalidWireTime(u64),
}

/// Parsed announce data.
#[derive(Debug, Clone)]
pub struct AnnounceData {
    pub public_key: [u8; 64],
    pub name_hash: [u8; 10],
    pub random_hash: [u8; 10],
    pub ratchet: Option<[u8; 32]>,
    pub signature: [u8; 64],
    pub app_data: Option<Vec<u8>>,
}

impl AnnounceData {
    /// Create and sign an announce for a destination.
    ///
    /// The `random_hash` is `random(5) || timestamp_be(5)` so receivers can
    /// detect replays without a shared clock.
    pub fn create(
        identity: &Identity,
        app_name: &str,
        app_data: Option<&[u8]>,
        ratchet_pub: Option<&[u8; 32]>,
    ) -> Result<Self, AnnounceError> {
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        Self::create_at(identity, app_name, app_data, ratchet_pub, ts)
    }

    /// Create and sign an announce with an explicit persisted 40-bit ordering
    /// value. Rotation and expiry clocks must be managed separately.
    pub fn create_at(
        identity: &Identity,
        app_name: &str,
        app_data: Option<&[u8]>,
        ratchet_pub: Option<&[u8; 32]>,
        wire_time: u64,
    ) -> Result<Self, AnnounceError> {
        if wire_time > ANNOUNCE_TIME_MAX {
            return Err(AnnounceError::InvalidWireTime(wire_time));
        }

        let public_key = identity.get_public_key();
        let nh = name_hash(app_name);
        let random_bytes = rns_crypto::random::random_bytes(5);
        let ts_bytes = wire_time.to_be_bytes();
        let mut random_hash = [0u8; 10];
        random_hash[..5].copy_from_slice(&random_bytes);
        // The value was range checked, so these are the complete 40 bits.
        random_hash[5..].copy_from_slice(&ts_bytes[3..8]);

        let dest_hash = crate::destination::Destination::hash_from_name_and_identity(
            app_name,
            Some(&identity.hash),
        );

        let mut signed_data = Vec::new();
        signed_data.extend_from_slice(&dest_hash);
        signed_data.extend_from_slice(&public_key);
        signed_data.extend_from_slice(&nh);
        signed_data.extend_from_slice(&random_hash);
        if let Some(r) = ratchet_pub {
            signed_data.extend_from_slice(r);
        }
        if let Some(ad) = app_data {
            signed_data.extend_from_slice(ad);
        }

        let signature = identity
            .sign(&signed_data)
            .ok_or(AnnounceError::NoPrivateKey)?;

        Ok(Self {
            public_key,
            name_hash: nh,
            random_hash,
            ratchet: ratchet_pub.copied(),
            signature,
            app_data: app_data.map(|d| d.to_vec()),
        })
    }

    /// Serialise the announce into its on-wire packet payload.
    ///
    /// Layout: `pub_key(64) || name_hash(10) || random_hash(10) || [ratchet(32)] || signature(64) || [app_data]`.
    pub fn pack(&self) -> Vec<u8> {
        let size = PUBKEY_SIZE
            + NAME_HASH_SIZE
            + RANDOM_HASH_SIZE
            + if self.ratchet.is_some() {
                RATCHET_SIZE
            } else {
                0
            }
            + SIGNATURE_SIZE
            + self.app_data.as_ref().map_or(0, |d| d.len());

        let mut out = Vec::with_capacity(size);
        out.extend_from_slice(&self.public_key);
        out.extend_from_slice(&self.name_hash);
        out.extend_from_slice(&self.random_hash);
        if let Some(ref r) = self.ratchet {
            out.extend_from_slice(r);
        }
        out.extend_from_slice(&self.signature);
        if let Some(ref ad) = self.app_data {
            out.extend_from_slice(ad);
        }
        out
    }

    /// Parse an announce from packet payload bytes.
    ///
    /// `has_ratchet` must match the packet header's context flag; the ratchet
    /// field is not self-delimiting.
    pub fn unpack(data: &[u8], has_ratchet: bool) -> Result<Self, AnnounceError> {
        let min_size = if has_ratchet {
            MIN_ANNOUNCE_SIZE + RATCHET_SIZE
        } else {
            MIN_ANNOUNCE_SIZE
        };

        if data.len() < min_size {
            return Err(AnnounceError::TooShort(data.len()));
        }

        let mut pos = 0;

        let mut public_key = [0u8; 64];
        public_key.copy_from_slice(&data[pos..pos + 64]);
        pos += 64;

        let mut nh = [0u8; 10];
        nh.copy_from_slice(&data[pos..pos + 10]);
        pos += 10;

        let mut random_hash = [0u8; 10];
        random_hash.copy_from_slice(&data[pos..pos + 10]);
        pos += 10;

        let ratchet = if has_ratchet {
            let mut r = [0u8; 32];
            r.copy_from_slice(&data[pos..pos + 32]);
            pos += 32;
            Some(r)
        } else {
            None
        };

        let mut signature = [0u8; 64];
        signature.copy_from_slice(&data[pos..pos + 64]);
        pos += 64;

        let app_data = if pos < data.len() {
            Some(data[pos..].to_vec())
        } else {
            None
        };

        Ok(Self {
            public_key,
            name_hash: nh,
            random_hash,
            ratchet,
            signature,
            app_data,
        })
    }

    /// Validate an announce against the destination hash from the packet header.
    pub fn validate(&self, packet_dest_hash: &[u8; 16]) -> Result<Identity, AnnounceError> {
        self.validate_with_known_key(packet_dest_hash, None)
    }

    /// Validate and optionally enforce first-seen key binding.
    ///
    /// If `known_public_key` is supplied and differs from the announced key,
    /// the announce is rejected as a potential hash-collision hijack.
    pub fn validate_with_known_key(
        &self,
        packet_dest_hash: &[u8; 16],
        known_public_key: Option<&[u8; 64]>,
    ) -> Result<Identity, AnnounceError> {
        let identity = self.verify_signature(packet_dest_hash)?;
        self.validate_destination_binding(packet_dest_hash, &identity, known_public_key)?;
        Ok(identity)
    }

    /// Verify the announce signature without checking destination-hash
    /// binding or first-seen key continuity.
    ///
    /// Reticulum transport performs this lightweight precheck before announce
    /// ingress limiting, then runs full binding validation before learning the
    /// path. Keeping this as a distinct step lets transport match that order
    /// without duplicating announce wire-format logic.
    pub fn verify_signature(&self, packet_dest_hash: &[u8; 16]) -> Result<Identity, AnnounceError> {
        let identity = Identity::from_public_key(&self.public_key)
            .map_err(|_| AnnounceError::InvalidPublicKey)?;

        let mut signed_data = Vec::new();
        signed_data.extend_from_slice(packet_dest_hash);
        signed_data.extend_from_slice(&self.public_key);
        signed_data.extend_from_slice(&self.name_hash);
        signed_data.extend_from_slice(&self.random_hash);
        if let Some(ref r) = self.ratchet {
            signed_data.extend_from_slice(r);
        }
        if let Some(ref ad) = self.app_data {
            signed_data.extend_from_slice(ad);
        }

        trace!(
            signed_data_len = signed_data.len(),
            signed_data_head = hex::encode(&signed_data[..std::cmp::min(32, signed_data.len())]),
            signed_data_tail = hex::encode(&signed_data[signed_data.len().saturating_sub(16)..]),
            identity_hash = hex::encode(identity.hash),
            "announce: verifying signature"
        );
        if !identity.verify(&signed_data, &self.signature) {
            return Err(AnnounceError::SignatureInvalid);
        }

        Ok(identity)
    }

    /// Validate destination-hash binding and first-seen public-key continuity
    /// after [`Self::verify_signature`] has succeeded.
    pub fn validate_destination_binding(
        &self,
        packet_dest_hash: &[u8; 16],
        identity: &Identity,
        known_public_key: Option<&[u8; 64]>,
    ) -> Result<(), AnnounceError> {
        // Destination hash = SHA-256(name_hash || identity_hash) truncated to 16 bytes.
        let expected_hash = {
            let mut material = Vec::with_capacity(26);
            material.extend_from_slice(&self.name_hash);
            material.extend_from_slice(&identity.hash);
            truncated_hash(&material)
        };

        if &expected_hash != packet_dest_hash {
            trace!(
                expected = hex::encode(expected_hash),
                actual = hex::encode(packet_dest_hash),
                name_hash = hex::encode(self.name_hash),
                identity_hash = hex::encode(identity.hash),
                "announce: destination hash mismatch"
            );
            return Err(AnnounceError::HashMismatch);
        }

        // First-seen key binding: a valid signature on a different public key
        // for an already-known destination hash implies a collision attack.
        if let Some(known_key) = known_public_key {
            if known_key != &self.public_key {
                tracing::error!(
                    dest = hex::encode(packet_dest_hash),
                    "announce has valid signature and destination hash, but public key \
                         differs from already known key — possible hash collision attack, rejecting"
                );
                return Err(AnnounceError::HashCollision);
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_and_validate_announce() {
        let id = Identity::new();
        let app_name = "test.announce";

        let announce = AnnounceData::create(&id, app_name, Some(b"hello"), None).unwrap();

        let dest_hash =
            crate::destination::Destination::hash_from_name_and_identity(app_name, Some(&id.hash));

        let validated_id = announce.validate(&dest_hash).unwrap();
        assert_eq!(validated_id.hash, id.hash);
    }

    #[test]
    fn explicit_wire_time_uses_exact_40_bit_value() {
        let id = Identity::new();
        let wire_time = 0x12_3456_789Au64;
        let announce = AnnounceData::create_at(&id, "test.time", None, None, wire_time).unwrap();
        assert_eq!(&announce.random_hash[5..], &wire_time.to_be_bytes()[3..]);

        let maximum = AnnounceData::create_at(&id, "test.time", None, None, ANNOUNCE_TIME_MAX);
        assert!(maximum.is_ok());
        assert!(matches!(
            AnnounceData::create_at(&id, "test.time", None, None, ANNOUNCE_TIME_MAX + 1,),
            Err(AnnounceError::InvalidWireTime(_))
        ));
    }

    #[test]
    fn test_create_and_validate_with_ratchet() {
        let id = Identity::new();
        let ratchet_pub = rns_crypto::random::random_32();

        let announce = AnnounceData::create(&id, "test.ratchet", None, Some(&ratchet_pub)).unwrap();
        assert!(announce.ratchet.is_some());

        let dest_hash = crate::destination::Destination::hash_from_name_and_identity(
            "test.ratchet",
            Some(&id.hash),
        );
        announce.validate(&dest_hash).unwrap();
    }

    #[test]
    fn test_pack_unpack_roundtrip() {
        let id = Identity::new();
        let announce = AnnounceData::create(&id, "test.pack", Some(b"data"), None).unwrap();
        let packed = announce.pack();
        let unpacked = AnnounceData::unpack(&packed, false).unwrap();

        assert_eq!(announce.public_key, unpacked.public_key);
        assert_eq!(announce.name_hash, unpacked.name_hash);
        assert_eq!(announce.random_hash, unpacked.random_hash);
        assert_eq!(announce.signature, unpacked.signature);
        assert_eq!(announce.app_data, unpacked.app_data);
    }

    #[test]
    fn test_pack_unpack_with_ratchet() {
        let id = Identity::new();
        let ratchet = rns_crypto::random::random_32();
        let announce = AnnounceData::create(&id, "test.pack", None, Some(&ratchet)).unwrap();
        let packed = announce.pack();
        let unpacked = AnnounceData::unpack(&packed, true).unwrap();

        assert_eq!(announce.ratchet, unpacked.ratchet);
        assert_eq!(announce.signature, unpacked.signature);
    }

    #[test]
    fn test_tampered_signature_fails() {
        let id = Identity::new();
        let mut announce = AnnounceData::create(&id, "test.tamper", None, None).unwrap();
        announce.signature[0] ^= 0xFF;

        let dest_hash = crate::destination::Destination::hash_from_name_and_identity(
            "test.tamper",
            Some(&id.hash),
        );
        assert!(announce.validate(&dest_hash).is_err());
    }

    #[test]
    fn test_wrong_dest_hash_fails() {
        let id = Identity::new();
        let announce = AnnounceData::create(&id, "test.wrong", None, None).unwrap();

        let wrong_hash = [0xFF; 16];
        assert!(announce.validate(&wrong_hash).is_err());
    }

    #[test]
    fn test_announce_too_short() {
        assert!(AnnounceData::unpack(&[0u8; 10], false).is_err());
    }

    #[test]
    fn test_hash_collision_defense_same_key_accepted() {
        let id = Identity::new();
        let app_name = "test.collision";
        let announce = AnnounceData::create(&id, app_name, None, None).unwrap();
        let dest_hash =
            crate::destination::Destination::hash_from_name_and_identity(app_name, Some(&id.hash));
        let known_key = id.get_public_key();
        assert!(
            announce
                .validate_with_known_key(&dest_hash, Some(&known_key))
                .is_ok()
        );
    }

    #[test]
    fn test_hash_collision_defense_different_key_rejected() {
        let id = Identity::new();
        let app_name = "test.collision2";
        let announce = AnnounceData::create(&id, app_name, None, None).unwrap();
        let dest_hash =
            crate::destination::Destination::hash_from_name_and_identity(app_name, Some(&id.hash));
        let other_id = Identity::new();
        let other_key = other_id.get_public_key();
        let result = announce.validate_with_known_key(&dest_hash, Some(&other_key));
        assert!(matches!(result, Err(AnnounceError::HashCollision)));
    }

    #[test]
    fn test_hash_collision_defense_no_known_key_accepted() {
        let id = Identity::new();
        let app_name = "test.collision3";
        let announce = AnnounceData::create(&id, app_name, None, None).unwrap();
        let dest_hash =
            crate::destination::Destination::hash_from_name_and_identity(app_name, Some(&id.hash));
        assert!(announce.validate_with_known_key(&dest_hash, None).is_ok());
    }

    use proptest::prelude::*;

    type AnnounceBytes = (
        [u8; 64],         // public_key
        [u8; 10],         // name_hash
        [u8; 10],         // random_hash
        [u8; 64],         // signature
        Option<[u8; 32]>, // ratchet
        Option<Vec<u8>>,  // app_data
    );

    fn any_announce_bytes() -> impl Strategy<Value = AnnounceBytes> {
        (
            any::<[u8; 64]>(),
            any::<[u8; 10]>(),
            any::<[u8; 10]>(),
            any::<[u8; 64]>(),
            proptest::option::of(any::<[u8; 32]>()),
            // Empty app_data is omitted on the wire and parses back as None,
            // so generate only None or Some(non-empty) for a clean roundtrip.
            proptest::option::of(proptest::collection::vec(any::<u8>(), 1..=256)),
        )
    }

    proptest! {
        #[test]
        fn proptest_announce_pack_unpack_roundtrip(
            (public_key, name_hash, random_hash, signature, ratchet, app_data)
                in any_announce_bytes(),
        ) {
            let has_ratchet = ratchet.is_some();
            let announce = AnnounceData {
                public_key,
                name_hash,
                random_hash,
                ratchet,
                signature,
                app_data: app_data.clone(),
            };

            let packed = announce.pack();
            let unpacked = AnnounceData::unpack(&packed, has_ratchet).unwrap();

            prop_assert_eq!(unpacked.public_key, public_key);
            prop_assert_eq!(unpacked.name_hash, name_hash);
            prop_assert_eq!(unpacked.random_hash, random_hash);
            prop_assert_eq!(unpacked.ratchet, ratchet);
            prop_assert_eq!(unpacked.signature, signature);
            prop_assert_eq!(&unpacked.app_data, &app_data);

            // Canonical form: re-pack must yield identical bytes.
            prop_assert_eq!(unpacked.pack(), packed);
        }
    }
}
