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

/// Parsed announce fields; parsing alone does not authenticate them.
/// Call [`Self::validate`] or [`Self::validate_with_known_key`] before learning
/// a destination. Replay, age and ingress policy belong to the caller.
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
    /// The `random_hash` is `random(5) || timestamp_be(5)`, using current Unix
    /// seconds. This supplies randomness and ordering information; replay
    /// rejection requires receiver state and is not performed by this type.
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

    /// Create and sign an announce with an explicit 40-bit ordering value.
    /// The caller manages persistence before transmission, and manages rotation
    /// and expiry clocks separately. No state is persisted by this method.
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
    /// field is not self-delimiting. This checks minimum length only; use the
    /// validation methods before trusting a parsed announce.
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
    /// after [`Self::verify_signature`] has succeeded. Pass the identity
    /// returned by that call; this method does not repeat signature validation.
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
        if let Some(known_key) = known_public_key
            && known_key != &self.public_key
        {
            tracing::error!(
                dest = hex::encode(packet_dest_hash),
                "announce has valid signature and destination hash, but public key \
                         differs from already known key — possible hash collision attack, rejecting"
            );
            return Err(AnnounceError::HashCollision);
        }

        Ok(())
    }
}

/// Trailing announce stamp extension: marker, flags, stamp, lr_cost (Identity.py:86-90).
pub const ANNOUNCE_EXT_LENGTH: usize = 18;
pub const ANNOUNCE_EXT_HEADER_LENGTH: usize = 2;
pub const ANNOUNCE_EXT_MARKER: u8 = 0xC1;

/// A known-format stamp extension, borrowed from the announce app_data.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct AnnounceExt<'a> {
    pub flags: u8,
    pub stamp: &'a [u8; crate::stamps::NETWORK_STAMP_SIZE],
    pub lr_cost: f64,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum AnnounceExtParse<'a> {
    /// Fewer than 18 bytes of app_data.
    Absent,
    /// Wrong marker, reserved anchor bit set, or lr_cost above the cap.
    Unknown,
    Present(AnnounceExt<'a>),
}

/// Parse the last 18 bytes of app_data as a stamp extension (Identity.py:840-856).
pub fn parse_announce_ext(app_data: Option<&[u8]>) -> AnnounceExtParse<'_> {
    let Some(app_data) = app_data else {
        return AnnounceExtParse::Absent;
    };
    if app_data.len() < ANNOUNCE_EXT_LENGTH {
        return AnnounceExtParse::Absent;
    }
    let ext = &app_data[app_data.len() - ANNOUNCE_EXT_LENGTH..];
    let anchor = ext[ANNOUNCE_EXT_LENGTH - 1];
    let extended = anchor & 0x80 != 0;
    let lr_cost = crate::stamps::cost_from_bytes([anchor & 0x7F, ext[ANNOUNCE_EXT_LENGTH - 2]]);
    if ext[0] != ANNOUNCE_EXT_MARKER || extended || lr_cost > crate::stamps::STAMP_COST_CAP {
        return AnnounceExtParse::Unknown;
    }
    let stamp = ext[ANNOUNCE_EXT_HEADER_LENGTH
        ..ANNOUNCE_EXT_HEADER_LENGTH + crate::stamps::NETWORK_STAMP_SIZE]
        .try_into()
        .expect("slice is exactly the stamp length");
    AnnounceExtParse::Present(AnnounceExt {
        flags: ext[1],
        stamp,
        lr_cost,
    })
}

/// Outcome of the announce stamp check, as upstream records it.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct AnnounceStampCheck {
    /// A known-format extension was present.
    pub stamped: bool,
    /// The stamp met the required value; the extension is stripped.
    pub validated: bool,
    /// Recorded for any known-format extension, valid or not.
    pub stamp: Option<[u8; crate::stamps::NETWORK_STAMP_SIZE]>,
    pub value: Option<f64>,
    /// Recorded only when the stamp is valid.
    pub lr_cost: Option<f64>,
}

impl AnnounceStampCheck {
    /// The app_data upstream remembers and hands to handlers: the extension is
    /// removed only when the stamp validated, and empty app_data becomes `None`.
    pub fn app_data<'a>(&self, raw_app_data: Option<&'a [u8]>) -> Option<&'a [u8]> {
        let data = raw_app_data?;
        let data = if self.validated {
            &data[..data.len() - ANNOUNCE_EXT_LENGTH]
        } else {
            data
        };
        (!data.is_empty()).then_some(data)
    }
}

impl AnnounceData {
    /// Check the stamp extension against `required_value` (Identity.py:840-870).
    /// The workblock is `destination_hash || public_key || name_hash`, unexpanded.
    pub fn check_stamp(
        &self,
        destination_hash: &[u8; 16],
        required_value: f64,
    ) -> AnnounceStampCheck {
        let mut check = AnnounceStampCheck::default();
        let AnnounceExtParse::Present(ext) = parse_announce_ext(self.app_data.as_deref()) else {
            return check;
        };
        check.stamped = true;
        check.stamp = Some(*ext.stamp);
        let mut material = [0u8; 16 + PUBKEY_SIZE + NAME_HASH_SIZE];
        material[..16].copy_from_slice(destination_hash);
        material[16..16 + PUBKEY_SIZE].copy_from_slice(&self.public_key);
        material[16 + PUBKEY_SIZE..].copy_from_slice(&self.name_hash);
        match crate::stamps::stamp_valid(ext.stamp, required_value, &material) {
            Ok(valid) => {
                check.value = Some(crate::stamps::stamp_value(&material, ext.stamp));
                if valid {
                    check.validated = true;
                    check.lr_cost = Some(ext.lr_cost);
                }
            }
            Err(e) => tracing::error!(error = %e, "announce stamp parsing failed"),
        }
        check
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

    fn ext(marker: u8, anchor: u8, frac: u8) -> Vec<u8> {
        let mut data = b"app".to_vec();
        data.extend_from_slice(&[marker, 0x00]);
        data.extend_from_slice(&[0x5A; 14]);
        data.extend_from_slice(&[frac, anchor]);
        data
    }

    #[test]
    fn extension_needs_eighteen_trailing_bytes() {
        assert_eq!(parse_announce_ext(None), AnnounceExtParse::Absent);
        let data = ext(ANNOUNCE_EXT_MARKER, 12, 0x80);
        assert_eq!(
            parse_announce_ext(Some(&data[4..])),
            AnnounceExtParse::Absent
        );
        assert!(matches!(
            parse_announce_ext(Some(&data[3..])),
            AnnounceExtParse::Present(_)
        ));
        assert!(matches!(
            parse_announce_ext(Some(&data)),
            AnnounceExtParse::Present(_)
        ));
    }

    #[test]
    fn extension_fields_are_read_from_the_tail() {
        let data = ext(ANNOUNCE_EXT_MARKER, 12, 0x80);
        let AnnounceExtParse::Present(parsed) = parse_announce_ext(Some(&data)) else {
            panic!("extension not parsed");
        };
        assert_eq!(parsed.stamp, &[0x5A; 14]);
        assert_eq!(parsed.lr_cost, 12.5);
        assert_eq!(parsed.flags, 0);
    }

    #[test]
    fn unknown_marker_reserved_bit_and_excess_cost_are_unknown_format() {
        for data in [
            ext(0xC0, 12, 0),
            ext(ANNOUNCE_EXT_MARKER, 0x80 | 12, 0),
            ext(ANNOUNCE_EXT_MARKER, 100, 1),
        ] {
            assert_eq!(parse_announce_ext(Some(&data)), AnnounceExtParse::Unknown);
        }
        assert!(matches!(
            parse_announce_ext(Some(&ext(ANNOUNCE_EXT_MARKER, 100, 0))),
            AnnounceExtParse::Present(p) if p.lr_cost == 100.0
        ));
    }

    #[test]
    fn invalid_stamp_is_recorded_but_app_data_is_kept() {
        let id = Identity::new();
        let data = ext(ANNOUNCE_EXT_MARKER, 12, 0x80);
        let announce = AnnounceData::create(&id, "test.stamp", Some(&data), None).unwrap();
        let dest = crate::destination::Destination::hash_from_name_and_identity(
            "test.stamp",
            Some(&id.hash),
        );
        let check = announce.check_stamp(&dest, 100.0);
        assert!(check.stamped && !check.validated);
        assert_eq!(check.stamp, Some([0x5A; 14]));
        assert!(check.value.is_some());
        assert_eq!(check.lr_cost, None);
        assert_eq!(check.app_data(Some(&data)), Some(&data[..]));
    }

    #[test]
    fn valid_stamp_strips_extension_and_records_link_cost() {
        let id = Identity::new();
        let data = ext(ANNOUNCE_EXT_MARKER, 12, 0x80);
        let announce = AnnounceData::create(&id, "test.stamp", Some(&data), None).unwrap();
        let dest = crate::destination::Destination::hash_from_name_and_identity(
            "test.stamp",
            Some(&id.hash),
        );
        let check = announce.check_stamp(&dest, 0.0);
        assert!(check.stamped && check.validated);
        assert_eq!(check.lr_cost, Some(12.5));
        assert_eq!(check.app_data(Some(&data)), Some(&b"app"[..]));
        assert_eq!(check.app_data(Some(&data[3..])), None);
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
