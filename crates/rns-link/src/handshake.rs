use rns_crypto::ed25519::{Ed25519PrivateKey, Ed25519PublicKey};
use rns_crypto::sha::truncated_hash;
use rns_crypto::x25519::{X25519PrivateKey, X25519PublicKey};
use zeroize::Zeroize;

use crate::constants::{DEFAULT_MODE, ECPUBSIZE, LINK_MTU_SIZE};
use crate::key_derivation::{LinkKeyError, LinkKeys};
use crate::mtu_discovery::SignallingData;

/// Ephemeral key pair generated per link (initiator or responder).
///
/// The inner `X25519PrivateKey` and `Ed25519PrivateKey` zeroize themselves;
/// the `Drop` impl below propagates that through the composite struct.
pub struct EphemeralKeys {
    pub x25519_prv: X25519PrivateKey,
    pub x25519_pub: X25519PublicKey,
    pub ed25519_prv: Ed25519PrivateKey,
    pub ed25519_pub: Ed25519PublicKey,
}

impl Zeroize for EphemeralKeys {
    fn zeroize(&mut self) {
        self.x25519_prv.zeroize();
        self.ed25519_prv.zeroize();
    }
}

impl Drop for EphemeralKeys {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl EphemeralKeys {
    /// Generate a fresh ephemeral key pair for link establishment.
    pub fn generate() -> Self {
        let x25519_prv = X25519PrivateKey::generate();
        let x25519_pub = x25519_prv.public_key();
        let ed25519_prv = Ed25519PrivateKey::generate();
        let ed25519_pub = ed25519_prv.public_key();
        Self {
            x25519_prv,
            x25519_pub,
            ed25519_prv,
            ed25519_pub,
        }
    }
}

/// Link request payload (Message 1: initiator -> destination).
///
/// Wire format: `X25519_pub(32) || Ed25519_pub(32) || signalling(3)` — 67 bytes.
#[derive(Debug, Clone)]
pub struct LinkRequestData {
    pub peer_x25519_pub: [u8; 32],
    pub peer_ed25519_pub: [u8; 32],
    pub signalling: SignallingData,
}

impl LinkRequestData {
    /// Serialize as `x25519_pub(32) || ed25519_pub(32) || signalling(3)`.
    pub fn pack(keys: &EphemeralKeys, signalling: SignallingData) -> Vec<u8> {
        let mut data = Vec::with_capacity(ECPUBSIZE + LINK_MTU_SIZE);
        data.extend_from_slice(&keys.x25519_pub.to_bytes());
        data.extend_from_slice(&keys.ed25519_pub.to_bytes());
        data.extend_from_slice(&signalling.pack());
        data
    }

    /// Parse a link request payload.
    ///
    /// Python accepts exactly the legacy 64-byte key payload or the modern
    /// 67-byte key payload with signalling. Other lengths are dropped.
    pub fn unpack(data: &[u8]) -> Result<Self, HandshakeError> {
        if data.len() < ECPUBSIZE {
            return Err(HandshakeError::TooShort);
        }
        if data.len() != ECPUBSIZE && data.len() != ECPUBSIZE + LINK_MTU_SIZE {
            return Err(HandshakeError::InvalidLength(data.len()));
        }

        rns_wire::link_signalling::parse_request_signalling(data)?;
        let mut x25519_pub = [0u8; 32];
        x25519_pub.copy_from_slice(&data[0..32]);

        let mut ed25519_pub = [0u8; 32];
        ed25519_pub.copy_from_slice(&data[32..64]);

        let signalling = if data.len() == ECPUBSIZE + LINK_MTU_SIZE {
            SignallingData::unpack(&data[ECPUBSIZE..ECPUBSIZE + LINK_MTU_SIZE]).unwrap_or(
                SignallingData::new(DEFAULT_MODE, rns_wire::constants::MTU as u32),
            )
        } else {
            SignallingData::new(DEFAULT_MODE, rns_wire::constants::MTU as u32)
        };

        Ok(Self {
            peer_x25519_pub: x25519_pub,
            peer_ed25519_pub: ed25519_pub,
            signalling,
        })
    }
}

/// Compute the link ID from a link request.
///
/// The hashable body is `flags_low_nibble || dest_hash || context || data[..ECPUBSIZE]`
/// — the signalling trailer is intentionally excluded so both sides agree on the same
/// link ID regardless of MTU/mode negotiation.
pub fn compute_link_id(destination_hash: &[u8; 16], request_data: &[u8]) -> [u8; 16] {
    // LinkRequest(0x02) | DestinationType::Single(0x00); context is PacketContext::None.
    let flags_low_nibble = 0x02u8;
    let context = 0x00u8;

    let data_len = request_data.len().min(ECPUBSIZE);
    let mut hashable = Vec::with_capacity(1 + 16 + 1 + data_len);
    hashable.push(flags_low_nibble);
    hashable.extend_from_slice(destination_hash);
    hashable.push(context);
    hashable.extend_from_slice(&request_data[..data_len]);

    truncated_hash(&hashable)
}

/// Compute the link ID from a full raw packet (for transport relay paths).
pub fn compute_link_id_from_raw(raw: &[u8], header_type: rns_wire::flags::HeaderType) -> [u8; 16] {
    rns_wire::hash::link_id_from_raw(raw, header_type)
}

/// Link proof payload (Message 2: destination -> initiator).
///
/// Wire format: `signature(64) || X25519_pub(32) || signalling(3)` — 99 bytes.
/// The signature covers `link_id || responder_x25519_pub || identity_ed25519_pub || signalling`
/// under the destination's long-term identity Ed25519 key.
#[derive(Debug, Clone)]
pub struct LinkProofData {
    pub signature: [u8; 64],
    pub responder_x25519_pub: [u8; 32],
    pub signalling: SignallingData,
}

impl LinkProofData {
    /// Create and sign a link proof.
    ///
    /// The signature binds the link to the destination's long-term identity key, not
    /// the ephemeral responder key — this is what authenticates the responder to the
    /// initiator.
    pub fn create(
        identity_signing_key: &Ed25519PrivateKey,
        responder_x25519_pub: &[u8; 32],
        identity_ed25519_pub: &[u8; 32],
        link_id: &[u8; 16],
        signalling: SignallingData,
    ) -> Self {
        let sig_bytes = signalling.pack();
        let mut signed_data = Vec::with_capacity(16 + 32 + 32 + 3);
        signed_data.extend_from_slice(link_id);
        signed_data.extend_from_slice(responder_x25519_pub);
        signed_data.extend_from_slice(identity_ed25519_pub);
        signed_data.extend_from_slice(&sig_bytes);

        let signature = identity_signing_key.sign(&signed_data);

        Self {
            signature,
            responder_x25519_pub: *responder_x25519_pub,
            signalling,
        }
    }

    /// Create a link proof using an external signer (e.g. YubiKey/PIV).
    ///
    /// Variant of [`LinkProofData::create`] for identities whose private key cannot
    /// be exported — the closure receives the signed-data blob and must return a
    /// 64-byte Ed25519 signature.
    pub fn create_with<F>(
        sign_fn: F,
        responder_x25519_pub: &[u8; 32],
        identity_ed25519_pub: &[u8; 32],
        link_id: &[u8; 16],
        signalling: SignallingData,
    ) -> Self
    where
        F: FnOnce(&[u8]) -> [u8; 64],
    {
        let sig_bytes = signalling.pack();
        let mut signed_data = Vec::with_capacity(16 + 32 + 32 + 3);
        signed_data.extend_from_slice(link_id);
        signed_data.extend_from_slice(responder_x25519_pub);
        signed_data.extend_from_slice(identity_ed25519_pub);
        signed_data.extend_from_slice(&sig_bytes);

        let signature = sign_fn(&signed_data);

        Self {
            signature,
            responder_x25519_pub: *responder_x25519_pub,
            signalling,
        }
    }

    /// Serialize as `signature(64) || responder_x25519_pub(32) || signalling(3)`.
    pub fn pack(&self) -> Vec<u8> {
        let mut data = Vec::with_capacity(64 + 32 + LINK_MTU_SIZE);
        data.extend_from_slice(&self.signature);
        data.extend_from_slice(&self.responder_x25519_pub);
        data.extend_from_slice(&self.signalling.pack());
        data
    }

    /// Parse a proof payload, accepting exactly 96-byte legacy frames or
    /// 99-byte frames with signalling.
    pub fn unpack(data: &[u8]) -> Result<Self, HandshakeError> {
        if data.len() < 96 {
            return Err(HandshakeError::TooShort);
        }
        if data.len() != 96 && data.len() != 96 + LINK_MTU_SIZE {
            return Err(HandshakeError::InvalidLength(data.len()));
        }

        rns_wire::link_signalling::parse_proof_signalling(data)?;
        let mut signature = [0u8; 64];
        signature.copy_from_slice(&data[0..64]);

        let mut responder_pub = [0u8; 32];
        responder_pub.copy_from_slice(&data[64..96]);

        let signalling = if data.len() == 96 + LINK_MTU_SIZE {
            SignallingData::unpack(&data[96..96 + LINK_MTU_SIZE]).unwrap_or(SignallingData::new(
                DEFAULT_MODE,
                rns_wire::constants::MTU as u32,
            ))
        } else {
            SignallingData::new(DEFAULT_MODE, rns_wire::constants::MTU as u32)
        };

        Ok(Self {
            signature,
            responder_x25519_pub: responder_pub,
            signalling,
        })
    }

    /// Verify the proof signature against the destination's identity public key.
    pub fn validate(
        &self,
        identity_verify_key: &Ed25519PublicKey,
        link_id: &[u8; 16],
        peer_ed25519_pub: &[u8; 32],
    ) -> bool {
        let sig_bytes = self.signalling.pack();
        let mut signed_data = Vec::with_capacity(16 + 32 + 32 + 3);
        signed_data.extend_from_slice(link_id);
        signed_data.extend_from_slice(&self.responder_x25519_pub);
        signed_data.extend_from_slice(peer_ed25519_pub);
        signed_data.extend_from_slice(&sig_bytes);

        identity_verify_key
            .verify(&signed_data, &self.signature)
            .is_ok()
    }
}

/// Perform the ECDH handshake and derive session keys.
pub fn perform_handshake(
    my_x25519_prv: &X25519PrivateKey,
    peer_x25519_pub_bytes: &[u8; 32],
    link_id: &[u8; 16],
    mode: u8,
) -> Result<LinkKeys, LinkKeyError> {
    let peer_pub = X25519PublicKey::from_bytes(peer_x25519_pub_bytes);
    LinkKeys::derive(my_x25519_prv, &peer_pub, link_id, mode)
}

#[derive(Debug, thiserror::Error)]
pub enum HandshakeError {
    #[error(transparent)]
    Signalling(#[from] rns_wire::link_signalling::LinkSignallingError),
    #[error("handshake data too short")]
    TooShort,
    #[error("invalid handshake data length: {0}")]
    InvalidLength(usize),
    #[error("invalid signature")]
    InvalidSignature,
    #[error("key derivation failed: {0}")]
    KeyDerivation(#[from] LinkKeyError),
    #[error("unsupported encryption mode: {0}")]
    UnsupportedMode(u8),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_link_request_pack_unpack() {
        let keys = EphemeralKeys::generate();
        let sig = SignallingData::new(1, 500);
        let packed = LinkRequestData::pack(&keys, sig);
        assert_eq!(packed.len(), ECPUBSIZE + LINK_MTU_SIZE);

        let unpacked = LinkRequestData::unpack(&packed).unwrap();
        assert_eq!(unpacked.peer_x25519_pub, keys.x25519_pub.to_bytes());
        assert_eq!(unpacked.peer_ed25519_pub, keys.ed25519_pub.to_bytes());
        assert_eq!(unpacked.signalling.mode, 1);
        assert_eq!(unpacked.signalling.mtu, 500);
    }

    #[test]
    fn test_link_request_unpack_accepts_only_python_lengths() {
        let keys = EphemeralKeys::generate();
        let sig = SignallingData::new(1, 500);
        let modern = LinkRequestData::pack(&keys, sig);

        let legacy = &modern[..ECPUBSIZE];
        let unpacked = LinkRequestData::unpack(legacy).unwrap();
        assert_eq!(unpacked.peer_x25519_pub, keys.x25519_pub.to_bytes());
        assert_eq!(unpacked.peer_ed25519_pub, keys.ed25519_pub.to_bytes());
        assert_eq!(unpacked.signalling.mode, DEFAULT_MODE);
        assert_eq!(unpacked.signalling.mtu, rns_wire::constants::MTU as u32);

        assert!(matches!(
            LinkRequestData::unpack(&modern[..ECPUBSIZE - 1]),
            Err(HandshakeError::TooShort)
        ));
        for len in [ECPUBSIZE + 1, ECPUBSIZE + 2] {
            assert!(matches!(
                LinkRequestData::unpack(&modern[..len]),
                Err(HandshakeError::InvalidLength(actual)) if actual == len
            ));
        }
        let mut over = modern.clone();
        over.push(0xCC);
        assert!(matches!(
            LinkRequestData::unpack(&over),
            Err(HandshakeError::InvalidLength(actual)) if actual == ECPUBSIZE + LINK_MTU_SIZE + 1
        ));
    }

    #[test]
    fn test_link_id_computation() {
        let keys = EphemeralKeys::generate();
        let sig = SignallingData::new(1, 500);
        let packed = LinkRequestData::pack(&keys, sig);
        let dest_hash = [0xAA; 16];

        let link_id = compute_link_id(&dest_hash, &packed);
        assert_eq!(link_id.len(), 16);

        let link_id2 = compute_link_id(&dest_hash, &packed);
        assert_eq!(link_id, link_id2);
    }

    #[test]
    fn test_link_id_excludes_signalling() {
        let keys = EphemeralKeys::generate();
        let dest_hash = [0xBB; 16];

        let sig1 = SignallingData::new(1, 500);
        let packed1 = LinkRequestData::pack(&keys, sig1);

        let sig2 = SignallingData::new(2, 1000);
        let packed2 = LinkRequestData::pack(&keys, sig2);

        // Different signalling, same keys -> same link_id.
        let id1 = compute_link_id(&dest_hash, &packed1);
        let id2 = compute_link_id(&dest_hash, &packed2);
        assert_eq!(id1, id2);
    }

    #[test]
    fn test_link_id_includes_dest_hash() {
        let keys = EphemeralKeys::generate();
        let sig = SignallingData::new(1, 500);
        let packed = LinkRequestData::pack(&keys, sig);

        let id1 = compute_link_id(&[0xAA; 16], &packed);
        let id2 = compute_link_id(&[0xBB; 16], &packed);
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_link_id_from_raw_matches_components() {
        let keys = EphemeralKeys::generate();
        let sig = SignallingData::new(1, 500);
        let request_data = LinkRequestData::pack(&keys, sig);
        let dest_hash = [0xCC; 16];

        // Build a synthetic Header1 packet: LinkRequest + Single, 3 hops, no context.
        let flags = 0x02u8;
        let hops = 3u8;
        let context = 0x00u8;
        let mut raw = Vec::new();
        raw.push(flags);
        raw.push(hops);
        raw.extend_from_slice(&dest_hash);
        raw.push(context);
        raw.extend_from_slice(&request_data);

        let id_components = compute_link_id(&dest_hash, &request_data);
        let id_raw = compute_link_id_from_raw(&raw, rns_wire::flags::HeaderType::Header1);
        assert_eq!(id_components, id_raw);
    }

    #[test]
    fn test_link_proof_create_validate() {
        let identity_key = Ed25519PrivateKey::generate();
        let identity_pub = identity_key.public_key();
        let identity_ed25519_pub = identity_pub.to_bytes();

        let responder_keys = EphemeralKeys::generate();
        let link_id = [0xAB; 16];
        let signalling = SignallingData::new(1, 500);

        let proof = LinkProofData::create(
            &identity_key,
            &responder_keys.x25519_pub.to_bytes(),
            &identity_ed25519_pub,
            &link_id,
            signalling,
        );

        let packed = proof.pack();
        assert_eq!(packed.len(), 99);

        let unpacked = LinkProofData::unpack(&packed).unwrap();

        assert!(unpacked.validate(&identity_pub, &link_id, &identity_ed25519_pub,));
    }

    #[test]
    fn test_link_proof_unpack_accepts_only_python_lengths() {
        let proof = LinkProofData {
            signature: [0xAA; 64],
            responder_x25519_pub: [0xBB; 32],
            signalling: SignallingData::new(1, 500),
        };
        let modern = proof.pack();

        let legacy = LinkProofData::unpack(&modern[..96]).unwrap();
        assert_eq!(legacy.signature, [0xAA; 64]);
        assert_eq!(legacy.responder_x25519_pub, [0xBB; 32]);
        assert_eq!(legacy.signalling.mode, DEFAULT_MODE);
        assert_eq!(legacy.signalling.mtu, rns_wire::constants::MTU as u32);

        assert!(matches!(
            LinkProofData::unpack(&modern[..95]),
            Err(HandshakeError::TooShort)
        ));
        for len in [97, 98] {
            assert!(matches!(
                LinkProofData::unpack(&modern[..len]),
                Err(HandshakeError::InvalidLength(actual)) if actual == len
            ));
        }
        let mut over = modern.clone();
        over.push(0xCC);
        assert!(matches!(
            LinkProofData::unpack(&over),
            Err(HandshakeError::InvalidLength(100))
        ));
    }

    #[test]
    fn test_link_proof_wrong_identity_fails() {
        let identity_key = Ed25519PrivateKey::generate();
        let wrong_key = Ed25519PrivateKey::generate();
        let wrong_pub = wrong_key.public_key();

        let responder_keys = EphemeralKeys::generate();
        let identity_ed25519_pub = identity_key.public_key().to_bytes();
        let link_id = [0xAB; 16];
        let signalling = SignallingData::new(1, 500);

        let proof = LinkProofData::create(
            &identity_key,
            &responder_keys.x25519_pub.to_bytes(),
            &identity_ed25519_pub,
            &link_id,
            signalling,
        );

        assert!(!proof.validate(&wrong_pub, &link_id, &identity_ed25519_pub,));
    }

    #[test]
    fn test_full_handshake_key_agreement() {
        let initiator_keys = EphemeralKeys::generate();
        let signalling = SignallingData::new(1, 500);
        let request_data = LinkRequestData::pack(&initiator_keys, signalling);
        let dest_hash = [0xDD; 16];

        let link_id = compute_link_id(&dest_hash, &request_data);

        let _request = LinkRequestData::unpack(&request_data).unwrap();
        let responder_keys = EphemeralKeys::generate();

        let initiator_session = perform_handshake(
            &initiator_keys.x25519_prv,
            &responder_keys.x25519_pub.to_bytes(),
            &link_id,
            DEFAULT_MODE,
        )
        .unwrap();

        let responder_session = perform_handshake(
            &responder_keys.x25519_prv,
            &initiator_keys.x25519_pub.to_bytes(),
            &link_id,
            DEFAULT_MODE,
        )
        .unwrap();

        assert_eq!(initiator_session.signing_key, responder_session.signing_key);
        assert_eq!(
            initiator_session.encryption_key,
            responder_session.encryption_key
        );
    }

    use proptest::prelude::*;

    proptest! {
        /// LinkRequest round-trip over arbitrary key + signalling input.
        /// The wire layout is `x25519_pub(32) || ed25519_pub(32) ||
        /// signalling(3)`, so pack → unpack → re-pack must be stable for
        /// any bit pattern in the key fields (we don't need valid curve
        /// points — the wire codec doesn't care).
        #[test]
        fn proptest_link_request_pack_unpack_roundtrip(
            x25519_pub: [u8; 32],
            ed25519_pub: [u8; 32],
            mode in 0u8..=7,
            mtu in prop_oneof![Just(0u32), 500u32..=crate::constants::MTU_BYTEMASK],
        ) {
            let signalling = SignallingData::new(mode, mtu);
            // EphemeralKeys is the higher-level wrapper; we pack the
            // bytes directly here to avoid generating live ECDH keys in
            // the property loop.
            let mut data = Vec::with_capacity(ECPUBSIZE + LINK_MTU_SIZE);
            data.extend_from_slice(&x25519_pub);
            data.extend_from_slice(&ed25519_pub);
            data.extend_from_slice(&signalling.pack());

            let unpacked = LinkRequestData::unpack(&data).unwrap();
            prop_assert_eq!(unpacked.peer_x25519_pub, x25519_pub);
            prop_assert_eq!(unpacked.peer_ed25519_pub, ed25519_pub);
            prop_assert_eq!(unpacked.signalling, signalling);
        }

        /// LinkProof round-trip. Wire: `signature(64) || x25519_pub(32) ||
        /// signalling(3)` = 99 bytes. Like the request, we skip signature
        /// validity and only check the packing byte layout — validity is
        /// covered by the non-proptest tests.
        #[test]
        fn proptest_link_proof_pack_unpack_roundtrip(
            signature: [u8; 64],
            responder_x25519_pub: [u8; 32],
            mode in 0u8..=7,
            mtu in prop_oneof![Just(0u32), 500u32..=crate::constants::MTU_BYTEMASK],
        ) {
            let signalling = SignallingData::new(mode, mtu);
            let proof = LinkProofData {
                signature,
                responder_x25519_pub,
                signalling,
            };
            let packed = proof.pack();
            prop_assert_eq!(packed.len(), 64 + 32 + LINK_MTU_SIZE);

            let unpacked = LinkProofData::unpack(&packed).unwrap();
            prop_assert_eq!(unpacked.signature, signature);
            prop_assert_eq!(unpacked.responder_x25519_pub, responder_x25519_pub);
            prop_assert_eq!(unpacked.signalling, signalling);
            prop_assert_eq!(unpacked.pack(), packed);
        }

        /// The representation packer remains permissive, but both handshake
        /// parsers reject every nonzero offer below the supported Link floor.
        #[test]
        fn proptest_handshake_rejects_sub_base_mtu(mode in 0u8..=7, mtu in 1u32..500) {
            let signalling = SignallingData::new(mode, mtu).pack();
            let mut request = vec![0u8; ECPUBSIZE];
            request.extend_from_slice(&signalling);
            prop_assert!(LinkRequestData::unpack(&request).is_err());
            let mut proof = vec![0u8; 96];
            proof.extend_from_slice(&signalling);
            prop_assert!(LinkProofData::unpack(&proof).is_err());
        }
    }
}
