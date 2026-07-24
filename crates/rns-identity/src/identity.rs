use rns_crypto::ed25519::{Ed25519Error, Ed25519PrivateKey, Ed25519PublicKey};
use rns_crypto::hkdf::derive_key_64;
use rns_crypto::sha::truncated_hash;
use rns_crypto::token;
use rns_crypto::x25519::{X25519PrivateKey, X25519PublicKey};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

use crate::persistence;
use std::fmt;
use std::path::Path;
use std::sync::Arc;

/// Elliptic curve used for identity encryption and ratchets.
pub const CURVE: &str = "Curve25519";
/// Combined X25519 and Ed25519 public/private key size, in bits.
pub const KEY_SIZE_BITS: usize = 512;
/// X25519 ratchet key size, in bits.
pub const RATCHET_SIZE_BITS: usize = 256;
/// Addressable identity hash size, in bits.
pub const HASH_LENGTH_BITS: usize = 128;
/// Ratchet identifier size, in bytes.
pub const RATCHET_ID_LENGTH: usize = 10;
/// HKDF-derived key length: 32 bytes AES key || 32 bytes HMAC key.
pub const DERIVED_KEY_LENGTH: usize = 64;

/// Per-message overhead of `Identity::encrypt` before PKCS7 padding:
/// ephemeral X25519 public (32) + Token framing (48).
pub const IDENTITY_OVERHEAD: usize = 32 + rns_crypto::TOKEN_OVERHEAD;

#[derive(Debug, Error)]
pub enum IdentityError {
    #[error("invalid private key length: expected 64, got {0}")]
    InvalidPrivateKeyLength(usize),
    #[error("invalid public key length: expected 64, got {0}")]
    InvalidPublicKeyLength(usize),
    #[error("signature verification failed")]
    VerificationFailed,
    #[error("decryption failed")]
    DecryptionFailed,
    #[error("ed25519 error: {0}")]
    Ed25519(#[from] Ed25519Error),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

/// Delegate for an `Identity` whose private key is not in memory (e.g. a PIV
/// hardware token). Implemented outside this crate (see `rns-ratkey`). Both
/// operations must produce standard output — RFC 8032 Ed25519 / RFC 7748 X25519
/// — so the resulting identity is wire-identical to a software one.
pub trait LocalKeyBackend: Send + Sync {
    /// Ed25519 signature over `message`, or `None` if currently unavailable.
    fn sign_ed25519(&self, message: &[u8]) -> Option<[u8; 64]>;
    /// X25519 ECDH shared secret with `peer_pub`, or `None` if unavailable.
    fn ecdh(&self, peer_pub: &[u8; 32]) -> Option<[u8; 32]>;
    /// Drop any cached authentication so the next operation must re-authenticate
    /// (e.g. a hardware token re-locks its PIN). No-op for software backends.
    fn lock(&self) {}
}

/// A Reticulum identity: X25519 keypair for encryption + Ed25519 keypair for signing.
///
/// Wire representation:
/// - Private (64 B): `X25519_prv(32) || Ed25519_seed(32)`
/// - Public  (64 B): `X25519_pub(32) || Ed25519_pub(32)`
/// - Hash   (16 B): `SHA-256(public_64)[:16]`
pub struct Identity {
    prv: Option<X25519PrivateKey>,
    sig_prv: Option<Ed25519PrivateKey>,
    pub_key: X25519PublicKey,
    sig_pub: Ed25519PublicKey,
    pub hash: [u8; 16],
    /// Set only for hardware-backed identities; `None` for all software ones.
    backend: Option<Arc<dyn LocalKeyBackend>>,
}

/// Successful identity decryption plus the ratchet that authenticated it.
///
/// `ratchet_id` is absent when the identity's base key performed decryption.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecryptionResult {
    pub plaintext: Vec<u8>,
    pub ratchet_id: Option<[u8; RATCHET_ID_LENGTH]>,
}

impl Clone for Identity {
    /// Software identities clone their key material; hardware-backed identities
    /// share the same `LocalKeyBackend` (Arc) — there is no extractable key to copy.
    fn clone(&self) -> Self {
        Self {
            prv: self
                .prv
                .as_ref()
                .map(|k| X25519PrivateKey::from_bytes(&k.to_bytes())),
            sig_prv: self
                .sig_prv
                .as_ref()
                .map(|k| Ed25519PrivateKey::from_bytes(&k.to_bytes())),
            pub_key: self.pub_key.clone(),
            sig_pub: self.sig_pub.clone(),
            hash: self.hash,
            backend: self.backend.clone(),
        }
    }
}

impl Default for Identity {
    fn default() -> Self {
        Self::new()
    }
}

impl Identity {
    pub const CURVE: &'static str = CURVE;
    pub const KEY_SIZE_BITS: usize = KEY_SIZE_BITS;
    pub const RATCHET_SIZE_BITS: usize = RATCHET_SIZE_BITS;
    pub const HASH_LENGTH_BITS: usize = HASH_LENGTH_BITS;

    pub fn new() -> Self {
        let prv = X25519PrivateKey::generate();
        let sig_prv = Ed25519PrivateKey::generate();
        let pub_key = prv.public_key();
        let sig_pub = sig_prv.public_key();
        let hash = Self::compute_hash(&pub_key, &sig_pub);

        Self {
            prv: Some(prv),
            sig_prv: Some(sig_prv),
            pub_key,
            sig_pub,
            hash,
            backend: None,
        }
    }

    pub fn from_private_key(key: &[u8]) -> Result<Self, IdentityError> {
        if key.len() != 64 {
            return Err(IdentityError::InvalidPrivateKeyLength(key.len()));
        }
        let mut x_bytes = Zeroizing::new([0u8; 32]);
        x_bytes.copy_from_slice(&key[..32]);
        let mut ed_bytes = Zeroizing::new([0u8; 32]);
        ed_bytes.copy_from_slice(&key[32..]);

        let prv = X25519PrivateKey::from_bytes(&x_bytes);
        let sig_prv = Ed25519PrivateKey::from_bytes(&ed_bytes);
        let pub_key = prv.public_key();
        let sig_pub = sig_prv.public_key();
        let hash = Self::compute_hash(&pub_key, &sig_pub);

        Ok(Self {
            prv: Some(prv),
            sig_prv: Some(sig_prv),
            pub_key,
            sig_pub,
            hash,
            backend: None,
        })
    }

    /// Construct a verify/encrypt-only identity from its 64-byte public key.
    pub fn from_public_key(key: &[u8]) -> Result<Self, IdentityError> {
        if key.len() != 64 {
            return Err(IdentityError::InvalidPublicKeyLength(key.len()));
        }
        let mut x_bytes = [0u8; 32];
        x_bytes.copy_from_slice(&key[..32]);
        let mut ed_bytes = [0u8; 32];
        ed_bytes.copy_from_slice(&key[32..]);

        let pub_key = X25519PublicKey::from_bytes(&x_bytes);
        let sig_pub = Ed25519PublicKey::from_bytes(&ed_bytes)?;
        let hash = Self::compute_hash(&pub_key, &sig_pub);

        Ok(Self {
            prv: None,
            sig_prv: None,
            pub_key,
            sig_pub,
            hash,
            backend: None,
        })
    }

    /// Construct an identity whose private operations are served by `backend`
    /// (e.g. a hardware token). Public-key-only in memory; `sign` and `decrypt`
    /// delegate to the backend. Wire-identical to a software identity.
    pub fn from_backend(
        public_key: &[u8],
        backend: Arc<dyn LocalKeyBackend>,
    ) -> Result<Self, IdentityError> {
        let mut id = Self::from_public_key(public_key)?;
        id.backend = Some(backend);
        Ok(id)
    }

    /// Load an identity from file, accepting either the current msgpack envelope
    /// or a legacy raw 64-byte private key.
    pub fn from_file(path: &Path) -> Result<Self, IdentityError> {
        let data = std::fs::read(path)?;

        if let Ok(persisted) = rmp_serde::from_slice::<IdentityPersisted>(&data) {
            return Self::from_private_key(&persisted.private_key);
        }

        Self::from_private_key(&data)
    }

    /// Persist the identity as the raw 64-byte private key used by the Python
    /// reference implementation, so identity files are interchangeable.
    pub fn to_file(&self, path: &Path) -> Result<(), IdentityError> {
        let key = self
            .get_private_key()
            .ok_or(IdentityError::DecryptionFailed)?;
        persistence::atomic_write(path, &*key)?;
        Ok(())
    }

    /// Persist the raw 64-byte public key used by Python `rnid -x/-w`.
    pub fn pub_to_file(&self, path: &Path) -> Result<(), IdentityError> {
        persistence::atomic_write(path, &self.get_public_key())?;
        Ok(())
    }

    /// Return the 64-byte private key (`X25519_prv || Ed25519_seed`), zeroised on drop.
    pub fn get_private_key(&self) -> Option<Zeroizing<[u8; 64]>> {
        let prv = self.prv.as_ref()?;
        let sig_prv = self.sig_prv.as_ref()?;
        let mut key = Zeroizing::new([0u8; 64]);
        key[..32].copy_from_slice(&prv.to_bytes());
        key[32..].copy_from_slice(&sig_prv.to_bytes());
        Some(key)
    }

    /// Return the 64-byte public key (`X25519_pub || Ed25519_pub`).
    pub fn get_public_key(&self) -> [u8; 64] {
        let mut key = [0u8; 64];
        key[..32].copy_from_slice(&self.pub_key.to_bytes());
        key[32..].copy_from_slice(&self.sig_pub.to_bytes());
        key
    }

    /// Lowercase, delimiter-free hexadecimal identity hash.
    pub fn hexhash(&self) -> String {
        hex::encode(self.hash)
    }

    pub fn has_private_key(&self) -> bool {
        self.prv.is_some() && self.sig_prv.is_some()
    }

    /// True if private operations are served by a hardware backend.
    pub fn has_backend(&self) -> bool {
        self.backend.is_some()
    }

    /// Re-lock the hardware backend (drop its cached authentication). No-op for
    /// software identities. The next private operation will fail until re-auth.
    pub fn lock(&self) {
        if let Some(b) = self.backend.as_ref() {
            b.lock();
        }
    }

    pub fn get_signing_key(&self) -> Option<Ed25519PrivateKey> {
        self.sig_prv
            .as_ref()
            .map(|k| Ed25519PrivateKey::from_bytes(&k.to_bytes()))
    }

    /// Sign `message` with the Ed25519 key, delegating to the hardware backend
    /// when the in-memory key is absent; `None` if neither is available.
    pub fn sign(&self, message: &[u8]) -> Option<[u8; 64]> {
        match self.sig_prv.as_ref() {
            Some(key) => Some(key.sign(message)),
            None => self.backend.as_ref().and_then(|b| b.sign_ed25519(message)),
        }
    }

    pub fn verify(&self, message: &[u8], signature: &[u8; 64]) -> bool {
        self.sig_pub.verify(message, signature).is_ok()
    }

    /// Encrypt `plaintext` for this identity using ECIES.
    ///
    /// Output layout: `ephemeral_X25519_pub(32) || IV(16) || AES-256-CBC(PKCS7(pt)) || HMAC(32)`.
    ///
    /// Passing a `ratchet` public key substitutes it for the identity's X25519
    /// public key in the ECDH, giving forward secrecy against later key
    /// compromise.
    pub fn encrypt(
        &self,
        plaintext: &[u8],
        ratchet: Option<&[u8; 32]>,
    ) -> Result<Vec<u8>, IdentityError> {
        let ephemeral = X25519PrivateKey::generate();
        let ephemeral_pub = ephemeral.public_key();

        let target = match ratchet {
            Some(r) => X25519PublicKey::from_bytes(r),
            None => self.pub_key.clone(),
        };

        let mut shared = ephemeral.exchange(&target);
        let derived =
            derive_key_64(&shared, &self.hash).map_err(|_| IdentityError::DecryptionFailed);
        shared.zeroize();
        let derived = derived?;
        let ciphertext =
            token::encrypt(plaintext, &derived).map_err(|_| IdentityError::DecryptionFailed)?;

        let mut result = Vec::with_capacity(32 + ciphertext.len());
        result.extend_from_slice(&ephemeral_pub.to_bytes());
        result.extend_from_slice(&ciphertext);
        Ok(result)
    }

    /// Decrypt ciphertext addressed to this identity, trying each ratchet key
    /// before falling back to the identity key (unless `enforce_ratchets`).
    pub fn decrypt(
        &self,
        ciphertext: &[u8],
        ratchets: Option<&[&[u8; 32]]>,
        enforce_ratchets: bool,
    ) -> Result<Vec<u8>, IdentityError> {
        self.decrypt_with_ratchet_id(ciphertext, ratchets, enforce_ratchets)
            .map(|result| result.plaintext)
    }

    /// Decrypt ciphertext and report the ratchet key that authenticated it.
    ///
    /// The identifier is `SHA-256(ratchet_public_key)[:10]`, matching the
    /// reference implementation. Base-identity decryption returns no ratchet
    /// identifier.
    pub fn decrypt_with_ratchet_id(
        &self,
        ciphertext: &[u8],
        ratchets: Option<&[&[u8; 32]]>,
        enforce_ratchets: bool,
    ) -> Result<DecryptionResult, IdentityError> {
        if ciphertext.len() < 32 {
            return Err(IdentityError::DecryptionFailed);
        }

        let mut peer_pub_bytes = [0u8; 32];
        peer_pub_bytes.copy_from_slice(&ciphertext[..32]);
        let peer_pub = X25519PublicKey::from_bytes(&peer_pub_bytes);
        let ct = &ciphertext[32..];

        if let Some(ratchets) = ratchets {
            for ratchet in ratchets {
                let ratchet_prv = X25519PrivateKey::from_bytes(ratchet);
                let mut shared = ratchet_prv.exchange(&peer_pub);
                let derived_result = derive_key_64(&shared, &self.hash);
                shared.zeroize();
                if let Ok(derived) = derived_result {
                    if let Ok(plaintext) = token::decrypt(ct, &derived) {
                        return Ok(DecryptionResult {
                            plaintext,
                            ratchet_id: Some(Self::ratchet_id(
                                &ratchet_prv.public_key().to_bytes(),
                            )),
                        });
                    }
                }
            }
        }

        if enforce_ratchets {
            return Err(IdentityError::DecryptionFailed);
        }

        // Identity-key ECDH: in-memory key if present, else the hardware backend.
        let mut shared: [u8; 32] = if let Some(prv) = self.prv.as_ref() {
            prv.exchange(&peer_pub)
        } else if let Some(backend) = self.backend.as_ref() {
            backend
                .ecdh(&peer_pub_bytes)
                .ok_or(IdentityError::DecryptionFailed)?
        } else {
            return Err(IdentityError::DecryptionFailed);
        };
        let derived_result =
            derive_key_64(&shared, &self.hash).map_err(|_| IdentityError::DecryptionFailed);
        shared.zeroize();
        let derived = derived_result?;
        let plaintext =
            token::decrypt(ct, &derived).map_err(|_| IdentityError::DecryptionFailed)?;
        Ok(DecryptionResult {
            plaintext,
            ratchet_id: None,
        })
    }

    /// Derive the stable 80-bit identifier for a ratchet public key.
    pub fn ratchet_id(ratchet_public_key: &[u8; 32]) -> [u8; RATCHET_ID_LENGTH] {
        let full = rns_crypto::sha::sha256(ratchet_public_key);
        let mut id = [0u8; RATCHET_ID_LENGTH];
        id.copy_from_slice(&full[..RATCHET_ID_LENGTH]);
        id
    }

    /// Sign `packet_hash` and return proof bytes.
    ///
    /// `implicit_proof = true` returns the 64-byte signature alone; `false`
    /// returns `packet_hash(32) || signature(64)` (96 bytes).
    pub fn prove(
        &self,
        packet_hash: &[u8],
        implicit_proof: bool,
    ) -> Result<Vec<u8>, IdentityError> {
        let signature = self
            .sign(packet_hash)
            .ok_or(IdentityError::DecryptionFailed)?;

        if implicit_proof {
            Ok(signature.to_vec())
        } else {
            let mut proof_data = Vec::with_capacity(packet_hash.len() + 64);
            proof_data.extend_from_slice(packet_hash);
            proof_data.extend_from_slice(&signature);
            Ok(proof_data)
        }
    }

    fn compute_hash(pub_key: &X25519PublicKey, sig_pub: &Ed25519PublicKey) -> [u8; 16] {
        let mut combined = [0u8; 64];
        combined[..32].copy_from_slice(&pub_key.to_bytes());
        combined[32..].copy_from_slice(&sig_pub.to_bytes());
        truncated_hash(&combined)
    }
}

impl fmt::Display for Identity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "<{}>", self.hexhash())
    }
}

// Msgpack envelope wrapping the raw 64-byte private key on disk.
#[derive(Serialize, Deserialize)]
struct IdentityPersisted {
    private_key: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_identity() {
        let id = Identity::new();
        assert!(id.has_private_key());
        assert_ne!(id.hash, [0u8; 16]);
    }

    #[test]
    fn test_private_key_roundtrip() {
        let id1 = Identity::new();
        let prv = id1.get_private_key().unwrap();
        let id2 = Identity::from_private_key(&*prv).unwrap();
        assert_eq!(id1.hash, id2.hash);
        assert_eq!(id1.get_public_key(), id2.get_public_key());
    }

    #[test]
    fn test_public_key_roundtrip() {
        let id1 = Identity::new();
        let pub_key = id1.get_public_key();
        let id2 = Identity::from_public_key(&pub_key).unwrap();
        assert_eq!(id1.hash, id2.hash);
        assert!(!id2.has_private_key());
    }

    #[test]
    fn test_sign_verify() {
        let id = Identity::new();
        let msg = b"hello reticulum";
        let sig = id.sign(msg).unwrap();
        assert!(id.verify(msg, &sig));
    }

    #[test]
    fn test_sign_verify_wrong_message() {
        let id = Identity::new();
        let sig = id.sign(b"correct").unwrap();
        assert!(!id.verify(b"wrong", &sig));
    }

    #[test]
    fn test_encrypt_decrypt() {
        let id = Identity::new();
        let plaintext = b"secret message";
        let ct = id.encrypt(plaintext, None).unwrap();
        let pt = id.decrypt(&ct, None, false).unwrap();
        assert_eq!(&pt, plaintext);
    }

    #[test]
    fn test_encrypt_decrypt_with_ratchet() {
        let id = Identity::new();
        let ratchet_prv = rns_crypto::x25519::X25519PrivateKey::generate();
        let ratchet_pub = ratchet_prv.public_key().to_bytes();
        let ratchet_prv_bytes = ratchet_prv.to_bytes();

        let plaintext = b"ratcheted message";
        let ct = id.encrypt(plaintext, Some(&ratchet_pub)).unwrap();

        assert!(id.decrypt(&ct, None, false).is_err());

        let ratchets: Vec<&[u8; 32]> = vec![&ratchet_prv_bytes];
        let decrypted = id
            .decrypt_with_ratchet_id(&ct, Some(&ratchets), false)
            .unwrap();
        assert_eq!(&decrypted.plaintext, plaintext);
        assert_eq!(
            decrypted.ratchet_id,
            Some(Identity::ratchet_id(&ratchet_pub))
        );
    }

    #[test]
    fn base_identity_decryption_reports_no_ratchet() {
        let id = Identity::new();
        let ciphertext = id.encrypt(b"base identity", None).unwrap();
        let decrypted = id
            .decrypt_with_ratchet_id(&ciphertext, None, false)
            .unwrap();

        assert_eq!(decrypted.plaintext, b"base identity");
        assert_eq!(decrypted.ratchet_id, None);
    }

    #[test]
    fn identity_metadata_and_display_match_wire_identity() {
        let id = Identity::new();

        assert_eq!(CURVE, "Curve25519");
        assert_eq!(KEY_SIZE_BITS, id.get_public_key().len() * 8);
        assert_eq!(RATCHET_SIZE_BITS, 32 * 8);
        assert_eq!(HASH_LENGTH_BITS, id.hash.len() * 8);
        assert_eq!(id.hexhash(), hex::encode(id.hash));
        assert_eq!(id.to_string(), format!("<{}>", hex::encode(id.hash)));
    }

    #[test]
    fn test_cross_identity_encrypt_decrypt() {
        let sender = Identity::new();
        let receiver = Identity::new();

        let plaintext = b"from sender to receiver";
        let ct = receiver.encrypt(plaintext, None).unwrap();
        let pt = receiver.decrypt(&ct, None, false).unwrap();
        assert_eq!(&pt, plaintext);

        assert!(sender.decrypt(&ct, None, false).is_err());
    }

    #[test]
    fn test_public_key_only_cannot_sign() {
        let id = Identity::new();
        let pub_id = Identity::from_public_key(&id.get_public_key()).unwrap();
        assert!(pub_id.sign(b"test").is_none());
    }

    #[test]
    fn test_hash_is_truncated_sha256() {
        let id = Identity::new();
        let full = rns_crypto::sha::sha256(&id.get_public_key());
        assert_eq!(&id.hash[..], &full[..16]);
    }

    #[test]
    fn test_file_roundtrip() {
        let dir = std::env::temp_dir().join("reticulum_identity_test_msgpack");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("test_identity");

        let id1 = Identity::new();
        id1.to_file(&path).unwrap();
        let id2 = Identity::from_file(&path).unwrap();

        assert_eq!(id1.hash, id2.hash);
        assert_eq!(id1.get_public_key(), id2.get_public_key());
        assert_eq!(id1.get_private_key(), id2.get_private_key());

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn test_file_backward_compat_raw() {
        let dir = std::env::temp_dir().join("reticulum_identity_test_compat");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("raw_identity");

        let id1 = Identity::new();
        let key = id1.get_private_key().unwrap();
        // Legacy format: raw 64-byte private key, no msgpack envelope.
        std::fs::write(&path, &key).unwrap();

        let id2 = Identity::from_file(&path).unwrap();
        assert_eq!(id1.hash, id2.hash);
        assert_eq!(id1.get_public_key(), id2.get_public_key());

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn test_public_file_roundtrip() {
        let dir = std::env::temp_dir().join("reticulum_identity_test_public");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("identity.pub");

        let id1 = Identity::new();
        id1.pub_to_file(&path).unwrap();
        let data = std::fs::read(&path).unwrap();
        let id2 = Identity::from_public_key(&data).unwrap();

        assert_eq!(id1.hash, id2.hash);
        assert_eq!(id1.get_public_key(), id2.get_public_key());
        assert!(!id2.has_private_key());

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn test_prove_implicit() {
        let id = Identity::new();
        let packet_hash = rns_crypto::sha::sha256(b"test packet");

        let proof = id.prove(&packet_hash, true).unwrap();
        assert_eq!(proof.len(), 64);
        let mut sig = [0u8; 64];
        sig.copy_from_slice(&proof);
        assert!(id.verify(&packet_hash, &sig));
    }

    #[test]
    fn test_prove_explicit() {
        let id = Identity::new();
        let packet_hash = rns_crypto::sha::sha256(b"test packet");

        let proof = id.prove(&packet_hash, false).unwrap();
        assert_eq!(proof.len(), 32 + 64);
        assert_eq!(&proof[..32], &packet_hash);
        let mut sig = [0u8; 64];
        sig.copy_from_slice(&proof[32..]);
        assert!(id.verify(&packet_hash, &sig));
    }

    #[test]
    fn test_prove_no_private_key_fails() {
        let id = Identity::new();
        let pub_id = Identity::from_public_key(&id.get_public_key()).unwrap();
        assert!(pub_id.prove(b"test", true).is_err());
    }

    // A software-keyed backend, standing in for a hardware token in tests.
    struct SoftwareBackend {
        sig: rns_crypto::ed25519::Ed25519PrivateKey,
        x: rns_crypto::x25519::X25519PrivateKey,
    }
    impl LocalKeyBackend for SoftwareBackend {
        fn sign_ed25519(&self, message: &[u8]) -> Option<[u8; 64]> {
            Some(self.sig.sign(message))
        }
        fn ecdh(&self, peer_pub: &[u8; 32]) -> Option<[u8; 32]> {
            let peer = rns_crypto::x25519::X25519PublicKey::from_bytes(peer_pub);
            Some(self.x.exchange(&peer))
        }
    }

    #[test]
    fn test_backend_identity_is_wire_identical() {
        use std::sync::Arc;

        // Build a backend from a software identity's keys, then a separate
        // backend-driven identity over the same public key.
        let sw = Identity::new();
        let prv = sw.get_private_key().unwrap();
        let mut x_bytes = [0u8; 32];
        x_bytes.copy_from_slice(&prv[..32]);
        let mut ed_bytes = [0u8; 32];
        ed_bytes.copy_from_slice(&prv[32..]);
        let backend = Arc::new(SoftwareBackend {
            sig: rns_crypto::ed25519::Ed25519PrivateKey::from_bytes(&ed_bytes),
            x: rns_crypto::x25519::X25519PrivateKey::from_bytes(&x_bytes),
        });

        let hw = Identity::from_backend(&sw.get_public_key(), backend).unwrap();

        // Same identity, but no extractable in-memory key.
        assert_eq!(hw.hash, sw.hash);
        assert!(!hw.has_private_key());
        assert!(hw.get_private_key().is_none());

        // sign() delegates and is byte-identical (Ed25519 is deterministic).
        let msg = b"hardware parity";
        assert_eq!(hw.sign(msg), sw.sign(msg));
        assert!(hw.verify(msg, &hw.sign(msg).unwrap()));

        // decrypt() delegates the ECDH to the backend; round-trips, and the
        // software identity decrypts the same ciphertext (identical key material).
        let ct = hw.encrypt(b"secret payload", None).unwrap();
        assert_eq!(hw.decrypt(&ct, None, false).unwrap(), b"secret payload");
        assert_eq!(sw.decrypt(&ct, None, false).unwrap(), b"secret payload");
    }
}
