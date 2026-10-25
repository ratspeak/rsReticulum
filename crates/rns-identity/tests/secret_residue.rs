//! Private keys, derived keys and plaintext must not survive in freed heap
//! memory when identities are stored, loaded and used.

#[path = "../../rns-crypto/tests/residue/mod.rs"]
mod residue;

use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};

use residue::{assert_no_residue, freed_by, holds, pseudo_random, serial};
use rns_crypto::hkdf::hkdf_sha256;
use rns_crypto::sha::sha256;
use rns_crypto::x25519::{X25519PrivateKey, X25519PublicKey};
use rns_identity::identity::Identity;
use rns_identity::ifac::derive_ifac_key;
use rns_identity::ratchet::RatchetRing;
use zeroize::Zeroizing;

struct TempDir(PathBuf);

impl TempDir {
    fn new(label: &str) -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let path = std::env::temp_dir().join(format!(
            "rns-residue-{label}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&path).unwrap();
        Self(path)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn derived_key(private: &[u8; 32], ephemeral_public: &[u8], salt: &[u8]) -> Zeroizing<Vec<u8>> {
    let private = X25519PrivateKey::from_bytes(private);
    let public = X25519PublicKey::from_bytes(ephemeral_public.try_into().unwrap());
    let shared = Zeroizing::new(private.exchange(&public));
    hkdf_sha256(64, &*shared, Some(salt), None).unwrap()
}

#[test]
fn identity_to_file_frees_no_key() {
    let _serial = serial();
    let dir = TempDir::new("to-file");
    let key: [u8; 64] = pseudo_random(11);
    let identity = Identity::from_private_key(&key).unwrap();
    let path = dir.0.join("identity");

    let ((), freed) = freed_by(|| identity.to_file(&path).unwrap());

    assert_no_residue(&freed, &[("private key", &key)]);
    assert_eq!(std::fs::read(&path).unwrap(), key);
}

#[test]
fn identity_from_file_frees_no_key() {
    let _serial = serial();
    let dir = TempDir::new("from-file");
    let key: [u8; 64] = pseudo_random(12);
    let expected = Identity::from_private_key(&key).unwrap().hash;
    let path = dir.0.join("identity");
    std::fs::write(&path, key).unwrap();

    let (identity, freed) = freed_by(|| Identity::from_file(&path).unwrap());

    assert_no_residue(&freed, &[("private key", &key)]);
    assert_eq!(identity.hash, expected);
}

#[test]
fn identity_from_file_with_a_msgpack_looking_key_frees_no_key() {
    let _serial = serial();
    let dir = TempDir::new("from-file-msgpack-prefix");
    // A one-field array holding a long integer array: a parse of this key as
    // an envelope runs out of input partway through.
    let mut key = [0u8; 64];
    key[..4].copy_from_slice(&[0x91, 0xdc, 0xff, 0xff]);
    let tail: [u8; 60] = pseudo_random(13);
    for (out, byte) in key[4..].iter_mut().zip(tail) {
        *out = byte & 0x7f;
    }
    let expected = Identity::from_private_key(&key).unwrap().hash;
    let path = dir.0.join("identity");
    std::fs::write(&path, key).unwrap();

    let (identity, freed) = freed_by(|| Identity::from_file(&path).unwrap());

    assert_no_residue(&freed, &[("private key", &key[4..])]);
    assert_eq!(identity.hash, expected);
}

#[test]
fn identity_from_envelope_file_frees_no_key() {
    #[derive(serde::Serialize)]
    struct Envelope {
        private_key: Vec<u8>,
    }

    let _serial = serial();
    let dir = TempDir::new("from-envelope");
    let key: [u8; 64] = pseudo_random(14);
    let expected = Identity::from_private_key(&key).unwrap().hash;
    let envelope = Envelope {
        private_key: key.to_vec(),
    };
    for (name, bytes) in [
        ("named", rmp_serde::to_vec_named(&envelope).unwrap()),
        ("compact", rmp_serde::to_vec(&envelope).unwrap()),
    ] {
        let path = dir.0.join(name);
        std::fs::write(&path, bytes).unwrap();

        let (identity, freed) = freed_by(|| Identity::from_file(&path).unwrap());

        assert_no_residue(&freed, &[("private key", &key)]);
        assert_eq!(identity.hash, expected, "{name} envelope");
    }
}

#[test]
fn identity_from_file_refuses_an_oversize_file_without_reading_it_whole() {
    let _serial = serial();
    let dir = TempDir::new("from-file-oversize");
    let path = dir.0.join("identity");
    std::fs::write(&path, vec![0xc1; 1 << 20]).unwrap();

    let (result, freed) = freed_by(|| Identity::from_file(&path));

    assert!(result.is_err());
    assert!(
        freed.peak_allocation < 64 * 1024,
        "loading allocated {} bytes",
        freed.peak_allocation
    );
}

#[test]
fn identity_encrypt_frees_no_plaintext_or_key() {
    let _serial = serial();
    let key: [u8; 64] = pseudo_random(15);
    let identity = Identity::from_private_key(&key).unwrap();
    let plaintext: [u8; 100] = pseudo_random(16);

    let (ciphertext, freed) = freed_by(|| identity.encrypt(&plaintext, None).unwrap());

    let derived = derived_key(
        key[..32].try_into().unwrap(),
        &ciphertext[..32],
        &identity.hash,
    );
    assert_no_residue(
        &freed,
        &[("plaintext", &plaintext), ("derived key", &derived)],
    );
}

#[test]
fn identity_decrypt_frees_no_plaintext_or_key() {
    let _serial = serial();
    let key: [u8; 64] = pseudo_random(17);
    let identity = Identity::from_private_key(&key).unwrap();
    let plaintext: [u8; 100] = pseudo_random(18);
    let ciphertext = identity.encrypt(&plaintext, None).unwrap();
    let derived = derived_key(
        key[..32].try_into().unwrap(),
        &ciphertext[..32],
        &identity.hash,
    );

    let ((), freed) = freed_by(|| {
        let decrypted = Zeroizing::new(identity.decrypt(&ciphertext, None, false).unwrap());
        assert_eq!(&decrypted[..], &plaintext[..]);
    });

    assert_no_residue(
        &freed,
        &[("plaintext", &plaintext), ("derived key", &derived)],
    );
}

#[test]
fn identity_ratchet_decrypt_frees_no_plaintext_or_key() {
    let _serial = serial();
    let key: [u8; 64] = pseudo_random(19);
    let identity = Identity::from_private_key(&key).unwrap();
    let ratchet: [u8; 32] = pseudo_random(20);
    let ratchet_public = X25519PrivateKey::from_bytes(&ratchet)
        .public_key()
        .to_bytes();
    let plaintext: [u8; 100] = pseudo_random(21);
    let ciphertext = identity.encrypt(&plaintext, Some(&ratchet_public)).unwrap();
    let derived = derived_key(&ratchet, &ciphertext[..32], &identity.hash);

    let ((), freed) = freed_by(|| {
        let ratchets = [&ratchet];
        let decrypted = identity
            .decrypt_with_ratchet_id(&ciphertext, Some(&ratchets), true)
            .unwrap();
        let plaintext_copy = Zeroizing::new(decrypted.plaintext);
        assert_eq!(&plaintext_copy[..], &plaintext[..]);
    });

    assert_no_residue(
        &freed,
        &[
            ("plaintext", &plaintext),
            ("derived key", &derived),
            ("ratchet key", &ratchet),
        ],
    );
}

#[test]
fn ratchet_ring_save_and_load_free_no_ratchet_keys() {
    let _serial = serial();
    let dir = TempDir::new("ratchets");
    let identity = Identity::from_private_key(&pseudo_random::<64>(22)).unwrap();
    let mut ring = RatchetRing::new();
    for _ in 0..200 {
        ring.rotate();
    }
    let keys = Zeroizing::new(ring.private_keys().concat());
    let path = dir.0.join("ratchets");

    let ((), saved) = freed_by(|| ring.save_verified(&path, &identity).unwrap());
    let (loaded, read) = freed_by(|| RatchetRing::load_verified(&path, &identity).unwrap());

    let mut found = Vec::new();
    for (stage, freed) in [("save", &saved), ("load", &read)] {
        let sizes: Vec<usize> = freed
            .blocks
            .iter()
            .filter(|block| keys.chunks(32).any(|key| holds(block, key)))
            .map(Vec::len)
            .collect();
        if !sizes.is_empty() {
            found.push(format!(
                "{stage}: ratchet keys in freed blocks of {sizes:?} bytes"
            ));
        }
    }
    assert!(found.is_empty(), "secret residue: {found:?}");
    assert_eq!(loaded.ring().private_keys(), ring.private_keys());
}

#[test]
fn ifac_key_derivation_frees_no_key() {
    let _serial = serial();
    let passphrase = "correct horse battery staple";

    let (key, freed) = freed_by(|| derive_ifac_key(Some("residue"), Some(passphrase)).unwrap());

    assert_no_residue(
        &freed,
        &[
            ("IFAC key", &key),
            ("passphrase hash", &sha256(passphrase.as_bytes())),
        ],
    );
}
