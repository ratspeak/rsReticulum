//! A security key's ECDH shared secret, and what is derived from it, must not
//! survive in freed heap memory.

#[path = "../../rns-crypto/tests/residue/mod.rs"]
mod residue;

use residue::{assert_no_residue, freed_by, pseudo_random, serial};
use rns_crypto::ed25519::Ed25519PrivateKey;
use rns_crypto::hkdf::derive_key_64;
use rns_crypto::x25519::{X25519PrivateKey, X25519PublicKey};
use rns_ratkey::apdu::SLOT_KEY_MANAGEMENT;
use rns_ratkey::detect::DeviceType;
use rns_ratkey::{DeviceMeta, HardwareIdentity, PivSession, PivTransport, RatkeyError};
use zeroize::Zeroizing;

/// Answers GENERAL AUTHENTICATE with the X25519 shared secret of its key and
/// the peer key in the command, as a token does.
struct EcdhToken {
    key: X25519PrivateKey,
}

impl PivTransport for EcdhToken {
    fn transmit(&mut self, apdu: &[u8]) -> Result<Vec<u8>, RatkeyError> {
        let mut response = Vec::with_capacity(38);
        if apdu[1] == 0x87 {
            let peer: [u8; 32] = apdu[apdu.len() - 32..].try_into().unwrap();
            let shared = Zeroizing::new(self.key.exchange(&X25519PublicKey::from_bytes(&peer)));
            response.extend_from_slice(&[0x7c, 0x22, 0x82, 0x20]);
            response.extend_from_slice(&*shared);
        }
        response.extend_from_slice(&[0x90, 0x00]);
        Ok(response)
    }

    fn is_connected(&self) -> bool {
        true
    }
}

fn session(key: X25519PrivateKey) -> PivSession<EcdhToken> {
    PivSession::new(
        EcdhToken { key },
        DeviceMeta {
            device_type: DeviceType::YubiKey5,
            serial: None,
            firmware: None,
        },
    )
}

#[test]
fn piv_ecdh_frees_no_shared_secret() {
    let _serial = serial();
    let key = X25519PrivateKey::from_bytes(&pseudo_random(40));
    let peer = X25519PrivateKey::from_bytes(&pseudo_random(41))
        .public_key()
        .to_bytes();
    let expected = Zeroizing::new(key.exchange(&X25519PublicKey::from_bytes(&peer)));
    let mut session = session(key);

    let ((), freed) = freed_by(|| {
        let shared = Zeroizing::new(session.ecdh_x25519(SLOT_KEY_MANAGEMENT, &peer).unwrap());
        assert_eq!(*shared, *expected);
    });

    assert_no_residue(&freed, &[("shared secret", &expected[..])]);
}

#[test]
fn hardware_decrypt_frees_no_shared_secret_or_plaintext() {
    let _serial = serial();
    let x25519: [u8; 32] = pseudo_random(42);
    let key = X25519PrivateKey::from_bytes(&x25519);
    let x25519_public = key.public_key().to_bytes();
    let ed25519_public = Ed25519PrivateKey::from_bytes(&pseudo_random(43))
        .public_key()
        .to_bytes();
    let mut hardware =
        HardwareIdentity::from_keys(ed25519_public, x25519_public, Box::new(session(key))).unwrap();
    let plaintext: [u8; 100] = pseudo_random(44);
    let ciphertext = hardware.identity.encrypt(&plaintext, None).unwrap();
    let shared = Zeroizing::new(X25519PrivateKey::from_bytes(&x25519).exchange(
        &X25519PublicKey::from_bytes(ciphertext[..32].try_into().unwrap()),
    ));
    let derived = derive_key_64(&*shared, &hardware.identity.hash).unwrap();

    let ((), freed) = freed_by(|| {
        let decrypted = Zeroizing::new(hardware.decrypt(&ciphertext, None, false).unwrap());
        assert_eq!(&decrypted[..], &plaintext[..]);
    });

    assert_no_residue(
        &freed,
        &[
            ("shared secret", &shared[..]),
            ("derived key", &derived[..]),
            ("plaintext", &plaintext),
        ],
    );
}
