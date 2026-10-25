//! Plaintext and key material must not survive in freed heap memory.

mod residue;

use residue::{assert_no_residue, freed_by, pseudo_random, serial};
use rns_crypto::{aes_cbc, hkdf, hmac, token};
use zeroize::Zeroizing;

#[test]
fn token_encrypt_frees_no_plaintext() {
    let _serial = serial();
    let key: [u8; 64] = pseudo_random(1);
    let plaintext: [u8; 100] = pseudo_random(2);

    let (token, freed) = freed_by(|| token::encrypt(&plaintext, &key).unwrap());

    assert_no_residue(&freed, &[("plaintext", &plaintext)]);
    assert_eq!(
        &Zeroizing::new(token::decrypt(&token, &key).unwrap())[..],
        &plaintext[..]
    );
}

#[test]
fn token_decrypt_frees_no_plaintext() {
    let _serial = serial();
    let key: [u8; 64] = pseudo_random(3);
    let plaintext: [u8; 100] = pseudo_random(4);
    let token = token::encrypt(&plaintext, &key).unwrap();

    let ((), freed) = freed_by(|| {
        let decrypted = Zeroizing::new(token::decrypt(&token, &key).unwrap());
        assert_eq!(&decrypted[..], &plaintext[..]);
    });

    assert_no_residue(&freed, &[("plaintext", &plaintext)]);
}

#[test]
fn token_decrypt_wipes_an_authenticated_plaintext_with_bad_padding() {
    let _serial = serial();
    let key: [u8; 64] = pseudo_random(5);
    let mut plaintext: [u8; 64] = pseudo_random(6);
    plaintext[63] = 0;
    let iv = [0x24u8; 16];
    let mut token = iv.to_vec();
    token.extend_from_slice(&aes_cbc::encrypt(&key[32..], &iv, &plaintext).unwrap());
    let mac = hmac::hmac_sha256(&key[..32], &token);
    token.extend_from_slice(&mac);

    let (result, freed) = freed_by(|| token::decrypt(&token, &key));

    assert!(matches!(
        result,
        Err(token::TokenError::AuthenticationFailed)
    ));
    assert_no_residue(&freed, &[("plaintext", &plaintext[..63])]);
}

#[test]
fn aes_cbc_encrypt_with_a_bad_key_frees_no_plaintext() {
    let _serial = serial();
    let plaintext: [u8; 64] = pseudo_random(7);

    let (result, freed) = freed_by(|| aes_cbc::encrypt(&[0x11; 24], &[0x22; 16], &plaintext));

    assert!(matches!(
        result,
        Err(aes_cbc::AesCbcError::InvalidKeyLength(24))
    ));
    assert_no_residue(&freed, &[("plaintext", &plaintext)]);
}

#[test]
fn derive_key_64_frees_no_key() {
    let _serial = serial();
    let shared: [u8; 32] = pseudo_random(8);
    let salt: [u8; 16] = pseudo_random(9);
    let expected = Zeroizing::new(hkdf::hkdf_sha256(64, &shared, Some(&salt), None).unwrap());

    let (derived, freed): (Zeroizing<[u8; 64]>, _) =
        freed_by(|| hkdf::derive_key_64(&shared, &salt).unwrap());

    assert_eq!(&derived[..], &expected[..]);
    assert_no_residue(&freed, &[("derived key", &expected)]);
}

#[test]
fn hkdf_output_is_wiped_when_dropped() {
    let _serial = serial();
    let ikm: [u8; 32] = pseudo_random(10);
    let salt: [u8; 16] = pseudo_random(11);
    let expected = hkdf::derive_key_64(&ikm, &salt).unwrap();

    let ((), freed) = freed_by(|| {
        let okm: Zeroizing<Vec<u8>> = hkdf::hkdf_sha256(64, &ikm, Some(&salt), None).unwrap();
        assert_eq!(&okm[..], &expected[..]);
    });

    assert_no_residue(&freed, &[("HKDF output", &expected[..])]);
}
