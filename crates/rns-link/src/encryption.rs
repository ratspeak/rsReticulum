use crate::key_derivation::LinkKeys;
use zeroize::Zeroizing;

/// Encrypt a plaintext frame with the link's session keys.
///
/// Wire format: `IV(16) || AES-CBC(PKCS7(pt)) || HMAC-SHA256(32)`.
pub fn link_encrypt(keys: &LinkKeys, plaintext: &[u8]) -> Result<Vec<u8>, LinkCryptoError> {
    // Token keying is signing(32) || encryption(32); Zeroizing wipes it on drop.
    let mut combined_key = Zeroizing::new(Vec::with_capacity(
        keys.signing_key.len() + keys.encryption_key.len(),
    ));
    combined_key.extend_from_slice(&keys.signing_key);
    combined_key.extend_from_slice(&keys.encryption_key);

    rns_crypto::token::encrypt(plaintext, &combined_key)
        .map_err(|_| LinkCryptoError::EncryptionFailed)
}

/// Decrypt a ciphertext frame with the link's session keys.
///
/// All token errors map to `DecryptionFailed`, so the error value does not
/// distinguish padding, HMAC, or key-length failure. This error mapping alone
/// is not a guarantee of identical execution time for every invalid input.
pub fn link_decrypt(keys: &LinkKeys, ciphertext: &[u8]) -> Result<Vec<u8>, LinkCryptoError> {
    let mut combined_key = Zeroizing::new(Vec::with_capacity(
        keys.signing_key.len() + keys.encryption_key.len(),
    ));
    combined_key.extend_from_slice(&keys.signing_key);
    combined_key.extend_from_slice(&keys.encryption_key);

    rns_crypto::token::decrypt(ciphertext, &combined_key)
        .map_err(|_| LinkCryptoError::DecryptionFailed)
}

#[derive(Debug, thiserror::Error)]
pub enum LinkCryptoError {
    #[error("encryption failed")]
    EncryptionFailed,
    #[error("decryption failed")]
    DecryptionFailed,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::MODE_AES256_CBC;
    use crate::key_derivation::LinkKeys;
    use rns_crypto::x25519::X25519PrivateKey;

    fn make_test_keys() -> (LinkKeys, LinkKeys) {
        let prv_a = X25519PrivateKey::generate();
        let pub_a = prv_a.public_key();
        let prv_b = X25519PrivateKey::generate();
        let pub_b = prv_b.public_key();
        let link_id = [0x42; 16];
        let keys_a = LinkKeys::derive(&prv_a, &pub_b, &link_id, MODE_AES256_CBC).unwrap();
        let keys_b = LinkKeys::derive(&prv_b, &pub_a, &link_id, MODE_AES256_CBC).unwrap();
        (keys_a, keys_b)
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let (keys_a, keys_b) = make_test_keys();
        let plaintext = b"Hello, Reticulum Link!";
        let ct = link_encrypt(&keys_a, plaintext).unwrap();
        let pt = link_decrypt(&keys_b, &ct).unwrap();
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn test_bidirectional() {
        let (keys_a, keys_b) = make_test_keys();

        // A -> B
        let msg1 = b"from A to B";
        let ct1 = link_encrypt(&keys_a, msg1).unwrap();
        let pt1 = link_decrypt(&keys_b, &ct1).unwrap();
        assert_eq!(pt1, msg1);

        // B -> A uses the same keys: the link is symmetric.
        let msg2 = b"from B to A";
        let ct2 = link_encrypt(&keys_b, msg2).unwrap();
        let pt2 = link_decrypt(&keys_a, &ct2).unwrap();
        assert_eq!(pt2, msg2);
    }

    #[test]
    fn test_wrong_keys_fail() {
        let (keys_a, _) = make_test_keys();
        let prv = X25519PrivateKey::generate();
        let pub_key = X25519PrivateKey::generate().public_key();
        let wrong_keys = LinkKeys::derive(&prv, &pub_key, &[0xFF; 16], MODE_AES256_CBC).unwrap();

        let ct = link_encrypt(&keys_a, b"secret").unwrap();
        assert!(link_decrypt(&wrong_keys, &ct).is_err());
    }

    #[test]
    fn test_tampered_ciphertext() {
        let (keys_a, keys_b) = make_test_keys();
        let mut ct = link_encrypt(&keys_a, b"test").unwrap();
        ct[20] ^= 0xFF;
        assert!(link_decrypt(&keys_b, &ct).is_err());
    }

    #[test]
    fn test_empty_plaintext() {
        let (keys_a, keys_b) = make_test_keys();
        let ct = link_encrypt(&keys_a, b"").unwrap();
        let pt = link_decrypt(&keys_b, &ct).unwrap();
        assert_eq!(pt, b"");
    }
}
