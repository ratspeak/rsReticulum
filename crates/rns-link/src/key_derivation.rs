use rns_crypto::x25519::{X25519PrivateKey, X25519PublicKey};
use zeroize::Zeroize;

use crate::constants::{
    AES128_DERIVED_KEY_LENGTH, AES256_DERIVED_KEY_LENGTH, MODE_AES128_CBC, MODE_AES256_CBC,
};

/// Derived session keys for a link.
#[derive(Clone)]
pub struct LinkKeys {
    /// HMAC-SHA256 signing key.
    pub signing_key: Vec<u8>,
    /// AES encryption key.
    pub encryption_key: Vec<u8>,
}

impl LinkKeys {
    /// Derive link session keys from an ECDH exchange.
    ///
    /// Runs `HKDF-SHA256(ECDH(my_prv, peer_pub), salt = link_id)` and splits the
    /// output into `signing_key || encryption_key`. Intermediate shared secrets
    /// are zeroized as soon as HKDF consumes them.
    pub fn derive(
        my_prv: &X25519PrivateKey,
        peer_pub: &X25519PublicKey,
        link_id: &[u8; 16],
        mode: u8,
    ) -> Result<Self, LinkKeyError> {
        let derived_key_length = match mode {
            MODE_AES128_CBC => AES128_DERIVED_KEY_LENGTH,
            MODE_AES256_CBC => AES256_DERIVED_KEY_LENGTH,
            _ => return Err(LinkKeyError::UnsupportedMode(mode)),
        };

        let mut shared_key = my_prv.exchange(peer_pub);

        let derived_result =
            rns_crypto::hkdf::hkdf_sha256(derived_key_length, &shared_key, Some(link_id), None)
                .map_err(|_| LinkKeyError::HkdfFailed);
        shared_key.zeroize();
        let derived = derived_result?;

        let half = derived_key_length / 2;
        let signing_key = derived[..half].to_vec();
        let encryption_key = derived[half..].to_vec();

        Ok(Self {
            signing_key,
            encryption_key,
        })
    }
}

impl Drop for LinkKeys {
    fn drop(&mut self) {
        self.signing_key.zeroize();
        self.encryption_key.zeroize();
    }
}

#[derive(Debug, thiserror::Error)]
pub enum LinkKeyError {
    #[error("unsupported encryption mode: {0}")]
    UnsupportedMode(u8),
    #[error("HKDF key derivation failed")]
    HkdfFailed,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_aes256() {
        let prv_a = X25519PrivateKey::generate();
        let pub_a = prv_a.public_key();
        let prv_b = X25519PrivateKey::generate();
        let pub_b = prv_b.public_key();
        let link_id = [0xAA; 16];

        let keys_a = LinkKeys::derive(&prv_a, &pub_b, &link_id, MODE_AES256_CBC).unwrap();
        let keys_b = LinkKeys::derive(&prv_b, &pub_a, &link_id, MODE_AES256_CBC).unwrap();

        assert_eq!(keys_a.signing_key, keys_b.signing_key);
        assert_eq!(keys_a.encryption_key, keys_b.encryption_key);
        assert_eq!(keys_a.signing_key.len(), 32);
        assert_eq!(keys_a.encryption_key.len(), 32);
    }

    #[test]
    fn test_derive_different_link_ids() {
        let prv_a = X25519PrivateKey::generate();
        let pub_b = X25519PrivateKey::generate().public_key();

        let keys1 = LinkKeys::derive(&prv_a, &pub_b, &[0x01; 16], MODE_AES256_CBC).unwrap();
        let keys2 = LinkKeys::derive(&prv_a, &pub_b, &[0x02; 16], MODE_AES256_CBC).unwrap();

        assert_ne!(keys1.signing_key, keys2.signing_key);
        assert_ne!(keys1.encryption_key, keys2.encryption_key);
    }

    #[test]
    fn test_unsupported_mode() {
        let prv = X25519PrivateKey::generate();
        let pub_key = prv.public_key();
        let result = LinkKeys::derive(&prv, &pub_key, &[0; 16], 0xFF);
        assert!(result.is_err());
    }
}
