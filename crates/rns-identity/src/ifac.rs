use rns_crypto::hkdf::hkdf_sha256;
use rns_crypto::sha::sha256;
use thiserror::Error;

/// Fixed IFAC HKDF salt shared with the Python reference.
///
/// This is public for applications that need to derive or inspect
/// Python-compatible IFAC material outside the runtime helper. Changing it
/// would break interoperability.
pub const IFAC_SALT: &str = "adf54d882c9a9b80771eb4995d702d4a3e733391b2a0f53f416d9f907e55cff8";

#[derive(Debug, Error)]
pub enum IfacError {
    #[error("HKDF derivation failed: {0}")]
    HkdfFailed(#[from] rns_crypto::hkdf::HkdfError),
    #[error("invalid IFAC salt hex")]
    InvalidSalt,
}

/// Derive the 64-byte IFAC (Interface Access Control) key.
///
/// `ifac_origin` concatenates `SHA-256(network_name)` and `SHA-256(passphrase)`
/// for whichever fields are `Some(_)` (a `None` field is omitted, so `None`
/// and `Some("")` differ), then HKDF-SHA256 expands it under the fixed salt.
/// First 32 bytes → X25519 private; second 32 → Ed25519 seed.
pub fn derive_ifac_key(
    network_name: Option<&str>,
    passphrase: Option<&str>,
) -> Result<[u8; 64], IfacError> {
    let mut ifac_origin = Vec::new();

    if let Some(name) = network_name {
        ifac_origin.extend_from_slice(&sha256(name.as_bytes()));
    }
    if let Some(key) = passphrase {
        ifac_origin.extend_from_slice(&sha256(key.as_bytes()));
    }

    let ifac_origin_hash = sha256(&ifac_origin);

    let salt = hex_decode(IFAC_SALT).ok_or(IfacError::InvalidSalt)?;

    let derived = hkdf_sha256(64, &ifac_origin_hash, Some(&salt), None)?;
    let mut key = [0u8; 64];
    key.copy_from_slice(&derived);
    Ok(key)
}

/// Build the IFAC identity plus a self-signature over `SHA-256(ifac_key)`.
///
/// Returns `(identity, ifac_key, signature)`.
pub fn derive_ifac_identity(
    network_name: Option<&str>,
    passphrase: Option<&str>,
) -> Result<(crate::identity::Identity, [u8; 64], [u8; 64]), IfacError> {
    let ifac_key = derive_ifac_key(network_name, passphrase)?;

    let identity = crate::identity::Identity::from_private_key(&ifac_key)
        .map_err(|_| IfacError::InvalidSalt)?;

    let key_hash = sha256(&ifac_key);
    let signature = identity.sign(&key_hash).ok_or(IfacError::InvalidSalt)?;

    Ok((identity, ifac_key, signature))
}

/// Split IFAC key into `(signing_key, masking_key)`, each 32 bytes.
pub fn split_ifac_key(key: &[u8; 64]) -> (&[u8], &[u8]) {
    (&key[..32], &key[32..])
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ifac_derivation_deterministic() {
        let key1 = derive_ifac_key(Some("testnet"), Some("password")).unwrap();
        let key2 = derive_ifac_key(Some("testnet"), Some("password")).unwrap();
        assert_eq!(key1, key2);
    }

    #[test]
    fn test_ifac_different_inputs_different_keys() {
        let key1 = derive_ifac_key(Some("net1"), Some("pass1")).unwrap();
        let key2 = derive_ifac_key(Some("net2"), Some("pass2")).unwrap();
        assert_ne!(key1, key2);
    }

    #[test]
    fn test_ifac_none_inputs() {
        let key = derive_ifac_key(None, None).unwrap();
        assert_eq!(key.len(), 64);
    }

    #[test]
    fn test_ifac_key_split() {
        let key = derive_ifac_key(Some("test"), Some("test")).unwrap();
        let (signing, masking) = split_ifac_key(&key);
        assert_eq!(signing.len(), 32);
        assert_eq!(masking.len(), 32);
    }

    #[test]
    fn test_ifac_partial_inputs() {
        let key_name_only = derive_ifac_key(Some("testnet"), None).unwrap();
        let key_both = derive_ifac_key(Some("testnet"), Some("password")).unwrap();
        assert_ne!(key_name_only, key_both);

        let key_pass_only = derive_ifac_key(None, Some("password")).unwrap();
        assert_ne!(key_pass_only, key_both);
    }

    #[test]
    fn test_ifac_none_vs_empty() {
        // `None` omits the field from the origin; `Some("")` includes SHA-256("").
        let key_none = derive_ifac_key(None, None).unwrap();
        let key_empty = derive_ifac_key(Some(""), Some("")).unwrap();
        assert_ne!(key_none, key_empty);
    }

    #[test]
    fn test_derive_ifac_identity() {
        let (identity, ifac_key, signature) =
            derive_ifac_identity(Some("testnet"), Some("password")).unwrap();

        assert!(identity.has_private_key());
        assert_eq!(ifac_key.len(), 64);

        let key_hash = sha256(&ifac_key);
        assert!(identity.verify(&key_hash, &signature));
    }
}
