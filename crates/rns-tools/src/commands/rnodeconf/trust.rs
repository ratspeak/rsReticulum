//! Trust-store and device-signing helpers for rnodeconf.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use rns_identity::identity::Identity;
use rns_interface::rnode_admin::{self, AdminFrame};
use rsa::pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePublicKey};
use rsa::traits::PublicKeyParts;
use rsa::{Pss, RsaPrivateKey, RsaPublicKey};
use sha2::{Digest, Sha256};

use super::log;

/// Upstream `known_keys`: vendor EEPROM signing keys (DER SubjectPublicKeyInfo).
pub const KNOWN_KEYS: &[(&str, &str)] = &[
    (
        "unsigned.io",
        "30819f300d06092a864886f70d010101050003818d0030818902818100bf831ebd99f43b477caf1a094bec829389da40653e8f1f83fc14bf1b98a3e1cc70e759c213a43f71e5a47eb56a9ca487f241335b3e6ff7cdde0ee0a1c75c698574aeba0485726b6a9dfc046b4188e3520271ee8555a8f405cf21f81f2575771d0b0887adea5dd53c1f594f72c66b5f14904ffc2e72206a6698a490d51ba1105b0203010001",
    ),
    (
        "unsigned.io",
        "30819f300d06092a864886f70d010101050003818d0030818902818100e5d46084e445595376bf7efd9c6ccf19d39abbc59afdb763207e4ff68b8d00ebffb63847aa2fe6dd10783d3ea63b55ac66f71ad885c20e223709f0d51ed5c6c0d0b093be9e1d165bb8a483a548b67a3f7a1e4580f50e75b306593fa6067ae259d3e297717bd7ff8c8f5b07f2bed89929a9a0321026cf3699524db98e2d18fb2d020300ff39",
    ),
];

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct SignatureCheck {
    pub valid: bool,
    pub locally_signed: bool,
    pub vendor: Option<String>,
}

/// Upstream `parse_eeprom` signature check: RSA-PSS/SHA-256 over the EEPROM
/// checksum against the vendor keys, the local signing key and trusted keys.
pub fn validate_device_signature(
    signature: &[u8],
    checksum: &[u8],
    root: Option<&Path>,
) -> SignatureCheck {
    let mut keys: Vec<(String, String)> = KNOWN_KEYS
        .iter()
        .map(|(vendor, der)| (vendor.to_string(), der.to_string()))
        .collect();
    if let Some(root) = root {
        let signing_key = signing_key_path(root);
        if signing_key.is_file() {
            let private_bytes = fs::read(&signing_key).unwrap_or_else(|_| {
                log("Could not load local signing key");
                Vec::new()
            });
            match RsaPrivateKey::from_pkcs8_der(&private_bytes)
                .map_err(|error| error.to_string())
                .and_then(|key| {
                    key.to_public_key()
                        .to_public_key_der()
                        .map_err(|error| error.to_string())
                }) {
                Ok(public) => add_local_key(&mut keys, hex::encode(public.as_bytes())),
                Err(error) => {
                    log("Could not deserialize local signing key");
                    log(error);
                }
            }
        }
        let mut trusted: Vec<PathBuf> = fs::read_dir(root.join("trusted_keys"))
            .map(|entries| {
                entries
                    .filter_map(|entry| Some(entry.ok()?.path()))
                    .collect()
            })
            .unwrap_or_default();
        trusted.sort();
        for path in trusted {
            let name = path.file_name().unwrap_or_default().to_string_lossy();
            if !path.is_file() || !name.ends_with(".pubkey") {
                continue;
            }
            match fs::read(&path) {
                Ok(public) => add_local_key(&mut keys, hex::encode(public)),
                Err(_) => log(format!("Could not load trusted signing key{name}")),
            }
        }
    }

    let mut check = SignatureCheck::default();
    let hashed = Sha256::digest(checksum);
    for (vendor, der) in keys {
        // Upstream raises on an undecodable key; skip it instead.
        let Some(key) = hex::decode(&der)
            .ok()
            .and_then(|der| RsaPublicKey::from_public_key_der(&der).ok())
        else {
            continue;
        };
        if pss_verify_any_salt(&key, &hashed, signature) {
            if vendor == "LOCAL" {
                check.locally_signed = true;
            }
            check.valid = true;
            check.vendor = Some(vendor);
        }
    }
    check
}

fn add_local_key(keys: &mut Vec<(String, String)>, der_hex: String) {
    if !keys.iter().any(|(_, known)| *known == der_hex) {
        keys.push(("LOCAL".to_string(), der_hex));
    }
}

/// `padding.PSS.MAX_LENGTH` on verify accepts any salt length.
fn pss_verify_any_salt(key: &RsaPublicKey, hashed: &[u8], signature: &[u8]) -> bool {
    let em_len = (key.n().bits() + 6) / 8;
    let max_salt = em_len.saturating_sub(Sha256::output_size() + 2);
    (0..=max_salt).any(|salt| {
        key.verify(Pss::new_with_salt::<Sha256>(salt), hashed, signature)
            .is_ok()
    })
}

pub const SIGNING_KEY_RELATIVE_PATH: &[&str] = &["firmware", "signing.key"];
pub const DEVICE_KEY_FILENAME: &str = "device.key";

pub fn trusted_key_filename(public_key_der: &[u8]) -> String {
    format!(
        "{}.pubkey",
        hex::encode(rns_crypto::sha::sha256(public_key_der))
    )
}

pub fn trusted_key_path(root: &Path, public_key_der: &[u8]) -> PathBuf {
    root.join("trusted_keys")
        .join(trusted_key_filename(public_key_der))
}

pub fn write_trusted_key(root: &Path, public_key_der: &[u8]) -> io::Result<PathBuf> {
    let path = trusted_key_path(root, public_key_der);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&path, public_key_der)?;
    Ok(path)
}

pub fn signing_key_path(root: &Path) -> PathBuf {
    SIGNING_KEY_RELATIVE_PATH
        .iter()
        .fold(root.to_path_buf(), |path, component| path.join(component))
}

pub fn device_key_path(root: &Path) -> PathBuf {
    root.join("firmware").join(DEVICE_KEY_FILENAME)
}

pub fn load_device_identity(path: &Path) -> Result<Identity, String> {
    Identity::from_file(path).map_err(|e| format!("could not load device identity: {e}"))
}

pub fn sign_device_hash(identity: &Identity, device_hash: &[u8; 32]) -> Result<[u8; 64], String> {
    identity
        .sign(device_hash)
        .ok_or_else(|| "device identity does not contain a private signing key".to_string())
}

pub fn device_signature_frame(signature: &[u8; 64]) -> AdminFrame {
    rnode_admin::device_signature_frame(signature)
}

pub fn firmware_hash_frame(hash: &[u8; 32]) -> AdminFrame {
    rnode_admin::firmware_hash_frame(hash)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trusted_key_filename_is_sha256_pubkey_name() {
        let der = b"not-real-der-but-stable";
        assert_eq!(
            trusted_key_filename(der),
            format!("{}.pubkey", hex::encode(rns_crypto::sha::sha256(der)))
        );
    }

    #[test]
    fn signing_keys_live_in_the_firmware_dir() {
        let root = Path::new("/home/u/.config/rnodeconf");
        assert_eq!(
            signing_key_path(root),
            root.join("firmware").join("signing.key")
        );
        assert_eq!(
            device_key_path(root),
            root.join("firmware").join("device.key")
        );
    }

    #[test]
    fn device_hash_signing_uses_reticulum_identity_key() {
        let private = [7u8; 64];
        let identity = Identity::from_private_key(&private).unwrap();
        let device_hash = [9u8; 32];
        let signature = sign_device_hash(&identity, &device_hash).unwrap();
        assert!(identity.verify(&device_hash, &signature));
        assert_eq!(
            device_signature_frame(&signature),
            rnode_admin::device_signature_frame(&signature)
        );
    }
}
