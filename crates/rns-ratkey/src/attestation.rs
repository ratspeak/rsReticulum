//! YubiKey PIV attestation verification. Bundled root CAs — never fetched at runtime.
//!
//! Legacy chain (firmware < 5.7.4):
//!   per-key attestation cert → device intermediate (slot F9)
//!     → `Yubico PIV Root CA Serial 263751` (bundled root).
//!
//! New chain (firmware >= 5.7.4):
//!   per-key attestation cert → device intermediate (slot F9)
//!     → `Yubico PIV Attestation {A,B,B2} 1` (bundled intermediate)
//!     → `Yubico Attestation Intermediate {A,B} 1` (bundled intermediate)
//!     → `Yubico Attestation Root 1` (bundled root).
//! The two tiers of intermediate CAs are not present on the device; they are
//! bundled here from Yubico's published attestation PKI (yubico-intermediate.pem).
//! Both A and B branches plus the 2025 B2 PIV intermediate are bundled, so any
//! firmware-5.7.4+ YubiKey PIV attestation chains to the bundled root.
//!
//! Nitrokey 3 does not support PIV attestation (firmware 1.8) — verification skipped.
//!
//! ## What `chain_verified == true` means here
//!
//! Every link from the per-key attestation cert up to (and including) a bundled
//! trust anchor has a valid RSA PKCS#1 v1.5 signature (issuer public key over the
//! child's TBS bytes), the terminal issuer's DER SHA-256 matches a pinned
//! fingerprint constant, and every certificate in the walked path is inside its
//! notBefore/notAfter validity window at verification time.
//!
//! ## Explicit non-goals (NOT checked)
//!
//! Revocation (CRL/OCSP), name constraints, basicConstraints/keyUsage/pathlen
//! enforcement, and the remainder of RFC 5280 path validation are intentionally
//! out of scope. The root's own self-signature is not verified — the root is
//! trusted by pinned fingerprint plus validity window. All required chain links
//! are sha256WithRSAEncryption; the per-cert signature OID is still inspected so
//! a sha512WithRSA link would be honored rather than silently mis-verified.

use crate::error::RatkeyError;

use const_oid::ObjectIdentifier;
use der::Encode;
use rsa::RsaPublicKey;
use rsa::pkcs1::DecodeRsaPublicKey;
use rsa::pkcs1v15::{Signature as RsaSignature, VerifyingKey};
use rsa::signature::Verifier;
use sha2::{Digest, Sha256, Sha512};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use x509_cert::Certificate;
use x509_cert::der::Decode;

/// Yubico PIV Root CA (legacy, firmware < 5.7.4). Subject: "Yubico PIV Root CA Serial 263751".
pub const YUBICO_PIV_ROOT_CA_LEGACY_PEM: &str =
    include_str!("../certs/yubico-piv-root-ca-legacy.pem");

/// Yubico Attestation Root 1 (firmware >= 5.7.4). Subject: "Yubico Attestation Root 1".
pub const YUBICO_ATTESTATION_ROOT_1_PEM: &str =
    include_str!("../certs/yubico-attestation-root-1.pem");

// New-PKI intermediates (firmware >= 5.7.4). Bundled from Yubico's published
// yubico-intermediate.pem. A, B, and the 2025 B2 PIV branches are all covered.
const YUBICO_ATTESTATION_INTERMEDIATE_A_1_PEM: &str =
    include_str!("../certs/yubico-attestation-intermediate-a-1.pem");
const YUBICO_ATTESTATION_INTERMEDIATE_B_1_PEM: &str =
    include_str!("../certs/yubico-attestation-intermediate-b-1.pem");
const YUBICO_PIV_ATTESTATION_A_1_PEM: &str =
    include_str!("../certs/yubico-piv-attestation-a-1.pem");
const YUBICO_PIV_ATTESTATION_B_1_PEM: &str =
    include_str!("../certs/yubico-piv-attestation-b-1.pem");
const YUBICO_PIV_ATTESTATION_B2_1_PEM: &str =
    include_str!("../certs/yubico-piv-attestation-b2-1.pem");

/// SHA-256 fingerprint of the legacy Yubico PIV Root CA (belt-and-suspenders vs PEM swap).
pub const YUBICO_LEGACY_ROOT_SHA256: &str =
    "63ece914e54dd87915f34033c85af4c0696ba1512f8add66ced738331207b546";

/// SHA-256 fingerprint of the new Yubico Attestation Root 1 (belt-and-suspenders vs PEM swap).
pub const YUBICO_NEW_ROOT_SHA256: &str =
    "62760c6a6ef91679f454c8902b80fd009825b3f25da90f1fbace2ec6586cd5a8";

// Yubico PIV attestation OIDs. Yubico PEN: 1.3.6.1.4.1.41482; PIV attestation subtree: .3.

/// Firmware version (3 bytes: major.minor.patch).
pub const OID_FIRMWARE_VERSION: &[u8] =
    &[0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0xC4, 0x0A, 0x03, 0x03];

/// Serial number (INTEGER).
pub const OID_SERIAL_NUMBER: &[u8] = &[0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0xC4, 0x0A, 0x03, 0x07];

/// Usage policy (2 bytes: pin_policy, touch_policy).
pub const OID_USAGE_POLICY: &[u8] = &[0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0xC4, 0x0A, 0x03, 0x08];

/// Form factor (1 byte).
pub const OID_FORM_FACTOR: &[u8] = &[0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0xC4, 0x0A, 0x03, 0x09];

// Signature algorithm OIDs (PKCS#1).
const OID_SHA256_RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");
const OID_SHA512_RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.13");

// Guard against issuer cycles in a malformed/hostile pool.
const MAX_CHAIN_DEPTH: usize = 8;

#[derive(Debug, Clone)]
pub struct AttestationInfo {
    pub firmware_version: Option<(u8, u8, u8)>,
    pub serial_number: Option<u32>,
    pub pin_policy: Option<u8>,
    pub touch_policy: Option<u8>,
    pub form_factor: Option<u8>,
    pub attestation_cert_der: Vec<u8>,
    /// Device intermediate (slot F9) DER.
    pub device_cert_der: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct AttestationVerification {
    /// True only when the attestation certificate chain has been
    /// cryptographically verified to a bundled trusted root.
    pub verified: bool,
    /// True when Yubico attestation metadata could be extracted from the cert.
    pub metadata_extracted: bool,
    /// Explicit chain-verification label for UI/CLI surfaces.
    pub chain_verified: bool,
    pub info: AttestationInfo,
    /// "legacy" or "new".
    pub root_ca: String,
    pub description: String,
}

/// Verify chain: attestation cert (from ATTEST F9) + device intermediate (slot F9).
///
/// Sets `verified`/`chain_verified == true` only when every signature from the
/// per-key cert up to a bundled, fingerprint-pinned Yubico root validates and
/// all walked certs are inside their validity window. See module docs for the
/// precise meaning and the explicit non-goals.
pub fn verify_attestation(
    attestation_cert_der: &[u8],
    device_cert_der: &[u8],
) -> Result<AttestationVerification, RatkeyError> {
    let info = extract_attestation_info(attestation_cert_der, device_cert_der)?;

    let metadata_extracted = info.firmware_version.is_some();
    let root_ca = if let Some((major, minor, patch)) = info.firmware_version {
        if major > 5 || (major == 5 && (minor > 7 || (minor == 7 && patch >= 4))) {
            "new".to_string()
        } else {
            "legacy".to_string()
        }
    } else {
        "unknown".to_string()
    };

    let anchors = bundled_trust_anchors();
    let pool = bundled_intermediate_pool();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();

    let chain_result = verify_chain(attestation_cert_der, device_cert_der, &anchors, &pool, now);

    let chain_verified = chain_result.is_ok();

    let description = build_description(metadata_extracted, &info, &chain_result);

    Ok(AttestationVerification {
        verified: chain_verified,
        metadata_extracted,
        chain_verified,
        info,
        root_ca,
        description,
    })
}

fn build_description(
    metadata_extracted: bool,
    info: &AttestationInfo,
    chain_result: &Result<(), ChainError>,
) -> String {
    let prefix = if metadata_extracted {
        let (maj, min, pat) = info.firmware_version.unwrap_or((0, 0, 0));
        format!(
            "YubiKey firmware {maj}.{min}.{pat}{}",
            info.serial_number
                .map(|s| format!(", serial {s}"))
                .unwrap_or_default()
        )
    } else {
        "could not extract YubiKey attestation metadata".to_string()
    };

    match chain_result {
        Ok(()) => {
            format!("{prefix}; attestation chain cryptographically verified to bundled Yubico root")
        }
        Err(e) => format!("{prefix}; attestation chain not verified: {e}"),
    }
}

/// YubiKey 5 (firmware >= 4.3.0) only. Nitrokey 3 has no PIV attestation.
pub fn supports_attestation(device_type: &str) -> bool {
    device_type == "yubikey5"
}

// ---------------------------------------------------------------------------
// Chain verification
// ---------------------------------------------------------------------------

/// A parsed trust anchor. Only included after its DER SHA-256 matched a pinned
/// fingerprint constant (see `bundled_trust_anchors`), so reaching one is the
/// terminal trust condition.
#[derive(Clone)]
struct TrustAnchor {
    cert: Certificate,
}

#[derive(Debug)]
enum ChainError {
    ParseLeaf,
    ParseDevice,
    IssuerNotFound,
    SignatureInvalid,
    Expired,
    UnsupportedSignatureAlg(String),
    BadPublicKey,
    DepthExceeded,
}

impl std::fmt::Display for ChainError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ChainError::ParseLeaf => write!(f, "attestation certificate did not parse as X.509"),
            ChainError::ParseDevice => {
                write!(f, "device (slot F9) certificate did not parse as X.509")
            }
            ChainError::IssuerNotFound => {
                write!(
                    f,
                    "no bundled/known issuer found for a certificate in the chain"
                )
            }
            ChainError::SignatureInvalid => write!(f, "a certificate signature failed to verify"),
            ChainError::Expired => write!(f, "a certificate is outside its validity window"),
            ChainError::UnsupportedSignatureAlg(oid) => {
                write!(f, "unsupported certificate signature algorithm {oid}")
            }
            ChainError::BadPublicKey => write!(f, "issuer public key could not be decoded as RSA"),
            ChainError::DepthExceeded => write!(f, "chain exceeded maximum depth"),
        }
    }
}

/// Bundled, fingerprint-pinned roots. A cert is only a valid terminal if its DER
/// SHA-256 matches one of these constants — guarding against a swapped PEM.
fn bundled_trust_anchors() -> Vec<TrustAnchor> {
    let mut anchors = Vec::new();
    for (pem, fp) in [
        (YUBICO_PIV_ROOT_CA_LEGACY_PEM, YUBICO_LEGACY_ROOT_SHA256),
        (YUBICO_ATTESTATION_ROOT_1_PEM, YUBICO_NEW_ROOT_SHA256),
    ] {
        if let Some(der) = pem_to_der(pem) {
            if hex::encode(Sha256::digest(&der)) == fp {
                if let Ok(cert) = Certificate::from_der(&der) {
                    anchors.push(TrustAnchor { cert });
                }
            }
        }
    }
    anchors
}

/// Bundled intermediate CAs (new-PKI A/B/B2 branches). Searchable issuers only —
/// never terminal trust anchors.
fn bundled_intermediate_pool() -> Vec<Certificate> {
    [
        YUBICO_ATTESTATION_INTERMEDIATE_A_1_PEM,
        YUBICO_ATTESTATION_INTERMEDIATE_B_1_PEM,
        YUBICO_PIV_ATTESTATION_A_1_PEM,
        YUBICO_PIV_ATTESTATION_B_1_PEM,
        YUBICO_PIV_ATTESTATION_B2_1_PEM,
    ]
    .into_iter()
    .filter_map(|pem| pem_to_der(pem).and_then(|der| Certificate::from_der(&der).ok()))
    .collect()
}

/// Walk from the leaf up to a pinned anchor, verifying each signature and every
/// cert's validity window. `now` is seconds since the Unix epoch.
fn verify_chain(
    attestation_cert_der: &[u8],
    device_cert_der: &[u8],
    anchors: &[TrustAnchor],
    intermediates: &[Certificate],
    now: Duration,
) -> Result<(), ChainError> {
    let leaf = Certificate::from_der(attestation_cert_der).map_err(|_| ChainError::ParseLeaf)?;
    let device = Certificate::from_der(device_cert_der).map_err(|_| ChainError::ParseDevice)?;

    // Searchable issuers: the device F9 cert plus all bundled intermediates.
    let mut searchable: Vec<&Certificate> = Vec::with_capacity(intermediates.len() + 1);
    searchable.push(&device);
    for c in intermediates {
        searchable.push(c);
    }

    check_validity(&leaf, now)?;

    let mut current = leaf.clone();
    let mut current_der = attestation_cert_der.to_vec();
    for _ in 0..MAX_CHAIN_DEPTH {
        // Terminal: is `current` signed by a pinned anchor?
        for anchor in anchors {
            // `anchor` is trusted only because its DER SHA-256 matched a pinned
            // constant in bundled_trust_anchors(); its self-signature is not checked.
            if names_match(
                &anchor.cert.tbs_certificate.subject,
                &current.tbs_certificate.issuer,
            ) && verify_signature(&current, &anchor.cert).is_ok()
            {
                check_validity(&anchor.cert, now)?;
                return Ok(());
            }
        }

        // A self-issued cert that is not a pinned anchor is an untrusted root:
        // the chain terminates here without reaching a trust anchor. (Anchors are
        // checked above, so reaching this point means it is not pinned.)
        if names_match(
            &current.tbs_certificate.subject,
            &current.tbs_certificate.issuer,
        ) {
            return Err(ChainError::IssuerNotFound);
        }

        // Otherwise advance one link via a searchable (non-anchor) issuer.
        let issuer = searchable.iter().copied().find(|cand| {
            names_match(
                &cand.tbs_certificate.subject,
                &current.tbs_certificate.issuer,
            ) && verify_signature(&current, cand).is_ok()
        });

        match issuer {
            Some(issuer_cert) => {
                check_validity(issuer_cert, now)?;
                let issuer_der = issuer_cert
                    .to_der()
                    .map_err(|_| ChainError::IssuerNotFound)?;
                // Cycle guard: a non-self-issued cert pointing back at itself.
                if issuer_der == current_der {
                    return Err(ChainError::IssuerNotFound);
                }
                current = issuer_cert.clone();
                current_der = issuer_der;
            }
            None => {
                // No pinned anchor and no searchable issuer signs `current`.
                // Distinguish "issuer present but bad signature" for diagnostics.
                let issuer_present = anchors.iter().any(|a| {
                    names_match(
                        &a.cert.tbs_certificate.subject,
                        &current.tbs_certificate.issuer,
                    )
                }) || searchable.iter().any(|c| {
                    names_match(&c.tbs_certificate.subject, &current.tbs_certificate.issuer)
                });
                return Err(if issuer_present {
                    ChainError::SignatureInvalid
                } else {
                    ChainError::IssuerNotFound
                });
            }
        }
    }

    Err(ChainError::DepthExceeded)
}

/// RFC 5280 distinguished-name match via canonical DER encoding of the Name.
fn names_match(a: &x509_cert::name::Name, b: &x509_cert::name::Name) -> bool {
    match (a.to_der(), b.to_der()) {
        (Ok(da), Ok(db)) => da == db,
        _ => false,
    }
}

/// Verify `child`'s signature using `issuer`'s public key (RSA PKCS#1 v1.5).
fn verify_signature(child: &Certificate, issuer: &Certificate) -> Result<(), ChainError> {
    let tbs = child
        .tbs_certificate
        .to_der()
        .map_err(|_| ChainError::SignatureInvalid)?;

    let sig_bytes = child
        .signature
        .as_bytes()
        .ok_or(ChainError::SignatureInvalid)?;
    let sig = RsaSignature::try_from(sig_bytes).map_err(|_| ChainError::SignatureInvalid)?;

    let spki_key = issuer
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .as_bytes()
        .ok_or(ChainError::BadPublicKey)?;
    let pubkey = RsaPublicKey::from_pkcs1_der(spki_key).map_err(|_| ChainError::BadPublicKey)?;

    let alg = child.signature_algorithm.oid;
    if alg == OID_SHA256_RSA {
        VerifyingKey::<Sha256>::new(pubkey)
            .verify(&tbs, &sig)
            .map_err(|_| ChainError::SignatureInvalid)
    } else if alg == OID_SHA512_RSA {
        VerifyingKey::<Sha512>::new(pubkey)
            .verify(&tbs, &sig)
            .map_err(|_| ChainError::SignatureInvalid)
    } else {
        Err(ChainError::UnsupportedSignatureAlg(alg.to_string()))
    }
}

/// Reject certs outside their notBefore/notAfter window at time `now`.
fn check_validity(cert: &Certificate, now: Duration) -> Result<(), ChainError> {
    let nb = cert.tbs_certificate.validity.not_before.to_unix_duration();
    let na = cert.tbs_certificate.validity.not_after.to_unix_duration();
    if now < nb || now > na {
        Err(ChainError::Expired)
    } else {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// OID metadata extraction (byte-scan; unchanged behavior)
// ---------------------------------------------------------------------------

fn extract_attestation_info(
    attestation_cert_der: &[u8],
    device_cert_der: &[u8],
) -> Result<AttestationInfo, RatkeyError> {
    let firmware = find_oid_value(attestation_cert_der, OID_FIRMWARE_VERSION).and_then(|v| {
        if v.len() >= 3 {
            Some((v[0], v[1], v[2]))
        } else {
            None
        }
    });

    let serial = find_oid_value(attestation_cert_der, OID_SERIAL_NUMBER)
        .and_then(|v| parse_asn1_integer(&v));

    let (pin_policy, touch_policy) = find_oid_value(attestation_cert_der, OID_USAGE_POLICY)
        .map(|v| {
            let pp = v.first().copied();
            let tp = v.get(1).copied();
            (pp, tp)
        })
        .unwrap_or((None, None));

    let form_factor =
        find_oid_value(attestation_cert_der, OID_FORM_FACTOR).and_then(|v| v.first().copied());

    Ok(AttestationInfo {
        firmware_version: firmware,
        serial_number: serial,
        pin_policy,
        touch_policy,
        form_factor,
        attestation_cert_der: attestation_cert_der.to_vec(),
        device_cert_der: device_cert_der.to_vec(),
    })
}

// Byte-scan DER for OID pattern, return TLV value after it. Avoids full ASN.1 parser dependency.
fn find_oid_value(der: &[u8], oid_bytes: &[u8]) -> Option<Vec<u8>> {
    let oid_with_tag = {
        let mut v = Vec::with_capacity(2 + oid_bytes.len());
        v.push(0x06); // OID tag
        v.push(oid_bytes.len() as u8);
        v.extend_from_slice(oid_bytes);
        v
    };

    let pos = der
        .windows(oid_with_tag.len())
        .position(|w| w == oid_with_tag.as_slice())?;

    let after_oid = pos + oid_with_tag.len();
    if after_oid >= der.len() {
        return None;
    }

    let tag = der[after_oid];
    if after_oid + 1 >= der.len() {
        return None;
    }

    let (value_len, len_bytes) = decode_der_length(&der[after_oid + 1..])?;
    let value_start = after_oid + 1 + len_bytes;
    let value_end = value_start + value_len;

    if value_end > der.len() {
        return None;
    }

    let value = &der[value_start..value_end];

    // Unwrap one level if OCTET STRING wraps another OCTET STRING or INTEGER.
    if tag == 0x04 && value.len() >= 2 {
        let inner_tag = value[0];
        if inner_tag == 0x04 || inner_tag == 0x02 {
            if let Some((inner_len, inner_len_bytes)) = decode_der_length(&value[1..]) {
                let inner_start = 1 + inner_len_bytes;
                if inner_start + inner_len <= value.len() {
                    return Some(value[inner_start..inner_start + inner_len].to_vec());
                }
            }
        }
        return Some(value.to_vec());
    }

    Some(value.to_vec())
}

fn parse_asn1_integer(bytes: &[u8]) -> Option<u32> {
    if bytes.is_empty() || bytes.len() > 4 {
        return None;
    }
    let mut result: u32 = 0;
    for &b in bytes {
        result = result.checked_shl(8)?.checked_add(b as u32)?;
    }
    Some(result)
}

fn decode_der_length(data: &[u8]) -> Option<(usize, usize)> {
    if data.is_empty() {
        return None;
    }
    let first = data[0];
    if first < 0x80 {
        Some((first as usize, 1))
    } else if first == 0x81 {
        data.get(1).map(|&b| (b as usize, 2))
    } else if first == 0x82 {
        if data.len() < 3 {
            return None;
        }
        Some((((data[1] as usize) << 8) | data[2] as usize, 3))
    } else {
        None
    }
}

pub fn pem_to_der(pem: &str) -> Option<Vec<u8>> {
    let lines: Vec<&str> = pem.lines().filter(|l| !l.starts_with("-----")).collect();
    let b64: String = lines.join("");
    base64_decode(&b64)
}

// Standard alphabet, padding optional.
fn base64_decode(input: &str) -> Option<Vec<u8>> {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    fn val(c: u8) -> Option<u8> {
        TABLE.iter().position(|&b| b == c).map(|p| p as u8)
    }

    let bytes: Vec<u8> = input
        .bytes()
        .filter(|&b| b != b'=' && b != b'\n' && b != b'\r' && b != b' ')
        .collect();
    let mut out = Vec::with_capacity(bytes.len() * 3 / 4);
    let mut i = 0;
    while i + 3 < bytes.len() {
        let a = val(bytes[i])?;
        let b = val(bytes[i + 1])?;
        let c = val(bytes[i + 2])?;
        let d = val(bytes[i + 3])?;
        out.push((a << 2) | (b >> 4));
        out.push((b << 4) | (c >> 2));
        out.push((c << 6) | d);
        i += 4;
    }
    let remaining = bytes.len() - i;
    if remaining >= 2 {
        let a = val(bytes[i])?;
        let b = val(bytes[i + 1])?;
        out.push((a << 2) | (b >> 4));
        if remaining >= 3 {
            let c = val(bytes[i + 2])?;
            out.push((b << 4) | (c >> 2));
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_legacy_root_ca_loads() {
        let der = pem_to_der(YUBICO_PIV_ROOT_CA_LEGACY_PEM);
        assert!(der.is_some(), "legacy root CA PEM should decode");
        let der = der.unwrap();
        assert!(der.len() > 500, "DER should be substantial");
        // DER starts with SEQUENCE tag (0x30)
        assert_eq!(der[0], 0x30, "DER must start with SEQUENCE tag");
    }

    #[test]
    fn test_new_root_ca_loads() {
        let der = pem_to_der(YUBICO_ATTESTATION_ROOT_1_PEM);
        assert!(der.is_some(), "new root CA PEM should decode");
        let der = der.unwrap();
        assert!(der.len() > 500);
        assert_eq!(der[0], 0x30);
    }

    #[test]
    fn test_pem_to_der_roundtrip() {
        let pem = "-----BEGIN CERTIFICATE-----\nTUlJ\n-----END CERTIFICATE-----\n";
        let der = pem_to_der(pem);
        assert!(der.is_some());
    }

    #[test]
    fn test_supports_attestation() {
        assert!(supports_attestation("yubikey5"));
        assert!(!supports_attestation("nitrokey3"));
        assert!(!supports_attestation("unknown"));
    }

    #[test]
    fn test_parse_asn1_integer() {
        assert_eq!(parse_asn1_integer(&[0x01]), Some(1));
        assert_eq!(parse_asn1_integer(&[0x00, 0xFF]), Some(255));
        assert_eq!(parse_asn1_integer(&[0x01, 0x00, 0x00]), Some(65536));
        assert_eq!(parse_asn1_integer(&[]), None);
        assert_eq!(parse_asn1_integer(&[0x01, 0x02, 0x03, 0x04, 0x05]), None); // > 4 bytes
    }

    #[test]
    fn test_find_oid_in_synthetic_der() {
        // Build a minimal DER structure containing a Yubico firmware OID
        // SEQUENCE { OID(firmware) OCTET_STRING(3 bytes: 05 07 01) }
        let mut der = Vec::new();
        // Outer SEQUENCE
        let mut inner = Vec::new();
        // OID tag + length + firmware OID bytes
        inner.push(0x06); // OID tag
        inner.push(OID_FIRMWARE_VERSION.len() as u8);
        inner.extend_from_slice(OID_FIRMWARE_VERSION);
        // OCTET STRING with firmware version 5.7.1
        inner.push(0x04); // OCTET STRING tag
        inner.push(0x03); // length = 3
        inner.push(0x05); // major = 5
        inner.push(0x07); // minor = 7
        inner.push(0x01); // patch = 1

        der.push(0x30); // SEQUENCE tag
        der.push(inner.len() as u8);
        der.extend_from_slice(&inner);

        let value = find_oid_value(&der, OID_FIRMWARE_VERSION);
        assert!(value.is_some(), "should find firmware OID");
        let v = value.unwrap();
        assert_eq!(v, vec![0x05, 0x07, 0x01], "firmware should be 5.7.1");
    }

    #[test]
    fn test_find_oid_serial_number() {
        // Build DER with serial number OID
        let mut der = Vec::new();
        let mut inner = Vec::new();
        inner.push(0x06);
        inner.push(OID_SERIAL_NUMBER.len() as u8);
        inner.extend_from_slice(OID_SERIAL_NUMBER);
        // INTEGER with serial 12345678 = 0x00BC614E
        inner.push(0x02); // INTEGER tag
        inner.push(0x04); // length = 4
        inner.extend_from_slice(&[0x00, 0xBC, 0x61, 0x4E]);

        der.push(0x30);
        der.push(inner.len() as u8);
        der.extend_from_slice(&inner);

        let value = find_oid_value(&der, OID_SERIAL_NUMBER);
        assert!(value.is_some());
        let serial = parse_asn1_integer(&value.unwrap());
        assert_eq!(serial, Some(12345678));
    }

    #[test]
    fn test_verify_attestation_synthetic_metadata() {
        // Minimal attestation cert with firmware OID; not a real X.509 cert, so the
        // chain cannot verify — exercises metadata extraction + graceful chain failure.
        let mut attest_der = Vec::new();
        let mut inner = Vec::new();
        inner.push(0x06);
        inner.push(OID_FIRMWARE_VERSION.len() as u8);
        inner.extend_from_slice(OID_FIRMWARE_VERSION);
        inner.push(0x04);
        inner.push(0x03);
        inner.extend_from_slice(&[0x05, 0x07, 0x01]); // 5.7.1

        attest_der.push(0x30);
        attest_der.push(inner.len() as u8);
        attest_der.extend_from_slice(&inner);

        let device_der = vec![0x30, 0x00];

        let result = verify_attestation(&attest_der, &device_der).unwrap();
        assert!(result.metadata_extracted);
        assert!(!result.verified);
        assert!(!result.chain_verified);
        assert_eq!(result.root_ca, "legacy"); // 5.7.1 < 5.7.4
        assert!(result.description.contains("5.7.1"));
        assert!(result.description.contains("not verified"));
    }

    #[test]
    fn test_verify_attestation_new_firmware_metadata_only() {
        let mut attest_der = Vec::new();
        let mut inner = Vec::new();
        inner.push(0x06);
        inner.push(OID_FIRMWARE_VERSION.len() as u8);
        inner.extend_from_slice(OID_FIRMWARE_VERSION);
        inner.push(0x04);
        inner.push(0x03);
        inner.extend_from_slice(&[0x05, 0x07, 0x04]); // 5.7.4

        attest_der.push(0x30);
        attest_der.push(inner.len() as u8);
        attest_der.extend_from_slice(&inner);

        let device_der = vec![0x30, 0x00];

        let result = verify_attestation(&attest_der, &device_der).unwrap();
        assert!(result.metadata_extracted);
        assert!(!result.verified);
        assert!(!result.chain_verified);
        assert_eq!(result.root_ca, "new"); // 5.7.4 → new root CA
    }

    #[test]
    fn test_verify_attestation_future_firmware_uses_new_root_label() {
        let mut attest_der = Vec::new();
        let mut inner = Vec::new();
        inner.push(0x06);
        inner.push(OID_FIRMWARE_VERSION.len() as u8);
        inner.extend_from_slice(OID_FIRMWARE_VERSION);
        inner.push(0x04);
        inner.push(0x03);
        inner.extend_from_slice(&[0x05, 0x08, 0x00]); // 5.8.0

        attest_der.push(0x30);
        attest_der.push(inner.len() as u8);
        attest_der.extend_from_slice(&inner);

        let result = verify_attestation(&attest_der, &[0x30, 0x00]).unwrap();
        assert_eq!(result.root_ca, "new");
    }

    #[test]
    fn test_verify_attestation_empty_cert() {
        let result = verify_attestation(&[], &[]).unwrap();
        assert!(!result.verified);
        assert!(!result.metadata_extracted);
        assert!(!result.chain_verified);
        assert_eq!(result.root_ca, "unknown");
    }

    // Real on-device vectors captured from a YubiKey 5.7.4 (serial 35284666) via
    // `rnid-rs hw attest`: the slot-9A per-key attestation cert + the slot-F9
    // device intermediate. Proves the verifier chains a real device's ATTEST
    // output to a bundled, fingerprint-pinned Yubico root — the regression guard
    // for the hardware validation, runnable in CI without a device.
    // Both certs are notAfter=9999-12-31 (Yubico attestation certs do not expire),
    // so the validity-window check in `verify_chain` will not rot this vector.
    #[test]
    fn test_real_yubikey_attestation_chain_verifies() {
        let attest = include_bytes!("../tests/fixtures/9a_attest.der");
        let device = include_bytes!("../tests/fixtures/f9_device.der");
        let v = verify_attestation(attest, device).unwrap();
        assert!(
            v.chain_verified,
            "real-device chain must verify: {}",
            v.description
        );
        assert!(v.verified);
        assert_eq!(v.root_ca, "new");
        assert_eq!(v.info.firmware_version, Some((5, 7, 4)));
        assert_eq!(v.info.serial_number, Some(35284666));
    }

    // ---------------------------------------------------------------------
    // Pinned-fingerprint guards: compute the SHA-256 with our own code path
    // (pem_to_der + sha2) and assert it equals the pinned constant. Catches a
    // swapped PEM and validates the hand-rolled base64 against the same DER the
    // x509 parser consumes.
    // ---------------------------------------------------------------------

    #[test]
    fn test_legacy_root_fingerprint_matches_constant() {
        let der = pem_to_der(YUBICO_PIV_ROOT_CA_LEGACY_PEM).expect("decode legacy root");
        assert_eq!(hex::encode(Sha256::digest(&der)), YUBICO_LEGACY_ROOT_SHA256);
    }

    #[test]
    fn test_new_root_fingerprint_matches_constant() {
        let der = pem_to_der(YUBICO_ATTESTATION_ROOT_1_PEM).expect("decode new root");
        assert_eq!(hex::encode(Sha256::digest(&der)), YUBICO_NEW_ROOT_SHA256);
    }

    #[test]
    fn test_bundled_anchors_and_pool_parse() {
        let anchors = bundled_trust_anchors();
        assert_eq!(anchors.len(), 2, "both pinned roots must parse and match");
        let pool = bundled_intermediate_pool();
        assert_eq!(pool.len(), 5, "five PIV-chain intermediates bundled");
    }

    #[test]
    fn test_real_intermediate_chains_to_pinned_root() {
        // The bundled PIV Attestation A 1 cert chains to the bundled Attestation
        // Root 1 via the bundled Intermediate A 1. Verify the new-PKI links work
        // against the real published certs (using PIV Attestation A 1 as the
        // synthetic "leaf"/"device" entry point).
        let anchors = bundled_trust_anchors();
        let pool = bundled_intermediate_pool();
        // Use Intermediate A 1 as the leaf; its issuer is the pinned root.
        let int_a = pem_to_der(YUBICO_ATTESTATION_INTERMEDIATE_A_1_PEM).unwrap();
        let now = Duration::from_secs(1_900_000_000); // ~2030, inside all windows
        let res = verify_chain(&int_a, &int_a, &anchors, &pool, now);
        assert!(
            res.is_ok(),
            "real intermediate must chain to pinned root: {res:?}"
        );
    }

    // ---------------------------------------------------------------------
    // Synthetic chains. Build our own root → sub-CA → leaf with the x509
    // builder, then exercise verify_chain directly with injected anchors.
    // ---------------------------------------------------------------------

    use rsa::RsaPrivateKey;
    use rsa::pkcs1v15::SigningKey;
    use std::str::FromStr;
    use x509_cert::builder::{Builder, CertificateBuilder, Profile};
    use x509_cert::name::Name;
    use x509_cert::serial_number::SerialNumber;
    use x509_cert::spki::SubjectPublicKeyInfoOwned;
    use x509_cert::time::{Time, Validity};

    struct Node {
        cert: Certificate,
        der: Vec<u8>,
    }

    fn gen_key() -> RsaPrivateKey {
        let mut rng = rand::thread_rng();
        RsaPrivateKey::new(&mut rng, 1024).expect("rsa keygen")
    }

    fn spki_of(key: &RsaPrivateKey) -> SubjectPublicKeyInfoOwned {
        use rsa::pkcs1::EncodeRsaPublicKey;
        let pub_der = key.to_public_key().to_pkcs1_der().unwrap();
        // Wrap PKCS#1 RSAPublicKey in an rsaEncryption SubjectPublicKeyInfo.
        use x509_cert::spki::AlgorithmIdentifierOwned;
        SubjectPublicKeyInfoOwned {
            algorithm: AlgorithmIdentifierOwned {
                oid: ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1"),
                parameters: Some(der::Any::null()),
            },
            subject_public_key: x509_cert::der::asn1::BitString::from_bytes(pub_der.as_bytes())
                .unwrap(),
        }
    }

    fn far_validity() -> Validity {
        // Wide window covering "now".
        Validity::from_now(Duration::from_secs(60 * 60 * 24 * 365 * 20)).unwrap()
    }

    /// Build a cert with `subject`, signed by `signer_key` under `issuer` name.
    fn build_cert(
        profile: Profile,
        subject: &str,
        subject_key: &RsaPrivateKey,
        signer_key: &RsaPrivateKey,
        validity: Validity,
        serial: u32,
    ) -> Node {
        let signer = SigningKey::<Sha256>::new(signer_key.clone());
        let builder = CertificateBuilder::new(
            profile,
            SerialNumber::from(serial),
            validity,
            Name::from_str(subject).unwrap(),
            spki_of(subject_key),
            &signer,
        )
        .expect("builder");
        let cert: Certificate = builder.build::<RsaSignature>().expect("build/sign");
        let der = cert.to_der().expect("encode");
        Node { cert, der }
    }

    /// Root self-signed; sub-CA signed by root; leaf signed by sub-CA. Returns
    /// (leaf, sub_ca, root) so callers can inject the root as anchor and the
    /// sub-CA into the searchable pool.
    fn synthetic_chain() -> (Node, Node, Node) {
        let root_key = gen_key();
        let sub_key = gen_key();
        let leaf_key = gen_key();

        let root = build_cert(
            Profile::Root,
            "CN=Test Root",
            &root_key,
            &root_key,
            far_validity(),
            1,
        );
        let sub = build_cert(
            Profile::SubCA {
                issuer: Name::from_str("CN=Test Root").unwrap(),
                path_len_constraint: Some(1),
            },
            "CN=Test SubCA",
            &sub_key,
            &root_key,
            far_validity(),
            2,
        );
        let leaf = build_cert(
            Profile::Leaf {
                issuer: Name::from_str("CN=Test SubCA").unwrap(),
                enable_key_agreement: false,
                enable_key_encipherment: false,
            },
            "CN=Test Leaf",
            &leaf_key,
            &sub_key,
            far_validity(),
            3,
        );
        (leaf, sub, root)
    }

    fn anchor_of(node: &Node) -> TrustAnchor {
        TrustAnchor {
            cert: node.cert.clone(),
        }
    }

    fn now() -> Duration {
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap()
    }

    #[test]
    fn test_synthetic_chain_verifies() {
        let (leaf, sub, root) = synthetic_chain();
        // Device slot = sub-CA here; intermediates = [sub].
        let res = verify_chain(
            &leaf.der,
            &sub.der,
            &[anchor_of(&root)],
            &[sub.cert.clone()],
            now(),
        );
        assert!(res.is_ok(), "valid synthetic chain must verify: {res:?}");
    }

    #[test]
    fn test_tampered_signature_fails() {
        let (leaf, sub, root) = synthetic_chain();
        // Flip one byte in the leaf signature, re-encode.
        let mut tampered = leaf.cert.clone();
        let mut sig = tampered.signature.as_bytes().unwrap().to_vec();
        sig[0] ^= 0x01;
        tampered.signature = x509_cert::der::asn1::BitString::from_bytes(&sig).unwrap();
        let tampered_der = tampered.to_der().unwrap();

        let res = verify_chain(
            &tampered_der,
            &sub.der,
            &[anchor_of(&root)],
            &[sub.cert.clone()],
            now(),
        );
        assert!(
            matches!(res, Err(ChainError::SignatureInvalid)),
            "got {res:?}"
        );
    }

    #[test]
    fn test_expired_cert_fails() {
        let root_key = gen_key();
        let sub_key = gen_key();
        let leaf_key = gen_key();

        let root = build_cert(
            Profile::Root,
            "CN=Test Root",
            &root_key,
            &root_key,
            far_validity(),
            1,
        );
        let sub = build_cert(
            Profile::SubCA {
                issuer: Name::from_str("CN=Test Root").unwrap(),
                path_len_constraint: Some(1),
            },
            "CN=Test SubCA",
            &sub_key,
            &root_key,
            far_validity(),
            2,
        );
        // Leaf already expired: notBefore..notAfter both in the past.
        let expired = Validity {
            not_before: Time::UtcTime(
                x509_cert::der::asn1::UtcTime::from_unix_duration(Duration::from_secs(
                    1_000_000_000,
                ))
                .unwrap(),
            ),
            not_after: Time::UtcTime(
                x509_cert::der::asn1::UtcTime::from_unix_duration(Duration::from_secs(
                    1_100_000_000,
                ))
                .unwrap(),
            ),
        };
        let leaf = build_cert(
            Profile::Leaf {
                issuer: Name::from_str("CN=Test SubCA").unwrap(),
                enable_key_agreement: false,
                enable_key_encipherment: false,
            },
            "CN=Test Leaf",
            &leaf_key,
            &sub_key,
            expired,
            3,
        );

        let res = verify_chain(
            &leaf.der,
            &sub.der,
            &[anchor_of(&root)],
            &[sub.cert.clone()],
            now(),
        );
        assert!(matches!(res, Err(ChainError::Expired)), "got {res:?}");
    }

    #[test]
    fn test_wrong_root_fails_on_pin() {
        // Build a fully valid chain, but the actual signing root is NOT pinned.
        // Put the bogus root in the SEARCHABLE pool (so issuer-by-name succeeds and
        // its signature verifies) but NOT in the anchor set. Verification must fail
        // because no walked cert reaches a pinned terminal — exercises pin rejection,
        // not a mere "issuer not found".
        let (leaf, sub, bogus_root) = synthetic_chain();

        // A second, unrelated key serves as the only *pinned* anchor — it signs
        // nothing in this chain.
        let other_root_key = gen_key();
        let other_root = build_cert(
            Profile::Root,
            "CN=Unrelated Pinned Root",
            &other_root_key,
            &other_root_key,
            far_validity(),
            9,
        );

        let res = verify_chain(
            &leaf.der,
            &sub.der,
            &[anchor_of(&other_root)], // pinned set: unrelated root only
            &[sub.cert.clone(), bogus_root.cert.clone()], // searchable: real signer present
            now(),
        );
        // The real signing root is reachable by name+signature but is not pinned,
        // so the walk terminates without a pinned anchor.
        assert!(
            matches!(res, Err(ChainError::IssuerNotFound)),
            "wrong-root chain must be rejected at the pin, got {res:?}"
        );
    }

    #[test]
    fn test_unknown_issuer_fails() {
        let (leaf, _sub, root) = synthetic_chain();
        // No sub-CA in the pool: leaf's issuer is unfindable.
        let res = verify_chain(&leaf.der, &leaf.der, &[anchor_of(&root)], &[], now());
        assert!(
            matches!(res, Err(ChainError::IssuerNotFound)),
            "got {res:?}"
        );
    }
}
