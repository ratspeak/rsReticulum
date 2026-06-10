//! PIV APDU build/parse. Specs: ISO 7816-4 (APDU), NIST SP 800-73-4 (PIV),
//! Yubico Ed25519 (0xE0) / X25519 (0xE1) extensions.
//! Ref: <https://docs.yubico.com/yesdk/users-manual/application-piv/commands.html>

use crate::error::RatkeyError;

/// NIST RID + PIV PIX.
pub const PIV_AID: &[u8] = &[0xA0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00];

pub const INS_SELECT: u8 = 0xA4;
pub const INS_VERIFY: u8 = 0x20;
pub const INS_CHANGE_REFERENCE: u8 = 0x24;
pub const INS_RESET_RETRY: u8 = 0x2C;
pub const INS_GENERAL_AUTHENTICATE: u8 = 0x87;
pub const INS_GENERATE_ASYMMETRIC: u8 = 0x47;
pub const INS_GET_DATA: u8 = 0xCB;
pub const INS_RESET_PIV: u8 = 0xFB;
pub const INS_GET_METADATA: u8 = 0xF7;
pub const INS_ATTEST: u8 = 0xF9;
pub const INS_IMPORT_KEY: u8 = 0xFE;
pub const INS_GET_VERSION: u8 = 0xFD;
pub const INS_GET_SERIAL: u8 = 0xF8;

// Algorithm IDs; ALG_ED25519/ALG_X25519 are YubiKey 5.7+ Yubico extensions.
pub const ALG_ED25519: u8 = 0xE0;
pub const ALG_X25519: u8 = 0xE1;
pub const ALG_ECCP256: u8 = 0x11;
pub const ALG_ECCP384: u8 = 0x14;

pub const SLOT_AUTHENTICATION: u8 = 0x9A;
pub const SLOT_SIGNATURE: u8 = 0x9C;
pub const SLOT_KEY_MANAGEMENT: u8 = 0x9D;
pub const SLOT_CARD_AUTH: u8 = 0x9E;
pub const SLOT_ATTESTATION: u8 = 0xF9;
pub const SLOT_CARD_MANAGEMENT: u8 = 0x9B;

// Management-key algorithm (key reference 9B). AES-192 is the YubiKey 5.7 default.
pub const MGMT_ALG_TDES: u8 = 0x03;
pub const MGMT_ALG_AES128: u8 = 0x08;
pub const MGMT_ALG_AES192: u8 = 0x0A;
pub const MGMT_ALG_AES256: u8 = 0x0C;

pub const PIN_POLICY_NEVER: u8 = 0x01;
pub const PIN_POLICY_ONCE: u8 = 0x02;
pub const PIN_POLICY_ALWAYS: u8 = 0x03;

pub const TOUCH_POLICY_NEVER: u8 = 0x01;
pub const TOUCH_POLICY_ALWAYS: u8 = 0x02;
pub const TOUCH_POLICY_CACHED: u8 = 0x03;

const TAG_DYNAMIC_AUTH: u8 = 0x7C;
const TAG_AUTH_RESPONSE: u8 = 0x82;
const TAG_AUTH_CHALLENGE: u8 = 0x81;
/// Management-key auth witness (same byte as `TAG_GEN_ALGORITHM`, different context).
const TAG_AUTH_WITNESS: u8 = 0x80;
const TAG_AUTH_EXPONENTIATION: u8 = 0x85;
const TAG_GEN_ALGORITHM: u8 = 0x80;
const TAG_PIN_POLICY: u8 = 0xAA;
const TAG_TOUCH_POLICY: u8 = 0xAB;
const TAG_OBJECT_ID: u8 = 0x5C;
const TAG_ECC_POINT: u8 = 0x86;
/// GET METADATA public-key field (Yubico).
const TAG_METADATA_PUBLIC_KEY: u8 = 0x04;

/// Cert object ID for slot 9A (Authentication).
pub const OBJ_ID_9A: &[u8] = &[0x5F, 0xC1, 0x05];
/// Cert object ID for slot 9D (Key Management).
pub const OBJ_ID_9D: &[u8] = &[0x5F, 0xC1, 0x0B];
/// Object ID for the device attestation (slot F9) intermediate certificate.
pub const OBJ_ID_F9: &[u8] = &[0x5F, 0xFF, 0x01];

pub fn slot_to_object_id(slot: u8) -> Option<&'static [u8]> {
    match slot {
        0x9A => Some(OBJ_ID_9A),
        0x9D => Some(OBJ_ID_9D),
        SLOT_ATTESTATION => Some(OBJ_ID_F9),
        _ => None,
    }
}

/// Extract the certificate DER from a PIV GET DATA cert object response, which
/// wraps the cert as `53 L { 70 L <certDER> 71 .. FE .. }`. Falls back to the raw
/// buffer if it already looks like a bare certificate (`30` SEQUENCE).
pub fn parse_certificate_object(resp: &[u8]) -> Option<Vec<u8>> {
    let content = read_ber_tlv(resp, 0x53).unwrap_or(resp);
    if let Some(cert) = read_ber_tlv(content, 0x70) {
        return Some(cert.to_vec());
    }
    match resp.first() {
        Some(0x30) => Some(resp.to_vec()),
        _ => None,
    }
}

/// First top-level BER-TLV with `tag` in `buf`, returning its value. Handles
/// short-form and 1-/2-byte long-form lengths; single-byte tags only.
fn read_ber_tlv(buf: &[u8], tag: u8) -> Option<&[u8]> {
    let mut i = 0;
    while i + 1 < buf.len() {
        let t = buf[i];
        let len_byte = buf[i + 1];
        i += 2;
        let len = if len_byte < 0x80 {
            len_byte as usize
        } else {
            let n = (len_byte & 0x7f) as usize;
            if n == 0 || n > 2 || i + n > buf.len() {
                return None;
            }
            let mut l = 0usize;
            for _ in 0..n {
                l = (l << 8) | buf[i] as usize;
                i += 1;
            }
            l
        };
        if i + len > buf.len() {
            return None;
        }
        if t == tag {
            return Some(&buf[i..i + len]);
        }
        i += len;
    }
    None
}

// ISO 7816-4 APDU: CLA INS P1 P2 [Lc] [Data]. CLA=0x00 (no chaining, no secure messaging).
fn build_apdu(ins: u8, p1: u8, p2: u8, data: &[u8]) -> Vec<u8> {
    let mut apdu = Vec::with_capacity(5 + data.len());
    apdu.push(0x00);
    apdu.push(ins);
    apdu.push(p1);
    apdu.push(p2);
    if !data.is_empty() {
        if data.len() > 255 {
            // Extended Lc: 0x00 + 2-byte BE length.
            apdu.push(0x00);
            apdu.push((data.len() >> 8) as u8);
            apdu.push(data.len() as u8);
        } else {
            apdu.push(data.len() as u8);
        }
        apdu.extend_from_slice(data);
    }
    apdu
}

fn tlv(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + value.len());
    out.push(tag);
    encode_der_length(value.len(), &mut out);
    out.extend_from_slice(value);
    out
}

fn encode_der_length(len: usize, out: &mut Vec<u8>) {
    if len < 128 {
        out.push(len as u8);
    } else if len < 256 {
        out.push(0x81);
        out.push(len as u8);
    } else {
        out.push(0x82);
        out.push((len >> 8) as u8);
        out.push(len as u8);
    }
}

pub fn select_piv() -> Vec<u8> {
    build_apdu(INS_SELECT, 0x04, 0x00, PIV_AID)
}

/// PIN is ASCII, 0xFF-padded to 8 bytes (NIST SP 800-73-4 §2.4.3).
pub fn verify_pin(pin: &str) -> Vec<u8> {
    use zeroize::Zeroize;
    let mut pin_data = [0xFFu8; 8];
    let pin_bytes = pin.as_bytes();
    let copy_len = pin_bytes.len().min(8);
    pin_data[..copy_len].copy_from_slice(&pin_bytes[..copy_len]);
    let cmd = build_apdu(INS_VERIFY, 0x00, 0x80, &pin_data);
    pin_data.zeroize();
    cmd
}

// CHANGE REFERENCE DATA.
pub fn change_pin(old_pin: &str, new_pin: &str) -> Vec<u8> {
    use zeroize::Zeroize;
    let mut data = [0xFFu8; 16];
    let old_bytes = old_pin.as_bytes();
    let new_bytes = new_pin.as_bytes();
    let old_len = old_bytes.len().min(8);
    let new_len = new_bytes.len().min(8);
    data[..old_len].copy_from_slice(&old_bytes[..old_len]);
    data[8..8 + new_len].copy_from_slice(&new_bytes[..new_len]);
    let cmd = build_apdu(INS_CHANGE_REFERENCE, 0x00, 0x80, &data);
    data.zeroize();
    cmd
}

/// RESET RETRY COUNTER: unblock a locked PIN with the PUK and set a new PIN.
pub fn reset_retry(puk: &str, new_pin: &str) -> Vec<u8> {
    use zeroize::Zeroize;
    let mut data = [0xFFu8; 16];
    let puk_bytes = puk.as_bytes();
    let new_bytes = new_pin.as_bytes();
    let puk_len = puk_bytes.len().min(8);
    let new_len = new_bytes.len().min(8);
    data[..puk_len].copy_from_slice(&puk_bytes[..puk_len]);
    data[8..8 + new_len].copy_from_slice(&new_bytes[..new_len]);
    let cmd = build_apdu(INS_RESET_RETRY, 0x00, 0x80, &data);
    data.zeroize();
    cmd
}

/// RESET PIV: erase all PIV data and restore factory PIV secrets.
///
/// YubiKey only accepts this command after both the PIN and PUK are blocked.
pub fn reset_piv() -> Vec<u8> {
    build_apdu(INS_RESET_PIV, 0x00, 0x00, &[])
}

// GENERATE ASYMMETRIC KEY PAIR (Ed25519/X25519).
pub fn generate_key(
    slot: u8,
    algorithm: u8,
    pin_policy: Option<u8>,
    touch_policy: Option<u8>,
) -> Vec<u8> {
    let mut inner = tlv(TAG_GEN_ALGORITHM, &[algorithm]);
    if let Some(pp) = pin_policy {
        inner.extend_from_slice(&tlv(TAG_PIN_POLICY, &[pp]));
    }
    if let Some(tp) = touch_policy {
        inner.extend_from_slice(&tlv(TAG_TOUCH_POLICY, &[tp]));
    }
    let data = tlv(0xAC, &inner);
    build_apdu(INS_GENERATE_ASYMMETRIC, 0x00, slot, &data)
}

// Yubico private-key import elements: Ed25519 = 0x07, X25519 = 0x08.
const TAG_IMPORT_ED25519: u8 = 0x07;
const TAG_IMPORT_X25519: u8 = 0x08;

/// IMPORT ASYMMETRIC KEY (Ed25519, slot). Requires management-key auth. For
/// recoverable provisioning — the key was derived off-device from a seed phrase.
pub fn import_ed25519(
    slot: u8,
    private_key: &[u8; 32],
    pin_policy: Option<u8>,
    touch_policy: Option<u8>,
) -> Vec<u8> {
    import_key(
        slot,
        ALG_ED25519,
        TAG_IMPORT_ED25519,
        private_key,
        pin_policy,
        touch_policy,
    )
}

/// IMPORT ASYMMETRIC KEY (X25519, slot). Requires management-key auth.
pub fn import_x25519(
    slot: u8,
    private_key: &[u8; 32],
    pin_policy: Option<u8>,
    touch_policy: Option<u8>,
) -> Vec<u8> {
    import_key(
        slot,
        ALG_X25519,
        TAG_IMPORT_X25519,
        private_key,
        pin_policy,
        touch_policy,
    )
}

fn import_key(
    slot: u8,
    alg: u8,
    key_tag: u8,
    private_key: &[u8; 32],
    pin_policy: Option<u8>,
    touch_policy: Option<u8>,
) -> Vec<u8> {
    let mut data = tlv(key_tag, private_key);
    if let Some(pp) = pin_policy {
        data.extend_from_slice(&tlv(TAG_PIN_POLICY, &[pp]));
    }
    if let Some(tp) = touch_policy {
        data.extend_from_slice(&tlv(TAG_TOUCH_POLICY, &[tp]));
    }
    build_apdu(INS_IMPORT_KEY, alg, slot, &data)
}

/// GENERAL AUTHENTICATE Ed25519 sign. Send raw message — device does SHA-512 internally; no pre-hash.
pub fn sign_ed25519(slot: u8, message: &[u8]) -> Vec<u8> {
    let challenge = tlv(TAG_AUTH_CHALLENGE, message);
    // Empty response tag = request sig output.
    let response_request = vec![TAG_AUTH_RESPONSE, 0x00];
    let mut inner = Vec::with_capacity(response_request.len() + challenge.len());
    inner.extend_from_slice(&response_request);
    inner.extend_from_slice(&challenge);
    let data = tlv(TAG_DYNAMIC_AUTH, &inner);
    build_apdu(INS_GENERAL_AUTHENTICATE, ALG_ED25519, slot, &data)
}

/// GENERAL AUTHENTICATE X25519 ECDH: peer 32-byte pubkey in, 32-byte shared secret out.
pub fn ecdh_x25519(slot: u8, peer_public_key: &[u8; 32]) -> Vec<u8> {
    let exponentiation = tlv(TAG_AUTH_EXPONENTIATION, peer_public_key);
    let response_request = vec![TAG_AUTH_RESPONSE, 0x00];
    let mut inner = Vec::with_capacity(response_request.len() + exponentiation.len());
    inner.extend_from_slice(&response_request);
    inner.extend_from_slice(&exponentiation);
    let data = tlv(TAG_DYNAMIC_AUTH, &inner);
    build_apdu(INS_GENERAL_AUTHENTICATE, ALG_X25519, slot, &data)
}

pub fn get_data(slot: u8) -> Option<Vec<u8>> {
    let obj_id = slot_to_object_id(slot)?;
    let data = tlv(TAG_OBJECT_ID, obj_id);
    Some(build_apdu(INS_GET_DATA, 0x3F, 0xFF, &data))
}

pub fn get_metadata(slot: u8) -> Vec<u8> {
    build_apdu(INS_GET_METADATA, 0x00, slot, &[])
}

/// Yubico proprietary; unsupported on Nitrokey 3.
pub fn get_version() -> Vec<u8> {
    build_apdu(INS_GET_VERSION, 0x00, 0x00, &[])
}

/// Yubico proprietary; unsupported on Nitrokey 3.
pub fn get_serial() -> Vec<u8> {
    build_apdu(INS_GET_SERIAL, 0x00, 0x00, &[])
}

pub fn attest_key(slot: u8) -> Vec<u8> {
    build_apdu(INS_ATTEST, slot, 0x00, &[])
}

// --- Management-key authentication (slot 9B, witness/challenge mutual auth) ---

/// Step 1: request an encrypted witness from the card. `mgmt_alg` is the
/// management-key algorithm (P1).
pub fn auth_witness_request(mgmt_alg: u8) -> Vec<u8> {
    let inner = tlv(TAG_AUTH_WITNESS, &[]);
    let data = tlv(TAG_DYNAMIC_AUTH, &inner);
    build_apdu(
        INS_GENERAL_AUTHENTICATE,
        mgmt_alg,
        SLOT_CARD_MANAGEMENT,
        &data,
    )
}

/// Step 3: return the decrypted witness plus our own challenge.
pub fn auth_witness_response(mgmt_alg: u8, decrypted_witness: &[u8], challenge: &[u8]) -> Vec<u8> {
    let mut inner = tlv(TAG_AUTH_WITNESS, decrypted_witness);
    inner.extend_from_slice(&tlv(TAG_AUTH_CHALLENGE, challenge));
    let data = tlv(TAG_DYNAMIC_AUTH, &inner);
    build_apdu(
        INS_GENERAL_AUTHENTICATE,
        mgmt_alg,
        SLOT_CARD_MANAGEMENT,
        &data,
    )
}

/// Extract the witness (tag 0x80) from a witness-request response.
pub fn parse_auth_witness(data: &[u8]) -> Result<Vec<u8>, RatkeyError> {
    find_tlv_value(data, TAG_AUTH_WITNESS)
        .map(<[u8]>::to_vec)
        .ok_or(RatkeyError::Apdu {
            sw1: 0x6A,
            sw2: 0x80,
        })
}

/// Extract the card's encrypted challenge (tag 0x82) from a witness-response reply.
pub fn parse_auth_response(data: &[u8]) -> Result<Vec<u8>, RatkeyError> {
    find_tlv_value(data, TAG_AUTH_RESPONSE)
        .map(<[u8]>::to_vec)
        .ok_or(RatkeyError::Apdu {
            sw1: 0x6A,
            sw2: 0x80,
        })
}

/// Algorithm byte (tag 0x01) from a GET METADATA response (e.g. slot 9B mgmt key).
pub fn parse_metadata_algorithm(metadata: &[u8]) -> Result<u8, RatkeyError> {
    find_tlv_value(metadata, 0x01)
        .and_then(|v| v.first().copied())
        .ok_or(RatkeyError::Apdu {
            sw1: 0x6A,
            sw2: 0x80,
        })
}

pub fn check_response(response: &[u8]) -> Result<&[u8], RatkeyError> {
    if response.len() < 2 {
        return Err(RatkeyError::Apdu {
            sw1: 0x00,
            sw2: 0x00,
        });
    }
    let sw1 = response[response.len() - 2];
    let sw2 = response[response.len() - 1];
    if sw1 == 0x90 && sw2 == 0x00 {
        Ok(&response[..response.len() - 2])
    } else if sw1 == 0x63 && (sw2 & 0xF0) == 0xC0 {
        // NIST SP 800-73-4 §2.4.3: low nibble of SW2 = retries remaining.
        let remaining = sw2 & 0x0F;
        if remaining == 0 {
            Err(RatkeyError::PinLocked)
        } else {
            Err(RatkeyError::PinFailed { remaining })
        }
    } else if sw1 == 0x69 && sw2 == 0x83 {
        Err(RatkeyError::PinLocked)
    } else {
        Err(RatkeyError::Apdu { sw1, sw2 })
    }
}

/// GENERATE ASYMMETRIC response: `7F49 <len> 86 20 <32 bytes>` → 32-byte public key.
pub fn parse_generate_response(data: &[u8]) -> Result<[u8; 32], RatkeyError> {
    let key_bytes = find_tlv_value(data, TAG_ECC_POINT).ok_or(RatkeyError::Apdu {
        sw1: 0x6A,
        sw2: 0x80,
    })?;
    if key_bytes.len() != 32 {
        return Err(RatkeyError::InvalidHwid(format!(
            "expected 32-byte public key, got {} bytes",
            key_bytes.len()
        )));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(key_bytes);
    Ok(out)
}

/// GENERAL AUTHENTICATE response: `7C <len> 82 40 <64 bytes>` → 64-byte Ed25519 sig.
pub fn parse_sign_response(data: &[u8]) -> Result<[u8; 64], RatkeyError> {
    let sig_bytes = find_tlv_value(data, TAG_AUTH_RESPONSE).ok_or(RatkeyError::Apdu {
        sw1: 0x6A,
        sw2: 0x80,
    })?;
    if sig_bytes.len() != 64 {
        return Err(RatkeyError::InvalidHwid(format!(
            "expected 64-byte signature, got {} bytes",
            sig_bytes.len()
        )));
    }
    let mut out = [0u8; 64];
    out.copy_from_slice(sig_bytes);
    Ok(out)
}

/// GET VERSION → (major, minor, patch).
pub fn parse_version_response(data: &[u8]) -> Result<(u8, u8, u8), RatkeyError> {
    if data.len() != 3 {
        return Err(RatkeyError::InvalidHwid(format!(
            "expected 3-byte version, got {} bytes",
            data.len()
        )));
    }
    Ok((data[0], data[1], data[2]))
}

/// GET SERIAL → u32 (4-byte BE).
pub fn parse_serial_response(data: &[u8]) -> Result<u32, RatkeyError> {
    if data.len() != 4 {
        return Err(RatkeyError::InvalidHwid(format!(
            "expected 4-byte serial, got {} bytes",
            data.len()
        )));
    }
    Ok(u32::from_be_bytes([data[0], data[1], data[2], data[3]]))
}

/// X25519 ECDH response: `7C <len> 82 20 <32 bytes>` → 32-byte shared secret.
pub fn parse_ecdh_response(data: &[u8]) -> Result<[u8; 32], RatkeyError> {
    let secret_bytes = find_tlv_value(data, TAG_AUTH_RESPONSE).ok_or(RatkeyError::Apdu {
        sw1: 0x6A,
        sw2: 0x80,
    })?;
    if secret_bytes.len() != 32 {
        return Err(RatkeyError::InvalidHwid(format!(
            "expected 32-byte shared secret, got {} bytes",
            secret_bytes.len()
        )));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(secret_bytes);
    Ok(out)
}

/// GET METADATA public key: field tag 0x04, then EC point tag 0x86 → 32 bytes.
/// `find_tlv_value` recurses into a `7F49` wrapper if present, so both the
/// bare (`86 20 ..`) and wrapped (`7F49 .. 86 20 ..`) encodings resolve.
/// Yubico 5.3+ extension; Nitrokey 3 does not implement GET METADATA.
pub fn parse_metadata_public_key(metadata: &[u8]) -> Result<[u8; 32], RatkeyError> {
    let pubkey_field =
        find_tlv_value(metadata, TAG_METADATA_PUBLIC_KEY).ok_or(RatkeyError::Apdu {
            sw1: 0x6A,
            sw2: 0x80,
        })?;
    let point = find_tlv_value(pubkey_field, TAG_ECC_POINT).ok_or(RatkeyError::Apdu {
        sw1: 0x6A,
        sw2: 0x80,
    })?;
    if point.len() != 32 {
        return Err(RatkeyError::InvalidHwid(format!(
            "expected 32-byte public key in metadata, got {} bytes",
            point.len()
        )));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(point);
    Ok(out)
}

// Recurse into 7C / AC / 53 / any 2-byte tag (7F49 etc) to find a single-byte tag.
fn find_tlv_value(data: &[u8], target_tag: u8) -> Option<&[u8]> {
    let mut pos = 0;
    while pos < data.len() {
        let (tag_len, tag_first) = if pos < data.len() {
            (1, data[pos])
        } else {
            return None;
        };

        // 2-byte tags begin with 0x7F (e.g. 7F49 ECC pubkey).
        let tag_bytes;
        let tag_total_len;
        if tag_first == 0x7F && pos + 1 < data.len() {
            tag_bytes = 2;
            tag_total_len = 2;
            pos += 2;
        } else {
            tag_bytes = 1;
            tag_total_len = 1;
            let _ = tag_len;
            pos += 1;
        }

        if pos >= data.len() {
            return None;
        }

        let (value_len, len_bytes) = decode_der_length(&data[pos..])?;
        pos += len_bytes;

        if pos + value_len > data.len() {
            return None;
        }

        let value = &data[pos..pos + value_len];

        if tag_bytes == 1 && tag_first == target_tag {
            return Some(value);
        }

        if tag_first == TAG_DYNAMIC_AUTH
            || tag_first == 0xAC
            || tag_first == 0x53
            || (tag_total_len == 2)
        {
            if let Some(found) = find_tlv_value(value, target_tag) {
                return Some(found);
            }
        }

        pos += value_len;
    }
    None
}

fn decode_der_length(data: &[u8]) -> Option<(usize, usize)> {
    if data.is_empty() {
        return None;
    }
    let first = data[0];
    if first < 0x80 {
        Some((first as usize, 1))
    } else if first == 0x81 {
        if data.len() < 2 {
            return None;
        }
        Some((data[1] as usize, 2))
    } else if first == 0x82 {
        if data.len() < 3 {
            return None;
        }
        Some((((data[1] as usize) << 8) | data[2] as usize, 3))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_select_piv() {
        let apdu = select_piv();
        assert_eq!(
            apdu,
            vec![
                0x00, 0xA4, 0x04, 0x00, 0x09, 0xA0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00
            ]
        );
    }

    #[test]
    fn test_verify_pin_default() {
        let apdu = verify_pin("123456");
        assert_eq!(
            apdu,
            vec![
                0x00, 0x20, 0x00, 0x80, 0x08, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0xFF, 0xFF
            ]
        );
    }

    #[test]
    fn test_verify_pin_full_length() {
        let apdu = verify_pin("12345678");
        assert_eq!(
            apdu,
            vec![
                0x00, 0x20, 0x00, 0x80, 0x08, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38
            ]
        );
    }

    #[test]
    fn test_generate_ed25519_slot_9a() {
        let apdu = generate_key(SLOT_AUTHENTICATION, ALG_ED25519, None, None);
        assert_eq!(
            apdu,
            vec![0x00, 0x47, 0x00, 0x9A, 0x05, 0xAC, 0x03, 0x80, 0x01, 0xE0]
        );
    }

    #[test]
    fn test_generate_x25519_with_policies() {
        let apdu = generate_key(
            SLOT_KEY_MANAGEMENT,
            ALG_X25519,
            Some(PIN_POLICY_ONCE),
            Some(TOUCH_POLICY_CACHED),
        );
        // AC 09: 80 01 E1, AA 01 02, AB 01 03
        assert_eq!(
            apdu,
            vec![
                0x00, 0x47, 0x00, 0x9D, 0x0B, 0xAC, 0x09, 0x80, 0x01, 0xE1, 0xAA, 0x01, 0x02, 0xAB,
                0x01, 0x03
            ]
        );
    }

    #[test]
    fn test_sign_ed25519_short_message() {
        let message = [0xAA; 32];
        let apdu = sign_ed25519(SLOT_AUTHENTICATION, &message);
        // Header: 00 87 E0 9A
        assert_eq!(apdu[0], 0x00); // CLA
        assert_eq!(apdu[1], 0x87); // INS = GENERAL AUTHENTICATE
        assert_eq!(apdu[2], 0xE0); // P1 = Ed25519
        assert_eq!(apdu[3], 0x9A); // P2 = slot
        // Data starts at [5]: 7C container
        assert_eq!(apdu[5], 0x7C); // Dynamic Auth Template tag
        // Inside 7C: 82 00, 81 20 <32 bytes>
        // 82 00 = response request (2 bytes)
        // 81 20 <32 bytes> = challenge (34 bytes)
        // 7C length = 36 = 0x24
        assert_eq!(apdu[6], 0x24); // 7C length
        assert_eq!(apdu[7], 0x82); // Response tag
        assert_eq!(apdu[8], 0x00); // Empty (request)
        assert_eq!(apdu[9], 0x81); // Challenge tag
        assert_eq!(apdu[10], 0x20); // Challenge length (32)
        assert_eq!(&apdu[11..43], &message); // Message data
        assert_eq!(apdu.len(), 43);
    }

    #[test]
    fn test_sign_ed25519_empty_message() {
        let apdu = sign_ed25519(SLOT_AUTHENTICATION, &[]);
        assert_eq!(apdu[2], 0xE0); // P1 = Ed25519
        assert_eq!(apdu[9], 0x81); // Challenge tag
        assert_eq!(apdu[10], 0x00); // Challenge length = 0
    }

    #[test]
    fn test_ecdh_x25519() {
        let peer_pub = [0xBB; 32];
        let apdu = ecdh_x25519(SLOT_KEY_MANAGEMENT, &peer_pub);
        assert_eq!(apdu[0], 0x00); // CLA
        assert_eq!(apdu[1], 0x87); // INS = GENERAL AUTHENTICATE
        assert_eq!(apdu[2], 0xE1); // P1 = X25519
        assert_eq!(apdu[3], 0x9D); // P2 = Key Management slot
        assert_eq!(apdu[5], 0x7C); // Dynamic Auth Template
        assert_eq!(apdu[7], 0x82); // Response tag
        assert_eq!(apdu[8], 0x00); // Empty (request)
        assert_eq!(apdu[9], 0x85); // Exponentiation tag (NOT 0x81)
        assert_eq!(apdu[10], 0x20); // Length = 32
        assert_eq!(&apdu[11..43], &peer_pub);
    }

    #[test]
    fn test_get_data_slot_9a() {
        let apdu = get_data(SLOT_AUTHENTICATION).unwrap();
        assert_eq!(
            apdu,
            vec![0x00, 0xCB, 0x3F, 0xFF, 0x05, 0x5C, 0x03, 0x5F, 0xC1, 0x05]
        );
    }

    #[test]
    fn test_get_data_slot_9d() {
        let apdu = get_data(SLOT_KEY_MANAGEMENT).unwrap();
        assert_eq!(
            apdu,
            vec![0x00, 0xCB, 0x3F, 0xFF, 0x05, 0x5C, 0x03, 0x5F, 0xC1, 0x0B]
        );
    }

    #[test]
    fn test_attest_slot_9a() {
        let apdu = attest_key(SLOT_AUTHENTICATION);
        assert_eq!(apdu, vec![0x00, 0xF9, 0x9A, 0x00]);
    }

    #[test]
    fn test_get_data_slot_f9_attestation() {
        let apdu = get_data(SLOT_ATTESTATION).unwrap();
        assert_eq!(
            apdu,
            vec![0x00, 0xCB, 0x3F, 0xFF, 0x05, 0x5C, 0x03, 0x5F, 0xFF, 0x01]
        );
    }

    #[test]
    fn test_parse_certificate_object() {
        // A 200-byte "cert" (DER SEQUENCE header) forces long-form lengths, wrapped
        // as the PIV cert object: 53 L { 70 L <cert> 71 01 00 FE 00 }.
        let mut cert = vec![0x30, 0x81, 0xC5];
        cert.extend(std::iter::repeat_n(0xAB, 197));
        let mut inner = vec![0x70, 0x81, cert.len() as u8];
        inner.extend_from_slice(&cert);
        inner.extend_from_slice(&[0x71, 0x01, 0x00, 0xFE, 0x00]);
        let mut obj = vec![0x53, 0x81, inner.len() as u8];
        obj.extend_from_slice(&inner);

        assert_eq!(parse_certificate_object(&obj).unwrap(), cert);
        // Bare DER (no PIV wrapper) is returned as-is.
        assert_eq!(parse_certificate_object(&cert).unwrap(), cert);
        // Non-cert payload yields nothing.
        assert!(parse_certificate_object(&[0x00, 0x01, 0x02]).is_none());
    }

    #[test]
    fn test_get_metadata() {
        let apdu = get_metadata(SLOT_AUTHENTICATION);
        assert_eq!(apdu, vec![0x00, 0xF7, 0x00, 0x9A]);
    }

    #[test]
    fn test_get_version_apdu() {
        assert_eq!(get_version(), vec![0x00, 0xFD, 0x00, 0x00]);
    }

    #[test]
    fn test_get_serial_apdu() {
        assert_eq!(get_serial(), vec![0x00, 0xF8, 0x00, 0x00]);
    }

    #[test]
    fn test_parse_version_response() {
        assert_eq!(
            parse_version_response(&[0x05, 0x07, 0x01]).unwrap(),
            (5, 7, 1)
        );
    }

    #[test]
    fn test_parse_version_response_wrong_length() {
        assert!(parse_version_response(&[0x05, 0x07]).is_err());
        assert!(parse_version_response(&[0x05, 0x07, 0x01, 0x00]).is_err());
    }

    #[test]
    fn test_parse_serial_response() {
        // 0x00BC614E = 12_345_678
        assert_eq!(
            parse_serial_response(&[0x00, 0xBC, 0x61, 0x4E]).unwrap(),
            12_345_678
        );
    }

    #[test]
    fn test_parse_serial_response_wrong_length() {
        assert!(parse_serial_response(&[0x00, 0x01, 0x02]).is_err());
    }

    #[test]
    fn test_change_pin() {
        let apdu = change_pin("123456", "654321");
        assert_eq!(apdu[0], 0x00); // CLA
        assert_eq!(apdu[1], 0x24); // INS = CHANGE REFERENCE
        assert_eq!(apdu[2], 0x00); // P1
        assert_eq!(apdu[3], 0x80); // P2 = PIN
        assert_eq!(apdu[4], 0x10); // Lc = 16
        // Old PIN: 31 32 33 34 35 36 FF FF
        assert_eq!(
            &apdu[5..13],
            &[0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0xFF, 0xFF]
        );
        // New PIN: 36 35 34 33 32 31 FF FF
        assert_eq!(
            &apdu[13..21],
            &[0x36, 0x35, 0x34, 0x33, 0x32, 0x31, 0xFF, 0xFF]
        );
    }

    #[test]
    fn test_reset_retry() {
        let apdu = reset_retry("12345678", "654321");
        assert_eq!(apdu[0], 0x00); // CLA
        assert_eq!(apdu[1], 0x2C); // INS = RESET RETRY
        assert_eq!(apdu[2], 0x00); // P1
        assert_eq!(apdu[3], 0x80); // P2 = PIN
        assert_eq!(apdu[4], 0x10); // Lc = 16
        assert_eq!(
            &apdu[5..13],
            &[0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38]
        );
        assert_eq!(
            &apdu[13..21],
            &[0x36, 0x35, 0x34, 0x33, 0x32, 0x31, 0xFF, 0xFF]
        );
    }

    #[test]
    fn test_reset_piv() {
        assert_eq!(reset_piv(), vec![0x00, 0xFB, 0x00, 0x00]);
    }

    #[test]
    fn test_check_response_success() {
        let response = vec![0xAA, 0xBB, 0x90, 0x00];
        let data = check_response(&response).unwrap();
        assert_eq!(data, &[0xAA, 0xBB]);
    }

    #[test]
    fn test_check_response_pin_failed() {
        let response = vec![0x63, 0xC2]; // 2 retries remaining
        match check_response(&response) {
            Err(RatkeyError::PinFailed { remaining }) => assert_eq!(remaining, 2),
            other => panic!("expected PinFailed, got {other:?}"),
        }
    }

    #[test]
    fn test_check_response_pin_locked() {
        let response = vec![0x69, 0x83];
        assert!(matches!(
            check_response(&response),
            Err(RatkeyError::PinLocked)
        ));
    }

    #[test]
    fn test_check_response_pin_locked_via_c0() {
        let response = vec![0x63, 0xC0]; // 0 retries = locked
        assert!(matches!(
            check_response(&response),
            Err(RatkeyError::PinLocked)
        ));
    }

    #[test]
    fn test_parse_generate_response_ed25519() {
        // 7F49 22 86 20 <32 bytes key>
        let mut response = vec![0x7F, 0x49, 0x22, 0x86, 0x20];
        response.extend_from_slice(&[0xAA; 32]);
        let key = parse_generate_response(&response).unwrap();
        assert_eq!(key, [0xAA; 32]);
    }

    #[test]
    fn test_parse_sign_response() {
        // 7C 42 82 40 <64 bytes sig>
        let mut response = vec![0x7C, 0x42, 0x82, 0x40];
        response.extend_from_slice(&[0xBB; 64]);
        let sig = parse_sign_response(&response).unwrap();
        assert_eq!(sig, [0xBB; 64]);
    }

    #[test]
    fn test_parse_ecdh_response() {
        // 7C 22 82 20 <32 bytes secret>
        let mut response = vec![0x7C, 0x22, 0x82, 0x20];
        response.extend_from_slice(&[0xCC; 32]);
        let secret = parse_ecdh_response(&response).unwrap();
        assert_eq!(secret, [0xCC; 32]);
    }

    #[test]
    fn test_auth_witness_request() {
        let apdu = auth_witness_request(MGMT_ALG_AES192);
        assert_eq!(
            apdu,
            vec![0x00, 0x87, 0x0A, 0x9B, 0x04, 0x7C, 0x02, 0x80, 0x00]
        );
    }

    #[test]
    fn test_auth_witness_response_carries_witness() {
        let witness = [0xAA; 16];
        let challenge = [0xBB; 16];
        let apdu = auth_witness_response(MGMT_ALG_AES192, &witness, &challenge);
        assert_eq!(apdu[1], 0x87); // INS GENERAL AUTHENTICATE
        assert_eq!(apdu[2], 0x0A); // P1 = AES-192
        assert_eq!(apdu[3], 0x9B); // P2 = mgmt slot
        assert_eq!(apdu[5], 0x7C); // dynamic auth template
        assert_eq!(parse_auth_witness(&apdu[5..]).unwrap(), witness.to_vec());
    }

    #[test]
    fn test_parse_auth_witness() {
        let mut resp = vec![0x7C, 0x12, 0x80, 0x10];
        resp.extend_from_slice(&[0xCC; 16]);
        assert_eq!(parse_auth_witness(&resp).unwrap(), vec![0xCC; 16]);
    }

    #[test]
    fn test_parse_auth_response() {
        let mut resp = vec![0x7C, 0x12, 0x82, 0x10];
        resp.extend_from_slice(&[0xDD; 16]);
        assert_eq!(parse_auth_response(&resp).unwrap(), vec![0xDD; 16]);
    }

    #[test]
    fn test_parse_metadata_algorithm() {
        let meta = vec![0x01, 0x01, MGMT_ALG_AES192];
        assert_eq!(parse_metadata_algorithm(&meta).unwrap(), MGMT_ALG_AES192);
    }

    #[test]
    fn test_import_ed25519() {
        let key = [0x11; 32];
        let apdu = import_ed25519(
            SLOT_AUTHENTICATION,
            &key,
            Some(PIN_POLICY_ONCE),
            Some(TOUCH_POLICY_NEVER),
        );
        assert_eq!(apdu[1], 0xFE); // INS IMPORT KEY
        assert_eq!(apdu[2], 0xE0); // P1 = Ed25519
        assert_eq!(apdu[3], 0x9A); // P2 = slot
        assert_eq!(apdu[5], 0x07); // Ed25519 private-key element tag
        assert_eq!(apdu[6], 0x20); // 32-byte length
        assert_eq!(&apdu[7..39], &key);
        assert_eq!(
            &apdu[39..45],
            &[0xAA, 0x01, PIN_POLICY_ONCE, 0xAB, 0x01, TOUCH_POLICY_NEVER]
        );
    }

    #[test]
    fn test_import_x25519_tag() {
        let apdu = import_x25519(SLOT_KEY_MANAGEMENT, &[0x22; 32], None, None);
        assert_eq!(apdu[1], 0xFE);
        assert_eq!(apdu[2], 0xE1); // X25519
        assert_eq!(apdu[3], 0x9D);
        assert_eq!(apdu[5], 0x08); // X25519 private-key element tag
        assert_eq!(apdu[6], 0x20);
    }

    #[test]
    fn test_parse_metadata_public_key_bare() {
        // Slot metadata: 01(algo) 02(policy) 03(origin) 04(pubkey = 86 20 <32>).
        // Layout pending confirmation against a real YubiKey GET METADATA response.
        let mut meta = vec![
            0x01,
            0x01,
            ALG_ED25519,
            0x02,
            0x02,
            PIN_POLICY_ONCE,
            TOUCH_POLICY_ALWAYS,
            0x03,
            0x01,
            0x01,
            0x04,
            0x22,
            0x86,
            0x20,
        ];
        meta.extend_from_slice(&[0xAB; 32]);
        assert_eq!(parse_metadata_public_key(&meta).unwrap(), [0xAB; 32]);
    }

    #[test]
    fn test_parse_metadata_public_key_7f49_wrapped() {
        // Same, but the point is wrapped in a 7F49 template (04 25 7F49 22 86 20 <32>).
        let mut meta = vec![
            0x01, 0x01, ALG_X25519, 0x04, 0x25, 0x7F, 0x49, 0x22, 0x86, 0x20,
        ];
        meta.extend_from_slice(&[0xCD; 32]);
        assert_eq!(parse_metadata_public_key(&meta).unwrap(), [0xCD; 32]);
    }

    #[test]
    fn test_parse_metadata_public_key_missing_field() {
        // No 0x04 field present.
        let meta = vec![0x01, 0x01, ALG_ED25519, 0x03, 0x01, 0x01];
        assert!(parse_metadata_public_key(&meta).is_err());
    }

    #[test]
    fn test_parse_generate_response_wrong_size() {
        let mut response = vec![0x7F, 0x49, 0x12, 0x86, 0x10];
        response.extend_from_slice(&[0xAA; 16]);
        assert!(parse_generate_response(&response).is_err());
    }

    #[test]
    fn test_der_length_short() {
        let mut buf = Vec::new();
        encode_der_length(32, &mut buf);
        assert_eq!(buf, vec![0x20]);
    }

    #[test]
    fn test_der_length_medium() {
        let mut buf = Vec::new();
        encode_der_length(200, &mut buf);
        assert_eq!(buf, vec![0x81, 0xC8]);
    }

    #[test]
    fn test_der_length_long() {
        let mut buf = Vec::new();
        encode_der_length(500, &mut buf);
        assert_eq!(buf, vec![0x82, 0x01, 0xF4]);
    }

    #[test]
    fn test_decode_der_length() {
        assert_eq!(decode_der_length(&[0x20]), Some((32, 1)));
        assert_eq!(decode_der_length(&[0x81, 0xC8]), Some((200, 2)));
        assert_eq!(decode_der_length(&[0x82, 0x01, 0xF4]), Some((500, 3)));
    }

    #[test]
    fn test_sign_large_message_der_length() {
        // >127 bytes: DER extended length (0x81 prefix).
        let message = vec![0xAA; 200];
        let apdu = sign_ed25519(SLOT_AUTHENTICATION, &message);
        let response_request_pos = apdu.iter().position(|&b| b == TAG_AUTH_RESPONSE).unwrap();
        let challenge_tag_pos = response_request_pos + 2;
        assert_eq!(apdu[challenge_tag_pos], TAG_AUTH_CHALLENGE);
        assert_eq!(apdu[challenge_tag_pos + 1], 0x81);
        assert_eq!(apdu[challenge_tag_pos + 2], 200);
        assert_eq!(
            &apdu[challenge_tag_pos + 3..challenge_tag_pos + 3 + 200],
            &message[..]
        );
    }
}
