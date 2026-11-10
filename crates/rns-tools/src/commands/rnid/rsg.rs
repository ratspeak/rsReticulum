//! RSG/RSM signature containers: `create_rsg`, `validate_rsg` and
//! `extract_signed_rsg_data` from `RNS/Utilities/rnid.py:400-487@1.6.0`.
//! Validation follows Python's control flow, including which malformed
//! envelopes are "invalid" and which raise (rnid exits 254 for those).

use std::io::{Cursor, Read};

use rmpv::Value;
use sha2::{Digest, Sha256};

use rns_identity::identity::Identity;

pub const SIG_LEN: usize = 64;
pub const HASH_TYPE_SHA256: &str = "sha256";

/// Python `create_rsg(identity, message, embed, meta)` for binary output.
/// `meta` keys already present (`signer`, `pubkey`) are skipped.
pub fn create_rsg<R: Read>(
    signer_identity: &Identity,
    mut message: R,
    embed: bool,
    meta: Option<&[(String, Value)]>,
) -> Result<Vec<u8>, String> {
    if !signer_identity.has_private_key() {
        return Err(format!(
            "{} does not hold a private key",
            pretty_hash(&signer_identity.hash)
        ));
    }
    let (file_hash, embedded) = if embed {
        let mut data = Vec::new();
        message.read_to_end(&mut data).map_err(|e| e.to_string())?;
        (rns_crypto::sha::sha256(&data), Some(data))
    } else {
        (sha256_reader(message).map_err(|e| e.to_string())?, None)
    };

    let mut meta_entries = vec![
        (
            Value::from("signer"),
            Value::Binary(signer_identity.hash.to_vec()),
        ),
        (
            Value::from("pubkey"),
            Value::Binary(signer_identity.get_public_key().to_vec()),
        ),
    ];
    for (key, value) in meta.unwrap_or_default() {
        if !meta_entries.iter().any(|(k, _)| k.as_str() == Some(key)) {
            meta_entries.push((Value::from(key.as_str()), value.clone()));
        }
    }
    let mut entries = vec![
        (Value::from("hashtype"), Value::from(HASH_TYPE_SHA256)),
        (Value::from("hash"), Value::Binary(file_hash.to_vec())),
        (Value::from("meta"), Value::Map(meta_entries)),
    ];
    if let Some(message) = embedded {
        entries.push((Value::from("message"), Value::Binary(message)));
    }
    let mut envelope = Vec::new();
    rmpv::encode::write_value(&mut envelope, &Value::Map(entries)).map_err(|e| e.to_string())?;
    let signature = signer_identity
        .sign(&envelope)
        .ok_or_else(|| "signing failed".to_string())?;
    let mut out = signature.to_vec();
    out.extend_from_slice(&envelope);
    Ok(out)
}

/// `--raw` signature: Ed25519 over the file bytes.
pub fn create_raw_signature<R: Read>(
    identity: &Identity,
    mut message: R,
) -> Result<[u8; SIG_LEN], String> {
    let mut data = Vec::new();
    message.read_to_end(&mut data).map_err(|e| e.to_string())?;
    identity
        .sign(&data)
        .ok_or_else(|| "signing failed".to_string())
}

/// Python `rsg_is_legacy_format` for file contents.
pub fn is_legacy_format(rsg_data: &[u8]) -> bool {
    rsg_data.len() == SIG_LEN
}

/// Python `umsgpack.unpackb`: one object, trailing bytes ignored; invalid
/// UTF-8 strings, unhashable or duplicate map keys fail.
pub fn unpackb(data: &[u8]) -> Option<Value> {
    let value = rmpv::decode::read_value(&mut Cursor::new(data)).ok()?;
    umsgpack_acceptable(&value).then_some(value)
}

fn umsgpack_acceptable(value: &Value) -> bool {
    match value {
        Value::String(s) => s.as_str().is_some(),
        Value::Array(items) => items.iter().all(umsgpack_acceptable),
        Value::Map(entries) => entries.iter().enumerate().all(|(i, (k, v))| {
            umsgpack_acceptable(k)
                && umsgpack_acceptable(v)
                && py_hashable(k)
                && !entries[..i].iter().any(|(prev, _)| py_eq(prev, k))
        }),
        _ => true,
    }
}

fn py_hashable(value: &Value) -> bool {
    match value {
        Value::Map(_) => false,
        Value::Array(items) => items.iter().all(py_hashable),
        _ => true,
    }
}

fn py_num(value: &Value) -> Option<f64> {
    match value {
        Value::Integer(i) => i.as_f64(),
        Value::Boolean(b) => Some(f64::from(u8::from(*b))),
        Value::F32(f) => Some(f64::from(*f)),
        Value::F64(f) => Some(*f),
        _ => None,
    }
}

/// Python `==` between unpacked values.
pub fn py_eq(a: &Value, b: &Value) -> bool {
    if let (Value::Integer(x), Value::Integer(y)) = (a, b) {
        return x == y;
    }
    if let (Some(x), Some(y)) = (py_num(a), py_num(b)) {
        return x == y;
    }
    match (a, b) {
        (Value::Array(x), Value::Array(y)) => {
            x.len() == y.len() && x.iter().zip(y).all(|(p, q)| py_eq(p, q))
        }
        (Value::Map(x), Value::Map(y)) => {
            x.len() == y.len()
                && x.iter()
                    .all(|(k, v)| y.iter().any(|(k2, v2)| py_eq(k, k2) && py_eq(v, v2)))
        }
        _ => a == b,
    }
}

/// Python `extract_signed_rsg_data`.
pub fn extract_signed_rsg_data(rsg_data: &[u8]) -> Option<Value> {
    unpackb(rsg_data.get(SIG_LEN..).unwrap_or_default())
}

pub fn py_type_name(value: &Value) -> &'static str {
    match value {
        Value::Nil => "NoneType",
        Value::Boolean(_) => "bool",
        Value::Integer(_) => "int",
        Value::F32(_) | Value::F64(_) => "float",
        Value::String(_) => "str",
        Value::Binary(_) => "bytes",
        Value::Array(_) => "list",
        Value::Map(_) => "dict",
        Value::Ext(_, _) => "Ext",
    }
}

/// Python truthiness.
pub fn py_truthy(value: &Value) -> bool {
    match value {
        Value::Nil => false,
        Value::Boolean(b) => *b,
        Value::Integer(_) | Value::F32(_) | Value::F64(_) => py_num(value) != Some(0.0),
        Value::String(s) => !s.as_bytes().is_empty(),
        Value::Binary(b) => !b.is_empty(),
        Value::Array(a) => !a.is_empty(),
        Value::Map(m) => !m.is_empty(),
        Value::Ext(_, _) => true,
    }
}

/// Python `key in container`; `Err` is the TypeError text.
pub fn py_contains(container: Option<&Value>, key: &str) -> Result<bool, String> {
    match container {
        None => Err("argument of type 'NoneType' is not iterable".to_string()),
        Some(Value::Map(entries)) => Ok(entries.iter().any(|(k, _)| k.as_str() == Some(key))),
        Some(Value::Array(items)) => Ok(items.iter().any(|v| v.as_str() == Some(key))),
        Some(Value::String(s)) => Ok(s.as_str().is_some_and(|s| s.contains(key))),
        Some(Value::Binary(_)) => Err("a bytes-like object is required, not 'str'".to_string()),
        Some(other) => Err(format!(
            "argument of type '{}' is not iterable",
            py_type_name(other)
        )),
    }
}

/// Python `container[key]`; `Err` is the exception text.
pub fn py_index<'a>(container: &'a Value, key: &str) -> Result<&'a Value, String> {
    match container {
        Value::Map(entries) => entries
            .iter()
            .find(|(k, _)| k.as_str() == Some(key))
            .map(|(_, v)| v)
            .ok_or_else(|| format!("'{key}'")),
        Value::Array(_) => Err("list indices must be integers or slices, not str".to_string()),
        Value::String(_) => Err("string indices must be integers, not 'str'".to_string()),
        Value::Binary(_) => Err("byte indices must be integers or slices, not str".to_string()),
        other => Err(format!(
            "'{}' object is not subscriptable",
            py_type_name(other)
        )),
    }
}

/// Python `type(x)` as printed in `TypeError` messages.
pub fn py_class(value: &Value) -> String {
    format!(
        "<class '{}'>",
        match value {
            Value::Ext(_, _) => "RNS.vendor.umsgpack.Ext",
            other => py_type_name(other),
        }
    )
}

/// The `message` argument of `validate_rsg`.
pub enum Message<'a> {
    File(&'a mut dyn Read),
    Unpacked(&'a Value),
}

/// The `required_signer` argument of `validate_rsg`.
#[derive(Clone, Copy)]
pub enum RequiredSigner<'a> {
    Identity(&'a Identity),
    Hash(&'a [u8]),
}

/// A `(True, signed_data, signing_identity)` result.
pub struct Valid {
    pub signed_data: Value,
    pub signer_hash: [u8; 16],
}

/// Python `validate_rsg`: `Ok(None)` is an invalid signature, `Err` is an
/// exception (rnid prints `Error while validating ...` and exits 254).
pub fn validate_rsg(
    rsg_data: &[u8],
    message: Message<'_>,
    required_signer: Option<RequiredSigner<'_>>,
) -> Result<Option<Valid>, String> {
    if let Message::Unpacked(value) = &message
        && !py_truthy(value)
    {
        return Err("No message specified for rsg validation".to_string());
    }
    let rsg_hash: Vec<u8> = match message {
        Message::File(reader) => sha256_reader(reader).map_err(|e| e.to_string())?.to_vec(),
        Message::Unpacked(Value::Binary(b)) => rns_crypto::sha::sha256(b).to_vec(),
        Message::Unpacked(Value::String(s)) if s.as_str().is_some() => {
            rns_crypto::sha::sha256(s.as_bytes()).to_vec()
        }
        Message::Unpacked(other) => {
            return Err(format!(
                "Invalid input type {} for rsg creation",
                py_class(other)
            ));
        }
    };
    if rsg_data.len() == SIG_LEN {
        return Err("Cannot validate legacy rsg format".to_string());
    }
    if rsg_data.len() < SIG_LEN + 1 {
        return Ok(None);
    }
    let mut signature = [0u8; SIG_LEN];
    signature.copy_from_slice(&rsg_data[..SIG_LEN]);
    let envelope = &rsg_data[SIG_LEN..];
    let Some(signed_data) = unpackb(envelope) else {
        return Ok(None);
    };

    if !py_contains(Some(&signed_data), "hashtype")? || !py_contains(Some(&signed_data), "hash")? {
        return Ok(None);
    }
    if py_index(&signed_data, "hashtype")?.as_str() != Some(HASH_TYPE_SHA256) {
        return Ok(None);
    }
    if !py_contains(Some(&signed_data), "meta")? {
        return Ok(None);
    }
    let meta = py_index(&signed_data, "meta")?;
    if !py_contains(Some(meta), "signer")? || !py_contains(Some(meta), "pubkey")? {
        return Ok(None);
    }

    // `None` stands for an identity whose public key failed to load.
    let signing_identity: Option<Identity> = match required_signer {
        Some(RequiredSigner::Identity(identity)) => Some(identity.clone()),
        _ => {
            let Ok(pubkey) = py_index(meta, "pubkey") else {
                return Ok(None);
            };
            match pubkey {
                Value::Binary(b) if b.len() == 64 => Identity::from_public_key(b).ok(),
                _ => None,
            }
        }
    };
    let signing_hash = signing_identity.as_ref().map(|i| i.hash.to_vec());
    let required_hash = match required_signer {
        Some(RequiredSigner::Identity(identity)) => Some(identity.hash.to_vec()),
        Some(RequiredSigner::Hash(hash)) => Some(hash.to_vec()),
        None => signing_hash.clone(),
    };
    if signing_hash != required_hash {
        return Ok(None);
    }
    if !matches!(py_index(&signed_data, "hash")?, Value::Binary(h) if *h == rsg_hash) {
        return Ok(None);
    }
    let Some(identity) = signing_identity else {
        return Err(
            "'Signature validation failed because identity does not hold a public key'".to_string(),
        );
    };
    if !identity.verify(envelope, &signature) {
        return Ok(None);
    }
    Ok(Some(Valid {
        signed_data,
        signer_hash: identity.hash,
    }))
}

fn sha256_reader<R: Read>(mut reader: R) -> std::io::Result<[u8; 32]> {
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let n = reader.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        hasher.update(&buffer[..n]);
    }
    Ok(hasher.finalize().into())
}

pub fn pretty_hash(hash: &[u8]) -> String {
    format!("<{}>", hex::encode(hash))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Generated by upstream rnid.py create_rsg with the identity below; the
    // container format is unchanged in RNS 1.6.0.
    const FIXTURE_PRV_HEX: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f";
    const FIXTURE_MESSAGE: &str = "Hello Reticulum 1.3.8 signed message test.\nSecond line æø.";
    const FIXTURE_RSM_HEX: &str = "266bce756d1873e4b44113fd24bd57c9c8e78dc25b5acd109e9417b045a5d736520049307a49293c13b432a5899065374060fe8b97d7ef4228e40c7bdcafbf0384a86861736874797065a6736861323536a468617368c420322779176317ebc50102a216a56a68d41c8e9aa1c849f4d4eded5c31ba542795a46d65746182a67369676e6572c410aca31af0441d81dbec71e82da0b4b5f5a67075626b6579c4408f40c5adb68f25624ae5b214ea767a6ec94d829d3d7b5e1ad1ba6f3e2138285f29acbae141bccaf0b22e1a94d34d0bc7361e526d0bfe12c89794bc9322966dd7a76d657373616765c43c48656c6c6f205265746963756c756d20312e332e38207369676e6564206d65737361676520746573742e0a5365636f6e64206c696e6520c3a6c3b82e";
    const FIXTURE_RSG_HEX: &str = "804718b7b983d4d555035627aab086d91ecddea89eaf7c75aa72b5275038b478c5db2c105841a8aa06c18dc6b84a2638694937a9b649a3a06ed1d4ba3127800083a86861736874797065a6736861323536a468617368c420322779176317ebc50102a216a56a68d41c8e9aa1c849f4d4eded5c31ba542795a46d65746182a67369676e6572c410aca31af0441d81dbec71e82da0b4b5f5a67075626b6579c4408f40c5adb68f25624ae5b214ea767a6ec94d829d3d7b5e1ad1ba6f3e2138285f29acbae141bccaf0b22e1a94d34d0bc7361e526d0bfe12c89794bc9322966dd7";

    fn fixture_identity() -> Identity {
        Identity::from_private_key(&hex::decode(FIXTURE_PRV_HEX).unwrap()).unwrap()
    }

    #[test]
    fn created_containers_are_byte_exact_with_upstream() {
        let identity = fixture_identity();
        let rsm = create_rsg(&identity, FIXTURE_MESSAGE.as_bytes(), true, None).unwrap();
        assert_eq!(hex::encode(&rsm), FIXTURE_RSM_HEX);
        let rsg = create_rsg(&identity, FIXTURE_MESSAGE.as_bytes(), false, None).unwrap();
        assert_eq!(hex::encode(&rsg), FIXTURE_RSG_HEX);
    }

    #[test]
    fn upstream_containers_validate() {
        let identity = fixture_identity();
        let rsg = hex::decode(FIXTURE_RSG_HEX).unwrap();
        let mut file = FIXTURE_MESSAGE.as_bytes();
        let valid = validate_rsg(&rsg, Message::File(&mut file), None)
            .unwrap()
            .unwrap();
        assert_eq!(valid.signer_hash, identity.hash);

        let rsm = hex::decode(FIXTURE_RSM_HEX).unwrap();
        let envelope = extract_signed_rsg_data(&rsm).unwrap();
        let message = py_index(&envelope, "message").unwrap().clone();
        let valid = validate_rsg(
            &rsm,
            Message::Unpacked(&message),
            Some(RequiredSigner::Hash(&identity.hash)),
        )
        .unwrap()
        .unwrap();
        assert_eq!(valid.signer_hash, identity.hash);
    }
}
