use std::fmt;
use std::io::{Cursor, Read};

use rmpv::Value;
use sha2::{Digest, Sha256};

use rns_identity::identity::Identity;

pub const SIG_LEN: usize = 64;
pub const HASH_TYPE_SHA256: &str = "sha256";

#[derive(Debug)]
pub enum RsgError {
    LegacyFormat,
    InvalidLength,
    Msgpack(String),
    InvalidEnvelope(&'static str),
    UnsupportedHashType(String),
    BadPublicKey(String),
    RequiredSignerMismatch,
    SignerMetadataMismatch,
    HashMismatch,
    SignatureInvalid,
    MissingPrivateKey,
    Io(std::io::Error),
}

impl fmt::Display for RsgError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LegacyFormat => write!(f, "cannot validate legacy rsg format"),
            Self::InvalidLength => write!(f, "rsg data is too short"),
            Self::Msgpack(e) => write!(f, "msgpack error: {e}"),
            Self::InvalidEnvelope(e) => write!(f, "invalid rsg envelope: {e}"),
            Self::UnsupportedHashType(t) => write!(f, "unsupported rsg hash type: {t}"),
            Self::BadPublicKey(e) => write!(f, "invalid signer public key: {e}"),
            Self::RequiredSignerMismatch => {
                write!(f, "signature was not made by the required signer")
            }
            Self::SignerMetadataMismatch => {
                write!(f, "rsg signer metadata does not match embedded public key")
            }
            Self::HashMismatch => write!(f, "rsg hash does not match message"),
            Self::SignatureInvalid => write!(f, "rsg signature is invalid"),
            Self::MissingPrivateKey => write!(f, "signing identity does not hold a private key"),
            Self::Io(e) => write!(f, "io error: {e}"),
        }
    }
}

impl From<std::io::Error> for RsgError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

#[derive(Clone, Copy)]
pub enum RequiredSigner<'a> {
    Identity(&'a Identity),
    Hash([u8; 16]),
}

#[derive(Debug)]
pub struct ValidatedRsg {
    pub signer_hash: [u8; 16],
    pub file_hash: [u8; 32],
    pub public_key: [u8; 64],
    /// Full envelope meta map, for `--meta` display (Python signed_data["meta"]).
    pub meta: Vec<(Value, Value)>,
}

struct ParsedEnvelope {
    hashtype: String,
    file_hash: [u8; 32],
    signer_hash: [u8; 16],
    public_key: [u8; 64],
    meta: Vec<(Value, Value)>,
}

pub fn is_legacy_format(rsg_data: &[u8]) -> bool {
    rsg_data.len() == SIG_LEN
}

/// Python ref: 1.3.8 rnid.py:488-516 create_rsg. With `embed` the message
/// bytes are packed into the envelope under "message"; `meta` keys not
/// already present are merged into the envelope meta map (rnid.py:501-503).
pub fn create_rsg<R: Read>(
    signer_identity: &Identity,
    mut message: R,
    embed: bool,
    meta: Option<&[(String, Value)]>,
) -> Result<Vec<u8>, RsgError> {
    if !signer_identity.has_private_key() {
        return Err(RsgError::MissingPrivateKey);
    }

    let (file_hash, embedded) = if embed {
        let mut data = Vec::new();
        message.read_to_end(&mut data)?;
        (rns_crypto::sha::sha256(&data), Some(data))
    } else {
        (sha256_reader(message)?, None)
    };
    let envelope = encode_envelope(signer_identity, file_hash, embedded.as_deref(), meta)?;
    let signature = signer_identity
        .sign(&envelope)
        .ok_or(RsgError::MissingPrivateKey)?;

    let mut out = Vec::with_capacity(SIG_LEN + envelope.len());
    out.extend_from_slice(&signature);
    out.extend_from_slice(&envelope);
    Ok(out)
}

// TODO(rngit): Python 1.3.8 rnid.py:588-600 also hosts check_release_rsm_structure,
// the canonical release-manifest validator consumed only by rngit/server.py.
// Excluded per the rngit/release-manifest stub policy; a Rust rngit must port it.

/// Decode the msgpack envelope after the 64-byte signature without any
/// validation. Python ref: 1.3.8 rnid.py:413-419 extract_signed_rsg_data.
pub fn extract_signed_rsg_data(rsg_data: &[u8]) -> Option<Value> {
    let envelope = rsg_data.get(SIG_LEN..)?;
    rmpv::decode::read_value(&mut Cursor::new(envelope)).ok()
}

pub fn create_raw_signature<R: Read>(
    signer_identity: &Identity,
    mut message: R,
) -> Result<[u8; SIG_LEN], RsgError> {
    if !signer_identity.has_private_key() {
        return Err(RsgError::MissingPrivateKey);
    }
    let mut data = Vec::new();
    message.read_to_end(&mut data)?;
    signer_identity
        .sign(&data)
        .ok_or(RsgError::MissingPrivateKey)
}

pub fn validate_rsg<R: Read>(
    rsg_data: &[u8],
    message: R,
    required_signer: Option<RequiredSigner<'_>>,
) -> Result<ValidatedRsg, RsgError> {
    if rsg_data.len() == SIG_LEN {
        return Err(RsgError::LegacyFormat);
    }
    if rsg_data.len() < SIG_LEN + 1 {
        return Err(RsgError::InvalidLength);
    }

    let mut signature = [0u8; SIG_LEN];
    signature.copy_from_slice(&rsg_data[..SIG_LEN]);
    let envelope = &rsg_data[SIG_LEN..];
    let parsed = parse_envelope(envelope)?;
    if parsed.hashtype != HASH_TYPE_SHA256 {
        return Err(RsgError::UnsupportedHashType(parsed.hashtype));
    }

    let embedded_identity = Identity::from_public_key(&parsed.public_key)
        .map_err(|e| RsgError::BadPublicKey(e.to_string()))?;
    if embedded_identity.hash != parsed.signer_hash {
        return Err(RsgError::SignerMetadataMismatch);
    }

    let verification_identity = match required_signer {
        Some(RequiredSigner::Identity(identity)) => {
            if identity.hash != parsed.signer_hash {
                return Err(RsgError::RequiredSignerMismatch);
            }
            identity
        }
        Some(RequiredSigner::Hash(hash)) => {
            if hash != parsed.signer_hash {
                return Err(RsgError::RequiredSignerMismatch);
            }
            &embedded_identity
        }
        None => &embedded_identity,
    };

    let file_hash = sha256_reader(message)?;
    if parsed.file_hash != file_hash {
        return Err(RsgError::HashMismatch);
    }
    if !verification_identity.verify(envelope, &signature) {
        return Err(RsgError::SignatureInvalid);
    }

    Ok(ValidatedRsg {
        signer_hash: parsed.signer_hash,
        file_hash: parsed.file_hash,
        public_key: parsed.public_key,
        meta: parsed.meta,
    })
}

pub fn validate_legacy_signature<R: Read>(
    signature_data: &[u8],
    mut message: R,
    required_identity: &Identity,
) -> Result<(), RsgError> {
    if signature_data.len() != SIG_LEN {
        return Err(RsgError::InvalidLength);
    }
    let mut signature = [0u8; SIG_LEN];
    signature.copy_from_slice(signature_data);
    let mut data = Vec::new();
    message.read_to_end(&mut data)?;
    if required_identity.verify(&data, &signature) {
        Ok(())
    } else {
        Err(RsgError::SignatureInvalid)
    }
}

fn sha256_reader<R: Read>(mut reader: R) -> Result<[u8; 32], RsgError> {
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

// Envelope layout matches Python 1.3.8 byte-for-byte: top-level key order
// hashtype, hash, meta, [message]; meta order signer, pubkey, then merged
// keys. The meta.note field is no longer emitted (dropped upstream in
// 1.2.8/1.3.2, commits a2193b9f/22ab5c29).
fn encode_envelope(
    identity: &Identity,
    file_hash: [u8; 32],
    message: Option<&[u8]>,
    meta: Option<&[(String, Value)]>,
) -> Result<Vec<u8>, RsgError> {
    let mut meta_entries = vec![
        (Value::from("signer"), Value::Binary(identity.hash.to_vec())),
        (
            Value::from("pubkey"),
            Value::Binary(identity.get_public_key().to_vec()),
        ),
    ];
    if let Some(meta) = meta {
        for (key, value) in meta {
            let present = meta_entries
                .iter()
                .any(|(k, _)| value_as_str(k) == Some(key.as_str()));
            if !present {
                meta_entries.push((Value::from(key.as_str()), value.clone()));
            }
        }
    }
    let mut entries = vec![
        (Value::from("hashtype"), Value::from(HASH_TYPE_SHA256)),
        (Value::from("hash"), Value::Binary(file_hash.to_vec())),
        (Value::from("meta"), Value::Map(meta_entries)),
    ];
    if let Some(message) = message {
        entries.push((Value::from("message"), Value::Binary(message.to_vec())));
    }
    let envelope = Value::Map(entries);
    let mut buf = Vec::new();
    rmpv::encode::write_value(&mut buf, &envelope).map_err(|e| RsgError::Msgpack(e.to_string()))?;
    Ok(buf)
}

fn parse_envelope(envelope: &[u8]) -> Result<ParsedEnvelope, RsgError> {
    let value = rmpv::decode::read_value(&mut Cursor::new(envelope))
        .map_err(|e| RsgError::Msgpack(e.to_string()))?;
    let Value::Map(map) = value else {
        return Err(RsgError::InvalidEnvelope("top-level value is not a map"));
    };

    let hashtype = map_get(&map, "hashtype")
        .and_then(value_as_str)
        .ok_or(RsgError::InvalidEnvelope("missing hashtype"))?
        .to_string();
    let file_hash = map_get(&map, "hash")
        .and_then(value_as_bytes)
        .and_then(slice_to_array::<32>)
        .ok_or(RsgError::InvalidEnvelope("missing or invalid hash"))?;
    let meta = map_get(&map, "meta").ok_or(RsgError::InvalidEnvelope("missing meta"))?;
    let Value::Map(meta_map) = meta else {
        return Err(RsgError::InvalidEnvelope("meta is not a map"));
    };
    let signer_hash = map_get(meta_map, "signer")
        .and_then(value_as_bytes)
        .and_then(slice_to_array::<16>)
        .ok_or(RsgError::InvalidEnvelope("missing or invalid meta.signer"))?;
    let public_key = map_get(meta_map, "pubkey")
        .and_then(value_as_bytes)
        .and_then(slice_to_array::<64>)
        .ok_or(RsgError::InvalidEnvelope("missing or invalid meta.pubkey"))?;
    // meta.note is neither required nor emitted since upstream 1.2.8/1.3.2;
    // envelopes still carrying it (incl. note:nil) remain accepted.

    Ok(ParsedEnvelope {
        hashtype,
        file_hash,
        signer_hash,
        public_key,
        meta: meta_map.clone(),
    })
}

fn map_get<'a>(map: &'a [(Value, Value)], key: &str) -> Option<&'a Value> {
    map.iter()
        .find(|(k, _)| value_as_str(k) == Some(key))
        .map(|(_, v)| v)
}

fn value_as_str(value: &Value) -> Option<&str> {
    match value {
        Value::String(s) => s.as_str(),
        _ => None,
    }
}

fn value_as_bytes(value: &Value) -> Option<&[u8]> {
    match value {
        Value::Binary(bytes) => Some(bytes.as_slice()),
        Value::String(s) => s.as_str().map(str::as_bytes),
        _ => None,
    }
}

fn slice_to_array<const N: usize>(bytes: &[u8]) -> Option<[u8; N]> {
    if bytes.len() != N {
        return None;
    }
    let mut out = [0u8; N];
    out.copy_from_slice(bytes);
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn message() -> &'static [u8] {
        b"Reticulum 1.2.5 rsg test payload"
    }

    fn pack_value(value: Value) -> Vec<u8> {
        let mut out = Vec::new();
        rmpv::encode::write_value(&mut out, &value).unwrap();
        out
    }

    fn envelope_value(
        hashtype: Option<Value>,
        file_hash: Option<Value>,
        meta: Option<Value>,
    ) -> Value {
        let mut entries = Vec::new();
        if let Some(v) = hashtype {
            entries.push((Value::from("hashtype"), v));
        }
        if let Some(v) = file_hash {
            entries.push((Value::from("hash"), v));
        }
        if let Some(v) = meta {
            entries.push((Value::from("meta"), v));
        }
        Value::Map(entries)
    }

    fn meta_value(signer: Option<Value>, pubkey: Option<Value>, note: Option<Value>) -> Value {
        let mut entries = Vec::new();
        if let Some(v) = signer {
            entries.push((Value::from("signer"), v));
        }
        if let Some(v) = pubkey {
            entries.push((Value::from("pubkey"), v));
        }
        if let Some(v) = note {
            entries.push((Value::from("note"), v));
        }
        Value::Map(entries)
    }

    fn signed_rsg(signer: &Identity, envelope: Vec<u8>) -> Vec<u8> {
        let signature = signer.sign(&envelope).unwrap();
        let mut out = signature.to_vec();
        out.extend(envelope);
        out
    }

    #[test]
    fn validates_new_rsg_with_embedded_signer() {
        let identity = Identity::new();
        let rsg = create_rsg(&identity, message(), false, None).unwrap();
        assert!(!is_legacy_format(&rsg));

        let validated = validate_rsg(&rsg, message(), None).unwrap();
        assert_eq!(validated.signer_hash, identity.hash);
        assert_eq!(validated.file_hash, rns_crypto::sha::sha256(message()));
        assert_eq!(validated.public_key, identity.get_public_key());
    }

    #[test]
    fn validates_new_rsg_with_required_hash() {
        let identity = Identity::new();
        let rsg = create_rsg(&identity, message(), false, None).unwrap();

        let validated =
            validate_rsg(&rsg, message(), Some(RequiredSigner::Hash(identity.hash))).unwrap();
        assert_eq!(validated.signer_hash, identity.hash);
    }

    #[test]
    fn rejects_wrong_required_hash() {
        let identity = Identity::new();
        let other = Identity::new();
        let rsg = create_rsg(&identity, message(), false, None).unwrap();

        let err =
            validate_rsg(&rsg, message(), Some(RequiredSigner::Hash(other.hash))).unwrap_err();
        assert!(matches!(err, RsgError::RequiredSignerMismatch));
    }

    #[test]
    fn rejects_modified_message() {
        let identity = Identity::new();
        let rsg = create_rsg(&identity, message(), false, None).unwrap();

        let err = validate_rsg(&rsg, b"modified".as_slice(), None).unwrap_err();
        assert!(matches!(err, RsgError::HashMismatch));
    }

    #[test]
    fn created_envelope_omits_note_field() {
        let identity = Identity::new();
        let rsg = create_rsg(&identity, message(), false, None).unwrap();
        let Some(Value::Map(map)) = extract_signed_rsg_data(&rsg) else {
            panic!("envelope must decode to a map");
        };
        let Some(Value::Map(meta)) = map_get(&map, "meta").cloned() else {
            panic!("meta must be a map");
        };
        let keys: Vec<_> = meta.iter().filter_map(|(k, _)| value_as_str(k)).collect();
        assert_eq!(keys, ["signer", "pubkey"]);
    }

    #[test]
    fn accepts_envelope_with_legacy_note_field() {
        // Python <=1.3.1 emitted meta.note (note:None shim) — stays accepted.
        let identity = Identity::new();
        let envelope = pack_value(envelope_value(
            Some(Value::from(HASH_TYPE_SHA256)),
            Some(Value::Binary(rns_crypto::sha::sha256(message()).to_vec())),
            Some(meta_value(
                Some(Value::Binary(identity.hash.to_vec())),
                Some(Value::Binary(identity.get_public_key().to_vec())),
                Some(Value::Nil),
            )),
        ));
        let rsg = signed_rsg(&identity, envelope);

        let validated = validate_rsg(&rsg, message(), None).unwrap();
        assert_eq!(validated.signer_hash, identity.hash);
    }

    #[test]
    fn embeds_message_and_merges_meta() {
        let identity = Identity::new();
        let meta = vec![
            ("title".to_string(), Value::from("t")),
            // Reserved keys must not be overridden by merged meta.
            ("signer".to_string(), Value::from("bogus")),
        ];
        let rsg = create_rsg(&identity, message(), true, Some(&meta)).unwrap();

        let Some(Value::Map(map)) = extract_signed_rsg_data(&rsg) else {
            panic!("envelope must decode to a map");
        };
        assert_eq!(
            map_get(&map, "message").and_then(value_as_bytes),
            Some(message())
        );
        let Some(Value::Map(meta_map)) = map_get(&map, "meta").cloned() else {
            panic!("meta must be a map");
        };
        let keys: Vec<_> = meta_map
            .iter()
            .filter_map(|(k, _)| value_as_str(k))
            .collect();
        assert_eq!(keys, ["signer", "pubkey", "title"]);
        assert_eq!(
            map_get(&meta_map, "signer").and_then(value_as_bytes),
            Some(identity.hash.as_slice())
        );

        // The embedded message validates against the envelope hash.
        let validated = validate_rsg(&rsg, message(), None).unwrap();
        assert_eq!(validated.signer_hash, identity.hash);
    }

    #[test]
    fn extract_returns_none_on_bad_envelope() {
        assert!(extract_signed_rsg_data(&[0u8; 10]).is_none());
        let mut rsg = vec![0u8; SIG_LEN];
        rsg.extend_from_slice(&[0xd9, 0x20]);
        assert!(extract_signed_rsg_data(&rsg).is_none());
    }

    // Fixture generated by running the VERBATIM Python 1.3.8 rnid.py create_rsg
    // (git show 1.3.8:RNS/Utilities/rnid.py) with embed=True over MESSAGE using
    // the identity below (vendored umsgpack + RNS Identity from pip rns).
    const FIXTURE_PRV_HEX: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f";
    const FIXTURE_MESSAGE: &str = "Hello Reticulum 1.3.8 signed message test.\nSecond line æø.";
    const FIXTURE_RSM_HEX: &str = "266bce756d1873e4b44113fd24bd57c9c8e78dc25b5acd109e9417b045a5d736520049307a49293c13b432a5899065374060fe8b97d7ef4228e40c7bdcafbf0384a86861736874797065a6736861323536a468617368c420322779176317ebc50102a216a56a68d41c8e9aa1c849f4d4eded5c31ba542795a46d65746182a67369676e6572c410aca31af0441d81dbec71e82da0b4b5f5a67075626b6579c4408f40c5adb68f25624ae5b214ea767a6ec94d829d3d7b5e1ad1ba6f3e2138285f29acbae141bccaf0b22e1a94d34d0bc7361e526d0bfe12c89794bc9322966dd7a76d657373616765c43c48656c6c6f205265746963756c756d20312e332e38207369676e6564206d65737361676520746573742e0a5365636f6e64206c696e6520c3a6c3b82e";

    fn fixture_identity() -> Identity {
        Identity::from_private_key(&hex::decode(FIXTURE_PRV_HEX).unwrap()).unwrap()
    }

    // Same generator, embed=False: a plain note-less .rsg as Python >=1.3.2
    // emits it (rsg-note-field-drop).
    const FIXTURE_RSG_HEX: &str = "804718b7b983d4d555035627aab086d91ecddea89eaf7c75aa72b5275038b478c5db2c105841a8aa06c18dc6b84a2638694937a9b649a3a06ed1d4ba3127800083a86861736874797065a6736861323536a468617368c420322779176317ebc50102a216a56a68d41c8e9aa1c849f4d4eded5c31ba542795a46d65746182a67369676e6572c410aca31af0441d81dbec71e82da0b4b5f5a67075626b6579c4408f40c5adb68f25624ae5b214ea767a6ec94d829d3d7b5e1ad1ba6f3e2138285f29acbae141bccaf0b22e1a94d34d0bc7361e526d0bfe12c89794bc9322966dd7";

    #[test]
    fn embedded_message_rsm_is_byte_exact_with_python_138() {
        let identity = fixture_identity();
        let rsg = create_rsg(&identity, FIXTURE_MESSAGE.as_bytes(), true, None).unwrap();
        assert_eq!(hex::encode(&rsg), FIXTURE_RSM_HEX);
    }

    #[test]
    fn plain_rsg_is_byte_exact_with_python_138_and_cross_validates() {
        let identity = fixture_identity();
        let rsg = create_rsg(&identity, FIXTURE_MESSAGE.as_bytes(), false, None).unwrap();
        assert_eq!(hex::encode(&rsg), FIXTURE_RSG_HEX);

        // Python >=1.3.2 note-less output is accepted by the Rust validator.
        let python_rsg = hex::decode(FIXTURE_RSG_HEX).unwrap();
        let validated = validate_rsg(&python_rsg, FIXTURE_MESSAGE.as_bytes(), None).unwrap();
        assert_eq!(validated.signer_hash, identity.hash);
    }

    #[test]
    fn validates_python_138_created_rsm() {
        let rsm = hex::decode(FIXTURE_RSM_HEX).unwrap();
        let identity = fixture_identity();

        let Some(Value::Map(map)) = extract_signed_rsg_data(&rsm) else {
            panic!("fixture envelope must decode to a map");
        };
        let embedded = map_get(&map, "message")
            .and_then(value_as_bytes)
            .expect("fixture must embed a message");
        assert_eq!(embedded, FIXTURE_MESSAGE.as_bytes());

        let validated =
            validate_rsg(&rsm, embedded, Some(RequiredSigner::Hash(identity.hash))).unwrap();
        assert_eq!(validated.signer_hash, identity.hash);
        assert_eq!(validated.public_key, identity.get_public_key());
    }

    #[test]
    fn validates_legacy_raw_signature() {
        let identity = Identity::new();
        let sig = create_raw_signature(&identity, message()).unwrap();
        validate_legacy_signature(&sig, message(), &identity).unwrap();
    }

    #[test]
    fn new_validator_rejects_legacy_format() {
        let identity = Identity::new();
        let sig = create_raw_signature(&identity, message()).unwrap();
        let err =
            validate_rsg(&sig, message(), Some(RequiredSigner::Identity(&identity))).unwrap_err();
        assert!(matches!(err, RsgError::LegacyFormat));
    }

    #[test]
    fn rejects_truncated_rsg() {
        let err = validate_rsg(&[0u8; SIG_LEN - 1], message(), None).unwrap_err();
        assert!(matches!(err, RsgError::InvalidLength));
    }

    #[test]
    fn rejects_bad_msgpack_envelope() {
        let mut rsg = vec![0u8; SIG_LEN];
        rsg.extend_from_slice(&[0xd9, 0x20]);
        let err = validate_rsg(&rsg, message(), None).unwrap_err();
        assert!(matches!(err, RsgError::Msgpack(_)));
    }

    #[test]
    fn rejects_missing_required_envelope_fields() {
        let identity = Identity::new();
        let file_hash = Value::Binary(rns_crypto::sha::sha256(message()).to_vec());
        let meta = meta_value(
            Some(Value::Binary(identity.hash.to_vec())),
            Some(Value::Binary(identity.get_public_key().to_vec())),
            Some(Value::Nil),
        );

        let missing_hashtype = signed_rsg(
            &identity,
            pack_value(envelope_value(
                None,
                Some(file_hash.clone()),
                Some(meta.clone()),
            )),
        );
        let err = validate_rsg(&missing_hashtype, message(), None).unwrap_err();
        assert!(matches!(err, RsgError::InvalidEnvelope("missing hashtype")));

        let missing_signer = signed_rsg(
            &identity,
            pack_value(envelope_value(
                Some(Value::from(HASH_TYPE_SHA256)),
                Some(file_hash.clone()),
                Some(meta_value(
                    None,
                    Some(Value::Binary(identity.get_public_key().to_vec())),
                    Some(Value::Nil),
                )),
            )),
        );
        let err = validate_rsg(&missing_signer, message(), None).unwrap_err();
        assert!(matches!(
            err,
            RsgError::InvalidEnvelope("missing or invalid meta.signer")
        ));

        let missing_pubkey = signed_rsg(
            &identity,
            pack_value(envelope_value(
                Some(Value::from(HASH_TYPE_SHA256)),
                Some(file_hash),
                Some(meta_value(
                    Some(Value::Binary(identity.hash.to_vec())),
                    None,
                    Some(Value::Nil),
                )),
            )),
        );
        let err = validate_rsg(&missing_pubkey, message(), None).unwrap_err();
        assert!(matches!(
            err,
            RsgError::InvalidEnvelope("missing or invalid meta.pubkey")
        ));
    }

    #[test]
    fn rejects_unsupported_hash_type() {
        let identity = Identity::new();
        let envelope = pack_value(envelope_value(
            Some(Value::from("sha512")),
            Some(Value::Binary(rns_crypto::sha::sha256(message()).to_vec())),
            Some(meta_value(
                Some(Value::Binary(identity.hash.to_vec())),
                Some(Value::Binary(identity.get_public_key().to_vec())),
                Some(Value::Nil),
            )),
        ));
        let rsg = signed_rsg(&identity, envelope);

        let err = validate_rsg(&rsg, message(), None).unwrap_err();
        assert!(matches!(err, RsgError::UnsupportedHashType(t) if t == "sha512"));
    }

    #[test]
    fn rejects_signer_hash_pubkey_mismatch() {
        let identity = Identity::new();
        let other = Identity::new();
        let envelope = pack_value(envelope_value(
            Some(Value::from(HASH_TYPE_SHA256)),
            Some(Value::Binary(rns_crypto::sha::sha256(message()).to_vec())),
            Some(meta_value(
                Some(Value::Binary(identity.hash.to_vec())),
                Some(Value::Binary(other.get_public_key().to_vec())),
                Some(Value::Nil),
            )),
        ));
        let rsg = signed_rsg(&identity, envelope);

        let err = validate_rsg(&rsg, message(), None).unwrap_err();
        assert!(matches!(err, RsgError::SignerMetadataMismatch));
    }

    #[test]
    fn rejects_invalid_signature_over_valid_envelope() {
        let identity = Identity::new();
        let other = Identity::new();
        let envelope = pack_value(envelope_value(
            Some(Value::from(HASH_TYPE_SHA256)),
            Some(Value::Binary(rns_crypto::sha::sha256(message()).to_vec())),
            Some(meta_value(
                Some(Value::Binary(identity.hash.to_vec())),
                Some(Value::Binary(identity.get_public_key().to_vec())),
                Some(Value::Nil),
            )),
        ));
        let rsg = signed_rsg(&other, envelope);

        let err = validate_rsg(&rsg, message(), None).unwrap_err();
        assert!(matches!(err, RsgError::SignatureInvalid));
    }
}
