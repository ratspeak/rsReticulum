//! `rngcs` signatures: git commit signing with Reticulum identities, a port
//! of `RNS/Utilities/rngit/commitsigs.py@1.6.0`. The signature is an rsg
//! envelope inside an SSHSIG container, so only rngcs (not `ssh-keygen`) can
//! verify it. The command line is in the `rngcs-rs` binary.

use rns_identity::identity::Identity;

pub const SSHSIG_MAGIC: &[u8] = b"SSHSIG";
pub const SSHSIG_VERSION: u32 = 1;
pub const NAMESPACE_GIT: &[u8] = b"git";
pub const RESERVED_EMPTY: &[u8] = b"";
pub const HASH_ALGORITHM: &[u8] = b"sha256";

/// `ssh_string`: a big-endian u32 length, then the bytes.
pub fn ssh_string(data: &[u8]) -> Vec<u8> {
    let mut out = (data.len() as u32).to_be_bytes().to_vec();
    out.extend_from_slice(data);
    out
}

fn read_ssh_string(data: &[u8], offset: usize) -> Result<(&[u8], usize), String> {
    if offset + 4 > data.len() {
        return Err("Not enough data for string length".to_string());
    }
    let length = u32::from_be_bytes(data[offset..offset + 4].try_into().expect("4 bytes")) as usize;
    if offset + 4 + length > data.len() {
        return Err("Not enough data for string content".to_string());
    }
    Ok((&data[offset + 4..offset + 4 + length], offset + 4 + length))
}

/// `create_ssh_signature`.
pub fn create_ssh_signature(
    public_key_wire: &[u8],
    namespace: &[u8],
    reserved: &[u8],
    hash_algorithm: &[u8],
    signature_data: &[u8],
) -> Vec<u8> {
    let mut blob = SSHSIG_MAGIC.to_vec();
    blob.extend_from_slice(&SSHSIG_VERSION.to_be_bytes());
    for field in [
        public_key_wire,
        namespace,
        reserved,
        hash_algorithm,
        signature_data,
    ] {
        blob.extend_from_slice(&ssh_string(field));
    }
    blob
}

/// The fields `parse_ssh_signature` returns.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshSignature {
    pub version: u32,
    pub public_key: Vec<u8>,
    pub namespace: Vec<u8>,
    pub reserved: Vec<u8>,
    pub hash_algorithm: Vec<u8>,
    pub signature_data: Vec<u8>,
}

/// `parse_ssh_signature`; trailing bytes are ignored as upstream does.
pub fn parse_ssh_signature(sig_data: &[u8]) -> Result<SshSignature, String> {
    if !sig_data.starts_with(SSHSIG_MAGIC) {
        return Err("Invalid SSH signature: missing SSHSIG magic".to_string());
    }
    let mut offset = SSHSIG_MAGIC.len();
    if offset + 4 > sig_data.len() {
        return Err("Invalid SSH signature: truncated".to_string());
    }
    let version = u32::from_be_bytes(sig_data[offset..offset + 4].try_into().expect("4 bytes"));
    if version != SSHSIG_VERSION {
        return Err(format!("Unsupported SSH signature version: {version}"));
    }
    offset += 4;
    let mut fields = Vec::with_capacity(5);
    for _ in 0..5 {
        let (field, next) = read_ssh_string(sig_data, offset)?;
        fields.push(field.to_vec());
        offset = next;
    }
    let mut fields = fields.into_iter();
    let mut next = || fields.next().expect("five fields");
    Ok(SshSignature {
        version,
        public_key: next(),
        namespace: next(),
        reserved: next(),
        hash_algorithm: next(),
        signature_data: next(),
    })
}

/// `armor_ssh_signature`: standard base64 in 70-character lines.
pub fn armor_ssh_signature(sig_blob: &[u8]) -> String {
    use base64::Engine;
    let b64 = base64::engine::general_purpose::STANDARD.encode(sig_blob);
    let lines: Vec<&str> = b64
        .as_bytes()
        .chunks(70)
        .map(|chunk| std::str::from_utf8(chunk).expect("base64 is ASCII"))
        .collect();
    format!(
        "-----BEGIN SSH SIGNATURE-----\n{}\n-----END SSH SIGNATURE-----\n",
        lines.join("\n")
    )
}

fn is_py_space(c: char) -> bool {
    c.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&c)
}

/// `unarmor_ssh_signature`: collects the stripped lines between the markers,
/// so the indentation git adds in a `gpgsig` header is tolerated.
pub fn unarmor_ssh_signature(armored: &str) -> Result<Vec<u8>, String> {
    let mut b64 = String::new();
    let mut in_sig = false;
    for line in armored.trim_matches(is_py_space).split('\n') {
        if line.contains("BEGIN SSH SIGNATURE") {
            in_sig = true;
            continue;
        }
        if line.contains("END SSH SIGNATURE") {
            break;
        }
        if in_sig {
            b64.push_str(line.trim_matches(is_py_space));
        }
    }
    if b64.is_empty() {
        return Err("No signature data found in armored input".to_string());
    }
    py_b64decode(&b64)
}

/// Python `base64.b64decode` without `validate`: characters outside the
/// alphabet are skipped and padding is checked as `binascii` does.
fn py_b64decode(text: &str) -> Result<Vec<u8>, String> {
    if !text.is_ascii() {
        return Err("string argument should contain only ASCII characters".to_string());
    }
    let mut out = Vec::new();
    let (mut quad, mut left, mut pads) = (0, 0u8, 0);
    for c in text.bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            b'=' => {
                pads += 1;
                continue;
            }
            _ => continue,
        };
        pads = 0;
        match quad {
            0 => {
                left = v;
                quad = 1;
            }
            1 => {
                out.push((left << 2) | (v >> 4));
                left = v & 0x0f;
                quad = 2;
            }
            2 => {
                out.push((left << 4) | (v >> 2));
                left = v & 0x03;
                quad = 3;
            }
            _ => {
                out.push((left << 6) | v);
                quad = 0;
            }
        }
    }
    match quad {
        1 => Err(format!(
            "Invalid base64-encoded string: number of data characters ({}) cannot be 1 more than a multiple of 4",
            out.len() / 3 * 4 + 1
        )),
        2 | 3 if quad + pads < 4 => Err("Incorrect padding".to_string()),
        _ => Ok(out),
    }
}

/// `get_pubkey_wire_format`: the OpenSSH `ssh-ed25519` public key blob.
pub fn get_pubkey_wire_format(identity: &Identity) -> Vec<u8> {
    let mut wire = ssh_string(b"ssh-ed25519");
    wire.extend_from_slice(&ssh_string(&identity.get_public_key()[32..]));
    wire
}

/// An email taken from a commit header. `DecodeError` is the int 1 upstream
/// returns after failing to decode it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HeaderEmail {
    Email(String),
    DecodeError,
}

impl std::fmt::Display for HeaderEmail {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HeaderEmail::Email(email) => f.write_str(email),
            HeaderEmail::DecodeError => f.write_str("1"),
        }
    }
}

/// Python `bytes.splitlines()`.
fn bytes_splitlines(data: &[u8]) -> Vec<&[u8]> {
    let mut lines = Vec::new();
    let (mut start, mut i) = (0, 0);
    while i < data.len() {
        match data[i] {
            b'\n' => {
                lines.push(&data[start..i]);
                start = i + 1;
            }
            b'\r' => {
                lines.push(&data[start..i]);
                if data.get(i + 1) == Some(&b'\n') {
                    i += 1;
                }
                start = i + 1;
            }
            _ => {}
        }
        i += 1;
    }
    if start < data.len() {
        lines.push(&data[start..]);
    }
    lines
}

/// The `<email>` of a header line, under upstream's bounds.
fn header_email(line: &[u8], target: &[u8]) -> Option<Result<String, ()>> {
    let spos = line.iter().position(|b| *b == b'<')?;
    let epos = line.iter().position(|b| *b == b'>')?;
    if spos > target.len() && epos > spos && epos + 1 < line.len() {
        Some(String::from_utf8(line[spos + 1..epos].to_vec()).map_err(|_| ()))
    } else {
        None
    }
}

fn extract_header(message: &[u8], target: &[u8], what: &str) -> HeaderEmail {
    for line in bytes_splitlines(message) {
        if line.is_empty() {
            break;
        }
        if line.starts_with(target) {
            match header_email(line, target) {
                Some(Ok(email)) => return HeaderEmail::Email(email),
                Some(Err(())) => {
                    println!("Error while determining {what} from signed commit");
                    return HeaderEmail::DecodeError;
                }
                None => {}
            }
        }
    }
    HeaderEmail::Email(String::new())
}

/// `extract_commit_author`.
pub fn extract_commit_author(message: &[u8]) -> HeaderEmail {
    extract_header(message, b"author ", "author")
}

/// `extract_commit_committer`.
pub fn extract_commit_committer(message: &[u8]) -> HeaderEmail {
    extract_header(message, b"committer ", "committer")
}

/// `extract_commit_tagger`: `(tagger, is_tag)`, or `None` where upstream
/// returns the int 1 after a decode failure.
pub fn extract_commit_tagger(message: &[u8]) -> Option<(String, bool)> {
    let mut is_tag = false;
    for line in bytes_splitlines(message) {
        if line.is_empty() {
            break;
        } else if line.starts_with(b"tag ") {
            is_tag = true;
        } else if line.starts_with(b"tagger ") && is_tag {
            match header_email(line, b"tagger ") {
                Some(Ok(email)) => return Some((email, is_tag)),
                Some(Err(())) => {
                    println!("Error while determining tagger from signed commit");
                    return None;
                }
                None => {}
            }
        }
    }
    Some((String::new(), is_tag))
}
