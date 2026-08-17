use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE;
use rns_identity::identity::Identity;

struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new(prefix: &str) -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock before unix epoch")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "rsreticulum-{prefix}-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir_all(&path).expect("create tempdir");
        Self { path }
    }

    fn join(&self, path: impl AsRef<Path>) -> PathBuf {
        self.path.join(path)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn rnid<I, S>(tmp: &TempDir, args: I) -> Output
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let config = tmp.join("config");
    fs::create_dir_all(&config).expect("create config dir");
    Command::new(env!("CARGO_BIN_EXE_rnid-rs"))
        .arg("--config")
        .arg(config)
        .args(args)
        .output()
        .expect("run rnid-rs")
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn assert_success(output: &Output, context: &str) {
    assert!(
        output.status.success(),
        "{context} failed with status {}\n--- stdout ---\n{}\n--- stderr ---\n{}",
        output.status,
        stdout(output),
        stderr(output)
    );
}

fn assert_failure(output: &Output, expected_code: Option<i32>, needle: &str, context: &str) {
    assert!(
        !output.status.success(),
        "{context} unexpectedly succeeded\n--- stdout ---\n{}\n--- stderr ---\n{}",
        stdout(output),
        stderr(output)
    );
    if let Some(expected_code) = expected_code {
        assert_eq!(
            output.status.code(),
            Some(expected_code),
            "{context} exited with unexpected status\n--- stdout ---\n{}\n--- stderr ---\n{}",
            stdout(output),
            stderr(output)
        );
    }
    let err = stderr(output);
    assert!(
        err.contains(needle),
        "{context} stderr did not contain {needle:?}\n--- stderr ---\n{err}"
    );
}

fn private_key_hex(identity: &Identity) -> String {
    let key = identity.get_private_key().expect("private key");
    hex::encode(&key[..])
}

fn private_key_bytes(identity: &Identity) -> Vec<u8> {
    identity.get_private_key().expect("private key").to_vec()
}

fn public_key_bytes(identity: &Identity) -> [u8; 64] {
    identity.get_public_key()
}

fn encode_base32(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut out = String::new();
    let mut buffer = 0u16;
    let mut bits = 0u8;
    for byte in bytes {
        buffer = (buffer << 8) | u16::from(*byte);
        bits += 8;
        while bits >= 5 {
            let index = ((buffer >> (bits - 5)) & 0x1f) as usize;
            out.push(ALPHABET[index] as char);
            bits -= 5;
        }
    }
    if bits > 0 {
        let index = ((buffer << (5 - bits)) & 0x1f) as usize;
        out.push(ALPHABET[index] as char);
    }
    while !out.len().is_multiple_of(8) {
        out.push('=');
    }
    out
}

#[test]
fn rnid_flag_conflicts_are_rejected() {
    let tmp = TempDir::new("rnid-flag-conflicts");

    let output = rnid(&tmp, ["-b", "-B"]);
    assert_failure(
        &output,
        Some(1),
        "-b, -B, --hex and --base256",
        "base64/base32 conflict",
    );

    let generated = tmp.join("identity");
    let output = rnid(
        &tmp,
        [
            "-i".as_ref(),
            "abc".as_ref(),
            "-g".as_ref(),
            generated.as_os_str(),
        ],
    );
    assert_failure(
        &output,
        Some(1),
        "-i, -g, -m and -M",
        "identity source conflict",
    );

    let output = rnid(&tmp, ["-e", "plain.bin", "-d", "cipher.rfe"]);
    assert_failure(&output, Some(1), "only supports one", "operation conflict");
}

#[test]
fn rnid_public_private_import_export_and_pub_write_behaviour() {
    let tmp = TempDir::new("rnid-import-export");
    let identity = Identity::new();
    let public = public_key_bytes(&identity);
    let private = private_key_bytes(&identity);
    let public_hex = hex::encode(public);
    let private_hex = private_key_hex(&identity);

    let public_out_base = tmp.join("imported-public");
    let public_out = tmp.join("imported-public.pub");
    let output = rnid(
        &tmp,
        [
            "-m".as_ref(),
            public_hex.as_ref(),
            "-w".as_ref(),
            public_out_base.as_os_str(),
            "-f".as_ref(),
        ],
    );
    assert_success(&output, "import public and write");
    assert_eq!(fs::read(&public_out).unwrap(), public);
    assert!(!public_out_base.exists());

    let default_private_write_base = tmp.join("private-default-write");
    let default_private_write_pub = tmp.join("private-default-write.pub");
    let output = rnid(
        &tmp,
        [
            "-M".as_ref(),
            private_hex.as_ref(),
            "-w".as_ref(),
            default_private_write_base.as_os_str(),
            "-f".as_ref(),
        ],
    );
    assert_success(&output, "import private and default write public");
    assert_eq!(fs::read(&default_private_write_pub).unwrap(), public);
    assert!(!default_private_write_base.exists());

    let private_out = tmp.join("private.rid");
    let output = rnid(
        &tmp,
        [
            "-M".as_ref(),
            private_hex.as_ref(),
            "-X".as_ref(),
            "-w".as_ref(),
            private_out.as_os_str(),
            "-f".as_ref(),
        ],
    );
    assert_success(&output, "import private and write private");
    assert_eq!(fs::read(&private_out).unwrap(), private);

    let export_public = rnid(&tmp, ["-i".as_ref(), public_out.as_os_str(), "-x".as_ref()]);
    assert_success(&export_public, "export public from .pub");
    assert!(stdout(&export_public).contains(&public_hex));

    let export_private = rnid(
        &tmp,
        ["-i".as_ref(), private_out.as_os_str(), "-X".as_ref()],
    );
    assert_success(&export_private, "export private from .rid");
    assert!(stdout(&export_private).contains(&private_hex));
}

#[test]
fn rnid_encoding_import_export_roundtrips() {
    let tmp = TempDir::new("rnid-encodings");
    let identity = Identity::new();
    let public = public_key_bytes(&identity);
    let private = private_key_bytes(&identity);
    let public_hex = hex::encode(public);
    let private_hex = hex::encode(&private);
    let public_b32 = encode_base32(&public);
    let public_b64 = URL_SAFE.encode(public);
    let private_b32 = encode_base32(&private);
    let private_b64 = URL_SAFE.encode(&private);

    let private_b64_arg = format!("--import-prv={private_b64}");
    let output = rnid(&tmp, [private_b64_arg.as_str(), "-X"]);
    assert_success(&output, "import private base64 and export hex");
    assert!(stdout(&output).contains(&private_hex));

    let output = rnid(&tmp, ["-M", &private_b32, "-X", "-b"]);
    assert_success(&output, "import private base32 and export base64");
    assert!(stdout(&output).contains(&private_b64));

    let output = rnid(&tmp, ["-M", &private_hex, "-X", "-B"]);
    assert_success(&output, "import private hex and export base32");
    assert!(stdout(&output).contains(&private_b32));

    let output = rnid(&tmp, ["-m", &public_b32.to_ascii_lowercase(), "-x"]);
    assert_success(&output, "import public lowercase base32 and export hex");
    assert!(stdout(&output).contains(&public_hex));

    let public_b64_arg = format!("--import-pub={public_b64}");
    let output = rnid(&tmp, [public_b64_arg.as_str(), "-x", "-B"]);
    assert_success(&output, "import public base64 and export base32");
    assert!(stdout(&output).contains(&public_b32));
}

#[test]
fn rnid_public_key_only_private_operations_fail() {
    let tmp = TempDir::new("rnid-public-only");
    let identity = Identity::new();
    let public_file = tmp.join("identity.pub");
    let message = tmp.join("message.bin");
    let signature = tmp.join("message.bin.rsg");
    let ciphertext = tmp.join("message.bin.rfe");
    let decrypted = tmp.join("decrypted.bin");
    fs::write(&public_file, public_key_bytes(&identity)).unwrap();
    fs::write(&message, b"public-key-only rnid test").unwrap();
    fs::write(&ciphertext, b"not a valid ciphertext").unwrap();

    let output = rnid(
        &tmp,
        ["-i".as_ref(), public_file.as_os_str(), "-X".as_ref()],
    );
    assert_failure(
        &output,
        Some(4),
        "doesn't hold a private key",
        "export private from public identity",
    );

    let output = rnid(
        &tmp,
        [
            "-i".as_ref(),
            public_file.as_os_str(),
            "-s".as_ref(),
            message.as_os_str(),
            "-w".as_ref(),
            signature.as_os_str(),
            "-f".as_ref(),
        ],
    );
    assert_failure(
        &output,
        Some(4),
        "does not hold a private key",
        "sign with public identity",
    );

    let output = rnid(
        &tmp,
        [
            "-i".as_ref(),
            public_file.as_os_str(),
            "-d".as_ref(),
            ciphertext.as_os_str(),
            "-w".as_ref(),
            decrypted.as_os_str(),
            "-f".as_ref(),
        ],
    );
    assert_failure(
        &output,
        Some(4),
        "does not hold a private key",
        "decrypt with public identity",
    );
}

#[test]
fn rnid_no_cache_validates_embedded_rsg_signer_by_hash() {
    let tmp = TempDir::new("rnid-no-cache-rsg");
    let identity = Identity::new();
    let private_file = tmp.join("identity.rid");
    let message = tmp.join("message.bin");
    let signature = tmp.join("message.bin.rsg");
    fs::write(&private_file, private_key_bytes(&identity)).unwrap();
    fs::write(&message, b"rnid no-cache embedded signer").unwrap();

    let output = rnid(
        &tmp,
        [
            "-i".as_ref(),
            private_file.as_os_str(),
            "-s".as_ref(),
            message.as_os_str(),
            "-w".as_ref(),
            signature.as_os_str(),
            "-f".as_ref(),
        ],
    );
    assert_success(&output, "sign rsg");

    let hash_hex = hex::encode(identity.hash);
    let output = rnid(
        &tmp,
        [
            "-i".as_ref(),
            hash_hex.as_ref(),
            "-N".as_ref(),
            "-V".as_ref(),
            signature.as_os_str(),
        ],
    );
    assert_success(&output, "validate no-cache embedded rsg signer by hash");
    assert!(stdout(&output).contains("Signature is valid"));
}
