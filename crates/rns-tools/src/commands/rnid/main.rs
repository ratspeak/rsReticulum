//! rnid-rs - identity create/inspect/sign/verify/encrypt/decrypt.
//!
//! Port of `RNS/Utilities/rnid.py` from Reticulum 1.6.0: operation order,
//! exit codes and the text printed on stdout follow the Python tool.

use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE;
use clap::Parser;
#[cfg(feature = "hardware")]
use clap::Subcommand;
use rmpv::Value;
use rns_identity::destination::{DestType, Destination, Direction};
use rns_identity::identity::Identity;
use rns_runtime::reticulum::ReticulumHandle;
use rns_transport::messages::{
    OutboundRequest, TransportMessage, TransportQuery, TransportQueryResponse,
};

#[cfg(feature = "hardware")]
mod hw_commands;

use rns_tools::RS_RETICULUM_VERSION;
use rns_tools::format::pretty_size;
use rns_tools::rsg::pyfmt::{self, py_fromhex, py_os_error};
use rns_tools::rsg::{self, b256, meta};

const DEFAULT_ASPECTS: &str = "rns.id";
const NO_MESSAGE: &str = "\u{1}";
const NO_META: &str = "\u{2}";
const ENC_CHUNK: usize = 16 * 1024 * 1024;
/// A known destination: `(destination hash, public key)`.
type Known = ([u8; 16], [u8; 64]);

const DEC_CHUNK: usize = ENC_CHUNK + rns_crypto::TOKEN_OVERHEAD * 2;

const R_NO_IDENTITY: u8 = 2;
const R_NO_PRVKEY: u8 = 4;
const R_NO_KEYS: u8 = 5;
const R_NO_FILE: u8 = 6;
const R_INVALID_FILE: u8 = 7;
const R_INVALID_IDENTITY: u8 = 8;
const R_INVALID_ASPECTS: u8 = 9;
const R_INVALID_SIGNATURE: u8 = 10;
const R_FILE_EXISTS: u8 = 11;
const R_DECRYPT_FAILED: u8 = 12;
const R_INVALID_ARGS: u8 = 250;
const R_READ_ERROR: u8 = 252;
const R_WRITE_ERROR: u8 = 253;
const R_UNKNOWN_ERROR: u8 = 254;
const R_INTERRUPTED: u8 = 255;

#[derive(Parser)]
#[command(
    name = "rnid-rs",
    about = "Reticulum Identity & Encryption Utility",
    disable_version_flag = true,
    disable_help_flag = true,
    infer_long_args = true
)]
struct Args {
    /// show this help message and exit
    #[arg(short = 'h', long)]
    help: bool,

    /// path to alternative Reticulum config directory
    #[arg(long, value_name = "path")]
    config: Option<String>,

    /// hexadecimal Reticulum identity or destination hash, or path to Identity file
    #[arg(short = 'i', long, value_name = "rid")]
    identity: Option<String>,

    /// generate a new Identity and save to path
    #[arg(short = 'g', long, value_name = "path")]
    generate: Option<String>,

    /// import public Reticulum identity in hex, base32 or base64 format, or from file
    #[arg(short = 'm', long = "import-pub", value_name = "rid")]
    import_pub: Option<String>,

    /// import Reticulum identity in hex, base32 or base64 format, or from file
    #[arg(short = 'M', long = "import-prv", value_name = "rid")]
    import_prv: Option<String>,

    /// export public identity to hex, base32 or base64 format
    #[arg(short = 'x', long = "export-pub")]
    export_pub: bool,

    /// export private identity to hex, base32 or base64 format, or to file
    #[arg(short = 'X', long = "export-prv")]
    export_prv: bool,

    /// increase verbosity
    #[arg(short = 'v', long, action = clap::ArgAction::Count)]
    verbose: u8,

    /// decrease verbosity
    #[arg(short = 'q', long, action = clap::ArgAction::Count)]
    quiet: u8,

    /// announce a destination based on this Identity
    #[arg(short = 'a', long, value_name = "aspects", num_args = 0..=1, default_missing_value = DEFAULT_ASPECTS)]
    announce: Option<String>,

    /// show destination hashes for other aspects for this Identity
    #[arg(short = 'H', long = "hash", value_name = "aspects")]
    hash: Option<String>,

    /// decrypt file
    #[arg(short = 'd', long, num_args = 0.., value_name = "file")]
    decrypt: Option<Vec<String>>,

    /// encrypt file
    #[arg(short = 'e', long, num_args = 0.., value_name = "file")]
    encrypt: Option<Vec<String>>,

    /// validate signature
    #[arg(short = 'V', long = "validate", num_args = 0.., value_name = "path")]
    validate: Option<Vec<String>>,

    /// sign file
    #[arg(short = 's', long, num_args = 0.., value_name = "path")]
    sign: Option<Vec<String>>,

    /// create embedded signed message
    #[arg(short = 'S', long = "sign-message", value_name = "text", num_args = 0..=1, default_missing_value = NO_MESSAGE)]
    sign_message: Option<String>,

    /// embed metadata structure from file
    #[arg(short = 'E', long = "embed-meta", value_name = "path", num_args = 0..=1, default_missing_value = NO_META)]
    embed_meta: Option<String>,

    /// validate metadata for embedding with spec from file
    #[arg(long = "meta-spec", value_name = "path", num_args = 0..=1)]
    meta_spec: Option<Option<String>>,

    /// sign raw input data instead of hashing first
    #[arg(long)]
    raw: bool,

    /// output file path
    #[arg(short = 'w', long, value_name = "path")]
    write: Option<String>,

    /// input file path for operations with optional file input
    #[arg(short = 'r', long, value_name = "path")]
    read: Option<String>,

    /// write output even if it overwrites existing files
    #[arg(short = 'f', long)]
    force: bool,

    #[arg(short = 'I', long = "stdin", hide = true)]
    stdin: bool,

    #[arg(short = 'O', long = "stdout", hide = true)]
    stdout: bool,

    /// request unknown Identities from the network
    #[arg(short = 'R', long = "request")]
    request: bool,

    /// never used cached or network-sourced information
    #[arg(short = 'N', long = "no-cache")]
    no_cache: bool,

    /// identity request timeout before giving up
    #[arg(short = 't', value_name = "seconds", default_value_t = rns_transport::constants::PATH_REQUEST_TIMEOUT)]
    timeout: f64,

    /// print identity info and exit
    #[arg(short = 'p', long = "print-identity")]
    print_identity: bool,

    /// allow displaying private keys
    #[arg(short = 'P', long = "print-private")]
    print_private: bool,

    /// Use base32-encoded input and output
    #[arg(short = 'B', long)]
    base32: bool,

    /// Use base64-encoded input and output
    #[arg(short = 'b', long)]
    base64: bool,

    /// Use base256-encoded input and output
    #[arg(short = 'U', long)]
    base256: bool,

    /// Use hex-encoded input and output
    #[arg(short = 'F', long)]
    hex: bool,

    /// Display RSM metadata if available
    #[arg(long)]
    meta: bool,

    /// show program's version number and exit
    #[arg(long)]
    version: bool,
}

#[cfg(feature = "hardware")]
#[derive(Subcommand)]
enum HwCommands {
    /// List recognized PC/SC PIV readers and metadata availability; this is not a capability test.
    Detect,
    /// Generate Ed25519/X25519 keys in slots 9A/9D of the selected token.
    /// This writes the slots without an overwrite confirmation; existing keys can be replaced.
    /// Use --output to save public .hwid metadata; no hardware-key backup is created.
    Provision {
        /// Current token PIN, required by this command; no interactive PIN prompt.
        #[arg(long)]
        pin: Option<String>,
        /// Nickname stored in the optional .hwid output.
        #[arg(short, long)]
        nickname: Option<String>,
        /// Output directory; writes <identity-hash>/identity.hwid. Omit to save no file.
        #[arg(short, long)]
        output: Option<std::path::PathBuf>,
        /// PIV management key (hex). Defaults to the factory key.
        #[arg(long)]
        mgmt_key: Option<String>,
    },
    /// List saved identity.hwid files in the immediate subdirectories of --dir.
    List {
        /// Parent directory of identity folders; required by the command.
        #[arg(short, long)]
        dir: Option<std::path::PathBuf>,
    },
    /// Show saved .hwid metadata without contacting a token or verifying attestation.
    Info {
        /// Path to a saved public .hwid metadata file.
        hwid: std::path::PathBuf,
    },
    /// Compare the token's 9A/9D public keys with a .hwid file; no signing or attestation test.
    Verify {
        /// Path to a saved public .hwid metadata file.
        hwid: std::path::PathBuf,
    },
    /// Test signing, X25519 agreement and decryption against a .hwid identity; requires --pin.
    Test {
        /// Path to a saved public .hwid metadata file.
        hwid: std::path::PathBuf,
        /// Current token PIN, required by this command; no interactive PIN prompt.
        #[arg(long)]
        pin: Option<String>,
    },
    /// Fetch the on-card attestation (slots 9A/9D + device F9) and verify the
    /// certificate chain to a bundled Yubico root. No PIN required.
    /// Checks certificate signatures and validity, not revocation or binding to an expected identity.
    Attest,
}

#[cfg(feature = "hardware")]
#[derive(Parser)]
#[command(name = "rnid-rs hw")]
struct HwArgs {
    #[command(subcommand)]
    command: HwCommands,
}

/// Result of one operation: keep going, or `exit(code)` like the Python tool.
type Step = Result<(), u8>;

/// Identity argument after resolution: Python passes `identity or args.identity`.
enum Target<'a> {
    Identity(&'a Identity),
    Text(&'a str),
    None,
}

/// Lazily started runtime (`ensure_reticulum`).
struct Ctx {
    handle: Option<ReticulumHandle>,
    shutdown: rns_runtime::lifecycle::ShutdownSignal,
    started: Arc<AtomicBool>,
}

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
pub(crate) async fn main() -> ExitCode {
    #[cfg(feature = "hardware")]
    {
        let mut raw = std::env::args_os();
        let _program = raw.next();
        if raw.next().as_deref() == Some(std::ffi::OsStr::new("hw")) {
            let hw_args = HwArgs::parse_from(std::iter::once("rnid-rs hw".into()).chain(raw));
            hw_commands::run(hw_args.command);
            return ExitCode::SUCCESS;
        }
    }

    let args = Args::parse();
    let mut ctx = Ctx {
        handle: None,
        shutdown: rns_runtime::lifecycle::ShutdownSignal::new(),
        started: Arc::new(AtomicBool::new(false)),
    };
    let started = ctx.started.clone();
    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            // Before Reticulum starts Python exits R_INTERRUPTED; after, its
            // SIGINT handler exits 0.
            if started.load(Ordering::SeqCst) {
                std::process::exit(0);
            }
            println!();
            std::process::exit(i32::from(R_INTERRUPTED));
        }
    });
    let code = run(&args, &mut ctx).await;
    let _ = std::io::stdout().flush();
    if let Some(handle) = ctx.handle.take() {
        handle.shutdown_and_wait().await;
    }
    ExitCode::from(code)
}

fn nonempty(value: &Option<String>) -> Option<&str> {
    value.as_deref().filter(|v| !v.is_empty())
}

fn paths_active(paths: &Option<Vec<String>>) -> bool {
    paths.as_ref().is_some_and(|p| !p.is_empty())
}

/// argparse help of upstream rnid at its default 80-column width.
const HELP: &str = include_str!("help.txt");

async fn run(args: &Args, ctx: &mut Ctx) -> u8 {
    if args.help {
        print!("{HELP}");
        return 0;
    }
    if args.version {
        println!("rnid-rs {RS_RETICULUM_VERSION}");
        return 0;
    }

    let level = rns_tools::Utility::Rnid.loglevel(None, args.verbose, args.quiet, false);
    let config_dir = rns_runtime::platform::resolve_config_dir(args.config.as_deref());
    rns_tools::init_tracing(
        level,
        rns_tools::config_log_timestamps(&config_dir),
        true,
        std::io::stderr,
    );

    // validate_args (rnid.py)
    let ops = [
        paths_active(&args.encrypt),
        paths_active(&args.decrypt),
        paths_active(&args.validate),
        paths_active(&args.sign),
        nonempty(&args.sign_message).is_some(),
    ];
    if ops.iter().filter(|o| **o).count() > 1 {
        println!(
            "This utility currently only supports one of the encrypt, decrypt, sign or verify operations per invocation"
        );
        return 1;
    }
    let sources = [
        nonempty(&args.import_pub).is_some(),
        nonempty(&args.import_prv).is_some(),
        nonempty(&args.identity).is_some(),
        nonempty(&args.generate).is_some(),
    ];
    if sources.iter().filter(|o| **o).count() > 1 {
        println!("The -i, -g, -m and -M args are mutually exclusive");
        return 1;
    }
    if [args.base64, args.base32, args.base256, args.hex]
        .iter()
        .filter(|o| **o)
        .count()
        > 1
    {
        println!("The -b, -B, --hex and --base256 args are mutually exclusive");
        return 1;
    }

    let op_requires_identity = paths_active(&args.sign)
        || nonempty(&args.sign_message).is_some()
        || paths_active(&args.encrypt)
        || paths_active(&args.decrypt)
        || nonempty(&args.announce).is_some()
        || nonempty(&args.write).is_some()
        || args.print_identity
        || args.export_pub
        || args.export_prv;

    let identity = match get_operating_identity(args, ctx, !op_requires_identity).await {
        Ok(identity) => identity,
        Err(code) => return code,
    };
    if identity.is_none() && op_requires_identity {
        println!("Could not get working identity");
        return R_NO_IDENTITY;
    }
    match run_ops(args, ctx, identity.as_ref()).await {
        Ok(()) => 0,
        Err(code) => code,
    }
}

async fn run_ops(args: &Args, ctx: &mut Ctx, identity: Option<&Identity>) -> Step {
    let target = || match (identity, nonempty(&args.identity)) {
        (Some(identity), _) => Target::Identity(identity),
        (None, Some(text)) => Target::Text(text),
        (None, None) => Target::None,
    };
    let mut op = false;
    if args.print_identity {
        print_identity_information(args, identity.expect("required"));
        op = true;
    }
    if args.export_pub {
        export_pub_identity(args, identity.expect("required"))?;
        op = true;
    }
    if args.export_prv {
        export_prv_identity(args, identity.expect("required"))?;
        op = true;
    }
    if let Some(aspects) = nonempty(&args.hash) {
        print_hash_information(aspects, target())?;
        op = true;
    }
    if let Some(aspects) = nonempty(&args.announce) {
        announce(args, ctx, aspects, identity.expect("required")).await?;
        op = true;
    }
    if paths_active(&args.validate) {
        let target = target();
        for path in args.validate.as_ref().expect("active") {
            validate(args, path, &target)?;
        }
        return Err(0);
    }
    if paths_active(&args.sign) {
        for path in args.sign.as_ref().expect("active") {
            sign(args, path, identity.expect("required"))?;
        }
        return Err(0);
    }
    if nonempty(&args.sign_message).is_some() {
        sign_message(args, identity.expect("required"))?;
        return Err(0);
    }
    if paths_active(&args.encrypt) {
        for path in args.encrypt.as_ref().expect("active") {
            encrypt(args, path, identity.expect("required"))?;
        }
        return Err(0);
    }
    if paths_active(&args.decrypt) {
        for path in args.decrypt.as_ref().expect("active") {
            decrypt(args, path, identity.expect("required"))?;
        }
        return Err(0);
    }
    if let Some(write) = nonempty(&args.write) {
        write_identity(args, write, identity.expect("required"))?;
        op = true;
    }
    if nonempty(&args.generate).is_some() {
        op = true;
    }
    if !op {
        print!("{HELP}");
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Python helpers
// ---------------------------------------------------------------------------

/// `os.path.expanduser`.
fn expanduser(path: &str) -> String {
    let Some(rest) = path.strip_prefix('~') else {
        return path.to_string();
    };
    let (user, tail) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, ""),
    };
    let home = if user.is_empty() {
        std::env::var("HOME").ok()
    } else {
        std::fs::read_to_string("/etc/passwd")
            .ok()
            .and_then(|passwd| {
                passwd.lines().find_map(|line| {
                    let fields: Vec<&str> = line.split(':').collect();
                    (fields.len() >= 6 && fields[0] == user).then(|| fields[5].to_string())
                })
            })
    };
    match home {
        Some(home) => {
            let home = if home.len() > 1 {
                home.trim_end_matches('/')
            } else {
                &home
            };
            format!("{home}{tail}")
        }
        None => path.to_string(),
    }
}

fn is_file(path: &str) -> bool {
    Path::new(path).is_file()
}

/// `base64.b32decode` (strict alphabet and padding).
fn py_b32decode(text: &str) -> Option<Vec<u8>> {
    if !text.is_ascii() || !text.len().is_multiple_of(8) {
        return None;
    }
    let stripped = text.trim_end_matches('=');
    let padchars = text.len() - stripped.len();
    let mut decoded = Vec::new();
    let mut acc: u64 = 0;
    for quanta in stripped.as_bytes().chunks(8) {
        acc = 0;
        for &c in quanta {
            let v = match c {
                b'A'..=b'Z' => c - b'A',
                b'2'..=b'7' => c - b'2' + 26,
                _ => return None,
            };
            acc = (acc << 5) + u64::from(v);
        }
        decoded.extend_from_slice(&acc.to_be_bytes()[3..]);
    }
    if ![0, 1, 3, 4, 6].contains(&padchars) {
        return None;
    }
    if padchars > 0 && !decoded.is_empty() {
        acc <<= 5 * padchars;
        let last = acc.to_be_bytes();
        let leftover = (43 - 5 * padchars) / 8;
        let n = decoded.len();
        decoded.truncate(n - 5);
        decoded.extend_from_slice(&last[3..3 + leftover]);
    }
    Some(decoded)
}

/// `base64.urlsafe_b64decode` (`binascii.a2b_base64`, non-strict).
fn py_urlsafe_b64decode(text: &str) -> Option<Vec<u8>> {
    if !text.is_ascii() {
        return None;
    }
    let mut out = Vec::new();
    let mut quad = 0;
    let mut left = 0u8;
    let mut trailing_pad = 0;
    for c in text.bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'-' | b'+' => 62,
            b'_' | b'/' => 63,
            b'=' => {
                trailing_pad += 1;
                continue;
            }
            _ => continue,
        };
        trailing_pad = 0;
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
        1 => None,
        2 if trailing_pad < 2 => None,
        3 if trailing_pad < 1 => None,
        _ => Some(out),
    }
}

fn pretty_hash(hash: &[u8]) -> String {
    format!("<{}>", hex::encode(hash))
}

fn identity_str(identity: &Identity) -> String {
    pretty_hash(&identity.hash)
}

/// `RNS.log` line printed to stdout before Reticulum is configured.
fn rns_log(level: &str, message: &str) {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    println!(
        "[{year:04}-{month:02}-{day:02} {:02}:{:02}:{:02}] {level} {message}",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    );
}

fn output_format(args: &Args) -> &'static str {
    if args.base32 {
        "base32"
    } else if args.base64 {
        "base64"
    } else if args.base256 {
        "base256"
    } else if args.hex {
        "hex"
    } else {
        "bin"
    }
}

fn encode_key_text(bytes: &[u8], args: &Args) -> String {
    if args.base64 {
        URL_SAFE.encode(bytes)
    } else if args.base32 {
        encode_base32(bytes)
    } else {
        hex::encode(bytes)
    }
}

// ---------------------------------------------------------------------------
// Runtime
// ---------------------------------------------------------------------------

async fn ensure_reticulum<'a>(
    args: &Args,
    ctx: &'a mut Ctx,
) -> Result<&'a ReticulumHandle, String> {
    if ctx.handle.is_none() {
        let foreground = Arc::new(AtomicBool::new(true));
        let handle = rns_runtime::reticulum::init(
            args.config.as_deref(),
            None,
            ctx.shutdown.clone(),
            foreground,
        )
        .await
        .map_err(|e| e.to_string())?;
        ctx.started.store(true, Ordering::SeqCst);
        ctx.handle = Some(handle);
    }
    Ok(ctx.handle.as_ref().expect("started"))
}

/// Known `(destination hash, public key)` pairs visible to this process: the
/// runtime's restored and live announce table, the announce packets a running
/// instance has cached in storage, and a legacy Python `known_destinations`.
async fn known_identities(args: &Args, handle: &ReticulumHandle) -> Result<Vec<Known>, String> {
    let mut known = legacy_known_destinations(args)?;
    if let Some(TransportQueryResponse::Announces(announces)) = handle
        .query_transport(TransportQuery::GetRecentAnnounces)
        .await
    {
        known.extend(
            announces
                .into_iter()
                .filter_map(|a| a.public_key.map(|k| (a.dest_hash, k))),
        );
    }
    let config_dir = rns_runtime::platform::resolve_config_dir(args.config.as_deref());
    let cache_dir = config_dir.join("storage").join("cache").join("announces");
    if let Ok(entries) = std::fs::read_dir(&cache_dir) {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let Some(hash) = name
                .to_str()
                .and_then(|n| hex::decode(n).ok())
                .and_then(|h| <[u8; 32]>::try_from(h).ok())
            else {
                continue;
            };
            let Ok(Some(cached)) =
                rns_transport::persistence::load_python_cached_announce(&cache_dir, &hash)
            else {
                continue;
            };
            let Ok(packet) = rns_wire::packet::Packet::from_raw_owned(cached.raw_packet) else {
                continue;
            };
            if packet.header.flags.packet_type != rns_wire::flags::PacketType::Announce {
                continue;
            }
            let dest = packet.header.destination_hash;
            let Ok(announce) = rns_identity::announce::AnnounceData::unpack(
                packet.data(),
                packet.header.flags.context_flag,
            ) else {
                continue;
            };
            if announce.validate(&dest).is_ok() {
                known.push((dest, announce.public_key));
            }
        }
    }
    Ok(known)
}

/// Legacy (pre-1.6) Python msgpack `storage/known_destinations`.
fn legacy_known_destinations(args: &Args) -> Result<Vec<Known>, String> {
    let config_dir = rns_runtime::platform::resolve_config_dir(args.config.as_deref());
    let Ok(data) = std::fs::read(config_dir.join("storage/known_destinations")) else {
        return Ok(Vec::new());
    };
    let Ok(Value::Map(entries)) = rmpv::decode::read_value(&mut std::io::Cursor::new(data)) else {
        return Ok(Vec::new());
    };
    let mut out = Vec::new();
    for (key, value) in entries {
        let Some(dest) = key.as_slice().and_then(|k| <[u8; 16]>::try_from(k).ok()) else {
            continue;
        };
        let Some(items) = value.as_array().filter(|items| items.len() >= 3) else {
            continue;
        };
        let Some(public_key) = items[2].as_slice() else {
            continue;
        };
        match <[u8; 64]>::try_from(public_key) {
            Ok(key) if Identity::from_public_key(&key).is_ok() => out.push((dest, key)),
            _ => {
                return Err(format!(
                    "Can't remember {}, the public key size of {} is not valid.",
                    pretty_hash(&dest),
                    public_key.len()
                ));
            }
        }
    }
    Ok(out)
}

/// `Identity.recall(h) or Identity.recall(h, from_identity_hash=True)`.
async fn recall(
    args: &Args,
    handle: &ReticulumHandle,
    hash: &[u8; 16],
) -> Result<Option<Identity>, String> {
    let known = known_identities(args, handle).await?;
    let found = known.iter().find(|(dest, _)| dest == hash).or_else(|| {
        known
            .iter()
            .find(|(_, key)| rns_crypto::sha::truncated_hash(key) == *hash)
    });
    let Some((dest, key)) = found else {
        return Ok(None);
    };
    // Identity.recall marks the matched destination used (Identity.py).
    let _ = handle
        .query_control(TransportQuery::UseDestination { dest: *dest })
        .await;
    Ok(Identity::from_public_key(key).ok())
}

/// `spin()`: animated wait until `done` or the timeout.
async fn spin(
    args: &Args,
    handle: &ReticulumHandle,
    hash: &[u8; 16],
    msg: &str,
    timeout: f64,
) -> Option<Identity> {
    const SYMS: [char; 7] = ['⢄', '⢂', '⢁', '⡁', '⡈', '⡐', '⡠'];
    let deadline = Instant::now() + Duration::from_secs_f64(timeout.max(0.0));
    let mut out = std::io::stdout();
    let _ = write!(out, "{msg}   ");
    let _ = out.flush();
    let mut i = 0;
    let mut found = None;
    while Instant::now() < deadline {
        if let Ok(Some(identity)) = recall(args, handle, hash).await {
            found = Some(identity);
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
        let _ = write!(out, "\x08\x08{} ", SYMS[i]);
        let _ = out.flush();
        i = (i + 1) % SYMS.len();
    }
    let _ = write!(out, "\r{}  \r", " ".repeat(msg.chars().count()));
    let _ = out.flush();
    match found {
        Some(identity) => Some(identity),
        None => recall(args, handle, hash).await.ok().flatten(),
    }
}

// ---------------------------------------------------------------------------
// Identity loading and resolution (rnid.py)
// ---------------------------------------------------------------------------

/// `RNS.Identity.from_file`: the file always holds a 64-byte private key.
/// Rust's msgpack identity envelope is also accepted.
fn identity_from_file(path: &str) -> Option<Identity> {
    let data = match std::fs::read(path) {
        Ok(data) => data,
        Err(e) => {
            rns_log(
                "[Error]   ",
                &format!("Error while loading identity from {path}"),
            );
            rns_log(
                "[Error]   ",
                &format!("The contained exception was: {}", py_os_error(&e, path)),
            );
            return None;
        }
    };
    if data.len() == 64 {
        return Identity::from_private_key(&data).ok();
    }
    if let Ok(identity) = Identity::from_file(Path::new(path)) {
        return Some(identity);
    }
    let reason = if data.len() < 32 {
        "An X25519 private key is 32 bytes long"
    } else {
        "An Ed25519 private key is 32 bytes long"
    };
    rns_log(
        "[Error]   ",
        &format!("Failed to load identity key, the contained exception was: {reason}"),
    );
    None
}

async fn get_operating_identity(
    args: &Args,
    ctx: &mut Ctx,
    allow_none: bool,
) -> Result<Option<Identity>, u8> {
    if let Some(path) = nonempty(&args.generate) {
        let identity = Identity::new();
        if !args.force && is_file(path) {
            println!("Identity file {path} already exists. Not overwriting.");
            return Err(R_FILE_EXISTS);
        }
        // Identity.to_file logs and swallows write errors.
        if let Err(e) = identity.to_file(Path::new(path)) {
            rns_log(
                "[Error]   ",
                &format!("Error while saving identity to {path}"),
            );
            rns_log("[Notice]  ", &format!("The contained exception was: {e}"));
        }
        println!("New identity {} written to {path}", identity_str(&identity));
        return Ok(Some(identity));
    }

    if let Some(arg) = nonempty(&args.identity) {
        let load_path = expanduser(arg);
        if is_file(&load_path) {
            let identity = identity_from_file(&load_path);
            match identity {
                Some(identity) => {
                    println!(
                        "Loaded Identity {} from {load_path}",
                        identity_str(&identity)
                    );
                    if !identity.has_private_key() {
                        println!(
                            "Could not load Identity from specified file: Missing key data in loaded identity"
                        );
                        return Err(R_INVALID_IDENTITY);
                    }
                    return Ok(Some(identity));
                }
                None => {
                    println!("Loaded Identity None from {load_path}");
                    println!(
                        "Could not load Identity from specified file: 'NoneType' object has no attribute 'get_private_key'"
                    );
                    return Err(R_INVALID_IDENTITY);
                }
            }
        }
        if args.no_cache {
            if allow_none {
                return Ok(None);
            }
            println!("Could not resolve identity");
            return Err(R_NO_IDENTITY);
        }
        if arg.chars().count() == 32 {
            return recall_from_hash(args, ctx, arg, allow_none).await;
        }
        return Ok(None);
    }

    if let Some(import) = nonempty(&args.import_pub).or(nonempty(&args.import_prv)) {
        let public = nonempty(&args.import_pub).is_some();
        let kind = if public { "public" } else { "private" };
        let import_path = expanduser(import);
        let mut identity_bytes: Option<Vec<u8>> = None;
        if is_file(&import_path)
            && let Ok(data) = std::fs::read(&import_path)
            && data.len() == 64
        {
            println!("Reticulum Identity imported from {import_path}");
            identity_bytes = Some(data);
        }
        if identity_bytes.is_none()
            && import.chars().count() == 128
            && let Ok(data) = py_fromhex(import)
        {
            println!("Reticulum Identity imported from hex input");
            identity_bytes = Some(data);
        }
        if identity_bytes.is_none()
            && let Some(data) = py_b32decode(import).filter(|d| d.len() == 64)
        {
            println!("Reticulum Identity imported from base32 input");
            identity_bytes = Some(data);
        }
        if identity_bytes.is_none()
            && let Some(data) = py_urlsafe_b64decode(import).filter(|d| d.len() == 64)
        {
            println!("Reticulum Identity imported from base64 input");
            identity_bytes = Some(data);
        }
        let Some(bytes) = identity_bytes else {
            println!("Could not decode specified data to a valid {kind} Reticulum Identity");
            return Err(R_INVALID_IDENTITY);
        };
        let identity = if public {
            Identity::from_public_key(&bytes)
        } else {
            Identity::from_private_key(&bytes)
        };
        return match identity {
            Ok(identity) => Ok(Some(identity)),
            Err(e) => {
                println!("Could not create Reticulum identity from specified data: {e}");
                Err(R_INVALID_IDENTITY)
            }
        };
    }
    Ok(None)
}

async fn recall_from_hash(
    args: &Args,
    ctx: &mut Ctx,
    arg: &str,
    allow_none: bool,
) -> Result<Option<Identity>, u8> {
    let invalid = |e: String| {
        println!("Invalid hexadecimal hash provided: {e}");
        R_INVALID_IDENTITY
    };
    let handle = ensure_reticulum(args, ctx).await.map_err(invalid)?.clone();
    let requested = py_fromhex(arg).map_err(invalid)?;
    let Ok(requested) = <[u8; 16]>::try_from(requested.as_slice()) else {
        return Err(invalid("Invalid identity hash length".to_string()));
    };
    let mut identity = recall(args, &handle, &requested).await.map_err(invalid)?;
    match &identity {
        None if allow_none && !args.request => return Ok(None),
        None if !args.request => {
            println!("Could not recall Identity for {}.", pretty_hash(&requested));
            println!("You can query the network for unknown Identities with the -R option.");
            return Err(R_NO_IDENTITY);
        }
        None => {
            let id_destination =
                Destination::hash_from_name_and_identity(DEFAULT_ASPECTS, Some(&requested));
            for destination_hash in [requested, id_destination] {
                let _ = handle
                    .transport_tx
                    .send(TransportMessage::RequestPath { destination_hash })
                    .await;
            }
            let msg = format!(
                "Requesting unknown Identity for {}",
                pretty_hash(&requested)
            );
            identity = spin(args, &handle, &requested, &msg, args.timeout).await;
            match &identity {
                None => {
                    println!("Identity request timed out");
                    if !allow_none {
                        return Err(R_NO_IDENTITY);
                    }
                    return Ok(None);
                }
                Some(found) => println!(
                    "Received Identity {} for destination {} from the network",
                    identity_str(found),
                    pretty_hash(&requested)
                ),
            }
        }
        Some(found) => {
            let ident = identity_str(found);
            let hash = pretty_hash(&requested);
            if ident == hash {
                println!("Recalled Identity {ident}");
            } else {
                println!("Recalled Identity {ident} for destination {hash}");
            }
        }
    }
    if let Some(found) = &identity {
        let _ = handle
            .query_control(TransportQuery::RetainIdentity {
                identity_hash: found.hash,
            })
            .await;
    }
    Ok(identity)
}

// ---------------------------------------------------------------------------
// Operations
// ---------------------------------------------------------------------------

fn print_identity_information(args: &Args, identity: &Identity) {
    println!("Identity Hash : {}", pretty_hash(&identity.hash));
    println!(
        "Public Key    : {}",
        encode_key_text(&identity.get_public_key(), args)
    );
    if let Some(private_key) = identity.get_private_key() {
        if args.print_private {
            println!("Private Key   : {}", encode_key_text(&*private_key, args));
        } else {
            println!("Private Key   : Hidden");
        }
    }
}

fn export_pub_identity(args: &Args, identity: &Identity) -> Step {
    println!(
        "Public Identity Keys  : {}",
        encode_key_text(&identity.get_public_key(), args)
    );
    Ok(())
}

fn export_prv_identity(args: &Args, identity: &Identity) -> Step {
    let Some(key) = identity.get_private_key() else {
        println!("Identity doesn't hold a private key, cannot export");
        return Err(R_NO_PRVKEY);
    };
    println!("Private Identity Keys : {}", encode_key_text(&*key, args));
    Ok(())
}

fn print_hash_information(aspects: &str, target: Target<'_>) -> Step {
    let (identity_hash, identity) = match target {
        Target::Identity(identity) => (identity.hash, Some(identity)),
        Target::Text(text) => {
            if text.chars().count() != 32 {
                println!("Invalid identity hash length");
                return Err(R_INVALID_IDENTITY);
            }
            match py_fromhex(text).map(<[u8; 16]>::try_from) {
                Ok(Ok(hash)) => (hash, None),
                Ok(Err(_)) => {
                    println!(
                        "An error ocurred while attempting to get hash information: Invalid material supplied for destination hash calculation"
                    );
                    return Err(R_UNKNOWN_ERROR);
                }
                Err(e) => {
                    println!("Invalid identity: {e}");
                    return Err(R_INVALID_IDENTITY);
                }
            }
        }
        Target::None => {
            println!("Invalid identity");
            return Err(R_INVALID_IDENTITY);
        }
    };
    let destination_hash = Destination::hash_from_name_and_identity(aspects, Some(&identity_hash));
    println!(
        "The {aspects} destination for this Identity is {}",
        pretty_hash(&destination_hash)
    );
    if identity.is_some() {
        println!(
            "The full destination specifier is <{aspects}.{}:{}>",
            hex::encode(identity_hash),
            hex::encode(destination_hash)
        );
    }
    Ok(())
}

async fn announce(args: &Args, ctx: &mut Ctx, aspects: &str, identity: &Identity) -> Step {
    let fail = |e: String| {
        println!("An error ocurred while attempting to send the announce: {e}");
        R_UNKNOWN_ERROR
    };
    let handle = ensure_reticulum(args, ctx).await.map_err(fail)?.clone();
    if aspects.split('.').count() <= 1 {
        println!("Invalid destination aspects specified");
        return Err(R_INVALID_ASPECTS);
    }
    if !identity.has_private_key() {
        println!("Cannot announce this destination, since the private key is not held");
        return Err(R_NO_PRVKEY);
    }
    let mut destination =
        Destination::new(Some(identity), Direction::In, DestType::Single, aspects)
            .map_err(|e| fail(e.to_string()))?;
    println!(
        "Announcing {aspects} destination {} for identity {}",
        pretty_hash(&destination.hash),
        identity_str(identity)
    );
    // Rust destinations are side-effect free: register this one so transport
    // treats its announce as locally originated.
    let dest_hash = destination.hash;
    handle
        .transport_tx
        .send(TransportMessage::RegisterDestination {
            hash: dest_hash,
            app_name: aspects.to_string(),
            delivery_tx: None,
        })
        .await
        .map_err(|e| fail(e.to_string()))?;
    rns_runtime::destination_stamper::load_stored_stamp(&mut destination, identity);
    let raw = rns_runtime::destination_stamper::announce_packet(
        &mut destination,
        identity,
        None,
        None,
        false,
        None,
    )
    .await
    .map_err(|e| fail(e.to_string()))?;
    // A dropped stamp job sends nothing, as Destination.announce returns None.
    let Some(raw) = raw else {
        tokio::time::sleep(Duration::from_millis(250)).await;
        return Ok(());
    };
    handle
        .transport_tx
        .send(TransportMessage::Outbound(OutboundRequest {
            raw: raw.into(),
            destination_hash: dest_hash,
        }))
        .await
        .map_err(|e| fail(e.to_string()))?;
    tokio::time::sleep(Duration::from_millis(250)).await;
    Ok(())
}

/// `validate()` for one path (rnid.py). Unlike upstream, the legacy
/// branch checks every listed file before succeeding.
fn validate(args: &Args, path: &str, target: &Target<'_>) -> Step {
    let validate_path = expanduser(path);
    let lower = validate_path.to_lowercase();
    if lower.ends_with(".rsm") {
        return validate_message(args, &validate_path, target);
    }
    let (signature_path, file_path) = if lower.ends_with(".rsg") {
        let chars: Vec<char> = validate_path.chars().collect();
        (
            validate_path.clone(),
            chars[..chars.len() - 4].iter().collect::<String>(),
        )
    } else {
        (format!("{validate_path}.rsg"), validate_path.clone())
    };
    if !is_file(&file_path) {
        println!("The validation target \"{file_path}\" does not exist");
        return Err(R_NO_FILE);
    }
    if !is_file(&signature_path) {
        println!("No signature file exists for \"{file_path}\"");
        return Err(R_NO_FILE);
    }
    let rsg_data = match std::fs::read(&signature_path) {
        Ok(data) => data,
        Err(e) => {
            println!(
                "Could not detect rsg format: {}",
                py_os_error(&e, &signature_path)
            );
            return Err(R_UNKNOWN_ERROR);
        }
    };

    if !rsg::is_legacy_format(&rsg_data) {
        let required = required_signer(target)?;
        let mut file = match std::fs::File::open(&file_path) {
            Ok(file) => file,
            Err(e) => {
                println!(
                    "Could not read {file_path}: {}",
                    py_os_error(&e, &file_path)
                );
                return Err(R_READ_ERROR);
            }
        };
        let required_ref = required.as_ref().map(|r| match r {
            Required::Identity(identity) => rsg::RequiredSigner::Identity(identity),
            Required::Hash(hash) => rsg::RequiredSigner::Hash(hash),
        });
        match rsg::validate_rsg(&rsg_data, rsg::Message::File(&mut file), required_ref) {
            Ok(Some(valid)) => {
                println!(
                    "Signature is valid, the file {file_path} was signed by {}",
                    pretty_hash(&valid.signer_hash)
                );
                Ok(())
            }
            Ok(None) => {
                let description = required
                    .as_ref()
                    .map(|r| format!("\nThis file was NOT signed by {}", r.describe()))
                    .unwrap_or_default();
                println!("Invalid signature {signature_path} for file {file_path}{description}");
                Err(R_INVALID_SIGNATURE)
            }
            Err(e) => {
                println!("Error while validating {signature_path}: {e}");
                Err(R_UNKNOWN_ERROR)
            }
        }
    } else {
        let Target::Identity(identity) = target else {
            println!("Cannot validate legacy rsg signatures without an explicit required identity");
            return Err(R_NO_IDENTITY);
        };
        let data = match std::fs::read(&file_path) {
            Ok(data) => data,
            Err(e) => {
                println!(
                    "Could not validate signature: {}",
                    py_os_error(&e, &file_path)
                );
                return Err(R_READ_ERROR);
            }
        };
        let mut signature = [0u8; 64];
        signature.copy_from_slice(&rsg_data);
        if identity.verify(&data, &signature) {
            println!(
                "Signature is valid, the file {file_path} was signed by {}",
                identity_str(identity)
            );
            Ok(())
        } else {
            println!(
                "Invalid signature {signature_path} for file {file_path}\nThis file was NOT signed by {}",
                identity_str(identity)
            );
            Err(R_INVALID_SIGNATURE)
        }
    }
}

enum Required<'a> {
    Identity(&'a Identity),
    Hash(Vec<u8>),
}

impl Required<'_> {
    fn describe(&self) -> String {
        match self {
            Required::Identity(identity) => identity_str(identity),
            Required::Hash(hash) => pretty_hash(hash),
        }
    }
}

/// The `identity` argument of `validate()`: a hash string is decoded first.
fn required_signer<'a>(target: &Target<'a>) -> Result<Option<Required<'a>>, u8> {
    match target {
        Target::Identity(identity) => Ok(Some(Required::Identity(identity))),
        Target::None => Ok(None),
        Target::Text(text) => {
            if text.chars().count() != 32 {
                println!("Invalid identity hash length");
                return Err(R_INVALID_IDENTITY);
            }
            match py_fromhex(text) {
                Ok(hash) => Ok(Some(Required::Hash(hash))),
                Err(e) => {
                    println!("Invalid identity hash: {e}");
                    Err(R_INVALID_IDENTITY)
                }
            }
        }
    }
}

fn validate_message(args: &Args, signature_path: &str, target: &Target<'_>) -> Step {
    if !is_file(signature_path) {
        println!("The signature file \"{signature_path}\" does not exist");
        return Err(R_NO_FILE);
    }
    let rsg_data = match std::fs::read(signature_path) {
        Ok(data) => data,
        Err(e) => {
            println!("Could not read rsg: {}", py_os_error(&e, signature_path));
            return Err(R_READ_ERROR);
        }
    };
    let required = required_signer(target)?;
    let fail = |e: String| {
        println!("Error while validating {signature_path}: {e}");
        R_UNKNOWN_ERROR
    };
    let contents = rsg::extract_signed_rsg_data(&rsg_data);
    if !rsg::py_contains(contents.as_ref(), "message").map_err(fail)? {
        println!("No embedded message in {signature_path}");
        return Err(R_INVALID_SIGNATURE);
    }
    let contents = contents.expect("contains message");
    let message = rsg::py_index(&contents, "message").map_err(fail)?.clone();
    let required_ref = required.as_ref().map(|r| match r {
        Required::Identity(identity) => rsg::RequiredSigner::Identity(identity),
        Required::Hash(hash) => rsg::RequiredSigner::Hash(hash),
    });
    let valid = match rsg::validate_rsg(&rsg_data, rsg::Message::Unpacked(&message), required_ref)
        .map_err(fail)?
    {
        Some(valid) => valid,
        None => {
            let description = required
                .as_ref()
                .map(|r| format!("\nThe message was NOT signed by {}", r.describe()))
                .unwrap_or_default();
            println!("Invalid signature in {signature_path}{description}");
            return Err(R_INVALID_SIGNATURE);
        }
    };
    if args.meta {
        println!("RSM Metadata\n============\n");
        let meta = rsg::py_index(&valid.signed_data, "meta").map_err(fail)?;
        let Value::Map(entries) = meta else {
            return Err(fail(
                rsg::py_index(meta, "signer").err().unwrap_or_default(),
            ));
        };
        let mut dump = String::new();
        for (key, entry) in entries {
            format_meta_entry(&mut dump, entry, &pyfmt::py_str(key), 1);
        }
        print!("{dump}");
        println!("\nValidation\n==========");
    }
    let (f, c) = if args.meta {
        ("", "")
    } else {
        (" following", ":")
    };
    println!(
        "\nSignature is valid, the{f} message was signed by {}{c}\n",
        pretty_hash(&valid.signer_hash)
    );
    if args.meta {
        println!("Message\n=======\n");
    }
    let message = rsg::py_index(&valid.signed_data, "message").map_err(fail)?;
    match message {
        Value::Binary(bytes) => match std::str::from_utf8(bytes) {
            Ok(text) => println!("{text}"),
            Err(_) => return Err(fail(pyfmt::py_utf8_error(bytes).unwrap_or_default())),
        },
        other => {
            return Err(fail(format!(
                "'{}' object has no attribute 'decode'",
                rsg::py_type_name(other)
            )));
        }
    }
    Ok(())
}

/// The `recurse()` metadata printer of `validate_message` (rnid.py).
fn format_meta_entry(out: &mut String, entry: &Value, key: &str, level: usize) {
    const MAX_WIDTH: usize = 64;
    let indent = "  ".repeat(level);
    if let Value::Map(entries) = entry {
        out.push_str(&format!("d{indent}{key}:\n"));
        for (sub_key, sub_entry) in entries {
            format_meta_entry(out, sub_entry, &pyfmt::py_str(sub_key), level + 1);
        }
        return;
    }
    let etype = match entry {
        Value::String(_) => 's',
        Value::Binary(_) => 'b',
        Value::Array(_) => 'l',
        Value::Integer(_) => 'i',
        Value::F32(_) | Value::F64(_) => 'f',
        Value::Nil => 'N',
        _ => 'u',
    };
    if key == "note" && entry.is_nil() {
        return;
    }
    let text = match entry {
        Value::Binary(bytes) => hex::encode(bytes),
        other => pyfmt::py_str(other),
    };
    let leadin = format!("{etype}{indent}{key}=");
    let leadln = leadin.chars().count();
    let chars: Vec<char> = text.chars().collect();
    let first: String = chars.iter().take(MAX_WIDTH).collect();
    out.push_str(&format!("{leadin}{first}\n"));
    for chunk in chars.chunks(MAX_WIDTH).skip(1) {
        out.push_str(&" ".repeat(leadln));
        out.extend(chunk);
        out.push('\n');
    }
}

fn sign(args: &Args, path: &str, identity: &Identity) -> Step {
    let sign_path = expanduser(path);
    let rsg_path = format!("{sign_path}.rsg");
    let output = output_format(args);
    if !identity.has_private_key() {
        println!("Cannot sign \"{sign_path}\", the identity does not hold a private key");
        return Err(R_NO_PRVKEY);
    }
    if !is_file(&sign_path) {
        println!("The file \"{sign_path}\" does not exist");
        return Err(R_NO_FILE);
    }
    if output == "bin" && is_file(&rsg_path) && !args.force {
        println!("The signature file \"{rsg_path}\" already exists, not overwriting");
        return Err(R_FILE_EXISTS);
    }
    let fail = |e: String| {
        println!("Could not sign {sign_path}: {e}");
        R_UNKNOWN_ERROR
    };
    let input = std::fs::File::open(&sign_path).map_err(|e| fail(py_os_error(&e, &sign_path)))?;
    if args.raw {
        let signature = rsg::create_raw_signature(identity, input).map_err(fail)?;
        std::fs::write(&rsg_path, signature).map_err(|e| fail(py_os_error(&e, &rsg_path)))?;
    } else {
        let rsg_data = rsg::create_rsg(identity, input, false, None).map_err(fail)?;
        if output == "bin" {
            std::fs::write(&rsg_path, &rsg_data).map_err(|e| fail(py_os_error(&e, &rsg_path)))?;
        } else {
            println!("\n{}\n", armor(&rsg_data, output));
        }
    }
    println!("Signed file {sign_path} with {}", identity_str(identity));
    Ok(())
}

fn armor(data: &[u8], output: &str) -> String {
    match output {
        "base32" => wrap_rsg(encode_base32(data).as_bytes()),
        "base64" => wrap_rsg(URL_SAFE.encode(data).as_bytes()),
        "base256" => wrap_rsg_str(&b256::b256rep(data)),
        _ => wrap_rsg(hex::encode(data).as_bytes()),
    }
}

/// Python text-mode read: universal newlines.
fn universal_newlines(text: &str) -> String {
    text.replace("\r\n", "\n").replace('\r', "\n")
}

fn sign_message(args: &Args, identity: &Identity) -> Step {
    let output = output_format(args);
    let write = nonempty(&args.write);
    if output == "bin" && write.is_none() {
        println!("No write path specified");
        return Err(R_INVALID_ARGS);
    }
    if !identity.has_private_key() {
        println!("Cannot sign, the identity does not hold a private key");
        return Err(R_NO_PRVKEY);
    }
    let arg = args.sign_message.as_deref().expect("active");
    let mut message: Vec<u8> = if arg == NO_MESSAGE {
        Vec::new()
    } else {
        arg.as_bytes().to_vec()
    };
    let mut from_editor = arg == NO_MESSAGE;
    if let Some(read) = nonempty(&args.read) {
        if arg != NO_MESSAGE {
            println!(
                "Both an input file and command-line provided message was specified, aborting"
            );
            return Err(R_INVALID_ARGS);
        }
        let sign_path = expanduser(read);
        if !is_file(&sign_path) {
            println!("The file {sign_path} does not exist");
            return Err(R_NO_FILE);
        }
        let data = std::fs::read(&sign_path).map_err(|e| {
            eprintln!("{}", py_os_error(&e, &sign_path));
            1u8
        })?;
        match std::str::from_utf8(&data) {
            Ok(text) => message = universal_newlines(text).into_bytes(),
            Err(_) => {
                // Uncaught in rnid.py: Python prints a traceback and exits 1.
                eprintln!(
                    "UnicodeDecodeError: {}",
                    pyfmt::py_utf8_error(&data).unwrap_or_default()
                );
                return Err(1);
            }
        }
        from_editor = false;
    }
    if from_editor {
        message = get_editor_content()?;
    }
    if message.is_empty() {
        println!("No message specified");
        return Err(R_INVALID_ARGS);
    }

    let mut meta_values = None;
    if let Some(embed) = nonempty(&args.embed_meta) {
        if embed == NO_META {
            // `os.path.expanduser(NO_META)` raises outside any handler.
            eprintln!("TypeError: expected str, bytes or os.PathLike object, not int");
            return Err(1);
        }
        let meta_path = expanduser(embed);
        let spec = match args
            .meta_spec
            .as_ref()
            .and_then(|s| s.as_deref())
            .filter(|s| !s.is_empty())
        {
            Some(spec) => spec.to_string(),
            None => format!("{meta_path}.spec"),
        };
        if !is_file(&meta_path) {
            println!("Metadata file {meta_path} does not exist");
            return Err(R_NO_FILE);
        }
        let spec_path = is_file(&spec).then_some(spec);
        let spec_info = spec_path
            .as_ref()
            .map(|p| format!(" using spec from {p}"))
            .unwrap_or_default();
        println!("Embedding metadata from {meta_path}{spec_info}");
        match meta::rsg_meta_from_file(Path::new(&meta_path), spec_path.as_deref().map(Path::new)) {
            Ok(values) => meta_values = Some(values),
            Err(e) => {
                println!("Could not load metadata from {meta_path}: {e}");
                return Err(R_UNKNOWN_ERROR);
            }
        }
    }

    let fail = |e: String| {
        println!("Could not sign message: {e}");
        R_UNKNOWN_ERROR
    };
    let packed = meta_values
        .as_deref()
        .map(meta::meta_entries)
        .transpose()
        .map_err(fail)?;
    let rsg_data =
        rsg::create_rsg(identity, &message[..], true, packed.as_deref()).map_err(fail)?;
    if output == "bin" {
        let mut rsg_path = expanduser(write.expect("checked"));
        if !rsg_path.ends_with(".rsm") {
            rsg_path.push_str(".rsm");
        }
        if is_file(&rsg_path) && !args.force {
            println!("The signature file \"{rsg_path}\" already exists, not overwriting");
            return Err(R_FILE_EXISTS);
        }
        std::fs::write(&rsg_path, &rsg_data).map_err(|e| fail(py_os_error(&e, &rsg_path)))?;
        println!(
            "Message signed with {} saved to {rsg_path}",
            identity_str(identity)
        );
        return Err(0);
    }
    println!("\n{}\n", armor(&rsg_data, output));
    println!("Message signed with {}", identity_str(identity));
    Err(0)
}

fn encrypt(args: &Args, path: &str, identity: &Identity) -> Step {
    let encrypt_path = expanduser(path);
    let rfe_path = match nonempty(&args.write) {
        Some(write) => write.to_string(),
        None => format!("{encrypt_path}.rfe"),
    };
    if !is_file(&encrypt_path) {
        println!("The file \"{encrypt_path}\" does not exist");
        return Err(R_NO_FILE);
    }
    if is_file(&rfe_path) && !args.force {
        println!("The encryption output file \"{rfe_path}\" already exists, not overwriting");
        return Err(R_FILE_EXISTS);
    }
    let mut input = std::fs::File::open(&encrypt_path).map_err(|e| {
        println!(
            "\nError reading {encrypt_path} for encryption: {}",
            py_os_error(&e, &encrypt_path)
        );
        R_WRITE_ERROR
    })?;
    let write_error = |e: String| {
        println!("\nError writing encrypted output to {rfe_path}: {e}");
        R_WRITE_ERROR
    };
    let mut output =
        std::fs::File::create(&rfe_path).map_err(|e| write_error(py_os_error(&e, &rfe_path)))?;
    let mut buffer = vec![0u8; ENC_CHUNK];
    let mut wrote = 0usize;
    loop {
        let n = read_full(&mut input, &mut buffer).map_err(|e| write_error(e.to_string()))?;
        if n > 0 {
            let token = identity
                .encrypt(&buffer[..n], None)
                .map_err(|e| write_error(e.to_string()))?;
            output
                .write_all(&token)
                .map_err(|e| write_error(e.to_string()))?;
            wrote += token.len();
        }
        print!("\rWrote {} to {rfe_path}   ", pretty_size(wrote as u64));
        if n == 0 {
            break;
        }
    }
    println!(
        "\nFile {encrypt_path} encrypted for {} to {rfe_path}",
        identity_str(identity)
    );
    Ok(())
}

/// Python `fh.read(n)` on a regular file: up to `n` bytes, short only at EOF.
fn read_full(input: &mut std::fs::File, buffer: &mut [u8]) -> std::io::Result<usize> {
    let mut filled = 0;
    while filled < buffer.len() {
        match input.read(&mut buffer[filled..])? {
            0 => break,
            n => filled += n,
        }
    }
    Ok(filled)
}

fn decrypt(args: &Args, path: &str, identity: &Identity) -> Step {
    let rfe_path = expanduser(path);
    // Case-sensitive, and only the final suffix is stripped (rnid.py).
    let Some(stem) = rfe_path.strip_suffix(".rfe") else {
        println!("The file {rfe_path} does not appear to be a Reticulum encrypted file");
        return Err(R_INVALID_FILE);
    };
    let decrypt_path = match nonempty(&args.write) {
        Some(write) => expanduser(write),
        None => stem.to_string(),
    };
    if decrypt_path.is_empty() {
        println!("Invalid output filename");
        return Err(R_INVALID_FILE);
    }
    if !identity.has_private_key() {
        println!("Cannot decrypt \"{rfe_path}\", the identity does not hold a private key");
        return Err(R_NO_PRVKEY);
    }
    if !is_file(&rfe_path) {
        println!("The file \"{rfe_path}\" does not exist");
        return Err(R_NO_FILE);
    }
    if is_file(&decrypt_path) && !args.force {
        println!("The decryption output file \"{decrypt_path}\" already exists, not overwriting");
        return Err(R_FILE_EXISTS);
    }
    let mut input = std::fs::File::open(&rfe_path).map_err(|e| {
        println!(
            "\nError reading {rfe_path} for decryption: {}",
            py_os_error(&e, &rfe_path)
        );
        R_WRITE_ERROR
    })?;
    let write_error = |e: String| {
        println!("\nError writing decrypted output to {decrypt_path}: {e}");
        R_WRITE_ERROR
    };
    let mut output = std::fs::File::create(&decrypt_path)
        .map_err(|e| write_error(py_os_error(&e, &decrypt_path)))?;
    let chunk_size =
        decrypt_chunk_size(identity, &mut input).map_err(|e| write_error(e.to_string()))?;
    let mut buffer = vec![0u8; chunk_size];
    let mut wrote = 0usize;
    loop {
        let n = read_full(&mut input, &mut buffer).map_err(|e| write_error(e.to_string()))?;
        if n == 0 {
            break;
        }
        match identity.decrypt(&buffer[..n], None, false) {
            Ok(plaintext) if !plaintext.is_empty() => {
                output
                    .write_all(&plaintext)
                    .map_err(|e| write_error(e.to_string()))?;
                wrote += plaintext.len();
            }
            _ => {
                println!("The provided identity could not decrypt the file");
                return Err(R_DECRYPT_FAILED);
            }
        }
        print!("\rWrote {} to {decrypt_path}   ", pretty_size(wrote as u64));
    }
    println!("\nFile {rfe_path} decrypted to {decrypt_path}");
    Ok(())
}

/// Token size of the file's chunks: `DEC_CHUNK`, or `ENC_CHUNK` for files
/// written by rnid-rs before 1.2.4.
fn decrypt_chunk_size(identity: &Identity, input: &mut std::fs::File) -> std::io::Result<usize> {
    let len = input.metadata()?.len() as usize;
    if len <= ENC_CHUNK {
        return Ok(DEC_CHUNK);
    }
    let mut first = vec![0u8; DEC_CHUNK.min(len)];
    read_full(input, &mut first)?;
    let legacy = identity.decrypt(&first, None, false).is_err()
        && identity.decrypt(&first[..ENC_CHUNK], None, false).is_ok();
    input.seek(SeekFrom::Start(0))?;
    Ok(if legacy { ENC_CHUNK } else { DEC_CHUNK })
}

fn write_identity(args: &Args, write: &str, identity: &Identity) -> Step {
    let mut wp = expanduser(write);
    if identity.has_private_key() && args.export_prv {
        if is_file(&wp) && !args.force {
            println!("File {wp} already exists, not overwriting");
            return Err(R_FILE_EXISTS);
        }
        if let Err(e) = identity.to_file(Path::new(&wp)) {
            rns_log(
                "[Error]   ",
                &format!("Error while saving identity to {wp}"),
            );
            rns_log("[Notice]  ", &format!("The contained exception was: {e}"));
        }
        println!("Wrote private identity to {wp}");
        return Ok(());
    }
    if identity.get_public_key().len() != 64 {
        println!("Identity holds neither a public nor private key");
        return Err(R_NO_KEYS);
    }
    if !wp.to_lowercase().ends_with(".pub") {
        wp.push_str(".pub");
    }
    if is_file(&wp) && !args.force {
        println!("File {wp} already exists, not overwriting");
        return Err(R_FILE_EXISTS);
    }
    if let Err(e) = identity.pub_to_file(Path::new(&wp)) {
        rns_log(
            "[Error]   ",
            &format!("Error while saving identity to {wp}"),
        );
        rns_log("[Notice]  ", &format!("The contained exception was: {e}"));
    }
    println!("Wrote public identity to {wp}");
    Ok(())
}

fn get_editor_content() -> Result<Vec<u8>, u8> {
    let mut editor = std::env::var("EDITOR").unwrap_or_default();
    if editor.is_empty() {
        for fallback in ["nano", "vim", "vi"] {
            let found = std::process::Command::new("which")
                .arg(fallback)
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()
                .is_ok_and(|status| status.success());
            if found {
                editor = fallback.to_string();
                break;
            }
        }
    }
    if editor.is_empty() {
        println!("Could not launch editor");
        return Err(R_READ_ERROR);
    }
    let tmp_path = std::env::temp_dir().join(format!(
        "rnid-message-{}-{}.tmp",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    let run = || -> Result<Vec<u8>, String> {
        std::fs::write(&tmp_path, "").map_err(|e| e.to_string())?;
        let status = std::process::Command::new(&editor)
            .arg(&tmp_path)
            .status()
            .map_err(|e| e.to_string())?;
        if !status.success() {
            return Err(format!(
                "Editor exited with error code {}",
                status.code().unwrap_or(-1)
            ));
        }
        std::fs::read_to_string(&tmp_path)
            .map(|text| universal_newlines(&text).into_bytes())
            .map_err(|e| e.to_string())
    };
    let result = run();
    let _ = std::fs::remove_file(&tmp_path);
    result.map_err(|e| {
        println!("Could not get content from editor: {e}");
        R_READ_ERROR
    })
}

fn wrap_rsg(rsg: &[u8]) -> String {
    wrap_rsg_str(&String::from_utf8_lossy(rsg))
}

/// `wrap_rsg_str` (rnid.py): 64-character rows padded with `=`.
fn wrap_rsg_str(rsg: &str) -> String {
    const HEADER: &str = "#### Start of rsg data ";
    const FOOTER: &str = " End of rsg data ####";
    const ROW_WIDTH: usize = 64;
    let mut wrapped = format!("{HEADER}{}\n", "#".repeat(ROW_WIDTH - HEADER.len()));
    let chars: Vec<char> = rsg.chars().collect();
    for chunk in chars.chunks(ROW_WIDTH) {
        wrapped.extend(chunk);
        wrapped.push_str(&"=".repeat(ROW_WIDTH - chunk.len()));
        wrapped.push('\n');
    }
    wrapped.push_str(&"#".repeat(ROW_WIDTH - FOOTER.len()));
    wrapped.push_str(FOOTER);
    wrapped
}

fn encode_base32(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut out = String::new();
    let mut buffer = 0u16;
    let mut bits = 0u8;
    for byte in bytes {
        buffer = (buffer << 8) | (*byte as u16);
        bits += 8;
        while bits >= 5 {
            out.push(ALPHABET[((buffer >> (bits - 5)) & 0x1f) as usize] as char);
            bits -= 5;
        }
    }
    if bits > 0 {
        out.push(ALPHABET[((buffer << (5 - bits)) & 0x1f) as usize] as char);
    }
    while !out.len().is_multiple_of(8) {
        out.push('=');
    }
    out
}
