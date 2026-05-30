//! rnid-rs - identity create/inspect/sign/verify/encrypt/decrypt.
//!
//! Python reference: `RNS/Utilities/rnid.py` from Reticulum 1.2.5.

mod rsg;

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE;
#[cfg(feature = "hardware")]
use clap::Subcommand;
use clap::{CommandFactory, Parser};
use rns_identity::destination::{DestType, Destination, Direction};
use rns_identity::identity::Identity;
use rns_identity::known_destinations::KnownDestinations;
use rns_transport::messages::{
    OutboundRequest, TransportMessage, TransportQuery, TransportQueryResponse,
};

#[cfg(feature = "hardware")]
mod hw_commands;

const RETICULUM_COMPAT_VERSION: &str = "1.2.5";
const DEFAULT_ASPECTS: &str = "rns.id";
const PUB_EXT: &str = "pub";
const SIG_EXT: &str = "rsg";
const ENCRYPT_EXT: &str = "rfe";
const ENC_CHUNK: usize = 16 * 1024 * 1024;
const DEC_CHUNK: usize = ENC_CHUNK + rns_crypto::TOKEN_OVERHEAD * 2;
const BLOCK_SIZE: usize = 16;
const FULL_CHUNK_TOKEN_SIZE: usize =
    ENC_CHUNK + rns_identity::identity::IDENTITY_OVERHEAD + BLOCK_SIZE;

#[derive(Parser)]
#[command(
    name = "rnid-rs",
    about = "Reticulum Identity & Encryption Utility",
    disable_version_flag = true
)]
struct Args {
    /// Path to alternative Reticulum config directory.
    #[arg(long)]
    config: Option<String>,

    /// Hexadecimal identity/destination hash, or path to an Identity file.
    #[arg(short = 'i', long)]
    identity: Option<String>,

    /// Generate a new Identity and write it to this file.
    #[arg(short = 'g', long)]
    generate: Option<PathBuf>,

    /// Import public Identity data in hex, base32 or base64 format, or from file.
    #[arg(short = 'm', long = "import-pub", value_name = "identity_data")]
    import_pub: Option<String>,

    /// Import private Identity data in hex, base32 or base64 format, or from file.
    #[arg(
        short = 'M',
        long = "import-prv",
        alias = "import",
        visible_alias = "import-private",
        value_name = "identity_data"
    )]
    import_prv: Option<String>,

    /// Export public Identity data in hex, base32 or base64 format.
    #[arg(short = 'x', long = "export-pub")]
    export_pub: bool,

    /// Export private Identity data in hex, base32 or base64 format, or to file.
    #[arg(
        short = 'X',
        long = "export-prv",
        alias = "export",
        visible_alias = "export-private"
    )]
    export_prv: bool,

    /// Increase verbosity.
    #[arg(short = 'v', long, action = clap::ArgAction::Count)]
    verbose: u8,

    /// Decrease verbosity.
    #[arg(short = 'q', long, action = clap::ArgAction::Count)]
    quiet: u8,

    /// Announce a destination based on this Identity.
    #[arg(short = 'a', long, num_args = 0..=1, default_missing_value = DEFAULT_ASPECTS)]
    announce: Option<String>,

    /// Show destination hash for aspects based on this Identity.
    #[arg(short = 'H', long = "hash")]
    hash: Option<String>,

    /// Encrypt file.
    #[arg(short = 'e', long)]
    encrypt: Option<PathBuf>,

    /// Decrypt file.
    #[arg(short = 'd', long)]
    decrypt: Option<PathBuf>,

    /// Sign file.
    #[arg(short = 's', long)]
    sign: Option<PathBuf>,

    /// Validate signature.
    #[arg(short = 'V', long = "validate")]
    validate: Option<PathBuf>,

    /// Sign raw input data instead of hashing first.
    #[arg(long)]
    raw: bool,

    /// Legacy input file path override.
    #[arg(short = 'r', long, hide = true)]
    read: Option<PathBuf>,

    /// Output file path.
    #[arg(short = 'w', long)]
    write: Option<PathBuf>,

    /// Write output even if it overwrites existing files.
    #[arg(short = 'f', long)]
    force: bool,

    /// Request unknown Identities from the network.
    #[arg(short = 'R', long = "request")]
    request: bool,

    /// Never use cached or network-sourced information.
    #[arg(short = 'N', long = "no-cache")]
    no_cache: bool,

    /// Identity request timeout before giving up.
    #[arg(short = 't', value_name = "seconds", default_value_t = rns_transport::constants::PATH_REQUEST_TIMEOUT)]
    timeout: f64,

    /// Print identity info and exit.
    #[arg(short = 'p', long = "print-identity")]
    print_identity: bool,

    /// Allow displaying private keys.
    #[arg(short = 'P', long = "print-private")]
    print_private: bool,

    /// Use base64-encoded input and output.
    #[arg(short = 'b', long)]
    base64: bool,

    /// Use base32-encoded input and output.
    #[arg(short = 'B', long)]
    base32: bool,

    /// Use hex-encoded input and output.
    #[arg(long)]
    hex: bool,

    /// Print version and exit.
    #[arg(long)]
    version: bool,

    /// Parsed for Python CLI parity.
    #[arg(short = 'I', long = "stdin", hide = true)]
    stdin: bool,

    /// Parsed for Python CLI parity.
    #[arg(short = 'O', long = "stdout", hide = true)]
    stdout: bool,
}

#[cfg(feature = "hardware")]
#[derive(Subcommand)]
enum HwCommands {
    Detect,
    Provision {
        #[arg(long)]
        pin: Option<String>,
        #[arg(short, long)]
        nickname: Option<String>,
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// PIV management key (hex). Defaults to the factory key.
        #[arg(long)]
        mgmt_key: Option<String>,
    },
    List {
        #[arg(short, long)]
        dir: Option<PathBuf>,
    },
    Info {
        hwid: PathBuf,
    },
    Verify {
        hwid: PathBuf,
    },
    Test {
        hwid: PathBuf,
        #[arg(long)]
        pin: Option<String>,
    },
    /// Fetch the on-card attestation (slots 9A/9D + device F9) and verify the
    /// certificate chain to a bundled Yubico root. No PIN required.
    Attest,
}

#[cfg(feature = "hardware")]
#[derive(Parser)]
#[command(name = "rnid-rs hw")]
struct HwArgs {
    #[command(subcommand)]
    command: HwCommands,
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
    run(args).await
}

async fn run(mut args: Args) -> ExitCode {
    if args.version {
        println!("rnid-rs {RETICULUM_COMPAT_VERSION}");
        return ExitCode::SUCCESS;
    }

    let target_loglevel = 4 + args.verbose as i32 - args.quiet as i32;
    let level = match target_loglevel {
        i32::MIN..=1 => tracing::Level::ERROR,
        2..=3 => tracing::Level::WARN,
        4 => tracing::Level::INFO,
        5 => tracing::Level::DEBUG,
        _ => tracing::Level::TRACE,
    };
    let _ = tracing_subscriber::fmt()
        .with_max_level(level)
        .with_writer(std::io::stderr)
        .try_init();

    let op_count = [
        args.encrypt.is_some(),
        args.decrypt.is_some(),
        args.validate.is_some(),
        args.sign.is_some(),
    ]
    .into_iter()
    .filter(|op| *op)
    .count();
    if op_count > 1 {
        eprintln!(
            "This utility currently only supports one of the encrypt, decrypt, sign or verify operations per invocation"
        );
        return ExitCode::from(1);
    }
    let identity_source_count = [
        args.import_pub.is_some(),
        args.import_prv.is_some(),
        args.identity.is_some(),
        args.generate.is_some(),
    ]
    .into_iter()
    .filter(|source| *source)
    .count();
    if identity_source_count > 1 {
        eprintln!("The -i, -g, -m and -M args are mutually exclusive");
        return ExitCode::from(1);
    }
    let encoding_count = [args.base64, args.base32, args.hex]
        .into_iter()
        .filter(|flag| *flag)
        .count();
    if encoding_count > 1 {
        eprintln!("The -b, -B and --hex args are mutually exclusive");
        return ExitCode::from(1);
    }

    if args.read.is_none() {
        args.read = args
            .encrypt
            .clone()
            .or_else(|| args.decrypt.clone())
            .or_else(|| args.sign.clone());
    }

    let op_requires_identity = args.sign.is_some()
        || args.encrypt.is_some()
        || args.decrypt.is_some()
        || args.announce.is_some()
        || args.write.is_some()
        || args.print_identity
        || args.export_pub
        || args.export_prv;

    let identity = match get_operating_identity(&args, !op_requires_identity).await {
        Ok(identity) => identity,
        Err((code, msg)) => {
            eprintln!("{msg}");
            return ExitCode::from(code);
        }
    };
    if op_requires_identity && identity.is_none() {
        eprintln!("Could not get working identity");
        return ExitCode::from(2);
    }

    let mut op = args.generate.is_some();
    if args.print_identity {
        print_identity(identity.as_ref().expect("identity checked"), &args);
        op = true;
    }
    if args.export_pub {
        let code = export_public_identity(identity.as_ref().expect("identity checked"), &args);
        if code != ExitCode::SUCCESS {
            return code;
        }
        op = true;
    }
    if args.export_prv {
        let code = export_private_identity(identity.as_ref().expect("identity checked"), &args);
        if code != ExitCode::SUCCESS {
            return code;
        }
        op = true;
    }
    if let Some(aspects) = args.hash.as_deref() {
        let identity_ref = identity.as_ref();
        let identity_hash_arg = args.identity.as_deref();
        let code = hash_destination(identity_ref, identity_hash_arg, aspects);
        if code != ExitCode::SUCCESS {
            return code;
        }
        op = true;
    }
    if let Some(aspects) = args.announce.as_deref() {
        return announce_destination(identity.as_ref().expect("identity checked"), aspects, &args)
            .await;
    }
    if args.validate.is_some() {
        return validate_signature(identity.as_ref(), args.identity.as_deref(), &args);
    }
    if args.sign.is_some() {
        return sign_file(identity.as_ref().expect("identity checked"), &args);
    }
    if args.encrypt.is_some() {
        return encrypt_file(identity.as_ref().expect("identity checked"), &args);
    }
    if args.decrypt.is_some() {
        return decrypt_file(identity.as_ref().expect("identity checked"), &args);
    }
    if args.write.is_some() {
        let code = write_identity(identity.as_ref().expect("identity checked"), &args);
        if code != ExitCode::SUCCESS {
            return code;
        }
        op = true;
    }

    if !op {
        let mut cmd = Args::command();
        let _ = cmd.print_help();
        println!();
    }
    ExitCode::SUCCESS
}

fn generate_identity(path: &Path, force: bool) -> Result<Identity, (u8, String)> {
    if let Err(e) = ensure_output_allowed(path, force) {
        return Err((11, e));
    }
    let identity = Identity::new();
    match identity.to_file(path) {
        Ok(()) => {
            println!(
                "New identity {} written to {}",
                hex::encode(identity.hash),
                path.display()
            );
            Ok(identity)
        }
        Err(e) => Err((
            253,
            format!("An error occurred while saving the generated Identity: {e}"),
        )),
    }
}

async fn get_operating_identity(
    args: &Args,
    allow_none: bool,
) -> Result<Option<Identity>, (u8, String)> {
    if let Some(path) = args.generate.as_ref() {
        return generate_identity(path, args.force).map(Some);
    }
    if let Some(import_pub) = args.import_pub.as_deref() {
        return import_public_identity(import_pub).map(Some);
    }
    if let Some(import_prv) = args.import_prv.as_deref() {
        return import_private_identity(import_prv).map(Some);
    }
    let Some(identity_arg) = args.identity.as_deref() else {
        return Ok(None);
    };

    let path = Path::new(identity_arg);
    if path.is_file() {
        let identity = load_identity_file(path).map_err(|e| (8, e))?;
        return Ok(Some(identity));
    }

    if args.no_cache {
        if allow_none {
            return Ok(None);
        }
        return Err((2, "Could not resolve identity".to_string()));
    }

    if identity_arg.len() == 32 {
        let hash = parse_hash16(identity_arg)
            .ok_or((8, "Invalid hexadecimal hash provided".to_string()))?;
        match recall_identity_from_python_known_destinations(hash, args) {
            Ok(Some(identity)) => {
                if identity.hash == hash {
                    println!("Recalled Identity {}", pretty_hash(&identity.hash));
                } else {
                    println!(
                        "Recalled Identity {} for destination {}",
                        pretty_hash(&identity.hash),
                        pretty_hash(&hash)
                    );
                }
                retain_identity_hash(args, identity.hash).await;
                return Ok(Some(identity));
            }
            Ok(None) => {}
            Err(msg) => return Err((8, msg)),
        }
        if allow_none && !args.request {
            return Ok(None);
        }
        if !args.request {
            return Err((
                2,
                format!(
                    "Could not recall Identity for {}.\nYou can query the network for unknown Identities with the -R option.",
                    pretty_hash(&hash)
                ),
            ));
        }
        let identity = request_identity(hash, args).await?;
        retain_identity_hash(args, identity.hash).await;
        return Ok(Some(identity));
    }

    Err((2, "Could not get working identity".to_string()))
}

fn import_public_identity(input: &str) -> Result<Identity, (u8, String)> {
    let identity_bytes = decode_import_identity_data(input, 64).ok_or((
        8,
        "Could not decode specified data to a valid public Reticulum Identity".to_string(),
    ))?;
    let identity = Identity::from_public_key(&identity_bytes).map_err(|e| {
        (
            8,
            format!("Could not create Reticulum identity from specified data: {e}"),
        )
    })?;
    println!("Reticulum Identity imported");
    Ok(identity)
}

fn import_private_identity(input: &str) -> Result<Identity, (u8, String)> {
    let identity_bytes = decode_import_identity_data(input, 64).ok_or((
        8,
        "Could not decode specified data to a valid private Reticulum Identity".to_string(),
    ))?;
    let identity = Identity::from_private_key(&identity_bytes).map_err(|e| {
        (
            8,
            format!("Could not create Reticulum identity from specified data: {e}"),
        )
    })?;
    println!("Reticulum Identity imported");
    Ok(identity)
}

fn decode_import_identity_data(input: &str, expected_len: usize) -> Option<Vec<u8>> {
    let path = Path::new(input);
    if path.is_file() {
        if let Ok(data) = std::fs::read(path) {
            if data.len() == expected_len {
                return Some(data);
            }
        }
    }
    if input.len() == expected_len * 2 {
        if let Ok(data) = hex::decode(input) {
            if data.len() == expected_len {
                return Some(data);
            }
        }
    }
    if let Ok(data) = decode_base32(input) {
        if data.len() == expected_len {
            return Some(data);
        }
    }
    if let Ok(data) = URL_SAFE.decode(input) {
        if data.len() == expected_len {
            return Some(data);
        }
    }
    None
}

async fn retain_identity_hash(args: &Args, identity_hash: [u8; 16]) {
    retain_identity_in_known_destinations_file(args, identity_hash);

    let shutdown = rns_runtime::lifecycle::ShutdownSignal::new();
    let foreground = Arc::new(AtomicBool::new(true));
    let Ok(handle) =
        rns_runtime::reticulum::init(args.config.as_deref(), None, shutdown.clone(), foreground)
            .await
    else {
        return;
    };
    let _ = handle
        .query_transport(TransportQuery::RetainIdentity { identity_hash })
        .await;
    shutdown.trigger();
}

fn retain_identity_in_known_destinations_file(args: &Args, identity_hash: [u8; 16]) {
    let config_dir = rns_runtime::platform::resolve_config_dir(args.config.as_deref());
    let path = config_dir.join("storage/known_destinations");
    let Ok(mut known) = KnownDestinations::load(&path) else {
        return;
    };
    if known.retain_identity(&identity_hash) > 0 {
        let _ = known.save(&path);
    }
}

fn load_identity_file(path: &Path) -> Result<Identity, String> {
    if path
        .extension()
        .and_then(|ext| ext.to_str())
        .is_some_and(|ext| ext.eq_ignore_ascii_case(PUB_EXT))
    {
        let data = std::fs::read(path)
            .map_err(|e| format!("Could not decode Identity from specified file: {e}"))?;
        return Identity::from_public_key(&data)
            .map_err(|e| format!("Could not decode public Identity from specified file: {e}"));
    }

    match Identity::from_file(path) {
        Ok(identity) => Ok(identity),
        Err(private_err) => {
            let data = std::fs::read(path).map_err(|_| {
                format!("Could not decode Identity from specified file: {private_err}")
            })?;
            Identity::from_public_key(&data).map_err(|public_err| {
                format!(
                    "Could not decode Identity from specified file: {private_err}; public key: {public_err}"
                )
            })
        }
    }
}

async fn request_identity(hash: [u8; 16], args: &Args) -> Result<Identity, (u8, String)> {
    let shutdown = rns_runtime::lifecycle::ShutdownSignal::new();
    let foreground = Arc::new(AtomicBool::new(true));
    let handle =
        rns_runtime::reticulum::init(args.config.as_deref(), None, shutdown.clone(), foreground)
            .await
            .map_err(|e| (1, format!("Failed to initialize Reticulum runtime: {e}")))?;

    let id_destination_hash =
        Destination::hash_from_name_and_identity(DEFAULT_ASPECTS, Some(&hash));
    for destination_hash in [hash, id_destination_hash] {
        handle
            .transport_tx
            .send(TransportMessage::RequestPath { destination_hash })
            .await
            .map_err(|_| (1, "Transport closed while requesting path".to_string()))?;
    }

    let timeout = Duration::from_secs_f64(args.timeout.max(0.0));
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if let Some(identity) = query_recent_announces_for_hash(&handle, hash).await {
            shutdown.trigger();
            println!(
                "Received Identity {} for destination {} from the network",
                pretty_hash(&identity.hash),
                pretty_hash(&hash)
            );
            return Ok(identity);
        }
        if tokio::time::Instant::now() >= deadline {
            break;
        }
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        let sleep_for = remaining.min(Duration::from_millis(100));
        tokio::time::sleep(sleep_for).await;
    }

    let identity = query_recent_announces_for_hash(&handle, hash).await;
    shutdown.trigger();
    identity.ok_or((2, "Identity request timed out".to_string()))
}

async fn query_recent_announces_for_hash(
    handle: &rns_runtime::reticulum::ReticulumHandle,
    hash: [u8; 16],
) -> Option<Identity> {
    let response = handle
        .query_transport(TransportQuery::GetRecentAnnounces)
        .await?;
    let TransportQueryResponse::Announces(announces) = response else {
        return None;
    };

    for announce in announces {
        let public_key = announce.public_key?;
        if announce.dest_hash == hash {
            return Identity::from_public_key(&public_key).ok();
        }
        let identity_hash = rns_crypto::sha::truncated_hash(&public_key);
        if identity_hash == hash {
            return Identity::from_public_key(&public_key).ok();
        }
    }
    None
}

fn recall_identity_from_python_known_destinations(
    hash: [u8; 16],
    args: &Args,
) -> Result<Option<Identity>, String> {
    let config_dir = rns_runtime::platform::resolve_config_dir(args.config.as_deref());
    let path = config_dir.join("storage/known_destinations");
    let data = match std::fs::read(path) {
        Ok(data) => data,
        Err(_) => return Ok(None),
    };
    let mut cursor = std::io::Cursor::new(data);
    let value = match rmpv::decode::read_value(&mut cursor) {
        Ok(value) => value,
        Err(_) => return Ok(None),
    };
    let rmpv::Value::Map(entries) = value else {
        return Ok(None);
    };

    for (key, value) in entries {
        let dest_hash = value_bytes(&key).and_then(hash16_from_slice);
        let Some(items) = value.as_array() else {
            continue;
        };
        if items.len() < 3 {
            continue;
        }
        let Some(public_key_vec) = value_bytes(&items[2]) else {
            continue;
        };
        let identity = match Identity::from_public_key(&public_key_vec) {
            Ok(identity) => identity,
            Err(e) if dest_hash == Some(hash) => {
                return Err(format!("Invalid hexadecimal hash provided: {e}"));
            }
            Err(_) => continue,
        };
        if dest_hash == Some(hash) || identity.hash == hash {
            return Ok(Some(identity));
        }
    }
    Ok(None)
}

fn value_bytes(value: &rmpv::Value) -> Option<Vec<u8>> {
    match value {
        rmpv::Value::Binary(bytes) => Some(bytes.clone()),
        rmpv::Value::String(s) => s.as_str().map(|s| s.as_bytes().to_vec()),
        _ => None,
    }
}

fn hash16_from_slice(bytes: Vec<u8>) -> Option<[u8; 16]> {
    if bytes.len() != 16 {
        return None;
    }
    let mut out = [0u8; 16];
    out.copy_from_slice(&bytes);
    Some(out)
}

fn hash_destination(
    identity: Option<&Identity>,
    identity_hash_arg: Option<&str>,
    aspects: &str,
) -> ExitCode {
    if aspects.trim().is_empty() {
        eprintln!("Invalid destination aspects specified");
        return ExitCode::from(9);
    }
    let identity_hash = if let Some(identity) = identity {
        identity.hash
    } else if let Some(identity_hash_arg) = identity_hash_arg {
        match parse_hash16(identity_hash_arg) {
            Some(hash) => hash,
            None => {
                eprintln!("Invalid identity hash length");
                return ExitCode::from(8);
            }
        }
    } else {
        eprintln!("Invalid identity");
        return ExitCode::from(8);
    };

    let hash = Destination::hash_from_name_and_identity(aspects, Some(&identity_hash));
    println!(
        "The {aspects} destination for this Identity is {}",
        pretty_hash(&hash)
    );
    if identity.is_some() {
        println!(
            "The full destination specifier is {}.{}",
            aspects,
            hex::encode(identity_hash)
        );
    }
    ExitCode::SUCCESS
}

async fn announce_destination(identity: &Identity, aspects: &str, args: &Args) -> ExitCode {
    if aspects.split('.').count() <= 1 {
        eprintln!("Invalid destination aspects specified");
        return ExitCode::from(9);
    }
    if !identity.has_private_key() {
        let hash = Destination::hash_from_name_and_identity(aspects, Some(&identity.hash));
        println!(
            "The {aspects} destination for this Identity is {}",
            pretty_hash(&hash)
        );
        println!(
            "The full destination specifier is {}.{}",
            aspects,
            hex::encode(identity.hash)
        );
        println!("Cannot announce this destination, since the private key is not held");
        return ExitCode::from(4);
    }

    let shutdown = rns_runtime::lifecycle::ShutdownSignal::new();
    let foreground = Arc::new(AtomicBool::new(true));
    let handle = match rns_runtime::reticulum::init(
        args.config.as_deref(),
        None,
        shutdown.clone(),
        foreground,
    )
    .await
    {
        Ok(handle) => handle,
        Err(e) => {
            eprintln!("Failed to initialize Reticulum runtime: {e}");
            return ExitCode::from(1);
        }
    };

    let mut destination =
        match Destination::new(Some(identity), Direction::In, DestType::Single, aspects) {
            Ok(destination) => destination,
            Err(e) => {
                eprintln!("Could not create destination: {e}");
                shutdown.trigger();
                return ExitCode::from(1);
            }
        };
    println!("Created destination {aspects}");
    println!("Announcing destination {}", pretty_hash(&destination.hash));

    let raw = match destination.announce_packet(identity, None, None, false, None, now_epoch()) {
        Ok(raw) => raw,
        Err(e) => {
            eprintln!("An error occurred while attempting to send the announce: {e}");
            shutdown.trigger();
            return ExitCode::from(1);
        }
    };
    let dest_hash = destination.hash;
    let _ = handle
        .transport_tx
        .send(TransportMessage::Outbound(OutboundRequest {
            raw: raw.into(),
            destination_hash: dest_hash,
        }))
        .await;
    tokio::time::sleep(Duration::from_millis(250)).await;
    shutdown.trigger();
    ExitCode::SUCCESS
}

fn print_identity(identity: &Identity, args: &Args) {
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

fn export_public_identity(identity: &Identity, args: &Args) -> ExitCode {
    println!(
        "Public Identity Keys  : {}",
        encode_key_text(&identity.get_public_key(), args)
    );
    ExitCode::SUCCESS
}

fn export_private_identity(identity: &Identity, args: &Args) -> ExitCode {
    let Some(private_key) = identity.get_private_key() else {
        eprintln!("Identity doesn't hold a private key, cannot export");
        return ExitCode::from(4);
    };
    println!(
        "Private Identity Keys : {}",
        encode_key_text(&*private_key, args)
    );
    ExitCode::SUCCESS
}

fn sign_file(identity: &Identity, args: &Args) -> ExitCode {
    if !identity.has_private_key() {
        eprintln!("Specified Identity does not hold a private key. Cannot sign.");
        return ExitCode::from(4);
    }
    let Some(input_path) = args.read.as_ref() else {
        eprintln!("Signing requested, but no input data specified");
        return ExitCode::from(6);
    };
    let input = match std::fs::File::open(input_path) {
        Ok(file) => file,
        Err(e) => {
            eprintln!("The file \"{}\" does not exist: {e}", input_path.display());
            return ExitCode::from(6);
        }
    };
    let signature = if args.raw {
        match rsg::create_raw_signature(identity, input) {
            Ok(signature) => signature.to_vec(),
            Err(e) => {
                eprintln!("Could not sign {}: {e}", input_path.display());
                return ExitCode::from(254);
            }
        }
    } else {
        match rsg::create_rsg(identity, input) {
            Ok(rsg) => rsg,
            Err(e) => {
                eprintln!("Could not sign {}: {e}", input_path.display());
                return ExitCode::from(254);
            }
        }
    };

    if !args.raw && (args.base64 || args.base32 || args.hex) {
        let encoded = if args.base64 {
            URL_SAFE.encode(&signature)
        } else if args.base32 {
            encode_base32(&signature)
        } else {
            hex::encode(&signature)
        };
        println!("\n{}\n", wrap_rsg(encoded.as_bytes()));
        println!(
            "Signed file {} with {}",
            input_path.display(),
            pretty_hash(&identity.hash)
        );
        return ExitCode::SUCCESS;
    }

    let Some(output_path) = args
        .write
        .clone()
        .or_else(|| Some(append_extension(input_path, SIG_EXT)))
    else {
        eprintln!("Signing requested, but no output specified");
        return ExitCode::from(253);
    };
    if let Err(e) = ensure_output_allowed(&output_path, args.force) {
        eprintln!("{e}");
        return ExitCode::from(11);
    }

    if let Err(e) = write_output(&output_path, &signature, args.stdout) {
        eprintln!("{e}");
        return ExitCode::from(253);
    }

    if !args.stdout {
        println!(
            "Signed file {} with {} to {}",
            input_path.display(),
            pretty_hash(&identity.hash),
            output_path.display()
        );
    }
    ExitCode::SUCCESS
}

fn validate_signature(
    identity: Option<&Identity>,
    identity_arg: Option<&str>,
    args: &Args,
) -> ExitCode {
    let Some(validate_path) = args.validate.as_ref() else {
        return ExitCode::from(20);
    };

    let validate_str = validate_path.to_string_lossy();
    let path_is_sigfile = validate_str
        .to_lowercase()
        .ends_with(&format!(".{SIG_EXT}"));
    let (sig_path, inferred_input_path) = if path_is_sigfile {
        let stripped = &validate_str[..validate_str.len() - SIG_EXT.len() - 1];
        (validate_path.clone(), PathBuf::from(stripped))
    } else {
        (
            append_extension(validate_path, SIG_EXT),
            validate_path.clone(),
        )
    };
    let input_path = args.read.clone().unwrap_or(inferred_input_path);

    let sig_bytes = match std::fs::read(&sig_path) {
        Ok(data) => data,
        Err(e) => {
            eprintln!(
                "An error occurred while opening {}: {e}",
                sig_path.display()
            );
            return ExitCode::from(6);
        }
    };
    let input = match std::fs::File::open(&input_path) {
        Ok(file) => file,
        Err(e) => {
            eprintln!(
                "The validation target \"{}\" does not exist: {e}",
                input_path.display()
            );
            return ExitCode::from(6);
        }
    };

    if rsg::is_legacy_format(&sig_bytes) {
        let Some(identity) = identity else {
            eprintln!(
                "Cannot validate legacy rsg signatures without an explicit required identity"
            );
            return ExitCode::from(2);
        };
        match rsg::validate_legacy_signature(&sig_bytes, input, identity) {
            Ok(()) => {
                println!(
                    "Signature is valid, the file {} was signed by {}",
                    input_path.display(),
                    pretty_hash(&identity.hash)
                );
                ExitCode::SUCCESS
            }
            Err(_) => {
                eprintln!(
                    "Invalid signature {} for file {}\nThis file was NOT signed by {}",
                    sig_path.display(),
                    input_path.display(),
                    pretty_hash(&identity.hash)
                );
                ExitCode::from(10)
            }
        }
    } else {
        let required = if let Some(identity) = identity {
            Some(rsg::RequiredSigner::Identity(identity))
        } else if let Some(identity_arg) = identity_arg {
            match parse_hash16(identity_arg) {
                Some(hash) => Some(rsg::RequiredSigner::Hash(hash)),
                None => {
                    eprintln!("Invalid identity hash length");
                    return ExitCode::from(8);
                }
            }
        } else {
            None
        };
        match rsg::validate_rsg(&sig_bytes, input, required) {
            Ok(validated) => {
                let _ = (&validated.file_hash, &validated.public_key);
                println!(
                    "Signature is valid, the file {} was signed by {}",
                    input_path.display(),
                    pretty_hash(&validated.signer_hash)
                );
                ExitCode::SUCCESS
            }
            Err(e) => {
                let signer_description = required
                    .map(|required| match required {
                        rsg::RequiredSigner::Identity(identity) => pretty_hash(&identity.hash),
                        rsg::RequiredSigner::Hash(hash) => pretty_hash(&hash),
                    })
                    .map(|s| format!("\nThis file was NOT signed by {s}"))
                    .unwrap_or_default();
                eprintln!(
                    "Invalid signature {} for file {}{signer_description}: {e}",
                    sig_path.display(),
                    input_path.display()
                );
                ExitCode::from(10)
            }
        }
    }
}

fn encrypt_file(identity: &Identity, args: &Args) -> ExitCode {
    let Some(input_path) = args.read.as_ref() else {
        eprintln!("Encryption requested, but no input data specified");
        return ExitCode::from(6);
    };
    let mut input: Box<dyn Read> = match std::fs::File::open(input_path) {
        Ok(file) => Box::new(file),
        Err(e) => {
            eprintln!("Input file {} not found: {e}", input_path.display());
            return ExitCode::from(6);
        }
    };
    let Some(output_path) = args
        .write
        .clone()
        .or_else(|| Some(append_extension(input_path, ENCRYPT_EXT)))
    else {
        eprintln!("Encryption requested, but no output specified");
        return ExitCode::from(253);
    };
    if let Err(e) = ensure_output_allowed(&output_path, args.force) {
        eprintln!("{e}");
        return ExitCode::from(11);
    };
    let mut output = match create_output(&output_path, args.stdout) {
        Ok(file) => file,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(253);
        }
    };

    let mut buffer = vec![0u8; ENC_CHUNK];
    loop {
        let n = match input.read(&mut buffer) {
            Ok(n) => n,
            Err(e) => {
                eprintln!("Could not read input file: {e}");
                return ExitCode::from(252);
            }
        };
        if n == 0 {
            break;
        }
        let ciphertext = match identity.encrypt(&buffer[..n], None) {
            Ok(ciphertext) => ciphertext,
            Err(e) => {
                eprintln!("An error occurred while encrypting data: {e}");
                return ExitCode::from(254);
            }
        };
        if let Err(e) = output.write_all(&ciphertext) {
            eprintln!("Could not write encrypted output: {e}");
            return ExitCode::from(253);
        }
    }

    if !args.stdout {
        println!(
            "File {} encrypted for {} to {}",
            input_path.display(),
            pretty_hash(&identity.hash),
            output_path.display()
        );
    }
    ExitCode::SUCCESS
}

fn decrypt_file(identity: &Identity, args: &Args) -> ExitCode {
    if !identity.has_private_key() {
        eprintln!("Specified Identity does not hold a private key. Cannot decrypt.");
        return ExitCode::from(4);
    }
    let Some(input_path) = args.read.as_ref() else {
        eprintln!("Decryption requested, but no input data specified");
        return ExitCode::from(6);
    };
    if !input_path
        .to_string_lossy()
        .to_lowercase()
        .ends_with(&format!(".{ENCRYPT_EXT}"))
    {
        eprintln!(
            "The file {} does not appear to be a Reticulum encrypted file",
            input_path.display()
        );
        return ExitCode::from(7);
    }
    let ciphertext = match read_input(input_path, args.stdin) {
        Ok(data) => data,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(6);
        }
    };
    let Some(output_path) = args
        .write
        .clone()
        .or_else(|| default_decrypt_output_path(input_path))
    else {
        eprintln!("Decryption requested, but no output specified");
        return ExitCode::from(7);
    };
    if let Err(e) = ensure_output_allowed(&output_path, args.force) {
        eprintln!("{e}");
        return ExitCode::from(11);
    }

    let plaintext = match decrypt_ciphertext(identity, &ciphertext) {
        Ok(plaintext) => plaintext,
        Err(()) => {
            eprintln!("Data could not be decrypted with the specified Identity");
            return ExitCode::from(12);
        }
    };

    if let Err(e) = write_output(&output_path, &plaintext, args.stdout) {
        eprintln!("{e}");
        return ExitCode::from(253);
    }
    if !args.stdout {
        println!(
            "File {} decrypted with {} to {}",
            input_path.display(),
            pretty_hash(&identity.hash),
            output_path.display()
        );
    }
    ExitCode::SUCCESS
}

fn decrypt_ciphertext(identity: &Identity, ciphertext: &[u8]) -> Result<Vec<u8>, ()> {
    if ciphertext.is_empty() {
        return Ok(Vec::new());
    }

    if let Ok(plaintext) = identity.decrypt(ciphertext, None, false) {
        return Ok(plaintext);
    }

    if ciphertext.len() > ENC_CHUNK {
        if let Ok(plaintext) = decrypt_ciphertext_chunks(identity, ciphertext, DEC_CHUNK) {
            return Ok(plaintext);
        }
        if let Ok(plaintext) =
            decrypt_ciphertext_chunks(identity, ciphertext, FULL_CHUNK_TOKEN_SIZE)
        {
            return Ok(plaintext);
        }
        if let Ok(plaintext) = decrypt_ciphertext_chunks(identity, ciphertext, ENC_CHUNK) {
            return Ok(plaintext);
        }
    }

    Err(())
}

fn decrypt_ciphertext_chunks(
    identity: &Identity,
    ciphertext: &[u8],
    chunk_size: usize,
) -> Result<Vec<u8>, ()> {
    let mut plaintext = Vec::new();
    let mut pos = 0usize;
    while pos < ciphertext.len() {
        let end = (pos + chunk_size).min(ciphertext.len());
        let chunk = identity
            .decrypt(&ciphertext[pos..end], None, false)
            .map_err(|_| ())?;
        plaintext.extend_from_slice(&chunk);
        pos = end;
    }
    Ok(plaintext)
}

fn write_identity(identity: &Identity, args: &Args) -> ExitCode {
    let Some(path) = args.write.as_ref() else {
        return ExitCode::SUCCESS;
    };
    let mut path = path.clone();

    if identity.has_private_key() && args.export_prv {
        if let Err(e) = ensure_output_allowed(&path, args.force) {
            eprintln!("{e}");
            return ExitCode::from(11);
        }
        match identity.to_file(&path) {
            Ok(()) => {
                println!("Wrote private identity to {}", path.display());
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("Error while writing private identity to file: {e}");
                ExitCode::from(253)
            }
        }
    } else {
        if !path
            .to_string_lossy()
            .to_lowercase()
            .ends_with(&format!(".{PUB_EXT}"))
        {
            path = PathBuf::from(format!("{}.{}", path.to_string_lossy(), PUB_EXT));
        }
        if let Err(e) = ensure_output_allowed(&path, args.force) {
            eprintln!("{e}");
            return ExitCode::from(11);
        }
        match identity.pub_to_file(&path) {
            Ok(()) => {
                println!("Wrote public identity to {}", path.display());
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("Error while writing public identity to file: {e}");
                ExitCode::from(253)
            }
        }
    }
}

fn read_input(path: &Path, _use_stdin: bool) -> Result<Vec<u8>, String> {
    std::fs::read(path).map_err(|e| format!("Input file {} not found: {e}", path.display()))
}

fn create_output(path: &Path, _use_stdout: bool) -> Result<Box<dyn Write>, String> {
    let file = std::fs::File::create(path).map_err(|e| {
        format!(
            "Could not open output file {} for writing: {e}",
            path.display()
        )
    })?;
    Ok(Box::new(file))
}

fn write_output(path: &Path, data: &[u8], use_stdout: bool) -> Result<(), String> {
    let mut output = create_output(path, use_stdout)?;
    output
        .write_all(data)
        .map_err(|e| format!("Could not write output: {e}"))
}

fn ensure_output_allowed(path: &Path, force: bool) -> Result<(), String> {
    if path.exists() && !force {
        return Err(format!(
            "Output file {} already exists. Not overwriting.",
            path.display()
        ));
    }
    Ok(())
}

fn append_extension(path: &Path, ext: &str) -> PathBuf {
    PathBuf::from(format!("{}.{}", path.to_string_lossy(), ext))
}

fn default_decrypt_output_path(path: &Path) -> Option<PathBuf> {
    let s = path.to_string_lossy();
    if s.to_lowercase().ends_with(&format!(".{ENCRYPT_EXT}")) {
        Some(PathBuf::from(s.replace(&format!(".{ENCRYPT_EXT}"), "")))
    } else {
        None
    }
}

fn parse_hash16(s: &str) -> Option<[u8; 16]> {
    if s.len() != 32 {
        return None;
    }
    let bytes = hex::decode(s).ok()?;
    hash16_from_slice(bytes)
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

fn wrap_rsg(rsg: &[u8]) -> String {
    const HEADER: &[u8] = b"#### Start of rsg data ";
    const FOOTER: &[u8] = b" End of rsg data ####";
    const ROW_WIDTH: usize = 64;

    let mut header = String::from_utf8_lossy(HEADER).into_owned();
    while header.len() < ROW_WIDTH {
        header.push('#');
    }

    let mut footer = String::new();
    while footer.len() + FOOTER.len() < ROW_WIDTH {
        footer.push('#');
    }
    footer.push_str(&String::from_utf8_lossy(FOOTER));

    let mut wrapped = String::new();
    wrapped.push_str(&header);
    wrapped.push('\n');
    for chunk in rsg.chunks(ROW_WIDTH) {
        wrapped.push_str(&String::from_utf8_lossy(chunk));
        for _ in chunk.len()..ROW_WIDTH {
            wrapped.push('=');
        }
        wrapped.push('\n');
    }
    wrapped.push_str(&footer);
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
            let index = ((buffer >> (bits - 5)) & 0x1f) as usize;
            out.push(ALPHABET[index] as char);
            bits -= 5;
        }
    }
    if bits > 0 {
        let index = ((buffer << (5 - bits)) & 0x1f) as usize;
        out.push(ALPHABET[index] as char);
    }
    while out.len() % 8 != 0 {
        out.push('=');
    }
    out
}

fn decode_base32(input: &str) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    let mut buffer = 0u32;
    let mut bits = 0u8;
    for ch in input.chars() {
        if ch == '=' {
            break;
        }
        let val = match ch {
            'A'..='Z' => ch as u8 - b'A',
            'a'..='z' => ch as u8 - b'a',
            '2'..='7' => ch as u8 - b'2' + 26,
            c if c.is_whitespace() => continue,
            _ => return Err(format!("invalid base32 character {ch:?}")),
        };
        buffer = (buffer << 5) | u32::from(val);
        bits += 5;
        while bits >= 8 {
            out.push(((buffer >> (bits - 8)) & 0xff) as u8);
            bits -= 8;
        }
    }
    Ok(out)
}

fn pretty_hash(hash: &[u8; 16]) -> String {
    format!("<{}>", hex::encode(hash))
}

fn now_epoch() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decrypt_accepts_pre_1_2_4_rnid_rs_chunking() {
        let identity = Identity::new();
        let legacy_plaintext_chunk =
            ENC_CHUNK - rns_identity::identity::IDENTITY_OVERHEAD - BLOCK_SIZE;
        let plaintext = vec![0xA5; legacy_plaintext_chunk + 1];
        let mut ciphertext = Vec::new();
        for chunk in plaintext.chunks(legacy_plaintext_chunk) {
            ciphertext.extend(identity.encrypt(chunk, None).unwrap());
        }

        let decrypted = decrypt_ciphertext(&identity, &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }
}
