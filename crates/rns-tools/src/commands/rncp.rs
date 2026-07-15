//! rncp-rs — file transfer (send, listen, fetch).
//!
//! Modes:
//! * `rncp-rs <file> <destination_hash>` — send
//! * `rncp-rs -l [-s <dir>] [-a <hash>] [-F [-j <jail>]]` — listen (optionally serving fetch)
//! * `rncp-rs -f <destination_hash> <remote_path> [-s <dir>]` — fetch
//!
//! Exit codes: 0 success, 1 generic failure, 2 identity unreadable,
//! 3 output dir missing, 4 output dir not writable.
//!
//! Security: listener mode follows Python rncp auth semantics. By default it
//! accepts only identities from `-a` or the standard rncp allow-list files.
//! `-n` / `--no-auth` explicitly accepts anyone. Use `-j <jail>` with `-F`
//! unless you intentionally want upstream-compatible unrestricted fetch paths.

use std::path::PathBuf;
use std::process;
use std::time::Duration;

use bytes::Bytes;
use clap::Parser;
use rns_identity::destination::{DestType, Destination, Direction};
use rns_transport::messages::{OutboundRequest, TransportMessage};
use tokio::io::AsyncWriteExt;

fn expand_tilde(p: &str) -> PathBuf {
    if let Some(rest) = p.strip_prefix("~/") {
        if let Some(home) = std::env::var_os("HOME") {
            return PathBuf::from(home).join(rest);
        }
    }
    PathBuf::from(p)
}

use rns_identity::identity::Identity;
use rns_runtime::lifecycle::{ShutdownSignal, install_signal_handlers};
use rns_runtime::platform::StoragePaths;
use rns_runtime::rncp::{
    DEFAULT_RNCP_APP_NAME, RncpError, RncpEvent, RncpFetchOutcome, RncpFetchRequest,
    RncpListenerConfig, RncpOutcome, RncpSendRequest, default_rncp_app_name, rncp_fetch_file,
    rncp_send_file, spawn_rncp_listener,
};

const DEFAULT_TIMEOUT_SECS: f64 = 15.0;
use rns_tools::RS_RETICULUM_VERSION;

#[derive(Parser)]
#[command(
    name = "rncp-rs",
    about = "Reticulum File Transfer Utility",
    disable_version_flag = true
)]
struct Args {
    /// Path to alternative Reticulum config directory
    #[arg(long, value_name = "path")]
    config: Option<String>,

    /// Increase verbosity
    #[arg(short = 'v', long, action = clap::ArgAction::Count)]
    verbose: u8,

    /// Decrease verbosity
    #[arg(short = 'q', long, action = clap::ArgAction::Count)]
    quiet: u8,

    /// Disable transfer progress output
    #[arg(short = 'S', long)]
    silent: bool,

    /// Listen for incoming transfer requests
    #[arg(short = 'l', long)]
    listen: bool,

    /// Disable automatic compression
    #[arg(short = 'C', long)]
    no_compress: bool,

    /// Allow clients to fetch files from this listener (use -a or -n; -j is recommended)
    #[arg(short = 'F', long)]
    allow_fetch: bool,

    /// Fetch file from remote listener instead of sending. Positional args
    /// become `<destination_hash> <remote_path>`.
    #[arg(short = 'f', long)]
    fetch: bool,

    /// Restrict fetch requests to the specified directory (absolute path).
    /// Used with -F on listener side, or with -f on fetch client side.
    #[arg(short = 'j', long, value_name = "path")]
    jail: Option<String>,

    /// Save received files in specified path (listen mode)
    #[arg(short = 's', long, value_name = "path")]
    save: Option<String>,

    /// Allow overwriting received files instead of adding a numeric postfix
    #[arg(short = 'O', long)]
    overwrite: bool,

    /// Listen-mode announce interval in seconds; -1 disables, 0 announces once at startup
    #[arg(short = 'b', value_name = "seconds", default_value_t = -1)]
    announce_interval: i64,

    /// Allowed sender identity hash (repeat for multiple). 32 hex chars each.
    #[arg(short = 'a', value_name = "hash", action = clap::ArgAction::Append)]
    allowed: Vec<String>,

    /// Accept requests from anyone.
    #[arg(short = 'n', long = "no-auth")]
    no_auth: bool,

    /// Print identity and destination hash, then exit (listen mode)
    #[arg(short = 'p', long)]
    print_identity: bool,

    /// Path to identity file to use (default: `<storage>/identities/rncp`)
    #[arg(short = 'i', value_name = "identity")]
    identity_path: Option<String>,

    /// Timeout before giving up (seconds)
    #[arg(short = 'w', value_name = "seconds", default_value_t = DEFAULT_TIMEOUT_SECS)]
    timeout: f64,

    /// Display physical layer transfer rates.
    #[arg(short = 'P', long = "phy-rates")]
    phy_rates: bool,

    /// Print version and exit.
    #[arg(long)]
    version: bool,

    /// File to be transferred (send mode)
    file: Option<String>,

    /// Hexadecimal hash of the receiver (send mode, 32 hex chars)
    destination: Option<String>,
}

fn parse_dest_hash(hex_str: &str) -> Result<[u8; 16], String> {
    if hex_str.len() != 32 {
        return Err(
            "Destination length is invalid, must be 32 hexadecimal characters (16 bytes)."
                .to_string(),
        );
    }
    let bytes = hex::decode(hex_str)
        .map_err(|_| "Invalid destination entered. Check your input.".to_string())?;
    <[u8; 16]>::try_from(bytes.as_slice())
        .map_err(|_| "Invalid destination entered. Check your input.".to_string())
}

// Default path: `<storage>/identities/rncp`; `-i` overrides.
fn load_or_create_identity(
    identity_path: Option<&str>,
    default_dir: &std::path::Path,
) -> Result<Identity, (i32, String)> {
    let path = match identity_path {
        Some(p) => expand_tilde(p),
        None => default_dir.join("rncp"),
    };

    if path.is_file() {
        match Identity::from_file(&path) {
            Ok(id) => Ok(id),
            Err(e) => Err((
                2,
                format!(
                    "Could not load identity for rncp. The identity file at \"{}\" may be corrupt or unreadable: {e}",
                    path.display()
                ),
            )),
        }
    } else {
        if let Some(parent) = path.parent() {
            if let Err(e) = std::fs::create_dir_all(parent) {
                return Err((
                    2,
                    format!(
                        "Could not create identity directory \"{}\": {e}",
                        parent.display()
                    ),
                ));
            }
        }
        let id = Identity::new();
        if let Err(e) = id.to_file(&path) {
            return Err((
                2,
                format!("Could not persist identity to \"{}\": {e}", path.display()),
            ));
        }
        Ok(id)
    }
}

#[tokio::main]
pub(crate) async fn main() {
    let args = Args::parse();
    if args.version {
        println!("rncp-rs {RS_RETICULUM_VERSION}");
        return;
    }
    if args.phy_rates {
        eprintln!(
            "rncp-rs: -P/--phy-rates is not implemented yet; the Rust resource layer currently exposes logical transfer progress only."
        );
        process::exit(2);
    }

    let level = match (args.verbose as i32) - (args.quiet as i32) {
        n if n >= 2 => tracing::Level::DEBUG,
        1 => tracing::Level::INFO,
        0 => tracing::Level::WARN,
        _ => tracing::Level::ERROR,
    };
    let config_dir = rns_runtime::platform::resolve_config_dir(args.config.as_deref());
    rns_tools::init_tracing(
        level,
        rns_tools::config_log_timestamps(&config_dir),
        true,
        std::io::stderr,
    );

    if args.fetch {
        run_fetch(args).await;
    } else if args.listen {
        run_listen(args).await;
    } else {
        run_send(args).await;
    }
}

async fn run_fetch(args: Args) -> ! {
    // Register before any slow init so an early SIGINT exits cleanly.
    let shutdown = ShutdownSignal::new();
    let _signal_rx = install_signal_handlers(shutdown.clone());
    // In fetch mode the positionals are `<destination_hash> <remote_path>`.
    let (Some(dest_arg), Some(path_arg)) = (args.file.as_ref(), args.destination.as_ref()) else {
        eprintln!("rncp-rs: fetch mode requires <destination_hash> <remote_path>");
        process::exit(1);
    };

    let dest_hash = match parse_dest_hash(dest_arg) {
        Ok(h) => h,
        Err(e) => {
            eprintln!("{e}");
            process::exit(1);
        }
    };

    let save_dir = match args.save.as_deref() {
        Some(p) => {
            let path = expand_tilde(p);
            if !path.is_dir() {
                eprintln!("Output directory not found");
                process::exit(3);
            }
            let probe = path.join(".rncp_write_test");
            match std::fs::File::create(&probe) {
                Ok(_) => {
                    let _ = std::fs::remove_file(&probe);
                }
                Err(_) => {
                    eprintln!("Output directory not writable");
                    process::exit(4);
                }
            }
            path
        }
        None => std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
    };

    let handle = start_reticulum(args.config.as_deref(), shutdown.clone()).await;
    let paths = StoragePaths::from_config_dir(&handle.config_dir);
    let identity = match load_or_create_identity(args.identity_path.as_deref(), &paths.identity_dir)
    {
        Ok(id) => id,
        Err((code, msg)) => {
            eprintln!("{msg}");
            process::exit(code);
        }
    };

    if !args.silent {
        println!("Fetching \"{path_arg}\" from <{}>", hex::encode(dest_hash));
    }

    let timeout = Duration::from_secs_f64(args.timeout.max(1.0));
    let path_wait = timeout;

    let (progress_tx, mut progress_rx) = tokio::sync::mpsc::channel::<f32>(32);
    let silent = args.silent;
    let progress_task = tokio::spawn(async move {
        let mut last = -1.0_f32;
        while let Some(p) = progress_rx.recv().await {
            if silent {
                continue;
            }
            if (p - last).abs() < 0.01 && p < 1.0 {
                continue;
            }
            last = p;
            let pct = (p * 100.0).clamp(0.0, 100.0);
            let mut stderr = tokio::io::stderr();
            let _ = stderr
                .write_all(format!("\rfetch: {pct:5.1}%   ").as_bytes())
                .await;
            let _ = stderr.flush().await;
        }
        if !silent {
            let _ = tokio::io::stderr().write_all(b"\n").await;
        }
    });

    let result = rncp_fetch_file(RncpFetchRequest {
        transport_tx: handle.transport_tx.clone(),
        identity,
        dest_hash,
        remote_path: path_arg,
        save_dir: &save_dir,
        overwrite: args.overwrite,
        overall_timeout: timeout,
        path_wait,
        progress_tx: Some(progress_tx),
    })
    .await;

    let _ = progress_task.await;

    match result {
        Ok(outcome) => {
            if !args.silent {
                print_fetch_summary(&outcome);
            }
            process::exit(0);
        }
        Err(RncpError::PathTimeout) => {
            eprintln!("Path not found");
            process::exit(1);
        }
        Err(RncpError::NoIdentity) => {
            eprintln!("Destination's identity is not known.");
            process::exit(1);
        }
        Err(RncpError::Timeout(what)) => {
            eprintln!("Timed out waiting for {what}");
            process::exit(1);
        }
        Err(RncpError::Denied) => {
            eprintln!("Remote denied the fetch (not in allow-list or outside jail).");
            process::exit(1);
        }
        Err(RncpError::ResourceFailed(reason)) => {
            eprintln!("Fetch failed: {reason}");
            process::exit(1);
        }
        Err(e) => {
            eprintln!("rncp-rs: fetch failed: {e}");
            process::exit(1);
        }
    }
}

fn print_fetch_summary(outcome: &RncpFetchOutcome) {
    let elapsed = outcome.duration.as_secs_f64().max(1e-6);
    let throughput_bps = (outcome.bytes as f64) * 8.0 / elapsed;
    let (t_value, t_unit) = human_rate(throughput_bps);
    println!(
        "Fetched \"{}\" ({} bytes) in {:.2}s ({:.2} {}) → {}",
        outcome.file_name,
        outcome.bytes,
        elapsed,
        t_value,
        t_unit,
        outcome.saved_path.display()
    );
}

async fn run_send(args: Args) -> ! {
    // Register before any slow init so an early SIGINT exits cleanly.
    let shutdown = ShutdownSignal::new();
    let _signal_rx = install_signal_handlers(shutdown.clone());
    let (Some(file_arg), Some(dest_arg)) = (args.file.as_ref(), args.destination.as_ref()) else {
        // Bare `rncp` prints help and exits 0.
        let mut cmd = <Args as clap::CommandFactory>::command();
        cmd.print_help().ok();
        println!();
        process::exit(0);
    };

    let dest_hash = match parse_dest_hash(dest_arg) {
        Ok(h) => h,
        Err(e) => {
            eprintln!("{e}");
            process::exit(1);
        }
    };

    let file_path = expand_tilde(file_arg);
    if !file_path.is_file() {
        eprintln!("File not found");
        process::exit(1);
    }

    let file_name = file_path
        .file_name()
        .and_then(|s| s.to_str())
        .map(|s| s.to_string())
        .unwrap_or_else(|| "file".to_string());

    let data = match tokio::fs::read(&file_path).await {
        Ok(d) => d,
        Err(e) => {
            eprintln!("Failed to read \"{}\": {e}", file_path.display());
            process::exit(1);
        }
    };

    let handle = start_reticulum(args.config.as_deref(), shutdown.clone()).await;

    let paths = StoragePaths::from_config_dir(&handle.config_dir);
    let identity = match load_or_create_identity(args.identity_path.as_deref(), &paths.identity_dir)
    {
        Ok(id) => id,
        Err((code, msg)) => {
            eprintln!("{msg}");
            process::exit(code);
        }
    };

    if !args.silent {
        println!("Sending \"{file_name}\" to <{}>", hex::encode(dest_hash));
    }

    let timeout = Duration::from_secs_f64(args.timeout.max(1.0));
    let path_wait = timeout;
    let auto_compress = !args.no_compress;
    let bytes_total = data.len();

    let (progress_tx, mut progress_rx) = tokio::sync::mpsc::channel::<f32>(32);
    let silent = args.silent;
    let progress_task = tokio::spawn(async move {
        let mut last = -1.0_f32;
        while let Some(p) = progress_rx.recv().await {
            if silent {
                continue;
            }
            if (p - last).abs() < 0.01 && p < 1.0 {
                continue;
            }
            last = p;
            let pct = (p * 100.0).clamp(0.0, 100.0);
            let mut stderr = tokio::io::stderr();
            let _ = stderr
                .write_all(format!("\rtransfer: {pct:5.1}%   ").as_bytes())
                .await;
            let _ = stderr.flush().await;
        }
        if !silent {
            let _ = tokio::io::stderr().write_all(b"\n").await;
        }
    });

    let result = rncp_send_file(RncpSendRequest {
        transport_tx: handle.transport_tx.clone(),
        identity,
        dest_hash,
        file_name: &file_name,
        data,
        auto_compress,
        overall_timeout: timeout,
        path_wait,
        progress_tx: Some(progress_tx),
    })
    .await;

    let _ = progress_task.await;

    match result {
        Ok(outcome) => {
            if !args.silent {
                print_send_summary(&outcome, bytes_total);
            }
            process::exit(0);
        }
        Err(RncpError::PathTimeout) => {
            eprintln!("Path not found");
            process::exit(1);
        }
        Err(RncpError::NoIdentity) => {
            eprintln!(
                "Destination's identity is not known — wait for an announce or use rnstatus to verify the destination has been seen."
            );
            process::exit(1);
        }
        Err(RncpError::Timeout(what)) => {
            eprintln!("Timed out waiting for {what}");
            process::exit(1);
        }
        Err(RncpError::ResourceFailed(reason)) => {
            eprintln!(
                "File was not accepted by <{}>: {reason}",
                hex::encode(dest_hash)
            );
            process::exit(1);
        }
        Err(e) => {
            eprintln!("rncp-rs: transfer failed: {e}");
            process::exit(1);
        }
    }
}

fn print_send_summary(outcome: &RncpOutcome, bytes: usize) {
    let elapsed = outcome.duration.as_secs_f64().max(1e-6);
    let throughput_bps = (bytes as f64) * 8.0 / elapsed;
    let (t_value, t_unit) = human_rate(throughput_bps);
    println!(
        "Transferred {} bytes in {:.2}s ({:.2} {})",
        bytes, elapsed, t_value, t_unit
    );
}

fn human_rate(bps: f64) -> (f64, &'static str) {
    if bps >= 1_000_000_000.0 {
        (bps / 1_000_000_000.0, "Gbps")
    } else if bps >= 1_000_000.0 {
        (bps / 1_000_000.0, "Mbps")
    } else if bps >= 1_000.0 {
        (bps / 1_000.0, "kbps")
    } else {
        (bps, "bps")
    }
}

async fn run_listen(args: Args) -> ! {
    // Register before any slow init so an early SIGINT exits cleanly.
    let shutdown = ShutdownSignal::new();
    let _signal_rx = install_signal_handlers(shutdown.clone());
    let save_dir = match args.save.as_deref() {
        Some(p) => {
            let path = expand_tilde(p);
            if !path.exists() {
                eprintln!("Output directory not found");
                process::exit(3);
            }
            if !path.is_dir() {
                eprintln!("Output directory not found");
                process::exit(3);
            }
            // Probe-file write test (no portable W_OK check on all platforms).
            let probe = path.join(".rncp_write_test");
            match std::fs::File::create(&probe) {
                Ok(_) => {
                    let _ = std::fs::remove_file(&probe);
                }
                Err(_) => {
                    eprintln!("Output directory not writable");
                    process::exit(4);
                }
            }
            path
        }
        None => std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
    };

    let allowed: Vec<[u8; 16]> = {
        let mut v = Vec::with_capacity(args.allowed.len());
        for a in &args.allowed {
            match parse_dest_hash(a) {
                Ok(h) => v.push(h),
                Err(e) => {
                    eprintln!("{e}");
                    process::exit(1);
                }
            }
        }
        extend_allowed_from_files(&mut v);
        v
    };
    let allow_all = args.no_auth;
    if allowed.is_empty() && !allow_all && !args.print_identity {
        eprintln!("Warning: No allowed identities configured, rncp will not accept any files!");
    }

    let handle = start_reticulum(args.config.as_deref(), shutdown.clone()).await;
    let paths = StoragePaths::from_config_dir(&handle.config_dir);
    let identity = match load_or_create_identity(args.identity_path.as_deref(), &paths.identity_dir)
    {
        Ok(id) => id,
        Err((code, msg)) => {
            eprintln!("{msg}");
            process::exit(code);
        }
    };
    let announce_identity = identity
        .get_private_key()
        .and_then(|key| Identity::from_private_key(&*key).ok());

    if args.print_identity {
        let dest = match rns_identity::destination::Destination::new(
            Some(&identity),
            rns_identity::destination::Direction::In,
            rns_identity::destination::DestType::Single,
            DEFAULT_RNCP_APP_NAME,
        ) {
            Ok(d) => d,
            Err(e) => {
                eprintln!("Failed to derive destination: {e:?}");
                process::exit(2);
            }
        };
        println!("Identity     : {}", hex::encode(identity.hash));
        println!("Listening on : {}", hex::encode(dest.hash));
        process::exit(0);
    }

    let fetch_jail = args.jail.as_deref().map(expand_tilde);
    if let Some(ref jail) = fetch_jail {
        if !jail.is_dir() {
            eprintln!("Fetch jail directory not found: {}", jail.display());
            process::exit(3);
        }
    }

    let (event_tx, mut event_rx) = tokio::sync::mpsc::channel::<RncpEvent>(64);
    let cfg = RncpListenerConfig {
        identity,
        app_name: default_rncp_app_name().to_string(),
        save_dir,
        allow_all,
        allowed,
        overwrite: args.overwrite,
        allow_fetch: args.allow_fetch,
        fetch_jail,
        fetch_auto_compress: !args.no_compress,
    };
    let listener = match spawn_rncp_listener(handle.transport_tx.clone(), cfg, event_tx).await {
        Ok(h) => h,
        Err(e) => {
            eprintln!("rncp-rs: failed to start listener: {e}");
            process::exit(1);
        }
    };
    let announce_task = spawn_listen_announcer(
        handle.transport_tx.clone(),
        announce_identity,
        listener.destination_hash(),
        args.announce_interval,
    );

    if !args.silent {
        println!(
            "rncp-rs listening on <{}> — waiting for transfers. Ctrl-C to stop.",
            hex::encode(listener.destination_hash())
        );
    }

    loop {
        tokio::select! {
            ev = event_rx.recv() => {
                let Some(ev) = ev else { break };
                match ev {
                    RncpEvent::LinkEstablished { link_id } => {
                        if !args.silent {
                            println!("link established: <{}>", hex::encode(link_id));
                        }
                    }
                    RncpEvent::SenderIdentified { link_id, identity_hash } => {
                        if !args.silent {
                            println!(
                                "sender identified on <{}>: <{}>",
                                hex::encode(link_id),
                                hex::encode(identity_hash)
                            );
                        }
                    }
                    RncpEvent::SenderDenied { link_id, identity_hash } => {
                        eprintln!(
                            "denied sender <{}> on <{}> (not in allow-list)",
                            hex::encode(identity_hash),
                            hex::encode(link_id)
                        );
                    }
                    RncpEvent::Completed { file_name, saved_path, bytes, .. } => {
                        println!(
                            "received \"{file_name}\" ({bytes} bytes) → {}",
                            saved_path.display()
                        );
                    }
                    RncpEvent::WriteFailed { file_name, reason, .. } => {
                        eprintln!("write failed for \"{file_name}\": {reason}");
                    }
                    RncpEvent::FetchServing { link_id, file_name, bytes } => {
                        if !args.silent {
                            println!(
                                "serving fetch \"{file_name}\" ({bytes} bytes) on <{}>",
                                hex::encode(link_id)
                            );
                        }
                    }
                    RncpEvent::FetchDenied { link_id, reason } => {
                        eprintln!(
                            "denied fetch on <{}>: {reason}",
                            hex::encode(link_id)
                        );
                    }
                }
            }
            _ = handle.shutdown.wait() => {
                break;
            }
        }
    }

    if let Some(task) = announce_task {
        task.abort();
        let _ = task.await;
    }
    listener.shutdown().await;

    process::exit(0);
}

fn spawn_listen_announcer(
    transport_tx: tokio::sync::mpsc::Sender<TransportMessage>,
    identity: Option<Identity>,
    destination_hash: [u8; 16],
    interval_seconds: i64,
) -> Option<tokio::task::JoinHandle<()>> {
    if interval_seconds < 0 {
        return None;
    }
    let Some(identity) = identity else {
        tracing::warn!("rncp-rs: listener identity has no private key; announce disabled");
        return None;
    };

    Some(tokio::spawn(async move {
        let mut destination = match Destination::new(
            Some(&identity),
            Direction::In,
            DestType::Single,
            default_rncp_app_name(),
        ) {
            Ok(destination) => destination,
            Err(e) => {
                tracing::warn!(error = ?e, "rncp-rs: could not build announce destination");
                return;
            }
        };

        loop {
            send_rncp_announce(&transport_tx, &mut destination, &identity, destination_hash).await;
            if interval_seconds == 0 {
                break;
            }
            tokio::time::sleep(Duration::from_secs(interval_seconds as u64)).await;
        }
    }))
}

async fn send_rncp_announce(
    transport_tx: &tokio::sync::mpsc::Sender<TransportMessage>,
    destination: &mut Destination,
    identity: &Identity,
    destination_hash: [u8; 16],
) {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0);
    let raw = match destination.announce_packet(identity, None, None, false, None, now) {
        Ok(raw) => raw,
        Err(e) => {
            tracing::warn!(error = %e, "rncp-rs: could not build announce packet");
            return;
        }
    };

    if transport_tx
        .send(TransportMessage::Outbound(OutboundRequest {
            raw: Bytes::from(raw),
            destination_hash,
        }))
        .await
        .is_err()
    {
        tracing::warn!("rncp-rs: transport stopped before announce could be sent");
    }
}

fn extend_allowed_from_files(allowed: &mut Vec<[u8; 16]>) {
    for path in rncp_allowed_identity_file_candidates() {
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        for line in text.lines() {
            let value = line.trim();
            if value.len() != 32 {
                continue;
            }
            if let Ok(hash) = parse_dest_hash(value) {
                allowed.push(hash);
            }
        }
        break;
    }
}

fn rncp_allowed_identity_file_candidates() -> Vec<PathBuf> {
    let mut paths = vec![PathBuf::from("/etc/rncp/allowed_identities")];
    if let Some(home) = std::env::var_os("HOME") {
        let home = PathBuf::from(home);
        paths.push(home.join(".config/rncp/allowed_identities"));
        paths.push(home.join(".rncp/allowed_identities"));
    }
    paths
}

async fn start_reticulum(
    config_dir: Option<&str>,
    shutdown: ShutdownSignal,
) -> rns_runtime::reticulum::ReticulumHandle {
    let is_foreground = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
    match rns_runtime::reticulum::init(config_dir, None, shutdown.clone(), is_foreground).await {
        Ok(h) => h,
        Err(e) => {
            eprintln!("failed to start reticulum: {e}");
            process::exit(1);
        }
    }
}
