//! rncp-rs — file transfer (send, listen, fetch).
//!
//! Modes:
//! * `rncp-rs <file> <destination_hash>` — send
//! * `rncp-rs -l [-s <dir>] [-a <hash>] [-F [-j <jail>]]` — listen (optionally serving fetch)
//! * `rncp-rs -f <destination_hash> <remote_path> [-s <dir>]` — fetch
//!
//! Exit codes follow rncp: 0 success, an answered fetch failure or an
//! interrupt; 1 generic failure; 2 identity unreadable; 3 output dir missing;
//! 4 output dir not writable.
//!
//! The listener accepts pushed files and fetch requests only from identified
//! peers in `-a` or the allowed_identities file, unless `-n` is given. `-F`
//! also leaves push reception enabled. Use `-j <jail>` to constrain fetched
//! paths to a directory under trusted local control; it is not an OS sandbox.

use std::path::PathBuf;
use std::process;
use std::time::Duration;

use bytes::Bytes;
use clap::Parser;
use rns_identity::destination::{DestType, Destination, Direction};
use rns_transport::messages::{OutboundRequest, TransportMessage};
use tokio::io::AsyncWriteExt;

fn expand_tilde(p: &str) -> PathBuf {
    if let Some(rest) = p.strip_prefix("~/")
        && let Some(home) = std::env::var_os("HOME")
    {
        return PathBuf::from(home).join(rest);
    }
    PathBuf::from(p)
}

use rns_identity::identity::Identity;
use rns_runtime::lifecycle::{ShutdownSignal, install_signal_handlers};
use rns_runtime::platform::StoragePaths;
use rns_runtime::reticulum::{InstanceMode, ReticulumHandle, SharedInstanceRpcEndpoint};
use rns_runtime::rncp::{
    DEFAULT_RNCP_APP_NAME, RncpError, RncpEvent, RncpFetchOutcome, RncpFetchRequest,
    RncpListenerConfig, RncpOutcome, RncpSendRequest, default_rncp_app_name, rncp_fetch_file,
    rncp_send_file, spawn_rncp_listener,
};
use rns_runtime::rpc::{RpcRequest, RpcResponse};

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

    /// Allow clients to fetch files from this listener (use -a or -n; -j is recommended).
    /// Pushed-file reception remains enabled.
    #[arg(short = 'F', long)]
    allow_fetch: bool,

    /// Fetch file from remote listener instead of sending. Positional args
    /// become `<destination_hash> <remote_path>`.
    #[arg(short = 'f', long)]
    fetch: bool,

    /// Restrict fetch requests to this path (-l -F only; ignored with -f).
    /// Keep the directory under trusted local control; this is not an OS sandbox.
    #[arg(short = 'j', long, value_name = "path")]
    jail: Option<String>,

    /// Save received files in this directory (listen or fetch mode; default: current directory)
    #[arg(short = 's', long, value_name = "path")]
    save: Option<String>,

    /// Allow overwriting received files instead of adding a numeric postfix
    #[arg(short = 'O', long)]
    overwrite: bool,

    /// Announce interval, 0 to only announce at startup
    #[arg(short = 'b', value_name = "seconds", default_value_t = -1)]
    announce_interval: i64,

    /// Allow this identity (or add in ~/.rncp/allowed_identities). 32 hex chars each.
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

    /// Sender timeout before giving up: the path wait, raised to the medium
    /// path timeout; the transfer itself has no deadline
    #[arg(short = 'w', value_name = "seconds", default_value_t = DEFAULT_TIMEOUT_SECS)]
    timeout: f64,

    /// Request physical-layer rates (currently unsupported; exits with an error).
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
        if let Some(parent) = path.parent()
            && let Err(e) = std::fs::create_dir_all(parent)
        {
            return Err((
                2,
                format!(
                    "Could not create identity directory \"{}\": {e}",
                    parent.display()
                ),
            ));
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

    let level = rns_tools::Utility::Rncp.loglevel(None, args.verbose, args.quiet, false);
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
    let interrupt = ShutdownSignal::new();
    let _signal_rx = install_signal_handlers(interrupt.clone());
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

    let handle = start_interruptible(args.config.as_deref(), &interrupt).await;
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

    let path_timeout = path_timeout(&handle, args.timeout).await;

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
        path_timeout,
        progress_tx: Some(progress_tx),
        shutdown: Some(interrupt.clone()),
    })
    .await;

    let _ = progress_task.await;

    // rncp.py:543-567: every answered request failure exits 0.
    match result {
        Ok(outcome) => {
            if !args.silent {
                print_fetch_summary(&outcome);
            }
            process::exit(0);
        }
        Err(RncpError::Interrupted) => {
            println!();
            process::exit(0);
        }
        Err(RncpError::Denied) => {
            println!(
                "Fetch request failed, fetching the file {path_arg} was not allowed by the remote"
            );
            process::exit(0);
        }
        Err(RncpError::NotFound) => {
            println!("Fetch request failed, the file {path_arg} was not found on the remote");
            process::exit(0);
        }
        Err(RncpError::RemoteError) => {
            println!("Fetch request failed due to an error on the remote system");
            process::exit(0);
        }
        Err(RncpError::RequestFailed) => {
            println!("Fetch request failed due to an unknown error (probably not authorised)");
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
    let interrupt = ShutdownSignal::new();
    let _signal_rx = install_signal_handlers(interrupt.clone());
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

    let file = match std::fs::File::open(&file_path) {
        Ok(f) => f,
        Err(e) => {
            println!("Could not start transfer: {e}");
            process::exit(1);
        }
    };
    let bytes_total = file.metadata().map(|m| m.len() as usize).unwrap_or(0);

    let handle = start_interruptible(args.config.as_deref(), &interrupt).await;

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

    let path_timeout = path_timeout(&handle, args.timeout).await;
    let auto_compress = !args.no_compress;

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
        source: Box::new(file),
        auto_compress,
        path_timeout,
        progress_tx: Some(progress_tx),
        shutdown: Some(interrupt.clone()),
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
        Err(RncpError::Interrupted) => {
            println!();
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

    // rncp.py:118-170: -n skips the allowed_identities file and -a entirely.
    let allow_all = args.no_auth;
    let allowed = if allow_all {
        Vec::new()
    } else {
        match allowed_identities(&args.allowed, &rncp_allowed_identity_file_candidates()) {
            Ok(allowed) => allowed,
            Err(e) => {
                eprintln!("Could not apply allowed identity: {e}");
                process::exit(1);
            }
        }
    };
    if allowed.is_empty() && !allow_all {
        eprintln!("No allowed identities configured, rncp will not accept any files!");
    }

    let fetch_jail = args.jail.as_deref().map(PathBuf::from);

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
        rns_runtime::destination_stamper::load_stored_stamp(&mut destination, &identity);

        loop {
            send_rncp_announce(&transport_tx, &mut destination, &identity, destination_hash).await;
            // rncp.py:86-87, 222-230: -1 and 0 both announce once.
            if interval_seconds <= 0 {
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
    let raw = match rns_runtime::destination_stamper::announce_packet(
        destination,
        identity,
        None,
        None,
        false,
        None,
    )
    .await
    {
        Ok(Some(raw)) => raw,
        Ok(None) => return,
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

/// The `-a` values plus the first existing allowed_identities file, each
/// validated as a 16-byte hex hash (rncp.py:121-167).
fn allowed_identities(cli: &[String], candidates: &[PathBuf]) -> Result<Vec<[u8; 16]>, String> {
    let mut entries: Vec<String> = cli.to_vec();
    if let Some(path) = candidates.iter().find(|p| p.is_file()) {
        match std::fs::read_to_string(path) {
            Ok(text) => {
                let lines: Vec<String> = text
                    .replace('\r', "")
                    .split('\n')
                    .filter(|line| line.chars().count() == 32)
                    .map(str::to_string)
                    .collect();
                tracing::info!(
                    "Loaded {} allowed identit{} from {}",
                    lines.len(),
                    if lines.len() == 1 { "y" } else { "ies" },
                    path.display()
                );
                entries.extend(lines);
            }
            Err(e) => tracing::error!(
                "Error while parsing allowed_identities file. The contained exception was: {e}"
            ),
        }
    }
    entries
        .iter()
        .map(|entry| {
            if entry.chars().count() != 32 {
                return Err("Allowed destination length is invalid, must be 32 hexadecimal characters (16 bytes).".to_string());
            }
            hex::decode(entry)
                .ok()
                .and_then(|bytes| <[u8; 16]>::try_from(bytes.as_slice()).ok())
                .ok_or_else(|| "Invalid destination entered. Check your input.".to_string())
        })
        .collect()
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

/// Start Reticulum for a send or fetch. The runtime gets its own shutdown
/// signal so the transport outlives an interrupt until rncp has closed its
/// link; an interrupt during startup exits 0 as rncp does.
async fn start_interruptible(
    config_dir: Option<&str>,
    interrupt: &ShutdownSignal,
) -> ReticulumHandle {
    tokio::select! {
        biased;
        _ = interrupt.wait() => {
            println!();
            process::exit(0);
        }
        handle = start_reticulum(config_dir, ShutdownSignal::new()) => handle,
    }
}

/// `max(-w, reticulum.get_medium_path_timeout())` (rncp.py:405, 662).
async fn path_timeout(handle: &ReticulumHandle, timeout: f64) -> Duration {
    let medium = medium_path_timeout(handle).await;
    let secs = if timeout.is_finite() {
        timeout.max(medium)
    } else {
        medium
    };
    Duration::try_from_secs_f64(secs.max(0.0)).unwrap_or(Duration::MAX)
}

/// Reticulum.get_medium_path_timeout (Reticulum.py:2011-2029): ask the shared
/// instance, or compute Transport.medium_path_timeout (Transport.py:3550-3553)
/// from the lowest online interface bitrate. 0 when unknown or on error.
async fn medium_path_timeout(handle: &ReticulumHandle) -> f64 {
    if handle.instance_mode == InstanceMode::Client {
        let Some(rpc_key) = handle.config.rpc_key.as_deref() else {
            return 0.0;
        };
        let request = RpcRequest::GetMediumPathTimeout;
        let timeout = Duration::from_secs(5);
        let response = match handle.config.shared_rpc_endpoint(&handle.socket_base) {
            SharedInstanceRpcEndpoint::Tcp(port) => {
                rns_runtime::rpc::connect_and_request(port, rpc_key, &request, timeout).await
            }
            SharedInstanceRpcEndpoint::Unix(path) => {
                rns_runtime::rpc::connect_unix_and_request(&path, rpc_key, &request, timeout).await
            }
        };
        return match response {
            Ok(RpcResponse::FloatResult(Some(v))) if v.is_finite() => v,
            _ => 0.0,
        };
    }
    let lowest = match handle
        .query_transport(rns_transport::messages::TransportQuery::GetInterfaceStats)
        .await
    {
        Some(rns_transport::messages::TransportQueryResponse::InterfaceStats(entries)) => entries
            .iter()
            .filter(|entry| entry.online && entry.bitrate > 0)
            .map(|entry| entry.bitrate)
            .min(),
        _ => None,
    };
    match lowest {
        Some(bitrate) => {
            let bits = (rns_wire::constants::MTU * 8) as f64;
            2.0 * (bits / bitrate.max(rns_runtime::constants::MINIMUM_BITRATE) as f64)
                + rns_wire::constants::DEFAULT_PER_HOP_TIMEOUT
        }
        None => 0.0,
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    const A: &str = "00112233445566778899aabbccddeeff";
    const B: &str = "ffeeddccbbaa99887766554433221100";

    fn scratch(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("rncp-allowed-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn allowed_identities_file_keeps_exact_32_char_lines_from_first_existing_file() {
        let dir = scratch("parse");
        let first = dir.join("first");
        let second = dir.join("second");
        std::fs::write(&first, format!("{A}\r\n {B}\n{B} \nshort\n")).unwrap();
        std::fs::write(&second, format!("{B}\n")).unwrap();
        let candidates = [dir.join("missing"), first, second];
        let parsed = allowed_identities(&[B.to_string()], &candidates).unwrap();
        let mut expected_b = [0u8; 16];
        hex::decode_to_slice(B, &mut expected_b).unwrap();
        let mut expected_a = [0u8; 16];
        hex::decode_to_slice(A, &mut expected_a).unwrap();
        assert_eq!(parsed, vec![expected_b, expected_a]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn allowed_identities_reject_invalid_entries() {
        let dir = scratch("invalid");
        let file = dir.join("allowed");
        std::fs::write(&file, format!("{}\n", "zz".repeat(16))).unwrap();
        assert!(allowed_identities(&[], std::slice::from_ref(&file)).is_err());
        assert!(allowed_identities(&["abcd".into()], &[]).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
