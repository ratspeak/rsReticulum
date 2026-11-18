//! rncp-rs — file transfer (send, listen, fetch).
//!
//! Modes:
//! * `rncp-rs <file> <destination_hash>` — send
//! * `rncp-rs -l [-s <dir>] [-a <hash>] [-F [-j <jail>]]` — listen (optionally serving fetch)
//! * `rncp-rs -f <remote_path> <destination_hash> [-s <dir>]` — fetch
//!
//! Exit codes follow rncp: 0 success, an answered fetch failure or an
//! interrupt; 1 generic failure; 2 identity unreadable; 3 output dir missing;
//! 4 output dir not writable.
//!
//! The listener accepts pushed files and fetch requests only from identified
//! peers in `-a` or the allowed_identities file, unless `-n` is given. `-F`
//! also leaves push reception enabled. Use `-j <jail>` to constrain fetched
//! paths to a directory under trusted local control; it is not an OS sandbox.

use std::collections::VecDeque;
use std::io::Write;
use std::path::PathBuf;
use std::process;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bytes::Bytes;
use clap::Parser;
use rns_identity::destination::{DestType, Destination, Direction};
use rns_transport::messages::{OutboundRequest, TransportMessage};

fn expand_tilde(p: &str) -> PathBuf {
    if let Some(rest) = p
        .strip_prefix('~')
        .and_then(|rest| rest.strip_prefix(std::path::is_separator))
        && let Some(home) = rns_runtime::platform::home_dir()
    {
        return home.join(rest);
    }
    PathBuf::from(p)
}

use rns_identity::identity::Identity;
use rns_runtime::lifecycle::{ShutdownSignal, install_signal_handlers};
use rns_runtime::platform::StoragePaths;
use rns_runtime::reticulum::ReticulumHandle;
use rns_runtime::rncp::{
    DEFAULT_RNCP_APP_NAME, RncpError, RncpEvent, RncpFetchRequest, RncpListenerConfig,
    RncpProgress, RncpSendRequest, default_rncp_app_name, rncp_fetch_file_with_resource_dir,
    rncp_send_file, spawn_rncp_listener_with_resource_dir,
};

const DEFAULT_TIMEOUT_SECS: f64 = 15.0;
use rns_tools::RS_RETICULUM_VERSION;
use rns_tools::format::pretty_hex_rep;

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

    /// Fetch file from remote listener instead of sending
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

    /// Display physical layer transfer rates
    #[arg(short = 'P', long = "phy-rates")]
    phy_rates: bool,

    /// Print version and exit.
    #[arg(long)]
    version: bool,

    /// File to be transferred (the remote path with -f)
    file: Option<String>,

    /// Hexadecimal hash of the receiver
    destination: Option<String>,
}

// rncp.py and :615-624 share this text for send and fetch.
fn parse_dest_hash(hex_str: &str) -> Result<[u8; 16], String> {
    if hex_str.chars().count() != 32 {
        return Err(
            "Allowed destination length is invalid, must be 32 hexadecimal characters (16 bytes)."
                .to_string(),
        );
    }
    let bytes = hex::decode(hex_str)
        .map_err(|_| "Invalid destination entered. Check your input.".to_string())?;
    <[u8; 16]>::try_from(bytes.as_slice())
        .map_err(|_| "Invalid destination entered. Check your input.".to_string())
}

const ERASE: &str = "\x1b[2K\r";
const SYMS: [char; 7] = ['⢄', '⢂', '⢁', '⡁', '⡈', '⡐', '⡠'];

/// rncp.py (`prepare_identity`): `-i` is used as given, and an identity
/// that cannot be saved is still used for this run.
async fn prepare_identity(
    handle: &ReticulumHandle,
    identity_path: Option<&str>,
    default_dir: &std::path::Path,
) -> Identity {
    let path = match identity_path {
        Some(p) => PathBuf::from(p),
        None => default_dir.join("rncp"),
    };
    if path.is_file() {
        match Identity::from_file(&path) {
            Ok(id) => return id,
            Err(_) => {
                tracing::error!(
                    "Could not load identity for rncp. The identity file at \"{}\" may be corrupt or unreadable.",
                    path.display()
                );
                rns_tools::exit(handle, 2).await;
            }
        }
    }
    tracing::info!("No valid saved identity found, creating new...");
    let id = Identity::new();
    if let Err(e) = id.to_file(&path) {
        tracing::error!("Error while saving identity to {}", path.display());
        tracing::info!("The contained exception was: {e}");
    }
    id
}

/// rncp.py (`size_str`).
fn size_str(num: f64, suffix: char) -> String {
    let mut num = if suffix == 'b' { num * 8.0 } else { num };
    for unit in ["", "K", "M", "G", "T", "P", "E", "Z"] {
        if num.abs() < 1000.0 {
            return if unit.is_empty() {
                format!("{num:.0} {unit}{suffix}")
            } else {
                format!("{num:.2} {unit}{suffix}")
            };
        }
        num /= 1000.0;
    }
    format!("{num:.2}Y{suffix}")
}

/// `RNS.prettytime` (RNS/__init__.py) for the float durations rncp prints.
fn prettytime(time: f64) -> String {
    let neg = time < 0.0;
    let mut time = time.abs();
    let days = (time / 86400.0).floor() as u64;
    time %= 86400.0;
    let hours = (time / 3600.0).floor() as u64;
    time %= 3600.0;
    let minutes = (time / 60.0).floor() as u64;
    time %= 60.0;
    // Python round() and Rust's formatter both round the exact binary value.
    let seconds: f64 = format!("{time:.2}").parse().unwrap_or(0.0);
    let mut components = Vec::new();
    if days > 0 {
        components.push(format!("{days}d"));
    }
    if hours > 0 {
        components.push(format!("{hours}h"));
    }
    if minutes > 0 {
        components.push(format!("{minutes}m"));
    }
    if seconds > 0.0 {
        components.push(format!("{}s", python_float(seconds)));
    }
    let mut out = String::new();
    for (i, c) in components.iter().enumerate() {
        if i > 0 {
            out.push_str(if i + 1 < components.len() {
                ", "
            } else {
                " and "
            });
        }
        out.push_str(c);
    }
    if out.is_empty() {
        "0s".into()
    } else if neg {
        format!("-{out}")
    } else {
        out
    }
}

/// Python `str(float)` for the short values rncp prints.
fn python_float(v: f64) -> String {
    if v.fract() == 0.0 {
        format!("{v:.1}")
    } else {
        format!("{v}")
    }
}

/// `str(round(prg * 100.0, 1))` (rncp.py).
fn percent_str(progress: f64) -> String {
    python_float(format!("{:.1}", progress * 100.0).parse().unwrap_or(0.0))
}

/// Resource `total_size`: data plus the 3-byte length and msgpack of
/// `{"name": <basename>}` (Resource.py, rncp.py).
fn resource_total_size(data_size: u64, file_name: &str) -> f64 {
    let meta = rmpv::Value::Map(vec![(
        rmpv::Value::String("name".into()),
        rmpv::Value::Binary(file_name.as_bytes().to_vec()),
    )]);
    let mut packed = Vec::new();
    let _ = rmpv::encode::write_value(&mut packed, &meta);
    (data_size + 3 + packed.len() as u64) as f64
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Tick {
    Off,
    Spin,
    Transfer,
}

struct UiState {
    tick: Tick,
    sym: usize,
    total_size: Option<f64>,
    started: Option<Instant>,
    progress: f64,
    stats: VecDeque<(Instant, f64, f64)>,
    speed: f64,
    /// `-P`: append the physical-layer rate to the progress line.
    phy_rates: bool,
    phy_speed: f64,
}

impl UiState {
    /// rncp.py (`sender_progress`): speed over the last 32 updates.
    fn update(&mut self, progress: f64, phy_got: f64) {
        let now = Instant::now();
        self.started.get_or_insert(now);
        self.progress = progress;
        let got = progress * self.total_size.unwrap_or(0.0);
        self.stats.push_back((now, got, phy_got));
        while self.stats.len() > 32 {
            self.stats.pop_front();
        }
        let (first_at, first_got, first_phy) = self.stats[0];
        let span = now.duration_since(first_at).as_secs_f64();
        if span == 0.0 {
            self.speed = 0.0;
            self.phy_speed = 0.0;
        } else {
            self.speed = (got - first_got) / span;
            // Segment progress restarts per segment, so only a gain moves the rate.
            if phy_got - first_phy > 0.0 {
                self.phy_speed = (phy_got - first_phy) / span;
            }
        }
    }

    fn stat_str(&self, elapsed: Option<f64>) -> String {
        let percent = percent_str(self.progress);
        let Some(total) = self.total_size else {
            return format!("{percent}%");
        };
        let cs = size_str((self.progress * total).trunc(), 'B');
        let ts = size_str(total, 'B');
        let ss = size_str(self.speed, 'b');
        // rncp.py.
        let phy_str = if self.phy_rates {
            format!(" ({}ps at physical layer)", size_str(self.phy_speed, 'b'))
        } else {
            String::new()
        };
        match elapsed {
            Some(dt) => format!(
                "{percent}% - {cs} of {ts} in {} - {ss}ps{phy_str}",
                prettytime(dt)
            ),
            None => format!("{percent}% - {cs} of {ts} - {ss}ps{phy_str}"),
        }
    }
}

/// rncp's status lines on stdout: one line per step with `-S`, otherwise
/// erase-and-rewrite lines with a spinner and the progress line.
#[derive(Clone)]
struct Ui {
    silent: bool,
    fetch: bool,
    state: Arc<Mutex<UiState>>,
}

impl Ui {
    fn new(silent: bool, fetch: bool) -> Self {
        let ui = Self {
            silent,
            fetch,
            state: Arc::new(Mutex::new(UiState {
                tick: Tick::Off,
                sym: 0,
                total_size: None,
                started: None,
                progress: 0.0,
                stats: VecDeque::new(),
                speed: 0.0,
                phy_rates: false,
                phy_speed: 0.0,
            })),
        };
        if !silent {
            let ticker = ui.clone();
            tokio::spawn(async move {
                loop {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    ticker.tick();
                }
            });
        }
        ui
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, UiState> {
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn tick(&self) {
        let mut st = self.lock();
        let sym = SYMS[st.sym];
        match st.tick {
            Tick::Off => return,
            Tick::Spin => print!("\x08\x08{sym} "),
            Tick::Transfer if self.fetch && st.started.is_none() => {
                print!("{ERASE}Waiting for transfer to start {sym} ")
            }
            Tick::Transfer => {
                let es = if self.fetch { " " } else { "  " };
                print!("{ERASE}Transferring file {sym} {}{es}", st.stat_str(None));
            }
        }
        let _ = std::io::stdout().flush();
        st.sym = (st.sym + 1) % SYMS.len();
    }

    /// Print a step and keep the spinner (or progress) running after it.
    fn step(&self, silent: &str, loud: &str, tick: Tick) {
        let mut st = self.lock();
        if self.silent {
            println!("{silent}");
        } else {
            print!("{loud}");
            let _ = std::io::stdout().flush();
        }
        st.tick = tick;
    }

    /// Print a final line and stop the spinner.
    fn finish(&self, silent: &str, loud: &str) {
        let mut st = self.lock();
        st.tick = Tick::Off;
        if self.silent {
            println!("{silent}");
        } else {
            println!("{loud}");
        }
    }

    /// rncp.py: the erase before the fetch progress, without a line under `-S`.
    fn transfer_started(&self) {
        let mut st = self.lock();
        if !self.silent {
            print!("{ERASE}");
            let _ = std::io::stdout().flush();
        }
        st.tick = Tick::Transfer;
    }

    fn set_total(&self, total: f64) {
        self.lock().total_size = Some(total);
    }

    fn progress(&self, update: RncpProgress) {
        self.lock()
            .update(f64::from(update.progress), update.phy_bytes);
    }

    fn show_phy_rates(&self, on: bool) {
        self.lock().phy_rates = on;
    }
}

#[tokio::main]
pub(crate) async fn main() {
    let args = Args::parse();
    if args.version {
        println!(
            "{}",
            rns_tools::version_line("rncp-rs", RS_RETICULUM_VERSION, &[])
        );
        return;
    }

    let level = rns_tools::Utility::Rncp.loglevel(None, args.verbose, args.quiet, false);
    let config_dir = rns_runtime::platform::resolve_config_dir(args.config.as_deref());
    rns_tools::init_tracing(
        level,
        rns_tools::config_log_timestamps(&config_dir),
        true,
        std::io::stderr,
    );

    // rncp.py.
    let positionals = args.file.is_some() && args.destination.is_some();
    if args.listen || args.print_identity {
        run_listen(args).await;
    } else if args.fetch && positionals {
        run_fetch(args).await;
    } else if !args.fetch && positionals {
        run_send(args).await;
    } else {
        println!();
        let mut cmd = <Args as clap::CommandFactory>::command();
        cmd.print_help().ok();
        println!();
        process::exit(0);
    }
}

/// rncp.py / :640-676: request a path unless one is known, wait
/// `max(-w, medium path timeout)` for it, and return the time left for the
/// link, which rncp waits for until the later of that deadline and the link
/// establishment timeout.
async fn wait_for_path(
    handle: &ReticulumHandle,
    dest_hash: [u8; 16],
    timeout: f64,
    ui: &Ui,
    interrupt: &ShutdownSignal,
    link_tail: &str,
) -> Duration {
    let deadline = Instant::now() + path_timeout(handle, timeout).await;
    let h = pretty_hex_rep(&dest_hash);
    let has_path = || async { rns_tools::has_local_path(handle, dest_hash).await };
    if !has_path().await {
        let _ = handle
            .transport_tx
            .send(TransportMessage::RequestPath {
                destination_hash: dest_hash,
            })
            .await;
        ui.step(
            &format!("Path to {h} requested"),
            &format!("Path to {h} requested   "),
            Tick::Spin,
        );
        while !has_path().await && Instant::now() < deadline {
            tokio::select! {
                _ = tokio::time::sleep(Duration::from_millis(100)) => {}
                _ = interrupt.wait() => {
                    println!();
                    rns_tools::exit(handle, 0).await;
                }
            }
        }
    }
    if !has_path().await {
        ui.finish("Path not found", &format!("{ERASE}Path not found"));
        rns_tools::exit(handle, 1).await;
    }
    ui.step(
        &format!("Establishing link with {h}"),
        &format!("{ERASE}Establishing link with {h}{link_tail} "),
        Tick::Spin,
    );
    deadline.saturating_duration_since(Instant::now())
}

async fn run_fetch(args: Args) -> ! {
    // Register before any slow init so an early SIGINT exits cleanly.
    let interrupt = ShutdownSignal::new();
    let _signal_rx = install_signal_handlers(interrupt.clone());
    let (Some(path_arg), Some(dest_arg)) = (args.file.as_ref(), args.destination.as_ref()) else {
        process::exit(0);
    };

    // rncp.py: the save directory is checked before the hash.
    let save_dir = match args.save.as_deref() {
        Some(p) => {
            let path = expand_tilde(p);
            if !path.is_dir() {
                tracing::error!("Output directory not found");
                process::exit(3);
            }
            let probe = path.join(".rncp_write_test");
            match std::fs::File::create(&probe) {
                Ok(_) => {
                    let _ = std::fs::remove_file(&probe);
                }
                Err(_) => {
                    tracing::error!("Output directory not writable");
                    process::exit(4);
                }
            }
            path
        }
        None => std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
    };

    let dest_hash = match parse_dest_hash(dest_arg) {
        Ok(h) => h,
        Err(e) => {
            println!("{e}");
            process::exit(1);
        }
    };

    let handle = start_interruptible(args.config.as_deref(), &interrupt).await;
    handle.wants_destination_type(DEFAULT_RNCP_APP_NAME).await;
    let paths = StoragePaths::from_config_dir(&handle.config_dir);
    let identity =
        prepare_identity(&handle, args.identity_path.as_deref(), &paths.identity_dir).await;

    let ui = Ui::new(args.silent, true);
    ui.show_phy_rates(args.phy_rates);
    let h = pretty_hex_rep(&dest_hash);
    let link_wait = wait_for_path(&handle, dest_hash, args.timeout, &ui, &interrupt, "  ").await;

    // The request goes out once the link is up; it is shown when the first
    // answer or Resource progress arrives.
    let requesting = Arc::new(std::sync::Once::new());
    let show_requesting = {
        let ui = ui.clone();
        let requesting = requesting.clone();
        move || {
            requesting.call_once(|| {
                ui.step(
                    "Requesting file from remote...",
                    &format!("{ERASE}Requesting file from remote   "),
                    Tick::Spin,
                )
            })
        }
    };

    let (progress_tx, mut progress_rx) = tokio::sync::mpsc::channel::<RncpProgress>(32);
    let progress_task = {
        let ui = ui.clone();
        let show_requesting = show_requesting.clone();
        tokio::spawn(async move {
            let mut first = true;
            while let Some(p) = progress_rx.recv().await {
                if first {
                    first = false;
                    show_requesting();
                    ui.transfer_started();
                }
                ui.progress(p);
            }
        })
    };

    let result = rncp_fetch_file_with_resource_dir(
        RncpFetchRequest {
            transport_tx: handle.transport_tx.clone(),
            identity,
            dest_hash,
            remote_path: path_arg,
            save_dir: &save_dir,
            overwrite: args.overwrite,
            path_timeout: link_wait,
            progress_tx: Some(progress_tx),
            shutdown: Some(interrupt.clone()),
        },
        &paths.resource_dir,
    )
    .await;

    let _ = progress_task.await;

    let fail = |line: &str| ui.finish(line, &format!("{ERASE}{line}"));
    let transfer_failed = |preface: &str| {
        println!("{preface}");
        fail("The transfer failed");
    };

    // rncp.py: every answered request failure exits 0.
    match result {
        Err(RncpError::Interrupted) => {
            println!();
            rns_tools::exit(&handle, 0).await;
        }
        Err(
            RncpError::PathTimeout
            | RncpError::NoIdentity
            | RncpError::Timeout(_)
            | RncpError::HandshakeFailed(_)
            | RncpError::ProofInvalid(_)
            | RncpError::RequestDispatch(_),
        ) => {
            fail(&format!("Could not establish link with {h}"));
            rns_tools::exit(&handle, 1).await;
        }
        _ => {}
    }
    show_requesting();
    let code = match result {
        Ok(outcome) => {
            let total = resource_total_size(outcome.bytes as u64, &outcome.file_name);
            let line = {
                let mut st = ui.lock();
                st.tick = Tick::Off;
                st.total_size = Some(total);
                st.progress = 1.0;
                let started = st
                    .started
                    .unwrap_or_else(|| Instant::now() - outcome.duration);
                let dt = started.elapsed().as_secs_f64();
                st.speed = if dt > 0.0 { total / dt } else { 0.0 };
                st.stat_str(Some(dt))
            };
            if args.silent {
                println!("{path_arg} fetched from {h}");
            } else {
                print!("{ERASE}Transfer complete  {line} ");
                println!("\n{path_arg} fetched from {h}");
            }
            0
        }
        Err(RncpError::Denied) => {
            fail(&format!(
                "Fetch request failed, fetching the file {path_arg} was not allowed by the remote"
            ));
            0
        }
        Err(RncpError::NotFound) => {
            fail(&format!(
                "Fetch request failed, the file {path_arg} was not found on the remote"
            ));
            0
        }
        Err(RncpError::RemoteError) => {
            fail("Fetch request failed due to an error on the remote system");
            0
        }
        Err(RncpError::RequestFailed) => {
            fail("Fetch request failed due to an unknown error (probably not authorised)");
            0
        }
        Err(RncpError::ResourceFailed(reason)) if reason == "invalid data received" => {
            transfer_failed("Invalid data received, ignoring resource");
            1
        }
        Err(RncpError::ResourceFailed(_)) => {
            transfer_failed("Resource failed");
            1
        }
        Err(RncpError::Io(e)) => {
            transfer_failed(&format!(
                "An error occurred while saving received resource: {e}"
            ));
            1
        }
        Err(e) => {
            tracing::debug!("Fetch failed: {e}");
            fail("The transfer failed");
            1
        }
    };
    rns_tools::exit(&handle, code).await;
}

async fn run_send(args: Args) -> ! {
    // Register before any slow init so an early SIGINT exits cleanly.
    let interrupt = ShutdownSignal::new();
    let _signal_rx = install_signal_handlers(interrupt.clone());
    let (Some(file_arg), Some(dest_arg)) = (args.file.as_ref(), args.destination.as_ref()) else {
        process::exit(0);
    };

    let dest_hash = match parse_dest_hash(dest_arg) {
        Ok(h) => h,
        Err(e) => {
            println!("{e}");
            process::exit(1);
        }
    };

    let file_path = expand_tilde(file_arg);
    if !file_path.is_file() {
        println!("File not found");
        process::exit(1);
    }

    let file_name = file_path
        .file_name()
        .and_then(|s| s.to_str())
        .map(|s| s.to_string())
        .unwrap_or_else(|| "file".to_string());

    print!("{ERASE}");
    let _ = std::io::stdout().flush();

    let handle = start_interruptible(args.config.as_deref(), &interrupt).await;
    handle.wants_destination_type(DEFAULT_RNCP_APP_NAME).await;
    let paths = StoragePaths::from_config_dir(&handle.config_dir);
    let identity =
        prepare_identity(&handle, args.identity_path.as_deref(), &paths.identity_dir).await;

    let ui = Ui::new(args.silent, false);
    ui.show_phy_rates(args.phy_rates);
    let h = pretty_hex_rep(&dest_hash);
    let link_wait = wait_for_path(&handle, dest_hash, args.timeout, &ui, &interrupt, " ").await;

    let file = match std::fs::File::open(&file_path) {
        Ok(f) => f,
        Err(e) => {
            ui.finish(
                &format!("Could not start transfer: {e}"),
                &format!("Could not start transfer: {e}"),
            );
            rns_tools::exit(&handle, 1).await;
        }
    };
    let data_size = file.metadata().map(|m| m.len()).unwrap_or(0);
    ui.set_total(resource_total_size(data_size, &file_name));

    // The first update follows the advertisement; the next one follows the
    // receiver's first part request, which is where rncp starts transferring.
    let transferring = Arc::new(AtomicBool::new(false));
    let show_transferring = {
        let ui = ui.clone();
        let transferring = transferring.clone();
        move || {
            if !transferring.swap(true, Ordering::SeqCst) {
                ui.step(
                    "Transferring file...",
                    &format!("{ERASE}Transferring file   "),
                    Tick::Transfer,
                );
            }
        }
    };
    let (progress_tx, mut progress_rx) = tokio::sync::mpsc::channel::<RncpProgress>(32);
    let progress_task = {
        let ui = ui.clone();
        let show_transferring = show_transferring.clone();
        tokio::spawn(async move {
            let mut updates = 0usize;
            while let Some(p) = progress_rx.recv().await {
                match updates {
                    0 => ui.step(
                        "Advertising file resource...",
                        &format!("{ERASE}Advertising file resource   "),
                        Tick::Spin,
                    ),
                    1 => show_transferring(),
                    _ => {}
                }
                updates += 1;
                ui.progress(p);
            }
        })
    };

    let result = rncp_send_file(RncpSendRequest {
        transport_tx: handle.transport_tx.clone(),
        identity,
        dest_hash,
        file_name: &file_name,
        source: Box::new(file),
        auto_compress: !args.no_compress,
        path_timeout: link_wait,
        progress_tx: Some(progress_tx),
        shutdown: Some(interrupt.clone()),
    })
    .await;

    let _ = progress_task.await;

    let fail = |line: &str| ui.finish(line, &format!("{ERASE}{line}"));

    match result {
        Ok(_) => {
            show_transferring();
            let line = {
                let mut st = ui.lock();
                st.tick = Tick::Off;
                st.progress = 1.0;
                // The send's final line drops the physical rate once the resource is done (rncp.py).
                st.phy_rates = false;
                let total = st.total_size.unwrap_or(0.0);
                let dt = st.started.map(|t| t.elapsed().as_secs_f64()).unwrap_or(0.0);
                st.speed = if dt > 0.0 { total / dt } else { 0.0 };
                st.stat_str(None)
            };
            let path = file_path.display();
            if args.silent {
                println!("{path} copied to {h}");
            } else {
                print!("{ERASE}Transfer complete  {line}  ");
                println!("\n{path} copied to {h}");
            }
            rns_tools::exit(&handle, 0).await;
        }
        Err(RncpError::Interrupted) => {
            println!();
            rns_tools::exit(&handle, 0).await;
        }
        Err(RncpError::PathTimeout | RncpError::NoIdentity) => {
            fail(&format!("No path found to {h}"));
        }
        Err(
            RncpError::Timeout(_)
            | RncpError::HandshakeFailed(_)
            | RncpError::ProofInvalid(_)
            | RncpError::RequestDispatch(_),
        ) => fail(&format!("Link establishment with {h} timed out")),
        Err(RncpError::ResourceCreate(e)) => fail(&format!("Could not start transfer: {e}")),
        Err(e) if !transferring.load(Ordering::SeqCst) => {
            tracing::debug!("Transfer failed: {e}");
            fail(&format!("File was not accepted by {h}"));
        }
        Err(e) => {
            tracing::debug!("Transfer failed: {e}");
            fail("The transfer failed");
        }
    }
    rns_tools::exit(&handle, 1).await;
}

async fn run_listen(args: Args) -> ! {
    // Register before any slow init so an early SIGINT exits cleanly.
    let shutdown = ShutdownSignal::new();
    let _signal_rx = install_signal_handlers(shutdown.clone());
    let handle = start_reticulum(args.config.as_deref(), shutdown.clone()).await;

    let fetch_jail = args.jail.as_deref().map(|jail| {
        let jail = expand_tilde(jail);
        tracing::debug!(
            "Restricting fetch requests to paths under \"{}\"",
            jail.display()
        );
        jail
    });

    let save_dir = match args.save.as_deref() {
        Some(p) => {
            let path = expand_tilde(p);
            if !path.is_dir() {
                tracing::error!("Output directory not found");
                process::exit(3);
            }
            // Probe-file write test (no portable W_OK check on all platforms).
            let probe = path.join(".rncp_write_test");
            match std::fs::File::create(&probe) {
                Ok(_) => {
                    let _ = std::fs::remove_file(&probe);
                }
                Err(_) => {
                    tracing::error!("Output directory not writable");
                    process::exit(4);
                }
            }
            tracing::debug!("Saving received files in \"{}\"", path.display());
            path
        }
        None => std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
    };

    let paths = StoragePaths::from_config_dir(&handle.config_dir);
    let identity =
        prepare_identity(&handle, args.identity_path.as_deref(), &paths.identity_dir).await;
    let announce_identity = identity
        .get_private_key()
        .and_then(|key| Identity::from_private_key(&*key).ok());

    if args.print_identity {
        let dest = match Destination::new(
            Some(&identity),
            Direction::In,
            DestType::Single,
            DEFAULT_RNCP_APP_NAME,
        ) {
            Ok(d) => d,
            Err(e) => {
                eprintln!("Failed to derive destination: {e:?}");
                process::exit(2);
            }
        };
        println!("Identity     : {}", pretty_hex_rep(&identity.hash));
        println!("Listening on : {}", pretty_hex_rep(&dest.hash));
        process::exit(0);
    }

    // rncp.py: -n skips the allowed_identities file and -a entirely.
    let allow_all = args.no_auth;
    let allowed = if allow_all {
        Vec::new()
    } else {
        match allowed_identities(&args.allowed, &rncp_allowed_identity_file_candidates()) {
            Ok(allowed) => allowed,
            Err(e) => {
                tracing::error!("Could not apply allowed identity: {e}");
                process::exit(1);
            }
        }
    };
    if allowed.is_empty() && !allow_all {
        tracing::warn!("No allowed identities configured, rncp will not accept any files!");
    }
    if args.allow_fetch && allow_all {
        tracing::warn!("Allowing unauthenticated fetch requests");
    }

    let (event_tx, mut event_rx) = tokio::sync::mpsc::channel::<RncpEvent>(64);
    let cfg = RncpListenerConfig {
        identity,
        app_name: default_rncp_app_name().to_string(),
        save_dir,
        allow_all,
        allowed: allowed.clone(),
        overwrite: args.overwrite,
        allow_fetch: args.allow_fetch,
        fetch_jail,
        fetch_auto_compress: !args.no_compress,
    };
    let listener = match spawn_rncp_listener_with_resource_dir(
        handle.transport_tx.clone(),
        cfg,
        event_tx,
        &paths.resource_dir,
    )
    .await
    {
        Ok(h) => h,
        Err(e) => {
            tracing::error!("rncp-rs: failed to start listener: {e}");
            process::exit(1);
        }
    };
    let announce_task = spawn_listen_announcer(
        handle.transport_tx.clone(),
        announce_identity,
        listener.destination_hash(),
        args.announce_interval,
    );

    tracing::info!(
        "rncp listening on {}",
        pretty_hex_rep(&listener.destination_hash())
    );

    loop {
        tokio::select! {
            ev = event_rx.recv() => {
                let Some(ev) = ev else { break };
                match ev {
                    RncpEvent::LinkEstablished { .. } => {
                        tracing::debug!("Incoming link established");
                    }
                    RncpEvent::SenderIdentified { identity_hash, .. } => {
                        if allowed.contains(&identity_hash) {
                            tracing::debug!("Authenticated sender");
                        }
                    }
                    RncpEvent::SenderDenied { .. } => {
                        tracing::debug!("Sender not allowed, tearing down link");
                    }
                    RncpEvent::Completed { saved_path, .. } => {
                        rns_transport::notice!("Saved received file to {}", saved_path.display());
                    }
                    RncpEvent::WriteFailed { reason, .. } => {
                        tracing::error!("An error occurred while saving received resource: {reason}");
                    }
                    RncpEvent::FetchServing { file_name, .. } => {
                        tracing::debug!("Sending file {file_name} to client");
                    }
                    RncpEvent::FetchDenied { reason, .. } => {
                        tracing::warn!("Disallowing fetch request: {reason}");
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

    rns_tools::exit(&handle, 0).await;
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
            // rncp.py: -1 and 0 both announce once.
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
/// validated as a 16-byte hex hash (rncp.py).
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
                tracing::debug!(
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
    if let Some(home) = rns_runtime::platform::home_dir() {
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

/// `max(-w, reticulum.get_medium_path_timeout())` (rncp.py).
async fn path_timeout(handle: &ReticulumHandle, timeout: f64) -> Duration {
    let medium = rns_tools::medium_path_timeout(handle).await;
    let secs = if timeout.is_finite() {
        timeout.max(medium)
    } else {
        medium
    };
    Duration::try_from_secs_f64(secs.max(0.0)).unwrap_or(Duration::MAX)
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

    const PROGRESS_VECTORS: &str =
        include_str!("../../tests/fixtures/rncp_progress/rncp_progress.tsv");

    #[test]
    fn progress_fields_match_upstream_size_str_prettytime_and_percent() {
        let mut checked = 0;
        for line in PROGRESS_VECTORS.lines().filter(|l| !l.starts_with('#')) {
            let row: Vec<&str> = line.split('\t').collect();
            let input: f64 = row[1].parse().unwrap();
            let got = match row[0] {
                "size" => size_str(input, row[2].chars().next().unwrap()),
                "time" => prettytime(input),
                "percent" => percent_str(input),
                other => panic!("unknown vector kind {other}"),
            };
            assert_eq!(got, row[3], "{line}");
            checked += 1;
        }
        assert!(checked > 30);
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
