//! rnstatus-rs — interface status viewer, following `RNS/Utilities/rnstatus.py`.
//!
//! Local: attach to the shared instance as a client and read its stats over
//! the RPC control port. Remote (`-R <hash> -i <identity>`): request
//! `/status` from `rnstransport.remote.management` over a link. Both render
//! the same upstream stats dictionary.

use std::collections::HashSet;
use std::fmt::Write as _;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::Duration;

use clap::Parser;
use rmpv::Value;

use rns_identity::destination::Destination;
use rns_identity::identity::Identity;
use rns_runtime::lifecycle::ShutdownSignal;
use rns_runtime::link_client::{LinkClient, LinkClientError, RequestFailure};
use rns_runtime::link_session::{
    LinkSession, LinkSessionCloseReason, LinkSessionError, LinkSessionEvent, RequestOptions,
};
use rns_runtime::platform::{StoragePaths, resolve_config_dir};
use rns_runtime::prelude::CloseReason;
use rns_runtime::reticulum::{
    InitOptions, InstanceMode, LinkConnectError, LinkConnectOptions, ReticulumConfig,
    ReticulumHandle, SharedInstanceRpcEndpoint, init_with_options,
};
use rns_runtime::rpc::{self, ManageOperation, RpcRequest};
use rns_tools::RS_RETICULUM_VERSION;
use rns_tools::format::{
    PyNum as Num, pretty_cost, prettyfrequency, prettyshorttime, prettysize, prettyspeed,
    prettytime, py_float_repr, py_round,
};
use rns_transport::constants::PATH_REQUEST_TIMEOUT;
use rns_transport::discovery::{DiscoveredInterface, DiscoveryStatus, DiscoveryStore};
use rns_transport::messages::PathRequestOptions;

const LOCAL_RPC_TIMEOUT: Duration = Duration::from_secs(10);
/// Budget for link establishment and the request once a remote path is known.
const REMOTE_LINK_TIMEOUT: Duration = Duration::from_secs(30);
const REMOTE_HOPS: u8 = 8;
const MGMT_APP: &str = "rnstransport.remote.management";
/// rnstatus.py.
const CLR: &str = "\r                                                          \r";

#[derive(Parser)]
#[command(
    name = "rnstatus-rs",
    about = "Reticulum Network Stack Status",
    disable_version_flag = true
)]
struct Args {
    /// Path to alternative Reticulum config directory.
    #[arg(short = 'c', long)]
    config: Option<String>,

    /// Print version and exit.
    #[arg(long)]
    version: bool,

    /// Attach interface by name.
    #[arg(long, value_name = "name")]
    attach: Option<String>,

    /// Detach interface by name.
    #[arg(long, value_name = "name")]
    detach: Option<String>,

    /// Reload interface by name.
    #[arg(long, value_name = "name")]
    reload: Option<String>,

    /// Show all interfaces.
    #[arg(short, long)]
    all: bool,

    /// Show announce stats.
    #[arg(short = 'A', long)]
    announce_stats: bool,

    /// Show path request stats.
    #[arg(short = 'P', long = "pr-stats")]
    pr_stats: bool,

    /// Show link stats.
    #[arg(short, long)]
    link_stats: bool,

    /// Only show interfaces with active bursts.
    #[arg(short = 'B', long)]
    burst: bool,

    /// Show blocked IPs per interface.
    #[arg(short = 'b', long)]
    blocked_ips: bool,

    /// Display traffic totals.
    #[arg(short, long)]
    totals: bool,

    /// Display packets per second in totals.
    #[arg(short = 'p', long)]
    pps: bool,

    /// Display queue stats.
    #[arg(short = 'q', long)]
    queues: bool,

    /// Display live profiling results.
    #[arg(short = 'z', long)]
    profiling: bool,

    /// Sort interfaces by [rate, traffic, rx, tx, rxs, txs, anns, arx, atx, arxc, atxc, held,
    /// prx, ptx, prxc, ptxc, pvs, ivs, flt, txdrp, txdrb, txbuf].
    #[arg(short, long)]
    sort: Option<String>,

    /// Reverse sorting.
    #[arg(short, long)]
    reverse: bool,

    /// Output in JSON format.
    #[arg(short, long)]
    json: bool,

    /// Transport identity hash of remote instance to get status from.
    #[arg(short = 'R', long = "remote", value_name = "hash")]
    remote: Option<String>,

    /// Path to identity used for remote management.
    #[arg(short = 'i', long = "identity", value_name = "path")]
    identity: Option<PathBuf>,

    /// Timeout before giving up on remote queries.
    #[arg(short = 'w', long = "timeout", value_name = "seconds", default_value_t = PATH_REQUEST_TIMEOUT)]
    timeout: f64,

    /// List discovered interfaces.
    #[arg(short = 'd', long)]
    discovered: bool,

    /// Show details and config entries for discovered interfaces.
    #[arg(short = 'D')]
    discovered_details: bool,

    /// Show stale discovery entries.
    #[arg(long)]
    show_stale: bool,

    /// Show discovery entries without version info.
    #[arg(long)]
    show_unknown: bool,

    /// Continuously monitor status.
    #[arg(short = 'm', long)]
    monitor: bool,

    /// Refresh interval for monitor mode (default: 1).
    #[arg(
        short = 'I',
        long = "monitor-interval",
        value_name = "seconds",
        default_value_t = 1.0
    )]
    monitor_interval: f64,

    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,

    /// Only display interfaces with names including filter.
    filter: Option<String>,
}

/// Rust-only spellings kept for existing scripts (upstream has `--config`,
/// `-R`, `-i` and `-w` only).
const DEPRECATED_SPELLINGS: &[(&str, &str)] = &[
    ("-c", "--config"),
    ("--remote", "-R"),
    ("--identity", "-i"),
    ("--timeout", "-w"),
];

fn warn_deprecated_spellings() {
    for arg in std::env::args().skip(1) {
        if arg == "--" {
            break;
        }
        for (old, new) in DEPRECATED_SPELLINGS {
            if arg == *old || arg.starts_with(&format!("{old}=")) {
                eprintln!("rnstatus-rs: warning: {old} is deprecated, use {new}");
            }
        }
    }
}

/// Output of one run. Direct output is written out at each progress point;
/// monitor mode buffers a whole frame, as rnstatus.py does.
struct Out {
    buf: String,
    direct: bool,
}

impl Out {
    fn new(direct: bool) -> Self {
        Self {
            buf: String::new(),
            direct,
        }
    }

    fn flush_now(&mut self) {
        if self.direct {
            write_stdout(&self.buf);
            self.buf.clear();
        }
    }
}

impl std::fmt::Write for Out {
    fn write_str(&mut self, s: &str) -> std::fmt::Result {
        self.buf.push_str(s);
        Ok(())
    }
}

fn write_stdout(s: &str) {
    let mut stdout = std::io::stdout().lock();
    let _ = stdout.write_all(s.as_bytes());
    let _ = stdout.flush();
}

macro_rules! outln {
    ($o:expr) => {
        $o.buf.push('\n')
    };
    ($o:expr, $($t:tt)*) => {{
        let _ = writeln!($o, $($t)*);
    }};
}

macro_rules! outp {
    ($o:expr, $($t:tt)*) => {{
        let _ = write!($o, $($t)*);
    }};
}

/// How a status run ends. `Hard` exits even in monitor mode, where upstream
/// calls `exit()` regardless of `must_exit`.
enum Flow {
    Done(u8),
    Hard(u8),
}

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
pub(crate) async fn main() -> ExitCode {
    let args = Args::parse();
    if args.version {
        println!(
            "{}",
            rns_tools::version_line("rnstatus-rs", RS_RETICULUM_VERSION, &[])
        );
        return ExitCode::SUCCESS;
    }
    warn_deprecated_spellings();

    let level = rns_tools::Utility::Rnstatus.loglevel(None, args.verbose, 0, false);
    let config_dir = resolve_config_dir(args.config.as_deref());
    rns_tools::init_tracing(
        level,
        rns_tools::config_log_timestamps(&config_dir),
        true,
        std::io::stdout,
    );

    let session = match Session::open(&args).await {
        Ok(session) => session,
        Err(code) => return ExitCode::from(code),
    };
    let code = if args.monitor {
        run_monitor(&args, &session).await
    } else {
        let mut out = Out::new(true);
        let flow = session.status(&args, &mut out).await;
        out.flush_now();
        match flow {
            Flow::Done(code) | Flow::Hard(code) => code,
        }
    };
    session.close().await;
    ExitCode::from(code)
}

/// rnstatus.py: one instance across refreshes; each frame is
/// rendered into a buffer, then printed after `ESC[H ESC[2J`.
async fn run_monitor(args: &Args, session: &Session) -> u8 {
    let interrupt = ShutdownSignal::new();
    let _signal_rx = rns_runtime::lifecycle::install_signal_handlers(interrupt.clone());
    loop {
        let started = std::time::Instant::now();
        let mut out = Out::new(false);
        if let Flow::Hard(code) = session.status(args, &mut out).await {
            return code;
        }
        write_stdout(&format!("\x1b[H\x1b[2J{}", out.buf));
        tokio::select! {
            _ = tokio::time::sleep(monitor_sleep(args.monitor_interval, started.elapsed())) => {}
            _ = interrupt.wait() => {}
        }
        // rnstatus.py: KeyboardInterrupt prints an empty line.
        if interrupt.is_triggered() {
            write_stdout("\n");
            return 0;
        }
    }
}

/// rnstatus.py: sleep `max(interval - render time, 0.2)`.
fn monitor_sleep(interval_secs: f64, elapsed: Duration) -> Duration {
    Duration::from_secs_f64((interval_secs - elapsed.as_secs_f64()).max(0.2))
}

/// The Reticulum instance rnstatus runs with: a shared-instance client for
/// local queries, as `RNS.Reticulum(require_shared_instance=True)`, or any
/// instance for `-R` (rnstatus.py).
struct Session {
    handle: ReticulumHandle,
    rpc_key: Vec<u8>,
    first_remote_request: std::sync::atomic::AtomicBool,
    /// Monitor mode's remote link, reused while it stays up (rnstatus.py).
    remote_link: tokio::sync::Mutex<Option<RemoteLink>>,
}

struct RemoteLink {
    session: LinkSession,
    closed: tokio::sync::watch::Receiver<Option<LinkSessionCloseReason>>,
}

/// How a remote `/status` query ended without a response.
enum RemoteFailure {
    /// The request failed; carries the link-closed line printed before it.
    Unanswered(Option<&'static str>),
    LinkTimeout,
    LinkLost,
}

impl Session {
    async fn open(args: &Args) -> Result<Self, u8> {
        let mut options = InitOptions::default();
        options.require_shared_instance = args.remote.is_none();
        let handle = match init_with_options(
            args.config.as_deref(),
            None,
            ShutdownSignal::new(),
            Arc::new(AtomicBool::new(true)),
            options,
        )
        .await
        {
            Ok(handle) => handle,
            Err(_) => {
                println!("No shared RNS instance available to get status from");
                return Err(1);
            }
        };
        handle.wants_destination_type(MGMT_APP).await;
        let rpc_key = local_rpc_key(&handle.config_dir, &handle.config);
        Ok(Self {
            handle,
            rpc_key,
            first_remote_request: AtomicBool::new(true),
            remote_link: tokio::sync::Mutex::new(None),
        })
    }

    async fn close(self) {
        if let Some(link) = self.remote_link.lock().await.take() {
            link.session.handle.close().await;
        }
        rns_tools::shut_down(&self.handle).await;
    }

    fn is_client(&self) -> bool {
        self.handle.instance_mode == InstanceMode::Client
    }

    /// One shared-instance RPC call, answered as the raw upstream value.
    async fn rpc(&self, request: &RpcRequest) -> Result<Value, String> {
        if !self.is_client() {
            return Err("not connected to a shared instance".to_string());
        }
        let endpoint = self
            .handle
            .config
            .shared_rpc_endpoint(&self.handle.socket_base);
        let bytes = match &endpoint {
            SharedInstanceRpcEndpoint::Tcp(port) => {
                rpc::connect_and_request_bytes(*port, &self.rpc_key, request, LOCAL_RPC_TIMEOUT)
                    .await
            }
            SharedInstanceRpcEndpoint::Unix(path) => {
                rpc::connect_unix_and_request_bytes(path, &self.rpc_key, request, LOCAL_RPC_TIMEOUT)
                    .await
            }
        }
        .map_err(|e| e.to_string())?;
        rmpv::decode::read_value(&mut bytes.as_slice()).map_err(|e| e.to_string())
    }

    /// `program_setup` (rnstatus.py).
    async fn status(&self, args: &Args, out: &mut Out) -> Flow {
        for (name, operation) in [
            (&args.attach, ManageOperation::Attach),
            (&args.detach, ManageOperation::Detach),
            (&args.reload, ManageOperation::Reload),
        ] {
            if let Some(name) = name {
                return Flow::Hard(self.manage(operation, name, out).await);
            }
        }

        if args.discovered || args.discovered_details {
            return Flow::Done(self.discovered(args, out).await);
        }

        let mut link_count = None;
        let mut active_link_count = None;
        let mut profiling_results = None;
        let stats;
        let mut remote_hash = None;
        if let Some(remote) = args.remote.as_deref() {
            let (hash, identity) = match remote_inputs(remote, args.identity.as_deref()) {
                Ok(inputs) => inputs,
                Err(message) => {
                    outln!(out, "{message}");
                    return Flow::Hard(20).soft_in_monitor(args);
                }
            };
            remote_hash = Some(hash);
            match self.remote_status(args, hash, identity, out).await {
                Ok(Some((s, l, p))) => {
                    stats = Some(s);
                    link_count = l;
                    profiling_results = p;
                }
                Ok(None) => stats = None,
                Err(code) => return Flow::Hard(code),
            }
        } else {
            if args.link_stats {
                link_count = self.rpc(&RpcRequest::GetLinkCount).await.ok();
                active_link_count = self.rpc(&RpcRequest::GetActiveLinkCount).await.ok();
            }
            if args.profiling {
                profiling_results = self.rpc(&RpcRequest::GetProfilingResults).await.ok();
            }
            stats = match self.rpc(&RpcRequest::GetInterfaceStats).await {
                Ok(value) if !value.is_nil() => Some(value),
                Ok(_) => None,
                Err(e) => {
                    tracing::error!(
                        "Shared instance RPC failed while getting interface stats: {e}"
                    );
                    None
                }
            };
        }

        match stats {
            Some(mut stats) => {
                render_status(
                    out,
                    &mut stats,
                    link_count.as_ref(),
                    active_link_count.as_ref(),
                    profiling_results.as_ref(),
                    args,
                );
                Flow::Done(0)
            }
            None => {
                match remote_hash {
                    None => outln!(out, "Could not get RNS status"),
                    Some(hash) => outln!(
                        out,
                        "Could not get RNS status from remote transport instance {}",
                        pretty_hex(&hash)
                    ),
                }
                Flow::Done(2)
            }
        }
    }

    /// `--attach/--detach/--reload` (rnstatus.py).
    async fn manage(&self, operation: ManageOperation, name: &str, out: &mut Out) -> u8 {
        let (verb, done, doing) = match operation {
            ManageOperation::Attach => ("attach", "attached", "attaching"),
            ManageOperation::Detach => ("detach", "detached", "detaching"),
            ManageOperation::Reload => ("reload", "reloaded", "reloading"),
        };
        let request = RpcRequest::ManageInterface {
            operation,
            name: name.to_string(),
        };
        let result = self.rpc(&request).await;
        let ok = matches!(&result, Ok(v) if py_eq_bool(v, true));
        match &result {
            Ok(v) if py_eq_bool(v, true) => outln!(out, "Interface {name} was {done}"),
            Ok(v) if py_eq_bool(v, false) => outln!(out, "Could not {verb} interface {name}"),
            Ok(Value::Nil) => outln!(out, "The interface {name} does not exist"),
            _ => outln!(out, "Unknown error while {doing} interface {name}"),
        }
        if ok { 0 } else { 1 }
    }
}

impl Flow {
    /// Input errors exit only outside monitor mode (`must_exit`).
    fn soft_in_monitor(self, args: &Args) -> Flow {
        match self {
            Flow::Hard(code) if args.monitor => Flow::Done(code),
            other => other,
        }
    }
}

fn local_rpc_key(config_dir: &Path, rc: &ReticulumConfig) -> Vec<u8> {
    if let Some(key) = rc.rpc_key.as_ref() {
        return key.clone();
    }
    let path = StoragePaths::from_config_dir(config_dir)
        .storage_dir
        .join("transport_identity");
    let identity = Identity::from_file(&path).unwrap_or_else(|_| Identity::new());
    match identity.get_private_key() {
        Some(key) => rpc::derive_rpc_key(&*key).to_vec(),
        None => Vec::new(),
    }
}

/// rnstatus.py: the remote hash and management identity, or the
/// message upstream prints before exiting 20.
fn remote_inputs(remote: &str, identity: Option<&Path>) -> Result<([u8; 16], Identity), String> {
    let Some(identity_path) = identity else {
        return Err("Remote management requires an identity file. Use -i to specify the path to a management identity.".to_string());
    };
    if remote.chars().count() != 32 {
        return Err(
            "Destination length is invalid, must be 32 hexadecimal characters (16 bytes)."
                .to_string(),
        );
    }
    let hash: [u8; 16] = hex::decode(remote)
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| "Invalid destination entered. Check your input.".to_string())?;
    let path = expand_user(identity_path);
    match Identity::from_file(&path) {
        Ok(identity) => Ok((hash, identity)),
        Err(e) => {
            tracing::error!("Error while loading identity from {}", path.display());
            tracing::error!("The contained exception was: {e}");
            Err(format!(
                "Could not load management identity from {}",
                identity_path.display()
            ))
        }
    }
}

/// Python `os.path.expanduser` for a leading `~`.
fn expand_user(path: &Path) -> PathBuf {
    let text = path.to_string_lossy();
    match (text.strip_prefix('~'), std::env::var_os("HOME")) {
        (Some(rest), Some(home)) if rest.is_empty() || rest.starts_with('/') => {
            PathBuf::from(format!("{}{rest}", PathBuf::from(home).display()))
        }
        _ => path.to_path_buf(),
    }
}

impl Session {
    /// rnstatus.py `get_remote_status`: wait for a path, then ask
    /// `/status` over a link. `Err` carries an exit code.
    async fn remote_status(
        &self,
        args: &Args,
        identity_hash: [u8; 16],
        identity: Identity,
        out: &mut Out,
    ) -> Result<Option<(Value, Option<Value>, Option<Value>)>, u8> {
        let no_output = args.json;
        let destination = Destination::hash_from_name_and_identity(MGMT_APP, Some(&identity_hash));
        if !self.handle.has_path(destination).await.unwrap_or(false) {
            if !no_output {
                outp!(out, "Path to {} requested ", pretty_hex(&destination));
                out.flush_now();
            }
            let _ = self
                .handle
                .request_path(destination, PathRequestOptions::default())
                .await;
            let started = std::time::Instant::now();
            while !self.handle.has_path(destination).await.unwrap_or(false) {
                tokio::time::sleep(Duration::from_millis(100)).await;
                if started.elapsed().as_secs_f64() > args.timeout {
                    if !no_output {
                        outp!(out, "{CLR}");
                        outln!(out, "Path request timed out");
                    }
                    return Err(12);
                }
            }
        }

        let first = self
            .first_remote_request
            .swap(false, std::sync::atomic::Ordering::SeqCst);
        if first && !no_output {
            outp!(out, "{CLR}");
            outp!(out, "Establishing link with remote transport instance... ");
            out.flush_now();
        }
        // The first request asks for profiling too; refreshes send only the
        // link-count flag (rnstatus.py).
        let request = if first {
            Value::Array(vec![
                Value::Boolean(args.link_stats),
                Value::Boolean(args.profiling),
            ])
        } else {
            Value::Array(vec![Value::Boolean(args.link_stats)])
        };
        let answer = if args.monitor {
            self.monitor_query(identity_hash, identity, request).await
        } else {
            one_shot_query(&self.handle, identity_hash, identity, &request).await
        };
        let bytes = match answer {
            Ok(bytes) => bytes,
            // No response to the identified request, or the link closed while
            // it was pending. Upstream's link-closed callback prints its line but
            // its exit() runs off the main thread, so the request failure follows.
            Err(RemoteFailure::Unanswered(closed_text)) => {
                if !no_output {
                    if first {
                        outp!(out, "{CLR}Sending request... ");
                    }
                    if let Some(text) = closed_text {
                        outp!(out, "{CLR}");
                        outln!(out, "{text}");
                    }
                    outp!(out, "{CLR}");
                    outln!(
                        out,
                        "The remote status request failed. Likely authentication failure."
                    );
                }
                return Ok(None);
            }
            Err(RemoteFailure::LinkTimeout) => {
                if !no_output {
                    outp!(out, "{CLR}");
                    outln!(out, "The link timed out, exiting now");
                }
                return Err(10);
            }
            Err(RemoteFailure::LinkLost) => {
                if !no_output {
                    outp!(out, "{CLR}");
                    outln!(out, "Link closed unexpectedly, exiting now");
                }
                return Err(10);
            }
        };
        if first && !no_output {
            outp!(out, "{CLR}");
            outp!(out, "Sending request... ");
        }
        let result = match rmpv::decode::read_value(&mut bytes.as_slice()) {
            Ok(Value::Array(items)) if !items.is_empty() => {
                let mut items = items.into_iter();
                let status = items.next().unwrap_or(Value::Nil);
                Some((status, items.next(), items.next()))
            }
            _ => None,
        };
        if result.is_some() {
            outp!(out, "{CLR}");
        }
        Ok(result)
    }

    /// `-d`/`-D` (rnstatus.py).
    async fn discovered(&self, args: &Args, out: &mut Out) -> u8 {
        let paths = StoragePaths::from_config_dir(&self.handle.config_dir);
        let store = match DiscoveryStore::open(&paths.storage_dir) {
            Ok(store) => store,
            Err(e) => {
                eprintln!("rnstatus-rs: could not open discovery store: {e}");
                return 1;
            }
        };
        let sources = &self.handle.config.interface_discovery_sources;
        let sources = (!sources.is_empty()).then_some(sources.as_slice());
        let blackholed: HashSet<[u8; 16]> =
            match self.rpc(&RpcRequest::GetBlackholedIdentities).await {
                Ok(Value::Map(entries)) => entries
                    .iter()
                    .filter_map(|(k, _)| k.as_slice().and_then(|b| b.try_into().ok()))
                    .collect(),
                _ => HashSet::new(),
            };
        let records = match store.list_filtered(sources, &blackholed) {
            Ok(records) => records,
            Err(e) => {
                eprintln!("rnstatus-rs: could not read discovered interfaces: {e}");
                return 1;
            }
        };
        let raw: Vec<Value> = records
            .iter()
            .map(|record| stored_info(store.root(), record))
            .collect();
        outln!(out);

        if args.json {
            outln!(out, "{}", py_json(&Value::Array(raw)));
            return 0;
        }

        let mut filtered = Vec::new();
        let mut stored = Vec::new();
        for (record, info) in records.iter().zip(&raw) {
            let matches = args.filter.as_deref().is_none_or(|needle| {
                record
                    .info
                    .name
                    .to_lowercase()
                    .contains(&needle.to_lowercase())
            });
            if matches {
                filtered.push(record);
                stored.push(info);
            }
        }
        if args.discovered_details {
            print_discovered_details(out, &filtered, &stored, args.show_stale, args.show_unknown);
        } else {
            print_discovered_summary(out, &filtered, args.show_stale, args.show_unknown);
        }
        0
    }
}

/// One `/status` request on a fresh link, torn down afterwards.
async fn one_shot_query(
    handle: &ReticulumHandle,
    identity_hash: [u8; 16],
    identity: Identity,
    request: &Value,
) -> Result<Vec<u8>, RemoteFailure> {
    let mut payload = Vec::new();
    let _ = rmpv::encode::write_value(&mut payload, request);
    let client = LinkClient::new(handle.transport_tx.clone(), identity);
    client
        .query(
            identity_hash,
            MGMT_APP,
            "/status",
            payload,
            REMOTE_HOPS,
            REMOTE_LINK_TIMEOUT,
        )
        .await
        .map_err(|e| match e {
            LinkClientError::RequestFailed(RequestFailure::LinkClosed(reason)) => {
                RemoteFailure::Unanswered(rns_tools::link_closed_text(reason))
            }
            LinkClientError::RequestFailed(RequestFailure::TimedOut) => {
                RemoteFailure::Unanswered(None)
            }
            LinkClientError::Timeout(_) => RemoteFailure::LinkTimeout,
            e => {
                tracing::debug!("remote status query failed: {e}");
                RemoteFailure::LinkLost
            }
        })
}

impl Session {
    /// Monitor mode: request on the remote link while it is active, else open
    /// a new one (rnstatus.py).
    async fn monitor_query(
        &self,
        identity_hash: [u8; 16],
        identity: Identity,
        request: Value,
    ) -> Result<Vec<u8>, RemoteFailure> {
        let mut cached = self.remote_link.lock().await;
        if cached
            .as_ref()
            .is_some_and(|link| link.closed.borrow().is_some())
        {
            *cached = None;
        }
        if cached.is_none() {
            *cached = Some(self.open_remote_link(identity_hash, identity).await?);
        }
        let link = cached.as_mut().expect("opened above");
        let result = link
            .session
            .handle
            .request_with_options("/status", request, RequestOptions::default())
            .await;
        match result {
            Ok(response) => {
                let mut bytes = Vec::new();
                let _ = rmpv::encode::write_value(&mut bytes, &response.value);
                Ok(bytes)
            }
            Err(LinkSessionError::Timeout(_)) => Err(RemoteFailure::Unanswered(None)),
            Err(_) => {
                // The session reports its close reason just after failing the request.
                let mut closed = link.closed.clone();
                let reason =
                    tokio::time::timeout(Duration::from_secs(1), closed.wait_for(Option::is_some))
                        .await
                        .ok()
                        .and_then(|r| r.ok().and_then(|reason| *reason));
                *cached = None;
                let reason = match reason {
                    Some(LinkSessionCloseReason::Local) => Some(CloseReason::InitiatorClosed),
                    Some(LinkSessionCloseReason::Remote) => Some(CloseReason::DestinationClosed),
                    Some(LinkSessionCloseReason::Timeout) => Some(CloseReason::Timeout),
                    _ => None,
                };
                Err(RemoteFailure::Unanswered(rns_tools::link_closed_text(
                    reason,
                )))
            }
        }
    }

    async fn open_remote_link(
        &self,
        identity_hash: [u8; 16],
        identity: Identity,
    ) -> Result<RemoteLink, RemoteFailure> {
        let destination = Destination::hash_from_name_and_identity(MGMT_APP, Some(&identity_hash));
        let options = LinkConnectOptions {
            client_label: "rnstatus".to_string(),
            identify: true,
            ..LinkConnectOptions::default()
        };
        let connected = tokio::time::timeout(
            REMOTE_LINK_TIMEOUT,
            self.handle.connect_link(destination, identity, options),
        )
        .await;
        let mut session = match connected {
            Ok(Ok(session)) => session,
            Err(_) | Ok(Err(LinkConnectError::Session(LinkSessionError::Timeout(_)))) => {
                return Err(RemoteFailure::LinkTimeout);
            }
            Ok(Err(e)) => {
                tracing::debug!("remote link failed: {e}");
                return Err(RemoteFailure::LinkLost);
            }
        };
        let (closed_tx, closed) = tokio::sync::watch::channel(None);
        let mut events = std::mem::replace(&mut session.events, tokio::sync::mpsc::channel(1).1);
        tokio::spawn(async move {
            while let Some(event) = events.recv().await {
                if let LinkSessionEvent::Closed { reason } = event {
                    closed_tx.send_replace(Some(reason));
                }
            }
        });
        Ok(RemoteLink { session, closed })
    }
}

/// The stored info dictionary as `list_discovered_interfaces` returns it:
/// the file's keys in order, the name sanitized, `"None"` IFAC values
/// dropped, and the status appended (Discovery.py).
fn stored_info(root: &Path, record: &DiscoveredInterface) -> Value {
    let mut map = std::fs::read(root.join(record.filename()))
        .ok()
        .and_then(|bytes| rmpv::decode::read_value(&mut bytes.as_slice()).ok())
        .and_then(|value| match value {
            Value::Map(map) => Some(map),
            _ => None,
        })
        .unwrap_or_default();
    map.retain(|(k, v)| {
        !(matches!(k.as_str(), Some("ifac_netname" | "ifac_netkey")) && v.as_str() == Some("None"))
    });
    let status = record.status.unwrap_or(DiscoveryStatus::Unknown);
    set_key(&mut map, "name", Value::from(record.info.name.as_str()));
    set_key(&mut map, "status", Value::from(status.as_str()));
    set_key(&mut map, "status_code", Value::from(status.code()));
    Value::Map(map)
}

fn set_key(map: &mut Vec<(Value, Value)>, key: &str, value: Value) {
    match map.iter_mut().find(|(k, _)| k.as_str() == Some(key)) {
        Some(entry) => entry.1 = value,
        None => map.push((Value::from(key), value)),
    }
}

// ---------------------------------------------------------------------------
// The stats renderer: rnstatus.py.

const HIDDEN_PREFIXES: &[&str] = &[
    "LocalInterface[",
    "TCPInterface[Client",
    "BackboneInterface[Client on",
    "AutoInterfacePeer[",
    "WeaveInterfacePeer[",
    "I2PInterfacePeer[Connected peer",
];

/// Python's sort keys (rnstatus.py); an unknown key sorts nothing.
fn sort_key(name: &str) -> Option<fn(&Value) -> f64> {
    fn k(i: &Value, key: &str) -> f64 {
        num(get(i, key)).f()
    }
    Some(match name {
        "rate" | "bitrate" => |i| k(i, "bitrate"),
        "rx" => |i| k(i, "rxb"),
        "tx" => |i| k(i, "txb"),
        "rxs" => |i| k(i, "rxs"),
        "txs" => |i| k(i, "txs"),
        "traffic" => |i| k(i, "rxb") + k(i, "txb"),
        "anns" | "announces" => {
            |i| k(i, "incoming_announce_frequency") + k(i, "outgoing_announce_frequency")
        }
        "arx" => |i| k(i, "incoming_announce_frequency"),
        "atx" => |i| k(i, "outgoing_announce_frequency"),
        "arxc" => |i| k(i, "arxc"),
        "atxc" => |i| k(i, "atxc"),
        "prx" => |i| k(i, "incoming_pr_frequency"),
        "ptx" => |i| k(i, "outgoing_pr_frequency"),
        "prxc" => |i| k(i, "prxc"),
        "ptxc" => |i| k(i, "ptxc"),
        "held" => |i| k(i, "held_announces"),
        "pvs" => |i| k(i, "protocol_violations"),
        "ivs" => |i| k(i, "ifac_violations"),
        "flt" => |i| k(i, "packet_filter_hits"),
        "gravity" | "g" => |i| k(i, "gravity"),
        "txdrp" => |i| k(i, "txdrp"),
        "txdrb" => |i| k(i, "txdrb"),
        "txbuf" => |i| k(i, "txbuffered"),
        _ => return None,
    })
}

fn mode_name(mode: Option<&Value>) -> &'static str {
    let m = num(mode).f();
    if m.fract() != 0.0 {
        return "Full";
    }
    match m as i64 {
        3 => "Access Point",
        2 => "Point-to-Point",
        4 => "Roaming",
        5 => "Boundary",
        6 => "Gateway",
        7 => "Internal",
        _ => "Full",
    }
}

fn render_status(
    out: &mut Out,
    stats: &mut Value,
    link_count: Option<&Value>,
    active_link_count: Option<&Value>,
    profiling_results: Option<&Value>,
    args: &Args,
) {
    if args.json {
        outln!(out, "{}", py_json(stats));
        return;
    }
    let astats = args.announce_stats;
    let pstats = args.pr_stats;

    let mut interfaces: Vec<Value> = match get(stats, "interfaces") {
        Some(Value::Array(list)) => list.clone(),
        _ => Vec::new(),
    };
    if let Some(key) = args
        .sort
        .as_deref()
        .and_then(|s| sort_key(&s.to_lowercase()))
    {
        // Stable, like list.sort(reverse=...): equal keys keep their order.
        interfaces.sort_by(|a, b| {
            let ord = key(a)
                .partial_cmp(&key(b))
                .unwrap_or(std::cmp::Ordering::Equal);
            if args.reverse { ord } else { ord.reverse() }
        });
    }

    for ifstat in &interfaces {
        let name = py_str_opt(get(ifstat, "name"));
        let i2p_hidden = name.starts_with("I2PInterface[")
            && get(ifstat, "i2p_connectable").is_some_and(|v| py_eq_bool(v, false));
        let hidden = HIDDEN_PREFIXES.iter().any(|p| name.starts_with(p)) || i2p_hidden;
        if i2p_hidden || (hidden && !args.all) {
            continue;
        }
        let show_if = if !args.burst {
            args.filter
                .as_deref()
                .is_none_or(|f| name.to_lowercase().contains(&f.to_lowercase()))
        } else {
            let burst_act = has(ifstat, "burst_active")
                && has(ifstat, "pr_burst_active")
                && (truthy(get(ifstat, "burst_active")) || truthy(get(ifstat, "pr_burst_active")));
            let nfilt = args
                .filter
                .as_deref()
                .is_some_and(|f| name.to_lowercase().contains(&f.to_lowercase()));
            burst_act || nfilt
        };
        if show_if {
            render_interface(out, ifstat, &name, args);
        }
    }

    let mut lstr = String::new();
    if let Some(lc) = link_count.filter(|v| !v.is_nil())
        && args.link_stats
    {
        let ms = if num(Some(lc)).f() == 1.0 { "y" } else { "ies" };
        let lc = py_str(lc);
        lstr = if not_none(stats, "transport_id").is_some() {
            format!(", {lc} entr{ms} in link table")
        } else {
            format!(" {lc} entr{ms} in link table")
        };
        if let Some(alc) = active_link_count.filter(|v| truthy(Some(v))) {
            lstr = format!("{lstr} ({} active)", py_str(alc));
        }
    }

    if args.totals {
        render_totals(out, stats, astats, pstats, args.pps);
    }
    if args.queues {
        render_queues(out, stats);
    }
    if let Some(results) = profiling_results.filter(|v| truthy(Some(v))) {
        outln!(out, "\n Profiling    :\n{}", format_profiling(results));
    }

    if let Some(tid) = not_none(stats, "transport_id") {
        outln!(
            out,
            "\n Transport Instance {} running",
            pretty_hex_value(tid)
        );
        if let Some(v) = not_none(stats, "network_id") {
            outln!(out, " Network Identity   {}", pretty_hex_value(v));
        }
        if let Some(v) = not_none(stats, "probe_responder") {
            outln!(out, " Probe responder at {} active", pretty_hex_value(v));
        }
        if let Some(v) = not_none(stats, "transport_uptime") {
            outln!(out, " Uptime is {}{lstr}", prettytime(num(Some(v)), false));
        }
    } else if !lstr.is_empty() {
        outln!(out, "\n{lstr}");
    }
    outln!(out);
}

/// One interface block (rnstatus.py).
fn render_interface(out: &mut Out, ifstat: &Value, name: &str, args: &Args) {
    let astats = args.announce_stats;
    let pstats = args.pr_stats;
    outln!(out);

    let mut ss = if truthy(get(ifstat, "status")) {
        "Up".to_string()
    } else {
        "Down".to_string()
    };
    if let Some(g) = get(ifstat, "gravity").filter(|v| truthy(Some(v))) {
        ss = format!("{ss}, gravity {}", py_str(g));
    }
    let mut modestr = mode_name(get(ifstat, "mode")).to_string();
    if truthy(get(ifstat, "announces_to_internal")) {
        modestr.push_str(" (a>i)");
    }

    let mut clients = not_none(ifstat, "clients").map(|v| num(Some(v)));
    let mut clients_string = String::new();
    if let Some(c) = clients {
        if name.starts_with("Shared Instance[") {
            let cnum = Num::Int((c.i() - 1).max(0));
            let spec = if cnum.f() == 1.0 {
                " program"
            } else {
                " programs"
            };
            clients_string = format!("Serving   : {}{spec}", cnum.py_str());
        } else if name.starts_with("I2PInterface[") {
            if get(ifstat, "i2p_connectable").is_some_and(|v| py_eq_bool(v, true)) {
                let spec = if c.f() == 1.0 {
                    " connected I2P endpoint"
                } else {
                    " connected I2P endpoints"
                };
                clients_string = format!("Peers     : {}{spec}", c.py_str());
            }
        } else {
            clients_string = format!("Clients   : {}", c.py_str());
            if let Some(b) = get(ifstat, "blocked_ips")
                && num(Some(b)).f() > 0.0
            {
                // Upstream's conditional covers the whole suffix, so one IP reads "IPs".
                clients_string.push_str(&format!("\n    Blocked   : {} IPs", py_str(b)));
            }
        }
        if args.blocked_ips
            && let Some(Value::Array(list)) = get(ifstat, "blocked_ip_list")
        {
            for bip in list {
                clients_string.push_str(&format!("\n                {}", py_str(bip)));
            }
        }
    }

    outln!(out, " {name}");
    if let Some(v) = not_none(ifstat, "autoconnect_source") {
        outln!(out, "    Source    : Auto-connect via <{}>", py_str(v));
    }
    if let Some(v) = not_none(ifstat, "ifac_netname") {
        outln!(out, "    Network   : {}", py_str(v));
    }
    outln!(out, "    Status    : {ss}");
    if clients.is_some() && !clients_string.is_empty() {
        outln!(out, "    {clients_string}");
    }
    if !(name.starts_with("Shared Instance[")
        || name.starts_with("TCPInterface[Client")
        || name.starts_with("LocalInterface["))
    {
        outln!(out, "    Mode      : {modestr}");
    }
    if truthy(get(ifstat, "txdrp")) {
        outln!(
            out,
            "    TX Drops  : {} ({})",
            py_str_opt(get(ifstat, "txdrp")),
            prettysize(num(get(ifstat, "txdrb")).f(), "B")
        );
    }
    if let Some(bitrate) = not_none(ifstat, "bitrate") {
        outln!(
            out,
            "    Rate      : {}, MTU {}",
            speed_str(num(Some(bitrate)).f()),
            py_str_opt(get(ifstat, "mtu"))
        );
    }

    render_radio_lines(out, ifstat);

    if astats
        && let Some(q) = not_none(ifstat, "announce_queue")
        && num(Some(q)).f() > 0.0
    {
        let s = if num(Some(q)).f() == 1.0 { "" } else { "s" };
        outln!(out, "    Queued    : {} announce{s}", py_str(q));
    }
    if astats
        && let Some(h) = not_none(ifstat, "held_announces")
        && num(Some(h)).f() > 0.0
    {
        let s = if num(Some(h)).f() == 1.0 { "" } else { "s" };
        outln!(out, "    Held      : {} announce{s}", py_str(h));
    }

    let (art, arp, arg) = if astats {
        (
            get(ifstat, "announce_rate_target"),
            get(ifstat, "announce_rate_penalty"),
            get(ifstat, "announce_rate_grace"),
        )
    } else {
        (None, None, None)
    };
    let arp_set = arp.is_some_and(|v| !v.is_nil());
    let art_str = if truthy(art) && arp_set && truthy(arg) {
        format!(
            "(t:{}/p:{}/g:{})",
            prettytime(num(art), false),
            prettytime(num(arp), false),
            py_str_opt(arg)
        )
    } else if truthy(art) && arp_set {
        format!(
            "(t:{}/p:{})",
            prettytime(num(art), false),
            prettytime(num(arp), false)
        )
    } else if truthy(art) {
        format!("(t:{})", prettytime(num(art), false))
    } else {
        String::new()
    };

    let now = unix_now();
    let mut burst_str = String::new();
    if truthy(get(ifstat, "burst_active")) {
        let bcstr = match get(ifstat, "burst_count").filter(|v| truthy(Some(v))) {
            Some(c) => format!("on {} ", py_str(c)),
            None => String::new(),
        };
        let for_str = prettytime(
            Num::Float(now - num(get(ifstat, "burst_activated")).f()),
            false,
        );
        burst_str = format!(" burst {bcstr}for {for_str}");
    }
    let mut pburst_str = String::new();
    if truthy(get(ifstat, "pr_burst_active")) {
        let bcstr = match get(ifstat, "pr_burst_count").filter(|v| truthy(Some(v))) {
            Some(c) => format!("on {} ", py_str(c)),
            None => String::new(),
        };
        let for_str = prettytime(
            Num::Float(now - num(get(ifstat, "pr_burst_activated")).f()),
            false,
        );
        pburst_str = format!("burst {bcstr}for {for_str}");
    }

    let mut rxb_str = format!("↓{}", prettysize(num(get(ifstat, "rxb")).f(), "B"));
    let mut txb_str = format!("↑{}", prettysize(num(get(ifstat, "txb")).f(), "B"));
    let flow_keys = ["prxs", "rxs", "ptxs", "txs"]
        .iter()
        .all(|k| has(ifstat, k));
    let pct = |part: &str, whole: &str| -> i64 {
        let (p, w) = (get(ifstat, part), get(ifstat, whole));
        if truthy(w) && truthy(p) {
            (100.0f64).min(num(p).f() / num(w).f() * 100.0) as i64
        } else {
            0
        }
    };

    let (mut iaf, mut oaf, mut pc_str) = (String::new(), String::new(), String::new());
    let mut asr = false;
    if astats && not_none(ifstat, "incoming_announce_frequency").is_some() {
        let mut oan = num(get(ifstat, "outgoing_announce_frequency"));
        let ian = num(get(ifstat, "incoming_announce_frequency"));
        if name.starts_with("Shared Instance[")
            && let Some(c) = clients
            && c.f() > 0.0
        {
            oan = Num::Float(oan.f() - oan.f() / c.f());
        }
        oaf = prettyfrequency(oan, "Hz", 1, true);
        iaf = prettyfrequency(ian, "Hz", 1, true);
        let mut cspec = "c";
        if clients.is_none() && truthy(get(ifstat, "peers")) {
            clients = Some(num(get(ifstat, "peers")));
            cspec = "p";
        }
        if let Some(c) = clients.filter(|c| c.f() > 0.0) {
            let per = num(get(ifstat, "outgoing_announce_frequency")).f() / c.f();
            pc_str = format!(
                " {}/{cspec}",
                prettyfrequency(Num::Float(per), "Hz", 1, true)
            );
        }
        if flow_keys {
            let apct = format!(
                "(↓{}% / ↑{}% of flow)",
                pct("arxs", "rxs"),
                pct("atxs", "txs")
            );
            pc_str = if pc_str.is_empty() {
                apct
            } else {
                format!("{pc_str} {apct}")
            };
        }
        asr = true;
    }

    let (mut ipf, mut opf, mut rpc_str) = (String::new(), String::new(), String::new());
    let mut psr = false;
    if pstats && not_none(ifstat, "incoming_pr_frequency").is_some() {
        let mut opn = num(get(ifstat, "outgoing_pr_frequency"));
        let ipn = num(get(ifstat, "incoming_pr_frequency"));
        if name.starts_with("Shared Instance[")
            && let Some(c) = clients
            && c.f() > 0.0
        {
            opn = Num::Float(opn.f() - opn.f() / c.f());
        }
        if astats {
            opf = format!("↑{}", prettyfrequency(opn, "Hz", 1, true));
            ipf = format!("↓{}", prettyfrequency(ipn, "Hz", 1, true));
        } else {
            opf = format!("{}↑", prettyfrequency(opn, "Hz", 1, true));
            ipf = format!("{}↓", prettyfrequency(ipn, "Hz", 1, true));
        }
        let mut cspec = "c";
        if clients.is_none() && truthy(get(ifstat, "peers")) {
            clients = Some(num(get(ifstat, "peers")));
            cspec = "p";
        }
        if let Some(c) = clients.filter(|c| c.f() > 0.0) {
            let per = num(get(ifstat, "outgoing_pr_frequency")).f() / c.f();
            rpc_str = format!(
                " {}/{cspec}",
                prettyfrequency(Num::Float(per), "Hz", 1, true)
            );
        }
        if flow_keys {
            let ppct = format!(
                "(↓{}% / ↑{}% of flow)",
                pct("prxs", "rxs"),
                pct("ptxs", "txs")
            );
            rpc_str = if rpc_str.is_empty() {
                ppct
            } else {
                format!("{rpc_str} {ppct}")
            };
        }
        psr = true;
    }

    if !asr {
        iaf.clear();
        oaf.clear();
    }
    if !psr {
        ipf.clear();
        opf.clear();
    }
    let amlen = clen(&iaf).max(clen(&oaf));
    pad(&mut iaf, amlen);
    iaf.push('↓');
    pad(&mut oaf, amlen);
    oaf.push('↑');
    let mlen = [&iaf, &oaf, &rxb_str, &txb_str, &ipf, &opf]
        .iter()
        .map(|s| clen(s))
        .max()
        .unwrap_or(0)
        .max(10);
    for s in [
        &mut iaf,
        &mut oaf,
        &mut ipf,
        &mut opf,
        &mut rxb_str,
        &mut txb_str,
    ] {
        pad(s, mlen);
    }

    if has(ifstat, "protocol_violations") && has(ifstat, "ifac_violations") {
        let (pv, iv) = (
            get(ifstat, "protocol_violations"),
            get(ifstat, "ifac_violations"),
        );
        if truthy(pv) || truthy(iv) {
            let sep = if truthy(iv) { ", " } else { "" };
            let ivstr = if truthy(iv) {
                format!("{} IFAC", py_str_opt(iv))
            } else {
                String::new()
            };
            outln!(
                out,
                "    Violatns. : {} protocol{sep}{ivstr}",
                py_str_opt(pv)
            );
        }
    }
    if let Some(hits) = get(ifstat, "packet_filter_hits").filter(|v| truthy(Some(v))) {
        outln!(out, "    Flt. Hits : {}", py_str(hits));
    }

    if psr {
        if truthy(get(ifstat, "prxc")) && truthy(get(ifstat, "ptxc")) {
            outln!(
                out,
                "    Path Rqs. : {}↓ {}↑ total",
                py_str_opt(get(ifstat, "prxc")),
                py_str_opt(get(ifstat, "ptxc"))
            );
            outln!(out, "                {opf} {rpc_str}");
        } else {
            outln!(out, "    Path Rqs. : {opf} {rpc_str}");
        }
        outln!(out, "                {ipf}  {pburst_str}");
    }
    if asr {
        if truthy(get(ifstat, "arxc")) && truthy(get(ifstat, "atxc")) {
            outln!(
                out,
                "    Announces : {}↓ {}↑ total",
                py_str_opt(get(ifstat, "arxc")),
                py_str_opt(get(ifstat, "atxc"))
            );
            outln!(out, "                {oaf} {pc_str}");
        } else {
            outln!(out, "    Announces : {oaf} {pc_str}");
        }
        outln!(out, "                {iaf} {art_str}{burst_str}");
    }

    let mut rxstat = rxb_str;
    let mut txstat = txb_str;
    if has(ifstat, "rxs") && has(ifstat, "txs") {
        rxstat.push_str(&format!("  {}", prettyspeed(num(get(ifstat, "rxs")).f())));
        txstat.push_str(&format!("  {}", prettyspeed(num(get(ifstat, "txs")).f())));
    }
    if truthy(get(ifstat, "txbuffered")) {
        let stl = if truthy(get(ifstat, "txstalled")) {
            ", stalled"
        } else {
            ""
        };
        txstat.push_str(&format!(
            " ({} waiting{stl})",
            prettysize(num(get(ifstat, "txbuffered")).f(), "B")
        ));
    }
    outln!(out, "    Traffic   : {txstat}\n                {rxstat}");
}

/// The optional radio, Weave and I2P lines (rnstatus.py), with
/// upstream's labels as printed.
fn render_radio_lines(out: &mut Out, ifstat: &Value) {
    if has(ifstat, "noise_floor") {
        let nstr = if !has(ifstat, "interference") {
            String::new()
        } else {
            let nf = get(ifstat, "interference");
            let mut lstr = ", no interference".to_string();
            if has(ifstat, "interference_last_ts") && has(ifstat, "interference_last_dbm") {
                let lago = unix_now() - num(get(ifstat, "interference_last_ts")).f();
                lstr = format!(
                    "\n    Intrfrnc. : {} dBm {} ago",
                    py_str_opt(get(ifstat, "interference_last_dbm")),
                    prettytime(Num::Float(lago), true)
                );
            }
            if truthy(nf) {
                format!("\n    Intrfrnc. : {} dBm", py_str_opt(nf))
            } else {
                lstr
            }
        };
        match not_none(ifstat, "noise_floor") {
            Some(v) => outln!(out, "    Noise Fl. : {} dBm{nstr}", py_str(v)),
            None => outln!(out, "    Noise Fl. : Unknown"),
        }
    }
    if has(ifstat, "cpu_load") {
        match not_none(ifstat, "cpu_load") {
            Some(v) => outln!(out, "    CPU load  : {} %", py_str(v)),
            None => outln!(out, "    CPU load  : Unknown"),
        }
    }
    if has(ifstat, "cpu_temp") {
        match not_none(ifstat, "cpu_temp") {
            Some(v) => outln!(out, "    CPU temp  : {}°C", py_str(v)),
            None => outln!(out, "    CPU load  : Unknown"),
        }
    }
    if has(ifstat, "mem_load") {
        // Upstream tests cpu_load here.
        if not_none(ifstat, "cpu_load").is_some() {
            outln!(
                out,
                "    Mem usage : {} %",
                py_str_opt(get(ifstat, "mem_load"))
            );
        } else {
            outln!(out, "    Mem usage : Unknown");
        }
    }
    if let Some(bp) = not_none(ifstat, "battery_percent")
        && let Some(bpi) = py_int(bp)
        && let Some(bss) = get(ifstat, "battery_state")
    {
        outln!(out, "    Battery   : {bpi}% ({})", py_str(bss));
    }
    if has(ifstat, "airtime_short") && has(ifstat, "airtime_long") {
        outln!(
            out,
            "    Airtime   : {}% (15s), {}% (1h)",
            py_str_opt(get(ifstat, "airtime_short")),
            py_str_opt(get(ifstat, "airtime_long"))
        );
    }
    if has(ifstat, "channel_load_short") && has(ifstat, "channel_load_long") {
        outln!(
            out,
            "    Ch. Load  : {}% (15s), {}% (1h)",
            py_str_opt(get(ifstat, "channel_load_short")),
            py_str_opt(get(ifstat, "channel_load_long"))
        );
    }
    for (key, label) in [
        ("switch_id", "Switch ID :"),
        ("endpoint_id", "Endpoint  :"),
        ("via_switch_id", "Via       :"),
    ] {
        if has(ifstat, key) {
            match not_none(ifstat, key) {
                Some(v) => outln!(out, "    {label} {}", py_str(v)),
                None => outln!(out, "    {label} Unknown"),
            }
        }
    }
    if let Some(v) = not_none(ifstat, "peers") {
        outln!(out, "    Peers     : {} reachable", py_str(v));
    }
    if let Some(v) = not_none(ifstat, "tunnelstate") {
        outln!(out, "    I2P       : {}", py_str(v));
    }
    if let Some(sig) = not_none(ifstat, "ifac_signature") {
        let bytes = sig.as_slice().unwrap_or_default();
        let tail = &bytes[bytes.len().saturating_sub(5)..];
        let size = num(get(ifstat, "ifac_size"));
        let nb = match size {
            Num::Int(n) => Num::Int(n * 8),
            Num::Float(f) => Num::Float(f * 8.0),
        };
        outln!(
            out,
            "    Access    : {}-bit IFAC by <…{}>",
            nb.py_str(),
            hex::encode(tail)
        );
    }
    if let Some(v) = not_none(ifstat, "i2p_b32") {
        outln!(out, "    I2P B32   : {}", py_str(v));
    }
}

/// The traffic totals blocks (rnstatus.py).
fn render_totals(out: &mut Out, stats: &Value, astats: bool, pstats: bool, pps: bool) {
    let n = |k: &str| num(get(stats, k)).f();
    let (mut rxb_str, mut txb_str) = pair(n("rxb"), n("txb"));
    let rxs = n("rxs");
    let txs = n("txs");
    let mut rxstat = format!("{rxb_str}  {}", prettyspeed(rxs));
    let mut txstat = format!("{txb_str}  {}", prettyspeed(txs));
    if (pstats || astats)
        && ["prxs", "ptxs", "arxs", "atxs"]
            .iter()
            .all(|k| has(stats, k))
    {
        let parxs = n("prxs") + n("arxs");
        let patxs = n("ptxs") + n("atxs");
        let drxpct = if truthy(get(stats, "rxs")) {
            100.0 - (100.0f64).min(parxs / rxs * 100.0)
        } else {
            100.0
        };
        let dtxpct = if truthy(get(stats, "txs")) {
            100.0 - (100.0f64).min(patxs / txs * 100.0)
        } else {
            100.0
        };
        if rxs > 0.0 {
            rxstat = format!(
                "{rxstat}, {}% data ({})",
                drxpct as i64,
                prettyspeed(rxs * (drxpct / 100.0))
            );
        }
        if txs > 0.0 {
            txstat = format!(
                "{txstat}, {}% data ({})",
                dtxpct as i64,
                prettyspeed(txs * (dtxpct / 100.0))
            );
        }
    }
    if pps {
        rxstat = format!("{rxstat}, {}", prettysize(n("rxpps"), "pps"));
        txstat = format!("{txstat}, {}", prettysize(n("txpps"), "pps"));
    }
    outln!(out, "\n Totals       : {txstat}\n                {rxstat}");

    let flow_pct = |part: &str, whole: &str| -> i64 {
        if truthy(get(stats, whole)) && truthy(get(stats, part)) {
            (100.0f64).min(n(part) / n(whole) * 100.0) as i64
        } else {
            0
        }
    };
    for (enabled, b, label) in [(pstats, 'p', "Path Rqs.   "), (astats, 'a', "Announces   ")] {
        let k = |s: &str| format!("{b}{s}");
        if !enabled
            || !["rxb", "txb", "rxs", "txs"]
                .iter()
                .all(|s| has(stats, &k(s)))
        {
            continue;
        }
        (rxb_str, txb_str) = pair(n(&k("rxb")), n(&k("txb")));
        let rxf = prettyfrequency(num(get(stats, &k("rxf"))), "Hz", 2, false);
        let txf = prettyfrequency(num(get(stats, &k("txf"))), "Hz", 2, false);
        let rx = format!(
            "{rxb_str}  {}, {}% of flow, {rxf}",
            prettyspeed(n(&k("rxs"))),
            flow_pct(&k("rxs"), "rxs")
        );
        let tx = format!(
            "{txb_str}  {}, {}% of flow, {txf}",
            prettyspeed(n(&k("txs"))),
            flow_pct(&k("txs"), "txs")
        );
        outln!(out, "\n {label} : {tx}\n                {rx}");
    }
}

/// `↓rx` and `↑tx` sizes padded to the same width.
fn pair(rx: f64, tx: f64) -> (String, String) {
    let mut rx = format!("↓{}", prettysize(rx, "B"));
    let mut tx = format!("↑{}", prettysize(tx, "B"));
    let width = clen(&rx).max(clen(&tx));
    pad(&mut rx, width);
    pad(&mut tx, width);
    (rx, tx)
}

/// `-q` (rnstatus.py).
fn render_queues(out: &mut Out, stats: &Value) {
    let line = |pressure: &str, count: &str, dropped: &str, label: &str| {
        let d = get(stats, dropped);
        let dstr = if truthy(d) {
            format!(", {} dropped", py_str_opt(d))
        } else {
            String::new()
        };
        let p = py_round(num(get(stats, pressure)).f() * 100.0, 1);
        format!(
            "{}% {label}, {} pkts{dstr}",
            py_float_repr(p),
            py_str_opt(get(stats, count))
        )
    };
    outln!(
        out,
        "\n Qu. Pressure : {}",
        line("tqpressure", "rxqt", "rxqtd", "total")
    );
    outln!(
        out,
        "                {}",
        line("dqpressure", "rxqd", "rxqdd", "data")
    );
    outln!(
        out,
        "                {}",
        line("aqpressure", "rxqa", "rxqad", "announce")
    );
    outln!(
        out,
        "                {}",
        line("pqpressure", "rxqp", "rxqpd", "path request")
    );
    outln!(
        out,
        "                {}",
        line("ilqpressure", "rxqil", "rxqild", "ingress limiter")
    );
}

/// `RNS.Profiler.format_results` (RNS/__init__.py).
fn format_profiling(results: &Value) -> String {
    let tags: Vec<&Value> = match results {
        Value::Map(entries) => entries.iter().map(|(_, v)| v).collect(),
        _ => Vec::new(),
    };
    fn pst(time: Option<&Value>) -> String {
        match time.filter(|v| !v.is_nil()) {
            Some(t) => prettyshorttime(num(Some(t)).f()),
            None => "-----".to_string(),
        }
    }
    fn tag_results(tag: &Value, level: usize) -> String {
        let ind = "  ".repeat(level);
        let stats_all = get(tag, "stats_all");
        let mut s = format!(" {ind}{}\n", py_str_opt(get(tag, "name")));
        let threads = num(stats_all.and_then(|v| get(v, "threads")));
        s += &format!(
            " {ind}  Samples  : {} from {} thread{}\n",
            py_str_opt(stats_all.and_then(|v| get(v, "count"))),
            threads.py_str(),
            if threads.f() > 1.0 { "s" } else { "" }
        );
        let row = |label: &str, stats: &Value| {
            let f = |k: &str| pst(get(stats, k));
            format!(
                " {ind}{label}({:^15} | {:^15} | {:^15} | {:^15} | {:^15} | {:^15})\n",
                f("mean"),
                f("median"),
                f("min"),
                f("max"),
                f("stdev"),
                f("sum")
            )
        };
        if let Some(all) = stats_all.filter(|v| !v.is_nil()) {
            s += &format!(
                " {ind}              {:^15} | {:^15} | {:^15} | {:^15} | {:^15} | {:^15}\n",
                "Mean", "Median", "Min", "Max", "St. dev", "Total"
            );
            s += &row("  Stats    : ", all);
        }
        for (key, label) in [
            ("stats_1m", "   0-1m    : "),
            ("stats_5m", "   1-5m    : "),
            ("stats_30m", "  5-30m    : "),
            ("stats_60m", " 30-60m    : "),
        ] {
            if let Some(v) = not_none(tag, key) {
                s += &row(label, v);
            }
        }
        s
    }
    fn recursive(tag: &Value, tags: &[&Value], level: usize) -> String {
        let mut s = tag_results(tag, level + 1) + "\n";
        for sub in tags {
            if values_eq(get(sub, "super"), get(tag, "name")) {
                s += &recursive(sub, tags, level + 1);
            }
        }
        s
    }
    let mut s = String::new();
    for tag in &tags {
        if not_none(tag, "super").is_none() {
            s += &recursive(tag, &tags, 0);
        }
    }
    s
}

fn values_eq(a: Option<&Value>, b: Option<&Value>) -> bool {
    match (a, b) {
        (Some(a), Some(b)) => a == b,
        (None, None) => true,
        (Some(v), None) | (None, Some(v)) => v.is_nil(),
    }
}

// ---------------------------------------------------------------------------
// Python value semantics over the decoded msgpack.

fn get<'a>(map: &'a Value, key: &str) -> Option<&'a Value> {
    map.as_map()?
        .iter()
        .find(|(k, _)| k.as_str() == Some(key))
        .map(|(_, v)| v)
}

fn has(map: &Value, key: &str) -> bool {
    get(map, key).is_some()
}

/// Present and not None.
fn not_none<'a>(map: &'a Value, key: &str) -> Option<&'a Value> {
    get(map, key).filter(|v| !v.is_nil())
}

fn truthy(value: Option<&Value>) -> bool {
    match value {
        None | Some(Value::Nil) => false,
        Some(Value::Boolean(b)) => *b,
        Some(Value::Integer(i)) => i.as_i64() != Some(0) && i.as_u64() != Some(0),
        Some(Value::F32(f)) => *f != 0.0,
        Some(Value::F64(f)) => *f != 0.0,
        Some(Value::String(s)) => !s.as_bytes().is_empty(),
        Some(Value::Binary(b)) => !b.is_empty(),
        Some(Value::Array(a)) => !a.is_empty(),
        Some(Value::Map(m)) => !m.is_empty(),
        Some(Value::Ext(..)) => true,
    }
}

/// Python `value == True` / `value == False`.
fn py_eq_bool(value: &Value, b: bool) -> bool {
    let want = if b { 1.0 } else { 0.0 };
    match value {
        Value::Boolean(v) => *v == b,
        Value::Integer(_) | Value::F32(_) | Value::F64(_) => num(Some(value)).f() == want,
        _ => false,
    }
}

fn num(value: Option<&Value>) -> Num {
    match value {
        Some(Value::Integer(i)) => i
            .as_i64()
            .map(Num::Int)
            .unwrap_or_else(|| Num::Float(i.as_f64().unwrap_or(0.0))),
        Some(Value::F32(f)) => Num::Float(f64::from(*f)),
        Some(Value::F64(f)) => Num::Float(*f),
        Some(Value::Boolean(b)) => Num::Int(i64::from(*b)),
        _ => Num::Int(0),
    }
}

/// Python `int(value)` for a number or numeric string.
fn py_int(value: &Value) -> Option<i64> {
    match value {
        Value::Integer(_) | Value::F32(_) | Value::F64(_) | Value::Boolean(_) => {
            Some(num(Some(value)).i())
        }
        Value::String(s) => s.as_str()?.trim().parse().ok(),
        _ => None,
    }
}

/// Python `str(value)`.
fn py_str(value: &Value) -> String {
    match value {
        Value::Nil => "None".to_string(),
        Value::Boolean(true) => "True".to_string(),
        Value::Boolean(false) => "False".to_string(),
        Value::Integer(_) | Value::F32(_) | Value::F64(_) => num(Some(value)).py_str(),
        Value::String(s) => s.as_str().unwrap_or_default().to_string(),
        Value::Binary(b) => format!("b'{}'", b.escape_ascii()),
        Value::Array(items) => format!(
            "[{}]",
            items.iter().map(py_repr).collect::<Vec<_>>().join(", ")
        ),
        Value::Map(entries) => format!(
            "{{{}}}",
            entries
                .iter()
                .map(|(k, v)| format!("{}: {}", py_repr(k), py_repr(v)))
                .collect::<Vec<_>>()
                .join(", ")
        ),
        Value::Ext(..) => "None".to_string(),
    }
}

fn py_repr(value: &Value) -> String {
    match value {
        Value::String(s) => format!("'{}'", s.as_str().unwrap_or_default()),
        other => py_str(other),
    }
}

fn py_str_opt(value: Option<&Value>) -> String {
    value.map(py_str).unwrap_or_else(|| "None".to_string())
}

fn pretty_hex(bytes: &[u8]) -> String {
    format!("<{}>", hex::encode(bytes))
}

fn pretty_hex_value(value: &Value) -> String {
    match value {
        Value::Binary(b) => pretty_hex(b),
        Value::String(s) => pretty_hex(s.as_bytes()),
        other => py_str(other),
    }
}

/// Characters, as Python's `len` counts them.
fn clen(s: &str) -> usize {
    s.chars().count()
}

fn pad(s: &mut String, width: usize) {
    let n = width.saturating_sub(clen(s));
    s.extend(std::iter::repeat_n(' ', n));
}

/// `json.dumps` with default separators; bytes are written as hex, which
/// is what rnstatus converts them to before dumping (rnstatus.py).
fn py_json(value: &Value) -> String {
    match value {
        Value::Nil | Value::Ext(..) => "null".to_string(),
        Value::Boolean(b) => b.to_string(),
        Value::Integer(i) => i.to_string(),
        Value::F32(_) | Value::F64(_) => {
            let f = num(Some(value)).f();
            if f.is_nan() {
                "NaN".to_string()
            } else if f.is_infinite() {
                if f > 0.0 { "Infinity" } else { "-Infinity" }.to_string()
            } else {
                py_float_repr(f)
            }
        }
        Value::String(s) => py_json_str(s.as_str().unwrap_or_default()),
        Value::Binary(b) => py_json_str(&hex::encode(b)),
        Value::Array(items) => format!(
            "[{}]",
            items.iter().map(py_json).collect::<Vec<_>>().join(", ")
        ),
        Value::Map(entries) => format!(
            "{{{}}}",
            entries
                .iter()
                .map(|(k, v)| {
                    let key = match k {
                        Value::String(_) => py_json(k),
                        Value::Binary(b) => py_json_str(&hex::encode(b)),
                        other => py_json_str(&py_json(other)),
                    };
                    format!("{key}: {}", py_json(v))
                })
                .collect::<Vec<_>>()
                .join(", ")
        ),
    }
}

/// A `json.dumps` string with the default `ensure_ascii`.
fn py_json_str(s: &str) -> String {
    let mut out = String::from("\"");
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            c if c.is_ascii() && !c.is_ascii_control() => out.push(c),
            c => {
                let mut units = [0u16; 2];
                for unit in c.encode_utf16(&mut units) {
                    let _ = write!(out, "\\u{unit:04x}");
                }
            }
        }
    }
    out.push('"');
    out
}

/// rnstatus.py `speed_str`.
fn speed_str(num: f64) -> String {
    let mut num = num;
    for unit in ["", "k", "M", "G", "T", "P", "E", "Z"] {
        if num.abs() < 1000.0 {
            return format!("{num:3.2} {unit}bps");
        }
        num /= 1000.0;
    }
    format!("{num:.2} Ybps")
}

fn unix_now() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

// ---------------------------------------------------------------------------
// Discovered interfaces (rnstatus.py).

fn print_discovered_summary(
    out: &mut Out,
    records: &[&DiscoveredInterface],
    show_stale: bool,
    show_unknown: bool,
) {
    outln!(
        out,
        "{:<25} {:<10}   {:<10} {:<12} {:<7} {:<16} {:<15}",
        "Name",
        "Type",
        "Status",
        "Last Heard",
        "Value",
        "Running",
        "Location"
    );
    outln!(out, "{}", "-".repeat(110));
    let now = unix_now();
    for record in records {
        if !discovered_shown(record, show_stale, show_unknown) {
            continue;
        }
        let info = &record.info;
        let name = truncate_ellipsis(&info.name, 24);
        let mut stack = discovered_stack(record).unwrap_or_else(|| "Unknown".into());
        if stack.chars().count() > 16 {
            stack = stack.chars().take(15).collect::<String>() + "…";
        }
        let status = match record.status {
            Some(DiscoveryStatus::Available) => "✓ Available",
            Some(DiscoveryStatus::Unknown) => "? Unknown",
            Some(DiscoveryStatus::Stale) => "× Stale",
            None => "? Unknown",
        };
        let diff = (now - record.last_heard).max(0.0) as u64;
        let last_heard = if diff < 60 {
            "Just now".to_string()
        } else if diff < 3600 {
            format!("{}m ago", diff / 60)
        } else if diff < 86400 {
            format!("{}h ago", diff / 3600)
        } else {
            format!("{}d ago", diff / 86400)
        };
        let location = match (
            finite_location(info.latitude),
            finite_location(info.longitude),
        ) {
            (Some(lat), Some(lon)) => format!("{}, {}", py_round4(lat), py_round4(lon)),
            _ => "N/A".to_string(),
        };
        outln!(
            out,
            "{:<25} {:<10} {:<12} {:<12} {:<7} {:<16} {:<15}",
            name,
            info.interface_type.replace("Interface", ""),
            status,
            last_heard,
            pretty_cost(Some(record.stamp_value)),
            stack,
            location
        );
    }
}

fn print_discovered_details(
    out: &mut Out,
    records: &[&DiscoveredInterface],
    stored: &[&Value],
    show_stale: bool,
    show_unknown: bool,
) {
    let now = unix_now();
    for (idx, record) in records.iter().enumerate() {
        if !discovered_shown(record, show_stale, show_unknown) {
            continue;
        }
        let info = &record.info;
        // Python numbers the separator by the filtered list, hidden records included.
        if idx > 0 {
            outln!(out, "\n{}\n", "=".repeat(47));
        }
        if record.network_id != info.transport_id {
            outln!(out, "Network   ID : {}", hex::encode(record.network_id));
        }
        outln!(out, "Transport ID : {}", hex::encode(info.transport_id));
        if let Some(address) = info.operator_lxmf_address {
            outln!(out, "LXMF address : {}", hex::encode(address));
        }
        outln!(out, "Name         : {}", info.name);
        outln!(out, "Type         : {}", info.interface_type);
        outln!(
            out,
            "Stack        : {}",
            discovered_stack(record).unwrap_or_else(|| "Unknown".into())
        );
        outln!(
            out,
            "Status       : {}",
            match record.status {
                Some(DiscoveryStatus::Available) => "Available",
                Some(DiscoveryStatus::Stale) => "Stale",
                _ => "Unknown",
            }
        );
        outln!(
            out,
            "Transport    : {}",
            if info.transport_enabled {
                "Enabled"
            } else {
                "Disabled"
            }
        );
        outln!(
            out,
            "Stamp Value  : {}",
            pretty_cost(Some(record.stamp_value))
        );
        let info_dict = stored[idx];
        if has(info_dict, "dst_cost") && has(info_dict, "pr_cost") {
            outln!(
                out,
                "Costs        : Dst {}, PR {}",
                pretty_cost(info.dst_cost),
                pretty_cost(info.pr_cost)
            );
        }
        outln!(
            out,
            "Distance     : {} hop{}",
            record.hops,
            if record.hops == 1 { "" } else { "s" }
        );
        outln!(
            out,
            "Discovered   : {} ago",
            pretty_time_compact((now - record.discovered).max(0.0) as u64)
        );
        outln!(
            out,
            "Last Heard   : {} ago",
            pretty_time_compact((now - record.last_heard).max(0.0) as u64)
        );
        let location = match (
            finite_location(info.latitude),
            finite_location(info.longitude),
        ) {
            (Some(lat), Some(lon)) => {
                let height = finite_location(info.height)
                    .map(|height| format!(", {}m h", py_float(height)))
                    .unwrap_or_default();
                format!("{}, {}{height}", py_round4(lat), py_round4(lon))
            }
            _ => "Unknown".to_string(),
        };
        outln!(out, "Location     : {location}");
        if let Some(freq) = info.frequency {
            outln!(out, "Frequency    : {} Hz", thousands(freq));
        }
        if let Some(bw) = info.bandwidth {
            outln!(out, "Bandwidth    : {} Hz", thousands(bw));
        }
        if let Some(sf) = info.spreading_factor {
            outln!(out, "Sprd. Factor : {sf}");
        }
        if let Some(cr) = info.coding_rate {
            outln!(out, "Coding Rate  : {cr}");
        }
        if let Some(modu) = &info.modulation {
            outln!(out, "Modulation   : {modu}");
        }
        if let Some(addr) = &info.reachable_on {
            outln!(out, "Address      : {addr}");
        }
        if let Some(port) = info.port {
            outln!(out, "Port         : {port}");
        }
        outln!(out, "\nConfiguration Entry:");
        // Upstream prints the header, then fails on a record without an entry.
        if let Some(entry) = get(info_dict, "config_entry") {
            for line in py_str(entry).split('\n') {
                outln!(out, "  {line}");
            }
        }
    }
}

fn finite_location(value: Option<f64>) -> Option<f64> {
    value.filter(|number| number.is_finite())
}

/// Python's `impl_name version`, when the record names both (rnstatus.py).
fn discovered_stack(record: &DiscoveredInterface) -> Option<String> {
    match (&record.info.impl_name, &record.info.impl_version) {
        (Some(name), Some(version)) if !name.is_empty() && !version.is_empty() => {
            Some(format!("{name} {version}"))
        }
        _ => None,
    }
}

/// Whether Python lists this record: stale and stack-less records are hidden
/// unless asked for (rnstatus.py).
fn discovered_shown(record: &DiscoveredInterface, show_stale: bool, show_unknown: bool) -> bool {
    (show_stale || record.status != Some(DiscoveryStatus::Stale))
        && (show_unknown || discovered_stack(record).is_some())
}

/// Python's `RNS.prettytime(t, compact=True)` for whole seconds.
fn pretty_time_compact(seconds: u64) -> String {
    let parts = [
        (seconds / 86400, "d"),
        ((seconds % 86400) / 3600, "h"),
        ((seconds % 3600) / 60, "m"),
        (seconds % 60, "s"),
    ];
    let components: Vec<String> = parts
        .iter()
        .filter(|(value, _)| *value > 0)
        .take(2)
        .map(|(value, unit)| format!("{value}{unit}"))
        .collect();
    match components.as_slice() {
        [] => "0s".to_string(),
        [one] => one.clone(),
        [first, second] => format!("{first} and {second}"),
        _ => unreachable!("at most two components"),
    }
}

/// Python's `str(float)` for ordinary magnitudes.
fn py_float(value: f64) -> String {
    if value.fract() == 0.0 && value.abs() < 1e16 {
        format!("{value:.1}")
    } else {
        format!("{value}")
    }
}

/// Python's `str(round(value, 4))`.
fn py_round4(value: f64) -> String {
    py_float(format!("{value:.4}").parse().unwrap_or(value))
}

/// Python's `f"{value:,}"` for integers.
fn thousands(value: u64) -> String {
    let digits = value.to_string();
    let mut out = String::new();
    for (idx, digit) in digits.chars().enumerate() {
        if idx > 0 && (digits.len() - idx).is_multiple_of(3) {
            out.push(',');
        }
        out.push(digit);
    }
    out
}

/// Python cuts long names to `limit` characters plus an ellipsis.
fn truncate_ellipsis(s: &str, limit: usize) -> String {
    if s.chars().count() > limit {
        s.chars().take(limit).collect::<String>() + "…"
    } else {
        s.to_string()
    }
}
