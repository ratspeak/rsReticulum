//! rnpath-rs — path and routing management, following `RNS/Utilities/rnpath.py`.
//!
//! Local actions query the shared instance over its RPC control port. `-R`
//! manages a remote transport through `rnstransport.remote.management`, and
//! `-p` fetches a remote transport's published blackhole list.

use std::fmt;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::{Duration, Instant};

use clap::Parser;

use rns_identity::destination::Destination;
use rns_identity::identity::Identity;
use rns_runtime::config::Config;
use rns_runtime::lifecycle::ShutdownSignal;
use rns_runtime::link_client::{LinkClient, LinkClientError};
use rns_runtime::platform::resolve_config_dir;
use rns_runtime::reticulum::{
    InitOptions, InstanceMode, ReticulumConfig, ReticulumHandle, SharedInstanceRpcEndpoint, init,
    init_with_options,
};
use rns_runtime::rpc::{self, RpcRequest, RpcResponse};
use rns_tools::RS_RETICULUM_VERSION;
use rns_tools::format::pretty_hex_rep;
use rns_transport::constants::PATH_REQUEST_TIMEOUT;
use rns_transport::messages::PathRequestOptions;

const LOCAL_RPC_TIMEOUT: Duration = Duration::from_secs(5);
/// Budget for link establishment and the request once a remote path is known.
const REMOTE_LINK_TIMEOUT: Duration = Duration::from_secs(30);
const REMOTE_HOPS: u8 = 8;
const MGMT_APP: &str = "rnstransport.remote.management";
const BLACKHOLE_APP: &str = "rnstransport.info.blackhole";
const SPINNER: [char; 7] = ['⢄', '⢂', '⢁', '⡁', '⡈', '⡐', '⡠'];
/// rnpath.py:42.
const OUTPUT_RST: &str = "\r                                                          \r";
/// rnpath.py:478,489.
const LOOKUP_RST: &str = "\r                                                       \r";
const DEST_LENGTH_INVALID: &str =
    "Destination length is invalid, must be 32 hexadecimal characters (16 bytes).";
const DEST_INVALID: &str = "Invalid destination entered. Check your input.";
const HASH_LENGTH_INVALID: &str =
    "Hash length is invalid, must be 32 hexadecimal characters (16 bytes).";
const HASH_INVALID: &str = "Invalid hash entered. Check your input.";
/// Python's `len(None)` error, printed when a flag needs the missing destination.
const NO_DESTINATION: &str = "object of type 'NoneType' has no len()";

#[derive(Parser)]
#[command(
    name = "rnpath-rs",
    about = "Reticulum Path Management Utility",
    disable_version_flag = true
)]
struct Args {
    /// Path to alternative Reticulum config directory
    #[arg(short = 'c', long)]
    config: Option<String>,

    /// Show program's version number and exit
    #[arg(long)]
    version: bool,

    /// Show all known paths
    #[arg(short, long)]
    table: bool,

    /// Sort the path table by last use, most recent first
    #[arg(short = 'u', long)]
    usage: bool,

    /// Maximum hops to filter path table by
    #[arg(short = 'm', long, value_name = "hops", allow_negative_numbers = true)]
    max: Option<i64>,

    /// Show announce rate info
    #[arg(short, long)]
    rates: bool,

    /// Remove the path to a destination
    #[arg(short, long)]
    drop: bool,

    /// Drop all queued announces
    #[arg(short = 'D', long)]
    drop_announces: bool,

    /// Drop all paths via specified transport instance
    #[arg(short = 'x', long)]
    drop_via: bool,

    /// Timeout before giving up
    #[arg(short = 'w', long = "timeout", value_name = "seconds", default_value_t = PATH_REQUEST_TIMEOUT)]
    timeout: f64,

    /// Transport identity hash of remote instance to manage
    #[arg(short = 'R', long = "remote", value_name = "hash")]
    remote: Option<String>,

    /// Path to identity used for remote management
    #[arg(short = 'i', long = "identity", value_name = "path")]
    identity: Option<PathBuf>,

    /// Timeout before giving up on remote queries
    #[arg(short = 'W', long = "remote-timeout", value_name = "seconds", default_value_t = PATH_REQUEST_TIMEOUT)]
    remote_timeout: f64,

    /// List blackholed identities
    #[arg(short, long)]
    blackholed: bool,

    /// Blackhole identity
    #[arg(short = 'B', long)]
    blackhole: bool,

    /// Unblackhole identity
    #[arg(short = 'U', long)]
    unblackhole: bool,

    /// Duration of blackhole enforcement in hours
    #[arg(long)]
    duration: Option<f64>,

    /// Reason for blackholing identity
    #[arg(long)]
    reason: Option<String>,

    /// View published blackhole list for remote transport instance
    #[arg(short = 'p', long = "blackholed-list")]
    blackholed_list: bool,

    /// Output in JSON format
    #[arg(short, long)]
    json: bool,

    /// Hexadecimal hash of the destination
    destination: Option<String>,

    /// Filter for remote blackhole list view
    list_filter: Option<String>,

    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,
}

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
pub(crate) async fn main() -> ExitCode {
    let args = Args::parse();

    if args.version {
        println!("rnpath-rs {RS_RETICULUM_VERSION}");
        return ExitCode::SUCCESS;
    }

    let level = rns_tools::Utility::Rnpath.loglevel(None, args.verbose, 0, false);
    let config_dir = resolve_config_dir(args.config.as_deref());
    rns_tools::init_tracing(
        level,
        rns_tools::config_log_timestamps(&config_dir),
        true,
        std::io::stdout,
    );

    let destination = args.destination.as_deref().filter(|d| !d.is_empty());
    // rnpath.py:525-528.
    if !(args.drop_announces
        || args.table
        || args.rates
        || destination.is_some()
        || args.drop_via
        || args.blackholed)
    {
        let help = <Args as clap::CommandFactory>::command()
            .render_help()
            .to_string();
        println!();
        print!("{help}");
        if !help.ends_with('\n') {
            println!();
        }
        println!();
        return ExitCode::SUCCESS;
    }

    if args.blackholed_list && !args.blackholed {
        return run_remote_blackhole_list(&args).await;
    }
    if let Some(remote) = args.remote.as_deref() {
        return run_remote(&args, remote).await;
    }

    let ctx = match ClientCtx::load(&config_dir) {
        Ok(ctx) => ctx,
        Err(code) => return code,
    };
    // Dispatch order of rnpath.py:132-490.
    if args.blackholed {
        return show_blackholed(&ctx, destination).await;
    }
    if args.blackhole {
        return do_blackhole(&ctx, destination, args.duration, args.reason.clone()).await;
    }
    if args.unblackhole {
        return do_unblackhole(&ctx, destination).await;
    }
    if args.table {
        return show_path_table(&ctx, destination, args.max, args.json, args.usage).await;
    }
    if args.rates {
        return show_rate_table(&ctx, destination, args.json).await;
    }
    if args.drop_announces {
        return drop_announces(&ctx).await;
    }
    if args.drop {
        return drop_path(&ctx, destination).await;
    }
    if args.drop_via {
        return drop_all_via(&ctx, destination).await;
    }
    query_path(&ctx, destination, args.timeout).await
}

/// rnpath.py:249-255 and its copies: a 32-character hex destination.
fn parse_destination(input: Option<&str>) -> Result<[u8; 16], &'static str> {
    parse_hex16(input, DEST_LENGTH_INVALID, DEST_INVALID)
}

/// rnpath.py:94-100.
fn parse_hash(input: Option<&str>) -> Result<[u8; 16], &'static str> {
    parse_hex16(input, HASH_LENGTH_INVALID, HASH_INVALID)
}

fn parse_hex16(
    input: Option<&str>,
    length_msg: &'static str,
    invalid_msg: &'static str,
) -> Result<[u8; 16], &'static str> {
    let input = input.ok_or(NO_DESTINATION)?;
    if input.chars().count() != 32 {
        return Err(length_msg);
    }
    let bytes = hex::decode(input).map_err(|_| invalid_msg)?;
    bytes.try_into().map_err(|_| invalid_msg)
}

fn local_rpc_key(config_dir: &Path, rc: &ReticulumConfig) -> Option<Vec<u8>> {
    if let Some(key) = rc.rpc_key.as_ref() {
        return Some(key.clone());
    }
    let identity = Identity::from_file(&transport_identity_path(config_dir)).ok()?;
    let private_key = identity.get_private_key()?;
    Some(rpc::derive_rpc_key(&*private_key).to_vec())
}

fn transport_identity_path(config_dir: &Path) -> PathBuf {
    rns_runtime::platform::StoragePaths::from_config_dir(config_dir)
        .storage_dir
        .join("transport_identity")
}

struct ClientCtx {
    endpoint: SharedInstanceRpcEndpoint,
    config_dir: PathBuf,
    rpc_key: Vec<u8>,
    static_transport_identity: bool,
}

impl ClientCtx {
    fn load(config_dir: &Path) -> Result<Self, ExitCode> {
        let config_path = config_dir.join("config");
        let config = Config::from_file(&config_path).map_err(|e| {
            eprintln!(
                "rnpath-rs: could not read config at {}: {e}",
                config_path.display()
            );
            ExitCode::from(1)
        })?;
        let rc = ReticulumConfig::from_config(&config);
        let Some(rpc_key) = local_rpc_key(config_dir, &rc) else {
            eprintln!(
                "rnpath-rs: no rpc_key configured and no transport identity at {} — cannot query rnsd.",
                config_path.display()
            );
            return Err(ExitCode::from(1));
        };
        Ok(Self {
            endpoint: rc.shared_rpc_endpoint(&std::env::temp_dir()),
            config_dir: config_dir.to_path_buf(),
            rpc_key,
            static_transport_identity: rc.static_transport_identity,
        })
    }

    /// `RNS.Transport.identity` of a shared-instance client: ephemeral unless
    /// `static_transport_identity` is set (Transport.py:440-445).
    fn local_transport_identity(&self) -> Option<[u8; 16]> {
        if !self.static_transport_identity {
            return None;
        }
        Identity::from_file(&transport_identity_path(&self.config_dir))
            .ok()
            .map(|identity| identity.hash)
    }
}

async fn request(ctx: &ClientCtx, req: &RpcRequest) -> Result<RpcResponse, LocalRpcFailure> {
    let result = match &ctx.endpoint {
        SharedInstanceRpcEndpoint::Tcp(port) => {
            rpc::connect_and_request(*port, &ctx.rpc_key, req, LOCAL_RPC_TIMEOUT).await
        }
        SharedInstanceRpcEndpoint::Unix(socket_path) => {
            rpc::connect_unix_and_request(socket_path, &ctx.rpc_key, req, LOCAL_RPC_TIMEOUT).await
        }
    };
    result.map_err(|source| LocalRpcFailure {
        endpoint: ctx.endpoint.clone(),
        config_dir: ctx.config_dir.clone(),
        source,
    })
}

fn rpc_failed(e: LocalRpcFailure) -> ExitCode {
    eprintln!("rnpath-rs: {e}");
    ExitCode::from(1)
}

fn unexpected(response: RpcResponse) -> ExitCode {
    eprintln!("rnpath-rs: unexpected response: {response:?}");
    ExitCode::from(1)
}

#[derive(Debug)]
struct LocalRpcFailure {
    endpoint: SharedInstanceRpcEndpoint,
    config_dir: PathBuf,
    source: rns_runtime::rpc::RpcError,
}

impl fmt::Display for LocalRpcFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            local_rpc_failure_message(&self.endpoint, &self.config_dir, &self.source)
        )
    }
}

impl std::error::Error for LocalRpcFailure {}

fn local_rpc_failure_message(
    endpoint: &SharedInstanceRpcEndpoint,
    config_dir: &Path,
    err: &rns_runtime::rpc::RpcError,
) -> String {
    let endpoint = endpoint.display();
    let config_path = config_dir.join("config");
    let transport_identity_path = rns_runtime::platform::StoragePaths::from_config_dir(config_dir)
        .storage_dir
        .join("transport_identity");

    match err {
        rns_runtime::rpc::RpcError::AuthFailed => format!(
            "local RPC authentication failed for rnsd-rs-compatible daemon at {endpoint}.\n\
             This usually means a config mismatch (different --config, rpc_key, or \
             transport_identity) or another app is owning the control port.\n\
             System Reticulum defaults are 37428/37429; Ratspeak app-private \
             configs use 37430/37431.\n\
             Config checked: {}.\n\
             If rpc_key is unset, the fallback key is derived from {}.",
            config_path.display(),
            transport_identity_path.display()
        ),
        rns_runtime::rpc::RpcError::Io(e)
            if matches!(
                e.kind(),
                std::io::ErrorKind::ConnectionRefused | std::io::ErrorKind::NotFound
            ) =>
        {
            format!(
                "could not connect to local rnsd-rs-compatible daemon at {endpoint}: {e}.\n\
                 Start rnsd-rs with the same --config directory, or check \
                 shared_instance_type and instance_control_port in {}. \
                 System Reticulum defaults are 37428/37429; Ratspeak \
                 app-private configs use 37430/37431.",
                config_path.display()
            )
        }
        rns_runtime::rpc::RpcError::Io(e) if e.kind() == std::io::ErrorKind::TimedOut => {
            format!(
                "timed out while talking to local rnsd-rs-compatible daemon at {endpoint}: {e}.\n\
                 If a process is listening there, it may not be rnsd-rs-compatible or may be using \
                 a different local RPC auth key. Config checked: {}.",
                config_path.display()
            )
        }
        _ => format!(
            "could not query local rnsd-rs-compatible daemon at {endpoint} using {}: {err}",
            config_path.display()
        ),
    }
}

/// rnpath.py:132-206: `-b` lists the shared instance's blackhole list.
async fn show_blackholed(ctx: &ClientCtx, filter: Option<&str>) -> ExitCode {
    let entries = match request(ctx, &RpcRequest::GetBlackholedIdentities).await {
        Ok(RpcResponse::BlackholeList(entries)) => entries,
        Ok(RpcResponse::Error(e)) => {
            println!("Could not get blackholed identities from RNS instance: {e}");
            return ExitCode::from(20);
        }
        Ok(other) => return unexpected(other),
        Err(e) => {
            println!("Could not get blackholed identities from RNS instance: {e}");
            return ExitCode::from(20);
        }
    };
    let entries: Vec<BlackholeLine> = entries
        .into_iter()
        .map(|e| BlackholeLine {
            identity: e.identity_hash,
            until: e.until,
            reason: e.reason.unwrap_or_default(),
            source: e.source,
        })
        .collect();
    print_blackhole_list(
        &entries,
        filter,
        ctx.local_transport_identity(),
        now_epoch(),
    )
}

struct BlackholeLine {
    identity: Vec<u8>,
    until: Option<f64>,
    reason: String,
    source: Option<Vec<u8>>,
}

/// rnpath.py:176-206, shared by `-b` and `-p`.
fn print_blackhole_list(
    entries: &[BlackholeLine],
    filter: Option<&str>,
    own_transport_id: Option<[u8; 16]>,
    now: f64,
) -> ExitCode {
    if entries.is_empty() {
        println!("No blackholed identity data available");
        return ExitCode::from(20);
    }
    for line in blackhole_lines(entries, filter, own_transport_id, now) {
        println!("{line}");
    }
    ExitCode::SUCCESS
}

fn blackhole_lines(
    entries: &[BlackholeLine],
    filter: Option<&str>,
    own_transport_id: Option<[u8; 16]>,
    now: f64,
) -> Vec<String> {
    let mut lines = Vec::new();
    for entry in entries {
        let identity = pretty_hex_rep(&entry.identity);
        let until = match entry.until {
            Some(until) if until != 0.0 => {
                format!("for {}", py_prettytime((until - now).max(0.0), false))
            }
            _ => "indefinitely".to_string(),
        };
        let reason = if entry.reason.is_empty() {
            String::new()
        } else {
            format!(" ({})", truncate_reason(&entry.reason))
        };
        let by = match entry.source.as_deref() {
            Some(source) if Some(source) != own_transport_id.as_ref().map(|id| &id[..]) => {
                format!(" by {}", pretty_hex_rep(source))
            }
            _ => String::new(),
        };
        let filter_str = format!("{identity} {until} {reason} {by}");
        if filter.is_some_and(|needle| !filter_str.contains(needle)) {
            continue;
        }
        lines.push(format!("{identity} blackholed {until}{reason}{by}"));
    }
    lines
}

/// rnpath.py:181-184: at most 64 characters, the last one an ellipsis.
fn truncate_reason(reason: &str) -> String {
    const RMLEN: usize = 64;
    if reason.chars().count() <= RMLEN {
        reason.to_string()
    } else {
        let mut out: String = reason.chars().take(RMLEN - 1).collect();
        out.push('…');
        out
    }
}

/// rnpath.py:208-225.
async fn do_blackhole(
    ctx: &ClientCtx,
    destination: Option<&str>,
    duration_hours: Option<f64>,
    reason: Option<String>,
) -> ExitCode {
    let id = match parse_hash(destination) {
        Ok(id) => id,
        Err(e) => {
            println!("Could not blackhole identity: {e}");
            return ExitCode::from(20);
        }
    };
    let typed = destination.unwrap_or_default();
    let until = duration_hours
        .filter(|h| *h != 0.0)
        .map(|h| now_epoch() + h * 3600.0);
    let req = RpcRequest::BlackholeIdentity {
        identity_hash: id.to_vec(),
        until,
        reason,
    };
    match request(ctx, &req).await {
        Ok(RpcResponse::OptBoolResult(Some(true))) => println!("Blackholed identity {typed}"),
        Ok(RpcResponse::OptBoolResult(None)) => println!("Identity {typed} already blackholed"),
        Ok(RpcResponse::OptBoolResult(Some(false))) => {
            println!("Could not blackhole identity {typed}")
        }
        Ok(RpcResponse::Error(e)) => {
            println!("Could not blackhole identity: {e}");
            return ExitCode::from(20);
        }
        Ok(other) => return unexpected(other),
        Err(e) => {
            println!("Could not blackhole identity: {e}");
            return ExitCode::from(20);
        }
    }
    ExitCode::SUCCESS
}

/// rnpath.py:227-243.
async fn do_unblackhole(ctx: &ClientCtx, destination: Option<&str>) -> ExitCode {
    let id = match parse_hash(destination) {
        Ok(id) => id,
        Err(e) => {
            println!("Could not unblackhole identity: {e}");
            return ExitCode::from(20);
        }
    };
    let typed = destination.unwrap_or_default();
    let req = RpcRequest::UnblackholeIdentity {
        identity_hash: id.to_vec(),
    };
    match request(ctx, &req).await {
        Ok(RpcResponse::OptBoolResult(Some(true))) => {
            println!("Lifted blackhole for identity {typed}")
        }
        Ok(RpcResponse::OptBoolResult(None)) => println!("Identity {typed} not blackholed"),
        Ok(RpcResponse::OptBoolResult(Some(false))) => {
            println!("Could not unblackhole identity {typed}")
        }
        Ok(RpcResponse::Error(e)) => {
            println!("Could not unblackhole identity: {e}");
            return ExitCode::from(20);
        }
        Ok(other) => return unexpected(other),
        Err(e) => {
            println!("Could not unblackhole identity: {e}");
            return ExitCode::from(20);
        }
    }
    ExitCode::SUCCESS
}

/// The `-t`/`-r` destination filter; an invalid one prints and exits 1.
fn table_filter(destination: Option<&str>) -> Result<Option<[u8; 16]>, ExitCode> {
    match destination {
        None => Ok(None),
        Some(_) => parse_destination(destination).map(Some).map_err(|e| {
            println!("{e}");
            ExitCode::from(1)
        }),
    }
}

/// rnpath.py:245-306, local shared instance.
async fn show_path_table(
    ctx: &ClientCtx,
    destination: Option<&str>,
    max_hops: Option<i64>,
    json: bool,
    usage: bool,
) -> ExitCode {
    let filter = match table_filter(destination) {
        Ok(filter) => filter,
        Err(code) => return code,
    };
    let mut table = match request(ctx, &RpcRequest::GetPathTable { max_hops: None }).await {
        Ok(RpcResponse::PathTable(table)) => table,
        Ok(other) => return unexpected(other),
        Err(e) => return rpc_failed(e),
    };
    if let Some(max) = max_hops {
        table.retain(|e| i64::from(e.hops) <= max);
    }
    table.sort_by(|a, b| (&a.interface, a.hops).cmp(&(&b.interface, b.hops)));
    print_path_table(table, filter, json, usage, now_epoch())
}

fn print_path_table(
    mut table: Vec<rpc::PathTableEntry>,
    filter: Option<[u8; 16]>,
    json: bool,
    usage: bool,
    now: f64,
) -> ExitCode {
    // rnpath.py:276-283 dumps the whole table, filter or not.
    if json {
        println!("{}", path_table_json(&table));
        return ExitCode::SUCCESS;
    }
    if usage {
        sort_by_usage(&mut table);
    }
    let mut displayed = 0;
    for entry in &table {
        if filter.is_none_or(|f| entry.hash == f) {
            displayed += 1;
            println!("{}", path_table_line(entry, now));
        }
    }
    if filter.is_some() && displayed == 0 {
        println!("No path known");
        return ExitCode::from(1);
    }
    ExitCode::SUCCESS
}

/// rnpath.py:302.
fn path_table_line(entry: &rpc::PathTableEntry, now: f64) -> String {
    format!(
        "{} {:>3}h via {} on {} expires in {} {}",
        pretty_hex_rep(&entry.hash),
        entry.hops,
        pretty_hex_rep(entry.via.as_deref().unwrap_or_default()),
        entry.interface,
        py_prettytime(entry.expires - now, true),
        cost_suffix(entry.value, entry.lr_cost)
    )
}

/// rnpath.py:287-288: most recently used first.
fn sort_by_usage(entries: &mut [rpc::PathTableEntry]) {
    entries.sort_by(|a, b| b.used.total_cmp(&a.used));
}

/// The `(dv:<value>/lc:<lr_cost>)` tail of an rnpath 1.6.0 table line (rnpath.py:302).
fn cost_suffix(value: Option<f64>, lr_cost: Option<f64>) -> String {
    format!("(dv:{}/lc:{})", pretty_cost(value), pretty_cost(lr_cost))
}

/// `RNS.prettycost`: the quantized cost to three decimals, `n` when absent.
fn pretty_cost(value: Option<f64>) -> String {
    match value.map(rns_identity::stamps::quantize_cost) {
        Some(Ok(cost)) => format!("{cost:.3}"),
        _ => "n".to_string(),
    }
}

/// `json.dumps` of the path table rows with bytes as hex (rnpath.py:276-282).
/// Upstream sends `value` and `used` as int 0 when unset, and floats otherwise.
fn path_table_json(entries: &[rpc::PathTableEntry]) -> String {
    let rows: Vec<String> = entries
        .iter()
        .map(|e| {
            let via = e
                .via
                .as_ref()
                .map(|v| py_json_str(&hex::encode(v)))
                .unwrap_or_else(|| "null".to_string());
            format!(
                "{{\"hash\": {}, \"timestamp\": {}, \"via\": {via}, \"hops\": {}, \"expires\": {}, \"value\": {}, \"used\": {}, \"lr_cost\": {}, \"interface\": {}}}",
                py_json_str(&hex::encode(&e.hash)),
                py_float_repr(e.timestamp),
                e.hops,
                py_float_repr(e.expires),
                e.value.map(py_int_or_float).unwrap_or_else(|| "null".to_string()),
                py_int_or_float(e.used),
                e.lr_cost.map(py_float_repr).unwrap_or_else(|| "null".to_string()),
                py_json_str(&e.interface)
            )
        })
        .collect();
    format!("[{}]", rows.join(", "))
}

fn py_int_or_float(value: f64) -> String {
    if value == 0.0 {
        "0".to_string()
    } else {
        py_float_repr(value)
    }
}

/// rnpath.py:308-390, local shared instance.
async fn show_rate_table(ctx: &ClientCtx, destination: Option<&str>, json: bool) -> ExitCode {
    let filter = match table_filter(destination) {
        Ok(filter) => filter,
        Err(code) => return code,
    };
    let table = match request(ctx, &RpcRequest::GetRateTable).await {
        Ok(RpcResponse::RateTable(table)) => table,
        Ok(other) => return unexpected(other),
        Err(e) => return rpc_failed(e),
    };
    print_rate_table(table, filter, json, now_epoch())
}

fn print_rate_table(
    mut table: Vec<rpc::RateTableEntry>,
    filter: Option<[u8; 16]>,
    json: bool,
    now: f64,
) -> ExitCode {
    table.sort_by(|a, b| a.last.total_cmp(&b.last));
    if json {
        println!("{}", rate_table_json(&table));
        return ExitCode::SUCCESS;
    }
    if table.is_empty() {
        println!("No information available");
        return ExitCode::SUCCESS;
    }
    let mut displayed = 0;
    for entry in &table {
        if filter.is_none_or(|f| entry.hash == f) {
            displayed += 1;
            for line in rate_table_lines(entry, now) {
                println!("{line}");
            }
        }
    }
    if filter.is_some() && displayed == 0 {
        println!("No information available");
        return ExitCode::from(1);
    }
    ExitCode::SUCCESS
}

/// rnpath.py:355-386.
fn rate_table_lines(entry: &rpc::RateTableEntry, now: f64) -> Vec<String> {
    let hash = pretty_hex_rep(&entry.hash);
    let Some(&start_ts) = entry.timestamps.first() else {
        return vec![
            format!("Error while processing entry for {hash}"),
            "list index out of range".to_string(),
        ];
    };
    let last_str = pretty_date(entry.last.trunc(), now);
    let span_hours = (now - start_ts).max(3600.0) / 3600.0;
    let span_str = pretty_date(start_ts.trunc(), now);
    let hour_rate = py_round(entry.timestamps.len() as f64 / span_hours, 3);
    let hour_rate = if hour_rate.fract() == 0.0 {
        format!("{}", hour_rate as i64)
    } else {
        py_float_repr(hour_rate)
    };
    let rv_str = match entry.rate_violations {
        0 => String::new(),
        1 => ", 1 active rate violation".to_string(),
        n => format!(", {n} active rate violations"),
    };
    let bl_str = if entry.blocked_until > now {
        let bli = now - (entry.blocked_until.trunc() - now);
        format!(
            ", new announces allowed in {}",
            pretty_date(bli.trunc(), now)
        )
    } else {
        String::new()
    };
    vec![format!(
        "{hash} last heard {last_str} ago, {hour_rate} announces/hour in the last {span_str}{rv_str}{bl_str}"
    )]
}

/// `json.dumps` of the rate table rows, in upstream key order (Storage.py:162-163,
/// Reticulum.py:1911).
fn rate_table_json(entries: &[rpc::RateTableEntry]) -> String {
    let rows: Vec<String> = entries
        .iter()
        .map(|e| {
            let timestamps: Vec<String> = e.timestamps.iter().copied().map(py_float_repr).collect();
            format!(
                "{{\"last\": {}, \"rate_violations\": {}, \"blocked_until\": {}, \"timestamps\": [{}], \"hash\": {}}}",
                py_float_repr(e.last),
                e.rate_violations,
                py_float_repr(e.blocked_until),
                timestamps.join(", "),
                py_json_str(&hex::encode(&e.hash))
            )
        })
        .collect();
    format!("[{}]", rows.join(", "))
}

/// rnpath.py:392-400.
async fn drop_announces(ctx: &ClientCtx) -> ExitCode {
    println!("Dropping announce queues on all interfaces...");
    match request(ctx, &RpcRequest::DropAnnounceQueues).await {
        Ok(RpcResponse::Error(e)) => {
            eprintln!("rnpath-rs: {e}");
            ExitCode::from(1)
        }
        Ok(_) => ExitCode::SUCCESS,
        Err(e) => rpc_failed(e),
    }
}

/// rnpath.py:402-421.
async fn drop_path(ctx: &ClientCtx, destination: Option<&str>) -> ExitCode {
    let dest = match parse_destination(destination) {
        Ok(dest) => dest,
        Err(e) => {
            println!("{e}");
            return ExitCode::from(1);
        }
    };
    let req = RpcRequest::DropPath {
        destination_hash: dest.to_vec(),
    };
    match request(ctx, &req).await {
        Ok(RpcResponse::BoolResult(true)) => {
            println!("Dropped path to {}", pretty_hex_rep(&dest));
            ExitCode::SUCCESS
        }
        Ok(RpcResponse::BoolResult(false)) => {
            println!(
                "Unable to drop path to {}. Does it exist?",
                pretty_hex_rep(&dest)
            );
            ExitCode::from(1)
        }
        Ok(other) => unexpected(other),
        Err(e) => rpc_failed(e),
    }
}

/// rnpath.py:423-442.
async fn drop_all_via(ctx: &ClientCtx, destination: Option<&str>) -> ExitCode {
    let via = match parse_destination(destination) {
        Ok(via) => via,
        Err(e) => {
            println!("{e}");
            return ExitCode::from(1);
        }
    };
    let req = RpcRequest::DropAllVia {
        transport_hash: via.to_vec(),
    };
    match request(ctx, &req).await {
        Ok(RpcResponse::IntResult(n)) if n != 0 => {
            println!("Dropped all paths via {}", pretty_hex_rep(&via));
            ExitCode::SUCCESS
        }
        Ok(RpcResponse::IntResult(_)) => {
            println!(
                "Unable to drop paths via {}. Does the transport instance exist?",
                pretty_hex_rep(&via)
            );
            ExitCode::from(1)
        }
        Ok(other) => unexpected(other),
        Err(e) => rpc_failed(e),
    }
}

/// rnpath.py:444-490: request a path through the shared instance and wait
/// `max(-w, medium_path_timeout)` with the spinner.
async fn query_path(ctx: &ClientCtx, destination: Option<&str>, timeout: f64) -> ExitCode {
    let dest = match parse_destination(destination) {
        Ok(dest) => dest,
        Err(e) => {
            println!("{e}");
            return ExitCode::from(1);
        }
    };
    let handle = match attach_client(ctx).await {
        Ok(handle) => handle,
        Err(e) => {
            eprintln!("rnpath-rs: {e}");
            return ExitCode::from(1);
        }
    };
    let code = query_path_attached(ctx, &handle, dest, timeout).await;
    handle.shutdown.trigger();
    handle.shutdown_and_wait().await;
    code
}

async fn query_path_attached(
    ctx: &ClientCtx,
    handle: &ReticulumHandle,
    dest: [u8; 16],
    timeout: f64,
) -> ExitCode {
    // A client's own path table starts empty, so upstream always requests.
    if let Err(e) = handle
        .request_path(dest, PathRequestOptions::default())
        .await
    {
        eprintln!("rnpath-rs: path request failed: {e}");
        return ExitCode::from(1);
    }
    print!("Path to {} requested   ", pretty_hex_rep(&dest));
    flush();
    let medium = medium_path_timeout(ctx).await;
    let deadline = deadline_after(timeout.max(medium));
    let found = spin_until(deadline, || async { has_path(ctx, dest).await }).await;

    if !found {
        println!("{LOOKUP_RST}Path not found");
        return ExitCode::from(1);
    }
    let hops = path_hops(ctx, dest).await;
    let next_hop = match request(
        ctx,
        &RpcRequest::GetNextHop {
            destination_hash: dest.to_vec(),
        },
    )
    .await
    {
        Ok(RpcResponse::HashResult(next_hop)) => next_hop,
        Ok(other) => return unexpected(other),
        Err(e) => return rpc_failed(e),
    };
    let Some(next_hop) = next_hop else {
        println!("{LOOKUP_RST}Error: Invalid path data returned");
        return ExitCode::from(1);
    };
    let interface = match request(
        ctx,
        &RpcRequest::GetNextHopIfName {
            destination_hash: dest.to_vec(),
        },
    )
    .await
    {
        Ok(RpcResponse::StringResult(name)) => name.unwrap_or_else(|| "None".to_string()),
        Ok(other) => return unexpected(other),
        Err(e) => return rpc_failed(e),
    };
    println!(
        "\rPath found, destination {} is {hops} hop{} away via {} on {interface}",
        pretty_hex_rep(&dest),
        if hops == 1 { "" } else { "s" },
        pretty_hex_rep(&next_hop)
    );
    ExitCode::SUCCESS
}

/// Print one spinner frame every 100 ms until `done` or the deadline
/// (rnpath.py:465-472, rnprobe.py:85-91). Returns whether `done` held.
async fn spin_until<F, Fut>(deadline: Option<Instant>, mut done: F) -> bool
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let mut i = 0;
    loop {
        if done().await {
            return true;
        }
        if deadline.is_some_and(|d| Instant::now() >= d) {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
        print!("\u{8}\u{8}{} ", SPINNER[i]);
        flush();
        i = (i + 1) % SPINNER.len();
    }
}

/// `None` when the wait cannot end (Python's `time.time() + inf`).
fn deadline_after(secs: f64) -> Option<Instant> {
    if secs.is_nan() || secs <= 0.0 {
        return Some(Instant::now());
    }
    Duration::try_from_secs_f64(secs)
        .ok()
        .and_then(|d| Instant::now().checked_add(d))
}

fn flush() {
    let _ = std::io::stdout().flush();
}

async fn has_path(ctx: &ClientCtx, dest: [u8; 16]) -> bool {
    path_entry(ctx, dest).await.is_some()
}

async fn path_hops(ctx: &ClientCtx, dest: [u8; 16]) -> u8 {
    path_entry(ctx, dest)
        .await
        .map(|e| e.hops)
        .unwrap_or(rns_transport::constants::PATHFINDER_M)
}

async fn path_entry(ctx: &ClientCtx, dest: [u8; 16]) -> Option<rpc::PathTableEntry> {
    match request(ctx, &RpcRequest::GetPathTable { max_hops: None }).await {
        Ok(RpcResponse::PathTable(entries)) => entries.into_iter().find(|e| e.hash == dest),
        _ => None,
    }
}

async fn medium_path_timeout(ctx: &ClientCtx) -> f64 {
    match request(ctx, &RpcRequest::GetMediumPathTimeout).await {
        Ok(RpcResponse::FloatResult(Some(v))) if v.is_finite() => v,
        _ => 0.0,
    }
}

/// Attach to the shared instance as a client, as `RNS.Reticulum()` does in rnpath.
async fn attach_client(ctx: &ClientCtx) -> Result<ReticulumHandle, String> {
    let config_dir = ctx.config_dir.to_string_lossy().into_owned();
    let handle = init_with_options(
        Some(&config_dir),
        None,
        ShutdownSignal::new(),
        Arc::new(AtomicBool::new(true)),
        InitOptions {
            require_shared_instance: true,
            ..InitOptions::default()
        },
    )
    .await
    .map_err(|e| format!("could not attach to the shared instance: {e}"))?;
    if handle.instance_mode != InstanceMode::Client {
        handle.shutdown.trigger();
        handle.shutdown_and_wait().await;
        return Err("could not attach to the shared instance".to_string());
    }
    Ok(handle)
}

fn now_epoch() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

/// Start the runtime used for `-R` and `-p`, as rnpath.py:108 does.
async fn start_runtime(args: &Args) -> Result<ReticulumHandle, ExitCode> {
    init(
        args.config.as_deref(),
        None,
        ShutdownSignal::new(),
        Arc::new(AtomicBool::new(true)),
    )
    .await
    .map_err(|e| {
        eprintln!("rnpath-rs: failed to initialize Reticulum runtime: {e:?}");
        ExitCode::from(1)
    })
}

async fn stop_runtime(handle: ReticulumHandle, code: ExitCode) -> ExitCode {
    handle.shutdown.trigger();
    handle.shutdown_and_wait().await;
    code
}

/// rnpath.py:43-58: wait for a path to the remote destination, printing the
/// request line when one is needed. Exit 12 on timeout.
async fn await_remote_path(
    handle: &ReticulumHandle,
    dest: [u8; 16],
    timeout: f64,
) -> Result<(), ExitCode> {
    let medium = match handle
        .query_control(rns_transport::messages::TransportQuery::GetInterfaceStats)
        .await
    {
        Some(rns_transport::messages::TransportQueryResponse::InterfaceStats(ifs)) => ifs
            .iter()
            .filter(|i| i.online && i.bitrate > 0)
            .map(|i| i.bitrate)
            .min()
            .map(medium_path_timeout_for_bitrate)
            .unwrap_or(0.0),
        _ => 0.0,
    };
    if handle.has_path(dest).await.unwrap_or(false) {
        return Ok(());
    }
    print!("Path to {} requested ", pretty_hex_rep(&dest));
    flush();
    let _ = handle
        .request_path(dest, PathRequestOptions::default())
        .await;
    let deadline = deadline_after(timeout.max(medium));
    loop {
        if handle.has_path(dest).await.unwrap_or(false) {
            return Ok(());
        }
        if deadline.is_some_and(|d| Instant::now() >= d) {
            println!("{OUTPUT_RST}Path request timed out");
            return Err(ExitCode::from(12));
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// `Transport.medium_path_timeout()` (Transport.py:3550-3553).
fn medium_path_timeout_for_bitrate(lowest_bitrate: u64) -> f64 {
    let bits = (rns_wire::constants::MTU * 8) as f64;
    2.0 * (bits / lowest_bitrate.max(rns_runtime::constants::MINIMUM_BITRATE) as f64)
        + rns_wire::constants::DEFAULT_PER_HOP_TIMEOUT
}

/// rnpath.py:59-92 and the request: one link query, with upstream's
/// progress lines and link failure messages (exit 10).
async fn remote_query(
    handle: &ReticulumHandle,
    identity: Identity,
    transport_hash: [u8; 16],
    app: &str,
    path: &str,
    payload: Vec<u8>,
) -> Result<Vec<u8>, ExitCode> {
    print!("{OUTPUT_RST}Establishing link with remote transport instance... ");
    flush();
    print!("{OUTPUT_RST}Sending request... ");
    flush();
    let client = LinkClient::new(handle.transport_tx.clone(), identity);
    client
        .query(
            transport_hash,
            app,
            path,
            payload,
            REMOTE_HOPS,
            REMOTE_LINK_TIMEOUT,
        )
        .await
        .map_err(|e| {
            print!("{OUTPUT_RST}");
            match e {
                LinkClientError::Timeout(_) => println!("The link timed out, exiting now"),
                _ => println!("Link closed unexpectedly, exiting now"),
            }
            ExitCode::from(10)
        })
}

/// rnpath.py:146-206: `-p` fetches `/list` from the transport whose identity
/// hash is the destination argument, filtered by `list_filter`.
async fn run_remote_blackhole_list(args: &Args) -> ExitCode {
    let identity_hash = match parse_hash(args.destination.as_deref()) {
        Ok(h) => h,
        Err(e) => {
            println!("{e}");
            return ExitCode::from(20);
        }
    };
    let handle = match start_runtime(args).await {
        Ok(handle) => handle,
        Err(code) => return code,
    };
    let code = remote_blackhole_list(args, &handle, identity_hash).await;
    stop_runtime(handle, code).await
}

async fn remote_blackhole_list(
    args: &Args,
    handle: &ReticulumHandle,
    identity_hash: [u8; 16],
) -> ExitCode {
    let dest = Destination::hash_from_name_and_identity(BLACKHOLE_APP, Some(&identity_hash));
    if let Err(code) = await_remote_path(handle, dest, args.remote_timeout).await {
        return code;
    }
    let bytes = match remote_query(
        handle,
        Identity::new(),
        identity_hash,
        BLACKHOLE_APP,
        "/list",
        Vec::new(),
    )
    .await
    {
        Ok(bytes) => bytes,
        Err(code) => return code,
    };
    let Ok(entries) = rns_transport::discovery::decode_manifest(&bytes) else {
        println!("{OUTPUT_RST}The remote request failed.");
        return ExitCode::from(10);
    };
    print!("{OUTPUT_RST}");
    let entries: Vec<BlackholeLine> = entries
        .into_iter()
        .map(|(identity, entry)| BlackholeLine {
            identity: identity.to_vec(),
            until: entry.until,
            reason: entry.reason,
            source: Some(entry.source.as_bytes().to_vec()),
        })
        .collect();
    print_blackhole_list(
        &entries,
        args.list_filter.as_deref(),
        Some(handle.transport_identity.hash),
        now_epoch(),
    )
}

/// rnpath.py:111-130 and the remote branches: `-t` and `-r` over
/// `rnstransport.remote.management`; other actions are not implemented upstream.
async fn run_remote(args: &Args, remote: &str) -> ExitCode {
    let remote_hash = match parse_destination(Some(remote)) {
        Ok(h) => h,
        Err(e) => {
            println!("{e}");
            return ExitCode::from(20);
        }
    };
    let identity = match args.identity.as_ref() {
        None => {
            println!("expected str, bytes or os.PathLike object, not NoneType");
            return ExitCode::from(20);
        }
        Some(path) => match Identity::from_file(path) {
            Ok(identity) => identity,
            Err(_) => {
                println!("Could not load management identity from {}", path.display());
                return ExitCode::from(20);
            }
        },
    };
    let handle = match start_runtime(args).await {
        Ok(handle) => handle,
        Err(code) => return code,
    };
    let dest = Destination::hash_from_name_and_identity(MGMT_APP, Some(&remote_hash));
    if let Err(code) = await_remote_path(&handle, dest, args.remote_timeout).await {
        return stop_runtime(handle, code).await;
    }
    if let Some(message) = remote_unimplemented(args) {
        println!("{OUTPUT_RST}{message}");
        return stop_runtime(handle, ExitCode::from(255)).await;
    }
    let destination = args.destination.as_deref().filter(|d| !d.is_empty());
    let filter = match table_filter(destination) {
        Ok(filter) => filter,
        Err(code) => return stop_runtime(handle, code).await,
    };
    let code = remote_management(args, &handle, identity, remote_hash, filter).await;
    stop_runtime(handle, code).await
}

/// The remote branches that print "not implemented" and exit 255 (rnpath.py:135-449).
fn remote_unimplemented(args: &Args) -> Option<&'static str> {
    if args.blackholed {
        Some("Listing blackholed identities on remote instances not yet implemented")
    } else if args.blackhole || args.unblackhole {
        Some("Blackholing identity on remote instances not yet implemented")
    } else if args.table || args.rates {
        None
    } else if args.drop_announces {
        Some("Dropping announce queues on remote instances not yet implemented")
    } else if args.drop {
        Some("Dropping path on remote instances not yet implemented")
    } else if args.drop_via {
        Some(
            "Dropping all paths via specific transport instance on remote instances yet not implemented",
        )
    } else {
        Some("Requesting paths on remote instances not implemented")
    }
}

async fn remote_management(
    args: &Args,
    handle: &ReticulumHandle,
    identity: Identity,
    remote_hash: [u8; 16],
    filter: Option<[u8; 16]>,
) -> ExitCode {
    let dest_value = filter
        .map(|f| rmpv::Value::Binary(f.to_vec()))
        .unwrap_or(rmpv::Value::Nil);
    // rnpath.py:263,326.
    let request = if args.table {
        let max = args.max.map(rmpv::Value::from).unwrap_or(rmpv::Value::Nil);
        vec![rmpv::Value::from("table"), dest_value, max]
    } else {
        vec![rmpv::Value::from("rates"), dest_value]
    };
    let mut payload = Vec::new();
    if let Err(e) = rmpv::encode::write_value(&mut payload, &rmpv::Value::Array(request)) {
        eprintln!("rnpath-rs: msgpack encode failed: {e}");
        return ExitCode::from(1);
    }
    let bytes = match remote_query(handle, identity, remote_hash, MGMT_APP, "/path", payload).await
    {
        Ok(bytes) => bytes,
        Err(code) => return code,
    };
    let now = now_epoch();
    // A falsy reply, including an empty table, is reported as a failure (rnpath.py:266-273).
    if args.table {
        match rpc::decode_response_for_request(&bytes, &RpcRequest::GetPathTable { max_hops: None })
        {
            Ok(RpcResponse::PathTable(table)) if !table.is_empty() => {
                print!("{OUTPUT_RST}");
                print_path_table(table, filter, args.json, args.usage, now)
            }
            _ => remote_request_failed(),
        }
    } else {
        match rpc::decode_response_for_request(&bytes, &RpcRequest::GetRateTable) {
            Ok(RpcResponse::RateTable(table)) if !table.is_empty() => {
                print!("{OUTPUT_RST}");
                print_rate_table(table, filter, args.json, now)
            }
            _ => remote_request_failed(),
        }
    }
}

fn remote_request_failed() -> ExitCode {
    println!("{OUTPUT_RST}The remote request failed. Likely authentication failure.");
    ExitCode::from(10)
}

/// `RNS.prettytime` (RNS/__init__.py:239-290), not verbose.
fn py_prettytime(time: f64, compact: bool) -> String {
    let neg = time < 0.0;
    let mut time = time.abs();
    let days = (time / 86400.0).floor();
    time %= 86400.0;
    let hours = (time / 3600.0).floor();
    time %= 3600.0;
    let minutes = (time / 60.0).floor();
    time %= 60.0;
    let seconds = if compact {
        time.trunc()
    } else {
        py_round(time, 2)
    };

    let mut components = Vec::new();
    for (value, unit) in [(days, "d"), (hours, "h"), (minutes, "m")] {
        if value > 0.0 && (!compact || components.len() < 2) {
            components.push(format!("{}{unit}", value as i64));
        }
    }
    if seconds > 0.0 && (!compact || components.len() < 2) {
        let seconds = if compact {
            format!("{}", seconds as i64)
        } else {
            py_float_repr(seconds)
        };
        components.push(format!("{seconds}s"));
    }
    let mut out = String::new();
    let count = components.len();
    for (i, c) in components.iter().enumerate() {
        if i > 0 {
            out.push_str(if i + 1 < count { ", " } else { " and " });
        }
        out.push_str(c);
    }
    if out.is_empty() {
        "0s".to_string()
    } else if neg {
        format!("-{out}")
    } else {
        out
    }
}

/// rnpath.py:542-561 for an integer timestamp, from `datetime` differences.
fn pretty_date(time: f64, now: f64) -> String {
    let diff = now - time;
    let day_diff = (diff / 86400.0).floor() as i64;
    let second_diff = (diff - day_diff as f64 * 86400.0).floor() as i64;
    if day_diff < 0 {
        return String::new();
    }
    if day_diff == 0 {
        if second_diff < 60 {
            return format!("{second_diff} seconds");
        }
        if second_diff < 70 {
            return "1 minute".to_string();
        }
        if second_diff < 7200 {
            return format!("{} minutes", second_diff / 60);
        }
        return format!("{} hours", second_diff / 3600);
    }
    if day_diff == 1 {
        return "1 day".to_string();
    }
    if day_diff < 7 {
        return format!("{day_diff} days");
    }
    if day_diff < 31 {
        return format!("{} weeks", day_diff / 7);
    }
    if day_diff < 365 {
        return format!("{} months", day_diff / 30);
    }
    format!("{} years", day_diff / 365)
}

/// Python `round(x, n)` for a float.
fn py_round(value: f64, digits: usize) -> f64 {
    format!("{value:.digits$}").parse().unwrap_or(value)
}

/// Python `repr(float)`: shortest round-trip digits, scientific notation
/// outside `1e-4 <= |x| < 1e16`.
fn py_float_repr(value: f64) -> String {
    if value.is_nan() {
        return "nan".to_string();
    }
    if value.is_infinite() {
        return if value > 0.0 { "inf" } else { "-inf" }.to_string();
    }
    let sci = format!("{value:e}");
    let (mantissa, exponent) = sci
        .split_once('e')
        .expect("scientific format has an exponent");
    let exponent: i32 = exponent.parse().expect("integer exponent");
    if value == 0.0 || (-4..16).contains(&exponent) {
        let fixed = format!("{value}");
        if fixed.contains('.') {
            fixed
        } else {
            format!("{fixed}.0")
        }
    } else {
        let sign = if exponent < 0 { '-' } else { '+' };
        format!("{mantissa}e{sign}{:02}", exponent.abs())
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
                    out.push_str(&format!("\\u{unit:04x}"));
                }
            }
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    fn fixture() -> Value {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/python_formatting/python_formatting.json");
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
    }

    fn cases(name: &str) -> Vec<Value> {
        fixture()[name].as_array().unwrap().clone()
    }

    #[test]
    fn formatting_matches_upstream_helpers() {
        for case in cases("prettytime_compact") {
            let t = case[0].as_f64().unwrap();
            assert_eq!(py_prettytime(t, true), case[1].as_str().unwrap(), "{t}");
        }
        for case in cases("prettytime") {
            let t = case[0].as_f64().unwrap();
            assert_eq!(py_prettytime(t, false), case[1].as_str().unwrap(), "{t}");
        }
        let now = fixture()["pretty_date_now"].as_f64().unwrap();
        for case in cases("pretty_date") {
            let t = case[0].as_f64().unwrap();
            assert_eq!(pretty_date(t, now), case[1].as_str().unwrap(), "{t}");
        }
        for case in cases("float_repr") {
            let x = case[0].as_f64().unwrap();
            assert_eq!(py_float_repr(x), case[1].as_str().unwrap(), "{x}");
        }
        for case in cases("round_repr") {
            let (x, n) = (case[0].as_f64().unwrap(), case[1].as_u64().unwrap());
            assert_eq!(
                py_float_repr(py_round(x, n as usize)),
                case[2].as_str().unwrap(),
                "round({x}, {n})"
            );
        }
    }

    // Expected strings are RNS 1.6.0 `prettycost` output for the same values.
    #[test]
    fn cost_suffix_formats_costs_as_upstream_prettycost() {
        for (value, expected) in [
            (None, "n"),
            (Some(0.0), "0.000"),
            (Some(0.0625), "0.062"),
            (Some(0.1875), "0.188"),
            (Some(0.3125), "0.312"),
            (Some(0.002), "0.004"),
            (Some(6.078125), "6.078"),
            (Some(8.78515625), "8.785"),
            (Some(255.5), "100.000"),
            (Some(-3.0), "0.000"),
        ] {
            assert_eq!(pretty_cost(value), expected, "{value:?}");
        }
        assert_eq!(cost_suffix(Some(23.5), None), "(dv:23.500/lc:n)");
        assert_eq!(cost_suffix(Some(0.0), Some(3.25)), "(dv:0.000/lc:3.250)");
    }

    #[test]
    fn usage_sort_lists_most_recently_used_first_and_keeps_ties_in_order() {
        let entry = |tag: u8, used: f64| rpc::PathTableEntry {
            hash: vec![tag; 16],
            timestamp: 0.0,
            via: None,
            hops: 1,
            expires: 0.0,
            value: None,
            used,
            lr_cost: None,
            interface: String::new(),
        };
        let mut entries = vec![entry(1, 0.0), entry(2, 20.0), entry(3, 0.0), entry(4, 30.0)];
        sort_by_usage(&mut entries);
        let order: Vec<u8> = entries.iter().map(|e| e.hash[0]).collect();
        assert_eq!(order, [4, 2, 1, 3]);
    }

    /// rnpath.py:181-202: reason truncation, the `by` suffix and the filter string.
    #[test]
    fn blackhole_lines_truncate_reason_and_filter_on_rendered_text() {
        let own = [0xdd; 16];
        let entries = [
            BlackholeLine {
                identity: vec![0xee; 16],
                until: None,
                reason: format!("spam source {}", "x".repeat(80)),
                source: Some(own.to_vec()),
            },
            BlackholeLine {
                identity: vec![0xff; 16],
                until: Some(1000.0 + 3.0 * 3600.0 + 900.0),
                reason: String::new(),
                source: Some(vec![0x11; 16]),
            },
        ];
        let lines = blackhole_lines(&entries, None, Some(own), 1000.0);
        assert_eq!(
            lines[0],
            format!(
                "<{}> blackholed indefinitely (spam source {}…)",
                "ee".repeat(16),
                "x".repeat(51)
            )
        );
        assert_eq!(
            lines[1],
            format!(
                "<{}> blackholed for 3h and 15m by <{}>",
                "ff".repeat(16),
                "11".repeat(16)
            )
        );
        assert_eq!(
            blackhole_lines(&entries, Some("for 3h"), Some(own), 1000.0).len(),
            1
        );
    }

    #[test]
    fn local_rpc_auth_failure_explains_config_mismatch_and_port_owner() {
        let endpoint = SharedInstanceRpcEndpoint::Tcp(37429);
        let msg = local_rpc_failure_message(
            &endpoint,
            Path::new("/tmp/rns-auth-test"),
            &rns_runtime::rpc::RpcError::AuthFailed,
        );

        assert!(msg.contains("config mismatch"));
        assert!(msg.contains("another app is owning the control port"));
        assert!(msg.contains("rpc_key"));
        assert!(msg.contains("transport_identity"));
        assert!(msg.contains("37430/37431"));
    }
}
