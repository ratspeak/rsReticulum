//! rnpath-rs — path and routing management.
//!
//! Local mode supports the full table/rate/blackhole surface via HMAC RPC
//! (TCP or shared Unix socket).
//! Remote mode (`-R <hash> -i <identity>`) is read-only (`--table` / `--rates`);
//! `-p <hash>` fetches a remote transport's published blackhole list.

use std::fmt;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::Duration;

use clap::Parser;

use rns_runtime::config::Config;
use rns_runtime::lifecycle::ShutdownSignal;
use rns_runtime::link_client::{LinkClient, LinkClientError};
use rns_runtime::platform::resolve_config_dir;
use rns_runtime::reticulum::{ReticulumConfig, SharedInstanceRpcEndpoint, init};
use rns_runtime::rpc::{self, RpcRequest, RpcResponse};
use rns_tools::{format, hash};

const DEFAULT_TIMEOUT_SECS: u64 = 5;
const REMOTE_TIMEOUT_SECS: u64 = 30;
const REMOTE_HOPS: u8 = 8;
const MGMT_APP: &str = "rnstransport.remote.management";
const BLACKHOLE_APP: &str = "rnstransport.info.blackhole";
use rns_tools::RS_RETICULUM_VERSION;

#[derive(Parser)]
#[command(
    name = "rnpath-rs",
    about = "Reticulum path management",
    disable_version_flag = true
)]
struct Args {
    /// Destination hash to request a path to.
    destination: Option<String>,

    /// Show the full path table.
    #[arg(short, long)]
    table: bool,

    /// Show announce rate-limiting table.
    #[arg(short, long)]
    rates: bool,

    /// Drop the path to a specific destination.
    #[arg(short, long)]
    drop: Option<String>,

    /// Drop all queued announces on all interfaces.
    #[arg(short = 'D', long)]
    drop_announces: bool,

    /// Drop all paths routed via a specific transport identity.
    #[arg(short = 'x', long)]
    drop_via: Option<String>,

    /// Filter path table by maximum hops.
    #[arg(short, long)]
    max: Option<u8>,

    /// List blackholed identities.
    #[arg(short, long)]
    blackholed: bool,

    /// View published blackhole list for remote transport instance.
    #[arg(short = 'p', long = "blackholed-list")]
    blackholed_list: bool,

    /// Blackhole an identity (pass its hash).
    #[arg(short = 'B', long)]
    blackhole: Option<String>,

    /// Remove the blackhole on an identity.
    #[arg(short = 'U', long)]
    unblackhole: Option<String>,

    /// Blackhole duration (hours, float).
    #[arg(long)]
    duration: Option<f64>,

    /// Reason to record on the blackhole entry.
    #[arg(long)]
    reason: Option<String>,

    /// JSON output (machine-readable).
    #[arg(short, long)]
    json: bool,

    /// Alternative config directory.
    #[arg(short = 'c', long)]
    config: Option<String>,

    /// Remote transport hash (32 hex chars). Query that node over Reticulum.
    /// Only `--table` and `--rates` are supported in remote mode; mutations
    /// are local-only.
    #[arg(short = 'R', long = "remote")]
    remote: Option<String>,

    /// Identity file for remote authentication (used with `-R`).
    #[arg(short = 'i', long)]
    identity: Option<PathBuf>,

    /// Seconds to wait for local shared-instance responses.
    #[arg(short = 'w', long)]
    timeout: Option<u64>,

    /// Seconds to wait for remote management responses.
    #[arg(short = 'W', long = "remote-timeout")]
    remote_timeout: Option<u64>,

    /// Print version and exit.
    #[arg(long)]
    version: bool,

    /// Increase verbosity.
    #[arg(short, action = clap::ArgAction::Count)]
    verbose: u8,

    /// Filter for remote blackhole list view.
    list_filter: Option<String>,
}

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
pub(crate) async fn main() -> ExitCode {
    let args = Args::parse();

    if args.version {
        println!("rnpath-rs {RS_RETICULUM_VERSION}");
        return ExitCode::SUCCESS;
    }

    let level = match args.verbose {
        0 => tracing::Level::WARN,
        1 => tracing::Level::INFO,
        _ => tracing::Level::DEBUG,
    };
    tracing_subscriber::fmt().with_max_level(level).init();

    if args.blackholed_list {
        return run_remote_blackhole_list(args).await;
    }

    if args.remote.is_some() {
        return run_remote(args).await;
    }

    if !local_action_requested(&args) {
        eprintln!("rnpath-rs: no action specified (use --help)");
        return ExitCode::from(2);
    }
    if let Err(e) = validate_local_hash_args(&args) {
        eprintln!("rnpath-rs: {e}");
        return ExitCode::from(2);
    }

    let config_dir = resolve_config_dir(args.config.as_deref());
    let config_path = config_dir.join("config");
    let config = match Config::from_file(&config_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!(
                "rnpath-rs: could not read config at {}: {e}",
                config_path.display()
            );
            return ExitCode::from(1);
        }
    };
    let rc = ReticulumConfig::from_config(&config);

    let rpc_key = match local_rpc_key(&config_dir, &rc) {
        Some(k) => k,
        None => {
            eprintln!(
                "rnpath-rs: no rpc_key configured and no transport identity at {} — cannot query rnsd.",
                config_path.display()
            );
            return ExitCode::from(1);
        }
    };

    let ctx = ClientCtx {
        endpoint: rc.shared_rpc_endpoint(&std::env::temp_dir()),
        config_dir,
        rpc_key,
        timeout: std::time::Duration::from_secs(args.timeout.unwrap_or(DEFAULT_TIMEOUT_SECS)),
        explicit_timeout: args.timeout.map(std::time::Duration::from_secs),
    };

    // First matching branch wins when multiple action flags are passed.
    if args.table {
        return show_path_table(&ctx, args.max, args.json, args.destination.as_deref()).await;
    }
    if args.rates {
        return show_rate_table(&ctx, args.json, args.destination.as_deref()).await;
    }
    if args.blackholed {
        return show_blackholed(&ctx, args.json).await;
    }
    if let Some(dest_hex) = args.drop.as_deref() {
        return drop_path(&ctx, dest_hex).await;
    }
    if args.drop_announces {
        return drop_announces(&ctx).await;
    }
    if let Some(via_hex) = args.drop_via.as_deref() {
        return drop_all_via(&ctx, via_hex).await;
    }
    if let Some(h) = args.blackhole.as_deref() {
        return do_blackhole(&ctx, h, args.duration, args.reason).await;
    }
    if let Some(h) = args.unblackhole.as_deref() {
        return do_unblackhole(&ctx, h).await;
    }
    if let Some(dest) = args.destination.as_deref() {
        return query_path(&ctx, dest).await;
    }

    unreachable!("local action was validated before config load")
}

fn local_action_requested(args: &Args) -> bool {
    args.table
        || args.rates
        || args.blackholed
        || args.drop.is_some()
        || args.drop_announces
        || args.drop_via.is_some()
        || args.blackhole.is_some()
        || args.unblackhole.is_some()
        || args.destination.is_some()
}

fn validate_hash_arg(value: Option<&str>) -> Result<(), String> {
    if let Some(value) = value {
        hash::parse_dest_hash(value)?;
    }
    Ok(())
}

fn validate_local_hash_args(args: &Args) -> Result<(), String> {
    validate_hash_arg(args.destination.as_deref())?;
    validate_hash_arg(args.drop.as_deref())?;
    validate_hash_arg(args.drop_via.as_deref())?;
    validate_hash_arg(args.blackhole.as_deref())?;
    validate_hash_arg(args.unblackhole.as_deref())?;
    Ok(())
}

fn local_rpc_key(config_dir: &Path, rc: &ReticulumConfig) -> Option<Vec<u8>> {
    if let Some(key) = rc.rpc_key.as_ref() {
        return Some(key.clone());
    }
    let paths = rns_runtime::platform::StoragePaths::from_config_dir(config_dir);
    let identity =
        rns_identity::identity::Identity::from_file(&paths.storage_dir.join("transport_identity"))
            .ok()?;
    let private_key = identity.get_private_key()?;
    Some(rpc::derive_rpc_key(&*private_key).to_vec())
}

struct ClientCtx {
    endpoint: SharedInstanceRpcEndpoint,
    config_dir: PathBuf,
    rpc_key: Vec<u8>,
    timeout: std::time::Duration,
    /// `-w` as given; `None` means path requests wait `PATH_REQUEST_TIMEOUT`.
    explicit_timeout: Option<std::time::Duration>,
}

async fn request(ctx: &ClientCtx, req: &RpcRequest) -> Result<RpcResponse, LocalRpcFailure> {
    request_with_timeout(ctx, req, ctx.timeout).await
}

async fn request_with_timeout(
    ctx: &ClientCtx,
    req: &RpcRequest,
    timeout: std::time::Duration,
) -> Result<RpcResponse, LocalRpcFailure> {
    let result = match &ctx.endpoint {
        SharedInstanceRpcEndpoint::Tcp(port) => {
            rpc::connect_and_request(*port, &ctx.rpc_key, req, timeout).await
        }
        SharedInstanceRpcEndpoint::Unix(socket_path) => {
            rpc::connect_unix_and_request(socket_path, &ctx.rpc_key, req, timeout).await
        }
    };
    result.map_err(|source| LocalRpcFailure {
        endpoint: ctx.endpoint.clone(),
        config_dir: ctx.config_dir.clone(),
        source,
    })
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

fn optional_dest_filter(value: Option<&str>) -> Result<Option<[u8; 16]>, String> {
    value.map(hash::parse_dest_hash).transpose()
}

async fn show_path_table(
    ctx: &ClientCtx,
    max_hops: Option<u8>,
    json: bool,
    destination_filter: Option<&str>,
) -> ExitCode {
    let destination_filter = match optional_dest_filter(destination_filter) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("rnpath-rs: {e}");
            return ExitCode::from(2);
        }
    };
    let mut resp = match request(ctx, &RpcRequest::GetPathTable { max_hops }).await {
        Ok(RpcResponse::PathTable(v)) => v,
        Ok(other) => {
            eprintln!("rnpath-rs: unexpected response: {other:?}");
            return ExitCode::from(1);
        }
        Err(e) => {
            eprintln!("rnpath-rs: {e}");
            return ExitCode::from(1);
        }
    };
    if let Some(dest) = destination_filter {
        resp.retain(|entry| entry.hash.as_slice() == dest);
    }

    if json {
        println!("{}", path_table_json(&resp));
        return ExitCode::SUCCESS;
    }

    if resp.is_empty() {
        println!("Path table is empty.");
        return ExitCode::SUCCESS;
    }
    println!(
        "{:<36} {:>5} {:<36} Interface",
        "Destination", "Hops", "Via"
    );
    for e in &resp {
        let via = e
            .via
            .as_ref()
            .map(hex::encode)
            .unwrap_or_else(|| "-".to_string());
        println!(
            "{:<36} {:>5} {:<36} {}",
            hex::encode(&e.hash),
            e.hops,
            via,
            e.interface
        );
    }
    ExitCode::SUCCESS
}

async fn show_rate_table(
    ctx: &ClientCtx,
    json: bool,
    destination_filter: Option<&str>,
) -> ExitCode {
    let destination_filter = match optional_dest_filter(destination_filter) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("rnpath-rs: {e}");
            return ExitCode::from(2);
        }
    };
    let mut resp = match request(ctx, &RpcRequest::GetRateTable).await {
        Ok(RpcResponse::RateTable(v)) => v,
        Ok(other) => {
            eprintln!("rnpath-rs: unexpected response: {other:?}");
            return ExitCode::from(1);
        }
        Err(e) => {
            eprintln!("rnpath-rs: {e}");
            return ExitCode::from(1);
        }
    };
    if let Some(dest) = destination_filter {
        resp.retain(|entry| entry.hash.as_slice() == dest);
    }

    if json {
        print!("[");
        for (i, e) in resp.iter().enumerate() {
            if i > 0 {
                print!(",");
            }
            print!(
                "{{\"hash\":\"{}\",\"violations\":{},\"blocked_until\":{}}}",
                hex::encode(&e.hash),
                e.rate_violations,
                e.blocked_until
            );
        }
        println!("]");
        return ExitCode::SUCCESS;
    }

    if resp.is_empty() {
        println!("Rate table is empty.");
        return ExitCode::SUCCESS;
    }
    println!(
        "{:<36} {:>10} {:>12}",
        "Destination", "Violations", "Blocked"
    );
    for e in &resp {
        let blocked = if e.blocked_until > 0.0 {
            format::pretty_time(e.blocked_until - now_epoch())
        } else {
            "-".to_string()
        };
        println!(
            "{:<36} {:>10} {:>12}",
            hex::encode(&e.hash),
            e.rate_violations,
            blocked
        );
    }
    ExitCode::SUCCESS
}

async fn show_blackholed(ctx: &ClientCtx, json: bool) -> ExitCode {
    let resp = match request(ctx, &RpcRequest::GetBlackholedIdentities).await {
        Ok(RpcResponse::BlackholeList(v)) => v,
        Ok(other) => {
            eprintln!("rnpath-rs: unexpected response: {other:?}");
            return ExitCode::from(1);
        }
        Err(e) => {
            eprintln!("rnpath-rs: {e}");
            return ExitCode::from(1);
        }
    };

    if json {
        print!("[");
        for (i, e) in resp.iter().enumerate() {
            if i > 0 {
                print!(",");
            }
            let reason = e.reason.as_deref().unwrap_or("manual");
            let until = e
                .until
                .map(|u| format!("{u}"))
                .unwrap_or_else(|| "null".to_string());
            print!(
                "{{\"identity\":\"{}\",\"reason\":\"{}\",\"until\":{}}}",
                hex::encode(&e.identity_hash),
                reason,
                until
            );
        }
        println!("]");
        return ExitCode::SUCCESS;
    }

    if resp.is_empty() {
        println!("No identities are blackholed.");
        return ExitCode::SUCCESS;
    }
    println!("Blackholed identities:");
    println!("  {:<32}  {:<18}  {:<10}", "identity", "reason", "expires");
    for e in &resp {
        let reason = e.reason.as_deref().unwrap_or("manual");
        let expires = match e.until {
            Some(u) => {
                let now = now_epoch();
                let secs = (u - now) as i64;
                if secs <= 0 {
                    "expired".to_string()
                } else if secs >= 3600 {
                    format!("{}h", secs / 3600)
                } else if secs >= 60 {
                    format!("{}m", secs / 60)
                } else {
                    format!("{}s", secs)
                }
            }
            None => "never".to_string(),
        };
        println!(
            "  {:<32}  {:<18}  {:<10}",
            hex::encode(&e.identity_hash),
            reason,
            expires
        );
    }
    ExitCode::SUCCESS
}

async fn drop_path(ctx: &ClientCtx, dest_hex: &str) -> ExitCode {
    let dest = match hash::parse_dest_hash(dest_hex) {
        Ok(h) => h,
        Err(e) => {
            eprintln!("rnpath-rs: {e}");
            return ExitCode::from(2);
        }
    };
    match request(
        ctx,
        &RpcRequest::DropPath {
            destination_hash: dest.to_vec(),
        },
    )
    .await
    {
        Ok(RpcResponse::Ok) => {
            println!("Dropped path to {}", hex::encode(dest));
            ExitCode::SUCCESS
        }
        Ok(other) => {
            eprintln!("rnpath-rs: unexpected response: {other:?}");
            ExitCode::from(1)
        }
        Err(e) => {
            eprintln!("rnpath-rs: {e}");
            ExitCode::from(1)
        }
    }
}

async fn drop_announces(ctx: &ClientCtx) -> ExitCode {
    match request(ctx, &RpcRequest::DropAnnounceQueues).await {
        Ok(RpcResponse::Ok) => {
            println!("All announce queues cleared.");
            ExitCode::SUCCESS
        }
        Ok(other) => {
            eprintln!("rnpath-rs: unexpected response: {other:?}");
            ExitCode::from(1)
        }
        Err(e) => {
            eprintln!("rnpath-rs: {e}");
            ExitCode::from(1)
        }
    }
}

async fn drop_all_via(ctx: &ClientCtx, via_hex: &str) -> ExitCode {
    let via = match hash::parse_dest_hash(via_hex) {
        Ok(h) => h,
        Err(e) => {
            eprintln!("rnpath-rs: {e}");
            return ExitCode::from(2);
        }
    };
    match request(
        ctx,
        &RpcRequest::DropAllVia {
            transport_hash: via.to_vec(),
        },
    )
    .await
    {
        Ok(RpcResponse::IntResult(n)) => {
            println!(
                "Dropped {n} path{} via {}",
                if n == 1 { "" } else { "s" },
                hex::encode(via)
            );
            ExitCode::SUCCESS
        }
        Ok(RpcResponse::Ok) => {
            println!("Dropped all paths via {}", hex::encode(via));
            ExitCode::SUCCESS
        }
        Ok(other) => {
            eprintln!("rnpath-rs: unexpected response: {other:?}");
            ExitCode::from(1)
        }
        Err(e) => {
            eprintln!("rnpath-rs: {e}");
            ExitCode::from(1)
        }
    }
}

async fn do_blackhole(
    ctx: &ClientCtx,
    identity_hex: &str,
    duration_hours: Option<f64>,
    reason: Option<String>,
) -> ExitCode {
    let id = match hash::parse_dest_hash(identity_hex) {
        Ok(h) => h,
        Err(e) => {
            eprintln!("rnpath-rs: {e}");
            return ExitCode::from(2);
        }
    };
    let until = duration_hours.map(|h| now_epoch() + h * 3600.0);
    match request(
        ctx,
        &RpcRequest::BlackholeIdentity {
            identity_hash: id.to_vec(),
            until,
            reason,
        },
    )
    .await
    {
        Ok(RpcResponse::Ok) => {
            println!("Blackholed {}", hex::encode(id));
            ExitCode::SUCCESS
        }
        Ok(other) => {
            eprintln!("rnpath-rs: unexpected response: {other:?}");
            ExitCode::from(1)
        }
        Err(e) => {
            eprintln!("rnpath-rs: {e}");
            ExitCode::from(1)
        }
    }
}

async fn do_unblackhole(ctx: &ClientCtx, identity_hex: &str) -> ExitCode {
    let id = match hash::parse_dest_hash(identity_hex) {
        Ok(h) => h,
        Err(e) => {
            eprintln!("rnpath-rs: {e}");
            return ExitCode::from(2);
        }
    };
    match request(
        ctx,
        &RpcRequest::UnblackholeIdentity {
            identity_hash: id.to_vec(),
        },
    )
    .await
    {
        Ok(RpcResponse::Ok) => {
            println!("Removed blackhole on {}", hex::encode(id));
            ExitCode::SUCCESS
        }
        Ok(other) => {
            eprintln!("rnpath-rs: unexpected response: {other:?}");
            ExitCode::from(1)
        }
        Err(e) => {
            eprintln!("rnpath-rs: {e}");
            ExitCode::from(1)
        }
    }
}

async fn query_path(ctx: &ClientCtx, dest_hex: &str) -> ExitCode {
    let dest = match hash::parse_dest_hash(dest_hex) {
        Ok(h) => h,
        Err(e) => {
            eprintln!("rnpath-rs: {e}");
            return ExitCode::from(2);
        }
    };

    let next_hop = match request(
        ctx,
        &RpcRequest::GetNextHop {
            destination_hash: dest.to_vec(),
        },
    )
    .await
    {
        Ok(RpcResponse::HashResult(Some(h))) => Some(h),
        Ok(RpcResponse::HashResult(None)) => None,
        Ok(other) => {
            eprintln!("rnpath-rs: unexpected response: {other:?}");
            return ExitCode::from(1);
        }
        Err(e) => {
            eprintln!("rnpath-rs: {e}");
            return ExitCode::from(1);
        }
    };

    let iface = match request(
        ctx,
        &RpcRequest::GetNextHopIfName {
            destination_hash: dest.to_vec(),
        },
    )
    .await
    {
        Ok(RpcResponse::StringResult(s)) => s,
        _ => None,
    };

    let mut path_entry = match request(ctx, &RpcRequest::GetPathTable { max_hops: None }).await {
        Ok(RpcResponse::PathTable(entries)) => entries
            .into_iter()
            .find(|entry| entry.hash.as_slice() == dest),
        _ => None,
    };

    let mut next_hop = next_hop;
    let mut iface = iface;
    if next_hop.is_none() && path_entry.is_none() {
        // Python rnpath defaults -w to Transport.PATH_REQUEST_TIMEOUT.
        let timeout_secs = ctx
            .explicit_timeout
            .map(|d| d.as_secs_f64())
            .unwrap_or(rns_transport::constants::PATH_REQUEST_TIMEOUT)
            .max(0.1);
        let req = RpcRequest::RequestPath {
            destination_hash: dest.to_vec(),
            timeout_secs: Some(timeout_secs),
        };
        let rpc_timeout = std::time::Duration::from_secs_f64(timeout_secs + 1.0);
        let found = match request_with_timeout(ctx, &req, rpc_timeout).await {
            Ok(RpcResponse::BoolResult(found)) => found,
            Ok(other) => {
                eprintln!("rnpath-rs: unexpected response: {other:?}");
                return ExitCode::from(1);
            }
            Err(e) => {
                eprintln!("rnpath-rs: {e}");
                return ExitCode::from(1);
            }
        };

        if found {
            next_hop = match request(
                ctx,
                &RpcRequest::GetNextHop {
                    destination_hash: dest.to_vec(),
                },
            )
            .await
            {
                Ok(RpcResponse::HashResult(h)) => h,
                Ok(other) => {
                    eprintln!("rnpath-rs: unexpected response: {other:?}");
                    return ExitCode::from(1);
                }
                Err(e) => {
                    eprintln!("rnpath-rs: {e}");
                    return ExitCode::from(1);
                }
            };
            iface = match request(
                ctx,
                &RpcRequest::GetNextHopIfName {
                    destination_hash: dest.to_vec(),
                },
            )
            .await
            {
                Ok(RpcResponse::StringResult(s)) => s,
                _ => None,
            };
            path_entry = match request(ctx, &RpcRequest::GetPathTable { max_hops: None }).await {
                Ok(RpcResponse::PathTable(entries)) => entries
                    .into_iter()
                    .find(|entry| entry.hash.as_slice() == dest),
                _ => None,
            };
        }
    }

    println!("Destination: {}", hex::encode(dest));
    match next_hop.as_ref() {
        Some(h) => println!("  Next hop : {}", hex::encode(h)),
        None if path_entry.is_some() => println!("  Next hop : (direct)"),
        None => println!("  Next hop : (no known path)"),
    }
    if let Some(entry) = path_entry.as_ref() {
        println!("  Hops     : {}", entry.hops);
    }
    if let Some(i) = iface {
        println!("  Interface: {i}");
    }

    if next_hop.is_none() && path_entry.is_none() {
        println!("  Note     : path request timed out or no path was found");
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}

fn path_table_json(entries: &[rpc::PathTableEntry]) -> String {
    let mut out = String::from("[");
    for (i, e) in entries.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        let via = e
            .via
            .as_ref()
            .map(|v| format!("\"{}\"", hex::encode(v)))
            .unwrap_or_else(|| "null".to_string());
        out.push_str(&format!(
            "{{\"hash\":\"{}\",\"hops\":{},\"via\":{},\"timestamp\":{},\"expires\":{},\"interface\":{:?}}}",
            hex::encode(&e.hash),
            e.hops,
            via,
            e.timestamp,
            e.expires,
            e.interface
        ));
    }
    out.push(']');
    out
}

fn now_epoch() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

async fn run_remote_blackhole_list(args: Args) -> ExitCode {
    let remote_hex = args.remote.as_deref().or(args.destination.as_deref());
    let Some(remote_hex) = remote_hex else {
        eprintln!("rnpath-rs: -p requires a remote transport identity hash.");
        return ExitCode::from(2);
    };
    let remote_hash = match hash::parse_dest_hash(remote_hex) {
        Ok(h) => h,
        Err(e) => {
            eprintln!("rnpath-rs: remote blackhole source: {e}");
            return ExitCode::from(2);
        }
    };

    let identity = match args.identity.as_ref() {
        Some(path) => match rns_identity::identity::Identity::from_file(path) {
            Ok(id) => id,
            Err(e) => {
                eprintln!(
                    "rnpath-rs: could not load identity from {}: {e:?}",
                    path.display()
                );
                return ExitCode::from(1);
            }
        },
        None => rns_identity::identity::Identity::new(),
    };

    let shutdown = ShutdownSignal::new();
    let foreground = Arc::new(AtomicBool::new(true));
    let handle = match init(args.config.as_deref(), None, shutdown.clone(), foreground).await {
        Ok(h) => h,
        Err(e) => {
            eprintln!("rnpath-rs: failed to initialize Reticulum runtime: {e:?}");
            return ExitCode::from(1);
        }
    };

    let timeout = Duration::from_secs(
        args.remote_timeout
            .or(args.timeout)
            .unwrap_or(REMOTE_TIMEOUT_SECS),
    );
    let client = LinkClient::new(handle.transport_tx.clone(), identity);
    let response_bytes = match client
        .query(
            remote_hash,
            BLACKHOLE_APP,
            "/list",
            Vec::new(),
            REMOTE_HOPS,
            timeout,
        )
        .await
    {
        Ok(b) => b,
        Err(e) => {
            eprintln!(
                "rnpath-rs: remote blackhole query failed: {}",
                remote_err(&e)
            );
            shutdown.trigger();
            return match e {
                LinkClientError::Timeout(_) => ExitCode::from(124),
                _ => ExitCode::from(1),
            };
        }
    };

    let list_filter = args.list_filter.as_deref().or_else(|| {
        if args.remote.is_some() {
            args.destination.as_deref()
        } else {
            None
        }
    });
    let exit = print_remote_blackhole_list(&response_bytes, args.json, list_filter, remote_hash);
    shutdown.trigger();
    exit
}

fn print_remote_blackhole_list(
    bytes: &[u8],
    json: bool,
    filter: Option<&str>,
    publisher: [u8; 16],
) -> ExitCode {
    let entries = match rns_transport::discovery::decode_manifest(bytes) {
        Ok(entries) => entries,
        Err(e) => {
            eprintln!("rnpath-rs: malformed blackhole manifest: {e}");
            return ExitCode::from(1);
        }
    };

    let filter_match = |identity: &[u8; 16], reason: &str, source: &[u8; 16]| {
        filter.is_none_or(|needle| {
            let haystack = format!(
                "{} {} {}",
                hex::encode(identity),
                reason,
                hex::encode(source)
            );
            haystack.contains(needle)
        })
    };
    let entries: Vec<_> = entries
        .into_iter()
        .filter(|(identity, entry)| filter_match(identity, &entry.reason, entry.source.as_bytes()))
        .collect();

    if json {
        print!("[");
        for (i, (identity, entry)) in entries.iter().enumerate() {
            if i > 0 {
                print!(",");
            }
            let until = entry
                .until
                .map(|u| u.to_string())
                .unwrap_or_else(|| "null".to_string());
            print!(
                "{{\"identity\":\"{}\",\"until\":{},\"reason\":{:?},\"source\":\"{}\"}}",
                hex::encode(identity),
                until,
                entry.reason,
                hex::encode(entry.source.as_bytes())
            );
        }
        println!("]");
        return ExitCode::SUCCESS;
    }

    if entries.is_empty() {
        println!("No blackholed identity data available.");
        return ExitCode::SUCCESS;
    }

    let now = now_epoch();
    for (identity, entry) in entries {
        let until = match entry.until {
            Some(u) => format!("for {}", format::pretty_time((u - now).max(0.0))),
            None => "indefinitely".to_string(),
        };
        let reason = if entry.reason.is_empty() {
            String::new()
        } else {
            format!(" ({})", entry.reason)
        };
        let by = if entry.source.as_bytes() == &publisher {
            String::new()
        } else {
            format!(" by {}", hex::encode(entry.source.as_bytes()))
        };
        println!("{} blackholed {until}{reason}{by}", hex::encode(identity));
    }
    ExitCode::SUCCESS
}

fn remote_mutation_flag(args: &Args) -> Option<&'static str> {
    if args.drop.is_some() {
        Some("--drop")
    } else if args.drop_announces {
        Some("--drop-announces")
    } else if args.drop_via.is_some() {
        Some("--drop-via")
    } else if args.blackhole.is_some() {
        Some("--blackhole")
    } else if args.unblackhole.is_some() {
        Some("--unblackhole")
    } else {
        None
    }
}

async fn run_remote(args: Args) -> ExitCode {
    let remote_hex = args.remote.as_deref().expect("checked in main");
    let remote_hash = match hash::parse_dest_hash(remote_hex) {
        Ok(h) => h,
        Err(e) => {
            eprintln!("rnpath-rs: --remote: {e}");
            return ExitCode::from(2);
        }
    };

    // Remote management protocol is read-only — reject any mutation flag.
    if let Some(flag) = remote_mutation_flag(&args) {
        eprintln!("rnpath-rs: {flag} is local-only in remote mode.");
        eprintln!(
            "        Remote mode supports read-only --table and --rates queries; \
             path mutations and blackhole management are local-only \
             (no remote endpoint exists in the Reticulum management protocol)."
        );
        return ExitCode::from(2);
    }
    if args.blackholed {
        eprintln!("rnpath-rs: --blackholed is local-only (no remote endpoint).");
        return ExitCode::from(2);
    }
    if !args.table && !args.rates {
        if args.destination.is_some() {
            eprintln!(
                "rnpath-rs: remote destination path requests are not implemented; use --table or --rates with the destination as a filter, or run the path request locally."
            );
        } else {
            eprintln!("rnpath-rs: remote mode requires --table or --rates.");
        }
        return ExitCode::from(2);
    }

    let identity_path = match args.identity.as_ref() {
        Some(p) => p.clone(),
        None => {
            eprintln!("rnpath-rs: --remote requires --identity <path>.");
            return ExitCode::from(2);
        }
    };
    let identity = match rns_identity::identity::Identity::from_file(&identity_path) {
        Ok(id) => id,
        Err(e) => {
            eprintln!(
                "rnpath-rs: could not load identity from {}: {e:?}",
                identity_path.display()
            );
            return ExitCode::from(1);
        }
    };

    let shutdown = ShutdownSignal::new();
    let foreground = Arc::new(AtomicBool::new(true));
    let handle = match init(args.config.as_deref(), None, shutdown.clone(), foreground).await {
        Ok(h) => h,
        Err(e) => {
            eprintln!("rnpath-rs: failed to initialize Reticulum runtime: {e:?}");
            return ExitCode::from(1);
        }
    };

    let timeout = Duration::from_secs(
        args.remote_timeout
            .or(args.timeout)
            .unwrap_or(REMOTE_TIMEOUT_SECS),
    );

    // Wire payload: [command, destination, max_hops]. Destination filter not
    // exposed by all older peers; max_hops is table-only.
    let command = if args.table { "table" } else { "rates" };
    let mut req_args: Vec<rmpv::Value> = vec![rmpv::Value::from(command)];
    if let Some(dest_hex) = args.destination.as_deref() {
        let dest = match hash::parse_dest_hash(dest_hex) {
            Ok(dest) => dest,
            Err(e) => {
                eprintln!("rnpath-rs: destination filter: {e}");
                shutdown.trigger();
                return ExitCode::from(2);
            }
        };
        req_args.push(rmpv::Value::Binary(dest.to_vec()));
    }
    if args.table {
        if let Some(m) = args.max {
            if args.destination.is_none() {
                req_args.push(rmpv::Value::Nil);
            }
            req_args.push(rmpv::Value::from(m));
        }
    }
    let req_value = rmpv::Value::Array(req_args);
    let mut payload = Vec::new();
    if let Err(e) = rmpv::encode::write_value(&mut payload, &req_value) {
        eprintln!("rnpath-rs: msgpack encode failed: {e}");
        shutdown.trigger();
        return ExitCode::from(1);
    }

    let client = LinkClient::new(handle.transport_tx.clone(), identity);
    let response_bytes = match client
        .query(
            remote_hash,
            MGMT_APP,
            "/path",
            payload,
            REMOTE_HOPS,
            timeout,
        )
        .await
    {
        Ok(b) => b,
        Err(e) => {
            eprintln!("rnpath-rs: remote query failed: {}", remote_err(&e));
            shutdown.trigger();
            return match e {
                LinkClientError::Timeout(_) => ExitCode::from(124),
                _ => ExitCode::from(1),
            };
        }
    };

    let exit = if args.table {
        print_remote_path_table(&response_bytes, args.json)
    } else {
        print_remote_rate_table(&response_bytes, args.json)
    };
    shutdown.trigger();
    exit
}

fn print_remote_path_table(bytes: &[u8], json: bool) -> ExitCode {
    let value: rmpv::Value = match rmp_serde::from_slice(bytes) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("rnpath-rs: malformed response: {e}");
            return ExitCode::from(1);
        }
    };
    let arr = match value.as_array() {
        Some(a) => a,
        None => {
            eprintln!("rnpath-rs: response is not an array");
            return ExitCode::from(1);
        }
    };

    if json {
        print!("[");
        for (i, entry) in arr.iter().enumerate() {
            if i > 0 {
                print!(",");
            }
            if let Some(m) = entry.as_map() {
                let h = map_bin(m, "hash").unwrap_or_default();
                let via = map_bin(m, "via");
                let hops = map_u64(m, "hops").unwrap_or(0);
                let iface = map_str(m, "interface").unwrap_or_default();
                let via_str = via
                    .map(|v| format!("\"{}\"", hex::encode(v)))
                    .unwrap_or_else(|| "null".to_string());
                print!(
                    "{{\"hash\":\"{}\",\"hops\":{hops},\"via\":{via_str},\"interface\":{:?}}}",
                    hex::encode(&h),
                    iface
                );
            }
        }
        println!("]");
        return ExitCode::SUCCESS;
    }

    if arr.is_empty() {
        println!("Remote path table is empty.");
        return ExitCode::SUCCESS;
    }
    println!(
        "{:<36} {:>5} {:<36} Interface",
        "Destination", "Hops", "Via"
    );
    for entry in arr {
        if let Some(m) = entry.as_map() {
            let h = map_bin(m, "hash").unwrap_or_default();
            let via = map_bin(m, "via")
                .map(hex::encode)
                .unwrap_or_else(|| "-".to_string());
            let hops = map_u64(m, "hops").unwrap_or(0);
            let iface = map_str(m, "interface").unwrap_or_default();
            println!("{:<36} {:>5} {:<36} {iface}", hex::encode(&h), hops, via);
        }
    }
    ExitCode::SUCCESS
}

fn print_remote_rate_table(bytes: &[u8], json: bool) -> ExitCode {
    let value: rmpv::Value = match rmp_serde::from_slice(bytes) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("rnpath-rs: malformed response: {e}");
            return ExitCode::from(1);
        }
    };
    let arr = match value.as_array() {
        Some(a) => a,
        None => {
            eprintln!("rnpath-rs: response is not an array");
            return ExitCode::from(1);
        }
    };

    if json {
        print!("[");
        for (i, entry) in arr.iter().enumerate() {
            if i > 0 {
                print!(",");
            }
            if let Some(m) = entry.as_map() {
                let h = map_bin(m, "hash").unwrap_or_default();
                let rate = map_f64(m, "rate").unwrap_or(0.0);
                print!("{{\"hash\":\"{}\",\"rate\":{rate}}}", hex::encode(&h));
            }
        }
        println!("]");
        return ExitCode::SUCCESS;
    }

    if arr.is_empty() {
        println!("Remote rate table is empty.");
        return ExitCode::SUCCESS;
    }
    println!("{:<36} {:>10}", "Destination", "Rate");
    for entry in arr {
        if let Some(m) = entry.as_map() {
            let h = map_bin(m, "hash").unwrap_or_default();
            let rate = map_f64(m, "rate").unwrap_or(0.0);
            println!("{:<36} {:>10.4}", hex::encode(&h), rate);
        }
    }
    ExitCode::SUCCESS
}

fn remote_err(e: &LinkClientError) -> String {
    match e {
        LinkClientError::PubkeyNotDiscovered => {
            "remote node not discovered (no announce received). \
             Verify the transport hash and that the local rnsd has connectivity."
                .to_string()
        }
        LinkClientError::Timeout(stage) => format!("timeout while waiting for {stage}"),
        other => other.to_string(),
    }
}

fn map_str(map: &[(rmpv::Value, rmpv::Value)], key: &str) -> Option<String> {
    map.iter()
        .find(|(k, _)| k.as_str() == Some(key))
        .and_then(|(_, v)| v.as_str().map(|s| s.to_string()))
}

fn map_u64(map: &[(rmpv::Value, rmpv::Value)], key: &str) -> Option<u64> {
    map.iter()
        .find(|(k, _)| k.as_str() == Some(key))
        .and_then(|(_, v)| v.as_u64())
}

fn map_f64(map: &[(rmpv::Value, rmpv::Value)], key: &str) -> Option<f64> {
    map.iter()
        .find(|(k, _)| k.as_str() == Some(key))
        .and_then(|(_, v)| v.as_f64())
}

fn map_bin(map: &[(rmpv::Value, rmpv::Value)], key: &str) -> Option<Vec<u8>> {
    map.iter()
        .find(|(k, _)| k.as_str() == Some(key))
        .and_then(|(_, v)| v.as_slice().map(|s| s.to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;

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
