//! rnstatus-rs — interface status viewer.
//!
//! Local: HMAC RPC to local rnsd (TCP or shared Unix socket). Remote
//! (`-R <hash> -i <identity>`): Link to `rnstransport.remote.management`
//! `/status`; remote must allow-list our identity hash.

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::Duration;

use clap::Parser;
use serde_json::json;

use rns_runtime::config::Config;
use rns_runtime::lifecycle::ShutdownSignal;
use rns_runtime::link_client::{LinkClient, LinkClientError};
use rns_runtime::platform::StoragePaths;
use rns_runtime::platform::resolve_config_dir;
use rns_runtime::reticulum::{ReticulumConfig, SharedInstanceRpcEndpoint, init};
use rns_runtime::rpc::{self, RpcRequest, RpcResponse};
use rns_tools::{format, hash};
use rns_transport::discovery::{DiscoveredInterface, DiscoveryStore};

const DEFAULT_TIMEOUT_SECS: u64 = 5;
const REMOTE_TIMEOUT_SECS: u64 = 30;
const REMOTE_HOPS: u8 = 8;
const MGMT_APP: &str = "rnstransport.remote.management";
use rns_tools::RS_RETICULUM_VERSION;

#[derive(Parser)]
#[command(
    name = "rnstatus-rs",
    about = "Reticulum interface status",
    disable_version_flag = true
)]
struct Args {
    /// Show all interfaces (including internal / disabled).
    #[arg(short, long)]
    all: bool,

    /// Show announce queue / frequency stats.
    #[arg(short = 'A', long)]
    announce_stats: bool,

    /// Show path request frequency stats.
    #[arg(short = 'P', long = "pr-stats")]
    pr_stats: bool,

    /// Show link table entry count.
    #[arg(short, long)]
    link_stats: bool,

    /// Only show interfaces with active announce or path request bursts.
    #[arg(short = 'B', long)]
    burst: bool,

    /// Display traffic totals.
    #[arg(short, long)]
    totals: bool,

    /// Sort interfaces by rate, traffic, rx, tx, rxs, txs, announces, arx, atx, prx, ptx or held.
    #[arg(short, long)]
    sort: Option<String>,

    /// Reverse sorting.
    #[arg(short, long)]
    reverse: bool,

    /// JSON output (machine-readable).
    #[arg(short, long)]
    json: bool,

    /// Alternative config directory.
    #[arg(short = 'c', long)]
    config: Option<String>,

    /// Remote transport hash (32 hex chars). Query that node over Reticulum.
    #[arg(short = 'R', long = "remote")]
    remote: Option<String>,

    /// Identity file used to authenticate to the remote node (required with `-R`).
    #[arg(short = 'i', long)]
    identity: Option<PathBuf>,

    /// Seconds to wait for the response (default 5 local, 30 remote).
    #[arg(short = 'w', long)]
    timeout: Option<u64>,

    /// List discovered interfaces from the local discovery store.
    #[arg(short = 'd', long)]
    discovered: bool,

    /// Show details and config data for discovered interfaces.
    #[arg(short = 'D')]
    discovered_details: bool,

    /// Continuously monitor status.
    #[arg(short = 'm', long)]
    monitor: bool,

    /// Refresh interval for monitor mode, in seconds.
    #[arg(short = 'I', long = "monitor-interval", default_value_t = 1.0)]
    monitor_interval: f64,

    /// Print version and exit.
    #[arg(long)]
    version: bool,

    /// Increase verbosity (info level by default; `-vv` for debug).
    #[arg(short, action = clap::ArgAction::Count)]
    verbose: u8,

    /// Decrease verbosity.
    #[arg(short, action = clap::ArgAction::Count)]
    quiet: u8,

    /// Only display interfaces with names including this filter.
    filter: Option<String>,
}

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
pub(crate) async fn main() -> ExitCode {
    let args = Args::parse();

    if args.version {
        println!("rnstatus-rs {RS_RETICULUM_VERSION}");
        return ExitCode::SUCCESS;
    }
    if let Err(e) = validate_args(&args) {
        eprintln!("rnstatus-rs: {e}");
        return ExitCode::from(2);
    }

    let verbosity = (args.verbose as i32) - (args.quiet as i32);
    let level = match verbosity {
        v if v <= -1 => tracing::Level::ERROR,
        0 => tracing::Level::WARN,
        1 => tracing::Level::INFO,
        _ => tracing::Level::DEBUG,
    };
    tracing_subscriber::fmt().with_max_level(level).init();

    if args.monitor {
        run_monitor(args).await
    } else if args.remote.is_some() {
        run_remote(args).await
    } else {
        run_local(args).await
    }
}

async fn run_monitor(args: Args) -> ExitCode {
    let interval = Duration::from_secs_f64(args.monitor_interval.max(0.1));
    loop {
        print!("\x1b[2J\x1b[H");
        let exit = if args.remote.is_some() {
            run_remote_once(&args).await
        } else {
            run_local_once(&args).await
        };
        if exit != ExitCode::SUCCESS {
            return exit;
        }
        tokio::time::sleep(interval).await;
    }
}

async fn run_local(args: Args) -> ExitCode {
    run_local_once(&args).await
}

async fn run_local_once(args: &Args) -> ExitCode {
    let config_dir = resolve_config_dir(args.config.as_deref());
    let config_path = config_dir.join("config");
    let config = match Config::from_file(&config_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!(
                "rnstatus-rs: could not read config at {}: {e}",
                config_path.display()
            );
            return ExitCode::from(1);
        }
    };
    let rc = ReticulumConfig::from_config(&config);

    if args.discovered || args.discovered_details {
        return print_discovered_interfaces(&config_dir, &rc, args);
    }

    let rpc_key = match local_rpc_key(&config_dir, &rc) {
        Some(k) => k,
        None => {
            eprintln!(
                "rnstatus-rs: no rpc_key configured and no transport identity at {} — nothing to query.",
                config_path.display()
            );
            return ExitCode::from(1);
        }
    };

    let timeout = Duration::from_secs(args.timeout.unwrap_or(DEFAULT_TIMEOUT_SECS));
    let endpoint = rc.shared_rpc_endpoint(&std::env::temp_dir());

    let stats =
        match local_rpc_request(&endpoint, &rpc_key, &RpcRequest::GetInterfaceStats, timeout).await
        {
            Ok(RpcResponse::InterfaceStats(v)) => v,
            Ok(RpcResponse::Error(e)) => {
                eprintln!("rnstatus-rs: {e}");
                return ExitCode::from(1);
            }
            Ok(other) => {
                eprintln!("rnstatus-rs: unexpected response: {other:?}");
                return ExitCode::from(1);
            }
            Err(e) => {
                eprintln!(
                    "rnstatus-rs: {}",
                    local_rpc_failure_message(&endpoint, &config_dir, &e)
                );
                return ExitCode::from(1);
            }
        };

    let link_count = if args.link_stats {
        match local_rpc_request(&endpoint, &rpc_key, &RpcRequest::GetLinkCount, timeout).await {
            Ok(RpcResponse::IntResult(n)) => Some(n),
            _ => None,
        }
    } else {
        None
    };

    if args.json {
        print_local_json(&stats, link_count, args);
    } else {
        print_local_human(&stats, link_count, args);
    }

    ExitCode::SUCCESS
}

async fn local_rpc_request(
    endpoint: &SharedInstanceRpcEndpoint,
    rpc_key: &[u8],
    request: &RpcRequest,
    timeout: Duration,
) -> Result<RpcResponse, rns_runtime::rpc::RpcError> {
    match endpoint {
        SharedInstanceRpcEndpoint::Tcp(port) => {
            rpc::connect_and_request(*port, rpc_key, request, timeout).await
        }
        SharedInstanceRpcEndpoint::Unix(socket_path) => {
            rpc::connect_unix_and_request(socket_path, rpc_key, request, timeout).await
        }
    }
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SortKey {
    Rate,
    Rx,
    Tx,
    RxRate,
    TxRate,
    Traffic,
    Announces,
    AnnounceRx,
    AnnounceTx,
    PathRequestRx,
    PathRequestTx,
    Held,
}

fn validate_args(args: &Args) -> Result<(), String> {
    parse_sort_key(args.sort.as_deref()).map(|_| ())?;
    if args.monitor_interval <= 0.0 {
        return Err("--monitor-interval must be greater than 0".to_string());
    }
    if (args.discovered || args.discovered_details) && args.remote.is_some() {
        return Err(
            "--discovered/-D is local-only and cannot be combined with --remote".to_string(),
        );
    }
    Ok(())
}

fn parse_sort_key(value: Option<&str>) -> Result<Option<SortKey>, String> {
    let Some(value) = value else {
        return Ok(None);
    };
    let key = match value.to_ascii_lowercase().as_str() {
        "rate" | "bitrate" => SortKey::Rate,
        "rx" => SortKey::Rx,
        "tx" => SortKey::Tx,
        "rxs" => SortKey::RxRate,
        "txs" => SortKey::TxRate,
        "traffic" => SortKey::Traffic,
        "announces" | "announce" => SortKey::Announces,
        "arx" => SortKey::AnnounceRx,
        "atx" => SortKey::AnnounceTx,
        "prx" => SortKey::PathRequestRx,
        "ptx" => SortKey::PathRequestTx,
        "held" => SortKey::Held,
        _ => {
            return Err(format!(
                "--sort must be one of rate, traffic, rx, tx, rxs, txs, announces, arx, atx, prx, ptx or held; got {value}"
            ));
        }
    };
    Ok(Some(key))
}

fn local_stat_sort_value(e: &rpc::InterfaceStatEntry, key: SortKey) -> f64 {
    match key {
        SortKey::Rate => e.bitrate as f64,
        SortKey::Rx => e.rx_bytes as f64,
        SortKey::Tx => e.tx_bytes as f64,
        SortKey::RxRate => e.rx_rate as f64,
        SortKey::TxRate => e.tx_rate as f64,
        SortKey::Traffic => e.rx_bytes.saturating_add(e.tx_bytes) as f64,
        SortKey::Announces => e.incoming_announce_frequency + e.outgoing_announce_frequency,
        SortKey::AnnounceRx => e.incoming_announce_frequency,
        SortKey::AnnounceTx => e.outgoing_announce_frequency,
        SortKey::PathRequestRx => e.incoming_pr_frequency,
        SortKey::PathRequestTx => e.outgoing_pr_frequency,
        SortKey::Held => e.held_announces as f64,
    }
}

fn visible_by_default(name: &str) -> bool {
    !(name.starts_with("LocalInterface[")
        || name.starts_with("TCPInterface[Client")
        || name.starts_with("BackboneInterface[Client on")
        || name.starts_with("AutoInterfacePeer[")
        || name.starts_with("WeaveInterfacePeer[")
        || name.starts_with("I2PInterfacePeer[Connected peer"))
}

fn interface_matches_filter(name: &str, filter: Option<&str>) -> bool {
    filter.is_none_or(|needle| {
        name.to_ascii_lowercase()
            .contains(&needle.to_ascii_lowercase())
    })
}

fn interface_matches_burst_filter(
    name: &str,
    burst_active: bool,
    pr_burst_active: bool,
    args: &Args,
) -> bool {
    if !args.burst {
        return interface_matches_filter(name, args.filter.as_deref());
    }

    burst_active
        || pr_burst_active
        || args.filter.as_deref().is_some_and(|filter| {
            name.to_ascii_lowercase()
                .contains(&filter.to_ascii_lowercase())
        })
}

fn filtered_local_stats<'a>(
    stats: &'a [rpc::InterfaceStatEntry],
    args: &Args,
) -> Vec<&'a rpc::InterfaceStatEntry> {
    let mut entries: Vec<_> = stats
        .iter()
        .filter(|entry| args.all || visible_by_default(&entry.name))
        .filter(|entry| {
            interface_matches_burst_filter(
                &entry.name,
                entry.burst_active,
                entry.pr_burst_active,
                args,
            )
        })
        .collect();
    if let Ok(Some(key)) = parse_sort_key(args.sort.as_deref()) {
        entries.sort_by(|a, b| {
            let ord = local_stat_sort_value(a, key)
                .partial_cmp(&local_stat_sort_value(b, key))
                .unwrap_or(std::cmp::Ordering::Equal);
            if args.reverse { ord } else { ord.reverse() }
        });
    }
    entries
}

fn print_local_human(stats: &[rpc::InterfaceStatEntry], link_count: Option<i64>, args: &Args) {
    println!(
        "Reticulum Status [rnstatus-rs {}]",
        env!("CARGO_PKG_VERSION")
    );
    println!();

    let entries = filtered_local_stats(stats, args);
    if entries.is_empty() {
        println!("  No interfaces.");
    } else {
        for entry in entries {
            let status = if entry.online { "Up" } else { "Down" };
            println!("  {}", entry.name);
            println!("    Status   : {status}");
            println!("    Mode     : {}", entry.mode);
            println!("    Role     : {}", entry.role);
            println!("    Bitrate  : {}", format::pretty_speed(entry.bitrate));
            println!("    MTU      : {} B", entry.mtu);
            if let Some(clients) = entry.clients {
                println!("    Clients  : {clients}");
            }
            if entry.ifac_size > 0 {
                println!("    IFAC     : {} bits", entry.ifac_size * 8);
            }
            if args.announce_stats {
                if let Some(queued) = entry.announce_queue {
                    if queued > 0 {
                        println!(
                            "    Queued   : {queued} announce{}",
                            if queued == 1 { "" } else { "s" }
                        );
                    }
                }
                if entry.held_announces > 0 {
                    println!(
                        "    Held     : {} announce{}",
                        entry.held_announces,
                        if entry.held_announces == 1 { "" } else { "s" }
                    );
                }
                if entry.incoming_announce_frequency > 0.0
                    || entry.outgoing_announce_frequency > 0.0
                    || entry.burst_active
                {
                    print_announce_frequency(
                        entry.incoming_announce_frequency,
                        entry.outgoing_announce_frequency,
                        entry.clients,
                        entry.announce_rate_target,
                        entry.announce_rate_penalty,
                        entry.announce_rate_grace,
                        burst_status_text(entry.burst_active, entry.burst_activated),
                    );
                }
            }
            if args.pr_stats {
                print_path_request_frequency(
                    entry.incoming_pr_frequency,
                    entry.outgoing_pr_frequency,
                    entry.clients,
                    burst_status_text(entry.pr_burst_active, entry.pr_burst_activated),
                );
            }
            println!(
                "    Traffic  : {} rx / {} tx",
                format::pretty_size(entry.rx_bytes),
                format::pretty_size(entry.tx_bytes)
            );
            if entry.rx_rate > 0 || entry.tx_rate > 0 {
                println!(
                    "    Rates    : {} rx / {} tx",
                    format::pretty_speed(entry.rx_rate),
                    format::pretty_speed(entry.tx_rate)
                );
            }
            if entry.tx_drops > 0 {
                println!("    TX drops : {}", entry.tx_drops);
            }
            println!();
        }
    }

    if args.totals {
        let (rxb, txb) = stats
            .iter()
            .fold((0u64, 0u64), |(r, t), e| (r + e.rx_bytes, t + e.tx_bytes));
        println!("  Totals:");
        println!("    RX : {}", format::pretty_size(rxb));
        println!("    TX : {}", format::pretty_size(txb));
        println!();
    }

    if let Some(n) = link_count {
        println!("  Active links: {n}");
    }
}

fn print_local_json(stats: &[rpc::InterfaceStatEntry], link_count: Option<i64>, args: &Args) {
    let (total_rxb, total_txb) = stats
        .iter()
        .fold((0u64, 0u64), |(r, t), e| (r + e.rx_bytes, t + e.tx_bytes));
    let entries = filtered_local_stats(stats, args);

    print!("{{\"interfaces\":[");
    for (i, e) in entries.iter().enumerate() {
        if i > 0 {
            print!(",");
        }
        print!(
            "{{\"name\":{},\"online\":{},\"mode\":{},\"role\":{},\"bitrate\":{},\"mtu\":{},\"rxb\":{},\"txb\":{},\"rxs\":{},\"txs\":{},\"announce_queue\":{},\"held_announces\":{},\"incoming_announce_frequency\":{},\"outgoing_announce_frequency\":{},\"incoming_pr_frequency\":{},\"outgoing_pr_frequency\":{},\"burst_active\":{},\"burst_activated\":{},\"pr_burst_active\":{},\"pr_burst_activated\":{},\"clients\":{},\"announce_rate_target\":{},\"announce_rate_grace\":{},\"announce_rate_penalty\":{},\"tx_drops\":{}}}",
            json_str(&e.name),
            e.online,
            json_str(&e.mode),
            json_str(&e.role),
            e.bitrate,
            e.mtu,
            e.rx_bytes,
            e.tx_bytes,
            e.rx_rate,
            e.tx_rate,
            e.announce_queue
                .map(|v| v.to_string())
                .unwrap_or_else(|| "null".to_string()),
            e.held_announces,
            e.incoming_announce_frequency,
            e.outgoing_announce_frequency,
            e.incoming_pr_frequency,
            e.outgoing_pr_frequency,
            e.burst_active,
            e.burst_activated,
            e.pr_burst_active,
            e.pr_burst_activated,
            opt_u64_json(e.clients),
            opt_f64_json(e.announce_rate_target),
            opt_u32_json(e.announce_rate_grace),
            opt_f64_json(e.announce_rate_penalty),
            e.tx_drops,
        );
    }
    print!("]");
    if args.totals {
        print!(",\"rxb_total\":{total_rxb},\"txb_total\":{total_txb}");
    }
    if let Some(n) = link_count {
        print!(",\"link_count\":{n}");
    }
    println!("}}");
}

fn print_discovered_interfaces(config_dir: &Path, rc: &ReticulumConfig, args: &Args) -> ExitCode {
    let paths = StoragePaths::from_config_dir(config_dir);
    let store = match DiscoveryStore::open(&paths.storage_dir) {
        Ok(store) => store,
        Err(e) => {
            eprintln!("rnstatus-rs: could not open discovery store: {e}");
            return ExitCode::from(1);
        }
    };
    let sources = if rc.interface_discovery_sources.is_empty() {
        None
    } else {
        Some(rc.interface_discovery_sources.as_slice())
    };
    let mut records = match store.list(sources) {
        Ok(records) => records,
        Err(e) => {
            eprintln!("rnstatus-rs: could not read discovered interfaces: {e}");
            return ExitCode::from(1);
        }
    };
    records.retain(|record| interface_matches_filter(&record.info.name, args.filter.as_deref()));

    if args.json {
        let value = records
            .iter()
            .map(discovered_json)
            .collect::<Vec<serde_json::Value>>();
        println!("{}", serde_json::Value::Array(value));
        return ExitCode::SUCCESS;
    }

    if args.discovered_details {
        print_discovered_details(&records);
    } else {
        print_discovered_summary(&records);
    }
    ExitCode::SUCCESS
}

fn discovered_json(record: &DiscoveredInterface) -> serde_json::Value {
    let info = &record.info;
    json!({
        "name": info.name,
        "type": info.interface_type,
        "status": record.status.map(|s| s.as_str()).unwrap_or("unknown"),
        "transport": info.transport_enabled,
        "transport_id": hex::encode(info.transport_id),
        "network_id": hex::encode(record.network_id),
        "hops": record.hops,
        "value": record.stamp_value,
        "discovered": record.discovered,
        "last_heard": record.last_heard,
        "heard_count": record.heard_count,
        "latitude": finite_location(info.latitude),
        "longitude": finite_location(info.longitude),
        "height": finite_location(info.height),
        "reachable_on": info.reachable_on,
        "port": info.port,
        "frequency": info.frequency,
        "bandwidth": info.bandwidth,
        "sf": info.spreading_factor,
        "cr": info.coding_rate,
        "modulation": info.modulation,
        "channel": info.channel,
        "config_entry": discovered_config_entry(record),
    })
}

fn finite_location(value: f64) -> Option<f64> {
    value.is_finite().then_some(value)
}

fn print_discovered_summary(records: &[DiscoveredInterface]) {
    if records.is_empty() {
        println!("No discovered interfaces.");
        return;
    }
    println!(
        "{:<25} {:<18} {:<10} {:<12} {:<8} Location",
        "Name", "Type", "Status", "Last Heard", "Value"
    );
    println!("{}", "-".repeat(92));
    let now = unix_now_secs();
    for record in records {
        let info = &record.info;
        let status = record.status.map(|s| s.as_str()).unwrap_or("unknown");
        let location = location_summary(info.latitude, info.longitude, info.height);
        println!(
            "{:<25} {:<18} {:<10} {:<12} {:<8} {}",
            truncate_ascii(&info.name, 25),
            truncate_ascii(&info.interface_type.replace("Interface", ""), 18),
            status,
            age_label(now, record.last_heard),
            record.stamp_value,
            location
        );
    }
}

fn print_discovered_details(records: &[DiscoveredInterface]) {
    if records.is_empty() {
        println!("No discovered interfaces.");
        return;
    }
    let now = unix_now_secs();
    for (idx, record) in records.iter().enumerate() {
        if idx > 0 {
            println!("\n{}\n", "=".repeat(32));
        }
        let info = &record.info;
        println!("Name         : {}", info.name);
        println!("Type         : {}", info.interface_type);
        println!(
            "Status       : {}",
            record.status.map(|s| s.as_str()).unwrap_or("unknown")
        );
        println!(
            "Transport    : {}",
            if info.transport_enabled {
                "Enabled"
            } else {
                "Disabled"
            }
        );
        println!("Transport ID : {}", hex::encode(info.transport_id));
        if record.network_id != info.transport_id {
            println!("Network ID   : {}", hex::encode(record.network_id));
        }
        println!(
            "Distance     : {} hop{}",
            record.hops,
            if record.hops == 1 { "" } else { "s" }
        );
        println!("Discovered   : {} ago", age_label(now, record.discovered));
        println!("Last Heard   : {} ago", age_label(now, record.last_heard));
        println!(
            "Location     : {}",
            location_summary(info.latitude, info.longitude, info.height)
        );
        if let Some(freq) = info.frequency {
            println!("Frequency    : {freq} Hz");
        }
        if let Some(bw) = info.bandwidth {
            println!("Bandwidth    : {bw} Hz");
        }
        if let Some(sf) = info.spreading_factor {
            println!("Sprd. Factor : {sf}");
        }
        if let Some(cr) = info.coding_rate {
            println!("Coding Rate  : {cr}");
        }
        if let Some(modu) = &info.modulation {
            println!("Modulation   : {modu}");
        }
        if let Some(ch) = info.channel {
            println!("Channel      : {ch}");
        }
        if let Some(addr) = &info.reachable_on {
            println!("Address      : {addr}");
        }
        if let Some(port) = info.port {
            println!("Port         : {port}");
        }
        println!("Stamp Value  : {}", record.stamp_value);
        println!("\nConfiguration Entry:");
        for line in discovered_config_entry(record).lines() {
            println!("  {line}");
        }
    }
}

fn discovered_config_entry(record: &DiscoveredInterface) -> String {
    let info = &record.info;
    let mut lines = vec![
        format!("[[{}]]", info.name),
        format!("type = {}", info.interface_type),
        "interface_enabled = True".to_string(),
        format!(
            "transport = {}",
            if info.transport_enabled {
                "True"
            } else {
                "False"
            }
        ),
    ];
    if let Some(addr) = &info.reachable_on {
        lines.push(format!("target_host = {addr}"));
    }
    if let Some(port) = info.port {
        lines.push(format!("target_port = {port}"));
    }
    if let Some(freq) = info.frequency {
        lines.push(format!("frequency = {freq}"));
    }
    if let Some(bw) = info.bandwidth {
        lines.push(format!("bandwidth = {bw}"));
    }
    if let Some(sf) = info.spreading_factor {
        lines.push(format!("spreading_factor = {sf}"));
    }
    if let Some(cr) = info.coding_rate {
        lines.push(format!("coding_rate = {cr}"));
    }
    if let Some(modu) = &info.modulation {
        lines.push(format!("modulation = {modu}"));
    }
    if let Some(ch) = info.channel {
        lines.push(format!("channel = {ch}"));
    }
    if let Some(netname) = &info.ifac_netname {
        lines.push(format!("ifac_netname = {netname}"));
    }
    lines.join("\n")
}

fn location_summary(latitude: f64, longitude: f64, height: f64) -> String {
    if latitude == 0.0 && longitude == 0.0 {
        return "N/A".to_string();
    }
    if height != 0.0 {
        format!("{latitude:.4}, {longitude:.4}, {height:.0}m h")
    } else {
        format!("{latitude:.4}, {longitude:.4}")
    }
}

fn truncate_ascii(s: &str, max_chars: usize) -> String {
    if s.chars().count() <= max_chars {
        return s.to_string();
    }
    s.chars()
        .take(max_chars.saturating_sub(3))
        .collect::<String>()
        + "..."
}

fn age_label(now: u64, timestamp: u64) -> String {
    let diff = now.saturating_sub(timestamp);
    if diff < 60 {
        "0s".to_string()
    } else if diff < 3600 {
        format!("{}m", diff / 60)
    } else if diff < 86400 {
        format!("{}h", diff / 3600)
    } else {
        format!("{}d", diff / 86400)
    }
}

fn unix_now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

async fn run_remote(args: Args) -> ExitCode {
    run_remote_once(&args).await
}

async fn run_remote_once(args: &Args) -> ExitCode {
    let remote_hex = args.remote.as_deref().expect("checked in main");
    let remote_hash = match hash::parse_dest_hash(remote_hex) {
        Ok(h) => h,
        Err(e) => {
            eprintln!("rnstatus-rs: --remote: {e}");
            return ExitCode::from(2);
        }
    };

    let identity_path = match args.identity.as_ref() {
        Some(p) => p.clone(),
        None => {
            eprintln!("rnstatus-rs: --remote requires --identity <path>.");
            return ExitCode::from(2);
        }
    };
    let identity = match rns_identity::identity::Identity::from_file(&identity_path) {
        Ok(id) => id,
        Err(e) => {
            eprintln!(
                "rnstatus-rs: could not load identity from {}: {e:?}",
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
            eprintln!("rnstatus-rs: failed to initialize Reticulum runtime: {e:?}");
            return ExitCode::from(1);
        }
    };

    let timeout = Duration::from_secs(args.timeout.unwrap_or(REMOTE_TIMEOUT_SECS));

    // Wire format: msgpack 1-tuple `(include_link_count,)`.
    let payload = match rmp_serde::to_vec(&(args.link_stats,)) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("rnstatus-rs: msgpack encode failed: {e}");
            shutdown.trigger();
            return ExitCode::from(1);
        }
    };

    let client = LinkClient::new(handle.transport_tx.clone(), identity);
    let response_bytes = match client
        .query(
            remote_hash,
            MGMT_APP,
            "/status",
            payload,
            REMOTE_HOPS,
            timeout,
        )
        .await
    {
        Ok(b) => b,
        Err(e) => {
            eprintln!("rnstatus-rs: remote query failed: {}", remote_err(&e));
            shutdown.trigger();
            return match e {
                LinkClientError::Timeout(_) => ExitCode::from(124),
                _ => ExitCode::from(1),
            };
        }
    };

    let exit = print_remote_status(&response_bytes, args);
    shutdown.trigger();
    exit
}

#[derive(Debug, Clone)]
struct RemoteInterface {
    name: String,
    online: bool,
    mode: u64,
    bitrate: u64,
    rxb: u64,
    txb: u64,
    rxs: u64,
    txs: u64,
    announce_queue: Option<u64>,
    held_announces: u64,
    incoming_announce_frequency: f64,
    outgoing_announce_frequency: f64,
    incoming_pr_frequency: f64,
    outgoing_pr_frequency: f64,
    burst_active: bool,
    burst_activated: f64,
    pr_burst_active: bool,
    pr_burst_activated: f64,
    clients: Option<u64>,
    announce_rate_target: Option<f64>,
    announce_rate_grace: Option<u32>,
    announce_rate_penalty: Option<f64>,
}

impl RemoteInterface {
    fn sort_value(&self, key: SortKey) -> f64 {
        match key {
            SortKey::Rate => self.bitrate as f64,
            SortKey::Rx => self.rxb as f64,
            SortKey::Tx => self.txb as f64,
            SortKey::RxRate => self.rxs as f64,
            SortKey::TxRate => self.txs as f64,
            SortKey::Traffic => self.rxb.saturating_add(self.txb) as f64,
            SortKey::Announces => {
                self.incoming_announce_frequency + self.outgoing_announce_frequency
            }
            SortKey::AnnounceRx => self.incoming_announce_frequency,
            SortKey::AnnounceTx => self.outgoing_announce_frequency,
            SortKey::PathRequestRx => self.incoming_pr_frequency,
            SortKey::PathRequestTx => self.outgoing_pr_frequency,
            SortKey::Held => self.held_announces as f64,
        }
    }
}

// Wire format: outer array is [stats] or [stats, link_count].
fn print_remote_status(bytes: &[u8], args: &Args) -> ExitCode {
    let value: rmpv::Value = match rmp_serde::from_slice(bytes) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("rnstatus-rs: malformed response: {e}");
            return ExitCode::from(1);
        }
    };
    let arr = match value.as_array() {
        Some(a) => a,
        None => {
            eprintln!("rnstatus-rs: response is not a msgpack array");
            return ExitCode::from(1);
        }
    };
    let stats = match arr.first().and_then(|v| v.as_map()) {
        Some(m) => m,
        None => {
            eprintln!("rnstatus-rs: response missing stats dict");
            return ExitCode::from(1);
        }
    };
    let link_count = arr.get(1).and_then(|v| v.as_u64());

    let interfaces = stats
        .iter()
        .find(|(k, _)| k.as_str() == Some("interfaces"))
        .and_then(|(_, v)| v.as_array());
    let total_rxb = stats
        .iter()
        .find(|(k, _)| k.as_str() == Some("rxb"))
        .and_then(|(_, v)| v.as_u64())
        .unwrap_or(0);
    let total_txb = stats
        .iter()
        .find(|(k, _)| k.as_str() == Some("txb"))
        .and_then(|(_, v)| v.as_u64())
        .unwrap_or(0);

    let mut parsed_interfaces = interfaces
        .map(|ifs| {
            ifs.iter()
                .filter_map(|iface| iface.as_map().map(|m| remote_interface_from_map(m)))
                .filter(|iface| args.all || visible_by_default(&iface.name))
                .filter(|iface| {
                    interface_matches_burst_filter(
                        &iface.name,
                        iface.burst_active,
                        iface.pr_burst_active,
                        args,
                    )
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    if let Ok(Some(key)) = parse_sort_key(args.sort.as_deref()) {
        parsed_interfaces.sort_by(|a, b| {
            let ord = a
                .sort_value(key)
                .partial_cmp(&b.sort_value(key))
                .unwrap_or(std::cmp::Ordering::Equal);
            if args.reverse { ord } else { ord.reverse() }
        });
    }

    if args.json {
        print!("{{");
        print!("\"interfaces\":[");
        for (i, iface) in parsed_interfaces.iter().enumerate() {
            if i > 0 {
                print!(",");
            }
            print!(
                "{{\"name\":{},\"online\":{},\"mode\":{},\"bitrate\":{},\"rxb\":{},\"txb\":{},\"rxs\":{},\"txs\":{},\"announce_queue\":{},\"held_announces\":{},\"incoming_announce_frequency\":{},\"outgoing_announce_frequency\":{},\"incoming_pr_frequency\":{},\"outgoing_pr_frequency\":{},\"burst_active\":{},\"burst_activated\":{},\"pr_burst_active\":{},\"pr_burst_activated\":{},\"clients\":{},\"announce_rate_target\":{},\"announce_rate_grace\":{},\"announce_rate_penalty\":{}}}",
                json_str(&iface.name),
                iface.online,
                iface.mode,
                iface.bitrate,
                iface.rxb,
                iface.txb,
                iface.rxs,
                iface.txs,
                iface
                    .announce_queue
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "null".to_string()),
                iface.held_announces,
                iface.incoming_announce_frequency,
                iface.outgoing_announce_frequency,
                iface.incoming_pr_frequency,
                iface.outgoing_pr_frequency,
                iface.burst_active,
                iface.burst_activated,
                iface.pr_burst_active,
                iface.pr_burst_activated,
                opt_u64_json(iface.clients),
                opt_f64_json(iface.announce_rate_target),
                opt_u32_json(iface.announce_rate_grace),
                opt_f64_json(iface.announce_rate_penalty),
            );
        }
        print!("]");
        if args.totals {
            print!(",\"rxb_total\":{total_rxb},\"txb_total\":{total_txb}");
        }
        if let Some(n) = link_count {
            print!(",\"link_count\":{n}");
        }
        println!("}}");
        return ExitCode::SUCCESS;
    }

    println!("Remote Reticulum Status");
    println!();

    if !parsed_interfaces.is_empty() {
        for iface in &parsed_interfaces {
            let status = if iface.online { "Up" } else { "Down" };
            println!("  {}", iface.name);
            println!("    Status   : {status}");
            println!("    Mode     : 0x{:02x}", iface.mode);
            println!("    Bitrate  : {}", format::pretty_speed(iface.bitrate));
            if let Some(clients) = iface.clients {
                println!("    Clients  : {clients}");
            }
            if args.announce_stats {
                if let Some(queued) = iface.announce_queue {
                    if queued > 0 {
                        println!(
                            "    Queued   : {queued} announce{}",
                            if queued == 1 { "" } else { "s" }
                        );
                    }
                }
                if iface.held_announces > 0 {
                    println!(
                        "    Held     : {} announce{}",
                        iface.held_announces,
                        if iface.held_announces == 1 { "" } else { "s" }
                    );
                }
                if iface.incoming_announce_frequency > 0.0
                    || iface.outgoing_announce_frequency > 0.0
                    || iface.burst_active
                {
                    print_announce_frequency(
                        iface.incoming_announce_frequency,
                        iface.outgoing_announce_frequency,
                        iface.clients,
                        iface.announce_rate_target,
                        iface.announce_rate_penalty,
                        iface.announce_rate_grace,
                        burst_status_text(iface.burst_active, iface.burst_activated),
                    );
                }
            }
            if args.pr_stats {
                print_path_request_frequency(
                    iface.incoming_pr_frequency,
                    iface.outgoing_pr_frequency,
                    iface.clients,
                    burst_status_text(iface.pr_burst_active, iface.pr_burst_activated),
                );
            }
            println!(
                "    Traffic  : {} rx / {} tx",
                format::pretty_size(iface.rxb),
                format::pretty_size(iface.txb)
            );
            if iface.rxs > 0 || iface.txs > 0 {
                println!(
                    "    Rates    : {} rx / {} tx",
                    format::pretty_speed(iface.rxs),
                    format::pretty_speed(iface.txs)
                );
            }
            println!();
        }
    } else {
        println!("  No interfaces reported.");
    }

    if args.totals {
        println!("  Totals:");
        println!("    RX : {}", format::pretty_size(total_rxb));
        println!("    TX : {}", format::pretty_size(total_txb));
        println!();
    }
    if let Some(n) = link_count {
        println!("  Active links: {n}");
    }

    ExitCode::SUCCESS
}

fn remote_interface_from_map(m: &[(rmpv::Value, rmpv::Value)]) -> RemoteInterface {
    RemoteInterface {
        name: map_str(m, "name").unwrap_or_else(|| "(unnamed)".to_string()),
        online: map_bool(m, "status")
            .or_else(|| map_bool(m, "online"))
            .unwrap_or(false),
        mode: map_u64(m, "mode").unwrap_or(0),
        bitrate: map_u64(m, "bitrate").unwrap_or(0),
        rxb: map_u64(m, "rxb").unwrap_or(0),
        txb: map_u64(m, "txb").unwrap_or(0),
        rxs: map_u64(m, "rxs").unwrap_or(0),
        txs: map_u64(m, "txs").unwrap_or(0),
        announce_queue: map_u64(m, "announce_queue"),
        held_announces: map_u64(m, "held_announces").unwrap_or(0),
        incoming_announce_frequency: map_f64_or_u64(m, "incoming_announce_frequency")
            .unwrap_or(0.0),
        outgoing_announce_frequency: map_f64_or_u64(m, "outgoing_announce_frequency")
            .unwrap_or(0.0),
        incoming_pr_frequency: map_f64_or_u64(m, "incoming_pr_frequency").unwrap_or(0.0),
        outgoing_pr_frequency: map_f64_or_u64(m, "outgoing_pr_frequency").unwrap_or(0.0),
        burst_active: map_bool(m, "burst_active").unwrap_or(false),
        burst_activated: map_f64_or_u64(m, "burst_activated").unwrap_or(0.0),
        pr_burst_active: map_bool(m, "pr_burst_active").unwrap_or(false),
        pr_burst_activated: map_f64_or_u64(m, "pr_burst_activated").unwrap_or(0.0),
        clients: map_u64(m, "clients"),
        announce_rate_target: map_f64_or_u64(m, "announce_rate_target"),
        announce_rate_grace: map_u64(m, "announce_rate_grace")
            .map(|v| v.min(u32::MAX as u64) as u32),
        announce_rate_penalty: map_f64_or_u64(m, "announce_rate_penalty"),
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

fn map_f64_or_u64(map: &[(rmpv::Value, rmpv::Value)], key: &str) -> Option<f64> {
    map.iter()
        .find(|(k, _)| k.as_str() == Some(key))
        .and_then(|(_, v)| v.as_f64().or_else(|| v.as_u64().map(|n| n as f64)))
}

fn map_bool(map: &[(rmpv::Value, rmpv::Value)], key: &str) -> Option<bool> {
    map.iter()
        .find(|(k, _)| k.as_str() == Some(key))
        .and_then(|(_, v)| v.as_bool())
}

fn print_announce_frequency(
    incoming: f64,
    outgoing: f64,
    clients: Option<u64>,
    target: Option<f64>,
    penalty: Option<f64>,
    grace: Option<u32>,
    burst_text: String,
) {
    let outgoing_text = format!("{}↑", format::pretty_frequency(outgoing));
    let incoming_text = format!("{}↓", format::pretty_frequency(incoming));
    let per_client = clients
        .filter(|clients| *clients > 0)
        .map(|clients| format!(" {}/c", format::pretty_frequency(outgoing / clients as f64)))
        .unwrap_or_default();
    let limits = announce_rate_limits_text(target, penalty, grace);
    println!("    Announces: {outgoing_text}{per_client}");
    println!("               {incoming_text} {limits}{burst_text}");
}

fn print_path_request_frequency(
    incoming: f64,
    outgoing: f64,
    clients: Option<u64>,
    burst_text: String,
) {
    let outgoing_text = format!("{}↑", format::pretty_frequency(outgoing));
    let incoming_text = format!("{}↓", format::pretty_frequency(incoming));
    let per_client = clients
        .filter(|clients| *clients > 0)
        .map(|clients| format!(" {}/c", format::pretty_frequency(outgoing / clients as f64)))
        .unwrap_or_default();
    println!("    Path Rqs.: {outgoing_text}{per_client}");
    println!("               {incoming_text} {burst_text}");
}

fn burst_status_text(active: bool, activated: f64) -> String {
    if !active || activated <= 0.0 {
        return String::new();
    }
    let age = (unix_now() - activated).max(0.0);
    format!(" burst for {}", format::pretty_time(age))
}

fn unix_now() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64()
}

fn announce_rate_limits_text(
    target: Option<f64>,
    penalty: Option<f64>,
    grace: Option<u32>,
) -> String {
    match (target, penalty, grace) {
        (Some(t), Some(p), Some(g)) if t > 0.0 => {
            format!(
                "(t:{}/p:{}/g:{g})",
                format::pretty_time(t),
                format::pretty_time(p)
            )
        }
        (Some(t), Some(p), _) if t > 0.0 => {
            format!(
                "(t:{}/p:{})",
                format::pretty_time(t),
                format::pretty_time(p)
            )
        }
        (Some(t), _, _) if t > 0.0 => format!("(t:{})", format::pretty_time(t)),
        _ => String::new(),
    }
}

fn opt_u64_json(value: Option<u64>) -> String {
    value
        .map(|v| v.to_string())
        .unwrap_or_else(|| "null".to_string())
}

fn opt_u32_json(value: Option<u32>) -> String {
    value
        .map(|v| v.to_string())
        .unwrap_or_else(|| "null".to_string())
}

fn opt_f64_json(value: Option<f64>) -> String {
    value
        .map(|v| v.to_string())
        .unwrap_or_else(|| "null".to_string())
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

fn json_str(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_args() -> Args {
        Args {
            all: true,
            announce_stats: false,
            pr_stats: false,
            link_stats: false,
            burst: false,
            totals: false,
            sort: None,
            reverse: false,
            json: false,
            config: None,
            remote: None,
            identity: None,
            timeout: None,
            discovered: false,
            discovered_details: false,
            monitor: false,
            monitor_interval: 1.0,
            version: false,
            verbose: 0,
            quiet: 0,
            filter: None,
        }
    }

    fn local_entry(
        name: &str,
        burst_active: bool,
        pr_burst_active: bool,
    ) -> rpc::InterfaceStatEntry {
        rpc::InterfaceStatEntry {
            id: 1,
            name: name.to_string(),
            rx_bytes: 0,
            tx_bytes: 0,
            rx_rate: 0,
            tx_rate: 0,
            online: true,
            bitrate: 1,
            mtu: 500,
            mode: "Full".to_string(),
            role: "normal".to_string(),
            announce_queue: None,
            held_announces: 0,
            incoming_announce_frequency: 0.0,
            outgoing_announce_frequency: 0.0,
            incoming_pr_frequency: 2.0,
            outgoing_pr_frequency: 3.0,
            burst_active,
            burst_activated: if burst_active { 1_700_000_000.0 } else { 0.0 },
            pr_burst_active,
            pr_burst_activated: if pr_burst_active {
                1_700_000_001.0
            } else {
                0.0
            },
            clients: None,
            announce_rate_target: None,
            announce_rate_grace: None,
            announce_rate_penalty: None,
            announce_cap: 0.0,
            ifac_size: 0,
            tx_drops: 0,
        }
    }

    #[test]
    fn sort_key_accepts_path_request_rates() {
        assert_eq!(
            parse_sort_key(Some("prx")).unwrap(),
            Some(SortKey::PathRequestRx)
        );
        assert_eq!(
            parse_sort_key(Some("ptx")).unwrap(),
            Some(SortKey::PathRequestTx)
        );

        let entry = local_entry("SortIf", false, false);
        assert_eq!(local_stat_sort_value(&entry, SortKey::PathRequestRx), 2.0);
        assert_eq!(local_stat_sort_value(&entry, SortKey::PathRequestTx), 3.0);
    }

    #[test]
    fn pr_and_burst_flags_parse() {
        let args = Args::try_parse_from(["rnstatus-rs", "-P", "-B"]).unwrap();
        assert!(args.pr_stats);
        assert!(args.burst);
    }

    #[test]
    fn burst_filter_includes_active_bursts_or_name_matches() {
        let stats = vec![
            local_entry("InactiveIf", false, false),
            local_entry("AnnounceBurstIf", true, false),
            local_entry("PrBurstIf", false, true),
            local_entry("ManualMatchIf", false, false),
        ];
        let mut args = test_args();
        args.burst = true;
        args.filter = Some("manual".to_string());

        let names: Vec<_> = filtered_local_stats(&stats, &args)
            .into_iter()
            .map(|entry| entry.name.as_str())
            .collect();

        assert_eq!(names, vec!["AnnounceBurstIf", "PrBurstIf", "ManualMatchIf"]);
    }

    #[test]
    fn remote_status_parser_defaults_missing_125_fields() {
        let iface = remote_interface_from_map(&[
            (rmpv::Value::from("name"), rmpv::Value::from("LegacyIf")),
            (rmpv::Value::from("status"), rmpv::Value::from(true)),
        ]);

        assert_eq!(iface.incoming_pr_frequency, 0.0);
        assert_eq!(iface.outgoing_pr_frequency, 0.0);
        assert!(!iface.burst_active);
        assert_eq!(iface.burst_activated, 0.0);
        assert!(!iface.pr_burst_active);
        assert_eq!(iface.pr_burst_activated, 0.0);
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
