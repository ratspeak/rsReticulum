//! rnprobe-rs — send PROBE packets, measure RTT.
//!
//! Exit codes: 0 all delivered, 1 path timeout, 2 packet loss, 3 size > MTU.

use std::process;
use std::time::Duration;

use clap::Parser;

use rns_runtime::probe::{
    ProbeError, ProbeOutcome, default_probe_app_name, parse_dest_hash, probe_once,
};

const DEFAULT_PROBE_SIZE: usize = 16;
use rns_tools::RS_RETICULUM_VERSION;

#[derive(Parser)]
#[command(
    name = "rnprobe-rs",
    about = "Reticulum Probe Utility",
    disable_version_flag = true
)]
struct Args {
    /// Path to alternative Reticulum config directory
    #[arg(long)]
    config: Option<String>,

    /// Size of probe packet payload in bytes
    #[arg(short = 's', long)]
    size: Option<usize>,

    /// Number of probes to send
    #[arg(short = 'n', long, default_value_t = 1)]
    probes: u32,

    /// Timeout before giving up (seconds)
    #[arg(short = 't', long, value_name = "seconds")]
    timeout: Option<f64>,

    /// Time between each probe (seconds)
    #[arg(short = 'w', long, default_value_t = 0.0, value_name = "seconds")]
    wait: f64,

    /// Output one JSON object per probe to stdout (machine-readable)
    #[arg(long)]
    json: bool,

    /// Increase verbosity
    #[arg(short = 'v', long, action = clap::ArgAction::Count)]
    verbose: u8,

    /// Print version and exit.
    #[arg(long)]
    version: bool,

    /// Full destination name in dotted notation (e.g. `rnstransport.probe`)
    full_name: Option<String>,

    /// Hexadecimal hash of the destination (32 hex chars)
    destination_hash: Option<String>,
}

#[tokio::main]
pub(crate) async fn main() {
    let args = Args::parse();
    if args.version {
        println!("rnprobe-rs {RS_RETICULUM_VERSION}");
        return;
    }

    let Some(dest_hex) = args.destination_hash.clone() else {
        // Print help on missing args (don't error).
        let mut cmd = <Args as clap::CommandFactory>::command();
        cmd.print_help().ok();
        println!();
        return;
    };

    let level = match args.verbose {
        0 => tracing::Level::WARN,
        1 => tracing::Level::INFO,
        _ => tracing::Level::DEBUG,
    };
    let config_dir = rns_runtime::platform::resolve_config_dir(args.config.as_deref());
    rns_tools::init_tracing(
        level,
        rns_tools::config_log_timestamps(&config_dir),
        true,
        std::io::stderr,
    );

    let full_name = args
        .full_name
        .clone()
        .unwrap_or_else(|| default_probe_app_name().to_string());

    let dest_hash = match parse_dest_hash(&dest_hex) {
        Ok(h) => h,
        Err(_) => {
            eprintln!(
                "Destination length is invalid, must be 32 hexadecimal characters (16 bytes)."
            );
            process::exit(1);
        }
    };

    let size = args.size.unwrap_or(DEFAULT_PROBE_SIZE);
    // None = Python default: 12 s + first-hop timeout, resolved per wait.
    let timeout = args.timeout.map(Duration::from_secs_f64);
    let wait = Duration::from_secs_f64(args.wait.max(0.0));

    let shutdown = rns_runtime::lifecycle::ShutdownSignal::new();
    let _signal_rx = rns_runtime::lifecycle::install_signal_handlers(shutdown.clone());
    let is_foreground = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
    let handle = match rns_runtime::reticulum::init(
        args.config.as_deref(),
        None,
        shutdown.clone(),
        is_foreground,
    )
    .await
    {
        Ok(h) => h,
        Err(e) => {
            eprintln!("failed to start reticulum: {e}");
            process::exit(1);
        }
    };

    let mut sent: u32 = 0;
    let mut replies: u32 = 0;
    let mut first = true;
    let mut remaining = args.probes;

    while remaining > 0 {
        if !first {
            tokio::time::sleep(wait).await;
        }
        first = false;

        sent += 1;
        let result = probe_once(
            handle.transport_tx.clone(),
            dest_hash,
            &full_name,
            size,
            timeout,
            timeout,
            handle.should_use_implicit_proof(),
        )
        .await;

        match result {
            Ok(outcome) => {
                replies += 1;
                if args.json {
                    print_json(sent, size, dest_hash, &full_name, Some(&outcome), None);
                } else {
                    let via = outcome
                        .via
                        .map(|v| format!(" via <{}>", hex::encode(v)))
                        .unwrap_or_default();
                    let iface = outcome
                        .interface
                        .as_deref()
                        .filter(|n| !n.is_empty())
                        .map(|n| format!(" on {n}"))
                        .unwrap_or_default();
                    println!(
                        "Sent probe {sent} ({size} bytes) to <{}>{via}{iface}",
                        hex::encode(dest_hash)
                    );
                    let ms = if outcome.hops == 1 { "" } else { "s" };
                    let rttstring = if outcome.rtt.as_secs_f64() >= 1.0 {
                        format!("{:.3} seconds", outcome.rtt.as_secs_f64())
                    } else {
                        format!("{:.3} milliseconds", outcome.rtt.as_secs_f64() * 1000.0)
                    };
                    println!(
                        "Valid reply from <{}>\nRound-trip time is {} over {} hop{}\n",
                        hex::encode(dest_hash),
                        rttstring,
                        outcome.hops,
                        ms
                    );
                }
            }
            Err(ProbeError::MtuExceeded(s, mtu)) => {
                eprintln!("Error: Probe packet size of {s} bytes exceed MTU of {mtu} bytes");
                process::exit(3);
            }
            Err(ProbeError::PathTimeout) => {
                if args.json {
                    print_json(
                        sent,
                        size,
                        dest_hash,
                        &full_name,
                        None,
                        Some("path_timeout"),
                    );
                } else {
                    println!("Path request timed out");
                }
                process::exit(1);
            }
            Err(ProbeError::NoIdentity) => {
                if args.json {
                    print_json(sent, size, dest_hash, &full_name, None, Some("no_identity"));
                } else {
                    eprintln!(
                        "Destination's identity is not known — wait for an announce or use rnstatus to verify the destination has been seen."
                    );
                }
                process::exit(1);
            }
            Err(ProbeError::PacketTimeout) => {
                if args.json {
                    print_json(
                        sent,
                        size,
                        dest_hash,
                        &full_name,
                        None,
                        Some("packet_timeout"),
                    );
                } else {
                    println!("Probe timed out");
                }
            }
            Err(e) => {
                eprintln!("probe error: {e}");
                process::exit(1);
            }
        }

        remaining -= 1;
    }

    let loss_pct = if sent > 0 {
        (1.0 - (replies as f64 / sent as f64)) * 100.0
    } else {
        0.0
    };
    let loss_rounded = (loss_pct * 100.0).round() / 100.0;
    if !args.json {
        println!("Sent {sent}, received {replies}, packet loss {loss_rounded}%");
    }

    if loss_rounded > 0.0 {
        process::exit(2);
    }
    process::exit(0);
}

fn print_json(
    probe_num: u32,
    size: usize,
    dest_hash: [u8; 16],
    full_name: &str,
    outcome: Option<&ProbeOutcome>,
    error: Option<&str>,
) {
    use std::fmt::Write;
    let mut out = String::new();
    write!(
        out,
        "{{\"probe\":{probe_num},\"size\":{size},\"destination\":\"{}\",\"name\":\"{}\"",
        hex::encode(dest_hash),
        full_name
    )
    .ok();
    if let Some(o) = outcome {
        write!(
            out,
            ",\"status\":\"ok\",\"rtt_ms\":{:.3},\"hops\":{}",
            o.rtt.as_secs_f64() * 1000.0,
            o.hops
        )
        .ok();
        if let Some(via) = o.via {
            write!(out, ",\"via\":\"{}\"", hex::encode(via)).ok();
        }
        if let Some(ref iface) = o.interface {
            write!(out, ",\"interface\":\"{iface}\"").ok();
        }
    } else if let Some(err) = error {
        write!(out, ",\"status\":\"error\",\"error\":\"{err}\"").ok();
    }
    out.push('}');
    println!("{out}");
}
