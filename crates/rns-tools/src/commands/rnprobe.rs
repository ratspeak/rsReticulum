//! rnprobe-rs — send probe packets and measure round-trip time, following
//! `RNS/Utilities/rnprobe.py`.
//!
//! Exit codes: 0 all delivered, 1 path timeout, 2 packet loss, 3 size > MTU.

use std::io::Write;
use std::process;
use std::time::{Duration, Instant};

use bytes::Bytes;
use clap::Parser;
use tokio::sync::watch;

use rns_identity::destination::{
    DestType, Destination, DestinationPacketError, DestinationPacketOptions, Direction,
};
use rns_runtime::reticulum::{InstanceMode, ReticulumHandle};
use rns_tools::RS_RETICULUM_VERSION;
use rns_tools::format::{pretty_hex_rep, py_float_repr, py_round};
use rns_transport::link_messages::PacketMetrics;
use rns_transport::messages::{
    OutboundRequest, PathRequestOptions, ReceiptUpdate, TrackedReceiptRegistration,
    TransportMessage, TransportQuery, TransportQueryResponse,
};
use rns_wire::constants::{DEFAULT_PER_HOP_TIMEOUT, MTU};

const DEFAULT_PROBE_SIZE: usize = 16;
const DEFAULT_TIMEOUT: f64 = 12.0;
const SPINNER: [char; 7] = ['⢄', '⢂', '⢁', '⡁', '⡈', '⡐', '⡠'];
const RST_58: &str = "\r                                                          \r";
const RST_64: &str = "\r                                                                \r";

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

    /// Timeout before giving up
    #[arg(short = 't', long, value_name = "seconds")]
    timeout: Option<f64>,

    /// Time between each probe
    #[arg(short = 'w', long, default_value_t = 0.0, value_name = "seconds")]
    wait: f64,

    /// Print probe results as JSON; some fatal errors are reported only on stderr.
    #[arg(long)]
    json: bool,

    #[arg(short = 'v', long, action = clap::ArgAction::Count)]
    verbose: u8,

    /// Show program's version number and exit
    #[arg(long)]
    version: bool,

    /// Full destination name in dotted notation
    full_name: Option<String>,

    /// Hexadecimal hash of the destination
    destination_hash: Option<String>,
}

#[tokio::main]
pub(crate) async fn main() {
    let args = Args::parse();
    if args.version {
        println!("rnprobe-rs {RS_RETICULUM_VERSION}");
        return;
    }
    exit_silently_on_signal();

    let Some(dest_hex) = args.destination_hash.clone().filter(|d| !d.is_empty()) else {
        let help = <Args as clap::CommandFactory>::command()
            .render_help()
            .to_string();
        println!();
        print!("{help}");
        if !help.ends_with('\n') {
            println!();
        }
        println!();
        return;
    };
    // The single positional fills full_name, so this is unreachable from the CLI.
    let Some(full_name) = args.full_name.clone() else {
        println!(
            "The full destination name including application name aspects must be specified for the destination"
        );
        return;
    };
    // rnprobe.py:57-67: input errors print to stdout and exit 0.
    let dest_hash: [u8; 16] = if dest_hex.chars().count() != 32 {
        println!("Destination length is invalid, must be 32 hexadecimal characters (16 bytes).");
        return;
    } else {
        match hex::decode(&dest_hex).ok().and_then(|b| b.try_into().ok()) {
            Some(hash) => hash,
            None => {
                println!("Invalid destination entered. Check your input.");
                return;
            }
        }
    };

    let level = rns_tools::Utility::Rnprobe.loglevel(None, args.verbose, 0, false);
    let config_dir = rns_runtime::platform::resolve_config_dir(args.config.as_deref());
    rns_tools::init_tracing(
        level,
        rns_tools::config_log_timestamps(&config_dir),
        true,
        std::io::stderr,
    );

    let shutdown = rns_runtime::lifecycle::ShutdownSignal::new();
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
    let code = run(&args, &handle, dest_hash, &full_name).await;
    shutdown.trigger();
    handle.shutdown_and_wait().await;
    process::exit(code);
}

/// Python's `Reticulum.sigint_handler`/`sigterm_handler` end in `os._exit(0)`.
fn exit_silently_on_signal() {
    tokio::spawn(async {
        let _ = tokio::signal::ctrl_c().await;
        process::exit(0);
    });
    #[cfg(unix)]
    if let Ok(mut term) = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
    {
        tokio::spawn(async move {
            term.recv().await;
            process::exit(0);
        });
    }
}

async fn run(args: &Args, handle: &ReticulumHandle, dest_hash: [u8; 16], full_name: &str) -> i32 {
    let json = args.json;
    let size = args.size.unwrap_or(DEFAULT_PROBE_SIZE);
    let timeout = args.timeout.filter(|t| *t != 0.0);

    // rnprobe.py:79-95.
    if !local_has_path(handle, dest_hash).await {
        let _ = handle
            .request_path(dest_hash, PathRequestOptions::default())
            .await;
        if !json {
            print!("Path to {} requested   ", pretty_hex_rep(&dest_hash));
            flush();
        }
    }
    let path_deadline = deadline_after(probe_timeout(handle, dest_hash, timeout).await);
    let mut i = 0;
    while !local_has_path(handle, dest_hash).await && !passed(path_deadline) {
        tokio::time::sleep(Duration::from_millis(100)).await;
        if !json {
            print!("\u{8}\u{8}{} ", SPINNER[i]);
            flush();
        }
        i = (i + 1) % SPINNER.len();
    }
    if passed(path_deadline) {
        if json {
            print_json(1, size, dest_hash, full_name, None, Some("path_timeout"));
        } else {
            println!("{RST_58}Path request timed out");
        }
        return 1;
    }

    let recalled = match handle.recall(dest_hash).await {
        Ok(Some(recalled)) => recalled,
        _ => {
            if json {
                print_json(1, size, dest_hash, full_name, None, Some("no_identity"));
            } else {
                eprintln!(
                    "Destination's identity is not known — wait for an announce or use rnstatus to verify the destination has been seen."
                );
            }
            return 1;
        }
    };
    let destination = match Destination::new(
        Some(&recalled.identity),
        Direction::Out,
        DestType::Single,
        full_name,
    ) {
        Ok(destination) => destination,
        Err(e) => {
            eprintln!("probe error: {e}");
            return 1;
        }
    };

    let wait = Duration::try_from_secs_f64(args.wait.max(0.0)).unwrap_or(Duration::ZERO);
    let mut sent: u32 = 0;
    let mut replies: u32 = 0;
    for _ in 0..args.probes {
        if sent > 0 {
            tokio::time::sleep(wait).await;
        }
        // rnprobe.py:114-119: the packed length is reported.
        let payload = rns_crypto::random::random_bytes(size);
        let packet = match destination.pack_packet(
            &payload,
            Some(&recalled.identity),
            recalled.ratchet.as_ref(),
            DestinationPacketOptions::default(),
        ) {
            Ok(packed) => packed.packet,
            Err(DestinationPacketError::Packet(rns_wire::packet::PacketError::ExceedsMtu(len))) => {
                println!("Error: Probe packet size of {len} bytes exceed MTU of {MTU} bytes");
                return 3;
            }
            Err(e) => {
                eprintln!("probe error: {e}");
                return 1;
            }
        };

        let probe = match send_probe(handle, &packet, &recalled.identity, dest_hash).await {
            Some(probe) => probe,
            None => {
                eprintln!("probe error: transport channel closed");
                return 1;
            }
        };
        sent += 1;

        let (via, interface) = next_hop_info(handle, dest_hash).await;
        if !json {
            let more = if args.verbose > 0 {
                let via_str = via
                    .map(|v| format!(" via {}", pretty_hex_rep(&v)))
                    .unwrap_or_default();
                let if_str = if interface != "None" {
                    format!(" on {interface}")
                } else {
                    String::new()
                };
                format!("{via_str}{if_str}")
            } else {
                String::new()
            };
            print!(
                "\rSent probe {sent} ({size} bytes) to {}{more}   ",
                pretty_hex_rep(&dest_hash)
            );
            flush();
        }

        // rnprobe.py:134-143, and the receipt's own timeout (Packet.py:432-433).
        let probe_deadline = deadline_after(probe_timeout(handle, dest_hash, timeout).await);
        let outcome = probe.wait(probe_deadline, json).await;
        match outcome {
            ProbeResult::TimedOut => {
                if json {
                    print_json(
                        sent,
                        size,
                        dest_hash,
                        full_name,
                        None,
                        Some("packet_timeout"),
                    );
                } else {
                    println!("{RST_64}Probe timed out");
                }
            }
            ProbeResult::Failed => {
                if json {
                    print_json(
                        sent,
                        size,
                        dest_hash,
                        full_name,
                        None,
                        Some("packet_timeout"),
                    );
                } else {
                    println!("\u{8}\u{8} ");
                    println!("{RST_58}Probe timed out");
                }
            }
            ProbeResult::Delivered {
                rtt,
                proof_hash,
                metrics,
            } => {
                replies += 1;
                let hops = local_hops(handle, dest_hash).await;
                if json {
                    let ok = JsonOk {
                        rtt,
                        hops,
                        via,
                        interface: &interface,
                    };
                    print_json(sent, size, dest_hash, full_name, Some(&ok), None);
                } else {
                    println!("\u{8}\u{8} ");
                    let stats = reception_stats(handle, proof_hash, metrics).await;
                    println!(
                        "Valid reply from {}\nRound-trip time is {} over {hops} hop{}{stats}\n",
                        pretty_hex_rep(&dest_hash),
                        rtt_string(rtt),
                        if hops == 1 { "" } else { "s" }
                    );
                }
            }
        }
    }

    if sent == 0 {
        return 0;
    }
    let loss = py_round((1.0 - f64::from(replies) / f64::from(sent)) * 100.0, 2);
    if !json {
        println!(
            "Sent {sent}, received {replies}, packet loss {}%",
            py_float_repr(loss)
        );
    }
    if loss > 0.0 { 2 } else { 0 }
}

enum ProbeResult {
    Delivered {
        rtt: Duration,
        proof_hash: Option<[u8; 32]>,
        metrics: PacketMetrics,
    },
    /// The receipt concluded without a proof (PacketReceipt FAILED or CULLED).
    Failed,
    /// The probe timeout passed first.
    TimedOut,
}

/// One sent probe awaiting its transport receipt (Python `PacketReceipt`).
struct PendingProbe {
    status: watch::Receiver<ReceiptUpdate>,
}

async fn send_probe(
    handle: &ReticulumHandle,
    packet: &rns_wire::packet::Packet,
    identity: &rns_identity::identity::Identity,
    dest_hash: [u8; 16],
) -> Option<PendingProbe> {
    // Packet.py:430-433: first-hop timeout plus TIMEOUT_PER_HOP per hop.
    let first_hop = handle
        .first_hop_timeout(dest_hash)
        .await
        .map(|d| d.as_secs_f64())
        .unwrap_or(DEFAULT_PER_HOP_TIMEOUT);
    let hops = local_hops(handle, dest_hash).await;
    let receipt_timeout = first_hop + DEFAULT_PER_HOP_TIMEOUT * f64::from(hops);

    let (status_tx, status) = watch::channel(ReceiptUpdate::Sent);
    let (result_tx, result_rx) = tokio::sync::oneshot::channel();
    handle
        .transport_tx
        .send(TransportMessage::SendPacket {
            request: OutboundRequest {
                raw: Bytes::from(packet.raw.clone()),
                destination_hash: dest_hash,
            },
            attached_interface: None,
            receipt: Some(TrackedReceiptRegistration {
                truncated_hash: packet.truncated_hash,
                full_hash: packet.packet_hash,
                destination_hash: dest_hash,
                destination_public_key: identity.get_public_key(),
                timeout: Duration::try_from_secs_f64(receipt_timeout).ok(),
                status_tx,
            }),
            result_tx,
        })
        .await
        .ok()?;
    result_rx.await.ok()?;
    Some(PendingProbe { status })
}

impl PendingProbe {
    async fn wait(mut self, probe_deadline: Option<Instant>, quiet: bool) -> ProbeResult {
        let mut i = 0;
        let mut tick = tokio::time::interval(Duration::from_millis(100));
        tick.tick().await;
        loop {
            match *self.status.borrow_and_update() {
                ReceiptUpdate::Sent => {}
                ReceiptUpdate::Delivered {
                    rtt,
                    proof_hash,
                    metrics,
                } => {
                    return ProbeResult::Delivered {
                        rtt,
                        proof_hash,
                        metrics,
                    };
                }
                ReceiptUpdate::TimedOut | ReceiptUpdate::Failed | ReceiptUpdate::Culled => {
                    return ProbeResult::Failed;
                }
            }
            // An undispatched packet drops its receipt and stays SENT, as upstream's does.
            if passed(probe_deadline) {
                return ProbeResult::TimedOut;
            }
            tokio::select! {
                changed = self.status.changed() => {
                    if changed.is_err() {
                        tick.tick().await;
                    }
                    continue;
                }
                _ = tick.tick() => {}
            }
            if !quiet {
                print!("\u{8}\u{8}{} ", SPINNER[i]);
                flush();
            }
            i = (i + 1) % SPINNER.len();
        }
    }
}

/// rnprobe.py:165-186: over RPC on a shared-instance client, else from the proof packet.
async fn reception_stats(
    handle: &ReticulumHandle,
    proof_hash: Option<[u8; 32]>,
    metrics: PacketMetrics,
) -> String {
    let (rssi, snr, q) =
        if let (InstanceMode::Client, Some(proof_hash)) = (handle.instance_mode, proof_hash) {
            let get = |query| async move {
                match handle.query_control(query).await {
                    Some(TransportQueryResponse::FloatResult(v)) => v,
                    _ => None,
                }
            };
            (
                get(TransportQuery::GetPacketRssi {
                    packet_hash: proof_hash,
                })
                .await,
                get(TransportQuery::GetPacketSnr {
                    packet_hash: proof_hash,
                })
                .await,
                get(TransportQuery::GetPacketQ {
                    packet_hash: proof_hash,
                })
                .await,
            )
        } else {
            (
                metrics.rssi.map(f32_to_f64),
                metrics.snr.map(f32_to_f64),
                None,
            )
        };
    format_reception_stats(rssi, snr, q)
}

/// Upstream interfaces report RSSI as an int and SNR/Q as floats; the RPC
/// decoder carries all three as floats, so an integral RSSI prints as an int.
fn format_reception_stats(rssi: Option<f64>, snr: Option<f64>, q: Option<f64>) -> String {
    let mut out = String::new();
    if let Some(rssi) = rssi {
        let rssi = if rssi.fract() == 0.0 && rssi.abs() < 1e15 {
            format!("{}", rssi as i64)
        } else {
            py_float_repr(rssi)
        };
        out.push_str(&format!(" [RSSI {rssi} dBm]"));
    }
    if let Some(snr) = snr {
        out.push_str(&format!(" [SNR {} dB]", py_float_repr(snr)));
    }
    if let Some(q) = q {
        out.push_str(&format!(" [Link Quality {}%]", py_float_repr(q)));
    }
    out
}

/// The shortest decimal of an `f32`, as the interface reported it.
fn f32_to_f64(value: f32) -> f64 {
    format!("{value}").parse().unwrap_or(f64::from(value))
}

/// rnprobe.py:157-163.
fn rtt_string(rtt: Duration) -> String {
    let rtt = rtt.as_secs_f64();
    if rtt >= 1.0 {
        format!("{} seconds", py_float_repr(py_round(rtt, 3)))
    } else {
        format!("{} milliseconds", py_float_repr(py_round(rtt * 1000.0, 3)))
    }
}

/// `timeout or max(DEFAULT_TIMEOUT + first_hop_timeout, medium_path_timeout)`.
async fn probe_timeout(handle: &ReticulumHandle, dest: [u8; 16], timeout: Option<f64>) -> f64 {
    if let Some(timeout) = timeout {
        return timeout;
    }
    let first_hop = handle
        .first_hop_timeout(dest)
        .await
        .map(|d| d.as_secs_f64())
        .unwrap_or(DEFAULT_PER_HOP_TIMEOUT);
    (DEFAULT_TIMEOUT + first_hop).max(medium_path_timeout(handle).await)
}

/// `Reticulum.get_medium_path_timeout()`: the slowest online interface of
/// this instance, or of the shared instance for a client.
async fn medium_path_timeout(handle: &ReticulumHandle) -> f64 {
    let Ok(stats) = handle.interface_stats().await else {
        return 0.0;
    };
    stats
        .interfaces
        .iter()
        .filter(|i| i.online && i.bitrate > 0)
        .map(|i| i.bitrate)
        .min()
        .map(|bitrate| {
            2.0 * ((MTU * 8) as f64 / bitrate.max(rns_runtime::constants::MINIMUM_BITRATE) as f64)
                + DEFAULT_PER_HOP_TIMEOUT
        })
        .unwrap_or(0.0)
}

/// `RNS.Transport.has_path`: this process's own path table.
async fn local_has_path(handle: &ReticulumHandle, dest: [u8; 16]) -> bool {
    matches!(
        handle
            .query_transport(TransportQuery::HasPath { dest })
            .await,
        Some(TransportQueryResponse::BoolResult(true))
    )
}

/// `RNS.Transport.hops_to`: this process's own path table.
async fn local_hops(handle: &ReticulumHandle, dest: [u8; 16]) -> u8 {
    match handle
        .query_transport(TransportQuery::HopsTo { dest })
        .await
    {
        Some(TransportQueryResponse::IntResult(hops)) => {
            u8::try_from(hops).unwrap_or(rns_transport::constants::PATHFINDER_M)
        }
        _ => rns_transport::constants::PATHFINDER_M,
    }
}

/// `get_next_hop` and `get_next_hop_if_name`, from the shared instance for a client.
async fn next_hop_info(handle: &ReticulumHandle, dest: [u8; 16]) -> (Option<[u8; 16]>, String) {
    let via = match handle
        .query_control(TransportQuery::GetNextHop { dest })
        .await
    {
        Some(TransportQueryResponse::HashResult(via)) => via,
        _ => None,
    };
    let interface = match handle
        .query_control(TransportQuery::GetNextHopIfName { dest })
        .await
    {
        Some(TransportQueryResponse::StringResult(Some(name))) => name,
        _ => "None".to_string(),
    };
    (via, interface)
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

fn passed(deadline: Option<Instant>) -> bool {
    deadline.is_some_and(|d| Instant::now() > d)
}

fn flush() {
    let _ = std::io::stdout().flush();
}

struct JsonOk<'a> {
    rtt: Duration,
    hops: u8,
    via: Option<[u8; 16]>,
    interface: &'a str,
}

fn print_json(
    probe_num: u32,
    size: usize,
    dest_hash: [u8; 16],
    full_name: &str,
    outcome: Option<&JsonOk<'_>>,
    error: Option<&str>,
) {
    let mut out = serde_json::json!({
        "probe": probe_num,
        "size": size,
        "destination": hex::encode(dest_hash),
        "name": full_name,
    });
    if let Some(o) = outcome {
        out["status"] = "ok".into();
        out["rtt_ms"] = (o.rtt.as_secs_f64() * 1000.0).into();
        out["hops"] = o.hops.into();
        if let Some(via) = o.via {
            out["via"] = hex::encode(via).into();
        }
        if o.interface != "None" {
            out["interface"] = o.interface.into();
        }
    } else if let Some(err) = error {
        out["status"] = "error".into();
        out["error"] = err.into();
    }
    println!("{out}");
}

#[cfg(test)]
mod tests {
    use super::*;

    // Expected strings are Python `str(round(x, 3))` and `str()` output.
    #[test]
    fn rtt_and_reception_stats_print_python_number_forms() {
        assert_eq!(
            rtt_string(Duration::from_secs_f64(0.00099)),
            "0.99 milliseconds"
        );
        assert_eq!(
            rtt_string(Duration::from_secs_f64(0.1278714)),
            "127.871 milliseconds"
        );
        assert_eq!(rtt_string(Duration::from_secs(1)), "1.0 seconds");
        assert_eq!(format_reception_stats(None, None, None), "");
        assert_eq!(
            format_reception_stats(Some(-87.0), Some(9.25), Some(88.0)),
            " [RSSI -87 dBm] [SNR 9.25 dB] [Link Quality 88.0%]"
        );
        assert_eq!(
            format_reception_stats(None, Some(-3.0), None),
            " [SNR -3.0 dB]"
        );
        assert_eq!(f32_to_f64(0.1), 0.1);
    }
}
