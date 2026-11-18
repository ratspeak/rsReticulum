//! rnx-rs — Reticulum remote execution (RNS/Utilities/rnx.py).
//!
//! `-l` listens on `rnx.execute` and runs `command` requests from allowed
//! identities; with a destination and a command it executes remotely. Exit
//! codes follow rnx: 240-249 for client failures, `-m` mirrors the remote code.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::Duration;

use clap::Parser;
use tokio::sync::mpsc;

use rns_identity::destination::{AllowPolicy, DestType, Destination, Direction};
use rns_identity::identity::Identity;
use rns_runtime::lifecycle::{ShutdownSignal, install_signal_handlers};
use rns_runtime::link_manager::{LinkManager, LinkManagerCommand, RequestOutcome};
use rns_runtime::link_session::{LinkSession, LinkSessionError, LinkSessionEvent, RequestOptions};
use rns_runtime::platform::StoragePaths;
use rns_runtime::reticulum::{LinkConnectOptions, ReticulumHandle};
use rns_tools::RS_RETICULUM_VERSION;
use rns_tools::rnx::{
    APP_NAME, COMMAND_PATH, CommandRequest, REMOTE_EXEC_GRACE, Timeout, TransferStats,
};
use rns_transport::messages::{PathRequestOptions, TransportMessage};

#[derive(Parser)]
#[command(
    name = "rnx-rs",
    about = "Reticulum Remote Execution Utility",
    disable_version_flag = true
)]
struct Args {
    /// hexadecimal hash of the listener
    destination: Option<String>,
    /// command to be execute
    command: Option<String>,
    /// path to alternative Reticulum config directory
    #[arg(long, value_name = "path")]
    config: Option<String>,
    /// increase verbosity
    #[arg(short = 'v', long = "verbose", action = clap::ArgAction::Count)]
    verbose: u8,
    /// decrease verbosity
    #[arg(short = 'q', long = "quiet", action = clap::ArgAction::Count)]
    quiet: u8,
    /// print identity and destination info and exit
    #[arg(short = 'p', long = "print-identity")]
    print_identity: bool,
    /// listen for incoming commands
    #[arg(short = 'l', long = "listen")]
    listen: bool,
    /// path to identity to use
    #[arg(short = 'i', value_name = "identity")]
    identity: Option<PathBuf>,
    /// enter interactive mode
    #[arg(short = 'x', long = "interactive")]
    interactive: bool,
    /// don't announce at program start
    #[arg(short = 'b', long = "no-announce")]
    no_announce: bool,
    /// accept from this identity
    #[arg(short = 'a', value_name = "allowed_hash")]
    allowed: Vec<String>,
    /// accept commands from anyone
    #[arg(short = 'n', long = "noauth")]
    noauth: bool,
    /// don't identify to listener
    #[arg(short = 'N', long = "noid")]
    noid: bool,
    /// show detailed result output
    #[arg(short = 'd', long = "detailed")]
    detailed: bool,
    /// mirror exit code of remote command
    #[arg(short = 'm')]
    mirror: bool,
    /// connect and request timeout before giving up
    #[arg(short = 'w', value_name = "seconds")]
    w: Option<f64>,
    /// max result download time
    #[arg(short = 'W', value_name = "seconds")]
    result_timeout: Option<f64>,
    /// pass input to stdin
    #[arg(long)]
    stdin: Option<String>,
    /// max size in bytes of returned stdout
    #[arg(long)]
    stdout: Option<i64>,
    /// max size in bytes of returned stderr
    #[arg(long)]
    stderr: Option<i64>,
    /// print version and exit
    #[arg(long)]
    version: bool,
}

#[tokio::main]
pub(crate) async fn main() {
    let args = Args::parse();
    if args.version {
        println!(
            "{}",
            rns_tools::version_line("rnx-rs", RS_RETICULUM_VERSION, &[])
        );
        return;
    }
    let level = rns_tools::Utility::Rnx.loglevel(None, args.verbose, args.quiet, false);
    let config_dir = rns_runtime::platform::resolve_config_dir(args.config.as_deref());
    rns_tools::init_tracing(
        level,
        rns_tools::config_log_timestamps(&config_dir),
        true,
        std::io::stdout,
    );

    let interrupt = ShutdownSignal::new();
    let _signal_rx = install_signal_handlers(interrupt.clone());

    if args.listen || args.print_identity {
        listen(&args, &interrupt).await;
    }
    let Some(destination) = args.destination.clone() else {
        print_help();
    };
    if args.command.is_none() && !args.interactive {
        print_help();
    }
    let destination_hash = match rns_tools::rnx::parse_hash_arg(&destination) {
        Ok(hash) => hash,
        Err(e) => {
            println!("{e}");
            std::process::exit(241);
        }
    };
    let handle = start(&args, &interrupt).await;
    let mut link = None;
    let code = tokio::select! {
        biased;
        _ = interrupt.wait() => {
            println!();
            0
        }
        code = run_client(&args, &handle, destination_hash, &mut link) => code,
    };
    // rnx.py tears the Link down before exiting, on an interrupt too.
    if let Some(link) = link {
        link.teardown().await;
    }
    rns_tools::exit(&handle, code).await;
}

fn print_help() -> ! {
    println!();
    let _ = <Args as clap::CommandFactory>::command().print_help();
    println!();
    std::process::exit(0);
}

/// Start Reticulum on its own shutdown signal, so an interrupt still leaves
/// the runtime able to deregister from the shared instance.
async fn start(args: &Args, interrupt: &ShutdownSignal) -> ReticulumHandle {
    let foreground = Arc::new(AtomicBool::new(true));
    tokio::select! {
        biased;
        _ = interrupt.wait() => {
            println!();
            std::process::exit(0);
        }
        handle = rns_runtime::reticulum::init(args.config.as_deref(), None, ShutdownSignal::new(), foreground) => match handle {
            Ok(handle) => handle,
            Err(e) => {
                eprintln!("failed to start reticulum: {e}");
                std::process::exit(1);
            }
        },
    }
}

/// `prepare_identity` (rnx.py): load the identity file or write a new one there.
fn prepare_identity(path: Option<&Path>, handle: &ReticulumHandle) -> Identity {
    let path = path.map(Path::to_path_buf).unwrap_or_else(|| {
        StoragePaths::from_config_dir(&handle.config_dir)
            .identity_dir
            .join("rnx")
    });
    if path.is_file()
        && let Ok(identity) = Identity::from_file(&path)
    {
        return identity;
    }
    tracing::info!("No valid saved identity found, creating new...");
    let identity = Identity::new();
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if let Err(e) = identity.to_file(&path) {
        tracing::error!("could not save identity to {}: {e}", path.display());
    }
    identity
}

async fn listen(args: &Args, interrupt: &ShutdownSignal) -> ! {
    let handle = start(args, interrupt).await;
    let identity = prepare_identity(args.identity.as_deref(), &handle);
    let destination = Destination::new(Some(&identity), Direction::In, DestType::Single, APP_NAME)
        .expect("rnx.execute is a valid SINGLE destination name");
    let destination_hash = destination.hash;

    if args.print_identity {
        println!("Identity     : <{}>", hex::encode(identity.hash));
        println!("Listening on : <{}>", hex::encode(destination_hash));
        rns_tools::exit(&handle, 0).await;
    }

    let mut allowed: Vec<[u8; 16]> = Vec::new();
    if !args.noauth {
        for a in &args.allowed {
            match rns_tools::rnx::parse_hash_arg(a) {
                Ok(hash) => allowed.push(hash),
                Err(e) => {
                    println!("{e}");
                    rns_tools::exit(&handle, 1).await;
                }
            }
        }
        let home = rns_runtime::platform::home_dir();
        let file = rns_tools::rnx::allowed_identity_files(home.as_deref())
            .into_iter()
            .find(|f| f.is_file());
        if let Some(file) = file {
            match std::fs::read_to_string(&file)
                .map_err(|e| e.to_string())
                .and_then(|text| rns_tools::rnx::parse_allowed_identities(&text))
            {
                Ok(hashes) => allowed.extend(hashes),
                Err(e) => {
                    println!("{e}");
                    rns_tools::exit(&handle, 1).await;
                }
            }
        }
    }
    if allowed.is_empty() && !args.noauth {
        println!("Warning: No allowed identities configured, rncx will not accept any commands!");
    }

    let (dest_tx, dest_rx) = mpsc::channel(256);
    let mut manager = LinkManager::with_destination(
        handle.transport_tx.clone(),
        dest_rx,
        &identity,
        APP_NAME,
        identity.get_signing_key(),
    );
    manager.set_link_endpoint_dispatch_handle(handle.link_endpoint_dispatch_handle());
    manager.set_use_implicit_proof(handle.should_use_implicit_proof());
    if !args.noauth {
        let gate = allowed.clone();
        manager.set_link_identity_gate(move |link_id, identity_hash| {
            let ok = gate.contains(&identity_hash);
            if !ok {
                tracing::info!(
                    target: rns_tools::NOTICE_TARGET,
                    "Identity <{}> not allowed, tearing down link <{}>",
                    hex::encode(identity_hash),
                    hex::encode(link_id)
                );
            }
            ok
        });
    }
    let (allow, allowed_list) = if args.noauth {
        (AllowPolicy::AllowAll, None)
    } else {
        (AllowPolicy::AllowList, Some(allowed))
    };
    let registered = manager.register_deferred_request_handler(
        COMMAND_PATH,
        allow,
        allowed_list,
        true,
        64 * 1024 * 1024,
        |request, responder| {
            // Upstream raises on a malformed request and sends nothing.
            let Some(command) = CommandRequest::from_value(&request.value) else {
                return;
            };
            let requestor = request.remote_identity.as_ref().map_or_else(
                || "unknown requestor".to_string(),
                |id| format!("<{}>", hex::encode(id.hash)),
            );
            tokio::spawn(async move {
                tracing::info!(target: rns_tools::NOTICE_TARGET, "Executing command [{}] for {requestor}", command.command);
                let result = rns_tools::rnx::execute(&command).await;
                tracing::info!(target: rns_tools::NOTICE_TARGET, "Delivering result of command [{}] to {requestor}", command.command);
                if let Err(e) = responder.respond(RequestOutcome::ReplyValue(result.to_msgpack())) {
                    tracing::warn!("could not deliver result of command [{}]: {e}", command.command);
                }
            });
        },
    );
    if !registered {
        eprintln!("rnx-rs: could not register the command handler");
        rns_tools::exit(&handle, 1).await;
    }

    let send = |message| handle.transport_tx.send(message);
    if send(TransportMessage::RegisterDestination {
        hash: destination_hash,
        app_name: APP_NAME.to_string(),
        delivery_tx: Some(dest_tx),
    })
    .await
    .is_err()
        || send(TransportMessage::SetLocalDestinationKey {
            hash: destination_hash,
            public_key: identity.get_public_key(),
        })
        .await
        .is_err()
    {
        eprintln!("rnx-rs: transport is unavailable");
        rns_tools::exit(&handle, 1).await;
    }
    let (command_tx, command_rx) = mpsc::channel(16);
    let manager_task = tokio::spawn(manager.run_with_commands(command_rx));

    tracing::info!(
        target: rns_tools::NOTICE_TARGET,
        "rnx listening for commands on <{}>",
        hex::encode(destination_hash)
    );
    if !args.no_announce {
        let _ = command_tx.send(LinkManagerCommand::Announce).await;
    }

    interrupt.wait().await;
    println!();
    drop(command_tx);
    let _ = tokio::time::timeout(Duration::from_secs(5), manager_task).await;
    let _ = handle
        .transport_tx
        .send(TransportMessage::DeregisterDestination {
            hash: destination_hash,
        })
        .await;
    rns_tools::exit(&handle, 0).await;
}

/// `spin` (rnx.py): an animated message on stdout while `until` runs.
async fn spin<F: std::future::Future>(msg: &str, until: F) -> F::Output {
    const SYMS: [char; 7] = ['⢄', '⢂', '⢁', '⡁', '⡈', '⡐', '⡠'];
    let mut out = std::io::stdout();
    let _ = write!(out, "{msg}   ");
    let _ = out.flush();
    tokio::pin!(until);
    let mut tick = tokio::time::interval_at(
        tokio::time::Instant::now() + Duration::from_millis(100),
        Duration::from_millis(100),
    );
    let mut i = 0;
    let result = loop {
        tokio::select! {
            result = &mut until => break result,
            _ = tick.tick() => {
                let _ = write!(out, "\x08\x08{} ", SYMS[i]);
                let _ = out.flush();
                i = (i + 1) % SYMS.len();
            }
        }
    };
    let _ = write!(out, "\r{}  \r", " ".repeat(msg.chars().count()));
    let _ = out.flush();
    result
}

fn secs(seconds: f64) -> Duration {
    Duration::try_from_secs_f64(seconds.max(0.0)).unwrap_or(Duration::MAX)
}

async fn run_client(
    args: &Args,
    handle: &ReticulumHandle,
    destination_hash: [u8; 16],
    link: &mut Option<Connected>,
) -> i32 {
    // rnx.py
    handle.wants_destination_type(APP_NAME).await;
    let identity = prepare_identity(args.identity.as_deref(), handle);
    let mut client = Client {
        handle,
        identity,
        destination_hash,
        session: link,
    };
    let timeout = args.w.map_or(Timeout::Default, Timeout::Given);
    run_commands(args, &mut client, timeout).await
}

async fn run_commands(args: &Args, client: &mut Client<'_>, timeout: Timeout) -> i32 {
    if let Some(command) = args.command.as_deref() {
        match client
            .execute(
                args,
                command,
                args.stdin.as_deref(),
                timeout,
                args.interactive,
            )
            .await
        {
            Outcome::Exit(code) => return code,
            Outcome::Done(_) if !args.interactive => unreachable!("one-shot runs exit"),
            Outcome::Done(_) => {}
        }
    }
    interactive(args, client, timeout).await
}

/// The interactive loop (rnx.py).
async fn interactive(args: &Args, client: &mut Client<'_>, timeout: Timeout) -> i32 {
    let (line_tx, mut line_rx) = mpsc::channel::<Option<String>>(1);
    std::thread::spawn(move || {
        let stdin = std::io::stdin();
        loop {
            let mut line = String::new();
            let read = stdin.read_line(&mut line);
            let line = match read {
                Ok(0) | Err(_) => None,
                Ok(_) => Some(line.trim_end_matches(['\n', '\r']).to_string()),
            };
            let end = line.is_none();
            if line_tx.blocking_send(line).is_err() || end {
                break;
            }
        }
    });
    let mut code: Option<i64> = None;
    loop {
        let prompt = match code {
            Some(c) if c != 0 => format!("{c}> "),
            _ => "> ".to_string(),
        };
        print!("{prompt}");
        let _ = std::io::stdout().flush();
        let Some(Some(command)) = line_rx.recv().await else {
            return 0;
        };
        let lower = command.to_lowercase();
        if lower == "exit" || lower == "quit" {
            return 0;
        }
        if lower == "clear" {
            print!("\x1bc");
            continue;
        }
        match client.execute(args, &command, None, timeout, true).await {
            Outcome::Exit(code) => return code,
            Outcome::Done(c) => code = c,
        }
    }
}

enum Outcome {
    /// Leave the process with this code.
    Exit(i32),
    /// An interactive command finished; the code shown in the next prompt.
    Done(Option<i64>),
}

struct Client<'a> {
    handle: &'a ReticulumHandle,
    identity: Identity,
    destination_hash: [u8; 16],
    session: &'a mut Option<Connected>,
}

/// An established Link, its measured round trip, and the task draining its
/// events until the session actor reports it closed.
struct Connected {
    session: LinkSession,
    rtt: f64,
    closed: tokio::task::JoinHandle<()>,
}

impl Connected {
    /// `Link.teardown()` (Link.py): the close is done before this returns.
    async fn teardown(self) {
        self.session.handle.close().await;
        let _ = self.closed.await;
    }
}

impl Client<'_> {
    /// Ensure a path, as `execute` does before linking (rnx.py).
    async fn ensure_path(&self, timeout: Timeout) -> bool {
        let handle = self.handle;
        let hash = self.destination_hash;
        if rns_tools::has_local_path(handle, hash).await {
            return true;
        }
        let _ = handle
            .request_path(hash, PathRequestOptions::default())
            .await;
        let wait = timeout
            .seconds()
            .max(rns_tools::medium_path_timeout(handle).await);
        let msg = format!("Path to <{}> requested", hex::encode(hash));
        let found = spin(&msg, async {
            loop {
                if rns_tools::has_local_path(handle, hash).await {
                    return true;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        });
        tokio::time::timeout(secs(wait), found).await.is_ok()
    }

    /// Open the Link with `max(-w, establishment timeout)` (rnx.py).
    async fn connect(&self, noid: bool, timeout: Timeout) -> Option<Connected> {
        let handle = self.handle;
        let hash = self.destination_hash;
        let hops = handle.hops_to(hash).await.unwrap_or(1);
        let first_hop = handle
            .first_hop_timeout(hash)
            .await
            .map_or(rns_wire::constants::DEFAULT_PER_HOP_TIMEOUT, |d| {
                d.as_secs_f64()
            });
        let establishment =
            first_hop + rns_wire::constants::DEFAULT_PER_HOP_TIMEOUT * f64::from(hops.max(1));
        let options = LinkConnectOptions {
            path_timeout: secs(timeout.seconds()),
            establishment_timeout: Some(secs(timeout.seconds().max(establishment))),
            client_label: "rnx".to_string(),
            identify: !noid,
            track_phy_stats: false,
            ..LinkConnectOptions::default()
        };
        let msg = format!("Establishing link with <{}>", hex::encode(hash));
        let connected = spin(
            &msg,
            handle.connect_link(hash, self.identity.clone(), options),
        )
        .await;
        match connected {
            Ok(mut session) => {
                let rtt = session.handle.rtt();
                let events = std::mem::replace(&mut session.events, mpsc::channel(1).1);
                let closed = tokio::spawn(drain(events));
                Some(Connected {
                    session,
                    rtt,
                    closed,
                })
            }
            Err(e) => {
                tracing::debug!("link establishment failed: {e}");
                None
            }
        }
    }

    async fn execute(
        &mut self,
        args: &Args,
        command: &str,
        stdin: Option<&str>,
        timeout: Timeout,
        interactive: bool,
    ) -> Outcome {
        let fail = |msg: &str, code: i32| {
            println!("{msg}");
            if interactive {
                Outcome::Done(None)
            } else {
                Outcome::Exit(code)
            }
        };
        if !self.ensure_path(timeout).await {
            println!("Path not found");
            return Outcome::Exit(242);
        }
        if self.session.is_none() {
            match self.connect(args.noid, timeout).await {
                Some(connected) => *self.session = Some(connected),
                None => {
                    println!(
                        "Could not establish link with <{}>",
                        hex::encode(self.destination_hash)
                    );
                    return Outcome::Exit(243);
                }
            }
        }
        let connected = self.session.as_ref().expect("connected above");
        let (link, rtt) = (connected.session.handle.clone(), connected.rtt);
        let data = rns_tools::rnx::request_value(command, timeout, args.stdout, args.stderr, stdin);
        let request_size = packed_request_size(&data);
        let rexec_timeout = timeout.seconds() + rtt * 4.0 + REMOTE_EXEC_GRACE;
        let (progress_tx, mut progress_rx) = tokio::sync::watch::channel(0.0);
        let request = link.request_with_options(
            COMMAND_PATH,
            data,
            RequestOptions {
                timeout: Some(secs(rexec_timeout)),
                progress: Some(progress_tx),
                ..RequestOptions::default()
            },
        );
        tokio::pin!(request);
        // `-W` bounds only the result transfer; when it passes, the receipt
        // still holds no response (rnx.py).
        let result = match args.result_timeout {
            Some(w) => tokio::select! {
                r = &mut request => Some(r),
                _ = progress_rx.changed() => tokio::time::timeout(secs(w), &mut request).await.ok(),
            },
            None => Some(request.await),
        };
        let response = match result {
            None => return fail("No response", 249),
            Some(Ok(response)) => response,
            Some(Err(LinkSessionError::SessionClosed | LinkSessionError::LinkNotActive)) => {
                *self.session = None;
                println!("Could not request remote execution, link was closed");
                return Outcome::Exit(244);
            }
            Some(Err(
                LinkSessionError::RequestResourceFailed(_)
                | LinkSessionError::ResponseRejected { .. },
            )) => return fail("Receiving result failed", 246),
            Some(Err(_)) => return fail("Could not request remote execution", 244),
        };
        let stats = match (
            response.response_size,
            response.started_at,
            response.response_concluded_at,
        ) {
            (Some(response_size), Some(sent), Some(concluded)) => Some(TransferStats {
                request_size: Some(request_size),
                response_size,
                elapsed: concluded.saturating_duration_since(sent).as_secs_f64(),
            }),
            _ => None,
        };
        let (rendered, parsed, code) = rns_tools::rnx::client_result(
            &response.value,
            args.detailed,
            args.mirror,
            args.stdout,
            args.stderr,
            stats,
        );
        let Some(parsed) = parsed else {
            let _ = std::io::stdout().write_all(&rendered.stdout);
            return if interactive {
                Outcome::Done(None)
            } else {
                Outcome::Exit(code)
            };
        };
        write_split(&parsed, &rendered);

        if !interactive {
            return Outcome::Exit(code);
        }
        Outcome::Done(if args.mirror { parsed.retcode } else { None })
    }
}

/// Write remote output first, then the trailer lines, as rnx.py orders them.
fn write_split(parsed: &rns_tools::rnx::Response, rendered: &rns_tools::rnx::Rendered) {
    let remote_out = parsed.stdout.as_deref().map_or(0, <[u8]>::len);
    let (out, trailer) = rendered
        .stdout
        .split_at(remote_out.min(rendered.stdout.len()));
    let mut stdout = std::io::stdout();
    let mut stderr = std::io::stderr();
    let _ = stdout.write_all(out);
    let _ = stderr.write_all(&rendered.stderr);
    let _ = stdout.flush();
    let _ = stderr.flush();
    let _ = stdout.write_all(trailer);
    let _ = stdout.flush();
}

/// `len(umsgpack.packb([time.time(), path_hash, data]))` (Link.py).
fn packed_request_size(data: &rmpv::Value) -> u64 {
    let request = rmpv::Value::Array(vec![
        rmpv::Value::F64(0.0),
        rmpv::Value::Binary(vec![0; 16]),
        data.clone(),
    ]);
    let mut out = Vec::new();
    let _ = rmpv::encode::write_value(&mut out, &request);
    out.len() as u64
}

async fn drain(mut events: mpsc::Receiver<LinkSessionEvent>) {
    while let Some(event) = events.recv().await {
        if let LinkSessionEvent::Closed { .. } = event {
            return;
        }
    }
}
