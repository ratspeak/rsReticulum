//! `rngit-rs`: the Reticulum Git repository node (`RNS/Utilities/rngit/server.py@1.6.0`).

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::{Duration, Instant};

use clap::Parser;
use rns_git::server::config::{
    NodeConfig, load_or_create_identity, read_or_create_config, resolve_config_dir,
};
use rns_git::server::handlers::handle_list;
use rns_git::server::layout::{Repositories, git_available};
use rns_git::server::{APP_NAME, PATH_LIST};
use rns_identity::destination::{AllowPolicy, Destination};
use rns_identity::identity::Identity;
use rns_runtime::config::ConfigError;
use rns_runtime::destination_runtime::DestinationRuntimeOptions;
use rns_runtime::lifecycle::{ShutdownSignal, install_signal_handlers};
use rns_runtime::link_manager::{DestinationAnnounceOptions, RequestOutcome};
use rns_tools::{LogLevel, RS_RETICULUM_VERSION};

const JOBS_INTERVAL: Duration = Duration::from_secs(5);

#[derive(Parser)]
#[command(
    name = "rngit-rs",
    about = "Reticulum Git Repository Node",
    disable_version_flag = true
)]
struct Args {
    /// path to alternative config directory
    #[arg(long)]
    config: Option<String>,
    /// path to alternative Reticulum config directory
    #[arg(long)]
    rnsconfig: Option<String>,
    /// print identity and destination info and exit
    #[arg(short = 'p', long = "print-identity")]
    print_identity: bool,
    /// rngit is running as a service and should log to file
    #[arg(short = 's', long)]
    service: bool,
    #[arg(short = 'v', long, action = clap::ArgAction::Count)]
    verbose: u8,
    #[arg(short = 'q', long, action = clap::ArgAction::Count)]
    quiet: u8,
    #[arg(long)]
    version: bool,
}

/// `RNS.LOG_MAXSIZE` (`RNS/__init__.py:74`).
const LOG_MAXSIZE: u64 = 5 * 1024 * 1024;

/// The `-s` log file: appended per line and rotated to `.1` past
/// `LOG_MAXSIZE`, falling back to stderr as `RNS.log` falls back to the console.
#[derive(Clone)]
struct ServerLog(PathBuf);

impl std::io::Write for ServerLog {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let appended = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.0)
            .and_then(|mut file| file.write_all(buf).map(|()| file.metadata()));
        match appended {
            Ok(Ok(meta)) if meta.len() > LOG_MAXSIZE => {
                let mut rotated = self.0.clone().into_os_string();
                rotated.push(".1");
                let _ = std::fs::remove_file(&rotated);
                let _ = std::fs::rename(&self.0, &rotated);
            }
            Ok(_) => {}
            Err(_) => std::io::stderr().write_all(buf)?,
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn prettyhex(hash: &[u8]) -> String {
    format!("<{}>", hex::encode(hash))
}

fn non_empty(value: Option<String>) -> Option<String> {
    value.filter(|v| !v.is_empty())
}

#[tokio::main]
async fn main() {
    let mut argv: Vec<String> = std::env::args().collect();
    if argv.get(1).map(String::as_str) == Some("node") {
        argv.remove(1);
    }
    let args = Args::parse_from(argv);
    if args.version {
        println!("rngit-rs {RS_RETICULUM_VERSION}");
        return;
    }
    let verbosity = if args.service {
        0
    } else {
        i64::from(args.verbose) - i64::from(args.quiet)
    };
    let configdir = non_empty(args.config.clone()).map(PathBuf::from);
    let rnsconfig = non_empty(args.rnsconfig.clone());

    if !git_available() {
        eprintln!("The \"git\" command is not available. Aborting server startup.");
        std::process::exit(255);
    }
    let configdir = resolve_config_dir(configdir.as_deref());
    let text = match read_or_create_config(&configdir) {
        Ok(text) => text,
        Err(e) => {
            eprintln!(
                "Could not load the configuration at {}: {e}",
                configdir.display()
            );
            std::process::exit(1);
        }
    };
    let config = match NodeConfig::parse(&text, verbosity) {
        Ok(config) => config,
        Err(e @ ConfigError::InvalidValue { .. }) => {
            eprintln!("{e}");
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!(
                "Could not parse the configuration at {}/config",
                configdir.display()
            );
            eprintln!("Check your configuration file for errors! ({e})");
            std::process::exit(255);
        }
    };
    // RNS.Reticulum applies the Reticulum config loglevel first; rngit's own key overrides it.
    let rns_dir = rns_runtime::platform::resolve_config_dir(rnsconfig.as_deref());
    let level = match config.loglevel {
        Some(level) => LogLevel::clamped(level),
        None => {
            let configured = rns_runtime::config::Config::from_file(&rns_dir.join("config"))
                .ok()
                .and_then(|c| c.section("logging")?.get_int("loglevel"));
            let (verbose, quiet) = if args.service {
                (0, 0)
            } else {
                (args.verbose, args.quiet)
            };
            rns_tools::Utility::Rnir.loglevel(configured, verbose, quiet, args.service)
        }
    };
    let timestamps = rns_tools::config_log_timestamps(&rns_dir);
    if args.service {
        let log = ServerLog(configdir.join("server_log"));
        rns_tools::init_tracing(level, timestamps, false, move || log.clone());
    } else {
        rns_tools::init_tracing(level, timestamps, true, std::io::stdout);
    }

    let identity = match load_or_create_identity(&configdir.join("repositories_identity")) {
        Ok(identity) => identity,
        Err(e) => {
            eprintln!("Could not initialize repositories identity. Exiting now. ({e})");
            std::process::exit(255);
        }
    };
    let destination_hash = Destination::hash_from_name_and_identity(APP_NAME, Some(&identity.hash));

    if args.print_identity {
        let path = configdir.join("client_identity");
        let client = if path.is_file() {
            Identity::from_file(&path)
        } else {
            let id = Identity::new();
            id.to_file(&path).map(|_| id)
        };
        let Ok(client) = client else {
            eprintln!("Could not load {}", path.display());
            std::process::exit(1);
        };
        println!("Git Peer Identity         : {}", prettyhex(&client.hash));
        println!("Repository Node Identity  : {}", prettyhex(&identity.hash));
        println!(
            "Repositories Destination  : {}",
            prettyhex(&destination_hash)
        );
        if config.serve_nomadnet {
            let nomad =
                Destination::hash_from_name_and_identity("nomadnetwork.node", Some(&identity.hash));
            println!("Nomad Network Destination : {}", prettyhex(&nomad));
        }
        return;
    }

    let interrupt = ShutdownSignal::new();
    let _signal_rx = install_signal_handlers(interrupt.clone());
    let foreground = Arc::new(AtomicBool::new(!args.service));
    let handle = match rns_runtime::reticulum::init(
        rnsconfig.as_deref(),
        None,
        ShutdownSignal::new(),
        foreground,
    )
    .await
    {
        Ok(handle) => handle,
        Err(e) => {
            eprintln!("failed to start reticulum: {e}");
            std::process::exit(1);
        }
    };
    handle.wants_destination_type(APP_NAME).await;
    tracing::info!(target: rns_tools::NOTICE_TARGET, "Starting Reticulum Git Node...");

    let repositories = match Repositories::load(&config) {
        Ok(repositories) => Arc::new(repositories),
        Err(e) => {
            tracing::error!("Could not load repositories: {e:?}");
            rns_tools::exit(&handle, 1).await;
        }
    };

    let registered = match handle
        .register_destination(identity, APP_NAME, DestinationRuntimeOptions::default())
        .await
    {
        Ok(registered) => registered,
        Err(e) => {
            tracing::error!("Could not register the repositories destination: {e}");
            rns_tools::exit(&handle, 1).await;
        }
    };
    let list_repos = repositories.clone();
    let ok = registered
        .handle
        .register_request_handler(
            PATH_LIST,
            AllowPolicy::AllowAll,
            Vec::new(),
            true,
            move |request| {
                let hash = request.remote_identity.as_ref().map(|id| id.hash);
                tracing::debug!("List request from remote {:?}", hash.map(hex::encode));
                match handle_list(&list_repos, hash.as_ref(), &request.value) {
                    Some(reply) => RequestOutcome::ReplyBytes(reply),
                    None => RequestOutcome::Drop,
                }
            },
        )
        .await;
    if !matches!(ok, Ok(true)) {
        tracing::error!("Could not register the {PATH_LIST} handler");
        rns_tools::exit(&handle, 1).await;
    }
    tracing::info!(
        target: rns_tools::NOTICE_TARGET,
        "Reticulum Git Node listening on {}",
        prettyhex(&destination_hash)
    );

    // The jobs loop (server.py:2656-2661): the first tick announces when an interval is set.
    let announce_interval = config.announce_interval;
    let mut last_announce: Option<Instant> = None;
    loop {
        tokio::select! {
            _ = interrupt.wait() => break,
            _ = tokio::time::sleep(JOBS_INTERVAL) => {}
        }
        let due = last_announce
            .is_none_or(|last| last.elapsed().as_secs_f64() > announce_interval as f64);
        if announce_interval != 0 && due {
            tracing::debug!("Announcing repositories destination");
            if let Err(e) = registered
                .handle
                .announce(DestinationAnnounceOptions::default())
                .await
            {
                tracing::warn!("Could not announce: {e}");
            }
            last_announce = Some(Instant::now());
        }
    }
    println!();
    rns_tools::exit(&handle, 0).await;
}
