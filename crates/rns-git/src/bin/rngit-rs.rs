//! `rngit-rs`: the Reticulum Git repository node (`RNS/Utilities/rngit/server.py@1.6.0`).

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use clap::Parser;
use rns_git::server::config::{
    NodeConfig, load_or_create_identity, read_or_create_config, resolve_config_dir,
};
use rns_git::server::handlers::{
    Reply, handle_create, handle_delete, handle_fetch, handle_list, handle_push,
};
use rns_git::server::layout::{Repositories, git_available};
use rns_git::server::{APP_NAME, PATH_CREATE, PATH_DELETE, PATH_FETCH, PATH_LIST, PATH_PUSH};
use rns_identity::destination::{AllowPolicy, Destination};
use rns_identity::identity::Identity;
use rns_runtime::config::ConfigError;
use rns_runtime::destination_runtime::DestinationRuntimeOptions;
use rns_runtime::lifecycle::{ShutdownSignal, install_signal_handlers};
use rns_runtime::link_manager::{
    DeferredRequestResponder, DestinationAnnounceOptions, DestinationRequest, RequestOutcome,
};
use rns_tools::{LogLevel, RS_RETICULUM_VERSION};

const JOBS_INTERVAL: Duration = Duration::from_secs(5);

/// Ceiling for a deferred reply held in memory: status bytes or file metadata.
const REPLY_LIMIT: usize = 64 * 1024;

/// Bundle directories kept until their Link closes (`link.temporary_directories`).
type LinkTempDirs = Arc<Mutex<HashMap<[u8; 16], Vec<tempfile::TempDir>>>>;

type Handler = fn(&RwLock<Repositories>, Option<&[u8; 16]>, &rmpv::Value) -> Option<Reply>;

/// Run a git handler on the blocking pool and answer through the responder.
fn deferred(
    repositories: Arc<RwLock<Repositories>>,
    tempdirs: LinkTempDirs,
    handler: Handler,
) -> impl Fn(DestinationRequest, DeferredRequestResponder) + Send + 'static {
    move |request, responder| {
        let repositories = repositories.clone();
        let tempdirs = tempdirs.clone();
        tokio::task::spawn_blocking(move || {
            let hash = request.remote_identity.as_ref().map(|id| id.hash);
            let (outcome, tmpdir) = match handler(&repositories, hash.as_ref(), &request.value) {
                None => (RequestOutcome::Drop, None),
                Some(Reply::Bytes(bytes)) => (RequestOutcome::ReplyBytes(bytes), None),
                Some(Reply::File {
                    file,
                    metadata,
                    tmpdir,
                }) => (
                    RequestOutcome::ReplyFile {
                        source: Box::new(file),
                        metadata: Some(metadata),
                    },
                    Some(tmpdir),
                ),
            };
            let sent = responder.respond(outcome).is_ok();
            if let Some(tmpdir) = tmpdir.filter(|_| sent) {
                tracing::debug!(
                    "Created {} for link <{}>",
                    tmpdir.path().display(),
                    hex::encode(request.link_id)
                );
                tempdirs
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .entry(request.link_id)
                    .or_default()
                    .push(tmpdir);
            }
        });
    }
}

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

#[derive(Parser)]
#[command(
    name = "rngit-rs create",
    about = "Reticulum Git Repository Creation",
    disable_version_flag = true
)]
struct CreateArgs {
    /// path to alternative config directory
    #[arg(long)]
    config: Option<String>,
    /// path to alternative Reticulum config directory
    #[arg(long)]
    rnsconfig: Option<String>,
    /// path to identity
    #[arg(short = 'i', long, value_name = "PATH")]
    identity: Option<String>,
    /// URL of repository to create
    repository: String,
    #[arg(short = 'v', long, action = clap::ArgAction::Count)]
    verbose: u8,
    #[arg(short = 'q', long, action = clap::ArgAction::Count)]
    quiet: u8,
    #[arg(long)]
    version: bool,
}

/// `ReticulumGitClient.abort` (`server.py:402-403`).
async fn abort(handle: &rns_runtime::reticulum::ReticulumHandle, message: &str) -> ! {
    println!("{message}");
    rns_tools::exit(handle, 1).await
}

/// `rngit create` (`server.py:85-87`, `create_repository` `server.py:569-604`).
async fn create(args: CreateArgs) {
    use rns_git::server::client::{ClientConfig, client_config_dir, create_outcome};
    use rns_git::server::{IDX_REPOSITORY, PATH_CREATE};
    use std::io::Write;

    let configdir = client_config_dir(non_empty(args.config).map(PathBuf::from).as_deref());
    let rnsconfig = non_empty(args.rnsconfig);
    let rns_dir = rns_runtime::platform::resolve_config_dir(rnsconfig.as_deref());
    let configured = rns_runtime::config::Config::from_file(&rns_dir.join("config"))
        .ok()
        .and_then(|c| c.section("logging")?.get_int("loglevel"));
    let level = rns_tools::Utility::Rnir.loglevel(configured, args.verbose, args.quiet, false);
    rns_tools::init_tracing(
        level,
        rns_tools::config_log_timestamps(&rns_dir),
        true,
        std::io::stdout,
    );
    let handle = match rns_runtime::reticulum::init(
        rnsconfig.as_deref(),
        None,
        ShutdownSignal::new(),
        Arc::new(AtomicBool::new(true)),
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
    if let Err(e) = std::fs::create_dir_all(&configdir) {
        abort(
            &handle,
            &format!("Could not create {}: {e}", configdir.display()),
        )
        .await;
    }
    let identity_path = non_empty(args.identity)
        .map(PathBuf::from)
        .unwrap_or_else(|| configdir.join("client_identity"));
    let identity = if identity_path.is_file() {
        Identity::from_file(&identity_path).ok()
    } else {
        let id = Identity::new();
        id.to_file(&identity_path).ok().map(|_| id)
    };
    let Some(identity) = identity else {
        abort(&handle, "Could not initialize client identity").await;
    };
    let config = match ClientConfig::load_or_create(&configdir) {
        Ok(config) => config,
        Err(e) => {
            tracing::error!(
                "Could not parse the configuration at {}",
                configdir.join("client_config").display()
            );
            tracing::error!("Check your configuration file for errors! ({e})");
            rns_tools::exit(&handle, 255).await;
        }
    };
    if let Some(level) = config.loglevel {
        tracing::debug!("Client log level {level}");
    }

    let remote = args.repository;
    let destination = match config.parse_remote_destination_url(&remote) {
        Ok(hash) => hash,
        Err(message) => abort(&handle, &message).await,
    };
    let Ok(destination) = <[u8; 16]>::try_from(destination.as_slice()) else {
        abort(&handle, "Invalid destination hash length").await;
    };
    print!("Requesting path... ");
    let _ = std::io::stdout().flush();
    let path_timeout = rns_tools::medium_path_timeout(&handle).await.max(15.0);
    if handle
        .await_path(destination, Duration::from_secs_f64(path_timeout))
        .await
        .is_err()
    {
        println!();
        abort(
            &handle,
            &format!("Could not resolve path to {}", prettyhex(&destination)),
        )
        .await;
    }
    print!("\rPath resolved      ");
    print!("\rEstablishing link... ");
    let _ = std::io::stdout().flush();
    let hops = handle.hops_to(destination).await.unwrap_or(1);
    let first_hop = handle
        .first_hop_timeout(destination)
        .await
        .map_or(rns_wire::constants::DEFAULT_PER_HOP_TIMEOUT, |d| {
            d.as_secs_f64()
        });
    let establishment =
        first_hop + rns_wire::constants::DEFAULT_PER_HOP_TIMEOUT * f64::from(hops.max(1));
    let options = rns_runtime::reticulum::LinkConnectOptions {
        path_timeout: Duration::from_secs_f64(path_timeout),
        establishment_timeout: Some(Duration::from_secs_f64(establishment.max(15.0))),
        client_label: "rngit".to_string(),
        identify: true,
        ..Default::default()
    };
    let session = match handle.connect_link(destination, identity, options).await {
        Ok(session) => session,
        Err(_) => abort(&handle, "Link establishment failed").await,
    };
    print!("\rLink established     ");
    print!("\r                       \r");
    let _ = std::io::stdout().flush();
    let outcome = match config.parse_remote_url(&remote) {
        Err(message) => Err(message),
        Ok((_, group, repo)) => {
            let repo_path = format!("{group}/{repo}");
            let request = rmpv::Value::Map(vec![(
                rmpv::Value::from(IDX_REPOSITORY),
                rmpv::Value::from(repo_path.as_str()),
            )]);
            let options = rns_runtime::link_session::RequestOptions {
                timeout: Some(Duration::from_secs(120)),
                ..Default::default()
            };
            match session
                .handle
                .request_with_options(PATH_CREATE, request, options)
                .await
            {
                Ok(response) if matches!(response.value, rmpv::Value::Binary(_)) => {
                    create_outcome(&repo_path, Some(&response.data))
                }
                Ok(_) => create_outcome(&repo_path, None),
                Err(_) => Err("Request failed or timed out".to_string()),
            }
        }
    };
    session.handle.close().await;
    match outcome {
        Ok(message) => {
            println!("{message}");
            rns_tools::exit(&handle, 0).await;
        }
        Err(message) => abort(&handle, &message).await,
    }
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
    } else if argv.get(1).map(String::as_str) == Some("create") {
        argv.remove(1);
        let args = CreateArgs::parse_from(argv);
        if args.version {
            println!("rngit-rs {RS_RETICULUM_VERSION}");
            return;
        }
        create(args).await;
        return;
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
        Ok(repositories) => Arc::new(RwLock::new(repositories)),
        Err(e) => {
            tracing::error!("Could not load repositories: {e:?}");
            rns_tools::exit(&handle, 1).await;
        }
    };

    let options = DestinationRuntimeOptions {
        endpoint_dispatch: Some(handle.link_endpoint_dispatch_handle()),
        ..DestinationRuntimeOptions::default()
    };
    let mut registered = match handle
        .register_destination(identity, APP_NAME, options)
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
                let repos = list_repos.read().unwrap_or_else(|e| e.into_inner());
                match handle_list(&repos, hash.as_ref(), &request.value) {
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
    let tempdirs: LinkTempDirs = Arc::default();
    let fetch: Handler = handle_fetch;
    let push: Handler = |r, i, d| handle_push(r, i, d).map(Reply::Bytes);
    let delete: Handler = |r, i, d| handle_delete(r, i, d).map(Reply::Bytes);
    let create: Handler = |r, i, d| handle_create(r, i, d).map(Reply::Bytes);
    for (path, handler) in [
        (PATH_FETCH, fetch),
        (PATH_PUSH, push),
        (PATH_CREATE, create),
        (PATH_DELETE, delete),
    ] {
        let ok = registered
            .handle
            .register_deferred_request_handler(
                path,
                AllowPolicy::AllowAll,
                Vec::new(),
                true,
                REPLY_LIMIT,
                deferred(repositories.clone(), tempdirs.clone(), handler),
            )
            .await;
        if !matches!(ok, Ok(true)) {
            tracing::error!("Could not register the {path} handler");
            rns_tools::exit(&handle, 1).await;
        }
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
            Some(link_id) = registered.events.links_closed.recv() => {
                let removed = tempdirs.lock().unwrap_or_else(|e| e.into_inner()).remove(&link_id);
                for tmpdir in removed.into_iter().flatten() {
                    let name = tmpdir.path().display().to_string();
                    match tmpdir.close() {
                        Ok(()) => tracing::debug!("Cleaned up {name}"),
                        Err(e) => tracing::error!("Error while cleaning temporary directory: {e}"),
                    }
                }
            }
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
