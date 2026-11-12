//! `rngit fork`, `rngit mirror` and `rngit sync` (`fork_repository`,
//! `mirror_repository`, `_remote_clone_operation`, `sync_repository`,
//! `server.py:606-716@1.6.0`).

use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::Duration;

use rns_identity::identity::Identity;
use rns_runtime::lifecycle::ShutdownSignal;
use rns_runtime::reticulum::ReticulumHandle;

use crate::server::client::{ClientConfig, client_config_dir};
use crate::server::{
    APP_NAME, IDX_REPOSITORY, PATH_FORK, PATH_MIRROR, PATH_SYNC, RES_DISALLOWED, RES_INVALID_REQ,
    RES_NOT_FOUND, RES_OK,
};

/// The three subcommands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operation {
    Fork,
    Mirror,
    Sync,
}

impl Operation {
    fn name(self) -> &'static str {
        match self {
            Operation::Fork => "fork",
            Operation::Mirror => "mirror",
            Operation::Sync => "sync",
        }
    }
}

/// What the subcommand was given on the command line.
#[derive(Debug, Clone, Default)]
pub struct ClientArgs {
    pub config: Option<String>,
    pub rnsconfig: Option<String>,
    pub identity: Option<String>,
    /// `fork`/`mirror`: the source URL; `sync`: unused.
    pub source: Option<String>,
    /// `fork`/`mirror`: the target URL; `sync`: the repository URL.
    pub target: String,
    pub verbose: u8,
    pub quiet: u8,
}

/// The decoded status text, or `fallback` for a lone status byte.
fn reply_text(response: &[u8], fallback: &str) -> String {
    if response.len() > 1 {
        response[1..].utf8_chunks().map(|c| c.valid()).collect()
    } else {
        fallback.to_string()
    }
}

/// What `_remote_clone_operation` and `sync_repository` print for a reply
/// (`server.py:646-667`, `694-711`): `Ok` on success, `Err` for the abort text.
pub fn outcome(op: Operation, repo_path: &str, response: Option<&[u8]>) -> Result<String, String> {
    let Some(response) = response.filter(|r| !r.is_empty()) else {
        return Err("No response from remote".into());
    };
    match response[0] {
        RES_OK => Ok(match op {
            Operation::Sync => "Repository synced".to_string(),
            _ => format!("Repository {}ed to {repo_path}", op.name()),
        }),
        RES_NOT_FOUND => Err(reply_text(response, "Not found")),
        RES_INVALID_REQ => Err(reply_text(response, "Invalid request")),
        RES_DISALLOWED => Err(reply_text(response, "Not allowed")),
        _ => Err(format!(
            "Server error: {}",
            reply_text(response, "Unknown error")
        )),
    }
}

fn prettyhex(hash: &[u8]) -> String {
    format!("<{}>", hex::encode(hash))
}

/// `ReticulumGitClient.abort` (`server.py:433-434`).
async fn abort(handle: &ReticulumHandle, message: &str) -> ! {
    println!("{message}");
    rns_tools::exit(handle, 1).await
}

/// Run `rngit fork`, `rngit mirror` or `rngit sync`; never returns.
pub async fn run(op: Operation, args: ClientArgs) -> ! {
    let non_empty = |v: Option<String>| v.filter(|v| !v.is_empty());
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

    // fork_repository / mirror_repository, then _resolve_aliased_url (server.py:610-626).
    let mut source = None;
    if op != Operation::Sync {
        let Some(src) = non_empty(args.source) else {
            abort(&handle, "No source specified").await;
        };
        if args.target.is_empty() {
            abort(&handle, "No target specified").await;
        }
        let resolved = if src.to_lowercase().starts_with("rns://") {
            match config.parse_remote_url(&src) {
                Ok((hash, group, repo)) if !group.is_empty() && !repo.is_empty() => {
                    format!("rns://{}/{group}/{repo}", hex::encode(hash))
                }
                Ok(_) => abort(&handle, "Invalid source URL").await,
                Err(message) => abort(&handle, &message).await,
            }
        } else {
            src
        };
        source = Some(resolved);
    } else if args.target.is_empty() {
        abort(&handle, "No remote specified").await;
    }

    // connect_remote (server.py:466-483).
    let remote = args.target;
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

    let result = match config.parse_remote_url(&remote) {
        Err(message) => Err(message),
        Ok((_, group, repo)) => {
            let repo_path = format!("{group}/{repo}");
            let mut request = vec![(
                rmpv::Value::from(IDX_REPOSITORY),
                rmpv::Value::from(repo_path.as_str()),
            )];
            let path = match op {
                Operation::Fork => PATH_FORK,
                Operation::Mirror => PATH_MIRROR,
                Operation::Sync => PATH_SYNC,
            };
            match &source {
                Some(source) => {
                    request.push((
                        rmpv::Value::from("source"),
                        rmpv::Value::from(source.as_str()),
                    ));
                    println!("Remote is {}ing repository to {repo_path}...", op.name());
                }
                None => println!("Remote is syncing repository..."),
            }
            let options = rns_runtime::link_session::RequestOptions {
                timeout: Some(Duration::from_secs(7200)),
                ..Default::default()
            };
            match session
                .handle
                .request_with_options(path, rmpv::Value::Map(request), options)
                .await
            {
                Ok(response) if matches!(response.value, rmpv::Value::Binary(_)) => {
                    outcome(op, &repo_path, Some(&response.data))
                }
                Ok(_) => outcome(op, &repo_path, None),
                Err(_) => Err("Request failed or timed out".to_string()),
            }
        }
    };
    session.handle.close().await;
    match result {
        Ok(message) => {
            println!("{message}");
            rns_tools::exit(&handle, 0).await;
        }
        Err(message) => abort(&handle, &message).await,
    }
}
