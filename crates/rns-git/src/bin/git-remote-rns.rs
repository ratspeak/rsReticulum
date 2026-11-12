//! `git-remote-rns`: the git remote helper for `rns://` URLs
//! (`RNS/Utilities/rngit/client.py@1.6.0`).

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::{Duration, Instant};

use rns_git::remote_helper::{
    Abort, ClientConfig, ClientConfigError, PATH_TIMEOUT, REQUEST_TIMEOUT, RemoteHelper, Response,
    Transport, load_or_create_identity, parse_args, resolve_config_dir,
};
use rns_git::server::APP_NAME;
use rns_runtime::lifecycle::ShutdownSignal;
use rns_runtime::link_session::{LinkSessionHandle, RequestOptions};
use rns_runtime::reticulum::{LinkConnectOptions, ReticulumHandle};
use rns_tools::rsg::pyfmt::py_fromhex;
use rns_transport::messages::PathRequestOptions;

/// `RNS.LOG_MAXSIZE` (`RNS/__init__.py:74`).
const LOG_MAXSIZE: u64 = 5 * 1024 * 1024;

/// `client_log`, appended per line and rotated to `.1` past `LOG_MAXSIZE`
/// as `RNS.log` does with `LOG_FILE` (`RNS/__init__.py:137-143`).
#[derive(Clone)]
struct ClientLog(PathBuf);

impl Write for ClientLog {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let appended = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.0)
            .and_then(|mut file| file.write_all(buf).map(|()| file.metadata()));
        if let Ok(Ok(meta)) = appended
            && meta.len() > LOG_MAXSIZE
        {
            let mut rotated = self.0.clone().into_os_string();
            rotated.push(".1");
            let _ = std::fs::remove_file(&rotated);
            let _ = std::fs::rename(&self.0, &rotated);
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn status(text: &str) {
    let mut stderr = std::io::stderr();
    let _ = stderr.write_all(text.as_bytes());
    let _ = stderr.flush();
}

fn prettyhex(hash: &[u8]) -> String {
    format!("<{}>", hex::encode(hash))
}

/// Requests on the established link, made from the blocking command loop.
struct LinkTransport {
    runtime: tokio::runtime::Handle,
    link: LinkSessionHandle,
    spool: PathBuf,
}

impl Transport for LinkTransport {
    fn request(&mut self, path: &str, data: rmpv::Value) -> Option<Response> {
        tracing::debug!("Sending request: {path}");
        let options = RequestOptions {
            timeout: Some(Duration::from_secs_f64(REQUEST_TIMEOUT)),
            spool_dir: Some(self.spool.clone()),
            ..RequestOptions::default()
        };
        let request = self.link.request_with_options(path, data, options);
        let response = self
            .runtime
            .block_on(async {
                tokio::time::timeout(Duration::from_secs_f64(REQUEST_TIMEOUT), request).await
            })
            .ok()?
            .map_err(|e| tracing::debug!("Request {path} failed: {e}"))
            .ok()?;
        tracing::debug!("Got response for: {path}");
        match (response.metadata, response.file) {
            (Some(metadata), Some(file)) => Some(Response::File {
                path: file,
                metadata: rmpv::decode::read_value(&mut metadata.as_slice())
                    .unwrap_or(rmpv::Value::Nil),
            }),
            // A spooled Resource response without metadata: the value itself.
            (None, Some(file)) => {
                let data = std::fs::read(&file).ok();
                let _ = std::fs::remove_file(&file);
                let value = rmpv::decode::read_value(&mut data?.as_slice()).ok()?;
                Some(response_value(value))
            }
            _ => Some(response_value(response.value)),
        }
    }
}

fn response_value(value: rmpv::Value) -> Response {
    match value {
        rmpv::Value::Binary(bytes) => Response::Bytes(bytes),
        other => Response::Other(other),
    }
}

/// `abort()`; `sys.exit` also runs Reticulum's exit handler (Reticulum.py:389).
fn abort(
    reason: Abort,
    link: Option<&LinkSessionHandle>,
    handle: &ReticulumHandle,
    runtime: &tokio::runtime::Runtime,
) -> ! {
    eprintln!("{}", reason.message());
    runtime.block_on(async {
        if let Some(link) = link {
            link.close().await;
        }
        rns_tools::exit(handle, reason.code).await
    })
}

/// Whether the path is known and its announce has reached this process.
/// A shared-instance client's `has_path` reads the daemon's path table, so the
/// identity can arrive just after the path shows up there.
async fn path_ready(handle: &ReticulumHandle, hash: [u8; 16]) -> bool {
    handle.has_path(hash).await.unwrap_or(false)
        && matches!(handle.recall_without_use(hash).await, Ok(Some(_)))
}

/// `Transport.await_path` with `medium_path_timeout(PATH_TIMEOUT)` (`client.py:229`).
async fn await_path(handle: &ReticulumHandle, hash: [u8; 16]) -> bool {
    if path_ready(handle, hash).await {
        return true;
    }
    let _ = handle
        .request_path(hash, PathRequestOptions::default())
        .await;
    let wait = PATH_TIMEOUT.max(rns_tools::medium_path_timeout(handle).await);
    let deadline = Instant::now() + Duration::from_secs_f64(wait);
    while Instant::now() < deadline {
        if path_ready(handle, hash).await {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    handle.has_path(hash).await.unwrap_or(false)
}

fn init_logging(configdir: &Path, rnsconfig: Option<&str>, level: Option<i64>) {
    let rns_dir = rns_runtime::platform::resolve_config_dir(rnsconfig);
    // Reticulum applies its own config loglevel first; the client config overrides it.
    let level = level.or_else(|| {
        rns_runtime::config::Config::from_file(&rns_dir.join("config"))
            .ok()
            .and_then(|c| c.section("logging")?.get_int("loglevel"))
            .or(Some(rns_tools::LogLevel::Notice as i64))
    });
    let Some(level) = level.filter(|l| *l >= 0) else {
        return;
    };
    let log = ClientLog(configdir.join("client_log"));
    rns_tools::init_tracing(
        rns_tools::LogLevel::clamped(level),
        rns_tools::config_log_timestamps(&rns_dir),
        false,
        move || log.clone(),
    );
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let url = match parse_args(&args) {
        Ok(url) => url,
        Err((message, code)) => {
            eprintln!("{message}");
            std::process::exit(code);
        }
    };
    let configdir = std::env::var_os("RNGIT_CONFIG").map(PathBuf::from);
    let rnsconfig = std::env::var("RNS_CONFIG").ok();
    let home = PathBuf::from(std::env::var_os("HOME").unwrap_or_default());
    let configdir = resolve_config_dir(configdir.as_deref(), &home);

    let config = match ClientConfig::load(&configdir) {
        Ok(config) => config,
        Err(e @ ClientConfigError::Parse(..)) => {
            eprintln!("{e}");
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(1);
        }
    };
    init_logging(&configdir, rnsconfig.as_deref(), config.loglevel);

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    let handle = match runtime.block_on(rns_runtime::reticulum::init(
        rnsconfig.as_deref(),
        None,
        ShutdownSignal::new(),
        Arc::new(AtomicBool::new(false)),
    )) {
        Ok(handle) => handle,
        Err(e) => {
            eprintln!("Failed to initialize Reticulum: {e}");
            std::process::exit(1);
        }
    };
    runtime.block_on(handle.wants_destination_type(APP_NAME));

    let identitypath = configdir.join("client_identity");
    let existed = identitypath.is_file();
    let Some(identity) = load_or_create_identity(&identitypath) else {
        tracing::error!("Could not initialize client identity.");
        std::process::exit(1);
    };
    if existed {
        tracing::debug!("Client identity loaded from {}", identitypath.display());
    } else {
        tracing::debug!(
            "Client identity generated and persisted to {}",
            identitypath.display()
        );
    }
    let destination = config.resolve_destination(&url.destination);

    // connect_server (client.py:223-244)
    let hash = match py_fromhex(&destination) {
        Ok(hash) => hash,
        Err(e) => abort(
            Abort::new(format!("Invalid destination hash: {e}")),
            None,
            &handle,
            &runtime,
        ),
    };
    tracing::debug!("Requesting path to {}", prettyhex(&hash));
    status("Requesting path...");
    let hash16: Option<[u8; 16]> = hash.as_slice().try_into().ok();
    let found = match hash16 {
        Some(h) => runtime.block_on(await_path(&handle, h)),
        None => false,
    };
    let Some(hash16) = hash16.filter(|_| found) else {
        status("\n");
        abort(
            Abort::new(format!("Could not resolve path to {}", prettyhex(&hash))),
            None,
            &handle,
            &runtime,
        );
    };
    tracing::debug!("Path to {} resolved", prettyhex(&hash));
    status("\rPath resolved     ");
    let recalled = runtime.block_on(handle.recall(hash16)).ok().flatten();
    if recalled.is_none() {
        abort(
            Abort::new("Could not recall remote identity. Is the server announcing?"),
            None,
            &handle,
            &runtime,
        );
    }
    status("\rEstablishing link...");

    // The Link fails at its own establishment timeout, which ends run()'s
    // max(15, establishment_timeout) wait (client.py:341-346).
    let options = LinkConnectOptions {
        client_label: "git-remote-rns".to_string(),
        identify: true,
        ..LinkConnectOptions::default()
    };
    let session = runtime.block_on(handle.connect_link(hash16, identity, options));
    let mut session = match session {
        Ok(session) => session,
        Err(e) => {
            tracing::debug!("Link establishment failed: {e}");
            abort(
                Abort::new("Failed to establish link"),
                None,
                &handle,
                &runtime,
            );
        }
    };
    tracing::debug!("Link established, identifying...");
    status("\rLink established with remote\n");
    let link = session.handle.clone();
    let events = std::mem::replace(&mut session.events, tokio::sync::mpsc::channel(1).1);
    runtime.spawn(async move {
        let mut events = events;
        while events.recv().await.is_some() {}
    });

    let spool = match tempfile::tempdir() {
        Ok(dir) => dir,
        Err(e) => abort(Abort::new(e.to_string()), Some(&link), &handle, &runtime),
    };
    let transport = LinkTransport {
        runtime: runtime.handle().clone(),
        link: link.clone(),
        spool: spool.path().to_path_buf(),
    };
    let git_dir = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let mut helper = RemoteHelper::new(transport, url.repo_path(), config.ref_batch_size, git_dir);
    let result = {
        let stdin = std::io::stdin();
        let mut stdin = stdin.lock();
        let mut stdout = std::io::stdout();
        let mut stderr = std::io::stderr();
        helper.run(&mut stdin, &mut stdout, &mut stderr)
    };
    drop(helper);
    if let Err(reason) = result {
        drop(spool);
        abort(reason, Some(&link), &handle, &runtime);
    }
    runtime.block_on(link.close());
    drop(spool);
    runtime.block_on(rns_tools::shut_down(&handle));
    std::process::exit(0);
}
