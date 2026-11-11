//! File transfer over Reticulum Links and Resources: send, receive and fetch.
//! The default destination aspect is `rncp.receive`. See [`spawn_rncp_listener`]
//! for its authorization and shutdown behaviour; a Resource proof alone does
//! not establish that the receiving application saved a file.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use tokio::sync::mpsc;
use tokio::time::timeout;

use rns_crypto::ed25519::Ed25519PublicKey;
use rns_identity::destination::{DestType, Destination, Direction};
use rns_identity::identity::Identity;
use rns_link::link::LinkAction;
use rns_link::link::{CloseReason, Link};
use rns_protocol::resource::{OutboundTransfer, TransferAction};
use rns_transport::link_messages::DestinationEvent;
use rns_transport::messages::{
    AnnounceRpcEntry, InterfaceId, LinkEndpointLifecycleEvent, LinkEndpointRole, OutboundRequest,
    TransportMessage, TransportQuery, TransportQueryResponse,
};
use tokio::sync::oneshot;

use crate::lifecycle::ShutdownSignal;
use crate::link_manager::{DestinationRequest, LinkManager, RequestOutcome, ResourceCompletion};
use crate::resource_source::{PreparedResourceSource, ResourceOptions, ResourceSource};
use rns_identity::destination::AllowPolicy;
use rns_link::link::ResourceStrategy;

/// Fetch-denial response value, the integer 240 (packed `cc f0`).
pub const REQ_FETCH_NOT_ALLOWED: u8 = 0xF0;

/// Python sleeps this long after tearing links down on SIGINT so the
/// LINKCLOSE packets can leave (Transport.detach_interfaces).
const RNCP_INTERRUPT_TEARDOWN_WINDOW: Duration = Duration::from_millis(150);

/// Idle wake-up for the link watchdog and Resource timeouts.
const RNCP_SERVICE_INTERVAL: Duration = Duration::from_secs(1);

pub const FETCH_PATH_NAME: &str = "fetch_file";

pub const DEFAULT_RNCP_APP_NAME: &str = "rncp.receive";

/// Python sends the final Resource proof before it runs the receiver-side
/// conclusion callback that materialises the file. Keep the Link alive for a
/// short, bounded settlement window after a valid proof so an immediate
/// teardown cannot race that callback and turn a proven Resource into
/// `FAILED` on a loaded peer.
const RNCP_POST_PROOF_SETTLE: Duration = Duration::from_millis(250);

async fn send_endpoint_packet(
    transport_tx: &mpsc::Sender<TransportMessage>,
    link_id: [u8; 16],
    raw: Bytes,
) -> Result<(), RncpError> {
    crate::link_endpoint::send(transport_tx, link_id, LinkEndpointRole::Initiator, raw)
        .await
        .map_err(|_| RncpError::TransportUnavailable)
}

pub fn default_rncp_app_name() -> &'static str {
    DEFAULT_RNCP_APP_NAME
}

#[derive(Debug, thiserror::Error)]
pub enum RncpError {
    #[error("link request admission failed: {0}")]
    RequestDispatch(#[from] rns_transport::link_messages::LinkRequestDispatchError),
    #[error("link request stamp failed: {0}")]
    StampFailure(#[from] rns_link::stamp::LinkStampError),
    #[error("transport channel unavailable")]
    TransportUnavailable,
    #[error("timed out waiting for {0}")]
    Timeout(&'static str),
    #[error("remote destination identity has not been announced")]
    PathTimeout,
    #[error("announce carried no public key")]
    NoIdentity,
    #[error("link handshake failed: {0}")]
    HandshakeFailed(String),
    #[error("link proof validation failed: {0}")]
    ProofInvalid(String),
    #[error("link crypto error: {0}")]
    LinkCrypto(String),
    #[error("resource build failed: {0}")]
    ResourceCreate(String),
    #[error("resource transfer failed: {0}")]
    ResourceFailed(String),
    #[error("I/O error: {0}")]
    Io(String),
    #[error("local identity has no signing key")]
    NoSigningKey,
    /// The listener answered REQ_FETCH_NOT_ALLOWED.
    #[error("fetch not allowed by the remote")]
    Denied,
    /// The listener answered `False`: the file does not exist.
    #[error("file not found on the remote")]
    NotFound,
    /// The listener answered `None`.
    #[error("error on the remote system")]
    RemoteError,
    /// The fetch request got no answer before its timeout or the link closed.
    #[error("fetch request failed")]
    RequestFailed,
    /// The caller's shutdown signal fired; any established link was closed.
    #[error("interrupted")]
    Interrupted,
}

#[derive(Debug, Clone)]
pub struct RncpOutcome {
    pub file_name: String,
    pub bytes: usize,
    pub link_rtt: Duration,
    pub duration: Duration,
}

pub struct RncpSendRequest<'a> {
    pub transport_tx: mpsc::Sender<TransportMessage>,
    pub identity: Identity,
    pub dest_hash: [u8; 16],
    pub file_name: &'a str,
    /// File contents, read one Resource segment at a time.
    pub source: Box<dyn ResourceSource>,
    pub auto_compress: bool,
    /// Path wait, rncp's `max(-w, medium path timeout)`. The link proof wait
    /// ends at the later of this and the link establishment timeout; the
    /// transfer itself has no deadline.
    pub path_timeout: Duration,
    pub progress_tx: Option<mpsc::Sender<f32>>,
    /// Stops the transfer and closes the link, as rncp does on SIGINT.
    pub shutdown: Option<ShutdownSignal>,
}

#[derive(Debug, Clone)]
pub enum RncpEvent {
    LinkEstablished {
        link_id: [u8; 16],
    },
    /// An identified sender passed the listener's identity check. The hash is
    /// from LinkIdentify; unidentified peers do not emit this event.
    SenderIdentified {
        link_id: [u8; 16],
        identity_hash: [u8; 16],
    },
    SenderDenied {
        link_id: [u8; 16],
        identity_hash: [u8; 16],
    },
    Completed {
        link_id: [u8; 16],
        file_name: String,
        saved_path: PathBuf,
        bytes: usize,
    },
    WriteFailed {
        link_id: [u8; 16],
        file_name: String,
        reason: String,
    },
    FetchServing {
        link_id: [u8; 16],
        file_name: String,
        bytes: usize,
    },
    FetchDenied {
        link_id: [u8; 16],
        reason: String,
    },
}

/// The value a fetch handler answers with, and the status a fetch client
/// derives from it (rncp.py:172-208, 463-474).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FetchReply {
    Found,
    NotFound,
    RemoteError,
    NotAllowed,
}

impl FetchReply {
    /// The packed MessagePack value: `True`, `False` or the integer 240.
    fn packed(self) -> Vec<u8> {
        match self {
            Self::Found => vec![0xC3],
            Self::NotFound => vec![0xC2],
            Self::RemoteError => vec![0xC0],
            Self::NotAllowed => vec![0xCC, REQ_FETCH_NOT_ALLOWED],
        }
    }

    /// Python compares with `==`, so `0` and `240.0` match too.
    fn from_value(value: &rmpv::Value) -> Self {
        let number = match value {
            rmpv::Value::Nil => return Self::RemoteError,
            rmpv::Value::Boolean(false) => return Self::NotFound,
            rmpv::Value::Integer(i) => i.as_f64(),
            rmpv::Value::F32(f) => Some(f64::from(*f)),
            rmpv::Value::F64(f) => Some(*f),
            _ => None,
        };
        match number {
            Some(0.0) => Self::NotFound,
            Some(n) if n == f64::from(REQ_FETCH_NOT_ALLOWED) => Self::NotAllowed,
            // Older rncp-rs listeners sent the single byte 0xF0, fixint -16.
            Some(-16.0) => Self::NotAllowed,
            _ => Self::Found,
        }
    }
}

/// `posixpath.normpath`.
fn normpath(path: &str) -> String {
    if path.is_empty() {
        return ".".into();
    }
    let initial_slashes = if path.starts_with("//") && !path.starts_with("///") {
        2
    } else if path.starts_with('/') {
        1
    } else {
        0
    };
    let mut comps: Vec<&str> = Vec::new();
    for comp in path.split('/') {
        if comp.is_empty() || comp == "." {
            continue;
        }
        if comp != ".." || (initial_slashes == 0 && comps.is_empty()) || comps.last() == Some(&"..")
        {
            comps.push(comp);
        } else {
            comps.pop();
        }
    }
    let normalized = format!("{}{}", "/".repeat(initial_slashes), comps.join("/"));
    if normalized.is_empty() {
        ".".into()
    } else {
        normalized
    }
}

/// `os.path.expanduser` for `~` and `~/...`; `~user` is left unchanged.
fn expanduser(path: &str, home: Option<&str>) -> String {
    let Some(home) = home else {
        return path.to_string();
    };
    if path != "~" && !path.starts_with("~/") {
        return path.to_string();
    }
    let expanded = format!("{}{}", home.trim_end_matches('/'), &path[1..]);
    if expanded.is_empty() {
        "/".into()
    } else {
        expanded
    }
}

/// `os.path.abspath`, lexical only: symlinks are not resolved.
fn abspath(path: &str, cwd: &str) -> String {
    if path.starts_with('/') {
        normpath(path)
    } else if cwd.ends_with('/') {
        normpath(&format!("{cwd}{path}"))
    } else {
        normpath(&format!("{cwd}/{path}"))
    }
}

fn process_home() -> Option<String> {
    std::env::var("HOME").ok()
}

fn process_cwd() -> String {
    std::env::current_dir()
        .map(|dir| dir.to_string_lossy().into_owned())
        .unwrap_or_else(|_| "/".into())
}

/// The path a fetch request names, or `None` when it falls outside the jail
/// (rncp.py:177-185). `jail` is already absolute and normalised.
fn fetch_request_path(
    jail: Option<&str>,
    data: &str,
    home: Option<&str>,
    cwd: &str,
) -> Option<String> {
    match jail {
        Some(jail) => {
            let prefix = format!("{jail}/");
            let data = if data.starts_with(&prefix) {
                data.replace(&prefix, "")
            } else {
                data.to_string()
            };
            let path = abspath(&expanduser(&format!("{jail}/{data}"), home), cwd);
            path.starts_with(&prefix).then_some(path)
        }
        None => Some(abspath(&expanduser(data, home), cwd)),
    }
}

/// Refuses a jailed file whose resolved location leaves the resolved jail,
/// such as a symlink pointing outside it.
fn escapes_jail(path: &str, jail: &str) -> bool {
    match (std::fs::canonicalize(path), std::fs::canonicalize(jail)) {
        (Ok(path), Ok(jail)) => !path.starts_with(jail),
        _ => true,
    }
}

/// `os.path.basename`.
fn basename(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

/// Listener policy and file locations. Defaults generate a fresh identity,
/// use `rncp.receive` and the current directory, disable fetch and overwrite,
/// and leave the allow-list empty. Supply a persistent identity when the
/// listener must retain its destination address.
///
/// Received filenames use their platform basename when available, or the
/// original string otherwise. With overwrite disabled, an existing name gets
/// a numeric suffix; the existence check and
/// write are separate, so this is not exclusive creation. Use a save directory
/// controlled by the listener, without untrusted symlinks or concurrent writers.
pub struct RncpListenerConfig {
    pub identity: Identity,
    pub app_name: String,
    pub save_dir: PathBuf,
    /// Bypass identity allow-list checks for push and fetch, including for
    /// unidentified peers.
    pub allow_all: bool,
    /// Allowed identity hashes, ignored when `allow_all` is true.
    pub allowed: Vec<[u8; 16]>,
    pub overwrite: bool,
    /// Serve `fetch_file` requests as well as receiving pushed files.
    pub allow_fetch: bool,
    /// Restrict fetched paths to this directory. Requests are resolved
    /// lexically as rncp does; a path that then resolves outside the jail
    /// (through a symlink) is also refused. `None` allows any readable path.
    /// This is not an OS sandbox or a race-free filesystem boundary.
    pub fetch_jail: Option<PathBuf>,
    /// Try compression when serving fetched files; enabled by default.
    pub fetch_auto_compress: bool,
}

impl Default for RncpListenerConfig {
    fn default() -> Self {
        Self {
            identity: Identity::new(),
            app_name: DEFAULT_RNCP_APP_NAME.to_string(),
            save_dir: PathBuf::from("."),
            allow_all: false,
            allowed: Vec::new(),
            overwrite: false,
            allow_fetch: false,
            fetch_jail: None,
            fetch_auto_compress: true,
        }
    }
}

pub struct RncpListenerHandle {
    pub destination_hash: [u8; 16],
    task: tokio::task::JoinHandle<()>,
}

impl RncpListenerHandle {
    pub fn destination_hash(&self) -> [u8; 16] {
        self.destination_hash
    }
    /// Abort and join the listener's event/file-writing task. The separately
    /// spawned LinkManager is not joined or stopped here, and the destination
    /// is not deregistered. This is not a complete service shutdown.
    pub async fn shutdown(self) {
        self.task.abort();
        let _ = self.task.await;
    }
}

/// Register a file receiver and spawn its background tasks. This function
/// does not announce the destination; the caller owns reachability/publication.
/// Drain `events_tx` to avoid blocking completion processing. Fetched files
/// are read one Resource segment at a time.
///
/// # Authorization
///
/// Unless `allow_all` is set, a pushed Resource is accepted only on a link
/// whose peer identified with an allowed identity, and a peer identifying with
/// any other identity has its link torn down. `fetch_file` is registered with
/// ALLOW_LIST (or ALLOW_ALL), so requests from other peers get no answer.
///
/// Keep the handle and read [`RncpListenerHandle::shutdown`] before embedding this
/// listener in a longer-lived runtime.
pub async fn spawn_rncp_listener(
    transport_tx: mpsc::Sender<TransportMessage>,
    cfg: RncpListenerConfig,
    events_tx: mpsc::Sender<RncpEvent>,
) -> Result<RncpListenerHandle, RncpError> {
    let signing_key = cfg
        .identity
        .get_signing_key()
        .ok_or(RncpError::NoSigningKey)?;

    let destination = Destination::new(
        Some(&cfg.identity),
        Direction::In,
        DestType::Single,
        &cfg.app_name,
    )
    .map_err(|e| RncpError::HandshakeFailed(format!("destination: {e:?}")))?;
    let dest_hash = destination.hash;

    let (dest_tx, dest_rx) = mpsc::channel::<DestinationEvent>(256);
    transport_tx
        .send(TransportMessage::RegisterDestination {
            hash: dest_hash,
            app_name: cfg.app_name.clone(),
            delivery_tx: Some(dest_tx),
        })
        .await
        .map_err(|_| RncpError::TransportUnavailable)?;
    let mut link_mgr = LinkManager::with_destination(
        transport_tx.clone(),
        dest_rx,
        &cfg.identity,
        &cfg.app_name,
        Some(signing_key),
    );

    let (completion_tx, mut completion_rx) = mpsc::channel::<ResourceCompletion>(64);
    link_mgr.set_resource_completion_channel(completion_tx);

    let allowed_set: Arc<std::collections::HashSet<[u8; 16]>> =
        Arc::new(cfg.allowed.iter().copied().collect());
    let allow_all = cfg.allow_all;

    // Every incoming link: ACCEPT_APP with the identity check (rncp.py:234-266).
    let (identified_tx, mut identified_rx) = mpsc::channel::<([u8; 16], [u8; 16])>(64);
    link_mgr.set_link_identified_channel(identified_tx);
    link_mgr.set_resource_strategy(ResourceStrategy::AcceptApp);
    // Received files are handed to storage, as upstream rncp moves its file.
    link_mgr.set_inbound_reassembly_limit(None);
    let link_identities = link_mgr.link_identities_handle();
    let push_allowed = Arc::clone(&allowed_set);
    link_mgr.set_resource_accept_handler(move |link_id, _adv| {
        allow_all
            || link_identities
                .lock()
                .ok()
                .and_then(|ids| ids.get(&link_id).copied())
                .is_some_and(|hash| push_allowed.contains(&hash))
    });
    if !allow_all {
        let gate_allowed = Arc::clone(&allowed_set);
        link_mgr.set_link_identity_gate(move |_link_id, identity_hash| {
            gate_allowed.contains(&identity_hash)
        });
    }

    if cfg.allow_fetch {
        let jail = cfg.fetch_jail.as_ref().map(|jail| {
            abspath(
                &expanduser(&jail.to_string_lossy(), process_home().as_deref()),
                &process_cwd(),
            )
        });
        let auto_compress = cfg.fetch_auto_compress;
        let fetch_events = events_tx.clone();
        let (allow, allowed_list) = if allow_all {
            (AllowPolicy::AllowAll, None)
        } else {
            (AllowPolicy::AllowList, Some(cfg.allowed.clone()))
        };
        link_mgr.register_request_handler(
            FETCH_PATH_NAME,
            allow,
            allowed_list,
            auto_compress,
            move |request: DestinationRequest| {
                serve_fetch(request, jail.as_deref(), auto_compress, &fetch_events)
            },
        );
    }

    let app_name = cfg.app_name.clone();
    let save_dir = cfg.save_dir.clone();
    let overwrite = cfg.overwrite;
    let events_tx_cb = events_tx.clone();

    let task = tokio::spawn(async move {
        let lm_task = tokio::spawn(async move { link_mgr.run().await });

        let mut denied_links: std::collections::HashSet<[u8; 16]> = Default::default();

        loop {
            tokio::select! {
                ident = identified_rx.recv() => {
                    let Some((link_id, ident_hash)) = ident else { break };
                    if allow_all || allowed_set.contains(&ident_hash) {
                        let _ = events_tx_cb
                            .send(RncpEvent::SenderIdentified {
                                link_id,
                                identity_hash: ident_hash,
                            })
                            .await;
                    } else {
                        // The identity gate has already torn this link down.
                        denied_links.insert(link_id);
                        let _ = events_tx_cb
                            .send(RncpEvent::SenderDenied {
                                link_id,
                                identity_hash: ident_hash,
                            })
                            .await;
                    }
                }
                completion = completion_rx.recv() => {
                    let Some(evt) = completion else { break };
                    if denied_links.contains(&evt.link_id) {
                        continue;
                    }

                    let Some(file_name) = extract_filename(evt.metadata.as_deref()) else {
                        tracing::warn!(
                            link_id = hex::encode(evt.link_id),
                            "Invalid data received, ignoring resource"
                        );
                        continue;
                    };

                    match save_payload(&save_dir, &file_name, &evt.data, overwrite).await {
                        Ok(path) => {
                            let _ = events_tx_cb
                                .send(RncpEvent::Completed {
                                    link_id: evt.link_id,
                                    file_name,
                                    saved_path: path,
                                    bytes: evt.data.len(),
                                })
                                .await;
                        }
                        Err(e) => {
                            let _ = events_tx_cb
                                .send(RncpEvent::WriteFailed {
                                    link_id: evt.link_id,
                                    file_name,
                                    reason: e,
                                })
                                .await;
                        }
                    }
                }
            }
        }

        let _ = lm_task.await;
    });

    tracing::info!(
        dest = hex::encode(dest_hash),
        app_name = %app_name,
        "rncp listener started"
    );

    Ok(RncpListenerHandle {
        destination_hash: dest_hash,
        task,
    })
}

/// Upstream's `fetch_request` (rncp.py:172-208). The LinkManager has already
/// applied the ALLOW_ALL / ALLOW_LIST policy.
fn serve_fetch(
    request: DestinationRequest,
    jail: Option<&str>,
    auto_compress: bool,
    events: &mpsc::Sender<RncpEvent>,
) -> RequestOutcome {
    let link_id = request.link_id;
    let deny = |reason: String| {
        let _ = events.try_send(RncpEvent::FetchDenied { link_id, reason });
        RequestOutcome::ReplyValue(FetchReply::NotAllowed.packed())
    };
    let data = String::from_utf8_lossy(&request.data);
    let Some(path) = fetch_request_path(jail, &data, process_home().as_deref(), &process_cwd())
    else {
        return deny("outside fetch jail".into());
    };
    if let Some(jail) = jail
        && Path::new(&path).exists()
        && escapes_jail(&path, jail)
    {
        return deny("resolves outside fetch jail".into());
    }
    if !Path::new(&path).is_file() {
        return RequestOutcome::ReplyValue(FetchReply::NotFound.packed());
    }
    let Ok(file) = std::fs::File::open(&path) else {
        return RequestOutcome::ReplyValue(FetchReply::NotFound.packed());
    };
    let bytes = file.metadata().map_or(0, |meta| meta.len() as usize);
    let name = basename(&path).to_string();
    let metadata = pack_metadata(&name);
    let _ = events.try_send(RncpEvent::FetchServing {
        link_id,
        file_name: name,
        bytes,
    });
    RequestOutcome::ReplyWithResource {
        ack: FetchReply::Found.packed(),
        source: Box::new(file),
        metadata: Some(metadata),
        auto_compress,
    }
}

fn extract_filename(metadata: Option<&[u8]>) -> Option<String> {
    let meta = metadata?;
    // Envelope: msgpack({"name": b"filename"}).
    let map: rmpv::Value = rmpv::decode::read_value(&mut std::io::Cursor::new(meta)).ok()?;
    let entries = match map {
        rmpv::Value::Map(m) => m,
        _ => return None,
    };
    for (k, v) in entries {
        let key = match k {
            rmpv::Value::String(s) => s.into_str()?,
            rmpv::Value::Binary(b) => String::from_utf8(b).ok()?,
            _ => continue,
        };
        if key == "name" {
            let bytes = match v {
                rmpv::Value::Binary(b) => b,
                rmpv::Value::String(s) => s.into_bytes(),
                _ => continue,
            };
            return String::from_utf8(bytes).ok();
        }
    }
    None
}

async fn save_payload(
    save_dir: &Path,
    file_name: &str,
    data: &[u8],
    overwrite: bool,
) -> Result<PathBuf, String> {
    // rncp.py:286-293: the basename must name an entry directly in save_dir.
    let basename = basename(file_name).to_string();
    if basename.is_empty() || basename == "." || basename == ".." {
        return Err(format!("invalid save path for {file_name:?}"));
    }

    tokio::fs::create_dir_all(save_dir)
        .await
        .map_err(|e| format!("create save_dir: {e}"))?;
    let mut path = save_dir.join(&basename);
    if !overwrite && path.exists() {
        let mut i = 1;
        loop {
            let candidate = save_dir.join(format!("{basename}.{i}"));
            if !candidate.exists() {
                path = candidate;
                break;
            }
            i += 1;
        }
    }
    tokio::fs::write(&path, data)
        .await
        .map_err(|e| format!("write {}: {e}", path.display()))?;
    Ok(path)
}

fn build_link_close(link: &mut Link) -> Option<Bytes> {
    let link_id = link.link_id;
    let teardown_data = link.teardown(CloseReason::InitiatorClosed)?;
    Some(build_data_packet(
        link_id,
        rns_wire::context::PacketContext::LinkClose,
        &teardown_data,
    ))
}

/// Send a file and its filename metadata, identifying the local identity on
/// the Link. Large sources are read one Resource segment at a time. Success
/// means every segment received a valid proof, followed by a short settlement
/// delay; it does not confirm a remote file write.
///
/// Only the path and link waits are bounded; the transfer runs until the
/// Resource concludes, its retry timeouts expire or the link closes, as
/// rncp does. Progress notifications may be dropped when their channel is full.
pub async fn rncp_send_file(request: RncpSendRequest<'_>) -> Result<RncpOutcome, RncpError> {
    let RncpSendRequest {
        transport_tx,
        identity,
        dest_hash,
        file_name,
        source,
        auto_compress,
        path_timeout,
        progress_tx,
        shutdown,
    } = request;
    let shutdown = shutdown.as_ref();
    let started = Instant::now();

    let options = ResourceOptions {
        auto_compress,
        metadata: Some(pack_metadata(file_name)),
    };
    let prepared = interruptible(shutdown, async move {
        tokio::task::spawn_blocking(move || PreparedResourceSource::prepare(source, options))
            .await
            .map_err(|_| RncpError::ResourceCreate("preparation task failed".into()))?
            .map_err(|e| RncpError::ResourceCreate(e.to_string()))
    })
    .await?;

    let mut rl = establish(
        &transport_tx,
        &identity,
        dest_hash,
        path_timeout,
        "rncp.sender",
        shutdown,
    )
    .await?;
    let link_rtt = rl.link.rtt.unwrap_or(Duration::from_millis(500));

    let transfer_result = interruptible(
        shutdown,
        send_segments(&transport_tx, &mut rl, prepared, progress_tx),
    )
    .await;
    if transfer_result.is_ok() {
        tokio::time::sleep(RNCP_POST_PROOF_SETTLE).await;
    }
    close_link(rl, &transport_tx, &transfer_result).await;
    let byte_count = transfer_result?;

    tracing::info!(
        dest = hex::encode(dest_hash),
        bytes = byte_count,
        "rncp send complete"
    );

    Ok(RncpOutcome {
        file_name: file_name.to_string(),
        bytes: byte_count,
        link_rtt,
        duration: started.elapsed(),
    })
}

async fn send_segments(
    transport_tx: &mpsc::Sender<TransportMessage>,
    rl: &mut RncpLink,
    mut prepared: PreparedResourceSource,
    progress_tx: Option<mpsc::Sender<f32>>,
) -> Result<usize, RncpError> {
    let keys = rl
        .link
        .session_keys()
        .ok_or_else(|| RncpError::LinkCrypto("no session keys".into()))?;
    let rtt = rl.link.rtt.unwrap_or(Duration::from_millis(500));
    let link_sdu = rl.link.resource_sdu();
    let mut data_size = 0;
    loop {
        let segment_keys = keys.clone();
        let (returned, segment) = tokio::task::spawn_blocking(move || {
            let segment = prepared.next_segment(&segment_keys, rtt, link_sdu);
            (prepared, segment)
        })
        .await
        .map_err(|_| RncpError::ResourceCreate("segment preparation task failed".into()))?;
        prepared = returned;
        let Some(segment) = segment.map_err(|e| RncpError::ResourceCreate(e.to_string()))? else {
            return Ok(data_size);
        };
        data_size = segment.data_size;
        let total = segment.total_segments.max(1) as f32;
        drive_outbound(OutboundDrive {
            transport_tx,
            link: &mut rl.link,
            link_id: rl.link_id,
            transfer: segment.transfer,
            lpkt_rx: &mut rl.lpkt_rx,
            endpoint_lifecycle_rx: &mut rl.endpoint_lifecycle_rx,
            attached_interface: rl.attached_interface,
            interface_owner: rl.interface_owner,
            progress_tx: progress_tx.clone(),
            progress_base: (segment.segment_index - 1) as f32 / total,
            progress_span: 1.0 / total,
        })
        .await?;
        if segment.segment_index >= segment.total_segments {
            return Ok(data_size);
        }
    }
}

/// An established, identified initiator Link owned by an rncp transfer.
struct RncpLink {
    link: Link,
    link_id: [u8; 16],
    lpkt_rx: mpsc::Receiver<DestinationEvent>,
    endpoint_lifecycle_rx: mpsc::UnboundedReceiver<LinkEndpointLifecycleEvent>,
    attached_interface: InterfaceId,
    interface_owner: Option<rns_transport::messages::InterfaceOwnerId>,
    registration: crate::link_endpoint::LinkEndpointCleanupGuard,
}

/// Run `fut` until it completes or `shutdown` fires.
async fn interruptible<T>(
    shutdown: Option<&ShutdownSignal>,
    fut: impl std::future::Future<Output = Result<T, RncpError>>,
) -> Result<T, RncpError> {
    match shutdown {
        Some(shutdown) => tokio::select! {
            biased;
            _ = shutdown.wait() => Err(RncpError::Interrupted),
            result = fut => result,
        },
        None => fut.await,
    }
}

async fn query(
    transport_tx: &mpsc::Sender<TransportMessage>,
    query: TransportQuery,
) -> Result<TransportQueryResponse, RncpError> {
    let (response_tx, response_rx) = oneshot::channel();
    transport_tx
        .send(TransportMessage::Rpc { query, response_tx })
        .await
        .map_err(|_| RncpError::TransportUnavailable)?;
    response_rx
        .await
        .map_err(|_| RncpError::TransportUnavailable)
}

/// Path wait, link request and identification (rncp.py:394-450, 651-706).
/// The path wait lasts `path_timeout`; the proof wait ends at the later of
/// that deadline and the link establishment timeout.
async fn establish(
    transport_tx: &mpsc::Sender<TransportMessage>,
    identity: &Identity,
    dest_hash: [u8; 16],
    path_timeout: Duration,
    endpoint_name: &str,
    shutdown: Option<&ShutdownSignal>,
) -> Result<RncpLink, RncpError> {
    let path_deadline = Instant::now() + path_timeout;
    let pubkey = interruptible(
        shutdown,
        discover_pubkey(transport_tx, dest_hash, path_timeout),
    )
    .await?;

    // Link.py:308-309: first_hop_timeout + ESTABLISHMENT_TIMEOUT_PER_HOP * max(1, hops).
    let hops = match query(transport_tx, TransportQuery::HopsTo { dest: dest_hash }).await? {
        TransportQueryResponse::IntResult(hops) => u8::try_from(hops.max(1)).unwrap_or(u8::MAX),
        _ => 1,
    };
    let first_hop = match query(
        transport_tx,
        TransportQuery::FirstHopTimeout { dest: dest_hash },
    )
    .await?
    {
        TransportQueryResponse::FloatResult(Some(t)) if t.is_finite() && t >= 0.0 => t,
        _ => rns_wire::constants::DEFAULT_PER_HOP_TIMEOUT,
    };
    let (mut link, link_request_data) =
        crate::link_stamp::new_initiator(transport_tx, dest_hash, hops).await?;
    let _ = link.try_extend_establishment_timeout(first_hop);
    let link_id = link.link_id;
    let deadline = path_deadline.max(Instant::now() + link.establishment_timeout);

    let (lpkt_tx, mut lpkt_rx) = mpsc::channel::<DestinationEvent>(256);
    transport_tx
        .send(TransportMessage::RegisterDestination {
            hash: link_id,
            app_name: endpoint_name.to_string(),
            delivery_tx: Some(lpkt_tx),
        })
        .await
        .map_err(|_| RncpError::TransportUnavailable)?;
    let mut registration = crate::link_endpoint::LinkEndpointCleanupGuard::new(
        transport_tx.clone(),
        link_id,
        LinkEndpointRole::Initiator,
    );

    let link_req_pkt = build_link_request_packet(dest_hash, &link_request_data);
    interruptible(shutdown, async {
        tokio::time::timeout(
            remaining(deadline),
            rns_transport::link_messages::dispatch_link_request(
                transport_tx,
                OutboundRequest {
                    raw: link_req_pkt,
                    destination_hash: dest_hash,
                },
            ),
        )
        .await
        .map_err(|_| RncpError::Timeout("link request admission"))?
        .map_err(RncpError::from)
    })
    .await?;

    let (rtt_data, attached_interface, interface_owner) = interruptible(
        shutdown,
        wait_for_valid_rncp_proof(&mut lpkt_rx, &mut link, &pubkey, deadline),
    )
    .await?;

    let endpoint_lifecycle_rx = crate::link_endpoint::bind(
        transport_tx,
        link_id,
        attached_interface,
        interface_owner,
        LinkEndpointRole::Initiator,
    )
    .await
    .map_err(|_| RncpError::TransportUnavailable)?;
    registration.endpoint_bound();

    let rtt_pkt = build_data_packet(link_id, rns_wire::context::PacketContext::Lrrtt, &rtt_data);
    send_endpoint_packet(transport_tx, link_id, rtt_pkt).await?;

    let our_pub = identity.get_public_key();
    let our_priv = identity.get_signing_key().ok_or(RncpError::NoSigningKey)?;
    let ident_data = link
        .identify(&our_pub, &our_priv)
        .map_err(|e| RncpError::LinkCrypto(format!("identify: {e:?}")))?;
    let ident_pkt = build_data_packet(
        link_id,
        rns_wire::context::PacketContext::LinkIdentify,
        &ident_data,
    );
    send_endpoint_packet(transport_tx, link_id, ident_pkt).await?;
    link.keepalive.record_outbound();

    Ok(RncpLink {
        link,
        link_id,
        lpkt_rx,
        endpoint_lifecycle_rx,
        attached_interface,
        interface_owner,
        registration,
    })
}

/// Tear the link down. After an interrupt, wait as Python's SIGINT handler
/// does so the LINKCLOSE can leave.
async fn close_link<T>(
    mut rl: RncpLink,
    transport_tx: &mpsc::Sender<TransportMessage>,
    result: &Result<T, RncpError>,
) {
    let endpoint_closing = if let Some(close_pkt) = build_link_close(&mut rl.link) {
        crate::link_endpoint::send_and_unbind(
            transport_tx,
            rl.link_id,
            LinkEndpointRole::Initiator,
            close_pkt,
        )
        .await
        .is_ok()
    } else {
        false
    };
    if !endpoint_closing {
        let _ = rl.registration.cleanup().await;
    } else {
        rl.registration.disarm();
    }
    if matches!(result, Err(RncpError::Interrupted)) {
        tokio::time::sleep(RNCP_INTERRUPT_TEARDOWN_WINDOW).await;
    }
}

/// Run the initiator side of the link watchdog (Link.py:799-857): keepalives,
/// stale detection and request timeouts.
async fn service_link(
    transport_tx: &mpsc::Sender<TransportMessage>,
    link: &mut Link,
    link_id: [u8; 16],
) -> Result<(), RncpError> {
    match link.tick() {
        LinkAction::None => Ok(()),
        LinkAction::SendKeepalive | LinkAction::TransitionedToStale => {
            let raw = build_data_packet(
                link_id,
                rns_wire::context::PacketContext::Keepalive,
                &[rns_link::constants::KEEPALIVE_REQUEST],
            );
            link.record_tx_keepalive(1);
            send_endpoint_packet(transport_tx, link_id, raw).await
        }
        LinkAction::SendTeardownAndClose(teardown_data) => {
            if !teardown_data.is_empty() {
                let raw = build_data_packet(
                    link_id,
                    rns_wire::context::PacketContext::LinkClose,
                    &teardown_data,
                );
                let _ = send_endpoint_packet(transport_tx, link_id, raw).await;
            }
            Err(RncpError::ResourceFailed("link timed out".into()))
        }
        LinkAction::Closed(reason) => Err(RncpError::ResourceFailed(format!(
            "link closed: {reason:?}"
        ))),
    }
}

async fn next_link_event(
    lpkt_rx: &mut mpsc::Receiver<DestinationEvent>,
    endpoint_lifecycle_rx: &mut mpsc::UnboundedReceiver<LinkEndpointLifecycleEvent>,
) -> Result<DestinationEvent, RncpError> {
    tokio::select! {
        event = lpkt_rx.recv() => event.ok_or_else(|| {
            RncpError::ResourceFailed("link channel closed".into())
        }),
        terminal = endpoint_lifecycle_rx.recv() => Err(RncpError::ResourceFailed(
            format!("link endpoint terminated: {terminal:?}")
        )),
    }
}

fn pack_metadata(file_name: &str) -> Vec<u8> {
    let entries = vec![(
        rmpv::Value::String(rmpv::Utf8String::from("name")),
        rmpv::Value::Binary(file_name.as_bytes().to_vec()),
    )];
    let mut buf = Vec::new();
    let _ = rmpv::encode::write_value(&mut buf, &rmpv::Value::Map(entries));
    buf
}

struct OutboundDrive<'a> {
    transport_tx: &'a mpsc::Sender<TransportMessage>,
    link: &'a mut Link,
    link_id: [u8; 16],
    transfer: OutboundTransfer,
    lpkt_rx: &'a mut mpsc::Receiver<DestinationEvent>,
    endpoint_lifecycle_rx: &'a mut mpsc::UnboundedReceiver<LinkEndpointLifecycleEvent>,
    attached_interface: InterfaceId,
    interface_owner: Option<rns_transport::messages::InterfaceOwnerId>,
    progress_tx: Option<mpsc::Sender<f32>>,
    progress_base: f32,
    progress_span: f32,
}

async fn drive_outbound(request: OutboundDrive<'_>) -> Result<(), RncpError> {
    let OutboundDrive {
        transport_tx,
        link,
        link_id,
        mut transfer,
        lpkt_rx,
        endpoint_lifecycle_rx,
        attached_interface,
        interface_owner,
        progress_tx,
        progress_base,
        progress_span,
    } = request;

    transfer.advertisement_mdu = link.mdu;
    let total = transfer.resource.parts.len();
    if let Some(ref tx) = progress_tx {
        let _ = tx.try_send(if total == 0 {
            progress_base + progress_span
        } else {
            progress_base
        });
    }

    loop {
        loop {
            match transfer.tick() {
                TransferAction::None => break,
                TransferAction::Complete => return Ok(()),
                TransferAction::Failed(reason) => return Err(RncpError::ResourceFailed(reason)),
                action => send_transfer_action(transport_tx, link, link_id, action).await?,
            }
        }
        service_link(transport_tx, link, link_id).await?;

        let ev = match tokio::time::timeout(
            RNCP_SERVICE_INTERVAL,
            next_link_event(lpkt_rx, endpoint_lifecycle_rx),
        )
        .await
        {
            Ok(Ok(ev)) => ev,
            Ok(Err(error)) => return Err(error),
            Err(_) => continue,
        };

        let DestinationEvent::InboundPacket {
            raw,
            interface_id,
            interface_owner: event_owner,
            ..
        } = ev
        else {
            continue;
        };
        if interface_id != attached_interface || event_owner != interface_owner {
            continue;
        }
        let (header, off) = match rns_wire::header::PacketHeader::unpack(&raw) {
            Ok(h) => h,
            Err(_) => continue,
        };
        if header.destination_hash != link_id {
            continue;
        }
        crate::link_endpoint::record_initiator_inbound(link, &raw);
        let body = &raw[off..];
        match header.context {
            rns_wire::context::PacketContext::Keepalive
                if body.first() == Some(&rns_link::constants::KEEPALIVE_REQUEST) =>
            {
                send_keepalive_response(transport_tx, link_id).await?;
            }
            rns_wire::context::PacketContext::ResourceHmu
            | rns_wire::context::PacketContext::ResourceReq => {
                let Ok(plaintext) = link.decrypt(body) else {
                    continue;
                };
                if header.context == rns_wire::context::PacketContext::ResourceReq {
                    let packet_hash = rns_wire::hash::packet_hash(&raw, header.flags.header_type);
                    for action in transfer.handle_request_packet(packet_hash, &plaintext) {
                        send_transfer_action(transport_tx, link, link_id, action).await?;
                    }
                } else {
                    transfer.handle_hmu(&plaintext);
                }
                if let Some(ref tx) = progress_tx {
                    let confirmed_count = transfer.confirmed_parts.iter().filter(|c| **c).count();
                    let frac = if total == 0 {
                        1.0
                    } else {
                        confirmed_count as f32 / total as f32
                    };
                    let _ = tx.try_send(progress_base + (progress_span * frac));
                }
            }
            rns_wire::context::PacketContext::ResourcePrf => {
                // PROOF+RESOURCE_PRF plaintext = resource_hash(32) || proof(32) (Packet.py:195-197).
                if body.len() < 64 {
                    continue;
                }
                if !transfer.handle_proof(body) {
                    return Err(RncpError::ResourceFailed("proof mismatch".into()));
                }
                if let Some(ref tx) = progress_tx {
                    let _ = tx.try_send(progress_base + progress_span);
                }
                return Ok(());
            }
            rns_wire::context::PacketContext::ResourceRcl => {
                return Err(RncpError::ResourceFailed("receiver cancelled".into()));
            }
            rns_wire::context::PacketContext::LinkClose if link.receive_teardown(body) => {
                return Err(RncpError::ResourceFailed("link closed before proof".into()));
            }
            _ => {}
        }
    }
}

async fn send_keepalive_response(
    transport_tx: &mpsc::Sender<TransportMessage>,
    link_id: [u8; 16],
) -> Result<(), RncpError> {
    let raw = build_data_packet(
        link_id,
        rns_wire::context::PacketContext::Keepalive,
        &[rns_link::constants::KEEPALIVE_RESPONSE],
    );
    send_endpoint_packet(transport_tx, link_id, raw).await
}

async fn send_transfer_action(
    transport_tx: &mpsc::Sender<TransportMessage>,
    link: &Link,
    link_id: [u8; 16],
    action: TransferAction,
) -> Result<(), RncpError> {
    if let TransferAction::SendProof(proof) = action {
        let raw = build_resource_proof_packet(link_id, &proof);
        send_endpoint_packet(transport_tx, link_id, raw).await?;
        return Ok(());
    }

    if let TransferAction::QueryProofCache(proof_data) = action {
        return transport_tx
            .send(TransportMessage::CacheRequest {
                packet_hash: rns_protocol::resource::resource_proof_packet_hash(
                    &link_id,
                    &proof_data,
                ),
                destination_hash: link_id,
            })
            .await
            .map_err(|_| RncpError::TransportUnavailable);
    }

    let (context, body) = match action {
        TransferAction::SendAdvertisement(adv) => {
            let encrypted = link
                .encrypt(&adv)
                .map_err(|e| RncpError::LinkCrypto(format!("adv encrypt: {e:?}")))?;
            (
                rns_wire::context::PacketContext::ResourceAdv,
                Bytes::from(encrypted),
            )
        }
        TransferAction::SendPart(_, part) => (
            rns_wire::context::PacketContext::Resource,
            Bytes::from(part),
        ),
        TransferAction::SendHmu(hmu) => {
            let encrypted = link
                .encrypt(&hmu)
                .map_err(|e| RncpError::LinkCrypto(format!("hmu encrypt: {e:?}")))?;
            (
                rns_wire::context::PacketContext::ResourceHmu,
                Bytes::from(encrypted),
            )
        }
        TransferAction::SendRequest(req) => {
            let encrypted = link
                .encrypt(&req)
                .map_err(|e| RncpError::LinkCrypto(format!("request encrypt: {e:?}")))?;
            (
                rns_wire::context::PacketContext::ResourceReq,
                Bytes::from(encrypted),
            )
        }
        TransferAction::SendCancel(cancel_type, resource_hash) => {
            let encrypted = link
                .encrypt(&resource_hash)
                .map_err(|e| RncpError::LinkCrypto(format!("cancel encrypt: {e:?}")))?;
            let context = match cancel_type {
                rns_protocol::resource::CancelType::Icl => {
                    rns_wire::context::PacketContext::ResourceIcl
                }
                rns_protocol::resource::CancelType::Rcl => {
                    rns_wire::context::PacketContext::ResourceRcl
                }
            };
            (context, Bytes::from(encrypted))
        }
        TransferAction::SendProof(_) | TransferAction::QueryProofCache(_) => {
            unreachable!("handled before data-packet match")
        }
        TransferAction::None | TransferAction::Complete => return Ok(()),
        TransferAction::Failed(reason) => return Err(RncpError::ResourceFailed(reason)),
    };
    let raw = build_data_packet(link_id, context, &body);
    send_endpoint_packet(transport_tx, link_id, raw).await
}

fn remaining(deadline: Instant) -> Duration {
    deadline.saturating_duration_since(Instant::now())
}

async fn discover_pubkey(
    transport_tx: &mpsc::Sender<TransportMessage>,
    dest_hash: [u8; 16],
    path_wait: Duration,
) -> Result<[u8; 64], RncpError> {
    if let Some(pk) = lookup_pubkey(transport_tx, dest_hash).await? {
        return Ok(pk);
    }

    transport_tx
        .send(TransportMessage::RequestPath {
            destination_hash: dest_hash,
        })
        .await
        .map_err(|_| RncpError::TransportUnavailable)?;
    // rncp.py:394-406: one path request, then poll has_path until the deadline.
    let deadline = Instant::now() + path_wait;
    loop {
        if let TransportQueryResponse::BoolResult(true) =
            query(transport_tx, TransportQuery::HasPath { dest: dest_hash }).await?
        {
            break;
        }
        if Instant::now() >= deadline {
            return Err(RncpError::PathTimeout);
        }
        tokio::time::sleep(Duration::from_millis(100).min(remaining(deadline))).await;
    }

    lookup_pubkey(transport_tx, dest_hash)
        .await?
        .ok_or(RncpError::NoIdentity)
}

/// `Ok(None)` = peer not in announce cache.
async fn lookup_pubkey(
    transport_tx: &mpsc::Sender<TransportMessage>,
    dest_hash: [u8; 16],
) -> Result<Option<[u8; 64]>, RncpError> {
    let (resp_tx, resp_rx) = oneshot::channel();
    transport_tx
        .send(TransportMessage::Rpc {
            query: TransportQuery::GetRecentAnnounces,
            response_tx: resp_tx,
        })
        .await
        .map_err(|_| RncpError::TransportUnavailable)?;
    let resp = resp_rx.await.map_err(|_| RncpError::TransportUnavailable)?;
    let announces: Vec<AnnounceRpcEntry> = match resp {
        TransportQueryResponse::Announces(v) => v,
        _ => Vec::new(),
    };
    Ok(announces
        .into_iter()
        .find(|a| a.dest_hash == dest_hash)
        .and_then(|a| a.public_key))
}

async fn wait_for_valid_rncp_proof(
    rx: &mut mpsc::Receiver<DestinationEvent>,
    link: &mut Link,
    public_key: &[u8; 64],
    deadline: Instant,
) -> Result<
    (
        Vec<u8>,
        InterfaceId,
        Option<rns_transport::messages::InterfaceOwnerId>,
    ),
    RncpError,
> {
    let identity_ed25519_pub: [u8; 32] = public_key[32..64]
        .try_into()
        .map_err(|_| RncpError::ProofInvalid("remote pub key length".into()))?;
    let verify_key = Ed25519PublicKey::from_bytes(&identity_ed25519_pub)
        .map_err(|e| RncpError::ProofInvalid(format!("verify key: {e}")))?;
    let proof = timeout(
        remaining(deadline),
        crate::link_endpoint::wait_for_valid_proof(rx, link, &verify_key, &identity_ed25519_pub),
    )
    .await
    .map_err(|_| RncpError::Timeout("link proof"))?
    .map_err(|error| match error {
        crate::link_endpoint::LinkProofWaitError::LinkClosed => {
            RncpError::HandshakeFailed("link closed".into())
        }
        crate::link_endpoint::LinkProofWaitError::DeliveryClosed => {
            RncpError::HandshakeFailed("channel closed".into())
        }
    })?;
    Ok((proof.rtt_data, proof.interface_id, proof.interface_owner))
}

fn build_link_request_packet(dest_hash: [u8; 16], request_data: &[u8]) -> Bytes {
    let header = rns_wire::header::PacketHeader {
        flags: rns_wire::flags::PacketFlags {
            header_type: rns_wire::flags::HeaderType::Header1,
            context_flag: false,
            transport_type: rns_wire::flags::TransportType::Broadcast,
            destination_type: rns_wire::flags::DestinationType::Single,
            packet_type: rns_wire::flags::PacketType::LinkRequest,
        },
        hops: 0,
        transport_id: None,
        destination_hash: dest_hash,
        context: rns_wire::context::PacketContext::None,
    };
    let mut raw = header.pack();
    raw.extend_from_slice(request_data);
    Bytes::from(raw)
}

fn build_data_packet(
    link_id: [u8; 16],
    context: rns_wire::context::PacketContext,
    body: &[u8],
) -> Bytes {
    let header = rns_wire::header::PacketHeader {
        flags: rns_wire::flags::PacketFlags {
            header_type: rns_wire::flags::HeaderType::Header1,
            context_flag: false,
            transport_type: rns_wire::flags::TransportType::Broadcast,
            destination_type: rns_wire::flags::DestinationType::Link,
            packet_type: rns_wire::flags::PacketType::Data,
        },
        hops: 0,
        transport_id: None,
        destination_hash: link_id,
        context,
    };
    let mut raw = header.pack();
    raw.extend_from_slice(body);
    Bytes::from(raw)
}

fn build_resource_proof_packet(link_id: [u8; 16], proof: &[u8]) -> Bytes {
    let header = rns_wire::header::PacketHeader {
        flags: rns_wire::flags::PacketFlags {
            header_type: rns_wire::flags::HeaderType::Header1,
            context_flag: false,
            transport_type: rns_wire::flags::TransportType::Broadcast,
            destination_type: rns_wire::flags::DestinationType::Link,
            packet_type: rns_wire::flags::PacketType::Proof,
        },
        hops: 0,
        transport_id: None,
        destination_hash: link_id,
        context: rns_wire::context::PacketContext::ResourcePrf,
    };
    let mut raw = header.pack();
    raw.extend_from_slice(proof);
    Bytes::from(raw)
}

#[derive(Debug, Clone)]
pub struct RncpFetchOutcome {
    pub file_name: String,
    pub saved_path: PathBuf,
    pub bytes: usize,
    pub link_rtt: Duration,
    pub duration: Duration,
}

pub struct RncpFetchRequest<'a> {
    pub transport_tx: mpsc::Sender<TransportMessage>,
    pub identity: Identity,
    pub dest_hash: [u8; 16],
    pub remote_path: &'a str,
    pub save_dir: &'a Path,
    pub overwrite: bool,
    /// Path wait, rncp's `max(-w, medium path timeout)`. The link proof wait
    /// ends at the later of this and the link establishment timeout; the
    /// request uses the Link's default timeout and the transfer has no deadline.
    pub path_timeout: Duration,
    pub progress_tx: Option<mpsc::Sender<f32>>,
    /// Stops the fetch and closes the link, as rncp does on SIGINT.
    pub shutdown: Option<ShutdownSignal>,
}

/// Fetch a file over a Link: identify the local identity and request
/// `fetch_file`. The listener answers `True` and sends the file as a Resource,
/// or answers `False` ([`RncpError::NotFound`]), `None`
/// ([`RncpError::RemoteError`]) or 240 ([`RncpError::Denied`]). No answer
/// within the request timeout gives [`RncpError::RequestFailed`].
///
/// Success means the assembled file was written under `save_dir`; the Resource
/// proof is sent before this local write. Filename collision handling follows
/// [`RncpListenerConfig`].
pub async fn rncp_fetch_file(request: RncpFetchRequest<'_>) -> Result<RncpFetchOutcome, RncpError> {
    use rns_protocol::resource::{InboundTransfer, MultiSegmentInbound, TransferAction};

    let RncpFetchRequest {
        transport_tx,
        identity,
        dest_hash,
        remote_path,
        save_dir,
        overwrite,
        path_timeout,
        progress_tx,
        shutdown,
    } = request;
    let shutdown = shutdown.as_ref();
    let started = Instant::now();

    let rl = establish(
        &transport_tx,
        &identity,
        dest_hash,
        path_timeout,
        "rncp.fetch",
        shutdown,
    )
    .await?;
    let RncpLink {
        mut link,
        link_id,
        mut lpkt_rx,
        mut endpoint_lifecycle_rx,
        attached_interface,
        interface_owner,
        registration,
    } = rl;

    let request_timeout = link.default_request_timeout();
    let (req_encrypted, _req_id) = link
        .request_str(FETCH_PATH_NAME, remote_path, request_timeout)
        .map_err(|e| RncpError::LinkCrypto(format!("request: {e:?}")))?;
    let req_pkt = build_data_packet(
        link_id,
        rns_wire::context::PacketContext::Request,
        &req_encrypted,
    );
    let packet_request_id =
        rns_wire::hash::truncated_packet_hash(&req_pkt, rns_wire::flags::HeaderType::Header1);
    link.update_pending_request_id(&_req_id, packet_request_id);
    send_endpoint_packet(&transport_tx, link_id, req_pkt).await?;
    link.keepalive.record_outbound();
    let request_deadline = Instant::now() + request_timeout;

    let session_keys = link
        .session_keys()
        .ok_or_else(|| RncpError::LinkCrypto("no session keys".into()))?;
    let session_keys_dec = session_keys.clone();
    let decrypt_fn =
        move |ciphertext: &[u8]| -> Result<Vec<u8>, rns_protocol::resource::ResourceError> {
            rns_link::encryption::link_decrypt(&session_keys_dec, ciphertext)
                .map_err(|_| rns_protocol::resource::ResourceError::DecryptFailed)
        };

    let link_rtt = link.rtt.unwrap_or(Duration::from_millis(500));
    let mut ack_seen = false;
    let mut transfers: std::collections::HashMap<[u8; 32], InboundTransfer> =
        std::collections::HashMap::new();
    let mut split_resources: std::collections::HashMap<[u8; 32], MultiSegmentInbound> =
        std::collections::HashMap::new();
    let mut segment_routes: std::collections::HashMap<[u8; 32], ([u8; 32], usize)> =
        std::collections::HashMap::new();

    let fetch_loop = async {
        let result: Result<(String, Vec<u8>), RncpError> = loop {
            if !ack_seen && Instant::now() >= request_deadline {
                break Err(RncpError::RequestFailed);
            }
            let mut failed = None;
            for t in transfers.values_mut() {
                match t.check_timeout() {
                    TransferAction::SendRequest(req) => {
                        if let Ok(encrypted) = link.encrypt(&req) {
                            let raw = build_data_packet(
                                link_id,
                                rns_wire::context::PacketContext::ResourceReq,
                                &encrypted,
                            );
                            send_endpoint_packet(&transport_tx, link_id, raw).await?;
                        }
                    }
                    TransferAction::Failed(reason) => failed = Some(reason),
                    // Out of retries: Resource.cancel() sends RCL (Resource.py:1133-1139).
                    TransferAction::SendCancel(_, resource_hash) => {
                        if let Ok(encrypted) = link.encrypt(&resource_hash) {
                            let raw = build_data_packet(
                                link_id,
                                rns_wire::context::PacketContext::ResourceRcl,
                                &encrypted,
                            );
                            send_endpoint_packet(&transport_tx, link_id, raw).await?;
                        }
                        failed = Some("resource transfer timed out".to_string());
                    }
                    _ => {}
                }
            }
            if let Some(reason) = failed {
                break Err(RncpError::ResourceFailed(reason));
            }
            if let Err(error) = service_link(&transport_tx, &mut link, link_id).await {
                break Err(if ack_seen {
                    error
                } else {
                    RncpError::RequestFailed
                });
            }
            let ev = match tokio::time::timeout(
                RNCP_SERVICE_INTERVAL,
                next_link_event(&mut lpkt_rx, &mut endpoint_lifecycle_rx),
            )
            .await
            {
                Ok(Ok(ev)) => ev,
                Ok(Err(error)) => {
                    break Err(if ack_seen {
                        error
                    } else {
                        RncpError::RequestFailed
                    });
                }
                Err(_) => continue,
            };

            let DestinationEvent::InboundPacket {
                raw,
                interface_id,
                interface_owner: event_owner,
                ..
            } = ev
            else {
                continue;
            };
            if interface_id != attached_interface || event_owner != interface_owner {
                continue;
            }
            let (header, off) = match rns_wire::header::PacketHeader::unpack(&raw) {
                Ok(h) => h,
                Err(_) => continue,
            };
            if header.destination_hash != link_id {
                continue;
            }
            crate::link_endpoint::record_initiator_inbound(&mut link, &raw);
            let body = &raw[off..];
            match header.context {
                rns_wire::context::PacketContext::Keepalive
                    if body.first() == Some(&rns_link::constants::KEEPALIVE_REQUEST) =>
                {
                    send_keepalive_response(&transport_tx, link_id).await?;
                }
                rns_wire::context::PacketContext::Response => {
                    let Ok(plaintext) = link.decrypt(body) else {
                        continue;
                    };
                    let Ok((response_id, value)) = Link::parse_response_value(&plaintext) else {
                        continue;
                    };
                    if response_id != packet_request_id {
                        continue;
                    }
                    link.deliver_response_data(&response_id, Vec::new());
                    match FetchReply::from_value(&value) {
                        FetchReply::Found => ack_seen = true,
                        FetchReply::NotFound => break Err(RncpError::NotFound),
                        FetchReply::RemoteError => break Err(RncpError::RemoteError),
                        FetchReply::NotAllowed => break Err(RncpError::Denied),
                    }
                }
                rns_wire::context::PacketContext::ResourceAdv => {
                    if !ack_seen {
                        // Some implementations race ADV with ack; treat ADV as implicit consent.
                        ack_seen = true;
                    }
                    let Ok(plaintext) = link.decrypt(body) else {
                        continue;
                    };
                    let Ok(adv) =
                        rns_protocol::resource_adv::ResourceAdvertisement::unpack(&plaintext)
                    else {
                        continue;
                    };
                    if adv.total_segments > 1 {
                        if adv.segment_index == 0 || adv.segment_index > adv.total_segments {
                            break Err(RncpError::ResourceFailed(
                                "invalid split-resource advertisement".into(),
                            ));
                        }
                        let coord = split_resources.entry(adv.original_hash).or_insert_with(|| {
                            MultiSegmentInbound::new(adv.total_segments, adv.original_hash)
                                .with_size_bound(adv.data_size)
                        });
                        if coord.total_segments != adv.total_segments {
                            break Err(RncpError::ResourceFailed(
                                "split-resource total_segments changed".into(),
                            ));
                        }
                        // Upstream advertises segments in order; anything else is stale.
                        if adv.segment_index != coord.assembled_count() + 1 {
                            continue;
                        }
                        segment_routes
                            .insert(adv.resource_hash, (adv.original_hash, adv.segment_index));
                    }
                    let map_hashes = adv.get_map_hashes();
                    let mut transfer_flags = adv.flags;
                    if adv.total_segments > 1 && adv.segment_index > 1 {
                        transfer_flags.has_metadata = false;
                    }
                    let mut rh = [0u8; rns_protocol::resource::RANDOM_HASH_SIZE];
                    let copy_len = adv.random_hash.len().min(rh.len());
                    rh[..copy_len].copy_from_slice(&adv.random_hash[..copy_len]);
                    let Ok(mut t) = InboundTransfer::from_advertisement(
                        adv.num_parts,
                        adv.transfer_size,
                        adv.data_size,
                        rh,
                        adv.resource_hash,
                        transfer_flags,
                        map_hashes,
                        link_rtt,
                    ) else {
                        continue;
                    };
                    t.resource.sdu = link.resource_sdu();
                    if let TransferAction::SendRequest(req_data) = t.request_next()
                        && let Ok(encrypted) = link.encrypt(&req_data)
                    {
                        let req_raw = build_data_packet(
                            link_id,
                            rns_wire::context::PacketContext::ResourceReq,
                            &encrypted,
                        );
                        send_endpoint_packet(&transport_tx, link_id, req_raw).await?;
                    }
                    transfers.insert(adv.resource_hash, t);
                }
                rns_wire::context::PacketContext::Resource => {
                    let mut resource_action_to_send = None;
                    let mut completed_rh = None;
                    for (rh, t) in &mut transfers {
                        let action = t.receive_part(body.to_vec());
                        if let Some(ref tx) = progress_tx {
                            let _ = tx.try_send(t.resource.progress() as f32);
                        }
                        match action {
                            TransferAction::SendHmu(_) | TransferAction::SendRequest(_) => {
                                resource_action_to_send = Some(action);
                            }
                            TransferAction::Complete => {
                                completed_rh = Some(*rh);
                            }
                            _ => {}
                        }
                        if completed_rh.is_none() && t.resource.is_complete() {
                            completed_rh = Some(*rh);
                        }
                        if resource_action_to_send.is_some() || completed_rh.is_some() {
                            break;
                        }
                    }

                    if let Some(action) = resource_action_to_send {
                        let (context, payload) = match action {
                            TransferAction::SendHmu(hmu) => {
                                (rns_wire::context::PacketContext::ResourceHmu, hmu)
                            }
                            TransferAction::SendRequest(req) => {
                                (rns_wire::context::PacketContext::ResourceReq, req)
                            }
                            _ => unreachable!(),
                        };
                        if let Ok(encrypted) = link.encrypt(&payload) {
                            let raw = build_data_packet(link_id, context, &encrypted);
                            send_endpoint_packet(&transport_tx, link_id, raw).await?;
                        }
                    }

                    if let Some(rh) = completed_rh {
                        let (payload, proof, metadata) = match transfers.get_mut(&rh) {
                            Some(t) => match t.complete(Some(&decrypt_fn)) {
                                Ok((payload, proof)) => {
                                    (payload, proof, t.resource.metadata.clone())
                                }
                                Err(e) => {
                                    break Err(RncpError::ResourceFailed(format!(
                                        "resource assemble/proof failed: {e:?}; parts={}/{} map_hashes={} total_size={} data_size={} flags={:?}",
                                        t.resource.received_count(),
                                        t.resource.total_parts,
                                        t.resource.map_hashes.len(),
                                        t.resource.total_size,
                                        t.resource.data_size,
                                        t.resource.flags,
                                    )));
                                }
                            },
                            None => {
                                break Err(RncpError::ResourceFailed(
                                    "resource assemble/proof failed: transfer missing".into(),
                                ));
                            }
                        };
                        let prf_raw = build_resource_proof_packet(link_id, &proof);
                        // The received file is not locally concluded until its
                        // Resource proof has been admitted on the exact Link
                        // endpoint. Otherwise a stale or lost binding could make
                        // the receiver publish success that the sender can never
                        // observe.
                        send_endpoint_packet(&transport_tx, link_id, prf_raw).await?;

                        transfers.remove(&rh);

                        if let Some((original_hash, segment_index)) = segment_routes.remove(&rh) {
                            let Some(coord) = split_resources.get_mut(&original_hash) else {
                                break Err(RncpError::ResourceFailed(
                                    "split-resource coordinator missing".into(),
                                ));
                            };
                            if let Some(meta) = metadata {
                                coord.set_metadata(meta);
                            }
                            if let Err(e) = coord.set_segment_data(segment_index, payload) {
                                break Err(RncpError::ResourceFailed(format!(
                                    "split segment rejected: {e:?}"
                                )));
                            }
                            if !coord.is_complete() {
                                if let Some(ref tx) = progress_tx {
                                    let _ = tx.try_send(coord.progress() as f32);
                                }
                                continue;
                            }

                            let payload = match coord.reassemble() {
                                Ok(p) => p,
                                Err(e) => {
                                    break Err(RncpError::ResourceFailed(format!(
                                        "split reassemble: {e:?}"
                                    )));
                                }
                            };
                            let meta_bytes = coord.metadata.clone();
                            let Some(file_name) = extract_filename(meta_bytes.as_deref()) else {
                                break Err(RncpError::ResourceFailed(
                                    "invalid data received".into(),
                                ));
                            };
                            split_resources.remove(&original_hash);
                            if let Some(ref tx) = progress_tx {
                                let _ = tx.try_send(1.0);
                            }
                            break Ok((file_name, payload));
                        }

                        let Some(file_name) = extract_filename(metadata.as_deref()) else {
                            break Err(RncpError::ResourceFailed("invalid data received".into()));
                        };
                        if let Some(ref tx) = progress_tx {
                            let _ = tx.try_send(1.0);
                        }
                        break Ok((file_name, payload));
                    }
                }
                rns_wire::context::PacketContext::ResourceHmu => {
                    let Ok(plaintext) = link.decrypt(body) else {
                        continue;
                    };
                    let Ok((rh, segment, hashmap)) =
                        rns_protocol::resource::parse_hashmap_update(&plaintext)
                    else {
                        continue;
                    };
                    let Some(t) = transfers.get_mut(&rh) else {
                        continue;
                    };
                    if let TransferAction::SendRequest(req) = t.hashmap_update(segment, &hashmap)
                        && let Ok(encrypted) = link.encrypt(&req)
                    {
                        let req_raw = build_data_packet(
                            link_id,
                            rns_wire::context::PacketContext::ResourceReq,
                            &encrypted,
                        );
                        send_endpoint_packet(&transport_tx, link_id, req_raw).await?;
                    }
                }
                rns_wire::context::PacketContext::LinkClose if link.receive_teardown(body) => {
                    break Err(if ack_seen {
                        RncpError::ResourceFailed("link closed".into())
                    } else {
                        RncpError::RequestFailed
                    });
                }
                _ => {}
            }
        };
        result
    };
    let result = interruptible(shutdown, fetch_loop).await;

    let rl = RncpLink {
        link,
        link_id,
        lpkt_rx,
        endpoint_lifecycle_rx,
        attached_interface,
        interface_owner,
        registration,
    };
    close_link(rl, &transport_tx, &result).await;

    let (file_name, payload) = result?;
    let bytes = payload.len();
    let saved_path = save_payload(save_dir, &file_name, &payload, overwrite)
        .await
        .map_err(RncpError::Io)?;

    tracing::info!(
        dest = hex::encode(dest_hash),
        link_id = hex::encode(link_id),
        bytes = bytes,
        file_name = %file_name,
        "rncp fetch complete"
    );

    Ok(RncpFetchOutcome {
        file_name,
        saved_path,
        bytes,
        link_rtt,
        duration: started.elapsed(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn fetch_requested_before_lrrtt_still_advertises_the_file() {
        use rns_transport::messages::{LinkEndpointBindResult, LinkEndpointSendResult};
        use rns_wire::context::PacketContext;

        let jail = tempfile::tempdir().unwrap();
        std::fs::write(jail.path().join("file.bin"), vec![0x5a; 4000]).unwrap();
        let identity = Identity::new();
        let public_key = identity.get_public_key();
        let (transport_tx, mut transport_rx) = mpsc::channel(256);
        let (events_tx, _events_rx) = mpsc::channel(64);
        let cfg = RncpListenerConfig {
            identity,
            allow_all: true,
            allow_fetch: true,
            fetch_jail: Some(jail.path().to_path_buf()),
            ..RncpListenerConfig::default()
        };
        let listener = spawn_rncp_listener(transport_tx, cfg, events_tx)
            .await
            .unwrap();
        let dest_hash = listener.destination_hash();
        let Some(TransportMessage::RegisterDestination {
            delivery_tx: Some(delivery_tx),
            ..
        }) = transport_rx.recv().await
        else {
            panic!("listener must register its destination");
        };

        let (sent_tx, mut sent_rx) = mpsc::unbounded_channel::<Bytes>();
        tokio::spawn(async move {
            while let Some(message) = transport_rx.recv().await {
                match message {
                    TransportMessage::BindLinkEndpoint {
                        lifecycle_tx,
                        result_tx,
                        ..
                    } => {
                        let _ = result_tx.send(LinkEndpointBindResult::Bound);
                        std::mem::forget(lifecycle_tx);
                    }
                    TransportMessage::SendLinkEndpoint {
                        request, result_tx, ..
                    }
                    | TransportMessage::SendLinkEndpointBestEffort {
                        request, result_tx, ..
                    } => {
                        let _ = result_tx.send(LinkEndpointSendResult::Sent);
                        let _ = sent_tx.send(request.raw);
                    }
                    TransportMessage::OutboundAttached { request, .. }
                    | TransportMessage::Outbound(request) => {
                        let _ = sent_tx.send(request.raw);
                    }
                    _ => {}
                }
            }
        });
        let next_sent = async |rx: &mut mpsc::UnboundedReceiver<Bytes>, context| loop {
            let raw = tokio::time::timeout(Duration::from_secs(5), rx.recv())
                .await
                .unwrap_or_else(|_| panic!("listener sent no {context:?}"))
                .unwrap();
            let (header, offset) = rns_wire::header::PacketHeader::unpack(&raw).unwrap();
            if header.context == context {
                break raw[offset..].to_vec();
            }
        };
        let inbound = |raw: Bytes| DestinationEvent::InboundPacket {
            interface_owner: None,
            raw,
            interface_id: 1,
            metrics: Default::default(),
        };

        let (mut link, request_data) = Link::new_initiator(dest_hash, 1);
        delivery_tx
            .send(DestinationEvent::LinkRequest {
                interface_owner: None,
                raw: build_link_request_packet(dest_hash, &request_data),
                interface_id: 1,
                metrics: Default::default(),
            })
            .await
            .unwrap();
        let proof = next_sent(&mut sent_rx, PacketContext::Lrproof).await;
        let ed25519: [u8; 32] = public_key[32..].try_into().unwrap();
        let verify_key = Ed25519PublicKey::from_bytes(&ed25519).unwrap();
        link.validate_proof(&proof, &verify_key, &ed25519).unwrap();

        // The initiator is active, but its LRRTT has not reached the listener.
        let (request, _) = link
            .request_str(FETCH_PATH_NAME, "file.bin", Duration::from_secs(5))
            .unwrap();
        delivery_tx
            .send(inbound(build_data_packet(
                link.link_id,
                PacketContext::Request,
                &request,
            )))
            .await
            .unwrap();
        let response = next_sent(&mut sent_rx, PacketContext::Response).await;
        let (_, reply) = link.handle_response(&response).unwrap();
        assert_eq!(reply, FetchReply::Found.packed());
        next_sent(&mut sent_rx, PacketContext::ResourceAdv).await;
        listener.shutdown().await;
    }

    #[test]
    fn metadata_roundtrip() {
        let packed = pack_metadata("hello.txt");
        let parsed = extract_filename(Some(&packed)).unwrap();
        assert_eq!(parsed, "hello.txt");
    }

    const FETCH_VECTORS: &str = include_str!("../tests/fixtures/rncp_fetch/rncp_fetch.tsv");

    fn vector_rows(kind: &str) -> Vec<Vec<&'static str>> {
        FETCH_VECTORS
            .lines()
            .filter(|line| !line.starts_with('#'))
            .map(|line| line.split('\t').collect::<Vec<_>>())
            .filter(|row| row[0] == kind)
            .collect()
    }

    fn vector_header(key: &str) -> &'static str {
        FETCH_VECTORS
            .lines()
            .find_map(|line| line.strip_prefix(&format!("# {key}\t")))
            .expect("fixture header")
    }

    #[test]
    fn fetch_request_paths_match_upstream_rncp() {
        let home = vector_header("home");
        let rows = vector_rows("case");
        assert!(!rows.is_empty());
        for row in rows {
            let (jail, request, expected) = (row[1], row[2], row[3]);
            let jail = (jail != "<none>").then(|| abspath(&expanduser(jail, Some(home)), "/"));
            let expected = (expected != "<none>").then(|| expected.to_string());
            assert_eq!(
                fetch_request_path(jail.as_deref(), request, Some(home), "/"),
                expected,
                "jail {jail:?}, request {request:?}"
            );
        }
    }

    #[test]
    fn fetch_replies_pack_and_decode_as_upstream_rncp() {
        let rows = vector_rows("reply");
        assert!(!rows.is_empty());
        let rid: [u8; 16] = core::array::from_fn(|i| i as u8);
        for row in rows {
            let (name, packed, status) = (row[1], hex::decode(row[2]).unwrap(), row[3]);
            let (id, value) = Link::parse_response_value(&packed).unwrap();
            assert_eq!(id, rid, "{name}");
            let reply = FetchReply::from_value(&value);
            let expected = match status {
                "found" => FetchReply::Found,
                "not_found" => FetchReply::NotFound,
                "remote_error" => FetchReply::RemoteError,
                "fetch_not_allowed" => FetchReply::NotAllowed,
                other => panic!("unknown status {other}"),
            };
            // Rust keeps decoding its old single-byte denial as a denial.
            if name == "legacy_fixint_f0" {
                assert_eq!(reply, FetchReply::NotAllowed, "{name}");
                continue;
            }
            assert_eq!(reply, expected, "{name}");
            let sent = match name {
                "not_allowed" => Some(FetchReply::NotAllowed),
                "not_found" => Some(FetchReply::NotFound),
                "found" => Some(FetchReply::Found),
                "no_link" => Some(FetchReply::RemoteError),
                _ => None,
            };
            if let Some(sent) = sent {
                assert_eq!(
                    Link::pack_response(&rid, &sent.packed()).unwrap(),
                    packed,
                    "{name}"
                );
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn jailed_symlink_leading_outside_is_refused() {
        let base = std::env::temp_dir().join(format!("rncp-jail-{}", std::process::id()));
        let jail = base.join("jail");
        std::fs::create_dir_all(&jail).unwrap();
        std::fs::write(base.join("secret"), b"x").unwrap();
        std::fs::write(jail.join("inside"), b"y").unwrap();
        let link = jail.join("link");
        let _ = std::fs::remove_file(&link);
        std::os::unix::fs::symlink(base.join("secret"), &link).unwrap();
        let jail_str = jail.to_string_lossy();
        assert!(escapes_jail(&link.to_string_lossy(), &jail_str));
        assert!(!escapes_jail(
            &jail.join("inside").to_string_lossy(),
            &jail_str
        ));
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn default_app_name_matches_python() {
        assert_eq!(default_rncp_app_name(), "rncp.receive");
    }

    #[test]
    fn resource_proof_packet_uses_proof_type() {
        let raw = build_resource_proof_packet([0x11; 16], &[0x22; 64]);
        let (header, off) = rns_wire::header::PacketHeader::unpack(&raw).unwrap();
        assert_eq!(header.flags.packet_type, rns_wire::flags::PacketType::Proof);
        assert_eq!(
            header.context,
            rns_wire::context::PacketContext::ResourcePrf
        );
        assert_eq!(&raw[off..], &[0x22; 64]);
    }

    #[tokio::test]
    async fn resource_proof_rejection_is_not_a_successful_send() {
        let link_id = [0x12; 16];
        let (transport_tx, mut transport_rx) = mpsc::channel(1);
        let send = tokio::spawn(async move {
            send_endpoint_packet(
                &transport_tx,
                link_id,
                build_resource_proof_packet(link_id, &[0x34; 64]),
            )
            .await
        });
        let TransportMessage::SendLinkEndpoint {
            role,
            request,
            result_tx,
            ..
        } = transport_rx
            .recv()
            .await
            .expect("typed Resource proof send")
        else {
            panic!("Resource proof must use the established-Link endpoint");
        };
        assert_eq!(role, LinkEndpointRole::Initiator);
        let (header, _) = rns_wire::header::PacketHeader::unpack(&request.raw).unwrap();
        assert_eq!(
            header.context,
            rns_wire::context::PacketContext::ResourcePrf
        );
        let _ = result_tx.send(rns_transport::messages::LinkEndpointSendResult::NotBound);
        assert!(matches!(
            send.await.unwrap(),
            Err(RncpError::TransportUnavailable)
        ));
    }

    #[test]
    fn link_close_packet_uses_authenticated_teardown_payload() {
        let dest_hash = [0x33; 16];
        let responder_key = rns_crypto::ed25519::Ed25519PrivateKey::generate();
        let responder_pub = responder_key.public_key();
        let (mut initiator, request_data) = Link::new_initiator(dest_hash, 1);
        let (mut responder, proof_data) =
            Link::new_responder(&request_data, &responder_key, dest_hash, 1).unwrap();
        let rtt_data = initiator
            .validate_proof(&proof_data, &responder_pub, &responder_pub.to_bytes())
            .unwrap();
        responder.receive_rtt_packet(&rtt_data).unwrap();

        let raw = build_link_close(&mut initiator).expect("active link emits teardown");
        let (header, offset) = rns_wire::header::PacketHeader::unpack(&raw).unwrap();
        assert_eq!(header.context, rns_wire::context::PacketContext::LinkClose);
        assert!(responder.receive_teardown(&raw[offset..]));
    }

    #[test]
    fn successful_rncp_send_retains_python_receiver_settlement_window() {
        assert_eq!(RNCP_POST_PROOF_SETTLE, Duration::from_millis(250));
    }
}
