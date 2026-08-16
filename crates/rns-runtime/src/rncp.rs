//! Wire-compatible with Python `RNS.Utilities.rncp`. Supports `-l` (listen),
//! send (default), and `-F` / `-f` (fetch serve / client).

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use tokio::sync::mpsc;
use tokio::time::timeout;

use rns_crypto::ed25519::Ed25519PublicKey;
use rns_crypto::sha::truncated_hash;
use rns_identity::destination::{DestType, Destination, Direction};
use rns_identity::identity::Identity;
use rns_link::encryption::link_encrypt;
use rns_link::link::{CloseReason, Link};
use rns_protocol::resource::{
    MAX_EFFICIENT_SIZE, MultiSegmentOutbound, OutboundResource, OutboundTransfer, TransferAction,
};
use rns_transport::link_messages::DestinationEvent;
use rns_transport::messages::{
    AnnounceRpcEntry, InterfaceId, LinkEndpointLifecycleEvent, LinkEndpointRole, OutboundRequest,
    TransportMessage, TransportQuery, TransportQueryResponse,
};
use tokio::sync::oneshot;

use crate::link_manager::{LinkManager, RequestOutcome, ResourceCompletion};

/// Python `REQ_FETCH_NOT_ALLOWED` sentinel (rncp.py:70).
pub const REQ_FETCH_NOT_ALLOWED: u8 = 0xF0;

pub const FETCH_PATH_NAME: &str = "fetch_file";

pub const DEFAULT_RNCP_APP_NAME: &str = "rncp.receive";

/// Python sends the final Resource proof before it runs the receiver-side
/// conclusion callback that materialises the file. Keep the Link alive for a
/// short, bounded settlement window after a valid proof so an immediate
/// teardown cannot race that callback and turn a proven Resource into
/// `FAILED` on a loaded peer.
const RNCP_POST_PROOF_SETTLE: Duration = Duration::from_millis(250);

struct RncpLinkGuard {
    transport_tx: mpsc::Sender<TransportMessage>,
    link_id: [u8; 16],
    endpoint_bound: bool,
    cleanup_required: bool,
}

impl Drop for RncpLinkGuard {
    fn drop(&mut self) {
        if !self.cleanup_required {
            return;
        }
        if self.endpoint_bound {
            let _ = self
                .transport_tx
                .try_send(crate::link_endpoint::unbind_message(
                    self.link_id,
                    LinkEndpointRole::Initiator,
                ));
        }
        let _ = self
            .transport_tx
            .try_send(TransportMessage::DeregisterDestination { hash: self.link_id });
    }
}

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
    #[error("sender not in allow-list")]
    Denied,
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
    pub data: Vec<u8>,
    pub auto_compress: bool,
    pub overall_timeout: Duration,
    pub path_wait: Duration,
    pub progress_tx: Option<mpsc::Sender<f32>>,
}

#[derive(Debug, Clone)]
pub enum RncpEvent {
    LinkEstablished {
        link_id: [u8; 16],
    },
    /// Zero `identity_hash` = remote never identified; only accepted under `allow_all`.
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

/// Resolves a fetch path under the jail root (Python rncp.py:177-183).
/// Absolute paths replace the jail prefix; relatives join onto it; canonical
/// result must stay inside `jail_canonical`.
fn resolve_fetch_path(jail: Option<&Path>, data: &[u8]) -> Result<PathBuf, String> {
    let path_str = std::str::from_utf8(data).map_err(|_| "non-utf8 path".to_string())?;
    if path_str.is_empty() {
        return Err("empty path".into());
    }
    match jail {
        Some(jail_dir) => {
            let jail_canonical =
                std::fs::canonicalize(jail_dir).map_err(|e| format!("jail canonicalize: {e}"))?;
            // canonicalize resolves symlinks (macOS `/var` → `/private/var`)
            // before the containment check.
            let requested = Path::new(path_str);
            let combined = if requested.is_absolute() {
                requested.to_path_buf()
            } else {
                jail_canonical.join(path_str)
            };
            let canonical =
                std::fs::canonicalize(&combined).map_err(|e| format!("not found: {e}"))?;
            if !canonical.starts_with(&jail_canonical) {
                return Err("outside fetch jail".into());
            }
            Ok(canonical)
        }
        None => std::fs::canonicalize(path_str).map_err(|e| format!("not found: {e}")),
    }
}

pub struct RncpListenerConfig {
    pub identity: Identity,
    pub app_name: String,
    pub save_dir: PathBuf,
    /// Python `allow_all` / `-n`.
    pub allow_all: bool,
    /// Ignored when `allow_all` is set.
    pub allowed: Vec<[u8; 16]>,
    pub overwrite: bool,
    /// Python `-F` / `--allow-fetch`.
    pub allow_fetch: bool,
    /// Python `-j` / `--jail`.
    pub fetch_jail: Option<PathBuf>,
    /// Python default on; `--no-compress` disables.
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
    pub async fn shutdown(self) {
        self.task.abort();
        let _ = self.task.await;
    }
}

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
    let link_control_tx = dest_tx.clone();
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

    // Gate the allow-list before parts arrive.
    let (identified_tx, mut identified_rx) = mpsc::channel::<([u8; 16], [u8; 16])>(64);
    link_mgr.set_link_identified_channel(identified_tx);

    if !cfg.allow_fetch && !cfg.allow_all {
        let allowed_push: std::collections::HashSet<[u8; 16]> =
            cfg.allowed.iter().copied().collect();
        link_mgr.set_link_identity_gate(move |_link_id, identity_hash| {
            allowed_push.contains(&identity_hash)
        });
    }

    if cfg.allow_fetch {
        let jail = cfg.fetch_jail.clone();
        let auto_compress = cfg.fetch_auto_compress;
        let allowed_fetch: Arc<std::collections::HashSet<[u8; 16]>> =
            Arc::new(cfg.allowed.iter().copied().collect());
        let allow_all_fetch = cfg.allow_all;
        let link_identities = link_mgr.link_identities_handle();
        let fetch_events = events_tx.clone();
        let fetch_path_hash = truncated_hash(FETCH_PATH_NAME.as_bytes());
        link_mgr.set_request_handler_ex(move |link_id, path_hash, data| {
            if path_hash != fetch_path_hash {
                return RequestOutcome::Drop;
            }
            // Allow-all bypasses ident check; else peer must have sent
            // LinkIdentify with an identity in `allowed`.
            if !allow_all_fetch {
                let ident = link_identities
                    .lock()
                    .ok()
                    .and_then(|m| m.get(&link_id).copied());
                match ident {
                    Some(h) if allowed_fetch.contains(&h) => {}
                    _ => {
                        let _ = fetch_events.try_send(RncpEvent::FetchDenied {
                            link_id,
                            reason: "not in allow-list".into(),
                        });
                        return RequestOutcome::Reply(vec![REQ_FETCH_NOT_ALLOWED]);
                    }
                }
            }
            match resolve_fetch_path(jail.as_deref(), &data) {
                Ok(file_path) => match std::fs::read(&file_path) {
                    Ok(bytes) => {
                        let basename = file_path
                            .file_name()
                            .map(|s| s.to_string_lossy().into_owned())
                            .unwrap_or_default();
                        let metadata = pack_metadata(&basename);
                        let _ = fetch_events.try_send(RncpEvent::FetchServing {
                            link_id,
                            file_name: basename,
                            bytes: bytes.len(),
                        });
                        RequestOutcome::ReplyWithResource {
                            ack: vec![0xC3], // msgpack `true`
                            data: bytes,
                            metadata: Some(metadata),
                            auto_compress,
                        }
                    }
                    Err(_) => RequestOutcome::Reply(vec![0xC2]), // msgpack `false`
                },
                Err(reason) => {
                    let _ = fetch_events.try_send(RncpEvent::FetchDenied { link_id, reason });
                    RequestOutcome::Reply(vec![REQ_FETCH_NOT_ALLOWED])
                }
            }
        });
    }

    let app_name = cfg.app_name.clone();
    let save_dir = cfg.save_dir.clone();
    let allow_all = cfg.allow_all;
    let allowed: std::collections::HashSet<[u8; 16]> = cfg.allowed.iter().copied().collect();
    let overwrite = cfg.overwrite;
    let allow_fetch_outer = cfg.allow_fetch;
    let events_tx_cb = events_tx.clone();
    let link_control_tx_cb = link_control_tx.clone();

    let task = tokio::spawn(async move {
        let lm_task = tokio::spawn(async move { link_mgr.run().await });

        let mut denied_links: std::collections::HashSet<[u8; 16]> = Default::default();

        loop {
            tokio::select! {
                ident = identified_rx.recv() => {
                    let Some((link_id, ident_hash)) = ident else { break };
                    if allow_all || allowed.contains(&ident_hash) {
                        let _ = events_tx_cb
                            .send(RncpEvent::SenderIdentified {
                                link_id,
                                identity_hash: ident_hash,
                            })
                            .await;
                    } else {
                        denied_links.insert(link_id);
                        let _ = events_tx_cb
                            .send(RncpEvent::SenderDenied {
                                link_id,
                                identity_hash: ident_hash,
                            })
                            .await;
                        // Keep the link open under fetch so the handler can
                        // reply REQ_FETCH_NOT_ALLOWED rather than a generic close.
                        if !allow_fetch_outer {
                            let _ = link_control_tx_cb
                                .send(DestinationEvent::LinkClosed { link_id })
                                .await;
                        }
                    }
                }
                completion = completion_rx.recv() => {
                    let Some(evt) = completion else { break };
                    if denied_links.contains(&evt.link_id) {
                        continue;
                    }

                    let file_name = extract_filename(evt.metadata.as_deref())
                        .unwrap_or_else(|| default_file_name(&evt.resource_hash));

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

fn default_file_name(resource_hash: &[u8; 32]) -> String {
    format!("rncp_{}", hex::encode(&resource_hash[..8]))
}

async fn save_payload(
    save_dir: &Path,
    file_name: &str,
    data: &[u8],
    overwrite: bool,
) -> Result<PathBuf, String> {
    // Strip path traversal components.
    let basename = Path::new(file_name)
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| file_name.to_string());
    if basename.is_empty() {
        return Err("empty filename".into());
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

pub async fn rncp_send_file(request: RncpSendRequest<'_>) -> Result<RncpOutcome, RncpError> {
    let RncpSendRequest {
        transport_tx,
        identity,
        dest_hash,
        file_name,
        data,
        auto_compress,
        overall_timeout,
        path_wait,
        progress_tx,
    } = request;

    let started = Instant::now();
    let deadline = started + overall_timeout;
    let byte_count = data.len();

    let pubkey =
        discover_pubkey(&transport_tx, dest_hash, path_wait.min(remaining(deadline))).await?;

    let (mut link, link_request_data) = Link::new_initiator(dest_hash, 1);
    let link_id = link.link_id;

    // Route LRPROOF / link packets back to this task.
    let (lpkt_tx, mut lpkt_rx) = mpsc::channel::<DestinationEvent>(256);
    transport_tx
        .send(TransportMessage::RegisterDestination {
            hash: link_id,
            app_name: "rncp.sender".to_string(),
            delivery_tx: Some(lpkt_tx),
        })
        .await
        .map_err(|_| RncpError::TransportUnavailable)?;
    let mut registration = RncpLinkGuard {
        transport_tx: transport_tx.clone(),
        link_id,
        endpoint_bound: false,
        cleanup_required: true,
    };

    let link_req_pkt = build_link_request_packet(dest_hash, &link_request_data);
    transport_tx
        .send(TransportMessage::Outbound(OutboundRequest {
            raw: link_req_pkt,
            destination_hash: dest_hash,
        }))
        .await
        .map_err(|_| RncpError::TransportUnavailable)?;

    let (rtt_data, attached_interface) =
        wait_for_valid_rncp_proof(&mut lpkt_rx, &mut link, &pubkey, deadline).await?;

    let mut endpoint_lifecycle_rx = crate::link_endpoint::bind(
        &transport_tx,
        link_id,
        attached_interface,
        LinkEndpointRole::Initiator,
    )
    .await
    .map_err(|_| RncpError::TransportUnavailable)?;
    registration.endpoint_bound = true;

    let rtt_pkt = build_data_packet(link_id, rns_wire::context::PacketContext::Lrrtt, &rtt_data);
    send_endpoint_packet(&transport_tx, link_id, rtt_pkt).await?;

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
    send_endpoint_packet(&transport_tx, link_id, ident_pkt).await?;

    // Encrypt full payload BEFORE chunking (Resource.py:424).
    let session_keys = link
        .session_keys()
        .ok_or_else(|| RncpError::LinkCrypto("no session keys".into()))?;
    let session_keys_enc = session_keys.clone();
    let encrypt_fn = move |plaintext: &[u8]| -> Vec<u8> {
        link_encrypt(&session_keys_enc, plaintext).unwrap_or_default()
    };

    let metadata_bytes = pack_metadata(file_name);

    let link_rtt = link.rtt.unwrap_or(Duration::from_millis(500));
    let resources = if metadata_bytes.len() + 3 + data.len() <= MAX_EFFICIENT_SIZE {
        vec![
            OutboundResource::with_options(
                data,
                auto_compress,
                Some(metadata_bytes),
                None,
                Some(&encrypt_fn),
            )
            .map_err(|e| RncpError::ResourceCreate(format!("{e:?}")))?,
        ]
    } else {
        MultiSegmentOutbound::with_options(
            data,
            auto_compress,
            Some(metadata_bytes),
            None,
            false,
            Some(&encrypt_fn),
        )
        .map_err(|e| RncpError::ResourceCreate(format!("{e:?}")))?
        .segments
    };
    let resource_hash = resources
        .first()
        .map(|r| r.original_hash.unwrap_or(r.resource_hash))
        .unwrap_or([0u8; 32]);
    let total_parts: usize = resources.iter().map(|r| r.parts.len()).sum();
    let total_parts_nonzero = total_parts.max(1);

    let proof_deadline = Instant::now() + overall_timeout.min(Duration::from_secs(120));
    let mut transfer_result = Ok(());
    let mut completed_parts = 0usize;
    for resource in resources {
        let segment_parts = resource.parts.len();
        transfer_result = drive_outbound(OutboundDrive {
            transport_tx: &transport_tx,
            link: &mut link,
            link_id,
            resource,
            lpkt_rx: &mut lpkt_rx,
            endpoint_lifecycle_rx: &mut endpoint_lifecycle_rx,
            attached_interface,
            progress_tx: progress_tx.clone(),
            progress_base: completed_parts as f32 / total_parts_nonzero as f32,
            progress_span: segment_parts as f32 / total_parts_nonzero as f32,
            deadline: proof_deadline.min(deadline),
        })
        .await;
        if transfer_result.is_err() {
            break;
        }
        completed_parts += segment_parts;
    }

    if transfer_result.is_ok() {
        tokio::time::sleep(RNCP_POST_PROOF_SETTLE).await;
    }

    let endpoint_closing = if let Some(close_pkt) = build_link_close(&mut link) {
        crate::link_endpoint::send_and_unbind(
            &transport_tx,
            link_id,
            LinkEndpointRole::Initiator,
            close_pkt,
        )
        .await
        .is_ok()
    } else {
        false
    };
    if !endpoint_closing {
        let _ =
            crate::link_endpoint::unbind(&transport_tx, link_id, LinkEndpointRole::Initiator).await;
        registration.endpoint_bound = false;
        cleanup_destination(&transport_tx, link_id).await;
        registration.cleanup_required = false;
    } else {
        registration.cleanup_required = false;
    }

    transfer_result?;

    tracing::info!(
        dest = hex::encode(dest_hash),
        link_id = hex::encode(link_id),
        resource = hex::encode(&resource_hash[..8]),
        bytes = byte_count,
        parts = total_parts,
        "rncp send complete"
    );

    Ok(RncpOutcome {
        file_name: file_name.to_string(),
        bytes: byte_count,
        link_rtt,
        duration: started.elapsed(),
    })
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
    resource: OutboundResource,
    lpkt_rx: &'a mut mpsc::Receiver<DestinationEvent>,
    endpoint_lifecycle_rx: &'a mut mpsc::UnboundedReceiver<LinkEndpointLifecycleEvent>,
    attached_interface: InterfaceId,
    progress_tx: Option<mpsc::Sender<f32>>,
    progress_base: f32,
    progress_span: f32,
    deadline: Instant,
}

async fn drive_outbound(request: OutboundDrive<'_>) -> Result<(), RncpError> {
    let OutboundDrive {
        transport_tx,
        link,
        link_id,
        resource,
        lpkt_rx,
        endpoint_lifecycle_rx,
        attached_interface,
        progress_tx,
        progress_base,
        progress_span,
        deadline,
    } = request;

    let rtt = link.rtt.unwrap_or(Duration::from_millis(500));
    let mut transfer = OutboundTransfer::from_prebuilt(resource, rtt);
    let total = transfer.resource.parts.len();
    if let Some(ref tx) = progress_tx {
        let _ = tx.try_send(if total == 0 {
            progress_base + progress_span
        } else {
            progress_base
        });
    }

    loop {
        if Instant::now() >= deadline {
            return Err(RncpError::Timeout("resource proof"));
        }

        loop {
            match transfer.tick() {
                TransferAction::None => break,
                TransferAction::Complete => return Ok(()),
                TransferAction::Failed(reason) => return Err(RncpError::ResourceFailed(reason)),
                action => send_transfer_action(transport_tx, link, link_id, action).await?,
            }
        }

        let recv_timeout = remaining(deadline).min(Duration::from_secs(5));
        let ev = match tokio::time::timeout(recv_timeout, async {
            tokio::select! {
                event = lpkt_rx.recv() => event.ok_or_else(|| {
                    RncpError::ResourceFailed("link channel closed".into())
                }),
                terminal = endpoint_lifecycle_rx.recv() => Err(RncpError::ResourceFailed(
                    format!("link endpoint terminated: {terminal:?}")
                )),
            }
        })
        .await
        {
            Ok(Ok(ev)) => ev,
            Ok(Err(error)) => return Err(error),
            Err(_) => continue,
        };

        let DestinationEvent::InboundPacket {
            raw, interface_id, ..
        } = ev
        else {
            continue;
        };
        if interface_id != attached_interface {
            continue;
        }
        let (header, off) = match rns_wire::header::PacketHeader::unpack(&raw) {
            Ok(h) => h,
            Err(_) => continue,
        };
        if header.destination_hash != link_id {
            continue;
        }
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
        TransferAction::SendProof(_) => unreachable!("proof handled before data-packet match"),
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
    let (await_tx, await_rx) = oneshot::channel();
    transport_tx
        .send(TransportMessage::AwaitPath {
            dest: dest_hash,
            reply: await_tx,
        })
        .await
        .map_err(|_| RncpError::TransportUnavailable)?;
    let found = timeout(path_wait, await_rx)
        .await
        .map_err(|_| RncpError::PathTimeout)?
        .unwrap_or(false);
    if !found {
        return Err(RncpError::PathTimeout);
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
) -> Result<(Vec<u8>, InterfaceId), RncpError> {
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
    Ok((proof.rtt_data, proof.interface_id))
}

async fn cleanup_destination(transport_tx: &mpsc::Sender<TransportMessage>, link_id: [u8; 16]) {
    let _ = transport_tx.try_send(TransportMessage::DeregisterDestination { hash: link_id });
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
    pub overall_timeout: Duration,
    pub path_wait: Duration,
    pub progress_tx: Option<mpsc::Sender<f32>>,
}

/// Fetches a remote file via `rncp --fetch`. Wire flow:
/// link + identify → REQUEST `fetch_file` → ack byte (`0xC3` ok, `0xC2` not
/// found, [`REQ_FETCH_NOT_ALLOWED`] denied) → resource → write to `save_dir`.
pub async fn rncp_fetch_file(request: RncpFetchRequest<'_>) -> Result<RncpFetchOutcome, RncpError> {
    use rns_protocol::resource::{
        InboundTransfer, MAX_SEGMENTS, MultiSegmentInbound, TransferAction,
    };

    let RncpFetchRequest {
        transport_tx,
        identity,
        dest_hash,
        remote_path,
        save_dir,
        overwrite,
        overall_timeout,
        path_wait,
        progress_tx,
    } = request;

    let started = Instant::now();
    let deadline = started + overall_timeout;

    let pubkey =
        discover_pubkey(&transport_tx, dest_hash, path_wait.min(remaining(deadline))).await?;

    let (mut link, link_request_data) = Link::new_initiator(dest_hash, 1);
    let link_id = link.link_id;

    let (lpkt_tx, mut lpkt_rx) = mpsc::channel::<DestinationEvent>(256);
    transport_tx
        .send(TransportMessage::RegisterDestination {
            hash: link_id,
            app_name: "rncp.fetch".to_string(),
            delivery_tx: Some(lpkt_tx),
        })
        .await
        .map_err(|_| RncpError::TransportUnavailable)?;
    let mut registration = RncpLinkGuard {
        transport_tx: transport_tx.clone(),
        link_id,
        endpoint_bound: false,
        cleanup_required: true,
    };

    let link_req_pkt = build_link_request_packet(dest_hash, &link_request_data);
    transport_tx
        .send(TransportMessage::Outbound(OutboundRequest {
            raw: link_req_pkt,
            destination_hash: dest_hash,
        }))
        .await
        .map_err(|_| RncpError::TransportUnavailable)?;

    let (rtt_data, attached_interface) =
        wait_for_valid_rncp_proof(&mut lpkt_rx, &mut link, &pubkey, deadline).await?;

    let mut endpoint_lifecycle_rx = crate::link_endpoint::bind(
        &transport_tx,
        link_id,
        attached_interface,
        LinkEndpointRole::Initiator,
    )
    .await
    .map_err(|_| RncpError::TransportUnavailable)?;
    registration.endpoint_bound = true;

    let rtt_pkt = build_data_packet(link_id, rns_wire::context::PacketContext::Lrrtt, &rtt_data);
    send_endpoint_packet(&transport_tx, link_id, rtt_pkt).await?;

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
    send_endpoint_packet(&transport_tx, link_id, ident_pkt).await?;

    let (req_encrypted, _req_id) = link
        .request_str(FETCH_PATH_NAME, remote_path, remaining(deadline))
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

    let result: Result<(String, Vec<u8>), RncpError> = loop {
        if Instant::now() >= deadline {
            break Err(RncpError::Timeout("fetch"));
        }
        let recv_timeout = remaining(deadline).min(Duration::from_secs(5));
        let ev = match tokio::time::timeout(recv_timeout, async {
            tokio::select! {
                event = lpkt_rx.recv() => event.ok_or_else(|| {
                    RncpError::ResourceFailed("link channel closed".into())
                }),
                terminal = endpoint_lifecycle_rx.recv() => Err(RncpError::ResourceFailed(
                    format!("link endpoint terminated: {terminal:?}")
                )),
            }
        })
        .await
        {
            Ok(Ok(ev)) => ev,
            Ok(Err(error)) => break Err(error),
            Err(_) => continue,
        };

        let DestinationEvent::InboundPacket {
            raw, interface_id, ..
        } = ev
        else {
            continue;
        };
        if interface_id != attached_interface {
            continue;
        }
        let (header, off) = match rns_wire::header::PacketHeader::unpack(&raw) {
            Ok(h) => h,
            Err(_) => continue,
        };
        if header.destination_hash != link_id {
            continue;
        }
        let body = &raw[off..];
        match header.context {
            rns_wire::context::PacketContext::Keepalive
                if body.first() == Some(&rns_link::constants::KEEPALIVE_REQUEST) =>
            {
                send_keepalive_response(&transport_tx, link_id).await?;
            }
            rns_wire::context::PacketContext::Response => {
                let Ok((_req_id, resp)) = link.handle_response(body) else {
                    continue;
                };
                match resp.first().copied() {
                    Some(0xC3) => ack_seen = true,
                    Some(0xC2) => break Err(RncpError::ResourceFailed("remote: not found".into())),
                    Some(REQ_FETCH_NOT_ALLOWED) => break Err(RncpError::Denied),
                    _ => break Err(RncpError::ResourceFailed("unknown ack".into())),
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
                let Ok(adv) = rns_protocol::resource_adv::ResourceAdvertisement::unpack(&plaintext)
                else {
                    continue;
                };
                if adv.total_segments > 1 {
                    if adv.total_segments > MAX_SEGMENTS
                        || adv.segment_index == 0
                        || adv.segment_index > adv.total_segments
                    {
                        break Err(RncpError::ResourceFailed(
                            "invalid split-resource advertisement".into(),
                        ));
                    }
                    let coord = split_resources.entry(adv.original_hash).or_insert_with(|| {
                        MultiSegmentInbound::new(adv.total_segments, adv.original_hash)
                    });
                    if coord.total_segments != adv.total_segments {
                        break Err(RncpError::ResourceFailed(
                            "split-resource total_segments changed".into(),
                        ));
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
                if let TransferAction::SendRequest(req_data) = t.request_next() {
                    if let Ok(encrypted) = link.encrypt(&req_data) {
                        let req_raw = build_data_packet(
                            link_id,
                            rns_wire::context::PacketContext::ResourceReq,
                            &encrypted,
                        );
                        send_endpoint_packet(&transport_tx, link_id, req_raw).await?;
                    }
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
                    let (payload, proof, metadata, resource_hash) = match transfers.get_mut(&rh) {
                        Some(t) => match t.complete(Some(&decrypt_fn)) {
                            Ok((payload, proof)) => (
                                payload,
                                proof,
                                t.resource.metadata.clone(),
                                t.resource.resource_hash,
                            ),
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
                        let file_name = extract_filename(meta_bytes.as_deref())
                            .unwrap_or_else(|| default_file_name(&original_hash));
                        split_resources.remove(&original_hash);
                        if let Some(ref tx) = progress_tx {
                            let _ = tx.try_send(1.0);
                        }
                        break Ok((file_name, payload));
                    }

                    let file_name = extract_filename(metadata.as_deref())
                        .unwrap_or_else(|| default_file_name(&resource_hash));
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
                if let TransferAction::SendRequest(req) = t.hashmap_update(segment, &hashmap) {
                    if let Ok(encrypted) = link.encrypt(&req) {
                        let req_raw = build_data_packet(
                            link_id,
                            rns_wire::context::PacketContext::ResourceReq,
                            &encrypted,
                        );
                        send_endpoint_packet(&transport_tx, link_id, req_raw).await?;
                    }
                }
            }
            rns_wire::context::PacketContext::LinkClose if link.receive_teardown(body) => {
                break Err(RncpError::ResourceFailed("link closed".into()));
            }
            _ => {}
        }
    };

    let endpoint_closing = if let Some(close_pkt) = build_link_close(&mut link) {
        crate::link_endpoint::send_and_unbind(
            &transport_tx,
            link_id,
            LinkEndpointRole::Initiator,
            close_pkt,
        )
        .await
        .is_ok()
    } else {
        false
    };
    if !endpoint_closing {
        let _ =
            crate::link_endpoint::unbind(&transport_tx, link_id, LinkEndpointRole::Initiator).await;
        registration.endpoint_bound = false;
        cleanup_destination(&transport_tx, link_id).await;
        registration.cleanup_required = false;
    } else {
        registration.cleanup_required = false;
    }

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

    #[test]
    fn metadata_roundtrip() {
        let packed = pack_metadata("hello.txt");
        let parsed = extract_filename(Some(&packed)).unwrap();
        assert_eq!(parsed, "hello.txt");
    }

    #[test]
    fn default_file_name_uses_resource_hash_prefix() {
        let rh = [0xAB; 32];
        let name = default_file_name(&rh);
        assert!(name.starts_with("rncp_"));
        assert_eq!(name.len(), "rncp_".len() + 16);
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
