//! Local control port for CLI tools (rnstatus, rnpath). Default 37429.
//! Wire-compatible with Python `multiprocessing.connection`.

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;
use tokio::sync::mpsc;

use rns_transport::messages::TransportMessage;

use crate::lifecycle::ShutdownSignal;
use crate::rpc::{self, RpcError, RpcRequest, RpcResponse};

const MAX_REQUEST_SIZE: usize = 1_048_576;

pub async fn run_rpc_server(
    port: u16,
    rpc_key: Vec<u8>,
    _transport_tx: mpsc::Sender<TransportMessage>,
    shutdown: ShutdownSignal,
) -> Result<(), RpcError> {
    let listener = TcpListener::bind(format!("127.0.0.1:{}", port))
        .await
        .map_err(RpcError::Io)?;
    run_rpc_server_with_listener(listener, rpc_key, _transport_tx, shutdown).await
}

#[cfg(unix)]
pub async fn run_unix_rpc_server(
    socket_path: &str,
    rpc_key: Vec<u8>,
    transport_tx: mpsc::Sender<TransportMessage>,
    shutdown: ShutdownSignal,
) -> Result<(), RpcError> {
    let listener = bind_unix_rpc_listener(socket_path).map_err(RpcError::Io)?;
    run_unix_rpc_server_with_listener(
        listener,
        display_socket_path(socket_path),
        rpc_key,
        transport_tx,
        shutdown,
    )
    .await
}

#[cfg(not(unix))]
pub async fn run_unix_rpc_server(
    _socket_path: &str,
    _rpc_key: Vec<u8>,
    _transport_tx: mpsc::Sender<TransportMessage>,
    _shutdown: ShutdownSignal,
) -> Result<(), RpcError> {
    Err(RpcError::Io(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "Unix shared-instance RPC is not supported on this platform",
    )))
}

async fn run_rpc_server_with_listener(
    listener: TcpListener,
    rpc_key: Vec<u8>,
    _transport_tx: mpsc::Sender<TransportMessage>,
    shutdown: ShutdownSignal,
) -> Result<(), RpcError> {
    let port = listener.local_addr().map_err(RpcError::Io)?.port();
    tracing::info!("RPC server listening on 127.0.0.1:{}", port);

    loop {
        tokio::select! {
            accept_result = listener.accept() => {
                match accept_result {
                    Ok((stream, addr)) => {
                        tracing::debug!("RPC connection from {}", addr);
                        let key = rpc_key.clone();
                        let tx = _transport_tx.clone();
                        tokio::spawn(async move {
                            if let Err(e) = handle_rpc_client(stream, &key, tx).await {
                                tracing::debug!("RPC client error: {}", e);
                            }
                        });
                    }
                    Err(e) => {
                        tracing::warn!("RPC accept error: {}", e);
                    }
                }
            }
            _ = shutdown.wait() => {
                tracing::info!("RPC server shutting down");
                break;
            }
        }
    }

    Ok(())
}

#[cfg(unix)]
async fn run_unix_rpc_server_with_listener(
    listener: tokio::net::UnixListener,
    display_path: String,
    rpc_key: Vec<u8>,
    transport_tx: mpsc::Sender<TransportMessage>,
    shutdown: ShutdownSignal,
) -> Result<(), RpcError> {
    tracing::info!("RPC server listening on {}", display_path);

    loop {
        tokio::select! {
            accept_result = listener.accept() => {
                match accept_result {
                    Ok((stream, _addr)) => {
                        tracing::debug!("Unix RPC connection accepted");
                        let key = rpc_key.clone();
                        let tx = transport_tx.clone();
                        tokio::spawn(async move {
                            if let Err(e) = handle_rpc_client(stream, &key, tx).await {
                                tracing::debug!("Unix RPC client error: {}", e);
                            }
                        });
                    }
                    Err(e) => {
                        tracing::warn!("Unix RPC accept error: {}", e);
                    }
                }
            }
            _ = shutdown.wait() => {
                tracing::info!("Unix RPC server shutting down");
                break;
            }
        }
    }

    Ok(())
}

#[cfg(unix)]
fn bind_unix_rpc_listener(socket_path: &str) -> std::io::Result<tokio::net::UnixListener> {
    if let Some(abstract_name) = socket_path.strip_prefix('\0') {
        return bind_abstract_unix_listener(abstract_name);
    }

    let _ = std::fs::remove_file(socket_path);
    tokio::net::UnixListener::bind(socket_path)
}

#[cfg(all(unix, any(target_os = "linux", target_os = "android")))]
fn bind_abstract_unix_listener(name: &str) -> std::io::Result<tokio::net::UnixListener> {
    use std::os::unix::net::{SocketAddr, UnixListener};

    #[cfg(target_os = "android")]
    use std::os::android::net::SocketAddrExt as _;
    #[cfg(target_os = "linux")]
    use std::os::linux::net::SocketAddrExt as _;

    let addr = SocketAddr::from_abstract_name(name.as_bytes())?;
    let listener = UnixListener::bind_addr(&addr)?;
    listener.set_nonblocking(true)?;
    tokio::net::UnixListener::from_std(listener)
}

#[cfg(all(unix, not(any(target_os = "linux", target_os = "android"))))]
fn bind_abstract_unix_listener(_name: &str) -> std::io::Result<tokio::net::UnixListener> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "abstract Unix sockets are only available on Linux/Android",
    ))
}

fn display_socket_path(path: &str) -> String {
    if let Some(rest) = path.strip_prefix('\0') {
        format!("\\0{rest}")
    } else {
        path.to_string()
    }
}

async fn handle_rpc_client(
    mut stream: impl AsyncRead + AsyncWrite + Unpin,
    rpc_key: &[u8],
    transport_tx: mpsc::Sender<TransportMessage>,
) -> Result<(), RpcError> {
    let challenge = rpc::new_python_challenge();
    let mut challenge_frame = Vec::with_capacity(rpc::MP_CHALLENGE.len() + challenge.len());
    challenge_frame.extend_from_slice(rpc::MP_CHALLENGE);
    challenge_frame.extend_from_slice(&challenge);
    rpc::write_mp_frame(&mut stream, &challenge_frame).await?;

    let response = rpc::read_mp_frame(&mut stream, 256).await?;

    if !rpc::verify_python_auth_response(rpc_key, &challenge, &response) {
        let _ = rpc::write_mp_frame(&mut stream, rpc::MP_FAILURE).await;
        return Err(RpcError::AuthFailed);
    }

    rpc::write_mp_frame(&mut stream, rpc::MP_WELCOME).await?;

    let client_challenge_frame = rpc::read_mp_frame(&mut stream, 256).await?;
    if !client_challenge_frame.starts_with(rpc::MP_CHALLENGE) {
        return Err(RpcError::AuthFailed);
    }
    let client_challenge = &client_challenge_frame[rpc::MP_CHALLENGE.len()..];
    let client_response = rpc::compute_python_auth_response_for(
        rpc::detect_python_auth_protocol(client_challenge),
        rpc_key,
        client_challenge,
    );
    rpc::write_mp_frame(&mut stream, &client_response).await?;
    let client_welcome = rpc::read_mp_frame(&mut stream, 256).await?;
    if client_welcome != rpc::MP_WELCOME {
        return Err(RpcError::AuthFailed);
    }

    let req_buf = rpc::read_mp_frame(&mut stream, MAX_REQUEST_SIZE).await?;
    let request = rpc::decode_request(&req_buf)?;

    let response = process_rpc_request(request, &transport_tx).await;
    let resp_data = rpc::encode_response(&response)?;

    rpc::write_mp_frame(&mut stream, &resp_data).await?;

    Ok(())
}

const TRANSPORT_QUERY_BUDGET: std::time::Duration = std::time::Duration::from_secs(5);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TransportQueryFailure {
    SendTimedOut,
    ChannelClosed,
    ResponseTimedOut,
    ResponseClosed,
}

impl TransportQueryFailure {
    fn description(self) -> &'static str {
        match self {
            Self::SendTimedOut => "request enqueue timed out",
            Self::ChannelClosed => "query channel is closed",
            Self::ResponseTimedOut => "response timed out",
            Self::ResponseClosed => "response channel closed without an answer",
        }
    }
}

fn transport_failure_response(
    operation: &'static str,
    failure: TransportQueryFailure,
) -> RpcResponse {
    RpcResponse::Error(format!(
        "transport actor failed {operation}: {}",
        failure.description()
    ))
}

fn unexpected_transport_response(operation: &'static str) -> RpcResponse {
    RpcResponse::Error(format!(
        "transport actor returned an unexpected response to {operation}"
    ))
}

fn invalid_request_hash(kind: &'static str) -> RpcResponse {
    RpcResponse::Error(format!("invalid {kind} hash in RPC request"))
}

/// 5 s cap so a wedged actor can't hold a client open indefinitely.
async fn query_transport(
    transport_tx: &mpsc::Sender<TransportMessage>,
    query: rns_transport::messages::TransportQuery,
) -> Result<rns_transport::messages::TransportQueryResponse, TransportQueryFailure> {
    let (tx, rx) = tokio::sync::oneshot::channel();
    let started = std::time::Instant::now();
    match tokio::time::timeout(
        TRANSPORT_QUERY_BUDGET,
        transport_tx.send(TransportMessage::Rpc {
            query,
            response_tx: tx,
        }),
    )
    .await
    {
        Ok(Ok(())) => {}
        Ok(Err(_)) => return Err(TransportQueryFailure::ChannelClosed),
        Err(_) => return Err(TransportQueryFailure::SendTimedOut),
    }
    let remaining = TRANSPORT_QUERY_BUDGET
        .checked_sub(started.elapsed())
        .ok_or(TransportQueryFailure::ResponseTimedOut)?;
    match tokio::time::timeout(remaining, rx).await {
        Ok(Ok(response)) => Ok(response),
        Ok(Err(_)) => Err(TransportQueryFailure::ResponseClosed),
        Err(_) => Err(TransportQueryFailure::ResponseTimedOut),
    }
}

async fn request_path(
    transport_tx: &mpsc::Sender<TransportMessage>,
    destination_hash: [u8; 16],
    timeout_secs: Option<f64>,
) -> Result<bool, TransportQueryFailure> {
    let wait = std::time::Duration::from_secs_f64(timeout_secs.unwrap_or(5.0).max(0.1));
    match tokio::time::timeout(
        TRANSPORT_QUERY_BUDGET,
        transport_tx.send(TransportMessage::RequestPath { destination_hash }),
    )
    .await
    {
        Ok(Ok(())) => {}
        Ok(Err(_)) => return Err(TransportQueryFailure::ChannelClosed),
        Err(_) => return Err(TransportQueryFailure::SendTimedOut),
    }

    let (reply, rx) = tokio::sync::oneshot::channel();
    match tokio::time::timeout(
        TRANSPORT_QUERY_BUDGET,
        transport_tx.send(TransportMessage::AwaitPath {
            dest: destination_hash,
            reply,
        }),
    )
    .await
    {
        Ok(Ok(())) => {}
        Ok(Err(_)) => return Err(TransportQueryFailure::ChannelClosed),
        Err(_) => return Err(TransportQueryFailure::SendTimedOut),
    }

    match tokio::time::timeout(wait, rx).await {
        Ok(Ok(found)) => Ok(found),
        Ok(Err(_)) => Err(TransportQueryFailure::ResponseClosed),
        // This is the caller-selected path-discovery deadline, so an intact
        // actor that simply did not discover a path reports `false`.
        Err(_) => Ok(false),
    }
}

async fn process_rpc_request(
    request: RpcRequest,
    transport_tx: &mpsc::Sender<TransportMessage>,
) -> RpcResponse {
    use rns_transport::messages::{TransportQuery, TransportQueryResponse};

    macro_rules! authoritative_query {
        ($query:expr, $operation:literal) => {
            match query_transport(transport_tx, $query).await {
                Ok(response) => response,
                Err(failure) => return transport_failure_response($operation, failure),
            }
        };
    }

    match request {
        RpcRequest::GetPathTable { max_hops } => {
            match authoritative_query!(TransportQuery::GetPathTable, "path table query") {
                TransportQueryResponse::PathTable(entries) => {
                    let rpc_entries = entries
                        .into_iter()
                        .filter(|e| max_hops.is_none_or(|max| e.hops <= max))
                        .map(|e| rpc::PathTableEntry {
                            hash: e.hash.to_vec(),
                            timestamp: e.timestamp,
                            via: e.via.map(|v| v.to_vec()),
                            hops: e.hops,
                            expires: e.expires,
                            interface: e.interface,
                        })
                        .collect();
                    RpcResponse::PathTable(rpc_entries)
                }
                _ => unexpected_transport_response("path table query"),
            }
        }
        RpcRequest::GetInterfaceStats => {
            match authoritative_query!(TransportQuery::GetInterfaceStats, "interface stats query") {
                TransportQueryResponse::InterfaceStats(entries) => {
                    let rpc_entries = entries
                        .into_iter()
                        .map(|e| rpc::InterfaceStatEntry {
                            id: e.id,
                            name: e.name,
                            rx_bytes: e.rx_bytes,
                            tx_bytes: e.tx_bytes,
                            rx_rate: e.rx_rate,
                            tx_rate: e.tx_rate,
                            online: e.online,
                            bitrate: e.bitrate,
                            mtu: e.mtu,
                            mode: e.mode,
                            role: e.role,
                            announce_queue: e.announce_queue,
                            held_announces: e.held_announces,
                            incoming_announce_frequency: e.incoming_announce_frequency,
                            outgoing_announce_frequency: e.outgoing_announce_frequency,
                            incoming_pr_frequency: e.incoming_pr_frequency,
                            outgoing_pr_frequency: e.outgoing_pr_frequency,
                            burst_active: e.burst_active,
                            burst_activated: e.burst_activated,
                            pr_burst_active: e.pr_burst_active,
                            pr_burst_activated: e.pr_burst_activated,
                            clients: e.clients,
                            blocked_ips: e.blocked_ips,
                            announce_rate_target: e.announce_rate_target,
                            announce_rate_grace: e.announce_rate_grace,
                            announce_rate_penalty: e.announce_rate_penalty,
                            announce_cap: e.announce_cap,
                            ifac_size: e.ifac_size,
                            tx_drops: e.tx_drops,
                        })
                        .collect();
                    RpcResponse::InterfaceStats(rpc_entries)
                }
                _ => unexpected_transport_response("interface stats query"),
            }
        }
        RpcRequest::GetRateTable => {
            match authoritative_query!(TransportQuery::GetRateTable, "rate table query") {
                TransportQueryResponse::RateTable(entries) => {
                    let rpc_entries = entries
                        .into_iter()
                        .map(|e| rpc::RateTableEntry {
                            hash: e.hash.to_vec(),
                            rate: e.rate,
                            last: e.last,
                            rate_violations: e.rate_violations,
                            blocked_until: e.blocked_until,
                            timestamps: e.timestamps,
                        })
                        .collect();
                    RpcResponse::RateTable(rpc_entries)
                }
                _ => unexpected_transport_response("rate table query"),
            }
        }
        RpcRequest::GetLinkCount => {
            match authoritative_query!(TransportQuery::GetLinkCount, "link count query") {
                TransportQueryResponse::IntResult(n) => RpcResponse::IntResult(n),
                _ => unexpected_transport_response("link count query"),
            }
        }
        RpcRequest::GetNextHopIfName { destination_hash } => {
            let Some(dest) = hash_to_array(&destination_hash) else {
                return invalid_request_hash("destination");
            };
            match authoritative_query!(
                TransportQuery::GetNextHopIfName { dest },
                "next-hop interface query"
            ) {
                TransportQueryResponse::StringResult(name) => RpcResponse::StringResult(name),
                _ => unexpected_transport_response("next-hop interface query"),
            }
        }
        RpcRequest::GetNextHop { destination_hash } => {
            let Some(dest) = hash_to_array(&destination_hash) else {
                return invalid_request_hash("destination");
            };
            match authoritative_query!(TransportQuery::GetNextHop { dest }, "next-hop query") {
                TransportQueryResponse::HashResult(hash) => {
                    RpcResponse::HashResult(hash.map(|hash| hash.to_vec()))
                }
                _ => unexpected_transport_response("next-hop query"),
            }
        }
        RpcRequest::RequestPath {
            destination_hash,
            timeout_secs,
        } => {
            let Some(dest) = hash_to_array(&destination_hash) else {
                return invalid_request_hash("destination");
            };
            match request_path(transport_tx, dest, timeout_secs).await {
                Ok(found) => RpcResponse::BoolResult(found),
                Err(failure) => transport_failure_response("path request", failure),
            }
        }
        RpcRequest::DropPath { destination_hash } => {
            let Some(dest) = hash_to_array(&destination_hash) else {
                return invalid_request_hash("destination");
            };
            match authoritative_query!(TransportQuery::DropPath { dest }, "path drop") {
                TransportQueryResponse::Ok => RpcResponse::Ok,
                _ => unexpected_transport_response("path drop"),
            }
        }
        RpcRequest::DropPathTable => {
            match authoritative_query!(TransportQuery::DropPathTable, "path table drop") {
                TransportQueryResponse::IntResult(n) => RpcResponse::IntResult(n),
                _ => unexpected_transport_response("path table drop"),
            }
        }
        RpcRequest::DropRecentAnnounces => {
            match authoritative_query!(TransportQuery::DropRecentAnnounces, "recent announces drop")
            {
                TransportQueryResponse::IntResult(n) => RpcResponse::IntResult(n),
                _ => unexpected_transport_response("recent announces drop"),
            }
        }
        RpcRequest::DropAnnounceQueues => {
            match authoritative_query!(TransportQuery::DropAnnounceQueues, "announce queue drop") {
                TransportQueryResponse::Ok => RpcResponse::Ok,
                _ => unexpected_transport_response("announce queue drop"),
            }
        }
        RpcRequest::GetBlackholedIdentities => match authoritative_query!(
            TransportQuery::GetBlackholedIdentities,
            "blackholed identity query"
        ) {
            TransportQueryResponse::BlackholeList(entries) => {
                let rpc_entries = entries
                    .into_iter()
                    .map(|e| rpc::BlackholeEntry {
                        identity_hash: e.identity_hash.to_vec(),
                        source: e.source.map(|source| source.to_vec()),
                        // Wire compat: `until` is absolute expiry (created + ttl);
                        // permanent entries report `None`.
                        until: e.ttl.map(|t| e.created + t),
                        reason: Some(
                            e.reason_label
                                .unwrap_or_else(|| e.reason.as_str().to_string()),
                        ),
                    })
                    .collect();
                RpcResponse::BlackholeList(rpc_entries)
            }
            _ => unexpected_transport_response("blackholed identity query"),
        },
        RpcRequest::IsBlackholed { identity_hash } => {
            let Some(hash) = hash_to_array(&identity_hash) else {
                return invalid_request_hash("identity");
            };
            match authoritative_query!(
                TransportQuery::IsBlackholed { hash },
                "blackhole status query"
            ) {
                TransportQueryResponse::BoolResult(value) => RpcResponse::BoolResult(value),
                _ => unexpected_transport_response("blackhole status query"),
            }
        }
        RpcRequest::BlackholeIdentity {
            identity_hash,
            until,
            reason,
        } => {
            let Some(hash) = hash_to_array(&identity_hash) else {
                return invalid_request_hash("identity");
            };
            // `until` (absolute unix ts) → relative TTL; past timestamps
            // clamp to ~0 so the entry expires on the next maintenance tick.
            let ttl = until.map(|until| {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs_f64();
                (until - now).max(0.001)
            });
            let reason_enum = reason
                .as_deref()
                .map(rns_transport::blackhole::BlackholeReason::parse)
                .unwrap_or_default();
            match authoritative_query!(
                TransportQuery::BlackholeIdentity {
                    hash,
                    ttl,
                    reason: reason_enum,
                    reason_label: reason,
                },
                "identity blackhole"
            ) {
                TransportQueryResponse::Ok => RpcResponse::Ok,
                _ => unexpected_transport_response("identity blackhole"),
            }
        }
        RpcRequest::UnblackholeIdentity { identity_hash } => {
            let Some(hash) = hash_to_array(&identity_hash) else {
                return invalid_request_hash("identity");
            };
            match authoritative_query!(
                TransportQuery::UnblackholeIdentity { hash },
                "identity unblackhole"
            ) {
                // Python's mutation response is success-shaped even when the
                // identity was not present; the typed actor result proves the
                // mutation was authoritatively processed.
                TransportQueryResponse::BoolResult(_) => RpcResponse::Ok,
                _ => unexpected_transport_response("identity unblackhole"),
            }
        }
        RpcRequest::GetFirstHopTimeout { destination_hash } => {
            let Some(dest) = hash_to_array(&destination_hash) else {
                return invalid_request_hash("destination");
            };
            match authoritative_query!(
                TransportQuery::FirstHopTimeout { dest },
                "first-hop timeout query"
            ) {
                TransportQueryResponse::FloatResult(value) => RpcResponse::FloatResult(value),
                _ => unexpected_transport_response("first-hop timeout query"),
            }
        }
        RpcRequest::GetPacketRssi { packet_hash } => {
            let Some(packet_hash) = packet_hash_to_array(&packet_hash) else {
                return invalid_request_hash("packet");
            };
            match authoritative_query!(
                TransportQuery::GetPacketRssi { packet_hash },
                "packet RSSI query"
            ) {
                TransportQueryResponse::FloatResult(value) => RpcResponse::FloatResult(value),
                _ => unexpected_transport_response("packet RSSI query"),
            }
        }
        RpcRequest::GetPacketSnr { packet_hash } => {
            let Some(packet_hash) = packet_hash_to_array(&packet_hash) else {
                return invalid_request_hash("packet");
            };
            match authoritative_query!(
                TransportQuery::GetPacketSnr { packet_hash },
                "packet SNR query"
            ) {
                TransportQueryResponse::FloatResult(value) => RpcResponse::FloatResult(value),
                _ => unexpected_transport_response("packet SNR query"),
            }
        }
        RpcRequest::GetPacketQ { packet_hash } => {
            let Some(packet_hash) = packet_hash_to_array(&packet_hash) else {
                return invalid_request_hash("packet");
            };
            match authoritative_query!(
                TransportQuery::GetPacketQ { packet_hash },
                "packet quality query"
            ) {
                TransportQueryResponse::FloatResult(value) => RpcResponse::FloatResult(value),
                _ => unexpected_transport_response("packet quality query"),
            }
        }
        RpcRequest::DropAllVia { transport_hash } => {
            let Some(next_hop) = hash_to_array(&transport_hash) else {
                return invalid_request_hash("transport");
            };
            match authoritative_query!(
                TransportQuery::DropAllVia { next_hop },
                "drop all via transport"
            ) {
                TransportQueryResponse::IntResult(count) => RpcResponse::IntResult(count),
                _ => unexpected_transport_response("drop all via transport"),
            }
        }
        RpcRequest::UseDestination { destination_hash } => {
            let Some(dest) = hash_to_array(&destination_hash) else {
                return invalid_request_hash("destination");
            };
            match authoritative_query!(TransportQuery::UseDestination { dest }, "destination use") {
                TransportQueryResponse::BoolResult(value) => RpcResponse::BoolResult(value),
                _ => unexpected_transport_response("destination use"),
            }
        }
        RpcRequest::RetainDestination { destination_hash } => {
            let Some(dest) = hash_to_array(&destination_hash) else {
                return invalid_request_hash("destination");
            };
            match authoritative_query!(
                TransportQuery::RetainDestination { dest },
                "destination retention"
            ) {
                TransportQueryResponse::BoolResult(value) => RpcResponse::BoolResult(value),
                _ => unexpected_transport_response("destination retention"),
            }
        }
        RpcRequest::RetainIdentity { identity_hash } => {
            let Some(identity_hash) = hash_to_array(&identity_hash) else {
                return invalid_request_hash("identity");
            };
            match authoritative_query!(
                TransportQuery::RetainIdentity { identity_hash },
                "identity retention"
            ) {
                TransportQueryResponse::BoolResult(value) => RpcResponse::BoolResult(value),
                _ => unexpected_transport_response("identity retention"),
            }
        }
        RpcRequest::UnretainDestination { destination_hash } => {
            let Some(dest) = hash_to_array(&destination_hash) else {
                return invalid_request_hash("destination");
            };
            match authoritative_query!(
                TransportQuery::UnretainDestination { dest },
                "destination release"
            ) {
                TransportQueryResponse::BoolResult(value) => RpcResponse::BoolResult(value),
                _ => unexpected_transport_response("destination release"),
            }
        }
    }
}

fn hash_to_array(hash: &[u8]) -> Option<[u8; 16]> {
    if hash.len() >= 16 {
        let mut arr = [0u8; 16];
        arr.copy_from_slice(&hash[..16]);
        Some(arr)
    } else {
        None
    }
}

fn packet_hash_to_array(hash: &[u8]) -> Option<[u8; 32]> {
    if hash.len() >= 32 {
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&hash[..32]);
        Some(arr)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn all_rpc_requests() -> Vec<RpcRequest> {
        vec![
            RpcRequest::GetPathTable { max_hops: Some(5) },
            RpcRequest::GetInterfaceStats,
            RpcRequest::GetRateTable,
            RpcRequest::GetNextHopIfName {
                destination_hash: vec![0; 16],
            },
            RpcRequest::GetNextHop {
                destination_hash: vec![0; 16],
            },
            RpcRequest::RequestPath {
                destination_hash: vec![0; 16],
                timeout_secs: Some(0.01),
            },
            RpcRequest::GetFirstHopTimeout {
                destination_hash: vec![0; 16],
            },
            RpcRequest::GetLinkCount,
            RpcRequest::GetPacketRssi {
                packet_hash: vec![0; 32],
            },
            RpcRequest::GetPacketSnr {
                packet_hash: vec![0; 32],
            },
            RpcRequest::GetPacketQ {
                packet_hash: vec![0; 32],
            },
            RpcRequest::GetBlackholedIdentities,
            RpcRequest::IsBlackholed {
                identity_hash: vec![0; 16],
            },
            RpcRequest::DropPath {
                destination_hash: vec![0; 16],
            },
            RpcRequest::DropAllVia {
                transport_hash: vec![0; 16],
            },
            RpcRequest::DropPathTable,
            RpcRequest::DropRecentAnnounces,
            RpcRequest::DropAnnounceQueues,
            RpcRequest::BlackholeIdentity {
                identity_hash: vec![0; 16],
                until: Some(99999.0),
                reason: Some("test".to_string()),
            },
            RpcRequest::UnblackholeIdentity {
                identity_hash: vec![0; 16],
            },
            RpcRequest::UseDestination {
                destination_hash: vec![0; 16],
            },
            RpcRequest::RetainDestination {
                destination_hash: vec![0; 16],
            },
            RpcRequest::RetainIdentity {
                identity_hash: vec![0; 16],
            },
            RpcRequest::UnretainDestination {
                destination_hash: vec![0; 16],
            },
        ]
    }

    #[tokio::test]
    async fn test_rpc_server_bind_and_shutdown() {
        let shutdown = ShutdownSignal::new();
        let (tx, _rx) = mpsc::channel(16);
        let rpc_key = vec![0x42u8; 32];

        let shutdown_clone = shutdown.clone();
        let handle = tokio::spawn(async move {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            run_rpc_server_with_listener(listener, rpc_key, tx, shutdown_clone).await
        });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        shutdown.trigger();

        let result = tokio::time::timeout(std::time::Duration::from_secs(2), handle).await;
        assert!(result.is_ok(), "server should shut down promptly");
        assert!(result.unwrap().unwrap().is_ok());
    }

    #[tokio::test]
    async fn test_rpc_server_auth_and_query() {
        let shutdown = ShutdownSignal::new();
        let (actor, tx) = rns_transport::actor::TransportActor::new();
        tokio::spawn(actor.run());
        let rpc_key = b"test_rpc_key_for_auth".to_vec();

        let port = spawn_test_rpc_server(rpc_key.clone(), tx, shutdown.clone()).await;

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let response = rpc_client_request(port, &rpc_key, RpcRequest::GetLinkCount).await;
        match response {
            RpcResponse::IntResult(n) => assert_eq!(n, 0),
            other => panic!("expected IntResult(0), got {other:?}"),
        }

        shutdown.trigger();
    }

    #[tokio::test]
    async fn test_rpc_server_auth_failure() {
        let shutdown = ShutdownSignal::new();
        let (tx, _rx) = mpsc::channel(16);
        let rpc_key = b"correct_key".to_vec();

        let port = spawn_test_rpc_server(rpc_key.clone(), tx, shutdown.clone()).await;

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let mut stream = connect_retry(port).await;

        let challenge_frame = rpc::read_mp_frame(&mut stream, 256).await.unwrap();
        assert!(challenge_frame.starts_with(rpc::MP_CHALLENGE));
        let challenge = &challenge_frame[rpc::MP_CHALLENGE.len()..];

        let bad_hmac = rpc::compute_python_auth_response(b"wrong_key", challenge);
        rpc::write_mp_frame(&mut stream, &bad_hmac).await.unwrap();

        let result = rpc::read_mp_frame(&mut stream, 256).await.unwrap();
        assert_eq!(result, rpc::MP_FAILURE);

        shutdown.trigger();
    }

    #[tokio::test]
    async fn test_rpc_server_multiple_request_types() {
        let shutdown = ShutdownSignal::new();
        let (actor, tx) = rns_transport::actor::TransportActor::new();
        tokio::spawn(actor.run());
        let rpc_key = b"multi_test_key".to_vec();

        let port = spawn_test_rpc_server(rpc_key.clone(), tx, shutdown.clone()).await;

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let response =
            rpc_client_request(port, &rpc_key, RpcRequest::GetPathTable { max_hops: None }).await;
        assert!(matches!(response, RpcResponse::PathTable(ref v) if v.is_empty()));

        let response = rpc_client_request(port, &rpc_key, RpcRequest::GetInterfaceStats).await;
        assert!(matches!(response, RpcResponse::InterfaceStats(ref v) if v.is_empty()));

        let response = rpc_client_request(port, &rpc_key, RpcRequest::DropAnnounceQueues).await;
        assert!(matches!(response, RpcResponse::Ok));

        let response = rpc_client_request(
            port,
            &rpc_key,
            RpcRequest::GetNextHopIfName {
                destination_hash: vec![0; 16],
            },
        )
        .await;
        assert!(matches!(response, RpcResponse::StringResult(None)));

        shutdown.trigger();
    }

    #[tokio::test]
    async fn live_listener_returns_errors_when_transport_actor_is_closed() {
        let shutdown = ShutdownSignal::new();
        let (tx, rx) = mpsc::channel(1);
        drop(rx);
        let rpc_key = b"closed_actor_key".to_vec();
        let port = spawn_test_rpc_server(rpc_key.clone(), tx, shutdown.clone()).await;

        for request in all_rpc_requests() {
            let response = rpc_client_request(port, &rpc_key, request).await;
            assert!(
                matches!(response, RpcResponse::Error(_)),
                "closed transport actor must produce an RPC error, got {response:?}"
            );
        }

        shutdown.trigger();
    }

    #[tokio::test]
    async fn transport_query_reports_closed_send_and_response_channels() {
        let (closed_tx, closed_rx) = mpsc::channel(1);
        drop(closed_rx);
        assert!(matches!(
            query_transport(
                &closed_tx,
                rns_transport::messages::TransportQuery::GetLinkCount
            )
            .await,
            Err(TransportQueryFailure::ChannelClosed)
        ));

        let (tx, mut rx) = mpsc::channel(1);
        let responder = tokio::spawn(async move {
            let Some(TransportMessage::Rpc { response_tx, .. }) = rx.recv().await else {
                panic!("expected transport RPC query");
            };
            drop(response_tx);
        });
        assert!(matches!(
            query_transport(&tx, rns_transport::messages::TransportQuery::GetLinkCount).await,
            Err(TransportQueryFailure::ResponseClosed)
        ));
        responder.await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn transport_query_reports_enqueue_and_response_timeouts() {
        let (full_tx, full_rx) = mpsc::channel(1);
        full_tx.send(TransportMessage::Shutdown).await.unwrap();
        assert!(matches!(
            query_transport(
                &full_tx,
                rns_transport::messages::TransportQuery::GetLinkCount
            )
            .await,
            Err(TransportQueryFailure::SendTimedOut)
        ));
        drop(full_rx);

        let (tx, mut rx) = mpsc::channel(1);
        let responder = tokio::spawn(async move {
            let Some(TransportMessage::Rpc { response_tx, .. }) = rx.recv().await else {
                panic!("expected transport RPC query");
            };
            let _response_tx = response_tx;
            std::future::pending::<()>().await;
        });
        assert!(matches!(
            query_transport(&tx, rns_transport::messages::TransportQuery::GetLinkCount).await,
            Err(TransportQueryFailure::ResponseTimedOut)
        ));
        responder.abort();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_rpc_server_accepts_python_multiprocessing_client() {
        if std::process::Command::new("python3")
            .arg("-c")
            .arg("import multiprocessing.connection")
            .status()
            .is_err()
        {
            return;
        }

        let shutdown = ShutdownSignal::new();
        let (actor, tx) = rns_transport::actor::TransportActor::new();
        tokio::spawn(actor.run());
        let rpc_key = b"python_multiprocessing_key".to_vec();

        let port = spawn_test_rpc_server(rpc_key.clone(), tx, shutdown.clone()).await;

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Python >=1.3.4 clients speak umsgpack over send_bytes/recv_bytes
        // (commit a2ef9782); frames hardcoded so the test needs no msgpack module.
        let script = r#"
import multiprocessing.connection
import sys

port = int(sys.argv[1])
authkey = bytes.fromhex(sys.argv[2])
conn = multiprocessing.connection.Client(("127.0.0.1", port), authkey=authkey)
conn.send_bytes(bytes.fromhex("81a3676574aa6c696e6b5f636f756e74"))  # {"get": "link_count"}
resp = conn.recv_bytes()
conn.close()
if resp != b"\x00":
    raise SystemExit(f"unexpected response: {resp.hex()}")
conn = multiprocessing.connection.Client(("127.0.0.1", port), authkey=authkey)
conn.send_bytes(bytes.fromhex("81a3676574af696e746572666163655f7374617473"))  # {"get": "interface_stats"}
resp = conn.recv_bytes()
conn.close()
if b"\xaainterfaces" not in resp:
    raise SystemExit(f"unexpected interface_stats response: {resp.hex()}")
"#;
        let output = std::process::Command::new("python3")
            .arg("-c")
            .arg(script)
            .arg(port.to_string())
            .arg(hex::encode(&rpc_key))
            .output()
            .expect("python3 should run");

        shutdown.trigger();

        assert!(
            output.status.success(),
            "python client failed\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_rust_client_accepts_python_multiprocessing_listener() {
        if std::process::Command::new("python3")
            .arg("-c")
            .arg("import multiprocessing.connection")
            .status()
            .is_err()
        {
            return;
        }

        let port = portpicker_ephemeral();
        let rpc_key = b"python_listener_key".to_vec();
        // umsgpack frames over send_bytes/recv_bytes, matching a >=1.3.4
        // Python rpc_loop (commit a2ef9782); hardcoded so no msgpack module
        // is needed.
        let script = r#"
import multiprocessing.connection
import sys

port = int(sys.argv[1])
authkey = bytes.fromhex(sys.argv[2])
listener = multiprocessing.connection.Listener(("127.0.0.1", port), authkey=authkey)
print("READY", flush=True)
conn = listener.accept()
call = conn.recv_bytes()
if call != bytes.fromhex("81a3676574aa6c696e6b5f636f756e74"):  # {"get": "link_count"}
    raise SystemExit(f"unexpected call: {call.hex()}")
conn.send_bytes(b"\x07")  # 7
conn.close()
listener.close()
"#;
        let mut child = std::process::Command::new("python3")
            .arg("-c")
            .arg(script)
            .arg(port.to_string())
            .arg(hex::encode(&rpc_key))
            .stdout(std::process::Stdio::piped())
            .spawn()
            .expect("python3 should start");

        let stdout = child.stdout.take().expect("python listener stdout");
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            use std::io::BufRead as _;
            let mut line = String::new();
            let result = std::io::BufReader::new(stdout)
                .read_line(&mut line)
                .map(|_| line);
            let _ = ready_tx.send(result);
        });
        match ready_rx.recv_timeout(std::time::Duration::from_secs(5)) {
            Ok(Ok(line)) if line.trim() == "READY" => {}
            Ok(Ok(line)) => {
                let _ = child.kill();
                panic!("unexpected Python listener readiness line: {line:?}");
            }
            Ok(Err(e)) => {
                let _ = child.kill();
                panic!("failed to read Python listener readiness: {e}");
            }
            Err(e) => {
                let _ = child.kill();
                panic!("timed out waiting for Python listener readiness: {e}");
            }
        }

        match rpc::connect_and_request(
            port,
            &rpc_key,
            &RpcRequest::GetLinkCount,
            std::time::Duration::from_secs(5),
        )
        .await
        {
            Ok(RpcResponse::IntResult(7)) => {
                let status = child.wait().expect("python listener should exit");
                assert!(status.success(), "python listener exited with {status}");
            }
            Ok(other) => {
                let _ = child.kill();
                panic!("unexpected Python listener response: {other:?}");
            }
            Err(e) => {
                let _ = child.kill();
                panic!("Rust client could not connect to Python multiprocessing listener: {e}");
            }
        }
    }

    #[tokio::test]
    async fn test_process_rpc_request_all_variants() {
        let (actor, tx) = rns_transport::actor::TransportActor::new();
        tokio::spawn(actor.run());

        for req in all_rpc_requests() {
            let resp = process_rpc_request(req, &tx).await;
            assert!(
                !matches!(resp, RpcResponse::Error(_)),
                "unexpected Error response"
            );
        }

        let _ = tx.send(TransportMessage::Shutdown).await;
    }

    #[tokio::test]
    async fn request_path_rpc_sends_transport_request_and_awaits_result() {
        let (tx, mut rx) = mpsc::channel(4);
        let dest = [0x42; 16];
        let handle = tokio::spawn(async move {
            process_rpc_request(
                RpcRequest::RequestPath {
                    destination_hash: dest.to_vec(),
                    timeout_secs: Some(1.0),
                },
                &tx,
            )
            .await
        });

        match rx.recv().await.expect("RequestPath message") {
            TransportMessage::RequestPath { destination_hash } => {
                assert_eq!(destination_hash, dest)
            }
            other => panic!("expected RequestPath, got {other:?}"),
        }
        match rx.recv().await.expect("AwaitPath message") {
            TransportMessage::AwaitPath {
                dest: awaited,
                reply,
            } => {
                assert_eq!(awaited, dest);
                reply.send(true).unwrap();
            }
            other => panic!("expected AwaitPath, got {other:?}"),
        }

        assert!(matches!(
            handle.await.unwrap(),
            RpcResponse::BoolResult(true)
        ));
    }

    fn portpicker_ephemeral() -> u16 {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.local_addr().unwrap().port()
    }

    async fn rpc_client_request(port: u16, rpc_key: &[u8], request: RpcRequest) -> RpcResponse {
        let mut last_err = None;
        for _ in 0..20 {
            match rpc::connect_and_request(
                port,
                rpc_key,
                &request,
                std::time::Duration::from_secs(2),
            )
            .await
            {
                Ok(response) => return response,
                Err(e) => {
                    last_err = Some(e.to_string());
                    tokio::time::sleep(std::time::Duration::from_millis(25)).await;
                }
            }
        }
        panic!("RPC client request failed: {last_err:?}");
    }

    async fn spawn_test_rpc_server(
        rpc_key: Vec<u8>,
        tx: mpsc::Sender<TransportMessage>,
        shutdown: ShutdownSignal,
    ) -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let _ = run_rpc_server_with_listener(listener, rpc_key, tx, shutdown).await;
        });
        port
    }

    async fn connect_retry(port: u16) -> tokio::net::TcpStream {
        let addr = format!("127.0.0.1:{port}");
        let mut last_err = None;
        for _ in 0..20 {
            match tokio::net::TcpStream::connect(&addr).await {
                Ok(stream) => return stream,
                Err(e) => {
                    last_err = Some(e);
                    tokio::time::sleep(std::time::Duration::from_millis(25)).await;
                }
            }
        }
        panic!("failed to connect to RPC server on {addr}: {last_err:?}");
    }
}
