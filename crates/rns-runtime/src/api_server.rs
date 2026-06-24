//! Embedded REST API server for rnsd-rs.
//!
//! Enabled via `--features api` during build and the `api_listen` key in the
//! `[reticulum]` section of the config, for example:
//!
//! ```ini
//! [reticulum]
//! api_listen = 127.0.0.1:8080
//! ```
//!
//! Unlike RPC clients (rnstatus-rs and others), this server runs
//! within the rnsd process and accesses the transport directly via
//! `transport_tx`, bypassing the pickle/HMAC protocol.
//!
//! # Routes
//!
//! ```text
//! GET /health                     — liveness probe
//! GET /api/v1/status              — summary: counters + interface list
//! GET /api/v1/interfaces          — interface list (?filter=…&all=true)
//! GET /api/v1/interfaces/{id}     — one interface by numeric ID
//! GET /api/v1/paths               — path table (?max_hops=N)
//! GET /api/v1/links               — number of active links
//! ```

use std::net::SocketAddr;

use axum::Router;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Json, Response};
use axum::routing::get;
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::sync::mpsc;

use rns_transport::messages::{
    InterfaceStatRpcEntry, PathTableRpcEntry, TransportMessage, TransportQuery,
    TransportQueryResponse,
};

use crate::lifecycle::ShutdownSignal;

// ─────────────────────────────────────────────────────────────────────────────
// Starting the server
// ─────────────────────────────────────────────────────────────────────────────

pub async fn run_api_server(
    listen: SocketAddr,
    transport_tx: mpsc::Sender<TransportMessage>,
    shutdown: ShutdownSignal,
) {
    let state = AppState { transport_tx };

    let app = Router::new()
        .route("/health", get(health))
        .route("/api/v1/status", get(status))
        .route("/api/v1/interfaces", get(interfaces))
        .route("/api/v1/interfaces/{id}", get(interface_by_id))
        .route("/api/v1/paths", get(paths))
        .route("/api/v1/links", get(links))
        .layer(tower_http::trace::TraceLayer::new_for_http())
        .with_state(state);

    let listener = match tokio::net::TcpListener::bind(listen).await {
        Ok(l) => l,
        Err(e) => {
            tracing::error!(addr = %listen, error = %e, "REST API: failed to bind");
            return;
        }
    };

    tracing::info!(addr = %listen, "REST API listening");

    tokio::select! {
        result = axum::serve(listener, app) => {
            if let Err(e) = result {
                tracing::warn!(error = %e, "REST API server error");
            }
        }
        () = shutdown.wait() => {
            tracing::debug!("REST API shutting down");
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Shared state
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Clone)]
struct AppState {
    transport_tx: mpsc::Sender<TransportMessage>,
}

impl AppState {
    async fn query(&self, query: TransportQuery) -> Result<TransportQueryResponse, ApiError> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.transport_tx
            .send(TransportMessage::Rpc {
                query,
                response_tx: tx,
            })
            .await
            .map_err(|_| ApiError::transport("transport actor is gone"))?;

        rx.await
            .map_err(|_| ApiError::transport("transport actor dropped response channel"))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Errors
// ─────────────────────────────────────────────────────────────────────────────

enum ApiError {
    NotFound,
    Transport(String),
    Internal(String),
}

impl ApiError {
    fn transport(msg: impl Into<String>) -> Self {
        ApiError::Transport(msg.into())
    }
    fn internal(msg: impl Into<String>) -> Self {
        ApiError::Internal(msg.into())
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            ApiError::NotFound => (StatusCode::NOT_FOUND, "not found".to_string()),
            ApiError::Transport(m) => (StatusCode::SERVICE_UNAVAILABLE, m),
            ApiError::Internal(m) => (StatusCode::INTERNAL_SERVER_ERROR, m),
        };
        (status, Json(json!({ "error": message }))).into_response()
    }
}

type ApiResult<T> = Result<T, ApiError>;

// ─────────────────────────────────────────────────────────────────────────────
// Handlers
// ─────────────────────────────────────────────────────────────────────────────

async fn health() -> (StatusCode, Json<Value>) {
    (StatusCode::OK, Json(json!({ "ok": true })))
}

async fn status(State(s): State<AppState>) -> ApiResult<Json<Value>> {
    let ifaces = fetch_interfaces(&s).await?;

    let total_rx: u64 = ifaces.iter().map(|e| e.rx_bytes).sum();
    let total_tx: u64 = ifaces.iter().map(|e| e.tx_bytes).sum();
    let online = ifaces.iter().filter(|e| e.online).count();

    Ok(Json(json!({
        "interfaces_total": ifaces.len(),
        "interfaces_online": online,
        "rx_bytes_total": total_rx,
        "tx_bytes_total": total_tx,
        "interfaces": ifaces.iter().map(iface_json).collect::<Vec<_>>(),
    })))
}

#[derive(Deserialize)]
struct InterfacesQuery {
    filter: Option<String>,
    all: Option<bool>,
}

async fn interfaces(
    State(s): State<AppState>,
    Query(q): Query<InterfacesQuery>,
) -> ApiResult<Json<Value>> {
    let ifaces = fetch_interfaces(&s).await?;
    let show_all = q.all.unwrap_or(false);

    let entries: Vec<_> = ifaces
        .iter()
        .filter(|e| show_all || visible_by_default(&e.name))
        .filter(|e| {
            q.filter
                .as_deref()
                .map_or(true, |f| e.name.to_lowercase().contains(&f.to_lowercase()))
        })
        .map(iface_json)
        .collect();

    Ok(Json(json!({ "interfaces": entries })))
}

async fn interface_by_id(State(s): State<AppState>, Path(id): Path<u64>) -> ApiResult<Json<Value>> {
    let ifaces = fetch_interfaces(&s).await?;
    ifaces
        .iter()
        .find(|e| e.id == id)
        .map(|e| Json(iface_json(e)))
        .ok_or(ApiError::NotFound)
}

#[derive(Deserialize)]
struct PathsQuery {
    max_hops: Option<u8>,
}

async fn paths(State(s): State<AppState>, Query(q): Query<PathsQuery>) -> ApiResult<Json<Value>> {
    // TransportQuery::GetPathTable doesn't accept max_hops directly —
    // We filter on the API side, like rnpath-rs does.
    let entries = match s.query(TransportQuery::GetPathTable).await? {
        TransportQueryResponse::PathTable(v) => v,
        TransportQueryResponse::Error(e) => return Err(ApiError::internal(e)),
        other => {
            return Err(ApiError::internal(format!(
                "unexpected response: {other:?}"
            )));
        }
    };

    let rows: Vec<_> = entries
        .iter()
        .filter(|e| q.max_hops.map_or(true, |max| e.hops <= max))
        .map(path_json)
        .collect();

    Ok(Json(json!({ "paths": rows, "count": rows.len() })))
}

async fn links(State(s): State<AppState>) -> ApiResult<Json<Value>> {
    match s.query(TransportQuery::GetLinkCount).await? {
        TransportQueryResponse::IntResult(n) => Ok(Json(json!({ "link_count": n }))),
        TransportQueryResponse::Error(e) => Err(ApiError::internal(e)),
        other => Err(ApiError::internal(format!(
            "unexpected response: {other:?}"
        ))),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

async fn fetch_interfaces(s: &AppState) -> ApiResult<Vec<InterfaceStatRpcEntry>> {
    match s.query(TransportQuery::GetInterfaceStats).await? {
        TransportQueryResponse::InterfaceStats(v) => Ok(v),
        TransportQueryResponse::Error(e) => Err(ApiError::internal(e)),
        other => Err(ApiError::internal(format!(
            "unexpected response: {other:?}"
        ))),
    }
}

fn iface_json(e: &InterfaceStatRpcEntry) -> Value {
    json!({
        "id":                           e.id,
        "name":                         e.name,
        "online":                       e.online,
        "mode":                         e.mode,
        "role":                         e.role,
        "bitrate":                      e.bitrate,
        "mtu":                          e.mtu,
        "ifac_size":                    e.ifac_size,
        "clients":                      e.clients,
        "rx_bytes":                     e.rx_bytes,
        "tx_bytes":                     e.tx_bytes,
        "rx_rate":                      e.rx_rate,
        "tx_rate":                      e.tx_rate,
        "tx_drops":                     e.tx_drops,
        "announce_queue":               e.announce_queue,
        "held_announces":               e.held_announces,
        "incoming_announce_frequency":  e.incoming_announce_frequency,
        "outgoing_announce_frequency":  e.outgoing_announce_frequency,
        "announce_rate_target":         e.announce_rate_target,
        "announce_rate_grace":          e.announce_rate_grace,
        "announce_rate_penalty":        e.announce_rate_penalty,
        "announce_cap":                 e.announce_cap,
        "incoming_pr_frequency":        e.incoming_pr_frequency,
        "outgoing_pr_frequency":        e.outgoing_pr_frequency,
        "burst_active":                 e.burst_active,
        "burst_activated":              e.burst_activated,
        "pr_burst_active":              e.pr_burst_active,
        "pr_burst_activated":           e.pr_burst_activated,
    })
}

fn path_json(e: &PathTableRpcEntry) -> Value {
    json!({
        "hash":      hex::encode(e.hash),
        "hops":      e.hops,
        "interface": e.interface,
        "via":       e.via.map(hex::encode),
        "timestamp": e.timestamp,
        "expires":   e.expires,
    })
}

/// The same visibility rules as in rnstatus-rs - hide internal peerings.
fn visible_by_default(name: &str) -> bool {
    !(name.starts_with("LocalInterface[")
        || name.starts_with("TCPInterface[Client")
        || name.starts_with("BackboneInterface[Client on")
        || name.starts_with("AutoInterfacePeer[")
        || name.starts_with("WeaveInterfacePeer[")
        || name.starts_with("I2PInterfacePeer[Connected peer"))
}
