//! Embedded REST API server for rnsd-rs.
//!
//! Activated via `--features api` during build and the `api_listen` key in the
//! `[reticulum]` section of the config, for example:
//!
//! ```ini
//! [reticulum]
//! api_listen = 127.0.0.1:8080
//! ```
//!
//! The server runs inside the rnsd process and accesses the transport
//! directly via `transport_tx`, bypassing the pickle/HMAC protocol.
//!
//! # Routes
//!
//! ```text
//! GET /health                     — liveness probe
//! GET /api/v1/status              — summary: counters + interface list
//! GET /api/v1/interfaces          — list of interfaces (?filter=…&all=true)
//! GET /api/v1/interfaces/{id}     — one interface by numeric id
//! GET /api/v1/paths               — path table (?max_hops=N)
//! GET /api/v1/links               — number of active links
//! POST /api/v1/interfaces         — add an interface
//! PUT /api/v1/interfaces/{id}     — replace the interface configuration
//! DELETE /api/v1/interfaces/{id}  — delete an interface
//! ```

use std::net::SocketAddr;
use std::path::PathBuf;

use axum::Router;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Json, Response};
use axum::routing::{delete, get, post, put};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::sync::mpsc;

use rns_transport::messages::{
    InterfaceStatRpcEntry, PathTableRpcEntry, TransportMessage, TransportQuery,
    TransportQueryResponse,
};

use crate::config::{Config, ConfigSection};
use crate::interface_factory::{InterfaceConfig, synthesize_interface};
use crate::lifecycle::ShutdownSignal;
use crate::reticulum::{ReticulumHandle, teardown_interface};

// ─────────────────────────────────────────────────────────────────────────────
// Starting the server
// ─────────────────────────────────────────────────────────────────────────────

pub async fn run_api_server(
    listen: SocketAddr,
    transport_tx: mpsc::Sender<TransportMessage>,
    handle: ReticulumHandle,
    shutdown: ShutdownSignal,
) {
    let state = AppState {
        transport_tx,
        handle,
    };

    let app = Router::new()
        .route("/health", get(health))
        .route("/api/v1/status", get(status))
        .route("/api/v1/interfaces", get(interfaces).post(create_interface))
        .route(
            "/api/v1/interfaces/{id}",
            get(interface_by_id)
                .put(update_interface)
                .delete(delete_interface),
        )
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
// State
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Clone)]
struct AppState {
    transport_tx: mpsc::Sender<TransportMessage>,
    handle: ReticulumHandle,
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

    fn config_path(&self) -> PathBuf {
        self.handle.config_dir.join("config")
    }

    fn load_config(&self) -> Result<Config, ApiError> {
        Config::from_file(&self.config_path())
            .map_err(|e| ApiError::internal(format!("failed to read config: {e}")))
    }

    fn save_config(&self, config: &Config) -> Result<(), ApiError> {
        config
            .save_to(&self.config_path())
            .map_err(|e| ApiError::internal(format!("failed to write config: {e}")))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Errors
// ─────────────────────────────────────────────────────────────────────────────

enum ApiError {
    NotFound,
    BadRequest(String),
    Conflict(String),
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
    fn bad(msg: impl Into<String>) -> Self {
        ApiError::BadRequest(msg.into())
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            ApiError::NotFound => (StatusCode::NOT_FOUND, "not found".to_string()),
            ApiError::BadRequest(m) => (StatusCode::UNPROCESSABLE_ENTITY, m),
            ApiError::Conflict(m) => (StatusCode::CONFLICT, m),
            ApiError::Transport(m) => (StatusCode::SERVICE_UNAVAILABLE, m),
            ApiError::Internal(m) => (StatusCode::INTERNAL_SERVER_ERROR, m),
        };
        (status, Json(json!({ "error": message }))).into_response()
    }
}

type ApiResult<T> = Result<T, ApiError>;

// ─────────────────────────────────────────────────────────────────────────────
// Input JSON for creating/updating the interface
// ─────────────────────────────────────────────────────────────────────────────

/// Single request body for POST and PUT.
/// `type` defines the variant; the remaining fields are by type.
#[derive(Debug, Deserialize)]
struct InterfaceRequest {
    /// The interface name is the key in the `[interfaces]` section.
    name: String,

    #[serde(rename = "type")]
    iface_type: String,

    // TCPClientInterface
    target_host: Option<String>,
    target_port: Option<u16>,
    connect_timeout: Option<u64>,
    max_reconnect_tries: Option<u64>,
    fixed_mtu: Option<u32>,

    // TCPServerInterface
    listen_ip: Option<String>,
    listen_port: Option<u16>,
    prefer_ipv6: Option<bool>,
    device: Option<String>,

    // Shared
    kiss_framing: Option<bool>,
    interface_mode: Option<String>,
}

impl InterfaceRequest {
    /// Build `ConfigSection` from the request body to run through
    /// `synthesize_interface` with the same validation as during regular parsing.
    fn to_config_section(&self) -> ConfigSection {
        let mut s = ConfigSection::new();
        s.set("type", &self.iface_type);
        s.set("enabled", "Yes");

        if let Some(ref v) = self.target_host {
            s.set("target_host", v);
        }
        if let Some(v) = self.target_port {
            s.set("target_port", &v.to_string());
        }
        if let Some(v) = self.connect_timeout {
            s.set("connect_timeout", &v.to_string());
        }
        if let Some(v) = self.max_reconnect_tries {
            s.set("max_reconnect_tries", &v.to_string());
        }
        if let Some(v) = self.fixed_mtu {
            s.set("fixed_mtu", &v.to_string());
        }
        if let Some(ref v) = self.listen_ip {
            s.set("listen_ip", v);
        }
        if let Some(v) = self.listen_port {
            s.set("listen_port", &v.to_string());
        }
        if let Some(v) = self.prefer_ipv6 {
            s.set("prefer_ipv6", if v { "Yes" } else { "No" });
        }
        if let Some(ref v) = self.device {
            s.set("device", v);
        }
        if let Some(v) = self.kiss_framing {
            s.set("kiss_framing", if v { "Yes" } else { "No" });
        }
        if let Some(ref v) = self.interface_mode {
            s.set("interface_mode", v);
        }
        s
    }

    /// Validate and build `InterfaceConfig` via `synthesize_interface`.
    fn synthesize(&self) -> Result<InterfaceConfig, ApiError> {
        let section = self.to_config_section();
        synthesize_interface(&self.name, &section).map_err(|e| ApiError::bad(format!("{e}")))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Config change + interface restart
// ─────────────────────────────────────────────────────────────────────────────

/// Apply interface change:
/// 1. Write the new section to the config file (or delete it).
/// 2. Stop the old interface at runtime (if `old_id` is specified).
/// 3. Start the new interface at runtime (if `new_config` is specified).
///
/// Returns the ID of the new interface (or 0 if deleting).
async fn apply_interface_change(
    s: &AppState,
    iface_name: &str,
    new_section: Option<ConfigSection>, // None = remove from config
    old_id: Option<u64>,                // None = there was no new interface
    new_config: Option<&InterfaceConfig>, // None = deletion only
) -> ApiResult<u64> {
    // ── 1. Конфиг ──────────────────────────────────────────────────────────
    let mut config = s.load_config()?;
    let interfaces_section = config.ensure_section("interfaces");

    match new_section {
        Some(section) => {
            // Replace or add the [[iface_name]] subsection.
            interfaces_section.remove_subsection(iface_name);
            let target = interfaces_section.add_subsection(iface_name.to_string());
            *target = section;
        }
        None => {
            // Remove
            if !interfaces_section.remove_subsection(iface_name) {
                return Err(ApiError::NotFound);
            }
        }
    }
    s.save_config(&config)?;

    // ── 2. Teardown ─────────────────────────────────────────────────────────
    if let Some(id) = old_id {
        teardown_interface(&s.handle, id).await;
    }

    // ── 3. Spawn ─────────────────────────────────────────────────────────────
    let new_id = match new_config {
        Some(iface_config) => spawn_from_config(s, iface_config).await?,
        None => 0,
    };

    Ok(new_id)
}

/// Start the interface from `InterfaceConfig`.
/// Uses `spawn_interface_from_config` — the same path as when starting the daemon:
/// post_init, announce rates, and ingress defaults are read from the config on disk.
async fn spawn_from_config(s: &AppState, iface_config: &InterfaceConfig) -> ApiResult<u64> {
    crate::reticulum::spawn_interface_from_config(&s.handle, iface_config)
        .await
        .map_err(|e| ApiError::internal(format!("failed to spawn interface: {e}")))
}

fn interface_type_name(c: &InterfaceConfig) -> &'static str {
    match c {
        InterfaceConfig::TcpClient(_) => "TCPClientInterface",
        InterfaceConfig::TcpServer(_) => "TCPServerInterface",
        InterfaceConfig::Udp(_) => "UDPInterface",
        InterfaceConfig::Auto(_) => "AutoInterface",
        InterfaceConfig::Local(_) => "LocalInterface",
        InterfaceConfig::I2P(_) => "I2PInterface",
        InterfaceConfig::Pipe(_) => "PipeInterface",
        InterfaceConfig::Backbone(_) => "BackboneInterface",
        #[cfg(feature = "serial")]
        InterfaceConfig::Serial(_) => "SerialInterface",
        #[cfg(feature = "serial")]
        InterfaceConfig::KissSerial(_) => "KISSInterface",
        #[cfg(feature = "serial")]
        InterfaceConfig::RNodeMulti(_) => "RNodeMultiInterface",
        #[cfg(feature = "serial")]
        InterfaceConfig::AX25KISS(_) => "AX25KISSInterface",
        #[cfg(any(feature = "serial", feature = "rnode-tcp"))]
        InterfaceConfig::RNode(_) => "RNodeInterface",
        #[cfg(feature = "ble")]
        InterfaceConfig::BleRNode(_) => "BleRNodeInterface",
    }
}

/// Find the id of a running interface by name using transport stats.
async fn find_running_id(s: &AppState, name: &str) -> ApiResult<Option<u64>> {
    let stats = fetch_interfaces(s).await?;
    Ok(stats.into_iter().find(|e| e.name == name).map(|e| e.id))
}

// ─────────────────────────────────────────────────────────────────────────────
// Handlers — READ
// ─────────────────────────────────────────────────────────────────────────────

async fn health() -> (StatusCode, Json<Value>) {
    (StatusCode::OK, Json(json!({ "ok": true })))
}

async fn status(State(s): State<AppState>) -> ApiResult<Json<Value>> {
    let stats = fetch_interfaces(&s).await?;
    let configs = load_interface_configs(&s)?;
    let total_rx: u64 = stats.iter().map(|e| e.rx_bytes).sum();
    let total_tx: u64 = stats.iter().map(|e| e.tx_bytes).sum();
    let online = stats.iter().filter(|e| e.online).count();
    Ok(Json(json!({
        "interfaces_total":  stats.len(),
        "interfaces_online": online,
        "rx_bytes_total":    total_rx,
        "tx_bytes_total":    total_tx,
        "interfaces":        stats.iter().map(|e| merge_iface_json(e, configs.get(e.name.as_str()))).collect::<Vec<_>>(),
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
    let stats = fetch_interfaces(&s).await?;
    let configs = load_interface_configs(&s)?;
    let show_all = q.all.unwrap_or(false);
    let entries: Vec<_> = stats
        .iter()
        .filter(|e| show_all || visible_by_default(&e.name))
        .filter(|e| {
            q.filter
                .as_deref()
                .map_or(true, |f| e.name.to_lowercase().contains(&f.to_lowercase()))
        })
        .map(|e| merge_iface_json(e, configs.get(e.name.as_str())))
        .collect();
    Ok(Json(json!({ "interfaces": entries })))
}

async fn interface_by_id(State(s): State<AppState>, Path(id): Path<u64>) -> ApiResult<Json<Value>> {
    let stats = fetch_interfaces(&s).await?;
    let configs = load_interface_configs(&s)?;
    stats
        .iter()
        .find(|e| e.id == id)
        .map(|e| Json(merge_iface_json(e, configs.get(e.name.as_str()))))
        .ok_or(ApiError::NotFound)
}

#[derive(Deserialize)]
struct PathsQuery {
    max_hops: Option<u8>,
}

async fn paths(State(s): State<AppState>, Query(q): Query<PathsQuery>) -> ApiResult<Json<Value>> {
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
        other => Err(ApiError::internal(format!("unexpected: {other:?}"))),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Handlers — WRITE
// ─────────────────────────────────────────────────────────────────────────────

/// `POST /api/v1/interfaces` — add a new interface.
///
/// Returns `201 Created` with `{ "id": N, "name": "..." }`.
/// Name conflict → `409 Conflict`.
async fn create_interface(
    State(s): State<AppState>,
    Json(req): Json<InterfaceRequest>,
) -> ApiResult<Response> {
    // We check whether there is already an interface with this name at runtime.
    if find_running_id(&s, &req.name).await?.is_some() {
        return Err(ApiError::Conflict(format!(
            "interface '{}' already exists",
            req.name
        )));
    }

    // Validation via synthesize_interface
    let iface_config = req.synthesize()?;

    // Section for writing to the config — we build from req, not from InterfaceConfig,
    // to save only what was received (without defaults).
    let section = req.to_config_section();

    let id =
        apply_interface_change(&s, &req.name, Some(section), None, Some(&iface_config)).await?;

    let body = Json(json!({ "id": id, "name": req.name }));
    Ok((StatusCode::CREATED, body).into_response())
}

/// `PUT /api/v1/interfaces/{id}` — replace the interface configuration.
///
/// Teardowns the old interface and spawns a new one with new parameters.
/// The interface name is taken from the request body; the id is used only to find
/// the currently running interface.
async fn update_interface(
    State(s): State<AppState>,
    Path(id): Path<u64>,
    Json(req): Json<InterfaceRequest>,
) -> ApiResult<Json<Value>> {
    // Find the old interface by id to know its name for deleting from the config.
    let ifaces = fetch_interfaces(&s).await?;
    let old_entry = ifaces
        .iter()
        .find(|e| e.id == id)
        .ok_or(ApiError::NotFound)?;
    let old_name = old_entry.name.clone();

    let iface_config = req.synthesize()?;
    let section = req.to_config_section();

    // If the name has changed, delete the old entry from the config.
    if old_name != req.name {
        let mut config = s.load_config()?;
        config
            .ensure_section("interfaces")
            .remove_subsection(&old_name);
        s.save_config(&config)?;
    }

    let new_id =
        apply_interface_change(&s, &req.name, Some(section), Some(id), Some(&iface_config)).await?;

    Ok(Json(
        json!({ "id": new_id, "name": req.name, "old_id": id }),
    ))
}

/// `DELETE /api/v1/interfaces/{id}` — stop and delete the interface.
async fn delete_interface(
    State(s): State<AppState>,
    Path(id): Path<u64>,
) -> ApiResult<Json<Value>> {
    // find a name by id
    let ifaces = fetch_interfaces(&s).await?;
    let entry = ifaces
        .iter()
        .find(|e| e.id == id)
        .ok_or(ApiError::NotFound)?;
    let name = entry.name.clone();

    apply_interface_change(&s, &name, None, Some(id), None).await?;

    Ok(Json(json!({ "deleted": true, "id": id, "name": name })))
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

async fn fetch_interfaces(s: &AppState) -> ApiResult<Vec<InterfaceStatRpcEntry>> {
    match s.query(TransportQuery::GetInterfaceStats).await? {
        TransportQueryResponse::InterfaceStats(v) => Ok(v),
        TransportQueryResponse::Error(e) => Err(ApiError::internal(e)),
        other => Err(ApiError::internal(format!("unexpected: {other:?}"))),
    }
}

/// Runtime stats + configuration, combined into a single object.
///
/// `config` will be `None` for interfaces that exist at runtime but are missing
/// in the config (LocalInterface, child TCP clients of servers, etc.).
fn merge_iface_json(e: &InterfaceStatRpcEntry, config: Option<&InterfaceConfig>) -> Value {
    let mut v = json!({
        // ── identity ──────────────────────────────────────────────────
        "id":                           e.id,
        "name":                         e.name,
        // ── runtime status ────────────────────────────────────────────
        "online":                       e.online,
        "mode":                         e.mode,
        "role":                         e.role,
        "bitrate":                      e.bitrate,
        "mtu":                          e.mtu,
        "ifac_size":                    e.ifac_size,
        "clients":                      e.clients,
        // ── traffic counters ──────────────────────────────────────────
        "rx_bytes":                     e.rx_bytes,
        "tx_bytes":                     e.tx_bytes,
        "rx_rate":                      e.rx_rate,
        "tx_rate":                      e.tx_rate,
        "tx_drops":                     e.tx_drops,
        // ── announce / ingress ────────────────────────────────────────
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
        // ── config (null when not in config file) ─────────────────────
        "config":                       Value::Null,
    });

    if let Some(cfg) = config {
        v["config"] = iface_config_json(cfg);
    }
    v
}

/// Serialize `InterfaceConfig` to JSON with full settings.
/// Only fields specific to this type.
fn iface_config_json(cfg: &InterfaceConfig) -> Value {
    match cfg {
        InterfaceConfig::TcpClient(c) => json!({
            "type":                "TCPClientInterface",
            "target_host":         c.target_host,
            "target_port":         c.target_port,
            "interface_mode":      mode_to_str(c.mode),
            "kiss_framing":        c.kiss_framing,
            "connect_timeout":     c.connect_timeout_secs,
            "max_reconnect_tries": c.max_reconnect_tries,
            "fixed_mtu":           c.fixed_mtu,
        }),
        InterfaceConfig::TcpServer(c) => json!({
            "type":           "TCPServerInterface",
            "listen_ip":      c.listen_ip,
            "listen_port":    c.listen_port,
            "interface_mode": mode_to_str(c.mode),
            "kiss_framing":   c.kiss_framing,
            "prefer_ipv6":    c.prefer_ipv6,
            "device":         c.device,
        }),
        // The remaining types return only the type - it is expanded by analogy.
        other => json!({ "type": interface_type_name(other) }),
    }
}

fn mode_to_str(mode: rns_interface::traits::InterfaceMode) -> &'static str {
    use rns_interface::traits::InterfaceMode::*;
    match mode {
        Full => "Full",
        PointToPoint => "PointToPoint",
        AccessPoint => "AccessPoint",
        Roaming => "Roaming",
        Boundary => "Boundary",
        Gateway => "Gateway",
    }
}

/// Load all interfaces from the config and return the HashMap name → InterfaceConfig.
fn load_interface_configs(
    s: &AppState,
) -> ApiResult<std::collections::HashMap<String, InterfaceConfig>> {
    let config = s.load_config()?;
    let mut map = std::collections::HashMap::new();
    for (name, section) in config.subsections("interfaces") {
        match synthesize_interface(name, section) {
            Ok(cfg) => {
                map.insert(name.to_string(), cfg);
            }
            Err(_) => {} // disabled or unknown type - just skip
        }
    }
    Ok(map)
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

fn visible_by_default(name: &str) -> bool {
    !(name.starts_with("LocalInterface[")
        || name.starts_with("TCPInterface[Client")
        || name.starts_with("BackboneInterface[Client on")
        || name.starts_with("AutoInterfacePeer[")
        || name.starts_with("WeaveInterfacePeer[")
        || name.starts_with("I2PInterfacePeer[Connected peer"))
}
