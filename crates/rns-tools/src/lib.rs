//! Shared utility code for Reticulum CLI tools.

pub mod format;
pub mod hash;
pub mod rnx;
pub mod rsg;

use std::time::Duration;

use rns_runtime::reticulum::{InstanceMode, ReticulumHandle, SharedInstanceRpcEndpoint};
use rns_runtime::rpc::{RpcRequest, RpcResponse};

/// rsReticulum package version printed by CLI `--version` output.
pub const RS_RETICULUM_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Python compatibility-baseline label used by selected CLI surfaces,
/// including the `rnsd-rs` interactive console. It is distinct from this
/// package's release version and is not a Python installation requirement.
pub const RETICULUM_COMPAT_VERSION: &str = "1.4.2";

/// Read `[logging] logtimestamps` from `<config_dir>/config` before tracing
/// initialization. Returns true when the file cannot be read/parsed or the
/// setting is absent or not a recognized boolean.
pub fn config_log_timestamps(config_dir: &std::path::Path) -> bool {
    rns_runtime::config::Config::from_file(&config_dir.join("config"))
        .ok()
        .and_then(|config| config.section("logging")?.get_bool("logtimestamps"))
        .unwrap_or(true)
}

/// Target of the events Python logs at `LOG_PATHING`.
pub const PATHING_TARGET: &str = "rns::pathing";

/// Target of the events Python logs at `LOG_NOTICE` (`rns_transport::notice!`).
pub const NOTICE_TARGET: &str = "rns::notice";

/// Python RNS log levels (`RNS/__init__.py` `LOG_CRITICAL`..`LOG_EXTREME`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum LogLevel {
    Critical = 0,
    Error = 1,
    Warning = 2,
    Notice = 3,
    Info = 4,
    Verbose = 5,
    Debug = 6,
    Pathing = 7,
    Extreme = 8,
}

impl LogLevel {
    const ALL: [LogLevel; 9] = [
        LogLevel::Critical,
        LogLevel::Error,
        LogLevel::Warning,
        LogLevel::Notice,
        LogLevel::Info,
        LogLevel::Verbose,
        LogLevel::Debug,
        LogLevel::Pathing,
        LogLevel::Extreme,
    ];

    /// The level for `level`, clamped to 0..=8 as `Reticulum.__init__` does.
    pub fn clamped(level: i64) -> Self {
        Self::ALL[level.clamp(0, 8) as usize]
    }

    pub fn number(self) -> i32 {
        self as i32
    }

    /// Python `loglevelname()` without brackets and padding.
    pub fn name(self) -> &'static str {
        match self {
            LogLevel::Critical => "Critical",
            LogLevel::Error => "Error",
            LogLevel::Warning => "Warning",
            LogLevel::Notice => "Notice",
            LogLevel::Info => "Info",
            LogLevel::Verbose => "Verbose",
            LogLevel::Debug => "Debug",
            LogLevel::Pathing => "Pathing",
            LogLevel::Extreme => "Extra",
        }
    }

    /// Tracing filter for this level: `Notice` shows only the [`NOTICE_TARGET`]
    /// info events, `Info` adds every other info event, `Pathing` adds the
    /// [`PATHING_TARGET`] debug events to `Debug`, and only `Extreme` enables
    /// trace events.
    pub fn filter(self) -> tracing_subscriber::filter::Targets {
        use tracing_subscriber::filter::{LevelFilter, Targets};
        let default = match self {
            LogLevel::Critical | LogLevel::Error => LevelFilter::ERROR,
            LogLevel::Warning | LogLevel::Notice => LevelFilter::WARN,
            LogLevel::Info => LevelFilter::INFO,
            LogLevel::Verbose | LogLevel::Debug | LogLevel::Pathing => LevelFilter::DEBUG,
            LogLevel::Extreme => LevelFilter::TRACE,
        };
        let pathing = if self >= LogLevel::Pathing {
            default
        } else {
            LevelFilter::OFF
        };
        let notice = if self >= LogLevel::Notice {
            default.max(LevelFilter::INFO)
        } else {
            default
        };
        Targets::new()
            .with_default(default)
            .with_target(PATHING_TARGET, pathing)
            .with_target(NOTICE_TARGET, notice)
    }
}

/// The utilities whose log level follows their upstream counterpart.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Utility {
    Rnsd,
    Rnstatus,
    Rnpath,
    Rnprobe,
    Rncp,
    Rnid,
    Rnsh,
    Lxmd,
    Rnx,
    Rnir,
    Rnpkg,
}

impl Utility {
    /// The level the upstream utility runs at. `configured` is the
    /// `[logging] loglevel` key, which only rnsd and lxmd (its own config)
    /// read; the other utilities pass an explicit level to `RNS.Reticulum`.
    /// rnsd ignores `-v`/`-q` in service mode and stays at Notice without a
    /// `loglevel` key; lxmd starts at Notice without one and always applies
    /// the flags.
    pub fn loglevel(
        self,
        configured: Option<i64>,
        verbose: u8,
        quiet: u8,
        service: bool,
    ) -> LogLevel {
        let delta = i64::from(verbose) - i64::from(quiet);
        let level = match self {
            Utility::Rnsd => match configured {
                Some(level) if service => level,
                Some(level) => level.saturating_add(delta),
                None => LogLevel::Notice as i64,
            },
            Utility::Lxmd => configured
                .unwrap_or(LogLevel::Notice as i64)
                .saturating_add(delta),
            // rnir and rnpkg pass `verbosity`, which only offsets a configured loglevel.
            Utility::Rnir | Utility::Rnpkg => {
                configured.map_or(LogLevel::Notice as i64, |level| level.saturating_add(delta))
            }
            Utility::Rnprobe => 2 + delta,
            Utility::Rnstatus | Utility::Rnpath | Utility::Rncp | Utility::Rnx => 3 + delta,
            Utility::Rnid | Utility::Rnsh => 4 + delta,
        };
        LogLevel::clamped(level)
    }
}

/// Attempt to install the CLI's global tracing subscriber with the supplied
/// level, timestamp, ANSI and writer settings. A false `timestamps` omits the
/// time field. Initialization failure is ignored, so an existing global
/// subscriber is left in place.
pub fn init_tracing<W>(level: LogLevel, timestamps: bool, ansi: bool, writer: W)
where
    W: for<'a> tracing_subscriber::fmt::MakeWriter<'a> + Send + Sync + 'static,
{
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;
    let layer = tracing_subscriber::fmt::layer()
        .with_ansi(ansi)
        .with_writer(writer);
    let registry = tracing_subscriber::registry().with(level.filter());
    let _ = if timestamps {
        registry.with(layer).try_init()
    } else {
        registry.with(layer.without_time()).try_init()
    };
}

/// The line rnstatus and rnpath print for a remote link's `teardown_reason`,
/// none for a local close (rnstatus.py:87-100, rnpath.py:62-76).
pub fn link_closed_text(reason: Option<rns_runtime::prelude::CloseReason>) -> Option<&'static str> {
    use rns_runtime::prelude::CloseReason;
    match reason {
        Some(CloseReason::InitiatorClosed) => None,
        Some(CloseReason::Timeout) => Some("The link timed out, exiting now"),
        Some(CloseReason::DestinationClosed) => {
            Some("The link was closed by the server, exiting now")
        }
        _ => Some("Link closed unexpectedly, exiting now"),
    }
}

/// Longest a tool waits for its runtime to shut down before exiting.
const EXIT_SHUTDOWN_DEADLINE: Duration = Duration::from_secs(10);

/// Shut the runtime down as Python's exit handler does before the process
/// ends (Reticulum.py:186-195): a shared-instance client first deregisters its
/// destination types, so no registration outlives the tool run.
pub async fn shut_down(handle: &ReticulumHandle) {
    let _ = tokio::time::timeout(EXIT_SHUTDOWN_DEADLINE, handle.shutdown_and_wait()).await;
}

/// [`shut_down`], then exit the process with `code`.
pub async fn exit(handle: &ReticulumHandle, code: i32) -> ! {
    shut_down(handle).await;
    std::process::exit(code)
}

/// Destination types a tool that talks to the shared instance over RPC alone
/// registers there, with its own requester hash, as upstream's tools do
/// through `Reticulum.wants_destination_type` (Reticulum.py:2224-2267).
pub struct RpcRegistration {
    endpoint: SharedInstanceRpcEndpoint,
    rpc_key: Vec<u8>,
    requester: [u8; 16],
    timeout: Duration,
}

impl RpcRegistration {
    /// Register `full_names`. Failures are ignored, as upstream ignores them.
    pub async fn want(
        endpoint: SharedInstanceRpcEndpoint,
        rpc_key: Vec<u8>,
        full_names: &[&str],
        timeout: Duration,
    ) -> Self {
        let registration = Self {
            endpoint,
            rpc_key,
            requester: rns_identity::identity::Identity::new().hash,
            timeout,
        };
        for full_name in full_names {
            registration
                .request(&RpcRequest::WantsDestinationType {
                    full_name: (*full_name).to_string(),
                    requester: registration.requester.to_vec(),
                    signature: None,
                })
                .await;
        }
        registration
    }

    /// Deregister every type, as the exit handler's `unwants_all_destination_types`.
    pub async fn release(self) {
        self.request(&RpcRequest::UnwantsAllDestinationTypes {
            requester: self.requester.to_vec(),
            signature: None,
        })
        .await;
    }

    async fn request(&self, request: &RpcRequest) {
        let result = match &self.endpoint {
            SharedInstanceRpcEndpoint::Tcp(port) => {
                rns_runtime::rpc::connect_and_request(*port, &self.rpc_key, request, self.timeout)
                    .await
            }
            SharedInstanceRpcEndpoint::Unix(path) => {
                rns_runtime::rpc::connect_unix_and_request(
                    path,
                    &self.rpc_key,
                    request,
                    self.timeout,
                )
                .await
            }
        };
        if let Err(error) = result {
            tracing::debug!(%error, "shared instance RPC failed while setting destination type filters");
        }
    }
}

/// Reticulum.get_medium_path_timeout (Reticulum.py:2011-2029): ask the shared
/// instance, or compute Transport.medium_path_timeout (Transport.py:3550-3553)
/// from the lowest online interface bitrate. 0 when unknown or on error.
pub async fn medium_path_timeout(handle: &ReticulumHandle) -> f64 {
    if handle.instance_mode == InstanceMode::Client {
        let Some(rpc_key) = handle.config.rpc_key.as_deref() else {
            return 0.0;
        };
        let request = RpcRequest::GetMediumPathTimeout;
        let timeout = Duration::from_secs(5);
        let response = match handle.config.shared_rpc_endpoint(&handle.socket_base) {
            SharedInstanceRpcEndpoint::Tcp(port) => {
                rns_runtime::rpc::connect_and_request(port, rpc_key, &request, timeout).await
            }
            SharedInstanceRpcEndpoint::Unix(path) => {
                rns_runtime::rpc::connect_unix_and_request(&path, rpc_key, &request, timeout).await
            }
        };
        return match response {
            Ok(RpcResponse::FloatResult(Some(v))) if v.is_finite() => v,
            _ => 0.0,
        };
    }
    let lowest = match handle
        .query_transport(rns_transport::messages::TransportQuery::GetInterfaceStats)
        .await
    {
        Some(rns_transport::messages::TransportQueryResponse::InterfaceStats(entries)) => entries
            .iter()
            .filter(|entry| entry.online && entry.bitrate > 0)
            .map(|entry| entry.bitrate)
            .min(),
        _ => None,
    };
    match lowest {
        Some(bitrate) => {
            let bits = (rns_wire::constants::MTU * 8) as f64;
            2.0 * (bits / bitrate.max(rns_runtime::constants::MINIMUM_BITRATE) as f64)
                + rns_wire::constants::DEFAULT_PER_HOP_TIMEOUT
        }
        None => 0.0,
    }
}
