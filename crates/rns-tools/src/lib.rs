//! Shared utility code for Reticulum CLI tools.

pub mod format;
pub mod hash;

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
            Utility::Rnprobe => 2 + delta,
            Utility::Rnstatus | Utility::Rnpath | Utility::Rncp => 3 + delta,
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
