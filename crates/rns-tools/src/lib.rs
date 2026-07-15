//! Shared utility code for Reticulum CLI tools.

pub mod format;
pub mod hash;

/// rsReticulum package version printed by CLI `--version` output.
pub const RS_RETICULUM_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Python Reticulum version these tools track for CLI/protocol parity.
pub const RETICULUM_COMPAT_VERSION: &str = "1.2.5";

/// Python 1.3.2 `[logging] logtimestamps` (Reticulum.py:459-461,
/// RNS/__init__.py:85 default True): whether log lines carry a timestamp
/// prefix. Read pre-init from the config file, like the loglevel.
pub fn config_log_timestamps(config_dir: &std::path::Path) -> bool {
    rns_runtime::config::Config::from_file(&config_dir.join("config"))
        .ok()
        .and_then(|config| config.section("logging")?.get_bool("logtimestamps"))
        .unwrap_or(true)
}

/// Shared tracing-subscriber setup for the CLI binaries; omits the timestamp
/// field when `logtimestamps` is disabled (Python RNS.log parity).
pub fn init_tracing<W>(level: tracing::Level, timestamps: bool, ansi: bool, writer: W)
where
    W: for<'a> tracing_subscriber::fmt::MakeWriter<'a> + Send + Sync + 'static,
{
    let builder = tracing_subscriber::fmt()
        .with_max_level(level)
        .with_ansi(ansi)
        .with_writer(writer);
    if timestamps {
        let _ = builder.try_init();
    } else {
        let _ = builder.without_time().try_init();
    }
}
