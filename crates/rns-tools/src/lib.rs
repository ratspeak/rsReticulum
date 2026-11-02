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

/// Attempt to install the CLI's global tracing subscriber with the supplied
/// level, timestamp, ANSI and writer settings. A false `timestamps` omits the
/// time field. Initialization failure is ignored, so an existing global
/// subscriber is left in place.
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
