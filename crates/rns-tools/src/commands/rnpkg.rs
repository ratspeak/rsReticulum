//! rnpkg-rs — Reticulum Meta Package Manager (RNS/Utilities/rnpkg.py): starts Reticulum and exits 0.

use clap::Parser;

use rns_runtime::lifecycle::ShutdownSignal;
use rns_tools::RS_RETICULUM_VERSION;

/// `__example_rnpkg_config__` (rnpkg.py:76-77).
const EXAMPLE_CONFIG: &str = "# This is an example package manager configuration file.\n";

#[derive(Parser)]
#[command(
    name = "rnpkg-rs",
    about = "Reticulum Meta Package Manager",
    disable_version_flag = true
)]
struct Args {
    /// path to alternative Reticulum config directory
    #[arg(long)]
    config: Option<String>,
    #[arg(short = 'v', long = "verbose", action = clap::ArgAction::Count)]
    verbose: u8,
    #[arg(short = 'q', long = "quiet", action = clap::ArgAction::Count)]
    quiet: u8,
    /// print verbose configuration example to stdout and exit
    #[arg(long)]
    exampleconfig: bool,
    /// print version and exit
    #[arg(long)]
    version: bool,
}

#[tokio::main]
pub(crate) async fn main() {
    let args = Args::parse();
    if args.version {
        println!("rnpkg-rs {RS_RETICULUM_VERSION}");
        return;
    }
    if args.exampleconfig {
        println!("{EXAMPLE_CONFIG}");
        return;
    }
    let config_dir = rns_runtime::platform::resolve_config_dir(args.config.as_deref());
    let configured = rns_runtime::config::Config::from_file(&config_dir.join("config"))
        .ok()
        .and_then(|c| c.section("logging")?.get_int("loglevel"));
    let level = rns_tools::Utility::Rnpkg.loglevel(configured, args.verbose, args.quiet, false);
    rns_tools::init_tracing(
        level,
        rns_tools::config_log_timestamps(&config_dir),
        true,
        std::io::stdout,
    );
    let foreground = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
    match rns_runtime::reticulum::init(
        args.config.as_deref(),
        None,
        ShutdownSignal::new(),
        foreground,
    )
    .await
    {
        Ok(handle) => rns_tools::exit(&handle, 0).await,
        Err(e) => {
            eprintln!("failed to start reticulum: {e}");
            std::process::exit(1);
        }
    }
}
