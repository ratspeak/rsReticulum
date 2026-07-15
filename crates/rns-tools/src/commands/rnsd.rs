//! rnsd-rs - Reticulum daemon.

use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, Write};
use std::path::{Path, PathBuf};

use clap::Parser;
use tracing_subscriber::fmt::MakeWriter;

use rns_tools::{RETICULUM_COMPAT_VERSION, RS_RETICULUM_VERSION};
const LOG_ROTATE_BYTES: u64 = 5 * 1024 * 1024;
const RNSD_EXAMPLE_CONFIG: &str = r#"# This is an example Reticulum config file.

[reticulum]
enable_transport = no
share_instance = yes
instance_name = default

# Interval in minutes at which remote blackhole sources
# are updated. Defaults to one hour.
# blackhole_update_interval = 60

# When not running as a transport node, force the same,
# static transport identity at every instance start.
# Defaults to a new identity per start if transport is
# disabled.
# static_transport_identity = no

[logging]
loglevel = 4

# You can disable timestamp inclusion in logs.
# logtimestamps = no

[interfaces]

[[Default Interface]]
type = AutoInterface
enabled = yes

[[UDP Interface]]
type = UDPInterface
enabled = no
listen_ip = 0.0.0.0
listen_port = 4242
forward_ip = 255.255.255.255
forward_port = 4242

[[TCP Server Interface]]
type = TCPServerInterface
enabled = no
listen_ip = 0.0.0.0
listen_port = 4242

[[TCP Client Interface]]
type = TCPClientInterface
enabled = no
target_host = 127.0.0.1
target_port = 4242

[[I2P]]
type = I2PInterface
enabled = no
connectable = yes
peers = ykzlw5ujbaqc2xkec4cpvgyxj257wcrmmgkuxqmqcur7cq3w3lha.b32.i2p

[[RNode LoRa Interface]]
type = RNodeInterface
enabled = no
port = /dev/ttyUSB0
frequency = 867200000
bandwidth = 125000
txpower = 7
spreadingfactor = 8
codingrate = 5
flow_control = false

[[Packet Radio KISS Interface]]
type = KISSInterface
enabled = no
port = /dev/ttyUSB1
speed = 115200
databits = 8
parity = none
stopbits = 1
preamble = 150
txtail = 10
persistence = 200
slottime = 20
flow_control = false

[[Packet Radio AX.25 KISS Interface]]
type = AX25KISSInterface
callsign = NO1CLL
ssid = 0
enabled = no
port = /dev/ttyUSB2
speed = 115200
databits = 8
parity = none
stopbits = 1
flow_control = false
preamble = 150
txtail = 10
persistence = 200
slottime = 20
"#;

#[derive(Parser)]
#[command(
    name = "rnsd-rs",
    about = "Reticulum Network Stack Daemon",
    disable_version_flag = true
)]
struct Args {
    /// Alternative config directory.
    #[arg(long, short = 'c', hide_short_help = true)]
    config: Option<String>,

    /// Increase verbosity.
    #[arg(short = 'v', long, action = clap::ArgAction::Count)]
    verbose: u8,

    /// Decrease verbosity.
    #[arg(short = 'q', long, action = clap::ArgAction::Count)]
    quiet: u8,

    /// Run as service and log to <configdir>/logfile.
    #[arg(short = 's', long)]
    service: bool,

    /// Drop into an interactive shell after initialisation.
    #[arg(short = 'i', long)]
    interactive: bool,

    /// Print verbose configuration example to stdout and exit.
    #[arg(long)]
    exampleconfig: bool,

    /// Print version and exit.
    #[arg(long)]
    version: bool,
}

#[tokio::main]
pub(crate) async fn main() {
    let args = Args::parse();

    if args.version {
        println!("rnsd-rs {RS_RETICULUM_VERSION}");
        return;
    }

    if args.exampleconfig {
        print!("{RNSD_EXAMPLE_CONFIG}");
        return;
    }

    let config_dir = rns_runtime::platform::resolve_config_dir(args.config.as_deref());
    let config_loglevel = read_config_loglevel(&config_dir).unwrap_or(4);
    let verbosity = if args.service {
        config_loglevel
    } else {
        config_loglevel + args.verbose as i32 - args.quiet as i32
    };
    let level = tracing_level(verbosity);
    let log_timestamps = rns_tools::config_log_timestamps(&config_dir);

    if args.service {
        if let Err(e) = fs::create_dir_all(&config_dir) {
            eprintln!(
                "rnsd-rs: failed to create config directory {}: {e}",
                config_dir.display()
            );
            std::process::exit(1);
        }
        let log_path = config_dir.join("logfile");
        if let Err(e) = rotate_log_if_needed(&log_path) {
            eprintln!(
                "rnsd-rs: failed to rotate logfile {}: {e}",
                log_path.display()
            );
            std::process::exit(1);
        }
        rns_tools::init_tracing(level, log_timestamps, false, LogFileWriter::new(log_path));
    } else {
        rns_tools::init_tracing(level, log_timestamps, true, std::io::stdout);
    }

    tracing::info!("rnsd-rs {RS_RETICULUM_VERSION} starting");

    let shutdown = rns_runtime::lifecycle::ShutdownSignal::new();
    let _signal_rx = rns_runtime::lifecycle::install_signal_handlers(shutdown.clone());

    let is_foreground = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
    match rns_runtime::reticulum::init(
        args.config.as_deref(),
        None,
        shutdown.clone(),
        is_foreground,
    )
    .await
    {
        Ok(handle) => {
            tracing::info!("reticulum started in {:?} mode", handle.instance_mode);
            if args.interactive {
                run_interactive_shell(handle.clone()).await;
                shutdown.trigger();
            }

            shutdown.wait().await;
            tracing::info!("rnsd-rs shutting down");
        }
        Err(e) => {
            tracing::error!("failed to start reticulum: {e}");
            std::process::exit(1);
        }
    }
}

async fn run_interactive_shell(handle: rns_runtime::reticulum::ReticulumHandle) {
    let _ = tokio::task::spawn_blocking(move || {
        let stdin = io::stdin();
        let mut stdin = stdin.lock();
        let mut stdout = io::stdout();
        let _ = writeln!(
            stdout,
            "rnsd-rs {RS_RETICULUM_VERSION} interactive console"
        );
        let _ = writeln!(
            stdout,
            "Reticulum instance mode: {:?}",
            handle.instance_mode
        );
        let _ = writeln!(stdout, "Type exit() or press Ctrl-D to return.");

        let mut line = String::new();
        loop {
            line.clear();
            let _ = write!(stdout, ">>> ");
            let _ = stdout.flush();
            match stdin.read_line(&mut line) {
                Ok(0) => {
                    let _ = writeln!(stdout);
                    break;
                }
                Ok(_) => {
                    let trimmed = line.trim();
                    match trimmed {
                        "" => {}
                        "exit()" | "quit()" | "exit" | "quit" => break,
                        "__version__" => {
                            let _ = writeln!(stdout, "{RETICULUM_COMPAT_VERSION:?}");
                        }
                        "reticulum.is_shared_instance" => {
                            let _ = writeln!(
                                stdout,
                                "{}",
                                py_bool(
                                    handle.instance_mode
                                        == rns_runtime::reticulum::InstanceMode::Shared
                                )
                            );
                        }
                        "reticulum.is_connected_to_shared_instance" => {
                            let _ = writeln!(
                                stdout,
                                "{}",
                                py_bool(
                                    handle.instance_mode
                                        == rns_runtime::reticulum::InstanceMode::Client
                                )
                            );
                        }
                        "reticulum.is_standalone_instance" => {
                            let _ = writeln!(
                                stdout,
                                "{}",
                                py_bool(
                                    handle.instance_mode
                                        == rns_runtime::reticulum::InstanceMode::Standalone
                                )
                            );
                        }
                        "reticulum.configdir" => {
                            let _ = writeln!(stdout, "{:?}", handle.config_dir.display().to_string());
                        }
                        "reticulum.local_socket_path" => {
                            let _ = writeln!(stdout, "{:?}", handle.config.instance_name);
                        }
                        "reticulum.rpc_type" => {
                            let rpc_type = if handle.config.shared_instance_type
                                == rns_runtime::reticulum::SharedInstanceType::Unix
                            {
                                "AF_UNIX"
                            } else {
                                "AF_INET"
                            };
                            let _ = writeln!(stdout, "{rpc_type:?}");
                        }
                        "mode" | "instance_mode" => {
                            let _ = writeln!(stdout, "{:?}", handle.instance_mode);
                        }
                        "config" | "config_dir" => {
                            let _ = writeln!(stdout, "{}", handle.config_dir.display());
                        }
                        "help" | "help()" => {
                            let _ = writeln!(
                                stdout,
                                "Available names: __version__, reticulum, mode, instance_mode, config, config_dir, exit()"
                            );
                        }
                        other => {
                            if let Some(inner) =
                                other.strip_prefix("print(").and_then(|s| s.strip_suffix(')'))
                            {
                                write_interactive_print(&mut stdout, &handle, inner.trim());
                            } else {
                                let _ = writeln!(
                                    stdout,
                                    "NameError: name '{}' is not defined",
                                    other.replace('\'', "\\'")
                                );
                            }
                        }
                    }
                }
                Err(e) => {
                    let _ = writeln!(stdout, "I/O error: {e}");
                    break;
                }
            }
        }
    })
    .await;
}

fn py_bool(value: bool) -> &'static str {
    if value { "True" } else { "False" }
}

fn write_interactive_print(
    stdout: &mut io::Stdout,
    handle: &rns_runtime::reticulum::ReticulumHandle,
    expr: &str,
) {
    let value = match expr {
        "__version__" => Some(RETICULUM_COMPAT_VERSION.to_string()),
        "reticulum.is_shared_instance" => Some(
            py_bool(handle.instance_mode == rns_runtime::reticulum::InstanceMode::Shared)
                .to_string(),
        ),
        "reticulum.is_connected_to_shared_instance" => Some(
            py_bool(handle.instance_mode == rns_runtime::reticulum::InstanceMode::Client)
                .to_string(),
        ),
        "reticulum.is_standalone_instance" => Some(
            py_bool(handle.instance_mode == rns_runtime::reticulum::InstanceMode::Standalone)
                .to_string(),
        ),
        _ => parse_string_literal(expr),
    };
    let _ = writeln!(stdout, "{}", value.unwrap_or_else(|| expr.to_string()));
}

fn parse_string_literal(value: &str) -> Option<String> {
    value
        .strip_prefix('"')
        .and_then(|s| s.strip_suffix('"'))
        .or_else(|| value.strip_prefix('\'').and_then(|s| s.strip_suffix('\'')))
        .map(str::to_string)
}

fn read_config_loglevel(config_dir: &Path) -> Option<i32> {
    let config = rns_runtime::config::Config::from_file(&config_dir.join("config")).ok()?;
    let section = config.section("logging")?;
    section.get_int("loglevel").map(|v| v as i32)
}

fn tracing_level(verbosity: i32) -> tracing::Level {
    match verbosity {
        i32::MIN..=1 => tracing::Level::ERROR,
        2 => tracing::Level::WARN,
        3..=4 => tracing::Level::INFO,
        5..=6 => tracing::Level::DEBUG,
        _ => tracing::Level::TRACE,
    }
}

fn rotate_log_if_needed(path: &Path) -> std::io::Result<()> {
    if path.metadata().map(|m| m.len()).unwrap_or(0) < LOG_ROTATE_BYTES {
        return Ok(());
    }
    let rotated = path.with_file_name("logfile.1");
    let _ = fs::remove_file(&rotated);
    fs::rename(path, rotated)
}

#[derive(Clone)]
struct LogFileWriter {
    /// One persistent file handle + in-memory size counter shared across
    /// `make_writer` calls — tracing calls it per event, so per-event opens
    /// and per-write stats would dominate logging cost.
    shared: std::sync::Arc<std::sync::Mutex<RotatingLogFile>>,
}

impl LogFileWriter {
    fn new(path: PathBuf) -> Self {
        Self {
            shared: std::sync::Arc::new(std::sync::Mutex::new(RotatingLogFile {
                path,
                file: None,
                size: 0,
            })),
        }
    }
}

impl<'a> MakeWriter<'a> for LogFileWriter {
    type Writer = SharedLogWriter;

    fn make_writer(&'a self) -> Self::Writer {
        SharedLogWriter(self.shared.clone())
    }
}

/// Per-event writer handle; locks the shared rotating file for each write
/// and falls back to stderr if the logfile cannot be opened.
struct SharedLogWriter(std::sync::Arc<std::sync::Mutex<RotatingLogFile>>);

impl Write for SharedLogWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut inner = self.0.lock().expect("log writer mutex poisoned");
        match inner.write(buf) {
            Ok(n) => Ok(n),
            Err(_) => std::io::stderr().write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        let mut inner = self.0.lock().expect("log writer mutex poisoned");
        match inner.flush() {
            Ok(()) => Ok(()),
            Err(_) => std::io::stderr().flush(),
        }
    }
}

struct RotatingLogFile {
    path: PathBuf,
    file: Option<File>,
    /// Current logfile size, maintained in memory; stat only happens at open.
    size: u64,
}

impl RotatingLogFile {
    fn file_mut(&mut self) -> io::Result<&mut File> {
        if self.file.is_none() {
            let file = OpenOptions::new()
                .create(true)
                .append(true)
                .open(&self.path)?;
            self.size = file.metadata().map(|m| m.len()).unwrap_or(0);
            self.file = Some(file);
        }
        Ok(self.file.as_mut().expect("log file was just opened"))
    }

    fn rotate_if_needed(&mut self) -> io::Result<()> {
        if self.size <= LOG_ROTATE_BYTES {
            return Ok(());
        }

        if let Some(mut file) = self.file.take() {
            file.flush()?;
        }

        let rotated = self.path.with_file_name("logfile.1");
        let _ = fs::remove_file(&rotated);
        match fs::rename(&self.path, &rotated) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }

        self.file = Some(
            OpenOptions::new()
                .create(true)
                .append(true)
                .open(&self.path)?,
        );
        self.size = 0;
        Ok(())
    }
}

impl Write for RotatingLogFile {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let written = self.file_mut()?.write(buf)?;
        self.size += written as u64;
        self.rotate_if_needed()?;
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file_mut()?.flush()
    }
}
