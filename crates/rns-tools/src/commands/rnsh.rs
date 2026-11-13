//! rnsh-rs - Reticulum remote shell utility.

use std::io::{IsTerminal, Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

#[cfg(test)]
use std::collections::HashSet;
#[cfg(test)]
use std::process::{Command as ProcessCommand, Stdio};

use clap::{ArgAction, CommandFactory, Parser};
use rns_identity::destination::{DestType, Destination, Direction};
use rns_identity::identity::Identity;
use rns_runtime::lifecycle::{ShutdownSignal, install_signal_handlers};
use rns_runtime::platform::{StoragePaths, resolve_config_dir};
use rns_runtime::rnsh::{
    RNSH_SOFTWARE_VERSION, RnshClientConfig, RnshClientOutcome, RnshClientProgress, RnshError,
    RnshListenerConfig, RnshWindowSize, rnsh_client_execute, run_rnsh_listener_with_shutdown,
};
use tokio::sync::mpsc;

use rns_tools::RS_RETICULUM_VERSION;

const APP_NAME: &str = "rnsh";
const DEFAULT_SERVICE_NAME: &str = "default";
/// Rust counterpart of upstream's `rnsh` directory name (`~/.config/rnsh`, `~/.rnsh`).
const RNSH_CONFIG_DIR_NAME: &str = "rnsh-rs";
const IDENTITY_HASH_HEX_LEN: usize = 32;

#[derive(Debug, Parser, Clone)]
#[command(
    name = "rnsh-rs",
    about = "Reticulum Remote Shell Utility",
    disable_version_flag = true,
    after_help = "When specifying a command to execute, separate rnsh-rs options from the command and its arguments with --\n\nFor example:\n  rnsh-rs -l -- /bin/bash --login\n  rnsh-rs <destination> -- ls -la /tmp"
)]
struct Args {
    /// path to config directory
    #[arg(short = 'c', long = "config")]
    config: Option<PathBuf>,
    /// path to alternative Reticulum config directory
    #[arg(long = "rnsconfig")]
    rnsconfig: Option<PathBuf>,
    /// path to identity file to use
    #[arg(short = 'i', long = "identity")]
    identity: Option<PathBuf>,
    /// increase verbosity
    #[arg(short = 'v', long = "verbose", action = ArgAction::Count)]
    verbose: u8,
    /// decrease verbosity
    #[arg(short = 'q', long = "quiet", action = ArgAction::Count)]
    quiet: u8,
    /// print identity and destination info and exit
    #[arg(short = 'p', long = "print-identity")]
    print_identity: bool,
    /// show program's version number and exit
    #[arg(long = "version")]
    version: bool,

    /// listen (server) mode; any command specified after -- will be used as the default command when the initiator does not provide one or when remote command execution is disabled; if no command is specified, the default shell of the user running rnsh will be used
    #[arg(short = 'l', long = "listen")]
    listen: bool,
    /// service name for identity file if not the default
    #[arg(short = 's', long = "service")]
    service: Option<String>,
    /// announce on startup and every PERIOD seconds; specify 0 to announce on startup only
    #[arg(
        short = 'b',
        long = "announce",
        value_name = "PERIOD",
        allow_negative_numbers = true
    )]
    announce: Option<i64>,
    /// allow this identity to connect (may be specified multiple times); allowed identities can also be specified in ~/.rnsh-rs/allowed_identities or ~/.config/rnsh-rs/allowed_identities, one hash per line
    #[arg(short = 'a', long = "allowed", value_name = "HASH")]
    allowed: Vec<String>,
    /// disable authentication (allow any identity to connect)
    #[arg(short = 'n', long = "no-auth")]
    no_auth: bool,
    /// concatenate remote command to the argument list of the default program or shell
    #[arg(short = 'A', long = "remote-command-as-args")]
    remote_command_as_args: bool,
    /// disable executing command lines received from the remote initiator
    #[arg(short = 'C', long = "no-remote-command")]
    no_remote_command: bool,

    /// disable identity announcement on connect
    #[arg(short = 'N', long = "no-id")]
    no_id: bool,
    /// return with the exit code of the remote process
    #[arg(short = 'm', long = "mirror")]
    mirror: bool,
    /// connect and request timeout in seconds
    #[arg(
        short = 'w',
        long = "timeout",
        value_name = "SECONDS",
        allow_negative_numbers = true
    )]
    timeout: Option<f64>,

    /// hexadecimal hash of the destination to connect to
    destination: Option<String>,

    /// Command and arguments after --; in listen mode this sets the default command (otherwise the local shell).
    #[arg(last = true)]
    command: Vec<String>,
}

#[tokio::main]
pub(crate) async fn main() -> ExitCode {
    // Upstream main() swallows argparse's SystemExit, so help and usage errors exit 1.
    let args = match Args::try_parse() {
        Ok(args) => args,
        Err(e) => {
            let _ = e.print();
            return ExitCode::from(1);
        }
    };
    run(args).await
}

async fn run(mut args: Args) -> ExitCode {
    if args.version {
        // Upstream labels the rnsh release "protocol" (rnsh/args.py).
        println!(
            "{}",
            rns_tools::version_line(
                "rnsh-rs",
                RS_RETICULUM_VERSION,
                &[("protocol", RNSH_SOFTWARE_VERSION)]
            )
        );
        return ExitCode::SUCCESS;
    }

    if args.listen && args.service.as_deref().is_none_or(str::is_empty) {
        args.service = Some(DEFAULT_SERVICE_NAME.to_string());
    }

    let Some(config_dir) = ensure_config_directory(args.config.as_deref()) else {
        eprintln!("Could not get or create rnsh configuration directory, aborting");
        return ExitCode::from(1);
    };

    if args.print_identity {
        if let Err(e) = print_identity(&args, &config_dir) {
            println!("{e}");
        }
        // Upstream print_identity() ends in exit(0), which main() turns into 1.
        return ExitCode::from(1);
    }

    if args.listen {
        return run_listener(args, config_dir).await;
    }

    if args.destination.is_some() {
        return run_initiator(args, config_dir).await;
    }

    let mut cmd = Args::command();
    println!();
    let _ = cmd.print_help();
    println!();
    ExitCode::from(1)
}

async fn run_listener(args: Args, config_dir: PathBuf) -> ExitCode {
    // Register before any slow init so an early SIGINT exits cleanly.
    let shutdown = ShutdownSignal::new();
    let _signal_rx = install_signal_handlers(shutdown.clone());
    let log = LogDestination::console();
    init_logging(
        args.verbose,
        args.quiet,
        args.rnsconfig.as_deref(),
        log.clone(),
    );
    let service = args.service.clone().unwrap_or_default();
    tracing::info!("Using service name {service}");
    let logfile = config_dir.join("logfile");
    rns_transport::notice!("Logging to {}", logfile.display());

    // The runtime stops only after the listener has sent "Shutting down".
    let runtime_shutdown = ShutdownSignal::new();
    let handle = match start_reticulum(args.rnsconfig.as_deref(), runtime_shutdown.clone()).await {
        Ok(handle) => handle,
        Err(e) => {
            println!("{e}");
            return ExitCode::from(1);
        }
    };
    let paths = StoragePaths::from_config_dir(&handle.config_dir);
    let identity = match prepare_identity(
        args.identity.as_deref(),
        &config_dir,
        Some(&service),
        &paths,
    ) {
        Ok(identity) => identity,
        Err(e) => {
            println!("{e}");
            stop_reticulum(&handle, &runtime_shutdown).await;
            return ExitCode::from(1);
        }
    };
    if let Ok(destination) =
        Destination::new(Some(&identity), Direction::In, DestType::Single, APP_NAME)
    {
        rns_transport::notice!(
            "rnsh listening for commands on <{}>",
            hex::encode(destination.hash)
        );
    }
    log.switch_to_file(logfile);

    let command = listener_default_command(&args.command);
    if args.command.is_empty() {
        tracing::info!("Using {} for default command.", command.join(" "));
    } else {
        tracing::info!("Using command {}", shell_join(&command));
    }

    let allowed = if args.no_auth {
        Vec::new()
    } else {
        match parse_allowed_identities(&args.allowed) {
            Ok(allowed) => allowed,
            Err(e) => {
                tracing::error!("Unhandled error: {e}");
                stop_reticulum(&handle, &runtime_shutdown).await;
                return ExitCode::from(1);
            }
        }
    };
    let allowed_file = config_dir.join("allowed_identities");
    let allowed_identity_files = if allowed_file.is_file() {
        vec![allowed_file]
    } else {
        Vec::new()
    };

    let cfg = RnshListenerConfig {
        identity,
        command,
        allow_all: args.no_auth,
        allowed,
        allowed_identity_files,
        allow_remote_command: !args.no_remote_command,
        remote_command_as_args: args.remote_command_as_args,
        // argparse takes any int; zero or negative announces once at startup.
        announce_period: args.announce.map(|period| period.max(0) as u64),
    };

    let result = run_rnsh_listener_with_shutdown(handle.transport_tx.clone(), cfg, shutdown).await;
    stop_reticulum(&handle, &runtime_shutdown).await;
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            println!("{e}");
            ExitCode::from(1)
        }
    }
}

async fn stop_reticulum(
    handle: &rns_runtime::reticulum::ReticulumHandle,
    runtime_shutdown: &ShutdownSignal,
) {
    runtime_shutdown.trigger();
    rns_tools::shut_down(handle).await;
}

async fn run_initiator(args: Args, config_dir: PathBuf) -> ExitCode {
    // Register before any slow init so an early SIGINT exits cleanly.
    let shutdown = ShutdownSignal::new();
    let _signal_rx = install_signal_handlers(shutdown.clone());

    let destination = match parse_destination(args.destination.as_deref().unwrap_or_default()) {
        Ok(hash) => hash,
        Err(message) => {
            println!("{message}");
            return ExitCode::from(1);
        }
    };

    init_logging(
        args.verbose,
        args.quiet,
        args.rnsconfig.as_deref(),
        LogDestination::file(config_dir.join("logfile.initiator")),
    );

    // The runtime stops only after the session has torn its link down.
    let runtime_shutdown = ShutdownSignal::new();
    let handle = match start_reticulum(args.rnsconfig.as_deref(), runtime_shutdown.clone()).await {
        Ok(handle) => handle,
        Err(e) => {
            println!("{e}");
            return ExitCode::from(1);
        }
    };
    let paths = StoragePaths::from_config_dir(&handle.config_dir);
    let identity = match prepare_identity(args.identity.as_deref(), &config_dir, None, &paths) {
        Ok(identity) => identity,
        Err(e) => {
            println!("{e}");
            stop_reticulum(&handle, &runtime_shutdown).await;
            return ExitCode::from(1);
        }
    };

    let pipe_stdin = !std::io::stdin().is_terminal();
    let pipe_stdout = !std::io::stdout().is_terminal();
    let pipe_stderr = !std::io::stderr().is_terminal();
    let (rows, cols, hpix, vpix) = terminal_window_size();
    let tcflags = terminal_tcflags();
    let _terminal_mode = if pipe_stdin {
        None
    } else {
        enter_raw_stdin_mode()
    };
    let (stdout_tx, stdout_writer) = spawn_output_writer(false);
    let (stderr_tx, stderr_writer) = spawn_output_writer(true);
    let (escape_tx, mut escape_rx) = mpsc::channel::<()>(1);
    let stdin_rx = Some(spawn_stdin_reader(
        (!pipe_stdin).then(|| (escape_tx, stdout_tx.downgrade())),
    ));
    let (terminate_tx, terminate_rx) = tokio::sync::oneshot::channel::<()>();
    let terminate_signal = shutdown.clone();
    let terminate_task = tokio::spawn(async move {
        tokio::select! {
            _ = terminate_signal.wait() => {}
            Some(()) = escape_rx.recv() => {}
        }
        let _ = terminate_tx.send(());
    });
    let window_rx = spawn_window_size_watcher();
    let (progress_tx, progress_rx) = mpsc::unbounded_channel();
    let progress_task = tokio::spawn(report_progress(
        progress_rx,
        destination,
        args.quiet == 0 && !pipe_stdout,
    ));

    let cfg = RnshClientConfig {
        identity,
        destination_hash: destination,
        command: args.command.clone(),
        no_id: args.no_id,
        // Upstream defaults to RNS.Transport.PATH_REQUEST_TIMEOUT.
        timeout: client_timeout(args.timeout.unwrap_or(15.0)),
        stdin_data: Vec::new(),
        stdin_rx,
        stdout_tx: Some(stdout_tx),
        stderr_tx: Some(stderr_tx),
        window_rx,
        pipe_stdin,
        pipe_stdout,
        pipe_stderr,
        term: std::env::var("TERM").ok(),
        rows,
        cols,
        hpix,
        vpix,
        tcflags,
        terminate_rx: Some(terminate_rx),
        progress_tx: Some(progress_tx),
    };

    // initiator.py
    handle.wants_destination_type(APP_NAME).await;
    let result = rnsh_client_execute(handle.transport_tx.clone(), cfg).await;
    terminate_task.abort();
    let _ = progress_task.await;
    stop_reticulum(&handle, &runtime_shutdown).await;
    let writers = finish_output_writers(stdout_writer, stderr_writer).await;
    if result.is_ok()
        && let Err(e) = writers
    {
        println!("Client exception: {e}");
        return ExitCode::from(if args.mirror { 127 } else { 0 });
    }
    let (message, code) = client_exit(&result, &destination, args.mirror);
    if let Some(message) = message {
        println!("{message}");
    }
    ExitCode::from(code)
}

/// Message and exit code for a finished client run, as upstream `initiate()`
/// returns them and `main()` reports them. Setup failures exit 1; codes from
/// the running session only reach the exit status with `-m`.
fn client_exit(
    result: &Result<RnshClientOutcome, RnshError>,
    destination: &[u8; 16],
    mirror: bool,
) -> (Option<String>, u8) {
    let mirrored = |code: u8| if mirror { code } else { 0 };
    let error = match result {
        Ok(outcome) => return (None, remote_exit_code(outcome.return_code, mirror)),
        Err(error) => error,
    };
    match error {
        RnshError::PathTimeout => (Some("Path not found".into()), 1),
        RnshError::Timeout(_)
        | RnshError::HandshakeFailed(_)
        | RnshError::ProofInvalid(_)
        | RnshError::RequestDispatch(_) => (
            Some(format!(
                "Could not establish link with <{}>",
                hex::encode(destination)
            )),
            1,
        ),
        RnshError::Denied(msg) => (Some(format!("Remote error: {msg}")), 1),
        RnshError::ProtocolError => (Some("Protocol error".into()), mirrored(254)),
        RnshError::Remote(msg) => (Some(format!("Remote error: {msg}")), mirrored(255)),
        RnshError::ClientException(msg) => {
            (Some(format!("Client exception: {msg}")), mirrored(127))
        }
        RnshError::LinkClosed(_) | RnshError::Terminated => (None, 0),
        other => (Some(other.to_string()), 1),
    }
}

/// The `-w` budget; argparse's float accepts zero, negatives and infinity.
fn client_timeout(seconds: f64) -> Duration {
    const MAX_TIMEOUT: Duration = Duration::from_secs(100 * 365 * 24 * 3600);
    if seconds > 0.0 {
        Duration::try_from_secs_f64(seconds).map_or(MAX_TIMEOUT, |d| d.min(MAX_TIMEOUT))
    } else {
        Duration::ZERO
    }
}

const SPINNER_SYMBOLS: [char; 7] = ['⢄', '⢂', '⢁', '⡁', '⡈', '⡐', '⡠'];

/// Logs client setup progress and, on a TTY, draws upstream's `_spin_tty` spinner.
async fn report_progress(
    mut rx: mpsc::UnboundedReceiver<RnshClientProgress>,
    destination: [u8; 16],
    spin: bool,
) {
    let hash = format!("<{}>", hex::encode(destination));
    let mut current: Option<String> = None;
    let mut tick = tokio::time::interval(Duration::from_millis(100));
    let mut symbol = 0;
    loop {
        tokio::select! {
            event = rx.recv() => {
                if let Some(message) = current.take() {
                    print!("\r{}  \r", " ".repeat(message.chars().count()));
                    let _ = std::io::stdout().flush();
                }
                let message = match event {
                    Some(RnshClientProgress::RequestingPath) => format!("Requesting path to {hash}"),
                    Some(RnshClientProgress::EstablishingLink) => {
                        format!("Establishing link with {hash}")
                    }
                    Some(RnshClientProgress::LinkEstablished) => {
                        tracing::info!("Link established with {hash}");
                        return;
                    }
                    None => return,
                };
                tracing::info!("{message}");
                if spin {
                    print!("{message}   ");
                    let _ = std::io::stdout().flush();
                    current = Some(message);
                    tick.reset();
                }
            }
            _ = tick.tick(), if current.is_some() => {
                print!("\x08\x08{} ", SPINNER_SYMBOLS[symbol]);
                let _ = std::io::stdout().flush();
                symbol = (symbol + 1) % SPINNER_SYMBOLS.len();
            }
        }
    }
}

async fn start_reticulum(
    config_dir: Option<&Path>,
    shutdown: ShutdownSignal,
) -> Result<rns_runtime::reticulum::ReticulumHandle, rns_runtime::reticulum::ReticulumError> {
    let is_foreground = Arc::new(AtomicBool::new(true));
    let config = config_dir.and_then(|path| path.to_str());
    rns_runtime::reticulum::init(config, None, shutdown, is_foreground).await
}

fn init_logging(verbose: u8, quiet: u8, rns_config_dir: Option<&Path>, writer: LogDestination) {
    let level = rns_tools::Utility::Rnsh.loglevel(None, verbose, quiet, false);
    let resolved = resolve_config_dir(rns_config_dir.and_then(|path| path.to_str()));
    rns_tools::init_tracing(
        level,
        rns_tools::config_log_timestamps(&resolved),
        false,
        writer,
    );
}

/// `RNS.LOG_MAXSIZE`: past this size the logfile moves to `<logfile>.1`.
const LOG_MAXSIZE: u64 = 5 * 1024 * 1024;

/// Where `RNS.log` output goes: the console until a logfile is set, then the
/// file; back to the console for good if the file cannot be written.
#[derive(Clone)]
struct LogDestination(Arc<Mutex<LogTarget>>);

#[derive(Default)]
struct LogTarget {
    path: Option<PathBuf>,
    file: Option<std::fs::File>,
    size: u64,
}

impl LogDestination {
    fn console() -> Self {
        Self(Arc::new(Mutex::new(LogTarget::default())))
    }

    fn file(path: PathBuf) -> Self {
        let destination = Self::console();
        destination.switch_to_file(path);
        destination
    }

    fn switch_to_file(&self, path: PathBuf) {
        let mut target = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        target.path = Some(path);
        target.file = None;
        if target.open().is_err() {
            target.path = None;
        }
    }
}

impl LogTarget {
    fn open(&mut self) -> std::io::Result<&mut std::fs::File> {
        if self.file.is_none() {
            let path = self.path.as_ref().ok_or(std::io::ErrorKind::NotFound)?;
            let file = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)?;
            self.size = file.metadata().map(|m| m.len()).unwrap_or(0);
            self.file = Some(file);
        }
        Ok(self.file.as_mut().expect("log file was just opened"))
    }

    fn append(&mut self, buf: &[u8]) -> std::io::Result<()> {
        self.open()?.write_all(buf)?;
        self.size += buf.len() as u64;
        if self.size > LOG_MAXSIZE
            && let Some(path) = self.path.clone()
        {
            self.file = None;
            let mut rotated = path.clone().into_os_string();
            rotated.push(".1");
            let _ = std::fs::remove_file(&rotated);
            std::fs::rename(&path, &rotated)?;
            self.size = 0;
        }
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for LogDestination {
    type Writer = LogWriter;

    fn make_writer(&'a self) -> Self::Writer {
        LogWriter(self.0.clone())
    }
}

struct LogWriter(Arc<Mutex<LogTarget>>);

impl Write for LogWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let mut target = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        if target.path.is_some() {
            if target.append(buf).is_ok() {
                return Ok(buf.len());
            }
            target.path = None;
            target.file = None;
        }
        drop(target);
        std::io::stderr().write_all(buf)?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn terminal_window_size() -> (Option<u32>, Option<u32>, Option<u32>, Option<u32>) {
    terminal_window_size_for_fds(&[0, 1, 2])
}

#[cfg(unix)]
struct TerminalModeGuard {
    original: nix::libc::termios,
}

#[cfg(unix)]
impl Drop for TerminalModeGuard {
    fn drop(&mut self) {
        unsafe {
            nix::libc::tcsetattr(0, nix::libc::TCSANOW, &self.original);
        }
    }
}

#[cfg(unix)]
fn enter_raw_stdin_mode() -> Option<TerminalModeGuard> {
    let mut original = std::mem::MaybeUninit::<nix::libc::termios>::uninit();
    let rc = unsafe { nix::libc::tcgetattr(0, original.as_mut_ptr()) };
    if rc == -1 {
        return None;
    }
    let original = unsafe { original.assume_init() };
    let mut raw = original;
    unsafe {
        nix::libc::cfmakeraw(&mut raw);
    }
    let rc = unsafe { nix::libc::tcsetattr(0, nix::libc::TCSANOW, &raw) };
    if rc == -1 {
        return None;
    }
    Some(TerminalModeGuard { original })
}

#[cfg(not(unix))]
fn enter_raw_stdin_mode() -> Option<()> {
    None
}

/// Read local stdin on a thread. With `escape` (a TTY), input passes through
/// the rnsh escape filter: local echo goes to the stdout writer and `~.`
/// signals the escape sender.
fn spawn_stdin_reader(
    escape: Option<(mpsc::Sender<()>, mpsc::WeakSender<Vec<u8>>)>,
) -> mpsc::Receiver<Vec<u8>> {
    let (tx, rx) = mpsc::channel(16);
    std::thread::spawn(move || {
        let mut stdin = std::io::stdin();
        let mut buf = [0u8; 4096];
        let mut filter = EscapeFilter::default();
        loop {
            match stdin.read(&mut buf) {
                Ok(0) => {
                    let _ = tx.blocking_send(Vec::new());
                    break;
                }
                Ok(n) => {
                    let data = if let Some((escape_tx, echo_tx)) = escape.as_ref() {
                        let out = filter.process(&buf[..n]);
                        // Weak, so a blocked stdin read never keeps the writer open.
                        if !out.echo.is_empty()
                            && let Some(echo_tx) = echo_tx.upgrade()
                        {
                            let _ = echo_tx.blocking_send(out.echo);
                        }
                        if out.terminate {
                            let _ = escape_tx.blocking_send(());
                        }
                        out.send
                    } else {
                        buf[..n].to_vec()
                    };
                    if !data.is_empty() && tx.blocking_send(data).is_err() {
                        break;
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(_) => {
                    let _ = tx.blocking_send(Vec::new());
                    break;
                }
            }
        }
    });
    rx
}

const ESCAPE_HELP: &str = concat!(
    "\n\r\n\rSupported rnsh escape sequences:",
    "\n\r  ~~  Send the escape character by typing it twice",
    "\n\r  ~.  Terminate session and exit immediately",
    "\n\r  ~L  Toggle line-interactive mode",
    "\n\r  ~?  Display this quick reference\n\r",
    "\n\r(Escape sequences are only recognized immediately after newline)\n\r",
);
const LINE_FLUSH_CHARS: &[u8] = &[
    0x01, 0x03, 0x04, 0x05, 0x0c, 0x11, 0x13, 0x15, 0x19, b'\t', 0x1a, 0x1b,
];

/// Client escape handling from rnsh/initiator.py: `~` right after CR (or at
/// session start) begins an escape; `~L` toggles local line editing.
#[derive(Debug)]
struct EscapeFilter {
    pre_esc: bool,
    esc: bool,
    line_mode: bool,
    line_flush: bool,
    blind_write_count: i64,
    line_buffer: Vec<u8>,
}

impl Default for EscapeFilter {
    fn default() -> Self {
        Self {
            pre_esc: true,
            esc: false,
            line_mode: false,
            line_flush: false,
            blind_write_count: 0,
            line_buffer: Vec::new(),
        }
    }
}

#[derive(Debug, Default, PartialEq, Eq)]
struct EscapeOutput {
    /// Bytes to send to the remote stdin.
    send: Vec<u8>,
    /// Bytes to write to the local terminal.
    echo: Vec<u8>,
    terminate: bool,
}

impl EscapeFilter {
    fn process(&mut self, input: &[u8]) -> EscapeOutput {
        let mut out = EscapeOutput::default();
        let mut data = Vec::new();
        for &b in input {
            if b == b'\r' {
                self.pre_esc = true;
                self.line_flush = true;
                data.push(b);
            } else if self.line_mode && LINE_FLUSH_CHARS.contains(&b) {
                self.pre_esc = false;
                self.line_flush = true;
                data.push(b);
            } else if self.line_mode && (b == 0x08 || b == 0x7f) {
                self.pre_esc = false;
                if self.line_buffer.pop().is_some() {
                    self.blind_write_count -= 1;
                    out.echo.extend_from_slice(b"\x08 \x08");
                }
            } else if self.pre_esc && b == b'~' {
                self.pre_esc = false;
                self.esc = true;
            } else if self.esc {
                match b {
                    b'?' => out.echo.extend_from_slice(ESCAPE_HELP.as_bytes()),
                    b'.' => out.terminate = true,
                    b'L' => {
                        self.line_mode = !self.line_mode;
                        out.echo.extend_from_slice(if self.line_mode {
                            b"\n\rLine-interactive mode enabled\n\r".as_slice()
                        } else {
                            b"\n\rLine-interactive mode disabled\n\r".as_slice()
                        });
                    }
                    b'~' => data.push(b'~'),
                    other => {
                        data.push(b'~');
                        data.push(other);
                    }
                }
                self.esc = false;
            } else {
                self.pre_esc = false;
                data.push(b);
            }
        }

        if !self.line_mode {
            out.send = data;
        } else {
            self.line_buffer.extend_from_slice(&data);
            if self.line_flush {
                out.send = std::mem::take(&mut self.line_buffer);
                for _ in 0..self.blind_write_count.max(0) {
                    out.echo.extend_from_slice(b"\x08 \x08");
                }
                self.line_flush = false;
                self.blind_write_count = 0;
            } else {
                self.blind_write_count += data.len() as i64;
                out.echo.extend_from_slice(&data);
            }
        }
        out
    }
}

fn spawn_output_writer(
    stderr: bool,
) -> (
    mpsc::Sender<Vec<u8>>,
    tokio::task::JoinHandle<Result<(), String>>,
) {
    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(64);
    // Lock per chunk: tracing also writes to stderr and must never wait on this task.
    let task = tokio::task::spawn_blocking(move || {
        while let Some(chunk) = rx.blocking_recv() {
            let (name, result) = if stderr {
                let mut handle = std::io::stderr().lock();
                (
                    "stderr",
                    handle.write_all(&chunk).and_then(|()| handle.flush()),
                )
            } else {
                let mut handle = std::io::stdout().lock();
                (
                    "stdout",
                    handle.write_all(&chunk).and_then(|()| handle.flush()),
                )
            };
            result.map_err(|e| format!("could not write {name}: {e}"))?;
        }
        Ok(())
    });
    (tx, task)
}

async fn finish_output_writers(
    stdout_writer: tokio::task::JoinHandle<Result<(), String>>,
    stderr_writer: tokio::task::JoinHandle<Result<(), String>>,
) -> Result<(), String> {
    let (stdout, stderr) = tokio::join!(stdout_writer, stderr_writer);
    stdout.map_err(|e| format!("stdout writer task failed: {e}"))??;
    stderr.map_err(|e| format!("stderr writer task failed: {e}"))??;
    Ok(())
}

#[cfg(unix)]
fn spawn_window_size_watcher() -> Option<mpsc::Receiver<RnshWindowSize>> {
    let (tx, rx) = mpsc::channel(8);
    tokio::spawn(async move {
        let Ok(mut sigwinch) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::window_change())
        else {
            return;
        };
        while sigwinch.recv().await.is_some() {
            let Some(window) = stdin_window_size() else {
                continue;
            };
            if tx.send(window).await.is_err() {
                break;
            }
        }
    });
    Some(rx)
}

#[cfg(not(unix))]
fn spawn_window_size_watcher() -> Option<mpsc::Receiver<RnshWindowSize>> {
    None
}

/// `tty_get_winsize(0)`, used for window-change updates.
#[cfg(unix)]
fn stdin_window_size() -> Option<RnshWindowSize> {
    let mut winsize = nix::libc::winsize {
        ws_row: 0,
        ws_col: 0,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    let rc = unsafe { nix::libc::ioctl(0, nix::libc::TIOCGWINSZ, &mut winsize) };
    (rc == 0).then_some(RnshWindowSize {
        rows: Some(u32::from(winsize.ws_row)),
        cols: Some(u32::from(winsize.ws_col)),
        hpix: Some(u32::from(winsize.ws_xpixel)),
        vpix: Some(u32::from(winsize.ws_ypixel)),
    })
}

/// `termios.tcgetattr` of the first TTY among fds 0, 1 and 2, in Python's list
/// form `[iflag, oflag, cflag, lflag, ispeed, ospeed, cc]`.
#[cfg(unix)]
fn terminal_tcflags() -> Option<rmpv::Value> {
    use rmpv::Value;
    for fd in [0, 1, 2] {
        let mut attrs = std::mem::MaybeUninit::<nix::libc::termios>::uninit();
        if unsafe { nix::libc::tcgetattr(fd, attrs.as_mut_ptr()) } == -1 {
            continue;
        }
        let attrs = unsafe { attrs.assume_init() };
        let canonical = attrs.c_lflag & nix::libc::ICANON != 0;
        let cc = attrs
            .c_cc
            .iter()
            .enumerate()
            .map(|(index, &value)| {
                // Python returns VMIN/VTIME as ints in non-canonical mode.
                if !canonical && (index == nix::libc::VMIN || index == nix::libc::VTIME) {
                    Value::from(value)
                } else {
                    Value::Binary(vec![value])
                }
            })
            .collect();
        let ispeed = unsafe { nix::libc::cfgetispeed(&attrs) };
        let ospeed = unsafe { nix::libc::cfgetospeed(&attrs) };
        return Some(Value::Array(vec![
            Value::from(attrs.c_iflag),
            Value::from(attrs.c_oflag),
            Value::from(attrs.c_cflag),
            Value::from(attrs.c_lflag),
            Value::from(ispeed),
            Value::from(ospeed),
            Value::Array(cc),
        ]));
    }
    None
}

#[cfg(not(unix))]
fn terminal_tcflags() -> Option<rmpv::Value> {
    None
}

#[cfg(unix)]
fn terminal_window_size_for_fds(
    fds: &[i32],
) -> (Option<u32>, Option<u32>, Option<u32>, Option<u32>) {
    for fd in fds {
        let mut winsize = nix::libc::winsize {
            ws_row: 0,
            ws_col: 0,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        let rc = unsafe { nix::libc::ioctl(*fd, nix::libc::TIOCGWINSZ, &mut winsize) };
        if rc == 0 && (winsize.ws_row != 0 || winsize.ws_col != 0) {
            return (
                Some(u32::from(winsize.ws_row)),
                Some(u32::from(winsize.ws_col)),
                Some(u32::from(winsize.ws_xpixel)),
                Some(u32::from(winsize.ws_ypixel)),
            );
        }
    }
    (None, None, None, None)
}

#[cfg(not(unix))]
fn terminal_window_size_for_fds(
    _fds: &[i32],
) -> (Option<u32>, Option<u32>, Option<u32>, Option<u32>) {
    (None, None, None, None)
}

fn print_identity(args: &Args, config_dir: &Path) -> Result<(), String> {
    let rns_config_dir = resolve_config_dir(args.rnsconfig.as_deref().and_then(Path::to_str));
    let paths = StoragePaths::from_config_dir(&rns_config_dir);
    paths
        .ensure_dirs()
        .map_err(|e| format!("could not prepare Reticulum storage: {e}"))?;

    let service = args
        .service
        .as_deref()
        .filter(|service| !service.is_empty());
    if let Some(service) = service {
        println!("Using service name \"{service}\"");
    }
    let identity = prepare_identity(args.identity.as_deref(), config_dir, service, &paths)?;
    let destination = Destination::new(Some(&identity), Direction::In, DestType::Single, APP_NAME)
        .map_err(|e| format!("could not create rnsh destination: {e}"))?;
    println!("Identity     : <{}>", hex::encode(identity.hash));
    if args.listen {
        println!("Listening on : <{}>", hex::encode(destination.hash));
    }
    Ok(())
}

/// Upstream `ensure_config_directory`: the `-c` directory, else
/// `~/.config/rnsh-rs` if it exists, else `~/.rnsh-rs`, created when missing.
fn ensure_config_directory(explicit: Option<&Path>) -> Option<PathBuf> {
    let home = home_dir();
    let dir = match explicit {
        Some(dir) => expand_user(dir, home.as_deref()),
        None => default_config_dir(home.as_deref().unwrap_or(Path::new(""))),
    };
    if dir.is_dir() {
        return Some(dir);
    }
    std::fs::create_dir_all(&dir).ok()?;
    Some(dir)
}

fn default_config_dir(home: &Path) -> PathBuf {
    let xdg = home.join(".config").join(RNSH_CONFIG_DIR_NAME);
    if xdg.is_dir() {
        xdg
    } else {
        home.join(format!(".{RNSH_CONFIG_DIR_NAME}"))
    }
}

fn home_dir() -> Option<PathBuf> {
    ["HOME", "USERPROFILE"]
        .iter()
        .filter_map(std::env::var_os)
        .find(|home| !home.is_empty())
        .map(PathBuf::from)
}

/// `os.path.expanduser` for `~` and `~/...`.
fn expand_user(path: &Path, home: Option<&Path>) -> PathBuf {
    match (path.strip_prefix("~"), home) {
        (Ok(rest), Some(home)) => home.join(rest),
        _ => path.to_path_buf(),
    }
}

/// Upstream `prepare_identity`, plus a one-time copy of the identity older
/// rnsh-rs releases kept under Reticulum storage, so destination hashes survive.
fn prepare_identity(
    explicit: Option<&Path>,
    config_dir: &Path,
    service: Option<&str>,
    rns_paths: &StoragePaths,
) -> Result<Identity, String> {
    let path = identity_path(explicit, config_dir, service);
    if explicit.is_none() && !path.exists() {
        let legacy = rns_paths
            .identity_dir
            .join(suffixed(APP_NAME, service.unwrap_or("")));
        if legacy.is_file() {
            match std::fs::copy(&legacy, &path) {
                Ok(_) => eprintln!(
                    "Copied rnsh identity {} to {}",
                    legacy.display(),
                    path.display()
                ),
                Err(e) => eprintln!(
                    "Could not copy rnsh identity {} to {}: {e}",
                    legacy.display(),
                    path.display()
                ),
            }
        }
    }
    load_or_create_identity(&path)
}

fn load_or_create_identity(path: &Path) -> Result<Identity, String> {
    if path.is_file() {
        return Identity::from_file(path)
            .map_err(|e| format!("could not load identity {}: {e}", path.display()));
    }

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| {
            format!(
                "could not create identity directory {}: {e}",
                parent.display()
            )
        })?;
    }
    let identity = Identity::new();
    identity
        .to_file(path)
        .map_err(|e| format!("could not write identity {}: {e}", path.display()))?;
    Ok(identity)
}

/// `<configdir>/identity[.<service>]` unless `-i` names a file.
fn identity_path(explicit: Option<&Path>, config_dir: &Path, service: Option<&str>) -> PathBuf {
    match explicit {
        Some(path) => path.to_path_buf(),
        None => config_dir.join(suffixed("identity", service.unwrap_or(""))),
    }
}

fn suffixed(name: &str, service: &str) -> String {
    let service = sanitize_service_name(service);
    if service.is_empty() {
        name.to_string()
    } else {
        format!("{name}.{service}")
    }
}

/// `re.sub(r'\W+', '', service)` on a Unicode string.
fn sanitize_service_name(service: &str) -> String {
    service
        .chars()
        .filter(|c| c.is_alphanumeric() || *c == '_')
        .collect()
}

/// `shlex.join`, for the listener's command notice.
fn shell_join(args: &[String]) -> String {
    args.iter()
        .map(|arg| {
            let safe = |c: char| c.is_ascii_alphanumeric() || "_@%+=:,./-".contains(c);
            if !arg.is_empty() && arg.chars().all(safe) {
                arg.clone()
            } else {
                format!("'{}'", arg.replace('\'', "'\"'\"'"))
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg(test)]
enum LocalProcessMode {
    Pipes,
    Pty,
}

#[cfg(test)]
fn local_process_mode(pipe_stdin: bool, pipe_stdout: bool, pipe_stderr: bool) -> LocalProcessMode {
    if pipe_stdin && pipe_stdout && pipe_stderr {
        LocalProcessMode::Pipes
    } else {
        LocalProcessMode::Pty
    }
}

#[cfg(windows)]
fn env_nonempty(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|value| !value.is_empty())
}

fn default_shell_command() -> Vec<String> {
    #[cfg(windows)]
    let shell = env_nonempty("COMSPEC")
        .or_else(|| env_nonempty("SHELL"))
        .unwrap_or_else(|| "cmd.exe".to_string());

    #[cfg(not(windows))]
    let shell = passwd_shell().unwrap_or_else(|| "/bin/sh".to_string());

    vec![shell]
}

/// Login shell of the current user, as `pwd.getpwuid(os.getuid()).pw_shell`.
#[cfg(unix)]
fn passwd_shell() -> Option<String> {
    let mut pwd = std::mem::MaybeUninit::<nix::libc::passwd>::uninit();
    let mut result: *mut nix::libc::passwd = std::ptr::null_mut();
    let mut buf = vec![0 as nix::libc::c_char; 16384];
    let rc = unsafe {
        nix::libc::getpwuid_r(
            nix::libc::getuid(),
            pwd.as_mut_ptr(),
            buf.as_mut_ptr(),
            buf.len(),
            &mut result,
        )
    };
    if rc != 0 || result.is_null() {
        return None;
    }
    let shell = unsafe { (*result).pw_shell };
    if shell.is_null() {
        return None;
    }
    let shell = unsafe { std::ffi::CStr::from_ptr(shell) }
        .to_string_lossy()
        .into_owned();
    (!shell.is_empty()).then_some(shell)
}

#[cfg(all(not(unix), not(windows)))]
fn passwd_shell() -> Option<String> {
    None
}

fn listener_default_command(command: &[String]) -> Vec<String> {
    if command.is_empty() {
        default_shell_command()
    } else {
        command.to_vec()
    }
}

#[cfg(test)]
fn select_listener_command(
    default_command: &[String],
    remote_command: Option<&[String]>,
    allow_remote_command: bool,
    remote_command_as_args: bool,
) -> Result<Vec<String>, String> {
    let remote_command = remote_command.unwrap_or(&[]);
    let has_remote_command = !remote_command.is_empty();

    if !allow_remote_command && has_remote_command {
        return Err("Remote command line not allowed by listener".to_string());
    }

    if default_command.is_empty() && (!has_remote_command || remote_command_as_args) {
        return Err("no command configured for listener".to_string());
    }

    if remote_command_as_args && has_remote_command {
        let mut command = default_command.to_vec();
        command.extend_from_slice(remote_command);
        return Ok(command);
    }

    if has_remote_command {
        Ok(remote_command.to_vec())
    } else {
        Ok(default_command.to_vec())
    }
}

#[derive(Debug, Clone)]
#[cfg(test)]
struct ListenerAuth {
    allow_all: bool,
    allowed: HashSet<[u8; 16]>,
}

#[cfg(test)]
impl ListenerAuth {
    fn from_flags(no_auth: bool, allowed: &[String]) -> Result<Self, String> {
        let mut parsed = HashSet::new();
        for item in allowed {
            parsed.insert(parse_identity_hash(item)?);
        }
        Ok(Self {
            allow_all: no_auth,
            allowed: parsed,
        })
    }

    fn is_allowed(&self, identity_hash: Option<[u8; 16]>) -> bool {
        self.allow_all
            || identity_hash
                .as_ref()
                .is_some_and(|hash| self.allowed.contains(hash))
    }
}

const DESTINATION_LENGTH_ERROR: &str =
    "Allowed destination length is invalid, must be 32 hexadecimal characters (16 bytes).";
const DESTINATION_HEX_ERROR: &str = "Invalid destination entered. Check your input.";

fn parse_identity_hash(input: &str) -> Result<[u8; 16], String> {
    parse_destination(input).map_err(str::to_string)
}

/// Upstream checks the length first, then the hex digits.
fn parse_destination(input: &str) -> Result<[u8; 16], &'static str> {
    if input.len() != IDENTITY_HASH_HEX_LEN {
        return Err(DESTINATION_LENGTH_ERROR);
    }
    let decoded = hex::decode(input).map_err(|_| DESTINATION_HEX_ERROR)?;
    decoded.try_into().map_err(|_| DESTINATION_HEX_ERROR)
}

fn parse_allowed_identities(values: &[String]) -> Result<Vec<[u8; 16]>, String> {
    values
        .iter()
        .map(|value| parse_identity_hash(value))
        .collect()
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg(test)]
struct LocalProcessResult {
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    return_code: i32,
}

#[cfg(test)]
fn run_local_process_once(
    command: &[String],
    stdin_data: &[u8],
    pipe_stdin: bool,
    pipe_stdout: bool,
    pipe_stderr: bool,
    term: Option<&str>,
    remote_identity_hash: Option<[u8; 16]>,
) -> Result<LocalProcessResult, String> {
    if command.is_empty() {
        return Err("no command specified".to_string());
    }

    match local_process_mode(pipe_stdin, pipe_stdout, pipe_stderr) {
        LocalProcessMode::Pipes => {}
        LocalProcessMode::Pty => {
            return Err("local test helper only supports all-pipe mode".to_string());
        }
    }

    let mut child = ProcessCommand::new(&command[0])
        .args(&command[1..])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env("TERM", term.unwrap_or("xterm"))
        .env(
            "RNS_REMOTE_IDENTITY",
            remote_identity_hash
                .map(|hash| format!("<{}>", hex::encode(hash)))
                .unwrap_or_default(),
        )
        .spawn()
        .map_err(|e| format!("could not start {}: {e}", command[0]))?;

    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(stdin_data)
            .map_err(|e| format!("could not write process stdin: {e}"))?;
    }

    let output = child
        .wait_with_output()
        .map_err(|e| format!("could not wait for process: {e}"))?;
    Ok(LocalProcessResult {
        stdout: output.stdout,
        stderr: output.stderr,
        return_code: output.status.code().unwrap_or(255),
    })
}

/// `sys.exit(code)` keeps the low byte of the remote exit code.
fn remote_exit_code(return_code: i64, mirror: bool) -> u8 {
    if mirror {
        (return_code & 0xff) as u8
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> Args {
        Args::parse_from(std::iter::once("rnsh").chain(args.iter().copied()))
    }

    #[cfg(windows)]
    fn local_pipe_test_command(script: &str) -> Vec<String> {
        vec![
            "powershell.exe".to_string(),
            "-NoProfile".to_string(),
            "-NonInteractive".to_string(),
            "-Command".to_string(),
            script.to_string(),
        ]
    }

    #[cfg(not(windows))]
    fn local_pipe_test_command(script: &str) -> Vec<String> {
        vec!["/bin/sh".to_string(), "-c".to_string(), script.to_string()]
    }

    #[test]
    fn parser_accepts_upstream_flag_surface() {
        let args = parse(&[
            "--config",
            "/tmp/rnsh",
            "--rnsconfig",
            "/tmp/rns",
            "--identity",
            "/tmp/id",
            "-vv",
            "-q",
            "-p",
            "-l",
            "-s",
            "svc.name",
            "-b",
            "30",
            "-a",
            "00112233445566778899aabbccddeeff",
            "-a",
            "ffeeddccbbaa99887766554433221100",
            "-n",
            "-A",
            "-C",
            "-N",
            "-m",
            "-w",
            "1.5",
            "--",
            "sh",
            "-lc",
            "echo hi",
        ]);

        assert_eq!(args.config, Some(PathBuf::from("/tmp/rnsh")));
        assert_eq!(args.rnsconfig, Some(PathBuf::from("/tmp/rns")));
        assert_eq!(args.identity, Some(PathBuf::from("/tmp/id")));
        assert_eq!(args.verbose, 2);
        assert_eq!(args.quiet, 1);
        assert!(args.print_identity);
        assert!(args.listen);
        assert_eq!(args.service.as_deref(), Some("svc.name"));
        assert_eq!(args.announce, Some(30));
        assert_eq!(args.allowed.len(), 2);
        assert!(args.no_auth);
        assert!(args.remote_command_as_args);
        assert!(args.no_remote_command);
        assert!(args.no_id);
        assert!(args.mirror);
        assert_eq!(args.timeout, Some(1.5));
        assert_eq!(args.command, vec!["sh", "-lc", "echo hi"]);
    }

    #[test]
    fn parser_accepts_initiator_destination_and_command() {
        let args = parse(&["00112233445566778899aabbccddeeff", "--", "ls", "-la"]);
        assert_eq!(
            args.destination.as_deref(),
            Some("00112233445566778899aabbccddeeff")
        );
        assert_eq!(args.command, vec!["ls", "-la"]);
    }

    #[test]
    fn service_defaults_only_in_listener_mode() {
        let mut listener = parse(&["-l"]);
        if listener.listen && listener.service.is_none() {
            listener.service = Some(DEFAULT_SERVICE_NAME.to_string());
        }
        assert_eq!(listener.service.as_deref(), Some("default"));

        let initiator = parse(&["00112233445566778899aabbccddeeff"]);
        assert_eq!(initiator.service, None);
    }

    #[test]
    fn identity_paths_live_in_the_rnsh_config_dir() {
        let dir = Path::new("/tmp/rnsh");
        assert_eq!(
            identity_path(None, dir, Some("default")),
            PathBuf::from("/tmp/rnsh/identity.default")
        );
        assert_eq!(
            identity_path(None, dir, Some("svc/name!")),
            PathBuf::from("/tmp/rnsh/identity.svcname")
        );
        assert_eq!(
            identity_path(None, dir, None),
            PathBuf::from("/tmp/rnsh/identity")
        );
        assert_eq!(
            identity_path(Some(Path::new("/tmp/custom")), dir, None),
            PathBuf::from("/tmp/custom")
        );
    }

    #[test]
    fn client_exit_codes_follow_the_session_phase() {
        let dest = [0xab; 16];
        let err = |e: RnshError, mirror| client_exit(&Err(e), &dest, mirror);
        assert_eq!(
            err(RnshError::PathTimeout, true),
            (Some("Path not found".into()), 1)
        );
        assert_eq!(
            err(RnshError::Denied("Identity not allowed".into()), true),
            (Some("Remote error: Identity not allowed".into()), 1)
        );
        assert_eq!(
            err(RnshError::Timeout("link proof"), false),
            (
                Some(format!(
                    "Could not establish link with <{}>",
                    "ab".repeat(16)
                )),
                1
            )
        );
        for mirror in [false, true] {
            let m = |code: u8| if mirror { code } else { 0 };
            assert_eq!(err(RnshError::ProtocolError, mirror).1, m(254));
            assert_eq!(err(RnshError::Remote("x".into()), mirror).1, m(255));
            assert_eq!(
                err(RnshError::ClientException("x".into()), mirror).1,
                m(127)
            );
            assert_eq!(err(RnshError::LinkClosed("x".into()), mirror), (None, 0));
            assert_eq!(err(RnshError::Terminated, mirror), (None, 0));
        }
    }

    #[test]
    fn negative_and_zero_timeouts_are_accepted() {
        assert_eq!(parse(&["-w", "-1", "x"]).timeout, Some(-1.0));
        assert_eq!(client_timeout(-1.0), Duration::ZERO);
        assert_eq!(client_timeout(0.5), Duration::from_millis(500));
        assert!(client_timeout(f64::INFINITY) > Duration::from_secs(1 << 30));
        assert_eq!(parse(&["-l", "-b", "-1"]).announce, Some(-1));
    }

    #[test]
    fn shell_join_quotes_like_shlex() {
        let args = ["/bin/sh", "-c", "echo it's"].map(String::from);
        assert_eq!(shell_join(&args), r#"/bin/sh -c 'echo it'"'"'s'"#);
    }

    #[test]
    fn listener_command_policy_matches_upstream_modes() {
        let default = vec!["/bin/sh".to_string(), "-lc".to_string()];
        let remote = vec!["echo".to_string(), "remote".to_string()];

        assert_eq!(
            select_listener_command(&default, None, false, false).unwrap(),
            default
        );
        assert_eq!(
            select_listener_command(&default, Some(&remote), true, false).unwrap(),
            remote
        );
        assert_eq!(
            select_listener_command(&default, Some(&remote), true, true).unwrap(),
            vec!["/bin/sh", "-lc", "echo", "remote"]
        );
        assert!(
            select_listener_command(&default, Some(&remote), false, false)
                .unwrap_err()
                .contains("not allowed")
        );
    }

    #[test]
    fn listener_default_command_uses_explicit_command_or_shell_fallback() {
        let explicit = vec!["/usr/bin/env".to_string(), "sh".to_string()];
        assert_eq!(listener_default_command(&explicit), explicit);
        assert!(!listener_default_command(&[]).is_empty());
    }

    #[test]
    fn listener_auth_allows_no_auth_or_configured_identity_only() {
        let allowed_hash = "00112233445566778899aabbccddeeff".to_string();
        let allowed = parse_identity_hash(&allowed_hash).unwrap();
        let denied = parse_identity_hash("ffeeddccbbaa99887766554433221100").unwrap();

        let auth = ListenerAuth::from_flags(false, std::slice::from_ref(&allowed_hash)).unwrap();
        assert!(auth.is_allowed(Some(allowed)));
        assert!(!auth.is_allowed(Some(denied)));
        assert!(!auth.is_allowed(None));

        let no_auth = ListenerAuth::from_flags(true, &[]).unwrap();
        assert!(no_auth.is_allowed(None));
        assert!(no_auth.is_allowed(Some(denied)));
    }

    #[test]
    fn listener_auth_rejects_malformed_identity_hashes() {
        assert!(parse_identity_hash("001122").is_err());
        assert!(parse_identity_hash("zz112233445566778899aabbccddeeff").is_err());
    }

    #[test]
    fn local_process_mode_selects_pipes_only_when_all_streams_are_piped() {
        assert_eq!(
            local_process_mode(true, true, true),
            LocalProcessMode::Pipes
        );
        assert_eq!(local_process_mode(false, true, true), LocalProcessMode::Pty);
        assert_eq!(local_process_mode(true, false, true), LocalProcessMode::Pty);
        assert_eq!(local_process_mode(true, true, false), LocalProcessMode::Pty);
    }

    #[test]
    fn local_pipe_process_streams_stdin_stdout_stderr_and_exit() {
        #[cfg(windows)]
        let command = local_pipe_test_command(
            r#"$line = [Console]::In.ReadLine(); [Console]::Out.Write("out:$line`n"); [Console]::Error.Write("err:$line`n"); exit 7"#,
        );
        #[cfg(not(windows))]
        let command = local_pipe_test_command(
            "read line; printf 'out:%s\\n' \"$line\"; printf 'err:%s\\n' \"$line\" >&2; exit 7",
        );
        let result =
            run_local_process_once(&command, b"hello\n", true, true, true, Some("vt100"), None)
                .unwrap();

        assert_eq!(result.stdout, b"out:hello\n");
        assert_eq!(result.stderr, b"err:hello\n");
        assert_eq!(result.return_code, 7);
    }

    #[test]
    fn local_pipe_process_sets_term_and_remote_identity_env() {
        let remote = parse_identity_hash("00112233445566778899aabbccddeeff").unwrap();
        #[cfg(windows)]
        let command = local_pipe_test_command(
            r#"[Console]::Out.Write($env:TERM + "/" + $env:RNS_REMOTE_IDENTITY)"#,
        );
        #[cfg(not(windows))]
        let command = local_pipe_test_command("printf '%s/%s' \"$TERM\" \"$RNS_REMOTE_IDENTITY\"");
        let result =
            run_local_process_once(&command, b"", true, true, true, Some("ansi"), Some(remote))
                .unwrap();

        assert_eq!(
            String::from_utf8(result.stdout).unwrap(),
            "ansi/<00112233445566778899aabbccddeeff>"
        );
        assert!(result.stderr.is_empty());
        assert_eq!(result.return_code, 0);
    }

    #[test]
    fn local_process_helper_rejects_non_pipe_mode() {
        let command = local_pipe_test_command("");
        let err = run_local_process_once(&command, b"", false, true, true, None, None).unwrap_err();
        assert!(err.contains("all-pipe"));
    }

    #[test]
    fn mirrored_remote_exit_matches_upstream_cli_flag() {
        assert_eq!(remote_exit_code(7, false), 0);
        assert_eq!(remote_exit_code(7, true), 7);
        assert_eq!(remote_exit_code(300, true), 44);
        assert_eq!(remote_exit_code(-1, true), 255);
    }

    #[test]
    fn escape_after_cr_terminates_or_shows_help() {
        let mut filter = EscapeFilter::default();
        let out = filter.process(b"ls\r~?");
        assert_eq!(out.send, b"ls\r");
        assert_eq!(out.echo, ESCAPE_HELP.as_bytes());
        assert!(!out.terminate);
        let out = filter.process(b"\r~.");
        assert_eq!(out.send, b"\r");
        assert!(out.terminate);
    }

    #[test]
    fn escape_is_recognised_at_session_start_only_after_cr() {
        let mut filter = EscapeFilter::default();
        assert!(filter.process(b"~.").terminate);
        let mut filter = EscapeFilter::default();
        let out = filter.process(b"a~.");
        assert_eq!(out.send, b"a~.");
        assert!(!out.terminate);
    }

    #[test]
    fn double_tilde_sends_one_and_unknown_escape_passes_through() {
        let mut filter = EscapeFilter::default();
        assert_eq!(filter.process(b"~~").send, b"~");
        let mut filter = EscapeFilter::default();
        assert_eq!(filter.process(b"~x").send, b"~x");
    }

    #[test]
    fn line_mode_buffers_until_flush_with_local_editing() {
        let mut filter = EscapeFilter::default();
        let out = filter.process(b"~L");
        assert_eq!(out.echo, b"\n\rLine-interactive mode enabled\n\r");
        let out = filter.process(b"ab");
        assert!(out.send.is_empty());
        assert_eq!(out.echo, b"ab");
        let out = filter.process(b"\x7f");
        assert_eq!(out.echo, b"\x08 \x08");
        let out = filter.process(b"c\r");
        assert_eq!(out.send, b"ac\r");
        assert_eq!(out.echo, b"\x08 \x08");
    }
}
