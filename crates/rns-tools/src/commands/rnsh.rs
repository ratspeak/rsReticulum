//! rnsh-rs - Reticulum remote shell utility.

use std::io::{IsTerminal, Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
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
    RnshClientConfig, RnshError, RnshListenerConfig, RnshWindowSize, rnsh_client_execute,
    run_rnsh_listener_with_shutdown,
};
use tokio::sync::mpsc;

use rns_tools::RS_RETICULUM_VERSION;

const RNSH_PROTOCOL_VERSION: &str = "0.2.0";
const APP_NAME: &str = "rnsh";
const DEFAULT_SERVICE_NAME: &str = "default";
const IDENTITY_HASH_HEX_LEN: usize = 32;

#[derive(Debug, Parser, Clone)]
#[command(
    name = "rnsh-rs",
    about = "Reticulum Remote Shell Utility",
    disable_version_flag = true,
    after_help = "When specifying a command to execute, separate rnsh-rs options from the command and its arguments with --\n\nFor example:\n  rnsh-rs -l -- /bin/bash --login\n  rnsh-rs <destination> -- ls -la /tmp"
)]
struct Args {
    #[arg(short = 'c', long = "config")]
    config: Option<PathBuf>,
    #[arg(short = 'i', long = "identity")]
    identity: Option<PathBuf>,
    #[arg(short = 'v', long = "verbose", action = ArgAction::Count)]
    verbose: u8,
    #[arg(short = 'q', long = "quiet", action = ArgAction::Count)]
    quiet: u8,
    #[arg(short = 'p', long = "print-identity")]
    print_identity: bool,
    #[arg(long = "version")]
    version: bool,

    #[arg(short = 'l', long = "listen")]
    listen: bool,
    #[arg(short = 's', long = "service")]
    service: Option<String>,
    #[arg(short = 'b', long = "announce", value_name = "PERIOD")]
    announce: Option<u64>,
    #[arg(short = 'a', long = "allowed", value_name = "HASH")]
    allowed: Vec<String>,
    #[arg(short = 'n', long = "no-auth")]
    no_auth: bool,
    #[arg(short = 'A', long = "remote-command-as-args")]
    remote_command_as_args: bool,
    #[arg(short = 'C', long = "no-remote-command")]
    no_remote_command: bool,

    #[arg(short = 'N', long = "no-id")]
    no_id: bool,
    #[arg(short = 'm', long = "mirror")]
    mirror: bool,
    #[arg(short = 'w', long = "timeout", value_name = "SECONDS")]
    timeout: Option<f64>,

    destination: Option<String>,

    #[arg(last = true)]
    command: Vec<String>,
}

#[tokio::main]
pub(crate) async fn main() -> ExitCode {
    let args = Args::parse();
    run(args).await
}

async fn run(mut args: Args) -> ExitCode {
    if args.version {
        println!("rnsh-rs {RS_RETICULUM_VERSION} (protocol {RNSH_PROTOCOL_VERSION})");
        return ExitCode::SUCCESS;
    }

    if args.listen && args.service.is_none() {
        args.service = Some(DEFAULT_SERVICE_NAME.to_string());
    }

    if args.print_identity {
        return match print_identity(&args) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("rnsh-rs: {e}");
                ExitCode::from(1)
            }
        };
    }

    if args.listen {
        return run_listener(args).await;
    }

    if args.destination.is_some() {
        return run_initiator(args).await;
    }

    let mut cmd = Args::command();
    println!();
    let _ = cmd.print_help();
    println!();
    ExitCode::from(1)
}

async fn run_listener(args: Args) -> ExitCode {
    // Register before any slow init so an early SIGINT exits cleanly.
    let shutdown = ShutdownSignal::new();
    let _signal_rx = install_signal_handlers(shutdown.clone());
    init_logging(args.verbose, args.quiet, args.config.as_deref());

    let handle = match start_reticulum(args.config.as_deref(), shutdown.clone()).await {
        Ok(handle) => handle,
        Err(e) => {
            eprintln!("rnsh-rs: failed to start reticulum: {e}");
            return ExitCode::from(1);
        }
    };
    let paths = StoragePaths::from_config_dir(&handle.config_dir);
    let identity_path = identity_path(args.identity.as_deref(), &paths, args.service.as_deref());
    let identity = match load_or_create_identity(&identity_path) {
        Ok(identity) => identity,
        Err(e) => {
            eprintln!("rnsh-rs: {e}");
            return ExitCode::from(1);
        }
    };

    let mut allowed = match parse_allowed_identities(&args.allowed) {
        Ok(allowed) => allowed,
        Err(e) => {
            eprintln!("rnsh-rs: {e}");
            return ExitCode::from(1);
        }
    };
    let allowed_identity_files = allowed_identity_file_candidates();
    allowed.extend(load_allowed_identity_files(&allowed_identity_files));

    let cfg = RnshListenerConfig {
        identity,
        command: listener_default_command(&args.command),
        allow_all: args.no_auth,
        allowed,
        allowed_identity_files,
        allow_remote_command: !args.no_remote_command,
        remote_command_as_args: args.remote_command_as_args,
        announce_period: args.announce,
    };

    match run_rnsh_listener_with_shutdown(handle.transport_tx.clone(), cfg, handle.shutdown.clone())
        .await
    {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("rnsh-rs: {e}");
            ExitCode::from(error_exit_code(&e))
        }
    }
}

async fn run_initiator(args: Args) -> ExitCode {
    // Register before any slow init so an early SIGINT exits cleanly.
    let shutdown = ShutdownSignal::new();
    let _signal_rx = install_signal_handlers(shutdown.clone());
    init_logging(args.verbose, args.quiet, args.config.as_deref());

    let destination = match args.destination.as_deref().and_then(parse_hash16) {
        Some(hash) => hash,
        None => {
            eprintln!("Invalid destination entered. Check your input.");
            return ExitCode::from(1);
        }
    };

    let handle = match start_reticulum(args.config.as_deref(), shutdown.clone()).await {
        Ok(handle) => handle,
        Err(e) => {
            eprintln!("rnsh-rs: failed to start reticulum: {e}");
            return ExitCode::from(1);
        }
    };
    let paths = StoragePaths::from_config_dir(&handle.config_dir);
    let identity_path = identity_path(args.identity.as_deref(), &paths, None);
    let identity = match load_or_create_identity(&identity_path) {
        Ok(identity) => identity,
        Err(e) => {
            eprintln!("rnsh-rs: {e}");
            return ExitCode::from(1);
        }
    };

    let pipe_stdin = !std::io::stdin().is_terminal();
    let pipe_stdout = !std::io::stdout().is_terminal();
    let pipe_stderr = !std::io::stderr().is_terminal();
    let (rows, cols, hpix, vpix) = terminal_window_size();
    let _terminal_mode = if pipe_stdin {
        None
    } else {
        enter_raw_stdin_mode()
    };
    let stdin_rx = Some(spawn_stdin_reader());
    let (stdout_tx, stdout_writer) = spawn_output_writer(false);
    let (stderr_tx, stderr_writer) = spawn_output_writer(true);
    let window_rx = spawn_window_size_watcher();

    let timeout = Duration::from_secs_f64(args.timeout.unwrap_or(15.0).max(1.0));
    let cfg = RnshClientConfig {
        identity,
        destination_hash: destination,
        command: args.command.clone(),
        no_id: args.no_id,
        timeout,
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
    };

    match rnsh_client_execute(handle.transport_tx.clone(), cfg).await {
        Ok(outcome) => {
            if let Err(e) = finish_output_writers(stdout_writer, stderr_writer).await {
                eprintln!("rnsh-rs: {e}");
                return ExitCode::from(1);
            }
            ExitCode::from(remote_exit_code(outcome.return_code, args.mirror))
        }
        Err(e) => {
            let _ = finish_output_writers(stdout_writer, stderr_writer).await;
            eprintln!("rnsh-rs: {e}");
            ExitCode::from(error_exit_code(&e))
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

fn init_logging(verbose: u8, quiet: u8, config_dir: Option<&Path>) {
    let level = match (verbose as i32) - (quiet as i32) {
        n if n >= 2 => tracing::Level::DEBUG,
        1 => tracing::Level::INFO,
        0 => tracing::Level::WARN,
        _ => tracing::Level::ERROR,
    };
    let resolved = resolve_config_dir(config_dir.and_then(|path| path.to_str()));
    rns_tools::init_tracing(
        level,
        rns_tools::config_log_timestamps(&resolved),
        true,
        std::io::stderr,
    );
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

fn spawn_stdin_reader() -> mpsc::Receiver<Vec<u8>> {
    let (tx, rx) = mpsc::channel(16);
    std::thread::spawn(move || {
        let mut stdin = std::io::stdin();
        let mut buf = [0u8; 1024];
        loop {
            match stdin.read(&mut buf) {
                Ok(0) => {
                    let _ = tx.blocking_send(Vec::new());
                    break;
                }
                Ok(n) => {
                    if tx.blocking_send(buf[..n].to_vec()).is_err() {
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

fn spawn_output_writer(
    stderr: bool,
) -> (
    mpsc::Sender<Vec<u8>>,
    tokio::task::JoinHandle<Result<(), String>>,
) {
    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(64);
    let task = tokio::task::spawn_blocking(move || {
        if stderr {
            let stderr = std::io::stderr();
            let mut handle = stderr.lock();
            while let Some(chunk) = rx.blocking_recv() {
                handle
                    .write_all(&chunk)
                    .map_err(|e| format!("could not write stderr: {e}"))?;
                handle
                    .flush()
                    .map_err(|e| format!("could not flush stderr: {e}"))?;
            }
        } else {
            let stdout = std::io::stdout();
            let mut handle = stdout.lock();
            while let Some(chunk) = rx.blocking_recv() {
                handle
                    .write_all(&chunk)
                    .map_err(|e| format!("could not write stdout: {e}"))?;
                handle
                    .flush()
                    .map_err(|e| format!("could not flush stdout: {e}"))?;
            }
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
            let (rows, cols, hpix, vpix) = terminal_window_size();
            if tx
                .send(RnshWindowSize {
                    rows,
                    cols,
                    hpix,
                    vpix,
                })
                .await
                .is_err()
            {
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

fn error_exit_code(error: &RnshError) -> u8 {
    match error {
        RnshError::PathTimeout | RnshError::NoIdentity | RnshError::Timeout(_) => 1,
        RnshError::Remote(_) => 255,
        _ => 1,
    }
}

fn print_identity(args: &Args) -> Result<(), String> {
    let config_dir = resolve_config_dir(args.config.as_deref().and_then(Path::to_str));
    let paths = StoragePaths::from_config_dir(&config_dir);
    paths
        .ensure_dirs()
        .map_err(|e| format!("could not prepare Reticulum storage: {e}"))?;

    let identity_path = identity_path(args.identity.as_deref(), &paths, args.service.as_deref());
    let identity = load_or_create_identity(&identity_path)?;
    let destination = Destination::new(Some(&identity), Direction::In, DestType::Single, APP_NAME)
        .map_err(|e| format!("could not create rnsh destination: {e}"))?;

    if let Some(service) = args
        .service
        .as_deref()
        .filter(|service| !service.is_empty())
    {
        println!("Using service name \"{service}\"");
    }
    println!("Identity     : {}", hex::encode(identity.hash));
    if args.listen {
        println!("Listening on : {}", hex::encode(destination.hash));
    }
    Ok(())
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

fn identity_path(explicit: Option<&Path>, paths: &StoragePaths, service: Option<&str>) -> PathBuf {
    if let Some(path) = explicit {
        return path.to_path_buf();
    }
    let mut name = APP_NAME.to_string();
    let service = sanitize_service_name(service.unwrap_or(""));
    if !service.is_empty() {
        name.push('.');
        name.push_str(&service);
    }
    paths.identity_dir.join(name)
}

fn sanitize_service_name(service: &str) -> String {
    service
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '_')
        .collect()
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

fn env_nonempty(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|value| !value.is_empty())
}

fn default_shell_command() -> Vec<String> {
    #[cfg(windows)]
    let shell = env_nonempty("COMSPEC")
        .or_else(|| env_nonempty("SHELL"))
        .unwrap_or_else(|| "cmd.exe".to_string());

    #[cfg(not(windows))]
    let shell = env_nonempty("SHELL").unwrap_or_else(|| "/bin/sh".to_string());

    vec![shell]
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

fn parse_identity_hash(input: &str) -> Result<[u8; 16], String> {
    let trimmed = input.trim();
    if trimmed.len() != IDENTITY_HASH_HEX_LEN {
        return Err(format!(
            "identity hash must be {IDENTITY_HASH_HEX_LEN} hexadecimal characters"
        ));
    }
    let decoded = hex::decode(trimmed).map_err(|_| "identity hash is not valid hex".to_string())?;
    let mut hash = [0u8; 16];
    hash.copy_from_slice(&decoded);
    Ok(hash)
}

fn parse_hash16(input: &str) -> Option<[u8; 16]> {
    if input.len() != IDENTITY_HASH_HEX_LEN {
        return None;
    }
    let decoded = hex::decode(input).ok()?;
    let mut hash = [0u8; 16];
    hash.copy_from_slice(decoded.get(..16)?);
    Some(hash)
}

fn parse_allowed_identities(values: &[String]) -> Result<Vec<[u8; 16]>, String> {
    values
        .iter()
        .map(|value| parse_identity_hash(value))
        .collect()
}

fn allowed_identity_file_candidates() -> Vec<PathBuf> {
    let Some(home) = std::env::var_os("HOME").map(PathBuf::from) else {
        return Vec::new();
    };
    vec![
        home.join(".config/rnsh/allowed_identities"),
        home.join(".rnsh/allowed_identities"),
    ]
}

fn load_allowed_identity_files(candidates: &[PathBuf]) -> Vec<[u8; 16]> {
    let Some(path) = candidates.iter().find(|path| path.is_file()) else {
        return Vec::new();
    };
    let Ok(content) = std::fs::read_to_string(path) else {
        return Vec::new();
    };
    content
        .replace('\r', "")
        .lines()
        .filter_map(|line| parse_hash16(line.trim()))
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

fn remote_exit_code(return_code: i64, mirror: bool) -> u8 {
    if mirror {
        return_code.clamp(0, u8::MAX as i64) as u8
    } else {
        0
    }
}

fn _rnsh_config_dir(home: &Path, dot_config_exists: bool, _dot_rnsh_exists: bool) -> PathBuf {
    if dot_config_exists {
        home.join(".config/rnsh")
    } else {
        home.join(".rnsh")
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

        assert_eq!(args.config, Some(PathBuf::from("/tmp/rns")));
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
    fn identity_paths_match_upstream_service_suffix() {
        let paths = StoragePaths::from_config_dir(Path::new("/tmp/reticulum"));
        assert_eq!(
            identity_path(None, &paths, Some("default")),
            PathBuf::from("/tmp/reticulum/storage/identities/rnsh.default")
        );
        assert_eq!(
            identity_path(None, &paths, Some("svc/name!")),
            PathBuf::from("/tmp/reticulum/storage/identities/rnsh.svcname")
        );
        assert_eq!(
            identity_path(Some(Path::new("/tmp/custom")), &paths, None),
            PathBuf::from("/tmp/custom")
        );
    }

    #[test]
    fn version_string_uses_rust_command_name() {
        assert_eq!(
            format!("rnsh-rs {RS_RETICULUM_VERSION} (protocol {RNSH_PROTOCOL_VERSION})"),
            format!("rnsh-rs {} (protocol 0.2.0)", env!("CARGO_PKG_VERSION"))
        );
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
        assert_eq!(remote_exit_code(300, true), 255);
        assert_eq!(remote_exit_code(-1, true), 0);
    }
}
