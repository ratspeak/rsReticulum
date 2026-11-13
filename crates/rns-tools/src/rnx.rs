//! The `rnx` remote execution protocol (RNS/Utilities/rnx.py): request and
//! result arrays, command execution on the listener and result rendering on
//! the client.

use crate::format::py_round;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rmpv::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Destination aspects `rnx.execute` (rnx.py).
pub const APP_NAME: &str = "rnx.execute";
/// Request handler path (rnx.py).
pub const COMMAND_PATH: &str = "command";
/// `remote_exec_grace` (rnx.py).
pub const REMOTE_EXEC_GRACE: f64 = 2.0;
/// `RNS.Transport.PATH_REQUEST_TIMEOUT`, the default `-w`, sent as an integer.
pub const DEFAULT_TIMEOUT: i64 = 15;

/// The client's `-w`: the integer default, or the float a user gave.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Timeout {
    Default,
    Given(f64),
}

impl Timeout {
    pub fn seconds(self) -> f64 {
        match self {
            Timeout::Default => DEFAULT_TIMEOUT as f64,
            Timeout::Given(seconds) => seconds,
        }
    }

    fn value(self) -> Value {
        match self {
            Timeout::Default => Value::from(DEFAULT_TIMEOUT),
            Timeout::Given(seconds) => Value::F64(seconds),
        }
    }
}

/// `request_data` as `execute` builds it (rnx.py).
pub fn request_value(
    command: &str,
    timeout: Timeout,
    stdout_limit: Option<i64>,
    stderr_limit: Option<i64>,
    stdin: Option<&str>,
) -> Value {
    let limit = |l: Option<i64>| l.map_or(Value::Nil, Value::from);
    Value::Array(vec![
        Value::Binary(command.as_bytes().to_vec()),
        timeout.value(),
        limit(stdout_limit),
        limit(stderr_limit),
        stdin.map_or(Value::Nil, |s| Value::Binary(s.as_bytes().to_vec())),
    ])
}

/// A decoded request as `execute_received_command` reads it (rnx.py).
#[derive(Debug, Clone, PartialEq)]
pub struct CommandRequest {
    pub command: String,
    pub timeout: Option<f64>,
    pub stdout_limit: Option<i64>,
    pub stderr_limit: Option<i64>,
    pub stdin: Option<Vec<u8>>,
}

impl CommandRequest {
    /// `None` where the upstream handler raises before answering.
    pub fn from_value(value: &Value) -> Option<Self> {
        let items = value.as_array()?;
        let command = match items.first()? {
            Value::Binary(bytes) => String::from_utf8(bytes.clone()).ok()?,
            _ => return None,
        };
        let number = |v: Option<&Value>| -> Option<Option<f64>> {
            match v? {
                Value::Nil => Some(None),
                Value::F32(f) => Some(Some(f64::from(*f))),
                Value::F64(f) => Some(Some(*f)),
                Value::Integer(i) => Some(Some(i.as_f64()?)),
                _ => None,
            }
        };
        let limit = |v: Option<&Value>| -> Option<Option<i64>> {
            match v? {
                Value::Nil => Some(None),
                Value::Integer(i) => Some(Some(i.as_i64()?)),
                _ => None,
            }
        };
        let stdin = match items.get(4)? {
            Value::Nil => None,
            Value::Binary(bytes) => Some(bytes.clone()),
            _ => return None,
        };
        Some(Self {
            command,
            timeout: number(items.get(1))?,
            stdout_limit: limit(items.get(2))?,
            stderr_limit: limit(items.get(3))?,
            stdin,
        })
    }
}

/// The result array (rnx.py).
#[derive(Debug, Clone, PartialEq)]
pub struct CommandResult {
    pub executed: bool,
    pub retcode: Option<i64>,
    pub stdout: Option<Vec<u8>>,
    pub stderr: Option<Vec<u8>>,
    pub stdout_len: Option<u64>,
    pub stderr_len: Option<u64>,
    pub started: f64,
    pub concluded: Option<f64>,
}

impl CommandResult {
    fn not_executed(started: f64) -> Self {
        Self {
            executed: false,
            retcode: None,
            stdout: None,
            stderr: None,
            stdout_len: None,
            stderr_len: None,
            started,
            concluded: None,
        }
    }

    pub fn to_value(&self) -> Value {
        let bin = |b: &Option<Vec<u8>>| b.clone().map_or(Value::Nil, Value::Binary);
        let int = |i: Option<i64>| i.map_or(Value::Nil, Value::from);
        Value::Array(vec![
            Value::Boolean(self.executed),
            int(self.retcode),
            bin(&self.stdout),
            bin(&self.stderr),
            int(self.stdout_len.map(|n| n as i64)),
            int(self.stderr_len.map(|n| n as i64)),
            Value::F64(self.started),
            self.concluded.map_or(Value::Nil, Value::F64),
        ])
    }

    /// Packed result, the response value the listener returns.
    pub fn to_msgpack(&self) -> Vec<u8> {
        let mut out = Vec::new();
        rmpv::encode::write_value(&mut out, &self.to_value()).expect("encoding to a Vec");
        out
    }
}

fn now() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0.0, |d| d.as_secs_f64())
}

/// `out[0:limit]` with Python slice semantics, applied only when
/// `len(out) > limit` (rnx.py).
pub fn truncate(out: &[u8], limit: Option<i64>) -> Vec<u8> {
    let len = out.len() as i64;
    match limit {
        Some(limit) if len > limit => {
            let end = if limit < 0 {
                (len + limit).max(0)
            } else {
                limit
            };
            out[..end as usize].to_vec()
        }
        _ => out.to_vec(),
    }
}

/// `execute_received_command` (rnx.py): run the command without a
/// shell, feed stdin, SIGTERM it once the timeout passes, truncate output.
pub async fn execute(request: &CommandRequest) -> CommandResult {
    let started = now();
    let Some(argv) = rns_interface::pipe::split_command(&request.command) else {
        return CommandResult::not_executed(started);
    };
    let Some((program, args)) = argv.split_first() else {
        return CommandResult::not_executed(started);
    };
    let mut child = match tokio::process::Command::new(program)
        .args(args)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()
    {
        Ok(child) => child,
        Err(_) => return CommandResult::not_executed(started),
    };
    let mut stdin = child.stdin.take();
    let stdin_data = request.stdin.clone();
    let writer = tokio::spawn(async move {
        if let (Some(pipe), Some(data)) = (stdin.as_mut(), stdin_data) {
            let _ = pipe.write_all(&data).await;
        }
        drop(stdin);
    });
    let mut stdout_pipe = child.stdout.take().expect("piped stdout");
    let mut stderr_pipe = child.stderr.take().expect("piped stderr");
    let out_reader = tokio::spawn(async move {
        let mut buf = Vec::new();
        let _ = stdout_pipe.read_to_end(&mut buf).await;
        buf
    });
    let err_reader = tokio::spawn(async move {
        let mut buf = Vec::new();
        let _ = stderr_pipe.read_to_end(&mut buf).await;
        buf
    });

    let deadline = request.timeout.map(|t| {
        Duration::try_from_secs_f64((started + t - now()).max(0.0)).unwrap_or(Duration::MAX)
    });
    let mut killed = false;
    let status = match deadline {
        Some(deadline) => match tokio::time::timeout(deadline, child.wait()).await {
            Ok(status) => status,
            Err(_) => {
                killed = true;
                tracing::info!(target: crate::NOTICE_TARGET, "Command [{}] timed out and is being killed...", request.command);
                if let Some(pid) = child.id() {
                    // SAFETY: signals the child this task still owns.
                    unsafe {
                        nix::libc::kill(pid as i32, nix::libc::SIGTERM);
                    }
                }
                child.wait().await
            }
        },
        None => child.wait().await,
    };
    let _ = writer.await;
    let stdout = out_reader.await.unwrap_or_default();
    let stderr = err_reader.await.unwrap_or_default();

    // Upstream kills only once the deadline has passed, so a killed command never concludes.
    let concluded = request
        .timeout
        .filter(|_| !killed)
        .and_then(|t| (now() < started + t).then(now));
    let retcode = status.ok().and_then(|s| {
        use std::os::unix::process::ExitStatusExt;
        s.code().or_else(|| s.signal().map(|n| -n)).map(i64::from)
    });
    CommandResult {
        executed: true,
        retcode,
        stdout: Some(truncate(&stdout, request.stdout_limit)),
        stderr: Some(truncate(&stderr, request.stderr_limit)),
        stdout_len: Some(stdout.len() as u64),
        stderr_len: Some(stderr.len() as u64),
        started,
        concluded,
    }
}

/// A response as the client indexes it (rnx.py).
#[derive(Debug, Clone, PartialEq)]
pub struct Response {
    pub executed: bool,
    pub retcode: Option<i64>,
    pub stdout: Option<Vec<u8>>,
    pub stderr: Option<Vec<u8>>,
    pub stdout_len: Option<u64>,
    pub stderr_len: Option<u64>,
    pub started: Option<f64>,
    pub concluded: Option<f64>,
}

fn truthy(value: &Value) -> bool {
    match value {
        Value::Nil => false,
        Value::Boolean(b) => *b,
        Value::Integer(i) => i.as_i64() != Some(0) && i.as_u64() != Some(0),
        Value::F32(f) => *f != 0.0,
        Value::F64(f) => *f != 0.0,
        Value::String(s) => !s.as_bytes().is_empty(),
        Value::Binary(b) => !b.is_empty(),
        Value::Array(a) => !a.is_empty(),
        Value::Map(m) => !m.is_empty(),
        Value::Ext(..) => true,
    }
}

/// How the client reads a response.
#[derive(Debug, Clone, PartialEq)]
pub enum ResponseKind {
    /// `"No response"`, 249.
    Missing,
    /// `"Received invalid result"`, 247.
    Invalid,
    Result(Response),
}

impl ResponseKind {
    pub fn from_value(value: &Value) -> Self {
        let Some(items) = value.as_array() else {
            return if value.is_nil() {
                Self::Missing
            } else {
                Self::Invalid
            };
        };
        if items.len() < 8 {
            return Self::Invalid;
        }
        let bin = |v: &Value| match v {
            Value::Binary(b) => Some(b.clone()),
            Value::String(s) => Some(s.as_bytes().to_vec()),
            _ => None,
        };
        let float = |v: &Value| match v {
            Value::F64(f) => Some(*f),
            Value::F32(f) => Some(f64::from(*f)),
            Value::Integer(i) => i.as_f64(),
            _ => None,
        };
        Self::Result(Response {
            executed: truthy(&items[0]),
            retcode: items[1].as_i64(),
            stdout: bin(&items[2]),
            stderr: bin(&items[3]),
            stdout_len: items[4].as_u64(),
            stderr_len: items[5].as_u64(),
            started: float(&items[6]),
            concluded: float(&items[7]),
        })
    }
}

/// Request and response sizes and times for the `-d` transfer line.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct TransferStats {
    pub request_size: Option<u64>,
    pub response_size: u64,
    /// `response_concluded_at - sent_at`, in seconds.
    pub elapsed: f64,
}

/// Text the client writes for an executed result (rnx.py).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Rendered {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

/// Render an executed result. `stdout_limit`/`stderr_limit` are the
/// client's own `--stdout`/`--stderr`.
pub fn render(
    response: &Response,
    detailed: bool,
    stdout_limit: Option<i64>,
    stderr_limit: Option<i64>,
    stats: Option<TransferStats>,
) -> Rendered {
    let mut r = Rendered::default();
    let stdout = response.stdout.as_deref();
    let stderr = response.stderr.as_deref();
    if let Some(out) = stdout.filter(|o| !o.is_empty()) {
        r.stdout.extend_from_slice(out);
    }
    if let Some(err) = stderr.filter(|e| !e.is_empty()) {
        r.stderr.extend_from_slice(err);
    }
    let mut line = |s: String| {
        r.stdout.extend_from_slice(s.as_bytes());
        r.stdout.push(b'\n');
    };
    if detailed {
        line("\n--- End of remote output, rnx done ---".into());
        if let (Some(started), Some(concluded)) = (response.started, response.concluded) {
            let cmd_duration = py_round(concluded - started, 3);
            line(format!(
                "Remote command execution took {} seconds",
                py_float(cmd_duration)
            ));
            if let Some(stats) = stats {
                let total = stats.response_size + stats.request_size.unwrap_or(0);
                let td = py_round(stats.elapsed - cmd_duration, 3);
                let tdstr = if td == 1.0 {
                    " in 1 second".to_string()
                } else if td < 10.0 {
                    format!(" in {} seconds", py_float(td))
                } else {
                    format!(" in {}", pretty_time(td))
                };
                let spdstr = if td != 0.0 {
                    format!(", effective rate {}ps", size_str(total as f64 / td, 'b'))
                } else {
                    String::new()
                };
                line(format!(
                    "Transferred {}{tdstr}{spdstr}",
                    size_str(total as f64, 'B')
                ));
            }
        }
        let wrote = |name: &str, out: Option<&[u8]>, total: Option<u64>| {
            let (Some(out), Some(total)) = (out, total) else {
                return None;
            };
            let shown = if (out.len() as u64) < total {
                format!(", {} bytes displayed", out.len())
            } else {
                String::new()
            };
            Some(format!("Remote wrote {total} bytes to {name}{shown}"))
        };
        if let Some(l) = wrote("stdout", stdout, response.stdout_len) {
            line(l);
        }
        if let Some(l) = wrote("stderr", stderr, response.stderr_len) {
            line(l);
        }
    } else {
        let shorter = |out: Option<&[u8]>, total: Option<u64>| {
            (out.map_or(0, <[u8]>::len) as u64) < total.unwrap_or(0)
        };
        let out_short = shorter(stdout, response.stdout_len);
        let err_short = shorter(stderr, response.stderr_len);
        if (stdout_limit != Some(0) && out_short) || (stderr_limit != Some(0) && err_short) {
            line("\nOutput truncated before being returned:".into());
            if stdout.is_some_and(|o| !o.is_empty()) && out_short {
                line(format!(
                    "  stdout truncated to {} bytes",
                    stdout.map_or(0, <[u8]>::len)
                ));
            }
            if stderr.is_some_and(|e| !e.is_empty()) && err_short {
                line(format!(
                    "  stderr truncated to {} bytes",
                    stderr.map_or(0, <[u8]>::len)
                ));
            }
        }
    }
    r
}

/// The process status for `-m` (rnx.py): the remote code as Python's
/// `exit()` passes it to the OS, or 240 without one.
pub fn mirrored_exit_code(retcode: Option<i64>) -> i32 {
    retcode.map_or(240, |code| (code & 0xff) as i32)
}

/// Python `str(float)` for values without exponent notation.
pub fn py_float(x: f64) -> String {
    if x.is_finite() && x.fract() == 0.0 && x.abs() < 1e16 {
        format!("{x:.1}")
    } else {
        format!("{x}")
    }
}

/// `size_str` (rnx.py).
pub fn size_str(num: f64, suffix: char) -> String {
    let mut num = if suffix == 'b' { num * 8.0 } else { num };
    for unit in ["", "K", "M", "G", "T", "P", "E", "Z"] {
        if num.abs() < 1000.0 {
            return if unit.is_empty() {
                format!("{num:.0} {unit}{suffix}")
            } else {
                format!("{num:.2} {unit}{suffix}")
            };
        }
        num /= 1000.0;
    }
    format!("{num:.2}Y{suffix}")
}

/// `pretty_time` without `verbose` (rnx.py).
pub fn pretty_time(time: f64) -> String {
    let days = (time / 86400.0).floor() as i64;
    let time = time.rem_euclid(86400.0);
    let hours = (time / 3600.0).floor() as i64;
    let time = time.rem_euclid(3600.0);
    let minutes = (time / 60.0).floor() as i64;
    let seconds = py_round(time.rem_euclid(60.0), 2);
    let mut components = Vec::new();
    if days > 0 {
        components.push(format!("{days}d"));
    }
    if hours > 0 {
        components.push(format!("{hours}h"));
    }
    if minutes > 0 {
        components.push(format!("{minutes}m"));
    }
    if seconds > 0.0 {
        components.push(format!("{}s", py_float(seconds)));
    }
    let mut out = String::new();
    let n = components.len();
    for (i, c) in components.iter().enumerate() {
        if i > 0 {
            out.push_str(if i + 1 < n { ", " } else { " and " });
        }
        out.push_str(c);
    }
    out
}

/// The allowed-identities files the listener reads, first existing wins
/// (rnx.py).
pub fn allowed_identity_files(home: Option<&Path>) -> Vec<PathBuf> {
    let mut files = vec![PathBuf::from("/etc/rnx/allowed_identities")];
    if let Some(home) = home {
        files.push(home.join(".config/rnx/allowed_identities"));
        files.push(home.join(".rnx/allowed_identities"));
    }
    files
}

/// Parse an allowed-identities file: only lines of exactly 32 characters
/// count, and one that is not hex fails (rnx.py).
pub fn parse_allowed_identities(text: &str) -> Result<Vec<[u8; 16]>, String> {
    let mut allowed = Vec::new();
    for line in text.replace('\r', "").split('\n') {
        if line.chars().count() != 32 {
            continue;
        }
        let mut hash = [0u8; 16];
        hex::decode_to_slice(line, &mut hash).map_err(|_| {
            let position = line
                .char_indices()
                .find(|(_, c)| !c.is_ascii_hexdigit())
                .map_or(0, |(i, _)| i);
            format!("non-hexadecimal number found in fromhex() arg at position {position}")
        })?;
        allowed.push(hash);
    }
    Ok(allowed)
}

/// Validate a 32-character hash argument with upstream's messages
/// (rnx.py).
pub fn parse_hash_arg(value: &str) -> Result<[u8; 16], String> {
    if value.chars().count() != 32 {
        return Err(
            "Allowed destination length is invalid, must be 32 hexadecimal characters (16 bytes)."
                .into(),
        );
    }
    let mut hash = [0u8; 16];
    hex::decode_to_slice(value, &mut hash)
        .map_err(|_| "Invalid destination entered. Check your input.".to_string())?;
    Ok(hash)
}

/// A one-shot client's output and exit code for a received response value
/// (rnx.py).
pub fn client_result(
    value: &Value,
    detailed: bool,
    mirror: bool,
    stdout_limit: Option<i64>,
    stderr_limit: Option<i64>,
    stats: Option<TransferStats>,
) -> (Rendered, Option<Response>, i32) {
    let message = |text: &str, code| {
        let mut r = Rendered::default();
        r.stdout.extend_from_slice(text.as_bytes());
        r.stdout.push(b'\n');
        (r, None, code)
    };
    let response = match ResponseKind::from_value(value) {
        ResponseKind::Missing => return message("No response", 249),
        ResponseKind::Invalid => return message("Received invalid result", 247),
        ResponseKind::Result(response) => response,
    };
    if !response.executed {
        return message("Remote could not execute command", 248);
    }
    let rendered = render(&response, detailed, stdout_limit, stderr_limit, stats);
    let code = if mirror {
        mirrored_exit_code(response.retcode)
    } else {
        0
    };
    (rendered, Some(response), code)
}
