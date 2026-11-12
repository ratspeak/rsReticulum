//! `git-remote-rns`, the git remote helper for `rns://` URLs
//! (`RNS/Utilities/rngit/client.py`), without the network part.

use std::collections::BTreeMap;
use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use rmpv::Value;
use rns_identity::identity::Identity;
use rns_runtime::config::{Config, ConfigError};
use rns_tools::rsg::pyfmt::py_fromhex;

use crate::server::{
    IDX_REPOSITORY, IDX_RESULT_CODE, PATH_DELETE, PATH_FETCH, PATH_LIST, PATH_PUSH,
};

/// The file written when the config directory has none (`client.py`).
pub const DEFAULT_CLIENT_CONFIG: &str = include_str!("client_default_config.txt");

pub const REF_BATCH_SIZE: usize = 25;
pub const PATH_TIMEOUT: f64 = 15.0;
/// `send_request`'s default timeout, used for every request (`client.py`).
pub const REQUEST_TIMEOUT: f64 = 7200.0;

const LOG_NONE: i64 = -1;
const LOG_EXTREME: i64 = 8;

/// The parts of an `rns://<destination>/<group>/<repo>` URL (`client.py`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HelperUrl {
    pub destination: String,
    pub group: String,
    pub repo: String,
}

impl HelperUrl {
    /// The repository path sent on the wire (`client.py`).
    pub fn repo_path(&self) -> String {
        format!("{}/{}", self.group, self.repo)
    }
}

/// Parse the helper's arguments after the program name: `<remote-name> <url>`.
/// The error is the stderr line and the exit code.
pub fn parse_args(args: &[String]) -> Result<HelperUrl, (String, i32)> {
    if args.len() < 2 {
        return Err(("Usage: git-remote-rns <remote-name> <url>".into(), 1));
    }
    let Some(rest) = args[1].strip_prefix("rns://") else {
        return Err(("Invalid URL scheme. Must be rns://".into(), 1));
    };
    let parts: Vec<&str> = rest.splitn(3, '/').collect();
    if parts.len() < 3 {
        return Err((
            "Invalid URL format. Use rns://<hash>/<group>/<repo>".into(),
            1,
        ));
    }
    Ok(HelperUrl {
        destination: parts[0].to_string(),
        group: parts[1].to_string(),
        repo: parts[2].to_string(),
    })
}

/// The config directory (`client.py`). When `~/.config/rngit/config`
/// exists upstream picks `~/.rngit/reticulum`, not `~/.config/rngit`.
pub fn resolve_config_dir(configdir: Option<&Path>, home: &Path) -> PathBuf {
    if let Some(dir) = configdir {
        return dir.to_path_buf();
    }
    let user = home.join(".config/rngit");
    if user.is_dir() && user.join("config").is_file() {
        home.join(".rngit/reticulum")
    } else {
        home.join(".rngit")
    }
}

/// What `__apply_config` takes from `client_config` (`client.py`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientConfig {
    pub ref_batch_size: usize,
    /// `[logging] loglevel`, clamped; `None` when absent.
    pub loglevel: Option<i64>,
    /// Alias name to lowercase destination hash hex.
    pub aliases: BTreeMap<String, String>,
}

#[derive(Debug)]
pub enum ClientConfigError {
    /// The file does not parse; upstream logs it and exits 1 before starting Reticulum.
    Parse(PathBuf, ConfigError),
    /// A value `as_int` rejects; upstream raises out of `__init__` (exit 1).
    Value(ConfigError),
    Io(PathBuf, std::io::Error),
}

impl std::fmt::Display for ClientConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Parse(path, _) => {
                write!(f, "Could not parse the configuration at {}", path.display())
            }
            Self::Value(e) => write!(f, "{e}"),
            Self::Io(path, e) => write!(f, "{}: {e}", path.display()),
        }
    }
}

fn is_hash_hex(value: &str) -> bool {
    value.chars().count() == 32 && py_fromhex(value).is_ok_and(|h| !h.is_empty())
}

impl ClientConfig {
    /// Read `<configdir>/client_config`, writing the default first when missing.
    pub fn load(configdir: &Path) -> Result<Self, ClientConfigError> {
        let path = configdir.join("client_config");
        let text = if path.is_file() {
            std::fs::read_to_string(&path).map_err(|e| ClientConfigError::Io(path.clone(), e))?
        } else {
            std::fs::create_dir_all(configdir)
                .and_then(|()| std::fs::write(&path, DEFAULT_CLIENT_CONFIG))
                .map_err(|e| ClientConfigError::Io(path.clone(), e))?;
            DEFAULT_CLIENT_CONFIG.to_string()
        };
        let config = Config::parse(&text).map_err(|e| ClientConfigError::Parse(path, e))?;
        Self::apply(&config).map_err(ClientConfigError::Value)
    }

    fn apply(config: &Config) -> Result<Self, ConfigError> {
        let as_int = |section: &str, key: &str| -> Result<Option<i64>, ConfigError> {
            let Some(s) = config.section(section).filter(|s| s.has(key)) else {
                return Ok(None);
            };
            s.get_int(key)
                .map(Some)
                .ok_or_else(|| ConfigError::InvalidValue {
                    section: section.into(),
                    key: key.into(),
                    message: "not an integer".into(),
                })
        };
        let loglevel = as_int("logging", "loglevel")?.map(|l| l.clamp(LOG_NONE, LOG_EXTREME));
        let ref_batch_size = as_int("client", "ref_batch_size")?
            .map_or(REF_BATCH_SIZE, |n| n.clamp(0, 1024) as usize);
        let mut aliases = BTreeMap::new();
        if let Some(section) = config.section("aliases") {
            for alias in section.values.keys() {
                let Some(value) = section.get(alias).filter(|v| is_hash_hex(v)) else {
                    continue;
                };
                let hash = py_fromhex(value).expect("checked above");
                aliases
                    .entry(alias.clone())
                    .or_insert_with(|| hex::encode(hash));
            }
        }
        Ok(Self {
            ref_batch_size,
            loglevel,
            aliases,
        })
    }

    /// `__resolve_destination_alias` (`client.py`): a 32-character hex
    /// string as given, else a configured alias, else the input unchanged.
    pub fn resolve_destination(&self, destination: &str) -> String {
        if is_hash_hex(destination) {
            return destination.to_string();
        }
        self.aliases
            .get(destination)
            .cloned()
            .unwrap_or_else(|| destination.to_string())
    }
}

/// Load `client_identity`, creating it when missing (`client.py`).
/// A new identity that cannot be saved is still used, as upstream does.
pub fn load_or_create_identity(path: &Path) -> Option<Identity> {
    if path.is_file() {
        return Identity::from_file(path).ok();
    }
    let identity = Identity::new();
    if let Err(e) = identity.to_file(path) {
        tracing::error!("Error while saving identity to {}: {e}", path.display());
    }
    Some(identity)
}

/// A response as `send_request` returns it.
#[derive(Debug, Clone, PartialEq)]
pub enum Response {
    /// Python `bytes`.
    Bytes(Vec<u8>),
    /// A file response: the spooled body and its packed-then-decoded metadata.
    File { path: PathBuf, metadata: Value },
    /// Any other response value.
    Other(Value),
}

/// The link side of the helper. `None` is a failed or timed-out request.
pub trait Transport {
    fn request(&mut self, path: &str, data: Value) -> Option<Response>;
}

/// `abort()`: the process prints `git-remote-rns failed: <reason>` and exits
/// with `code`. A `code` of 1 with `traceback` set stands for an uncaught
/// Python exception, which prints `reason` alone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Abort {
    pub reason: String,
    pub code: i32,
    pub traceback: bool,
}

impl Abort {
    pub fn new(reason: impl Into<String>) -> Self {
        let reason = reason.into();
        Self {
            reason: if reason.is_empty() {
                "Unknown reason".into()
            } else {
                reason
            },
            code: 255,
            traceback: false,
        }
    }

    fn exception(reason: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
            code: 1,
            traceback: true,
        }
    }

    /// The stderr line.
    pub fn message(&self) -> String {
        if self.traceback {
            self.reason.clone()
        } else {
            format!("git-remote-rns failed: {}", self.reason)
        }
    }
}

/// `escape_for_stdout` (`client.py`), per code point.
pub fn escape_for_stdout(value: &str) -> String {
    let mut out = String::from("\"");
    for c in value.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\t' => out.push_str("\\t"),
            '\r' => out.push_str("\\r"),
            c if (c as u32) < 32 || (c as u32) > 126 => {
                out.push_str(&format!("\\x{:02x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Python `str.split(maxsplit=n)` on whitespace.
fn split_max(text: &str, n: usize) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut rest = text.trim_start();
    while !rest.is_empty() {
        if parts.len() == n {
            parts.push(rest.trim_end());
            break;
        }
        match rest.find(char::is_whitespace) {
            Some(end) => {
                parts.push(&rest[..end]);
                rest = rest[end..].trim_start();
            }
            None => {
                parts.push(rest);
                break;
            }
        }
    }
    parts
}

fn s(v: &str) -> Value {
    Value::String(v.into())
}

fn map(entries: Vec<(Value, Value)>) -> Value {
    Value::Map(entries)
}

/// `RNS.prettysize`.
fn prettysize(num: f64) -> String {
    rns_tools::format::prettysize(num, "B")
}

/// Python truthiness of an unpacked value.
fn is_falsy(value: &Value) -> bool {
    match value {
        Value::Nil => true,
        Value::Boolean(b) => !b,
        Value::Integer(i) => i.as_i64() == Some(0) || i.as_u64() == Some(0),
        Value::F32(f) => *f == 0.0,
        Value::F64(f) => *f == 0.0,
        Value::String(s) => s.as_bytes().is_empty(),
        Value::Binary(b) => b.is_empty(),
        Value::Array(a) => a.is_empty(),
        Value::Map(m) => m.is_empty(),
        Value::Ext(..) => false,
    }
}

/// Python `bytes.decode("utf-8", errors="ignore")`.
fn decode_ignore(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).replace('\u{FFFD}', "")
}

/// The helper's state for one run of git's stdin protocol.
pub struct RemoteHelper<T: Transport> {
    pub transport: T,
    pub repo_path: String,
    pub ref_batch_size: usize,
    /// Directory git commands run in; git itself passes `GIT_DIR`.
    pub git_dir: PathBuf,
    pub progress_enabled: bool,
    /// `remote_refs` from the last `list`, in insertion order.
    remote_refs: Vec<(String, String)>,
}

enum Flow {
    Continue,
    BrokenPipe,
}

fn broken(e: &std::io::Error) -> bool {
    e.kind() == std::io::ErrorKind::BrokenPipe
}

impl<T: Transport> RemoteHelper<T> {
    pub fn new(transport: T, repo_path: String, ref_batch_size: usize, git_dir: PathBuf) -> Self {
        Self {
            transport,
            repo_path,
            ref_batch_size,
            git_dir,
            progress_enabled: false,
            remote_refs: Vec::new(),
        }
    }

    fn git(&self, args: &[&str]) -> Command {
        let mut cmd = Command::new("git");
        cmd.args(args).current_dir(&self.git_dir);
        cmd
    }

    fn git_ok(&self, args: &[&str]) -> Option<String> {
        let out = self.git(args).stdin(Stdio::null()).output().ok()?;
        out.status
            .success()
            .then(|| String::from_utf8_lossy(&out.stdout).trim().to_string())
    }

    fn send(&mut self, path: &str, data: Value) -> Result<Response, Abort> {
        self.transport
            .request(path, data)
            .ok_or_else(|| Abort::new("Request failed or timed out"))
    }

    /// The command loop (`client.py`), from `run()` after the link is up.
    pub fn run(
        &mut self,
        stdin: &mut dyn BufRead,
        stdout: &mut dyn Write,
        stderr: &mut dyn Write,
    ) -> Result<(), Abort> {
        self.progress_enabled = false;
        let mut fetch_queue: Vec<(String, String)> = Vec::new();
        let mut push_queue: Vec<(String, String)> = Vec::new();
        let mut raw = Vec::new();
        loop {
            raw.clear();
            match stdin.read_until(b'\n', &mut raw) {
                Ok(0) | Err(_) => break,
                Ok(_) => {}
            }
            let text = String::from_utf8_lossy(&raw);
            let line = text.trim();
            let written = if line == "capabilities" {
                stdout
                    .write_all(b"list\nfetch\npush\noption\n\n")
                    .and_then(|()| stdout.flush())
            } else if line == "list" {
                self.handle_list(stdout, false)?
            } else if line.starts_with("list ") {
                self.handle_list(stdout, true)?
            } else if line.starts_with("option") {
                let parts = split_max(line, 2);
                let name = parts.get(1).copied().unwrap_or("");
                let value = parts.get(2).copied().unwrap_or("");
                let reply: &[u8] = if name == "progress" {
                    self.progress_enabled =
                        matches!(value.to_lowercase().as_str(), "true" | "1" | "yes");
                    b"ok\n"
                } else {
                    b"unsupported\n"
                };
                stdout.write_all(reply).and_then(|()| stdout.flush())
            } else if line.starts_with("fetch") {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() < 3 {
                    return Err(Abort::exception("IndexError: list index out of range"));
                }
                let entry = (parts[1].to_string(), parts[2].to_string());
                if !fetch_queue.contains(&entry) {
                    fetch_queue.push(entry);
                }
                push_queue.clear();
                Ok(())
            } else if line.starts_with("push") {
                let parts: Vec<&str> = line.split_whitespace().collect();
                let Some(refspec) = parts.get(1) else {
                    return Err(Abort::exception("IndexError: list index out of range"));
                };
                let Some((local, remote)) = refspec.split_once(':') else {
                    return Err(Abort::exception(
                        "ValueError: not enough values to unpack (expected 2, got 1)",
                    ));
                };
                push_queue.push((local.to_string(), remote.to_string()));
                fetch_queue.clear();
                Ok(())
            } else if line.is_empty() {
                let fetches = std::mem::take(&mut fetch_queue);
                let pushes = std::mem::take(&mut push_queue);
                let flow = match self.process_fetch_queue(fetches, stderr)? {
                    Flow::Continue => self.process_push_queue(pushes, stdout, stderr)?,
                    Flow::BrokenPipe => Flow::BrokenPipe,
                };
                match flow {
                    Flow::Continue => stdout.write_all(b"\n").and_then(|()| stdout.flush()),
                    Flow::BrokenPipe => break,
                }
            } else {
                return Err(Abort::new(format!("Unknown Git command: {line}")));
            };
            if let Err(e) = written
                && broken(&e)
            {
                break;
            }
        }
        let _ = stdout.flush();
        Ok(())
    }

    /// `handle_git_list` (`client.py`).
    fn handle_list(
        &mut self,
        stdout: &mut dyn Write,
        for_push: bool,
    ) -> Result<std::io::Result<()>, Abort> {
        let data = map(vec![
            (Value::from(IDX_REPOSITORY), s(&self.repo_path)),
            (s("for_push"), Value::Boolean(for_push)),
        ]);
        let response = match self.send(PATH_LIST, data)? {
            Response::Bytes(b) if !b.is_empty() => b,
            _ => return Err(Abort::new("Invalid list response from server")),
        };
        let payload = &response[1..];
        if response[0] != 0 {
            return Err(Abort::new(format!(
                "Server refused list: {}",
                decode_ignore(payload)
            )));
        }
        let text = std::str::from_utf8(payload).map_err(|e| {
            Abort::exception(format!(
                "UnicodeDecodeError: 'utf-8' codec can't decode the list response: {e}"
            ))
        })?;
        self.remote_refs.clear();
        for line in text.split('\n') {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            if let Some((sha, name)) = line.split_once(' ') {
                if name == "HEAD" {
                    continue;
                }
                match self.remote_refs.iter_mut().find(|(r, _)| r == name) {
                    Some(entry) => entry.1 = sha.to_string(),
                    None => self.remote_refs.push((name.to_string(), sha.to_string())),
                }
            }
        }
        Ok(stdout
            .write_all(text.as_bytes())
            .and_then(|()| stdout.write_all(b"\n"))
            .and_then(|()| stdout.flush()))
    }

    /// Remote ref SHAs whose objects exist locally (`git cat-file -t`).
    fn local_remote_shas(&self) -> Vec<String> {
        self.remote_refs
            .iter()
            .filter(|(_, sha)| self.git_ok(&["cat-file", "-t", sha]).is_some())
            .map(|(_, sha)| sha.clone())
            .collect()
    }

    /// `process_fetch_queue` (`client.py`).
    fn process_fetch_queue(
        &mut self,
        mut queue: Vec<(String, String)>,
        stderr: &mut dyn Write,
    ) -> Result<Flow, Abort> {
        if queue.is_empty() {
            return Ok(Flow::Continue);
        }
        let have_shas = self.local_remote_shas();
        // Upstream's batch size 0 sends an empty batch each time and never
        // shrinks the queue; its node answers "No refs specified", which aborts.
        while !queue.is_empty() {
            let take = self.ref_batch_size.min(queue.len());
            let batch: Vec<_> = queue.drain(..take).collect();
            let mut refs = Vec::new();
            for (sha, name) in &batch {
                let mut entry = vec![(s("sha"), s(sha)), (s("ref"), s(name))];
                if let Some(local) = self.git_ok(&["rev-parse", name])
                    && &local != sha
                {
                    entry.push((s("have"), s(&local)));
                }
                refs.push(map(entry));
            }
            let mut data = vec![
                (Value::from(IDX_REPOSITORY), s(&self.repo_path)),
                (s("refs"), Value::Array(refs)),
            ];
            if !have_shas.is_empty() {
                data.push((
                    s("have"),
                    Value::Array(have_shas.iter().map(|h| s(h)).collect()),
                ));
            }
            match self.send(PATH_FETCH, map(data))? {
                Response::Bytes(b) if b.is_empty() => {
                    return Err(Abort::new("No data in fetch response for batch"));
                }
                Response::Bytes(b) => {
                    if b[0] != 0 {
                        return Err(Abort::new(format!(
                            "Fetch failed for batch: {}",
                            decode_ignore(&b[1..])
                        )));
                    }
                }
                Response::Other(v) if is_falsy(&v) => {
                    return Err(Abort::new("No data in fetch response for batch"));
                }
                Response::Other(_) => return Err(Abort::new("Invalid fetch response for batch")),
                Response::File { metadata, .. } if is_falsy(&metadata) => {
                    return Err(Abort::new("Invalid fetch response for batch"));
                }
                Response::File { path, metadata } => {
                    self.unbundle(&path, &metadata, stderr)?;
                    let _ = std::fs::remove_file(&path);
                }
            }
        }
        Ok(Flow::Continue)
    }

    fn unbundle(&self, path: &Path, metadata: &Value, stderr: &mut dyn Write) -> Result<(), Abort> {
        let status = metadata.as_map().and_then(|m| {
            m.iter()
                .find(|(k, _)| k.as_u64() == Some(u64::from(IDX_RESULT_CODE)))
                .map(|(_, v)| v.clone())
        });
        let Some(status) = status else {
            return Err(Abort::new("No result metadata on bundle response"));
        };
        if status.as_u64() != Some(0) {
            return Err(Abort::new("Unknown remote state for batch ref fetch"));
        }
        let bundle = path.to_string_lossy().to_string();
        if self.progress_enabled {
            let size = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
            let _ = writeln!(
                stderr,
                "Transferring: 100% ({}).                       ",
                prettysize(size as f64)
            );
            let _ = stderr.flush();
        }
        let verified = self
            .git(&["bundle", "verify", "-q", &bundle])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        if !verified.is_ok_and(|s| s.success()) {
            return Err(Abort::new("Bundle verification failed for batch"));
        }
        let mut args = vec!["bundle", "unbundle"];
        if self.progress_enabled {
            args.push("--progress");
        }
        args.push(&bundle);
        let unbundled = self
            .git(&args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(if self.progress_enabled {
                Stdio::inherit()
            } else {
                Stdio::null()
            })
            .status();
        if !unbundled.is_ok_and(|s| s.success()) {
            return Err(Abort::new(
                "Bundle unbundle failed for batch: Non-zero return code",
            ));
        }
        Ok(())
    }

    /// Send a push or delete request and turn its reply into the status line's error, if any.
    fn status_request(&mut self, path: &str, data: Value) -> Result<Option<String>, Abort> {
        Ok(match self.send(path, data)? {
            Response::Bytes(b) if !b.is_empty() => (b[0] != 0).then(|| decode_ignore(&b[1..])),
            _ => Some("No response from server".into()),
        })
    }

    /// `process_push_queue` (`client.py`).
    fn process_push_queue(
        &mut self,
        queue: Vec<(String, String)>,
        stdout: &mut dyn Write,
        stderr: &mut dyn Write,
    ) -> Result<Flow, Abort> {
        for (local_ref, remote_ref) in queue {
            let error = self.push_one(&local_ref, &remote_ref, stderr)?;
            let line = match error {
                None => format!("ok {remote_ref}\n"),
                Some(msg) => format!("error {remote_ref} {}\n", escape_for_stdout(&msg)),
            };
            if let Err(e) = stdout
                .write_all(line.as_bytes())
                .and_then(|()| stdout.flush())
                && broken(&e)
            {
                return Ok(Flow::BrokenPipe);
            }
        }
        Ok(Flow::Continue)
    }

    fn push_one(
        &mut self,
        local_ref: &str,
        remote_ref: &str,
        stderr: &mut dyn Write,
    ) -> Result<Option<String>, Abort> {
        let repo = (Value::from(IDX_REPOSITORY), s(&self.repo_path));
        if local_ref.is_empty() {
            let data = map(vec![repo, (s("ref"), s(remote_ref))]);
            return self.status_request(PATH_DELETE, data);
        }
        let force = local_ref.starts_with('+');
        let local_ref = local_ref.strip_prefix('+').unwrap_or(local_ref);
        let Some(local_sha) = self.git_ok(&["rev-parse", local_ref]) else {
            return Ok(Some(format!("Could not resolve local ref {local_ref}")));
        };
        let tmp = tempfile::tempdir().map_err(|e| {
            Abort::exception(format!("Could not create a temporary directory: {e}"))
        })?;
        let bundle_path = tmp.path().join("push.bundle");
        let bundle = bundle_path.to_string_lossy().to_string();
        let excludes: Vec<String> = self
            .local_remote_shas()
            .into_iter()
            .map(|sha| format!("^{sha}"))
            .collect();
        let mut args = vec!["bundle", "create", bundle.as_str(), local_ref];
        args.extend(excludes.iter().map(String::as_str));
        if self.progress_enabled {
            args.insert(2, "--progress");
        }
        let created = self
            .git(&args)
            .stdin(Stdio::null())
            .output()
            .map_err(|e| Abort::exception(format!("FileNotFoundError: {e}")))?;
        let data = if created.status.success() {
            let bundle_data = std::fs::read(&bundle_path)
                .map_err(|e| Abort::exception(format!("FileNotFoundError: {e}")))?;
            map(vec![
                repo,
                (s("local_ref"), s(local_ref)),
                (s("remote_ref"), s(remote_ref)),
                (s("force"), Value::Boolean(force)),
                (s("bundle"), Value::Binary(bundle_data)),
            ])
        } else {
            let err = String::from_utf8_lossy(&created.stderr);
            if !err.to_lowercase().contains("empty bundle") {
                if self.progress_enabled && !err.is_empty() {
                    let _ = stderr.write_all(err.as_bytes());
                }
                return Ok(Some("Bundle creation failed".into()));
            }
            let operation = map(vec![
                (s("action"), s("update_ref")),
                (s("ref"), s(remote_ref)),
                (s("sha"), s(&local_sha)),
                (s("force"), Value::Boolean(force)),
            ]);
            map(vec![repo, (s("operations"), Value::Array(vec![operation]))])
        };
        self.status_request(PATH_PUSH, data)
    }
}
