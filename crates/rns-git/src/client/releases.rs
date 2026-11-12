//! `rngit release` (`ReticulumGitClient` release methods, `server.py:715-1239@1.6.0`).

use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Duration;

use rmpv::Value;
use rns_identity::identity::Identity;
use rns_tools::rsg::{
    Message, RequiredSigner, RsmStructure, check_release_rsm_structure, create_rsg,
    extract_signed_rsg_data, py_contains, py_index, validate_rsg,
};

use crate::server::client::ClientConfig;
use crate::server::releases::py_basename;
use crate::server::{IDX_REPOSITORY, RES_DISALLOWED, RES_INVALID_REQ, RES_NOT_FOUND};

/// The `rngit release` operations (`server.py:89-98`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReleaseOp {
    List,
    View,
    Fetch,
    Verify,
    Create,
    Latest,
    Delete,
}

impl ReleaseOp {
    pub fn parse(name: &str) -> Option<Self> {
        Some(match name {
            "list" => ReleaseOp::List,
            "view" => ReleaseOp::View,
            "fetch" => ReleaseOp::Fetch,
            "verify" => ReleaseOp::Verify,
            "create" => ReleaseOp::Create,
            "latest" => ReleaseOp::Latest,
            "delete" => ReleaseOp::Delete,
            _ => return None,
        })
    }

    /// `verify` is `fetch_release(..., offline=True)`.
    pub fn offline(self) -> bool {
        matches!(self, ReleaseOp::Verify)
    }
}

/// A reply as `send_request` hands it back.
#[derive(Debug)]
pub enum Response {
    Bytes(Vec<u8>),
    /// A file response: the spooled body and its metadata.
    File {
        path: PathBuf,
        metadata: Value,
    },
    Other(Value),
}

/// The Link to the remote node. `None` is "Request failed or timed out".
pub trait Remote {
    fn request(&mut self, data: Value, timeout: Duration) -> Option<Response>;
}

/// How a release command ends when it does not return normally.
#[derive(Debug, PartialEq, Eq)]
pub enum Fail {
    /// `abort(msg)`: the message on stdout, exit 1.
    Abort(String),
    /// An exception upstream does not catch: a traceback on stderr, exit 1.
    Raised(String),
}

fn abort<T>(message: impl Into<String>) -> Result<T, Fail> {
    Err(Fail::Abort(message.into()))
}

/// Opens the Link; the argument is the abort text when it cannot.
pub type Connect<'a> = dyn FnMut(&str, &str) -> Result<Box<dyn Remote>, Fail> + 'a;

/// `RNS.prettyhexrep`.
pub fn prettyhexrep(hash: &[u8]) -> String {
    format!("<{}>", hex::encode(hash))
}

/// `os.path.expanduser`.
pub fn expand_user(path: &str) -> PathBuf {
    let home = || std::env::var_os("HOME").map(PathBuf::from);
    if path == "~" {
        return home().unwrap_or_else(|| PathBuf::from(path));
    }
    match (path.strip_prefix("~/"), home()) {
        (Some(rest), Some(home)) => home.join(rest),
        _ => PathBuf::from(path),
    }
}

fn s(v: &str) -> Value {
    Value::from(v)
}

fn request(repo_path: &str, fields: Vec<(&str, Value)>) -> Value {
    let mut map = vec![(Value::from(IDX_REPOSITORY), s(repo_path))];
    map.extend(fields.into_iter().map(|(k, v)| (s(k), v)));
    Value::Map(map)
}

/// The value of `key` in a map, or `None`.
pub fn request_field<'a>(map: &'a [(Value, Value)], key: &str) -> Option<&'a Value> {
    map.iter()
        .find(|(k, _)| k.as_str() == Some(key))
        .map(|(_, v)| v)
}

/// `response[1:].decode("utf-8", errors="ignore")`.
fn message_of(response: &[u8]) -> String {
    response
        .get(1..)
        .unwrap_or_default()
        .utf8_chunks()
        .map(|c| c.valid())
        .collect()
}

/// The common `bytes` reply check: `Ok` is the body after a zero status.
fn status_body<'a>(response: &'a Option<Response>, prefix: &str) -> Result<&'a [u8], Fail> {
    let Some(Response::Bytes(bytes)) = response else {
        return abort("No response from remote");
    };
    if bytes.is_empty() {
        return abort("No response from remote");
    }
    if bytes[0] != 0 {
        return abort(format!("{prefix}{}", message_of(bytes)));
    }
    Ok(&bytes[1..])
}

fn send(remote: &mut dyn Remote, data: Value, timeout: u64) -> Result<Option<Response>, Fail> {
    match remote.request(data, Duration::from_secs(timeout)) {
        None => abort("Request failed or timed out"),
        Some(response) => Ok(Some(response)),
    }
}

/// Python `f"{text:<width}"`.
fn pad(text: &str, width: usize) -> String {
    format!(
        "{text}{}",
        " ".repeat(width.saturating_sub(text.chars().count()))
    )
}

fn first_chars(text: &str, n: usize) -> String {
    text.chars().take(n).collect()
}

/// `time.strftime(fmt, time.localtime(ts))` for the two formats used here.
fn strftime(ts: i64, seconds: bool) -> String {
    let time = ts as nix::libc::time_t;
    let mut tm = std::mem::MaybeUninit::<nix::libc::tm>::zeroed();
    // SAFETY: both pointers are valid for the call; localtime_r is reentrant.
    if unsafe { nix::libc::localtime_r(&time, tm.as_mut_ptr()) }.is_null() {
        return String::new();
    }
    // SAFETY: localtime_r filled `tm` when it returned non-null.
    let tm = unsafe { tm.assume_init() };
    let mut out = format!(
        "{:04}-{:02}-{:02} {:02}:{:02}",
        tm.tm_year + 1900,
        tm.tm_mon + 1,
        tm.tm_mday,
        tm.tm_hour,
        tm.tm_min
    );
    if seconds {
        out.push_str(&format!(":{:02}", tm.tm_sec));
    }
    out
}

fn py_str(value: &Value) -> String {
    rns_tools::rsg::pyfmt::py_str(value)
}

/// `list_releases` after the Link is up (`server.py:774-818`).
pub fn list_releases(
    out: &mut dyn Write,
    remote: &mut dyn Remote,
    repo_path: &str,
) -> Result<(), Fail> {
    let response = send(
        remote,
        request(repo_path, vec![("operation", s("list"))]),
        120,
    )?;
    let _ = write!(out, "\r                       \r");
    let body = status_body(&response, "Server error: ")?;
    let unpacked = if body.is_empty() {
        Value::Array(Vec::new())
    } else {
        rns_tools::rsg::unpackb(body)
            .ok_or_else(|| Fail::Abort("Error listing releases: unpack failed".into()))?
    };
    let (releases, latest) = match &unpacked {
        Value::Array(items) => (items.clone(), Value::Nil),
        Value::Map(map) => {
            let releases = request_field(map, "releases")
                .cloned()
                .unwrap_or(Value::Nil);
            let latest = request_field(map, "latest").cloned().unwrap_or(Value::Nil);
            let Value::Array(releases) = releases else {
                return abort("Error listing releases: 'releases'");
            };
            (releases, latest)
        }
        _ => return abort("Invalid release data format from remote"),
    };
    if releases.is_empty() {
        let _ = writeln!(out, "No releases for this repository");
        return Ok(());
    }
    let _ = writeln!(
        out,
        "{} {} {} {} Notes",
        pad("Tag", 10),
        pad("Status", 10),
        pad("Created", 17),
        pad("Objs", 5)
    );
    let _ = writeln!(out, "{}", "-".repeat(80));
    for release in &releases {
        let map = release.as_map().map(Vec::as_slice).unwrap_or_default();
        let text = |key: &str, default: &str| {
            request_field(map, key)
                .and_then(Value::as_str)
                .unwrap_or(default)
                .to_string()
        };
        let created_ts = request_field(map, "created")
            .and_then(Value::as_i64)
            .unwrap_or(0);
        let created = if created_ts != 0 {
            strftime(created_ts, false)
        } else {
            "unknown".into()
        };
        let artifacts = request_field(map, "artifacts").map_or_else(|| "0".into(), py_str);
        let preview = text("preview", "");
        // `"".splitlines()[0]` raises inside the try.
        let Some(line) = crate::server::releases::splitlines(&preview)
            .first()
            .copied()
        else {
            return abort("Error listing releases: list index out of range");
        };
        let _ = writeln!(
            out,
            "{} {} {} {} {}",
            pad(&first_chars(&text("tag", "unknown"), 10), 10),
            pad(&first_chars(&text("status", "unknown"), 9), 10),
            pad(&created, 17),
            pad(&artifacts, 5),
            first_chars(line, 34)
        );
    }
    if let Some(latest) = latest.as_str().filter(|l| !l.is_empty()) {
        let _ = writeln!(out, "\nThe latest release is: {latest}");
    }
    Ok(())
}

/// `view_release` after the Link is up (`server.py:832-877`).
pub fn view_release(
    out: &mut dyn Write,
    remote: &mut dyn Remote,
    repo_path: &str,
    target: &str,
) -> Result<(), Fail> {
    let data = request(
        repo_path,
        vec![("operation", s("view")), ("tag", s(target))],
    );
    let response = send(remote, data, 300)?;
    let _ = write!(out, "\r                       \r");
    let body = status_body(&response, "Remote error: ")?;
    if body.is_empty() {
        return abort("Empty response from remote");
    }
    let release = rns_tools::rsg::unpackb(body);
    let Some(Value::Map(map)) = release else {
        return abort("Error viewing release: 'get'");
    };
    let text = |key: &str, default: &str| {
        request_field(&map, key)
            .and_then(Value::as_str)
            .unwrap_or(default)
            .to_string()
    };
    let _ = writeln!(out, "Release : {}", text("tag", target));
    let _ = writeln!(out, "Status  : {}", text("status", "unknown"));
    let created = request_field(&map, "created")
        .and_then(Value::as_i64)
        .unwrap_or(0);
    if created != 0 {
        let _ = writeln!(out, "Created : {}", strftime(created, true));
    }
    let _ = writeln!(
        out,
        "Thanks  : {}",
        request_field(&map, "thanks").map_or_else(|| "0".into(), py_str)
    );
    let notes = text("notes", "");
    if !notes.is_empty() {
        let _ = writeln!(out, "\nRelease Notes\n=============\n\n{notes}");
    }
    let artifacts = request_field(&map, "artifacts")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    if !artifacts.is_empty() {
        let header = format!("Artifacts ({})", artifacts.len());
        let _ = writeln!(out, "\n{header}\n{}", "=".repeat(header.chars().count()));
        for artifact in &artifacts {
            let map = artifact.as_map().map(Vec::as_slice).unwrap_or_default();
            let size = request_field(map, "size")
                .and_then(Value::as_u64)
                .unwrap_or(0);
            let size = if size != 0 {
                rns_tools::format::prettysize(size as f64, "B")
            } else {
                "0 B".into()
            };
            let name = request_field(map, "name")
                .and_then(Value::as_str)
                .unwrap_or("unknown");
            let _ = writeln!(out, " - {name} ({size})");
        }
    }
    let _ = writeln!(out);
    Ok(())
}

/// `delete_release` and `latest_release` after the Link is up
/// (`server.py:1160-1192`, `1203-1239`): confirm, then send.
pub fn confirm_and_send(
    out: &mut dyn Write,
    input: &mut dyn std::io::BufRead,
    remote: &mut dyn Remote,
    repo_path: &str,
    operation: &str,
    target: &str,
) -> Result<(), Fail> {
    let (question, cancelled, done) = if operation == "delete" {
        (
            format!("Are you sure you want to delete release {target}? [y/N]: "),
            "Deletion cancelled",
            format!("Release {target} deleted"),
        )
    } else {
        (
            format!("Are you sure you want to set {target} as the latest release? [y/N]: "),
            "Update cancelled",
            format!("Release {target} set as latest"),
        )
    };
    let _ = write!(out, "\r                       \r{question}");
    let _ = out.flush();
    let mut line = String::new();
    let confirm = match input.read_line(&mut line) {
        Ok(0) | Err(_) => "n".to_string(),
        Ok(_) => line.trim().to_lowercase(),
    };
    if confirm != "y" {
        let _ = writeln!(out, "{cancelled}");
        return Ok(());
    }
    let response = send(
        remote,
        request(
            repo_path,
            vec![("operation", s(operation)), ("tag", s(target))],
        ),
        120,
    )?;
    status_body(&response, "Remote error: ")?;
    let _ = writeln!(out, "{done}");
    Ok(())
}

/// `fnmatch.fnmatch` on POSIX (case-sensitive): `*`, `?`, `[seq]`, `[!seq]`.
pub fn fnmatch(name: &str, pattern: &str) -> bool {
    type Class = (Vec<(char, char)>, bool, usize);
    fn class(pattern: &[char]) -> Option<Class> {
        let mut i = 1;
        let negated = pattern.get(i) == Some(&'!');
        if negated {
            i += 1;
        }
        let start = i;
        let mut ranges = Vec::new();
        while i < pattern.len() && (pattern[i] != ']' || i == start) {
            if i + 2 < pattern.len() && pattern[i + 1] == '-' && pattern[i + 2] != ']' {
                ranges.push((pattern[i], pattern[i + 2]));
                i += 3;
            } else {
                ranges.push((pattern[i], pattern[i]));
                i += 1;
            }
        }
        (i < pattern.len()).then_some((ranges, negated, i + 1))
    }
    fn go(name: &[char], pattern: &[char]) -> bool {
        match pattern.first() {
            None => name.is_empty(),
            Some('*') => (0..=name.len()).any(|i| go(&name[i..], &pattern[1..])),
            Some('?') => !name.is_empty() && go(&name[1..], &pattern[1..]),
            Some('[') => match class(pattern) {
                Some((ranges, negated, used)) => {
                    let Some(&c) = name.first() else { return false };
                    let hit = ranges.iter().any(|&(a, b)| a <= c && c <= b);
                    hit != negated && go(&name[1..], &pattern[used..])
                }
                None => name.first() == Some(&'[') && go(&name[1..], &pattern[1..]),
            },
            Some(&c) => name.first() == Some(&c) && go(&name[1..], &pattern[1..]),
        }
    }
    let name: Vec<char> = name.chars().collect();
    let pattern: Vec<char> = pattern.chars().collect();
    go(&name, &pattern)
}

/// `signer` on fetch/verify: a 32-hex required signer hash (`server.py:881-884`).
pub fn required_signer(signer: Option<&str>) -> Result<Option<Vec<u8>>, Fail> {
    let Some(signer) = signer.filter(|s| !s.is_empty()) else {
        return Ok(None);
    };
    if signer.chars().count() != 32 {
        return abort("Invalid required signer identity hash length");
    }
    rns_tools::rsg::pyfmt::py_fromhex(signer)
        .map(Some)
        .map_err(|e| Fail::Abort(format!("Invalid required signer identity hash: {e}")))
}

/// A manifest that validated and passed the structure check.
struct Manifest {
    rsg: Vec<u8>,
    meta: Vec<(Value, Value)>,
    signer: [u8; 16],
}

impl Manifest {
    fn text(&self, key: &str) -> String {
        request_field(&self.meta, key)
            .map(py_str)
            .unwrap_or_default()
    }
}

/// The manifest checks of `fetch_release` (`server.py:888-898`, `936-945`).
/// `inside_try` selects how an exception surfaces.
fn check_manifest(
    rsg: Vec<u8>,
    required: Option<&[u8]>,
    inside_try: bool,
) -> Result<Manifest, Fail> {
    let raised = |e: String| {
        if inside_try {
            Fail::Abort(format!("Error fetching release: {e}"))
        } else {
            Fail::Raised(e)
        }
    };
    let contents = extract_signed_rsg_data(&rsg);
    if !py_contains(contents.as_ref(), "message").map_err(raised)? {
        return abort("No embedded message in release manifest");
    }
    let message = py_index(contents.as_ref().expect("checked"), "message")
        .map_err(raised)?
        .clone();
    let valid = validate_rsg(
        &rsg,
        Message::Unpacked(&message),
        required.map(RequiredSigner::Hash),
    )
    .map_err(raised)?;
    let Some(valid) = valid else {
        return abort(match required {
            Some(hash) => format!(
                "Release manifest not signed by {}, aborting",
                prettyhexrep(hash)
            ),
            None => "Could not validate release manifest signature".to_string(),
        });
    };
    match check_release_rsm_structure(&valid.signed_data).map_err(raised)? {
        RsmStructure::Valid => {}
        RsmStructure::Invalid(text) => return abort(text),
    }
    let meta = match py_index(&valid.signed_data, "meta") {
        Ok(Value::Map(meta)) => meta.clone(),
        _ => Vec::new(),
    };
    Ok(Manifest {
        rsg,
        meta,
        signer: valid.signer_hash,
    })
}

/// `validate_rsg(rsg, fh, required_signer)` over a file; an exception counts
/// as the abort upstream's surrounding try produces.
fn file_valid(rsg: &[u8], path: &Path, required: Option<&[u8]>) -> Result<bool, Fail> {
    let mut file = std::fs::File::open(path).map_err(|e| {
        Fail::Abort(format!(
            "Error fetching release: {}",
            rns_tools::rsg::pyfmt::py_os_error(&e, &path.display().to_string())
        ))
    })?;
    validate_rsg(
        rsg,
        Message::File(&mut file),
        required.map(RequiredSigner::Hash),
    )
    .map(|v| v.is_some())
    .map_err(|e| Fail::Abort(format!("Error fetching release: {e}")))
}

/// `fetch_release` (`server.py:879-1013`); `verify` is `offline`. Files land
/// in the current directory. `Ok` is the exit code.
pub fn fetch_release(
    out: &mut dyn Write,
    config: &ClientConfig,
    connect: &mut Connect<'_>,
    remote: Option<&str>,
    target: Option<&str>,
    signer: Option<&str>,
    offline: bool,
) -> Result<i32, Fail> {
    let target = match target {
        None if offline => "latest:all",
        None => {
            return abort(if remote.is_none() {
                "No remote specified"
            } else {
                "No target specified"
            });
        }
        Some(t) => t,
    };
    let Some(mut remote) = remote.map(str::to_string) else {
        return abort("No remote specified");
    };
    let required = required_signer(signer)?;

    let mut local_manifest: Option<(String, String)> = None;
    let expanded = expand_user(&remote);
    if remote.ends_with(".rsm") && expanded.is_file() {
        let rsg = std::fs::read(&expanded).map_err(|e| Fail::Raised(e.to_string()))?;
        let manifest = check_manifest(rsg, required.as_deref(), false)?;
        let _ = writeln!(
            out,
            "Valid release manifest signature, signed by {}",
            prettyhexrep(&manifest.signer)
        );
        let origin = match request_field(&manifest.meta, "origin") {
            Some(Value::Binary(b)) => hex::encode(b),
            _ => String::new(),
        };
        remote = format!("rns://{origin}/{}", manifest.text("path"));
        let path = expanded.display().to_string();
        let name = expanded
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        // `local_manifest.replace(os.path.basename(local_manifest), "")`
        let dir = path.replace(&name, "");
        local_manifest = Some((path, dir));
        let _ = writeln!(out, "Release origin is {remote}");
    }
    if offline && local_manifest.is_none() {
        return abort("Cannot perform offline verification without a local manifest");
    }
    let mut link = if offline {
        None
    } else {
        Some(connect(&remote, "Link establishment failed")?)
    };

    let (_, group, repo) = config.parse_remote_url(&remote).map_err(Fail::Abort)?;
    let repo_path = format!("{group}/{repo}");
    let parts: Vec<&str> = target.split(':').collect();
    if parts.len() < 2 {
        return abort("Invalid release specification");
    }
    let (tag, artifact) = (parts[0], parts[1]);
    let spool = tempfile::TempDir::new()
        .map_err(|e| Fail::Abort(format!("Error fetching release: {e}")))?;

    let mut indent = "";
    let mut fetch = |name: &str, indent: &str, out: &mut dyn Write| -> Result<PathBuf, Fail> {
        if let Some((path, dir)) = local_manifest.as_ref().filter(|_| offline) {
            return Ok(PathBuf::from(if name == "manifest.rsm" {
                path.clone()
            } else {
                format!("{dir}{name}")
            }));
        }
        let link = link.as_mut().expect("online");
        let data = request(
            &repo_path,
            vec![
                ("operation", s("fetch")),
                ("tag", s(tag)),
                ("artifact", s(name)),
            ],
        );
        let response = send(link.as_mut(), data, 7200)?;
        let _ = write!(out, "\r                       \r");
        match response {
            Some(Response::File { path, metadata }) if !matches!(metadata, Value::Nil) => {
                if metadata
                    .as_map()
                    .is_none_or(|m| request_field(m, "name").is_none())
                {
                    return abort("Invalid result metadata on fetch response");
                }
                let kept = spool.path().join(path.file_name().unwrap_or_default());
                std::fs::rename(&path, &kept)
                    .or_else(|_| std::fs::copy(&path, &kept).map(|_| ()))
                    .map_err(|e| Fail::Abort(format!("Error fetching release: {e}")))?;
                let size = std::fs::metadata(&kept).map(|m| m.len()).unwrap_or(0);
                let _ = writeln!(
                    out,
                    "{indent}Transferring {name}: 100% ({}){}",
                    rns_tools::format::prettysize(size as f64, "B"),
                    " ".repeat(25)
                );
                Ok(kept)
            }
            Some(Response::Bytes(bytes)) if !bytes.is_empty() => {
                let text = |fallback: &str| {
                    if bytes.len() > 1 {
                        message_of(&bytes)
                    } else {
                        fallback.to_string()
                    }
                };
                abort(match bytes[0] {
                    RES_INVALID_REQ => "Remote error: Invalid request".to_string(),
                    RES_NOT_FOUND => text("Not found"),
                    RES_DISALLOWED => text("Not allowed"),
                    _ => format!("Remote error: {}", text("Unknown error")),
                })
            }
            _ => abort("No response from remote"),
        }
    };

    let manifest_path = fetch("manifest.rsm", indent, out)?;
    let rsg = std::fs::read(&manifest_path)
        .map_err(|e| Fail::Abort(format!("Error fetching release: {e}")))?;
    let manifest = check_manifest(rsg, required.as_deref(), true)?;
    let _ = writeln!(
        out,
        "Release manifest validated, signed by {}",
        prettyhexrep(&manifest.signer)
    );
    let manifest_out = format!("{}_{}.rsm", manifest.text("name"), manifest.text("version"));
    let manifest_out = PathBuf::from(py_basename(&manifest_out));
    std::fs::write(&manifest_out, &manifest.rsg)
        .map_err(|e| Fail::Abort(format!("Error fetching release: {e}")))?;

    let artifacts: Vec<(String, Vec<u8>)> = request_field(&manifest.meta, "artifacts")
        .and_then(Value::as_array)
        .map(|entries| {
            entries
                .iter()
                .filter_map(|e| {
                    let map = e.as_map()?;
                    let name = request_field(map, "name")?.as_str()?.to_string();
                    let Value::Binary(rsg) = request_field(map, "rsg")? else {
                        return None;
                    };
                    Some((name, rsg.clone()))
                })
                .collect()
        })
        .unwrap_or_default();
    if artifacts.is_empty() {
        return abort("Release manifest contains no artifacts");
    }
    let selected: Vec<&(String, Vec<u8>)> = artifacts
        .iter()
        .filter(|(name, _)| artifact == "all" || fnmatch(name, artifact))
        .collect();
    if selected.is_empty() {
        return abort("No available artifacts specified for fetch");
    }
    let plural = if selected.len() == 1 { "" } else { "s" };
    let _ = writeln!(
        out,
        "{} {} artifact{plural}...",
        if offline { "Validating" } else { "Fetching" },
        selected.len()
    );
    indent = "  ";
    let mut valid_count = 0;
    for (entry_name, rsg) in selected.iter().map(|e| (&e.0, &e.1)) {
        let name = py_basename(entry_name).to_string();
        if !offline && Path::new(&name).exists() {
            if file_valid(rsg, Path::new(&name), required.as_deref())? {
                let _ = writeln!(out, "Existing file {name} validated, not fetching again");
                continue;
            }
            let _ = writeln!(
                out,
                "Existing file {name} does not match manifest, fetching and overwriting"
            );
        }
        let artifact_path = fetch(&name, indent, out)?;
        if offline && !artifact_path.exists() {
            let _ = writeln!(
                out,
                "  File {name} from manifest does not exist locally, cannot validate"
            );
            continue;
        }
        let valid = file_valid(rsg, &artifact_path, required.as_deref())?;
        match (valid, offline) {
            (false, false) => {
                return abort(format!(
                    "Fetched file {name} does not match manifest, aborting"
                ));
            }
            (false, true) => {
                let _ = writeln!(out, "  File {name} does not match manifest");
            }
            (true, false) => {
                std::fs::rename(&artifact_path, &name)
                    .or_else(|_| std::fs::copy(&artifact_path, &name).map(|_| ()))
                    .map_err(|e| Fail::Abort(format!("Error fetching release: {e}")))?;
            }
            (true, true) => {
                let path = &local_manifest.as_ref().expect("offline").0;
                let _ = writeln!(out, "  File {name} validated against manifest {path}");
            }
        }
        if valid {
            valid_count += 1;
        }
    }
    if offline {
        if valid_count == selected.len() {
            let _ = writeln!(out, "\nAll files validated");
            return Ok(0);
        }
        let _ = writeln!(out, "\nRelease is not valid");
        return Ok(1);
    }
    Ok(0)
}

/// `RELEASE_NOTES_TEMPLATE` (`server.py:5081-5084`).
const RELEASE_NOTES_TEMPLATE: &str = "# Enter release notes for {TAG}.\n# Lines starting with '#' will be ignored.\n# Save and exit the editor when done, or exit without saving to abort.\n";

/// `_edit_release_notes` (`server.py:719-760`). `None` cancels the release.
fn edit_release_notes(out: &mut dyn Write, tag: &str) -> Option<String> {
    let mut editor = std::env::var("EDITOR").unwrap_or_default();
    if editor.is_empty() {
        editor = ["nano", "vim", "vi"]
            .into_iter()
            .find(|fallback| {
                std::process::Command::new("which")
                    .arg(fallback)
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .status()
                    .is_ok_and(|s| s.success())
            })?
            .to_string();
    }
    if editor.is_empty() {
        let _ = writeln!(
            out,
            "No editor found. Please set $EDITOR environment variable."
        );
        return None;
    }
    let mut tmp = tempfile::Builder::new().suffix(".md").tempfile().ok()?;
    tmp.write_all(RELEASE_NOTES_TEMPLATE.replace("{TAG}", tag).as_bytes())
        .ok()?;
    let (_, path) = tmp.keep().ok()?;
    let _ = out.flush();
    let status = std::process::Command::new(&editor).arg(&path).status();
    let status = match status {
        Ok(status) => status,
        Err(e) => {
            tracing::error!("Error getting release notes: {e}");
            let _ = std::fs::remove_file(&path);
            return None;
        }
    };
    if !status.success() {
        let _ = writeln!(
            out,
            "Editor exited with error code {}",
            status.code().unwrap_or(-1)
        );
        let _ = std::fs::remove_file(&path);
        return None;
    }
    let content = std::fs::read_to_string(&path).ok();
    let _ = std::fs::remove_file(&path);
    let content = content?;
    let lines: Vec<&str> = content
        .split('\n')
        .filter(|l| !l.trim().starts_with('#'))
        .collect();
    let notes = lines.join("\n").trim().to_string();
    (!notes.is_empty()).then_some(notes)
}

/// `__commit_hash_from_tag` (`server.py:395-410`), run in `./`.
fn commit_hash_from_tag(tag: &str) -> Option<String> {
    let output = std::process::Command::new("git")
        .args(["rev-list", "-n", "1", tag])
        .stdin(std::process::Stdio::null())
        .output()
        .ok()?;
    let hash = String::from_utf8_lossy(&output.stdout).trim().to_string();
    (output.status.success() && !hash.is_empty()).then_some(hash)
}

/// `datetime.fromtimestamp(t, tz=utc).isoformat().replace("+00:00", "Z")`.
pub fn iso_utc(ts: i64) -> String {
    let (days, secs) = (ts.div_euclid(86_400), ts.rem_euclid(86_400));
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        secs / 3600,
        secs % 3600 / 60,
        secs % 60
    )
}

fn generation_failed(e: impl std::fmt::Display) -> Fail {
    Fail::Abort(format!("Release manifest generation failed: {e}"))
}

/// `create_release` (`server.py:1015-1149`). `signer` is an identity path;
/// without it the client identity signs. `Ok` is the exit code.
#[allow(clippy::too_many_arguments)]
pub fn create_release(
    out: &mut dyn Write,
    config: &ClientConfig,
    connect: &mut Connect<'_>,
    client_identity: &Identity,
    remote: Option<&str>,
    target: Option<&str>,
    signer: Option<&str>,
    name: Option<&str>,
    no_upload: bool,
) -> Result<i32, Fail> {
    let loaded;
    let signer = match signer.filter(|s| !s.is_empty()) {
        Some(path) => {
            let identity_path = expand_user(path);
            if !identity_path.is_file() {
                return abort(format!(
                    "Signer identity {} does not exist",
                    identity_path.display()
                ));
            }
            loaded = Identity::from_file(Path::new(path)).map_err(|e| {
                Fail::Abort(format!(
                    "Could not load signer identity from {}: {e}",
                    identity_path.display()
                ))
            })?;
            &loaded
        }
        None => client_identity,
    };
    let Some(remote) = remote else {
        return abort("No remote specified");
    };
    let Some(target) = target else {
        return abort("No target specified");
    };
    let err = |e: Fail| match e {
        Fail::Abort(m) | Fail::Raised(m) => Fail::Abort(m),
    };
    let (destination, group, repo) = config.parse_remote_url(remote).map_err(Fail::Abort)?;
    let repo_path = format!("{group}/{repo}");
    let release_time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64);
    let parts: Vec<&str> = target.split(':').collect();
    if parts.len() < 2 {
        return abort(
            "Invalid release specification\nDid you provide both a tag and artifacts path such as \"1.0.0:./dist\"?",
        );
    }
    let tag = parts[0];
    let artifacts_path = expand_user(parts[1]);
    let commit_hash = commit_hash_from_tag(tag);
    if commit_hash.is_none() {
        let _ = writeln!(
            out,
            "Could not get commit hash for tag {tag}. Does the tag exist in the local repository?"
        );
    }
    if !artifacts_path.is_dir() {
        return abort("Specified artifacts directory does not exist");
    }
    let mut artifacts: Vec<String> = std::fs::read_dir(&artifacts_path)
        .map_err(|e| Fail::Abort(format!("Error creating release: {e}")))?
        .filter_map(Result::ok)
        .filter(|e| e.path().is_file())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    if artifacts.is_empty() {
        return abort("No files found in specified artifact directory");
    }
    let _ = writeln!(out, "Creating release {tag}");
    let Some(notes) = edit_release_notes(out, tag) else {
        let _ = writeln!(out, "Release creation cancelled");
        return Ok(0);
    };

    let package_name = name.filter(|n| !n.is_empty()).unwrap_or(&repo);
    // `artifacts_path+"/manifest.rsm"` on the path as given.
    let manifest_path = PathBuf::from(format!("{}/manifest.rsm", artifacts_path.display()));
    let mut entries = Vec::new();
    let mut rsgs = Vec::new();
    for artifact in &artifacts {
        if artifact.ends_with(".rsg") || artifact.ends_with(".rsm") {
            continue;
        }
        let artifact_path = artifacts_path.join(artifact);
        let signature_path = PathBuf::from(format!("{}.rsg", artifact_path.display()));
        let _ = writeln!(
            out,
            "Signing {} with {}",
            artifact_path.display(),
            prettyhexrep(&signer.hash)
        );
        let file = std::fs::File::open(&artifact_path).map_err(generation_failed)?;
        let meta = [("timestamp".to_string(), Value::from(release_time))];
        let rsg = create_rsg(signer, file, false, Some(&meta)).map_err(generation_failed)?;
        std::fs::write(&signature_path, &rsg).map_err(generation_failed)?;
        entries.push(Value::Map(vec![
            (s("name"), s(artifact)),
            (s("rsg"), Value::Binary(rsg)),
        ]));
        rsgs.push(format!("{artifact}.rsg"));
    }
    let manifest_meta = vec![
        ("name".to_string(), s(package_name)),
        ("version".to_string(), s(tag)),
        ("released".to_string(), s(&iso_utc(release_time))),
        ("timestamp".to_string(), Value::from(release_time)),
        ("origin".to_string(), Value::Binary(destination)),
        ("path".to_string(), s(&repo_path)),
        (
            "commit".to_string(),
            commit_hash.as_deref().map_or(Value::Nil, s),
        ),
        ("artifacts".to_string(), Value::Array(entries)),
    ];
    let manifest = create_rsg(signer, notes.as_bytes(), true, Some(&manifest_meta))
        .map_err(generation_failed)?;
    std::fs::write(&manifest_path, manifest).map_err(generation_failed)?;
    artifacts.extend(rsgs);
    artifacts.push("manifest.rsm".to_string());

    if no_upload {
        let _ = writeln!(
            out,
            "Local release {package_name}:{tag} generated successfully in {target}"
        );
        return Ok(0);
    }
    let mut link = connect(remote, "Failed to establish link")?;
    let _ = write!(out, "\r                       \r");
    let _ = writeln!(out, "Initializing release on remote...");
    let init = request(
        &repo_path,
        vec![
            ("operation", s("create")),
            ("step", s("init")),
            ("tag", s(tag)),
            ("hash", commit_hash.as_deref().map_or(Value::Nil, s)),
            ("notes", s(&notes)),
            ("notes_format", s("markdown")),
        ],
    );
    let response = send(link.as_mut(), init, 120).map_err(err)?;
    match &response {
        Some(Response::Bytes(b)) if !b.is_empty() => {
            if b[0] != 0 {
                return abort(format!("Server error during init: {}", message_of(b)));
            }
        }
        _ => return abort("No response from remote during release init"),
    }
    let _ = writeln!(out, "Release initialized");
    let plural = if artifacts.len() == 1 { "" } else { "s" };
    let _ = writeln!(out, "\nSending {} artifact{plural}...", artifacts.len());
    for artifact in &artifacts {
        let path = artifacts_path.join(artifact);
        let data = std::fs::read(&path).map_err(|e| {
            Fail::Abort(format!(
                "Error creating release: {}",
                rns_tools::rsg::pyfmt::py_os_error(&e, &path.display().to_string())
            ))
        })?;
        let size = data.len();
        let request = request(
            &repo_path,
            vec![
                ("operation", s("create")),
                ("step", s("artifact")),
                ("tag", s(tag)),
                ("artifact_name", s(artifact)),
                ("artifact_data", Value::Binary(data)),
            ],
        );
        match send(link.as_mut(), request, 7200)? {
            Some(Response::Bytes(b)) if b.first() == Some(&0) => {
                let _ = writeln!(
                    out,
                    "  {artifact} ({}) transferred{}",
                    rns_tools::format::prettysize(size as f64, "B"),
                    " ".repeat(33)
                );
            }
            Some(Response::Bytes(b)) => {
                let _ = writeln!(out, "  Failed to send {artifact}: {}", message_of(&b));
            }
            _ => {
                let _ = writeln!(out, "  Failed to send {artifact}: Unknown error");
            }
        }
    }
    let _ = writeln!(out, "\nFinalizing release...");
    let finalize = request(
        &repo_path,
        vec![
            ("operation", s("create")),
            ("step", s("finalize")),
            ("tag", s(tag)),
        ],
    );
    match send(link.as_mut(), finalize, 300)? {
        Some(Response::Bytes(b)) if !b.is_empty() => {
            if b[0] != 0 {
                return abort(format!("Server error during finalize: {}", message_of(&b)));
            }
        }
        _ => return abort("No response from remote during finalize"),
    }
    let _ = writeln!(out, "Release {tag} published");
    Ok(0)
}

/// `list` and `view` share the connect-then-request shape (`server.py:762-877`).
pub fn run_simple(
    out: &mut dyn Write,
    input: &mut dyn std::io::BufRead,
    config: &ClientConfig,
    connect: &mut Connect<'_>,
    operation: &str,
    remote: Option<&str>,
    target: Option<&str>,
) -> Result<i32, Fail> {
    let Some(remote) = remote else {
        return abort("No remote specified");
    };
    if operation != "list" && target.is_none() {
        return abort("No target specified");
    }
    let failed = if matches!(operation, "list" | "view") {
        "Link establishment failed"
    } else {
        "Failed to establish link"
    };
    let mut link = connect(remote, failed)?;
    let (_, group, repo) = config.parse_remote_url(remote).map_err(Fail::Abort)?;
    let repo_path = format!("{group}/{repo}");
    let target = target.unwrap_or_default();
    match operation {
        "list" => list_releases(out, link.as_mut(), &repo_path)?,
        "view" => view_release(out, link.as_mut(), &repo_path, target)?,
        _ => confirm_and_send(out, input, link.as_mut(), &repo_path, operation, target)?,
    }
    Ok(0)
}
