//! `/git/*` request handlers (`server.py:2870-2929@1.6.0`).

use std::process::{Command, Stdio};

use rmpv::Value;

use super::layout::{Repositories, parse_repository_path};
use super::perms::Perm;
use super::{IDX_REPOSITORY, RES_DISALLOWED, RES_INVALID_REQ, RES_NOT_FOUND, RES_REMOTE_FAIL};

fn status(code: u8, message: &str) -> Vec<u8> {
    let mut reply = vec![code];
    reply.extend_from_slice(message.as_bytes());
    reply
}

/// Python truthiness of an unpacked request value.
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
        Value::Ext(_, d) => !d.is_empty(),
    }
}

/// `data.get(key)` for an integer or string key.
fn get<'a>(map: &'a [(Value, Value)], key: &Value) -> Option<&'a Value> {
    map.iter().find(|(k, _)| k == key).map(|(_, v)| v)
}

/// A request map and its parsed repository path.
type Parsed<'a> = (&'a [(Value, Value)], Option<(&'a str, &'a str)>);

/// Common checks of every handler (`server.py:2872-2874`); `Err` is the reply.
/// `Ok(None)` is upstream raising before its try (key 0 not a string), which
/// sends no response.
fn request_path<'a>(
    identity: Option<&[u8; 16]>,
    data: &'a Value,
) -> Result<Option<Parsed<'a>>, Vec<u8>> {
    if identity.is_none() {
        return Err(status(RES_DISALLOWED, "Not identified"));
    }
    let Value::Map(map) = data else {
        return Err(status(RES_INVALID_REQ, "Invalid request"));
    };
    let Some(path) = get(map, &Value::from(IDX_REPOSITORY)) else {
        return Err(status(RES_INVALID_REQ, "No repository specified"));
    };
    let Some(path) = path.as_str() else {
        return Ok(None);
    };
    Ok(Some((map, parse_repository_path(path))))
}

/// `handle_list` (`server.py:2870-2929`). `None` sends no response.
pub fn handle_list(
    repos: &Repositories,
    identity: Option<&[u8; 16]>,
    data: &Value,
) -> Option<Vec<u8>> {
    let (map, path) = match request_path(identity, data) {
        Err(reply) => return Some(reply),
        Ok(None) => return None,
        Ok(Some(parsed)) => parsed,
    };
    let hash = identity.expect("checked");
    let (group, repo) = path.unwrap_or(("", ""));
    let for_push = get(map, &Value::from("for_push")).is_some_and(truthy);
    let read = path.is_some() && repos.resolve_permission(hash, group, repo, Perm::Read);
    let write = path.is_some() && repos.resolve_permission(hash, group, repo, Perm::Write);
    let access = if for_push { write } else { read };
    if !access {
        let message = if read { "Not allowed" } else { "Not found" };
        return Some(status(RES_NOT_FOUND, message));
    }
    let repository = repos.repository(group, repo).expect("resolved");
    let mut head_ref = "master".to_string();
    let head = std::fs::read(repository.path.join("HEAD")).unwrap_or_default();
    if let Some(rest) = head.strip_prefix(b"ref: ") {
        // bytes.strip() then decode("utf-8", errors="ignore")
        let ws = |b: &u8| b" \t\n\r\x0b\x0c".contains(b);
        let start = rest.iter().position(|b| !ws(b)).unwrap_or(rest.len());
        let end = rest.iter().rposition(|b| !ws(b)).map_or(start, |i| i + 1);
        head_ref = rest[start..end]
            .utf8_chunks()
            .map(|chunk| chunk.valid())
            .collect();
    }
    let output = Command::new("git")
        .args(["for-each-ref", "--format", "%(objectname) %(refname)"])
        .current_dir(&repository.path)
        .stdin(Stdio::null())
        .output();
    let output = match output {
        Ok(output) if output.status.success() => output,
        Ok(output) => {
            tracing::error!(
                "Error while listing refs for {group}/{repo}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            return Some(status(RES_REMOTE_FAIL, "Could not list refs"));
        }
        Err(e) => {
            tracing::error!("Error while handling list request for {group}/{repo}: {e}");
            return Some(status(RES_REMOTE_FAIL, "Remote error"));
        }
    };
    let Ok(stdout) = String::from_utf8(output.stdout) else {
        return Some(status(RES_REMOTE_FAIL, "Remote error"));
    };
    let mut seen = std::collections::HashSet::new();
    let mut lines = Vec::new();
    for line in stdout.trim().split('\n') {
        if line.trim().is_empty() {
            continue;
        }
        if let Some((_, name)) = line.split_once(' ')
            && seen.insert(name.to_string())
        {
            lines.push(line);
        }
    }
    let text = if lines.is_empty() {
        format!("@{head_ref} HEAD\n")
    } else {
        format!("{}\n@{head_ref} HEAD\n", lines.join("\n"))
    };
    let mut reply = vec![super::RES_OK];
    reply.extend_from_slice(text.as_bytes());
    Some(reply)
}

/// A handler's answer: status bytes, or a bundle file with its metadata. The
/// temporary directory holding the file must outlive the transfer.
#[derive(Debug)]
pub enum Reply {
    Bytes(Vec<u8>),
    File {
        file: std::fs::File,
        metadata: Vec<u8>,
        tmpdir: tempfile::TempDir,
    },
}

/// Upstream raised inside its `try`, replying "Remote error".
struct Raised;

/// `RNS.prettyhexrep` of the identity, or `None`, as `str(remote_identity)`.
pub fn identity_text(identity: Option<&[u8; 16]>) -> String {
    identity.map_or("None".to_string(), |h| format!("<{}>", hex::encode(h)))
}

/// `log_request` (`server.py:2705-2707`).
pub fn log_request(repos: &Repositories, message: &str, identity: Option<&[u8; 16]>) {
    if identity.is_some_and(|h| repos.blocked.iter().any(|b| b.as_slice() == h)) {
        tracing::debug!("Blocked: {message}");
    } else {
        tracing::debug!("{message}");
    }
}

fn run_git(cwd: &std::path::Path, args: &[&str]) -> std::io::Result<std::process::Output> {
    Command::new("git")
        .args(args)
        .current_dir(cwd)
        .stdin(Stdio::null())
        .output()
}

/// `san_ref` on an unpacked value; anything but a string raises.
fn san_ref_value(value: &Value) -> Result<Option<String>, Raised> {
    let s = value.as_str().ok_or(Raised)?;
    Ok(crate::util::san_ref(s).map(str::to_string))
}

/// `san_sha` on an unpacked value: `len()` raises for scalars, and
/// `bytes.fromhex` rejects (into `None`) anything but a string.
fn san_sha_value(value: &Value) -> Result<Option<String>, Raised> {
    match value {
        Value::String(s) => Ok(s
            .as_str()
            .and_then(crate::util::san_sha)
            .map(str::to_string)),
        Value::Binary(_) | Value::Array(_) | Value::Map(_) => Ok(None),
        _ => Err(Raised),
    }
}

/// Python iteration over an unpacked value in a `for` loop.
fn py_iter(value: &Value) -> Result<Vec<Value>, Raised> {
    match value {
        Value::Array(items) => Ok(items.clone()),
        Value::Map(entries) => Ok(entries.iter().map(|(k, _)| k.clone()).collect()),
        Value::String(s) => Ok(s
            .as_str()
            .ok_or(Raised)?
            .chars()
            .map(|c| Value::from(c.to_string()))
            .collect()),
        Value::Binary(b) => Ok(b.iter().map(|&x| Value::from(x)).collect()),
        _ => Err(Raised),
    }
}

/// Permission and repository lookup shared by fetch, push and delete.
/// `Ok(Ok(path))` is the repository directory to work in.
fn writable_repository(
    repos: &Repositories,
    hash: &[u8; 16],
    path: Option<(&str, &str)>,
    write: bool,
) -> Result<std::path::PathBuf, Vec<u8>> {
    let (group, repo) = path.unwrap_or(("", ""));
    let read = path.is_some() && repos.resolve_permission(hash, group, repo, Perm::Read);
    if !write {
        if !read {
            return Err(status(RES_NOT_FOUND, "Not found"));
        }
    } else if !(path.is_some() && repos.resolve_permission(hash, group, repo, Perm::Write)) {
        return Err(if read {
            status(RES_DISALLOWED, "Not allowed")
        } else {
            status(RES_NOT_FOUND, "Not found")
        });
    }
    Ok(repos
        .repository(group, repo)
        .expect("resolved")
        .path
        .clone())
}

/// `handle_fetch` (`server.py:2931-3004`). `None` sends no response.
pub fn handle_fetch(
    repos: &std::sync::RwLock<Repositories>,
    identity: Option<&[u8; 16]>,
    data: &Value,
) -> Option<Reply> {
    let (map, path, repository_path) = {
        let repos = repos.read().unwrap_or_else(|e| e.into_inner());
        log_request(
            &repos,
            &format!("Fetch request from remote {}", identity_text(identity)),
            identity,
        );
        let (map, path) = match request_path(identity, data) {
            Err(reply) => return Some(Reply::Bytes(reply)),
            Ok(None) => return None,
            Ok(Some(parsed)) => parsed,
        };
        match writable_repository(&repos, identity.expect("checked"), path, false) {
            Err(reply) => return Some(Reply::Bytes(reply)),
            Ok(p) => (map, path, p),
        }
    };
    let (group, repo) = path.unwrap_or(("", ""));
    let empty = Value::Array(Vec::new());
    let refs = get(map, &Value::from("refs")).unwrap_or(&empty);
    if !truthy(refs) {
        return Some(Reply::Bytes(status(RES_INVALID_REQ, "No refs specified")));
    }
    match fetch_bundle(map, refs, &repository_path, group, repo) {
        Ok(reply) => Some(reply),
        Err(Raised) => {
            tracing::error!("Error while handling fetch request for {group}/{repo}");
            Some(Reply::Bytes(status(RES_REMOTE_FAIL, "Remote error")))
        }
    }
}

fn fetch_bundle(
    map: &[(Value, Value)],
    refs: &Value,
    repository_path: &std::path::Path,
    group: &str,
    repo: &str,
) -> Result<Reply, Raised> {
    let Value::Array(refs) = refs else {
        return Err(Raised);
    };
    let mut ref_names = Vec::new();
    for r in refs {
        let Value::Map(r) = r else {
            return Err(Raised);
        };
        ref_names.push(get(r, &Value::from("ref")).ok_or(Raised)?.clone());
    }
    for name in &ref_names {
        if san_ref_value(name)?.is_none() {
            return Ok(Reply::Bytes(status(RES_INVALID_REQ, "Invalid request")));
        }
    }
    let names: Vec<&str> = ref_names.iter().filter_map(Value::as_str).collect();
    tracing::debug!("Fetching refs {names:?} for {group}/{repo}");
    let tmpdir = tempfile::TempDir::new().map_err(|_| Raised)?;
    let bundle_path = tmpdir.path().join("fetch.bundle");
    let mut execv: Vec<String> = ["bundle", "create", "--no-progress"]
        .map(String::from)
        .into();
    execv.push(bundle_path.to_string_lossy().into_owned());
    let have_known = |sha: &str| {
        run_git(repository_path, &["cat-file", "-t", sha]).is_ok_and(|o| o.status.success())
    };
    for (r, name) in refs.iter().zip(&names) {
        let Value::Map(r) = r else { unreachable!() };
        execv.push(name.to_string());
        if let Some(have) = get(r, &Value::from("have")).filter(|h| truthy(h)) {
            let Some(sha) = san_sha_value(have)? else {
                return Ok(Reply::Bytes(status(RES_INVALID_REQ, "Invalid SHA")));
            };
            if have_known(&sha) {
                execv.push(format!("^{sha}"));
            } else {
                tracing::warn!("Client have-sha {sha} not found in repository, skipping");
            }
        }
    }
    let empty = Value::Array(Vec::new());
    for sha in py_iter(get(map, &Value::from("have")).unwrap_or(&empty))? {
        let Some(sha) = san_sha_value(&sha)? else {
            return Ok(Reply::Bytes(status(RES_INVALID_REQ, "Invalid SHA")));
        };
        if have_known(&sha) {
            execv.push(format!("^{sha}"));
        } else {
            tracing::warn!("Client have-sha {sha} not found in repository, skipping");
        }
    }
    let args: Vec<&str> = execv.iter().map(String::as_str).collect();
    let result = run_git(repository_path, &args).map_err(|_| Raised)?;
    if !result.status.success() {
        let stderr = String::from_utf8_lossy(&result.stderr);
        if stderr.to_lowercase().contains("empty bundle") {
            tracing::debug!("Empty bundle for {names:?}, all objects already on client");
            return Ok(Reply::Bytes(vec![super::RES_OK]));
        }
        tracing::error!("Error while fetching refs {names:?} for {group}/{repo}: {stderr}");
        return Ok(Reply::Bytes(status(
            RES_REMOTE_FAIL,
            "Could not fetch refs",
        )));
    }
    fetch_succeeded(group, repo);
    let file = std::fs::File::open(&bundle_path).map_err(|_| Raised)?;
    // {IDX_RESULT_CODE: RES_OK}
    let metadata = vec![0x81, super::IDX_RESULT_CODE, super::RES_OK];
    Ok(Reply::File {
        file,
        metadata,
        tmpdir,
    })
}

/// `handle_push` (`server.py:3006-3100`). `None` sends no response.
pub fn handle_push(
    repos: &std::sync::RwLock<Repositories>,
    identity: Option<&[u8; 16]>,
    data: &Value,
) -> Option<Vec<u8>> {
    let (map, path, repository_path) = {
        let repos = repos.read().unwrap_or_else(|e| e.into_inner());
        log_request(
            &repos,
            &format!("Push request from remote {}", identity_text(identity)),
            identity,
        );
        let (map, path) = match request_path(identity, data) {
            Err(reply) => return Some(reply),
            Ok(None) => return None,
            Ok(Some(parsed)) => parsed,
        };
        match writable_repository(&repos, identity.expect("checked"), path, true) {
            Err(reply) => return Some(reply),
            Ok(p) => (map, path, p),
        }
    };
    let (group, repo) = path.unwrap_or(("", ""));
    let field = |key: &str| get(map, &Value::from(key));
    let empty = Value::from("");
    // san_ref runs before the try: a non-string ref raises with no response.
    let local_ref = san_ref_value(field("local_ref").unwrap_or(&empty)).ok()?;
    let remote_ref = san_ref_value(field("remote_ref").unwrap_or(&empty)).ok()?;
    let force = field("force").is_some_and(truthy);
    let bundle = field("bundle").filter(|b| truthy(b));
    let operations = field("operations").filter(|o| truthy(o));
    if let Some(bundle) = bundle {
        let (Some(local_ref), Some(remote_ref)) = (local_ref, remote_ref) else {
            return Some(status(RES_INVALID_REQ, "Missing ref specification"));
        };
        tracing::debug!("Push {local_ref}:{remote_ref} to {group}/{repo}");
        return Some(
            push_bundle(
                bundle,
                &local_ref,
                &remote_ref,
                force,
                &repository_path,
                group,
                repo,
            )
            .unwrap_or_else(|Raised| {
                tracing::error!("Error while handling push request for {group}/{repo}");
                status(RES_REMOTE_FAIL, "Remote error")
            }),
        );
    }
    let Some(operations) = operations else {
        return Some(status(RES_INVALID_REQ, "Invalid request data"));
    };
    let Value::Array(operations) = operations else {
        return Some(status(RES_INVALID_REQ, "Invalid data for operations"));
    };
    Some(
        push_operations(operations, &repository_path, group, repo).unwrap_or_else(|Raised| {
            tracing::error!("Error while handling push operations for {group}/{repo}");
            status(RES_REMOTE_FAIL, "Remote error")
        }),
    )
}

fn push_bundle(
    bundle: &Value,
    local_ref: &str,
    remote_ref: &str,
    force: bool,
    repository_path: &std::path::Path,
    group: &str,
    repo: &str,
) -> Result<Vec<u8>, Raised> {
    let tmpdir = tempfile::TempDir::new().map_err(|_| Raised)?;
    let bundle_path = tmpdir.path().join("push.bundle");
    let bytes = match bundle {
        Value::Binary(b) => b.as_slice(),
        Value::String(s) => s.as_bytes(),
        _ => return Err(Raised),
    };
    std::fs::write(&bundle_path, bytes).map_err(|_| Raised)?;
    let bundle_arg = bundle_path.to_string_lossy();
    let failed = |stderr: &[u8]| {
        tracing::error!(
            "Bundle verification failed for push {local_ref}:{remote_ref} to {group}/{repo}: {}",
            String::from_utf8_lossy(stderr)
        );
        status(RES_REMOTE_FAIL, "Could not verify bundle")
    };
    let result =
        run_git(repository_path, &["bundle", "verify", &bundle_arg]).map_err(|_| Raised)?;
    if !result.status.success() {
        return Ok(failed(&result.stderr));
    }
    let refspec = format!("{local_ref}:{remote_ref}");
    let mut args = vec!["fetch", &bundle_arg, &refspec];
    if force {
        args.push("--force");
    }
    let result = run_git(repository_path, &args).map_err(|_| Raised)?;
    if !result.status.success() {
        return Ok(failed(&result.stderr));
    }
    push_succeeded(group, repo);
    Ok(vec![super::RES_OK])
}

fn push_operations(
    operations: &[Value],
    repository_path: &std::path::Path,
    group: &str,
    repo: &str,
) -> Result<Vec<u8>, Raised> {
    let empty = Value::from("");
    for op in operations {
        let Value::Map(op) = op else {
            return Err(Raised);
        };
        let action = get(op, &Value::from("action")).unwrap_or(&empty);
        let reference = san_ref_value(get(op, &Value::from("ref")).unwrap_or(&empty))?;
        let sha = san_sha_value(get(op, &Value::from("sha")).unwrap_or(&empty))?;
        let op_force = get(op, &Value::from("force")).is_some_and(truthy);
        if action.as_str() != Some("update_ref") {
            let action = rns_tools::rsg::pyfmt::py_str(action);
            return Ok(status(
                RES_INVALID_REQ,
                &format!("Unknown operation: {action}"),
            ));
        }
        let Some(reference) = reference.filter(|r| r.starts_with("refs/")) else {
            return Ok(status(RES_INVALID_REQ, "Invalid request"));
        };
        let Some(sha) = sha else {
            return Ok(status(RES_INVALID_REQ, "Invalid SHA"));
        };
        let exists = run_git(repository_path, &["cat-file", "-t", &sha]).map_err(|_| Raised)?;
        if !exists.status.success() {
            return Ok(status(
                RES_REMOTE_FAIL,
                &format!("Object {sha} does not exist in repository"),
            ));
        }
        let current = run_git(repository_path, &["rev-parse", &reference]).map_err(|_| Raised)?;
        if current.status.success() {
            let existing = String::from_utf8(current.stdout).map_err(|_| Raised)?;
            if existing.trim() != sha && !op_force {
                return Ok(status(
                    RES_DISALLOWED,
                    &format!("Ref {reference} already exists at different SHA (force required)"),
                ));
            }
        }
        tracing::debug!("Updating ref {reference} to {sha} in {group}/{repo}");
        let result =
            run_git(repository_path, &["update-ref", &reference, &sha]).map_err(|_| Raised)?;
        if !result.status.success() {
            tracing::error!(
                "Error while updating ref {reference} to {sha} for {group}/{repo}: {}",
                String::from_utf8_lossy(&result.stderr)
            );
            return Ok(status(RES_REMOTE_FAIL, "Could not update refs"));
        }
    }
    push_succeeded(group, repo);
    Ok(vec![super::RES_OK])
}

/// `fetch_succeeded` (`server.py:4770-4773`): statistics, not recorded yet.
fn fetch_succeeded(_group: &str, _repo: &str) {}

/// `push_succeeded` (`server.py:4775-4777`): statistics, not recorded yet.
fn push_succeeded(_group: &str, _repo: &str) {}

/// `handle_delete` (`server.py:3102-3134`). `None` sends no response.
pub fn handle_delete(
    repos: &std::sync::RwLock<Repositories>,
    identity: Option<&[u8; 16]>,
    data: &Value,
) -> Option<Vec<u8>> {
    let (map, path, repository_path) = {
        let repos = repos.read().unwrap_or_else(|e| e.into_inner());
        log_request(
            &repos,
            &format!("Delete request from remote {}", identity_text(identity)),
            identity,
        );
        let (map, path) = match request_path(identity, data) {
            Err(reply) => return Some(reply),
            Ok(None) => return None,
            Ok(Some(parsed)) => parsed,
        };
        match writable_repository(&repos, identity.expect("checked"), path, true) {
            Err(reply) => return Some(reply),
            Ok(p) => (map, path, p),
        }
    };
    let (group, repo) = path.unwrap_or(("", ""));
    let empty = Value::from("");
    let reference = san_ref_value(get(map, &Value::from("ref")).unwrap_or(&empty)).ok()?;
    let Some(reference) = reference.filter(|r| r.starts_with("refs/")) else {
        return Some(status(RES_INVALID_REQ, "Invalid request"));
    };
    tracing::debug!("Deleting ref {reference} in {group}/{repo}");
    match run_git(&repository_path, &["update-ref", "-d", &reference]) {
        Ok(result) if result.status.success() => {
            push_succeeded(group, repo);
            Some(vec![super::RES_OK])
        }
        Ok(result) => {
            tracing::error!(
                "Error while deleting ref {reference} for {group}/{repo}: {}",
                String::from_utf8_lossy(&result.stderr)
            );
            Some(status(RES_REMOTE_FAIL, "Could not delete ref"))
        }
        Err(e) => {
            tracing::error!("Error while handling delete request for {group}/{repo}: {e}");
            Some(status(RES_REMOTE_FAIL, "Remote error"))
        }
    }
}

/// `REPO_CREATE_PERMS_TEMPLATE` (`server.py:5090`).
const REPO_CREATE_PERMS_TEMPLATE: &str = "adm:{IDENTITY_HASH}";

/// `handle_create` (`server.py:3141-3211`). `None` sends no response.
/// Group permissions are checked without the blocklist, as upstream does.
pub fn handle_create(
    repos: &std::sync::RwLock<Repositories>,
    identity: Option<&[u8; 16]>,
    data: &Value,
) -> Option<Vec<u8>> {
    let mut repos = repos.write().unwrap_or_else(|e| e.into_inner());
    log_request(
        &repos,
        &format!("Create request from remote {}", identity_text(identity)),
        identity,
    );
    let (_, path) = match request_path(identity, data) {
        Err(reply) => return Some(reply),
        Ok(None) => return None,
        Ok(Some(parsed)) => parsed,
    };
    let hash = identity.expect("checked");
    let Some((group, repo)) = path.filter(|(g, r)| !g.is_empty() && !r.is_empty()) else {
        return Some(status(RES_INVALID_REQ, "Invalid request"));
    };
    let Some(group_path) = repos.groups.get(group).map(|g| g.path.clone()) else {
        return Some(status(RES_NOT_FOUND, "Not found"));
    };
    let read = repos.resolve_group_permission(hash, group, Perm::Read);
    let create = repos.resolve_group_permission(hash, group, Perm::Create);
    if !std::path::Path::new(&group_path).exists() {
        return Some(status(RES_NOT_FOUND, "Not found"));
    }
    if !create {
        return Some(if read {
            status(RES_DISALLOWED, "Not allowed")
        } else {
            status(RES_NOT_FOUND, "Not found")
        });
    }
    let repository_path = std::path::Path::new(&group_path).join(repo);
    if repos.repository(group, repo).is_some() || repository_path.exists() {
        return Some(if repos.resolve_permission(hash, group, repo, Perm::Read) {
            status(RES_DISALLOWED, "Repository already exists")
        } else {
            status(RES_NOT_FOUND, "Not found")
        });
    }
    tracing::debug!(
        "Creating repository {group}/{repo} for {}",
        identity_text(identity)
    );
    let cleanup = |path: &std::path::Path| {
        if std::fs::remove_dir_all(path).is_err() {
            tracing::error!(
                "Could not clean up failed repository init at {}",
                path.display()
            );
        }
    };
    use std::os::unix::fs::DirBuilderExt;
    if let Err(e) = std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o755)
        .create(&repository_path)
    {
        tracing::error!(
            "Error while creating repository {group}/{repo} for {}: {e}",
            identity_text(identity)
        );
        return Some(status(RES_REMOTE_FAIL, "Remote error"));
    }
    match run_git(&repository_path, &["init", "--bare"]) {
        Ok(result) if result.status.success() => {}
        result => {
            if let Ok(result) = result {
                tracing::error!(
                    "Failed to initialize bare repository at {}: {}",
                    repository_path.display(),
                    String::from_utf8_lossy(&result.stderr)
                );
            }
            cleanup(&repository_path);
            return Some(status(RES_REMOTE_FAIL, "Could not initialize repository"));
        }
    }
    let allowed = format!("{}.allowed", repository_path.display());
    let tmp_allowed = format!("{allowed}.tmp");
    let permissions = REPO_CREATE_PERMS_TEMPLATE.replace("{IDENTITY_HASH}", &hex::encode(hash));
    if std::fs::write(&tmp_allowed, permissions)
        .and_then(|()| std::fs::rename(&tmp_allowed, &allowed))
        .is_err()
    {
        tracing::error!("Could not set default repository permissions for {group}/{repo}");
        cleanup(&repository_path);
        return Some(status(RES_REMOTE_FAIL, "Could not initialize repository"));
    }
    match repos.load_repository(group, &repository_path) {
        Ok(true) => {
            tracing::debug!("Repository {group}/{repo} created and loaded successfully");
            Some(vec![super::RES_OK])
        }
        Ok(false) => {
            tracing::error!(
                "Repository {} created, but runtime loading failed",
                repository_path.display()
            );
            cleanup(&repository_path);
            Some(status(RES_REMOTE_FAIL, "Failed to register repository"))
        }
        Err(e) => {
            tracing::error!("Error while creating repository {group}/{repo}: {e:?}");
            cleanup(&repository_path);
            Some(status(RES_REMOTE_FAIL, "Remote error"))
        }
    }
}
