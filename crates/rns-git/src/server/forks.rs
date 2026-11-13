//! `/git/fork`, `/git/mirror`, `/git/sync` and the periodic mirror job
//! (`server.py`).

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Mutex, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use rmpv::Value;

use super::handlers::{
    REPO_CREATE_PERMS_TEMPLATE, get, identity_text, log_request, status, truthy,
};
use super::layout::{Repositories, parse_repository_path};
use super::perms::Perm;
use super::{
    IDX_REPOSITORY, RES_DISALLOWED, RES_INVALID_REQ, RES_NOT_FOUND, RES_OK, RES_REMOTE_FAIL,
};

/// `CLONE_PROTOS` (`server.py`).
pub const CLONE_PROTOS: [&str; 4] = ["rns", "http", "https", "ssh"];

/// `sync_check_interval` (`server.py`): seconds between mirror job runs.
pub const SYNC_CHECK_INTERVAL: u64 = 15 * 60;

/// `ls-remote` is the only git call upstream bounds (`server.py`).
const LS_REMOTE_TIMEOUT: Duration = Duration::from_secs(30);

/// What a clone handler makes: a fork or a mirror.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RepoType {
    Fork,
    Mirror,
}

impl RepoType {
    fn name(self) -> &'static str {
        match self {
            RepoType::Fork => "fork",
            RepoType::Mirror => "mirror",
        }
    }
}

fn git(cwd: Option<&Path>, args: &[&str]) -> std::io::Result<std::process::Output> {
    let mut cmd = Command::new("git");
    if let Some(cwd) = cwd {
        cmd.current_dir(cwd);
    }
    cmd.args(args).stdin(Stdio::null()).output()
}

/// `subprocess.run(..., timeout=...)`: the child is killed at the deadline.
fn git_with_timeout(
    args: &[&str],
    timeout: Duration,
) -> std::io::Result<Option<std::process::Output>> {
    let mut child = Command::new("git")
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let mut stdout = child.stdout.take().expect("piped");
    let mut stderr = child.stderr.take().expect("piped");
    let out = std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = stdout.read_to_end(&mut buf);
        buf
    });
    let err = std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = stderr.read_to_end(&mut buf);
        buf
    });
    let deadline = Instant::now() + timeout;
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break Some(status);
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            break None;
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    let stdout = out.join().unwrap_or_default();
    let stderr = err.join().unwrap_or_default();
    Ok(status.map(|status| std::process::Output {
        status,
        stdout,
        stderr,
    }))
}

fn lossy(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// Python `int()` of a stripped string: sign, digits, single underscores between digits.
fn py_int(text: &str) -> Option<i64> {
    let text = text.trim();
    let (negative, digits) = match text.as_bytes().first()? {
        b'-' => (true, &text[1..]),
        b'+' => (false, &text[1..]),
        _ => (false, text),
    };
    if digits.is_empty()
        || digits.starts_with('_')
        || digits.ends_with('_')
        || digits.contains("__")
        || !digits.bytes().all(|b| b.is_ascii_digit() || b == b'_')
    {
        return None;
    }
    let value: i64 = digits.replace('_', "").parse().ok()?;
    Some(if negative { -value } else { value })
}

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64)
}

/// `__mirror_synced` (`server.py`): 0 when unset or unreadable.
pub fn mirror_synced(path: &Path) -> i64 {
    match git(Some(path), &["config", "repository.rngit.upstream.sync"]) {
        Ok(out) if out.status.success() => py_int(&lossy(&out.stdout)).unwrap_or(0),
        _ => 0,
    }
}

/// `__set_mirror_synced` (`server.py`).
pub fn set_mirror_synced(path: &Path) -> bool {
    let now = now_secs().to_string();
    git(
        Some(path),
        &["config", "repository.rngit.upstream.sync", &now],
    )
    .is_ok_and(|out| out.status.success())
}

/// `__update_head_to_source_default` (`server.py`): point HEAD at
/// the source's default branch, else at the first local branch.
pub fn update_head_to_source_default(repo_path: &Path, source_url: &str) -> bool {
    tracing::debug!(
        "Updating HEAD for {} from {source_url}",
        repo_path.display()
    );
    let mut target: Option<String> = None;
    match git_with_timeout(
        &["ls-remote", "--symref", source_url, "HEAD"],
        LS_REMOTE_TIMEOUT,
    ) {
        Ok(Some(out)) if out.status.success() => {
            for line in lossy(&out.stdout).split('\n') {
                if line.starts_with("ref: refs/heads/") {
                    let parts: Vec<&str> = line.split('\t').collect();
                    if parts.len() >= 2 && parts[1] == "HEAD" {
                        target = Some(parts[0][5..].trim().to_string());
                        break;
                    }
                }
            }
        }
        Ok(Some(_)) => {}
        Ok(None) => tracing::warn!("Timeout querying remote HEAD from {source_url}"),
        Err(e) => tracing::error!("Could not query remote HEAD from {source_url}: {e}"),
    }
    if let Some(branch) = &target {
        tracing::debug!("Determined target branch as {branch} from {source_url}");
        let found = git(
            Some(repo_path),
            &["show-ref", "--verify", "--quiet", branch],
        )
        .is_ok_and(|out| out.status.success());
        if !found {
            tracing::warn!("Remote default branch {branch} not found locally, using fallback");
            target = None;
        }
    }
    let target = match target {
        Some(target) => target,
        None => {
            tracing::warn!(
                "Could not determine target branch from {source_url}, falling back to first available local branch"
            );
            let args = [
                "for-each-ref",
                "--format=%(refname:short)",
                "refs/heads",
                "--count=1",
            ];
            match git(Some(repo_path), &args) {
                Ok(out) if out.status.success() && !lossy(&out.stdout).trim().is_empty() => {
                    format!("refs/heads/{}", lossy(&out.stdout).trim())
                }
                Ok(_) => return false,
                Err(e) => {
                    tracing::error!(
                        "Could not determine fallback branch for {}: {e}",
                        repo_path.display()
                    );
                    return false;
                }
            }
        }
    };
    match git(Some(repo_path), &["symbolic-ref", "HEAD", &target]) {
        Ok(out) if out.status.success() => {
            tracing::debug!("Updated {} HEAD to {target}", repo_path.display());
            true
        }
        Ok(out) => {
            tracing::warn!("Failed to update HEAD to {target}: {}", lossy(&out.stderr));
            false
        }
        Err(e) => {
            tracing::error!("Error updating HEAD: {e}");
            false
        }
    }
}

/// `__sync_mirror` / `__sync_fork` (`server.py`): fetch every ref
/// from the source; a mirror also follows the source's HEAD.
fn sync_upstream(kind: RepoType, label: &str, path: &Path, source: &str) -> bool {
    let what = match kind {
        RepoType::Mirror => "mirror",
        RepoType::Fork => "fork",
    };
    if source.is_empty() {
        tracing::error!("Could not determine upstream source for {what} {label}");
        return false;
    }
    match git(Some(path), &["fetch", source, "+refs/*:refs/*"]) {
        Ok(out) if out.status.success() => {}
        Ok(out) => {
            tracing::error!(
                "Failed to sync {what} {label} from {source}: {}",
                lossy(&out.stderr)
            );
            return false;
        }
        Err(e) => {
            tracing::error!("Error syncing {what} {label}: {e}");
            return false;
        }
    }
    if kind == RepoType::Mirror {
        update_head_to_source_default(path, source);
    }
    if set_mirror_synced(path) {
        tracing::info!(
            "{} {label} synced successfully from {source}",
            capitalise(what)
        );
    } else {
        tracing::warn!(
            "{} synced but could not update sync timestamp for {label}",
            capitalise(what)
        );
    }
    true
}

fn capitalise(word: &str) -> String {
    let mut chars = word.chars();
    chars
        .next()
        .map(|c| c.to_uppercase().chain(chars).collect())
        .unwrap_or_default()
}

/// `__sync_mirrors` (`server.py`): every mirror whose last sync is
/// older than `mirror_interval` seconds. Forks are never synced here. Returns
/// at once when a run is already in progress.
pub fn sync_mirrors(repos: &RwLock<Repositories>, mirror_interval: i64, sync_lock: &Mutex<()>) {
    let Ok(_guard) = sync_lock.try_lock() else {
        return;
    };
    let mirrors: Vec<(String, PathBuf, String)> = {
        let repos = repos.read().unwrap_or_else(|e| e.into_inner());
        repos
            .groups
            .values()
            .flat_map(|g| g.repositories.values())
            .filter_map(|r| {
                let source = r.mirror.clone().filter(|s| !s.is_empty())?;
                Some((format!("{}/{}", r.group, r.name), r.path.clone(), source))
            })
            .collect()
    };
    for (label, path, source) in mirrors {
        if now_secs() > mirror_synced(&path) + mirror_interval {
            tracing::info!("Syncing mirror {label}");
            sync_upstream(RepoType::Mirror, &label, &path, &source);
        }
    }
}

/// `shutil.move` of a directory: a rename, or a copy and delete across filesystems.
fn move_dir(from: &Path, to: &Path) -> std::io::Result<()> {
    match std::fs::rename(from, to) {
        Ok(()) => Ok(()),
        Err(e) if e.raw_os_error() == Some(nix::libc::EXDEV) => {
            copy_dir(from, to)?;
            std::fs::remove_dir_all(from)
        }
        Err(e) => Err(e),
    }
}

fn copy_dir(from: &Path, to: &Path) -> std::io::Result<()> {
    std::fs::create_dir(to)?;
    std::fs::set_permissions(to, std::fs::metadata(from)?.permissions())?;
    for entry in std::fs::read_dir(from)? {
        let entry = entry?;
        let target = to.join(entry.file_name());
        let kind = entry.file_type()?;
        if kind.is_symlink() {
            std::os::unix::fs::symlink(std::fs::read_link(entry.path())?, &target)?;
        } else if kind.is_dir() {
            copy_dir(&entry.path(), &target)?;
        } else {
            std::fs::copy(entry.path(), &target)?;
        }
    }
    Ok(())
}

/// `handle_fork` (`server.py`). `None` sends no response.
pub fn handle_fork(
    repos: &RwLock<Repositories>,
    identity: Option<&[u8; 16]>,
    data: &Value,
) -> Option<Vec<u8>> {
    {
        let r = repos.read().unwrap_or_else(|e| e.into_inner());
        let message = format!("Fork request from remote {}", identity_text(identity));
        log_request(&r, &message, identity);
    }
    handle_remote_clone(repos, identity, data, RepoType::Fork)
}

/// `handle_mirror` (`server.py`). `None` sends no response.
pub fn handle_mirror(
    repos: &RwLock<Repositories>,
    identity: Option<&[u8; 16]>,
    data: &Value,
) -> Option<Vec<u8>> {
    {
        let r = repos.read().unwrap_or_else(|e| e.into_inner());
        let message = format!("Mirror request from remote {}", identity_text(identity));
        log_request(&r, &message, identity);
    }
    handle_remote_clone(repos, identity, data, RepoType::Mirror)
}

/// `_handle_remote_clone` (`server.py`). An identified link and a
/// remote identity are the same condition here: both come from LINKIDENTIFY.
fn handle_remote_clone(
    repos: &RwLock<Repositories>,
    identity: Option<&[u8; 16]>,
    data: &Value,
    repo_type: RepoType,
) -> Option<Vec<u8>> {
    let Some(hash) = identity else {
        return Some(status(RES_DISALLOWED, "Not identified"));
    };
    let Value::Map(map) = data else {
        return Some(status(RES_INVALID_REQ, "Invalid request"));
    };
    let Some(path_value) = get(map, &Value::from(IDX_REPOSITORY)) else {
        return Some(status(RES_INVALID_REQ, "No repository specified"));
    };
    // Differs from `_handle_remote_clone` (`server.py`), which admits a blocked identity.
    if repos
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .is_blocked(hash)
    {
        return Some(status(RES_NOT_FOUND, "Not found"));
    }
    let source = get(map, &Value::from("source"));
    if !source.is_some_and(truthy) {
        return Some(status(RES_INVALID_REQ, "No source specified"));
    }
    let Some(source_url) = source.and_then(Value::as_str) else {
        return Some(status(RES_INVALID_REQ, "Invalid source URL"));
    };
    let lowered = source_url.to_lowercase();
    let scheme = lowered.split("://").next().unwrap_or_default();
    if !CLONE_PROTOS.contains(&scheme) {
        return Some(status(RES_DISALLOWED, "Prohibited source URL"));
    }
    // `str.split` on anything but a string raises before the try: no reply.
    let path_str = path_value.as_str()?;
    let Some((group, repo)) =
        parse_repository_path(path_str).filter(|(g, r)| !g.is_empty() && !r.is_empty())
    else {
        return Some(status(RES_INVALID_REQ, "Invalid request"));
    };

    let final_path = {
        let r = repos.read().unwrap_or_else(|e| e.into_inner());
        let Some(group_path) = r.groups.get(group).map(|g| g.path.clone()) else {
            return Some(status(RES_NOT_FOUND, "Not found"));
        };
        let read = r.resolve_group_permission(hash, group, Perm::Read);
        let create = r.resolve_group_permission(hash, group, Perm::Create);
        if !Path::new(&group_path).exists() {
            return Some(status(RES_NOT_FOUND, "Not found"));
        }
        if !create {
            return Some(if read {
                status(RES_DISALLOWED, "Not allowed")
            } else {
                status(RES_NOT_FOUND, "Not found")
            });
        }
        let final_path = Path::new(&group_path).join(repo);
        if r.repository(group, repo).is_some() || final_path.exists() {
            return Some(if r.resolve_permission(hash, group, repo, Perm::Read) {
                status(RES_DISALLOWED, "Repository already exists")
            } else {
                status(RES_NOT_FOUND, "Not found")
            });
        }
        final_path
    };

    let reply = clone_into(repos, hash, group, repo, source_url, &final_path, repo_type);
    Some(reply.unwrap_or_else(|e| {
        tracing::error!(
            "Error while {}ing repository {group}/{repo}: {e}",
            repo_type.name()
        );
        if final_path.exists() {
            let _ = std::fs::remove_dir_all(&final_path);
        }
        status(RES_REMOTE_FAIL, "Remote error")
    }))
}

/// The `try` body of `_handle_remote_clone` (`server.py`).
fn clone_into(
    repos: &RwLock<Repositories>,
    hash: &[u8; 16],
    group: &str,
    repo: &str,
    source_url: &str,
    final_path: &Path,
    repo_type: RepoType,
) -> Result<Vec<u8>, String> {
    let kind = repo_type.name();
    tracing::debug!(
        "{}ing {source_url} to {group}/{repo} for {}",
        capitalise(kind),
        identity_text(Some(hash))
    );
    let tmpdir = tempfile::TempDir::new().map_err(|e| e.to_string())?;
    tracing::debug!("Created temporary directory {}", tmpdir.path().display());
    let temp_path = tmpdir.path().join(repo);
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o755)
            .create(&temp_path)
            .map_err(|e| e.to_string())?;
    }
    let run = |args: &[&str]| git(Some(&temp_path), args).map_err(|e| e.to_string());

    let result = run(&["init", "--bare"])?;
    if !result.status.success() {
        tracing::error!(
            "Failed to initialize bare repository at {}: {}",
            temp_path.display(),
            lossy(&result.stderr)
        );
        return Ok(status(RES_REMOTE_FAIL, "Failed to initialize repository"));
    }
    tracing::debug!("Fetching from {source_url}...");
    let result = run(&["fetch", source_url, "+refs/*:refs/*"])?;
    if !result.status.success() {
        let stderr = lossy(&result.stderr);
        tracing::error!("Failed to fetch from {source_url}: {stderr}");
        return Ok(status(
            RES_REMOTE_FAIL,
            &format!("Failed to fetch from source: {stderr}"),
        ));
    }
    update_head_to_source_default(&temp_path, source_url);

    let result = run(&["config", "repository.rngit.type", kind])?;
    if !result.status.success() {
        let stderr = lossy(&result.stderr);
        tracing::warn!("Failed to set rngit.type config: {stderr}");
        return Ok(status(
            RES_REMOTE_FAIL,
            &format!("Failed to configure repository type: {stderr}"),
        ));
    }
    let result = run(&["config", "repository.rngit.upstream.source", source_url])?;
    if !result.status.success() {
        let stderr = lossy(&result.stderr);
        tracing::warn!("Failed to set rngit.upstream.source config: {stderr}");
        return Ok(status(
            RES_REMOTE_FAIL,
            &format!("Failed to configure repository upstream source: {stderr}"),
        ));
    }
    if !set_mirror_synced(&temp_path) {
        // Upstream reports the stderr of the previous (successful) call.
        let stderr = lossy(&result.stderr);
        tracing::warn!("Failed to set rngit.upstream.sync config: {stderr}");
        return Ok(status(
            RES_REMOTE_FAIL,
            &format!("Failed to configure repository type: {stderr}"),
        ));
    }

    let allowed = format!("{}.allowed", final_path.display());
    let tmp_allowed = format!("{allowed}.tmp");
    let permissions = REPO_CREATE_PERMS_TEMPLATE.replace("{IDENTITY_HASH}", &hex::encode(hash));
    if std::fs::write(&tmp_allowed, permissions)
        .and_then(|()| std::fs::rename(&tmp_allowed, &allowed))
        .is_err()
    {
        tracing::error!("Could not set default repository permissions for {group}/{repo}");
        return Ok(status(RES_REMOTE_FAIL, "Could not initialize repository"));
    }

    if move_dir(&temp_path, final_path).is_err() {
        tracing::warn!("Failed to deploy fetched repository to group directory");
        return Ok(status(RES_REMOTE_FAIL, "Could not write repository"));
    }
    tracing::debug!(
        "Deployed fetched repository from {} to {}",
        temp_path.display(),
        final_path.display()
    );
    let loaded = repos
        .write()
        .unwrap_or_else(|e| e.into_inner())
        .load_repository(group, final_path);
    match loaded {
        Ok(true) => {
            tracing::debug!("Repository {group}/{repo} {kind}ed successfully from {source_url}");
            Ok(vec![RES_OK])
        }
        Ok(false) => {
            tracing::error!(
                "Repository {} created, but runtime loading failed",
                final_path.display()
            );
            if std::fs::remove_dir_all(final_path).is_err() {
                tracing::error!(
                    "Could not clean up failed repository init at {}",
                    final_path.display()
                );
            }
            Ok(status(RES_REMOTE_FAIL, "Failed to register repository"))
        }
        Err(e) => Err(format!("{e:?}")),
    }
}

/// `handle_sync` (`server.py`). `None` sends no response.
pub fn handle_sync(
    repos: &RwLock<Repositories>,
    identity: Option<&[u8; 16]>,
    data: &Value,
) -> Option<Vec<u8>> {
    let target = {
        let r = repos.read().unwrap_or_else(|e| e.into_inner());
        let message = format!(
            "Upstream sync request from remote {}",
            identity_text(identity)
        );
        log_request(&r, &message, identity);
        let Some(hash) = identity else {
            return Some(status(RES_DISALLOWED, "Not identified"));
        };
        let Value::Map(map) = data else {
            return Some(status(RES_INVALID_REQ, "Invalid request"));
        };
        let Some(path_value) = get(map, &Value::from(IDX_REPOSITORY)) else {
            return Some(status(RES_INVALID_REQ, "No repository specified"));
        };
        let path = parse_repository_path(path_value.as_str()?);
        let (group, repo) = path.unwrap_or(("", ""));
        let read = path.is_some() && r.resolve_permission(hash, group, repo, Perm::Read);
        let write = path.is_some() && r.resolve_permission(hash, group, repo, Perm::Write);
        if !read {
            return Some(status(RES_NOT_FOUND, "Not found"));
        }
        if !write {
            return Some(status(RES_DISALLOWED, "Not allowed"));
        }
        let repository = r.repository(group, repo).expect("resolved");
        let label = format!("{group}/{repo}");
        let mirror = repository.mirror.clone().filter(|s| !s.is_empty());
        let fork = repository.fork.clone().filter(|s| !s.is_empty());
        (label, repository.path.clone(), mirror, fork)
    };
    let (label, path, mirror, fork) = target;
    if let Some(source) = mirror {
        tracing::info!("Syncing mirror {label}");
        return Some(if sync_upstream(RepoType::Mirror, &label, &path, &source) {
            vec![RES_OK]
        } else {
            status(RES_REMOTE_FAIL, "Mirror sync failed")
        });
    }
    if let Some(source) = fork {
        tracing::info!("Syncing fork {label} with upstream");
        return Some(if sync_upstream(RepoType::Fork, &label, &path, &source) {
            vec![RES_OK]
        } else {
            status(RES_REMOTE_FAIL, "Fork sync failed")
        });
    }
    Some(status(
        RES_INVALID_REQ,
        "Repository is neither fork nor mirror",
    ))
}
