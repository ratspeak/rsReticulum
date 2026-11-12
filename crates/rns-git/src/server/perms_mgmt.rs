//! `/mgmt/perms`: group and repository permission files
//! (`handle_perms` and helpers, `server.py`).

use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::RwLock;

use rmpv::Value;

use super::config::NodeConfig;
use super::handlers::{get, identity_text, log_request, status, truthy};
use super::layout::{Repositories, parse_group_path, parse_repository_path};
use super::perms::{Perm, load_allowed_permissions, parse_permission, py_splitlines};
use super::{
    IDX_GROUP, IDX_REPOSITORY, RES_DISALLOWED, RES_INVALID_REQ, RES_NOT_FOUND, RES_OK,
    RES_REMOTE_FAIL,
};

/// Upstream raised inside its `try`, replying "Remote error".
struct Raised;

fn py_strip(s: &str) -> &str {
    s.trim_matches(|c: char| c.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&c))
}

/// The validation every permission setter runs (`server.py`,
/// `4504-4517`): the first statement that does not parse, by 1-based line.
pub(crate) fn invalid_line(content: &str, aliases: &BTreeMap<String, String>) -> Option<String> {
    for (number, line) in py_splitlines(content).into_iter().enumerate() {
        let stripped = py_strip(line);
        if stripped.is_empty() || stripped.starts_with('#') {
            continue;
        }
        if let (None, _) | (_, None) = parse_permission(stripped, aliases) {
            return Some(format!(
                "Invalid permission \"{stripped}\" on line {}",
                number + 1
            ));
        }
    }
    None
}

fn get_str<'a>(data: &'a [(Value, Value)], key: &str) -> Option<&'a Value> {
    get(data, &Value::from(key))
}

/// `data.get("content", "")`, which must be a `str` for `splitlines`.
fn content_of(data: &[(Value, Value)]) -> Result<String, Raised> {
    match get_str(data, "content") {
        None => Ok(String::new()),
        Some(Value::String(s)) => s.as_str().map(str::to_string).ok_or(Raised),
        Some(_) => Err(Raised),
    }
}

/// `step == "get"` / `"set"`; `Err` is the reply.
fn step(data: &[(Value, Value)]) -> Result<bool, Vec<u8>> {
    match get_str(data, "step")
        .filter(|s| truthy(s))
        .map(Value::as_str)
    {
        None => Err(status(RES_INVALID_REQ, "Invalid request")),
        Some(Some("get")) => Ok(false),
        Some(Some("set")) => Ok(true),
        Some(_) => Err(status(RES_INVALID_REQ, "Invalid step")),
    }
}

/// The `get` step: the file's text, or "" when there is none.
fn read_allowed(path: &Path, what: &str) -> Vec<u8> {
    let text = if path.is_file() {
        match super::work::read_text(path) {
            Ok(text) => text,
            Err(e) => {
                tracing::error!("Error getting {what} permissions: {e}");
                return status(RES_REMOTE_FAIL, "Error getting permissions");
            }
        }
    } else {
        String::new()
    };
    let mut reply = vec![RES_OK];
    rmpv::encode::write_value(
        &mut reply,
        &Value::Map(vec![(Value::from("content"), Value::from(text))]),
    )
    .expect("msgpack write to memory");
    reply
}

/// The file part of the `set` step: refuse an executable resolver, then
/// write through `<path>.tmp` and a rename. `Ok(None)` was written.
fn write_allowed(path: &Path, content: &str) -> Option<Vec<u8>> {
    if nix::unistd::access(path, nix::unistd::AccessFlags::X_OK).is_ok() {
        return Some(status(
            RES_DISALLOWED,
            "Executable permission resolvers can only be modified node-side",
        ));
    }
    let mut tmp = path.as_os_str().to_os_string();
    tmp.push(".tmp");
    let tmp = PathBuf::from(tmp);
    let written = std::fs::File::create(&tmp)
        .and_then(|mut f| f.write_all(content.as_bytes()))
        .and_then(|_| std::fs::rename(&tmp, path));
    match written {
        Ok(()) => None,
        Err(e) => {
            tracing::error!("Error setting permissions: {e}");
            Some(status(RES_REMOTE_FAIL, "Error setting permissions"))
        }
    }
}

/// `_group_permissions` and its steps (`server.py`).
fn group_permissions(
    repos: &RwLock<Repositories>,
    config: &NodeConfig,
    hash: &[u8; 16],
    group: Option<&str>,
    data: &[(Value, Value)],
) -> Result<Vec<u8>, Raised> {
    let guard = repos.read().unwrap_or_else(|e| e.into_inner());
    let resolve = |perm| group.is_some_and(|g| guard.resolve_group_permission(hash, g, perm));
    if !resolve(Perm::Read) {
        return Ok(status(RES_NOT_FOUND, "Not found"));
    }
    if !resolve(Perm::Admin) {
        return Ok(status(RES_DISALLOWED, "Not allowed"));
    }
    let set = match step(data) {
        Ok(set) => set,
        Err(reply) => return Ok(reply),
    };
    let group = group.expect("resolved");
    let allowed = PathBuf::from(format!("{}.allowed", guard.groups[group].path));
    if !set {
        return Ok(read_allowed(&allowed, "group"));
    }
    let content = content_of(data)?;
    if let Some(message) = invalid_line(&content, &guard.aliases) {
        return Ok(status(RES_INVALID_REQ, &message));
    }
    if let Some(reply) = write_allowed(&allowed, &content) {
        return Ok(reply);
    }
    drop(guard);
    repos
        .write()
        .unwrap_or_else(|e| e.into_inner())
        .update_group_permissions(group, config);
    tracing::info!(
        "Permissions for group {group} updated by <{}>",
        hex::encode(hash)
    );
    Ok(vec![RES_OK])
}

/// `update_repository_permissions` (`server.py`): the repository
/// file alone replaces the repository's lists.
fn update_repository_permissions(repos: &mut Repositories, group: &str, repository: &str) {
    let aliases = repos.aliases.clone();
    let Some(repo) = repos
        .groups
        .get_mut(group)
        .and_then(|g| g.repositories.get_mut(repository))
    else {
        return;
    };
    let allowed = PathBuf::from(format!("{}.allowed", repo.path.display()));
    match load_allowed_permissions(&allowed, &aliases) {
        Ok((permissions, _)) => repo.permissions = permissions,
        Err(e) => tracing::error!(
            "Could not update repository permissions for {group}/{repository} from {}: {e:?}",
            allowed.display()
        ),
    }
}

/// `_repository_permissions` and its steps (`server.py`). Setting
/// takes group READ and ADMIN on top of repository ADMIN.
fn repository_permissions(
    repos: &RwLock<Repositories>,
    hash: &[u8; 16],
    group: &str,
    repository: &str,
    data: &[(Value, Value)],
) -> Result<Vec<u8>, Raised> {
    let guard = repos.read().unwrap_or_else(|e| e.into_inner());
    if !guard.resolve_permission(hash, group, repository, Perm::Read) {
        return Ok(status(RES_NOT_FOUND, "Not found"));
    }
    let set = match step(data) {
        Ok(set) => set,
        Err(reply) => return Ok(reply),
    };
    let allowed = PathBuf::from(format!(
        "{}.allowed",
        guard.groups[group].repositories[repository].path.display()
    ));
    if !set {
        return Ok(read_allowed(&allowed, "repository"));
    }
    if !guard.resolve_group_permission(hash, group, Perm::Read) {
        return Ok(status(RES_NOT_FOUND, "Not found"));
    }
    if !guard.resolve_group_permission(hash, group, Perm::Admin) {
        return Ok(status(RES_DISALLOWED, "Not allowed"));
    }
    let content = content_of(data)?;
    if let Some(message) = invalid_line(&content, &guard.aliases) {
        return Ok(status(RES_INVALID_REQ, &message));
    }
    if let Some(reply) = write_allowed(&allowed, &content) {
        return Ok(reply);
    }
    drop(guard);
    update_repository_permissions(
        &mut repos.write().unwrap_or_else(|e| e.into_inner()),
        group,
        repository,
    );
    tracing::info!(
        "Permissions for repository {group}/{repository} updated by <{}>",
        hex::encode(hash)
    );
    Ok(vec![RES_OK])
}

/// `handle_perms` (`server.py`).
pub fn handle_perms(
    repos: &RwLock<Repositories>,
    config: &NodeConfig,
    identity: Option<&[u8; 16]>,
    data: &Value,
) -> Vec<u8> {
    {
        let guard = repos.read().unwrap_or_else(|e| e.into_inner());
        let message = format!(
            "Permissions request from remote {}",
            identity_text(identity)
        );
        log_request(&guard, &message, identity);
    }
    let Some(hash) = identity else {
        return status(RES_DISALLOWED, "Not identified");
    };
    let Value::Map(data) = data else {
        return status(RES_INVALID_REQ, "Invalid request");
    };
    let reply = (|| -> Result<Vec<u8>, Raised> {
        let Some(operation) = get_str(data, "operation").filter(|o| truthy(o)) else {
            return Ok(status(RES_INVALID_REQ, "Invalid request"));
        };
        match operation.as_str() {
            Some("gperms") => {
                let Some(group) = get(data, &Value::from(IDX_GROUP)) else {
                    return Ok(status(RES_INVALID_REQ, "No group specified"));
                };
                let group = parse_group_path(group.as_str().ok_or(Raised)?);
                group_permissions(repos, config, hash, group, data)
            }
            Some("rperms") => {
                let Some(path) = get(data, &Value::from(IDX_REPOSITORY)) else {
                    return Ok(status(RES_INVALID_REQ, "No repository specified"));
                };
                let path = parse_repository_path(path.as_str().ok_or(Raised)?);
                let (group, repository) = path.unwrap_or(("", ""));
                let (read, admin) = {
                    let guard = repos.read().unwrap_or_else(|e| e.into_inner());
                    let resolve = |perm| {
                        path.is_some() && guard.resolve_permission(hash, group, repository, perm)
                    };
                    (resolve(Perm::Read), resolve(Perm::Admin))
                };
                if !admin {
                    return Ok(if read {
                        status(RES_DISALLOWED, "Not allowed")
                    } else {
                        status(RES_NOT_FOUND, "Not found")
                    });
                }
                repository_permissions(repos, hash, group, repository, data)
            }
            _ => Ok(status(RES_INVALID_REQ, "Invalid request")),
        }
    })();
    reply.unwrap_or_else(|Raised| {
        tracing::error!(
            "Error while handling permissions request from {}",
            identity_text(identity)
        );
        status(RES_REMOTE_FAIL, "Remote error")
    })
}
