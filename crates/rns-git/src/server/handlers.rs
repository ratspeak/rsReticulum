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
