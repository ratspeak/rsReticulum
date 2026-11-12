//! `rngit perms` (`group_permissions` and `repository_permissions`,
//! `server.py`).

use std::io::Write;

use rmpv::Value;

use super::releases::{Connect, Fail};
use super::work::edit_remote_permissions;
use crate::server::client::ClientConfig;
use crate::server::{IDX_GROUP, IDX_REPOSITORY};

/// Which file a `perms` URL names: 4 components a group, 5 a repository.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PermsTarget {
    Group,
    Repository,
}

/// `args.remote.rstrip("/")` and the component count (`server.py`);
/// `None` is "Invalid URL".
pub fn perms_target(remote: &str) -> Option<(String, PermsTarget)> {
    let remote = remote.trim_end_matches('/').to_string();
    match remote.split('/').count() {
        5 => Some((remote, PermsTarget::Repository)),
        4 => Some((remote, PermsTarget::Group)),
        _ => None,
    }
}

fn map(entries: Vec<(Value, Value)>) -> Value {
    Value::Map(entries)
}

/// `rngit perms <url>` once Reticulum is up. `Ok` is the exit code.
pub fn run_perms(
    out: &mut dyn Write,
    config: &ClientConfig,
    connect: &mut Connect<'_>,
    remote: &str,
    target: PermsTarget,
) -> Result<i32, Fail> {
    let mut link = connect(remote, "Failed to establish link")?;
    let _ = write!(out, "\r                       \r");
    let (key, name, operation) = match target {
        PermsTarget::Group => (
            Value::from(IDX_GROUP),
            config
                .parse_remote_group_url(remote)
                .map_err(Fail::Abort)?
                .1,
            "gperms",
        ),
        PermsTarget::Repository => {
            let (_, group, repo) = config.parse_remote_url(remote).map_err(Fail::Abort)?;
            (
                Value::from(IDX_REPOSITORY),
                format!("{group}/{repo}"),
                "rperms",
            )
        }
    };
    let get = map(vec![
        (key.clone(), Value::from(name.as_str())),
        (Value::from("operation"), Value::from(operation)),
        (Value::from("step"), Value::from("get")),
    ]);
    let set = |content: String| {
        map(vec![
            (key.clone(), Value::from(name.as_str())),
            (Value::from("operation"), Value::from(operation)),
            (Value::from("step"), Value::from("set")),
            (Value::from("content"), Value::from(content)),
        ])
    };
    if edit_remote_permissions(out, link.as_mut(), get, set)? {
        match target {
            PermsTarget::Group => writeln!(out, "Permissions updated for group {name}"),
            PermsTarget::Repository => writeln!(out, "Permissions updated for {name}"),
        }
        .ok();
    }
    Ok(0)
}
