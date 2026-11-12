//! Repository groups and repositories on disk (`load_repository_group`,
//! `update_group_permissions`, `load_repository`, `server.py`).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use super::config::{NodeConfig, expand_user};
use super::perms::{AllowedError, Perm, Permissions, load_allowed_permissions};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Repository {
    /// The directory name, including any `.git` suffix.
    pub name: String,
    pub group: String,
    pub path: PathBuf,
    /// Upstream source URL of a fork or mirror.
    pub fork: Option<String>,
    pub mirror: Option<String>,
    pub permissions: Permissions,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Group {
    pub name: String,
    /// The expanded configured path, kept as written (a trailing `/` stays).
    pub path: String,
    pub repositories: BTreeMap<String, Repository>,
    /// Whether the group's `.allowed` file is executable.
    pub dynamic_perms: bool,
    pub permissions: Permissions,
}

/// Groups and their repositories, as the node holds them.
#[derive(Debug, Clone, Default)]
pub struct Repositories {
    pub groups: BTreeMap<String, Group>,
    pub aliases: BTreeMap<String, String>,
    pub blocked: Vec<Vec<u8>>,
}

/// A `git` call in `cwd` with output captured; `None` when it cannot run
/// or exits non-zero, as `check=True` raising into a bare `except`.
fn git_stdout(cwd: &Path, args: &[&str]) -> Option<String> {
    let output = Command::new("git")
        .args(args)
        .current_dir(cwd)
        .stdin(Stdio::null())
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

/// `_ensure_git` (`server.py`).
pub fn git_available() -> bool {
    Command::new("git")
        .arg("--version")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

/// `__is_fork` / `__is_mirror` (`server.py`).
fn upstream_source(path: &Path, kind: &str) -> Option<String> {
    if git_stdout(path, &["config", "repository.rngit.type"])? != kind {
        return None;
    }
    git_stdout(path, &["config", "repository.rngit.upstream.source"])
}

impl Repositories {
    /// Load every `[repositories]` group whose path is a directory.
    pub fn load(config: &NodeConfig) -> Result<Self, AllowedError> {
        let mut repos = Repositories {
            groups: BTreeMap::new(),
            aliases: config.aliases.clone(),
            blocked: config.blocked_identities.clone(),
        };
        for (name, raw_path) in &config.repositories {
            let path = expand_user(raw_path);
            if !path.is_dir() {
                tracing::warn!(
                    "The path \"{}\" specified for repository group \"{name}\" does not exist, skipping.",
                    path.display()
                );
                continue;
            }
            repos.load_group(name, &path.to_string_lossy(), config)?;
        }
        Ok(repos)
    }

    /// `load_repository_group` (`server.py`).
    pub fn load_group(
        &mut self,
        name: &str,
        path: &str,
        config: &NodeConfig,
    ) -> Result<(), AllowedError> {
        let group = self
            .groups
            .entry(name.to_string())
            .or_insert_with(|| Group {
                name: name.to_string(),
                path: path.to_string(),
                repositories: BTreeMap::new(),
                dynamic_perms: false,
                permissions: Permissions::default(),
            });
        if group.path != path {
            tracing::error!(
                "Repository group path did not match existing entry while loading {name}, aborting load"
            );
            return Ok(());
        }
        self.update_group_permissions(name, config);
        let entries = std::fs::read_dir(path).map_err(AllowedError::Io)?;
        for entry in entries {
            let entry = entry.map_err(AllowedError::Io)?;
            let entry_path = format!("{path}/{}", entry.file_name().to_string_lossy());
            self.load_repository(name, Path::new(&entry_path))?;
        }
        Ok(())
    }

    /// `update_group_permissions` (`server.py`): the group's
    /// `.allowed` file first, then its `[access]` statements appended.
    pub fn update_group_permissions(&mut self, name: &str, config: &NodeConfig) {
        let aliases = self.aliases.clone();
        let Some(group) = self.groups.get_mut(name) else {
            tracing::warn!(
                "Attempt to set group permissions for non-existing group {name}, aborting"
            );
            return;
        };
        let mut permissions = Permissions::default();
        let allowed = PathBuf::from(format!("{}.allowed", group.path));
        if allowed.is_file() {
            match load_allowed_permissions(&allowed, &aliases) {
                Ok((loaded, dynamic)) => {
                    permissions = loaded;
                    group.dynamic_perms = dynamic;
                }
                Err(e) => tracing::error!(
                    "Could not load group permissions from {}: {e:?}",
                    allowed.display()
                ),
            }
        } else {
            group.dynamic_perms = false;
        }
        for statement in config.access.get(name).into_iter().flatten() {
            permissions.add_statement(statement, &aliases);
        }
        group.permissions = permissions;
    }

    /// `load_repository` (`server.py`). A repository `.allowed`
    /// file that cannot be read is an error, as upstream lets it raise.
    pub fn load_repository(&mut self, group_name: &str, path: &Path) -> Result<bool, AllowedError> {
        let Some(group) = self.groups.get_mut(group_name) else {
            return Ok(false);
        };
        let path_str = path.to_string_lossy();
        if !path.is_dir() || path_str.ends_with(".work") || path_str.ends_with(".releases") {
            return Ok(false);
        }
        if git_stdout(path, &["rev-parse", "--git-dir"]).as_deref() != Some(".") {
            tracing::warn!("The directory \"{path_str}\" is not a git repository, skipping");
            return Ok(false);
        }
        if git_stdout(path, &["config", "--bool", "core.bare"]).as_deref() != Some("true") {
            tracing::warn!("The directory \"{path_str}\" is not a bare git repository, skipping");
            tracing::warn!(
                "You can change it to a bare repository using \"git config --bool core.bare true\"."
            );
            return Ok(false);
        }
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let allowed = PathBuf::from(format!("{path_str}.allowed"));
        let (permissions, _) = load_allowed_permissions(&allowed, &self.aliases)?;
        let repository = Repository {
            name: name.clone(),
            group: group_name.to_string(),
            path: path.to_path_buf(),
            fork: upstream_source(path, "fork"),
            mirror: upstream_source(path, "mirror"),
            permissions,
        };
        group.repositories.insert(name, repository);
        Ok(true)
    }

    /// `resolve_permission` (`server.py`), the only resolver that
    /// checks the blocklist.
    pub fn resolve_permission(
        &self,
        hash: &[u8; 16],
        group: &str,
        repository: &str,
        perm: Perm,
    ) -> bool {
        if self.blocked.iter().any(|b| b.as_slice() == hash) {
            return false;
        }
        let Some(g) = self.groups.get(group) else {
            return false;
        };
        let Some(r) = g.repositories.get(repository) else {
            return false;
        };
        super::perms::resolve_repository(&g.permissions, &r.permissions, hash, perm)
    }

    /// `resolve_group_permission` (`server.py`).
    pub fn resolve_group_permission(&self, hash: &[u8; 16], group: &str, perm: Perm) -> bool {
        self.groups
            .get(group)
            .is_some_and(|g| super::perms::resolve_group(&g.permissions, hash, perm))
    }

    pub fn repository(&self, group: &str, repository: &str) -> Option<&Repository> {
        self.groups.get(group)?.repositories.get(repository)
    }
}

/// `parse_request_repository_path` (`server.py`).
pub fn parse_repository_path(path: &str) -> Option<(&str, &str)> {
    let mut parts = path.split('/');
    let (Some(group), Some(repo), None) = (parts.next(), parts.next(), parts.next()) else {
        return None;
    };
    (super::py_len(group) <= 256 && super::py_len(repo) <= 256).then_some((group, repo))
}

/// `parse_request_group_path` (`server.py`).
pub fn parse_group_path(path: &str) -> Option<&str> {
    (!path.contains('/') && super::py_len(path) <= 256).then_some(path)
}
