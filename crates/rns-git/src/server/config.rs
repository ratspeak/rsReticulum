//! Node configuration: `ReticulumGitNode.__init__` and `__apply_config`
//! (`server.py`).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use rns_identity::identity::Identity;
use rns_runtime::config::{Config, ConfigError, ConfigSection};
use rns_tools::rsg::pyfmt::py_fromhex;

use super::perms::{ALL_TGTS, resolve_identity_alias};
use super::py_len;

/// The file upstream writes when the config directory has none
/// (`__default_rngit_config__`, `server.py`), plus the fetch limit keys.
pub const DEFAULT_CONFIG: &str = include_str!("default_config.txt");

pub const DEFAULT_NODE_NAME: &str = "Anonymous Git Node";
const LOG_NONE: i64 = -1;
const LOG_EXTREME: i64 = 8;

/// Bounds on the `git fetch` of a fork, mirror, or sync, which upstream runs
/// unbounded (`_handle_remote_clone`, `__sync_mirror`, `__sync_fork`, `server.py`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FetchLimits {
    /// `fetch_time_limit`, minutes in the config file.
    pub time: Duration,
    /// `fetch_size_limit`, megabytes in the config file: the bytes a fetch may add on disk.
    pub size: u64,
}

impl Default for FetchLimits {
    fn default() -> Self {
        Self {
            time: Duration::from_secs(30 * 60),
            size: 1024 * 1024 * 1024,
        }
    }
}

/// What `__apply_config` takes from the config file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeConfig {
    pub node_name: String,
    /// Seconds; 0 never announces.
    pub announce_interval: i64,
    /// Seconds; 0 disables periodic mirror sync.
    pub mirror_interval: i64,
    pub record_stats: bool,
    pub serve_nomadnet: bool,
    /// `[logging] loglevel` plus verbosity, clamped; `None` when the key is absent.
    pub loglevel: Option<i64>,
    /// Alias name to lowercase identity hash hex.
    pub aliases: BTreeMap<String, String>,
    pub stats_ignored: Vec<Vec<u8>>,
    pub stats_push_ignored: Vec<Vec<u8>>,
    pub blocked_identities: Vec<Vec<u8>>,
    pub fetch_limits: FetchLimits,
    /// `[repositories]` group name to the configured path, before `~` expansion.
    pub repositories: BTreeMap<String, String>,
    /// `[access]` group name to its permission statements.
    pub access: BTreeMap<String, Vec<String>>,
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            node_name: DEFAULT_NODE_NAME.to_string(),
            announce_interval: 0,
            mirror_interval: 24 * 60 * 60,
            record_stats: false,
            serve_nomadnet: false,
            loglevel: None,
            aliases: BTreeMap::new(),
            stats_ignored: Vec::new(),
            stats_push_ignored: Vec::new(),
            blocked_identities: Vec::new(),
            fetch_limits: FetchLimits::default(),
            repositories: BTreeMap::new(),
            access: BTreeMap::new(),
        }
    }
}

fn invalid(section: &str, key: &str, message: &str) -> ConfigError {
    ConfigError::InvalidValue {
        section: section.to_string(),
        key: key.to_string(),
        message: message.to_string(),
    }
}

/// ConfigObj `as_int`, which raises on a value `int()` rejects.
fn as_int(section: &ConfigSection, name: &str, key: &str) -> Result<i64, ConfigError> {
    section
        .get_int(key)
        .ok_or_else(|| invalid(name, key, "not an integer"))
}

/// A fetch limit: there is no unlimited value, so anything below 1 counts as 1.
fn as_limit(section: &ConfigSection, name: &str, key: &str) -> Result<u64, ConfigError> {
    let value = as_int(section, name, key)?;
    if value < 1 {
        tracing::warn!("{key} = {value} in configuration file is below 1, using 1");
    }
    Ok(value.max(1) as u64)
}

/// ConfigObj `as_bool`, which raises on anything but its boolean words.
fn as_bool(section: &ConfigSection, name: &str, key: &str) -> Result<bool, ConfigError> {
    section
        .get_bool(key)
        .ok_or_else(|| invalid(name, key, "not a boolean"))
}

impl NodeConfig {
    /// Parse config text as `__apply_config` reads it. `verbosity` is the
    /// `-v` count minus the `-q` count, 0 in service mode.
    pub fn parse(text: &str, verbosity: i64) -> Result<Self, ConfigError> {
        let config = Config::parse(text)?;
        let mut node = NodeConfig::default();

        if let Some(section) = config.section("aliases") {
            for alias in section.values.keys() {
                let Some(hexhash) = section.get(alias) else {
                    tracing::warn!(
                        "Invalid identity hash for alias {alias} in configuration file, ignoring"
                    );
                    continue;
                };
                let hash = py_fromhex(hexhash).ok().filter(|h| !h.is_empty());
                let Some(hash) = hash.filter(|_| py_len(hexhash) == 32) else {
                    tracing::warn!(
                        "Invalid identity hash for alias {alias} in configuration file, ignoring"
                    );
                    continue;
                };
                if ALL_TGTS.contains(&alias.as_str()) {
                    tracing::warn!("Invalid alias {alias} in configuration file, ignoring");
                    continue;
                }
                node.aliases
                    .entry(alias.clone())
                    .or_insert_with(|| hex::encode(hash));
            }
        }

        if let Some(section) = config.section("rngit") {
            let name = "rngit";
            if let Some(value) = section.get("node_name") {
                node.node_name = value.to_string();
            }
            if section.has("announce_interval") {
                node.announce_interval = as_int(section, name, "announce_interval")? * 60;
            }
            if section.has("mirror_interval") {
                node.mirror_interval = (as_int(section, name, "mirror_interval")? * 3600).max(0);
            }
            if section.has("record_stats") {
                node.record_stats = as_bool(section, name, "record_stats")?;
            }
            if section.has("fetch_time_limit") {
                let minutes = as_limit(section, name, "fetch_time_limit")?;
                node.fetch_limits.time = Duration::from_secs(minutes.saturating_mul(60));
            }
            if section.has("fetch_size_limit") {
                let megabytes = as_limit(section, name, "fetch_size_limit")?;
                node.fetch_limits.size = megabytes.saturating_mul(1024 * 1024);
            }
            for (key, target) in [
                ("stats_ignore_identities", &mut node.stats_ignored),
                ("stats_push_ignore_identities", &mut node.stats_push_ignored),
                ("blocked_identities", &mut node.blocked_identities),
            ] {
                for entry in section.get_list(key).unwrap_or_default() {
                    let resolved = resolve_identity_alias(&entry, &node.aliases);
                    if py_len(&resolved) != 32 {
                        continue;
                    }
                    match py_fromhex(&resolved) {
                        Ok(hash) if !target.contains(&hash) => target.push(hash),
                        Ok(_) => {}
                        Err(_) => tracing::warn!("Invalid identity hash in {key}: {resolved}"),
                    }
                }
            }
        }

        if let Some(section) = config.section("logging").filter(|s| s.has("loglevel")) {
            let level = as_int(section, "logging", "loglevel")? + verbosity;
            node.loglevel = Some(level.clamp(LOG_NONE, LOG_EXTREME));
        }

        if let Some(section) = config.section("pages").filter(|s| s.has("serve_nomadnet")) {
            node.serve_nomadnet = as_bool(section, "pages", "serve_nomadnet")?;
        }

        if let Some(section) = config.section("repositories") {
            for key in section.values.keys() {
                if let Some(path) = section.get(key) {
                    node.repositories.insert(key.clone(), path.to_string());
                }
            }
        }

        if let Some(section) = config.section("access") {
            for key in section.values.keys() {
                node.access
                    .insert(key.clone(), section.get_list(key).unwrap_or_default());
            }
        }

        Ok(node)
    }
}

/// The config directory as `ReticulumGitNode.__init__` picks it
/// (`server.py`).
pub fn resolve_config_dir(configdir: Option<&Path>) -> PathBuf {
    if let Some(dir) = configdir {
        return dir.to_path_buf();
    }
    let etc = Path::new("/etc/rngit");
    if etc.is_dir() && etc.join("config").is_file() {
        return etc.to_path_buf();
    }
    let home = rns_runtime::platform::home_dir().unwrap_or_default();
    let user = home.join(".config/rngit");
    if user.is_dir() && user.join("config").is_file() {
        return user;
    }
    home.join(".rngit")
}

/// The config text, writing [`DEFAULT_CONFIG`] first when the file is
/// missing (`__create_default_config`, `server.py`).
pub fn read_or_create_config(configdir: &Path) -> std::io::Result<String> {
    let path = configdir.join("config");
    if path.is_file() {
        return std::fs::read_to_string(path);
    }
    tracing::info!("Could not load config file, creating default configuration file...");
    std::fs::create_dir_all(configdir)?;
    std::fs::write(&path, DEFAULT_CONFIG)?;
    Ok(DEFAULT_CONFIG.to_string())
}

/// Load `repositories_identity`, creating it when missing.
pub fn load_or_create_identity(
    path: &Path,
) -> Result<Identity, rns_identity::identity::IdentityError> {
    if path.is_file() {
        return Identity::from_file(path);
    }
    let identity = Identity::new();
    identity.to_file(path)?;
    Ok(identity)
}

/// Python `os.path.expanduser` for `~` and `~/...`, and `~\...` on Windows.
pub fn expand_user(path: &str) -> PathBuf {
    match path.strip_prefix('~') {
        Some(rest) if rest.is_empty() || rest.starts_with(std::path::is_separator) => {
            let mut home = rns_runtime::platform::home_dir()
                .unwrap_or_default()
                .into_os_string();
            home.push(rest);
            PathBuf::from(home)
        }
        _ => PathBuf::from(path),
    }
}
