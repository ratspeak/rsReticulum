//! The `rngit create` client side (`ReticulumGitClient`, `server.py`).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use rns_tools::rsg::pyfmt::py_fromhex;

/// `__default_rngit_config__` (`client.py`) as ConfigObj writes it.
pub const DEFAULT_CLIENT_CONFIG: &str = include_str!("default_client_config.txt");

const PROTO_SPEC: &str = "rns://";

/// `ReticulumGitClient.__init__` config directory (`server.py`),
/// including upstream's `~/.rngit/reticulum` when `~/.config/rngit/config` exists.
pub fn client_config_dir(configdir: Option<&Path>) -> PathBuf {
    if let Some(dir) = configdir {
        return dir.to_path_buf();
    }
    let home = super::config::expand_user("~");
    if home.join(".config/rngit/config").is_file() {
        home.join(".rngit/reticulum")
    } else {
        home.join(".rngit")
    }
}

/// The `[logging] loglevel` and `[aliases]` that `__apply_config` reads
/// (`server.py`). A missing file is created from the default.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ClientConfig {
    pub loglevel: Option<i64>,
    pub aliases: BTreeMap<String, String>,
}

impl ClientConfig {
    pub fn load_or_create(configdir: &Path) -> Result<Self, String> {
        let path = configdir.join("client_config");
        let text = if path.is_file() {
            std::fs::read_to_string(&path).map_err(|e| e.to_string())?
        } else {
            std::fs::create_dir_all(configdir).map_err(|e| e.to_string())?;
            std::fs::write(&path, DEFAULT_CLIENT_CONFIG).map_err(|e| e.to_string())?;
            DEFAULT_CLIENT_CONFIG.to_string()
        };
        Self::parse(&text)
    }

    pub fn parse(text: &str) -> Result<Self, String> {
        let config = rns_runtime::config::Config::parse(text).map_err(|e| e.to_string())?;
        let mut out = ClientConfig::default();
        if let Some(section) = config.section("logging").filter(|s| s.has("loglevel")) {
            let level = section
                .get_int("loglevel")
                .ok_or("invalid literal for int() with base 10")?;
            out.loglevel = Some(level.clamp(-1, 7));
        }
        if let Some(section) = config.section("aliases") {
            for alias in section.values.keys() {
                let Some(hexhash) = section.get(alias) else {
                    continue;
                };
                let hash = py_fromhex(hexhash).ok().filter(|h| !h.is_empty());
                if let Some(hash) = hash.filter(|_| hexhash.chars().count() == 32) {
                    out.aliases
                        .entry(alias.clone())
                        .or_insert_with(|| hex::encode(hash));
                }
            }
        }
        Ok(out)
    }

    /// `__resolve_destination_alias` (`server.py`).
    fn resolve(&self, alias: &str) -> String {
        let is_hash = alias.chars().count() == 32 && py_fromhex(alias).is_ok_and(|h| !h.is_empty());
        if is_hash {
            alias.to_string()
        } else {
            self.aliases
                .get(alias)
                .cloned()
                .unwrap_or_else(|| alias.to_string())
        }
    }

    fn destination(&self, remote: &str) -> Result<(Vec<u8>, Vec<String>), String> {
        let prefix_ok = remote
            .get(..PROTO_SPEC.len())
            .is_some_and(|p| p.eq_ignore_ascii_case(PROTO_SPEC));
        if !prefix_ok {
            return Err("Invalid protocol in remote URL".into());
        }
        let components: Vec<String> = remote[PROTO_SPEC.len()..]
            .split('/')
            .map(str::to_string)
            .collect();
        let hexhash = self.resolve(&components[0]);
        Ok((hexhash.into_bytes(), components))
    }

    fn decode(hexhash: &[u8]) -> Result<Vec<u8>, String> {
        let hexhash = String::from_utf8_lossy(hexhash);
        if hexhash.chars().count() != 32 {
            return Err("Invalid destination hash length".into());
        }
        py_fromhex(&hexhash).map_err(|e| format!("Invalid destination hash: {e}"))
    }

    /// `parse_remote_destination_url` (`server.py`): the abort text on error.
    pub fn parse_remote_destination_url(&self, remote: &str) -> Result<Vec<u8>, String> {
        let (hexhash, _) = self.destination(remote)?;
        Self::decode(&hexhash)
    }

    /// `parse_remote_group_url` (`server.py`): hash and group.
    pub fn parse_remote_group_url(&self, remote: &str) -> Result<(Vec<u8>, String), String> {
        let (hexhash, components) = self.destination(remote)?;
        if components.len() != 2 {
            return Err("Invalid number of URL components".into());
        }
        let hash = Self::decode(&hexhash)?;
        Ok((hash, components[1].clone()))
    }

    /// `parse_remote_url` (`server.py`): hash, group and repository.
    pub fn parse_remote_url(&self, remote: &str) -> Result<(Vec<u8>, String, String), String> {
        let (hexhash, components) = self.destination(remote)?;
        if components.len() != 3 {
            return Err("Invalid number of URL components".into());
        }
        let hash = Self::decode(&hexhash)?;
        Ok((hash, components[1].clone(), components[2].clone()))
    }
}

/// What `create_repository` prints for a `/git/create` reply
/// (`server.py`): `Ok` on success, `Err` for the abort text.
pub fn create_outcome(repo_path: &str, response: Option<&[u8]>) -> Result<String, String> {
    let Some(response) = response.filter(|r| !r.is_empty()) else {
        return Err("No response from remote".into());
    };
    let text = |fallback: &str| {
        if response.len() > 1 {
            response[1..]
                .utf8_chunks()
                .map(|chunk| chunk.valid())
                .collect()
        } else {
            fallback.to_string()
        }
    };
    match response[0] {
        super::RES_OK => Ok(format!("Repository {repo_path} created")),
        super::RES_INVALID_REQ => Err("Remote error: Invalid request".into()),
        super::RES_NOT_FOUND => Err("Not found".into()),
        super::RES_DISALLOWED => Err(text("Not allowed")),
        _ => Err(format!("Remote error: {}", text("Unknown error"))),
    }
}
