use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Platform {
    Linux,
    MacOS,
    Windows,
    Android,
    Other,
}

impl Platform {
    pub fn current() -> Self {
        if cfg!(target_os = "android") {
            Platform::Android
        } else if cfg!(target_os = "linux") {
            Platform::Linux
        } else if cfg!(target_os = "macos") {
            Platform::MacOS
        } else if cfg!(target_os = "windows") {
            Platform::Windows
        } else {
            Platform::Other
        }
    }

    pub fn has_unix_sockets(&self) -> bool {
        matches!(self, Platform::Linux | Platform::MacOS | Platform::Android)
    }

    pub fn config_dir(&self) -> PathBuf {
        match self {
            Platform::Windows => {
                if let Ok(appdata) = std::env::var("APPDATA") {
                    PathBuf::from(appdata).join("rsReticulum")
                } else {
                    PathBuf::from(".rsReticulum")
                }
            }
            Platform::Android => {
                // Android has no user HOME; callers must pass an explicit configdir.
                tracing::warn!(
                    "Platform::config_dir() called on Android without explicit configdir"
                );
                PathBuf::from("/data/local/tmp/.rsReticulum")
            }
            _ => {
                if let Ok(home) = std::env::var("HOME") {
                    PathBuf::from(home).join(".rsReticulum")
                } else {
                    PathBuf::from(".rsReticulum")
                }
            }
        }
    }

    pub fn display_name(&self) -> &'static str {
        match self {
            Platform::Linux => "linux",
            Platform::MacOS => "darwin",
            Platform::Windows => "win32",
            Platform::Android => "android",
            Platform::Other => "unknown",
        }
    }
}

/// Return an explicit `configdir` unchanged, without shell or tilde expansion.
/// Otherwise, on non-Windows/non-Android targets, select `/etc/rsReticulum`
/// or `$HOME/.config/rsReticulum` only if its `config` file exists, then fall
/// back to `$HOME/.rsReticulum` (or relative `.rsReticulum` without `HOME`).
/// Windows uses `$APPDATA/rsReticulum`, or relative `.rsReticulum`. Android
/// falls back to `/data/local/tmp/.rsReticulum` with a warning; applications
/// should supply their own writable config directory.
pub fn resolve_config_dir(configdir: Option<&str>) -> PathBuf {
    match configdir {
        Some(dir) => PathBuf::from(dir),
        None => {
            let platform = Platform::current();
            if !matches!(platform, Platform::Windows | Platform::Android) {
                let etc = PathBuf::from("/etc/rsReticulum");
                if etc.join("config").is_file() {
                    return etc;
                }
                if let Ok(home) = std::env::var("HOME") {
                    let xdg = PathBuf::from(home).join(".config/rsReticulum");
                    if xdg.join("config").is_file() {
                        return xdg;
                    }
                }
            }
            platform.config_dir()
        }
    }
}

pub struct StoragePaths {
    pub config_dir: PathBuf,
    pub interface_dir: PathBuf,
    pub storage_dir: PathBuf,
    pub cache_dir: PathBuf,
    pub resource_dir: PathBuf,
    pub identity_dir: PathBuf,
    pub blackhole_dir: PathBuf,
    pub announce_cache_dir: PathBuf,
}

impl StoragePaths {
    pub fn from_config_dir(config_dir: &Path) -> Self {
        let storage_dir = config_dir.join("storage");
        let cache_dir = storage_dir.join("cache");
        Self {
            config_dir: config_dir.to_path_buf(),
            interface_dir: config_dir.join("interfaces"),
            storage_dir: storage_dir.clone(),
            cache_dir: cache_dir.clone(),
            resource_dir: storage_dir.join("resources"),
            identity_dir: storage_dir.join("identities"),
            blackhole_dir: storage_dir.join("blackhole"),
            announce_cache_dir: cache_dir.join("announces"),
        }
    }

    pub fn ensure_dirs(&self) -> std::io::Result<()> {
        std::fs::create_dir_all(&self.config_dir)?;
        std::fs::create_dir_all(&self.interface_dir)?;
        std::fs::create_dir_all(&self.storage_dir)?;
        std::fs::create_dir_all(&self.cache_dir)?;
        std::fs::create_dir_all(&self.resource_dir)?;
        std::fs::create_dir_all(&self.identity_dir)?;
        std::fs::create_dir_all(&self.blackhole_dir)?;
        std::fs::create_dir_all(&self.announce_cache_dir)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_platform_detection() {
        let platform = Platform::current();
        let _ = platform.display_name();
        let _ = platform.has_unix_sockets();
        let _ = platform.config_dir();
    }

    #[test]
    fn test_explicit_config_dir() {
        let dir = resolve_config_dir(Some("/tmp/test_reticulum"));
        assert_eq!(dir, PathBuf::from("/tmp/test_reticulum"));
    }

    #[test]
    fn test_platform_config_dir_uses_rust_branded_name() {
        let dir = Platform::current().config_dir();
        assert!(
            dir.ends_with("rsReticulum")
                || dir.ends_with(".rsReticulum")
                || dir.ends_with("/data/local/tmp/.rsReticulum")
        );
    }

    #[test]
    fn test_storage_paths() {
        let config_dir = PathBuf::from("/tmp/test_config");
        let paths = StoragePaths::from_config_dir(&config_dir);
        assert_eq!(paths.interface_dir, config_dir.join("interfaces"));
        assert_eq!(paths.storage_dir, config_dir.join("storage"));
        assert_eq!(paths.cache_dir, config_dir.join("storage/cache"));
        assert_eq!(paths.resource_dir, config_dir.join("storage/resources"));
        assert_eq!(paths.identity_dir, config_dir.join("storage/identities"));
    }
}
