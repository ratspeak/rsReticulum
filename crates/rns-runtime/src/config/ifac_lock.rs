//! Cross-process coordination for config snapshots and atomic replacement.
use std::fs::{File, OpenOptions};
use std::io;
use std::path::Path;

/// Held across source comparison, immutable backup and publication. The lock
/// file remains in place: deleting it would let another writer lock a different
/// inode while the first lock is still held. OS ownership releases on crash.
#[derive(Debug)]
pub struct ConfigWriteLock {
    _file: File,
}
impl ConfigWriteLock {
    /// Acquire without waiting. All cooperating config writers use this same
    /// sibling lock. External editors must be stopped during migration.
    pub fn acquire(config_path: &Path) -> io::Result<Self> {
        let parent = std::fs::canonicalize(
            config_path
                .parent()
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or(Path::new(".")),
        )?;
        let name = config_path.file_name().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "config has no file name")
        })?;
        let mut lock_name = std::ffi::OsString::from(".");
        lock_name.push(name);
        lock_name.push(".write.lock");
        let lock_path = parent.join(lock_name);
        if std::fs::symlink_metadata(&lock_path)
            .is_ok_and(|metadata| !metadata.is_file() || metadata.file_type().is_symlink())
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "config lock must be a regular file",
            ));
        }
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let file = options.open(lock_path)?;
        rns_identity::persistence::try_lock_exclusive(&file)?;
        Ok(Self { _file: file })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn config_lock_excludes_concurrent_writers_and_releases_on_drop() {
        let dir = std::env::temp_dir().join(format!(
            "rns-config-lock-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let config = dir.join("config");
        let lock = ConfigWriteLock::acquire(&config).unwrap();
        assert_eq!(
            ConfigWriteLock::acquire(&config).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        drop(lock);
        let next = ConfigWriteLock::acquire(&config).unwrap();
        drop(next);
        std::fs::remove_dir_all(dir).unwrap();
    }
}
