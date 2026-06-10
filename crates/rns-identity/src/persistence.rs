use std::fs;
use std::io::Write;
use std::path::Path;

/// Write `data` to `path` via `<path>.tmp` + `rename`, fsyncing first.
///
/// On Unix the temp file is created with mode `0600` so that key material is
/// not world-readable even during the write. After the rename the parent
/// directory is fsynced best-effort so the rename itself survives power loss.
pub fn atomic_write(path: &Path, data: &[u8]) -> std::io::Result<()> {
    let tmp_path = path.with_extension("tmp");

    {
        #[cfg(unix)]
        let mut f = {
            use std::os::unix::fs::OpenOptionsExt;
            std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&tmp_path)?
        };
        #[cfg(not(unix))]
        let mut f = fs::File::create(&tmp_path)?;

        f.write_all(data)?;
        f.sync_all()?;
    }

    fs::rename(&tmp_path, path)?;

    #[cfg(unix)]
    if let Some(dir) = path.parent() {
        if let Ok(d) = fs::File::open(dir) {
            let _ = d.sync_all();
        }
    }

    Ok(())
}

/// Read `path` in full, returning `None` if the file does not exist.
pub fn read_file(path: &Path) -> std::io::Result<Option<Vec<u8>>> {
    match fs::read(path) {
        Ok(data) => Ok(Some(data)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_atomic_write_and_read() {
        let dir = std::env::temp_dir().join("reticulum_test_persistence");
        let _ = fs::create_dir_all(&dir);
        let path = dir.join("test_atomic");

        atomic_write(&path, b"hello world").unwrap();
        let data = read_file(&path).unwrap().unwrap();
        assert_eq!(data, b"hello world");

        let _ = fs::remove_file(&path);
        let _ = fs::remove_dir(&dir);
    }

    #[test]
    fn test_read_nonexistent() {
        let path = PathBuf::from("/tmp/reticulum_nonexistent_file_xyz");
        let result = read_file(&path).unwrap();
        assert!(result.is_none());
    }
}
