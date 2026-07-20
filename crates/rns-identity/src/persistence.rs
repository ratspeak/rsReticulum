use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

static TEMP_FILE_COUNTER: AtomicU64 = AtomicU64::new(0);
static ATOMIC_WRITE_LOCK: Mutex<()> = Mutex::new(());

fn invalid_data(message: &'static str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, message)
}

fn unique_temp_path(path: &Path) -> std::io::Result<PathBuf> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let file_name = path.file_name().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "atomic-write target has no file name",
        )
    })?;
    let sequence = TEMP_FILE_COUNTER.fetch_add(1, Ordering::Relaxed);
    let mut temp_name = file_name.to_os_string();
    temp_name.push(format!(".tmp-{}-{sequence}", std::process::id()));
    Ok(parent.join(temp_name))
}

#[cfg(not(windows))]
fn atomic_replace(source: &Path, destination: &Path) -> std::io::Result<()> {
    fs::rename(source, destination)
}

#[cfg(windows)]
fn atomic_replace(source: &Path, destination: &Path) -> std::io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{
        MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW,
    };

    let source: Vec<u16> = source.as_os_str().encode_wide().chain(Some(0)).collect();
    let destination: Vec<u16> = destination
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect();
    // Same-directory temporary files keep this on one volume. MoveFileExW is
    // the Windows replacement primitive; std::fs::rename rejects an existing
    // destination on Windows instead of replacing it.
    let replaced = unsafe {
        MoveFileExW(
            source.as_ptr(),
            destination.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    };
    if replaced == 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(not(test), allow(dead_code))]
enum InjectedFailure {
    Create,
    Write,
    Flush,
    Sync,
    VerifyTemp,
    Rename,
    VerifyFinal,
}

fn fail_if(stage: InjectedFailure, injected: Option<InjectedFailure>) -> std::io::Result<()> {
    if injected == Some(stage) {
        Err(std::io::Error::other(format!(
            "injected atomic-write failure at {stage:?}"
        )))
    } else {
        Ok(())
    }
}

/// Write `data` to `path` via a unique same-directory temporary file and
/// atomic rename.
///
/// On Unix the temp file is created with mode `0600` so that key material is
/// not world-readable even during the write. The bytes are flushed, fsynced,
/// and verified before the rename, then verified again at the final path. After
/// the rename the parent directory is fsynced best-effort so the directory
/// entry itself survives power loss.
pub fn atomic_write(path: &Path, data: &[u8]) -> std::io::Result<()> {
    atomic_write_inner(path, data, None)
}

fn atomic_write_inner(
    path: &Path,
    data: &[u8],
    injected: Option<InjectedFailure>,
) -> std::io::Result<()> {
    let _write_guard = ATOMIC_WRITE_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let tmp_path = unique_temp_path(path)?;

    let result = (|| {
        fail_if(InjectedFailure::Create, injected)?;

        #[cfg(unix)]
        let mut f = {
            use std::os::unix::fs::OpenOptionsExt;
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&tmp_path)?
        };
        #[cfg(not(unix))]
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp_path)?;

        fail_if(InjectedFailure::Write, injected)?;
        f.write_all(data)?;

        fail_if(InjectedFailure::Flush, injected)?;
        f.flush()?;

        fail_if(InjectedFailure::Sync, injected)?;
        f.sync_all()?;
        drop(f);

        fail_if(InjectedFailure::VerifyTemp, injected)?;
        let temp_data = read_file_bounded(&tmp_path, data.len())?
            .ok_or_else(|| invalid_data("atomic-write temp file disappeared"))?;
        if temp_data != data {
            return Err(invalid_data("atomic-write temp verification failed"));
        }

        fail_if(InjectedFailure::Rename, injected)?;
        atomic_replace(&tmp_path, path)?;

        fail_if(InjectedFailure::VerifyFinal, injected)?;
        let final_data = read_file_bounded(path, data.len())?
            .ok_or_else(|| invalid_data("atomic-write target disappeared"))?;
        if final_data != data {
            return Err(invalid_data("atomic-write final verification failed"));
        }

        #[cfg(unix)]
        if let Some(dir) = path.parent() {
            if let Ok(d) = fs::File::open(dir) {
                let _ = d.sync_all();
            }
        }

        Ok(())
    })();

    if result.is_err() {
        let _ = fs::remove_file(&tmp_path);
    }

    result
}

/// Read `path` in full, returning `None` if the file does not exist.
pub fn read_file(path: &Path) -> std::io::Result<Option<Vec<u8>>> {
    match fs::read(path) {
        Ok(data) => Ok(Some(data)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

/// Read at most `max_len` bytes from `path`.
///
/// A file larger than the supplied bound is rejected before it can be handed
/// to a deserializer. `None` means the path did not exist.
pub fn read_file_bounded(path: &Path, max_len: usize) -> std::io::Result<Option<Vec<u8>>> {
    let file = match fs::File::open(path) {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };

    let mut data = Vec::with_capacity(max_len.min(4096));
    file.take(max_len.saturating_add(1) as u64)
        .read_to_end(&mut data)?;
    if data.len() > max_len {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("file exceeds {max_len}-byte limit"),
        ));
    }
    Ok(Some(data))
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

        atomic_write(&path, b"replacement").unwrap();
        let data = read_file(&path).unwrap().unwrap();
        assert_eq!(
            data, b"replacement",
            "Windows must replace an existing state file instead of failing after the first write"
        );

        let _ = fs::remove_file(&path);
        let _ = fs::remove_dir(&dir);
    }

    #[test]
    fn test_read_nonexistent() {
        let path = PathBuf::from("/tmp/reticulum_nonexistent_file_xyz");
        let result = read_file(&path).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_bounded_read_rejects_oversize_file() {
        let dir = std::env::temp_dir().join("reticulum_test_bounded_read");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("bounded");
        fs::write(&path, [0xA5; 17]).unwrap();

        let err = read_file_bounded(&path, 16).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        assert_eq!(read_file_bounded(&path, 17).unwrap().unwrap().len(), 17);

        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn test_atomic_write_faults_before_rename_preserve_previous_file() {
        let dir = std::env::temp_dir().join("reticulum_test_atomic_faults");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("state");
        fs::write(&path, b"previous").unwrap();

        for stage in [
            InjectedFailure::Create,
            InjectedFailure::Write,
            InjectedFailure::Flush,
            InjectedFailure::Sync,
            InjectedFailure::VerifyTemp,
            InjectedFailure::Rename,
        ] {
            let err = atomic_write_inner(&path, b"candidate", Some(stage)).unwrap_err();
            assert!(err.to_string().contains("injected"));
            assert_eq!(fs::read(&path).unwrap(), b"previous", "stage {stage:?}");
        }

        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn test_atomic_write_final_readback_failure_is_reported() {
        let dir = std::env::temp_dir().join("reticulum_test_atomic_readback_fault");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("state");
        fs::write(&path, b"previous").unwrap();

        let err = atomic_write_inner(&path, b"candidate", Some(InjectedFailure::VerifyFinal))
            .unwrap_err();
        assert!(err.to_string().contains("injected"));
        assert_eq!(
            fs::read(&path).unwrap(),
            b"candidate",
            "the caller must not commit live state even if replacement reached disk"
        );

        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn concurrent_atomic_writers_do_not_share_temp_paths() {
        let dir = std::env::temp_dir().join("reticulum_test_atomic_concurrent");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("state");

        let mut writers = Vec::new();
        for byte in 0u8..16 {
            let path = path.clone();
            writers.push(std::thread::spawn(move || atomic_write(&path, &[byte; 64])));
        }
        for writer in writers {
            writer.join().unwrap().unwrap();
        }

        let final_data = fs::read(&path).unwrap();
        assert_eq!(final_data.len(), 64);
        assert!(final_data.iter().all(|byte| *byte == final_data[0]));
        assert_eq!(fs::read_dir(&dir).unwrap().count(), 1);

        fs::remove_dir_all(dir).unwrap();
    }
}
