use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use zeroize::Zeroizing;

mod file_lock;
mod strict;
pub use file_lock::try_lock_exclusive;
pub use strict::{
    DurableCleanupOutcome, DurableCommitPhase, DurableDirectoryReceipt, DurableErrorKind,
    DurableFileReceipt, DurableWriteError, StorageRisk, durable_create_dir_all, durable_reconcile,
    durable_reconcile_directory, durable_reconcile_hash, durable_remove, durable_rename_directory,
    durable_write, storage_risk, validate_durable_storage_directory,
};

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

/// Compare the file at `path` with `data`. The file is read through a stack
/// buffer that is wiped afterwards, so reading back a secret leaves no copy.
fn verify_bytes(path: &Path, data: &[u8]) -> std::io::Result<()> {
    let mut file = fs::File::open(path)?;
    let mut offset: usize = 0;
    let mut chunk = Zeroizing::new([0u8; 8192]);
    loop {
        let count = file.read(&mut chunk[..])?;
        if count == 0 {
            break;
        }
        let end = offset
            .checked_add(count)
            .filter(|end| data.get(offset..*end) == Some(&chunk[..count]))
            .ok_or_else(|| invalid_data("file readback mismatch"))?;
        offset = end;
    }
    if offset != data.len() {
        return Err(invalid_data("file readback length mismatch"));
    }
    Ok(())
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
    let _write_guard = ATOMIC_WRITE_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let tmp_path = unique_temp_path(path)?;

    let result = (|| {
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

        f.write_all(data)?;
        f.flush()?;
        f.sync_all()?;
        drop(f);

        verify_bytes(&tmp_path, data)?;
        atomic_replace(&tmp_path, path)?;
        verify_bytes(path, data)?;

        #[cfg(unix)]
        if let Some(dir) = path.parent()
            && let Ok(d) = fs::File::open(dir)
        {
            let _ = d.sync_all();
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

    fn unique_test_dir(label: &str) -> PathBuf {
        static NEXT_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let id = NEXT_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "reticulum-{label}-{}-{}-{id}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ))
    }

    #[test]
    fn test_atomic_write_and_read() {
        let dir = unique_test_dir("persistence");
        fs::create_dir_all(&dir).unwrap();
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

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_read_nonexistent() {
        let path = unique_test_dir("nonexistent").join("missing");
        let result = read_file(&path).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_bounded_read_rejects_oversize_file() {
        let dir = unique_test_dir("bounded-read");
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("bounded");
        fs::write(&path, [0xA5; 17]).unwrap();

        let err = read_file_bounded(&path, 16).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        assert_eq!(read_file_bounded(&path, 17).unwrap().unwrap().len(), 17);

        fs::remove_dir_all(dir).unwrap();
    }

    /// Re-run `test` in a child process whose files are limited to `limit`
    /// bytes, with SIGXFSZ ignored so a longer write fails with EFBIG. Returns
    /// true in the child, which then runs the test body.
    #[cfg(unix)]
    pub(super) fn in_file_size_limited_child(test: &str, limit: u64) -> bool {
        const CHILD: &str = "RNS_FILE_SIZE_LIMITED_CHILD";
        if std::env::var_os(CHILD).is_some() {
            unsafe {
                libc::signal(libc::SIGXFSZ, libc::SIG_IGN);
                let mut current = std::mem::zeroed::<libc::rlimit>();
                assert_eq!(libc::getrlimit(libc::RLIMIT_FSIZE, &mut current), 0);
                current.rlim_cur = limit as libc::rlim_t;
                assert_eq!(libc::setrlimit(libc::RLIMIT_FSIZE, &current), 0);
            }
            return true;
        }
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([test, "--exact", "--nocapture", "--test-threads=1"])
            .env(CHILD, "1")
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success() && stdout.contains("1 passed"),
            "file-size-limited child failed:\n{stdout}\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
        false
    }

    /// Root ignores directory permissions.
    #[cfg(unix)]
    pub(super) fn is_root() -> bool {
        unsafe { libc::geteuid() == 0 }
    }

    /// Holds the macOS user immutable flag (`chflags uchg`) on a file.
    #[cfg(target_os = "macos")]
    pub(super) struct Immutable(PathBuf);

    #[cfg(target_os = "macos")]
    impl Immutable {
        pub(super) fn new(path: &Path) -> Self {
            Self::set(path, libc::UF_IMMUTABLE);
            Self(path.to_path_buf())
        }

        fn set(path: &Path, flags: libc::c_uint) {
            use std::os::unix::ffi::OsStrExt;
            let path = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
            assert_eq!(unsafe { libc::chflags(path.as_ptr(), flags) }, 0);
        }
    }

    #[cfg(target_os = "macos")]
    impl Drop for Immutable {
        fn drop(&mut self) {
            Self::set(&self.0, 0);
        }
    }

    #[test]
    fn atomic_write_into_a_missing_directory_fails_without_creating_it() {
        let dir = unique_test_dir("atomic-missing-parent");
        let err = atomic_write(&dir.join("state"), b"candidate").unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
        assert!(!dir.exists());
    }

    #[cfg(unix)]
    #[test]
    fn atomic_write_in_a_read_only_directory_keeps_the_previous_file() {
        use std::os::unix::fs::PermissionsExt;
        if is_root() {
            return;
        }
        let dir = unique_test_dir("atomic-read-only");
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("state");
        fs::write(&path, b"previous").unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o500)).unwrap();

        let result = atomic_write(&path, b"candidate");
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();

        assert_eq!(
            result.unwrap_err().kind(),
            std::io::ErrorKind::PermissionDenied
        );
        assert_eq!(fs::read(&path).unwrap(), b"previous");
        assert_eq!(fs::read_dir(&dir).unwrap().count(), 1);
        fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn atomic_write_beyond_the_file_size_limit_keeps_the_previous_file() {
        if !in_file_size_limited_child(
            "persistence::tests::atomic_write_beyond_the_file_size_limit_keeps_the_previous_file",
            4096,
        ) {
            return;
        }
        let dir = unique_test_dir("atomic-file-size");
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("state");
        fs::write(&path, b"previous").unwrap();

        let err = atomic_write(&path, &[0x5a; 16384]).unwrap_err();

        assert_eq!(err.raw_os_error(), Some(libc::EFBIG));
        assert_eq!(fs::read(&path).unwrap(), b"previous");
        assert_eq!(fs::read_dir(&dir).unwrap().count(), 1);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn atomic_write_onto_a_directory_leaves_it_and_no_temporary_file() {
        let dir = unique_test_dir("atomic-directory-target");
        let target = dir.join("state");
        fs::create_dir_all(&target).unwrap();
        fs::write(target.join("kept"), b"kept").unwrap();

        assert!(atomic_write(&target, b"candidate").is_err());

        assert_eq!(fs::read(target.join("kept")).unwrap(), b"kept");
        assert_eq!(fs::read_dir(&dir).unwrap().count(), 1);
        fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn atomic_write_onto_an_immutable_file_keeps_it() {
        let dir = unique_test_dir("atomic-immutable");
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("state");
        fs::write(&path, b"previous").unwrap();
        let immutable = Immutable::new(&path);

        let result = atomic_write(&path, b"candidate");
        drop(immutable);

        assert!(result.is_err());
        assert_eq!(fs::read(&path).unwrap(), b"previous");
        assert_eq!(fs::read_dir(&dir).unwrap().count(), 1);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn readback_verification_rejects_changed_short_and_long_files() {
        let dir = unique_test_dir("readback");
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("state");
        let data: Vec<u8> = (0..20_000u32).map(|i| (i % 251) as u8).collect();

        fs::write(&path, &data).unwrap();
        verify_bytes(&path, &data).unwrap();
        let mut changed = data.clone();
        changed[12_345] ^= 1;
        for (name, contents) in [
            ("changed", changed),
            ("short", data[..data.len() - 1].to_vec()),
            ("long", [&data[..], b"!"].concat()),
            ("empty", Vec::new()),
        ] {
            fs::write(&path, contents).unwrap();
            let err = verify_bytes(&path, &data).unwrap_err();
            assert_eq!(err.kind(), std::io::ErrorKind::InvalidData, "{name}");
        }

        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn concurrent_atomic_writers_do_not_share_temp_paths() {
        let dir = unique_test_dir("atomic-concurrent");
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
