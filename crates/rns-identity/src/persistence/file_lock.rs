//! Nonblocking OS file-lock portability. Android's standard-library File lock
//! implementation is unsupported on some supported toolchains; bionic flock
//! provides the same retained-open-file-description ownership on that target.
use std::fs::File;
use std::io;

/// Take an exclusive advisory lock without waiting. Retain the original file
/// for the complete protected operation; do not clone/close handles to transfer
/// ownership since duplication semantics differ by platform. Closing the owning
/// handles (including on process exit) releases the lock. Contention is
/// `WouldBlock`, and unsupported or failed backends are errors, never success.
/// Do not delete/recreate the lock file while an owner may still hold it.
pub fn try_lock_exclusive(file: &File) -> io::Result<()> {
    #[cfg(target_os = "android")]
    {
        use std::os::fd::AsRawFd;
        // SAFETY: the borrowed File keeps its descriptor alive for this call;
        // flock neither takes ownership nor writes through any Rust pointer.
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }
    #[cfg(not(target_os = "android"))]
    file.try_lock().map_err(|error| match error {
        std::fs::TryLockError::WouldBlock => {
            io::Error::new(io::ErrorKind::WouldBlock, "file is locked by another owner")
        }
        std::fs::TryLockError::Error(error) => error,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn lock_files() -> (std::path::PathBuf, File, File) {
        let path = super::super::tests::unique_test_dir("native-lock");
        let first = File::create_new(&path).unwrap();
        let second = File::options().read(true).write(true).open(&path).unwrap();
        (path, first, second)
    }
    #[test]
    fn native_file_lock_contends_and_releases_on_drop() {
        let (path, first, second) = lock_files();
        try_lock_exclusive(&first).unwrap();
        assert_eq!(
            try_lock_exclusive(&second).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        drop(first);
        try_lock_exclusive(&second).unwrap();
        drop(second);
        std::fs::remove_file(path).unwrap();
    }
    #[cfg(unix)]
    #[test]
    fn native_file_lock_duplicate_keeps_exclusion_until_last_close() {
        let (path, first, second) = lock_files();
        try_lock_exclusive(&first).unwrap();
        let retained = first.try_clone().unwrap();
        drop(first);
        assert_eq!(
            try_lock_exclusive(&second).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        drop(retained);
        try_lock_exclusive(&second).unwrap();
        drop(second);
        std::fs::remove_file(path).unwrap();
    }
}
