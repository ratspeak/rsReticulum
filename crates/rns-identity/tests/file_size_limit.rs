//! Writes beyond the process file-size limit fail with EFBIG and keep the
//! previous file. Each test re-runs itself in a child with a lowered limit.
//! Spawning stays out of the unit-test binary: until a child execs it holds
//! copies of all its parent's descriptors, close-on-exec ones included, so a
//! sibling test's lock or FIFO end would outlive that test's close.
#![cfg(unix)]

use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use rns_identity::persistence::{DurableCommitPhase, atomic_write, durable_write};

fn unique_test_dir(label: &str) -> PathBuf {
    static NEXT_ID: AtomicU64 = AtomicU64::new(0);
    let dir = std::env::temp_dir().join(format!(
        "reticulum-{label}-{}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos(),
        NEXT_ID.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir_all(&dir).unwrap();
    dir
}

/// Re-run `test` in a child process whose files are limited to `limit`
/// bytes, with SIGXFSZ ignored so a longer write fails with EFBIG. Returns
/// true in the child, which then runs the test body.
fn in_file_size_limited_child(test: &str, limit: u64) -> bool {
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

#[test]
fn atomic_write_beyond_the_file_size_limit_keeps_the_previous_file() {
    if !in_file_size_limited_child(
        "atomic_write_beyond_the_file_size_limit_keeps_the_previous_file",
        4096,
    ) {
        return;
    }
    let dir = unique_test_dir("atomic-file-size");
    let path = dir.join("state");
    fs::write(&path, b"previous").unwrap();

    let err = atomic_write(&path, &[0x5a; 16384]).unwrap_err();

    assert_eq!(err.raw_os_error(), Some(libc::EFBIG));
    assert_eq!(fs::read(&path).unwrap(), b"previous");
    assert_eq!(fs::read_dir(&dir).unwrap().count(), 1);
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn strict_write_beyond_the_file_size_limit_keeps_the_previous_file() {
    if !in_file_size_limited_child(
        "strict_write_beyond_the_file_size_limit_keeps_the_previous_file",
        4096,
    ) {
        return;
    }
    let root = unique_test_dir("durable-file-size");
    let target = root.join("state");
    durable_write(&target, b"old").unwrap();

    let failure = durable_write(&target, &[0x5a; 16384]).unwrap_err();

    assert_eq!(failure.phase, DurableCommitPhase::NotCommitted);
    let source = std::error::Error::source(&failure)
        .and_then(|source| source.downcast_ref::<std::io::Error>())
        .unwrap();
    assert_eq!(source.raw_os_error(), Some(libc::EFBIG));
    assert_eq!(fs::read(&target).unwrap(), b"old");
    assert_eq!(failure.recovery_paths.len(), 2);
    fs::remove_dir_all(root).unwrap();
}
