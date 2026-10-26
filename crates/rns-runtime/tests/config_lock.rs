//! The config write lock excludes a second writer and is released on drop.
//! It runs outside the unit-test binary, whose tests spawn processes: until a
//! child execs it holds copies of all its parent's descriptors, close-on-exec
//! ones included, so a dropped lock would stay held for that window.

use std::io;

use rns_runtime::config::ifac_lock::ConfigWriteLock;

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
