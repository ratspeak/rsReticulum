#[cfg(unix)]
use std::fs;
#[cfg(unix)]
use std::path::{Path, PathBuf};
#[cfg(unix)]
use std::process::{Child, Command, Stdio};
#[cfg(unix)]
use std::thread;
#[cfg(unix)]
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[cfg(unix)]
struct TempDir {
    path: PathBuf,
}

#[cfg(unix)]
impl TempDir {
    fn new(prefix: &str) -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock before unix epoch")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "rsreticulum-{prefix}-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir_all(&path).expect("create tempdir");
        Self { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

#[cfg(unix)]
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

#[cfg(unix)]
fn write_config(tmp: &TempDir, enable_transport: bool) {
    let enable_transport = if enable_transport { "Yes" } else { "No" };
    fs::write(
        tmp.path().join("config"),
        format!(
            "[reticulum]\nshare_instance = No\nenable_transport = {enable_transport}\n\n[interfaces]\n"
        ),
    )
    .expect("write config");
}

#[cfg(unix)]
fn wait_until_running(child: &mut Child, settle: Duration) -> bool {
    let deadline = Instant::now() + settle;
    while Instant::now() < deadline {
        if child.try_wait().expect("poll child").is_some() {
            return false;
        }
        thread::sleep(Duration::from_millis(50));
    }
    true
}

/// Being alive does not mean runtime initialization has finished. In particular,
/// rnsd can already handle SIGTERM while it is still admitting interfaces.
#[cfg(unix)]
fn wait_for_ready_log(child: &mut Child, log: &Path, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        if child.try_wait().expect("poll child readiness").is_some() {
            return false;
        }
        if fs::read_to_string(log)
            .is_ok_and(|text| text.contains("reticulum started in Standalone mode"))
        {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        thread::sleep(Duration::from_millis(50));
    }
}

/// Sends a process signal after observed readiness (or a settle period for the
/// interactive listeners) and asserts a clean exit. The settle-only path retries once
/// with a longer settle if the child died from the raw signal (exit by signal
/// number): under full-workspace load the child can still be booting when the
/// first signal lands, before its handler is registered. A real handler
/// regression fails both attempts.
#[cfg(unix)]
fn assert_signal_exits(
    spawn: impl Fn() -> Child,
    name: &str,
    signal_name: &str,
    signal_number: i32,
    ready_log: Option<&Path>,
) {
    use std::os::unix::process::ExitStatusExt;

    let settles = [Duration::from_secs(3), Duration::from_secs(8)];
    let last_attempt = settles.len() - 1;
    for (attempt, settle) in settles.into_iter().enumerate() {
        let mut child = spawn();
        let ready = match ready_log {
            Some(log) => wait_for_ready_log(&mut child, log, Duration::from_secs(20)),
            None => wait_until_running(&mut child, settle),
        };
        if !ready {
            let _ = child.kill();
            let output = child.wait_with_output().expect("collect child output");
            panic!(
                "{name} did not become ready before {signal_name}\nstatus: {}\nstdout:\n{}\nstderr:\n{}\nreadiness log:\n{}",
                output.status,
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr),
                ready_log
                    .and_then(|log| fs::read_to_string(log).ok())
                    .unwrap_or_default(),
            );
        }

        let status = Command::new("kill")
            .arg(format!("-{signal_name}"))
            .arg(child.id().to_string())
            .status()
            .unwrap_or_else(|_| panic!("send {signal_name}"));
        assert!(status.success(), "kill -{signal_name} failed with {status}");

        let deadline = Instant::now() + Duration::from_secs(10);
        let exit_status = loop {
            if let Some(status) = child.try_wait().expect("poll child after SIGINT") {
                break Some(status);
            }
            if Instant::now() >= deadline {
                break None;
            }
            thread::sleep(Duration::from_millis(50));
        };

        match exit_status {
            Some(status) if status.success() => return,
            Some(status)
                if ready_log.is_none()
                    && attempt < last_attempt
                    && status.signal() == Some(signal_number) =>
            {
                let _ = child.wait_with_output();
                continue;
            }
            Some(status) => {
                let output = child.wait_with_output().expect("collect child output");
                panic!(
                    "{name} exited unsuccessfully after {signal_name}: {status}\nstdout:\n{}\nstderr:\n{}\nreadiness log:\n{}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr),
                    ready_log
                        .and_then(|log| fs::read_to_string(log).ok())
                        .unwrap_or_default(),
                );
            }
            None => {
                let _ = child.kill();
                let output = child
                    .wait_with_output()
                    .expect("collect killed child output");
                panic!(
                    "{name} did not exit after {signal_name}\nstdout:\n{}\nstderr:\n{}\nreadiness log:\n{}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr),
                    ready_log
                        .and_then(|log| fs::read_to_string(log).ok())
                        .unwrap_or_default(),
                );
            }
        }
    }
    unreachable!("attempt loop either returns or panics");
}

#[cfg(unix)]
#[test]
fn rncp_listener_exits_on_sigint() {
    let tmp = TempDir::new("rncp-sigint");
    write_config(&tmp, false);
    assert_signal_exits(
        || {
            Command::new(env!("CARGO_BIN_EXE_rncp-rs"))
                .arg("--config")
                .arg(tmp.path())
                .arg("-l")
                .arg("-n")
                .arg("-S")
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .expect("spawn rncp-rs listener")
        },
        "rncp-rs",
        "INT",
        2,
        None,
    );
}

#[cfg(unix)]
#[test]
fn rnsh_listener_exits_on_sigint() {
    let tmp = TempDir::new("rnsh-sigint");
    write_config(&tmp, false);
    assert_signal_exits(
        || {
            Command::new(env!("CARGO_BIN_EXE_rnsh-rs"))
                .arg("--config")
                .arg(tmp.path())
                .arg("-l")
                .arg("-n")
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .expect("spawn rnsh-rs listener")
        },
        "rnsh-rs",
        "INT",
        2,
        None,
    );
}

#[cfg(unix)]
#[test]
fn rnsd_flushes_state_and_exits_on_sigterm() {
    let tmp = TempDir::new("rnsd-sigterm");
    write_config(&tmp, true);
    let ready_log = tmp.path().join("logfile");
    assert_signal_exits(
        || {
            Command::new(env!("CARGO_BIN_EXE_rnsd-rs"))
                .arg("--config")
                .arg(tmp.path())
                .arg("--service")
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .expect("spawn rnsd-rs")
        },
        "rnsd-rs",
        "TERM",
        15,
        Some(&ready_log),
    );
    assert!(
        tmp.path().join("storage/packet_hashlist.raw").is_file(),
        "orderly SIGTERM shutdown must flush transport state"
    );
}

#[cfg(unix)]
#[test]
fn daemon_readiness_requires_completed_initialization_and_a_live_child() {
    let tmp = TempDir::new("rnsd-readiness");
    let log = tmp.path().join("logfile");
    let mut child = Command::new("sleep")
        .arg("10")
        .spawn()
        .expect("spawn control");

    assert!(!wait_for_ready_log(&mut child, &log, Duration::ZERO));
    // The starting message is not a promise of completed runtime initialization.
    fs::write(&log, "rnsd-rs 1.3.0 starting\n").expect("write starting log");
    assert!(!wait_for_ready_log(&mut child, &log, Duration::ZERO));
    fs::write(&log, "reticulum started in Standalone mode\n").expect("write ready log");
    assert!(wait_for_ready_log(&mut child, &log, Duration::ZERO));

    child.kill().expect("stop control");
    child.wait().expect("reap control");
    assert!(!wait_for_ready_log(&mut child, &log, Duration::ZERO));
}
