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
fn write_config(tmp: &TempDir) {
    fs::write(
        tmp.path().join("config"),
        "[reticulum]\nshare_instance = No\nenable_transport = No\n\n[interfaces]\n",
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

/// Sends SIGINT after a settle period and asserts a clean exit. Retries once
/// with a longer settle if the child died from the raw signal (exit by signal
/// 2): under full-workspace load the child can still be booting when the
/// first SIGINT lands, before its handler is registered. A real handler
/// regression fails both attempts.
#[cfg(unix)]
fn assert_sigint_exits(spawn: impl Fn() -> Child, name: &str) {
    use std::os::unix::process::ExitStatusExt;

    let settles = [Duration::from_secs(3), Duration::from_secs(8)];
    let last_attempt = settles.len() - 1;
    for (attempt, settle) in settles.into_iter().enumerate() {
        let mut child = spawn();
        if !wait_until_running(&mut child, settle) {
            let output = child.wait_with_output().expect("collect child output");
            panic!(
                "{name} exited before SIGINT\nstatus: {}\nstdout:\n{}\nstderr:\n{}",
                output.status,
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }

        let status = Command::new("kill")
            .arg("-INT")
            .arg(child.id().to_string())
            .status()
            .expect("send SIGINT");
        assert!(status.success(), "kill -INT failed with {status}");

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
            Some(status) if attempt < last_attempt && status.signal() == Some(2) => {
                let _ = child.wait_with_output();
                continue;
            }
            Some(status) => {
                let output = child.wait_with_output().expect("collect child output");
                panic!(
                    "{name} exited unsuccessfully after SIGINT: {status}\nstdout:\n{}\nstderr:\n{}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                );
            }
            None => {
                let _ = child.kill();
                let output = child
                    .wait_with_output()
                    .expect("collect killed child output");
                panic!(
                    "{name} did not exit after SIGINT\nstdout:\n{}\nstderr:\n{}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
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
    write_config(&tmp);
    assert_sigint_exits(
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
    );
}

#[cfg(unix)]
#[test]
fn rnsh_listener_exits_on_sigint() {
    let tmp = TempDir::new("rnsh-sigint");
    write_config(&tmp);
    assert_sigint_exits(
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
    );
}
