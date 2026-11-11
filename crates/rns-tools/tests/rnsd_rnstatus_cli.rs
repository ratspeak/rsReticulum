use std::ffi::OsStr;
use std::fs;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

struct TempDir {
    path: PathBuf,
}

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

    fn join(&self, path: impl AsRef<Path>) -> PathBuf {
        self.path.join(path)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

struct ChildGuard {
    child: Option<Child>,
}

impl ChildGuard {
    fn spawn<I, S>(program: &str, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        let child = Command::new(program)
            .args(args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn child process");
        Self { child: Some(child) }
    }

    fn try_wait(&mut self) -> Option<std::process::ExitStatus> {
        self.child
            .as_mut()
            .and_then(|child| child.try_wait().expect("poll child status"))
    }

    fn terminate_and_output(mut self) -> Output {
        let mut child = self.child.take().expect("child already taken");
        let _ = child.kill();
        child.wait_with_output().expect("collect child output")
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn free_tcp_port_pair() -> (u16, u16) {
    let first = TcpListener::bind("127.0.0.1:0").expect("bind first free tcp port");
    let second = TcpListener::bind("127.0.0.1:0").expect("bind second free tcp port");
    let first_port = first.local_addr().expect("first local addr").port();
    let second_port = second.local_addr().expect("second local addr").port();
    (first_port, second_port)
}

fn write_stale_python_destination_table(storage_dir: &Path, entries: usize) {
    fs::create_dir_all(storage_dir).expect("create storage dir");

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before unix epoch")
        .as_secs_f64();
    let mut table = rns_transport::path_table::PathTable::new();
    for i in 0..entries {
        let mut dest = [0u8; 16];
        dest[..8].copy_from_slice(&(i as u64).to_be_bytes());
        dest[8..].copy_from_slice(&(!i as u64).to_be_bytes());

        let mut packet_hash = [0u8; 32];
        packet_hash[..8].copy_from_slice(&(i as u64).to_be_bytes());
        packet_hash[8..16].copy_from_slice(&(entries as u64).to_be_bytes());
        packet_hash[16..24].copy_from_slice(&(0xA5A5_A5A5_A5A5_A5A5u64).to_be_bytes());
        packet_hash[24..].copy_from_slice(&(!i as u64).to_be_bytes());

        let mut entry = rns_transport::path_table::PathEntry::new(
            None,
            1,
            7,
            rns_transport::constants::InterfaceMode::Gateway,
        );
        entry.timestamp = now;
        entry.expires = now + 3600.0;
        entry.packet_hash = Some(packet_hash);
        table.insert(dest, entry);
    }

    let mut names = std::collections::HashMap::new();
    names.insert(7u64, "Border_TCP".to_string());
    rns_transport::persistence::save_python_destination_table(
        &table,
        &names,
        &storage_dir.join("destination_table"),
    )
    .expect("write Python destination_table");
}

fn output_text(output: &Output) -> (String, String) {
    (
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

fn rnstatus_json(tmp: &TempDir) -> Output {
    Command::new(env!("CARGO_BIN_EXE_rnstatus-rs"))
        .arg("--config")
        .arg(tmp.path())
        .arg("--json")
        .arg("--all")
        .output()
        .expect("run rnstatus-rs")
}

fn poll_rnstatus_until<F>(
    daemon: &mut ChildGuard,
    tmp: &TempDir,
    deadline_after: Duration,
    predicate: F,
) -> Result<(), String>
where
    F: Fn(&[serde_json::Value]) -> bool,
{
    let deadline = Instant::now() + deadline_after;
    let mut last_status = None;
    let mut last_stdout = String::new();
    let mut last_stderr = String::new();
    while Instant::now() < deadline {
        if let Some(status) = daemon.try_wait() {
            return Err(format!(
                "rnsd-rs exited before rnstatus-rs succeeded: {status}"
            ));
        }

        let output = rnstatus_json(tmp);
        last_status = output.status.code();
        (last_stdout, last_stderr) = output_text(&output);

        if output.status.success() {
            let value: serde_json::Value =
                serde_json::from_slice(&output.stdout).expect("rnstatus-rs JSON output");
            let interfaces = value
                .get("interfaces")
                .and_then(|v| v.as_array())
                .expect("interfaces array");
            if predicate(interfaces) {
                return Ok(());
            }
        }

        thread::sleep(Duration::from_millis(100));
    }

    Err(format!(
        "rnstatus-rs did not report the expected interface before the deadline\n\
         last rnstatus status: {last_status:?}\n\
         --- last rnstatus stdout ---\n{last_stdout}\n\
         --- last rnstatus stderr ---\n{last_stderr}"
    ))
}

fn panic_with_daemon_output(message: String, daemon: ChildGuard) -> ! {
    let daemon_output = daemon.terminate_and_output();
    let (daemon_stdout, daemon_stderr) = output_text(&daemon_output);
    panic!(
        "{message}\n\
         --- daemon stdout ---\n{daemon_stdout}\n\
         --- daemon stderr ---\n{daemon_stderr}"
    );
}

#[test]
fn rnsd_rnstatus_cli_survives_stale_python_destination_table() {
    let tmp = TempDir::new("rnsd-rnstatus-stale-python-table");
    let (shared_port, control_port) = free_tcp_port_pair();
    let rpc_key_hex = "5353535353535353535353535353535353535353535353535353535353535353";
    let config = format!(
        "[reticulum]\n\
         share_instance = Yes\n\
         shared_instance_type = tcp\n\
         shared_instance_port = {shared_port}\n\
         instance_control_port = {control_port}\n\
         rpc_key = {rpc_key_hex}\n\
         enable_transport = Yes\n\
         \n\
         [logging]\n\
         loglevel = 1\n\
         \n\
         [interfaces]\n"
    );
    fs::write(tmp.join("config"), config).expect("write config");
    write_stale_python_destination_table(&tmp.join("storage"), 512);

    let mut daemon = ChildGuard::spawn(
        env!("CARGO_BIN_EXE_rnsd-rs"),
        ["--config".as_ref(), tmp.path().as_os_str()],
    );

    if let Err(message) =
        poll_rnstatus_until(&mut daemon, &tmp, Duration::from_secs(5), |interfaces| {
            interfaces.iter().any(|entry| {
                entry.get("type").and_then(|v| v.as_str()) == Some("LocalServerInterface")
            })
        })
    {
        panic_with_daemon_output(message, daemon);
    }
}

#[test]
#[ignore = "requires network access to a public Reticulum TCP peer"]
fn rnsd_rnstatus_cli_public_tcp_testnet_smoke() {
    let tmp = TempDir::new("rnsd-rnstatus-public-tcp-testnet");
    let (shared_port, control_port) = free_tcp_port_pair();
    let host = std::env::var("RSRETICULUM_LIVE_TCP_HOST")
        .unwrap_or_else(|_| "rns.ratspeak.org".to_string());
    let port = std::env::var("RSRETICULUM_LIVE_TCP_PORT")
        .ok()
        .and_then(|value| value.parse::<u16>().ok())
        .unwrap_or(4242);
    let rpc_key_hex = "5353535353535353535353535353535353535353535353535353535353535353";
    let config = format!(
        "[reticulum]\n\
         share_instance = Yes\n\
         shared_instance_type = tcp\n\
         shared_instance_port = {shared_port}\n\
         instance_control_port = {control_port}\n\
         rpc_key = {rpc_key_hex}\n\
         enable_transport = No\n\
         \n\
         [logging]\n\
         loglevel = 1\n\
         \n\
         [interfaces]\n\
         \n\
         [[Public TCP]]\n\
         type = TCPClientInterface\n\
         enabled = Yes\n\
         target_host = {host}\n\
         target_port = {port}\n"
    );
    fs::write(tmp.join("config"), config).expect("write config");

    let mut daemon = ChildGuard::spawn(
        env!("CARGO_BIN_EXE_rnsd-rs"),
        ["--config".as_ref(), tmp.path().as_os_str()],
    );

    if let Err(message) =
        poll_rnstatus_until(&mut daemon, &tmp, Duration::from_secs(10), |interfaces| {
            interfaces.iter().any(|entry| {
                entry.get("name").and_then(|v| v.as_str()) == Some("Public TCP")
                    && entry.get("status").and_then(|v| v.as_bool()) == Some(true)
            })
        })
    {
        panic_with_daemon_output(
            format!("{message}\nexpected Public TCP to come online for {host}:{port}"),
            daemon,
        );
    }
}
