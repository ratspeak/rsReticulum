use std::ffi::OsStr;
use std::fs;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use rns_identity::destination::Destination;
use rns_identity::identity::Identity;

const PROBE_APP: &str = "rnstransport.probe";
const COMMAND_TIMEOUT_SECS: &str = "4";

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
    label: &'static str,
    child: Option<Child>,
}

impl ChildGuard {
    fn spawn<I, S>(label: &'static str, program: &str, args: I) -> Self
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
        Self {
            label,
            child: Some(child),
        }
    }

    fn try_wait(&mut self) -> Option<std::process::ExitStatus> {
        self.child
            .as_mut()
            .and_then(|child| child.try_wait().expect("poll child status"))
    }

    fn terminate_and_output_text(&mut self) -> (String, String) {
        let Some(mut child) = self.child.take() else {
            return ("<not started>\n".to_string(), String::new());
        };
        let _ = child.kill();
        let output = child.wait_with_output().expect("collect child output");
        output_text(&output)
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

fn free_tcp_ports(count: usize) -> Vec<u16> {
    let listeners: Vec<TcpListener> = (0..count)
        .map(|_| TcpListener::bind("127.0.0.1:0").expect("bind free tcp port"))
        .collect();
    listeners
        .iter()
        .map(|listener| listener.local_addr().expect("local addr").port())
        .collect()
}

fn write_responder_config(tmp: &TempDir, shared_port: u16, control_port: u16, link_port: u16) {
    let config = format!(
        "[reticulum]\n\
         share_instance = Yes\n\
         shared_instance_type = tcp\n\
         shared_instance_port = {shared_port}\n\
         instance_control_port = {control_port}\n\
         rpc_key = 5151515151515151515151515151515151515151515151515151515151515151\n\
         enable_transport = Yes\n\
         respond_to_probes = Yes\n\
         \n\
         [logging]\n\
         loglevel = 1\n\
         \n\
         [interfaces]\n\
         \n\
         [[Matrix TCP Server]]\n\
         type = TCPServerInterface\n\
         enabled = Yes\n\
         listen_ip = 127.0.0.1\n\
         listen_port = {link_port}\n"
    );
    fs::write(tmp.join("config"), config).expect("write responder config");
}

fn write_origin_config(tmp: &TempDir, shared_port: u16, control_port: u16, link_port: u16) {
    let config = format!(
        "[reticulum]\n\
         share_instance = Yes\n\
         shared_instance_type = tcp\n\
         shared_instance_port = {shared_port}\n\
         instance_control_port = {control_port}\n\
         rpc_key = 5252525252525252525252525252525252525252525252525252525252525252\n\
         enable_transport = No\n\
         \n\
         [logging]\n\
         loglevel = 1\n\
         \n\
         [interfaces]\n\
         \n\
         [[Matrix TCP Client]]\n\
         type = TCPClientInterface\n\
         enabled = Yes\n\
         target_host = 127.0.0.1\n\
         target_port = {link_port}\n"
    );
    fs::write(tmp.join("config"), config).expect("write origin config");
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

fn poll_shared_server(
    daemon: &mut ChildGuard,
    tmp: &TempDir,
    deadline_after: Duration,
) -> Result<(), String> {
    let deadline = Instant::now() + deadline_after;
    let mut last_status = None;
    let mut last_stdout = String::new();
    let mut last_stderr = String::new();
    while Instant::now() < deadline {
        if let Some(status) = daemon.try_wait() {
            return Err(format!(
                "{} exited before shared server was ready: {status}",
                daemon.label
            ));
        }

        let output = rnstatus_json(tmp);
        last_status = output.status.code();
        (last_stdout, last_stderr) = output_text(&output);
        if output.status.success() {
            let value: serde_json::Value =
                serde_json::from_slice(&output.stdout).expect("rnstatus-rs JSON output");
            let ready = value
                .get("interfaces")
                .and_then(|v| v.as_array())
                .is_some_and(|interfaces| {
                    interfaces.iter().any(|entry| {
                        entry.get("type").and_then(|v| v.as_str()) == Some("LocalServerInterface")
                    })
                });
            if ready {
                return Ok(());
            }
        }

        thread::sleep(Duration::from_millis(100));
    }

    Err(format!(
        "rnstatus-rs did not report {} shared server before the deadline\n\
         last rnstatus status: {last_status:?}\n\
         --- last rnstatus stdout ---\n{last_stdout}\n\
         --- last rnstatus stderr ---\n{last_stderr}",
        daemon.label
    ))
}

fn read_probe_hash(responder: &mut ChildGuard, tmp: &TempDir) -> Result<[u8; 16], String> {
    // The probe destination is derived from the transport identity, as in Python.
    let path = tmp.join("storage").join("transport_identity");
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut last_error = String::new();
    while Instant::now() < deadline {
        if let Some(status) = responder.try_wait() {
            return Err(format!(
                "{} exited before transport identity was ready: {status}",
                responder.label
            ));
        }

        match Identity::from_file(&path) {
            Ok(identity) => {
                return Ok(Destination::hash_from_name_and_identity(
                    PROBE_APP,
                    Some(&identity.hash),
                ));
            }
            Err(e) => last_error = e.to_string(),
        }
        thread::sleep(Duration::from_millis(100));
    }
    Err(format!(
        "transport identity was not readable at {}\nlast error: {last_error}",
        path.display()
    ))
}

fn run_rnpath(origin: &TempDir, probe_hash_hex: &str) -> Output {
    Command::new(env!("CARGO_BIN_EXE_rnpath-rs"))
        .arg("--config")
        .arg(origin.path())
        .arg("-w")
        .arg(COMMAND_TIMEOUT_SECS)
        .arg(probe_hash_hex)
        .output()
        .expect("run rnpath-rs")
}

fn run_rnprobe(origin: &TempDir, probe_hash_hex: &str) -> Output {
    Command::new(env!("CARGO_BIN_EXE_rnprobe-rs"))
        .arg("--config")
        .arg(origin.path())
        .arg("--json")
        .arg("-t")
        .arg(COMMAND_TIMEOUT_SECS)
        .arg(PROBE_APP)
        .arg(probe_hash_hex)
        .output()
        .expect("run rnprobe-rs")
}

fn poll_command_success<F>(
    label: &str,
    deadline_after: Duration,
    mut run: F,
) -> Result<Output, String>
where
    F: FnMut() -> Output,
{
    let deadline = Instant::now() + deadline_after;
    let mut last_output = None;
    while Instant::now() < deadline {
        let output = run();
        if output.status.success() {
            return Ok(output);
        }
        last_output = Some(output);
        thread::sleep(Duration::from_millis(200));
    }

    let Some(output) = last_output else {
        return Err(format!("{label} was not run"));
    };
    let (stdout, stderr) = output_text(&output);
    Err(format!(
        "{label} did not succeed before the deadline\n\
         last status: {}\n\
         --- last stdout ---\n{stdout}\n\
         --- last stderr ---\n{stderr}",
        output.status
    ))
}

fn panic_with_daemon_outputs(
    message: String,
    responder: &mut ChildGuard,
    path_origin: &mut ChildGuard,
    cold_origin: &mut ChildGuard,
) -> ! {
    let (responder_stdout, responder_stderr) = responder.terminate_and_output_text();
    let (path_stdout, path_stderr) = path_origin.terminate_and_output_text();
    let (cold_stdout, cold_stderr) = cold_origin.terminate_and_output_text();
    panic!(
        "{message}\n\
         --- responder stdout ---\n{responder_stdout}\n\
         --- responder stderr ---\n{responder_stderr}\n\
         --- path origin stdout ---\n{path_stdout}\n\
         --- path origin stderr ---\n{path_stderr}\n\
         --- cold origin stdout ---\n{cold_stdout}\n\
         --- cold origin stderr ---\n{cold_stderr}"
    );
}

#[test]
fn rust_probe_destination_supports_active_path_and_probe_matrix() {
    let responder_tmp = TempDir::new("rnprobe-rnpath-responder");
    let path_origin_tmp = TempDir::new("rnprobe-rnpath-path-origin");
    let cold_origin_tmp = TempDir::new("rnprobe-rnpath-cold-origin");
    let ports = free_tcp_ports(7);
    let link_port = ports[0];

    write_responder_config(&responder_tmp, ports[1], ports[2], link_port);
    write_origin_config(&path_origin_tmp, ports[3], ports[4], link_port);
    write_origin_config(&cold_origin_tmp, ports[5], ports[6], link_port);

    let mut responder = ChildGuard::spawn(
        "responder rnsd-rs",
        env!("CARGO_BIN_EXE_rnsd-rs"),
        ["--config".as_ref(), responder_tmp.path().as_os_str()],
    );
    if let Err(message) = poll_shared_server(&mut responder, &responder_tmp, Duration::from_secs(5))
    {
        let mut placeholder = ChildGuard {
            label: "path origin rnsd-rs",
            child: None,
        };
        let mut cold_placeholder = ChildGuard {
            label: "cold origin rnsd-rs",
            child: None,
        };
        panic_with_daemon_outputs(
            message,
            &mut responder,
            &mut placeholder,
            &mut cold_placeholder,
        );
    }

    let probe_hash = match read_probe_hash(&mut responder, &responder_tmp) {
        Ok(hash) => hash,
        Err(message) => {
            let mut placeholder = ChildGuard {
                label: "path origin rnsd-rs",
                child: None,
            };
            let mut cold_placeholder = ChildGuard {
                label: "cold origin rnsd-rs",
                child: None,
            };
            panic_with_daemon_outputs(
                message,
                &mut responder,
                &mut placeholder,
                &mut cold_placeholder,
            );
        }
    };
    let probe_hash_hex = hex::encode(probe_hash);

    let mut path_origin = ChildGuard::spawn(
        "path origin rnsd-rs",
        env!("CARGO_BIN_EXE_rnsd-rs"),
        ["--config".as_ref(), path_origin_tmp.path().as_os_str()],
    );
    if let Err(message) =
        poll_shared_server(&mut path_origin, &path_origin_tmp, Duration::from_secs(5))
    {
        let mut cold_placeholder = ChildGuard {
            label: "cold origin rnsd-rs",
            child: None,
        };
        panic_with_daemon_outputs(
            message,
            &mut responder,
            &mut path_origin,
            &mut cold_placeholder,
        );
    }

    let mut cold_origin = ChildGuard::spawn(
        "cold origin rnsd-rs",
        env!("CARGO_BIN_EXE_rnsd-rs"),
        ["--config".as_ref(), cold_origin_tmp.path().as_os_str()],
    );
    if let Err(message) =
        poll_shared_server(&mut cold_origin, &cold_origin_tmp, Duration::from_secs(5))
    {
        panic_with_daemon_outputs(message, &mut responder, &mut path_origin, &mut cold_origin);
    }

    let rnpath = poll_command_success(
        "rnpath-rs active path request",
        Duration::from_secs(16),
        || run_rnpath(&path_origin_tmp, &probe_hash_hex),
    );
    let rnpath = match rnpath {
        Ok(output) => output,
        Err(message) => {
            panic_with_daemon_outputs(message, &mut responder, &mut path_origin, &mut cold_origin)
        }
    };
    let (rnpath_stdout, _rnpath_stderr) = output_text(&rnpath);
    assert!(
        rnpath_stdout.contains(&format!("Path found, destination <{probe_hash_hex}>")),
        "rnpath-rs did not report the requested path\n{rnpath_stdout}"
    );

    let known_path_probe = poll_command_success(
        "rnprobe-rs with rnpath-populated path",
        Duration::from_secs(16),
        || run_rnprobe(&path_origin_tmp, &probe_hash_hex),
    );
    let known_path_probe = match known_path_probe {
        Ok(output) => output,
        Err(message) => {
            panic_with_daemon_outputs(message, &mut responder, &mut path_origin, &mut cold_origin)
        }
    };
    assert_probe_json_ok(&known_path_probe, &probe_hash_hex);

    let cold_probe = poll_command_success(
        "rnprobe-rs cold active-path probe",
        Duration::from_secs(16),
        || run_rnprobe(&cold_origin_tmp, &probe_hash_hex),
    );
    let cold_probe = match cold_probe {
        Ok(output) => output,
        Err(message) => {
            panic_with_daemon_outputs(message, &mut responder, &mut path_origin, &mut cold_origin)
        }
    };
    assert_probe_json_ok(&cold_probe, &probe_hash_hex);
}

fn assert_probe_json_ok(output: &Output, expected_hash: &str) {
    let (stdout, stderr) = output_text(output);
    let value: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("rnprobe-rs JSON output");
    assert_eq!(
        value.get("status").and_then(|v| v.as_str()),
        Some("ok"),
        "rnprobe-rs did not report ok\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert_eq!(
        value.get("destination").and_then(|v| v.as_str()),
        Some(expected_hash),
        "rnprobe-rs returned the wrong destination\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        value.get("rtt_ms").and_then(|v| v.as_f64()).is_some(),
        "rnprobe-rs JSON did not include an RTT\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
}
