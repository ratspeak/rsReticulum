use std::process::Command;

#[test]
fn installed_tools_report_rsreticulum_package_version() {
    let expected = env!("CARGO_PKG_VERSION");
    let tools = [
        ("rnsd-rs", env!("CARGO_BIN_EXE_rnsd-rs")),
        ("rnstatus-rs", env!("CARGO_BIN_EXE_rnstatus-rs")),
        ("rnpath-rs", env!("CARGO_BIN_EXE_rnpath-rs")),
        ("rnid-rs", env!("CARGO_BIN_EXE_rnid-rs")),
        ("rnprobe-rs", env!("CARGO_BIN_EXE_rnprobe-rs")),
        ("rncp-rs", env!("CARGO_BIN_EXE_rncp-rs")),
        ("rnodeconf-rs", env!("CARGO_BIN_EXE_rnodeconf-rs")),
        ("rnsh-rs", env!("CARGO_BIN_EXE_rnsh-rs")),
    ];

    for (name, program) in tools {
        let output = Command::new(program)
            .arg("--version")
            .output()
            .unwrap_or_else(|err| panic!("failed to run {name} --version: {err}"));
        assert!(
            output.status.success(),
            "{name} --version failed with status {}\n--- stdout ---\n{}\n--- stderr ---\n{}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );

        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            stdout.starts_with(&format!("{name} {expected}")),
            "{name} --version did not report package version {expected:?}\n--- stdout ---\n{stdout}"
        );
    }
}
