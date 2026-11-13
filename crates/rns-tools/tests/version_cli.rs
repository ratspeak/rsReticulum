use std::process::Command;

/// Every tool names itself and its package version, then what it follows.
#[test]
fn installed_tools_report_rsreticulum_package_version() {
    let expected = env!("CARGO_PKG_VERSION");
    let reticulum = rns_tools::RETICULUM_COMPAT_VERSION;
    let tools = [
        ("rnsd-rs", env!("CARGO_BIN_EXE_rnsd-rs"), ""),
        ("rnstatus-rs", env!("CARGO_BIN_EXE_rnstatus-rs"), ""),
        ("rnpath-rs", env!("CARGO_BIN_EXE_rnpath-rs"), ""),
        ("rnid-rs", env!("CARGO_BIN_EXE_rnid-rs"), ""),
        ("rnprobe-rs", env!("CARGO_BIN_EXE_rnprobe-rs"), ""),
        ("rncp-rs", env!("CARGO_BIN_EXE_rncp-rs"), ""),
        ("rnir-rs", env!("CARGO_BIN_EXE_rnir-rs"), ""),
        ("rnpkg-rs", env!("CARGO_BIN_EXE_rnpkg-rs"), ""),
        ("rnx-rs", env!("CARGO_BIN_EXE_rnx-rs"), ""),
        (
            "rnodeconf-rs",
            env!("CARGO_BIN_EXE_rnodeconf-rs"),
            "rnodeconf 2.5.0, ",
        ),
        ("rnsh-rs", env!("CARGO_BIN_EXE_rnsh-rs"), "protocol 0.3.0, "),
    ];

    for (name, program, also) in tools {
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

        assert_eq!(
            String::from_utf8_lossy(&output.stdout),
            format!("{name} {expected} ({also}Reticulum {reticulum})\n")
        );
    }
}

#[test]
fn the_version_line_lists_what_a_tool_follows_before_reticulum() {
    let reticulum = rns_tools::RETICULUM_COMPAT_VERSION;
    assert_eq!(
        rns_tools::version_line("lxmd-rs", "1.4.0", &[("LXMF", "1.3.0")]),
        format!("lxmd-rs 1.4.0 (LXMF 1.3.0, Reticulum {reticulum})")
    );
}
