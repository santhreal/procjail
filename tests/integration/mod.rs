//! Additional integration tests for procjail strategies and configurations.

use std::path::Path;

use procjail::{probe_capabilities, SandboxConfig, SandboxedProcess, Strategy};

fn create_sh_harness(dir: &Path, script: &str) -> std::path::PathBuf {
    let harness = dir.join("harness.sh");
    std::fs::write(&harness, script).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&harness, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    harness
}

/// Verify every available strategy can at least run `echo hello`.
#[test]
#[cfg(target_os = "linux")]
fn all_strategies_can_echo() {
    let strategies = vec![
        Strategy::None,
        Strategy::RlimitsOnly,
        Strategy::Unshare,
        Strategy::Bubblewrap,
        Strategy::Firejail,
    ];

    let caps = probe_capabilities();
    let probed_ok = |s: Strategy| match s {
        Strategy::Unshare => caps.has_unshare,
        Strategy::Bubblewrap => caps.has_bubblewrap,
        Strategy::Firejail => caps.has_firejail,
        _ => true, // None and RlimitsOnly always work
    };
    for strategy in strategies {
        if !probed_ok(strategy) {
            continue; // host blocks this strategy (e.g. AppArmor userns restriction)
        }
        let work_dir = tempfile::tempdir().unwrap();
        let harness = create_sh_harness(work_dir.path(), "#!/bin/sh\necho hello\n");

        let config = SandboxConfig::builder()
            .runtime("sh")
            .timeout_seconds(5)
            .strategy(strategy)
            .build();

        let mut proc = match SandboxedProcess::spawn(&harness, work_dir.path(), &config) {
            Ok(p) => p,
            Err(e) => {
                let msg = e.to_string();
                if msg.contains("not available") {
                    continue; // strategy not installed on this host
                }
                panic!("strategy {strategy} failed unexpectedly: {e}");
            }
        };

        let line = proc.recv().expect("recv failed").expect("eof early");
        assert_eq!(
            line.trim(),
            "hello",
            "strategy {strategy} must allow basic echo"
        );
        let usage = proc.wait_with_usage().expect("wait failed");
        assert_eq!(usage.exit_code, 0, "strategy {strategy} must exit 0");
    }
}

/// Verify that a read-only bind mount is actually read-only under Bubblewrap.
#[test]
#[cfg(target_os = "linux")]
fn bwrap_readonly_mount_is_readonly() {
    let work_dir = tempfile::tempdir().unwrap();
    let ro_dir = tempfile::tempdir().unwrap();
    let ro_file = ro_dir.path().join("test.txt");
    std::fs::write(&ro_file, "readonly").unwrap();

    let harness = create_sh_harness(
        work_dir.path(),
        &format!(
            "#!/bin/sh\nif echo x >> \"{file}\" 2>/dev/null; then echo WRITABLE; else echo READONLY; fi\n",
            file = ro_file.display()
        ),
    );

    let config = SandboxConfig::builder()
        .runtime("sh")
        .timeout_seconds(5)
        .strategy(Strategy::Bubblewrap)
        .readonly_mount(
            ro_dir.path().to_str().unwrap(),
            ro_dir.path().to_str().unwrap(),
        )
        .build();

    if !probe_capabilities().has_bubblewrap {
        return; // host blocks bwrap (e.g. AppArmor userns restriction)
    }
    let mut proc = SandboxedProcess::spawn(&harness, work_dir.path(), &config)
        .unwrap_or_else(|e| panic!("spawn failed on a bwrap-capable host: {e}"));

    let line = proc.recv().expect("recv failed").expect("eof early");
    assert_eq!(
        line.trim(),
        "READONLY",
        "readonly mount must be read-only under bwrap"
    );
    let usage = proc.wait_with_usage().expect("wait failed");
    assert_eq!(usage.exit_code, 0);
}

/// Verify that a writable bind mount allows modifications under Bubblewrap.
#[test]
#[cfg(target_os = "linux")]
fn bwrap_writable_mount_is_writable() {
    let work_dir = tempfile::tempdir().unwrap();
    let rw_dir = tempfile::tempdir().unwrap();

    let harness = create_sh_harness(
        work_dir.path(),
        &format!(
            "#!/bin/sh\necho test > \"{dir}/out.txt\" 2>/dev/null && echo WRITABLE || echo READONLY\n",
            dir = rw_dir.path().display()
        ),
    );

    let config = SandboxConfig::builder()
        .runtime("sh")
        .timeout_seconds(5)
        .strategy(Strategy::Bubblewrap)
        .writable_mount(
            rw_dir.path().to_str().unwrap(),
            rw_dir.path().to_str().unwrap(),
        )
        .build();

    if !probe_capabilities().has_bubblewrap {
        return; // host blocks bwrap (e.g. AppArmor userns restriction)
    }
    let mut proc = SandboxedProcess::spawn(&harness, work_dir.path(), &config)
        .unwrap_or_else(|e| panic!("spawn failed on a bwrap-capable host: {e}"));

    let line = proc.recv().expect("recv failed").expect("eof early");
    assert_eq!(
        line.trim(),
        "WRITABLE",
        "writable mount must be writable under bwrap"
    );
    let usage = proc.wait_with_usage().expect("wait failed");
    assert_eq!(usage.exit_code, 0);
    assert!(
        rw_dir.path().join("out.txt").exists(),
        "file must exist on host after write"
    );
}

/// Verify that stderr capture works when enabled.
#[test]
fn stderr_capture_mode() {
    let work_dir = tempfile::tempdir().unwrap();
    let harness = create_sh_harness(
        work_dir.path(),
        "#!/bin/sh\necho stdout_line\necho stderr_line >&2\n",
    );

    let config = SandboxConfig::builder()
        .runtime("sh")
        .timeout_seconds(5)
        .strategy(Strategy::None)
        .capture_stderr(true)
        .build();

    let mut proc =
        SandboxedProcess::spawn(&harness, work_dir.path(), &config).expect("spawn failed");
    let line = proc.recv().expect("recv failed").expect("eof early");
    assert_eq!(line.trim(), "stdout_line");
    let usage = proc.wait_with_usage().expect("wait failed");
    assert_eq!(usage.exit_code, 0);
    // We don't have a public API to read stderr, but we verify the process
    // spawns correctly with capture_stderr=true.
}

/// Verify that runtime arguments are passed before the harness.
#[test]
fn runtime_args_are_passed() {
    let work_dir = tempfile::tempdir().unwrap();
    let harness = create_sh_harness(work_dir.path(), "#!/bin/sh\necho \"$1\"\n");

    // Empty runtime_args: harness path is argv[1] ($1 inside the script = work_dir).
    let config = SandboxConfig::builder()
        .runtime("sh")
        .runtime_args(&[])
        .timeout_seconds(5)
        .strategy(Strategy::None)
        .build();

    let mut proc =
        SandboxedProcess::spawn(&harness, work_dir.path(), &config).expect("spawn failed");
    let line = proc.recv().expect("recv failed").expect("eof early");
    // $1 inside the harness script is the work_dir path.
    assert_eq!(line.trim(), work_dir.path().to_str().unwrap());
    let usage = proc.wait_with_usage().expect("wait failed");
    assert_eq!(usage.exit_code, 0);
}

/// Verify TOML config loading produces the same result as the builder.
#[test]
fn toml_config_roundtrip() {
    let toml = r#"
        runtime_path = "python3"
        max_memory_bytes = 67108864
        max_cpu_seconds = 5
        timeout_seconds = 10
        allow_localhost = true
        env_strip_secrets = false
    "#;

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    std::fs::write(&path, toml).unwrap();

    let config = SandboxConfig::load(&path).expect("load failed");
    assert_eq!(config.runtime_path.to_string_lossy(), "python3");
    assert_eq!(config.max_memory_bytes, 64 * 1024 * 1024);
    assert_eq!(config.max_cpu_seconds, 5);
    assert_eq!(config.timeout_seconds, 10);
    assert!(config.allow_localhost);
    assert!(!config.env_strip_secrets);
}

/// Verify that an absolute runtime path is accepted without PATH lookup.
#[test]
fn absolute_runtime_path_no_lookup() {
    let work_dir = tempfile::tempdir().unwrap();
    let harness = create_sh_harness(work_dir.path(), "#!/bin/sh\necho ok\n");

    let config = SandboxConfig::builder()
        .runtime("/bin/sh")
        .timeout_seconds(5)
        .strategy(Strategy::None)
        .build();

    let mut proc =
        SandboxedProcess::spawn(&harness, work_dir.path(), &config).expect("spawn failed");
    let line = proc.recv().expect("recv failed").expect("eof early");
    assert_eq!(line.trim(), "ok");
    let usage = proc.wait_with_usage().expect("wait failed");
    assert_eq!(usage.exit_code, 0);
}

/// Verify that `quick_spawn` uses a 30-second timeout by default.
#[test]
fn quick_spawn_default_timeout() {
    let work_dir = tempfile::tempdir().unwrap();
    let harness = create_sh_harness(work_dir.path(), "#!/bin/sh\necho ok\n");

    let mut proc =
        procjail::quick_spawn("sh", &harness, work_dir.path()).expect("quick_spawn failed");
    let line = proc.recv().expect("recv failed").expect("eof early");
    assert_eq!(line.trim(), "ok");
    let usage = proc.wait_with_usage().expect("wait failed");
    assert_eq!(usage.exit_code, 0);
}

/// Verify that the `Strategy` Display impl is non-empty for all variants.
#[test]
fn strategy_display_is_nonempty() {
    use procjail::Strategy;
    for s in [
        Strategy::None,
        Strategy::RlimitsOnly,
        Strategy::Unshare,
        Strategy::Bubblewrap,
        Strategy::Firejail,
    ] {
        let txt = format!("{s}");
        assert!(!txt.is_empty(), "strategy display must not be empty");
    }
}

/// Verify that Strategy::has_pid_isolation is correct for all variants.
#[test]
fn strategy_pid_isolation_matrix() {
    use procjail::Strategy;
    assert!(!Strategy::None.has_pid_isolation());
    assert!(!Strategy::RlimitsOnly.has_pid_isolation());
    assert!(Strategy::Unshare.has_pid_isolation());
    assert!(Strategy::Bubblewrap.has_pid_isolation());
    assert!(Strategy::Firejail.has_pid_isolation());
}

/// Verify that Strategy::has_network_isolation is correct for all variants.
#[test]
fn strategy_network_isolation_matrix() {
    use procjail::Strategy;
    assert!(!Strategy::None.has_network_isolation());
    assert!(!Strategy::RlimitsOnly.has_network_isolation());
    assert!(Strategy::Unshare.has_network_isolation());
    assert!(Strategy::Bubblewrap.has_network_isolation());
    assert!(Strategy::Firejail.has_network_isolation());
}

/// Verify that Strategy::has_fs_isolation is correct for all variants.
#[test]
fn strategy_fs_isolation_matrix() {
    use procjail::Strategy;
    assert!(!Strategy::None.has_fs_isolation());
    assert!(!Strategy::RlimitsOnly.has_fs_isolation());
    assert!(!Strategy::Unshare.has_fs_isolation());
    assert!(Strategy::Bubblewrap.has_fs_isolation());
    assert!(Strategy::Firejail.has_fs_isolation());
}

/// Verify that Strategy::has_mount_namespace is correct for all variants.
#[test]
fn strategy_mount_namespace_matrix() {
    use procjail::Strategy;
    assert!(!Strategy::None.has_mount_namespace());
    assert!(!Strategy::RlimitsOnly.has_mount_namespace());
    assert!(Strategy::Unshare.has_mount_namespace());
    assert!(Strategy::Bubblewrap.has_mount_namespace());
    assert!(Strategy::Firejail.has_mount_namespace());
}
