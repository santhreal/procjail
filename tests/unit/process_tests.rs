use procjail::{ResourceUsage, SandboxConfig, SandboxedProcess, Strategy};

#[test]
fn resource_usage_fields() {
    let usage = ResourceUsage {
        peak_memory_bytes: Some(1024),
        cpu_time_secs: Some(0.5),
        wall_time_secs: 1.0,
        exit_code: 0,
    };
    assert_eq!(usage.peak_memory_bytes, Some(1024));
    assert_eq!(usage.exit_code, 0);
}

#[test]
fn strategy_fs_isolation_honest() {
    assert!(!Strategy::Unshare.has_fs_isolation());
    assert!(Strategy::Bubblewrap.has_fs_isolation());
    assert!(Strategy::Firejail.has_fs_isolation());
    assert!(Strategy::Unshare.has_mount_namespace());
}

#[test]
fn drop_does_not_kill_already_exited_process() {
    let config = SandboxConfig::builder()
        .runtime("/bin/echo")
        .strategy(Strategy::None)
        .build();

    let harness = tempfile::NamedTempFile::new().unwrap();
    let work = tempfile::tempdir().unwrap();
    let mut proc = SandboxedProcess::spawn(harness.path(), work.path(), &config).unwrap();
    let wait_res = proc.wait().unwrap();
    drop(proc);
    assert_eq!(wait_res, 0);
}
