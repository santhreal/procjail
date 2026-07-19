use procjail::{SandboxConfig, SandboxedProcess, Strategy};
use std::path::Path;

#[test]
fn test_spawn_null_bytes_in_env() {
    let config = SandboxConfig::builder()
        .runtime("sh")
        .env_set("EVIL\0VAR", "value")
        .strategy(Strategy::None)
        .build();

    let harness = tempfile::NamedTempFile::new().unwrap();
    let work = tempfile::tempdir().unwrap();

    let res = SandboxedProcess::spawn(harness.path(), work.path(), &config);
    assert!(res.is_err());
    let err = res.unwrap_err().to_string();
    assert!(err.contains("environment variable name contains invalid characters"));
}

#[test]
fn test_spawn_huge_env_value() {
    let huge_value = "A".repeat(1024 * 64); // 64KB, max is 32KB
    let config = SandboxConfig::builder()
        .runtime("sh")
        .env_set("HUGE_VAR", &huge_value)
        .strategy(Strategy::None)
        .build();

    let harness = tempfile::NamedTempFile::new().unwrap();
    let work = tempfile::tempdir().unwrap();

    let res = SandboxedProcess::spawn(harness.path(), work.path(), &config);
    assert!(res.is_err());
    let err = res.unwrap_err().to_string();
    assert!(err.contains("exceeds"));
}

#[test]
fn test_spawn_empty_harness_path() {
    let config = SandboxConfig::builder()
        .runtime("sh")
        .strategy(Strategy::None)
        .build();

    let work = tempfile::tempdir().unwrap();
    let harness = Path::new("");

    let res = SandboxedProcess::spawn(harness, work.path(), &config);
    assert!(res.is_err());
}

#[test]
fn test_spawn_non_absolute_work_dir() {
    let config = SandboxConfig::builder()
        .runtime("sh")
        .strategy(Strategy::None)
        .build();

    let harness = tempfile::NamedTempFile::new().unwrap();
    let work = Path::new("relative/path/dir");

    let res = SandboxedProcess::spawn(harness.path(), work, &config);
    assert!(res.is_err());
}

#[test]
fn test_unicode_env_vars() {
    let config = SandboxConfig::builder()
        .runtime("sh")
        .env_set("🔥", "❄️")
        .strategy(Strategy::None)
        .build();

    let dir = tempfile::tempdir().unwrap();
    let harness = dir.path().join("harness.sh");
    std::fs::write(&harness, "#!/bin/sh\nexit 0\n").unwrap();
    
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&harness, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    let work = tempfile::tempdir().unwrap();
    let mut proc = SandboxedProcess::spawn(&harness, work.path(), &config).unwrap();
    let usage = proc.wait_with_usage().unwrap();
    assert_eq!(usage.exit_code, 0);
}

#[test]
fn test_zero_max_recv_limit() {
    let config = SandboxConfig::builder()
        .runtime("sh")
        .max_recv_line_bytes(0)
        .strategy(Strategy::None)
        .build();

    let dir = tempfile::tempdir().unwrap();
    let harness = dir.path().join("harness.sh");
    std::fs::write(&harness, "#!/bin/sh\nexit 0\n").unwrap();
    
    let work = tempfile::tempdir().unwrap();

    let res = SandboxedProcess::spawn(&harness, work.path(), &config);
    assert!(res.is_err());
    assert!(res.unwrap_err().to_string().contains("greater than zero"));
}
