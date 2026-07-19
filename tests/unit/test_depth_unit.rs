use procjail::{
    quick_spawn, available_strategy, probe_capabilities, EnvMode, SandboxConfig, Strategy
};
use std::collections::HashSet;
use std::path::PathBuf;

#[test]
fn test_sandbox_config_builder_methods() {
    let config = SandboxConfig::builder()
        .runtime("my-runtime")
        .runtime_args(&["--flag", "value"])
        .max_memory_mb(512)
        .max_cpu_seconds(120)
        .max_fds(1024)
        .max_disk_mb(100)
        .max_processes(10)
        .allow_localhost(true)
        .env_passthrough(&["FOO", "BAR"])
        .env_set("CUSTOM", "value")
        .env_strip_secrets(false)
        .env_strip(&["STRIP_ME"])
        .env_mode(EnvMode::Blocklist)
        .strategy(Strategy::Bubblewrap)
        .readonly_mount("/ro/host", "/ro/container")
        .writable_mount("/rw/host", "/rw/container")
        .timeout_seconds(300)
        .capture_stderr(true)
        .max_recv_line_bytes(2048)
        .build();

    assert_eq!(config.runtime_path, PathBuf::from("my-runtime"));
    assert_eq!(config.runtime_args, vec!["--flag", "value"]);
    assert_eq!(config.max_memory_bytes, 512 * 1024 * 1024);
    assert_eq!(config.max_cpu_seconds, 120);
    assert_eq!(config.max_fds, 1024);
    assert_eq!(config.max_disk_bytes, 100 * 1024 * 1024);
    assert_eq!(config.max_processes, 10);
    assert!(config.allow_localhost);

    let passthrough: HashSet<String> = ["FOO".to_string(), "BAR".to_string()].into_iter().collect();
    assert_eq!(config.env_passthrough, passthrough);
    assert_eq!(config.env_set, vec![("CUSTOM".to_string(), "value".to_string())]);
    assert!(!config.env_strip_secrets);

    let strip: HashSet<String> = ["STRIP_ME".to_string()].into_iter().collect();
    assert_eq!(config.env_strip, strip);

    assert_eq!(config.env_mode, EnvMode::Blocklist);
    assert_eq!(config.force_strategy, Some(Strategy::Bubblewrap));
    assert_eq!(config.readonly_mounts, vec![(PathBuf::from("/ro/host"), PathBuf::from("/ro/container"))]);
    assert_eq!(config.writable_mounts, vec![(PathBuf::from("/rw/host"), PathBuf::from("/rw/container"))]);
    assert_eq!(config.timeout_seconds, 300);
    assert!(config.capture_stderr);
    assert_eq!(config.max_recv_line_bytes, 2048);
}

#[test]
fn test_sandbox_config_load() {
    let toml = r#"
        max_memory_bytes = 1000000
        max_cpu_seconds = 42
        max_fds = 99
        max_disk_bytes = 5000
        max_processes = 5
        allow_localhost = true
        runtime_path = "/bin/custom"
        runtime_args = ["--test"]
        env_passthrough = ["HOME"]
        env_strip_secrets = false
        env_mode = "allowlist"
        timeout_seconds = 15
        capture_stderr = true
        max_recv_line_bytes = 100
    "#;
    
    let dir = tempfile::tempdir().unwrap();
    let file_path = dir.path().join("config.toml");
    std::fs::write(&file_path, toml).unwrap();

    let config = SandboxConfig::load(&file_path).unwrap();
    assert_eq!(config.max_memory_bytes, 1000000);
    assert_eq!(config.max_cpu_seconds, 42);
    assert_eq!(config.max_fds, 99);
    assert_eq!(config.max_disk_bytes, 5000);
    assert_eq!(config.max_processes, 5);
    assert!(config.allow_localhost);
    assert_eq!(config.runtime_path, PathBuf::from("/bin/custom"));
    assert_eq!(config.runtime_args, vec!["--test"]);
    assert_eq!(config.env_passthrough.iter().next().unwrap(), "HOME");
    assert!(!config.env_strip_secrets);
    assert_eq!(config.env_mode, EnvMode::Allowlist);
    assert_eq!(config.timeout_seconds, 15);
    assert!(config.capture_stderr);
    assert_eq!(config.max_recv_line_bytes, 100);
}

#[test]
fn test_quick_spawn_success() {
    let dir = tempfile::tempdir().unwrap();
    let harness = dir.path().join("harness.sh");
    std::fs::write(&harness, "#!/bin/sh\nexit 0\n").unwrap();
    
    // Set executable permissions natively
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&harness, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    let mut proc = quick_spawn("sh", &harness, dir.path()).unwrap();
    let usage = proc.wait_with_usage().unwrap();
    assert_eq!(usage.exit_code, 0);
}

#[test]
fn test_detect_probe_capabilities() {
    let caps = probe_capabilities();
    // Best strategy must match available_strategy
    assert_eq!(caps.best_strategy, available_strategy());
}
