use procjail::SandboxConfig;
use std::path::PathBuf;

#[test]
fn default_config() {
    let config = SandboxConfig::default();
    assert_eq!(config.max_memory_bytes, 256 * 1024 * 1024);
    assert_eq!(config.max_cpu_seconds, 30);
    assert_eq!(config.max_fds, 64);
    assert!(!config.allow_localhost);
    assert!(config.env_strip_secrets);
    assert_eq!(config.timeout_seconds, 60);
}

#[test]
fn builder_works() {
    let config = SandboxConfig::builder()
        .runtime("/usr/bin/python3")
        .max_memory_mb(512)
        .max_cpu_seconds(60)
        .max_fds(128)
        .max_processes(64)
        .allow_localhost(true)
        .env_passthrough(&["HOME", "PATH"])
        .env_set("MY_VAR", "my_value")
        .env_strip_secrets(true)
        .env_strip(&["CUSTOM_SECRET"])
        .timeout_seconds(120)
        .capture_stderr(true)
        .build();

    assert_eq!(config.runtime_path, PathBuf::from("/usr/bin/python3"));
    assert_eq!(config.max_memory_bytes, 512 * 1024 * 1024);
    assert_eq!(config.max_cpu_seconds, 60);
    assert_eq!(config.max_fds, 128);
    assert_eq!(config.max_processes, 64);
    assert!(config.allow_localhost);
    assert!(config.env_passthrough.contains("HOME"));
    assert!(config.env_passthrough.contains("PATH"));
    assert_eq!(config.env_set[0], ("MY_VAR".into(), "my_value".into()));
    assert!(config.env_strip.contains("CUSTOM_SECRET"));
    assert_eq!(config.timeout_seconds, 120);
    assert!(config.capture_stderr);
    assert_eq!(config.max_recv_line_bytes, 1024 * 1024);
}
