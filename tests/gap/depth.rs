use procjail::{SandboxConfig, SandboxedProcess, Strategy};

#[test]
fn test_gap_extreme_env_nesting() {
    let mut builder = SandboxConfig::builder()
        .runtime("sh")
        .strategy(Strategy::None);
    
    // Add many env vars
    for i in 0..1000 {
        builder = builder.env_set(&format!("VAR_{}", i), "value");
    }
    let config = builder.build();

    let dir = tempfile::tempdir().unwrap();
    let harness = dir.path().join("harness.sh");
    std::fs::write(&harness, "#!/bin/sh\nexit 0\n").unwrap();
    
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&harness, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    let mut proc = SandboxedProcess::spawn(&harness, dir.path(), &config).expect("Should handle many env vars");
    let usage = proc.wait_with_usage().unwrap();
    assert_eq!(usage.exit_code, 0);
}

#[test]
fn test_gap_large_recv_line() {
    // Generate a line larger than the default internal buffer of BufReader
    let large_output = "A".repeat(1024 * 1024 * 2); // 2MB
    let script = format!("#!/bin/sh\necho \"{}\"\n", large_output);
    
    let dir = tempfile::tempdir().unwrap();
    let harness = dir.path().join("harness.sh");
    std::fs::write(&harness, script).unwrap();
    
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&harness, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    let config = SandboxConfig::builder()
        .runtime("sh")
        .max_recv_line_bytes(1024 * 1024 * 3) // 3MB limit
        .strategy(Strategy::None)
        .build();

    let mut proc = SandboxedProcess::spawn(&harness, dir.path(), &config).unwrap();
    let line = proc.recv().unwrap().expect("Should read line");
    assert_eq!(line.trim(), large_output);
    let usage = proc.wait_with_usage().unwrap();
    assert_eq!(usage.exit_code, 0);
}
