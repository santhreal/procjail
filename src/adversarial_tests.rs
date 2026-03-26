//! Adversarial tests designed to break santh-sandbox.
//!
//! These tests probe edge cases, invalid inputs, and security-sensitive
//! scenarios that SHOULD fail or be handled securely.

#[cfg(test)]
mod tests {
    use crate::process::build_command;
    use crate::{SandboxConfig, SandboxedProcess, Strategy};
    use std::io::Write;
    use std::path::Path;

    // =========================================================================
    // Test 1: spawn with nonexistent runtime binary
    // =========================================================================
    #[test]
    fn spawn_nonexistent_runtime() {
        let config = SandboxConfig::builder()
            .runtime("/definitely/not/a/real/runtime/binary_xyz123")
            .strategy(Strategy::None)
            .build();

        let harness = tempfile::NamedTempFile::new().unwrap();
        let work = tempfile::tempdir().unwrap();

        let result = SandboxedProcess::spawn(harness.path(), work.path(), &config);

        // Should fail - runtime doesn't exist
        assert!(
            result.is_err(),
            "spawn with nonexistent runtime should fail"
        );
    }

    // =========================================================================
    // Test 2: spawn with empty harness path
    // =========================================================================
    #[test]
    fn spawn_empty_harness_path() {
        let config = SandboxConfig::builder()
            .runtime("/bin/echo")
            .strategy(Strategy::None)
            .build();

        let work = tempfile::tempdir().unwrap();
        let empty_harness = Path::new("");

        let result = SandboxedProcess::spawn(empty_harness, work.path(), &config);

        // Should fail - empty harness path is invalid
        assert!(result.is_err(), "spawn with empty harness path should fail");
    }

    // =========================================================================
    // Test 3: spawn with /dev/null as work_dir
    // =========================================================================
    #[test]
    fn spawn_dev_null_as_work_dir() {
        let config = SandboxConfig::builder()
            .runtime("/bin/echo")
            .strategy(Strategy::None)
            .build();

        let harness = tempfile::NamedTempFile::new().unwrap();

        let result = SandboxedProcess::spawn(harness.path(), Path::new("/dev/null"), &config);

        // Should fail - /dev/null is not a directory
        assert!(
            result.is_err(),
            "spawn with /dev/null as work_dir should fail"
        );
    }

    // =========================================================================
    // Test 4: build_command with Strategy::Bubblewrap and work_dir containing spaces
    // =========================================================================
    #[test]
    fn build_command_bubblewrap_work_dir_with_spaces() {
        // This tests if the bwrap command construction handles spaces properly
        let config = SandboxConfig::builder()
            .runtime("/bin/echo")
            .strategy(Strategy::Bubblewrap)
            .build();

        let result = build_command(
            Path::new("/bin/echo"),
            Path::new("/tmp/harness.js"),
            Path::new("/tmp/path with spaces/work dir"),
            &config,
            Strategy::Bubblewrap,
        );

        assert!(result.is_ok());
        let cmd = result.unwrap();
        let args: Vec<_> = cmd.get_args().map(|s| s.to_string_lossy().into_owned()).collect();
        assert!(
            args.iter().any(|arg| arg == "/tmp/path with spaces/work dir"),
            "work dir with spaces should be preserved as a single argument"
        );
    }

    // =========================================================================
    // Test 5: build_command with env_set containing = in the value
    // =========================================================================
    #[test]
    fn build_command_env_set_with_equals_in_value() {
        let config = SandboxConfig::builder()
            .runtime("/bin/echo")
            .strategy(Strategy::None)
            .env_set("MY_VAR", "value=with=equals=signs")
            .env_set("ANOTHER_VAR", "foo=bar=baz=qux")
            .build();

        let result = build_command(
            Path::new("/bin/echo"),
            Path::new("/tmp/harness.js"),
            Path::new("/tmp/work"),
            &config,
            Strategy::None,
        );

        // Should succeed - env values with = are valid
        assert!(
            result.is_ok(),
            "build_command with = in env value should succeed"
        );
    }

    // =========================================================================
    // Test 6: timeout of 0 should disable watchdog
    // =========================================================================
    #[test]
    fn timeout_zero_disables_watchdog() {
        let mut harness = tempfile::NamedTempFile::new().unwrap();
        writeln!(harness, "sleep 1").unwrap();
        let config = SandboxConfig::builder()
            .runtime("/bin/sh")
            .strategy(Strategy::None)
            .timeout_seconds(0) // 0 = no timeout
            .build();
        let work = tempfile::tempdir().unwrap();

        let result = SandboxedProcess::spawn(harness.path(), work.path(), &config);
        let mut proc = result.expect("process should spawn");
        std::thread::sleep(std::time::Duration::from_millis(100));
        assert!(proc.is_alive(), "timeout=0 should leave the process running");
        assert!(!proc.killed_by_timeout, "watchdog must remain disabled");
        proc.kill();
    }

    // =========================================================================
    // Test 7: config with max_memory_bytes = 0
    // =========================================================================
    #[test]
    fn config_zero_max_memory() {
        let config = SandboxConfig::builder()
            .runtime("/bin/echo")
            .strategy(Strategy::None)
            .max_memory_bytes(0) // 0 bytes - should this be allowed?
            .build();

        assert_eq!(config.max_memory_bytes, 0, "max_memory_bytes should be 0");

        let result = build_command(
            Path::new("/bin/echo"),
            Path::new("/tmp/harness.js"),
            Path::new("/tmp/work"),
            &config,
            Strategy::None,
        );

        // Build might succeed, but spawn/execution might fail with 0 memory limit
        assert!(
            result.is_ok(),
            "build_command with max_memory_bytes=0 should succeed in construction"
        );
    }

    // =========================================================================
    // Test 8: config with timeout_seconds = u64::MAX
    // =========================================================================
    #[test]
    fn config_max_timeout() {
        let mut harness = tempfile::NamedTempFile::new().unwrap();
        writeln!(harness, "sleep 1").unwrap();
        let config = SandboxConfig::builder()
            .runtime("/bin/sh")
            .strategy(Strategy::None)
            .timeout_seconds(u64::MAX) // Maximum possible timeout
            .build();

        assert_eq!(
            config.timeout_seconds,
            u64::MAX,
            "timeout_seconds should be u64::MAX"
        );

        // This could cause overflow issues in Duration calculations
        let work = tempfile::tempdir().unwrap();

        let mut proc = SandboxedProcess::spawn(harness.path(), work.path(), &config)
            .expect("spawn should handle huge timeout values");
        std::thread::sleep(std::time::Duration::from_millis(100));
        assert!(proc.is_alive(), "huge timeout should not overflow into immediate kill");
        assert!(!proc.killed_by_timeout, "watchdog should not mark process as timed out");
        proc.kill();
    }

    // =========================================================================
    // Test 9: build_command with empty work_dir
    // =========================================================================
    #[test]
    fn build_command_empty_work_dir() {
        let config = SandboxConfig::builder()
            .runtime("/bin/echo")
            .strategy(Strategy::None)
            .build();

        let result = build_command(
            Path::new("/bin/echo"),
            Path::new("/tmp/harness.js"),
            Path::new(""), // Empty work_dir
            &config,
            Strategy::None,
        );

        // Should fail - empty path is not absolute
        assert!(
            result.is_err(),
            "build_command with empty work_dir should fail"
        );
    }

    // =========================================================================
    // Test 10: build_command with relative work_dir
    // =========================================================================
    #[test]
    fn build_command_relative_work_dir() {
        let config = SandboxConfig::builder()
            .runtime("/bin/echo")
            .strategy(Strategy::None)
            .build();

        let result = build_command(
            Path::new("/bin/echo"),
            Path::new("/tmp/harness.js"),
            Path::new("relative/path/to/work"),
            &config,
            Strategy::None,
        );

        // Should fail - relative path is not absolute
        assert!(
            result.is_err(),
            "build_command with relative work_dir should fail"
        );
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("absolute"),
            "error should mention 'absolute': {err}"
        );
    }

    // =========================================================================
    // Test 11: spawn with nonexistent harness file
    // =========================================================================
    #[test]
    fn spawn_nonexistent_harness() {
        let config = SandboxConfig::builder()
            .runtime("cat")
            .strategy(Strategy::None)
            .build();

        let work = tempfile::tempdir().unwrap();

        let result = SandboxedProcess::spawn(
            Path::new("/definitely/not/a/real/harness_xyz123.js"),
            work.path(),
            &config,
        );
        match result {
            Err(error) => assert!(
                error
                    .to_string()
                    .contains("harness_path must exist"),
                "unexpected error: {error}"
            ),
            Ok(_) => panic!("spawn should fail for a missing harness file"),
        }
    }

    // =========================================================================
    // Test 12: env_set with empty key
    // =========================================================================
    #[test]
    fn build_command_env_set_empty_key() {
        let config = SandboxConfig::builder()
            .runtime("/bin/echo")
            .strategy(Strategy::None)
            .env_set("", "some_value") // Empty key
            .build();

        let result = build_command(
            Path::new("/bin/echo"),
            Path::new("/tmp/harness.js"),
            Path::new("/tmp/work"),
            &config,
            Strategy::None,
        );

        let error = result.expect_err("empty env var names must be rejected");
        assert!(error.to_string().contains("must not be empty"));
    }

    // =========================================================================
    // Test 13: env_set with newline in value (injection attempt)
    // =========================================================================
    #[test]
    fn build_command_env_set_newline_injection() {
        let config = SandboxConfig::builder()
            .runtime("/bin/echo")
            .strategy(Strategy::None)
            .env_set("MALICIOUS", "value\nSOMETHING_ELSE=evil") // Newline injection
            .build();

        let result = build_command(
            Path::new("/bin/echo"),
            Path::new("/tmp/harness.js"),
            Path::new("/tmp/work"),
            &config,
            Strategy::None,
        );

        let cmd = result.expect("newline in values should stay a single env value");
        let envs: Vec<_> = cmd
            .get_envs()
            .filter_map(|(k, v)| k.to_str().zip(v.and_then(|val| val.to_str())))
            .collect();
        let malicious = envs
            .iter()
            .find(|(k, _)| *k == "MALICIOUS")
            .expect("MALICIOUS env var");
        assert_eq!(malicious.1, "value\nSOMETHING_ELSE=evil");
    }

    // =========================================================================
    // Test 14: readonly_mount with nonexistent host path
    // =========================================================================
    #[test]
    fn build_command_readonly_mount_nonexistent() {
        let config = SandboxConfig::builder()
            .runtime("/bin/echo")
            .strategy(Strategy::Bubblewrap)
            .readonly_mount("/definitely/not/a/real/path_xyz123", "/mnt")
            .build();

        let result = build_command(
            Path::new("/bin/echo"),
            Path::new("/tmp/harness.js"),
            Path::new("/tmp/work"),
            &config,
            Strategy::Bubblewrap,
        );

        let cmd = result.expect("absolute mount paths should be accepted at command-build time");
        let args: Vec<_> = cmd.get_args().map(|s| s.to_string_lossy().into_owned()).collect();
        assert!(
            args.contains(&"/definitely/not/a/real/path_xyz123".to_string()),
            "readonly mount host path should be propagated to bubblewrap"
        );
    }

    // =========================================================================
    // Test 15: Firejail with timeout = 0 (edge case for --timeout formatting)
    // =========================================================================
    #[test]
    fn build_command_firejail_zero_timeout() {
        let config = SandboxConfig::builder()
            .runtime("/bin/echo")
            .strategy(Strategy::Firejail)
            .timeout_seconds(0)
            .build();

        let result = build_command(
            Path::new("/bin/echo"),
            Path::new("/tmp/harness.js"),
            Path::new("/tmp/work"),
            &config,
            Strategy::Firejail,
        );

        let cmd = result.unwrap();
        let args: Vec<_> = cmd.get_args().map(|s| s.to_string_lossy().into_owned()).collect();
        assert!(args.contains(&"--timeout=00:00:00".to_string()), "zero timeout should format correctly");
    }

    // =========================================================================
    // Test 16: max_fds = 0 (no file descriptors allowed)
    // =========================================================================
    #[test]
    fn config_zero_max_fds() {
        let config = SandboxConfig::builder()
            .runtime("/bin/echo")
            .strategy(Strategy::Firejail)
            .max_fds(0) // No file descriptors
            .build();

        assert_eq!(config.max_fds, 0);

        let result = build_command(
            Path::new("/bin/echo"),
            Path::new("/tmp/harness.js"),
            Path::new("/tmp/work"),
            &config,
            Strategy::Firejail,
        );

        let cmd = result.unwrap();
        let args: Vec<_> = cmd.get_args().map(|s| s.to_string_lossy().into_owned()).collect();
        assert!(args.contains(&"--rlimit-nofile=0".to_string()), "max_fds=0 must be in args");
    }

    // =========================================================================
    // Test 17: max_processes = 0 (no child processes allowed)
    // =========================================================================
    #[test]
    fn config_zero_max_processes() {
        let config = SandboxConfig::builder()
            .runtime("/bin/echo")
            .strategy(Strategy::Firejail)
            .max_processes(0) // No child processes
            .build();

        assert_eq!(config.max_processes, 0);

        let result = build_command(
            Path::new("/bin/echo"),
            Path::new("/tmp/harness.js"),
            Path::new("/tmp/work"),
            &config,
            Strategy::Firejail,
        );

        let cmd = result.unwrap();
        let args: Vec<_> = cmd.get_args().map(|s| s.to_string_lossy().into_owned()).collect();
        assert!(args.contains(&"--rlimit-nproc=0".to_string()), "max_processes=0 must be in args");
    }

    // =========================================================================
    // Test 18: Unshare strategy with allow_localhost = true (network namespace edge case)
    // =========================================================================
    #[test]
    fn build_command_unshare_allow_localhost() {
        let config = SandboxConfig::builder()
            .runtime("/bin/echo")
            .strategy(Strategy::Unshare)
            .allow_localhost(true)
            .build();

        let result = build_command(
            Path::new("/bin/echo"),
            Path::new("/tmp/harness.js"),
            Path::new("/tmp/work"),
            &config,
            Strategy::Unshare,
        );

        let cmd = result.unwrap();
        let args: Vec<_> = cmd.get_args().map(|s| s.to_string_lossy().into_owned()).collect();
        assert!(!args.contains(&"--net".to_string()), "--net should not be present");
    }

    // =========================================================================
    // Test 19: Very long runtime argument
    // =========================================================================
    #[test]
    fn build_command_very_long_runtime_arg() {
        let long_arg = "x".repeat(10000);
        let config = SandboxConfig::builder()
            .runtime("/bin/echo")
            .strategy(Strategy::None)
            .runtime_args(&[&long_arg])
            .build();

        let result = build_command(
            Path::new("/bin/echo"),
            Path::new("/tmp/harness.js"),
            Path::new("/tmp/work"),
            &config,
            Strategy::None,
        );

        let cmd = result.unwrap();
        let args: Vec<_> = cmd.get_args().map(|s| s.to_string_lossy().into_owned()).collect();
        assert!(args.contains(&long_arg), "long arg should be preserved");
    }

    // =========================================================================
    // Test 20: Multiple conflicting env modes with secrets
    // =========================================================================
    #[test]
    fn build_command_conflicting_env_modes() {
        let config = SandboxConfig::builder()
            .runtime("/bin/echo")
            .strategy(Strategy::None)
            .env_mode(crate::config::EnvMode::Allowlist)
            .env_passthrough(&["GITHUB_TOKEN"]) // Try to passthrough a secret
            .env_set("GITHUB_TOKEN", "should_be_blocked") // Try to set a secret
            .build();

        let result = build_command(
            Path::new("/bin/echo"),
            Path::new("/tmp/harness.js"),
            Path::new("/tmp/work"),
            &config,
            Strategy::None,
        );

        let cmd = result.unwrap();
        let envs: Vec<_> = cmd.get_envs().filter_map(|(k, _)| k.to_str().map(|s| s.to_string())).collect();
        println!("ENVS: {:?}", envs);
        assert!(!envs.contains(&"GITHUB_TOKEN".to_string()), "GITHUB_TOKEN must be stripped");
    }
}
