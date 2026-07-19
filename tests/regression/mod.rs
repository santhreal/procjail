//! Regression tests for historical security bugs in procjail.
//!
//! Each test documents a specific vulnerability class and verifies the fix.

use std::path::Path;

use procjail::{SandboxConfig, SandboxedProcess, Strategy};

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

// Regression: CVE-2016-1247 style path traversal via relative work_dir.
#[test]
fn relative_work_dir_rejected() {
    let config = SandboxConfig::builder()
        .runtime("sh")
        .strategy(Strategy::None)
        .build();

    let harness = tempfile::NamedTempFile::new().unwrap();
    let result = SandboxedProcess::spawn(harness.path(), Path::new("relative/path"), &config);
    assert!(result.is_err(), "relative work_dir must be rejected");
}

// Regression: harness path escape via empty string.
#[test]
fn empty_harness_path_rejected() {
    let config = SandboxConfig::builder()
        .runtime("sh")
        .strategy(Strategy::None)
        .build();

    let work = tempfile::tempdir().unwrap();
    let result = SandboxedProcess::spawn(Path::new(""), work.path(), &config);
    assert!(result.is_err(), "empty harness path must be rejected");
}

// Regression: secrets could be re-injected via env_set.
#[test]
fn env_set_cannot_override_secret_stripping() {
    let work_dir = tempfile::tempdir().unwrap();
    let harness = create_sh_harness(work_dir.path(), "#!/bin/sh\nenv\n");

    std::env::set_var("GITHUB_TOKEN", "super_secret");

    let config = SandboxConfig::builder()
        .runtime("sh")
        .strategy(Strategy::None)
        .env_strip_secrets(true)
        .env_set("GITHUB_TOKEN", "attacker_value")
        .build();

    let mut proc = SandboxedProcess::spawn(&harness, work_dir.path(), &config).expect("spawn failed");
    let mut output = String::new();
    while let Ok(Some(line)) = proc.recv() {
        output.push_str(&line);
    }
    assert!(
        !output.contains("GITHUB_TOKEN"),
        "env_set must not bypass secret stripping"
    );
    let usage = proc.wait_with_usage().expect("wait failed");
    assert_eq!(usage.exit_code, 0);
}

// Regression: passthrough mode could re-add secrets.
#[test]
fn allowlist_mode_cannot_resurrect_secrets() {
    let work_dir = tempfile::tempdir().unwrap();
    let harness = create_sh_harness(work_dir.path(), "#!/bin/sh\nenv\n");

    std::env::set_var("OPENAI_API_KEY", "sk-secret");

    let config = SandboxConfig::builder()
        .runtime("sh")
        .strategy(Strategy::None)
        .env_mode(procjail::EnvMode::Allowlist)
        .env_passthrough(&["OPENAI_API_KEY"])
        .build();

    let mut proc = SandboxedProcess::spawn(&harness, work_dir.path(), &config).expect("spawn failed");
    let mut output = String::new();
    while let Ok(Some(line)) = proc.recv() {
        output.push_str(&line);
    }
    assert!(
        !output.contains("OPENAI_API_KEY"),
        "allowlist must not resurrect secrets via passthrough"
    );
    let usage = proc.wait_with_usage().expect("wait failed");
    assert_eq!(usage.exit_code, 0);
}

// Regression: zero recv limit caused division-by-zero style hang.
#[test]
fn zero_recv_limit_rejected_at_spawn() {
    let config = SandboxConfig::builder()
        .runtime("sh")
        .max_recv_line_bytes(0)
        .strategy(Strategy::None)
        .build();

    let harness = tempfile::NamedTempFile::new().unwrap();
    let work = tempfile::tempdir().unwrap();
    let result = SandboxedProcess::spawn(harness.path(), work.path(), &config);
    assert!(result.is_err(), "zero recv limit must be rejected");
}

// Regression: mount paths that are relative could escape the sandbox.
#[test]
fn bwrap_relative_mount_rejected() {
    let work_dir = tempfile::tempdir().unwrap();
    let harness = create_sh_harness(work_dir.path(), "#!/bin/sh\necho ok\n");

    let config = SandboxConfig::builder()
        .runtime("sh")
        .strategy(Strategy::Bubblewrap)
        .readonly_mount("relative/path", "/container")
        .build();

    let result = SandboxedProcess::spawn(&harness, work_dir.path(), &config);
    match result {
        Err(e) => {
            let msg = e.to_string();
            assert!(
                msg.contains("must be absolute") || msg.contains("bwrap not available"),
                "relative mount must be rejected or bwrap unavailable; got: {msg}"
            );
        }
        Ok(_) => panic!("relative mount should be rejected"),
    }
}

// Regression: firejail relative mount whitelist escape.
#[test]
fn firejail_relative_mount_rejected() {
    let work_dir = tempfile::tempdir().unwrap();
    let harness = create_sh_harness(work_dir.path(), "#!/bin/sh\necho ok\n");

    let config = SandboxConfig::builder()
        .runtime("sh")
        .strategy(Strategy::Firejail)
        .readonly_mount("relative/path", "/container")
        .build();

    let result = SandboxedProcess::spawn(&harness, work_dir.path(), &config);
    match result {
        Err(e) => {
            let msg = e.to_string();
            assert!(
                msg.contains("must be absolute") || msg.contains("firejail not available"),
                "relative mount must be rejected or firejail unavailable; got: {msg}"
            );
        }
        Ok(_) => panic!("relative mount should be rejected"),
    }
}

// Regression: custom provider could be used to bypass absolute path checks.
#[test]
fn custom_provider_still_requires_absolute_paths() {
    use procjail::{SandboxConfig, SandboxProvider};
    use std::path::Path;
    use std::process::Command;

    #[derive(Debug)]
    struct NopProvider;

    impl SandboxProvider for NopProvider {
        fn name(&self) -> &'static str {
            "nop"
        }
        fn apply_to_command(
            &self,
            _cmd: &mut Command,
            _runtime: &Path,
            _work_dir: &Path,
            _config: &SandboxConfig,
        ) -> procjail::Result<()> {
            Ok(())
        }
    }

    let config = SandboxConfig::builder()
        .runtime("sh")
        .custom_provider(std::sync::Arc::new(NopProvider))
        .build();

    let harness = tempfile::NamedTempFile::new().unwrap();
    let result = SandboxedProcess::spawn(harness.path(), Path::new("relative/path"), &config);
    assert!(result.is_err(), "custom provider must not bypass absolute path checks");
}

// Regression: huge environment values could cause ENOMEM or truncation.
#[test]
fn env_value_size_limit_enforced() {
    let huge = "X".repeat(1024 * 64); // 64 KB, above 32 KB limit
    let config = SandboxConfig::builder()
        .runtime("sh")
        .env_set("HUGE", &huge)
        .strategy(Strategy::None)
        .build();

    let harness = tempfile::NamedTempFile::new().unwrap();
    let work = tempfile::tempdir().unwrap();
    let result = SandboxedProcess::spawn(harness.path(), work.path(), &config);
    assert!(result.is_err(), "oversized env value must be rejected");
}

// Regression: null byte in env name could inject extra variables.
#[test]
fn null_byte_in_env_name_rejected() {
    let config = SandboxConfig::builder()
        .runtime("sh")
        .env_set("EVIL\0NAME", "value")
        .strategy(Strategy::None)
        .build();

    let harness = tempfile::NamedTempFile::new().unwrap();
    let work = tempfile::tempdir().unwrap();
    let result = SandboxedProcess::spawn(harness.path(), work.path(), &config);
    assert!(result.is_err(), "null byte in env name must be rejected");
}

// Regression: whitespace in env name could confuse shell parsers.
#[test]
fn whitespace_in_env_name_rejected() {
    let config = SandboxConfig::builder()
        .runtime("sh")
        .env_set("EVIL NAME", "value")
        .strategy(Strategy::None)
        .build();

    let harness = tempfile::NamedTempFile::new().unwrap();
    let work = tempfile::tempdir().unwrap();
    let result = SandboxedProcess::spawn(harness.path(), work.path(), &config);
    assert!(result.is_err(), "whitespace in env name must be rejected");
}

// Regression: empty env name could be used to inject unnamed variables.
#[test]
fn empty_env_name_rejected() {
    let config = SandboxConfig::builder()
        .runtime("sh")
        .env_set("", "value")
        .strategy(Strategy::None)
        .build();

    let harness = tempfile::NamedTempFile::new().unwrap();
    let work = tempfile::tempdir().unwrap();
    let result = SandboxedProcess::spawn(harness.path(), work.path(), &config);
    assert!(result.is_err(), "empty env name must be rejected");
}
