use std::fs;

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

use procjail::{SandboxConfig, SandboxProvider, SandboxedProcess, Strategy};

fn create_sh_harness(dir: &Path, script: &str) -> PathBuf {
    let harness = dir.join("harness.sh");
    fs::write(&harness, script).unwrap();

    // Set executable permissions natively
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&harness, fs::Permissions::from_mode(0o755)).unwrap();
    }

    harness
}

#[test]
fn test_basic_shell_execution_and_io() {
    let work_dir = tempfile::tempdir().unwrap();
    let harness = create_sh_harness(
        work_dir.path(),
        "#!/bin/sh\n\
        read msg\n\
        printf '{\"resp\":\"%s\"}\\n' \"$msg\"\n",
    );

    let config = SandboxConfig::builder()
        .runtime("sh")
        .timeout_seconds(5)
        .strategy(Strategy::None) // fallback to None so it always succeeds without bwrap installed
        .build();

    let mut proc =
        SandboxedProcess::spawn(&harness, work_dir.path(), &config).expect("spawn failed");

    proc.send("hello_procjail").expect("send failed");

    let line = proc.recv().expect("recv failed").expect("eof early");

    assert_eq!(line.trim(), r#"{"resp":"hello_procjail"}"#);

    let usage = proc.wait_with_usage().expect("wait failed");
    assert_eq!(usage.exit_code, 0);
    assert!(!proc.killed_by_timeout);
}

#[test]
fn test_watchdog_timeout_kills_process() {
    let work_dir = tempfile::tempdir().unwrap();
    let harness = create_sh_harness(
        work_dir.path(),
        "#!/bin/sh\n\
        sleep 60\n",
    );

    let config = SandboxConfig::builder()
        .runtime("sh")
        .timeout_seconds(1) // Aggressive timeout
        .strategy(Strategy::None)
        .build();

    println!("Starting procjail timeout test...");

    let mut proc =
        SandboxedProcess::spawn(&harness, work_dir.path(), &config).expect("spawn failed");

    println!("Process spawned, awaiting watchdog...");

    let usage = proc.wait_with_usage().expect("wait failed!");

    println!("Process successfully reaped");

    // The process was forcefully killed by the parent watchdog
    assert!(proc.killed_by_timeout, "watchdog must register a kill");
    assert!(
        usage.wall_time_secs >= 0.9 && usage.wall_time_secs <= 2.0,
        "watchdog should trigger roughly around the 1 second mark"
    );
}

/// A community-driven provider that hijacks the command cleanly.
#[derive(Debug)]
struct HijackProvider;

impl SandboxProvider for HijackProvider {
    fn name(&self) -> &'static str {
        "hijack-test"
    }

    fn apply_to_command(
        &self,
        cmd: &mut Command,
        _runtime: &Path,
        _work_dir: &Path,
        _config: &SandboxConfig,
    ) -> procjail::Result<()> {
        // By the time apply_to_command is called, `cmd = Command::new(runtime)`
        // with args already established. We can clear args and do something completely custom!
        cmd.env("PROVIDER_HIJACK", "success");
        // Replace the exec target natively:
        *cmd = Command::new("echo");
        cmd.arg("custom-provider-ran");
        Ok(())
    }
}

#[test]
fn test_custom_sandbox_provider_extensibility() {
    let work_dir = tempfile::tempdir().unwrap();
    let harness = create_sh_harness(work_dir.path(), "#!/bin/sh\nexit 1");

    // We build a config using our Custom Provider
    let config = SandboxConfig::builder()
        .runtime("sh")
        .custom_provider(Arc::new(HijackProvider))
        .build();

    let mut proc =
        SandboxedProcess::spawn(&harness, work_dir.path(), &config).expect("spawn failed");

    // Read the output injected by the bespoke provider
    let output = proc.recv().expect("recv failed").expect("eof early");
    assert_eq!(output.trim(), "custom-provider-ran");

    // Normally the harness script returns 1, but we hijacked it to `echo` which returns 0
    let usage = proc.wait_with_usage().expect("wait failed");
    assert_eq!(usage.exit_code, 0);
}

#[test]
fn test_env_stripping_prevents_secret_leakage() {
    let work_dir = tempfile::tempdir().unwrap();
    // Harness prints out the current environment variables.
    let harness = create_sh_harness(
        work_dir.path(),
        "#!/bin/sh\n\
        env\n",
    );

    // Set an environment variable in the parent to test inheritance
    std::env::set_var("GITHUB_TOKEN", "super_secret_parent_token");

    let config = SandboxConfig::builder()
        .runtime("sh")
        .strategy(Strategy::None)
        .env_strip_secrets(true) // Native feature
        .env_strip(&["CUSTOM_SECRET_API"]) // Appended custom strip
        // Even if an attacker maliciously tries to re-attach the secret
        // via `env_set`, `procjail` must forcefully reject it.
        .env_set("GITHUB_TOKEN", "attacker_controlled")
        .env_set("CUSTOM_SECRET_API", "attacker_controlled")
        .env_set("SAFE_VAR", "safe_value")
        .build();

    let mut proc = SandboxedProcess::spawn(&harness, work_dir.path(), &config).expect("spawn");

    let mut envs = Vec::new();
    while let Ok(Some(line)) = proc.recv() {
        envs.push(line);
    }

    let env_output = envs.join("\n");

    // The safe var should be passed down
    assert!(env_output.contains("SAFE_VAR=safe_value"));

    // The secret tokens MUST NEVER be exposed in the child process memory
    assert!(!env_output.contains("GITHUB_TOKEN"));
    assert!(!env_output.contains("CUSTOM_SECRET_API"));

    let usage = proc.wait_with_usage().expect("wait");
    assert_eq!(usage.exit_code, 0);
}

#[test]
fn test_spawn_passes_work_dir_as_harness_argument() {
    let work_dir = tempfile::tempdir().unwrap();
    let harness = create_sh_harness(
        work_dir.path(),
        "#!/bin/sh\n\
        printf '{\"work_dir\":\"%s\"}\\n' \"$1\"\n",
    );

    let config = SandboxConfig::builder()
        .runtime("sh")
        .timeout_seconds(5)
        .strategy(Strategy::None)
        .build();

    let mut proc =
        SandboxedProcess::spawn(&harness, work_dir.path(), &config).expect("spawn failed");

    let line = proc.recv().expect("recv failed").expect("eof early");
    let parsed: serde_json::Value = serde_json::from_str(line.trim()).expect("valid json");
    assert_eq!(
        parsed.get("work_dir").and_then(|v| v.as_str()),
        Some(work_dir.path().to_str().unwrap())
    );

    let usage = proc.wait_with_usage().expect("wait failed");
    assert_eq!(usage.exit_code, 0);
}

/// Verify a shell harness can fork+exec an external command with the default
/// rlimit configuration. Regression for src/process/builder.rs:259: a low
/// absolute RLIMIT_NPROC cap and a missing SYS_vfork allowlist both caused
/// `sh` to fail with "Cannot fork" when running `env`.
#[test]
fn test_sh_can_fork_and_exec_env() {
    let work_dir = tempfile::tempdir().unwrap();
    let harness = create_sh_harness(work_dir.path(), "#!/bin/sh\n\nenv\n");

    let config = SandboxConfig::builder()
        .runtime("sh")
        .strategy(Strategy::None)
        .build();

    let mut proc =
        SandboxedProcess::spawn(&harness, work_dir.path(), &config).expect("spawn failed");

    let mut env_output = String::new();
    while let Ok(Some(line)) = proc.recv() {
        if !env_output.is_empty() {
            env_output.push('\n');
        }
        env_output.push_str(&line);
    }

    assert!(!env_output.is_empty(), "env output must not be empty");
    assert!(env_output.contains("PATH="), "env output must contain PATH");
    let usage = proc.wait_with_usage().expect("wait failed");
    assert_eq!(usage.exit_code, 0, "env must exit 0");
}

/// A custom provider that does not replace the runtime but is still active.
/// It proves that `build_command` applies rlimits and seccomp *after* the
/// provider has mutated the command.
#[derive(Debug)]
struct NoopCustomProvider;

impl SandboxProvider for NoopCustomProvider {
    fn name(&self) -> &'static str {
        "noop-custom"
    }

    fn apply_to_command(
        &self,
        cmd: &mut Command,
        _runtime: &Path,
        _work_dir: &Path,
        _config: &SandboxConfig,
    ) -> procjail::Result<()> {
        // Mutate the command so the test can distinguish provider-invoked paths.
        cmd.env("CUSTOM_PROVIDER", "active");
        Ok(())
    }
}

#[test]
fn test_custom_provider_preserves_pre_exec_rlimits_and_seccomp() {
    let work_dir = tempfile::tempdir().unwrap();
    // Use sh builtins for rlimits and a mkdir syscall for seccomp.
    let script = r#"#!/bin/sh
printf "CUSTOM_PROVIDER=%s\n" "$CUSTOM_PROVIDER"
printf "MEMORY_KB=%s\n" "$(ulimit -v)"
printf "CPU_SEC=%s\n" "$(ulimit -t)"
printf "MAX_FDS=%s\n" "$(ulimit -n)"
# mkdir is not in the seccomp allowlist and should be denied.
TMPDIR="/tmp"
DIR="$TMPDIR/procjail_seccomp_probe_$$"
OUT=$(mkdir "$DIR" 2>&1)
EC=$?
printf "MKDIR_EXIT=%s\n" "$EC"
printf "MKDIR_ERR=%s\n" "$OUT"
"#;
    let harness = create_sh_harness(work_dir.path(), script);

    let config = SandboxConfig::builder()
        .runtime("sh")
        .max_memory_mb(123)
        .max_cpu_seconds(456)
        .max_fds(89)
        .custom_provider(Arc::new(NoopCustomProvider))
        .build();

    let mut proc =
        SandboxedProcess::spawn(&harness, work_dir.path(), &config).expect("spawn failed");

    let mut lines = Vec::new();
    while let Ok(Some(line)) = proc.recv() {
        lines.push(line);
    }

    let output = lines.join(
        "
",
    );
    assert!(
        output.contains("CUSTOM_PROVIDER=active"),
        "custom provider must run: {output}"
    );
    assert!(
        output.contains("MEMORY_KB=125952"),
        "RLIMIT_AS must be 123 MiB in KB: {output}"
    );
    assert!(
        output.contains("CPU_SEC=456"),
        "RLIMIT_CPU must be 456s: {output}"
    );
    assert!(
        output.contains("MAX_FDS=89"),
        "RLIMIT_NOFILE must be 89: {output}"
    );
    assert!(
        output.contains("MKDIR_EXIT=1"),
        "mkdir must fail under seccomp: {output}"
    );
    assert!(
        output.contains("MKDIR_ERR=mkdir: ") && output.contains("Operation not permitted"),
        "mkdir must fail with EPERM, got: {output}"
    );

    let usage = proc.wait_with_usage().expect("wait failed");
    assert_eq!(
        usage.exit_code, 0,
        "harness must exit cleanly after reporting"
    );
}
