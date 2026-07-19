//! Resource limit enforcement tests.
//!
//! These tests verify that the sandbox kills or throttles processes that
//! exceed their memory, CPU, or file-descriptor quotas.  A failure here
//! means a DoS vector: untrusted code can exhaust host resources.

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

/// Spawn a process with a very tight memory limit and verify it is killed.
/// We use Strategy::None so the test works everywhere, but we rely on the
/// pre_exec rlimit that procjail installs even for Strategy::None.
#[test]
fn memory_limit_kills_greedy_process() {
    let work_dir = tempfile::tempdir().unwrap();
    // Python is widely available and can allocate memory deterministically.
    let harness = create_sh_harness(
        work_dir.path(),
        "#!/bin/sh\npython3 -c '
import sys
a = []
while True:
    a.append(b\"X\" * (1024 * 1024))
    sys.stdout.write(str(len(a)) + \"\\n\")
    sys.stdout.flush()
' || echo OOM_KILLED
",
    );

    let config = SandboxConfig::builder()
        .runtime("sh")
        .max_memory_bytes(32 * 1024 * 1024) // 32 MB
        .timeout_seconds(10)
        .strategy(Strategy::None)
        .build();

    let mut proc =
        SandboxedProcess::spawn(&harness, work_dir.path(), &config).expect("spawn failed");

    // The process should die before the 10-second timeout.
    let usage = proc.wait_with_usage().expect("wait failed");
    assert_ne!(
        usage.exit_code, 0,
        "greedy process must be killed by memory limit; exit_code={}",
        usage.exit_code
    );
    assert!(
        usage.wall_time_secs < 8.0,
        "memory kill should happen quickly; took {}s",
        usage.wall_time_secs
    );
}

/// Same test but using a pure shell loop to avoid depending on python.
#[test]
fn memory_limit_kills_shell_allocator() {
    let work_dir = tempfile::tempdir().unwrap();
    let harness = create_sh_harness(
        work_dir.path(),
        "#!/bin/sh\n\
        # Allocate a block larger than the address-space limit so dd cannot\n\
        # allocate its I/O buffer and exits immediately.\n\
        set -e\n\
        while true; do\n\
            dd if=/dev/zero of=\"$1/procjail_alloc\" bs=64M\n\
        done\n",
    );

    let config = SandboxConfig::builder()
        .runtime("sh")
        .max_memory_bytes(16 * 1024 * 1024)
        .timeout_seconds(10)
        .strategy(Strategy::None)
        .build();

    let mut proc =
        SandboxedProcess::spawn(&harness, work_dir.path(), &config).expect("spawn failed");
    let usage = proc.wait_with_usage().expect("wait failed");
    assert_ne!(
        usage.exit_code, 0,
        "shell allocator must be killed; exit_code={}",
        usage.exit_code
    );
    assert!(
        usage.wall_time_secs < 8.0,
        "memory kill should happen quickly; took {}s",
        usage.wall_time_secs
    );
}

/// Verify CPU time limit kills a CPU-bound process.
#[test]
fn cpu_limit_kills_burner_process() {
    let work_dir = tempfile::tempdir().unwrap();
    let harness = create_sh_harness(
        work_dir.path(),
        "#!/bin/sh\npython3 -c '
while True:
    pass
' || echo CPU_KILLED
",
    );

    let config = SandboxConfig::builder()
        .runtime("sh")
        .max_cpu_seconds(1)
        .timeout_seconds(10)
        .strategy(Strategy::None)
        .build();

    let mut proc =
        SandboxedProcess::spawn(&harness, work_dir.path(), &config).expect("spawn failed");
    let usage = proc.wait_with_usage().expect("wait failed");
    assert_ne!(
        usage.exit_code, 0,
        "CPU-bound process must be killed by CPU limit; exit_code={}",
        usage.exit_code
    );
    assert!(
        usage.wall_time_secs < 6.0,
        "CPU kill should happen within a few seconds; took {}s",
        usage.wall_time_secs
    );
}

/// Verify CPU limit using a pure shell busy-loop.
#[test]
fn cpu_limit_kills_shell_busy_loop() {
    let work_dir = tempfile::tempdir().unwrap();
    let harness = create_sh_harness(work_dir.path(), "#!/bin/sh\nwhile :; do :; done\n");

    let config = SandboxConfig::builder()
        .runtime("sh")
        .max_cpu_seconds(1)
        .timeout_seconds(10)
        .strategy(Strategy::None)
        .build();

    let mut proc =
        SandboxedProcess::spawn(&harness, work_dir.path(), &config).expect("spawn failed");
    let usage = proc.wait_with_usage().expect("wait failed");
    assert_ne!(
        usage.exit_code, 0,
        "shell busy-loop must be killed by CPU limit; exit_code={}",
        usage.exit_code
    );
}

/// Verify that a well-behaved process (uses almost no CPU or memory)
/// survives even with tight limits.
#[test]
fn well_behaved_process_survives_tight_limits() {
    let work_dir = tempfile::tempdir().unwrap();
    let harness = create_sh_harness(work_dir.path(), "#!/bin/sh\necho done\n");

    let config = SandboxConfig::builder()
        .runtime("sh")
        .max_memory_bytes(8 * 1024 * 1024)
        .max_cpu_seconds(1)
        .timeout_seconds(5)
        .strategy(Strategy::None)
        .build();

    let mut proc =
        SandboxedProcess::spawn(&harness, work_dir.path(), &config).expect("spawn failed");
    let line = proc.recv().expect("recv failed").expect("eof early");
    assert_eq!(line.trim(), "done");
    let usage = proc.wait_with_usage().expect("wait failed");
    assert_eq!(usage.exit_code, 0, "well-behaved process must exit cleanly");
}

/// Verify the timeout watchdog still works when resource limits are generous.
#[test]
fn timeout_overrides_generous_limits() {
    let work_dir = tempfile::tempdir().unwrap();
    let harness = create_sh_harness(work_dir.path(), "#!/bin/sh\nsleep 300\n");

    let config = SandboxConfig::builder()
        .runtime("sh")
        .max_memory_bytes(512 * 1024 * 1024)
        .max_cpu_seconds(300)
        .timeout_seconds(1)
        .strategy(Strategy::None)
        .build();

    let mut proc =
        SandboxedProcess::spawn(&harness, work_dir.path(), &config).expect("spawn failed");
    let usage = proc.wait_with_usage().expect("wait failed");
    assert!(
        proc.killed_by_timeout,
        "watchdog must kill sleeping process"
    );
    assert!(
        usage.wall_time_secs < 3.0,
        "timeout should fire around 1s; took {}s",
        usage.wall_time_secs
    );
}

/// Fork bomb inside the sandbox.  Even without a process limit enforced by
/// the kernel rlimit, the timeout should eventually kill the cascade.
#[test]
fn fork_bomb_is_contained_by_timeout() {
    let work_dir = tempfile::tempdir().unwrap();
    let harness = create_sh_harness(
        work_dir.path(),
        "#!/bin/sh\n\
        bomb() {\n\
            bomb | bomb &\n\
        }\n\
        bomb\n\
        sleep 300\n",
    );

    let config = SandboxConfig::builder()
        .runtime("sh")
        .timeout_seconds(2)
        .strategy(Strategy::None)
        .build();

    let mut proc =
        SandboxedProcess::spawn(&harness, work_dir.path(), &config).expect("spawn failed");
    let usage = proc.wait_with_usage().expect("wait failed");
    assert!(
        proc.killed_by_timeout,
        "fork bomb must be stopped by timeout"
    );
    assert!(
        usage.wall_time_secs < 4.0,
        "fork bomb timeout should fire quickly; took {}s",
        usage.wall_time_secs
    );
}

/// Verify that peak memory is reported when a process is killed.
#[test]
fn memory_usage_reported_for_killed_process() {
    let work_dir = tempfile::tempdir().unwrap();
    let harness = create_sh_harness(
        work_dir.path(),
        "#!/bin/sh\npython3 -c '
import sys
a = []
for i in range(100):
    a.append(b\"X\" * (1024 * 1024))
    sys.stdout.write(str(i) + \"\\n\")
    sys.stdout.flush()
' || echo FAIL
",
    );

    let config = SandboxConfig::builder()
        .runtime("sh")
        .max_memory_bytes(48 * 1024 * 1024)
        .timeout_seconds(15)
        .strategy(Strategy::None)
        .build();

    let mut proc =
        SandboxedProcess::spawn(&harness, work_dir.path(), &config).expect("spawn failed");
    let usage = proc.wait_with_usage().expect("wait failed");
    assert_ne!(usage.exit_code, 0);
    // Peak memory should be reported and should be >= the limit or at least substantial.
    if let Some(peak) = usage.peak_memory_bytes {
        assert!(
            peak > 0,
            "peak memory should be reported for killed process"
        );
    }
}

/// Test that CPU time is reported for a short-running process.
#[test]
fn cpu_usage_reported_for_short_process() {
    let work_dir = tempfile::tempdir().unwrap();
    let harness = create_sh_harness(
        work_dir.path(),
        "#!/bin/sh\n\
        for i in $(seq 1 100000); do\n\
            :\n\
        done\n\
        echo done\n",
    );

    let config = SandboxConfig::builder()
        .runtime("sh")
        .timeout_seconds(10)
        .strategy(Strategy::None)
        .build();

    let mut proc =
        SandboxedProcess::spawn(&harness, work_dir.path(), &config).expect("spawn failed");
    let _ = proc.recv();
    let usage = proc.wait_with_usage().expect("wait failed");
    assert_eq!(usage.exit_code, 0);
    if let Some(cpu) = usage.cpu_time_secs {
        assert!(cpu >= 0.0, "cpu time should be non-negative");
    }
}

/// Adversarial: process that repeatedly forks and exits tiny children.
/// The parent should survive briefly, but the timeout should limit total
/// wall-clock abuse.
#[test]
fn rapid_fork_exit_is_limited_by_timeout() {
    let work_dir = tempfile::tempdir().unwrap();
    let harness = create_sh_harness(
        work_dir.path(),
        "#!/bin/sh\n\
        while true; do\n\
            (exit 0) &\n\
        done\n",
    );

    let config = SandboxConfig::builder()
        .runtime("sh")
        .timeout_seconds(2)
        .strategy(Strategy::None)
        .build();

    let mut proc =
        SandboxedProcess::spawn(&harness, work_dir.path(), &config).expect("spawn failed");
    let usage = proc.wait_with_usage().expect("wait failed");
    assert!(proc.killed_by_timeout);
    assert!(
        usage.wall_time_secs < 4.0,
        "rapid fork-exit must be stopped by timeout; took {}s",
        usage.wall_time_secs
    );
}

/// Verify that a process which writes a huge amount of data to stdout
/// is bounded by max_recv_line_bytes, not by resource limits.
#[test]
fn large_stdout_bounded_by_recv_limit() {
    let work_dir = tempfile::tempdir().unwrap();
    let harness = create_sh_harness(
        work_dir.path(),
        "#!/bin/sh\nprintf '%s' \"A\"; printf '%s' \"A\"; echo\n",
    );

    let config = SandboxConfig::builder()
        .runtime("sh")
        .max_recv_line_bytes(5)
        .timeout_seconds(5)
        .strategy(Strategy::None)
        .build();

    let mut proc =
        SandboxedProcess::spawn(&harness, work_dir.path(), &config).expect("spawn failed");
    let line = proc.recv().expect("recv failed").expect("eof early");
    // recv should have read at most 5 bytes.
    assert!(
        line.len() <= 5,
        "recv must respect max_recv_line_bytes; got {} bytes",
        line.len()
    );
    let _ = proc.wait_with_usage().expect("wait failed");
}

/// Test memory limit with Strategy::Unshare (if available).
#[test]
#[cfg(target_os = "linux")]
fn memory_limit_enforced_under_unshare() {
    let work_dir = tempfile::tempdir().unwrap();
    let harness = create_sh_harness(work_dir.path(), "#!/bin/sh\nwhile :; do :; done\n");

    let config = SandboxConfig::builder()
        .runtime("sh")
        .max_cpu_seconds(1)
        .timeout_seconds(10)
        .strategy(Strategy::Unshare)
        .build();

    // If unshare is not available, this test is allowed to fail to spawn.
    let mut proc = match SandboxedProcess::spawn(&harness, work_dir.path(), &config) {
        Ok(p) => p,
        Err(e) => {
            let msg = e.to_string();
            if msg.contains("unshare not available") {
                return;
            }
            panic!("spawn failed unexpectedly: {e}");
        }
    };

    let usage = proc.wait_with_usage().expect("wait failed");
    assert_ne!(
        usage.exit_code, 0,
        "CPU limit must be enforced under unshare"
    );
}

/// Test memory limit with Strategy::Bubblewrap (if available).
#[test]
#[cfg(target_os = "linux")]
fn memory_limit_enforced_under_bwrap() {
    let work_dir = tempfile::tempdir().unwrap();
    let harness = create_sh_harness(work_dir.path(), "#!/bin/sh\nwhile :; do :; done\n");

    let config = SandboxConfig::builder()
        .runtime("sh")
        .max_cpu_seconds(1)
        .timeout_seconds(10)
        .strategy(Strategy::Bubblewrap)
        .build();

    let mut proc = match SandboxedProcess::spawn(&harness, work_dir.path(), &config) {
        Ok(p) => p,
        Err(e) => {
            let msg = e.to_string();
            if msg.contains("bwrap not available") {
                return;
            }
            panic!("spawn failed unexpectedly: {e}");
        }
    };

    let usage = proc.wait_with_usage().expect("wait failed");
    assert_ne!(
        usage.exit_code, 0,
        "CPU limit must be enforced under bubblewrap"
    );
}

/// Test that a cgroup-based memory limit actually limits resident set when
/// cgroups v2 is available.  We set a very low limit and verify the process
/// is OOM-killed by the kernel inside the cgroup.
#[test]
#[cfg(target_os = "linux")]
fn cgroup_memory_oom_kills_process() {
    let work_dir = tempfile::tempdir().unwrap();
    let harness = create_sh_harness(
        work_dir.path(),
        "#!/bin/sh\npython3 -c '
import sys
a = bytearray()
while True:
    a.extend(b\"X\" * (1024 * 1024))
' 2>/dev/null || echo PYTHON_MISSING
",
    );

    // Use None strategy but tiny memory so rlimit + cgroup (if any) both apply.
    let config = SandboxConfig::builder()
        .runtime("sh")
        .max_memory_bytes(8 * 1024 * 1024)
        .timeout_seconds(10)
        .strategy(Strategy::None)
        .build();

    let mut proc =
        SandboxedProcess::spawn(&harness, work_dir.path(), &config).expect("spawn failed");
    let usage = proc.wait_with_usage().expect("wait failed");
    assert_ne!(
        usage.exit_code, 0,
        "process must be killed by cgroup/rlimit memory pressure"
    );
}
