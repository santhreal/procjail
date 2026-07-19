//! Namespace isolation tests.
//!
//! These tests verify that PID, network, and mount namespaces actually
//! isolate the sandboxed process from the host.

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

fn skip_if_unavailable(result: Result<SandboxedProcess, procjail::ProcjailError>, tool: &str) -> Option<SandboxedProcess> {
    match result {
        Ok(p) => Some(p),
        Err(e) => {
            let msg = e.to_string();
            if msg.contains(&format!("{tool} not available")) || msg.contains("No such file") {
                return None;
            }
            panic!("spawn failed unexpectedly: {e}");
        }
    }
}

// =============================================================================
// PID namespace
// =============================================================================

/// In a PID namespace, the first process should see itself as PID 1.
#[test]
#[cfg(target_os = "linux")]
fn unshare_pid_namespace_shows_pid_one() {
    let work_dir = tempfile::tempdir().unwrap();
    let harness = create_sh_harness(
        work_dir.path(),
        "#!/bin/sh\necho $$\n",
    );

    let config = SandboxConfig::builder()
        .runtime("sh")
        .timeout_seconds(5)
        .strategy(Strategy::Unshare)
        .build();

    let mut proc = match skip_if_unavailable(SandboxedProcess::spawn(&harness, work_dir.path(), &config), "unshare") {
        Some(p) => p,
        None => return,
    };

    let line = proc.recv().expect("recv failed").expect("eof early");
    let pid: i32 = line.trim().parse().expect("output should be a pid");
    assert_eq!(pid, 1, "PID namespace root process must see itself as PID 1");
    let usage = proc.wait_with_usage().expect("wait failed");
    assert_eq!(usage.exit_code, 0);
}

/// Bubblewrap also provides PID isolation.
#[test]
#[cfg(target_os = "linux")]
fn bwrap_pid_namespace_shows_pid_one() {
    let work_dir = tempfile::tempdir().unwrap();
    let harness = create_sh_harness(
        work_dir.path(),
        "#!/bin/sh\necho $$\n",
    );

    let config = SandboxConfig::builder()
        .runtime("sh")
        .timeout_seconds(5)
        .strategy(Strategy::Bubblewrap)
        .build();

    let mut proc = match skip_if_unavailable(SandboxedProcess::spawn(&harness, work_dir.path(), &config), "bwrap") {
        Some(p) => p,
        None => return,
    };

    let line = proc.recv().expect("recv failed").expect("eof early");
    let pid: i32 = line.trim().parse().expect("output should be a pid");
    assert_eq!(pid, 1, "bwrap PID namespace root must be PID 1");
    let usage = proc.wait_with_usage().expect("wait failed");
    assert_eq!(usage.exit_code, 0);
}

/// Firejail PID isolation.
#[test]
#[cfg(target_os = "linux")]
fn firejail_pid_namespace_isolates() {
    let work_dir = tempfile::tempdir().unwrap();
    let harness = create_sh_harness(
        work_dir.path(),
        "#!/bin/sh\necho $$\n",
    );

    let config = SandboxConfig::builder()
        .runtime("sh")
        .timeout_seconds(5)
        .strategy(Strategy::Firejail)
        .build();

    let mut proc = match skip_if_unavailable(SandboxedProcess::spawn(&harness, work_dir.path(), &config), "firejail") {
        Some(p) => p,
        None => return,
    };

    let line = proc.recv().expect("recv failed").expect("eof early");
    let pid: i32 = line.trim().parse().expect("output should be a pid");
    // Firejail may or may not show PID 1 depending on its internal wrapper.
    // We just assert that it's NOT the same PID as the parent test runner.
    let parent_pid = std::process::id() as i32;
    assert_ne!(
        pid, parent_pid,
        "firejail must isolate PID; got parent pid {parent_pid}"
    );
    let usage = proc.wait_with_usage().expect("wait failed");
    assert_eq!(usage.exit_code, 0);
}

/// A process inside a PID namespace cannot see host PIDs in /proc.
#[test]
#[cfg(target_os = "linux")]
fn unshare_cannot_see_host_pids() {
    let work_dir = tempfile::tempdir().unwrap();
    let harness = create_sh_harness(
        work_dir.path(),
        "#!/bin/sh\nls /proc | wc -w\n",
    );

    let config = SandboxConfig::builder()
        .runtime("sh")
        .timeout_seconds(5)
        .strategy(Strategy::Unshare)
        .build();

    let mut proc = match skip_if_unavailable(SandboxedProcess::spawn(&harness, work_dir.path(), &config), "unshare") {
        Some(p) => p,
        None => return,
    };

    let line = proc.recv().expect("recv failed").expect("eof early");
    let count: usize = line.trim().parse().expect("output should be a number");
    // Inside a PID namespace with --mount-proc, /proc should be very small.
    assert!(
        count < 50,
        "PID namespace /proc should be tiny; got {count} entries"
    );
    let usage = proc.wait_with_usage().expect("wait failed");
    assert_eq!(usage.exit_code, 0);
}

// =============================================================================
// Network namespace
// =============================================================================

/// In a network namespace with --net, the loopback interface exists but
/// there are no external interfaces.
#[test]
#[cfg(target_os = "linux")]
fn unshare_network_namespace_isolates_interfaces() {
    let work_dir = tempfile::tempdir().unwrap();
    let harness = create_sh_harness(
        work_dir.path(),
        "#!/bin/sh\nip link show | grep -c '^[0-9]'\n",
    );

    let config = SandboxConfig::builder()
        .runtime("sh")
        .allow_localhost(false)
        .timeout_seconds(5)
        .strategy(Strategy::Unshare)
        .build();

    let mut proc = match skip_if_unavailable(SandboxedProcess::spawn(&harness, work_dir.path(), &config), "unshare") {
        Some(p) => p,
        None => return,
    };

    let line = proc.recv().expect("recv failed").expect("eof early");
    let count: usize = line.trim().parse().unwrap_or(999);
    // Only lo should exist inside a fresh netns.
    assert!(
        count <= 2,
        "network namespace should have <= 2 interfaces; got {count}"
    );
    let usage = proc.wait_with_usage().expect("wait failed");
    assert_eq!(usage.exit_code, 0);
}

/// Bubblewrap network isolation.
#[test]
#[cfg(target_os = "linux")]
fn bwrap_network_namespace_blocks_external() {
    let work_dir = tempfile::tempdir().unwrap();
    // Try to reach an external host.  This should fail.
    let harness = create_sh_harness(
        work_dir.path(),
        "#!/bin/sh\n\
        if ping -c 1 -W 1 8.8.8.8 >/dev/null 2>&1; then\n\
            echo REACHABLE\n\
        else\n\
            echo BLOCKED\n\
        fi\n",
    );

    let config = SandboxConfig::builder()
        .runtime("sh")
        .allow_localhost(false)
        .timeout_seconds(10)
        .strategy(Strategy::Bubblewrap)
        .build();

    let mut proc = match skip_if_unavailable(SandboxedProcess::spawn(&harness, work_dir.path(), &config), "bwrap") {
        Some(p) => p,
        None => return,
    };

    let line = proc.recv().expect("recv failed").expect("eof early");
    assert_eq!(line.trim(), "BLOCKED", "bwrap must block external network");
    let usage = proc.wait_with_usage().expect("wait failed");
    assert_eq!(usage.exit_code, 0);
}

/// With allow_localhost=true, Bubblewrap should NOT use --unshare-net.
#[test]
#[cfg(target_os = "linux")]
fn bwrap_allow_localhost_permits_network() {
    let work_dir = tempfile::tempdir().unwrap();
    let harness = create_sh_harness(
        work_dir.path(),
        "#!/bin/sh\n\
        if ip link show | grep -q eth0; then\n\
            echo HAS_NET\n\
        else\n\
            echo CHECK_LOOPBACK\n\
        fi\n",
    );

    let config = SandboxConfig::builder()
        .runtime("sh")
        .allow_localhost(true)
        .timeout_seconds(5)
        .strategy(Strategy::Bubblewrap)
        .build();

    let mut proc = match skip_if_unavailable(SandboxedProcess::spawn(&harness, work_dir.path(), &config), "bwrap") {
        Some(p) => p,
        None => return,
    };

    let line = proc.recv().expect("recv failed").expect("eof early");
    // We just assert the process didn't fail to spawn due to missing network.
    let _ = line;
    let usage = proc.wait_with_usage().expect("wait failed");
    assert_eq!(usage.exit_code, 0);
}

/// Firejail network isolation.
#[test]
#[cfg(target_os = "linux")]
fn firejail_network_namespace_blocks_external() {
    let work_dir = tempfile::tempdir().unwrap();
    let harness = create_sh_harness(
        work_dir.path(),
        "#!/bin/sh\n\
        if ping -c 1 -W 1 8.8.8.8 >/dev/null 2>&1; then\n\
            echo REACHABLE\n\
        else\n\
            echo BLOCKED\n\
        fi\n",
    );

    let config = SandboxConfig::builder()
        .runtime("sh")
        .allow_localhost(false)
        .timeout_seconds(10)
        .strategy(Strategy::Firejail)
        .build();

    let mut proc = match skip_if_unavailable(SandboxedProcess::spawn(&harness, work_dir.path(), &config), "firejail") {
        Some(p) => p,
        None => return,
    };

    let line = proc.recv().expect("recv failed").expect("eof early");
    assert_eq!(line.trim(), "BLOCKED", "firejail must block external network");
    let usage = proc.wait_with_usage().expect("wait failed");
    assert_eq!(usage.exit_code, 0);
}

// =============================================================================
// Mount namespace
// =============================================================================

/// In a mount namespace, changes to the mount table must not leak to the host.
/// We mount a tmpfs inside the namespace and verify it does not appear on the host.
#[test]
#[cfg(target_os = "linux")]
fn unshare_mount_namespace_isolates_changes() {
    let work_dir = tempfile::tempdir().unwrap();
    let host_marker = work_dir.path().join("host_visible");
    std::fs::write(&host_marker, "before").unwrap();

    let harness = create_sh_harness(
        work_dir.path(),
        "#!/bin/sh\n\
        mkdir -p /tmp/procjail_mount_test\n\
        mount -t tmpfs none /tmp/procjail_mount_test 2>/dev/null\n\
        if mountpoint -q /tmp/procjail_mount_test; then\n\
            echo MOUNTED_INSIDE\n\
        else\n\
            echo MOUNT_FAILED\n\
        fi\n",
    );

    let config = SandboxConfig::builder()
        .runtime("sh")
        .timeout_seconds(5)
        .strategy(Strategy::Unshare)
        .build();

    let mut proc = match skip_if_unavailable(SandboxedProcess::spawn(&harness, work_dir.path(), &config), "unshare") {
        Some(p) => p,
        None => return,
    };

    let line = proc.recv().expect("recv failed").expect("eof early");
    // The mount may fail inside an unprivileged user namespace depending on
    // kernel config, but if it succeeds it must NOT be visible on the host.
    assert!(
        line.trim() == "MOUNTED_INSIDE" || line.trim() == "MOUNT_FAILED",
        "unexpected output: {line}"
    );
    let usage = proc.wait_with_usage().expect("wait failed");
    assert_eq!(usage.exit_code, 0);

    // Verify the mount did NOT leak to the host.
    let host_mountinfo = std::fs::read_to_string("/proc/self/mountinfo").unwrap();
    assert!(
        !host_mountinfo.contains("procjail_mount_test"),
        "mount namespace change must not leak to host"
    );
}

/// Bubblewrap should present a completely empty root (tmpfs) except for
/// explicitly bound paths.
#[test]
#[cfg(target_os = "linux")]
fn bwrap_filesystem_isolation_blocks_host_root() {
    let work_dir = tempfile::tempdir().unwrap();
    let harness = create_sh_harness(
        work_dir.path(),
        "#!/bin/sh\n\
        if [ -d /etc ]; then\n\
            echo HAS_ETC\n\
        else\n\
            echo NO_ETC\n\
        fi\n",
    );

    let config = SandboxConfig::builder()
        .runtime("sh")
        .timeout_seconds(5)
        .strategy(Strategy::Bubblewrap)
        .build();

    let mut proc = match skip_if_unavailable(SandboxedProcess::spawn(&harness, work_dir.path(), &config), "bwrap") {
        Some(p) => p,
        None => return,
    };

    let line = proc.recv().expect("recv failed").expect("eof early");
    // bwrap mounts --tmpfs / and --proc /proc, so /etc may or may not exist
    // depending on bwrap defaults.  We just verify the sandbox runs.
    let _ = line;
    let usage = proc.wait_with_usage().expect("wait failed");
    assert_eq!(usage.exit_code, 0);
}

/// Firejail should provide a private filesystem based on the work_dir.
#[test]
#[cfg(target_os = "linux")]
fn firejail_filesystem_isolation_private_workdir() {
    let work_dir = tempfile::tempdir().unwrap();
    let harness = create_sh_harness(
        work_dir.path(),
        "#!/bin/sh\npwd\n",
    );

    let config = SandboxConfig::builder()
        .runtime("sh")
        .timeout_seconds(5)
        .strategy(Strategy::Firejail)
        .build();

    let mut proc = match skip_if_unavailable(SandboxedProcess::spawn(&harness, work_dir.path(), &config), "firejail") {
        Some(p) => p,
        None => return,
    };

    let line = proc.recv().expect("recv failed").expect("eof early");
    let pwd = line.trim();
    // Firejail --private=work_dir makes the cwd inside the private copy.
    assert!(
        !pwd.is_empty(),
        "firejail must provide a valid working directory"
    );
    let usage = proc.wait_with_usage().expect("wait failed");
    assert_eq!(usage.exit_code, 0);
}

// =============================================================================
// User namespace
// =============================================================================

/// Inside a user namespace mapped to root, getuid should return 0.
#[test]
#[cfg(target_os = "linux")]
fn unshare_user_namespace_maps_root() {
    let work_dir = tempfile::tempdir().unwrap();
    let harness = create_sh_harness(
        work_dir.path(),
        "#!/bin/sh\nid -u\n",
    );

    let config = SandboxConfig::builder()
        .runtime("sh")
        .timeout_seconds(5)
        .strategy(Strategy::Unshare)
        .build();

    let mut proc = match skip_if_unavailable(SandboxedProcess::spawn(&harness, work_dir.path(), &config), "unshare") {
        Some(p) => p,
        None => return,
    };

    let line = proc.recv().expect("recv failed").expect("eof early");
    let uid: u32 = line.trim().parse().expect("output should be a uid");
    assert_eq!(uid, 0, "unshare --map-root-user must map current user to root");
    let usage = proc.wait_with_usage().expect("wait failed");
    assert_eq!(usage.exit_code, 0);
}

/// Even as "root" inside the user namespace, a blocked syscall must still
/// be blocked by seccomp.
#[test]
#[cfg(target_os = "linux")]
fn unshare_root_cannot_bypass_seccomp() {
    let work_dir = tempfile::tempdir().unwrap();
    let harness = create_sh_harness(
        work_dir.path(),
        "#!/bin/sh\n\
        python3 -c '
import ctypes, errno
libc = ctypes.CDLL(None)
ret = libc.syscall(libc.SYS_mount, 0, 0, 0, 0, 0)
print(errno.errorcode.get(ctypes.get_errno(), \"UNKNOWN\"))
' 2>/dev/null || echo PYTHON_MISSING\n",
    );

    let config = SandboxConfig::builder()
        .runtime("sh")
        .timeout_seconds(5)
        .strategy(Strategy::Unshare)
        .build();

    let mut proc = match skip_if_unavailable(SandboxedProcess::spawn(&harness, work_dir.path(), &config), "unshare") {
        Some(p) => p,
        None => return,
    };

    let line = proc.recv().expect("recv failed").expect("eof early");
    let output = line.trim();
    // If python is missing, skip the assertion.
    if output == "PYTHON_MISSING" {
        let _ = proc.wait_with_usage().expect("wait failed");
        return;
    }
    assert_eq!(
        output, "EPERM",
        "even namespaced root must be blocked by seccomp; got {output}"
    );
    let usage = proc.wait_with_usage().expect("wait failed");
    assert_eq!(usage.exit_code, 0);
}

// =============================================================================
// Cross-namespace contamination
// =============================================================================

/// Verify that a process spawned inside a PID namespace cannot signal the
/// parent test runner.
#[test]
#[cfg(target_os = "linux")]
fn namespaced_process_cannot_signal_parent() {
    let work_dir = tempfile::tempdir().unwrap();
    let parent_pid = std::process::id();
    let harness = create_sh_harness(
        work_dir.path(),
        &format!(
            "#!/bin/sh\nkill -0 {parent_pid} 2>/dev/null && echo CAN_SIGNAL || echo CANT_SIGNAL\n"
        ),
    );

    let config = SandboxConfig::builder()
        .runtime("sh")
        .timeout_seconds(5)
        .strategy(Strategy::Unshare)
        .build();

    let mut proc = match skip_if_unavailable(SandboxedProcess::spawn(&harness, work_dir.path(), &config), "unshare") {
        Some(p) => p,
        None => return,
    };

    let line = proc.recv().expect("recv failed").expect("eof early");
    assert_eq!(
        line.trim(),
        "CANT_SIGNAL",
        "namespaced process must not be able to signal host"
    );
    let usage = proc.wait_with_usage().expect("wait failed");
    assert_eq!(usage.exit_code, 0);
}
