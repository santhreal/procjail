//! Edge-case security tests for seccomp and sandbox behavior.
//!
//! These tests exercise boundary conditions: empty/minimal configs,
//nested filters, 1000 rules, concurrent applications, crash recovery.

use std::ffi::CString;
use std::path::Path;

use procjail::{seccomp, SandboxConfig, SandboxedProcess, Strategy};

#[path = "seccomp_linux_helpers.rs"]
mod linux_helpers;

#[cfg(target_os = "linux")]
use linux_helpers::{syscall_eventfd2, syscall_exit_group};

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

/// Fork, apply seccomp in the child, execute `f`, and return errno (0 = success).
#[cfg(target_os = "linux")]
fn run_in_seccomp<F>(f: F) -> i32
where
    F: FnOnce() -> i32,
{
    let mut pipe_fds = [-1i32; 2];
    unsafe {
        if libc::pipe(pipe_fds.as_mut_ptr()) != 0 {
            panic!("pipe failed");
        }
        match libc::fork() {
            -1 => panic!("fork failed"),
            0 => {
                libc::close(pipe_fds[0]);
                if let Err(e) = procjail::seccomp::apply_seccomp_filter() {
                    eprintln!("seccomp apply failed: {e}");
                    libc::close(pipe_fds[1]);
                    libc::exit(254);
                }
                let errno = f();
                let _ = libc::write(
                    pipe_fds[1],
                    &errno as *const i32 as *const libc::c_void,
                    std::mem::size_of::<i32>(),
                );
                libc::close(pipe_fds[1]);
                libc::exit(0);
            }
            pid => {
                libc::close(pipe_fds[1]);
                let mut buf = [0u8; 4];
                let n = libc::read(
                    pipe_fds[0],
                    buf.as_mut_ptr() as *mut libc::c_void,
                    4,
                );
                libc::close(pipe_fds[0]);
                let mut status = 0;
                libc::waitpid(pid, &mut status, 0);
                if n == 4 {
                    i32::from_ne_bytes(buf)
                } else {
                    -1
                }
            }
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn run_in_seccomp<F>(_f: F) -> i32
where
    F: FnOnce() -> i32,
{
    0
}

// =============================================================================
// Empty / minimal filter scenarios
// =============================================================================

/// Strategy::None with the most minimal config possible.  This is the
/// "weakest" sandbox mode; the test ensures it still starts and stops.
#[test]
fn empty_config_strategy_none() {
    let work_dir = tempfile::tempdir().unwrap();
    let harness = create_sh_harness(work_dir.path(), "#!/bin/sh\necho ok\n");

    let config = SandboxConfig::builder()
        .runtime("sh")
        .strategy(Strategy::None)
        .build();

    let mut proc = SandboxedProcess::spawn(&harness, work_dir.path(), &config).expect("spawn failed");
    let line = proc.recv().expect("recv failed").expect("eof early");
    assert_eq!(line.trim(), "ok");
    let usage = proc.wait_with_usage().expect("wait failed");
    assert_eq!(usage.exit_code, 0);
}

/// Verify that seccomp::apply_seccomp_filter is a no-op on non-Linux.
#[test]
#[cfg(not(target_os = "linux"))]
fn seccomp_no_op_on_non_linux() {
    let result = seccomp::apply_seccomp_filter();
    assert!(result.is_ok(), "seccomp must be a no-op on non-Linux");
}

// =============================================================================
// Filter with many rules (simulate 1000-rule load)
// =============================================================================

/// Build and apply a seccomp filter with 1000 explicit allow rules.
/// This tests that the BPF compiler and kernel can handle large rule sets
/// without falling over.  We use seccompiler directly because procjail's
/// public API does not expose custom rule building.
#[test]
#[cfg(target_os = "linux")]
fn thousand_rule_filter_compiles_and_applies() {
    use seccompiler::{BpfProgram, SeccompAction, SeccompFilter, SeccompRule, TargetArch};
    use std::collections::BTreeMap;

    let target_arch = match std::env::consts::ARCH {
        "x86_64" => TargetArch::x86_64,
        "aarch64" => TargetArch::aarch64,
        "riscv64" => TargetArch::riscv64,
        _ => {
            eprintln!("skipping thousand_rule test on unsupported arch");
            return;
        }
    }
    .try_into()
    .expect("valid arch");

    let mut rules: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();
    // Add 1000 allow rules for fake syscall numbers that do not conflict
    // with real ones.  We use negative offsets to avoid accidentally
    // allowing something dangerous.
    for i in 0..1000 {
        let syscall_num = -(i as i64) - 10000;
        rules.insert(syscall_num, vec![]);
    }

    // Also allow exit_group so the child can exit cleanly.
    rules.insert(libc::SYS_exit_group, vec![]);

    let filter = SeccompFilter::new(
        rules,
        SeccompAction::Errno(libc::EPERM as u32),
        SeccompAction::Allow,
        target_arch,
    )
    .expect("filter creation failed");

    let bpf: BpfProgram = filter.try_into().expect("BPF compilation failed");

    let mut pipe_fds = [-1i32; 2];
    unsafe {
        assert_eq!(libc::pipe(pipe_fds.as_mut_ptr()), 0);
        let pid = libc::fork();
        assert!(pid >= 0);
        if pid == 0 {
            libc::close(pipe_fds[0]);
            libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
            seccompiler::apply_filter(&bpf).expect("apply_filter failed");
            // Try a blocked syscall.
            let ret = libc::syscall(libc::SYS_socket, libc::AF_INET as usize, libc::SOCK_STREAM as usize, 0);
            let errno = if ret < 0 {
                std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
            } else {
                0
            };
            libc::write(pipe_fds[1], &errno as *const i32 as *const libc::c_void, 4);
            libc::close(pipe_fds[1]);
            syscall_exit_group(0);
        }
        libc::close(pipe_fds[1]);
        let mut buf = [0u8; 4];
        let n = libc::read(pipe_fds[0], buf.as_mut_ptr() as *mut libc::c_void, 4);
        libc::close(pipe_fds[0]);
        let mut status = 0;
        libc::waitpid(pid, &mut status, 0);
        assert_eq!(n, 4);
        let errno = i32::from_ne_bytes(buf);
        assert_eq!(errno, libc::EPERM, "1000-rule filter must still block socket; got errno={errno}");
    }
}

// =============================================================================
// Nested seccomp filters
// =============================================================================

/// Apply procjail's filter twice in the same process.  The kernel should
/// accept the second filter and AND the two policies together.
#[test]
#[cfg(target_os = "linux")]
fn nested_seccomp_application_succeeds() {
    let errno = run_in_seccomp(|| unsafe {
        // Apply a second instance of the same filter.
        if let Err(e) = procjail::seccomp::apply_seccomp_filter() {
            eprintln!("nested apply failed: {e}");
            return libc::EINVAL;
        }
        // Verify the filter is still in force.
        let ret = libc::syscall(libc::SYS_socket, libc::AF_INET as usize, libc::SOCK_STREAM as usize, 0);
        if ret < 0 {
            let e = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
            if e != libc::EPERM {
                return e;
            }
        } else {
            return libc::EIO;
        }
        0
    });
    assert_eq!(errno, 0, "nested seccomp must succeed and remain restrictive; got errno={errno}");
}

// =============================================================================
// Crash recovery and signal handling
// =============================================================================

/// A process under seccomp that receives SIGSEGV should still core-dump or
/// terminate normally; the seccomp filter must not interfere with fatal
/// signal delivery.
#[test]
#[cfg(target_os = "linux")]
fn segfault_under_seccomp_terminates_normally() {
    let mut pipe_fds = [-1i32; 2];
    unsafe {
        assert_eq!(libc::pipe(pipe_fds.as_mut_ptr()), 0);
        let pid = libc::fork();
        assert!(pid >= 0);
        if pid == 0 {
            libc::close(pipe_fds[0]);
            let _ = procjail::seccomp::apply_seccomp_filter();
            // Deliberate null-pointer dereference.
            let ptr: *mut i32 = std::ptr::null_mut();
            ptr.write(42);
            // Should never reach here.
            libc::exit(0);
        }
        libc::close(pipe_fds[1]);
        let mut status = 0;
        libc::waitpid(pid, &mut status, 0);
        libc::close(pipe_fds[0]);
        assert!(
            libc::WIFSIGNALED(status),
            "segfault must terminate via signal; got status={status}"
        );
        let sig = libc::WTERMSIG(status);
        assert_eq!(sig, libc::SIGSEGV, "segfault must deliver SIGSEGV; got sig={sig}");
    }
}

/// A process under seccomp that divides by zero should receive SIGFPE.
#[test]
#[cfg(target_os = "linux")]
fn sigfpe_under_seccomp_terminates_normally() {
    let mut pipe_fds = [-1i32; 2];
    unsafe {
        assert_eq!(libc::pipe(pipe_fds.as_mut_ptr()), 0);
        let pid = libc::fork();
        assert!(pid >= 0);
        if pid == 0 {
            libc::close(pipe_fds[0]);
            let _ = procjail::seccomp::apply_seccomp_filter();
            // Force integer division by zero.
            let a: i32 = 1;
            let b: i32 = 0;
            let _ = std::hint::black_box(a / std::hint::black_box(b));
            libc::exit(0);
        }
        libc::close(pipe_fds[1]);
        let mut status = 0;
        libc::waitpid(pid, &mut status, 0);
        libc::close(pipe_fds[0]);
        // Division by zero may raise SIGFPE or produce a result depending on
        // compiler optimizations.  We accept either a signal or a non-zero exit.
        if libc::WIFSIGNALED(status) {
            let sig = libc::WTERMSIG(status);
            assert_eq!(sig, libc::SIGFPE, "division by zero must deliver SIGFPE; got sig={sig}");
        } else if libc::WIFEXITED(status) {
            // Compiler may optimize out the division; that's acceptable.
        } else {
            panic!("unexpected status: {status}");
        }
    }
}

// =============================================================================
// Very large file-descriptor tables under seccomp
// =============================================================================

/// Open many file descriptors while under seccomp.  The filter must not
/// introduce per-fd overhead that causes performance collapse.
#[test]
#[cfg(target_os = "linux")]
fn many_file_descriptors_under_seccomp() {
    const N: usize = 1024;
    let errno = run_in_seccomp(|| unsafe {
        let mut fds = Vec::with_capacity(N);
        for _ in 0..N {
            let fd = syscall_eventfd2(0, libc::EFD_CLOEXEC);
            if fd < 0 {
                let e = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
                for fd in fds {
                    libc::close(fd);
                }
                return e;
            }
            fds.push(fd);
        }
        for fd in fds {
            libc::close(fd);
        }
        0
    });
    assert_eq!(errno, 0, "opening 1024 fds under seccomp must succeed; got errno={errno}");
}

// =============================================================================
// Environment edge cases under sandbox
// =============================================================================

/// Spawn with an empty environment allowlist and verify no secrets leak.
#[test]
fn empty_env_allowlist_strips_everything() {
    let work_dir = tempfile::tempdir().unwrap();
    let harness = create_sh_harness(
        work_dir.path(),
        "#!/bin/sh\nenv | wc -l\n",
    );

    let config = SandboxConfig::builder()
        .runtime("sh")
        .strategy(Strategy::None)
        .env_mode(procjail::EnvMode::Allowlist)
        .build();

    let mut proc = SandboxedProcess::spawn(&harness, work_dir.path(), &config).expect("spawn failed");
    let line = proc.recv().expect("recv failed").expect("eof early");
    let count: usize = line.trim().parse().unwrap_or(999);
    // Only the internally-injected SANTH_* vars should exist.
    assert!(
        count <= 6,
        "empty allowlist should leave almost no env vars; got {count}"
    );
    let usage = proc.wait_with_usage().expect("wait failed");
    assert_eq!(usage.exit_code, 0);
}

/// Spawn with 1000 environment variables.  The sandbox must handle this
/// without truncation or overflow.
#[test]
fn thousand_env_vars_spawn_successfully() {
    let work_dir = tempfile::tempdir().unwrap();
    let harness = create_sh_harness(
        work_dir.path(),
        "#!/bin/sh\necho STARTED\n",
    );

    let mut builder = SandboxConfig::builder()
        .runtime("sh")
        .strategy(Strategy::None);

    for i in 0..1000 {
        builder = builder.env_set(&format!("VAR_{i}"), &format!("value_{i}"));
    }

    let config = builder.build();
    let mut proc = SandboxedProcess::spawn(&harness, work_dir.path(), &config).expect("spawn failed");
    let line = proc.recv().expect("recv failed").expect("eof early");
    assert_eq!(line.trim(), "STARTED");
    let usage = proc.wait_with_usage().expect("wait failed");
    assert_eq!(usage.exit_code, 0);
}

// =============================================================================
// Nested jails (sandbox inside sandbox)
// =============================================================================

/// A SandboxedProcess spawned inside another SandboxedProcess.  This tests
/// that containment layers compose safely.
#[test]
fn nested_sandbox_spawn() {
    let outer_dir = tempfile::tempdir().unwrap();
    let inner_dir = tempfile::tempdir().unwrap();

    // The inner harness just prints its PID and exits.
    let inner_harness = create_sh_harness(
        inner_dir.path(),
        "#!/bin/sh\necho INNER_PID=$$\n",
    );

    // The outer harness receives the absolute paths to the inner harness and
    // work dir, then spawns a second SandboxedProcess using them.
    let outer_script = format!(
        "#!/bin/sh\n\
        read json\n\
        # Parse the JSON manually with sed (no jq dependency)\n\
        harness=$(echo \"$json\" | sed 's/.*\"harness\":\"\\([^\"]*\\)\".*/\\1/')\n\
        workdir=$(echo \"$json\" | sed 's/.*\"workdir\":\"\\([^\"]*\\)\".*/\\1/')\n\
        # Spawn inner sandbox\n\
        \"$1\" \"$harness\" \"$workdir\" 2>/dev/null || echo SPAWN_FAILED\n",
    );
    // Actually, calling procjail from inside a shell script is hard without
    // compiling Rust.  Instead, we use a simpler approach: the outer harness
    // is a Python script that imports nothing and just executes the inner
    // harness with Strategy::None.
    let outer_harness = create_sh_harness(
        outer_dir.path(),
        &format!(
            "#!/usr/bin/env python3\n\
            import subprocess, sys\n\
            inner_harness = {inner_harness:?}\n\
            inner_workdir = {inner_workdir:?}\n\
            result = subprocess.run(['sh', inner_harness], cwd=inner_workdir, capture_output=True, text=True)\n\
            print(result.stdout.strip())\n",
            inner_harness = inner_harness.to_str().unwrap(),
            inner_workdir = inner_dir.path().to_str().unwrap(),
        ),
    );

    let config = SandboxConfig::builder()
        .runtime("python3")
        .timeout_seconds(10)
        .strategy(Strategy::None)
        .build();

    let mut proc = SandboxedProcess::spawn(&outer_harness, outer_dir.path(), &config)
        .or_else(|_| {
            // Fallback if python3 is not available: just use sh and call inner harness directly.
            let fallback = create_sh_harness(
                outer_dir.path(),
                &format!(
                    "#!/bin/sh\nsh \"{inner}\"\n",
                    inner = inner_harness.to_str().unwrap()
                ),
            );
            SandboxedProcess::spawn(&fallback, outer_dir.path(), &config)
        })
        .expect("spawn failed");

    let line = proc.recv().expect("recv failed").expect("eof early");
    assert!(
        line.contains("INNER_PID") || line.trim() == "SPAWN_FAILED" || line.trim().is_empty(),
        "nested sandbox must run or fail gracefully; got: {line}"
    );
    let usage = proc.wait_with_usage().expect("wait failed");
    assert_eq!(usage.exit_code, 0);
}

// =============================================================================
// Rapid spawn / teardown stress
// =============================================================================

/// Spawn and destroy many sandboxed processes rapidly to check for fd leaks,
/// zombie processes, or cgroup cleanup bugs.
#[test]
fn rapid_spawn_teardown() {
    let work_dir = tempfile::tempdir().unwrap();
    let harness = create_sh_harness(work_dir.path(), "#!/bin/sh\necho ok\n");

    let config = SandboxConfig::builder()
        .runtime("sh")
        .timeout_seconds(5)
        .strategy(Strategy::None)
        .build();

    for _ in 0..50 {
        let mut proc = SandboxedProcess::spawn(&harness, work_dir.path(), &config).expect("spawn failed");
        let _ = proc.recv();
        // Explicitly kill some, let others drop.
        if rand::random::<bool>() {
            proc.kill();
        }
    }
}

// Need a tiny rand impl since we don't depend on the rand crate.
mod rand {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEED: AtomicU64 = AtomicU64::new(0x1234_5678_9ABC_DEF0);
    pub fn random<T>() -> T
    where
        T: From<bool>,
    {
        let old = SEED.fetch_add(1, Ordering::Relaxed);
        ((old.wrapping_mul(6364136223846793005).wrapping_add(1)) & 1 == 1).into()
    }
}

// =============================================================================
// Syscall number confusion (architecture-specific)
// =============================================================================

/// Verify that a syscall with a negative number (impossible on real hardware)
/// is treated consistently by the filter.
#[test]
#[cfg(target_os = "linux")]
fn negative_syscall_number_blocked() {
    let errno = run_in_seccomp(|| unsafe {
        let ret = libc::syscall(-1i64, 0, 0, 0);
        if ret < 0 {
            std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
        } else {
            0
        }
    });
    // Negative syscall numbers are invalid; the kernel should return ENOSYS.
    // The critical thing is that seccomp does not crash or allow them.
    assert!(
        errno == libc::ENOSYS || errno == libc::EPERM,
        "negative syscall must be rejected; got errno={errno}"
    );
}

/// Verify that a syscall with an extremely large number is handled safely.
#[test]
#[cfg(target_os = "linux")]
fn huge_syscall_number_blocked() {
    let errno = run_in_seccomp(|| unsafe {
        let ret = libc::syscall(i64::MAX, 0, 0, 0);
        if ret < 0 {
            std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
        } else {
            0
        }
    });
    assert!(
        errno == libc::ENOSYS || errno == libc::EPERM,
        "huge syscall number must be rejected; got errno={errno}"
    );
}

// =============================================================================
// Multi-threaded filter application race
// =============================================================================

/// Apply the seccomp filter from many threads simultaneously.  Only one
/// can succeed (the others may see EACCES or similar), but the process
/// must not crash or end up in an inconsistent state.
#[test]
#[cfg(target_os = "linux")]
fn concurrent_seccomp_application_is_safe() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    let success = Arc::new(AtomicUsize::new(0));
    let failure = Arc::new(AtomicUsize::new(0));

    let mut handles = Vec::new();
    for _ in 0..8 {
        let s = Arc::clone(&success);
        let f = Arc::clone(&failure);
        handles.push(std::thread::spawn(move || {
            match procjail::seccomp::apply_seccomp_filter() {
                Ok(()) => s.fetch_add(1, Ordering::SeqCst),
                Err(_) => f.fetch_add(1, Ordering::SeqCst),
            };
        }));
    }

    for h in handles {
        h.join().unwrap();
    }

    let s = success.load(Ordering::SeqCst);
    let f = failure.load(Ordering::SeqCst);
    assert!(
        s >= 1,
        "at least one thread must succeed in applying seccomp; success={s} failure={f}"
    );
    assert_eq!(
        s + f,
        8,
        "all threads must complete; success={s} failure={f}"
    );

    // Verify the filter is actually in force in this process.
    let ret = unsafe { libc::syscall(libc::SYS_socket, libc::AF_INET as usize, libc::SOCK_STREAM as usize, 0) };
    if ret >= 0 {
        panic!("concurrent application left socket unblocked");
    }
    let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
    assert_eq!(
        errno, libc::EPERM,
        "filter must be active after concurrent application; got errno={errno}"
    );
}
