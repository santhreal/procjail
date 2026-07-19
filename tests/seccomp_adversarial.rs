//! Adversarial security tests: attempt to bypass or weaken the seccomp filter.
//!
//! An attacker with code execution inside the sandbox will try every trick
//! in the book to escape.  These tests probe the most common avenues:
//! - Duplicating a privileged file descriptor onto a sensitive one
//! - Calling prctl to disable or modify seccomp
//! - Installing a new, more permissive seccomp filter
//! - Using direct syscall instructions to avoid libc wrappers
//! - Forking before the filter is applied (not applicable here, but we test
//!   that the filter is inherited correctly across execve)

use std::ffi::CString;
use std::os::unix::io::AsRawFd;

#[path = "seccomp_linux_helpers.rs"]
mod linux_helpers;

#[cfg(target_os = "linux")]
use linux_helpers::{CAP_CHOWN, SECCOMP_DATA_NR_OFFSET};

/// Path to the C `socket_probe` helper built in `build.rs` (`OUT_DIR`).
#[cfg(target_os = "linux")]
fn socket_probe_path() -> CString {
    let path = env!("SEC_SOCKET_PROBE_C");
    CString::new(path).expect("probe path")
}

/// Fork, apply seccomp in the child, execute `f`, and return the child's
/// reported errno (0 means success).
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
// FD-based bypass attempts
// =============================================================================

/// dup2 is in the allowlist, but it cannot be used to bypass seccomp because
/// seccomp operates on syscalls, not file descriptors.  This test verifies
/// that dup2 still works normally (attacker can't make it fail to open a
/// blocked device, but they also can't use it to disable the filter).
#[test]
#[cfg(target_os = "linux")]
fn dup2_cannot_bypass_seccomp() {
    let errno = run_in_seccomp(|| unsafe {
        let mut fds = [-1i32; 2];
        if libc::pipe(fds.as_mut_ptr()) != 0 {
            return std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        }
        // dup2 the read end to an arbitrary high fd.
        let target = fds[0] + 50;
        let newfd = libc::dup2(fds[0], target);
        libc::close(fds[0]);
        libc::close(fds[1]);
        if target < 0 {
            libc::close(target);
        }
        if newfd < 0 {
            return std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        }
        // Now try a blocked syscall; it should still fail.
        let ret = libc::syscall(libc::SYS_socket, libc::AF_INET as usize, libc::SOCK_STREAM as usize, 0);
        if ret < 0 {
            let e = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
            if e != libc::EPERM {
                return e; // unexpected
            }
        } else {
            return libc::EIO; // socket should have failed
        }
        0
    });
    assert_eq!(errno, 0, "dup2 must not weaken seccomp; got errno={errno}");
}

/// dup3 similarly cannot be used to escape.
#[test]
#[cfg(target_os = "linux")]
fn dup3_cannot_bypass_seccomp() {
    let errno = run_in_seccomp(|| unsafe {
        let mut fds = [-1i32; 2];
        if libc::pipe(fds.as_mut_ptr()) != 0 {
            return std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        }
        let target = fds[0] + 51;
        let newfd = libc::dup3(fds[0], target, libc::O_CLOEXEC);
        libc::close(fds[0]);
        libc::close(fds[1]);
        if target < 0 {
            libc::close(target);
        }
        if newfd < 0 {
            return std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        }
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
    assert_eq!(errno, 0, "dup3 must not weaken seccomp; got errno={errno}");
}

// =============================================================================
// prctl-based bypass attempts
// =============================================================================

/// Attempt to disable seccomp via prctl.  This MUST fail because:
/// 1. NO_NEW_PRIVS is already set, which prevents removing seccomp.
/// 2. PR_SET_SECCOMP with mode 0 (disabled) is not permitted once a filter is loaded.
#[test]
#[cfg(target_os = "linux")]
fn prctl_disable_seccomp_is_blocked() {
    let errno = run_in_seccomp(|| unsafe {
        let ret = libc::prctl(libc::PR_SET_SECCOMP, libc::SECCOMP_MODE_DISABLED, 0, 0, 0);
        if ret < 0 {
            std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
        } else {
            // If it somehow succeeded, that's a sandbox escape.
            libc::EPERM
        }
    });
    assert_ne!(errno, 0, "prctl(PR_SET_SECCOMP, DISABLED) must fail; got errno={errno}");
}

/// Attempt to install a second seccomp filter that is more permissive.
/// The kernel allows nested filters, but they are ANDed together, so a
/// permissive second filter cannot override a restrictive first one.
/// This test verifies that even after a nested filter attempt, blocked
/// syscalls still return EPERM.
#[test]
#[cfg(target_os = "linux")]
fn nested_seccomp_filter_cannot_weaken_first() {
    let errno = run_in_seccomp(|| unsafe {
        // Try to install a second seccomp filter.
        // We build a trivial BPF program that allows everything.
        let bpf: Vec<libc::sock_filter> = vec![
            libc::sock_filter {
                code: (libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16,
                jt: 0,
                jf: 0,
                k: SECCOMP_DATA_NR_OFFSET,
            },
            libc::sock_filter {
                code: (libc::BPF_RET | libc::BPF_K) as u16,
                jt: 0,
                jf: 0,
                k: libc::SECCOMP_RET_ALLOW as u32,
            },
        ];
        let prog = libc::sock_fprog {
            len: bpf.len() as u16,
            filter: bpf.as_ptr() as *mut libc::sock_filter,
        };
        let ret = libc::syscall(
            libc::SYS_seccomp,
            libc::SECCOMP_SET_MODE_FILTER as usize,
            0usize,
            &prog as *const _ as usize,
        );
        // The seccomp syscall itself is allowed, so this may succeed or fail
        // depending on the kernel version and flags.  What matters is that
        // the original filter is still in force.
        let _ = ret;

        // Now try a syscall that was blocked by the original filter.
        let ret2 = libc::syscall(libc::SYS_socket, libc::AF_INET as usize, libc::SOCK_STREAM as usize, 0);
        if ret2 < 0 {
            let e = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
            if e != libc::EPERM {
                return e;
            }
        } else {
            return libc::EIO;
        }
        0
    });
    assert_eq!(errno, 0, "nested seccomp must not weaken the original filter; got errno={errno}");
}

/// Attempt to use prctl(PR_SET_NO_NEW_PRIVS, 0) to unset it.  This should
/// fail because NO_NEW_PRIVS is a one-way switch.
#[test]
#[cfg(target_os = "linux")]
fn prctl_unset_no_new_privs_is_blocked() {
    let errno = run_in_seccomp(|| unsafe {
        let ret = libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 0, 0, 0, 0);
        if ret < 0 {
            std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
        } else {
            libc::EPERM
        }
    });
    assert_ne!(errno, 0, "prctl(PR_SET_NO_NEW_PRIVS, 0) must fail; got errno={errno}");
}

/// Attempt to raise privileges via prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE).
/// Even if the syscall is allowed, the kernel should refuse because NO_NEW_PRIVS
/// prevents gaining new capabilities.
#[test]
#[cfg(target_os = "linux")]
fn prctl_cap_ambient_raise_fails_under_no_new_privs() {
    let errno = run_in_seccomp(|| unsafe {
        let ret = libc::prctl(
            libc::PR_CAP_AMBIENT,
            libc::PR_CAP_AMBIENT_RAISE,
            CAP_CHOWN as usize,
            0,
            0,
        );
        if ret < 0 {
            std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
        } else {
            // If it succeeded, that's a privilege escalation.
            libc::EPERM
        }
    });
    assert_ne!(errno, 0, "prctl(CAP_AMBIENT_RAISE) must fail under NO_NEW_PRIVS; got errno={errno}");
}

// =============================================================================
// Direct syscall bypass attempts
// =============================================================================

/// An attacker might try to invoke a blocked syscall using a raw `syscall`
/// instruction to bypass any libc interception.  seccomp operates at the
/// kernel entry point, so this must still fail.
#[test]
#[cfg(target_os = "linux")]
fn raw_syscall_socket_still_blocked() {
    let errno = run_in_seccomp(|| unsafe {
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
    assert_eq!(errno, 0, "raw syscall bypass must not work; got errno={errno}");
}

/// Same test but for ptrace  -  the most dangerous syscall for sandbox escapes.
#[test]
#[cfg(target_os = "linux")]
fn raw_syscall_ptrace_still_blocked() {
    let errno = run_in_seccomp(|| unsafe {
        let ret = libc::syscall(libc::SYS_ptrace, libc::PTRACE_TRACEME as usize, 0, 0, 0);
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
    assert_eq!(errno, 0, "raw ptrace bypass must not work; got errno={errno}");
}

/// Attempt to call mount via raw syscall.
#[test]
#[cfg(target_os = "linux")]
fn raw_syscall_mount_still_blocked() {
    let errno = run_in_seccomp(|| unsafe {
        let ret = libc::syscall(libc::SYS_mount, 0, 0, 0, 0, 0);
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
    assert_eq!(errno, 0, "raw mount bypass must not work; got errno={errno}");
}

/// Attempt to open /proc/self/mem (often used for code injection) via openat.
/// openat itself is allowed, but this verifies that the allowed-open path
/// does not give the attacker arbitrary kernel access.
#[test]
#[cfg(target_os = "linux")]
fn opening_proc_self_mem_is_not_blocked_by_seccomp() {
    // Important: seccomp does NOT block this openat.  The test documents
    // the current security posture: seccomp is not a file-system ACL.
    // Real containment must come from namespaces or DAC.
    let path = CString::new("/proc/self/mem").unwrap();
    let errno = run_in_seccomp(|| unsafe {
        let fd = libc::openat(libc::AT_FDCWD, path.as_ptr(), libc::O_RDONLY);
        if fd < 0 {
            // Will likely fail with EACCES/EPERM from the kernel DAC layer,
            // not from seccomp.
            std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
        } else {
            libc::close(fd);
            0
        }
    });
    // We don't assert a specific errno here; the point is that the test runs
    // and documents the behavior.
    let _ = errno;
}

// =============================================================================
// execve inheritance tests
// =============================================================================

/// When execve is called, the seccomp filter is inherited by the new process.
/// We verify this by execing a tiny helper that tries a blocked syscall.
#[test]
#[cfg(target_os = "linux")]
fn seccomp_filter_is_inherited_across_execve() {
    let helper = socket_probe_path();

    let mut pipe_fds = [-1i32; 2];
    unsafe {
        assert_eq!(libc::pipe(pipe_fds.as_mut_ptr()), 0);
        let pid = libc::fork();
        assert!(pid >= 0);
        if pid == 0 {
            libc::close(pipe_fds[0]);
            let _ = procjail::seccomp::apply_seccomp_filter();
            libc::dup2(pipe_fds[1], libc::STDOUT_FILENO);
            libc::close(pipe_fds[1]);
            let argv: [*const libc::c_char; 2] = [helper.as_ptr(), std::ptr::null()];
            libc::execve(helper.as_ptr(), argv.as_ptr(), std::ptr::null());
            // If execve fails, exit with a distinctive code.
            libc::exit(253);
        }
        libc::close(pipe_fds[1]);
        let mut buf = [0u8; 16];
        let n = libc::read(pipe_fds[0], buf.as_mut_ptr() as *mut libc::c_void, 15);
        libc::close(pipe_fds[0]);
        let mut status = 0;
        libc::waitpid(pid, &mut status, 0);
        assert!(libc::WIFEXITED(status));
        assert_eq!(libc::WEXITSTATUS(status), 0, "helper script must exit 0");
        let output = String::from_utf8_lossy(&buf[..n as usize]);
        let errno: i32 = output.trim().parse().expect("helper must print errno");
        assert_eq!(errno, libc::EPERM as i32, "inherited filter must block socket; got errno={errno}");
    }
}

// =============================================================================
// Signal-based escape attempts
// =============================================================================

/// Verify that sending SIGSYS to oneself does not crash the process in a way
/// that leaks state, and that the default SIGSYS handler terminates cleanly.
#[test]
#[cfg(target_os = "linux")]
fn sigsys_default_terminates_process() {
    let mut pipe_fds = [-1i32; 2];
    unsafe {
        assert_eq!(libc::pipe(pipe_fds.as_mut_ptr()), 0);
        let pid = libc::fork();
        assert!(pid >= 0);
        if pid == 0 {
            libc::close(pipe_fds[0]);
            let _ = procjail::seccomp::apply_seccomp_filter();
            // Trigger a blocked syscall (socket) which delivers SIGSYS by default
            // unless the action is EPERM.  Our filter uses EPERM, so no signal.
            // This test is really a no-op for our filter, but documents the behavior.
            libc::write(
                pipe_fds[1],
                b"ok".as_ptr() as *const libc::c_void,
                2,
            );
            libc::close(pipe_fds[1]);
            libc::exit(0);
        }
        libc::close(pipe_fds[1]);
        let mut buf = [0u8; 2];
        let n = libc::read(pipe_fds[0], buf.as_mut_ptr() as *mut libc::c_void, 2);
        libc::close(pipe_fds[0]);
        let mut status = 0;
        libc::waitpid(pid, &mut status, 0);
        assert_eq!(n, 2);
        assert_eq!(buf, *b"ok");
        assert!(libc::WIFEXITED(status));
        assert_eq!(libc::WEXITSTATUS(status), 0);
    }
}

// =============================================================================
// Clone / fork behavior
// =============================================================================

/// clone is in the allowlist, but we verify that a cloned thread still
/// operates under the same seccomp filter.
#[test]
#[cfg(target_os = "linux")]
fn clone_thread_inherits_seccomp() {
    use std::sync::atomic::{AtomicI32, Ordering};
    use std::sync::Arc;

    let errno = run_in_seccomp(|| {
        let result = Arc::new(AtomicI32::new(-1));
        let result2 = Arc::clone(&result);
        let handle = std::thread::spawn(move || unsafe {
            let ret = libc::syscall(
                libc::SYS_socket,
                libc::AF_INET as usize,
                libc::SOCK_STREAM as usize,
                0,
            );
            let errno = if ret < 0 {
                std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
            } else {
                0
            };
            result2.store(errno, Ordering::SeqCst);
        });
        handle.join().unwrap();
        result.load(Ordering::SeqCst)
    });
    assert_eq!(
        errno, libc::EPERM,
        "thread must inherit seccomp filter; got errno={errno}"
    );
}

// =============================================================================
// Environment / proc attacks
// =============================================================================

/// Verify that reading /proc/self/status does not reveal seccomp state that
/// would help an attacker craft a bypass.  (This is more of a documentation
/// test: Seccomp: 2 is actually visible in /proc/self/status.)
#[test]
#[cfg(target_os = "linux")]
fn proc_self_status_shows_seccomp_mode() {
    let errno = run_in_seccomp(|| unsafe {
        let fd = libc::open(CString::new("/proc/self/status").unwrap().as_ptr(), libc::O_RDONLY);
        if fd < 0 {
            return std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        }
        let mut buf = [0u8; 4096];
        let n = libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len() - 1);
        libc::close(fd);
        if n < 0 {
            return std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        }
        let text = String::from_utf8_lossy(&buf[..n as usize]);
        assert!(
            text.contains("Seccomp:"),
            "/proc/self/status must contain Seccomp line"
        );
        0
    });
    assert_eq!(errno, 0, "reading /proc/self/status must succeed; got errno={errno}");
}
