//! Security tests: verify blocked syscalls return EPERM under seccomp.
//!
//! These tests fork a child process, apply procjail's seccomp filter,
//! attempt a blocked syscall, and report the resulting errno back to the
//! parent via a pipe.  A sandbox escape through any of these syscalls
//! would be catastrophic, so each test is treated as critical.

#[path = "seccomp_linux_helpers.rs"]
mod linux_helpers;

use std::ffi::CString;

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
use linux_helpers::{SYS_NICE, SYS_STIME};

/// Fork, apply seccomp in the child, execute `f`, and return the child's
/// reported errno (or 0 if the syscall succeeded).
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
                // Child: close read end, apply filter, run test, report errno.
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
                // Parent: close write end, read errno, reap child.
                libc::close(pipe_fds[1]);
                let mut buf = [0u8; 4];
                let n = libc::read(pipe_fds[0], buf.as_mut_ptr() as *mut libc::c_void, 4);
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

/// Helper: attempt a raw syscall and return errno (0 on success).
#[cfg(target_os = "linux")]
unsafe fn syscall_errno(num: i64, a1: usize, a2: usize, a3: usize) -> i32 {
    let ret = libc::syscall(num, a1, a2, a3);
    if ret < 0 {
        std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
    } else {
        0
    }
}

// =============================================================================
// Explicitly blocked syscalls
// =============================================================================

#[test]
#[cfg(target_os = "linux")]
fn ptrace_is_blocked() {
    let errno = run_in_seccomp(|| unsafe {
        syscall_errno(libc::SYS_ptrace, libc::PTRACE_TRACEME as usize, 0, 0)
    });
    assert_eq!(
        errno,
        libc::EPERM,
        "ptrace must return EPERM; got errno={errno}"
    );
}

#[test]
#[cfg(target_os = "linux")]
fn process_vm_readv_is_blocked() {
    let errno = run_in_seccomp(|| unsafe { syscall_errno(libc::SYS_process_vm_readv, 0, 0, 0) });
    assert_eq!(
        errno,
        libc::EPERM,
        "process_vm_readv must return EPERM; got errno={errno}"
    );
}

#[test]
#[cfg(target_os = "linux")]
fn process_vm_writev_is_blocked() {
    let errno = run_in_seccomp(|| unsafe { syscall_errno(libc::SYS_process_vm_writev, 0, 0, 0) });
    assert_eq!(
        errno,
        libc::EPERM,
        "process_vm_writev must return EPERM; got errno={errno}"
    );
}

#[test]
#[cfg(target_os = "linux")]
fn mount_is_blocked() {
    let errno = run_in_seccomp(|| unsafe { syscall_errno(libc::SYS_mount, 0, 0, 0) });
    assert_eq!(
        errno,
        libc::EPERM,
        "mount must return EPERM; got errno={errno}"
    );
}

#[test]
#[cfg(target_os = "linux")]
fn umount2_is_blocked() {
    let errno = run_in_seccomp(|| unsafe { syscall_errno(libc::SYS_umount2, 0, 0, 0) });
    assert_eq!(
        errno,
        libc::EPERM,
        "umount2 must return EPERM; got errno={errno}"
    );
}

#[test]
#[cfg(target_os = "linux")]
fn reboot_is_blocked() {
    let errno = run_in_seccomp(|| unsafe { syscall_errno(libc::SYS_reboot, 0, 0, 0) });
    assert_eq!(
        errno,
        libc::EPERM,
        "reboot must return EPERM; got errno={errno}"
    );
}

#[test]
#[cfg(target_os = "linux")]
fn swapon_is_blocked() {
    let errno = run_in_seccomp(|| unsafe { syscall_errno(libc::SYS_swapon, 0, 0, 0) });
    assert_eq!(
        errno,
        libc::EPERM,
        "swapon must return EPERM; got errno={errno}"
    );
}

#[test]
#[cfg(target_os = "linux")]
fn swapoff_is_blocked() {
    let errno = run_in_seccomp(|| unsafe { syscall_errno(libc::SYS_swapoff, 0, 0, 0) });
    assert_eq!(
        errno,
        libc::EPERM,
        "swapoff must return EPERM; got errno={errno}"
    );
}

#[test]
#[cfg(target_os = "linux")]
fn kexec_load_is_blocked() {
    let errno = run_in_seccomp(|| unsafe { syscall_errno(libc::SYS_kexec_load, 0, 0, 0) });
    assert_eq!(
        errno,
        libc::EPERM,
        "kexec_load must return EPERM; got errno={errno}"
    );
}

#[test]
#[cfg(target_os = "linux")]
fn kexec_file_load_is_blocked() {
    let errno = run_in_seccomp(|| unsafe { syscall_errno(libc::SYS_kexec_file_load, 0, 0, 0) });
    assert_eq!(
        errno,
        libc::EPERM,
        "kexec_file_load must return EPERM; got errno={errno}"
    );
}

#[test]
#[cfg(target_os = "linux")]
fn bpf_is_blocked() {
    let errno = run_in_seccomp(|| unsafe { syscall_errno(libc::SYS_bpf, 0, 0, 0) });
    assert_eq!(
        errno,
        libc::EPERM,
        "bpf must return EPERM; got errno={errno}"
    );
}

#[test]
#[cfg(target_os = "linux")]
fn userfaultfd_is_blocked() {
    let errno = run_in_seccomp(|| unsafe { syscall_errno(libc::SYS_userfaultfd, 0, 0, 0) });
    assert_eq!(
        errno,
        libc::EPERM,
        "userfaultfd must return EPERM; got errno={errno}"
    );
}

#[test]
#[cfg(target_os = "linux")]
fn perf_event_open_is_blocked() {
    let errno = run_in_seccomp(|| unsafe { syscall_errno(libc::SYS_perf_event_open, 0, 0, 0) });
    assert_eq!(
        errno,
        libc::EPERM,
        "perf_event_open must return EPERM; got errno={errno}"
    );
}

// =============================================================================
// Syscalls NOT in the allowlist (default-deny)
// =============================================================================

#[test]
#[cfg(target_os = "linux")]
fn socket_is_blocked() {
    let errno = run_in_seccomp(|| unsafe {
        syscall_errno(
            libc::SYS_socket,
            libc::AF_INET as usize,
            libc::SOCK_STREAM as usize,
            0,
        )
    });
    assert_eq!(
        errno,
        libc::EPERM,
        "socket must return EPERM; got errno={errno}"
    );
}

#[test]
#[cfg(target_os = "linux")]
fn socketpair_is_blocked() {
    let mut fds = [-1i32; 2];
    let errno = run_in_seccomp(|| unsafe {
        let ret = libc::syscall(
            libc::SYS_socketpair,
            libc::AF_UNIX as usize,
            libc::SOCK_STREAM as usize,
            0,
            fds.as_mut_ptr(),
        );
        if ret < 0 {
            std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
        } else {
            libc::close(fds[0]);
            libc::close(fds[1]);
            0
        }
    });
    assert_eq!(
        errno,
        libc::EPERM,
        "socketpair must return EPERM; got errno={errno}"
    );
}

#[test]
#[cfg(target_os = "linux")]
fn connect_is_blocked() {
    let errno = run_in_seccomp(|| unsafe { syscall_errno(libc::SYS_connect, 0, 0, 0) });
    assert_eq!(
        errno,
        libc::EPERM,
        "connect must return EPERM; got errno={errno}"
    );
}

#[test]
#[cfg(target_os = "linux")]
fn bind_is_blocked() {
    let errno = run_in_seccomp(|| unsafe { syscall_errno(libc::SYS_bind, 0, 0, 0) });
    assert_eq!(
        errno,
        libc::EPERM,
        "bind must return EPERM; got errno={errno}"
    );
}

#[test]
#[cfg(target_os = "linux")]
fn accept_is_blocked() {
    let errno = run_in_seccomp(|| unsafe { syscall_errno(libc::SYS_accept, 0, 0, 0) });
    assert_eq!(
        errno,
        libc::EPERM,
        "accept must return EPERM; got errno={errno}"
    );
}

#[test]
#[cfg(target_os = "linux")]
fn listen_is_blocked() {
    let errno = run_in_seccomp(|| unsafe { syscall_errno(libc::SYS_listen, 0, 0, 0) });
    assert_eq!(
        errno,
        libc::EPERM,
        "listen must return EPERM; got errno={errno}"
    );
}

#[test]
#[cfg(target_os = "linux")]
fn setsockopt_is_blocked() {
    let errno = run_in_seccomp(|| unsafe { syscall_errno(libc::SYS_setsockopt, 0, 0, 0) });
    assert_eq!(
        errno,
        libc::EPERM,
        "setsockopt must return EPERM; got errno={errno}"
    );
}

#[test]
#[cfg(target_os = "linux")]
fn getsockopt_is_blocked() {
    let errno = run_in_seccomp(|| unsafe { syscall_errno(libc::SYS_getsockopt, 0, 0, 0) });
    assert_eq!(
        errno,
        libc::EPERM,
        "getsockopt must return EPERM; got errno={errno}"
    );
}

#[test]
#[cfg(target_os = "linux")]
fn shutdown_is_blocked() {
    let errno = run_in_seccomp(|| unsafe { syscall_errno(libc::SYS_shutdown, 0, 0, 0) });
    assert_eq!(
        errno,
        libc::EPERM,
        "shutdown must return EPERM; got errno={errno}"
    );
}

#[test]
#[cfg(target_os = "linux")]
fn sendto_is_blocked() {
    let errno = run_in_seccomp(|| unsafe { syscall_errno(libc::SYS_sendto, 0, 0, 0) });
    assert_eq!(
        errno,
        libc::EPERM,
        "sendto must return EPERM; got errno={errno}"
    );
}

#[test]
#[cfg(target_os = "linux")]
fn recvfrom_is_blocked() {
    let errno = run_in_seccomp(|| unsafe { syscall_errno(libc::SYS_recvfrom, 0, 0, 0) });
    assert_eq!(
        errno,
        libc::EPERM,
        "recvfrom must return EPERM; got errno={errno}"
    );
}

#[test]
#[cfg(target_os = "linux")]
fn creat_is_blocked() {
    let path = CString::new("/tmp/procjail_test_creat").unwrap();
    let errno = run_in_seccomp(|| unsafe {
        syscall_errno(libc::SYS_creat, path.as_ptr() as usize, 0o644, 0)
    });
    assert_eq!(
        errno,
        libc::EPERM,
        "creat must return EPERM; got errno={errno}"
    );
}

#[test]
#[cfg(target_os = "linux")]
fn unlink_is_blocked() {
    let path = CString::new("/tmp/procjail_test_unlink").unwrap();
    let errno =
        run_in_seccomp(|| unsafe { syscall_errno(libc::SYS_unlink, path.as_ptr() as usize, 0, 0) });
    assert_eq!(
        errno,
        libc::EPERM,
        "unlink must return EPERM; got errno={errno}"
    );
}

#[test]
#[cfg(target_os = "linux")]
fn mkdir_is_blocked() {
    let path = CString::new("/tmp/procjail_test_mkdir").unwrap();
    let errno = run_in_seccomp(|| unsafe {
        syscall_errno(libc::SYS_mkdir, path.as_ptr() as usize, 0o755, 0)
    });
    assert_eq!(
        errno,
        libc::EPERM,
        "mkdir must return EPERM; got errno={errno}"
    );
}

#[test]
#[cfg(target_os = "linux")]
fn rmdir_is_blocked() {
    let path = CString::new("/tmp/procjail_test_rmdir").unwrap();
    let errno =
        run_in_seccomp(|| unsafe { syscall_errno(libc::SYS_rmdir, path.as_ptr() as usize, 0, 0) });
    assert_eq!(
        errno,
        libc::EPERM,
        "rmdir must return EPERM; got errno={errno}"
    );
}

#[test]
#[cfg(target_os = "linux")]
fn link_is_blocked() {
    let old = CString::new("/tmp/procjail_test_link_old").unwrap();
    let new = CString::new("/tmp/procjail_test_link_new").unwrap();
    let errno = run_in_seccomp(|| unsafe {
        syscall_errno(
            libc::SYS_link,
            old.as_ptr() as usize,
            new.as_ptr() as usize,
            0,
        )
    });
    assert_eq!(
        errno,
        libc::EPERM,
        "link must return EPERM; got errno={errno}"
    );
}

#[test]
#[cfg(target_os = "linux")]
fn symlink_is_blocked() {
    let target = CString::new("/tmp/procjail_test_symlink_tgt").unwrap();
    let linkpath = CString::new("/tmp/procjail_test_symlink_lnk").unwrap();
    let errno = run_in_seccomp(|| unsafe {
        syscall_errno(
            libc::SYS_symlink,
            target.as_ptr() as usize,
            linkpath.as_ptr() as usize,
            0,
        )
    });
    assert_eq!(
        errno,
        libc::EPERM,
        "symlink must return EPERM; got errno={errno}"
    );
}

#[test]
#[cfg(target_os = "linux")]
fn chmod_is_blocked() {
    let path = CString::new("/tmp/procjail_test_chmod").unwrap();
    let errno = run_in_seccomp(|| unsafe {
        syscall_errno(libc::SYS_chmod, path.as_ptr() as usize, 0o644, 0)
    });
    assert_eq!(
        errno,
        libc::EPERM,
        "chmod must return EPERM; got errno={errno}"
    );
}

#[test]
#[cfg(target_os = "linux")]
fn chown_is_blocked() {
    let path = CString::new("/tmp/procjail_test_chown").unwrap();
    let errno =
        run_in_seccomp(|| unsafe { syscall_errno(libc::SYS_chown, path.as_ptr() as usize, 0, 0) });
    assert_eq!(
        errno,
        libc::EPERM,
        "chown must return EPERM; got errno={errno}"
    );
}

#[test]
#[cfg(target_os = "linux")]
fn rename_is_blocked() {
    let old = CString::new("/tmp/procjail_test_rename_old").unwrap();
    let new = CString::new("/tmp/procjail_test_rename_new").unwrap();
    let errno = run_in_seccomp(|| unsafe {
        syscall_errno(
            libc::SYS_rename,
            old.as_ptr() as usize,
            new.as_ptr() as usize,
            0,
        )
    });
    assert_eq!(
        errno,
        libc::EPERM,
        "rename must return EPERM; got errno={errno}"
    );
}

#[test]
#[cfg(target_os = "linux")]
fn truncate_is_blocked() {
    let path = CString::new("/tmp/procjail_test_truncate").unwrap();
    let errno = run_in_seccomp(|| unsafe {
        syscall_errno(libc::SYS_truncate, path.as_ptr() as usize, 0, 0)
    });
    assert_eq!(
        errno,
        libc::EPERM,
        "truncate must return EPERM; got errno={errno}"
    );
}

#[test]
#[cfg(target_os = "linux")]
fn ftruncate_is_blocked_on_blocked_fd() {
    // ftruncate itself is not in the allowlist, but even if it were,
    // calling it on an invalid fd should fail.
    let errno = run_in_seccomp(|| unsafe { syscall_errno(libc::SYS_ftruncate, 9999, 0, 0) });
    assert_eq!(
        errno,
        libc::EPERM,
        "ftruncate must return EPERM; got errno={errno}"
    );
}

#[test]
#[cfg(target_os = "linux")]
fn statfs_is_blocked() {
    let path = CString::new("/").unwrap();
    let errno =
        run_in_seccomp(|| unsafe { syscall_errno(libc::SYS_statfs, path.as_ptr() as usize, 0, 0) });
    assert_eq!(
        errno,
        libc::EPERM,
        "statfs must return EPERM; got errno={errno}"
    );
}

#[test]
#[cfg(target_os = "linux")]
fn sync_is_blocked() {
    let errno = run_in_seccomp(|| unsafe { syscall_errno(libc::SYS_sync, 0, 0, 0) });
    assert_eq!(
        errno,
        libc::EPERM,
        "sync must return EPERM; got errno={errno}"
    );
}

#[test]
#[cfg(target_os = "linux")]
fn fsync_is_blocked() {
    let errno = run_in_seccomp(|| unsafe { syscall_errno(libc::SYS_fsync, 9999, 0, 0) });
    assert_eq!(
        errno,
        libc::EPERM,
        "fsync must return EPERM; got errno={errno}"
    );
}

#[test]
#[cfg(target_os = "linux")]
fn fdatasync_is_blocked() {
    let errno = run_in_seccomp(|| unsafe { syscall_errno(libc::SYS_fdatasync, 9999, 0, 0) });
    assert_eq!(
        errno,
        libc::EPERM,
        "fdatasync must return EPERM; got errno={errno}"
    );
}

#[test]
#[cfg(target_os = "linux")]
fn nice_is_blocked() {
    let errno = run_in_seccomp(|| unsafe { syscall_errno(SYS_NICE, 5, 0, 0) });
    assert_eq!(
        errno,
        libc::EPERM,
        "nice must return EPERM; got errno={errno}"
    );
}

#[test]
#[cfg(target_os = "linux")]
fn setpriority_is_blocked() {
    let errno = run_in_seccomp(|| unsafe { syscall_errno(libc::SYS_setpriority, 0, 0, 10) });
    assert_eq!(
        errno,
        libc::EPERM,
        "setpriority must return EPERM; got errno={errno}"
    );
}

#[test]
#[cfg(target_os = "linux")]
fn sched_setparam_is_blocked() {
    let errno = run_in_seccomp(|| unsafe { syscall_errno(libc::SYS_sched_setparam, 0, 0, 0) });
    assert_eq!(
        errno,
        libc::EPERM,
        "sched_setparam must return EPERM; got errno={errno}"
    );
}

#[test]
#[cfg(target_os = "linux")]
fn sched_setscheduler_is_blocked() {
    let errno = run_in_seccomp(|| unsafe { syscall_errno(libc::SYS_sched_setscheduler, 0, 0, 0) });
    assert_eq!(
        errno,
        libc::EPERM,
        "sched_setscheduler must return EPERM; got errno={errno}"
    );
}

#[test]
#[cfg(target_os = "linux")]
fn iopl_is_blocked() {
    let errno = run_in_seccomp(|| unsafe { syscall_errno(libc::SYS_iopl, 3, 0, 0) });
    assert_eq!(
        errno,
        libc::EPERM,
        "iopl must return EPERM; got errno={errno}"
    );
}

#[test]
#[cfg(target_os = "linux")]
fn ioperm_is_blocked() {
    let errno = run_in_seccomp(|| unsafe { syscall_errno(libc::SYS_ioperm, 0, 0x3ff, 1) });
    assert_eq!(
        errno,
        libc::EPERM,
        "ioperm must return EPERM; got errno={errno}"
    );
}

#[test]
#[cfg(target_os = "linux")]
fn kcmp_is_blocked() {
    let errno = run_in_seccomp(|| unsafe { syscall_errno(libc::SYS_kcmp, 0, 0, 0) });
    assert_eq!(
        errno,
        libc::EPERM,
        "kcmp must return EPERM; got errno={errno}"
    );
}

#[test]
#[cfg(target_os = "linux")]
fn fanotify_init_is_blocked() {
    let errno = run_in_seccomp(|| unsafe { syscall_errno(libc::SYS_fanotify_init, 0, 0, 0) });
    assert_eq!(
        errno,
        libc::EPERM,
        "fanotify_init must return EPERM; got errno={errno}"
    );
}

#[test]
#[cfg(target_os = "linux")]
fn inotify_init_is_blocked() {
    let errno = run_in_seccomp(|| unsafe { syscall_errno(libc::SYS_inotify_init, 0, 0, 0) });
    assert_eq!(
        errno,
        libc::EPERM,
        "inotify_init must return EPERM; got errno={errno}"
    );
}

#[test]
#[cfg(target_os = "linux")]
fn quotactl_is_blocked() {
    let errno = run_in_seccomp(|| unsafe { syscall_errno(libc::SYS_quotactl, 0, 0, 0) });
    assert_eq!(
        errno,
        libc::EPERM,
        "quotactl must return EPERM; got errno={errno}"
    );
}

#[test]
#[cfg(target_os = "linux")]
fn sysfs_is_blocked() {
    let errno = run_in_seccomp(|| unsafe { syscall_errno(libc::SYS_sysfs, 1, 0, 0) });
    assert_eq!(
        errno,
        libc::EPERM,
        "sysfs must return EPERM; got errno={errno}"
    );
}

#[test]
#[cfg(target_os = "linux")]
fn lookup_dcookie_is_blocked() {
    let errno = run_in_seccomp(|| unsafe { syscall_errno(libc::SYS_lookup_dcookie, 0, 0, 0) });
    assert_eq!(
        errno,
        libc::EPERM,
        "lookup_dcookie must return EPERM; got errno={errno}"
    );
}

#[test]
#[cfg(target_os = "linux")]
fn add_key_is_blocked() {
    let errno = run_in_seccomp(|| unsafe { syscall_errno(libc::SYS_add_key, 0, 0, 0) });
    assert_eq!(
        errno,
        libc::EPERM,
        "add_key must return EPERM; got errno={errno}"
    );
}

#[test]
#[cfg(target_os = "linux")]
fn request_key_is_blocked() {
    let errno = run_in_seccomp(|| unsafe { syscall_errno(libc::SYS_request_key, 0, 0, 0) });
    assert_eq!(
        errno,
        libc::EPERM,
        "request_key must return EPERM; got errno={errno}"
    );
}

#[test]
#[cfg(target_os = "linux")]
fn keyctl_is_blocked() {
    let errno = run_in_seccomp(|| unsafe { syscall_errno(libc::SYS_keyctl, 0, 0, 0) });
    assert_eq!(
        errno,
        libc::EPERM,
        "keyctl must return EPERM; got errno={errno}"
    );
}

#[test]
#[cfg(target_os = "linux")]
fn acct_is_blocked() {
    let errno = run_in_seccomp(|| unsafe { syscall_errno(libc::SYS_acct, 0, 0, 0) });
    assert_eq!(
        errno,
        libc::EPERM,
        "acct must return EPERM; got errno={errno}"
    );
}

#[test]
#[cfg(target_os = "linux")]
fn pivot_root_is_blocked() {
    let errno = run_in_seccomp(|| unsafe { syscall_errno(libc::SYS_pivot_root, 0, 0, 0) });
    assert_eq!(
        errno,
        libc::EPERM,
        "pivot_root must return EPERM; got errno={errno}"
    );
}

#[test]
#[cfg(target_os = "linux")]
fn chroot_is_blocked() {
    let path = CString::new("/").unwrap();
    let errno =
        run_in_seccomp(|| unsafe { syscall_errno(libc::SYS_chroot, path.as_ptr() as usize, 0, 0) });
    assert_eq!(
        errno,
        libc::EPERM,
        "chroot must return EPERM; got errno={errno}"
    );
}

#[test]
#[cfg(target_os = "linux")]
fn init_module_is_blocked() {
    let errno = run_in_seccomp(|| unsafe { syscall_errno(libc::SYS_init_module, 0, 0, 0) });
    assert_eq!(
        errno,
        libc::EPERM,
        "init_module must return EPERM; got errno={errno}"
    );
}

#[test]
#[cfg(target_os = "linux")]
fn delete_module_is_blocked() {
    let errno = run_in_seccomp(|| unsafe { syscall_errno(libc::SYS_delete_module, 0, 0, 0) });
    assert_eq!(
        errno,
        libc::EPERM,
        "delete_module must return EPERM; got errno={errno}"
    );
}

#[test]
#[cfg(target_os = "linux")]
fn setdomainname_is_blocked() {
    let name = CString::new("test").unwrap();
    let errno = run_in_seccomp(|| unsafe {
        syscall_errno(libc::SYS_setdomainname, name.as_ptr() as usize, 4, 0)
    });
    assert_eq!(
        errno,
        libc::EPERM,
        "setdomainname must return EPERM; got errno={errno}"
    );
}

#[test]
#[cfg(target_os = "linux")]
fn sethostname_is_blocked() {
    let name = CString::new("test").unwrap();
    let errno = run_in_seccomp(|| unsafe {
        syscall_errno(libc::SYS_sethostname, name.as_ptr() as usize, 4, 0)
    });
    assert_eq!(
        errno,
        libc::EPERM,
        "sethostname must return EPERM; got errno={errno}"
    );
}

#[test]
#[cfg(target_os = "linux")]
fn timer_create_is_blocked() {
    let errno = run_in_seccomp(|| unsafe { syscall_errno(libc::SYS_timer_create, 0, 0, 0) });
    assert_eq!(
        errno,
        libc::EPERM,
        "timer_create must return EPERM; got errno={errno}"
    );
}

#[test]
#[cfg(target_os = "linux")]
fn timer_settime_is_blocked() {
    let errno = run_in_seccomp(|| unsafe { syscall_errno(libc::SYS_timer_settime, 0, 0, 0) });
    assert_eq!(
        errno,
        libc::EPERM,
        "timer_settime must return EPERM; got errno={errno}"
    );
}

#[test]
#[cfg(target_os = "linux")]
fn timer_gettime_is_blocked() {
    let errno = run_in_seccomp(|| unsafe { syscall_errno(libc::SYS_timer_gettime, 0, 0, 0) });
    assert_eq!(
        errno,
        libc::EPERM,
        "timer_gettime must return EPERM; got errno={errno}"
    );
}

#[test]
#[cfg(target_os = "linux")]
fn timer_getoverrun_is_blocked() {
    let errno = run_in_seccomp(|| unsafe { syscall_errno(libc::SYS_timer_getoverrun, 0, 0, 0) });
    assert_eq!(
        errno,
        libc::EPERM,
        "timer_getoverrun must return EPERM; got errno={errno}"
    );
}

#[test]
#[cfg(target_os = "linux")]
fn timer_delete_is_blocked() {
    let errno = run_in_seccomp(|| unsafe { syscall_errno(libc::SYS_timer_delete, 0, 0, 0) });
    assert_eq!(
        errno,
        libc::EPERM,
        "timer_delete must return EPERM; got errno={errno}"
    );
}

#[test]
#[cfg(target_os = "linux")]
fn clock_settime_is_blocked() {
    let errno = run_in_seccomp(|| unsafe { syscall_errno(libc::SYS_clock_settime, 0, 0, 0) });
    assert_eq!(
        errno,
        libc::EPERM,
        "clock_settime must return EPERM; got errno={errno}"
    );
}

#[test]
#[cfg(target_os = "linux")]
fn adjtimex_is_blocked() {
    let errno = run_in_seccomp(|| unsafe { syscall_errno(libc::SYS_adjtimex, 0, 0, 0) });
    assert_eq!(
        errno,
        libc::EPERM,
        "adjtimex must return EPERM; got errno={errno}"
    );
}

#[test]
#[cfg(target_os = "linux")]
fn settimeofday_is_blocked() {
    let errno = run_in_seccomp(|| unsafe { syscall_errno(libc::SYS_settimeofday, 0, 0, 0) });
    assert_eq!(
        errno,
        libc::EPERM,
        "settimeofday must return EPERM; got errno={errno}"
    );
}

#[test]
#[cfg(target_os = "linux")]
fn stime_is_blocked() {
    let errno = run_in_seccomp(|| unsafe { syscall_errno(SYS_STIME, 0, 0, 0) });
    assert_eq!(
        errno,
        libc::EPERM,
        "stime must return EPERM; got errno={errno}"
    );
}

#[test]
#[cfg(target_os = "linux")]
fn syslog_is_blocked() {
    let errno = run_in_seccomp(|| unsafe { syscall_errno(libc::SYS_syslog, 10, 0, 0) });
    assert_eq!(
        errno,
        libc::EPERM,
        "syslog must return EPERM; got errno={errno}"
    );
}

#[test]
#[cfg(target_os = "linux")]
fn vhangup_is_blocked() {
    let errno = run_in_seccomp(|| unsafe { syscall_errno(libc::SYS_vhangup, 0, 0, 0) });
    assert_eq!(
        errno,
        libc::EPERM,
        "vhangup must return EPERM; got errno={errno}"
    );
}

#[test]
#[cfg(target_os = "linux")]
fn reboot_is_blocked_even_with_magic() {
    // Attempt reboot with the magic numbers that normally allow it.
    let errno = run_in_seccomp(|| unsafe {
        syscall_errno(
            libc::SYS_reboot,
            0xfee1dead,
            672274793,
            libc::LINUX_REBOOT_CMD_RESTART as usize,
        )
    });
    assert_eq!(
        errno,
        libc::EPERM,
        "reboot must return EPERM even with magic numbers; got errno={errno}"
    );
}

#[test]
#[cfg(target_os = "linux")]
fn mmap_with_weird_flags_is_still_allowed() {
    // mmap IS allowed, but verify that a normal anonymous mapping works.
    // This is a sanity check that our test harness itself functions.
    let errno = run_in_seccomp(|| unsafe {
        let addr = libc::mmap(
            std::ptr::null_mut(),
            4096,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        );
        if addr == libc::MAP_FAILED {
            std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
        } else {
            libc::munmap(addr, 4096);
            0
        }
    });
    assert_eq!(
        errno, 0,
        "mmap with normal flags should succeed; got errno={errno}"
    );
}

#[test]
#[cfg(target_os = "linux")]
fn msync_is_blocked() {
    let errno = run_in_seccomp(|| unsafe { syscall_errno(libc::SYS_msync, 0, 0, 0) });
    assert_eq!(
        errno,
        libc::EPERM,
        "msync must return EPERM; got errno={errno}"
    );
}

#[test]
#[cfg(target_os = "linux")]
fn mincore_is_blocked() {
    let errno = run_in_seccomp(|| unsafe { syscall_errno(libc::SYS_mincore, 0, 0, 0) });
    assert_eq!(
        errno,
        libc::EPERM,
        "mincore must return EPERM; got errno={errno}"
    );
}

#[test]
#[cfg(target_os = "linux")]
fn madvise_is_blocked() {
    let errno = run_in_seccomp(|| unsafe { syscall_errno(libc::SYS_madvise, 0, 0, 0) });
    assert_eq!(
        errno,
        libc::EPERM,
        "madvise must return EPERM; got errno={errno}"
    );
}

#[test]
#[cfg(target_os = "linux")]
fn mlock_is_blocked() {
    let errno = run_in_seccomp(|| unsafe { syscall_errno(libc::SYS_mlock, 0, 0, 0) });
    assert_eq!(
        errno,
        libc::EPERM,
        "mlock must return EPERM; got errno={errno}"
    );
}

#[test]
#[cfg(target_os = "linux")]
fn munlock_is_blocked() {
    let errno = run_in_seccomp(|| unsafe { syscall_errno(libc::SYS_munlock, 0, 0, 0) });
    assert_eq!(
        errno,
        libc::EPERM,
        "munlock must return EPERM; got errno={errno}"
    );
}

#[test]
#[cfg(target_os = "linux")]
fn mlockall_is_blocked() {
    let errno = run_in_seccomp(|| unsafe { syscall_errno(libc::SYS_mlockall, 0, 0, 0) });
    assert_eq!(
        errno,
        libc::EPERM,
        "mlockall must return EPERM; got errno={errno}"
    );
}

#[test]
#[cfg(target_os = "linux")]
fn munlockall_is_blocked() {
    let errno = run_in_seccomp(|| unsafe { syscall_errno(libc::SYS_munlockall, 0, 0, 0) });
    assert_eq!(
        errno,
        libc::EPERM,
        "munlockall must return EPERM; got errno={errno}"
    );
}

#[test]
#[cfg(target_os = "linux")]
fn remap_file_pages_is_blocked() {
    let errno = run_in_seccomp(|| unsafe { syscall_errno(libc::SYS_remap_file_pages, 0, 0, 0) });
    assert_eq!(
        errno,
        libc::EPERM,
        "remap_file_pages must return EPERM; got errno={errno}"
    );
}

#[test]
#[cfg(target_os = "linux")]
fn io_setup_is_blocked() {
    let errno = run_in_seccomp(|| unsafe { syscall_errno(libc::SYS_io_setup, 0, 0, 0) });
    assert_eq!(
        errno,
        libc::EPERM,
        "io_setup must return EPERM; got errno={errno}"
    );
}

#[test]
#[cfg(target_os = "linux")]
fn io_destroy_is_blocked() {
    let errno = run_in_seccomp(|| unsafe { syscall_errno(libc::SYS_io_destroy, 0, 0, 0) });
    assert_eq!(
        errno,
        libc::EPERM,
        "io_destroy must return EPERM; got errno={errno}"
    );
}

#[test]
#[cfg(target_os = "linux")]
fn io_submit_is_blocked() {
    let errno = run_in_seccomp(|| unsafe { syscall_errno(libc::SYS_io_submit, 0, 0, 0) });
    assert_eq!(
        errno,
        libc::EPERM,
        "io_submit must return EPERM; got errno={errno}"
    );
}

#[test]
#[cfg(target_os = "linux")]
fn io_cancel_is_blocked() {
    let errno = run_in_seccomp(|| unsafe { syscall_errno(libc::SYS_io_cancel, 0, 0, 0) });
    assert_eq!(
        errno,
        libc::EPERM,
        "io_cancel must return EPERM; got errno={errno}"
    );
}

#[test]
#[cfg(target_os = "linux")]
fn io_getevents_is_blocked() {
    let errno = run_in_seccomp(|| unsafe { syscall_errno(libc::SYS_io_getevents, 0, 0, 0) });
    assert_eq!(
        errno,
        libc::EPERM,
        "io_getevents must return EPERM; got errno={errno}"
    );
}

#[test]
#[cfg(target_os = "linux")]
fn migrate_pages_is_blocked() {
    let errno = run_in_seccomp(|| unsafe { syscall_errno(libc::SYS_migrate_pages, 0, 0, 0) });
    assert_eq!(
        errno,
        libc::EPERM,
        "migrate_pages must return EPERM; got errno={errno}"
    );
}

#[test]
#[cfg(target_os = "linux")]
fn move_pages_is_blocked() {
    let errno = run_in_seccomp(|| unsafe { syscall_errno(libc::SYS_move_pages, 0, 0, 0) });
    assert_eq!(
        errno,
        libc::EPERM,
        "move_pages must return EPERM; got errno={errno}"
    );
}

#[test]
#[cfg(target_os = "linux")]
fn set_mempolicy_is_blocked() {
    let errno = run_in_seccomp(|| unsafe { syscall_errno(libc::SYS_set_mempolicy, 0, 0, 0) });
    assert_eq!(
        errno,
        libc::EPERM,
        "set_mempolicy must return EPERM; got errno={errno}"
    );
}

#[test]
#[cfg(target_os = "linux")]
fn get_mempolicy_is_blocked() {
    let errno = run_in_seccomp(|| unsafe { syscall_errno(libc::SYS_get_mempolicy, 0, 0, 0) });
    assert_eq!(
        errno,
        libc::EPERM,
        "get_mempolicy must return EPERM; got errno={errno}"
    );
}

#[test]
#[cfg(target_os = "linux")]
fn mbind_is_blocked() {
    let errno = run_in_seccomp(|| unsafe { syscall_errno(libc::SYS_mbind, 0, 0, 0) });
    assert_eq!(
        errno,
        libc::EPERM,
        "mbind must return EPERM; got errno={errno}"
    );
}

#[test]
#[cfg(target_os = "linux")]
fn name_to_handle_at_is_blocked() {
    let errno = run_in_seccomp(|| unsafe { syscall_errno(libc::SYS_name_to_handle_at, 0, 0, 0) });
    assert_eq!(
        errno,
        libc::EPERM,
        "name_to_handle_at must return EPERM; got errno={errno}"
    );
}

#[test]
#[cfg(target_os = "linux")]
fn open_by_handle_at_is_blocked() {
    let errno = run_in_seccomp(|| unsafe { syscall_errno(libc::SYS_open_by_handle_at, 0, 0, 0) });
    assert_eq!(
        errno,
        libc::EPERM,
        "open_by_handle_at must return EPERM; got errno={errno}"
    );
}

#[test]
#[cfg(target_os = "linux")]
fn seccomp_filter_blocks_unknown_syscalls() {
    // Use a deliberately non-existent or extremely unlikely syscall number
    // to verify the default action is EPERM.  We pick a very high number
    // that is extremely unlikely to be assigned on x86_64 or aarch64.
    let fake_syscall: i64 = 9999;
    let errno = run_in_seccomp(|| unsafe {
        let ret = libc::syscall(fake_syscall, 0, 0, 0);
        if ret < 0 {
            std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
        } else {
            0
        }
    });
    assert_eq!(
        errno,
        libc::EPERM,
        "unknown syscall 9999 must return EPERM; got errno={errno}"
    );
}
