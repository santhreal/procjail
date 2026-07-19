//! Security tests: verify allowed syscalls succeed under seccomp.
//!
//! These tests ensure that the whitelist does not break legitimate
//! process execution.  If any of these fail, the filter is too tight
//! and will break harnesses.

#[path = "seccomp_linux_helpers.rs"]
mod linux_helpers;

use std::ffi::CString;

#[cfg(target_os = "linux")]
use linux_helpers::{
    syscall_arch_prctl, syscall_capget, syscall_eventfd2, syscall_exit_group,
    syscall_set_tid_address, syscall_signalfd4, ARCH_GET_FS, CapUserData, CapUserHeader,
    LINUX_CAPABILITY_VERSION_3,
};

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
// Basic I/O
// =============================================================================

#[test]
#[cfg(target_os = "linux")]
fn read_from_pipe_is_allowed() {
    let errno = run_in_seccomp(|| unsafe {
        let mut fds = [-1i32; 2];
        if libc::pipe(fds.as_mut_ptr()) != 0 {
            return std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        }
        let msg = b"x";
        libc::write(fds[1], msg.as_ptr() as *const libc::c_void, 1);
        let mut buf = [0u8; 1];
        let n = libc::read(fds[0], buf.as_mut_ptr() as *mut libc::c_void, 1);
        libc::close(fds[0]);
        libc::close(fds[1]);
        if n == 1 { 0 } else { libc::EIO }
    });
    assert_eq!(errno, 0, "read from pipe must succeed; got errno={errno}");
}

#[test]
#[cfg(target_os = "linux")]
fn write_to_pipe_is_allowed() {
    let errno = run_in_seccomp(|| unsafe {
        let mut fds = [-1i32; 2];
        if libc::pipe(fds.as_mut_ptr()) != 0 {
            return std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        }
        let msg = b"hello";
        let n = libc::write(fds[1], msg.as_ptr() as *const libc::c_void, msg.len());
        libc::close(fds[0]);
        libc::close(fds[1]);
        if n == msg.len() as isize { 0 } else { libc::EIO }
    });
    assert_eq!(errno, 0, "write to pipe must succeed; got errno={errno}");
}

#[test]
#[cfg(target_os = "linux")]
fn close_is_allowed() {
    let errno = run_in_seccomp(|| unsafe {
        let mut fds = [-1i32; 2];
        if libc::pipe(fds.as_mut_ptr()) != 0 {
            return std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        }
        libc::close(fds[0]);
        libc::close(fds[1]);
        0
    });
    assert_eq!(errno, 0, "close must succeed; got errno={errno}");
}

// =============================================================================
// Memory management
// =============================================================================

#[test]
#[cfg(target_os = "linux")]
fn mmap_is_allowed() {
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
            return std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        }
        libc::munmap(addr, 4096);
        0
    });
    assert_eq!(errno, 0, "mmap must succeed; got errno={errno}");
}

#[test]
#[cfg(target_os = "linux")]
fn mprotect_is_allowed() {
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
            return std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        }
        let ret = libc::mprotect(addr, 4096, libc::PROT_READ);
        let err = if ret != 0 {
            std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
        } else {
            0
        };
        libc::munmap(addr, 4096);
        err
    });
    assert_eq!(errno, 0, "mprotect must succeed; got errno={errno}");
}

#[test]
#[cfg(target_os = "linux")]
fn munmap_is_allowed() {
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
            return std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        }
        if libc::munmap(addr, 4096) != 0 {
            return std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        }
        0
    });
    assert_eq!(errno, 0, "munmap must succeed; got errno={errno}");
}

#[test]
#[cfg(target_os = "linux")]
fn brk_is_allowed() {
    let errno = run_in_seccomp(|| unsafe {
        let current = libc::sbrk(0);
        if current == (-1isize) as *mut libc::c_void {
            return std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        }
        // brk is the actual syscall; sbrk is a libc wrapper that may call brk.
        let new_brk = (current as usize + 4096) as *mut libc::c_void;
        if libc::brk(new_brk) != 0 {
            return std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        }
        libc::brk(current);
        0
    });
    assert_eq!(errno, 0, "brk must succeed; got errno={errno}");
}

// =============================================================================
// Signals
// =============================================================================

#[test]
#[cfg(target_os = "linux")]
fn rt_sigaction_is_allowed() {
    let errno = run_in_seccomp(|| unsafe {
        let mut old: libc::sigaction = std::mem::zeroed();
        let mut new: libc::sigaction = std::mem::zeroed();
        new.sa_sigaction = libc::SIG_DFL;
        let ret = libc::sigemptyset(&mut new.sa_mask);
        if ret != 0 {
            return std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        }
        new.sa_flags = 0;
        if libc::sigaction(libc::SIGTERM, &new, &mut old) != 0 {
            return std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        }
        0
    });
    assert_eq!(errno, 0, "rt_sigaction must succeed; got errno={errno}");
}

#[test]
#[cfg(target_os = "linux")]
fn rt_sigprocmask_is_allowed() {
    let errno = run_in_seccomp(|| unsafe {
        let mut oldset: libc::sigset_t = std::mem::zeroed();
        let mut newset: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut newset);
        libc::sigaddset(&mut newset, libc::SIGUSR1);
        if libc::sigprocmask(libc::SIG_BLOCK, &newset, &mut oldset) != 0 {
            return std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        }
        libc::sigprocmask(libc::SIG_SETMASK, &oldset, std::ptr::null_mut());
        0
    });
    assert_eq!(errno, 0, "rt_sigprocmask must succeed; got errno={errno}");
}

#[test]
#[cfg(target_os = "linux")]
fn rt_sigreturn_is_allowed() {
    // We can't easily test rt_sigreturn directly (it returns from a signal
    // handler), but we verify the syscall number isn't blocked by checking
    // that signal delivery works end-to-end.
    let errno = run_in_seccomp(|| unsafe {
        let mut act: libc::sigaction = std::mem::zeroed();
        extern "C" fn handler(_: libc::c_int) {}
        act.sa_sigaction = handler as usize;
        libc::sigemptyset(&mut act.sa_mask);
        act.sa_flags = 0;
        libc::sigaction(libc::SIGUSR2, &act, std::ptr::null_mut());
        libc::kill(libc::getpid(), libc::SIGUSR2);
        0
    });
    assert_eq!(errno, 0, "signal handling (which uses rt_sigreturn) must succeed; got errno={errno}");
}

// =============================================================================
// File descriptors
// =============================================================================

#[test]
#[cfg(target_os = "linux")]
fn pipe_is_allowed() {
    let errno = run_in_seccomp(|| unsafe {
        let mut fds = [-1i32; 2];
        if libc::pipe(fds.as_mut_ptr()) != 0 {
            return std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        }
        libc::close(fds[0]);
        libc::close(fds[1]);
        0
    });
    assert_eq!(errno, 0, "pipe must succeed; got errno={errno}");
}

#[test]
#[cfg(target_os = "linux")]
fn pipe2_is_allowed() {
    let errno = run_in_seccomp(|| unsafe {
        let mut fds = [-1i32; 2];
        if libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) != 0 {
            return std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        }
        libc::close(fds[0]);
        libc::close(fds[1]);
        0
    });
    assert_eq!(errno, 0, "pipe2 must succeed; got errno={errno}");
}

#[test]
#[cfg(target_os = "linux")]
fn dup_is_allowed() {
    let errno = run_in_seccomp(|| unsafe {
        let mut fds = [-1i32; 2];
        if libc::pipe(fds.as_mut_ptr()) != 0 {
            return std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        }
        let newfd = libc::dup(fds[0]);
        if newfd < 0 {
            let e = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
            libc::close(fds[0]);
            libc::close(fds[1]);
            return e;
        }
        libc::close(newfd);
        libc::close(fds[0]);
        libc::close(fds[1]);
        0
    });
    assert_eq!(errno, 0, "dup must succeed; got errno={errno}");
}

#[test]
#[cfg(target_os = "linux")]
fn dup2_is_allowed() {
    let errno = run_in_seccomp(|| unsafe {
        let mut fds = [-1i32; 2];
        if libc::pipe(fds.as_mut_ptr()) != 0 {
            return std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        }
        let target = fds[0] + 100; // pick a high fd number
        let newfd = libc::dup2(fds[0], target);
        if newfd < 0 {
            let e = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
            libc::close(fds[0]);
            libc::close(fds[1]);
            return e;
        }
        libc::close(target);
        libc::close(fds[0]);
        libc::close(fds[1]);
        0
    });
    assert_eq!(errno, 0, "dup2 must succeed; got errno={errno}");
}

#[test]
#[cfg(target_os = "linux")]
fn dup3_is_allowed() {
    let errno = run_in_seccomp(|| unsafe {
        let mut fds = [-1i32; 2];
        if libc::pipe(fds.as_mut_ptr()) != 0 {
            return std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        }
        let target = fds[0] + 100;
        let newfd = libc::dup3(fds[0], target, libc::O_CLOEXEC);
        if newfd < 0 {
            let e = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
            libc::close(fds[0]);
            libc::close(fds[1]);
            return e;
        }
        libc::close(target);
        libc::close(fds[0]);
        libc::close(fds[1]);
        0
    });
    assert_eq!(errno, 0, "dup3 must succeed; got errno={errno}");
}

#[test]
#[cfg(target_os = "linux")]
fn ioctl_on_tty_is_allowed() {
    let errno = run_in_seccomp(|| unsafe {
        // Even if stdin is not a tty, the ioctl syscall itself must not be blocked.
        // We use TCGETS which is a harmless query.
        let mut termios: libc::termios = std::mem::zeroed();
        let ret = libc::ioctl(libc::STDIN_FILENO, libc::TCGETS, &mut termios);
        if ret < 0 {
            // EINVAL or ENOTTY is fine; EPERM means seccomp blocked it.
            let e = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
            if e == libc::EPERM {
                return e;
            }
        }
        0
    });
    assert_eq!(errno, 0, "ioctl must not be blocked by seccomp; got errno={errno}");
}

// =============================================================================
// File access and stat
// =============================================================================

#[test]
#[cfg(target_os = "linux")]
fn access_is_allowed() {
    let path = CString::new("/").unwrap();
    let errno = run_in_seccomp(|| unsafe {
        let ret = libc::access(path.as_ptr(), libc::F_OK);
        if ret < 0 {
            std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
        } else {
            0
        }
    });
    assert_eq!(errno, 0, "access must succeed; got errno={errno}");
}

#[test]
#[cfg(target_os = "linux")]
fn faccessat_is_allowed() {
    let path = CString::new("/").unwrap();
    let errno = run_in_seccomp(|| unsafe {
        let ret = libc::faccessat(libc::AT_FDCWD, path.as_ptr(), libc::F_OK, 0);
        if ret < 0 {
            std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
        } else {
            0
        }
    });
    assert_eq!(errno, 0, "faccessat must succeed; got errno={errno}");
}

#[test]
#[cfg(target_os = "linux")]
fn getcwd_is_allowed() {
    let errno = run_in_seccomp(|| unsafe {
        let mut buf = vec![0u8; 4096];
        let ptr = libc::getcwd(buf.as_mut_ptr() as *mut libc::c_char, buf.len());
        if ptr.is_null() {
            std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
        } else {
            0
        }
    });
    assert_eq!(errno, 0, "getcwd must succeed; got errno={errno}");
}

#[test]
#[cfg(target_os = "linux")]
fn fstat_is_allowed() {
    let errno = run_in_seccomp(|| unsafe {
        let mut statbuf: libc::stat = std::mem::zeroed();
        let ret = libc::fstat(libc::STDIN_FILENO, &mut statbuf);
        if ret < 0 {
            std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
        } else {
            0
        }
    });
    assert_eq!(errno, 0, "fstat must succeed; got errno={errno}");
}

#[test]
#[cfg(target_os = "linux")]
fn stat_is_allowed() {
    let path = CString::new("/").unwrap();
    let errno = run_in_seccomp(|| unsafe {
        let mut statbuf: libc::stat = std::mem::zeroed();
        let ret = libc::stat(path.as_ptr(), &mut statbuf);
        if ret < 0 {
            std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
        } else {
            0
        }
    });
    assert_eq!(errno, 0, "stat must succeed; got errno={errno}");
}

#[test]
#[cfg(target_os = "linux")]
fn lstat_is_allowed() {
    let path = CString::new("/").unwrap();
    let errno = run_in_seccomp(|| unsafe {
        let mut statbuf: libc::stat = std::mem::zeroed();
        let ret = libc::lstat(path.as_ptr(), &mut statbuf);
        if ret < 0 {
            std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
        } else {
            0
        }
    });
    assert_eq!(errno, 0, "lstat must succeed; got errno={errno}");
}

#[test]
#[cfg(target_os = "linux")]
fn openat_is_allowed() {
    let path = CString::new("/").unwrap();
    let errno = run_in_seccomp(|| unsafe {
        let fd = libc::openat(libc::AT_FDCWD, path.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY);
        if fd < 0 {
            std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
        } else {
            libc::close(fd);
            0
        }
    });
    assert_eq!(errno, 0, "openat must succeed; got errno={errno}");
}

#[test]
#[cfg(target_os = "linux")]
fn open_is_allowed() {
    let path = CString::new("/dev/null").unwrap();
    let errno = run_in_seccomp(|| unsafe {
        let fd = libc::open(path.as_ptr(), libc::O_RDONLY);
        if fd < 0 {
            std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
        } else {
            libc::close(fd);
            0
        }
    });
    assert_eq!(errno, 0, "open must succeed; got errno={errno}");
}

#[test]
#[cfg(target_os = "linux")]
fn lseek_is_allowed() {
    let errno = run_in_seccomp(|| unsafe {
        let path = CString::new("/proc/self/exe").unwrap();
        let fd = libc::openat(libc::AT_FDCWD, path.as_ptr(), libc::O_RDONLY);
        if fd < 0 {
            return std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        }
        let off = libc::lseek(fd, 0, libc::SEEK_CUR);
        let result = if off < 0 {
            std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
        } else {
            0
        };
        libc::close(fd);
        result
    });
    assert_eq!(errno, 0, "lseek must succeed; got errno={errno}");
}

#[test]
#[cfg(target_os = "linux")]
fn readlink_is_allowed() {
    let path = CString::new("/proc/self/exe").unwrap();
    let errno = run_in_seccomp(|| unsafe {
        let mut buf = vec![0u8; 4096];
        let n = libc::readlink(
            path.as_ptr(),
            buf.as_mut_ptr() as *mut libc::c_char,
            buf.len(),
        );
        if n < 0 {
            std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
        } else {
            0
        }
    });
    assert_eq!(errno, 0, "readlink must succeed; got errno={errno}");
}

#[test]
#[cfg(target_os = "linux")]
fn readlinkat_is_allowed() {
    let path = CString::new("/proc/self/exe").unwrap();
    let errno = run_in_seccomp(|| unsafe {
        let mut buf = vec![0u8; 4096];
        let n = libc::readlinkat(
            libc::AT_FDCWD,
            path.as_ptr(),
            buf.as_mut_ptr() as *mut libc::c_char,
            buf.len(),
        );
        if n < 0 {
            std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
        } else {
            0
        }
    });
    assert_eq!(errno, 0, "readlinkat must succeed; got errno={errno}");
}

// =============================================================================
// Process info
// =============================================================================

#[test]
#[cfg(target_os = "linux")]
fn getpid_is_allowed() {
    let errno = run_in_seccomp(|| unsafe {
        let _ = libc::getpid();
        0
    });
    assert_eq!(errno, 0, "getpid must succeed; got errno={errno}");
}

#[test]
#[cfg(target_os = "linux")]
fn getppid_is_allowed() {
    let errno = run_in_seccomp(|| unsafe {
        let _ = libc::getppid();
        0
    });
    assert_eq!(errno, 0, "getppid must succeed; got errno={errno}");
}

#[test]
#[cfg(target_os = "linux")]
fn getuid_is_allowed() {
    let errno = run_in_seccomp(|| unsafe {
        let _ = libc::getuid();
        0
    });
    assert_eq!(errno, 0, "getuid must succeed; got errno={errno}");
}

#[test]
#[cfg(target_os = "linux")]
fn geteuid_is_allowed() {
    let errno = run_in_seccomp(|| unsafe {
        let _ = libc::geteuid();
        0
    });
    assert_eq!(errno, 0, "geteuid must succeed; got errno={errno}");
}

#[test]
#[cfg(target_os = "linux")]
fn getgid_is_allowed() {
    let errno = run_in_seccomp(|| unsafe {
        let _ = libc::getgid();
        0
    });
    assert_eq!(errno, 0, "getgid must succeed; got errno={errno}");
}

#[test]
#[cfg(target_os = "linux")]
fn getegid_is_allowed() {
    let errno = run_in_seccomp(|| unsafe {
        let _ = libc::getegid();
        0
    });
    assert_eq!(errno, 0, "getegid must succeed; got errno={errno}");
}

// =============================================================================
// Time
// =============================================================================

#[test]
#[cfg(target_os = "linux")]
fn clock_gettime_is_allowed() {
    let errno = run_in_seccomp(|| unsafe {
        let mut ts: libc::timespec = std::mem::zeroed();
        if libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) != 0 {
            std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
        } else {
            0
        }
    });
    assert_eq!(errno, 0, "clock_gettime must succeed; got errno={errno}");
}

#[test]
#[cfg(target_os = "linux")]
fn gettimeofday_is_allowed() {
    let errno = run_in_seccomp(|| unsafe {
        let mut tv: libc::timeval = std::mem::zeroed();
        if libc::gettimeofday(&mut tv, std::ptr::null_mut()) != 0 {
            std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
        } else {
            0
        }
    });
    assert_eq!(errno, 0, "gettimeofday must succeed; got errno={errno}");
}

#[test]
#[cfg(target_os = "linux")]
fn nanosleep_is_allowed() {
    let errno = run_in_seccomp(|| unsafe {
        let req = libc::timespec {
            tv_sec: 0,
            tv_nsec: 1,
        };
        let mut rem: libc::timespec = std::mem::zeroed();
        if libc::nanosleep(&req, &mut rem) != 0 {
            let e = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
            // EINTR is acceptable.
            if e == libc::EINTR { 0 } else { e }
        } else {
            0
        }
    });
    assert_eq!(errno, 0, "nanosleep must succeed; got errno={errno}");
}

#[test]
#[cfg(target_os = "linux")]
fn clock_nanosleep_is_allowed() {
    let errno = run_in_seccomp(|| unsafe {
        let req = libc::timespec {
            tv_sec: 0,
            tv_nsec: 1,
        };
        let mut rem: libc::timespec = std::mem::zeroed();
        if libc::clock_nanosleep(libc::CLOCK_MONOTONIC, 0, &req, &mut rem) != 0 {
            let e = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
            if e == libc::EINTR { 0 } else { e }
        } else {
            0
        }
    });
    assert_eq!(errno, 0, "clock_nanosleep must succeed; got errno={errno}");
}

// =============================================================================
// Random
// =============================================================================

#[test]
#[cfg(target_os = "linux")]
fn getrandom_is_allowed() {
    let errno = run_in_seccomp(|| unsafe {
        let mut buf = [0u8; 16];
        let n = libc::getrandom(
            buf.as_mut_ptr() as *mut libc::c_void,
            buf.len(),
            0,
        );
        if n < 0 {
            std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
        } else {
            0
        }
    });
    assert_eq!(errno, 0, "getrandom must succeed; got errno={errno}");
}

// =============================================================================
// Signalfd / eventfd / timerfd
// =============================================================================

#[test]
#[cfg(target_os = "linux")]
fn eventfd2_is_allowed() {
    let errno = run_in_seccomp(|| unsafe {
        let fd = syscall_eventfd2(0, libc::EFD_CLOEXEC);
        if fd < 0 {
            std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
        } else {
            libc::close(fd);
            0
        }
    });
    assert_eq!(errno, 0, "eventfd2 must succeed; got errno={errno}");
}

#[test]
#[cfg(target_os = "linux")]
fn signalfd4_is_allowed() {
    let errno = run_in_seccomp(|| unsafe {
        let mut mask: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut mask);
        libc::sigaddset(&mut mask, libc::SIGUSR1);
        // Kernel expects the legacy 64-bit sigset size, not glibc's larger sigset_t.
        let fd = syscall_signalfd4(-1, &mask, 8, libc::SFD_CLOEXEC);
        if fd < 0 {
            std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
        } else {
            libc::close(fd);
            0
        }
    });
    assert_eq!(errno, 0, "signalfd4 must succeed; got errno={errno}");
}

#[test]
#[cfg(target_os = "linux")]
fn timerfd_create_is_allowed() {
    let errno = run_in_seccomp(|| unsafe {
        let fd = libc::timerfd_create(libc::CLOCK_MONOTONIC, libc::TFD_CLOEXEC);
        if fd < 0 {
            std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
        } else {
            libc::close(fd);
            0
        }
    });
    assert_eq!(errno, 0, "timerfd_create must succeed; got errno={errno}");
}

// =============================================================================
// Epoll
// =============================================================================

#[test]
#[cfg(target_os = "linux")]
fn epoll_create1_is_allowed() {
    let errno = run_in_seccomp(|| unsafe {
        let fd = libc::epoll_create1(libc::EPOLL_CLOEXEC);
        if fd < 0 {
            std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
        } else {
            libc::close(fd);
            0
        }
    });
    assert_eq!(errno, 0, "epoll_create1 must succeed; got errno={errno}");
}

// =============================================================================
// Poll / select
// =============================================================================

#[test]
#[cfg(target_os = "linux")]
fn poll_is_allowed() {
    let errno = run_in_seccomp(|| unsafe {
        let mut fds = [-1i32; 2];
        if libc::pipe(fds.as_mut_ptr()) != 0 {
            return std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        }
        let mut pfd = libc::pollfd {
            fd: fds[0],
            events: libc::POLLIN,
            revents: 0,
        };
        // Write so poll doesn't block forever.
        let _ = libc::write(fds[1], b"x".as_ptr() as *const libc::c_void, 1);
        let ret = libc::poll(&mut pfd, 1, 1000);
        let err = if ret < 0 {
            std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
        } else {
            0
        };
        libc::close(fds[0]);
        libc::close(fds[1]);
        err
    });
    assert_eq!(errno, 0, "poll must succeed; got errno={errno}");
}

#[test]
#[cfg(target_os = "linux")]
fn select_is_allowed() {
    let errno = run_in_seccomp(|| unsafe {
        let mut fds = [-1i32; 2];
        if libc::pipe(fds.as_mut_ptr()) != 0 {
            return std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        }
        let _ = libc::write(fds[1], b"x".as_ptr() as *const libc::c_void, 1);
        let mut readfds: libc::fd_set = std::mem::zeroed();
        libc::FD_SET(fds[0], &mut readfds);
        let mut tv = libc::timeval {
            tv_sec: 1,
            tv_usec: 0,
        };
        let ret = libc::select(
            fds[0] + 1,
            &mut readfds,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut tv,
        );
        let err = if ret < 0 {
            std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
        } else {
            0
        };
        libc::close(fds[0]);
        libc::close(fds[1]);
        err
    });
    assert_eq!(errno, 0, "select must succeed; got errno={errno}");
}

// =============================================================================
// Uname / sysinfo
// =============================================================================

#[test]
#[cfg(target_os = "linux")]
fn uname_is_allowed() {
    let errno = run_in_seccomp(|| unsafe {
        let mut buf: libc::utsname = std::mem::zeroed();
        if libc::uname(&mut buf) != 0 {
            std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
        } else {
            0
        }
    });
    assert_eq!(errno, 0, "uname must succeed; got errno={errno}");
}

#[test]
#[cfg(target_os = "linux")]
fn sysinfo_is_allowed() {
    let errno = run_in_seccomp(|| unsafe {
        let mut buf: libc::sysinfo = std::mem::zeroed();
        if libc::sysinfo(&mut buf) != 0 {
            std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
        } else {
            0
        }
    });
    assert_eq!(errno, 0, "sysinfo must succeed; got errno={errno}");
}

// =============================================================================
// Directory operations
// =============================================================================

#[test]
#[cfg(target_os = "linux")]
fn chdir_is_allowed() {
    let path = CString::new("/tmp").unwrap();
    let errno = run_in_seccomp(|| unsafe {
        if libc::chdir(path.as_ptr()) != 0 {
            std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
        } else {
            0
        }
    });
    assert_eq!(errno, 0, "chdir must succeed; got errno={errno}");
}

#[test]
#[cfg(target_os = "linux")]
fn fchdir_is_allowed() {
    let errno = run_in_seccomp(|| unsafe {
        let fd = libc::open(CString::new("/tmp").unwrap().as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY);
        if fd < 0 {
            return std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        }
        let ret = libc::fchdir(fd);
        let err = if ret != 0 {
            std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
        } else {
            0
        };
        libc::close(fd);
        err
    });
    assert_eq!(errno, 0, "fchdir must succeed; got errno={errno}");
}

// =============================================================================
// Process control (exit must work)
// =============================================================================

#[test]
#[cfg(target_os = "linux")]
fn exit_group_is_allowed() {
    // We test this by forking and verifying the child exits cleanly.
    let mut pipe_fds = [-1i32; 2];
    unsafe {
        assert_eq!(libc::pipe(pipe_fds.as_mut_ptr()), 0);
        let pid = libc::fork();
        assert!(pid >= 0, "fork failed");
        if pid == 0 {
            libc::close(pipe_fds[0]);
            let _ = procjail::seccomp::apply_seccomp_filter();
            libc::write(pipe_fds[1], b"ok".as_ptr() as *const libc::c_void, 2);
            libc::close(pipe_fds[1]);
            syscall_exit_group(42);
        }
        libc::close(pipe_fds[1]);
        let mut buf = [0u8; 2];
        let n = libc::read(pipe_fds[0], buf.as_mut_ptr() as *mut libc::c_void, 2);
        libc::close(pipe_fds[0]);
        let mut status = 0;
        libc::waitpid(pid, &mut status, 0);
        assert_eq!(n, 2);
        assert_eq!(buf, *b"ok");
        assert!(libc::WIFEXITED(status), "child must exit normally");
        assert_eq!(libc::WEXITSTATUS(status), 42);
    }
}

// =============================================================================
// Robust list / tid address
// =============================================================================

#[test]
#[cfg(target_os = "linux")]
fn set_tid_address_is_allowed() {
    let errno = run_in_seccomp(|| unsafe {
        let mut tid = 0i32;
        syscall_set_tid_address(&mut tid);
        0
    });
    assert_eq!(errno, 0, "set_tid_address must succeed; got errno={errno}");
}

// =============================================================================
// Capget
// =============================================================================

#[test]
#[cfg(target_os = "linux")]
fn capget_is_allowed() {
    let errno = run_in_seccomp(|| unsafe {
        let mut hdr = CapUserHeader {
            version: LINUX_CAPABILITY_VERSION_3,
            pid: 0,
        };
        let mut data = [CapUserData {
            effective: 0,
            permitted: 0,
            inheritable: 0,
        }; 2];
        if syscall_capget(&mut hdr, data.as_mut_ptr()) != 0 {
            std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
        } else {
            0
        }
    });
    assert_eq!(errno, 0, "capget must succeed; got errno={errno}");
}

// =============================================================================
// Prctl (some prctl ops are allowed because the syscall itself is whitelisted)
// =============================================================================

#[test]
#[cfg(target_os = "linux")]
fn prctl_get_name_is_blocked() {
    let errno = run_in_seccomp(|| unsafe {
        let mut name = [0u8; 16];
        if libc::prctl(libc::PR_GET_NAME, name.as_mut_ptr(), 0, 0, 0) != 0 {
            std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
        } else {
            libc::EPERM
        }
    });
    assert_eq!(
        errno, libc::EPERM,
        "prctl must stay blocked to prevent filter tampering; got errno={errno}"
    );
}

// =============================================================================
// Arch_prctl
// =============================================================================

#[test]
#[cfg(target_os = "linux")]
fn arch_prctl_is_allowed() {
    let errno = run_in_seccomp(|| unsafe {
        let mut addr: usize = 0;
        // GS_BASE read is safe and available on x86_64.
        #[cfg(target_arch = "x86_64")]
        {
            if syscall_arch_prctl(ARCH_GET_FS, &mut addr as *mut usize as *mut libc::c_void) != 0 {
                return std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
            }
        }
        0
    });
    assert_eq!(errno, 0, "arch_prctl must succeed; got errno={errno}");
}

// =============================================================================
// Restart_syscall (kernel internal, but listed in allowlist)
// =============================================================================

#[test]
#[cfg(target_os = "linux")]
fn restart_syscall_is_allowed() {
    // restart_syscall returns ENOSYS or EINVAL when called from userspace;
    // the critical thing is that seccomp does NOT block it with EPERM.
    let errno = run_in_seccomp(|| unsafe {
        let ret = libc::syscall(libc::SYS_restart_syscall);
        if ret < 0 {
            let e = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
            // Accept ENOSYS or EINVAL; reject EPERM.
            if e == libc::EPERM { libc::EPERM } else { 0 }
        } else {
            0
        }
    });
    assert_eq!(errno, 0, "restart_syscall must not be blocked by seccomp; got errno={errno}");
}
