use std::fs;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::io::OwnedFd;

#[allow(clippy::similar_names)]
pub fn kill_process(pid: u32) -> bool {
    if pid == 0 {
        return false;
    }

    #[cfg(unix)]
    {
        // Guard against PID overflow: u32 values > i32::MAX would produce
        // negative values when cast to pid_t (i32). Negative PIDs sent to
        // kill() target process groups, and -1 broadcasts to ALL processes.
        let Ok(pid_i32) = i32::try_from(pid) else {
            eprintln!("[santh-sandbox] refusing to kill PID {pid}: exceeds i32::MAX");
            return false;
        };
        // SAFETY: libc::kill with a negative PID targets the entire process group.
        // Since we explicitly called `cmd.process_group(0)` on spawn,
        // the child PID acts as the process group leader, isolating all
        // descendants and preventing pipe leaks or orphaned fork-bombs.
        let pgid = -pid_i32;
        let ret = unsafe { libc::kill(pgid, libc::SIGKILL) };
        if ret != 0 {
            // ESRCH (no such process) is expected if process already exited.
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() != Some(libc::ESRCH) {
                eprintln!("[santh-sandbox] kill({pid}, SIGKILL) failed: {err}");
            }
            return false;
        }
        // Avoid blocking on an unrelated or already-reaped child.
        let wait_ret = unsafe { libc::waitpid(pid_i32, std::ptr::null_mut(), libc::WNOHANG) };
        if wait_ret < 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() != Some(libc::ECHILD) {
                eprintln!("[santh-sandbox] waitpid({pid}, WNOHANG) failed: {err}");
            }
        }
        true
    }
    #[cfg(not(unix))]
    {
        let _ = pid;
        false
    }
}

#[cfg(target_os = "linux")]
pub fn open_pidfd(pid: u32) -> Option<OwnedFd> {
    if pid == 0 || pid > i32::MAX as u32 {
        return None;
    }

    let pid_i32 = i32::try_from(pid).ok()?;

    // SAFETY: `syscall` is invoked with the documented pidfd_open arguments.
    // PIDFD_NONBLOCK is set for immediate readiness polling; CLOEXEC is added
    // via fcntl so the fd is not leaked to any child processes.
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid_i32, libc::PIDFD_NONBLOCK) };
    if fd < 0 {
        return None;
    }

    let fd_i32 = i32::try_from(fd).ok()?;
    // SAFETY: the kernel returned a fresh owned file descriptor.
    unsafe {
        // Fail closed if close-on-exec cannot be set: an fd without FD_CLOEXEC
        // would leak into every spawned child, which in a sandbox is a real
        // escape/leak vector. Close it and report no pidfd rather than hand back
        // a leaky descriptor.
        if libc::fcntl(fd_i32, libc::F_SETFD, libc::FD_CLOEXEC) < 0 {
            libc::close(fd_i32);
            return None;
        }
        Some(OwnedFd::from_raw_fd(fd_i32))
    }
}

#[cfg(target_os = "linux")]
pub fn kill_process_pidfd(pidfd: &OwnedFd, fallback_pid: u32) -> bool {
    // SAFETY: `pidfd_send_signal` operates on a valid pidfd and does not require
    // additional invariants beyond passing null siginfo and zero flags.
    let ret = unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            pidfd.as_raw_fd(),
            libc::SIGKILL,
            std::ptr::null::<libc::siginfo_t>(),
            0,
        )
    };
    if ret != 0 {
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::ESRCH) {
            return false;
        }

        // If pidfd_send_signal is blocked (e.g. Docker default seccomp profile)
        // or unimplemented natively, fallback unconditionally to old style kill
        return kill_process(fallback_pid);
    }
    true
}

#[cfg(target_os = "linux")]
pub fn peak_memory_bytes_for_process(pid: u32) -> Option<u64> {
    let path = format!("/proc/{pid}/status");
    let status = fs::read_to_string(path).ok()?;

    for line in status.lines() {
        if !line.starts_with("VmPeak:") {
            continue;
        }
        let fields: Vec<_> = line.split_whitespace().collect();
        if fields.len() < 2 {
            return None;
        }
        let kb = fields[1].parse::<u64>().ok()?;
        return Some(kb.saturating_mul(1024));
    }

    None
}

#[cfg(not(target_os = "linux"))]
pub fn peak_memory_bytes_for_process(_pid: u32) -> Option<u64> {
    None
}

#[cfg(target_os = "linux")]
pub fn cpu_time_secs_for_process(pid: u32) -> Option<f64> {
    let path = format!("/proc/{pid}/stat");
    let stat = fs::read_to_string(path).ok()?;

    let (_, rest) = stat.split_once(") ")?;
    let parts: Vec<&str> = rest.split_whitespace().collect();
    if parts.len() < 15 {
        return None;
    }

    let utime = parts[11].parse::<f64>().ok()?;
    let stime = parts[12].parse::<f64>().ok()?;
    let ticks_per_sec = clock_ticks_per_second();
    if ticks_per_sec <= 0.0 {
        return None;
    }
    Some((utime + stime) / ticks_per_sec)
}

#[cfg(not(target_os = "linux"))]
pub fn cpu_time_secs_for_process(_pid: u32) -> Option<f64> {
    None
}

#[cfg(target_os = "linux")]
fn clock_ticks_per_second() -> f64 {
    let ticks = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    if ticks <= 0 {
        return 0.0;
    }
    // `ticks` is a small positive clock rate (CLK_TCK is ~100 Hz), so a direct
    // cast is exact - the old `u32::try_from(ticks).unwrap_or(100)` would have
    // silently substituted 100 on an implausible overflow instead of using the
    // real value the kernel reported.
    #[allow(clippy::cast_precision_loss)]
    let ticks_f64 = ticks as f64;
    ticks_f64
}
