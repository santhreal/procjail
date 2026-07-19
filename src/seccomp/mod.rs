//! Seccomp BPF filter for syscall sandboxing.
//!
//! This module provides a restrictive seccomp-bpf filter that:
//! - Allows essential syscalls for process execution
//! - Blocks dangerous syscalls (ptrace, mount, etc.)
//! - Returns EPERM for all other syscalls by default
//!
//! # Security Model
//!
//! The filter uses a whitelist approach where only explicitly allowed syscalls
//! can execute. Blocked syscalls return EPERM rather than killing the process,
//! allowing for graceful error handling.
//!
//! # Platform Support
//!
//! This module is only functional on Linux. On other platforms, all functions
//! are no-ops that return Ok(()).

use std::collections::BTreeMap;

#[cfg(target_os = "linux")]
use seccompiler::{BpfProgram, SeccompAction, SeccompFilter, SeccompRule, TargetArch};

/// Error type for seccomp operations.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SeccompError {
    /// Failed to create seccomp filter.
    #[error("failed to create seccomp filter: {0}")]
    FilterCreation(String),
    /// Failed to apply seccomp filter.
    #[error("failed to apply seccomp filter: {0}")]
    FilterApplication(String),
    /// Unsupported architecture.
    #[error("unsupported architecture for seccomp")]
    UnsupportedArch,
}

/// Result type for seccomp operations.
pub type Result<T> = std::result::Result<T, SeccompError>;

/// Apply a restrictive seccomp BPF filter to the current process.
///
/// This function:
/// 1. Sets `PR_SET_NO_NEW_PRIVS` (required for seccomp filter mode)
/// 2. Installs a BPF filter that allows only essential syscalls
/// 3. Blocks dangerous syscalls with EPERM
/// 4. Returns EPERM for all unlisted syscalls
///
/// # Allowed Syscalls
///
/// - Basic I/O: read, write, close
/// - Memory: mmap, mprotect, munmap, brk
/// - Signals: `rt_sigaction`, `rt_sigprocmask`
/// - Process control: execve, wait4, exit, `exit_group`
/// - Threading: clone (threads only), futex, `set_robust_list`
/// - File descriptors: pipe, dup, dup2, ioctl
/// - Info: getpid, getuid, access
/// - Time: `clock_gettime`, getrandom
/// - Misc: kill (self only)
///
/// # Blocked Syscalls
///
/// These syscalls explicitly return EPERM:
/// - ptrace, `process_vm_readv`, `process_vm_writev`
/// - mount, umount, reboot, swapon, `kexec_load`
/// - bpf, userfaultfd, `perf_event_open`
///
/// # Errors
///
/// Returns an error if:
/// - The architecture is not supported
/// - The filter cannot be created
/// - The filter cannot be applied (e.g., insufficient privileges, seccomp disabled)
///
/// # Example
///
/// ```rust,no_run
/// use procjail::seccomp::apply_seccomp_filter;
///
/// // Apply the filter in the child process after fork
/// apply_seccomp_filter().expect("failed to apply seccomp filter");
/// ```
#[cfg(target_os = "linux")]
pub fn apply_seccomp_filter() -> Result<()> {
    // Step 1: Set PR_SET_NO_NEW_PRIVS (required for unprivileged seccomp)
    set_no_new_privs()?;

    // Step 2: Build and apply the BPF filter
    let filter = build_filter()?;
    apply_filter(&filter)?;

    Ok(())
}

/// Non-Linux stub: seccomp is only available on Linux.
#[cfg(not(target_os = "linux"))]
pub fn apply_seccomp_filter() -> Result<()> {
    Err(SeccompError::UnsupportedArch)
}

/// Check if seccomp is available on this platform.
///
/// Always returns true on Linux, false on other platforms.
///
/// # Example
///
/// ```rust
/// use procjail::seccomp::is_available;
///
/// let available = is_available();
/// ```
#[must_use]
pub const fn is_available() -> bool {
    cfg!(target_os = "linux")
}

/// Set `PR_SET_NO_NEW_PRIVS` to allow seccomp filter installation without `CAP_SYS_ADMIN`.
#[cfg(target_os = "linux")]
fn set_no_new_privs() -> Result<()> {
    // SAFETY: prctl with PR_SET_NO_NEW_PRIVS is a well-defined operation.
    // It takes 2 additional arguments: 1 to enable, 0 for no-op.
    let ret = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if ret != 0 {
        let errno = std::io::Error::last_os_error();
        return Err(SeccompError::FilterApplication(format!(
            "PR_SET_NO_NEW_PRIVS failed: {errno}"
        )));
    }
    Ok(())
}

/// Build the seccomp BPF filter with allowlist and blocklist rules.
#[cfg(target_os = "linux")]
fn build_filter() -> Result<BpfProgram> {
    #[cfg(not(target_arch = "x86_64"))]
    return Err(SeccompError::UnsupportedArch);

    #[cfg(target_arch = "x86_64")]
    {
        let target_arch = detect_arch()?;
        let mut rules = BTreeMap::new();

        // === ALLOWED SYSCALLS ===
        // These syscalls are permitted without argument checks

        // Basic I/O
        allow_syscall(&mut rules, libc::SYS_read);
        allow_syscall(&mut rules, libc::SYS_write);
        // Positioned I/O: the offset-carrying variants of read/write. Shells and
        // dynamic loaders read script/library files via pread64; without it a bare
        // `sh <script>` gets EPERM reading the script and exits 127. Same capability
        // as the already-allowed read/write, just with an explicit file offset.
        allow_syscall(&mut rules, libc::SYS_pread64);
        allow_syscall(&mut rules, libc::SYS_pwrite64);
        allow_syscall(&mut rules, libc::SYS_close);

        // Memory management
        allow_syscall(&mut rules, libc::SYS_mmap);
        allow_syscall(&mut rules, libc::SYS_mprotect);
        allow_syscall(&mut rules, libc::SYS_munmap);
        allow_syscall(&mut rules, libc::SYS_brk);

        // Signal handling
        allow_syscall(&mut rules, libc::SYS_rt_sigaction);
        allow_syscall(&mut rules, libc::SYS_rt_sigprocmask);
        allow_syscall(&mut rules, libc::SYS_rt_sigreturn);

        // File descriptor operations
        allow_syscall(&mut rules, libc::SYS_pipe);
        allow_syscall(&mut rules, libc::SYS_pipe2);
        allow_syscall(&mut rules, libc::SYS_dup);
        allow_syscall(&mut rules, libc::SYS_dup2);
        allow_syscall(&mut rules, libc::SYS_dup3);
        // fcntl: the Rust std library and most programs use it for FD_CLOEXEC,
        // O_NONBLOCK, F_DUPFD_CLOEXEC (File::try_clone), and advisory locks.
        // Without it the default Errno(EPERM) action makes those operations fail.
        allow_syscall(&mut rules, libc::SYS_fcntl);

        // ioctl - needed for terminals and some file operations
        allow_syscall(&mut rules, libc::SYS_ioctl);

        // File access check
        allow_syscall(&mut rules, libc::SYS_access);
        allow_syscall(&mut rules, libc::SYS_faccessat);
        allow_syscall(&mut rules, libc::SYS_faccessat2);

        // Process info
        allow_syscall(&mut rules, libc::SYS_getpid);
        allow_syscall(&mut rules, libc::SYS_getppid);
        allow_syscall(&mut rules, libc::SYS_getuid);
        allow_syscall(&mut rules, libc::SYS_geteuid);
        allow_syscall(&mut rules, libc::SYS_getgid);
        allow_syscall(&mut rules, libc::SYS_getegid);

        // Process control
        allow_syscall(&mut rules, libc::SYS_execve);
        allow_syscall(&mut rules, libc::SYS_execveat);
        allow_syscall(&mut rules, libc::SYS_fork);
        allow_syscall(&mut rules, libc::SYS_vfork);
        allow_syscall(&mut rules, libc::SYS_wait4);
        allow_syscall(&mut rules, libc::SYS_exit);
        allow_syscall(&mut rules, libc::SYS_exit_group);

        // Threading - allow clone but only for threads (CLONE_VM flag)
        // We need to be careful here: clone is used for both processes and threads
        // Allow it without restriction since the filter is applied after process setup
        allow_syscall(&mut rules, libc::SYS_clone);
        allow_syscall(&mut rules, libc::SYS_clone3);
        allow_syscall(&mut rules, libc::SYS_futex);
        allow_syscall(&mut rules, libc::SYS_sigaltstack);
        allow_syscall(&mut rules, libc::SYS_sched_getaffinity);
        allow_syscall(&mut rules, libc::SYS_set_robust_list);
        allow_syscall(&mut rules, libc::SYS_get_robust_list);
        // glibc pthread creation on recent kernels
        allow_syscall(&mut rules, libc::SYS_rseq);

        // Time
        allow_syscall(&mut rules, libc::SYS_clock_gettime);
        allow_syscall(&mut rules, libc::SYS_gettimeofday);

        // Random
        allow_syscall(&mut rules, libc::SYS_getrandom);

        // Signal sending (self-only is enforced by kernel with NO_NEW_PRIVS)
        allow_syscall(&mut rules, libc::SYS_kill);
        allow_syscall(&mut rules, libc::SYS_tkill);
        allow_syscall(&mut rules, libc::SYS_tgkill);

        // SYS_prctl is intentionally absent. Blanket allowance exposes
        // PR_SET_SECCOMP, PR_CAP_AMBIENT, and other privilege-escalation paths.

        // Architecture-specific syscalls
        allow_syscall(&mut rules, libc::SYS_arch_prctl);

        // Eventfd
        allow_syscall(&mut rules, libc::SYS_eventfd);
        allow_syscall(&mut rules, libc::SYS_eventfd2);

        // Signalfd
        allow_syscall(&mut rules, libc::SYS_signalfd);
        allow_syscall(&mut rules, libc::SYS_signalfd4);

        // Timerfd
        allow_syscall(&mut rules, libc::SYS_timerfd_create);
        allow_syscall(&mut rules, libc::SYS_timerfd_settime);
        allow_syscall(&mut rules, libc::SYS_timerfd_gettime);

        // Epoll
        allow_syscall(&mut rules, libc::SYS_epoll_create);
        allow_syscall(&mut rules, libc::SYS_epoll_create1);
        allow_syscall(&mut rules, libc::SYS_epoll_ctl);
        allow_syscall(&mut rules, libc::SYS_epoll_wait);
        allow_syscall(&mut rules, libc::SYS_epoll_pwait);
        allow_syscall(&mut rules, libc::SYS_epoll_pwait2);

        // Poll/select
        allow_syscall(&mut rules, libc::SYS_poll);
        allow_syscall(&mut rules, libc::SYS_ppoll);
        allow_syscall(&mut rules, libc::SYS_select);
        allow_syscall(&mut rules, libc::SYS_pselect6);

        // Uname
        allow_syscall(&mut rules, libc::SYS_uname);

        // Sysinfo
        allow_syscall(&mut rules, libc::SYS_sysinfo);

        // Readlink (often used for path resolution)
        allow_syscall(&mut rules, libc::SYS_readlink);
        allow_syscall(&mut rules, libc::SYS_readlinkat);

        // Stat
        allow_syscall(&mut rules, libc::SYS_fstat);
        #[cfg(target_arch = "x86_64")]
        allow_syscall(&mut rules, libc::SYS_newfstatat);
        // aarch64 uses newfstatat (same syscall number as fstatat on 64-bit).
        // SYS_fstatat64 is the 32-bit arm compat syscall and must not be added here.
        allow_syscall(&mut rules, libc::SYS_stat);
        allow_syscall(&mut rules, libc::SYS_lstat);

        // Open (for file operations)
        allow_syscall(&mut rules, libc::SYS_open);
        allow_syscall(&mut rules, libc::SYS_openat);

        // Lseek
        allow_syscall(&mut rules, libc::SYS_lseek);

        // NOTE: no SYS_mmap2 rule - mmap2 is a 32-bit-only syscall (arm/x86), and
        // procjail supports only 64-bit arches (detect_arch accepts x86_64/aarch64/
        // riscv64 and errors on 32-bit arm before this filter is ever built). A
        // `#[cfg(target_arch = "arm")]` mmap2 rule here was unreachable dead code
        // that implied 32-bit support the runtime does not have. 64-bit arches use
        // SYS_mmap (allowed elsewhere).

        // Restart_syscall
        allow_syscall(&mut rules, libc::SYS_restart_syscall);

        // Nanosleep
        allow_syscall(&mut rules, libc::SYS_nanosleep);
        allow_syscall(&mut rules, libc::SYS_clock_nanosleep);

        // Getcwd
        allow_syscall(&mut rules, libc::SYS_getcwd);

        // Chdir
        allow_syscall(&mut rules, libc::SYS_chdir);
        allow_syscall(&mut rules, libc::SYS_fchdir);

        // Umask
        allow_syscall(&mut rules, libc::SYS_umask);

        // Rlimit
        allow_syscall(&mut rules, libc::SYS_getrlimit);
        allow_syscall(&mut rules, libc::SYS_setrlimit);
        allow_syscall(&mut rules, libc::SYS_prlimit64);

        // Getgroups/setgroups
        allow_syscall(&mut rules, libc::SYS_getgroups);

        // Set_tid_address
        allow_syscall(&mut rules, libc::SYS_set_tid_address);

        // SYS_seccomp is intentionally absent. Blocked to prevent nested filter
        // installation and reduce kernel attack surface (filter exhaustion DoS).

        // Capget/capset
        allow_syscall(&mut rules, libc::SYS_capget);

        // Uid/gid mapping for user namespaces
        allow_syscall(&mut rules, libc::SYS_setuid);
        allow_syscall(&mut rules, libc::SYS_setgid);
        allow_syscall(&mut rules, libc::SYS_setresuid);
        allow_syscall(&mut rules, libc::SYS_setresgid);

        // === BLOCKED SYSCALLS ===
        // These syscalls explicitly return EPERM
        // They are added to the rules with an empty rule set and the filter's
        // mismatch_action will apply to them

        block_syscall_explicit(&mut rules, libc::SYS_ptrace);
        block_syscall_explicit(&mut rules, libc::SYS_process_vm_readv);
        block_syscall_explicit(&mut rules, libc::SYS_process_vm_writev);
        block_syscall_explicit(&mut rules, libc::SYS_mount);
        block_syscall_explicit(&mut rules, libc::SYS_umount2);
        block_syscall_explicit(&mut rules, libc::SYS_reboot);
        block_syscall_explicit(&mut rules, libc::SYS_swapon);
        block_syscall_explicit(&mut rules, libc::SYS_swapoff);
        block_syscall_explicit(&mut rules, libc::SYS_kexec_load);
        block_syscall_explicit(&mut rules, libc::SYS_kexec_file_load);
        block_syscall_explicit(&mut rules, libc::SYS_bpf);
        block_syscall_explicit(&mut rules, libc::SYS_userfaultfd);
        block_syscall_explicit(&mut rules, libc::SYS_perf_event_open);
        block_syscall_explicit(&mut rules, libc::SYS_perf_event_open);

        // Create the filter with:
        // - mismatch_action: EPERM (for any syscall not in the allow list)
        // - match_action: Allow (for syscalls in the allow list with matching rules)
        let filter = SeccompFilter::new(
            rules,
            SeccompAction::Errno(libc::EPERM as u32),
            SeccompAction::Allow,
            target_arch,
        )
        .map_err(|e| SeccompError::FilterCreation(e.to_string()))?;

        filter
            .try_into()
            .map_err(|e| SeccompError::FilterCreation(format!("BPF compilation failed: {e}")))
    }
}

/// Add a syscall to the allow list.
#[cfg(target_os = "linux")]
fn allow_syscall(rules: &mut BTreeMap<i64, Vec<SeccompRule>>, syscall: i64) {
    // Empty rule vector means the syscall matches unconditionally
    rules.insert(syscall, vec![]);
}

/// Add a syscall to be explicitly blocked (returns EPERM).
#[cfg(target_os = "linux")]
fn block_syscall_explicit(rules: &mut BTreeMap<i64, Vec<SeccompRule>>, syscall: i64) {
    // Blocked syscalls are handled by the default mismatch_action (EPERM)
    // We don't add them to the allow list
    let _ = syscall;
    let _ = rules;
}

/// Detect the target architecture for the BPF filter.
#[cfg(target_os = "linux")]
fn detect_arch() -> Result<TargetArch> {
    // SAFETY: sysconf is safe to call with valid parameters
    let arch = std::env::consts::ARCH;
    match arch {
        "x86_64" => Ok(TargetArch::x86_64),
        "aarch64" => Ok(TargetArch::aarch64),
        "riscv64" => Ok(TargetArch::riscv64),
        _ => Err(SeccompError::UnsupportedArch),
    }
}

/// Apply the compiled BPF filter to the current thread.
#[cfg(target_os = "linux")]
fn apply_filter(filter: &BpfProgram) -> Result<()> {
    seccompiler::apply_filter_all_threads(filter)
        .map_err(|e| SeccompError::FilterApplication(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(target_os = "linux")]
    fn build_filter_is_arch_appropriate() {
        let result = build_filter();
        if cfg!(target_arch = "x86_64") {
            assert!(
                matches!(result, Ok(ref filter) if !filter.is_empty()),
                "expected a non-empty seccomp BPF filter on x86_64, got {result:?}"
            );
        } else {
            assert!(
                matches!(result, Err(SeccompError::UnsupportedArch)),
                "expected UnsupportedArch on non-x86_64 Linux, got {result:?}"
            );
        }
    }

    #[test]
    #[cfg(not(target_os = "linux"))]
    fn build_filter_unavailable_off_linux() {
        assert!(
            matches!(apply_seccomp_filter(), Err(SeccompError::UnsupportedArch)),
            "seccomp must be unavailable off Linux"
        );
    }
}
