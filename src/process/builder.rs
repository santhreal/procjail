
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::Duration;

#[cfg(target_os = "linux")]
use std::os::fd::OwnedFd;

use anyhow::Result as AnyResult;

use crate::error::BuildCommandError;
use crate::process::kill::kill_process;
use crate::process::MAX_ENV_VALUE_BYTES;
use crate::{EnvMode, Result, SandboxConfig, SandboxedIO, SandboxedProcess, Strategy};

#[cfg(target_os = "linux")]
use crate::process::kill::kill_process_pidfd;

/// - Mount configs applied to all strategies that support them
pub fn build_command(
    runtime: &Path,
    harness_path: &Path,
    work_dir: &Path,
    config: &SandboxConfig,
    strategy: Strategy,
) -> std::result::Result<Command, BuildCommandError> {
    // SECURITY: Validate work_dir is absolute to prevent path escape.
    if !work_dir.is_absolute() {
        return Err(BuildCommandError::WorkDirNotAbsolute {
            path: work_dir.to_path_buf(),
        });
    }

    // Validate harness_path is non-empty.
    if harness_path.as_os_str().is_empty() {
        return Err(BuildCommandError::HarnessPathEmpty);
    }
    if !harness_path.is_absolute() {
        return Err(BuildCommandError::HarnessPathNotAbsolute {
            path: harness_path.to_path_buf(),
        });
    }
    validate_environment(config)?;

    if let Some(ref provider) = config.custom_provider {
        let mut cmd = Command::new(runtime);
        // Runtime args (before harness).
        for arg in &config.runtime_args {
            cmd.arg(arg);
        }
        // Harness script.
        cmd.arg(harness_path);

        if let Err(e) = provider.apply_to_command(&mut cmd, runtime, work_dir, config) {
            return Err(BuildCommandError::ProviderRejected {
                name: provider.name().to_string(),
                reason: e.to_string(),
            });
        }
        apply_environment(&mut cmd, config, work_dir);
        // Apply standard deep isolation unconditionally even when a custom
        // provider is active. The provider mutates cmd; we enforce rlimits
        // and seccomp after that.
        apply_pre_exec_isolation(&mut cmd, config);
        cmd.process_group(0);
        return Ok(cmd);
    }

    let mut cmd = match strategy {
        Strategy::Unshare => build_unshare_command(runtime, config),
        Strategy::Bubblewrap => build_bwrap_command(runtime, harness_path, work_dir, config)?,
        Strategy::Firejail => build_firejail_command(runtime, work_dir, config)?,
        Strategy::RlimitsOnly | Strategy::None => build_rlimits_command(runtime),
    };

    // Runtime args (before harness).
    for arg in &config.runtime_args {
        cmd.arg(arg);
    }

    // Harness script.
    cmd.arg(harness_path);
    // Pass the bound work dir to the harness as its first script argument.
    // This keeps the spawn contract generic while supporting runtimes like
    // Node and Python that conventionally read argv[2] / sys.argv[1].
    cmd.arg(work_dir);

    apply_environment(&mut cmd, config, work_dir);

    // Deep isolation check before exec payload to stop privileged escalation chains.
    // Apply kernel rlimits first and then attempt seccomp.
    apply_pre_exec_isolation(&mut cmd, config);

    cmd.process_group(0);

    Ok(cmd)
}

fn validate_environment(config: &SandboxConfig) -> std::result::Result<(), BuildCommandError> {
    for (key, value) in &config.env_set {
        if key.is_empty() {
            return Err(BuildCommandError::EmptyEnvName);
        }
        if key.contains('=') || key.contains('\0') || key.chars().any(char::is_whitespace) {
            return Err(BuildCommandError::InvalidEnvName { name: key.clone() });
        }
        if value.contains('\0') {
            return Err(BuildCommandError::EnvValueContainsNul { key: key.clone() });
        }
        if value.len() > MAX_ENV_VALUE_BYTES {
            return Err(BuildCommandError::EnvValueTooLarge {
                key: key.clone(),
                max_bytes: MAX_ENV_VALUE_BYTES,
            });
        }
    }
    Ok(())
}

fn apply_environment(cmd: &mut Command, config: &SandboxConfig, work_dir: &Path) {
    // Environment handling  -  order matters for security.
    // Step 1: Start with the right base.
    match config.env_mode {
        EnvMode::Allowlist => {
            // Clear everything, then add only allowed vars.
            cmd.env_clear();
            for (key, val) in std::env::vars() {
                // SECURITY FIX: env_passthrough CANNOT re-add secrets.
                if config.env_passthrough.contains(&key) && !config.is_secret_env_var(&key) {
                    cmd.env(&key, &val);
                }
            }
        }
        EnvMode::StripSecrets => {
            // Keep everything except known secrets.
            for (key, _) in std::env::vars() {
                if config.is_secret_env_var(&key) {
                    cmd.env_remove(&key);
                }
            }
            // Passthrough is a no-op in this mode  -  vars are already present
            // unless they're secrets (which we just stripped).
        }
        EnvMode::Blocklist => {
            // Keep everything except explicitly blocked + secrets.
            for (key, _) in std::env::vars() {
                if config.is_secret_env_var(&key) {
                    cmd.env_remove(&key);
                }
            }
        }
    }

    // Step 2: Set custom env vars  -  SECURITY: cannot set known secrets.
    for (key, val) in &config.env_set {
        if config.is_secret_env_var(key) {
            eprintln!("[santh-sandbox] WARNING: env_set tried to set secret '{key}'  -  blocked");
            continue;
        }
        cmd.env(key, val);
    }

    // Step 3: Always set internal sandbox control vars (after everything else).
    cmd.env("SANTH_MAX_MEMORY", config.max_memory_bytes.to_string());
    cmd.env("SANTH_MAX_CPU", config.max_cpu_seconds.to_string());
    cmd.env("SANTH_MAX_FDS", config.max_fds.to_string());
    cmd.env("SANTH_MAX_PROCESSES", config.max_processes.to_string());
    cmd.env("SANTH_WORK_DIR", work_dir);
}

/// Close all file descriptors > 2 before exec to prevent inherited fd leaks.
///
/// Attempts `close_range(3, u32::MAX, 0)` first (Linux 5.11+), then falls back
/// to iterating `/proc/self/fd`.
fn close_inherited_fds() -> std::io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        let ret = unsafe { libc::syscall(libc::SYS_close_range, 3u32, u32::MAX, 0u32) };
        if ret == 0 {
            return Ok(());
        }
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() != Some(libc::ENOSYS) {
            return Err(err);
        }
    }

    // Fallback: collect fds first so we don't close the iterator itself.
    let mut to_close = Vec::new();
    if let Ok(dir) = std::fs::read_dir("/proc/self/fd") {
        for entry in dir.flatten() {
            if let Ok(name) = entry.file_name().into_string() {
                if let Ok(fd) = name.parse::<i32>() {
                    if fd > 2 {
                        to_close.push(fd);
                    }
                }
            }
        }
    }
    for fd in to_close {
        unsafe { libc::close(fd) };
    }
    Ok(())
}

/// Count threads owned by the given real UID.
///
/// `RLIMIT_NPROC` is per-user and counts kernel tasks, not just processes, so
/// the limit must be set relative to the current UID task count rather than an
/// absolute sandbox cap.
fn count_threads_for_uid(uid: u32) -> u64 {
    let mut count = 0u64;
    if let Ok(dir) = std::fs::read_dir("/proc") {
        for entry in dir.flatten() {
            if entry.file_name().to_string_lossy().parse::<u32>().is_err() {
                continue;
            }
            let status = entry.path().join("status");
            if let Ok(content) = std::fs::read_to_string(&status) {
                let uid_ok = content
                    .lines()
                    .find(|line| line.starts_with("Uid:"))
                    .map_or(false, |line| {
                        line.split_whitespace()
                            .nth(1)
                            .and_then(|s| s.parse::<u32>().ok())
                            .unwrap_or(u32::MAX)
                            == uid
                    });
                if uid_ok {
                    if let Some(line) = content.lines().find(|line| line.starts_with("Threads:")) {
                        if let Some(n) = line.split_whitespace().nth(1) {
                            if let Ok(n) = n.parse::<u64>() {
                                count += n;
                            }
                        }
                    }
                }
            }
        }
    }
    count
}
/// Return the RLIMIT_NPROC soft/hard limit for the current real UID.
///
/// The limit is the current UID thread count plus the configured sandbox
/// headroom plus a small fixed buffer so the child can make at least one
/// `fork`/`vfork` call before the cgroup pids controller is attached.
fn nproc_limit_for_uid(max_processes: u64) -> u64 {
    let uid = unsafe { libc::getuid() };
    count_threads_for_uid(uid)
        .saturating_add(max_processes)
        .saturating_add(64)
}


/// Apply rlimits and seccomp in a `pre_exec` closure.
///
/// This is invoked for **all** strategies (including custom providers) so that
/// kernel-enforced resource limits and syscall filtering are never silently
/// skipped.
///
/// # Note on `RLIMIT_AS`
///
/// `RLIMIT_AS` limits virtual address space, not resident memory. A runtime
/// with large shared libraries may hit this ceiling while using far less
/// physical RAM. For accurate RAM containment, ensure cgroups v2 is available.
fn apply_pre_exec_isolation(cmd: &mut Command, config: &SandboxConfig) {
    let max_mem = config.max_memory_bytes;
    let max_cpu = config.max_cpu_seconds;
    let max_fds = config.max_fds;
    // Compute the NPROC limit in the parent; pre_exec is after fork and must not
    // do I/O or allocation (the heap may be in an inconsistent state in a
    // multi-threaded parent after fork).
    let nproc_limit = nproc_limit_for_uid(config.max_processes);
    unsafe {
        cmd.pre_exec(move || {
            if let Err(e) = close_inherited_fds() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("Fix: close all fds >2 before exec to prevent information leaks. {e}")
                ));
            }

            let rlim_as = libc::rlimit {
                rlim_cur: max_mem as libc::rlim_t,
                rlim_max: max_mem as libc::rlim_t,
            };
            if libc::setrlimit(libc::RLIMIT_AS, &raw const rlim_as) != 0 {
                return Err(std::io::Error::last_os_error());
            }

            let rlim_cpu = libc::rlimit {
                rlim_cur: max_cpu as libc::rlim_t,
                rlim_max: max_cpu as libc::rlim_t,
            };
            if libc::setrlimit(libc::RLIMIT_CPU, &raw const rlim_cpu) != 0 {
                return Err(std::io::Error::last_os_error());
            }

            let rlim_nofile = libc::rlimit {
                rlim_cur: max_fds as libc::rlim_t,
                rlim_max: max_fds as libc::rlim_t,
            };
            if libc::setrlimit(libc::RLIMIT_NOFILE, &raw const rlim_nofile) != 0 {
                return Err(std::io::Error::last_os_error());
            }

            // RLIMIT_NPROC is per-real-UID, not per-sandbox. The limit was
            // computed relative to the current UID thread count so the child can
            // fork without being killed by a low absolute cap.
            let rlim_nproc = libc::rlimit {
                rlim_cur: nproc_limit as libc::rlim_t,
                rlim_max: nproc_limit as libc::rlim_t,
            };
            if libc::setrlimit(libc::RLIMIT_NPROC, &raw const rlim_nproc) != 0 {
                return Err(std::io::Error::last_os_error());
            }

            if let Err(e) = crate::seccomp::apply_seccomp_filter() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("Fix: verify kernel has CONFIG_SECCOMP=y and container runtime does not block prctl(PR_SET_SECCOMP). {e}")
                ));
            }
            Ok(())
        });
    }
}

fn build_unshare_command(runtime: &Path, config: &SandboxConfig) -> Command {
    // NOTE: unshare with --mount creates a new mount namespace but does
    // NOT restrict filesystem visibility by itself. The sandboxed process
    // inherits all existing mounts. True filesystem restriction requires
    // pivot_root or additional mount operations inside the namespace.
    //
    // For full filesystem isolation, prefer Bubblewrap (Strategy::Bubblewrap).
    // Unshare provides: PID isolation + network isolation + mount namespace
    // (preventing mount changes from leaking to parent).
    let mut cmd = Command::new("unshare");
    cmd.args([
        "--pid",
        "--fork",
        "--mount-proc",
        "--mount",
        "--map-root-user",
    ]);
    if !config.allow_localhost {
        cmd.arg("--net");
    }
    cmd.arg("--");
    cmd.arg(runtime);
    cmd
}

fn build_bwrap_command(
    runtime: &Path,
    harness_path: &Path,
    work_dir: &Path,
    config: &SandboxConfig,
) -> std::result::Result<Command, BuildCommandError> {
    let mut cmd = Command::new("bwrap");
    // Use an empty tmpfs root and only bind specific host paths to avoid exposing host '/'.
    cmd.args(["--tmpfs", "/"]);
    cmd.args(["--tmpfs", "/tmp"]);
    cmd.args(["--proc", "/proc"]);
    cmd.args(["--dev", "/dev"]);

    // The tmpfs root has no /usr, /bin, /lib, or /lib64. A bare-name runtime
    // like "sh" resolves to /bin/sh inside the sandbox and must be able to find
    // its binary and loader. Bind the system directories read-only (with -try
    // for optional dirs like /lib64 on merged-/usr hosts) before the per-test
    // mounts so the sandbox can exec any runtime available on the host.
    cmd.args(["--ro-bind", "/usr", "/usr"]);
    for dir in ["/bin", "/lib", "/lib64"] {
        cmd.args(["--ro-bind-try", dir, dir]);
    }

    // Fix: canonicalize all mount paths to prevent symlink races.
    let wd =
        std::fs::canonicalize(work_dir).map_err(|_| BuildCommandError::CanonicalizationFailed {
            path: work_dir.to_path_buf(),
        })?;
    let wd = wd.to_string_lossy();
    cmd.args(["--ro-bind", &wd, &wd]);

    // The tmpfs root hides the host filesystem, so the harness script and the
    // runtime binary must be explicitly bound or bwrap cannot read/exec them.
    // Previously only work_dir was bound, leaving the sandbox unable to launch
    // whenever the harness or runtime lived outside it. harness_path is validated
    // absolute by build_command.
    let hp = std::fs::canonicalize(harness_path).map_err(|_| {
        BuildCommandError::CanonicalizationFailed {
            path: harness_path.to_path_buf(),
        }
    })?;
    let hp = hp.to_string_lossy();
    cmd.args(["--ro-bind", &hp, &hp]);

    // Bind the runtime executable when it is an absolute path. A bare
    // PATH-resolved name (for example "sh") cannot be bound directly; such a
    // runtime must be provided through readonly_mounts plus a suitable PATH.
    if runtime.is_absolute() {
        let rt = std::fs::canonicalize(runtime).map_err(|_| {
            BuildCommandError::CanonicalizationFailed {
                path: runtime.to_path_buf(),
            }
        })?;
        let rt = rt.to_string_lossy();
        cmd.args(["--ro-bind", &rt, &rt]);
    }

    for (host, container) in &config.readonly_mounts {
        if !host.is_absolute() {
            return Err(BuildCommandError::MountHostNotAbsolute {
                mount_kind: "readonly_mount",
                path: host.clone(),
            });
        }
        let host_canon = std::fs::canonicalize(host)
            .map_err(|_| BuildCommandError::CanonicalizationFailed { path: host.clone() })?;
        let host = host_canon.to_string_lossy();
        let container = container.to_string_lossy();
        cmd.args(["--ro-bind", &host, &container]);
    }
    for (host, container) in &config.writable_mounts {
        if !host.is_absolute() {
            return Err(BuildCommandError::MountHostNotAbsolute {
                mount_kind: "writable_mount",
                path: host.clone(),
            });
        }
        let host_canon = std::fs::canonicalize(host)
            .map_err(|_| BuildCommandError::CanonicalizationFailed { path: host.clone() })?;
        let host = host_canon.to_string_lossy();
        let container = container.to_string_lossy();
        cmd.args(["--bind", &host, &container]);
    }

    if !config.allow_localhost {
        cmd.arg("--unshare-net");
    }
    cmd.args(["--unshare-pid", "--die-with-parent"]);
    cmd.arg("--");
    cmd.arg(runtime);
    Ok(cmd)
}

fn build_firejail_command(
    runtime: &Path,
    work_dir: &Path,
    config: &SandboxConfig,
) -> std::result::Result<Command, BuildCommandError> {
    let mut cmd = Command::new("firejail");
    cmd.args(["--quiet", "--noprofile", "--noroot", "--nosound", "--no3d"]);
    cmd.args(["--nodvd", "--nonewprivs", "--seccomp"]);
    cmd.arg(format!("--private={}", work_dir.display()));
    cmd.arg(format!("--rlimit-as={}", config.max_memory_bytes));
    cmd.arg(format!("--rlimit-nofile={}", config.max_fds));
    let firejail_nproc_limit = nproc_limit_for_uid(config.max_processes);
    cmd.arg(format!("--rlimit-nproc={}", firejail_nproc_limit));
    cmd.arg(format!(
        "--timeout=00:{:02}:{:02}",
        config.timeout_seconds / 60,
        config.timeout_seconds % 60
    ));
    if !config.allow_localhost {
        cmd.arg("--net=none");
    }

    for (host, _container) in &config.readonly_mounts {
        if !host.is_absolute() {
            return Err(BuildCommandError::MountHostNotAbsolute {
                mount_kind: "readonly_mount",
                path: host.clone(),
            });
        }
        cmd.arg(format!("--whitelist={}", host.display()));
        cmd.arg(format!("--read-only={}", host.display()));
    }
    for (host, _container) in &config.writable_mounts {
        if !host.is_absolute() {
            return Err(BuildCommandError::MountHostNotAbsolute {
                mount_kind: "writable_mount",
                path: host.clone(),
            });
        }
        cmd.arg(format!("--whitelist={}", host.display()));
    }

    cmd.arg("--");
    cmd.arg(runtime);
    Ok(cmd)
}

fn build_rlimits_command(runtime: &Path) -> Command {
    // NOTE: RlimitsOnly provides NO namespace isolation.
    // Resource limits are enforced via SANTH_* env vars that the
    // harness reads and applies via setrlimit(). This is the weakest
    // strategy  -  use only when no better option is available.
    Command::new(runtime)
}

/// Find a binary in PATH.
pub fn which(name: &Path) -> AnyResult<std::path::PathBuf> {
    let name_str = name.to_string_lossy();

    // Absolute path: single metadata() call  -  no TOCTOU between exists() and metadata().
    if name.is_absolute() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            match std::fs::metadata(name) {
                Ok(meta) if meta.is_file() && (meta.permissions().mode() & 0o111 != 0) => {
                    return Ok(name.to_path_buf());
                }
                _ => {}
            }
        }
        #[cfg(not(unix))]
        {
            if std::fs::metadata(name)
                .map(|m| m.is_file())
                .unwrap_or(false)
            {
                return Ok(name.to_path_buf());
            }
        }
    }

    if let Some(paths) = std::env::var_os("PATH") {
        for p in std::env::split_paths(&paths) {
            let candidate = p.join(&*name_str);
            // Fix: use a single metadata() call instead of exists() + metadata() TOCTOU.
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                match std::fs::metadata(&candidate) {
                    Ok(meta) if meta.is_file() && (meta.permissions().mode() & 0o111 != 0) => {
                        return Ok(candidate);
                    }
                    _ => {}
                }
            }
            #[cfg(not(unix))]
            {
                match std::fs::metadata(&candidate) {
                    Ok(meta) if meta.is_file() => return Ok(candidate),
                    _ => {}
                }
            }
        }
    }

    Err(anyhow::anyhow!(
        "runtime '{name_str}' not found in PATH. Fix: install the runtime or set `runtime_path` to an absolute executable path."
    ))
}

impl SandboxedIO for SandboxedProcess {
    fn send(&mut self, line: &str) -> Result<()> {
        SandboxedProcess::send(self, line)
    }

    fn recv(&mut self) -> Result<Option<String>> {
        SandboxedProcess::recv(self)
    }

    fn kill(&mut self) {
        SandboxedProcess::kill(self);
    }

    fn is_alive(&mut self) -> bool {
        SandboxedProcess::is_alive(self)
    }
}

/// Cancellation signal for the parent watchdog.
///
/// Backed by a `Condvar` so the watchdog thread can block for the WHOLE timeout
/// in a single wait, waking early only when cancellation is signalled, instead
/// of busy-polling a flag every 25ms for the entire timeout window (which woke
/// ~40 times/second, e.g. 12,000 wakeups for a 300s timeout - Law 7).
#[derive(Debug, Default)]
pub struct WatchdogCancel {
    cancelled: Mutex<bool>,
    cv: Condvar,
}

impl WatchdogCancel {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Request cancellation and wake the watchdog immediately.
    pub fn cancel(&self) {
        {
            let mut guard = self
                .cancelled
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            *guard = true;
        }
        // Notify AFTER releasing the lock; the waiter re-checks the flag under
        // the mutex via wait_timeout_while, so no wakeup can be lost.
        self.cv.notify_all();
    }

    /// True if cancellation has been requested.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        *self
            .cancelled
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Block until cancellation is signalled or `timeout` elapses, in a single
    /// wait (no polling). Returns `true` if cancelled, `false` if the timeout
    /// elapsed first.
    ///
    /// `wait_timeout_while` releases the mutex while parked and re-acquires it to
    /// re-check the predicate on every (real or spurious) wakeup, so the returned
    /// flag is authoritative rather than a racy snapshot.
    #[must_use]
    pub fn wait_until_cancelled_or(&self, timeout: Duration) -> bool {
        let guard = self
            .cancelled
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let (guard, _timed_out) = self
            .cv
            .wait_timeout_while(guard, timeout, |c| !*c)
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *guard
    }
}

pub fn spawn_parent_watchdog(
    pid: u32,
    #[cfg(target_os = "linux")] pidfd: Option<OwnedFd>,
    timeout_seconds: u64,
    cancel: Arc<WatchdogCancel>,
    timed_out: Arc<AtomicBool>,
    cgroup_path: Option<std::path::PathBuf>,
) {
    if pid == 0 || timeout_seconds == 0 {
        return;
    }

    thread::spawn(move || {
        // Block once for the entire timeout, waking early only if cancelled - no
        // busy poll.
        if cancel.wait_until_cancelled_or(Duration::from_secs(timeout_seconds)) {
            return;
        }

        timed_out.store(true, Ordering::Release);

        if let Some(cg_path) = cgroup_path {
            let _ = std::fs::write(cg_path.join("cgroup.kill"), "1");
        }
        #[cfg(target_os = "linux")]
        let _ = pidfd
            .as_ref()
            .map_or_else(|| kill_process(pid), |fd| kill_process_pidfd(fd, pid));
        #[cfg(not(target_os = "linux"))]
        let _ = kill_process(pid);
    });
}

#[cfg(test)]
mod bwrap_bind_tests {
    use super::build_command;
    use crate::{SandboxConfig, Strategy};

    /// True if `--ro-bind <path> <path>` appears in the argument list.
    fn ro_bind_present(args: &[String], path: &str) -> bool {
        args.windows(3)
            .any(|w| w[0] == "--ro-bind" && w[1] == path && w[2] == path)
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn bwrap_binds_harness_and_absolute_runtime() {
        // Regression for builder.rs:321: the bwrap sandbox mounts a tmpfs root and
        // previously bound only work_dir, so the harness script and runtime binary
        // were absent inside the sandbox and it could not launch. Both must now be
        // --ro-bind mounted.
        let work = tempfile::tempdir().unwrap();
        let harness = work.path().join("harness.sh");
        std::fs::write(&harness, "#!/bin/sh\necho hi\n").unwrap();

        // Canonicalization requires an absolute, existing runtime path.
        let runtime = std::path::Path::new("/bin/sh");
        if !runtime.exists() {
            return;
        }

        let config = SandboxConfig::builder()
            .runtime("/bin/sh")
            .strategy(Strategy::Bubblewrap)
            .build();
        let cmd = build_command(runtime, &harness, work.path(), &config, Strategy::Bubblewrap)
            .expect("build_command should succeed for the bwrap strategy");

        let args: Vec<String> = cmd
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();

        let harness_canon = std::fs::canonicalize(&harness)
            .unwrap()
            .to_string_lossy()
            .into_owned();
        let runtime_canon = std::fs::canonicalize(runtime)
            .unwrap()
            .to_string_lossy()
            .into_owned();

        assert!(
            ro_bind_present(&args, &harness_canon),
            "harness must be --ro-bind mounted into the sandbox; args={args:?}"
        );
        assert!(
            ro_bind_present(&args, &runtime_canon),
            "absolute runtime must be --ro-bind mounted into the sandbox; args={args:?}"
        );
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn bwrap_binds_system_dirs_for_bare_name_runtime() {
        // Regression for tests/integration/mod.rs:296: a bare-name runtime like "sh"
        // must find its binary and loader inside the tmpfs root. build_bwrap_command
        // must bind /usr, /bin, /lib, and /lib64 read-only before the per-test mounts.
        let work = tempfile::tempdir().unwrap();
        let harness = work.path().join("harness.sh");
        std::fs::write(&harness, "#!/bin/sh\necho hi\n").unwrap();

        let runtime = std::path::Path::new("sh");
        let config = SandboxConfig::builder()
            .runtime("sh")
            .strategy(Strategy::Bubblewrap)
            .build();
        let cmd = build_command(runtime, &harness, work.path(), &config, Strategy::Bubblewrap)
            .expect("build_command should succeed for the bwrap strategy");

        let args: Vec<String> = cmd
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();

        assert!(
            ro_bind_present(&args, "/usr"),
            "/usr must be --ro-bind mounted for bare-name runtime; args={args:?}"
        );
        assert!(
            args.windows(3).any(|w| w[0] == "--ro-bind-try" && w[1] == "/bin" && w[2] == "/bin"),
            "/bin must be --ro-bind-try mounted for bare-name runtime; args={args:?}"
        );
        assert!(
            args.windows(3).any(|w| w[0] == "--ro-bind-try" && w[1] == "/lib" && w[2] == "/lib"),
            "/lib must be --ro-bind-try mounted for bare-name runtime; args={args:?}"
        );
        assert!(
            args.windows(3).any(|w| w[0] == "--ro-bind-try" && w[1] == "/lib64" && w[2] == "/lib64"),
            "/lib64 must be --ro-bind-try mounted for bare-name runtime; args={args:?}"
        );
    }
}

#[cfg(test)]
mod watchdog_cancel_tests {
    use super::WatchdogCancel;
    use std::sync::Arc;
    use std::thread;
    use std::time::{Duration, Instant};

    #[test]
    fn cancel_sets_flag() {
        let c = WatchdogCancel::new();
        assert!(!c.is_cancelled());
        c.cancel();
        assert!(c.is_cancelled());
    }

    #[test]
    fn wait_returns_true_immediately_when_already_cancelled() {
        let c = WatchdogCancel::new();
        c.cancel();
        let start = Instant::now();
        // A 60s timeout must be short-circuited by the already-set cancel flag.
        assert!(c.wait_until_cancelled_or(Duration::from_secs(60)));
        assert!(
            start.elapsed() < Duration::from_secs(1),
            "must not block when already cancelled"
        );
    }

    #[test]
    fn wait_returns_false_on_timeout() {
        let c = WatchdogCancel::new();
        // Short timeout, never cancelled -> returns false (timed out), and the
        // wait actually lasted about that long (a single blocking wait).
        let start = Instant::now();
        assert!(!c.wait_until_cancelled_or(Duration::from_millis(40)));
        assert!(start.elapsed() >= Duration::from_millis(30));
    }

    #[test]
    fn cancel_wakes_waiter_promptly_not_after_full_timeout() {
        // The Law-7 win: a waiter blocked on a long (60s) timeout must be woken
        // by cancel() within milliseconds, proving the Condvar signal path (vs
        // the old code, which could only notice cancellation on its next 25ms
        // poll and here would still be correct but is the busy-poll being removed).
        let c = Arc::new(WatchdogCancel::new());
        let c2 = Arc::clone(&c);
        let start = Instant::now();
        let handle = thread::spawn(move || c2.wait_until_cancelled_or(Duration::from_secs(60)));
        thread::sleep(Duration::from_millis(30));
        c.cancel();
        let cancelled = handle.join().expect("watchdog wait thread panicked");
        assert!(cancelled, "waiter must observe cancellation, not a timeout");
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "cancel must wake the waiter promptly, elapsed={:?}",
            start.elapsed()
        );
    }
}

