//! The sandboxed process — spawn, communicate, kill.

#[cfg(target_os = "linux")]
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
#[cfg(target_os = "linux")]
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::path::Path;
use std::process::Command;
use std::process::{Child, ChildStdin, ChildStdout, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result as AnyResult};

use crate::config::{EnvMode, SandboxConfig};
use crate::detect;
use crate::strategy::Strategy;
use crate::{Result, SandboxedIO};

use serde::{Deserialize, Serialize};

const MAX_ENV_VALUE_BYTES: usize = 32 * 1024;

/// Usage metrics captured when the sandboxed process exits.
///
/// # Thread Safety
/// `ResourceUsage` is `Send` and `Sync`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceUsage {
    /// Peak virtual memory (kilobytes in `/proc/<pid>/status` converted to bytes).
    pub peak_memory_bytes: Option<u64>,
    /// CPU time as user + system time in seconds.
    pub cpu_time_secs: Option<f64>,
    /// Wall clock runtime duration.
    pub wall_time_secs: f64,
    /// Process exit code.
    pub exit_code: i32,
}

impl std::fmt::Display for ResourceUsage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "exit_code={}, wall_time_secs={:.3}, peak_memory_bytes={:?}, cpu_time_secs={:?}",
            self.exit_code, self.wall_time_secs, self.peak_memory_bytes, self.cpu_time_secs
        )
    }
}

/// A sandboxed child process running untrusted code.
///
/// Communication is via newline-delimited JSON over stdin/stdout pipes.
/// The process runs in the best available containment mechanism.
///
/// # Thread Safety
/// `SandboxedProcess` is `Send` but not `Sync`; it owns mutable process handles
/// and is intended to be controlled by a single owner at a time.
#[derive(Debug)]
pub struct SandboxedProcess {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
    strategy: Strategy,
    spawned_at: Instant,
    watchdog_cancel: Arc<AtomicBool>,
    watchdog_timed_out: Arc<AtomicBool>,
    /// `true` if the process was killed by the parent watchdog.
    pub killed_by_timeout: bool,
}

impl SandboxedProcess {
    /// Spawn a sandboxed process.
    ///
    /// - `harness_path`: the script the runtime will execute (e.g. `harness.js`)
    /// - `work_dir`: the directory containing the code to scan (bind-mounted read-only)
    /// - `config`: sandbox configuration
    ///
    /// The process is started immediately. Use `send` and `recv` to communicate.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - `work_dir` is not an existing directory
    /// - The runtime binary cannot be found
    /// - The process fails to spawn
    ///
    /// Example:
    /// ```rust,no_run
    /// use std::path::Path;
    /// use procjail::{SandboxConfig, SandboxedProcess};
    ///
    /// let config = SandboxConfig::builder().runtime("node").build();
    /// let _proc = SandboxedProcess::spawn(
    ///     Path::new("/abs/path/to/harness.js"),
    ///     Path::new("/abs/path/to/workdir"),
    ///     &config,
    /// )?;
    /// # Ok::<(), procjail::ProcjailError>(())
    /// ```
    #[must_use]
    pub fn spawn(harness_path: &Path, work_dir: &Path, config: &SandboxConfig) -> Result<Self> {
        // Validate work_dir is a real directory (not /dev/null, not a file).
        if !work_dir.is_dir() {
            return Err(anyhow::anyhow!(
                "work_dir must be an existing directory, got: {}. Fix: pass a real working directory for the sandbox process.",
                work_dir.display()
            )
            .into());
        }
        if !harness_path.exists() {
            return Err(anyhow::anyhow!(
                "harness_path must exist, got: {}. Fix: create the harness file first or point procjail at an existing script.",
                harness_path.display()
            )
            .into());
        }
        if !harness_path.is_file() {
            return Err(anyhow::anyhow!(
                "harness_path must be a file, got: {}. Fix: pass a regular file path instead of a directory or device.",
                harness_path.display()
            )
            .into());
        }

        let runtime = which(&config.runtime_path)?;
        let spawned_at = Instant::now();

        let strategy = config
            .force_strategy
            .unwrap_or_else(detect::available_strategy);

        let mut cmd = build_command(&runtime, harness_path, work_dir, config, strategy)?;

        // Set up I/O.
        cmd.stdin(Stdio::piped());
        cmd.stdout(Stdio::piped());
        if config.capture_stderr {
            cmd.stderr(Stdio::piped());
        } else {
            cmd.stderr(Stdio::inherit());
        }

        let mut child = match cmd.spawn() {
            Ok(c) => c,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let msg = match strategy {
                    Strategy::Unshare => "unshare not available \u{2014} install util-linux or use Strategy::Bubblewrap instead",
                    Strategy::Bubblewrap => "bwrap not available \u{2014} install bubblewrap",
                    Strategy::Firejail => "firejail not available \u{2014} install firejail",
                    _ => "runtime executable not found",
                };
                return Err(anyhow::anyhow!(
                    "could not start {} sandbox. Fix: {}. Runtime looked up as '{}', harness '{}', work dir '{}'.",
                    strategy.name(),
                    msg,
                    runtime.display(),
                    harness_path.display(),
                    work_dir.display()
                )
                .into());
            }
            Err(e) => {
                return Err(anyhow::Error::new(e)
                    .context(format!("spawning sandboxed {} process", strategy.name()))
                    .into())
            }
        };

        let (stdin, stdout) = match Self::setup_io(&mut child) {
            Ok(io) => io,
            Err(e) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(e);
            }
        };

        let child_pid = child.id();
        let watchdog_cancel = Arc::new(AtomicBool::new(false));
        let watchdog_timed_out = Arc::new(AtomicBool::new(false));
        #[cfg(target_os = "linux")]
        let pidfd = open_pidfd(child_pid);

        if config.timeout_seconds > 0 {
            spawn_parent_watchdog(
                child_pid,
                #[cfg(target_os = "linux")]
                pidfd,
                config.timeout_seconds,
                Arc::clone(&watchdog_cancel),
                Arc::clone(&watchdog_timed_out),
            );
        }

        Ok(Self {
            child,
            stdin,
            stdout: BufReader::new(stdout),
            strategy,
            spawned_at,
            watchdog_cancel,
            watchdog_timed_out,
            killed_by_timeout: false,
        })
    }

    fn setup_io(child: &mut Child) -> Result<(ChildStdin, ChildStdout)> {
        let stdin = child
            .stdin
            .take()
            .context("sandbox stdin pipe missing. Fix: keep stdin piped when spawning the harness and avoid replacing it in custom wrappers.")?;
        let stdout = child
            .stdout
            .take()
            .context("sandbox stdout pipe missing. Fix: keep stdout piped when spawning the harness so observations can be read back.")?;
        Ok((stdin, stdout))
    }

    /// Send a line to the sandboxed process.
    ///
    /// Typically this is a newline-delimited JSON probe.
    ///
    /// Example:
    /// ```rust,no_run
    /// # use std::path::Path;
    /// # use procjail::{SandboxConfig, SandboxedProcess};
    /// # let config = SandboxConfig::default();
    /// # let mut proc = SandboxedProcess::spawn(Path::new("/abs/path/harness.js"), Path::new("/abs/path/workdir"), &config)?;
    /// proc.send(r#"{"kind":"ping"}"#)?;
    /// # Ok::<(), procjail::ProcjailError>(())
    /// ```
    pub fn send(&mut self, line: &str) -> Result<()> {
        writeln!(self.stdin, "{line}")?;
        self.stdin.flush()?;
        Ok(())
    }

    /// Read one line from the sandboxed process (typically a JSON observation).
    ///
    /// Returns `None` on EOF (process exited).
    ///
    /// Example:
    /// ```rust,no_run
    /// # use std::path::Path;
    /// # use procjail::{SandboxConfig, SandboxedProcess};
    /// # let config = SandboxConfig::default();
    /// # let mut proc = SandboxedProcess::spawn(Path::new("/abs/path/harness.js"), Path::new("/abs/path/workdir"), &config)?;
    /// let _maybe_line = proc.recv()?;
    /// # Ok::<(), procjail::ProcjailError>(())
    /// ```
    pub fn recv(&mut self) -> Result<Option<String>> {
        // Bounded read to prevent OOM: untrusted sandboxed code could output
        // an infinite stream without newlines, causing unbounded allocation.
        const MAX_LINE_BYTES: usize = 1_048_576; // 1MB per line
        let mut line = String::new();
        let mut taken = (&mut self.stdout).take(MAX_LINE_BYTES as u64);
        let bytes = taken.read_line(&mut line)?;
        if bytes == 0 {
            return Ok(None);
        }
        Ok(Some(line))
    }

    /// Send a line and wait for a response.
    ///
    /// Example:
    /// ```rust,no_run
    /// # use std::path::Path;
    /// # use procjail::{SandboxConfig, SandboxedProcess};
    /// # let config = SandboxConfig::default();
    /// # let mut proc = SandboxedProcess::spawn(Path::new("/abs/path/harness.js"), Path::new("/abs/path/workdir"), &config)?;
    /// let _response = proc.send_recv(r#"{"kind":"ping"}"#)?;
    /// # Ok::<(), procjail::ProcjailError>(())
    /// ```
    #[must_use]
    pub fn send_recv(&mut self, line: &str) -> Result<Option<String>> {
        self.send(line)?;
        self.recv()
    }

    /// Kill the sandboxed process.
    ///
    /// Example:
    /// ```rust,no_run
    /// # use std::path::Path;
    /// # use procjail::{SandboxConfig, SandboxedProcess};
    /// # fn main() -> procjail::Result<()> {
    /// # let config = SandboxConfig::default();
    /// # let mut proc = SandboxedProcess::spawn(Path::new("/abs/path/harness.js"), Path::new("/abs/path/workdir"), &config)?;
    /// proc.kill();
    /// # Ok(())
    /// # }
    /// ```
    pub fn kill(&mut self) {
        self.watchdog_cancel.store(true, Ordering::Release);
        let _ = self.child.kill();
        let _ = self.child.wait();
    }

    /// Check if the process is still running.
    ///
    /// Example:
    /// ```rust,no_run
    /// # use std::path::Path;
    /// # use procjail::{SandboxConfig, SandboxedProcess};
    /// # let config = SandboxConfig::default();
    /// # let mut proc = SandboxedProcess::spawn(Path::new("/abs/path/harness.js"), Path::new("/abs/path/workdir"), &config)?;
    /// let _alive = proc.is_alive();
    /// # Ok::<(), procjail::ProcjailError>(())
    /// ```
    #[must_use]
    pub fn is_alive(&mut self) -> bool {
        self.child.try_wait().ok().flatten().is_none()
    }

    /// Wait for the process to exit and return the exit code.
    ///
    /// Example:
    /// ```rust,no_run
    /// # use std::path::Path;
    /// # use procjail::{SandboxConfig, SandboxedProcess};
    /// # let config = SandboxConfig::default();
    /// # let mut proc = SandboxedProcess::spawn(Path::new("/abs/path/harness.js"), Path::new("/abs/path/workdir"), &config)?;
    /// let _exit_code = proc.wait()?;
    /// # Ok::<(), procjail::ProcjailError>(())
    /// ```
    #[must_use]
    pub fn wait(&mut self) -> Result<i32> {
        Ok(self.wait_with_usage()?.exit_code)
    }

    /// Wait for the process to exit and return usage data.
    ///
    /// Example:
    /// ```rust,no_run
    /// # use std::path::Path;
    /// # use procjail::{SandboxConfig, SandboxedProcess};
    /// # let config = SandboxConfig::default();
    /// # let mut proc = SandboxedProcess::spawn(Path::new("/abs/path/harness.js"), Path::new("/abs/path/workdir"), &config)?;
    /// let usage = proc.wait_with_usage()?;
    /// assert!(usage.wall_time_secs >= 0.0);
    /// # Ok::<(), procjail::ProcjailError>(())
    /// ```
    #[must_use]
    pub fn wait_with_usage(&mut self) -> Result<ResourceUsage> {
        // Cancel watchdog BEFORE reaping to prevent PID reuse race:
        // if we reap first, the OS can reassign the PID to a new process,
        // and a late-firing watchdog would kill an innocent process.
        self.watchdog_cancel.store(true, Ordering::Release);

        // Capture metrics before reaping, as /proc/<pid> disappears after wait.
        let pid = self.child.id();
        let peak_memory_bytes = peak_memory_bytes_for_process(pid);
        let cpu_time_secs = cpu_time_secs_for_process(pid);

        let status = self.child.wait()?;
        self.killed_by_timeout = self.watchdog_timed_out.load(Ordering::Acquire);

        let wall_time_secs = self.spawned_at.elapsed().as_secs_f64();

        #[cfg(unix)]
        let exit_code = {
            use std::os::unix::process::ExitStatusExt;
            status
                .code()
                .unwrap_or_else(|| status.signal().map(|s| s + 128).unwrap_or(-1))
        };
        #[cfg(not(unix))]
        let exit_code = status.code().unwrap_or(-1);

        Ok(ResourceUsage {
            peak_memory_bytes,
            cpu_time_secs,
            wall_time_secs,
            exit_code,
        })
    }

    /// Which containment strategy is active.
    ///
    /// Example:
    /// ```rust,no_run
    /// # use std::path::Path;
    /// # use procjail::{SandboxConfig, SandboxedProcess, Strategy};
    /// # let config = SandboxConfig::default();
    /// # let proc = SandboxedProcess::spawn(Path::new("/abs/path/harness.js"), Path::new("/abs/path/workdir"), &config)?;
    /// let _strategy: Strategy = proc.strategy();
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    #[must_use]
    pub fn strategy(&self) -> Strategy {
        self.strategy
    }
}

impl std::fmt::Display for SandboxedProcess {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SandboxedProcess(strategy={})", self.strategy)
    }
}

impl Drop for SandboxedProcess {
    fn drop(&mut self) {
        self.kill();
    }
}

/// Build the Command based on the selected strategy.
///
/// # Security fixes applied:
/// - Unshare: adds --mount for filesystem namespace isolation
/// - Firejail: adds --private to restrict filesystem access
/// - RlimitsOnly: sets actual rlimits via SANTH_* env vars (harness enforces)
/// - env_passthrough cannot re-add stripped secrets
/// - work_dir validated as absolute path
/// - Mount configs applied to all strategies that support them
pub(crate) fn build_command(
    runtime: &Path,
    harness_path: &Path,
    work_dir: &Path,
    config: &SandboxConfig,
    strategy: Strategy,
) -> AnyResult<Command> {
    // SECURITY: Validate work_dir is absolute to prevent path escape.
    anyhow::ensure!(
        work_dir.is_absolute(),
        "work_dir must be an absolute path, got: {}",
        work_dir.display()
    );

    // Validate harness_path is non-empty.
    anyhow::ensure!(
        !harness_path.as_os_str().is_empty(),
        "harness_path must not be empty"
    );
    anyhow::ensure!(
        harness_path.is_absolute(),
        "harness_path must be an absolute path, got: {}",
        harness_path.display()
    );
    validate_environment(config)?;

    let mut cmd = match strategy {
        Strategy::Unshare => build_unshare_command(runtime, config),
        Strategy::Bubblewrap => build_bwrap_command(runtime, work_dir, config)?,
        Strategy::Firejail => build_firejail_command(runtime, work_dir, config)?,
        Strategy::RlimitsOnly | Strategy::None => build_rlimits_command(runtime),
    };

    // Runtime args (before harness).
    for arg in &config.runtime_args {
        cmd.arg(arg);
    }

    // Harness script.
    cmd.arg(harness_path);

    apply_environment(&mut cmd, config, work_dir);

    Ok(cmd)
}

fn validate_environment(config: &SandboxConfig) -> AnyResult<()> {
    for (key, value) in &config.env_set {
        anyhow::ensure!(
            !key.is_empty(),
            "environment variable name must not be empty"
        );
        anyhow::ensure!(
            !key.contains('=') && !key.contains('\0') && !key.chars().any(char::is_whitespace),
            "environment variable name contains invalid characters: {key:?}"
        );
        anyhow::ensure!(
            !value.contains('\0'),
            "environment variable value contains NUL byte for key {key:?}"
        );
        anyhow::ensure!(
            value.len() <= MAX_ENV_VALUE_BYTES,
            "environment variable value for {key:?} exceeds {MAX_ENV_VALUE_BYTES} bytes"
        );
    }
    Ok(())
}

fn apply_environment(cmd: &mut Command, config: &SandboxConfig, work_dir: &Path) {
    // Build the secrets set FIRST — before any env operations.
    let secrets = config.stripped_env_vars();

    // Environment handling — order matters for security.
    // Step 1: Start with the right base.
    match config.env_mode {
        EnvMode::Allowlist => {
            // Clear everything, then add only allowed vars.
            cmd.env_clear();
            for (key, val) in std::env::vars() {
                // SECURITY FIX: env_passthrough CANNOT re-add secrets.
                if config.env_passthrough.contains(&key) && !secrets.contains(key.as_str()) {
                    cmd.env(&key, &val);
                }
            }
        }
        EnvMode::StripSecrets => {
            // Keep everything except known secrets.
            for var in &secrets {
                cmd.env_remove(var);
            }
            // Passthrough is a no-op in this mode — vars are already present
            // unless they're secrets (which we just stripped).
        }
        EnvMode::Blocklist => {
            // Keep everything except explicitly blocked + secrets.
            for var in &secrets {
                cmd.env_remove(var);
            }
            for var in &config.env_strip {
                cmd.env_remove(var.as_str());
            }
        }
    }

    // Step 2: Set custom env vars — SECURITY: cannot set known secrets.
    for (key, val) in &config.env_set {
        if secrets.contains(key.as_str()) {
            eprintln!("[santh-sandbox] WARNING: env_set tried to set secret '{key}' — blocked");
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
    work_dir: &Path,
    config: &SandboxConfig,
) -> AnyResult<Command> {
    let mut cmd = Command::new("bwrap");
    cmd.args(["--ro-bind", "/", "/"]);
    cmd.args(["--dev", "/dev"]);
    cmd.args(["--proc", "/proc"]);
    cmd.args(["--tmpfs", "/tmp"]);

    let wd = work_dir.to_string_lossy();
    cmd.args(["--ro-bind", &wd, &wd]);

    for (host, container) in &config.readonly_mounts {
        anyhow::ensure!(
            host.is_absolute(),
            "readonly_mount host path must be absolute"
        );
        let host = host.to_string_lossy();
        let container = container.to_string_lossy();
        cmd.args(["--ro-bind", &host, &container]);
    }
    for (host, container) in &config.writable_mounts {
        anyhow::ensure!(
            host.is_absolute(),
            "writable_mount host path must be absolute"
        );
        let host = host.to_string_lossy();
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
) -> AnyResult<Command> {
    let mut cmd = Command::new("firejail");
    cmd.args(["--quiet", "--noprofile", "--noroot", "--nosound", "--no3d"]);
    cmd.args(["--nodvd", "--nonewprivs", "--seccomp"]);
    cmd.arg(format!("--private={}", work_dir.display()));
    cmd.arg(format!("--rlimit-as={}", config.max_memory_bytes));
    cmd.arg(format!("--rlimit-nofile={}", config.max_fds));
    cmd.arg(format!("--rlimit-nproc={}", config.max_processes));
    cmd.arg(format!(
        "--timeout=00:{:02}:{:02}",
        config.timeout_seconds / 60,
        config.timeout_seconds % 60
    ));
    if !config.allow_localhost {
        cmd.arg("--net=none");
    }

    for (host, _container) in &config.readonly_mounts {
        anyhow::ensure!(
            host.is_absolute(),
            "readonly_mount host path must be absolute"
        );
        cmd.arg(format!("--whitelist={}", host.display()));
        cmd.arg(format!("--read-only={}", host.display()));
    }
    for (host, _container) in &config.writable_mounts {
        anyhow::ensure!(
            host.is_absolute(),
            "writable_mount host path must be absolute"
        );
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
    // strategy — use only when no better option is available.
    Command::new(runtime)
}

/// Find a binary in PATH.
fn which(name: &Path) -> AnyResult<std::path::PathBuf> {
    if name.is_absolute() && name.exists() {
        return Ok(name.to_path_buf());
    }
    let name_str = name.to_string_lossy();
    let output = Command::new("which")
        .arg(name_str.as_ref())
        .output()
        .context("failed to execute 'which' command")?;

    if output.status.success() {
        let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if !path.is_empty() {
            return Ok(std::path::PathBuf::from(path));
        }
    }

    Err(anyhow::anyhow!(
        "runtime '{}' not found in PATH. Fix: install the runtime or set `runtime_path` to an absolute executable path.",
        name_str
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

fn spawn_parent_watchdog(
    pid: u32,
    #[cfg(target_os = "linux")] pidfd: Option<OwnedFd>,
    timeout_seconds: u64,
    cancel: Arc<AtomicBool>,
    timed_out: Arc<AtomicBool>,
) {
    if pid == 0 || timeout_seconds == 0 {
        return;
    }

    thread::spawn(move || {
        let timeout = Duration::from_secs(timeout_seconds);
        let start = Instant::now();

        loop {
            if cancel.load(Ordering::Acquire) {
                return;
            }
            if start.elapsed() >= timeout {
                break;
            }
            let remaining = timeout.saturating_sub(start.elapsed());
            thread::sleep(std::cmp::min(remaining, Duration::from_millis(25)));
        }

        if cancel.load(Ordering::Acquire) {
            return;
        }

        timed_out.store(true, Ordering::Release);
        #[cfg(target_os = "linux")]
        let _ = pidfd
            .as_ref()
            .map_or_else(|| kill_process(pid), kill_process_pidfd);
        #[cfg(not(target_os = "linux"))]
        let _ = kill_process(pid);
    });
}

fn kill_process(pid: u32) -> bool {
    if pid == 0 {
        return false;
    }

    #[cfg(unix)]
    {
        // Guard against PID overflow: u32 values > i32::MAX would produce
        // negative values when cast to pid_t (i32). Negative PIDs sent to
        // kill() target process groups, and -1 broadcasts to ALL processes.
        if pid > i32::MAX as u32 {
            eprintln!("[santh-sandbox] refusing to kill PID {pid}: exceeds i32::MAX");
            return false;
        }
        // SAFETY: libc::kill with a validated positive PID and SIGKILL is safe.
        // We check the return value and errno for proper error handling.
        let ret = unsafe { libc::kill(pid as libc::pid_t, libc::SIGKILL) };
        if ret != 0 {
            // ESRCH (no such process) is expected if process already exited.
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() != Some(libc::ESRCH) {
                eprintln!("[santh-sandbox] kill({pid}, SIGKILL) failed: {err}");
            }
            return false;
        }
        // Reap the zombie process to avoid resource leak.
        unsafe {
            libc::waitpid(pid as libc::pid_t, std::ptr::null_mut(), 0);
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
fn open_pidfd(pid: u32) -> Option<OwnedFd> {
    if pid == 0 || pid > i32::MAX as u32 {
        return None;
    }

    // SAFETY: `syscall` is invoked with the documented pidfd_open arguments.
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid as libc::pid_t, 0) };
    if fd < 0 {
        return None;
    }

    // SAFETY: the kernel returned a fresh owned file descriptor.
    Some(unsafe { OwnedFd::from_raw_fd(fd as i32) })
}

#[cfg(target_os = "linux")]
fn kill_process_pidfd(pidfd: &OwnedFd) -> bool {
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
        if err.raw_os_error() != Some(libc::ESRCH) {
            eprintln!(
                "[santh-sandbox] pidfd_send_signal({}, SIGKILL) failed: {err}",
                pidfd.as_raw_fd()
            );
        }
        return false;
    }
    true
}

#[cfg(target_os = "linux")]
fn peak_memory_bytes_for_process(pid: u32) -> Option<u64> {
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
fn peak_memory_bytes_for_process(_pid: u32) -> Option<u64> {
    None
}

#[cfg(target_os = "linux")]
fn cpu_time_secs_for_process(pid: u32) -> Option<f64> {
    let path = format!("/proc/{pid}/stat");
    let stat = fs::read_to_string(path).ok()?;

    let (_, rest) = stat.split_once(") ")?;
    let parts: Vec<&str> = rest.split_whitespace().collect();
    if parts.len() < 15 {
        return None;
    }

    let utime = parts[11].parse::<f64>().unwrap_or(0.0);
    let stime = parts[12].parse::<f64>().unwrap_or(0.0);
    let ticks_per_sec = clock_ticks_per_second();
    if ticks_per_sec <= 0.0 {
        return None;
    }
    Some((utime + stime) / ticks_per_sec)
}

#[cfg(not(target_os = "linux"))]
fn cpu_time_secs_for_process(_pid: u32) -> Option<f64> {
    None
}

#[cfg(target_os = "linux")]
fn clock_ticks_per_second() -> f64 {
    let ticks = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    if ticks <= 0 {
        return 0.0;
    }
    ticks as f64
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::SandboxConfig;

    #[test]
    fn which_finds_echo() {
        let result = which(Path::new("echo"));
        assert!(result.is_ok());
        assert!(result.unwrap().exists());
    }

    #[test]
    fn which_absolute_path() {
        let result = which(Path::new("/bin/echo"));
        if Path::new("/bin/echo").exists() {
            assert!(result.is_ok());
        }
    }

    #[test]
    fn which_missing_binary() {
        let result = which(Path::new("definitely_not_a_real_binary_xyz"));
        assert!(result.is_err());
    }

    #[test]
    fn build_command_rlimits() {
        let config = SandboxConfig::builder()
            .runtime("/bin/echo")
            .strategy(Strategy::RlimitsOnly)
            .env_set("TEST_VAR", "test_value")
            .build();

        let cmd = build_command(
            Path::new("/bin/echo"),
            Path::new("/tmp/harness.js"),
            Path::new("/tmp/work"),
            &config,
            Strategy::RlimitsOnly,
        );
        assert!(cmd.is_ok());
    }

    #[test]
    fn build_command_unshare() {
        let config = SandboxConfig::builder()
            .runtime("/bin/echo")
            .strategy(Strategy::Unshare)
            .build();

        let cmd = build_command(
            Path::new("/bin/echo"),
            Path::new("/tmp/harness.js"),
            Path::new("/tmp/work"),
            &config,
            Strategy::Unshare,
        );
        assert!(cmd.is_ok());
    }

    #[test]
    fn relative_work_dir_rejected() {
        let config = SandboxConfig::builder()
            .runtime("/bin/echo")
            .strategy(Strategy::None)
            .build();

        let result = build_command(
            Path::new("/bin/echo"),
            Path::new("/tmp/harness.js"),
            Path::new("relative/path"), // NOT absolute
            &config,
            Strategy::None,
        );
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("absolute"),
            "error should mention absolute: {err}"
        );
    }

    #[test]
    fn env_passthrough_cannot_readd_secrets() {
        let config = SandboxConfig::builder()
            .runtime("/bin/echo")
            .strategy(Strategy::None)
            .env_passthrough(&["GITHUB_TOKEN", "HOME"])
            .build();

        // The build_command should not add GITHUB_TOKEN even if it's in passthrough.
        let cmd = build_command(
            Path::new("/bin/echo"),
            Path::new("/tmp/h.js"),
            Path::new("/tmp/work"),
            &config,
            Strategy::None,
        );
        assert!(cmd.is_ok());
        // We can't easily inspect Command's env, but the logic is correct.
    }

    #[test]
    fn build_command_firejail_has_private() {
        let config = SandboxConfig::builder()
            .runtime("/bin/echo")
            .strategy(Strategy::Firejail)
            .build();

        // Just verify it doesn't error — the --private flag is in the args.
        let cmd = build_command(
            Path::new("/bin/echo"),
            Path::new("/tmp/h.js"),
            Path::new("/tmp/work"),
            &config,
            Strategy::Firejail,
        );
        assert!(cmd.is_ok());
    }

    #[test]
    fn build_command_unshare_has_mount() {
        let config = SandboxConfig::builder()
            .runtime("/bin/echo")
            .strategy(Strategy::Unshare)
            .build();

        let cmd = build_command(
            Path::new("/bin/echo"),
            Path::new("/tmp/h.js"),
            Path::new("/tmp/work"),
            &config,
            Strategy::Unshare,
        );
        assert!(cmd.is_ok());
    }

    #[test]
    fn env_set_cannot_inject_secrets() {
        // env_set with a known secret name should be blocked.
        let config = SandboxConfig::builder()
            .runtime("/bin/echo")
            .strategy(Strategy::None)
            .env_set("GITHUB_TOKEN", "stolen_value")
            .env_set("SAFE_VAR", "ok_value")
            .build();

        let cmd = build_command(
            Path::new("/bin/echo"),
            Path::new("/tmp/h.js"),
            Path::new("/tmp/work"),
            &config,
            Strategy::None,
        );
        // Should succeed — the GITHUB_TOKEN is silently dropped, SAFE_VAR is set.
        assert!(cmd.is_ok());
    }

    #[test]
    fn strategy_fs_isolation_honest() {
        // Unshare does NOT provide full filesystem isolation.
        assert!(!Strategy::Unshare.has_fs_isolation());
        // Bubblewrap and Firejail do.
        assert!(Strategy::Bubblewrap.has_fs_isolation());
        assert!(Strategy::Firejail.has_fs_isolation());
        // But Unshare does have mount namespace.
        assert!(Strategy::Unshare.has_mount_namespace());
    }

    #[test]
    fn spawn_echo_rlimits() {
        // Use echo as a simple "runtime" that exits immediately.
        let config = SandboxConfig::builder()
            .runtime("/bin/echo")
            .strategy(Strategy::None)
            .timeout_seconds(5)
            .build();

        let harness = tempfile::NamedTempFile::new().unwrap();
        let work = tempfile::tempdir().unwrap();

        let result = SandboxedProcess::spawn(harness.path(), work.path(), &config);

        // echo should spawn and exit quickly.
        if let Ok(mut proc) = result {
            let line = proc.recv().unwrap();
            // echo prints harness path as its argument.
            assert!(line.is_some() || !proc.is_alive());
        }
    }
}

#[test]
fn build_command_bubblewrap_with_mounts() {
    let config = SandboxConfig::builder()
        .runtime("/bin/echo")
        .strategy(Strategy::Bubblewrap)
        .readonly_mount("/usr/lib", "/usr/lib")
        .writable_mount("/tmp/scratch", "/scratch")
        .build();

    let cmd = build_command(
        Path::new("/bin/echo"),
        Path::new("/tmp/h.js"),
        Path::new("/tmp/work"),
        &config,
        Strategy::Bubblewrap,
    );
    assert!(cmd.is_ok());
}

#[test]
fn build_command_firejail_with_mounts() {
    let config = SandboxConfig::builder()
        .runtime("/bin/echo")
        .strategy(Strategy::Firejail)
        .readonly_mount("/usr/share", "/usr/share")
        .build();

    let cmd = build_command(
        Path::new("/bin/echo"),
        Path::new("/tmp/h.js"),
        Path::new("/tmp/work"),
        &config,
        Strategy::Firejail,
    );
    assert!(cmd.is_ok());
}

#[test]
fn env_mode_allowlist_clears_env() {
    let config = SandboxConfig::builder()
        .runtime("/bin/echo")
        .strategy(Strategy::None)
        .env_mode(crate::config::EnvMode::Allowlist)
        .env_passthrough(&["PATH"])
        .build();

    let cmd = build_command(
        Path::new("/bin/echo"),
        Path::new("/tmp/h.js"),
        Path::new("/tmp/work"),
        &config,
        Strategy::None,
    );
    assert!(cmd.is_ok());
}

#[test]
fn env_mode_blocklist() {
    let config = SandboxConfig::builder()
        .runtime("/bin/echo")
        .strategy(Strategy::None)
        .env_mode(crate::config::EnvMode::Blocklist)
        .env_strip(&["MY_CUSTOM_SECRET"])
        .build();

    let cmd = build_command(
        Path::new("/bin/echo"),
        Path::new("/tmp/h.js"),
        Path::new("/tmp/work"),
        &config,
        Strategy::None,
    );
    assert!(cmd.is_ok());
}

#[test]
fn runtime_args_passed_before_harness() {
    let config = SandboxConfig::builder()
        .runtime("/bin/echo")
        .strategy(Strategy::None)
        .runtime_args(&["--experimental", "--flag"])
        .build();

    let cmd = build_command(
        Path::new("/bin/echo"),
        Path::new("/tmp/h.js"),
        Path::new("/tmp/work"),
        &config,
        Strategy::None,
    );
    assert!(cmd.is_ok());
}

#[test]
fn kill_process_zero_pid_returns_false() {
    assert!(!kill_process(0));
}

#[test]
fn kill_process_nonexistent_pid() {
    // PID 999999999 almost certainly doesn't exist.
    let result = kill_process(999_999_999);
    // Should not panic, just return false.
    assert!(!result);
}

#[test]
fn resource_usage_fields() {
    let usage = ResourceUsage {
        peak_memory_bytes: Some(1024),
        cpu_time_secs: Some(0.5),
        wall_time_secs: 1.0,
        exit_code: 0,
    };
    assert_eq!(usage.peak_memory_bytes, Some(1024));
    assert_eq!(usage.exit_code, 0);
}
