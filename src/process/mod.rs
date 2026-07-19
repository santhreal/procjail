//! The sandboxed process  -  spawn, communicate, kill.

pub(crate) mod builder;
pub(crate) mod kill;

#[cfg(target_os = "linux")]
use std::io::{BufRead, BufReader, Read, Write};
use std::path::Path;
use std::process::{Child, ChildStdin, ChildStdout, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Instant;

use anyhow::Context;
use thiserror::Error;

use crate::config::SandboxConfig;
use crate::detect;
use crate::strategy::Strategy;
use crate::Result;

pub use crate::process::builder::{build_command, spawn_parent_watchdog, which, WatchdogCancel};
pub use crate::process::kill::{
    cpu_time_secs_for_process, open_pidfd, peak_memory_bytes_for_process,
};

use serde::{Deserialize, Serialize};

pub(crate) const MAX_ENV_VALUE_BYTES: usize = 32 * 1024;

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
    max_recv_line_bytes: usize,
    strategy: Strategy,
    spawned_at: Instant,
    watchdog_cancel: Arc<WatchdogCancel>,
    watchdog_timed_out: Arc<AtomicBool>,
    /// Securely unescapable hardware constraint.
    cgroup: Option<crate::cgroups::CgroupV2>,
    /// `true` if the process was killed by the parent watchdog.
    pub killed_by_timeout: bool,
}

/// Kill a child and reap it to avoid a zombie, ignoring errors (the child may
/// already be gone). Consolidates the kill+wait cleanup used on every spawn-time
/// error path.
fn kill_and_reap(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
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
    pub fn spawn(harness_path: &Path, work_dir: &Path, config: &SandboxConfig) -> Result<Self> {
        Self::validate_inputs(harness_path, work_dir, config.max_recv_line_bytes)?;

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
                kill_and_reap(&mut child);
                return Err(e);
            }
        };

        let child_pid = child.id();
        let watchdog_cancel = Arc::new(WatchdogCancel::new());
        let watchdog_timed_out = Arc::new(AtomicBool::new(false));

        // Enforce strong hardware limits via cgroups v2. Every failure path kills
        // the child and reports the error rather than leaving an unconstrained
        // process running.
        let mut attached_cgroup = None;
        match crate::cgroups::CgroupV2::new(&format!("procjail-{child_pid}")) {
            Ok(cgroup) => {
                // cgroup created: treat write failures as security-critical.
                let limits = cgroup
                    .set_memory_limit(config.max_memory_bytes)
                    .and_then(|()| cgroup.set_cpu_limit(100_000, 100_000))
                    .and_then(|()| cgroup.set_pids_limit(config.max_processes))
                    .and_then(|()| cgroup.attach_pid(child_pid));
                if let Err(e) = limits {
                    kill_and_reap(&mut child);
                    return Err(anyhow::anyhow!("failed to apply cgroup limits: {e}").into());
                }
                attached_cgroup = Some(cgroup);
            }
            Err(e) => {
                // Creation failed: the hardware isolation control is unavailable.
                // NEVER degrade silently (Law 10). Fail closed when the caller
                // requires hardware limits; otherwise surface a loud warning.
                if config.require_hardware_limits {
                    kill_and_reap(&mut child);
                    return Err(anyhow::anyhow!(
                        "cgroup v2 hardware limits required but unavailable: {e}"
                    )
                    .into());
                }
                eprintln!(
                    "[procjail] WARNING: cgroup v2 unavailable ({e}); process runs WITHOUT \
                     memory/CPU/pids hardware limits. Set require_hardware_limits(true) to fail closed."
                );
            }
        }

        #[cfg(target_os = "linux")]
        let pidfd = open_pidfd(child_pid);

        eprintln!(
            "[procjail] spawn: child_pid={}, timeout_seconds={}",
            child_pid, config.timeout_seconds
        );

        let cgroup_path = attached_cgroup.as_ref().map(|cg| cg.path.clone());
        if config.timeout_seconds > 0 {
            eprintln!(
                "[procjail] spawn: starting watchdog for pid={} timeout={}s",
                child_pid, config.timeout_seconds
            );
            spawn_parent_watchdog(
                child_pid,
                #[cfg(target_os = "linux")]
                pidfd,
                config.timeout_seconds,
                Arc::clone(&watchdog_cancel),
                Arc::clone(&watchdog_timed_out),
                cgroup_path,
            );
        } else {
            eprintln!("[procjail] spawn: watchdog disabled for pid={child_pid}");
        }

        Ok(Self {
            child,
            stdin,
            stdout: BufReader::new(stdout),
            max_recv_line_bytes: config.max_recv_line_bytes,
            strategy,
            spawned_at,
            watchdog_cancel,
            watchdog_timed_out,
            cgroup: attached_cgroup,
            killed_by_timeout: false,
        })
    }

    fn validate_inputs(harness_path: &Path, work_dir: &Path, max_recv: usize) -> Result<()> {
        if !work_dir.is_dir() {
            return Err(anyhow::anyhow!(
                "work_dir must be an existing directory, got: {}. Fix: pass a real working directory for the sandbox process.",
                work_dir.display()
            ).into());
        }
        if !harness_path.exists() {
            return Err(anyhow::anyhow!(
                "harness_path must exist, got: {}. Fix: create the harness file first or point procjail at an existing script.",
                harness_path.display()
            ).into());
        }
        if !harness_path.is_file() {
            return Err(anyhow::anyhow!(
                "harness_path must be a file, got: {}. Fix: pass a regular file path instead of a directory or device.",
                harness_path.display()
            ).into());
        }
        if max_recv == 0 {
            return Err(anyhow::Error::new(RecvError::ZeroRecvLimit).into());
        }
        Ok(())
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
    /// # Errors
    /// Returns an error if writing to the stdin pipe fails.
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
    /// # Errors
    /// Returns an error if reading from the stdout pipe fails.
    pub fn recv(&mut self) -> Result<Option<String>> {
        // Bounded read to prevent OOM: untrusted sandboxed code could output
        // an infinite stream without newlines, causing unbounded allocation.
        let mut line = String::new();
        let mut taken = (&mut self.stdout).take(self.max_recv_line_bytes as u64);
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
    /// # Errors
    /// Returns an error if either sending or receiving fails.
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
        self.watchdog_cancel.cancel();

        // Deep isolation tear down natively. Use Kernel limits if bound.
        if let Some(ref cg) = self.cgroup {
            let _ = cg.kill_all();
        }

        if matches!(self.child.try_wait(), Ok(Some(_))) {
            return;
        }
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
    pub fn is_alive(&mut self) -> bool {
        match self.child.try_wait() {
            Ok(None) => true,     // still running
            Ok(Some(_)) => false, // exited
            Err(e) => {
                // Cannot query status (typically ECHILD: the child was already
                // reaped, so it is gone). Surface the error loudly instead of the
                // old `.ok().flatten().is_none()` which SILENTLY swallowed it and
                // reported the process as ALIVE - that would hang any caller that
                // polls is_alive() waiting for exit (Law 10).
                eprintln!(
                    "[procjail] is_alive: try_wait failed ({e}); treating process as not alive"
                );
                false
            }
        }
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
    /// # Errors
    /// Returns an error if the process cannot be waited on.
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
    /// # Errors
    /// Returns an error if reading from the OS process table fails or waiting fails.
    pub fn wait_with_usage(&mut self) -> Result<ResourceUsage> {
        // Capture metrics before reaping, as /proc/<pid> disappears after wait.
        let pid = self.child.id();
        let peak_memory_bytes = self
            .cgroup
            .as_ref()
            .and_then(crate::cgroups::CgroupV2::current_memory_peak)
            .or_else(|| peak_memory_bytes_for_process(pid));
        let cpu_time_secs = cpu_time_secs_for_process(pid);

        // We MUST NOT cancel the watchdog before wait completes, or else `wait()`
        // could hang infinitely on a process that ignores SIGTERM or is deadlocked.
        // Pidfds natively solve PID reuse races for modern unprivileged Sandboxes.
        let status = self.child.wait()?;

        // Cancel the timeout since the app successfully exited natively.
        self.watchdog_cancel.cancel();
        self.killed_by_timeout = self.watchdog_timed_out.load(Ordering::Acquire);

        let wall_time_secs = self.spawned_at.elapsed().as_secs_f64();

        #[cfg(unix)]
        let exit_code = {
            use std::os::unix::process::ExitStatusExt;
            status
                .code()
                .unwrap_or_else(|| status.signal().map_or(-1, |s| s + 128))
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
        self.watchdog_cancel.cancel();
        match self.child.try_wait() {
            Ok(Some(_)) => {}
            Ok(None) | Err(_) => self.kill(),
        }
    }
}

#[derive(Debug, Error)]
enum RecvError {
    #[error("max_recv_line_bytes must be greater than zero")]
    ZeroRecvLimit,
}
