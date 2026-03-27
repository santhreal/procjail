//! # procjail
//!
//! Process sandbox for running untrusted code in real runtimes.
//!
//! When security tools need to execute untrusted code (npm packages, pip
//! packages, browser extensions, binaries), they need containment that
//! actually works. This crate provides kernel-level isolation using the
//! best available mechanism on the host.
//!
//! # Containment Strategies (ordered by preference)
//!
//! 1. **unshare** — Linux namespaces (PID, network, mount, user). No root needed.
//! 2. **bubblewrap (bwrap)** — Lightweight container (Flatpak uses this). Rootless.
//! 3. **firejail** — Feature-rich sandbox. Needs installation.
//! 4. **rlimits** — Basic resource limits only. Always available. Least secure.
//!
//! The sandbox auto-selects the best available strategy, or you can force one.
//!
//! # Usage
//!
//! ```rust,no_run
//! use std::path::Path;
//! use procjail::{SandboxConfig, SandboxedProcess};
//!
//! let config = SandboxConfig::builder()
//!     .runtime("/usr/bin/node")
//!     .max_memory_mb(256)
//!     .max_cpu_seconds(30)
//!     .max_fds(64)
//!     .allow_localhost(false)
//!     .env_passthrough(&["HOME", "PATH", "NODE_PATH"])
//!     .env_strip_secrets(true)
//!     .build();
//!
//! let mut proc = SandboxedProcess::spawn(
//!     Path::new("/path/to/harness.js"),
//!     Path::new("/path/to/package"),
//!     &config,
//! ).unwrap();
//!
//! proc.send(r#"{"method":"eval","args":["1+1"]}"#).unwrap();
//! if let Some(line) = proc.recv().unwrap() {
//!     println!("observation: {}", line);
//! }
//! ```
//!
//! # Architecture
//!
//! ```text
//! Parent (full privileges)
//!   │
//!   ├── stdin pipe  → probes flow in
//!   ├── stdout pipe ← observations flow out
//!   │
//!   └── [containment layer]
//!         ├── PID namespace (process isolation)
//!         ├── NET namespace (no external network)
//!         ├── MNT namespace (read-only filesystem)
//!         ├── USER namespace (unprivileged)
//!         ├── rlimits (memory, CPU, FDs)
//!         └── env stripping (no secrets leak)
//! ```

// Note: unsafe code is used in process.rs for libc calls
#![warn(missing_docs)]

mod config;
mod detect;
mod error;
mod process;
mod strategy;

#[cfg(test)]
mod adversarial_tests;

pub use config::{EnvMode, SandboxConfig, SandboxConfigBuilder};
pub use detect::{available_strategy, probe_capabilities, ContainmentLevel};
pub use error::{ProcjailError, Result};
pub use process::{ResourceUsage, SandboxedProcess};
pub use strategy::Strategy;

/// Trait for communicating with a sandboxed process.
///
/// # Thread Safety
/// This trait does not require `Send` or `Sync`. Thread-safety depends on the
/// concrete implementing type.
pub trait SandboxedIO {
    /// Send a line to the process.
    fn send(&mut self, line: &str) -> Result<()>;
    /// Receive a line from the process. None = EOF.
    fn recv(&mut self) -> Result<Option<String>>;
    /// Kill the process.
    fn kill(&mut self);
    /// Check if alive.
    fn is_alive(&mut self) -> bool;
}

/// Convenience helper that spawns a sandboxed process with a minimal default config.
///
/// Example:
/// ```rust,no_run
/// use std::path::Path;
/// use procjail::quick_spawn;
///
/// let _child = quick_spawn(
///     "node",
///     Path::new("/abs/path/to/harness.js"),
///     Path::new("/abs/path/to/workdir"),
/// )?;
/// # Ok::<(), procjail::ProcjailError>(())
/// ```
#[must_use]
pub fn quick_spawn(
    runtime: &str,
    harness: impl AsRef<std::path::Path>,
    work_dir: impl AsRef<std::path::Path>,
) -> Result<process::SandboxedProcess> {
    let config = config::SandboxConfig::builder()
        .runtime(runtime)
        .timeout_seconds(30)
        .build();
    process::SandboxedProcess::spawn(harness.as_ref(), work_dir.as_ref(), &config)
}
