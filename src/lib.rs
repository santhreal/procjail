#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::todo,
        clippy::unimplemented,
        clippy::panic
    )
)]
#![allow(
    clippy::module_name_repetitions,
    clippy::must_use_candidate,
    clippy::missing_errors_doc,
)]
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
//! 1. **unshare**  -  Linux namespaces (PID, network, mount, user). No root needed.
//! 2. **bubblewrap (bwrap)**  -  Lightweight container (Flatpak uses this). Rootless.
//! 3. **firejail**  -  Feature-rich sandbox. Needs installation.
//! 4. **rlimits**  -  Basic resource limits only. Always available. Least secure.
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
#![warn(clippy::pedantic)]
#![allow(clippy::too_many_lines)]
#![allow(clippy::useless_conversion)]

mod cgroups;
mod config;

mod detect;
mod error;
mod process;
mod provider;
pub mod strategy;

pub use config::{EnvMode, SandboxConfig, SandboxConfigBuilder, DEFAULT_SECRET_ENV_VARS};
pub use detect::{available_strategy, probe_capabilities, ContainmentLevel};
pub use error::{ProcjailError, Result};
pub use process::{ResourceUsage, SandboxedProcess};
pub use provider::SandboxProvider;
pub use strategy::Strategy;

/// Trait for communicating with a sandboxed process.
///
/// # Thread Safety
/// This trait does not require `Send` or `Sync`. Thread-safety depends on the
/// concrete implementing type.
pub trait SandboxedIO {
    /// Send a line to the process.
    /// # Errors
    /// Returns an error if writing to the sandbox fails.
    fn send(&mut self, line: &str) -> Result<()>;
    /// Receive a line from the process. None = EOF.
    /// # Errors
    /// Returns an error if reading from the sandbox fails.
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
/// # Errors
/// Returns an error if the sandbox cannot be spawned.
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
pub mod seccomp;

#[cfg(test)]
mod audit_tests;
