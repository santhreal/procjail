use std::path::PathBuf;
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::{provider::SandboxProvider, Strategy};

use crate::config::SandboxConfig;

/// Builder for [`SandboxConfig`].
///
/// # Thread Safety
/// `SandboxConfigBuilder` is `Send` and `Sync`.
#[derive(Debug, Clone)]
pub struct SandboxConfigBuilder {
    config: SandboxConfig,
}

impl std::fmt::Display for SandboxConfigBuilder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SandboxConfigBuilder({})", self.config)
    }
}

impl SandboxConfigBuilder {
    /// Create a new builder with default values.
    ///
    /// Example:
    /// ```rust
    /// use procjail::SandboxConfigBuilder;
    ///
    /// let config = SandboxConfigBuilder::new().build();
    /// assert_eq!(config.timeout_seconds, 60);
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self {
            config: SandboxConfig::default(),
        }
    }

    /// Set the runtime binary path.
    #[must_use]
    pub fn runtime(mut self, path: &str) -> Self {
        self.config.runtime_path = PathBuf::from(path);
        self
    }

    /// Add arguments to pass to the runtime before the harness script.
    #[must_use]
    pub fn runtime_args(mut self, args: &[&str]) -> Self {
        self.config.runtime_args = args.iter().map(|&s| s.to_string()).collect();
        self
    }

    /// Set maximum memory in megabytes.
    #[must_use]
    pub fn max_memory_mb(mut self, mb: u64) -> Self {
        self.config.max_memory_bytes = mb * 1024 * 1024;
        self
    }

    /// Set maximum memory in bytes.
    #[must_use]
    pub fn max_memory_bytes(mut self, bytes: u64) -> Self {
        self.config.max_memory_bytes = bytes;
        self
    }

    /// Set maximum CPU time in seconds.
    #[must_use]
    pub fn max_cpu_seconds(mut self, seconds: u64) -> Self {
        self.config.max_cpu_seconds = seconds;
        self
    }

    /// Set maximum open file descriptors.
    #[must_use]
    pub fn max_fds(mut self, fds: u64) -> Self {
        self.config.max_fds = fds;
        self
    }

    /// Set maximum writable disk space in megabytes.
    #[must_use]
    pub fn max_disk_mb(mut self, mb: u64) -> Self {
        self.config.max_disk_bytes = mb * 1024 * 1024;
        self
    }

    /// Set maximum child processes/threads.
    #[must_use]
    pub fn max_processes(mut self, n: u64) -> Self {
        self.config.max_processes = n;
        self
    }

    /// Require cgroup v2 hardware limits. When `true`, spawn fails closed if the
    /// cgroup cannot be created instead of running without memory/CPU/pids limits.
    #[must_use]
    pub fn require_hardware_limits(mut self, require: bool) -> Self {
        self.config.require_hardware_limits = require;
        self
    }

    /// Allow localhost networking.
    #[must_use]
    pub fn allow_localhost(mut self, allow: bool) -> Self {
        self.config.allow_localhost = allow;
        self
    }

    /// Set environment variables to pass through.
    #[must_use]
    pub fn env_passthrough(mut self, vars: &[&str]) -> Self {
        self.config.env_passthrough = vars.iter().map(|&s| s.to_string()).collect();
        self
    }

    /// Set additional env vars in the sandbox.
    #[must_use]
    pub fn env_set(mut self, key: &str, value: &str) -> Self {
        self.config.env_set.push((key.into(), value.into()));
        self
    }

    /// Whether to strip known secret env vars.
    #[must_use]
    pub fn env_strip_secrets(mut self, strip: bool) -> Self {
        self.config.env_strip_secrets = strip;
        self
    }

    /// Add specific env vars to strip.
    #[must_use]
    pub fn env_strip(mut self, vars: &[&str]) -> Self {
        for v in vars {
            self.config.env_strip.insert(v.to_string());
        }
        self
    }

    /// Configure how environment variables are propagated.
    #[must_use]
    pub fn env_mode(mut self, mode: EnvMode) -> Self {
        self.config.env_mode = mode;
        self
    }

    /// Force a specific containment strategy.
    #[must_use]
    pub fn strategy(mut self, strategy: Strategy) -> Self {
        self.config.force_strategy = Some(strategy);
        self
    }

    /// Set a highly custom, community-built isolation provider natively.
    #[must_use]
    pub fn custom_provider(mut self, provider: Arc<dyn SandboxProvider>) -> Self {
        self.config.custom_provider = Some(provider);
        self
    }

    /// Add a read-only bind mount.
    #[must_use]
    pub fn readonly_mount(mut self, host: &str, container: &str) -> Self {
        self.config
            .readonly_mounts
            .push((host.into(), container.into()));
        self
    }

    /// Add a read-write bind mount.
    #[must_use]
    pub fn writable_mount(mut self, host: &str, container: &str) -> Self {
        self.config
            .writable_mounts
            .push((host.into(), container.into()));
        self
    }

    /// Set process timeout in seconds (0 = no timeout).
    #[must_use]
    pub fn timeout_seconds(mut self, seconds: u64) -> Self {
        self.config.timeout_seconds = seconds;
        self
    }

    /// Capture stderr separately instead of piping to parent.
    #[must_use]
    pub fn capture_stderr(mut self, capture: bool) -> Self {
        self.config.capture_stderr = capture;
        self
    }

    /// Set the maximum number of bytes read from stdout in a single `recv()` call.
    #[must_use]
    pub fn max_recv_line_bytes(mut self, bytes: usize) -> Self {
        self.config.max_recv_line_bytes = bytes;
        self
    }

    /// Build the config.
    ///
    /// Example:
    /// ```rust
    /// use procjail::SandboxConfig;
    ///
    /// let config = SandboxConfig::builder().runtime("node").build();
    /// assert_eq!(config.runtime_path.to_string_lossy(), "node");
    /// ```
    #[must_use]
    pub fn build(self) -> SandboxConfig {
        self.config
    }
}

impl Default for SandboxConfigBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Environment inheritance strategy for the sandbox process.
///
/// # Thread Safety
/// `EnvMode` is `Send` and `Sync`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum EnvMode {
    /// Keep current behavior: inherit host environment and strip secret values.
    StripSecrets,
    /// Only pass through `env_passthrough` variables and `env_set` overrides.
    Allowlist,
    /// Inherit host environment except values listed in `env_strip` and secret defaults.
    Blocklist,
}

impl std::fmt::Display for EnvMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            Self::StripSecrets => "strip-secrets",
            Self::Allowlist => "allowlist",
            Self::Blocklist => "blocklist",
        };
        f.write_str(name)
    }
}
