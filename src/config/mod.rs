pub mod builder;

/// Sandbox configuration  -  fully configurable, builder pattern.
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::{Path, PathBuf};

use crate::provider::SandboxProvider;
use crate::strategy::Strategy;

pub use crate::config::builder::{EnvMode, SandboxConfigBuilder};
use crate::Result;
use std::sync::Arc;

/// Well-known secret environment variables that should never leak into sandboxed processes.
pub const DEFAULT_SECRET_ENV_VARS: &[&str] = &[
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "GITHUB_TOKEN",
    "GH_TOKEN",
    "GITLAB_TOKEN",
    "NPM_TOKEN",
    "DATABASE_URL",
    "PGPASSWORD",
    "MYSQL_PWD",
    "REDIS_URL",
    "REDIS_PASSWORD",
    "SENTRY_DSN",
    "STRIPE_SECRET_KEY",
    "STRIPE_API_KEY",
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "GOOGLE_API_KEY",
    "SLACK_TOKEN",
    "SLACK_BOT_TOKEN",
    "DISCORD_TOKEN",
    "TELEGRAM_BOT_TOKEN",
    "TWILIO_AUTH_TOKEN",
    "SENDGRID_API_KEY",
    "DOCKER_PASSWORD",
    "DOCKER_AUTH_CONFIG",
    "KUBECONFIG",
    "SSH_AUTH_SOCK",
    "GPG_PASSPHRASE",
    "PYPI_TOKEN",
    "CARGO_REGISTRY_TOKEN",
    "NUGET_API_KEY",
    "HEROKU_API_KEY",
    "DIGITALOCEAN_TOKEN",
    "VAULT_TOKEN",
    "CONSUL_TOKEN",
];

/// Secret environment variable prefixes that should never leak into sandboxed processes.
pub const DEFAULT_SECRET_ENV_PREFIXES: &[&str] = &["AWS_", "GCP_", "AZURE_"];

/// Configuration for sandbox behavior.
///
/// Use [`SandboxConfigBuilder`] for ergonomic construction.
///
/// # Thread Safety
/// `SandboxConfig` is `Send` and `Sync`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
#[allow(clippy::struct_excessive_bools)]
pub struct SandboxConfig {
    /// Maximum memory in bytes.
    pub max_memory_bytes: u64,
    /// Maximum CPU time in seconds.
    pub max_cpu_seconds: u64,
    /// Maximum open file descriptors.
    pub max_fds: u64,
    /// Maximum writable disk space in bytes.
    pub max_disk_bytes: u64,
    /// Maximum number of processes/threads.
    pub max_processes: u64,
    /// Require cgroup v2 hardware limits (memory/CPU/pids). When `true`, spawn
    /// fails closed if the cgroup cannot be created; when `false`, spawn continues
    /// with a loud warning (never a silent degrade). Default `false` for
    /// compatibility with hosts lacking cgroup v2 (CI, containers, non-Linux).
    pub require_hardware_limits: bool,
    /// Allow localhost networking (e.g. for web server testing).
    pub allow_localhost: bool,
    /// Path to the runtime binary (e.g. "/usr/bin/node", "/usr/bin/python3").
    pub runtime_path: PathBuf,
    /// Runtime arguments inserted before the harness path (e.g. `["--experimental-vm-modules"]`).
    pub runtime_args: Vec<String>,
    /// Environment variables to pass through to the sandboxed process.
    pub env_passthrough: HashSet<String>,
    /// Additional environment variables to set in the sandboxed process.
    pub env_set: Vec<(String, String)>,
    /// Environment variables to explicitly strip (added to defaults when `env_strip_secrets` is true).
    pub env_strip: HashSet<String>,
    /// Whether to strip all known secret env vars (see `DEFAULT_SECRET_ENV_VARS`).
    pub env_strip_secrets: bool,
    /// How environment variables are propagated into the sandbox.
    pub env_mode: EnvMode,
    /// Force a specific containment strategy. `None` = auto-detect best.
    pub force_strategy: Option<Strategy>,
    /// Community-driven backend that overrides `force_strategy` entirely if set.
    #[serde(skip)]
    pub custom_provider: Option<Arc<dyn SandboxProvider>>,
    /// Read-only bind mounts: `(host_path, container_path)`.
    pub readonly_mounts: Vec<(PathBuf, PathBuf)>,
    /// Read-write bind mounts: `(host_path, container_path)`.
    pub writable_mounts: Vec<(PathBuf, PathBuf)>,
    /// Timeout for the entire process in seconds (0 = no timeout).
    pub timeout_seconds: u64,
    /// Whether to capture stderr separately (default: pipe to parent's stderr).
    pub capture_stderr: bool,
    /// Maximum bytes to read from stdout in one `recv()` call.
    pub max_recv_line_bytes: usize,
}

impl Default for SandboxConfig {
    fn default() -> Self {
        Self {
            max_memory_bytes: 256 * 1024 * 1024, // 256 MB
            max_cpu_seconds: 30,
            max_fds: 64,
            max_disk_bytes: 50 * 1024 * 1024, // 50 MB
            max_processes: 32,
            require_hardware_limits: false,
            allow_localhost: false,
            runtime_path: PathBuf::from("node"),
            runtime_args: Vec::new(),
            env_passthrough: HashSet::new(),
            env_set: Vec::new(),
            env_strip: HashSet::new(),
            env_strip_secrets: true,
            env_mode: EnvMode::StripSecrets,
            force_strategy: None,
            custom_provider: None,
            readonly_mounts: Vec::new(),
            writable_mounts: Vec::new(),
            timeout_seconds: 60,
            capture_stderr: false,
            max_recv_line_bytes: 1024 * 1024,
        }
    }
}

impl SandboxConfig {
    /// Load configuration from a TOML file.
    ///
    /// The default configuration uses the `node` runtime, a 256 MiB memory cap,
    /// a 60 second timeout, and strips known secret environment variables.
    ///
    /// Example:
    /// ```rust
    /// use procjail::SandboxConfig;
    ///
    /// let dir = tempfile::tempdir().unwrap();
    /// let path = dir.path().join("sandbox.toml");
    /// std::fs::write(&path, "runtime_path = \"python3\"\nmax_cpu_seconds = 10\n").unwrap();
    ///
    /// let config = SandboxConfig::load(&path).unwrap();
    /// assert_eq!(config.runtime_path.to_string_lossy(), "python3");
    /// ```
    /// # Errors
    /// Returns an error if the TOML file cannot be read or parsed.
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let config = toml::from_str(&content)?;
        Ok(config)
    }

    /// Load configuration from a TOML byte slice.
    ///
    /// # Errors
    /// Returns an error if the slice cannot be parsed as a TOML document.
    pub fn from_toml_bytes(bytes: &[u8]) -> Result<Self> {
        let content = std::str::from_utf8(bytes)
            .map_err(|e| anyhow::anyhow!("Invalid UTF-8 in TOML configuration: {e}"))?;
        let config = toml::from_str(content)?;
        Ok(config)
    }

    /// Start building a config.
    ///
    /// Example:
    /// ```rust
    /// use procjail::SandboxConfig;
    ///
    /// let config = SandboxConfig::builder().runtime("python3").timeout_seconds(15).build();
    /// assert_eq!(config.timeout_seconds, 15);
    /// ```
    #[must_use]
    pub fn builder() -> SandboxConfigBuilder {
        SandboxConfigBuilder::new()
    }

    /// All env vars that should be stripped from the sandboxed process.
    ///
    /// Example:
    /// ```rust
    /// use procjail::SandboxConfig;
    ///
    /// let config = SandboxConfig::default();
    /// let stripped = config.stripped_env_vars();
    /// assert!(stripped.contains("OPENAI_API_KEY"));
    /// ```
    pub fn stripped_env_vars(&self) -> HashSet<&str> {
        let mut stripped: HashSet<&str> = self.env_strip.iter().map(String::as_str).collect();
        if self.env_strip_secrets {
            for var in DEFAULT_SECRET_ENV_VARS {
                stripped.insert(var);
            }
        }
        stripped
    }

    /// Returns true when an environment variable name should be treated as secret.
    ///
    /// Example:
    /// ```rust
    /// use procjail::SandboxConfig;
    ///
    /// let config = SandboxConfig::default();
    /// assert!(config.is_secret_env_var("AWS_PROFILE_TOKEN"));
    /// assert!(config.is_secret_env_var("GITHUB_TOKEN"));
    /// assert!(!config.is_secret_env_var("PATH"));
    /// ```
    #[must_use]
    pub fn is_secret_env_var(&self, name: &str) -> bool {
        self.env_strip.contains(name)
            || (self.env_strip_secrets
                && (DEFAULT_SECRET_ENV_VARS.contains(&name)
                    || DEFAULT_SECRET_ENV_PREFIXES
                        .iter()
                        .any(|prefix| name.starts_with(prefix))))
    }
}

impl std::fmt::Display for SandboxConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "SandboxConfig(runtime={}, timeout_seconds={}, strategy={})",
            self.runtime_path.display(),
            self.timeout_seconds,
            self.force_strategy
                .map_or_else(|| "auto".to_string(), |strategy| strategy.to_string())
        )
    }
}

#[cfg(test)]
mod require_hardware_limits_tests {
    use super::SandboxConfig;

    #[test]
    fn defaults_to_not_requiring_hardware_limits() {
        assert!(
            !SandboxConfig::default().require_hardware_limits,
            "default must be false for compatibility with cgroup-less hosts"
        );
    }

    #[test]
    fn builder_sets_require_hardware_limits() {
        let config = SandboxConfig::builder()
            .require_hardware_limits(true)
            .build();
        assert!(config.require_hardware_limits);
        let config = SandboxConfig::builder()
            .require_hardware_limits(false)
            .build();
        assert!(!config.require_hardware_limits);
    }

    #[test]
    fn require_hardware_limits_parses_from_toml() {
        let config =
            SandboxConfig::from_toml_bytes(b"require_hardware_limits = true").expect("parse toml");
        assert!(config.require_hardware_limits);
    }
}
