//! Sandbox configuration — fully configurable, builder pattern.

use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::{Path, PathBuf};

use crate::strategy::Strategy;
use crate::Result;

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

/// Configuration for sandbox behavior.
///
/// Use [`SandboxConfigBuilder`] for ergonomic construction.
///
/// # Thread Safety
/// `SandboxConfig` is `Send` and `Sync`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
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
    /// Read-only bind mounts: `(host_path, container_path)`.
    pub readonly_mounts: Vec<(PathBuf, PathBuf)>,
    /// Read-write bind mounts: `(host_path, container_path)`.
    pub writable_mounts: Vec<(PathBuf, PathBuf)>,
    /// Timeout for the entire process in seconds (0 = no timeout).
    pub timeout_seconds: u64,
    /// Whether to capture stderr separately (default: pipe to parent's stderr).
    pub capture_stderr: bool,
}

impl Default for SandboxConfig {
    fn default() -> Self {
        Self {
            max_memory_bytes: 256 * 1024 * 1024, // 256 MB
            max_cpu_seconds: 30,
            max_fds: 64,
            max_disk_bytes: 50 * 1024 * 1024, // 50 MB
            max_processes: 32,
            allow_localhost: false,
            runtime_path: PathBuf::from("node"),
            runtime_args: Vec::new(),
            env_passthrough: HashSet::new(),
            env_set: Vec::new(),
            env_strip: HashSet::new(),
            env_strip_secrets: true,
            env_mode: EnvMode::StripSecrets,
            force_strategy: None,
            readonly_mounts: Vec::new(),
            writable_mounts: Vec::new(),
            timeout_seconds: 60,
            capture_stderr: false,
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
    #[must_use]
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let config = toml::from_str(&content)?;
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
    #[must_use]
    pub fn stripped_env_vars(&self) -> HashSet<&str> {
        let mut stripped: HashSet<&str> = self.env_strip.iter().map(String::as_str).collect();
        if self.env_strip_secrets {
            for var in DEFAULT_SECRET_ENV_VARS {
                stripped.insert(var);
            }
        }
        stripped
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
                .map(|strategy| strategy.to_string())
                .unwrap_or_else(|| "auto".to_string())
        )
    }
}

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config() {
        let config = SandboxConfig::default();
        assert_eq!(config.max_memory_bytes, 256 * 1024 * 1024);
        assert_eq!(config.max_cpu_seconds, 30);
        assert_eq!(config.max_fds, 64);
        assert!(!config.allow_localhost);
        assert!(config.env_strip_secrets);
        assert_eq!(config.timeout_seconds, 60);
    }

    #[test]
    fn builder_works() {
        let config = SandboxConfig::builder()
            .runtime("/usr/bin/python3")
            .max_memory_mb(512)
            .max_cpu_seconds(60)
            .max_fds(128)
            .max_processes(64)
            .allow_localhost(true)
            .env_passthrough(&["HOME", "PATH"])
            .env_set("MY_VAR", "my_value")
            .env_strip_secrets(true)
            .env_strip(&["CUSTOM_SECRET"])
            .timeout_seconds(120)
            .capture_stderr(true)
            .build();

        assert_eq!(config.runtime_path, PathBuf::from("/usr/bin/python3"));
        assert_eq!(config.max_memory_bytes, 512 * 1024 * 1024);
        assert_eq!(config.max_cpu_seconds, 60);
        assert_eq!(config.max_fds, 128);
        assert_eq!(config.max_processes, 64);
        assert!(config.allow_localhost);
        assert!(config.env_passthrough.contains("HOME"));
        assert!(config.env_passthrough.contains("PATH"));
        assert_eq!(config.env_set[0], ("MY_VAR".into(), "my_value".into()));
        assert!(config.env_strip.contains("CUSTOM_SECRET"));
        assert_eq!(config.timeout_seconds, 120);
        assert!(config.capture_stderr);
    }

    #[test]
    fn stripped_env_vars_includes_defaults() {
        let config = SandboxConfig::default();
        let stripped = config.stripped_env_vars();
        assert!(stripped.contains("AWS_ACCESS_KEY_ID"));
        assert!(stripped.contains("GITHUB_TOKEN"));
        assert!(stripped.contains("ANTHROPIC_API_KEY"));
        assert!(stripped.contains("OPENAI_API_KEY"));
        assert!(stripped.len() >= 30);
    }

    #[test]
    fn stripped_env_vars_custom_additions() {
        let config = SandboxConfig::builder()
            .env_strip(&["MY_SECRET_1", "MY_SECRET_2"])
            .build();

        let stripped = config.stripped_env_vars();
        assert!(stripped.contains("MY_SECRET_1"));
        assert!(stripped.contains("MY_SECRET_2"));
        assert!(stripped.contains("AWS_ACCESS_KEY_ID")); // defaults still there
    }

    #[test]
    fn stripped_env_vars_no_defaults() {
        let config = SandboxConfig::builder()
            .env_strip_secrets(false)
            .env_strip(&["ONLY_THIS"])
            .build();

        let stripped = config.stripped_env_vars();
        assert!(stripped.contains("ONLY_THIS"));
        assert!(!stripped.contains("AWS_ACCESS_KEY_ID"));
    }

    #[test]
    fn builder_mounts() {
        let config = SandboxConfig::builder()
            .readonly_mount("/usr/lib", "/usr/lib")
            .writable_mount("/tmp/work", "/work")
            .build();

        assert_eq!(config.readonly_mounts.len(), 1);
        assert_eq!(config.writable_mounts.len(), 1);
        assert_eq!(config.readonly_mounts[0].0, PathBuf::from("/usr/lib"));
        assert_eq!(config.writable_mounts[0].1, PathBuf::from("/work"));
    }

    #[test]
    fn builder_runtime_args() {
        let config = SandboxConfig::builder()
            .runtime("node")
            .runtime_args(&["--experimental-vm-modules", "--max-old-space-size=256"])
            .build();

        assert_eq!(config.runtime_args.len(), 2);
        assert_eq!(config.runtime_args[0], "--experimental-vm-modules");
    }

    #[test]
    fn load_toml_config_success() {
        use std::io::Write;
        let mut file = tempfile::NamedTempFile::new().unwrap();
        let toml_content = r#"
max_memory_bytes = 104857600
max_cpu_seconds = 15
max_fds = 32
max_disk_bytes = 20971520
max_processes = 16
allow_localhost = true
runtime_path = "/usr/bin/custom"
runtime_args = ["--flag"]
env_passthrough = ["HOME"]
env_set = [["MY_VAR", "value"]]
env_strip = ["SECRET"]
env_strip_secrets = false
env_mode = "allowlist"
readonly_mounts = [["/host", "/container"]]
writable_mounts = [["/host_w", "/container_w"]]
timeout_seconds = 45
capture_stderr = true
"#;
        file.write_all(toml_content.as_bytes()).unwrap();
        let config = SandboxConfig::load(file.path()).unwrap();
        assert_eq!(config.max_memory_bytes, 104857600);
        assert_eq!(config.max_cpu_seconds, 15);
        assert_eq!(config.max_fds, 32);
        assert_eq!(config.max_disk_bytes, 20971520);
        assert_eq!(config.max_processes, 16);
        assert!(config.allow_localhost);
        assert_eq!(config.runtime_path, PathBuf::from("/usr/bin/custom"));
        assert_eq!(config.runtime_args, vec!["--flag"]);
        assert!(config.env_passthrough.contains("HOME"));
        assert_eq!(config.env_set[0], ("MY_VAR".into(), "value".into()));
        assert!(config.env_strip.contains("SECRET"));
        assert!(!config.env_strip_secrets);
        assert_eq!(config.env_mode, EnvMode::Allowlist);
        assert_eq!(
            config.readonly_mounts[0],
            (PathBuf::from("/host"), PathBuf::from("/container"))
        );
        assert_eq!(
            config.writable_mounts[0],
            (PathBuf::from("/host_w"), PathBuf::from("/container_w"))
        );
        assert_eq!(config.timeout_seconds, 45);
        assert!(config.capture_stderr);
    }

    #[test]
    fn load_toml_config_missing_file() {
        let result = SandboxConfig::load("/does/not/exist.toml");
        assert!(result.is_err());
    }

    #[test]
    fn load_toml_config_invalid_toml() {
        use std::io::Write;
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(b"invalid toml content = [[").unwrap();
        let result = SandboxConfig::load(file.path());
        assert!(result.is_err());
    }

    #[test]
    fn test_builder_max_disk_mb() {
        let config = SandboxConfig::builder().max_disk_mb(100).build();
        assert_eq!(config.max_disk_bytes, 100 * 1024 * 1024);
    }

    #[test]
    fn test_builder_max_memory_bytes() {
        let config = SandboxConfig::builder().max_memory_bytes(1000).build();
        assert_eq!(config.max_memory_bytes, 1000);
    }

    #[test]
    fn test_builder_env_mode() {
        let config = SandboxConfig::builder()
            .env_mode(EnvMode::Blocklist)
            .build();
        assert_eq!(config.env_mode, EnvMode::Blocklist);
    }

    #[test]
    fn test_builder_strategy() {
        let config = SandboxConfig::builder()
            .strategy(Strategy::Firejail)
            .build();
        assert_eq!(config.force_strategy, Some(Strategy::Firejail));
    }

    #[test]
    fn test_builder_max_fds() {
        let config = SandboxConfig::builder().max_fds(256).build();
        assert_eq!(config.max_fds, 256);
    }

    #[test]
    fn test_builder_allow_localhost() {
        let config = SandboxConfig::builder().allow_localhost(true).build();
        assert!(config.allow_localhost);
    }

    #[test]
    fn test_builder_default() {
        let config = SandboxConfigBuilder::default().build();
        assert_eq!(config.max_cpu_seconds, 30);
    }

    #[test]
    fn test_stripped_env_vars_allowlist() {
        let config = SandboxConfig::builder()
            .env_mode(EnvMode::Allowlist)
            .env_strip_secrets(false)
            .build();
        assert!(config.stripped_env_vars().is_empty());
    }
}
