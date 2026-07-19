use std::path::PathBuf;

use thiserror::Error;

/// Result type for procjail public APIs.
pub type Result<T> = std::result::Result<T, ProcjailError>;

/// Internal command construction failures for sandbox startup.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum BuildCommandError {
    /// Work directory must be absolute.
    #[error("work_dir must be an absolute path, got: {path}")]
    WorkDirNotAbsolute { path: PathBuf },
    /// Harness path must not be empty.
    #[error("harness_path must not be empty")]
    HarnessPathEmpty,
    /// Harness path must be absolute.
    #[error("harness_path must be an absolute path, got: {path}")]
    HarnessPathNotAbsolute { path: PathBuf },
    /// Environment variable names must not be empty.
    #[error("environment variable name must not be empty")]
    EmptyEnvName,
    /// Environment variable names must not contain forbidden characters.
    #[error("environment variable name contains invalid characters: {name:?}")]
    InvalidEnvName { name: String },
    /// Environment variable values must not contain NUL bytes.
    #[error("environment variable value contains NUL byte for key {key:?}")]
    EnvValueContainsNul { key: String },
    /// Environment variable values are bounded to prevent oversized env payloads.
    #[error("environment variable value for {key:?} exceeds {max_bytes} bytes")]
    EnvValueTooLarge { key: String, max_bytes: usize },
    /// Mount host paths must be absolute.
    #[error("{mount_kind} host path must be absolute, got: {path}")]
    MountHostNotAbsolute {
        mount_kind: &'static str,
        path: PathBuf,
    },
    /// Path canonicalization failed (e.g. symlink loop or missing component).
    #[error("path canonicalization failed: {path}. Fix: resolve symlinks and ensure the path exists before sandbox spawn.")]
    CanonicalizationFailed { path: PathBuf },
    /// Custom provider rejected configuration.
    #[error("custom provider '{name}' rejected sandbox config: {reason}")]
    ProviderRejected { name: String, reason: String },
}

/// Public error type for procjail APIs.
///
/// # Thread Safety
/// `ProcjailError` is `Send` and `Sync`.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ProcjailError {
    /// I/O failure while interacting with the sandbox or reading config.
    #[error("{0}. Fix: verify the runtime binary, harness path, work directory, and any config file paths exist and are readable on this host.")]
    Io(#[from] std::io::Error),
    /// TOML parse failure while loading configuration.
    #[error("failed to parse procjail TOML configuration: {0}. Fix: keep settings at the top level, for example `runtime_path = \"node\"` and `timeout_seconds = 30`.")]
    TomlDe(#[from] toml::de::Error),
    /// Generic procjail failure with context.
    #[error("{0}. Fix: verify the runtime path, containment strategy, harness file, and working directory before retrying.")]
    Message(String),
    /// Transparent anyhow error.
    #[error("procjail operation failed: {0}. Fix: verify the runtime path, containment strategy, harness file, and working directory before retrying.")]
    Anyhow(#[from] anyhow::Error),
    /// Command construction failure while validating sandbox inputs.
    #[error("{0}. Fix: pass absolute paths, valid environment variable names, and bounded environment values before spawning the sandbox.")]
    BuildCommand(#[from] BuildCommandError),
}
