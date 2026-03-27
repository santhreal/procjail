use thiserror::Error;

/// Result type for procjail public APIs.
pub type Result<T> = std::result::Result<T, ProcjailError>;

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
}
