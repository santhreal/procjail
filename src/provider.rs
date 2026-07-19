use std::path::Path;
use std::process::Command;

use crate::config::SandboxConfig;
use crate::Result;

/// A dynamic containment provider API.
///
/// Under the Crate-First Tier architecture of Santh, the community can
/// implement `SandboxProvider` to supply bespoke process isolation techniques
/// such as `Krun` (`MicroVMs`), `gVisor`, `systemd-nspawn`, or `AppArmor` hooks
/// natively into `procjail` without modifying the core crate structure or binary.
pub trait SandboxProvider: std::fmt::Debug + Send + Sync {
    /// Human-readable identifier for the provider (e.g., "gvisor").
    fn name(&self) -> &'static str;

    /// Apply the sandbox containment to a nascent command.
    ///
    /// The provider assumes full responsibility for mutating `cmd` so that
    /// the target `runtime` behaves strictly as specified by `config`.
    ///
    /// # Errors
    /// Returns an error if the host does not support this confinement
    /// implementation or the `config` demands constraints the provider cannot ensure.
    fn apply_to_command(
        &self,
        cmd: &mut Command,
        runtime: &Path,
        work_dir: &Path,
        config: &SandboxConfig,
    ) -> Result<()>;
}
