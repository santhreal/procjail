//! Capability detection  -  probe the host to find what containment is available.

use std::process::{Command, Stdio};

use crate::strategy::Strategy;

/// How much containment is available on this host.
///
/// # Thread Safety
/// `ContainmentLevel` is `Send` and `Sync`.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[allow(clippy::struct_excessive_bools)]
pub struct ContainmentLevel {
    /// Best strategy available.
    pub best_strategy: Strategy,
    /// Whether unprivileged user namespaces work.
    pub has_user_ns: bool,
    /// Whether `unshare` works with PID + NET + USER namespaces.
    pub has_unshare: bool,
    /// Whether `bwrap` (bubblewrap) is installed and functional.
    pub has_bubblewrap: bool,
    /// Whether `firejail` is installed and functional.
    pub has_firejail: bool,
    /// Human-readable diagnostics explaining why a strategy is unavailable.
    pub diagnostics: Vec<String>,
}

impl std::fmt::Display for ContainmentLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "ContainmentLevel(best={}, unshare={}, bubblewrap={}, firejail={})",
            self.best_strategy, self.has_unshare, self.has_bubblewrap, self.has_firejail
        )?;
        for diag in &self.diagnostics {
            write!(f, "; {diag}")?;
        }
        Ok(())
    }
}

/// Probe the host and return what containment is available.
///
/// This runs small test commands to verify each mechanism actually works
/// (not just that the binary exists).
///
/// Example:
/// ```rust,no_run
/// use procjail::probe_capabilities;
///
/// let level = probe_capabilities();
/// println!("best strategy: {}", level.best_strategy);
/// ```
#[must_use]
pub fn probe_capabilities() -> ContainmentLevel {
    let mut diagnostics = Vec::new();

    let unshare_res = check_unshare();
    let has_unshare = unshare_res.as_ref().map_or_else(
        |e| {
            diagnostics.push(format!(
                "unshare unavailable: {e}. Fix: enable unprivileged user namespaces (sysctl kernel.unprivileged_userns_clone=1) or install bubblewrap."
            ));
            false
        },
        |v| *v,
    );

    let bwrap_res = check_bubblewrap();
    let has_bubblewrap = bwrap_res.as_ref().map_or_else(
        |e| {
            diagnostics.push(format!(
                "bubblewrap unavailable: {e}. Fix: install bubblewrap."
            ));
            false
        },
        |v| *v,
    );

    let firejail_res = check_firejail();
    let has_firejail = firejail_res.as_ref().map_or_else(
        |e| {
            diagnostics.push(format!(
                "firejail unavailable: {e}. Fix: install firejail."
            ));
            false
        },
        |v| *v,
    );

    let has_user_ns = has_unshare || has_bubblewrap;

    let best_strategy = if has_bubblewrap {
        Strategy::Bubblewrap
    } else if has_unshare {
        Strategy::Unshare
    } else if has_firejail {
        Strategy::Firejail
    } else {
        Strategy::RlimitsOnly
    };

    ContainmentLevel {
        best_strategy,
        has_user_ns,
        has_unshare,
        has_bubblewrap,
        has_firejail,
        diagnostics,
    }
}

/// Return the best available containment strategy for the current host.
///
/// Example:
/// ```rust,no_run
/// use procjail::available_strategy;
///
/// let strategy = available_strategy();
/// assert!(!strategy.to_string().is_empty());
/// ```
#[must_use]
pub fn available_strategy() -> Strategy {
    probe_capabilities().best_strategy
}

/// Check if `unshare` with user + PID + net namespaces actually works.
fn check_unshare() -> std::io::Result<bool> {
    // Probe the same namespaces the real sandbox creates: build_unshare_command
    // uses --mount and --mount-proc, so the probe must too, otherwise a host that
    // allows --pid/--fork but denies a new mount namespace would false-report
    // unshare as usable. --mount does not hide inherited mounts, so `echo` still
    // resolves via PATH inside the probe.
    Command::new("unshare")
        .args([
            "--pid",
            "--fork",
            "--mount-proc",
            "--mount",
            "--map-root-user",
            "--",
            "echo",
            "ok",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .map(|o| o.status.success() && String::from_utf8_lossy(&o.stdout).contains("ok"))
}

/// Check if bubblewrap is installed and works.
fn check_bubblewrap() -> std::io::Result<bool> {
    // Probe the SAME filesystem layout the real sandbox uses: an empty tmpfs
    // root (build_bwrap_command uses `--tmpfs /`), not `--ro-bind / /` which
    // exposes the whole host root and tests a different, weaker configuration.
    // The probe command needs its own binary and libraries present under the
    // tmpfs root, so bind the minimal system dirs; `--ro-bind-try` skips any
    // that do not exist on this host (merged-/usr, no /lib64, etc.) instead of
    // failing the probe and false-reporting bwrap as unavailable.
    Command::new("bwrap")
        .args([
            "--tmpfs",
            "/",
            "--proc",
            "/proc",
            "--dev",
            "/dev",
            "--ro-bind",
            "/usr",
            "/usr",
            "--ro-bind-try",
            "/bin",
            "/bin",
            "--ro-bind-try",
            "/lib",
            "/lib",
            "--ro-bind-try",
            "/lib64",
            "/lib64",
            "--",
            "/bin/echo",
            "ok",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .map(|o| o.status.success() && String::from_utf8_lossy(&o.stdout).contains("ok"))
}

/// Check if firejail is installed and can execute a minimal real sandbox.
fn check_firejail() -> std::io::Result<bool> {
    Command::new("firejail")
        .args(["--noprofile", "--", "echo", "ok"])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .map(|o| o.status.success() && String::from_utf8_lossy(&o.stdout).contains("ok"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_returns_valid_strategy() {
        let level = probe_capabilities();
        // Strategy must be one of the valid variants.
        let valid = matches!(
            level.best_strategy,
            Strategy::Unshare | Strategy::Bubblewrap | Strategy::Firejail | Strategy::RlimitsOnly
        );
        assert!(valid, "invalid strategy: {:?}", level.best_strategy);
    }

    #[test]
    fn strategy_consistency() {
        let level = probe_capabilities();
        if level.has_bubblewrap {
            assert_eq!(level.best_strategy, Strategy::Bubblewrap);
        }
        if !level.has_bubblewrap && level.has_unshare {
            assert_eq!(level.best_strategy, Strategy::Unshare);
        }
    }
}
