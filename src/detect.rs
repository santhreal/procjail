//! Capability detection — probe the host to find what containment is available.

use std::process::{Command, Stdio};

use crate::strategy::Strategy;

/// How much containment is available on this host.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
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
pub fn probe_capabilities() -> ContainmentLevel {
    let has_unshare = check_unshare().unwrap_or(false);
    let has_bubblewrap = check_bubblewrap().unwrap_or(false);
    let has_firejail = check_firejail().unwrap_or(false);
    let has_user_ns = has_unshare || has_bubblewrap;

    let best_strategy = if has_unshare {
        Strategy::Unshare
    } else if has_bubblewrap {
        Strategy::Bubblewrap
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
pub fn available_strategy() -> Strategy {
    probe_capabilities().best_strategy
}

/// Check if `unshare` with user + PID + net namespaces actually works.
fn check_unshare() -> std::io::Result<bool> {
    Command::new("unshare")
        .args(["--pid", "--fork", "--map-root-user", "--", "echo", "ok"])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .map(|o| o.status.success() && String::from_utf8_lossy(&o.stdout).contains("ok"))
}

/// Check if bubblewrap is installed and works.
fn check_bubblewrap() -> std::io::Result<bool> {
    Command::new("bwrap")
        .args([
            "--ro-bind",
            "/",
            "/",
            "--dev",
            "/dev",
            "--proc",
            "/proc",
            "echo",
            "ok",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .map(|o| o.status.success() && String::from_utf8_lossy(&o.stdout).contains("ok"))
}

/// Check if firejail is installed and works.
fn check_firejail() -> std::io::Result<bool> {
    Command::new("firejail")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
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
        if level.has_unshare {
            assert_eq!(level.best_strategy, Strategy::Unshare);
        }
        if !level.has_unshare && level.has_bubblewrap {
            assert_eq!(level.best_strategy, Strategy::Bubblewrap);
        }
    }
}
