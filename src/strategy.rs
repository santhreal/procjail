//! Containment strategies — how we isolate the process.

use serde::{Deserialize, Serialize};

/// Which containment mechanism to use.
///
/// Capabilities by strategy:
///
/// | Strategy | PID | Network | Filesystem | Seccomp | rlimits |
/// |----------|-----|---------|------------|---------|---------|
/// | Bubblewrap | Yes | Yes | **Full** (ro-bind) | No | No |
/// | Firejail | Yes | Yes | **Full** (--private) | **Yes** | **Yes** |
/// | Unshare | Yes | Yes | Partial (mount ns) | No | No |
/// | `RlimitsOnly` | No | No | No | No | Via harness |
/// | None | No | No | No | No | No |
///
/// **Bubblewrap** is the recommended strategy for maximum security without root.
/// **Firejail** adds seccomp and rlimits. **Unshare** provides PID/NET isolation
/// but filesystem access is only partially restricted (mount changes don't leak,
/// but existing mounts are still visible).
///
/// # Thread Safety
/// `Strategy` is `Send` and `Sync`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum Strategy {
    /// Linux namespaces via `unshare` (PID + NET + mount namespace).
    /// Mount namespace prevents mount changes from leaking but does NOT
    /// hide existing filesystem content. Prefer Bubblewrap for full FS isolation.
    Unshare,
    /// Bubblewrap (`bwrap`) — rootless container with full filesystem isolation.
    /// Read-only root, explicit bind mounts. **Recommended for production.**
    Bubblewrap,
    /// Firejail — seccomp + namespaces + rlimits + private filesystem.
    Firejail,
    /// Basic resource limits via env vars (harness must enforce).
    /// **No namespace isolation.** Only use as last resort.
    RlimitsOnly,
    /// No containment at all. **Only for testing.**
    None,
}

impl Strategy {
    /// Human-readable name.
    ///
    /// Example:
    /// ```rust
    /// use procjail::Strategy;
    ///
    /// assert_eq!(Strategy::Bubblewrap.name(), "bubblewrap");
    /// ```
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Unshare => "unshare",
            Self::Bubblewrap => "bubblewrap",
            Self::Firejail => "firejail",
            Self::RlimitsOnly => "rlimits-only",
            Self::None => "none",
        }
    }

    /// Whether this strategy provides PID namespace isolation.
    ///
    /// Example:
    /// ```rust
    /// use procjail::Strategy;
    ///
    /// assert!(Strategy::Unshare.has_pid_isolation());
    /// ```
    #[must_use]
    pub fn has_pid_isolation(self) -> bool {
        matches!(self, Self::Unshare | Self::Bubblewrap | Self::Firejail)
    }

    /// Whether this strategy provides network isolation.
    ///
    /// Example:
    /// ```rust
    /// use procjail::Strategy;
    ///
    /// assert!(Strategy::Firejail.has_network_isolation());
    /// ```
    #[must_use]
    pub fn has_network_isolation(self) -> bool {
        matches!(self, Self::Unshare | Self::Bubblewrap | Self::Firejail)
    }

    /// Whether this strategy provides filesystem isolation.
    ///
    /// Note: Unshare provides a mount namespace (preventing mount changes
    /// from leaking) but does NOT hide existing filesystem content.
    /// Only Bubblewrap and Firejail provide true filesystem restriction.
    ///
    /// Example:
    /// ```rust
    /// use procjail::Strategy;
    ///
    /// assert!(Strategy::Bubblewrap.has_fs_isolation());
    /// assert!(!Strategy::Unshare.has_fs_isolation());
    /// ```
    #[must_use]
    pub fn has_fs_isolation(self) -> bool {
        matches!(self, Self::Bubblewrap | Self::Firejail)
    }

    /// Whether this strategy provides mount namespace isolation.
    /// (Prevents mount changes from leaking to the parent.)
    ///
    /// Example:
    /// ```rust
    /// use procjail::Strategy;
    ///
    /// assert!(Strategy::Unshare.has_mount_namespace());
    /// ```
    #[must_use]
    pub fn has_mount_namespace(self) -> bool {
        matches!(self, Self::Unshare | Self::Bubblewrap | Self::Firejail)
    }
}

impl std::fmt::Display for Strategy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

impl TryFrom<&str> for Strategy {
    type Error = &'static str;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value.trim().to_ascii_lowercase().as_str() {
            "unshare" => Ok(Self::Unshare),
            "bubblewrap" | "bwrap" => Ok(Self::Bubblewrap),
            "firejail" => Ok(Self::Firejail),
            "rlimits-only" | "rlimits_only" | "rlimits" => Ok(Self::RlimitsOnly),
            "none" => Ok(Self::None),
            _ => Err(
                "unknown strategy. Fix: use one of `unshare`, `bubblewrap`, `firejail`, `rlimits-only`, or `none`.",
            ),
        }
    }
}

impl TryFrom<String> for Strategy {
    type Error = &'static str;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::try_from(value.as_str())
    }
}
