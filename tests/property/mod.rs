//! Property-based tests for procjail.
//!
//! These use proptest to verify invariants hold across a wide range of inputs.

pub mod test_depth_property;

use proptest::prelude::*;
use std::path::PathBuf;

use procjail::{EnvMode, SandboxConfig, Strategy};

proptest! {
    #[test]
    fn builder_memory_roundtrip(mb in 0u64..100_000u64) {
        let config = SandboxConfig::builder().max_memory_mb(mb).build();
        prop_assert_eq!(config.max_memory_bytes, mb * 1024 * 1024);
    }

    #[test]
    fn builder_disk_roundtrip(mb in 0u64..100_000u64) {
        let config = SandboxConfig::builder().max_disk_mb(mb).build();
        prop_assert_eq!(config.max_disk_bytes, mb * 1024 * 1024);
    }

    #[test]
    fn env_mode_roundtrip(mode in prop::sample::select(&[EnvMode::Allowlist, EnvMode::StripSecrets, EnvMode::Blocklist])) {
        let config = SandboxConfig::builder().env_mode(mode).build();
        prop_assert_eq!(config.env_mode, mode);
    }

    #[test]
    fn strategy_from_str_roundtrip(s in "unshare|bubblewrap|bwrap|firejail|rlimits-only|rlimits_only|rlimits|none") {
        let parsed = Strategy::try_from(s.as_str());
        prop_assert!(parsed.is_ok());
    }

    #[test]
    fn strategy_from_str_invalid_rejected(s in "[a-z0-9_]+") {
        prop_assume!(
            s != "unshare" &&
            s != "bubblewrap" && s != "bwrap" &&
            s != "firejail" &&
            s != "rlimits-only" && s != "rlimits_only" && s != "rlimits" &&
            s != "none"
        );
        let parsed = Strategy::try_from(s.as_str());
        prop_assert!(parsed.is_err());
    }

    #[test]
    fn config_clone_preserves_values(
        max_mem in 0u64..1_000_000u64,
        max_cpu in 0u64..1_000_000u64,
        timeout in 0u64..1_000_000u64,
        allow_localhost in any::<bool>(),
        strip_secrets in any::<bool>(),
    ) {
        let config = SandboxConfig::builder()
            .max_memory_bytes(max_mem)
            .max_cpu_seconds(max_cpu)
            .timeout_seconds(timeout)
            .allow_localhost(allow_localhost)
            .env_strip_secrets(strip_secrets)
            .build();
        let cloned = config.clone();
        prop_assert_eq!(cloned.max_memory_bytes, max_mem);
        prop_assert_eq!(cloned.max_cpu_seconds, max_cpu);
        prop_assert_eq!(cloned.timeout_seconds, timeout);
        prop_assert_eq!(cloned.allow_localhost, allow_localhost);
        prop_assert_eq!(cloned.env_strip_secrets, strip_secrets);
    }

    #[test]
    fn secret_detection_is_consistent(key in "[A-Z_][A-Z0-9_]*") {
        let config = SandboxConfig::default();
        let expected = key.starts_with("AWS_") ||
            key.starts_with("GCP_") ||
            key.starts_with("AZURE_") ||
            procjail::DEFAULT_SECRET_ENV_VARS.contains(&key.as_str());
        prop_assert_eq!(config.is_secret_env_var(&key), expected);
    }

    #[test]
    fn stripped_env_vars_contains_defaults_when_enabled(
        extra in prop::collection::hash_set("[A-Z][A-Z0-9_]{0,20}", 0..10)
    ) {
        let mut config = SandboxConfig::default();
        config.env_strip = extra.iter().cloned().collect();
        config.env_strip_secrets = true;
        let stripped = config.stripped_env_vars();
        for var in procjail::DEFAULT_SECRET_ENV_VARS {
            prop_assert!(stripped.contains(*var));
        }
        for var in &extra {
            prop_assert!(stripped.contains(var.as_str()));
        }
    }

    #[test]
    fn stripped_env_vars_omits_defaults_when_disabled(
        extra in prop::collection::hash_set("[A-Z][A-Z0-9_]{0,20}", 0..10)
    ) {
        let mut config = SandboxConfig::default();
        config.env_strip = extra.iter().cloned().collect();
        config.env_strip_secrets = false;
        let stripped = config.stripped_env_vars();
        for var in procjail::DEFAULT_SECRET_ENV_VARS {
            prop_assert!(!stripped.contains(*var));
        }
        for var in &extra {
            prop_assert!(stripped.contains(var.as_str()));
        }
    }
}
