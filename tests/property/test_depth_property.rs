use procjail::{SandboxConfig, Strategy};
use proptest::prelude::*;

proptest! {
    #[test]
    fn test_sandbox_config_builder_invariants(
        max_mem_mb in 0u64..1000000,
        max_cpu in 0u64..1000000,
        max_fds in 0u64..1000000,
        max_disk_mb in 0u64..1000000,
        max_procs in 0u64..1000000,
        timeout in 0u64..1000000,
        max_recv in 1usize..1000000,
        allow_localhost in any::<bool>(),
        capture_stderr in any::<bool>(),
        env_strip_secrets in any::<bool>(),
    ) {
        let config = SandboxConfig::builder()
            .max_memory_mb(max_mem_mb)
            .max_cpu_seconds(max_cpu)
            .max_fds(max_fds)
            .max_disk_mb(max_disk_mb)
            .max_processes(max_procs)
            .timeout_seconds(timeout)
            .max_recv_line_bytes(max_recv)
            .allow_localhost(allow_localhost)
            .capture_stderr(capture_stderr)
            .env_strip_secrets(env_strip_secrets)
            .build();

        assert_eq!(config.max_memory_bytes, max_mem_mb * 1024 * 1024);
        assert_eq!(config.max_cpu_seconds, max_cpu);
        assert_eq!(config.max_fds, max_fds);
        assert_eq!(config.max_disk_bytes, max_disk_mb * 1024 * 1024);
        assert_eq!(config.max_processes, max_procs);
        assert_eq!(config.timeout_seconds, timeout);
        assert_eq!(config.max_recv_line_bytes, max_recv);
        assert_eq!(config.allow_localhost, allow_localhost);
        assert_eq!(config.capture_stderr, capture_stderr);
        assert_eq!(config.env_strip_secrets, env_strip_secrets);
    }

    #[test]
    fn test_strategy_parsing(strategy_str in "unshare|bubblewrap|bwrap|firejail|rlimits-only|rlimits_only|rlimits|none") {
        let parsed = Strategy::try_from(strategy_str);
        assert!(parsed.is_ok());
    }

    #[test]
    fn test_strategy_parsing_invalid(strategy_str in "[a-z0-9]+") {
        prop_assume!(strategy_str != "unshare" && strategy_str != "bubblewrap" && strategy_str != "bwrap" && strategy_str != "firejail" && strategy_str != "rlimits-only" && strategy_str != "rlimits_only" && strategy_str != "rlimits" && strategy_str != "none");
        let parsed = Strategy::try_from(strategy_str);
        assert!(parsed.is_err());
    }
}
