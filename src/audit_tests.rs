//! Audit verification tests  -  each test is designed to FAIL on the current
//! (unfixed) codebase, demonstrating a real security or correctness bug.

use std::path::Path;

#[test]
fn verify_seccomp_seccomp_not_allowed() {
    let src = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/seccomp/mod.rs"));
    assert!(
        !src.contains("allow_syscall(&mut rules, libc::SYS_seccomp);"),
        "SYS_seccomp must not be in the seccomp allowlist because it allows filter bypass"
    );
}

#[test]
fn verify_seccomp_prctl_not_allowed() {
    let src = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/seccomp/mod.rs"));
    assert!(
        !src.contains("allow_syscall(&mut rules, libc::SYS_prctl);"),
        "SYS_prctl must not be in the seccomp allowlist because it allows filter bypass"
    );
}

#[test]
fn verify_seccomp_errors_not_swallowed() {
    let src = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/process/builder.rs"
    ));
    assert!(
        !src.contains("let _ = crate::seccomp::apply_seccomp_filter();"),
        "seccomp filter application errors must not be silently ignored"
    );
}

#[test]
fn verify_custom_provider_enforces_limits() {
    let src = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/process/builder.rs"
    ));
    let provider_block = src
        .split("if let Some(ref provider) = config.custom_provider")
        .nth(1)
        .and_then(|s| s.split("cmd.process_group(0);").next())
        .expect("custom provider block not found");
    // The custom provider path must call apply_pre_exec_isolation, which sets
    // rlimits and seccomp unconditionally.
    let has_isolation = provider_block.contains("apply_pre_exec_isolation");
    assert!(
        has_isolation,
        "custom provider path must apply deep isolation (rlimits + seccomp) before returning"
    );
}

#[test]
fn verify_bubblewrap_preferred_over_unshare() {
    let src = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/detect.rs"));
    let unshare_idx = src.find("Strategy::Unshare").expect("Unshare not found");
    let bwrap_idx = src
        .find("Strategy::Bubblewrap")
        .expect("Bubblewrap not found");
    assert!(
        bwrap_idx < unshare_idx,
        "Bubblewrap (stronger isolation) should be preferred over Unshare in auto-detection"
    );
}

#[test]
fn verify_bwrap_mounts_runtime_and_harness() {
    let src = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/process/builder.rs"
    ));
    let bwrap_block = src
        .split("fn build_bwrap_command")
        .nth(1)
        .and_then(|s| s.split("fn build_firejail_command").next())
        .expect("bwrap block not found");
    let ro_bind_count = bwrap_block.matches("--ro-bind").count();
    assert!(
        ro_bind_count >= 3,
        "bwrap must bind at least runtime, harness, and work_dir read-only"
    );
}

#[test]
fn verify_cgroup_swap_max_set() {
    let src = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/cgroups.rs"));
    assert!(
        src.contains("memory.swap.max"),
        "set_memory_limit must also write memory.swap.max to prevent swap escape"
    );
}

#[test]
fn verify_cgroup_pids_max_set() {
    let src = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/cgroups.rs"));
    assert!(
        src.contains("pids.max"),
        "CgroupV2 must enforce max_processes via pids.max"
    );
}

#[test]
fn verify_rlimit_nofile_nproc_set() {
    let src = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/process/builder.rs"
    ));
    let isolation_block = src
        .split("fn apply_pre_exec_isolation")
        .nth(1)
        .expect("apply_pre_exec_isolation not found");
    assert!(
        isolation_block.contains("RLIMIT_NOFILE"),
        "pre_exec must enforce max_fds via RLIMIT_NOFILE"
    );
    assert!(
        isolation_block.contains("RLIMIT_NPROC"),
        "pre_exec must enforce max_processes via RLIMIT_NPROC"
    );
}

#[test]
fn verify_unshare_probe_matches_actual_command() {
    let detect_src = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/detect.rs"));
    let builder_src = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/process/builder.rs"
    ));
    let probe = detect_src
        .split("fn check_unshare()")
        .nth(1)
        .and_then(|s| s.split(".output()").next())
        .unwrap();
    let actual = builder_src
        .split("fn build_unshare_command")
        .nth(1)
        .and_then(|s| s.split("fn build_bwrap_command").next())
        .unwrap();
    assert_eq!(
        probe.contains("--mount-proc"),
        actual.contains("--mount-proc"),
        "check_unshare probe arguments must match build_unshare_command"
    );
}

#[test]
fn verify_bwrap_probe_matches_actual_command() {
    let detect_src = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/detect.rs"));
    let builder_src = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/process/builder.rs"
    ));
    let probe = detect_src
        .split("fn check_bubblewrap()")
        .nth(1)
        .and_then(|s| s.split(".output()").next())
        .unwrap();
    let actual = builder_src
        .split("fn build_bwrap_command")
        .nth(1)
        .and_then(|s| s.split("fn build_firejail_command").next())
        .unwrap();
    assert_eq!(
        probe.contains("--tmpfs"),
        actual.contains("--tmpfs"),
        "check_bubblewrap probe must match actual bwrap filesystem layout"
    );
}

#[test]
fn verify_which_checks_executable() {
    let result = crate::process::builder::which(Path::new("/tmp"));
    assert!(
        result.is_err(),
        "which() must reject absolute paths that are not executable files"
    );
}

#[test]
fn verify_seccomp_fcntl_allowed() {
    let src = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/seccomp/mod.rs"));
    assert!(
        src.contains("SYS_fcntl"),
        "seccomp filter must allow fcntl for standard library I/O"
    );
}

#[test]
fn verify_aarch64_fstatat_config() {
    let src = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/seccomp/mod.rs"));
    assert!(
        !src.contains("#[cfg(target_arch = \"aarch64\")]\n    allow_syscall(&mut rules, libc::SYS_fstatat64);"),
        "SYS_fstatat64 is for 32-bit arm, not aarch64"
    );
}

#[test]
fn verify_firejail_probe_runs_real_sandbox() {
    let src = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/detect.rs"));
    let probe = src
        .split("fn check_firejail()")
        .nth(1)
        .and_then(|s| s.split('}').next())
        .unwrap();
    assert!(
        probe.contains("--noprofile") || probe.contains("echo ok") || probe.contains("true"),
        "check_firejail must exercise a real sandbox invocation, not just --version"
    );
}
