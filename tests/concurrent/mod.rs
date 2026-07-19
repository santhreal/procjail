//! Concurrent stress tests for procjail.
//!
//! These tests spawn many sandboxed processes in parallel to exercise
//! race conditions in cgroup creation, pipe setup, and process reaping.

use std::path::Path;

use procjail::{SandboxConfig, SandboxedProcess, Strategy};

fn create_sh_harness(dir: &Path, script: &str) -> std::path::PathBuf {
    let harness = dir.join("harness.sh");
    std::fs::write(&harness, script).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&harness, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    harness
}

/// Spawn 32 sandboxed processes in parallel, all with tight timeouts.
/// Verify that none hang and that the parent can reap them all.
#[test]
fn parallel_spawn_with_timeouts() {
    let work_dir = tempfile::tempdir().unwrap();
    let harness = create_sh_harness(
        work_dir.path(),
        "#!/bin/sh\necho hello\nsleep 60\n",
    );

    let config = SandboxConfig::builder()
        .runtime("sh")
        .timeout_seconds(1)
        .strategy(Strategy::None)
        .build();

    let mut handles = Vec::new();
    for _ in 0..32 {
        let h = harness.clone();
        let w = work_dir.path().to_path_buf();
        let c = config.clone();
        handles.push(std::thread::spawn(move || {
            let mut proc = SandboxedProcess::spawn(&h, &w, &c).expect("spawn failed");
            let _ = proc.recv();
            let usage = proc.wait_with_usage().expect("wait failed");
            assert!(
                proc.killed_by_timeout,
                "each parallel process must be killed by timeout"
            );
            usage
        }));
    }

    let mut total_wall = 0.0;
    for h in handles {
        let usage = h.join().expect("thread panicked");
        total_wall += usage.wall_time_secs;
    }

    let avg_wall = total_wall / 32.0;
    assert!(
        avg_wall < 3.0,
        "average wall time should be ~1s; got {avg_wall}s"
    );
}

/// Spawn many short-lived processes in parallel to stress pidfd and kill paths.
#[test]
fn parallel_rapid_exit() {
    let work_dir = tempfile::tempdir().unwrap();
    let harness = create_sh_harness(work_dir.path(), "#!/bin/sh\necho done\n");

    let config = SandboxConfig::builder()
        .runtime("sh")
        .timeout_seconds(5)
        .strategy(Strategy::None)
        .build();

    let mut handles = Vec::new();
    for i in 0..64 {
        let h = harness.clone();
        let w = work_dir.path().to_path_buf();
        let mut c = config.clone();
        // Slightly stagger timeouts to avoid thundering herd.
        c.timeout_seconds = 2 + (i % 3) as u64;
        handles.push(std::thread::spawn(move || {
            let mut proc = SandboxedProcess::spawn(&h, &w, &c).expect("spawn failed");
            let line = proc.recv().expect("recv failed").expect("eof early");
            assert_eq!(line.trim(), "done");
            let usage = proc.wait_with_usage().expect("wait failed");
            assert_eq!(usage.exit_code, 0);
        }));
    }

    for h in handles {
        h.join().expect("thread panicked");
    }
}

/// Concurrent mixed-strategy spawn (if multiple strategies are available).
/// This tests that strategy-specific global state does not collide.
#[test]
#[cfg(target_os = "linux")]
fn parallel_mixed_strategies() {
    let strategies = vec![
        Strategy::None,
        Strategy::Unshare,
        Strategy::Bubblewrap,
    ];

    let mut handles = Vec::new();
    for (idx, strategy) in strategies.iter().cycle().take(12).enumerate() {
        let dir = tempfile::tempdir().unwrap();
        let harness = create_sh_harness(
            dir.path(),
            "#!/bin/sh\necho hello\n",
        );
        let w = dir.path().to_path_buf();
        let s = *strategy;
        handles.push(std::thread::spawn(move || {
            let config = SandboxConfig::builder()
                .runtime("sh")
                .timeout_seconds(5)
                .strategy(s)
                .build();

            match SandboxedProcess::spawn(&harness, &w, &config) {
                Ok(mut proc) => {
                    let _ = proc.recv();
                    let _ = proc.wait_with_usage();
                }
                Err(e) => {
                    let msg = e.to_string();
                    // It's OK if the strategy isn't available on this host.
                    if !msg.contains("not available") {
                        panic!("unexpected spawn error for {s}: {e}");
                    }
                }
            }
        }));
    }

    for h in handles {
        h.join().expect("thread panicked");
    }
}

/// Concurrent send/recv on the same process from multiple threads.
/// SandboxedProcess is not Sync, so we spawn threads that each create
/// their own process and communicate with it.
#[test]
fn parallel_io_on_separate_processes() {
    let work_dir = tempfile::tempdir().unwrap();
    let harness = create_sh_harness(
        work_dir.path(),
        "#!/bin/sh\nwhile read line; do echo \"$line\"; done\n",
    );

    let config = SandboxConfig::builder()
        .runtime("sh")
        .timeout_seconds(5)
        .strategy(Strategy::None)
        .build();

    let mut handles = Vec::new();
    for t in 0..16 {
        let h = harness.clone();
        let w = work_dir.path().to_path_buf();
        let c = config.clone();
        handles.push(std::thread::spawn(move || {
            let mut proc = SandboxedProcess::spawn(&h, &w, &c).expect("spawn failed");
            for i in 0..10 {
                let msg = format!("thread_{t}_msg_{i}");
                proc.send(&msg).expect("send failed");
                let resp = proc.recv().expect("recv failed").expect("eof early");
                assert_eq!(resp.trim(), msg);
            }
            let usage = proc.wait_with_usage().expect("wait failed");
            assert_eq!(usage.exit_code, 0);
        }));
    }

    for h in handles {
        h.join().expect("thread panicked");
    }
}

/// Stress test: many processes killed concurrently to verify cgroup.kill
/// and pidfd_send_signal paths don't race destructively.
#[test]
fn parallel_mass_kill() {
    let work_dir = tempfile::tempdir().unwrap();
    let harness = create_sh_harness(
        work_dir.path(),
        "#!/bin/sh\nsleep 300\n",
    );

    let config = SandboxConfig::builder()
        .runtime("sh")
        .timeout_seconds(300) // long timeout so watchdog doesn't interfere
        .strategy(Strategy::None)
        .build();

    let mut procs = Vec::new();
    for _ in 0..32 {
        let mut proc = SandboxedProcess::spawn(&harness, work_dir.path(), &config).expect("spawn failed");
        procs.push(proc);
    }

    let mut handles = Vec::new();
    for mut proc in procs {
        handles.push(std::thread::spawn(move || {
            proc.kill();
            assert!(!proc.is_alive(), "process must be dead after kill");
        }));
    }

    for h in handles {
        h.join().expect("thread panicked");
    }
}

/// Verify that concurrent cgroup creation does not collide when many
/// processes share the same parent pid namespace.
#[test]
#[cfg(target_os = "linux")]
fn parallel_cgroup_creation() {
    let work_dir = tempfile::tempdir().unwrap();
    let harness = create_sh_harness(work_dir.path(), "#!/bin/sh\necho ok\n");

    let config = SandboxConfig::builder()
        .runtime("sh")
        .max_memory_bytes(16 * 1024 * 1024)
        .timeout_seconds(5)
        .strategy(Strategy::None)
        .build();

    let mut handles = Vec::new();
    for _ in 0..20 {
        let h = harness.clone();
        let w = work_dir.path().to_path_buf();
        let c = config.clone();
        handles.push(std::thread::spawn(move || {
            let mut proc = SandboxedProcess::spawn(&h, &w, &c).expect("spawn failed");
            let _ = proc.recv();
            let usage = proc.wait_with_usage().expect("wait failed");
            assert_eq!(usage.exit_code, 0);
        }));
    }

    for h in handles {
        h.join().expect("thread panicked");
    }
}
