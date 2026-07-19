use std::fs;
use std::path::{Path, PathBuf};

/// A cgroup v2 controller for hardware containment.
///
/// cgroups v2 provides unescapable hardware isolation.
/// Requires the host to have cgroupfs mounted at `/sys/fs/cgroup`.
#[derive(Debug)]
pub struct CgroupV2 {
    pub path: PathBuf,
}

impl CgroupV2 {
    /// Attempt to acquire a new random cgroup v2 slice for the sandbox.
    ///
    /// # Errors
    /// Returns an error if the kernel does not support cgroups v2 or
    /// if we lack permissions to create a new cgroup leaf.
    pub fn new(name: &str) -> std::io::Result<Self> {
        let base_path = Path::new("/sys/fs/cgroup");
        if !base_path.exists() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "cgroups v2 not mounted at /sys/fs/cgroup. Fix: ensure cgroup2 is mounted or use firejail/bwrap for resource containment.",
            ));
        }

        // Verify this is actually a cgroup v2 mount, not v1 or hybrid.
        let controllers = base_path.join("cgroup.controllers");
        if !controllers.exists() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "cgroups v1 detected; procjail requires v2. Fix: migrate to cgroups v2 or use firejail/bwrap for resource containment.",
            ));
        }

        // We create a procjail slice. Note: In real environments, permissions will vary unless root.
        let cg_path = base_path.join("procjail").join(name);
        fs::create_dir_all(&cg_path)?;

        Ok(Self { path: cg_path })
    }

    /// Enforce a hard memory maximum.
    ///
    /// Also writes `memory.swap.max` to prevent swap escape.
    ///
    /// # Errors
    /// Returns an error if the specific cgroup attribute cannot be written.
    pub fn set_memory_limit(&self, bytes: u64) -> std::io::Result<()> {
        let mem_max = self.path.join("memory.max");
        fs::write(&mem_max, bytes.to_string())?;
        let swap_max = self.path.join("memory.swap.max");
        fs::write(swap_max, "0")
    }

    /// Enforce a hard CPU quota/limit.
    ///
    /// # Errors
    /// Returns an error if CPU scheduling cannot be restricted.
    pub fn set_cpu_limit(&self, quota: u64, period: u64) -> std::io::Result<()> {
        let cpu_max = self.path.join("cpu.max");
        let val = format!("{quota} {period}");
        fs::write(cpu_max, val)
    }

    /// Enforce a hard limit on the number of processes/threads.
    ///
    /// # Errors
    /// Returns an error if the pids controller is not available.
    pub fn set_pids_limit(&self, max: u64) -> std::io::Result<()> {
        let pids_max = self.path.join("pids.max");
        fs::write(pids_max, max.to_string())
    }

    /// Attach a sandboxed PID into this cgroup.
    ///
    /// # Errors
    /// Returns an error if the process table denies moving the PID.
    pub fn attach_pid(&self, pid: u32) -> std::io::Result<()> {
        let procs = self.path.join("cgroup.procs");
        fs::write(procs, pid.to_string())
    }

    /// Fetch current peak memory usage from cgroup controller natively.
    #[must_use]
    pub fn current_memory_peak(&self) -> Option<u64> {
        let peak = self.path.join("memory.peak");
        std::fs::read_to_string(peak)
            .ok()?
            .trim()
            .parse::<u64>()
            .ok()
    }

    /// Recursively kill all processes and descendants inside this hardware slice.
    /// Available on Linux 5.14+.
    pub fn kill_all(&self) -> std::io::Result<()> {
        let kill_file = self.path.join("cgroup.kill");
        std::fs::write(kill_file, "1")
    }
}

impl Drop for CgroupV2 {
    fn drop(&mut self) {
        // Attempt cleanup. The kernel won't delete it if processes still live inside.
        let _ = fs::remove_dir(&self.path);
    }
}
