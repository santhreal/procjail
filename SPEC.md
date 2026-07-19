# procjail  -  Technical Spec

## Overview

# procjail  Process sandbox for running untrusted code in real runtimes.  When security tools need to execute untrusted code (npm packages, pip packages, browser extensions, binaries), they need containment that actually works. This crate provides kernel-level isolation using the best available mechanism on the host.  # Containment Strategies (ordered by preference)  1. **unshare**  -  Linux namespaces (PID, network, mount, user). No root needed. 2. **bubblewrap (bwrap)**  -  Lightweight container (Flatpak uses this). Rootless. 3. **firejail**  -  Feature-rich sandbox. Needs installation. 4. **rlimits**  -  Basic resource limits only. Always available. Least secure.  The sandbox auto-selects the best available strategy, or you can force one.  # Usage  ```rust,no_run use std::path::Path; use procjail::{SandboxConfig, SandboxedProcess};  let config = SandboxConfig::builder() .runtime("/usr/bin/node") .max_memory_mb(256) .max_cpu_seconds(30) .max_fds(64) .allow_localhost(false) .env_passthrough(&["HOME", "PATH", "NODE_PATH"]) .env_strip_secrets(true) .build();  let mut proc = SandboxedProcess::spawn( Path::new("/path/to/harness.js"), Path::new("/path/to/package"), &config, ).unwrap();  proc.send(r#"{"method":"eval","args":["1+1"]}"#).unwrap(); if let Some(line) = proc.recv().unwrap() { println!("observation: {}", line); } ```  # Architecture  ```text Parent (full privileges) │ ├── stdin pipe  → probes flow in ├── stdout pipe ← observations flow out │ └── [containment layer] ├── PID namespace (process isolation) ├── NET namespace (no external network) ├── MNT namespace (read-only filesystem) ├── USER namespace (unprivileged) ├── rlimits (memory, CPU, FDs) └── env stripping (no secrets leak) ```

## Architecture

The crate is organized into the following public modules:

- `strategy`
- `seccomp`

## Guarantees

- `#![forbid(unsafe_code)]` where applicable; see `src/lib.rs` for the exact lint preamble.
- All public types have doc comments.
- Error messages are actionable where applicable.

## Public API Summary

Key entry points are exported from `src/lib.rs` via `pub mod` and `pub use` re-exports.
Consult the module-level documentation in each source file for function signatures and usage examples.

## Error Handling

- `BuildCommandError`
- `ProcjailError`
