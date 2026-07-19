# procjail  -  Internal Spec

> This file is gitignored. It exists for agents and internal development. Never committed to public repos.

## Identity
Process sandbox for running untrusted code using Linux namespaces, seccomp, firejail, and bubblewrap.

## Purpose
Provides kernel-level isolation for running external binaries or scripts safely. Without it, evaluating untrusted payloads (like package installs or dynamic scripts) would risk host compromise.

## North Star
An impenetrable, multi-layered sandbox that automatically degrades to the safest available kernel primitive without requiring root privileges.

## Role in Ecosystem
- **Depends on:** none (internal)
- **Depended on by:** warpscan
- **Relationship to warpscan:** Isolates third-party tool execution (like npm, python) during deeper analysis steps.
- **Standalone value:** YES. Any Rust tool needing a lightweight, unprivileged Linux sandbox could use it.

## Invariants
Processes cannot access the host network or read arbitrary host files (unless configured). Secrets in the environment are strictly stripped.

## Boundaries
Does not inspect the output for vulnerabilities. Only manages the execution boundary.

## Quality State
- Tests: Good (includes proptest)
- Lint preamble: yes
- `#![forbid(unsafe_code)]`: no. Unsafe code is confined to libc syscall wrappers in `process/` and `seccomp/` modules. All unsafe blocks are annotated with SAFETY comments.
- Doc coverage: ~85%
- Known issues: Limited strictly to Linux environments.