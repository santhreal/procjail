# procjail

Run untrusted code in a sandbox. procjail picks the best containment strategy available on the system (bubblewrap > firejail > unshare > rlimits), strips secret environment variables, enforces timeouts, and reports resource usage.

Linux only. procjail relies on Linux process isolation primitives and sandbox launchers such as `bubblewrap`, `firejail`, and `unshare`.

```rust,no_run
use procjail::{SandboxConfig, SandboxedProcess};
use std::{fs, path::Path};

let config = SandboxConfig::builder()
    .runtime("sh")
    .max_memory_mb(256)
    .timeout_seconds(5)
    .build();

let work_dir = std::env::temp_dir().join("procjail-readme-example");
fs::create_dir_all(&work_dir)?;

let harness = work_dir.join("harness.sh");
fs::write(
    &harness,
    "#!/bin/sh\nwhile IFS= read -r line; do printf '{\"echo\":%s}\\n' \"$line\"; done\n",
)?;

let mut proc = SandboxedProcess::spawn(
    Path::new(&harness),
    Path::new(&work_dir),
    &config,
)?;

proc.send("42")?;
let response = proc.recv()?;
println!("{response:?}");
# Ok::<(), procjail::ProcjailError>(())
```

## Containment strategies

| Strategy | PID isolation | Network | Filesystem | How |
|----------|:---:|:---:|:---:|-----|
| Bubblewrap | Yes | Yes | Full (ro-bind) | Recommended. Rootless. |
| Firejail | Yes | Yes | Full (--private) | Adds seccomp + rlimits. |
| Unshare | Yes | Yes | Partial (mount ns) | No full FS restriction. |
| RlimitsOnly | No | No | No | Harness enforces limits. Last resort. |

procjail auto-detects which strategies work on the current system. Override with `.strategy(Strategy::Bubblewrap)`.

## Secret stripping

36 environment variables are stripped by default (AWS keys, GitHub tokens, database URLs, API keys). Custom additions via `.env_strip(&["MY_SECRET"])`. The passthrough list cannot re-add stripped secrets.

## Resource reporting

```rust
let usage = proc.wait_with_usage().unwrap();
println!("peak memory: {} bytes", usage.peak_memory_bytes);
println!("cpu time: {:.2}s", usage.cpu_time_secs);
println!("killed by timeout: {}", proc.killed_by_timeout);
```

## Contributing

Pull requests are welcome. There is no such thing as a perfect crate. If you find a bug, a better API, or just a rough edge, open a PR. We review quickly.

## License

MIT. Copyright 2026 CORUM COLLECTIVE LLC.

[![crates.io](https://img.shields.io/crates/v/procjail.svg)](https://crates.io/crates/procjail)
[![docs.rs](https://docs.rs/procjail/badge.svg)](https://docs.rs/procjail)
