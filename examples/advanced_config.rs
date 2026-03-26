//! Advanced configuration example for procjail.
//!
//! Run: cargo run --example advanced_config

use procjail::{SandboxConfig, SandboxedProcess};
use std::path::Path;

fn main() -> anyhow::Result<()> {
    // Configure a more restricted sandbox, demonstrating real use cases
    // like running an untrusted script with specific arguments.
    let config = SandboxConfig::builder()
        .runtime("/bin/sh")
        .runtime_args(&["-c", "echo 'Running restricted in advanced config!'"])
        .build();

    let mut process = SandboxedProcess::spawn(Path::new("/dev/null"), Path::new("/tmp"), &config)?;

    if let Some(line) = process.recv()? {
        println!("Output: {}", line.trim());
    }

    let usage = process.wait_with_usage()?;
    println!("Exited with code: {}", usage.exit_code);
    Ok(())
}
