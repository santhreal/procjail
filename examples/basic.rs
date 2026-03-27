use procjail::{SandboxConfig, SandboxedProcess};
use std::path::Path;

fn main() -> anyhow::Result<()> {
    let temp = tempfile::tempdir()?;
    let harness = temp.path().join("harness.js");
    std::fs::write(&harness, "console.log('sandbox harness');\n")?;

    let config = SandboxConfig::builder()
        .runtime("/bin/echo")
        .runtime_args(&["hello from sandbox"])
        .build();

    let mut process = SandboxedProcess::spawn(&harness, Path::new(temp.path()), &config)?;

    if let Some(line) = process.recv()? {
        println!("Output from sandbox: {}", line.trim());
    }

    let usage = process.wait_with_usage()?;
    println!("Sandbox exited with code: {}", usage.exit_code);

    Ok(())
}
