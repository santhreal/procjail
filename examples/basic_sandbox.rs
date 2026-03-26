use procjail::{SandboxConfig, SandboxedProcess};
use std::path::Path;

fn main() -> anyhow::Result<()> {
    // We configure the sandbox to run `/bin/echo`
    let config = SandboxConfig::builder()
        .runtime("/bin/echo")
        .runtime_args(&["hello from sandbox"])
        .build();

    // The harness script path is required, we use /dev/null as a dummy
    let mut process = SandboxedProcess::spawn(Path::new("/dev/null"), Path::new("/tmp"), &config)?;

    // Read the output
    if let Some(line) = process.recv()? {
        println!("Output from sandbox: {}", line.trim());
    }

    // Wait for the process to complete and print usage
    let usage = process.wait_with_usage()?;
    println!("Sandbox exited with code: {}", usage.exit_code);

    Ok(())
}
