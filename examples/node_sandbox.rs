use procjail::{SandboxConfig, SandboxedProcess};
use std::io::Write;

fn main() -> anyhow::Result<()> {
    // Write a temporary Node.js harness script
    let harness_dir = tempfile::tempdir()?;
    let harness_path = harness_dir.path().join("harness.js");
    let mut file = std::fs::File::create(&harness_path)?;
    writeln!(
        file,
        r#"
const fs = require('fs');
const readline = require('readline');
const rl = readline.createInterface({{
  input: process.stdin,
  output: process.stdout,
  terminal: false
}});

rl.on('line', (line) => {{
  if (line === 'ping') {{
    console.log('pong from node');
  }} else {{
    console.log('unknown command: ' + line);
  }}
}});
        "#
    )?;

    // Configure the sandbox to run the node script
    let config = SandboxConfig::builder()
        .runtime("node")
        .max_memory_mb(128)
        .max_cpu_seconds(10)
        .build();

    let mut process = SandboxedProcess::spawn(
        &harness_path,
        harness_dir.path(), // use the same dir as the work dir
        &config,
    )?;

    // Send a message and wait for a response
    process.send("ping")?;

    if let Some(line) = process.recv()? {
        println!("Received: {}", line);
    }

    process.send("exit")?;

    if let Some(line) = process.recv()? {
        println!("Received: {}", line);
    }

    process.kill();

    Ok(())
}
