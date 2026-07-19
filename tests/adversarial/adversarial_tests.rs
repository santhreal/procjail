use procjail::{SandboxConfig, SandboxedProcess, Strategy};
use std::path::Path;

#[test]
fn spawn_nonexistent_runtime() {
    let config = SandboxConfig::builder()
        .runtime("/definitely/not/a/real/binary_xyz123")
        .strategy(Strategy::None)
        .build();

    let harness = tempfile::NamedTempFile::new().unwrap();
    let work = tempfile::tempdir().unwrap();

    let result = SandboxedProcess::spawn(harness.path(), work.path(), &config);
    match result {
        Err(error) => assert!(
            error.to_string().contains("not found in PATH")
                || error.to_string().contains("No such file or directory"),
            "unexpected error: {error}"
        ),
        Ok(_) => panic!("spawn should fail for a missing runtime"),
    }
}

#[test]
fn spawn_nonexistent_harness() {
    let config = SandboxConfig::builder()
        .runtime("cat")
        .strategy(Strategy::None)
        .build();

    let work = tempfile::tempdir().unwrap();

    let result = SandboxedProcess::spawn(
        Path::new("/definitely/not/a/real/harness_xyz123.js"),
        work.path(),
        &config,
    );
    match result {
        Err(error) => assert!(
            error.to_string().contains("harness_path must exist"),
            "unexpected error: {error}"
        ),
        Ok(_) => panic!("spawn should fail for a missing harness file"),
    }
}
