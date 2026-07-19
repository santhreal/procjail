use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    if env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("linux") {
        return;
    }

    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR"));
    let probe = out_dir.join("seccomp_socket_probe_c");
    let src = PathBuf::from("tests/bin/socket_probe.c");

    // Prefer a known-good compiler; ignore CC wrappers like `distcc gcc`.
    let compiler = if PathBuf::from("/usr/bin/gcc").exists() {
        "/usr/bin/gcc".to_string()
    } else {
        "gcc".to_string()
    };
    let status = Command::new(&compiler)
        .args([
            "-static",
            "-O2",
            "-o",
            probe.to_str().expect("probe path"),
            src.to_str().expect("source path"),
        ])
        .status()
        .unwrap_or_else(|e| panic!("spawn {compiler}: {e}"));

    if !status.success() {
        panic!("failed to compile socket_probe.c");
    }

    println!("cargo:rustc-env=SEC_SOCKET_PROBE_C={}", probe.display());
    println!("cargo:rerun-if-changed=tests/bin/socket_probe.c");
}
