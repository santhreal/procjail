use procjail::seccomp::*;

#[test]
fn test_is_available() {
    let available = is_available();
    if cfg!(target_os = "linux") {
        assert!(available);
    } else {
        assert!(!available);
    }
}
