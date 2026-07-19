use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};
use std::io::{BufRead, BufReader, Write};

fn main() {
    let mut cmd = Command::new("sh");
    cmd.arg("/tmp/test_harness.sh");
    cmd.arg("/tmp");
    cmd.stdin(Stdio::piped());
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::inherit());
    
    unsafe {
        cmd.pre_exec(|| {
            let max_mem = 256u64 * 1024 * 1024;
            let max_cpu = 30u64;
            let rlim_as = libc::rlimit {
                rlim_cur: max_mem as libc::rlim_t,
                rlim_max: max_mem as libc::rlim_t,
            };
            if libc::setrlimit(libc::RLIMIT_AS, &rlim_as) != 0 {
                eprintln!("setrlimit AS failed: {}", std::io::Error::last_os_error());
            }
            let rlim_cpu = libc::rlimit {
                rlim_cur: max_cpu as libc::rlim_t,
                rlim_max: max_cpu as libc::rlim_t,
            };
            if libc::setrlimit(libc::RLIMIT_CPU, &rlim_cpu) != 0 {
                eprintln!("setrlimit CPU failed: {}", std::io::Error::last_os_error());
            }
            if let Err(e) = procjail::seccomp::apply_seccomp_filter() {
                eprintln!("seccomp failed: {e}");
            }
            Ok(())
        });
    }
    
    let mut child = cmd.spawn().unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let stdout = child.stdout.take().unwrap();
    
    writeln!(stdin, "hello").unwrap();
    stdin.flush().unwrap();
    
    let mut reader = BufReader::new(stdout);
    let mut line = String::new();
    let n = reader.read_line(&mut line).unwrap();
    println!("Read {} bytes: {:?}", n, line);
    
    let status = child.wait().unwrap();
    println!("Exit: {:?}", status);
}
