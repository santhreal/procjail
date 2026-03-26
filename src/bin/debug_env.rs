fn main() {
    let config = procjail::SandboxConfig::builder()
            .runtime("/bin/echo")
            .strategy(procjail::Strategy::None)
            .env_mode(procjail::EnvMode::Allowlist)
            .env_passthrough(&["GITHUB_TOKEN"]) // Try to passthrough a secret
            .env_set("GITHUB_TOKEN", "should_be_blocked") // Try to set a secret
            .build();
    let secrets = config.stripped_env_vars();
    println!("secrets size: {}", secrets.len());
    for s in secrets {
        println!("secret: {}", s);
    }
}
