# Changelog

## v0.2.0

- Added `#[non_exhaustive]` to extensible public enums such as `Strategy`, `EnvMode`, and `ProcjailError`.
- Added `Display` implementations for developer-facing public types including `SandboxConfig`, `SandboxConfigBuilder`, `ContainmentLevel`, `ResourceUsage`, and `SandboxedProcess`.
- Added `# Thread Safety` sections across public types and traits, including a single-owner note for `SandboxedProcess`.
- Added `#[must_use]` to important constructors and value-returning APIs such as `spawn`, `wait_with_usage`, and capability probes.
