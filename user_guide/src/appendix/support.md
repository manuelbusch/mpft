# Licensing and support

## Licence

`mpt` is free software under either the MIT licence or the Apache License,
Version 2.0, at your option — the arrangement most of the Rust ecosystem uses,
so it combines with either family of licences without a conflict. The full
texts are `LICENSE-MIT` and `LICENSE-APACHE` at the root of the repository,
and `Cargo.toml` records the same choice as `MIT OR Apache-2.0`. Every
dependency is listed in `Cargo.lock` with its version; their licences are
their own, and a build has them at hand:

```
cargo install cargo-license && cargo license
```

## Versions

This guide describes `mpt` 0.1. `mpt --version` prints the version of the
binary you have, and `mpt --help` is authoritative for that binary. What is
kept stable between versions, and what is not, is under [Compatibility and
stability](../reference/compatibility.md).

## Reporting a problem

Problems go to the repository's issue tracker. [Reporting a
problem](troubleshooting.md#reporting-a-problem) lists what a useful report
contains; the short form is the exact command with credentials removed, the
output of `mpt -vv`, and `mpt --version`. Passwords are masked in every log
line, so the output can be attached as it is.

A problem that has a security consequence — a credential in a log, a check
that can be bypassed, a file written where it should not be — should not go
to a public tracker. Send it to the maintainer directly and allow time for a
fix before it is discussed in public.

## Building with an audit trail

There are no pre-built binaries; a deployment builds from source, which is
also where a review of the supply chain starts:

- `Cargo.lock` pins every dependency, so two builds of the same commit take
  the same crates.
- `cargo audit` (from `cargo install cargo-audit`) checks those crates
  against the RustSec advisory database.
- `cargo cyclonedx` or `cargo sbom` produce a software bill of materials in
  a standard format for whoever keeps an inventory.
- A build with `--no-default-features` and only the protocols that are
  needed pulls in fewer crates to audit; see [Choosing
  protocols](../getting-started/installation.md#choosing-protocols).
