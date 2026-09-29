# mpft (Multi Protocol File Transceiver)

Send and receive files over many protocols. Every endpoint is a URL, and the
prefix of the URL picks the protocol:

```
mpft cp report.pdf sftp://deploy@srv.example.com/incoming/
mpft cp report.pdf "s3://bucket/reports/" "mailto:boss@example.com?subject=Report"
mpft cp ftps://partner.example/out/x.csv "s3://bucket/import/?endpoint=https://minio.example.com"
mpft cp sftp://srv.example.com/var/log/app.log ./
mpft ls webdavs://cloud.example.com/documents/
```

One command copies from anywhere to anywhere — a local path, SFTP, SCP, FTP,
FTPS, HTTP, WebDAV, S3-compatible object storage, or an e-mail attachment —
with the same options whatever the protocol: checksums, signatures, timeouts,
resuming, parallelism. The source is read once and delivered to every target
concurrently, nothing is spooled in between, and a file appears under its
final name only when it is complete.

`mpft` is a Rust library with a command-line program of the same name on top.

## Installation

A Rust toolchain of 1.89 or newer is the only requirement; there are no
pre-built binaries yet.

```
cargo install --path .                       # every protocol, the relay, both signature backends
cargo build --release --features server      # adds `mpft serve`, jobs over HTTP
```

Every protocol is a cargo feature, so a build can carry only what it needs;
[Installation](user_guide/src/getting-started/installation.md) lists them,
with shell completions and the manual page.

## Documentation

The **user guide** under `user_guide/` is the documentation. Build it with
[mdBook](https://rust-lang.github.io/mdBook/) and `mdbook-mermaid`, or read
the Markdown as it is:

```
cargo install mdbook mdbook-mermaid
mdbook serve user_guide                      # http://localhost:3000
```

Where to start:

| If you want to… | Read |
|---|---|
| see what `mpft` is for, and where another tool fits better | [Why mpft?](user_guide/src/why-mpft.md) |
| make a first transfer and understand the URL model | [Your first transfer](user_guide/src/getting-started/first-transfer.md), [Thinking in URLs](user_guide/src/getting-started/addressing.md) |
| send one file to several places, or many files at once | [Several targets at once](user_guide/src/guide/fan-out.md), [Many files](user_guide/src/guide/many-files.md), [Job lists and pipelines](user_guide/src/guide/job-lists.md) |
| survive a dropped line: atomic finishing, `--resume`, `--skip-existing` | [Interrupted and repeated transfers](user_guide/src/guide/reliability.md) |
| leave checksums and signatures the recipient can verify with standard tools | [Checksums](user_guide/src/trust/checksums.md), [Signatures](user_guide/src/trust/signatures.md) |
| keep passwords off the command line and pin host keys | [Credentials and secrets](user_guide/src/configuration/credentials.md), [Securing the connection](user_guide/src/trust/connections.md) |
| stop retyping options: the configuration file, profiles, policies | [Configuration](user_guide/src/configuration/file.md), [Profiles](user_guide/src/configuration/profiles.md), [Policies](user_guide/src/configuration/policies.md) |
| run it from a script, cron or systemd, and read the JSON report | [Using mpft in scripts](user_guide/src/automation/scripting.md), [Scheduled and triggered runs](user_guide/src/automation/scheduling.md) |
| take jobs over HTTP from another program | [Jobs over HTTP with mpft serve](user_guide/src/server/serve.md), [HTTP API](user_guide/src/reference/api.md) |
| upload once to a fast host and let it fan out — passwords on demand, keys that stay on the client, relay to relay | [Relaying through a fast host](user_guide/src/server/relay.md), [Running a relay](user_guide/src/server/relay-host.md), [Relay topologies](user_guide/src/server/relay-topologies.md) |
| review it: trust boundaries, what is checked when, where a secret lives | [Security overview](user_guide/src/security/overview.md) |
| look something up | [Quick reference](user_guide/src/reference/quick-reference.md), [Command line](user_guide/src/reference/cli.md), [Configuration keys](user_guide/src/reference/configuration.md), [Exit codes](user_guide/src/reference/exit-codes.md) |
| know what stays stable between versions | [Compatibility and stability](user_guide/src/reference/compatibility.md) |
| use it as a library | [Using mpft as a library](user_guide/src/appendix/library.md) |
| fix something that went wrong | [Troubleshooting](user_guide/src/appendix/troubleshooting.md) |

`mpft --help`, `mpft <command> --help` and `mpft man` describe the binary you
actually have.

## The library in three lines

```rust
let src = mpft::open("sftp://deploy@srv.example.com/var/log/app.log")?;
let dst = mpft::open("s3://bucket/logs/?endpoint=https://minio.example.com")?;
let report = mpft::copy(src.as_ref(), dst.as_ref()).await?;
```

`copy_many` is the fan-out, `batch::run` the job list, `tee` and
`MemoryCache` the stream utilities underneath; the
[library appendix](user_guide/src/appendix/library.md) walks through them.

## Contributing

[docs/DEVELOPMENT.md](docs/DEVELOPMENT.md) has the test setup (the end-to-end
suites run against local Python servers and the user's own `sshd`, no Docker),
the static checks and fuzz targets, the conventions the user guide follows,
and the design decisions worth knowing before changing something. Protocols
that would slot in next are listed there too.

## Licence

MIT or Apache-2.0, at your option; see `LICENSE-MIT` and `LICENSE-APACHE`.
