# Development notes

Material for people working on `mpft` itself. The user guide under
`user_guide/` is written for people who run it; anything about the test
setup, design history or extension points belongs here instead.

## User guide conventions

The guide was reviewed and restructured in September 2026. Three rules keep
it in that state:

1. **Every fact has exactly one page.** A rule, a default, an error message or
   a behaviour is explained in full on one page and nowhere else. Every other
   mention is one sentence and a link to that page. When adding a page, check
   whether the fact already has a home before explaining it again.
2. **No developer context in the user guide.** Test-server quirks, design
   history, what has and has not been verified, and extension points go in
   this file. The guide states what the program does.
3. **Descriptive headings, plain prose.** A heading says what the section
   covers, so the table of contents and the search index are usable, and so
   that anchors stay stable. Prose states the fact; it does not argue for it
   outside `why-mpft.md`. In the reference and protocol pages headings are
   noun phrases; the guide chapters may use a sentence.
4. **Overview pages summarise and link.** The security overview, the
   deployment patterns, the quick reference and the glossary repeat nothing
   in full: each entry is a sentence or a row and a link to the page that
   owns the fact (rule 1 still holds). The compatibility page is the one
   place that states what is kept stable; a change that breaks something
   listed there is noted in the release notes.

The prose is British English; flags and keys keep the program's spelling.
Two phrasings to avoid, because they read as translations or are ambiguous:
"stands in" for "is in", and "at once" where "immediately" or "in parallel"
is meant.

`python3 user_guide/tools/linkcheck.py user_guide/src` checks relative links
and heading anchors; run it after renaming a heading. `mdbook build` in
`user_guide/` must pass without warnings, and needs `mdbook-mermaid`
(`cargo install mdbook-mermaid`) for the diagrams on the deployment page;
`mermaid.min.js` and `mermaid-init.js` in `user_guide/` are what
`mdbook-mermaid install` put there.

## Running the tests

```
cargo test                                   # unit tests and the local-only suites
cargo test --features server                 # adds the server's tests and tests/server.rs
cargo clippy --features server --all-targets
cargo fmt --check
```

`tests/cli.rs` runs the binary on local files only: what it prints, with
and without `--json`, and how it exits. `tests/server.rs` starts the binary as a server and moves local files over
HTTP and WebSocket (one case, with feature `relay`, starts a relay beside it
and needs `ssh-keygen`); `tests/relay.rs` starts it as a relay and sends files
through it with the binary as the client, and needs `ssh-keygen` for the
client keys. A few relay cases start two relays, to cover a target that one
relay hands on to the other; the ones that need a real target behind the
relay are skipped unless `MPFT_IT_FTP` or `MPFT_IT_SFTP` is set.

### Test servers

The end-to-end tests in `tests/integration.rs` run against real servers and
are skipped unless the corresponding `MPFT_IT_*` variable is set. A Docker-free
setup using Python servers plus the user's own `sshd` is provided:

```
python3 -m venv .venv && .venv/bin/pip install pyftpdlib pyopenssl aiosmtpd "moto[server]" wsgidav cheroot
bash tests/local/start_servers.sh .venv /tmp/mpft-it
source /tmp/mpft-it/env.sh && cargo test --test integration
bash tests/local/stop_servers.sh /tmp/mpft-it
```

`start_servers.sh` writes `<work-dir>/env.sh` with these variables; each one
switches its suite on, and an unset one skips it with a message:

| Variable | Server | Suite |
|---|---|---|
| `MPFT_IT_FTP`, `MPFT_IT_FTPS` | pyftpdlib, plain and explicit TLS with a self-signed certificate | FTP round trips, on-demand relay passwords |
| `MPFT_IT_HTTP`, `MPFT_IT_WEBDAV` | a static HTTP server and WsgiDAV | HTTP and WebDAV round trips |
| `MPFT_IT_S3` | moto | S3 round trips including a multipart upload |
| `MPFT_IT_MAILTO`, `MPFT_SMTP_URL`, `MPFT_IT_MAILDIR` | aiosmtpd writing to a maildir | mail delivery, checked by reading the maildir |
| `MPFT_IT_SFTP`, `MPFT_IT_SCP`, `MPFT_IT_SSH_HOSTKEY` | the user's `sshd` with a generated client key | SFTP and SCP round trips, host-key pinning, agent forwarding through a relay |
| `MPFT_IT_SFTP_CERT`, `MPFT_IT_SSH_AGENT` | the same `sshd` trusting a CA, and an `ssh-agent` holding the certificate key | certificate authentication from a file and from an agent, also through a relay |
| `MPFT_IT_LOG` | — | `debug` shows the client's tracing while the tests run |

Running the script again starts only what is not running; `pids` in the
work dir keeps every server it started, and `agent.pid` the `ssh-agent`, so
`stop_servers.sh` stops all of them. It removes the agent's socket only once
the agent is gone.

The ports are the defaults in the table's order: 2121 and 2122 (FTP, FTPS),
8082 (HTTP), 8081 (WebDAV), 9000 (S3), 8025 (SMTP) and 2222 (SSH). A second
set beside the first — when the defaults are taken by another checkout, say —
needs a work dir of its own and other ports, given as `MPFT_IT_PORT_FTP`,
`MPFT_IT_PORT_FTPS`, `MPFT_IT_PORT_HTTP`, `MPFT_IT_PORT_WEBDAV`,
`MPFT_IT_PORT_S3`, `MPFT_IT_PORT_SMTP` and `MPFT_IT_PORT_SSH`; the `env.sh` it
writes points at them:

```
export MPFT_IT_PORT_FTP=2131 MPFT_IT_PORT_FTPS=2132 MPFT_IT_PORT_HTTP=8092 \
       MPFT_IT_PORT_WEBDAV=8091 MPFT_IT_PORT_S3=9010 MPFT_IT_PORT_SMTP=8035 MPFT_IT_PORT_SSH=2232
bash tests/local/start_servers.sh .venv /tmp/mpft-it2
source /tmp/mpft-it2/env.sh && cargo test --test integration
bash tests/local/stop_servers.sh /tmp/mpft-it2
```

Implicit FTPS (`tls=implicit`) is implemented but not covered by these
servers.

WsgiDAV percent-decodes a MOVE's `Destination` header before it parses it as
a URL, so an encoded `?` in the destination ends the path there and the file
is renamed to the part before it. `mpft` sends the header encoded, as RFC 4918
asks; the test with such names therefore uploads them without the atomic
rename on WebDAV.

The Python FTP server duplicates its greeting on roughly 1.5 % of concurrent
connections, which desynchronises that one control channel. It is a defect of
that server, not of FTP or of `mpft`, and it is why the generated test URLs
carry `?connect_retries=1`. Real servers do not need it.

The scripts under `tests/local/` are Unix shell scripts and do not run on
Windows. The unit tests do (`cargo test --lib`) and cover the parsers, the
configuration, the fan-out and the stream utilities. A PowerShell equivalent
of the setup script, using the same Python servers plus the Windows OpenSSH
server, is what would close the gap for the end-to-end tests.

### Static checks and fuzzing

```
cargo deny check                     # licences, advisories, duplicate crates, sources
cargo audit                          # RustSec advisories against Cargo.lock
cargo +nightly fuzz run <target>     # see fuzz/fuzz_targets
```

The fuzz targets under `fuzz/` cover everything that parses input from the
far side or from a file the user did not write: `location_parse`,
`safe_name`, `parse_sidecar`, `allowed_signers`, `scp_header`, and the three
job-list forms `batch_lines`, `batch_jsonl`, `batch_csv`. `stream::tee` has a
property test instead (`proptest`, in `src/stream.rs`), since its contract is
about bytes rather than parsing: for any chunk size, queue depth and number of
readers, every reader that stays sees exactly the source bytes.

`cargo deny` accepts one advisory on purpose, RUSTSEC-2023-0071 (a timing side
channel in the `rsa` crate, reachable through `pgp` and `russh`). No fixed
release exists; `mpft` signs and verifies with those keys but never decrypts,
and ed25519 keys are unaffected. `deny.toml` carries the reasoning, and the
licence allow-list is permissive licences only.

### Continuous integration

`.github/workflows/ci.yml` runs on every push to `main` and `test-ci`, and
on every pull request: `cargo fmt` and `clippy -D warnings`, the whole test suite on Linux
and macOS, a build plus the unit tests on Windows, the end-to-end suite on
Linux against the servers of `tests/local/start_servers.sh`, `cargo check`
with the minimum Rust version, and `cargo deny check`.

### Minimum Rust version

`rust-version` in `Cargo.toml` is 1.89, set by `russh` and `aes` rather than
by this crate. Raise it when a dependency needs it, and note it in the
release notes: the user guide's installation page states the number.

## Windows status

Most of the code is platform-agnostic Rust; the places where the operating
system differs (ssh-agent transport, path handling, file-permission checks,
credential commands) are handled explicitly and are documented in the user
guide's Windows appendix. The development machine has no Windows target and
the cryptography crates cannot be cross-compiled to one from macOS, so that
appendix describes what the code does rather than what has been observed. The
Windows job of the CI workflow is what will settle it.

## Signature interoperability

`mpft` produces SSHSIG signatures in namespace `file` and ordinary detached
OpenPGP signatures, and verifies what `ssh-keygen -Y sign` and
`gpg --detach-sign` produce. Both directions are exercised against the real
tools in the test suite, so the compatibility claim in the user guide is a
tested property rather than a statement about the format.

## Design decisions worth remembering

**One SSH connection per job.** Sharing one SSH session between concurrent
transfers was tried and withdrawn: under concurrency a dropped stream could
poison the whole connection and fail a transfer mid-write. The saving was on
the order of a hundred milliseconds per job, which is not worth that failure
mode. `--parallel` is therefore also the number of simultaneous logins.

**`./mpft.toml` is allow-listed.** A configuration file in the working
directory contributes `[defaults]` and `[policy]` only. Any section added to
the configuration later is dropped there until someone decides otherwise, so
a directory nobody vetted can never redirect a transfer or run a credential
command.

## Adding a protocol

Implement `Endpoint` with whichever of `Receiver` and `Sender` makes sense,
add a `Scheme` variant with its `SchemeInfo`, and hand it out from
`protocols::open`. The optional methods (`supports_rename`, `rename`,
`remove`, `supports_append`, `existing_size`, `append`, `supports_mkdir`,
`mkdir_all`) default to "not supported", and the transfer pipeline adapts: a
target without rename simply does not get atomic finishing, a source without
listing cannot be a pattern or tree source.

Two methods of `Sender` are worth overriding even so. `scheme_name` names the
scheme in the error an unsupported method returns; a sender that keeps the
default is called `unknown` there. `is_dir` says whether the location names
an existing directory, so that a target without a trailing slash still takes
the file under its own name, as `cp` does; the default `false` is right only
where the slash alone decides (S3, HTTP, mail). Add the scheme to the capability
matrix in `user_guide/src/protocols/overview.md` and give it a protocol page.

## Possible further protocols

The `Receiver` / `Sender` split is designed so that new channels slot in
without changing the core. Candidates, roughly in order of effort:

- `az://`, `gs://` (Azure Blob, Google Cloud Storage) — nearly free through
  `object_store`, which already carries S3
- `smb://` — `pavao` (a libsmbclient binding)
- `imap://` — receive attachments from a mailbox, the counterpart of `mailto:`
- `mqtt://`, `nats://`, `amqp://` — message queues; send-only or receive-only
  fits the endpoint model naturally
- `tftp://` — network devices
- `-` — stdin and stdout for pipes; today `mpft batch -` is the only reader of
  standard input
- webhooks (Slack, Teams, Matrix) — send-only over HTTPS
- Dropbox, Google Drive, OneDrive — each needs an OAuth flow
- rsync — only by way of the external binary
