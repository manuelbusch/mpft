# Development notes

Material for people working on `mpt` itself. The user guide under
`user_guide/` is written for people who run it; anything about the test
setup, design history or extension points belongs here instead.

## Test servers

The end-to-end tests need real servers. `tests/local/start_servers.sh` starts
Python implementations of FTP, HTTP/WebDAV, S3 and SMTP plus the user's own
`sshd`; see the README for the `MPT_IT_*` variables that switch each suite on.

The Python FTP server duplicates its greeting on roughly 1.5 % of concurrent
connections, which desynchronises that one control channel. It is a defect of
that server, not of FTP or of `mpt`, and it is why the generated test URLs
carry `?connect_retries=1`. Real servers do not need it.

The scripts under `tests/local/` are Unix shell scripts and do not run on
Windows. The unit tests do (`cargo test --lib`) and cover the parsers, the
configuration, the fan-out and the stream utilities. A PowerShell equivalent
of the setup script, using the same Python servers plus the Windows OpenSSH
server, is what would close the gap for the end-to-end tests.

## Windows status

Most of the code is platform-agnostic Rust; the places where the operating
system differs (ssh-agent transport, path handling, file-permission checks,
credential commands) are handled explicitly and are documented in the user
guide's Windows appendix. The development machine has no Windows target and
the cryptography crates cannot be cross-compiled to one from macOS, so that
appendix describes what the code does rather than what has been observed. The
Windows job of the CI workflow is what will settle it.

## Signature interoperability

`mpt` produces SSHSIG signatures in namespace `file` and ordinary detached
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

**`./mpt.toml` is allow-listed.** A configuration file in the working
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
listing cannot be a pattern or tree source. Add the scheme to the capability
matrix in `user_guide/src/protocols/overview.md` and give it a protocol page.
