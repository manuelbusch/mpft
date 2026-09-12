# Installation

`mpt` is a single binary with no runtime dependencies: no interpreter, no
shared library beyond what the operating system provides, no configuration
needed to start. Building it needs a Rust toolchain of version **1.89 or
newer**.

## Building from source

```
git clone <repository> multi_protocol_transceiver
cd multi_protocol_transceiver
cargo build --release
```

The binary is `target/release/mpt`. Copy it wherever your `PATH` points, or
let cargo do it:

```
cargo install --path .
```

That puts `mpt` in `~/.cargo/bin`, which cargo's own installer already added to
your `PATH`.

## Choosing protocols

Every protocol is a cargo feature, and all of them are on by default. A build
that only speaks what you need is smaller and pulls in fewer dependencies,
which matters for a container image or a CI runner.

| Feature | What it adds | Default |
|---|---|---|
| `ssh` | `sftp://`, `scp://` | ✓ |
| `ftp` | `ftp://`, `ftps://` | ✓ |
| `http` | `http://`, `https://` | ✓ |
| `webdav` | `webdav://`, `webdavs://` (implies `http`) | ✓ |
| `s3` | `s3://` | ✓ |
| `mail` | `mailto:`, `smtp://` | ✓ |
| `sign-ssh` | signing and verifying with OpenSSH keys | ✓ |
| `sign-pgp` | signing and verifying with OpenPGP keys | ✓ |
| `keyring` | secrets from the OS key store, and `mpt credentials` | – |
| `vault` | secrets from HashiCorp Vault | – |
| `s3-aws-auth` | the AWS credential chain: SSO, profiles, AssumeRole, IMDS | – |

`all` is a shorthand for the eight default features. To build a smaller binary,
switch the defaults off and name what you want:

```
cargo build --release --no-default-features --features ssh,s3
```

To keep everything and add an optional feature:

```
cargo build --release --features keyring,s3-aws-auth
```

A URL whose protocol was not compiled in fails at once, before any connection
is attempted, and the message names the missing feature:

```
$ mpt cp report.pdf sftp://srv.example.com/in/
error: unsupported scheme 'sftp (compiled without the 'ssh' feature)'
```

## Listing the compiled-in schemes

`mpt schemes` prints what this particular binary can speak, which is the
quickest way to see whether a feature made it in:

```
$ mpt schemes
prefix      recv  send  port    feature   options
file://     yes   yes   -       -         -
            local file system (bare paths work too)
sftp://     yes   yes   22      ssh       key=<file>, known_hosts=strict|accept-new|off, hostkey=SHA256:…
            SFTP over SSH
...
```

The `recv` and `send` columns say which direction a scheme supports: `mailto:`
can send but never receive.

## Shell completions and the manual page

`mpt` generates both itself:

```
mpt completions zsh  > ~/.zfunc/_mpt
mpt completions bash > /etc/bash_completion.d/mpt
mpt man > /usr/local/share/man/man1/mpt.1
```

`bash`, `zsh`, `fish`, `elvish` and `powershell` are supported. The manual page
is roff, so it can also be read without installing it:

```
mpt man | man -l -
```

## Supported platforms

| Platform | Status | Build requirements |
|---|---|---|
| Linux (x86_64, aarch64) | built and tested | Rust toolchain, C linker |
| macOS (Apple silicon, Intel) | built and tested | Rust toolchain, Xcode command-line tools |
| Windows | builds; not yet covered by automated tests | MSVC toolchain. NASM is not required |

Windows has a handful of behavioural differences, all listed in [the Windows
appendix](../appendix/windows.md). Cross-compiling works for targets whose
cryptography crates can be built for them; the pure-Rust parts have no
platform-specific code beyond paths and the ssh-agent transport.

There are no pre-built binaries at present. Building from source is the only
installation path.
