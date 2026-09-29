# Windows

`mpft` builds and runs on Windows. Most of it is platform-agnostic Rust; this
page collects the places where the operating system differs and how `mpft`
handles each. Windows is not yet covered by automated tests, so it is
supported on a best-effort basis; see [Supported
platforms](../getting-started/installation.md#supported-platforms).

## Building

The MSVC toolchain alone is enough:

```
cargo build --release
```

NASM is **not** required. The TLS stack uses its own pre-built assembly
(`aws-lc-rs/prebuilt-nasm`); a missing NASM is what usually trips a Windows
build of a Rust project that uses rustls.

## ssh-agent

Unix has one answer, `$SSH_AUTH_SOCK`. Windows has two, and `mpft` tries both:

1. **The named pipe in `$SSH_AUTH_SOCK`**, if it is set. Git for Windows and
   several other tools point it at a pipe rather than a socket.
2. **`\\.\pipe\openssh-ssh-agent`**, the default pipe of the Windows OpenSSH
   agent service, when the variable is unset.
3. **Pageant**, PuTTY's agent, if neither pipe answers.

On Windows the agent is always tried, because neither the service pipe nor
Pageant needs an environment variable to be found. On Unix the absence of
`$SSH_AUTH_SOCK` is taken as "no agent". When none of the three answers, the
error names each one that was tried and why it failed.

Signing works through the same path: SSHSIG is assembled on the client side, so
an agent that can sign at all can sign here.

## Credential commands

`{ cmd = "…" }` runs through `cmd /C` instead of `sh -c`. What that means in
practice:

```toml
# Unix
password = { cmd = "pass show hosting/partner | head -1" }
# Windows
password = { cmd = "op read op://Infra/prod/password" }
```

Pipes and redirection follow `cmd` rules rather than shell rules, quoting is
`cmd` quoting, and PowerShell is not involved unless you invoke it yourself
(`powershell -Command "…"`). Everything else about the provider is
[as it is elsewhere](../configuration/credentials.md#the-cmd-provider).

## File permissions

There are no mode bits to check, so the question "can anyone else read this?"
is answered by location instead: a key, password file or configuration file
that holds secrets and lies **outside the user's profile directory** produces a
warning.

```
WARN … holds a secret and lies outside your profile directory; check who else can read it
```

That is a weaker check than the Unix one. A file inside `%USERPROFILE%` is
assumed to be as private as the profile itself; an ACL check is not
implemented. `[policy] strict_permissions` turns the check of a [secret
file](../configuration/credentials.md#files-with-secrets-in-them) into a
refusal here too; for the configuration file itself it applies to the Unix
check only.

## Paths

Local paths work as they look:

```
mpft cp C:\data\report.pdf sftp://srv.example.com/in/
mpft cp \\fileserver\share\report.pdf "s3://bucket/in/"
```

- **A drive letter is not a scheme.** `C:\data\x.bin` is recognised as a local
  path rather than mistaken for a URL, and so is a UNC path.
- **`\` is a path separator** in a local path, and only there: in a URL's
  path it is part of a name, as the server sees it. That matters for the files
  `mpft` writes beside yours: a checksum file and a `.mpft-part` land next to
  their file rather than in the working directory.
- **A trailing `\` marks a directory target**, as `/` does.

Remote paths are unaffected: an `sftp://` path is the server's, and the server
is usually not Windows.

## Everything else

- **Colour** works: the terminal is put into the right mode automatically, and
  `NO_COLOR` is honoured as elsewhere.
- **Ctrl-C** stops a transfer, cleans up part files and exits 130 as it does on
  Unix.
- **The configuration file** is looked for in `%USERPROFILE%\.config\mpft\config.toml`
  when `XDG_CONFIG_HOME` is unset, since that is what the home directory
  resolves to.
- **Completions** include `powershell`:

  ```
  mpft completions powershell > $PROFILE.CurrentUserAllHosts
  ```
