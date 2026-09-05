# multi_protocol_transceiver (`mpt`)

Send and receive files over many protocols. Every endpoint is a URL whose
prefix selects the protocol:

```
mpt cp sftp://deploy@srv.example.com/var/log/app.log ./
mpt cp report.pdf "mailto:boss@example.com?subject=Report%20KW36"
mpt cp ftps://user@ftp.example.com/in/x.csv "s3://bucket/import/?endpoint=https://minio:9000"
mpt cp https://example.com/data.json "smtp://me@mail.example.com:587/team@example.com?subject=Data"
mpt ls   "s3://bucket/import/?endpoint=https://minio:9000"
mpt schemes
```

The crate is a library (`mpt`) with a thin CLI binary of the same name.

## URL scheme

```
<scheme>://[user[:password]@]host[:port]/path[?option=value&...]
```

| Prefix | Protocol | Receive | Send | Port | Options |
|---|---|---|---|---|---|
| `file:///abs/path` or a bare path | local file system | ✓ | ✓ | – | – |
| `sftp://user@host/path` | SFTP over SSH | ✓ | ✓ | 22 | `key=<file>`, `passphrase=`, `known_hosts=strict\|accept-new\|off`, `hostkey=SHA256:…`, `timeout=<s>` |
| `scp://user@host/path` | SCP over SSH | ✓ | ✓ | 22 | as sftp (no `ls`) |
| `ftp://user@host/path` | FTP without TLS | ✓ | ✓ | 21 | `passive=`, `nat=` |
| `ftps://user@host/path` | FTP with TLS, explicit `AUTH TLS` by default | ✓ | ✓ | 21 / 990 | `tls=explicit\|implicit`, `insecure=`, `passive=`, `nat=` |
| `http://`, `https://` | HTTP GET / PUT | ✓ | ✓ | 80 / 443 | `method=put\|post\|patch`, `header=Name:Value` (repeatable), `insecure=`, `timeout=` |
| `webdav://`, `webdavs://` | WebDAV over HTTP(S) | ✓ | ✓ | 80 / 443 | `insecure=`, `timeout=` |
| `s3://bucket/key` | S3-compatible object storage | ✓ | ✓ | – | `endpoint=<url>`, `region=`, `path_style=`, `insecure=` |
| `mailto:a@x.de,b@y.de` | e-mail attachment, server from `MPT_SMTP_URL` | ✗ | ✓ | – | `subject=`, `body=`, `cc=`, `bcc=`, `from=`, `filename=` |
| `smtp://user@mail.host:587/a@x.de` | e-mail attachment, server in the URL | ✗ | ✓ | 587 | as mailto, plus `tls=starttls\|implicit\|none`, `insecure=` |

Rules:

* A path without a scheme is a local file.
* A path ending in `/` is a directory: the source file name is appended when sending.
* SSH paths are absolute; `/~/dir/file` is relative to the login directory.
* For `http(s)://` and `webdav(s)://`, query parameters other than the options
  above are passed through to the server.
* E-mail endpoints can only send. Using one as a source fails before any
  connection is made (`scheme 'mailto' cannot receive`).

### Credentials

Priority: URL > environment > default. Passwords are masked in all log output.

| Variable | Purpose |
|---|---|
| `MPT_PASSWORD` | password for sftp/scp/ftp/ftps/http/webdav when not in the URL (`--password`, `--password-file`, `--password-stdin` on the CLI) |
| `MPT_REFUSE_PLAINTEXT_AUTH` | `1` turns the warning about unencrypted credentials into an error |
| `MPT_SSH_KEY`, `MPT_SSH_KEY_PASSPHRASE` | SSH private key. Without it: ssh-agent (`SSH_AUTH_SOCK`), then `~/.ssh/id_ed25519`, `id_ecdsa`, `id_rsa`, then password |
| `MPT_SSH_USER` | SSH user when not in the URL (default `$USER`) |
| `MPT_SSH_KNOWN_HOSTS` | default host-key policy (`strict` if unset) |
| `MPT_SSH_HOSTKEY` | expected host-key fingerprints, comma-separated (`?hostkey=` per URL) |
| `MPT_SMTP_URL`, `MPT_SMTP_PASSWORD` | SMTP server for `mailto:` targets, e.g. `smtp://user@mail.example.com:587?tls=starttls` |
| `MPT_MAIL_FROM` | sender address (also `?from=`, or the SMTP user if it is an address) |
| `MPT_MAIL_MAX_ATTACHMENT` | attachment size limit in bytes (default 25 MiB; mail is buffered in memory) |
| `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_REGION`, `AWS_ENDPOINT_URL`, `AWS_SESSION_TOKEN` | S3 (the standard names; `user:pass@` in the URL overrides the key pair) |

## CLI

```
mpt cp <SRC_URL> <DST_URL>...    copy from one endpoint to one or more targets
mpt ls <URL>                     list a directory
mpt schemes                      print the table above
mpt profiles                     list the named targets from the configuration
mpt credentials set|get|delete   manage OS key store entries (feature "keyring")
mpt config check                 read the configuration file and print what it sets
  -v / -vv / -vvv   log level    --insecure   disable TLS verification    --password <pw>
  --config <PATH>                configuration file (see below)
  --color auto|always|never      colored output (auto: only on a terminal, honours NO_COLOR)
  --password-file <PATH>  --password-stdin   read the password without putting it in argv
  --refuse-plaintext-auth        make unencrypted credentials an error instead of a warning
  --timeout <SECONDS>            inactivity timeout, 30 by default, 0 disables it
  --no-atomic                    write straight to the target name (see below)
  --hash <ALGO>  --check        checksums (see below)     --sign <SPEC>  --verify-signers/--verify-keyring <FILE>
```

Ctrl-C stops a running copy: open connections are dropped, partial files are
removed, every unfinished target reports `cancelled`, and the exit code is 130.

## Configuration

Everything that is not a source or a target can come from a TOML file, so
recurring settings do not have to be repeated on every command line. The first
of these that exists is read:

1. `--config <path>` (an error if it does not exist)
2. `$MPT_CONFIG` (likewise)
3. `$XDG_CONFIG_HOME/mpt/config.toml`, else `~/.config/mpt/config.toml`

`./mpt.toml` in the working directory is read in addition and wins over the
user file, but only for `[defaults]` and `[policy]`: a directory one happens to
stand in must not redirect a transfer or name a key. Other sections in it are
ignored with a warning.

The file never overrides what the caller says explicitly:

```
command-line flag  >  URL option  >  environment variable  >  configuration  >  built-in
```

```toml
[defaults]                    # values for the flags of the same name
timeout     = 60              # seconds of inactivity, 0 disables it
cache       = false
cache_limit = "256M"
retries     = 0
chunk       = "64K"
queue       = 16
atomic      = true            # finish through <name>.mpt-part
hash        = "sha256"
color       = "auto"          # auto | always | never
log         = "warn"          # level, or RUST_LOG syntax; -v and RUST_LOG win

[policy]                      # rules for every endpoint of the process
known_hosts           = "strict"   # default for sftp/scp: strict|accept-new|off
refuse_plaintext_auth = false      # ftp:// with a password, http Basic, smtp without TLS
refuse_insecure_tls   = false      # refuse ?insecure=true instead of honouring it
require_signature     = false      # --check must verify a signature as well
strict_permissions    = false      # a readable file with credentials is an error
max_signature_age     = "0"        # refuse signatures older than e.g. "7d"; 0 = no limit

[signing]                     # default for --sign
key = "ssh:~/.ssh/id_ed25519"      # used when --sign only names the format
agent_fingerprint = "SHA256:…"     # which ssh-agent identity to sign with

[verify]                      # trusted keys for --check, when no --verify-* is given
allowed_signers = "~/.config/mpt/allowed_signers"
keyring         = "~/.config/mpt/trusted.asc"

[ssh]                         # defaults for sftp:// and scp://
user             = "deploy"
key              = "~/.ssh/id_ed25519"
passphrase       = { cmd = "pass ssh/prod" }
known_hosts_file = "~/.ssh/known_hosts"
hostkey          = ["SHA256:…"]    # pinned host keys, one string or a list

[mail]                        # defaults for mailto: and smtp://
smtp           = "smtp://user@mail.example.com:587?tls=starttls"
password       = { env = "MPT_SMTP_PASSWORD" }   # see "Credentials" below
from           = "reports@example.com"
max_attachment = "25M"

[s3]                          # defaults for s3://
endpoint   = "https://minio.example.com"
region     = "eu-central-1"
path_style = true
```

### Credentials

The configuration file should not hold passwords. It holds a reference, and
the secret is fetched when the endpoint is about to be used — and only then,
so a `cmd` provider does not run for a profile this command does not touch:

```toml
[profiles.prod]
url      = "sftp://deploy@srv.example.com/data/"
password = { env = "PROD_PW" }                            # environment variable
# password = { file = "~/.config/mpt/prod.pw" }           # first line of a file
# password = { cmd = "op read op://Infra/prod/password" } # 1Password, pass, gopass, az, …
# password = { keyring = "mpt/prod" }                     # OS key store (feature "keyring")
# password = { vault = "secret/data/mpt/prod#password" }  # HashiCorp Vault (feature "vault")
```

The same references work for `[ssh] passphrase`, `[signing] passphrase`,
`[mail] password` and `[s3] access_key_id` / `secret_access_key`. A password
written out in the file works too, but warns.

| Provider | Where it reads from | Good for |
|---|---|---|
| `env` | environment variable | CI, containers, systemd `LoadCredential` |
| `file` | first line of a file (permissions are checked) | mounted secrets |
| `cmd` | standard output of `sh -c <command>` | any secret manager with a CLI |
| `keyring` | macOS Keychain, Windows Credential Manager, Linux Secret Service | workstations |
| `vault` | `$VAULT_ADDR/v1/<path>` with `$VAULT_TOKEN` | servers without CLI tools |

`keyring` and `vault` are optional features:
`cargo build --features keyring,vault`. With `keyring`,
`mpt credentials set mpt/prod` (secret on stdin), `get` and `delete` manage the
entries.

Because `cmd` runs what the file says, a configuration file that holds or
points at credentials should be readable only by its owner: `mpt` warns
otherwise, and `[policy] strict_permissions = true` makes it an error. `./mpt.toml`
may not carry credentials at all.

### Named targets

A profile gives a recurring endpoint a name, and `mpt://<name>/<path>` stands
for it anywhere a URL is expected:

```toml
[profiles.prod]
url         = "sftp://deploy@srv.example.com/data/"
key         = "~/.ssh/prod_ed25519"      # every other key becomes a URL option
known_hosts = "strict"
hostkey     = "SHA256:f29GJDwDP5hekqa22VhNdaNPBM+q6AzG3FvQaBCJnmg"
timeout     = 60
sign        = "ssh:~/.ssh/prod_ed25519"  # always sign when sending there
hash        = "blake3"

[profiles.boss]
url     = "mailto:boss@example.com"
subject = "Report"
```

```
mpt cp report.pdf mpt://prod/incoming/          # → sftp://…/data/incoming/
mpt cp report.pdf "mpt://prod/in/?timeout=120"  # the reference overrides the profile
mpt ls mpt://prod                               # the profile URL as it stands
mpt profiles                                    # what is defined, passwords masked
```

`url` is required; `sign`, `hash` and `atomic` set the transfer options for
that target (a flag on the command line still wins); everything else becomes a
URL option, so a profile can carry whatever its scheme understands. The path of
the reference is appended to the profile's own path and cannot climb out of it
(`mpt://prod/../etc` is refused). Profiles do not chain, and `./mpt.toml` may
not define any.

Every string may contain `${VAR}`, which is replaced by that environment
variable (an error if it is unset), and paths may start with `~/`. Unknown keys
are an error rather than a silent typo — `mpt config check` reports them, shows
which files were read and prints everything they set.

## Several targets at once

`cp` accepts any number of targets. The source is read **once** and
delivered to all targets concurrently. Nothing is written to the disk in between.

```
mpt cp report.pdf sftp://srv/in/ "s3://bucket/reports/" "mailto:boss@example.com"
mpt cp --cache --retries 2 big.iso sftp://a/ sftp://b/ webdavs://c/
```

Two modes:

| Mode | Memory | How it works | When |
|---|---|---|---|
| streaming (default) | about 1 MiB, independent of size and target count | each chunk is handed to every target as a reference-counted buffer; the slowest target sets the pace | large files, many targets |
| `--cache` | the whole payload, up to `--cache-limit` (default 256M) | the source is read into RAM once; every target reads its own copy | `--retries`, targets that need the size up front (SCP), unreliable targets |

Above the cache limit the copy fails instead of falling back to the disk.
A failing target does not stop the others: every target gets its own result
line, and the exit code is 1 if at least one failed. `--retries` needs
`--cache` (a stream cannot be replayed); note that a retried mail target may be
delivered twice. `--chunk` and `--queue` tune the streaming buffer.

Targets that connect before they read (SCP, SMTP) pause the stream briefly at
the start until they are ready; this is head-of-line blocking, not a deadlock.
A target that stops accepting data altogether is dropped from the fan-out after
`--timeout` and reports a timeout, so it cannot hold up the others.

## Timeouts

`--timeout <seconds>` (default 30, `0` disables it) is an **inactivity** limit,
not a deadline for the whole transfer: any read or write that makes progress
resets it, so arbitrarily large files are fine on a slow but steady line. It
applies to connecting and logging in, to every data stream, to the FTP control
channel, and to a fan-out target that stops draining its queue. `?timeout=` in
a URL overrides the flag for that endpoint.

`--retries <n>` also repeats the connect and login phase, which is safe because
no payload has been read at that point; this works without `--cache`. Only
transient failures are retried, never a rejected password. Per URL:
`?connect_retries=`.

## Atomic transfers

A target file appears under its final name only once it is complete: the
payload goes to `<name>.mpt-part` first and is renamed into place afterwards.
An aborted transfer therefore leaves nothing that a pickup job could mistake
for a finished file, and the partial file is removed. Checksum and signature
files are written after the rename, so they remain the "transfer complete"
marker.

| Protocol | Rename | Mechanism |
|---|---|---|
| file | ✓ | `rename(2)` |
| sftp | ✓ | SFTP `RENAME` (an existing target is removed first) |
| scp | ✓ | `mv -f` over the same SSH connection |
| ftp, ftps | ✓ | `RNFR`/`RNTO` |
| webdav | ✓ | `MOVE` |
| http | – | HTTP cannot rename; the PUT goes straight to the target |
| s3 | – | not needed: an object appears only when its upload is complete |
| mail | – | atomic by nature |

`--no-atomic` writes straight to the target name, for pickup processes that
would trip over the extra file. Two transfers writing the same target file at
the same time still conflict, and the second rename now reports it instead of
interleaving silently.

## Checksums

```
mpt cp --hash sha256 report.pdf sftp://srv/in/ "s3://bucket/reports/" "mailto:boss@example.com"
mpt cp --check sftp://srv/in/report.pdf ./
```

`--hash sha256|sha512|blake3` computes the digest **while the data streams**
(one pass, no re-read, no buffering) and writes `<name>.sha256`, `.sha512` or
`.b3` next to every target that received the file. The content is one line in
the format of `sha256sum` / `b3sum` (`<hex>  <name>`), so recipients can run
`sha256sum -c report.pdf.sha256` or `b3sum -c report.pdf.b3`. Mail targets get
the checksum file as a second attachment plus a `SHA-256: …` line in the body.
The checksum file is written through a second connection to the same target
after the transfer succeeded; a failure there is reported for that target.

`--check` looks for `<name>.b3`, `.sha256` or `.sha512` next to the **source**,
verifies the transferred content against it and fails (exit code 1) on a
mismatch or when no checksum file exists. The target file is left in place so
you can inspect it; the message shows both digests. Both flags work together and
with several targets.

## Credentials in the clear

Two things get a warning, once per run:

* **Credentials without encryption.** `ftp://` with a password, `http://` or
  `webdav://` with basic auth, and SMTP with `tls=none` hand the password to
  anyone on the path. `--refuse-plaintext-auth` (or
  `MPT_REFUSE_PLAINTEXT_AUTH=1`) makes it an error instead.
* **A password in the URL.** It is visible in `ps` and in the shell history.
  `MPT_PASSWORD`, `--password-file <path>` and `--password-stdin` keep it out
  of the command line; a password file that others can read is reported too.

`--insecure` switches off certificate checking for *every* endpoint of a run
and is deprecated for that reason. Put `?insecure=true` on the one URL that
needs it.

Inside the process, passwords and key passphrases are held in `SecretString`
(the `secrecy` crate): they are redacted in `Debug` output and overwritten when
dropped, so they do not linger in memory or turn up in a log line by accident.

## Host keys

`sftp://` and `scp://` check the server's host key against `~/.ssh/known_hosts`
before anything is transferred. The policy is `strict` by default: an unknown
host, a changed key or an unreadable `known_hosts` file aborts the connection,
and the error names the fingerprint the server offered.

```
mpt ls sftp://srv/in/
error: host key of srv:22 is not in known_hosts: SHA256:f29GJDwDP5he…
       Verify it, then add it with `ssh-keyscan -p 22 srv >> ~/.ssh/known_hosts`,
       or connect with ?hostkey=SHA256:f29GJDwDP5he… or ?known_hosts=accept-new
```

| Setting | Meaning |
|---|---|
| `?known_hosts=strict` (default) | only keys already in `known_hosts` are accepted |
| `?known_hosts=accept-new` | trust on first use: a new key is added to `known_hosts` and reported on stderr; a *changed* key is still refused |
| `?known_hosts=off` | no verification at all — only for throwaway test servers |
| `?hostkey=SHA256:…` | pin the expected key; `known_hosts` is not consulted. Repeat the option for several keys |

Pinning is the right choice for scripts and CI, where no `known_hosts` file is
maintained. `+` in a fingerprint may be written as `%2B` or left as is.

## Signatures

```
mpt cp --sign ssh:~/.ssh/id_ed25519 report.pdf sftp://srv/in/
mpt cp --sign pgp:release-key.asc --hash blake3 report.pdf "s3://bucket/releases/"
mpt cp --verify-signers allowed_signers sftp://srv/in/report.pdf ./
mpt cp --verify-keyring release-pub.asc "s3://bucket/releases/report.pdf" ./
```

A checksum alone protects against transfer errors, not against someone who can
replace both the file and its checksum file on the target. `--sign` adds a
detached signature over the checksum file (`report.pdf.sha256.sig` or `.asc`),
written last, so it doubles as the "transfer complete" marker. `--sign` implies
`--hash sha256` unless `--hash` is given. Mail targets get the signature as a
third attachment.

| Backend | `--sign` | Signature file | Receiver verifies with |
|---|---|---|---|
| OpenSSH | `ssh` (ssh-agent, then `MPT_SSH_KEY`, then `~/.ssh/id_*`) or `ssh:<key>` | `<name>.sha256.sig` (SSHSIG, namespace `file`) | `ssh-keygen -Y verify -f allowed_signers -I <principal> -n file -s report.pdf.sha256.sig < report.pdf.sha256` |
| OpenPGP | `pgp:<secret-key.asc>` (`gpg --export-secret-keys --armor`) | `<name>.sha256.asc` | `gpg --verify report.pdf.sha256.asc report.pdf.sha256` |

Encrypted key files take their passphrase from `MPT_SIGN_KEY_PASSPHRASE`;
`MPT_SIGN_KEY_FINGERPRINT` selects a specific ssh-agent identity.

`allowed_signers` options are honoured: `namespaces="…"` must include `file`,
`valid-after=`/`valid-before=` (`YYYYMMDD[HHMM[SS]]`, read as UTC) must contain
the time of verification, and `cert-authority` lines are skipped, because
certificate signatures are not checked. For OpenPGP the keyring's
self-signatures are verified on load; revoked keys and subkeys, and keys that
were not yet valid or had expired when the signature was made, are refused.

On the receiving side `--verify-signers <allowed_signers>` (OpenSSH) or
`--verify-keyring <pubkeys.asc>` (OpenPGP) imply `--check`, require the
signature next to the source's checksum file and reject the transfer **before
any data is copied** when the signature is missing, invalid or made by a key
that is not trusted. The signer's identity is printed on success.

### Signing time

A signed checksum file carries a second line with the moment it was signed:

```
9f2b…  report.pdf
# mpt-signed-at: 2026-09-09T05:12:44Z
```

It is a comment, so `sha256sum -c` and `b3sum -c` ignore it, and it is covered
by the signature, so it cannot be changed unnoticed. Two things use it:

* the signer is judged as it stood **at that moment**, not as it stands now, so
  a key that has expired or been revoked since then still verifies for what it
  signed before;
* `[policy] max_signature_age = "7d"` refuses a signature older than that, which
  is what keeps an old but validly signed file from being replayed in place of
  the current one. With the policy set, a checksum file without a signing time
  is refused as well.

Both backends are verified against the reference tools in the test-suite:
OpenSSH accepts mpt's signatures and vice versa, and `gpg --verify` accepts
mpt's OpenPGP signatures. Cargo features `sign-ssh` and `sign-pgp` (both
default) select the backends.

## Library

```rust
let src = mpt::open("sftp://deploy@srv/var/log/app.log")?;
let dst = mpt::open("s3://bucket/logs/?endpoint=https://minio:9000")?;
let report = mpt::copy(src.as_ref(), dst.as_ref()).await?;
println!("{} bytes", report.bytes);

// fan-out: read once, send to many
let targets: Vec<Box<dyn mpt::Endpoint>> = vec![mpt::open("sftp://a/in/")?, mpt::open("mailto:x@y.z")?];
let refs: Vec<&dyn mpt::Endpoint> = targets.iter().map(|t| t.as_ref()).collect();
let opts = mpt::CopyOptions { cache: mpt::CacheMode::Memory { limit: 64 << 20 }, retries: 2, ..Default::default() };
let report = mpt::copy_many(src.as_ref(), &refs, &opts).await?;
for t in &report.targets {
    println!("{}: {:?}", t.target, t.result);
}
```

`stream::tee` (split one `AsyncRead` into N with backpressure) and
`stream::MemoryCache` are public and usable on their own.

`open` returns a `Box<dyn Endpoint>`. An endpoint exposes `as_receiver()` /
`as_sender()`; both are optional per protocol, so a send-only channel such as
e-mail (or, later, a webhook or message queue) needs no special casing. Data
flows as `Pin<Box<dyn AsyncRead + Send>>` from receiver to sender without
intermediate buffering, except where a protocol forces it (mail; SCP when the
source size is unknown).

Cargo features select protocols: `ssh`, `ftp`, `http`, `webdav`, `s3`, `mail`
(default: all).

## Testing

Unit tests: `cargo test`.

End-to-end tests in `tests/integration.rs` run against real servers and are
skipped unless the corresponding `MPT_IT_*` variable is set. A Docker-free local
setup using Python servers (pyftpdlib, aiosmtpd, moto, WsgiDAV) plus a
user-level `sshd` is provided:

```
python3 -m venv .venv && .venv/bin/pip install pyftpdlib pyopenssl aiosmtpd "moto[server]" wsgidav cheroot
bash tests/local/start_servers.sh .venv /tmp/mpt-it
source /tmp/mpt-it/env.sh && cargo test --test integration
bash tests/local/stop_servers.sh /tmp/mpt-it
```

Implicit FTPS (`tls=implicit`) is implemented but not covered by these servers.

Beyond the two suites:

```
cargo deny check                     # licences, advisories, duplicate crates, sources
cargo audit                          # RustSec advisories against Cargo.lock
cargo +nightly fuzz run <target>     # location_parse, safe_name, parse_sidecar,
                                     # allowed_signers, scp_header
```

The fuzz targets in `fuzz/` cover everything that parses input from the far
side: URLs, file names, checksum files, the `allowed_signers` trust file and
the SCP header. `stream::tee` has a property test instead, since its contract
is about bytes rather than parsing: for any chunk size, queue depth and number
of readers, every reader that stays sees exactly the source bytes.

`cargo deny` accepts one advisory on purpose, RUSTSEC-2023-0071 (a timing side
channel in the `rsa` crate, reachable through `pgp` and `russh`). No fixed
release exists; we sign and verify with those keys but never decrypt, and
ed25519 keys are unaffected. `deny.toml` carries the reasoning.

The minimum supported Rust version is 1.89, set by `russh` and `aes` rather
than by this crate.

One caveat of the local setup: under concurrent connects pyftpdlib writes its
`220` greeting twice on about 1.5 % of connections, which shifts every reply on
that control channel by one. It is a defect of the test server, reproducible
with a plain Python client and unrelated to TLS, so the generated FTP URLs carry
`connect_retries=1`.

## Possible further protocols

The `Receiver` / `Sender` split is designed so that new channels slot in without
changing the core:

* `az://`, `gs://` (Azure Blob, Google Cloud Storage) – nearly free via `object_store`
* `smb://` – `pavao` (libsmbclient binding)
* `imap://` – receive attachments from a mailbox, the counterpart of `mailto:`
* `mqtt://`, `nats://`, `amqp://` – message queues (send-only or receive-only fits naturally)
* `tftp://` – network devices
* `-` – stdin / stdout for pipes
* webhooks (Slack, Teams, Matrix) – send-only over HTTPS
* Dropbox / Google Drive / OneDrive – need OAuth flows
* rsync – only via the external binary
