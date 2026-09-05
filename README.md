# multi_protocol_transceiver (`mpt`)

Send and receive files over many protocols. Every endpoint is a URL whose
prefix selects the protocol:

```
mpt copy sftp://deploy@srv.example.com/var/log/app.log ./
mpt copy report.pdf "mailto:boss@example.com?subject=Report%20KW36"
mpt copy ftps://user@ftp.example.com/in/x.csv "s3://bucket/import/?endpoint=https://minio:9000"
mpt copy https://example.com/data.json "smtp://me@mail.example.com:587/team@example.com?subject=Data"
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
| `sftp://user@host/path` | SFTP over SSH | ✓ | ✓ | 22 | `key=<file>`, `passphrase=`, `known_hosts=strict\|accept-new\|off`, `timeout=<s>` |
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
| `MPT_PASSWORD` | password for sftp/scp/ftp/ftps/http/webdav when not in the URL (`--password` on the CLI) |
| `MPT_SSH_KEY`, `MPT_SSH_KEY_PASSPHRASE` | SSH private key. Without it: ssh-agent (`SSH_AUTH_SOCK`), then `~/.ssh/id_ed25519`, `id_ecdsa`, `id_rsa`, then password |
| `MPT_SSH_USER` | SSH user when not in the URL (default `$USER`) |
| `MPT_SSH_KNOWN_HOSTS` | default host-key policy (`accept-new` if unset) |
| `MPT_SMTP_URL`, `MPT_SMTP_PASSWORD` | SMTP server for `mailto:` targets, e.g. `smtp://user@mail.example.com:587?tls=starttls` |
| `MPT_MAIL_FROM` | sender address (also `?from=`, or the SMTP user if it is an address) |
| `MPT_MAIL_MAX_ATTACHMENT` | attachment size limit in bytes (default 25 MiB; mail is buffered in memory) |
| `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_REGION`, `AWS_ENDPOINT_URL`, `AWS_SESSION_TOKEN` | S3 (the standard names; `user:pass@` in the URL overrides the key pair) |

## CLI

```
mpt copy <SRC_URL> <DST_URL>     copy between any two endpoints
mpt send <LOCAL_FILE> <DST_URL>  shorthand for copy
mpt recv <SRC_URL> [LOCAL_PATH]  shorthand for copy into a local path (default ./)
mpt ls <URL>                     list a directory
mpt schemes                      print the table above
  -v / -vv / -vvv   log level    --insecure   disable TLS verification    --password <pw>
```

## Several targets at once

`copy` and `send` accept any number of targets. The source is read **once** and
delivered to all targets concurrently. Nothing is written to the disk in between.

```
mpt copy report.pdf sftp://srv/in/ "s3://bucket/reports/" "mailto:boss@example.com"
mpt copy --cache --retries 2 big.iso sftp://a/ sftp://b/ webdavs://c/
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
