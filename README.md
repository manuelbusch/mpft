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
| `sftp://user@host/path` | SFTP over SSH | ✓ | ✓ | 22 | `key=<file>`, `cert=<file>`, `passphrase=`, `known_hosts=strict\|accept-new\|off`, `hostkey=SHA256:…`, `timeout=<s>` |
| `scp://user@host/path` | SCP over SSH | ✓ | ✓ | 22 | as sftp (no `ls`) |
| `ftp://user@host/path` | FTP without TLS | ✓ | ✓ | 21 | `passive=`, `nat=` |
| `ftps://user@host/path` | FTP with TLS, explicit `AUTH TLS` by default | ✓ | ✓ | 21 / 990 | `tls=explicit\|implicit`, `insecure=`, `passive=`, `nat=` |
| `http://`, `https://` | HTTP GET / PUT | ✓ | ✓ | 80 / 443 | `method=put\|post\|patch`, `header=Name:Value` (repeatable), `token=<bearer>`, `insecure=`, `timeout=` |
| `webdav://`, `webdavs://` | WebDAV over HTTP(S) | ✓ | ✓ | 80 / 443 | `token=<bearer>`, `insecure=`, `timeout=` |
| `s3://bucket/key` | S3-compatible object storage | ✓ | ✓ | – | `endpoint=<url>`, `region=`, `path_style=`, `insecure=`, `profile=`, `aws_chain=` |
| `mailto:a@x.de,b@y.de` | e-mail attachment, server from `MPT_SMTP_URL` | ✗ | ✓ | – | `subject=`, `body=`, `cc=`, `bcc=`, `from=`, `filename=` |
| `smtp://user@mail.host:587/a@x.de` | e-mail attachment, server in the URL | ✗ | ✓ | 587 | as mailto, plus `tls=starttls\|implicit\|none`, `auth=xoauth2\|plain\|login`, `insecure=` |

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
| `MPT_SSH_CERT` | OpenSSH certificate for that key (`<key>-cert.pub` is found on its own) |
| `SSH_AUTH_SOCK` | ssh-agent socket (Unix) or named pipe (Windows); without it Windows tries the OpenSSH agent service and then Pageant |
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
mpt cp -t <DST_URL> <SRC_URL>... copy every source into a directory target (-t repeatable)
mpt batch <FILE|->               run a job list: lines, JSON Lines or CSV (see below)
mpt batch - --follow             run jobs as their lines arrive on stdin
mpt ls <URL>                     list a directory
mpt schemes                      print the table above
mpt profiles                     list the named targets from the configuration
mpt credentials set|get|delete   manage OS key store entries (feature "keyring")
mpt config check                 read the configuration file and print what it sets
mpt completions <shell>          completion script for bash, zsh, fish, elvish or powershell
mpt man                          the manual page in roff (mpt man | man -l -)
  -v / -vv / -vvv   log level    --insecure   disable TLS verification    --password <pw>
  --config <PATH>                configuration file (see below)
  --color auto|always|never      colored output (auto: only on a terminal, honours NO_COLOR)
  --password-file <PATH>  --password-stdin   read the password without putting it in argv
  --refuse-plaintext-auth        make unencrypted credentials an error instead of a warning
  --json                         print the result as JSON on stdout (see below)
  --progress auto|always|never   progress line (auto: only on a terminal, and not with --json)
  --timeout <SECONDS>            inactivity timeout, 30 by default, 0 disables it
  --no-atomic                    write straight to the target name (see below)
  --resume                       continue an interrupted transfer from its .mpt-part file
  --skip-existing                leave targets alone that already hold the file (same name and size)
  --delete-source                delete the source once every target has it
  --hash <ALGO>  --check        checksums (see below)     --sign <SPEC>  --verify-signers/--verify-keyring <FILE>
  -r  --parallel <N>  --fail-fast  --dry-run  --allow-empty   for cp and batch (see "Many files")
```

Ctrl-C stops a running copy: open connections are dropped, partial files are
removed, every unfinished target reports `cancelled`, and the exit code is 130.

### Exit codes

| Code | Meaning |
|---|---|
| 0 | everything succeeded |
| 1 | a target failed, or the remote side reported an error |
| 2 | the command line, a URL or the configuration is wrong |
| 3 | a checksum did not match, or a signature was missing, invalid or not trusted |
| 4 | authentication failed |
| 130 | stopped with Ctrl-C |

With several targets a mixed outcome is 1; with one target the code says what
went wrong with it. A batch works the same way: if every failed job failed for
the same reason (all 4, say), that is the code; otherwise 1.

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
resume      = false           # continue from a leftover .mpt-part
hash        = "sha256"
color       = "auto"          # auto | always | never
log         = "warn"          # level, or RUST_LOG syntax; -v and RUST_LOG win
json        = false           # print the result as JSON on stdout

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
cert             = "~/.ssh/id_ed25519-cert.pub"
passphrase       = { cmd = "pass ssh/prod" }
known_hosts_file = "~/.ssh/known_hosts"
hostkey          = ["SHA256:…"]    # pinned host keys, one string or a list

[mail]                        # defaults for mailto: and smtp://
smtp           = "smtp://user@mail.example.com:587?tls=starttls"
password       = { env = "MPT_SMTP_PASSWORD" }   # see "Credentials" below
auth           = "auto"       # or xoauth2 | plain | login
from           = "reports@example.com"
max_attachment = "25M"

[http]                        # defaults for http(s):// and WebDAV
token = { cmd = "az account get-access-token --query accessToken -o tsv" }

[s3]                          # defaults for s3://
endpoint   = "https://minio.example.com"
region     = "eu-central-1"
path_style = true
profile    = "prod"           # AWS credential chain (feature "s3-aws-auth")
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

## Many files

`cp` moves one file; `cp -t` and `batch` move many. Each job is one source
with its targets, run through the same pipeline as a single `cp` (fan-out,
checksums, signatures, atomic finish, resume all apply per job). Up to
`--parallel` jobs (4 by default, `[defaults] parallel`) run at the same time.

```
mpt cp -t sftp://srv/in/ -t s3://bucket/in/ *.csv        # every file to both targets
mpt batch jobs.txt --parallel 8
find /export -name '*.pdf' -printf '%p sftp://srv/in/\n' | mpt batch -
mpt batch jobs.csv --dry-run                              # list the jobs, send nothing
mpt cp 'sftp://srv/out/*.csv' /data/incoming/            # every matching remote file
mpt cp -r /data/export/ sftp://srv/in/export/             # a whole tree
```

`-r` copies a directory with everything below it, as `rsync` reads the
slash: `dir/` puts the contents into the target, `dir` the directory itself.
Directories are created on the target first (the empty ones too), then
every file is a job of its own, so `--parallel` applies to a tree just as it
does to a list. That needs a target with directories to create: file, sftp,
scp, ftp, webdav, and S3 (where keys make their own "directories"); an HTTP
target refuses a tree, and a source has to be able to list, which rules out
`scp://` and `http://` as tree sources. Links are whatever the source's
listing says they are.

A source whose file name holds `*` or `[…]` stands for every file in that
directory whose name matches (a listing, filtered; dotfiles only when the
pattern starts with a dot). It works on any protocol that can list, in a job
list as well as on the command line, and its targets must be directories.
`?` is not a pattern character, since it starts the URL's query. A pattern
that matches nothing is an error, unless `--allow-empty` says a quiet run
is fine (a cron job over an inbox, say).

A job list is read from a file or from standard input (`-`), in one of three
forms; the form is taken from the file name (`.jsonl`, `.csv`, `.tsv`) or
guessed from the first line, and `--format lines|jsonl|csv` settles it.

| Form | One job looks like | Notes |
|---|---|---|
| lines | `/data/a.bin sftp://srv/in/ s3://bucket/in/` | shell quoting for names with spaces, `#` comments |
| JSON Lines | `{"src": "/data/a.bin", "dst": ["sftp://srv/in/", "s3://bucket/in/"]}` | `dst` is a string or a list |
| CSV / TSV | header `src,dst,dst`, one row per job | extra columns are ignored, empty `dst` cells too |

`batch - --follow` does not wait for the end of the input: every line is
run as soon as it is complete, and the batch ends when the input does. That
turns a pipe into a queue, `inotifywait -m … | mpt batch - --follow` say, or
a script that decides job by job. Credentials for endpoints that first
appear in a later line are fetched when that line arrives. A line that
cannot be read, resolved or would write a file an earlier job already
writes is reported (`line 7: …`) and skipped; the rest carry on. The line
form and JSON Lines work as they do from a file; CSV needs its header row
first.

URLs in a list are what you would type on the command line: `mpt://profile/`
names work, and the credentials of every endpoint in the list are fetched
before the first job starts. What the list may not do is send two jobs to the
same file: they would share a `.mpt-part`, so the batch is refused before
anything is transferred (exit code 2).

Every job opens its own connections; `--parallel` is therefore also the number
of simultaneous logins on a host (an `sshd` with the default `MaxStartups`
starts refusing at ten). With `--cache`, memory is `--cache-limit` times
`--parallel`. `--fail-fast` stops starting jobs after the first failure and
cancels the running ones; Ctrl-C stops everything, as for a single copy.

Each job is reported as it finishes, prefixed `[3/120]`; with `--json`, one
JSON object per job goes to stdout as it completes (JSON Lines, with a `job`
field holding the position in the list), which a script can follow with
`jq -c`. The progress line shows jobs done, jobs failed and bytes so far.

### Moving instead of copying

`--delete-source` (`[defaults] delete_source`) deletes the source once every
target has the file: all targets succeeded, the checksum matched if one was
checked, and targets skipped with `--skip-existing` count as having it. If a
single target is missing the file, nothing is deleted. A failure to delete
after a successful copy is reported as such (exit code 1) and shows as
`source_removed: false` in the JSON; the copy itself stands. The source has
to be somewhere that can delete: file, sftp, scp, ftp, webdav or s3, which is
checked before anything is transferred. With `-r` this empties an inbox tree
of its files; the directories stay.

```
mpt cp -r --skip-existing --delete-source sftp://srv/outbox/ /data/inbox/   # drain a remote outbox
```

## Server

`mpt serve` (feature `server`, not in the default build) takes jobs over
HTTP and runs them through the same pipeline as `cp` and `batch`. A job is
one transfer (a source and its targets) or a batch of them; every transfer
has its own progress, which a client polls with `GET` or follows over a
WebSocket.

```
cargo build --release --features server
MPT_API_TOKEN=… mpt serve                                  # 127.0.0.1:7788
curl -H "Authorization: Bearer $MPT_API_TOKEN" \
     -d '{"src": "mpt://inbox/report.pdf", "dst": ["mpt://prod/", "mpt://archive/"]}' \
     localhost:7788/v1/jobs
```

```toml
[server]
token     = { env = "MPT_API_TOKEN" }   # any credential provider works here
bind      = "127.0.0.1:7788"            # anything but loopback needs a token
journal   = "~/.local/state/mpt/jobs.jsonl"
retention = "24h"                       # finished jobs stay this long; 0 = until restart
parallel  = 4                           # transfers in flight, over all jobs
grace     = "30s"                       # a shutdown waits this long for running jobs
urls      = "profiles"                  # or "any"
profiles  = ["inbox", "prod", "archive"] # optional: only these
```

Every flag of `mpt serve` (`--bind`, `--token-env`, `--journal`,
`--retention`, `--parallel`, `--grace`, `--allow-any-url`, `--port-file`)
wins over its key in `[server]`. The global flags apply to every job the
server runs: `--sign`, `--check`, `--cache`, `--timeout`, `--insecure` and
the rest set the server's defaults, and a job may override the ones listed
under `options` below.

| Route | What it does |
|---|---|
| `POST /v1/jobs` | one transfer: `{"src": …, "dst": … \| […], "options": {…}}` → `202 {"id", "url", "state"}` |
| `POST /v1/batches` | many: `{"jobs": [{"src", "dst"}, …], "options": {…}}` as JSON, or a job list as `application/x-ndjson`, `text/csv` or `text/plain` (the forms of `mpt batch`) with the options in the query, `?parallel=2&fail_fast=true` |
| `GET /v1/jobs?state=running&limit=50` | summaries, newest first |
| `GET /v1/jobs/{id}` | the job with every transfer: state, bytes, size, report |
| `GET /v1/jobs/{id}/transfers/{n}` | one transfer |
| `DELETE /v1/jobs/{id}` | cancel; partial files are removed as with Ctrl-C |
| `GET /v1/jobs/{id}/events` | WebSocket: a `snapshot`, then the job's events until `done` |
| `GET /v1/events` | WebSocket: every job's events |
| `GET /v1/healthz` | no token needed; `503` while shutting down |

`options` per job: `parallel` (transfers of this batch in flight, capped by
the server's), `fail_fast`, `hash`, `check`, `skip_existing`,
`delete_source`, `atomic`, `resume`, `cache`, `retries` (needs `cache`),
`timeout`, `allow_empty`, `recursive`. A job goes `queued → preparing →
running → done | failed | cancelled`; `preparing` resolves the URLs, expands
patterns and trees and refuses a target another running job is writing.
A job that fails there has an `error` and no transfers; otherwise each
transfer carries its own `state`, `progress: {read, total}`, `error` and,
once it is over, the same `report` that `--json` prints. Transfers and
their reports name endpoints as they were submitted (`mpt://inbox/report.pdf`,
or `mpt://inbox/a.csv` for a file a pattern matched), not by what a profile
resolves to; a URL given in full is shown with its password masked. Errors come as
`{"error": {"kind", "message"}}` with 400, 401, 404, 409 (a target taken
twice), 413, 415 or 503.

The WebSocket carries one JSON object per frame: `snapshot`, `queued`,
`started`, `transfer_started`, `progress` (bytes, four times a second while
they change), `transfer_done` and `done`. A client that falls behind gets
a fresh `snapshot` in place of what it missed. The token goes in the
`Authorization` header here too; there is no `?token=`.

By default a job may only name `mpt://<profile>/…` endpoints, so the
configuration decides which hosts, options and credentials the API can
reach, and no password ever travels in a request or lands in the journal;
a local directory is a profile with a local `url`. `urls = "any"` (or
`--allow-any-url`) lets a job name any URL, as on the command line. Whoever
has the token can use every allowed profile, including its credential
providers. There is no TLS: put a reverse proxy in front for anything
beyond the local machine.

With a `journal`, every accepted job is appended to a JSONL file (mode
`0600`) and closed there when it is over. After a restart, jobs left open
run again with `attempt` raised by one — also those the shutdown cancelled
after `grace` ran out — so a target that cannot take a file twice (mail)
may get it twice, and a `delete_source` job whose source is already gone
fails on the second run; file targets are safe, since a transfer either
finished or left only a `.mpt-part`. Finished jobs do not survive a restart.
Ctrl-C stops taking jobs, waits `grace` for the running ones and exits 0;
a second Ctrl-C cancels them at once.

## Single sign-on

Long-lived keys in a file are what SSO replaces. Where a protocol has an
answer, mpt uses it:

**S3** — with the `s3-aws-auth` feature, credentials come from the AWS chain
instead of from the URL: the SSO cache that `aws sso login` fills, the profiles
in `~/.aws/config`, AssumeRole, web identity and the instance metadata service.

```
cargo build --features s3-aws-auth
mpt cp report.pdf "s3://bucket/reports/?profile=prod"       # or [s3] profile = "prod"
mpt cp report.pdf "s3://bucket/reports/?aws_chain=true"     # the chain without a named profile
```

It is used only when a profile is named (`?profile=`, `[s3] profile`,
`$AWS_PROFILE`) or `?aws_chain=true` asks for it, so nothing reaches for the
instance metadata service unbidden. Explicit keys — `user:pass@` in the URL or
`[s3] access_key_id` — always win.

**SMTP** — `?auth=xoauth2` logs in with an OAuth2 access token instead of a
password, which is what Microsoft 365 and Google want now that they have
switched basic authentication off. The token takes the place of the password,
so a credential provider fetches it:

```toml
[mail]
smtp     = "smtp://reports@example.com@smtp.office365.com:587?tls=starttls"
auth     = "xoauth2"
password = { cmd = "az account get-access-token --resource https://outlook.office365.com --query accessToken -o tsv" }
```

Anything that prints a token works the same way (`gcloud auth print-access-token`,
a script around a client-credentials flow), and the token is fetched once per
run, when the mail is about to be sent.

**SFTP and SCP** — short-lived OpenSSH certificates from Vault, Teleport or
step-ca work, so a CA can vouch for a key that `authorized_keys` never lists.
An agent that holds a certificate needs nothing extra; a key in a file takes
`?cert=<id-cert.pub>` — or nothing at all, since `<key>-cert.pub` beside the
key is found the way OpenSSH finds it:

```
mpt cp report.pdf "sftp://deploy@srv/in/?key=~/.ssh/id_ed25519"     # uses id_ed25519-cert.pub
mpt cp report.pdf "sftp://deploy@srv/in/?key=/tmp/k&cert=/tmp/k-cert.pub"
```

If the server will not take the certificate, the bare key still gets its turn.

**HTTP and WebDAV** — `?token=<bearer>` sends `Authorization: Bearer …`
instead of basic authentication, and `[http] token` takes a credential
reference, so the token is fetched when it is needed rather than pasted into
the command line:

```toml
[http]
token = { cmd = "az account get-access-token --resource https://graph.microsoft.com --query accessToken -o tsv" }
```

The header is marked sensitive, so it stays out of the logs. A device-code
flow with a refresh token in the key store is not built in; a script that
prints a token covers the same ground.

## Machine-readable output

`--json` writes the outcome to **stdout** as JSON while the human-readable
lines stay on stderr, so a script reads one and a person the other:

```
$ mpt --json cp report.pdf sftp://srv/in/ ftp://old/in/ 2>/dev/null | jq '.targets[] | select(.ok | not)'
{
  "target": "ftp://old/in/",
  "bytes": 0,
  "elapsed_ms": 5,
  "attempts": 1,
  "ok": false,
  "error": "authentication failed: wrong password",
  "cancelled": false,
  "sidecar": null,
  "signature": null
}
```

The object has `source`, `bytes_read`, `elapsed_ms`, `ok` (every target
succeeded and `--check` agreed), `targets`, `digests` (algorithm → hex) and
`check` (`algo`, `ok`, `expected`, `actual`, `signer`). `mpt --json ls <url>`
prints the listing the same way, with `modified` in RFC 3339.

## While it runs

On a terminal a copy shows one line that redraws itself:

```
26.9 MiB / 38.1 MiB ( 70%)  107.4 MiB/s
```

It appears only where someone is watching — a terminal on stderr, and not
with `--json` — and the percentage only when the source could say how large it
is. `--progress always|never` decides instead of guessing; with `always` and no
terminal each reading gets its own line, so it can go into a log.

`mpt completions <shell>` prints a completion script (bash, zsh, fish, elvish,
powershell) and `mpt man` the manual page:

```
mpt completions zsh > ~/.zfunc/_mpt
mpt man > /usr/local/share/man/man1/mpt.1
```

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

### Resuming

`--resume` continues where an interrupted transfer stopped: whatever
`<name>.mpt-part` already holds on the target stays, and only the rest is
sent.

```
mpt cp --resume big.iso sftp://srv/in/
```

```
INFO resuming part=big.iso.mpt-part offset=50839552
big.iso -> sftp://srv/in/: 69160448 bytes in 526.28ms
```

The source is still read from the beginning — a checksum has to cover the whole
file — but only the missing bytes travel, which is what a slow line cares
about. The `--resume` flag also decides what happens to the partial file when a
transfer is interrupted: with it, what arrived is kept to be continued;
without it, the leftovers are cleaned up as before.

| Protocol | Resumable | How |
|---|---|---|
| file, sftp, ftp/ftps | ✓ | append to the part file (`APPE` for FTP) |
| scp, webdav, http, s3, mail | ✗ | no append; the whole payload is sent |

In a fan-out each target resumes from its own offset — the shared source stream
is read once and every target skips what it already has. A part file that is
not shorter than the payload is not treated as a prefix of it: it is written
again from the top.

### Skipping what is there

`--skip-existing` (`[defaults] skip_existing`) leaves a target alone when it
already holds a file of the source's name and size, and reports it as
`skipped`. It is decided per target, so in a fan-out only the targets that
lack the file receive it, and the source is not read at all when none does.
With `-r` or a pattern this makes a repeated run send only what is new,
which is what a cron job over an inbox wants; it is a size comparison, not a
checksum, so a changed file of the same length is not noticed. Targets
without a size to ask for (mail, an HTTP server without HEAD) are never
skipped.

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

## Windows

The code is written to build and run on Windows, with three differences that
are worth knowing:

* **ssh-agent**: `$SSH_AUTH_SOCK` is read as a named-pipe path (Git for Windows
  sets it that way); without it the OpenSSH agent service
  (`\\.\pipe\openssh-ssh-agent`) is tried, then PuTTY's Pageant.
* **Credential commands**: `{ cmd = … }` runs through `cmd /C` instead of
  `sh -c`.
* **File permissions**: there are no mode bits to check, so a key, password or
  configuration file that holds secrets is judged by its place instead — a
  warning if it lies outside the user's profile directory.

Paths with a drive letter (`C:\data\x.bin`) and UNC paths are recognized as
local files, and `\` counts as a path separator, so sidecar and `.mpt-part`
files land next to their file rather than in the working directory.

Building needs no NASM: rustls 0.23 turns on `aws-lc-rs/prebuilt-nasm` itself,
so `cargo build` works with the MSVC toolchain alone.

**Not verified.** None of this is built here — this machine has no Windows
target, and the crypto crates cannot be cross-compiled to one from macOS. The
Windows job of the CI workflow is what will prove it. The test servers under
`tests/local/` are Unix shell scripts; the unit tests (`cargo test --lib`) run
without them.

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
(default: all). `server` adds `mpt::server`: `serve()` runs the API on its
own, `router()` hands the routes to an axum application of your own.

## Testing

Unit tests: `cargo test` (`cargo test --features server` adds the server's,
including `tests/server.rs`, which starts the binary and moves local files
over HTTP and WebSocket).

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
