# Logging and observability

What `mpt` writes about itself, where, at which level, and what an operator
can watch. The result lines a person reads are on [Using mpt in
scripts](scripting.md#stdout-and-stderr); this page is about the log behind
them.

## Where the log goes

Every log line goes to **stderr**, with the result lines and the progress
display, so stdout stays free for `--json`. There is no log file option: a
service manager or a redirection decides where stderr ends up, and under
systemd that is the journal.

```
mpt cp report.pdf sftp://srv/in/ 2>> /var/log/mpt/mpt.log     # keep it
mpt -v cp … 2>&1 | logger -t mpt                                # to syslog
```

## Levels

The level is decided in this order, the first that applies:

1. `$RUST_LOG`, which takes the full `tracing` filter syntax and wins over
   everything, so `-vv` does nothing while it is set;
2. `-v` (info), `-vv` (debug), `-vvv` (trace);
3. `[defaults] log` in the configuration, a level or the same filter syntax;
4. `warn`, the built-in default.

```
RUST_LOG=mpt::protocols::ssh=debug,warn mpt cp …     # one module in detail
```

What each level adds:

| Level | What appears |
|---|---|
| `warn` (default) | only what needs a decision: a password in the clear, a host key added on first use, a part file that could not be removed, a certificate that is not trusted |
| `-v` | one line per operation with sizes and outcomes; for the server and a relay, job ids and logins. **No hosts and no paths** |
| `-vv` | hosts, paths, the protocol conversation, each question a relay asks; the level that resolves most problems |
| `-vvv` | everything, including the libraries underneath |

```
$ mpt -v cp report.pdf out/
2026-09-12T15:19:46.471183Z  INFO mpt::transfer: copy targets=1 size=Some(40000) cache=Stream hash=None check=false
report.pdf -> out/: 40000 bytes in 5.03ms

$ mpt -vv cp report.pdf out/again/
2026-09-12T15:19:46.485268Z  INFO mpt::transfer: copy targets=1 size=Some(40000) cache=Stream hash=None check=false
2026-09-12T15:19:46.485301Z DEBUG mpt::transfer: copy source=report.pdf
2026-09-12T15:19:46.485391Z DEBUG mpt::transfer: uploading to a temporary file loc=out/again/report.pdf.mpt-part
2026-09-12T15:19:46.489033Z DEBUG mpt::transfer: renamed into place part=report.pdf.mpt-part name=report.pdf
report.pdf -> out/again/: 40000 bytes in 3.91ms
```

## The line format

One line per event: a UTC timestamp in RFC 3339, the level, the module that
wrote it (`mpt::transfer`, `mpt::protocols::ssh`, `mpt::relay::sshd`, …), a
colon, the message, and then `key=value` fields. The fields are what a log
search keys on: `job=`, `peer=`, `fingerprint=`, `target=`, `attempt=`. Colour
follows [`--color`](scripting.md#colour) and is off in a pipe.

The format is a rendering of `tracing` events and may gain fields between
versions; the message texts of warnings and errors are the part that is kept
stable. Parse the [JSON report](scripting.md#the-json-report), not the log.

## What is never logged

A password, a token or a passphrase does not reach the log at any level.
Every URL in a log line is written with the password and [secret
options](../configuration/credentials.md#in-memory) as `***`, the
`Authorization` header is marked sensitive, and a relay that asks for a
password on demand logs the target it asked about, not the answer. Pasting a
`-vv` log into a ticket is safe.

## The server and the relay

Both run for a long time and log per session rather than per run:

- **`mpt serve`** logs at `-v` when a job starts (`running` with its id and
  transfer count), when it is over (`over` with its state), when it is
  cancelled, when the journal re-runs one, and when finished jobs age out of
  `retention`. A misconfigured profile or a failing credential provider is
  described here, and only here: the client is told the profile's name.
  `GET /v1/healthz` with the token reports the version, whether the server is
  accepting jobs, and how many are queued and running — the one live figure
  it publishes. See [Jobs over HTTP](../server/serve.md#logging).
- **`mpt relay --listen`** logs its host-key fingerprint at start-up, every
  login with the peer and the key's fingerprint, every session's outcome and
  exit code, and — at `-vv` — every password it asked for. A refused login
  names the fingerprint it refused. See [Running a
  relay](../server/relay-host.md).

Under systemd both write to the journal like any other service, and
`journalctl -u <unit> -p warning` is the alert feed: at the default level
nothing appears that does not need attention.

## What is not there

- **No metrics endpoint.** `healthz` is the whole of it. A run's figures are
  in its [JSON report](scripting.md#the-json-report); a batch's in one
  object per job.
- **No log rotation.** stderr is a stream; `journald`, `logrotate` or the
  container runtime own the file.
- **No audit log of its own.** What moved where is the JSON report, kept by
  whoever ran the job; [Retaining run
  output](scheduling.md#retaining-run-output) shows a pattern.
