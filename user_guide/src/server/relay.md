# Relaying through a fast host with `cp --via`

`mpt cp` reads a source once but sends it once per target. On a thin uplink,
a home office or a mobile connection, three targets are three uploads. `mpt
relay` puts the fan-out where the bandwidth is: a machine that takes the file
**once**, over SSH, and delivers it to the targets itself while the data is
still arriving.

```
mpt cp --via ssh://relay@fast.example.com:2222 report.pdf mpt://prod/ mpt://archive/
```

A relay is `cp` with its standard input as the source. Nothing is spooled on
the relay (with one exception for [chained
targets](relay-topologies.md#a-target-behind-another-relay)), and everything
`cp` does applies unchanged: checksums, atomic
finishing, the memory cache with retries, timeouts, the report. The relay
knows no targets of its own. The client names them, and the relay only
delivers — with the passwords it is given, or by asking for each one as it
logs in and keeping none.

The relay is in the default build (feature `relay`, which needs `ssh`).

## On the client

`--via` takes an `ssh://` URL, or a [profile](../configuration/profiles.md)
whose `url` is one. The key, the agent, `known_hosts` and `?hostkey=` work as
they do for [`sftp://`](../protocols/ssh.md#authentication); the relay's host
key is checked like any other. The output is that of a batch, because a relay
run is one:

```
$ mpt cp --via mpt://relay --hash sha256 report.pdf mpt://prod/ mpt://archive/
[1/1] ok             40000 bytes     7.00ms  sftp://deploy@srv.example.com/data/incoming/
[1/1]         + sftp://deploy@srv.example.com/data/incoming/report.pdf.sha256
[1/1] ok             40000 bytes     7.00ms  s3://archive-bucket/reports/
[1/1]         + s3://archive-bucket/reports/report.pdf.sha256
[1/1] report.pdf: 40000 bytes read, 2/2 targets ok in 39.73ms
[1/1] sha256  e07113054489e8074ce8256f9c1a3aa076b57c3d76b3e7d367abc20d976e27dc
1/1 jobs ok in 41.78ms
```

`--via` is a [job flag](../reference/cli.md#job-flags): `cp -t`, `batch`,
`batch - --follow` and a `cp` with a pattern or `-r` send every file of the
list through the relay, one SSH session per file, `--parallel` of them at
once, with `--fail-fast` and the batch's summary as usual. Patterns and trees
are expanded on the client, where the source is.

The report comes back and is printed as `cp` prints its own; `--json` gives
the [same object](../automation/scripting.md#the-json-report) per job, and the
exit code is what `cp` would have given. A target the relay could not write
is reported against the job, prefixed with `relay:`:

```
[1/1] FAILED copy report.pdf -> sftp://deploy@srv.example.com/data/incoming/: relay: I/O error: File exists (os error 17)
```

### What travels with the job

The targets are resolved on the client: profiles, [credential
references](../configuration/credentials.md), `--password`. The relay needs
nothing but a line in its `authorized_keys` per client. The flags `--hash`,
`--timeout`, `--cache` with `--retries`, `--skip-existing` and `--no-atomic`
go along, as do the `?options` of the targets.

Three flags need what only this side has and are refused with a relay:

```
error: --check is not available with a relay: it needs what only this side has
       (the checksum file, the source, the key)
```

`--check`, `--sign` and `--resume` are those three. `--delete-source` is
allowed in one case — when the relay reads the source itself, writes every
target of the job and was started to allow it; see [Deleting a source the
relay read](relay-topologies.md#deleting-a-source-the-relay-read).

### Passwords: in the header, or asked for at every login

By default a target's password travels with its URL and the relay holds it
while it delivers. That is one upload's worth of trust in the relay host. The
other way is to send the URLs without passwords and let the relay ask:

```
mpt cp --via mpt://relay --via-credentials on-demand report.pdf ftp://upload@partner.example/in/
```

The relay then asks this side at every single login and drops the answer as
soon as that login is done. Nothing of it stays in its memory between
connects, and nothing of it reaches its log:

```
# on the relay, with -vv
DEBUG mpt::relay::broker: asking the client for the password target=ftp://upload@partner.example/in/report.pdf.mpt-part attempt=1
DEBUG mpt::relay::broker: asking the client for the password target=ftp://upload@partner.example/in/ attempt=1

# on the client, with -vv
DEBUG mpt::relay::broker: password asked for by the relay target=ftp://upload:***@partner.example/in/ attempt=1
```

Two questions for one file is normal: every protocol logs in more than once
per transfer — FTP the most, because it reconnects for nearly every operation.
The answers ride on the session that is already open, in a lane of their own,
so they never queue up behind the payload.

Both sides have to agree. The relay is started with `--credentials
header` (the default), `on-demand` or `any`, and a mismatch is refused before
anything is sent, in terms of both settings:

```
invalid option 'credentials': the client asks for on-demand passwords, but this relay is set to credentials = "header"; start the relay with --credentials on-demand or any
invalid option 'credentials': this relay takes passwords on demand only, but the client sends them in the header; run cp with --via-credentials on-demand
```

An **S3 key** cannot be asked for this way: the store signs every request
itself and binds its key when it is built. Such a target is refused with
`--via-credentials on-demand`, and has to go in the header or use a
credential chain on the relay itself.

### Keys stay here: the forwarded agent

For SSH targets the client forwards its ssh-agent, so the key never leaves
this machine. `?key=`, `?cert=` and `?passphrase=` are taken out of the URL
before it is sent, and the relay signs through the agent:

```
$ mpt cp --via mpt://relay report.pdf "sftp://deploy@srv.example.com/data/?key=~/.ssh/prod_ed25519"
[1/1] report.pdf -> sftp://deploy@srv.example.com/data/: 40000 bytes in 93.64ms

# in the relay's log
INFO mpt::protocols::ssh: ssh: authenticated via the forwarded ssh-agent
```

The agent this side runs for the relay holds the keys those targets name —
`?key=` with its `?cert=`, `[ssh] key`, `MPT_SSH_KEY`, and otherwise
`~/.ssh/id_ed25519`, `id_ecdsa`, `id_rsa` — and passes every other request on
to your own `SSH_AUTH_SOCK`, so a key that only your own agent holds works
too. A **certificate** is offered as a certificate, so a CA-signed login works
through a relay exactly as it does from here. The agent answers signature
requests and nothing else: it never adds, removes or locks a key, whatever
the relay asks.

`--no-via-agent` switches the forwarding off. A target whose key file is on
this machine is then refused, because nothing can stand in for it:

```
invalid option 'key': sftp://deploy@srv.example.com/data/?key=~/.ssh/prod_ed25519: names a file on this machine, which the relay cannot read; let the relay use the forwarded agent (without --no-via-agent), give the target a password, or put the key on the relay
```

A relay may refuse to take an agent (`--no-agent-forwarding`); the targets
then fall back to the relay's own keys and passwords, and a target that has
neither fails with an authentication error.

### The connection is the transfer

The client stays connected until the relay is done: the upload *is* the
transfer, and the progress line counts it. (When the relay [reads the source
itself](relay-topologies.md#letting-the-relay-read-the-source) nothing is uploaded, but the
session still has to stay open: it is what carries the progress, the questions
and the report.) If the connection drops, the relay's source ends early or is
cancelled, every target fails and partial files are removed (`--no-atomic`
leaves them). Nothing resumes, because nothing is kept on the
relay. The same happens when this side cannot read the file to the end, or
when the file grows or shrinks while it is sent: the job fails with that
error, and the relay finishes no target with what it got. The slowest target sets the pace, as in any [fan-out](../guide/fan-out.md#slow-targets-stalled-targets);
`--timeout` drops one that stops taking data, and the others finish.

### Making it the rule

`[defaults] via` sends every `cp` and `batch` through the relay; `--no-via`
copies from here for once. A profile may name a relay of its own, which wins
over the default — that is what puts an endpoint permanently behind a relay:

```toml
[defaults]
via             = "mpt://relay"    # or "ssh://relay@fast.example.com:2222"
via_credentials = "on-demand"      # ask at every login instead of sending passwords
via_agent       = true             # forward the ssh-agent (the default)

[profiles.relay]
url = "ssh://relay@fast.example.com:2222"

[profiles.prod]
url = "sftp://deploy@srv.example.com/data/"
via = "mpt://relay"                # this target is always written by the relay
```

`mpt profiles` shows it under the profile:

```
$ mpt profiles
mpt://prod  sftp://deploy@srv.example.com/data/
    via    mpt://relay
```

A [`./mpt.toml`](../configuration/file.md#the-file-in-the-working-directory)
may set none of the three. The relay is where every target's credentials go,
and a file in a directory you happen to be standing in must not choose that:

```
warning mpt.toml: ignoring [defaults] via — a configuration file in the working
directory may not choose the relay that receives the targets' credentials
```

## Beyond the client

Two things the relay can do without the client touching the file are on
their own page, [Relay topologies](relay-topologies.md): reading a source
that sits behind it, and handing a target on to a second relay. [Running a
relay](relay-host.md) is the operator's side — starting the server, the
flags, an existing `sshd`, and what a relay holds and what it does not.
