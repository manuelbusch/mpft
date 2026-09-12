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
the relay, and everything `cp` does applies unchanged: checksums, atomic
finishing, the memory cache with retries, timeouts, the report. The relay
knows no targets of its own. The client names them, credentials included, and
the relay only delivers.

The relay is in the default build (feature `relay`, which needs `ssh`).

## On the client

`--via` takes an `ssh://` URL, or a [profile](../configuration/profiles.md)
whose `url` is one. The key, the agent, `known_hosts` and `?hostkey=` work as
they do for [`sftp://`](../protocols/ssh.md#authentication); the relay's host
key is checked like any other. The output is that of a batch, because a relay
run is one:

```
$ mpt cp --via mpt://relay --hash sha256 report.pdf mpt://prod/ mpt://archive/
[1/1] ok             40000 bytes     4.00ms  sftp://deploy@srv.example.com/data/incoming/
[1/1]         + sftp://deploy@srv.example.com/data/incoming/report.pdf.sha256
[1/1] ok             40000 bytes     5.00ms  s3://archive-bucket/reports/
[1/1]         + s3://archive-bucket/reports/report.pdf.sha256
[1/1] report.pdf: 40000 bytes read, 2/2 targets ok in 11.00ms
[1/1] sha256  72ce9800d09328daeb679aade0ac2d073b9e668a0d680c3fa44167dc6d0156df
1/1 jobs ok in 17.86ms
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

### What travels, and what cannot

The targets are resolved on the client: profiles, [credential
references](../configuration/credentials.md), `--password`. They travel to
the relay in full over the SSH channel, so the relay needs nothing but a line
in its `authorized_keys` per client. The flags `--hash`, `--timeout`,
`--cache` with `--retries`, `--skip-existing` and `--no-atomic` go along, as
do the `?options` of the targets.

Two things stay on this side. A **key file** of a target cannot travel, so a
target with `?key=`, `?cert=` or `?passphrase=` is refused:

```
[1/1] FAILED report.pdf: invalid option 'key': sftp://someone@nowhere/in/?key=/etc/hostname&timeout=30: names a file on this machine, which the relay cannot read; give the target a password, or put the key on the relay
```

Give such a target a password or a token, or put its key on the relay and
name it there in the relay's `[ssh]` section. And the flags that need the
client's side, `--check`, `--sign`, `--delete-source` and `--resume`, are
refused with `--via`:

```
error: --check is not available with --via: it needs what only this side has (the checksum file, the source, the key)
```

### The connection is the transfer

The client stays connected until the relay is done: the upload *is* the
transfer, and the progress line counts it. If the connection drops, the
relay's source ends early, every target fails and partial files are removed
(`--no-atomic` leaves them). Nothing resumes, because nothing is kept on the
relay. The slowest target sets the pace, as in any [fan-out](../guide/fan-out.md#slow-targets-stalled-targets);
`--timeout` drops one that stops taking data, and the others finish.

### Making it the rule

`[defaults] via` sends every `cp` and `batch` through the relay; `--no-via`
copies from here for once:

```toml
[defaults]
via = "mpt://relay"        # or "ssh://relay@fast.example.com:2222"
```

A [`./mpt.toml`](../configuration/file.md#the-file-in-the-working-directory)
may not set it. The relay is where every target's credentials go, and a file
in a directory you happen to be standing in must not choose that:

```
warning mpt.toml: ignoring [defaults] via — a configuration file in the working directory may not choose the relay that receives the targets' credentials
```

## On the relay host

`mpt relay --listen` is an SSH server of its own. It needs a host key, which
it generates on the first start, and an `authorized_keys` file that says who
may relay:

```
$ mpt relay --listen                          # 0.0.0.0:2222
$ cat laptop.pub >> ~/.config/mpt/authorized_keys
```

The host key's fingerprint is in the log at start-up, so a client can
[pin it](../trust/connections.md#pinning-for-scripts-and-ci) or add it to
`known_hosts` with `ssh-keyscan -p 2222`:

```
INFO mpt::relay::sshd: host key generated path=/home/relay/.local/state/mpt/relay_host_key
INFO mpt::relay::sshd: authorized_keys read keys=1 path=/home/relay/.config/mpt/authorized_keys
INFO mpt::relay::sshd: relay host key fingerprint=SHA256:5X2qOkD53WE80U+4jq5ZaV1SGead0/ZBv3P+YX26m1o …
INFO mpt::relay::sshd: relay listening bound=0.0.0.0:2222 parallel=4
```

The server answers `exec "mpt relay"` and the subsystem `mpt`, and nothing
else: no shell, no pty, no forwarding, no sftp. `authorized_keys` is in
OpenSSH format and is re-read whenever it changes, so adding a client needs
no restart.

| Flag | `[relay]` key | Default | Meaning |
|---|---|---|---|
| `--listen [ADDR]` | – | `0.0.0.0:2222` | listen here instead of reading one upload from stdin |
| `--host-key <PATH>` | `host_key` | `~/.local/state/mpt/relay_host_key` | the host key; generated when missing |
| `--authorized-keys <PATH>` | `authorized_keys` | `~/.config/mpt/authorized_keys` | who may relay |
| `--parallel <N>` | `parallel` | `4` | relays running at once; further sessions wait |
| `--max-size <SIZE>` | `max_size` | `0` (no limit) | refuse larger uploads |
| `--grace <SECONDS>` | `grace` | `30` | how long a shutdown waits for running relays |
| `--port-file <PATH>` | – | – | write the port actually bound, for `--listen 127.0.0.1:0` |

The flags of the process apply to every relay it runs, as they do for the
server: a relay started with `--timeout 120 --cache` delivers every upload
that way unless the client's header says otherwise, and `[defaults]` and
`[policy]` of the relay's configuration are in force. Ctrl-C stops accepting
sessions, waits `--grace` for the running relays and then cancels them.

### Through an existing sshd

Without a server of its own, a relay is an account on an ordinary `sshd`
with `mpt` in its `PATH`: the client runs `mpt relay` there, and the protocol
on the channel is the same. Keep the key from doing anything else:

```
command="mpt relay",restrict ssh-ed25519 AAAAC3Nz… laptop
```

in that account's `~/.ssh/authorized_keys`. The relay reads that account's
configuration, so `[ssh]` keys placed there serve targets whose key file
could not travel from the client.

### Trust

Whoever is in `authorized_keys` can make the relay write wherever the URLs
say, with whatever credentials they carry: trust it like a shell account on
the relay. Those credentials go over SSH to a host whose key the client
verified, and the relay's log names sizes and outcomes at `-v`, not hosts or
paths.

## The protocol on the channel

The exchange is small enough for other clients. The client writes one JSON
header line, then exactly `size` bytes; the relay writes JSON lines back and
exits the way `cp` would. [Relay protocol](../reference/api.md#relay-protocol)
has the shapes. `mpt relay` without `--listen` speaks it on standard input
and output, which is how it runs under an ordinary `sshd` and how it can be
tried without one:

```
$ printf '{"name": "piped.txt", "size": 6, "dst": ["/srv/in/"]}\nhello\n' | mpt relay
{"progress":{"read":6,"total":6}}
{"report":{"bytes_read":6,"ok":true,"source":"piped.txt","targets":[…]}}
```
