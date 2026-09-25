# Running a relay

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
else: no shell, no pty, no port forwarding, no sftp. The one channel it opens
back to the client is the agent channel, and only when the client forwards an
agent and `--no-agent-forwarding` is not set. `authorized_keys` is in OpenSSH
format and is re-read whenever its content changes, so adding a client needs
no restart. A file that is removed or cannot be read lets nobody in until it
is back.

Of the per-key options, the relay honours these:

| Option | Effect |
|---|---|
| `from="pattern-list"` | the key is taken only from a matching client address: `*` and `?` wildcards, `address/length` networks, `!` to exclude. Matched against the address, never a host name, as `sshd` does with `UseDNS no` |
| `expiry-time="YYYYMMDD[HHMM[SS]]"` | the key is refused after that time, read as UTC |
| `no-agent-forwarding`, `restrict` | the client's agent is refused for this key; `agent-forwarding` after `restrict` allows it again |
| `no-pty`, `no-port-forwarding`, `no-X11-forwarding`, `no-user-rc` and their positive forms | taken as they are: the server offers none of these to anyone |

A key with any other option — `command=`, `permitopen=`, `cert-authority`,
`principals=`, … — is left out, with a warning in the log naming the line,
because the relay would not keep the limit it sets. The line for an existing
`sshd` below is such a line; it belongs in that account's file, not in the
relay server's.

| Flag | `[relay]` key | Default | Meaning |
|---|---|---|---|
| `--listen [ADDR]` | – | `0.0.0.0:2222` | listen here instead of reading one upload from stdin |
| `--host-key <PATH>` | `host_key` | `~/.local/state/mpt/relay_host_key` | the host key; generated when missing |
| `--authorized-keys <PATH>` | `authorized_keys` | `~/.config/mpt/authorized_keys` | who may relay |
| `--parallel <N>` | `parallel` | `4` | relays running concurrently; further sessions wait |
| `--max-size <SIZE>` | `max_size` | `0` (no limit) | refuse larger uploads, and larger sources the relay reads; a source that does not state its size fails once it passes the limit |
| `--grace <SECONDS>` | `grace` | `30` | how long a shutdown waits for running relays |
| `--credentials <MODE>` | `credentials` | `header` | how clients may send the targets' passwords: `header`, `on-demand` or `any` |
| `--no-agent-forwarding` | `agent_forwarding` | `true` | take the ssh-agent a client forwards; the flag refuses it |
| `--allow-delete` | `allow_delete` | `false` | let a client have the source deleted that the relay read for it; see [Deleting a source the relay read](relay-topologies.md#deleting-a-source-the-relay-read) |
| `--port-file <PATH>` | – | – | write the port actually bound, for `--listen 127.0.0.1:0` |

The flags of the process apply to every relay it runs, as they do for the
server: a relay started with `--timeout 120 --cache` delivers every upload
that way unless the client's header says otherwise, and `[defaults]` and
`[policy]` of the relay's configuration are in force. Ctrl-C or `SIGTERM`
stops accepting sessions, waits `--grace` for the running relays and then
cancels them.

### Through an existing sshd

Without a server of its own, a relay is an account on an ordinary `sshd`
with `mpt` in its `PATH`: the client runs `mpt relay` there, and the protocol
on the channel is the same. Keep the key from doing anything else, but let
the agent through:

```
command="mpt relay",restrict,agent-forwarding ssh-ed25519 AAAAC3Nz… laptop
```

in that account's `~/.ssh/authorized_keys` (`sshd` also needs
`AllowAgentForwarding yes`, which is its default). Leave `,agent-forwarding`
out and the clients need `--no-via-agent`, with a key on the relay or a
password for every SSH target. The relay reads that account's configuration,
so `[ssh]` keys placed there serve targets whose key does not come from the
client.

### Trust

Whoever is in `authorized_keys` can make the relay write wherever the URLs
say, with whatever credentials they carry: trust it like a shell account on
the relay. Those credentials go over SSH to a host whose key the client
verified, and the relay's log names sizes and outcomes at `-v`, not hosts or
paths.

The relay's own password settings — `--password`, `--password-file`,
`--password-stdin`, `MPT_PASSWORD` and `MPT_SMTP_PASSWORD` — are not applied
to a URL a client names, since they would go to whichever host that is. They
apply to the relay's own [profiles](../configuration/profiles.md), an
`mpt://<name>/` URL in a header, as they do for `cp`, and so do each
profile's password and credential references. What is tied to a host stays
with it: `[http] token` goes only to its hosts and `[mail] password` only to
its server. In an on-demand session no endpoint may bring a password along,
not even from a profile of the relay's; such a header is refused.

With `--via-credentials on-demand` and the forwarded agent, what the relay
holds is one password for the length of one login and no key at all; while
the session runs it can have SSH logins signed with the client's keys, and
nothing else ([the forwarded agent](relay.md#keys-stay-here-the-forwarded-agent)). A relay
that is compromised while nothing is running on it has nothing of yours; one
that is compromised *during* a transfer still sees the file and the passwords
that transfer uses.

## The protocol on the channel

The exchange is small enough for other clients. The client writes one JSON
header line and then the file in frames, control messages in between; the
relay writes JSON lines back and exits the way `cp` would. [Relay
protocol](../reference/relay-protocol.md) has the shapes.

`mpt relay` without `--listen` speaks it on standard input and output, which
is how it runs under an ordinary `sshd` and how it can be tried without one.
Version 1 — the header, then exactly `size` raw bytes, no questions — is
still accepted and is the easiest way to see it work:

```
$ printf '{"v": 1, "name": "piped.txt", "size": 6, "dst": ["/srv/in/"]}\nhello\n' | mpt relay
{"progress":{"read":6,"total":6}}
{"report":{"bytes_read":6,"ok":true,"source":"piped.txt","targets":[…]}}
```

A header without `"v"` means version 2, so a client that relies on the raw
form has to say `"v": 1`.
