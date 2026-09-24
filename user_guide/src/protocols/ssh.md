# SFTP and SCP

Two ways over one SSH connection. Both authenticate the same way, check the
host key the same way, and take the same options. They differ in what they can
do once connected. A third scheme, `ssh://`, names an SSH host without
holding files: it is the relay behind [`--via`](../server/relay.md), and
everything on this page about authentication and host keys applies to it.

```
mpt cp report.pdf sftp://deploy@srv.example.com/var/spool/incoming/
mpt ls sftp://deploy@srv.example.com/var/spool/incoming/
mpt cp sftp://deploy@srv.example.com/var/log/app.log ./
```

## SFTP versus SCP

| | `sftp://` | `scp://` |
|---|---|---|
| list a directory (`mpt ls`, patterns, `-r` as source) | ✓ | – |
| report the size of a source | ✓ | – |
| resume an interrupted upload | ✓ | – |
| atomic finishing | ✓ | ✓ (via `mv` on the same connection) |
| directory creation as a tree target | ✓ | ✓ (via `mkdir -p`) |

SFTP is a subsystem of the same SSH server, so if `sftp://` fails where
`scp://` works, the server has the subsystem switched off. That is the one
situation where SCP is the right choice.

### SCP and the source size

The SCP protocol announces the length of a file before sending it. An
`scp://` source says its size the same way: `mpt` reads it from the header of
an `scp -f` it then abandons, one extra login, as asking an SFTP server for the
size costs one. When the source cannot say how large it is (an HTTP server
that answers `HEAD` without a `Content-Length`, or refuses it), the payload has
to be spooled first:

```
WARN scp: source size unknown, spooling to a temporary file
     (use the memory cache to avoid disk I/O)
```

That is a temporary file on the local disk. `--cache` keeps it in memory
instead, at the cost of holding the whole payload. In a fan-out, an SCP target
also pauses the stream at the start while it connects and sends its header;
that is [head-of-line blocking](../guide/fan-out.md#slow-targets-stalled-targets),
not a hang.

## Paths

SSH paths are absolute on the server. To address something relative to the
login directory, use `/~/`:

```
mpt cp report.pdf sftp://deploy@srv.example.com/~/incoming/
```

The user comes from the URL, then `$MPT_SSH_USER`, then `[ssh] user`, then the
local user name.

## Authentication

The order is not simply a list of fallbacks:

1. **The key you named** with `?key=`, `[ssh] key`, or `$MPT_SSH_KEY`. If a
   key is named, the agent and the default keys are **not** tried: naming a
   key means using that key.
2. **The ssh-agent**, if `$SSH_AUTH_SOCK` points at one and no key was named.
3. **`~/.ssh/id_ed25519`, `id_ecdsa`, `id_rsa`**, in that order, again only if
   no key was named.
4. **A password**, if there is one, whatever happened above.

```
$ mpt ls sftp://deploy@srv.example.com/in/
error: authentication failed: no accepted method for deploy@srv.example.com
       (tried: ssh-agent, key /home/me/.ssh/id_ed25519)
```

The message lists what was actually attempted, which is usually enough to see
what went wrong.

| Option | Configuration | Meaning |
|---|---|---|
| `?key=<file>` | `[ssh] key` | private key file |
| `?passphrase=` | `[ssh] passphrase` | passphrase for it (prefer the configuration, which takes a [credential reference](../configuration/credentials.md)) |
| `?cert=<file>` | `[ssh] cert` | OpenSSH certificate for the key |
| `?known_hosts=` | `[policy] known_hosts` | `strict`, `accept-new` or `off` |
| `?hostkey=SHA256:…` | `[ssh] hostkey` | pin the host key; repeatable |

Encrypted keys take their passphrase from the option, the configuration, or
`$MPT_SSH_KEY_PASSPHRASE`. The key types that work are **Ed25519**, **ECDSA**
on P-256 and P-384, and **RSA**, which is offered with the SHA-2 signature
algorithm the server asks for. Keys in OpenSSH's own format, which is what
`ssh-keygen` writes by default, are read directly; PuTTY's `.ppk` has to be
converted first.

### Certificates

Short-lived OpenSSH certificates from Vault, Teleport or step-ca work, which
lets a CA vouch for a key that `authorized_keys` never lists. An agent holding
a certificate needs nothing extra. A key in a file takes `?cert=`, or nothing
at all, since `<key>-cert.pub` next to the key is found the way OpenSSH finds
it:

```
mpt cp report.pdf "sftp://deploy@srv/in/?key=~/.ssh/id_ed25519"          # uses id_ed25519-cert.pub
mpt cp report.pdf "sftp://deploy@srv/in/?key=/tmp/k&cert=/tmp/k-cert.pub"
```

If the server refuses the certificate, the bare key still gets its turn.

### Authentication through a relay

A target written by a [relay](../server/relay.md) is logged into from there,
so the order is the relay's: the key its own configuration names, then the
**agent the client forwarded**, then the relay's own agent and default keys,
then a password. The client takes `?key=`, `?cert=` and `?passphrase=` out of
the URL before it sends it — the file stays here — and answers the relay's
signature requests from the agent it runs for that session. A certificate is
offered as a certificate there too, so a CA-signed login works through a relay
exactly as it does from here.

## Host keys

The host key is checked before authentication, strictly by default: an unknown
host, a changed key or an unreadable `known_hosts` aborts the connection.
[Securing the connection](../trust/connections.md#ssh-host-keys) covers first
contact, `accept-new`, pinning with `?hostkey=` for CI, and what a changed key
means.

## Running many jobs against one server

Each job opens its own SSH connection, so
[`--parallel`](../guide/many-files.md#parallelism) is also the number of
simultaneous logins, and `sshd`'s `MaxStartups` caps it. Single digits are
the useful range, and `?connect_retries=1` absorbs the occasional refusal.
