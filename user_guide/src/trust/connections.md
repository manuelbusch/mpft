# Securing the connection

Checksums and signatures say something about a file. This page is about the
step before that: making sure the machine on the other end is the machine you
meant, and that what you send it, credentials in particular, cannot be read
on the way.

## SSH host keys

`sftp://` and `scp://` check the server's host key against `~/.ssh/known_hosts`
before anything is transferred. The default is **strict**: an unknown host, a
changed key, or a `known_hosts` file that cannot be read all abort the
connection.

```
$ mpt ls sftp://srv.example.com/incoming/
error: authentication failed: host key of srv.example.com:22 is not in known_hosts:
       SHA256:GFb3ByRBzc3YOA2B7PCZeSWXCPpf4DIlKm/UrNkKGhY. Verify it, then add it with
       `ssh-keyscan -p 22 srv.example.com >> ~/.ssh/known_hosts`, or connect with
       ?hostkey=SHA256:GFb3ByRBzc3YOA2B7PCZeSWXCPpf4DIlKm/UrNkKGhY or ?known_hosts=accept-new
```

An unreadable file counts as a failure rather than as "no restrictions". The
alternative would accept any key at the moment the trust store went missing.

| Policy | Meaning |
|---|---|
| `?known_hosts=strict` (default) | only keys already in `known_hosts` are accepted |
| `?known_hosts=accept-new` | trust on first use: a new key is recorded and reported; a *changed* key is still refused |
| `?known_hosts=off` | no verification at all — throwaway test servers only |
| `?hostkey=SHA256:…` | pin this key; `known_hosts` is not consulted |

The default for the whole machine is `[policy] known_hosts`, and
`$MPT_SSH_KNOWN_HOSTS` sets it for one run. A different file can be named with
`[ssh] known_hosts_file`.

### First contact

If you can check the fingerprint, from the machine's console, from whoever
runs it or from the ticket that announced it, record it:

```
ssh-keyscan srv.example.com >> ~/.ssh/known_hosts
```

If you cannot, and the network between you is one you are willing to trust
once, `accept-new` does what `ssh` does on first connection:

```
$ mpt cp report.pdf "sftp://srv.example.com/in/?known_hosts=accept-new"
WARN mpt::protocols::ssh: adding new host key for srv.example.com:22 to known_hosts:
     SHA256:GFb3ByRBzc3YOA2B7PCZeSWXCPpf4DIlKm/UrNkKGhY
```

It is announced on stderr rather than only in a debug log, because it is the
one moment where trust is established without being verified.

### When a key changes

```
error: authentication failed: HOST KEY CHANGED for srv.example.com:22: the server offers
       SHA256:GFb3ByRBzc3YOA2B7PCZeSWXCPpf4DIlKm/UrNkKGhY, but known_hosts line 1 holds a
       different key — refusing to connect
```

`accept-new` does not help here. A changed key means the machine was rebuilt,
or someone is between you and it, and the two look identical from the client.
Find out which before editing the line the message names.

### Pinning, for scripts and CI

A build agent usually has no maintained `known_hosts` file, and creating one
at the start of every pipeline tends to end in `accept-new` or `off`. Pin the
key in the URL instead:

```
mpt cp report.pdf "sftp://deploy@srv.example.com/in/?hostkey=SHA256:GFb3ByRBzc3YOA2B7PCZeSWXCPpf4DIlKm/UrNkKGhY"
```

```
error: authentication failed: host key of srv.example.com:22 is
       SHA256:GFb3ByRBzc3YOA2B7PCZeSWXCPpf4DIlKm/UrNkKGhY, but hostkey= pins
       SHA256:AAAABBBBCCCC…
```

The option may be repeated, or given as a list in a
[profile](../configuration/profiles.md). During a key rotation both keys are
then acceptable while the change is rolled out:

```toml
[profiles.prod]
url     = "sftp://deploy@srv.example.com/data/"
hostkey = ["SHA256:GFb3ByRBzc3YOA2B7PCZeSWXCPpf4DIlKm/UrNkKGhY", "SHA256:2mGf4C1Pq0Xk…"]
```

A `+` in a fingerprint may be written as `%2B` or left as it is.

## TLS certificates

`ftps://`, `https://`, `webdavs://`, `s3://` and SMTP with TLS verify the
server's certificate against the system trust store. A certificate that does
not check out ends the connection:

```
$ mpt ls ftps://ftp.example.com/
error: ftp: Secure error: invalid peer certificate: “ftp.example.com” certificate is not trusted
```

For an internal server with a self-signed certificate there are three answers,
in order of preference: install the internal CA in the system trust store; use
a certificate from a CA that is already there; or, as a last resort, switch
verification off for that one endpoint:

```
mpt cp report.pdf "ftps://upload@ftp.internal/in/?insecure=true"
```

`?insecure=true` [belongs to one
URL](../getting-started/addressing.md#options-belong-to-one-endpoint), so in a
fan-out the other targets are still checked. The global `--insecure` is
**deprecated** for that reason: it lowers the bar for every endpoint of the
run, and it warns when used.

`insecure=true` switches off the hostname check as well as the CA chain, and
the hostname check is what distinguishes the right server from any server
with a certificate.
[`[policy] refuse_insecure_tls`](../configuration/policies.md#refusing-to-skip-certificate-checks)
takes the option away entirely.

## Credentials in the clear

Four combinations hand a credential to anyone on the path: `ftp://` with a
password, `http://` or `webdav://` with basic authentication, `http://` or
`webdav://` with a bearer token in the URL (`?token=`) or a header named
like a credential (`header=Authorization:…`, `Cookie`, `X-Api-Key`), and SMTP
with `tls=none`. A password counts whether the URL carries it or it is asked
for at login, as a [relay asks](../server/relay.md) on demand. Each produces
one warning per run:

```
WARN mpt::policy: ftp://ftp.example.com: FTP without TLS sends the password unencrypted.
     Prefer the TLS variant of this scheme
```

Usually the fix is the TLS variant of the scheme (`ftps://`, `https://`,
`webdavs://`), since the same server tends to offer both. Where that is not
available, the policy turns the warning into a refusal so that the decision
is made explicitly:

```
$ mpt --refuse-plaintext-auth ls "ftp://user:secret@ftp.example.com/"
error: authentication failed: ftp://ftp.example.com: FTP without TLS sends the password
       unencrypted (refused by policy; switch to the TLS variant of the scheme, or drop
       --refuse-plaintext-auth / MPT_REFUSE_PLAINTEXT_AUTH)
```

`[policy] refuse_plaintext_auth = true` makes that permanent, and
`MPT_REFUSE_PLAINTEXT_AUTH=1` sets it for one run. Anonymous FTP is unaffected;
there is no password to lose.

## Passwords in the process list

A password in a URL is visible in `ps` and in the shell history, so it gets a
warning of its own. [Credentials and secrets](../configuration/credentials.md)
covers the alternatives and how passwords are [handled in
memory](../configuration/credentials.md#in-memory); every log line and error
that quotes a URL shows the password as `***`, as the policy message above
does.

## What is checked, and when

Everything that can be decided without exchanging data is decided first:
credentials in the clear before connecting, certificates and host keys during
the handshake, a signature before any data is copied, the checksum while it
streams. The [Security overview](../security/overview.md#what-is-verified-and-when)
has the table, with the relay's and the server's checks beside these.
