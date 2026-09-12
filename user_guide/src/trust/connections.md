# Securing the connection

Checksums and signatures say something about a file. This page is about the
step before that: making sure the machine on the other end is the machine you
meant, and that what you send it — credentials in particular — cannot be read
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

An unreadable file counts as a failure rather than as "no restrictions", which
is the failure mode that matters: the alternative would accept any key at the
moment your trust store went missing.

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

If you can check the fingerprint — from the machine's console, from whoever
runs it, from the ticket that announced it — record it and be done:

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

`accept-new` does not help here, and that is deliberate. A changed key means
the machine was rebuilt, or someone is between you and it, and the two look
identical from where you stand. Find out which before editing the line the
message names.

### Pinning, for scripts and CI

A build agent has no `known_hosts` file worth maintaining, and creating one at
the start of every pipeline is how "just accept it" ends up in a script. Pin
the key in the URL instead:

```
mpt cp report.pdf "sftp://deploy@srv.example.com/in/?hostkey=SHA256:GFb3ByRBzc3YOA2B7PCZeSWXCPpf4DIlKm/UrNkKGhY"
```

```
error: authentication failed: host key of srv.example.com:22 is
       SHA256:GFb3ByRBzc3YOA2B7PCZeSWXCPpf4DIlKm/UrNkKGhY, but hostkey= pins
       SHA256:AAAABBBBCCCC…
```

The option may be repeated, or given as a list where the configuration names
that server — a [profile](../configuration/profiles.md) — which is what a key
rotation needs:
both keys are acceptable while the change is rolled out.

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

`?insecure=true` belongs to one URL. That matters in a fan-out, where the
alternative would be to lower the bar for every target at once:

```
mpt cp report.pdf "ftps://old.internal/in/?insecure=true" ftps://partner.example.com/in/
```

The old server is trusted blindly; the partner is still checked properly.

There is also a global `--insecure`, which is **deprecated** for exactly this
reason: it applies to every endpoint of the run, including the ones you were
not thinking about when you added it. It warns when used.

Remember what it switches off: not just the CA chain but the hostname check
too, which is the part that distinguishes the right server from any server with
a certificate. Where that trade is not yours to make,
[`[policy] refuse_insecure_tls`](../configuration/policies.md#refusing-to-skip-certificate-checks)
takes the option away entirely.

## Credentials in the clear

Three combinations hand a password to anyone on the path: `ftp://` with a
password, `http://` or `webdav://` with basic authentication, and SMTP with
`tls=none`. Each produces one warning per run:

```
WARN mpt::policy: ftp://ftp.example.com: FTP without TLS sends the password unencrypted.
     Prefer the TLS variant of this scheme
```

Usually the fix is one character — `ftps://`, `https://`, `webdavs://` — since
the same server tends to offer both. Where it is not, decide deliberately
rather than by not noticing, and let the policy hold you to it:

```
$ mpt --refuse-plaintext-auth ls "ftp://user:secret@ftp.example.com/"
error: authentication failed: ftp://ftp.example.com: FTP without TLS sends the password
       unencrypted (refused by policy; switch to the TLS variant of the scheme, or drop
       --refuse-plaintext-auth / MPT_REFUSE_PLAINTEXT_AUTH)
```

`[policy] refuse_plaintext_auth = true` makes that permanent, and
`MPT_REFUSE_PLAINTEXT_AUTH=1` sets it for one run. Anonymous FTP is unaffected;
there is no password to lose.

## Passwords where other people can read them

A password in a URL is visible in `ps` to every user on the machine and stays
in the shell history, so it gets [a warning of its
own](../configuration/credentials.md) — and that page covers the alternatives,
from `--password-stdin` for one run to a credential reference that is resolved
when the endpoint is used.

Inside the process, passwords and passphrases are held in a type that redacts
itself in debug output and overwrites its memory when dropped. Every log line
and every error that mentions a URL shows the password as `***` — including the
policy message above, which quotes the URL it is refusing.

## What is checked, and when

| Check | When |
|---|---|
| plaintext credentials, password in the URL | before connecting |
| TLS certificate | during the handshake |
| SSH host key | during the handshake, before authentication |
| signature on the source's checksum file | before any data is copied |
| checksum | while the data streams |

The order is deliberate: everything that can be decided without exchanging
data is decided first, and the cheapest way to fail is the earliest one.

## Next

That is trust. [The configuration file](../configuration/file.md) is about not
having to type any of it — or any of the rest — twice.
