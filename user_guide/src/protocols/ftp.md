# FTP and FTPS

FTP is the one protocol here where two options, `passive` and `nat`, decide
whether a transfer works at all through a firewall.

```
mpt cp report.pdf ftps://upload@ftp.partner.example/incoming/
mpt ls "ftps://upload@ftp.partner.example/incoming/?tls=implicit"
mpt cp ftp://anonymous@ftp.example.org/pub/data.csv ./
```

## TLS modes

| Scheme and option | What happens | Default port |
|---|---|---|
| `ftps://` | connect in the clear, then `AUTH TLS` before logging in ("explicit" FTPS) | 21 |
| `ftps://…?tls=implicit` | the connection is TLS from the first byte | 990 |
| `ftp://` | no encryption at all | 21 |

Explicit is the default for `ftps://` because it is what modern servers offer.
Implicit is the older arrangement and is usually announced by the port: if the
server says 990, it means implicit. The port is filled in from the mode, so
`ftps://host/?tls=implicit` needs no `:990`.

`ftp://` with a password [warns](../trust/connections.md#credentials-in-the-clear);
anonymous FTP does not. A certificate that does not check out is handled as
under [TLS certificates](../trust/connections.md#tls-certificates).

## Passive mode and NAT

```
mpt cp report.pdf "ftps://upload@ftp.example.com/in/?passive=false"
mpt cp report.pdf "ftps://upload@ftp.example.com/in/?nat=true"
```

**`passive=true` is the default**, and it is what works from behind a firewall:
the client opens the data connection. `passive=false` asks the server to
connect back, which needs an inbound hole. Try it only when a server insists
on it.

**`nat=true`** helps with the classic misconfiguration where a server behind
NAT announces its internal address for the data connection. With it, `mpt`
ignores the announced address and reuses the one it is already talking to. If
transfers hang after the listing works, this is the first thing to try.

## Capabilities

FTP supports listing, sizes (`SIZE`), renaming (`RNFR`/`RNTO`), appending
(`APPE`) and directory creation (`MKD`), so every column of the [capability
matrix](overview.md#what-each-one-can-do) is ticked.

Renaming onto an existing name is refused by most servers, so `mpt` deletes the
target first and then renames. Atomic finishing therefore behaves the same
here as everywhere else.

Listings are parsed from whatever format the server chose, and servers vary. If
a listing looks wrong, `-vv` shows the raw lines.

## Paths

FTP paths are absolute on the server: `ftp://srv/incoming/` is `/incoming/`,
under the server's root, which for a locked-down account is often the login
directory anyway. To address something relative to the login directory, use
`/~/`, as over SSH:

```
mpt cp report.pdf ftps://deploy@srv.example.com/~/incoming/
mpt ls ftps://deploy@srv.example.com/~/
```

## Timeouts

FTP uses two connections, a control channel and a data channel, and the
[inactivity timeout](../guide/copying.md#time-limits) covers both: every reply
on the control channel and every pause on the data channel. A server that
accepts the command and then never opens the data connection is the failure
mode `--timeout` exists for.
