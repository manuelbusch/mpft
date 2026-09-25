# Security overview

What `mpt` trusts, what it checks, where a secret is at each moment, and what
ends up in a log. Every fact here is explained in full on another page; this
page is the map for a review.

## Trust boundaries

| Party | Sees | Never sees |
|---|---|---|
| **the client** (`mpt cp`, `batch`) | every URL, every resolved credential, the file | — |
| **a relay** (`cp --via`) | the targets, the file as it passes, and either the passwords for the length of the transfer (`header`) or one password for the length of one login (`on-demand`) | a key file; with `on-demand`, a password between logins |
| **a second relay** in a chain | its own target and the file; its questions go back through the first relay | anything about the other targets |
| **the server** (`mpt serve`) | the profiles it is allowed to use, with their credentials, as the server's own user | a password from a client, unless `urls = "any"` is set |
| **a client of the server** | job states, progress and reports, with endpoints named as submitted | what a profile resolves to, why a provider failed |
| **a target** | what its protocol sends: the file, the checksum file, the credentials for that endpoint | anything about the other targets |

Whoever can log in to a relay can make it write wherever a URL says; whoever
holds the server's token can use every allowed profile as the server's user.
Both are to be trusted like a shell account, and both have the switches under
[Hardening](#hardening-checklist) to narrow what that account reaches. See
[Trust](../server/relay-host.md#trust) and [What a client can
reach](../server/serve.md#what-a-client-can-reach).

## What is verified, and when

| Check | When | Page |
|---|---|---|
| plaintext credentials, password in the URL | before connecting | [Credentials in the clear](../trust/connections.md#credentials-in-the-clear) |
| TLS certificate | during the handshake | [TLS certificates](../trust/connections.md#tls-certificates) |
| SSH host key | during the handshake, before authentication | [SSH host keys](../trust/connections.md#ssh-host-keys) |
| relay: credential mode of both sides, passwords in URLs, size | before a byte of the payload is read | [Relay protocol](../reference/relay-protocol.md#the-header) |
| server: token, `Origin` header, allowed profiles, options on a reference | before a job is accepted | [Securing the listener](../server/serve.md#securing-the-listener) |
| signature on the source's checksum file | before any data is copied | [Verifying](../trust/signatures.md#verifying) |
| checksum | while the data streams | [Checksums](../trust/checksums.md) |
| colliding targets in a batch | before the first byte moves | [Colliding targets](../guide/many-files.md#colliding-targets) |

Everything that can be decided without exchanging data is decided first. A
failed check is an error with an [exit code](../reference/exit-codes.md) of
its own — 4 for anything about identity, 3 for anything about integrity — so
a script can tell "wrong password" from "wrong file" without reading the
message.

## Where a secret is, and for how long

| Stage | Where the secret is | How long |
|---|---|---|
| on the command line (`--password`, `user:pw@host`) | the argument list: `ps`, shell history | the process, and beyond it — which is why `mpt` warns |
| `--password-stdin`, `--password-file`, `MPT_PASSWORD` | the process only | the run |
| a [credential reference](../configuration/credentials.md) | not in the file: an environment variable, a file, a command's output, the OS key store, Vault | fetched when the endpoint is used; a command's answer is kept ten minutes by default |
| in memory | a type that redacts itself in debug output and overwrites its memory when dropped | until no endpoint needs it |
| in a log line or an error | masked as `***` | — |
| sent to a relay, `header` mode | the target URL in the header, over SSH to a host whose key was checked | the transfer |
| sent to a relay, `on-demand` mode | one answer per login, over the open session | one login, then dropped |
| a key for an SSH target behind a relay | stays here; the relay signs through the forwarded agent | the session |
| the server's token | `[server] token` as a reference; compared in constant time; a wrong one is answered late | the server's lifetime |
| the server's journal | job descriptions with endpoints as submitted, mode `0600`; a URL under `urls = "any"` keeps its password | until the job is over and the file is [next compacted](../server/serve.md#the-journal-and-restarts) |

[Credentials and secrets](../configuration/credentials.md) covers the first
five rows, [Relaying through a fast host](../server/relay.md) the relay rows,
[Jobs over HTTP](../server/serve.md) the server rows.

## What is logged

- **A password is never logged.** Every URL in a log line, an error or a
  report shows it as `***`. A relay asked on demand logs the target it asked
  about without the password; the client logs that it answered, not what.
- **At the default level** (`warn`) a run is quiet unless something needs a
  decision: a password in the clear, a host key added on first use, a part
  file that could not be removed.
- **`-v`** names sizes, outcomes and — for the server and a relay — job ids,
  but no hosts and no paths. **`-vv`** adds hosts, paths and the protocol
  conversation. The server keeps the reason a profile is misconfigured in its
  own log and tells the client only the profile's name.
- **What the far side sees** is the protocol's business: an SSH server logs
  the login, an FTP server the commands, S3 the request.

[Logging and observability](../automation/logging.md) has the levels and the
line format.

## Data at rest

- A transfer streams. Nothing is written to the local disk between a source
  and its targets, with two exceptions: an SCP target whose source cannot
  say its size spools to a temporary file (unless `--cache` holds it in
  memory), and a mail target assembles the message in memory.
- A target being written holds `<name>.mpt-part` until the transfer is
  complete; a failed transfer removes it, `--resume` keeps it.
- A relay keeps nothing: no spool, no part of a file after the session, no
  password between logins in `on-demand` mode. Its host key is generated
  once under `~/.local/state/mpt/`.
- The server keeps jobs in memory, and in a journal file only when one is
  configured.

## Hardening checklist

For a machine that runs `mpt` unattended, or for anyone else's jobs:

| Setting | Effect | Page |
|---|---|---|
| `[policy] known_hosts = "strict"` | the default; an unknown or changed SSH host key aborts | [The host-key policy](../configuration/policies.md#the-host-key-policy-for-the-machine) |
| `[policy] refuse_plaintext_auth = true` | credentials over `ftp://`, `http://`, SMTP without TLS are refused, not warned about | [Refusing unencrypted credentials](../configuration/policies.md#refusing-unencrypted-credentials) |
| `[policy] refuse_insecure_tls = true` | `?insecure=true` is taken away | [Refusing to skip certificate checks](../configuration/policies.md#refusing-to-skip-certificate-checks) |
| `[policy] require_signature = true` and `max_signature_age` | a check is a signature check, and an old signature is refused | [Requiring signatures](../configuration/policies.md#requiring-signatures) |
| `[policy] strict_permissions = true` | a readable file with credentials is an error | [Strict file permissions](../configuration/policies.md#strict-file-permissions) |
| the configuration where the account cannot rewrite it, named with `--config` | a policy is a control, not a suggestion | [Where to put a policy](../configuration/policies.md#where-to-put-a-policy) |
| `--via-credentials on-demand`, the forwarded agent left on | a relay holds one password per login and no key | [Passwords on demand](../server/relay.md#passwords-in-the-header-or-asked-for-at-every-login) |
| `mpt relay --credentials on-demand` | the relay refuses clients that would send passwords in the header | [Running a relay](../server/relay-host.md) |
| `command="mpt relay",restrict,agent-forwarding` in `authorized_keys` | a relay account under `sshd` can do nothing else | [Through an existing sshd](../server/relay-host.md#through-an-existing-sshd) |
| `[server] urls = "profiles"` (the default) and `profiles = […]` | the API reaches only the named profiles, and no request carries a password | [What a client can reach](../server/serve.md#what-a-client-can-reach) |
| the server behind a reverse proxy with TLS | the token never crosses the network in the clear | [Securing the listener](../server/serve.md#securing-the-listener) |
| `[server] allow_delete` left off | no job may delete its source | [What a job may set](../server/serve.md#what-a-job-may-set) |
| `[relay] allow_delete` left off | no client may have a relay delete the source it read | [Deleting a source the relay read](../server/relay-topologies.md#deleting-a-source-the-relay-read) |

A [`./mpt.toml`](../configuration/file.md#the-file-in-the-working-directory)
in the working directory cannot loosen any of this: it contributes only
`[defaults]` and `[policy]`, never a profile, a credential command or a relay.

## Reporting a vulnerability

A problem with a security consequence does not go to a public tracker; see
[Licensing and support](../appendix/support.md#reporting-a-problem).
