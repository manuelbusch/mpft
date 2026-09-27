# Troubleshooting

The errors that come up, what they mean, and what to do. Every message below is
what `mpt` actually prints; the exit code is in brackets, since that is what a
script sees.

## Diagnostic commands

| Command | Answers |
|---|---|
| `mpt -v …`, `-vv`, `-vvv` | what it is doing; `-vv` shows the protocol conversation |
| `mpt config check` | which configuration files were read and what they set |
| `mpt schemes` | which protocols this binary was built with |
| `mpt cp --dry-run …` | what a pattern, a tree or a job list expands to |

`-vv` is the one that resolves most mysteries. Passwords are masked in every
log line, so it is safe to paste the output into a ticket.

## Connecting and logging in

**`host key of srv:22 is not in known_hosts: SHA256:…`** [4]

Working as intended: the server is not yet trusted. Verify the fingerprint and
record it with `ssh-keyscan`, or connect once with `?known_hosts=accept-new`,
or pin it with `?hostkey=SHA256:…`. See [Securing the
connection](../trust/connections.md#ssh-host-keys).

**`HOST KEY CHANGED for srv:22 … refusing to connect`** [4]

The server offers a different key from the one in `known_hosts`. Either the
machine was rebuilt or someone is in the middle, and both look the same from
here. Find out which before editing the line the message names.

**`known_hosts=off would check host keys less than policy.known_hosts = "strict" allows`** [2]

`[policy] known_hosts` is the least a URL, a profile or
`MPT_SSH_KNOWN_HOSTS` may ask for. Record the host key instead (above), or
lower the policy where that is the decision; see [The host-key
policy](../configuration/policies.md#the-host-key-policy-for-the-machine).

**`no accepted method for deploy@srv (tried: ssh-agent, key /home/me/.ssh/id_ed25519)`** [4]

The list is what was actually attempted. If the key you meant is not in it, it
was not found — note that naming a key with `?key=` means the agent and the
default keys are **not** tried. See
[Authentication](../protocols/ssh.md#authentication).

**`ftp login failed for 'ftpuser'`** [4]

Wrong credentials, or the account cannot log in at all. `-vv` shows the
server's own reply, which is usually more specific.

**`mailto: requires MPT_SMTP_URL or [mail] smtp in the configuration`** [2]

`mailto:` names recipients but no server. Set `[mail] smtp`, or use an
`smtp://` URL that carries the server itself.

**`password of profile 'q': $PROD_PW is not set`** [4]
**``password of profile 'r': `op read …` failed (exit status: 1)``** [4]

The credential reference could not be resolved. The message names the profile,
so with several in play you know which one. See [Credentials and
secrets](../configuration/credentials.md).

## Certificates and encryption

**`invalid peer certificate: … certificate is not trusted`** [1]

The server's TLS certificate does not check out. Install the internal CA in the
system trust store, or — for one endpoint only — add `?insecure=true`. Note
that this switches off the hostname check too.

**`insecure=true would switch off certificate verification, which policy.refuse_insecure_tls forbids`** [2]

A policy forbids it, which is what the policy is for. If it is your machine,
`[policy] refuse_insecure_tls` is where it is set.

**`FTP without TLS sends the password unencrypted (refused by policy; …)`** [4]

`ftp://` with a password, `http://` with basic auth or SMTP with `tls=none`,
plus `refuse_plaintext_auth`. Usually one character fixes it: `ftps://`,
`https://`, `webdavs://`.

## The transfer itself

**`I/O error: sftp: No such file`** [1]

The remote directory does not exist. Unlike a local target, a remote one is not
created for you. Use `-r`, which creates directories as part of copying a tree,
or create it first.

**`I/O error: Not a directory (os error 20)`** [1]

Something that is not a directory is in the way of a local target path.

**`payload exceeds the configured limit of 268435456 bytes`** [1]

`--cache` was asked to hold more than `--cache-limit`. Raise the limit, or drop
`--cache` and stream. Above the limit `mpt` fails rather than spilling to disk.

**`invalid option 'retries': retries need the memory cache (a stream cannot be replayed)`** [2]

`--retries` retries the *transfer*, which needs the payload again. Add
`--cache`, or rely on connect retries, which work without it.

**`scp: source size unknown, spooling to a temporary file`** (warning)

SCP announces a length before it sends, and the source could not say one. Use
`sftp://` instead, or `--cache` to spool in memory rather than on disk.

**`could not remove the partial file: …`** (warning)

Cleaning up after a failure did not work. When the connection never came up in
the first place there was nothing to remove and the line is noise; when the
transfer failed partway, a `.mpt-part` file may be left on the target.

**A transfer hangs.** The inactivity timeout (30 s) covers connecting, every
stream, and a fan-out target that stops draining. If something still hangs,
`-vv` shows where it stopped. For FTP through NAT, a listing that works
followed by a transfer that hangs is the classic case for `?nat=true`.

## Checksums and signatures

**`no checksum file next to the source (tried report.pdf.b3, report.pdf.sha256, report.pdf.sha512)`** [1]

`--check` needs one of those three next to the source. If the sender used
`--hash`, it is there; otherwise there is nothing to check against.

**`BLAKE3 checksum mismatch: expected 4ee59acf…, got a08daaa9…`** [3]

What arrived is not what the checksum file says. The transferred file is left
in place so you can look at it. Repeat the transfer; if it mismatches again the
source or the checksum file is wrong, not the line.

**`check: report.pdf.sha256 is not a checksum file for report.pdf: it has no entry for 'report.pdf' …`** [1, or 3 when signed]

The checksum file beside the source names other files. It was written for a
file of another name, or renamed; see [Verifying a download with
`--check`](../trust/checksums.md#verifying-a-download-with---check).

**`signature: made by SHA256:…, which is not in allowed_signers`** [3]

The signature is valid but the key is not one you trust. Add it to the trust
file if it should be.

**`signature: SSH signature invalid: signature error`** [3]

The checksum file does not match its signature — it was changed after signing.

**`signature: rejected at 2026-09-10T18:05:31Z: release@example.com: key expired at 2020-01-01T00:00:00Z`** [3]

An `allowed_signers` option (`valid-before`, `valid-after`) excludes the moment
of verification; see [Trust files](../trust/signatures.md#trust-files).

**`signature: the checksum file was signed 9d ago …, longer than the 7d the policy allows`** [3]

`[policy] max_signature_age`. Either the file really is old, or the limit is
too tight for how often it is regenerated.

**`signature: the checksum file claims to be signed at …, in the future`** [3]

The signer's clock, or this machine's, is more than five minutes off; see
[Signing time](../trust/signatures.md#signing-time).

**`policy.require_signature is set, but no trusted keys are given`** [2]

`--check` alone is not enough under that policy. Point `--verify-signers` or
`[verify] allowed_signers` at a trust file.

## Configuration

**``unknown field `timeuot`, expected one of `color`, `hash`, …``** [2]

A misspelled key. The message lists the ones that would have been accepted.

**`invalid type: string "soon", expected u64`** [2]

A value of the wrong shape. `timeout` is a number of seconds; sizes and
durations are strings with a unit.

**`'${SECRETS_DIR}/id_ed25519' refers to ${SECRETS_DIR}, which is not set`** [2]

Interpolation of an unset variable, which is an error rather than an empty
string. Common with `${CREDENTIALS_DIRECTORY}` in a systemd unit, which only
exists inside the unit.

**`no profile 'nosuch' (known: boss, prod)`** [2]

A `mpt://` name the configuration does not define. `mpt profiles` lists what
there is.

**`mpt.toml: ignoring [ssh] — a configuration file in the working directory only contributes [defaults] and [policy]`** (warning)

Working as intended. A directory you happen to be standing in may tune how a
transfer runs, never where it goes. Put the section in the user file.

**`config.toml holds credentials and is readable by others (mode 644); chmod 600 it`**

A warning, or an error [2] with `[policy] strict_permissions`. `cmd` providers
run what the file says, which is why this matters.

**A setting seems to be ignored.** Two usual causes. First, `mpt config check`
prints a summary rather than everything, so a key missing from the listing may
still be in force. Second, and more often: for per-endpoint options a URL
option and a profile both beat a command-line flag. `--timeout 7` does not
override `?timeout=60`. See [Precedence](../configuration/file.md#precedence),
and read the target echoed in the result line, which shows what was used.

## Jobs, patterns and trees

**`jobs 1 and 2 write the same target out/data1.csv`** [2]

Two jobs would share one `.mpt-part` file and destroy each other's upload, so
the batch is refused before anything moves.

**`in/*.nothing matches no file (--allow-empty makes that fine)`** [2]

A pattern that matched nothing. For a scheduled job over an inbox that is
usually empty, add `--allow-empty`.

**`in/*.csv is a pattern, so its target out/one.csv must be a directory (end it with /)`** [2]

Several sources need somewhere to go, not one name.

**`scheme 'http' cannot list (use webdav:// for PROPFIND)`** [2]

Patterns, `mpt ls` and `-r` as a source all need a listing. `scp://` and
`http://` cannot; use `sftp://` and `webdav://`.

**`scheme 'mailto' cannot receive`** [2]

A send-only endpoint was used as a source.

**An option has no effect.** A misspelled URL option is ignored rather than
reported — for HTTP and WebDAV it is passed to the server, and no scheme
polices the query string. Check the spelling against the [protocol
page](../protocols/overview.md).

## The command line

**`the argument '--resume' cannot be used with '--no-atomic'`** [2]

Resuming continues a part file, which `--no-atomic` never creates.

**`the job list and the password cannot both come from stdin`** [2]

`--password-stdin` with `mpt batch -`; the upload of `mpt relay` and the secret
of `mpt credentials set` are refused the same way. Use `--password-file`
instead.

**`unexpected argument '-r' found`** [2]

`-r`, `--parallel`, `--fail-fast`, `--dry-run`, `--allow-empty`, `--format` and
`--follow` belong to the subcommand: `mpt cp -r …`, not `mpt -r cp …`.

**`unsupported scheme 'sftp (compiled without the 'ssh' feature)'`** [2]
**`keyring credentials need the 'keyring' feature, which is not compiled in`** [4]

The binary was built without that part. `mpt schemes` shows the protocols;
rebuild with the feature. See
[Installation](../getting-started/installation.md#choosing-protocols).

## The server

The API answers with `{"error": {"kind", "message"}}`; the [status and kind
table](../reference/api.md#errors) maps them. The ones that come up:

**`refusing to listen on 0.0.0.0:7788 without a token: set [server] token (or --token-env), or bind to 127.0.0.1`** [2]

Working as intended: without a token anyone who can reach the port could use
every profile. Set a token, or stay on loopback.

**`--delete-source would make every job delete its source; add --allow-delete (or [server] allow_delete) if that is meant`** [2]

The server was started with a global `--delete-source`, which would apply to
every job, without the switch that allows deleting.

**`only mpt://<profile>/ endpoints are accepted (set [server] urls = "any" or --allow-any-url to allow others)`** (400)

A job named a raw URL or a local path. Define a profile for it, or, when
every client is trusted as much as the server's user, allow any URL.

**`a job may not add ?options to a profile; set them in the profile`** (400)

`mpt://prod/?timeout=5` in a job. A reference's options would replace the
profile's, so the profile has to carry them.

**`profile 'prod' is misconfigured; see the server log`**, **`credentials for profile 'prod' could not be fetched; see the server log`** (400)

The detail goes to the log and not into the answer, so a client learns
nothing about the paths and providers behind a profile.

**`requests from a web page are not accepted (Origin header present)`** (403)

The request came from a browser acting for a page, or a client sends an
`Origin` header it does not need. Drop the header.

**A job sits in `queued`.** The server-wide `parallel` limit is taken by
other jobs' transfers; `GET /v1/healthz` with the token shows the counts.

## The relay

**`--via needs an ssh:// URL (or a profile with one), not sftp://…`** [2]

The relay is named with `ssh://`, not `sftp://`: it is a host to run a
command on, not a place that holds files. The same message with
`[profiles.<name>] via` in front of it means that profile's relay, not the
flag.

**`--check is not available with a relay: it needs what only this side has (the checksum file, the source, the key)`** [2]

`--check`, `--sign` and `--resume` do not work through a relay. Run that copy
from here, or verify on the receiving side.

**`invalid option 'delete-source': with a relay, only when the source and every target are behind the relay that reads the source (a profile with `via`)`** [2]

The relay may remove the source only if it read it and wrote every target;
otherwise nobody knows when the file is safe to delete. Give the source's
profile a `via`, and every target the same one — or drop `--delete-source`
and remove the file yourself afterwards. See [Letting the relay read the
source](../server/relay-topologies.md#letting-the-relay-read-the-source).

**`invalid option 'key': …: names a file on this machine, which the relay cannot read; let the relay use the forwarded agent (without --no-via-agent), give the target a password, or put the key on the relay`** [2]

A target with `?key=`, `?cert=` or `?passphrase=` while the agent is switched
off (`--no-via-agent`, or `[defaults] via_agent = false`). The file stays on
the client. Leave the forwarding on, use a password or token for that target,
or configure the key in the relay's `[ssh]` section.

**`invalid option 'credentials': the client asks for on-demand passwords, but this relay is set to credentials = "header"`** [2]

The two sides disagree about where passwords come from. Start the relay with
`--credentials on-demand` (or `any`), or drop `--via-credentials on-demand`.
The reverse message, `this relay takes passwords on demand only`, means the
relay insists and the client has to pass `--via-credentials on-demand`.

**`invalid option 'via-credentials': …: an S3 key cannot be asked for on demand`** [2]

An S3 store binds its key when it is built, so there is nothing to ask for at
login time. Send that target's credentials in the header, or let the relay use
its own AWS credential chain.

**`authentication failed`** for an SSH target behind a relay [4]

The forwarded agent had no key for it. Check that the target's key is one this
side can offer (`?key=`, `[ssh] key`, `MPT_SSH_KEY` or `~/.ssh/id_*`, or your
own agent), that the relay was not started with `--no-agent-forwarding`, and —
under an ordinary `sshd` — that the `authorized_keys` line says
`agent-forwarding`.

**``the server does not run `mpt relay` (not a relay, or not in its PATH)``** [1]

The SSH host accepted the login but refused the command. Either it is an
ordinary server without `mpt` on the `PATH` of that account, or the account's
`authorized_keys` forces another command.

**`no accepted method for relay@fast.example.com (tried: key …)`** [4]

The client's public key is not in the relay's `authorized_keys`. The relay's
log names the fingerprint it refused.

**`I/O error: relay: …`** or **`remote error: relay: …`** on a `FAILED` line [1]

The relay reached the target and the target refused; the message after
`relay:` is the target's own, as `cp` would have printed it there.

**`invalid option 'check': not over a relay`** (in a relay's `error` line) [2]

A header of your own set an option the relay refuses; see the [relay
protocol](../reference/relay-protocol.md).

**`I/O error: unknown frame kind 104`** from a relay reading your own header [1]

A header without `"v"` means version 2, which expects framed payload. Write
`"v": 1` to send the raw bytes of version 1.

## Reporting a problem

[Licensing and support](support.md#reporting-a-problem) says where a report
goes, and what to do instead when the problem has a security consequence.
Include in a report:

- the exact command, with credentials removed
- the output of `mpt -vv` for the failing run
- `mpt --version` and `mpt schemes`
- the operating system
- `mpt config check`, if a configuration file is involved
- the server software and version, if a particular server is involved. FTP
  servers especially differ in their listings and in how they handle renaming.
