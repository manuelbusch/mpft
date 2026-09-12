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

**`no accepted method for deploy@srv (tried: ssh-agent, key /home/me/.ssh/id_ed25519)`** [4]

The list is what was actually attempted. If the key you meant is not in it, it
was not found — note that naming a key with `?key=` means the agent and the
default keys are **not** tried. See
[Authentication](../protocols/ssh.md#authentication).

**`ftp login failed for 'ftpuser'`** [4]

Wrong credentials, or the account cannot log in at all. `-vv` shows the
server's own reply, which is usually more specific.

**`mailto: requires MPT_SMTP_URL or [mail] smtp in the configuration`** [4]

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

**`insecure=true would switch off certificate verification, which policy.refuse_insecure_tls forbids`** [4]

A policy forbids it. That is the point of the policy; if it is your machine,
`[policy] refuse_insecure_tls` is where it is set.

**`FTP without TLS sends the password unencrypted (refused by policy; …)`** [4]

`ftp://` with a password, `http://` with basic auth or SMTP with `tls=none`,
plus `refuse_plaintext_auth`. Usually one character fixes it: `ftps://`,
`https://`, `webdavs://`.

## The transfer itself

**`sftp: No such file: No such file`** [1]

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

**`signature: made by SHA256:…, which is not in allowed_signers`** [3]

The signature is valid but the key is not one you trust. Add it to the trust
file if it should be.

**`signature: SSH signature invalid: signature error`** [3]

The checksum file does not match its signature — it was changed after signing.

**`signature: rejected at 2026-09-10T18:05:31Z: release@example.com: key expired at 2020-01-01T00:00:00Z`** [3]

An `allowed_signers` option (`valid-before`, `valid-after`) excludes the moment
the file was signed.

**`signature: the checksum file was signed 9d ago …, longer than the 7d the policy allows`** [3]

`[policy] max_signature_age`. Either the file really is old, or the limit is
too tight for how often it is regenerated.

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

`--password-stdin` with `mpt batch -`. Use `--password-file` instead.

**`unexpected argument '-r' found`** [2]

`-r`, `--parallel`, `--fail-fast`, `--dry-run`, `--allow-empty`, `--format` and
`--follow` belong to the subcommand: `mpt cp -r …`, not `mpt -r cp …`.

**`unsupported scheme 'sftp (compiled without the 'ssh' feature)'`** [2]
**`keyring credentials need the 'keyring' feature, which is not compiled in`** [4]

The binary was built without that part. `mpt schemes` shows the protocols;
rebuild with the feature. See
[Installation](../getting-started/installation.md#choosing-protocols).

## Reporting a problem

Include in a report:

- the exact command, with credentials removed
- the output of `mpt -vv` for the failing run
- `mpt --version` and `mpt schemes`
- the operating system
- `mpt config check`, if a configuration file is involved
- the server software and version, if a particular server is involved. FTP
  servers especially differ in their listings and in how they handle renaming.
