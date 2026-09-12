# Your first transfer

This page walks through one real session: a local copy to see the shape of the
output, an upload that is refused on the first attempt for a good reason, a
listing, a download, and a checksum the recipient can verify. Ten minutes, and
afterwards the rest of the guide is mostly detail.

The examples use `srv.example.com` as the server and `deploy` as the account.
Substitute a machine you can reach by SSH; nothing here writes outside a
directory you name.

## 1. A copy with no network in it

Start with a copy that needs no network and no credentials. `mpt cp` takes a
source and a target:

```
$ mpt cp report.pdf backup/
report.pdf -> backup/: 40000 bytes in 4.85ms
```

That one line is the whole report: what went where, how much, how long. It is
written to **stderr**, not stdout, which matters later — a script can read a
machine-readable report from stdout while a person watches this on the
terminal.

The trailing slash on `backup/` is not decoration. It says *directory*, so the
source's file name is appended and the copy lands at `backup/report.pdf`.
Without the slash the target is the file name itself:

```
$ mpt cp report.pdf backup/2026-09-10.pdf
report.pdf -> backup/2026-09-10.pdf: 40000 bytes in 8.93ms
```

That rule holds for every protocol, and it is the single most important thing
to internalise — [Thinking in URLs](addressing.md) returns to it.

## 2. An upload that is refused

Now the same file to an SFTP server. A remote endpoint is a URL:

```
$ mpt cp report.pdf sftp://deploy@srv.example.com/incoming/
error: copy report.pdf -> sftp://deploy@srv.example.com/incoming/?timeout=30:
       authentication failed: host key of srv.example.com:22 is not in known_hosts:
       SHA256:GFb3ByRBzc3YOA2B7PCZeSWXCPpf4DIlKm/UrNkKGhY. Verify it, then add it with
       `ssh-keyscan -p 22 srv.example.com >> ~/.ssh/known_hosts`, or connect with
       ?hostkey=SHA256:GFb3ByRBzc3YOA2B7PCZeSWXCPpf4DIlKm/UrNkKGhY or ?known_hosts=accept-new
```

This is not a misconfiguration. `mpt` checks the server's host key against
`~/.ssh/known_hosts` before it sends anything, and an unknown host is refused
rather than accepted with a shrug. A machine that answers on port 22 is not
yet a machine you have any reason to trust, and the moment before you hand it
a password or a file is exactly the moment to say so.

The message tells you the three ways forward. Which one is right depends on
whether you can verify the fingerprint:

**You can check the fingerprint** — ask the machine's owner, or read it on the
console with `ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub`. If it matches,
record it:

```
ssh-keyscan srv.example.com >> ~/.ssh/known_hosts
```

**You cannot check it right now** and the network between you is one you
trust. Accept the key on first use, the way `ssh` itself offers to:

```
$ mpt cp report.pdf "sftp://deploy@srv.example.com/incoming/?known_hosts=accept-new"
WARN adding new host key for srv.example.com:22 to known_hosts: SHA256:GFb3ByRBzc3…
report.pdf -> sftp://deploy@srv.example.com/incoming/?known_hosts=accept-new&timeout=30: 40000 bytes in 92.26ms
```

The key is written to `known_hosts` and announced. From then on it is checked
strictly: a *changed* key is still refused, which is the case that matters.

**You are writing a script or a CI job** where no `known_hosts` file is
maintained. Pin the fingerprint in the URL and skip the file entirely:

```
mpt cp report.pdf "sftp://deploy@srv.example.com/incoming/?hostkey=SHA256:GFb3ByRBzc3…"
```

[Securing the connection](../trust/connections.md) covers all three in full.

## 3. The second attempt

With the key known, the plain command works:

```
$ mpt cp report.pdf sftp://deploy@srv.example.com/incoming/
report.pdf -> sftp://deploy@srv.example.com/incoming/?timeout=30: 40000 bytes in 83.38ms
```

**`?timeout=30` appeared although you did not type it.** `mpt` echoes the
target with the options that were actually in force, filled in from the
defaults. Seeing them is useful when a configuration file is in play and you
want to know what a run really used.

**Authentication happened without being mentioned.** No key was named, so
`mpt` looked in the usual places: `$MPT_SSH_KEY`, then a running ssh-agent,
then `~/.ssh/id_ed25519`, `id_ecdsa`, `id_rsa`, and only then would it have
asked for a password. To name a key explicitly, put it in the URL:

```
mpt cp report.pdf "sftp://deploy@srv.example.com/incoming/?key=~/.ssh/deploy_ed25519"
```

## 4. Looking at the other side

```
$ mpt ls sftp://deploy@srv.example.com/incoming/
-        40000  report.pdf
```

The columns are type (`-` file, `d` directory), size and name. `ls` works on
every scheme that can list a directory, which is all of them except `scp://`,
`http://` and the mail schemes.

## 5. Coming back

Reverse the arguments to download. Nothing about the command changes shape:

```
$ mpt cp sftp://deploy@srv.example.com/incoming/report.pdf ./
sftp://deploy@srv.example.com/incoming/report.pdf?timeout=30 -> ./: 40000 bytes in 82.44ms
```

Source and target are both just URLs, and either side may be local or remote.
A copy from one server straight to another needs no local file:

```
mpt cp sftp://old.example.com/export/data.csv "s3://bucket/import/?endpoint=https://minio.example.com"
```

## 6. Proving it arrived intact

`--hash` computes a digest while the bytes stream past — one pass, no re-read —
and leaves it next to the copy:

```
$ mpt cp --hash sha256 report.pdf sftp://deploy@srv.example.com/incoming/
report.pdf -> sftp://deploy@srv.example.com/incoming/?timeout=30: 40000 bytes in 118.43ms
+ sftp://deploy@srv.example.com/incoming/report.pdf.sha256
sha256  4ae30c5fbf7fd48c42dd9d26004fcde7c47cf90e0fe642c4c8069b239e4a299b
```

The `+` line names the extra file that was written, and the last line is the
digest itself. That file is one line in the format `sha256sum` already speaks:

```
$ cat report.pdf.sha256
4ae30c5fbf7fd48c42dd9d26004fcde7c47cf90e0fe642c4c8069b239e4a299b  report.pdf

$ sha256sum -c report.pdf.sha256
report.pdf: OK
```

So the recipient needs nothing from you but the two files. Going the other
way, `--check` verifies a download against a checksum file that sits beside the
*source*, and fails if they disagree.

## 7. Two places at once

The last thing worth seeing on day one is why `cp` takes more than two
arguments:

```
$ mpt cp report.pdf sftp://deploy@srv.example.com/incoming/ "s3://bucket/reports/" "mailto:boss@example.com?subject=Report"
ok             40000 bytes    79.43ms  sftp://deploy@srv.example.com/incoming/
ok             40000 bytes     7.13ms  s3://bucket/reports/
ok             40000 bytes    32.14ms  mailto:boss@example.com?subject=Report
report.pdf: 40000 bytes read, 3/3 targets ok in 123.12ms
```

The source was read **once**. The three targets received the bytes
concurrently, each with its own result line, and the `40000 bytes read` in the
summary is what actually came off the disk — not three times that. A failing
target would print `FAILED` on its own line and leave the others alone.

That is the feature that most often replaces a shell script, and
[Several targets at once](../guide/fan-out.md) is about nothing else.

## When something goes wrong

**Read the exit code.** It says what kind of failure it was, which matters more
in a script than the message:

```
$ mpt cp report.pdf sftp://deploy@srv.example.com/incoming/ ; echo $?
4
```

`4` is authentication: the host key was not trusted. `0` is success, `1` a
failed transfer, `2` a wrong command, `3` a checksum or signature that did not
hold up, and `130` a run stopped with Ctrl-C. The [full
table](../reference/exit-codes.md) says which error counts as which.

The mistake of asking a send-only endpoint for data is caught before any
connection is made, and lands in the "wrong command" category:

```
$ mpt cp mailto:x@example.com ./ ; echo $?
error: copy mailto:x@example.com?timeout=30: scheme 'mailto' cannot receive
2
```

**Turn up the log.** `-v` adds an info line per operation, `-vv` shows the
protocol conversation, `-vvv` everything:

```
$ mpt -v cp report.pdf backup/
INFO mpt::transfer: copy source=report.pdf targets=1 size=Some(40000) cache=Stream hash=None check=false
report.pdf -> backup/: 40000 bytes in 6.70ms
```

Log lines go to stderr along with the result, and passwords are masked in all
of them.

One thing that trips people up early: a **local** target creates the
directories it needs, a **remote** one refuses a path whose parent does not
exist. [Copying a file](../guide/copying.md#where-the-file-lands) shows both
and what to do about it.

[Troubleshooting](../appendix/troubleshooting.md) collects the errors that come
up, what each one means and what to do about it.

## Next

[Thinking in URLs](addressing.md) sets out the addressing model properly: the
trailing slash, per-endpoint options, quoting, and which schemes can do what.
It is the shortest chapter in the guide and the one the rest depends on.
