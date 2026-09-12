# Your first transfer

This page walks through one session: a local copy to see the shape of the
output, an upload that is refused on the first attempt, a listing, a download,
a checksum the recipient can verify, and a copy to several targets.

The examples use `srv.example.com` as the server and `deploy` as the account.
Substitute a machine you can reach by SSH; nothing here writes outside a
directory you name.

## 1. A local copy

Start with a copy that needs no network and no credentials. `mpt cp` takes a
source and a target:

```
$ mpt cp report.pdf backup/
report.pdf -> backup/: 40000 bytes in 4.85ms
```

That one line is the whole report: what went where, how much, how long. It is
written to **stderr**, not stdout. A script can therefore read a
machine-readable report from stdout while a person watches this on the
terminal.

The trailing slash on `backup/` says *directory*, so the copy lands at
`backup/report.pdf`. Without it the target is the file name itself:

```
$ mpt cp report.pdf backup/2026-09-10.pdf
report.pdf -> backup/2026-09-10.pdf: 40000 bytes in 8.93ms
```

The rule holds for every protocol; [Thinking in
URLs](addressing.md#the-trailing-slash-decides-where-a-file-lands) states it in
full.

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
`~/.ssh/known_hosts` before it sends anything, and an unknown host is refused.
A machine that answers on port 22 is not yet a machine you have any reason to
trust, and the check happens before a password or a file is handed to it.

The message names the three ways forward. For this walk-through, accept the
key on first use, the way `ssh` itself offers to:

```
$ mpt cp report.pdf "sftp://deploy@srv.example.com/incoming/?known_hosts=accept-new"
WARN adding new host key for srv.example.com:22 to known_hosts: SHA256:GFb3ByRBzc3…
report.pdf -> sftp://deploy@srv.example.com/incoming/?known_hosts=accept-new&timeout=30: 40000 bytes in 92.26ms
```

The key is now in `known_hosts` and is checked strictly from here on; a
*changed* key is still refused. When you can verify the fingerprint, or when a
script needs to pin it in the URL, [Securing the
connection](../trust/connections.md#ssh-host-keys) has the other two ways.

## 3. The upload succeeds

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
`mpt` tried the ssh-agent and the default keys under `~/.ssh`, in the order
[SFTP and SCP](../protocols/ssh.md#authentication) lists. To name a key
explicitly, put it in the URL:

```
mpt cp report.pdf "sftp://deploy@srv.example.com/incoming/?key=~/.ssh/deploy_ed25519"
```

## 4. Listing the remote directory

```
$ mpt ls sftp://deploy@srv.example.com/incoming/
-        40000  report.pdf
```

The columns are type (`-` file, `d` directory), size and name. Which schemes
can list is the `list` column of the [capability
matrix](../protocols/overview.md#what-each-one-can-do).

## 5. Downloading

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

## 6. A checksum for the recipient

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

## 7. Several targets

`cp` takes more than two arguments:

```
$ mpt cp report.pdf sftp://deploy@srv.example.com/incoming/ "s3://bucket/reports/" "mailto:boss@example.com?subject=Report"
ok             40000 bytes    79.43ms  sftp://deploy@srv.example.com/incoming/
ok             40000 bytes     7.13ms  s3://bucket/reports/
ok             40000 bytes    32.14ms  mailto:boss@example.com?subject=Report
report.pdf: 40000 bytes read, 3/3 targets ok in 123.12ms
```

The source was read **once** and the three targets received the bytes
concurrently, each with its own result line. [Several targets at
once](../guide/fan-out.md) explains the output, the buffering and what happens
when one target fails.

## When something goes wrong

**Read the exit code.** It says what kind of failure it was, which matters more
in a script than the message:

```
$ mpt cp report.pdf sftp://deploy@srv.example.com/incoming/ ; echo $?
4
```

`4` is authentication: the host key was not trusted. [Exit
codes](../reference/exit-codes.md) lists the others and says which error counts
as which.

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
