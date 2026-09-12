# Why mpt?

Moving a file from one machine to another is a solved problem, once per
protocol: `scp` for SSH, `curl` for HTTP, `lftp` for FTP, `aws s3 cp` for
object storage, `mailx` for an attachment. Each is good at the protocol it
knows. The trouble starts when one job needs several of them.

Take a nightly export that has to reach an SFTP inbox, an S3 bucket and a
colleague's mailbox. It becomes a shell script: three tools, three ways of
passing a password, three kinds of error output, three exit-code conventions,
and a temporary file in the middle because the same bytes have to be read three
times. Then someone asks for a checksum beside each copy, and for the transfer
not to leave half a file behind when the line drops at 03:00.

That script is what `mpt` replaces:

```
mpt cp --hash sha256 export.csv \
    sftp://deploy@srv.example.com/incoming/ \
    "s3://bucket/exports/" \
    "mailto:colleague@example.com?subject=Nightly%20export"
```

## One vocabulary for every protocol

The URL is the address, and the prefix decides the protocol. Everything else —
how to authenticate, whether to checksum, how long to wait, how many transfers
run in parallel — is expressed the same way no matter what the far side speaks.
A flag learned for SFTP works for S3; a habit formed on HTTP carries to FTP.

That also means one place to look when something fails. The error messages,
the log format and the [exit codes](reference/exit-codes.md) are the tool's,
not each protocol library's.

## The source is read once

`mpt cp` takes any number of targets. The source is read a single time and the
bytes are handed to every target concurrently, in constant memory, with nothing
written to disk in between. A slow target does not make the others wait for it,
a failing target does not stop the rest, and each one reports its own outcome.

Reading a 40 GB image once instead of four times is the difference between a
transfer that fits in the maintenance window and one that does not.

## Safe defaults

The defaults are the conservative choice in every case:

- a file appears under its final name only when it is complete, so a pickup job
  never sees a half-written file;
- an unknown or changed SSH host key aborts the connection instead of being
  accepted silently;
- a stalled connection is given up on rather than hanging until morning;
- credentials that would go over the wire unencrypted are called out.

None of this needs a flag, and each of it can be turned off where a situation
genuinely calls for it.

## Integrity the recipient can check

`--hash` computes the digest while the data streams — one pass, no re-read —
and writes a checksum file next to every copy, in the format `sha256sum -c` and
`b3sum -c` already understand. The recipient needs no special tool.

`--sign` adds a detached OpenSSH or OpenPGP signature over that checksum file,
and on the receiving side an untrusted signature is refused **before any data
is copied**. A checksum protects against a corrupted transfer; a signature also
protects against someone who can replace both the file and its checksum.

## Secrets stay out of the command line

A password on the command line is visible in `ps` and in the shell history.
`mpt` takes credentials from environment variables, files, the OS key store,
HashiCorp Vault, or the standard output of any command — a reference in the
configuration file, resolved at the moment the endpoint is used, and only for
the endpoints the current command actually touches.

Where a protocol has a single-sign-on answer, that answer is available: the AWS
credential chain for S3, OAuth2 tokens for SMTP and HTTP, OpenSSH certificates
for SFTP.

## Made to be run by a machine

Unattended use is the primary use case:

- exit codes distinguish a wrong password from a checksum mismatch from a
  network failure;
- `--json` puts a machine-readable report on stdout while the human-readable
  lines stay on stderr;
- job lists come from a file, a CSV export or a pipe, and `--follow` turns a
  pipe into a work queue;
- `--dry-run` shows what would happen;
- `--skip-existing` makes a scheduled run send only what is new;
- [`mpt serve`](server/serve.md) takes jobs over HTTP from a program that
  should not shell out, and reports on them the same way.

## What mpt is not

Knowing where a tool stops is part of knowing when to use it.

- **It is not rsync.** There is no delta algorithm: a file that changed is sent
  in full. For keeping a large tree in sync over a slow line where most files
  change a little, rsync is the better tool.
- **It is not a sync tool.** `--skip-existing` compares name and size, not
  content, and nothing is ever deleted on a target to match a source.
- **It is not a scheduler.** There is no built-in cron and no retry queue.
  `mpt` is meant to be called by systemd timers, cron or a CI job, and to
  report clearly enough that those can act on the result. [`mpt
  serve`](server/serve.md) runs the jobs it is given, as soon as it is given
  them; deciding when to submit one is still the caller's job.
- **It does not watch anything.** `batch --follow` reads a pipe for as long
  as the pipe is open, which covers the "watch a directory" case together
  with `inotifywait`, and the server and the relay wait for a client. None of
  them looks at a directory on its own.
- **It does not do interactive browsing.** `ls` lists a directory; there is no
  shell, no `mget`, no tab completion on the remote side.
