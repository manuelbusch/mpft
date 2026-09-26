# Copying a file

`mpt cp` takes a source and a target. Both are [URLs](../getting-started/addressing.md),
either may be local or remote, and nothing about the command changes when the
protocol does.

```
mpt cp report.pdf sftp://deploy@srv.example.com/incoming/     # up
mpt cp sftp://deploy@srv.example.com/incoming/report.pdf ./   # down
mpt cp ftps://old.example.com/out/x.csv "s3://bucket/in/"     # between two servers
```

The third case never touches the local disk. The bytes are read from one
connection and written to the other as they arrive, so a machine with no room
to spare can still move a file that would not fit on it.

## Where the file lands

The [trailing slash](../getting-started/addressing.md#where-a-file-lands)
decides, or a directory that already exists: `backup/` puts the file at
`backup/report.pdf`, `backup/2026-09-10.pdf` renames it on the way.

A **local** target creates the directories it needs. A **remote** one does not:

```
$ mpt cp report.pdf backup/2026/09/            # directories created
$ mpt cp report.pdf sftp://srv.example.com/no/such/dir/
error: … sftp: No such file
```

If the remote directory has to be created, copy a tree with
[`-r`](many-files.md#whole-directories-with--r), which creates directories as
part of the job, or create it on the far side first.

## Progress display

On a terminal a copy shows one line that redraws itself, and it disappears when
the copy is done:

```
148.9 MiB / 381.5 MiB ( 39%)  589.4 MiB/s
```

The percentage appears only when the source could say how large it is; an HTTP
server without a `Content-Length`, for instance, gives bytes and a rate but no
share. The line is drawn only when stderr is a terminal and `--json` is off,
so it never pollutes a log or a pipe.

`--progress always` overrides that. Without a terminal each reading gets a
line of its own, which suits a build log:

```
$ mpt --progress always cp big.bin sftp://srv.example.com/in/
656.0 KiB / 381.5 MiB (  0%)  558.5 MiB/s
148.9 MiB / 381.5 MiB ( 39%)  589.4 MiB/s
297.0 MiB / 381.5 MiB ( 78%)  590.8 MiB/s
big.bin -> sftp://srv.example.com/in/?timeout=30: 400000000 bytes in 922.49ms
```

`--progress never` switches it off for good.

## Stopping a copy

Ctrl-C stops the transfer rather than abandoning it:

```
^C
interrupted, stopping and cleaning up (Ctrl-C again exits immediately)…
error: copy big.bin -> sftp://srv.example.com/in/: cancelled: interrupted
```

The partial file is removed and the exit code is 130; nothing is left under
the final name. [Interrupted and repeated transfers](reliability.md#ctrl-c)
has the details, including what `--resume` keeps.

## Time limits

`--timeout <seconds>` (30 by default) is an **inactivity** limit, not a
deadline. Any read or write that makes progress resets it. A large file over a
slow but steady line is therefore fine, while a connection that has stopped
answering is given up on. It covers connecting, logging in, and every byte
after that. S3 uploads count their progress per part instead; [Timeouts on
S3](../protocols/s3.md#timeouts-on-s3) has the detail.

```
mpt --timeout 120 cp big.iso sftp://srv.example.com/in/
mpt cp big.iso "sftp://srv.example.com/in/?timeout=120"     # this endpoint only
```

`--timeout 0` disables it. Over SFTP, SCP, FTP, HTTP and WebDAV, connecting
and logging in keep a deadline of 30 seconds even then, so a server that
cannot be reached still fails. Disable it only when something else will notice
a hung process.

Two kinds of retry exist, and they are set differently:

| | Connect retries | Transfer retries |
|---|---|---|
| What is repeated | connecting and logging in | the whole transfer to a target that failed |
| Safe because | no payload has been read yet | the payload is replayed from memory |
| Needs | nothing else | `--cache` |
| Set by | `?connect_retries=<n>` on the endpoint, `[defaults] retries`, or `--retries` | `--retries <n>` or `[defaults] retries` |

`--retries <n>` sets **both**: it puts `connect_retries=<n>` on every endpoint
that does not name its own, and it retries failed transfers. Because the
second part needs the payload again, `--retries` without `--cache` is an
error:

```
$ mpt --retries 2 cp report.pdf sftp://srv.example.com/in/
error: copy report.pdf: invalid option 'retries': retries need the memory cache (a stream cannot be replayed)
```

For connect retries alone, put `?connect_retries=` on the endpoint or in its
[profile](../configuration/profiles.md). A rejected password is never retried;
only transient failures are.

The wait between attempts grows by a second each time: one second before the
second attempt, two before the third. Three retries therefore delay a doomed
connection by six seconds, which matters when a job has a window to finish in.

[Several targets at once](fan-out.md#retrying-a-target) covers transfer
retries in a fan-out.

## Checksums in passing

Adding `--hash sha256` costs one pass over data that is being read anyway, and
leaves a checksum file next to the copy that the recipient can verify with
`sha256sum -c`. `--check` goes the other way and verifies a download against a
checksum file beside the source. [Checksums](../trust/checksums.md) covers
both, and [Signatures](../trust/signatures.md) the case where the far side is
not trusted.

## What `cp` does not do

**`-` is not standard input.** A lone dash is treated as a file called `-`,
which almost certainly does not exist. Only `mpt batch -` reads stdin, and it
reads a job list rather than a payload. To send something a program produced,
write it to a file first.

**A directory is not a file.** `mpt cp sftp://srv/incoming/ ./` asks to read a
directory as if it were a file and fails. Copying directories is
[`-r`](many-files.md#whole-directories-with--r).

## Flag placement

Most flags are global and may come before or after the subcommand. The
[job flags](../reference/cli.md#job-flags) — `-r`, `--parallel`, `--dry-run`
and their kin — belong to `cp` and `batch` and must follow the subcommand.
