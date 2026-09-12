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

The trailing slash decides, on every protocol:

```
$ mpt cp report.pdf backup/                    # backup/report.pdf
$ mpt cp report.pdf backup/2026-09-10.pdf      # renamed on the way
report.pdf -> backup/2026-09-10.pdf: 40000 bytes in 8.93ms
```

A **local** target creates the directories it needs. A **remote** one does not:

```
$ mpt cp report.pdf backup/2026/09/            # directories created
$ mpt cp report.pdf sftp://srv.example.com/no/such/dir/
error: … sftp: No such file
```

If the remote directory has to be created, copy a tree with
[`-r`](many-files.md#whole-directories-with--r), which creates directories as
part of the job, or create it on the far side first.

## Watching it happen

On a terminal a copy shows one line that redraws itself, and it disappears when
the copy is done:

```
148.9 MiB / 381.5 MiB ( 39%)  589.4 MiB/s
```

The percentage appears only when the source could say how large it is; an HTTP
server without a `Content-Length`, for instance, gives bytes and a rate but no
share. The line is drawn only where someone is watching — a terminal on stderr,
and not when `--json` is in use — so it never pollutes a log or a pipe.

`--progress always` overrides that judgement. Without a terminal each reading
gets a line of its own, which is what you want in a build log:

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
interrupted, stopping and cleaning up…
error: copy big.bin -> sftp://srv.example.com/in/: cancelled: interrupted
```

Open connections are dropped, the partial file on the target is removed, and
the exit code is 130. Nothing is left under the final name, because a transfer
in progress never had that name to begin with —
[atomic finishing](reliability.md#a-file-appears-only-when-it-is-whole)
explains why. With `--resume` the partial file is kept on purpose, so the next
run can continue it.

## Time limits

`--timeout <seconds>` (30 by default) is an **inactivity** limit, not a
deadline. Any read or write that makes progress resets it, so a large file over
a slow but steady line is fine, while a connection that has genuinely stopped
answering is given up on. It covers connecting, logging in, and every byte
after that.

```
mpt --timeout 120 cp big.iso sftp://srv.example.com/in/
mpt cp big.iso "sftp://srv.example.com/in/?timeout=120"     # this endpoint only
```

`--timeout 0` disables it, which is worth doing only when something else will
notice a hung process.

`--retries <n>` repeats the connect-and-login phase when it fails for a
transient reason. That is safe at any time, because no payload has been read
yet, and it needs no other flag. A rejected password is never retried. Per
endpoint the option is `?connect_retries=`.

The wait between attempts grows by a second each time: one second before the
second attempt, two before the third. Three retries therefore delay a doomed
connection by six seconds, which is worth knowing when a job has a window to
finish in.

Retrying the **transfer** itself is a different matter and needs `--cache`; see
[Several targets at once](fan-out.md#retrying-a-target).

## Checksums in passing

Adding `--hash sha256` costs one pass over data that is being read anyway, and
leaves a checksum file next to the copy that the recipient can verify with
`sha256sum -c`. `--check` goes the other way and verifies a download against a
checksum file beside the source. [Checksums](../trust/checksums.md) covers
both, and [Signatures](../trust/signatures.md) the case where the far side is
not trusted.

## Two things `cp` does not do

**`-` is not standard input.** A lone dash is treated as a file called `-`,
which almost certainly does not exist. Only `mpt batch -` reads stdin, and it
reads a job list rather than a payload. To send something a program produced,
write it to a file first.

**A directory is not a file.** `mpt cp sftp://srv/incoming/ ./` asks to read a
directory as if it were a file and fails. Copying directories is
[`-r`](many-files.md#whole-directories-with--r).

## Where the flags go

Most flags are global and may stand before or after the subcommand:

```
mpt --json cp report.pdf backup/
mpt cp --hash sha256 report.pdf backup/
```

The flags that belong to copying many files — `-r`, `--parallel`,
`--fail-fast`, `--dry-run`, `--allow-empty`, and `--format`/`--follow` for
`batch` — belong to the subcommand and must follow it:

```
mpt cp -r /data/export/ sftp://srv/in/     # right
mpt -r cp /data/export/ sftp://srv/in/     # error: unexpected argument
```

## Next

One source and one target is the simple case. The reason `cp` takes more
arguments is [Several targets at once](fan-out.md).
