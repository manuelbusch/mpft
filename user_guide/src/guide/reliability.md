# Interrupted and repeated transfers

Transfers fail: a line drops, a server reboots, someone presses Ctrl-C. This
page is about what is left behind and what the next run does about it. Two
rules hold throughout: nothing incomplete ever carries a final name, and the
next run can continue or skip rather than start over.

## A file appears only when it is whole

Every target that can rename a file is written in two steps. The payload goes
to `<name>.mpt-part`, and only when the transfer has finished is it renamed to
`<name>`.

```
report.pdf.mpt-part      ← while it is being written
report.pdf               ← the moment it is complete
```

Nothing on the far side ever sees a half-written `report.pdf`. That matters
whenever something else is watching the directory: a pickup job, an import, a
partner's cron. Without it, the classic failure is a consumer reading a file
that is still growing, and the classic workaround is a marker file that
everyone forgets to write.

If the transfer fails, the part file is removed. Checksum and signature files
are written **after** the rename, so they remain a reliable "this is finished"
marker: if `report.pdf.sha256` is there, `report.pdf` is complete.

Which protocols can rename is the `rename` column of the [capability
matrix](../protocols/overview.md#what-each-one-can-do); what they use to do it:

| Protocol | Mechanism |
|---|---|
| local | `rename(2)` |
| `sftp://` | SFTP `RENAME`, replacing an existing target |
| `scp://` | `mv -f` over the same SSH connection |
| `ftp://`, `ftps://` | `RNFR` / `RNTO` |
| `webdav://` | `MOVE` |
| `http://` | none: HTTP cannot rename, so the PUT goes straight to the target |
| `s3://` | none needed: an object appears only when its upload completes |
| mail | none needed: atomic by its nature |

`--no-atomic` writes straight to the final name. It exists for pickup processes
that cannot cope with an extra file appearing next to the one they are waiting
for — a directory watcher with a pattern too loose, typically.

Two transfers writing the same target at the same time still conflict. The
difference is that the second rename now reports it instead of the two
interleaving silently, and within one command `mpt` refuses the situation
[before it starts](many-files.md#colliding-targets).

## Ctrl-C

[Stopping a copy](copying.md#stopping-a-copy) shows what it looks like. Running
transfers are stopped, connections are dropped, part files are removed and the
exit code is **130**. In a fan-out, targets that had already finished
keep their file; the unfinished ones report `cancelled`. In a batch, jobs that
had not started never start.

With `--resume` the part file is kept instead of removed, so that the next
run can continue it.

## Resuming with `--resume`

`--resume` keeps whatever is already in `<name>.mpt-part` on the target and
sends only the rest.

```
$ mpt --resume cp big.bin sftp://srv.example.com/in/
^C
interrupted, stopping and cleaning up…
error: copy big.bin -> sftp://srv.example.com/in/: cancelled: interrupted

$ ls -l …/in/
-rw-r--r--  1 deploy  users  209240064  big.bin.mpt-part

$ mpt -v --resume cp big.bin sftp://srv.example.com/in/
INFO mpt::transfer: resuming part=big.bin.mpt-part offset=209240064
big.bin -> sftp://srv.example.com/in/: 290759936 bytes in 2.08s
```

Half a gigabyte was already there, and only the remaining 290 MB travelled.

The flag does two things, and both are needed: it tells the transfer to
continue from a part file, and it tells an interrupted transfer to **keep** its
part file instead of cleaning up. Without `--resume` on the first run there is
nothing to continue from, so put it on both.

Three things to know:

- **The source is still read from the beginning.** A checksum has to cover the
  whole file, and the source is usually the cheap side. Only the missing bytes
  go over the network.
- **A part file that is not shorter than the payload is not a prefix of it.**
  It may be a leftover from something else entirely, so it is written again
  from the top rather than trusted.
- **In a fan-out each target resumes from its own offset.** The single source
  stream is read once and each target skips the bytes it already has.

Resuming needs the `append` column of the [capability
matrix](../protocols/overview.md#what-each-one-can-do). Local and `sftp://`
targets write the rest at the offset where the part file ended, so a retry
after a failed attempt replaces what that attempt left instead of adding to
it. `ftp://` and `ftps://` append with `APPE` and then compare the size the
server reports with what it should hold; a mismatch fails the target. The rest
have no append, so the whole payload is sent again.

`--resume` needs atomic finishing, so it cannot be combined with `--no-atomic`.

## Skipping with `--skip-existing`

`--skip-existing` asks each target, before anything is read, whether it already
holds a file of the source's name and size:

```
$ mpt cp --skip-existing report.pdf a/ b/
skip   already there             a/
ok             40000 bytes     4.30ms  b/
report.pdf: 40000 bytes read, 2/2 targets ok in 4.55ms
```

With a single target the line is shorter:

```
$ mpt cp --skip-existing report.pdf a/
report.pdf -> a/: already there, skipped
```

A skipped target counts as successful. If **every** target already has the
file, the source is not opened at all, so a nightly `-r` run over an unchanged
tree costs almost nothing.

The caveat is in the name of the comparison: **size, not content**. A file that
was edited without changing its length is not noticed. Where that matters, use
`--hash` on the way out and `--check` on the way back, or leave
`--skip-existing` off and let the transfer overwrite.

Targets that cannot say what they hold — mail, an HTTP server without `HEAD` —
are never skipped.

## Timeouts and connect retries

`--timeout` counts inactivity, not total duration, so a slow but steady
transfer is never cut off and a stalled one fails instead of hanging.
`?connect_retries=` covers the overnight case of a server that is briefly
unreachable while it restarts. Both are described under [Time
limits](copying.md#time-limits), and both belong in the [configuration
file](../configuration/file.md) when they should hold for every run.

## Example: a repeatable nightly job

A scheduled job that has to survive a bad night, and be safe to run twice:

```
mpt cp -r --skip-existing --resume --hash sha256 \
    /data/export/ sftp://deploy@srv.example.com/incoming/
```

- `-r` walks the tree and creates directories as needed;
- `--skip-existing` means a second run after a partial night sends only what is
  missing;
- `--resume` continues any file that was cut off mid-way;
- `--hash` leaves a checksum beside each file, which doubles as the marker that
  it is complete;
- atomic finishing, on by default, means the consumer on the far side never
  sees a partial file.

Add `--delete-source` when the export directory should be emptied as it is
drained, and check the [exit code](../reference/exit-codes.md) rather than the
output in whatever calls it. [Scheduled and triggered
runs](../automation/scheduling.md) puts a command like this into cron or a
systemd timer.
