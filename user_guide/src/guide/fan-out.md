# Several targets at once

`mpt cp` takes any number of targets after the source. The source is read
**once**, and the bytes are handed to every target as they arrive:

```
$ mpt cp --hash sha256 report.pdf sftp://deploy@srv.example.com/incoming/ "s3://bucket/reports/" "mailto:boss@example.com?subject=Report"
ok             40000 bytes    79.43ms  sftp://deploy@srv.example.com/incoming/
        + sftp://deploy@srv.example.com/incoming/report.pdf.sha256
ok             40000 bytes     7.13ms  s3://bucket/reports/
        + s3://bucket/reports/report.pdf.sha256
ok             40000 bytes    32.14ms  mailto:boss@example.com?subject=Report
report.pdf: 40000 bytes read, 3/3 targets ok in 123.12ms
sha256  4ae30c5fbf7fd48c42dd9d26004fcde7c47cf90e0fe642c4c8069b239e4a299b
```

Each target gets a line: outcome, bytes it took, how long it needed, and which
target it was. The summary counts the bytes that came off the disk (`40000`,
not three times that). The digest is printed once, because there is one
payload and therefore one checksum, and a copy of the checksum file was
written beside each target.

This is the feature that most often replaces a shell script, where the
alternative is to read the source three times or to spool it to a temporary
file.

## Buffering and memory

By default nothing is buffered beyond a small window. The source is read in
`--chunk` sized pieces (64 KiB), and each piece is handed to every target as
one reference-counted buffer rather than as a copy per target. Each target has
a queue of `--queue` pieces (16) before the source is paused.

The live memory is therefore bounded by the **slowest** target's queue
(64 KiB × 16, about a megabyte) and not multiplied by the number of targets,
because a piece that three targets still hold is one allocation with three
references. It does not grow with the size of the file either: 40 KB and 40 GB
cost the same.

The consequence is that **the slowest target sets the pace**. A fan-out to
three servers takes as long as the slowest of them, not as long as all three
added together. Where that is not acceptable, the cache decouples them.

## Streaming or cached

| | Streaming (default) | `--cache` |
|---|---|---|
| Memory | about 1 MiB, whatever the size | the whole payload, up to `--cache-limit` (256M) |
| How | one read, chunks handed to every target | the source is read into memory once, each target reads its own copy |
| Pace | the slowest target sets it | targets are independent |
| `--retries` | not available | available |
| Size known up front | only if the source could say | always, once buffered |

```
mpt cp --cache --retries 2 big.iso sftp://a.example.com/ sftp://b.example.com/
```

Above the limit the copy fails rather than quietly spilling to disk:

```
$ mpt cp --cache big.iso backup/
error: copy big.iso: I/O error: payload exceeds the configured limit of 268435456 bytes
```

Use `--cache` when you want retries, when a target needs the size before it
will accept anything (SCP does, and a source that cannot say how large it is
would otherwise force a spool), or when one unreliable target should not hold
up the others. Leave it off for anything large.

## Retrying a target

`--retries <n>` repeats a **transfer** that failed, which is only possible when
the payload can be replayed from the cache. Each target is retried on its own,
with the backoff described under [Time limits](copying.md#time-limits).

One caveat: [a retried mail target may deliver
twice](../protocols/mail.md#in-a-fan-out), because SMTP cannot say whether a
message that failed halfway was accepted.

## When a target fails

A failing target does not stop the others:

```
$ mpt cp report.pdf backup/ sftp://unreachable.example.com/in/
ok             40000 bytes     4.37ms  backup/
FAILED             0 bytes   254.50µs  sftp://unreachable.example.com/in/: authentication failed: …
report.pdf: 40000 bytes read, 1/2 targets ok in 4.60ms
error: 1 of 2 targets failed
```

The exit code is 1 when the outcomes are mixed, and the specific code when
every failed target failed the same way; [Exit
codes](../reference/exit-codes.md#when-several-things-fail-at-once) has the
rule.

Nothing is rolled back. The targets that succeeded keep the file; re-running
the command with [`--skip-existing`](reliability.md#skipping-with---skip-existing)
will leave them alone and retry only the ones that are missing it.

## Slow targets, stalled targets

**A pause at the start is normal.** Targets that must connect and negotiate
before they can accept a single byte, SCP and SMTP in particular, hold the
stream briefly while they get ready. Everything else waits, because there is
only one read. This is head-of-line blocking, not a deadlock, and it passes
quickly.

**A target that stops taking data is dropped.** If a target has not accepted
anything for `--timeout` seconds, it is removed from the fan-out and reported
as a timeout, and the remaining targets carry on. One unresponsive server
therefore cannot hold a transfer open indefinitely.

`--chunk` and `--queue` tune that buffer. Raising the queue lets a fast target
run further ahead of a slow one, at `--chunk` bytes per extra place; raising
the chunk size trades syscalls for memory. Values below the floor are raised to
it silently: `--chunk` is at least 1024 bytes and `--queue` at least 1.

## Checksums and signatures per target

`--hash` writes the checksum file beside **every** target that received the
file, through a second connection, after the transfer succeeded. If that write
fails, only that target is reported as failed; the file itself is already
there.

[Mail targets](../protocols/mail.md#the-message) receive the checksum and the
signature as further attachments instead.
