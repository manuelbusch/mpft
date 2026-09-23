# Checksums

A transfer can go wrong quietly: a truncated upload, a proxy that rewrote
something, a disk that returned a bad block. None of these announce
themselves, and the file on the far side looks like a file. A checksum makes
the difference detectable.

```
mpt cp --hash sha256 report.pdf sftp://srv.example.com/incoming/
```

## Algorithms and checksum files

`--hash sha256|sha512|blake3` digests the data as it passes through, in one
pass, with no re-read and no buffering. On a fan-out it costs one computation
no matter how many targets there are, because there is one payload.

The result is written next to every target that received the file:

```
$ mpt cp --hash sha256 report.pdf out/
report.pdf -> out/: 12 bytes in 4.39ms
+ out/report.pdf.sha256
sha256  4dc21b974cc293d0dfbb25326f0df4ac461f29d69ccc2c2dc5391f4f39a45aed
```

| Algorithm | File | Notes |
|---|---|---|
| `sha256` | `<name>.sha256` | the default with `--sign`, and what most recipients expect |
| `sha512` | `<name>.sha512` | faster than SHA-256 on 64-bit hardware |
| `blake3` | `<name>.b3` | considerably faster again; needs `b3sum` on the other end |

## Verifying with standard tools

The file is one line in the format `sha256sum` and `b3sum` already speak:

```
$ cat out/report.pdf.sha256
4dc21b974cc293d0dfbb25326f0df4ac461f29d69ccc2c2dc5391f4f39a45aed  report.pdf

$ cd out && sha256sum -c report.pdf.sha256
report.pdf: OK
```

Whoever picks the file up verifies it with a tool they already have, on a
machine without `mpt`.

## In a fan-out

Every target that took the file gets its own copy of the checksum file, and
the digest is printed once, since there was one payload; [Several targets at
once](../guide/fan-out.md) shows the output. Two details matter in practice:

- **The checksum file is written after the transfer**, through a second
  connection to the same target. Combined with
  [atomic finishing](../guide/reliability.md#a-file-appears-only-when-it-is-whole)
  it doubles as a completion marker: if `report.pdf.sha256` is there, then
  `report.pdf` is complete.
- **If that write fails, only that target fails.** The message says that the
  file itself arrived and the checksum beside it did not, so the two situations
  can be told apart.

[Mail targets](../protocols/mail.md#the-message) receive the checksum as a
second attachment instead.

## Verifying a download with `--check`

`--check` looks for a checksum file next to the **source**, verifies what was
transferred against it, and fails if they disagree:

```
$ mpt cp --check sftp://srv/in/report.pdf ./
sftp://srv/in/report.pdf -> ./: 12 bytes in 4.39ms
blake3  4ee59acf208cdb32d826d48ea23246352f6c47babdb7f0d237744536ef34c0eb
check ok (BLAKE3)
```

The algorithm comes from whichever file is there. `mpt` tries `<name>.b3`,
then `<name>.sha256`, then `<name>.sha512`, and uses the first it finds. That
is why the run above reports BLAKE3 without having been asked for it.

The digest used is the one on the line that names the source, `report.pdf`
or `./report.pdf`, so a file with an entry per file in the format of
`SHA256SUMS` works too. A checksum file that lists only other files is
refused rather than read for its first line:

```
error: remote error: check: out/report.pdf.sha256 is not a checksum file for report.pdf:
       it has no entry for 'report.pdf' (it lists 'other.bin')
```

A line whose digest does not have the length of the file's algorithm, 64 hex
digits for SHA-256 and BLAKE3 and 128 for SHA-512, makes the file malformed
rather than a mismatch.

A file that holds nothing but a digest, as some download sites publish, is
taken for the file it sits beside. A [signed](signatures.md) checksum file
must name the file, since otherwise the signature would not say which file it
covers; a signed file for another file, renamed to sit beside this one, fails
with exit code 3.

A mismatch shows both digests:

```
$ mpt cp --check out/report.pdf ./
blake3  a08daaa9b2cf700b857ace55a2c1cc1775eaaaac17fba456be9cebacd102965a
CHECK FAILED (BLAKE3): expected 4ee59acf208cdb32d826d48ea23246352f6c47babdb7f0d237744536ef34c0eb,
                       got a08daaa9b2cf700b857ace55a2c1cc1775eaaaac17fba456be9cebacd102965a
error: BLAKE3 checksum mismatch: expected 4ee59acf…, got a08daaa9…
```

The exit code is **3**, which a script can act on without reading the message.
The verdict is in before the part file is renamed, so a file that does not
match never appears under its final name: its part file is removed, even with
`--resume`, and no checksum or signature file is written beside it. A target
that writes directly (see [A file appears only when it is
whole](../guide/reliability.md#a-file-appears-only-when-it-is-whole)) keeps
what it received, and reports the mismatch all the same.

A copy that fails before the source has been read to the end has nothing to
compare. It is not judged at all: the failure keeps its own message and [exit
code](../reference/exit-codes.md), rather than turning into a mismatch.

A missing checksum file is a failure too, since a check that silently did not
happen would be worse than no check:

```
error: copy report.pdf: remote error: check: no checksum file next to the source
       (tried report.pdf.b3, report.pdf.sha256, report.pdf.sha512)
```

Both flags work together, and with several targets:

```
mpt cp --check --hash sha256 sftp://old/out/report.pdf sftp://new/in/ "s3://bucket/in/"
```

That verifies the source against its own checksum file and leaves a fresh one
beside each target.

## What a checksum does not do

A checksum proves that the file matches the checksum. It says nothing about
who wrote either of them. Anyone who can write into the target directory can
replace the file *and* recompute the checksum beside it, and the result
verifies perfectly.

For a file that came from somewhere you do not control, that is the question
that matters, and it needs [Signatures](signatures.md).
