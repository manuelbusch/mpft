# Local files

The local file system is the endpoint every other one is usually paired with,
and the only one that needs no scheme:

```
mpt cp report.pdf sftp://srv.example.com/in/
mpt cp /var/log/app.log "s3://bucket/logs/"
mpt cp ./exports/ -r sftp://srv.example.com/in/exports/
```

A bare path is a local file. `file:///var/log/app.log` means the same thing and
is worth writing only when a path could be mistaken for something else.

## Paths

Relative paths are resolved against the working directory, absolute ones are
taken as they are. The [trailing
slash](../getting-started/addressing.md#the-trailing-slash-decides-where-a-file-lands)
decides whether a target is a directory or a file name, exactly as elsewhere:

```
mpt cp report.pdf backup/                 # backup/report.pdf
mpt cp report.pdf backup/2026-09-10.pdf   # renamed
```

A `~` in a local path is expanded by the shell, so write it unquoted. Inside a
URL option (`?key=~/.ssh/id_ed25519`) it is `mpt` that expands it; see
[Quoting](../getting-started/addressing.md#quoting).

## Directories are created

A local target creates the directories it needs:

```
$ mpt cp report.pdf backup/2026/09/10/
report.pdf -> backup/2026/09/10/: 40000 bytes in 4.85ms
```

This is the one place where `mpt` differs from remote targets, which refuse a
path whose parent does not exist. It follows what a person expects of a local
copy, and it is why a date-stamped archive directory needs no `mkdir` in front
of it.

If something that is not a directory is in the way, the copy fails for that
target only:

```
FAILED             0 bytes   254.50µs  blocker/sub/: I/O error: Not a directory (os error 20)
```

## Everything is supported

Local files can do all of it: listing, sizes, renaming, appending, creating
directories, deleting. In practice that means every feature works without a
caveat — [atomic finishing](../guide/reliability.md#a-file-appears-only-when-it-is-whole),
[`--resume`](../guide/reliability.md#continuing-where-it-stopped),
[`-r`](../guide/many-files.md#whole-directories-with--r),
[patterns](../guide/many-files.md#patterns-on-the-far-side),
[`--skip-existing`](../guide/reliability.md#skipping-what-is-already-there) and
[`--delete-source`](../guide/many-files.md#repeating-a-run).

```
$ mpt ls .
d            -  out
-        40000  report.pdf
-           77  report.pdf.sha256
```

A directory shows `d` and no size; a file shows its length in bytes.

## Two local endpoints

Nothing stops both sides being local, and it is a reasonable way to get
checksums, atomic finishing and a fan-out over a plain copy:

```
mpt cp --hash sha256 release.tar.gz /mnt/archive/ /mnt/offsite/
```

The file is read once and written twice, with a checksum file beside each copy.
For a straight local copy of one file, `cp` is still `cp`; the point here is
the other three things.

## What is written

The payload is written with the process's own umask, as any program's output
would be. Ownership and permissions of the source are not carried across —
`mpt` moves file *contents* between systems that mostly cannot express each
other's metadata anyway. Where that matters, use a tool built for it (`rsync`,
`tar`) or set the permissions afterwards.

Timestamps are not preserved either. A file that arrives has the time it
arrived, which is usually what an inbox on the far side wants to sort by.

## Windows

Local paths on Windows work the way they look:

```
mpt cp C:\data\report.pdf sftp://srv.example.com/in/
mpt cp \\fileserver\share\report.pdf "s3://bucket/in/"
```

A drive letter or a UNC path is recognised as a local file rather than mistaken
for a scheme, and `\` counts as a path separator, so checksum and `.mpt-part`
files land next to their file. See the [Windows
appendix](../appendix/windows.md).

## Next

[SFTP and SCP](ssh.md), the other end of most commands on this page.
