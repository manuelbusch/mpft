# Local files

The local file system is the endpoint every other one is usually paired with,
and the only one that needs no scheme:

```
mpt cp report.pdf sftp://srv.example.com/in/
mpt cp /var/log/app.log "s3://bucket/logs/"
mpt cp -r ./exports/ sftp://srv.example.com/in/exports/
```

A bare path is a local file. `file:///var/log/app.log` means the same thing
and is only needed when a path could be mistaken for something else.

## Paths

Relative paths are resolved against the working directory, absolute ones are
taken as they are. The [trailing
slash](../getting-started/addressing.md#the-trailing-slash-decides-where-a-file-lands)
decides whether a target is a directory or a file name, as elsewhere.

A `~` in a local path is expanded by the shell, so write it unquoted. Inside a
URL option (`?key=~/.ssh/id_ed25519`) it is `mpt` that expands it; see
[Quoting](../getting-started/addressing.md#quoting).

## Directories are created

A local target creates the directories it needs, [unlike a remote
one](../guide/copying.md#where-the-file-lands), so a date-stamped archive
directory needs no `mkdir` in front of it. If something that is not a
directory is in the way, the copy fails for that target only:

```
FAILED             0 bytes   254.50µs  blocker/sub/: I/O error: Not a directory (os error 20)
```

## Capabilities

Local files have every capability in the
[matrix](overview.md#what-each-one-can-do), so every feature works without a
caveat.

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

## Permissions and timestamps

The payload is written with the process's own umask, as any program's output
would be. Ownership and permissions of the source are not carried across:
`mpt` moves file *contents* between systems that mostly cannot express each
other's metadata. Where that matters, use a tool built for it (`rsync`,
`tar`) or set the permissions afterwards.

Timestamps are not preserved either. A file that arrives has the time it
arrived, which is usually what an inbox on the far side wants to sort by.

## Windows

Drive letters, UNC paths and `\` as a separator are recognised; see the
[Windows appendix](../appendix/windows.md#paths).
