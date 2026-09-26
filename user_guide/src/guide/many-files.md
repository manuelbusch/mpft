# Many files

`cp` with one source moves one file. There are three ways to move many, and all
three end up in the same place: a list of jobs, each of which is one source
with its targets, run as a fan-out of its own. Up to `--parallel` jobs (4 by
default) are in flight at a time.

```
mpt cp -t sftp://srv/in/ *.csv                    # several sources named directly
mpt cp 'sftp://srv/out/*.csv' /data/incoming/     # a pattern, expanded by listing
mpt cp -r /data/export/ sftp://srv/in/export/     # a whole directory tree
```

A fourth way — a list from a file or a pipe — is
[Job lists and pipelines](job-lists.md).

Output is per job, prefixed with its position in the list:

```
$ mpt cp -t backup/a/ -t backup/b/ data1.csv data2.csv
[1/2] ok                 6 bytes     6.51ms  backup/a/
[1/2] ok                 6 bytes     6.52ms  backup/b/
[1/2] data1.csv: 6 bytes read, 2/2 targets ok in 6.72ms
[2/2] ok                 6 bytes     6.46ms  backup/a/
[2/2] ok                 6 bytes     8.97ms  backup/b/
[2/2] data2.csv: 6 bytes read, 2/2 targets ok in 9.17ms
2/2 jobs ok in 9.34ms
```

Jobs finish in whatever order they finish, so with `--parallel` above 1 the
prefixes will not be in sequence.

## Several sources with `-t`

`-t` names a target, and every positional argument becomes a source. It is the
same `-t` as in GNU `cp`, and it exists for the same reason: with several
sources, the last argument can no longer be the target.

```
mpt cp -t sftp://srv/in/ report.pdf summary.csv notes.txt
mpt cp -t sftp://srv/in/ -t "s3://bucket/in/" *.csv     # every file to both
```

Repeating `-t` gives every job the same fan-out. The shell expands `*.csv`
before `mpt` sees it, so this works for local sources without any pattern
support at all. Targets must be directories, since several files are going
into them.

## Patterns on the far side

A shell cannot expand `sftp://srv/out/*.csv` — it has no idea what is on the
server. `mpt` can: if the last path component of the **source** contains `*` or
`[…]`, the directory is listed and every matching file becomes a job.

```
$ mpt cp 'in/*.csv' out/
[3/3] in/data3.csv -> out/: 6 bytes in 3.30ms
[2/3] in/data2.csv -> out/: 6 bytes in 3.36ms
[1/3] in/data1.csv -> out/: 6 bytes in 3.40ms
3/3 jobs ok in 3.44ms
```

Quote the pattern so the shell leaves it alone, especially for local sources
where it would otherwise expand it itself.

Rules:

- It works on any protocol with `list` in the [capability
  matrix](../protocols/overview.md#what-each-one-can-do).
- **`?` is not a pattern character.** It starts the query part of a URL, so it
  could not be one. Use `*` or a character class.
- Dotfiles need a literal dot in the pattern, as in a shell: `*` does not match
  `.hidden`.
- Directories are not matched, only files.
- The targets must be directories.

A pattern that matches nothing is an error, on the assumption that you expected
something:

```
$ mpt cp 'in/*.nothing' out/
error: invalid URL: in/*.nothing matches no file (--allow-empty makes that fine)
```

For a [scheduled job](../automation/scheduling.md) over an inbox that is often
empty, say so:

```
mpt cp --allow-empty 'sftp://srv/outbox/*.csv' /data/incoming/
```

## Whole directories with `-r`

`-r` copies a directory with everything below it. The trailing slash decides
what travels, the way `rsync` reads it:

| Command | Result |
|---|---|
| `mpt cp -r export/ sftp://srv/in/` | the *contents* of `export` land in `/in/` |
| `mpt cp -r export sftp://srv/in/` | the directory itself lands as `/in/export/` |

```
$ mpt cp -r src_tree/ out/tree/
[2/2] src_tree/sub/one.txt -> out/tree/sub/: 4 bytes in 3.46ms
[1/2] src_tree/top.txt -> out/tree/: 4 bytes in 3.52ms
2/2 jobs ok in 3.57ms
```

The tree is listed first, the directories are created on the target, empty
ones included, and then every file is a job. `--parallel` applies to a tree
as it does to a list.

The source must be able to `list` and the target to `mkdir`; the [capability
matrix](../protocols/overview.md#what-each-one-can-do) says which schemes can.

Symbolic links are whatever the source's listing says they are: a link that
looks like a file has its content copied, a link that looks like a directory is
descended into. Nothing follows a link back up, and there is a depth limit of
64 as a backstop.

A name in a listing, of a pattern or a tree, is copied under exactly that name,
leading spaces and all. A name that cannot be one file on the target — `.`,
`..`, a blank one, one with control characters — is skipped with a warning
rather than renamed:

```
WARN mpt::batch::expand: skipping a listed name that cannot be copied: invalid URL:
     unsafe file name '..': refers to a directory name=..
```

## Skipping existing files and deleting the source

Two flags turn a copy into something you can run on a schedule.

**`--skip-existing`** leaves a target alone when it already holds a file of the
source's name and size, so with `-r` or a pattern a nightly run sends only what
is new. It is decided per target, and it compares sizes rather than content:
[Skipping with `--skip-existing`](reliability.md#skipping-with---skip-existing)
has the detail.

**`--delete-source`** removes the source once every target has it, which turns
a copy into a move:

```
$ mpt cp --delete-source export.csv sftp://srv/in/
export.csv -> sftp://srv/in/?timeout=30: 40000 bytes in 2.55ms
source deleted
```

Nothing is deleted while a single target is still missing the file, a checked
checksum must have matched first, and a source on a protocol that cannot delete
(`http://`) is refused before anything is transferred. Together the two flags
drain an inbox and leave it empty for the next run:

```
mpt cp -r --skip-existing --delete-source sftp://srv/outbox/ /data/inbox/
```

The directories stay; only the files are removed.

A target skipped as already there counts as having the file, and that rests
on its size. Where the target keeps a checksum file beside it (one that
`--hash` left there), the source is read once more and compared with it; if
they disagree the source stays and the copy fails. Without a checksum file the
size is all there is, and a warning in the log says so. Send with
`--hash` when the same files are later drained with `--delete-source`.

## Dry run

`--dry-run` expands everything — patterns, trees, profile names — and prints
the jobs without transferring anything:

```
$ mpt cp --dry-run 'in/*.csv' out/
[1/3] in/data1.csv -> out/
[2/3] in/data2.csv -> out/
[3/3] in/data3.csv -> out/
```

This is the cheap way to find out what a pattern matches on a server. Run it
before any command with `--delete-source`.

## Colliding targets

A list in which two jobs would write the same file is refused **before anything
is transferred**:

```
$ mpt cp -t out/ in/data1.csv in/data1.csv
error: invalid URL: jobs 1 and 2 write the same target out/data1.csv
```

They would otherwise share the same temporary file and destroy each other's
upload, and the survivor would be whichever finished last. The exit code is 2:
it is a mistake in the command, not a failure of the transfer.

Targets are compared by where they lead: a profile reference by what it
resolves to, and a path on a file system (local, SFTP, SCP, FTP) with
repeated slashes and `.` components evened out, so `out//a.csv`,
`out/./a.csv` and `out/a.csv` are one file. `..` is not resolved, and
object keys and HTTP paths are compared as written. Case is compared as
written too: on a file system that ignores it, `A.csv` and `a.csv` are one
file that the check does not catch.

## Parallelism

`--parallel <n>` (4 by default, `[defaults] parallel` in the configuration)
says how many jobs are in flight. Every job opens its own connections, which
has two consequences:

- **It is also the number of simultaneous logins on a host.** An `sshd` with
  the default `MaxStartups 10:30:100` starts refusing connections beyond ten
  unauthenticated connections at a time. Against a single SSH server, stay below ten;
  a higher value produces failures rather than speed.
- **With `--cache`, memory is the limit times the parallelism.** Four jobs at
  256M is a gigabyte.

Higher values pay off when the jobs are spread over several hosts, or when the
target is object storage, which has no login to throttle.

`--fail-fast` stops starting new jobs after the first failure and cancels the
ones that are running, for a batch where a single failure makes the rest
pointless.
