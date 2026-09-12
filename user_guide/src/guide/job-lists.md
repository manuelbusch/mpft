# Job lists and pipelines

Everything on the previous page starts from arguments you type. Often the jobs
come from somewhere else: a `find`, a database export, a spreadsheet, a queue
of events. `mpt batch` reads them from a file or from standard input.

```
mpt batch jobs.txt --parallel 8
find /export -name '*.pdf' -printf '%p sftp://srv/in/\n' | mpt batch -
mpt batch jobs.csv --dry-run
inotifywait -m -e close_write /var/spool/out --format '%w%f sftp://srv/in/' | mpt batch - --follow
```

A job is one source and its targets, as on the command line, and it runs
through the same pipeline: fan-out, checksums, signatures, atomic finishing,
resuming. Everything from [Many files](many-files.md) applies: `--parallel`,
`--skip-existing`, `--delete-source`, `--dry-run`, `-r`, and patterns in a
source.

## Three ways to write a list

The **line form** is the default, and the one to write by hand or from a shell:

```
# nightly exports
/data/export/sales.csv    sftp://srv.example.com/in/
/data/export/stock.csv    sftp://srv.example.com/in/   s3://bucket/in/
'/data/export/with space.csv'  sftp://srv.example.com/in/
```

One job per line: the source first, then one or more targets. Shell quoting
applies, so names with spaces work. Blank lines and `#` comments are ignored.

**JSON Lines** suits a program that generates jobs, because nothing needs
quoting:

```json
{"src": "/data/export/sales.csv", "dst": "sftp://srv.example.com/in/"}
{"src": "/data/export/stock.csv", "dst": ["sftp://srv.example.com/in/", "s3://bucket/in/"]}
```

`dst` is a string or a list. An unknown field is an error rather than a typo
that goes unnoticed.

**CSV or TSV** suits an export from a spreadsheet or a database. The header row
is required, one column must be `src`, and one or more must be `dst`:

```csv
id,src,dst,dst,note
1,/data/export/sales.csv,sftp://srv.example.com/in/,,daily
2,/data/export/stock.csv,sftp://srv.example.com/in/,s3://bucket/in/,daily
```

Columns that are not `src` or `dst` are ignored, so a query result can be used
as it comes out. Empty `dst` cells are ignored too, so rows may have different
numbers of targets.

The format is taken from the file name (`.jsonl`, `.csv`, `.tsv`) or guessed
from the first line: a `{` means JSON, a header naming `src` means CSV,
anything else is the line form. `--format lines|jsonl|csv` settles it when the
guess would be wrong.

## Running a list

```
$ mpt batch jobs.txt
[2/2] notes.txt -> out/: 8 bytes in 3.75ms
[1/2] data1.csv -> out/: 6 bytes in 3.82ms
2/2 jobs ok in 3.87ms
```

URLs in a list are what you would type on the command line: `mpt://` profile
names and options work. The credentials for every endpoint in the list are
fetched once, before the first job starts, rather than per job.
[`--via`](../server/relay.md) sends every job of the list through a relay.

A failure is reported against its job and the rest continue:

```
$ mpt batch jobs.txt
[2/2] FAILED in/nope.csv: I/O error: No such file or directory (os error 2)
[1/2] in/data1.csv -> out/: 6 bytes in 4.34ms
1/2 jobs ok in 4.40ms
error: 1 of 2 jobs failed
```

The whole list is checked for [colliding
targets](many-files.md#colliding-targets) before the first byte moves, so a
list that would have two jobs writing one file fails at once with exit code 2.

## Reading from a pipe

`mpt batch -` reads the list from standard input. The common case is `find`:

```
find /export -name '*.pdf' -newermt '-1 day' -printf '%p sftp://srv/in/\n' | mpt batch -
```

Anything that can print two words per line works: `awk` over a report, `psql
-t`, a script that decides where each file should go.

Note that the password cannot also come from stdin in this case — `mpt` refuses
`--password-stdin` together with `batch -` rather than reading one into the
other.

## Streaming input with `--follow`

By default the whole list is read before the first job starts. `--follow` does
not wait: each line is run as soon as it is complete, and the batch ends when
the input does.

```
$ ( echo "data1.csv out/"; sleep 1; echo "data2.csv out/" ) | mpt batch - --follow
[1] data1.csv -> out/: 6 bytes in 6.26ms
[2] data2.csv -> out/: 6 bytes in 6.93ms
2/2 jobs ok in 1.02s
```

The first job finished before the second line was written. Note the prefix:
`[1]` rather than `[1/2]`, because how many jobs there will be is not yet
known.

This turns a pipe into a work queue. The natural partner is a file-system
watcher:

```
inotifywait -m -e close_write --format '%w%f sftp://srv/in/' /var/spool/out \
  | mpt batch - --follow --skip-existing
```

or any program that decides jobs as it goes. Three things behave differently
in this mode:

- **Credentials are fetched when they are first needed.** An endpoint that only
  appears in line 400 has its secret resolved then, not at the start.
- **A bad line is reported and skipped**, rather than stopping everything:

  ```
  [1] data1.csv -> out/: 6 bytes in 6.26ms
  [2] FAILED nope.csv: I/O error: No such file or directory (os error 2)
  [3] data2.csv -> out/: 6 bytes in 6.93ms
  2/3 jobs ok in 1.02s
  error: 1 of 3 jobs failed
  ```

  The same goes for a line that cannot be parsed or that would write a file an
  earlier job already wrote; it is named by its line number and the rest carry
  on.
- **CSV needs its header row first**, which is the price of not reading ahead.

Ctrl-C stops the reading and the running jobs alike.

## Progress and JSON output

For a person, the progress line counts jobs rather than bytes:

```
12/120 jobs, 1 failed, 1.4 GiB  22.0 MiB/s
```

For a program, `--json` writes one JSON object per job to stdout as it
finishes — JSON Lines, with a `job` field holding its position in the list:

```
$ mpt --json batch jobs.txt 2>/dev/null
{"cancelled":false,"error":"I/O error: No such file or directory (os error 2)","job":2,"ok":false,"source":"in/nope.csv"}
{"bytes_read":6,"check":null,"digests":{},"elapsed_ms":3,"job":1,"ok":true,"remove_error":null,"source":"in/data1.csv","source_removed":null,"targets":[{"attempts":1,"bytes":6,"cancelled":false,"elapsed_ms":3,"error":null,"ok":true,"sidecar":null,"signature":null,"skipped":false,"target":"out/"}]}
```

Objects arrive as jobs complete, so `jq -c` can follow a long run live rather
than waiting for the end. The human-readable lines stay on stderr throughout.
[Using mpt in scripts](../automation/scripting.md) has the field list.

## Stopping after the first failure

`--fail-fast` stops starting new jobs after the first failure and cancels those
already running:

```
$ mpt batch jobs.txt --fail-fast --parallel 1
WARN mpt::batch: failed, stopping the batch job=1
[1/9] FAILED nosuch.csv: I/O error: No such file or directory (os error 2)
[2/9] FAILED export2.csv: cancelled
[3/9] FAILED export3.csv: cancelled
…
0/9 jobs ok in 384.25µs (stopped after the first failure)
error: 9 of 9 jobs unfinished: interrupted
```

Every job that never ran is listed as cancelled, so the output accounts for the
whole list. Use it when one failure makes the rest pointless — bad credentials,
a full disk — and leave it off when each job stands on its own.

Note that a run stopped by `--fail-fast` [exits with
130](../reference/exit-codes.md#--fail-fast), the code for Ctrl-C. Without
the flag the exit code is aggregated over the jobs as [Exit
codes](../reference/exit-codes.md#when-several-things-fail-at-once) describes.
