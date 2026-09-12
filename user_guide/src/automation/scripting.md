# Using mpt in scripts

A calling program needs three things: separated output streams, an exit code
that says what kind of failure occurred, and a report it can parse. This page
covers all three.

## stdout and stderr

Everything a person reads (result lines, warnings, the progress display) goes
to **stderr**. Everything a program reads goes to **stdout**, and only with
`--json`. Without it, stdout stays empty except for the few commands whose
output *is* data (`ls`, `schemes`, `profiles`, `completions`, `man`).

```
mpt --json cp report.pdf sftp://srv/in/ > report.json      # the machine's copy
mpt --json cp report.pdf sftp://srv/in/ 2>/dev/null | jq . # ignore the human's
mpt cp report.pdf sftp://srv/in/ 2>> transfer.log          # keep the human's
```

So a log file and a parser can be fed from one run without either seeing the
other's output.

## The exit code

[Exit codes](../reference/exit-codes.md) lists what each one means and which
error counts as which. What a script does with them:

| Code | What to do about it |
|---|---|
| 0 | carry on |
| 1 | retry on the next run, and alert if it keeps happening |
| 2 | fix the command or the configuration; retrying will not help |
| 3 | do **not** use the file, and alert loudly |
| 4 | the credentials need attention; retrying will not help |
| 130 | a person stopped the run; not a transfer failure |

```
$ mpt cp nosuch.pdf out/            ; echo $?     # 1
$ mpt cp --nosuchflag x y           ; echo $?     # 2
$ mpt cp mailto:x@example.com out/  ; echo $?     # 2
$ mpt ls mpt://nosuch/              ; echo $?     # 2
```

The distinction that matters most is 2 and 4 against 1: a wrong URL or a
rejected password will fail again in five minutes, a refused connection may
not. Code 3 deserves its own branch: the bytes arrived but cannot be trusted,
which is a different problem from a transfer that failed.

With several targets or jobs the code is [aggregated](../reference/exit-codes.md#when-several-things-fail-at-once):
1 when the outcomes are mixed, the specific code when every failure was of the
same kind.

```sh
#!/bin/sh
set -u
# No `set -e`: the script inspects the exit code itself.
mpt --json cp --hash sha256 /data/export.csv sftp://srv.example.com/incoming/ > last-run.json
case $? in
  0) mv /data/export.csv /data/sent/ ;;
  3) echo "export.csv did not verify — not marking it as sent" >&2; exit 3 ;;
  4) echo "credentials rejected; check the key store" >&2; exit 4 ;;
  *) echo "transfer failed, will retry on the next run" >&2; exit 1 ;;
esac
```

## The JSON report

`--json` prints one object for a copy. The same object is what the [HTTP
API](../reference/api.md#the-job-object) returns as a transfer's `report`
and what a [relay](../server/relay.md) sends back.

```
$ mpt --json cp --check out/report.pdf back/ 2>/dev/null
{
  "bytes_read": 8,
  "check": {
    "actual": "d4e4877bac978b7952f0d544fc52ebff5411d351d129f1f056fa43f11da9af2b",
    "algo": "sha256",
    "expected": "d4e4877bac978b7952f0d544fc52ebff5411d351d129f1f056fa43f11da9af2b",
    "ok": true,
    "signer": null
  },
  "digests": {
    "sha256": "d4e4877bac978b7952f0d544fc52ebff5411d351d129f1f056fa43f11da9af2b"
  },
  "elapsed_ms": 2,
  "ok": true,
  "remove_error": null,
  "source": "out/report.pdf",
  "source_removed": null,
  "targets": [
    {
      "attempts": 1,
      "bytes": 8,
      "cancelled": false,
      "elapsed_ms": 2,
      "error": null,
      "ok": true,
      "sidecar": null,
      "signature": null,
      "skipped": false,
      "target": "back/"
    }
  ]
}
```

| Field | Meaning |
|---|---|
| `source`, `bytes_read`, `elapsed_ms` | what was read, and how long the whole copy took |
| `ok` | every target succeeded **and** the check, if any, agreed |
| `targets[]` | one object per target, in the order they were given |
| `targets[].ok`, `.error`, `.cancelled` | that target's outcome |
| `targets[].bytes`, `.elapsed_ms`, `.attempts` | what it took and how often it was tried |
| `targets[].skipped` | it already had the file (`--skip-existing`) |
| `targets[].sidecar`, `.signature` | the extra files written beside it, or `null` |
| `digests` | algorithm → hex, empty unless a checksum was computed |
| `check` | `algo`, `ok`, `expected`, `actual`, `signer`; `null` without `--check` |
| `source_removed`, `remove_error` | `--delete-source`: whether the source went, and why not |

`ok` is the field to branch on. It is not simply "no error": a copy whose
targets all succeeded but whose checksum did not match is `false`.

`mpt --json ls <url>` prints the listing as an array, with `modified` in RFC
3339:

```
$ mpt --json ls .
[
  {
    "is_dir": true,
    "modified": "2026-09-10T18:15:29Z",
    "name": "out",
    "size": null
  },
  …
]
```

## A batch: one object per job

For [`cp -t` and `batch`](../guide/job-lists.md) the output is **JSON Lines**:
one object per job, written as that job finishes, with a `job` field holding
its position in the list. Objects arrive as the run progresses, so a consumer
can follow a long batch live instead of waiting for the end.

```
$ mpt --json batch jobs.txt 2>/dev/null | jq -c 'select(.ok | not) | {job, source, error}'
{"job":2,"source":"nosuch.pdf","error":"I/O error: No such file or directory (os error 2)"}
```

A job whose source could not be opened has a shorter object (`source`, `ok`,
`error`, `cancelled`, `job`), because there was never a transfer to report on.
Read `.ok` rather than assuming `.targets` exists.

Some pipelines that come up:

```
# which targets failed, and why
mpt --json cp report.pdf sftp://a/ ftp://b/ 2>/dev/null \
  | jq -c '.targets[] | select(.ok | not) | {target, error}'

# total bytes moved by a batch
mpt --json batch jobs.txt 2>/dev/null | jq -s 'map(.bytes_read // 0) | add'

# the digest, for a manifest
mpt --json cp --hash sha256 report.pdf sftp://srv/in/ 2>/dev/null | jq -r '.digests.sha256'

# follow a long batch live
mpt --json batch jobs.txt 2>/dev/null | jq -c '{job, ok}'
```

Note that `--json` switches the progress display off by itself, so nothing
redraws over the output.

## Seeing what would happen

[`--dry-run`](../guide/many-files.md#dry-run) prints the jobs a
command would run and transfers nothing, and with `--json` it prints them as
one object per job. In a script that builds its own arguments, a dry run is
the cheapest check available, especially in front of `--delete-source`.

## Logging

Log lines go to stderr, and the level is decided in this order:

1. `$RUST_LOG`, which wins over everything and takes the full `tracing`
   filter syntax (`mpt::protocols::ssh=debug,warn`)
2. `-v` (info), `-vv` (debug), `-vvv` (trace)
3. `[defaults] log` in the configuration
4. `warn`, the built-in default

Note the first line: with `RUST_LOG` set in the environment, `-vv` does
nothing. That is convenient in a CI job that sets it globally and surprising
anywhere else.

At the default level a run is quiet unless something deserves attention: a
plaintext password, a host key added on first use, a partial file that could
not be removed. Those are warnings that a log should keep.

## Colour

`--color auto` (the default) emits colour only when stderr is a terminal, and
honours `NO_COLOR`. Piping therefore produces plain text without any flag:

```
$ mpt cp report.pdf out/ 2>&1 | cat -v
report.pdf -> out/: 8 bytes in 6.32ms
```

`--color always` wins over `NO_COLOR` and over the absence of a terminal,
which suits a CI system that renders ANSI codes.
`--color never` switches it off for good. `[defaults] color` sets the default.

## Interruption and exit code 130

`SIGINT` stops the run and exits 130; a script that runs `mpt` under a
supervisor should treat that as "someone stopped this", not as a transfer
failure. What is left behind, and what `--resume` keeps, is under
[Ctrl-C](../guide/reliability.md#ctrl-c).
