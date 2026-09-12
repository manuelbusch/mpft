# Exit codes

| Code | Meaning |
|---|---|
| 0 | everything succeeded |
| 1 | a target failed, or the far side reported an error |
| 2 | the command line, a URL or the configuration is wrong |
| 3 | a checksum did not match, or a signature was missing, invalid or not trusted |
| 4 | authentication failed |
| 130 | stopped with Ctrl-C |

Code 2 is also clap's own code for a malformed command line, which is why a bad
URL and a bad configuration file join it there: all three mean "the request was
wrong", and none of them will come right on a retry.

## Which errors count as which

| Kind of failure | Code |
|---|---|
| checksum mismatch; signature missing, invalid, untrusted or too old | 3 |
| authentication rejected: wrong password, no accepted key, host key not trusted | 4 |
| unusable configuration, unknown profile, unsupported scheme or operation, bad URL or option | 2 |
| cancelled | 130 |
| everything else: I/O, remote errors, timeouts, transport failures | 1 |

A host-key refusal counts as authentication (4), because that is the stage it
happens at and because the answer is the same: something about how you are
identifying the other side needs attention before a retry can help.

## When several things fail at once

**A fan-out** collects the code of every failed target. If they all agree, that
code is used; otherwise the result is 1.

```
mpt cp report.pdf sftp://a/ sftp://b/     # both refuse the password  → 4
mpt cp report.pdf sftp://a/ sftp://b/     # one refuses, one times out → 1
```

**A batch** applies the same rule over its jobs, counting each failed job by
the code it would have had on its own. A batch that failed entirely on
authentication exits 4; a mixed batch exits 1.

A line in a job list that never became a job — unreadable, unresolvable, or
writing a file an earlier job writes — counts as a failure with its own code,
which is usually 2.

**With a single target** the code is simply that target's.

## Success that is not a copy

Some outcomes are 0 although nothing was transferred:

- every target was skipped by `--skip-existing`;
- a pattern matched nothing and `--allow-empty` was given;
- a job list was empty;
- `--dry-run`.

A script that needs to know whether bytes actually moved should read
`bytes_read` from the [JSON report](../automation/scripting.md#the-json-report)
rather than infer it from the exit code.

## Failures that leave a completed copy

`--delete-source` can fail after the transfer succeeded. The copy stands, the
source is still there, and the run exits **1**:

```
error: copied, but deleting the source /data/export.csv failed: …
```

In JSON this is `"source_removed": false` with `remove_error` set. The same
shape applies to a checksum file that could not be written after a successful
transfer: that target is reported as failed, and the message says the file
itself arrived.

## `--fail-fast`

A batch stopped by `--fail-fast` currently exits **130**, the code for Ctrl-C,
rather than the code of the failure that stopped it. A script that treats 130
as "a person interrupted this" needs to account for that when it passes
`--fail-fast`.

## Next

That is the reference. The appendix covers [the
library](../appendix/library.md), [Windows](../appendix/windows.md) and
[troubleshooting](../appendix/troubleshooting.md).
