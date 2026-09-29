# Exit codes

| Code | Meaning |
|---|---|
| 0 | everything succeeded |
| 1 | a target failed, or the far side reported an error |
| 2 | the command line, a URL or the configuration is wrong |
| 3 | a checksum did not match, or a signature was missing, invalid or not trusted |
| 4 | authentication failed |
| 130 | stopped with Ctrl-C or `SIGTERM` |

Code 2 is also clap's own code for a malformed command line, which is why a bad
URL and a bad configuration file join it there: all three mean "the request was
wrong", and none of them will come right on a retry.

## Error kinds and their codes

| Kind of failure | Code |
|---|---|
| checksum mismatch; signature missing, invalid, untrusted or too old | 3 |
| authentication rejected: wrong password, no accepted key, host key not trusted, a signing key's passphrase missing or wrong; access refused (HTTP and WebDAV 401 or 403, S3 access denied or a signature that does not match) | 4 |
| unusable configuration or trust file (`allowed_signers`, keyring), a signing key file that cannot be read or is no key, no signing key at all, unknown profile, unsupported scheme or operation, bad URL or option, `insecure=true` where the policy forbids it, `mailto:` without an SMTP server; a flag or setting with a value that does not parse (an address, a size, a duration) or that is not allowed as given (a flag a relay cannot honour, `--delete-source` for a server without `--allow-delete`, `require_signature` without trusted keys), a `--password-file` that cannot be read | 2 |
| cancelled | 130 |
| everything else: I/O, remote errors, timeouts, transport failures | 1 |

A host-key refusal counts as authentication (4), because that is the stage it
happens at and because the answer is the same: something about how you are
identifying the other side needs attention before a retry can help.

A file that is not there is kind `io` with code 1 on every protocol: a local
path, HTTP and WebDAV 404 or 410, a missing S3 object, SFTP's "no such file"
and the message `scp` gives for it. So is a file the server refuses to open
(SFTP's and `scp`'s "permission denied"), which is about the file rather than
the login. FTP says both with the same reply, 550, and its reply is kept as
kind `remote`.

## Several failures

**A fan-out** collects the code of every failed target. If they all agree, that
code is used; otherwise the result is 1.

```
mpft cp report.pdf sftp://a/ sftp://b/     # both refuse the password  → 4
mpft cp report.pdf sftp://a/ sftp://b/     # one refuses, one times out → 1
```

**A batch** applies the same rule over its jobs, counting each failed job by
the code it would have had on its own. A batch that failed entirely on
authentication exits 4; a mixed batch exits 1.

A line in a job list that never became a job — unreadable, unresolvable, or
writing a file an earlier job writes — counts as a failure with its own code,
which is usually 2.

**With a single target** the code is simply that target's.

**Through a relay** the fan-out runs on the relay, which exits with the code
`cp` would have given; `cp --via` reports that code for the job and applies
the batch rule over jobs. A relay that could not be reached or logged into
counts as a failed job with code 4 or 1, like any other endpoint.

**`mpft serve` and `mpft relay --listen`** exit 0 after Ctrl-C or `SIGTERM`,
whatever the jobs they were running did (130 after a third one, which does not
wait for them); those outcomes are in the API and in the log.

## Zero without a transfer

Some outcomes are 0 although nothing was transferred:

- every target was skipped by `--skip-existing`;
- a pattern matched nothing and `--allow-empty` was given;
- a job list was empty;
- `--dry-run`.

A script that needs to know whether bytes actually moved should read
`bytes_read` from the [JSON report](../automation/scripting.md#the-json-report)
rather than infer it from the exit code.

## Failures after a completed copy

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

A batch stopped by `--fail-fast` exits with the code of the failure that
stopped it, under the batch rule above: the jobs it cancelled after that
failure count as consequences, not as failures of their own. 130 is reserved
for a run that was interrupted, so a script can tell the two apart.

```
$ mpft cp --fail-fast --parallel 1 -t wall/ a b ; echo $?    # wall is a file
[1/2] FAILED copy a -> wall/: I/O error: Not a directory (os error 20)
[2/2] FAILED b: cancelled
0/2 jobs ok in 7.78ms (stopped after the first failure)
error: 2 of 2 jobs failed
1
```
