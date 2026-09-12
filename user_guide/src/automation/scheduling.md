# Scheduled and triggered runs

`mpt` has no scheduler, no retry queue and no state database, and that is
deliberate: cron, systemd timers and CI runners already do that job, and they
do it where the rest of your operational tooling can see it. What `mpt` offers
instead is a run that is safe to repeat and an outcome that is unambiguous
enough for those systems to act on.

## The shape of a repeatable job

Two flags do most of the work:

```
mpt cp -r --skip-existing --allow-empty \
    sftp://srv.example.com/outbox/ /data/incoming/
```

- **`--skip-existing`** leaves alone anything the target already holds under
  the same name and size, so a run that follows a partial one sends only what
  is missing, and a run over an unchanged tree sends nothing at all.
- **`--allow-empty`** stops a pattern that matched nothing from being an error.
  An inbox is empty most nights, and a job that alerts every night is a job
  nobody reads.

Add `--resume` when the files are large enough that finishing half of one is
worth keeping, and `--delete-source` when the point is to drain the source
rather than mirror it:

```
mpt cp -r --skip-existing --resume --delete-source \
    sftp://srv.example.com/outbox/ /data/incoming/
```

`--dry-run` first, especially with `--delete-source`. See
[Many files](../guide/many-files.md).

## cron

```cron
# m  h  dom mon dow  command
  17 *  *   *   *    /usr/local/bin/mpt cp -r --skip-existing --allow-empty \
                       sftp://srv.example.com/outbox/ /data/incoming/ 2>&1 | logger -t mpt
```

Use an absolute path: cron's `PATH` is usually `/usr/bin:/bin`. Send the
human-readable output somewhere it will be seen — `logger`, a file, a log
shipper — since cron's own mail rarely reaches anyone. And pick a minute that
is not zero, so that a fleet of machines does not arrive at the same server in
the same second.

cron gives a job almost no environment, so name the configuration explicitly
rather than relying on `$HOME`:

```cron
17 * * * * MPT_CONFIG=/etc/mpt/config.toml /usr/local/bin/mpt cp -r --skip-existing …
```

## systemd

A timer and a service are more work to write and much easier to operate: the
run has its own journal entries, its own resource limits, and a way to pass
credentials that never puts them in the environment of anything else.

```ini
# /etc/systemd/system/export-upload.service
[Unit]
Description=Upload the nightly export
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
User=exporter
Environment=MPT_CONFIG=/etc/mpt/config.toml
LoadCredential=sftp-password:/etc/mpt/sftp.pw
ExecStart=/usr/local/bin/mpt cp -r --skip-existing --allow-empty \
    /data/export/ mpt://prod/incoming/
```

```ini
# /etc/systemd/system/export-upload.timer
[Unit]
Description=Upload the nightly export

[Timer]
OnCalendar=*-*-* 02:17:00
RandomizedDelaySec=10m
Persistent=true

[Install]
WantedBy=timers.target
```

`Persistent=true` catches up a run that was missed because the machine was off;
`RandomizedDelaySec` spreads the load. Because the whole run reports one exit
code, `systemctl status export-upload` and `OnFailure=` work without any
wrapper script.

`LoadCredential=` puts the secret in a file under `$CREDENTIALS_DIRECTORY`,
readable only by that unit's user, and the configuration reads it from there:

```toml
[profiles.prod]
url      = "sftp://deploy@srv.example.com/data/"
key      = "/etc/mpt/deploy_ed25519"
password = { file = "${CREDENTIALS_DIRECTORY}/sftp-password" }
```

The `${VAR}` interpolation of the configuration file does the rest. Nothing
carries the secret in an environment variable, so it does not turn up in
`/proc` or in the journal.

One consequence to expect: a configuration that refers to
`${CREDENTIALS_DIRECTORY}` can only be read inside that unit. Running
`mpt config check` by hand fails with *refers to ${CREDENTIALS_DIRECTORY},
which is not set*, which is the interpolation doing its job — an unset variable
is an error rather than an empty string. Check such a file with
`systemd-run --pipe --unit=mpt-check --property=LoadCredential=… mpt config check`,
or set the variable for the length of one command.

## Credentials for an account that is not a person

A service account has no keychain to unlock and no shell to type into. Three
arrangements that work:

- **A file with tight permissions**, delivered by systemd's `LoadCredential`,
  by a Kubernetes secret mount, or by whatever manages the host —
  `{ file = "…" }`.
- **A command that fetches the secret**, if the platform has one —
  `{ cmd = "vault kv get -field=password secret/mpt/prod" }`. Anything that
  prints the secret on stdout works.
- **The AWS credential chain** for `s3://`, with the `s3-aws-auth` feature,
  which is what an instance role or a workload identity already provides.

Keep the configuration file readable only by the account, and set
`[policy] strict_permissions = true` so a wrong `chmod` is an error rather than
a warning nobody reads. Put the file somewhere the account cannot rewrite, and
name it with `--config` or `MPT_CONFIG`, so the policies in it are a control
rather than a suggestion. See
[Credentials and secrets](../configuration/credentials.md) and
[Policies](../configuration/policies.md).

## Reacting to files instead of the clock

A timer is the wrong tool when the work arrives at unpredictable times.
[`batch --follow`](../guide/job-lists.md#a-pipe-as-a-queue---follow) runs a job as
soon as its line arrives on standard input, so any program that prints one line
per event becomes a queue:

```
inotifywait -m -e close_write --format '%w%f sftp://srv.example.com/in/' /var/spool/out \
  | mpt batch - --follow --skip-existing
```

`close_write` rather than `create` matters: it fires when the writer is done,
not when the file appears. On systems without `inotify`, anything that polls
and prints will do.

The same pattern takes jobs from elsewhere:

```
# from a directory listing
find /export -name '*.pdf' -newermt '-1 day' -printf '%p sftp://srv/in/\n' | mpt batch -

# from a database
psql -At -c "select path, target from outbox where sent is null" \
  | tr '|' ' ' | mpt batch -

# from a spreadsheet export, with columns src and dst
mpt batch todays-jobs.csv --parallel 4
```

For a long-running `--follow` process, remember that it ends when its input
ends. Under systemd that is a `Type=simple` service with `Restart=always` and
the watcher in the same pipeline, so both come back together.

## How hard to push

[`--parallel`](../guide/many-files.md#how-many-at-once) is also the number of
simultaneous logins on the far side, which is why single digits are the useful
range against one server. Two limits matter on a shared machine: with
`--cache`, memory is the cache limit times the parallelism, and every job holds
its own connections for as long as it runs.

If the far side is a partner's server, the polite arrangement is a small
`--parallel`, a `RandomizedDelaySec`, and a `--timeout` generous enough that
their slow morning does not turn into your failed job.

## What to keep

For each run, three things are worth having afterwards: the exit code, the
human-readable summary, and — when the job matters — the JSON report.

```
mpt --json cp -r --skip-existing /data/export/ mpt://prod/incoming/ \
    > /var/log/mpt/$(date +%F-%H%M).json 2>> /var/log/mpt/mpt.log
```

The JSON tells you later which files moved and what their checksums were, which
is the question that actually gets asked when a partner says something did not
arrive. [Using mpt in scripts](scripting.md) has the fields.

## Next

The [protocol pages](../protocols/overview.md) collect what is specific to each
scheme, and the [reference](../reference/cli.md) is the lookup material.
