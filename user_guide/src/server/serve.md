# Jobs over HTTP with `mpt serve`

`mpt serve` takes transfer jobs over HTTP and runs them through the same
pipeline as `cp` and `batch`. A program submits a job and gets an id back; it
then polls the job or follows it over a WebSocket, transfer by transfer, and
reads the same report that `--json` prints. This is the way in for a web
application, a workflow engine or a service written in another language that
should not shell out to `mpt` for every file.

The server is a cargo feature that is **not** in the default build:

```
cargo build --release --features server
```

[Choosing protocols](../getting-started/installation.md#choosing-protocols)
lists the features. The [HTTP API](../reference/api.md) page is the reference
for every route, field and event; this page explains how to run the server
and what it lets a client do.

## Starting it

The server needs a bearer token unless it listens on loopback only, and it
needs profiles, because a job may only name `mpt://<profile>/` endpoints
unless told otherwise. Both go in the [configuration
file](../configuration/file.md):

```toml
[server]
token = { env = "MPT_API_TOKEN" }     # any credential reference works here

[profiles.inbox]
url = "/srv/inbox/"

[profiles.prod]
url = "sftp://deploy@srv.example.com/data/incoming/"
key = "~/.ssh/prod_ed25519"

[profiles.archive]
url = "s3://archive-bucket/reports/"
```

```
$ MPT_API_TOKEN=… mpt serve
```

That listens on `127.0.0.1:7788`. A first job, with `curl`:

```
$ curl -H "Authorization: Bearer $MPT_API_TOKEN" \
       -d '{"src": "mpt://inbox/report.pdf", "dst": ["mpt://prod/", "mpt://archive/"]}' \
       localhost:7788/v1/jobs
{"id":"7be835687082d16fa4bf1d11f6686297","state":"queued","transfers":1,"url":"/v1/jobs/7be835687082d16fa4bf1d11f6686297"}
```

The answer is `202 Accepted`. The job runs on its own; `GET` on the `url`
shows where it stands.

Without a token the server refuses to bind anywhere but loopback:

```
error: refusing to listen on 0.0.0.0:7788 without a token: set [server] token
       (or --token-env), or bind to 127.0.0.1
```

Every setting has a flag and a key: `--bind` and `[server] bind`,
`--token-env` and `[server] token`, and so on. The flag wins. [Configuration
keys](../reference/configuration.md#server) lists them with their defaults.

## Jobs and batches

A **job** is one source with one or more targets, the same thing `mpt cp`
does, and goes to `POST /v1/jobs` (the [glossary](../appendix/glossary.md)
keeps the server's *job* and *transfer* apart from the command line's). A **batch** is a list of them, the same
thing `mpt batch` does, and goes to `POST /v1/batches` either as JSON or as a
[job list](../guide/job-lists.md#three-ways-to-write-a-list) in one of the
three text forms:

```
$ curl -H "Authorization: Bearer $MPT_API_TOKEN" -H 'Content-Type: text/plain' \
       --data-binary 'mpt://inbox/report.pdf mpt://archive/
mpt://inbox/data1.csv mpt://archive/' \
       'localhost:7788/v1/batches?parallel=2&fail_fast=true'
{"id":"ccdddba96fe81f58fbc3ebfa385fc749","state":"queued","transfers":2,"url":"/v1/jobs/ccdddba96fe81f58fbc3ebfa385fc749"}
```

A source may be a [pattern](../guide/many-files.md#patterns-on-the-far-side)
or, with the `recursive` option, a [directory](../guide/many-files.md#whole-directories-with--r).
Either is expanded on the server when the job starts, and the transfers the
expansion produced appear in the job as if they had been listed.

Both kinds are then the same thing: a job with one or more **transfers**.
Each transfer has its own state, its own byte counter and, once it is over,
its own report.

## Following a job

`GET /v1/jobs/{id}` returns the job with every transfer. The job as a whole
goes `queued`, `preparing`, `running`, and ends as `done`, `failed` or
`cancelled`. `preparing` is where URLs are resolved, patterns and trees are
expanded and the targets are checked against what other jobs are writing; a
job that fails there carries an `error` and no transfers.

```
$ curl -s -H "Authorization: Bearer $MPT_API_TOKEN" localhost:7788/v1/jobs/7be835687082d16fa4bf1d11f6686297
{
  "id": "7be835687082d16fa4bf1d11f6686297",
  "kind": "single",
  "state": "done",
  "submitted_at": "2026-09-12T07:59:31Z",
  "started_at": "2026-09-12T07:59:31Z",
  "finished_at": "2026-09-12T07:59:31Z",
  "attempt": 1,
  "options": {},
  "stopped_early": false,
  "progress": {
    "bytes": 40000,
    "total": 40000,
    "transfers": {"total": 1, "queued": 0, "running": 0, "done": 1, "failed": 0, "cancelled": 0}
  },
  "transfers": [
    {
      "index": 0,
      "id": "7be835687082d16fa4bf1d11f6686297:0",
      "src": "mpt://inbox/report.pdf",
      "dst": ["mpt://prod/", "mpt://archive/"],
      "state": "done",
      "progress": {"read": 40000, "total": 40000},
      "report": { "ok": true, "bytes_read": 40000, "targets": [ … ] }
    }
  ]
}
```

`report` is the object `--json` prints for a copy, described under [The JSON
report](../automation/scripting.md#the-json-report). A transfer that failed
has an `error` with a `kind` and a `message` instead.

A WebSocket on `/v1/jobs/{id}/events` pushes the same information as it
happens: a `snapshot` first, then `progress` frames while bytes move, a
`transfer_done` per transfer and a final `done`. `/v1/events` carries every
job's events on one connection. The [event
reference](../reference/api.md#websocket-events) has the frames.

`GET /v1/jobs?state=running` lists jobs, newest first. `DELETE /v1/jobs/{id}`
cancels one: running transfers stop and their partial files are removed, as
with [Ctrl-C](../guide/reliability.md#ctrl-c). A job still `preparing` stops
where it is, in a listing, a credential command (which is killed) or the
creation of a tree's directories.

## What a job may set

A job's `options` object carries the settings that `cp` and `batch` take as
flags: `hash`, `check`, `skip_existing`, `atomic`, `resume`, `cache`,
`retries`, `timeout`, and for a batch `parallel` and `fail_fast`. What the job
does not set comes from the server's own settings: the global flags of `mpt
serve` and `[defaults]` apply to every job it runs, so a server started with
`--hash sha256 --timeout 120` writes checksums with that timeout unless a job
says otherwise. `--sign` on the server signs every job's checksum file. The
[options table](../reference/api.md#job-options) has the full list.

Two things a job may not do without the operator's say-so:

- **Delete its source.** `delete_source` is refused unless the server runs
  with `--allow-delete` or `[server] allow_delete = true`:

  ```
  {"error":{"kind":"invalid_option","message":"delete_source is not allowed on this server ([server] allow_delete)"}}
  ```

  A server started with `--delete-source` and without `--allow-delete` does
  not start, since every job would delete its source.
- **Grow without bound.** `max_transfers` caps what one job may hold after
  patterns and trees are expanded. A list longer than that is refused immediately;
  a pattern or a tree that turns out that large fails the job with kind
  `too_many_transfers`, and the listing stops there rather than reading a huge
  tree to the end. `max_queued` caps the jobs not yet finished; a `POST`
  beyond it gets `429` with a `Retry-After` header.

## What a client can reach

By default a job may only name `mpt://<profile>/…` endpoints. The
configuration therefore decides which hosts, credentials and options the API
can use, and no password ever travels in a request. A local directory is a
profile with a local `url`. Anything else is refused:

```
{"error":{"kind":"invalid_url","message":"invalid URL: /etc/hosts: only mpt://<profile>/ endpoints are accepted (set [server] urls = \"any\" or --allow-any-url to allow others)"}}
```

A reference may not add `?options` either, because [options on a reference
replace the profile's](../configuration/profiles.md#overriding-a-profile):
`?known_hosts=off` or `?key=` would undo what the profile fixes.
`[server] profiles = ["inbox", "prod"]` narrows the API to some of the
profiles the configuration defines.

`urls = "any"` or `--allow-any-url` lets a job name any URL, as on the
command line. Use it only where every client is trusted as much as the
server's user: a URL may then carry a password, which lands in the journal if
there is one.

Whoever holds the token can use every allowed profile **as the server's
user**, including the profile's credential providers, and can read and write
whatever those profiles reach. A profile meant for the API should therefore
point at the directories it is meant to serve and nothing wider, not at a
home directory or a bucket root.

Two further points of the design:

- A misconfigured profile or a failing credential provider is described in
  the server's log. The client learns only which profile to ask about:
  `profile 'prod' is misconfigured; see the server log`.
- Transfers, reports and errors name endpoints as they were submitted
  (`mpt://inbox/report.pdf`, or `mpt://inbox/a.csv` for a file a pattern
  matched), not by what the profile resolves to. A URL given in full under
  `urls = "any"` appears with its password masked.

## Securing the listener

The server speaks plain HTTP. For anything beyond the local machine put a
reverse proxy with TLS in front of it, and let the proxy do rate limiting per
client address. The server itself only slows guessing down: a wrong token,
on any route including the health check, is answered after 250 ms, and
wrong tokens are answered one at a time over the whole server, so parallel
requests guess no faster. A client that is refused slows down the other
refused clients, never one with the right token.

Requests that carry an `Origin` header are refused with `403`. Such a request
comes from a browser acting for a web page, and the API is not for pages:
without the rule, any site the operator visits could post jobs to a token-less
server on loopback or open its WebSocket. A client of your own does not send
the header. The token goes in the `Authorization` header for the WebSocket
too; there is no `?token=` in the URL.

A server without a token also answers only requests whose `Host` is
`localhost`, a `127.x.x.x` address or `[::1]`, with any port; anything else
gets `403`. A page could otherwise point a name of its own at 127.0.0.1
(DNS rebinding), and its requests would then be same-origin and carry no
`Origin` header.

The health check answers without a token, but says only whether the server is
up:

```
$ curl localhost:7788/v1/healthz
{"ok":true}
$ curl -H "Authorization: Bearer $MPT_API_TOKEN" localhost:7788/v1/healthz
{"accepting":true,"jobs":{"queued":0,"running":0},"ok":true,"version":"0.1.0"}
```

It answers `503` while the server is shutting down.

## The journal and restarts

Without a journal, jobs live in memory and a restart forgets them. With one,
every accepted job is appended to a JSON Lines file, created with mode `0600`,
and closed there when it is over:

```toml
[server]
journal = "~/.local/state/mpt/jobs.jsonl"
```

After a restart, the jobs the file still shows as open run again with
`attempt` raised by one. That includes the jobs a shutdown cancelled after
its grace period ran out, but not a job a client cancelled with `DELETE`, nor
one that finished on its own while the shutdown was cancelling the rest. A file target is safe to run twice, since a
transfer either finished or left only a `.mpt-part`; a mail target may
deliver twice, and a `delete_source` job whose source is already gone fails
the second time. Finished jobs do not survive a restart.

The file is compacted to the jobs still open when the server starts, and
again while it runs whenever it has grown past 16 MiB and twice the size it
had after the last compaction; each rewrite goes through a temporary file,
so a crash in the middle loses nothing.

A job from the journal is judged by the settings the server has now, as a
new submission would be: its URLs against `urls` and `profiles`,
`delete_source` against `allow_delete`, its length against `max_transfers`
and its options. One they no longer allow is not run; it is closed as
`failed` with an error that begins `not run again after the restart:`.

`retention` says how long finished jobs stay available over the API, 24 hours
by default; `"0"` keeps them until the server stops.

## Stopping it

Ctrl-C stops the server taking jobs, waits `grace` for the running ones and
exits 0. A second Ctrl-C cancels them immediately. Those cancelled jobs are the
ones a journal runs again. A third exits with 130 without waiting any longer.

```
$ mpt serve
^C
interrupted, finishing the running jobs (Ctrl-C again cancels them)…
```

`SIGTERM` does the same, so `systemctl stop` and `docker stop` drain the
server rather than kill it. Give the unit a `TimeoutStopSec` longer than
`grace`, or systemd cuts the drain short with `SIGKILL`.

## Logging

With `-v` the log names job ids, sizes and outcomes but no hosts or paths;
`-vv` adds them along with everything else at debug level. [Logging and
observability](../automation/logging.md#the-server-and-the-relay) lists what
the server reports at each level. Under systemd the log goes to the journal
like any other service; [Scheduled and triggered
runs](../automation/scheduling.md#systemd) shows a unit, and a server differs
from it in `Type=simple`, no timer, and the stop signal noted above.

## A client in Python

`examples/python-client` in the repository is a small `uv` project that
submits jobs, follows them over the WebSocket with a progress bar per
transfer, and lists and cancels them. Its `demo.sh` builds `mpt` with the
server feature, starts it on temporary directories and runs the client
through a single transfer, a batch with a pattern, a checked copy and a
refused profile. It is an example to copy from rather than a package to
depend on.
