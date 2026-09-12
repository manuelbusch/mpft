# HTTP API

Lookup material for [`mpt serve`](../server/serve.md); the channel protocol
of `mpt relay` is on [its own page](relay-protocol.md). Every request to the
server carries `Authorization: Bearer <token>`; the only exception is the health
check.

## Routes

| Route | What it does |
|---|---|
| `POST /v1/jobs` | one transfer; `202` with `{"id", "url", "state", "transfers"}` |
| `POST /v1/batches` | many transfers; the same answer |
| `GET /v1/jobs?state=<state>&limit=<n>` | job summaries without transfers, newest first; `limit` defaults to 100, at most 1000 |
| `GET /v1/jobs/{id}` | the job with every transfer |
| `GET /v1/jobs/{id}/transfers/{index}` | one transfer |
| `DELETE /v1/jobs/{id}` | cancel; `202` while it stops, `200` with the final state once it is over |
| `GET /v1/jobs/{id}/events` | WebSocket: a `snapshot`, then the job's events until `done` |
| `GET /v1/events` | WebSocket: every job's events; stays open |
| `GET /v1/healthz` | `{"ok": true}`; with the token also `version`, `accepting` and job counts. `503` while shutting down |

## Submitting

`POST /v1/jobs` takes JSON. `dst` is one URL or a list:

```json
{"src": "mpt://inbox/report.pdf", "dst": ["mpt://prod/", "mpt://archive/"], "options": {"hash": "sha256"}}
```

`POST /v1/batches` takes either JSON, with the options beside the list:

```json
{"jobs": [{"src": "mpt://inbox/*.csv", "dst": "mpt://prod/"}, {"src": "mpt://inbox/report.pdf", "dst": ["mpt://prod/", "mpt://archive/"]}], "options": {"parallel": 2}}
```

or a [job list](../guide/job-lists.md#three-ways-to-write-a-list) as
`application/x-ndjson`, `text/csv` or `text/plain`, the forms `mpt batch`
reads, with the options in the query string:

```
POST /v1/batches?parallel=2&fail_fast=true
Content-Type: text/plain

mpt://inbox/report.pdf mpt://archive/
mpt://inbox/data1.csv mpt://archive/
```

A body without a `Content-Type`, or with `application/x-www-form-urlencoded`
as `curl -d` sends, is read as JSON. The body is limited to
`[server] max_body`, 8 MiB by default.

## Job options

Everything is optional. What a job leaves out comes from the server's own
flags and `[defaults]`.

| Option | Type | Flag of `cp` | Notes |
|---|---|---|---|
| `hash` | `"sha256"`, `"sha512"`, `"blake3"` | `--hash` | |
| `check` | boolean | `--check` | |
| `skip_existing` | boolean | `--skip-existing` | |
| `delete_source` | boolean | `--delete-source` | needs `[server] allow_delete` |
| `atomic` | boolean | `--no-atomic` inverts it | |
| `resume` | boolean | `--resume` | needs `atomic` |
| `cache` | boolean | `--cache` | bounded by the server's `--cache-limit` |
| `retries` | integer | `--retries` | needs `cache` |
| `timeout` | integer, seconds | `--timeout` | `0` disables it |
| `allow_empty` | boolean | `--allow-empty` | |
| `recursive` | boolean | `-r` | |
| `parallel` | integer, at least 1 | `--parallel` | transfers of this job in flight; capped by the server's `parallel` |
| `fail_fast` | boolean | `--fail-fast` | |

An unknown option is refused, and the message lists the ones that would have
been accepted. The same object is the `options` of a [relay
header](relay-protocol.md#the-header), where `check`, `resume`, `recursive`, `allow_empty`,
`parallel` and `fail_fast` are refused as `not over a relay`, and
`delete_source` is refused unless the header names a `src` the relay reads
itself.

## The job object

| Field | Meaning |
|---|---|
| `id` | 32 hex characters |
| `kind` | `single` or `batch` |
| `state` | `queued`, `preparing`, `running`, `done`, `failed`, `cancelled` |
| `submitted_at`, `started_at`, `finished_at` | UTC timestamps; the last two absent until they happen |
| `attempt` | `1`, or more for a job the journal ran again |
| `options` | what the job set, nothing else |
| `stopped_early` | `true` when `fail_fast` stopped the batch |
| `error` | `{"kind", "message"}` for a job that failed in `preparing`; then there are no transfers |
| `progress` | `bytes`, `total` (absent while unknown) and `transfers` with counts per state |
| `transfers` | the list below; absent in `GET /v1/jobs` listings |

`done` means every transfer succeeded; one failure makes the job `failed`
when it is over. A transfer:

| Field | Meaning |
|---|---|
| `index` | position in the job, from 0 |
| `id` | `<job id>:<index>` |
| `src`, `dst` | as submitted; a file a pattern or a tree produced is shown under the reference's directory |
| `state` | `queued`, `running`, `done`, `failed`, `cancelled` |
| `started_at`, `finished_at` | UTC |
| `progress` | `read` and, when known, `total` |
| `report` | once it is over: the object `--json` prints, see [The JSON report](../automation/scripting.md#the-json-report) |
| `error` | `{"kind", "message"}` for a failed transfer |

## Errors

An error is `{"error": {"kind": "…", "message": "…"}}`. The `kind` is the
stable part.

| Status | `kind` | When |
|---|---|---|
| 400 | `invalid_body` | the JSON could not be read, or names an unknown option |
| 400 | `invalid_url` | a URL is malformed, is not an allowed profile, or adds `?options` to one |
| 400 | `invalid_option` | an option value that cannot work: `retries` without `cache`, `delete_source` on a server without `allow_delete` |
| 400 | `too_many_transfers` | the list is longer than `[server] max_transfers` |
| 401 | `unauthorized` | no token, or the wrong one; the answer to a wrong one is delayed by 250 ms |
| 403 | `forbidden` | the request carries an `Origin` header |
| 404 | `not_found` | no such job or transfer |
| 409 | `conflict` | two transfers of the job, or of this and a running job, write the same target |
| 413 | `too_large` | the body exceeds `[server] max_body` |
| 415 | `unsupported_media_type` | a body type the route does not take |
| 429 | `too_many_jobs` | `[server] max_queued` jobs are open; the `Retry-After` header says when to try again |
| 503 | `shutting_down` | the server is draining and takes no new jobs |

A job that fails after it was accepted carries the same shape in its `error`
field, with the kinds of the [exit-code table](exit-codes.md#which-errors-count-as-which):
`io`, `remote`, `transport`, `auth`, `checksum_mismatch`, `signature`,
`config`, `invalid_url`, `invalid_option`, `unsupported_scheme`,
`unsupported_operation`, `cancelled`, plus `too_many_transfers` when a pattern
or a tree expanded beyond the limit and `conflict` when the expansion produced
a target another job is writing.

## WebSocket events

One JSON object per text frame, tagged by `event`. Every event names its job,
so `/v1/events` can carry all of them on one connection. Nothing a client
sends is read, and frames from the client are capped at 4 KiB.

| `event` | Fields | When |
|---|---|---|
| `snapshot` | `job`, with `transfers` | first frame on every connection, and again in place of events a slow client missed |
| `queued` | `id` | the job was accepted |
| `started` | `id`, `transfers` (a count) | preparation is over; this many transfers will run |
| `transfer_started` | `id`, `index` | |
| `progress` | `id`, `bytes`, `transfers: [{index, read, total}]` | at most four times a second, only while bytes move |
| `transfer_done` | `id`, `index`, `state`, `transfer` | with the transfer's `report` or `error` |
| `done` | `id`, `state`, `job` (without transfers) | the job is over; `/v1/jobs/{id}/events` closes after it |

`started` and `transfer_started` do not name the transfers. A client that
wants `src` and `dst` fetches `GET /v1/jobs/{id}` once when `started`
arrives.
