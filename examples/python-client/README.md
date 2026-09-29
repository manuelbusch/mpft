# mpft-client — a Python client for `mpft serve`

A small [uv](https://docs.astral.sh/uv/) project that shows how to drive
the HTTP API of `mpft serve`: submit a transfer or a batch, follow its
progress over the WebSocket, list and cancel jobs. It is an example, not a
package to depend on — copy what you need.

```
src/mpft_client/api.py       MpftApi: the routes and the event stream (httpx + websockets)
src/mpft_client/progress.py  JobView: events → per-transfer state; render(): lines for a terminal
src/mpft_client/cli.py       mpft-client: submit, batch, watch, list, show, cancel, health
demo.sh                     builds mpft, starts a server on local directories, runs the client
jobs.example.json           a batch: a pattern and a job with two targets
```

## Try it

`demo.sh` needs a Rust toolchain and `uv`. It builds `mpft` with the
`server` feature, starts it on a free port with three profiles that point at
temporary directories, fills `inbox` with a few files and runs the client
against it:

```
./demo.sh            # ~150 MiB of temporary files; DEMO_MB=… scales them
```

Against a server of your own:

```
export MPFT_API_URL=http://127.0.0.1:7788
export MPFT_API_TOKEN=…                      # what the server's [server] token resolves to
uv run mpft-client health
uv run mpft-client submit --follow mpft://inbox/report.pdf mpft://prod/ mpft://archive/
uv run mpft-client batch --follow --parallel 2 jobs.example.json
uv run mpft-client watch --all               # every job's events, one line each
uv run mpft-client list --state running
uv run mpft-client cancel <job id>
```

`submit --follow` draws one line per transfer and redraws it four times a
second while bytes move:

```
job 3f1c…  running   3 transfers  96.0 MiB / 192.0 MiB  (1 running, 2 done)
 ✔ [████████████████████████] 100%   32.0 MiB / 32.0 MiB   mpft://inbox/a.bin → mpft://outbox/
 ✔ [████████████████████████] 100%   64.0 MiB / 64.0 MiB   mpft://inbox/b.bin → mpft://outbox/
 ▶ [██████░░░░░░░░░░░░░░░░░░]  25%   24.0 MiB / 96.0 MiB   mpft://inbox/c.bin → 2 targets
```

## How the pieces talk to the server

**Submitting** is one `POST` with the bearer token in the `Authorization`
header; the answer is `202 {"id", "url", "state": "queued"}` and the job
runs on its own. `MpftApi.submit` sends `{"src", "dst", "options"}` to
`/v1/jobs`, `submit_batch` sends `{"jobs": [...], "options"}` to
`/v1/batches`, and `submit_lines` posts an NDJSON, CSV or plain-text job
list with the options in the query — the file forms `mpft batch` takes.

**Following** opens `GET /v1/jobs/{id}/events` as a WebSocket, with the
same `Authorization` header on the upgrade (the server takes no `?token=`,
and refuses any request that carries an `Origin` header, so this is not
something a browser page can do). One JSON object comes per text frame:

| event | carries | meaning |
|---|---|---|
| `snapshot` | `job` with `transfers` | where the job stands right now; always the first frame |
| `queued` | `id` | the job was accepted |
| `preparing` | `id` | the job has a slot; URLs are resolved, patterns expanded |
| `started` | `id`, `transfers` (count) | preparation is over; this many transfers will run |
| `transfer_started` | `id`, `index` | |
| `progress` | `id`, `bytes`, `transfers: [{index, read, total}]` | at most four times a second, only while bytes move |
| `transfer_done` | `id`, `index`, `state`, `transfer` | with the transfer's `report` (as `mpft --json` prints it) or `error` |
| `done` | `id`, `state`, `job` | the job is over; the server closes the socket |

`JobView.apply` folds these into per-transfer state. Two things worth
copying: `started` and `transfer_started` do not name the transfers (only
their count and index), so `follow` does one `GET /v1/jobs/{id}` when
`started` arrives to learn `src` and `dst`; and a client that falls behind
gets a fresh `snapshot` instead of the events it missed, which
`JobView.apply` handles the same way as the first one. Without a WebSocket,
`MpftApi.wait` polls the job until its state is `done`, `failed` or
`cancelled`.

`GET /v1/events` starts with a `snapshot` (without transfers) of every job
not yet over, then streams every job's events and never closes on its own;
a client that falls behind there gets a `lagged` frame and the snapshots
again. `mpft-client watch --all` prints them one per line (`--json` for the
raw frames).

**Errors** come as `{"error": {"kind", "message"}}`; `ApiError` carries
the status, the kind and, for a `429`, the server's `Retry-After`. A refused
WebSocket upgrade raises it too, and the command line exits with 3 for
either. A
`400 too_many_transfers` means the list was longer than the server's
`max_transfers`; the same kind on a *failed* job means a pattern or a tree
turned out that large.

**Relay.** `mpft relay` is the other way in: one upload over SSH that the
relay fans out itself (see [the relay page of the user
guide](../../user_guide/src/server/relay.md)). It is not an HTTP
route — a client for it opens an SSH session, runs `mpft relay`, writes one
JSON header line and the bytes, and reads JSON lines back; `asyncssh`
would do, and `mpft cp --via` already does.

## Development

```
uv run pytest            # unit tests of JobView and the renderer, no server needed
```
