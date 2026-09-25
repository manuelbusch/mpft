"""`mpt-client`: submit jobs to `mpt serve` and watch them run.

    export MPT_API_URL=http://127.0.0.1:7788 MPT_API_TOKEN=…
    mpt-client submit --follow mpt://inbox/report.pdf mpt://prod/ mpt://archive/
    mpt-client batch --follow jobs.json
    mpt-client watch <job id>        # progress of one job over WebSocket
    mpt-client watch --all           # every event of every job, as lines
    mpt-client list --state running
    mpt-client cancel <job id>

Exit status: 0 when the job ended `done`, 1 when it `failed` or was
`cancelled`, 2 for a bad command line, 3 when the server refused.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from pathlib import Path
from typing import Any

from .api import LINE_TYPES, ApiError, MptApi
from .progress import JobView, Screen, render

Json = dict[str, Any]

STATUS = {"done": 0, "failed": 1, "cancelled": 1}


def options_of(args: argparse.Namespace) -> Json:
    """The `options` object of a job from the common flags."""
    options: Json = {}
    for key in ("parallel", "hash", "timeout"):
        value = getattr(args, key, None)
        if value is not None:
            options[key] = value
    for key in ("fail_fast", "check", "skip_existing", "recursive", "allow_empty"):
        if getattr(args, key, False):
            options[key] = True
    if getattr(args, "no_atomic", False):
        options["atomic"] = False
    return options


async def follow(api: MptApi, job_id: str, out=sys.stdout) -> str:
    """Draw the job's transfers until it is over; returns its final state.

    `snapshot` comes first and names the transfers of a job that already
    runs; for one that is still queued the names are fetched once when
    `started` says how many there are.
    """
    view = JobView(job_id)
    screen = Screen(out)
    async for event in api.events(job_id):
        view.apply(event)
        if event["event"] == "started":
            view.name_from(await api.get_job(job_id))
        # Off a terminal, every quarter-second progress line would be noise.
        if screen.tty or event["event"] != "progress":
            screen.update(render(view))
        if view.is_final:
            break
    screen.update(render(view))
    screen.finish()
    return view.state


async def cmd_health(api: MptApi, args: argparse.Namespace) -> int:
    print(json.dumps(await api.health(), indent=2))
    return 0


async def cmd_submit(api: MptApi, args: argparse.Namespace) -> int:
    dst = args.dst[0] if len(args.dst) == 1 else args.dst
    accepted = await api.submit(args.src, dst, options_of(args))
    print(f"accepted {accepted['id']} ({accepted['state']})", file=sys.stderr)
    if not args.follow:
        print(accepted["id"])
        return 0
    return STATUS.get(await follow(api, accepted["id"]), 1)


async def cmd_batch(api: MptApi, args: argparse.Namespace) -> int:
    path = Path(args.file)
    text = sys.stdin.read() if args.file == "-" else path.read_text()
    options = options_of(args)
    if args.file != "-" and path.suffix in LINE_TYPES:
        accepted = await api.submit_lines(text, LINE_TYPES[path.suffix], options)
    else:
        body = json.loads(text)
        jobs = body["jobs"] if isinstance(body, dict) else body
        if isinstance(body, dict):
            options = {**body.get("options", {}), **options}
        accepted = await api.submit_batch(jobs, options)
    print(f"accepted {accepted['id']} ({accepted['state']})", file=sys.stderr)
    if not args.follow:
        print(accepted["id"])
        return 0
    return STATUS.get(await follow(api, accepted["id"]), 1)


async def cmd_watch(api: MptApi, args: argparse.Namespace) -> int:
    if args.job_id:
        return STATUS.get(await follow(api, args.job_id), 1)
    # Every job's events, one line each; this stream never ends on its own.
    async for event in api.events():
        line = json.dumps(event) if args.json else describe(event)
        print(line, flush=True)
    return 0


def describe(event: Json) -> str:
    """One line for an event of the all-jobs stream."""
    kind = event["event"]
    if kind == "snapshot":
        job = event["job"]
        return f"{job['id']} snapshot {job['state']}"
    if kind == "lagged":
        # Snapshots of the open jobs follow; the ones that ended meanwhile
        # are in `mpt-client list`.
        return f"fell behind, {event['missed']} events missed"
    job_id = event["id"]
    match kind:
        case "started":
            return f"{job_id} started, {event['transfers']} transfers"
        case "transfer_started":
            return f"{job_id}:{event['index']} started"
        case "progress":
            running = ", ".join(
                f"#{t['index']} {t['read']}/{t.get('total', '?')}" for t in event["transfers"]
            )
            return f"{job_id} progress {event['bytes']} bytes  {running}"
        case "transfer_done":
            t = event["transfer"]
            why = f"  {t['error']['kind']}: {t['error']['message']}" if t.get("error") else ""
            targets = ", ".join(t["dst"])
            return f"{job_id}:{event['index']} {event['state']}  {t['src']} → {targets}{why}"
        case "done":
            job = event["job"]
            counts = job["progress"]["transfers"]
            why = f"  {job['error']['kind']}: {job['error']['message']}" if job.get("error") else ""
            return (
                f"{job_id} {event['state']}  {counts['done']} done, "
                f"{counts['failed']} failed, {counts['cancelled']} cancelled{why}"
            )
        case _:
            return f"{job_id} {kind}"


async def cmd_list(api: MptApi, args: argparse.Namespace) -> int:
    jobs = await api.list_jobs(args.state, args.limit)
    if args.json:
        print(json.dumps(jobs, indent=2))
        return 0
    for job in jobs:
        counts = job["progress"]["transfers"]
        print(
            f"{job['id']}  {job['state']:<9} {job['kind']:<8} {job['submitted_at']}  "
            f"{counts['done']}/{counts['total']} done"
            + (f", {counts['failed']} failed" if counts["failed"] else "")
        )
    return 0


async def cmd_show(api: MptApi, args: argparse.Namespace) -> int:
    if args.transfer is not None:
        print(json.dumps(await api.get_transfer(args.job_id, args.transfer), indent=2))
    else:
        print(json.dumps(await api.get_job(args.job_id), indent=2))
    return 0


async def cmd_cancel(api: MptApi, args: argparse.Namespace) -> int:
    answer = await api.cancel(args.job_id)
    if answer.get("cancelling"):
        print(f"{answer['id']} is being cancelled (was {answer['state']})")
    else:
        print(f"{answer['id']} was already {answer['state']}")
    return 0


def job_flags(p: argparse.ArgumentParser) -> None:
    p.add_argument("-f", "--follow", action="store_true", help="stay and show the progress")
    g = p.add_argument_group("job options")
    g.add_argument("--parallel", type=int, help="transfers of this batch in flight at once")
    g.add_argument("--fail-fast", action="store_true", help="stop after the first failure")
    g.add_argument(
        "--hash", help="write a checksum file next to every target: sha256, sha512, blake3"
    )
    g.add_argument(
        "--check", action="store_true", help="verify against the checksum file next to the source"
    )
    g.add_argument("--skip-existing", action="store_true", help="leave targets that have the file")
    g.add_argument("--no-atomic", action="store_true", help="write straight to the target name")
    g.add_argument("--recursive", action="store_true", help="a source directory is a tree")
    g.add_argument("--allow-empty", action="store_true", help="a pattern may match nothing")
    g.add_argument("--timeout", type=int, help="seconds per transfer")


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="mpt-client",
        description=__doc__.split("\n\n")[0],
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__.split("\n\n", 1)[1],
    )
    p.add_argument(
        "--url",
        default=os.environ.get("MPT_API_URL", "http://127.0.0.1:7788"),
        help="the server (MPT_API_URL, default %(default)s)",
    )
    p.add_argument(
        "--token",
        default=os.environ.get("MPT_API_TOKEN"),
        help="the bearer token (MPT_API_TOKEN)",
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("health", help="is the server up").set_defaults(run=cmd_health)

    s = sub.add_parser("submit", help="one transfer: a source and its targets")
    s.add_argument("src")
    s.add_argument("dst", nargs="+")
    job_flags(s)
    s.set_defaults(run=cmd_submit)

    s = sub.add_parser(
        "batch",
        help="many transfers from a file: JSON ({jobs, options} or a list), "
        ".ndjson, .csv, .tsv or .txt as mpt batch takes them, or - for JSON on stdin",
    )
    s.add_argument("file")
    job_flags(s)
    s.set_defaults(run=cmd_batch)

    s = sub.add_parser("watch", help="follow a job's progress, or every job's events")
    s.add_argument("job_id", nargs="?")
    s.add_argument("--all", action="store_true", help="every job (GET /v1/events)")
    s.add_argument("--json", action="store_true", help="with --all: raw events")
    s.set_defaults(run=cmd_watch)

    s = sub.add_parser("list", help="jobs, newest first")
    s.add_argument(
        "--state", choices=["queued", "preparing", "running", "done", "failed", "cancelled"]
    )
    s.add_argument("--limit", type=int)
    s.add_argument("--json", action="store_true")
    s.set_defaults(run=cmd_list)

    s = sub.add_parser("show", help="a job with its transfers, as JSON")
    s.add_argument("job_id")
    s.add_argument("--transfer", type=int, metavar="N", help="only transfer N")
    s.set_defaults(run=cmd_show)

    s = sub.add_parser("cancel", help="stop a job; partial files are removed")
    s.add_argument("job_id")
    s.set_defaults(run=cmd_cancel)
    return p


async def run(args: argparse.Namespace) -> int:
    async with MptApi(args.url, args.token) as api:
        return await args.run(api, args)


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    if args.cmd == "watch" and not args.job_id and not args.all:
        parser().error("watch needs a job id or --all")
    try:
        return asyncio.run(run(args))
    except ApiError as e:
        print(f"mpt-client: {e}", file=sys.stderr)
        if e.retry_after:
            print(f"mpt-client: try again in {e.retry_after:.0f} s", file=sys.stderr)
        return 3
    except KeyboardInterrupt:
        return 130
    except OSError as e:
        print(f"mpt-client: {args.url}: {e}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    sys.exit(main())
