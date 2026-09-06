"""JobView folds the server's events; render draws them. No server needed."""

import io

from mpt_client.progress import JobView, Screen, human_size, render

JOB = "0123456789abcdef0123456789abcdef"


def snapshot(state="queued", transfers=None, **more):
    job = {
        "id": JOB,
        "kind": "batch",
        "state": state,
        "submitted_at": "2026-09-11T10:00:00Z",
        "attempt": 1,
        "options": {},
        "stopped_early": False,
        "progress": {
            "bytes": 0,
            "transfers": {
                "total": len(transfers or []),
                "queued": 0,
                "running": 0,
                "done": 0,
                "failed": 0,
                "cancelled": 0,
            },
        },
        "transfers": transfers,
        **more,
    }
    return {"event": "snapshot", "job": job}


def transfer(index, state="queued", read=0, total=None, error=None):
    t = {
        "index": index,
        "id": f"{JOB}:{index}",
        "src": f"mpt://inbox/f{index}.bin",
        "dst": ["mpt://outbox/"],
        "state": state,
        "progress": {"read": read, **({"total": total} if total else {})},
    }
    if error:
        t["error"] = error
    return t


def test_a_queued_job_fills_in_as_the_events_come():
    view = JobView(JOB)
    assert view.apply(snapshot())
    assert view.state == "queued" and view.transfers == {}

    view.apply({"event": "started", "id": JOB, "transfers": 2})
    assert view.state == "running" and sorted(view.transfers) == [0, 1]

    view.apply({"event": "transfer_started", "id": JOB, "index": 1})
    view.apply(
        {
            "event": "progress",
            "id": JOB,
            "bytes": 10,
            "transfers": [{"index": 1, "read": 10, "total": 40}],
        }
    )
    t = view.transfers[1]
    assert (t.state, t.read, t.total, t.fraction) == ("running", 10, 40, 0.25)

    view.apply(
        {
            "event": "transfer_done",
            "id": JOB,
            "index": 1,
            "state": "done",
            "transfer": transfer(1, "done", 40, 40),
        }
    )
    assert view.transfers[1].read == 40 and view.transfers[1].src == "mpt://inbox/f1.bin"

    view.apply(
        {
            "event": "transfer_done",
            "id": JOB,
            "index": 0,
            "state": "failed",
            "transfer": transfer(0, "failed", 0, 5, {"kind": "io", "message": "gone"}),
        }
    )
    assert view.transfers[0].error == "io: gone"

    done = snapshot("failed")["job"]
    done["transfers"] = None
    view.apply({"event": "done", "id": JOB, "state": "failed", "job": done})
    assert view.is_final and view.state == "failed"
    assert len(view.transfers) == 2, "the summary must not drop what the events built"


def test_a_snapshot_of_a_running_job_names_the_transfers():
    view = JobView(JOB)
    view.apply(snapshot("running", [transfer(0, "running", 3, 9), transfer(1)]))
    assert view.transfers[0].src == "mpt://inbox/f0.bin"
    assert view.transfers[0].fraction == 3 / 9
    assert view.expected == 2


def test_events_of_other_jobs_are_ignored():
    view = JobView(JOB)
    other = "f" * 32
    assert not view.apply({"event": "started", "id": other, "transfers": 5})
    assert not view.apply({"event": "snapshot", "job": {**snapshot()["job"], "id": other}})
    assert view.transfers == {} and view.state == "queued"


def test_render_shows_a_line_per_transfer_and_the_error():
    view = JobView(JOB)
    view.apply(
        snapshot(
            "failed",
            [transfer(0, "done", 8, 8)],
            error={"kind": "invalid_url", "message": "nothing matched"},
        )
    )
    lines = render(view)
    assert lines[0].startswith(f"job {JOB}  failed    1 transfer")
    assert "error: invalid_url: nothing matched" in lines[1]
    assert "100%" in lines[2] and "mpt://inbox/f0.bin → mpt://outbox/" in lines[2]


def test_the_screen_redraws_in_place_only_on_a_terminal():
    out = io.StringIO()
    screen = Screen(out)
    screen.update(["a", "b"])
    screen.update(["a", "b"])  # unchanged: nothing written
    screen.update(["c"])
    assert out.getvalue() == "a\nb\nc\n"
    assert "\x1b[" not in out.getvalue()


def test_sizes_read_well():
    assert human_size(512) == "512 B"
    assert human_size(1536) == "1.5 KiB"
    assert human_size(3 * 1024**3) == "3.0 GiB"


class Tty(io.StringIO):
    def isatty(self):
        return True


def test_on_a_terminal_the_block_is_redrawn_in_place():
    out = Tty()
    screen = Screen(out)
    screen.update(["a", "b", "c"])
    screen.update(["a", "x"])
    text = out.getvalue()
    # First block, then: up three lines, two fresh lines, one blanked, up one.
    assert text == ("\x1b[2Ka\n\x1b[2Kb\n\x1b[2Kc\n\x1b[3A\x1b[2Ka\n\x1b[2Kx\n\x1b[2K\n\x1b[1A")
    screen.finish()
    screen.update(["d"])
    assert text + "\x1b[2Kd\n" == out.getvalue(), "after finish nothing is moved over"
