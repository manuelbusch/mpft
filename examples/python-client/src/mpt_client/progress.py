"""From events to a picture: what a job's transfers are doing right now.

`JobView.apply` folds every event of one job into per-transfer state;
`render` turns that into lines for a terminal. The names of the transfers
are not in `started` or `transfer_started` (only their number and index),
so a client that connected before the job ran learns them from a `GET` of
the job once `started` arrives — see `JobView.name_from`.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from typing import Any, TextIO

Json = dict[str, Any]

_UNITS = ("B", "KiB", "MiB", "GiB", "TiB")


def human_size(n: int | float) -> str:
    n = float(n)
    for unit in _UNITS:
        if n < 1024 or unit == _UNITS[-1]:
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} {_UNITS[-1]}"


@dataclass
class TransferView:
    index: int
    src: str = "?"
    dst: list[str] = field(default_factory=list)
    state: str = "queued"
    read: int = 0
    total: int | None = None
    error: str | None = None

    @property
    def fraction(self) -> float | None:
        if not self.total:
            return None
        return min(1.0, self.read / self.total)

    def take(self, snap: Json) -> None:
        """Take what a transfer snapshot (from a job `GET`, a `snapshot`
        event or `transfer_done`) says."""
        self.src = snap.get("src", self.src)
        self.dst = list(snap.get("dst", self.dst))
        self.state = snap.get("state", self.state)
        progress = snap.get("progress") or {}
        self.read = progress.get("read", self.read)
        self.total = progress.get("total", self.total)
        error = snap.get("error")
        if error:
            self.error = f"{error.get('kind')}: {error.get('message')}"


@dataclass
class JobView:
    job_id: str
    state: str = "queued"
    kind: str | None = None
    #: How many transfers `started` announced; the dict fills as they run.
    expected: int | None = None
    transfers: dict[int, TransferView] = field(default_factory=dict)
    bytes: int = 0
    total: int | None = None
    #: The job failed before any transfer ran (a bad URL, a busy target).
    error: str | None = None
    #: The final job summary from `done`, once it came.
    summary: Json | None = None

    @property
    def is_final(self) -> bool:
        return self.state in ("done", "failed", "cancelled")

    def transfer(self, index: int) -> TransferView:
        return self.transfers.setdefault(index, TransferView(index))

    def name_from(self, job: Json) -> None:
        """Take state, progress and every transfer from a job as `GET
        /v1/jobs/{id}` or the `snapshot` event returns it."""
        self.state = job.get("state", self.state)
        self.kind = job.get("kind", self.kind)
        progress = job.get("progress") or {}
        self.bytes = progress.get("bytes", self.bytes)
        self.total = progress.get("total", self.total)
        counts = progress.get("transfers") or {}
        if "total" in counts:
            self.expected = counts["total"]
        error = job.get("error")
        if error:
            self.error = f"{error.get('kind')}: {error.get('message')}"
        for snap in job.get("transfers") or []:
            self.transfer(snap["index"]).take(snap)

    def apply(self, event: Json) -> bool:
        """Fold one event in; returns whether it was this job's."""
        if event.get("event") == "snapshot":
            job = event["job"]
            if job["id"] != self.job_id:
                return False
            self.name_from(job)
            return True
        if event.get("id") != self.job_id:
            return False
        match event["event"]:
            case "queued":
                self.state = "queued"
            case "started":
                self.state = "running"
                self.expected = event["transfers"]
                for i in range(self.expected):
                    self.transfer(i)
            case "transfer_started":
                self.transfer(event["index"]).state = "running"
            case "progress":
                self.bytes = event["bytes"]
                for tp in event["transfers"]:
                    t = self.transfer(tp["index"])
                    t.state = "running"
                    t.read = tp["read"]
                    t.total = tp.get("total", t.total)
            case "transfer_done":
                t = self.transfer(event["index"])
                t.take(event["transfer"])
                t.state = event["state"]
                if t.total is not None and t.state == "done":
                    t.read = t.total
            case "done":
                self.state = event["state"]
                self.summary = event["job"]
                self.name_from(event["job"])
        return True


# -- rendering ------------------------------------------------------------

BAR_WIDTH = 24
_MARK = {"queued": "·", "running": "▶", "done": "✔", "failed": "✘", "cancelled": "–"}


def bar(fraction: float | None, width: int = BAR_WIDTH) -> str:
    if fraction is None:
        return "[" + "?" * width + "]"
    full = int(round(fraction * width))
    return "[" + "█" * full + "░" * (width - full) + "]"


def transfer_line(t: TransferView) -> str:
    mark = _MARK.get(t.state, "?")
    if t.total is not None:
        amount = f"{human_size(t.read):>10} / {human_size(t.total):<10}"
        pct = f"{(t.fraction or 0) * 100:3.0f}%"
    else:
        amount = f"{human_size(t.read):>10} / {'?':<10}"
        pct = "   ?"
    target = t.dst[0] if len(t.dst) == 1 else f"{len(t.dst)} targets"
    line = f" {mark} {bar(t.fraction)} {pct} {amount} {t.src} → {target}"
    if t.error:
        line += f"  ({t.error})"
    return line


def render(view: JobView) -> list[str]:
    counts = {s: 0 for s in _MARK}
    for t in view.transfers.values():
        counts[t.state] = counts.get(t.state, 0) + 1
    n = view.expected if view.expected is not None else len(view.transfers)
    head = f"job {view.job_id}  {view.state:<9} {n} transfer{'s' if n != 1 else ''}"
    if view.total:
        head += f"  {human_size(view.bytes)} / {human_size(view.total)}"
    elif view.bytes:
        head += f"  {human_size(view.bytes)}"
    parts = [f"{v} {k}" for k, v in counts.items() if v]
    if parts:
        head += "  (" + ", ".join(parts) + ")"
    lines = [head]
    if view.error:
        lines.append(f"   error: {view.error}")
    for i in sorted(view.transfers):
        lines.append(transfer_line(view.transfers[i]))
    return lines


class Screen:
    """Redraws a block of lines in place on a terminal; on anything else
    it prints only when the block changes and never moves the cursor."""

    def __init__(self, out: TextIO = sys.stdout):
        self.out = out
        self.tty = out.isatty()
        self._shown = 0
        self._last: list[str] | None = None

    def update(self, lines: list[str]) -> None:
        if lines == self._last:
            return
        self._last = list(lines)
        if self.tty:
            if self._shown:
                self.out.write(f"\x1b[{self._shown}A")
            self.out.write("".join(f"\x1b[2K{line}\n" for line in lines))
            # A shorter block leaves old lines behind: blank them, go back.
            extra = self._shown - len(lines)
            if extra > 0:
                self.out.write("\x1b[2K\n" * extra + f"\x1b[{extra}A")
            self._shown = len(lines)
        else:
            self.out.write("\n".join(lines) + "\n")
        self.out.flush()

    def finish(self) -> None:
        """Leave the last picture standing and start a fresh line."""
        self._shown = 0
        self._last = None
