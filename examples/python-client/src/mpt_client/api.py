"""The routes of `mpt serve` and its event stream.

Everything takes and returns the JSON the server speaks; nothing is
interpreted here. See the "Server" section of the mpt README for the shapes.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator
from typing import Any

import httpx
from websockets.asyncio.client import connect
from websockets.exceptions import ConnectionClosedOK

Json = dict[str, Any]

#: Job states after which nothing changes any more.
FINAL_STATES = frozenset({"done", "failed", "cancelled"})

#: The content types `POST /v1/batches` takes besides JSON; the options go
#: in the query then (`?parallel=2&fail_fast=true`).
LINE_TYPES = {
    ".ndjson": "application/x-ndjson",
    ".jsonl": "application/x-ndjson",
    ".csv": "text/csv",
    ".tsv": "text/tab-separated-values",
    ".txt": "text/plain",
}


class ApiError(Exception):
    """The server refused: `{"error": {"kind", "message"}}` with its status."""

    def __init__(self, status: int, kind: str, message: str, retry_after: float | None = None):
        super().__init__(f"{status} {kind}: {message}")
        self.status = status
        self.kind = kind
        self.message = message
        #: Seconds the server asked to wait (429), if it said.
        self.retry_after = retry_after

    @classmethod
    def from_response(cls, resp: httpx.Response) -> ApiError:
        kind, message = "error", resp.text.strip() or resp.reason_phrase
        try:
            error = resp.json().get("error", {})
            kind = error.get("kind", kind)
            message = error.get("message", message)
        except ValueError:
            pass
        retry_after = None
        if "retry-after" in resp.headers:
            try:
                retry_after = float(resp.headers["retry-after"])
            except ValueError:
                pass
        return cls(resp.status_code, kind, message, retry_after)


class MptApi:
    """One server, one token.

    Use it as an async context manager so the HTTP connection pool is
    closed; every method is a coroutine.
    """

    def __init__(
        self,
        base_url: str = "http://127.0.0.1:7788",
        token: str | None = None,
        timeout: float = 30.0,
    ):
        self.base_url = base_url.rstrip("/")
        self._headers = {"Authorization": f"Bearer {token}"} if token else {}
        self._http = httpx.AsyncClient(
            base_url=self.base_url, headers=self._headers, timeout=timeout
        )

    async def __aenter__(self) -> MptApi:
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.close()

    async def close(self) -> None:
        await self._http.aclose()

    # -- HTTP ---------------------------------------------------------------

    @staticmethod
    def _checked(resp: httpx.Response) -> Any:
        if resp.status_code >= 400:
            raise ApiError.from_response(resp)
        return resp.json()

    async def health(self) -> Json:
        """`{"ok": true}`; with a valid token also `version` and `jobs`."""
        resp = await self._http.get("/v1/healthz")
        # 503 while the server drains still carries a body worth reading.
        if resp.status_code == 503:
            return resp.json()
        return self._checked(resp)

    async def submit(self, src: str, dst: str | list[str], options: Json | None = None) -> Json:
        """One transfer: a source and one or more targets.

        Returns `{"id", "url", "state"}`; the job runs in the background.
        """
        body: Json = {"src": src, "dst": dst}
        if options:
            body["options"] = options
        resp = await self._http.post("/v1/jobs", json=body)
        return self._checked(resp)

    async def submit_batch(self, jobs: list[Json], options: Json | None = None) -> Json:
        """Many transfers as one job: `[{"src": …, "dst": … | […]}, …]`."""
        body: Json = {"jobs": jobs}
        if options:
            body["options"] = options
        resp = await self._http.post("/v1/batches", json=body)
        return self._checked(resp)

    async def submit_lines(self, text: str, content_type: str, options: Json | None = None) -> Json:
        """A batch in one of the line forms of `mpt batch` (NDJSON, CSV,
        plain `src dst…` lines); the options travel in the query."""
        params = {
            k: json.dumps(v) if isinstance(v, bool) else v for k, v in (options or {}).items()
        }
        resp = await self._http.post(
            "/v1/batches",
            content=text.encode(),
            headers={"Content-Type": content_type},
            params=params,
        )
        return self._checked(resp)

    async def list_jobs(self, state: str | None = None, limit: int | None = None) -> list[Json]:
        """Summaries without transfers, newest first."""
        params: dict[str, Any] = {}
        if state:
            params["state"] = state
        if limit:
            params["limit"] = limit
        resp = await self._http.get("/v1/jobs", params=params)
        return self._checked(resp)

    async def get_job(self, job_id: str) -> Json:
        """The job with every transfer: state, bytes, size, report."""
        resp = await self._http.get(f"/v1/jobs/{job_id}")
        return self._checked(resp)

    async def get_transfer(self, job_id: str, index: int) -> Json:
        resp = await self._http.get(f"/v1/jobs/{job_id}/transfers/{index}")
        return self._checked(resp)

    async def cancel(self, job_id: str) -> Json:
        """`{"id", "state", "cancelling": true}` while it stops; without
        `cancelling` when the job was already over."""
        resp = await self._http.delete(f"/v1/jobs/{job_id}")
        return self._checked(resp)

    async def wait(self, job_id: str, interval: float = 0.5) -> Json:
        """Poll `GET /v1/jobs/{id}` until the job is over; the alternative
        to the event stream when a WebSocket is not an option."""
        while True:
            job = await self.get_job(job_id)
            if job["state"] in FINAL_STATES:
                return job
            await asyncio.sleep(interval)

    # -- WebSocket ----------------------------------------------------------

    def _ws_url(self, route: str) -> str:
        scheme = "wss" if self.base_url.startswith("https") else "ws"
        return scheme + self.base_url[self.base_url.index(":") :] + route

    async def events(self, job_id: str | None = None) -> AsyncIterator[Json]:
        """The event stream, one JSON object per frame.

        For one job: its `snapshot` first, then `queued`, `started`,
        `transfer_started`, `progress`, `transfer_done`, `done`; the server
        closes the socket after `done` and the iterator ends. Without a
        job id every job's events come, and the stream stays open.

        The token goes in the `Authorization` header of the upgrade; no
        `Origin` header is sent, since the server refuses those.
        """
        route = f"/v1/jobs/{job_id}/events" if job_id else "/v1/events"
        async with connect(self._ws_url(route), additional_headers=self._headers) as ws:
            try:
                async for frame in ws:
                    yield json.loads(frame)
            except ConnectionClosedOK:
                return
