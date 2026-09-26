"""ApiError from the answers the server gives. No server needed."""

import httpx
from websockets.datastructures import Headers
from websockets.exceptions import InvalidStatus
from websockets.http11 import Response

from mpt_client import cli
from mpt_client.api import ApiError, MptApi

BODY = b'{"error": {"kind": "unauthorized", "message": "a valid bearer token is required"}}'


def test_an_http_error_keeps_kind_and_message():
    resp = httpx.Response(429, content=BODY, headers={"Retry-After": "2"})
    err = ApiError.from_response(resp)
    assert (err.status, err.kind, err.retry_after) == (429, "unauthorized", 2.0)
    assert "bearer token" in err.message


def test_a_refused_websocket_upgrade_is_an_api_error():
    refused = InvalidStatus(Response(401, "Unauthorized", Headers(), BODY))
    err = ApiError.from_handshake(refused)
    assert (err.status, err.kind) == (401, "unauthorized")
    assert "bearer token" in err.message

    plain = InvalidStatus(Response(404, "Not Found", Headers(), b""))
    err = ApiError.from_handshake(plain)
    assert (err.status, err.kind, err.message) == (404, "error", "Not Found")


def test_watch_exits_with_3_when_the_upgrade_is_refused(monkeypatch, capsys):
    async def refused(self, job_id=None):
        raise ApiError.from_handshake(InvalidStatus(Response(401, "Unauthorized", Headers(), BODY)))
        yield  # an async generator, like the real one

    monkeypatch.setattr(MptApi, "events", refused)
    code = cli.main(["watch", "--all", "--json"])
    assert code == 3
    assert "401 unauthorized" in capsys.readouterr().err
