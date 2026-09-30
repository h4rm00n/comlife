from __future__ import annotations

import json

from mcp_ssh_shell.auth import QueryKeyAuthMiddleware


async def test_query_key_authorizes_only_exact_key() -> None:
    calls = []
    responses = []

    async def app(scope, receive, send):
        calls.append(scope)
        await send(
            {"type": "http.response.start", "status": 200, "headers": []}
        )
        await send({"type": "http.response.body", "body": b"ok"})

    async def receive():
        return {"type": "http.disconnect"}

    async def send(message):
        responses.append(message)

    middleware = QueryKeyAuthMiddleware(app, "secret-value")

    await middleware(
        scope_for_valid_request(),
        receive,
        send,
    )
    assert len(calls) == 1

    response = []
    async def reject_receive():
        return {"type": "http.disconnect"}

    async def reject_send(message):
        response.append(message)

    await middleware(
        {"type": "http", "path": "/mcp", "query_string": b"key=wrong"},
        reject_receive,
        reject_send,
    )
    assert calls == [scope_for_valid_request()]
    assert response[0]["status"] == 401
    assert json.loads(response[1]["body"])["detail"] == "Invalid or missing key"


async def test_non_mcp_paths_bypass_query_key() -> None:
    calls = []

    async def app(scope, receive, send):
        calls.append(scope)

    middleware = QueryKeyAuthMiddleware(app, "secret-value")
    scope = {"type": "http", "path": "/other", "query_string": b""}
    async def receive():
        return {"type": "http.disconnect"}

    async def send(message):
        return None

    await middleware(scope, receive, send)
    assert calls == [scope]


def scope_for_valid_request():
    return {"type": "http", "path": "/mcp", "query_string": b"key=secret-value"}

