from __future__ import annotations

import hmac
import json
from urllib.parse import parse_qs


class QueryKeyAuthMiddleware:
    def __init__(self, app, api_key: str, protected_path: str = "/mcp") -> None:
        self.app = app
        self.api_key = api_key.encode()
        self.protected_path = protected_path.rstrip("/") or "/"

    async def __call__(self, scope, receive, send) -> None:
        if scope["type"] != "http" or scope.get("path") != self.protected_path:
            await self.app(scope, receive, send)
            return

        values = parse_qs(scope.get("query_string", b"").decode("latin-1")).get("key", [])
        if len(values) != 1 or not self._is_authorized(values[0]):
            await self._unauthorized(send)
            return

        await self.app(scope, receive, send)

    def _is_authorized(self, provided_key: str) -> bool:
        return hmac.compare_digest(provided_key.encode(), self.api_key)

    @staticmethod
    async def _unauthorized(send) -> None:
        body = json.dumps({"detail": "Invalid or missing key"}).encode()
        await send(
            {
                "type": "http.response.start",
                "status": 401,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(body)).encode("ascii")),
                    (b"cache-control", b"no-store"),
                ],
            }
        )
        await send({"type": "http.response.body", "body": body})
