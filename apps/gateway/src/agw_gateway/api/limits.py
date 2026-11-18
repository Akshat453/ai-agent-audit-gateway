"""Phase 10 hardening: a global request-body size limit and a per-credential rate limit.

Both are plain ASGI middleware, so they run BEFORE routing, authentication and any body
parsing, on every endpoint (``/v1/actions`` keeps its own check as well).

* Body limit: a declared ``Content-Length`` above ``max_body_bytes`` -> 413 at once. A body
  without a declared length (chunked) is read up to the limit + 1 byte before the app sees
  it; more -> 413. The buffered body is replayed to the app unchanged.
* Rate limit: token bucket (capacity ``rate_limit_burst``, refill ``rate_limit_per_minute``/60
  per second) keyed by SHA-256 of the ``Authorization`` header (the raw credential is never
  stored), or by client address when there is none. Exceeded -> 429 ``RATE_LIMITED`` with
  ``Retry-After``. Health, readiness and metrics are exempt. The state is per process: N
  gateway replicas allow N x the rate (documented in ADR-0032).
"""

from __future__ import annotations

import hashlib
import math
import time
from collections import OrderedDict
from collections.abc import Awaitable, Callable, MutableMapping
from typing import Any

from starlette.responses import JSONResponse

from agw_gateway.api.errors import MESSAGES
from agw_gateway.ids import uuid7

Scope = MutableMapping[str, Any]
Message = MutableMapping[str, Any]
Receive = Callable[[], Awaitable[Message]]
Send = Callable[[Message], Awaitable[None]]
ASGIApp = Callable[[Scope, Receive, Send], Awaitable[None]]

EXEMPT = frozenset({"/v1/health", "/v1/ready", "/metrics"})
MAX_BUCKETS = 50_000  # LRU bound so random credentials cannot grow memory without limit


def _error(status: int, code: str, headers: dict[str, str] | None = None) -> JSONResponse:
    body = {"error": {"code": code, "message": MESSAGES[code], "request_id": str(uuid7())}}
    return JSONResponse(body, status_code=status, headers=headers)


class BodySizeLimit:
    def __init__(self, app: ASGIApp, max_bytes: int) -> None:
        self.app, self.max_bytes = app, max_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or scope["method"] in ("GET", "HEAD", "OPTIONS"):
            await self.app(scope, receive, send)
            return
        headers = dict(scope.get("headers") or [])
        declared = headers.get(b"content-length")
        if declared is not None:
            if not declared.isdigit() or int(declared) > self.max_bytes:
                await _error(413, "PAYLOAD_TOO_LARGE")(scope, receive, send)
                return
            await self.app(scope, _capped(receive, self.max_bytes), send)
            return
        chunks: list[bytes] = []
        size = 0
        while True:
            message = await receive()
            if message["type"] != "http.request":  # client went away
                await self.app(scope, _replay([message]), send)
                return
            body = message.get("body", b"")
            size += len(body)
            if size > self.max_bytes:
                await _error(413, "PAYLOAD_TOO_LARGE")(scope, receive, send)
                return
            chunks.append(body)
            if not message.get("more_body", False):
                break
        replay: list[Message] = [
            {"type": "http.request", "body": b"".join(chunks), "more_body": False}
        ]
        await self.app(scope, _replay(replay), send)


def _replay(messages: list[Message]) -> Receive:
    pending = list(messages)

    async def receive() -> Message:
        return pending.pop(0) if pending else {"type": "http.disconnect"}

    return receive


def _capped(receive: Receive, limit: int) -> Receive:
    """A body longer than its declared Content-Length is cut off at the limit (the server
    normally enforces the declared length; this is defence in depth)."""
    seen = 0

    async def wrapped() -> Message:
        nonlocal seen
        message = await receive()
        if message["type"] == "http.request":
            seen += len(message.get("body", b""))
            if seen > limit:
                return {"type": "http.disconnect"}
        return message

    return wrapped


class RateLimit:
    def __init__(
        self,
        app: ASGIApp,
        per_minute: int,
        burst: int,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.app, self.rate, self.burst, self.clock = app, per_minute / 60.0, float(burst), clock
        self.buckets: OrderedDict[bytes, tuple[float, float]] = OrderedDict()

    def _key(self, scope: Scope) -> bytes:
        for name, value in scope.get("headers") or []:
            if name == b"authorization":
                return b"c:" + hashlib.sha256(value).digest()
        client = scope.get("client")
        return b"a:" + (str(client[0]) if client else "-").encode()

    def take(self, key: bytes) -> float:
        """0.0 if a token was taken, else the seconds until one is available."""
        now = self.clock()
        tokens, last = self.buckets.pop(key, (self.burst, now))
        tokens = min(self.burst, tokens + (now - last) * self.rate)
        wait = 0.0
        if tokens >= 1.0:
            tokens -= 1.0
        else:
            wait = (1.0 - tokens) / self.rate
        self.buckets[key] = (tokens, now)
        while len(self.buckets) > MAX_BUCKETS:
            self.buckets.popitem(last=False)
        return wait

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or self.rate <= 0 or scope["path"] in EXEMPT:
            await self.app(scope, receive, send)
            return
        wait = self.take(self._key(scope))
        if wait > 0:
            retry = str(max(1, math.ceil(wait)))
            await _error(429, "RATE_LIMITED", {"Retry-After": retry})(scope, receive, send)
            return
        await self.app(scope, receive, send)
