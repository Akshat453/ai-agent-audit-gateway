"""Phase 10 hardening: body-size and rate-limit middleware (api/limits.py), in isolation."""

from __future__ import annotations

from typing import Any

from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from agw_gateway.api.limits import MAX_BUCKETS, BodySizeLimit, RateLimit


class Clock:
    def __init__(self) -> None:
        self.t = 1000.0

    def __call__(self) -> float:
        return self.t


def _echo_app(**limits: Any) -> tuple[TestClient, Clock]:
    app = FastAPI()

    @app.post("/v1/x")
    async def x(request: Request) -> dict[str, int]:
        return {"n": len(await request.body())}

    @app.get("/v1/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    clock = Clock()
    app.add_middleware(BodySizeLimit, max_bytes=limits.get("max_bytes", 100))
    app.add_middleware(RateLimit, per_minute=limits.get("per_minute", 60),
                       burst=limits.get("burst", 3), clock=clock)  # fmt: skip
    return TestClient(app), clock


def test_body_limit_declared_length() -> None:
    c, _ = _echo_app(per_minute=0)
    assert c.post("/v1/x", content=b"a" * 100).json() == {"n": 100}
    r = c.post("/v1/x", content=b"a" * 101)
    assert r.status_code == 413
    assert r.json()["error"]["code"] == "PAYLOAD_TOO_LARGE"


def test_body_limit_chunked_without_length() -> None:
    c, _ = _echo_app(per_minute=0)

    def chunks(n: int, size: int) -> Any:
        for _ in range(n):
            yield b"b" * size

    ok = c.post("/v1/x", content=chunks(4, 25))  # 100 bytes, no Content-Length
    assert ok.status_code == 200 and ok.json() == {"n": 100}
    big = c.post("/v1/x", content=chunks(5, 25))
    assert big.status_code == 413


def test_rate_limit_burst_then_429_then_refill() -> None:
    c, clock = _echo_app(per_minute=60, burst=3)  # 1 token / s
    h = {"Authorization": "Bearer agw_a"}
    assert [c.post("/v1/x", headers=h).status_code for _ in range(3)] == [200, 200, 200]
    r = c.post("/v1/x", headers=h)
    assert r.status_code == 429
    assert r.json()["error"]["code"] == "RATE_LIMITED"
    assert r.headers["Retry-After"] == "1"
    clock.t += 1.0
    assert c.post("/v1/x", headers=h).status_code == 200
    assert c.post("/v1/x", headers=h).status_code == 429


def test_rate_limit_is_per_credential_and_exempts_health() -> None:
    c, _ = _echo_app(per_minute=60, burst=1)
    a, b = {"Authorization": "Bearer agw_a"}, {"Authorization": "Bearer agw_b"}
    assert c.post("/v1/x", headers=a).status_code == 200
    assert c.post("/v1/x", headers=a).status_code == 429
    assert c.post("/v1/x", headers=b).status_code == 200  # other credential unaffected
    assert all(c.get("/v1/health").status_code == 200 for _ in range(5))


def test_rate_limit_does_not_store_credentials_and_is_bounded() -> None:
    rl = RateLimit(lambda *a: None, per_minute=60, burst=1)  # type: ignore[arg-type,return-value]
    key = rl._key({"headers": [(b"authorization", b"Bearer agw_secret")], "client": None})
    assert b"agw_secret" not in key
    for i in range(MAX_BUCKETS + 10):
        rl.take(i.to_bytes(4, "big"))
    assert len(rl.buckets) == MAX_BUCKETS


def test_rate_limit_off() -> None:
    c, _ = _echo_app(per_minute=0, burst=1)
    assert all(c.post("/v1/x").status_code == 200 for _ in range(10))


# --------------------------------------------------------------------------- adapter timeouts
def test_object_store_call_is_bounded_when_the_server_hangs() -> None:
    """Phase 10: a MinIO that accepts the connection and never answers must fail closed
    (BlobUnavailable) within the configured bound, not minio-py's 300 s x retries default."""
    import socket
    import threading
    import time

    import pytest

    from agw_gateway.evidence.blobs import BlobUnavailable, S3BlobStore

    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(8)
    held: list[socket.socket] = []
    stop = threading.Event()

    def accept() -> None:
        srv.settimeout(0.2)
        while not stop.is_set():
            try:
                held.append(srv.accept()[0])  # accept, never respond
            except OSError:
                continue

    th = threading.Thread(target=accept, daemon=True)
    th.start()
    try:
        store = S3BlobStore(endpoint=f"127.0.0.1:{srv.getsockname()[1]}", access_key="x",
                            secret_key="y", bucket="agw-hang", secure=False, timeout_seconds=1.0)  # fmt: skip
        t0 = time.monotonic()
        with pytest.raises(BlobUnavailable):
            store.put("t/k", b"z" * 10)
        assert time.monotonic() - t0 < 8.0
    finally:
        stop.set()
        th.join()
        for s in held:
            s.close()
        srv.close()
