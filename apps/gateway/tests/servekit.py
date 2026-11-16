"""Serve an ASGI app on a real localhost port in a background thread (Phase 8 integration
tests: the MCP SDK client must talk real Streamable HTTP)."""

from __future__ import annotations

import socket
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

import uvicorn


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


@contextmanager
def serve(app: Any, port: int | None = None) -> Iterator[str]:
    port = port or free_port()
    server = uvicorn.Server(
        uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning", lifespan="on")
    )
    th = threading.Thread(target=server.run, daemon=True)
    th.start()
    for _ in range(200):
        if server.started:
            break
        time.sleep(0.02)
    assert server.started, "server did not start"
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        server.should_exit = True
        th.join(timeout=10)


@contextmanager
def pump(gw: Any, interval: float = 0.02) -> Iterator[None]:
    """Run the gateway's executor in the background (the worker, in-process)."""
    stop = threading.Event()

    def loop() -> None:
        while not stop.is_set():
            gw.state.executor.run_once()
            time.sleep(interval)

    th = threading.Thread(target=loop, daemon=True)
    th.start()
    try:
        yield
    finally:
        stop.set()
        th.join()
