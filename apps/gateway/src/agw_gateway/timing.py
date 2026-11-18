"""Per-stage timers for the evaluation harness (Phase 10, ADR-0032). Pure (time only).

Disabled by default: ``timed()`` then costs one attribute check. The RQ1 harness calls
``enable()`` in its own process and reads ``drain()``. Stage names are fixed strings (auth,
risk, policy, durable_write, dispatch_tx, adapter, result_tx, seal); no ids or content.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager

_lock = threading.Lock()
_state = {"on": False}
_samples: list[tuple[str, float]] = []


def enable(on: bool = True) -> None:
    with _lock:
        _state["on"] = on
        _samples.clear()


@contextmanager
def timed(stage: str) -> Iterator[None]:
    if not _state["on"]:
        yield
        return
    t0 = time.perf_counter()
    try:
        yield
    finally:
        dt = time.perf_counter() - t0
        with _lock:
            _samples.append((stage, dt))


def drain() -> list[tuple[str, float]]:
    with _lock:
        out = list(_samples)
        _samples.clear()
    return out
