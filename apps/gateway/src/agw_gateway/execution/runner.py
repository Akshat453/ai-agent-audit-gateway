"""In-process background loop (AGW_EXECUTOR_MODE=inprocess). Also used by agw_worker."""

from __future__ import annotations

import logging
import threading
import time
from collections.abc import Callable, Sequence

from agw_gateway.db import is_db_unavailable
from agw_gateway.execution.executor import Executor
from agw_gateway.execution.reconciler import Reconciler
from agw_gateway.logs import log

logger = logging.getLogger("agw.execution.runner")


class BackgroundRunner:
    def __init__(
        self,
        executor: Executor,
        reconciler: Reconciler,
        *,
        poll_seconds: float,
        reconcile_seconds: float,
        periodic: Sequence[tuple[float, Callable[[], object]]] = (),
    ) -> None:
        # Extra (interval, task) pairs, e.g. the worker's epoch sealer.
        self._periodic = [(interval, task, [0.0]) for interval, task in periodic]
        self._executor = executor
        self._reconciler = reconciler
        self._poll = poll_seconds
        self._reconcile_every = reconcile_seconds
        self._wake = threading.Event()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def nudge(self) -> None:
        self._wake.set()

    def start(self) -> None:
        self._thread = threading.Thread(target=self.run_forever, name="agw-executor", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        self._wake.set()
        if self._thread is not None:
            self._thread.join(timeout=5)

    def run_forever(self) -> None:
        last_reconcile = 0.0
        while not self._stop.is_set():
            try:
                if time.monotonic() - last_reconcile >= self._reconcile_every:
                    self._reconciler.run_once()
                    last_reconcile = time.monotonic()
                while self._executor.run_once() and not self._stop.is_set():
                    pass
                for interval, task, last in self._periodic:
                    if time.monotonic() - last[0] >= interval:
                        task()
                        last[0] = time.monotonic()
            except Exception as exc:  # keep the loop alive; DB outages are expected (fail closed)
                level = logging.WARNING if is_db_unavailable(exc) else logging.ERROR
                log(logger, level, "executor loop error", error_code=type(exc).__name__)
            self._wake.wait(self._poll)
            self._wake.clear()
