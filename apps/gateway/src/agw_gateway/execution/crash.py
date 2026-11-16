"""Test-only crash injection (14 §7). Disabled unless AGW_ENV=test.

``SimulatedCrash`` derives from BaseException so ordinary ``except Exception`` handlers cannot
swallow it: it behaves like the process dying at that point.
"""

from __future__ import annotations

from typing import Final

CRASH_POINTS: Final = frozenset(
    {
        "after_tx1_commit",
        "after_claim",
        "after_dispatch_commit",
        "after_adapter_return",
        "seal_before_commit",
        "anchor_before_broadcast",  # Phase 6: after the write-ahead SUBMITTED row commits
    }
)


class SimulatedCrash(BaseException):
    pass


class CrashPoints:
    def __init__(self, env: str) -> None:
        self._enabled = env == "test"
        self._armed: set[str] = set()

    def arm(self, point: str) -> None:
        if not self._enabled:
            raise RuntimeError("crash points are only available when AGW_ENV=test")
        if point not in CRASH_POINTS:
            raise ValueError(f"unknown crash point {point}")
        self._armed.add(point)

    def hit(self, point: str) -> None:
        """One-shot: raises SimulatedCrash once if armed."""
        if point in self._armed:
            self._armed.discard(point)
            raise SimulatedCrash(point)
