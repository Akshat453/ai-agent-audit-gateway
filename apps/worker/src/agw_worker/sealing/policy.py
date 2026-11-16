"""Risk-adaptive seal decision (09 §2, ADR-0026). Pure: the sealer feeds it a per-tenant
summary of the pending (unsealed) window read from durable rows; the comparison experiment
feeds it a simulated window. Same function, so the experiment measures the real rule.

Rules, checked in this order for one tenant:

1. ``MAX_EVENTS``: pending count (receipts included, as in Phase 3) >= T. With
   ``count_basis="lowest"`` (default, the prompt's wording) T is the ``max_events`` of the
   lowest level present; with ``"strictest"`` it is the smallest ``max_events`` among the
   levels present. Seals exactly T events, so epoch sizes stay bounded; the drain
   loop then re-evaluates the rest in the same tick.
2. ``RISK_HIGH`` / ``RISK_CRITICAL``: an event of an immediate level (HIGH, CRITICAL) is
   pending -> seal everything up to and including the LATEST such event. Older pending events
   are never skipped: epochs are contiguous seq ranges.
3. ``MAX_AGE``: the oldest pending non-receipt event is older than the STRICTEST ``max_age``
   among the levels present -> seal everything pending.

Pending ``EPOCH_SEALED`` receipts never trigger a seal on their own ("no events -> no seal").
Events without a risk level (legacy rows, written before Phase 4) count as LOW.

Why both exist: "strictest" is monotone (an extra LOW event can never postpone a MEDIUM batch)
but, measured in experiments/risk/seal_comparison.py, it creates about 2.8x more epochs than
"lowest" under mixed traffic. MEDIUM urgency stays bounded by its 60 s age rule under either
basis, so the default follows the prompt ("lowest"); ``AGW_SEAL_COUNT_BASIS`` switches it.
Recorded in ADR-0026.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Final, Literal

LEVELS: Final = ("LOW", "MEDIUM", "HIGH", "CRITICAL")


@dataclass(frozen=True)
class LevelRule:
    max_events: int
    max_age_seconds: float
    immediate: bool = False


CountBasis = Literal["strictest", "lowest"]


@dataclass(frozen=True)
class SealPolicy:
    rules: dict[str, LevelRule] = field(default_factory=dict)
    count_basis: CountBasis = "lowest"

    @classmethod
    def adaptive(
        cls,
        *,
        low_max_events: int = 100,
        low_max_age_seconds: float = 300.0,
        medium_max_events: int = 25,
        medium_max_age_seconds: float = 60.0,
        count_basis: CountBasis = "lowest",
    ) -> SealPolicy:
        """Defaults are HYPOTHESES (Phase 4 prompt), not measured optima."""
        low = LevelRule(low_max_events, low_max_age_seconds)
        medium = LevelRule(medium_max_events, medium_max_age_seconds)
        high = LevelRule(low_max_events, low_max_age_seconds, immediate=True)
        return cls({"LOW": low, "MEDIUM": medium, "HIGH": high, "CRITICAL": high}, count_basis)

    @classmethod
    def fixed(cls, max_events: int = 100, max_age_seconds: float = 300.0) -> SealPolicy:
        """Phase 3 behaviour: one count/age rule for every level, no risk triggers."""
        rule = LevelRule(max_events, max_age_seconds)
        return cls(dict.fromkeys(LEVELS, rule))


@dataclass(frozen=True)
class PendingLevel:
    """Pending non-receipt events of one risk level for one tenant."""

    level: str
    count: int
    oldest_age_seconds: float
    max_seq: int


@dataclass(frozen=True)
class PendingWindow:
    sealed_up_to: int
    last_seq: int
    levels: tuple[PendingLevel, ...]


def decide(window: PendingWindow, policy: SealPolicy) -> tuple[int, str] | None:
    """Return ``(up_to_seq, seal_reason)`` or None if nothing is due."""
    levels = [lv for lv in window.levels if lv.count > 0]
    if not levels or window.last_seq <= window.sealed_up_to:
        return None
    rules = [policy.rules[lv.level] for lv in levels]
    pending = window.last_seq - window.sealed_up_to
    if policy.count_basis == "lowest":
        threshold = policy.rules[
            min(levels, key=lambda lv: LEVELS.index(lv.level)).level
        ].max_events
    else:
        threshold = min(r.max_events for r in rules)
    if pending >= threshold:
        return window.sealed_up_to + threshold, "MAX_EVENTS"
    urgent = [lv for lv, r in zip(levels, rules, strict=True) if r.immediate]
    if urgent:
        reason = "RISK_CRITICAL" if any(lv.level == "CRITICAL" for lv in urgent) else "RISK_HIGH"
        return max(lv.max_seq for lv in urgent), reason
    oldest = max(lv.oldest_age_seconds for lv in levels)
    if oldest >= min(r.max_age_seconds for r in rules):
        return window.last_seq, "MAX_AGE"
    return None


def anchor_priority(levels_in_epoch: Sequence[str | None]) -> str:
    """09 §4: CRITICAL -> CRITICAL (pre-action anchoring flag), HIGH -> PRIORITY, else ROUTINE."""
    present = set(levels_in_epoch)
    if "CRITICAL" in present:
        return "CRITICAL"
    if "HIGH" in present:
        return "PRIORITY"
    return "ROUTINE"
