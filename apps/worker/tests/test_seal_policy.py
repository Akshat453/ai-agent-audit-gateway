"""Risk-adaptive seal decision (pure; ADR-0026)."""

import pytest

from agw_worker.sealing.policy import (
    PendingLevel,
    PendingWindow,
    SealPolicy,
    anchor_priority,
    decide,
)

ADAPTIVE = SealPolicy.adaptive()
FIXED = SealPolicy.fixed()


def window(
    *levels: tuple[str, int, float, int], sealed: int = -1, last: int | None = None
) -> PendingWindow:
    lv = tuple(PendingLevel(*x) for x in levels)
    top = max((x.max_seq for x in lv), default=sealed)
    return PendingWindow(sealed_up_to=sealed, last_seq=top if last is None else last, levels=lv)


def test_defaults_are_the_prompt_hypotheses() -> None:
    r = ADAPTIVE.rules
    assert (r["LOW"].max_events, r["LOW"].max_age_seconds, r["LOW"].immediate) == (100, 300, False)
    assert (r["MEDIUM"].max_events, r["MEDIUM"].max_age_seconds) == (25, 60)
    assert r["HIGH"].immediate and r["CRITICAL"].immediate
    assert not any(x.immediate for x in FIXED.rules.values())


def test_nothing_pending_or_only_receipts() -> None:
    assert decide(window(), ADAPTIVE) is None
    assert decide(window(sealed=9, last=12), ADAPTIVE) is None  # 3 receipts, no levels
    assert decide(window(("LOW", 0, 0.0, 5)), ADAPTIVE) is None


def test_low_batches_until_count_or_age() -> None:
    assert decide(window(("LOW", 99, 10.0, 98)), ADAPTIVE) is None
    assert decide(window(("LOW", 100, 10.0, 99)), ADAPTIVE) == (99, "MAX_EVENTS")
    assert decide(window(("LOW", 150, 10.0, 149)), ADAPTIVE) == (99, "MAX_EVENTS")  # exactly T
    assert decide(window(("LOW", 3, 299.9, 2)), ADAPTIVE) is None
    assert decide(window(("LOW", 3, 300.0, 2)), ADAPTIVE) == (2, "MAX_AGE")


def test_medium_uses_its_stricter_thresholds() -> None:
    assert decide(window(("MEDIUM", 25, 1.0, 24)), ADAPTIVE) == (24, "MAX_EVENTS")
    assert decide(window(("MEDIUM", 2, 60.0, 1)), ADAPTIVE) == (1, "MAX_AGE")
    # Mixed LOW+MEDIUM: by default the LOWEST level present sets the count (prompt wording);
    # the "strictest" basis takes MEDIUM's 25.
    mixed = window(("LOW", 20, 1.0, 30), ("MEDIUM", 5, 1.0, 10), sealed=5)
    assert decide(mixed, ADAPTIVE) is None
    assert decide(mixed, SealPolicy.adaptive(count_basis="strictest")) == (30, "MAX_EVENTS")
    aged = window(("LOW", 1, 1.0, 3), ("MEDIUM", 1, 61.0, 2))
    assert decide(aged, ADAPTIVE) == (3, "MAX_AGE")  # seals everything pending


def test_high_seals_up_to_and_including_the_latest_urgent_event() -> None:
    w = window(("LOW", 40, 1.0, 50), ("HIGH", 3, 0.1, 44), sealed=10, last=52)
    assert decide(w, ADAPTIVE) == (44, "RISK_HIGH")
    w = window(("HIGH", 1, 0.1, 44), ("CRITICAL", 1, 0.1, 47), sealed=10)
    assert decide(w, ADAPTIVE) == (47, "RISK_CRITICAL")
    w = window(("CRITICAL", 1, 0.1, 44), ("HIGH", 1, 0.1, 47), sealed=10)
    assert decide(w, ADAPTIVE) == (47, "RISK_CRITICAL")  # any CRITICAL in range
    assert decide(window(("HIGH", 3, 0.1, 44), sealed=10), FIXED) is None  # Phase 3 mode


def test_count_trigger_first_keeps_epochs_bounded() -> None:
    w = window(("LOW", 120, 1.0, 130), ("HIGH", 1, 0.1, 125), sealed=-1, last=130)
    assert decide(w, ADAPTIVE) == (99, "MAX_EVENTS")
    # after that seal the rest of the window is re-evaluated in the same tick
    rest = window(("LOW", 30, 1.0, 130), ("HIGH", 1, 0.1, 125), sealed=99, last=130)
    assert decide(rest, ADAPTIVE) == (125, "RISK_HIGH")


@pytest.mark.parametrize(
    ("levels", "prio"),
    [
        ([], "ROUTINE"),
        ([None, "LOW", "MEDIUM"], "ROUTINE"),
        (["LOW", "HIGH"], "PRIORITY"),
        (["HIGH", "CRITICAL", None], "CRITICAL"),
    ],
)
def test_anchor_priority(levels: list[str | None], prio: str) -> None:
    assert anchor_priority(levels) == prio


def test_count_basis_lowest_is_the_default_literal_reading() -> None:
    lowest = SealPolicy.adaptive()
    assert lowest.count_basis == "lowest"
    mixed = window(("LOW", 20, 1.0, 30), ("MEDIUM", 5, 1.0, 10), sealed=5)
    assert decide(mixed, lowest) is None  # LOW present -> 100
    assert decide(window(("MEDIUM", 25, 1.0, 24)), lowest) == (24, "MAX_EVENTS")
    assert decide(window(("LOW", 1, 1.0, 3), ("MEDIUM", 1, 61.0, 2)), lowest) == (3, "MAX_AGE")
    assert decide(window(("LOW", 1, 1.0, 3), ("HIGH", 1, 0.1, 2)), lowest) == (2, "RISK_HIGH")
