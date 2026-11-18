"""Rule hits and their combination for the coding policy. Pure: no I/O."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final, Literal

Effect = Literal["allow", "ask", "deny"]
Level = Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
LEVELS: Final = ("LOW", "MEDIUM", "HIGH", "CRITICAL")
EFFECT_ORDER: Final = ("allow", "ask", "deny")


@dataclass(frozen=True)
class Hit:
    """One matched rule. ``reason`` is a fixed text per rule (plus at most a path or pattern
    the agent itself supplied): never file content, diff text or command output."""

    rule: str
    effect: Effect
    level: Level
    reason: str
    role: str | None = None  # approving role for an ask (None = policy default)
    # Context for the "balanced" profile (e.g. "hook-config", "temp", "destructive",
    # "local-net", "external-net", "delete"); never shown, never in evidence.
    tag: str | None = None


@dataclass(frozen=True)
class Combined:
    effect: Effect
    level: Level
    rule_ids: tuple[str, ...]
    reason: str
    role: str | None


def combine(hits: list[Hit], default_role: str, critical_role: str) -> Combined:
    """deny > ask > allow; level = max over ALL hits; reason = first hit of the winning effect.

    The approving role of an ask: the critical role whenever the level is CRITICAL, else the
    role of the first ask hit that names one, else the default role.
    """
    if not hits:  # every evaluation path adds at least one hit; this is a safety net
        hits = [Hit("CODE-NO-RULE", "ask", "HIGH", "No policy rule matched this action.")]
    effect = max((h.effect for h in hits), key=EFFECT_ORDER.index)
    level = max((h.level for h in hits), key=LEVELS.index)
    winner = next(h for h in hits if h.effect == effect)
    seen: dict[str, None] = {}
    for h in hits:
        seen.setdefault(h.rule, None)
    role: str | None = None
    if effect == "ask":
        if level == "CRITICAL":
            role = critical_role
        else:
            role = next((h.role for h in hits if h.effect == "ask" and h.role), default_role)
    return Combined(effect, level, tuple(seen), winner.reason, role)
