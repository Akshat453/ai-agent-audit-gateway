"""Adapter contract: one adapter per coding agent, behind a registry.

An adapter only translates: native hook JSON -> :class:`HookInput` (normalized actions), and
a final allow/deny -> the agent's native output. It never talks to the gateway. Its
:class:`AgentSpec` is plain data (events, matchers, timeout unit, config locations, how to
make hooks mandatory) that a later ``agw init`` can use to GENERATE agent configuration.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, ClassVar

from agw_cli.normalize import HookInput


class PayloadError(ValueError):
    """The native payload is not an object, or misses what the event needs."""


@dataclass(frozen=True)
class Rendered:
    stdout: str = ""
    stderr: str = ""
    exit_code: int = 0


@dataclass(frozen=True)
class Verdict:
    allow: bool
    user_message: str  # shown to the developer
    agent_message: str  # shown to the model (why, and what to do instead)


@dataclass(frozen=True)
class AgentSpec:
    """Facts from the agent's current official hook docs (docs/gateway/coding-agents.md)."""

    pre_events: tuple[str, ...]
    post_events: tuple[str, ...]
    session_start_events: tuple[str, ...]
    session_end_events: tuple[str, ...]
    default_hook_timeout_seconds: float  # documented default (or an assumption, see docs)
    timeout_unit: str  # "s" | "ms" | "n/a"
    native_ask: str  # where the agent supports a native ask (we never emit it; see docs)
    fail_closed_option: str | None  # the agent's own "block if the hook fails" switch
    config_files: tuple[str, ...]
    managed_config: tuple[str, ...]
    recommended_matchers: dict[str, str] = field(default_factory=dict)


class Adapter:
    kind: ClassVar[str]
    spec: ClassVar[AgentSpec]

    def phase(self, event: str) -> str:
        e = event
        if e in self.spec.pre_events or e == "pre":
            return "pre"
        if e in self.spec.post_events or e == "post":
            return "post"
        if e in self.spec.session_start_events or e == "session-start":
            return "session_start"
        if e in self.spec.session_end_events or e == "session-end":
            return "session_end"
        return "unknown"

    def parse(self, event: str, payload: dict[str, Any]) -> HookInput:
        raise NotImplementedError

    def render_pre(self, event: str, verdict: Verdict, allow_mode: str) -> Rendered:
        raise NotImplementedError

    def render_other(self, event: str, payload: dict[str, Any] | None) -> Rendered:
        """Post / session events: never block (they cannot), print nothing."""
        return Rendered()

    def max_wait(self, configured_hook_timeout: float) -> float:
        """Seconds the hook may spend waiting for an approval, safely below the agent's hook
        timeout (else the agent kills the hook, and most agents then fail OPEN)."""
        timeout = configured_hook_timeout or self.spec.default_hook_timeout_seconds
        return max(0.0, timeout - 15.0)


def dumps(value: Any) -> str:
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False)
