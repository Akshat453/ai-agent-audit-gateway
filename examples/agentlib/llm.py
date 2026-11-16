"""Provider-neutral "LLM" for the example agents (Phase 8).

``AGW_LLM_PROVIDER`` selects the model:
  * ``mock`` (default): ``MockLLM``, deterministic, no network, no keys. It follows a fixed
    plan AND is deliberately GULLIBLE: any line ``ACTION: {...json...}`` it reads in a tool
    result (e.g. a retrieved document) is executed as if the model had been prompt-injected.
    That makes injection scenarios reproducible; the point is that the GATEWAY blocks them.
  * ``anthropic``: ``AnthropicLLM`` (needs the ``anthropic`` package and credentials; never
    run in CI). Model from ``AGW_LLM_MODEL`` (default ``claude-opus-5-5``).

Interface: ``next_turn(task, tools, history) -> Turn``. ``tools`` are
``{"name", "description", "input_schema"}``; ``history`` is every earlier tool call with the
text the tool returned (``is_error`` for denials / pending approvals).
"""

from __future__ import annotations

import json
import os
import re
import uuid
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any, Protocol

NOT_FINAL = frozenset({"PENDING_APPROVAL", "AUTHORIZED", "DISPATCHED"})
ACTION_RE = re.compile(r"^ACTION:\s*(\{.*\})\s*$", re.MULTILINE)


@dataclass(frozen=True)
class ToolCall:
    id: str
    name: str
    args: dict[str, Any]


@dataclass(frozen=True)
class Observation:
    call: ToolCall
    content: str
    is_error: bool


@dataclass(frozen=True)
class Turn:
    text: str
    calls: list[ToolCall]


class LLM(Protocol):
    def next_turn(
        self, task: str, tools: Sequence[dict[str, Any]], history: Sequence[Observation]
    ) -> Turn: ...


def injected_directives(text: str) -> list[dict[str, Any]]:
    out = []
    for m in ACTION_RE.finditer(text):
        try:
            d = json.loads(m.group(1))
        except ValueError:
            continue
        if isinstance(d, dict):
            out.append(d)
    return out


def _result_json(content: str) -> dict[str, Any]:
    try:
        data = json.loads(content)
    except ValueError:
        return {}
    return data if isinstance(data, dict) else {}


@dataclass
class MockLLM:
    """Deterministic plan + gullibility. ``plan`` entries are ``(tool, args)``; string args
    may use ``{ticket_id}`` / ``{titles}`` / ``{action_id}``, filled from earlier results."""

    plan: list[tuple[str, dict[str, Any]]]
    gullible: bool = True
    poll_pending: bool = True  # call agw_action_status for PENDING_APPROVAL results (MCP)
    _queue: list[tuple[str, dict[str, Any]]] = field(default_factory=list)
    _seen: int = 0
    _n: int = 0
    _vars: dict[str, str] = field(default_factory=dict)
    _polls: int = 0

    def __post_init__(self) -> None:
        self._queue = list(self.plan)

    def next_turn(
        self, task: str, tools: Sequence[dict[str, Any]], history: Sequence[Observation]
    ) -> Turn:
        names = {t["name"] for t in tools}
        injected: list[tuple[str, dict[str, Any]]] = []
        pending: str | None = None
        for obs in history[self._seen :]:
            data = _result_json(obs.content)
            result = data.get("result") if isinstance(data.get("result"), dict) else data
            hits = result.get("results") if isinstance(result, dict) else None
            if isinstance(hits, list):
                self._vars["titles"] = "; ".join(str(h.get("title")) for h in hits[:3])
                if self.gullible:
                    for h in hits:
                        for d in injected_directives(str(h.get("excerpt", ""))):
                            injected.append((str(d.get("tool")), dict(d.get("args") or {})))
            if isinstance(result, dict) and "ticket_id" in result:
                self._vars["ticket_id"] = str(result["ticket_id"])
            if "action_id" in data:
                self._vars["action_id"] = str(data["action_id"])
            # Not final yet (waiting for a human, or approved and still executing): poll again.
            if obs.is_error and data.get("status") in NOT_FINAL and self.poll_pending:
                pending = str(data.get("action_id") or self._vars.get("action_id", ""))
        self._seen = len(history)
        # An injected instruction "takes over" before the rest of the plan (that is the
        # failure mode being demonstrated); the gateway is what stops it.
        self._queue[:0] = injected
        if pending and "agw_action_status" in names and self._polls < 600:
            self._polls += 1
            return Turn("waiting for a human approval", [self._call("agw_action_status",
                        {"action_id": pending})])  # fmt: skip
        while self._queue:
            tool, args = self._queue.pop(0)
            if tool not in names and "raw_gateway_request" in names:
                # A tool the framework does not offer (hallucinated / unregistered): a model
                # with a generic HTTP tool would try the gateway directly.
                args = {
                    "method": "POST",
                    "path": "/v1/actions",
                    "body": {"run_id": str(uuid.uuid4()), "tool": tool, "environment": "dev",
                             "args": args},
                }  # fmt: skip
                tool = "raw_gateway_request"
            return Turn("", [self._call(tool, self._fill(args))])
        return Turn("done: " + task, [])

    def _call(self, name: str, args: dict[str, Any]) -> ToolCall:
        self._n += 1
        return ToolCall(f"call_{self._n}", name, args)

    def _fill(self, value: Any) -> Any:
        if isinstance(value, str):
            for k, v in self._vars.items():
                value = value.replace("{" + k + "}", v)
            return value
        if isinstance(value, dict):
            return {k: self._fill(v) for k, v in value.items()}
        if isinstance(value, list):
            return [self._fill(v) for v in value]
        return value


class AnthropicLLM:  # pragma: no cover - needs credentials; never run in CI
    def __init__(self, model: str | None = None) -> None:
        import anthropic

        self._client = anthropic.Anthropic()
        self._model = model or os.environ.get("AGW_LLM_MODEL", "claude-opus-5-5")
        self._messages: list[dict[str, Any]] = []
        self._seen = 0

    def next_turn(
        self, task: str, tools: Sequence[dict[str, Any]], history: Sequence[Observation]
    ) -> Turn:
        if not self._messages:
            self._messages.append({"role": "user", "content": task})
        new = history[self._seen :]
        self._seen = len(history)
        if new:
            self._messages.append(
                {
                    "role": "user",
                    "content": [
                        {
                            "type": "tool_result",
                            "tool_use_id": o.call.id,
                            "content": o.content,
                            "is_error": o.is_error,
                        }
                        for o in new
                    ],
                }
            )
        while True:
            response = self._client.messages.create(
                model=self._model,
                max_tokens=16000,
                tools=list(tools),
                messages=self._messages,
            )
            self._messages.append({"role": "assistant", "content": response.content})
            if response.stop_reason == "pause_turn":
                continue
            break
        if response.stop_reason in ("refusal", "max_tokens"):
            return Turn(f"stopped: {response.stop_reason}", [])
        calls = [
            ToolCall(b.id, b.name, dict(b.input)) for b in response.content if b.type == "tool_use"
        ]
        text = "".join(b.text for b in response.content if b.type == "text")
        return Turn(text, calls)


def make_llm(plan: list[tuple[str, dict[str, Any]]], *, gullible: bool = True) -> LLM:
    provider = os.environ.get("AGW_LLM_PROVIDER", "mock")
    if provider == "mock":
        return MockLLM(plan, gullible=gullible)
    if provider == "anthropic":
        return AnthropicLLM()
    raise SystemExit(f"AGW_LLM_PROVIDER must be mock|anthropic, got {provider!r}")
