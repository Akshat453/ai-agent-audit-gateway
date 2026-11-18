"""Test doubles for the agw CLI: a scripted gateway client and a config factory."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from agw_cli.client import GatewayUnavailable
from agw_cli.config import Config

GOLDEN = Path(__file__).parent / "golden"
SCHEMA = Path(__file__).resolve().parents[2] / "schemas" / "coding" / "coding-action-v1.schema.json"
SID = "01900000-0000-7000-8000-000000000001"
LINK = "http://localhost:3000/approvals/01900000-0000-7000-8000-0000000000aa"


def golden(agent: str, name: str) -> str:
    return (GOLDEN / agent / name).read_text(encoding="utf-8")


def cfg(tmp: Path, **over: Any) -> Config:
    values: dict[str, Any] = {
        "url": "http://gateway.test",
        "device_key": "agw_0123456789abcdef_" + "A" * 43,
        "state_dir": tmp,
        "approval_wait": 0.0,
    }
    values.update(over)
    return Config(**values)


def allow(**extra: Any) -> dict[str, Any]:
    return {
        "decision": "allow",
        "reason": "ok",
        "rule_ids": ["CMD-ALLOW"],
        "action_id": "a-1",
        "status": "AUTHORIZED",
        **extra,
    }


def deny(
    reason: str = "git push is denied; the developer pushes.", rule: str = "GIT-PUSH"
) -> dict[str, Any]:
    return {
        "decision": "deny",
        "reason": reason,
        "rule_ids": [rule],
        "action_id": "a-2",
        "status": "DENIED",
    }


def ask(role: str = "maintainer") -> dict[str, Any]:
    return {
        "decision": "ask",
        "reason": "needs approval",
        "rule_ids": ["PKG-ADD"],
        "action_id": "a-3",
        "status": "PENDING_APPROVAL",
        "approval": {
            "approval_id": "ap-1",
            "state": "PENDING",
            "required_role": role,
            "link": LINK,
        },
    }


class FakeClient:
    """Scripted stand-in for GatewayClient: ``decisions`` are returned in order."""

    def __init__(
        self,
        decisions: list[dict[str, Any] | Exception] | None = None,
        statuses: list[dict[str, Any]] | None = None,
    ) -> None:
        self.decisions = list(decisions or [])
        self.statuses = list(statuses or [])
        self.decided: list[dict[str, Any]] = []
        self.observed: list[dict[str, Any]] = []
        self.sessions: list[dict[str, Any]] = []
        self.ended: list[str] = []

    def start_session(self, body: dict[str, Any]) -> str:
        self.sessions.append(body)
        return SID

    def end_session(self, sid: str) -> dict[str, Any]:
        self.ended.append(sid)
        return {"status": "ENDED"}

    def decide(self, body: dict[str, Any]) -> dict[str, Any]:
        self.decided.append(json.loads(json.dumps(body)))
        if not self.decisions:
            raise GatewayUnavailable("no scripted decision")
        nxt = self.decisions.pop(0)
        if isinstance(nxt, Exception):
            raise nxt
        return nxt

    def action_status(self, action_id: str, wait: float) -> dict[str, Any]:
        if not self.statuses:
            return {"status": "PENDING_APPROVAL", "approval_state": "PENDING"}
        return self.statuses.pop(0)

    def observe(self, body: dict[str, Any]) -> dict[str, Any]:
        self.observed.append(body)
        return {"recorded": "COMPLETED"}

    def status(self) -> dict[str, Any]:
        return {"tenant": "t"}
