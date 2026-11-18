"""Helpers for the C1 coding-agent tests (ADR-0034)."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import Engine

from agw_gateway.admin import create_device_key, ensure_human
from tests.approvalkit import PASSWORD

ROOT = "/w/mintrail"
REPO_URL = "https://github.com/Akshat453/MintRail.git"
HEAD = "a" * 40


@dataclass
class CodingWorld:
    device_token: str
    other_device_token: str
    sessions: dict[str, str] = field(default_factory=dict)  # human name -> session token

    def device(self, token: str | None = None) -> dict[str, str]:
        return {"Authorization": f"Bearer {token or self.device_token}"}

    def human(self, name: str) -> dict[str, str]:
        return {"Authorization": f"Session {self.sessions[name]}"}


def make_coding_world(migrator: Engine, client: Any, tenant: str) -> CodingWorld:
    roles = {
        "dev": ["approver"],  # the developer: approver role, but not security/ledger_lead
        "dev2": ["approver"],
        "sec1": ["security"],
        "sec2": ["security"],
        "lead": ["ledger_lead"],
        "maint": ["maintainer"],
    }
    for name, r in roles.items():
        ensure_human(migrator, tenant, name, PASSWORD, r)
    world = CodingWorld(
        device_token=create_device_key(migrator, tenant, "dev", "laptop"),
        other_device_token=create_device_key(migrator, tenant, "dev2", "laptop"),
    )
    for name in roles:
        r = client.post(
            "/v1/auth/login", json={"tenant": tenant, "username": name, "password": PASSWORD}
        )
        assert r.status_code == 200, r.text
        world.sessions[name] = r.json()["session_token"]
        s = client.post("/v1/auth/step-up", json={"password": PASSWORD}, headers=world.human(name))
        assert s.status_code == 200, s.text
    return world


def start_session(client: Any, cw: CodingWorld, **over: Any) -> str:
    body = {
        "agent_kind": "claude_code",
        "agent_version": "2.1.319",
        "native_session_id": "abc123",
        "repo": {"remote_url": REPO_URL, "head_sha": HEAD},
        "workspace_root": ROOT,
        "issue": {"number": 42, "text_sha256": "b" * 64},
        **over,
    }
    r = client.post("/v1/coding/sessions", json=body, headers=cw.device())
    assert r.status_code == 201, r.text
    return str(r.json()["session_id"])


def coding_action(kind: str, target: str, **extra: Any) -> dict[str, Any]:
    targets: dict[str, Any] = {}
    if kind in ("file_read", "file_write", "file_delete", "search"):
        targets["paths"] = [target]
    elif kind == "command_exec":
        targets["command"] = target
    elif kind == "web_fetch":
        targets["url"] = target
    return {
        "agent_kind": "claude_code",
        "agent_version": "2.1.319",
        "action_type": kind,
        "workspace_root": ROOT,
        "repo": {"remote_url": REPO_URL, "head_sha": HEAD},
        "targets": targets,
        **extra,
    }


def decide(
    client: Any,
    cw: CodingWorld,
    session: str,
    kind: str,
    target: str,
    diff: str | None = None,
    correlation: str | None = None,
    token: str | None = None,
) -> Any:
    body: dict[str, Any] = {"session_id": session, "action": coding_action(kind, target)}
    if diff is not None:
        body["diff"] = diff
    body["correlation_id"] = correlation or f"toolu_{uuid.uuid4().hex[:12]}"
    return client.post("/v1/coding/decide", json=body, headers=cw.device(token))


def approve(
    client: Any, cw: CodingWorld, approval_id: str, who: str, decision: str = "APPROVE"
) -> Any:
    shown = client.get(f"/v1/approvals/{approval_id}", headers=cw.human(who))
    assert shown.status_code == 200, shown.text
    v = shown.json()
    return client.post(
        f"/v1/approvals/{approval_id}/decision",
        json={
            "decision": decision,
            "reason": "reviewed the change",
            "action_digest": v["action_digest"],
            "nonce": v["nonce"],
        },
        headers=cw.human(who),
    )
