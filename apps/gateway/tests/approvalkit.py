"""Helpers for the Phase 5 approval tests (ADR-0027)."""

from __future__ import annotations

import os
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from sqlalchemy import Engine, func, select, text

from agw_gateway.admin import ensure_human
from agw_gateway.approvals.service import AuthorizeResult
from agw_gateway.db import tables as t

PASSWORD = "correct-horse-battery-staple"  # test-only, never a real secret
EXTERNAL = ["bob@partner.example"]  # one external recipient -> HIGH -> REQUIRE_APPROVAL


@dataclass
class Humans:
    tenant: str
    ids: dict[str, str]
    sessions: dict[str, str] = field(default_factory=dict)

    def headers(self, name: str) -> dict[str, str]:
        return {"Authorization": f"Session {self.sessions[name]}"}


def make_humans(migrator: Engine, client: Any, tenant: str, *, step_up: bool = True) -> Humans:
    ids = {
        "alice": ensure_human(migrator, tenant, "alice", PASSWORD, ["approver"]),
        "bob": ensure_human(migrator, tenant, "bob", PASSWORD, ["approver"]),
        "audrey": ensure_human(migrator, tenant, "audrey", PASSWORD, ["auditor"]),
        "adam": ensure_human(migrator, tenant, "adam", PASSWORD, ["admin"]),  # Phase 7/9
    }
    humans = Humans(tenant=tenant, ids=ids)
    for name in ids:
        r = client.post(
            "/v1/auth/login", json={"tenant": tenant, "username": name, "password": PASSWORD}
        )
        assert r.status_code == 200, r.text
        humans.sessions[name] = r.json()["session_token"]
        if step_up:  # Phase 9: CRITICAL approvals need a recent re-authentication
            s = client.post(
                "/v1/auth/step-up", json={"password": PASSWORD}, headers=humans.headers(name)
            )
            assert s.status_code == 200, s.text
    return humans


def email(gw: Any, to: list[str] | None = None, **kw: Any) -> tuple[str, str | None]:
    """Submit send_email; return (action_id, approval_id or None)."""
    r = gw.post("send_email", {"to": to or EXTERNAL, "subject": "quarterly report"}, **kw)
    assert r.status_code in (200, 201), r.text
    body = r.json()
    return body["action_id"], (body.get("approval") or {}).get("approval_id")


def view(gw: Any, humans: Humans, approval_id: str, who: str = "alice") -> dict[str, Any]:
    r = gw.client.get(f"/v1/approvals/{approval_id}", headers=humans.headers(who))
    assert r.status_code == 200, r.text
    body: dict[str, Any] = r.json()
    return body


def decide(
    gw: Any,
    humans: Humans,
    approval_id: str,
    decision: str = "APPROVE",
    who: str = "alice",
    shown: dict[str, Any] | None = None,
    **override: Any,
) -> Any:
    shown = shown or view(gw, humans, approval_id, who)
    body = {
        "decision": decision,
        "reason": "checked recipient and content",
        "action_digest": shown["action_digest"],
        "nonce": shown["nonce"],
        **override,
    }
    return gw.client.post(
        f"/v1/approvals/{approval_id}/decision", json=body, headers=humans.headers(who)
    )


@contextmanager
def no_auto_authorize(gw: Any) -> Iterator[None]:
    """Let a decision leave the approval APPROVED without the immediate authorize call, so a
    test can tamper with / race the authorization step (as a crash would)."""
    real = gw.state.approvals.authorize
    gw.state.approvals.authorize = lambda _id: AuthorizeResult("NOOP", "TEST")
    try:
        yield
    finally:
        gw.state.approvals.authorize = real


def approval_row(engine: Engine, approval_id: str) -> Any:
    with engine.connect() as conn:
        return conn.execute(
            select(t.approvals).where(t.approvals.c.approval_id == uuid.UUID(approval_id))
        ).one()


def count(engine: Engine, table: Any, **where: Any) -> int:
    with engine.connect() as conn:
        q = select(func.count()).select_from(table)
        for k, v in where.items():
            q = q.where(table.c[k] == v)
        return int(conn.execute(q).scalar_one())


def expire_now(migrator: Engine, approval_id: str) -> None:
    """Move an approval's window into the past (DB clock), as if its TTL had run out."""
    with migrator.begin() as conn:
        conn.execute(
            text(
                "UPDATE approvals SET requested_at = now() - interval '20 minutes', "
                "expires_at = now() - interval '1 second' WHERE approval_id = :a"
            ),
            {"a": approval_id},
        )


# --------------------------------------------------------------------------- attack table
def _natural(row: tuple[str, int, int, str]) -> tuple[int, str]:
    """A2 before A10: sort by the attack number, then by name."""
    digits = "".join(c for c in row[0].split()[0] if c.isdigit())
    return (int(digits or 0), row[0])


@dataclass
class AttackLog:
    """Rows for the Phase 5 attack table (reused by Phase 10 RQ4)."""

    rows: list[tuple[str, int, int, str]] = field(default_factory=list)

    def add(self, name: str, attempts: int, unauthorized_executions: int, blocked_by: str) -> None:
        self.rows.append((name, attempts, unauthorized_executions, blocked_by))

    def write(self) -> None:
        out = os.environ.get("AGW_ATTACK_TABLE_OUT")
        if not out or not self.rows:
            return
        lines = [
            "| attack | attempts | unauthorized executions | blocked by |",
            "|---|---|---|---|",
            *(f"| {n} | {a} | {u} | {b} |" for n, a, u, b in sorted(self.rows, key=_natural)),
            "",
            f"Total: {sum(r[1] for r in self.rows)} attempts, "
            f"{sum(r[2] for r in self.rows)} unauthorized executions.",
        ]
        Path(out).write_text("\n".join(lines) + "\n", encoding="utf-8")
