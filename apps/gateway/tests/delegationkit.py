"""Helpers for the Phase 8 delegation tests (ADR-0030)."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import Engine, text

from agw_gateway.admin import create_key, ensure_agent

ALL_TOOL_SCOPES = (
    "tools:public_doc_search",
    "tools:create_ticket",
    "tools:send_email",
    "tools:delete_record",
)


def new_agent(
    migrator: Engine, tenant: str, name: str, scopes: tuple[str, ...] = ALL_TOOL_SCOPES
) -> tuple[str, str]:
    agent_id = ensure_agent(migrator, tenant, name, scopes)
    return agent_id, create_key(migrator, tenant, name)


def delegate(
    gw: Any,
    child_id: str | uuid.UUID,
    *,
    token: str | None = None,
    scopes: tuple[str, ...] = ("tools:create_ticket", "tools:public_doc_search"),
    tools: tuple[str, ...] = ("create_ticket", "public_doc_search"),
    max_risk: str = "HIGH",
    max_uses: int = 10,
    ttl: timedelta | None = None,
    parent_token: str | None = None,
    run_id: str | None = None,
    expect: int = 201,
) -> dict[str, Any]:
    if ttl is None:  # a sub-delegation must not outlive its parent
        ttl = timedelta(minutes=5 if parent_token else 10)
    body: dict[str, Any] = {
        "child_agent_id": str(child_id),
        "scopes": list(scopes),
        "tools": list(tools),
        "max_risk_level": max_risk,
        "expires_at": (datetime.now(UTC) + ttl).isoformat(),
        "max_uses": max_uses,
        "purpose": "create ticket + email summary",
    }
    if parent_token:
        body["parent_token"] = parent_token
    if run_id:
        body["run_id"] = run_id
    r = gw.client.post(
        "/v1/delegations",
        json=body,
        headers={"Authorization": f"Bearer {token or gw.world.token}"},
    )
    assert r.status_code == expect, r.text
    out: dict[str, Any] = r.json()
    return out


def act(
    gw: Any, tool: str, args: Any, child_token: str, dtoken: str, **extra: Any
) -> dict[str, Any]:
    r = gw.post(tool, args, token=child_token, delegation={"token": dtoken}, **extra)
    assert r.status_code in (200, 201), r.text
    body: dict[str, Any] = r.json()
    return body


def ticket(n: int = 0) -> dict[str, Any]:
    return {"title": f"delegated ticket {n}", "body": "summary"}


def set_scopes(migrator: Engine, agent_id: str | uuid.UUID, scopes: list[str]) -> None:
    with migrator.begin() as conn:
        conn.execute(
            text("UPDATE agents SET scopes = :s WHERE agent_id = :a"),
            {"s": scopes, "a": str(agent_id)},
        )


def expire(migrator: Engine, delegation_id: str) -> None:
    with migrator.begin() as conn:
        conn.execute(
            text(
                "UPDATE delegations SET expires_at = now() - interval '1 second' "
                "WHERE delegation_id = :d"
            ),
            {"d": delegation_id},
        )
