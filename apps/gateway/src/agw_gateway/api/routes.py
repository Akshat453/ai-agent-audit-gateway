"""Phase 1 endpoints (11 §5)."""

from __future__ import annotations

from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, Header, Request, Response
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse
from sqlalchemy import select, text

from agw_gateway.api.state import GatewayState
from agw_gateway.auth import AuthenticatedAgent
from agw_gateway.db import tables as t
from agw_gateway.execution.errors import NotFound, PayloadTooLarge

router = APIRouter(prefix="/v1")


def _state(request: Request) -> GatewayState:
    state: GatewayState = request.app.state.agw
    return state


def authenticated_agent(
    request: Request, authorization: Annotated[str | None, Header()] = None
) -> AuthenticatedAgent:
    agent = _state(request).authenticator.authenticate(authorization)
    request.state.agent_id = str(agent.agent_id)
    return agent


Agent = Annotated[AuthenticatedAgent, Depends(authenticated_agent)]


def _iso(value: Any) -> str | None:
    if value is None:
        return None
    return str(value.isoformat().replace("+00:00", "Z"))


@router.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@router.get("/ready")
def ready(request: Request) -> dict[str, str]:
    with _state(request).engine.connect() as conn:
        conn.execute(text("SELECT 1"))
    return {"status": "ready"}


@router.post("/actions", status_code=201)
async def post_action(
    request: Request,
    agent: Agent,
    idempotency_key: Annotated[str | None, Header()] = None,
) -> Response:
    state = _state(request)
    declared = request.headers.get("content-length")
    if (
        declared is not None
        and declared.isdigit()
        and int(declared) > state.settings.max_body_bytes
    ):
        raise PayloadTooLarge
    raw = await request.body()
    if len(raw) > state.settings.max_body_bytes:
        raise PayloadTooLarge
    result = await run_in_threadpool(state.actions.submit, agent, raw, idempotency_key)
    headers = {"Idempotent-Replayed": "true"} if result.replayed else {}
    return JSONResponse(result.body, status_code=result.status_code, headers=headers)


@router.get("/actions/{action_id}")
def get_action(request: Request, agent: Agent, action_id: UUID) -> dict[str, Any]:
    engine = _state(request).engine
    with engine.connect() as conn:
        row = conn.execute(
            select(t.actions).where(
                t.actions.c.action_id == action_id,
                t.actions.c.agent_id == agent.agent_id,  # owner only; else 404 (no oracle)
            )
        ).one_or_none()
        if row is None:
            raise NotFound
        evaluated = conn.execute(
            select(t.evidence_events.c.body).where(
                t.evidence_events.c.action_id == action_id,
                t.evidence_events.c.event_type == "POLICY_EVALUATED",
            )
        ).scalar_one_or_none()
    policy = (evaluated or {}).get("policy", {})
    return {
        "action_id": str(row.action_id),
        "run_id": str(row.run_id),
        "tool": {"id": row.tool_id, "version": row.tool_version},
        "environment": row.environment,
        "status": row.status,
        "decision": {
            "effect": row.decision,
            "policy_id": row.policy_id,
            "policy_version": row.policy_version,
            "matched_rule_ids": policy.get("rules", []),
            "reasons": policy.get("reasons", []),
            "risk_level": row.risk_level,
        },
        "result": row.result_public if row.status == "COMPLETED" else None,
        "error_code": row.error_code,
        "created_at": _iso(row.created_at),
        "updated_at": _iso(row.updated_at),
    }


@router.get("/tools")
def list_tools(request: Request, agent: Agent) -> dict[str, Any]:
    specs = _state(request).registry.callable_for(agent)
    return {
        "tools": [
            {
                "tool_id": s.meta.tool_id,
                "version": s.meta.version,
                "operation_type": s.meta.operation_type,
                "environments_allowed": sorted(s.meta.environments_allowed),
                "args_schema": s.args_schema(),
            }
            for s in specs
        ]
    }


@router.get("/runs/{run_id}/timeline")
def run_timeline(request: Request, agent: Agent, run_id: UUID) -> dict[str, Any]:
    with _state(request).engine.connect() as conn:
        rows = conn.execute(
            select(
                t.evidence_events.c.seq,
                t.evidence_events.c.event_id,
                t.evidence_events.c.event_type,
                t.evidence_events.c.occurred_at,
                t.evidence_events.c.action_id,
                t.evidence_events.c.body,
            )
            .where(
                t.evidence_events.c.tenant_id == agent.tenant_id,
                t.evidence_events.c.run_id == run_id,
                t.evidence_events.c.agent_id == agent.agent_id,
            )
            .order_by(t.evidence_events.c.seq)
        ).all()
    events = []
    for r in rows:
        body = r.body
        item: dict[str, Any] = {
            "seq": r.seq,
            "event_id": str(r.event_id),
            "type": r.event_type,
            "occurred_at": _iso(r.occurred_at),
            "action_id": str(r.action_id) if r.action_id else None,
            "tool": body.get("tool"),
        }
        if "policy" in body:
            item["decision"] = body["policy"]["effect"]
            item["reasons"] = body["policy"]["reasons"]
        if "outcome" in body:
            item["status"] = body["outcome"]["status"]
        events.append(item)
    return {"run_id": str(run_id), "events": events}
