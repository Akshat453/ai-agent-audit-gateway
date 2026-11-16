"""Phase 1 endpoints (11 §5)."""

from __future__ import annotations

import asyncio
import time
from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, Header, Path, Query, Request, Response
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse
from sqlalchemy import select, text

from agw_gateway.api.state import GatewayState
from agw_gateway.auth import AuthenticatedAgent
from agw_gateway.db import tables as t
from agw_gateway.evidence.bundle import (
    EventNotFound,
    EventNotSealed,
    anchor_claim,
    build_bundle,
    epoch_record,
    get_epoch,
)
from agw_gateway.execution.errors import EventNotSealedYet, NotFound, PayloadTooLarge
from agw_gateway.keys import KeyUnavailable

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
    state = _state(request)
    with state.engine.connect() as conn:
        conn.execute(text("SELECT 1"))
    if state.key_provider is None:
        raise KeyUnavailable("no KEK")  # -> 503 KEY_UNAVAILABLE (Phase 7)
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
async def get_action(
    request: Request,
    agent: Agent,
    action_id: UUID,
    wait: Annotated[float, Query(ge=0, le=120)] = 0,
) -> dict[str, Any]:
    """``?wait=N``: long-poll up to N seconds (capped by settings) until the status changes."""
    state = _state(request)
    view = await run_in_threadpool(_action_view, state, agent, action_id)
    deadline = time.monotonic() + min(wait, state.settings.action_long_poll_max_seconds)
    initial = view["status"]
    while view["status"] == initial and time.monotonic() < deadline:
        await asyncio.sleep(0.25)
        view = await run_in_threadpool(_action_view, state, agent, action_id)
    return view


def _action_view(state: GatewayState, agent: AuthenticatedAgent, action_id: UUID) -> dict[str, Any]:
    engine = state.engine
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
            select(t.evidence_events.c.body)
            .where(
                t.evidence_events.c.action_id == action_id,
                t.evidence_events.c.event_type == "POLICY_EVALUATED",
            )
            .order_by(t.evidence_events.c.seq)
            .limit(1)  # the request-time evaluation (a re-evaluation may follow, ADR-0027)
        ).scalar_one_or_none()
        approval = conn.execute(
            select(
                t.approvals.c.approval_id,
                t.approvals.c.state,
                t.approvals.c.expires_at,
                t.approvals.c.required_approvals,
            ).where(t.approvals.c.action_id == action_id)
        ).one_or_none()
    policy = (evaluated or {}).get("policy", {})
    view: dict[str, Any] = {
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
    if approval is not None:  # never the nonce: agents do not decide approvals
        view["approval"] = {
            "approval_id": str(approval.approval_id),
            "state": approval.state,
            "expires_at": _iso(approval.expires_at),
            "required_approvals": approval.required_approvals,
        }
    return view


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
                t.evidence_events.c.risk_level,
            )
            .where(
                t.evidence_events.c.tenant_id == agent.tenant_id,
                t.evidence_events.c.run_id == run_id,
                t.evidence_events.c.agent_id == agent.agent_id,
            )
            .order_by(t.evidence_events.c.seq)
        ).all()
        epochs = (
            conn.execute(
                select(
                    t.epochs.c.epoch_no,
                    t.epochs.c.first_seq,
                    t.epochs.c.last_seq,
                    t.epochs.c.seal_reason,
                    t.epochs.c.anchor_priority,
                )
                .where(
                    t.epochs.c.tenant_id == agent.tenant_id,
                    t.epochs.c.last_seq >= rows[0].seq,
                    t.epochs.c.first_seq <= rows[-1].seq,
                )
                .order_by(t.epochs.c.epoch_no)
            ).all()
            if rows
            else []
        )
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
            "risk_level": r.risk_level,
            # Which epoch sealed this event (None = not sealed yet). Derived from tiling.
            "epoch": next(
                (
                    {
                        "epoch_no": e.epoch_no,
                        "seal_reason": e.seal_reason,
                        "anchor_priority": e.anchor_priority,
                    }
                    for e in epochs
                    if e.first_seq <= r.seq <= e.last_seq
                ),
                None,
            ),
        }
        if "policy" in body:
            item["decision"] = body["policy"]["effect"]
            item["reasons"] = body["policy"]["reasons"]
            item["matched_rules"] = body["policy"]["rules"]
            item["controls"] = body["policy"]["controls"]
        if "risk" in body:
            item["risk"] = {
                "level": body["risk"]["level"],
                "score": body["risk"]["score"],
                "rules": body["risk"]["rules"],
                "reasons": body["risk"].get("reasons", []),
            }
        if "outcome" in body:
            item["status"] = body["outcome"]["status"]
            if "code" in body["outcome"]:
                item["code"] = body["outcome"]["code"]
        if "delegation" in body:  # Phase 8: delegation provenance (hash-linked via refs)
            item["delegation"] = body["delegation"]
        if "refs" in body:
            item["refs"] = body["refs"]
        if "approval" in body:
            ap = body["approval"]
            item["approval"] = {
                k: ap[k] for k in ("id", "dec", "votes", "req", "approver") if k in ap
            }
            if "decs" in ap:
                item["approval"]["approvers"] = [d["approver"] for d in ap["decs"]]
        events.append(item)
    return {"run_id": str(run_id), "events": events}


AUDIT_EVENTS_SCOPE = "audit:events:read"


@router.get("/events")
def list_events(
    request: Request,
    agent: Agent,
    agent_id: UUID | None = None,
    action_id: UUID | None = None,
    run_id: UUID | None = None,
    tool: Annotated[str | None, Query(max_length=128)] = None,
    event_type: Annotated[str | None, Query(alias="type", max_length=64)] = None,
    from_seq: Annotated[int | None, Query(ge=0)] = None,
    to_seq: Annotated[int | None, Query(ge=0)] = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
) -> dict[str, Any]:
    """Event HEADERS only (structural, non-sensitive). Payloads are never returned here.

    Without the ``audit:events:read`` scope an agent sees only its own events; with it, every
    event of its tenant. Never another tenant's.
    """
    ev = t.evidence_events
    conds = [ev.c.tenant_id == agent.tenant_id]
    if AUDIT_EVENTS_SCOPE not in agent.scopes:
        if agent_id is not None and agent_id != agent.agent_id:
            raise NotFound
        conds.append(ev.c.agent_id == agent.agent_id)
    elif agent_id is not None:
        conds.append(ev.c.agent_id == agent_id)
    if action_id is not None:
        conds.append(ev.c.action_id == action_id)
    if run_id is not None:
        conds.append(ev.c.run_id == run_id)
    if tool is not None:
        conds.append(ev.c.body["tool"]["id"].astext == tool)
    if event_type is not None:
        conds.append(ev.c.event_type == event_type)
    if from_seq is not None:
        conds.append(ev.c.seq >= from_seq)
    if to_seq is not None:
        conds.append(ev.c.seq <= to_seq)
    with _state(request).engine.connect() as conn:
        rows = conn.execute(
            select(
                ev.c.seq,
                ev.c.event_id,
                ev.c.event_type,
                ev.c.occurred_at,
                ev.c.event_hash,
                ev.c.body,
            )
            .where(*conds)
            .order_by(ev.c.seq)
            .limit(limit + 1)
        ).all()
    page = rows[:limit]
    return {
        "events": [
            {
                "seq": r.seq,
                "event_id": str(r.event_id),
                "type": r.event_type,
                "occurred_at": _iso(r.occurred_at),
                "event_hash": bytes(r.event_hash).hex(),
                "header": r.body,  # derived projection of the canonical header (05 §7)
            }
            for r in page
        ],
        "next_from_seq": rows[limit].seq if len(rows) > limit else None,
    }


ADMIN_EVIDENCE_SCOPE = "admin:evidence:read"


def _scoped_tenant(agent: AuthenticatedAgent, tenant: str | None) -> str:
    """Agents read their own tenant; another tenant needs the admin scope (else 404)."""
    if tenant is None or tenant == agent.tenant_id:
        return agent.tenant_id
    if ADMIN_EVIDENCE_SCOPE not in agent.scopes:
        raise NotFound
    return tenant


@router.get("/epochs/latest")
def latest_epoch(
    request: Request, agent: Agent, tenant: Annotated[str | None, Query(max_length=63)] = None
) -> dict[str, Any]:
    with _state(request).engine.connect() as conn:
        row = get_epoch(conn, _scoped_tenant(agent, tenant), None)
        claim = anchor_claim(conn, row.tenant_id, int(row.epoch_no)) if row is not None else None
    if row is None:
        raise NotFound
    return {**epoch_record(row), **({"anchor": claim} if claim else {})}


@router.get("/epochs/{epoch_no}")
def get_epoch_by_no(
    request: Request,
    agent: Agent,
    epoch_no: Annotated[int, Path(ge=0)],
    tenant: Annotated[str | None, Query(max_length=63)] = None,
) -> dict[str, Any]:
    with _state(request).engine.connect() as conn:
        row = get_epoch(conn, _scoped_tenant(agent, tenant), epoch_no)
        claim = anchor_claim(conn, row.tenant_id, int(row.epoch_no)) if row is not None else None
    if row is None:
        raise NotFound
    return {**epoch_record(row), **({"anchor": claim} if claim else {})}


@router.get("/events/{event_id}/proof")
def event_proof(
    request: Request,
    agent: Agent,
    event_id: UUID,
    tenant: Annotated[str | None, Query(max_length=63)] = None,
) -> dict[str, Any]:
    """Evidence bundle for one event: header + inclusion proof + epoch chain. No payload."""
    scope = _scoped_tenant(agent, tenant)
    try:
        with _state(request).engine.connect() as conn:
            return build_bundle(conn, event_id, tenant_id=scope, include_payload=False)
    except EventNotFound:
        raise NotFound from None
    except EventNotSealed:
        raise EventNotSealedYet from None
