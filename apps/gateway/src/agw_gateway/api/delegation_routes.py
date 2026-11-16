"""Delegation + integration endpoints (Phase 8, ADR-0030).

POST /v1/delegations                       agent P delegates to agent C (token, once)
POST /v1/delegations/{id}/revoke           any issuer in the chain revokes (cascades)
GET  /v1/delegations/{id}/timeline         issuer's view: the delegation + child events
GET  /v1/delegation-signing-keys           published Ed25519 public keys (offline checks)
POST /v1/oauth/token                       RFC 8693 token exchange (integration clients)
"""

from __future__ import annotations

from typing import Annotated, Any, Literal
from urllib.parse import parse_qs
from uuid import UUID

from fastapi import APIRouter, Header, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse
from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, ValidationError
from sqlalchemy import select, text

from agw_gateway.api.routes import Agent, _iso
from agw_gateway.api.state import GatewayState
from agw_gateway.db import tables as t
from agw_gateway.delegation.service import DelegationRequest
from agw_gateway.execution.errors import NotFound, RequestInvalid

router = APIRouter(prefix="/v1")

UUID_RE = r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
Scope = Annotated[str, Field(pattern=r"^[A-Za-z0-9_.:\-]{1,128}$")]
ToolId = Annotated[str, Field(pattern=r"^[a-z][a-z0-9_]{1,63}$")]


def _state(request: Request) -> GatewayState:
    state: GatewayState = request.app.state.agw
    return state


class CreateDelegation(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    child_agent_id: Annotated[str, Field(pattern=UUID_RE)]
    scopes: list[Scope] = Field(min_length=1, max_length=64)
    tools: list[ToolId] = Field(min_length=1, max_length=64)
    max_risk_level: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    expires_at: AwareDatetime
    max_uses: int = Field(ge=1, le=1_000_000)
    purpose: str = Field(min_length=1, max_length=500)
    parent_token: str | None = Field(default=None, min_length=16, max_length=4096)
    run_id: Annotated[str, Field(pattern=UUID_RE)] | None = None


def _parse(model: type[BaseModel], raw: bytes) -> Any:
    try:
        return model.model_validate_json(raw)
    except ValidationError as exc:
        fields = sorted({".".join(str(p) for p in e["loc"]) or "<body>" for e in exc.errors()})
        raise RequestInvalid(fields) from None


@router.post("/delegations", status_code=201)
async def create_delegation(request: Request, agent: Agent) -> dict[str, Any]:
    state = _state(request)
    body: CreateDelegation = _parse(CreateDelegation, await request.body())
    req = DelegationRequest(
        child_agent_id=UUID(body.child_agent_id),
        scopes=tuple(body.scopes),
        tools=tuple(body.tools),
        max_risk=body.max_risk_level,
        expires_at=body.expires_at,
        max_uses=body.max_uses,
        purpose=body.purpose,
        parent_token=body.parent_token,
        run_id=UUID(body.run_id) if body.run_id else None,
    )
    result: dict[str, Any] = await run_in_threadpool(state.delegations.create, agent, req)
    return result


@router.post("/delegations/{delegation_id}/revoke")
async def revoke_delegation(request: Request, agent: Agent, delegation_id: UUID) -> dict[str, Any]:
    state = _state(request)
    result: dict[str, Any] = await run_in_threadpool(state.delegations.revoke, agent, delegation_id)
    return result


@router.get("/delegation-signing-keys")
def delegation_keys(request: Request, agent: Agent) -> dict[str, Any]:
    return {"keys": _state(request).delegations.public_keys()}


@router.get("/delegations/{delegation_id}/timeline")
def delegation_timeline(request: Request, agent: Agent, delegation_id: UUID) -> dict[str, Any]:
    """For an issuer anywhere in the chain: the delegation (and its sub-delegations) and every
    event of every child action requested under them, in seq order. Payloads are omitted."""
    state = _state(request)
    with state.engine.connect() as conn:
        tree = conn.execute(
            text(
                """
                WITH RECURSIVE down AS (
                    SELECT d.delegation_id, d.issuer_agent_id, d.child_agent_id,
                           d.created_event_id, d.depth, 0 AS lvl
                      FROM delegations d
                     WHERE d.delegation_id = :id AND d.tenant_id = :tenant
                    UNION ALL
                    SELECT c.delegation_id, c.issuer_agent_id, c.child_agent_id,
                           c.created_event_id, c.depth, down.lvl + 1
                      FROM delegations c JOIN down ON c.parent_delegation_id = down.delegation_id
                     WHERE down.lvl < 8
                )
                SELECT * FROM down
                """
            ),
            {"id": delegation_id, "tenant": agent.tenant_id},
        ).all()
        if not tree:
            raise NotFound
        up = conn.execute(
            text(
                """
                WITH RECURSIVE up AS (
                    SELECT delegation_id, parent_delegation_id, issuer_agent_id, 0 AS lvl
                      FROM delegations WHERE delegation_id = :id
                    UNION ALL
                    SELECT p.delegation_id, p.parent_delegation_id, p.issuer_agent_id, up.lvl + 1
                      FROM delegations p JOIN up ON p.delegation_id = up.parent_delegation_id
                     WHERE up.lvl < 8
                )
                SELECT issuer_agent_id FROM up
                """
            ),
            {"id": delegation_id},
        ).scalars()
        if agent.agent_id not in set(up):
            raise NotFound  # not an issuer in this chain: no existence oracle
        ids = [r.delegation_id for r in tree]
        ev = t.evidence_events
        action_ids = select(t.actions.c.action_id).where(t.actions.c.delegation_id.in_(ids))
        rows = conn.execute(
            select(
                ev.c.seq,
                ev.c.event_id,
                ev.c.event_type,
                ev.c.occurred_at,
                ev.c.action_id,
                ev.c.agent_id,
                ev.c.run_id,
                ev.c.event_hash,
                ev.c.body,
            )
            .where(
                ev.c.tenant_id == agent.tenant_id,
                ev.c.event_id.in_([r.created_event_id for r in tree])
                | ev.c.action_id.in_(action_ids),
            )
            .order_by(ev.c.seq)
        ).all()
    events = []
    for r in rows:
        item: dict[str, Any] = {
            "seq": r.seq,
            "event_id": str(r.event_id),
            "event_hash": bytes(r.event_hash).hex(),
            "type": r.event_type,
            "occurred_at": _iso(r.occurred_at),
            "agent_id": str(r.agent_id) if r.agent_id else None,
            "run_id": str(r.run_id) if r.run_id else None,
            "action_id": str(r.action_id) if r.action_id else None,
        }
        for key in ("delegation", "refs", "tool", "outcome"):
            if key in r.body:
                item[key] = r.body[key]
        if "policy" in r.body:
            item["decision"] = r.body["policy"]["effect"]
            item["reasons"] = r.body["policy"]["reasons"]
        events.append(item)
    return {
        "delegation_id": str(delegation_id),
        "delegations": [
            {
                "delegation_id": str(r.delegation_id),
                "issuer_agent_id": str(r.issuer_agent_id),
                "child_agent_id": str(r.child_agent_id),
                "depth": r.depth,
                "created_event_id": str(r.created_event_id),
            }
            for r in tree
        ],
        "events": events,
    }


@router.post("/oauth/token")
async def token_exchange(
    request: Request, authorization: Annotated[str | None, Header()] = None
) -> JSONResponse:
    """RFC 8693 token exchange for registered integration clients (the MCP adapter)."""
    state = _state(request)
    client = await run_in_threadpool(state.exchange.authenticate_client, authorization)
    raw = await request.body()
    if len(raw) > 8192:
        raise RequestInvalid(["<body>"])
    parsed = parse_qs(raw.decode("utf-8", errors="replace"), max_num_fields=10)
    form = {k: v[0] for k, v in parsed.items() if len(v) == 1}
    result = await run_in_threadpool(state.exchange.exchange, client, form)
    return JSONResponse(result, headers={"Cache-Control": "no-store", "Pragma": "no-cache"})
