"""Human-facing endpoints (Phase 5, ADR-0027): approver login and the approval API.

Every route here authenticates a HUMAN (``Authorization: Session <token>``). An AGENT
credential presented here is answered 403 ``AGENT_NOT_PERMITTED`` and recorded as a
``SECURITY_VIOLATION`` (kind AGENT_ON_HUMAN_ENDPOINT) in the agent's tenant chain.
"""

from __future__ import annotations

from typing import Annotated, Any, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, Header, Query, Request, Response
from fastapi.concurrency import run_in_threadpool
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select

from agw_gateway.api.state import GatewayState
from agw_gateway.auth import AuthenticationFailed
from agw_gateway.db import tables as t
from agw_gateway.execution.errors import AgentNotPermitted
from agw_gateway.humans import AuthenticatedHuman, HumanAuthFailed

router = APIRouter(prefix="/v1")


def _state(request: Request) -> GatewayState:
    state: GatewayState = request.app.state.agw
    return state


def authenticated_human(
    request: Request, authorization: Annotated[str | None, Header()] = None
) -> AuthenticatedHuman:
    state = _state(request)
    try:
        human = state.humans.authenticate(authorization)
    except HumanAuthFailed:
        # Is this an AGENT credential? Then it is not just unauthenticated: it is an agent
        # trying to act as a human (e.g. approve its own action). Record it, answer 403.
        try:
            agent = state.authenticator.authenticate(authorization)
        except AuthenticationFailed:
            raise HumanAuthFailed from None
        route = request.scope.get("route")
        endpoint = f"{request.method} {getattr(route, 'path', '?')}"[:128]
        state.approvals.record_agent_on_human_endpoint(agent, endpoint)
        request.state.agent_id = str(agent.agent_id)
        raise AgentNotPermitted from None
    request.state.human_id = str(human.human_id)
    return human


Human = Annotated[AuthenticatedHuman, Depends(authenticated_human)]


class _Body(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class LoginRequest(_Body):
    tenant: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{0,62}$")
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=1024)


class DecisionRequest(_Body):
    decision: Literal["APPROVE", "REJECT"]
    reason: str = Field(default="", max_length=1024)
    # Echo of what the approver was SHOWN (GET /v1/approvals/{id}): deciding a different
    # version of the action than the one displayed is impossible.
    action_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    nonce: str = Field(pattern=r"^[0-9a-f]{32}$")


@router.post("/auth/login")
async def login(request: Request, body: LoginRequest) -> dict[str, Any]:
    issued = await run_in_threadpool(
        _state(request).humans.login, body.tenant, body.username, body.password
    )
    return {
        "token_type": "Session",
        "session_token": issued.token,
        "expires_at": issued.expires_at.isoformat().replace("+00:00", "Z"),
    }


@router.get("/auth/me")
def whoami(human: Human) -> dict[str, Any]:
    """The authenticated human's own identity (no secrets)."""
    return {
        "human_id": str(human.human_id),
        "tenant": human.tenant_id,
        "username": human.username,
        "roles": sorted(human.roles),
    }


@router.post("/auth/logout", status_code=204)
def logout(
    request: Request, human: Human, authorization: Annotated[str | None, Header()] = None
) -> Response:
    _state(request).humans.logout(human, authorization)
    return Response(status_code=204)


@router.get("/approvals")
def list_approvals(
    request: Request,
    human: Human,
    state: Annotated[
        Literal["PENDING", "APPROVED", "REJECTED", "EXPIRED", "CONSUMED", "INVALIDATED"] | None,
        Query(),
    ] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
) -> dict[str, Any]:
    return {"approvals": _state(request).approvals.list_approvals(human, state, limit)}


@router.get("/approvals/{approval_id}")
def get_approval(request: Request, human: Human, approval_id: UUID) -> dict[str, Any]:
    return _state(request).approvals.get(human, approval_id)


@router.post("/approvals/{approval_id}/decision")
async def decide(
    request: Request, human: Human, approval_id: UUID, body: DecisionRequest
) -> dict[str, Any]:
    return await run_in_threadpool(
        lambda: _state(request).approvals.decide(
            human,
            approval_id,
            decision=body.decision,
            reason=body.reason,
            echoed_digest=body.action_digest,
            echoed_nonce=body.nonce,
        )
    )


@router.get("/approvals-signing-keys")
def signing_keys(request: Request, human: Human) -> dict[str, Any]:
    """Public keys that verify decision signatures (for auditors / offline verification)."""
    with _state(request).engine.connect() as conn:
        rows = conn.execute(select(t.approval_signing_keys)).all()
    return {
        "keys": [
            {"key_id": r.key_id, "algorithm": r.algorithm, "public_key": bytes(r.public_key).hex()}
            for r in rows
        ]
    }
