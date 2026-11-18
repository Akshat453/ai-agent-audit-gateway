"""C2 endpoints (ADR-0035): connectors (admin), GitHub App manifest/install callbacks, device
enrollment (RFC 8628), repositories + .agentguard.yaml proposals, people, onboarding."""

from __future__ import annotations

import secrets
from typing import Annotated, Any, Literal
from uuid import UUID

from fastapi import APIRouter, Query, Request, Response
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse, RedirectResponse
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func, select, text

from agw_gateway.api.approval_routes import Human
from agw_gateway.api.coding_routes import DeviceDep
from agw_gateway.api.state import GatewayState
from agw_gateway.db import tables as t
from agw_gateway.enrollment import DeviceFlowError
from agw_gateway.execution.errors import Conflict, Forbidden, RequestInvalid, StepUpRequired
from agw_gateway.humans.models import ROLES
from agw_gateway.humans.service import hash_password
from agw_gateway.ids import uuid7

router = APIRouter(prefix="/v1")


def _s(request: Request) -> GatewayState:
    state: GatewayState = request.app.state.agw
    return state


async def _json(request: Request) -> dict[str, Any]:
    try:
        body = await request.json()
    except ValueError:
        raise RequestInvalid(["<body>"]) from None
    if not isinstance(body, dict):
        raise RequestInvalid(["<body>"])
    return body


# --------------------------------------------------------------------------- connectors
@router.get("/connectors/catalog", tags=["connectors"])
def catalog(request: Request, human: Human) -> dict[str, Any]:
    return {"types": _s(request).connectors.catalog()}


@router.get("/connectors", tags=["connectors"])
def list_connectors(request: Request, human: Human) -> dict[str, Any]:
    return {"connectors": _s(request).connectors.list_connectors(human)}


@router.post("/connectors", status_code=201, tags=["connectors"])
async def create_connector(request: Request, human: Human) -> dict[str, Any]:
    body = await _json(request)
    return await run_in_threadpool(_s(request).connectors.create, human, body)


@router.get("/connectors/{connector_id}", tags=["connectors"])
def get_connector(request: Request, human: Human, connector_id: UUID) -> dict[str, Any]:
    return _s(request).connectors.get(human, connector_id)


@router.patch("/connectors/{connector_id}", tags=["connectors"])
async def update_connector(request: Request, human: Human, connector_id: UUID) -> dict[str, Any]:
    body = await _json(request)
    return await run_in_threadpool(_s(request).connectors.update, human, connector_id, body)


@router.post("/connectors/{connector_id}/test", tags=["connectors"])
async def test_connector(request: Request, human: Human, connector_id: UUID) -> dict[str, Any]:
    return await run_in_threadpool(_s(request).connectors.test, human, connector_id)


@router.post("/connectors/{connector_id}/classify", tags=["connectors"])
async def classify(request: Request, human: Human, connector_id: UUID) -> dict[str, Any]:
    body = await _json(request)
    return await run_in_threadpool(_s(request).connectors.classify, human, connector_id, body)


@router.post("/connectors/{connector_id}/rotate", tags=["connectors"])
async def rotate(request: Request, human: Human, connector_id: UUID) -> dict[str, Any]:
    body = await _json(request)
    return await run_in_threadpool(_s(request).connectors.rotate, human, connector_id, body)


@router.post("/connectors/{connector_id}/disable", tags=["connectors"])
def disable(request: Request, human: Human, connector_id: UUID) -> dict[str, Any]:
    return _s(request).connectors.set_enabled(human, connector_id, False)


@router.post("/connectors/{connector_id}/enable", tags=["connectors"])
def enable(request: Request, human: Human, connector_id: UUID) -> dict[str, Any]:
    return _s(request).connectors.set_enabled(human, connector_id, True)


@router.delete("/connectors/{connector_id}", status_code=204, tags=["connectors"])
def delete(request: Request, human: Human, connector_id: UUID) -> Response:
    _s(request).connectors.delete(human, connector_id)
    return Response(status_code=204)


@router.post("/connectors/{connector_id}/github/manifest", tags=["connectors"])
def github_manifest(request: Request, human: Human, connector_id: UUID) -> dict[str, Any]:
    return _s(request).connectors.github_manifest(human, connector_id)


@router.post("/connectors/{connector_id}/github/install", tags=["connectors"])
def github_install(request: Request, human: Human, connector_id: UUID) -> dict[str, Any]:
    return _s(request).connectors.github_install_url(human, connector_id)


@router.get("/connectors/github/manifest-callback", include_in_schema=False)
async def github_manifest_callback(
    request: Request,
    code: Annotated[str, Query(max_length=200)],
    state: Annotated[str, Query(max_length=200)],
) -> RedirectResponse:
    """GitHub redirects the admin's browser here (no session header): the single-use state,
    minted for an admin with step-up, is the authorization."""
    try:
        url = await run_in_threadpool(_s(request).connectors.github_manifest_callback, code, state)
    except (Forbidden, ValueError):
        return RedirectResponse(
            f"{_s(request).settings.coding_dashboard_url}/integrations?error=github", 303
        )
    return RedirectResponse(url, 303)


@router.get("/connectors/github/setup-callback", include_in_schema=False)
async def github_setup_callback(
    request: Request,
    installation_id: Annotated[int, Query(gt=0)],
    state: Annotated[str, Query(max_length=200)] = "",
) -> RedirectResponse:
    try:
        url = await run_in_threadpool(
            _s(request).connectors.github_setup_callback, installation_id, state
        )
    except Forbidden:
        return RedirectResponse(
            f"{_s(request).settings.coding_dashboard_url}/integrations?error=github", 303
        )
    return RedirectResponse(url, 303)


# --------------------------------------------------------------------------- device enrollment
def _device_error(exc: DeviceFlowError) -> JSONResponse:
    return JSONResponse({"error": exc.code}, status_code=400, headers={"Cache-Control": "no-store"})


@router.post("/device/authorize", tags=["enrollment"])
async def device_authorize(request: Request) -> dict[str, Any]:
    body = await _json(request)
    return await run_in_threadpool(_s(request).enrollment.authorize, body)


@router.post("/device/token", tags=["enrollment"])
async def device_token(request: Request) -> Response:
    body = await _json(request)
    try:
        out = await run_in_threadpool(_s(request).enrollment.token, body)
    except DeviceFlowError as exc:
        return _device_error(exc)
    return JSONResponse(out, headers={"Cache-Control": "no-store"})


@router.get("/device/requests/{user_code}", tags=["enrollment"])
def device_request(request: Request, human: Human, user_code: str) -> dict[str, Any]:
    return _s(request).enrollment.lookup(human, user_code)


class _Decision(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    approve: bool


@router.post("/device/requests/{user_code}/decision", tags=["enrollment"])
def device_decision(
    request: Request, human: Human, user_code: str, body: _Decision
) -> dict[str, Any]:
    return _s(request).enrollment.decide(human, user_code, body.approve)


# --------------------------------------------------------------------------- repositories
@router.post("/coding/repos", tags=["coding"])
async def register_repo(request: Request, device: DeviceDep) -> dict[str, Any]:
    body = await _json(request)
    return await run_in_threadpool(_s(request).repos.register, device, body)


@router.get("/coding/repos/status", tags=["coding"])
def repo_status(
    request: Request, device: DeviceDep, remote_url: Annotated[str, Query(max_length=2048)]
) -> dict[str, Any]:
    return _s(request).repos.status(device, remote_url)


@router.get("/repos", tags=["repos"])
def list_repos(request: Request, human: Human) -> dict[str, Any]:
    return {"repos": _s(request).repos.list_repos(human)}


class _ProposalDecision(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    decision: Literal["approve", "reject"]
    reason: Annotated[str, Field(max_length=1000)] = ""


@router.post("/repos/proposals/{proposal_id}/decision", tags=["repos"])
def decide_proposal(
    request: Request, human: Human, proposal_id: UUID, body: _ProposalDecision
) -> dict[str, Any]:
    return _s(request).repos.decide(human, proposal_id, body.decision == "approve", body.reason)


# --------------------------------------------------------------------------- people
class _Invite(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    username: Annotated[str, Field(pattern=r"^[a-z0-9][a-z0-9._-]{0,63}$")]
    roles: Annotated[list[str], Field(min_length=1, max_length=6)]


@router.get("/people", tags=["people"])
def people(request: Request, human: Human) -> dict[str, Any]:
    if not human.has("admin"):
        raise Forbidden
    with _s(request).engine.connect() as conn:
        rows = conn.execute(
            select(t.humans.c.username, t.humans.c.roles, t.humans.c.status)
            .where(t.humans.c.tenant_id == human.tenant_id)
            .order_by(t.humans.c.username)
        ).all()
    return {
        "people": [
            {"username": r.username, "roles": list(r.roles), "status": r.status} for r in rows
        ]
    }


@router.post("/people", status_code=201, tags=["people"])
def invite(request: Request, human: Human, body: _Invite) -> dict[str, Any]:
    """An admin (with step-up) adds a person; the temporary password is shown ONCE."""
    state = _s(request)
    if not human.has("admin"):
        raise Forbidden
    age = human.stepped_up_age_seconds
    if age is None or age > state.settings.step_up_window_seconds:
        raise StepUpRequired
    if set(body.roles) - ROLES:
        raise RequestInvalid(["roles"])
    password = secrets.token_urlsafe(18)
    with state.engine.begin() as conn:
        exists = conn.execute(
            select(t.humans.c.human_id).where(
                t.humans.c.tenant_id == human.tenant_id, t.humans.c.username == body.username
            )
        ).first()
        if exists is not None:
            raise Conflict
        conn.execute(
            text("SELECT agw_invite_human(:t, :a, :h, :u, :r, :p)"),
            {
                "t": human.tenant_id,
                "a": human.human_id,
                "h": uuid7(),
                "u": body.username,
                "r": sorted(set(body.roles)),
                "p": hash_password(password),
            },
        )
    return {
        "username": body.username,
        "roles": sorted(set(body.roles)),
        "temporary_password": password,
    }


# --------------------------------------------------------------------------- onboarding
@router.get("/onboarding", tags=["onboarding"])
def onboarding(request: Request, human: Human) -> dict[str, Any]:
    """The new-tenant checklist on Overview; every step is derived from real state."""
    s = _s(request)
    tenant = human.tenant_id
    with s.engine.connect() as conn:

        def count(q: Any) -> int:
            return int(conn.execute(q).scalar_one())

        conns = conn.execute(
            select(t.connectors.c.type_id, t.connectors.c.status, t.connectors.c.config).where(
                t.connectors.c.tenant_id == tenant, t.connectors.c.deleted_at.is_(None)
            )
        ).all()
        humans = count(
            select(func.count()).select_from(t.humans).where(t.humans.c.tenant_id == tenant)
        )
        devices = count(
            select(func.count())
            .select_from(t.coding_devices)
            .where(t.coding_devices.c.tenant_id == tenant)
        )
        repos = count(
            select(func.count()).select_from(t.repos).where(t.repos.c.tenant_id == tenant)
        )
        protected = count(
            select(func.count())
            .select_from(t.github_prs)
            .where(t.github_prs.c.tenant_id == tenant, t.github_prs.c.conclusion == "success")
        )
    github = any(c.type_id == "github" and (c.config or {}).get("installation_ids") for c in conns)
    notify = any(c.type_id in ("slack", "email") and c.status == "connected" for c in conns)
    steps = [
        {"id": "tenant", "label": "Create tenant", "done": True},
        {
            "id": "github",
            "label": "Connect GitHub",
            "done": github,
            "href": "/integrations?add=github",
        },
        {
            "id": "notification",
            "label": "Add a notification channel",
            "done": notify,
            "href": "/integrations?add=slack",
        },
        {
            "id": "people",
            "label": "Invite people and assign roles",
            "done": humans >= 2,
            "href": "/people",
        },
        {
            "id": "device",
            "label": "Enroll the first developer device",
            "done": devices >= 1,
            "href": "/integrations?category=agent_client",
        },
        {
            "id": "init",
            "label": "Run agw init in a repository",
            "done": repos >= 1,
            "href": "/repos",
        },
        {
            "id": "protected_pr",
            "label": "First protected pull request",
            "done": protected >= 1,
            "note": "a pull request opened through AgentGuard whose evidence check passed",
            "href": "/runs",
        },
    ]
    return {"steps": steps, "complete": all(st["done"] for st in steps)}


# --------------------------------------------------------------------------- C3: GitHub
@router.post("/webhooks/github/{connector_id}", include_in_schema=False)
async def github_webhook(request: Request, connector_id: UUID) -> Response:
    """GitHub App webhook. Authenticated ONLY by X-Hub-Signature-256 (HMAC of the raw body
    with the connector's write-only webhook secret); unverified deliveries change nothing."""
    raw = await request.body()
    headers = {k.lower(): v for k, v in request.headers.items()}
    status, note = await run_in_threadpool(
        _s(request).github_checks.webhook, connector_id, headers, raw
    )
    return JSONResponse({"result": note}, status_code=status)


@router.get("/dashboard/runs/{run_id}/prs", tags=["github"])
def run_prs(request: Request, human: Human, run_id: UUID) -> dict[str, Any]:
    """PRs linked to a run (number, state, AgentGuard evidence check)."""
    with _s(request).engine.connect() as conn:
        rows = conn.execute(
            select(t.github_prs)
            .where(t.github_prs.c.tenant_id == human.tenant_id, t.github_prs.c.run_id == run_id)
            .order_by(t.github_prs.c.number)
        ).all()
    return {
        "pull_requests": [
            {
                "repo": r.repo,
                "number": r.number,
                "state": r.state,
                "conclusion": r.conclusion,
                "html_url": r.html_url,
                "summary": (r.summary or "")[:500],
            }
            for r in rows
        ]
    }


@router.get("/connectors/{connector_id}/github", tags=["github"])
def github_detail(request: Request, human: Human, connector_id: UUID) -> dict[str, Any]:
    """Installation, repositories, webhook health and tracked PRs of a GitHub connector."""
    s = _s(request)
    detail = s.connectors.get(human, connector_id)
    if detail["type_id"] != "github":
        raise RequestInvalid(["connector_id"])
    cfg = detail["config"]
    return {
        "installation_ids": cfg.get("installation_ids", []),
        "repos": cfg.get("repos", []),
        "mode": cfg.get("mode", "webhook"),
        "app_slug": cfg.get("app_slug"),
        "webhook_url": f"{s.settings.public_url.rstrip('/')}/v1/webhooks/github/{connector_id}",
        **s.github_checks.webhook_health(connector_id),
    }


@router.post("/connectors/{connector_id}/classify-proposed", tags=["connectors"])
async def classify_proposed(request: Request, human: Human, connector_id: UUID) -> dict[str, Any]:
    """Accept the type's DEFAULT classification proposal for every still-unclassified action
    (admin + step-up, a new policy version, CONNECTOR_ACTION_CLASSIFIED per action)."""
    s = _s(request)
    detail = s.connectors.get(human, connector_id)
    proposed = {
        a["name"]: a["proposed"]
        for a in detail["actions"]
        if a.get("proposed") and a["classification"] is None
    }
    if not proposed:
        return {"policy_version": detail["policy_version"], "changed": []}
    return await run_in_threadpool(
        s.connectors.classify, human, connector_id, {"actions": proposed}
    )
