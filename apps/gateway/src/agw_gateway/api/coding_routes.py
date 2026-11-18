"""C1 coding-agent endpoints (ADR-0034). Authenticated with a per-developer device key
(``Authorization: Bearer agw_...``), so the gateway's rate limits, evidence and monitoring
apply exactly as for every other agent call."""

from __future__ import annotations

import asyncio
import time
from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Request
from fastapi.concurrency import run_in_threadpool

from agw_gateway.api.routes import Agent
from agw_gateway.api.state import GatewayState
from agw_gateway.coding.service import CodingService, Device
from agw_gateway.execution.errors import PayloadTooLarge

coding_router = APIRouter(prefix="/v1/coding", tags=["coding"])


def _svc(request: Request) -> CodingService:
    state: GatewayState = request.app.state.agw
    return state.coding


async def coding_device(request: Request, agent: Agent) -> Device:
    return await run_in_threadpool(_svc(request).device, agent)


DeviceDep = Annotated[Device, Depends(coding_device)]


async def _body(request: Request) -> bytes:
    state: GatewayState = request.app.state.agw
    raw = await request.body()
    if len(raw) > state.settings.max_body_bytes:
        raise PayloadTooLarge
    return raw


@coding_router.get("/status")
async def status(request: Request, device: DeviceDep) -> dict[str, Any]:
    return await run_in_threadpool(_svc(request).status, device)


@coding_router.post("/sessions", status_code=201)
async def start_session(request: Request, device: DeviceDep) -> dict[str, Any]:
    return await run_in_threadpool(_svc(request).start, device, await _body(request))


@coding_router.post("/sessions/{session_id}/end")
async def end_session(request: Request, device: DeviceDep, session_id: UUID) -> dict[str, Any]:
    return await run_in_threadpool(_svc(request).end, device, session_id)


@coding_router.post("/decide")
async def decide(request: Request, device: DeviceDep) -> dict[str, Any]:
    """Pre-action question -> ``allow | deny | ask`` (+ reason, rule ids, approval link)."""
    return await run_in_threadpool(_svc(request).decide, device, await _body(request))


@coding_router.post("/observe", status_code=202)
async def observe(request: Request, device: DeviceDep) -> dict[str, Any]:
    """Post-action report: exit code, result digest, files touched."""
    return await run_in_threadpool(_svc(request).observe, device, await _body(request))


@coding_router.get("/actions/{action_id}")
async def action_status(
    request: Request,
    device: DeviceDep,
    action_id: UUID,
    wait: Annotated[float, Query(ge=0, le=60)] = 0,
) -> dict[str, Any]:
    """``?wait=N`` long-polls (capped by settings) until the approval state changes."""
    svc = _svc(request)
    state: GatewayState = request.app.state.agw
    view = await run_in_threadpool(svc.action_status, device, action_id)
    deadline = time.monotonic() + min(wait, state.settings.action_long_poll_max_seconds)
    initial = (view["status"], view["approval_state"])
    while (view["status"], view["approval_state"]) == initial and time.monotonic() < deadline:
        await asyncio.sleep(0.25)
        view = await run_in_threadpool(svc.action_status, device, action_id)
    return view
