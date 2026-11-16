"""Selective disclosure API (Phase 7, ADR-0029 §6). HUMAN sessions only: an agent credential is
answered 403 AGENT_NOT_PERMITTED and recorded, exactly as on the approval endpoints.

    POST /v1/auditor-keys                     auditor registers an X25519 public key
    POST /v1/disclosures                      admin grants events to an auditor (+ evidence)
    POST /v1/disclosures/{grant_id}/revoke    admin revokes a grant
    POST /v1/disclosures/{grant_id}/export    auditor exports bundles (+ evidence, every time)
"""

from __future__ import annotations

from typing import Annotated, Any, Literal
from uuid import UUID

from fastapi import APIRouter, Request
from fastapi.concurrency import run_in_threadpool
from pydantic import BaseModel, ConfigDict, Field

from agw_gateway.api.approval_routes import Human
from agw_gateway.api.state import GatewayState
from agw_gateway.keys import KeyUnavailable
from agw_gateway.privacy.disclosure import DisclosureService

router = APIRouter(prefix="/v1")


def _svc(request: Request) -> DisclosureService:
    state: GatewayState = request.app.state.agw
    if state.disclosure is None:
        raise KeyUnavailable("disclosure needs the KEK")
    return state.disclosure


class _Body(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class AuditorKeyRequest(_Body):
    public_key: str = Field(pattern=r"^[0-9a-f]{64}$")  # raw X25519 public key, hex


UUID_RE = r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
UuidStr = Annotated[str, Field(pattern=UUID_RE)]


class GrantRequest(_Body):
    auditor_id: UuidStr
    auditor_key_id: str = Field(pattern=r"^[0-9a-f]{32}$")
    event_ids: list[UuidStr] | None = Field(default=None, min_length=1, max_length=1000)
    action_id: UuidStr | None = None
    purpose: str = Field(min_length=1, max_length=500)
    expires_in_seconds: int = Field(default=7 * 24 * 3600, gt=0)
    delivery: Literal["hpke", "plaintext"] = "hpke"


class ExportRequest(_Body):
    event_ids: list[UuidStr] | None = Field(default=None, min_length=1, max_length=1000)


def _uuids(values: Any) -> Any:
    return [UUID(str(v)) for v in values] if values is not None else None


@router.post("/auditor-keys", status_code=201)
async def register_auditor_key(
    request: Request, human: Human, body: AuditorKeyRequest
) -> dict[str, Any]:
    return await run_in_threadpool(
        _svc(request).register_key, human, bytes.fromhex(body.public_key)
    )


@router.post("/disclosures", status_code=201)
async def create_grant(request: Request, human: Human, body: GrantRequest) -> dict[str, Any]:
    svc = _svc(request)
    return await run_in_threadpool(
        lambda: svc.create_grant(
            human,
            auditor_id=UUID(str(body.auditor_id)),
            auditor_key_id=body.auditor_key_id,
            event_ids=_uuids(body.event_ids),
            action_id=UUID(str(body.action_id)) if body.action_id else None,
            purpose=body.purpose,
            expires_in_seconds=body.expires_in_seconds,
            delivery=body.delivery,
        )
    )


@router.post("/disclosures/{grant_id}/revoke", status_code=204)
async def revoke_grant(request: Request, human: Human, grant_id: UUID) -> None:
    await run_in_threadpool(_svc(request).revoke_grant, human, grant_id)


@router.post("/disclosures/{grant_id}/export")
async def export_grant(
    request: Request, human: Human, grant_id: UUID, body: ExportRequest | None = None
) -> dict[str, Any]:
    svc = _svc(request)
    wanted = _uuids(body.event_ids) if body is not None else None
    return await run_in_threadpool(svc.export, human, grant_id, wanted)
