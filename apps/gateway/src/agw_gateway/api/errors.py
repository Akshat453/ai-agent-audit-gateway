"""Uniform error model (11 §2). ``message`` is a fixed string per code; nothing user-supplied
(tool args, arg values, keys, payloads) is ever echoed."""

from __future__ import annotations

import logging
from typing import Any, Final

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from agw_gateway.auth import AuthenticationFailed
from agw_gateway.db import is_db_unavailable
from agw_gateway.evidence.blobs import BlobUnavailable
from agw_gateway.evidence.payloads import PayloadUnavailable
from agw_gateway.execution.errors import GatewayError, RequestInvalid
from agw_gateway.humans import HumanAuthFailed
from agw_gateway.keys import KeyUnavailable
from agw_gateway.logs import log

logger = logging.getLogger("agw.api")

MESSAGES: Final[dict[str, str]] = {
    "IDEMPOTENCY_KEY_MISSING": "Idempotency-Key header is required.",
    "IDEMPOTENCY_KEY_INVALID": "Idempotency-Key header is malformed.",
    "UNAUTHENTICATED": "Authentication required.",
    "AGENT_ID_MISMATCH": "agent_id does not match the authenticated agent.",
    "NOT_FOUND": "Resource not found.",
    "METHOD_NOT_ALLOWED": "Method not allowed.",
    "IDEMPOTENCY_KEY_REUSED": "Idempotency-Key was used with a different request body.",
    "PAYLOAD_TOO_LARGE": "Request body too large.",
    "EVENT_NOT_SEALED": "The event is not sealed into an epoch yet; retry later.",
    "REQUEST_INVALID": "Request envelope is invalid.",
    "DEPENDENCY_UNAVAILABLE": "A required dependency is unavailable. Nothing was executed.",
    "INTERNAL": "Internal error.",
    "FORBIDDEN": "The authenticated principal lacks the required role.",
    "AGENT_NOT_PERMITTED": "Agent credentials cannot be used on human endpoints.",
    "APPROVAL_NOT_PENDING": "The approval is not pending.",
    "APPROVAL_EXPIRED": "The approval has expired.",
    "APPROVAL_STALE": "action_digest or nonce does not match the approval being decided.",
    "APPROVAL_ALREADY_DECIDED": "This approver has already decided this approval.",
    # Phase 7 (ADR-0029)
    "KEY_UNAVAILABLE": "Encryption key unavailable. Nothing was recorded or executed.",
    "STORAGE_UNAVAILABLE": "Payload storage unavailable. Nothing was recorded or executed.",
    "ROLE_REQUIRED": "The authenticated human lacks the role this operation needs.",
    "DISCLOSURE_INVALID": "The disclosure request is invalid.",
    "DISCLOSURE_DENIED": "Disclosure denied.",
    "GRANT_EXPIRED": "The disclosure grant has expired. The attempt was recorded.",
    "GRANT_REVOKED": "The disclosure grant was revoked. The attempt was recorded.",
    "NOT_GRANTEE": "This grant belongs to another auditor. The attempt was recorded.",
    "EVENT_NOT_GRANTED": "An event is outside this grant. The attempt was recorded.",
}


def request_id(request: Request) -> str:
    return str(getattr(request.state, "request_id", ""))


def error_response(
    request: Request,
    status: int,
    code: str,
    extra: dict[str, Any] | None = None,
    scheme: str = "Bearer",
) -> JSONResponse:
    body: dict[str, Any] = {
        "code": code,
        "message": MESSAGES[code],
        "request_id": request_id(request),
    }
    if extra:
        body.update(extra)
    headers = {"WWW-Authenticate": scheme} if status == 401 else None
    return JSONResponse({"error": body}, status_code=status, headers=headers)


def install_error_handlers(app: FastAPI) -> None:
    @app.exception_handler(AuthenticationFailed)
    async def _unauth(request: Request, exc: AuthenticationFailed) -> JSONResponse:
        return error_response(request, 401, "UNAUTHENTICATED")

    @app.exception_handler(HumanAuthFailed)
    async def _human_unauth(request: Request, exc: HumanAuthFailed) -> JSONResponse:
        return error_response(request, 401, "UNAUTHENTICATED", scheme="Session")

    @app.exception_handler(GatewayError)
    async def _gateway(request: Request, exc: GatewayError) -> JSONResponse:
        extra = {"fields": exc.fields} if isinstance(exc, RequestInvalid) else None
        return error_response(request, exc.http_status, exc.code, extra)

    @app.exception_handler(RequestValidationError)
    async def _validation(request: Request, exc: RequestValidationError) -> JSONResponse:
        # Field names only. FastAPI's default handler would echo input values.
        fields = sorted({".".join(str(p) for p in e.get("loc", ())) for e in exc.errors()})
        return error_response(request, 422, "REQUEST_INVALID", {"fields": fields})

    @app.exception_handler(StarletteHTTPException)
    async def _http(request: Request, exc: StarletteHTTPException) -> JSONResponse:
        if exc.status_code == 405:
            return error_response(request, 405, "METHOD_NOT_ALLOWED")
        return error_response(request, 404, "NOT_FOUND")


def unexpected_error_response(request: Request, exc: Exception) -> JSONResponse:
    rid = request_id(request)
    if isinstance(exc, KeyUnavailable | BlobUnavailable) or (
        isinstance(exc, PayloadUnavailable) and exc.code == "KEK_UNAVAILABLE"
    ):
        # Phase 7: no KEK (or MinIO for large payloads) -> nothing is written. Fail closed.
        code = "KEY_UNAVAILABLE" if not isinstance(exc, BlobUnavailable) else "STORAGE_UNAVAILABLE"
        log(logger, logging.ERROR, "encryption dependency unavailable", request_id=rid,
            error_code=code)  # fmt: skip
        return error_response(request, 503, code)
    if is_db_unavailable(exc):
        log(
            logger,
            logging.WARNING,
            "dependency unavailable",
            request_id=rid,
            error_code="DEPENDENCY_UNAVAILABLE",
        )
        return error_response(request, 503, "DEPENDENCY_UNAVAILABLE")
    log(logger, logging.ERROR, "unexpected error", request_id=rid, error_code=type(exc).__name__)
    return error_response(request, 500, "INTERNAL")
