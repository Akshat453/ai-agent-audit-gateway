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
from agw_gateway.execution.errors import GatewayError, RequestInvalid
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
    "REQUEST_INVALID": "Request envelope is invalid.",
    "DEPENDENCY_UNAVAILABLE": "A required dependency is unavailable. Nothing was executed.",
    "INTERNAL": "Internal error.",
}


def request_id(request: Request) -> str:
    return str(getattr(request.state, "request_id", ""))


def error_response(
    request: Request, status: int, code: str, extra: dict[str, Any] | None = None
) -> JSONResponse:
    body: dict[str, Any] = {
        "code": code,
        "message": MESSAGES[code],
        "request_id": request_id(request),
    }
    if extra:
        body.update(extra)
    headers = {"WWW-Authenticate": "Bearer"} if status == 401 else None
    return JSONResponse({"error": body}, status_code=status, headers=headers)


def install_error_handlers(app: FastAPI) -> None:
    @app.exception_handler(AuthenticationFailed)
    async def _unauth(request: Request, exc: AuthenticationFailed) -> JSONResponse:
        return error_response(request, 401, "UNAUTHENTICATED")

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
