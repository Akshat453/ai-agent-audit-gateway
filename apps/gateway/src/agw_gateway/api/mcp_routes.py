"""C2 remote MCP endpoint + its OAuth authorization server (ADR-0035 §5)."""

from __future__ import annotations

from typing import Any
from urllib.parse import parse_qsl, urlsplit

from fastapi import APIRouter, Request, Response
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse, RedirectResponse

from agw_gateway.api.approval_routes import Human
from agw_gateway.api.state import GatewayState
from agw_gateway.mcp_remote.oauth import OAuthError
from agw_gateway.mcp_remote.server import McpServer

router = APIRouter()
NO_STORE = {"Cache-Control": "no-store", "Pragma": "no-cache"}


def _s(request: Request) -> GatewayState:
    state: GatewayState = request.app.state.agw
    return state


def _oauth_error(exc: OAuthError) -> JSONResponse:
    return JSONResponse({"error": exc.code}, status_code=exc.http_status, headers=NO_STORE)


@router.get("/.well-known/oauth-protected-resource", include_in_schema=False)
@router.get("/.well-known/oauth-protected-resource/mcp", include_in_schema=False)
def protected_resource(request: Request) -> dict[str, Any]:
    return _s(request).oauth.protected_resource()


@router.get("/.well-known/oauth-authorization-server", include_in_schema=False)
def as_metadata(request: Request) -> dict[str, Any]:
    return _s(request).oauth.metadata()


@router.post("/oauth/register", include_in_schema=False)
async def register(request: Request) -> Response:
    try:
        body = await request.json()
        if not isinstance(body, dict):
            raise OAuthError("invalid_client_metadata")
        out = await run_in_threadpool(_s(request).oauth.register, body)
    except ValueError:
        return _oauth_error(OAuthError("invalid_client_metadata"))
    except OAuthError as exc:
        return _oauth_error(exc)
    return JSONResponse(out, status_code=201, headers=NO_STORE)


@router.get("/oauth/authorize", include_in_schema=False)
async def authorize(request: Request) -> Response:
    q = dict(request.query_params)
    try:
        url = await run_in_threadpool(_s(request).oauth.consent_url, q)
    except OAuthError as exc:
        # Never redirect to an unvalidated redirect_uri: errors are shown here.
        return _oauth_error(exc)
    return RedirectResponse(url, 302)


@router.get("/v1/oauth/consent", tags=["oauth"])
async def consent_info(request: Request, human: Human) -> Response:
    q = dict(request.query_params)
    try:
        req = await run_in_threadpool(_s(request).oauth.check_request, q)
    except OAuthError as exc:
        return _oauth_error(exc)
    return JSONResponse(
        {
            "client_id": req["client_id"],
            "client_name": req["client_name"],
            "redirect_host": urlsplit(req["redirect_uri"]).netloc,
            "resource": req["resource"],
            "scope": req["scope"],
            "developer": human.username,
        }
    )


@router.post("/v1/oauth/consent", tags=["oauth"])
async def consent(request: Request, human: Human) -> Response:
    body = await request.json()
    params = body.get("params") if isinstance(body, dict) else None
    if not isinstance(params, dict) or not isinstance(body.get("allow"), bool):
        return _oauth_error(OAuthError("invalid_request"))
    try:
        url = await run_in_threadpool(
            _s(request).oauth.approve,
            human,
            {str(k): str(v) for k, v in params.items()},
            body["allow"],
        )
    except OAuthError as exc:
        return _oauth_error(exc)
    return JSONResponse({"redirect_to": url}, headers=NO_STORE)


@router.post("/oauth/token", include_in_schema=False)
async def token(request: Request) -> Response:
    form = dict(
        parse_qsl((await request.body()).decode("utf-8", "replace"), keep_blank_values=True)
    )
    try:
        out = await run_in_threadpool(_s(request).oauth.token, form)
    except OAuthError as exc:
        return _oauth_error(exc)
    return JSONResponse(out, headers=NO_STORE)


@router.post("/oauth/revoke", include_in_schema=False)
async def revoke(request: Request) -> Response:
    form = dict(parse_qsl((await request.body()).decode("utf-8", "replace")))
    await run_in_threadpool(_s(request).oauth.revoke, form)
    return Response(status_code=200)


def _server(request: Request) -> McpServer:
    s = _s(request)
    srv: McpServer | None = getattr(request.app.state, "mcp_server", None)
    if srv is None:
        origins = {s.settings.public_url.rstrip("/"), s.settings.coding_dashboard_url.rstrip("/")}
        srv = McpServer(
            s, frozenset(f"{urlsplit(o).scheme}://{urlsplit(o).netloc}" for o in origins)
        )
        request.app.state.mcp_server = srv
    return srv


@router.post("/mcp", include_in_schema=False)
async def mcp(request: Request) -> Response:
    s = _s(request)
    srv = _server(request)
    if not srv.origin_ok(request.headers.get("origin")):
        return Response(status_code=403)
    principal = await run_in_threadpool(s.oauth.authenticate, request.headers.get("authorization"))
    if principal is None:
        has_token = bool(request.headers.get("authorization"))
        return JSONResponse(
            {"error": "invalid_token" if has_token else "unauthorized"},
            status_code=401,
            headers={"WWW-Authenticate": s.oauth.challenge("invalid_token" if has_token else None)},
        )
    raw = await request.body()
    headers = {k.lower(): v for k, v in request.headers.items()}
    out = await run_in_threadpool(srv.handle, principal, headers, raw)
    if out.body is None:
        return Response(status_code=out.status)
    return JSONResponse(out.body, status_code=out.status, headers=out.headers)


@router.get("/mcp", include_in_schema=False)
@router.delete("/mcp", include_in_schema=False)
def mcp_other() -> Response:
    return Response(status_code=405, headers={"Allow": "POST"})
