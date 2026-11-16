"""MCP server adapter (Phase 8, ADR-0030 §6). Spec 2026-07-28, Streamable HTTP, Python SDK 2.x.

What it is: a thin protocol front-end. ``tools/list`` returns ONLY the registered tools the
authenticated agent may call (the gateway's ``GET /v1/tools`` for that agent); ``tools/call``
becomes one ``agw_sdk.Client.call`` (one idempotency key; the gateway alone decides, records
evidence and holds the tool credentials). The adapter holds no tool credentials and no agent
keys of its own.

Authorization (spec "Authorization", 2026-07-28):
* The adapter is an OAuth 2.1 RESOURCE SERVER: RFC 9728 protected-resource metadata at
  ``/.well-known/oauth-protected-resource/mcp``; 401 + ``WWW-Authenticate`` (with
  ``resource_metadata``) for a missing/invalid token (SDK ``RequireAuthMiddleware``).
* It accepts only tokens issued FOR IT: an agent key whose ``audience`` equals this adapter's
  canonical URI. Validation happens at the issuer (the gateway) by RFC 8693 token exchange,
  which also yields a SEPARATE short-lived gateway token for the agent: the client's MCP token
  is never used as an access token anywhere else (no token passthrough).
* The authorization server is the gateway (``issuer_url``); tokens are provisioned
  out-of-band by the operator (``admin create-agent-key --audience``), not by an interactive
  OAuth code flow (documented deviation, ADR-0030).

Results: COMPLETED -> ``is_error=False`` with structured content. DENIED, PENDING_APPROVAL,
FAILED, OUTCOME_UNKNOWN -> ``is_error=True`` with the gateway status, reason codes and the
action id, never a fake success. ``agw_action_status`` lets the client poll a pending action.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import time
from dataclasses import dataclass
from typing import Any

import anyio
import httpx
import mcp_types as types
import uvicorn
from mcp.server import Server
from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.server.auth.provider import AccessToken, TokenVerifier
from mcp.server.auth.settings import AuthSettings
from mcp.server.transport_security import TransportSecuritySettings
from starlette.applications import Starlette

from agw_sdk import (
    ApprovalExpired,
    ApprovalRequired,
    Client,
    Denied,
    OutcomeUnknown,
    StillRunning,
    ToolCallError,
    ToolFailed,
)

STATUS_TOOL = "agw_action_status"
DELEGATION_HEADER = "agw-delegation"
RUN_HEADER = "agw-run-id"
GRANT = "urn:ietf:params:oauth:grant-type:token-exchange"
ACCESS = "urn:ietf:params:oauth:token-type:access_token"


@dataclass(frozen=True)
class AdapterConfig:
    gateway_url: str
    client_token: str  # this adapter's integration credential (agwi_...); never logged
    resource_url: str  # canonical URI of this MCP endpoint (token audience)
    approval_wait: float = 0.0  # 0: return PENDING_APPROVAL at once (client polls)
    call_timeout: float = 30.0

    def __repr__(self) -> str:
        return f"AdapterConfig(gateway_url={self.gateway_url!r}, resource={self.resource_url!r})"


class GatewayTokenVerifier(TokenVerifier):
    """Validates an MCP access token at its issuer (the gateway) by RFC 8693 exchange."""

    def __init__(self, cfg: AdapterConfig, transport: httpx.AsyncBaseTransport | None = None):
        self._cfg = cfg
        self._transport = transport
        self._cache: dict[bytes, AccessToken] = {}

    async def verify_token(self, token: str) -> AccessToken | None:
        key = hashlib.sha256(token.encode()).digest()
        cached = self._cache.get(key)
        if cached is not None and (cached.expires_at or 0) > time.time() + 15:
            return cached
        async with httpx.AsyncClient(
            base_url=self._cfg.gateway_url, transport=self._transport, timeout=5.0
        ) as http:
            try:
                r = await http.post(
                    "/v1/oauth/token",
                    data={
                        "grant_type": GRANT,
                        "subject_token": token,
                        "subject_token_type": ACCESS,
                    },
                    headers={"Authorization": f"Bearer {self._cfg.client_token}"},
                )
            except httpx.HTTPError:
                return None  # gateway unreachable: no token is valid (fail closed)
        if r.status_code != 200:
            self._cache.pop(key, None)
            return None
        body = r.json()
        access = AccessToken(
            token=token,
            client_id=str(body["sub"]),
            scopes=str(body.get("scope", "")).split(),
            expires_at=int(time.time()) + int(body["expires_in"]),
            resource=self._cfg.resource_url,  # the exchange succeeded only for this audience
            subject=str(body["sub"]),
            claims={"gw": body["access_token"]},  # in-memory only; never logged or returned
        )
        if len(self._cache) > 10_000:
            self._cache.clear()
        self._cache[key] = access
        return access


def _gateway_client(cfg: AdapterConfig, http: httpx.Client | None) -> Client:
    access = get_access_token()
    if access is None or not access.claims or "gw" not in access.claims:
        raise PermissionError("unauthenticated")  # unreachable behind RequireAuthMiddleware
    return Client(cfg.gateway_url, str(access.claims["gw"]), http_client=http)


def _header(ctx: Any, name: str) -> str | None:
    req = getattr(ctx, "request", None)
    headers = getattr(req, "headers", None)
    value = headers.get(name) if headers is not None else None
    return str(value) if value else None


def _error(status: str, action_id: str, **extra: Any) -> types.CallToolResult:
    body = {"status": status, "action_id": action_id, "executed": status == "COMPLETED", **extra}
    return types.CallToolResult(
        content=[types.TextContent(type="text", text=json.dumps(body))],
        structured_content=body,
        is_error=True,
    )


def build_server(cfg: AdapterConfig, http: httpx.Client | None = None) -> Server[Any]:
    """``http``: optional sync client for the gateway (tests inject the in-process app)."""

    async def list_tools(
        ctx: Any, params: types.PaginatedRequestParams | None
    ) -> types.ListToolsResult:
        client = _gateway_client(cfg, http)
        specs = await anyio.to_thread.run_sync(client.list_tools)
        tools = [
            types.Tool(
                name=str(s["tool_id"]),
                description=(
                    f"{s['operation_type']} tool executed by the AI agent audit gateway; "
                    "policy, approvals and tamper-evident evidence apply."
                ),
                input_schema={k: v for k, v in s["args_schema"].items() if k != "title"},
                annotations=types.ToolAnnotations(
                    read_only_hint=s["operation_type"] == "read",
                    destructive_hint=s["operation_type"] in ("delete", "update", "execute"),
                    open_world_hint=True,
                ),
            )
            for s in specs
        ]
        tools.append(
            types.Tool(
                name=STATUS_TOOL,
                description="Status of an earlier action (e.g. one PENDING_APPROVAL).",
                input_schema={
                    "type": "object",
                    "properties": {"action_id": {"type": "string", "format": "uuid"}},
                    "required": ["action_id"],
                    "additionalProperties": False,
                },
                annotations=types.ToolAnnotations(read_only_hint=True),
            )
        )
        return types.ListToolsResult(tools=tools)

    async def call_tool(ctx: Any, params: types.CallToolRequestParams) -> types.CallToolResult:
        client = _gateway_client(cfg, http)
        args = dict(params.arguments or {})
        if params.name == STATUS_TOOL:
            action_id = str(args.get("action_id", ""))
            try:
                out = await anyio.to_thread.run_sync(lambda: client.wait(action_id, timeout=0.1))
            except ToolCallError as exc:
                return _status_error(exc)
            return _ok(out.action_id, out.result)
        run_id = _header(ctx, RUN_HEADER)
        try:
            out = await anyio.to_thread.run_sync(
                lambda: client.call(
                    params.name,
                    args,
                    run_id=run_id,
                    delegation_token=_header(ctx, DELEGATION_HEADER),
                    approval_wait=cfg.approval_wait,
                    timeout=cfg.call_timeout,
                )
            )
        except ToolCallError as exc:
            return _status_error(exc)
        return _ok(out.action_id, out.result)

    return Server(
        "agw-gateway",
        version="0.1.0",
        instructions=(
            "Tools are executed by an audit gateway. A result with is_error=true and status "
            "PENDING_APPROVAL means a human must approve; nothing was executed yet. Poll "
            f"{STATUS_TOOL} with the action_id."
        ),
        on_list_tools=list_tools,
        on_call_tool=call_tool,
    )


def _ok(action_id: str, result: dict[str, Any]) -> types.CallToolResult:
    body = {"status": "COMPLETED", "action_id": action_id, "executed": True, "result": result}
    return types.CallToolResult(
        content=[types.TextContent(type="text", text=json.dumps(body))],
        structured_content=body,
        is_error=False,
    )


def _status_error(exc: ToolCallError) -> types.CallToolResult:
    if isinstance(exc, Denied):
        return _error("DENIED", exc.action_id, reasons=exc.reasons)
    if isinstance(exc, ApprovalRequired):
        return _error(
            "PENDING_APPROVAL",
            exc.action_id,
            approval_id=exc.approval_id,
            next=f"call {STATUS_TOOL} after a human approved",
        )
    if isinstance(exc, ApprovalExpired):
        return _error("EXPIRED", exc.action_id)
    if isinstance(exc, ToolFailed):
        return _error("FAILED", exc.action_id, error_code=exc.error_code)
    if isinstance(exc, OutcomeUnknown):
        return _error("OUTCOME_UNKNOWN", exc.action_id)
    if isinstance(exc, StillRunning):
        return _error(exc.status, exc.action_id)
    return _error(exc.status, exc.action_id)  # pragma: no cover


def build_app(
    cfg: AdapterConfig,
    *,
    http: httpx.Client | None = None,
    verifier_transport: httpx.AsyncBaseTransport | None = None,
    host: str = "127.0.0.1",
    allowed_hosts: list[str] | None = None,
) -> Starlette:
    server = build_server(cfg, http)
    security = (
        TransportSecuritySettings(
            enable_dns_rebinding_protection=True,
            allowed_hosts=allowed_hosts,
            allowed_origins=[],
        )
        if allowed_hosts
        else None
    )
    return server.streamable_http_app(
        streamable_http_path="/mcp",
        json_response=True,
        host=host,
        transport_security=security,
        auth=AuthSettings(
            issuer_url=cfg.gateway_url,
            resource_server_url=cfg.resource_url,
            validate_token_resource=True,
            required_scopes=[],
        ),
        token_verifier=GatewayTokenVerifier(cfg, verifier_transport),
    )


def main() -> None:  # pragma: no cover - process entry point
    p = argparse.ArgumentParser(prog="agw-mcp")
    p.add_argument("--host", default=os.environ.get("AGW_MCP_HOST", "127.0.0.1"))
    p.add_argument("--port", type=int, default=int(os.environ.get("AGW_MCP_PORT", "8765")))
    args = p.parse_args()
    token = os.environ.get("AGW_MCP_CLIENT_TOKEN")
    if not token and os.environ.get("AGW_MCP_CLIENT_TOKEN_FILE"):
        with open(os.environ["AGW_MCP_CLIENT_TOKEN_FILE"], encoding="ascii") as fh:
            token = fh.read().strip()
    if not token:
        raise SystemExit("AGW_MCP_CLIENT_TOKEN (missing)")
    cfg = AdapterConfig(
        gateway_url=os.environ.get("AGW_GATEWAY_URL", "http://127.0.0.1:8080"),
        client_token=token,
        resource_url=os.environ.get("AGW_MCP_RESOURCE_URL", f"http://{args.host}:{args.port}/mcp"),
        approval_wait=float(os.environ.get("AGW_MCP_APPROVAL_WAIT", "0")),
    )
    allowed = [h for h in os.environ.get("AGW_MCP_ALLOWED_HOSTS", "").split(",") if h]
    uvicorn.run(
        build_app(cfg, host=args.host, allowed_hosts=allowed or None),
        host=args.host,
        port=args.port,
        log_level="warning",
    )
