"""The per-tenant remote MCP endpoint ``POST /mcp`` (C2, ADR-0035 §5).

Dual-era, as MCP 2026-07-28 recommends for servers that must also serve older clients:

* **Modern (2026-07-28), stateless:** every request carries ``_meta`` with
  ``io.modelcontextprotocol/protocolVersion`` and ``clientCapabilities``; the headers
  ``MCP-Protocol-Version``, ``Mcp-Method`` (and ``Mcp-Name`` for ``tools/call``) must match the
  body. ``server/discover`` is implemented; results carry ``resultType``; ``tools/list`` carries
  ``ttlMs`` and ``cacheScope: "private"`` (the list depends on the caller's authorization).
* **Legacy (2025-11-25 and earlier):** ``initialize`` / ``notifications/initialized`` / ``ping``
  without sessions (no ``Mcp-Session-Id`` is minted).

Identity: an OAuth access token issued by :mod:`oauth` for THIS resource, bound to a developer
and a device. Tools are the classified, enabled connector actions that device may call; a call
is an ordinary ``POST /v1/actions`` submission, so identity -> risk -> policy -> approval ->
evidence applies unchanged. Tool descriptions are written by the gateway; an upstream's
(untrusted) description is never forwarded to the client's model.
"""

from __future__ import annotations

import json
import time
import uuid
from dataclasses import dataclass
from typing import Any, Final
from urllib.parse import urlsplit

from sqlalchemy import select

from agw_gateway.db import tables as t
from agw_gateway.execution.errors import GatewayError
from agw_gateway.mcp_remote.oauth import McpPrincipal

MODERN: Final = "2026-07-28"
LEGACY: Final = ("2025-11-25", "2025-06-18", "2025-03-26")
SERVER_INFO: Final = {"name": "agentguard", "version": "1"}
NS: Final = uuid.UUID("6d9a0c5e-7f1b-4d8e-9a1f-0c2e5b7a4d10")


@dataclass
class McpResponse:
    status: int
    body: dict[str, Any] | None
    headers: dict[str, str]


def _err(id_: Any, code: int, message: str, status: int = 200, data: Any = None) -> McpResponse:
    e: dict[str, Any] = {"code": code, "message": message}
    if data is not None:
        e["data"] = data
    return McpResponse(status, {"jsonrpc": "2.0", "id": id_, "error": e}, {})


class McpServer:
    def __init__(self, state: Any, allowed_origins: frozenset[str], wait_seconds: float = 25.0):
        self._state = state
        self._origins = allowed_origins
        self._wait = wait_seconds

    def origin_ok(self, origin: str | None) -> bool:
        if origin is None:
            return True
        p = urlsplit(origin)
        return f"{p.scheme}://{p.netloc}" in self._origins

    def handle(self, principal: McpPrincipal, headers: dict[str, str], raw: bytes) -> McpResponse:
        try:
            msg = json.loads(raw)
        except ValueError:
            return _err(None, -32700, "Parse error", 400)
        if (
            not isinstance(msg, dict)
            or msg.get("jsonrpc") != "2.0"
            or not isinstance(msg.get("method"), str)
        ):
            return _err(None, -32600, "Invalid Request", 400)
        method: str = msg["method"]
        id_ = msg.get("id")
        raw_params = msg.get("params")
        params: dict[str, Any] = raw_params if isinstance(raw_params, dict) else {}
        if "id" not in msg:  # a notification
            return McpResponse(202, None, {})
        raw_meta = params.get("_meta")
        meta: dict[str, Any] = raw_meta if isinstance(raw_meta, dict) else {}
        modern = "io.modelcontextprotocol/protocolVersion" in meta
        if modern:
            if meta.get("io.modelcontextprotocol/protocolVersion") != MODERN:
                return _err(
                    id_,
                    -32022,
                    "Unsupported protocol version",
                    400,
                    {
                        "supported": [MODERN, *LEGACY],
                        "requested": meta.get("io.modelcontextprotocol/protocolVersion"),
                    },
                )
            if "io.modelcontextprotocol/clientCapabilities" not in meta:
                return _err(id_, -32602, "Missing clientCapabilities", 400)
            if headers.get("mcp-protocol-version") != MODERN or headers.get("mcp-method") != method:
                return _err(id_, -32020, "Header mismatch", 400)
            if method == "tools/call" and headers.get("mcp-name") != params.get("name"):
                return _err(id_, -32020, "Header mismatch", 400)
        else:
            version = headers.get("mcp-protocol-version")
            if version is not None and version not in LEGACY and method != "initialize":
                return _err(
                    id_,
                    -32022,
                    "Unsupported protocol version",
                    400,
                    {"supported": [MODERN, *LEGACY], "requested": version},
                )
        result = self._dispatch(principal, method, params, modern)
        if result is None:
            return _err(id_, -32601, f"Method not found: {method[:64]}", 404 if modern else 200)
        if isinstance(result, McpResponse):
            result.body = {"jsonrpc": "2.0", "id": id_, **(result.body or {})}
            return result
        if modern:
            result = {
                "resultType": "complete",
                **result,
                "_meta": {"io.modelcontextprotocol/serverInfo": SERVER_INFO},
            }
        return McpResponse(200, {"jsonrpc": "2.0", "id": id_, "result": result}, {})

    def _dispatch(
        self, p: McpPrincipal, method: str, params: dict[str, Any], modern: bool
    ) -> dict[str, Any] | McpResponse | None:
        if method == "server/discover" and modern:
            return {
                "supportedVersions": [MODERN, *LEGACY],
                "capabilities": {"tools": {}},
                "instructions": "AgentGuard: every tool call is policy-checked, may need a "
                "human approval, and is recorded as tamper-evident evidence.",
                "ttlMs": 300_000,
                "cacheScope": "private",
            }
        if method == "initialize" and not modern:
            requested = params.get("protocolVersion")
            version = requested if requested in LEGACY else LEGACY[0]
            return {
                "protocolVersion": version,
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": SERVER_INFO,
            }
        if method == "ping" and not modern:
            return {}
        if method == "tools/list":
            tools = [self._tool(s) for s in self._state.registry.callable_for(p.agent)]
            out: dict[str, Any] = {"tools": tools}
            if modern:
                out.update(ttlMs=60_000, cacheScope="private")
            return out
        if method == "tools/call":
            return self._call(p, params)
        return None

    def _tool(self, spec: Any) -> dict[str, Any]:
        b = spec.binding
        if b.type_id not in ("mcp_upstream", "http_api"):
            # Built-in types: the description is the gateway's own code (trusted), e.g. the
            # GitHub dev-tools that tell agents to use git_submit_change instead of git push.
            from agw_gateway.connectors.types import CATALOG  # noqa: PLC0415

            ctype = CATALOG.get(b.type_id)
            m = (
                next((a for a in ctype.manifest.actions if a.name == b.action), None)
                if ctype
                else None
            )
            if m is not None and m.description:
                return {
                    "name": spec.meta.tool_id,
                    "title": f"{b.slug}: {b.action}",
                    "description": m.description + " (Policy-checked by AgentGuard.)",
                    "inputSchema": spec.args_model.model_json_schema(),
                }
        side = {"read": "reads", "update": "changes", "delete": "deletes", "execute": "runs"}
        desc = (
            f"{b.action.replace('_', ' ')} via connector '{b.slug}' "
            f"({side.get(spec.meta.operation_type, 'acts on')} external data). "
            "Policy-checked by AgentGuard; may require human approval."
        )
        return {
            "name": spec.meta.tool_id,
            "title": f"{b.slug}: {b.action}",
            "description": desc,
            "inputSchema": spec.args_model.model_json_schema(),
        }

    def _call(self, p: McpPrincipal, params: dict[str, Any]) -> dict[str, Any] | McpResponse:
        name, arguments = params.get("name"), params.get("arguments") or {}
        if not isinstance(name, str) or not isinstance(arguments, dict):
            return McpResponse(200, {"error": {"code": -32602, "message": "Invalid params"}}, {})
        run_id = uuid.uuid5(NS, f"{p.agent.agent_id}:{p.client_id}")
        # The action's own target environment (GitHub dev-tools: "dev"), else production.
        spec = self._state.registry.resolve(name, None, p.agent.tenant_id)
        env = "prod"
        if spec is not None and "prod" not in spec.meta.environments_allowed:
            env = "dev" if "dev" in spec.meta.environments_allowed else "staging"
        raw = json.dumps(
            {"run_id": str(run_id), "tool": name, "environment": env, "args": arguments}
        ).encode()
        try:
            res = self._state.actions.submit(p.agent, raw, f"mcp-{uuid.uuid4().hex}")
        except GatewayError as exc:
            return {
                "content": [{"type": "text", "text": f"AgentGuard refused the call: {exc.code}"}],
                "isError": True,
            }
        body = res.body
        status = body.get("status")
        if status == "DENIED":
            reasons = ", ".join(body.get("decision", {}).get("reasons", [])) or "policy"
            return {
                "content": [{"type": "text", "text": f"AgentGuard denied this call ({reasons})."}],
                "isError": True,
            }
        if status == "PENDING_APPROVAL":
            ap = body.get("approval", {}).get("approval_id", "")
            link = f"{self._state.settings.coding_dashboard_url.rstrip('/')}/approvals/{ap}"
            return {
                "content": [
                    {
                        "type": "text",
                        "text": (
                            f"Approval pending: {link}. The action runs once approved "
                            f"(action {body['action_id']})."
                        ),
                    }
                ],
                "isError": True,
            }
        final = self._await(body["action_id"])
        if final is None:
            return {
                "content": [
                    {"type": "text", "text": f"Still running (action {body['action_id']})."}
                ]
            }
        if final.status != "COMPLETED":
            return {
                "content": [
                    {"type": "text", "text": f"Failed: {final.error_code or final.status}"}
                ],
                "isError": True,
            }
        text = json.dumps(final.result_public or {}, sort_keys=True)[:20000]
        return {
            "content": [{"type": "text", "text": text}],
            "structuredContent": final.result_public or {},
        }

    def _await(self, action_id: str) -> Any:
        deadline = time.monotonic() + self._wait
        while True:
            with self._state.engine.connect() as conn:
                row = conn.execute(
                    select(
                        t.actions.c.status, t.actions.c.result_public, t.actions.c.error_code
                    ).where(t.actions.c.action_id == uuid.UUID(action_id))
                ).one()
            if row.status in ("COMPLETED", "FAILED", "DENIED", "EXPIRED"):
                return row
            if time.monotonic() >= deadline:
                return None
            if self._state.runner is not None:
                self._state.runner.nudge()
            time.sleep(0.2)
