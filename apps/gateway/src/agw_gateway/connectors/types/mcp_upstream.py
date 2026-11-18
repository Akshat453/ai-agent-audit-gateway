"""MCP upstream connector (C2 §2g): connect to an external MCP server (Streamable HTTP), list
its tools and re-expose each as a gateway action, UNCLASSIFIED (denied) until an admin
classifies it. Tool names/descriptions/schemas come from the upstream and are UNTRUSTED
text: they are stored, rendered escaped, and never used in any decision. Calls go through
:class:`SafeHttp` (https, exact host allowlist, public IPs, no redirects).

Client side of MCP 2026-07-28 (stateless: ``_meta`` + ``MCP-Protocol-Version`` /
``Mcp-Method`` / ``Mcp-Name`` headers); a server that answers only the 2025-11-25 era is
initialized first (``initialize`` + ``notifications/initialized``, ``Mcp-Session-Id``).
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from typing import Annotated, Any, ClassVar, Final
from urllib.parse import urlsplit

from pydantic import BaseModel, Field, SecretStr, model_validator

from agw_gateway.connectors.manifest import (
    ActionManifest,
    ConnectorManifest,
    ManifestError,
    check_input_schema,
)
from agw_gateway.connectors.ssrf import SafeHttp, SsrfBlocked, check_url
from agw_gateway.connectors.types.base import (
    ActionFailed,
    ConnectorType,
    ExecContext,
    Health,
    StrictModel,
)

MODERN: Final = "2026-07-28"
LEGACY: Final = "2025-11-25"
MAX_TOOLS: Final = 200
CLIENT_INFO: Final = {"name": "agentguard-gateway", "version": "1"}
FALLBACK_SCHEMA: Final = {
    "type": "object",
    "additionalProperties": False,
    "required": ["arguments_json"],
    "properties": {"arguments_json": {"type": "string", "maxLength": 65536}},
}


class McpUpstreamConfig(StrictModel):
    url: Annotated[str, Field(max_length=2048)]
    allowed_hosts: tuple[str, ...]

    @model_validator(mode="after")
    def _url(self) -> McpUpstreamConfig:
        try:
            check_url(self.url, self.allowed_hosts)
        except SsrfBlocked as exc:
            raise ValueError(exc.code) from None
        return self


class McpUpstreamCredentials(StrictModel):
    bearer_token: SecretStr | None = None


def action_name(upstream: str, taken: set[str]) -> str:
    base = re.sub(r"[^a-z0-9_]", "_", upstream.lower()).strip("_") or "tool"
    if not base[0].isalpha():
        base = "t_" + base
    base = base[:32]
    name, n = base, 2
    while name in taken:
        name = f"{base[:32]}_{n}"
        n += 1
    taken.add(name)
    return name


class McpClient:
    def __init__(self, http: SafeHttp, config: McpUpstreamConfig, creds: McpUpstreamCredentials):
        self._http, self._cfg, self._creds = http, config, creds
        self._legacy_session: str | None = None
        self._legacy = False
        self._ids = 0

    def _headers(self, method: str, name: str | None, version: str) -> dict[str, str]:
        h = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            "MCP-Protocol-Version": version,
            "Mcp-Method": method,
        }
        if name is not None:
            h["Mcp-Name"] = name
        if self._creds.bearer_token is not None:
            h["Authorization"] = f"Bearer {self._creds.bearer_token.get_secret_value()}"
        if self._legacy_session is not None:
            h["Mcp-Session-Id"] = self._legacy_session
        return h

    def _post(self, method: str, params: dict[str, Any], name: str | None = None) -> Any:
        self._ids += 1
        version = LEGACY if self._legacy else MODERN
        body: dict[str, Any] = {"jsonrpc": "2.0", "id": self._ids, "method": method}
        if not self._legacy:
            params = {
                **params,
                "_meta": {
                    "io.modelcontextprotocol/protocolVersion": MODERN,
                    "io.modelcontextprotocol/clientCapabilities": {},
                    "io.modelcontextprotocol/clientInfo": CLIENT_INFO,
                },
            }
        body["params"] = params
        r = self._http.request(
            "POST",
            self._cfg.url,
            allow_hosts=self._cfg.allowed_hosts,
            headers=self._headers(method, name, version),
            json=body,
        )
        if r.status_code in (400, 404) and not self._legacy and method == "server/discover":
            return None  # not a 2026-07-28 server
        if r.status_code >= 400:
            raise ActionFailed(f"UPSTREAM_HTTP_{r.status_code}")
        if "mcp-session-id" in r.headers and self._legacy:
            self._legacy_session = r.headers["mcp-session-id"][:256]
        msg = _parse(r.text, r.headers.get("content-type", ""))
        if "error" in msg:
            raise ActionFailed("UPSTREAM_ERROR")
        return msg.get("result")

    def open(self) -> None:
        if self._post("server/discover", {}) is not None:
            return
        self._legacy = True
        self._post(
            "initialize", {"protocolVersion": LEGACY, "capabilities": {}, "clientInfo": CLIENT_INFO}
        )
        h = self._headers("notifications/initialized", None, LEGACY)
        self._http.request(
            "POST",
            self._cfg.url,
            allow_hosts=self._cfg.allowed_hosts,
            headers=h,
            json={"jsonrpc": "2.0", "method": "notifications/initialized"},
        )

    def list_tools(self) -> list[dict[str, Any]]:
        tools: list[dict[str, Any]] = []
        cursor: str | None = None
        while len(tools) < MAX_TOOLS:
            result = self._post("tools/list", {"cursor": cursor} if cursor else {}) or {}
            tools.extend(t for t in result.get("tools", []) if isinstance(t, dict))
            cursor = result.get("nextCursor")
            if not cursor:
                break
        return tools[:MAX_TOOLS]

    def call(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        result = self._post("tools/call", {"name": name, "arguments": arguments}, name=name)
        return result if isinstance(result, dict) else {}


def _parse(text: str, ctype: str) -> dict[str, Any]:
    if "text/event-stream" in ctype:
        for line in text.splitlines():
            if line.startswith("data:"):
                try:
                    msg = json.loads(line[5:].strip())
                except ValueError:
                    continue
                if isinstance(msg, dict) and ("result" in msg or "error" in msg):
                    return msg
        raise ActionFailed("UPSTREAM_MALFORMED")
    try:
        msg = json.loads(text)
    except ValueError:
        raise ActionFailed("UPSTREAM_MALFORMED") from None
    if not isinstance(msg, dict):
        raise ActionFailed("UPSTREAM_MALFORMED")
    return msg


class McpUpstreamConnector(ConnectorType):
    manifest: ClassVar[ConnectorManifest] = ConnectorManifest(
        id="mcp_upstream",
        name="MCP server (upstream)",
        category="mcp_upstream",
        auth="api_key",
        description="Re-expose an external MCP server's tools as governed gateway actions.",
        dynamic_actions=True,
    )
    config_model: ClassVar[type[BaseModel]] = McpUpstreamConfig
    credential_model: ClassVar[type[BaseModel]] = McpUpstreamCredentials

    def result_classes(self, action: str, config: Mapping[str, Any]) -> dict[str, str]:
        return {"is_error": "internal", "text": "internal"}

    def _client(self, config: BaseModel, creds: BaseModel, http: SafeHttp) -> McpClient:
        assert isinstance(config, McpUpstreamConfig)  # noqa: S101
        assert isinstance(creds, McpUpstreamCredentials)  # noqa: S101
        c = McpClient(http, config, creds)
        c.open()
        return c

    def health(self, config: BaseModel, creds: BaseModel, http: SafeHttp) -> Health:
        try:
            n = len(self._client(config, creds, http).list_tools())
        except SsrfBlocked as exc:
            return Health(False, f"SSRF_{exc.code}", {})
        except ActionFailed as exc:
            return Health(False, exc.code, {})
        except Exception as exc:
            return Health(False, "UNREACHABLE", {"error": type(exc).__name__})
        return Health(True, "OK", {"tools": n})

    def discover(
        self, config: BaseModel, creds: BaseModel, http: SafeHttp
    ) -> list[tuple[ActionManifest, str | None]]:
        taken: set[str] = set()
        out: list[tuple[ActionManifest, str | None]] = []
        for tool in self._client(config, creds, http).list_tools():
            upstream = str(tool.get("name", ""))[:200]
            if not upstream:
                continue
            schema = tool.get("inputSchema")
            try:
                if not isinstance(schema, dict):
                    raise ManifestError("no schema")
                schema = {**schema, "additionalProperties": False}
                schema.pop("$schema", None)
                check_input_schema(schema)
            except ManifestError:
                schema = FALLBACK_SCHEMA  # arguments travel as one JSON string
            out.append(
                (
                    ActionManifest(
                        name=action_name(upstream, taken),
                        description=str(tool.get("description", ""))[:4000],  # untrusted
                        input_schema=schema,
                        side_effect="execute",  # unknown upstream effect: assume the worst
                        suggested_risk="HIGH",
                    ),
                    upstream,
                )
            )
        return out

    def execute(self, ctx: ExecContext, args: Mapping[str, Any]) -> Mapping[str, Any]:
        if ctx.upstream_name is None:
            raise ActionFailed("UPSTREAM_TOOL_UNKNOWN")
        if set(args) == {"arguments_json"}:
            try:
                arguments = json.loads(str(args["arguments_json"]))
            except ValueError:
                raise ActionFailed("ARGUMENTS_JSON_INVALID") from None
            if not isinstance(arguments, dict):
                raise ActionFailed("ARGUMENTS_JSON_INVALID")
        else:
            arguments = {k: v for k, v in args.items() if v is not None}
        try:
            result = self._client(ctx.config, ctx.credentials, ctx.http).call(
                ctx.upstream_name, arguments
            )
        except SsrfBlocked as exc:
            raise ActionFailed(f"SSRF_{exc.code}") from None
        texts = [
            str(c.get("text", ""))[:20000]
            for c in result.get("content", [])
            if isinstance(c, dict) and c.get("type") == "text"
        ]
        return {"is_error": bool(result.get("isError")), "text": "\n".join(texts)[:20000]}


def upstream_host(url: str) -> str:
    return (urlsplit(url).hostname or "").lower()
