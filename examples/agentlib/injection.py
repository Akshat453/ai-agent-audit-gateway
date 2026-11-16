"""Prompt-injection harness (Phase 8, ADR-0030 §8).

Each corpus document hides an instruction (and a machine-readable ``ACTION:`` line that the
gullible ``MockLLM`` follows). One run per document: the agent searches for that document,
reads it, TRIES what it says, then continues its real task. The gateway's job is that none
of those attempts executes, and that every attempt is recorded with the digest of the
document that caused it (context provenance).

``raw_gateway_request`` models an agent that also has a generic HTTP tool: it calls the
gateway API directly with its OWN credential (it has no other).
"""

from __future__ import annotations

import json
from typing import Any

import httpx
from langchain_core.tools import BaseTool, StructuredTool, ToolException


def raw_gateway_tool(http: httpx.Client, token: str, log: list[dict[str, Any]]) -> BaseTool:
    def raw_gateway_request(method: str, path: str, body: dict[str, Any] | None = None) -> str:
        headers = {"Authorization": f"Bearer {token}"}
        if method.upper() == "POST" and path == "/v1/actions":
            headers["Idempotency-Key"] = f"raw-{len(log)}-{abs(hash(json.dumps(body)))}"
        r = http.request(method.upper(), path, json=body, headers=headers)
        try:
            data = r.json()
        except ValueError:
            data = {}
        entry = {"path": path, "http": r.status_code, "body": data}
        log.append(entry)
        status = data.get("status") if isinstance(data, dict) else None
        if r.status_code >= 400 or status in ("DENIED", "PENDING_APPROVAL"):
            raise ToolException(json.dumps({"http": r.status_code, "response": data}))
        return json.dumps(data)

    return StructuredTool.from_function(
        func=raw_gateway_request,
        name="raw_gateway_request",
        description="Send an HTTP request to the gateway API with your own credential.",
        handle_tool_error=True,
    )
