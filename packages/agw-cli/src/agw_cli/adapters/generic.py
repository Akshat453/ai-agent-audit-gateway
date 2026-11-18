"""Adapters for agents without a hook system of their own.

* ``mcp_generic``: MCP-only IDEs. Input is the MCP JSON-RPC ``tools/call`` request a filtering
  proxy intercepted; allow prints the request unchanged (forward it), deny prints a JSON-RPC
  response whose result has ``isError: true`` (return it to the client, the model sees why).
  The server name comes from ``$AGW_MCP_SERVER`` (the request does not carry it).
* ``other``: a documented neutral JSON protocol for anything else::

      stdin  {"event": "pre", "session_id": "...", "cwd": "...", "agent_version": "...",
              "action": {"action_type": "...", "targets": {...}}, "diff": "..."}
      stdout {"decision": "allow" | "deny", "reason": "..."}
"""

from __future__ import annotations

import os
from typing import Any

from agw_cli.adapters.base import Adapter, AgentSpec, PayloadError, Rendered, Verdict, dumps
from agw_cli.normalize import HookInput, PreAction, build, digest_json, fallback_correlation

KNOWN_TYPES = (
    "file_read",
    "file_write",
    "file_delete",
    "command_exec",
    "search",
    "web_fetch",
    "mcp_call",
    "git_op",
)


class McpGenericAdapter(Adapter):
    kind = "mcp_generic"
    spec = AgentSpec(
        pre_events=("tools/call",),
        post_events=("tools/result",),
        session_start_events=("initialize",),
        session_end_events=("shutdown",),
        default_hook_timeout_seconds=120,  # set by the proxy that calls the hook
        timeout_unit="n/a",
        native_ask="n/a (no hook system; a filtering proxy calls agw)",
        fail_closed_option="the proxy must treat a non-zero exit or non-JSON output as deny",
        config_files=(".vscode/mcp.json (point the server entry at the filtering proxy)",),
        managed_config=("VS Code ChatMCP / ChatAllowedMcpServers policies",),
    )

    def parse(self, event: str, payload: dict[str, Any]) -> HookInput:
        phase = self.phase(event)
        hi = HookInput(
            phase=phase, native_session=str(os.environ.get("AGW_MCP_SESSION", "default"))
        )
        if phase == "pre":
            if payload.get("method") != "tools/call":
                raise PayloadError("not a tools/call request")
            params = payload.get("params")
            if not isinstance(params, dict) or not isinstance(params.get("name"), str):
                raise PayloadError("params.name")
            server = os.environ.get("AGW_MCP_SERVER", "")
            a = build(
                agent_kind=self.kind,
                action_type="mcp_call",
                native_tool=params["name"],
                cwd=os.getcwd(),
                mcp={"server": server, "tool": params["name"]},
                args_sha256=digest_json(params.get("arguments")),
            )
            hi.actions = [PreAction(a, correlation=f"rpc:{payload.get('id')}")]
        elif phase == "post":
            result = payload.get("result")
            hi.correlation = f"rpc:{payload.get('id')}"
            hi.action_type = "mcp_call"
            hi.success = "error" not in payload and not (
                isinstance(result, dict) and result.get("isError") is True
            )
            hi.result_sha256 = digest_json(result if result is not None else payload.get("error"))
        return hi

    def render_pre(self, event: str, verdict: Verdict, allow_mode: str) -> Rendered:
        raise NotImplementedError  # handled by render_pre_with_request

    def render_pre_with_request(self, request: dict[str, Any], verdict: Verdict) -> Rendered:
        if verdict.allow:
            return Rendered(stdout=dumps(request))
        response = {
            "jsonrpc": "2.0",
            "id": request.get("id"),
            "result": {
                "content": [{"type": "text", "text": verdict.agent_message}],
                "isError": True,
            },
        }
        return Rendered(stdout=dumps(response), stderr=verdict.user_message)


class OtherAdapter(Adapter):
    kind = "other"
    spec = AgentSpec(
        pre_events=("pre",),
        post_events=("post",),
        session_start_events=("session-start",),
        session_end_events=("session-end",),
        default_hook_timeout_seconds=120,
        timeout_unit="s",
        native_ask="n/a",
        fail_closed_option="the caller must treat a non-zero exit or non-JSON output as deny",
        config_files=(),
        managed_config=(),
    )

    def parse(self, event: str, payload: dict[str, Any]) -> HookInput:
        phase = self.phase(event)
        cwd = payload.get("cwd") if isinstance(payload.get("cwd"), str) else None
        version = (
            payload.get("agent_version") if isinstance(payload.get("agent_version"), str) else None
        )
        hi = HookInput(
            phase=phase,
            native_session=str(payload.get("session_id") or "default")[:128],
            cwd=cwd,
            agent_version=version,
        )
        if phase not in ("pre", "post"):
            return hi
        act = payload.get("action")
        if not isinstance(act, dict):
            raise PayloadError("action")
        kind = act.get("action_type")
        raw_targets = act.get("targets")
        targets: dict[str, Any] = raw_targets if isinstance(raw_targets, dict) else {}
        diff = payload.get("diff") if isinstance(payload.get("diff"), str) else None
        paths = [p for p in targets.get("paths", []) if isinstance(p, str)]
        raw_mcp = targets.get("mcp")
        mcp: dict[str, Any] | None = raw_mcp if isinstance(raw_mcp, dict) else None
        a = build(
            agent_kind=self.kind,
            action_type=kind if kind in KNOWN_TYPES else "unknown",
            native_tool=str(act.get("native_tool") or "")[:256] or None,
            cwd=cwd,
            agent_version=version,
            paths=paths,
            command=targets.get("command") if isinstance(targets.get("command"), str) else None,
            url=targets.get("url") if isinstance(targets.get("url"), str) else None,
            mcp={"server": str(mcp.get("server", "")), "tool": str(mcp.get("tool", ""))}
            if mcp
            else None,
            diff=diff,
            incomplete=kind not in KNOWN_TYPES,
        )
        corr = payload.get("correlation_id")
        pre = PreAction(a, diff, corr if isinstance(corr, str) else fallback_correlation(a))
        if phase == "pre":
            hi.actions = [pre]
        else:
            hi.correlation, hi.action_type = pre.correlation, a["action_type"]
            hi.success = payload.get("success") is not False
            code = payload.get("exit_code")
            hi.exit_code = code if isinstance(code, int) else None
        return hi

    def render_pre(self, event: str, verdict: Verdict, allow_mode: str) -> Rendered:
        if verdict.allow:
            return Rendered(stdout=dumps({"decision": "allow", "reason": verdict.user_message}))
        return Rendered(stdout=dumps({"decision": "deny", "reason": verdict.agent_message}))
