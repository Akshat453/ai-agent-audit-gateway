"""Cursor adapter (https://cursor.com/docs/hooks, fetched 2026-11-18).

Pre events: ``preToolUse`` (all tools: Shell, Read, Write, Grep, Delete, Task, MCP:<tool>),
``beforeShellExecution`` (command, cwd), ``beforeMCPExecution`` (tool_name, tool_input as a
JSON *string*, mcp_server_name), ``beforeReadFile`` (file_path, content - the content is
never forwarded). Output: ``{"permission": "allow" | "deny", "user_message", "agent_message"}``;
for permission hooks invalid output BLOCKS, so allow is always explicit. Cursor's ``ask``
exists for shell/MCP but is a LOCAL prompt; we never emit it.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from agw_cli.adapters.base import Adapter, AgentSpec, PayloadError, Rendered, Verdict, dumps
from agw_cli.normalize import (
    HookInput,
    PreAction,
    build,
    digest_json,
    fallback_correlation,
    find_repo_root,
    sha256_hex,
    write_diff,
)


def _str(d: dict[str, Any], *keys: str) -> str | None:
    for k in keys:
        v = d.get(k)
        if isinstance(v, str) and v:
            return v
    return None


class CursorAdapter(Adapter):
    kind = "cursor"
    spec = AgentSpec(
        pre_events=("preToolUse", "beforeShellExecution", "beforeMCPExecution", "beforeReadFile"),
        post_events=(
            "postToolUse",
            "postToolUseFailure",
            "afterShellExecution",
            "afterMCPExecution",
            "afterFileEdit",
        ),
        session_start_events=("sessionStart",),
        session_end_events=("sessionEnd",),
        # NOT DOCUMENTED ("platform default"); assumed 60 s. Configure timeout explicitly.
        default_hook_timeout_seconds=60,
        timeout_unit="s",
        native_ask="beforeShellExecution / beforeMCPExecution 'ask' (LOCAL prompt; never emitted)",
        fail_closed_option='"failClosed": true on the hook',
        config_files=("~/.cursor/hooks.json", ".cursor/hooks.json"),
        managed_config=(
            "/Library/Application Support/Cursor/hooks.json",
            "/etc/cursor/hooks.json",
            "C:\\ProgramData\\Cursor\\hooks.json",
            "team hooks (Enterprise dashboard)",
        ),
        recommended_matchers={
            "preToolUse": "Write|Delete|Grep|Task|MCP:.*",
            "beforeShellExecution": "*",
            "beforeReadFile": "*",
        },
    )

    def parse(self, event: str, payload: dict[str, Any]) -> HookInput:
        phase = self.phase(event)
        roots = payload.get("workspace_roots")
        root_s = (
            roots[0] if isinstance(roots, list) and roots and isinstance(roots[0], str) else None
        )
        cwd = _str(payload, "cwd") or root_s
        version = _str(payload, "cursor_version")
        session = _str(payload, "conversation_id", "session_id") or "default"
        hi = HookInput(phase=phase, native_session=session[:128], cwd=cwd, agent_version=version)
        if phase not in ("pre", "post"):
            return hi
        root = find_repo_root(root_s or cwd)
        common: dict[str, Any] = {
            "agent_kind": self.kind,
            "cwd": cwd,
            "agent_version": version,
            "workspace_root": root,
        }
        pre = self._action(event, payload, common)
        if pre.correlation is None:
            pre.correlation = fallback_correlation(pre.action)
        if phase == "pre":
            hi.actions = [pre]
            return hi
        hi.correlation = pre.correlation
        hi.action_type = pre.action["action_type"]
        hi.success = event != "postToolUseFailure"
        out = payload.get("tool_output", payload.get("output", payload.get("result_json")))
        hi.result_sha256 = digest_json(out) if out is not None else None
        if isinstance(out, str):
            try:
                parsed = json.loads(out)
            except ValueError:
                parsed = None
            if isinstance(parsed, dict) and isinstance(parsed.get("exitCode"), int):
                hi.exit_code = parsed["exitCode"]
                hi.success = hi.success and hi.exit_code == 0
        hi.files = list(pre.action["targets"].get("paths", []))
        d = payload.get("duration")
        hi.duration_ms = d if isinstance(d, int) and d >= 0 else None
        return hi

    def _action(self, event: str, p: dict[str, Any], common: dict[str, Any]) -> PreAction:
        if event in ("beforeShellExecution", "afterShellExecution"):
            cmd = _str(p, "command")
            return PreAction(
                build(
                    action_type="command_exec",
                    native_tool="Shell",
                    command=cmd or "",
                    incomplete=cmd is None,
                    **common,
                )
            )
        if event in ("beforeMCPExecution", "afterMCPExecution"):
            mcp_tool = _str(p, "tool_name") or ""
            raw = p.get("tool_input")
            return PreAction(
                build(
                    action_type="mcp_call",
                    native_tool=f"MCP:{mcp_tool}",
                    mcp={"server": _str(p, "mcp_server_name") or "", "tool": mcp_tool},
                    args_sha256=digest_json(raw),
                    incomplete=not mcp_tool,
                    **common,
                )
            )
        if event == "beforeReadFile":
            path = _str(p, "file_path")
            return PreAction(
                build(
                    action_type="file_read",
                    native_tool="Read",
                    paths=[path] if path else [],
                    incomplete=path is None,
                    **common,
                )
            )
        if event == "afterFileEdit":
            path = _str(p, "file_path")
            return PreAction(
                build(
                    action_type="file_write",
                    native_tool="Write",
                    paths=[path] if path else [],
                    **common,
                )
            )
        tool = p.get("tool_name")
        raw_ti = p.get("tool_input")
        if not isinstance(tool, str):
            raise PayloadError("tool_name")
        ti: dict[str, Any] = raw_ti if isinstance(raw_ti, dict) else {}
        corr = _str(p, "tool_use_id")
        if tool == "Shell":
            cmd = _str(ti, "command")
            a = build(
                action_type="command_exec",
                native_tool=tool,
                command=cmd or "",
                incomplete=cmd is None,
                **common,
            )
            return PreAction(a, correlation=corr)
        if tool == "Read":
            path = _str(ti, "file_path", "path", "target_file")
            return PreAction(
                build(
                    action_type="file_read",
                    native_tool=tool,
                    paths=[path] if path else [],
                    incomplete=path is None,
                    **common,
                ),
                correlation=corr,
            )
        if tool == "Write":
            path = _str(ti, "file_path", "path", "target_file")
            content = ti.get("content", ti.get("contents"))
            diff = None
            if isinstance(content, str) and path:
                abs_p = (
                    Path(path) if Path(path).is_absolute() else Path(common["cwd"] or ".") / path
                )
                diff = write_diff(abs_p, path, content)
            return PreAction(
                build(
                    action_type="file_write",
                    native_tool=tool,
                    paths=[path] if path else [],
                    diff=diff,
                    content_sha256=sha256_hex(content) if isinstance(content, str) else None,
                    incomplete=path is None,
                    **common,
                ),
                diff,
                corr,
            )
        if tool == "Delete":
            path = _str(ti, "file_path", "path", "target_file")
            return PreAction(
                build(
                    action_type="file_delete",
                    native_tool=tool,
                    paths=[path] if path else [],
                    incomplete=path is None,
                    **common,
                ),
                correlation=corr,
            )
        if tool == "Grep":
            path = _str(ti, "path", "directory") or common["cwd"] or "."
            return PreAction(
                build(
                    action_type="search",
                    native_tool=tool,
                    paths=[path],
                    query=_str(ti, "pattern", "query"),
                    **common,
                ),
                correlation=corr,
            )
        if tool.startswith("MCP:"):
            return PreAction(
                build(
                    action_type="mcp_call",
                    native_tool=tool,
                    mcp={"server": "", "tool": tool[4:]},
                    args_sha256=digest_json(ti),
                    **common,
                ),
                correlation=corr,
            )
        return PreAction(
            build(action_type="unknown", native_tool=tool, incomplete=True, **common),
            correlation=corr,
        )

    def render_pre(self, event: str, verdict: Verdict, allow_mode: str) -> Rendered:
        if verdict.allow:
            return Rendered(stdout=dumps({"permission": "allow"}))
        out = {
            "permission": "deny",
            "user_message": verdict.user_message,
            "agent_message": verdict.agent_message,
        }
        if event == "beforeReadFile":  # documented fields: permission + user_message only
            out.pop("agent_message")
        return Rendered(stdout=dumps(out))
