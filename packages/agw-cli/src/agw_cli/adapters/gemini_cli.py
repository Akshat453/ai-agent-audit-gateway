"""Gemini CLI adapter (google-gemini/gemini-cli docs/hooks, fetched 2026-11-18).

Pre: ``BeforeTool`` (stdin: session_id, cwd, hook_event_name, tool_name, tool_input,
mcp_context?). Tools: run_shell_command, read_file, read_many_files, write_file, replace,
glob, grep_search / search_file_content, list_directory, web_fetch (URLs inside ``prompt``),
google_web_search, MCP tools ``mcp_<server>_<tool>``. Output: ``{"decision": "allow"}`` or
``{"decision": "deny", "reason", "systemMessage"}``. Gemini has no ask. Timeouts are in ms.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from agw_cli.adapters.base import Adapter, AgentSpec, PayloadError, Rendered, Verdict, dumps
from agw_cli.normalize import (
    HookInput,
    PreAction,
    build,
    digest_json,
    edit_diff,
    fallback_correlation,
    find_repo_root,
    urls_in,
    write_diff,
)


def _s(d: dict[str, Any], *keys: str) -> str | None:
    for k in keys:
        v = d.get(k)
        if isinstance(v, str) and v:
            return v
    return None


class GeminiCliAdapter(Adapter):
    kind = "gemini_cli"
    spec = AgentSpec(
        pre_events=("BeforeTool",),
        post_events=("AfterTool",),
        session_start_events=("SessionStart",),
        session_end_events=("SessionEnd",),
        default_hook_timeout_seconds=60,  # 60000 ms
        timeout_unit="ms",
        native_ask="none",
        fail_closed_option=None,
        config_files=("~/.gemini/settings.json", ".gemini/settings.json"),
        managed_config=(
            "/Library/Application Support/GeminiCli/settings.json",
            "/etc/gemini-cli/settings.json",
            "C:\\ProgramData\\gemini-cli\\settings.json",
            "(no managed-only hook switch documented; users can /hooks disable)",
        ),
        recommended_matchers={"BeforeTool": "*", "AfterTool": "*"},
    )

    def parse(self, event: str, payload: dict[str, Any]) -> HookInput:
        phase = self.phase(event)
        cwd = _s(payload, "cwd")
        hi = HookInput(
            phase=phase, native_session=(_s(payload, "session_id") or "default")[:128], cwd=cwd
        )
        if phase not in ("pre", "post"):
            return hi
        tool = payload.get("tool_name")
        ti = payload.get("tool_input")
        if not isinstance(tool, str) or not isinstance(ti, dict):
            raise PayloadError("tool_name / tool_input")
        actions = self._actions(tool, ti, cwd, payload.get("mcp_context"))
        for a in actions:
            a.correlation = fallback_correlation(a.action)
        if phase == "pre":
            hi.actions = actions
            return hi
        first = actions[0]
        hi.correlation = first.correlation
        hi.action_type = first.action["action_type"]
        resp = payload.get("tool_response")
        hi.result_sha256 = digest_json(resp) if resp is not None else None
        if isinstance(resp, dict) and resp.get("error"):
            hi.success = False
        hi.files = [p for a in actions for p in a.action["targets"].get("paths", [])]
        return hi

    def _actions(
        self, tool: str, ti: dict[str, Any], cwd: str | None, mcp_context: Any
    ) -> list[PreAction]:
        root = find_repo_root(cwd)
        c: dict[str, Any] = {
            "agent_kind": self.kind,
            "native_tool": tool,
            "cwd": cwd,
            "workspace_root": root,
        }
        if tool == "run_shell_command":
            cmd = _s(ti, "command")
            run_cwd = _s(ti, "dir_path") or cwd
            c["cwd"] = run_cwd
            return [
                PreAction(
                    build(
                        action_type="command_exec", command=cmd or "", incomplete=cmd is None, **c
                    )
                )
            ]
        if tool == "read_file":
            p = _s(ti, "file_path")
            return [
                PreAction(
                    build(
                        action_type="file_read", paths=[p] if p else [], incomplete=p is None, **c
                    )
                )
            ]
        if tool == "read_many_files":
            inc = ti.get("include")
            paths = [x for x in inc if isinstance(x, str)] if isinstance(inc, list) else []
            return [
                PreAction(build(action_type="file_read", paths=paths, incomplete=not paths, **c))
            ]
        if tool in ("write_file", "replace"):
            p = _s(ti, "file_path")
            if p is None:
                return [PreAction(build(action_type="file_write", incomplete=True, **c))]
            abs_p = Path(p) if Path(p).is_absolute() else Path(cwd or ".") / p
            diff: str | None = None
            if tool == "write_file" and isinstance(ti.get("content"), str):
                diff = write_diff(abs_p, p, ti["content"])
            elif tool == "replace":
                o, n = ti.get("old_string"), ti.get("new_string")
                if isinstance(o, str) and isinstance(n, str):
                    diff = edit_diff(abs_p, p, [(o, n, bool(ti.get("allow_multiple")))])
            return [PreAction(build(action_type="file_write", paths=[p], diff=diff, **c), diff)]
        if tool in ("glob", "grep_search", "search_file_content", "list_directory"):
            p = _s(ti, "dir_path", "path") or cwd or "."
            return [PreAction(build(action_type="search", paths=[p], query=_s(ti, "pattern"), **c))]
        if tool == "web_fetch":
            urls = urls_in(_s(ti, "prompt") or "")[:8]
            if not urls:
                return [PreAction(build(action_type="web_fetch", incomplete=True, **c))]
            return [PreAction(build(action_type="web_fetch", url=u, **c)) for u in urls]
        if tool == "google_web_search":
            return [PreAction(build(action_type="web_fetch", query=_s(ti, "query"), **c))]
        if tool.startswith("mcp_"):
            server = ""
            if isinstance(mcp_context, dict):
                server = _s(mcp_context, "server_name", "serverName", "server") or ""
            return [
                PreAction(
                    build(
                        action_type="mcp_call",
                        mcp={"server": server, "tool": tool[4:]},
                        args_sha256=digest_json(ti),
                        **c,
                    )
                )
            ]
        return [PreAction(build(action_type="unknown", incomplete=True, **c))]

    def render_pre(self, event: str, verdict: Verdict, allow_mode: str) -> Rendered:
        if verdict.allow:
            return Rendered(stdout=dumps({"decision": "allow"}))
        return Rendered(
            stdout=dumps(
                {
                    "decision": "deny",
                    "reason": verdict.agent_message,
                    "systemMessage": verdict.user_message,
                }
            )
        )
