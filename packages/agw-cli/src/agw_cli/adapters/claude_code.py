"""Claude Code adapter (hooks: https://code.claude.com/docs/en/hooks, fetched 2026-11-18).

Pre: ``PreToolUse`` (stdin: session_id, cwd, hook_event_name, tool_name, tool_input,
tool_use_id). Output: ``hookSpecificOutput.permissionDecision`` = ``deny`` (+ reason) or, in
``explicit`` allow mode, ``allow``; by default an allowed action prints nothing, so Claude
Code's own permission rules still apply (AgentGuard is necessary, not sufficient).
Post: ``PostToolUse`` / ``PostToolUseFailure`` (observe only; cannot undo).
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
    find_repo_root,
    write_diff,
)

SHELL_TOOLS = ("Bash", "PowerShell")


def _s(d: dict[str, Any], key: str) -> str | None:
    v = d.get(key)
    return v if isinstance(v, str) and v else None


def claude_style_action(
    kind: str,
    tool: str,
    ti: dict[str, Any],
    cwd: str | None,
    version: str | None,
    mcp_server: str | None = None,
) -> PreAction:
    """Claude Code's tool vocabulary (also used where other agents mirror it)."""
    root = find_repo_root(cwd)
    common: dict[str, Any] = {
        "agent_kind": kind,
        "native_tool": tool,
        "cwd": cwd,
        "agent_version": version,
        "workspace_root": root,
    }
    if tool in SHELL_TOOLS:
        cmd = _s(ti, "command")
        return PreAction(
            build(action_type="command_exec", command=cmd or "", incomplete=cmd is None, **common)
        )
    if tool == "Read":
        p = _s(ti, "file_path")
        return PreAction(
            build(action_type="file_read", paths=[p] if p else [], incomplete=p is None, **common)
        )
    if tool in ("Write", "Edit", "MultiEdit"):
        p = _s(ti, "file_path")
        if p is None:
            return PreAction(build(action_type="file_write", incomplete=True, **common))
        abs_p = Path(p) if Path(p).is_absolute() else Path(cwd or ".") / p
        label = p
        diff: str | None
        if tool == "Write":
            content = ti.get("content")
            diff = write_diff(abs_p, label, content) if isinstance(content, str) else None
        elif tool == "Edit":
            o, n = ti.get("old_string"), ti.get("new_string")
            diff = (
                edit_diff(abs_p, label, [(o, n, bool(ti.get("replace_all")))])
                if isinstance(o, str) and isinstance(n, str)
                else None
            )
        else:
            edits = ti.get("edits")
            pairs = (
                [
                    (e["old_string"], e["new_string"], bool(e.get("replace_all")))
                    for e in edits
                    if isinstance(e, dict)
                    and isinstance(e.get("old_string"), str)
                    and isinstance(e.get("new_string"), str)
                ]
                if isinstance(edits, list)
                else []
            )
            diff = edit_diff(abs_p, label, pairs) if pairs else None
        return PreAction(build(action_type="file_write", paths=[p], diff=diff, **common), diff)
    if tool == "NotebookEdit":
        p = _s(ti, "notebook_path") or _s(ti, "file_path")
        return PreAction(
            build(action_type="file_write", paths=[p] if p else [], incomplete=True, **common)
        )
    if tool in ("Glob", "Grep"):
        p = _s(ti, "path") or cwd or "."
        return PreAction(build(action_type="search", paths=[p], query=_s(ti, "pattern"), **common))
    if tool == "WebFetch":
        return PreAction(build(action_type="web_fetch", url=_s(ti, "url"), **common))
    if tool == "WebSearch":
        return PreAction(build(action_type="web_fetch", query=_s(ti, "query"), **common))
    if tool.startswith("mcp__"):
        parts = tool.split("__", 2)
        server = mcp_server or (parts[1] if len(parts) == 3 else None)
        name = parts[2] if len(parts) == 3 else tool
        return PreAction(
            build(
                action_type="mcp_call",
                mcp={"server": server or "", "tool": name},
                args_sha256=digest_json(ti),
                **common,
            )
        )
    # Unknown tool: never allowed silently (the gateway asks a human).
    return PreAction(build(action_type="unknown", incomplete=True, **common))


class ClaudeCodeAdapter(Adapter):
    kind = "claude_code"
    spec = AgentSpec(
        pre_events=("PreToolUse",),
        post_events=("PostToolUse", "PostToolUseFailure"),
        session_start_events=("SessionStart",),
        session_end_events=("SessionEnd",),
        default_hook_timeout_seconds=600,
        timeout_unit="s",
        native_ask="PreToolUse permissionDecision 'ask' (a LOCAL prompt; never emitted)",
        fail_closed_option='"onFailure": "block" on the hook (v2.1.295+)',
        config_files=("~/.claude/settings.json", ".claude/settings.json"),
        managed_config=(
            "/Library/Application Support/ClaudeCode/managed-settings.json",
            "/etc/claude-code/managed-settings.json",
            "C:\\Program Files\\ClaudeCode\\managed-settings.json",
            'with "allowManagedHooksOnly": true',
        ),
        recommended_matchers={
            "PreToolUse": "Bash|PowerShell|Read|Write|Edit|MultiEdit|NotebookEdit|Glob|Grep"
            "|WebFetch|WebSearch|mcp__.*",
            "PostToolUse": "*",
        },
    )

    def parse(self, event: str, payload: dict[str, Any]) -> HookInput:
        phase = self.phase(event)
        session = str(payload.get("session_id") or "default")[:128]
        cwd = _s(payload, "cwd")
        hi = HookInput(phase=phase, native_session=session, cwd=cwd)
        if phase not in ("pre", "post"):
            return hi
        tool = payload.get("tool_name")
        ti = payload.get("tool_input")
        if not isinstance(tool, str) or not isinstance(ti, dict):
            raise PayloadError("tool_name / tool_input")
        mcp = payload.get("mcp_server")
        server = (
            mcp.get("name") if isinstance(mcp, dict) and isinstance(mcp.get("name"), str) else None
        )
        pre = claude_style_action(self.kind, tool, ti, cwd, None, server)
        pre.correlation = _s(payload, "tool_use_id")
        if phase == "pre":
            hi.actions = [pre]
            return hi
        hi.correlation = pre.correlation
        hi.action_type = pre.action["action_type"]
        hi.success = event != "PostToolUseFailure"
        resp = payload.get("tool_response")
        hi.result_sha256 = digest_json(resp) if resp is not None else None
        hi.files = (
            list(pre.action["targets"].get("paths", [])) if hi.action_type == "file_write" else []
        )
        d = payload.get("duration_ms")
        hi.duration_ms = d if isinstance(d, int) and d >= 0 else None
        if isinstance(resp, dict) and isinstance(resp.get("exit_code"), int):
            hi.exit_code = resp["exit_code"]
            hi.success = hi.success and resp["exit_code"] == 0
        return hi

    def render_pre(self, event: str, verdict: Verdict, allow_mode: str) -> Rendered:
        if verdict.allow:
            if allow_mode != "explicit":
                return Rendered()  # no decision: Claude Code's own permission flow continues
            out = {
                "hookEventName": "PreToolUse",
                "permissionDecision": "allow",
                "permissionDecisionReason": verdict.user_message,
            }
            return Rendered(stdout=dumps({"hookSpecificOutput": out}))
        out = {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": verdict.agent_message,
        }
        return Rendered(stdout=dumps({"hookSpecificOutput": out}), stderr=verdict.user_message)
