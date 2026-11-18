"""OpenAI Codex CLI adapter (https://developers.openai.com/codex/hooks, fetched 2026-11-18).

Pre: ``PreToolUse`` (stdin: session_id, turn_id, cwd, tool_name, tool_use_id, tool_input).
``Bash`` carries ``tool_input.command``; ``apply_patch`` carries the PATCH TEXT in
``tool_input.command`` (all file edits go through it); MCP tools are ``mcp__<server>__<tool>``.
Output: deny = ``hookSpecificOutput.permissionDecision: "deny"`` (+ reason); allow = exit 0
with no output (Codex documents ``allow`` only together with ``updatedInput``).
Codex has no ask ("parsed but not supported yet": it would fail OPEN), so we never emit it.
"""

from __future__ import annotations

import re
from typing import Any

from agw_cli.adapters.base import Adapter, AgentSpec, PayloadError, Rendered, Verdict, dumps
from agw_cli.adapters.claude_code import claude_style_action
from agw_cli.normalize import HookInput, PreAction, build, digest_json, find_repo_root

_PATCH_OP = re.compile(r"^\*\*\* (Add|Update|Delete) File: (.+)$")
_MOVE = re.compile(r"^\*\*\* Move to: (.+)$")


def patch_actions(patch: str, cwd: str | None, version: str | None) -> list[PreAction]:
    """One ``apply_patch`` -> a write action (added/updated/moved-to files, diff = the patch)
    and, if it deletes files, a separate delete action (deleting tests is CRITICAL)."""
    writes: list[str] = []
    deletes: list[str] = []
    for line in patch.splitlines():
        m = _PATCH_OP.match(line)
        if m:
            (deletes if m.group(1) == "Delete" else writes).append(m.group(2).strip())
        elif mv := _MOVE.match(line):
            writes.append(mv.group(1).strip())
    root = find_repo_root(cwd)
    common: dict[str, Any] = {
        "agent_kind": "codex",
        "native_tool": "apply_patch",
        "cwd": cwd,
        "agent_version": version,
        "workspace_root": root,
    }
    out: list[PreAction] = []
    if writes:
        out.append(
            PreAction(build(action_type="file_write", paths=writes, diff=patch, **common), patch)
        )
    if deletes:
        out.append(PreAction(build(action_type="file_delete", paths=deletes, **common)))
    if not out:  # not a patch we understand
        out.append(PreAction(build(action_type="file_write", incomplete=True, **common)))
    return out


class CodexAdapter(Adapter):
    kind = "codex"
    spec = AgentSpec(
        pre_events=("PreToolUse",),
        post_events=("PostToolUse",),
        session_start_events=("SessionStart",),
        session_end_events=("SessionEnd",),
        default_hook_timeout_seconds=600,
        timeout_unit="s",
        native_ask="none (permissionDecision 'ask' is parsed but unsupported; fails open)",
        fail_closed_option=None,
        config_files=("~/.codex/hooks.json", ".codex/hooks.json", "~/.codex/config.toml [hooks]"),
        managed_config=(
            "/etc/codex/requirements.toml",
            "%ProgramData%\\OpenAI\\Codex\\requirements.toml",
            "MDM com.openai.codex:requirements_toml_base64",
            "allow_managed_hooks_only = true; [features] hooks = true",
        ),
        recommended_matchers={"PreToolUse": "*", "PostToolUse": "*"},
    )

    def parse(self, event: str, payload: dict[str, Any]) -> HookInput:
        phase = self.phase(event)
        cwd = payload.get("cwd") if isinstance(payload.get("cwd"), str) else None
        hi = HookInput(
            phase=phase, native_session=str(payload.get("session_id") or "default")[:128], cwd=cwd
        )
        if phase not in ("pre", "post"):
            return hi
        tool = payload.get("tool_name")
        ti = payload.get("tool_input")
        if not isinstance(tool, str) or ti is None:
            raise PayloadError("tool_name / tool_input")
        corr = payload.get("tool_use_id") if isinstance(payload.get("tool_use_id"), str) else None
        if tool in ("apply_patch", "Edit", "Write"):
            patch = ti.get("command") if isinstance(ti, dict) else None
            if isinstance(patch, list):
                patch = next(
                    (p for p in patch if isinstance(p, str) and "*** Begin Patch" in p), None
                )
            actions = (
                patch_actions(patch, cwd, None)
                if isinstance(patch, str)
                else [
                    PreAction(
                        build(
                            agent_kind="codex",
                            action_type="file_write",
                            native_tool=tool,
                            cwd=cwd,
                            incomplete=True,
                        )
                    )
                ]
            )
        elif tool == "Bash" and isinstance(ti, dict):
            cmd = ti.get("command")
            if isinstance(cmd, list) and all(isinstance(c, str) for c in cmd):
                # Codex may pass argv (e.g. ["bash", "-lc", "<script>"]): evaluated as argv.
                actions = [
                    PreAction(
                        build(
                            agent_kind="codex",
                            action_type="command_exec",
                            native_tool=tool,
                            cwd=cwd,
                            argv=cmd,
                        )
                    )
                ]
            else:
                actions = [claude_style_action("codex", "Bash", ti, cwd, None)]
        elif isinstance(ti, dict):
            actions = [claude_style_action("codex", tool, ti, cwd, None)]
        else:
            actions = [
                PreAction(
                    build(
                        agent_kind="codex",
                        action_type="unknown",
                        native_tool=tool,
                        cwd=cwd,
                        incomplete=True,
                        args_sha256=digest_json(ti),
                    )
                )
            ]
        for a in actions:
            a.correlation = f"{corr}:{a.action['action_type']}" if corr else None
        if phase == "pre":
            hi.actions = actions
            return hi
        first = actions[0]
        hi.correlation = first.correlation
        hi.action_type = first.action["action_type"]
        resp = payload.get("tool_response")
        hi.result_sha256 = digest_json(resp) if resp is not None else None
        if isinstance(resp, dict):
            code = resp.get("exit_code", resp.get("exitCode"))
            if isinstance(code, int):
                hi.exit_code = code
                hi.success = code == 0
        hi.files = [p for a in actions for p in a.action["targets"].get("paths", [])]
        return hi

    def render_pre(self, event: str, verdict: Verdict, allow_mode: str) -> Rendered:
        if verdict.allow:
            return Rendered()
        out = {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": verdict.agent_message,
        }
        return Rendered(stdout=dumps({"hookSpecificOutput": out}), stderr=verdict.user_message)
