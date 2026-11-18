"""Every agent's tool vocabulary normalizes to the right ``agw.coding-action/1`` type and
targets (field names from each agent's current hook docs, coding-agents.md §1)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import jsonschema
import pytest
from agwcli_fakes import SCHEMA

from agw_cli.adapters import REGISTRY

pytestmark = pytest.mark.unit
VALIDATOR = jsonschema.Draft202012Validator(json.loads(SCHEMA.read_text()))


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    r = tmp_path / "r"
    (r / ".git").mkdir(parents=True)
    (r / ".git" / "HEAD").write_text("b" * 40 + "\n")  # detached HEAD
    (r / "a.ts").write_text("one\ntwo\n")
    return r


def cases(r: str) -> list[tuple[str, str, dict[str, Any], str, dict[str, Any]]]:
    claude = {"session_id": "s", "cwd": r, "tool_use_id": "t"}
    cur = {"conversation_id": "c", "workspace_roots": [r], "cwd": r, "cursor_version": "1.7.2"}
    gem = {"session_id": "g", "cwd": r}
    return [
        (
            "claude_code",
            "PreToolUse",
            {
                **claude,
                "tool_name": "Write",
                "tool_input": {"file_path": f"{r}/a.ts", "content": "one\nTWO\n"},
            },
            "file_write",
            {"paths": ["a.ts"]},
        ),
        (
            "claude_code",
            "PreToolUse",
            {
                **claude,
                "tool_name": "MultiEdit",
                "tool_input": {
                    "file_path": f"{r}/a.ts",
                    "edits": [{"old_string": "one", "new_string": "1"}],
                },
            },
            "file_write",
            {"paths": ["a.ts"]},
        ),
        (
            "claude_code",
            "PreToolUse",
            {
                **claude,
                "tool_name": "NotebookEdit",
                "tool_input": {"notebook_path": f"{r}/n.ipynb"},
            },
            "file_write",
            {"paths": ["n.ipynb"]},
        ),
        (
            "claude_code",
            "PreToolUse",
            {**claude, "tool_name": "Grep", "tool_input": {"pattern": "x", "path": f"{r}/src"}},
            "search",
            {"paths": ["src"]},
        ),
        (
            "claude_code",
            "PreToolUse",
            {
                **claude,
                "tool_name": "WebFetch",
                "tool_input": {"url": "https://vitest.dev/x", "prompt": "p"},
            },
            "web_fetch",
            {"url": "https://vitest.dev/x"},
        ),
        (
            "claude_code",
            "PreToolUse",
            {**claude, "tool_name": "WebSearch", "tool_input": {"query": "q"}},
            "web_fetch",
            {"query": "q"},
        ),
        (
            "claude_code",
            "PreToolUse",
            {
                **claude,
                "tool_name": "mcp__github__get_issue",
                "tool_input": {"n": 1},
                "mcp_server": {"name": "github", "source": "user"},
            },
            "mcp_call",
            {"mcp": {"server": "github", "tool": "get_issue"}},
        ),
        (
            "claude_code",
            "PreToolUse",
            {**claude, "tool_name": "PowerShell", "tool_input": {"command": "Get-ChildItem"}},
            "command_exec",
            {"command": "Get-ChildItem"},
        ),
        (
            "codex",
            "PreToolUse",
            {
                "session_id": "x",
                "cwd": r,
                "tool_name": "Bash",
                "tool_use_id": "c",
                "tool_input": {"command": ["bash", "-lc", "ls"]},
            },
            "command_exec",
            {"argv": ["bash", "-lc", "ls"]},
        ),
        (
            "codex",
            "PreToolUse",
            {
                "session_id": "x",
                "cwd": r,
                "tool_name": "mcp__fs__read",
                "tool_use_id": "c",
                "tool_input": {"p": 1},
            },
            "mcp_call",
            {"mcp": {"server": "fs", "tool": "read"}},
        ),
        (
            "codex",
            "PreToolUse",
            {
                "session_id": "x",
                "cwd": r,
                "tool_name": "update_plan",
                "tool_use_id": "c",
                "tool_input": {"plan": []},
            },
            "unknown",
            {},
        ),
        (
            "cursor",
            "preToolUse",
            {
                **cur,
                "tool_name": "Write",
                "tool_use_id": "u",
                "tool_input": {"file_path": f"{r}/a.ts", "content": "x\n"},
            },
            "file_write",
            {"paths": ["a.ts"]},
        ),
        (
            "cursor",
            "preToolUse",
            {
                **cur,
                "tool_name": "Delete",
                "tool_use_id": "u",
                "tool_input": {"file_path": f"{r}/a.ts"},
            },
            "file_delete",
            {"paths": ["a.ts"]},
        ),
        (
            "cursor",
            "preToolUse",
            {
                **cur,
                "tool_name": "Read",
                "tool_use_id": "u",
                "tool_input": {"file_path": f"{r}/a.ts"},
            },
            "file_read",
            {"paths": ["a.ts"]},
        ),
        (
            "cursor",
            "preToolUse",
            {**cur, "tool_name": "Grep", "tool_use_id": "u", "tool_input": {"pattern": "x"}},
            "search",
            {"paths": ["."]},
        ),
        (
            "cursor",
            "preToolUse",
            {**cur, "tool_name": "MCP:get_issue", "tool_use_id": "u", "tool_input": {}},
            "mcp_call",
            {"mcp": {"tool": "get_issue"}},
        ),
        (
            "cursor",
            "preToolUse",
            {**cur, "tool_name": "Task", "tool_use_id": "u", "tool_input": {}},
            "unknown",
            {},
        ),
        (
            "gemini_cli",
            "BeforeTool",
            {
                **gem,
                "tool_name": "write_file",
                "tool_input": {"file_path": f"{r}/a.ts", "content": "z\n"},
            },
            "file_write",
            {"paths": ["a.ts"]},
        ),
        (
            "gemini_cli",
            "BeforeTool",
            {
                **gem,
                "tool_name": "replace",
                "tool_input": {"file_path": f"{r}/a.ts", "old_string": "one", "new_string": "1"},
            },
            "file_write",
            {"paths": ["a.ts"]},
        ),
        (
            "gemini_cli",
            "BeforeTool",
            {**gem, "tool_name": "read_many_files", "tool_input": {"include": [".env", "src/**"]}},
            "file_read",
            {"paths": [".env", "src/**"]},
        ),
        (
            "gemini_cli",
            "BeforeTool",
            {**gem, "tool_name": "list_directory", "tool_input": {"dir_path": f"{r}/src"}},
            "search",
            {"paths": ["src"]},
        ),
        (
            "gemini_cli",
            "BeforeTool",
            {
                **gem,
                "tool_name": "web_fetch",
                "tool_input": {"prompt": "summarize https://nodejs.org/api please"},
            },
            "web_fetch",
            {"url": "https://nodejs.org/api"},
        ),
        (
            "gemini_cli",
            "BeforeTool",
            {**gem, "tool_name": "google_web_search", "tool_input": {"query": "q"}},
            "web_fetch",
            {"query": "q"},
        ),
        (
            "gemini_cli",
            "BeforeTool",
            {
                **gem,
                "tool_name": "mcp_github_get_issue",
                "tool_input": {},
                "mcp_context": {"server_name": "github"},
            },
            "mcp_call",
            {"mcp": {"server": "github", "tool": "github_get_issue"}},
        ),
        (
            "gemini_cli",
            "BeforeTool",
            {**gem, "tool_name": "save_memory", "tool_input": {}},
            "unknown",
            {},
        ),
        (
            "other",
            "pre",
            {"cwd": r, "action": {"action_type": "teleport", "targets": {}}},
            "unknown",
            {},
        ),
    ]


def test_tool_vocabularies(repo: Path) -> None:
    for agent, event, payload, kind, targets in cases(str(repo)):
        hi = REGISTRY[agent].parse(event, payload)
        assert hi.phase == "pre", agent
        action = hi.actions[0].action
        assert action["action_type"] == kind, (agent, payload.get("tool_name"), action)
        for key, value in targets.items():
            got = action["targets"].get(key)
            if isinstance(value, dict):
                assert {k: got.get(k) for k in value} == value, (agent, got)
            else:
                assert got == value, (agent, key, got)
        if kind == "unknown":
            assert action["incomplete"] is True
        if (kind == "file_write" and agent != "claude_code") or payload.get("tool_name") in (
            "Write",
            "MultiEdit",
        ):
            diff = hi.actions[0].diff
            assert diff is not None and "a/" in diff, (agent, payload.get("tool_name"))
        assert action.get("repo", {}).get("head_sha") == "b" * 40
        VALIDATOR.validate(action)


def test_post_and_session_phases(repo: Path) -> None:
    gem = REGISTRY["gemini_cli"].parse(
        "AfterTool",
        {
            "session_id": "g",
            "cwd": str(repo),
            "tool_name": "run_shell_command",
            "tool_input": {"command": "x"},
            "tool_response": {"error": "boom"},
        },
    )
    assert gem.phase == "post" and gem.success is False
    cx = REGISTRY["codex"].parse(
        "PostToolUse",
        {
            "session_id": "x",
            "cwd": str(repo),
            "tool_name": "Bash",
            "tool_use_id": "c",
            "tool_input": {"command": "false"},
            "tool_response": {"exit_code": 1},
        },
    )
    assert (cx.success, cx.exit_code, cx.correlation) == (False, 1, "c:command_exec")
    mcp = REGISTRY["mcp_generic"].parse(
        "tools/result", {"jsonrpc": "2.0", "id": 7, "result": {"isError": True}}
    )
    assert (mcp.success, mcp.correlation) == (False, "rpc:7")
    assert (
        REGISTRY["cursor"].parse("sessionStart", {"conversation_id": "c"}).phase == "session_start"
    )
