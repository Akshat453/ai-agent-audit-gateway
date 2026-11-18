"""C1: adapter golden tests (samples from the official hook docs) and the hook flow
(allow / deny / ask -> wait -> approved | rejected | pending) for every supported agent."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import jsonschema
import pytest
from agwcli_fakes import LINK, SCHEMA, FakeClient, allow, ask, cfg, deny, golden

from agw_cli.adapters import REGISTRY
from agw_cli.commands.hook import run_hook

pytestmark = pytest.mark.unit

UNAVAILABLE = "AgentGuard unavailable - action blocked"
PENDING = f"Approval pending: {LINK}. Retry after approval."
VALIDATOR = jsonschema.Draft202012Validator(json.loads(SCHEMA.read_text()))


def run(agent: str, event: str, raw: str, client: FakeClient, tmp: Path, **over: Any) -> Any:
    return run_hook(
        agent, event, raw, loader=lambda: cfg(tmp, **over), client_factory=lambda c: client
    )


def out(r: Any) -> Any:
    return json.loads(r.stdout) if r.stdout else None


# (agent, golden file, event, native ALLOW stdout (None = no output), DENY stdout builder)
PRE_SAMPLES = [
    ("claude_code", "pre_bash_npm_test.json", "PreToolUse"),
    ("codex", "pre_bash.json", "PreToolUse"),
    ("codex", "pre_apply_patch.json", "PreToolUse"),
    ("cursor", "pre_tool_use_shell.json", "preToolUse"),
    ("cursor", "before_shell.json", "beforeShellExecution"),
    ("cursor", "before_mcp.json", "beforeMCPExecution"),
    ("cursor", "before_read_file.json", "beforeReadFile"),
    ("gemini_cli", "before_tool_shell.json", "BeforeTool"),
    ("gemini_cli", "before_tool_read_env.json", "BeforeTool"),
    ("mcp_generic", "tools_call.json", "tools/call"),
    ("other", "pre.json", "pre"),
]


def expected_allow(agent: str, raw: str) -> Any:
    return {
        "claude_code": None,  # no decision: the agent's own permission flow continues
        "codex": None,  # Codex: exit 0, no output = allow
        "cursor": {"permission": "allow"},
        "gemini_cli": {"decision": "allow"},
        "mcp_generic": json.loads(raw),  # forward the request unchanged
        "other": {"decision": "allow", "reason": "AgentGuard: allowed (CMD-ALLOW)."},
    }[agent]


def deny_reason_of(agent: str, event: str, body: Any) -> str:
    if agent in ("claude_code", "codex"):
        hso = body["hookSpecificOutput"]
        assert (hso["hookEventName"], hso["permissionDecision"]) == ("PreToolUse", "deny")
        return str(hso["permissionDecisionReason"])
    if agent == "cursor":
        assert body["permission"] == "deny"
        if event == "beforeReadFile":
            assert set(body) == {"permission", "user_message"}
            return str(body["user_message"])
        return str(body["agent_message"])
    if agent == "gemini_cli":
        assert body["decision"] == "deny" and body["systemMessage"]
        return str(body["reason"])
    if agent == "mcp_generic":
        assert body["jsonrpc"] == "2.0" and body["id"] == 7 and body["result"]["isError"] is True
        return str(body["result"]["content"][0]["text"])
    assert body["decision"] == "deny"
    return str(body["reason"])


@pytest.mark.parametrize(("agent", "name", "event"), PRE_SAMPLES)
def test_allow_native_response(agent: str, name: str, event: str, tmp_path: Path) -> None:
    raw = golden(agent, name)
    client = FakeClient([allow(), allow()])
    r = run(agent, event, raw, client, tmp_path)
    assert r.exit_code == 0
    assert out(r) == expected_allow(agent, raw)
    for body in client.decided:  # the normalized action conforms to agw.coding-action/1
        VALIDATOR.validate(body["action"])
        assert body["action"]["agent_kind"] == agent


@pytest.mark.parametrize(("agent", "name", "event"), PRE_SAMPLES)
def test_deny_native_response(agent: str, name: str, event: str, tmp_path: Path) -> None:
    client = FakeClient([deny(), deny()])
    r = run(agent, event, golden(agent, name), client, tmp_path)
    assert r.exit_code == 0
    reason = deny_reason_of(agent, event, out(r))
    assert "git push is denied" in reason


@pytest.mark.parametrize(("agent", "name", "event"), PRE_SAMPLES)
def test_ask_pending_blocks_with_link(agent: str, name: str, event: str, tmp_path: Path) -> None:
    client = FakeClient([ask(), ask()])
    r = run(agent, event, golden(agent, name), client, tmp_path)
    reason = deny_reason_of(agent, event, out(r))
    if event != "beforeReadFile":
        assert reason.startswith(PENDING)
    else:
        assert PENDING in reason or "Approval pending" in reason


@pytest.mark.parametrize(("agent", "name", "event"), PRE_SAMPLES)
def test_ask_approved_while_waiting_allows(
    agent: str, name: str, event: str, tmp_path: Path
) -> None:
    raw = golden(agent, name)
    client = FakeClient(
        [ask(), allow(), ask(), allow()],
        statuses=[
            {"status": "PENDING_APPROVAL", "approval_state": "PENDING"},
            {"status": "PENDING_APPROVAL", "approval_state": "APPROVED"},
        ]
        * 2,
    )
    r = run(agent, event, raw, client, tmp_path, approval_wait=30.0)
    if agent == "other":
        assert out(r)["decision"] == "allow"
    else:
        assert out(r) == expected_allow(agent, raw)
    first, retry = client.decided[0], client.decided[1]
    assert first == retry  # the IDENTICAL request consumes the approval


def test_ask_rejected_denies(tmp_path: Path) -> None:
    client = FakeClient([ask()], statuses=[{"status": "DENIED", "approval_state": "REJECTED"}])
    r = run(
        "claude_code",
        "PreToolUse",
        golden("claude_code", "pre_bash_npm_test.json"),
        client,
        tmp_path,
        approval_wait=30.0,
    )
    assert "rejected" in deny_reason_of("claude_code", "PreToolUse", out(r))


def test_wait_respects_the_agent_hook_timeout(tmp_path: Path) -> None:
    """approval_wait 90 s but a 20 s hook timeout -> the hook gives up after <= 5 s."""
    t = [0.0]

    def clock() -> float:
        t[0] += 1.0
        return t[0]

    client = FakeClient([ask()])
    r = run_hook(
        "gemini_cli",
        "BeforeTool",
        golden("gemini_cli", "before_tool_shell.json"),
        loader=lambda: cfg(tmp_path, approval_wait=90.0, hook_timeout=20.0),
        client_factory=lambda c: client,
        clock=clock,
    )
    assert out(r)["reason"].startswith(PENDING)
    assert t[0] < 12


def test_explicit_allow_mode_for_claude(tmp_path: Path) -> None:
    client = FakeClient([allow()])
    r = run(
        "claude_code",
        "PreToolUse",
        golden("claude_code", "pre_bash_npm_test.json"),
        client,
        tmp_path,
        allow_mode="explicit",
    )
    hso = out(r)["hookSpecificOutput"]
    assert hso["permissionDecision"] == "allow"


def test_codex_apply_patch_is_a_write_with_the_patch_as_diff(tmp_path: Path) -> None:
    client = FakeClient([allow()])
    run("codex", "PreToolUse", golden("codex", "pre_apply_patch.json"), client, tmp_path)
    body = client.decided[0]
    assert body["action"]["action_type"] == "file_write"
    assert body["action"]["targets"]["paths"] == ["/workspace/api/src/csv.ts"]
    assert body["diff"].startswith("*** Begin Patch")


def test_codex_patch_with_delete_asks_twice(tmp_path: Path) -> None:
    raw = json.dumps(
        {
            "session_id": "s",
            "cwd": "/workspace",
            "tool_name": "apply_patch",
            "tool_use_id": "c",
            "tool_input": {
                "command": "*** Begin Patch\n*** Update File: a.ts\n+x\n*** Delete File: a.test.ts\n"
                "*** End Patch\n"
            },
        }
    )
    client = FakeClient([allow(), deny("Deleting a test file", "PATH-DELETE-TEST")])
    r = run("codex", "PreToolUse", raw, client, tmp_path)
    assert [b["action"]["action_type"] for b in client.decided] == ["file_write", "file_delete"]
    assert "Deleting a test file" in deny_reason_of("codex", "PreToolUse", out(r))


def test_cursor_read_never_sends_file_content(tmp_path: Path) -> None:
    client = FakeClient([deny("Reading secrets is denied", "SECRET-READ")])
    run("cursor", "beforeReadFile", golden("cursor", "before_read_file.json"), client, tmp_path)
    assert "postgres://" not in json.dumps(client.decided)
    assert client.decided[0]["action"]["targets"]["paths"] == ["/project/.env"]


def test_claude_edit_sends_a_diff_not_the_file(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    (repo / ".git").mkdir(parents=True)
    (repo / ".git" / "HEAD").write_text("ref: refs/heads/main\n")
    (repo / ".git" / "refs" / "heads").mkdir(parents=True)
    (repo / ".git" / "refs" / "heads" / "main").write_text("a" * 40 + "\n")
    (repo / ".git" / "config").write_text(
        '[remote "origin"]\n\turl = https://user:tok@github.com/acme/repo.git\n'
    )
    big = "".join(f"line {i}\n" for i in range(500))
    (repo / "src.ts").write_text(big)
    payload = {
        "session_id": "s",
        "cwd": str(repo),
        "hook_event_name": "PreToolUse",
        "tool_name": "Edit",
        "tool_use_id": "t",
        "tool_input": {
            "file_path": str(repo / "src.ts"),
            "old_string": "line 250\n",
            "new_string": "line 250 changed\n",
        },
    }
    client = FakeClient([allow()])
    run("claude_code", "PreToolUse", json.dumps(payload), client, tmp_path)
    body = client.decided[0]
    assert body["action"]["targets"]["paths"] == ["src.ts"]
    assert body["action"]["repo"] == {
        "head_sha": "a" * 40,
        "remote_url": "https://github.com/acme/repo.git",
    }
    assert "+line 250 changed" in body["diff"] and "line 10\n" not in body["diff"]
    assert len(body["diff"]) < 600
    VALIDATOR.validate(body["action"])


def test_unknown_tool_is_never_allowed_silently(tmp_path: Path) -> None:
    raw = json.dumps({"session_id": "s", "cwd": "/x", "tool_name": "Teleport", "tool_input": {}})
    client = FakeClient([ask()])
    run("claude_code", "PreToolUse", raw, client, tmp_path)
    assert client.decided[0]["action"]["action_type"] == "unknown"
    assert client.decided[0]["action"]["incomplete"] is True


def test_post_events_observe_and_never_block(tmp_path: Path) -> None:
    for agent, name, event in [
        ("claude_code", "post_write.json", "PostToolUse"),
        ("cursor", "post_tool_use.json", "postToolUse"),
        ("gemini_cli", "after_tool.json", "AfterTool"),
    ]:
        client = FakeClient()
        r = run(agent, event, golden(agent, name), client, tmp_path)
        assert (r.exit_code, r.stdout) == (0, "")
        obs = client.observed[0]
        assert obs["session_id"] and "result_sha256" in obs
        assert "All tests passed" not in json.dumps(obs)  # results travel as digests only
    claude = FakeClient()
    run("claude_code", "PostToolUse", golden("claude_code", "post_write.json"), claude, tmp_path)
    assert claude.observed[0]["correlation_id"] == "toolu_01ABC123..."


def test_session_end_events(tmp_path: Path) -> None:
    for agent in ("claude_code", "codex"):
        client = FakeClient()
        run(agent, "SessionStart", '{"session_id": "zz", "cwd": "/x"}', client, tmp_path)
        assert len(client.sessions) == 1
        r = run(agent, "SessionEnd", '{"session_id": "zz", "cwd": "/x"}', client, tmp_path)
        assert r.exit_code == 0 and client.ended


def test_registry_covers_every_agent_kind_with_specs() -> None:
    assert set(REGISTRY) == {"claude_code", "codex", "cursor", "gemini_cli", "mcp_generic", "other"}
    for adapter in REGISTRY.values():
        assert adapter.spec.pre_events and adapter.spec.config_files is not None
        assert adapter.max_wait(0) >= 0
