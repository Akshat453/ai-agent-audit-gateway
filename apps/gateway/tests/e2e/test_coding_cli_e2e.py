"""C1 acceptance, end to end: ``agw hook <agent> <event> < sample.json`` (the installed CLI, a
separate process, real HTTP) against a real gateway returns the agent's native response for
allow, deny and ask on every supported agent; a human approval while the hook waits turns
into allow; the session's evidence chain verifies with the independent verifier."""

from __future__ import annotations

import io
import json
import os
import subprocess
import sys
import time
import uuid
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import Engine, select

from agw_gateway.api.app import create_app
from agw_gateway.db import tables as t
from agw_gateway.evidence.export import export_chain
from agw_verifier.chain import verify_lines
from tests.codingkit import CodingWorld, approve, make_coding_world
from tests.servekit import serve

pytestmark = pytest.mark.e2e
UNAVAILABLE = "AgentGuard unavailable - action blocked"


@pytest.fixture
def cw(gw: Any, migrator_engine: Engine) -> CodingWorld:
    return make_coding_world(migrator_engine, gw.client, gw.world.tenant_id)


@pytest.fixture
def url(gw: Any) -> Iterator[str]:
    with serve(create_app(gw.state, sync_registry=False)) as base:
        yield base


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    """A MintRail-shaped git checkout (read from files by the CLI; no git binary needed)."""
    r = tmp_path / "mintrail"
    (r / ".git" / "refs" / "heads").mkdir(parents=True)
    (r / ".git" / "HEAD").write_text("ref: refs/heads/main\n")
    (r / ".git" / "refs" / "heads" / "main").write_text("c" * 40 + "\n")
    (r / ".git" / "config").write_text(
        '[remote "origin"]\n\turl = https://github.com/Akshat453/MintRail.git\n'
    )
    for rel, text in {
        "api/src/csv.ts": "export const a = 1;\n",
        "ledger/src/service.ts": "export const post = 1;\n",
        ".env": "SECRET=never-sent\n",
    }.items():
        (r / rel).parent.mkdir(parents=True, exist_ok=True)
        (r / rel).write_text(text)
    return r


def agw(
    args: list[str], payload: dict[str, Any], url: str, token: str, home: Path, **env: str
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "agw_cli", *args],
        input=json.dumps(payload),
        capture_output=True,
        text=True,
        env={
            "PATH": os.environ.get("PATH", ""),
            "HOME": str(home),
            "AGW_URL": url,
            "AGW_DEVICE_KEY": token,
            "AGW_STATE_DIR": str(home / "state"),
            "AGW_APPROVAL_WAIT_SECONDS": "0",
            **env,
        },
        timeout=60,
        check=False,
    )


def samples(repo: Path) -> dict[str, dict[str, tuple[str, dict[str, Any]]]]:
    """Per agent: (event, native payload) for an allow, a deny and an ask."""
    cwd = str(repo)

    def claude(tool: str, ti: dict[str, Any], sid: str = "cc-1") -> dict[str, Any]:
        return {
            "session_id": sid,
            "cwd": cwd,
            "hook_event_name": "PreToolUse",
            "tool_name": tool,
            "tool_input": ti,
            "tool_use_id": f"toolu_{uuid.uuid4().hex}",
        }

    def codex(tool: str, ti: dict[str, Any]) -> dict[str, Any]:
        return {
            "session_id": "cx-1",
            "turn_id": "t",
            "cwd": cwd,
            "hook_event_name": "PreToolUse",
            "model": "gpt-5-codex",
            "tool_name": tool,
            "tool_use_id": uuid.uuid4().hex,
            "tool_input": ti,
        }

    def cursor(event: str, extra: dict[str, Any]) -> dict[str, Any]:
        return {
            "conversation_id": "cu-1",
            "hook_event_name": event,
            "cursor_version": "1.7.2",
            "workspace_roots": [cwd],
            "cwd": cwd,
            **extra,
        }

    def gemini(tool: str, ti: dict[str, Any]) -> dict[str, Any]:
        return {
            "session_id": "ge-1",
            "cwd": cwd,
            "hook_event_name": "BeforeTool",
            "tool_name": tool,
            "tool_input": ti,
        }

    patch = "*** Begin Patch\n*** Update File: ledger/src/service.ts\n+// order\n*** End Patch\n"
    rpc = {"jsonrpc": "2.0", "id": 1, "method": "tools/call"}
    return {
        "claude_code": {
            "allow": ("PreToolUse", claude("Bash", {"command": "pnpm test"})),
            "deny": ("PreToolUse", claude("Read", {"file_path": f"{cwd}/.env"})),
            "ask": (
                "PreToolUse",
                claude(
                    "Edit",
                    {
                        "file_path": f"{cwd}/ledger/src/service.ts",
                        "old_string": "post = 1",
                        "new_string": "post = 2",
                    },
                ),
            ),
        },
        "codex": {
            "allow": ("PreToolUse", codex("Bash", {"command": "git status"})),
            "deny": ("PreToolUse", codex("Bash", {"command": "git push origin main"})),
            "ask": ("PreToolUse", codex("apply_patch", {"command": patch})),
        },
        "cursor": {
            "allow": (
                "beforeShellExecution",
                cursor("beforeShellExecution", {"command": "pnpm lint", "sandbox": False}),
            ),
            "deny": (
                "beforeReadFile",
                cursor(
                    "beforeReadFile", {"file_path": f"{cwd}/.env", "content": "SECRET=never-sent"}
                ),
            ),
            "ask": (
                "beforeShellExecution",
                cursor("beforeShellExecution", {"command": "pnpm add left-pad-ng"}),
            ),
        },
        "gemini_cli": {
            "allow": ("BeforeTool", gemini("read_file", {"file_path": f"{cwd}/api/src/csv.ts"})),
            "deny": ("BeforeTool", gemini("run_shell_command", {"command": "printenv"})),
            "ask": (
                "BeforeTool",
                gemini(
                    "write_file",
                    {"file_path": f"{cwd}/drizzle/0009.sql", "content": "ALTER TABLE x;\n"},
                ),
            ),
        },
        "mcp_generic": {
            "allow": ("tools/call", {**rpc, "params": {"name": "get_issue", "arguments": {}}}),
            "deny": ("tools/call", {**rpc, "params": {"name": "push_files", "arguments": {}}}),
            "ask": (
                "tools/call",
                {**rpc, "params": {"name": "create_issue", "arguments": {"t": 1}}},
            ),
        },
        "other": {
            "allow": (
                "pre",
                {
                    "event": "pre",
                    "session_id": "o-1",
                    "cwd": cwd,
                    "action": {"action_type": "command_exec", "targets": {"command": "make test"}},
                },
            ),
            "deny": (
                "pre",
                {
                    "event": "pre",
                    "session_id": "o-1",
                    "cwd": cwd,
                    "action": {
                        "action_type": "command_exec",
                        "targets": {"command": "curl https://x.example"},
                    },
                },
            ),
            "ask": (
                "pre",
                {
                    "event": "pre",
                    "session_id": "o-1",
                    "cwd": cwd,
                    "action": {
                        "action_type": "command_exec",
                        "targets": {"command": "pnpm db:migrate"},
                    },
                },
            ),
        },
    }


def verdict(agent: str, p: subprocess.CompletedProcess[str]) -> tuple[str, str]:
    """(allow|deny, reason) from the agent's native output."""
    assert p.returncode == 0, p.stderr
    out = json.loads(p.stdout) if p.stdout.strip() else None
    if agent in ("claude_code", "codex"):
        if out is None:
            return "allow", ""
        hso = out["hookSpecificOutput"]
        return hso["permissionDecision"], hso.get("permissionDecisionReason", "")
    if agent == "cursor":
        return out["permission"], out.get("agent_message", out.get("user_message", ""))
    if agent == "gemini_cli":
        return out["decision"], out.get("reason", "")
    if agent == "mcp_generic":
        if "method" in out:
            return "allow", ""
        return "deny", out["result"]["content"][0]["text"]
    return out["decision"], out.get("reason", "")


@pytest.mark.parametrize(
    "agent", ["claude_code", "codex", "cursor", "gemini_cli", "mcp_generic", "other"]
)
def test_allow_deny_ask_native_on_every_agent(
    gw: Any, cw: CodingWorld, url: str, repo: Path, tmp_path: Path, agent: str
) -> None:
    s = samples(repo)[agent]
    extra = {"AGW_MCP_SERVER": "github"} if agent == "mcp_generic" else {}
    results = {
        case: verdict(
            agent, agw(["hook", agent, ev], payload, url, cw.device_token, tmp_path, **extra)
        )
        for case, (ev, payload) in s.items()
    }
    assert results["allow"][0] == "allow", results
    assert results["deny"][0] == "deny" and "AgentGuard denied" in results["deny"][1], results
    assert results["ask"][0] == "deny"
    assert results["ask"][1].startswith("Approval pending: http://localhost:3000/approvals/")
    assert "Retry after approval." in results["ask"][1]
    # The diff / file content never leaves in a response; .env content never left at all.
    with gw.engine.connect() as conn:
        bodies = conn.execute(
            select(t.evidence_events.c.body).where(
                t.evidence_events.c.tenant_id == gw.world.tenant_id
            )
        ).scalars()
        assert "never-sent" not in json.dumps(list(bodies))


def test_human_approval_while_hook_waits_then_retry_consumes_once(
    gw: Any, cw: CodingWorld, url: str, repo: Path, tmp_path: Path
) -> None:
    payload = samples(repo)["claude_code"]["ask"][1]
    env = {
        "PATH": os.environ.get("PATH", ""),
        "HOME": str(tmp_path),
        "AGW_URL": url,
        "AGW_DEVICE_KEY": cw.device_token,
        "AGW_STATE_DIR": str(tmp_path / "state"),
        "AGW_APPROVAL_WAIT_SECONDS": "45",
    }
    proc = subprocess.Popen(
        [sys.executable, "-m", "agw_cli", "hook", "claude_code", "PreToolUse"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=env,
    )
    assert proc.stdin is not None
    proc.stdin.write(json.dumps(payload))
    proc.stdin.close()
    proc.stdin = None  # closed: communicate() must not flush it
    approval_id = None
    for _ in range(200):
        with gw.engine.connect() as conn:
            approval_id = conn.execute(
                select(t.approvals.c.approval_id).where(
                    t.approvals.c.tenant_id == gw.world.tenant_id,
                    t.approvals.c.state == "PENDING",
                )
            ).scalar_one_or_none()
        if approval_id is not None:
            break
        time.sleep(0.05)
    assert approval_id is not None
    r = approve(gw.client, cw, str(approval_id), "lead")  # ledger/** -> ledger_lead
    assert r.status_code == 200, r.text
    stdout, stderr = proc.communicate(timeout=60)
    assert proc.returncode == 0, stderr
    assert stdout.strip() == ""  # allow (defer mode): no objection, Claude's own flow continues
    with gw.engine.connect() as conn:
        ap = conn.execute(
            select(t.approvals.c.state, t.approvals.c.action_id).where(
                t.approvals.c.approval_id == approval_id
            )
        ).one()
        uses = conn.execute(
            select(t.approval_uses).where(t.approval_uses.c.approval_id == approval_id)
        ).all()
    assert ap.state == "CONSUMED" and len(uses) == 1
    assert gw.action_status(ap.action_id) == "AUTHORIZED"
    # The same action again is a NEW request: the approval was single use.
    again = agw(["hook", "claude_code", "PreToolUse"], payload, url, cw.device_token, tmp_path)
    assert verdict("claude_code", again)[1].startswith("Approval pending: ")
    # Post-action report closes the lifecycle; the chain verifies independently.
    post = {**payload, "hook_event_name": "PostToolUse", "tool_response": {"ok": True}}
    p = agw(["hook", "claude_code", "PostToolUse"], post, url, cw.device_token, tmp_path)
    assert p.returncode == 0 and p.stdout == ""
    assert gw.events(ap.action_id)[-1] == "ACTION_COMPLETED"
    buf = io.StringIO()
    export_chain(gw.engine, gw.world.tenant_id, buf, store=gw.state.payloads)
    with gw.engine.connect() as conn:
        head = conn.execute(
            select(t.chain_heads).where(t.chain_heads.c.tenant_id == gw.world.tenant_id)
        ).one()
    report = verify_lines(
        buf.getvalue().splitlines(), trusted_head=bytes(head.last_hash), trusted_seq=head.last_seq
    )
    assert report.as_dict()["result"] == "VERIFIED", report.as_dict()


def test_cli_status_and_session_commands(
    gw: Any, cw: CodingWorld, url: str, repo: Path, tmp_path: Path
) -> None:
    env = {"AGW_ISSUE_NUMBER": "42", "AGW_ISSUE_SHA256": "d" * 64}
    st = agw(["status"], {}, url, cw.device_token, tmp_path)
    assert st.returncode == 0, st.stdout
    report = json.loads(st.stdout)
    assert report["gateway"]["developer"] == "dev"
    assert cw.device_token not in st.stdout
    started = subprocess.run(
        [sys.executable, "-m", "agw_cli", "session", "start", "--agent", "codex", "--issue", "42"],
        capture_output=True,
        text=True,
        cwd=repo,
        check=False,
        timeout=30,
        env={
            "PATH": os.environ.get("PATH", ""),
            "HOME": str(tmp_path),
            "AGW_URL": url,
            "AGW_DEVICE_KEY": cw.device_token,
            "AGW_STATE_DIR": str(tmp_path / "state"),
            **env,
        },
    )
    assert started.returncode == 0, started.stdout
    sid = json.loads(started.stdout)["session_id"]
    with gw.engine.connect() as conn:
        row = conn.execute(
            select(t.coding_sessions).where(t.coding_sessions.c.session_id == uuid.UUID(sid))
        ).one()
    assert (row.agent_kind, row.issue_number, row.head_sha) == ("codex", 42, "c" * 40)
    ended = subprocess.run(
        [sys.executable, "-m", "agw_cli", "session", "end", "--agent", "codex"],
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
        env={
            "PATH": os.environ.get("PATH", ""),
            "HOME": str(tmp_path),
            "AGW_URL": url,
            "AGW_DEVICE_KEY": cw.device_token,
            "AGW_STATE_DIR": str(tmp_path / "state"),
        },
    )
    assert ended.returncode == 0 and json.loads(ended.stdout)["status"] == "ENDED"
