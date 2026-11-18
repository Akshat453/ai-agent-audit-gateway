"""C1 fail-closed: gateway down, timeout, garbage responses, bad configuration, unreadable
input and internal errors all BLOCK a pre-action, with "AgentGuard unavailable - action
blocked", in each agent's native format. Real sockets and the real HTTP client are used."""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import threading
import time
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest
from agwcli_fakes import cfg, golden

from agw_cli.client import GatewayClient
from agw_cli.commands.hook import run_hook
from agw_cli.config import ConfigError, load

pytestmark = pytest.mark.unit
UNAVAILABLE = "AgentGuard unavailable - action blocked"
CLAUDE = golden("claude_code", "pre_bash_npm_test.json")


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


class Behaviour:
    mode = "ok"


def handler_for(behaviour: Behaviour) -> type[BaseHTTPRequestHandler]:
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a: Any) -> None:
            return

        def _send(self, status: int, body: bytes, ctype: str = "application/json") -> None:
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self) -> None:
            n = int(self.headers.get("Content-Length") or 0)
            self.rfile.read(n)
            m = behaviour.mode
            if self.path == "/v1/coding/sessions":
                self._send(
                    201,
                    json.dumps({"session_id": "0" * 8 + "-0000-7000-8000-" + "0" * 12}).encode(),
                )
                return
            if m == "sleep":
                time.sleep(3)
                self._send(200, b'{"decision":"allow","action_id":"x"}')
            elif m == "html":
                self._send(200, b"<html>proxy login</html>", "text/html")
            elif m == "bad_decision":
                self._send(200, b'{"decision":"maybe","action_id":"x"}')
            elif m == "ask_without_approval":
                self._send(200, b'{"decision":"ask","action_id":"x"}')
            elif m == "list":
                self._send(200, b"[1,2,3]")
            elif m == "500":
                self._send(500, b'{"error":{"code":"INTERNAL"}}')
            elif m == "503":
                self._send(503, b'{"error":{"code":"DEPENDENCY_UNAVAILABLE"}}')
            elif m == "401":
                self._send(401, b'{"error":{"code":"UNAUTHENTICATED"}}')
            elif m == "truncated":
                self._send(200, b'{"decision":"al')
            else:
                self._send(200, b'{"decision":"allow","action_id":"x","reason":""}')

        do_GET = do_POST

    return H


@pytest.fixture
def server() -> Iterator[tuple[str, Behaviour]]:
    b = Behaviour()
    srv = ThreadingHTTPServer(("127.0.0.1", 0), handler_for(b))
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        yield f"http://127.0.0.1:{srv.server_address[1]}", b
    finally:
        srv.shutdown()


def hook(agent: str, event: str, raw: str, tmp: Path, url: str, **over: Any) -> Any:
    c = cfg(tmp, url=url, request_timeout=1.0, **over)
    return run_hook(agent, event, raw, loader=lambda: c, client_factory=GatewayClient)


def claude_reason(r: Any) -> str:
    body = json.loads(r.stdout)
    assert body["hookSpecificOutput"]["permissionDecision"] == "deny"
    return str(body["hookSpecificOutput"]["permissionDecisionReason"])


def test_sanity_ok_server_allows(server: tuple[str, Behaviour], tmp_path: Path) -> None:
    url, _ = server
    r = hook("cursor", "beforeShellExecution", golden("cursor", "before_shell.json"), tmp_path, url)
    assert json.loads(r.stdout) == {"permission": "allow"}


def test_gateway_down(tmp_path: Path) -> None:
    r = hook("claude_code", "PreToolUse", CLAUDE, tmp_path, f"http://127.0.0.1:{free_port()}")
    assert claude_reason(r).startswith(UNAVAILABLE)


@pytest.mark.parametrize(
    "mode",
    [
        "sleep",
        "html",
        "bad_decision",
        "ask_without_approval",
        "list",
        "500",
        "503",
        "401",
        "truncated",
    ],
)
def test_bad_gateway_answers_block(
    server: tuple[str, Behaviour], tmp_path: Path, mode: str
) -> None:
    url, b = server
    b.mode = mode
    started = time.monotonic()
    r = hook("claude_code", "PreToolUse", CLAUDE, tmp_path, url)
    assert claude_reason(r).startswith(UNAVAILABLE)
    assert time.monotonic() - started < 2.5  # the request timeout bounds the wait


@pytest.mark.parametrize(
    ("agent", "name", "event", "check"),
    [
        (
            "codex",
            "pre_bash.json",
            "PreToolUse",
            lambda o: o["hookSpecificOutput"]["permissionDecisionReason"],
        ),
        ("cursor", "before_shell.json", "beforeShellExecution", lambda o: o["user_message"]),
        ("gemini_cli", "before_tool_shell.json", "BeforeTool", lambda o: o["systemMessage"]),
        (
            "mcp_generic",
            "tools_call.json",
            "tools/call",
            lambda o: o["result"]["content"][0]["text"],
        ),
        ("other", "pre.json", "pre", lambda o: o["reason"]),
    ],
)
def test_every_agent_fails_closed_natively(
    tmp_path: Path, agent: str, name: str, event: str, check: Any
) -> None:
    r = hook(agent, event, golden(agent, name), tmp_path, f"http://127.0.0.1:{free_port()}")
    assert check(json.loads(r.stdout)).startswith(UNAVAILABLE)


def test_missing_config_blocks(tmp_path: Path) -> None:
    def loader() -> Any:
        raise ConfigError("gateway URL is not configured")

    r = run_hook("claude_code", "PreToolUse", CLAUDE, loader=loader)
    assert claude_reason(r).startswith(UNAVAILABLE)


def test_garbage_stdin_blocks(tmp_path: Path) -> None:
    r = hook("claude_code", "PreToolUse", "not json{", tmp_path, "http://127.0.0.1:9")
    assert "could not read" in claude_reason(r)
    r2 = hook("cursor", "preToolUse", '{"tool_input": {}}', tmp_path, "http://127.0.0.1:9")
    assert json.loads(r2.stdout)["permission"] == "deny"


def test_internal_error_blocks(tmp_path: Path) -> None:
    def boom(_: Any) -> Any:
        raise RuntimeError("bug")

    r = run_hook(
        "claude_code", "PreToolUse", CLAUDE, loader=lambda: cfg(tmp_path), client_factory=boom
    )
    assert claude_reason(r).startswith(UNAVAILABLE)


def test_post_event_failures_never_block(tmp_path: Path) -> None:
    r = hook(
        "claude_code",
        "PostToolUse",
        golden("claude_code", "post_write.json"),
        tmp_path,
        f"http://127.0.0.1:{free_port()}",
    )
    assert (r.exit_code, r.stdout) == (0, "")
    assert "could not record" in r.stderr


def test_key_file_permissions_and_url_are_checked(tmp_path: Path) -> None:
    key = tmp_path / "device.key"
    key.write_text("agw_0123456789abcdef_" + "A" * 43)
    key.chmod(0o644)
    with pytest.raises(ConfigError, match="readable by others"):
        load({"AGW_URL": "http://x", "AGW_DEVICE_KEY_FILE": str(key), "AGW_CONFIG": "/nonexistent"})
    key.chmod(0o600)
    c = load({"AGW_URL": "http://x", "AGW_DEVICE_KEY_FILE": str(key), "AGW_CONFIG": "/nonexistent"})
    assert c.device_key.startswith("agw_") and "AAAA" not in json.dumps(c.redacted())
    with pytest.raises(ConfigError):
        load({"AGW_URL": "ftp://x", "AGW_DEVICE_KEY": "agw_x", "AGW_CONFIG": "/nonexistent"})


def _agw(args: list[str], stdin: str, env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "agw_cli", *args],
        input=stdin,
        capture_output=True,
        text=True,
        env={"PATH": os.environ.get("PATH", ""), "HOME": env["HOME"], **env},
        timeout=30,
        check=False,
    )


def test_binary_unknown_agent_or_event_exits_2(tmp_path: Path) -> None:
    env = {"HOME": str(tmp_path), "AGW_URL": "http://127.0.0.1:9", "AGW_DEVICE_KEY": "agw_x"}
    p = _agw(["hook", "windsurf", "pre"], CLAUDE, env)
    assert p.returncode == 2 and UNAVAILABLE in p.stderr
    p2 = _agw(["hook", "claude_code", "Teleport"], CLAUDE, env)
    assert p2.returncode == 2 and UNAVAILABLE in p2.stderr


def test_binary_gateway_down_prints_native_deny(tmp_path: Path) -> None:
    env = {
        "HOME": str(tmp_path),
        "AGW_URL": f"http://127.0.0.1:{free_port()}",
        "AGW_DEVICE_KEY": "agw_0123456789abcdef_" + "A" * 43,
        "AGW_STATE_DIR": str(tmp_path / "state"),
    }
    p = _agw(["hook", "claude_code", "PreToolUse"], CLAUDE, env)
    assert p.returncode == 0
    out = json.loads(p.stdout)["hookSpecificOutput"]
    assert out["permissionDecision"] == "deny"
    assert out["permissionDecisionReason"].startswith(UNAVAILABLE)
    status = _agw(["status"], "", env)
    assert status.returncode == 1 and UNAVAILABLE in status.stdout
    assert "AAAA" not in status.stdout  # the key is never printed
