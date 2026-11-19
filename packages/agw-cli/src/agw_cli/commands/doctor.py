"""``agw doctor`` (C2): is this machine and repository actually protected?

Checks: gateway reachable; logged in (device key valid); repository registered (and pending
admin proposals); per agent: tier, hooks present and pointing to ``agw hook``, safe hook
settings (timeout above the approval wait, fail-closed switches), MCP config valid and pointing
at this gateway, managed (mandatory) configuration present; ``agw`` on PATH; push/credential
exposure (credentials in the remote URL, credential helpers, tokens in the environment).
Exit status: 1 if any check FAILs; every FAIL / WARN carries a fix instruction.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from agw_cli.client import GatewayClient, GatewayRefused, GatewayUnavailable
from agw_cli.config import ConfigError, load, read_file_config
from agw_cli.detect import installed_agents, scan
from agw_cli.normalize import find_repo_root, git_info
from agw_cli.wiring import HOOK_PATH_DIRS, HOOK_PREFIX, SERVER_KEY, TIERS, is_hook_command

HOOK_FILES = {
    "claude_code": ".claude/settings.json",
    "codex": ".codex/hooks.json",
    "cursor": ".cursor/hooks.json",
    "gemini_cli": ".gemini/settings.json",
}
PRE_EVENT = {
    "claude_code": "PreToolUse",
    "codex": "PreToolUse",
    "cursor": "beforeShellExecution",
    "gemini_cli": "BeforeTool",
}
MANAGED = {
    "claude_code": [
        "/Library/Application Support/ClaudeCode/managed-settings.json",
        "/etc/claude-code/managed-settings.json",
    ],
    "codex": ["/etc/codex/requirements.toml", "/etc/codex/hooks.json"],
    "cursor": ["/Library/Application Support/Cursor/hooks.json", "/etc/cursor/hooks.json"],
    "gemini_cli": [
        "/Library/Application Support/GeminiCli/settings.json",
        "/etc/gemini-cli/settings.json",
    ],
}


@dataclass
class Check:
    status: str  # OK | WARN | FAIL
    name: str
    detail: str
    fix: str = ""


def register(sub: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    p = sub.add_parser("doctor", help="check this machine and repository")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=main)


def _json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _hook_entries(doc: Any, event: str) -> list[dict[str, Any]]:
    groups = (doc or {}).get("hooks", {}).get(event, []) if isinstance(doc, dict) else []
    out: list[dict[str, Any]] = []
    for g in groups if isinstance(groups, list) else []:
        if isinstance(g, dict) and isinstance(g.get("hooks"), list):
            out += [h for h in g["hooks"] if isinstance(h, dict)]
        elif isinstance(g, dict):
            out.append(g)
    return out


def agent_checks(root: Path, kind: str, gateway: str) -> list[Check]:
    tier, why = TIERS[kind]
    checks = [Check("OK", f"{kind}: tier", f"{tier} - {why}")]
    mcp_url = gateway.rstrip("/") + "/mcp"
    if kind in HOOK_FILES:
        doc = _json(root / HOOK_FILES[kind])
        ours = [
            h
            for h in _hook_entries(doc, PRE_EVENT[kind])
            if is_hook_command(h.get("command"), kind)
        ]
        if not ours:
            checks.append(
                Check(
                    "FAIL",
                    f"{kind}: pre-action hook",
                    f"no '{HOOK_PREFIX}{kind}' in {HOOK_FILES[kind]}",
                    "run: agw init --agents " + kind,
                )
            )
        else:
            h = ours[0]
            limit = 100_000 if kind == "gemini_cli" else 100
            if not isinstance(h.get("timeout"), int) or h["timeout"] < limit:
                checks.append(
                    Check(
                        "WARN",
                        f"{kind}: hook timeout",
                        "below the approval wait: the agent may kill the hook (fails open)",
                        "run: agw init --agents " + kind + " --yes",
                    )
                )
            if kind == "claude_code" and h.get("onFailure") != "block":
                checks.append(
                    Check(
                        "WARN",
                        f"{kind}: fail closed",
                        "onFailure is not 'block'",
                        "run: agw init --yes",
                    )
                )
            if kind == "cursor" and h.get("failClosed") is not True:
                checks.append(
                    Check(
                        "WARN",
                        f"{kind}: fail closed",
                        "failClosed is not true",
                        "run: agw init --yes",
                    )
                )
            checks.append(
                Check("OK", f"{kind}: pre-action hook", f"{HOOK_FILES[kind]} -> {h['command']}")
            )
        managed = [
            p
            for p in MANAGED[kind]
            if Path(p).is_file() and HOOK_PREFIX in Path(p).read_text(errors="replace")
        ]
        if managed:
            checks.append(Check("OK", f"{kind}: mandatory", f"managed config {managed[0]}"))
        else:
            checks.append(
                Check(
                    "WARN",
                    f"{kind}: mandatory",
                    "project hooks only: a user can remove them",
                    "ask IT to deploy the managed configuration (docs/gateway/coding-agents.md §2)",
                )
            )
    mcp_files = {
        "claude_code": (".mcp.json", "mcpServers", "url"),
        "cursor": (".cursor/mcp.json", "mcpServers", "url"),
        "gemini_cli": (".gemini/settings.json", "mcpServers", "httpUrl"),
        "vscode": (".vscode/mcp.json", "servers", "url"),
        "antigravity": (".agents/mcp_config.json", "mcpServers", "serverUrl"),
    }
    if kind == "codex":
        toml = root / ".codex/config.toml"
        ok = (
            toml.is_file()
            and f"[mcp_servers.{SERVER_KEY}]" in toml.read_text()
            and mcp_url in toml.read_text()
        )
        checks.append(
            Check(
                "OK" if ok else "FAIL",
                f"{kind}: MCP config",
                ".codex/config.toml"
                if ok
                else "AgentGuard MCP server missing or pointing elsewhere",
                "" if ok else "run: agw init --agents codex",
            )
        )
    elif kind in mcp_files:
        rel, key, field = mcp_files[kind]
        entry = (
            ((_json(root / rel) or {}).get(key) or {}).get(SERVER_KEY)
            if (root / rel).is_file()
            else None
        )
        ok = isinstance(entry, dict) and entry.get(field) == mcp_url
        checks.append(
            Check(
                "OK" if ok else "FAIL",
                f"{kind}: MCP config",
                f"{rel} -> {entry.get(field) if isinstance(entry, dict) else 'missing'}",
                "" if ok else f"run: agw init --agents {kind}",
            )
        )
    return checks


def git_checks(root: Path) -> list[Check]:
    out: list[Check] = []
    cfg = (
        (root / ".git" / "config").read_text(errors="replace")
        if (root / ".git" / "config").is_file()
        else ""
    )
    if (
        "@" in cfg and any(f"https://{x}" in cfg for x in ("x-access-token:", "oauth2:"))
    ) or ":ghp_" in cfg:
        out.append(
            Check(
                "FAIL",
                "git: remote credentials",
                "a token is embedded in a remote URL",
                "git remote set-url origin <url without credentials>",
            )
        )
    global_cfg = Path.home() / ".gitconfig"
    helper = "[credential" in cfg or (
        global_cfg.is_file() and "[credential" in global_cfg.read_text(errors="replace")
    )
    if helper:
        out.append(
            Check(
                "WARN",
                "git: credential helper",
                "stored git credentials let a process push without asking",
                "AgentGuard denies git push from agents; prefer short-lived tokens",
            )
        )
    leaked = [
        k
        for k in ("GITHUB_TOKEN", "GH_TOKEN", "NPM_TOKEN", "AWS_SECRET_ACCESS_KEY")
        if os.environ.get(k)
    ]
    if leaked:
        out.append(
            Check(
                "WARN",
                "environment tokens",
                f"set: {', '.join(leaked)}",
                "agents inherit the shell environment; unset tokens before starting an agent",
            )
        )
    if not out:
        out.append(Check("OK", "git: credentials", "no embedded tokens or credential helpers"))
    return out


def run(cwd: str | None = None) -> list[Check]:
    checks: list[Check] = []
    cfg_file = read_file_config()
    gateway = str(cfg_file.get("url") or os.environ.get("AGW_URL") or "")
    if not gateway:
        return [
            Check(
                "FAIL",
                "login",
                "no gateway configured",
                "run: agw login --url <gateway> --tenant <tenant>",
            )
        ]
    try:
        with urllib.request.urlopen(gateway.rstrip("/") + "/v1/health", timeout=5) as r:  # noqa: S310
            checks.append(Check("OK" if r.status == 200 else "FAIL", "gateway reachable", gateway))
    except Exception as exc:
        checks.append(
            Check(
                "FAIL",
                "gateway reachable",
                f"{gateway} ({type(exc).__name__})",
                "check the URL / network; hooks block every action while it is down",
            )
        )
    client: GatewayClient | None = None
    try:
        client = GatewayClient(load())
        st = client.status()
        checks.append(
            Check(
                "OK",
                "logged in",
                f"{st.get('developer')} on {st.get('tenant')} (device {st['device']['label']})",
            )
        )
    except (ConfigError, GatewayUnavailable, GatewayRefused, KeyError) as exc:
        client = None
        checks.append(Check("FAIL", "logged in", type(exc).__name__, "run: agw login"))
    # Hooks search PATH plus HOOK_PATH_DIRS (see wiring.hook_command), so check the same places.
    hook_path = os.pathsep.join(
        [os.environ.get("PATH", "")] + [os.path.expandvars(p) for p in HOOK_PATH_DIRS]
    )
    agw_bin = shutil.which("agw", path=hook_path)
    checks.append(
        Check(
            "OK" if agw_bin else "FAIL",
            "agw reachable by hooks",
            agw_bin or "not found",
            "" if agw_bin else "pipx install agw-cli (hooks call `agw`)",
        )
    )
    root = find_repo_root(cwd or os.getcwd())
    if root is None:
        checks.append(Check("WARN", "repository", "not inside a git repository"))
        return checks
    url = git_info(root).get("remote_url")
    if client is not None and url:
        try:
            rs = client.repo_status(url)
            note = f"policy v{rs.get('policy_version')}"
            if rs.get("pending_proposals"):
                note += f", {rs['pending_proposals']} proposal(s) waiting for an admin"
            checks.append(Check("OK", "repository registered", note))
        except GatewayRefused:
            checks.append(
                Check("FAIL", "repository registered", "unknown to the gateway", "run: agw init")
            )
        except GatewayUnavailable as exc:
            checks.append(Check("FAIL", "repository registered", str(exc)))
    info = scan(root)
    agents = [k for k in TIERS if k in info.agent_configs or k in installed_agents()]
    for kind in agents:
        checks += agent_checks(root, kind, gateway)
    checks += git_checks(root)
    return checks


def main(args: argparse.Namespace, out: Any = print) -> int:
    checks = run()
    if getattr(args, "json", False):
        out(json.dumps([c.__dict__ for c in checks], indent=2))
    else:
        for c in checks:
            out(f"[{c.status:<4}] {c.name}: {c.detail}")
            if c.fix and c.status != "OK":
                out(f"        fix: {c.fix}")
    failed = [c for c in checks if c.status == "FAIL"]
    out(
        f"{len(failed)} problem(s)."
        if failed
        else "All checks passed."
        if not any(c.status == "WARN" for c in checks)
        else "No failures (see warnings)."
    )
    return 1 if failed else 0
