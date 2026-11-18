"""``agw init [--dry-run] [--agents a,b] [--devcontainer] [--yes]`` (C2).

Detects the repository (root, package managers, languages, CODEOWNERS, existing agent configs)
and the installed agents, then writes: hook configs for hook-capable agents (Claude Code,
Codex, Cursor, Gemini CLI), the AgentGuard MCP server for every agent/IDE, a marked AGENTS.md
section, ``.agentguard.yaml`` with suggested sensitive paths (only if absent) and optionally a
hardened devcontainer. Existing files are never overwritten silently: a changed existing file
is shown as a diff and needs confirmation (``--yes`` for non-interactive use); our own parts
are identified by markers, so re-running is idempotent. Finally the repository is registered
with the gateway (tiers + the .agentguard.yaml text).
"""

from __future__ import annotations

import argparse
import difflib
import hashlib
import json
import os
import sys
from pathlib import Path
from typing import Any

from agw_cli.client import GatewayClient, GatewayRefused, GatewayUnavailable
from agw_cli.config import ConfigError, load, read_file_config
from agw_cli.detect import installed_agents, scan, suggested_yaml
from agw_cli.normalize import find_repo_root, git_info
from agw_cli.wiring import AGENT_KINDS, TIERS, Plan, build_plan

PLACEHOLDER_URL = "https://agentguard.example"


def installs_dir() -> Path:
    return Path(os.environ.get("AGW_HOME", str(Path.home() / ".agentguard"))) / "installs"


def manifest_path(root: Path) -> Path:
    return installs_dir() / f"{hashlib.sha256(str(root.resolve()).encode()).hexdigest()[:16]}.json"


def register(sub: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    p = sub.add_parser("init", help="wire this repository's coding agents to AgentGuard")
    p.add_argument("--dry-run", action="store_true", help="show what would change; write nothing")
    p.add_argument("--agents", default=None, help=f"comma list of {','.join(AGENT_KINDS)}")
    p.add_argument("--devcontainer", action="store_true", help="add a hardened devcontainer")
    p.add_argument("--yes", action="store_true", help="apply changes to existing files")
    p.add_argument("--url", default=None, help="gateway URL (default: from agw login)")
    p.set_defaults(func=main)


def choose_agents(raw: str | None, configured: dict[str, list[str]]) -> list[str]:
    if raw:
        agents = [a.strip() for a in raw.split(",") if a.strip()]
        bad = [a for a in agents if a not in AGENT_KINDS]
        if bad:
            raise ValueError(f"unknown agents: {', '.join(bad)}")
        return list(dict.fromkeys(agents))
    found: list[str] = [k for k in AGENT_KINDS if k in configured or k in installed_agents()]
    return found or list(AGENT_KINDS)


def diff_text(path: str, before: str | None, after: str) -> str:
    return "".join(
        difflib.unified_diff(
            (before or "").splitlines(keepends=True),
            after.splitlines(keepends=True),
            fromfile=f"a/{path}" if before is not None else "/dev/null",
            tofile=f"b/{path}",
        )
    )


def describe(plan: Plan, agents: list[str], info: Any, gateway: str, out: Any) -> None:
    out(f"Repository: {plan.root}")
    out(f"  package managers: {', '.join(info.package_managers) or 'none detected'}")
    out(f"  languages: {', '.join(info.languages) or 'none detected'}")
    out(f"  CODEOWNERS: {info.codeowners or 'none'}")
    configured = ", ".join(f"{k} ({', '.join(v)})" for k, v in info.agent_configs.items()) or "none"
    out(f"  existing agent configs: {configured}")
    out(f"  installed agents: {', '.join(installed_agents()) or 'none detected'}")
    out(f"Gateway: {gateway}")
    out("Agents and enforcement tiers:")
    for a in agents:
        tier, why = TIERS[a]
        out(f"  {a:<12} {tier:<9} {why}")
    out("Files:")
    for c in plan.changes:
        state = (
            ("create" if c.new_file else "modify")
            if c.changed
            else ("keep (exists)" if c.kind == "create" else "unchanged")
        )
        out(f"  {state:<14} {c.path}")
    for prob in plan.problems:
        out(f"  problem: {prob}")


def apply(plan: Plan, *, yes: bool, interactive: bool, out: Any) -> dict[str, Any]:
    record = _load_manifest(plan.root)
    for c in plan.changes:
        if not c.changed:
            continue
        target = plan.root / c.path
        if not c.new_file:
            out(diff_text(c.path, c.before, c.after))
            ok = yes or (
                interactive
                and input(f"Apply this change to {c.path}? [y/N] ").strip().lower() == "y"
            )
            if not ok:
                out(f"skipped {c.path} (re-run with --yes to apply)")
                continue
        else:
            for parent in reversed(target.relative_to(plan.root).parents[:-1]):
                d = plan.root / parent
                if not d.exists():
                    record["created_dirs"].append(parent.as_posix())
            record["created"][c.path] = hashlib.sha256(c.after.encode()).hexdigest()
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(c.after, encoding="utf-8")
        if c.path not in record["touched"]:
            record["touched"].append(c.path)
    p = manifest_path(plan.root)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return record


def _load_manifest(root: Path) -> dict[str, Any]:
    p = manifest_path(root)
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        if isinstance(data, dict):
            data.setdefault("created", {})
            data.setdefault("created_dirs", [])
            data.setdefault("touched", [])
            return data
    except (OSError, ValueError):
        pass
    return {"root": str(root), "created": {}, "created_dirs": [], "touched": []}


def remote_url(root: Path) -> str | None:
    return git_info(root).get("remote_url")


def main(args: argparse.Namespace, out: Any = print) -> int:
    root = find_repo_root(os.getcwd())
    if root is None:
        out("agw init: not inside a git repository.")
        return 2
    cfg_file = read_file_config()
    gateway = (args.url or cfg_file.get("url") or PLACEHOLDER_URL).rstrip("/")
    info = scan(root)
    try:
        agents = choose_agents(args.agents, info.agent_configs)
    except ValueError as exc:
        out(f"agw init: {exc}")
        return 2
    existing_yaml = root / ".agentguard.yaml"
    yaml_text = suggested_yaml(info)
    plan = build_plan(root, agents, gateway, yaml_text=yaml_text, devcontainer=args.devcontainer)
    describe(plan, agents, info, gateway, out)
    if args.dry_run:
        for c in plan.changes:
            if c.changed:
                out(diff_text(c.path, c.before, c.after))
        out("Dry run: nothing was written and the repository was not registered.")
        return 0
    apply(plan, yes=args.yes, interactive=sys.stdin.isatty(), out=out)
    url = remote_url(root)
    if url is None:
        out("No git remote 'origin': the repository was not registered with the gateway.")
        return 0
    try:
        cfg = load()
    except ConfigError:
        out(
            "Not logged in: files are written but the repository is not registered. "
            "Run agw login, then agw init again."
        )
        return 0
    try:
        client = GatewayClient(cfg)
        body = {
            "remote_url": url,
            "name": root.name,
            "agents": {
                a: {
                    "tier": TIERS[a][0],
                    "hooks": a in ("claude_code", "codex", "cursor", "gemini_cli"),
                }
                for a in agents
            },
            "agentguard_yaml": existing_yaml.read_text(encoding="utf-8")
            if existing_yaml.is_file()
            else yaml_text,
        }
        reg = client.register_repo(body)
    except (GatewayUnavailable, GatewayRefused) as exc:
        out(
            f"Not registered with the gateway ({type(exc).__name__}: {exc}). "
            "Run agw login, then agw init again."
        )
        return 1
    out(f"Registered {reg.get('name')} (repo policy v{reg.get('policy_version')}).")
    for item in reg.get("ignored", []):
        out(f"  ignored (needs an admin): {json.dumps(item, sort_keys=True)}")
    if reg.get("proposal_id"):
        out(f"  proposal {reg['proposal_id']} is waiting for an admin in the dashboard (Repos).")
    return 0
