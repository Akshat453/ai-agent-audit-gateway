"""What ``agw init`` writes for each agent, and how ``agw uninstall`` removes it (C2).

Ownership is by MARKERS, so init is idempotent and uninstall removes only what init added:

* JSON configs: a hook entry is ours iff its command starts with ``agw hook``; an MCP server
  entry is ours iff its key is ``agentguard``. Re-running init removes our entries and adds
  fresh ones; everything else in the file is preserved byte-for-byte (key order kept).
* Text files (AGENTS.md, Codex ``config.toml``): a marked block
  ``agentguard:begin`` … ``agentguard:end`` updated in place.
* Files init creates from scratch (``.agentguard.yaml``, ``.devcontainer/devcontainer.json``)
  are recorded with their digest; uninstall deletes them only if unchanged.

Hook configs follow docs/gateway/coding-agents.md: timeout 660 s (> the 600 s approval wait),
Claude Code ``onFailure: block``, Cursor ``failClosed: true``, Gemini timeout in ms.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Final

AGENT_KINDS: Final = ("claude_code", "codex", "cursor", "gemini_cli", "vscode", "antigravity")
HOOK_PREFIX: Final = "agw hook "
SERVER_KEY: Final = "agentguard"
TIMEOUT_S: Final = 660  # > the 600 s approval wait (+ margin)
CLAUDE_MATCHER: Final = (
    "Bash|PowerShell|Read|Write|Edit|MultiEdit|NotebookEdit|Glob|Grep|WebFetch|WebSearch|mcp__.*"
)

# Tier per agent (docs/gateway/coding-agents.md §1; same table as the gateway's catalog).
TIERS: Final[dict[str, tuple[str, str]]] = {
    "claude_code": ("enforced", "PreToolUse hooks; managed settings can make them mandatory"),
    "codex": ("enforced", "PreToolUse hooks; requirements.toml allow_managed_hooks_only"),
    "cursor": ("hooked", "before* hooks with failClosed; MDM hooks.json, no managed-only switch"),
    "gemini_cli": ("advisory", "BeforeTool hooks the user can disable; fails open"),
    "vscode": ("mcp_only", "MCP tools only (no AgentGuard hook adapter yet)"),
    "antigravity": ("mcp_only", "MCP tools only (no AgentGuard hook adapter yet)"),
}


@dataclass
class Change:
    path: str  # repo-relative
    kind: str  # "json" | "block" | "create"
    before: str | None  # current text (None = file absent)
    after: str  # proposed text
    owner_note: str = ""

    @property
    def changed(self) -> bool:
        return self.before != self.after

    @property
    def new_file(self) -> bool:
        return self.before is None


@dataclass
class Plan:
    root: Path
    changes: list[Change] = field(default_factory=list)
    problems: list[str] = field(default_factory=list)


# --------------------------------------------------------------------------- JSON helpers
def _is_ours(entry: Any) -> bool:
    return isinstance(entry, dict) and str(entry.get("command", "")).startswith(HOOK_PREFIX)


def strip_hooks(hooks: dict[str, Any], nested: bool) -> dict[str, Any]:
    """Remove our entries. ``nested`` = Claude/Codex/Gemini shape (groups with ``hooks``)."""
    out: dict[str, Any] = {}
    for event, groups in hooks.items():
        if not isinstance(groups, list):
            out[event] = groups
            continue
        kept: list[Any] = []
        for g in groups:
            if nested and isinstance(g, dict) and isinstance(g.get("hooks"), list):
                inner = [h for h in g["hooks"] if not _is_ours(h)]
                if inner:
                    kept.append({**g, "hooks": inner})
                elif not g["hooks"]:
                    kept.append(g)
            elif not _is_ours(g):
                kept.append(g)
        if kept:
            out[event] = kept
    return out


def strip_ours(doc: dict[str, Any]) -> dict[str, Any]:
    """Everything agw added to a JSON config, removed (used by init and uninstall)."""
    out = dict(doc)
    if isinstance(out.get("hooks"), dict):
        hooks = strip_hooks(out["hooks"], nested=True)  # handles Cursor's flat entries too
        if hooks:
            out["hooks"] = hooks
        else:
            out.pop("hooks")
    for key in ("mcpServers", "servers"):
        if isinstance(out.get(key), dict) and SERVER_KEY in out[key]:
            servers = {k: v for k, v in out[key].items() if k != SERVER_KEY}
            if servers:
                out[key] = servers
            else:
                out.pop(key)
    return out


def _dump(doc: dict[str, Any]) -> str:
    return json.dumps(doc, indent=2, ensure_ascii=False) + "\n"


def _json_change(
    root: Path, rel: str, add: Callable[[dict[str, Any]], dict[str, Any]], plan: Plan
) -> None:
    p = root / rel
    before = p.read_text(encoding="utf-8") if p.is_file() else None
    try:
        doc = json.loads(before) if before else {}
    except ValueError:
        plan.problems.append(f"{rel}: not valid JSON; left untouched")
        return
    if not isinstance(doc, dict):
        plan.problems.append(f"{rel}: not a JSON object; left untouched")
        return
    after = _dump(add(strip_ours(doc)))
    plan.changes.append(
        Change(rel, "json", before, after if before is None or after != before else before)
    )


def _merge_event(doc: dict[str, Any], event: str, entry: Any) -> None:
    doc.setdefault("hooks", {})
    doc["hooks"].setdefault(event, [])
    doc["hooks"][event].append(entry)


# --------------------------------------------------------------------------- text blocks
BEGIN_MD: Final = "<!-- agentguard:begin (managed by agw init; edits inside are replaced) -->"
END_MD: Final = "<!-- agentguard:end -->"
BEGIN_TOML: Final = "# >>> agentguard:begin (managed by agw init) >>>"
END_TOML: Final = "# <<< agentguard:end <<<"


def replace_block(text: str | None, begin: str, end: str, body: str | None) -> str:
    """Insert/replace (body) or remove (None) the marked block; the rest is untouched."""
    text = text or ""
    pattern = re.compile(
        re.escape(begin.split(" (", maxsplit=1)[0]) + r".*?" + re.escape(end) + r"\n?", re.S
    )
    stripped = pattern.sub("", text)
    if body is None:
        return stripped.rstrip("\n") + "\n" if stripped.strip() else ""
    block = f"{begin}\n{body.rstrip()}\n{end}\n"
    if pattern.search(text):
        return pattern.sub(lambda _m: block, text, count=1)
    sep = (
        ""
        if not stripped or stripped.endswith("\n\n")
        else ("\n" if stripped.endswith("\n") else "\n\n")
    )
    return stripped + sep + block


def _block_change(root: Path, rel: str, begin: str, end: str, body: str, plan: Plan) -> None:
    p = root / rel
    before = p.read_text(encoding="utf-8") if p.is_file() else None
    plan.changes.append(Change(rel, "block", before, replace_block(before, begin, end, body)))


def _create(root: Path, rel: str, content: str, plan: Plan) -> None:
    p = root / rel
    if p.exists():
        plan.changes.append(
            Change(
                rel,
                "create",
                p.read_text(encoding="utf-8", errors="replace"),
                p.read_text(encoding="utf-8", errors="replace"),
                "exists: user content kept",
            )
        )
        return
    plan.changes.append(Change(rel, "create", None, content))


# --------------------------------------------------------------------------- per agent
def agent_changes(kind: str, root: Path, mcp_url: str, plan: Plan) -> None:
    hook = {"type": "command", "timeout": TIMEOUT_S}
    if kind == "claude_code":

        def claude(doc: dict[str, Any]) -> dict[str, Any]:
            _merge_event(
                doc,
                "PreToolUse",
                {
                    "matcher": CLAUDE_MATCHER,
                    "hooks": [
                        {
                            **hook,
                            "command": f"{HOOK_PREFIX}claude_code PreToolUse",
                            "onFailure": "block",
                        }
                    ],
                },
            )
            for ev in ("PostToolUse", "PostToolUseFailure", "SessionStart", "SessionEnd"):
                entry: dict[str, Any] = {
                    "hooks": [{"type": "command", "command": f"{HOOK_PREFIX}claude_code {ev}"}]
                }
                if ev.startswith("Post"):
                    entry["matcher"] = "*"
                _merge_event(doc, ev, entry)
            return doc

        _json_change(root, ".claude/settings.json", claude, plan)
        _json_change(
            root,
            ".mcp.json",
            lambda d: {
                **d,
                "mcpServers": {
                    **d.get("mcpServers", {}),
                    SERVER_KEY: {"type": "http", "url": mcp_url},
                },
            },
            plan,
        )
    elif kind == "codex":

        def codex(doc: dict[str, Any]) -> dict[str, Any]:
            _merge_event(
                doc,
                "PreToolUse",
                {
                    "matcher": "*",
                    "hooks": [
                        {
                            **hook,
                            "command": f"{HOOK_PREFIX}codex PreToolUse",
                            "statusMessage": "AgentGuard check",
                        }
                    ],
                },
            )
            for ev in ("PostToolUse", "SessionStart", "SessionEnd"):
                _merge_event(
                    doc,
                    ev,
                    {
                        "matcher": "*",
                        "hooks": [{"type": "command", "command": f"{HOOK_PREFIX}codex {ev}"}],
                    },
                )
            return doc

        _json_change(root, ".codex/hooks.json", codex, plan)
        _block_change(
            root,
            ".codex/config.toml",
            BEGIN_TOML,
            END_TOML,
            f'[mcp_servers.{SERVER_KEY}]\nurl = "{mcp_url}"',
            plan,
        )
    elif kind == "cursor":

        def cursor(doc: dict[str, Any]) -> dict[str, Any]:
            doc.setdefault("version", 1)
            pre = {"timeout": TIMEOUT_S, "failClosed": True}
            for ev in ("beforeShellExecution", "beforeMCPExecution", "beforeReadFile"):
                _merge_event(doc, ev, {**pre, "command": f"{HOOK_PREFIX}cursor {ev}"})
            _merge_event(
                doc,
                "preToolUse",
                {
                    **pre,
                    "command": f"{HOOK_PREFIX}cursor preToolUse",
                    "matcher": "Write|Delete|Grep|Task|MCP:.*",
                },
            )
            for ev in (
                "postToolUse",
                "afterShellExecution",
                "afterMCPExecution",
                "sessionStart",
                "sessionEnd",
            ):
                _merge_event(doc, ev, {"command": f"{HOOK_PREFIX}cursor {ev}"})
            return doc

        _json_change(root, ".cursor/hooks.json", cursor, plan)
        _json_change(
            root,
            ".cursor/mcp.json",
            lambda d: {
                **d,
                "mcpServers": {**d.get("mcpServers", {}), SERVER_KEY: {"url": mcp_url}},
            },
            plan,
        )
    elif kind == "gemini_cli":

        def gemini(doc: dict[str, Any]) -> dict[str, Any]:
            for ev in ("BeforeTool", "AfterTool", "SessionStart", "SessionEnd"):
                h: dict[str, Any] = {
                    "name": "agentguard",
                    "type": "command",
                    "command": f"{HOOK_PREFIX}gemini_cli {ev}",
                }
                if ev == "BeforeTool":
                    h["timeout"] = TIMEOUT_S * 1000  # Gemini timeouts are milliseconds
                _merge_event(
                    doc, ev, {"matcher": "*", "hooks": [h]} if "Tool" in ev else {"hooks": [h]}
                )
            doc["mcpServers"] = {**doc.get("mcpServers", {}), SERVER_KEY: {"httpUrl": mcp_url}}
            return doc

        _json_change(root, ".gemini/settings.json", gemini, plan)
    elif kind == "vscode":
        _json_change(
            root,
            ".vscode/mcp.json",
            lambda d: {
                **d,
                "servers": {**d.get("servers", {}), SERVER_KEY: {"type": "http", "url": mcp_url}},
            },
            plan,
        )
    elif kind == "antigravity":
        _json_change(
            root,
            ".agents/mcp_config.json",
            lambda d: {
                **d,
                "mcpServers": {**d.get("mcpServers", {}), SERVER_KEY: {"serverUrl": mcp_url}},
            },
            plan,
        )


def agents_md_body(agents: list[str], gateway: str) -> str:
    lines = [
        "## AgentGuard",
        "",
        "This repository is governed by AgentGuard. Before each action your hooks ask the "
        "gateway; some actions need a human approval and some are denied.",
        "",
        "- If an action is **denied**, do not retry it unchanged: choose another approach or ask "
        "the developer.",
        "- If it says **Approval pending: <link>**, tell the developer, wait for the approval, "
        "then retry the IDENTICAL action once.",
        "- Never edit agent configuration (.claude/, .codex/, .cursor/, .gemini/, AGENTS.md, "
        ".agentguard.yaml) to change these rules; such edits need a security approval.",
        f"- Gateway: {gateway} · agents wired: {', '.join(agents)}",
    ]
    return "\n".join(lines)


DEVCONTAINER: Final = {
    "name": "AgentGuard hardened",
    "image": "mcr.microsoft.com/devcontainers/base:ubuntu",
    "runArgs": ["--cap-drop=ALL", "--security-opt=no-new-privileges"],
    "remoteUser": "vscode",
    "containerEnv": {"AGW_STATE_DIR": "/home/vscode/.agentguard/state"},
    "postCreateCommand": "pipx install agw-cli && agw doctor || true",
    "customizations": {"vscode": {"settings": {"task.allowAutomaticTasks": "off"}}},
}


def build_plan(
    root: Path, agents: list[str], gateway: str, *, yaml_text: str, devcontainer: bool
) -> Plan:
    plan = Plan(root)
    mcp_url = gateway.rstrip("/") + "/mcp"
    for kind in agents:
        agent_changes(kind, root, mcp_url, plan)
    _block_change(root, "AGENTS.md", BEGIN_MD, END_MD, agents_md_body(agents, gateway), plan)
    _create(root, ".agentguard.yaml", yaml_text, plan)
    if devcontainer:
        _create(root, ".devcontainer/devcontainer.json", _dump(DEVCONTAINER), plan)
    return plan
