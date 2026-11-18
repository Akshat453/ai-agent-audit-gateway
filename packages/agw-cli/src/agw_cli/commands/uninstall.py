"""``agw uninstall [--dry-run]`` (C2): remove ONLY what ``agw init`` added.

Our hook entries (commands starting ``agw hook``), the ``agentguard`` MCP server entries and the
marked blocks are removed from every file; files and directories init created are deleted only
if nothing else is left in them (created files such as ``.agentguard.yaml`` only if unchanged).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
from typing import Any

from agw_cli.commands.init import _load_manifest, diff_text, manifest_path
from agw_cli.normalize import find_repo_root
from agw_cli.wiring import BEGIN_MD, BEGIN_TOML, END_MD, END_TOML, replace_block, strip_ours

JSON_FILES = (
    ".claude/settings.json",
    ".mcp.json",
    ".codex/hooks.json",
    ".cursor/hooks.json",
    ".cursor/mcp.json",
    ".gemini/settings.json",
    ".vscode/mcp.json",
    ".agents/mcp_config.json",
)
BLOCK_FILES = ((".codex/config.toml", BEGIN_TOML, END_TOML), ("AGENTS.md", BEGIN_MD, END_MD))
CREATED_ONLY = (".agentguard.yaml", ".devcontainer/devcontainer.json")


def register(sub: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    p = sub.add_parser("uninstall", help="remove what agw init added to this repository")
    p.add_argument("--dry-run", action="store_true")
    p.set_defaults(func=main)


def plan_removal(root: Path, record: dict[str, Any]) -> list[tuple[str, str | None, str | None]]:
    """(path, before, after); after None = delete the file."""
    created = record.get("created", {})
    out: list[tuple[str, str | None, str | None]] = []
    for rel in JSON_FILES:
        p = root / rel
        if not p.is_file():
            continue
        before = p.read_text(encoding="utf-8")
        try:
            doc = json.loads(before)
        except ValueError:
            continue
        if not isinstance(doc, dict):
            continue
        stripped = strip_ours(doc)
        if stripped == doc:
            continue
        leftover = {k: v for k, v in stripped.items() if not (k == "version" and v == 1)}
        if rel in created and not leftover:
            out.append((rel, before, None))
        else:
            out.append((rel, before, json.dumps(stripped, indent=2, ensure_ascii=False) + "\n"))
    for rel, begin, end in BLOCK_FILES:
        p = root / rel
        if not p.is_file():
            continue
        before = p.read_text(encoding="utf-8")
        after = replace_block(before, begin, end, None)
        if after == before:
            continue
        out.append((rel, before, None if (rel in created and not after.strip()) else after))
    for rel in CREATED_ONLY:
        p = root / rel
        if rel in created and p.is_file():
            same = hashlib.sha256(p.read_bytes()).hexdigest() == created[rel]
            if same:
                out.append((rel, p.read_text(encoding="utf-8"), None))
    return out


def main(args: argparse.Namespace, out: Any = print) -> int:
    root = find_repo_root(os.getcwd())
    if root is None:
        out("agw uninstall: not inside a git repository.")
        return 2
    record = _load_manifest(root)
    changes = plan_removal(root, record)
    for rel, before, after in changes:
        out(f"{'delete' if after is None else 'modify':<7} {rel}")
        if after is not None:
            out(diff_text(rel, before, after))
    kept = [
        r
        for r in CREATED_ONLY
        if r in record.get("created", {})
        and (root / r).is_file()
        and not any(c[0] == r for c in changes)
    ]
    for r in kept:
        out(f"kept    {r} (edited since agw init created it)")
    if args.dry_run:
        out("Dry run: nothing was removed.")
        return 0
    for rel, _before, after in changes:
        p = root / rel
        if after is None:
            p.unlink(missing_ok=True)
        else:
            p.write_text(after, encoding="utf-8")
    for d in sorted(record.get("created_dirs", []), key=lambda s: -s.count("/")):
        path = root / d
        if path.is_dir() and not any(path.iterdir()):
            path.rmdir()
    manifest_path(root).unlink(missing_ok=True)
    out("AgentGuard removed from this repository (only what agw init added).")
    return 0
