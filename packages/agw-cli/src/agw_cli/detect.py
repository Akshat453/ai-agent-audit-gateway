"""Repository and machine detection for ``agw init`` / ``agw doctor`` (C2). Read-only."""

from __future__ import annotations

import os
import re
import shutil
import sys
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Final

SKIP_DIRS: Final = frozenset(
    {
        ".git",
        "node_modules",
        "dist",
        "build",
        ".next",
        ".venv",
        "venv",
        "__pycache__",
        "coverage",
        ".turbo",
        "target",
        ".mypy_cache",
    }
)
LANG_EXT: Final = {
    ".ts": "typescript",
    ".tsx": "typescript",
    ".js": "javascript",
    ".py": "python",
    ".go": "go",
    ".rs": "rust",
    ".java": "java",
    ".rb": "ruby",
    ".kt": "kotlin",
}
LOCKFILES: Final = {
    "pnpm-lock.yaml": "pnpm",
    "package-lock.json": "npm",
    "yarn.lock": "yarn",
    "bun.lockb": "bun",
    "uv.lock": "uv",
    "poetry.lock": "poetry",
    "Pipfile.lock": "pipenv",
    "requirements.txt": "pip",
    "go.sum": "go",
    "Cargo.lock": "cargo",
}
SENSITIVE: Final = re.compile(
    r"^(payments?|billing|refunds?|auth|authn|authz|ledger|settlements?|payouts?|migrations|"
    r"drizzle|alembic|infra|terraform|signing|signatures?|money|webhooks?)$",
    re.I,
)
# Front-end code (pages, components, route groups such as "(app)"): a "refunds" page is UI,
# not money logic. The money logic it calls (api/, ledger/, ...) is what gets flagged.
UI_DIRS: Final = frozenset({"pages", "components", "ui", "views"})  # plus "(group)" dirs
AGENT_DIRS: Final = {
    "claude_code": [".claude"],
    "codex": [".codex"],
    "cursor": [".cursor"],
    "gemini_cli": [".gemini"],
    "vscode": [".vscode/mcp.json"],
    "antigravity": [".agents"],
}
AGENT_BINARIES: Final = {
    "claude_code": (["claude"], []),
    "codex": (["codex"], []),
    "cursor": (["cursor", "cursor-agent"], ["/Applications/Cursor.app"]),
    "gemini_cli": (["gemini"], []),
    "vscode": (["code"], ["/Applications/Visual Studio Code.app"]),
    "antigravity": (["antigravity"], ["/Applications/Antigravity.app"]),
}


@dataclass
class RepoInfo:
    root: Path
    package_managers: list[str] = field(default_factory=list)
    languages: list[str] = field(default_factory=list)
    codeowners: str | None = None
    agent_configs: dict[str, list[str]] = field(default_factory=dict)
    sensitive: list[tuple[str, str, str | None]] = field(
        default_factory=list
    )  # (glob, level, owner)


def _walk(root: Path, max_depth: int = 4) -> list[Path]:
    out: list[Path] = []
    base = len(root.parts)
    for dirpath, dirnames, filenames in os.walk(root):
        depth = len(Path(dirpath).parts) - base
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS and depth < max_depth)
        for d in dirnames:
            out.append(Path(dirpath) / d)
        for f in sorted(filenames):
            out.append(Path(dirpath) / f)
        if len(out) > 20000:
            break
    return out


def scan(root: Path) -> RepoInfo:
    info = RepoInfo(root=root)
    entries = _walk(root)
    langs: Counter[str] = Counter()
    seen: set[str] = set()
    for p in entries:
        rel = p.relative_to(root).as_posix()
        if p.is_file():
            if p.suffix in LANG_EXT:
                langs[LANG_EXT[p.suffix]] += 1
            if rel in LOCKFILES and LOCKFILES[rel] not in info.package_managers:
                info.package_managers.append(LOCKFILES[rel])
        name = p.stem if p.is_file() else p.name
        parts = rel.lower().split("/")[:-1]
        ui = any(d in UI_DIRS or (d.startswith("(") and d.endswith(")")) for d in parts)
        if SENSITIVE.match(name) and "test" not in rel.lower() and not ui:
            glob = f"{rel}/**" if p.is_dir() else rel
            if any(glob.startswith(s.rstrip("*")) for s in seen):
                continue  # already covered by a parent directory
            seen.add(glob)
            owner = "ledger_lead" if name.lower() == "ledger" else None
            level = "critical" if name.lower() in ("infra", "terraform") else "high"
            info.sensitive.append((glob, level, owner))
    for rel in (".github/CODEOWNERS", "CODEOWNERS", "docs/CODEOWNERS"):
        if (root / rel).is_file():
            info.codeowners = rel
            break
    if (root / ".github").is_dir():
        info.sensitive.insert(0, (".github/**", "critical", None))
    for lock in LOCKFILES:
        if (root / lock).is_file() and lock != "requirements.txt":
            info.sensitive.append((lock, "critical", None))
    info.languages = [lang for lang, _n in langs.most_common(5)]
    for kind, paths in AGENT_DIRS.items():
        found = [p for p in paths if (root / p).exists()]
        if found:
            info.agent_configs[kind] = found
    for extra in ("AGENTS.md", "CLAUDE.md", "GEMINI.md", ".mcp.json"):
        if (root / extra).exists():
            info.agent_configs.setdefault("shared", []).append(extra)
    return info


def installed_agents() -> list[str]:
    out = []
    for kind, (bins, apps) in AGENT_BINARIES.items():
        if any(shutil.which(b) for b in bins) or (
            sys.platform == "darwin" and any(Path(a).exists() for a in apps)
        ):
            out.append(kind)
    return out


def suggested_yaml(info: RepoInfo) -> str:
    lines = [
        "# AgentGuard repository policy (generated by agw init).",
        "# This file can only TIGHTEN the organisation's policy. Anything that would loosen it",
        "# (allow_paths, allow_commands, removing an entry) is ignored and sent to an admin as",
        "# a proposal. Edits to this file by an agent need a security approval.",
        "version: 1",
        "sensitive_paths:",
    ]
    if not info.sensitive:
        lines[-1] = "sensitive_paths: []"
    for glob, level, owner in info.sensitive:
        lines.append(f'  - path: "{glob}"')
        lines.append(f"    level: {level}")
        if owner:
            lines.append(f"    owner: {owner}")
    lines += ["deny_paths: []", "deny_commands: []", ""]
    return "\n".join(lines)
