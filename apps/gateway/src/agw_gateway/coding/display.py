"""What a person may SEE about a coding action (ADR-0039).

Paths, commands, URLs, search patterns and MCP tool names are metadata of the action, not its
content: the console shows them so a reviewer knows what the agent tried. File contents and
diffs are content and are never shown; only a count (files, +lines, -lines) is kept.

Commands can carry secrets (``TOKEN=... cmd``, ``-H "Authorization: Bearer ..."``,
``postgres://user:pass@host``). :func:`redact` replaces every recognised secret VALUE with
``[REDACTED]`` before anything is stored. The stored copy is additionally sealed under the KEK
(``ops_context(tenant, "coding_target", action_id)``), like approval request args (ADR-0029).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Final

from agw_gateway.coding.content import _GENERIC_SECRET, _PLACEHOLDER, _SECRET_PATTERNS
from agw_gateway.coding.digest import normalized_targets
from agw_gateway.coding.model import CodingAction

MARK: Final = "[REDACTED]"
MAX_SHOWN: Final = 2000  # characters per shown field

# NAME=value (env assignment / flag=value) where NAME looks like a secret.
_ASSIGN: Final = re.compile(
    r"""(?ix)\b([\w.-]*?(password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key
        |private[_-]?key|signing[_-]?key|client[_-]?secret|credentials?|auth))
        (\s*=\s*)(["']?)([^\s"']+)\4"""
)
_FLAG: Final = re.compile(
    r"""(?ix)(--?(password|passwd|pwd|token|secret|api[_-]?key|access[_-]?token|auth[_-]?token
        |client[_-]?secret|private[_-]?key)(=|\s+))(["']?)([^\s"']+)\4"""
)
_AUTH_HEADER: Final = re.compile(
    r"(?i)\b(authorization|x-api-key|api-key|cookie)\s*:\s*([^\"'\n]+)"
)
_URL_CRED: Final = re.compile(r"(?i)\b([a-z][a-z0-9+.-]*://[^:/\s@]+:)([^@\s]+)(@)")


def redact(text: str) -> str:
    """Replace secret values in free text (commands, URLs) with ``[REDACTED]``."""
    out = _URL_CRED.sub(lambda m: f"{m.group(1)}{MARK}{m.group(3)}", text)
    out = _AUTH_HEADER.sub(lambda m: f"{m.group(1)}: {MARK}", out)
    out = _FLAG.sub(lambda m: f"{m.group(1)}{m.group(4)}{MARK}{m.group(4)}", out)

    def _assign(m: re.Match[str]) -> str:
        value = m.group(5)
        if _PLACEHOLDER.match(value) or value.startswith("$"):
            return m.group(0)
        return f"{m.group(1)}{m.group(3)}{m.group(4)}{MARK}{m.group(4)}"

    out = _ASSIGN.sub(_assign, out)
    for p in _SECRET_PATTERNS:
        out = p.sub(MARK, out)
    out = _GENERIC_SECRET.sub(lambda m: m.group(0).replace(m.group(2), MARK), out)
    return out


def _clip(s: str) -> str:
    return s if len(s) <= MAX_SHOWN else f"{s[:MAX_SHOWN]}… [TRUNCATED]"


def display_target(action: CodingAction) -> dict[str, Any]:
    """The normalized targets, with every free-text field redacted and clipped."""
    return display_from_targets(normalized_targets(action), action.native_tool)


def display_from_targets(targets: dict[str, Any], native_tool: str | None) -> dict[str, Any]:
    """Same, from an already normalized targets map (the evidence payload's
    ``intent.action.targets``), used to fill in actions recorded before migration 0015."""
    shown: dict[str, Any] = {}
    for key in ("command", "url", "query"):
        if isinstance(targets.get(key), str):
            shown[key] = _clip(redact(targets[key]))
    if isinstance(targets.get("argv"), list):
        shown["argv"] = [_clip(redact(str(a))) for a in targets["argv"]]
    if isinstance(targets.get("paths"), list):
        shown["paths"] = [_clip(str(p)) for p in targets["paths"]]
    mcp = targets.get("mcp")
    if isinstance(mcp, dict) and mcp.get("tool"):
        shown["mcp"] = {"tool": str(mcp["tool"])}
        if mcp.get("server"):
            shown["mcp"]["server"] = str(mcp["server"])
    if native_tool:
        shown["native_tool"] = native_tool
    return shown


@dataclass(frozen=True)
class DiffSummary:
    files: int
    added: int
    removed: int


def diff_summary(diff: str | None) -> DiffSummary | None:
    """Counts only (files touched, lines added, lines removed). Never the text."""
    if not diff:
        return None
    files: set[str] = set()
    added = removed = 0
    for ln in diff.splitlines():
        if ln.startswith("+++ ") or ln.startswith("--- "):
            name = ln[4:].strip()
            if name != "/dev/null":
                files.add(name[2:] if name[:2] in ("a/", "b/") else name)
        elif ln.startswith("+"):
            added += 1
        elif ln.startswith("-"):
            removed += 1
    return DiffSummary(files=len(files), added=added, removed=removed)
