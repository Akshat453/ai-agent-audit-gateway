"""Building ``agw.coding-action/1`` actions from native payloads (shared by all adapters).

Nothing here sends file contents anywhere: a write becomes a unified DIFF (the gateway's
content rules need it; it is stored only encrypted), reads become paths, results become
SHA-256 digests.
"""

from __future__ import annotations

import difflib
import hashlib
import json
import os
import posixpath
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

SCHEMA = "agw.coding-action/1"
MAX_FILE_BYTES = 1024 * 1024  # larger files: the diff is not computed (the gateway asks)
_URL = re.compile(r"https?://[^\s\"'<>)]+")


@dataclass
class PreAction:
    """One normalized pre-action question plus what travels next to it."""

    action: dict[str, Any]
    diff: str | None = None
    correlation: str | None = None


@dataclass
class HookInput:
    phase: str  # pre | post | session_start | session_end | ignore
    native_session: str = "default"
    cwd: str | None = None
    agent_version: str | None = None
    actions: list[PreAction] = field(default_factory=list)
    # post only
    correlation: str | None = None
    action_type: str | None = None
    success: bool = True
    exit_code: int | None = None
    result_sha256: str | None = None
    files: list[str] = field(default_factory=list)
    duration_ms: int | None = None


def sha256_hex(data: str | bytes) -> str:
    raw = data.encode("utf-8") if isinstance(data, str) else data
    return hashlib.sha256(raw).hexdigest()


def digest_json(value: Any) -> str:
    return sha256_hex(json.dumps(value, sort_keys=True, separators=(",", ":"), default=str))


# --------------------------------------------------------------------------- git
def find_repo_root(start: str | None) -> Path | None:
    p = Path(start or os.getcwd()).resolve()
    for candidate in (p, *p.parents):
        if (candidate / ".git").exists():
            return candidate
    return None


def _git_dir(root: Path) -> Path | None:
    g = root / ".git"
    if g.is_dir():
        return g
    if g.is_file():  # worktree / submodule: "gitdir: <path>"
        text = g.read_text(encoding="utf-8", errors="replace").strip()
        if text.startswith("gitdir:"):
            target = Path(text[7:].strip())
            return target if target.is_absolute() else (root / target).resolve()
    return None


def git_info(root: Path | None) -> dict[str, str]:
    """Remote URL (origin) and HEAD sha, read from files (no subprocess, no network)."""
    if root is None:
        return {}
    gd = _git_dir(root)
    if gd is None:
        return {}
    info: dict[str, str] = {}
    try:
        head = (gd / "HEAD").read_text(encoding="utf-8").strip()
        if head.startswith("ref:"):
            ref = head[4:].strip()
            common = gd
            if (gd / "commondir").is_file():
                common = (gd / (gd / "commondir").read_text().strip()).resolve()
            ref_file = gd / ref if (gd / ref).is_file() else common / ref
            if ref_file.is_file():
                head = ref_file.read_text(encoding="utf-8").strip()
            else:
                packed = common / "packed-refs"
                head = ""
                if packed.is_file():
                    for line in packed.read_text(encoding="utf-8").splitlines():
                        parts = line.split(" ")
                        if len(parts) == 2 and parts[1] == ref:
                            head = parts[0]
        if re.fullmatch(r"[0-9a-f]{40}([0-9a-f]{24})?", head):
            info["head_sha"] = head
        config = gd / "config"
        if not config.is_file() and (gd / "commondir").is_file():
            config = (gd / (gd / "commondir").read_text().strip() / "config").resolve()
        if config.is_file():
            section = ""
            for line in config.read_text(encoding="utf-8", errors="replace").splitlines():
                s = line.strip()
                if s.startswith("["):
                    section = s
                elif section == '[remote "origin"]' and s.startswith("url"):
                    url = s.split("=", 1)[1].strip()
                    info["remote_url"] = re.sub(r"//[^/@]+@", "//", url)  # drop credentials
    except OSError:
        return info
    return info


# --------------------------------------------------------------------------- paths
def rel_path(raw: str, root: Path | None, cwd: str | None) -> str:
    """Repo-relative when inside the workspace, ``~/...`` under home, else absolute.
    Symlinks are resolved when the path exists (a link to ``.env`` is ``.env``)."""
    p = Path(raw).expanduser()
    if not p.is_absolute():
        p = Path(cwd or os.getcwd()) / p
    try:
        resolved = p.resolve(strict=False)
    except (OSError, RuntimeError):
        resolved = Path(posixpath.normpath(str(p)))
    if root is not None:
        try:
            return resolved.relative_to(root.resolve()).as_posix() or "."
        except ValueError:
            pass
    home = Path.home().resolve()
    try:
        return "~/" + resolved.relative_to(home).as_posix()
    except ValueError:
        return resolved.as_posix()


# --------------------------------------------------------------------------- diffs
def _read_text(path: Path) -> str | None:
    try:
        if not path.exists():
            return ""
        if path.stat().st_size > MAX_FILE_BYTES:
            return None
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def unified(path_label: str, old: str, new: str) -> str:
    return "".join(
        difflib.unified_diff(
            old.splitlines(keepends=True),
            new.splitlines(keepends=True),
            fromfile=f"a/{path_label}",
            tofile=f"b/{path_label}",
        )
    )


def write_diff(abs_path: Path, label: str, new_content: str) -> str | None:
    old = _read_text(abs_path)
    if old is None:
        return None
    return unified(label, old, new_content)


def edit_diff(abs_path: Path, label: str, edits: list[tuple[str, str, bool]]) -> str | None:
    """Apply (old_string, new_string, replace_all) edits to the file on disk, diff the result.
    If an old_string is not found, fall back to a diff of the strings themselves."""
    old = _read_text(abs_path)
    if old is None:
        return None
    new = old
    for old_s, new_s, all_ in edits:
        if old_s and old_s in new:
            new = new.replace(old_s, new_s) if all_ else new.replace(old_s, new_s, 1)
        else:
            return unified(label, "".join(o for o, _, _ in edits), "".join(n for _, n, _ in edits))
    return unified(label, old, new)


def urls_in(text: str) -> list[str]:
    return _URL.findall(text or "")


# --------------------------------------------------------------------------- builder
def build(
    *,
    agent_kind: str,
    action_type: str,
    native_tool: str | None,
    cwd: str | None,
    agent_version: str | None = None,
    paths: list[str] | None = None,
    command: str | None = None,
    argv: list[str] | None = None,
    url: str | None = None,
    query: str | None = None,
    mcp: dict[str, str] | None = None,
    diff: str | None = None,
    content_sha256: str | None = None,
    args_sha256: str | None = None,
    incomplete: bool = False,
    workspace_root: Path | None = None,
) -> dict[str, Any]:
    root = workspace_root if workspace_root is not None else find_repo_root(cwd)
    targets: dict[str, Any] = {}
    if paths:
        targets["paths"] = [rel_path(p, root, cwd) for p in paths][:256]
    if command is not None:
        targets["command"] = command
    if argv:
        targets["argv"] = list(argv)
    if url is not None:
        targets["url"] = url
    if query is not None:
        targets["query"] = query[:4096]
    if mcp is not None:
        targets["mcp"] = {k: v[:256] for k, v in mcp.items() if v}
    digests: dict[str, str] = {}
    if diff is not None:
        digests["diff"] = sha256_hex(diff)
    if content_sha256:
        digests["content"] = content_sha256
    if args_sha256:
        digests["args"] = args_sha256
    action: dict[str, Any] = {
        "schema": SCHEMA,
        "agent_kind": agent_kind,
        "action_type": action_type,
        "targets": targets,
        "content_digests": digests,
        "incomplete": incomplete,
    }
    if native_tool:
        action["native_tool"] = native_tool[:256]
    if agent_version and re.fullmatch(r"[A-Za-z0-9._/+\-]{1,64}", agent_version):
        action["agent_version"] = agent_version
    if root is not None:
        action["workspace_root"] = root.as_posix()
        repo = git_info(root)
        if repo:
            action["repo"] = repo
    return action


def fallback_correlation(action: dict[str, Any]) -> str:
    """Pre/post pairing for agents without a tool-use id: the same tool on the same targets."""
    t = action.get("targets", {})
    key = [action.get("action_type"), t.get("paths"), t.get("command"), t.get("url"), t.get("mcp")]
    return "fp:" + digest_json(key)[:40]
