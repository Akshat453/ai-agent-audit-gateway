"""Path normalisation and glob matching for the coding policy. Pure: no I/O.

Paths are POSIX strings in one of three forms:

* repo-relative (``api/src/app.ts``): inside the session's workspace;
* ``~/...``: under the developer's home (the CLI abbreviates the home directory);
* absolute (``/etc/hosts``): anywhere else.

Glob rules (deliberately small and documented in docs/gateway/coding-agents.md §4):

* a pattern without ``/`` matches the **basename** at any depth (``*.pem``, ``CODEOWNERS``);
* a pattern starting with ``**/`` matches at any depth, including inside absolute paths;
* any other pattern is anchored at the start of the path;
* ``**`` spans path segments, ``*`` and ``?`` stay inside one segment;
* matching is **case-insensitive** (macOS and Windows file systems are, and a policy that
  misses ``.ENV`` would be bypassable). This can only over-match, never under-match.
"""

from __future__ import annotations

import posixpath
import re
from collections.abc import Iterable
from functools import lru_cache
from typing import Final

MAX_PATH_LEN: Final = 4096


class PathInvalid(ValueError):
    """A path the policy refuses to interpret (NUL byte, too long, empty)."""


def normalize_path(raw: str, workspace_root: str | None) -> str:
    """Normalise a target path to the policy's canonical form (see module docstring).

    ``..`` segments are resolved lexically; a relative path that escapes the workspace
    becomes absolute (joined to the workspace root), so ``../../.ssh/id_rsa`` cannot hide.
    """
    if not raw or "\x00" in raw or len(raw) > MAX_PATH_LEN:
        raise PathInvalid("path")
    path = raw.strip().replace("\\", "/")
    if path.startswith("~/") or path == "~":
        return posixpath.normpath(path)
    root = posixpath.normpath(workspace_root.replace("\\", "/")) if workspace_root else None
    if not path.startswith("/"):
        if root is None:
            norm = posixpath.normpath(path)
            if norm == ".." or norm.startswith("../"):
                return "/" + norm  # unknown root: an escaping path is treated as outside
            return norm
        path = posixpath.join(root, path)
    norm = posixpath.normpath(path)
    if norm.startswith("//"):  # POSIX allows a leading '//'; collapse it
        norm = "/" + norm.lstrip("/")
    if root is not None and (norm == root or norm.startswith(root.rstrip("/") + "/")):
        rel = posixpath.relpath(norm, root)
        return "." if rel == "." else rel
    return norm


def is_outside(path: str) -> bool:
    """True for ``~/...`` and absolute paths (outside the workspace)."""
    return path.startswith(("/", "~"))


@lru_cache(maxsize=1024)
def _compile(pattern: str) -> re.Pattern[str]:
    pat = pattern.replace("\\", "/")
    anywhere = False
    if pat.startswith("**/"):
        anywhere = True
        pat = pat[3:]
    out: list[str] = []
    i = 0
    while i < len(pat):
        c = pat[i]
        if pat.startswith("**/", i):
            out.append("(?:[^/]*/)*")
            i += 3
            continue
        if pat.startswith("**", i):
            out.append(".*")
            i += 2
            continue
        if c == "*":
            out.append("[^/]*")
        elif c == "?":
            out.append("[^/]")
        else:
            out.append(re.escape(c))
        i += 1
    body = "".join(out)
    prefix = "(?:.*/)?" if anywhere else ""
    return re.compile(f"^{prefix}{body}$", re.IGNORECASE)


def glob_match(path: str, pattern: str) -> bool:
    if "/" not in pattern:
        return _compile(pattern).match(posixpath.basename(path)) is not None
    return _compile(pattern).match(path) is not None


def first_match(path: str, patterns: Iterable[str]) -> str | None:
    for p in patterns:
        if glob_match(path, p):
            return p
    return None
