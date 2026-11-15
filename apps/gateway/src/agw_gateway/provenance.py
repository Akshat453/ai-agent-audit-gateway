"""Code provenance (Paper B field 7): which gateway build recorded the evidence."""

from __future__ import annotations

import shutil
import subprocess
from functools import lru_cache
from pathlib import Path


@lru_cache(maxsize=1)
def resolve_build_commit(configured: str | None = None) -> str:
    """``AGW_BUILD_COMMIT`` if set (container builds), else ``git rev-parse HEAD`` of the
    source tree with ``+dirty`` for uncommitted changes, else ``"unknown"``."""
    if configured:
        return configured
    git = shutil.which("git")
    if git is None:
        return "unknown"
    here = Path(__file__).resolve().parent
    try:
        commit = subprocess.run(  # noqa: S603 - fixed argv, no shell
            [git, "rev-parse", "HEAD"],
            cwd=here,
            capture_output=True,
            text=True,
            timeout=2,
            check=True,
        ).stdout.strip()
        dirty = subprocess.run(  # noqa: S603
            [git, "status", "--porcelain", "--untracked-files=no"],
            cwd=here,
            capture_output=True,
            text=True,
            timeout=2,
            check=True,
        ).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return "unknown"
    return f"{commit[:40]}+dirty" if dirty else commit[:40]
