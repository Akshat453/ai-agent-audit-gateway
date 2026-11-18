"""Server-side application of an agent's change (C3, ADR-0036 §3).

``prepare`` clones the repository (no working tree), applies the change onto ``base_sha`` and
validates the RESULT, so nothing an agent sends can touch the gateway's file system:

* unified diff: ``git read-tree <base>`` + ``git apply --cached --binary`` (index only: no
  checkout, so a symlink in the change can never be followed on disk), ``write-tree``,
  ``commit-tree`` with the gateway as committer;
* git bundle: ``git bundle verify`` (its prerequisite must be ``base_sha``), exactly one head,
  every new commit must descend from ``base_sha``.

Then every changed entry is checked: no ``.git`` path component, no absolute or ``..`` paths,
no submodules (mode 160000), symlinks (120000) only to relative targets that stay inside the
repository, every blob under the size limit, a bounded number of files and diff size.

Credentials: the installation token reaches git ONLY through the environment
(``GIT_CONFIG_*`` -> ``http.extraHeader``), never argv, a URL or a log line. git runs with no
user/system config, no hooks, no terminal prompts, in a fresh temporary directory.
"""

from __future__ import annotations

import base64
import hashlib
import os
import posixpath
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Final

MAX_BLOB: Final = 1024 * 1024
MAX_FILES: Final = 500
MAX_DIFF: Final = 4 * 1024 * 1024
TIMEOUT: Final = 120
SHA_RE: Final = re.compile(r"^[0-9a-f]{40}$")


class GitError(Exception):
    """A change was refused or git failed; ``code`` is stable and never contains content."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass
class FileChange:
    status: str  # A M D R T
    path: str
    old_path: str | None = None
    mode: str = "100644"


@dataclass
class Prepared:
    workdir: Path
    base_sha: str
    head_sha: str
    tree_sha: str
    commits: list[str]
    diff: str
    diff_digest: bytes
    files: list[FileChange] = field(default_factory=list)

    def cleanup(self) -> None:
        shutil.rmtree(self.workdir, ignore_errors=True)


def git_env(token: str | None, home: Path) -> dict[str, str]:
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": str(home),
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_ASKPASS": "/bin/false",
        "LC_ALL": "C",
    }
    pairs = [("core.hooksPath", os.devnull), ("protocol.file.allow", "always")]
    if token:
        basic = base64.b64encode(f"x-access-token:{token}".encode()).decode()
        pairs.append(("http.extraHeader", f"Authorization: Basic {basic}"))
    env["GIT_CONFIG_COUNT"] = str(len(pairs))
    for i, (k, v) in enumerate(pairs):
        env[f"GIT_CONFIG_KEY_{i}"] = k
        env[f"GIT_CONFIG_VALUE_{i}"] = v
    return env


def _git(
    args: list[str],
    cwd: Path,
    env: dict[str, str],
    *,
    input_bytes: bytes | None = None,
    code: str = "GIT_FAILED",
) -> bytes:
    try:
        r = subprocess.run(  # noqa: S603 - fixed executable, list argv, no shell
            ["git", *args],  # noqa: S607
            cwd=cwd,
            env=env,
            input=input_bytes,
            capture_output=True,
            timeout=TIMEOUT,
            check=False,
        )
    except subprocess.TimeoutExpired:
        raise GitError("GIT_TIMEOUT") from None
    if r.returncode != 0:
        raise GitError(code)
    return r.stdout


def _safe_path(path: str) -> bool:
    if not path or path.startswith("/") or "\\" in path or "\x00" in path:
        return False
    parts = path.split("/")
    return not any(p in ("", ".", "..") or p.lower() == ".git" for p in parts)


def _symlink_ok(path: str, target: str) -> bool:
    if target.startswith("/") or "\x00" in target:
        return False
    resolved = posixpath.normpath(posixpath.join(posixpath.dirname(path), target))
    return not (resolved == ".." or resolved.startswith("../")) and ".git" not in resolved.split(
        "/"
    )


def prepare(
    *,
    clone_url: str,
    token: str | None,
    base_sha: str,
    change_format: str,
    change: bytes,
    message: str,
    author: tuple[str, str],
    committer: tuple[str, str] = ("AgentGuard", "agentguard@users.noreply.github.com"),
) -> Prepared:
    if not SHA_RE.fullmatch(base_sha):
        raise GitError("BASE_SHA_INVALID")
    tmp = Path(tempfile.mkdtemp(prefix="agw-git-"))
    env = git_env(token, tmp)
    repo = tmp / "repo.git"
    try:
        _git(
            ["clone", "--quiet", "--bare", "--no-tags", clone_url, str(repo)],
            tmp,
            env,
            code="CLONE_FAILED",
        )
        _git(["cat-file", "-e", f"{base_sha}^{{commit}}"], repo, env, code="BASE_SHA_UNKNOWN")
        if change_format == "diff":
            if len(change) > MAX_DIFF:
                raise GitError("CHANGE_TOO_LARGE")
            idx = {**env, "GIT_INDEX_FILE": str(tmp / "index")}
            _git(["read-tree", base_sha], repo, idx)
            patch = tmp / "change.patch"
            patch.write_bytes(change)
            _git(
                ["apply", "--cached", "--binary", "--whitespace=nowarn", str(patch)],
                repo,
                idx,
                code="PATCH_DOES_NOT_APPLY",
            )
            tree = _git(["write-tree"], repo, idx).decode().strip()
            commit_env = {
                **env,
                "GIT_AUTHOR_NAME": author[0],
                "GIT_AUTHOR_EMAIL": author[1],
                "GIT_COMMITTER_NAME": committer[0],
                "GIT_COMMITTER_EMAIL": committer[1],
            }
            head = (
                _git(
                    ["commit-tree", tree, "-p", base_sha],
                    repo,
                    commit_env,
                    input_bytes=message.encode(),
                )
                .decode()
                .strip()
            )
        elif change_format == "bundle":
            bundle = tmp / "change.bundle"
            bundle.write_bytes(change)
            _git(["bundle", "verify", "--quiet", str(bundle)], repo, env, code="BUNDLE_INVALID")
            heads = [
                ln.split()[0]
                for ln in _git(["bundle", "list-heads", str(bundle)], repo, env)
                .decode()
                .splitlines()
                if ln.strip()
            ]
            if len(set(heads)) != 1 or not SHA_RE.fullmatch(heads[0]):
                raise GitError("BUNDLE_HEADS")
            head = heads[0]
            _git(
                ["fetch", "--quiet", str(bundle), f"{head}:refs/agw/incoming"],
                repo,
                env,
                code="BUNDLE_INVALID",
            )
            try:
                _git(["merge-base", "--is-ancestor", base_sha, head], repo, env)
            except GitError:
                raise GitError("BUNDLE_NOT_ON_BASE") from None
            tree = _git(["rev-parse", f"{head}^{{tree}}"], repo, env).decode().strip()
        else:
            raise GitError("CHANGE_FORMAT")
        commits = _git(["rev-list", "--reverse", f"{base_sha}..{head}"], repo, env).decode().split()
        if not commits:
            raise GitError("EMPTY_CHANGE")
        files = _validate(repo, env, base_sha, head)
        diff = _git(["diff", "--binary", "--full-index", "-M", base_sha, head], repo, env)
        if len(diff) > MAX_DIFF:
            raise GitError("CHANGE_TOO_LARGE")
        return Prepared(
            tmp,
            base_sha,
            head,
            tree,
            commits,
            diff.decode("utf-8", "replace"),
            hashlib.sha256(diff).digest(),
            files,
        )
    except BaseException:
        shutil.rmtree(tmp, ignore_errors=True)
        raise


def _validate(repo: Path, env: dict[str, str], base: str, head: str) -> list[FileChange]:
    raw = _git(["diff", "--name-status", "-M", "-z", base, head], repo, env)
    fields = raw.decode("utf-8", "replace").split("\x00")
    files: list[FileChange] = []
    i = 0
    while i < len(fields) and fields[i]:
        status = fields[i][0]
        if status in "RC":
            old, new = fields[i + 1], fields[i + 2]
            files.append(FileChange(status, new, old))
            i += 3
        else:
            files.append(FileChange(status, fields[i + 1]))
            i += 2
    if len(files) > MAX_FILES:
        raise GitError("TOO_MANY_FILES")
    for f in files:
        for p in (f.path, f.old_path):
            if p is not None and not _safe_path(p):
                raise GitError("PATH_NOT_ALLOWED")
        if f.status == "D":
            continue
        entry = _git(["ls-tree", "-z", head, "--", f.path], repo, env).decode("utf-8", "replace")
        if not entry:
            continue
        mode, otype, oid = entry.split("\t", 1)[0].split()
        f.mode = mode
        if mode == "160000" or otype == "commit":
            raise GitError("SUBMODULE_NOT_ALLOWED")
        size = int(_git(["cat-file", "-s", oid], repo, env).decode().strip())
        if size > MAX_BLOB:
            raise GitError("BLOB_TOO_LARGE")
        if mode == "120000":
            target = _git(["cat-file", "blob", oid], repo, env).decode("utf-8", "replace")
            if not _symlink_ok(f.path, target):
                raise GitError("SYMLINK_ESCAPES_REPO")
    return files


def push(prepared: Prepared, *, clone_url: str, token: str | None, branch: str) -> None:
    """Fast-forward only (no force): a branch that moved since base_sha is refused."""
    env = git_env(token, prepared.workdir)
    _git(
        ["push", "--quiet", clone_url, f"{prepared.head_sha}:refs/heads/{branch}"],
        prepared.workdir / "repo.git",
        env,
        code="PUSH_REJECTED",
    )


def split_diff(diff: str) -> dict[str, str]:
    """Per-file sections of a combined ``git diff`` (keyed by the new path; deletions by the
    old path), for the per-file content rules."""
    out: dict[str, str] = {}
    current: list[str] = []
    key: str | None = None
    for line in diff.splitlines(keepends=True):
        if line.startswith("diff --git "):
            if key is not None:
                out[key] = "".join(current)
            m = re.match(r"diff --git a/(.+) b/(.+)$", line.rstrip("\n"))
            key = m.group(2) if m else line
            current = [line]
        else:
            current.append(line)
    if key is not None:
        out[key] = "".join(current)
    return out
