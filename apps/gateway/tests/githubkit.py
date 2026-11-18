"""C3 test kit: local bare git repositories standing in for github.com, and a stateful fake of
the GitHub REST API behind SafeHttp (no network)."""

from __future__ import annotations

import json
import os
import re
import subprocess
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx

from agw_gateway.connectors.ssrf import SafeHttp

REPO = "Akshat453/MintRail"
TOKEN = "ghs_FAKE_INSTALLATION_TOKEN_never_logged_1234567890"
ENV = {
    **os.environ,
    "GIT_CONFIG_GLOBAL": os.devnull,
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_AUTHOR_NAME": "dev",
    "GIT_AUTHOR_EMAIL": "dev@example.com",
    "GIT_COMMITTER_NAME": "dev",
    "GIT_COMMITTER_EMAIL": "dev@example.com",
}


def git(cwd: Path, *args: str, input_bytes: bytes | None = None) -> str:
    r = subprocess.run(
        ["git", *args], cwd=cwd, env=ENV, input=input_bytes, capture_output=True, check=True
    )
    return r.stdout.decode()


SEED = {
    "README.md": "# MintRail\n",
    "api/src/csv.ts": "export const a = 1;\n",
    "api/src/old_name.ts": "export const keep = true;\n",
    "api/test/fees.test.ts": 'it("charges bps", () => {});\n',
    "ledger/src/service.ts": "export const post = 1;\n",
    ".github/workflows/ci.yml": "jobs:\n  test:\n    steps:\n      - run: pnpm test\n",
    "signal/src/verify.ts": "export function verifyWebhook() { return signatures.verify(a, b, c); }\n",
}


@dataclass
class LocalGithub:
    """``<root>/<owner>/<name>.git`` bare repo + a working clone to make 'manual' commits."""

    root: Path
    work: Path

    @property
    def bare(self) -> Path:
        return self.root / f"{REPO}.git"

    def ref(self, branch: str) -> str | None:
        r = subprocess.run(
            ["git", "rev-parse", "--verify", "-q", f"refs/heads/{branch}"],
            cwd=self.bare,
            env=ENV,
            capture_output=True,
        )
        return r.stdout.decode().strip() or None

    def main(self) -> str:
        sha = self.ref("main")
        assert sha
        return sha

    def commits(self, base: str, head: str) -> list[str]:
        return git(self.bare, "rev-list", "--reverse", f"{base}..{head}").split()

    def manual_push(self, branch: str, path: str, text: str) -> str:
        git(self.work, "fetch", "-q", "origin")
        git(self.work, "checkout", "-q", "-B", branch, f"origin/{branch}")
        (self.work / path).parent.mkdir(parents=True, exist_ok=True)
        (self.work / path).write_text(text)
        git(self.work, "add", "-A")
        git(self.work, "commit", "-q", "-m", "manual change")
        git(self.work, "push", "-q", "origin", f"HEAD:refs/heads/{branch}")
        return git(self.work, "rev-parse", "HEAD").strip()


def make_local(tmp: Path) -> LocalGithub:
    root = tmp / "gh"
    bare = root / f"{REPO}.git"
    bare.parent.mkdir(parents=True)
    git(root, "init", "-q", "--bare", "-b", "main", str(bare))
    work = tmp / "work"
    git(tmp, "clone", "-q", str(bare), str(work))
    for rel, text in SEED.items():
        (work / rel).parent.mkdir(parents=True, exist_ok=True)
        (work / rel).write_text(text)
    (work / "assets").mkdir()
    (work / "assets/logo.bin").write_bytes(bytes(range(256)))
    git(work, "checkout", "-q", "-b", "main")
    git(work, "add", "-A")
    git(work, "commit", "-q", "-m", "seed")
    git(work, "push", "-q", "origin", "main")
    return LocalGithub(root, work)


def local_diff(lg: LocalGithub, edit: Callable[[Path], None]) -> tuple[str, bytes]:
    """Make an edit in a scratch clone at main and return (base_sha, `git diff --binary`)."""
    scratch = lg.root.parent / f"scratch-{os.urandom(4).hex()}"
    git(lg.root.parent, "clone", "-q", str(lg.bare), str(scratch))
    base = git(scratch, "rev-parse", "HEAD").strip()
    edit(scratch)
    git(scratch, "add", "-A")
    return base, git(scratch, "diff", "--cached", "--binary", "-M", base).encode()


def local_bundle(
    lg: LocalGithub, edit: Callable[[Path], None], message: str = "agent commit", stage: bool = True
) -> tuple[str, bytes]:
    scratch = lg.root.parent / f"scratch-{os.urandom(4).hex()}"
    git(lg.root.parent, "clone", "-q", str(lg.bare), str(scratch))
    base = git(scratch, "rev-parse", "HEAD").strip()
    edit(scratch)
    if stage:
        git(scratch, "add", "-A")
    git(scratch, "commit", "-q", "-m", message)
    out = subprocess.run(
        ["git", "bundle", "create", "-", f"{base}..HEAD"],
        cwd=scratch,
        env=ENV,
        capture_output=True,
        check=True,
    ).stdout
    return base, out


@dataclass
class FakeGithub:
    """Stateful fake of the GitHub REST API, reading git state from the local bare repo."""

    lg: LocalGithub
    issues: dict[int, dict[str, Any]] = field(
        default_factory=lambda: {
            7: {
                "number": 7,
                "title": "Refund rounding",
                "body": "Fix rounding",
                "state": "open",
                "labels": [{"name": "bug"}],
                "user": {"login": "akshat"},
                "html_url": "https://github.com/x/7",
            }
        }
    )
    prs: dict[int, dict[str, Any]] = field(default_factory=dict)
    checks: dict[int, dict[str, Any]] = field(default_factory=dict)
    comments: list[tuple[int, str]] = field(default_factory=list)
    token_requests: list[dict[str, Any]] = field(default_factory=list)
    seen: list[httpx.Request] = field(default_factory=list)
    protected: set[str] = field(default_factory=lambda: {"main"})
    extra_commits: int = 0  # simulate commits GitHub counts but the listing does not return

    def handler(self, r: httpx.Request) -> httpx.Response:
        self.seen.append(r)
        if r.headers.get("host") != "api.github.com":
            return httpx.Response(404)
        p, m = r.url.path, r.method
        body = json.loads(r.content) if r.content else {}
        if re.fullmatch(r"/app/installations/\d+/access_tokens", p) and m == "POST":
            assert r.headers["authorization"].startswith("Bearer ey")  # the App JWT
            self.token_requests.append(body)
            return httpx.Response(
                201,
                json={
                    "token": TOKEN,
                    "expires_at": "2099-01-01T00:00:00Z",
                    "repositories": [{"full_name": REPO}],
                },
            )
        if r.headers.get("authorization") != f"Bearer {TOKEN}":
            return httpx.Response(401, json={"message": "Bad credentials"})
        base = f"/repos/{REPO}"
        if not p.startswith(base):
            return httpx.Response(404, json={"message": "Not Found"})
        p = p[len(base) :]
        if m == "GET" and (mt := re.fullmatch(r"/issues/(\d+)", p)):
            issue = self.issues.get(int(mt.group(1)))
            return httpx.Response(200, json=issue) if issue else httpx.Response(404)
        if m == "GET" and p == "/issues":
            return httpx.Response(200, json=list(self.issues.values()))
        if m == "POST" and (mt := re.fullmatch(r"/issues/(\d+)/comments", p)):
            self.comments.append((int(mt.group(1)), body["body"]))
            return httpx.Response(
                201, json={"id": len(self.comments), "html_url": "https://github.com/c"}
            )
        if m == "GET" and (mt := re.fullmatch(r"/rules/branches/(.+)", p)):
            name = mt.group(1).replace("%2F", "/")
            rules = (
                [{"type": "pull_request"}, {"type": "required_status_checks"}]
                if name in self.protected
                else []
            )
            return httpx.Response(200, json=rules)
        if m == "GET" and (mt := re.fullmatch(r"/branches/(.+)", p)):
            name = mt.group(1).replace("%2F", "/")
            sha = self.lg.ref(name)
            if sha is None:
                return httpx.Response(404)
            return httpx.Response(
                200,
                json={"name": name, "commit": {"sha": sha}, "protected": name in self.protected},
            )
        if m == "POST" and p == "/pulls":
            n = 100 + len(self.prs)
            self.prs[n] = {
                "number": n,
                "head_ref": body["head"],
                "base": body["base"],
                "state": "open",
                "body": body["body"],
                "title": body["title"],
                "fork": False,
            }
            return httpx.Response(201, json=self._pr(n))
        if m == "GET" and p == "/pulls":
            return httpx.Response(
                200, json=[self._pr(n) for n, x in self.prs.items() if x["state"] == "open"]
            )
        if m == "GET" and (mt := re.fullmatch(r"/pulls/(\d+)", p)):
            return httpx.Response(200, json=self._pr(int(mt.group(1))))
        if m == "GET" and (mt := re.fullmatch(r"/pulls/(\d+)/commits", p)):
            pr = self.prs[int(mt.group(1))]
            head = self.lg.ref(pr["head_ref"]) or ""
            per, page = int(r.url.params.get("per_page", 30)), int(r.url.params.get("page", 1))
            shas = self.lg.commits(self.lg.main(), head)[(page - 1) * per : page * per]
            return httpx.Response(200, json=[{"sha": s} for s in shas])
        if m == "POST" and p == "/check-runs":
            cid = 9000 + len(self.checks)
            self.checks[cid] = dict(body)
            return httpx.Response(201, json={"id": cid})
        if m == "PATCH" and (mt := re.fullmatch(r"/check-runs/(\d+)", p)):
            self.checks[int(mt.group(1))].update(body)
            return httpx.Response(200, json={"id": int(mt.group(1))})
        return httpx.Response(404, json={"message": f"unmocked {m} {p}"})

    def _pr(self, n: int) -> dict[str, Any]:
        pr = self.prs[n]
        repo = "someone/fork" if pr["fork"] else REPO
        return {
            "number": n,
            "state": pr["state"],
            "merged": False,
            "commits": len(self.lg.commits(self.lg.main(), self.lg.ref(pr["head_ref"]) or ""))
            + self.extra_commits,
            "html_url": f"https://github.com/{REPO}/pull/{n}",
            "head": {
                "sha": self.lg.ref(pr["head_ref"]),
                "ref": pr["head_ref"],
                "repo": {"full_name": repo},
            },
            "base": {"ref": pr["base"]},
        }

    def latest_check(self, pr_number: int) -> dict[str, Any]:
        head = self._pr(pr_number)["head"]["sha"]
        mine = [
            c for c in self.checks.values() if c.get("head_sha") == head or c.get("_head") == head
        ]
        return mine[-1] if mine else {}

    def http(self) -> SafeHttp:
        return SafeHttp(
            resolver=lambda h, p: ["140.82.112.6"], transport=httpx.MockTransport(self.handler)
        )
