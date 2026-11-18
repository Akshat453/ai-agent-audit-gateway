"""C3 LIVE acceptance against github.com (Akshat453/MintRail). Skipped unless AGW_GITHUB_LIVE=1.

Runs against a gateway that is ALREADY configured by the owner (docs/gateway/github-app-setup.md):
the GitHub connector exists, its actions are classified, the App is installed on the repo, and
webhooks (or polling) reach the gateway. Inputs (environment, never committed):

    AGW_GITHUB_LIVE=1
    AGW_LIVE_GATEWAY=https://<gateway>            AGW_LIVE_DEVICE_KEY_FILE=<0600 file>
    AGW_LIVE_SLUG=gh                              AGW_LIVE_ISSUE=<an open issue number>
    AGW_LIVE_MINTRAIL=<a local clone of Akshat453/MintRail used to build the diff>

Scripted session: read the issue, submit a one-line doc change on fix/MR-<issue>-agw-live-<n>,
open a PR, wait for the "AgentGuard evidence" check -> success; then push a commit DIRECTLY to
the PR branch with the owner's own git credentials -> the check becomes failure.
"""

from __future__ import annotations

import base64
import json
import os
import subprocess
import time
import urllib.request
import uuid
from pathlib import Path
from typing import Any

import pytest

pytestmark = [
    pytest.mark.e2e,
    pytest.mark.skipif(
        os.environ.get("AGW_GITHUB_LIVE") != "1", reason="live GitHub test (AGW_GITHUB_LIVE=1)"
    ),
]


def _req(method: str, path: str, body: Any = None) -> Any:
    key = Path(os.environ["AGW_LIVE_DEVICE_KEY_FILE"]).read_text().strip()
    req = urllib.request.Request(
        os.environ["AGW_LIVE_GATEWAY"].rstrip("/") + path,
        method=method,
        data=json.dumps(body).encode() if body is not None else None,
        headers={
            "Authorization": f"Bearer {key}",
            "Content-Type": "application/json",
            "Idempotency-Key": f"live-{uuid.uuid4().hex}",
        },
    )
    with urllib.request.urlopen(req, timeout=120) as r:
        return json.loads(r.read())


def _action(tool: str, args: dict[str, Any], run: str) -> dict[str, Any]:
    slug = os.environ.get("AGW_LIVE_SLUG", "gh")
    res = _req(
        "POST",
        "/v1/actions",
        {"run_id": run, "tool": f"cx_{slug}_{tool}", "environment": "dev", "args": args},
    )
    assert res["status"] in ("AUTHORIZED", "PENDING_APPROVAL"), res
    for _ in range(120):
        view = _req("GET", f"/v1/actions/{res['action_id']}?wait=10")
        if view["status"] in ("COMPLETED", "FAILED", "DENIED", "EXPIRED"):
            assert view["status"] == "COMPLETED", view
            return dict(view["result"] or {})
    raise AssertionError("action did not finish (approval pending?)")


def test_live_issue_submit_pr_check() -> None:
    run = str(uuid.uuid4())
    issue = int(os.environ["AGW_LIVE_ISSUE"])
    got = _action("github_issue_get", {"number": issue}, run)
    assert got["number"] == issue
    repo = Path(os.environ["AGW_LIVE_MINTRAIL"])
    subprocess.run(["git", "fetch", "-q", "origin", "main"], cwd=repo, check=True)
    base = subprocess.run(
        ["git", "rev-parse", "origin/main"], cwd=repo, check=True, capture_output=True, text=True
    ).stdout.strip()
    stamp = int(time.time())
    patch = (
        f"diff --git a/docs/agentguard-live.md b/docs/agentguard-live.md\nnew file mode 100644\n"
        f"--- /dev/null\n+++ b/docs/agentguard-live.md\n@@ -0,0 +1 @@\n+AgentGuard live test {stamp}\n"
    )
    branch = f"fix/MR-{issue}-agw-live-{stamp}"
    sub = _action(
        "git_submit_change",
        {
            "session_id": f"live-{stamp}",
            "issue_number": issue,
            "branch": branch,
            "base_sha": base,
            "commit_message": f"MR-{issue}: AgentGuard live test",
            "change_format": "diff",
            "change": base64.b64encode(patch.encode()).decode(),
        },
        run,
    )
    assert sub["commits"]
    pr = _action(
        "github_pr_create",
        {"branch": branch, "title": f"AgentGuard live test {stamp}", "issue_number": issue},
        run,
    )
    number = pr["number"]
    for _ in range(60):  # sealing + monitor verification can take a few minutes
        st = _action("github_pr_status", {"number": number}, run)
        if st["check"] in ("success", "failure"):
            break
        time.sleep(15)
    assert st["check"] == "success", st
    # A manual push with the OWNER's credentials (not the gateway) -> failure.
    subprocess.run(["git", "fetch", "-q", "origin", branch], cwd=repo, check=True)
    subprocess.run(
        ["git", "checkout", "-q", "-B", f"agw-live-{stamp}", f"origin/{branch}"],
        cwd=repo,
        check=True,
    )
    (repo / "docs/agentguard-live.md").write_text(f"manual edit {stamp}\n")
    subprocess.run(
        ["git", "commit", "-qam", "manual push (must fail the check)"], cwd=repo, check=True
    )
    subprocess.run(
        ["git", "push", "-q", "origin", f"HEAD:refs/heads/{branch}"], cwd=repo, check=True
    )
    for _ in range(20):
        time.sleep(15)
        st = _action("github_pr_status", {"number": number}, run)
        if st["check"] == "failure":
            break
    assert st["check"] == "failure", st
