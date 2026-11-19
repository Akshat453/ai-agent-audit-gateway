"""C3 mocked end to end (ADR-0036): GitHub connector actions through identity -> risk ->
policy -> approval -> evidence; git_submit_change with server-side apply + full-diff policy +
push; PR body; the "AgentGuard evidence" check (success / failure matrix, forged webhook,
polling, tamper flip + comment); installation tokens never leaked; dev-tools over MCP."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import uuid
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import Engine, select, text

from agw_gateway.db import tables as t
from agw_gateway.enrollment import enroll_device
from agw_gateway.github import actions as gh_actions
from agw_gateway.github.client import forget_token
from agw_worker.monitoring.monitor import Monitor, MonitorConfig
from tests.anchorkit import sealer
from tests.approvalkit import decide as approve
from tests.approvalkit import make_humans
from tests.e2e.test_monitoring import su
from tests.githubkit import (
    REPO,
    TOKEN,
    FakeGithub,
    LocalGithub,
    local_bundle,
    local_diff,
    make_local,
)

pytestmark = pytest.mark.e2e
WEBHOOK_SECRET = "whsec-test-only-0001"


def _pem() -> str:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    ).decode()


@pytest.fixture
def env(gw: Any, migrator_engine: Engine, tmp_path: Path) -> Any:
    lg = make_local(tmp_path)
    fake = FakeGithub(lg)
    gw.state.connectors.http = fake.http()
    gh_actions.CLONE_ROOT[0] = lg.root
    h = make_humans(migrator_engine, gw.client, gw.world.tenant_id)
    from agw_gateway.admin import ensure_human
    from tests.approvalkit import PASSWORD

    for name, roles in (
        ("lead", ["ledger_lead"]),
        ("sec1", ["security"]),
        ("sec2", ["security"]),
        ("maint", ["maintainer"]),
    ):
        ensure_human(migrator_engine, gw.world.tenant_id, name, PASSWORD, roles)
        r = gw.client.post(
            "/v1/auth/login",
            json={"tenant": gw.world.tenant_id, "username": name, "password": PASSWORD},
        )
        h.sessions[name] = r.json()["session_token"]
        gw.client.post("/v1/auth/step-up", json={"password": PASSWORD}, headers=h.headers(name))
    with gw.engine.begin() as conn:
        _agent, device_key = enroll_device(
            conn,
            gw.state.writer,
            tenant=gw.world.tenant_id,
            human_id=uuid.UUID(h.ids["alice"]),
            label="laptop",
            agent_kind="claude_code",
            via="admin",
        )
    r = gw.client.post(
        "/v1/connectors",
        headers=h.headers("adam"),
        json={
            "type_id": "github",
            "slug": "gh",
            "name": "GitHub",
            "config": {
                "owner_type": "user",
                "owner": "Akshat453",
                "app_id": 4711,
                "client_id": "Iv1.test",
                "installation_ids": [31337],
                "repos": [REPO],
                "mode": "polling",
                "protected_branches": ["main", "master", "fix/MR-7-release"],
            },
            "credentials": {"pem": _pem(), "webhook_secret": WEBHOOK_SECRET},
        },
    )
    assert r.status_code == 201, r.text
    cid = r.json()["connector_id"]
    yield {"lg": lg, "fake": fake, "h": h, "key": device_key, "cid": cid}
    # Isolation: the worker polls EVERY tenant's GitHub connectors; stop this one.
    gw.client.post(f"/v1/connectors/{cid}/disable", headers=h.headers("adam"))
    gh_actions.CLONE_ROOT[0] = None
    forget_token(cid)


def call(
    gw: Any, e: Any, action: str, args: dict[str, Any], run: str | None = None
) -> dict[str, Any]:
    r = gw.post(
        f"cx_gh_{action}",
        args,
        token=e["key"],
        env="dev",
        run_id=run or e.setdefault("run", str(uuid.uuid4())),
    )
    assert r.status_code in (200, 201), r.text
    return dict(r.json())


def result(gw: Any, action_id: str) -> Any:
    gw.drain()
    with gw.engine.connect() as conn:
        return conn.execute(
            select(t.actions.c.status, t.actions.c.result_public, t.actions.c.error_code).where(
                t.actions.c.action_id == uuid.UUID(action_id)
            )
        ).one()


def b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode()


def submit(
    gw: Any,
    e: Any,
    edit: Any,
    branch: str = "fix/MR-7-rounding",
    fmt: str = "diff",
    base: str | None = None,
) -> dict[str, Any]:
    lg: LocalGithub = e["lg"]
    if fmt == "diff":
        b, change = local_diff(lg, edit)
    else:
        b, change = local_bundle(lg, edit)
    return call(
        gw,
        e,
        "git_submit_change",
        {
            "session_id": "sess-abc",
            "issue_number": 7,
            "branch": branch,
            "base_sha": base or b,
            "commit_message": "MR-7: fix rounding",
            "change_format": fmt,
            "change": b64(change),
        },
    )


def verify(gw: Any) -> Any:
    sealer(gw).drain()
    m = Monitor(
        engine=gw.engine, writer=gw.state.writer, config=MonitorConfig(alert_cooldown_seconds=0)
    )
    m.on_report = lambda rep: gw.state.github_checks.on_monitor_report(
        rep.tenant, rep.result, rep.report_id
    )
    return m.run_once([gw.world.tenant_id])[0]


def signed(body: dict[str, Any], secret: str = WEBHOOK_SECRET) -> tuple[bytes, dict[str, str]]:
    raw = json.dumps(body).encode()
    sig = "sha256=" + hmac.new(secret.encode(), raw, hashlib.sha256).hexdigest()
    return raw, {
        "X-Hub-Signature-256": sig,
        "X-GitHub-Event": "pull_request",
        "X-GitHub-Delivery": str(uuid.uuid4()),
        "Content-Type": "application/json",
    }


def test_full_flow_check_success_then_manual_push_fails(
    gw: Any, env: Any, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG)
    e, fake, h = env, env["fake"], env["h"]
    cid = e["cid"]
    # Unclassified until the admin accepts the proposal (a new policy version).
    denied = call(gw, e, "github_issue_get", {"number": 7})
    assert denied["decision"]["reasons"] == ["CONNECTOR_ACTION_UNCLASSIFIED"]
    detail = gw.client.get(f"/v1/connectors/{cid}", headers=h.headers("adam")).json()
    assert {a["name"]: a["proposed"]["risk"] for a in detail["actions"]}[
        "git_submit_change"
    ] == "MEDIUM"
    acc = gw.client.post(
        f"/v1/connectors/{cid}/classify-proposed", headers=h.headers("adam")
    ).json()
    assert len(acc["changed"]) == 7 and acc["policy_version"] == 1
    # Reads.
    issue = call(gw, e, "github_issue_get", {"number": 7})
    assert issue["status"] == "AUTHORIZED", issue
    r = result(gw, issue["action_id"])
    assert r.status == "COMPLETED" and r.result_public["title"] == "Refund rounding"
    assert fake.token_requests == [{"repositories": ["MintRail"]}]  # scoped to the configured repo
    other = call(gw, e, "github_issue_get", {"number": 7, "repo": "someone/else"})
    assert result(gw, other["action_id"]).status == "FAILED"  # only the configured repos
    assert not any("someone/else" in r_.url.path for r_ in e["fake"].seen)
    lst = call(gw, e, "github_issue_list", {"state": "open"})
    assert result(gw, lst["action_id"]).result_public["issues"][0]["number"] == 7
    # A normal change: MEDIUM -> no approval; applied server-side and pushed.
    sub = submit(gw, e, lambda w: (w / "api/src/csv.ts").write_text("export const a = 2;\n"))
    assert sub["status"] == "AUTHORIZED", sub["decision"]
    rs = result(gw, sub["action_id"])
    assert rs.status == "COMPLETED", rs
    head = e["lg"].ref("fix/MR-7-rounding")
    assert rs.result_public["head_sha"] == head and len(rs.result_public["diff_digest"]) == 64
    with gw.engine.connect() as conn:
        rec = conn.execute(select(t.github_commits).where(t.github_commits.c.sha == head)).one()
        req = conn.execute(
            select(t.evidence_events.c.event_id).where(
                t.evidence_events.c.action_id == uuid.UUID(sub["action_id"]),
                t.evidence_events.c.event_type == "ACTION_REQUESTED",
            )
        ).scalar_one()
        payload = gw.state.payloads.load_payload(conn, req)
    assert (
        rec.session_id == "sess-abc"
        and rec.issue_number == 7
        and rec.tree_sha == rs.result_public["tree_sha"]
    )
    assert bytes(rec.diff_digest) in (payload or b"")  # the assessed diff digest is in the evidence
    # PR: body template, then the check is in progress until sealed + verified.
    pr = call(
        gw,
        e,
        "github_pr_create",
        {"branch": "fix/MR-7-rounding", "title": "Fix rounding", "issue_number": 7},
    )
    out = result(gw, pr["action_id"]).result_public
    number = out["number"]
    body = fake.prs[number]["body"]
    for part in (
        "Closes #7",
        "sess-abc",
        "Developer | alice",
        f"/runs/{e['run']}",
        "Evidence events in run",
        "Approvals:** none required",
    ):
        assert part in body, part
    assert out["check"] == "in_progress"
    rep = verify(gw)
    assert rep.result in ("VERIFIED", "UNANCHORED"), rep.result
    check = fake.latest_check(number)
    assert check["conclusion"] == "success" and check["name"] == "AgentGuard evidence", check
    assert check["details_url"].endswith(f"/runs/{e['run']}")
    st = call(gw, e, "github_pr_status", {"number": number})
    assert result(gw, st["action_id"]).result_public["check"] == "success"
    steps = gw.client.get("/v1/onboarding", headers=h.headers("adam")).json()["steps"]
    assert next(x for x in steps if x["id"] == "protected_pr")["done"] is True
    # A manual push to the PR branch -> FAILURE "commits not recorded by AgentGuard".
    sha = e["lg"].manual_push("fix/MR-7-rounding", "api/src/csv.ts", "export const a = 3;\n")
    raw, hdrs = signed(
        {"action": "synchronize", "number": number, "repository": {"full_name": REPO}}
    )
    resp = gw.client.post(f"/v1/webhooks/github/{cid}", content=raw, headers=hdrs)
    assert resp.status_code == 202 and resp.json()["result"] == "failure"
    check = fake.latest_check(number)
    assert (
        check["conclusion"] == "failure"
        and "not recorded by AgentGuard" in check["output"]["title"]
    )
    assert sha[:12] in check["output"]["summary"]
    # The installation token never left the gateway.
    assert TOKEN not in caplog.text
    with gw.engine.connect() as conn:
        dump = json.dumps(
            [list(r) for r in conn.execute(text("SELECT body::text FROM evidence_events")).all()]
        )
    assert TOKEN not in dump
    assert TOKEN not in gw.client.get(f"/v1/connectors/{cid}", headers=h.headers("adam")).text


def test_high_and_critical_diffs_need_routed_approval_and_denies(
    gw: Any, env: Any, pg: Any
) -> None:
    e, h = env, env["h"]
    gw.client.post(f"/v1/connectors/{e['cid']}/classify-proposed", headers=h.headers("adam"))
    # HIGH (ledger/**) -> approval by ledger_lead, bound to the exact change.
    hi = submit(
        gw,
        e,
        lambda w: (w / "ledger/src/service.ts").write_text("export const post = 2;\n"),
        branch="fix/MR-7-ledger",
    )
    assert hi["status"] == "PENDING_APPROVAL" and hi["decision"]["risk_level"] == "HIGH", hi[
        "decision"
    ]
    assert "PATH-HIGH" in hi["decision"]["matched_rule_ids"]
    with gw.engine.connect() as conn:
        role = conn.execute(
            select(t.approvals.c.required_role).where(
                t.approvals.c.action_id == uuid.UUID(hi["action_id"])
            )
        ).scalar_one()
    assert role == "ledger_lead"
    assert (
        approve(gw, h, hi["approval"]["approval_id"], who="alice").status_code == 403
    )  # not routed
    assert approve(gw, h, hi["approval"]["approval_id"], who="lead").status_code == 200
    assert result(gw, hi["action_id"]).status == "COMPLETED"
    assert e["lg"].ref("fix/MR-7-ledger") is not None
    # Its PR passes only while the consumed approval still matches the action's digest.
    pr = call(
        gw,
        e,
        "github_pr_create",
        {"branch": "fix/MR-7-ledger", "title": "ledger", "issue_number": 7},
    )
    number = result(gw, pr["action_id"]).result_public["number"]
    assert "CONSUMED by lead" in e["fake"].prs[number]["body"]
    verify(gw)
    assert e["fake"].latest_check(number)["conclusion"] == "success"
    su(
        pg,
        "UPDATE approvals SET action_digest = decode(repeat('ab', 32), 'hex') WHERE action_id = %s",
        (hi["action_id"],),
    )
    gw.state.github_checks.evaluate_and_publish(uuid.UUID(e["cid"]), REPO, number)
    failed = e["fake"].latest_check(number)
    assert (
        failed["conclusion"] == "failure"
        and "approval is missing or does not match" in failed["output"]["summary"]
    )
    # CRITICAL (a CI change that keeps the steps) -> four-eyes by security, not a deny.
    seed_ci = "jobs:\n  test:\n    steps:\n      - run: pnpm test\n"
    cr = submit(
        gw,
        e,
        lambda w: (w / ".github/workflows/ci.yml").write_text(seed_ci + "      - run: pnpm lint\n"),
        branch="feat/MR-7-ci",
    )
    assert cr["status"] == "PENDING_APPROVAL" and cr["decision"]["risk_level"] == "CRITICAL", cr[
        "decision"
    ]
    assert cr["approval"]["required_approvals"] == 2
    approve(gw, h, cr["approval"]["approval_id"], who="sec1")
    approve(gw, h, cr["approval"]["approval_id"], who="sec2")
    assert result(gw, cr["action_id"]).status == "COMPLETED"
    # Content denies: removing signature verification, disabling CI, a secret, skipping tests.
    for edit, rule in (
        (
            lambda w: (w / "signal/src/verify.ts").write_text(
                "export function verifyWebhook() { return true; }\n"
            ),
            "CONTENT-SIGNATURE-BYPASS",
        ),
        (
            lambda w: (w / "api/src/k.ts").write_text('const k = "AKIAIOSFODNN7EXAMPLQ";\n'),
            "CONTENT-SECRET",
        ),
        (
            lambda w: (w / "api/test/fees.test.ts").write_text(
                'it.skip("charges bps", () => {});\n'
            ),
            "CONTENT-TEST-SKIP",
        ),
    ):
        d = submit(gw, e, edit, branch="fix/MR-7-bad")
        assert d["status"] == "DENIED" and d["decision"]["reasons"] == ["CONNECTOR_CONTENT_DENIED"]
        assert rule in d["decision"]["matched_rule_ids"]
    assert e["lg"].ref("fix/MR-7-bad") is None  # nothing was ever pushed


def test_branch_rules_and_change_refusals(gw: Any, env: Any) -> None:
    e, h, lg = env, env["h"], env["lg"]
    gw.client.post(f"/v1/connectors/{e['cid']}/classify-proposed", headers=h.headers("adam"))
    ok_edit = lambda w: (w / "api/src/csv.ts").write_text("export const a = 5;\n")  # noqa: E731
    # Branch name outside the pattern (schema), issue mismatch (assessment), main (refused).
    bad = gw.post(
        "cx_gh_git_submit_change",
        {
            "issue_number": 7,
            "branch": "main",
            "base_sha": "a" * 40,
            "change_format": "diff",
            "change": "eA==",
        },
        token=e["key"],
    )
    assert bad.json()["decision"]["reasons"] == ["ARGS_SCHEMA_INVALID"]
    prot = submit(gw, e, ok_edit, branch="fix/MR-7-release")  # matches the pattern, but protected
    assert (
        prot["status"] == "DENIED" and "GH-BRANCH-PROTECTED" in prot["decision"]["matched_rule_ids"]
    )
    assert e["lg"].ref("fix/MR-7-release") is None
    mis = submit(gw, e, ok_edit, branch="fix/MR-8-other")
    assert "GH-BRANCH-ISSUE-MISMATCH" in mis["decision"]["matched_rule_ids"]
    # Not fast-forward: the branch moved since base_sha.
    first = submit(gw, e, ok_edit, branch="fix/MR-7-ff")
    assert result(gw, first["action_id"]).status == "COMPLETED"
    stale = submit(
        gw, e, lambda w: (w / "README.md").write_text("x\n"), branch="fix/MR-7-ff", base=lg.main()
    )
    r = result(gw, stale["action_id"])
    assert r.status == "FAILED" and "TOOL_ERROR" in (r.error_code or "")
    # Traversal / garbage change -> denied at assessment, never executed.
    trav = call(
        gw,
        e,
        "git_submit_change",
        {
            "issue_number": 7,
            "branch": "fix/MR-7-trav",
            "base_sha": lg.main(),
            "change_format": "diff",
            "change": b64(
                b"diff --git a/../x b/../x\nnew file mode 100644\n"
                b"--- /dev/null\n+++ b/../x\n@@ -0,0 +1 @@\n+x\n"
            ),
        },
    )
    assert trav["status"] == "DENIED" and any(
        r_.startswith("GH-") for r_ in trav["decision"]["matched_rule_ids"]
    )

    # Bundle with a rename + delete works.
    def edit(w: Path) -> None:
        import subprocess

        subprocess.run(
            ["git", "mv", "api/src/old_name.ts", "api/src/renamed.ts"], cwd=w, check=True
        )

    bun = submit(gw, e, edit, branch="feat/MR-7-bundle", fmt="bundle")
    assert result(gw, bun["action_id"]).status == "COMPLETED"


def test_check_failure_matrix_forged_webhook_polling_and_tamper(gw: Any, env: Any, pg: Any) -> None:
    e, fake, h, lg = env, env["fake"], env["h"], env["lg"]
    cid = e["cid"]
    gw.client.post(f"/v1/connectors/{cid}/classify-proposed", headers=h.headers("adam"))
    sub = submit(gw, e, lambda w: (w / "api/src/csv.ts").write_text("export const a = 7;\n"))
    assert result(gw, sub["action_id"]).status == "COMPLETED"
    pr = call(
        gw, e, "github_pr_create", {"branch": "fix/MR-7-rounding", "title": "t", "issue_number": 7}
    )
    number = result(gw, pr["action_id"]).result_public["number"]
    # Forged webhook: rejected, recorded, nothing evaluated.
    raw, hdrs = signed(
        {"action": "synchronize", "number": number, "repository": {"full_name": REPO}}, "wrong"
    )
    assert (
        gw.client.post(f"/v1/webhooks/github/{cid}", content=raw, headers=hdrs).status_code == 401
    )
    raw, hdrs = signed(
        {"action": "synchronize", "number": number, "repository": {"full_name": REPO}}
    )
    hdrs.pop("X-Hub-Signature-256")
    assert (
        gw.client.post(f"/v1/webhooks/github/{cid}", content=raw, headers=hdrs).status_code == 401
    )
    health = gw.client.get(f"/v1/connectors/{cid}/github", headers=h.headers("adam")).json()
    assert [d["verified"] for d in health["deliveries"]] == [False, False]
    assert health["repos"] == [REPO] and health["installation_ids"] == [31337]
    # Replay of a verified delivery id is a no-op.
    raw, hdrs = signed({"action": "opened", "number": number, "repository": {"full_name": REPO}})
    assert (
        gw.client.post(f"/v1/webhooks/github/{cid}", content=raw, headers=hdrs).status_code == 202
    )
    assert (
        gw.client.post(f"/v1/webhooks/github/{cid}", content=raw, headers=hdrs).json()["result"]
        == "duplicate delivery"
    )
    # Polling mode evaluates open PRs (here: success once verified).
    verify(gw)
    assert fake.latest_check(number)["conclusion"] == "success"
    published = len(fake.checks)
    gw.state.github_checks.poll_once()  # nothing changed for this PR -> no new check run
    assert fake.latest_check(number)["conclusion"] == "success"
    assert all(
        c.get("head_sha") != fake._pr(number)["head"]["sha"]
        for c in list(fake.checks.values())[published:]
    )
    # A fork PR fails.
    fake.prs[number]["fork"] = True
    raw, hdrs = signed({"action": "reopened", "number": number, "repository": {"full_name": REPO}})
    gw.client.post(f"/v1/webhooks/github/{cid}", content=raw, headers=hdrs)
    assert "fork" in fake.latest_check(number)["output"]["summary"]
    fake.prs[number]["fork"] = False
    gw.state.github_checks.evaluate_and_publish(uuid.UUID(cid), REPO, number)
    assert fake.latest_check(number)["conclusion"] == "success"
    # More commits than the listing returned (GitHub caps it) -> failure, never a partial check.
    fake.extra_commits = 300
    gw.state.github_checks.evaluate_and_publish(uuid.UUID(cid), REPO, number)
    capped = fake.latest_check(number)
    assert (
        capped["conclusion"] == "failure"
        and "could not all be listed" in capped["output"]["summary"]
    )
    fake.extra_commits = 0
    gw.state.github_checks.evaluate_and_publish(uuid.UUID(cid), REPO, number)
    assert fake.latest_check(number)["conclusion"] == "success"
    # Tamper: the monitor reports TAMPERED -> the check flips to FAILURE + one PR comment.
    with gw.engine.connect() as conn:
        victim = conn.execute(
            select(t.evidence_events.c.event_id).where(
                t.evidence_events.c.action_id == uuid.UUID(sub["action_id"]),
                t.evidence_events.c.event_type == "ACTION_AUTHORIZED",
            )
        ).scalar_one()
    su(
        pg,
        "UPDATE evidence_events SET canonical_bytes = overlay(canonical_bytes placing "
        "decode('ff', 'hex') from 40 for 1) WHERE event_id = %s",
        (victim,),
    )
    rep = verify(gw)
    assert rep.result == "TAMPERED"
    check = fake.latest_check(number)
    assert check["conclusion"] == "failure" and "TAMPERED" in check["output"]["title"]
    comments = [c for n, c in fake.comments if n == number]
    assert len(comments) == 1 and "TAMPERED" in comments[0] and "detected" in comments[0]
    gw.state.github_checks.on_monitor_report(gw.world.tenant_id, "TAMPERED", rep.report_id)
    assert len([c for n, c in fake.comments if n == number]) == 1  # once per (PR, report)
    _ = lg


def test_editing_config_keeps_the_app_identity_from_the_github_flow(gw: Any, env: Any) -> None:
    """The dashboard edit form sends owner/repos/mode only: the App id, client id and
    installation ids recorded by the manifest/install flow must survive (and cannot be set)."""
    e, h = env, env["h"]
    r = gw.client.patch(
        f"/v1/connectors/{e['cid']}",
        headers=h.headers("adam"),
        json={
            "config": {
                "owner_type": "user",
                "owner": "Akshat453",
                "repos": [REPO],
                "mode": "webhook",
                "installation_ids": [999],  # a hand-typed id is ignored
                "app_id": 1,
            }
        },
    )
    assert r.status_code == 200, r.text
    cfg = gw.client.get(f"/v1/connectors/{e['cid']}", headers=h.headers("adam")).json()["config"]
    assert cfg["installation_ids"] == [31337] and cfg["app_id"] == 4711
    assert cfg["client_id"] == "Iv1.test" and cfg["mode"] == "webhook"


def test_polling_picks_up_new_prs_and_run_page_lists_prs(gw: Any, env: Any) -> None:
    e, fake, h = env, env["fake"], env["h"]
    gw.client.post(f"/v1/connectors/{e['cid']}/classify-proposed", headers=h.headers("adam"))
    sub = submit(gw, e, lambda w: (w / "api/src/csv.ts").write_text("export const a = 8;\n"))
    assert result(gw, sub["action_id"]).status == "COMPLETED"
    fake.prs[500] = {
        "number": 500,
        "head_ref": "fix/MR-7-rounding",
        "base": "main",
        "state": "open",
        "body": "",
        "title": "opened on github.com",
        "fork": False,
    }
    gw.state.github_checks.poll_once()
    assert (
        fake.latest_check(500)["status"] == "in_progress"
    )  # waiting for seal + verification  # waiting for seal + verification
    pr = call(
        gw, e, "github_pr_create", {"branch": "fix/MR-7-rounding", "title": "t", "issue_number": 7}
    )
    result(gw, pr["action_id"])
    prs = gw.client.get(f"/v1/dashboard/runs/{e['run']}/prs", headers=h.headers("audrey")).json()[
        "pull_requests"
    ]
    assert prs and prs[0]["repo"] == REPO


def test_dev_tools_over_mcp_and_descriptions(gw: Any, env: Any) -> None:
    from tests.e2e.test_c2_identity import mcp, oauth_login

    e, h = env, env["h"]
    gw.client.post(f"/v1/connectors/{e['cid']}/classify-proposed", headers=h.headers("adam"))
    tok, _ = oauth_login(gw, h)
    tools = {
        x["name"]: x for x in mcp(gw, tok["access_token"], "tools/list").json()["result"]["tools"]
    }
    assert set(tools) >= {
        "cx_gh_git_submit_change",
        "cx_gh_github_pr_create",
        "cx_gh_github_issue_get",
    }
    assert "instead of `git push`" in tools["cx_gh_git_submit_change"]["description"]
    res = mcp(
        gw,
        tok["access_token"],
        "tools/call",
        {"name": "cx_gh_github_issue_get", "arguments": {"number": 7}},
    )
    out = res.json()["result"]
    assert (
        "Still running" in out["content"][0]["text"]
        or "Refund rounding" in out["content"][0]["text"]
    )


def test_github_actions_belong_to_their_repository(
    gw: Any, env: Any, migrator_engine: Engine
) -> None:
    """ADR-0042: GitHub tool calls (one MCP run per device) are scoped by the repository they
    targeted, so selecting a repository shows them and no other repository does."""
    from agw_gateway.coding.backfill import backfill_action_repos

    e, h = env, env["h"]
    gw.client.post(f"/v1/connectors/{e['cid']}/classify-proposed", headers=h.headers("adam"))
    one = call(gw, e, "github_issue_get", {"number": 7})  # default repo
    two = call(gw, e, "github_issue_get", {"number": 7, "repo": REPO})
    ids = {}
    for url in ("https://github.com/Akshat453/MintRail.git", "git@github.com:Akshat453/Other.git"):
        r = gw.client.post(
            "/v1/coding/repos",
            json={"remote_url": url, "agents": {}, "agentguard_yaml": "version: 1\n"},
            headers={"Authorization": f"Bearer {e['key']}"},
        )
        assert r.status_code in (200, 201), r.text
        ids[url] = r.json()["repo_id"]
    mint, other = (
        ids["https://github.com/Akshat453/MintRail.git"],
        ids["git@github.com:Akshat453/Other.git"],
    )
    hd = h.headers("audrey")

    def runs(repo: str) -> list[dict[str, Any]]:
        return list(gw.client.get(f"/v1/dashboard/runs?repo_id={repo}", headers=hd).json())

    got = [r for r in runs(mint) if r["run_id"] == e["run"]]
    assert got and got[0]["actions"] == 2 and got[0]["repos"] == [REPO]
    assert all(r["run_id"] != e["run"] for r in runs(other))
    ev = gw.client.get(f"/v1/dashboard/events?repo_id={mint}&limit=500", headers=hd).json()
    assert {x["header"].get("action") for x in ev["events"]} >= {one["action_id"], two["action_id"]}
    act = gw.client.get(f"/v1/dashboard/activity?repo_id={other}", headers=hd).json()
    assert act["current"]["actions"] == 0
    detail = gw.client.get(f"/v1/dashboard/runs/{e['run']}", headers=hd).json()
    assert detail["repos"] == [REPO]

    # Actions decided before 0016 get their repository back from their own payload.
    with migrator_engine.begin() as conn:
        conn.execute(
            text("DELETE FROM action_repos WHERE tenant_id = :t"), {"t": gw.world.tenant_id}
        )
    assert all(r["run_id"] != e["run"] for r in runs(mint))
    done = backfill_action_repos(
        migrator_engine, gw.state.writer.payloads, tenant=gw.world.tenant_id
    )
    assert done["filled"] == 2
    assert any(r["run_id"] == e["run"] for r in runs(mint))
    assert (
        backfill_action_repos(migrator_engine, gw.state.writer.payloads, tenant=gw.world.tenant_id)[
            "filled"
        ]
        == 0
    )
