"""ADR-0040: the console can be scoped to one repository. Runs, approvals, events, incidents,
activity and overview figures then only include that repository's coding sessions; another
tenant's repository id matches nothing."""

from __future__ import annotations

from typing import Any

import pytest
from sqlalchemy import Engine

from agw_gateway.admin import ensure_human, ensure_tenant
from tests.approvalkit import PASSWORD
from tests.codingkit import HEAD, REPO_URL, CodingWorld, decide, make_coding_world, start_session

pytestmark = pytest.mark.e2e
OTHER_URL = "https://github.com/Akshat453/Other.git"
DIFF = "--- a/ledger/src/a.ts\n+++ b/ledger/src/a.ts\n@@ -1 +1 @@\n-x\n+y\n"


@pytest.fixture
def cw(gw: Any, migrator_engine: Engine) -> CodingWorld:
    return make_coding_world(migrator_engine, gw.client, gw.world.tenant_id)


def _register(gw: Any, cw: CodingWorld, url: str) -> str:
    r = gw.client.post(
        "/v1/coding/repos",
        json={"remote_url": url, "agents": {"claude_code": {"tier": "enforced"}},
              "agentguard_yaml": "version: 1\n"},
        headers=cw.device(),
    )  # fmt: skip
    assert r.status_code in (200, 201), r.text
    return str(r.json()["repo_id"])


def _get(gw: Any, cw: CodingWorld, path: str, who: str = "dev") -> Any:
    r = gw.client.get(path, headers=cw.human(who))
    assert r.status_code == 200, (path, r.text)
    return r.json()


def test_every_list_can_be_scoped_to_one_repository(
    gw: Any, cw: CodingWorld, migrator_engine: Engine
) -> None:
    mint = _register(gw, cw, REPO_URL)
    other = _register(gw, cw, OTHER_URL)
    s1 = start_session(gw.client, cw)
    s2 = start_session(gw.client, cw, repo={"remote_url": OTHER_URL, "head_sha": HEAD})
    a1 = decide(gw.client, cw, s1, "file_write", "ledger/src/a.ts", DIFF).json()  # ask
    a2 = decide(gw.client, cw, s2, "file_write", "ledger/src/a.ts", DIFF).json()  # ask
    d1 = decide(gw.client, cw, s1, "command_exec", "git push origin main").json()  # deny
    assert a1["decision"] == "ask" and a2["decision"] == "ask" and d1["decision"] == "deny"

    choices = _get(gw, cw, "/v1/dashboard/repo-choices")
    by_name = {c["repo_id"]: c for c in choices}
    assert by_name[mint]["sessions"] == 1 and by_name[other]["sessions"] == 1

    runs = {r["run_id"] for r in _get(gw, cw, f"/v1/dashboard/runs?repo_id={mint}")}
    assert runs == {s1}
    assert {r["run_id"] for r in _get(gw, cw, "/v1/dashboard/runs")} >= {s1, s2}

    ap = _get(gw, cw, f"/v1/dashboard/approvals?state=PENDING&repo_id={other}")
    assert [r["action_id"] for r in ap["rows"]] == [a2["action_id"]] and ap["total"] == 1

    ev = _get(gw, cw, f"/v1/dashboard/events?repo_id={mint}&limit=500")["events"]
    assert ev and {e["header"].get("run") for e in ev} == {s1}

    inc = _get(gw, cw, f"/v1/dashboard/incidents?kind=denied&repo_id={other}")
    assert inc == []
    inc = _get(gw, cw, f"/v1/dashboard/incidents?kind=denied&repo_id={mint}")
    assert [i["action_id"] for i in inc] == [d1["action_id"]]

    act = _get(gw, cw, f"/v1/dashboard/activity?repo_id={other}")
    assert act["current"]["actions"] == 1 and act["current"]["denied"] == 0
    ov = _get(gw, cw, f"/v1/dashboard/overview?repo_id={mint}")
    assert ov["pending_approvals"] == 1 and ov["decisions"] == {"REQUIRE_APPROVAL": 1, "DENY": 1}

    # Another tenant cannot use the scope to see anything, nor list our repositories.
    ensure_tenant(migrator_engine, "other-co", "Other")
    ensure_human(migrator_engine, "other-co", "eve", PASSWORD, ["admin", "auditor"])
    tok = gw.client.post(
        "/v1/auth/login", json={"tenant": "other-co", "username": "eve", "password": PASSWORD}
    ).json()["session_token"]
    h = {"Authorization": f"Session {tok}"}
    assert gw.client.get(f"/v1/dashboard/runs?repo_id={mint}", headers=h).json() == []
    assert gw.client.get(f"/v1/dashboard/approvals?repo_id={mint}", headers=h).json()["total"] == 0
    assert gw.client.get("/v1/dashboard/repo-choices", headers=h).json() == []


def test_run_story_carries_rule_ids(gw: Any, cw: CodingWorld) -> None:
    s = start_session(gw.client, cw)
    decide(gw.client, cw, s, "command_exec", "git push origin main")
    detail = _get(gw, cw, f"/v1/dashboard/runs/{s}")
    pe = next(e for e in detail["events"] if e["type"] == "POLICY_EVALUATED")
    assert "GIT-PUSH" in pe["rules"]
