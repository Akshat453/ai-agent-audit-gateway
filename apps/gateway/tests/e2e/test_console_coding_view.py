"""ADR-0039: the console shows WHAT a coding action targeted (path, redacted command) and WHO ran
the session, never file contents; the stored copy is sealed; other tenants see nothing."""

from __future__ import annotations

from typing import Any

import pytest
from sqlalchemy import Engine, select

from agw_gateway.admin import ensure_human, ensure_tenant
from agw_gateway.db import tables as t
from tests.approvalkit import PASSWORD
from tests.codingkit import CodingWorld, decide, make_coding_world, start_session

pytestmark = pytest.mark.e2e
SECRET = "sk_live_" + "Q" * 20
CANARY = "CANARY_FILE_CONTENT_7f3a"
DIFF = (
    "--- a/ledger/src/service.ts\n+++ b/ledger/src/service.ts\n@@ -1 +1,2 @@\n"
    f"-const a = 1;\n+const a = 2; // {CANARY}\n+export const k = 'x';\n"
)


@pytest.fixture
def cw(gw: Any, migrator_engine: Engine) -> CodingWorld:
    return make_coding_world(migrator_engine, gw.client, gw.world.tenant_id)


def _detail(gw: Any, cw: CodingWorld, action_id: str, who: str = "dev") -> Any:
    r = gw.client.get(f"/v1/dashboard/actions/{action_id}", headers=cw.human(who))
    assert r.status_code == 200, r.text
    return r


def test_action_detail_shows_path_redacted_command_and_counts_never_content(
    gw: Any, cw: CodingWorld, app_engine: Engine
) -> None:
    s = start_session(gw.client, cw)
    write = decide(gw.client, cw, s, "file_write", "ledger/src/service.ts", DIFF).json()
    cmd = decide(
        gw.client, cw, s, "command_exec", f"STRIPE_KEY={SECRET} curl https://api.example.com"
    ).json()

    w = _detail(gw, cw, write["action_id"])
    body = w.json()
    assert body["coding"]["action_type"] == "file_write"
    assert body["coding"]["target"]["paths"] == ["ledger/src/service.ts"]
    assert body["coding"]["diff"] == {"files": 1, "added": 2, "removed": 1}
    assert CANARY not in w.text  # file contents are never shown
    sess = body["session"]
    assert sess["agent_kind"] == "claude_code" and sess["agent_version"] == "2.1.319"
    assert sess["developer"] == "dev" and sess["device"] == "laptop" and sess["issue_number"] == 42

    c = _detail(gw, cw, cmd["action_id"])
    shown = c.json()["coding"]["target"]["command"]
    assert "curl https://api.example.com" in shown and "[REDACTED]" in shown
    assert SECRET not in c.text

    # The stored copy is sealed: neither the path nor the command is readable in the row.
    with app_engine.connect() as conn:
        rows = conn.execute(
            select(t.coding_actions.c.target_sealed).where(
                t.coding_actions.c.session_id == s  # type: ignore[arg-type]
            )
        ).all()
    blob = b"".join(bytes(r.target_sealed) for r in rows)
    assert (
        rows and b"ledger/src" not in blob and b"curl" not in blob and SECRET.encode() not in blob
    )


def test_lists_carry_session_and_short_target(gw: Any, cw: CodingWorld) -> None:
    s = start_session(gw.client, cw)
    ask = decide(gw.client, cw, s, "file_write", "ledger/src/journal.ts", DIFF).json()
    assert ask["decision"] == "ask", ask
    runs = gw.client.get("/v1/dashboard/runs", headers=cw.human("dev")).json()
    run = next(r for r in runs if r["run_id"] == s)
    assert run["session"]["issue_number"] == 42 and run["decisions"]["REQUIRE_APPROVAL"] == 1
    detail = gw.client.get(f"/v1/dashboard/runs/{s}", headers=cw.human("dev")).json()
    assert detail["session"]["developer"] == "dev"
    assert detail["coding"][ask["action_id"]]["target"]["paths"] == ["ledger/src/journal.ts"]
    page = gw.client.get("/v1/dashboard/approvals?state=PENDING", headers=cw.human("dev")).json()
    row = next(r for r in page["rows"] if r["action_id"] == ask["action_id"])
    assert row["action_type"] == "file_write" and row["target"] == "ledger/src/journal.ts"
    assert row["agent_kind"] == "claude_code" and row["issue_number"] == 42
    detail = _detail(gw, cw, ask["action_id"]).json()
    pe = next(e for e in detail["events"] if e["type"] == "POLICY_EVALUATED")
    assert "PATH-HIGH" in pe["rules"]


def test_other_tenant_sees_nothing(gw: Any, cw: CodingWorld, migrator_engine: Engine) -> None:
    s = start_session(gw.client, cw)
    a = decide(gw.client, cw, s, "file_write", "ledger/src/service.ts", DIFF).json()
    ensure_tenant(migrator_engine, "other-co", "Other")
    ensure_human(migrator_engine, "other-co", "eve", PASSWORD, ["admin", "auditor"])
    tok = gw.client.post(
        "/v1/auth/login", json={"tenant": "other-co", "username": "eve", "password": PASSWORD}
    ).json()["session_token"]
    h = {"Authorization": f"Session {tok}"}
    assert gw.client.get(f"/v1/dashboard/actions/{a['action_id']}", headers=h).status_code == 404
    assert gw.client.get(f"/v1/dashboard/runs/{s}", headers=h).status_code == 404
    assert all(r["run_id"] != s for r in gw.client.get("/v1/dashboard/runs", headers=h).json())


def test_rule_descriptions_endpoint(gw: Any, cw: CodingWorld) -> None:
    r = gw.client.get("/v1/dashboard/rule-descriptions", headers=cw.human("dev"))
    assert r.status_code == 200
    d = r.json()
    assert d["rules"]["CONTENT-SIGNATURE-BYPASS"]["why"] == (
        "The change would remove webhook signature checks."
    )
    assert "REPO-OVERLAY-v*" in d["patterns"]
    assert gw.client.get("/v1/dashboard/rule-descriptions").status_code == 401


def test_who_decided_is_named_in_action_and_run(gw: Any, cw: CodingWorld) -> None:
    from tests.codingkit import approve

    s = start_session(gw.client, cw)
    ask = decide(gw.client, cw, s, "file_write", "ledger/src/journal.ts", DIFF).json()
    assert approve(gw.client, cw, ask["approval"]["approval_id"], "lead").status_code == 200
    d = _detail(gw, cw, ask["action_id"]).json()
    assert d["approvals"][0]["decisions"][0]["approver"] == "lead"
    assert d["approvals"][0]["decisions"][0]["decision"] == "APPROVED"
    run = gw.client.get(f"/v1/dashboard/runs/{s}", headers=cw.human("dev")).json()
    assert "lead" in run["people"].values()
