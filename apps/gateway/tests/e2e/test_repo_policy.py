"""C2: repo-side .agentguard.yaml can only TIGHTEN policy; loosening is ignored, reported and
becomes a proposal an admin approves (step-up) or rejects; every applied change is a new
repo policy version with REPO_POLICY_CHANGED evidence."""

from __future__ import annotations

from typing import Any

import pytest
from sqlalchemy import Engine

from tests.approvalkit import make_humans
from tests.codingkit import REPO_URL, CodingWorld, decide, make_coding_world, start_session

pytestmark = pytest.mark.e2e

TIGHTEN = """
version: 1
sensitive_paths:
  - path: "api/src/billing/**"
    level: critical
  - "reports/**"
deny_paths: ["fixtures/secrets/**"]
deny_commands: ["pnpm db:reset"]
"""
LOOSEN = (
    TIGHTEN
    + """
allow_commands: ["node scripts/demo.ts"]
allow_paths: ["ledger/src/docs/**"]
surprise_key: true
"""
)


@pytest.fixture
def cw(gw: Any, migrator_engine: Engine) -> CodingWorld:
    return make_coding_world(migrator_engine, gw.client, gw.world.tenant_id)


def register(gw: Any, cw: CodingWorld, yaml_text: str) -> dict[str, Any]:
    r = gw.client.post(
        "/v1/coding/repos",
        headers=cw.device(),
        json={
            "remote_url": REPO_URL,
            "agents": {"claude_code": {"tier": "enforced"}},
            "agentguard_yaml": yaml_text,
        },
    )
    assert r.status_code == 200, r.text
    return dict(r.json())


def test_tighten_applies_loosen_becomes_proposal(
    gw: Any, cw: CodingWorld, migrator_engine: Engine
) -> None:
    s = start_session(gw.client, cw)
    before = decide(gw.client, cw, s, "file_read", "fixtures/secrets/k.json").json()
    assert before["decision"] == "allow"
    r = register(gw, cw, TIGHTEN)
    assert r["policy_version"] == 1 and r["proposal_id"] is None
    assert gw.count_events("REPO_POLICY_CHANGED") == 1
    diff = "--- a/x\n+++ b/x\n@@ -1 +1,2 @@\n+// x\n"
    crit = decide(gw.client, cw, s, "file_write", "api/src/billing/invoice.ts", diff).json()
    assert crit["decision"] == "ask" and crit["approval"]["required_role"] == "security"
    assert "REPO-OVERLAY-v1" in crit["rule_ids"]
    high = decide(gw.client, cw, s, "file_write", "reports/q3.ts", diff).json()
    assert high["decision"] == "ask" and high["risk_level"] == "HIGH"
    sec = decide(gw.client, cw, s, "file_read", "fixtures/secrets/k.json").json()
    assert sec["decision"] == "deny" and "SECRET-READ" in sec["rule_ids"]
    cmd = decide(gw.client, cw, s, "command_exec", "pnpm db:reset --force").json()
    assert cmd["decision"] == "deny" and "CMD-REPO-DENY" in cmd["rule_ids"]
    # Loosening: ignored, reported, proposal; nothing loosened yet.
    r2 = register(gw, cw, LOOSEN)
    assert r2["policy_version"] == 1 and r2["proposal_id"]
    ops = sorted(i.get("op", i.get("problem")) for i in r2["ignored"])
    assert ops == ["add_allow_command", "add_allow_path", "unknown key ignored: surprise_key"]
    assert register(gw, cw, LOOSEN)["proposal_id"] == r2["proposal_id"]  # not duplicated
    still = decide(gw.client, cw, s, "command_exec", "node scripts/demo.ts").json()
    assert still["decision"] == "ask"
    # Removing a tightening from the file is loosening too.
    r3 = register(gw, cw, "version: 1\nsensitive_paths: ['reports/**']\n")
    assert {i["op"] for i in r3["ignored"]} >= {
        "remove_sensitive",
        "remove_deny_path",
        "remove_deny_command",
    }
    assert decide(gw.client, cw, s, "command_exec", "pnpm db:reset").json()["decision"] == "deny"
    # The admin sees proposals with a diff; approval needs admin + step-up.
    h = make_humans(migrator_engine, gw.client, gw.world.tenant_id)
    repos = gw.client.get("/v1/repos", headers=h.headers("adam")).json()["repos"]
    props = repos[0]["proposals"]
    assert len(props) == 2 and "allow_commands" in props[0]["diff"]
    assert repos[0]["agents"] == {"claude_code": {"tier": "enforced"}}
    unstepped = make_humans(migrator_engine, gw.client, gw.world.tenant_id, step_up=False)
    assert (
        gw.client.post(
            f"/v1/repos/proposals/{r2['proposal_id']}/decision",
            headers=unstepped.headers("adam"),
            json={"decision": "approve"},
        ).json()["error"]["code"]
        == "STEP_UP_REQUIRED"
    )
    assert (
        gw.client.post(
            f"/v1/repos/proposals/{r2['proposal_id']}/decision",
            headers=h.headers("alice"),
            json={"decision": "approve"},
        ).status_code
        == 403
    )
    ok = gw.client.post(
        f"/v1/repos/proposals/{r2['proposal_id']}/decision",
        headers=h.headers("adam"),
        json={"decision": "approve", "reason": "demo script reviewed"},
    ).json()
    assert ok == {"status": "approved", "policy_version": 2}
    now = decide(gw.client, cw, s, "command_exec", "node scripts/demo.ts").json()
    assert now["decision"] == "allow" and "REPO-ALLOW-CMD" in now["rule_ids"]
    # An approved exception never relaxes a CRITICAL path, a secret or a denied command.
    assert (
        decide(gw.client, cw, s, "command_exec", "curl https://x.example").json()["decision"]
        == "deny"
    )
    rej = gw.client.post(
        f"/v1/repos/proposals/{r3['proposal_id']}/decision",
        headers=h.headers("adam"),
        json={"decision": "reject"},
    ).json()
    assert rej["status"] == "rejected"
    assert decide(gw.client, cw, s, "command_exec", "pnpm db:reset").json()["decision"] == "deny"
    assert gw.count_events("REPO_POLICY_CHANGED") == 3  # tightened, approved, rejected


def test_status_and_invalid_yaml(gw: Any, cw: CodingWorld) -> None:
    assert (
        gw.client.get(
            "/v1/coding/repos/status", params={"remote_url": REPO_URL}, headers=cw.device()
        ).status_code
        == 404
    )
    r = register(gw, cw, "version: [unclosed")
    assert r["ignored"] == [{"problem": "not valid YAML"}] and r["policy_version"] == 0
    bad = register(gw, cw, "sensitive_paths: ['../../etc/**', {path: 'x/**', level: 'low'}]\n")
    assert len([i for i in bad["ignored"] if "invalid" in i.get("problem", "")]) == 2
    st = gw.client.get(
        "/v1/coding/repos/status", params={"remote_url": REPO_URL}, headers=cw.device()
    ).json()
    assert st["policy_version"] == 0 and st["pending_proposals"] == 0
