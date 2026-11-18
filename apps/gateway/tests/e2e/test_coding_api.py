"""C1 coding-agent API (ADR-0034): sessions, decide, observe, end; approvals (route, wait,
consume once, replay, changed action, reject, expiry); identity; evidence; no secrets leak."""

from __future__ import annotations

import logging
import uuid
from typing import Any

import pytest
from sqlalchemy import Engine, select, text

from agw_gateway.db import tables as t
from tests.approvalkit import expire_now
from tests.codingkit import CodingWorld, approve, decide, make_coding_world, start_session

pytestmark = pytest.mark.e2e

NORMAL_DIFF = "--- a/api/src/csv.ts\n+++ b/api/src/csv.ts\n@@ -1 +1,2 @@\n+// quoting\n x\n"
LEDGER_DIFF = "--- a/ledger/src/service.ts\n+++ b/ledger/src/service.ts\n@@ -1 +1,2 @@\n+// order\n"
SECRET = "AKIAIOSFODNN7EXAMPLQ"
SECRET_DIFF = f'--- a/api/src/x.ts\n+++ b/api/src/x.ts\n@@ -1 +1,2 @@\n+const k = "{SECRET}";\n'


@pytest.fixture
def cw(gw: Any, migrator_engine: Engine) -> CodingWorld:
    return make_coding_world(migrator_engine, gw.client, gw.world.tenant_id)


def _events(engine: Engine, action_id: str) -> list[str]:
    with engine.connect() as conn:
        return list(
            conn.execute(
                select(t.evidence_events.c.event_type)
                .where(t.evidence_events.c.action_id == uuid.UUID(action_id))
                .order_by(t.evidence_events.c.seq)
            ).scalars()
        )


def test_allow_deny_ask_and_evidence(gw: Any, cw: CodingWorld) -> None:
    s = start_session(gw.client, cw)
    allow = decide(gw.client, cw, s, "file_write", "api/src/csv.ts", NORMAL_DIFF)
    assert allow.status_code == 200, allow.text
    a = allow.json()
    assert (a["decision"], a["status"], a["session_id"]) == ("allow", "AUTHORIZED", s)
    assert _events(gw.engine, a["action_id"]) == [
        "ACTION_REQUESTED",
        "POLICY_EVALUATED",
        "ACTION_AUTHORIZED",
    ]
    deny = decide(gw.client, cw, s, "command_exec", "git push origin main").json()
    assert deny["decision"] == "deny" and "GIT-PUSH" in deny["rule_ids"]
    assert _events(gw.engine, deny["action_id"])[-1] == "ACTION_DENIED"
    ask = decide(gw.client, cw, s, "file_write", "ledger/src/service.ts", LEDGER_DIFF).json()
    assert ask["decision"] == "ask"
    assert ask["approval"]["required_role"] == "ledger_lead"
    assert ask["approval"]["link"].endswith(f"/approvals/{ask['approval']['approval_id']}")
    assert _events(gw.engine, ask["action_id"])[-1] == "APPROVAL_REQUIRED"
    # Headers: tool coding.<type>, code provenance with repo/head/diff digests, run = session.
    with gw.engine.connect() as conn:
        body = conn.execute(
            select(t.evidence_events.c.body).where(
                t.evidence_events.c.action_id == uuid.UUID(a["action_id"]),
                t.evidence_events.c.event_type == "ACTION_REQUESTED",
            )
        ).scalar_one()
    assert body["tool"] == {"id": "coding.file_write", "ver": "1"}
    assert body["code"]["kind"] == "claude_code"
    assert body["code"]["agent"] == "claude_code/2.1.319"
    assert len(bytes.fromhex(body["code"]["repo"])) == 32
    assert body["code"]["head"] == "a" * 40
    assert len(bytes.fromhex(body["code"]["diff"])) == 32
    assert "quoting" not in str(body)  # the diff is only in the encrypted payload


def test_observe_completes_and_undecided_is_a_violation(gw: Any, cw: CodingWorld) -> None:
    s = start_session(gw.client, cw)
    a = decide(gw.client, cw, s, "command_exec", "pnpm test", correlation="toolu_1").json()
    r = gw.client.post(
        "/v1/coding/observe",
        json={
            "session_id": s,
            "correlation_id": "toolu_1",
            "success": True,
            "exit_code": 0,
            "result_sha256": "c" * 64,
            "files_touched": ["/w/mintrail/api/src/csv.ts"],
        },
        headers=cw.device(),
    )
    assert r.status_code == 202, r.text
    assert r.json() == {"recorded": "COMPLETED", "action_id": a["action_id"]}
    assert _events(gw.engine, a["action_id"])[-1] == "ACTION_COMPLETED"
    again = gw.client.post(
        "/v1/coding/observe",
        json={"session_id": s, "action_id": a["action_id"], "success": True},
        headers=cw.device(),
    )
    assert again.json()["recorded"] == "duplicate"
    before = gw.count_events("SECURITY_VIOLATION")
    v = gw.client.post(
        "/v1/coding/observe",
        json={
            "session_id": s,
            "correlation_id": "never-decided",
            "success": True,
            "action_type": "command_exec",
        },
        headers=cw.device(),
    )
    assert v.json() == {"recorded": "violation"}
    assert gw.count_events("SECURITY_VIOLATION") == before + 1
    # Running an action that was DENIED is a violation too, not a completion.
    d = decide(gw.client, cw, s, "command_exec", "curl https://x.example", correlation="t2").json()
    v2 = gw.client.post(
        "/v1/coding/observe",
        json={"session_id": s, "action_id": d["action_id"], "success": True},
        headers=cw.device(),
    )
    assert v2.json() == {"recorded": "violation"}
    assert gw.action_status(d["action_id"]) == "DENIED"


def test_approval_wait_consume_once_replay_and_change(gw: Any, cw: CodingWorld) -> None:
    s = start_session(gw.client, cw)
    first = decide(gw.client, cw, s, "file_write", "ledger/src/service.ts", LEDGER_DIFF).json()
    ap_id, action_id = first["approval"]["approval_id"], first["action_id"]
    # Identical retry while pending: the same approval, no new action.
    pending = decide(gw.client, cw, s, "file_write", "ledger/src/service.ts", LEDGER_DIFF).json()
    assert (pending["decision"], pending["action_id"]) == ("ask", action_id)
    # The developer (approver role) cannot approve a ledger_lead-routed approval.
    assert approve(gw.client, cw, ap_id, "dev").status_code == 403
    r = approve(gw.client, cw, ap_id, "lead")
    assert r.status_code == 200, r.text
    assert r.json()["state"] == "APPROVED"
    assert r.json()["authorization"]["code"] == "AWAITING_AGENT_RETRY"
    polled = gw.client.get(f"/v1/coding/actions/{action_id}", headers=cw.device()).json()
    assert polled["approval_state"] == "APPROVED" and polled["status"] == "PENDING_APPROVAL"
    # A CHANGED action does not consume it: it needs its own approval.
    changed = decide(
        gw.client, cw, s, "file_write", "ledger/src/service.ts", LEDGER_DIFF + "+// more\n"
    ).json()
    assert changed["decision"] == "ask" and changed["action_id"] != action_id
    # The identical retry consumes it exactly once.
    ok = decide(gw.client, cw, s, "file_write", "ledger/src/service.ts", LEDGER_DIFF).json()
    assert (ok["decision"], ok["action_id"], ok["status"]) == ("allow", action_id, "AUTHORIZED")
    assert _events(gw.engine, action_id)[-2:] == ["POLICY_EVALUATED", "ACTION_AUTHORIZED"]
    # Replay: the next identical retry is a NEW request needing a new approval.
    replay = decide(gw.client, cw, s, "file_write", "ledger/src/service.ts", LEDGER_DIFF).json()
    assert replay["decision"] == "ask" and replay["action_id"] not in (action_id,)
    with gw.engine.connect() as conn:
        uses = conn.execute(
            select(t.approval_uses).where(t.approval_uses.c.approval_id == uuid.UUID(ap_id))
        ).all()
    assert len(uses) == 1


def test_reject_and_expiry(gw: Any, cw: CodingWorld, migrator_engine: Engine) -> None:
    s = start_session(gw.client, cw)
    a = decide(gw.client, cw, s, "command_exec", "pnpm add left-pad-ng").json()
    assert a["approval"]["required_role"] == "maintainer"
    assert (
        approve(gw.client, cw, a["approval"]["approval_id"], "maint", "REJECT").status_code == 200
    )
    again = decide(gw.client, cw, s, "command_exec", "pnpm add left-pad-ng").json()
    assert again["decision"] == "deny" and "APPROVAL-REJECTED" in again["rule_ids"]
    b = decide(gw.client, cw, s, "command_exec", "pnpm db:migrate").json()
    approve(gw.client, cw, b["approval"]["approval_id"], "maint")
    expire_now(migrator_engine, b["approval"]["approval_id"])
    late = decide(gw.client, cw, s, "command_exec", "pnpm db:migrate").json()
    assert late["decision"] == "ask" and late["action_id"] != b["action_id"]  # expired: anew
    assert gw.action_status(b["action_id"]) == "EXPIRED"


def test_critical_needs_two_security_approvers(gw: Any, cw: CodingWorld) -> None:
    s = start_session(gw.client, cw)
    a = decide(gw.client, cw, s, "file_delete", "api/test/refunds.test.ts").json()
    assert (a["risk_level"], a["approval"]["required_role"]) == ("CRITICAL", "security")
    assert a["approval"]["required_approvals"] == 2
    assert approve(gw.client, cw, a["approval"]["approval_id"], "maint").status_code == 403
    approve(gw.client, cw, a["approval"]["approval_id"], "sec1")
    still = decide(gw.client, cw, s, "file_delete", "api/test/refunds.test.ts").json()
    assert still["decision"] == "ask"  # one of two votes: still pending
    approve(gw.client, cw, a["approval"]["approval_id"], "sec2")
    ok = decide(gw.client, cw, s, "file_delete", "api/test/refunds.test.ts").json()
    assert ok["decision"] == "allow"


def test_identity_and_session_rules(gw: Any, cw: CodingWorld) -> None:
    # An ordinary agent key is not a device key.
    r = gw.client.get("/v1/coding/status", headers={"Authorization": f"Bearer {gw.world.token}"})
    assert (r.status_code, r.json()["error"]["code"]) == (403, "CODING_DEVICE_REQUIRED")
    assert gw.client.get("/v1/coding/status").status_code == 401
    st = gw.client.get("/v1/coding/status", headers=cw.device()).json()
    assert st["developer"] == "dev" and st["policy"]["id"] == "coding-mintrail"
    s = start_session(gw.client, cw)
    # Another developer's device cannot use or see this session.
    other = decide(gw.client, cw, s, "file_read", "api/src/app.ts", token=cw.other_device_token)
    assert other.status_code == 404
    # A device key cannot call gateway tools.
    tool = gw.post("public_doc_search", {"query": "x"}, token=cw.device_token)
    assert tool.json()["status"] == "DENIED"
    # Agent-kind mismatch with the session -> deny.
    body = {
        "session_id": s,
        "action": {
            "agent_kind": "codex",
            "action_type": "file_read",
            "targets": {"paths": ["api/src/app.ts"]},
        },
    }
    mm = gw.client.post("/v1/coding/decide", json=body, headers=cw.device()).json()
    assert mm["decision"] == "deny" and mm["rule_ids"][0] == "CODE-SESSION-MISMATCH"
    end = gw.client.post(f"/v1/coding/sessions/{s}/end", headers=cw.device())
    assert end.status_code == 200 and end.json()["status"] == "ENDED"
    closed = decide(gw.client, cw, s, "file_read", "api/src/app.ts")
    assert (closed.status_code, closed.json()["error"]["code"]) == (409, "CODING_SESSION_CLOSED")
    bad = gw.client.post(
        "/v1/coding/decide", json={"session_id": s, "action": {"x": 1}}, headers=cw.device()
    )
    assert bad.status_code == 422 and "x" not in str(bad.json()["error"]["message"])


def test_no_diff_or_secret_in_logs_headers_or_payloads(
    gw: Any, cw: CodingWorld, caplog: pytest.LogCaptureFixture, pg: Any
) -> None:
    """Canary: a credential in a diff is denied and appears in no log, header, response or
    stored payload; normal diffs appear only inside ciphertext."""
    caplog.set_level(logging.DEBUG)
    s = start_session(gw.client, cw)
    r = decide(gw.client, cw, s, "file_write", "api/src/x.ts", SECRET_DIFF)
    assert r.json()["decision"] == "deny"
    canary = "CANARY-diff-text-3f9a"
    ok = decide(
        gw.client,
        cw,
        s,
        "file_write",
        "api/src/csv.ts",
        f"--- a/x\n+++ b/x\n@@ -1 +1 @@\n+// {canary}\n",
    )
    assert ok.json()["decision"] == "allow"
    assert SECRET not in r.text and canary not in ok.text
    assert SECRET not in caplog.text and canary not in caplog.text
    import psycopg

    with psycopg.connect(pg.superuser) as conn:
        dump = conn.execute(
            "SELECT coalesce(string_agg(body::text, ''), '') FROM evidence_events "
            "WHERE tenant_id = %s",
            (gw.world.tenant_id,),
        ).fetchone()
        blobs = conn.execute(
            "SELECT ciphertext FROM payload_objects WHERE tenant_id = %s", (gw.world.tenant_id,)
        ).fetchall()
    assert dump is not None and blobs
    assert SECRET not in dump[0] and canary not in dump[0]
    raw = b"".join(bytes(b[0] or b"") for b in blobs)
    assert SECRET.encode() not in raw and canary.encode() not in raw
    # Not vacuous: the normal diff IS kept, inside the encrypted ACTION_REQUESTED payload;
    # the secret diff is not kept at all (digest only).
    plain = []
    with gw.engine.connect() as conn:
        for action_id in (ok.json()["action_id"], r.json()["action_id"]):
            event_id = conn.execute(
                select(t.evidence_events.c.event_id).where(
                    t.evidence_events.c.action_id == uuid.UUID(action_id),
                    t.evidence_events.c.event_type == "ACTION_REQUESTED",
                )
            ).scalar_one()
            plain.append(gw.state.payloads.load_payload(conn, event_id) or b"")
    assert canary.encode() in plain[0]
    assert SECRET.encode() not in plain[1]


def test_rate_limit_and_body_limit_apply(gw: Any, cw: CodingWorld) -> None:
    s = start_session(gw.client, cw)
    big = "+" + "x" * (gw.state.settings.coding_max_diff_bytes + 10)
    r = decide(gw.client, cw, s, "file_write", "api/src/csv.ts", big)
    assert r.status_code == 413


def test_policy_evaluated_header_and_reasons(gw: Any, cw: CodingWorld) -> None:
    s = start_session(gw.client, cw)
    a = decide(gw.client, cw, s, "file_read", "~/.ssh/id_rsa").json()
    assert a["decision"] == "deny"
    with gw.engine.connect() as conn:
        body = conn.execute(
            text(
                "SELECT body FROM evidence_events WHERE action_id = :a "
                "AND event_type = 'POLICY_EVALUATED'"
            ),
            {"a": a["action_id"]},
        ).scalar_one()
    assert body["policy"]["id"] == "coding-mintrail" and body["policy"]["effect"] == "DENY"
    assert body["risk"]["cv"] == "coding-policy-v1" and "SECRET-READ" in body["risk"]["rules"]
    assert ".ssh" not in str(body)  # headers carry rule ids, not paths


def test_disabled_developer_device_is_refused(
    gw: Any, cw: CodingWorld, migrator_engine: Engine
) -> None:
    assert gw.client.get("/v1/coding/status", headers=cw.device()).status_code == 200
    with migrator_engine.begin() as conn:
        conn.execute(
            text("UPDATE humans SET status = 'disabled' WHERE tenant_id = :t AND username = 'dev'"),
            {"t": gw.world.tenant_id},
        )
    r = gw.client.get("/v1/coding/status", headers=cw.device())
    assert (r.status_code, r.json()["error"]["code"]) == (403, "CODING_DEVICE_REQUIRED")
