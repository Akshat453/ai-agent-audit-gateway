"""Phase 5 approval workflow (ADR-0027): happy path, reject, roles, sessions, expiry, sweeper,
fail-closed signer, evidence shape, sealing, privileges. Named attacks: test_approval_attacks.py.
"""

from __future__ import annotations

import io
import threading
import time
import uuid
from typing import Any

import pytest
from sqlalchemy import Engine, select, text, update
from sqlalchemy.exc import DBAPIError

from agw_gateway.approvals.signing import verify_decision
from agw_gateway.crypto.canonical import decode
from agw_gateway.db import tables as t
from agw_gateway.evidence import EvidenceWriter
from agw_gateway.evidence.export import export_chain
from agw_verifier.chain import verify_lines
from agw_worker.sealing import Sealer
from agw_worker.sealing.policy import SealPolicy

from ..approvalkit import (
    EXTERNAL,
    PASSWORD,
    Humans,
    approval_row,
    count,
    decide,
    email,
    expire_now,
    make_humans,
    no_auto_authorize,
    view,
)

pytestmark = pytest.mark.e2e


@pytest.fixture
def humans(gw: Any, migrator_engine: Engine) -> Humans:
    return make_humans(migrator_engine, gw.client, gw.world.tenant_id)


def headers_of(gw: Any, action_id: str) -> list[tuple[str, str | None, dict[str, Any]]]:
    with gw.engine.connect() as conn:
        rows = conn.execute(
            select(
                t.evidence_events.c.event_type,
                t.evidence_events.c.risk_level,
                t.evidence_events.c.canonical_bytes,
            )
            .where(t.evidence_events.c.action_id == uuid.UUID(action_id))
            .order_by(t.evidence_events.c.seq)
        ).all()
    return [(r.event_type, r.risk_level, decode(bytes(r.canonical_bytes))) for r in rows]


# --------------------------------------------------------------------------- happy path
def test_high_email_pending_then_approved_then_executed_exactly(gw: Any, humans: Humans) -> None:
    action_id, approval_id = email(gw)
    assert approval_id is not None
    assert gw.action_status(action_id) == "PENDING_APPROVAL"
    gw.drain()
    assert gw.spies.email.calls == []  # nothing runs without approval (INV-2)
    assert gw.events(action_id) == ["ACTION_REQUESTED", "POLICY_EVALUATED", "APPROVAL_REQUIRED"]

    listed = gw.client.get("/v1/approvals?state=PENDING", headers=humans.headers("alice")).json()
    assert approval_id in [a["approval_id"] for a in listed["approvals"]]

    shown = view(gw, humans, approval_id)
    assert shown["action"]["tool"] == {"id": "send_email", "version": "1.0.0"}
    assert "bob@partner.example" in shown["action"]["args_rendered"]
    assert "bob@partner.example" in shown["action"]["target_rendered"]
    assert shown["action"]["risk"]["level"] == "HIGH"
    assert shown["action"]["risk"]["reasons"]  # risk reasons are shown to the approver
    assert shown["action"]["agent"]["name"] == "demo-agent"
    with gw.engine.connect() as conn:
        stored = conn.execute(
            select(t.actions.c.action_digest).where(t.actions.c.action_id == uuid.UUID(action_id))
        ).scalar_one()
    assert shown["action_digest"] == bytes(stored).hex()
    assert len(shown["nonce"]) == 32

    r = decide(gw, humans, approval_id, shown=shown)
    assert r.status_code == 200, r.text
    assert r.json()["state"] == "APPROVED"
    assert r.json()["authorization"] == {"result": "AUTHORIZED", "code": None}
    assert r.json()["action_status"] == "AUTHORIZED"
    gw.drain()
    assert gw.spies.email.calls == [uuid.UUID(action_id)]
    assert gw.action_status(action_id) == "COMPLETED"
    assert approval_row(gw.engine, approval_id).state == "CONSUMED"
    with gw.engine.connect() as conn:  # sealed request kept only while pending
        assert (
            conn.execute(
                select(t.actions.c.request_args_sealed).where(
                    t.actions.c.action_id == uuid.UUID(action_id)
                )
            ).scalar_one()
            is None
        )
    assert count(gw.engine, t.approval_uses, approval_id=uuid.UUID(approval_id)) == 1

    events = headers_of(gw, action_id)
    assert [e[0] for e in events] == [
        "ACTION_REQUESTED",
        "POLICY_EVALUATED",
        "APPROVAL_REQUIRED",
        "APPROVAL_GRANTED",
        "POLICY_EVALUATED",  # dispatch-time re-evaluation
        "ACTION_AUTHORIZED",
        "ACTION_DISPATCHED",
        "ACTION_COMPLETED",
    ]
    required, granted, authorized = events[2][2], events[3][2], events[5][2]
    digest = bytes(stored)
    assert required["approval"] == {
        "id": uuid.UUID(approval_id).bytes,
        "binding": digest,
        "exp": required["approval"]["exp"],
        "req": 1,
    }
    assert granted["actor"] == {"kind": "human", "id": humans.ids["alice"]}
    assert granted["approval"]["dec"] == "APPROVED" and granted["approval"]["votes"] == 1
    assert granted["approval"]["binding"] == digest
    signer = gw.state.approvals.signer
    assert verify_decision(signer.public_raw, granted["approval"]["dd"], granted["approval"]["sig"])
    decs = authorized["approval"]["decs"]
    assert [(d["approver"], d["dd"], d["sig"]) for d in decs] == [
        (humans.ids["alice"], granted["approval"]["dd"], granted["approval"]["sig"])
    ]
    assert authorized["args"] == events[6][2]["args"]  # dispatched args == approved args
    # approval events are HIGH -> sealed immediately (Phase 4)
    assert {lvl for typ, lvl, _ in events if typ.startswith("APPROVAL")} == {"HIGH"}

    # whole chain still verifies offline with the new event types
    buf = io.StringIO()
    export_chain(gw.engine, gw.world.tenant_id, buf, store=gw.state.payloads)
    assert verify_lines(buf.getvalue().splitlines()).result == "VERIFIED"


def test_reject_denies_and_never_executes(gw: Any, humans: Humans) -> None:
    action_id, approval_id = email(gw)
    assert approval_id
    r = decide(gw, humans, approval_id, "REJECT", reason="external recipient not expected")
    assert r.status_code == 200 and r.json()["state"] == "REJECTED"
    gw.drain()
    assert gw.spies.email.calls == []
    assert gw.action_status(action_id) == "DENIED"
    events = headers_of(gw, action_id)
    assert events[-1][0] == "APPROVAL_DENIED"
    assert events[-1][2]["outcome"] == {"status": "DENIED", "code": "APPROVAL_REJECTED"}
    assert events[-1][2]["approval"]["dec"] == "REJECTED"


def test_approval_sealed_with_risk_trigger(gw: Any, humans: Humans) -> None:
    _, approval_id = email(gw)
    assert approval_id
    sealer = Sealer(
        engine=gw.engine,
        writer=EvidenceWriter(),
        crash=gw.state.crash,
        policy=SealPolicy.adaptive(),
    )
    sealer.drain()
    assert decide(gw, humans, approval_id).status_code == 200
    sealer.drain()
    with gw.engine.connect() as conn:
        granted_seq = conn.execute(
            select(t.evidence_events.c.seq).where(
                t.evidence_events.c.tenant_id == gw.world.tenant_id,
                t.evidence_events.c.event_type == "APPROVAL_GRANTED",
            )
        ).scalar_one()
        epoch = conn.execute(
            select(t.epochs.c.seal_reason, t.epochs.c.anchor_priority).where(
                t.epochs.c.tenant_id == gw.world.tenant_id,
                t.epochs.c.first_seq <= granted_seq,
                t.epochs.c.last_seq >= granted_seq,
            )
        ).one()
    assert epoch.seal_reason == "RISK_HIGH" and epoch.anchor_priority == "PRIORITY"


# --------------------------------------------------------------------------- roles, sessions
def test_auditor_can_view_but_not_decide(gw: Any, humans: Humans) -> None:
    action_id, approval_id = email(gw)
    assert approval_id
    shown = view(gw, humans, approval_id, who="audrey")
    r = decide(gw, humans, approval_id, who="audrey", shown=shown)
    assert r.status_code == 403 and r.json()["error"]["code"] == "FORBIDDEN"
    assert gw.action_status(action_id) == "PENDING_APPROVAL"


def test_login_failures_are_uniform_and_logout_revokes(
    gw: Any, humans: Humans, migrator_engine: Engine
) -> None:
    tenant = gw.world.tenant_id
    bad = [
        {"tenant": tenant, "username": "alice", "password": "wrong-password-123"},
        {"tenant": tenant, "username": "nobody", "password": PASSWORD},
        {"tenant": "t-other", "username": "alice", "password": PASSWORD},
    ]
    for body in bad:
        r = gw.client.post("/v1/auth/login", json=body)
        assert r.status_code == 401
        assert r.json()["error"]["code"] == "UNAUTHENTICATED"
        assert r.headers["WWW-Authenticate"] == "Session"
    with migrator_engine.begin() as conn:
        conn.execute(
            update(t.humans)
            .where(t.humans.c.tenant_id == tenant, t.humans.c.username == "bob")
            .values(status="disabled")
        )
    assert gw.client.get("/v1/approvals", headers=humans.headers("bob")).status_code == 401
    r = gw.client.post(
        "/v1/auth/login", json={"tenant": tenant, "username": "bob", "password": PASSWORD}
    )
    assert r.status_code == 401
    assert gw.client.post("/v1/auth/logout", headers=humans.headers("alice")).status_code == 204
    assert gw.client.get("/v1/approvals", headers=humans.headers("alice")).status_code == 401
    assert (
        gw.client.get("/v1/approvals", headers={"Authorization": "Session junk"}).status_code == 401
    )
    assert gw.client.get("/v1/approvals").status_code == 401


def test_agent_and_human_credentials_are_disjoint(gw: Any, humans: Humans) -> None:
    # An agent key under the human scheme is not a session.
    r = gw.client.get("/v1/approvals", headers={"Authorization": f"Session {gw.world.token}"})
    assert r.status_code == 401
    # A human session is not an agent credential, under either scheme.
    for scheme in ("Bearer", "Session"):
        r = gw.client.post(
            "/v1/actions",
            json={
                "run_id": str(uuid.uuid4()),
                "tool": "send_email",
                "environment": "dev",
                "args": {"to": EXTERNAL, "subject": "s"},
            },
            headers={
                "Authorization": f"{scheme} {humans.sessions['alice']}",
                "Idempotency-Key": "k1",
            },
        )
        assert r.status_code == 401


def test_password_policy_and_role_validation(migrator_engine: Engine, gw: Any) -> None:
    from agw_gateway.admin import ensure_human

    with pytest.raises(ValueError):
        ensure_human(migrator_engine, gw.world.tenant_id, "shorty", "short", ["approver"])
    with pytest.raises(SystemExit):
        ensure_human(migrator_engine, gw.world.tenant_id, "x", PASSWORD, ["root"])
    with pytest.raises(SystemExit):
        ensure_human(migrator_engine, gw.world.tenant_id, "x", PASSWORD, [])


# --------------------------------------------------------------------------- agent view
def test_agent_sees_approval_state_but_never_the_nonce(gw: Any, humans: Humans) -> None:
    action_id, approval_id = email(gw)
    a = gw.client.get(f"/v1/actions/{action_id}", headers=gw.headers()).json()
    assert a["status"] == "PENDING_APPROVAL"
    assert a["approval"]["approval_id"] == approval_id and a["approval"]["state"] == "PENDING"
    assert "nonce" not in str(a) and view(gw, humans, approval_id)["nonce"] not in str(a)


def test_long_poll_returns_when_status_changes(gw: Any, humans: Humans) -> None:
    action_id, approval_id = email(gw)
    assert approval_id
    shown = view(gw, humans, approval_id)

    def approve_later() -> None:
        time.sleep(0.5)
        decide(gw, humans, approval_id, shown=shown)

    th = threading.Thread(target=approve_later)
    th.start()
    started = time.monotonic()
    r = gw.client.get(f"/v1/actions/{action_id}?wait=10", headers=gw.headers())
    th.join()
    assert r.status_code == 200 and r.json()["status"] == "AUTHORIZED"
    assert time.monotonic() - started < 8
    # no change -> returns after the wait with the same status
    gw.drain()
    r = gw.client.get(f"/v1/actions/{action_id}?wait=0.3", headers=gw.headers())
    assert r.json()["status"] == "COMPLETED"


def test_timeline_shows_approval_steps(gw: Any, humans: Humans) -> None:
    run_id = str(uuid.uuid4())
    _, approval_id = email(gw, run_id=run_id)
    assert approval_id and decide(gw, humans, approval_id).status_code == 200
    gw.drain()
    events = gw.client.get(f"/v1/runs/{run_id}/timeline", headers=gw.headers()).json()["events"]
    by_type = {e["type"]: e for e in events}
    assert by_type["APPROVAL_REQUIRED"]["approval"]["req"] == 1
    assert by_type["APPROVAL_GRANTED"]["approval"]["dec"] == "APPROVED"
    assert by_type["APPROVAL_GRANTED"]["approval"]["approver"] == humans.ids["alice"]
    assert by_type["ACTION_AUTHORIZED"]["approval"]["approvers"] == [humans.ids["alice"]]


# --------------------------------------------------------------------------- expiry, sweeper
def test_sweeper_expires_pending_approval(gw: Any, humans: Humans, migrator_engine: Engine) -> None:
    action_id, approval_id = email(gw)
    assert approval_id
    expire_now(migrator_engine, approval_id)
    assert gw.state.approvals.sweep() >= 1
    assert approval_row(gw.engine, approval_id).state == "EXPIRED"
    assert gw.action_status(action_id) == "EXPIRED"
    assert gw.events(action_id)[-1] == "APPROVAL_EXPIRED"
    a = gw.client.get(f"/v1/actions/{action_id}", headers=gw.headers()).json()
    assert a["approval"]["state"] == "EXPIRED"
    gw.drain()
    assert gw.spies.email.calls == []


def test_sweeper_authorizes_an_approval_left_approved_by_a_crash(gw: Any, humans: Humans) -> None:
    action_id, approval_id = email(gw)
    assert approval_id
    with no_auto_authorize(gw):
        assert decide(gw, humans, approval_id).json()["state"] == "APPROVED"
    assert gw.action_status(action_id) == "PENDING_APPROVAL"
    gw.state.approvals.sweep()
    assert gw.action_status(action_id) == "AUTHORIZED"
    gw.drain()
    assert gw.spies.email.calls == [uuid.UUID(action_id)]


def test_signing_key_unavailable_fails_closed(
    gw: Any, humans: Humans, migrator_engine: Engine
) -> None:
    action_id, approval_id = email(gw)
    assert approval_id
    approvals = gw.state.approvals
    signer, approvals._signer = approvals._signer, None
    try:
        r = decide(gw, humans, approval_id)
        assert r.status_code == 503 and r.json()["error"]["code"] == "DEPENDENCY_UNAVAILABLE"
        assert count(gw.engine, t.approval_decisions, approval_id=uuid.UUID(approval_id)) == 0
        assert gw.action_status(action_id) == "PENDING_APPROVAL"  # stays pending...
        expire_now(migrator_engine, approval_id)
        approvals.sweep()
        assert gw.action_status(action_id) == "EXPIRED"  # ...then expires
    finally:
        approvals._signer = signer
    gw.drain()
    assert gw.spies.email.calls == []


def test_approved_but_no_key_at_authorization_fails_closed(gw: Any, humans: Humans) -> None:
    _action_id, approval_id = email(gw)
    assert approval_id
    with no_auto_authorize(gw):
        decide(gw, humans, approval_id)
    approvals = gw.state.approvals
    signer, approvals._signer = approvals._signer, None
    try:
        res = approvals.authorize(uuid.UUID(approval_id))
    finally:
        approvals._signer = signer
    assert (res.result, res.code) == ("DENIED", "DECISION_SIGNATURE_INVALID")
    gw.drain()
    assert gw.spies.email.calls == []


# --------------------------------------------------------------------------- privileges
def test_app_role_cannot_rewrite_the_binding_or_forge_humans(gw: Any, humans: Humans) -> None:
    _, approval_id = email(gw)
    assert approval_id
    decide(gw, humans, approval_id)
    attempts = [
        "UPDATE approvals SET action_digest = '\\x00'::bytea WHERE approval_id = :a",
        "UPDATE approvals SET nonce = '\\x00'::bytea WHERE approval_id = :a",
        "UPDATE approvals SET expires_at = now() + interval '1 year' WHERE approval_id = :a",
        "UPDATE approvals SET action_id = gen_random_uuid() WHERE approval_id = :a",
        "UPDATE approvals SET required_approvals = 1 WHERE approval_id = :a",
        "UPDATE approval_decisions SET decision = 'APPROVED' WHERE approval_id = :a",
        "DELETE FROM approval_decisions WHERE approval_id = :a",
        "DELETE FROM approval_uses WHERE approval_id = :a",
        "UPDATE humans SET roles = ARRAY['approver'] WHERE tenant_id <> ''",
        "INSERT INTO humans (human_id, tenant_id, username, password_hash, roles) VALUES "
        "(gen_random_uuid(), 'x', 'mallory', '$argon2id$x', ARRAY['approver'])",
    ]
    for sql in attempts:
        with pytest.raises(DBAPIError) as err, gw.engine.begin() as conn:
            conn.execute(text(sql), {"a": approval_id})
        assert getattr(err.value.orig, "sqlstate", None) in {"42501", "P0001"}, sql


def test_signing_keys_endpoint_publishes_the_public_key(gw: Any, humans: Humans) -> None:
    keys = gw.client.get("/v1/approvals-signing-keys", headers=humans.headers("audrey")).json()
    signer = gw.state.approvals.signer
    assert {
        "key_id": signer.key_id,
        "algorithm": "Ed25519",
        "public_key": signer.public_raw.hex(),
    } in keys["keys"]


def test_decision_body_is_strict(gw: Any, humans: Humans) -> None:
    action_id, approval_id = email(gw)
    shown = view(gw, humans, approval_id or "")
    for extra in ({"args": {"to": ["eve@x.example"]}}, {"approver_id": humans.ids["bob"]}):
        r = decide(gw, humans, approval_id or "", shown=shown, **extra)
        assert r.status_code == 422
    r = decide(gw, humans, approval_id or "", shown=shown, decision="MAYBE")
    assert r.status_code == 422
    assert gw.action_status(action_id) == "PENDING_APPROVAL"


def test_unknown_approval_is_404(gw: Any, humans: Humans) -> None:
    missing = str(uuid.uuid4())
    assert (
        gw.client.get(f"/v1/approvals/{missing}", headers=humans.headers("alice")).status_code
        == 404
    )
    r = gw.client.post(
        f"/v1/approvals/{missing}/decision",
        json={"decision": "APPROVE", "action_digest": "0" * 64, "nonce": "0" * 32},
        headers=humans.headers("alice"),
    )
    assert r.status_code == 404


def test_approval_required_is_sealed_as_high_or_above(gw: Any) -> None:
    r = gw.post(
        "export_customer_data",
        {"destination": "s3://exports.corp.example/x", "limit": 10, "fields": ["id"]},
    )
    body = r.json()
    assert body["status"] == "PENDING_APPROVAL"
    levels = {
        lvl for typ, lvl, _ in headers_of(gw, body["action_id"]) if typ == "APPROVAL_REQUIRED"
    }
    assert levels and levels <= {"HIGH", "CRITICAL"}
