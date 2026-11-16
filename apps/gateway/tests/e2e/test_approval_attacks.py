"""Phase 5 named approval attacks (ADR-0027, INV-11). Each test is one attack; each records
(attempts, unauthorized executions) into the attack table. Reused by Phase 10 RQ4.

    AGW_ATTACK_TABLE_OUT=experiments/approvals/results/attack-table.md \\
        uv run pytest apps/gateway/tests/e2e/test_approval_attacks.py

"Unauthorized execution" = a spy-adapter invocation for an action that was not authorized by a
valid, unexpired, single-use approval of exactly that action. Every row must be 0.
"""

from __future__ import annotations

import contextlib
import threading
import uuid
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, insert, select, text, update
from sqlalchemy.exc import DBAPIError, IntegrityError

from agw_gateway.admin import create_key, ensure_agent, ensure_tenant
from agw_gateway.api.app import build_state, create_app
from agw_gateway.db import create_db_engine
from agw_gateway.db import tables as t
from agw_gateway.policies.default_policy import DEFAULT_POLICY_V2
from agw_gateway.privacy.cipher import ops_context

from ..approvalkit import (
    EXTERNAL,
    AttackLog,
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
from ..conftest import ALL_SCOPES, Gw, make_registry, make_settings, make_spies

pytestmark = pytest.mark.e2e


@pytest.fixture(scope="module")
def attacks() -> Iterator[AttackLog]:
    log = AttackLog()
    yield log
    log.write()


@pytest.fixture
def humans(gw: Any, migrator_engine: Engine) -> Humans:
    return make_humans(migrator_engine, gw.client, gw.world.tenant_id)


def approved_not_authorized(gw: Any, humans: Humans, **kw: Any) -> tuple[str, str]:
    action_id, approval_id = email(gw, **kw)
    assert approval_id is not None
    with no_auto_authorize(gw):
        assert decide(gw, humans, approval_id).json()["state"] == "APPROVED"
    return action_id, approval_id


def tamper_action(migrator: Engine, action_id: str, gw: Any = None, **values: Any) -> None:
    """Insider DB write. ``request_args`` is re-sealed as an insider who ALSO holds the KEK
    would do (Phase 7): the attack must still fail on the digest, not on the encryption."""
    if "request_args" in values:
        assert gw is not None
        values["request_args_sealed"] = gw.state.cipher.seal_json(
            ops_context(gw.world.tenant_id, "request_args", uuid.UUID(action_id).bytes),
            values.pop("request_args"),
        )
    with migrator.begin() as conn:
        conn.execute(
            update(t.actions).where(t.actions.c.action_id == uuid.UUID(action_id)).values(**values)
        )


# --------------------------------------------------------------------------- A1-A3 alter
@pytest.mark.parametrize(
    ("name", "change"),
    [
        (
            "A1 approve, then alter args (subject)",
            {"request_args": {"to": EXTERNAL, "subject": "PAYROLL DUMP"}},
        ),
        (
            "A2 approve, then alter target (recipient)",
            {"request_args": {"to": ["eve@attacker.example"], "subject": "quarterly report"}},
        ),
        ("A3 approve, then alter tool version", {"tool_version": "9.9.9"}),
        ("A3b approve, then alter environment", {"environment": "prod"}),
        ("A3c approve, then lower recorded risk", {"risk_level": "LOW"}),
    ],
)
def test_alter_after_approval_is_digest_mismatch(
    gw: Any,
    humans: Humans,
    migrator_engine: Engine,
    attacks: AttackLog,
    name: str,
    change: dict[str, Any],
) -> None:
    action_id, approval_id = approved_not_authorized(gw, humans)
    tamper_action(migrator_engine, action_id, gw, **change)  # insider rewrites the request
    res = gw.state.approvals.authorize(uuid.UUID(approval_id))
    assert (res.result, res.code) == ("DENIED", "APPROVAL_BINDING_MISMATCH")
    gw.drain()
    assert gw.spies.email.calls == []
    assert gw.action_status(action_id) == "DENIED"
    assert approval_row(gw.engine, approval_id).state == "INVALIDATED"
    assert gw.events(action_id)[-1] == "ACTION_DENIED"
    attacks.add(name, 1, len(gw.spies.email.calls), "digest recomputed from stored request")


def test_altered_recipient_resubmitted_needs_new_approval(
    gw: Any, humans: Humans, attacks: AttackLog
) -> None:
    """Demo scenario: first email approved and sent; the agent then asks again with a
    different recipient and tries to ride on the first approval."""
    first, first_ap = email(gw)
    assert first_ap
    shown_first = view(gw, humans, first_ap)
    decide(gw, humans, first_ap, shown=shown_first)
    gw.drain()
    assert gw.spies.email.calls == [uuid.UUID(first)]

    second, second_ap = email(gw, to=["eve@attacker.example"])
    assert second_ap and second_ap != first_ap
    assert gw.action_status(second) == "PENDING_APPROVAL"
    attempts = 0
    # (a) decide the new approval while echoing what was shown for the FIRST one
    attempts += 1
    r = decide(gw, humans, second_ap, shown=shown_first)
    assert r.status_code == 409 and r.json()["error"]["code"] == "APPROVAL_STALE"
    # (b) re-run authorization of the consumed first approval
    attempts += 1
    assert gw.state.approvals.authorize(uuid.UUID(first_ap)).result == "NOOP"
    gw.drain()
    unauthorized = gw.spies.email.calls.count(uuid.UUID(second))
    assert unauthorized == 0 and gw.action_status(second) == "PENDING_APPROVAL"
    assert view(gw, humans, second_ap)["action_digest"] != shown_first["action_digest"]
    attacks.add(
        "A4 approve, then resubmit with altered recipient",
        attempts,
        unauthorized,
        "new action -> new digest + new approval",
    )


# --------------------------------------------------------------------------- A5 replay
def test_replay_consumed_approval_for_identical_request(
    gw: Any, humans: Humans, attacks: AttackLog
) -> None:
    first, first_ap = email(gw)
    assert first_ap
    decide(gw, humans, first_ap)
    gw.drain()
    second, second_ap = email(gw)  # byte-identical request, new idempotency key
    assert second_ap
    old, new = view(gw, humans, first_ap), view(gw, humans, second_ap)
    assert old["action_digest"] == new["action_digest"]  # same digest: action_id is not in it
    assert old["nonce"] != new["nonce"]  # ...so the nonce/approval row is what stops replay
    attempts = 0
    attempts += 1  # (a) decide the consumed approval again
    r = decide(gw, humans, first_ap, shown=old)
    assert r.status_code == 409 and r.json()["error"]["code"] == "APPROVAL_NOT_PENDING"
    attempts += 1  # (b) authorize the consumed approval again
    assert gw.state.approvals.authorize(uuid.UUID(first_ap)).result == "NOOP"
    attempts += 1  # (c) app-role insider re-points the consumed approval at the new action
    with pytest.raises(DBAPIError) as err, gw.engine.begin() as conn:
        conn.execute(
            update(t.approvals)
            .where(t.approvals.c.approval_id == uuid.UUID(first_ap))
            .values(action_id=uuid.UUID(second))
        )
    assert err.value.orig.sqlstate == "42501"  # type: ignore[union-attr]
    attempts += 1  # (d) app-role insider resets the consumed approval to APPROVED
    with gw.engine.begin() as conn:
        conn.execute(
            update(t.approvals)
            .where(t.approvals.c.approval_id == uuid.UUID(first_ap))
            .values(state="APPROVED")
        )
    res = gw.state.approvals.authorize(uuid.UUID(first_ap))
    assert (res.result, res.code) == ("DENIED", "ACTION_NOT_PENDING")  # first already ran
    attempts += 1  # (e) second use of the nonce at the constraint level
    with pytest.raises(IntegrityError), gw.engine.begin() as conn:
        conn.execute(
            insert(t.approval_uses).values(
                nonce=bytes.fromhex(old["nonce"]),
                approval_id=uuid.UUID(second_ap),
                action_id=uuid.UUID(second),
            )
        )
    gw.drain()
    unauthorized = gw.spies.email.calls.count(uuid.UUID(second))
    assert unauthorized == 0 and gw.spies.email.calls.count(uuid.UUID(first)) == 1
    attacks.add(
        "A5 replay consumed approval for identical request",
        attempts,
        unauthorized,
        "approval bound to action_id; CONSUMED; nonce PK; column grants",
    )


# --------------------------------------------------------------------------- A6 expiry
def test_expired_approval_rejected(
    gw: Any, humans: Humans, migrator_engine: Engine, attacks: AttackLog
) -> None:
    # (a) decision after expiry
    a1, ap1 = email(gw)
    assert ap1
    shown = view(gw, humans, ap1)
    expire_now(migrator_engine, ap1)
    r = decide(gw, humans, ap1, shown=shown)
    assert r.status_code == 409 and r.json()["error"]["code"] == "APPROVAL_EXPIRED"
    assert gw.action_status(a1) == "EXPIRED" and gw.events(a1)[-1] == "APPROVAL_EXPIRED"
    # (b) approved in time, expired before the authorization step ran
    a2, ap2 = approved_not_authorized(gw, humans)
    expire_now(migrator_engine, ap2)
    res = gw.state.approvals.authorize(uuid.UUID(ap2))
    assert (res.result, res.code) == ("EXPIRED", "APPROVAL_EXPIRED")
    assert gw.action_status(a2) == "EXPIRED"
    # (c) decision on an approval the sweeper already expired
    _a3, ap3 = email(gw)
    assert ap3
    shown3 = view(gw, humans, ap3)
    expire_now(migrator_engine, ap3)
    gw.state.approvals.sweep()
    r = decide(gw, humans, ap3, shown=shown3)
    assert r.status_code == 409 and r.json()["error"]["code"] == "APPROVAL_NOT_PENDING"
    gw.drain()
    unauthorized = len(gw.spies.email.calls)
    assert unauthorized == 0
    attacks.add("A6 use an expired approval", 3, unauthorized, "expires_at checked against DB time")


# --------------------------------------------------------------------------- A7 race
def test_twenty_concurrent_dispatch_attempts_one_execution(
    gw: Any, humans: Humans, attacks: AttackLog
) -> None:
    action_id, approval_id = approved_not_authorized(gw, humans)
    barrier = threading.Barrier(20)
    results: list[str] = []
    lock = threading.Lock()

    def attempt() -> None:
        barrier.wait()
        res = gw.state.approvals.authorize(uuid.UUID(approval_id))
        with lock:
            results.append(res.result)

    threads = [threading.Thread(target=attempt) for _ in range(20)]
    for th in threads:
        th.start()
    for th in threads:
        th.join()
    gw.drain()
    assert sorted(results) == ["AUTHORIZED"] + ["NOOP"] * 19
    assert gw.spies.email.calls == [uuid.UUID(action_id)]
    assert count(gw.engine, t.outbox_jobs, action_id=uuid.UUID(action_id), kind="DISPATCH") == 1
    assert gw.events(action_id).count("ACTION_AUTHORIZED") == 1
    attacks.add(
        "A7 20 concurrent dispatch attempts, one approval",
        20,
        len(gw.spies.email.calls) - 1,
        "approval row lock + nonce PK",
    )


# --------------------------------------------------------------------------- A8 agent as human
def test_agent_credential_on_approval_endpoints(
    gw: Any, humans: Humans, migrator_engine: Engine, attacks: AttackLog
) -> None:
    _action_id, approval_id = email(gw)
    assert approval_id
    shown = view(gw, humans, approval_id)
    # an agent that even holds a scope literally called "approver" is still not a human
    ensure_agent(migrator_engine, gw.world.tenant_id, "sneaky", (*ALL_SCOPES, "approver"))
    sneaky = create_key(migrator_engine, gw.world.tenant_id, "sneaky")
    body = {
        "decision": "APPROVE",
        "reason": "",
        "action_digest": shown["action_digest"],
        "nonce": shown["nonce"],
    }
    before = gw.count_events("SECURITY_VIOLATION")
    calls = [
        ("POST", f"/v1/approvals/{approval_id}/decision", body),
        ("GET", f"/v1/approvals/{approval_id}", None),
        ("GET", "/v1/approvals", None),
    ]
    attempts = 0
    for token in (gw.world.token, sneaky):
        for method, path, payload in calls:
            attempts += 1
            r = gw.client.request(
                method, path, json=payload, headers={"Authorization": f"Bearer {token}"}
            )
            assert r.status_code == 403 and r.json()["error"]["code"] == "AGENT_NOT_PERMITTED"
    assert gw.count_events("SECURITY_VIOLATION") == before + attempts  # every attempt recorded
    with gw.engine.connect() as conn:
        last = conn.execute(
            select(t.evidence_events.c.body)
            .where(
                t.evidence_events.c.tenant_id == gw.world.tenant_id,
                t.evidence_events.c.event_type == "SECURITY_VIOLATION",
            )
            .order_by(t.evidence_events.c.seq.desc())
            .limit(1)
        ).scalar_one()
    assert last["violation"]["kind"] == "AGENT_ON_HUMAN_ENDPOINT"
    assert last["violation"]["claimed"] == "GET /v1/approvals"
    gw.drain()
    assert approval_row(gw.engine, approval_id).state == "PENDING"
    unauthorized = len(gw.spies.email.calls)
    assert unauthorized == 0
    attacks.add(
        "A8 agent credential on decision/approval endpoints",
        attempts,
        unauthorized,
        "separate human auth scheme; 403 + SECURITY_VIOLATION",
    )


# --------------------------------------------------------------------------- A9 forged
def test_forged_decisions_rejected(
    gw: Any, humans: Humans, migrator_engine: Engine, attacks: AttackLog
) -> None:
    from agw_gateway.approvals.binding import DecisionRecord
    from agw_gateway.approvals.signing import DecisionSigner

    action_id, approval_id = email(gw)
    assert approval_id
    shown = view(gw, humans, approval_id)
    attempts = 0
    # (a) wrong nonce echo, (b) wrong digest echo
    for override in ({"nonce": "00" * 16}, {"action_digest": "00" * 32}):
        attempts += 1
        r = decide(gw, humans, approval_id, shown=shown, **override)
        assert r.status_code == 409 and r.json()["error"]["code"] == "APPROVAL_STALE"
    assert approval_row(gw.engine, approval_id).state == "PENDING"

    # (c, d) an app-role DB insider writes decision rows directly and flips the state.
    ap = approval_row(gw.engine, approval_id)

    def record(approver: str) -> DecisionRecord:
        return DecisionRecord(
            tenant=gw.world.tenant_id,
            approval_id=ap.approval_id,
            action_id=ap.action_id,
            action_digest=bytes(ap.action_digest),
            nonce=bytes(ap.nonce),
            decision="APPROVED",
            approver_id=uuid.UUID(humans.ids[approver]),
            decided_at_us=1,
            reason="",
        )

    attacker = DecisionSigner.from_seed(b"\x66" * 32)
    with gw.engine.begin() as conn:  # agw_app may INSERT keys: publication, never trust
        conn.execute(
            insert(t.approval_signing_keys).values(
                key_id=attacker.key_id, algorithm="Ed25519", public_key=attacker.public_raw
            )
        )
    forgeries = [
        # garbage signature claiming the gateway's key id
        ("bob", bytes(64), gw.state.approvals.signer.key_id),
        # a VALID signature, but by the attacker's own (DB-registered) key
        ("alice", attacker.sign(record("alice").digest()), attacker.key_id),
    ]
    for approver, sig, kid in forgeries:
        attempts += 1
        with gw.engine.begin() as conn:
            conn.execute(
                insert(t.approval_decisions).values(
                    approval_id=ap.approval_id,
                    approver_id=uuid.UUID(humans.ids[approver]),
                    decision="APPROVED",
                    reason="",
                    decided_at_us=1,
                    decision_digest=record(approver).digest(),
                    signature=sig,
                    key_id=kid,
                )
            )
            conn.execute(
                update(t.approvals)
                .where(t.approvals.c.approval_id == ap.approval_id)
                .values(state="APPROVED")
            )
        res = gw.state.approvals.authorize(ap.approval_id)
        assert (res.result, res.code) == ("DENIED", "DECISION_SIGNATURE_INVALID")
        with migrator_engine.begin() as conn:  # reset for the next forgery
            conn.execute(
                text("UPDATE actions SET status = 'PENDING_APPROVAL' WHERE action_id = :a"),
                {"a": action_id},
            )
    gw.drain()
    unauthorized = len(gw.spies.email.calls)
    assert unauthorized == 0
    attacks.add(
        "A9 forged decision (wrong nonce / wrong digest / bad or foreign signature)",
        attempts,
        unauthorized,
        "echo check; Ed25519 under the configured key only",
    )


# --------------------------------------------------------------------------- A10 cross-tenant
def test_cross_tenant_approval_rejected(
    gw: Any, humans: Humans, migrator_engine: Engine, attacks: AttackLog
) -> None:
    other = f"t-{uuid.uuid4().hex[:12]}"
    ensure_tenant(migrator_engine, other, "tenant B")
    b_humans = make_humans(migrator_engine, gw.client, other)
    action_id, approval_id = email(gw)
    assert approval_id
    shown = view(gw, humans, approval_id)
    attempts = 0
    attempts += 1  # (a) tenant B approver reads tenant A's approval
    r = gw.client.get(f"/v1/approvals/{approval_id}", headers=b_humans.headers("alice"))
    assert r.status_code == 404
    attempts += 1  # (b) tenant B approver decides it, echoing a leaked digest + nonce
    r = decide(gw, b_humans, approval_id, shown=shown)
    assert r.status_code == 404
    listed = gw.client.get("/v1/approvals", headers=b_humans.headers("alice")).json()["approvals"]
    assert approval_id not in [a["approval_id"] for a in listed]
    attempts += 1  # (c) a DB insider moves the approval into tenant B; B's approver approves
    with migrator_engine.begin() as conn:
        conn.execute(
            text("UPDATE approvals SET tenant_id = :b WHERE approval_id = :a"),
            {"b": other, "a": approval_id},
        )
    r = decide(gw, b_humans, approval_id, shown=shown)
    assert r.status_code == 200
    assert r.json()["authorization"] == {"result": "DENIED", "code": "TENANT_MISMATCH"}
    gw.drain()
    unauthorized = len(gw.spies.email.calls)
    assert unauthorized == 0 and gw.action_status(action_id) == "PENDING_APPROVAL"
    attacks.add(
        "A10 approval for tenant A used from tenant B",
        attempts,
        unauthorized,
        "tenant-scoped lookup; tenant check at authorization",
    )


# --------------------------------------------------------------------------- A11 decided/executed
def test_approving_executed_or_denied_actions_rejected(
    gw: Any, humans: Humans, migrator_engine: Engine, attacks: AttackLog
) -> None:
    attempts = 0
    # executed
    done, done_ap = email(gw)
    assert done_ap
    shown = view(gw, humans, done_ap)
    decide(gw, humans, done_ap, shown=shown)
    gw.drain()
    attempts += 1
    r = decide(gw, humans, done_ap, who="bob", shown=shown)
    assert r.status_code == 409 and r.json()["error"]["code"] == "APPROVAL_NOT_PENDING"
    # rejected (denied by a human)
    rej, rej_ap = email(gw)
    assert rej_ap
    shown = view(gw, humans, rej_ap)
    decide(gw, humans, rej_ap, "REJECT", shown=shown)
    attempts += 1
    r = decide(gw, humans, rej_ap, who="bob", shown=shown)
    assert r.status_code == 409
    # invalidated at authorization (tampered), then approved again
    inv, inv_ap = approved_not_authorized(gw, humans)
    tamper_action(migrator_engine, inv, gw, request_args={"to": ["eve@x.example"], "subject": "s"})
    gw.state.approvals.authorize(uuid.UUID(inv_ap))
    attempts += 1
    r = decide(gw, humans, inv_ap, who="bob")
    assert r.status_code == 409
    # denied by policy: there is no approval at all for it
    denied = gw.post("delete_record", {"record_id": str(uuid.uuid4())}).json()
    assert denied["status"] == "DENIED" and "approval" not in denied
    gw.drain()
    calls = gw.spies.email.calls
    unauthorized = calls.count(uuid.UUID(rej)) + calls.count(uuid.UUID(inv))
    assert calls == [uuid.UUID(done)] and gw.spies.delete.calls == []
    attacks.add(
        "A11 approve an already executed / rejected / invalidated action",
        attempts,
        unauthorized,
        "state machine: only PENDING is decidable",
    )


# --------------------------------------------------------------------------- A12 changes before dispatch
def test_scope_revoked_or_agent_disabled_between_approval_and_dispatch(
    gw: Any, humans: Humans, migrator_engine: Engine, attacks: AttackLog
) -> None:
    a1, ap1 = approved_not_authorized(gw, humans)
    with migrator_engine.begin() as conn:
        conn.execute(
            update(t.agents)
            .where(t.agents.c.agent_id == gw.world.agent_id)
            .values(scopes=[s for s in ALL_SCOPES if s != "tools:send_email"])
        )
    res = gw.state.approvals.authorize(uuid.UUID(ap1))
    assert (res.result, res.code) == ("DENIED", "POLICY_REEVALUATION_DENIED")
    assert gw.events(a1)[-2:] == ["POLICY_EVALUATED", "ACTION_DENIED"]
    with migrator_engine.begin() as conn:
        conn.execute(
            update(t.agents)
            .where(t.agents.c.agent_id == gw.world.agent_id)
            .values(scopes=list(ALL_SCOPES))
        )
    _a2, ap2 = approved_not_authorized(gw, humans)
    with migrator_engine.begin() as conn:
        conn.execute(
            update(t.agents)
            .where(t.agents.c.agent_id == gw.world.agent_id)
            .values(status="disabled")
        )
    try:
        res = gw.state.approvals.authorize(uuid.UUID(ap2))
        assert (res.result, res.code) == ("DENIED", "AGENT_INACTIVE")
    finally:
        with migrator_engine.begin() as conn:
            conn.execute(
                update(t.agents)
                .where(t.agents.c.agent_id == gw.world.agent_id)
                .values(status="active")
            )
    gw.drain()
    unauthorized = len(gw.spies.email.calls)
    assert unauthorized == 0
    attacks.add(
        "A12b scope revoked / agent disabled after approval",
        2,
        unauthorized,
        "re-evaluation with current agent row",
    )


def test_risk_increase_after_approval_requires_new_approval(
    gw: Any, humans: Humans, monkeypatch: pytest.MonkeyPatch, attacks: AttackLog
) -> None:
    """Re-evaluation that still says REQUIRE_APPROVAL but at a HIGHER level than approved
    (e.g. a CRITICAL exception) needs a new approval: stricter wins. The default policies
    have no reachable HIGH->CRITICAL-with-exception path, so the re-evaluation is wrapped."""
    import dataclasses

    import agw_gateway.approvals.service as svc
    from agw_gateway.risk.engine import RiskLevel

    _action_id, approval_id = approved_not_authorized(gw, humans)
    real = svc.decide_action

    def riskier(**kw: Any) -> Any:
        d = real(**kw)
        return dataclasses.replace(
            d,
            effect="REQUIRE_APPROVAL",
            risk=dataclasses.replace(d.risk, level=RiskLevel.CRITICAL),
        )

    monkeypatch.setattr(svc, "decide_action", riskier)
    res = gw.state.approvals.authorize(uuid.UUID(approval_id))
    assert (res.result, res.code) == ("DENIED", "RISK_INCREASED_SINCE_APPROVAL")
    gw.drain()
    unauthorized = len(gw.spies.email.calls)
    assert unauthorized == 0
    attacks.add("A12c risk rose after approval (stricter wins)", 1, unauthorized, "level re-check")


def test_four_eyes_same_person_twice_not_satisfied(
    gw: Any, humans: Humans, migrator_engine: Engine, attacks: AttackLog
) -> None:
    ensure_agent(migrator_engine, gw.world.tenant_id, "iam-admin", (*ALL_SCOPES, "iam:admin"))
    token = create_key(migrator_engine, gw.world.tenant_id, "iam-admin")
    r = gw.post("update_iam_role", {"principal": "ana", "role": "editor"}, token=token)
    body = r.json()
    assert body["status"] == "PENDING_APPROVAL" and body["decision"]["risk_level"] == "CRITICAL"
    assert body["approval"]["required_approvals"] == 2
    approval_id = body["approval"]["approval_id"]
    shown = view(gw, humans, approval_id)
    first = decide(gw, humans, approval_id, shown=shown)
    assert first.status_code == 200 and first.json()["state"] == "PENDING"  # 1 of 2
    attempts = 1
    second = decide(gw, humans, approval_id, shown=shown)  # alice again
    assert second.status_code == 409
    assert second.json()["error"]["code"] == "APPROVAL_ALREADY_DECIDED"
    gw.drain()
    unauthorized = len(gw.spies.iam.calls)
    assert unauthorized == 0 and approval_row(gw.engine, approval_id).state == "PENDING"
    # forging a second vote by re-using alice's id at the DB level hits the PK
    with pytest.raises(IntegrityError), gw.engine.begin() as conn:
        conn.execute(
            insert(t.approval_decisions).values(
                approval_id=uuid.UUID(approval_id),
                approver_id=uuid.UUID(humans.ids["alice"]),
                decision="APPROVED",
                reason="",
                decided_at_us=2,
                decision_digest=b"\x01" * 32,
                signature=bytes(64),
                key_id="0" * 16,
            )
        )
    attempts += 1
    # a DIFFERENT approver completes four-eyes -> executes exactly once
    third = decide(gw, humans, approval_id, who="bob", shown=shown)
    assert third.json()["state"] == "APPROVED"
    assert third.json()["authorization"]["result"] == "AUTHORIZED"
    gw.drain()
    assert gw.spies.iam.calls == [uuid.UUID(body["action_id"])]
    authorized = [
        e
        for e in gw.client.get(
            f"/v1/runs/{_run_of(gw, body['action_id'])}/timeline",
            headers={"Authorization": f"Bearer {token}"},
        ).json()["events"]
        if e["type"] == "ACTION_AUTHORIZED"
    ]
    assert sorted(authorized[0]["approval"]["approvers"]) == sorted(
        [humans.ids["alice"], humans.ids["bob"]]
    )
    attacks.add(
        "A13 four-eyes CRITICAL: same approver twice",
        attempts,
        unauthorized,
        "PK(approval, approver); distinct valid signatures counted",
    )


def _run_of(gw: Any, action_id: str) -> str:
    with gw.engine.connect() as conn:
        return str(
            conn.execute(
                select(t.actions.c.run_id).where(t.actions.c.action_id == uuid.UUID(action_id))
            ).scalar_one()
        )


# --------------------------------------------------------------------------- A12 policy tightened
@pytest.fixture(scope="module")
def isolated(tmp_path_factory: pytest.TempPathFactory) -> Iterator[tuple[Gw, Engine]]:
    """Own Postgres: inserting a new `default` policy version must not leak into other tests."""
    from ..conftest import World, init_database, start_postgres

    container = start_postgres()
    try:
        urls = init_database(container)
        mig = create_db_engine(urls.migrator, pool_size=2)
        app = create_db_engine(urls.app, pool_size=10)
        ensure_tenant(mig, "iso", "isolated")
        agent = ensure_agent(mig, "iso", "demo-agent", ALL_SCOPES)
        token = create_key(mig, "iso", "demo-agent")
        spies = make_spies()
        tmp = tmp_path_factory.mktemp("iso")
        state = build_state(make_settings(urls.app, tmp), engine=app, registry=make_registry(spies))
        state.sync()
        with TestClient(create_app(state, sync_registry=False)) as client:
            world = World(
                "iso", uuid.UUID(agent), token, uuid.uuid4(), "", uuid.uuid4(), "", "", "", ""
            )
            yield Gw(state=state, client=client, spies=spies, world=world, engine=app), mig
        state.executor.close()
        app.dispose()
        mig.dispose()
    finally:
        with contextlib.suppress(Exception):
            container.stop()


def test_policy_tightened_between_approval_and_dispatch(
    isolated: tuple[Gw, Engine], attacks: AttackLog
) -> None:
    gw, mig = isolated
    humans = make_humans(mig, gw.client, "iso")
    action_id, approval_id = email(gw)
    assert approval_id
    with no_auto_authorize(gw):
        assert decide(gw, humans, approval_id).json()["state"] == "APPROVED"
    tightened = {
        **DEFAULT_POLICY_V2,
        "version": 3,
        "rules": [
            *DEFAULT_POLICY_V2["rules"],
            {
                "rule_id": "deny-external-email",
                "effect": "DENY",
                "match": {"tools": ["send_email"]},
            },
        ],
    }
    with gw.engine.begin() as conn:
        conn.execute(
            insert(t.policies).values(
                policy_id="default", version=3, document=tightened, created_by="test"
            )
        )
    res = gw.state.approvals.authorize(uuid.UUID(approval_id))
    assert (res.result, res.code) == ("DENIED", "POLICY_REEVALUATION_DENIED")
    with gw.engine.connect() as conn:
        bodies = (
            conn.execute(
                select(t.evidence_events.c.body)
                .where(
                    t.evidence_events.c.action_id == uuid.UUID(action_id),
                    t.evidence_events.c.event_type == "POLICY_EVALUATED",
                )
                .order_by(t.evidence_events.c.seq)
            )
            .scalars()
            .all()
        )
    assert [(b["policy"]["ver"], b["policy"]["effect"]) for b in bodies] == [
        (2, "REQUIRE_APPROVAL"),
        (3, "DENY"),  # re-evaluated under the current version: stricter wins
    ]
    assert "deny-external-email" in bodies[1]["policy"]["rules"]
    while gw.state.executor.run_once():
        pass
    unauthorized = len(gw.spies.email.calls)
    assert unauthorized == 0 and gw.action_status(action_id) == "DENIED"
    attacks.add(
        "A12 policy tightened between approval and dispatch",
        1,
        unauthorized,
        "re-evaluation under current policy; stricter wins",
    )


def test_attack_table_written(
    tmp_path: Path, attacks: AttackLog, monkeypatch: pytest.MonkeyPatch
) -> None:
    out = tmp_path / "table.md"
    monkeypatch.setenv("AGW_ATTACK_TABLE_OUT", str(out))
    probe = AttackLog(rows=[("x", 2, 0, "y")])
    probe.write()
    assert "| x | 2 | 0 | y |" in out.read_text()
