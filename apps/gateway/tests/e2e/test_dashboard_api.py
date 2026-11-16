"""Phase 9 dashboard API (ADR-0031 §2, §4, §5): roles, tenant scoping, no payloads anywhere,
step-up for CRITICAL approvals, operator reconciliation of OUTCOME_UNKNOWN, tracing allowlist.
"""

from __future__ import annotations

import json
import uuid
from typing import Any

import pytest
from sqlalchemy import Engine, select, text

from agw_gateway.admin import create_key, ensure_agent, ensure_human
from agw_gateway.db import tables as t
from agw_gateway.execution.crash import SimulatedCrash

from ..approvalkit import EXTERNAL, PASSWORD, decide, email, make_humans, view
from ..delegationkit import delegate, new_agent
from ..privacykit import canary, event_id, payload

pytestmark = pytest.mark.e2e
READS = [
    "/v1/dashboard/config",
    "/v1/dashboard/overview",
    "/v1/dashboard/runs",
    "/v1/dashboard/events",
    "/v1/dashboard/epochs",
    "/v1/dashboard/policies",
    "/v1/dashboard/incidents",
    "/v1/dashboard/verifications",
    "/v1/dashboard/alerts",
]


@pytest.fixture
def humans(gw: Any, migrator_engine: Engine) -> Any:
    ensure_human(migrator_engine, gw.world.tenant_id, "adam", PASSWORD, ["admin"])
    return make_humans(migrator_engine, gw.client, gw.world.tenant_id)


def _get(gw: Any, humans: Any, who: str, path: str) -> Any:
    return gw.client.get(path, headers=humans.headers(who))


def test_every_dashboard_read_needs_a_human_session(gw: Any, humans: Any) -> None:
    for path in READS:
        assert gw.client.get(path).status_code == 401, path
        r = gw.client.get(path, headers={"Authorization": f"Bearer {gw.world.token}"})
        assert r.status_code == 403 and r.json()["error"]["code"] == "AGENT_NOT_PERMITTED", path
        for who in ("alice", "audrey", "adam"):
            assert _get(gw, humans, who, path).status_code == 200, (path, who)


def test_overview_runs_and_timeline_with_delegation_tree(
    gw: Any, humans: Any, migrator_engine: Engine
) -> None:
    child_id, child_token = new_agent(migrator_engine, gw.world.tenant_id, "worker")
    parent_run = str(uuid.uuid4())
    d = delegate(gw, child_id, run_id=parent_run)
    child_run = str(uuid.uuid4())
    gw.post("create_ticket", {"title": "t"}, token=child_token, run_id=child_run,
            delegation={"token": d["token"]})  # fmt: skip
    email(gw, EXTERNAL, run_id=child_run)
    gw.drain()
    ov = _get(gw, humans, "alice", "/v1/dashboard/overview").json()
    assert ov["pending_approvals"] == 1 and sum(ov["risk"].values()) >= 2
    assert ov["statuses"]["COMPLETED"] >= 1 and ov["unsealed_events"] > 0
    runs = _get(gw, humans, "alice", "/v1/dashboard/runs").json()
    assert child_run in {r["run_id"] for r in runs}
    detail = _get(gw, humans, "audrey", f"/v1/dashboard/runs/{child_run}").json()
    types = [e["type"] for e in detail["events"]]
    assert "ACTION_COMPLETED" in types and "APPROVAL_REQUIRED" in types
    req = next(e for e in detail["events"] if e["type"] == "ACTION_REQUESTED")
    assert req["delegation"]["id"] and req["refs"]["parent"]
    tree = detail["delegations"]
    assert len(tree) == 1 and tree[0]["issuer"] == "demo-agent" and tree[0]["child"] == "worker"
    assert tree[0]["issuer_run"] == parent_run and child_run in tree[0]["child_runs"]
    assert detail["approvals"][0]["state"] == "PENDING"


def test_no_payload_or_arg_values_in_any_dashboard_response(gw: Any, humans: Any) -> None:
    secret = canary("ARG")
    gw.post("send_email", {"to": EXTERNAL, "subject": secret, "body": secret})
    gw.post("test_echo", {"text": secret})
    gw.drain()
    for path in READS:
        for who in ("alice", "audrey", "adam"):
            assert secret not in _get(gw, humans, who, path).text, (path, who)
    # the approval view shows the args to the APPROVER by design (they must see what they
    # approve), escaped as JSON text; it is not a dashboard read endpoint
    aid = gw.client.get("/v1/approvals", headers=humans.headers("alice")).json()["approvals"][0]
    assert secret in view(gw, humans, aid["approval_id"])["action"]["args_rendered"]


def test_auditor_cannot_approve_and_approver_cannot_read_payloads(gw: Any, humans: Any) -> None:
    _, approval_id = email(gw, EXTERNAL)
    assert approval_id
    shown = view(gw, humans, approval_id, who="alice")
    r = decide(gw, humans, approval_id, who="audrey", shown=shown)
    assert r.status_code == 403 and r.json()["error"]["code"] == "FORBIDDEN"
    # Payloads exist only behind disclosure grants (auditor role). An approver can neither
    # export a disclosure nor fetch an evidence bundle from the dashboard.
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    pub = X25519PrivateKey.generate().public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    key = gw.client.post("/v1/auditor-keys", json={"public_key": pub.hex()},
                         headers=humans.headers("audrey")).json()  # fmt: skip
    eid = event_id(gw, shown["action"]["action_id"], "ACTION_REQUESTED")
    grant = gw.client.post(
        "/v1/disclosures",
        json={"auditor_id": humans.ids["audrey"], "auditor_key_id": key["key_id"],
              "event_ids": [str(eid)], "purpose": "audit"},
        headers=humans.headers("adam"),
    )  # fmt: skip
    assert grant.status_code == 201, grant.text
    r = gw.client.post(f"/v1/disclosures/{grant.json()['grant_id']}/export", json={},
                       headers=humans.headers("alice"))  # fmt: skip
    assert r.status_code == 403 and r.json()["error"]["code"] in ("NOT_GRANTEE", "ROLE_REQUIRED")
    r = _get(gw, humans, "alice", f"/v1/dashboard/events/{eid}/bundle")
    assert r.status_code == 403 and r.json()["error"]["code"] == "ROLE_REQUIRED"
    r = _get(gw, humans, "audrey", "/v1/dashboard/incidents/export")
    assert r.status_code == 200 and r.json()["format"] == "agw-incident-export/v1"


def test_tenant_scoping(gw: Any, humans: Any, migrator_engine: Engine) -> None:
    from agw_gateway.admin import ensure_tenant

    other = f"t-{uuid.uuid4().hex[:10]}"
    ensure_tenant(migrator_engine, other, "other")
    ensure_agent(migrator_engine, other, "a", ("tools:test_echo",))
    r = gw.post("test_echo", {"text": "x"}, token=create_key(migrator_engine, other, "a"))
    run_other = r.json()["links"]["timeline"].split("/")[3]
    assert _get(gw, humans, "adam", f"/v1/dashboard/runs/{run_other}").status_code == 404


def test_critical_approval_needs_step_up(gw: Any, migrator_engine: Engine) -> None:
    ensure_agent(migrator_engine, gw.world.tenant_id, "iam", ("tools:update_iam_role", "iam:admin"))
    token = create_key(migrator_engine, gw.world.tenant_id, "iam")
    body = gw.post(
        "update_iam_role", {"principal": "svc-x", "role": "editor", "grant": True}, token=token
    ).json()
    assert body["decision"]["risk_level"] == "CRITICAL" and body["status"] == "PENDING_APPROVAL"
    approval_id = body["approval"]["approval_id"]
    plain = make_humans(migrator_engine, gw.client, gw.world.tenant_id, step_up=False)
    r = decide(gw, plain, approval_id, who="alice")
    assert r.status_code == 403 and r.json()["error"]["code"] == "STEP_UP_REQUIRED"
    # a REJECT never needs step-up; a wrong password does not step up
    bad = gw.client.post("/v1/auth/step-up", json={"password": "wrong-password-123"},
                         headers=plain.headers("alice"))  # fmt: skip
    assert bad.status_code == 401
    ok = gw.client.post(
        "/v1/auth/step-up", json={"password": PASSWORD}, headers=plain.headers("alice")
    )
    assert ok.status_code == 200
    assert decide(gw, plain, approval_id, who="alice").status_code == 200
    # an old step-up does not count
    with migrator_engine.begin() as conn:
        conn.execute(
            text("UPDATE human_sessions SET stepped_up_at = now() - interval '1 hour' "
                 "WHERE human_id = :h"),
            {"h": plain.ids["bob"]},
        )  # fmt: skip
    gw.client.post("/v1/auth/step-up", json={"password": PASSWORD}, headers=plain.headers("bob"))
    with migrator_engine.begin() as conn:
        conn.execute(
            text("UPDATE human_sessions SET stepped_up_at = now() - interval '1 hour' "
                 "WHERE human_id = :h"),
            {"h": plain.ids["bob"]},
        )  # fmt: skip
    r = decide(gw, plain, approval_id, who="bob")
    assert r.status_code == 403 and r.json()["error"]["code"] == "STEP_UP_REQUIRED"


def _outcome_unknown(gw: Any) -> str:
    aid = gw.post("create_ticket", {"title": "t"}).json()["action_id"]
    gw.state.crash.arm("after_dispatch_commit")
    with pytest.raises(SimulatedCrash):
        gw.state.executor.run_once()
    with gw.engine.begin() as conn:
        conn.execute(
            text("UPDATE outbox_jobs SET lease_expires_at = now() - interval '1 second' "
                 "WHERE tenant_id = :t AND status = 'CLAIMED'"),
            {"t": gw.world.tenant_id},
        )  # fmt: skip
    gw.state.reconciler.run_once()
    assert gw.action_status(aid) == "OUTCOME_UNKNOWN"
    return str(aid)


def test_reconcile_outcome_unknown(gw: Any, humans: Any) -> None:
    aid = _outcome_unknown(gw)
    inc = _get(gw, humans, "audrey", "/v1/dashboard/incidents?kind=outcome_unknown").json()
    assert inc[0]["action_id"] == aid and inc[0]["reconcilable"] is True
    body = {"observed": "NOT_EXECUTED", "justification": "checked the ticket system: absent"}
    r = gw.client.post(f"/v1/actions/{aid}/reconcile", json=body, headers=humans.headers("alice"))
    assert r.status_code == 403  # approvers are not operators
    r = gw.client.post(f"/v1/actions/{aid}/reconcile", json=body, headers=humans.headers("adam"))
    assert r.status_code == 200 and r.json()["status"] == "FAILED"
    assert gw.events(aid)[-1] == "ACTION_RECONCILED"
    p = payload(gw, event_id(gw, aid, "ACTION_RECONCILED"))
    assert p is not None and p["reconciliation"]["observed"] == "NOT_EXECUTED"
    assert p["reconciliation"]["by"] == "adam"
    again = gw.client.post(f"/v1/actions/{aid}/reconcile", json=body,
                           headers=humans.headers("adam"))  # fmt: skip
    assert again.status_code == 409
    gw.drain()
    assert gw.spies.ticket.calls == []  # never retried, before or after reconciliation
    with gw.engine.connect() as conn:
        jobs = conn.execute(
            select(t.outbox_jobs.c.status).where(t.outbox_jobs.c.action_id == uuid.UUID(aid))
        ).scalars()
        assert list(jobs) == ["FAILED"]


def test_tracing_allowlist(gw: Any, humans: Any) -> None:
    from opentelemetry import trace
    from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

    from agw_gateway.tracing import ALLOWED_ATTRIBUTES, configure

    secret = canary("TRACE")
    exporter = InMemorySpanExporter()
    provider = configure(enabled=True, exporter=exporter)
    assert provider is not None
    tracer = provider.get_tracer("test")
    with tracer.start_as_current_span("hostile", attributes={"args": secret, "agw.tool_id": "x"}):
        pass  # a span created WITHOUT our helper, carrying a forbidden attribute
    trace._TRACER_PROVIDER = None  # type: ignore[attr-defined]  # not global for other tests
    trace._TRACER_PROVIDER_SET_ONCE._done = False  # type: ignore[attr-defined]
    trace.set_tracer_provider(provider)
    try:
        gw.post("test_echo", {"text": secret})
        gw.drain()
        _get(gw, humans, "alice", "/v1/dashboard/overview")
    finally:
        trace._TRACER_PROVIDER = None  # type: ignore[attr-defined]
        trace._TRACER_PROVIDER_SET_ONCE._done = False  # type: ignore[attr-defined]
    spans = exporter.get_finished_spans()
    names = {s.name for s in spans}
    assert {"http.request", "action.decision", "action.dispatch", "hostile"} <= names
    for s in spans:
        assert set(s.attributes or {}) <= ALLOWED_ATTRIBUTES, (s.name, dict(s.attributes or {}))
        assert secret not in json.dumps(dict(s.attributes or {}))
        assert not s.events
    decision = next(s for s in spans if s.name == "action.decision")
    assert decision.attributes["agw.decision"] == "ALLOW"
    assert decision.attributes["agw.tool_id"] == "test_echo"
