"""INV-1, INV-2, INV-7 through HTTP: auth, spoofing, every DENY path never reaches an adapter."""

import uuid

import pytest
from sqlalchemy import func, select

from agw_gateway.db import tables as t

pytestmark = pytest.mark.e2e


def test_unauthenticated_requests_401_and_never_dispatch(gw) -> None:
    w = gw.world
    body = {
        "run_id": str(uuid.uuid4()),
        "tool": "public_doc_search",
        "environment": "dev",
        "args": {"query": "x"},
    }
    wrong = w.token[:-1] + ("A" if w.token[-1] != "A" else "B")
    cases = [
        {},
        {"Authorization": "Bearer"},
        {"Authorization": "Token abc"},
        {"Authorization": "Bearer agw_nothex_" + "a" * 43},
        {"Authorization": f"Bearer {wrong}"},
        {"Authorization": f"Bearer {w.revoked_token}"},
        {"Authorization": f"Bearer {w.expired_token}"},
        {"Authorization": f"Bearer {w.disabled_token}"},
    ]
    for headers in cases:
        r = gw.client.post("/v1/actions", json=body, headers={**headers, "Idempotency-Key": "k1"})
        assert r.status_code == 401
        assert r.json()["error"]["code"] == "UNAUTHENTICATED"  # same code for all: no oracle
        assert r.headers["WWW-Authenticate"] == "Bearer"
    for path in ["/v1/tools", f"/v1/actions/{uuid.uuid4()}", f"/v1/runs/{uuid.uuid4()}/timeline"]:
        assert gw.client.get(path).status_code == 401
    gw.drain()
    with gw.engine.connect() as conn:
        n = conn.execute(
            select(func.count()).select_from(t.actions).where(t.actions.c.tenant_id == w.tenant_id)
        ).scalar_one()
    assert n == 0
    assert gw.count_events("ACTION_DISPATCHED") == 0
    assert gw.spies.total_calls() == 0


def test_spoofed_agent_id_rejected_and_recorded(gw) -> None:
    other = str(gw.world.other_id)
    r = gw.post("public_doc_search", {"query": "x"}, agent_id=other)
    assert r.status_code == 403
    assert r.json()["error"]["code"] == "AGENT_ID_MISMATCH"
    r2 = gw.post("public_doc_search", {"query": "x"}, agent_id="not-a-uuid")
    assert r2.status_code == 403
    with gw.engine.connect() as conn:
        rows = conn.execute(
            select(t.evidence_events.c.body, t.evidence_events.c.agent_id).where(
                t.evidence_events.c.tenant_id == gw.world.tenant_id,
                t.evidence_events.c.event_type == "SECURITY_VIOLATION",
            )
        ).all()
        n_actions = conn.execute(
            select(func.count())
            .select_from(t.actions)
            .where(t.actions.c.tenant_id == gw.world.tenant_id)
        ).scalar_one()
    assert len(rows) == 2
    body, agent_id = rows[0]
    assert agent_id == gw.world.agent_id  # INV-7: recorded identity is the authenticated one
    assert body["actor"] == {"kind": "agent", "id": str(gw.world.agent_id)}
    assert body["violation"] == {"kind": "AGENT_ID_MISMATCH", "claimed": other}
    assert n_actions == 0  # nothing else processed
    # matching agent_id is fine
    assert (
        gw.post("public_doc_search", {"query": "x"}, agent_id=str(gw.world.agent_id)).status_code
        == 201
    )


@pytest.mark.parametrize(
    ("tool", "args", "env", "token_attr", "rule"),
    [
        ("transfer_funds", {"amount": "1"}, "dev", "token", "SYS-TOOL-UNKNOWN"),
        ("public_doc_search", {"query": "x", "limit": "5"}, "dev", "token", "SYS-ARGS-INVALID"),
        ("public_doc_search", {"query": "x", "rm": "-rf"}, "dev", "token", "SYS-ARGS-INVALID"),
        ("create_ticket", {"title": "t"}, "prod", "token", "SYS-ENV-FORBIDDEN"),
        ("create_ticket", {"title": "t"}, "dev", "readonly_token", "SYS-SCOPE-MISSING"),
        ("delete_record", {"record_id": str(uuid.uuid4())}, "dev", "token", "deny-delete-record"),
    ],
)
def test_denials_never_reach_adapter(gw, tool, args, env, token_attr, rule) -> None:
    r = gw.post(tool, args, env=env, token=getattr(gw.world, token_attr))
    assert r.status_code == 201  # a DENY is a successful, recorded evaluation
    data = r.json()
    assert data["status"] == "DENIED"
    assert data["decision"]["effect"] == "DENY"
    assert data["decision"]["matched_rule_ids"][0] == rule
    gw.drain()
    assert gw.spies.total_calls() == 0
    assert gw.events(data["action_id"]) == ["ACTION_REQUESTED", "POLICY_EVALUATED", "ACTION_DENIED"]
    with gw.engine.connect() as conn:
        jobs = conn.execute(
            select(func.count())
            .select_from(t.outbox_jobs)
            .where(t.outbox_jobs.c.action_id == uuid.UUID(data["action_id"]))
        ).scalar_one()
    assert jobs == 0
    assert gw.action_status(data["action_id"]) == "DENIED"


def test_delete_record_denied_despite_scope(gw) -> None:
    r = gw.post("delete_record", {"record_id": str(uuid.uuid4())})
    d = r.json()["decision"]
    assert d["matched_rule_ids"] == ["deny-delete-record", "deny-critical"]
    assert d["risk_level"] == "CRITICAL"


def test_require_approval_leaves_pending(gw) -> None:
    r = gw.post("test_restricted_update", {"name": "n"})
    data = r.json()
    assert data["status"] == "PENDING_APPROVAL"
    assert data["decision"]["effect"] == "REQUIRE_APPROVAL"
    gw.drain()
    assert gw.spies.restricted.calls == []
    assert gw.events(data["action_id"]) == [
        "ACTION_REQUESTED",
        "POLICY_EVALUATED",
        "APPROVAL_REQUIRED",
    ]


def test_policy_evaluated_record_contents(gw) -> None:
    r = gw.post("create_ticket", {"title": "t"})
    aid = uuid.UUID(r.json()["action_id"])
    with gw.engine.connect() as conn:
        row = conn.execute(
            select(t.evidence_events.c.body, t.evidence_events.c.canonical_bytes).where(
                t.evidence_events.c.action_id == aid,
                t.evidence_events.c.event_type == "POLICY_EVALUATED",
            )
        ).one()
    body = row.body
    assert body["policy"] == {
        "id": "default",
        "ver": 1,
        "effect": "ALLOW",
        "rules": ["allow-medium-ticket"],
        "reasons": [],
        "controls": [],
        "ev": "policy-v1",
    }
    assert body["risk"] == {"level": "MEDIUM", "score": 20, "rules": [], "cv": "risk-v1"}
    assert body["class"] == "SYS" and body["v"] == 1
    # Phase 2: the JSONB body is a projection of the canonical bytes, which are authoritative.
    from agw_gateway.crypto.canonical import decode, to_json_projection

    assert to_json_projection(decode(bytes(row.canonical_bytes))) == body
