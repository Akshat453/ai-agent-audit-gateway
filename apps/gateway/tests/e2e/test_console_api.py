"""Phase 9.5 read-only console endpoints (ADR-0033): human session only, tenant-scoped, no
payloads or arg values, approvals list with server-side sort/filter/pagination, evidence nodes
whose hash/link checks flip when the stored record is edited."""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from sqlalchemy import Engine, select

from agw_gateway.admin import create_key, ensure_agent, ensure_human, ensure_tenant
from agw_gateway.db import tables as t

from ..approvalkit import EXTERNAL, PASSWORD, email, make_humans
from ..privacykit import canary, su

pytestmark = pytest.mark.e2e


@pytest.fixture
def humans(gw: Any, migrator_engine: Engine) -> Any:
    ensure_human(migrator_engine, gw.world.tenant_id, "adam", PASSWORD, ["admin"])
    return make_humans(migrator_engine, gw.client, gw.world.tenant_id)


def _get(gw: Any, humans: Any, who: str, path: str) -> Any:
    return gw.client.get(path, headers=humans.headers(who))


def _paths(gw: Any, humans: Any) -> list[str]:
    action_id, _ = email(gw, EXTERNAL)
    gw.post("test_echo", {"text": "x"})
    gw.drain()
    ev = _get(gw, humans, "alice", f"/v1/dashboard/events?action_id={action_id}")
    ev = ev.json()["events"][0]["event_id"]
    return [
        "/v1/dashboard/activity",
        "/v1/dashboard/activity?range=7d",
        "/v1/dashboard/activity?range=30d",
        "/v1/dashboard/approvals",
        f"/v1/dashboard/actions/{action_id}",
        f"/v1/dashboard/events/{ev}",
        "/v1/dashboard/session",
        "/v1/dashboard/health",
        f"/v1/dashboard/search?q={action_id}",
    ]


def test_console_reads_need_a_human_session(gw: Any, humans: Any) -> None:
    for path in _paths(gw, humans):
        assert gw.client.get(path).status_code == 401, path
        r = gw.client.get(path, headers={"Authorization": f"Bearer {gw.world.token}"})
        assert r.status_code == 403 and r.json()["error"]["code"] == "AGENT_NOT_PERMITTED", path
        for who in ("alice", "audrey", "adam"):
            assert _get(gw, humans, who, path).status_code == 200, (path, who)


def test_no_payload_or_arg_values_in_console_responses(gw: Any, humans: Any) -> None:
    secret = canary("ARG")
    action_id, _ = email(gw, EXTERNAL)
    gw.post("send_email", {"to": EXTERNAL, "subject": secret, "body": secret})
    echo = gw.post("test_echo", {"text": secret}).json()["action_id"]
    gw.drain()
    for path in [*_paths(gw, humans), f"/v1/dashboard/actions/{echo}"]:
        for who in ("alice", "audrey", "adam"):
            assert secret not in _get(gw, humans, who, path).text, (path, who)
    assert action_id


def test_tenant_scoping(gw: Any, humans: Any, migrator_engine: Engine) -> None:
    other = f"t-{uuid.uuid4().hex[:10]}"
    ensure_tenant(migrator_engine, other, "other")
    ensure_agent(migrator_engine, other, "a", ("tools:test_echo",))
    r = gw.post("test_echo", {"text": "x"}, token=create_key(migrator_engine, other, "a"))
    foreign_action = r.json()["action_id"]
    assert _get(gw, humans, "adam", f"/v1/dashboard/actions/{foreign_action}").status_code == 404
    with migrator_engine.connect() as conn:  # an event id of the OTHER tenant
        foreign_event = conn.execute(
            select(t.evidence_events.c.event_id).where(t.evidence_events.c.tenant_id == other)
        ).scalar()
    assert _get(gw, humans, "adam", f"/v1/dashboard/events/{foreign_event}").status_code == 404
    own = _get(gw, humans, "adam", "/v1/dashboard/approvals").json()
    assert all(r["action_id"] != foreign_action for r in own["rows"])


def test_approvals_sorted_filtered_paginated(gw: Any, humans: Any) -> None:
    ids = [email(gw, EXTERNAL)[1] for _ in range(3)]
    assert all(ids)
    page = _get(gw, humans, "alice", "/v1/dashboard/approvals?state=PENDING&limit=2").json()
    assert page["total"] == 3 and len(page["rows"]) == 2
    rest = _get(gw, humans, "alice", "/v1/dashboard/approvals?state=PENDING&limit=2&offset=2")
    assert len(rest.json()["rows"]) == 1
    expiries = [r["expires_at"] for r in page["rows"] + rest.json()["rows"]]
    assert expiries == sorted(expiries)  # default: soonest expiry first
    desc = _get(gw, humans, "alice", "/v1/dashboard/approvals?state=PENDING&order=desc").json()
    assert [r["expires_at"] for r in desc["rows"]] == sorted(expiries, reverse=True)
    row = page["rows"][0]
    assert row["agent"]["name"] == "demo-agent" and row["tool"]["id"] == "send_email"
    assert row["risk_level"] == "HIGH" and row["decisions"] == 0
    none = _get(gw, humans, "alice", "/v1/dashboard/approvals?risk=CRITICAL").json()
    assert none["total"] == 0
    bad = _get(gw, humans, "alice", "/v1/dashboard/approvals?sort=approval_id")
    assert bad.status_code == 422  # only whitelisted sort keys


def test_action_detail_evidence_chain(gw: Any, humans: Any) -> None:
    action_id = gw.post("test_echo", {"text": "hello"}).json()["action_id"]
    gw.drain()
    d = _get(gw, humans, "audrey", f"/v1/dashboard/actions/{action_id}").json()
    assert d["status"] == "COMPLETED" and d["decision"] == "ALLOW"
    types = [e["type"] for e in d["events"]]
    assert types[0] == "ACTION_REQUESTED" and "ACTION_COMPLETED" in types
    seqs = [e["seq"] for e in d["events"]]
    assert seqs == sorted(seqs)
    assert all(e["hash_ok"] for e in d["events"])
    assert all(e["link_ok"] is True for e in d["events"])  # predecessors are all visible


def test_event_detail_and_tamper_flips_hash_ok(gw: Any, humans: Any, pg: Any) -> None:
    action_id = gw.post("test_echo", {"text": "hello"}).json()["action_id"]
    gw.drain()
    events = _get(gw, humans, "alice", f"/v1/dashboard/actions/{action_id}").json()["events"]
    victim = events[1]
    ok = _get(gw, humans, "alice", f"/v1/dashboard/events/{victim['event_id']}").json()
    assert ok["node"]["hash_ok"] and ok["node"]["link_ok"]
    assert ok["header"]["prev"] == ok["node"]["prev_hash"] and ok["canonical_header"]
    # A privileged insider edits one byte of the stored canonical header.
    su(pg, "UPDATE evidence_events SET canonical_bytes = canonical_bytes || '\\x00'::bytea "
           "WHERE event_id = %s", (victim["event_id"],))  # fmt: skip
    bad = _get(gw, humans, "alice", f"/v1/dashboard/events/{victim['event_id']}").json()
    assert bad["node"]["hash_ok"] is False
    # ...or rewrites a stored hash: the NEXT event's link no longer matches.
    nxt = events[2]
    su(pg, "UPDATE evidence_events SET event_hash = %s WHERE event_id = %s",
       (b"\x11" * 32, victim["event_id"]))  # fmt: skip
    after = _get(gw, humans, "alice", f"/v1/dashboard/events/{nxt['event_id']}").json()
    assert after["node"]["link_ok"] is False


def test_activity_buckets_totals_and_pipeline(gw: Any, humans: Any) -> None:
    for _ in range(2):
        gw.post("test_echo", {"text": "x"})
    email(gw, EXTERNAL)
    gw.drain()
    a = _get(gw, humans, "alice", "/v1/dashboard/activity?range=24h").json()
    assert a["bucket_seconds"] == 3600 and 24 <= len(a["buckets"]) <= 25
    assert sum(b["total"] for b in a["buckets"]) == a["current"]["actions"] >= 3
    assert sum(b["REQUIRE_APPROVAL"] for b in a["buckets"]) >= 1
    assert a["previous"]["actions"] == 0
    p = a["pipeline"]
    assert p["recorded"]["count"] > 0 and p["recorded"]["oldest_waiting_seconds"] is not None
    assert p["sealed"]["count"] <= p["recorded"]["count"]
    week = _get(gw, humans, "alice", "/v1/dashboard/activity?range=7d").json()
    assert week["bucket_seconds"] == 6 * 3600 and 28 <= len(week["buckets"]) <= 29
    assert _get(gw, humans, "alice", "/v1/dashboard/activity?range=1y").status_code == 422


def test_session_reports_step_up_window(gw: Any, migrator_engine: Engine) -> None:
    fresh = make_humans(migrator_engine, gw.client, gw.world.tenant_id, step_up=False)
    s = _get(gw, fresh, "alice", "/v1/dashboard/session").json()
    assert s["step_up_remaining_seconds"] is None and s["roles"] == ["approver"]
    assert s["env"] in ("dev", "test")
    stepped = make_humans(migrator_engine, gw.client, gw.world.tenant_id)
    s = _get(gw, stepped, "alice", "/v1/dashboard/session").json()
    assert 0 < s["step_up_remaining_seconds"] <= s["step_up_window_seconds"]


def test_health_chips(gw: Any, humans: Any) -> None:
    gw.post("test_echo", {"text": "x"})
    gw.drain()
    chips = {c["name"]: c for c in _get(gw, humans, "audrey", "/v1/dashboard/health").json()}
    assert set(chips) == {"gateway", "database", "worker", "anchoring", "monitor"}
    assert chips["worker"]["status"] == "ok" and chips["monitor"]["status"] == "off"


def test_search_by_uuid_and_hash_prefix_is_tenant_scoped(
    gw: Any, humans: Any, migrator_engine: Engine
) -> None:
    action_id = gw.post("test_echo", {"text": "x"}).json()["action_id"]
    gw.drain()
    hits = _get(gw, humans, "alice", f"/v1/dashboard/search?q={action_id}").json()
    assert {h["kind"] for h in hits} == {"action"} and hits[0]["href"] == f"/actions/{action_id}"
    ev = _get(gw, humans, "alice", f"/v1/dashboard/actions/{action_id}").json()["events"][0]
    by_hash = _get(gw, humans, "alice", f"/v1/dashboard/search?q=0x{ev['event_hash'][:12]}")
    assert ev["event_id"] in {h["id"] for h in by_hash.json()}
    assert _get(gw, humans, "alice", "/v1/dashboard/search?q=abc").json() == []  # too short
    assert _get(gw, humans, "alice", "/v1/dashboard/search?q=zzzzzzzzzz").json() == []
    other = f"t-{uuid.uuid4().hex[:10]}"
    ensure_tenant(migrator_engine, other, "other")
    ensure_agent(migrator_engine, other, "a", ("tools:test_echo",))
    r = gw.post("test_echo", {"text": "x"}, token=create_key(migrator_engine, other, "a"))
    foreign = r.json()["action_id"]
    assert _get(gw, humans, "alice", f"/v1/dashboard/search?q={foreign}").json() == []
