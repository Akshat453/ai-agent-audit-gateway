"""INV-3, INV-5, INV-6 and the ALLOW ordering through the outbox executor and reconciler."""

import threading
import uuid

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select, text

from agw_gateway.db import tables as t
from agw_gateway.execution.crash import SimulatedCrash

pytestmark = pytest.mark.e2e

ALLOW_ORDER = [
    "ACTION_REQUESTED",
    "POLICY_EVALUATED",
    "ACTION_AUTHORIZED",
    "ACTION_DISPATCHED",
    "ACTION_COMPLETED",
]


def _seqs(gw, action_id: str) -> list[int]:
    with gw.engine.connect() as conn:
        return list(
            conn.execute(
                select(t.evidence_events.c.seq)
                .where(t.evidence_events.c.action_id == uuid.UUID(action_id))
                .order_by(t.evidence_events.c.seq)
            ).scalars()
        )


def _expire_leases(gw) -> None:
    with gw.engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE outbox_jobs SET lease_expires_at = now() - interval '1 second' "
                "WHERE tenant_id = :t AND status = 'CLAIMED'"
            ),
            {"t": gw.world.tenant_id},
        )


def test_allow_path_ordering_and_result(gw) -> None:
    r = gw.post("create_ticket", {"title": "hello", "body": "b", "priority": "high"})
    assert r.status_code == 201
    aid = r.json()["action_id"]
    assert r.json()["status"] == "AUTHORIZED"
    assert gw.spies.ticket.calls == []  # tx1 alone never calls the adapter
    gw.drain()
    assert gw.events(aid) == ALLOW_ORDER
    s = _seqs(gw, aid)
    assert s == sorted(s) and len(set(s)) == 5
    assert gw.spies.ticket.calls == [uuid.UUID(aid)]
    got = gw.client.get(f"/v1/actions/{aid}", headers=gw.headers()).json()
    assert got["status"] == "COMPLETED"
    assert set(got["result"]) == {"ticket_id"}
    with gw.engine.connect() as conn:
        ticket = conn.execute(
            select(t.demo_tickets).where(t.demo_tickets.c.created_by_action == uuid.UUID(aid))
        ).one()
        job = conn.execute(
            select(t.outbox_jobs).where(t.outbox_jobs.c.action_id == uuid.UUID(aid))
        ).one()
    assert (ticket.title, ticket.priority) == ("hello", "high")
    assert (job.status, job.args, job.attempts) == ("DONE", None, 1)  # plaintext args cleared


def test_crash_after_tx1_commit_authorized_is_durable_and_adapter_not_called(gw) -> None:
    # Driven at the service layer: SimulatedCrash models process death and would also tear down
    # the TestClient's event loop.
    import json

    agent = gw.state.authenticator.authenticate(f"Bearer {gw.world.token}")
    rid = str(uuid.uuid4())
    raw = json.dumps(
        {"run_id": rid, "tool": "create_ticket", "environment": "dev", "args": {"title": "t"}}
    )
    gw.state.crash.arm("after_tx1_commit")
    with pytest.raises(SimulatedCrash):
        gw.state.actions.submit(agent, raw.encode(), "crash-key")
    assert gw.spies.ticket.calls == []
    with gw.engine.connect() as conn:
        aid = conn.execute(
            select(t.actions.c.action_id).where(t.actions.c.run_id == uuid.UUID(rid))
        ).scalar_one()
        job = conn.execute(
            select(t.outbox_jobs.c.status).where(t.outbox_jobs.c.action_id == aid)
        ).scalar_one()
    assert gw.events(aid) == ALLOW_ORDER[:3]  # AUTHORIZED committed before any side effect
    assert job == "PENDING"
    gw.drain()  # C2 recovery: executor picks it up after "restart"
    assert gw.events(aid) == ALLOW_ORDER
    assert len(gw.spies.ticket.calls) == 1


def test_crash_after_claim_job_released_then_completed(gw) -> None:
    aid = gw.post("create_ticket", {"title": "t"}).json()["action_id"]
    gw.state.crash.arm("after_claim")
    with pytest.raises(SimulatedCrash):
        gw.state.executor.run_once()
    _expire_leases(gw)
    gw.state.reconciler.run_once()  # no DISPATCHED -> provably not called -> PENDING
    assert gw.action_status(aid) == "AUTHORIZED"
    gw.drain()
    assert gw.events(aid) == ALLOW_ORDER
    assert len(gw.spies.ticket.calls) == 1


def test_crash_after_dispatch_before_adapter_outcome_unknown_no_call(gw) -> None:
    aid = gw.post("create_ticket", {"title": "t"}).json()["action_id"]
    gw.state.crash.arm("after_dispatch_commit")
    with pytest.raises(SimulatedCrash):
        gw.state.executor.run_once()
    assert gw.events(aid)[-1] == "ACTION_DISPATCHED"
    _expire_leases(gw)
    gw.state.reconciler.run_once()
    assert gw.action_status(aid) == "OUTCOME_UNKNOWN"
    assert gw.events(aid)[-1] == "ACTION_OUTCOME_UNKNOWN"
    gw.drain()
    gw.drain()
    assert gw.spies.ticket.calls == []  # never re-invoked (ADR-0011)
    with gw.engine.connect() as conn:
        job = conn.execute(
            select(t.outbox_jobs).where(t.outbox_jobs.c.action_id == uuid.UUID(aid))
        ).one()
    assert (job.status, job.last_error_code) == ("FAILED", "LEASE_EXPIRED_AFTER_DISPATCH")


def test_crash_after_adapter_return_call_count_stays_one(gw) -> None:
    aid = gw.post("create_ticket", {"title": "t"}).json()["action_id"]
    gw.state.crash.arm("after_adapter_return")
    with pytest.raises(SimulatedCrash):
        gw.state.executor.run_once()
    assert len(gw.spies.ticket.calls) == 1
    _expire_leases(gw)
    gw.drain()
    gw.drain()
    assert len(gw.spies.ticket.calls) == 1
    assert gw.action_status(aid) == "OUTCOME_UNKNOWN"


def test_idempotent_tool_is_redispatched_after_ambiguous_crash(gw) -> None:
    aid = gw.post("public_doc_search", {"query": "evidence"}).json()["action_id"]
    gw.state.crash.arm("after_dispatch_commit")
    with pytest.raises(SimulatedCrash):
        gw.state.executor.run_once()
    _expire_leases(gw)
    gw.state.reconciler.run_once()
    gw.drain()
    assert gw.action_status(aid) == "COMPLETED"
    assert gw.events(aid) == [*ALLOW_ORDER[:4], "ACTION_DISPATCHED", "ACTION_COMPLETED"]
    assert len(gw.spies.search.calls) == 1


def test_adapter_error_records_failed(gw) -> None:
    def boom(args, ctx):
        raise RuntimeError("SECRET-ADAPTER-DETAIL")

    gw.spies.echo.behavior = boom
    aid = gw.post("test_echo", {"text": "x"}).json()["action_id"]
    gw.drain()
    assert gw.events(aid)[-1] == "ACTION_FAILED"
    got = gw.client.get(f"/v1/actions/{aid}", headers=gw.headers()).json()
    assert (got["status"], got["error_code"], got["result"]) == ("FAILED", "TOOL_ERROR", None)
    assert "SECRET-ADAPTER-DETAIL" not in str(got)


def test_adapter_timeout_is_outcome_unknown(gw, pg, app_engine, tmp_path) -> None:
    from agw_gateway.api.app import build_state

    from ..conftest import make_settings

    release = threading.Event()

    def slow(args, ctx):
        release.wait(5)
        raise AssertionError("unreachable result")

    gw.spies.echo.behavior = slow
    st = build_state(
        make_settings(pg.app, tmp_path, adapter_timeout_seconds=0.2),
        engine=app_engine,
        registry=gw.state.registry,
    )
    aid = gw.post("test_echo", {"text": "x"}).json()["action_id"]
    st.executor.run_once()
    release.set()
    st.executor.close()
    assert gw.action_status(aid) == "OUTCOME_UNKNOWN"
    assert gw.events(aid)[-1] == "ACTION_OUTCOME_UNKNOWN"


def test_concurrent_executors_dispatch_each_job_once(gw, pg, app_engine, tmp_path) -> None:
    from agw_gateway.api.app import build_state

    from ..conftest import make_settings

    ids = [gw.post("test_echo", {"text": str(i)}).json()["action_id"] for i in range(40)]
    executors = [
        build_state(
            make_settings(pg.app, tmp_path), engine=app_engine, registry=gw.state.registry
        ).executor
        for _ in range(6)
    ]

    def loop(ex) -> None:
        while ex.run_once():
            pass

    threads = [threading.Thread(target=loop, args=(ex,)) for ex in executors]
    for th in threads:
        th.start()
    for th in threads:
        th.join()
    for ex in executors:
        ex.close()
    assert sorted(map(str, gw.spies.echo.calls)) == sorted(ids)
    assert all(gw.action_status(a) == "COMPLETED" for a in ids)


# ---------------------------------------------------------------- idempotency (INV-5)
def test_idempotency_replay_conflict_and_header_validation(gw) -> None:
    rid = str(uuid.uuid4())
    first = gw.post("public_doc_search", {"query": "a", "limit": 2}, run_id=rid, key="same-key")
    replay = gw.post("public_doc_search", {"limit": 2, "query": "a"}, run_id=rid, key="same-key")
    assert first.status_code == 201 and "Idempotent-Replayed" not in first.headers
    assert replay.status_code == 200 and replay.headers["Idempotent-Replayed"] == "true"
    assert replay.json() == first.json()
    conflict = gw.post("public_doc_search", {"query": "b"}, run_id=rid, key="same-key")
    assert conflict.status_code == 409
    assert conflict.json()["error"]["code"] == "IDEMPOTENCY_KEY_REUSED"
    # same key, different agent: independent namespace
    assert (
        gw.post(
            "public_doc_search",
            {"query": "b"},
            run_id=rid,
            key="same-key",
            token=gw.world.other_token,
        ).status_code
        == 201
    )
    body = {
        "run_id": rid,
        "tool": "public_doc_search",
        "environment": "dev",
        "args": {"query": "a"},
    }
    auth = {"Authorization": f"Bearer {gw.world.token}"}
    missing = gw.client.post("/v1/actions", json=body, headers=auth)
    assert (missing.status_code, missing.json()["error"]["code"]) == (
        400,
        "IDEMPOTENCY_KEY_MISSING",
    )
    bad = gw.client.post("/v1/actions", json=body, headers={**auth, "Idempotency-Key": "has space"})
    assert (bad.status_code, bad.json()["error"]["code"]) == (400, "IDEMPOTENCY_KEY_INVALID")


def test_twenty_concurrent_identical_requests_one_action(gw) -> None:
    rid = str(uuid.uuid4())
    body = {"run_id": rid, "tool": "create_ticket", "environment": "dev", "args": {"title": "race"}}
    headers = gw.headers(key="race-key")
    barrier = threading.Barrier(20)
    results: list[tuple[int, str]] = []
    lock = threading.Lock()

    def fire() -> None:
        c = TestClient(gw.client.app)  # no context manager: do not re-run lifespan
        barrier.wait()
        r = c.post("/v1/actions", json=body, headers=headers)
        with lock:
            results.append((r.status_code, r.json()["action_id"]))

    threads = [threading.Thread(target=fire) for _ in range(20)]
    for th in threads:
        th.start()
    for th in threads:
        th.join()
    gw.drain()
    statuses = sorted(s for s, _ in results)
    assert statuses == [200] * 19 + [201]
    assert len({a for _, a in results}) == 1
    with gw.engine.connect() as conn:
        n = conn.execute(
            select(func.count()).select_from(t.actions).where(t.actions.c.run_id == uuid.UUID(rid))
        ).scalar_one()
    assert n == 1
    assert gw.count_events("ACTION_REQUESTED") == 1
    assert len(gw.spies.ticket.calls) == 1
