"""Phase 4 (ADR-0026): risk in the decision path, risk-adaptive sealing, policy versions,
metrics and the run timeline. Real Postgres, real sealer."""

import itertools
import threading
import time
import uuid
from typing import Any

import pytest
from prometheus_client import REGISTRY
from sqlalchemy import select, text
from sqlalchemy.exc import DBAPIError

from agw_gateway.crypto.canonical import decode
from agw_gateway.db import tables as t
from agw_gateway.evidence import EvidenceWriter
from agw_gateway.execution.runner import BackgroundRunner
from agw_gateway.risk import RiskPolicyLoadError, load_risk_policy_toml
from agw_gateway.risk_store import RiskPolicyStore, default_risk_policy_text, store_risk_policy
from agw_verifier.epochs import verify_epochs
from agw_worker.sealing import Sealer
from agw_worker.sealing.policy import SealPolicy

from .test_epochs import epochs_of, exports

pytestmark = pytest.mark.e2e

EXPORT_INTERNAL = {"destination": "s3://exports.corp.example/x", "limit": 10, "fields": ["id"]}


def sealer(gw: Any, policy: SealPolicy | None = None, **kw: Any) -> Sealer:
    return Sealer(
        engine=gw.engine,
        writer=EvidenceWriter(),
        crash=gw.state.crash,
        policy=policy or SealPolicy.adaptive(**kw),
    )


def rows(gw: Any, action_id: str | None = None) -> list[Any]:
    q = select(
        t.evidence_events.c.event_id,
        t.evidence_events.c.seq,
        t.evidence_events.c.event_type,
        t.evidence_events.c.risk_level,
        t.evidence_events.c.body,
    ).where(t.evidence_events.c.tenant_id == gw.world.tenant_id)
    if action_id is not None:
        q = q.where(t.evidence_events.c.action_id == uuid.UUID(action_id))
    with gw.engine.connect() as conn:
        return conn.execute(q.order_by(t.evidence_events.c.seq)).all()


def low(gw: Any, n: int) -> None:
    for i in range(n):
        gw.post("test_echo", {"text": str(i)})
    gw.drain()  # 5 LOW events per action


# --------------------------------------------------------------------------- decision path
def test_every_event_of_an_action_carries_its_risk_level(gw) -> None:
    ok = gw.post("public_doc_search", {"query": "q"}).json()
    gw.drain()
    high = gw.post("export_customer_data", EXPORT_INTERNAL).json()
    crit = gw.post("delete_record", {"record_id": str(uuid.uuid4())}).json()
    assert {r.risk_level for r in rows(gw, ok["action_id"])} == {"LOW"}
    assert len(rows(gw, ok["action_id"])) == 5  # executor events inherit the action's level
    assert (high["status"], high["decision"]["risk_level"]) == ("PENDING_APPROVAL", "HIGH")
    assert {r.risk_level for r in rows(gw, high["action_id"])} == {"HIGH"}
    assert (crit["status"], crit["decision"]["risk_level"]) == ("DENIED", "CRITICAL")
    assert crit["decision"]["reasons"] == ["POLICY_RULE_DENY", "CRITICAL_DENIED"]
    assert {r.risk_level for r in rows(gw, crit["action_id"])} == {"CRITICAL"}


def test_new_tools_end_to_end(gw) -> None:
    mail = gw.post("send_email", {"to": ["a@corp.example"], "subject": "hi"}).json()
    assert (mail["status"], mail["decision"]["risk_level"]) == ("AUTHORIZED", "MEDIUM")
    ext = gw.post("send_email", {"to": ["a@gmail.example"], "subject": "hi"}).json()
    assert (ext["status"], ext["decision"]["risk_level"]) == ("PENDING_APPROVAL", "HIGH")
    bulk = {"destination": "https://x.example/d", "limit": 5000, "fields": ["email"]}
    exp = gw.post("export_customer_data", bulk).json()
    assert exp["status"] == "DENIED"
    assert "MR-PII-EXTERNAL-BULK" in exp["decision"]["matched_rule_ids"]
    assert "AGW-CTRL-06" in exp["decision"]["control_ids"]
    iam = gw.post("update_iam_role", {"principal": "svc", "role": "admin"}).json()
    assert (iam["status"], iam["decision"]["risk_level"]) == ("DENIED", "CRITICAL")
    gw.drain()
    assert gw.action_status(mail["action_id"]) == "COMPLETED"


def test_declared_delegation_raises_risk_and_is_recorded(gw) -> None:
    r = gw.post("public_doc_search", {"query": "q"}, delegation={"depth": 3}).json()
    assert (r["status"], r["decision"]["risk_level"]) == ("PENDING_APPROVAL", "HIGH")
    assert "MR-DEEP-DELEGATION" in r["decision"]["matched_rule_ids"]  # it forces approval
    assert "MR-DEEP-DELEGATION" in r["decision"]["risk_rules"]
    requested = next(x for x in rows(gw, r["action_id"]) if x.event_type == "ACTION_REQUESTED")
    with gw.engine.connect() as conn:
        payload = gw.state.payloads.load_payload(conn, requested.event_id)
    assert decode(payload)["delegation"] == {"depth": 3, "declared_by": "agent"}
    bad = gw.post("public_doc_search", {"query": "q"}, delegation={"depth": -1})
    assert bad.status_code == 422


def test_missing_trust_tier_scores_as_untrusted(gw, migrator_engine) -> None:
    from agw_gateway.admin import create_key, ensure_agent

    ensure_agent(
        migrator_engine, gw.world.tenant_id, "no-tier", ["tools:create_ticket"], trust_tier=None
    )
    token = create_key(migrator_engine, gw.world.tenant_id, "no-tier")
    r = gw.post("create_ticket", {"title": "t"}, token=token).json()
    assert r["decision"]["risk_level"] == "HIGH"
    assert {"MR-MISSING-META", "MR-UNTRUSTED-WRITE"} <= set(r["decision"]["risk_rules"])


# --------------------------------------------------------------------------- sealing
def test_high_event_seals_an_epoch_ending_at_its_seq_in_one_tick(gw) -> None:
    low(gw, 3)  # 15 LOW events, nowhere near count/age
    s = sealer(gw)
    s.tick()
    assert epochs_of(gw) == []  # LOW is batched
    high = gw.post("export_customer_data", EXPORT_INTERNAL).json()
    high_seq = max(r.seq for r in rows(gw, high["action_id"]))
    s.tick()  # ONE worker tick
    eps = epochs_of(gw)
    assert len(eps) == 1
    e = eps[0]
    assert (e.first_seq, e.last_seq) == (0, high_seq)  # older LOW events are not skipped
    assert (e.seal_reason, e.anchor_priority) == ("RISK_HIGH", "PRIORITY")


def test_critical_event_seals_immediately_with_critical_priority(gw) -> None:
    low(gw, 1)
    crit = gw.post("delete_record", {"record_id": str(uuid.uuid4())}).json()
    crit_seq = max(r.seq for r in rows(gw, crit["action_id"]))
    sealer(gw).tick()
    e = epochs_of(gw)[0]
    assert (e.last_seq, e.seal_reason, e.anchor_priority) == (crit_seq, "RISK_CRITICAL", "CRITICAL")


def test_high_seal_inside_the_real_background_loop(gw) -> None:
    """The periodic runner (as in ``python -m agw_worker``) seals a HIGH event within one
    sealer interval, without any explicit call."""
    interval = 0.2
    s = sealer(gw)
    runner = BackgroundRunner(
        gw.state.executor,
        gw.state.reconciler,
        poll_seconds=0.05,
        reconcile_seconds=60,
        periodic=[(interval, s.tick)],
    )
    runner.start()
    try:
        high = gw.post("export_customer_data", EXPORT_INTERNAL).json()
        high_seq = max(r.seq for r in rows(gw, high["action_id"]))
        start = time.monotonic()
        deadline = start + 10 * interval + 2
        while time.monotonic() < deadline and not any(
            e.last_seq >= high_seq for e in epochs_of(gw)
        ):
            time.sleep(0.02)
        waited = time.monotonic() - start
    finally:
        runner.stop()
    assert any(e.last_seq == high_seq and e.seal_reason == "RISK_HIGH" for e in epochs_of(gw))
    assert waited < 10 * interval + 2  # loose bound for CI noise; typical: < 2 intervals


def test_low_only_traffic_seals_on_count(gw) -> None:
    s = sealer(gw, low_max_events=12, low_max_age_seconds=3600)
    low(gw, 2)  # 10 events
    s.drain()
    assert epochs_of(gw) == []
    low(gw, 1)  # 15 events
    s.drain()
    eps = epochs_of(gw)
    assert [(e.first_seq, e.last_seq, e.seal_reason) for e in eps] == [(0, 11, "MAX_EVENTS")]
    assert eps[0].anchor_priority == "ROUTINE"


def test_low_only_traffic_seals_on_age(gw) -> None:
    s = sealer(gw, low_max_age_seconds=0.3)
    low(gw, 1)
    s.drain()
    assert epochs_of(gw) == []
    time.sleep(0.35)
    s.drain()
    assert [(e.first_seq, e.last_seq, e.seal_reason) for e in epochs_of(gw)] == [(0, 4, "MAX_AGE")]


def test_medium_seals_sooner_than_low(gw) -> None:
    s = sealer(gw, low_max_age_seconds=3600, medium_max_events=25, medium_max_age_seconds=0.3)
    low(gw, 1)
    time.sleep(0.35)
    s.drain()
    assert epochs_of(gw) == []  # LOW only, 0.35 s old: well within LOW's 3600 s
    gw.post("create_ticket", {"title": "t"})  # MEDIUM
    gw.drain()
    time.sleep(0.35)
    s.drain()
    eps = epochs_of(gw)
    assert [(e.first_seq, e.seal_reason) for e in eps] == [(0, "MAX_AGE")]
    assert eps[0].last_seq == max(r.seq for r in rows(gw) if r.event_type != "EPOCH_SEALED")


def test_fixed_mode_does_not_seal_high_immediately(gw) -> None:
    gw.post("export_customer_data", EXPORT_INTERNAL)
    sealer(gw, policy=SealPolicy.fixed(100, 3600)).drain()
    assert epochs_of(gw) == []


def test_security_violation_is_sealed_immediately(gw) -> None:
    r = gw.post("public_doc_search", {"query": "q"}, agent_id=str(uuid.uuid4()))
    assert r.status_code == 403
    v = next(x for x in rows(gw) if x.event_type == "SECURITY_VIOLATION")
    assert v.risk_level == "HIGH"
    sealer(gw).tick()
    assert epochs_of(gw)[0].last_seq == v.seq


def test_ordering_and_continuity_under_mixed_concurrent_load(gw) -> None:
    """Four writer threads submit mixed LOW/MEDIUM/HIGH/CRITICAL traffic while a sealer ticks
    concurrently. Afterwards: epochs tile the chain, every RISK_* epoch ends exactly on an
    urgent event, every urgent event was sealed, and the offline verifier accepts it all."""
    s = sealer(gw, low_max_events=30, low_max_age_seconds=3600, medium_max_events=15)
    stop = threading.Event()
    errors: list[BaseException] = []

    def tick_loop() -> None:
        while not stop.is_set():
            try:
                s.tick()
            except BaseException as exc:  # pragma: no cover - surfaced below
                errors.append(exc)
            time.sleep(0.005)

    calls = [
        ("test_echo", {"text": "x"}),
        ("create_ticket", {"title": "t"}),
        ("export_customer_data", EXPORT_INTERNAL),
        ("delete_record", {"record_id": str(uuid.uuid4())}),
        ("public_doc_search", {"query": "q"}),
    ]

    def writer(k: int) -> None:
        for i in range(8):
            tool, args = calls[(k + i) % len(calls)]
            if gw.post(tool, args).status_code != 201:
                errors.append(AssertionError(tool))

    sealing = threading.Thread(target=tick_loop)
    sealing.start()
    workers = [threading.Thread(target=writer, args=(k,)) for k in range(4)]
    for w in workers:
        w.start()
    for w in workers:
        w.join()
    gw.drain()
    stop.set()
    sealing.join()
    assert errors == []
    s.tick()  # anything urgent written by the drain

    evs = rows(gw)
    eps = epochs_of(gw)
    assert [r.seq for r in evs] == list(range(len(evs)))  # gap-free, one chain
    assert eps and eps[0].first_seq == 0
    for a, b in itertools.pairwise(eps):
        assert b.first_seq == a.last_seq + 1 and b.prev_root == a.epoch_root
    level_at = {r.seq: r.risk_level for r in evs}
    for e in eps:
        if e.seal_reason.startswith("RISK_"):
            assert level_at[e.last_seq] in {"HIGH", "CRITICAL"}
        in_range = {level_at[q] for q in range(e.first_seq, e.last_seq + 1)}
        expected = (
            "CRITICAL"
            if "CRITICAL" in in_range
            else "PRIORITY"
            if "HIGH" in in_range
            else "ROUTINE"
        )
        assert e.anchor_priority == expected
    sealed_to = eps[-1].last_seq
    assert all(seq <= sealed_to for seq, lv in level_at.items() if lv in {"HIGH", "CRITICAL"})
    assert {"RISK_HIGH", "RISK_CRITICAL"} & {e.seal_reason for e in eps}

    ev_lines, ep_lines = exports(gw)
    res = verify_epochs(ep_lines, event_lines=ev_lines, trusted_root=bytes(eps[-1].epoch_root))
    assert res.result == "VERIFIED", res.as_dict()


# --------------------------------------------------------------------------- policy versions
def test_policy_change_new_version_old_decisions_keep_old_digest(gw, migrator_engine) -> None:
    pid = f"risk-test-{uuid.uuid4().hex[:8]}"
    v1 = load_risk_policy_toml(
        default_risk_policy_text().replace('policy_id = "risk-default"', f'policy_id = "{pid}"')
    )
    store_risk_policy(gw.engine, v1, created_by="test")
    gw.state.actions._risk_policies = RiskPolicyStore(gw.engine, pid)
    first = gw.post("create_ticket", {"title": "t"}).json()

    v2_text = (
        default_risk_policy_text()
        .replace('policy_id = "risk-default"\nversion = 1', f'policy_id = "{pid}"\nversion = 2')
        .replace("[factors.environment]\nweight = 5", "[factors.environment]\nweight = 9")
    )
    v2 = load_risk_policy_toml(v2_text)
    store_risk_policy(gw.engine, v2, created_by="test")
    second = gw.post("create_ticket", {"title": "t"}).json()

    def evaluated(action_id: str) -> dict[str, Any]:
        r = next(x for x in rows(gw, action_id) if x.event_type == "POLICY_EVALUATED")
        return dict(r.body["risk"])

    a, b = evaluated(first["action_id"]), evaluated(second["action_id"])
    assert (a["pver"], a["pd"]) == (1, v1.digest().hex())
    assert (b["pver"], b["pd"]) == (2, v2.digest().hex())
    assert a["pd"] != b["pd"]
    with gw.engine.connect() as conn:
        stored = conn.execute(
            select(t.risk_policies.c.version, t.risk_policies.c.digest)
            .where(t.risk_policies.c.policy_id == pid)
            .order_by(t.risk_policies.c.version)
        ).all()
    assert [(r.version, bytes(r.digest)) for r in stored] == [(1, v1.digest()), (2, v2.digest())]

    # The old version is immutable: same version with other content fails closed ...
    with pytest.raises(RiskPolicyLoadError, match="version bump"):
        store_risk_policy(
            gw.engine, load_risk_policy_toml(v2_text.replace("version = 2", "version = 1")), "x"
        )
    # ... and the row cannot be changed or deleted, by the app role or the migrator.
    for engine, code in ((gw.engine, "42501"), (migrator_engine, "P0001")):
        with pytest.raises(DBAPIError) as err, engine.begin() as conn:
            conn.execute(
                text("UPDATE risk_policies SET created_by = 'x' WHERE policy_id = :p"), {"p": pid}
            )
        assert err.value.orig.sqlstate == code  # type: ignore[union-attr]
        with pytest.raises(DBAPIError), engine.begin() as conn:
            conn.execute(text("DELETE FROM risk_policies WHERE policy_id = :p"), {"p": pid})


def test_tampered_stored_policy_fails_closed(gw) -> None:
    pid = f"risk-bad-{uuid.uuid4().hex[:8]}"
    p = load_risk_policy_toml(
        default_risk_policy_text().replace('policy_id = "risk-default"', f'policy_id = "{pid}"')
    )
    with gw.engine.begin() as conn:
        conn.execute(
            t.risk_policies.insert().values(
                policy_id=pid,
                version=1,
                digest=bytes(32),
                canonical=p.canonical_bytes(),
                document={},
                created_by="attacker",
            )
        )
    with pytest.raises(RiskPolicyLoadError):
        RiskPolicyStore(gw.engine, pid).active()
    with pytest.raises(RiskPolicyLoadError, match="no risk policy"):
        RiskPolicyStore(gw.engine, "risk-absent").active()


# --------------------------------------------------------------------------- observability
def _sample(name: str, **labels: str) -> float:
    return REGISTRY.get_sample_value(name, labels) or 0.0


def test_metrics(gw) -> None:
    before = _sample("agw_risk_decisions_total", level="HIGH", effect="REQUIRE_APPROVAL")
    sealed_before = _sample("agw_epochs_sealed_total", seal_reason="RISK_HIGH")
    gw.post("export_customer_data", EXPORT_INTERNAL)
    assert (
        _sample("agw_risk_decisions_total", level="HIGH", effect="REQUIRE_APPROVAL") == before + 1
    )
    s = sealer(gw, policy=SealPolicy.fixed(100_000, 3600))
    s.schedule()
    assert _sample("agw_sealer_pending_events", level="HIGH") >= 3
    assert _sample("agw_sealer_oldest_unsealed_age_seconds") >= 0
    sealer(gw).tick()
    assert _sample("agw_epochs_sealed_total", seal_reason="RISK_HIGH") >= sealed_before + 1
    body = gw.client.get("/metrics").text
    assert "agw_risk_decisions_total" in body
    assert gw.world.tenant_id not in body and str(gw.world.agent_id) not in body


def test_timeline_shows_risk_reasons_and_sealing(gw) -> None:
    run = str(uuid.uuid4())
    gw.post("public_doc_search", {"query": "q"}, run_id=run)
    gw.drain()
    gw.post("export_customer_data", EXPORT_INTERNAL, run_id=run)
    gw.post("delete_record", {"record_id": str(uuid.uuid4())}, run_id=run)
    sealer(gw).tick()
    tl = gw.client.get(f"/v1/runs/{run}/timeline", headers=gw.headers()).json()["events"]
    evaluated = [e for e in tl if e["type"] == "POLICY_EVALUATED"]
    assert [e["risk"]["level"] for e in evaluated] == ["LOW", "HIGH", "CRITICAL"]
    assert "BASE_RISK:CRITICAL" in evaluated[2]["risk"]["reasons"]
    assert evaluated[2]["matched_rules"] == ["deny-delete-record", "CAP-CRITICAL-DENY"]
    assert evaluated[1]["controls"] == ["HITL-APPROVAL"]
    assert all(e["epoch"] is not None for e in tl)  # everything up to the CRITICAL is sealed
    reasons = {e["epoch"]["seal_reason"] for e in tl}
    assert reasons <= {"RISK_HIGH", "RISK_CRITICAL"}
    assert tl[-1]["epoch"]["anchor_priority"] == "CRITICAL"


def test_a_broken_tenant_does_not_stop_sealing_for_others(gw, migrator_engine) -> None:
    """Anti-starvation: a job that is processed WITHOUT producing an epoch (here: another
    tenant's self-check fails because its range has no events) must not end the tick."""
    from agw_gateway.admin import ensure_tenant

    broken = f"b-{uuid.uuid4().hex[:12]}"
    ensure_tenant(migrator_engine, broken, "broken")
    s = sealer(gw)
    assert s.request_seal(broken, 0, "MANUAL")  # queued FIRST (lower job id), cannot seal
    high = gw.post("export_customer_data", EXPORT_INTERNAL).json()
    high_seq = max(r.seq for r in rows(gw, high["action_id"]))
    s.tick()  # ONE tick
    assert [e.last_seq for e in epochs_of(gw)] == [high_seq]
    with gw.engine.connect() as conn:
        status = conn.execute(
            select(t.outbox_jobs.c.status, t.outbox_jobs.c.last_error_code).where(
                t.outbox_jobs.c.tenant_id == broken
            )
        ).one()
    assert tuple(status) == ("FAILED", "SEAL_SELF_CHECK_FAILED")
