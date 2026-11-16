"""Phase 9 monitoring (ADR-0031 §3): the monitor verifies every tenant with the independent
verifier, records VERIFICATION_REPORT evidence in the ``_monitor`` chain, and alerts.

Required: an injected DB tamper is detected within ONE cycle and raises an alert (webhook,
HMAC-signed). Plus: anchor-root mismatch, sequence gap, OUTCOME_UNKNOWN / approval-queue /
unsealed-age alerts, dashboard-requested runs, and the monitoring stream itself verifies.
"""

from __future__ import annotations

import hashlib
import hmac
import io
import json
import threading
import uuid
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

import psycopg
import pytest
from sqlalchemy import Engine, select

from agw_gateway.crypto.canonical import decode
from agw_gateway.db import tables as t
from agw_gateway.evidence.export import export_chain
from agw_verifier.chain import verify_lines
from agw_worker.monitoring import Monitor, MonitorConfig, report_digest

from ..anchorkit import sealer
from ..approvalkit import EXTERNAL, email, make_humans
from ..conftest import PgUrls

pytestmark = pytest.mark.e2e
SECRET = "webhook-test-secret"  # test-only


class _Hook(BaseHTTPRequestHandler):
    def log_message(self, *a: Any) -> None:
        pass

    def do_POST(self) -> None:
        body = self.rfile.read(int(self.headers["Content-Length"]))
        self.server.received.append((dict(self.headers), body))  # type: ignore[attr-defined]
        self.send_response(204)
        self.end_headers()


@pytest.fixture
def webhook() -> Iterator[Any]:
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Hook)
    srv.received = []  # type: ignore[attr-defined]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield srv
    srv.shutdown()


def monitor(gw: Any, webhook: Any = None, **cfg: Any) -> Monitor:
    values: dict[str, Any] = {"webhook_secret": SECRET, "alert_cooldown_seconds": 0}
    if webhook is not None:
        values["webhook_url"] = f"http://127.0.0.1:{webhook.server_port}/alerts"
    values.update(cfg)
    return Monitor(engine=gw.engine, writer=gw.state.writer, config=MonitorConfig(**values))


def _activity(gw: Any, n: int = 3) -> list[str]:
    ids = [gw.post("test_echo", {"text": f"m{i}"}).json()["action_id"] for i in range(n)]
    gw.drain()
    sealer(gw).drain()
    return ids


def su(pg: PgUrls, sql: str, params: tuple[Any, ...] = ()) -> None:
    with psycopg.connect(pg.superuser, autocommit=True) as conn:
        conn.execute("SET session_replication_role = replica")  # triggers off: an insider
        conn.execute(sql, params)  # type: ignore[arg-type]


def _alert_kinds(rep: Any) -> list[str]:
    return [a["kind"] for a in rep.alerts]


def test_clean_tenant_verifies_and_report_is_evidence(gw: Any) -> None:
    _activity(gw)
    rep = monitor(gw).run_once([gw.world.tenant_id])[0]
    assert rep.result == "VERIFIED", rep.report
    assert rep.report["chain"]["events_checked"] >= 15
    # no anchoring configured: epochs verified locally (the verifier's UNANCHORED is expected)
    assert rep.report["epochs"]["result"] == "UNANCHORED"
    assert "locally" in rep.report["epochs"]["note"]
    with gw.engine.connect() as conn:
        ev = conn.execute(
            select(t.evidence_events).where(t.evidence_events.c.event_id == rep.event_id)
        ).one()
        row = conn.execute(
            select(t.monitor_reports).where(t.monitor_reports.c.report_id == rep.report_id)
        ).one()
    header = decode(bytes(ev.canonical_bytes))
    assert ev.tenant_id == "_monitor" and header["type"] == "VERIFICATION_REPORT"
    assert header["report"]["tenant"] == gw.world.tenant_id
    assert header["report"]["result"] == "VERIFIED"
    # the header commits to the stored report
    assert header["report"]["digest"] == bytes(row.report_digest) == report_digest(row.report)
    # the monitoring stream is itself a verifiable chain
    buf = io.StringIO()
    export_chain(gw.engine, "_monitor", buf, include_payloads=False)
    assert verify_lines(buf.getvalue().splitlines()).result in ("VERIFIED",)


def test_db_tamper_detected_within_one_cycle_and_alerted(gw: Any, pg: PgUrls, webhook: Any) -> None:
    _activity(gw)
    m = monitor(gw, webhook)
    assert m.run_once([gw.world.tenant_id])[0].result == "VERIFIED"
    # An insider edits one evidence header byte in place (triggers disabled).
    with gw.engine.connect() as conn:
        victim = conn.execute(
            select(t.evidence_events.c.event_id, t.evidence_events.c.seq)
            .where(t.evidence_events.c.tenant_id == gw.world.tenant_id)
            .order_by(t.evidence_events.c.seq)
            .offset(4)
            .limit(1)
        ).one()
    su(
        pg,
        "UPDATE evidence_events SET canonical_bytes = overlay(canonical_bytes placing "
        "decode('ff', 'hex') from 40 for 1) WHERE event_id = %s",
        (victim.event_id,),
    )
    rep = m.run_once([gw.world.tenant_id])[0]  # ONE cycle
    assert rep.result == "TAMPERED"
    assert rep.report["chain"]["first_bad_seq"] == victim.seq
    assert "VERIFICATION_FAILED" in _alert_kinds(rep)
    # delivered to the webhook, HMAC-signed, no evidence content in it
    assert webhook.received, "no alert delivered"
    headers, body = webhook.received[-1]
    alert = json.loads(body)
    assert alert["kind"] == "VERIFICATION_FAILED" and alert["report_result"] == "TAMPERED"
    expected = hmac.new(SECRET.encode(), body, hashlib.sha256).hexdigest()
    assert headers["X-AGW-Signature"] == expected
    with gw.engine.connect() as conn:
        delivered = conn.execute(
            select(t.monitor_alerts.c.delivered).where(
                t.monitor_alerts.c.report_id == rep.report_id
            )
        ).scalars()
        assert all(delivered)


def test_anchor_root_mismatch_alert(gw: Any, pg: PgUrls) -> None:
    _activity(gw)
    with gw.engine.connect() as conn:
        epoch_no = conn.execute(
            select(t.epochs.c.epoch_no).where(t.epochs.c.tenant_id == gw.world.tenant_id).limit(1)
        ).scalar_one()
    su(
        pg,
        "INSERT INTO anchors (tenant_id, epoch_no, recorder_id, root, tree_size, last_seq, "
        "priority, status, chain_id, contract, submitter, attempts, resubmissions, sealed_at, "
        "created_at, updated_at, block_number, block_hash) VALUES (%s, %s, %s, %s, 1, 0, "
        "'ROUTINE', 'FINALIZED', 31337, '0x' || repeat('a', 40), '0x' || repeat('b', 40), 1, 0, "
        "now(), now(), now(), 7, %s)",
        (gw.world.tenant_id, epoch_no, bytes(32), b"\x01" * 32, b"\x02" * 32),
    )
    rep = monitor(gw).run_once([gw.world.tenant_id])[0]
    assert rep.result == "TAMPERED"
    assert rep.report["anchors"]["db_root_mismatch"] == [epoch_no]
    assert "ANCHOR_ROOT_MISMATCH" in _alert_kinds(rep)


def test_sequence_gap_alert(gw: Any, pg: PgUrls) -> None:
    gw.post("test_echo", {"text": "a"})
    gw.drain()
    with gw.engine.connect() as conn:
        mid = conn.execute(
            select(t.evidence_events.c.event_id)
            .where(t.evidence_events.c.tenant_id == gw.world.tenant_id)
            .order_by(t.evidence_events.c.seq)
            .offset(2)
            .limit(1)
        ).scalar_one()
    su(pg, "DELETE FROM payload_keys WHERE event_id = %s", (mid,))
    su(pg, "DELETE FROM payload_objects WHERE event_id = %s", (mid,))
    su(pg, "DELETE FROM evidence_payloads WHERE event_id = %s", (mid,))
    su(pg, "DELETE FROM evidence_events WHERE event_id = %s", (mid,))
    rep = monitor(gw).run_once([gw.world.tenant_id])[0]
    assert rep.result in ("INCOMPLETE", "TAMPERED")
    assert "SEQUENCE_GAP" in _alert_kinds(rep)


def test_operational_alerts(gw: Any, migrator_engine: Engine) -> None:
    email(gw, EXTERNAL)  # leaves a PENDING approval (unsealed events too)
    rep = monitor(
        gw, unsealed_alert_seconds=0.000001, approval_queue_alert_seconds=0.000001
    ).run_once([gw.world.tenant_id])[0]
    kinds = _alert_kinds(rep)
    assert "APPROVAL_QUEUE_AGE" in kinds and "UNSEALED_AGE" in kinds
    assert rep.report["checks"]["pending_approvals"] == 1


def test_no_age_alerts_below_thresholds(gw: Any) -> None:
    """Ages are compared in the right unit: a 1.2 s old item is below a 5 s threshold."""
    import time

    email(gw, EXTERNAL)
    time.sleep(1.2)
    rep = monitor(gw, unsealed_alert_seconds=5, approval_queue_alert_seconds=5).run_once(
        [gw.world.tenant_id]
    )[0]
    kinds = _alert_kinds(rep)
    assert "UNSEALED_AGE" not in kinds and "APPROVAL_QUEUE_AGE" not in kinds
    assert 1200 <= rep.report["checks"]["oldest_unsealed_ms"] < 5000


def test_tamper_in_unsealed_tail_detected_by_chain(gw: Any, pg: PgUrls) -> None:
    """The newest events are in no epoch yet: only the hash chain covers them (03 R2: an
    attacker could truncate the tail undetected, but not EDIT an event before the head)."""
    _activity(gw, 1)
    gw.post("test_echo", {"text": "tail"})
    gw.drain()  # 5 more events, not sealed
    with gw.engine.connect() as conn:
        tail = conn.execute(
            select(t.evidence_events.c.event_id, t.evidence_events.c.seq)
            .where(t.evidence_events.c.tenant_id == gw.world.tenant_id)
            .order_by(t.evidence_events.c.seq.desc())
            .offset(2)
            .limit(1)
        ).one()
    su(
        pg,
        "UPDATE evidence_events SET canonical_bytes = overlay(canonical_bytes placing "
        "decode('ff', 'hex') from 40 for 1) WHERE event_id = %s",
        (tail.event_id,),
    )
    # a recent-window run (max_events): the epochs are checked without events, so the hash
    # chain over the window is what must catch it
    rep = monitor(gw, max_events=4).run_once([gw.world.tenant_id])[0]
    assert rep.report["epochs"]["events_checked_against_epochs"] is False
    assert rep.result == "TAMPERED"
    assert rep.report["chain"]["first_bad_seq"] == tail.seq


def test_outcome_unknown_alert(gw: Any) -> None:
    from sqlalchemy import text

    from agw_gateway.execution.crash import SimulatedCrash

    gw.post("create_ticket", {"title": "t"})
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
    rep = monitor(gw).run_once([gw.world.tenant_id])[0]
    assert "OUTCOME_UNKNOWN" in _alert_kinds(rep)
    assert rep.report["checks"]["outcome_unknown_actions"] == 1


def test_dashboard_requested_run(gw: Any, migrator_engine: Engine) -> None:
    from agw_gateway.admin import ensure_human

    from ..approvalkit import PASSWORD

    _activity(gw, 1)
    ensure_human(migrator_engine, gw.world.tenant_id, "audrey", PASSWORD, ["auditor"])
    humans = make_humans(migrator_engine, gw.client, gw.world.tenant_id)
    r = gw.client.post("/v1/dashboard/verifications", headers=humans.headers("audrey"))
    assert r.status_code == 202
    r = gw.client.post("/v1/dashboard/verifications", headers=humans.headers("alice"))
    assert r.status_code == 403  # approvers cannot start verifier jobs
    assert monitor(gw).process_requests() == 1
    page = gw.client.get("/v1/dashboard/verifications", headers=humans.headers("audrey")).json()
    assert page["pending_requests"] == 0
    assert page["reports"][0]["trigger"] == "manual"
    assert page["reports"][0]["requested_by"] == "audrey"
    assert page["reports"][0]["result"] == "VERIFIED"
    assert "convenience view" in page["note"]
    full = gw.client.get(
        f"/v1/dashboard/verifications/{page['reports'][0]['report_id']}",
        headers=humans.headers("audrey"),
    ).json()
    assert full["report"]["tenant"] == gw.world.tenant_id
    assert uuid.UUID(full["summary"]["event_id"])
