"""Phase 2: evidence round-trips gateway -> export -> standalone verifier; DB tampering by a
privileged attacker (superuser, triggers disabled) is detected; 50 concurrent actions form a
contiguous, valid chain; /v1/events and logs never contain payload content."""

import io
import logging
import threading
import uuid
from typing import Any

import psycopg
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from agw_gateway.crypto.canonical import decode
from agw_gateway.db import tables as t
from agw_gateway.evidence.export import export_chain
from agw_verifier.chain import verify_lines

pytestmark = pytest.mark.e2e

CANARY = "CANARY-p2-5b1e-NEVER-IN-HEADERS"


def _export(gw: Any, **kw: Any) -> list[str]:
    buf = io.StringIO()
    export_chain(gw.engine, gw.world.tenant_id, buf, store=gw.state.payloads, **kw)
    return buf.getvalue().splitlines()


def _head(gw: Any) -> tuple[int, bytes]:
    with gw.engine.connect() as conn:
        h = conn.execute(
            select(t.chain_heads).where(t.chain_heads.c.tenant_id == gw.world.tenant_id)
        ).one()
    return h.last_seq, bytes(h.last_hash)


def _su(pg: Any, sql: str, params: tuple = ()) -> None:
    """Privileged attacker: superuser who can bypass the append-only triggers."""
    with psycopg.connect(pg.superuser, autocommit=True) as conn:
        conn.execute("SET session_replication_role = replica")  # no triggers, no FK checks
        conn.execute(sql, params)  # type: ignore[arg-type]


def _lifecycle(gw: Any) -> str:
    r = gw.post(
        "create_ticket",
        {"title": "p2 ticket", "body": "b", "priority": "high"},
        intent={"summary": "open a ticket"},
        context={"sources": [{"uri": "kb://doc/1", "sha256": "ab" * 32}]},
        agent_version="demo-agent/2.1",
    )
    assert r.status_code == 201
    gw.drain()
    return str(r.json()["action_id"])


def test_full_lifecycle_round_trips_and_verifies(gw) -> None:
    aid = _lifecycle(gw)
    gw.post("delete_record", {"record_id": str(uuid.uuid4())})  # a DENY too
    seq, head = _head(gw)
    lines = _export(gw)
    report = verify_lines(lines, trusted_head=head, trusted_seq=seq)
    assert report.as_dict()["result"] == "VERIFIED", report.as_dict()
    assert report.events_checked == seq + 1 == 8

    # The eight fields, read back from canonical bytes (not from the JSONB projection).
    with gw.engine.connect() as conn:
        rows = conn.execute(
            select(
                t.evidence_events.c.event_id,
                t.evidence_events.c.event_type,
                t.evidence_events.c.canonical_bytes,
            )
            .where(t.evidence_events.c.action_id == uuid.UUID(aid))
            .order_by(t.evidence_events.c.seq)
        ).all()
        by_type = {}
        for r in rows:
            content = gw.state.payloads.load_payload(conn, r.event_id)  # decrypts (KEK)
            by_type[r.event_type] = (
                decode(bytes(r.canonical_bytes)),
                content and decode(content),
            )
    req_h, req_p = by_type["ACTION_REQUESTED"]
    assert req_p["intent"] == {
        "args": {"title": "p2 ticket", "body": "b", "priority": "high"},
        "summary": "open a ticket",
    }
    assert req_p["context"] == {
        "sources": [{"uri": "kb://doc/1", "digest": bytes.fromhex("ab" * 32)}]
    }
    assert "delegation" in req_p and req_p["delegation"] is None
    assert req_h["code"]["agent"] == "demo-agent/2.1" and req_h["code"]["gw"]
    assert by_type["POLICY_EVALUATED"][0]["policy"]["rules"] == ["allow-medium"]
    auth_h = by_type["ACTION_AUTHORIZED"][0]
    assert auth_h["code"]["adapter"].endswith("CreateTicketAdapter@1.0.0")
    disp_h, disp_p = by_type["ACTION_DISPATCHED"]
    assert disp_h["args"] == auth_h["args"] and len(disp_h["args"]) == 32  # same args digest
    assert disp_p["execution"]["params"] == {"title": "p2 ticket", "body": "b", "priority": "high"}
    assert disp_h["dispatch"]["cg"] and disp_h["obs"] > 0
    done_h, done_p = by_type["ACTION_COMPLETED"]
    assert set(done_p["effects"]["result"]) == {"ticket_id"}
    assert done_h["obs"] >= disp_h["obs"]
    for header, _ in by_type.values():
        assert "reasoning" not in header and header["tenant"] == gw.world.tenant_id


def test_reasoning_field_is_rejected(gw) -> None:
    r = gw.post("public_doc_search", {"query": "x"}, reasoning="my chain of thought")
    assert r.status_code == 422 and r.json()["error"]["fields"] == ["reasoning"]


def test_invalid_args_are_not_stored_only_keys_and_salted_digest(gw) -> None:
    """Phase 7 (ADR-0029 §4): unvalidated args cannot be classified, so their values are never
    stored (Phase 2 kept them as JSON text). Key names + a per-tenant salted digest remain."""
    aid = gw.post("public_doc_search", {"query": "x", "limit": 2.5}).json()["action_id"]
    with gw.engine.connect() as conn:
        eid = conn.execute(
            select(t.evidence_events.c.event_id).where(
                t.evidence_events.c.action_id == uuid.UUID(aid),
                t.evidence_events.c.event_type == "ACTION_REQUESTED",
            )
        ).scalar_one()
        content = gw.state.payloads.load_payload(conn, eid)
    intent = decode(content)["intent"]
    assert set(intent) == {"args_unvalidated"}  # no raw values anywhere in the payload
    assert set(intent["args_unvalidated"]) == {"keys", "digest"}
    assert intent["args_unvalidated"]["keys"] == ["limit", "query"]
    assert intent["args_unvalidated"]["digest"].startswith("[REDACTED:sha256:")


@pytest.mark.parametrize("target", ["header", "payload"])
def test_one_byte_edit_in_db_is_tampered_at_that_seq(gw, pg, target: str) -> None:
    _lifecycle(gw)
    seq, head = _head(gw)
    victim = 3  # ACTION_DISPATCHED (has a payload)
    if target == "header":
        sql = (
            "UPDATE evidence_events SET canonical_bytes = overlay(canonical_bytes placing "
            "decode(lpad(to_hex(get_byte(canonical_bytes, 40) # 1), 2, '0'), 'hex') from 41 for 1) "
            "WHERE tenant_id = %s AND seq = %s"
        )
    else:
        # Phase 7: the stored bytes are AES-GCM ciphertext; one flipped byte fails the
        # stored SHA-256 / AEAD tag, which the export reports and the verifier calls TAMPERED.
        sql = (
            "UPDATE payload_objects SET ciphertext = overlay(ciphertext placing "
            "decode(lpad(to_hex(get_byte(ciphertext, 20) # 1), 2, '0'), 'hex') from 21 for 1) "
            "WHERE tenant_id = %s AND seq = %s"
        )
    _su(pg, sql, (gw.world.tenant_id, victim))
    r = verify_lines(_export(gw), trusted_head=head, trusted_seq=seq)
    assert (r.result, r.first_bad_seq) == ("TAMPERED", victim), r.as_dict()


def test_delete_middle_event_detected(gw, pg) -> None:
    _lifecycle(gw)
    seq, head = _head(gw)
    _su(pg, "DELETE FROM payload_keys WHERE event_id IN (SELECT event_id FROM payload_objects "
        "WHERE tenant_id = %s AND seq = 2)", (gw.world.tenant_id,))  # fmt: skip
    _su(pg, "DELETE FROM payload_objects WHERE tenant_id = %s AND seq = 2", (gw.world.tenant_id,))
    _su(pg, "DELETE FROM evidence_events WHERE tenant_id = %s AND seq = 2", (gw.world.tenant_id,))
    r = verify_lines(_export(gw), trusted_head=head, trusted_seq=seq)
    assert r.result in ("TAMPERED", "INCOMPLETE")
    assert r.missing_ranges == [(2, 2)]
    # A smarter attacker renumbers the tail to close the gap: the prev link breaks.
    # Two steps, so the (tenant, seq) unique check never depends on the row update order
    # (a single "seq = seq - 1" collides whenever Postgres happens to visit seq 4 first).
    _su(
        pg,
        "UPDATE evidence_events SET seq = seq + 1000000 WHERE tenant_id = %s AND seq > 2",
        (gw.world.tenant_id,),
    )
    _su(
        pg,
        "UPDATE evidence_events SET seq = seq - 1000001 WHERE tenant_id = %s AND seq > 1000000",
        (gw.world.tenant_id,),
    )
    r2 = verify_lines(_export(gw, to_seq=seq))
    assert r2.result == "TAMPERED"


def test_suffix_deletion_needs_a_trusted_head(gw, pg) -> None:
    _lifecycle(gw)
    seq, head = _head(gw)  # an auditor recorded this head earlier (out of band)
    # Attacker deletes the newest two events and rewinds the chain head consistently.
    with gw.engine.connect() as conn:
        new_last = conn.execute(
            select(t.evidence_events.c.event_hash).where(
                t.evidence_events.c.tenant_id == gw.world.tenant_id,
                t.evidence_events.c.seq == seq - 2,
            )
        ).scalar_one()
    _su(
        pg,
        "DELETE FROM payload_objects WHERE tenant_id = %s AND seq > %s",
        (gw.world.tenant_id, seq - 2),
    )
    _su(
        pg,
        "DELETE FROM evidence_events WHERE tenant_id = %s AND seq > %s",
        (gw.world.tenant_id, seq - 2),
    )
    _su(
        pg,
        "UPDATE chain_heads SET last_seq = %s, last_hash = %s WHERE tenant_id = %s",
        (seq - 2, bytes(new_last), gw.world.tenant_id),
    )
    lines = _export(gw)
    assert (
        verify_lines(lines).result == "VERIFIED"
    )  # NOT detectable without a trusted head (by design)
    r = verify_lines(lines, trusted_head=head, trusted_seq=seq)
    assert (r.result, r.reason, r.first_bad_seq) == (
        "TAMPERED",
        "TRUNCATED_BEFORE_TRUSTED_HEAD",
        seq - 1,
    )


def test_reordering_two_events_is_tampered(gw, pg) -> None:
    _lifecycle(gw)
    seq, head = _head(gw)
    tid = gw.world.tenant_id
    _su(pg, "UPDATE evidence_events SET seq = 999999 WHERE tenant_id = %s AND seq = 1", (tid,))
    _su(pg, "UPDATE evidence_events SET seq = 1 WHERE tenant_id = %s AND seq = 2", (tid,))
    _su(pg, "UPDATE evidence_events SET seq = 2 WHERE tenant_id = %s AND seq = 999999", (tid,))
    r = verify_lines(_export(gw), trusted_head=head, trusted_seq=seq)
    assert (r.result, r.first_bad_seq) == ("TAMPERED", 1)


def test_fifty_concurrent_actions_contiguous_valid_chain(gw) -> None:
    run_id = str(uuid.uuid4())
    barrier = threading.Barrier(50)
    codes: list[int] = []
    lock = threading.Lock()

    def fire(i: int) -> None:
        c = TestClient(gw.client.app)
        barrier.wait()
        r = c.post(
            "/v1/actions",
            json={
                "run_id": run_id,
                "tool": "test_echo",
                "environment": "dev",
                "args": {"text": str(i)},
            },
            headers=gw.headers(),
        )
        with lock:
            codes.append(r.status_code)

    threads = [threading.Thread(target=fire, args=(i,)) for i in range(50)]
    for th in threads:
        th.start()
    for th in threads:
        th.join()
    assert codes == [201] * 50
    gw.drain()
    seq, head = _head(gw)
    assert seq + 1 == 50 * 5  # REQUESTED, EVALUATED, AUTHORIZED, DISPATCHED, COMPLETED
    with gw.engine.connect() as conn:
        seqs = (
            conn.execute(
                select(t.evidence_events.c.seq)
                .where(t.evidence_events.c.tenant_id == gw.world.tenant_id)
                .order_by(t.evidence_events.c.seq)
            )
            .scalars()
            .all()
        )
    assert seqs == list(range(250))
    r = verify_lines(_export(gw), trusted_head=head, trusted_seq=seq)
    assert (r.result, r.events_checked) == ("VERIFIED", 250)
    assert len(gw.spies.echo.calls) == 50


def test_events_endpoint_filters_scope_and_no_payload(gw, migrator_engine, caplog) -> None:
    caplog.set_level(logging.DEBUG)
    rid = str(uuid.uuid4())
    aid = gw.post("create_ticket", {"title": CANARY, "body": CANARY}, run_id=rid).json()[
        "action_id"
    ]
    gw.post("public_doc_search", {"query": CANARY}, run_id=rid, token=gw.world.other_token)
    gw.drain()
    h = gw.headers()
    mine = gw.client.get("/v1/events", headers=h)
    assert mine.status_code == 200
    assert CANARY not in mine.text
    events = mine.json()["events"]
    assert {e["type"] for e in events} >= {"ACTION_REQUESTED", "ACTION_COMPLETED"}
    assert all(e["header"]["actor"]["id"] != str(gw.world.other_id) for e in events)
    assert all(
        "payload" not in e or set(e["header"]["payload"]) == {"digest", "len", "ref"}
        for e in events
    )
    assert all(len(e["event_hash"]) == 64 for e in events)
    # filters
    q = gw.client.get(f"/v1/events?action_id={aid}&type=ACTION_DISPATCHED", headers=h).json()[
        "events"
    ]
    assert [e["type"] for e in q] == ["ACTION_DISPATCHED"]
    assert (
        gw.client.get("/v1/events?tool=create_ticket&from_seq=0&to_seq=1", headers=h).json()[
            "events"
        ][-1]["seq"]
        <= 1
    )
    assert (
        gw.client.get(f"/v1/events?run_id={rid}&limit=2", headers=h).json()["next_from_seq"]
        is not None
    )
    # other agent's events: not visible without the audit scope
    assert gw.client.get(f"/v1/events?agent_id={gw.world.other_id}", headers=h).status_code == 404
    # with audit scope: tenant-wide (still headers only)
    from agw_gateway.admin import create_key, ensure_agent

    ensure_agent(migrator_engine, gw.world.tenant_id, "auditor", ["audit:events:read"])
    auditor = create_key(migrator_engine, gw.world.tenant_id, "auditor")
    wide = gw.client.get(f"/v1/events?agent_id={gw.world.other_id}", headers=gw.headers(auditor))
    assert wide.status_code == 200 and wide.json()["events"] and CANARY not in wide.text
    server_logs = [r for r in caplog.records if not r.name.startswith("httpx")]
    assert server_logs and all(CANARY not in repr(r.__dict__) for r in server_logs)
