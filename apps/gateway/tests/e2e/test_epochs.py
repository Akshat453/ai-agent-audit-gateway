"""Phase 3: sealing (triggers, determinism, races, self-check), DB tiling, epoch/proof API,
evidence bundles, the offline CLI and the tamper matrix."""

import io
import json
import subprocess
import sys
import threading
import time
import uuid
from pathlib import Path
from typing import Any

import jsonschema
import psycopg
import pytest
from sqlalchemy import Engine, select, text
from sqlalchemy.exc import DBAPIError

from agw_gateway.crypto.canonical import decode
from agw_gateway.db import tables as t
from agw_gateway.evidence import EvidenceWriter
from agw_gateway.evidence.bundle import build_bundle, export_epochs
from agw_gateway.evidence.export import export_chain
from agw_gateway.execution.crash import SimulatedCrash
from agw_verifier.epochs import verify_bundle, verify_epochs
from agw_worker.sealing import Sealer

pytestmark = pytest.mark.e2e

REPO = Path(__file__).resolve().parents[4]
SCHEMA = json.loads((REPO / "packages/schemas/bundle/evidence-bundle.v1.schema.json").read_text())
sys.path.insert(0, str(REPO / "experiments/tampering"))


def sealer(gw: Any, *, max_events: int = 5, max_age: float = 3600.0) -> Sealer:
    return Sealer(
        engine=gw.engine,
        writer=EvidenceWriter(),
        crash=gw.state.crash,
        max_events=max_events,
        max_age_seconds=max_age,
    )


def actions(gw: Any, n: int) -> list[str]:
    ids = [gw.post("test_echo", {"text": str(i)}).json()["action_id"] for i in range(n)]
    gw.drain()
    return ids  # 5 events each: REQUESTED, EVALUATED, AUTHORIZED, DISPATCHED, COMPLETED


def epochs_of(gw: Any) -> list[Any]:
    with gw.engine.connect() as conn:
        return conn.execute(
            select(t.epochs)
            .where(t.epochs.c.tenant_id == gw.world.tenant_id)
            .order_by(t.epochs.c.epoch_no)
        ).all()


def seal_jobs(gw: Any) -> list[Any]:
    with gw.engine.connect() as conn:
        return conn.execute(
            select(t.outbox_jobs).where(
                t.outbox_jobs.c.tenant_id == gw.world.tenant_id, t.outbox_jobs.c.kind == "SEAL"
            )
        ).all()


def exports(gw: Any) -> tuple[list[str], list[str]]:
    ev, ep = io.StringIO(), io.StringIO()
    export_chain(gw.engine, gw.world.tenant_id, ev)
    with gw.engine.connect() as conn:
        export_epochs(conn, gw.world.tenant_id, ep)
    return ev.getvalue().splitlines(), ep.getvalue().splitlines()


# ---------------------------------------------------------------------------- sealing
def test_no_events_no_seal(gw) -> None:
    s = sealer(gw, max_events=1, max_age=0.001)
    s.drain()
    assert epochs_of(gw) == [] and seal_jobs(gw) == []
    actions(gw, 1)
    s.drain()
    n = len(epochs_of(gw))
    assert n >= 1
    time.sleep(0.01)
    s.drain()  # only the EPOCH_SEALED receipt is pending -> no further seal
    assert len(epochs_of(gw)) == n


def test_max_events_tiles_and_receipts_land_in_later_epochs(gw) -> None:
    actions(gw, 4)  # seq 0..19
    s = sealer(gw, max_events=5)
    sealed = [r for r in s.drain() if r.tenant_id == gw.world.tenant_id]
    eps = epochs_of(gw)
    assert [(e.epoch_no, e.first_seq, e.last_seq, e.tree_size, e.seal_reason) for e in eps] == [
        (k, 5 * k, 5 * k + 4, 5, "MAX_EVENTS") for k in range(4)
    ]
    assert [r.epoch_root for r in sealed] == [bytes(e.epoch_root) for e in eps]
    assert all(bytes(eps[k].prev_root) == bytes(eps[k - 1].epoch_root) for k in range(1, 4))
    assert bytes(eps[0].prev_root) == bytes(32)
    with gw.engine.connect() as conn:
        receipts = conn.execute(
            select(t.evidence_events.c.seq, t.evidence_events.c.canonical_bytes)
            .where(
                t.evidence_events.c.tenant_id == gw.world.tenant_id,
                t.evidence_events.c.event_type == "EPOCH_SEALED",
            )
            .order_by(t.evidence_events.c.seq)
        ).all()
    assert [r.seq for r in receipts] == [20, 21, 22, 23]
    for k, r in enumerate(receipts):
        epoch = decode(bytes(r.canonical_bytes))["epoch"]
        assert (epoch["no"], epoch["root"], epoch["reason"]) == (
            k,
            bytes(eps[k].epoch_root),
            "MAX_EVENTS",
        )
    actions(gw, 1)  # seq 24..28 -> receipts get sealed into epoch 4 (a later epoch)
    s.drain()
    e4 = epochs_of(gw)[4]
    assert (e4.first_seq, e4.last_seq) == (20, 24)
    ev, ep = exports(gw)
    res = verify_epochs(ep, event_lines=ev, trusted_root=bytes(epochs_of(gw)[-1].epoch_root))
    assert res.result == "VERIFIED", res.as_dict()
    assert res.unsealed_events and res.unsealed_events > 0


def test_max_age_seals_everything_pending(gw) -> None:
    actions(gw, 1)
    s = sealer(gw, max_events=1000, max_age=0.3)
    s.drain()
    assert epochs_of(gw) == []  # too young
    time.sleep(0.35)
    s.drain()
    (e,) = epochs_of(gw)
    assert (e.first_seq, e.last_seq, e.seal_reason) == (0, 4, "MAX_AGE")


def test_crash_mid_seal_then_rerun_produces_identical_epoch(gw) -> None:
    actions(gw, 1)
    s = sealer(gw, max_events=5)
    s.request_seal(gw.world.tenant_id, 4)
    gw.state.crash.arm("seal_before_commit")
    with pytest.raises(SimulatedCrash):
        while True:  # other tenants' jobs may be processed first
            s.run_once()
    crashed = s.last_computed
    assert crashed is not None and crashed.tenant_id == gw.world.tenant_id
    assert epochs_of(gw) == []
    assert [j.status for j in seal_jobs(gw)] == ["PENDING"]  # rolled back with the tx
    s.drain()
    (e,) = epochs_of(gw)
    assert bytes(e.epoch_root) == crashed.epoch_root and bytes(e.merkle_root) == crashed.merkle_root
    assert [j.status for j in seal_jobs(gw)] == ["DONE"]


def test_two_sealers_racing_produce_one_epoch_chain(gw) -> None:
    actions(gw, 6)  # 30 events -> 6 epochs of 5
    workers = [sealer(gw, max_events=5) for _ in range(4)]
    errors: list[BaseException] = []
    barrier = threading.Barrier(len(workers))

    def run(s: Sealer) -> None:
        barrier.wait()
        try:
            for _ in range(20):
                s.drain()
        except BaseException as exc:
            errors.append(exc)

    threads = [threading.Thread(target=run, args=(w,)) for w in workers]
    for th in threads:
        th.start()
    for th in threads:
        th.join()
    assert errors == []
    eps = epochs_of(gw)
    assert [e.epoch_no for e in eps] == list(range(len(eps)))
    assert [(e.first_seq, e.last_seq) for e in eps[:6]] == [(5 * k, 5 * k + 4) for k in range(6)]
    assert all(eps[k].first_seq == eps[k - 1].last_seq + 1 for k in range(1, len(eps)))


def test_self_check_refuses_to_seal_over_a_broken_chain(gw, pg) -> None:
    actions(gw, 1)
    with psycopg.connect(pg.superuser, autocommit=True) as conn:
        conn.execute("ALTER TABLE evidence_events DISABLE TRIGGER USER")
        conn.execute(
            "UPDATE evidence_events SET canonical_bytes = canonical_bytes || '\\x00'::bytea "
            "WHERE tenant_id = %s AND seq = 2",
            (gw.world.tenant_id,),
        )
        conn.execute("ALTER TABLE evidence_events ENABLE TRIGGER USER")
    s = sealer(gw, max_events=5)
    s.drain()
    assert epochs_of(gw) == []
    jobs = seal_jobs(gw)
    assert [(j.status, j.last_error_code) for j in jobs] == [("FAILED", "SEAL_SELF_CHECK_FAILED")]
    s.drain()  # sealing stays stopped for this tenant
    assert len(seal_jobs(gw)) == 1 and epochs_of(gw) == []


# ---------------------------------------------------------------------------- DB rules
def _sqlstate(engine: Engine, sql: str, params: dict[str, Any] | None = None) -> str | None:
    with pytest.raises(DBAPIError) as exc, engine.begin() as conn:
        conn.execute(text(sql), params or {})
    return getattr(exc.value.orig, "sqlstate", None)


def test_db_enforces_tiling_and_append_only(gw, migrator_engine) -> None:
    actions(gw, 2)
    sealer(gw, max_events=5).drain()
    tid = gw.world.tenant_id
    last = epochs_of(gw)[-1]
    z = "'\\x" + "00" * 32 + "'::bytea"
    ins = (
        "INSERT INTO epochs (tenant_id, epoch_no, first_seq, last_seq, tree_size, merkle_root, prev_root, "
        "epoch_root, seal_reason) VALUES (:t, :no, :f, :l, :l - :f + 1, "
        + z
        + ", :p, "
        + z
        + ", 'MANUAL')"
    )
    nxt, lst, root = last.epoch_no + 1, last.last_seq, bytes(last.epoch_root)
    cases = {
        "gap": {"no": nxt, "f": lst + 2, "l": lst + 2, "p": root},
        "overlap": {"no": nxt, "f": lst, "l": lst + 1, "p": root},
        "wrong prev": {"no": nxt, "f": lst + 1, "l": lst + 1, "p": bytes(32)},
        "skipped epoch_no": {"no": nxt + 1, "f": lst + 1, "l": lst + 1, "p": root},
        "beyond chain head": {"no": nxt, "f": lst + 1, "l": lst + 10_000, "p": root},
    }
    for name, params in cases.items():
        assert _sqlstate(gw.engine, ins, {"t": tid, **params}) == "P0002", name
    assert _sqlstate(gw.engine, "UPDATE epochs SET seal_reason = 'MANUAL'") == "42501"
    assert _sqlstate(gw.engine, "DELETE FROM epochs") == "42501"
    assert _sqlstate(migrator_engine, "UPDATE epochs SET seal_reason = 'MANUAL'") == "P0001"
    assert (
        _sqlstate(migrator_engine, "DELETE FROM epochs WHERE tenant_id = :t", {"t": tid}) == "P0001"
    )


# ---------------------------------------------------------------------------- API + bundles
def _first_event_id(gw: Any, action_id: str) -> str:
    r = gw.client.get(f"/v1/events?action_id={action_id}", headers=gw.headers())
    return str(r.json()["events"][0]["event_id"])


def test_epoch_and_proof_endpoints_and_bundle_verification(gw, migrator_engine) -> None:
    ids = actions(gw, 3)
    pending_event = _first_event_id(gw, ids[-1])
    r = gw.client.get(f"/v1/events/{pending_event}/proof", headers=gw.headers())
    assert (r.status_code, r.json()["error"]["code"]) == (409, "EVENT_NOT_SEALED")
    sealer(gw, max_events=5).drain()
    h = gw.headers()
    latest = gw.client.get("/v1/epochs/latest", headers=h).json()
    assert latest["epoch_no"] == 2 and latest["tenant"] == gw.world.tenant_id
    assert gw.client.get("/v1/epochs/0", headers=h).json()["prev_root"] == "00" * 32
    assert gw.client.get("/v1/epochs/99", headers=h).status_code == 404
    assert gw.client.get("/v1/epochs/0?tenant=demo-other", headers=h).status_code == 404
    from agw_gateway.admin import create_key, ensure_agent

    ensure_agent(migrator_engine, gw.world.tenant_id, "evidence-admin", ["admin:evidence:read"])
    admin = create_key(migrator_engine, gw.world.tenant_id, "evidence-admin")
    other_tenant = gw.client.get(
        f"/v1/epochs/0?tenant={gw.world.tenant_id}", headers=gw.headers(admin)
    )
    assert other_tenant.status_code == 200

    event_id = _first_event_id(gw, ids[0])
    bundle = gw.client.get(f"/v1/events/{event_id}/proof", headers=h).json()
    jsonschema.validate(bundle, SCHEMA)
    assert "payload" not in bundle["event"]  # the API never returns payloads
    assert gw.client.get(f"/v1/events/{uuid.uuid4()}/proof", headers=h).status_code == 404
    root = bytes.fromhex(latest["epoch_root"])
    assert verify_bundle(bundle, trusted_root=root).result == "VERIFIED"
    assert verify_bundle(bundle, trusted_root=root, trusted_epoch=2).result == "VERIFIED"
    unanchored = verify_bundle(bundle)
    assert unanchored.result == "UNANCHORED" and "locally sealed only" in unanchored.notes[0]
    assert verify_bundle(bundle, trusted_root=bytes(32)).reason == "TRUSTED_ROOT_MISMATCH"
    # a later event, trusted root of an epoch BEFORE its epoch: cannot vouch
    later = gw.client.get(f"/v1/events/{_first_event_id(gw, ids[2])}/proof", headers=h).json()
    early_root = bytes.fromhex(gw.client.get("/v1/epochs/0", headers=h).json()["epoch_root"])
    assert verify_bundle(later, trusted_root=early_root, trusted_epoch=0).result == "INCOMPLETE"

    def tampered(path: list[str], value: Any) -> dict[str, Any]:
        b = json.loads(json.dumps(bundle))
        obj = b
        for k in path[:-1]:
            obj = obj[k]
        obj[path[-1]] = value
        return b

    hdr = bundle["event"]["header"]
    flipped = hdr[:40] + ("0" if hdr[40] != "0" else "1") + hdr[41:]
    assert verify_bundle(tampered(["event", "header"], flipped), trusted_root=root).result in (
        "INVALID_PROOF",
        "TAMPERED",
    )
    assert (
        verify_bundle(tampered(["proof", "leaf_index"], 1), trusted_root=root).result
        == "INVALID_PROOF"
    )
    assert (
        verify_bundle(tampered(["proof", "tree_size"], 6), trusted_root=root).result
        == "INVALID_PROOF"
    )
    assert (
        verify_bundle(tampered(["epoch", "merkle_root"], "11" * 32), trusted_root=root).result
        == "INVALID_PROOF"
    )
    assert (
        verify_bundle(tampered(["epoch", "tree_size"], 6), trusted_root=root).result == "TAMPERED"
    )
    assert (
        verify_bundle(
            tampered(["epoch_chain"], bundle["epoch_chain"][:-1]),
            trusted_root=root,
            trusted_epoch=2,
        ).reason
        == "TRUNCATED_BEFORE_TRUSTED_ROOT"
    )
    chain = json.loads(json.dumps(bundle["epoch_chain"]))
    chain[0]["merkle_root"] = "22" * 32
    assert (
        verify_bundle(tampered(["epoch_chain"], chain), trusted_root=root).reason
        == "EPOCH_ROOT_MISMATCH"
    )
    assert verify_bundle({"format": "nope"}).result == "INCOMPLETE"
    # payload-bearing bundle (operator export) also checks the payload commitment
    with gw.engine.connect() as conn:
        dispatched = conn.execute(
            select(t.evidence_events.c.event_id).where(
                t.evidence_events.c.action_id == uuid.UUID(ids[0]),
                t.evidence_events.c.event_type == "ACTION_DISPATCHED",
            )
        ).scalar_one()
        with_payload = build_bundle(conn, dispatched, tenant_id=None, include_payload=True)
    jsonschema.validate(with_payload, SCHEMA)
    assert verify_bundle(with_payload, trusted_root=root).result == "VERIFIED"
    bad = json.loads(json.dumps(with_payload))
    bad["event"]["payload"] = bad["event"]["payload"][:-2] + (
        "00" if bad["event"]["payload"][-2:] != "00" else "01"
    )
    assert verify_bundle(bad, trusted_root=root).result == "TAMPERED"


def test_cli_verifies_exports_after_gateway_stopped(gw, tmp_path: Path) -> None:
    ids = actions(gw, 3)
    sealer(gw, max_events=5).drain()
    h = gw.headers()
    bundle = gw.client.get(f"/v1/events/{_first_event_id(gw, ids[1])}/proof", headers=h).json()
    root = gw.client.get("/v1/epochs/latest", headers=h).json()["epoch_root"]
    ev, ep = exports(gw)
    (tmp_path / "b.json").write_text(json.dumps(bundle))
    (tmp_path / "events.jsonl").write_text("\n".join(ev) + "\n")
    (tmp_path / "epochs.jsonl").write_text("\n".join(ep) + "\n")
    gw.client.__exit__(None, None, None)  # stop the gateway app (lifespan shutdown)
    cli = [sys.executable, "-m", "agw_verifier.cli"]

    def run(*args: str) -> tuple[int, dict[str, Any]]:
        p = subprocess.run([*cli, *args, "--json"], capture_output=True, text=True, check=False)
        return p.returncode, json.loads(p.stdout)

    code, rep = run("event", "--bundle", str(tmp_path / "b.json"), "--trusted-root", root)
    assert (code, rep["result"]) == (0, "VERIFIED")
    code, rep = run("event", "--bundle", str(tmp_path / "b.json"))
    assert (code, rep["result"]) == (4, "UNANCHORED")
    code, rep = run(
        "epochs",
        "--export",
        str(tmp_path / "epochs.jsonl"),
        "--events",
        str(tmp_path / "events.jsonl"),
        "--trusted-root",
        root,
    )
    assert (code, rep["result"]) == (0, "VERIFIED")
    p = subprocess.run(
        [*cli, "event", "--bundle", str(tmp_path / "b.json"), "--trusted-root", "zz"],
        capture_output=True,
        check=False,
    )
    assert p.returncode == 64


# ---------------------------------------------------------------------------- tamper matrix
def test_tamper_matrix(gw) -> None:
    from tamper_suite import Material, markdown, run_matrix

    actions(gw, 5)  # 25 events -> 5 epochs of 5
    sealer(gw, max_events=5).drain()
    ev, ep = exports(gw)
    m = Material.load(ev, ep)
    assert len(m.epochs) >= 4
    rows = {(r["attack"], r["adversary"]): r for r in run_matrix(m, attacked_epoch=1)}
    print("\n" + markdown(list(rows.values())))
    assert (
        verify_epochs(
            ep, event_lines=ev, trusted_root=bytes.fromhex(m.epochs[-1]["epoch_root"])
        ).result
        == "VERIFIED"
    )
    # naive tampering is detected even without any trust root
    assert rows[("edit event", "naive")]["none"] == "TAMPERED"
    assert rows[("delete whole epoch", "naive")]["none"] == "TAMPERED"
    # a full-rewrite insider is only caught by a trusted root at/after the attacked epoch
    for attack in (
        "edit event",
        "delete event",
        "reorder two events",
        "delete whole epoch",
        "fork epoch (same prev, other root)",
    ):
        r = rows[(attack, "rewriter")]
        assert r["none"] == "UNANCHORED", attack
        assert r["before"] == "UNANCHORED", attack  # later epochs not covered by the old root
        assert r["after"] == "TAMPERED", attack
    trunc = rows[("truncate tail (from epoch)", "rewriter")]
    assert trunc["none"] == "UNANCHORED"
    assert trunc["before"] == "VERIFIED"  # an old trusted root cannot see a later truncation
    assert (trunc["after"], trunc["after_reason"]) == ("TAMPERED", "TRUNCATED_BEFORE_TRUSTED_ROOT")
