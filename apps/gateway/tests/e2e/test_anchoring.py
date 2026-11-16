"""Phase 6: blockchain anchoring on a real Anvil node (ADR-0028).

Required tests (prompt) -> test:
  seal -> anchor -> finalized -> verifier VERIFIED offline ... test_seal_anchor_finalize_verify
  edit a DB epoch root after anchoring -> TAMPERED ........... test_edit_db_epoch_root_after_anchoring
  delete DB tail -> missing epochs vs chain lastEpoch ........ test_delete_db_tail_detected_vs_chain
  wrong contract address in bundle -> UNTRUSTED_ANCHOR ....... test_wrong_contract_in_bundle_untrusted
  kill RPC mid-submit; restart -> same root, one anchor ...... test_kill_rpc_mid_submit_restart_*
  simulated reorg (snapshot/revert) -> same root resubmitted . test_reorg_resubmits_same_root
  CRITICAL pre-anchor: RPC down -> fails closed, no adapter .. test_critical_pre_anchor_rpc_down_*
"""

from __future__ import annotations

import contextlib
import json
import subprocess
import sys
import time
import uuid
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import psycopg
import pytest
from fastapi.testclient import TestClient
from prometheus_client import REGISTRY
from sqlalchemy import Engine, select, text
from sqlalchemy.exc import DBAPIError

from agw_gateway.admin import create_key, ensure_agent
from agw_gateway.api.app import build_state, create_app
from agw_gateway.crypto.canonical import decode
from agw_gateway.crypto.merkle import epoch_root, merkle_root
from agw_gateway.db import tables as t
from agw_gateway.execution.crash import SimulatedCrash
from agw_worker.anchoring import AnchorItem
from agw_worker.anchoring.evm import EvmAnchorBackend

from ..anchorkit import (
    SALT,
    Chain,
    Recorder,
    bundle_for,
    deploy_registry,
    echo,
    epochs_export,
    first_event_id,
    new_key,
    register,
    rpc_proxy,
    sealer,
    trust_file,
    verify,
)
from ..approvalkit import decide, make_humans
from ..conftest import ALL_SCOPES, Gw, PgUrls, World, make_registry, make_settings, make_spies

pytestmark = pytest.mark.e2e

REPO = Path(__file__).resolve().parents[4]


@pytest.fixture
def rec(chain: Chain, migrator_engine: Engine, gw: Gw) -> Recorder:
    return register(chain, migrator_engine, gw)


def epochs_of(gw: Any) -> list[Any]:
    with gw.engine.connect() as conn:
        return list(
            conn.execute(
                select(t.epochs)
                .where(t.epochs.c.tenant_id == gw.world.tenant_id)
                .order_by(t.epochs.c.epoch_no)
            ).all()
        )


def chain_args(tmp: Path, rec: Recorder, **trust: Any) -> list[str]:
    return ["--chain-rpc", rec.chain.rpc, "--trust-config", trust_file(tmp, rec.trust(**trust))]


def anchored_world(gw: Gw, rec: Recorder, actions: int = 3) -> tuple[list[str], list[Any]]:
    ids = echo(gw, actions)
    sealer(gw).drain()
    eps = epochs_of(gw)
    assert len(eps) >= 1
    a = rec.anchorer()
    a.tick()
    a.tick()
    assert [r.status for r in rec.anchors()] == ["FINALIZED"] * len(eps)
    return ids, eps


@contextlib.contextmanager
def superuser(pg: PgUrls) -> Iterator[Any]:
    """An operator with full DB rights who disables triggers (the threat in 03 R8)."""
    with psycopg.connect(pg.superuser, autocommit=True) as conn:
        conn.execute("SET session_replication_role = replica")
        yield conn


# ============================================================================ happy path
def test_seal_anchor_finalize_verify(gw: Gw, rec: Recorder, tmp_path: Path) -> None:
    ids = echo(gw, 3)
    sealer(gw).drain()
    eps = epochs_of(gw)
    assert len(eps) >= 3
    a = rec.anchorer(finality="confirmations:10")
    rep = a.tick()
    assert rep.error is None and rep.submitted == len(eps)
    a.tick()
    assert {r.status for r in rec.anchors()} == {"INCLUDED"}  # mined, not yet final
    bundle = bundle_for(gw, first_event_id(gw, ids[0], "ACTION_COMPLETED"))
    rc, report = verify(
        tmp_path, "event", bundle, *chain_args(tmp_path, rec, finality="confirmations:10")
    )
    assert (rc, report["result"], report["reason"]) == (4, "UNANCHORED", "ANCHOR_NOT_FINAL")

    rec.chain.mine(10)
    a.tick()
    rows = rec.anchors()
    assert [r.status for r in rows] == ["FINALIZED"] * len(eps)
    for e, r in zip(eps, rows, strict=True):
        root, size, last, _, block = rec.onchain(int(e.epoch_no))
        assert (root, size, last) == (bytes(e.epoch_root), int(e.tree_size), int(e.last_seq))
        assert block == r.block_number and r.gas_used > 0
        assert rec.chain.anchored_logs(rec.rid, int(e.epoch_no)) == 1
    assert rec.next_epoch() == len(eps)
    # on-chain: recorder id, epoch no, root, size, last seq, time. No tenant name, no payload.
    assert (
        gw.world.tenant_id.encode()
        not in rec.chain.w3.eth.get_transaction(rows[0].tx_hash)["input"]
    )

    # ---- offline: only the bundle, a pinned trust config and a chain RPC
    trust = rec.trust(finality="confirmations:10")
    rc, report = verify(
        tmp_path, "event", bundle, *chain_args(tmp_path, rec, finality="confirmations:10")
    )
    assert (rc, report["result"]) == (0, "VERIFIED"), report
    assert report["anchor"]["epoch_no"] == bundle["epoch"]["epoch_no"]
    rc, report = verify(
        tmp_path,
        "epochs",
        epochs_export(gw),
        *chain_args(tmp_path, rec, finality="confirmations:10"),
    )
    assert (rc, report["result"]) == (0, "VERIFIED"), report
    # same through the installed console script, explicit flags instead of a config file
    bpath = tmp_path / "b.json"
    bpath.write_text(json.dumps(bundle))
    proc = subprocess.run(
        [
            str(Path(sys.executable).parent / "agw-verify"),
            "event", "--bundle", str(bpath), "--chain-rpc", rec.chain.rpc,
            "--chain-id", str(trust["chain_id"]), "--contract", trust["contract"],
            "--recorder-id", trust["recorder_id"], "--finality", "confirmations:10",
        ],
        capture_output=True, text=True, check=False,
    )  # fmt: skip
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "RESULT: VERIFIED" in proc.stdout


def test_verifier_chain_unreachable_is_incomplete(gw: Gw, rec: Recorder, tmp_path: Path) -> None:
    ids, _ = anchored_world(gw, rec, 1)
    bundle = bundle_for(gw, first_event_id(gw, ids[0], "ACTION_REQUESTED"))
    with rpc_proxy(rec.chain.rpc) as px:
        px.mode = "down"
        rc, report = verify(
            tmp_path, "event", bundle, "--chain-rpc", px.url,
            "--trust-config", trust_file(tmp_path, rec.trust()),
        )  # fmt: skip
    assert (rc, report["result"]) == (2, "INCOMPLETE")
    assert report["reason"].startswith("CHAIN_UNAVAILABLE")


# ============================================================================ tampering
def test_edit_db_epoch_root_after_anchoring(
    gw: Gw, rec: Recorder, pg: PgUrls, tmp_path: Path
) -> None:
    ids, eps = anchored_world(gw, rec)
    event_id = first_event_id(gw, ids[0], "ACTION_REQUESTED")  # lives in epoch 0
    assert bundle_for(gw, event_id)["epoch"]["epoch_no"] == 0

    # (a) blunt edit of a stored root: caught offline already, and by the anchor.
    with superuser(pg) as su:
        su.execute(
            "UPDATE epochs SET epoch_root = %s WHERE tenant_id = %s AND epoch_no = 0",
            (b"\x42" * 32, gw.world.tenant_id),
        )
    bundle = bundle_for(gw, event_id)
    rc, report = verify(tmp_path, "event", bundle, *chain_args(tmp_path, rec))
    assert (rc, report["result"]) == (1, "TAMPERED")

    # (b) consistent rewrite: re-seal the same events into a different partition (merge
    # epochs 0 and 1), recomputing every M_t, R_t and prev link. Every offline check passes;
    # only the on-chain anchor shows the history was rewritten.
    tenant = gw.world.tenant_id
    with gw.engine.connect() as conn:
        hashes = [
            bytes(h)
            for h in conn.execute(
                select(t.evidence_events.c.event_hash)
                .where(t.evidence_events.c.tenant_id == tenant)
                .order_by(t.evidence_events.c.seq)
            ).scalars()
        ]
    ranges = [(0, int(eps[1].last_seq))] + [(int(e.first_seq), int(e.last_seq)) for e in eps[2:]]
    prev = bytes(32)
    with superuser(pg) as su:
        su.execute("DELETE FROM epochs WHERE tenant_id = %s", (tenant,))
        for no, (first, last) in enumerate(ranges):
            m = merkle_root(hashes[first : last + 1])
            size = last - first + 1
            root = epoch_root(tenant, no, size, first, last, m, prev)
            su.execute(
                "INSERT INTO epochs (tenant_id, epoch_no, first_seq, last_seq, tree_size, "
                "merkle_root, prev_root, epoch_root, seal_reason) "
                "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, 'MAX_EVENTS')",
                (tenant, no, first, last, size, m, prev, root),
            )
            prev = root
    forged = bundle_for(gw, event_id)
    rc, report = verify(tmp_path, "event", forged)  # offline only: internally consistent
    assert (rc, report["result"]) == (4, "UNANCHORED")
    rc, report = verify(tmp_path, "event", forged, *chain_args(tmp_path, rec))
    assert (rc, report["result"], report["reason"]) == (1, "TAMPERED", "ANCHOR_ROOT_MISMATCH")
    rc, report = verify(tmp_path, "epochs", epochs_export(gw), *chain_args(tmp_path, rec))
    assert (rc, report["result"]) == (1, "TAMPERED")


def test_delete_db_tail_detected_vs_chain(
    gw: Gw, rec: Recorder, pg: PgUrls, tmp_path: Path
) -> None:
    _, eps = anchored_world(gw, rec, 4)
    last = int(eps[-1].epoch_no)
    cut = int(eps[-2].first_seq)  # drop the last two epochs and every event from there on
    tenant = gw.world.tenant_id
    with superuser(pg) as su:
        su.execute("DELETE FROM epochs WHERE tenant_id = %s AND epoch_no >= %s", (tenant, last - 1))
        su.execute("DELETE FROM payload_objects WHERE tenant_id = %s AND seq >= %s", (tenant, cut))
        su.execute("DELETE FROM evidence_events WHERE tenant_id = %s AND seq >= %s", (tenant, cut))
    export = epochs_export(gw)
    rc, report = verify(tmp_path, "epochs", export)  # offline: a shorter history looks fine
    assert rc == 4 and report["result"] == "UNANCHORED"
    rc, report = verify(tmp_path, "epochs", export, *chain_args(tmp_path, rec))
    assert (rc, report["result"], report["reason"]) == (1, "TAMPERED", "EPOCHS_MISSING_VS_CHAIN")
    assert report["first_bad_epoch"] == last - 1
    assert report["chain_last_epoch"] == last


def test_wrong_contract_in_bundle_untrusted(gw: Gw, rec: Recorder, tmp_path: Path) -> None:
    ids, _ = anchored_world(gw, rec, 1)
    bundle = bundle_for(gw, first_event_id(gw, ids[0], "ACTION_REQUESTED"))
    assert bundle["anchor"]["contract"] == rec.chain.contract  # the producer's (untrusted) claim
    rc, _ = verify(tmp_path, "event", bundle, *chain_args(tmp_path, rec))
    assert rc == 0

    # The bundle names another registry: never followed, never trusted.
    evil = deploy_registry(rec.chain.rpc)
    wrong = json.loads(json.dumps(bundle))
    wrong["anchor"]["contract"] = evil.contract
    rc, report = verify(tmp_path, "event", wrong, *chain_args(tmp_path, rec))
    assert (rc, report["result"], report["reason"]) == (
        5, "UNTRUSTED_ANCHOR", "BUNDLE_CONTRACT_NOT_PINNED",
    )  # fmt: skip
    wrong = json.loads(json.dumps(bundle))
    wrong["anchor"]["chain_id"] = 84532
    rc, report = verify(tmp_path, "event", wrong, *chain_args(tmp_path, rec))
    assert (rc, report["reason"]) == (5, "BUNDLE_CHAIN_ID_NOT_PINNED")

    # Trust roots taken from nowhere but the bundle -> UNTRUSTED_ANCHOR.
    rc, report = verify(tmp_path, "event", bundle, "--chain-rpc", rec.chain.rpc)
    assert (rc, report["result"], report["reason"]) == (
        5,
        "UNTRUSTED_ANCHOR",
        "TRUST_ROOTS_NOT_PINNED",
    )
    # Pinned chain id differs from the RPC's chain; pinned code hash differs from the contract.
    rc, report = verify(tmp_path, "event", bundle, *chain_args(tmp_path, rec, chain_id=84532))
    assert (rc, report["reason"]) == (5, "BUNDLE_CHAIN_ID_NOT_PINNED")
    stripped = {k: v for k, v in bundle.items() if k != "anchor"}
    rc, report = verify(tmp_path, "event", stripped, *chain_args(tmp_path, rec, chain_id=84532))
    assert (rc, report["reason"]) == (5, "RPC_CHAIN_ID_MISMATCH")
    rc, report = verify(
        tmp_path, "event", bundle, *chain_args(tmp_path, rec, code_sha256="00" * 32)
    )
    assert (rc, report["reason"]) == (5, "CONTRACT_CODE_MISMATCH")

    # The claims are informational: a bundle with them stripped still verifies against the
    # pinned roots (they were never what made it trustworthy).
    rc, report = verify(tmp_path, "event", stripped, *chain_args(tmp_path, rec))
    assert (rc, report["result"]) == (0, "VERIFIED")


# ============================================================================ worker resilience
def test_kill_rpc_mid_submit_restart_same_root_single_anchor(gw: Gw, rec: Recorder) -> None:
    echo(gw, 2)
    sealer(gw).drain()
    eps = epochs_of(gw)
    with rpc_proxy(rec.chain.rpc) as px:
        first = rec.anchorer(rpc=px.url)
        px.mode = "drop_send"  # the tx reaches the node, the reply never reaches us
        rep = first.tick()
        assert rep.error is not None and rep.error.startswith("RPC")
        assert px.sent_raw == 1
        row = rec.anchors()[0]
        assert row.status == "SUBMITTED" and row.tx_hash is not None  # write-ahead
        written_ahead = (bytes(row.tx_hash), bytes(row.raw_tx), int(row.nonce))

        px.mode = "up"
        restarted = rec.anchorer(rpc=px.url)  # new process: no in-memory state carried over
        for _ in range(3):
            restarted.tick()
    rows = rec.anchors()
    assert [r.status for r in rows] == ["FINALIZED"] * len(eps)
    assert (bytes(rows[0].tx_hash), bytes(rows[0].raw_tx), int(rows[0].nonce)) == written_ahead
    for e in eps:
        assert rec.onchain(int(e.epoch_no))[0] == bytes(e.epoch_root)  # same root
        assert rec.chain.anchored_logs(rec.rid, int(e.epoch_no)) == 1  # single anchor
    assert rec.next_epoch() == len(eps)


def test_kill_rpc_mid_submit_restart_crash_before_broadcast(gw: Gw, rec: Recorder) -> None:
    echo(gw, 1)
    sealer(gw).drain()
    first = rec.anchorer()
    gw.state.crash.arm("anchor_before_broadcast")
    with pytest.raises(SimulatedCrash):
        first.tick()  # process dies after the write-ahead commit, before sending
    row = rec.anchors()[0]
    assert row.status == "SUBMITTED"
    assert not rec.chain.w3.eth.get_transaction_count(rec.chain.w3.to_checksum_address(rec.address))
    restarted = rec.anchorer()
    for _ in range(3):
        restarted.tick()
    rows = rec.anchors()
    assert rows[0].status == "FINALIZED"
    assert bytes(rows[0].tx_hash) == bytes(row.tx_hash)  # identical bytes re-broadcast
    assert rows[0].resubmissions == 1 and rows[0].last_error == "NOT_IN_POOL"
    assert rec.chain.anchored_logs(rec.rid, 0) == 1


def test_rpc_outage_backs_off_and_metrics_show_backlog(gw: Gw, rec: Recorder) -> None:
    echo(gw, 1)
    sealer(gw).drain()
    with rpc_proxy(rec.chain.rpc) as px:
        a = rec.anchorer(rpc=px.url, alert_age_seconds=0.0)
        px.mode = "down"
        errors_before = REGISTRY.get_sample_value("agw_anchor_rpc_errors_total") or 0
        # LOW..HIGH actions keep running while the chain is unreachable (08 §8)
        during = gw.post("test_echo", {"text": "during outage"}).json()["action_id"]
        gw.drain()
        assert uuid.UUID(during) in gw.spies.echo.calls
        rep = a.tick()
        assert rep.error is not None
        assert {r.status for r in rec.anchors()} == {"PENDING"}
        assert (REGISTRY.get_sample_value("agw_anchor_rpc_errors_total") or 0) > errors_before
        assert (REGISTRY.get_sample_value("agw_anchor_oldest_unanchored_age_seconds") or 0) > 0
        assert REGISTRY.get_sample_value("agw_anchor_backlog_alert") == 1
        px.mode = "up"
        a.reset_backoff()
        a.tick()
        a.tick()
    assert {r.status for r in rec.anchors()} == {"FINALIZED"}


def test_reorg_resubmits_same_root(gw: Gw, rec: Recorder) -> None:
    echo(gw, 2)
    sealer(gw).drain()
    eps = epochs_of(gw)
    a = rec.anchorer(finality="confirmations:5")
    snap = rec.chain.snapshot()
    a.tick()
    a.tick()
    before = rec.anchors()
    assert {r.status for r in before} == {"INCLUDED"}
    rec.chain.revert(snap)  # the blocks holding our anchors are gone (reorg)
    assert rec.next_epoch() == 0
    reorged = a.tick()
    assert reorged.reorged == len(eps)
    assert {r.status for r in rec.anchors()} == {"SUBMITTED"}
    resent = a.tick()
    assert resent.resubmitted == len(eps)
    a.tick()
    rec.chain.mine(5)
    a.tick()
    after = rec.anchors()
    assert {r.status for r in after} == {"FINALIZED"}
    for b, r, e in zip(before, after, eps, strict=True):
        assert bytes(r.tx_hash) == bytes(b.tx_hash)  # the same signed tx: same root, same nonce
        assert bytes(r.root) == bytes(e.epoch_root) == rec.onchain(int(e.epoch_no))[0]
        assert r.resubmissions == 1 and r.last_error == "REORG"
        assert rec.chain.anchored_logs(rec.rid, int(e.epoch_no)) == 1


def test_idempotent_adopts_existing_same_root(gw: Gw, rec: Recorder) -> None:
    echo(gw, 1)
    sealer(gw).drain()
    eps = epochs_of(gw)
    # A previous worker anchored epoch 0, then its DB update was lost (restore from backup).
    other = EvmAnchorBackend(
        rpc_url=rec.chain.rpc, chain_id=rec.chain.chain_id, contract=rec.chain.contract,
        private_key=rec.key,
    )  # fmt: skip
    e0 = eps[0]
    item = AnchorItem(rec.rid, 0, bytes(e0.epoch_root), int(e0.tree_size), int(e0.last_seq))
    other.broadcast(other.sign_anchor(item, other.pending_nonce()).raw)
    a = rec.anchorer()
    rep = a.tick()
    a.tick()
    rows = rec.anchors()
    assert rep.adopted == 1
    assert rows[0].status == "FINALIZED" and rows[0].tx_hash is None
    assert rows[0].last_error == "ADOPTED:ALREADY_ON_CHAIN"
    assert rec.chain.anchored_logs(rec.rid, 0) == 1
    assert [r.status for r in rows] == ["FINALIZED"] * len(eps)


def test_different_root_on_chain_halts_recorder(gw: Gw, rec: Recorder, tmp_path: Path) -> None:
    ids = echo(gw, 1)
    sealer(gw).drain()
    eps = epochs_of(gw)
    other = EvmAnchorBackend(
        rpc_url=rec.chain.rpc, chain_id=rec.chain.chain_id, contract=rec.chain.contract,
        private_key=rec.key,
    )  # fmt: skip
    e0 = eps[0]
    forged = AnchorItem(rec.rid, 0, b"\x66" * 32, int(e0.tree_size), int(e0.last_seq))
    other.broadcast(other.sign_anchor(forged, other.pending_nonce()).raw)
    before = REGISTRY.get_sample_value("agw_anchor_equivocations_total") or 0
    a = rec.anchorer()
    rep = a.tick()
    assert rep.equivocations == 1
    rows = rec.anchors()
    assert rows[0].status == "FAILED" and rows[0].last_error == "CHAIN_ROOT_MISMATCH"
    assert all(r.status == "PENDING" for r in rows[1:])
    with gw.engine.connect() as conn:
        halted = conn.execute(
            select(t.anchor_recorders.c.halted, t.anchor_recorders.c.halt_reason).where(
                t.anchor_recorders.c.tenant_id == gw.world.tenant_id
            )
        ).one()
    assert halted.halted and halted.halt_reason == "CHAIN_ROOT_MISMATCH@epoch:0"
    a.tick()
    assert rec.next_epoch() == 1  # nothing more anchored for a halted recorder
    assert (REGISTRY.get_sample_value("agw_anchor_equivocations_total") or 0) == before + 1
    bundle = bundle_for(gw, first_event_id(gw, ids[0], "ACTION_REQUESTED"))
    rc, report = verify(tmp_path, "event", bundle, *chain_args(tmp_path, rec))
    assert (rc, report["reason"]) == (1, "ANCHOR_ROOT_MISMATCH")


def test_epoch_row_edited_before_anchoring_halts(gw: Gw, rec: Recorder, pg: PgUrls) -> None:
    echo(gw, 1)
    sealer(gw).drain()
    with superuser(pg) as su:
        su.execute(
            "UPDATE epochs SET merkle_root = %s WHERE tenant_id = %s AND epoch_no = 0",
            (b"\x13" * 32, gw.world.tenant_id),
        )
    rep = rec.anchorer().tick()
    assert rep.equivocations == 1 and rep.submitted == 0
    assert rec.anchors()[0].last_error == "EPOCH_HEADER_MISMATCH"
    assert rec.next_epoch() == 0  # nothing published


def test_priority_shortens_wait_never_reorders(gw: Gw, rec: Recorder) -> None:
    echo(gw, 3)  # LOW only -> ROUTINE epochs
    sealer(gw).drain()
    a = rec.anchorer(routine_delay_seconds=3600.0)
    assert a.tick().submitted == 0  # routine epochs wait to be batched
    assert {r.status for r in rec.anchors()} == {"PENDING"}
    # one HIGH event (external email -> approval required) is sealed at once as PRIORITY
    r = gw.post("send_email", {"to": ["x@partner.example"], "subject": "s"})
    assert r.json()["status"] == "PENDING_APPROVAL"
    sealer(gw).drain()
    a.tick()
    a.tick()
    rows = rec.anchors()
    assert rows[-1].priority == "PRIORITY"
    assert all(x.status == "FINALIZED" for x in rows)  # the whole queue went, in order
    nonces = [int(x.nonce) for x in rows]
    assert nonces == sorted(nonces) and len(set(nonces)) == len(nonces)
    blocks = [int(x.block_number) for x in rows]
    assert blocks == sorted(blocks)


def test_strict_epoch_order_when_predecessor_not_ready(
    gw: Gw, rec: Recorder, migrator_engine: Engine
) -> None:
    echo(gw, 2)
    sealer(gw).drain()
    a = rec.anchorer()
    a._enqueue()
    with migrator_engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE anchors SET next_attempt_at = now() + interval '1 hour' "
                "WHERE tenant_id = :t AND epoch_no = 0"
            ),
            {"t": gw.world.tenant_id},
        )
    assert a.tick().submitted == 0  # epoch 1.. must not overtake epoch 0
    assert rec.next_epoch() == 0
    # epoch 0 given up (FAILED): epoch 1 must still not be sent out of order
    with migrator_engine.begin() as conn:
        conn.execute(
            text("UPDATE anchors SET status = 'FAILED' WHERE tenant_id = :t AND epoch_no = 0"),
            {"t": gw.world.tenant_id},
        )
    assert a.tick().submitted == 0
    assert (
        rec.chain.w3.eth.get_transaction_count(rec.chain.w3.to_checksum_address(rec.address)) == 0
    )  # no doomed transaction was even broadcast


def test_unregistered_recorder_is_not_anchored(
    gw: Gw, chain: Chain, migrator_engine: Engine
) -> None:
    from agw_gateway.anchoring import recorder_id

    key, address = new_key(chain)
    with migrator_engine.begin() as conn:  # DB says so, the chain does not
        conn.execute(
            t.anchor_recorders.insert().values(
                tenant_id=gw.world.tenant_id, recorder_id=recorder_id(gw.world.tenant_id, SALT),
                chain_id=chain.chain_id, contract=chain.contract, submitter=address, halted=False,
            )
        )  # fmt: skip
    echo(gw, 1)
    sealer(gw).drain()
    r = Recorder(chain, gw.world.tenant_id, recorder_id(gw.world.tenant_id, SALT), key, address, gw)
    rep = r.anchorer().tick()
    assert rep.submitted == 0 and any("not registered" in n for n in rep.notes)
    assert chain.w3.eth.get_transaction_count(chain.w3.to_checksum_address(address)) == 0


# ============================================================================ DB guards
def test_runtime_role_cannot_change_an_anchored_root(
    gw: Gw, rec: Recorder, app_engine: Engine
) -> None:
    echo(gw, 1)
    sealer(gw).drain()
    rec.anchorer().tick()
    tenant = gw.world.tenant_id
    for sql in (
        "UPDATE anchors SET root = '\\x" + "77" * 32 + "' WHERE tenant_id = :t",
        "UPDATE anchors SET tree_size = 99 WHERE tenant_id = :t",
        "UPDATE anchors SET epoch_no = epoch_no + 100 WHERE tenant_id = :t",
        "UPDATE anchor_recorders SET recorder_id = '\\x" + "00" * 32 + "' WHERE tenant_id = :t",
        "UPDATE anchor_recorders SET contract = '0x" + "11" * 20 + "' WHERE tenant_id = :t",
        "DELETE FROM anchors WHERE tenant_id = :t",
        "INSERT INTO anchor_recorders (tenant_id, recorder_id, chain_id, contract, submitter) "
        "VALUES (:t || 'x', '\\x"
        + "01" * 32
        + "', 1, '0x"
        + "11" * 20
        + "', '0x"
        + "11" * 20
        + "')",
    ):
        with pytest.raises(DBAPIError, match="permission denied"), app_engine.begin() as conn:
            conn.execute(text(sql), {"t": tenant})
    # INSERT is granted, but only with the sealed epoch's exact root (trigger).
    with gw.engine.connect() as conn:
        e = conn.execute(select(t.epochs).where(t.epochs.c.tenant_id == tenant)).first()
    assert e is not None
    with (
        pytest.raises(DBAPIError, match="anchor must carry the sealed epoch root"),
        app_engine.begin() as conn,
    ):
        conn.execute(
            text(
                "INSERT INTO anchors (tenant_id, epoch_no, recorder_id, root, tree_size, "
                "last_seq, priority, chain_id, contract) VALUES (:t, :e, :r, :root, :s, :l, "
                "'ROUTINE', 1, '0x" + "11" * 20 + "')"
            ),
            {
                "t": tenant, "e": int(e.epoch_no) + 1000, "r": rec.rid, "root": b"\x09" * 32,
                "s": int(e.tree_size), "l": int(e.last_seq),
            },
        )  # fmt: skip


# ============================================================================ CRITICAL gate
@contextlib.contextmanager
def gate_gateway(
    pg: PgUrls, app_engine: Engine, world: World, tmp_path: Path, timeout: float
) -> Iterator[Gw]:
    spies = make_spies()
    for spy in spies.all():
        spy.tenant = world.tenant_id
    settings = make_settings(
        pg.app,
        tmp_path,
        pre_anchor_rules=("*",),
        critical_anchor_timeout_seconds=timeout,
        anchor_finality="confirmations:2",
    )
    state = build_state(settings, engine=app_engine, registry=make_registry(spies))
    state.sync()
    with TestClient(create_app(state, sync_registry=False)) as client:
        g = Gw(state=state, client=client, spies=spies, world=world, engine=app_engine)
        yield g
        g.drain()


def critical_iam_action(g: Gw, migrator: Engine) -> tuple[str, int]:
    """CRITICAL update_iam_role, approved by two distinct approvers -> AUTHORIZED, gated."""
    ensure_agent(migrator, g.world.tenant_id, "iam-admin", (*ALL_SCOPES, "iam:admin"))
    token = create_key(migrator, g.world.tenant_id, "iam-admin")
    body = g.post("update_iam_role", {"principal": "ana", "role": "editor"}, token=token).json()
    assert body["decision"]["risk_level"] == "CRITICAL", body
    humans = make_humans(migrator, g.client, g.world.tenant_id)
    approval_id = body["approval"]["approval_id"]
    assert decide(g, humans, approval_id, who="alice").status_code == 200
    second = decide(g, humans, approval_id, who="bob").json()
    assert second["authorization"]["result"] == "AUTHORIZED", second
    with g.engine.connect() as conn:
        job = conn.execute(
            select(t.outbox_jobs).where(
                t.outbox_jobs.c.action_id == uuid.UUID(body["action_id"]),
                t.outbox_jobs.c.kind == "DISPATCH",
            )
        ).one()
        authorized_seq = conn.execute(
            select(t.evidence_events.c.seq).where(
                t.evidence_events.c.action_id == uuid.UUID(body["action_id"]),
                t.evidence_events.c.event_type == "ACTION_AUTHORIZED",
            )
        ).scalar_one()
    assert job.status == "WAITING_ANCHOR" and job.gate_seq == authorized_seq
    return body["action_id"], int(authorized_seq)


def job_status(g: Gw, action_id: str) -> str:
    with g.engine.connect() as conn:
        return str(
            conn.execute(
                select(t.outbox_jobs.c.status).where(
                    t.outbox_jobs.c.action_id == uuid.UUID(action_id),
                    t.outbox_jobs.c.kind == "DISPATCH",
                )
            ).scalar_one()
        )


def test_critical_pre_anchor_rpc_down_fails_closed(
    pg: PgUrls, app_engine: Engine, world: World, tmp_path: Path, chain: Chain,
    migrator_engine: Engine,
) -> None:  # fmt: skip
    with gate_gateway(pg, app_engine, world, tmp_path, timeout=1.5) as g:
        rec = register(chain, migrator_engine, g)
        action_id, _ = critical_iam_action(g, migrator_engine)
        g.drain()
        assert g.spies.iam.calls == []  # waiting for the anchor: not dispatchable
        sealer(g).drain()
        with rpc_proxy(chain.rpc) as px:
            px.mode = "down"
            a = rec.anchorer(rpc=px.url, finality="confirmations:2")
            assert a.tick().error is not None
            time.sleep(1.6)
            assert g.state.anchor_gate is not None
            assert g.state.anchor_gate.sweep_timeouts() == 1
            assert g.action_status(action_id) == "FAILED"
            assert g.events(action_id)[-1] == "ACTION_FAILED"
            with g.engine.connect() as conn:
                hdr = decode(
                    bytes(
                        conn.execute(
                            select(t.evidence_events.c.canonical_bytes).where(
                                t.evidence_events.c.action_id == uuid.UUID(action_id),
                                t.evidence_events.c.event_type == "ACTION_FAILED",
                            )
                        ).scalar_one()
                    )
                )
            assert hdr["outcome"] == {"status": "FAILED", "code": "ANCHOR_TIMEOUT"}
            g.drain()
            assert g.spies.iam.calls == []  # adapter never called
            # The RPC comes back and the anchor finalizes AFTER the deadline: still no release.
            px.mode = "up"
            a.reset_backoff()
            a.tick()
            chain.mine(2)
            rep = a.tick()
            assert rep.released == 0
        assert {r.status for r in rec.anchors()} == {"FINALIZED"}
        assert job_status(g, action_id) == "FAILED"
        g.drain()
        assert g.spies.iam.calls == []


def test_critical_pre_anchor_released_only_after_finality(
    pg: PgUrls, app_engine: Engine, world: World, tmp_path: Path, chain: Chain,
    migrator_engine: Engine,
) -> None:  # fmt: skip
    with gate_gateway(pg, app_engine, world, tmp_path, timeout=120.0) as g:
        rec = register(chain, migrator_engine, g)
        action_id, s = critical_iam_action(g, migrator_engine)
        sealer(g).drain()
        eps = epochs_of(g)
        gate_epoch = next(e for e in eps if int(e.first_seq) <= s <= int(e.last_seq))
        # ACTION_AUTHORIZED sits alone in its epoch; everything before it was sealed first.
        assert (int(gate_epoch.first_seq), int(gate_epoch.tree_size)) == (s, 1)
        assert (
            gate_epoch.seal_reason == "RISK_CRITICAL" and gate_epoch.anchor_priority == "CRITICAL"
        )
        assert int(eps[int(gate_epoch.epoch_no) - 1].last_seq) == s - 1
        a = rec.anchorer(finality="confirmations:2")
        a.tick()  # submitted
        a.tick()  # included
        gate_anchor = next(r for r in rec.anchors() if r.epoch_no == gate_epoch.epoch_no)
        assert gate_anchor.status == "INCLUDED"  # on-chain, but not final yet
        assert job_status(g, action_id) == "WAITING_ANCHOR"
        g.drain()
        assert g.spies.iam.calls == []
        chain.mine(2)
        rep = a.tick()
        assert rep.released == 1
        g.drain()
        assert g.spies.iam.calls == [uuid.UUID(action_id)]
        with g.engine.connect() as conn:
            hdr = decode(
                bytes(
                    conn.execute(
                        select(t.evidence_events.c.canonical_bytes).where(
                            t.evidence_events.c.action_id == uuid.UUID(action_id),
                            t.evidence_events.c.event_type == "ACTION_DISPATCHED",
                        )
                    ).scalar_one()
                )
            )
        gate_row = next(r for r in rec.anchors() if r.epoch_no == gate_epoch.epoch_no)
        assert hdr["dispatch"]["anchor"] == {
            "epoch": int(gate_epoch.epoch_no),
            "block": int(gate_row.block_number),
            "tx": bytes(gate_row.tx_hash),
            "fin": "confirmations:2",
        }
        bundle = bundle_for(g, first_event_id(g, action_id, "ACTION_AUTHORIZED"))
        rc, report = verify(
            tmp_path, "event", bundle, *chain_args(tmp_path, rec, finality="confirmations:2")
        )
        assert (rc, report["result"]) == (0, "VERIFIED"), report
        assert report["anchor"]["epoch_no"] == int(gate_epoch.epoch_no)


def test_gate_release_and_timeout_exactly_one_wins(
    pg: PgUrls, app_engine: Engine, world: World, tmp_path: Path, chain: Chain,
    migrator_engine: Engine,
) -> None:  # fmt: skip
    with gate_gateway(pg, app_engine, world, tmp_path, timeout=120.0) as g:
        rec = register(chain, migrator_engine, g)
        action_id, _ = critical_iam_action(g, migrator_engine)
        sealer(g).drain()
        a = rec.anchorer(finality="confirmations:1", release=False)  # anchor, never release
        a.tick()
        a.tick()
        assert {r.status for r in rec.anchors()} == {"FINALIZED"}
        with migrator_engine.begin() as conn:  # the deadline passes just before release
            conn.execute(
                text(
                    "UPDATE outbox_jobs SET gate_deadline = now() - interval '1 second' "
                    "WHERE action_id = :a"
                ),
                {"a": action_id},
            )
        gate = g.state.anchor_gate
        assert gate is not None
        assert gate.release_ready() == 0
        assert gate.sweep_timeouts() == 1
        assert gate.release_ready() == 0 and gate.sweep_timeouts() == 0
        g.drain()
        assert g.spies.iam.calls == [] and g.action_status(action_id) == "FAILED"


def test_high_actions_are_not_gated(
    pg: PgUrls, app_engine: Engine, world: World, tmp_path: Path, migrator_engine: Engine
) -> None:
    with gate_gateway(pg, app_engine, world, tmp_path, timeout=1.0) as g:
        humans = make_humans(migrator_engine, g.client, g.world.tenant_id)
        body = g.post("send_email", {"to": ["x@partner.example"], "subject": "q"}).json()
        assert body["decision"]["risk_level"] == "HIGH"
        decide(g, humans, body["approval"]["approval_id"])
        assert job_status(g, body["action_id"]) == "PENDING"
        g.drain()
        assert g.spies.email.calls == [uuid.UUID(body["action_id"])]


def test_finalized_block_tag(gw: Gw, rec: Recorder) -> None:
    """AGW_ANCHOR_FINALITY=finalized uses the node's own `finalized` tag (Anvil: latest - 64)."""
    echo(gw, 1)
    sealer(gw).drain()
    a = rec.anchorer(finality="finalized")
    a.tick()
    a.tick()
    assert {r.status for r in rec.anchors()} == {"INCLUDED"}
    rec.chain.mine(70)
    a.tick()
    assert {r.status for r in rec.anchors()} == {"FINALIZED"}
