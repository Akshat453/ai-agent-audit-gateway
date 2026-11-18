"""Anchor worker: sealed epochs -> on-chain anchors (09 §6, ADR-0028).

State per (tenant, epoch) in ``anchors``:

    PENDING --sign + write-ahead--> SUBMITTED(tx_hash, nonce, raw_tx) --receipt--> INCLUDED(block)
       ^                                |   ^                                         |
       |  reverted / nonce replaced     |   |      reorg: block hash changed          |
       +--------------------------------+   +-----------------------------------------+
    INCLUDED --block <= final block (AGW_ANCHOR_FINALITY)--> FINALIZED
    FAILED: chain holds a DIFFERENT root for the epoch (recorder halted) or attempts exhausted.

Rules:
* Order. A recorder's epochs go on-chain strictly in epoch order (the contract demands it);
  epoch N is only submitted once N-1 is on-chain or in flight. Recorders are served by
  (highest pending priority desc, lowest pending epoch asc). Priority shortens the wait (a
  PRIORITY/CRITICAL epoch makes the whole queue up to it go out at this tick; ROUTINE epochs
  wait up to AGW_ANCHOR_ROUTINE_DELAY_SECONDS to batch); it never reorders.
* Same root, always. The signed raw transaction is stored BEFORE it is broadcast
  (write-ahead). A crash, an RPC failure, a dropped tx or a reorg leads to re-broadcasting the
  identical bytes; the DB grants forbid changing an anchor's root (migration 0006).
* Idempotent. Before submitting epoch N the chain is consulted: N already anchored with the
  same root -> adopted (INCLUDED at the chain's block); with a DIFFERENT root -> CRITICAL alert,
  status FAILED, recorder halted (equivocation or key compromise; never "fixed" by us).
* One signer per recorder, one worker per signer (session advisory lock), nonces from
  max(node pending nonce, highest in-flight nonce + 1).
* Outages. Any RPC failure aborts the tick and backs off exponentially; epochs keep sealing
  and queue up; ``agw_anchor_oldest_unanchored_age_seconds`` and an alert above
  AGW_ANCHOR_ALERT_AGE_SECONDS make the growing window visible (08 §8).
"""

from __future__ import annotations

import logging
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any

from sqlalchemy import Engine, func, text, update

from agw_gateway.anchoring import AnchorGate, Finality
from agw_gateway.crypto.merkle import epoch_root
from agw_gateway.db import tables as t
from agw_gateway.execution.crash import CrashPoints
from agw_gateway.logs import log
from agw_gateway.metrics import (
    ANCHOR_BACKLOG_ALERT,
    ANCHOR_EQUIVOCATIONS,
    ANCHOR_OLDEST_UNANCHORED_AGE,
    ANCHOR_RESUBMISSIONS,
    ANCHOR_RPC_ERRORS,
    ANCHOR_TRANSITIONS,
)
from agw_worker.anchoring.backend import (
    AnchorBackend,
    AnchorConfigError,
    AnchorItem,
    AnchorRpcError,
)

logger = logging.getLogger("agw.worker.anchorer")

PRIORITY_RANK = "CASE a.priority WHEN 'CRITICAL' THEN 2 WHEN 'PRIORITY' THEN 1 ELSE 0 END"


@dataclass(frozen=True)
class AnchorerConfig:
    finality: Finality
    routine_delay_seconds: float = 60.0
    max_inflight: int = 8
    rebroadcast_seconds: float = 30.0
    max_attempts: int = 10
    backoff_base_seconds: float = 1.0
    backoff_max_seconds: float = 60.0
    alert_age_seconds: float = 900.0


@dataclass
class TickReport:
    enqueued: int = 0
    submitted: int = 0
    included: int = 0
    finalized: int = 0
    adopted: int = 0
    resubmitted: int = 0
    reorged: int = 0
    equivocations: int = 0
    released: int = 0
    error: str | None = None
    skipped: str | None = None
    notes: list[str] = field(default_factory=list)


class Anchorer:
    def __init__(
        self,
        *,
        engine: Engine,
        backend: AnchorBackend,
        config: AnchorerConfig,
        gate: AnchorGate | None = None,
        crash: CrashPoints | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._engine = engine
        self.backend = backend
        self.config = config
        self._gate = gate
        self._crash = crash or CrashPoints("prod")
        self._clock = clock
        self._failures = 0
        self._backoff_until = 0.0
        self._mine = {
            "c": backend.chain_id,
            "addr": backend.contract,
            "sub": backend.submitter,
        }

    # ================================================================ tick
    def tick(self) -> TickReport:
        rep = TickReport()
        if self._clock() < self._backoff_until:
            rep.skipped = "BACKOFF"
            self._observe()
            return rep
        key = f"agw-anchor:{self.backend.chain_id}:{self.backend.contract}:{self.backend.submitter}"
        with self._engine.connect() as lock_conn:
            got = lock_conn.execute(
                text("SELECT pg_try_advisory_lock(hashtextextended(:k, 0))"), {"k": key}
            ).scalar_one()
            lock_conn.commit()
            if not got:
                rep.skipped = "LOCKED"  # another worker serves this signer
                return rep
            try:
                rep.enqueued = self._enqueue()
                self._track(rep)
                self._submit(rep)
                self._failures = 0
            except AnchorRpcError as exc:
                self._fail_tick(rep, f"RPC:{exc}", logging.WARNING)
            except AnchorConfigError as exc:
                self._fail_tick(rep, f"CONFIG:{exc}", logging.CRITICAL)
            finally:
                lock_conn.execute(
                    text("SELECT pg_advisory_unlock(hashtextextended(:k, 0))"), {"k": key}
                )
                lock_conn.commit()
        if self._gate is not None:
            rep.released = self._gate.release_ready()
        self._observe()
        return rep

    def _fail_tick(self, rep: TickReport, error: str, level: int) -> None:
        self._failures += 1
        delay = min(
            self.config.backoff_max_seconds,
            self.config.backoff_base_seconds * 2 ** (self._failures - 1),
        )
        self._backoff_until = self._clock() + delay
        rep.error = error
        ANCHOR_RPC_ERRORS.inc()
        log(
            logger,
            level,
            "anchor tick aborted; backing off",
            error_code=error.split(":", maxsplit=1)[0],
        )

    def reset_backoff(self) -> None:
        self._backoff_until = 0.0

    # ================================================================ enqueue
    def _enqueue(self) -> int:
        with self._engine.begin() as conn:
            return conn.execute(
                text(
                    """
                    INSERT INTO anchors (tenant_id, epoch_no, recorder_id, root, tree_size,
                                         last_seq, priority, chain_id, contract, sealed_at)
                    SELECT e.tenant_id, e.epoch_no, r.recorder_id, e.epoch_root, e.tree_size,
                           e.last_seq, e.anchor_priority, r.chain_id, r.contract, e.sealed_at
                      FROM epochs e
                      JOIN anchor_recorders r ON r.tenant_id = e.tenant_id
                     WHERE r.chain_id = :c AND r.contract = :addr AND r.submitter = :sub
                       AND NOT EXISTS (SELECT 1 FROM anchors a
                                        WHERE a.tenant_id = e.tenant_id
                                          AND a.epoch_no = e.epoch_no)
                     ORDER BY e.tenant_id, e.epoch_no
                    ON CONFLICT DO NOTHING
                    """
                ),
                self._mine,
            ).rowcount

    # ================================================================ track
    def _track(self, rep: TickReport) -> None:
        with self._engine.connect() as conn:
            rows = conn.execute(
                text(
                    """
                    SELECT a.*, EXTRACT(EPOCH FROM (now() - a.submitted_at)) AS age
                      FROM anchors a
                      JOIN anchor_recorders r ON r.tenant_id = a.tenant_id
                     WHERE a.status IN ('SUBMITTED', 'INCLUDED') AND NOT r.halted
                       AND r.chain_id = :c AND r.contract = :addr AND r.submitter = :sub
                     ORDER BY a.tenant_id, a.epoch_no
                    """
                ),
                self._mine,
            ).all()
        if not rows:
            return
        final_block = self.backend.final_block(self.config.finality)
        confirmed_nonce: int | None = None
        for row in rows:
            if row.status == "INCLUDED":
                canonical = self.backend.block_hash(int(row.block_number))
                if canonical != bytes(row.block_hash):
                    self._reorged(row, rep)
                elif int(row.block_number) <= final_block:
                    self._set(row, "FINALIZED", finalized_at=func.now())
                    rep.finalized += 1
                continue
            # SUBMITTED
            tx_hash = bytes(row.tx_hash)
            receipt = self.backend.receipt(tx_hash)
            if receipt is not None:
                if receipt.succeeded:
                    self._set(
                        row,
                        "INCLUDED",
                        block_number=receipt.block_number,
                        block_hash=receipt.block_hash,
                        gas_used=receipt.gas_used,
                        effective_gas_price=receipt.effective_gas_price,
                        included_at=func.now(),
                    )
                    rep.included += 1
                    if receipt.block_number <= final_block:
                        self._set(row, "FINALIZED", finalized_at=func.now())
                        rep.finalized += 1
                else:
                    self._resolve_from_chain(row, "REVERTED", rep)
                continue
            if self.backend.is_known(tx_hash):
                if float(row.age or 0) >= self.config.rebroadcast_seconds:
                    self.backend.broadcast(bytes(row.raw_tx))  # nudge; same bytes
                continue
            # Unknown to the node: never broadcast (crash), dropped, or reorged out.
            if confirmed_nonce is None:
                confirmed_nonce = self.backend.confirmed_nonce()
            if confirmed_nonce > int(row.nonce):
                self._resolve_from_chain(row, "REPLACED", rep)  # nonce used by another tx
                continue
            reason = row.last_error if row.last_error == "REORG" else "NOT_IN_POOL"
            self.backend.broadcast(bytes(row.raw_tx))
            self._bump_resubmission(row, reason)
            rep.resubmitted += 1

    def _reorged(self, row: Any, rep: TickReport) -> None:
        rep.reorged += 1
        if row.tx_hash is None or row.raw_tx is None:
            # Adopted from chain without our own transaction: look again from scratch.
            self._set(
                row, "PENDING", block_number=None, block_hash=None, included_at=None,
                last_error="REORG",
            )  # fmt: skip
        else:
            self._set(
                row, "SUBMITTED", block_number=None, block_hash=None, included_at=None,
                gas_used=None, effective_gas_price=None, last_error="REORG",
            )  # fmt: skip
        log(
            logger,
            logging.WARNING,
            "anchor block no longer canonical (reorg); resubmitting the same root",
            tenant_id=row.tenant_id,
            error_code="REORG",
        )

    # ================================================================ submit
    def _submit(self, rep: TickReport) -> None:
        with self._engine.connect() as conn:
            queues = conn.execute(
                text(
                    f"""
                    SELECT r.tenant_id, r.recorder_id,
                           max({PRIORITY_RANK}) AS prio,
                           min(a.epoch_no) AS first_pending,
                           EXTRACT(EPOCH FROM (now() - min(a.sealed_at))) AS oldest_age
                      FROM anchor_recorders r
                      JOIN anchors a ON a.tenant_id = r.tenant_id AND a.status = 'PENDING'
                     WHERE NOT r.halted
                       AND r.chain_id = :c AND r.contract = :addr AND r.submitter = :sub
                     GROUP BY r.tenant_id, r.recorder_id
                     ORDER BY prio DESC, first_pending ASC, r.tenant_id
                    """  # noqa: S608  # nosec B608 - PRIORITY_RANK is a constant SQL fragment, no user input
                ),
                self._mine,
            ).all()
        nonce: int | None = None
        for q in queues:
            due = int(q.prio) > 0 or float(q.oldest_age or 0) >= self.config.routine_delay_seconds
            if not due:
                continue
            rid = bytes(q.recorder_id)
            if self.backend.submitter_of(rid) != self.backend.submitter:
                rep.notes.append(f"recorder of {q.tenant_id} is not registered to this submitter")
                log(
                    logger,
                    logging.ERROR,
                    "recorder not registered on-chain to this submitter; not anchoring",
                    tenant_id=q.tenant_id,
                    error_code="RECORDER_NOT_REGISTERED",
                )
                continue
            onchain_next = self.backend.next_epoch(rid)
            with self._engine.connect() as conn:
                rows = conn.execute(
                    text(
                        """
                        SELECT a.*, (a.next_attempt_at <= now()) AS ready
                          FROM anchors a
                         WHERE a.tenant_id = :t AND a.status = 'PENDING'
                         ORDER BY a.epoch_no
                        """
                    ),
                    {"t": q.tenant_id},
                ).all()
                inflight = conn.execute(
                    text(
                        "SELECT count(*) FROM anchors WHERE tenant_id = :t AND status = 'SUBMITTED'"
                    ),
                    {"t": q.tenant_id},
                ).scalar_one()
            for row in rows:
                epoch_no = int(row.epoch_no)
                if epoch_no < onchain_next:
                    if not self._resolve_from_chain(row, "ALREADY_ON_CHAIN", rep):
                        break  # equivocation: recorder halted
                    continue
                if inflight >= self.config.max_inflight or not row.ready:
                    break
                if epoch_no > onchain_next and not self._predecessor_in_flight(row):
                    break  # strict order: N-1 must be on chain or in flight first
                if not self._header_ok(row):
                    self._halt(row, "EPOCH_HEADER_MISMATCH", rep)
                    break
                if nonce is None:
                    nonce = self._next_nonce()
                item = _item(row)
                signed = self.backend.sign_anchor(item, nonce)
                with self._engine.begin() as wconn:
                    n = wconn.execute(
                        text(
                            """
                            UPDATE anchors
                               SET status = 'SUBMITTED', submitter = :sub, nonce = :n,
                                   tx_hash = :h, raw_tx = :raw, submitted_at = now(),
                                   attempts = attempts + 1, updated_at = now()
                             WHERE tenant_id = :t AND epoch_no = :e AND status = 'PENDING'
                            """
                        ),
                        {
                            "sub": self.backend.submitter,
                            "n": nonce,
                            "h": signed.tx_hash,
                            "raw": signed.raw,
                            "t": row.tenant_id,
                            "e": epoch_no,
                        },
                    ).rowcount
                if n != 1:
                    break  # concurrent change; re-read next tick
                ANCHOR_TRANSITIONS.labels("SUBMITTED").inc()
                self._crash.hit("anchor_before_broadcast")
                nonce += 1
                inflight += 1
                rep.submitted += 1
                outcome = self.backend.broadcast(signed.raw)
                if outcome == "NONCE_USED":
                    nonce = None  # stale nonce view; the tracker sorts the row out next tick
                    break

    def _predecessor_in_flight(self, row: Any) -> bool:
        with self._engine.connect() as conn:
            status = conn.execute(
                text("SELECT status FROM anchors WHERE tenant_id = :t AND epoch_no = :e"),
                {"t": row.tenant_id, "e": int(row.epoch_no) - 1},
            ).scalar_one_or_none()
        return status in ("SUBMITTED", "INCLUDED", "FINALIZED")

    def _next_nonce(self) -> int:
        with self._engine.connect() as conn:
            highest = conn.execute(
                text(
                    "SELECT max(nonce) FROM anchors WHERE status = 'SUBMITTED' "
                    "AND submitter = :sub AND chain_id = :c"
                ),
                self._mine,
            ).scalar_one()
        node = self.backend.pending_nonce()
        return max(node, int(highest) + 1) if highest is not None else node

    def _header_ok(self, row: Any) -> bool:
        """Recompute R_t from the stored epoch header before publishing it (09 §2 self-check
        covers events; this covers the epoch row between sealing and anchoring)."""
        with self._engine.connect() as conn:
            e = conn.execute(
                text("SELECT * FROM epochs WHERE tenant_id = :t AND epoch_no = :e"),
                {"t": row.tenant_id, "e": int(row.epoch_no)},
            ).one_or_none()
        if e is None:
            return False
        recomputed = epoch_root(
            e.tenant_id,
            int(e.epoch_no),
            int(e.tree_size),
            int(e.first_seq),
            int(e.last_seq),
            bytes(e.merkle_root),
            bytes(e.prev_root),
        )
        return recomputed == bytes(e.epoch_root) == bytes(row.root)

    # ================================================================ chain reconciliation
    def _resolve_from_chain(self, row: Any, reason: str, rep: TickReport) -> bool:
        """What does the chain hold for this epoch? Returns False if the recorder was halted."""
        item = _item(row)
        onchain = self.backend.get_anchor(item.recorder_id, item.epoch_no)
        if onchain is None:
            attempts = int(row.attempts)
            if attempts >= self.config.max_attempts:
                self._set(row, "FAILED", last_error=f"{reason}:ATTEMPTS_EXHAUSTED")
                log(
                    logger,
                    logging.ERROR,
                    "anchor attempts exhausted",
                    tenant_id=row.tenant_id,
                    error_code=reason,
                )
                return True
            delay = min(self.config.backoff_max_seconds, 2.0**attempts)
            self._set(
                row, "PENDING", submitter=None, nonce=None, tx_hash=None, raw_tx=None,
                block_number=None, block_hash=None, last_error=reason,
                next_attempt_at=func.now() + timedelta(seconds=delay),
            )  # fmt: skip
            return True
        if onchain.matches(item):
            block_hash = self.backend.block_hash(onchain.block_number)
            if block_hash is None:
                return True  # chain view moving under us; retry next tick
            ours = row.status == "SUBMITTED" and reason not in ("REVERTED", "REPLACED")
            self._set(
                row,
                "INCLUDED",
                block_number=onchain.block_number,
                block_hash=block_hash,
                included_at=func.now(),
                last_error=None if ours else f"ADOPTED:{reason}",
                **({} if ours else {"tx_hash": None, "raw_tx": None}),
            )
            rep.adopted += 1
            return True
        self._halt(row, "CHAIN_ROOT_MISMATCH", rep)
        return False

    def _halt(self, row: Any, code: str, rep: TickReport) -> None:
        rep.equivocations += 1
        ANCHOR_EQUIVOCATIONS.inc()
        with self._engine.begin() as conn:
            conn.execute(
                text(
                    "UPDATE anchor_recorders SET halted = true, halt_reason = :r, "
                    "updated_at = now() WHERE tenant_id = :t"
                ),
                {"r": f"{code}@epoch:{int(row.epoch_no)}", "t": row.tenant_id},
            )
        self._set(row, "FAILED", last_error=code)
        log(
            logger,
            logging.CRITICAL,
            "anchoring HALTED for recorder: the chain or the epoch row disagrees with the sealed "
            "root (possible equivocation, key compromise or DB tampering)",
            tenant_id=row.tenant_id,
            error_code=code,
        )

    # ================================================================ writes / metrics
    def _set(self, row: Any, status: str, **values: Any) -> None:
        with self._engine.begin() as conn:
            conn.execute(
                update(t.anchors)
                .where(t.anchors.c.tenant_id == row.tenant_id, t.anchors.c.epoch_no == row.epoch_no)
                .values(status=status, updated_at=func.now(), **values)
            )
        ANCHOR_TRANSITIONS.labels(status).inc()

    def _bump_resubmission(self, row: Any, reason: str) -> None:
        with self._engine.begin() as conn:
            conn.execute(
                text(
                    "UPDATE anchors SET resubmissions = resubmissions + 1, last_error = :r, "
                    "submitted_at = now(), updated_at = now() "
                    "WHERE tenant_id = :t AND epoch_no = :e"
                ),
                {"r": reason, "t": row.tenant_id, "e": int(row.epoch_no)},
            )
        ANCHOR_RESUBMISSIONS.labels(reason).inc()
        log(
            logger,
            logging.WARNING,
            "anchor transaction re-broadcast (same bytes, same root)",
            tenant_id=row.tenant_id,
            error_code=reason,
        )

    def _observe(self) -> None:
        """Oldest sealed-but-not-final epoch across this signer's recorders (DB only, so it
        keeps working while the RPC is down)."""
        with self._engine.connect() as conn:
            age = conn.execute(
                text(
                    """
                    SELECT COALESCE(EXTRACT(EPOCH FROM (now() - min(e.sealed_at))), 0)
                      FROM epochs e
                      JOIN anchor_recorders r ON r.tenant_id = e.tenant_id
                      LEFT JOIN anchors a ON a.tenant_id = e.tenant_id AND a.epoch_no = e.epoch_no
                     WHERE r.chain_id = :c AND r.contract = :addr AND r.submitter = :sub
                       AND (a.status IS NULL OR a.status <> 'FINALIZED')
                    """
                ),
                self._mine,
            ).scalar_one()
        age = float(age or 0)
        ANCHOR_OLDEST_UNANCHORED_AGE.set(age)
        alert = age > self.config.alert_age_seconds
        ANCHOR_BACKLOG_ALERT.set(1 if alert else 0)
        if alert:
            log(
                logger,
                logging.ERROR,
                "anchoring backlog above alert threshold: the compromise window is growing",
                error_code="ANCHOR_BACKLOG",
            )


def _item(row: Any) -> AnchorItem:
    return AnchorItem(
        recorder_id=bytes(row.recorder_id),
        epoch_no=int(row.epoch_no),
        root=bytes(row.root),
        tree_size=int(row.tree_size),
        last_seq=int(row.last_seq),
    )
