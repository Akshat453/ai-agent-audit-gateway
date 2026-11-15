"""Outbox-driven epoch sealer.

Two steps, both durable in Postgres:

``schedule()``  scans tenants with pending (unsealed) events and enqueues at most one open
                ``outbox_jobs(kind='SEAL', up_to_seq, seal_reason)`` per tenant when a trigger
                fires: pending >= max_events (seal exactly max_events) OR the oldest pending
                non-receipt event is older than max_age (seal everything pending). Pending
                EPOCH_SEALED receipts alone never trigger a seal ("no events -> no seal").

``run_once()``  claims one SEAL job (``FOR UPDATE SKIP LOCKED``) and, in ONE transaction:
                takes a per-tenant advisory lock (one sealer per tenant), locks
                ``epoch_heads``, SELF-CHECKS the range (recomputes every event_hash from the
                stored canonical bytes, checks seq and prev links back to the last sealed
                event), builds the RFC 9162 tree, computes R_t, inserts the epoch (the DB
                trigger re-checks tiling), advances ``epoch_heads``, appends an
                ``EPOCH_SEALED`` receipt to the tenant's chain (it lands in a LATER epoch) and
                marks the job DONE.

Determinism: the epoch is a pure function of (tenant, epoch head, up_to_seq, stored events).
A crash anywhere before COMMIT rolls everything back; the job stays PENDING and the rerun
produces the identical epoch. ``sealed_at`` is informational and not part of R_t.

A failed self-check never seals over a break: the job is marked FAILED with
``SEAL_SELF_CHECK_FAILED``, a CRITICAL log is emitted, and the scheduler stops sealing that
tenant until an operator resolves it.
"""

from __future__ import annotations

import logging
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from sqlalchemy import Connection, Engine, select, text

from agw_gateway.crypto.canonical import ZERO32, CanonicalError, decode, event_hash
from agw_gateway.crypto.merkle import epoch_root, merkle_root
from agw_gateway.db import tables as t
from agw_gateway.evidence import EvidenceWriter, NewEvent
from agw_gateway.execution.crash import CrashPoints
from agw_gateway.logs import log

logger = logging.getLogger("agw.worker.sealer")

SEALER_ACTOR = "agw-sealer"
SELF_CHECK_FAILED = "SEAL_SELF_CHECK_FAILED"


@dataclass(frozen=True)
class SealResult:
    tenant_id: str
    epoch_no: int
    first_seq: int
    last_seq: int
    tree_size: int
    merkle_root: bytes
    prev_root: bytes
    epoch_root: bytes
    seal_reason: str


class SelfCheckFailed(Exception):
    def __init__(self, seq: int, reason: str) -> None:
        super().__init__(f"seq {seq}: {reason}")
        self.seq = seq
        self.reason = reason


class Sealer:
    def __init__(
        self,
        *,
        engine: Engine,
        writer: EvidenceWriter,
        crash: CrashPoints,
        max_events: int = 100,
        max_age_seconds: float = 300.0,
    ) -> None:
        self._engine = engine
        self._writer = writer
        self._crash = crash
        self.max_events = max_events
        self.max_age_seconds = max_age_seconds
        self.last_computed: SealResult | None = None  # for crash/determinism tests

    # ---------------------------------------------------------------- scheduling
    def schedule(self) -> int:
        enqueued = 0
        with self._engine.begin() as conn:
            rows = conn.execute(
                text(
                    """
                    SELECT ch.tenant_id, ch.last_seq, eh.sealed_up_to,
                           EXTRACT(EPOCH FROM (now() - (
                               SELECT min(e.occurred_at) FROM evidence_events e
                                WHERE e.tenant_id = ch.tenant_id AND e.seq > eh.sealed_up_to
                                  AND e.event_type <> 'EPOCH_SEALED'))) AS oldest_age
                      FROM chain_heads ch
                      JOIN epoch_heads eh ON eh.tenant_id = ch.tenant_id
                     WHERE ch.last_seq > eh.sealed_up_to
                       AND NOT EXISTS (
                           SELECT 1 FROM outbox_jobs j
                            WHERE j.kind = 'SEAL' AND j.tenant_id = ch.tenant_id
                              AND j.status = 'FAILED' AND j.last_error_code = :failed)
                    """
                ),
                {"failed": SELF_CHECK_FAILED},
            ).all()
            for r in rows:
                if r.oldest_age is None:  # only EPOCH_SEALED receipts pending
                    continue
                pending = r.last_seq - r.sealed_up_to
                if pending >= self.max_events:
                    up_to, reason = r.sealed_up_to + self.max_events, "MAX_EVENTS"
                elif float(r.oldest_age) >= self.max_age_seconds:
                    up_to, reason = r.last_seq, "MAX_AGE"
                else:
                    continue
                enqueued += conn.execute(
                    text(
                        """
                        INSERT INTO outbox_jobs
                               (kind, tenant_id, status, attempts, up_to_seq, seal_reason)
                        VALUES ('SEAL', :t, 'PENDING', 0, :u, :r)
                        ON CONFLICT (tenant_id)
                         WHERE kind = 'SEAL' AND status IN ('PENDING', 'CLAIMED')
                        DO NOTHING
                        """
                    ),
                    {"t": r.tenant_id, "u": up_to, "r": reason},
                ).rowcount
        return enqueued

    def request_seal(self, tenant_id: str, up_to_seq: int, reason: str = "MANUAL") -> bool:
        """Durably enqueue a seal (used by operators/tests; Phase 4 adds risk triggers)."""
        with self._engine.begin() as conn:
            n = conn.execute(
                text(
                    """
                    INSERT INTO outbox_jobs
                           (kind, tenant_id, status, attempts, up_to_seq, seal_reason)
                    VALUES ('SEAL', :t, 'PENDING', 0, :u, :r)
                    ON CONFLICT (tenant_id)
                     WHERE kind = 'SEAL' AND status IN ('PENDING', 'CLAIMED')
                    DO NOTHING
                    """
                ),
                {"t": tenant_id, "u": up_to_seq, "r": reason},
            ).rowcount
        return bool(n)

    # ---------------------------------------------------------------- sealing
    def run_once(self) -> SealResult | None:
        """Process at most one SEAL job. Returns the sealed epoch (None if nothing sealed)."""
        with self._engine.begin() as conn:
            job = conn.execute(
                text(
                    """
                    SELECT job_id, tenant_id, up_to_seq, seal_reason FROM outbox_jobs
                     WHERE kind = 'SEAL' AND status = 'PENDING' AND available_at <= now()
                     ORDER BY job_id
                     FOR UPDATE SKIP LOCKED
                     LIMIT 1
                    """
                )
            ).one_or_none()
            if job is None:
                return None
            got = conn.execute(
                text("SELECT pg_try_advisory_xact_lock(hashtextextended('agw-seal:' || :t, 0))"),
                {"t": job.tenant_id},
            ).scalar_one()
            if not got:
                return None  # another sealer holds this tenant; the job stays PENDING
            try:
                result = self._seal(conn, job)
            except SelfCheckFailed as exc:
                self._finish(conn, job.job_id, "FAILED", SELF_CHECK_FAILED)
                log(
                    logger,
                    logging.CRITICAL,
                    "seal self-check failed: evidence chain broken, sealing stopped",
                    tenant_id=job.tenant_id,
                    job_id=job.job_id,
                    error_code=exc.reason,
                )
                return None
            self._finish(conn, job.job_id, "DONE", None)
        if result is not None:
            log(logger, logging.INFO, "epoch sealed", tenant_id=result.tenant_id, status="SEALED")
        return result

    def drain(self, max_epochs: int = 1000) -> list[SealResult]:
        """Seal until nothing is due. Bounded so a scheduling bug can never spin forever."""
        out: list[SealResult] = []
        for _ in range(max_epochs):
            self.schedule()
            r = self.run_once()
            if r is None:
                return out
            out.append(r)
        log(logger, logging.ERROR, "sealer drain bound reached", error_code="DRAIN_BOUND")
        return out

    def tick(self) -> None:
        """Periodic hook for the background runner."""
        self.drain()

    def _seal(self, conn: Connection, job: Any) -> SealResult | None:
        tenant = job.tenant_id
        head = conn.execute(
            select(t.epoch_heads).where(t.epoch_heads.c.tenant_id == tenant).with_for_update()
        ).one()
        if job.up_to_seq <= head.sealed_up_to:
            return None  # already sealed (idempotent rerun)
        first, last = head.sealed_up_to + 1, int(job.up_to_seq)
        rows = conn.execute(
            select(
                t.evidence_events.c.seq,
                t.evidence_events.c.canonical_bytes,
                t.evidence_events.c.event_hash,
            )
            .where(
                t.evidence_events.c.tenant_id == tenant,
                t.evidence_events.c.seq.between(first, last),
            )
            .order_by(t.evidence_events.c.seq)
        ).all()
        leaves = self._self_check(conn, tenant, first, last, rows)
        size = last - first + 1
        m = merkle_root(leaves)
        prev = bytes(head.last_root)
        root = epoch_root(tenant, int(head.next_epoch_no), size, first, last, m, prev)
        result = SealResult(
            tenant_id=tenant,
            epoch_no=int(head.next_epoch_no),
            first_seq=first,
            last_seq=last,
            tree_size=size,
            merkle_root=m,
            prev_root=prev,
            epoch_root=root,
            seal_reason=job.seal_reason,
        )
        self.last_computed = result
        self._crash.hit("seal_before_commit")
        conn.execute(
            t.epochs.insert().values(
                tenant_id=tenant,
                epoch_no=result.epoch_no,
                first_seq=first,
                last_seq=last,
                tree_size=size,
                merkle_root=m,
                prev_root=prev,
                epoch_root=root,
                state="SEALED",
                seal_reason=result.seal_reason,
            )
        )
        conn.execute(
            t.epoch_heads.update()
            .where(t.epoch_heads.c.tenant_id == tenant)
            .values(next_epoch_no=result.epoch_no + 1, sealed_up_to=last, last_root=root)
        )
        self._writer.append(
            conn,
            tenant,
            [
                NewEvent(
                    type="EPOCH_SEALED",
                    actor_kind="system",
                    actor_id=SEALER_ACTOR,
                    fields={
                        "epoch": {
                            "no": result.epoch_no,
                            "first": first,
                            "last": last,
                            "size": size,
                            "mroot": m,
                            "prev": prev,
                            "root": root,
                            "reason": result.seal_reason,
                        }
                    },
                )
            ],
        )
        return result

    @staticmethod
    def _self_check(
        conn: Connection, tenant: str, first: int, last: int, rows: Sequence[Any]
    ) -> list[bytes]:
        if len(rows) != last - first + 1:
            raise SelfCheckFailed(first, "MISSING_EVENTS")
        if first == 0:
            prev = ZERO32
        else:
            prev_hash = conn.execute(
                select(t.evidence_events.c.event_hash).where(
                    t.evidence_events.c.tenant_id == tenant,
                    t.evidence_events.c.seq == first - 1,
                )
            ).scalar_one_or_none()
            if prev_hash is None:
                raise SelfCheckFailed(first - 1, "MISSING_PREDECESSOR")
            prev = bytes(prev_hash)
        leaves: list[bytes] = []
        for expected_seq, row in enumerate(rows, start=first):
            cb = bytes(row.canonical_bytes)
            h = event_hash(cb)
            if row.seq != expected_seq:
                raise SelfCheckFailed(expected_seq, "SEQ_GAP")
            if h != bytes(row.event_hash):
                raise SelfCheckFailed(row.seq, "EVENT_HASH_MISMATCH")
            try:
                rec = decode(cb)
            except CanonicalError:
                raise SelfCheckFailed(row.seq, "NONCANONICAL_HEADER") from None
            if rec.get("seq") != row.seq or rec.get("tenant") != tenant:
                raise SelfCheckFailed(row.seq, "HEADER_POSITION_MISMATCH")
            if rec.get("prev") != prev:
                raise SelfCheckFailed(row.seq, "PREV_LINK_BROKEN")
            leaves.append(h)
            prev = h
        return leaves

    @staticmethod
    def _finish(conn: Connection, job_id: int, status: str, error: str | None) -> None:
        conn.execute(
            t.outbox_jobs.update()
            .where(t.outbox_jobs.c.job_id == job_id)
            .values(status=status, last_error_code=error)
        )
