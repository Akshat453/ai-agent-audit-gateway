"""Outbox-driven epoch sealer.

Two steps, both durable in Postgres:

``schedule()``  reads each tenant's pending (unsealed) window from durable rows, grouped by
                the risk level recorded on each event (``evidence_events.risk_level``), asks
                the pure ``policy.decide`` whether a seal is due (count / risk / age, see
                ``sealing/policy.py``) and enqueues at most one open
                ``outbox_jobs(kind='SEAL', up_to_seq, seal_reason)`` per tenant. A HIGH or
                CRITICAL event is therefore sealed within one sealer tick, and the trigger is
                as durable as the event itself (no in-memory signal). Pending EPOCH_SEALED
                receipts alone never trigger a seal ("no events -> no seal").

``run_once()``  claims one SEAL job (``FOR UPDATE SKIP LOCKED``) and, in ONE transaction:
                takes a per-tenant advisory lock (one sealer per tenant), locks
                ``epoch_heads``, SELF-CHECKS the range (recomputes every event_hash from the
                stored canonical bytes, checks seq and prev links back to the last sealed
                event), builds the RFC 9162 tree, computes R_t, inserts the epoch (the DB
                trigger re-checks tiling; ``anchor_priority`` from the highest risk level in
                the range), advances ``epoch_heads``, appends an
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
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from typing import Any

from sqlalchemy import Connection, Engine, select, text

from agw_gateway.crypto.canonical import ZERO32, CanonicalError, decode, event_hash
from agw_gateway.crypto.merkle import epoch_root, merkle_root
from agw_gateway.db import tables as t
from agw_gateway.evidence import EvidenceWriter, NewEvent
from agw_gateway.execution.crash import CrashPoints
from agw_gateway.logs import log
from agw_gateway.metrics import EPOCHS_SEALED, LEVELS, OLDEST_UNSEALED_AGE, PENDING_EVENTS
from agw_worker.sealing.policy import (
    PendingLevel,
    PendingWindow,
    SealPolicy,
    anchor_priority,
    decide,
)

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
    anchor_priority: str = "ROUTINE"


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
        policy: SealPolicy | None = None,
    ) -> None:
        self._engine = engine
        self._writer = writer
        self._crash = crash
        # Default: adaptive, with max_events / max_age_seconds as the LOW thresholds.
        self.policy = policy or SealPolicy.adaptive(
            low_max_events=max_events,
            low_max_age_seconds=max_age_seconds,
            medium_max_events=min(25, max_events),
            medium_max_age_seconds=min(60.0, max_age_seconds),
        )
        self.last_computed: SealResult | None = None  # for crash/determinism tests

    # ---------------------------------------------------------------- scheduling
    def schedule(self) -> int:
        enqueued = 0
        with self._engine.begin() as conn:
            rows = conn.execute(
                text(
                    """
                    SELECT ch.tenant_id, ch.last_seq, eh.sealed_up_to,
                           COALESCE(e.risk_level, 'LOW') AS level,
                           count(*) AS n,
                           EXTRACT(EPOCH FROM (now() - min(e.occurred_at))) AS oldest_age,
                           max(e.seq) AS max_seq
                      FROM chain_heads ch
                      JOIN epoch_heads eh ON eh.tenant_id = ch.tenant_id
                      JOIN evidence_events e
                        ON e.tenant_id = ch.tenant_id AND e.seq > eh.sealed_up_to
                       AND e.event_type <> 'EPOCH_SEALED'
                     WHERE ch.last_seq > eh.sealed_up_to
                       AND NOT EXISTS (
                           SELECT 1 FROM outbox_jobs j
                            WHERE j.kind = 'SEAL' AND j.tenant_id = ch.tenant_id
                              AND j.status = 'FAILED' AND j.last_error_code = :failed)
                     GROUP BY ch.tenant_id, ch.last_seq, eh.sealed_up_to,
                              COALESCE(e.risk_level, 'LOW')
                    """
                ),
                {"failed": SELF_CHECK_FAILED},
            ).all()
            windows: dict[str, PendingWindow] = {}
            for r in rows:
                level = PendingLevel(r.level, int(r.n), float(r.oldest_age), int(r.max_seq))
                w = windows.get(r.tenant_id)
                windows[r.tenant_id] = PendingWindow(
                    sealed_up_to=int(r.sealed_up_to),
                    last_seq=int(r.last_seq),
                    levels=(*(w.levels if w else ()), level),
                )
            self._observe(windows.values())
            gates = self._gate_seals(conn)
            for tenant_id, window in windows.items():
                due = gates.get(tenant_id) or decide(window, self.policy)
                if due is None:
                    continue
                up_to, reason = due
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
                    {"t": tenant_id, "u": up_to, "r": reason},
                ).rowcount
        return enqueued

    @staticmethod
    def _gate_seals(conn: Connection) -> dict[str, tuple[int, str]]:
        """CRITICAL pre-action anchoring (09 §2/§5, ADR-0028): for the lowest unsealed
        ``gate_seq`` s of a WAITING_ANCHOR job, seal [first_pending, s-1] first (if non-empty),
        then [s, s] as its own one-leaf epoch. Takes precedence over the count/age/risk rules
        (which would otherwise fold s into a larger epoch)."""
        rows = conn.execute(
            text(
                """
                SELECT j.tenant_id, min(j.gate_seq) AS s, max(eh.sealed_up_to) AS sealed
                  FROM outbox_jobs j
                  JOIN epoch_heads eh ON eh.tenant_id = j.tenant_id
                 WHERE j.kind = 'DISPATCH' AND j.status = 'WAITING_ANCHOR'
                   AND j.gate_seq > eh.sealed_up_to
                 GROUP BY j.tenant_id
                """
            )
        ).all()
        out: dict[str, tuple[int, str]] = {}
        for r in rows:
            s, sealed = int(r.s), int(r.sealed)
            out[r.tenant_id] = (s - 1 if s - 1 > sealed else s, "RISK_CRITICAL")
        return out

    @staticmethod
    def _observe(windows: Iterable[PendingWindow]) -> None:
        """Operational gauges only (counts and ages; no tenant labels, no payloads)."""
        pending = dict.fromkeys(LEVELS, 0)
        oldest = 0.0
        for w in windows:
            for lv in w.levels:
                pending[lv.level] = pending.get(lv.level, 0) + lv.count
                oldest = max(oldest, lv.oldest_age_seconds)
        for level, n in pending.items():
            PENDING_EVENTS.labels(level).set(n)
        OLDEST_UNSEALED_AGE.set(oldest)

    def request_seal(self, tenant_id: str, up_to_seq: int, reason: str = "MANUAL") -> bool:
        """Durably enqueue a seal (operators/tests). Risk triggers come from ``schedule()``."""
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
        return self._process_one()[1]

    def _process_one(self) -> tuple[bool, SealResult | None]:
        """(a job was taken off the queue, the epoch it produced). A job can be processed
        without producing an epoch: its range is already sealed, or its self-check failed."""
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
                return False, None
            got = conn.execute(
                text("SELECT pg_try_advisory_xact_lock(hashtextextended('agw-seal:' || :t, 0))"),
                {"t": job.tenant_id},
            ).scalar_one()
            if not got:
                return False, None  # another sealer holds this tenant; the job stays PENDING
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
                return True, None
            self._finish(conn, job.job_id, "DONE", None)
        if result is not None:
            EPOCHS_SEALED.labels(result.seal_reason).inc()
            log(logger, logging.INFO, "epoch sealed", tenant_id=result.tenant_id, status="SEALED")
        return True, result

    def drain(self, max_epochs: int = 1000) -> list[SealResult]:
        """Seal until nothing is due. Jobs are served FIFO by job id across tenants, and a
        tenant's next job is only enqueued after its previous one finished, so a tenant with a
        burst of urgent seals cannot starve the others. One tenant's stale or failed job never
        ends the tick for the rest. Bounded so a scheduling bug can never spin forever."""
        out: list[SealResult] = []
        for _ in range(max_epochs):
            self.schedule()
            processed, result = self._process_one()
            if not processed:
                return out
            if result is not None:
                out.append(result)
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
                t.evidence_events.c.risk_level,
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
            anchor_priority=anchor_priority([r.risk_level for r in rows]),
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
                anchor_priority=result.anchor_priority,
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
