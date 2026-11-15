"""Reconciler (08 §7, ADR-0011).

Selects DISPATCH jobs that are CLAIMED with an expired lease:

* no ``ACTION_DISPATCHED`` for the action -> the adapter was provably not called (crash C3):
  release the job to PENDING;
* dispatched, tool non-idempotent -> ``ACTION_OUTCOME_UNKNOWN`` (reason
  ``LEASE_EXPIRED_AFTER_DISPATCH``), job FAILED, **never re-invoked** (C4/C5);
* dispatched, tool idempotent -> release for re-dispatch with a new attempt number, up to
  ``max_attempts``; then OUTCOME_UNKNOWN.

Also purges expired idempotency keys (08 §5; operational table, not evidence).
"""

from __future__ import annotations

import logging

from sqlalchemy import Engine, delete, exists, func, select, update

from agw_gateway.db import tables as t
from agw_gateway.evidence import EvidenceWriter
from agw_gateway.execution.executor import ClaimedJob, record_outcome_unknown
from agw_gateway.logs import log
from agw_gateway.tools.registry import ToolRegistry

logger = logging.getLogger("agw.execution.reconciler")

LEASE_EXPIRED_AFTER_DISPATCH = "LEASE_EXPIRED_AFTER_DISPATCH"
RETRIES_EXHAUSTED = "RETRIES_EXHAUSTED"


class Reconciler:
    def __init__(
        self,
        *,
        engine: Engine,
        registry: ToolRegistry,
        writer: EvidenceWriter,
        max_attempts: int = 3,
        batch: int = 50,
    ) -> None:
        self._engine = engine
        self._registry = registry
        self._writer = writer
        self._max_attempts = max_attempts
        self._batch = batch

    def run_once(self) -> int:
        handled = 0
        with self._engine.begin() as conn:
            jobs = conn.execute(
                select(
                    t.outbox_jobs.c.job_id,
                    t.outbox_jobs.c.action_id,
                    t.outbox_jobs.c.tenant_id,
                    t.outbox_jobs.c.attempts,
                )
                .where(
                    t.outbox_jobs.c.kind == "DISPATCH",
                    t.outbox_jobs.c.status == "CLAIMED",
                    t.outbox_jobs.c.lease_expires_at < func.now(),
                )
                .order_by(t.outbox_jobs.c.job_id)
                .limit(self._batch)
                .with_for_update(skip_locked=True)
            ).all()
            for j in jobs:
                job = ClaimedJob(
                    job_id=j.job_id,
                    action_id=j.action_id,
                    tenant_id=j.tenant_id,
                    attempt=j.attempts,
                )
                dispatched = conn.execute(
                    select(
                        exists().where(
                            t.evidence_events.c.action_id == job.action_id,
                            t.evidence_events.c.event_type == "ACTION_DISPATCHED",
                        )
                    )
                ).scalar_one()
                action = conn.execute(
                    select(
                        t.actions.c.run_id,
                        t.actions.c.agent_id,
                        t.actions.c.tool_id,
                        t.actions.c.tool_version,
                    )
                    .where(t.actions.c.action_id == job.action_id)
                    .with_for_update()
                ).one()
                spec = (
                    self._registry.get_any(action.tool_id, action.tool_version)
                    if action.tool_version
                    else None
                )
                idempotent = spec is not None and spec.meta.is_idempotent
                if not dispatched or (idempotent and job.attempt < self._max_attempts):
                    conn.execute(
                        update(t.outbox_jobs)
                        .where(t.outbox_jobs.c.job_id == job.job_id)
                        .values(status="PENDING", claimed_by=None, lease_expires_at=None)
                    )
                    log(
                        logger,
                        logging.INFO,
                        "job released",
                        job_id=job.job_id,
                        action_id=job.action_id,
                    )
                else:
                    reason = LEASE_EXPIRED_AFTER_DISPATCH if not idempotent else RETRIES_EXHAUSTED
                    record_outcome_unknown(
                        self._writer, conn, job, action, reason, worker="reconciler"
                    )
                    log(
                        logger,
                        logging.WARNING,
                        "outcome unknown",
                        job_id=job.job_id,
                        action_id=job.action_id,
                        error_code=reason,
                    )
                handled += 1
            conn.execute(
                delete(t.idempotency_keys).where(t.idempotency_keys.c.expires_at < func.now())
            )
        return handled
