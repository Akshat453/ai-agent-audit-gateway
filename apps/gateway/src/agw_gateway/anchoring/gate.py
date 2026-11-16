"""CRITICAL pre-action anchoring gate (ADR-0009, 09 §5, ADR-0028).

* ``GatePolicy.required``: a CRITICAL action is gated when ``AGW_PRE_ANCHOR_RULES`` contains
  "*" or one of the policy/risk rule ids that produced its decision.
* The authorizing tx inserts the DISPATCH job as ``WAITING_ANCHOR`` with ``gate_seq`` (the
  ACTION_AUTHORIZED seq) and ``gate_deadline`` (DB clock). The executor only claims PENDING
  jobs, so nothing can dispatch it yet. The sealer puts ``gate_seq`` into its own epoch.
* ``release_ready``: locks each waiting job whose epoch's anchor is FINALIZED (per
  ``AGW_ANCHOR_FINALITY``), re-checks status and deadline under the lock and sets PENDING with
  ``gate_anchor`` (copied into ACTION_DISPATCHED.dispatch.anchor).
* ``sweep_timeouts``: locks each waiting job past its deadline, re-checks, and writes
  ACTION_FAILED(ANCHOR_TIMEOUT); job FAILED, args dropped. No side effect ever happened.
Both take the job row lock and check status first, so exactly one of them wins; an anchor that
finalizes after the deadline never releases the job. A chain outage therefore fails CRITICAL
actions closed, while LOW..HIGH actions keep running.

The pre-action anchor proves that intent + authorization were publicly committed before the
side effect. It proves nothing about the result: ACTION_COMPLETED is anchored later, routinely.
"""

from __future__ import annotations

import logging
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from sqlalchemy import Connection, Engine, func, select, text, update

from agw_gateway.db import tables as t
from agw_gateway.evidence import EvidenceWriter, NewEvent
from agw_gateway.evidence.writer import GATEWAY_ACTOR_ID, now_us
from agw_gateway.logs import log
from agw_gateway.metrics import ANCHOR_GATE

logger = logging.getLogger("agw.anchoring.gate")

ANCHOR_TIMEOUT = "ANCHOR_TIMEOUT"


@dataclass(frozen=True)
class GatePolicy:
    rules: frozenset[str]
    timeout_seconds: float

    def required(self, risk_level: str, rule_ids: Iterable[str]) -> bool:
        if risk_level != "CRITICAL" or not self.rules:
            return False
        return "*" in self.rules or not self.rules.isdisjoint(rule_ids)

    @staticmethod
    def rule_ids(decision: Any) -> set[str]:
        """Policy rules and risk rules that produced a pipeline Decision."""
        return {*decision.matched_rule_ids, *decision.risk.matched_rules}

    def job_values(self, gate_seq: int) -> dict[str, Any]:
        """Extra outbox_jobs values for a gated DISPATCH job (deadline on the DB clock)."""
        return {
            "status": "WAITING_ANCHOR",
            "gate_seq": gate_seq,
            "gate_deadline": func.now()
            + func.make_interval(0, 0, 0, 0, 0, 0, float(self.timeout_seconds)),
        }


class AnchorGate:
    def __init__(self, *, engine: Engine, writer: EvidenceWriter, finality_label: str) -> None:
        self._engine = engine
        self._writer = writer
        self._finality = finality_label

    def tick(self) -> None:
        self.release_ready()
        self.sweep_timeouts()

    # ---------------------------------------------------------------- release
    def release_ready(self) -> int:
        released = 0
        with self._engine.begin() as conn:
            rows = conn.execute(
                text(
                    """
                    SELECT j.job_id, j.tenant_id, j.action_id, a.epoch_no, a.block_number,
                           a.tx_hash
                      FROM outbox_jobs j
                      JOIN epochs e ON e.tenant_id = j.tenant_id
                                   AND j.gate_seq BETWEEN e.first_seq AND e.last_seq
                      JOIN anchors a ON a.tenant_id = e.tenant_id AND a.epoch_no = e.epoch_no
                     WHERE j.kind = 'DISPATCH' AND j.status = 'WAITING_ANCHOR'
                       AND j.gate_deadline > now() AND a.status = 'FINALIZED'
                     ORDER BY j.job_id
                       FOR UPDATE OF j SKIP LOCKED
                    """
                )
            ).all()
            for r in rows:
                ref = {
                    "epoch": int(r.epoch_no),
                    "block": int(r.block_number),
                    "tx": bytes(r.tx_hash).hex() if r.tx_hash is not None else None,
                    "fin": self._finality,
                }
                released += conn.execute(
                    update(t.outbox_jobs)
                    .where(
                        t.outbox_jobs.c.job_id == r.job_id,
                        t.outbox_jobs.c.status == "WAITING_ANCHOR",
                    )
                    .values(status="PENDING", available_at=text("now()"), gate_anchor=ref)
                ).rowcount
                log(
                    logger,
                    logging.INFO,
                    "pre-action anchor final: dispatch released",
                    tenant_id=r.tenant_id,
                    action_id=r.action_id,
                    status="RELEASED",
                )
        if released:
            ANCHOR_GATE.labels("RELEASED").inc(released)
        return released

    # ---------------------------------------------------------------- timeout
    def sweep_timeouts(self, batch: int = 50) -> int:
        failed = 0
        with self._engine.begin() as conn:
            jobs = conn.execute(
                text(
                    """
                    SELECT job_id, tenant_id, action_id FROM outbox_jobs
                     WHERE kind = 'DISPATCH' AND status = 'WAITING_ANCHOR'
                       AND gate_deadline <= now()
                     ORDER BY job_id
                       FOR UPDATE SKIP LOCKED
                     LIMIT :n
                    """
                ),
                {"n": batch},
            ).all()
            for job in jobs:
                self._fail(conn, job)
                failed += 1
        if failed:
            ANCHOR_GATE.labels(ANCHOR_TIMEOUT).inc(failed)
        return failed

    def _fail(self, conn: Connection, job: Any) -> None:
        action = conn.execute(
            select(t.actions.c.status, t.actions.c.run_id, t.actions.c.agent_id)
            .where(t.actions.c.action_id == job.action_id)
            .with_for_update()
        ).one()
        if action.status == "AUTHORIZED":
            self._writer.append(
                conn,
                job.tenant_id,
                [
                    NewEvent(
                        type="ACTION_FAILED",
                        actor_kind="gateway",
                        actor_id=GATEWAY_ACTOR_ID,
                        action_id=job.action_id,
                        run_id=action.run_id,
                        agent_id=action.agent_id,
                        fields={
                            "outcome": {"status": "FAILED", "code": ANCHOR_TIMEOUT},
                            "obs": now_us(),
                        },
                        payload={"effects": {"error": ANCHOR_TIMEOUT}},
                    )
                ],
            )
            conn.execute(
                update(t.actions)
                .where(t.actions.c.action_id == job.action_id)
                .values(
                    status="FAILED",
                    error_code=ANCHOR_TIMEOUT,
                    updated_at=text("now()"),
                    version=t.actions.c.version + 1,
                )
            )
        conn.execute(
            update(t.outbox_jobs)
            .where(t.outbox_jobs.c.job_id == job.job_id)
            .values(status="FAILED", last_error_code=ANCHOR_TIMEOUT, args_sealed=None)
        )
        log(
            logger,
            logging.ERROR,
            "pre-action anchor not final before deadline: action failed closed",
            tenant_id=job.tenant_id,
            action_id=job.action_id,
            error_code=ANCHOR_TIMEOUT,
        )
