"""Outbox executor (02 §3, 08 §4, ADR-0004, ADR-0011).

Per job: claim tx (FOR UPDATE SKIP LOCKED + lease) -> dispatch tx (``ACTION_DISPATCHED``)
-> adapter call (timeout < lease) -> result tx (``ACTION_COMPLETED`` | ``ACTION_FAILED``).

* The adapter is called only after ``ACTION_AUTHORIZED`` + the outbox row (tx1) and
  ``ACTION_DISPATCHED`` (dispatch tx) are committed (INV-3).
* The outbox row is the source of truth: the dispatch tx re-locks the job and requires it to be
  still CLAIMED by this worker with a live lease, and the action to be AUTHORIZED (or, for an
  idempotent tool only, DISPATCHED from an earlier attempt). Anything else -> no call (INV-6).
* An adapter timeout is ambiguous (no adapter guarantees "no effect on timeout"), so it records
  ``ACTION_OUTCOME_UNKNOWN``, never a retry.
"""

from __future__ import annotations

import logging
import socket
import uuid
from concurrent.futures import Future, ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeout
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path
from typing import Any
from uuid import UUID

from pydantic import BaseModel
from sqlalchemy import Connection, Engine, func, select, text, update

from agw_gateway.crypto.canonical import args_digest, json_or_profile, profile_value
from agw_gateway.db import tables as t
from agw_gateway.evidence import EvidenceWriter, NewEvent
from agw_gateway.evidence.writer import GATEWAY_ACTOR_ID, now_us
from agw_gateway.execution.crash import CrashPoints
from agw_gateway.ids import uuid7
from agw_gateway.keys import KeyUnavailable
from agw_gateway.logs import log
from agw_gateway.privacy.cipher import EnvelopeCipher, SealedDataError, ops_context
from agw_gateway.privacy.classification import FieldClasses
from agw_gateway.privacy.minimize import Minimizer
from agw_gateway.tools.registry import ToolRegistry
from agw_gateway.tools.spec import ExecutionContext, ToolResult, ToolSpec

logger = logging.getLogger("agw.execution.executor")


@dataclass(frozen=True)
class ClaimedJob:
    job_id: int
    action_id: UUID
    tenant_id: str
    attempt: int
    cg: str = ""  # concurrency group: jobs claimed together by one worker in one batch


def default_worker_id() -> str:
    return f"{socket.gethostname()}:{uuid.uuid4().hex[:8]}"


class Executor:
    def __init__(
        self,
        *,
        engine: Engine,
        registry: ToolRegistry,
        writer: EvidenceWriter,
        crash: CrashPoints,
        sandbox_dir: Path,
        corpus_dir: Path,
        lease: timedelta = timedelta(seconds=30),
        adapter_timeout_seconds: float = 10.0,
        batch: int = 10,
        worker_id: str | None = None,
        cipher: EnvelopeCipher | None = None,
        minimizer: Minimizer | None = None,
    ) -> None:
        self._cipher_obj = cipher
        self._minimizer_obj = minimizer
        self._engine = engine
        self._registry = registry
        self._writer = writer
        self._crash = crash
        self._sandbox_dir = sandbox_dir
        self._corpus_dir = corpus_dir
        self._lease = lease
        self._timeout = adapter_timeout_seconds
        self._batch = batch
        self.worker_id = worker_id or default_worker_id()
        self._pool = ThreadPoolExecutor(max_workers=4, thread_name_prefix="agw-adapter")

    def close(self) -> None:
        self._pool.shutdown(wait=False, cancel_futures=True)

    # ---------------------------------------------------------------- loop body
    def run_once(self) -> int:
        jobs = self._claim()
        if jobs:
            self._crash.hit("after_claim")
        for job in jobs:
            self._process(job)
        return len(jobs)

    def _claim(self) -> list[ClaimedJob]:
        with self._engine.begin() as conn:
            rows = conn.execute(
                text(
                    """
                    WITH picked AS (
                        SELECT job_id FROM outbox_jobs
                         WHERE kind = 'DISPATCH' AND status = 'PENDING' AND available_at <= now()
                         ORDER BY job_id
                         FOR UPDATE SKIP LOCKED
                         LIMIT :batch
                    )
                    UPDATE outbox_jobs o
                       SET status = 'CLAIMED', claimed_by = :worker, attempts = o.attempts + 1,
                           lease_expires_at = now() + :lease
                      FROM picked
                     WHERE o.job_id = picked.job_id
                    RETURNING o.job_id, o.action_id, o.tenant_id, o.attempts
                    """
                ),
                {"batch": self._batch, "worker": self.worker_id, "lease": self._lease},
            ).all()
        cg = f"{self.worker_id}/{uuid7().hex[-12:]}"
        return [
            ClaimedJob(
                job_id=r.job_id,
                action_id=r.action_id,
                tenant_id=r.tenant_id,
                attempt=r.attempts,
                cg=cg,
            )
            for r in sorted(rows, key=lambda r: r.job_id)
        ]

    def _cipher(self) -> EnvelopeCipher:
        if self._cipher_obj is None:
            raise KeyUnavailable("no KEK configured")
        return self._cipher_obj

    def _minimizer(self) -> Minimizer:
        if self._minimizer_obj is None:
            raise KeyUnavailable("no KEK configured")
        return self._minimizer_obj

    # ---------------------------------------------------------------- per job
    def _process(self, job: ClaimedJob) -> None:
        try:
            prepared = self._dispatch_tx(job)
        except KeyUnavailable:
            # KEK down: nothing was dispatched (tx rolled back); the lease expires and the
            # reconciler returns the AUTHORIZED job to PENDING. Fail closed, retry later.
            log(
                logger,
                logging.ERROR,
                "KEK unavailable: dispatch postponed",
                action_id=job.action_id,
                error_code="KEK_UNAVAILABLE",
            )
            return
        if prepared is None:
            return
        spec, args = prepared
        self._crash.hit("after_dispatch_commit")

        ctx = ExecutionContext(
            action_id=job.action_id,
            tenant_id=job.tenant_id,
            attempt=job.attempt,
            engine=self._engine,
            sandbox_dir=self._sandbox_dir,
            corpus_dir=self._corpus_dir,
        )
        future: Future[ToolResult] = self._pool.submit(spec.adapter.execute, args, ctx)
        outcome: tuple[str, Any]
        try:
            outcome = ("COMPLETED", future.result(timeout=self._timeout))
        except FutureTimeout:
            outcome = ("OUTCOME_UNKNOWN", "ADAPTER_TIMEOUT")
        except Exception as exc:  # adapter errors are recorded, never re-raised to the agent
            # Sanitized: the exception type only, never its message (it may echo args).
            outcome = ("FAILED", f"TOOL_ERROR:{type(exc).__name__}")
            log(
                logger,
                logging.WARNING,
                "adapter error",
                action_id=job.action_id,
                tool_id=spec.meta.tool_id,
                error_code=type(exc).__name__,
            )
        observed = now_us()  # when the executor observed the adapter's outcome
        self._crash.hit("after_adapter_return")
        self._result_tx(job, spec, outcome, observed)

    def _lock_job(self, conn: Connection, job: ClaimedJob) -> Any:
        return conn.execute(
            select(
                t.outbox_jobs.c.status,
                t.outbox_jobs.c.claimed_by,
                t.outbox_jobs.c.args_sealed,
                t.outbox_jobs.c.gate_anchor,
                (t.outbox_jobs.c.lease_expires_at > func.now()).label("lease_live"),
            )
            .where(t.outbox_jobs.c.job_id == job.job_id)
            .with_for_update()
        ).one()

    def _dispatch_tx(self, job: ClaimedJob) -> tuple[ToolSpec, BaseModel] | None:
        with self._engine.begin() as conn:
            j = self._lock_job(conn, job)
            if j.status != "CLAIMED" or j.claimed_by != self.worker_id or not j.lease_live:
                return None  # lease lost: someone else owns the decision now
            action = conn.execute(
                select(
                    t.actions.c.status,
                    t.actions.c.tool_id,
                    t.actions.c.tool_version,
                    t.actions.c.run_id,
                    t.actions.c.agent_id,
                )
                .where(t.actions.c.action_id == job.action_id)
                .with_for_update()
            ).one()
            spec = (
                self._registry.get_any(action.tool_id, action.tool_version)
                if action.tool_version
                else None
            )
            redispatch_ok = (
                action.status == "DISPATCHED" and spec is not None and spec.meta.is_idempotent
            )
            if action.status != "AUTHORIZED" and not redispatch_ok:
                self._finish_job(conn, job, "FAILED", "INVALID_STATE_FOR_DISPATCH")
                return None
            args = None
            if spec is not None and j.args_sealed is not None:
                try:
                    raw = self._cipher().open_json(
                        ops_context(job.tenant_id, "dispatch_args", job.action_id.bytes),
                        bytes(j.args_sealed),
                    )
                except SealedDataError:
                    raw = None  # tampered / not ours: definite failure, the adapter never runs
                args = spec.validate_args(raw) if raw is not None else None
            if spec is None or args is None:
                # Never reached the adapter: a definite failure without side effect.
                self._record_result(
                    conn,
                    job,
                    action,
                    "FAILED",
                    "TOOL_UNAVAILABLE" if spec is None else "ARGS_INVALID_AT_DISPATCH",
                    None,
                    now_us(),
                )
                return None

            tool = {"id": spec.meta.tool_id, "ver": spec.meta.version}
            self._writer.append(
                conn,
                job.tenant_id,
                [
                    NewEvent(
                        type="ACTION_DISPATCHED",
                        actor_kind="gateway",
                        actor_id=GATEWAY_ACTOR_ID,
                        action_id=job.action_id,
                        run_id=action.run_id,
                        agent_id=action.agent_id,
                        fields={
                            "tool": tool,
                            "dispatch": {
                                "attempt": job.attempt,
                                "worker": self.worker_id,
                                "cg": job.cg,
                                "anchor": _anchor_ref(j.gate_anchor),
                            },
                            "args": args_digest(args),
                            "obs": now_us(),
                        },
                        # Execution (Paper B field 4): the parameters passed to the adapter,
                        # minimized (secret fields -> salted markers, ADR-0029 §4).
                        payload={
                            "execution": {
                                "params": profile_value(
                                    self._minimizer().args(
                                        conn,
                                        job.tenant_id,
                                        spec.classes,
                                        args.model_dump(mode="python"),
                                    )
                                )
                            }
                        },
                    )
                ],
            )
            self._set_action(conn, job.action_id, status="DISPATCHED")
        log(
            logger,
            logging.INFO,
            "dispatched",
            action_id=job.action_id,
            tool_id=spec.meta.tool_id,
            worker_id=self.worker_id,
        )
        return spec, args

    def _result_tx(
        self, job: ClaimedJob, spec: ToolSpec, outcome: tuple[str, Any], observed: int
    ) -> None:
        status, detail = outcome
        with self._engine.begin() as conn:
            j = self._lock_job(conn, job)
            if j.status != "CLAIMED" or j.claimed_by != self.worker_id:
                # The reconciler already recorded OUTCOME_UNKNOWN; resolution is Phase 4.
                log(
                    logger,
                    logging.WARNING,
                    "late result dropped",
                    action_id=job.action_id,
                    job_id=job.job_id,
                )
                return
            action = conn.execute(
                select(t.actions.c.run_id, t.actions.c.agent_id)
                .where(t.actions.c.action_id == job.action_id)
                .with_for_update()
            ).one()
            if status == "COMPLETED":
                assert isinstance(detail, ToolResult)  # noqa: S101
                self._record_result(
                    conn, job, action, "COMPLETED", None, dict(detail.public), observed, spec=spec
                )
            elif status == "FAILED":
                code, _, exc_type = str(detail).partition(":")
                self._record_result(conn, job, action, "FAILED", code, None, observed, exc_type)
            else:
                record_outcome_unknown(
                    self._writer,
                    conn,
                    job,
                    action,
                    str(detail),
                    worker=self.worker_id,
                    observed=observed,
                )
        log(logger, logging.INFO, "result recorded", action_id=job.action_id, status=status)

    # ---------------------------------------------------------------- writes
    def _record_result(
        self,
        conn: Connection,
        job: ClaimedJob,
        action: Any,
        status: str,
        error_code: str | None,
        result_public: dict[str, Any] | None,
        observed: int,
        error_type: str = "",
        spec: ToolSpec | None = None,
    ) -> None:
        outcome: dict[str, str] = {"status": status}
        if error_code is not None:
            outcome["code"] = error_code
        # Effects (Paper B field 5): the observable outcome, never the agent's interpretation.
        effects: dict[str, Any]
        if status == "COMPLETED":
            # Secret results -> markers in the encrypted payload; only public/internal results
            # stay in plaintext (actions.result_public, returned to the agent) (ADR-0029 §4).
            classes = spec.classes if spec is not None else FieldClasses()
            minimized, result_public = self._minimizer().results(
                conn, job.tenant_id, classes, result_public or {}
            )
            effects = json_or_profile(minimized, "result")
        else:
            effects = {"error": f"{error_code}:{error_type}" if error_type else str(error_code)}
        self._writer.append(
            conn,
            job.tenant_id,
            [
                NewEvent(
                    type="ACTION_COMPLETED" if status == "COMPLETED" else "ACTION_FAILED",
                    actor_kind="gateway",
                    actor_id=GATEWAY_ACTOR_ID,
                    action_id=job.action_id,
                    run_id=action.run_id,
                    agent_id=action.agent_id,
                    fields={"outcome": outcome, "obs": observed},
                    payload={"effects": effects},
                )
            ],
        )
        self._set_action(
            conn, job.action_id, status=status, error_code=error_code, result_public=result_public
        )
        self._finish_job(conn, job, "DONE", error_code)

    def _set_action(self, conn: Connection, action_id: UUID, **values: Any) -> None:
        conn.execute(
            update(t.actions)
            .where(t.actions.c.action_id == action_id)
            .values(**values, updated_at=func.now(), version=t.actions.c.version + 1)
        )

    @staticmethod
    def _finish_job(conn: Connection, job: ClaimedJob, status: str, error_code: str | None) -> None:
        conn.execute(
            update(t.outbox_jobs)
            .where(t.outbox_jobs.c.job_id == job.job_id)
            .values(
                status=status, last_error_code=error_code, lease_expires_at=None, args_sealed=None
            )
        )


def _anchor_ref(gate_anchor: Any) -> dict[str, Any] | None:
    """dispatch.anchor for a pre-anchored CRITICAL action (ADR-0028); None otherwise."""
    if not gate_anchor:
        return None
    tx = gate_anchor.get("tx")
    return {
        "epoch": int(gate_anchor["epoch"]),
        "block": int(gate_anchor["block"]),
        "tx": bytes.fromhex(tx) if tx else None,
        "fin": str(gate_anchor["fin"]),
    }


def record_outcome_unknown(
    writer: EvidenceWriter,
    conn: Connection,
    job: ClaimedJob,
    action: Any,
    reason: str,
    *,
    worker: str,
    observed: int | None = None,
) -> None:
    """``ACTION_OUTCOME_UNKNOWN`` + action status + job FAILED (ADR-0011). Never re-invokes."""
    writer.append(
        conn,
        job.tenant_id,
        [
            NewEvent(
                type="ACTION_OUTCOME_UNKNOWN",
                actor_kind="gateway",
                actor_id=GATEWAY_ACTOR_ID,
                action_id=job.action_id,
                run_id=action.run_id,
                agent_id=action.agent_id,
                fields={
                    "outcome": {"status": "OUTCOME_UNKNOWN", "code": reason},
                    "dispatch": {"attempt": job.attempt, "worker": worker},
                    "obs": observed if observed is not None else now_us(),
                },
                payload={"effects": {"error": reason}},
            )
        ],
    )
    conn.execute(
        update(t.actions)
        .where(t.actions.c.action_id == job.action_id)
        .values(
            status="OUTCOME_UNKNOWN",
            error_code=reason,
            updated_at=func.now(),
            version=t.actions.c.version + 1,
        )
    )
    conn.execute(
        update(t.outbox_jobs)
        .where(t.outbox_jobs.c.job_id == job.job_id)
        .values(status="FAILED", last_error_code=reason, lease_expires_at=None, args_sealed=None)
    )
