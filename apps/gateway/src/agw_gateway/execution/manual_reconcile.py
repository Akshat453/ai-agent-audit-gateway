"""Operator reconciliation of OUTCOME_UNKNOWN actions (Phase 9, ADR-0031 §5; ADR-0011).

An action is OUTCOME_UNKNOWN when the gateway cannot know whether the tool took effect (crash
or timeout after dispatch). The gateway NEVER retries it. An admin who has checked the target
system records what they observed, with a justification:

* ``COMPLETED``    the effect happened                 -> action COMPLETED
* ``FAILED``       the tool ran and failed             -> action FAILED
* ``NOT_EXECUTED`` no effect happened                  -> action FAILED (the agent may submit
                                                          a NEW action; this one is closed)

One transaction: ACTION_RECONCILED (A2H, actor = the human; observation + justification in the
encrypted payload) + the action status. No outbox job is created: nothing is dispatched.
"""

from __future__ import annotations

import logging
from typing import Any, Literal
from uuid import UUID

from sqlalchemy import Engine, func, select, update

from agw_gateway.db import tables as t
from agw_gateway.evidence import EvidenceWriter, NewEvent
from agw_gateway.execution.errors import NotFound, ReconcileInvalid, RoleRequired
from agw_gateway.humans import AuthenticatedHuman
from agw_gateway.logs import log

logger = logging.getLogger("agw.reconcile")
Observed = Literal["COMPLETED", "FAILED", "NOT_EXECUTED"]


class ManualReconciliation:
    def __init__(self, engine: Engine, writer: EvidenceWriter) -> None:
        self._engine = engine
        self._writer = writer

    def reconcile(
        self, human: AuthenticatedHuman, action_id: UUID, observed: Observed, justification: str
    ) -> dict[str, Any]:
        if not human.has("admin"):
            raise RoleRequired
        status = "COMPLETED" if observed == "COMPLETED" else "FAILED"
        code = f"RECONCILED_{observed}"
        with self._engine.begin() as conn:
            action = conn.execute(
                select(t.actions)
                .where(t.actions.c.action_id == action_id, t.actions.c.tenant_id == human.tenant_id)
                .with_for_update()
            ).one_or_none()
            if action is None:
                raise NotFound
            if action.status != "OUTCOME_UNKNOWN":
                raise ReconcileInvalid
            self._writer.append(
                conn,
                human.tenant_id,
                [
                    NewEvent(
                        type="ACTION_RECONCILED",
                        actor_kind="human",
                        actor_id=str(human.human_id),
                        action_id=action_id,
                        run_id=action.run_id,
                        agent_id=action.agent_id,
                        fields={
                            "tool": {
                                "id": action.tool_id,
                                **({"ver": action.tool_version} if action.tool_version else {}),
                            },
                            "outcome": {"status": status, "code": code},
                        },
                        payload={
                            "reconciliation": {
                                "observed": observed,
                                "justification": justification,
                                "by": human.username,
                            }
                        },
                        risk_level="HIGH",  # a human closing an ambiguous outcome: seal promptly
                    )
                ],
            )
            conn.execute(
                update(t.actions)
                .where(t.actions.c.action_id == action_id)
                .values(
                    status=status,
                    error_code=None if status == "COMPLETED" else code,
                    updated_at=func.now(),
                    version=t.actions.c.version + 1,
                )
            )
        log(
            logger,
            logging.WARNING,
            "outcome reconciled by operator",
            tenant_id=human.tenant_id,
            action_id=action_id,
            status=status,
            error_code=code,
        )
        return {"action_id": str(action_id), "status": status, "code": code}
