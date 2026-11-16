"""Approval workflow (Phase 5, ADR-0027; 04 §5; INV-11).

Lifecycle of one REQUIRE_APPROVAL action::

    tx1 (ActionService)   approvals(PENDING) + APPROVAL_REQUIRED{approval: id, binding, exp, req}
    decision tx           approval_decisions (signed) + APPROVAL_GRANTED | APPROVAL_DENIED
                          -> state APPROVED once ``required_approvals`` distinct approvers agreed
    authorize tx          (ONE tx, row locks) revalidate -> CONSUMED + approval_uses(nonce)
                          + POLICY_EVALUATED (re-evaluation) + ACTION_AUTHORIZED + outbox DISPATCH
                          or INVALIDATED + POLICY_EVALUATED? + ACTION_DENIED
    sweeper               PENDING/APPROVED past expires_at -> EXPIRED + APPROVAL_EXPIRED

Lock order everywhere: approvals row -> actions row -> chain head (EvidenceWriter). The
executor takes outbox job -> actions -> chain head and never touches approvals, so no cycle.

Authorization revalidation (all must hold, else the approval is INVALIDATED and the action
DENIED; nothing reaches the outbox):

1. approval APPROVED (CONSUMED / REJECTED / ... -> no-op: replay is rejected) and unexpired by
   DB time; approval and action in the same tenant (confused deputy);
2. action still PENDING_APPROVAL;
3. enough DISTINCT approvers with a valid gateway signature over the recomputed decision
   record (an approval row forged by a DB writer without the key does not count);
4. the action digest recomputed from the STORED request (args re-validated, target, tool
   version, environment, stored policy version + its stored document digest, risk level,
   delegation) equals the approved digest;
5. the agent is still active, and re-evaluation under the CURRENT policy, risk policy, agent
   scopes and registry is not DENY and not riskier than what was approved (stricter wins);
6. the nonce has never been used (``approval_uses`` PK: a constraint, not just a check).
"""

from __future__ import annotations

import hmac
import logging
import os
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Final, Literal
from uuid import UUID

from sqlalchemy import Connection, Engine, any_, func, insert, literal, select, update
from sqlalchemy.exc import IntegrityError

from agw_gateway.anchoring.gate import GatePolicy
from agw_gateway.approvals.binding import (
    ActionBinding,
    DecisionRecord,
    policy_digest,
    render_args,
    target_resource,
)
from agw_gateway.approvals.signing import DecisionSigner, verify_decision
from agw_gateway.auth.models import AuthenticatedAgent
from agw_gateway.crypto.canonical import args_digest
from agw_gateway.db import tables as t
from agw_gateway.evidence import EvidenceWriter, NewEvent
from agw_gateway.evidence.records import policy_evaluated_fields
from agw_gateway.evidence.writer import GATEWAY_ACTOR_ID
from agw_gateway.execution.errors import (
    ApprovalAlreadyDecided,
    ApprovalExpired,
    ApprovalNotPending,
    ApprovalStale,
    DependencyUnavailable,
    Forbidden,
    NotFound,
)
from agw_gateway.humans.models import AuthenticatedHuman
from agw_gateway.ids import uuid7
from agw_gateway.keys import KeyUnavailable
from agw_gateway.logs import log
from agw_gateway.metrics import APPROVAL_AUTHORIZATIONS, APPROVAL_DECISIONS, APPROVALS_EXPIRED
from agw_gateway.policies.pipeline import decide_action
from agw_gateway.policy_store import load_active_policy, load_policy_version
from agw_gateway.privacy.cipher import EnvelopeCipher, SealedDataError, ops_context
from agw_gateway.privacy.minimize import Minimizer
from agw_gateway.risk_store import RiskPolicyStore
from agw_gateway.tools.registry import ToolRegistry

logger = logging.getLogger("agw.approvals")

LEVEL_ORDER: Final = ("LOW", "MEDIUM", "HIGH", "CRITICAL")
APPROVAL_STATES: Final = frozenset(
    {"PENDING", "APPROVED", "REJECTED", "EXPIRED", "CONSUMED", "INVALIDATED"}
)
DecisionInput = Literal["APPROVE", "REJECT"]


def us(ts: datetime) -> int:
    """Microseconds since the Unix epoch (DB timestamps are timezone-aware)."""
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=UTC)
    return int(ts.timestamp() * 1_000_000)


def approval_event_level(action_level: str) -> str:
    """Approval events seal immediately: at least HIGH (Phase 4 risk-adaptive sealing)."""
    return max(action_level, "HIGH", key=LEVEL_ORDER.index)


@dataclass(frozen=True)
class ApprovalConfig:
    ttl_seconds: Mapping[str, int]  # by action risk level; default 900 s
    four_eyes_critical: bool = True

    def ttl(self, level: str) -> timedelta:
        return timedelta(seconds=self.ttl_seconds.get(level, 900))

    def required(self, level: str) -> int:
        return 2 if (level == "CRITICAL" and self.four_eyes_critical) else 1


@dataclass(frozen=True)
class NewApproval:
    """Created by tx1 for a REQUIRE_APPROVAL action (values fixed before tx1 opens)."""

    approval_id: UUID
    nonce: bytes
    action_digest: bytes
    required: int
    ttl: timedelta

    @classmethod
    def create(cls, action_digest: bytes, level: str, config: ApprovalConfig) -> NewApproval:
        return cls(
            uuid7(), os.urandom(16), action_digest, config.required(level), config.ttl(level)
        )

    def insert(self, conn: Connection, tenant_id: str, action_id: UUID) -> dict[str, Any]:
        """Insert the row (DB clock) and return the APPROVAL_REQUIRED ``approval`` header map."""
        now = conn.execute(select(func.now())).scalar_one()
        expires_at = now + self.ttl
        conn.execute(
            insert(t.approvals).values(
                approval_id=self.approval_id,
                tenant_id=tenant_id,
                action_id=action_id,
                action_digest=self.action_digest,
                nonce=self.nonce,
                required_role="approver",
                required_approvals=self.required,
                state="PENDING",
                requested_at=now,
                expires_at=expires_at,
            )
        )
        return {
            "id": self.approval_id.bytes,
            "binding": self.action_digest,
            "exp": us(expires_at),
            "req": self.required,
        }


@dataclass(frozen=True)
class AuthorizeResult:
    result: str  # AUTHORIZED | DENIED | NOOP | EXPIRED
    code: str | None = None


class ApprovalService:
    def __init__(
        self,
        *,
        engine: Engine,
        registry: ToolRegistry,
        writer: EvidenceWriter,
        risk_policies: RiskPolicyStore,
        signer: DecisionSigner | None,
        build_commit: str = "unknown",
        on_authorized: Callable[[], None] | None = None,
        batch: int = 50,
        gate: GatePolicy | None = None,
        cipher: EnvelopeCipher | None = None,
        minimizer: Minimizer | None = None,
        delegations: Any | None = None,  # DelegationService (Phase 8); Any avoids an import cycle
    ) -> None:
        self._delegations = delegations
        self._gate = gate or GatePolicy(frozenset(), 0.0)
        self._cipher = cipher
        self._minimizer = minimizer
        self._engine = engine
        self._registry = registry
        self._writer = writer
        self._risk_policies = risk_policies
        self._signer = signer
        self._build_commit = build_commit
        self._on_authorized = on_authorized
        self._batch = batch

    def _require_cipher(self) -> EnvelopeCipher:
        if self._cipher is None:
            raise KeyUnavailable("no KEK configured")
        return self._cipher

    def _open_request(self, action: Any) -> Any:
        """The pending request (sealed in actions.request_args_sealed), or None once closed."""
        if action.request_args_sealed is None:
            return None
        return self._require_cipher().open_json(
            ops_context(action.tenant_id, "request_args", action.action_id.bytes),
            bytes(action.request_args_sealed),
        )

    @property
    def signer(self) -> DecisionSigner | None:
        return self._signer

    # ---------------------------------------------------------------- startup
    def sync_signing_key(self) -> None:
        """Publish the signer's PUBLIC key (append-only table) so decisions verify later."""
        if self._signer is None:
            return
        with self._engine.begin() as conn:
            existing = conn.execute(
                select(t.approval_signing_keys.c.public_key).where(
                    t.approval_signing_keys.c.key_id == self._signer.key_id
                )
            ).scalar_one_or_none()
            if existing is None:
                conn.execute(
                    insert(t.approval_signing_keys).values(
                        key_id=self._signer.key_id,
                        algorithm="Ed25519",
                        public_key=self._signer.public_raw,
                    )
                )
            elif bytes(existing) != self._signer.public_raw:  # pragma: no cover - 64-bit id
                raise RuntimeError("signing key id collision")

    # ---------------------------------------------------------------- reads (approver UI)
    @staticmethod
    def _require_viewer(human: AuthenticatedHuman) -> None:
        if not (human.roles & {"approver", "auditor", "admin"}):
            raise Forbidden

    def list_approvals(
        self, human: AuthenticatedHuman, state: str | None, limit: int
    ) -> list[dict[str, Any]]:
        self._require_viewer(human)
        a = t.approvals
        q = (
            select(
                a.c.approval_id,
                a.c.action_id,
                a.c.state,
                a.c.requested_at,
                a.c.expires_at,
                a.c.required_approvals,
                t.actions.c.tool_id,
                t.actions.c.tool_version,
                t.actions.c.environment,
                t.actions.c.risk_level,
            )
            .join(t.actions, t.actions.c.action_id == a.c.action_id)
            .where(a.c.tenant_id == human.tenant_id)
            .order_by(a.c.requested_at)
            .limit(limit)
        )
        if state is not None:
            q = q.where(a.c.state == state)
        with self._engine.connect() as conn:
            rows = conn.execute(q).all()
        return [
            {
                "approval_id": str(r.approval_id),
                "action_id": str(r.action_id),
                "state": r.state,
                "tool": {"id": r.tool_id, "version": r.tool_version},
                "environment": r.environment,
                "risk_level": r.risk_level,
                "required_approvals": r.required_approvals,
                "requested_at": _iso(r.requested_at),
                "expires_at": _iso(r.expires_at),
            }
            for r in rows
        ]

    def get(self, human: AuthenticatedHuman, approval_id: UUID) -> dict[str, Any]:
        """What the approver sees: the EXACT tool, args (rendered safely), target, risk
        reasons, digest and nonce. The client must echo digest + nonce when deciding."""
        self._require_viewer(human)
        with self._engine.connect() as conn:
            ap = conn.execute(
                select(t.approvals).where(
                    t.approvals.c.approval_id == approval_id,
                    t.approvals.c.tenant_id == human.tenant_id,
                )
            ).one_or_none()
            if ap is None:
                raise NotFound
            action = conn.execute(
                select(t.actions, t.agents.c.name.label("agent_name"))
                .join(t.agents, t.agents.c.agent_id == t.actions.c.agent_id)
                .where(t.actions.c.action_id == ap.action_id)
            ).one()
            evaluated = conn.execute(
                select(t.evidence_events.c.body)
                .where(
                    t.evidence_events.c.action_id == ap.action_id,
                    t.evidence_events.c.event_type == "POLICY_EVALUATED",
                )
                .order_by(t.evidence_events.c.seq)
                .limit(1)
            ).scalar_one()
            decisions = conn.execute(
                select(
                    t.approval_decisions.c.approver_id,
                    t.approval_decisions.c.decision,
                    t.approval_decisions.c.decided_at_us,
                    t.humans.c.username,
                )
                .join(t.humans, t.humans.c.human_id == t.approval_decisions.c.approver_id)
                .where(t.approval_decisions.c.approval_id == approval_id)
                .order_by(t.approval_decisions.c.decided_at_us)
            ).all()
        spec = self._registry.get_any(action.tool_id, action.tool_version or "")
        args = self._open_request(action) or {}
        validated = spec.validate_args(args) if spec is not None else None
        target = (
            target_resource(spec.meta, validated.model_dump(mode="json"))
            if spec is not None and validated is not None
            else None
        )
        if spec is not None and self._minimizer is not None:
            # The approver sees the exact args EXCEPT secret fields (salted markers): the digest
            # still binds the real value (ADR-0029 §4).
            with self._engine.begin() as mconn:
                args = self._minimizer.args(mconn, action.tenant_id, spec.classes, args)
                tf = spec.meta.target_field or ""
                if target is not None and spec.classes.arg(tf) == "secret":
                    target = self._minimizer.marker(mconn, action.tenant_id, target)
        risk = evaluated.get("risk", {})
        policy = evaluated.get("policy", {})
        return {
            "approval_id": str(ap.approval_id),
            "state": ap.state,
            "state_reason": ap.state_reason,
            "required_role": ap.required_role,
            "required_approvals": ap.required_approvals,
            "requested_at": _iso(ap.requested_at),
            "expires_at": _iso(ap.expires_at),
            "action_digest": bytes(ap.action_digest).hex(),
            "nonce": bytes(ap.nonce).hex(),
            "action": {
                "action_id": str(action.action_id),
                "run_id": str(action.run_id),
                "status": action.status,
                "agent": {"id": str(action.agent_id), "name": action.agent_name},
                "tool": {"id": action.tool_id, "version": action.tool_version},
                "environment": action.environment,
                "args_rendered": render_args(args),
                "target_rendered": render_args({"target": target}),
                "delegation_depth": action.delegation_depth,
                "risk": {
                    "level": risk.get("level"),
                    "score": risk.get("score"),
                    "rules": risk.get("rules", []),
                    "reasons": risk.get("reasons", []),
                },
                "policy": {
                    "id": policy.get("id"),
                    "version": policy.get("ver"),
                    "effect": policy.get("effect"),
                    "rules": policy.get("rules", []),
                    "reasons": policy.get("reasons", []),
                    "controls": policy.get("controls", []),
                },
            },
            "decisions": [
                {
                    "approver": d.username,
                    "approver_id": str(d.approver_id),
                    "decision": d.decision,
                    "decided_at_us": d.decided_at_us,
                }
                for d in decisions
            ],
        }

    # ---------------------------------------------------------------- decision
    def decide(
        self,
        human: AuthenticatedHuman,
        approval_id: UUID,
        *,
        decision: DecisionInput,
        reason: str,
        echoed_digest: str,
        echoed_nonce: str,
    ) -> dict[str, Any]:
        if not human.has("approver"):
            raise Forbidden
        if self._signer is None:
            # Fail closed: an unsigned decision is never recorded; the action stays pending.
            raise DependencyUnavailable
        signer = self._signer
        outcome: str
        expired = False
        with self._engine.begin() as conn:
            ap = self._lock_approval(conn, approval_id, tenant_id=human.tenant_id)
            if ap is None:
                raise NotFound
            if ap.state != "PENDING":
                raise ApprovalNotPending
            action = self._lock_action(conn, ap.action_id)
            if not ap.live:
                self._expire(conn, ap, action)
                expired = True
            else:
                if not (
                    _hex_eq(echoed_digest, bytes(ap.action_digest))
                    and _hex_eq(echoed_nonce, bytes(ap.nonce))
                ):
                    log(
                        logger,
                        logging.WARNING,
                        "approval echo mismatch",
                        tenant_id=human.tenant_id,
                        error_code="APPROVAL_STALE",
                    )
                    raise ApprovalStale
                if action.status != "PENDING_APPROVAL":
                    raise ApprovalNotPending
                prior = conn.execute(
                    select(t.approval_decisions.c.decision).where(
                        t.approval_decisions.c.approval_id == approval_id,
                        t.approval_decisions.c.approver_id == human.human_id,
                    )
                ).scalar_one_or_none()
                if prior is not None:
                    raise ApprovalAlreadyDecided
                outcome = self._record_decision(conn, signer, human, ap, action, decision, reason)
        if expired:
            APPROVALS_EXPIRED.inc()
            raise ApprovalExpired
        APPROVAL_DECISIONS.labels("APPROVED" if decision == "APPROVE" else "REJECTED").inc()
        result: dict[str, Any] = {"approval_id": str(approval_id), "state": outcome}
        if outcome == "APPROVED":
            auth = self.authorize(approval_id)
            result["authorization"] = {"result": auth.result, "code": auth.code}
        with self._engine.connect() as conn:
            result["action_status"] = conn.execute(
                select(t.actions.c.status).where(t.actions.c.action_id == action.action_id)
            ).scalar_one()
        return result

    def _record_decision(
        self,
        conn: Connection,
        signer: DecisionSigner,
        human: AuthenticatedHuman,
        ap: Any,
        action: Any,
        decision: DecisionInput,
        reason: str,
    ) -> str:
        dec: Literal["APPROVED", "REJECTED"] = "APPROVED" if decision == "APPROVE" else "REJECTED"
        record = DecisionRecord(
            tenant=ap.tenant_id,
            approval_id=ap.approval_id,
            action_id=ap.action_id,
            action_digest=bytes(ap.action_digest),
            nonce=bytes(ap.nonce),
            decision=dec,
            approver_id=human.human_id,
            decided_at_us=us(ap.db_now),
            reason=reason,
        )
        dd = record.digest()
        sig = signer.sign(dd)
        try:
            with conn.begin_nested():
                conn.execute(
                    insert(t.approval_decisions).values(
                        approval_id=ap.approval_id,
                        approver_id=human.human_id,
                        decision=dec,
                        reason=reason,
                        decided_at_us=record.decided_at_us,
                        decision_digest=dd,
                        signature=sig,
                        key_id=signer.key_id,
                    )
                )
        except IntegrityError:  # pragma: no cover - the approval row lock serializes deciders
            raise ApprovalAlreadyDecided from None
        votes = int(
            conn.execute(
                select(func.count())
                .select_from(t.approval_decisions)
                .where(
                    t.approval_decisions.c.approval_id == ap.approval_id,
                    t.approval_decisions.c.decision == "APPROVED",
                )
            ).scalar_one()
        )
        state = "PENDING"
        if dec == "REJECTED":
            state = "REJECTED"
        elif votes >= ap.required_approvals:
            state = "APPROVED"
        approval_map = {
            "id": ap.approval_id.bytes,
            "binding": bytes(ap.action_digest),
            "exp": us(ap.expires_at),
            "req": ap.required_approvals,
            "votes": votes,
            "approver": str(human.human_id),
            "dec": dec,
            "dd": dd,
            "sig": sig,
            "kid": signer.key_id,
        }
        fields: dict[str, Any] = {"tool": _tool(action), "approval": approval_map}
        if dec == "REJECTED":
            fields["outcome"] = {"status": "DENIED", "code": "APPROVAL_REJECTED"}
        self._writer.append(
            conn,
            ap.tenant_id,
            [
                NewEvent(
                    type="APPROVAL_GRANTED" if dec == "APPROVED" else "APPROVAL_DENIED",
                    actor_kind="human",
                    actor_id=str(human.human_id),
                    action_id=ap.action_id,
                    run_id=action.run_id,
                    agent_id=action.agent_id,
                    fields=fields,
                    # The full signed record + the approver's comment (sensitive -> payload).
                    payload={"approval": {"record": record.record(), "comment": reason}},
                    risk_level=approval_event_level(action.risk_level),
                )
            ],
        )
        self._set_approval(conn, ap.approval_id, state, None)
        if state == "REJECTED":
            self._set_action(
                conn,
                ap.action_id,
                status="DENIED",
                error_code="APPROVAL_REJECTED",
                request_args_sealed=None,
            )
        log(
            logger,
            logging.INFO,
            "approval decision",
            tenant_id=ap.tenant_id,
            action_id=ap.action_id,
            decision=dec,
            status=state,
        )
        return state

    # ---------------------------------------------------------------- authorization
    def authorize(self, approval_id: UUID) -> AuthorizeResult:
        """Dispatch-time revalidation in ONE transaction (module docstring). Idempotent:
        concurrent callers serialize on the approval row; all but one see CONSUMED -> NOOP."""
        with self._engine.begin() as conn:
            ap = self._lock_approval(conn, approval_id)
            if ap is None or ap.state != "APPROVED":
                return AuthorizeResult("NOOP", ap.state if ap is not None else "NOT_FOUND")
            action = self._lock_action(conn, ap.action_id)
            if not ap.live:
                self._expire(conn, ap, action)
                result = AuthorizeResult("EXPIRED", "APPROVAL_EXPIRED")
            else:
                result = self._revalidate_and_commit(conn, ap, action)
        APPROVAL_AUTHORIZATIONS.labels(result.code or result.result).inc()
        if result.result == "EXPIRED":
            APPROVALS_EXPIRED.inc()
        if result.result == "AUTHORIZED" and self._on_authorized is not None:
            self._on_authorized()
        return result

    def _revalidate_and_commit(self, conn: Connection, ap: Any, action: Any) -> AuthorizeResult:
        # (1) confused deputy: the approval and the action must belong to the same tenant.
        if action is None or action.tenant_id != ap.tenant_id:
            self._set_approval(conn, ap.approval_id, "INVALIDATED", "TENANT_MISMATCH")
            return AuthorizeResult("DENIED", "TENANT_MISMATCH")
        # (2) only a still-pending action can be authorized by an approval.
        if action.status != "PENDING_APPROVAL":
            self._set_approval(conn, ap.approval_id, "INVALIDATED", "ACTION_NOT_PENDING")
            return AuthorizeResult("DENIED", "ACTION_NOT_PENDING")
        # (3) signed decisions from enough distinct approvers.
        decs = self._valid_decisions(conn, ap)
        if len(decs) < ap.required_approvals:
            return self._deny(conn, ap, action, "DECISION_SIGNATURE_INVALID", None)
        # (4) recompute the action digest from the stored request.
        spec = self._registry.get_any(action.tool_id, action.tool_version or "")
        try:
            request = self._open_request(action)
        except SealedDataError:
            request = None  # tampered or swapped sealed request: binding cannot be recomputed
        validated = spec.validate_args(request) if spec is not None and request else None
        stored_policy = load_policy_version(conn, action.policy_id, action.policy_version)
        if spec is None or validated is None or stored_policy is None:
            return self._deny(conn, ap, action, "APPROVAL_BINDING_MISMATCH", None)
        args_json = validated.model_dump(mode="json")
        # Phase 8: a delegated action is bound to its delegation (id + token hash).
        delegation_hash = None
        if action.delegation_id is not None:
            delegation_hash = conn.execute(
                select(t.delegations.c.token_hash).where(
                    t.delegations.c.delegation_id == action.delegation_id
                )
            ).scalar_one_or_none()
            if delegation_hash is None:
                return self._deny(conn, ap, action, "APPROVAL_BINDING_MISMATCH", None)
        binding = ActionBinding(
            tenant=action.tenant_id,
            agent_id=action.agent_id,
            tool_id=action.tool_id,
            tool_version=action.tool_version,
            args_digest=args_digest(validated),
            target=target_resource(spec.meta, validated.model_dump(mode="python")),
            environment=action.environment,
            policy_id=action.policy_id,
            policy_version=action.policy_version,
            policy_digest=policy_digest(stored_policy.raw),
            risk_policy_digest=bytes(action.risk_policy_digest or b""),
            risk_level=action.risk_level,
            delegation_depth=action.delegation_depth,
            delegation_id=action.delegation_id,
            delegation_hash=bytes(delegation_hash) if delegation_hash is not None else None,
        ).digest()
        if not (
            hmac.compare_digest(binding, bytes(ap.action_digest))
            and hmac.compare_digest(binding, bytes(action.action_digest or b""))
        ):
            return self._deny(conn, ap, action, "APPROVAL_BINDING_MISMATCH", None)
        # (5) agent still active and scoped; current policy is not stricter than approved.
        agent_row = conn.execute(
            select(t.agents).where(t.agents.c.agent_id == action.agent_id)
        ).one()
        if agent_row.status != "active":
            return self._deny(conn, ap, action, "AGENT_INACTIVE", None)
        agent = AuthenticatedAgent(
            tenant_id=agent_row.tenant_id,
            agent_id=agent_row.agent_id,
            name=agent_row.name,
            scopes=frozenset(agent_row.scopes),
            trust_tier=agent_row.trust_tier,
        )
        current = load_active_policy(conn)
        # The CURRENT registry: a tool disabled since the approval is unknown -> DENY.
        resolved = self._registry.resolve(action.tool_id, action.tool_version)
        # Phase 8: the delegation chain must STILL be live and covering (a parent's
        # revocation or scope reduction since the request takes effect here).
        constraint = None
        if action.delegation_id is not None:
            if self._delegations is None:
                return self._deny(conn, ap, action, "DELEGATION_INVALID", None)
            constraint = self._delegations.recheck(conn, action.delegation_id, agent).constraint
        decision = decide_action(
            agent=agent,
            tool_id=action.tool_id,
            tool=resolved.meta if resolved is not None else None,
            args=args_json,
            environment=action.environment,
            risk_policy=self._risk_policies.active(),
            policy=current.document,
            now=datetime.now(UTC),
            delegation_depth=action.delegation_depth if constraint is None else None,
            delegation=constraint,
        )
        if decision.effect == "DENY":
            return self._deny(conn, ap, action, "POLICY_REEVALUATION_DENIED", decision)
        if LEVEL_ORDER.index(decision.risk.level.name) > LEVEL_ORDER.index(action.risk_level):
            return self._deny(conn, ap, action, "RISK_INCREASED_SINCE_APPROVAL", decision)
        # (6) single use: the PK on approval_uses.nonce makes a second use a constraint error.
        conn.execute(
            insert(t.approval_uses).values(
                nonce=bytes(ap.nonce), approval_id=ap.approval_id, action_id=ap.action_id
            )
        )
        self._set_approval(conn, ap.approval_id, "CONSUMED", None)
        tool = _tool(action)
        common = {"action_id": ap.action_id, "run_id": action.run_id, "agent_id": action.agent_id}
        level = approval_event_level(action.risk_level)
        stored = self._writer.append(
            conn,
            ap.tenant_id,
            [
                NewEvent(
                    type="POLICY_EVALUATED",
                    actor_kind="gateway",
                    actor_id=GATEWAY_ACTOR_ID,
                    fields=policy_evaluated_fields(tool, action.environment, decision),
                    risk_level=level,
                    **common,
                ),
                NewEvent(
                    type="ACTION_AUTHORIZED",
                    actor_kind="gateway",
                    actor_id=GATEWAY_ACTOR_ID,
                    fields={
                        "tool": tool,
                        "code": {"gw": self._build_commit, "adapter": spec.adapter_version},
                        "args": args_digest(validated),
                        "approval": {
                            "id": ap.approval_id.bytes,
                            "binding": bytes(ap.action_digest),
                            "exp": us(ap.expires_at),
                            "req": ap.required_approvals,
                            "decs": decs,
                        },
                    },
                    risk_level=level,
                    **common,
                ),
            ],
        )
        # CRITICAL pre-action anchoring (ADR-0009/0028): the job waits for the anchor of the
        # epoch holding ACTION_AUTHORIZED to reach finality, or fails at the deadline.
        job: dict[str, Any] = {"status": "PENDING"}
        if self._gate.required(action.risk_level, GatePolicy.rule_ids(decision)):
            authorized = next(e for e in stored if e.type == "ACTION_AUTHORIZED")
            job = self._gate.job_values(authorized.seq)
        conn.execute(
            insert(t.outbox_jobs).values(
                kind="DISPATCH",
                tenant_id=ap.tenant_id,
                action_id=ap.action_id,
                attempts=0,
                args_sealed=self._require_cipher().seal_json(
                    ops_context(ap.tenant_id, "dispatch_args", ap.action_id.bytes), args_json
                ),
                **job,
            )
        )
        # The sealed request leaves the actions row once the approval closes; the dispatch
        # args now live (sealed) in the outbox job and, minimized, in the evidence payload.
        self._set_action(conn, ap.action_id, status="AUTHORIZED", request_args_sealed=None)
        log(
            logger,
            logging.INFO,
            "approval consumed",
            tenant_id=ap.tenant_id,
            action_id=ap.action_id,
            status="AUTHORIZED",
        )
        return AuthorizeResult("AUTHORIZED", None)

    def _valid_decisions(self, conn: Connection, ap: Any) -> list[dict[str, Any]]:
        """APPROVED decisions that (a) verify under the gateway's CONFIGURED key, (b) over the
        decision record recomputed from the approval row, (c) by a still-active approver of
        the approval's tenant. Rows in ``approval_signing_keys`` publish keys; they never
        make a key trusted (agw_app can insert there)."""
        if self._signer is None:
            return []  # cannot verify -> nothing counts (fail closed)
        trusted = {self._signer.key_id: self._signer.public_raw}
        rows = conn.execute(
            select(t.approval_decisions)
            .join(t.humans, t.humans.c.human_id == t.approval_decisions.c.approver_id)
            .where(
                t.approval_decisions.c.approval_id == ap.approval_id,
                t.approval_decisions.c.decision == "APPROVED",
                t.humans.c.tenant_id == ap.tenant_id,
                t.humans.c.status == "active",
                literal("approver") == any_(t.humans.c.roles),
            )
            .order_by(t.approval_decisions.c.decided_at_us)
        ).all()
        valid: dict[UUID, dict[str, Any]] = {}
        for r in rows:
            record = DecisionRecord(
                tenant=ap.tenant_id,
                approval_id=ap.approval_id,
                action_id=ap.action_id,
                action_digest=bytes(ap.action_digest),
                nonce=bytes(ap.nonce),
                decision="APPROVED",
                approver_id=r.approver_id,
                decided_at_us=r.decided_at_us,
                reason=r.reason,
            )
            dd = record.digest()
            public_raw = trusted.get(r.key_id)
            if (
                public_raw is not None
                and hmac.compare_digest(dd, bytes(r.decision_digest))
                and verify_decision(public_raw, dd, bytes(r.signature))
            ):
                valid[r.approver_id] = {
                    "approver": str(r.approver_id),
                    "dd": dd,
                    "sig": bytes(r.signature),
                    "kid": r.key_id,
                }
        return list(valid.values())

    def _deny(
        self, conn: Connection, ap: Any, action: Any, code: str, decision: Any | None
    ) -> AuthorizeResult:
        """Revalidation failed: approval INVALIDATED, action DENIED, evidence written."""
        self._set_approval(conn, ap.approval_id, "INVALIDATED", code)
        tool = _tool(action)
        common = {"action_id": ap.action_id, "run_id": action.run_id, "agent_id": action.agent_id}
        level = approval_event_level(action.risk_level)
        events: list[NewEvent] = []
        if decision is not None:
            events.append(
                NewEvent(
                    type="POLICY_EVALUATED",
                    actor_kind="gateway",
                    actor_id=GATEWAY_ACTOR_ID,
                    fields=policy_evaluated_fields(tool, action.environment, decision),
                    risk_level=level,
                    **common,
                )
            )
        events.append(
            NewEvent(
                type="ACTION_DENIED",
                actor_kind="gateway",
                actor_id=GATEWAY_ACTOR_ID,
                fields={"tool": tool, "outcome": {"status": "DENIED", "code": code}},
                risk_level=level,
                **common,
            )
        )
        self._writer.append(conn, ap.tenant_id, events)
        self._set_action(
            conn, ap.action_id, status="DENIED", error_code=code, request_args_sealed=None
        )
        log(
            logger,
            logging.WARNING,
            "approval invalidated at dispatch",
            tenant_id=ap.tenant_id,
            action_id=ap.action_id,
            error_code=code,
        )
        return AuthorizeResult("DENIED", code)

    # ---------------------------------------------------------------- expiry sweeper
    def sweep(self) -> int:
        """Expire overdue approvals; (re)try authorization of APPROVED ones (crash between the
        decision tx and the authorize tx). Returns the number of approvals handled."""
        handled = 0
        for _ in range(self._batch):
            with self._engine.begin() as conn:
                row = conn.execute(
                    select(t.approvals.c.approval_id)
                    .where(
                        t.approvals.c.state.in_(("PENDING", "APPROVED")),
                        t.approvals.c.expires_at <= func.now(),
                    )
                    .order_by(t.approvals.c.expires_at)
                    .limit(1)
                    .with_for_update(skip_locked=True)
                ).one_or_none()
                if row is None:
                    break
                ap = self._lock_approval(conn, row.approval_id)
                assert ap is not None  # noqa: S101 - locked above
                self._expire(conn, ap, self._lock_action(conn, ap.action_id))
            APPROVALS_EXPIRED.inc()
            handled += 1
        with self._engine.connect() as conn:
            approved = (
                conn.execute(
                    select(t.approvals.c.approval_id)
                    .where(t.approvals.c.state == "APPROVED", t.approvals.c.expires_at > func.now())
                    .order_by(t.approvals.c.requested_at)
                    .limit(self._batch)
                )
                .scalars()
                .all()
            )
        for approval_id in approved:
            self.authorize(approval_id)
            handled += 1
        return handled

    def _expire(self, conn: Connection, ap: Any, action: Any) -> None:
        votes = int(
            conn.execute(
                select(func.count())
                .select_from(t.approval_decisions)
                .where(
                    t.approval_decisions.c.approval_id == ap.approval_id,
                    t.approval_decisions.c.decision == "APPROVED",
                )
            ).scalar_one()
        )
        self._set_approval(conn, ap.approval_id, "EXPIRED", None)
        self._writer.append(
            conn,
            ap.tenant_id,
            [
                NewEvent(
                    type="APPROVAL_EXPIRED",
                    actor_kind="gateway",
                    actor_id=GATEWAY_ACTOR_ID,
                    action_id=ap.action_id,
                    run_id=action.run_id,
                    agent_id=action.agent_id,
                    fields={
                        "tool": _tool(action),
                        "approval": {
                            "id": ap.approval_id.bytes,
                            "binding": bytes(ap.action_digest),
                            "exp": us(ap.expires_at),
                            "req": ap.required_approvals,
                            "votes": votes,
                        },
                    },
                    risk_level=approval_event_level(action.risk_level),
                )
            ],
        )
        if action.status == "PENDING_APPROVAL":
            self._set_action(
                conn,
                ap.action_id,
                status="EXPIRED",
                error_code="APPROVAL_EXPIRED",
                request_args_sealed=None,
            )
        log(
            logger, logging.INFO, "approval expired", tenant_id=ap.tenant_id, action_id=ap.action_id
        )

    # ---------------------------------------------------------------- violations
    def record_agent_on_human_endpoint(self, agent: AuthenticatedAgent, endpoint: str) -> None:
        """An agent credential on a human-only endpoint: SECURITY_VIOLATION in its own tx."""
        with self._engine.begin() as conn:
            self._writer.append(
                conn,
                agent.tenant_id,
                [
                    NewEvent(
                        type="SECURITY_VIOLATION",
                        actor_kind="agent",
                        actor_id=str(agent.agent_id),
                        agent_id=agent.agent_id,
                        fields={
                            "violation": {"kind": "AGENT_ON_HUMAN_ENDPOINT", "claimed": endpoint}
                        },
                        risk_level="HIGH",
                    )
                ],
            )
        log(
            logger,
            logging.WARNING,
            "security violation",
            agent_id=agent.agent_id,
            tenant_id=agent.tenant_id,
            error_code="AGENT_ON_HUMAN_ENDPOINT",
        )

    # ---------------------------------------------------------------- row helpers
    @staticmethod
    def _lock_approval(conn: Connection, approval_id: UUID, *, tenant_id: str | None = None) -> Any:
        q = select(
            t.approvals,
            func.now().label("db_now"),
            (t.approvals.c.expires_at > func.now()).label("live"),
        ).where(t.approvals.c.approval_id == approval_id)
        if tenant_id is not None:
            q = q.where(t.approvals.c.tenant_id == tenant_id)
        return conn.execute(q.with_for_update(of=t.approvals)).one_or_none()

    @staticmethod
    def _lock_action(conn: Connection, action_id: UUID) -> Any:
        return conn.execute(
            select(t.actions).where(t.actions.c.action_id == action_id).with_for_update()
        ).one_or_none()

    @staticmethod
    def _set_approval(conn: Connection, approval_id: UUID, state: str, reason: str | None) -> None:
        conn.execute(
            update(t.approvals)
            .where(t.approvals.c.approval_id == approval_id)
            .values(state=state, state_reason=reason, updated_at=func.now())
        )

    @staticmethod
    def _set_action(conn: Connection, action_id: UUID, **values: Any) -> None:
        conn.execute(
            update(t.actions)
            .where(t.actions.c.action_id == action_id)
            .values(**values, updated_at=func.now(), version=t.actions.c.version + 1)
        )


def _tool(action: Any) -> dict[str, str]:
    tool = {"id": action.tool_id}
    if action.tool_version:
        tool["ver"] = action.tool_version
    return tool


def _hex_eq(echoed: str, actual: bytes) -> bool:
    try:
        raw = bytes.fromhex(echoed)
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(raw, actual)


def _iso(value: datetime | None) -> str | None:
    if value is None:
        return None
    return value.isoformat().replace("+00:00", "Z")
