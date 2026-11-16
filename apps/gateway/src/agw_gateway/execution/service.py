"""Action service: request envelope, idempotency and tx1 (02 §3, 08 §1, §5).

Order for ``POST /v1/actions``:

1. Parse the envelope (``extra="forbid"``). A body ``agent_id`` that differs from the
   authenticated agent -> ``SECURITY_VIOLATION`` in its own tx, then 403; nothing else runs.
2. Validate the Idempotency-Key header; compute the request fingerprint.
3. Resolve the tool, validate args, assess risk (risk policy from ``risk_policies``, ADR-0026),
   evaluate policy: pure, before tx1, so the tenant chain-head lock is held briefly.
4. tx1 (one COMMIT): ``idempotency_keys`` first (a concurrent duplicate blocks on the
   uncommitted unique entry), ``actions`` (with the action digest, ADR-0027), ``ACTION_REQUESTED``,
   ``POLICY_EVALUATED``, then ``ACTION_DENIED`` | ``approvals`` + ``APPROVAL_REQUIRED`` |
   ``ACTION_AUTHORIZED`` + ``outbox_jobs(DISPATCH)``.
5. Only after COMMIT is the executor nudged. The outbox row is the source of truth.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Final, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, ValidationError
from sqlalchemy import Engine, Row, func, insert, select, text
from sqlalchemy.exc import IntegrityError

from agw_gateway.anchoring.gate import GatePolicy
from agw_gateway.approvals.binding import ActionBinding, policy_digest, target_resource
from agw_gateway.approvals.service import ApprovalConfig, NewApproval
from agw_gateway.auth.models import AuthenticatedAgent
from agw_gateway.crypto.canonical import ZERO32, args_digest, profile_value
from agw_gateway.db import tables as t
from agw_gateway.evidence import EvidenceWriter, NewEvent
from agw_gateway.evidence.records import policy_evaluated_fields
from agw_gateway.evidence.writer import GATEWAY_ACTOR_ID
from agw_gateway.execution.crash import CrashPoints
from agw_gateway.execution.errors import (
    AgentIdMismatch,
    IdempotencyKeyInvalid,
    IdempotencyKeyMissing,
    IdempotencyKeyReused,
    RequestInvalid,
)
from agw_gateway.execution.fingerprint import FINGERPRINT_ALG, request_fingerprint
from agw_gateway.ids import uuid7
from agw_gateway.keys import KeyUnavailable
from agw_gateway.logs import log
from agw_gateway.metrics import RISK_DECISIONS
from agw_gateway.policies import Decision
from agw_gateway.policies.pipeline import decide_action
from agw_gateway.policy_store import ACTIVE_POLICY_ID, StoredPolicy, load_active_policy
from agw_gateway.privacy.cipher import EnvelopeCipher, ops_context
from agw_gateway.privacy.minimize import Minimizer
from agw_gateway.risk_store import RiskPolicyStore
from agw_gateway.tools.registry import AmbiguousToolVersion, ToolRegistry
from agw_gateway.tools.spec import ToolSpec

logger = logging.getLogger("agw.execution.service")

IDEMPOTENCY_KEY_RE: Final = re.compile(r"^[A-Za-z0-9_\-:.]{1,128}$")
__all__ = ["ACTIVE_POLICY_ID", "ActionService", "SubmitResult"]
_STATUS_FOR_EFFECT: Final = {
    "ALLOW": "AUTHORIZED",
    "DENY": "DENIED",
    "REQUIRE_APPROVAL": "PENDING_APPROVAL",
}


# --------------------------------------------------------------------------- envelope
class _Envelope(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class Intent(_Envelope):
    summary: str = Field(default="", max_length=1024)


class ContextSource(_Envelope):
    uri: str = Field(max_length=2048)
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class Context(_Envelope):
    sources: tuple[ContextSource, ...] = Field(default=(), max_length=64)


class Delegation(_Envelope):
    """Agent-DECLARED delegation (unauthenticated). It can only raise risk (ADR-0026)."""

    depth: int = Field(ge=0, le=32)


class ActionRequest(_Envelope):
    run_id: UUID
    tool: str = Field(pattern=r"^[A-Za-z0-9_.\-]{1,128}$")
    tool_version: str | None = Field(default=None, pattern=r"^[0-9A-Za-z.+\-]{1,32}$")
    environment: Literal["dev", "staging", "prod"]
    args: dict[str, Any]
    agent_id: str | None = Field(default=None, max_length=128)
    # Code provenance claimed by the agent (unauthenticated; recorded as such).
    agent_version: str | None = Field(default=None, pattern=r"^[A-Za-z0-9._/+\-]{1,64}$")
    # Recorded in the ACTION_REQUESTED payload (intent / context provenance). There is no
    # "reasoning" field: chain-of-thought is never captured (extra="forbid" rejects it).
    intent: Intent | None = None
    context: Context | None = None
    delegation: Delegation | None = None


@dataclass(frozen=True)
class SubmitResult:
    status_code: int
    body: dict[str, Any]
    replayed: bool


# --------------------------------------------------------------------------- service
class ActionService:
    def __init__(
        self,
        *,
        engine: Engine,
        registry: ToolRegistry,
        writer: EvidenceWriter,
        crash: CrashPoints,
        tx1_statement_timeout_ms: int = 5000,
        idempotency_ttl: timedelta = timedelta(hours=24),
        on_authorized: Callable[[], None] | None = None,
        build_commit: str = "unknown",
        risk_policies: RiskPolicyStore | None = None,
        approval_config: ApprovalConfig | None = None,
        gate: GatePolicy | None = None,
        cipher: EnvelopeCipher | None = None,
        minimizer: Minimizer | None = None,
    ) -> None:
        self._gate = gate or GatePolicy(frozenset(), 0.0)
        self._cipher_obj = cipher
        self._minimizer_obj = minimizer
        self._approval_config = approval_config or ApprovalConfig(ttl_seconds={})
        self._build_commit = build_commit
        self._risk_policies = risk_policies or RiskPolicyStore(engine, "risk-default")
        self._engine = engine
        self._registry = registry
        self._writer = writer
        self._crash = crash
        self._timeout_ms = int(tx1_statement_timeout_ms)
        self._ttl = idempotency_ttl
        self._on_authorized = on_authorized

    def _cipher(self) -> EnvelopeCipher:
        if self._cipher_obj is None:
            raise KeyUnavailable("no KEK configured")
        return self._cipher_obj

    def _minimizer(self) -> Minimizer:
        if self._minimizer_obj is None:
            raise KeyUnavailable("no KEK configured")
        return self._minimizer_obj

    # ---------------------------------------------------------------- public
    def submit(
        self, agent: AuthenticatedAgent, raw_body: bytes, idempotency_key: str | None
    ) -> SubmitResult:
        req = self._parse(raw_body)
        self._check_agent_id(agent, req)

        if idempotency_key is None:
            raise IdempotencyKeyMissing
        if not IDEMPOTENCY_KEY_RE.fullmatch(idempotency_key):
            raise IdempotencyKeyInvalid
        try:
            fingerprint = request_fingerprint(
                tool=req.tool,
                tool_version=req.tool_version,
                environment=req.environment,
                run_id=str(req.run_id),
                args=req.args,
            )
        except ValueError as exc:  # NaN/Infinity cannot be fingerprinted
            raise RequestInvalid(["args"]) from exc

        # Fast path: a completed earlier request with this key.
        with self._engine.connect() as conn:
            existing = self._read_key(conn, agent.agent_id, idempotency_key)
        if existing is not None:
            return self._replay(existing, fingerprint)

        spec, decision, validated, policy = self._evaluate(agent, req)
        binding = _binding(agent, req, spec, decision, validated, policy)
        approval = (
            NewApproval.create(binding, decision.risk.level.name, self._approval_config)
            if decision.effect == "REQUIRE_APPROVAL" and binding is not None
            else None
        )
        try:
            result = self._tx1(
                agent,
                req,
                idempotency_key,
                fingerprint,
                spec,
                decision,
                validated,
                binding,
                approval,
            )
        except IntegrityError as exc:
            if not _is_idempotency_conflict(exc):
                raise
            # A concurrent duplicate committed first: replay or 409.
            with self._engine.connect() as conn:
                existing = self._read_key(conn, agent.agent_id, idempotency_key)
            if existing is None:  # pragma: no cover - the winner's row is committed
                raise
            return self._replay(existing, fingerprint)

        RISK_DECISIONS.labels(decision.risk.level.name, decision.effect).inc()
        self._crash.hit("after_tx1_commit")
        if decision.effect == "ALLOW" and self._on_authorized is not None:
            self._on_authorized()
        return result

    # ---------------------------------------------------------------- steps
    @staticmethod
    def _parse(raw_body: bytes) -> ActionRequest:
        try:
            return ActionRequest.model_validate_json(raw_body)
        except ValidationError as exc:
            fields = sorted({".".join(str(p) for p in e["loc"]) or "<body>" for e in exc.errors()})
            raise RequestInvalid(fields) from None

    def _check_agent_id(self, agent: AuthenticatedAgent, req: ActionRequest) -> None:
        if req.agent_id is None:
            return
        try:
            same = UUID(req.agent_id) == agent.agent_id
        except ValueError:
            same = False
        if same:
            return
        event = NewEvent(
            type="SECURITY_VIOLATION",
            actor_kind="agent",
            actor_id=str(agent.agent_id),
            run_id=req.run_id,
            agent_id=agent.agent_id,
            fields={"violation": {"kind": "AGENT_ID_MISMATCH", "claimed": req.agent_id}},
            risk_level="HIGH",  # incident indicator: sealed immediately (Paper A §5)
        )
        with self._engine.begin() as conn:
            self._writer.append(conn, agent.tenant_id, [event])
        log(
            logger,
            logging.WARNING,
            "security violation",
            agent_id=agent.agent_id,
            tenant_id=agent.tenant_id,
            error_code="AGENT_ID_MISMATCH",
        )
        raise AgentIdMismatch

    def _load_policy(self) -> StoredPolicy:
        with self._engine.connect() as conn:
            return load_active_policy(conn, ACTIVE_POLICY_ID)

    def _evaluate(
        self, agent: AuthenticatedAgent, req: ActionRequest
    ) -> tuple[ToolSpec | None, Decision, BaseModel | None, StoredPolicy]:
        try:
            spec = self._registry.resolve(req.tool, req.tool_version)
        except AmbiguousToolVersion:
            raise RequestInvalid(["tool_version"]) from None
        validated = spec.validate_args(req.args) if spec is not None else None
        policy = self._load_policy()
        decision = decide_action(
            agent=agent,
            tool_id=req.tool,
            tool=spec.meta if spec else None,
            args=validated.model_dump(mode="json") if validated is not None else None,
            environment=req.environment,
            risk_policy=self._risk_policies.active(),
            policy=policy.document,
            now=datetime.now(UTC),
            delegation_depth=req.delegation.depth if req.delegation else None,
        )
        return spec, decision, validated, policy

    def _tx1(
        self,
        agent: AuthenticatedAgent,
        req: ActionRequest,
        key: str,
        fingerprint: bytes,
        spec: ToolSpec | None,
        decision: Decision,
        validated: BaseModel | None,
        binding: bytes | None,
        approval: NewApproval | None,
    ) -> SubmitResult:
        action_id = uuid7()
        status = _STATUS_FOR_EFFECT[decision.effect]
        tool_version = spec.meta.version if spec else req.tool_version
        body = _response_body(action_id, req.run_id, status, decision, approval)
        pending = decision.effect == "REQUIRE_APPROVAL"

        with self._engine.begin() as conn:
            conn.execute(text(f"SET LOCAL statement_timeout = {self._timeout_ms}"))
            conn.execute(
                insert(t.idempotency_keys).values(
                    agent_id=agent.agent_id,
                    key=key,
                    fingerprint=fingerprint,
                    fingerprint_alg=FINGERPRINT_ALG,
                    action_id=action_id,
                    response_status=201,
                    response_body=body,
                    expires_at=func.now() + self._ttl,
                )
            )
            conn.execute(
                insert(t.actions).values(
                    action_id=action_id,
                    tenant_id=agent.tenant_id,
                    agent_id=agent.agent_id,
                    run_id=req.run_id,
                    tool_id=req.tool,
                    tool_version=tool_version,
                    environment=req.environment,
                    status=status,
                    decision=decision.effect,
                    risk_level=decision.risk.level.name,
                    policy_id=decision.policy_id,
                    policy_version=decision.policy_version,
                    idempotency_key=key,
                    version=1,
                    action_digest=binding,
                    # The validated request is kept ONLY while approval is pending: the
                    # authorization tx recomputes the digest from it and dispatches it.
                    # Sealed (KEK envelope): it may hold SECRET fields the tool needs (ADR-0029).
                    request_args_sealed=(
                        self._cipher().seal_json(
                            ops_context(agent.tenant_id, "request_args", action_id.bytes),
                            validated.model_dump(mode="json"),
                        )
                        if pending and validated is not None
                        else None
                    ),
                    delegation_depth=req.delegation.depth if req.delegation else None,
                    risk_policy_digest=decision.risk.policy_digest,
                )
            )
            approval_map = (
                approval.insert(conn, agent.tenant_id, action_id) if approval is not None else None
            )
            # Minimization (ADR-0029 §4): secret fields -> salted markers; unvalidated args
            # are not stored at all (key names + salted digest only).
            intent_args = (
                {
                    "args": profile_value(
                        self._minimizer().args(
                            conn,
                            agent.tenant_id,
                            spec.classes,
                            validated.model_dump(mode="python"),
                        )
                    )
                }
                if validated is not None and spec is not None
                else self._minimizer().unvalidated(conn, agent.tenant_id, req.args)
            )
            events = _tx1_events(
                agent,
                req,
                action_id,
                tool_version,
                spec,
                decision,
                validated,
                intent_args,
                self._build_commit,
                approval_map,
            )
            stored = self._writer.append(conn, agent.tenant_id, events)
            if decision.effect == "ALLOW":
                assert validated is not None  # noqa: S101  (ALLOW implies valid args)
                job: dict[str, Any] = {"status": "PENDING"}
                if self._gate.required(decision.risk.level.name, GatePolicy.rule_ids(decision)):
                    authorized = next(e for e in stored if e.type == "ACTION_AUTHORIZED")
                    job = self._gate.job_values(authorized.seq)
                conn.execute(
                    insert(t.outbox_jobs).values(
                        kind="DISPATCH",
                        tenant_id=agent.tenant_id,
                        action_id=action_id,
                        attempts=0,
                        args_sealed=self._cipher().seal_json(
                            ops_context(agent.tenant_id, "dispatch_args", action_id.bytes),
                            validated.model_dump(mode="json"),
                        ),
                        **job,
                    )
                )
        log(
            logger,
            logging.INFO,
            "action evaluated",
            agent_id=agent.agent_id,
            tenant_id=agent.tenant_id,
            tool_id=req.tool,
            action_id=action_id,
            decision=decision.effect,
            status=status,
        )
        return SubmitResult(status_code=201, body=body, replayed=False)

    # ---------------------------------------------------------------- idempotency
    @staticmethod
    def _read_key(conn: Any, agent_id: UUID, key: str) -> Row[Any] | None:
        row: Row[Any] | None = conn.execute(
            select(
                t.idempotency_keys.c.fingerprint,
                t.idempotency_keys.c.response_body,
            ).where(t.idempotency_keys.c.agent_id == agent_id, t.idempotency_keys.c.key == key)
        ).one_or_none()
        return row

    @staticmethod
    def _replay(row: Row[Any], fingerprint: bytes) -> SubmitResult:
        if bytes(row.fingerprint) != fingerprint:
            raise IdempotencyKeyReused
        return SubmitResult(status_code=200, body=dict(row.response_body), replayed=True)


# --------------------------------------------------------------------------- helpers
def _is_idempotency_conflict(exc: IntegrityError) -> bool:
    diag = getattr(exc.orig, "diag", None)
    return getattr(diag, "constraint_name", None) == "idempotency_keys_pkey"


def _binding(
    agent: AuthenticatedAgent,
    req: ActionRequest,
    spec: ToolSpec | None,
    decision: Decision,
    validated: BaseModel | None,
    policy: StoredPolicy,
) -> bytes | None:
    """Action digest (ADR-0027), computed once at request time. None if args are invalid or
    the tool is unknown (such requests are DENIED and can never be approved)."""
    if spec is None or validated is None:
        return None
    return ActionBinding(
        tenant=agent.tenant_id,
        agent_id=agent.agent_id,
        tool_id=spec.meta.tool_id,
        tool_version=spec.meta.version,
        args_digest=args_digest(validated),
        target=target_resource(spec.meta, validated.model_dump(mode="python")),
        environment=req.environment,
        policy_id=decision.policy_id,
        policy_version=decision.policy_version,
        policy_digest=policy_digest(policy.raw),
        risk_policy_digest=decision.risk.policy_digest,
        risk_level=decision.risk.level.name,
        delegation_depth=req.delegation.depth if req.delegation else None,
    ).digest()


def _response_body(
    action_id: UUID,
    run_id: UUID,
    status: str,
    decision: Decision,
    approval: NewApproval | None = None,
) -> dict[str, Any]:
    body: dict[str, Any] = {
        "action_id": str(action_id),
        "status": status,
        "decision": {
            "effect": decision.effect,
            "policy_id": decision.policy_id,
            "policy_version": decision.policy_version,
            "matched_rule_ids": list(decision.matched_rule_ids),
            "reasons": [str(r) for r in decision.reasons],
            "risk_level": decision.risk.level.name,
            "risk_rules": list(decision.risk.matched_rules),
            "control_ids": list(decision.control_ids),
        },
        "links": {
            "self": f"/v1/actions/{action_id}",
            "timeline": f"/v1/runs/{run_id}/timeline",
        },
    }
    if approval is not None:
        # For reference only: an agent can never decide an approval (ADR-0027).
        body["approval"] = {
            "approval_id": str(approval.approval_id),
            "required_approvals": approval.required,
        }
    return body


def _tx1_events(
    agent: AuthenticatedAgent,
    req: ActionRequest,
    action_id: UUID,
    tool_version: str | None,
    spec: ToolSpec | None,
    decision: Decision,
    validated: BaseModel | None,
    intent_args: dict[str, Any],
    build_commit: str,
    approval_map: dict[str, Any] | None = None,
) -> list[NewEvent]:
    tool: dict[str, str] = {"id": req.tool}
    code: dict[str, str] = {"gw": build_commit}
    if req.agent_version is not None:
        code["agent"] = req.agent_version
    # Intent (Paper B field 1): minimized validated args, or (unvalidated) key names + digest.
    intent = dict(intent_args)
    if req.intent is not None and req.intent.summary:
        intent["summary"] = req.intent.summary
    sources = [
        {"uri": src.uri, "digest": bytes.fromhex(src.sha256)}
        for src in (req.context.sources if req.context else ())
    ]
    if tool_version is not None:
        tool["ver"] = tool_version
    common: dict[str, Any] = {
        "action_id": action_id,
        "run_id": req.run_id,
        "agent_id": agent.agent_id,
    }
    risk = decision.risk
    level = risk.level.name
    payload: dict[str, Any] = {"intent": intent, "context": {"sources": sources}}
    if req.delegation is not None:
        payload["delegation"] = {"depth": req.delegation.depth, "declared_by": "agent"}
    events = [
        NewEvent(
            type="ACTION_REQUESTED",
            actor_kind="agent",
            actor_id=str(agent.agent_id),
            fields={"tool": tool, "env": req.environment, "code": dict(code)},
            payload=payload,
            delegation_present=req.delegation is None,
            risk_level=level,
            **common,
        ),
        NewEvent(
            type="POLICY_EVALUATED",
            actor_kind="gateway",
            actor_id=GATEWAY_ACTOR_ID,
            fields=policy_evaluated_fields(tool, req.environment, decision),
            risk_level=level,
            **common,
        ),
    ]
    first_reason = str(decision.reasons[0]) if decision.reasons else ""
    if decision.effect == "ALLOW":
        assert spec is not None  # noqa: S101
        events.append(
            NewEvent(
                type="ACTION_AUTHORIZED",
                actor_kind="gateway",
                actor_id=GATEWAY_ACTOR_ID,
                fields={
                    "tool": tool,
                    "code": {**code, "adapter": spec.adapter_version},
                    "args": args_digest(validated) if validated is not None else ZERO32,
                },
                risk_level=level,
                **common,
            )
        )
    elif decision.effect == "DENY":
        events.append(
            NewEvent(
                type="ACTION_DENIED",
                actor_kind="gateway",
                actor_id=GATEWAY_ACTOR_ID,
                fields={"tool": tool, "outcome": {"status": "DENIED", "code": first_reason}},
                risk_level=level,
                **common,
            )
        )
    else:
        fields: dict[str, Any] = {
            "tool": tool,
            "outcome": {"status": "PENDING_APPROVAL", "code": first_reason},
        }
        if approval_map is not None:
            fields["approval"] = approval_map
        events.append(
            NewEvent(
                type="APPROVAL_REQUIRED",
                actor_kind="gateway",
                actor_id=GATEWAY_ACTOR_ID,
                fields=fields,
                # Approval events seal immediately (>= HIGH), even for a MEDIUM action.
                risk_level=max(level, "HIGH", key=("LOW", "MEDIUM", "HIGH", "CRITICAL").index),
                **common,
            )
        )
    return events
