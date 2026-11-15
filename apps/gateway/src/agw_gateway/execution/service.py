"""Action service: request envelope, idempotency and tx1 (02 §3, 08 §1, §5).

Order for ``POST /v1/actions``:

1. Parse the envelope (``extra="forbid"``). A body ``agent_id`` that differs from the
   authenticated agent -> ``SECURITY_VIOLATION`` in its own tx, then 403; nothing else runs.
2. Validate the Idempotency-Key header; compute the request fingerprint.
3. Resolve the tool, validate args, assess risk, evaluate policy: pure, before tx1, so the
   tenant chain-head lock is held briefly.
4. tx1 (one COMMIT): ``idempotency_keys`` first (a concurrent duplicate blocks on the
   uncommitted unique entry), ``actions``, ``ACTION_REQUESTED``, ``POLICY_EVALUATED``, then
   ``ACTION_DENIED`` | ``APPROVAL_REQUIRED`` | ``ACTION_AUTHORIZED`` + ``outbox_jobs(DISPATCH)``.
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

from agw_gateway.auth.models import AuthenticatedAgent
from agw_gateway.crypto.canonical import ZERO32, args_digest, json_or_profile, profile_value
from agw_gateway.db import tables as t
from agw_gateway.evidence import EvidenceWriter, NewEvent
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
from agw_gateway.logs import log
from agw_gateway.policies import Decision, EvaluationInput, evaluate, load_policy_document
from agw_gateway.policies.models import PolicyDocument
from agw_gateway.risk import classify
from agw_gateway.tools.registry import AmbiguousToolVersion, ToolRegistry
from agw_gateway.tools.spec import ToolSpec

logger = logging.getLogger("agw.execution.service")

IDEMPOTENCY_KEY_RE: Final = re.compile(r"^[A-Za-z0-9_\-:.]{1,128}$")
ACTIVE_POLICY_ID: Final = "default"
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
    ) -> None:
        self._build_commit = build_commit
        self._engine = engine
        self._registry = registry
        self._writer = writer
        self._crash = crash
        self._timeout_ms = int(tx1_statement_timeout_ms)
        self._ttl = idempotency_ttl
        self._on_authorized = on_authorized

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

        spec, decision, validated = self._evaluate(agent, req)
        try:
            result = self._tx1(agent, req, idempotency_key, fingerprint, spec, decision, validated)
        except IntegrityError as exc:
            if not _is_idempotency_conflict(exc):
                raise
            # A concurrent duplicate committed first: replay or 409.
            with self._engine.connect() as conn:
                existing = self._read_key(conn, agent.agent_id, idempotency_key)
            if existing is None:  # pragma: no cover - the winner's row is committed
                raise
            return self._replay(existing, fingerprint)

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

    def _load_policy(self) -> PolicyDocument:
        with self._engine.connect() as conn:
            document = conn.execute(
                select(t.policies.c.document)
                .where(t.policies.c.policy_id == ACTIVE_POLICY_ID)
                .order_by(t.policies.c.version.desc())
                .limit(1)
            ).scalar_one()
        return load_policy_document(document)

    def _evaluate(
        self, agent: AuthenticatedAgent, req: ActionRequest
    ) -> tuple[ToolSpec | None, Decision, BaseModel | None]:
        try:
            spec = self._registry.resolve(req.tool, req.tool_version)
        except AmbiguousToolVersion:
            raise RequestInvalid(["tool_version"]) from None
        validated = spec.validate_args(req.args) if spec is not None else None
        risk = classify(spec.meta if spec else None, req.environment)
        policy = self._load_policy()
        decision = evaluate(
            EvaluationInput(
                agent=agent,
                tool=spec.meta if spec else None,
                args_valid=validated is not None,
                args=validated.model_dump(mode="json") if validated is not None else None,
                environment=req.environment,
                policy=policy,
                risk=risk,
                now=datetime.now(UTC),
            )
        )
        return spec, decision, validated

    def _tx1(
        self,
        agent: AuthenticatedAgent,
        req: ActionRequest,
        key: str,
        fingerprint: bytes,
        spec: ToolSpec | None,
        decision: Decision,
        validated: BaseModel | None,
    ) -> SubmitResult:
        action_id = uuid7()
        status = _STATUS_FOR_EFFECT[decision.effect]
        tool_version = spec.meta.version if spec else req.tool_version
        body = _response_body(action_id, req.run_id, status, decision)
        events = _tx1_events(
            agent, req, action_id, tool_version, spec, decision, validated, self._build_commit
        )

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
                )
            )
            self._writer.append(conn, agent.tenant_id, events)
            if decision.effect == "ALLOW":
                assert validated is not None  # noqa: S101  (ALLOW implies valid args)
                conn.execute(
                    insert(t.outbox_jobs).values(
                        kind="DISPATCH",
                        tenant_id=agent.tenant_id,
                        action_id=action_id,
                        status="PENDING",
                        attempts=0,
                        args=validated.model_dump(mode="json"),
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


def _response_body(
    action_id: UUID, run_id: UUID, status: str, decision: Decision
) -> dict[str, Any]:
    return {
        "action_id": str(action_id),
        "status": status,
        "decision": {
            "effect": decision.effect,
            "policy_id": decision.policy_id,
            "policy_version": decision.policy_version,
            "matched_rule_ids": list(decision.matched_rule_ids),
            "reasons": [str(r) for r in decision.reasons],
            "risk_level": decision.risk.level.name,
        },
        "links": {
            "self": f"/v1/actions/{action_id}",
            "timeline": f"/v1/runs/{run_id}/timeline",
        },
    }


def _tx1_events(
    agent: AuthenticatedAgent,
    req: ActionRequest,
    action_id: UUID,
    tool_version: str | None,
    spec: ToolSpec | None,
    decision: Decision,
    validated: BaseModel | None,
    build_commit: str,
) -> list[NewEvent]:
    tool: dict[str, str] = {"id": req.tool}
    code: dict[str, str] = {"gw": build_commit}
    if req.agent_version is not None:
        code["agent"] = req.agent_version
    # Intent (Paper B field 1): validated args if valid, else the raw args as sorted JSON text.
    intent = (
        {"args": profile_value(validated.model_dump(mode="python"))}
        if validated is not None
        else json_or_profile(req.args, "args")
    )
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
    events = [
        NewEvent(
            type="ACTION_REQUESTED",
            actor_kind="agent",
            actor_id=str(agent.agent_id),
            fields={"tool": tool, "env": req.environment, "code": dict(code)},
            payload={"intent": intent, "context": {"sources": sources}},
            delegation_present=True,
            **common,
        ),
        NewEvent(
            type="POLICY_EVALUATED",
            actor_kind="gateway",
            actor_id=GATEWAY_ACTOR_ID,
            fields={
                "tool": tool,
                "env": req.environment,
                "risk": {
                    "level": risk.level.name,
                    "score": risk.score,
                    "rules": list(risk.mandatory_rule_ids),
                    "cv": risk.classifier_version,
                },
                "policy": {
                    "id": decision.policy_id,
                    "ver": decision.policy_version,
                    "effect": decision.effect,
                    "rules": list(decision.matched_rule_ids),
                    "reasons": [str(r) for r in decision.reasons],
                    "controls": list(decision.control_ids),
                    "ev": decision.engine_version,
                },
            },
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
                **common,
            )
        )
    else:
        events.append(
            NewEvent(
                type="APPROVAL_REQUIRED",
                actor_kind="gateway",
                actor_id=GATEWAY_ACTOR_ID,
                fields={
                    "tool": tool,
                    "outcome": {"status": "PENDING_APPROVAL", "code": first_reason},
                },
                **common,
            )
        )
    return events
