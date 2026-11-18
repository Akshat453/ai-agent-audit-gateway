"""Coding-agent integration service (C1, ADR-0034): sessions, decide, observe, end.

A coding action is an ordinary gateway action (``actions`` row + lifecycle evidence) whose
tool id is ``coding.<action_type>`` and whose effect happens on the developer's machine:

* ``decide``  -> one transaction: actions + coding_actions (+ approvals) + ACTION_REQUESTED,
  POLICY_EVALUATED and ACTION_AUTHORIZED | ACTION_DENIED | APPROVAL_REQUIRED. Nothing is
  dispatched: ``allow`` tells the agent it may run the action itself.
* ``ask``     -> a Phase 5 approval bound to the coding action digest and routed to a role.
  The agent's IDENTICAL retry consumes an APPROVED approval exactly once
  (``ApprovalService.consume_for_retry``); a different action needs a new approval.
* ``observe`` -> ACTION_COMPLETED / ACTION_FAILED reported by the agent (exit code, result
  digest, files touched). An observation of an action the gateway never authorized is a
  SECURITY_VIOLATION (CODING_UNDECIDED_ACTION).

Identity: the caller is a device key (an agent credential bound to a developer in
``coding_devices``). The developer is always taken from that binding, never from a request.
Diffs go only into the encrypted ACTION_REQUESTED payload (and not even there when the
secret scanner fired); headers carry digests; logs carry neither.
"""

from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass
from typing import Annotated, Any, Final
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, ValidationError
from sqlalchemy import Engine, func, insert, select, update

from agw_gateway.approvals.service import ApprovalConfig, ApprovalService, NewApproval
from agw_gateway.auth.models import AuthenticatedAgent
from agw_gateway.coding import CODING_TOOL_PREFIX, CODING_TOOL_VERSION
from agw_gateway.coding.digest import coding_action_digest, normalized_targets, repo_digest
from agw_gateway.coding.globs import PathInvalid, normalize_path
from agw_gateway.coding.model import AgentKind, CodingAction
from agw_gateway.coding.policy import ENGINE_VERSION, CodingDecision, CodingPolicy
from agw_gateway.db import tables as t
from agw_gateway.evidence import EvidenceWriter, NewEvent
from agw_gateway.evidence.writer import GATEWAY_ACTOR_ID, now_us
from agw_gateway.execution.errors import (
    CodingDeviceRequired,
    CodingSessionClosed,
    NotFound,
    PayloadTooLarge,
    RequestInvalid,
)
from agw_gateway.ids import uuid7
from agw_gateway.keys import KeyUnavailable
from agw_gateway.logs import log
from agw_gateway.metrics import RISK_DECISIONS
from agw_gateway.privacy.cipher import EnvelopeCipher, ops_context

logger = logging.getLogger("agw.coding")

DEVICE_SCOPE: Final = "coding:device"
ENVIRONMENT: Final = "dev"  # the developer's workstation
_STATUS: Final = {"allow": "AUTHORIZED", "deny": "DENIED", "ask": "PENDING_APPROVAL"}
_LEVEL_SCORE: Final = {"LOW": 0, "MEDIUM": 25, "HIGH": 50, "CRITICAL": 75}
_ACTIVE_APPROVAL: Final = ("PENDING", "APPROVED", "REJECTED")


# --------------------------------------------------------------------------- requests
class _Req(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class RepoIn(_Req):
    remote_url: Annotated[str, Field(max_length=2048)] | None = None
    head_sha: Annotated[str, Field(pattern=r"^[0-9a-f]{40}([0-9a-f]{24})?$")] | None = None


class IssueIn(_Req):
    number: Annotated[int, Field(gt=0, lt=2**31)]
    text_sha256: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]


class SessionStart(_Req):
    agent_kind: AgentKind
    agent_version: Annotated[str, Field(pattern=r"^[A-Za-z0-9._/+\-]{1,64}$")] | None = None
    native_session_id: Annotated[str, Field(max_length=128)] | None = None
    repo: RepoIn | None = None
    workspace_root: Annotated[str, Field(min_length=1, max_length=4096)] | None = None
    issue: IssueIn | None = None


class DecideRequest(_Req):
    session_id: UUID
    action: CodingAction
    diff: str | None = None
    correlation_id: Annotated[str, Field(max_length=128)] | None = None


class ObserveRequest(_Req):
    session_id: UUID
    action_id: UUID | None = None
    correlation_id: Annotated[str, Field(max_length=128)] | None = None
    action_type: Annotated[str, Field(max_length=32)] | None = None
    success: bool
    exit_code: Annotated[int, Field(ge=-(2**31), lt=2**31)] | None = None
    result_sha256: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")] | None = None
    files_touched: Annotated[
        list[Annotated[str, Field(max_length=4096)]], Field(max_length=256)
    ] = []
    duration_ms: Annotated[int, Field(ge=0, lt=2**40)] | None = None


def _parse[M: BaseModel](model: type[M], raw: bytes) -> M:
    try:
        return model.model_validate_json(raw)
    except ValidationError as exc:
        fields = sorted({".".join(str(p) for p in e["loc"]) or "<body>" for e in exc.errors()})
        raise RequestInvalid(fields) from None


@dataclass(frozen=True)
class Device:
    agent: AuthenticatedAgent
    developer_id: UUID
    developer: str
    label: str


# --------------------------------------------------------------------------- service
class CodingService:
    def __init__(
        self,
        *,
        engine: Engine,
        writer: EvidenceWriter,
        approvals: ApprovalService,
        approval_config: ApprovalConfig,
        policy: CodingPolicy,
        dashboard_url: str,
        build_commit: str = "unknown",
        max_diff_bytes: int = 512 * 1024,
        cipher: EnvelopeCipher | None = None,
        overlay_lookup: Any = None,
    ) -> None:
        self._cipher = cipher
        # C2 (ADR-0035): (tenant, repo digest) -> (overlay, version, digest) | None
        self._overlay_lookup = overlay_lookup
        self._overlay_cache: dict[bytes, CodingPolicy] = {}
        self._engine = engine
        self._writer = writer
        self._approvals = approvals
        self._approval_config = approval_config
        self.policy = policy
        self._dashboard = dashboard_url.rstrip("/")
        self._build_commit = build_commit
        self._max_diff = max_diff_bytes

    # ---------------------------------------------------------------- identity
    def device(self, agent: AuthenticatedAgent) -> Device:
        """The developer this device key acts for; 403 for any other credential."""
        if DEVICE_SCOPE not in agent.scopes:
            raise CodingDeviceRequired
        with self._engine.connect() as conn:
            row = conn.execute(
                select(t.coding_devices.c.developer_id, t.coding_devices.c.label, t.humans)
                .join(t.humans, t.humans.c.human_id == t.coding_devices.c.developer_id)
                .where(
                    t.coding_devices.c.agent_id == agent.agent_id,
                    t.coding_devices.c.tenant_id == agent.tenant_id,
                )
            ).one_or_none()
        if row is None or row.status != "active" or row.tenant_id != agent.tenant_id:
            raise CodingDeviceRequired
        return Device(agent, row.developer_id, row.username, row.label)

    def status(self, device: Device) -> dict[str, Any]:
        with self._engine.connect() as conn:
            open_sessions = conn.execute(
                select(func.count())
                .select_from(t.coding_sessions)
                .where(
                    t.coding_sessions.c.device_id == device.agent.agent_id,
                    t.coding_sessions.c.status == "OPEN",
                )
            ).scalar_one()
        return {
            "tenant": device.agent.tenant_id,
            "device": {"id": str(device.agent.agent_id), "label": device.label},
            "developer": device.developer,
            "open_sessions": int(open_sessions),
            "policy": {
                "id": self.policy.policy_id,
                "version": self.policy.version,
                "digest": self.policy.digest.hex(),
            },
        }

    # ---------------------------------------------------------------- sessions
    def start(self, device: Device, raw: bytes) -> dict[str, Any]:
        req = _parse(SessionStart, raw)
        session_id = uuid7()
        repo = req.repo or RepoIn()
        with self._engine.begin() as conn:
            conn.execute(
                insert(t.coding_sessions).values(
                    session_id=session_id,
                    tenant_id=device.agent.tenant_id,
                    device_id=device.agent.agent_id,
                    developer_id=device.developer_id,
                    agent_kind=req.agent_kind,
                    agent_version=req.agent_version,
                    native_session=req.native_session_id,
                    repo_digest=repo_digest(repo.remote_url) if repo.remote_url else None,
                    head_sha=repo.head_sha,
                    workspace_root=req.workspace_root,
                    issue_number=req.issue.number if req.issue else None,
                    issue_digest=bytes.fromhex(req.issue.text_sha256) if req.issue else None,
                    status="OPEN",
                )
            )
        log(
            logger,
            logging.INFO,
            "coding session started",
            tenant_id=device.agent.tenant_id,
            agent_id=device.agent.agent_id,
        )
        return {"session_id": str(session_id), "run_id": str(session_id)}

    def end(self, device: Device, session_id: UUID) -> dict[str, Any]:
        with self._engine.begin() as conn:
            session = self._session(conn, device, session_id, lock=True)
            if session.status == "OPEN":
                conn.execute(
                    update(t.coding_sessions)
                    .where(t.coding_sessions.c.session_id == session_id)
                    .values(status="ENDED", ended_at=func.now())
                )
            counts = conn.execute(
                select(t.actions.c.status, func.count())
                .join(t.coding_actions, t.coding_actions.c.action_id == t.actions.c.action_id)
                .where(t.coding_actions.c.session_id == session_id)
                .group_by(t.actions.c.status)
            ).all()
        return {
            "session_id": str(session_id),
            "status": "ENDED",
            "actions": {str(s): int(n) for s, n in counts},
        }

    def _session(self, conn: Any, device: Device, session_id: UUID, *, lock: bool = False) -> Any:
        q = select(t.coding_sessions).where(
            t.coding_sessions.c.session_id == session_id,
            t.coding_sessions.c.device_id == device.agent.agent_id,  # owner only; else 404
            t.coding_sessions.c.tenant_id == device.agent.tenant_id,
        )
        row = conn.execute(q.with_for_update() if lock else q).one_or_none()
        if row is None:
            raise NotFound
        return row

    # ---------------------------------------------------------------- decide
    def decide(self, device: Device, raw: bytes) -> dict[str, Any]:
        req = _parse(DecideRequest, raw)
        if req.diff is not None and len(req.diff.encode("utf-8")) > self._max_diff:
            raise PayloadTooLarge
        with self._engine.connect() as conn:
            session = self._session(conn, device, req.session_id)
        if session.status != "OPEN":
            raise CodingSessionClosed
        # The session's workspace root is authoritative for path normalisation.
        action = req.action
        if session.workspace_root:
            action = action.model_copy(update={"workspace_root": session.workspace_root})
        decision = self._policy_for(device.agent.tenant_id, session).evaluate(action, req.diff)
        if action.agent_kind != session.agent_kind:
            decision = _override(
                decision, "CODE-SESSION-MISMATCH", "The agent kind differs from the session's."
            )
        diff_digest = hashlib.sha256(req.diff.encode("utf-8")).digest() if req.diff else None
        digest = coding_action_digest(
            tenant=device.agent.tenant_id,
            device=device.agent.agent_id,
            developer=device.developer_id,
            session=req.session_id,
            action=action,
            diff_digest=diff_digest,
            decision=decision,
        )
        if decision.effect == "ask":
            reused = self._reuse_approval(device, req, digest, decision)
            if reused is not None:
                return reused
        return self._record(device, session, req, action, decision, digest, diff_digest)

    def _policy_for(self, tenant: str, session: Any) -> CodingPolicy:
        """The base policy, tightened (and, after admin approval, relaxed) by the repository's
        overlay. Cached by overlay digest: a new overlay version is a new cache entry."""
        if self._overlay_lookup is None or session.repo_digest is None:
            return self.policy
        found = self._overlay_lookup(tenant, bytes(session.repo_digest))
        if found is None:
            return self.policy
        overlay, version, digest = found
        cached = self._overlay_cache.get(digest)
        if cached is None:
            cached = self.policy.with_overlay(overlay, version, digest)
            self._overlay_cache[digest] = cached
        return cached

    def _reuse_approval(
        self, device: Device, req: DecideRequest, digest: bytes, decision: CodingDecision
    ) -> dict[str, Any] | None:
        """An identical earlier request: PENDING -> same ask; REJECTED -> deny; APPROVED ->
        consume once (allow). Anything else (consumed, expired, invalidated) -> None, so a
        new action and a new approval are recorded."""
        with self._engine.connect() as conn:
            prior = conn.execute(
                select(t.approvals.c.approval_id, t.approvals.c.state, t.coding_actions.c.action_id)
                .join(t.coding_actions, t.coding_actions.c.action_id == t.approvals.c.action_id)
                .where(
                    t.coding_actions.c.session_id == req.session_id,
                    t.coding_actions.c.action_digest == digest,
                    t.approvals.c.tenant_id == device.agent.tenant_id,
                    t.approvals.c.state.in_(_ACTIVE_APPROVAL),
                )
                .order_by(t.approvals.c.requested_at.desc())
                .limit(1)
            ).one_or_none()
        if prior is None:
            return None
        if prior.state == "PENDING":
            return self._view(prior.action_id, decision, digest=digest)
        if prior.state == "REJECTED":
            body = self._view(prior.action_id, decision, digest=digest)
            body.update(
                decision="deny",
                reason="A human rejected this exact action. Change the action to ask again.",
                rule_ids=[*decision.rule_ids, "APPROVAL-REJECTED"],
            )
            return body
        tool = {"id": CODING_TOOL_PREFIX + req.action.action_type, "ver": CODING_TOOL_VERSION}
        with self._engine.begin() as conn:
            ap, action_row = self._approvals.lock_for_retry(conn, prior.approval_id)
            if ap is None:  # pragma: no cover - the row was just read
                return None
            result = self._approvals.consume_for_retry(
                conn,
                ap,
                action_row,
                digest=digest,
                policy_fields=_policy_fields(tool, decision),
                authorized_fields={
                    "tool": tool,
                    "code": {"gw": self._build_commit, "adapter": "agent-executed"},
                    "args": digest,
                },
            )
            if result.result == "AUTHORIZED" and req.correlation_id:
                conn.execute(
                    update(t.coding_actions)
                    .where(t.coding_actions.c.action_id == prior.action_id)
                    .values(correlation=req.correlation_id)
                )
        if result.result != "AUTHORIZED":
            return None
        RISK_DECISIONS.labels(decision.level, "ALLOW").inc()
        body = self._view(prior.action_id, decision, digest=digest)
        body.update(decision="allow", reason="Approved by a human; this approval is now used.")
        return body

    def _record(
        self,
        device: Device,
        session: Any,
        req: DecideRequest,
        action: CodingAction,
        decision: CodingDecision,
        digest: bytes,
        diff_digest: bytes | None,
    ) -> dict[str, Any]:
        agent = device.agent
        action_id = uuid7()
        tool = {"id": CODING_TOOL_PREFIX + action.action_type, "ver": CODING_TOOL_VERSION}
        approval = (
            NewApproval.create(
                digest,
                decision.level,
                self._approval_config,
                role=decision.approval_role or self.policy.default_role,
            )
            if decision.effect == "ask"
            else None
        )
        with self._engine.begin() as conn:
            conn.execute(
                insert(t.actions).values(
                    action_id=action_id,
                    tenant_id=agent.tenant_id,
                    agent_id=agent.agent_id,
                    run_id=req.session_id,
                    tool_id=tool["id"],
                    tool_version=CODING_TOOL_VERSION,
                    environment=ENVIRONMENT,
                    status=_STATUS[decision.effect],
                    decision=decision.gateway_effect,
                    risk_level=decision.level,
                    policy_id=decision.policy_id,
                    policy_version=decision.policy_version,
                    idempotency_key=f"coding:{action_id}",
                    version=1,
                    action_digest=digest,
                    risk_policy_digest=decision.policy_digest,
                    # While approval is pending the approver must see the EXACT action (and
                    # diff): sealed under the KEK like Phase 5's request args (ADR-0029).
                    request_args_sealed=(
                        self._seal(agent.tenant_id, action_id, action, req.diff)
                        if decision.effect == "ask"
                        else None
                    ),
                )
            )
            conn.execute(
                insert(t.coding_actions).values(
                    action_id=action_id,
                    tenant_id=agent.tenant_id,
                    session_id=req.session_id,
                    action_type=action.action_type,
                    action_digest=digest,
                    correlation=req.correlation_id,
                )
            )
            approval_map = approval.insert(conn, agent.tenant_id, action_id) if approval else None
            events = self._events(
                device,
                session,
                req,
                action,
                decision,
                digest,
                diff_digest,
                tool,
                action_id,
                approval_map,
            )
            self._writer.append(conn, agent.tenant_id, events)
        RISK_DECISIONS.labels(decision.level, decision.gateway_effect).inc()
        log(
            logger,
            logging.INFO,
            "coding action evaluated",
            tenant_id=agent.tenant_id,
            agent_id=agent.agent_id,
            action_id=action_id,
            tool_id=tool["id"],
            decision=decision.gateway_effect,
        )
        body = self._view(action_id, decision, digest=digest)
        body["decision"] = decision.effect
        return body

    def _seal(self, tenant: str, action_id: UUID, action: CodingAction, diff: str | None) -> bytes:
        if self._cipher is None:
            raise KeyUnavailable("no KEK configured")
        shown: dict[str, Any] = {
            "action_type": action.action_type,
            "native_tool": action.native_tool or "",
            "targets": normalized_targets(action),
        }
        if diff is not None:
            shown["diff"] = diff
        return self._cipher.seal_json(ops_context(tenant, "request_args", action_id.bytes), shown)

    def _events(
        self,
        device: Device,
        session: Any,
        req: DecideRequest,
        action: CodingAction,
        decision: CodingDecision,
        digest: bytes,
        diff_digest: bytes | None,
        tool: dict[str, str],
        action_id: UUID,
        approval_map: dict[str, Any] | None,
    ) -> list[NewEvent]:
        agent = device.agent
        code: dict[str, Any] = {"gw": self._build_commit, "kind": action.agent_kind}
        version = action.agent_version or session.agent_version
        if version:
            code["agent"] = f"{action.agent_kind}/{version}"
        if session.repo_digest is not None:
            code["repo"] = bytes(session.repo_digest)
        head = (action.repo.head_sha if action.repo else None) or session.head_sha
        if head:
            code["head"] = head
        if diff_digest is not None:
            code["diff"] = diff_digest
        intent: dict[str, Any] = {
            "action": {
                "type": action.action_type,
                "native_tool": action.native_tool or "",
                "targets": normalized_targets(action),
            }
        }
        # The diff lives ONLY here (the encrypted payload), and not at all when the secret
        # scanner fired: storing a leaked credential, even encrypted, is not evidence we want.
        if req.diff is not None and "CONTENT-SECRET" not in decision.rule_ids:
            intent["diff"] = req.diff
        if action.repo and action.repo.remote_url:
            intent["repo_url"] = action.repo.remote_url
        context: dict[str, Any] = {"sources": [], "via": f"coding:{action.agent_kind}"}
        if session.issue_number is not None and session.issue_digest is not None:
            context["sources"] = [
                {"uri": f"issue:#{session.issue_number}", "digest": bytes(session.issue_digest)}
            ]
        payload = {
            "intent": intent,
            "context": context,
            # Paper B field 8: the developer delegated to this agent (gateway-asserted).
            "delegation": {
                "declared_by": "gateway",
                "from": {"kind": "human", "id": str(device.developer_id), "name": device.developer},
                "to": {"kind": "agent", "id": str(agent.agent_id), "agent_kind": action.agent_kind},
            },
        }
        common: dict[str, Any] = {
            "action_id": action_id,
            "run_id": req.session_id,
            "agent_id": agent.agent_id,
        }
        level = decision.level
        events = [
            NewEvent(
                type="ACTION_REQUESTED",
                actor_kind="agent",
                actor_id=str(agent.agent_id),
                fields={"tool": tool, "env": ENVIRONMENT, "code": code},
                payload=payload,
                risk_level=level,
                **common,
            ),
            NewEvent(
                type="POLICY_EVALUATED",
                actor_kind="gateway",
                actor_id=GATEWAY_ACTOR_ID,
                fields=_policy_fields(tool, decision),
                risk_level=level,
                **common,
            ),
        ]
        first_rule = decision.rule_ids[0] if decision.rule_ids else ""
        if decision.effect == "allow":
            events.append(
                NewEvent(
                    type="ACTION_AUTHORIZED",
                    actor_kind="gateway",
                    actor_id=GATEWAY_ACTOR_ID,
                    fields={
                        "tool": tool,
                        "code": {"gw": self._build_commit, "adapter": "agent-executed"},
                        "args": digest,
                    },
                    risk_level=level,
                    **common,
                )
            )
        elif decision.effect == "deny":
            code_id = _winning_rule(decision) or first_rule
            events.append(
                NewEvent(
                    type="ACTION_DENIED",
                    actor_kind="gateway",
                    actor_id=GATEWAY_ACTOR_ID,
                    fields={"tool": tool, "outcome": {"status": "DENIED", "code": code_id}},
                    risk_level=level,
                    **common,
                )
            )
        else:
            fields: dict[str, Any] = {
                "tool": tool,
                "outcome": {"status": "PENDING_APPROVAL", "code": _winning_rule(decision)},
            }
            if approval_map is not None:
                fields["approval"] = approval_map
            events.append(
                NewEvent(
                    type="APPROVAL_REQUIRED",
                    actor_kind="gateway",
                    actor_id=GATEWAY_ACTOR_ID,
                    fields=fields,
                    risk_level=max(level, "HIGH", key=("LOW", "MEDIUM", "HIGH", "CRITICAL").index),
                    **common,
                )
            )
        return events

    def _view(self, action_id: UUID, decision: CodingDecision, *, digest: bytes) -> dict[str, Any]:
        with self._engine.connect() as conn:
            row = conn.execute(
                select(t.actions.c.status, t.actions.c.run_id).where(
                    t.actions.c.action_id == action_id
                )
            ).one()
            ap = conn.execute(
                select(
                    t.approvals.c.approval_id,
                    t.approvals.c.state,
                    t.approvals.c.required_role,
                    t.approvals.c.required_approvals,
                    t.approvals.c.expires_at,
                ).where(t.approvals.c.action_id == action_id)
            ).one_or_none()
        body: dict[str, Any] = {
            "decision": decision.effect,
            "reason": decision.reason,
            "rule_ids": list(decision.rule_ids),
            "risk_level": decision.level,
            "action_id": str(action_id),
            "session_id": str(row.run_id),
            "status": row.status,
            "action_digest": digest.hex(),
            "policy": {"id": decision.policy_id, "version": decision.policy_version},
        }
        if ap is not None:
            body["approval"] = {
                "approval_id": str(ap.approval_id),
                "state": ap.state,
                "required_role": ap.required_role,
                "required_approvals": ap.required_approvals,
                "expires_at": ap.expires_at.isoformat().replace("+00:00", "Z"),
                "link": f"{self._dashboard}/approvals/{ap.approval_id}",
            }
        return body

    def action_status(self, device: Device, action_id: UUID) -> dict[str, Any]:
        """What the waiting hook polls: the action status and its approval state."""
        with self._engine.connect() as conn:
            row = conn.execute(
                select(t.actions.c.status, t.actions.c.risk_level, t.approvals.c.state)
                .join(t.coding_actions, t.coding_actions.c.action_id == t.actions.c.action_id)
                .outerjoin(t.approvals, t.approvals.c.action_id == t.actions.c.action_id)
                .where(
                    t.actions.c.action_id == action_id,
                    t.actions.c.agent_id == device.agent.agent_id,  # owner only; else 404
                )
            ).one_or_none()
        if row is None:
            raise NotFound
        return {
            "action_id": str(action_id),
            "status": row.status,
            "risk_level": row.risk_level,
            "approval_state": row.state,
        }

    # ---------------------------------------------------------------- observe
    def observe(self, device: Device, raw: bytes) -> dict[str, Any]:
        req = _parse(ObserveRequest, raw)
        agent = device.agent
        with self._engine.begin() as conn:
            session = self._session(conn, device, req.session_id)
            ca = t.coding_actions
            q = (
                select(ca.c.action_id)
                .join(t.actions, t.actions.c.action_id == ca.c.action_id)
                .where(ca.c.session_id == req.session_id)
            )
            if req.action_id is not None:
                q = q.where(ca.c.action_id == req.action_id)
            elif req.correlation_id is not None:
                q = q.where(ca.c.correlation == req.correlation_id, ca.c.observed_at.is_(None))
            else:
                q = q.where(ca.c.action_id.is_(None))  # nothing to correlate with
            # Several requests can share a correlation id (an agent retrying the same tool
            # call): the AUTHORIZED one is what ran; otherwise the latest explains the report.
            found = conn.execute(
                q.order_by(
                    (t.actions.c.status == "AUTHORIZED").desc(), ca.c.created_at.desc()
                ).limit(1)
            ).scalar_one_or_none()
            row = (
                conn.execute(
                    select(t.actions).where(t.actions.c.action_id == found).with_for_update()
                ).one()
                if found is not None
                else None
            )
            if row is None or row.status != "AUTHORIZED":
                if row is not None and row.status in ("COMPLETED", "FAILED"):
                    return {"recorded": "duplicate", "action_id": str(row.action_id)}
                # The agent ran something the gateway never authorized (no pre-action hook,
                # or it ignored a deny / a pending approval): an incident, sealed at once.
                claimed = (req.action_type or "unknown")[:32]
                if row is not None:
                    claimed = f"{claimed}:{row.status}"[:128]
                self._writer.append(
                    conn,
                    agent.tenant_id,
                    [
                        NewEvent(
                            type="SECURITY_VIOLATION",
                            actor_kind="agent",
                            actor_id=str(agent.agent_id),
                            run_id=req.session_id,
                            agent_id=agent.agent_id,
                            fields={
                                "violation": {"kind": "CODING_UNDECIDED_ACTION", "claimed": claimed}
                            },
                            risk_level="HIGH",
                        )
                    ],
                )
                log(
                    logger,
                    logging.WARNING,
                    "coding action observed without authorization",
                    tenant_id=agent.tenant_id,
                    agent_id=agent.agent_id,
                    error_code="CODING_UNDECIDED_ACTION",
                )
                return {"recorded": "violation"}
            files: list[str] = []
            for f in req.files_touched:
                try:
                    files.append(normalize_path(f, session.workspace_root))
                except PathInvalid:
                    continue
            status = "COMPLETED" if req.success else "FAILED"
            code = "OK" if req.success else "AGENT_REPORTED_FAILURE"
            if req.exit_code is not None:
                code = f"EXIT_{req.exit_code}"
            effects: dict[str, Any] = {"files_touched": files}
            if req.exit_code is not None:
                effects["exit_code"] = req.exit_code
            if req.result_sha256 is not None:
                effects["result_digest"] = bytes.fromhex(req.result_sha256)
            if req.duration_ms is not None:
                effects["duration_ms"] = req.duration_ms
            self._writer.append(
                conn,
                agent.tenant_id,
                [
                    NewEvent(
                        type="ACTION_COMPLETED" if req.success else "ACTION_FAILED",
                        actor_kind="agent",
                        actor_id=str(agent.agent_id),
                        action_id=row.action_id,
                        run_id=row.run_id,
                        agent_id=agent.agent_id,
                        fields={"outcome": {"status": status, "code": code}, "obs": now_us()},
                        payload={"effects": effects},
                        risk_level=row.risk_level,
                    )
                ],
            )
            conn.execute(
                update(t.actions)
                .where(t.actions.c.action_id == row.action_id)
                .values(status=status, updated_at=func.now(), version=t.actions.c.version + 1)
            )
            conn.execute(
                update(ca).where(ca.c.action_id == row.action_id).values(observed_at=func.now())
            )
        return {"recorded": status, "action_id": str(row.action_id)}


# --------------------------------------------------------------------------- helpers
def _winning_rule(decision: CodingDecision) -> str:
    return decision.rule_ids[0] if decision.rule_ids else ""


def _override(decision: CodingDecision, rule: str, reason: str) -> CodingDecision:
    return CodingDecision(
        effect="deny",
        level=max(decision.level, "HIGH", key=("LOW", "MEDIUM", "HIGH", "CRITICAL").index),
        rule_ids=(rule, *decision.rule_ids),
        reason=reason,
        approval_role=None,
        policy_id=decision.policy_id,
        policy_version=decision.policy_version,
        policy_digest=decision.policy_digest,
    )


def _policy_fields(tool: dict[str, str], decision: CodingDecision) -> dict[str, Any]:
    """POLICY_EVALUATED header for a coding decision: rule ids only, never reason text (a
    reason may name a path; headers stay structural)."""
    rules = list(decision.rule_ids)
    return {
        "tool": tool,
        "env": ENVIRONMENT,
        "risk": {
            "level": decision.level,
            "score": _LEVEL_SCORE[decision.level],
            "rules": rules,
            "cv": ENGINE_VERSION,
            "pid": decision.policy_id,
            "pver": decision.policy_version,
            "pd": decision.policy_digest,
        },
        "policy": {
            "id": decision.policy_id,
            "ver": decision.policy_version,
            "effect": decision.gateway_effect,
            "rules": rules,
            "reasons": [r for r in rules if r != "PATH-READ"][:8],
            "controls": ["HITL-APPROVAL"] if decision.effect == "ask" else [],
            "ev": ENGINE_VERSION,
        },
    }
