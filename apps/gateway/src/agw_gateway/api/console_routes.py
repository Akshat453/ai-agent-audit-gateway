"""Read-only endpoints for the redesigned dashboard (Phase 9.5, ADR-0033). HUMAN sessions only,
tenant-scoped, no payloads, no tool args or results: the same disclosure surface as the Phase 9
dashboard API (ADR-0031 §2), shaped for the new views.

    GET /v1/dashboard/activity            decisions over time, period totals, evidence pipeline
    GET /v1/dashboard/approvals           approvals with agent + delegation, sortable, paginated
    GET /v1/dashboard/actions/{id}        action metadata + its evidence chain (hash links)
    GET /v1/dashboard/events/{id}         one event header + epoch + anchor + link checks
    GET /v1/dashboard/session             this session: env, roles, step-up time remaining
    GET /v1/dashboard/health              gateway / database / worker / anchoring / monitor
    GET /v1/dashboard/search?q=           command palette: UUID or hash-prefix lookup

Nothing here writes. ``hash_ok`` / ``link_ok`` / ``stored_copy_ok`` are convenience
recomputations for the UI (shown values are decoded from the sealed bytes, ADR-0038); the
independent verifier (agw-verify with pinned trust roots) stays authoritative.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated, Any, Literal
from uuid import UUID

from fastapi import APIRouter, Query, Request
from pydantic import BaseModel, ConfigDict
from sqlalchemy import Connection, and_, case, func, select, text

from agw_gateway.api import coding_view
from agw_gateway.api.approval_routes import Human
from agw_gateway.api.dashboard_routes import _anchor_view, _iso, _state
from agw_gateway.crypto.canonical import event_hash
from agw_gateway.db import tables as t
from agw_gateway.evidence.bundle import epoch_record
from agw_gateway.evidence.sealed import header_for_display, stored_copy_ok
from agw_gateway.execution.errors import Forbidden, NotFound
from agw_gateway.policies import descriptions

router = APIRouter(prefix="/v1")
ZERO = "0" * 64
RANGES: dict[str, tuple[str, str]] = {
    "24h": ("24 hours", "1 hour"),
    "7d": ("7 days", "6 hours"),
    "30d": ("30 days", "1 day"),
}
RISK_RANK = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}


class _Out(BaseModel):
    model_config = ConfigDict(extra="forbid")


# --------------------------------------------------------------------------- activity
class ActivityBucket(_Out):
    start: str
    ALLOW: int
    DENY: int
    REQUIRE_APPROVAL: int
    total: int


class PeriodTotals(_Out):
    actions: int
    denied: int


class PipelineStage(_Out):
    count: int
    oldest_waiting_seconds: float | None  # oldest item that has NOT reached the next stage


class Pipeline(_Out):
    recorded: PipelineStage
    sealed: PipelineStage
    anchored: PipelineStage
    finalized: PipelineStage
    anchoring_configured: bool


class Activity(_Out):
    range: str
    bucket_seconds: int
    buckets: list[ActivityBucket]
    current: PeriodTotals
    previous: PeriodTotals
    pipeline: Pipeline


def _pipeline(conn: Connection, tenant: str) -> Pipeline:
    ev, ep, an = t.evidence_events, t.epochs, t.anchors
    recorded = conn.execute(select(func.count()).where(ev.c.tenant_id == tenant)).scalar_one()
    sealed_up_to = conn.execute(
        select(func.coalesce(func.max(ep.c.last_seq), -1)).where(ep.c.tenant_id == tenant)
    ).scalar_one()
    unsealed_age = conn.execute(
        select(func.extract("epoch", func.now() - func.min(ev.c.occurred_at))).where(
            ev.c.tenant_id == tenant, ev.c.seq > sealed_up_to
        )
    ).scalar_one()
    joined = ep.outerjoin(
        an, and_(an.c.tenant_id == ep.c.tenant_id, an.c.epoch_no == ep.c.epoch_no)
    )

    def stage(*statuses: str) -> tuple[int, float | None]:
        """Events in epochs whose anchor reached one of ``statuses`` and the age of the oldest
        epoch that has NOT (sealed_at of the oldest laggard)."""
        reached = an.c.status.in_(statuses)
        n, age = conn.execute(
            select(
                func.coalesce(func.sum(case((reached, ep.c.tree_size), else_=0)), 0),
                func.extract(
                    "epoch",
                    func.now()
                    - func.min(case((func.coalesce(reached, False), None), else_=ep.c.sealed_at)),
                ),
            )
            .select_from(joined)
            .where(ep.c.tenant_id == tenant)
        ).one()
        return int(n), float(age) if age is not None else None

    sealed_n = int(sealed_up_to) + 1 if sealed_up_to >= 0 else 0
    anchored_n, sealed_wait = stage("INCLUDED", "FINALIZED")
    finalized_n, anchored_wait = stage("FINALIZED")
    anchoring = bool(
        conn.execute(
            select(func.count())
            .select_from(t.anchor_recorders)
            .where(t.anchor_recorders.c.tenant_id == tenant)
        ).scalar_one()
    )
    return Pipeline(
        recorded=PipelineStage(
            count=int(recorded),
            oldest_waiting_seconds=float(unsealed_age) if unsealed_age is not None else None,
        ),
        sealed=PipelineStage(
            count=sealed_n, oldest_waiting_seconds=sealed_wait if anchoring else None
        ),
        anchored=PipelineStage(
            count=anchored_n, oldest_waiting_seconds=anchored_wait if anchoring else None
        ),
        finalized=PipelineStage(count=finalized_n, oldest_waiting_seconds=None),
        anchoring_configured=anchoring,
    )


@router.get("/dashboard/activity", response_model=Activity)
def activity(
    request: Request,
    human: Human,
    range_: Annotated[Literal["24h", "7d", "30d"], Query(alias="range")] = "24h",
    repo_id: UUID | None = None,  # ADR-0040
) -> Activity:
    span, step = RANGES[range_]
    tenant = human.tenant_id
    extra = {"repo": str(repo_id) if repo_id else None}
    with _state(request).engine.connect() as conn:
        rows = conn.execute(
            text(
                "WITH b AS (SELECT generate_series("
                " date_bin(CAST(:step AS interval), now() - CAST(:span AS interval)"
                "   + CAST(:step AS interval), timestamptz '2000-01-01'),"
                " date_bin(CAST(:step AS interval), now(), timestamptz '2000-01-01'),"
                " CAST(:step AS interval)) AS start) "
                "SELECT b.start,"
                " count(a.action_id) FILTER (WHERE a.decision = 'ALLOW'),"
                " count(a.action_id) FILTER (WHERE a.decision = 'DENY'),"
                " count(a.action_id) FILTER (WHERE a.decision = 'REQUIRE_APPROVAL'),"
                " count(a.action_id),"
                " extract(epoch FROM CAST(:step AS interval)) "
                "FROM b LEFT JOIN actions a ON a.tenant_id = :t"
                " AND a.created_at >= b.start AND a.created_at < b.start + CAST(:step AS interval)"
                " AND (CAST(:repo AS uuid) IS NULL OR a.run_id IN"
                " (SELECT s.session_id FROM coding_sessions s JOIN repos r"
                " ON r.tenant_id = s.tenant_id AND r.remote_digest = s.repo_digest"
                " WHERE r.repo_id = CAST(:repo AS uuid) AND s.tenant_id = :t))"
                " GROUP BY b.start ORDER BY b.start"
            ),
            {"t": tenant, "span": span, "step": step, **extra},
        ).all()
        totals = conn.execute(
            text(
                "SELECT"
                " count(*) FILTER (WHERE created_at > now() - CAST(:span AS interval)),"
                " count(*) FILTER (WHERE created_at > now() - CAST(:span AS interval)"
                "   AND decision = 'DENY'),"
                " count(*) FILTER (WHERE created_at <= now() - CAST(:span AS interval)"
                "   AND created_at > now() - 2 * CAST(:span AS interval)),"
                " count(*) FILTER (WHERE created_at <= now() - CAST(:span AS interval)"
                "   AND created_at > now() - 2 * CAST(:span AS interval) AND decision = 'DENY') "
                "FROM actions WHERE tenant_id = :t"
                " AND (CAST(:repo AS uuid) IS NULL OR run_id IN"
                " (SELECT s.session_id FROM coding_sessions s JOIN repos r"
                " ON r.tenant_id = s.tenant_id AND r.remote_digest = s.repo_digest"
                " WHERE r.repo_id = CAST(:repo AS uuid) AND s.tenant_id = :t))"
            ),
            {"t": tenant, "span": span, **extra},
        ).one()
        pipeline = _pipeline(conn, tenant)
    return Activity(
        range=range_,
        bucket_seconds=int(rows[0][5]) if rows else 0,
        buckets=[
            ActivityBucket(
                start=_iso(r[0]) or "", ALLOW=r[1], DENY=r[2], REQUIRE_APPROVAL=r[3], total=r[4]
            )
            for r in rows
        ],
        current=PeriodTotals(actions=int(totals[0]), denied=int(totals[1])),
        previous=PeriodTotals(actions=int(totals[2]), denied=int(totals[3])),
        pipeline=pipeline,
    )


# --------------------------------------------------------------------------- approvals
class Ref(_Out):
    id: str
    name: str


class ToolRef(_Out):
    id: str
    version: str | None


class ApprovalRow(_Out):
    approval_id: str
    action_id: str
    run_id: str
    state: str
    tool: ToolRef
    environment: str
    risk_level: str
    agent: Ref
    delegation_depth: int | None
    delegated_by: str | None
    required_approvals: int
    decisions: int
    requested_at: str | None
    expires_at: str | None
    # ADR-0039: coding actions only: what it targets (redacted), e.g. a path or a command.
    action_type: str | None = None
    target: str | None = None
    agent_kind: str | None = None
    issue_number: int | None = None


class ApprovalPage(_Out):
    total: int
    rows: list[ApprovalRow]


@router.get("/dashboard/approvals", response_model=ApprovalPage)
def approvals(
    request: Request,
    human: Human,
    state: Annotated[
        Literal["PENDING", "APPROVED", "REJECTED", "EXPIRED", "CONSUMED", "INVALIDATED"] | None,
        Query(),
    ] = None,
    risk: Annotated[Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"] | None, Query()] = None,
    tool: Annotated[str | None, Query(max_length=64)] = None,
    sort: Annotated[Literal["expires_at", "requested_at", "risk", "tool"], Query()] = "expires_at",
    order: Annotated[Literal["asc", "desc"], Query()] = "asc",
    limit: Annotated[int, Query(ge=1, le=200)] = 25,
    offset: Annotated[int, Query(ge=0, le=100_000)] = 0,
    repo_id: UUID | None = None,  # ADR-0040: only this repository's approvals
) -> ApprovalPage:
    # Same viewers as GET /v1/approvals (ApprovalService._require_viewer).
    if not (human.roles & {"approver", "auditor", "admin"}):
        raise Forbidden
    ap, ac, ag, d = t.approvals, t.actions, t.agents, t.delegations
    issuer = ag.alias("issuer")
    votes = (
        select(func.count())
        .where(t.approval_decisions.c.approval_id == ap.c.approval_id)
        .scalar_subquery()
    )
    conds = [ap.c.tenant_id == human.tenant_id]
    if state is not None:
        conds.append(ap.c.state == state)
    if risk is not None:
        conds.append(ac.c.risk_level == risk)
    if tool is not None:
        conds.append(ac.c.tool_id == tool)
    if repo_id is not None:
        conds.append(ac.c.run_id.in_(coding_view.repo_runs(human.tenant_id, repo_id)))
    rank = case(RISK_RANK, value=ac.c.risk_level, else_=-1)
    key = {
        "expires_at": ap.c.expires_at,
        "requested_at": ap.c.requested_at,
        "risk": rank,
        "tool": ac.c.tool_id,
    }[sort]
    base = (
        ap.join(ac, ac.c.action_id == ap.c.action_id)
        .join(ag, ag.c.agent_id == ac.c.agent_id)
        .outerjoin(d, d.c.delegation_id == ac.c.delegation_id)
        .outerjoin(issuer, issuer.c.agent_id == d.c.issuer_agent_id)
    )
    with _state(request).engine.connect() as conn:
        total = conn.execute(select(func.count()).select_from(base).where(*conds)).scalar_one()
        rows = conn.execute(
            select(
                ap.c.approval_id,
                ap.c.action_id,
                ap.c.state,
                ap.c.required_approvals,
                ap.c.requested_at,
                ap.c.expires_at,
                ac.c.run_id,
                ac.c.tool_id,
                ac.c.tool_version,
                ac.c.environment,
                ac.c.risk_level,
                ac.c.agent_id,
                ac.c.delegation_depth,
                ag.c.name.label("agent_name"),
                issuer.c.name.label("issuer_name"),
                votes.label("votes"),
            )
            .select_from(base)
            .where(*conds)
            .order_by(key.asc() if order == "asc" else key.desc(), ap.c.approval_id)
            .limit(limit)
            .offset(offset)
        ).all()
        coding = coding_view.actions(
            conn, _state(request), human.tenant_id, [r.action_id for r in rows]
        )
        sessions = coding_view.sessions(conn, human.tenant_id, [r.run_id for r in rows])
    return ApprovalPage(
        total=int(total),
        rows=[
            ApprovalRow(
                approval_id=str(r.approval_id),
                action_id=str(r.action_id),
                run_id=str(r.run_id),
                state=r.state,
                tool=ToolRef(id=r.tool_id, version=r.tool_version),
                environment=r.environment,
                risk_level=r.risk_level,
                agent=Ref(id=str(r.agent_id), name=r.agent_name),
                delegation_depth=r.delegation_depth,
                delegated_by=r.issuer_name,
                required_approvals=int(r.required_approvals),
                decisions=int(r.votes),
                requested_at=_iso(r.requested_at),
                expires_at=_iso(r.expires_at),
                action_type=coding[r.action_id].action_type if r.action_id in coding else None,
                target=coding_view.short_target(coding.get(r.action_id)),
                agent_kind=sessions[r.run_id].agent_kind if r.run_id in sessions else None,
                issue_number=sessions[r.run_id].issue_number if r.run_id in sessions else None,
            )
            for r in rows
        ],
    )


# --------------------------------------------------------------------------- evidence nodes
class AnchorRef(_Out):
    status: str
    tx_hash: str | None
    block_number: int | None
    chain_id: int | None
    explorer_url: str | None


class EvidenceNode(_Out):
    seq: int
    event_id: str
    type: str
    occurred_at: str | None
    risk_level: str | None
    event_hash: str
    prev_hash: str
    hash_ok: bool  # sha256(TAG(AGW/event/v1) || stored canonical bytes) == stored event_hash
    link_ok: bool | None  # prev_hash == stored hash of seq-1 (None: seq-1 not visible)
    # the readable copy (body) and the indexed columns equal the sealed record (ADR-0038)
    stored_copy_ok: bool
    epoch_no: int | None
    anchor: AnchorRef | None
    decision: str | None
    status: str | None
    reasons: list[str]
    rules: list[str] = []  # ADR-0039: matched rule ids (from the sealed record)


def _nodes(conn: Connection, request: Request, tenant: str, rows: list[Any]) -> list[EvidenceNode]:
    """Evidence nodes for ``rows`` (evidence_events rows incl. canonical_bytes), with the hash
    of each predecessor fetched in one query so every link can be checked."""
    ev = t.evidence_events
    seqs = sorted({int(r.seq) for r in rows})
    prev_hashes = {
        int(s): bytes(h).hex()
        for s, h in conn.execute(
            select(ev.c.seq, ev.c.event_hash).where(
                ev.c.tenant_id == tenant, ev.c.seq.in_([s - 1 for s in seqs if s > 0] or [-1])
            )
        ).all()
    }
    epochs = conn.execute(
        select(t.epochs.c.epoch_no, t.epochs.c.first_seq, t.epochs.c.last_seq).where(
            t.epochs.c.tenant_id == tenant,
            t.epochs.c.last_seq >= (seqs[0] if seqs else 0),
            t.epochs.c.first_seq <= (seqs[-1] if seqs else -1),
        )
    ).all()
    epoch_of = {
        s: next((int(e.epoch_no) for e in epochs if e.first_seq <= s <= e.last_seq), None)
        for s in seqs
    }
    anchors = {
        int(a.epoch_no): a
        for a in conn.execute(
            select(t.anchors).where(
                t.anchors.c.tenant_id == tenant,
                t.anchors.c.epoch_no.in_([int(e.epoch_no) for e in epochs] or [-1]),
            )
        ).all()
    }
    state = _state(request)
    out = []
    for r in rows:
        seq = int(r.seq)
        canonical = bytes(r.canonical_bytes)
        body = header_for_display(canonical)  # shown values come from the SEALED record
        prev = str(body.get("prev") or "")
        expected = ZERO if seq == 0 else prev_hashes.get(seq - 1)
        epoch_no = epoch_of.get(seq)
        view = _anchor_view(state, anchors.get(epoch_no)) if epoch_no is not None else None
        policy, outcome = body.get("policy") or {}, body.get("outcome") or {}
        out.append(
            EvidenceNode(
                seq=seq,
                event_id=str(r.event_id),
                type=r.event_type,
                occurred_at=_iso(r.occurred_at),
                risk_level=r.risk_level,
                event_hash=bytes(r.event_hash).hex(),
                prev_hash=prev,
                hash_ok=event_hash(bytes(r.canonical_bytes)) == bytes(r.event_hash),
                link_ok=None if expected is None else prev == expected,
                stored_copy_ok=stored_copy_ok(
                    canonical,
                    r.body,
                    tenant_id=tenant,
                    seq=seq,
                    event_type=r.event_type,
                    action_id=r.action_id,
                    run_id=r.run_id,
                ),
                epoch_no=epoch_no,
                anchor=AnchorRef(**view) if view is not None else None,
                decision=policy.get("effect"),
                status=outcome.get("status"),
                reasons=[str(x) for x in policy.get("reasons", [])],
                rules=[str(x) for x in policy.get("rules", [])],
            )
        )
    return out


# --------------------------------------------------------------------------- action detail
def _us_iso(us: int | None) -> str | None:
    if us is None:
        return None
    return datetime.fromtimestamp(us / 1_000_000, tz=UTC).isoformat().replace("+00:00", "Z")


class DecisionRef(_Out):
    approver: str  # username
    decision: str  # APPROVED | REJECTED
    decided_at: str | None


class ApprovalRef(_Out):
    approval_id: str
    state: str
    required_approvals: int
    requested_at: str | None
    expires_at: str | None
    decisions: list[DecisionRef] = []  # ADR-0039: who decided, and when


class DelegationRef(_Out):
    delegation_id: str
    depth: int | None
    issuer: str | None


class PolicyRef(_Out):
    id: str
    version: int


class ActionDetail(_Out):
    action_id: str
    run_id: str
    status: str
    decision: str
    risk_level: str
    tool: ToolRef
    environment: str
    agent: Ref
    policy: PolicyRef
    delegation: DelegationRef | None
    error_code: str | None
    created_at: str | None
    updated_at: str | None
    approvals: list[ApprovalRef]
    events: list[EvidenceNode]
    # ADR-0039: coding actions only (None otherwise): target, diff counts, session context.
    coding: coding_view.CodingView | None = None
    session: coding_view.CodingSession | None = None


@router.get("/dashboard/actions/{action_id}", response_model=ActionDetail)
def action_detail(request: Request, human: Human, action_id: UUID) -> ActionDetail:
    tenant = human.tenant_id
    ac, ev, d = t.actions, t.evidence_events, t.delegations
    with _state(request).engine.connect() as conn:
        a = conn.execute(
            select(ac, t.agents.c.name.label("agent_name"))
            .join(t.agents, t.agents.c.agent_id == ac.c.agent_id)
            .where(ac.c.action_id == action_id, ac.c.tenant_id == tenant)
        ).one_or_none()
        if a is None:
            raise NotFound
        deleg = None
        if a.delegation_id is not None:
            dr = conn.execute(
                select(d.c.delegation_id, d.c.depth, t.agents.c.name)
                .outerjoin(t.agents, t.agents.c.agent_id == d.c.issuer_agent_id)
                .where(d.c.delegation_id == a.delegation_id, d.c.tenant_id == tenant)
            ).one_or_none()
            if dr is not None:
                deleg = DelegationRef(
                    delegation_id=str(dr.delegation_id), depth=int(dr.depth), issuer=dr.name
                )
        aps = conn.execute(
            select(t.approvals)
            .where(t.approvals.c.action_id == action_id, t.approvals.c.tenant_id == tenant)
            .order_by(t.approvals.c.requested_at)
        ).all()
        rows = conn.execute(
            select(ev)
            .where(ev.c.tenant_id == tenant, ev.c.action_id == action_id)
            .order_by(ev.c.seq)
        ).all()
        nodes = _nodes(conn, request, tenant, list(rows))
        decided: dict[Any, list[DecisionRef]] = {}
        dec = t.approval_decisions
        for r in conn.execute(
            select(dec.c.approval_id, dec.c.decision, dec.c.decided_at_us, t.humans.c.username)
            .join(t.humans, t.humans.c.human_id == dec.c.approver_id)
            .where(dec.c.approval_id.in_([p.approval_id for p in aps] or [None]))
            .order_by(dec.c.decided_at_us)
        ):
            decided.setdefault(r.approval_id, []).append(
                DecisionRef(
                    approver=r.username,
                    decision=r.decision,
                    decided_at=_us_iso(r.decided_at_us),
                )
            )
        coding = coding_view.actions(conn, _state(request), tenant, [a.action_id]).get(a.action_id)
        session = coding_view.sessions(conn, tenant, [a.run_id]).get(a.run_id) if coding else None
    return ActionDetail(
        action_id=str(a.action_id),
        run_id=str(a.run_id),
        status=a.status,
        decision=a.decision,
        risk_level=a.risk_level,
        tool=ToolRef(id=a.tool_id, version=a.tool_version),
        environment=a.environment,
        agent=Ref(id=str(a.agent_id), name=a.agent_name),
        policy=PolicyRef(id=a.policy_id, version=int(a.policy_version)),
        delegation=deleg,
        error_code=a.error_code,
        created_at=_iso(a.created_at),
        updated_at=_iso(a.updated_at),
        approvals=[
            ApprovalRef(
                approval_id=str(p.approval_id),
                state=p.state,
                required_approvals=int(p.required_approvals),
                requested_at=_iso(p.requested_at),
                expires_at=_iso(p.expires_at),
                decisions=decided.get(p.approval_id, []),
            )
            for p in aps
        ],
        events=nodes,
        coding=coding,
        session=session,
    )


# --------------------------------------------------------------------------- event detail
class EventDetail(_Out):
    node: EvidenceNode
    tenant: str
    action_id: str | None
    run_id: str | None
    header: dict[str, Any]  # the JSON projection of the canonical header (no payload)
    canonical_header: str  # hex of the exact hashed bytes (public structural header)
    epoch: dict[str, Any] | None


@router.get("/dashboard/events/{event_id}", response_model=EventDetail)
def event_detail(request: Request, human: Human, event_id: UUID) -> EventDetail:
    tenant = human.tenant_id
    ev = t.evidence_events
    with _state(request).engine.connect() as conn:
        row = conn.execute(
            select(ev).where(ev.c.event_id == event_id, ev.c.tenant_id == tenant)
        ).one_or_none()
        if row is None:
            raise NotFound
        node = _nodes(conn, request, tenant, [row])[0]
        epoch = (
            conn.execute(
                select(t.epochs).where(
                    t.epochs.c.tenant_id == tenant, t.epochs.c.epoch_no == node.epoch_no
                )
            ).one()
            if node.epoch_no is not None
            else None
        )
    return EventDetail(
        node=node,
        tenant=tenant,
        action_id=str(row.action_id) if row.action_id else None,
        run_id=str(row.run_id) if row.run_id else None,
        header=header_for_display(bytes(row.canonical_bytes)),
        canonical_header=bytes(row.canonical_bytes).hex(),
        epoch=epoch_record(epoch) if epoch is not None else None,
    )


# --------------------------------------------------------------------------- session + health
class SessionInfo(_Out):
    username: str
    tenant: str
    roles: list[str]
    env: str
    step_up_window_seconds: int
    step_up_remaining_seconds: int | None  # None: this session never stepped up / expired


@router.get("/dashboard/session", response_model=SessionInfo)
def session_info(request: Request, human: Human) -> SessionInfo:
    s = _state(request).settings
    age = human.stepped_up_age_seconds
    left = None if age is None else int(s.step_up_window_seconds - age)
    return SessionInfo(
        username=human.username,
        tenant=human.tenant_id,
        roles=sorted(human.roles),
        env=s.env,
        step_up_window_seconds=s.step_up_window_seconds,
        step_up_remaining_seconds=left if left is not None and left > 0 else None,
    )


class HealthChip(_Out):
    name: Literal["gateway", "database", "worker", "anchoring", "monitor"]
    status: Literal["ok", "degraded", "down", "off"]
    detail: str
    at: str | None


# A queued dispatch/seal job older than this, or an anchor stuck/failed, is "degraded".
STALE_JOB_SECONDS = 60
STALE_MONITOR_SECONDS = 24 * 3600


@router.get("/dashboard/health", response_model=list[HealthChip])
def health(request: Request, human: Human) -> list[HealthChip]:
    tenant = human.tenant_id
    ob, an, r = t.outbox_jobs, t.anchors, t.monitor_reports
    with _state(request).engine.connect() as conn:
        queued, oldest = conn.execute(
            select(
                func.count(), func.extract("epoch", func.now() - func.min(ob.c.created_at))
            ).where(ob.c.tenant_id == tenant, ob.c.status.in_(("PENDING", "CLAIMED")))
        ).one()
        anchoring = conn.execute(
            select(func.count())
            .select_from(t.anchor_recorders)
            .where(t.anchor_recorders.c.tenant_id == tenant)
        ).scalar_one()
        failed, last_anchor = conn.execute(
            select(
                func.count().filter(an.c.status == "FAILED"),
                func.max(func.coalesce(an.c.finalized_at, an.c.included_at, an.c.submitted_at)),
            ).where(an.c.tenant_id == tenant)
        ).one()
        mon = conn.execute(
            select(
                r.c.result,
                r.c.created_at,
                func.extract("epoch", func.now() - r.c.created_at).label("age"),
            )
            .where(r.c.tenant_id == tenant)
            .order_by(r.c.created_at.desc())
            .limit(1)
        ).one_or_none()
    stale = queued and oldest is not None and float(oldest) > STALE_JOB_SECONDS
    chips = [
        HealthChip(name="gateway", status="ok", detail="answering", at=None),
        HealthChip(name="database", status="ok", detail="reachable", at=None),
        HealthChip(
            name="worker",
            status="degraded" if stale else "ok",
            detail=f"{int(queued)} queued job(s)"
            + (f", oldest {int(float(oldest))} s" if queued and oldest is not None else ""),
            at=None,
        ),
    ]
    if not anchoring:
        chips.append(HealthChip(name="anchoring", status="off", detail="not configured", at=None))
    else:
        chips.append(
            HealthChip(
                name="anchoring",
                status="degraded" if failed else "ok",
                detail=f"{int(failed)} failed anchor(s)" if failed else "anchors progressing",
                at=_iso(last_anchor),
            )
        )
    if mon is None:
        chips.append(HealthChip(name="monitor", status="off", detail="no report yet", at=None))
    else:
        bad = mon.result != "VERIFIED" or float(mon.age) > STALE_MONITOR_SECONDS
        chips.append(
            HealthChip(
                name="monitor",
                status="degraded" if bad else "ok",
                detail=f"last result {mon.result}",
                at=_iso(mon.created_at),
            )
        )
    return chips


# --------------------------------------------------------------------------- search
class SearchHit(_Out):
    kind: Literal["action", "run", "event", "approval", "epoch"]
    id: str
    label: str
    href: str


HEX = "0123456789abcdef"


def _event_label(seq: int, kind: str) -> str:
    return f"Event #{seq} · {kind}"


@router.get("/dashboard/search", response_model=list[SearchHit])
def search(
    request: Request, human: Human, q: Annotated[str, Query(min_length=1, max_length=80)]
) -> list[SearchHit]:
    """Command-palette lookup: an exact UUID (action / run / event / approval) or a hex prefix of
    an event hash or epoch root (>= 8 hex chars, optional 0x). Tenant-scoped, at most 10 hits."""
    tenant = human.tenant_id
    term = q.strip().lower()
    hits: list[SearchHit] = []
    with _state(request).engine.connect() as conn:
        try:
            uid = UUID(term)
        except ValueError:
            uid = None
        if uid is not None:
            a = conn.execute(
                select(t.actions.c.tool_id).where(
                    t.actions.c.action_id == uid, t.actions.c.tenant_id == tenant
                )
            ).scalar_one_or_none()
            if a is not None:
                hits.append(
                    SearchHit(
                        kind="action", id=str(uid), label=f"Action · {a}", href=f"/actions/{uid}"
                    )
                )
            e = conn.execute(
                select(t.evidence_events.c.event_type, t.evidence_events.c.seq).where(
                    t.evidence_events.c.event_id == uid, t.evidence_events.c.tenant_id == tenant
                )
            ).one_or_none()
            if e is not None:
                hits.append(
                    SearchHit(
                        kind="event",
                        id=str(uid),
                        label=_event_label(e.seq, e.event_type),
                        href=f"/events/{uid}",
                    )
                )
            n_run = conn.execute(
                select(func.count()).where(
                    t.actions.c.run_id == uid, t.actions.c.tenant_id == tenant
                )
            ).scalar_one()
            if n_run:
                hits.append(
                    SearchHit(
                        kind="run",
                        id=str(uid),
                        label=f"Run · {n_run} action(s)",
                        href=f"/runs/{uid}",
                    )
                )
            p = conn.execute(
                select(t.approvals.c.state).where(
                    t.approvals.c.approval_id == uid, t.approvals.c.tenant_id == tenant
                )
            ).scalar_one_or_none()
            if p is not None:
                hits.append(
                    SearchHit(
                        kind="approval",
                        id=str(uid),
                        label=f"Approval · {p}",
                        href=f"/approvals/{uid}",
                    )
                )
            return hits
        prefix = term[2:] if term.startswith("0x") else term
        if len(prefix) < 8 or any(c not in HEX for c in prefix):
            return hits
        like = prefix + "%"
        ev = t.evidence_events
        for row in conn.execute(
            select(ev.c.event_id, ev.c.seq, ev.c.event_type)
            .where(ev.c.tenant_id == tenant, func.encode(ev.c.event_hash, "hex").like(like))
            .order_by(ev.c.seq.desc())
            .limit(10)
        ).all():
            hits.append(
                SearchHit(
                    kind="event",
                    id=str(row.event_id),
                    label=_event_label(row.seq, row.event_type),
                    href=f"/events/{row.event_id}",
                )
            )
        for row in conn.execute(
            select(t.epochs.c.epoch_no)
            .where(
                t.epochs.c.tenant_id == tenant,
                func.encode(t.epochs.c.epoch_root, "hex").like(like),
            )
            .limit(10 - len(hits) if len(hits) < 10 else 0)
        ).all():
            hits.append(
                SearchHit(
                    kind="epoch",
                    id=str(row.epoch_no),
                    label=f"Epoch {row.epoch_no}",
                    href=f"/epochs?epoch={row.epoch_no}",
                )
            )
    return hits[:10]


# --------------------------------------------------------------------------- rule descriptions
class RuleDescription(_Out):
    name: str
    why: str


class RuleDescriptions(_Out):
    rules: dict[str, RuleDescription]
    patterns: dict[str, RuleDescription]  # "PREFIX*": {suffix} in `why` is the matched rest
    policies: list[dict[str, Any]]


@router.get("/dashboard/rule-descriptions", response_model=RuleDescriptions)
def rule_descriptions(human: Human) -> RuleDescriptions:
    """Plain-English names for every rule id (ADR-0039). Display only; static per release."""
    d = descriptions.load()
    return RuleDescriptions(
        rules={k: RuleDescription(**v) for k, v in d["rules"].items()},
        patterns={k: RuleDescription(**v) for k, v in d["patterns"].items()},
        policies=d["policies"],
    )


# --------------------------------------------------------------------------- repository switcher
@router.get("/dashboard/repo-choices", response_model=list[coding_view.RepoChoice])
def repo_choices(request: Request, human: Human) -> list[coding_view.RepoChoice]:
    """Names of this tenant's repositories for the console's repository switcher (ADR-0040).
    Names only (no overlay, no proposals): any signed-in human may filter by repository."""
    with _state(request).engine.connect() as conn:
        return coding_view.repo_choices(conn, human.tenant_id)
