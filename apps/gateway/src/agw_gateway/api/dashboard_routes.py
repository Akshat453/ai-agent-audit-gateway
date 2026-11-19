"""Dashboard read API (Phase 9, ADR-0031 §2). HUMAN sessions only (an agent key -> 403 +
SECURITY_VIOLATION, as on every human endpoint), always scoped to the human's tenant.

Nothing here returns an event PAYLOAD or tool args/results: only headers (the derived JSON
projection of the canonical header), operational metadata and verification reports. Payloads
are reachable only through a disclosure grant (Phase 7, auditor role).

    GET  /v1/dashboard/config                   chain/explorer/step-up settings for the UI
    GET  /v1/dashboard/overview                 counts, distributions, ages, failures
    GET  /v1/dashboard/runs                     recent runs
    GET  /v1/dashboard/runs/{run_id}            lifecycle + delegation tree + epoch/anchor
    GET  /v1/dashboard/events                   headers by filter
    GET  /v1/dashboard/events/{id}/bundle       evidence bundle WITHOUT payload (auditor/admin)
    GET  /v1/dashboard/epochs                   epochs + anchor states
    GET  /v1/dashboard/policies                 policy + risk-policy versions (read-only)
    GET  /v1/dashboard/incidents                denied / unknown outcome / violations / alerts
    GET  /v1/dashboard/incidents/export         bundle set (auditor/admin)
    GET  /v1/dashboard/verifications            monitor reports (+ open requests)
    GET  /v1/dashboard/verifications/{id}       one full report
    POST /v1/dashboard/verifications            request a verifier run (auditor/admin)
    GET  /v1/dashboard/alerts                   monitor alerts
    POST /v1/actions/{id}/reconcile             OUTCOME_UNKNOWN -> ACTION_RECONCILED (admin)
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Any, Literal
from uuid import UUID

from fastapi import APIRouter, Query, Request
from fastapi.concurrency import run_in_threadpool
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import Connection, and_, func, select, text

from agw_gateway.api import coding_view
from agw_gateway.api.approval_routes import Human
from agw_gateway.api.coding_view import CodingSession, CodingView
from agw_gateway.api.state import GatewayState
from agw_gateway.db import tables as t
from agw_gateway.evidence.bundle import EventNotFound, EventNotSealed, build_bundle
from agw_gateway.evidence.sealed import header_for_display
from agw_gateway.execution.errors import EventNotSealedYet, NotFound, RoleRequired
from agw_gateway.humans import AuthenticatedHuman
from agw_gateway.ids import uuid7

router = APIRouter(prefix="/v1")
LEVELS = ("LOW", "MEDIUM", "HIGH", "CRITICAL")


def _state(request: Request) -> GatewayState:
    state: GatewayState = request.app.state.agw
    return state


def _require(human: AuthenticatedHuman, *roles: str) -> None:
    if not any(human.has(r) for r in roles):
        raise RoleRequired


def _uuid_or_none(v: str) -> UUID | None:
    try:
        return UUID(v)
    except ValueError:
        return None


def _iso(v: datetime | None) -> str | None:
    return v.isoformat().replace("+00:00", "Z") if v is not None else None


# --------------------------------------------------------------------------- models
class _Out(BaseModel):
    model_config = ConfigDict(extra="forbid")


class DashboardConfig(_Out):
    tenant: str
    username: str
    roles: list[str]
    chain_id: int | None
    contract: str | None
    explorer_tx_url: str | None
    step_up_window_seconds: int
    step_up_levels: list[str]


class DayCount(_Out):
    day: str
    count: int


class Overview(_Out):
    actions_per_day: list[DayCount]
    decisions: dict[str, int]
    statuses: dict[str, int]
    risk: dict[str, int]
    pending_approvals: int
    oldest_pending_approval_seconds: float | None
    unsealed_events: int
    oldest_unsealed_seconds: float | None
    unanchored_epochs: int
    oldest_unanchored_seconds: float | None
    anchoring_configured: bool
    verification_failures: int
    last_verification: dict[str, Any] | None
    open_alerts: int


class RunSummary(_Out):
    run_id: str
    agents: list[str]
    actions: int
    statuses: dict[str, int]
    first_at: str | None
    last_at: str | None
    delegated: bool
    # ADR-0039: coding sessions only: developer, device, agent, repository, issue.
    session: CodingSession | None = None
    decisions: dict[str, int] = {}
    repos: list[str] = []  # ADR-0042: repositories its integration (GitHub) actions targeted


class TimelineEvent(_Out):
    seq: int
    event_id: str
    event_hash: str
    type: str
    evidence_class: str
    occurred_at: str | None
    actor: dict[str, Any]
    agent: str | None
    action_id: str | None
    tool: dict[str, Any] | None
    decision: str | None
    status: str | None
    code: str | None
    reasons: list[str]
    rules: list[str] = []  # ADR-0040: matched rule ids (sealed record), for the run story
    detail: str | None = None  # SECURITY_VIOLATION: what was claimed (an action type, endpoint)
    risk: dict[str, Any] | None
    approval: dict[str, Any] | None
    delegation: dict[str, Any] | None
    refs: dict[str, Any] | None
    epoch_no: int | None
    anchor: dict[str, Any] | None


class DelegationNode(_Out):
    delegation_id: str
    depth: int
    issuer: str
    child: str
    parent_delegation_id: str | None
    tools: list[str]
    max_risk: str
    uses: int
    max_uses: int
    expires_at: str | None
    revoked: bool
    created_event_id: str
    issuer_run: str | None
    child_runs: list[str]


class RunDetail(_Out):
    run_id: str
    events: list[TimelineEvent]
    delegations: list[DelegationNode]
    approvals: list[dict[str, Any]]
    # ADR-0039: coding context (None for non-coding runs) and each coding action's target.
    session: CodingSession | None = None
    coding: dict[str, CodingView] = {}
    people: dict[str, str] = {}  # human id -> username, for approvers named in the events
    repos: list[str] = []  # ADR-0042


class EventHeader(_Out):
    seq: int
    event_id: str
    type: str
    occurred_at: str | None
    event_hash: str
    header: dict[str, Any]


class EventPage(_Out):
    events: list[EventHeader]
    next_from_seq: int | None
    payloads: str = "never returned here: payloads require a disclosure grant (auditor)"


class EpochRow(_Out):
    epoch_no: int
    first_seq: int
    last_seq: int
    tree_size: int
    epoch_root: str
    sealed_at: str | None
    seal_reason: str | None
    anchor_priority: str | None
    anchor_status: str
    tx_hash: str | None
    block_number: int | None
    chain_id: int | None
    explorer_url: str | None
    submitted_at: str | None
    included_at: str | None
    finalized_at: str | None


class PolicyVersion(_Out):
    policy_id: str
    version: int
    created_at: str | None
    created_by: str
    document: dict[str, Any]


class RiskPolicyVersion(_Out):
    policy_id: str
    version: int
    digest: str
    created_at: str | None
    created_by: str
    document: dict[str, Any]


class Policies(_Out):
    policies: list[PolicyVersion]
    risk_policies: list[RiskPolicyVersion]
    note: str = "read-only: policy changes go through a reviewed PR + CLI and an ADR"


class Incident(_Out):
    kind: str
    at: str | None
    action_id: str | None
    run_id: str | None
    tool: str | None
    status: str | None
    code: str | None
    detail: dict[str, Any]
    reconcilable: bool


class ReportSummary(_Out):
    report_id: str
    result: str
    trigger: str
    requested_by: str | None
    first_seq: int | None
    last_seq: int | None
    created_at: str | None
    event_id: str | None
    reason: str | None
    alerts: int


class Verifications(_Out):
    reports: list[ReportSummary]
    pending_requests: int
    note: str = (
        "dashboard status is a convenience view; independent verification uses the CLI "
        "(agw-verify) on an exported bundle with trust roots obtained out of band"
    )


class Alert(_Out):
    alert_id: str
    kind: str
    severity: str
    detail: dict[str, Any]
    created_at: str | None
    delivered: bool
    report_id: str | None


class ReconcileRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)
    observed: Literal["COMPLETED", "FAILED", "NOT_EXECUTED"]
    justification: str = Field(min_length=10, max_length=2000)


# --------------------------------------------------------------------------- helpers
def _ages(conn: Connection, tenant: str) -> dict[str, Any]:
    ev, ep, an = t.evidence_events, t.epochs, t.anchors
    sealed_up_to = conn.execute(
        select(func.coalesce(func.max(ep.c.last_seq), -1)).where(ep.c.tenant_id == tenant)
    ).scalar_one()
    unsealed = conn.execute(
        select(
            func.count(),
            func.extract("epoch", func.now() - func.min(ev.c.occurred_at)),
        ).where(ev.c.tenant_id == tenant, ev.c.seq > sealed_up_to)
    ).one()
    anchoring = bool(
        conn.execute(
            select(func.count())
            .select_from(t.anchor_recorders)
            .where(t.anchor_recorders.c.tenant_id == tenant)
        ).scalar_one()
    )
    unanchored = conn.execute(
        select(func.count(), func.extract("epoch", func.now() - func.min(ep.c.sealed_at)))
        .select_from(
            ep.outerjoin(
                an,
                and_(
                    an.c.tenant_id == ep.c.tenant_id,
                    an.c.epoch_no == ep.c.epoch_no,
                    an.c.status == "FINALIZED",
                ),
            )
        )
        .where(ep.c.tenant_id == tenant, an.c.epoch_no.is_(None))
    ).one()
    return {
        "unsealed_events": int(unsealed[0]),
        "oldest_unsealed_seconds": float(unsealed[1]) if unsealed[1] is not None else None,
        "anchoring_configured": anchoring,
        "unanchored_epochs": int(unanchored[0]) if anchoring else 0,
        "oldest_unanchored_seconds": (
            float(unanchored[1]) if anchoring and unanchored[1] is not None else None
        ),
    }


def _explorer(state: GatewayState, tx: bytes | None) -> str | None:
    template = state.settings.anchor_explorer_tx_url
    if template is None or tx is None:
        return None
    return template.replace("{tx}", "0x" + bytes(tx).hex())


def _anchor_view(state: GatewayState, a: Any) -> dict[str, Any] | None:
    if a is None:
        return None
    tx = bytes(a.tx_hash) if a.tx_hash is not None else None
    return {
        "status": a.status,
        "tx_hash": "0x" + tx.hex() if tx else None,
        "block_number": a.block_number,
        "chain_id": a.chain_id,
        "explorer_url": _explorer(state, tx),
    }


# --------------------------------------------------------------------------- endpoints
@router.get("/dashboard/config", response_model=DashboardConfig)
def config(request: Request, human: Human) -> DashboardConfig:
    s = _state(request).settings
    return DashboardConfig(
        tenant=human.tenant_id,
        username=human.username,
        roles=sorted(human.roles),
        chain_id=s.anchor_chain_id,
        contract=s.anchor_contract,
        explorer_tx_url=s.anchor_explorer_tx_url,
        step_up_window_seconds=s.step_up_window_seconds,
        step_up_levels=list(s.step_up_levels),
    )


@router.get("/dashboard/overview", response_model=Overview)
def overview(
    request: Request,
    human: Human,
    days: Annotated[int, Query(ge=1, le=90)] = 14,
    repo_id: UUID | None = None,  # ADR-0040: action / approval figures of one repository
) -> Overview:
    tenant = human.tenant_id
    a = t.actions
    scope = [coding_view.in_repo(tenant, repo_id, a.c.run_id, a.c.action_id)] if repo_id else []

    with _state(request).engine.connect() as conn:
        per_day = conn.execute(
            text(
                "SELECT to_char(date_trunc('day', created_at), 'YYYY-MM-DD') AS d, count(*) "
                "FROM actions WHERE tenant_id = :t "
                "AND created_at > now() - make_interval(days => :n) "
                "AND (CAST(:repo AS uuid) IS NULL OR run_id IN"
                " (SELECT s.session_id FROM coding_sessions s JOIN repos r"
                " ON r.tenant_id = s.tenant_id AND r.remote_digest = s.repo_digest"
                " WHERE r.repo_id = CAST(:repo AS uuid) AND s.tenant_id = :t)"
                " OR action_id IN (SELECT ar.action_id FROM action_repos ar JOIN repos r2"
                " ON r2.tenant_id = ar.tenant_id WHERE r2.repo_id = CAST(:repo AS uuid)"
                " AND ar.tenant_id = :t AND right(lower(regexp_replace(r2.remote_url,"
                " '\\.git/?$', '')), length(ar.repo) + 1)"
                " IN ('/' || lower(ar.repo), ':' || lower(ar.repo))))"
                " "
                "GROUP BY 1 ORDER BY 1"
            ),
            {"t": tenant, "n": days, "repo": str(repo_id) if repo_id else None},
        ).all()

        def counts(col: Any) -> dict[str, int]:
            rows = conn.execute(
                select(col, func.count()).where(a.c.tenant_id == tenant, *scope).group_by(col)
            ).all()
            return {str(k): int(v) for k, v in rows}

        pending = conn.execute(
            select(
                func.count(),
                func.extract("epoch", func.now() - func.min(t.approvals.c.requested_at)),
            ).where(
                t.approvals.c.tenant_id == tenant,
                t.approvals.c.state == "PENDING",
                *(
                    [
                        t.approvals.c.action_id.in_(
                            select(a.c.action_id).where(a.c.tenant_id == tenant, *scope)
                        )
                    ]
                    if scope
                    else []
                ),
            )
        ).one()
        r = t.monitor_reports
        failures = conn.execute(
            select(func.count()).where(
                r.c.tenant_id == tenant,
                r.c.result != "VERIFIED",
                r.c.created_at > func.now() - text("interval '14 days'"),
            )
        ).scalar_one()
        last = conn.execute(
            select(r.c.report_id, r.c.result, r.c.created_at)
            .where(r.c.tenant_id == tenant)
            .order_by(r.c.created_at.desc())
            .limit(1)
        ).one_or_none()
        alerts = conn.execute(
            select(func.count()).where(
                t.monitor_alerts.c.tenant_id == tenant,
                t.monitor_alerts.c.created_at > func.now() - text("interval '1 day'"),
            )
        ).scalar_one()
        ages = _ages(conn, tenant)
        risk = counts(a.c.risk_level)
        decisions = counts(a.c.decision)
        statuses = counts(a.c.status)
    return Overview(
        actions_per_day=[DayCount(day=d, count=int(n)) for d, n in per_day],
        decisions=decisions,
        statuses=statuses,
        risk={lvl: risk.get(lvl, 0) for lvl in LEVELS},
        pending_approvals=int(pending[0]),
        oldest_pending_approval_seconds=float(pending[1]) if pending[1] is not None else None,
        verification_failures=int(failures),
        last_verification=(
            {"report_id": str(last.report_id), "result": last.result, "at": _iso(last.created_at)}
            if last is not None
            else None
        ),
        open_alerts=int(alerts),
        **ages,
    )


@router.get("/dashboard/runs", response_model=list[RunSummary])
def runs(
    request: Request,
    human: Human,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    repo_id: UUID | None = None,  # ADR-0040: only this repository's sessions
) -> list[RunSummary]:
    a, g = t.actions, t.agents
    tenant = human.tenant_id
    scope = [coding_view.in_repo(tenant, repo_id, a.c.run_id, a.c.action_id)] if repo_id else []
    with _state(request).engine.connect() as conn:
        rows = conn.execute(
            select(
                a.c.run_id,
                func.array_agg(func.distinct(g.c.name)).label("agents"),
                func.count().label("n"),
                func.min(a.c.created_at).label("first_at"),
                func.max(a.c.updated_at).label("last_at"),
                func.bool_or(a.c.delegation_id.is_not(None)).label("delegated"),
            )
            .join(g, g.c.agent_id == a.c.agent_id)
            .where(a.c.tenant_id == human.tenant_id, *scope)
            .group_by(a.c.run_id)
            .order_by(func.max(a.c.updated_at).desc())
            .limit(limit)
        ).all()
        statuses: dict[Any, dict[str, int]] = {}
        for run_id, status, n in conn.execute(
            select(a.c.run_id, a.c.status, func.count())
            .where(a.c.tenant_id == human.tenant_id, a.c.run_id.in_([r.run_id for r in rows]))
            .group_by(a.c.run_id, a.c.status)
        ):
            statuses.setdefault(run_id, {})[status] = int(n)
        decisions: dict[Any, dict[str, int]] = {}
        for run_id, decision, n in conn.execute(
            select(a.c.run_id, a.c.decision, func.count())
            .where(a.c.tenant_id == human.tenant_id, a.c.run_id.in_([r.run_id for r in rows]))
            .group_by(a.c.run_id, a.c.decision)
        ):
            decisions.setdefault(run_id, {})[decision] = int(n)
        info = coding_view.sessions(conn, human.tenant_id, [r.run_id for r in rows])
        repos_of = coding_view.run_repos(conn, human.tenant_id, [r.run_id for r in rows])
    return [
        RunSummary(
            run_id=str(r.run_id),
            agents=sorted(r.agents),
            actions=int(r.n),
            statuses=statuses.get(r.run_id, {}),
            first_at=_iso(r.first_at),
            last_at=_iso(r.last_at),
            delegated=bool(r.delegated),
            session=info.get(r.run_id),
            decisions=decisions.get(r.run_id, {}),
            repos=repos_of.get(r.run_id, []),
        )
        for r in rows
    ]


@router.get("/dashboard/runs/{run_id}", response_model=RunDetail)
def run_detail(request: Request, human: Human, run_id: UUID) -> RunDetail:
    state = _state(request)
    tenant = human.tenant_id
    ev = t.evidence_events
    with state.engine.connect() as conn:
        rows = conn.execute(
            select(ev, t.agents.c.name.label("agent_name"))
            .outerjoin(t.agents, t.agents.c.agent_id == ev.c.agent_id)
            .where(ev.c.tenant_id == tenant, ev.c.run_id == run_id)
            .order_by(ev.c.seq)
        ).all()
        if not rows:
            raise NotFound
        epochs = conn.execute(
            select(t.epochs.c.epoch_no, t.epochs.c.first_seq, t.epochs.c.last_seq).where(
                t.epochs.c.tenant_id == tenant,
                t.epochs.c.last_seq >= rows[0].seq,
                t.epochs.c.first_seq <= rows[-1].seq,
            )
        ).all()
        anchors = {
            int(a.epoch_no): a
            for a in conn.execute(
                select(t.anchors).where(
                    t.anchors.c.tenant_id == tenant,
                    t.anchors.c.epoch_no.in_([int(e.epoch_no) for e in epochs] or [-1]),
                )
            ).all()
        }
        # Delegations touching this run: created in it (as issuer) or used by its actions.
        d = t.delegations
        used = select(t.actions.c.delegation_id).where(
            t.actions.c.run_id == run_id, t.actions.c.delegation_id.is_not(None)
        )
        created_here = select(ev.c.event_id).where(
            ev.c.run_id == run_id, ev.c.event_type == "DELEGATION_CREATED"
        )
        drows = conn.execute(
            select(d).where(
                d.c.tenant_id == tenant,
                d.c.delegation_id.in_(used) | d.c.created_event_id.in_(created_here),
            )
        ).all()
        names = {
            r.agent_id: r.name
            for r in conn.execute(
                select(t.agents.c.agent_id, t.agents.c.name).where(t.agents.c.tenant_id == tenant)
            )
        }
        nodes = []
        for dr in drows:
            child_runs = conn.execute(
                select(t.actions.c.run_id)
                .where(t.actions.c.delegation_id == dr.delegation_id)
                .distinct()
            ).scalars()
            issuer_run = conn.execute(
                select(ev.c.run_id).where(ev.c.event_id == dr.created_event_id)
            ).scalar_one_or_none()
            nodes.append(
                DelegationNode(
                    delegation_id=str(dr.delegation_id),
                    depth=int(dr.depth),
                    issuer=names.get(dr.issuer_agent_id, str(dr.issuer_agent_id)),
                    child=names.get(dr.child_agent_id, str(dr.child_agent_id)),
                    parent_delegation_id=(
                        str(dr.parent_delegation_id) if dr.parent_delegation_id else None
                    ),
                    tools=list(dr.tools),
                    max_risk=dr.max_risk,
                    uses=int(dr.uses),
                    max_uses=int(dr.max_uses),
                    expires_at=_iso(dr.expires_at),
                    revoked=dr.revoked_at is not None,
                    created_event_id=str(dr.created_event_id),
                    issuer_run=str(issuer_run) if issuer_run else None,
                    child_runs=[str(x) for x in child_runs],
                )
            )
        session = coding_view.sessions(conn, tenant, [run_id]).get(run_id)
        run_repos = coding_view.run_repos(conn, tenant, [run_id]).get(run_id, [])
        sealed_approvals = [
            header_for_display(bytes(r.canonical_bytes)).get("approval") for r in rows
        ]  # from the sealed record (ADR-0038)
        approver_ids = {
            str(ap["approver"])
            for ap in sealed_approvals
            if isinstance(ap, dict) and ap.get("approver")
        }
        people = {
            str(h.human_id): h.username
            for h in conn.execute(
                select(t.humans.c.human_id, t.humans.c.username).where(
                    t.humans.c.tenant_id == tenant,
                    t.humans.c.human_id.in_([_uuid_or_none(x) for x in approver_ids] or [None]),
                )
            )
        }
        coding = coding_view.actions(
            conn, state, tenant, {r.action_id for r in rows if r.action_id is not None}
        )
        approvals = conn.execute(
            select(t.approvals)
            .join(t.actions, t.actions.c.action_id == t.approvals.c.action_id)
            .where(t.actions.c.run_id == run_id, t.approvals.c.tenant_id == tenant)
        ).all()
    events = []
    for r in rows:
        b = header_for_display(bytes(r.canonical_bytes))  # sealed record, ADR-0038
        epoch_no = next(
            (int(e.epoch_no) for e in epochs if e.first_seq <= r.seq <= e.last_seq), None
        )
        policy = b.get("policy") or {}
        outcome = b.get("outcome") or {}
        events.append(
            TimelineEvent(
                seq=r.seq,
                event_id=str(r.event_id),
                event_hash=bytes(r.event_hash).hex(),
                type=r.event_type,
                evidence_class=b.get("class", ""),
                occurred_at=_iso(r.occurred_at),
                actor=b.get("actor", {}),
                agent=r.agent_name,
                action_id=str(r.action_id) if r.action_id else None,
                tool=b.get("tool"),
                decision=policy.get("effect"),
                status=outcome.get("status"),
                # SECURITY_VIOLATION: the violation kind (ADR-0042 run story), else the outcome
                code=outcome.get("code") or (b.get("violation") or {}).get("kind"),
                reasons=list(policy.get("reasons", [])),
                rules=[str(x) for x in policy.get("rules", [])],
                detail=(b.get("violation") or {}).get("claimed"),
                risk=(
                    {k: b["risk"].get(k) for k in ("level", "score", "rules", "reasons")}
                    if "risk" in b
                    else None
                ),
                approval=(
                    {
                        k: b["approval"][k]
                        for k in ("id", "dec", "votes", "req", "approver")
                        if k in b["approval"]
                    }
                    if "approval" in b
                    else None
                ),
                delegation=b.get("delegation"),
                refs=b.get("refs"),
                epoch_no=epoch_no,
                anchor=_anchor_view(state, anchors.get(epoch_no)) if epoch_no is not None else None,
            )
        )
    return RunDetail(
        run_id=str(run_id),
        events=events,
        delegations=nodes,
        session=session,
        coding={str(k): v for k, v in coding.items()},
        people=people,
        repos=run_repos,
        approvals=[
            {
                "approval_id": str(a.approval_id),
                "action_id": str(a.action_id),
                "state": a.state,
                "required_approvals": a.required_approvals,
                "requested_at": _iso(a.requested_at),
                "expires_at": _iso(a.expires_at),
            }
            for a in approvals
        ],
    )


@router.get("/dashboard/events", response_model=EventPage)
def events(
    request: Request,
    human: Human,
    event_type: Annotated[str | None, Query(alias="type", max_length=64)] = None,
    run_id: UUID | None = None,
    action_id: UUID | None = None,
    agent_id: UUID | None = None,
    from_seq: Annotated[int | None, Query(ge=0)] = None,
    to_seq: Annotated[int | None, Query(ge=0)] = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    repo_id: UUID | None = None,  # ADR-0040
) -> EventPage:
    ev = t.evidence_events
    conds = [ev.c.tenant_id == human.tenant_id]
    if repo_id is not None:
        conds.append(coding_view.in_repo(human.tenant_id, repo_id, ev.c.run_id, ev.c.action_id))
    for col, val in (
        (ev.c.event_type, event_type),
        (ev.c.run_id, run_id),
        (ev.c.action_id, action_id),
        (ev.c.agent_id, agent_id),
    ):
        if val is not None:
            conds.append(col == val)
    if from_seq is not None:
        conds.append(ev.c.seq >= from_seq)
    if to_seq is not None:
        conds.append(ev.c.seq <= to_seq)
    with _state(request).engine.connect() as conn:
        rows = conn.execute(
            select(
                ev.c.seq,
                ev.c.event_id,
                ev.c.event_type,
                ev.c.occurred_at,
                ev.c.event_hash,
                ev.c.canonical_bytes,
            )
            .where(*conds)
            .order_by(ev.c.seq.desc())
            .limit(limit + 1)
        ).all()
    page = rows[:limit]
    return EventPage(
        events=[
            EventHeader(
                seq=r.seq,
                event_id=str(r.event_id),
                type=r.event_type,
                occurred_at=_iso(r.occurred_at),
                event_hash=bytes(r.event_hash).hex(),
                header=header_for_display(bytes(r.canonical_bytes)),
            )
            for r in page
        ],
        next_from_seq=rows[limit].seq if len(rows) > limit else None,
    )


@router.get("/dashboard/events/{event_id}/bundle")
def event_bundle(request: Request, human: Human, event_id: UUID) -> dict[str, Any]:
    """Evidence bundle (header + proof + epochs + anchor claim) WITHOUT the payload."""
    _require(human, "auditor", "admin")
    with _state(request).engine.connect() as conn:
        try:
            return build_bundle(conn, event_id, tenant_id=human.tenant_id)
        except EventNotFound:
            raise NotFound from None
        except EventNotSealed:
            raise EventNotSealedYet from None


@router.get("/dashboard/epochs", response_model=list[EpochRow])
def epochs(
    request: Request, human: Human, limit: Annotated[int, Query(ge=1, le=500)] = 100
) -> list[EpochRow]:
    state = _state(request)
    ep, an = t.epochs, t.anchors
    with state.engine.connect() as conn:
        rows = conn.execute(
            select(
                ep,
                an.c.status,
                an.c.tx_hash,
                an.c.block_number,
                an.c.chain_id,
                an.c.submitted_at,
                an.c.included_at,
                an.c.finalized_at,
            )
            .select_from(
                ep.outerjoin(
                    an, and_(an.c.tenant_id == ep.c.tenant_id, an.c.epoch_no == ep.c.epoch_no)
                )
            )
            .where(ep.c.tenant_id == human.tenant_id)
            .order_by(ep.c.epoch_no.desc())
            .limit(limit)
        ).all()
    return [
        EpochRow(
            epoch_no=int(r.epoch_no),
            first_seq=int(r.first_seq),
            last_seq=int(r.last_seq),
            tree_size=int(r.tree_size),
            epoch_root=bytes(r.epoch_root).hex(),
            sealed_at=_iso(r.sealed_at),
            seal_reason=r.seal_reason,
            anchor_priority=r.anchor_priority,
            anchor_status=r.status or "SEALED (not anchored)",
            tx_hash="0x" + bytes(r.tx_hash).hex() if r.tx_hash is not None else None,
            block_number=r.block_number,
            chain_id=r.chain_id,
            explorer_url=_explorer(state, bytes(r.tx_hash) if r.tx_hash is not None else None),
            submitted_at=_iso(r.submitted_at),
            included_at=_iso(r.included_at),
            finalized_at=_iso(r.finalized_at),
        )
        for r in rows
    ]


@router.get("/dashboard/policies", response_model=Policies)
def policies(request: Request, human: Human) -> Policies:
    with _state(request).engine.connect() as conn:
        pol = conn.execute(
            select(t.policies).order_by(t.policies.c.policy_id, t.policies.c.version)
        ).all()
        risk = conn.execute(
            select(t.risk_policies).order_by(t.risk_policies.c.policy_id, t.risk_policies.c.version)
        ).all()
    return Policies(
        policies=[
            PolicyVersion(
                policy_id=p.policy_id,
                version=p.version,
                created_at=_iso(p.created_at),
                created_by=p.created_by,
                document=p.document,
            )
            for p in pol
        ],
        risk_policies=[
            RiskPolicyVersion(
                policy_id=p.policy_id,
                version=p.version,
                digest=bytes(p.digest).hex(),
                created_at=_iso(p.created_at),
                created_by=p.created_by,
                document=p.document,
            )
            for p in risk
        ],
    )


IncidentKind = Literal["denied", "outcome_unknown", "failed", "security", "alerts"]


def _incidents(
    conn: Connection, tenant: str, kinds: list[str], limit: int, repo_id: UUID | None = None
) -> list[Incident]:
    rid = repo_id
    out: list[Incident] = []
    a = t.actions
    status_of = {"denied": "DENIED", "outcome_unknown": "OUTCOME_UNKNOWN", "failed": "FAILED"}
    for kind in kinds:
        if kind in status_of:
            for r in conn.execute(
                select(a)
                .where(
                    a.c.tenant_id == tenant,
                    a.c.status == status_of[kind],
                    *([coding_view.in_repo(tenant, rid, a.c.run_id, a.c.action_id)] if rid else []),
                )
                .order_by(a.c.updated_at.desc())
                .limit(limit)
            ):
                out.append(
                    Incident(
                        kind=kind,
                        at=_iso(r.updated_at),
                        action_id=str(r.action_id),
                        run_id=str(r.run_id),
                        tool=r.tool_id,
                        status=r.status,
                        code=r.error_code,
                        detail={"risk_level": r.risk_level, "decision": r.decision},
                        reconcilable=r.status == "OUTCOME_UNKNOWN",
                    )
                )
        elif kind == "security":
            ev = t.evidence_events
            for r in conn.execute(
                select(ev.c.occurred_at, ev.c.canonical_bytes, ev.c.event_id)
                .where(
                    ev.c.tenant_id == tenant,
                    ev.c.event_type == "SECURITY_VIOLATION",
                    *(
                        [coding_view.in_repo(tenant, rid, ev.c.run_id, ev.c.action_id)]
                        if rid
                        else []
                    ),
                )
                .order_by(ev.c.seq.desc())
                .limit(limit)
            ):
                out.append(
                    Incident(
                        kind=kind,
                        at=_iso(r.occurred_at),
                        action_id=None,
                        run_id=None,
                        tool=None,
                        status=None,
                        code=(h := header_for_display(bytes(r.canonical_bytes)))
                        .get("violation", {})
                        .get("kind"),
                        detail={
                            "event_id": str(r.event_id),
                            "actor": h.get("actor", {}),
                            "claimed": h.get("violation", {}).get("claimed"),
                        },
                        reconcilable=False,
                    )
                )
        elif kind == "alerts":
            m = t.monitor_alerts
            for r in conn.execute(
                select(m)
                .where(m.c.tenant_id == tenant)
                .order_by(m.c.created_at.desc())
                .limit(limit)
            ):
                out.append(
                    Incident(
                        kind=kind,
                        at=_iso(r.created_at),
                        action_id=None,
                        run_id=None,
                        tool=None,
                        status=r.severity,
                        code=r.kind,
                        detail=r.detail,
                        reconcilable=False,
                    )
                )
    out.sort(key=lambda i: i.at or "", reverse=True)
    return out


@router.get("/dashboard/incidents", response_model=list[Incident])
def incidents(
    request: Request,
    human: Human,
    kind: Annotated[list[IncidentKind] | None, Query()] = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    repo_id: UUID | None = None,  # ADR-0040 (monitor alerts are tenant-wide and stay)
) -> list[Incident]:
    kinds = list(kind or ["denied", "outcome_unknown", "failed", "security", "alerts"])
    with _state(request).engine.connect() as conn:
        return _incidents(conn, human.tenant_id, kinds, limit, repo_id)


@router.get("/dashboard/incidents/export")
def incidents_export(
    request: Request,
    human: Human,
    kind: Annotated[list[IncidentKind] | None, Query()] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
) -> dict[str, Any]:
    """Every SEALED event of the incident actions as a payload-free bundle (+ what is not
    sealed yet). Verify each bundle with ``agw-verify event --bundle``."""
    _require(human, "auditor", "admin")
    kinds = list(kind or ["denied", "outcome_unknown", "failed"])
    ev = t.evidence_events
    bundles: list[dict[str, Any]] = []
    unsealed: list[str] = []
    with _state(request).engine.connect() as conn:
        items = _incidents(conn, human.tenant_id, kinds, limit)
        ids = [UUID(i.action_id) for i in items if i.action_id]
        event_ids = conn.execute(
            select(ev.c.event_id)
            .where(ev.c.tenant_id == human.tenant_id, ev.c.action_id.in_(ids or [uuid7()]))
            .order_by(ev.c.seq)
        ).scalars()
        for eid in event_ids:
            try:
                bundles.append(build_bundle(conn, eid, tenant_id=human.tenant_id))
            except EventNotSealed:
                unsealed.append(str(eid))
    return {
        "format": "agw-incident-export/v1",
        "tenant": human.tenant_id,
        "kinds": kinds,
        "incidents": [i.model_dump() for i in items],
        "bundles": bundles,
        "unsealed_event_ids": unsealed,
        "verify": "for each bundle: agw-verify event --bundle <file> --trust-config <pinned>",
    }


def _report_summary(r: Any) -> ReportSummary:
    rep = r.report or {}
    return ReportSummary(
        report_id=str(r.report_id),
        result=r.result,
        trigger=r.trigger,
        requested_by=r.requested_by,
        first_seq=r.first_seq,
        last_seq=r.last_seq,
        created_at=_iso(r.created_at),
        event_id=str(r.event_id) if r.event_id else None,
        reason=rep.get("reason"),
        alerts=len(rep.get("alerts", [])),
    )


@router.get("/dashboard/verifications", response_model=Verifications)
def verifications(
    request: Request, human: Human, limit: Annotated[int, Query(ge=1, le=200)] = 50
) -> Verifications:
    r = t.monitor_reports
    with _state(request).engine.connect() as conn:
        rows = conn.execute(
            select(r)
            .where(r.c.tenant_id == human.tenant_id)
            .order_by(r.c.created_at.desc())
            .limit(limit)
        ).all()
        pending = conn.execute(
            select(func.count()).where(
                t.monitor_requests.c.tenant_id == human.tenant_id,
                t.monitor_requests.c.report_id.is_(None),
            )
        ).scalar_one()
    return Verifications(reports=[_report_summary(x) for x in rows], pending_requests=int(pending))


@router.get("/dashboard/verifications/{report_id}")
def verification(request: Request, human: Human, report_id: UUID) -> dict[str, Any]:
    r = t.monitor_reports
    with _state(request).engine.connect() as conn:
        row = conn.execute(
            select(r).where(r.c.report_id == report_id, r.c.tenant_id == human.tenant_id)
        ).one_or_none()
    if row is None:
        raise NotFound
    return {
        "summary": _report_summary(row).model_dump(),
        "report": row.report,
        "report_digest": bytes(row.report_digest).hex(),
    }


@router.post("/dashboard/verifications", status_code=202)
def request_verification(request: Request, human: Human) -> dict[str, Any]:
    """Queue a verifier run for the human's tenant. The WORKER runs it (the API process does
    not contain the verifier, ADR-0016); poll GET /v1/dashboard/verifications."""
    _require(human, "auditor", "admin")
    rid = uuid7()
    with _state(request).engine.begin() as conn:
        conn.execute(
            t.monitor_requests.insert().values(
                request_id=rid, tenant_id=human.tenant_id, requested_by=human.username
            )
        )
    return {"request_id": str(rid), "status": "QUEUED"}


@router.get("/dashboard/alerts", response_model=list[Alert])
def alerts(
    request: Request, human: Human, limit: Annotated[int, Query(ge=1, le=500)] = 100
) -> list[Alert]:
    m = t.monitor_alerts
    with _state(request).engine.connect() as conn:
        rows = conn.execute(
            select(m)
            .where(m.c.tenant_id == human.tenant_id)
            .order_by(m.c.created_at.desc())
            .limit(limit)
        ).all()
    return [
        Alert(
            alert_id=str(r.alert_id),
            kind=r.kind,
            severity=r.severity,
            detail=r.detail,
            created_at=_iso(r.created_at),
            delivered=r.delivered,
            report_id=str(r.report_id) if r.report_id else None,
        )
        for r in rows
    ]


@router.post("/actions/{action_id}/reconcile")
async def reconcile(
    request: Request, human: Human, action_id: UUID, body: ReconcileRequest
) -> dict[str, Any]:
    state = _state(request)
    result: dict[str, Any] = await run_in_threadpool(
        state.reconciliation.reconcile, human, action_id, body.observed, body.justification
    )
    return result
