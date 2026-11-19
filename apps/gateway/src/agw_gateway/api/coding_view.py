"""Read-only coding context for the console (ADR-0039): who ran the session (developer, device,
agent, repository, issue) and what each coding action targeted (redacted paths / command / URL,
diff COUNTS). File contents and diffs are never returned."""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict
from sqlalchemy import Connection, and_, func, literal, or_, select

from agw_gateway.api.state import GatewayState
from agw_gateway.db import tables as t
from agw_gateway.privacy.cipher import ops_context

SHORT_TARGET = 200


class _Out(BaseModel):
    model_config = ConfigDict(extra="forbid")


class CodingSession(_Out):
    session_id: str
    agent_kind: str
    agent_version: str | None
    developer: str | None
    device: str | None
    repo: str | None
    repo_url: str | None
    issue_number: int | None
    status: str
    started_at: str | None
    ended_at: str | None


class CodingTarget(_Out):
    paths: list[str] = []
    command: str | None = None
    argv: list[str] = []
    url: str | None = None
    query: str | None = None
    mcp_tool: str | None = None
    mcp_server: str | None = None
    native_tool: str | None = None


class DiffCounts(_Out):
    files: int
    added: int
    removed: int


class CodingView(_Out):
    action_type: str
    target: CodingTarget | None  # None: not recorded (older action, or no KEK configured)
    diff: DiffCounts | None
    session_id: str


def _iso(v: Any) -> str | None:
    return v.isoformat().replace("+00:00", "Z") if v is not None else None


def sessions(conn: Connection, tenant: str, run_ids: Iterable[UUID]) -> dict[UUID, CodingSession]:
    ids = list({*run_ids})
    if not ids:
        return {}
    s, dv, h, r = t.coding_sessions, t.coding_devices, t.humans, t.repos
    rows = conn.execute(
        select(
            s.c.session_id,
            s.c.agent_kind,
            s.c.agent_version,
            s.c.issue_number,
            s.c.status,
            s.c.started_at,
            s.c.ended_at,
            dv.c.label.label("device"),
            h.c.username.label("developer"),
            r.c.name.label("repo"),
            r.c.remote_url.label("repo_url"),
        )
        .outerjoin(dv, dv.c.agent_id == s.c.device_id)
        .outerjoin(h, h.c.human_id == s.c.developer_id)
        .outerjoin(r, and_(r.c.tenant_id == s.c.tenant_id, r.c.remote_digest == s.c.repo_digest))
        .where(s.c.tenant_id == tenant, s.c.session_id.in_(ids))
    ).all()
    return {
        row.session_id: CodingSession(
            session_id=str(row.session_id),
            agent_kind=row.agent_kind,
            agent_version=row.agent_version,
            developer=row.developer,
            device=row.device,
            repo=row.repo,
            repo_url=row.repo_url,
            issue_number=row.issue_number,
            status=row.status,
            started_at=_iso(row.started_at),
            ended_at=_iso(row.ended_at),
        )
        for row in rows
    }


def _target(state: GatewayState, tenant: str, action_id: UUID, sealed: Any) -> CodingTarget | None:
    if sealed is None or state.cipher is None:
        return None
    try:
        raw = state.cipher.open_json(
            ops_context(tenant, "coding_target", action_id.bytes), bytes(sealed)
        )
    except Exception:  # a key that cannot open it: show nothing rather than fail the page
        return None
    if not isinstance(raw, dict):
        return None
    mcp_raw = raw.get("mcp")
    mcp: dict[str, Any] = mcp_raw if isinstance(mcp_raw, dict) else {}
    return CodingTarget(
        paths=[str(p) for p in raw.get("paths", [])],
        command=raw.get("command"),
        argv=[str(a) for a in raw.get("argv", [])],
        url=raw.get("url"),
        query=raw.get("query"),
        mcp_tool=mcp.get("tool"),
        mcp_server=mcp.get("server"),
        native_tool=raw.get("native_tool"),
    )


def actions(
    conn: Connection, state: GatewayState, tenant: str, action_ids: Iterable[UUID]
) -> dict[UUID, CodingView]:
    ids = list({*action_ids})
    if not ids:
        return {}
    c = t.coding_actions
    rows = conn.execute(
        select(
            c.c.action_id,
            c.c.session_id,
            c.c.action_type,
            c.c.target_sealed,
            c.c.diff_files,
            c.c.diff_added,
            c.c.diff_removed,
        ).where(c.c.tenant_id == tenant, c.c.action_id.in_(ids))
    ).all()
    return {
        r.action_id: CodingView(
            action_type=r.action_type,
            target=_target(state, tenant, r.action_id, r.target_sealed),
            diff=(
                DiffCounts(files=r.diff_files, added=r.diff_added or 0, removed=r.diff_removed or 0)
                if r.diff_files is not None
                else None
            ),
            session_id=str(r.session_id),
        )
        for r in rows
    }


def short_target(view: CodingView | None) -> str | None:
    """One line for lists: the first path, else the command / URL / query / MCP tool."""
    if view is None or view.target is None:
        return None
    tg = view.target
    text = (
        (tg.paths[0] + (f" (+{len(tg.paths) - 1} more)" if len(tg.paths) > 1 else ""))
        if tg.paths
        else tg.command or " ".join(tg.argv) or tg.url or tg.query or tg.mcp_tool
    )
    if not text:
        return None
    return text if len(text) <= SHORT_TARGET else f"{text[:SHORT_TARGET]}…"


# ------------------------------------------------------------------ repository scope (ADR-0040)
# A run belongs to a repository when its coding session was started in that repository
# (coding_sessions.repo_digest = repos.remote_digest). Non-coding runs belong to none.


def repo_runs(tenant: str, repo_id: UUID) -> Any:
    """SELECT of the run ids (= coding session ids) of one repository, tenant-scoped."""
    s, r = t.coding_sessions, t.repos
    return (
        select(s.c.session_id)
        .join(r, and_(r.c.tenant_id == s.c.tenant_id, r.c.remote_digest == s.c.repo_digest))
        .where(s.c.tenant_id == tenant, r.c.repo_id == repo_id)
    )


def repo_actions(tenant: str, repo_id: UUID) -> Any:
    """SELECT of the integration (GitHub) actions recorded for one repository (ADR-0042). The
    repository's remote URL is normalised (https or ssh, with or without .git) and must end in
    "/owner/name" or ":owner/name"."""
    ar, r = t.action_repos, t.repos
    norm = func.lower(func.regexp_replace(r.c.remote_url, r"\.git/?$", ""))
    tail = func.right(norm, func.length(ar.c.repo) + 1)
    return (
        select(ar.c.action_id)
        .join(r, r.c.tenant_id == ar.c.tenant_id)
        .where(
            ar.c.tenant_id == tenant,
            r.c.repo_id == repo_id,
            or_(
                tail == literal("/") + func.lower(ar.c.repo),
                tail == literal(":") + func.lower(ar.c.repo),
            ),
        )
    )


def in_repo(tenant: str, repo_id: UUID, run_col: Any, action_col: Any) -> Any:
    """A row belongs to the repository when its run is a coding session started there, or its
    action is an integration action recorded for that repository."""
    runs, acts = repo_runs(tenant, repo_id), repo_actions(tenant, repo_id)
    return or_(run_col.in_(runs), action_col.in_(acts))


class RepoChoice(_Out):
    repo_id: str
    name: str
    sessions: int


def repo_choices(conn: Connection, tenant: str) -> list[RepoChoice]:
    s, r = t.coding_sessions, t.repos
    rows = conn.execute(
        select(r.c.repo_id, r.c.name, func.count(s.c.session_id))
        .outerjoin(s, and_(s.c.tenant_id == r.c.tenant_id, s.c.repo_digest == r.c.remote_digest))
        .where(r.c.tenant_id == tenant)
        .group_by(r.c.repo_id, r.c.name)
        .order_by(r.c.name)
    ).all()
    return [RepoChoice(repo_id=str(i), name=n, sessions=int(c)) for i, n, c in rows]


def run_repos(conn: Connection, tenant: str, run_ids: Iterable[UUID]) -> dict[UUID, list[str]]:
    """Repositories ("owner/name") that each run's integration actions targeted (ADR-0042)."""
    ids = list({*run_ids})
    if not ids:
        return {}
    a, ar = t.actions, t.action_repos
    out: dict[UUID, list[str]] = {}
    for run_id, repo in conn.execute(
        select(a.c.run_id, ar.c.repo)
        .join(ar, ar.c.action_id == a.c.action_id)
        .where(a.c.tenant_id == tenant, ar.c.tenant_id == tenant, a.c.run_id.in_(ids))
        .distinct()
        .order_by(ar.c.repo)
    ):
        out.setdefault(run_id, []).append(repo)
    return out
