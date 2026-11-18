"""The GitHub connector's actions (C3, ADR-0036 §3-4).

``git_submit_change`` is assessed BEFORE the policy decision: the change is applied onto a
fresh server-side clone at ``base_sha`` and the FULL combined diff runs through the C1 coding
policy (path rules + content rules, plus the repository's tighten-only overlay). A deny denies;
an ask raises the risk floor to the C1 level, so HIGH/CRITICAL changes need a human approval
bound to the exact change (the change is in the approved args; the diff is a deterministic
function of base_sha + change). At dispatch the change is applied and assessed AGAIN; a
different or riskier result is refused; then it is pushed fast-forward-only with the
installation token, and every commit is recorded in ``github_commits``.
"""

from __future__ import annotations

import base64
import binascii
import re
from collections.abc import Mapping
from typing import Any, Final
from uuid import UUID

from sqlalchemy import func, insert, select
from sqlalchemy.dialects.postgresql import insert as pg_insert

from agw_gateway.coding.digest import repo_digest
from agw_gateway.coding.model import CodingAction
from agw_gateway.coding.policy import CodingPolicy
from agw_gateway.connectors.constraint import Assessment
from agw_gateway.connectors.types.base import ActionFailed, ExecContext
from agw_gateway.connectors.types.github import GithubConfig, GithubCredentials
from agw_gateway.db import tables as t
from agw_gateway.github import gitops
from agw_gateway.github.client import GithubApi

LEVELS: Final = ("LOW", "MEDIUM", "HIGH", "CRITICAL")
BRANCH_RE: Final = re.compile(r"^(fix|feat)/MR-([0-9]{1,9})-[a-z0-9][a-z0-9-]{0,48}$")
RESULT_CLASSES: Final[dict[str, dict[str, str]]] = {
    "github_issue_get": {
        "number": "internal",
        "title": "internal",
        "state": "internal",
        "body": "internal",
        "labels": "internal",
        "author": "internal",
        "is_pull_request": "internal",
        "html_url": "internal",
    },
    "github_issue_list": {"issues": "internal"},
    "github_issue_comment": {"comment_id": "internal", "html_url": "internal"},
    "git_submit_change": {
        "branch": "internal",
        "head_sha": "internal",
        "tree_sha": "internal",
        "commits": "internal",
        "diff_digest": "internal",
        "files": "internal",
    },
    "github_pr_create": {"number": "internal", "html_url": "internal", "check": "internal"},
    "github_pr_comment": {"comment_id": "internal", "html_url": "internal"},
    "github_pr_status": {
        "number": "internal",
        "state": "internal",
        "merged": "internal",
        "head_sha": "internal",
        "check": "internal",
        "summary": "internal",
    },
}
# dev/test only (settings.github_clone_root): clone from local bare repositories.
CLONE_ROOT: list[Any] = [None]
POLICY: list[CodingPolicy] = []
OVERLAY_LOOKUP: list[Any] = [None]  # (tenant, repo digest) -> (overlay, version, digest) | None


def _api(ctx: ExecContext) -> GithubApi:
    cfg, creds = ctx.config, ctx.credentials
    assert isinstance(cfg, GithubConfig) and isinstance(creds, GithubCredentials)  # noqa: S101
    return GithubApi(ctx.http, cfg, creds, str(ctx.connector_id))


def _policy(tenant: str | None, repo: str) -> CodingPolicy:
    if not POLICY:
        POLICY.append(CodingPolicy.bundled())
    base = POLICY[0]
    lookup = OVERLAY_LOOKUP[0]
    if lookup is None or tenant is None:
        return base
    found = lookup(tenant, repo_digest(f"https://github.com/{repo}.git"))
    return base.with_overlay(*found) if found else base


# --------------------------------------------------------------------------- assessment
def _check_branch(args: Mapping[str, Any], cfg: GithubConfig) -> str | None:
    branch = str(args.get("branch", ""))
    m = BRANCH_RE.fullmatch(branch)
    if m is None:
        return "GH-BRANCH-NAME"
    if int(m.group(2)) != int(args.get("issue_number", -1)):
        return "GH-BRANCH-ISSUE-MISMATCH"
    if branch in cfg.protected_branches:
        return "GH-BRANCH-PROTECTED"
    return None


def _decode(args: Mapping[str, Any]) -> bytes:
    try:
        return base64.b64decode(str(args.get("change", "")), validate=True)
    except (binascii.Error, ValueError):
        raise gitops.GitError("CHANGE_ENCODING") from None


def evaluate_prepared(prepared: gitops.Prepared, policy: CodingPolicy) -> Assessment:
    """The C1 coding policy over every changed file of the combined diff."""
    sections = gitops.split_diff(prepared.diff)
    effect, level = "allow", "LOW"
    rules: list[str] = []
    role: str | None = None
    for f in prepared.files:
        checks: list[tuple[str, str, str | None]] = []
        if f.status == "D":
            checks.append(("file_delete", f.path, None))
        else:
            checks.append(("file_write", f.path, sections.get(f.path, "")))
            if f.old_path:  # a rename deletes the old path (renaming a test away is a delete)
                checks.append(("file_delete", f.old_path, None))
        for kind, path, diff in checks:
            d = policy.evaluate(
                CodingAction.model_validate(
                    {"agent_kind": "other", "action_type": kind, "targets": {"paths": [path]}}
                ),
                diff,
                stage="submit",  # the change leaves the machine: the full, strict check
            )
            rules.extend(
                r for r in d.rule_ids if r not in ("PATH-LOW", "PATH-READ") and r not in rules
            )
            if ("allow", "ask", "deny").index(d.effect) > ("allow", "ask", "deny").index(effect):
                effect = d.effect
            if d.effect != "allow":
                level = max(level, d.level, key=LEVELS.index)
                if d.effect == "ask" and (role is None or d.level == "CRITICAL"):
                    role = d.approval_role
    facts = {
        "diff_digest": prepared.diff_digest,
        "tree_sha": prepared.tree_sha,
        "base_sha": prepared.base_sha,
        "commits": len(prepared.commits),
        "files": len(prepared.files),
    }
    if effect == "deny":
        return Assessment(level="CRITICAL", deny=True, rule_ids=tuple(rules), facts=facts)
    if effect == "ask":
        # A C1 "ask" means a human approval: at least HIGH (approval by policy), CRITICAL is
        # approvable by the routed role (security) instead of the default CRITICAL deny.
        lvl = max(level, "HIGH", key=LEVELS.index)
        return Assessment(
            level=lvl,
            rule_ids=tuple(rules),
            facts=facts,
            approver_role=role,
            critical_approval=lvl == "CRITICAL",
        )
    return Assessment(level=None, rule_ids=tuple(rules), facts=facts)


def _prepare(
    ctx: ExecContext, args: Mapping[str, Any], repo: str, token: str | None, author: tuple[str, str]
) -> gitops.Prepared:
    api = _api(ctx)
    return gitops.prepare(
        clone_url=api.clone_url(repo, CLONE_ROOT[0]),
        token=token,
        base_sha=str(args["base_sha"]),
        change_format=str(args["change_format"]),
        change=_decode(args),
        message=str(
            args.get("commit_message") or f"MR-{args['issue_number']}: change via AgentGuard"
        ),
        author=author,
    )


def assess_submit(ctx: ExecContext, args: Mapping[str, Any]) -> Assessment:
    cfg = ctx.config
    assert isinstance(cfg, GithubConfig)  # noqa: S101
    bad = _check_branch(args, cfg)
    if bad is not None:
        return Assessment(level="HIGH", deny=True, rule_ids=(bad,))
    try:
        api = _api(ctx)
        repo = api.repo(args.get("repo"))
        token = api.token() if CLONE_ROOT[0] is None else None
        prepared = _prepare(ctx, args, repo, token, ("agent", "agent@users.noreply.agentguard"))
    except gitops.GitError as exc:
        return Assessment(level="HIGH", deny=True, rule_ids=(f"GH-{exc.code}",))
    except ActionFailed as exc:
        return Assessment(level="HIGH", deny=True, rule_ids=(f"GH-{exc.code}",))
    try:
        return evaluate_prepared(prepared, _policy(ctx.tenant, repo))
    finally:
        prepared.cleanup()


# --------------------------------------------------------------------------- execution
def _developer(ctx: ExecContext) -> tuple[str, str]:
    with ctx.engine.connect() as conn:
        name = conn.execute(
            select(t.humans.c.username)
            .join(t.coding_devices, t.coding_devices.c.developer_id == t.humans.c.human_id)
            .where(t.coding_devices.c.agent_id == ctx.agent_id)
        ).scalar_one_or_none()
    who = name or "agent"
    return (f"{who} (via AgentGuard)", f"{who}@users.noreply.agentguard")


def execute(ctx: ExecContext, args: Mapping[str, Any]) -> Mapping[str, Any]:
    api = _api(ctx)
    name = ctx.action.name
    repo = api.repo(args.get("repo"))
    if name == "github_issue_get":
        b = api.call("GET", f"/repos/{repo}/issues/{int(args['number'])}")
        return {
            "number": b.get("number"),
            "title": str(b.get("title", ""))[:500],
            "state": b.get("state"),
            "body": str(b.get("body") or "")[:20000],
            "labels": [
                str(lbl.get("name", "")) for lbl in b.get("labels", []) if isinstance(lbl, dict)
            ],
            "author": (b.get("user") or {}).get("login"),
            "is_pull_request": "pull_request" in b,
            "html_url": b.get("html_url"),
        }
    if name == "github_issue_list":
        params = {
            "state": str(args.get("state") or "open"),
            "per_page": str(args.get("per_page") or 20),
        }
        if args.get("labels"):
            params["labels"] = str(args["labels"])
        items = api.call("GET", f"/repos/{repo}/issues", params=params)
        return {
            "issues": [
                {
                    "number": i.get("number"),
                    "title": str(i.get("title", ""))[:300],
                    "state": i.get("state"),
                }
                for i in items
                if isinstance(i, dict) and "pull_request" not in i
            ]
        }
    if name in ("github_issue_comment", "github_pr_comment"):
        b = api.call(
            "POST",
            f"/repos/{repo}/issues/{int(args['number'])}/comments",
            json={"body": str(args["body"])},
        )
        return {"comment_id": b.get("id"), "html_url": b.get("html_url")}
    if name == "git_submit_change":
        return _submit(ctx, api, repo, args)
    if name == "github_pr_create":
        return _pr_create(ctx, api, repo, args)
    if name == "github_pr_status":
        from agw_gateway.github.checks import CHECKS  # noqa: PLC0415

        b = api.call("GET", f"/repos/{repo}/pulls/{int(args['number'])}")
        with ctx.engine.connect() as conn:
            pr = conn.execute(
                select(t.github_prs).where(
                    t.github_prs.c.connector_id == ctx.connector_id,
                    t.github_prs.c.repo == repo,
                    t.github_prs.c.number == int(args["number"]),
                )
            ).one_or_none()
        _ = CHECKS
        return {
            "number": b.get("number"),
            "state": b.get("state"),
            "merged": bool(b.get("merged")),
            "head_sha": (b.get("head") or {}).get("sha"),
            "check": pr.conclusion if pr else None,
            "summary": (pr.summary or "")[:2000] if pr else "",
        }
    raise ActionFailed("ACTION_UNKNOWN")


def _submit(
    ctx: ExecContext, api: GithubApi, repo: str, args: Mapping[str, Any]
) -> Mapping[str, Any]:
    cfg = ctx.config
    assert isinstance(cfg, GithubConfig)  # noqa: S101
    if _check_branch(args, cfg) is not None:
        raise ActionFailed("BRANCH_REFUSED")
    branch = str(args["branch"])
    rules = api.branch_rules(repo, branch)
    if any(
        isinstance(r, dict)
        and r.get("type")
        in ("update", "non_fast_forward", "pull_request", "required_status_checks")
        for r in rules
    ):
        raise ActionFailed("BRANCH_PROTECTED")
    existing = api.branch(repo, branch)
    if existing is not None:
        if existing.get("protected"):
            raise ActionFailed("BRANCH_PROTECTED")
        if (existing.get("commit") or {}).get("sha") != args["base_sha"]:
            raise ActionFailed("NOT_FAST_FORWARD")  # the branch moved: rebase and submit again
    token = api.token() if CLONE_ROOT[0] is None else None
    prepared = _prepare(ctx, args, repo, token, _developer(ctx))
    try:
        again = evaluate_prepared(prepared, _policy(ctx.tenant, repo))
        with ctx.engine.connect() as conn:
            decided = conn.execute(
                select(t.actions.c.risk_level).where(t.actions.c.action_id == ctx.action_id)
            ).scalar_one()
        if again.deny or (again.level and LEVELS.index(again.level) > LEVELS.index(decided)):
            raise ActionFailed("CHANGE_REASSESSED_STRICTER")
        gitops.push(
            prepared, clone_url=api.clone_url(repo, CLONE_ROOT[0]), token=token, branch=branch
        )
        with ctx.engine.begin() as conn:
            for sha in prepared.commits:
                conn.execute(
                    pg_insert(t.github_commits)
                    .values(
                        repo=repo,
                        sha=sha,
                        tenant_id=ctx.tenant,
                        connector_id=ctx.connector_id,
                        action_id=ctx.action_id,
                        run_id=ctx.run_id,
                        session_id=(
                            str(args.get("session_id"))[:64] if args.get("session_id") else None
                        ),
                        issue_number=int(args["issue_number"]),
                        branch=branch,
                        tree_sha=prepared.tree_sha,
                        diff_digest=prepared.diff_digest,
                    )
                    .on_conflict_do_nothing()
                )
        return {
            "branch": branch,
            "head_sha": prepared.head_sha,
            "tree_sha": prepared.tree_sha,
            "commits": prepared.commits,
            "diff_digest": prepared.diff_digest.hex(),
            "files": len(prepared.files),
        }
    except gitops.GitError as exc:
        raise ActionFailed(exc.code) from None
    finally:
        prepared.cleanup()


def pr_body(ctx: ExecContext, repo: str, branch: str, issue: int) -> str:
    """Session, agent, developer, issue, approvals, evidence summary and links."""
    from agw_gateway.github.checks import dashboard_url  # noqa: PLC0415

    base = dashboard_url()
    with ctx.engine.connect() as conn:
        commits = conn.execute(
            select(t.github_commits)
            .where(
                t.github_commits.c.repo == repo,
                t.github_commits.c.branch == branch,
                t.github_commits.c.tenant_id == ctx.tenant,
            )
            .order_by(t.github_commits.c.pushed_at)
        ).all()
        action_ids = list(dict.fromkeys(c.action_id for c in commits))
        sessions = sorted({c.session_id for c in commits if c.session_id})
        dev = _developer(ctx)[0].replace(" (via AgentGuard)", "")
        kind = conn.execute(
            select(t.coding_sessions.c.agent_kind, t.coding_sessions.c.agent_version)
            .where(t.coding_sessions.c.device_id == ctx.agent_id)
            .order_by(t.coding_sessions.c.started_at.desc())
            .limit(1)
        ).one_or_none()
        approvals = (
            conn.execute(
                select(t.approvals.c.approval_id, t.approvals.c.state, t.humans.c.username)
                .outerjoin(
                    t.approval_decisions,
                    t.approval_decisions.c.approval_id == t.approvals.c.approval_id,
                )
                .outerjoin(t.humans, t.humans.c.human_id == t.approval_decisions.c.approver_id)
                .where(t.approvals.c.action_id.in_(action_ids))
            ).all()
            if action_ids
            else []
        )
        events = conn.execute(
            select(func.count())
            .select_from(t.evidence_events)
            .where(
                t.evidence_events.c.tenant_id == ctx.tenant,
                t.evidence_events.c.run_id == ctx.run_id,
            )
        ).scalar_one()
        done = (
            conn.execute(
                select(t.evidence_events.c.event_id).where(
                    t.evidence_events.c.action_id.in_(action_ids),
                    t.evidence_events.c.event_type == "ACTION_COMPLETED",
                )
            )
            .scalars()
            .all()
            if action_ids
            else []
        )
    agent = f"{kind.agent_kind} {kind.agent_version or ''}".strip() if kind else "MCP client"
    lines = [
        "<!-- agentguard:pr-body v1 -->",
        f"Closes #{issue}",
        "",
        "### AgentGuard evidence",
        "",
        "| | |",
        "|---|---|",
        f"| Run (session) | `{ctx.run_id}`"
        + (f" · agent sessions: {', '.join(f'`{s}`' for s in sessions)}" if sessions else "")
        + " |",
        f"| Agent | {agent} |",
        f"| Developer | {dev} |",
        f"| Linked issue | #{issue} |",
        f"| Commits recorded | {len(commits)} (by {len(action_ids)} `git_submit_change` call(s)) |",
        f"| Evidence events in run | {events} |",
        "",
        "**Approvals:** "
        + (
            ", ".join(f"`{a.approval_id}` {a.state} by {a.username or '-'}" for a in approvals)
            if approvals
            else "none required"
        ),
        "",
        f"- Run timeline: {base}/runs/{ctx.run_id}",
        *[f"- Evidence bundle: {base}/events/{eid}" for eid in done[:5]],
        "",
        "The **AgentGuard evidence** check fails if any commit was not pushed through AgentGuard.",
    ]
    return "\n".join(lines)


def _pr_create(
    ctx: ExecContext, api: GithubApi, repo: str, args: Mapping[str, Any]
) -> Mapping[str, Any]:
    from agw_gateway.github.checks import CHECKS  # noqa: PLC0415

    branch = str(args["branch"])
    if BRANCH_RE.fullmatch(branch) is None:
        raise ActionFailed("BRANCH_REFUSED")
    body = pr_body(ctx, repo, branch, int(args["issue_number"]))
    pr = api.call(
        "POST",
        f"/repos/{repo}/pulls",
        json={
            "title": str(args["title"]),
            "head": branch,
            "base": str(args.get("base") or "main"),
            "body": body,
            "draft": bool(args.get("draft", False)),
            "maintainer_can_modify": False,
        },
    )
    number = int(pr["number"])
    with ctx.engine.begin() as conn:
        conn.execute(
            pg_insert(t.github_prs)
            .values(
                connector_id=ctx.connector_id,
                repo=repo,
                number=number,
                tenant_id=ctx.tenant,
                run_id=ctx.run_id,
                created_by_action=ctx.action_id,
                branch=branch,
                head_sha=(pr.get("head") or {}).get("sha"),
                state=pr.get("state", "open"),
                html_url=pr.get("html_url"),
            )
            .on_conflict_do_nothing()
        )
    check = CHECKS[0].evaluate_and_publish(ctx.connector_id, repo, number) if CHECKS else None
    return {"number": number, "html_url": pr.get("html_url"), "check": check}


_ = (insert, UUID)
