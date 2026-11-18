"""The "AgentGuard evidence" check run (C3, ADR-0036 §5).

Evaluated on pull_request opened / synchronize / reopened (verified webhook) or by polling,
and again whenever the monitor reports TAMPERED / INCOMPLETE. SUCCESS only if ALL hold:

1. the PR is from this repository (not a fork) and EVERY commit in it was pushed by a
   ``git_submit_change`` the gateway recorded (``github_commits``);
2. each of those actions COMPLETED after ACTION_AUTHORIZED, with no ACTION_DENIED, and if it
   required approval: the approval was CONSUMED and is bound to the action's digest (the
   digest covers the exact change, hence the diff);
3. every event of those actions is in a SEALED epoch (and, for CRITICAL actions, the epoch's
   anchor is FINALIZED);
4. the latest monitor (independent verifier) report for the tenant VERIFIED the chain up to
   at least those events.

Missing (3)/(4) -> ``in_progress`` (re-evaluated by polling / the next monitor report). Any
other failure -> ``failure`` with which commit / which rule, and a link to the run.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Final
from uuid import UUID

from sqlalchemy import Engine, func, select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert

from agw_gateway.connectors.types.base import ActionFailed
from agw_gateway.connectors.types.github import GithubConfig, GithubCredentials
from agw_gateway.db import tables as t
from agw_gateway.github.client import GithubApi
from agw_gateway.logs import log

logger = logging.getLogger("agw.github.checks")
CHECK_NAME: Final = "AgentGuard evidence"
MAX_COMMIT_PAGES: Final = 3
BAD_REPORTS: Final = frozenset(
    {"TAMPERED", "INCOMPLETE", "INVALID_PROOF", "UNTRUSTED_ANCHOR", "ERROR"}
)
CHECKS: list[GithubChecks] = []  # the process's instance (set by build_state)
_DASHBOARD: list[str] = ["http://localhost:3000"]


def dashboard_url() -> str:
    return _DASHBOARD[0]


@dataclass(frozen=True)
class Verdict:
    conclusion: str  # success | failure | in_progress
    title: str
    summary: str
    run_id: UUID | None = None


def verify_signature(secret: str, body: bytes, header: str | None) -> bool:
    if not header or not header.startswith("sha256="):
        return False
    expected = "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, header)


class GithubChecks:
    def __init__(self, *, engine: Engine, connectors: Any, dashboard: str) -> None:
        self._engine = engine
        self._connectors = connectors  # ConnectorService (runtime + http)
        _DASHBOARD[0] = dashboard.rstrip("/")

    # ------------------------------------------------------------------ plumbing
    def _api(self, tenant: str, cid: UUID) -> tuple[Any, GithubApi]:
        row, _ctype, config, creds = self._connectors.runtime(tenant, cid)
        assert isinstance(config, GithubConfig) and isinstance(creds, GithubCredentials)  # noqa: S101
        return row, GithubApi(self._connectors.http, config, creds, str(cid))

    def _tenant_of(self, cid: UUID) -> str | None:
        with self._engine.connect() as conn:
            return conn.execute(
                select(t.connectors.c.tenant_id).where(
                    t.connectors.c.connector_id == cid, t.connectors.c.deleted_at.is_(None)
                )
            ).scalar_one_or_none()

    # ------------------------------------------------------------------ evaluation
    def evaluate(
        self, tenant: str, api: GithubApi, repo: str, number: int
    ) -> tuple[Verdict, dict[str, Any]]:
        pr = api.call("GET", f"/repos/{repo}/pulls/{number}")
        head = pr.get("head") or {}
        if (head.get("repo") or {}).get("full_name") != repo:
            return Verdict(
                "failure",
                "Commits not recorded by AgentGuard",
                "This pull request comes from a fork: its commits were not pushed "
                "through AgentGuard.",
            ), pr
        shas: list[str] = []
        for page in range(1, MAX_COMMIT_PAGES + 1):  # GitHub lists at most 250 PR commits
            commits = api.call(
                "GET",
                f"/repos/{repo}/pulls/{number}/commits",
                params={"per_page": "100", "page": str(page)},
            )
            batch = [str(c.get("sha")) for c in commits if isinstance(c, dict) and c.get("sha")]
            shas.extend(batch)
            if len(batch) < 100:
                break
        if not shas:
            return Verdict("failure", "No commits", "The pull request has no commits."), pr
        total = pr.get("commits")
        if not isinstance(total, int) or total != len(set(shas)):
            return Verdict(
                "failure",
                "Commits not recorded by AgentGuard",
                f"The pull request has {total} commits but {len(set(shas))} could be listed: "
                "its commits could not all be listed, so they could not all be verified.",
            ), pr
        with self._engine.connect() as conn:
            rec = {
                r.sha: r
                for r in conn.execute(
                    select(t.github_commits).where(
                        t.github_commits.c.repo == repo,
                        t.github_commits.c.tenant_id == tenant,
                        t.github_commits.c.sha.in_(shas),
                    )
                ).all()
            }
            missing = [s for s in shas if s not in rec]
            if missing:
                missing_lines = "\n".join(
                    f"- `{s[:12]}`: not pushed by `git_submit_change`" for s in missing[:20]
                )
                return Verdict(
                    "failure",
                    "Commits not recorded by AgentGuard",
                    f"{len(missing)} of {len(shas)} commit(s) were not recorded by AgentGuard "
                    f"(manual push, web edit or fork):\n\n{missing_lines}",
                ), pr
            action_ids = list(dict.fromkeys(rec[s].action_id for s in shas))
            run_id = rec[shas[-1]].run_id
            problems: list[str] = []
            max_seq = -1
            critical = False
            for aid in action_ids:
                a = conn.execute(select(t.actions).where(t.actions.c.action_id == aid)).one()
                evs = conn.execute(
                    select(t.evidence_events.c.event_type, t.evidence_events.c.seq)
                    .where(t.evidence_events.c.action_id == aid)
                    .order_by(t.evidence_events.c.seq)
                ).all()
                types = [e.event_type for e in evs]
                max_seq = max([max_seq, *(e.seq for e in evs)])
                critical = critical or a.risk_level == "CRITICAL"
                label = f"action `{aid}`"
                if a.status != "COMPLETED" or "ACTION_COMPLETED" not in types:
                    problems.append(f"{label}: not completed ({a.status})")
                if "ACTION_DENIED" in types or "ACTION_AUTHORIZED" not in types:
                    problems.append(
                        f"{label}: a DENY decision was overridden or authorization is missing"
                    )
                if a.decision == "REQUIRE_APPROVAL":
                    ap = conn.execute(
                        select(t.approvals).where(t.approvals.c.action_id == aid)
                    ).one_or_none()
                    if (
                        ap is None
                        or ap.state != "CONSUMED"
                        or not hmac.compare_digest(
                            bytes(ap.action_digest), bytes(a.action_digest or b"")
                        )
                    ):
                        problems.append(
                            f"{label}: the required approval is missing or does not match the change"  # noqa: E501
                        )
            if problems:
                return Verdict(
                    "failure",
                    "Evidence rules failed",
                    "\n".join(f"- {p}" for p in problems),
                    run_id,
                ), pr
            epoch = conn.execute(
                select(t.epochs)
                .where(t.epochs.c.tenant_id == tenant, t.epochs.c.last_seq >= max_seq)
                .order_by(t.epochs.c.epoch_no)
                .limit(1)
            ).one_or_none()
            if epoch is None:
                return Verdict(
                    "in_progress",
                    "Waiting for the evidence epoch to be sealed",
                    f"Events up to seq {max_seq} are not sealed yet.",
                    run_id,
                ), pr
            if critical:
                anchor = conn.execute(
                    select(t.anchors.c.status).where(
                        t.anchors.c.tenant_id == tenant, t.anchors.c.epoch_no == epoch.epoch_no
                    )
                ).scalar_one_or_none()
                if anchor != "FINALIZED":
                    return Verdict(
                        "in_progress",
                        "Waiting for the on-chain anchor",
                        f"Epoch {epoch.epoch_no} holds a CRITICAL change; its anchor is "
                        f"{anchor or 'not submitted'}.",
                        run_id,
                    ), pr
            report = conn.execute(
                select(t.monitor_reports)
                .where(t.monitor_reports.c.tenant_id == tenant)
                .order_by(t.monitor_reports.c.created_at.desc())
                .limit(1)
            ).one_or_none()
        if report is not None and report.result in BAD_REPORTS:
            when = report.created_at.isoformat(timespec="seconds")
            return Verdict(
                "failure",
                f"Evidence verification failed: {report.result}",
                f"The independent verifier reported **{report.result}** at {when}.",
                run_id,
            ), pr
        if report is None or report.last_seq is None or report.last_seq < max_seq:
            return Verdict(
                "in_progress",
                "Waiting for independent verification",
                f"The monitor has not verified the chain up to seq {max_seq} yet.",
                run_id,
            ), pr
        lines = [
            f"- `{s[:12]}` -> action `{rec[s].action_id}` (diff `{bytes(rec[s].diff_digest).hex()[:16]}`)"  # noqa: E501
            for s in shas[:50]
        ]
        return Verdict(
            "success",
            "All commits are backed by verified AgentGuard evidence",
            f"{len(shas)} commit(s), {len(action_ids)} recorded change(s); epoch "
            f"{epoch.epoch_no} sealed; chain verified ({report.result}).\n\n" + "\n".join(lines),
            run_id,
        ), pr

    # ------------------------------------------------------------------ publish
    def evaluate_and_publish(self, cid: UUID, repo: str, number: int) -> str:
        tenant = self._tenant_of(cid)
        if tenant is None:
            return "skipped"
        _row, api = self._api(tenant, cid)
        verdict, pr = self.evaluate(tenant, api, repo, number)
        head_sha = (pr.get("head") or {}).get("sha")
        with self._engine.begin() as conn:
            conn.execute(
                pg_insert(t.github_prs)
                .values(
                    connector_id=cid,
                    repo=repo,
                    number=number,
                    tenant_id=tenant,
                    branch=(pr.get("head") or {}).get("ref"),
                    head_sha=head_sha,
                    state=pr.get("state", "open"),
                    html_url=pr.get("html_url"),
                )
                .on_conflict_do_nothing()
            )
            row = conn.execute(
                select(t.github_prs)
                .where(
                    t.github_prs.c.connector_id == cid,
                    t.github_prs.c.repo == repo,
                    t.github_prs.c.number == number,
                )
                .with_for_update()
            ).one()
        details = (
            f"{dashboard_url()}/runs/{verdict.run_id}"
            if verdict.run_id
            else f"{dashboard_url()}/integrations/{cid}"
        )
        body: dict[str, Any] = {
            "name": CHECK_NAME,
            "head_sha": head_sha,
            "details_url": details,
            "external_id": str(verdict.run_id or ""),
            "output": {"title": verdict.title[:255], "summary": verdict.summary[:60000]},
        }
        if verdict.conclusion == "in_progress":
            body["status"] = "in_progress"
        else:
            body.update(
                status="completed",
                conclusion=verdict.conclusion,
                completed_at=datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
            )
        try:
            if row.check_run_id and row.check_head_sha == head_sha:
                body.pop("head_sha")
                api.call("PATCH", f"/repos/{repo}/check-runs/{row.check_run_id}", json=body)
                check_id = row.check_run_id
            else:
                check_id = int(api.call("POST", f"/repos/{repo}/check-runs", json=body)["id"])
        except ActionFailed as exc:
            log(
                logger,
                logging.WARNING,
                "check publish failed",
                tenant_id=tenant,
                error_code=exc.code,
            )
            check_id = row.check_run_id
        with self._engine.begin() as conn:
            conn.execute(
                update(t.github_prs)
                .where(
                    t.github_prs.c.connector_id == cid,
                    t.github_prs.c.repo == repo,
                    t.github_prs.c.number == number,
                )
                .values(
                    check_run_id=check_id,
                    check_head_sha=head_sha if check_id else None,
                    conclusion=verdict.conclusion,
                    summary=verdict.summary[:4000],
                    head_sha=head_sha,
                    state=pr.get("state", "open"),
                    run_id=row.run_id or verdict.run_id,
                    evaluated_at=func.now(),
                )
            )
        return verdict.conclusion

    # ------------------------------------------------------------------ webhook
    def webhook(self, cid: UUID, headers: Mapping[str, str], raw: bytes) -> tuple[int, str]:
        tenant = self._tenant_of(cid)
        delivery = str(headers.get("x-github-delivery", ""))[:100]
        event = str(headers.get("x-github-event", ""))[:64]
        if tenant is None or not delivery:
            return 404, "unknown"
        _row, _ctype, _config, creds = self._connectors.runtime(tenant, cid)
        secret = (
            creds.webhook_secret.get_secret_value()
            if getattr(creds, "webhook_secret", None)
            else None
        )
        ok = secret is not None and verify_signature(
            secret, raw, headers.get("x-hub-signature-256")
        )
        try:
            payload = json.loads(raw) if ok else {}
        except ValueError:
            payload, ok = {}, False
        action = str(payload.get("action", ""))[:64] if ok else None
        with self._engine.begin() as conn:
            first = (
                conn.execute(
                    pg_insert(t.github_deliveries)
                    .values(
                        delivery_id=delivery,
                        connector_id=cid,
                        event=event,
                        action=action,
                        verified=ok,
                        outcome="accepted" if ok else "rejected: bad signature",
                    )
                    .on_conflict_do_nothing()
                    .returning(t.github_deliveries.c.delivery_id)
                ).scalar_one_or_none()
                is not None
            )
        if not ok:
            log(
                logger,
                logging.WARNING,
                "github webhook rejected",
                tenant_id=tenant,
                error_code="BAD_SIGNATURE",
            )
            return 401, "bad signature"
        if not first:
            return 200, "duplicate delivery"
        repo = str((payload.get("repository") or {}).get("full_name", ""))
        if event == "pull_request" and action in ("opened", "synchronize", "reopened"):
            number = int(
                payload.get("number") or (payload.get("pull_request") or {}).get("number", 0)
            )
            return 202, self.evaluate_and_publish(cid, repo, number)
        if event in ("check_suite", "check_run") and action in ("rerequested", "requested"):
            sha = (payload.get("check_suite") or payload.get("check_run") or {}).get("head_sha")
            with self._engine.connect() as conn:
                prs = (
                    conn.execute(
                        select(t.github_prs.c.number).where(
                            t.github_prs.c.connector_id == cid,
                            t.github_prs.c.repo == repo,
                            t.github_prs.c.head_sha == sha,
                        )
                    )
                    .scalars()
                    .all()
                )
            for n in prs:
                self.evaluate_and_publish(cid, repo, int(n))
            return 202, f"re-evaluated {len(prs)}"
        return 202, "ignored"

    # ------------------------------------------------------------------ polling
    def poll_once(self) -> int:
        """Polling mode (no public webhook URL): evaluate open PRs whose head changed or whose
        check is still in progress. Run every 60 s by the worker."""
        with self._engine.connect() as conn:
            rows = conn.execute(
                select(t.connectors).where(
                    t.connectors.c.type_id == "github",
                    t.connectors.c.deleted_at.is_(None),
                    t.connectors.c.status != "disabled",
                )
            ).all()
        done = 0
        for row in rows:
            cfg = GithubConfig.model_validate(row.config)
            if cfg.mode != "polling" or not cfg.installation_ids:
                continue
            try:
                _r, api = self._api(row.tenant_id, row.connector_id)
                for repo in cfg.repos:
                    for pr in api.call(
                        "GET", f"/repos/{repo}/pulls", params={"state": "open", "per_page": "50"}
                    ):
                        number, head = int(pr["number"]), (pr.get("head") or {}).get("sha")
                        with self._engine.connect() as conn:
                            known = conn.execute(
                                select(t.github_prs.c.head_sha, t.github_prs.c.conclusion).where(
                                    t.github_prs.c.connector_id == row.connector_id,
                                    t.github_prs.c.repo == repo,
                                    t.github_prs.c.number == number,
                                )
                            ).one_or_none()
                        if (
                            known is None
                            or known.head_sha != head
                            or known.conclusion == "in_progress"
                        ):
                            self.evaluate_and_publish(row.connector_id, repo, number)
                            done += 1
            except ActionFailed as exc:
                log(
                    logger,
                    logging.WARNING,
                    "github polling failed",
                    tenant_id=row.tenant_id,
                    error_code=exc.code,
                )
        return done

    # ------------------------------------------------------------------ tamper
    def on_monitor_report(self, tenant: str, result: str, report_id: UUID | None) -> int:
        """A TAMPERED / INCOMPLETE report: flip every open tracked PR of the tenant to FAILURE
        and comment once per (PR, report). VERIFIED: re-evaluate PRs waiting for it."""
        with self._engine.connect() as conn:
            prs = conn.execute(
                select(t.github_prs).where(
                    t.github_prs.c.tenant_id == tenant, t.github_prs.c.state == "open"
                )
            ).all()
        flipped = 0
        for pr in prs:
            if result not in BAD_REPORTS and pr.conclusion != "in_progress":
                continue
            try:
                conclusion = self.evaluate_and_publish(pr.connector_id, pr.repo, pr.number)
                if result in BAD_REPORTS and report_id is not None and conclusion == "failure":
                    with self._engine.begin() as conn:
                        new = (
                            conn.execute(
                                pg_insert(t.github_tamper_notices)
                                .values(
                                    connector_id=pr.connector_id,
                                    repo=pr.repo,
                                    number=pr.number,
                                    report_id=report_id,
                                )
                                .on_conflict_do_nothing()
                                .returning(t.github_tamper_notices.c.report_id)
                            ).scalar_one_or_none()
                            is not None
                        )
                    if new:
                        _r, api = self._api(tenant, pr.connector_id)
                        when = datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")
                        api.call(
                            "POST",
                            f"/repos/{pr.repo}/issues/{pr.number}/comments",
                            json={
                                "body": (
                                    f"**AgentGuard:** the evidence check is now **failing**. The independent "  # noqa: E501
                                    f"verifier reported **{result}** for this tenant's evidence chain "  # noqa: E501
                                    f"(detected {when}, report `{report_id}`). Do not merge until it is "  # noqa: E501
                                    f"investigated: {dashboard_url()}/verification"
                                )
                            },
                        )
                        flipped += 1
            except ActionFailed as exc:
                log(
                    logger,
                    logging.WARNING,
                    "tamper re-evaluation failed",
                    tenant_id=tenant,
                    error_code=exc.code,
                )
        return flipped

    def webhook_health(self, cid: UUID) -> dict[str, Any]:
        with self._engine.connect() as conn:
            rows = conn.execute(
                select(t.github_deliveries)
                .where(t.github_deliveries.c.connector_id == cid)
                .order_by(t.github_deliveries.c.received_at.desc())
                .limit(20)
            ).all()
            prs = conn.execute(
                select(t.github_prs)
                .where(t.github_prs.c.connector_id == cid)
                .order_by(t.github_prs.c.created_at.desc())
                .limit(50)
            ).all()
        return {
            "deliveries": [
                {
                    "event": r.event,
                    "action": r.action,
                    "verified": r.verified,
                    "outcome": r.outcome,
                    "received_at": r.received_at.isoformat().replace("+00:00", "Z"),
                }
                for r in rows
            ],
            "pull_requests": [
                {
                    "repo": p.repo,
                    "number": p.number,
                    "state": p.state,
                    "conclusion": p.conclusion,
                    "html_url": p.html_url,
                    "run_id": str(p.run_id) if p.run_id else None,
                }
                for p in prs
            ],
        }
