"""Monitoring service (Phase 9, ADR-0031 §3; Paper A §5 monitoring evidence stream).

Each cycle, for every tenant (except ``_monitor`` itself):

1. Export the chain (headers only, no payloads) and the epochs exactly as an auditor would,
   and verify them with the INDEPENDENT verifier (``agw_verifier``: chain links, stored hashes,
   gaps, epoch tiling, Merkle roots, epoch-root chaining). The monitor runs the same code a
   third party runs; it does not trust its own DB reads.
2. Anchors: DB anchor rows must carry the DB epoch root (else ANCHOR_ROOT_MISMATCH); with a
   chain RPC configured, the epochs are also checked ON-CHAIN against the pinned identity.
3. Operational checks: oldest unsealed event, oldest sealed-but-unfinalized epoch,
   OUTCOME_UNKNOWN actions, oldest pending approval, sequence gaps.
4. Record: VERIFICATION_REPORT in the ``_monitor`` tenant chain (header commits to the report
   digest; the full report is the encrypted payload), plus ``monitor_reports`` /
   ``monitor_alerts`` rows - one transaction.
5. Alerts: structured log + optional webhook (HMAC-SHA256 ``X-AGW-Signature``), with a
   per-(tenant, kind) cool-down.

A report proves what the monitor checked and found, not that the recorded actions were
correct (Paper A §5).
"""

from __future__ import annotations

import hashlib
import hmac
import io
import json
import logging
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, Final
from uuid import UUID

import httpx
from sqlalchemy import Engine, func, select, text, update

from agw_gateway.crypto.canonical import encode, profile_value
from agw_gateway.crypto.tags import MONITOR_REPORT_TAG, domain_tag
from agw_gateway.db import tables as t
from agw_gateway.evidence import EvidenceWriter, NewEvent
from agw_gateway.evidence.bundle import export_epochs
from agw_gateway.evidence.export import export_chain
from agw_gateway.evidence.sealed import stored_copy_ok
from agw_gateway.ids import uuid7
from agw_gateway.logs import log
from agw_gateway.tracing import span
from agw_verifier import STATEMENT
from agw_verifier.anchor import ChainUnavailable, ChainView, Rpc, TrustConfigError, make_trust
from agw_verifier.chain import verify_lines
from agw_verifier.epochs import verify_epochs, verify_epochs_on_chain
from agw_worker.monitoring.metrics import (
    MONITOR_ALERTS,
    MONITOR_OLDEST_PENDING_APPROVAL,
    MONITOR_OLDEST_UNANCHORED,
    MONITOR_OLDEST_UNSEALED,
    MONITOR_OUTCOME_UNKNOWN,
    MONITOR_RUNS,
)

logger = logging.getLogger("agw.monitor")
MONITOR_TENANT: Final = "_monitor"
REPORT_FORMAT: Final = "agw-monitor-report/v1"
_PREFIX: Final = domain_tag(MONITOR_REPORT_TAG)
# worst first: the report's result is the worst of its parts
_SEVERITY: Final = (
    "TAMPERED",
    "INVALID_PROOF",
    "UNTRUSTED_ANCHOR",
    "INCOMPLETE",
    "ERROR",
    "UNANCHORED",
    "VERIFIED",
)
CRITICAL_KINDS: Final = frozenset({"VERIFICATION_FAILED", "ANCHOR_ROOT_MISMATCH", "SEQUENCE_GAP"})
MAX_LISTED_SEQS: Final = 20


def report_digest(report: dict[str, Any]) -> bytes:
    return hashlib.sha256(_PREFIX + encode(profile_value(report))).digest()


def _stored_copies(conn: Any, tenant: str, from_seq: int) -> dict[str, Any]:
    """Compare every event's ``body`` / indexed columns with its sealed canonical bytes."""
    ev = t.evidence_events
    bad: list[int] = []
    checked = 0
    rows = conn.execution_options(stream_results=True, yield_per=2000).execute(
        select(
            ev.c.seq,
            ev.c.event_type,
            ev.c.action_id,
            ev.c.run_id,
            ev.c.body,
            ev.c.canonical_bytes,
        )
        .where(ev.c.tenant_id == tenant, ev.c.seq >= from_seq)
        .order_by(ev.c.seq)
    )
    for r in rows:
        checked += 1
        if not stored_copy_ok(
            bytes(r.canonical_bytes),
            r.body,
            tenant_id=tenant,
            seq=int(r.seq),
            event_type=r.event_type,
            action_id=r.action_id,
            run_id=r.run_id,
        ):
            bad.append(int(r.seq))
    return {
        "result": "TAMPERED" if bad else "VERIFIED",
        "events_checked": checked,
        "mismatched": len(bad),
        "mismatched_seqs": bad[:MAX_LISTED_SEQS],
    }


def _worst(results: list[str]) -> str:
    return min(results, key=_SEVERITY.index) if results else "VERIFIED"


@dataclass(frozen=True)
class MonitorConfig:
    max_events: int = 200_000
    unanchored_alert_seconds: float = 900.0
    unsealed_alert_seconds: float = 900.0
    approval_queue_alert_seconds: float = 900.0
    alert_cooldown_seconds: float = 900.0
    webhook_url: str | None = None
    webhook_secret: str | None = None
    chain_rpc_url: str | None = None
    finality: str = "latest"


@dataclass
class TenantReport:
    tenant: str
    report: dict[str, Any]
    alerts: list[dict[str, Any]] = field(default_factory=list)
    report_id: UUID | None = None
    event_id: UUID | None = None

    @property
    def result(self) -> str:
        return str(self.report["result"])


class Monitor:
    def __init__(
        self,
        *,
        engine: Engine,
        writer: EvidenceWriter,
        config: MonitorConfig,
        http: httpx.Client | None = None,
    ) -> None:
        self._engine = engine
        self._writer = writer
        self._cfg = config
        self._http = http
        # C3 (ADR-0036): called after each recorded report (e.g. the GitHub evidence check).
        self.on_report: Callable[[TenantReport], object] | None = None

    # ---------------------------------------------------------------- loop entry points
    def tick(self) -> int:
        """Worker periodic: dashboard requests first, then the scheduled cycle."""
        return self.process_requests() + len(self.run_once())

    def process_requests(self) -> int:
        """Run queued dashboard requests (``POST /v1/dashboard/verifications``)."""
        done = 0
        while True:
            with self._engine.begin() as conn:
                req = conn.execute(
                    text(
                        "SELECT request_id, tenant_id, requested_by FROM monitor_requests "
                        "WHERE report_id IS NULL AND picked_at IS NULL "
                        "ORDER BY created_at FOR UPDATE SKIP LOCKED LIMIT 1"
                    )
                ).one_or_none()
                if req is None:
                    return done
                conn.execute(
                    update(t.monitor_requests)
                    .where(t.monitor_requests.c.request_id == req.request_id)
                    .values(picked_at=func.now())
                )
            rep = self.verify_and_record(req.tenant_id, trigger="manual", by=req.requested_by)
            with self._engine.begin() as conn:
                conn.execute(
                    update(t.monitor_requests)
                    .where(t.monitor_requests.c.request_id == req.request_id)
                    .values(report_id=rep.report_id)
                )
            done += 1

    def run_once(self, tenants: list[str] | None = None) -> list[TenantReport]:
        if tenants is None:
            with self._engine.connect() as conn:
                tenants = [
                    r
                    for r in conn.execute(select(t.tenants.c.tenant_id)).scalars()
                    if r != MONITOR_TENANT
                ]
        return [self.verify_and_record(tn, trigger="schedule") for tn in tenants]

    # ---------------------------------------------------------------- one tenant
    def verify_and_record(
        self, tenant: str, *, trigger: str, by: str | None = None
    ) -> TenantReport:
        with span("monitor.verify", agw_tenant_id=tenant) as sp:
            rep = self._verify(tenant)
            self._record(rep, trigger=trigger, by=by)
            sp.set_attribute("agw.result", rep.result)
        self._deliver(rep)
        MONITOR_RUNS.labels(rep.result).inc()
        if self.on_report is not None:
            try:
                self.on_report(rep)
            except Exception as exc:
                logging.getLogger("agw.monitor").warning(
                    "report hook failed: %s", type(exc).__name__
                )
        return rep

    def _verify(self, tenant: str) -> TenantReport:
        cfg = self._cfg
        report: dict[str, Any] = {"format": REPORT_FORMAT, "tenant": tenant}
        alerts: list[dict[str, Any]] = []
        results: list[str] = []
        try:
            with self._engine.connect() as conn:
                head = conn.execute(
                    select(t.chain_heads.c.last_seq).where(t.chain_heads.c.tenant_id == tenant)
                ).scalar_one()
                checked_at = conn.execute(select(func.now())).scalar_one()
                from_seq = max(0, int(head) - cfg.max_events + 1)
                epochs_buf = io.StringIO()
                export_epochs(conn, tenant, epochs_buf)
                ops = self._operational(conn, tenant)
                stored = _stored_copies(conn, tenant, from_seq)
                anchor_rows = conn.execute(
                    select(t.anchors.c.epoch_no, t.anchors.c.root, t.anchors.c.status).where(
                        t.anchors.c.tenant_id == tenant
                    )
                ).all()
                db_roots = {
                    int(r.epoch_no): bytes(r.epoch_root)
                    for r in conn.execute(
                        select(t.epochs.c.epoch_no, t.epochs.c.epoch_root).where(
                            t.epochs.c.tenant_id == tenant
                        )
                    )
                }
                recorder = conn.execute(
                    select(t.anchor_recorders).where(t.anchor_recorders.c.tenant_id == tenant)
                ).one_or_none()
            chain_buf = io.StringIO()
            export_chain(self._engine, tenant, chain_buf, from_seq=from_seq, include_payloads=False)
            chain_lines = chain_buf.getvalue().splitlines()
            epoch_lines = epochs_buf.getvalue().splitlines()
        except Exception as exc:
            report.update(result="ERROR", reason=f"EXPORT_FAILED:{type(exc).__name__}")
            alerts.append(_alert("VERIFICATION_FAILED", "critical", reason=report["reason"]))
            return TenantReport(tenant, _finish(report, alerts), alerts)

        report["checked_at"] = checked_at.isoformat().replace("+00:00", "Z")
        report["range"] = {
            "first": from_seq if int(head) >= 0 else None,
            "last": int(head) if int(head) >= 0 else None,
        }
        # (1) chain, then epochs against the events (same functions as `agw-verify`)
        chain = verify_lines(chain_lines)
        report["chain"] = {
            "result": chain.result,
            "reason": chain.reason,
            "first_bad_seq": chain.first_bad_seq,
            "events_checked": chain.events_checked,
            "missing_ranges": [list(r) for r in chain.missing_ranges],
        }
        results.append(chain.result)
        if chain.result == "TAMPERED":
            alerts.append(
                _alert(
                    "VERIFICATION_FAILED",
                    "critical",
                    check="chain",
                    reason=chain.reason,
                    first_bad_seq=chain.first_bad_seq,
                )
            )
        if chain.missing_ranges and from_seq == 0:
            alerts.append(
                _alert("SEQUENCE_GAP", "critical", ranges=[list(r) for r in chain.missing_ranges])
            )
        # (1b) the readable copy and indexed columns must equal the sealed record (ADR-0038):
        # the verifier only sees the hashed bytes, but the screens and queries use the copy.
        report["stored_copy"] = stored
        results.append(stored["result"])
        if stored["result"] == "TAMPERED":
            alerts.append(
                _alert(
                    "VERIFICATION_FAILED",
                    "critical",
                    check="stored_copy",
                    reason="STORED_COPY_MISMATCH",
                    first_bad_seq=stored["mismatched_seqs"][0],
                )
            )
        whole = from_seq == 0
        ep = verify_epochs(epoch_lines, event_lines=chain_lines if whole else None)
        report["epochs"] = {
            "result": ep.result,
            "reason": ep.reason,
            "first_bad_epoch": ep.first_bad_epoch,
            "epochs_checked": ep.epochs_checked,
            "events_checked_against_epochs": whole,
        }
        # Without a trusted root the verifier reports epochs UNANCHORED ("sealed locally").
        # For a tenant WITHOUT anchoring that is the expected state; with anchoring, the
        # on-chain check below decides (or the result stays UNANCHORED if it cannot run).
        if ep.result == "UNANCHORED":
            report["epochs"]["note"] = (
                "epochs verified locally; no anchoring configured for this tenant"
                if recorder is None
                else "epochs verified locally; anchors checked below"
            )
        if ep.result != "UNANCHORED" or recorder is None:
            results.append("VERIFIED" if ep.result == "UNANCHORED" else ep.result)
        elif not cfg.chain_rpc_url:
            results.append("UNANCHORED")
        if ep.result in ("TAMPERED", "INVALID_PROOF"):
            alerts.append(
                _alert(
                    "VERIFICATION_FAILED",
                    "critical",
                    check="epochs",
                    reason=ep.reason,
                    first_bad_epoch=ep.first_bad_epoch,
                )
            )
        # (2) anchors
        mismatched = sorted(
            int(a.epoch_no)
            for a in anchor_rows
            if int(a.epoch_no) in db_roots and bytes(a.root) != db_roots[int(a.epoch_no)]
        )
        anchors: dict[str, Any] = {"rows": len(anchor_rows), "db_root_mismatch": mismatched}
        if mismatched:
            results.append("TAMPERED")
            alerts.append(_alert("ANCHOR_ROOT_MISMATCH", "critical", epochs=mismatched))
        if recorder is not None and cfg.chain_rpc_url and db_roots:
            try:
                trust = make_trust(
                    recorder.chain_id,
                    recorder.contract,
                    bytes(recorder.recorder_id).hex(),
                    cfg.finality,
                )
                onchain = verify_epochs_on_chain(
                    epoch_lines, ChainView(Rpc(cfg.chain_rpc_url, timeout=5.0), trust)
                )
                anchors["on_chain"] = {
                    "result": onchain.result,
                    "reason": onchain.reason,
                    "chain_last_epoch": onchain.chain_last_epoch,
                }
                results.append(onchain.result)
                if onchain.result in ("TAMPERED", "UNTRUSTED_ANCHOR", "INVALID_PROOF"):
                    alerts.append(
                        _alert(
                            "ANCHOR_ROOT_MISMATCH",
                            "critical",
                            check="on_chain",
                            reason=onchain.reason,
                        )
                    )
            except (ChainUnavailable, TrustConfigError) as exc:
                anchors["on_chain"] = {"result": "INCOMPLETE", "reason": str(exc) or "CHAIN"}
        report["anchors"] = anchors
        # (3) operational checks
        report["checks"] = ops
        if (
            ops["oldest_unsealed_ms"]
            and ops["oldest_unsealed_ms"] > cfg.unsealed_alert_seconds * 1000
        ):
            alerts.append(_alert("UNSEALED_AGE", "warning", ms=ops["oldest_unsealed_ms"]))
        if (
            ops["oldest_unanchored_ms"]
            and ops["oldest_unanchored_ms"] > cfg.unanchored_alert_seconds * 1000
        ):
            alerts.append(_alert("UNANCHORED_AGE", "warning", ms=ops["oldest_unanchored_ms"]))
        if ops["outcome_unknown_actions"]:
            alerts.append(
                _alert("OUTCOME_UNKNOWN", "warning", actions=ops["outcome_unknown_actions"])
            )
        if (
            ops["oldest_pending_approval_ms"]
            and ops["oldest_pending_approval_ms"] > cfg.approval_queue_alert_seconds * 1000
        ):
            alerts.append(
                _alert(
                    "APPROVAL_QUEUE_AGE",
                    "warning",
                    ms=ops["oldest_pending_approval_ms"],
                    pending=ops["pending_approvals"],
                )
            )
        report["result"] = _worst(results)
        report["reason"] = next((r for r in (chain.reason, ep.reason) if r), None) or (
            f"ANCHOR_ROOT_MISMATCH:{mismatched}" if mismatched else None
        )
        return TenantReport(tenant, _finish(report, alerts), alerts)

    def _operational(self, conn: Any, tenant: str) -> dict[str, Any]:
        sealed_up_to = conn.execute(
            select(func.coalesce(func.max(t.epochs.c.last_seq), -1)).where(
                t.epochs.c.tenant_id == tenant
            )
        ).scalar_one()
        unsealed = conn.execute(
            select(
                func.extract("epoch", func.now() - func.min(t.evidence_events.c.occurred_at))
            ).where(t.evidence_events.c.tenant_id == tenant, t.evidence_events.c.seq > sealed_up_to)
        ).scalar_one()
        anchoring = conn.execute(
            select(func.count()).where(t.anchor_recorders.c.tenant_id == tenant)
        ).scalar_one()
        unanchored = conn.execute(
            text(
                "SELECT extract(epoch FROM now() - min(e.sealed_at)) FROM epochs e "
                "LEFT JOIN anchors a ON a.tenant_id = e.tenant_id AND a.epoch_no = e.epoch_no "
                "AND a.status = 'FINALIZED' WHERE e.tenant_id = :t AND a.epoch_no IS NULL"
            ),
            {"t": tenant},
        ).scalar_one()
        unknown = conn.execute(
            select(func.count()).where(
                t.actions.c.tenant_id == tenant, t.actions.c.status == "OUTCOME_UNKNOWN"
            )
        ).scalar_one()
        pending = conn.execute(
            select(
                func.count(),
                func.extract("epoch", func.now() - func.min(t.approvals.c.requested_at)),
            ).where(t.approvals.c.tenant_id == tenant, t.approvals.c.state == "PENDING")
        ).one()
        out: dict[str, Any] = {
            "oldest_unsealed_ms": int(float(unsealed) * 1000) if unsealed is not None else None,
            "anchoring_configured": bool(anchoring),
            "oldest_unanchored_ms": (
                int(float(unanchored) * 1000) if anchoring and unanchored is not None else None
            ),
            "outcome_unknown_actions": int(unknown),
            "pending_approvals": int(pending[0]),
            "oldest_pending_approval_ms": (
                int(float(pending[1]) * 1000) if pending[1] is not None else None
            ),
        }
        MONITOR_OLDEST_UNSEALED.set((out["oldest_unsealed_ms"] or 0) / 1000)
        MONITOR_OLDEST_UNANCHORED.set((out["oldest_unanchored_ms"] or 0) / 1000)
        MONITOR_OUTCOME_UNKNOWN.set(out["outcome_unknown_actions"])
        MONITOR_OLDEST_PENDING_APPROVAL.set((out["oldest_pending_approval_ms"] or 0) / 1000)
        return out

    # ---------------------------------------------------------------- record + alert
    def _record(self, rep: TenantReport, *, trigger: str, by: str | None) -> None:
        digest = report_digest(rep.report)
        rng = rep.report.get("range") or {}
        report_id = uuid7()
        header: dict[str, Any] = {
            "tenant": rep.tenant,
            "result": rep.result,
            "digest": digest,
            "alerts": len(rep.alerts),
            "trigger": trigger,
        }
        if rng.get("first") is not None:
            header["first"], header["last"] = int(rng["first"]), int(rng["last"])
        with self._engine.begin() as conn:
            stored = self._writer.append(
                conn,
                MONITOR_TENANT,
                [
                    NewEvent(
                        type="VERIFICATION_REPORT",
                        actor_kind="system",
                        actor_id="agw-monitor",
                        fields={"report": header},
                        payload={"report": profile_value(rep.report)},
                        # failures seal (and anchor) at once; routine reports batch
                        risk_level="LOW" if rep.result == "VERIFIED" else "HIGH",
                    )
                ],
            )
            conn.execute(
                t.monitor_reports.insert().values(
                    report_id=report_id,
                    tenant_id=rep.tenant,
                    result=rep.result,
                    first_seq=rng.get("first"),
                    last_seq=rng.get("last"),
                    report=rep.report,
                    report_digest=digest,
                    event_id=stored[0].event_id,
                    trigger=trigger,
                    requested_by=by,
                )
            )
            for a in rep.alerts:
                recent = conn.execute(
                    select(func.count()).where(
                        t.monitor_alerts.c.tenant_id == rep.tenant,
                        t.monitor_alerts.c.kind == a["kind"],
                        t.monitor_alerts.c.created_at
                        > func.now()
                        - func.make_interval(0, 0, 0, 0, 0, 0, self._cfg.alert_cooldown_seconds),
                    )
                ).scalar_one()
                if recent and a["severity"] != "critical":
                    a["suppressed"] = True  # still in the report; not re-delivered
                    continue
                a["alert_id"] = str(uuid7())
                conn.execute(
                    t.monitor_alerts.insert().values(
                        alert_id=UUID(a["alert_id"]),
                        tenant_id=rep.tenant,
                        report_id=report_id,
                        kind=a["kind"],
                        severity=a["severity"],
                        detail=a["detail"],
                        delivered=False,
                    )
                )
        rep.report_id, rep.event_id = report_id, stored[0].event_id

    def _deliver(self, rep: TenantReport) -> None:
        for a in rep.alerts:
            if a.get("suppressed") or "alert_id" not in a:
                continue
            MONITOR_ALERTS.labels(a["kind"]).inc()
            log(
                logger,
                logging.ERROR if a["severity"] == "critical" else logging.WARNING,
                "monitor alert",
                tenant_id=rep.tenant,
                error_code=a["kind"],
                status=a["severity"],
            )
            if not self._cfg.webhook_url:
                continue
            body = json.dumps(
                {
                    "alert_id": a["alert_id"],
                    "tenant": rep.tenant,
                    "kind": a["kind"],
                    "severity": a["severity"],
                    "detail": a["detail"],
                    "report_id": str(rep.report_id),
                    "report_result": rep.result,
                },
                sort_keys=True,
            ).encode()
            headers = {"Content-Type": "application/json"}
            if self._cfg.webhook_secret:
                headers["X-AGW-Signature"] = hmac.new(
                    self._cfg.webhook_secret.encode(), body, hashlib.sha256
                ).hexdigest()
            try:
                client = self._http or httpx.Client(timeout=5.0)
                r = client.post(self._cfg.webhook_url, content=body, headers=headers)
                ok = r.status_code < 300
            except httpx.HTTPError:
                ok = False
            if ok:
                with self._engine.begin() as conn:
                    conn.execute(
                        update(t.monitor_alerts)
                        .where(t.monitor_alerts.c.alert_id == UUID(a["alert_id"]))
                        .values(delivered=True)
                    )


def _alert(kind: str, severity: str, **detail: Any) -> dict[str, Any]:
    return {"kind": kind, "severity": severity, "detail": detail}


def _finish(report: dict[str, Any], alerts: list[dict[str, Any]]) -> dict[str, Any]:
    report["alerts"] = [{"kind": a["kind"], "severity": a["severity"]} for a in alerts]
    report["statement"] = STATEMENT
    return report
