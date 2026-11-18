"""Phase 9 mutation check (ADR-0031): remove one dashboard-API / step-up / reconciliation /
monitoring / tracing guard, run the test named for it, expect it to FAIL, restore the file.
(The browser-side guards - CSRF, cookie flags, CSP, escaping - are covered by Playwright.)

    uv run python experiments/monitoring/mutation_check.py      (from the repo root)
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

G = Path("apps/gateway/src/agw_gateway")
APPROVALS, DASH = G / "approvals/service.py", G / "api/dashboard_routes.py"
RECON, TRACING = G / "execution/manual_reconcile.py", G / "tracing.py"
MON = Path("apps/worker/src/agw_worker/monitoring/monitor.py")
T = "apps/gateway/tests/e2e"
D, M = f"{T}/test_dashboard_api.py", f"{T}/test_monitoring.py"

MUTATIONS: list[tuple[str, Path, str, str, str]] = [
    ("CRITICAL approve needs step-up", APPROVALS,
     'if decision == "APPROVE" and action.risk_level in self._config.step_up_levels:',
     "if False:", f"{D}::test_critical_approval_needs_step_up"),
    ("step-up window enforced", APPROVALS,
     "if age is None or age > self._config.step_up_window_seconds:", "if age is None:",
     f"{D}::test_critical_approval_needs_step_up"),
    ("bundle download: auditor/admin only", DASH,
     '"""Evidence bundle (header + proof + epochs + anchor claim) WITHOUT the payload."""\n'
     '    _require(human, "auditor", "admin")',
     '"""Evidence bundle (header + proof + epochs + anchor claim) WITHOUT the payload."""',
     f"{D}::test_auditor_cannot_approve_and_approver_cannot_read_payloads"),
    ("verifier job: auditor/admin only", DASH,
     '    _require(human, "auditor", "admin")\n    rid = uuid7()', "    rid = uuid7()",
     f"{M}::test_dashboard_requested_run"),
    ("run timeline tenant-scoped", DASH,
     ".where(ev.c.tenant_id == tenant, ev.c.run_id == run_id)", ".where(ev.c.run_id == run_id)",
     f"{D}::test_tenant_scoping"),
    ("reconcile: admin only", RECON, '        if not human.has("admin"):\n            raise RoleRequired\n',
     "", f"{D}::test_reconcile_outcome_unknown"),
    ("reconcile: only OUTCOME_UNKNOWN, once", RECON,
     'if action.status != "OUTCOME_UNKNOWN":', "if False:", f"{D}::test_reconcile_outcome_unknown"),
    ("monitor: chain result counts", MON, "        results.append(chain.result)\n", "",
     f"{M}::test_tamper_in_unsealed_tail_detected_by_chain"),
    ("monitor: alert delivered to webhook", MON,
     "r = client.post(self._cfg.webhook_url, content=body, headers=headers)",
     "r = httpx.Response(204)",
     f"{M}::test_db_tamper_detected_within_one_cycle_and_alerted"),
    ("monitor: anchor root compared", MON,
     "if int(a.epoch_no) in db_roots and bytes(a.root) != db_roots[int(a.epoch_no)]",
     "if False", f"{M}::test_anchor_root_mismatch_alert"),
    ("monitor: report digest in the header", MON, '"digest": digest,', '"digest": bytes(32),',
     f"{M}::test_clean_tenant_verifies_and_report_is_evidence"),
    ("monitor: age thresholds in ms", MON,
     'ops["oldest_unsealed_ms"] > cfg.unsealed_alert_seconds * 1000',
     'ops["oldest_unsealed_ms"] > cfg.unsealed_alert_seconds',
     f"{M}::test_no_age_alerts_below_thresholds"),
    ("tracing: exporter drops non-allowlisted attributes", TRACING,
     "attributes=_clean(s.attributes),", "attributes=s.attributes,",
     f"{D}::test_tracing_allowlist"),
]  # fmt: skip

caught, lines = 0, []
for name, path, old, new, test in MUTATIONS:
    src = path.read_text()
    assert src.count(old) == 1, (name, src.count(old))
    path.write_text(src.replace(old, new))
    try:
        r = subprocess.run(
            ["uv", "run", "pytest", "-q", "-x", "-p", "no:cacheprovider", test],  # noqa: S607
            capture_output=True, text=True, check=False,
        )  # fmt: skip
    finally:
        path.write_text(src)
    ok = r.returncode != 0
    caught += ok
    line = f"{'CAUGHT ' if ok else 'SURVIVED'}  {name:<50} {test.split('::')[1]}"
    print(line, flush=True)
    lines.append(line)
summary = f"{caught}/{len(MUTATIONS)} mutations caught"
print(summary)
Path("experiments/monitoring/results/mutations.txt").write_text("\n".join([*lines, summary]) + "\n")
sys.exit(0 if caught == len(MUTATIONS) else 1)
