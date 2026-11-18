"""Phase 5 mutation check (ADR-0027): remove one guard, run its named test, expect failure,
restore the file. Run from the repo root: uv run python experiments/approvals/mutation_check.py"""

import subprocess
import sys
from pathlib import Path

SVC = Path("apps/gateway/src/agw_gateway/approvals/service.py")
ROUTES = Path("apps/gateway/src/agw_gateway/api/approval_routes.py")
A = "apps/gateway/tests/e2e/test_approval_attacks.py"
W = "apps/gateway/tests/e2e/test_approvals.py"
M = [
    (
        "digest recompute check",
        SVC,
        "        if not (\n            hmac.compare_digest(binding, bytes(ap.action_digest))",
        "        if False and not (\n            hmac.compare_digest(binding, bytes(ap.action_digest))",
        f"{A}::test_alter_after_approval_is_digest_mismatch",
    ),
    (
        "echo check",
        SVC,
        "                if not (\n                    _hex_eq(echoed_digest",
        "                if False and not (\n                    _hex_eq(echoed_digest",
        f"{A}::test_forged_decisions_rejected",
    ),
    (
        "APPROVED-only authorize",
        SVC,
        'if ap is None or ap.state != "APPROVED":',
        'if ap is None or ap.state not in ("APPROVED", "CONSUMED"):',
        f"{A}::test_twenty_concurrent_dispatch_attempts_one_execution",
    ),
    (
        "nonce single-use row",
        SVC,
        "        conn.execute(\n            insert(t.approval_uses)",
        "        False and conn.execute(\n            insert(t.approval_uses)",
        f"{A}::test_replay_consumed_approval_for_identical_request",
    ),
    (
        "expiry at decision",
        SVC,
        "            if not ap.live:\n                self._expire(conn, ap, action)\n                expired = True",
        "            if False:\n                self._expire(conn, ap, action)\n                expired = True",
        f"{A}::test_expired_approval_rejected",
    ),
    (
        "expiry at authorize",
        SVC,
        "            if not ap.live:\n                self._expire(conn, ap, action)\n                result =",
        "            if False:\n                self._expire(conn, ap, action)\n                result =",
        f"{A}::test_expired_approval_rejected",
    ),
    (
        "tenant check",
        SVC,
        "if action is None or action.tenant_id != ap.tenant_id:",
        "if action is None:",
        f"{A}::test_cross_tenant_approval_rejected",
    ),
    (
        "action still pending",
        SVC,
        '        if action.status != "PENDING_APPROVAL":\n            self._set_approval(conn, ap.approval_id, "INVALIDATED", "ACTION_NOT_PENDING")',
        '        if False:\n            self._set_approval(conn, ap.approval_id, "INVALIDATED", "ACTION_NOT_PENDING")',
        f"{A}::test_replay_consumed_approval_for_identical_request",
    ),
    (
        "signature verification",
        SVC,
        "                public_raw is not None\n                and hmac.compare_digest(dd, bytes(r.decision_digest))\n                and verify_decision(public_raw, dd, bytes(r.signature))",
        "                True",
        f"{A}::test_forged_decisions_rejected",
    ),
    (
        "re-evaluation DENY",
        SVC,
        'if decision.effect == "DENY":',
        "if False:",
        f"{A}::test_policy_tightened_between_approval_and_dispatch",
    ),
    (
        "risk increase",
        SVC,
        "if LEVEL_ORDER.index(decision.risk.level.name) > LEVEL_ORDER.index(action.risk_level):",
        "if False:",
        f"{A}::test_risk_increase_after_approval_requires_new_approval",
    ),
    (
        "agent active",
        SVC,
        'if agent_row.status != "active":',
        "if False:",
        f"{A}::test_scope_revoked_or_agent_disabled_between_approval_and_dispatch",
    ),
    (
        "four-eyes",
        SVC,
        'return 2 if (level == "CRITICAL" and self.four_eyes_critical) else 1',
        "return 1",
        f"{A}::test_four_eyes_same_person_twice_not_satisfied",
    ),
    (
        "approver role",
        SVC,
        'if not human.has("approver"):',
        "if False:",
        f"{W}::test_auditor_can_view_but_not_decide",
    ),
    (
        "agent-on-human 403 + record",
        ROUTES,
        "        except AuthenticationFailed:\n            raise HumanAuthFailed from None",
        "        except AuthenticationFailed:\n            raise HumanAuthFailed from None\n        raise HumanAuthFailed",
        f"{A}::test_agent_credential_on_approval_endpoints",
    ),
    (
        "enough signed approvers",
        SVC,
        "if len(decs) < ap.required_approvals:",
        "if False:",
        f"{A}::test_forged_decisions_rejected",
    ),
    (
        "signer required to decide",
        SVC,
        "        if self._signer is None:\n            # Fail closed",
        "        if False:\n            # Fail closed",
        f"{W}::test_signing_key_unavailable_fails_closed",
    ),
]
caught = 0
for name, path, old, new, test in M:
    src = path.read_text()
    assert src.count(old) == 1, (name, src.count(old))
    path.write_text(src.replace(old, new))
    try:
        r = subprocess.run(
            ["uv", "run", "pytest", "-q", "-x", "-p", "no:cacheprovider", test],  # noqa: S607
            capture_output=True,
            text=True,
            check=False,
        )
    finally:
        path.write_text(src)
    ok = r.returncode != 0
    caught += ok
    print(f"{'CAUGHT ' if ok else 'SURVIVED'}  {name:<32} {test.split('::')[1]}")
print(f"{caught}/{len(M)} mutations caught")
sys.exit(0 if caught == len(M) else 1)
