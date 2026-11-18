"""C1 mutation check: remove one coding-security guard at a time; its named test must FAIL.

Run: ``uv run python apps/gateway/tests/coding_mutation_check.py``. Every file is restored
byte-identical afterwards (checked). Not collected by pytest (no ``test_`` prefix).
"""

from __future__ import annotations

import hashlib
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
GW = REPO / "apps/gateway/src/agw_gateway"
CLI = REPO / "packages/agw-cli/src/agw_cli"
E2E = "apps/gateway/tests/e2e/test_coding_api.py"
CLI_E2E = "apps/gateway/tests/e2e/test_coding_cli_e2e.py"
CLI_FC = "packages/agw-cli/tests/test_agw_cli_fail_closed.py"

# (name, file, original text, mutated text, test node that must fail)
MUTATIONS = [
    (
        "balanced: the agent's own guard config always asks",
        GW / "coding/policy.py",
        'if h.rule == "PATH-CRITICAL" and h.tag == "hook-config":\n        return h',
        "if False:\n        return h",
        "apps/gateway/tests/unit/test_coding_balanced.py::test_crucial_local_actions_still_ask",
    ),
    (
        "balanced: git that destroys work still asks",
        GW / "coding/policy.py",
        'return h if h.tag in ("destructive", "delete") else',
        "return h if False else",
        "apps/gateway/tests/unit/test_coding_balanced.py::test_crucial_local_actions_still_ask",
    ),
    (
        "balanced: uploads to non-local hosts stay denied",
        GW / "coding/policy.py",
        "        if upload:\n            return None\n",
        "",
        "apps/gateway/tests/unit/test_coding_balanced.py::test_uploads_and_remote_shells_stay_denied",
    ),
    (
        "approval single use (approval_uses insert)",
        GW / "approvals/service.py",
        '        conn.execute(\n            insert(t.approval_uses).values(\n                nonce=bytes(ap.nonce), approval_id=ap.approval_id, action_id=ap.action_id\n            )\n        )\n        self._set_approval(conn, ap.approval_id, "CONSUMED", None)\n        common = {"action_id": ap.action_id, "run_id": action.run_id, "agent_id": action.agent_id}\n        level = approval_event_level(action.risk_level)\n        self._writer.append(\n            conn,\n            ap.tenant_id,\n            [\n                NewEvent(\n                    type="POLICY_EVALUATED",\n                    actor_kind="gateway",\n                    actor_id=GATEWAY_ACTOR_ID,\n                    fields=policy_fields,',
        '        self._set_approval(conn, ap.approval_id, "APPROVED", None)\n        common = {"action_id": ap.action_id, "run_id": action.run_id, "agent_id": action.agent_id}\n        level = approval_event_level(action.risk_level)\n        self._writer.append(\n            conn,\n            ap.tenant_id,\n            [\n                NewEvent(\n                    type="POLICY_EVALUATED",\n                    actor_kind="gateway",\n                    actor_id=GATEWAY_ACTOR_ID,\n                    fields=policy_fields,',
        f"{E2E}::test_approval_wait_consume_once_replay_and_change",
    ),
    (
        "routed role required to decide",
        GW / "approvals/service.py",
        "            if not human.has(ap.required_role):  # C1: routed approvals (ADR-0034)\n                raise Forbidden\n",
        "",
        f"{E2E}::test_approval_wait_consume_once_replay_and_change",
    ),
    (
        "coding approvals wait for the agent's retry (no registry dispatch)",
        GW / "approvals/service.py",
        "            elif action is not None and is_coding_tool(action.tool_id):",
        "            elif False:",
        f"{E2E}::test_approval_wait_consume_once_replay_and_change",
    ),
    (
        "pending identical retry reuses the approval",
        GW / "coding/service.py",
        '        if prior.state == "PENDING":\n            return self._view(prior.action_id, decision, digest=digest)\n',
        "",
        f"{E2E}::test_approval_wait_consume_once_replay_and_change",
    ),
    (
        "device key only while its developer is active",
        GW / "coding/service.py",
        '        if row is None or row.status != "active" or row.tenant_id != agent.tenant_id:',
        "        if row is None:",
        f"{E2E}::test_disabled_developer_device_is_refused",
    ),
    (
        "session belongs to the device",
        GW / "coding/service.py",
        "            t.coding_sessions.c.device_id == device.agent.agent_id,  # owner only; else 404\n",
        "",
        f"{E2E}::test_identity_and_session_rules",
    ),
    (
        "secret diffs are not stored",
        GW / "coding/service.py",
        '        if req.diff is not None and "CONTENT-SECRET" not in decision.rule_ids:',
        "        if req.diff is not None:",
        f"{E2E}::test_no_diff_or_secret_in_logs_headers_or_payloads",
    ),
    (
        "observe only completes AUTHORIZED actions",
        GW / "coding/service.py",
        '            if row is None or row.status != "AUTHORIZED":',
        "            if row is None:",
        f"{E2E}::test_observe_completes_and_undecided_is_a_violation",
    ),
    (
        "CLI fails closed on internal errors",
        CLI / "commands/hook.py",
        '        verdict = _deny(f"{UNAVAILABLE} (internal error: {type(exc).__name__})")\n    return _render_pre',
        '        verdict = Verdict(True, "", "")\n    return _render_pre',
        f"{CLI_FC}::test_internal_error_blocks",
    ),
    (
        "CLI never maps an unknown tool to a known action",
        CLI / "adapters/claude_code.py",
        '    return PreAction(build(action_type="unknown", incomplete=True, **common))',
        '    return PreAction(build(action_type="file_read", **common))',
        "packages/agw-cli/tests/test_agw_cli_hooks.py::test_unknown_tool_is_never_allowed_silently",
    ),
    (
        "CLI waits for approval, then retries identically",
        CLI / "commands/hook.py",
        '            if state == "APPROVED":',
        '            if state == "NEVER":',
        f"{CLI_E2E}::test_human_approval_while_hook_waits_then_retry_consumes_once",
    ),
]


def digest(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def main() -> int:
    caught = 0
    for name, path, original, mutated, test in MUTATIONS:
        text = path.read_text()
        if original not in text:
            print(f"SETUP ERROR: guard text not found for {name!r}")
            return 2
        before = digest(path)
        path.write_text(text.replace(original, mutated, 1))
        try:
            r = subprocess.run(
                [sys.executable, "-m", "pytest", "-q", "-x", "-p", "no:cacheprovider", test],
                cwd=REPO,
                capture_output=True,
                text=True,
                check=False,
            )
        finally:
            path.write_text(text)
        assert digest(path) == before, f"{path} not restored"
        ok = r.returncode != 0
        caught += ok
        print(f"{'CAUGHT ' if ok else 'MISSED '} {name}  ->  {test.split('::')[1]}")
    print(f"{caught}/{len(MUTATIONS)} guard removals caught; all files restored byte-identical")
    return 0 if caught == len(MUTATIONS) else 1


if __name__ == "__main__":
    sys.exit(main())
