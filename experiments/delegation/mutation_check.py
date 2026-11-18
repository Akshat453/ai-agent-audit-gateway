"""Phase 8 mutation check (ADR-0030): remove one delegation / integration guard, run the test
named for it, expect that test to FAIL, restore the file.

    uv run python experiments/delegation/mutation_check.py      (from the repo root)
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

G = Path("apps/gateway/src/agw_gateway")
TOKEN, SVC = G / "delegation/token.py", G / "delegation/service.py"
ENGINE, EXECUTOR = G / "policies/engine.py", G / "execution/executor.py"
APPROVALS, ACTIONS = G / "approvals/service.py", G / "execution/service.py"
AUTH, EXCHANGE = G / "auth/service.py", G / "auth/exchange.py"
EXTERNAL = G / "tools/adapters/external.py"
SDK = Path("packages/gateway-sdk/src/agw_sdk/client.py")
MCP = Path("integrations/mcp/src/agw_mcp/server.py")
T = "apps/gateway/tests/e2e"
UNIT = "apps/gateway/tests/unit/test_delegation_units.py"
D, S, MC, EX = (
    f"{T}/test_delegation.py",
    f"{T}/test_sdk.py",
    f"{T}/test_mcp_adapter.py",
    f"{T}/test_external_adapters.py",
)

M: list[tuple[str, Path, str | list[str], str, str]] = [
    ("token signature verified", TOKEN,
     "Ed25519PublicKey.from_public_bytes(public).verify(signature, _SIG + claims_cbor)", "pass",
     f"{UNIT}::test_widened_scopes_resigned_with_another_key_is_rejected"),
    ("token must be the issued one (hash)", SVC,
     "if token_hash is not None and not hashes_equal(bytes(leaf.token_hash), token_hash):",
     "if False:", f"{D}::test_tampered_and_forged_tokens_denied"),
    ("token only for its child agent (claims + chain)", SVC,
     ["if c.tenant != agent.tenant_id or c.subject != agent.agent_id:",
      "if leaf.child_agent_id != agent.agent_id or any(\n"
      "            r.tenant_id != agent.tenant_id for r in rows\n        ):"],
     "if False:", f"{D}::test_token_presented_by_another_agent_denied"),
    ("revocation (any ancestor)", SVC,
     "if any(r.revoked_at is not None for r in rows):", "if False:",
     f"{D}::test_root_revocation_cascades_to_subdelegation"),
    ("expiry (any link)", SVC, "if any(r.expired for r in rows):", "if False:",
     f"{D}::test_expired_token_denied"),
    ("use count checked at resolve", SVC,
     "if for_use and any(int(r.uses) >= int(r.max_uses) for r in rows):", "if False:",
     f"{D}::test_over_used_token_denied"),
    ("use consumed atomically in tx1", SVC,
     "        return len(rows) == len(chain)", "        return True",
     f"{D}::test_concurrent_over_use_never_exceeds_max_uses"),
    ("depth limit at use", SVC, "        if depth > self.max_depth:\n", "        if False:\n",
     f"{D}::test_depth_limit_at_issue_and_at_use"),
    ("depth limit at issue", SVC,
     "if parent.constraint.depth + 1 > self.max_depth:", "if False:",
     f"{D}::test_depth_limit_at_issue_and_at_use"),
    ("issuers' CURRENT scopes intersected", SVC,
     "scopes &= frozenset(r.scopes) & frozenset(r.issuer_scopes)", "scopes &= frozenset(r.scopes)",
     f"{D}::test_parent_scope_reduced_child_loses_it_immediately"),
    ("never expansion at issue", SVC, "not set(scopes) <= base_scopes", "False",
     f"{D}::test_parent_cannot_delegate_a_scope_it_lacks"),
    ("refused delegation is evidence", SVC,
     "            self._record_refusal(issuer, req, exc.code)\n", "",
     f"{D}::test_parent_cannot_delegate_a_scope_it_lacks"),
    ("policy: chain must cover the scope", ENGINE,
     "if inp.tool.required_scope not in d.scopes:", "if False:",
     f"{D}::test_child_using_a_scope_the_chain_lacks_is_denied"),
    ("policy: tool allowlist", ENGINE, "if inp.tool.tool_id not in d.tools:", "if False:",
     f"{D}::test_tool_outside_allowlist_and_risk_above_cap_denied"),
    ("policy: max risk cap", ENGINE,
     "if d is not None and _LEVELS.index(risk.level.name) > _LEVELS.index(d.max_risk):",
     "if False:", f"{D}::test_tool_outside_allowlist_and_risk_above_cap_denied"),
    ("pre-dispatch chain re-check", EXECUTOR,
     "if action.delegation_id is not None and not self._delegation_live(conn, action, spec):",
     "if False:", f"{D}::test_parent_scope_reduced_child_loses_it_immediately"),
    ("approval-time chain re-check", APPROVALS,
     "constraint = self._delegations.recheck(conn, action.delegation_id, agent).constraint",
     "constraint = None", f"{D}::test_revocation_while_pending_approval_blocks_authorization"),
    ("child request hash-linked to DELEGATION_CREATED", ACTIONS,
     '        requested["refs"] = {"parent": resolved.created_event_hash}\n', "",
     f"{D}::test_evidence_links_child_actions_to_the_delegation"),
    ("gateway refuses audience-bound (MCP) keys", AUTH,
     "            or row.audience is not None\n", "",
     f"{MC}::test_only_tokens_for_this_resource_are_accepted"),
    ("exchange checks the token's audience", EXCHANGE,
     "                or row.audience != client.audience\n", "",
     f"{MC}::test_only_tokens_for_this_resource_are_accepted"),
    ("exchanged token dies with its subject key", AUTH,
     "            or row.revoked_at is not None\n            or not row.cred_live\n",
     "            or not row.cred_live\n", f"{MC}::test_revoked_agent_key_stops_immediately"),
    ("MCP: pending approval is an error result", MCP,
     "        structured_content=body,\n        is_error=True,",
     "        structured_content=body,\n        is_error=False,",
     f"{MC}::test_call_completed_denied_and_pending_approval"),
    ("SDK: one idempotency key per logical call", SDK,
     'headers={"Idempotency-Key": key}', 'headers={"Idempotency-Key": f"sdk-{uuid.uuid4()}"}',
     f"{S}::test_retry_after_lost_response_replays_one_action"),
    ("public_api_get allowlist at validation", EXTERNAL,
     '                raise ValueError("host not allowlisted")\n', "                pass\n",
     f"{EX}::test_public_api_get_off_allowlist_denied_without_io"),
    ("public_api_get never follows redirects", EXTERNAL,
     "follow_redirects=False", "follow_redirects=True",
     f"{EX}::test_public_api_get_does_not_follow_redirects_and_caps_size"),
]  # fmt: skip

caught = 0
lines = []
for name, path, old, new, test in M:
    src = path.read_text()
    mutated = src
    for o in [old] if isinstance(old, str) else old:  # several sites = one redundant guard
        assert mutated.count(o) == 1, (name, mutated.count(o))
        mutated = mutated.replace(o, new)
    path.write_text(mutated)
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
    line = f"{'CAUGHT ' if ok else 'SURVIVED'}  {name:<48} {test.split('::')[1]}"
    print(line, flush=True)
    lines.append(line)
summary = f"{caught}/{len(M)} mutations caught"
print(summary)
Path("experiments/delegation/results/mutations.txt").write_text("\n".join([*lines, summary]) + "\n")
sys.exit(0 if caught == len(M) else 1)
