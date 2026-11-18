"""C2 mutation check: remove one connector / identity / repo-policy / CLI guard at a time; its
named test must FAIL. Run: ``uv run python apps/gateway/tests/c2_mutation_check.py``.
Every file is restored byte-identical afterwards (checked)."""

from __future__ import annotations

import hashlib
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
GW = REPO / "apps/gateway/src/agw_gateway"
CLI = REPO / "packages/agw-cli/src/agw_cli"
CON = "apps/gateway/tests/e2e/test_connectors.py"
IDT = "apps/gateway/tests/e2e/test_c2_identity.py"
REP = "apps/gateway/tests/e2e/test_repo_policy.py"
SSRF = "apps/gateway/tests/unit/test_ssrf.py"
INIT = "packages/agw-cli/tests/test_agw_cli_init.py"

MUTATIONS = [
    ("unclassified actions are denied", GW / "connectors/constraint.py",
     "    if entry is None:\n", "    if False:\n",
     f"{CON}::test_new_connector_actions_are_denied_until_classified"),
    ("superseded classification versions are not callable", GW / "connectors/tools.py",
     "if requested != ver and (current_only or requested > ver):", "if False:",
     f"{CON}::test_new_connector_actions_are_denied_until_classified"),
    ("connector changes need a recent step-up", GW / "connectors/service.py",
     "        if age is None or age > self._window:\n            raise StepUpRequired\n", "",
     f"{CON}::test_admin_step_up_and_evidence_for_every_change"),
    ("credentials are sealed (Phase 7 envelope)", GW / "connectors/service.py",
     "        return self._cipher.seal_json(ctx, _secret_dump(creds))",
     "        import json as _j\n\n        return _j.dumps(_secret_dump(creds)).encode()",
     f"{CON}::test_credentials_are_write_only_canary"),
    ("SSRF: every resolved address must be public", GW / "connectors/ssrf.py",
     "if not all(ip_is_public(ip) for ip in ips):", "if False:",
     f"{SSRF}::test_dns_rebinding_any_private_answer_blocks"),
    ("SSRF: redirects are not followed", GW / "connectors/ssrf.py",
     "if 300 <= resp.status_code < 400:", "if False:",
     f"{SSRF}::test_redirects_are_not_followed"),
    ("SSRF: the connection is pinned to the validated IP", GW / "connectors/ssrf.py",
     'netloc = f"[{ip}]" if ":" in ip else ip', "netloc = target.host",
     f"{SSRF}::test_connection_is_pinned_to_the_validated_ip"),
    ("repo yaml cannot loosen (allow_* -> proposal)", GW / "coding/repos.py",
     'loosen.append({"op": f"add_{key[:-1]}", "value": v})', "new[key].append(v)",
     f"{REP}::test_tighten_applies_loosen_becomes_proposal"),
    ("OAuth: PKCE S256 verifier must match", GW / "mcp_remote/oauth.py",
     'and challenge.rstrip(b"=").decode() == row.code_challenge', "",
     f"{IDT}::test_oauth_code_flow_guards"),
    ("MCP: tokens are bound to this resource", GW / "mcp_remote/oauth.py",
     "or row.resource != self.resource  # audience: tokens for another resource are refused", "",
     f"{IDT}::test_token_bound_to_resource_and_active_device"),
    ("device code: only pending, unexpired requests can be approved", GW / "enrollment.py",
     'if row.status != "pending" or not row.live:', "if False:",
     f"{IDT}::test_device_code_login_flow"),
    ("agw init never overwrites an existing file silently", CLI / "commands/init.py",
     "ok = yes or (", "ok = True or (",
     f"{INIT}::test_existing_user_config_is_preserved_and_needs_confirmation"),
    ("agw uninstall keeps files the user edited", CLI / "commands/uninstall.py",
     "            if same:", "            if True:",
     f"{INIT}::test_existing_user_config_is_preserved_and_needs_confirmation"),
]  # fmt: skip


def main() -> int:
    caught = 0
    for name, path, original, mutated, test in MUTATIONS:
        text = path.read_text()
        if original not in text:
            print(f"SETUP ERROR: guard text not found for {name!r}")
            return 2
        before = hashlib.sha256(text.encode()).hexdigest()
        path.write_text(text.replace(original, mutated, 1))
        try:
            r = subprocess.run(
                [sys.executable, "-m", "pytest", "-q", "-x", "-p", "no:cacheprovider", test],
                cwd=REPO, capture_output=True, text=True, check=False,
            )  # fmt: skip
        finally:
            path.write_text(text)
        assert hashlib.sha256(path.read_bytes()).hexdigest() == before, f"{path} not restored"
        ok = r.returncode != 0
        caught += ok
        print(f"{'CAUGHT ' if ok else 'MISSED '} {name}  ->  {test.split('::')[1]}")
    print(f"{caught}/{len(MUTATIONS)} guard removals caught; all files restored byte-identical")
    return 0 if caught == len(MUTATIONS) else 1


if __name__ == "__main__":
    sys.exit(main())
