"""C3 mutation check: remove one GitHub connector / evidence-check guard at a time; its named
test must FAIL. Run: ``uv run python apps/gateway/tests/c3_mutation_check.py``.
Every file is restored byte-identical afterwards (checked)."""

from __future__ import annotations

import hashlib
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
GH = REPO / "apps/gateway/src/agw_gateway/github"
E2E = "apps/gateway/tests/e2e/test_github.py"
OPS = "apps/gateway/tests/unit/test_gitops.py"

MUTATIONS = [
    ("check: every PR commit must be recorded by git_submit_change", GH / "checks.py",
     "            if missing:\n", "            if False:\n",
     f"{E2E}::test_full_flow_check_success_then_manual_push_fails"),
    ("check: consumed approval must match the action digest", GH / "checks.py",
     "                        or not hmac.compare_digest(\n"
     "                            bytes(ap.action_digest), bytes(a.action_digest or b\"\")\n"
     "                        )\n",
     "",
     f"{E2E}::test_high_and_critical_diffs_need_routed_approval_and_denies"),
    ("check: TAMPERED/INCOMPLETE monitor report -> failure", GH / "checks.py",
     "if report is not None and report.result in BAD_REPORTS:", "if False:",
     f"{E2E}::test_check_failure_matrix_forged_webhook_polling_and_tamper"),
    ("check: a PR whose commits cannot all be listed fails", GH / "checks.py",
     "if not isinstance(total, int) or total != len(set(shas)):", "if False:",
     f"{E2E}::test_check_failure_matrix_forged_webhook_polling_and_tamper"),
    ("check: fork PRs fail", GH / "checks.py",
     '(head.get("repo") or {}).get("full_name") != repo:', "False:",
     f"{E2E}::test_check_failure_matrix_forged_webhook_polling_and_tamper"),
    ("webhook: X-Hub-Signature-256 must verify", GH / "checks.py",
     "        ok = secret is not None and verify_signature(\n"
     "            secret, raw, headers.get(\"x-hub-signature-256\")\n        )\n",
     "        ok = True\n",
     f"{E2E}::test_check_failure_matrix_forged_webhook_polling_and_tamper"),
    ("submit: protected branches are refused", GH / "actions.py",
     "    if branch in cfg.protected_branches:\n", "    if False:\n",
     f"{E2E}::test_branch_rules_and_change_refusals"),
    ("submit: C1 deny rules on the full diff", GH / "actions.py",
     '    if effect == "deny":\n', "    if False:\n",
     f"{OPS}::test_c1_rules_on_the_full_diff"),
    ("client: only the configured repos", GH / "client.py",
     "        if repo not in self._cfg.repos:\n", "        if False:\n",
     f"{E2E}::test_full_flow_check_success_then_manual_push_fails"),
    ("gitops: path traversal / .git internals refused", GH / "gitops.py",
     "if p is not None and not _safe_path(p):", "if False:",
     f"{OPS}::test_dotgit_tree_entry_in_bundle_is_refused"),
    ("gitops: symlinks may not escape the repo", GH / "gitops.py",
     "            if not _symlink_ok(f.path, target):\n", "            if False:\n",
     f"{OPS}::test_dangerous_paths_are_refused"),
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
