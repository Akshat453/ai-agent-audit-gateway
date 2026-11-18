"""C3: server-side change application (index-only) and its refusals (ADR-0036 §3)."""

from __future__ import annotations

import base64
import os
import subprocess
from pathlib import Path

import pytest

from agw_gateway.coding.policy import CodingPolicy
from agw_gateway.github import gitops
from agw_gateway.github.actions import evaluate_prepared
from tests.githubkit import ENV, LocalGithub, git, local_bundle, local_diff, make_local

pytestmark = pytest.mark.unit
POLICY = CodingPolicy.bundled()


@pytest.fixture
def lg(tmp_path: Path) -> LocalGithub:
    return make_local(tmp_path)


def apply(lg: LocalGithub, fmt: str, base: str, change: bytes) -> gitops.Prepared:
    return gitops.prepare(
        clone_url=f"file://{lg.bare}",
        token=None,
        base_sha=base,
        change_format=fmt,
        change=change,
        message="MR-7: test",
        author=("dev (via AgentGuard)", "dev@x"),
    )


def test_diff_with_rename_delete_binary_and_new_file(lg: LocalGithub) -> None:
    def edit(w: Path) -> None:
        git(w, "mv", "api/src/old_name.ts", "api/src/new_name.ts")
        (w / "README.md").unlink()
        (w / "assets/logo.bin").write_bytes(bytes(reversed(range(256))))
        (w / "api/src/new.ts").write_text("export const n = 2;\n")

    base, diff = local_diff(lg, edit)
    p = apply(lg, "diff", base, diff)
    try:
        st = {f.path: (f.status, f.old_path) for f in p.files}
        assert st["api/src/new_name.ts"] == ("R", "api/src/old_name.ts")
        assert (
            st["README.md"][0] == "D"
            and st["assets/logo.bin"][0] == "M"
            and st["api/src/new.ts"][0] == "A"
        )
        assert len(p.commits) == 1 and len(p.tree_sha) == 40 and len(p.diff_digest) == 32
        assert "GIT binary patch" in p.diff
        assert evaluate_prepared(p, POLICY).deny is False
        # Deterministic: the same change on the same base gives the same tree and diff digest.
        again = apply(lg, "diff", base, diff)
        assert (again.tree_sha, again.diff_digest) == (p.tree_sha, p.diff_digest)
        again.cleanup()
    finally:
        p.cleanup()


def test_bundle_keeps_agent_commits(lg: LocalGithub) -> None:
    base, bundle = local_bundle(
        lg, lambda w: (w / "api/src/csv.ts").write_text("export const a = 2;\n")
    )
    p = apply(lg, "bundle", base, bundle)
    try:
        assert len(p.commits) == 1 and p.head_sha == p.commits[0]
    finally:
        p.cleanup()


def test_conflict_is_refused(lg: LocalGithub) -> None:
    base, diff = local_diff(
        lg, lambda w: (w / "api/src/csv.ts").write_text("export const a = 3;\n")
    )
    lg.manual_push("main", "api/src/csv.ts", "export const a = 99;\n")
    with pytest.raises(gitops.GitError) as exc:
        apply(lg, "diff", lg.main(), diff)  # the diff no longer applies on the new base
    assert exc.value.code == "PATCH_DOES_NOT_APPLY"
    _ = base


@pytest.mark.parametrize(
    ("patch", "code"),
    [
        (
            "diff --git a/../evil b/../evil\nnew file mode 100644\n--- /dev/null\n+++ b/../evil\n@@ -0,0 +1 @@\n+x\n",
            "PATCH_DOES_NOT_APPLY",
        ),
        (
            "diff --git a/.git/hooks/post-checkout b/.git/hooks/post-checkout\nnew file mode 100755\n"
            "--- /dev/null\n+++ b/.git/hooks/post-checkout\n@@ -0,0 +1 @@\n+rm -rf /\n",
            "PATCH_DOES_NOT_APPLY",
        ),
        (
            "diff --git a/link b/link\nnew file mode 120000\n--- /dev/null\n+++ b/link\n@@ -0,0 +1 @@\n"
            "+../../../etc/passwd\n\\ No newline at end of file\n",
            "SYMLINK_ESCAPES_REPO",
        ),
        (
            "diff --git a/abs b/abs\nnew file mode 120000\n--- /dev/null\n+++ b/abs\n@@ -0,0 +1 @@\n"
            "+/etc/passwd\n\\ No newline at end of file\n",
            "SYMLINK_ESCAPES_REPO",
        ),
    ],
)
def test_dangerous_paths_are_refused(lg: LocalGithub, patch: str, code: str) -> None:
    with pytest.raises(gitops.GitError) as exc:
        apply(lg, "diff", lg.main(), patch.encode())
    assert exc.value.code in (code, "PATH_NOT_ALLOWED", "PATCH_DOES_NOT_APPLY")


def test_symlink_inside_repo_is_fine(lg: LocalGithub) -> None:
    def edit(w: Path) -> None:
        os.symlink("../src/csv.ts", w / "api/test/link.ts")

    base, diff = local_diff(lg, edit)
    p = apply(lg, "diff", base, diff)
    try:
        assert any(f.mode == "120000" for f in p.files)
    finally:
        p.cleanup()


def test_submodule_and_large_blob_and_dotgit_in_bundle(lg: LocalGithub) -> None:
    def sub(w: Path) -> None:
        git(w, "update-index", "--add", "--cacheinfo", f"160000,{'a' * 40},vendor/lib")

    base, bundle = local_bundle(lg, sub, stage=False)
    with pytest.raises(gitops.GitError) as exc:
        apply(lg, "bundle", base, bundle)
    assert exc.value.code == "SUBMODULE_NOT_ALLOWED"
    base, bundle = local_bundle(
        lg, lambda w: (w / "big.bin").write_bytes(os.urandom(gitops.MAX_BLOB + 1))
    )
    with pytest.raises(gitops.GitError) as exc:
        apply(lg, "bundle", base, bundle)
    assert exc.value.code == "BLOB_TOO_LARGE"


def test_dotgit_tree_entry_in_bundle_is_refused(lg: LocalGithub, tmp_path: Path) -> None:
    """git apply already refuses ``.git/`` paths; a hand-crafted bundle tree must be refused too."""
    w = tmp_path / "craft"
    git(tmp_path, "clone", "-q", str(lg.bare), str(w))
    base = git(w, "rev-parse", "HEAD").strip()
    blob = git(w, "hash-object", "-w", "--stdin", input_bytes=b"[core]\n").strip()
    inner = git(w, "mktree", input_bytes=f"100644 blob {blob}\tconfig\n".encode()).strip()
    listing = git(w, "ls-tree", "HEAD")
    tree = git(w, "mktree", input_bytes=(listing + f"040000 tree {inner}\t.GIT\n").encode()).strip()
    commit = git(w, "commit-tree", tree, "-p", base, "-m", "crafted").strip()
    git(w, "update-ref", "refs/heads/crafted", commit)
    bundle = subprocess.run(
        ["git", "bundle", "create", "-", f"{base}..crafted"], cwd=w, env=ENV, capture_output=True,
        check=True,
    ).stdout  # fmt: skip
    with pytest.raises(gitops.GitError) as exc:
        apply(lg, "bundle", base, bundle)
    assert exc.value.code == "PATH_NOT_ALLOWED"


def test_bundle_not_on_base_and_garbage(lg: LocalGithub) -> None:
    with pytest.raises(gitops.GitError) as exc:
        apply(lg, "bundle", lg.main(), b"not a bundle")
    assert exc.value.code == "BUNDLE_INVALID"
    with pytest.raises(gitops.GitError) as exc:
        apply(lg, "diff", "0" * 40, b"x")
    assert exc.value.code == "BASE_SHA_UNKNOWN"


def test_token_only_in_environment_never_argv() -> None:
    env = gitops.git_env("ghs_SECRET", Path("/tmp"))
    assert "ghs_SECRET" not in " ".join(k for k in env if not k.startswith("GIT_CONFIG_VALUE"))
    header = next(
        v for k, v in env.items() if k.startswith("GIT_CONFIG_VALUE") and "Authorization" in v
    )
    assert base64.b64decode(header.split()[-1]).decode() == "x-access-token:ghs_SECRET"
    assert env["GIT_CONFIG_GLOBAL"] == os.devnull and env["GIT_TERMINAL_PROMPT"] == "0"


@pytest.mark.parametrize(
    ("edit", "deny", "level", "rule"),
    [
        (
            lambda w: (w / "ledger/src/service.ts").write_text("export const post = 2;\n"),
            False,
            "HIGH",
            "PATH-HIGH",
        ),
        (
            lambda w: (w / ".github/workflows/ci.yml").write_text("jobs: {}\n"),
            True,
            "CRITICAL",
            "CONTENT-CI-DISABLED",
        ),
        (
            lambda w: (w / ".github/workflows/ci.yml").write_text(
                SEEDCI + "      - run: pnpm lint\n"
            ),
            False,
            "CRITICAL",
            "PATH-CRITICAL",
        ),
        (
            lambda w: (w / "signal/src/verify.ts").write_text(
                "export function verifyWebhook() { return true; }\n"
            ),
            True,
            "CRITICAL",
            "CONTENT-SIGNATURE-BYPASS",
        ),
        (
            lambda w: (w / "api/test/fees.test.ts").write_text(
                'it.skip("charges bps", () => {});\n'
            ),
            True,
            "CRITICAL",
            "CONTENT-TEST-SKIP",
        ),
        (lambda w: (w / "api/test/fees.test.ts").unlink(), False, "CRITICAL", "PATH-DELETE-TEST"),
        (
            lambda w: (w / "api/src/k.ts").write_text('const k = "AKIAIOSFODNN7EXAMPLQ";\n'),
            True,
            "CRITICAL",
            "CONTENT-SECRET",
        ),
    ],
)
def test_c1_rules_on_the_full_diff(
    lg: LocalGithub, edit: object, deny: bool, level: str, rule: str
) -> None:
    base, diff = local_diff(lg, edit)  # type: ignore[arg-type]
    p = apply(lg, "diff", base, diff)
    try:
        a = evaluate_prepared(p, POLICY)
        assert a.deny is deny and rule in a.rule_ids, a
        assert a.level == level
        if not deny and level == "CRITICAL":
            assert a.critical_approval and a.approver_role == "security"
        if rule == "PATH-HIGH":
            assert a.approver_role == "ledger_lead"
    finally:
        p.cleanup()


SEEDCI = "jobs:\n  test:\n    steps:\n      - run: pnpm test\n"
