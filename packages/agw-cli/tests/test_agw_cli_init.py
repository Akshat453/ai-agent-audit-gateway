"""C2: ``agw init`` golden tests on fixture repositories (a skeleton of MintRail built from its
tracked file names, a Python repo, an empty repo) for every agent, plus dry-run, idempotency,
user-content preservation and ``agw uninstall`` removing only what init added.

Regenerate the golden files after an intended change: ``AGW_UPDATE_GOLDEN=1 pytest …``.
"""

from __future__ import annotations

import argparse
import json
import os
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from agw_cli.commands import init as init_cmd
from agw_cli.commands import uninstall as uninstall_cmd
from agw_cli.wiring import AGENT_KINDS

pytestmark = pytest.mark.unit
HERE = Path(__file__).parent
GOLDEN = HERE / "golden_init"
GW = "https://agentguard.test"
UPDATE = os.environ.get("AGW_UPDATE_GOLDEN") == "1"


def git(root: Path, remote: str | None) -> None:
    (root / ".git" / "refs" / "heads").mkdir(parents=True)
    (root / ".git" / "HEAD").write_text("ref: refs/heads/main\n")
    (root / ".git" / "refs" / "heads" / "main").write_text("e" * 40 + "\n")
    if remote:
        (root / ".git" / "config").write_text(f'[remote "origin"]\n\turl = {remote}\n')


def mintrail(root: Path) -> None:
    for rel in (HERE / "fixtures" / "mintrail-files.txt").read_text().splitlines():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("")
    git(root, "https://github.com/Akshat453/MintRail.git")


def python_repo(root: Path) -> None:
    for rel in (
        "pyproject.toml",
        "uv.lock",
        "src/shop/__init__.py",
        "src/shop/billing/charge.py",
        "src/shop/auth.py",
        "src/shop/views.py",
        "migrations/0001_init.py",
        "tests/test_views.py",
        ".github/workflows/ci.yml",
        "CODEOWNERS",
    ):
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        (root / rel).write_text("")
    git(root, "git@github.com:acme/shop.git")


def empty_repo(root: Path) -> None:
    git(root, None)


REPOS = {"mintrail": mintrail, "python": python_repo, "empty": empty_repo}


@pytest.fixture
def env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("AGW_HOME", str(home / ".agentguard"))
    monkeypatch.setenv("AGW_CONFIG", str(home / "config.toml"))
    (home / "config.toml").write_text(f'url = "{GW}"\n')
    monkeypatch.delenv("AGW_DEVICE_KEY", raising=False)
    monkeypatch.setattr(init_cmd, "installed_agents", lambda: [])
    yield tmp_path


def make(env: Path, name: str, monkeypatch: pytest.MonkeyPatch) -> Path:
    root = env / name
    root.mkdir()
    REPOS[name](root)
    monkeypatch.chdir(root)
    return root


def snapshot(root: Path) -> dict[str, str]:
    out = {}
    for p in sorted(root.rglob("*")):
        if p.is_file() and ".git" not in p.relative_to(root).parts:
            out[p.relative_to(root).as_posix()] = p.read_text(errors="replace")
    return out


def run_init(*argv: str) -> tuple[int, str]:
    lines: list[str] = []
    ns = argparse.Namespace(
        dry_run="--dry-run" in argv,
        agents=None,
        devcontainer="--devcontainer" in argv,
        yes="--yes" in argv,
        url=None,
    )
    for i, a in enumerate(argv):
        if a == "--agents":
            ns.agents = argv[i + 1]
    rc = init_cmd.main(ns, out=lines.append)
    return rc, "\n".join(lines)


def run_uninstall(dry: bool = False) -> tuple[int, str]:
    lines: list[str] = []
    rc = uninstall_cmd.main(argparse.Namespace(dry_run=dry), out=lines.append)
    return rc, "\n".join(lines)


@pytest.mark.parametrize("repo", sorted(REPOS))
@pytest.mark.parametrize("agent", AGENT_KINDS)
def test_golden(env: Path, monkeypatch: pytest.MonkeyPatch, repo: str, agent: str) -> None:
    root = make(env, repo, monkeypatch)
    before = snapshot(root)
    rc, out = run_init("--agents", agent, "--yes")
    assert rc == 0, out
    after = snapshot(root)
    written = {k: v for k, v in after.items() if before.get(k) != v}
    golden = GOLDEN / f"{repo}__{agent}.json"
    if UPDATE or not golden.exists():
        golden.write_text(json.dumps(written, indent=2, sort_keys=True) + "\n")
    assert written == json.loads(golden.read_text()), f"golden mismatch: {golden.name}"
    # Every JSON we wrote parses; every hook command is ours; the MCP entry points at /mcp.
    for rel, text in written.items():
        if rel.endswith(".json"):
            json.loads(text)
    assert f"{GW}/mcp" in json.dumps(written)
    # Idempotent: a second run changes nothing.
    rc2, out2 = run_init("--agents", agent, "--yes")
    assert rc2 == 0 and snapshot(root) == after
    assert "create " not in out2 and "modify " not in out2
    # Uninstall restores the repository exactly.
    rc3, _ = run_uninstall()
    assert rc3 == 0 and snapshot(root) == before


def test_dry_run_on_mintrail_shows_files_tiers_and_writes_nothing(
    env: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = make(env, "mintrail", monkeypatch)
    before = snapshot(root)
    rc, out = run_init("--dry-run", "--agents", ",".join(AGENT_KINDS), "--devcontainer")
    assert rc == 0 and snapshot(root) == before
    assert not (env / "home" / ".agentguard" / "installs").exists()
    for line in (
        "package managers: pnpm",
        "languages: typescript",
        "CODEOWNERS: .github/CODEOWNERS",
        "claude_code  enforced",
        "codex        enforced",
        "cursor       hooked",
        "gemini_cli   advisory",
        "vscode       mcp_only",
        "antigravity  mcp_only",
        "create         .claude/settings.json",
        "create         .mcp.json",
        "create         .codex/hooks.json",
        "create         .codex/config.toml",
        "create         .cursor/hooks.json",
        "create         .gemini/settings.json",
        "create         .vscode/mcp.json",
        "create         .agents/mcp_config.json",
        "create         AGENTS.md",
        "create         .agentguard.yaml",
        "create         .devcontainer/devcontainer.json",
        "Dry run: nothing was written",
    ):
        assert line in out, line
    # Suggested sensitive paths come from MintRail's real layout.
    for glob in (
        '".github/**"',
        '"ledger/**"',
        "owner: ledger_lead",
        '"drizzle/**"',
        '"infra/**"',
        '"api/src/services/settlements.ts"',
        '"api/src/services/payments.ts"',
        '"api/src/services/refunds.ts"',
        '"pnpm-lock.yaml"',
    ):
        assert glob in out, glob


def test_existing_user_config_is_preserved_and_needs_confirmation(
    env: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = make(env, "python", monkeypatch)
    user = {
        "permissions": {"allow": ["Bash(pytest:*)"]},
        "hooks": {
            "PreToolUse": [
                {"matcher": "Bash", "hooks": [{"type": "command", "command": "./lint.sh"}]}
            ]
        },
    }
    (root / ".claude").mkdir()
    (root / ".claude/settings.json").write_text(json.dumps(user, indent=2) + "\n")
    (root / "AGENTS.md").write_text("# Team rules\n\nUse pytest.\n")
    original = snapshot(root)
    # Without --yes (and no TTY) existing files are shown as a diff and skipped.
    rc, out = run_init("--agents", "claude_code")
    assert (
        rc == 0 and "skipped .claude/settings.json" in out and "+++ b/.claude/settings.json" in out
    )
    assert snapshot(root)[".claude/settings.json"] == original[".claude/settings.json"]
    rc, _ = run_init("--agents", "claude_code", "--yes")
    merged = json.loads((root / ".claude/settings.json").read_text())
    assert merged["permissions"] == user["permissions"]
    pre = merged["hooks"]["PreToolUse"]
    assert pre[0]["hooks"][0]["command"] == "./lint.sh"  # the user's hook stays first
    assert pre[1]["hooks"][0]["command"] == (
        'PATH="$PATH:$HOME/.local/bin:/opt/homebrew/bin:/usr/local/bin" '
        "agw hook claude_code PreToolUse"
    )  # works even when the editor's PATH lacks agw
    assert pre[1]["hooks"][0]["onFailure"] == "block" and pre[1]["hooks"][0]["timeout"] == 660
    md = (root / "AGENTS.md").read_text()
    assert md.startswith("# Team rules\n\nUse pytest.\n") and "agentguard:begin" in md
    # The user later edits the generated .agentguard.yaml: uninstall keeps it.
    (root / ".agentguard.yaml").write_text("version: 1\ndeny_commands: ['make deploy']\n")
    rc, out = run_uninstall()
    after = snapshot(root)
    assert json.loads(after[".claude/settings.json"]) == user
    assert after["AGENTS.md"] == original["AGENTS.md"]
    assert "kept    .agentguard.yaml" in out and ".agentguard.yaml" in after
    assert ".mcp.json" not in after  # created by init, nothing else in it -> removed


def test_marked_block_updates_in_place(env: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root = make(env, "empty", monkeypatch)
    run_init("--agents", "claude_code", "--yes")
    run_init("--agents", "claude_code,codex", "--yes")
    md = (root / "AGENTS.md").read_text()
    assert md.count("agentguard:begin") == 1 and "claude_code, codex" in md
    toml = (root / ".codex/config.toml").read_text()
    assert toml.count("[mcp_servers.agentguard]") == 1


def test_invalid_existing_json_is_left_untouched(
    env: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = make(env, "empty", monkeypatch)
    (root / ".cursor").mkdir()
    (root / ".cursor/hooks.json").write_text("{ not json")
    _rc, out = run_init("--agents", "cursor", "--yes")
    assert "problem: .cursor/hooks.json: not valid JSON; left untouched" in out
    assert (root / ".cursor/hooks.json").read_text() == "{ not json"


def test_unknown_agent_and_outside_repo(env: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    make(env, "empty", monkeypatch)
    rc, out = run_init("--agents", "windsurf")
    assert rc == 2 and "unknown agents: windsurf" in out
    monkeypatch.chdir(env)
    rc, out = run_init()
    assert rc == 2 and "not inside a git repository" in out


def _unused(_: Any) -> None:
    return None


def test_hook_command_survives_missing_path() -> None:
    """Regression: editors launched from the Dock lack ~/.local/bin, so a bare `agw` was
    "command not found" and the fail-closed PreToolUse hook blocked every tool call."""
    from agw_cli.wiring import hook_command, is_hook_command

    cmd = hook_command("claude_code", "PreToolUse")
    assert "$HOME/.local/bin" in cmd and cmd.endswith("agw hook claude_code PreToolUse")
    assert "/Users/" not in cmd  # committed config stays portable across machines
    # Legacy bare entries written by older versions are still recognized (replaced/uninstalled).
    assert is_hook_command("agw hook claude_code PreToolUse", "claude_code")
    assert is_hook_command(cmd, "claude_code") and not is_hook_command(cmd, "cursor")
    assert not is_hook_command("./lint.sh")
