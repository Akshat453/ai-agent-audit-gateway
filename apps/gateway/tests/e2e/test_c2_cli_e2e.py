"""C2 acceptance, end to end with the real CLI (subprocesses, real HTTP): ``agw login`` (device
code approved in parallel by the developer), ``agw init --dry-run`` on a MintRail skeleton shows
the correct files and tiers and writes nothing, ``agw init`` registers the repository, and
``agw doctor`` reports per-agent tiers."""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import Engine, select

from agw_gateway.api.app import create_app
from agw_gateway.db import tables as t
from tests.approvalkit import Humans, make_humans
from tests.servekit import serve

pytestmark = pytest.mark.e2e
REPO = Path(__file__).resolve().parents[4]
FILES = REPO / "packages/agw-cli/tests/fixtures/mintrail-files.txt"


@pytest.fixture
def url(gw: Any) -> Iterator[str]:
    with serve(create_app(gw.state, sync_registry=False)) as base:
        yield base


@pytest.fixture
def h(gw: Any, migrator_engine: Engine) -> Humans:
    return make_humans(migrator_engine, gw.client, gw.world.tenant_id)


def skeleton(root: Path) -> None:
    for rel in FILES.read_text().splitlines():
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        (root / rel).write_text("")
    (root / ".git/refs/heads").mkdir(parents=True)
    (root / ".git/HEAD").write_text("ref: refs/heads/main\n")
    (root / ".git/refs/heads/main").write_text("f" * 40 + "\n")
    (root / ".git/config").write_text(
        '[remote "origin"]\n\turl = https://github.com/Akshat453/MintRail.git\n'
    )


def env(home: Path) -> dict[str, str]:
    return {
        "PATH": f"{Path(sys.executable).parent}:{os.environ.get('PATH', '')}",
        "HOME": str(home),
        "AGW_CONFIG": str(home / "agentguard.toml"),
        "AGW_HOME": str(home / ".agentguard"),
        "AGW_STATE_DIR": str(home / "state"),
        "PYTHONUNBUFFERED": "1",
    }


def agw(args: list[str], home: Path, cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "agw_cli", *args],
        capture_output=True,
        text=True,
        env=env(home),
        cwd=cwd,
        timeout=120,
        check=False,
    )


def test_login_init_dry_run_doctor(gw: Any, h: Humans, url: str, tmp_path: Path) -> None:
    home = tmp_path / "home"
    home.mkdir()
    proc = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "agw_cli",
            "login",
            "--url",
            url,
            "--tenant",
            gw.world.tenant_id,
            "--agent-kind",
            "claude_code",
            "--label",
            "dev-laptop",
            "--no-browser",
            "--keystore",
            "file",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=env(home),
    )
    assert proc.stdout is not None
    code = None
    deadline = time.monotonic() + 30
    buf = ""
    while code is None and time.monotonic() < deadline:
        line = proc.stdout.readline()
        buf += line
        m = re.search(r"\b([B-Z]{4}-[B-Z]{4})\b", line)
        if m:
            code = m.group(1)
    if code is None:
        proc.kill()
    assert code is not None, buf
    assert "/enroll" in buf
    r = gw.client.post(
        f"/v1/device/requests/{code}/decision", headers=h.headers("alice"), json={"approve": True}
    )
    assert r.status_code == 200, r.text
    try:
        out, err = proc.communicate(timeout=60)
    except subprocess.TimeoutExpired:
        proc.kill()
        raise
    assert proc.returncode == 0, err
    assert "Enrolled as alice" in out
    key_file = home / ".config/agentguard/device.key"
    assert key_file.is_file() and oct(key_file.stat().st_mode)[-3:] == "600"
    assert key_file.read_text().strip() not in out + buf  # the key is never printed
    cfg = (home / "agentguard.toml").read_text()
    assert "device_key_ref" in cfg and "agw_" not in cfg  # the config holds a reference only

    repo = tmp_path / "mintrail-copy"
    skeleton(repo)
    before = sorted(p.as_posix() for p in repo.rglob("*"))
    dry = agw(
        ["init", "--dry-run", "--agents", "claude_code,codex,cursor,gemini_cli,vscode,antigravity"],
        home,
        repo,
    )
    assert dry.returncode == 0, dry.stderr
    assert sorted(p.as_posix() for p in repo.rglob("*")) == before  # nothing written
    for line in (
        f"Gateway: {url}",
        "claude_code  enforced",
        "codex        enforced",
        "cursor       hooked",
        "gemini_cli   advisory",
        "vscode       mcp_only",
        "antigravity  mcp_only",
        "create         .claude/settings.json",
        "create         .agentguard.yaml",
        '"ledger/**"',
        "not registered",
    ):
        assert line in dry.stdout, line
    with gw.engine.connect() as conn:
        assert (
            conn.execute(select(t.repos).where(t.repos.c.tenant_id == gw.world.tenant_id)).first()
            is None
        )

    done = agw(["init", "--agents", "claude_code,cursor,vscode", "--yes"], home, repo)
    assert done.returncode == 0, done.stdout + done.stderr
    assert "Registered mintrail-copy (repo policy v1)" in done.stdout
    with gw.engine.connect() as conn:
        row = conn.execute(select(t.repos).where(t.repos.c.tenant_id == gw.world.tenant_id)).one()
    assert row.agents["claude_code"] == {"tier": "enforced", "hooks": True}
    assert row.agents["vscode"] == {"tier": "mcp_only", "hooks": False}

    doc = agw(["doctor", "--json"], home, repo)
    checks = {
        (c["name"], c["status"]): c for c in json.loads(doc.stdout[: doc.stdout.rindex("]") + 1])
    }
    names = {n: s for (n, s) in checks}
    assert names["gateway reachable"] == "OK" and names["logged in"] == "OK"
    assert names["repository registered"] == "OK"
    assert (
        names["claude_code: pre-action hook"] == "OK" and names["cursor: pre-action hook"] == "OK"
    )
    assert names["claude_code: MCP config"] == "OK" and names["vscode: MCP config"] == "OK"
    tiers = {
        n.split(":")[0]: c["detail"].split(" ")[0]
        for (n, _s), c in checks.items()
        if n.endswith(": tier")
    }
    # (doctor also reports agents installed on this machine, so compare the ones we wired)
    assert {k: tiers[k] for k in ("claude_code", "cursor", "vscode")} == {
        "claude_code": "enforced",
        "cursor": "hooked",
        "vscode": "mcp_only",
    }
    assert names["claude_code: mandatory"] == "WARN"  # project hooks only on this machine
    human = agw(["doctor"], home, repo)
    assert "[OK  ] claude_code: tier: enforced" in human.stdout

    # A device key from login works for hooks right away.
    st = agw(["status"], home)
    assert st.returncode == 0 and json.loads(st.stdout)["gateway"]["developer"] == "alice"
    out_ = agw(["logout"], home)
    assert out_.returncode == 0 and not key_file.exists()
    assert agw(["doctor"], home, repo).returncode == 1  # not logged in any more
