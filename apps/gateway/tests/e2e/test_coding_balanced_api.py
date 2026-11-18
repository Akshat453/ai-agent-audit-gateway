"""The default "balanced" coding profile through the real gateway API (ADR-0037).

Everyday local work is ALLOWED and still fully recorded (evidence chain); crucial actions still
ask; denies are unchanged.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, select

from agw_gateway.api.app import build_state, create_app
from agw_gateway.db import tables as t
from tests.codingkit import CodingWorld, decide, make_coding_world, start_session
from tests.conftest import make_settings

pytestmark = pytest.mark.e2e
LEDGER_DIFF = "--- a/ledger/src/service.ts\n+++ b/ledger/src/service.ts\n@@ -1 +1,2 @@\n+// x\n"


@pytest.fixture
def bal(pg: Any, app_engine: Engine, tmp_path: Path) -> Iterator[TestClient]:
    state = build_state(
        make_settings(pg.app, tmp_path, coding_policy_profile="balanced"), engine=app_engine
    )
    state.sync()
    with TestClient(create_app(state, sync_registry=False)) as client:
        yield client


@pytest.fixture
def cw(bal: TestClient, migrator_engine: Engine, world: Any) -> CodingWorld:
    return make_coding_world(migrator_engine, bal, world.tenant_id)


def _events(engine: Engine, action_id: str) -> list[str]:
    with engine.connect() as conn:
        return list(
            conn.execute(
                select(t.evidence_events.c.event_type)
                .where(t.evidence_events.c.action_id == uuid.UUID(action_id))
                .order_by(t.evidence_events.c.seq)
            ).scalars()
        )


def test_everyday_work_runs_recorded_crucial_asks_denies_stay(
    bal: TestClient, cw: CodingWorld, app_engine: Engine
) -> None:
    s = start_session(bal, cw)
    # A sensitive source edit on the developer's machine: allowed, and recorded.
    edit = decide(bal, cw, s, "file_write", "ledger/src/service.ts", LEDGER_DIFF).json()
    assert edit["decision"] == "allow", edit
    assert "PATH-HIGH" in edit["rule_ids"]  # the evidence still says WHAT it was
    assert _events(app_engine, edit["action_id"]) == [
        "ACTION_REQUESTED",
        "POLICY_EVALUATED",
        "ACTION_AUTHORIZED",
    ]
    for cmd in ("git checkout main", "curl -s http://localhost:3000/health", "make dev"):
        r = decide(bal, cw, s, "command_exec", cmd).json()
        assert r["decision"] == "allow", (cmd, r)
    # Crucial: the agent editing its own guard still needs a human.
    guard = decide(bal, cw, s, "file_write", ".claude/settings.json", None).json()
    assert guard["decision"] == "ask" and guard["approval"]["required_role"] == "security"
    # Denies are unchanged.
    for cmd in ("git push origin main", "cat .env", "curl https://example.com"):
        r = decide(bal, cw, s, "command_exec", cmd).json()
        assert r["decision"] == "deny", (cmd, r)
    with app_engine.connect() as conn:
        pol = conn.execute(
            select(t.evidence_events.c.body).where(
                t.evidence_events.c.action_id == uuid.UUID(edit["action_id"]),
                t.evidence_events.c.event_type == "POLICY_EVALUATED",
            )
        ).scalar_one()
    assert pol["policy"]["id"] == "coding-mintrail" and pol["policy"]["ver"] == 2
