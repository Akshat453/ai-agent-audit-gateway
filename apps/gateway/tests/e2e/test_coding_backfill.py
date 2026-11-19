"""ADR-0041: actions recorded before migration 0015 get their readable (redacted) target from
their own encrypted evidence payload. Same redaction as new actions; contents never stored;
idempotent; evidence untouched."""

from __future__ import annotations

from typing import Any

import pytest
from sqlalchemy import Engine, func, select, text

from agw_gateway.coding.backfill import backfill_targets
from agw_gateway.db import tables as t
from tests.codingkit import CodingWorld, decide, make_coding_world, start_session

pytestmark = pytest.mark.e2e
SECRET = "sk_live_" + "Z" * 20
CANARY = "CANARY_OLD_CONTENT_51e"
DIFF = f"--- a/api/src/x.ts\n+++ b/api/src/x.ts\n@@ -1 +1,2 @@\n-a\n+b // {CANARY}\n+c\n"


@pytest.fixture
def cw(gw: Any, migrator_engine: Engine) -> CodingWorld:
    return make_coding_world(migrator_engine, gw.client, gw.world.tenant_id)


def test_old_actions_get_their_command_and_path_back(
    gw: Any, cw: CodingWorld, migrator_engine: Engine, app_engine: Engine
) -> None:
    s = start_session(gw.client, cw)
    cmd = decide(gw.client, cw, s, "command_exec", f"API_KEY={SECRET} pnpm test").json()
    edit = decide(gw.client, cw, s, "file_write", "api/src/x.ts", DIFF).json()
    # Make them look like pre-0015 actions.
    with migrator_engine.begin() as conn:
        conn.execute(text(
            "UPDATE coding_actions SET target_sealed = NULL, diff_files = NULL, diff_added = NULL,"
            " diff_removed = NULL WHERE session_id = :s"), {"s": s})  # fmt: skip
        events_before = conn.execute(select(func.count()).select_from(t.evidence_events)).scalar()
    shown = gw.client.get(f"/v1/dashboard/actions/{cmd['action_id']}", headers=cw.human("dev"))
    assert shown.json()["coding"]["target"] is None  # "not recorded" before the backfill

    store, cipher = gw.state.writer.payloads, gw.state.cipher
    rep = backfill_targets(migrator_engine, store, cipher, tenant=gw.world.tenant_id)
    assert rep.filled == 2 and rep.remaining == 0

    c = gw.client.get(f"/v1/dashboard/actions/{cmd['action_id']}", headers=cw.human("dev"))
    target = c.json()["coding"]["target"]["command"]
    assert "pnpm test" in target and "[REDACTED]" in target and SECRET not in c.text
    e = gw.client.get(f"/v1/dashboard/actions/{edit['action_id']}", headers=cw.human("dev")).json()
    assert e["coding"]["target"]["paths"] == ["api/src/x.ts"]
    assert e["coding"]["diff"] == {"files": 1, "added": 2, "removed": 1}
    assert CANARY not in repr(e)

    with app_engine.connect() as conn:
        blob = b"".join(
            bytes(x) for x in conn.execute(
                select(t.coding_actions.c.target_sealed).where(t.coding_actions.c.session_id == s)  # type: ignore[arg-type]
            ).scalars()
        )  # fmt: skip
        assert b"pnpm" not in blob and CANARY.encode() not in blob
        # evidence is only read, never written
        assert (
            conn.execute(select(func.count()).select_from(t.evidence_events)).scalar()
            == events_before
        )
    again = backfill_targets(migrator_engine, store, cipher, tenant=gw.world.tenant_id)
    assert again.filled == 0
