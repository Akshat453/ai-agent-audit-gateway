"""Phase 10 ablation flags (ADR-0032): one codebase, C1..C6, refused outside dev/test."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import Engine, func, select

from agw_gateway.config import ConfigError
from agw_gateway.db import tables as t
from agw_gateway.timing import drain, enable

from ..approvalkit import EXTERNAL
from ..conftest import PgUrls, World, make_settings
from ..privacykit import gateway

pytestmark = pytest.mark.e2e


def test_ablation_refused_in_prod(pg: PgUrls, tmp_path: Path) -> None:
    with pytest.raises(ConfigError):
        make_settings(pg.app, tmp_path, env="prod", ablation="C3")


def _events(gw: Any) -> int:
    with gw.engine.connect() as conn:
        return int(conn.execute(select(func.count()).select_from(t.evidence_events).where(
            t.evidence_events.c.tenant_id == gw.world.tenant_id)).scalar_one())  # fmt: skip


@pytest.mark.parametrize("config", ["C1", "C2", "C3", "C6"])
def test_ablation_layers(
    config: str, pg: PgUrls, app_engine: Engine, world: World, tmp_path: Path
) -> None:
    with gateway(pg, app_engine, world, tmp_path, ablation=config) as gw:
        ok = gw.post("test_echo", {"text": "x"}).json()
        mail = gw.post("send_email", {"to": EXTERNAL, "subject": "s"}).json()
        gw.drain()
        assert ok["status"] == "AUTHORIZED" and gw.action_status(ok["action_id"]) == "COMPLETED"
        events = _events(gw)
        if config == "C1":
            assert events == 0  # authorization only: no evidence at all
        else:
            assert events >= 5
        if config == "C6":
            assert mail["status"] == "PENDING_APPROVAL" and gw.spies.email.calls == []
        else:  # approval enforcement off in C1-C5 (the security-control ablation)
            assert mail["status"] == "AUTHORIZED"
            assert "ABLATION-NO-APPROVAL" in mail["decision"]["matched_rule_ids"]
            assert len(gw.spies.email.calls) == 1
        if config == "C2":  # records written but NOT hash-linked
            with gw.engine.connect() as conn:
                prevs = conn.execute(select(t.evidence_events.c.canonical_bytes).where(
                    t.evidence_events.c.tenant_id == gw.world.tenant_id)).scalars().all()  # fmt: skip
            from agw_gateway.crypto.canonical import decode

            assert all(decode(bytes(b))["prev"] == bytes(32) for b in prevs)


def test_stage_timers(pg: PgUrls, app_engine: Engine, world: World, tmp_path: Path) -> None:
    with gateway(pg, app_engine, world, tmp_path) as gw:
        enable(True)
        try:
            gw.post("test_echo", {"text": "x"})
            gw.drain()
            stages = {s for s, _ in drain()}
        finally:
            enable(False)
    assert {
        "auth",
        "risk",
        "policy",
        "durable_write",
        "dispatch_tx",
        "adapter",
        "result_tx",
    } <= stages
