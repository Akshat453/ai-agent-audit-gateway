"""AGW_EXECUTOR_MODE=inprocess: the background runner drains the outbox after tx1 commits."""

import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from agw_gateway.api.app import build_state, create_app

from ..conftest import make_registry, make_settings, make_spies

pytestmark = pytest.mark.e2e


def test_inprocess_runner_completes_actions(pg, app_engine, world, tmp_path: Path) -> None:
    spies = make_spies()
    for s in spies.all():
        s.tenant = world.tenant_id
    registry = make_registry(spies)
    settings = make_settings(
        pg.app, tmp_path, executor_mode="inprocess", executor_poll_seconds=0.05
    )
    state = build_state(settings, engine=app_engine, registry=registry)
    assert state.runner is not None
    with TestClient(create_app(state)) as client:  # lifespan: registry sync + runner start
        headers = {"Authorization": f"Bearer {world.token}", "Idempotency-Key": "inproc-1"}
        body = {
            "run_id": "0193d0c2-0000-7000-8000-000000000001",
            "tool": "create_ticket",
            "environment": "dev",
            "args": {"title": "inproc"},
        }
        aid = client.post("/v1/actions", json=body, headers=headers).json()["action_id"]
        deadline = time.monotonic() + 10
        status = ""
        while time.monotonic() < deadline:
            status = client.get(f"/v1/actions/{aid}", headers=headers).json()["status"]
            if status == "COMPLETED":
                break
            time.sleep(0.05)
    assert status == "COMPLETED"
    assert len(spies.ticket.calls) == 1
