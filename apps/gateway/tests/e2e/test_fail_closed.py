"""T23 / 08 §8: DB unavailable -> 503, nothing executes. Uses its own container (stopped)."""

import contextlib
import uuid
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from agw_gateway.admin import create_key, ensure_agent, ensure_tenant
from agw_gateway.api.app import build_state, create_app
from agw_gateway.db import create_db_engine

from ..conftest import make_registry, make_settings, make_spies

pytestmark = pytest.mark.e2e


def test_db_down_fails_closed(tmp_path: Path) -> None:
    from ..conftest import init_database, start_postgres

    container = start_postgres()
    try:
        urls = init_database(container)
        mig = create_db_engine(urls.migrator, pool_size=1)
        ensure_tenant(mig, "fc", "fail closed")
        ensure_agent(mig, "fc", "a", ["tools:public_doc_search", "tools:create_ticket"])
        token = create_key(mig, "fc", "a")
        mig.dispose()

        spies = make_spies()
        engine = create_db_engine(urls.app, connect_timeout=2, pool_size=2)
        registry = make_registry(spies)
        state = build_state(make_settings(urls.app, tmp_path), engine=engine, registry=registry)
        registry.sync(engine)
        client = TestClient(create_app(state, sync_registry=False))
        headers = {"Authorization": f"Bearer {token}"}
        body = {
            "run_id": str(uuid.uuid4()),
            "tool": "create_ticket",
            "environment": "dev",
            "args": {"title": "t"},
        }

        ok = client.post("/v1/actions", json=body, headers={**headers, "Idempotency-Key": "a"})
        assert ok.status_code == 201  # authorized while the DB is up, not yet dispatched

        container.stop()

        down = client.post("/v1/actions", json=body, headers={**headers, "Idempotency-Key": "b"})
        assert down.status_code == 503
        assert down.json()["error"]["code"] == "DEPENDENCY_UNAVAILABLE"
        assert client.get("/v1/ready").status_code == 503
        assert client.get("/v1/health").status_code == 200  # liveness has no DB dependency
        with pytest.raises(Exception):  # noqa: B017 - the executor cannot claim without the DB
            state.executor.run_once()
        assert spies.total_calls() == 0
        state.executor.close()
        engine.dispose()
    finally:
        with contextlib.suppress(Exception):
            container.stop()
