"""14 §8: the Phase 2 migration refuses to run over Phase 1 evidence (NULL canonical_bytes)
unless dev evidence reset is explicitly allowed. Own container (needs a database at 0001)."""

import uuid

import psycopg
import pytest
from alembic import command
from alembic.config import Config

pytestmark = pytest.mark.integration


def test_phase2_migration_guard(monkeypatch: pytest.MonkeyPatch) -> None:
    from ..conftest import GATEWAY_DIR, init_database, start_postgres

    container = start_postgres()
    try:
        urls = init_database(container, revision="0001_phase1_core")
        with psycopg.connect(urls.superuser, autocommit=True) as conn:
            conn.execute("INSERT INTO tenants (tenant_id, display_name) VALUES ('p1', 'p1')")
            conn.execute(
                "INSERT INTO evidence_events (event_id, tenant_id, seq, event_type, body) "
                "VALUES (%s, 'p1', 0, 'SECURITY_VIOLATION', '{}')",
                (uuid.uuid4(),),
            )
        cfg = Config(str(GATEWAY_DIR / "alembic.ini"))
        cfg.attributes["url"] = urls.migrator
        monkeypatch.delenv("AGW_ALLOW_DEV_EVIDENCE_RESET", raising=False)
        with pytest.raises(RuntimeError, match="cannot be backfilled"):
            command.upgrade(cfg, "head")
        monkeypatch.setenv("AGW_ALLOW_DEV_EVIDENCE_RESET", "1")
        monkeypatch.setenv("AGW_ENV", "prod")
        with pytest.raises(RuntimeError):  # never in prod
            command.upgrade(cfg, "head")
        monkeypatch.setenv("AGW_ENV", "dev")
        command.upgrade(cfg, "head")
        with psycopg.connect(urls.superuser) as conn:
            assert conn.execute("SELECT count(*) FROM evidence_events").fetchone() == (0,)
            assert conn.execute(
                "SELECT last_seq FROM chain_heads WHERE tenant_id='p1'"
            ).fetchone() == (-1,)
    finally:
        container.stop()


def test_phase4_migration_over_phase3_data() -> None:
    """0004 on a database with Phase 3 tool rows: the demo tools are backfilled and sync
    cleanly; an unknown pre-existing tool row stays NULL and fails sync (fail closed, and
    risk_attributes is the ONLY differing column); the default policy v2 is seeded."""
    import json
    from dataclasses import replace

    from sqlalchemy import Engine

    from agw_gateway.db import create_db_engine
    from agw_gateway.risk_store import sync_risk_policy
    from agw_gateway.tools.demo import demo_tool_specs
    from agw_gateway.tools.registry import ToolRegistry
    from agw_gateway.tools.spec import ToolSpec, ToolSpecError

    from ..conftest import GATEWAY_DIR, init_database, start_postgres

    search = demo_tool_specs()[0]
    legacy = ToolSpec(
        replace(search.meta, tool_id="legacy_tool", required_scope="tools:legacy"),
        search.args_model,
        search.adapter,
    )
    container = start_postgres()
    engine: Engine | None = None
    try:
        urls = init_database(container, revision="0003_phase3_merkle_epochs")
        with psycopg.connect(urls.superuser, autocommit=True) as conn:
            for spec in [*demo_tool_specs()[:3], legacy]:  # rows as Phase 3 wrote them
                m = spec.meta
                conn.execute(
                    "INSERT INTO tool_registry (tool_id, version, operation_type, sensitivity,"
                    " base_risk, environments_allowed, required_scope, is_idempotent,"
                    " external_effect, target_field, tags, args_schema, adapter)"
                    " VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s::jsonb,%s)",
                    (
                        m.tool_id,
                        m.version,
                        m.operation_type,
                        m.sensitivity,
                        m.base_risk,
                        sorted(m.environments_allowed),
                        m.required_scope,
                        m.is_idempotent,
                        m.external_effect,
                        m.target_field,
                        sorted(m.tags),
                        json.dumps(spec.args_schema()),
                        spec.adapter_name,
                    ),
                )
        cfg = Config(str(GATEWAY_DIR / "alembic.ini"))
        cfg.attributes["url"] = urls.migrator
        command.upgrade(cfg, "head")
        engine = create_db_engine(urls.app, pool_size=1)
        ToolRegistry(demo_tool_specs()).sync(engine)  # backfilled demo rows match the code
        sync_risk_policy(engine, None)
        with pytest.raises(ToolSpecError, match=r"version bump: risk_attributes$"):
            ToolRegistry([legacy]).sync(engine)
        with psycopg.connect(urls.superuser) as conn:
            assert conn.execute(
                "SELECT max(version) FROM policies WHERE policy_id = 'default'"
            ).fetchone() == (2,)
            assert conn.execute("SELECT count(*) FROM risk_policies").fetchone() == (1,)
    finally:
        if engine is not None:
            engine.dispose()
        container.stop()
