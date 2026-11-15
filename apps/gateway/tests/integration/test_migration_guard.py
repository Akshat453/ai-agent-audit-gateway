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
