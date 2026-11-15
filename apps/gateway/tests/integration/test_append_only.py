"""INV-4 (08 §2): evidence_events and policies are append-only by two independent layers."""

import uuid

import pytest
from sqlalchemy import Engine, text
from sqlalchemy.exc import DBAPIError

pytestmark = pytest.mark.integration

STATEMENTS = {
    "update": "UPDATE {table} SET created_at = created_at",
    "delete": "DELETE FROM {table}",
    "truncate": "TRUNCATE {table} CASCADE",
}


def _sqlstate(engine: Engine, sql: str) -> tuple[str | None, str]:
    with pytest.raises(DBAPIError) as exc, engine.begin() as conn:
        conn.execute(text(sql))
    return getattr(exc.value.orig, "sqlstate", None), str(exc.value.orig)


@pytest.fixture
def seeded(migrator_engine: Engine, gw) -> None:
    # ensure at least one evidence row exists (row triggers need a row to fire on)
    r = gw.post("public_doc_search", {"query": "x"})
    assert r.status_code == 201


APPEND_ONLY = ["evidence_events", "evidence_payloads", "policies"]


def _sql(op: str, table: str) -> str:
    col = {"evidence_events": "occurred_at"}.get(table, "created_at")
    return STATEMENTS[op].format(table=table).replace("created_at", col)


@pytest.mark.parametrize("table", APPEND_ONLY)
@pytest.mark.parametrize("op", ["update", "delete", "truncate"])
def test_app_role_lacks_privilege(app_engine: Engine, seeded: None, table: str, op: str) -> None:
    state, _ = _sqlstate(app_engine, _sql(op, table))
    assert state == "42501"  # insufficient_privilege


@pytest.mark.parametrize("table", APPEND_ONLY)
@pytest.mark.parametrize("op", ["update", "delete", "truncate"])
def test_trigger_blocks_privileged_role(
    migrator_engine: Engine, seeded: None, table: str, op: str
) -> None:
    state, msg = _sqlstate(migrator_engine, _sql(op, table))
    assert state == "P0001"
    assert "is append-only" in msg  # CASCADE may hit the referencing table's trigger first


def test_app_role_cannot_disable_triggers(app_engine: Engine) -> None:
    state, _ = _sqlstate(app_engine, "ALTER TABLE evidence_events DISABLE TRIGGER USER")
    assert state == "42501"


@pytest.mark.parametrize(
    "sql",
    [
        "UPDATE tenants SET display_name = 'x'",
        "UPDATE chain_heads SET tenant_id = tenant_id",
        "INSERT INTO chain_heads (tenant_id) VALUES ('nope')",
        "INSERT INTO agent_credentials (credential_id, agent_id, key_id, key_digest) "
        f"VALUES ('{uuid.uuid4()}', '{uuid.uuid4()}', '0123456789abcdef', '\\x00')",
        "UPDATE agents SET scopes = '{}'",
        "DELETE FROM actions",
        "UPDATE tool_registry SET enabled = true",
    ],
)
def test_app_role_least_privilege(app_engine: Engine, sql: str) -> None:
    state, _ = _sqlstate(app_engine, sql)
    assert state == "42501"


def test_app_role_can_append(app_engine: Engine, seeded: None) -> None:
    with app_engine.connect() as conn:
        assert conn.execute(text("SELECT count(*) FROM evidence_events")).scalar_one() > 0
