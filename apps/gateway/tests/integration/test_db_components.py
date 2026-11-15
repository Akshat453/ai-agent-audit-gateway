"""Registry sync (11 §4), authenticator (11 §3), seq allocation (08 §3)."""

import threading
import uuid
from dataclasses import replace

import pytest
from sqlalchemy import Engine, select, text

from agw_gateway.auth import AuthenticationFailed, Authenticator
from agw_gateway.db import tables as t
from agw_gateway.evidence import EvidenceWriter, NewEvent
from agw_gateway.tools.demo import demo_tool_specs
from agw_gateway.tools.metadata import ToolMetadata
from agw_gateway.tools.registry import ToolRegistry
from agw_gateway.tools.spec import ToolSpec, ToolSpecError

pytestmark = pytest.mark.integration


def test_registry_sync_and_changed_spec_is_startup_error(app_engine: Engine) -> None:
    reg = ToolRegistry(demo_tool_specs())
    reg.sync(app_engine)
    assert reg.resolve("public_doc_search", None) is not None
    reg.sync(app_engine)  # idempotent
    spec = demo_tool_specs()[0]
    changed = ToolSpec(replace(spec.meta, base_risk="MEDIUM"), spec.args_model, spec.adapter)
    with pytest.raises(ToolSpecError, match="base_risk"):
        ToolRegistry([changed]).sync(app_engine)


def test_disabled_in_table_is_not_callable(app_engine: Engine, migrator_engine: Engine) -> None:
    base = demo_tool_specs()[0]
    meta = replace(base.meta, tool_id=f"tmp_{uuid.uuid4().hex[:8]}")
    meta = ToolMetadata(**{f: getattr(meta, f) for f in meta.__dataclass_fields__})
    spec = ToolSpec(meta, base.args_model, base.adapter)
    ToolRegistry([spec]).sync(app_engine)
    with migrator_engine.begin() as conn:
        conn.execute(
            t.tool_registry.update()
            .where(t.tool_registry.c.tool_id == meta.tool_id)
            .values(enabled=False)
        )
    reg = ToolRegistry([spec])
    reg.sync(app_engine)
    assert reg.resolve(meta.tool_id, None) is None


def test_authenticator(app_engine: Engine, world) -> None:
    auth = Authenticator(app_engine)
    agent = auth.authenticate(f"Bearer {world.token}")
    assert (agent.agent_id, agent.tenant_id) == (world.agent_id, world.tenant_id)
    assert "tools:delete_record" in agent.scopes
    assert auth.authenticate(f"bearer {world.token}").agent_id == world.agent_id
    wrong_secret = world.token[:-1] + ("A" if world.token[-1] != "A" else "B")
    unknown_id = "agw_ffffffffffffffff_" + world.token[21:]
    for header in [
        None,
        "",
        "Bearer",
        f"Basic {world.token}",
        "Bearer agw_garbage",
        f"Bearer {wrong_secret}",
        f"Bearer {unknown_id}",
        f"Bearer {world.revoked_token}",
        f"Bearer {world.expired_token}",
        f"Bearer {world.disabled_token}",
    ]:
        with pytest.raises(AuthenticationFailed):
            auth.authenticate(header)


def test_no_plaintext_keys_at_rest(migrator_engine: Engine, world) -> None:
    with migrator_engine.connect() as conn:
        dump = (
            conn.execute(text("SELECT row_to_json(c)::text FROM agent_credentials c"))
            .scalars()
            .all()
        )
    secret = world.token[21:]
    assert all(secret not in row for row in dump)


def test_seq_gap_free_under_concurrency(app_engine: Engine, world) -> None:
    writer = EvidenceWriter()

    def work() -> None:
        for _ in range(10):
            with app_engine.begin() as conn:
                writer.append(
                    conn,
                    world.tenant_id,
                    [
                        NewEvent(type="SECURITY_VIOLATION", actor_kind="system", actor_id="t")
                        for _ in range(2)
                    ],
                )

    threads = [threading.Thread(target=work) for _ in range(8)]
    for th in threads:
        th.start()
    for th in threads:
        th.join()
    # a rolled-back append must not leave a gap
    with pytest.raises(RuntimeError), app_engine.begin() as conn:
        writer.append(
            conn,
            world.tenant_id,
            [NewEvent(type="SECURITY_VIOLATION", actor_kind="system", actor_id="t")],
        )
        raise RuntimeError("rollback")
    with app_engine.connect() as conn:
        seqs = (
            conn.execute(
                select(t.evidence_events.c.seq)
                .where(t.evidence_events.c.tenant_id == world.tenant_id)
                .order_by(t.evidence_events.c.seq)
            )
            .scalars()
            .all()
        )
        next_seq = conn.execute(
            select(t.tenants.c.next_seq).where(t.tenants.c.tenant_id == world.tenant_id)
        ).scalar_one()
    assert seqs == list(range(160))
    assert next_seq == 160


def test_unknown_tenant(app_engine: Engine) -> None:
    with pytest.raises(LookupError), app_engine.begin() as conn:
        EvidenceWriter().append(
            conn,
            "no-such-tenant",
            [NewEvent(type="SECURITY_VIOLATION", actor_kind="system", actor_id="t")],
        )
