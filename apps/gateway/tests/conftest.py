"""Shared fixtures.

* ``pg``: one Testcontainers ``postgres:16`` for the session, initialised exactly like the
  compose stack (infra/docker/postgres/roles.sql) and migrated with Alembic as agw_migrator.
* Every test gets its own tenant (``world``): evidence rows are append-only and cannot be
  cleaned up, so isolation is by tenant, not by truncation.
* ``gw``: a gateway wired with spy adapters, executor in ``worker`` mode (tests drive
  ``executor.run_once()`` / ``reconciler.run_once()`` explicitly), crash points enabled.
"""

from __future__ import annotations

import secrets
import threading
import uuid
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from datetime import timedelta
from pathlib import Path
from typing import Any

import psycopg
import pytest
from alembic import command
from alembic.config import Config
from fastapi.testclient import TestClient
from pydantic import BaseModel, ConfigDict
from sqlalchemy import Engine, func, select

from agw_gateway.admin import create_key, ensure_agent, ensure_tenant
from agw_gateway.api.app import build_state, create_app
from agw_gateway.api.state import GatewayState
from agw_gateway.config import load_settings
from agw_gateway.db import create_db_engine
from agw_gateway.db import tables as t
from agw_gateway.tools.adapters.create_ticket import CreateTicketAdapter
from agw_gateway.tools.adapters.delete_record import DeleteRecordAdapter
from agw_gateway.tools.adapters.public_doc_search import PublicDocSearchAdapter
from agw_gateway.tools.demo import demo_tool_specs
from agw_gateway.tools.metadata import ToolMetadata
from agw_gateway.tools.registry import ToolRegistry
from agw_gateway.tools.spec import ExecutionContext, ToolResult, ToolSpec

REPO = Path(__file__).resolve().parents[3]
GATEWAY_DIR = REPO / "apps" / "gateway"
CORPUS = REPO / "examples" / "single-agent" / "corpus"


# --------------------------------------------------------------------------- database
@dataclass(frozen=True)
class PgUrls:
    superuser: str  # psycopg conninfo
    migrator: str  # SQLAlchemy URL
    app: str  # SQLAlchemy URL


def init_database(container: Any, revision: str = "head") -> PgUrls:
    host = container.get_container_host_ip()
    port = container.get_exposed_port(5432)
    su_pw, mig_pw, app_pw = (secrets.token_hex(12) for _ in range(3))
    roles_sql = (REPO / "infra/docker/postgres/roles.sql").read_text()
    roles_sql = roles_sql.replace(":'migrator_password'", f"'{mig_pw}'").replace(
        ":'app_password'", f"'{app_pw}'"
    )
    su = f"host={host} port={port} dbname=agw user=postgres password={container.password}"
    with psycopg.connect(su, autocommit=True) as conn:
        conn.execute(roles_sql)  # type: ignore[arg-type]
    del su_pw
    urls = PgUrls(
        superuser=su,
        migrator=f"postgresql+psycopg://agw_migrator:{mig_pw}@{host}:{port}/agw",
        app=f"postgresql+psycopg://agw_app:{app_pw}@{host}:{port}/agw",
    )
    cfg = Config(str(GATEWAY_DIR / "alembic.ini"))
    cfg.attributes["url"] = urls.migrator
    command.upgrade(cfg, revision)
    return urls


def start_postgres() -> Any:
    from testcontainers.community.postgres import PostgresContainer

    container = PostgresContainer(
        "postgres:16", dbname="agw", username="postgres", password=secrets.token_hex(12)
    )
    container.start()
    return container


@pytest.fixture(scope="session")
def pg() -> Iterator[PgUrls]:
    container = start_postgres()
    try:
        yield init_database(container)
    finally:
        container.stop()


@pytest.fixture(scope="session")
def app_engine(pg: PgUrls) -> Iterator[Engine]:
    engine = create_db_engine(pg.app, pool_size=15)
    yield engine
    engine.dispose()


@pytest.fixture(scope="session")
def migrator_engine(pg: PgUrls) -> Iterator[Engine]:
    engine = create_db_engine(pg.migrator, pool_size=2)
    yield engine
    engine.dispose()


# --------------------------------------------------------------------------- spies
class SpyAdapter:
    """Records every invocation. ``adapter_name`` mirrors the wrapped adapter so the registry
    sync sees the same spec as production."""

    def __init__(
        self,
        inner: Any | None = None,
        *,
        name: str | None = None,
        behavior: Callable[[BaseModel, ExecutionContext], ToolResult] | None = None,
    ) -> None:
        self.inner = inner
        self.behavior = behavior
        cls = type(inner) if inner is not None else type(self)
        self.adapter_name = name or f"{cls.__module__}.{cls.__qualname__}"
        self.tenant: str | None = None  # only calls for this tenant are reported
        self._calls: list[tuple[str, uuid.UUID]] = []
        self._lock = threading.Lock()

    @property
    def calls(self) -> list[uuid.UUID]:
        """Invocations for the test's own tenant (the executor serves every tenant)."""
        with self._lock:
            return [a for tnt, a in self._calls if self.tenant is None or tnt == self.tenant]

    def execute(self, args: BaseModel, ctx: ExecutionContext) -> ToolResult:
        with self._lock:
            self._calls.append((ctx.tenant_id, ctx.action_id))
        if self.behavior is not None:
            return self.behavior(args, ctx)
        assert self.inner is not None
        result: ToolResult = self.inner.execute(args, ctx)
        return result


class RestrictedArgs(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)
    name: str


class EchoArgs(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)
    text: str


# Test-only tools (unique ids; never in production registries).
RESTRICTED_UPDATE = ToolMetadata(
    tool_id="test_restricted_update",
    version="1.0.0",
    operation_type="update",
    sensitivity="restricted",
    base_risk="HIGH",
    environments_allowed=frozenset({"dev"}),
    required_scope="tools:test_restricted_update",
    is_idempotent=False,
    external_effect=False,
)
# LOW read (allowed by the default policy) but declared non-idempotent, to exercise ADR-0011.
ECHO_NONIDEMPOTENT = ToolMetadata(
    tool_id="test_echo",
    version="1.0.0",
    operation_type="read",
    sensitivity="public",
    base_risk="LOW",
    environments_allowed=frozenset({"dev"}),
    required_scope="tools:test_echo",
    is_idempotent=False,
    external_effect=False,
)

ALL_SCOPES = (
    "tools:public_doc_search",
    "tools:create_ticket",
    "tools:delete_record",
    "tools:test_restricted_update",
    "tools:test_echo",
)


@dataclass
class Spies:
    search: SpyAdapter
    ticket: SpyAdapter
    delete: SpyAdapter
    restricted: SpyAdapter
    echo: SpyAdapter

    def all(self) -> list[SpyAdapter]:
        return [self.search, self.ticket, self.delete, self.restricted, self.echo]

    def total_calls(self) -> int:
        return sum(len(s.calls) for s in self.all())


def _echo(args: BaseModel, ctx: ExecutionContext) -> ToolResult:
    assert isinstance(args, EchoArgs)
    return ToolResult(public={"echo": args.text})


def make_spies() -> Spies:
    return Spies(
        search=SpyAdapter(PublicDocSearchAdapter()),
        ticket=SpyAdapter(CreateTicketAdapter()),
        delete=SpyAdapter(DeleteRecordAdapter()),
        restricted=SpyAdapter(name="tests.RestrictedAdapter", behavior=lambda a, c: ToolResult()),
        echo=SpyAdapter(name="tests.EchoAdapter", behavior=_echo),
    )


def make_registry(spies: Spies) -> ToolRegistry:
    specs = demo_tool_specs(search=spies.search, ticket=spies.ticket, delete=spies.delete)
    specs.append(ToolSpec(RESTRICTED_UPDATE, RestrictedArgs, spies.restricted))
    specs.append(ToolSpec(ECHO_NONIDEMPOTENT, EchoArgs, spies.echo))
    return ToolRegistry(specs)


# --------------------------------------------------------------------------- tenant world
@dataclass
class World:
    tenant_id: str
    agent_id: uuid.UUID
    token: str
    readonly_id: uuid.UUID
    readonly_token: str
    other_id: uuid.UUID
    other_token: str
    disabled_token: str
    revoked_token: str
    expired_token: str
    extra: dict[str, Any] = field(default_factory=dict)


@pytest.fixture
def world(migrator_engine: Engine) -> World:
    tenant = f"t-{uuid.uuid4().hex[:12]}"
    ensure_tenant(migrator_engine, tenant, "test tenant")
    agent = ensure_agent(migrator_engine, tenant, "demo-agent", ALL_SCOPES)
    readonly = ensure_agent(migrator_engine, tenant, "demo-readonly", ("tools:public_doc_search",))
    other = ensure_agent(migrator_engine, tenant, "other-agent", ALL_SCOPES)
    ensure_agent(migrator_engine, tenant, "disabled-agent", ALL_SCOPES, status="disabled")
    revoked = create_key(migrator_engine, tenant, "demo-agent")
    from agw_gateway.admin import revoke_key

    revoke_key(migrator_engine, revoked[4:20])
    return World(
        tenant_id=tenant,
        agent_id=uuid.UUID(agent),
        token=create_key(migrator_engine, tenant, "demo-agent"),
        readonly_id=uuid.UUID(readonly),
        readonly_token=create_key(migrator_engine, tenant, "demo-readonly"),
        other_id=uuid.UUID(other),
        other_token=create_key(migrator_engine, tenant, "other-agent"),
        disabled_token=create_key(migrator_engine, tenant, "disabled-agent"),
        revoked_token=revoked,
        expired_token=create_key(
            migrator_engine, tenant, "demo-agent", expires_in=timedelta(seconds=-1)
        ),
    )


# --------------------------------------------------------------------------- gateway
@dataclass
class Gw:
    state: GatewayState
    client: TestClient
    spies: Spies
    world: World
    engine: Engine

    def headers(self, token: str | None = None, key: str | None = None) -> dict[str, str]:
        h = {"Authorization": f"Bearer {token or self.world.token}"}
        h["Idempotency-Key"] = key or f"k-{uuid.uuid4().hex}"
        return h

    def post(
        self,
        tool: str,
        args: Any,
        *,
        env: str = "dev",
        run_id: str | None = None,
        token: str | None = None,
        key: str | None = None,
        **extra: Any,
    ) -> Any:
        body = {"run_id": run_id or str(uuid.uuid4()), "tool": tool, "environment": env}
        body["args"] = args
        body.update(extra)
        return self.client.post("/v1/actions", json=body, headers=self.headers(token, key))

    def drain(self) -> None:
        """Run the executor until the outbox is empty, then the reconciler once."""
        while self.state.executor.run_once():
            pass
        self.state.reconciler.run_once()

    def events(self, action_id: str | uuid.UUID) -> list[str]:
        with self.engine.connect() as conn:
            rows = conn.execute(
                select(t.evidence_events.c.event_type)
                .where(t.evidence_events.c.action_id == uuid.UUID(str(action_id)))
                .order_by(t.evidence_events.c.seq)
            ).scalars()
            return list(rows)

    def count_events(self, event_type: str) -> int:
        with self.engine.connect() as conn:
            return int(
                conn.execute(
                    select(func.count())
                    .select_from(t.evidence_events)
                    .where(
                        t.evidence_events.c.tenant_id == self.world.tenant_id,
                        t.evidence_events.c.event_type == event_type,
                    )
                ).scalar_one()
            )

    def action_status(self, action_id: str | uuid.UUID) -> str:
        with self.engine.connect() as conn:
            return str(
                conn.execute(
                    select(t.actions.c.status).where(
                        t.actions.c.action_id == uuid.UUID(str(action_id))
                    )
                ).scalar_one()
            )


def make_settings(app_url: str, tmp_path: Path, **overrides: Any) -> Any:
    values: dict[str, Any] = {
        "env": "test",
        "database_url": app_url,
        "executor_mode": "worker",
        "demo_corpus_dir": CORPUS,
        "demo_sandbox_dir": tmp_path,
        "lease_seconds": 30,
        "adapter_timeout_seconds": 5,
    }
    values.update(overrides)
    return load_settings(**values)


@pytest.fixture
def gw(pg: PgUrls, app_engine: Engine, world: World, tmp_path: Path) -> Iterator[Gw]:
    spies = make_spies()
    for spy in spies.all():
        spy.tenant = world.tenant_id
    registry = make_registry(spies)
    state = build_state(make_settings(pg.app, tmp_path), engine=app_engine, registry=registry)
    registry.sync(app_engine)
    app = create_app(state, sync_registry=False)
    with TestClient(app) as client:
        g = Gw(state=state, client=client, spies=spies, world=world, engine=app_engine)
        yield g
        g.drain()  # leave no PENDING jobs behind for later tests
