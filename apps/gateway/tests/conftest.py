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
import tempfile
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
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import Engine, func, select

from agw_gateway.admin import create_key, ensure_agent, ensure_tenant
from agw_gateway.api.app import build_state, create_app
from agw_gateway.api.state import GatewayState
from agw_gateway.config import load_settings
from agw_gateway.db import create_db_engine
from agw_gateway.db import tables as t
from agw_gateway.privacy.classification import FieldClasses
from agw_gateway.tools.adapters.create_ticket import CreateTicketAdapter
from agw_gateway.tools.adapters.delete_record import DeleteRecordAdapter
from agw_gateway.tools.adapters.phase4_mocks import (
    ExportCustomerDataAdapter,
    SendEmailAdapter,
    UpdateIamRoleAdapter,
)
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


class SecretToolArgs(BaseModel):
    """Phase 7: one field of every class (secret = a credential the tool needs)."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)
    endpoint: str
    api_token: str
    note: str = ""


class BigDocArgs(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)
    text: str = Field(max_length=200_000)


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
    data_classification="confidential",
    reversible=True,
    medium_effect="REQUIRE_APPROVAL",
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
    data_classification="public",
    reversible=True,
    medium_effect="ALLOW",
)

SECRET_TOOL = ToolMetadata(
    tool_id="test_secret_tool",
    version="1.0.0",
    operation_type="read",
    sensitivity="public",
    base_risk="LOW",
    environments_allowed=frozenset({"dev"}),
    required_scope="tools:test_secret_tool",
    is_idempotent=True,
    external_effect=False,
    data_classification="public",
    reversible=True,
    medium_effect="ALLOW",
)
SECRET_TOOL_CLASSES = FieldClasses(
    args={"endpoint": "internal", "api_token": "secret", "note": "confidential"},
    results={"status": "public", "session_token": "secret", "detail": "confidential"},
)
BIGDOC = ToolMetadata(
    tool_id="test_bigdoc",
    version="1.0.0",
    operation_type="read",
    sensitivity="public",
    base_risk="LOW",
    environments_allowed=frozenset({"dev"}),
    required_scope="tools:test_bigdoc",
    is_idempotent=True,
    external_effect=False,
    data_classification="public",
    reversible=True,
    medium_effect="ALLOW",
)

ALL_SCOPES = (
    "tools:public_doc_search",
    "tools:create_ticket",
    "tools:delete_record",
    "tools:test_restricted_update",
    "tools:test_echo",
    "tools:send_email",
    "tools:export_customer_data",
    "tools:update_iam_role",
    "tools:test_secret_tool",
    "tools:test_bigdoc",
)


@dataclass
class Spies:
    search: SpyAdapter
    ticket: SpyAdapter
    delete: SpyAdapter
    restricted: SpyAdapter
    echo: SpyAdapter
    email: SpyAdapter
    export: SpyAdapter
    iam: SpyAdapter
    secret: SpyAdapter
    bigdoc: SpyAdapter

    def all(self) -> list[SpyAdapter]:
        return [
            self.secret,
            self.bigdoc,
            self.search,
            self.ticket,
            self.delete,
            self.restricted,
            self.echo,
            self.email,
            self.export,
            self.iam,
        ]

    def total_calls(self) -> int:
        return sum(len(s.calls) for s in self.all())


def _echo(args: BaseModel, ctx: ExecutionContext) -> ToolResult:
    assert isinstance(args, EchoArgs)
    return ToolResult(public={"echo": args.text})


SECRET_RECEIVED: list[str] = []  # what the adapter really got (the tool needs the real token)


def _secret_tool(args: BaseModel, ctx: ExecutionContext) -> ToolResult:
    assert isinstance(args, SecretToolArgs)
    SECRET_RECEIVED.append(args.api_token)
    return ToolResult(
        public={
            "status": "ok",
            "session_token": "sess-" + args.api_token,  # a secret RESULT
            "detail": "confidential detail for " + args.note,
        }
    )


def make_spies() -> Spies:
    return Spies(
        search=SpyAdapter(PublicDocSearchAdapter()),
        ticket=SpyAdapter(CreateTicketAdapter()),
        delete=SpyAdapter(DeleteRecordAdapter()),
        restricted=SpyAdapter(name="tests.RestrictedAdapter", behavior=lambda a, c: ToolResult()),
        echo=SpyAdapter(name="tests.EchoAdapter", behavior=_echo),
        email=SpyAdapter(SendEmailAdapter()),
        export=SpyAdapter(ExportCustomerDataAdapter()),
        iam=SpyAdapter(UpdateIamRoleAdapter()),
        secret=SpyAdapter(name="tests.SecretToolAdapter", behavior=_secret_tool),
        bigdoc=SpyAdapter(
            name="tests.BigDocAdapter", behavior=lambda a, c: ToolResult(public={"ok": True})
        ),
    )


def make_registry(spies: Spies) -> ToolRegistry:
    specs = demo_tool_specs(
        search=spies.search,
        ticket=spies.ticket,
        delete=spies.delete,
        email=spies.email,
        export=spies.export,
        iam=spies.iam,
    )
    specs.append(
        ToolSpec(
            RESTRICTED_UPDATE,
            RestrictedArgs,
            spies.restricted,
            FieldClasses(args={"name": "internal"}),
        )
    )
    specs.append(
        ToolSpec(
            ECHO_NONIDEMPOTENT,
            EchoArgs,
            spies.echo,
            FieldClasses(args={"text": "internal"}, results={"echo": "internal"}),
        )
    )
    specs.append(ToolSpec(SECRET_TOOL, SecretToolArgs, spies.secret, SECRET_TOOL_CLASSES))
    specs.append(
        ToolSpec(
            BIGDOC,
            BigDocArgs,
            spies.bigdoc,
            FieldClasses(args={"text": "internal"}, results={"ok": "public"}),
        )
    )
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


_SIGNING_KEY: list[Path] = []


def signing_key_file() -> Path:
    """One dev Ed25519 decision-signing key for the whole test session."""
    if not _SIGNING_KEY:
        from agw_gateway.approvals.signing import generate_key_file

        path = Path(tempfile.mkdtemp(prefix="agw-test-")) / "approval-signing.key"
        generate_key_file(path)
        _SIGNING_KEY.append(path)
    return _SIGNING_KEY[0]


_DELEGATION_KEY: list[Path] = []


def delegation_key_file() -> Path:
    """One dev Ed25519 delegation-signing key for the whole test session (Phase 8)."""
    if not _DELEGATION_KEY:
        from agw_gateway.delegation.service import generate_delegation_key_file

        path = Path(tempfile.mkdtemp(prefix="agw-test-")) / "delegation-signing.key"
        generate_delegation_key_file(path)
        _DELEGATION_KEY.append(path)
    return _DELEGATION_KEY[0]


_KEK_DIR: list[Path] = []


def kek_dir() -> Path:
    """One dev KEK keyring (version 1) for the whole test session, outside the repo, 0600."""
    if not _KEK_DIR:
        from agw_gateway.keys import LocalKeyProvider

        path = Path(tempfile.mkdtemp(prefix="agw-kek-"))
        LocalKeyProvider.generate(path, "test")
        _KEK_DIR.append(path)
    return _KEK_DIR[0]


def make_settings(app_url: str, tmp_path: Path, **overrides: Any) -> Any:
    values: dict[str, Any] = {
        "approval_signing_key_file": signing_key_file(),
        "delegation_signing_key_file": delegation_key_file(),
        "kek_dir": kek_dir(),
        "kek_id": "test",
        "env": "test",
        "database_url": app_url,
        "executor_mode": "worker",
        "demo_corpus_dir": CORPUS,
        "demo_sandbox_dir": tmp_path,
        "lease_seconds": 30,
        "adapter_timeout_seconds": 5,
        # Production default is "*" (every CRITICAL action is pre-anchored, ADR-0028); tests
        # of other phases run without a chain, so they opt out. Phase 6 tests opt back in.
        "pre_anchor_rules": (),
        # Phase 10: the rate limiter is ON by default in production; tests that issue bursts
        # turn it off here, and test_limits.py turns it back on.
        "rate_limit_per_minute": 0,
        # C1-C3 tests exercise the approval machinery with the STRICT coding profile (v1);
        # the default "balanced" profile has its own tests (test_coding_balanced*.py).
        "coding_policy_profile": "strict",
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
    state.sync()  # tool registry + bundled risk policy
    app = create_app(state, sync_registry=False)
    with TestClient(app) as client:
        g = Gw(state=state, client=client, spies=spies, world=world, engine=app_engine)
        yield g
        g.drain()  # leave no PENDING jobs behind for later tests


# --------------------------------------------------------------------------- chain (Phase 6)
@pytest.fixture(scope="session")
def chain() -> Iterator[Any]:
    """A real Anvil node (pinned Foundry image) with EpochAnchor deployed from the committed
    artifact. Started only by tests that use it."""
    from .anchorkit import deploy_registry, start_anvil

    container, rpc = start_anvil()
    try:
        yield deploy_registry(rpc, container)
    finally:
        container.stop()


# --------------------------------------------------------------------------- Phase 7 services
MINIO_IMAGE = "cgr.dev/chainguard/minio@sha256:18c8fa28697b25e0f34c6faae171079e88a03efb8e76a21d3b5d07b4e3cbef3e"
VAULT_IMAGE = "hashicorp/vault:1.20.4"


@dataclass
class ServiceUrl:
    endpoint: str  # host:port (MinIO) or http URL (Vault)
    user: str
    secret: str
    container: Any


@pytest.fixture(scope="session")
def minio() -> Iterator[ServiceUrl]:
    """A real MinIO (S3 API), pinned by digest. Started only by tests that use it."""
    import time

    from minio import Minio
    from testcontainers.core.container import DockerContainer

    user, pw = "agw-" + secrets.token_hex(4), secrets.token_urlsafe(24)
    c = (
        DockerContainer(MINIO_IMAGE)
        .with_env("MINIO_ROOT_USER", user)
        .with_env("MINIO_ROOT_PASSWORD", pw)
        .with_command("server /data")
        .with_exposed_ports(9000)
    )
    c.start()
    endpoint = f"{c.get_container_host_ip()}:{c.get_exposed_port(9000)}"
    for _ in range(100):
        try:
            Minio(endpoint, access_key=user, secret_key=pw, secure=False).list_buckets()
            break
        except Exception:
            time.sleep(0.3)
    try:
        yield ServiceUrl(endpoint, user, pw, c)
    finally:
        c.stop()


@pytest.fixture(scope="session")
def vault() -> Iterator[ServiceUrl]:
    """Vault dev server with the transit engine and an aes256-gcm96 key ``agw-kek``."""
    import time

    import httpx
    from testcontainers.core.container import DockerContainer

    token = secrets.token_urlsafe(24)
    c = (
        DockerContainer(VAULT_IMAGE)
        .with_env("VAULT_DEV_ROOT_TOKEN_ID", token)
        .with_env("VAULT_DEV_LISTEN_ADDRESS", "0.0.0.0:8200")
        .with_kwargs(cap_add=["IPC_LOCK"])
        .with_exposed_ports(8200)
    )
    c.start()
    url = f"http://{c.get_container_host_ip()}:{c.get_exposed_port(8200)}"
    h = {"X-Vault-Token": token}
    for _ in range(100):
        try:
            if httpx.get(f"{url}/v1/sys/health", timeout=2).status_code == 200:
                break
        except httpx.HTTPError:
            pass
        time.sleep(0.3)
    httpx.post(f"{url}/v1/sys/mounts/transit", json={"type": "transit"}, headers=h)
    httpx.post(f"{url}/v1/transit/keys/agw-kek", json={"type": "aes256-gcm96"}, headers=h)
    try:
        yield ServiceUrl(url, "root", token, c)
    finally:
        c.stop()
