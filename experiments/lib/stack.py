"""An in-process gateway on a throwaway Postgres 16 (Testcontainers), configured per ablation
configuration. Reuses the test suite's setup so experiments and tests run the same code."""

from __future__ import annotations

import sys
import tempfile
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path
from typing import Any

from experiments.lib.common import REPO

sys.path.insert(0, str(REPO / "apps" / "gateway"))

from tests.conftest import (
    ALL_SCOPES,
    PgUrls,
    init_database,
    make_registry,
    make_settings,
    make_spies,
    start_postgres,
)


@contextmanager
def postgres() -> Iterator[PgUrls]:
    with postgres_container() as (_, urls):
        yield urls


@contextmanager
def postgres_container() -> Iterator[tuple[Any, PgUrls]]:
    """The container too (RQ5 pauses it to partition the database)."""
    container = start_postgres()
    try:
        yield container, init_database(container)
    finally:
        container.stop()


@dataclass
class Gateway:
    state: Any
    spies: Any
    tenant: str
    token: str
    migrator: Any
    engine: Any


def new_tenant(migrator: Any, scopes: tuple[str, ...] = ALL_SCOPES) -> tuple[str, str]:
    from agw_gateway.admin import create_key, ensure_agent, ensure_tenant

    tenant = f"x-{uuid.uuid4().hex[:12]}"
    ensure_tenant(migrator, tenant, "experiment")
    ensure_agent(migrator, tenant, "agent", scopes)
    return tenant, create_key(migrator, tenant, "agent", timedelta(hours=6))


@contextmanager
def gateway(
    urls: PgUrls,
    *,
    ablation: str | None,
    tenant: tuple[str, str] | None = None,
    spies: Any = None,
    **overrides: Any,
) -> Iterator[Gateway]:
    """``tenant`` = (tenant id, agent token) to attach to an existing tenant (crash recovery);
    ``spies`` = pre-built spy adapters (e.g. ones that log side effects to a file)."""
    from agw_gateway.api.app import build_state
    from agw_gateway.db import create_db_engine

    engine = create_db_engine(urls.app, pool_size=60)
    migrator = create_db_engine(urls.migrator, pool_size=4)
    spies = spies or make_spies()
    settings = make_settings(urls.app, Path(tempfile.mkdtemp()), ablation=ablation, **overrides)
    state = build_state(settings, engine=engine, registry=make_registry(spies))
    state.sync()
    tenant, token = tenant or new_tenant(migrator)
    for s in spies.all():
        s.tenant = tenant
    try:
        yield Gateway(state, spies, tenant, token, migrator, engine)
    finally:
        state.executor.close()
        engine.dispose()
        migrator.dispose()
