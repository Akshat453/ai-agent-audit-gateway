"""Helpers for the Phase 7 tests (ADR-0029): a configurable gateway, event/payload lookups, a
superuser binary dump of the whole database (the DB-only attacker), and canary scanning."""

from __future__ import annotations

import contextlib
import io
import secrets
import uuid
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import psycopg
from fastapi.testclient import TestClient
from sqlalchemy import Engine, select

from agw_gateway.api.app import build_state, create_app
from agw_gateway.crypto.canonical import decode
from agw_gateway.db import tables as t
from agw_gateway.evidence.export import export_chain
from agw_verifier.chain import verify_lines

from .conftest import Gw, PgUrls, World, make_registry, make_settings, make_spies


def canary(label: str) -> str:
    return f"CANARY-{label}-{secrets.token_hex(6)}"


@contextlib.contextmanager
def gateway(
    pg: PgUrls,
    app_engine: Engine,
    world: World,
    tmp_path: Path,
    *,
    key_provider: Any = None,
    blob_store: Any = None,
    **overrides: Any,
) -> Iterator[Gw]:
    spies = make_spies()
    for spy in spies.all():
        spy.tenant = world.tenant_id
    state = build_state(
        make_settings(pg.app, tmp_path, **overrides),
        engine=app_engine,
        registry=make_registry(spies),
        key_provider=key_provider,
        blob_store=blob_store,
    )
    state.sync()
    with TestClient(create_app(state, sync_registry=False)) as client:
        g = Gw(state=state, client=client, spies=spies, world=world, engine=app_engine)
        yield g


def event_id(gw: Any, action_id: str, event_type: str) -> uuid.UUID:
    with gw.engine.connect() as conn:
        return uuid.UUID(
            str(
                conn.execute(
                    select(t.evidence_events.c.event_id).where(
                        t.evidence_events.c.action_id == uuid.UUID(str(action_id)),
                        t.evidence_events.c.event_type == event_type,
                    )
                ).scalar_one()
            )
        )


def header(gw: Any, eid: uuid.UUID) -> dict[str, Any]:
    with gw.engine.connect() as conn:
        cb = conn.execute(
            select(t.evidence_events.c.canonical_bytes).where(t.evidence_events.c.event_id == eid)
        ).scalar_one()
    rec: dict[str, Any] = decode(bytes(cb))
    return rec


def payload(gw: Any, eid: uuid.UUID) -> dict[str, Any] | None:
    with gw.engine.connect() as conn:
        raw = gw.state.payloads.load_payload(conn, eid)
    return decode(raw) if raw is not None else None


def export_lines(gw: Any) -> list[str]:
    buf = io.StringIO()
    export_chain(gw.engine, gw.world.tenant_id, buf, store=gw.state.payloads)
    return buf.getvalue().splitlines()


def verify_export(gw: Any) -> Any:
    return verify_lines(export_lines(gw))


def su(pg: PgUrls, sql: str, params: tuple[Any, ...] = ()) -> None:
    """Privileged insider: superuser, triggers and FK checks off."""
    with psycopg.connect(pg.superuser, autocommit=True) as conn:
        conn.execute("SET session_replication_role = replica")
        conn.execute(sql, params)  # type: ignore[arg-type]


def dump_database(pg: PgUrls) -> bytes:
    """What a DB-only attacker gets: every row of every table (binary COPY), no KEK."""
    out = bytearray()
    with psycopg.connect(pg.superuser, autocommit=True) as conn:
        tables = conn.execute(
            "SELECT table_schema, table_name FROM information_schema.tables "
            "WHERE table_schema IN ('public', 'demo') AND table_type = 'BASE TABLE'"
        ).fetchall()
        for schema, name in tables:
            with conn.cursor().copy(f'COPY "{schema}"."{name}" TO STDOUT (FORMAT binary)') as cp:
                for chunk in cp:
                    out += bytes(chunk)
    return bytes(out)


def headers_blob(gw: Any) -> bytes:
    """Every stored header of the tenant: canonical bytes + the JSONB projection."""
    with gw.engine.connect() as conn:
        rows = conn.execute(
            select(t.evidence_events.c.canonical_bytes, t.evidence_events.c.body).where(
                t.evidence_events.c.tenant_id == gw.world.tenant_id
            )
        ).all()
    return b"".join(bytes(r.canonical_bytes) + repr(r.body).encode() for r in rows)
