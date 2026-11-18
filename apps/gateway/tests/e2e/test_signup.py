"""Self-service sign-up (dev/test only): a new tenant with its first admin.

Invariants:
1. OFF by default: the endpoint is 404 and reports ``enabled: false``.
2. Refused outside dev/test: ``signup_enabled`` cannot be configured in prod.
3. Never takes over an existing tenant (409, the existing humans are unchanged).
4. Weak or malformed input is rejected (422, field names only).
5. The new admin's session sees only their own tenant.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError
from sqlalchemy import Engine, select

from agw_gateway.api.app import build_state, create_app
from agw_gateway.config import Settings
from agw_gateway.db import tables as t
from tests.conftest import make_settings

pytestmark = pytest.mark.e2e
PASSWORD = "correct horse battery staple"


@pytest.fixture
def signup_client(pg: Any, app_engine: Engine, tmp_path: Path) -> Iterator[TestClient]:
    state = build_state(make_settings(pg.app, tmp_path, signup_enabled=True), engine=app_engine)
    state.sync()
    with TestClient(create_app(state, sync_registry=False)) as client:
        yield client


def _body(tenant: str, **kw: Any) -> dict[str, Any]:
    return {
        "organization": "Akshat Test Co",
        "tenant": tenant,
        "username": "akshat",
        "password": PASSWORD,
        **kw,
    }


def test_signup_is_off_by_default(gw: Any) -> None:
    assert gw.client.get("/v1/auth/signup").json() == {"enabled": False}
    r = gw.client.post("/v1/auth/signup", json=_body(f"t{uuid.uuid4().hex[:8]}"))
    assert r.status_code == 404


def test_signup_is_refused_outside_dev_and_test() -> None:
    common: dict[str, Any] = {
        "env": "prod",
        "database_url": "postgresql+psycopg://x:y@localhost/z",
        "_env_file": None,
    }
    Settings(**common)  # the same prod settings are valid without sign-up
    with pytest.raises(ValidationError, match="sign-up is refused outside dev/test"):
        Settings(**common, signup_enabled=True)


def test_signup_creates_tenant_and_admin_session(
    signup_client: TestClient, app_engine: Engine, gw: Any
) -> None:
    c = signup_client
    assert c.get("/v1/auth/signup").json() == {"enabled": True}
    tenant = f"acme-{uuid.uuid4().hex[:6]}"
    r = c.post("/v1/auth/signup", json=_body(tenant))
    assert r.status_code == 201, r.text
    token = r.json()["session_token"]
    assert token.startswith("agws_") and r.json()["tenant"] == tenant
    me = c.get("/v1/auth/me", headers={"Authorization": f"Session {token}"}).json()
    assert me["tenant"] == tenant and me["username"] == "akshat"
    assert {"admin", "approver", "security", "auditor"} <= set(me["roles"])
    with app_engine.connect() as conn:
        assert (
            conn.execute(
                select(t.tenants.c.display_name).where(t.tenants.c.tenant_id == tenant)
            ).scalar_one()
            == "Akshat Test Co"
        )
        assert (
            conn.execute(
                select(t.chain_heads.c.last_seq).where(t.chain_heads.c.tenant_id == tenant)
            ).scalar_one()
            == -1
        )
    # The password works for a normal login afterwards.
    login = c.post(
        "/v1/auth/login", json={"tenant": tenant, "username": "akshat", "password": PASSWORD}
    )
    assert login.status_code == 200
    # Isolation: the new tenant's session sees nothing of the fixture tenant.
    people = c.get("/v1/people", headers={"Authorization": f"Session {token}"}).json()
    assert [p["username"] for p in people["people"]] == ["akshat"]
    runs = c.get("/v1/dashboard/runs", headers={"Authorization": f"Session {token}"})
    assert runs.status_code == 200 and runs.json() == []
    _ = gw


def test_signup_never_takes_over_an_existing_tenant(
    signup_client: TestClient, app_engine: Engine, gw: Any
) -> None:
    existing = gw.world.tenant_id
    with app_engine.connect() as conn:
        before = conn.execute(
            select(t.humans.c.username, t.humans.c.password_hash).where(
                t.humans.c.tenant_id == existing
            )
        ).all()
    r = signup_client.post("/v1/auth/signup", json=_body(existing))
    assert r.status_code == 409
    with app_engine.connect() as conn:
        after = conn.execute(
            select(t.humans.c.username, t.humans.c.password_hash).where(
                t.humans.c.tenant_id == existing
            )
        ).all()
    assert sorted(before) == sorted(after)


@pytest.mark.parametrize(
    "override",
    [
        {"password": "short"},
        {"password": "a" * 1025},
        {"tenant": "Bad Tenant!"},
        {"tenant": "x"},
        {"username": "has space"},
        {"organization": ""},
    ],
)
def test_signup_rejects_bad_input(signup_client: TestClient, override: dict[str, Any]) -> None:
    body = {**_body(f"ok-{uuid.uuid4().hex[:6]}"), **override}
    assert signup_client.post("/v1/auth/signup", json=body).status_code == 422
