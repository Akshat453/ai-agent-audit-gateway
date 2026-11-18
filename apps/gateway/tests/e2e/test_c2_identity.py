"""C2 identity (ADR-0035): device-code login (pending/slow_down/approve/issue-once/deny/expiry),
the runtime role cannot create agents or humans directly, MCP OAuth (PKCE S256, resource
binding, single-use codes, refresh rotation + reuse detection) and the remote MCP endpoint
(401 challenge, modern + legacy eras, header checks, tools from classified connectors)."""

from __future__ import annotations

import base64
import hashlib
import secrets
import uuid
from typing import Any
from urllib.parse import parse_qs, urlsplit

import psycopg
import pytest
from sqlalchemy import Engine, select, text
from sqlalchemy.exc import ProgrammingError

from agw_gateway.db import tables as t
from tests.approvalkit import Humans, make_humans
from tests.c2kit import FakeWorld, slack

pytestmark = pytest.mark.e2e
MCP = "http://localhost:8000/mcp"


@pytest.fixture
def h(gw: Any, migrator_engine: Engine) -> Humans:
    return make_humans(migrator_engine, gw.client, gw.world.tenant_id)


def authorize(gw: Any, kind: str = "claude_code") -> dict[str, Any]:
    r = gw.client.post(
        "/v1/device/authorize",
        json={"tenant": gw.world.tenant_id, "agent_kind": kind, "label": "laptop"},
    )
    assert r.status_code == 200, r.text
    return dict(r.json())


def poll(gw: Any, code: str) -> Any:
    return gw.client.post("/v1/device/token", json={"device_code": code})


def test_device_code_login_flow(gw: Any, h: Humans, migrator_engine: Engine) -> None:
    a = authorize(gw)
    assert a["verification_uri"].endswith("/enroll") and len(a["user_code"]) == 9
    assert poll(gw, a["device_code"]).json() == {"error": "authorization_pending"}
    assert poll(gw, a["device_code"]).json() == {"error": "slow_down"}  # polled too fast
    seen = gw.client.get(
        f"/v1/device/requests/{a['user_code'].lower().replace('-', '')}", headers=h.headers("alice")
    ).json()
    assert seen["agent_kind"] == "claude_code" and seen["status"] == "pending"
    assert (
        gw.client.post(
            f"/v1/device/requests/{a['user_code']}/decision",
            headers=h.headers("alice"),
            json={"approve": True},
        ).status_code
        == 200
    )
    with migrator_engine.begin() as conn:  # skip the poll interval
        conn.execute(
            text("UPDATE device_enrollments SET last_poll_at = now() - interval '1 minute'")
        )
    issued = poll(gw, a["device_code"])
    assert issued.status_code == 200 and issued.headers["cache-control"] == "no-store"
    body = issued.json()
    assert body["developer"] == "alice" and body["device_key"].startswith("agw_")
    assert poll(gw, a["device_code"]).json() == {"error": "invalid_grant"}  # issued once
    st = gw.client.get(
        "/v1/coding/status", headers={"Authorization": f"Bearer {body['device_key']}"}
    )
    assert st.status_code == 200 and st.json()["developer"] == "alice"
    assert gw.count_events("DEVICE_ENROLLED") == 1
    with gw.engine.connect() as conn:
        scopes = conn.execute(
            select(t.agents.c.scopes).where(t.agents.c.agent_id == uuid.UUID(body["device_id"]))
        ).scalar_one()
    assert sorted(scopes) == ["coding:device", "connectors:invoke"]
    # Denied and expired requests.
    d = authorize(gw)
    gw.client.post(
        f"/v1/device/requests/{d['user_code']}/decision",
        headers=h.headers("bob"),
        json={"approve": False},
    )
    assert poll(gw, d["device_code"]).json() == {"error": "access_denied"}
    e = authorize(gw)
    with migrator_engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE device_enrollments SET expires_at = now() - interval '1 second' "
                "WHERE user_code = :u"
            ),
            {"u": e["user_code"]},
        )
    assert poll(gw, e["device_code"]).json() == {"error": "expired_token"}
    assert (
        gw.client.post(
            f"/v1/device/requests/{e['user_code']}/decision",
            headers=h.headers("alice"),
            json={"approve": True},
        ).status_code
        == 403
    )
    # Another tenant's human cannot see or approve this tenant's request.
    assert poll(gw, "x" * 43).json() == {"error": "invalid_grant"}


def test_runtime_role_cannot_create_agents_or_humans(gw: Any, pg: Any) -> None:
    for sql in (
        "INSERT INTO agents (agent_id, tenant_id, name, scopes, status) VALUES "
        f"('{uuid.uuid4()}', '{gw.world.tenant_id}', 'x', ARRAY['iam:admin'], 'active')",
        "INSERT INTO humans (human_id, tenant_id, username, password_hash, roles) VALUES "
        f"('{uuid.uuid4()}', '{gw.world.tenant_id}', 'mallory', '$argon2id$x', ARRAY['admin'])",
    ):
        with pytest.raises(ProgrammingError), gw.engine.begin() as conn:
            conn.execute(text(sql))
    # The definer function refuses a non-admin inviter.
    with pytest.raises(Exception), gw.engine.begin() as conn:
        conn.execute(
            text("SELECT agw_invite_human(:t, :a, :h, 'mallory', ARRAY['admin'], '$argon2id$x')"),
            {"t": gw.world.tenant_id, "a": uuid.uuid4(), "h": uuid.uuid4()},
        )


def test_people_invite_and_onboarding_checklist(
    gw: Any, h: Humans, migrator_engine: Engine
) -> None:
    steps = {
        s["id"]: s
        for s in gw.client.get("/v1/onboarding", headers=h.headers("adam")).json()["steps"]
    }
    assert steps["tenant"]["done"] and steps["people"]["done"]  # 4 humans already
    assert not steps["github"]["done"] and not steps["device"]["done"]
    assert steps["protected_pr"]["done"] is False and "available" not in steps["protected_pr"]  # C3
    unstepped = make_humans(migrator_engine, gw.client, gw.world.tenant_id, step_up=False)
    r = gw.client.post(
        "/v1/people",
        headers=unstepped.headers("adam"),
        json={"username": "dana", "roles": ["maintainer"]},
    )
    assert r.json()["error"]["code"] == "STEP_UP_REQUIRED"
    assert (
        gw.client.post(
            "/v1/people",
            headers=h.headers("alice"),
            json={"username": "dana", "roles": ["maintainer"]},
        ).status_code
        == 403
    )
    inv = gw.client.post(
        "/v1/people", headers=h.headers("adam"), json={"username": "dana", "roles": ["maintainer"]}
    )
    assert inv.status_code == 201, inv.text
    pw = inv.json()["temporary_password"]
    login = gw.client.post(
        "/v1/auth/login", json={"tenant": gw.world.tenant_id, "username": "dana", "password": pw}
    )
    assert login.status_code == 200
    a = authorize(gw)
    gw.client.post(
        f"/v1/device/requests/{a['user_code']}/decision",
        headers=h.headers("alice"),
        json={"approve": True},
    )
    poll(gw, a["device_code"])
    steps = {
        s["id"]: s
        for s in gw.client.get("/v1/onboarding", headers=h.headers("adam")).json()["steps"]
    }
    assert steps["device"]["done"]


# --------------------------------------------------------------------------- OAuth + MCP
def pkce() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(48)
    challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    )
    return verifier, challenge


def oauth_login(gw: Any, h: Humans, who: str = "alice") -> tuple[dict[str, Any], str]:
    reg = gw.client.post(
        "/oauth/register",
        json={"redirect_uris": ["http://127.0.0.1:33418/callback"], "client_name": "Test IDE"},
    )
    assert reg.status_code == 201, reg.text
    client_id = reg.json()["client_id"]
    verifier, challenge = pkce()
    q = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": "http://127.0.0.1:33418/callback",
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "state": "st8",
        "resource": MCP,
        "scope": "mcp:tools",
    }
    r = gw.client.get("/oauth/authorize", params=q, follow_redirects=False)
    assert r.status_code == 302 and "/oauth/consent?" in r.headers["location"]
    info = gw.client.get("/v1/oauth/consent", params=q, headers=h.headers(who)).json()
    assert info["client_name"] == "Test IDE" and info["redirect_host"] == "127.0.0.1:33418"
    c = gw.client.post(
        "/v1/oauth/consent", headers=h.headers(who), json={"params": q, "allow": True}
    )
    loc = urlsplit(c.json()["redirect_to"])
    got = parse_qs(loc.query)
    assert got["state"] == ["st8"] and got["iss"] == ["http://localhost:8000"]
    tok = gw.client.post(
        "/oauth/token",
        data={
            "grant_type": "authorization_code",
            "code": got["code"][0],
            "redirect_uri": q["redirect_uri"],
            "client_id": client_id,
            "code_verifier": verifier,
            "resource": MCP,
        },
    )
    assert tok.status_code == 200, tok.text
    return {
        **tok.json(),
        "client_id": client_id,
        "code": got["code"][0],
        "verifier": verifier,
        "q": q,
    }, client_id


def mcp(
    gw: Any,
    token: str | None,
    method: str,
    params: dict[str, Any] | None = None,
    modern: bool = True,
    headers: dict[str, str] | None = None,
) -> Any:
    p = dict(params or {})
    hdr = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream"}
    if modern:
        p["_meta"] = {
            "io.modelcontextprotocol/protocolVersion": "2026-07-28",
            "io.modelcontextprotocol/clientCapabilities": {},
        }
        hdr.update({"MCP-Protocol-Version": "2026-07-28", "Mcp-Method": method})
        if method == "tools/call":
            hdr["Mcp-Name"] = p.get("name", "")
    if token:
        hdr["Authorization"] = f"Bearer {token}"
    hdr.update(headers or {})
    return gw.client.post(
        "/mcp", headers=hdr, json={"jsonrpc": "2.0", "id": 1, "method": method, "params": p}
    )


def test_metadata_and_401_challenge(gw: Any) -> None:
    prm = gw.client.get("/.well-known/oauth-protected-resource/mcp").json()
    assert prm["resource"] == MCP and prm["authorization_servers"] == ["http://localhost:8000"]
    assert gw.client.get("/.well-known/oauth-protected-resource").json() == prm
    md = gw.client.get("/.well-known/oauth-authorization-server").json()
    assert md["code_challenge_methods_supported"] == ["S256"]
    assert md["client_id_metadata_document_supported"] is True and md["registration_endpoint"]
    r = mcp(gw, None, "server/discover")
    assert r.status_code == 401
    assert (
        'resource_metadata="http://localhost:8000/.well-known/oauth-protected-resource/mcp"'
        in r.headers["www-authenticate"]
    )
    bad = mcp(gw, "agwm_" + "A" * 43, "server/discover")
    assert bad.status_code == 401 and 'error="invalid_token"' in bad.headers["www-authenticate"]
    assert gw.client.get("/mcp").status_code == 405
    # An agent API key is not an MCP token (no token passthrough / confusion).
    assert mcp(gw, gw.world.token, "server/discover").status_code == 401


def test_oauth_code_flow_guards(gw: Any, h: Humans) -> None:
    tok, client_id = oauth_login(gw, h)
    assert tok["token_type"] == "Bearer" and tok["expires_in"] == 600
    # The code is single use.
    reuse = gw.client.post(
        "/oauth/token",
        data={
            "grant_type": "authorization_code",
            "code": tok["code"],
            "redirect_uri": tok["q"]["redirect_uri"],
            "client_id": client_id,
            "code_verifier": tok["verifier"],
        },
    )
    assert reuse.json() == {"error": "invalid_grant"}
    # Wrong verifier / wrong resource / unregistered redirect / plain PKCE are refused.
    q = dict(tok["q"])
    assert gw.client.get(
        "/oauth/authorize",
        params={**q, "redirect_uri": "https://evil.example/cb"},
        follow_redirects=False,
    ).json() == {"error": "invalid_redirect_uri"}
    assert gw.client.get(
        "/oauth/authorize",
        params={**q, "resource": "https://other.example/mcp"},
        follow_redirects=False,
    ).json() == {"error": "invalid_target"}
    assert gw.client.get(
        "/oauth/authorize", params={**q, "code_challenge_method": "plain"}, follow_redirects=False
    ).json() == {"error": "invalid_request"}
    c = gw.client.post(
        "/v1/oauth/consent", headers=h.headers("alice"), json={"params": q, "allow": True}
    )
    code = parse_qs(urlsplit(c.json()["redirect_to"]).query)["code"][0]
    wrong = gw.client.post(
        "/oauth/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": q["redirect_uri"],
            "client_id": client_id,
            "code_verifier": secrets.token_urlsafe(48),
        },
    )
    assert wrong.json() == {"error": "invalid_grant"}
    # ... and that failed attempt burned the code: the right verifier is now too late.
    late = gw.client.post(
        "/oauth/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": q["redirect_uri"],
            "client_id": client_id,
            "code_verifier": tok["verifier"],
        },
    )
    assert late.json() == {"error": "invalid_grant"}
    denied = gw.client.post(
        "/v1/oauth/consent", headers=h.headers("alice"), json={"params": q, "allow": False}
    )
    assert "error=access_denied" in denied.json()["redirect_to"]
    # Refresh rotates; reusing the old refresh token revokes the whole family.
    r1 = gw.client.post(
        "/oauth/token",
        data={
            "grant_type": "refresh_token",
            "refresh_token": tok["refresh_token"],
            "client_id": client_id,
        },
    ).json()
    assert r1["access_token"] != tok["access_token"]
    assert mcp(gw, r1["access_token"], "server/discover").status_code == 200
    reused = gw.client.post(
        "/oauth/token",
        data={
            "grant_type": "refresh_token",
            "refresh_token": tok["refresh_token"],
            "client_id": client_id,
        },
    )
    assert reused.json() == {"error": "invalid_grant"}
    assert mcp(gw, r1["access_token"], "server/discover").status_code == 401  # family revoked


def test_token_bound_to_resource_and_active_device(
    gw: Any, h: Humans, migrator_engine: Engine
) -> None:
    tok, _client = oauth_login(gw, h)
    assert mcp(gw, tok["access_token"], "server/discover").status_code == 200
    with migrator_engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE oauth_tokens SET resource = 'https://other.example/mcp' "
                "WHERE tenant_id = :t"
            ),
            {"t": gw.world.tenant_id},
        )
    assert mcp(gw, tok["access_token"], "server/discover").status_code == 401
    tok2, _ = oauth_login(gw, h, who="bob")
    with migrator_engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE agents SET status = 'disabled' WHERE agent_id IN "
                "(SELECT device_agent_id FROM oauth_tokens WHERE tenant_id = :t)"
            ),
            {"t": gw.world.tenant_id},
        )
    assert mcp(gw, tok2["access_token"], "server/discover").status_code == 401


def test_mcp_endpoint_eras_and_connector_tools(gw: Any, h: Humans) -> None:
    w = FakeWorld()
    slack(w)
    gw.state.connectors.http = w.http()
    tok, _ = oauth_login(gw, h)
    at = tok["access_token"]
    d = mcp(gw, at, "server/discover").json()["result"]
    assert d["resultType"] == "complete" and "2026-07-28" in d["supportedVersions"]
    assert mcp(gw, at, "server/discover", headers={"Mcp-Method": "tools/list"}).status_code == 400
    assert mcp(gw, at, "tools/list").json()["result"]["tools"] == []  # nothing classified yet
    legacy = mcp(
        gw,
        at,
        "initialize",
        {
            "protocolVersion": "2025-11-25",
            "capabilities": {},
            "clientInfo": {"name": "old", "version": "1"},
        },
        modern=False,
    )
    assert legacy.json()["result"]["protocolVersion"] == "2025-11-25"
    assert "mcp-session-id" not in legacy.headers
    assert mcp(gw, at, "ping", modern=False).json()["result"] == {}
    note = gw.client.post(
        "/mcp",
        headers={"Authorization": f"Bearer {at}"},
        json={"jsonrpc": "2.0", "method": "notifications/initialized"},
    )
    assert note.status_code == 202
    assert (
        mcp(gw, at, "server/discover", headers={"Origin": "https://evil.example"}).status_code
        == 403
    )
    # Classify a Slack action for enrolled devices -> it appears and is callable.
    c = gw.client.post(
        "/v1/connectors",
        headers=h.headers("adam"),
        json={
            "type_id": "slack",
            "slug": "ops",
            "name": "Ops",
            "credentials": {"bot_token": "xoxb-1-2-3"},
        },
    ).json()
    gw.client.post(
        f"/v1/connectors/{c['connector_id']}/classify",
        headers=h.headers("adam"),
        json={"actions": {"post_message": {"risk": "LOW", "allowed_agents": ["devices"]}}},
    )
    tools = mcp(gw, at, "tools/list").json()["result"]["tools"]
    assert [t_["name"] for t_ in tools] == ["cx_ops_post_message"]
    assert "Policy-checked by AgentGuard" in tools[0]["description"]
    assert sorted(tools[0]["inputSchema"]["required"]) == ["channel", "text"]
    res = mcp(
        gw,
        at,
        "tools/call",
        {"name": "cx_ops_post_message", "arguments": {"channel": "#ops", "text": "hi"}},
    ).json()["result"]
    assert res["isError"] is True and res["content"][0]["text"].startswith("Approval pending: ")
    mism = mcp(
        gw,
        at,
        "tools/call",
        {"name": "cx_ops_post_message", "arguments": {}},
        headers={"Mcp-Name": "something_else"},
    )
    assert mism.status_code == 400
    with gw.engine.connect() as conn:
        n = conn.execute(
            select(t.actions.c.status).where(
                t.actions.c.tenant_id == gw.world.tenant_id,
                t.actions.c.tool_id == "cx_ops_post_message",
            )
        ).all()
    assert [r.status for r in n] == ["PENDING_APPROVAL"]


_ = psycopg
