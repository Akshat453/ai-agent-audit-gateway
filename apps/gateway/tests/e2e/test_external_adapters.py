"""Phase 8 real external adapters (ADR-0030 §7).

* public_api_get: a real HTTP GET to an allowlisted host (a local server stands in for the
  public API). Off-allowlist URLs are DENIED before any network I/O; redirects are not
  followed; responses are size-capped; the body digest is returned for context provenance.
* send_email_smtp: an APPROVED write to a real SMTP server (Mailpit, pinned by digest). Every
  send needs an approval; the relay credential lives only in the gateway (canary-checked).
"""

from __future__ import annotations

import json
import secrets
import threading
import time
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine

from agw_gateway.api.app import build_state, create_app
from agw_gateway.tools.adapters.external import external_tool_specs
from agw_gateway.tools.demo import demo_tool_specs
from agw_gateway.tools.registry import ToolRegistry

from ..approvalkit import decide, make_humans
from ..conftest import Gw, PgUrls, World, make_settings, make_spies

pytestmark = pytest.mark.e2e

MAILPIT_IMAGE = (
    "axllent/mailpit@sha256:e22dce5b36f93c77082e204a3942fb6b283b7896e057458400a4c88344c3df68"
)
EXT_SCOPES = ["tools:public_api_get", "tools:send_email_smtp"]


class _Handler(BaseHTTPRequestHandler):
    hits: list[str]

    def log_message(self, *a: Any) -> None:
        pass

    def do_GET(self) -> None:
        self.server.hits.append(self.path)  # type: ignore[attr-defined]
        if self.path == "/status":
            body = json.dumps({"service": "public-api", "ok": True}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
        elif self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", self.server.redirect_to)  # type: ignore[attr-defined]
            body = b""
        elif self.path == "/big":
            body = b"x" * 200_000
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
        else:
            body = b"not found"
            self.send_response(404)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture
def http_servers() -> Iterator[tuple[ThreadingHTTPServer, ThreadingHTTPServer]]:
    servers = []
    for _ in range(2):
        srv = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        srv.hits = []  # type: ignore[attr-defined]
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        servers.append(srv)
    api, evil = servers
    api.redirect_to = f"http://127.0.0.1:{evil.server_port}/status"  # type: ignore[attr-defined]
    yield api, evil
    for s in servers:
        s.shutdown()


@pytest.fixture(scope="module")
def mailpit() -> Iterator[dict[str, Any]]:
    from testcontainers.core.container import DockerContainer

    c = (
        DockerContainer(MAILPIT_IMAGE)
        .with_env("MP_SMTP_AUTH_ACCEPT_ANY", "1")
        .with_env("MP_SMTP_AUTH_ALLOW_INSECURE", "1")
        .with_exposed_ports(1025, 8025)
    )
    c.start()
    host = c.get_container_host_ip()
    api = f"http://{host}:{c.get_exposed_port(8025)}"
    for _ in range(100):
        try:
            if httpx.get(f"{api}/api/v1/messages", timeout=2).status_code == 200:
                break
        except httpx.HTTPError:
            time.sleep(0.2)
    try:
        yield {"host": host, "port": int(c.get_exposed_port(1025)), "api": api}
    finally:
        c.stop()


@pytest.fixture
def ext(
    pg: PgUrls,
    app_engine: Engine,
    migrator_engine: Engine,
    world: World,
    tmp_path: Path,
    http_servers: Any,
    mailpit: dict[str, Any],
) -> Iterator[Any]:
    api, _evil = http_servers
    smtp_password = f"SMTP-CANARY-{secrets.token_hex(8)}"
    settings = make_settings(
        pg.app,
        tmp_path,
        http_allowlist=(f"127.0.0.1:{api.server_port}",),
        http_allow_plain=(f"127.0.0.1:{api.server_port}",),
        http_max_response_bytes=4096,
        smtp_host=mailpit["host"],
        smtp_port=mailpit["port"],
        smtp_starttls=False,
        smtp_username="agw-relay",
        smtp_password=smtp_password,
        smtp_from="gateway@corp.example",
        smtp_allowed_domains=("corp.example", "partner.example"),
    )
    spies = make_spies()
    registry = ToolRegistry([*demo_tool_specs(search=spies.search), *external_tool_specs(settings)])
    state = build_state(settings, engine=app_engine, registry=registry)
    state.sync()
    from agw_gateway.admin import create_key, ensure_agent

    ensure_agent(migrator_engine, world.tenant_id, "ext-agent", EXT_SCOPES)
    token = create_key(migrator_engine, world.tenant_id, "ext-agent")
    with TestClient(create_app(state, sync_registry=False)) as client:
        g = Gw(state=state, client=client, spies=spies, world=world, engine=app_engine)
        g.world.extra.update(token=token, password=smtp_password, api=api, mailpit=mailpit)
        yield g
        g.drain()


def _post(g: Any, tool: str, args: dict[str, Any]) -> dict[str, Any]:
    r = g.post(tool, args, token=g.world.extra["token"])
    assert r.status_code == 201, r.text
    body: dict[str, Any] = r.json()
    return body


def _result(g: Any, action_id: str) -> dict[str, Any]:
    g.drain()
    r = g.client.get(
        f"/v1/actions/{action_id}", headers={"Authorization": f"Bearer {g.world.extra['token']}"}
    )
    body: dict[str, Any] = r.json()
    return body


def test_public_api_get_allowlisted_host(ext: Any) -> None:
    api = ext.world.extra["api"]
    a = _post(ext, "public_api_get", {"url": f"http://127.0.0.1:{api.server_port}/status"})
    assert a["status"] == "AUTHORIZED" and a["decision"]["risk_level"] == "LOW"
    view = _result(ext, a["action_id"])
    assert view["status"] == "COMPLETED"
    assert view["result"]["body"] == {"service": "public-api", "ok": True}
    assert len(view["result"]["sha256"]) == 64 and api.hits == ["/status"]


@pytest.mark.parametrize(
    "url",
    [
        "http://169.254.169.254/latest/meta-data/",  # cloud metadata (SSRF)
        "https://evil.example/exfil?d=secret",
        "http://127.0.0.1:1/status",  # right host, wrong port
        "file:///etc/passwd",
        "https://user:pw@api.example/",
    ],
)
def test_public_api_get_off_allowlist_denied_without_io(ext: Any, url: str) -> None:
    a = _post(ext, "public_api_get", {"url": url})
    assert a["status"] == "DENIED" and a["decision"]["reasons"] == ["ARGS_SCHEMA_INVALID"]
    ext.drain()
    assert ext.world.extra["api"].hits == []


def test_public_api_get_does_not_follow_redirects_and_caps_size(
    ext: Any, http_servers: Any
) -> None:
    api, evil = http_servers
    a = _post(ext, "public_api_get", {"url": f"http://127.0.0.1:{api.server_port}/redirect"})
    view = _result(ext, a["action_id"])
    assert view["status"] == "COMPLETED" and view["result"]["status"] == 302
    assert evil.hits == []  # the redirect target (not allowlisted) was never contacted
    b = _post(ext, "public_api_get", {"url": f"http://127.0.0.1:{api.server_port}/big"})
    big = _result(ext, b["action_id"])
    assert big["result"]["truncated"] is True and len(big["result"]["body"]) == 4096


def _messages(mailpit: dict[str, Any]) -> list[dict[str, Any]]:
    msgs: list[dict[str, Any]] = httpx.get(f"{mailpit['api']}/api/v1/messages").json()["messages"]
    return msgs


def test_send_email_smtp_requires_approval_then_delivers(
    ext: Any, migrator_engine: Engine, caplog: pytest.LogCaptureFixture
) -> None:
    mailpit = ext.world.extra["mailpit"]
    subject = f"summary {secrets.token_hex(4)}"
    a = _post(ext, "send_email_smtp", {"to": ["ops@corp.example"], "subject": subject})
    assert a["status"] == "PENDING_APPROVAL"  # even an internal recipient needs approval
    ext.drain()
    assert not [m for m in _messages(mailpit) if m["Subject"] == subject]
    humans = make_humans(migrator_engine, ext.client, ext.world.tenant_id)
    assert decide(ext, humans, a["approval"]["approval_id"]).status_code == 200
    view = _result(ext, a["action_id"])
    assert view["status"] == "COMPLETED" and view["result"] == {"accepted": 1}
    sent = [m for m in _messages(mailpit) if m["Subject"] == subject]
    assert len(sent) == 1 and sent[0]["From"]["Address"] == "gateway@corp.example"
    # The relay credential never leaves the gateway runtime.
    leaked = ext.world.extra["password"]
    assert leaked not in json.dumps(view) and leaked not in caplog.text
    assert leaked not in repr(ext.state.registry.resolve("send_email_smtp", None).adapter)


@pytest.mark.parametrize(
    "args",
    [
        {"to": ["attacker@evil.example"], "subject": "exfil"},  # domain not allowed
        {"to": ["ops@corp.example"], "subject": "hi\r\nBcc: attacker@evil.example"},
        {"to": ["ops@corp.example>, x@evil.example"], "subject": "s"},
    ],
)
def test_send_email_smtp_rejects_bad_recipients_and_header_injection(
    ext: Any, args: dict[str, Any]
) -> None:
    a = _post(ext, "send_email_smtp", args)
    assert a["status"] == "DENIED" and a["decision"]["reasons"] == ["ARGS_SCHEMA_INVALID"]
