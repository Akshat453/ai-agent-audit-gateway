"""Phase 8 MCP adapter (ADR-0030 §6): conformance against the MCP Python SDK's OWN client over
real Streamable HTTP (spec 2026-07-28), with the real gateway behind it.

* 401 + WWW-Authenticate(resource_metadata) without a token; RFC 9728 metadata served
* only tokens issued for THIS resource are accepted (a gateway key is refused, and an MCP
  token is refused by the gateway API itself: no passthrough either way)
* tools/list = exactly the agent's permitted tools
* tools/call: COMPLETED -> structured success; DENIED / PENDING_APPROVAL -> is_error with the
  gateway status (never a fake success); approval then agw_action_status -> COMPLETED
* delegation through MCP (AGW-Delegation header) is verified and recorded
* revoking the agent's key stops it immediately (the gateway checks every exchanged token)
"""

from __future__ import annotations

import asyncio
import json
import uuid
from typing import Any

import httpx
import httpx2
import pytest
from mcp import Client
from mcp.client.streamable_http import streamable_http_client
from sqlalchemy import Engine

from agw_gateway.admin import create_integration_client, create_key, revoke_key
from agw_gateway.api.app import create_app
from agw_mcp import AdapterConfig, build_app

from ..approvalkit import EXTERNAL, decide, make_humans
from ..delegationkit import delegate, new_agent
from ..privacykit import event_id, header, payload
from ..servekit import free_port, pump, serve

pytestmark = pytest.mark.e2e


class Stack:
    def __init__(self, gw: Any, migrator: Engine, gateway_url: str, mcp_url: str) -> None:
        self.gw, self.migrator, self.gateway_url, self.mcp_url = gw, migrator, gateway_url, mcp_url

    def token_for(self, agent_name: str) -> str:
        return create_key(self.migrator, self.gw.world.tenant_id, agent_name, audience=self.mcp_url)

    def run(self, token: str | None, coro_fn: Any, **headers: str) -> Any:
        async def main() -> Any:
            h = dict(headers)
            if token:
                h["Authorization"] = f"Bearer {token}"
            async with (
                httpx2.AsyncClient(headers=h, timeout=30) as http,
                Client(streamable_http_client(self.mcp_url, http_client=http)) as c,
            ):
                return await coro_fn(c)

        return asyncio.run(main())


@pytest.fixture
def stack(gw: Any, migrator_engine: Engine) -> Any:
    mcp_port = free_port()
    mcp_url = f"http://127.0.0.1:{mcp_port}/mcp"
    client_token = create_integration_client(
        migrator_engine, gw.world.tenant_id, "mcp-test", mcp_url
    )
    with serve(create_app(gw.state, sync_registry=False)) as gateway_url:
        cfg = AdapterConfig(
            gateway_url=gateway_url, client_token=client_token, resource_url=mcp_url
        )
        with serve(build_app(cfg), port=mcp_port), pump(gw):
            yield Stack(gw, migrator_engine, gateway_url, mcp_url)


def _body(result: Any) -> dict[str, Any]:
    data: dict[str, Any] = result.structured_content or json.loads(result.content[0].text)
    return data


def test_unauthenticated_gets_401_with_resource_metadata(stack: Stack) -> None:
    r = httpx.post(stack.mcp_url, json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
    assert r.status_code == 401
    challenge = r.headers["www-authenticate"]
    assert challenge.startswith("Bearer") and "resource_metadata=" in challenge
    meta_url = challenge.split('resource_metadata="')[1].split('"')[0]
    meta = httpx.get(meta_url).json()
    assert meta["resource"] == stack.mcp_url
    assert meta["authorization_servers"] == [stack.gateway_url] or meta[
        "authorization_servers"
    ] == [stack.gateway_url + "/"]


def test_only_tokens_for_this_resource_are_accepted(stack: Stack) -> None:
    # (a) a plain GATEWAY key (no audience) is not an MCP token
    r = httpx.post(
        stack.mcp_url,
        json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
        headers={"Authorization": f"Bearer {stack.gw.world.token}"},
    )
    assert r.status_code == 401
    # (b) an MCP token is refused by the gateway API itself (it is not for that audience)
    mcp_token = stack.token_for("demo-agent")
    r = httpx.get(f"{stack.gateway_url}/v1/tools", headers={"Authorization": f"Bearer {mcp_token}"})
    assert r.status_code == 401
    # (c) a token bound to ANOTHER MCP server's URI is refused here
    other = create_key(stack.migrator, stack.gw.world.tenant_id, "demo-agent",
                       audience="https://other.example/mcp")  # fmt: skip
    r = httpx.post(
        stack.mcp_url,
        json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
        headers={"Authorization": f"Bearer {other}"},
    )
    assert r.status_code == 401


def test_tools_list_is_exactly_what_the_agent_may_call(stack: Stack) -> None:
    async def names(c: Client) -> list[str]:
        # The SDK client negotiated the CURRENT spec revision (stateless, server/discover).
        assert c.protocol_version == "2026-07-28"
        return sorted(t.name for t in (await c.list_tools()).tools)

    readonly = stack.run(stack.token_for("demo-readonly"), names)
    assert readonly == ["agw_action_status", "public_doc_search"]
    full = stack.run(stack.token_for("demo-agent"), names)
    assert {"create_ticket", "delete_record", "send_email"} <= set(full)


def test_call_completed_denied_and_pending_approval(stack: Stack) -> None:
    gw = stack.gw
    token = stack.token_for("demo-agent")
    run_id = str(uuid.uuid4())

    async def calls(c: Client) -> list[Any]:
        return [
            await c.call_tool("public_doc_search", {"query": "gateway", "limit": 1}),
            await c.call_tool(
                "delete_record", {"record_id": "00000000-0000-0000-0000-000000000001"}
            ),
            await c.call_tool("send_email", {"to": EXTERNAL, "subject": "summary"}),
        ]

    ok, denied, pending = stack.run(token, calls, **{"AGW-Run-Id": run_id})
    assert ok.is_error is False and _body(ok)["status"] == "COMPLETED"
    assert _body(ok)["result"]["count"] == 1
    assert denied.is_error is True and _body(denied)["status"] == "DENIED"
    assert _body(denied)["executed"] is False and gw.spies.delete.calls == []
    p = _body(pending)
    assert pending.is_error is True and p["status"] == "PENDING_APPROVAL" and p["approval_id"]
    assert gw.spies.email.calls == []  # not executed, not a fake success
    # The request records that it came through the MCP integration, under the agent's id.
    req = payload(gw, event_id(gw, _body(ok)["action_id"], "ACTION_REQUESTED"))
    assert req is not None and req["context"]["via"] == "mcp:mcp-test"
    h = header(gw, event_id(gw, _body(ok)["action_id"], "ACTION_REQUESTED"))
    assert h["actor"] == {"kind": "agent", "id": str(gw.world.agent_id)}
    assert h["run"] == uuid.UUID(run_id).bytes
    # A human approves; the client polls the status tool.
    humans = make_humans(stack.migrator, gw.client, gw.world.tenant_id)
    assert decide(gw, humans, p["approval_id"]).status_code == 200

    async def status(c: Client) -> Any:
        for _ in range(100):
            r = await c.call_tool("agw_action_status", {"action_id": p["action_id"]})
            if not r.is_error:
                return r
            await asyncio.sleep(0.05)
        return r

    done = stack.run(token, status)
    assert done.is_error is False and _body(done)["status"] == "COMPLETED"
    assert len(gw.spies.email.calls) == 1


def test_delegation_through_mcp(stack: Stack) -> None:
    gw = stack.gw
    child_id, _ = new_agent(stack.migrator, gw.world.tenant_id, "mcp-child")
    d = delegate(gw, child_id, scopes=("tools:public_doc_search",), tools=("public_doc_search",))
    token = stack.token_for("mcp-child")

    async def calls(c: Client) -> list[Any]:
        return [
            await c.call_tool("public_doc_search", {"query": "evidence"}),
            await c.call_tool("create_ticket", {"title": "t", "body": "b"}),
        ]

    ok, denied = stack.run(token, calls, **{"AGW-Delegation": d["token"]})
    assert ok.is_error is False
    assert _body(denied)["status"] == "DENIED"
    assert _body(denied)["reasons"] == ["DELEGATION_SCOPE_MISSING"]
    h = header(gw, event_id(gw, _body(ok)["action_id"], "ACTION_REQUESTED"))
    assert h["delegation"]["id"] == uuid.UUID(d["delegation_id"]).bytes


def test_revoked_agent_key_stops_immediately(stack: Stack) -> None:
    gw = stack.gw
    token = stack.token_for("demo-agent")

    async def two(c: Client) -> list[Any]:
        first = await c.call_tool("create_ticket", {"title": "a", "body": "b"})
        revoke_key(stack.migrator, token[4:20])  # operator revokes the agent's MCP key
        try:
            second = await c.call_tool("create_ticket", {"title": "c", "body": "d"})
        except Exception as exc:  # the adapter cannot act for a revoked key
            second = exc
        return [first, second]

    first, second = stack.run(token, two)
    assert first.is_error is False
    assert isinstance(second, Exception) or second.is_error is True
    gw.drain()
    assert len(gw.spies.ticket.calls) == 1
