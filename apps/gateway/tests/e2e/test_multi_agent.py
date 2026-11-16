"""Phase 8 ACCEPTANCE (ADR-0030): two agents delegate a permitted task through LangGraph (SDK
tools) or MCP, an approval-required step is approved by a human, and EVERY resulting event
verifies offline against roots anchored on a real chain (Anvil)."""

from __future__ import annotations

import sys
import threading
import time
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import Engine, select

from agw_gateway.admin import create_integration_client, create_key, ensure_agent
from agw_gateway.api.app import create_app
from agw_gateway.db import tables as t
from agw_mcp import AdapterConfig, build_app
from agw_sdk import Client

from ..anchorkit import Chain, bundle_for, register, sealer, trust_file, verify
from ..approvalkit import decide, make_humans
from ..privacykit import header, verify_export
from ..servekit import free_port, pump, serve

REPO = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(REPO / "examples"))

from agentlib.llm import MockLLM  # noqa: E402
from agentlib.multi_agent import run_scenario  # noqa: E402

pytestmark = pytest.mark.e2e
EMAIL_TO = "customer@partner.example"  # external -> HIGH -> approval


@contextmanager
def approver(gw: Any, migrator: Engine, tool: str) -> Iterator[list[str]]:
    """A human (alice) who approves pending approvals for ``tool`` after looking at them."""
    humans = make_humans(migrator, gw.client, gw.world.tenant_id)
    approved: list[str] = []
    stop = threading.Event()

    def loop() -> None:
        while not stop.is_set():
            r = gw.client.get("/v1/approvals?state=PENDING", headers=humans.headers("alice"))
            for ap in r.json().get("approvals", []):
                if ap["tool"]["id"] == tool and ap["approval_id"] not in approved:
                    assert decide(gw, humans, ap["approval_id"]).status_code == 200
                    approved.append(ap["approval_id"])
            time.sleep(0.05)

    th = threading.Thread(target=loop, daemon=True)
    th.start()
    try:
        yield approved
    finally:
        stop.set()
        th.join()


def _events(gw: Any, runs: list[str]) -> list[Any]:
    with gw.engine.connect() as conn:
        return list(
            conn.execute(
                select(t.evidence_events)
                .where(
                    t.evidence_events.c.tenant_id == gw.world.tenant_id,
                    t.evidence_events.c.run_id.in_([uuid.UUID(r) for r in runs]),
                )
                .order_by(t.evidence_events.c.seq)
            ).all()
        )


@pytest.mark.parametrize("transport", ["sdk", "mcp"])
def test_two_agents_delegate_approve_and_verify_against_anchors(
    gw: Any, migrator_engine: Engine, chain: Chain, tmp_path: Path, transport: str
) -> None:
    tenant = gw.world.tenant_id
    scopes = ("tools:public_doc_search", "tools:create_ticket", "tools:send_email")
    ensure_agent(migrator_engine, tenant, "planner", scopes)
    worker_id = ensure_agent(migrator_engine, tenant, "worker", (*scopes, "tools:delete_record"))
    planner = Client("http://testserver", create_key(migrator_engine, tenant, "planner"),
                     http_client=gw.client)  # fmt: skip
    rec = register(chain, migrator_engine, gw)
    factory = lambda plan: MockLLM(plan, gullible=False)  # noqa: E731

    with approver(gw, migrator_engine, "send_email") as approved, pump(gw):
        if transport == "sdk":
            worker = Client("http://testserver", create_key(migrator_engine, tenant, "worker"),
                            http_client=gw.client)  # fmt: skip
            out = run_scenario(planner=planner, worker=worker, worker_agent_id=worker_id,
                               email_tool="send_email", email_to=EMAIL_TO,
                               llm_factory=factory, log=lambda _: None)  # fmt: skip
        else:
            port = free_port()
            mcp_url = f"http://127.0.0.1:{port}/mcp"
            client_token = create_integration_client(migrator_engine, tenant, "mcp", mcp_url)
            with serve(create_app(gw.state, sync_registry=False)) as gateway_url:
                cfg = AdapterConfig(gateway_url, client_token, mcp_url)
                with serve(build_app(cfg), port=port):
                    out = run_scenario(
                        planner=planner, worker=None, worker_agent_id=worker_id,
                        email_tool="send_email", email_to=EMAIL_TO, transport="mcp",
                        mcp_url=mcp_url,
                        worker_mcp_token=create_key(migrator_engine, tenant, "worker",
                                                    audience=mcp_url),
                        llm_factory=factory, log=lambda _: None,
                    )  # fmt: skip
    gw.drain()
    assert len(approved) == 1 and len(gw.spies.email.calls) == 1
    assert len(gw.spies.ticket.calls) == 1 and gw.spies.delete.calls == []
    assert out.delegation is not None

    # ---- parent/child links in the evidence
    events = _events(gw, [out.planner_run, out.worker_run])
    types = [e.event_type for e in events]
    assert "DELEGATION_CREATED" in types and "APPROVAL_GRANTED" in types
    assert types.count("ACTION_COMPLETED") == 3  # planner search, ticket, email
    created = next(e for e in events if e.event_type == "DELEGATION_CREATED")
    assert created.run_id == uuid.UUID(out.planner_run)
    child_requests = [
        e for e in events
        if e.event_type == "ACTION_REQUESTED" and e.run_id == uuid.UUID(out.worker_run)
    ]  # fmt: skip
    assert len(child_requests) == 2
    for e in child_requests:
        h = header(gw, e.event_id)
        assert h["delegation"]["ev"] == created.event_id.bytes
        assert h["refs"]["parent"] == bytes(created.event_hash)
        assert h["delegation"]["from"] == h["delegation"]["root"]  # depth 1: planner is root
    # the planner's view of the delegation shows the worker's whole lifecycle
    tl = planner.delegation_timeline(out.delegation.delegation_id)
    tl_types = [e["type"] for e in tl["events"]]
    assert tl_types[0] == "DELEGATION_CREATED"
    assert "APPROVAL_REQUIRED" in tl_types and tl_types.count("ACTION_COMPLETED") == 2

    # ---- seal, anchor on-chain, then verify EVERY resulting event offline
    sealer(gw).drain()
    a = rec.anchorer()
    a.tick()
    a.tick()
    assert {r.status for r in rec.anchors()} == {"FINALIZED"}
    trust = trust_file(tmp_path, rec.trust())
    for e in events:
        rc, report = verify(
            tmp_path, "event", bundle_for(gw, e.event_id),
            "--chain-rpc", rec.chain.rpc, "--trust-config", trust,
        )  # fmt: skip
        assert (rc, report["result"]) == (0, "VERIFIED"), (e.event_type, report)
    assert verify_export(gw).result == "VERIFIED"
