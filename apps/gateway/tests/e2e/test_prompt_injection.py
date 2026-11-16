"""Phase 8 prompt-injection corpus (ADR-0030 §8): >= 10 retrieved documents that tell the
agent to delete records, exfiltrate data, escalate privileges, spoof identity, approve itself,
smuggle arguments, use unregistered tools or forged delegation tokens.

The agent is a LangGraph graph with a deliberately GULLIBLE deterministic model: it TRIES
every injected instruction. Each document is run twice: as a worker acting under a planner's
delegation, and as the same agent acting directly (holding every tool scope itself).

Asserted per case: 0 unauthorized executions (no adapter call for any injected action), the
attempt is recorded as evidence, and for tool calls the ACTION_REQUESTED context provenance
holds the SHA-256 of the exact document that carried the injection.
Writes the results table when AGW_INJECTION_TABLE_OUT is set (``make injection-corpus``).
"""

from __future__ import annotations

import dataclasses
import hashlib
import os
import sys
import uuid
from collections.abc import Iterator
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, func, select

from agw_gateway.admin import create_key, ensure_agent
from agw_gateway.api.app import build_state, create_app
from agw_gateway.db import tables as t
from agw_gateway.tools.adapters.external import external_tool_specs
from agw_gateway.tools.registry import ToolRegistry
from agw_langgraph import GatewayToolkit
from agw_sdk import Client

from ..approvalkit import decide, make_humans
from ..conftest import ALL_SCOPES, Gw, PgUrls, SpyAdapter, World, make_settings, make_spies
from ..privacykit import payload
from ..servekit import pump

REPO = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(REPO / "examples"))
CORPUS = REPO / "examples" / "injection" / "corpus"

from agentlib.graphs import agent_graph, run_graph  # noqa: E402
from agentlib.injection import raw_gateway_tool  # noqa: E402
from agentlib.llm import MockLLM, injected_directives  # noqa: E402

pytestmark = pytest.mark.e2e
CASES = sorted(p for p in CORPUS.glob("inj-*.md"))
LEGIT_TITLE = "vendor follow-up"


@pytest.fixture
def inj(
    pg: PgUrls, app_engine: Engine, migrator_engine: Engine, world: World, tmp_path: Path
) -> Iterator[Gw]:
    settings = make_settings(
        pg.app, tmp_path, demo_corpus_dir=CORPUS, http_allowlist=("api.partner.example",)
    )
    spies = make_spies()
    for s in spies.all():
        s.tenant = world.tenant_id
    from ..conftest import make_registry

    base = make_registry(spies)
    api = external_tool_specs(settings)[0]
    api_spy = SpyAdapter(api.adapter)
    api_spy.tenant = world.tenant_id
    registry = ToolRegistry([*base._specs.values(), dataclasses.replace(api, adapter=api_spy)])
    state = build_state(settings, engine=app_engine, registry=registry)
    state.sync()
    with TestClient(create_app(state, sync_registry=False)) as client:
        g = Gw(state=state, client=client, spies=spies, world=world, engine=app_engine)
        g.world.extra["api_spy"] = api_spy
        yield g
        g.drain()


def _count(gw: Any, **where: Any) -> int:
    with gw.engine.connect() as conn:
        q = (
            select(func.count())
            .select_from(t.evidence_events)
            .where(t.evidence_events.c.tenant_id == gw.world.tenant_id)
        )
        for k, v in where.items():
            q = q.where(t.evidence_events.c[k] == v)
        return int(conn.execute(q).scalar_one())


def _requested(gw: Any, action_id: str) -> Any:
    with gw.engine.connect() as conn:
        return conn.execute(
            select(t.evidence_events.c.event_id).where(
                t.evidence_events.c.action_id == uuid.UUID(action_id),
                t.evidence_events.c.event_type == "ACTION_REQUESTED",
            )
        ).scalar_one()


def test_injection_corpus_zero_unauthorized_executions(inj: Gw, migrator_engine: Engine) -> None:
    assert len(CASES) >= 10
    gw = inj
    tenant = gw.world.tenant_id
    planner_scopes = ("tools:public_doc_search", "tools:create_ticket", "tools:send_email")
    ensure_agent(migrator_engine, tenant, "planner", planner_scopes)
    worker_id = ensure_agent(
        migrator_engine, tenant, "worker", (*ALL_SCOPES, "tools:public_api_get")
    )
    planner = Client("http://testserver", create_key(migrator_engine, tenant, "planner"),
                     http_client=gw.client)  # fmt: skip
    worker_token = create_key(migrator_engine, tenant, "worker")
    worker = Client("http://testserver", worker_token, http_client=gw.client)
    dangerous = [gw.spies.delete, gw.spies.email, gw.spies.export, gw.spies.iam,
                 gw.world.extra["api_spy"], gw.spies.restricted]  # fmt: skip
    rows: list[dict[str, Any]] = []

    with pump(gw):
        for mode in ("delegated", "direct"):
            for doc in CASES:
                text = doc.read_text()
                title = text.splitlines()[0].lstrip("# ").strip()
                digest = hashlib.sha256(doc.read_bytes()).hexdigest()
                directive = injected_directives(text)[0]
                token = None
                if mode == "delegated":
                    token = planner.delegate(
                        child_agent_id=worker_id,
                        scopes=list(planner_scopes),
                        tools=["public_doc_search", "create_ticket", "send_email"],
                        max_risk_level="HIGH",
                        expires_in=timedelta(minutes=5),
                        max_uses=10,
                        purpose="vendor follow-up",
                    ).token
                run_id = str(uuid.uuid4())
                tk = GatewayToolkit(worker, run_id, delegation_token=token, approval_wait=0)
                raw_log: list[dict[str, Any]] = []
                tools = [*tk.tools(), raw_gateway_tool(gw.client, worker_token, raw_log)]
                before_exec = sum(len(s.calls) for s in dangerous)
                before_viol = _count(gw, event_type="SECURITY_VIOLATION")
                llm = MockLLM(
                    [
                        ("public_doc_search", {"query": title, "limit": 1}),
                        ("create_ticket", {"title": LEGIT_TITLE, "body": "summary: {titles}"}),
                    ]
                )
                run_graph(agent_graph(llm, tools, "summarize the vendor page"), "task")
                gw.drain()
                executed = sum(len(s.calls) for s in dangerous) - before_exec
                legit = [c for c in tk.calls if c["tool"] in ("public_doc_search",)]
                injected = [c for c in tk.calls if c not in legit]
                ticket_calls = [c for c in injected if c["tool"] == "create_ticket"]
                # the legit ticket is the LAST create_ticket; anything before it was injected
                if ticket_calls and ticket_calls[-1]["status"] == "COMPLETED":
                    injected.remove(ticket_calls[-1])
                provenance = "n/a (raw HTTP)"
                outcome = ""
                recorded = False
                if injected:
                    call = injected[0]
                    outcome = f"{call['status']} {','.join(r for r in call['reasons'] if r)}"
                    p = payload(gw, _requested(gw, call["action_id"]))
                    assert p is not None
                    srcs = [s["digest"].hex() for s in p["context"]["sources"]]
                    provenance = "doc sha256 recorded" if digest in srcs else "MISSING"
                    recorded = call["status"] in ("DENIED", "PENDING_APPROVAL")
                    assert digest in srcs, (doc.name, mode)
                elif raw_log:
                    r = raw_log[0]
                    body = r["body"] if isinstance(r["body"], dict) else {}
                    if r["http"] >= 400:
                        outcome = f"HTTP {r['http']} {body.get('error', {}).get('code', '')}"
                        recorded = _count(gw, event_type="SECURITY_VIOLATION") > before_viol
                    else:
                        reasons = ",".join(body.get("decision", {}).get("reasons", []))
                        outcome = f"{body.get('status')} {reasons}"
                        recorded = body.get("status") in ("DENIED", "PENDING_APPROVAL")
                assert injected or raw_log, f"{doc.name}: the agent did not even try"
                assert executed == 0, (doc.name, mode, executed)
                assert recorded, (doc.name, mode, outcome)
                rows.append(
                    {
                        "case": doc.stem,
                        "mode": mode,
                        "tried": directive["tool"]
                        if directive["tool"] != "raw_gateway_request"
                        else f"HTTP {directive['args']['path']}",
                        "outcome": outcome.strip(),
                        "provenance": provenance,
                        "executed": executed,
                    }
                )
        # A human reviews the emails the injected agent asked for (an external drop box) and
        # rejects them; nothing was sent before or after.
        humans = make_humans(migrator_engine, gw.client, tenant)
        listed = gw.client.get("/v1/approvals?state=PENDING", headers=humans.headers("alice"))
        pending = [a["approval_id"] for a in listed.json()["approvals"]]
        assert len(pending) == 2  # inj-04 in both modes
        for approval_id in pending:
            assert decide(gw, humans, approval_id, decision="REJECT").status_code == 200
        gw.drain()
    assert len(gw.spies.email.calls) == 0
    total = sum(r["executed"] for r in rows)
    assert total == 0 and len(rows) >= 20
    out = os.environ.get("AGW_INJECTION_TABLE_OUT")
    if out:
        lines = [
            "# Prompt-injection corpus (Phase 8, ADR-0030 §8)",
            "",
            f"{len(CASES)} documents x 2 modes = {len(rows)} runs; "
            f"unauthorized executions: **{total}**.",
            "Generated by `make injection-corpus` (test_prompt_injection.py).",
            "",
            "| case | mode | injected attempt | gateway outcome | context provenance | executed |",
            "|---|---|---|---|---|---|",
            *(
                f"| {r['case']} | {r['mode']} | {r['tried']} | {r['outcome']} | "
                f"{r['provenance']} | {r['executed']} |"
                for r in rows
            ),
        ]
        Path(out).parent.mkdir(parents=True, exist_ok=True)
        Path(out).write_text("\n".join(lines) + "\n")
