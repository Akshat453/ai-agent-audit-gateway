"""The Phase 8 multi-agent scenario (ADR-0030): a PLANNER delegates "create ticket + email
summary" to a WORKER; the email needs a human approval.

1. Planner (LangGraph): searches the docs through the gateway, then calls its local
   ``delegate_task`` tool, which asks the gateway for a delegation token for the worker:
   only {create_ticket, <email tool>}, max risk HIGH, 3 uses, 10 minutes, with a purpose.
   The gateway records DELEGATION_CREATED (A2A). The token is handed to the worker out of
   band (the A2A message itself is not evidence; the delegation is).
2. Worker (LangGraph): with the token, creates the ticket (allowed under the delegation) and
   emails the summary to an external address (HIGH: approval required). Its tools are either
   the SDK-backed ``agw_langgraph`` tools or MCP tools served by ``agw_mcp``.
3. A human approver approves exactly that email; the worker's call completes.
Every child event carries the delegation id and is hash-linked to DELEGATION_CREATED.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any

from langchain_core.tools import StructuredTool

from agentlib.graphs import agent_graph, mcp_tools, new_run, run_graph
from agentlib.llm import LLM, MockLLM, make_llm
from agw_langgraph import GatewayToolkit
from agw_sdk import Client, Delegation


@dataclass
class Outcome:
    planner_run: str
    worker_run: str
    delegation: Delegation | None = None
    worker_calls: list[dict[str, Any]] = field(default_factory=list)
    planner_calls: list[dict[str, Any]] = field(default_factory=list)
    transcript: list[str] = field(default_factory=list)


def run_scenario(
    *,
    planner: Client,
    worker: Client | None,
    worker_agent_id: str,
    email_tool: str,
    email_to: str,
    transport: str = "sdk",
    mcp_url: str | None = None,
    worker_mcp_token: str | None = None,
    llm_factory: Callable[[list[tuple[str, dict[str, Any]]]], LLM] | None = None,
    approval_wait: float = 120.0,
    log: Callable[[str], None] = print,
) -> Outcome:
    make = llm_factory or (lambda plan: make_llm(plan, gullible=False))
    out = Outcome(planner_run=new_run(), worker_run=new_run())
    tools_for_worker = ["create_ticket", email_tool]

    # ------------------------------------------------------------------ planner
    ptk = GatewayToolkit(planner, out.planner_run, approval_wait=approval_wait)

    def delegate_task(child_agent_id: str, tools: list[str], purpose: str) -> str:
        scopes = [f"tools:{t}" for t in tools]
        d = planner.delegate(
            child_agent_id=child_agent_id,
            scopes=scopes,
            tools=tools,
            max_risk_level="HIGH",
            expires_in=timedelta(minutes=10),
            max_uses=3,
            purpose=purpose,
            run_id=out.planner_run,
        )
        out.delegation = d  # handed to the worker out of band (A2A)
        log(
            f"  planner -> DELEGATION_CREATED {d.delegation_id} depth={d.depth} "
            f"tools={list(d.tools)} max_risk={d.max_risk_level} uses={d.max_uses}"
        )
        return json.dumps({"delegation_id": d.delegation_id, "token_hash": d.token_hash})

    delegate_tool = StructuredTool.from_function(
        func=delegate_task,
        name="delegate_task",
        description="Delegate a sub-task to another agent with a narrowed, expiring permission.",
    )
    planner_tools = [*ptk.tools(only=["public_doc_search"]), delegate_tool]
    planner_plan = [
        ("public_doc_search", {"query": "ticket", "limit": 3}),
        (
            "delegate_task",
            {
                "child_agent_id": worker_agent_id,
                "tools": tools_for_worker,
                "purpose": "create ticket + email summary",
            },
        ),
    ]
    task = "Open a follow-up ticket for the customer escalation and email them a summary."
    run_graph(agent_graph(make(planner_plan), planner_tools, task), task)
    out.planner_calls = ptk.calls
    if out.delegation is None:
        raise RuntimeError("planner did not delegate")
    titles = "; ".join(str(c.get("tool")) for c in ptk.calls)  # what the planner did (no content)
    log(f"  planner run {out.planner_run}: {titles}, delegate_task")

    # ------------------------------------------------------------------ worker
    worker_plan = [
        (
            "create_ticket",
            {
                "title": "Customer escalation follow-up",
                "body": "Follow-up per ticket guidelines (delegated by the planner).",
                "priority": "high",
            },
        ),
        (
            email_tool,
            {
                "to": [email_to],
                "subject": "Your escalation: ticket {ticket_id}",
                "body": "We opened ticket {ticket_id} and will follow up within one day.",
            },
        ),
    ]
    if transport == "mcp":
        assert mcp_url and worker_mcp_token
        worker_tools = [
            t
            for t in mcp_tools(
                mcp_url,
                worker_mcp_token,
                headers={"AGW-Delegation": out.delegation.token, "AGW-Run-Id": out.worker_run},
            )
            if t.name in (*tools_for_worker, "agw_action_status")
        ]
        wtk = None
    else:
        assert worker is not None
        wtk = GatewayToolkit(
            worker,
            out.worker_run,
            delegation_token=out.delegation.token,
            approval_wait=approval_wait,
        )
        worker_tools = wtk.tools(only=tools_for_worker)
    llm = make(worker_plan)
    if isinstance(llm, MockLLM):
        llm.gullible = False
    msgs = run_graph(agent_graph(llm, worker_tools, task), task)
    out.transcript = [
        f"{type(m).__name__}: {str(m.content)[:160]}" for m in msgs if str(m.content).strip()
    ]
    if wtk is not None:
        out.worker_calls = wtk.calls
    log(f"  worker  run {out.worker_run} via {transport}: {len(msgs)} messages")
    return out
