"""Phase 8: a tool-calling LLM agent on the gateway, framework-free (only ``agw_sdk``).

    AGW_LLM_PROVIDER=mock       (default) deterministic, no keys: tests and demo
    AGW_LLM_PROVIDER=anthropic  Claude via the ``anthropic`` package (credentials from env)

The model proposes tool calls; the GATEWAY decides. Denials and pending approvals come back
to the model as tool errors with the gateway's reason codes, never as fake successes. Digests
of content the agent read (search hits) are sent with later calls as context provenance.

Env: AGW_GATEWAY_URL, AGW_AGENT_TOKEN.
"""

from __future__ import annotations

import json
import os
import sys
import uuid
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from agentlib.llm import LLM, Observation, make_llm

from agw_langgraph import Provenance
from agw_sdk import Client, ToolCallError

TASK = "Find our guidance on evidence retention, then open a low-priority ticket summarizing it."
PLAN: list[tuple[str, dict[str, Any]]] = [
    ("public_doc_search", {"query": "retention policy", "limit": 3}),
    (
        "create_ticket",
        {"title": "Evidence retention review", "body": "Sources: {titles}", "priority": "low"},
    ),
]


def run_agent(client: Client, llm: LLM, task: str = TASK, max_steps: int = 12) -> dict[str, Any]:
    run_id = str(uuid.uuid4())
    specs = [
        {
            "name": t["tool_id"],
            "description": f"{t['operation_type']} tool executed by the audit gateway",
            "input_schema": {k: v for k, v in t["args_schema"].items() if k != "title"},
        }
        for t in client.list_tools()
    ]
    provenance = Provenance()
    history: list[Observation] = []
    log: list[dict[str, Any]] = []
    for _ in range(max_steps):
        turn = llm.next_turn(task, specs, history)
        if not turn.calls:
            return {"run_id": run_id, "final": turn.text, "calls": log}
        for call in turn.calls:
            try:
                out = client.call(
                    call.name,
                    call.args,
                    run_id=run_id,
                    sources=provenance.snapshot(),
                    approval_wait=0,
                    timeout=30,
                )
                provenance.observe(call.name, call.args, out.result)
                content = json.dumps({"status": out.status, "result": out.result})
                log.append({"tool": call.name, "status": out.status, "action_id": out.action_id})
                history.append(Observation(call, content, False))
            except ToolCallError as exc:
                content = json.dumps({"status": exc.status, "action_id": exc.action_id,
                                      "reasons": exc.info.get("reasons", [])})  # fmt: skip
                log.append({"tool": call.name, "status": exc.status, "action_id": exc.action_id})
                history.append(Observation(call, content, True))
    return {"run_id": run_id, "final": "step limit", "calls": log}


def main() -> int:
    token = os.environ.get("AGW_AGENT_TOKEN")
    if not token:
        print("AGW_AGENT_TOKEN (missing)", file=sys.stderr)
        return 2
    url = os.environ.get("AGW_GATEWAY_URL", "http://127.0.0.1:8080")
    with Client(url, token) as client:
        result = run_agent(client, make_llm(PLAN, gullible=False))
    provider = os.environ.get("AGW_LLM_PROVIDER", "mock")
    print(f"llm agent ({provider}) run {result['run_id']}:")
    for c in result["calls"]:
        print(f"  {c['tool']:<20} {c['status']:<17} action={c['action_id']}")
    print(f"  final: {result['final']}")
    ok = [c["status"] for c in result["calls"]] == ["COMPLETED", "COMPLETED"]
    return 0 if ok or provider != "mock" else 1


if __name__ == "__main__":
    raise SystemExit(main())
