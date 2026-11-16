"""Phase 8 multi-agent demo (ADR-0030): planner delegates "create ticket + email summary" to a
worker through LangGraph (``--transport sdk``) or MCP (``--transport mcp``); a human approves
the email. Prints the delegation timeline as the PLANNER sees it (parent/child links).

Env: AGW_GATEWAY_URL, AGW_PLANNER_TOKEN, AGW_WORKER_TOKEN (sdk) or AGW_WORKER_MCP_TOKEN +
AGW_MCP_URL (mcp), AGW_WORKER_AGENT_ID, AGW_APPROVER_TENANT/USER/PASSWORD (the human),
AGW_EMAIL_TOOL (default send_email_smtp), AGW_LLM_PROVIDER (mock|anthropic).
Writes ``<out>/multi-agent.json`` (run ids, delegation id) for the verification step.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import threading
import time
from pathlib import Path

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from agentlib.multi_agent import run_scenario

from agw_sdk import Client


def approver(url: str, tool: str, stop: threading.Event, approved: list[str]) -> None:
    """The human: logs in, looks at each pending approval for ``tool``, approves it once."""
    http = httpx.Client(base_url=url, timeout=15.0)
    r = http.post("/v1/auth/login", json={
        "tenant": os.environ["AGW_APPROVER_TENANT"],
        "username": os.environ["AGW_APPROVER_USER"],
        "password": os.environ["AGW_APPROVER_PASSWORD"],
    })  # fmt: skip
    r.raise_for_status()
    http.headers["Authorization"] = f"Session {r.json()['session_token']}"
    while not stop.is_set():
        for ap in http.get("/v1/approvals", params={"state": "PENDING"}).json()["approvals"]:
            if ap["tool"]["id"] != tool or ap["approval_id"] in approved:
                continue
            view = http.get(f"/v1/approvals/{ap['approval_id']}").json()
            print(f"  human sees: tool={view['action']['tool']['id']} "
                  f"risk={view['action']['risk']['level']} "
                  f"agent={view['action']['agent']['name']} "
                  f"delegation_depth={view['action']['delegation_depth']}")  # fmt: skip
            d = http.post(f"/v1/approvals/{ap['approval_id']}/decision", json={
                "decision": "APPROVE", "reason": "recipient is the escalating customer",
                "action_digest": view["action_digest"], "nonce": view["nonce"],
            })  # fmt: skip
            d.raise_for_status()
            approved.append(ap["approval_id"])
            print(f"  human APPROVED {ap['approval_id']}")
        time.sleep(0.2)


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--transport", choices=["sdk", "mcp"], default="sdk")
    p.add_argument("--out", default=None)
    args = p.parse_args()
    url = os.environ.get("AGW_GATEWAY_URL", "http://127.0.0.1:8080")
    tool = os.environ.get("AGW_EMAIL_TOOL", "send_email_smtp")
    stop, approved = threading.Event(), []
    th = threading.Thread(target=approver, args=(url, tool, stop, approved), daemon=True)
    th.start()
    planner = Client(url, os.environ["AGW_PLANNER_TOKEN"])
    worker = Client(url, os.environ["AGW_WORKER_TOKEN"]) if args.transport == "sdk" else None
    try:
        out = run_scenario(
            planner=planner,
            worker=worker,
            worker_agent_id=os.environ["AGW_WORKER_AGENT_ID"],
            email_tool=tool,
            email_to=os.environ.get("AGW_EMAIL_TO", "customer@partner.example"),
            transport=args.transport,
            mcp_url=os.environ.get("AGW_MCP_URL"),
            worker_mcp_token=os.environ.get("AGW_WORKER_MCP_TOKEN"),
        )
    finally:
        stop.set()
        th.join(timeout=5)
    assert out.delegation is not None
    print(f"  delegation timeline (planner's view of {out.delegation.delegation_id}):")
    tl = planner.delegation_timeline(out.delegation.delegation_id)
    for e in tl["events"]:
        link = ""
        if "delegation" in e:
            link = f"delegation.ev={e['delegation'].get('ev', '-')[:12]}…"
        if "refs" in e:
            link += f" refs.parent={e['refs']['parent'][:12]}…"
        what = e.get("decision") or (e.get("outcome") or {}).get("status") or ""
        print(f"    {e['seq']:<5} {e['type']:<20} {what:<17} run={e['run_id'][:8]} {link}")
    types = [e["type"] for e in tl["events"]]
    ok = (
        len(approved) == 1
        and types[0] == "DELEGATION_CREATED"
        and types.count("ACTION_COMPLETED") == 2
        and "APPROVAL_GRANTED" in types
    )
    if args.out:
        Path(args.out, f"multi-agent-{args.transport}.json").write_text(json.dumps({
            "planner_run": out.planner_run, "worker_run": out.worker_run,
            "delegation_id": out.delegation.delegation_id,
            "created_event_id": out.delegation.created_event_id,
        }))  # fmt: skip
    print(f"MULTI-AGENT ({args.transport}) {'OK' if ok else 'FAILED'}")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
