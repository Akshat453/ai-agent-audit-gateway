#!/usr/bin/env bash
# "ui" profile demo (Phase 9): replays the Phase 8 demo against the containerized gateway so
# the dashboard has real data: LLM agent, planner -> worker delegation via LangGraph AND via
# MCP (email approved by the human alice), then leaves work for the dashboard: one pending
# HIGH email approval, one pending CRITICAL IAM change (step-up), one DENIED delete.
set -euo pipefail
. /app/infra/docker/ui/env.sh
cd /app
key() { python -m agw_gateway.admin create-agent-key --tenant demo --agent "$1" --expires-days 1 "${@:2}"; }
export AGW_GATEWAY_URL=http://ui-gateway:8080
export AGW_AGENT_TOKEN; AGW_AGENT_TOKEN="$(key demo-agent)"
export AGW_PLANNER_TOKEN; AGW_PLANNER_TOKEN="$(key demo-planner)"
export AGW_WORKER_TOKEN; AGW_WORKER_TOKEN="$(key demo-worker)"
export AGW_WORKER_MCP_TOKEN; AGW_WORKER_MCP_TOKEN="$(key demo-worker --audience http://ui-mcp:8765/mcp)"
export AGW_WORKER_AGENT_ID; AGW_WORKER_AGENT_ID="$(python -m agw_gateway.admin agent-id --tenant demo --agent demo-worker)"
export AGW_MCP_URL=http://ui-mcp:8765/mcp
export AGW_APPROVER_TENANT=demo AGW_APPROVER_USER=alice AGW_APPROVER_PASSWORD="$AGW_UI_DEMO_PASSWORD"
IAM_TOKEN="$(key demo-iam-admin)"
OUT=/tmp/ui-demo; mkdir -p "$OUT"
python examples/single-agent/llm_agent.py
python examples/multi-agent/run.py --transport sdk --out "$OUT"
python examples/multi-agent/run.py --transport mcp --out "$OUT"
python - "$IAM_TOKEN" <<'PY'
import os, sys, uuid
from agw_sdk import Client
run = str(uuid.uuid4())
with Client(os.environ["AGW_GATEWAY_URL"], os.environ["AGW_AGENT_TOKEN"]) as c:
    for tool, args in (
        ("send_email", {"to": ["partner@partner.example"], "subject": "Q4 summary for the partner"}),
        ("delete_record", {"record_id": str(uuid.uuid4())}),
        ("public_doc_search", {"query": "retention"}),
    ):
        r = c.submit_action(run_id=run, tool=tool, args=args)
        print(f"  {tool:<18} {r.status}")
with Client(os.environ["AGW_GATEWAY_URL"], sys.argv[1]) as c:
    r = c.submit_action(run_id=str(uuid.uuid4()), tool="update_iam_role",
                        args={"principal": "svc-reporting", "role": "editor", "grant": True})
    print(f"  update_iam_role    {r.status} (CRITICAL: four-eyes + step-up in the dashboard)")
PY
echo "UI DEMO DATA READY: open http://localhost:${AGW_DASHBOARD_HOST_PORT:-3000} (demo / alice | bob | audrey | adam)"
