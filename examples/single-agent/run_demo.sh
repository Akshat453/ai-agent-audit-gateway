#!/usr/bin/env bash
# make demo: seed demo tenant/agents, issue a fresh key, start the gateway, run the scripted agent.
set -euo pipefail
cd "$(dirname "$0")/../.."
set -a; . ./.env; set +a
PORT="${AGW_DEMO_PORT:-8080}"
export AGW_GATEWAY_URL="http://127.0.0.1:${PORT}"

uv run python -m agw_gateway.admin seed-demo
# The token is printed once by the admin CLI and kept only in this process's environment.
AGW_AGENT_TOKEN="$(uv run python -m agw_gateway.admin create-agent-key --tenant demo --agent demo-agent --expires-days 1)"
export AGW_AGENT_TOKEN

LOG="$(mktemp -t agw-demo-gateway.XXXXXX)"
uv run uvicorn agw_gateway.api.app:create_app --factory --host 127.0.0.1 --port "$PORT" --no-access-log >"$LOG" 2>&1 &
GW_PID=$!
trap 'kill $GW_PID 2>/dev/null || true; wait $GW_PID 2>/dev/null || true' EXIT

for _ in $(seq 1 50); do
  if curl -fsS "$AGW_GATEWAY_URL/v1/ready" >/dev/null 2>&1; then break; fi
  sleep 0.2
done
curl -fsS "$AGW_GATEWAY_URL/v1/ready" >/dev/null || { echo "gateway not ready; log: $LOG"; cat "$LOG"; exit 1; }

uv run python examples/single-agent/agent.py "$@"

# Phase 2: export the tenant's chain and verify it with the standalone verifier against the
# chain head read from the gateway (in later phases the trusted head comes from an anchor).
EXPORT="$(mktemp -t agw-demo-export.XXXXXX)"
read -r HEAD_SEQ HEAD_HASH < <(uv run python -m agw_gateway.admin chain-head --tenant demo)
uv run python -m agw_gateway.admin export-chain --tenant demo --out "$EXPORT"
echo "verifying chain (seq 0..$HEAD_SEQ) with agw-verify:"
uv run agw-verify chain --export "$EXPORT" --trusted-head "$HEAD_HASH" --trusted-seq "$HEAD_SEQ" \
  | grep -E '"(result|events_checked|first_bad_seq|reason)"'
