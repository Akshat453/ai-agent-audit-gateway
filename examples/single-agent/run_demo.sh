#!/usr/bin/env bash
# make demo: seed demo tenant/agents, issue a fresh key, start the gateway AND the worker
# (executor + epoch sealer), run the scripted agent, fetch an evidence bundle, STOP the stack,
# then verify everything offline with the standalone verifier.
set -euo pipefail
cd "$(dirname "$0")/../.."
set -a; . ./.env; set +a
PORT="${AGW_DEMO_PORT:-8080}"
export AGW_GATEWAY_URL="http://127.0.0.1:${PORT}"
export AGW_EXECUTOR_MODE=worker          # the worker process dispatches and seals
export AGW_EPOCH_MAX_AGE_SECONDS="${AGW_EPOCH_MAX_AGE_SECONDS:-1}"   # seal quickly for the demo
OUT="$(mktemp -d -t agw-demo.XXXXXX)"

uv run python -m agw_gateway.admin seed-demo
# The token is printed once by the admin CLI and kept only in this process's environment.
AGW_AGENT_TOKEN="$(uv run python -m agw_gateway.admin create-agent-key --tenant demo --agent demo-agent --expires-days 1)"
export AGW_AGENT_TOKEN

uv run uvicorn agw_gateway.api.app:create_app --factory --host 127.0.0.1 --port "$PORT" --no-access-log >"$OUT/gateway.log" 2>&1 &
GW_PID=$!
uv run python -m agw_worker >"$OUT/worker.log" 2>&1 &
WK_PID=$!
stop_stack() { kill "$GW_PID" "$WK_PID" 2>/dev/null || true; wait "$GW_PID" "$WK_PID" 2>/dev/null || true; }
trap stop_stack EXIT

for _ in $(seq 1 50); do
  if curl -fsS "$AGW_GATEWAY_URL/v1/ready" >/dev/null 2>&1; then break; fi
  sleep 0.2
done
curl -fsS "$AGW_GATEWAY_URL/v1/ready" >/dev/null || { echo "gateway not ready; log: $OUT/gateway.log"; cat "$OUT/gateway.log"; exit 1; }

uv run python examples/single-agent/agent.py "$@"
uv run python examples/single-agent/fetch_bundle.py "$OUT"
uv run python -m agw_gateway.admin export-chain --tenant demo --out "$OUT/events.jsonl"
uv run python -m agw_gateway.admin export-epochs --tenant demo --out "$OUT/epochs.jsonl"

stop_stack
trap - EXIT
echo "--- gateway and worker STOPPED; verifying offline with agw-verify ---"
ROOT="$(cat "$OUT/trusted_root.txt")"
rc=0; uv run agw-verify event --bundle "$OUT/bundle.json" --trusted-root "$ROOT" || rc=$?
echo "agw-verify event (with trusted root) exit=$rc"; [ "$rc" -eq 0 ] || exit 1
rc=0; uv run agw-verify event --bundle "$OUT/bundle.json" >/dev/null || rc=$?
echo "agw-verify event (no trust root)     exit=$rc (4 = UNANCHORED, locally sealed only)"; [ "$rc" -eq 4 ] || exit 1
rc=0; uv run agw-verify epochs --export "$OUT/epochs.jsonl" --events "$OUT/events.jsonl" --trusted-root "$ROOT" || rc=$?
echo "agw-verify epochs --events            exit=$rc"; [ "$rc" -eq 0 ] || exit 1
echo "artifacts: $OUT"
