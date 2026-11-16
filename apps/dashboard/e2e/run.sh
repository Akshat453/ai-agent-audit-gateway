#!/usr/bin/env bash
# Dashboard e2e (Phase 9): real gateway (uvicorn, in-process executor) on the compose Postgres,
# a fresh seeded tenant, the PRODUCTION build of the dashboard, then Playwright.
#   make up && make migrate && make dashboard-e2e
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT="$(cd ../.. && pwd)"
set -a; . "$ROOT/.env"; set +a
GW_PORT="${AGW_E2E_GATEWAY_PORT:-18080}"
UI_PORT="${AGW_E2E_DASHBOARD_PORT:-13000}"
LOGS="$(mktemp -d -t agw-dashboard-e2e.XXXXXX)"
export AGW_EXECUTOR_MODE=inprocess AGW_PRE_ANCHOR_RULES= AGW_APPROVAL_SWEEP_SECONDS=1
export AGW_APPROVAL_SIGNING_KEY_FILE="$ROOT/secrets/approval-signing.key"
export AGW_DELEGATION_SIGNING_KEY_FILE="$ROOT/secrets/delegation-signing.key"
( cd "$ROOT" && [ -f "$AGW_APPROVAL_SIGNING_KEY_FILE" ] || uv run python -m agw_gateway.admin gen-signing-key --out "$AGW_APPROVAL_SIGNING_KEY_FILE" )
( cd "$ROOT" && uv run python -m agw_gateway.admin gen-delegation-key --out "$AGW_DELEGATION_SIGNING_KEY_FILE" --if-missing )
( cd "$ROOT" && uv run python -m agw_gateway.admin gen-kek --if-missing )
( cd "$ROOT" && uv run uvicorn agw_gateway.api.app:create_app --factory --host 127.0.0.1 --port "$GW_PORT" --no-access-log >"$LOGS/gateway.log" 2>&1 ) &
GW_PID=$!
# Stop the wrappers AND whatever listens on the two test ports (the python/node children of
# `uv run` / `npm run`): a leftover gateway with an in-process executor would otherwise keep
# claiming jobs from the shared dev database.
cleanup() {
  kill "$GW_PID" ${UI_PID:-} 2>/dev/null || true
  for port in "$GW_PORT" "$UI_PORT"; do
    lsof -ti "tcp:$port" -sTCP:LISTEN 2>/dev/null | xargs kill 2>/dev/null || true
  done
  wait 2>/dev/null || true
}
trap cleanup EXIT
( cd "$ROOT" && uv run python apps/dashboard/e2e/seed.py --gateway "http://127.0.0.1:$GW_PORT" )
export AGW_GATEWAY_URL="http://127.0.0.1:$GW_PORT"
AGW_DASHBOARD_SECRET="$(python3 -c 'import secrets; print(secrets.token_urlsafe(48))')"
export AGW_DASHBOARD_SECRET
[ -d .next ] && [ "${AGW_E2E_REBUILD:-1}" = "0" ] || npm run build >"$LOGS/build.log" 2>&1 || { cat "$LOGS/build.log"; exit 1; }
PORT="$UI_PORT" npm run start >"$LOGS/dashboard.log" 2>&1 &
UI_PID=$!
for _ in $(seq 1 60); do curl -fsS -o /dev/null "http://127.0.0.1:$UI_PORT/login" && break; sleep 0.5; done
export AGW_E2E_BASE_URL="http://localhost:$UI_PORT"  # localhost: Secure cookies allowed over http
rc=0; npx playwright test "$@" || rc=$?
echo "logs: $LOGS" >&2
exit "$rc"
