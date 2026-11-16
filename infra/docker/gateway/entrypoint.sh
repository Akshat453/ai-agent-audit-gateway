#!/bin/sh
# Gateway container start (Phase 8 containment demo). Migrates, creates dev keys INSIDE the
# gateway's private volume, seeds demo agents, writes ONE agent credential to the shared
# /creds volume (the agent's own API key, not a tool credential), then serves.
set -eu
export AGW_DATABASE_URL="postgresql+psycopg://agw_app:${AGW_APP_PASSWORD}@postgres:5432/agw"
export AGW_MIGRATOR_DATABASE_URL="postgresql+psycopg://agw_migrator:${AGW_MIGRATOR_PASSWORD}@postgres:5432/agw"
S=/var/lib/agw
umask 077
until python -c "import os, psycopg; psycopg.connect(os.environ['AGW_MIGRATOR_DATABASE_URL'].replace('+psycopg', '')).close()" 2>/dev/null; do sleep 0.5; done
( cd /app/apps/gateway && alembic upgrade head >/dev/null )
[ -f "$S/approval.key" ] || python -m agw_gateway.admin gen-signing-key --out "$S/approval.key"
python -m agw_gateway.admin gen-delegation-key --out "$S/delegation.key" --if-missing
AGW_KEK_DIR="$S/kek" python -m agw_gateway.admin gen-kek --if-missing
python -m agw_gateway.admin seed-demo >/dev/null
python -m agw_gateway.admin create-agent-key --tenant demo --agent demo-worker --expires-days 1 > /creds/agent.token
chmod 0444 /creds/agent.token
export AGW_APPROVAL_SIGNING_KEY_FILE="$S/approval.key" AGW_DELEGATION_SIGNING_KEY_FILE="$S/delegation.key" AGW_KEK_DIR="$S/kek"
exec uvicorn agw_gateway.api.app:create_app --factory --host 0.0.0.0 --port 8080 --no-access-log
