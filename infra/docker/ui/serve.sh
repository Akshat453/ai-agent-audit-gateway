#!/usr/bin/env bash
# Start one "ui" profile process with the shared environment: gateway | worker | mcp
set -euo pipefail
. /app/infra/docker/ui/env.sh
case "$1" in
  gateway) exec uvicorn agw_gateway.api.app:create_app --factory --host 0.0.0.0 --port 8080 --no-access-log ;;
  worker)  exec python -m agw_worker ;;
  mcp)     AGW_MCP_CLIENT_TOKEN="$(cat /var/lib/agw/mcp-client.token)" AGW_GATEWAY_URL=http://ui-gateway:8080 \
           AGW_MCP_RESOURCE_URL=http://ui-mcp:8765/mcp AGW_MCP_ALLOWED_HOSTS=ui-mcp:8765 \
           exec agw-mcp --host 0.0.0.0 --port 8765 ;;
  *) echo "usage: serve.sh gateway|worker|mcp" >&2; exit 2 ;;
esac
