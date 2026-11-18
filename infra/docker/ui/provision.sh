#!/usr/bin/env bash
# "ui" profile provisioner (DEV ONLY): tenants created by self-service sign-up get their
# on-chain anchoring recorder on the local Anvil contract, exactly like init.sh does for
# "demo". Runs where the Anvil test owner key lives (the private ui-state volume); the gateway
# never sees that key. Polls every 5 s; nothing secret is printed.
set -euo pipefail
. /app/infra/docker/ui/env.sh
S=/var/lib/agw
while true; do
  for tenant in $(python - <<'PY'
import os, psycopg
url = os.environ["AGW_MIGRATOR_DATABASE_URL"].replace("postgresql+psycopg://", "postgresql://")
with psycopg.connect(url) as c:
    for (t,) in c.execute("SELECT t.tenant_id FROM tenants t LEFT JOIN anchor_recorders r "
                          "USING (tenant_id) WHERE r.tenant_id IS NULL ORDER BY 1"):
        print(t)
PY
  ); do
    if python -m agw_worker.anchoring.admin register --tenant "$tenant" --owner-key-file "$S/anchor-owner.key" >/dev/null; then
      echo "provisioned anchoring for tenant $tenant"
    else
      echo "anchoring registration failed for tenant $tenant (retrying)" >&2
    fi
  done
  sleep 5
done
