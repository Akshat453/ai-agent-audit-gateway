#!/usr/bin/env bash
# "ui" profile init (Phase 9): database agw_ui, migrations, dev keys (private volume), contract
# on the compose Anvil, demo tenant + humans + agents, on-chain recorder registration.
# Idempotent: a second `docker compose --profile ui up` reuses everything.
set -euo pipefail
: "${AGW_UI_DEMO_PASSWORD:?set AGW_UI_DEMO_PASSWORD in .env}"
: "${POSTGRES_PASSWORD:?}" "${AGW_MIGRATOR_PASSWORD:?}" "${AGW_APP_PASSWORD:?}"
. /app/infra/docker/ui/env.sh
S=/var/lib/agw
umask 077
python - <<'PY'
import os, time, psycopg
su = f"host=postgres dbname=agw user=postgres password={os.environ['POSTGRES_PASSWORD']}"
for _ in range(120):
    try:
        conn = psycopg.connect(su, autocommit=True); break
    except psycopg.OperationalError:
        time.sleep(1)
if not conn.execute("SELECT 1 FROM pg_database WHERE datname = 'agw_ui'").fetchone():
    conn.execute("CREATE DATABASE agw_ui OWNER agw_migrator")
conn.close()
with psycopg.connect(su.replace("dbname=agw", "dbname=agw_ui"), autocommit=True) as c:
    c.execute("REVOKE ALL ON DATABASE agw_ui FROM PUBLIC")
    c.execute("GRANT CONNECT, CREATE, TEMPORARY ON DATABASE agw_ui TO agw_migrator")
    c.execute("GRANT CONNECT ON DATABASE agw_ui TO agw_app")
    c.execute("ALTER SCHEMA public OWNER TO agw_migrator")
    c.execute("REVOKE CREATE ON SCHEMA public FROM PUBLIC")
    c.execute("GRANT USAGE ON SCHEMA public TO agw_app")
PY
( cd /app/apps/gateway && alembic upgrade head >/dev/null )
[ -f "$S/approval-signing.key" ] || python -m agw_gateway.admin gen-signing-key --out "$S/approval-signing.key"
python -m agw_gateway.admin gen-delegation-key --out "$S/delegation-signing.key" --if-missing
python -m agw_gateway.admin gen-kek --if-missing --dir "$S/kek" --kek-id dev
[ -s "$S/smtp-relay.password" ] || python -c 'import secrets; print(secrets.token_urlsafe(24))' > "$S/smtp-relay.password"
[ -s "$S/anchor-salt.hex" ] || python -c 'import secrets; print(secrets.token_hex(32))' > "$S/anchor-salt.hex"
# Anvil's PUBLIC test mnemonic (dev only, never off Anvil): account 0 owner, 1 submitter.
python - <<'PY'
from pathlib import Path
from eth_account import Account
Account.enable_unaudited_hdwallet_features()
m = "test test test test test test test test test test test junk"
for i, name in ((0, "anchor-owner.key"), (1, "anchor-submitter.key")):
    p = Path("/var/lib/agw") / name
    if not p.exists():
        p.write_text(Account.from_mnemonic(m, account_path=f"m/44'/60'/0'/0/{i}").key.hex() + "\n")
PY
if ! python - <<'PY'
import json, sys, urllib.request
try:
    addr = json.load(open("/var/lib/agw/deployment.json"))["address"]
except FileNotFoundError:
    sys.exit(1)
req = urllib.request.Request("http://anvil:8545", data=json.dumps({"jsonrpc": "2.0", "id": 1,
      "method": "eth_getCode", "params": [addr, "latest"]}).encode(),
      headers={"Content-Type": "application/json"})
sys.exit(0 if json.load(urllib.request.urlopen(req))["result"] != "0x" else 1)
PY
then
  python -m agw_worker.anchoring.admin deploy --rpc http://anvil:8545 --owner-key-file "$S/anchor-owner.key" --out "$S/deployment.json" >/dev/null
fi
. /app/infra/docker/ui/env.sh   # picks up AGW_ANCHOR_CONTRACT
AGW_DEMO_APPROVER_PASSWORD="$AGW_UI_DEMO_PASSWORD" python -m agw_gateway.admin seed-demo >/dev/null
python -m agw_worker.anchoring.admin register --tenant demo --owner-key-file "$S/anchor-owner.key" >/dev/null
python -m agw_worker.anchoring.admin trust-config --tenant demo --deployment "$S/deployment.json" \
  --finality confirmations:2 --rpc http://anvil:8545 --out "$S/pinned-trust.json" >/dev/null
echo "ui-init done: database agw_ui, contract $(python -c "import json; print(json.load(open('$S/deployment.json'))['address'])"), tenant demo"
# The MCP adapter's own integration credential (re-keyed on every init; never an agent key).
python -m agw_gateway.admin create-integration-client --tenant demo --name demo-mcp \
  --audience http://ui-mcp:8765/mcp > "$S/mcp-client.token"
