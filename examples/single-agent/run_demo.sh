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
# Phase 4: default risk-adaptive sealing (LOW 100/300 s, MEDIUM 25/60 s, HIGH/CRITICAL at once).
OUT="$(mktemp -d -t agw-demo.XXXXXX)"

# Phase 5: gateway-held Ed25519 decision-signing key (dev; git-ignored secrets/), created once.
export AGW_APPROVAL_SIGNING_KEY_FILE="${AGW_APPROVAL_SIGNING_KEY_FILE:-./secrets/approval-signing.key}"
[ -f "$AGW_APPROVAL_SIGNING_KEY_FILE" ] || uv run python -m agw_gateway.admin gen-signing-key --out "$AGW_APPROVAL_SIGNING_KEY_FILE"
# Demo approver password: random per run, only in this process's environment, never printed.
AGW_DEMO_APPROVER_PASSWORD="$(uv run python -c 'import secrets; print(secrets.token_urlsafe(24))')"
export AGW_DEMO_APPROVER_PASSWORD
export AGW_APPROVER_TENANT=demo AGW_APPROVER_USER=alice AGW_APPROVER_PASSWORD="$AGW_DEMO_APPROVER_PASSWORD"

# Phase 7: KEK keyring outside the repo (AGW_KEK_DIR, default ~/.agw/kek), created once.
uv run python -m agw_gateway.admin gen-kek --if-missing
# Phase 7: the AUDITOR's side lives in its own venv with ONLY agw-verifier[disclosure]; the
# auditor generates her X25519 key there. Only the public key ever reaches the gateway.
AUD="$OUT/auditor"; AV="$OUT/auditor-venv"; mkdir -p "$AUD"
uv venv -q "$AV" --python 3.12
uv pip install -q --python "$AV/bin/python" "./packages/verifier[disclosure]"
AUDITOR_PUBLIC_KEY="$("$AV/bin/agw-verify" auditor-keygen --out "$AUD/auditor.key" | python3 -c 'import json,sys; print(json.load(sys.stdin)["public_key"])')"
export AUDITOR_PUBLIC_KEY

# Phase 8: delegation-token signing key (git-ignored secrets/), and the SMTP relay credential
# that ONLY the gateway holds (random, created once; the compose mailpit sink accepts any).
uv run python -m agw_gateway.admin gen-delegation-key --out secrets/delegation-signing.key --if-missing
export AGW_DELEGATION_SIGNING_KEY_FILE=./secrets/delegation-signing.key
[ -f secrets/smtp-relay.password ] || ( umask 077; python3 -c 'import secrets; print(secrets.token_urlsafe(24))' > secrets/smtp-relay.password )
export AGW_SMTP_HOST=127.0.0.1 AGW_SMTP_PORT="${AGW_MAILPIT_SMTP_PORT:-1025}" AGW_SMTP_STARTTLS=false
export AGW_SMTP_USERNAME=agw-relay AGW_SMTP_PASSWORD_FILE=./secrets/smtp-relay.password
export AGW_SMTP_FROM=gateway@corp.example AGW_SMTP_ALLOWED_DOMAINS=corp.example,partner.example

uv run python -m agw_gateway.admin seed-demo
# The token is printed once by the admin CLI and kept only in this process's environment.
AGW_AGENT_TOKEN="$(uv run python -m agw_gateway.admin create-agent-key --tenant demo --agent demo-agent --expires-days 1)"
export AGW_AGENT_TOKEN
AGW_IAM_AGENT_TOKEN="$(uv run python -m agw_gateway.admin create-agent-key --tenant demo --agent demo-iam-admin --expires-days 1)"
export AGW_IAM_AGENT_TOKEN
# Phase 8: planner + worker (multi-agent demo). The worker also gets an MCP-audience key and
# the MCP adapter its own integration credential (no agent key passes through the adapter).
AGW_PLANNER_TOKEN="$(uv run python -m agw_gateway.admin create-agent-key --tenant demo --agent demo-planner --expires-days 1)"
AGW_WORKER_TOKEN="$(uv run python -m agw_gateway.admin create-agent-key --tenant demo --agent demo-worker --expires-days 1)"
AGW_WORKER_AGENT_ID="$(uv run python -m agw_gateway.admin agent-id --tenant demo --agent demo-worker)"
MCP_PORT="${AGW_MCP_PORT:-8765}"
export AGW_MCP_URL="http://127.0.0.1:${MCP_PORT}/mcp"
AGW_MCP_CLIENT_TOKEN="$(uv run python -m agw_gateway.admin create-integration-client --tenant demo --name demo-mcp --audience "$AGW_MCP_URL")"
AGW_WORKER_MCP_TOKEN="$(uv run python -m agw_gateway.admin create-agent-key --tenant demo --agent demo-worker --expires-days 1 --audience "$AGW_MCP_URL")"
export AGW_PLANNER_TOKEN AGW_WORKER_TOKEN AGW_WORKER_AGENT_ID AGW_WORKER_MCP_TOKEN

# Phase 6: anchoring on the compose Anvil. Deployed with the Foundry script (record in
# contracts/deployments/anvil-31337.json); dev keys/salt in git-ignored secrets/ (never printed).
./contracts/deploy-anvil.sh
export AGW_ANCHOR_RPC_URL="http://127.0.0.1:${AGW_ANVIL_HOST_PORT:-8545}"
export AGW_ANCHOR_CHAIN_ID=31337
AGW_ANCHOR_CONTRACT="$(python3 -c "import json; print(json.load(open('contracts/deployments/anvil-31337.json'))['address'])")"
export AGW_ANCHOR_CONTRACT
export AGW_ANCHOR_SUBMITTER_KEY_FILE=./secrets/anchor-submitter.key
export AGW_ANCHOR_DEPLOYMENT_SALT_FILE=./secrets/anchor-salt.hex
export AGW_ANCHOR_FINALITY=confirmations:2   # Anvil has no real finality (block time 1 s)
export AGW_ANCHOR_ROUTINE_DELAY_SECONDS=5 AGW_ANCHOR_POLL_SECONDS=1
export AGW_PRE_ANCHOR_RULES='*' AGW_CRITICAL_ANCHOR_TIMEOUT_SECONDS=60
uv run python -m agw_worker.anchoring.admin register --tenant demo --owner-key-file secrets/anchor-owner.key

uv run uvicorn agw_gateway.api.app:create_app --factory --host 127.0.0.1 --port "$PORT" --no-access-log >"$OUT/gateway.log" 2>&1 &
GW_PID=$!
uv run python -m agw_worker >"$OUT/worker.log" 2>&1 &
WK_PID=$!
AGW_MCP_CLIENT_TOKEN="$AGW_MCP_CLIENT_TOKEN" AGW_MCP_RESOURCE_URL="$AGW_MCP_URL" \
  uv run agw-mcp --port "$MCP_PORT" >"$OUT/mcp.log" 2>&1 &
MCP_PID=$!
stop_stack() { kill "$GW_PID" "$WK_PID" "$MCP_PID" 2>/dev/null || true; wait "$GW_PID" "$WK_PID" "$MCP_PID" 2>/dev/null || true; }
trap stop_stack EXIT

for _ in $(seq 1 50); do
  if curl -fsS "$AGW_GATEWAY_URL/v1/ready" >/dev/null 2>&1; then break; fi
  sleep 0.2
done
curl -fsS "$AGW_GATEWAY_URL/v1/ready" >/dev/null || { echo "gateway not ready; log: $OUT/gateway.log"; cat "$OUT/gateway.log"; exit 1; }

uv run python examples/single-agent/agent.py "$@"
echo "--- Phase 8: LLM tool-calling agent (AGW_LLM_PROVIDER=${AGW_LLM_PROVIDER:-mock}) ---"
uv run python examples/single-agent/llm_agent.py
uv run python examples/single-agent/approval_demo.py
uv run python examples/single-agent/anchor_demo.py "$OUT"
uv run python examples/single-agent/disclosure_demo.py "$OUT"
echo "--- Phase 8: planner delegates to worker; LangGraph (SDK tools), then MCP ---"
uv run python examples/multi-agent/run.py --transport sdk --out "$OUT"
uv run python examples/multi-agent/run.py --transport mcp --out "$OUT"
curl -fsS "http://127.0.0.1:${AGW_MAILPIT_HTTP_PORT:-8025}/api/v1/messages" | python3 -c 'import json,sys; m=json.load(sys.stdin)["messages"]; s=[x for x in m if x["Subject"].startswith("Your escalation")]; print(f"SMTP sink received {len(s)} approved email(s) from the gateway"); sys.exit(0 if len(s) >= 2 else 1)'
uv run python examples/single-agent/fetch_bundle.py "$OUT"
echo "--- gateway risk metrics (operational counters only) ---"
curl -fsS "$AGW_GATEWAY_URL/metrics" | grep -E '^agw_(risk_decisions|approval_[a-z_]+)_total' || true
# The auditor's pinned trust roots: in reality obtained out of band (operator manifest /
# deployments record), NEVER from a bundle. Contains no secret: chain id, contract, recorder id.
uv run python -m agw_worker.anchoring.admin trust-config --tenant demo \
  --deployment contracts/deployments/anvil-31337.json --finality confirmations:2 \
  --rpc "$AGW_ANCHOR_RPC_URL" --out "$OUT/pinned-trust.json" >/dev/null
uv run python -m agw_gateway.admin export-chain --tenant demo --out "$OUT/events.jsonl"
uv run python -m agw_gateway.admin export-epochs --tenant demo --out "$OUT/epochs.jsonl"
uv run python - "$OUT/events.jsonl" <<'PY'
import collections, json, sys
from agw_gateway.crypto.canonical import decode
kinds = collections.Counter()
for line in list(open(sys.argv[1]))[1:]:
    rec = decode(bytes.fromhex(json.loads(line)["header"]))
    if rec["type"].startswith(("DISCLOSURE_", "PAYLOAD_")):
        outcome = rec.get("outcome", {}).get("code") or rec.get("outcome", {}).get("status") or ""
        kinds[f"{rec['type']} {outcome}".strip()] += 1
print("disclosure evidence in the chain:", dict(sorted(kinds.items())))
assert kinds["DISCLOSURE_GRANTED"] >= 1 and kinds["DISCLOSURE_ACCESSED COMPLETED"] >= 1
assert kinds["DISCLOSURE_ACCESSED EVENT_NOT_GRANTED"] >= 1
PY

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
echo "--- Phase 6: offline verification against the chain (pinned trust roots, no gateway) ---"
rc=0; uv run agw-verify event --bundle "$OUT/bundle.json" --trust-config "$OUT/pinned-trust.json" || rc=$?
echo "agw-verify event  (on-chain anchor)   exit=$rc"; [ "$rc" -eq 0 ] || exit 1
rc=0; uv run agw-verify event --bundle "$OUT/bundle-critical.json" --trust-config "$OUT/pinned-trust.json" >/dev/null || rc=$?
echo "agw-verify event  (CRITICAL ACTION_AUTHORIZED, pre-action anchor) exit=$rc"; [ "$rc" -eq 0 ] || exit 1
rc=0; uv run agw-verify epochs --export "$OUT/epochs.jsonl" --events "$OUT/events.jsonl" --trust-config "$OUT/pinned-trust.json" >/dev/null || rc=$?
echo "agw-verify epochs (on-chain anchors)  exit=$rc"; [ "$rc" -eq 0 ] || exit 1
python3 -c "import json,sys; d=json.load(open(sys.argv[1])); d['contract']='0x'+'de'*20; json.dump(d,open(sys.argv[2],'w'))" "$OUT/pinned-trust.json" "$OUT/wrong-trust.json"
rc=0; uv run agw-verify event --bundle "$OUT/bundle.json" --trust-config "$OUT/wrong-trust.json" >/dev/null || rc=$?
echo "agw-verify event  (auditor pinned a different contract) exit=$rc (5 = UNTRUSTED_ANCHOR)"; [ "$rc" -eq 5 ] || exit 1
echo "--- Phase 8: every multi-agent event, offline, against the on-chain anchors ---"
uv run python examples/multi-agent/verify_offline.py "$OUT" "$OUT/pinned-trust.json"
echo "--- Phase 7: the auditor, in her own venv, with ONLY bundles + her key + pinned trust roots ---"
cp "$OUT/pinned-trust.json" "$AUD/"
( cd "$AUD"
  echo "auditor workspace: $(ls | tr '\n' ' ')"
  "$AV/bin/python" -c "import importlib.util as u; assert not u.find_spec('agw_gateway'); print('auditor venv: no gateway code installed')"
  for b in bundle-*.json; do
    rc=0; "$AV/bin/agw-verify" event --bundle "$b" --auditor-key auditor.key --trust-config pinned-trust.json || rc=$?
    echo "agw-verify event $b (decrypt -> digest -> proof -> anchor) exit=$rc"; [ "$rc" -eq 0 ] || exit 1
  done
  python3 -c "import json; b=json.load(open('bundle-0.json')); c=b['disclosure']['ciphertext']; b['disclosure']['ciphertext']=c[:-2]+('00' if c[-2:]!='00' else '01'); json.dump(b,open('tampered.json','w'))"
  rc=0; "$AV/bin/agw-verify" event --bundle tampered.json --auditor-key auditor.key --trust-config pinned-trust.json >/dev/null || rc=$?
  echo "agw-verify event (one ciphertext byte flipped) exit=$rc (1 = TAMPERED)"; [ "$rc" -eq 1 ] || exit 1
  rc=0; "$AV/bin/agw-verify" event --bundle bundle-0.json --trust-config pinned-trust.json >/dev/null || rc=$?
  echo "agw-verify event (no auditor key: payload unchecked) exit=$rc (2 = INCOMPLETE)"; [ "$rc" -eq 2 ] || exit 1
)
echo "PHASE 7 AUDITOR VERIFICATION OK"
echo "artifacts: $OUT"
