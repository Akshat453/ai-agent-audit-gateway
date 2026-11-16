#!/usr/bin/env bash
# Phase 6: deploy EpochAnchor to the compose Anvil with the Foundry script, then write the
# deployment record contracts/deployments/anvil-31337.json (chain id, address, block, deployer,
# owner, creation/runtime code hashes, compiler settings).
#
# Dev keys: Anvil's PUBLIC test mnemonic, accounts 0 (owner/deployer) and 1 (submitter), derived
# inside the Foundry container into git-ignored secrets/ (0600). Never use them off Anvil.
set -euo pipefail
cd "$(dirname "$0")/.."
IMAGE=ghcr.io/foundry-rs/foundry:v1.3.5
RPC_HOST="http://127.0.0.1:${AGW_ANVIL_HOST_PORT:-8545}"
NET="${AGW_COMPOSE_NETWORK:-agw_default}"
MNEMONIC="test test test test test test test test test test test junk"
RECORD=contracts/deployments/anvil-31337.json

mkdir -p secrets
umask 077
derive() { docker run --rm --entrypoint cast "$IMAGE" wallet private-key --mnemonic "$MNEMONIC" --mnemonic-index "$1"; }
[ -s secrets/anchor-owner.key ] || derive 0 > secrets/anchor-owner.key
[ -s secrets/anchor-submitter.key ] || derive 1 > secrets/anchor-submitter.key
[ -s secrets/anchor-salt.hex ] || uv run python -c 'import secrets; print(secrets.token_hex(32))' > secrets/anchor-salt.hex

code_at() {
  curl -fsS -X POST -H 'Content-Type: application/json' \
    --data "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"eth_getCode\",\"params\":[\"$1\",\"latest\"]}" "$RPC_HOST" |
    python3 -c 'import json,sys; print(json.load(sys.stdin)["result"])'
}
if [ -f "$RECORD" ]; then
  ADDR=$(python3 -c "import json; print(json.load(open('$RECORD'))['address'])")
  if [ "$(code_at "$ADDR")" != "0x" ]; then
    echo "EpochAnchor already deployed at $ADDR (anvil 31337)"
    exit 0
  fi
fi
DEPLOYER_KEY="$(cat secrets/anchor-owner.key)" docker run --rm --network "$NET" -e DEPLOYER_KEY \
  -v "$PWD/contracts":/work -w /work --entrypoint forge "$IMAGE" \
  script script/Deploy.s.sol --rpc-url http://anvil:8545 --broadcast >/dev/null
uv run python -m agw_worker.anchoring.admin record-deployment \
  --broadcast contracts/broadcast/Deploy.s.sol/31337/run-latest.json --rpc "$RPC_HOST" --out "$RECORD"
