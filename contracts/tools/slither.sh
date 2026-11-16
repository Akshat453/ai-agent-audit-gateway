#!/usr/bin/env bash
# Slither (via uvx, solc 0.8.28 via solc-select) on an isolated copy of EpochAnchor.sol: run in
# the repo, crytic-compile would detect foundry.toml and try to call a host `forge`.
set -euo pipefail
SRC="$(cd "$(dirname "$0")/.." && pwd)/src/EpochAnchor.sol"
WORK="$(mktemp -d)"
cp "$SRC" "$WORK/"
cd "$WORK"
export SOLC_SELECT_DIR="$WORK/.solc"
uvx --from solc-select --with slither-analyzer sh -c \
  'solc-select install 0.8.28 >/dev/null && solc-select use 0.8.28 >/dev/null && slither EpochAnchor.sol --solc-args "--optimize --optimize-runs 10000 --evm-version cancun"'
