"""Measure gas per EpochAnchor.anchor() from real transactions (Phase 6, ADR-0028).

    # local: starts a throwaway Anvil (pinned Foundry image), deploys from the committed artifact
    uv run python experiments/anchoring/measure_gas.py --n 40

    # Base Sepolia (chain 84532): user-supplied, funded key files; nothing is printed from them
    uv run python experiments/anchoring/measure_gas.py --n 40 --rpc "$BASE_SEPOLIA_RPC" \
        --chain-id 84532 --owner-key-file secrets/sepolia-owner.key \
        --submitter-key-file secrets/sepolia-submitter.key [--contract 0x...]

Every number in the output comes from a mined receipt (gasUsed, effectiveGasPrice and, on OP
Stack chains such as Base, the receipt's l1Fee). The cost table multiplies MEASURED gas by
STATED gas-price assumptions; it does not reuse Paper B's $2.30 / 100K figure.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import secrets
import statistics
import subprocess
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from eth_account import Account
from web3 import HTTPProvider, Web3

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "apps/worker/src"))

from agw_worker.anchoring.admin import read_key  # noqa: E402
from agw_worker.anchoring.backend import AnchorItem  # noqa: E402
from agw_worker.anchoring.evm import EvmAnchorBackend, deploy, register_recorder  # noqa: E402

ARTIFACT = json.loads((REPO / "contracts/artifacts/EpochAnchor.json").read_text())
IMAGE = "ghcr.io/foundry-rs/foundry:v1.3.5"
# Stated assumptions for the cost table (NOT market data; edit and re-run).
L2_GAS_PRICES_GWEI = (0.001, 0.01, 0.1, 1.0)
ETH_USD = 3000.0


def start_anvil() -> tuple[str, str]:
    argv = ["docker", "run", "-d", "--rm", "-p", "127.0.0.1::8545", "--entrypoint", "anvil"]
    argv += [IMAGE, "--host", "0.0.0.0", "--chain-id", "31337", "--silent"]  # noqa: S104 - in container
    cid = subprocess.check_output(argv, text=True).strip()  # noqa: S603 - fixed argv
    port = subprocess.check_output(["docker", "port", cid, "8545"], text=True).split(":")[-1]  # noqa: S603, S607
    url = f"http://127.0.0.1:{port.strip()}"
    w3 = Web3(HTTPProvider(url))
    for _ in range(100):
        try:
            w3.eth.chain_id  # noqa: B018
            return cid, url
        except Exception:
            time.sleep(0.2)
    raise SystemExit("anvil did not start")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=40)
    ap.add_argument("--rpc")
    ap.add_argument("--chain-id", type=int)
    ap.add_argument("--contract")
    ap.add_argument("--owner-key-file")
    ap.add_argument("--submitter-key-file")
    ap.add_argument("--out", default=str(REPO / "experiments/anchoring/results"))
    ap.add_argument(
        "--finality-timeout",
        type=float,
        default=0.0,
        help="off Anvil: also wait (up to N s) for the last anchor's block to reach the node's "
        "`safe` and `finalized` tags and record how long that took (09 §6)",
    )
    args = ap.parse_args()
    if args.n < 30:
        raise SystemExit("--n must be >= 30 (Phase 6 acceptance)")

    container = None
    if args.rpc is None:
        container, rpc = start_anvil()
        w3 = Web3(HTTPProvider(rpc))
        owner, sub = Account.create(), Account.create()
        for a in (owner, sub):
            w3.provider.make_request("anvil_setBalance", [a.address, hex(10**20)])  # type: ignore[arg-type]
        owner_key, sub_key = "0x" + bytes(owner.key).hex(), "0x" + bytes(sub.key).hex()
        network = "anvil-31337"
    else:
        rpc = args.rpc
        w3 = Web3(HTTPProvider(rpc))
        if args.chain_id is not None and w3.eth.chain_id != args.chain_id:
            raise SystemExit("RPC chain id does not match --chain-id")
        if not (args.owner_key_file and args.submitter_key_file):
            raise SystemExit("--owner-key-file and --submitter-key-file are required off Anvil")
        owner_key, sub_key = read_key(args.owner_key_file), read_key(args.submitter_key_file)
        network = f"chain-{w3.eth.chain_id}"
    try:
        chain_id = int(w3.eth.chain_id)
        contract = args.contract
        deploy_gas = None
        if contract is None:
            contract, receipt = deploy(rpc, ARTIFACT, owner_key)
            deploy_gas = int(receipt["gasUsed"])
        submitter = Account.from_key(sub_key).address.lower()
        rid = hashlib.sha256(b"agw-gas-measurement" + secrets.token_bytes(16)).digest()
        reg = register_recorder(rpc, contract, owner_key, rid, submitter)
        backend = EvmAnchorBackend(
            rpc_url=rpc, chain_id=chain_id, contract=contract, private_key=sub_key
        )
        rows: list[dict[str, Any]] = []
        last_seq = -1
        nonce = backend.pending_nonce()
        for epoch in range(args.n):
            size = (1, 100, 25, 7)[epoch % 4]  # CRITICAL [s,s], LOW 100, MEDIUM 25, HIGH-ish
            last_seq += size
            item = AnchorItem(rid, epoch, secrets.token_bytes(32), size, last_seq)
            signed = backend.sign_anchor(item, nonce)
            t0 = time.monotonic()
            backend.broadcast(signed.raw)
            receipt = w3.eth.wait_for_transaction_receipt(signed.tx_hash, timeout=300)
            if int(receipt["status"]) != 1:
                raise SystemExit(f"anchor {epoch} reverted")
            rows.append(
                {
                    "epoch": epoch,
                    "tree_size": size,
                    "gas_used": int(receipt["gasUsed"]),
                    "effective_gas_price_wei": int(receipt.get("effectiveGasPrice", 0)),
                    "l1_fee_wei": int(receipt["l1Fee"], 16)
                    if isinstance(receipt.get("l1Fee"), str)
                    else receipt.get("l1Fee"),
                    "calldata_bytes": len(w3.eth.get_transaction(signed.tx_hash)["input"]),
                    "inclusion_seconds": round(time.monotonic() - t0, 3),
                    "block": int(receipt["blockNumber"]),
                    "tx": "0x" + signed.tx_hash.hex(),
                }
            )
            nonce += 1
    finally:
        if container:
            subprocess.run(["docker", "rm", "-f", container], capture_output=True, check=False)  # noqa: S603, S607

    finality: dict[str, float | None] = {}
    if args.finality_timeout > 0 and rows:
        target, t0 = rows[-1]["block"], time.monotonic()
        for tag in ("safe", "finalized"):
            while time.monotonic() - t0 < args.finality_timeout:
                if int(w3.eth.get_block(tag)["number"]) >= target:  # type: ignore[arg-type]
                    finality[tag] = round(time.monotonic() - t0, 1)
                    break
                time.sleep(5)
            else:
                finality[tag] = None  # not reached within the timeout

    gas = [r["gas_used"] for r in rows]
    first, warm = gas[0], gas[1:]
    summary = {
        "network": network,
        "chain_id": chain_id,
        "measured_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "contract": contract,
        "n_anchors": len(rows),
        "deploy_gas": deploy_gas,
        "register_gas": int(reg["gasUsed"]),
        "anchor_gas_first": first,
        "anchor_gas_warm": {
            "min": min(warm),
            "median": statistics.median(warm),
            "mean": round(statistics.mean(warm), 1),
            "max": max(warm),
        },
        "anchor_gas_all_mean": round(statistics.mean(gas), 1),
        "seconds_from_last_inclusion_to_tag": finality or None,
        "assumptions": {
            "l2_gas_price_gwei": list(L2_GAS_PRICES_GWEI),
            "eth_usd": ETH_USD,
            "note": "stated assumptions, not market data; L1 data fee only from real receipts",
        },
        "rows": rows,
    }
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / f"gas-{network}.json").write_text(json.dumps(summary, indent=2) + "\n")
    mean = summary["anchor_gas_all_mean"]
    lines = [
        f"# Anchor gas, {network} (measured {summary['measured_at']})",
        "",
        f"{len(rows)} mined `anchor()` transactions; contract `{contract}`.",
        "",
        "| metric | gas |",
        "|---|---|",
        f"| deploy | {deploy_gas if deploy_gas is not None else 'n/a (existing contract)'} |",
        f"| registerRecorder | {summary['register_gas']} |",
        f"| anchor, first for the recorder (cold `nextEpoch` slot) | {first} |",
        f"| anchor, later (min / median / mean / max) | {min(warm)} / {summary['anchor_gas_warm']['median']} / {summary['anchor_gas_warm']['mean']} / {max(warm)} |",
        f"| anchor, mean of all {len(rows)} | {mean} |",
        "",
        "Cost per anchor from the MEASURED mean gas under STATED assumptions "
        f"(ETH = ${ETH_USD:,.0f}; L2 execution gas only, L1 data fee excluded):",
        "",
        "| L2 gas price | ETH / anchor | USD / anchor | USD / 100K anchors |",
        "|---|---|---|---|",
    ]
    for gwei in L2_GAS_PRICES_GWEI:
        eth = mean * gwei * 1e-9
        lines.append(
            f"| {gwei} gwei | {eth:.3e} | ${eth * ETH_USD:.6f} | ${eth * ETH_USD * 1e5:,.2f} |"
        )
    l1 = [r["l1_fee_wei"] for r in rows if r["l1_fee_wei"]]
    lines += [
        "",
        f"L1 data fee (OP Stack receipts): {'mean ' + str(round(statistics.mean(l1))) + ' wei' if l1 else 'not present on this chain (Anvil): measure on Base Sepolia'}.",
    ]
    if finality:
        lines.append(
            "Time from the last anchor's inclusion until its block was `safe` / `finalized`: "
            + ", ".join(
                f"{k} {v if v is not None else 'not reached'} s" for k, v in finality.items()
            )
            + "."
        )
    (out / f"gas-{network}.md").write_text("\n".join(lines) + "\n")
    print("\n".join(lines))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
