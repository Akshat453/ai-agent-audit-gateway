"""``python -m agw_worker.anchoring.admin``: operator commands for anchoring (ADR-0028).

    recorder-id        --tenant T                      print the tenant's recorder id
    record-deployment  --broadcast run-latest.json --rpc URL --out deployments/<chain>.json
    deploy             --owner-key-file F --rpc URL --out deployments/<chain>.json
    register           --tenant T --owner-key-file F   on-chain registerRecorder + DB row
    trust-config       --tenant T --deployment deployments/<chain>.json [--finality F]
                       [--rpc URL] --out pinned.json   what an auditor pins (no secrets)

Configuration comes from the gateway settings (AGW_ANCHOR_*). Keys are read from files given
by path and never printed. ``register`` writes ``anchor_recorders`` as agw_migrator
(AGW_MIGRATOR_DATABASE_URL): the runtime role cannot point a tenant at another recorder.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from eth_account import Account
from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert
from web3 import HTTPProvider, Web3

from agw_gateway.anchoring import recorder_id
from agw_gateway.config import Settings, load_settings
from agw_gateway.db import create_db_engine
from agw_gateway.db import tables as t
from agw_worker.anchoring.evm import EvmAnchorBackend, deploy, register_recorder

REPO = Path(__file__).resolve().parents[5]
ARTIFACT = REPO / "contracts" / "artifacts" / "EpochAnchor.json"
TRUST_FORMAT = "agw-anchor-trust/v1"


class AdminError(Exception):
    pass


def read_key(path: str | Path) -> str:
    raw = Path(path).read_text(encoding="utf-8").strip()
    key = raw.removeprefix("0x")
    try:
        ok = len(bytes.fromhex(key)) == 32
    except ValueError:
        ok = False
    if not ok:
        raise AdminError(f"{path}: not a 32-byte hex private key")  # never echo content
    return "0x" + key


def salt(settings: Settings) -> bytes:
    if settings.anchor_deployment_salt is None:
        raise AdminError("AGW_ANCHOR_DEPLOYMENT_SALT is not set")
    return bytes.fromhex(settings.anchor_deployment_salt.get_secret_value())


def code_record(rpc_url: str, address: str) -> dict[str, str]:
    w3 = Web3(HTTPProvider(rpc_url))
    code = bytes(w3.eth.get_code(Web3.to_checksum_address(address)))
    return {
        "runtime_code_sha256": hashlib.sha256(code).hexdigest(),
        "runtime_code_keccak256": Web3.keccak(code).hex().removeprefix("0x"),
    }


def deployment_record(
    rpc_url: str, address: str, tx_hash: str, block: int, deployer: str
) -> dict[str, Any]:
    w3 = Web3(HTTPProvider(rpc_url))
    artifact = json.loads(ARTIFACT.read_text())
    creation = bytes.fromhex(artifact["bytecode"].removeprefix("0x"))
    return {
        "contract": "EpochAnchor",
        "chain_id": int(w3.eth.chain_id),
        "address": address.lower(),
        "deploy_tx": tx_hash.lower() if tx_hash.startswith("0x") else "0x" + tx_hash.lower(),
        "block_number": int(block),
        "deployer": deployer.lower(),
        "owner": str(
            w3.eth.contract(
                address=Web3.to_checksum_address(address),
                abi=[
                    {
                        "type": "function",
                        "name": "owner",
                        "stateMutability": "view",
                        "inputs": [],
                        "outputs": [{"name": "", "type": "address"}],
                    }
                ],
            )
            .functions.owner()
            .call()
        ).lower(),
        "creation_code_sha256": hashlib.sha256(creation).hexdigest(),
        **code_record(rpc_url, address),
        "compiler": artifact["compiler"],
        "source": artifact["source"],
    }


def cmd_record_deployment(args: argparse.Namespace) -> dict[str, Any]:
    run = json.loads(Path(args.broadcast).read_text())
    tx = next(x for x in run["transactions"] if x.get("transactionType") == "CREATE")
    receipt = next(r for r in run["receipts"] if r["transactionHash"] == tx["hash"])
    return deployment_record(
        args.rpc,
        tx["contractAddress"],
        tx["hash"],
        int(receipt["blockNumber"], 16),
        tx["transaction"]["from"],
    )


def cmd_deploy(args: argparse.Namespace) -> dict[str, Any]:
    key = read_key(args.owner_key_file)
    artifact = json.loads(ARTIFACT.read_text())
    address, receipt = deploy(args.rpc, artifact, key)
    return deployment_record(
        args.rpc,
        address,
        bytes(receipt["transactionHash"]).hex(),
        int(receipt["blockNumber"]),
        Account.from_key(key).address,
    )


def cmd_register(args: argparse.Namespace, settings: Settings) -> dict[str, Any]:
    if settings.anchor_rpc_url is None or settings.anchor_contract is None:
        raise AdminError("AGW_ANCHOR_RPC_URL / AGW_ANCHOR_CONTRACT are not set")
    if settings.anchor_submitter_key_file is None:
        raise AdminError("AGW_ANCHOR_SUBMITTER_KEY_FILE is not set")
    if settings.migrator_database_url is None:
        raise AdminError("AGW_MIGRATOR_DATABASE_URL is not set")
    rpc = settings.anchor_rpc_url.get_secret_value()
    submitter = Account.from_key(read_key(settings.anchor_submitter_key_file)).address.lower()
    rid = recorder_id(args.tenant, salt(settings))
    backend = EvmAnchorBackend(
        rpc_url=rpc,
        chain_id=int(settings.anchor_chain_id or 0),
        contract=settings.anchor_contract,
    )
    current = backend.submitter_of(rid)
    if current == "0x" + "00" * 20:
        register_recorder(
            rpc, settings.anchor_contract, read_key(args.owner_key_file), rid, submitter
        )
    elif current != submitter:
        raise AdminError("recorder is registered on-chain to a different submitter")
    engine = create_db_engine(settings.migrator_database_url.get_secret_value(), pool_size=1)
    try:
        with engine.begin() as conn:
            conn.execute(
                insert(t.anchor_recorders)
                .values(
                    tenant_id=args.tenant,
                    recorder_id=rid,
                    chain_id=backend.chain_id,
                    contract=backend.contract,
                    submitter=submitter,
                    halted=False,
                )
                .on_conflict_do_nothing()
            )
            row = conn.execute(
                select(t.anchor_recorders).where(t.anchor_recorders.c.tenant_id == args.tenant)
            ).one()
    finally:
        engine.dispose()
    if bytes(row.recorder_id) != rid or row.contract != backend.contract:
        raise AdminError("tenant already pinned to a different recorder/contract")
    return {"tenant": args.tenant, "recorder_id": rid.hex(), "submitter": submitter}


def cmd_trust_config(args: argparse.Namespace, settings: Settings) -> dict[str, Any]:
    dep = json.loads(Path(args.deployment).read_text())
    doc: dict[str, Any] = {
        "format": TRUST_FORMAT,
        "chain_id": dep["chain_id"],
        "contract": dep["address"],
        "recorder_id": recorder_id(args.tenant, salt(settings)).hex(),
        "finality": args.finality,
        "code_sha256": dep["runtime_code_sha256"],
    }
    if args.rpc:
        doc["rpc"] = args.rpc
    return doc


def main(argv: Sequence[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="agw-anchor-admin")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("recorder-id")
    p.add_argument("--tenant", required=True)
    p = sub.add_parser("record-deployment")
    p.add_argument("--broadcast", required=True)
    p.add_argument("--rpc", required=True)
    p.add_argument("--out", required=True)
    p = sub.add_parser("deploy")
    p.add_argument("--owner-key-file", required=True)
    p.add_argument("--rpc", required=True)
    p.add_argument("--out", required=True)
    p = sub.add_parser("register")
    p.add_argument("--tenant", required=True)
    p.add_argument("--owner-key-file", required=True)
    p = sub.add_parser("trust-config")
    p.add_argument("--tenant", required=True)
    p.add_argument("--deployment", required=True)
    p.add_argument("--finality", default="finalized")
    p.add_argument("--rpc")
    p.add_argument("--out", required=True)
    args = ap.parse_args(argv)
    try:
        if args.cmd in ("record-deployment", "deploy"):
            doc = (
                cmd_record_deployment(args) if args.cmd == "record-deployment" else cmd_deploy(args)
            )
            Path(args.out).parent.mkdir(parents=True, exist_ok=True)
            Path(args.out).write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n")
            print(f"{doc['address']} (chain {doc['chain_id']}, block {doc['block_number']})")
            return 0
        settings = load_settings()
        if args.cmd == "recorder-id":
            print(recorder_id(args.tenant, salt(settings)).hex())
        elif args.cmd == "register":
            print(json.dumps(cmd_register(args, settings), sort_keys=True))
        else:
            doc = cmd_trust_config(args, settings)
            Path(args.out).write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n")
            print(args.out)
    except AdminError as exc:
        print(f"agw-anchor-admin: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
