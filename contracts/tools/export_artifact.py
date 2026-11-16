"""Write/check contracts/artifacts/EpochAnchor.json from Foundry's build output.

    python contracts/tools/export_artifact.py [--check]

The committed artifact (ABI, creation and runtime bytecode, compiler settings, SHA-256 of the
runtime code) is what Python deploys and what auditors' pinned trust configs refer to. With
--check, a fresh ``forge build`` must reproduce it byte for byte.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "out" / "EpochAnchor.sol" / "EpochAnchor.json"
ARTIFACT = ROOT / "artifacts" / "EpochAnchor.json"


def build() -> str:
    raw = json.loads(OUT.read_text())
    runtime = bytes.fromhex(raw["deployedBytecode"]["object"].removeprefix("0x"))
    doc = {
        "contract": "EpochAnchor",
        "source": "contracts/src/EpochAnchor.sol",
        "compiler": {
            "solc": "0.8.28",
            "optimizer_runs": 10000,
            "evm_version": "cancun",
            "bytecode_hash": "none",
            "cbor_metadata": False,
        },
        "abi": raw["abi"],
        "bytecode": raw["bytecode"]["object"],
        "deployedBytecode": raw["deployedBytecode"]["object"],
        # Immutable `owner` is patched into the runtime code at deploy time, so the on-chain
        # code hash is per deployment (recorded in deployments/<chain>.json).
        # Byte offsets only: the map's keys are AST node ids, which change with whatever else
        # (tests, scripts) is in the same compilation unit.
        "immutableOffsets": sorted(
            (r["start"], r["length"])
            for refs in raw["deployedBytecode"].get("immutableReferences", {}).values()
            for r in refs
        ),
        "deployedBytecode_sha256_unlinked": hashlib.sha256(runtime).hexdigest(),
    }
    return json.dumps(doc, indent=2, sort_keys=True) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args()
    text = build()
    if args.check:
        if not ARTIFACT.exists() or ARTIFACT.read_text() != text:
            print("artifact differs from a fresh forge build", file=sys.stderr)
            return 1
        print("artifact matches forge build")
        return 0
    ARTIFACT.write_text(text)
    print(f"wrote {ARTIFACT.relative_to(ROOT.parent)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
