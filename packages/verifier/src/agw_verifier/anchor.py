"""On-chain anchor checks (Phase 6, ADR-0028; 06 §8 steps 3-5; 10 §3).

Stdlib only: JSON-RPC over urllib, hand-rolled ABI encoding for two view calls of
EpochAnchor.sol. Function selectors are constants (keccak-256 is not in hashlib); a test
recomputes them with an independent keccak implementation.

Trust roots (chain id, contract address, recorder id, finality, optional runtime-code
SHA-256) MUST come from a pinned configuration the auditor obtained independently (e.g. the
operator manifest / contracts/deployments/<chain>.json, received out of band). Anchor claims
inside a bundle are never trusted: if they disagree with the pinned values, or if no pinned
values were given, the result is UNTRUSTED_ANCHOR.

Checks, in order: RPC on the pinned chain; code at the pinned contract (and its hash, if
pinned); for each epoch in the material, the anchor at the pinned finality block must match
the recomputed epoch root, tree size and last seq (else TAMPERED); continuity: the chain must
not hold epochs that the material lacks (whole-export mode -> TAMPERED); an event is VERIFIED
only if its epoch, or a later epoch of the same chain in the material, is anchored at
finality. Anchored-but-not-final -> UNANCHORED (ANCHOR_NOT_FINAL).
"""

from __future__ import annotations

import hashlib
import json
import re
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any

TRUST_FORMAT = "agw-anchor-trust/v1"
SEL_GET_ANCHOR = "6a9fc0b2"  # getAnchor(bytes32,uint64)
SEL_NEXT_EPOCH = "fc31a647"  # nextEpoch(bytes32)
_ADDR = re.compile(r"^0x[0-9a-f]{40}$")
_FINALITY = re.compile(r"^(latest|safe|finalized|confirmations:[1-9][0-9]{0,4})$")


class ChainUnavailable(Exception):
    pass


class TrustConfigError(ValueError):
    pass


@dataclass(frozen=True)
class TrustAnchor:
    chain_id: int
    contract: str
    recorder_id: bytes
    finality: str = "finalized"
    code_sha256: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "chain_id": self.chain_id,
            "contract": self.contract,
            "recorder_id": self.recorder_id.hex(),
            "finality": self.finality,
            "code_sha256": self.code_sha256,
        }


def make_trust(
    chain_id: Any, contract: Any, recorder_id: Any, finality: Any = None, code_sha256: Any = None
) -> TrustAnchor:
    """Validate pinned values. Missing chain id / contract / recorder id -> TrustConfigError."""
    if chain_id is None or contract is None or recorder_id is None:
        raise TrustConfigError("TRUST_ROOTS_NOT_PINNED")
    try:
        cid = int(chain_id)
        rid = bytes.fromhex(str(recorder_id).removeprefix("0x"))
    except (TypeError, ValueError):
        raise TrustConfigError("TRUST_CONFIG_INVALID") from None
    addr = str(contract).lower()
    fin = str(finality or "finalized")
    if cid <= 0 or len(rid) != 32 or not _ADDR.match(addr) or not _FINALITY.match(fin):
        raise TrustConfigError("TRUST_CONFIG_INVALID")
    code = str(code_sha256).lower().removeprefix("0x") if code_sha256 else None
    if code is not None and not re.fullmatch(r"[0-9a-f]{64}", code):
        raise TrustConfigError("TRUST_CONFIG_INVALID")
    return TrustAnchor(cid, addr, rid, fin, code)


def load_trust_file(path: str) -> dict[str, Any]:
    with open(path, encoding="utf-8") as fh:
        doc = json.load(fh)
    if not isinstance(doc, dict) or doc.get("format") != TRUST_FORMAT:
        raise TrustConfigError("TRUST_CONFIG_INVALID")
    return doc


# --------------------------------------------------------------------------- JSON-RPC
class Rpc:
    def __init__(self, url: str, timeout: float = 15.0) -> None:
        if not url.startswith(("http://", "https://")):
            raise TrustConfigError("RPC_URL_INVALID")
        self._url = url
        self._timeout = timeout
        self._id = 0

    def call(self, method: str, params: list[Any]) -> Any:
        self._id += 1
        body = json.dumps({"jsonrpc": "2.0", "id": self._id, "method": method, "params": params})
        req = urllib.request.Request(  # noqa: S310 - scheme checked in __init__
            self._url, data=body.encode(), headers={"Content-Type": "application/json"}
        )
        try:
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:  # noqa: S310  # nosec B310 - http(s) only, checked in __init__
                doc = json.loads(resp.read())
        except (urllib.error.URLError, OSError, ValueError) as exc:
            raise ChainUnavailable(type(exc).__name__) from None
        if not isinstance(doc, dict) or "error" in doc:
            raise ChainUnavailable("RPC_ERROR")
        return doc.get("result")


@dataclass(frozen=True)
class OnChain:
    root: bytes
    tree_size: int
    last_seq: int
    timestamp: int
    block_number: int


class ChainView:
    def __init__(self, rpc: Rpc, trust: TrustAnchor) -> None:
        self.rpc = rpc
        self.trust = trust

    def identity_problem(self) -> str | None:
        got = int(self.rpc.call("eth_chainId", []), 16)
        if got != self.trust.chain_id:
            return "RPC_CHAIN_ID_MISMATCH"
        code = bytes.fromhex(str(self.rpc.call("eth_getCode", [self.trust.contract, "latest"]))[2:])
        if not code:
            return "NO_CONTRACT_AT_PINNED_ADDRESS"
        if self.trust.code_sha256 and hashlib.sha256(code).hexdigest() != self.trust.code_sha256:
            return "CONTRACT_CODE_MISMATCH"
        return None

    def latest_block(self) -> int:
        return int(self.rpc.call("eth_blockNumber", []), 16)

    def final_block(self) -> int:
        fin = self.trust.finality
        if fin == "latest":
            return self.latest_block()
        if fin.startswith("confirmations:"):
            return self.latest_block() - int(fin.split(":", 1)[1]) + 1
        block = self.rpc.call("eth_getBlockByNumber", [fin, False])
        return int(block["number"], 16) if isinstance(block, dict) else -1

    def _call(self, data: str, block: int) -> bytes:
        if block < 0:
            raise ChainUnavailable("NO_FINAL_BLOCK")
        out = self.rpc.call("eth_call", [{"to": self.trust.contract, "data": data}, hex(block)])
        return bytes.fromhex(str(out)[2:])

    def anchor(self, epoch_no: int, block: int) -> OnChain | None:
        data = "0x" + SEL_GET_ANCHOR + self.trust.recorder_id.hex() + _u256(epoch_no)
        raw = self._call(data, block)
        if len(raw) != 5 * 32:
            raise ChainUnavailable("BAD_ABI_RESPONSE")
        words = [raw[i : i + 32] for i in range(0, 160, 32)]
        if words[0] == bytes(32):
            return None
        return OnChain(words[0], *(int.from_bytes(w, "big") for w in words[1:]))

    def next_epoch(self, block: int) -> int:
        raw = self._call("0x" + SEL_NEXT_EPOCH + self.trust.recorder_id.hex(), block)
        if len(raw) != 32:
            raise ChainUnavailable("BAD_ABI_RESPONSE")
        return int.from_bytes(raw, "big")


def _u256(n: int) -> str:
    return n.to_bytes(32, "big").hex()


# --------------------------------------------------------------------------- checks
def bundle_claims_problem(bundle: Any, trust: TrustAnchor) -> str | None:
    """Anchor claims inside the bundle are informational; any disagreement with the pinned
    trust roots means the bundle points at an anchor we must not trust."""
    claims = bundle.get("anchor") if isinstance(bundle, dict) else None
    if not isinstance(claims, dict):
        return None
    if "chain_id" in claims and claims["chain_id"] != trust.chain_id:
        return "BUNDLE_CHAIN_ID_NOT_PINNED"
    if "contract" in claims and str(claims["contract"]).lower() != trust.contract:
        return "BUNDLE_CONTRACT_NOT_PINNED"
    if "recorder_id" in claims and str(claims["recorder_id"]).lower() != trust.recorder_id.hex():
        return "BUNDLE_RECORDER_NOT_PINNED"
    return None


def check_against_chain(
    res: Any,
    records: list[dict[str, Any]],
    view: ChainView,
    *,
    min_epoch: int | None,
    whole_export: bool,
) -> Any:
    """``res`` passed the offline checks (VERIFIED/UNANCHORED, no trust root yet). ``records``
    are its epoch records (each root already recomputed). ``min_epoch``: the event's epoch in
    bundle mode. Mutates and returns ``res``."""
    res.result, res.reason = "VERIFIED", None
    res.notes = [n for n in res.notes if not n.startswith("locally sealed only")]
    try:
        problem = view.identity_problem()
        if problem:
            return res.fail("UNTRUSTED_ANCHOR", problem)
        final = view.final_block()
        latest = view.latest_block()
        anchored: list[int] = []
        seen: dict[int, dict[str, Any]] = {}
        for rec in records:
            on = view.anchor(rec["epoch_no"], final) if final >= 0 else None
            if on is None:
                continue
            if (
                on.root.hex() != rec["epoch_root"]
                or on.tree_size != rec["tree_size"]
                or on.last_seq != rec["last_seq"]
            ):
                return res.fail("TAMPERED", "ANCHOR_ROOT_MISMATCH", epoch=rec["epoch_no"])
            anchored.append(rec["epoch_no"])
            seen[rec["epoch_no"]] = {
                "epoch_no": rec["epoch_no"],
                "block_number": on.block_number,
                "timestamp": on.timestamp,
                "final_block": final,
                "finality": view.trust.finality,
            }
        last_material = records[-1]["epoch_no"] if records else -1
        chain_next = view.next_epoch(latest)
        res.chain_last_epoch = chain_next - 1
        if whole_export and chain_next - 1 > last_material:
            return res.fail("TAMPERED", "EPOCHS_MISSING_VS_CHAIN", epoch=last_material + 1)
        if chain_next - 1 > last_material:
            res.notes.append(
                f"chain holds epochs up to {chain_next - 1}; material ends at {last_material}"
            )
        relevant = [e for e in anchored if min_epoch is None or e >= min_epoch]
        if not relevant:
            pending = [
                r["epoch_no"]
                for r in records
                if (min_epoch is None or r["epoch_no"] >= min_epoch)
                and view.anchor(r["epoch_no"], latest) is not None
            ]
            return res.fail(
                "UNANCHORED", "ANCHOR_NOT_FINAL" if pending else "NOT_ANCHORED", epoch=min_epoch
            )
        res.trusted_epoch = max(anchored) if whole_export else min(relevant)
        res.anchor = seen[res.trusted_epoch]  # the anchor this result relies on
        unanchored_tail = [r["epoch_no"] for r in records if r["epoch_no"] > max(anchored)]
        if whole_export and unanchored_tail:
            res.result = "UNANCHORED"
            res.reason = "TAIL_NOT_ANCHORED"
            res.notes.append(
                f"epochs {unanchored_tail[0]}..{unanchored_tail[-1]} are not anchored at "
                f"{view.trust.finality}"
            )
        return res
    except ChainUnavailable as exc:
        return res.fail("INCOMPLETE", f"CHAIN_UNAVAILABLE:{exc}")
