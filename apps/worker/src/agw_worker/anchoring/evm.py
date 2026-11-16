"""EVM implementation of ``AnchorBackend`` for EpochAnchor.sol (web3.py; ADR-0028).

* The submitter's private key is held only in the eth_account object; it is never logged,
  never put in an exception message and never written anywhere by this module.
* Transactions use a FIXED gas limit (``AGW_ANCHOR_GAS_LIMIT``) instead of eth_estimateGas:
  estimating epoch N+1 while epoch N is still in the mempool would revert (EpochOutOfOrder),
  which would serialize anchoring to one transaction per block.
* EIP-1559 fees: maxPriorityFee = node suggestion, maxFee = 2 * baseFee + priority.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import requests
from eth_account import Account
from eth_typing import ChecksumAddress
from hexbytes import HexBytes
from web3 import HTTPProvider, Web3
from web3.exceptions import (
    BlockNotFound,
    ProviderConnectionError,
    TimeExhausted,
    TransactionNotFound,
    Web3RPCError,
)
from web3.types import BlockIdentifier

from agw_gateway.anchoring import Finality
from agw_worker.anchoring.backend import (
    ZERO32,
    AnchorConfigError,
    AnchorItem,
    AnchorRpcError,
    OnChainAnchor,
    Receipt,
    SignedSubmission,
)

# Subset of contracts/artifacts/EpochAnchor.json (a unit test keeps them in sync).
EPOCH_ANCHOR_ABI: list[dict[str, Any]] = [
    {
        "type": "function",
        "name": "anchor",
        "stateMutability": "nonpayable",
        "inputs": [
            {"name": "recorderId", "type": "bytes32"},
            {"name": "epochNo", "type": "uint64"},
            {"name": "root", "type": "bytes32"},
            {"name": "treeSize", "type": "uint64"},
            {"name": "lastSeq", "type": "uint64"},
        ],
        "outputs": [],
    },
    {
        "type": "function",
        "name": "getAnchor",
        "stateMutability": "view",
        "inputs": [
            {"name": "recorderId", "type": "bytes32"},
            {"name": "epochNo", "type": "uint64"},
        ],
        "outputs": [
            {"name": "root", "type": "bytes32"},
            {"name": "treeSize", "type": "uint64"},
            {"name": "lastSeq", "type": "uint64"},
            {"name": "timestamp", "type": "uint64"},
            {"name": "blockNumber", "type": "uint64"},
        ],
    },
    {
        "type": "function",
        "name": "nextEpoch",
        "stateMutability": "view",
        "inputs": [{"name": "recorderId", "type": "bytes32"}],
        "outputs": [{"name": "nextEpochNo", "type": "uint64"}],
    },
    {
        "type": "function",
        "name": "submitterOf",
        "stateMutability": "view",
        "inputs": [{"name": "recorderId", "type": "bytes32"}],
        "outputs": [{"name": "submitter", "type": "address"}],
    },
    {
        "type": "function",
        "name": "registerRecorder",
        "stateMutability": "nonpayable",
        "inputs": [
            {"name": "recorderId", "type": "bytes32"},
            {"name": "submitter", "type": "address"},
        ],
        "outputs": [],
    },
    {
        "type": "function",
        "name": "owner",
        "stateMutability": "view",
        "inputs": [],
        "outputs": [{"name": "", "type": "address"}],
    },
    {
        "type": "event",
        "name": "Anchored",
        "anonymous": False,
        "inputs": [
            {"name": "recorderId", "type": "bytes32", "indexed": True},
            {"name": "epochNo", "type": "uint64", "indexed": True},
            {"name": "root", "type": "bytes32", "indexed": False},
            {"name": "treeSize", "type": "uint64", "indexed": False},
            {"name": "lastSeq", "type": "uint64", "indexed": False},
        ],
    },
]

_TRANSPORT_ERRORS = (
    requests.exceptions.RequestException,
    ConnectionError,
    TimeoutError,
    OSError,
)


def _rpc[T](fn: Callable[[], T]) -> T:
    """Transport failures -> AnchorRpcError. Answers (not found, revert, JSON-RPC errors)
    propagate unchanged so callers can tell "unreachable" from "no such thing"."""
    try:
        return fn()
    except (*_TRANSPORT_ERRORS, ProviderConnectionError, TimeExhausted) as exc:
        raise AnchorRpcError(type(exc).__name__) from None


class EvmAnchorBackend:
    def __init__(
        self,
        *,
        rpc_url: str,
        chain_id: int,
        contract: str,
        private_key: str | bytes | None = None,
        gas_limit: int = 200_000,
        timeout_seconds: float = 10.0,
    ) -> None:
        self.w3 = Web3(HTTPProvider(rpc_url, request_kwargs={"timeout": timeout_seconds}))
        self.chain_id = int(chain_id)
        self.contract = contract.lower()
        self._contract = self.w3.eth.contract(
            address=Web3.to_checksum_address(contract), abi=EPOCH_ANCHOR_ABI
        )
        self._account = Account.from_key(private_key) if private_key is not None else None
        self.submitter = self._account.address.lower() if self._account else ""
        self._gas_limit = gas_limit
        self._verified = False

    def __repr__(self) -> str:  # never include the key
        return f"EvmAnchorBackend(chain_id={self.chain_id}, contract={self.contract})"

    # ---------------------------------------------------------------- pinning
    def verify_pins(self) -> None:
        """The node must be on the pinned chain and the pinned address must hold code."""
        if self._verified:
            return
        got = _rpc(lambda: self.w3.eth.chain_id)
        if got != self.chain_id:
            raise AnchorConfigError(f"RPC chain id {got} != pinned {self.chain_id}")
        code = _rpc(lambda: self.w3.eth.get_code(self._contract.address))
        if not code:
            raise AnchorConfigError("no contract code at the pinned address")
        self._verified = True

    # ---------------------------------------------------------------- reads
    def next_epoch(self, recorder_id: bytes) -> int:
        self.verify_pins()
        return int(_rpc(lambda: self._contract.functions.nextEpoch(recorder_id).call()))

    def get_anchor(self, recorder_id: bytes, epoch_no: int) -> OnChainAnchor | None:
        self.verify_pins()
        root, size, last, ts, bn = _rpc(
            lambda: self._contract.functions.getAnchor(recorder_id, epoch_no).call()
        )
        if bytes(root) == ZERO32:
            return None
        return OnChainAnchor(bytes(root), int(size), int(last), int(ts), int(bn))

    def submitter_of(self, recorder_id: bytes) -> str:
        self.verify_pins()
        return str(_rpc(lambda: self._contract.functions.submitterOf(recorder_id).call())).lower()

    def pending_nonce(self) -> int:
        return int(_rpc(lambda: self.w3.eth.get_transaction_count(self._address(), "pending")))

    def confirmed_nonce(self) -> int:
        return int(_rpc(lambda: self.w3.eth.get_transaction_count(self._address(), "latest")))

    def head_block(self) -> int:
        return int(_rpc(lambda: self.w3.eth.block_number))

    def final_block(self, finality: Finality) -> int:
        if finality.kind in ("safe", "finalized"):
            try:
                tag: BlockIdentifier = "safe" if finality.kind == "safe" else "finalized"
                block = _rpc(lambda: self.w3.eth.get_block(tag))
            except Web3RPCError:
                return -1  # node does not know the tag yet: nothing is final
            return int(block["number"])
        return finality.final_block(self.head_block())

    def block_hash(self, number: int) -> bytes | None:
        try:
            block = _rpc(lambda: self.w3.eth.get_block(number))
        except BlockNotFound:
            return None  # beyond the head (e.g. after a reorg to a shorter chain)
        return bytes(block["hash"])

    def receipt(self, tx_hash: bytes) -> Receipt | None:
        try:
            r = _rpc(lambda: self.w3.eth.get_transaction_receipt(HexBytes(tx_hash)))
        except TransactionNotFound:
            return None
        return Receipt(
            succeeded=int(r["status"]) == 1,
            block_number=int(r["blockNumber"]),
            block_hash=bytes(r["blockHash"]),
            gas_used=int(r["gasUsed"]),
            effective_gas_price=int(r.get("effectiveGasPrice", 0)),
        )

    def is_known(self, tx_hash: bytes) -> bool:
        try:
            _rpc(lambda: self.w3.eth.get_transaction(HexBytes(tx_hash)))
        except TransactionNotFound:
            return False
        return True

    # ---------------------------------------------------------------- writes
    def sign_anchor(self, item: AnchorItem, nonce: int) -> SignedSubmission:
        if self._account is None:
            raise AnchorConfigError("no submitter key configured")
        self.verify_pins()
        latest = _rpc(lambda: self.w3.eth.get_block("latest"))
        base = int(latest.get("baseFeePerGas", 0))
        prio = int(_rpc(lambda: self.w3.eth.max_priority_fee))
        tx = self._contract.functions.anchor(
            item.recorder_id, item.epoch_no, item.root, item.tree_size, item.last_seq
        ).build_transaction(
            {  # type: ignore[arg-type]
                "chainId": self.chain_id,
                "from": self._account.address,
                "nonce": nonce,
                "gas": self._gas_limit,
                "maxFeePerGas": 2 * base + prio,
                "maxPriorityFeePerGas": prio,
            }
        )
        signed = self._account.sign_transaction(tx)
        return SignedSubmission(bytes(signed.hash), bytes(signed.raw_transaction), nonce)

    def broadcast(self, raw: bytes) -> str:
        try:
            _rpc(lambda: self.w3.eth.send_raw_transaction(raw))
        except Web3RPCError as exc:
            msg = str(exc).lower()
            if "already known" in msg or "already imported" in msg:
                return "KNOWN"
            if "nonce too low" in msg or "nonce has already been used" in msg:
                return "NONCE_USED"
            raise AnchorRpcError("SEND_REJECTED") from None
        return "SENT"

    def _address(self) -> ChecksumAddress:
        if self._account is None:
            raise AnchorConfigError("no submitter key configured")
        return Web3.to_checksum_address(self._account.address)


# ------------------------------------------------------------------ admin helpers (owner key)
def deploy(rpc_url: str, artifact: dict[str, Any], owner_key: str) -> tuple[str, Any]:
    """Deploy EpochAnchor from the committed artifact (tests and the dev demo). Returns
    (address, receipt). Production deployments use contracts/script/Deploy.s.sol."""
    w3 = Web3(HTTPProvider(rpc_url))
    acct = Account.from_key(owner_key)
    factory = w3.eth.contract(abi=artifact["abi"], bytecode=artifact["bytecode"])
    tx = factory.constructor().build_transaction(
        {
            "from": acct.address,
            "nonce": w3.eth.get_transaction_count(acct.address, "pending"),
            "chainId": w3.eth.chain_id,
        }
    )
    tx_hash = w3.eth.send_raw_transaction(acct.sign_transaction(tx).raw_transaction)
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=60)
    return str(receipt["contractAddress"]).lower(), receipt


def register_recorder(
    rpc_url: str, contract: str, owner_key: str, recorder_id: bytes, submitter: str
) -> Any:
    w3 = Web3(HTTPProvider(rpc_url))
    acct = Account.from_key(owner_key)
    c = w3.eth.contract(address=Web3.to_checksum_address(contract), abi=EPOCH_ANCHOR_ABI)
    tx = c.functions.registerRecorder(
        recorder_id, Web3.to_checksum_address(submitter)
    ).build_transaction(
        {
            "from": acct.address,
            "nonce": w3.eth.get_transaction_count(acct.address, "pending"),
            "chainId": w3.eth.chain_id,
        }
    )
    tx_hash = w3.eth.send_raw_transaction(acct.sign_transaction(tx).raw_transaction)
    return w3.eth.wait_for_transaction_receipt(tx_hash, timeout=60)
