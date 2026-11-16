"""``AnchorBackend``: what the anchor worker needs from an external, append-only commitment
log (ADR-0028 §6). Phase 6 ships one implementation, ``EvmAnchorBackend`` (EpochAnchor.sol).

The interface is shaped around an ordered log with inclusion and finality:

* ``next_epoch`` / ``get_anchor``: what the log already holds for a recorder (idempotency and
  equivocation checks read these, never our own database);
* ``sign_anchor`` -> ``broadcast``: a submission is prepared as immutable bytes FIRST (stored
  write-ahead in ``anchors.raw_tx``), so a retry after a crash, a dropped transaction or a
  reorg re-sends exactly the same root;
* ``receipt`` / ``block_hash`` / ``final_block``: inclusion, canonicality and finality.

A later non-chain backend (an RFC 3161 TSA or a transparency log) maps onto the same calls:
its "nonce" is a request counter, "inclusion" is the signed timestamp token / log inclusion
proof, and finality is immediate (TSA) or the log's signed tree head (transparency log).
Every transport failure is raised as ``AnchorRpcError`` so the worker can back off.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from agw_gateway.anchoring import Finality

ZERO32 = bytes(32)


class AnchorRpcError(Exception):
    """The backend is unreachable or timed out (retry with backoff)."""


class AnchorConfigError(Exception):
    """The backend is reachable but is not the pinned one (wrong chain id / contract)."""


@dataclass(frozen=True)
class AnchorItem:
    recorder_id: bytes
    epoch_no: int
    root: bytes
    tree_size: int
    last_seq: int


@dataclass(frozen=True)
class OnChainAnchor:
    root: bytes
    tree_size: int
    last_seq: int
    timestamp: int
    block_number: int

    def matches(self, item: AnchorItem) -> bool:
        return (
            self.root == item.root
            and self.tree_size == item.tree_size
            and self.last_seq == item.last_seq
        )


@dataclass(frozen=True)
class SignedSubmission:
    tx_hash: bytes
    raw: bytes
    nonce: int


@dataclass(frozen=True)
class Receipt:
    succeeded: bool
    block_number: int
    block_hash: bytes
    gas_used: int
    effective_gas_price: int


class AnchorBackend(Protocol):
    chain_id: int
    contract: str  # lower-case 0x address
    submitter: str  # lower-case 0x address of the signing key

    def next_epoch(self, recorder_id: bytes) -> int: ...

    def get_anchor(self, recorder_id: bytes, epoch_no: int) -> OnChainAnchor | None: ...

    def submitter_of(self, recorder_id: bytes) -> str: ...

    def pending_nonce(self) -> int: ...

    def confirmed_nonce(self) -> int: ...

    def sign_anchor(self, item: AnchorItem, nonce: int) -> SignedSubmission: ...

    def broadcast(self, raw: bytes) -> str:
        """Returns SENT | KNOWN (already in the pool/chain) | NONCE_USED."""
        ...

    def receipt(self, tx_hash: bytes) -> Receipt | None: ...

    def is_known(self, tx_hash: bytes) -> bool: ...

    def head_block(self) -> int: ...

    def final_block(self, finality: Finality) -> int: ...

    def block_hash(self, number: int) -> bytes | None: ...
