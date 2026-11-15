"""RFC 9162 §2.1 Merkle trees and AGW epoch roots (docs/gateway/06 §6-7, ADR-0007). Pure.

* leaf_hash(x) = SHA256(0x00 || x), node_hash(l, r) = SHA256(0x01 || l || r)
* split at the largest power of two strictly less than n; the last leaf is NEVER duplicated
  (Paper B's duplication makes [a,b,c] and [a,b,c,c] share a root - rejected)
* n = 0 is rejected: an epoch is never empty
* the leaf input is the 32-byte event_hash

The verifier (packages/verifier) re-implements all of this independently; both are checked
against the frozen vectors in packages/schemas/test-vectors/merkle/.
"""

from __future__ import annotations

import hashlib
from collections.abc import Sequence
from typing import Final

from agw_gateway.crypto.tags import domain_tag

EPOCH_TAG: Final = "AGW/epoch/v1"
_EPOCH_PREFIX: Final = domain_tag(EPOCH_TAG)
ZERO32: Final = bytes(32)


class MerkleError(ValueError):
    pass


def leaf_hash(leaf_input: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + leaf_input).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def _split(n: int) -> int:
    """Largest power of two strictly less than n (n >= 2)."""
    return 1 << ((n - 1).bit_length() - 1)


def merkle_root(leaves: Sequence[bytes]) -> bytes:
    """MTH(D[n]) over leaf inputs. n >= 1."""
    if not leaves:
        raise MerkleError("empty tree: epochs are never empty")
    return _mth([leaf_hash(x) for x in leaves])


def _mth(hashes: Sequence[bytes]) -> bytes:
    if len(hashes) == 1:
        return hashes[0]
    k = _split(len(hashes))
    return node_hash(_mth(hashes[:k]), _mth(hashes[k:]))


def audit_path(index: int, leaves: Sequence[bytes]) -> list[bytes]:
    """RFC 9162 §2.1.3.1 PATH(m, D[n]), leaf-to-root order."""
    n = len(leaves)
    if n == 0 or not 0 <= index < n:
        raise MerkleError("leaf index out of range")
    return _path(index, [leaf_hash(x) for x in leaves])


def _path(m: int, hashes: Sequence[bytes]) -> list[bytes]:
    n = len(hashes)
    if n == 1:
        return []
    k = _split(n)
    if m < k:
        return [*_path(m, hashes[:k]), _mth(hashes[k:])]
    return [*_path(m - k, hashes[k:]), _mth(hashes[:k])]


def verify_inclusion(
    leaf_input: bytes, leaf_index: int, tree_size: int, path: Sequence[bytes], root: bytes
) -> bool:
    """RFC 9162 §2.1.3.2. tree_size MUST come from the authenticated epoch header (06 §6.3)."""
    if tree_size < 1 or not 0 <= leaf_index < tree_size:
        return False
    if any(len(p) != 32 for p in path):
        return False
    fn, sn = leaf_index, tree_size - 1
    r = leaf_hash(leaf_input)
    for p in path:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            r = node_hash(p, r)
            while not fn & 1 and fn != 0:
                fn >>= 1
                sn >>= 1
        else:
            r = node_hash(r, p)
        fn >>= 1
        sn >>= 1
    return sn == 0 and r == root


def epoch_root_input(
    tenant: str,
    epoch_no: int,
    tree_size: int,
    first_seq: int,
    last_seq: int,
    merkle_root_: bytes,
    prev_root: bytes,
) -> bytes:
    """Exact byte layout of 06 §7 (111 + len(tenant) bytes)."""
    t = tenant.encode("utf-8")
    if not 1 <= len(t) <= 63:
        raise MerkleError("tenant id length out of range")
    if tree_size != last_seq - first_seq + 1 or tree_size < 1:
        raise MerkleError("tree_size must equal last_seq - first_seq + 1 >= 1")
    if len(merkle_root_) != 32 or len(prev_root) != 32:
        raise MerkleError("roots are 32 bytes")
    return (
        _EPOCH_PREFIX
        + len(t).to_bytes(2, "big")
        + t
        + epoch_no.to_bytes(8, "big")
        + tree_size.to_bytes(8, "big")
        + first_seq.to_bytes(8, "big")
        + last_seq.to_bytes(8, "big")
        + merkle_root_
        + prev_root
    )


def epoch_root(
    tenant: str,
    epoch_no: int,
    tree_size: int,
    first_seq: int,
    last_seq: int,
    merkle_root_: bytes,
    prev_root: bytes,
) -> bytes:
    """R_t = H(TAG("AGW/epoch/v1") || u16 len || tenant || u64 epoch_no || u64 tree_size ||
    u64 first_seq || u64 last_seq || M_t || R_{t-1}); R_{-1} = ZERO32."""
    return hashlib.sha256(
        epoch_root_input(tenant, epoch_no, tree_size, first_seq, last_seq, merkle_root_, prev_root)
    ).digest()
