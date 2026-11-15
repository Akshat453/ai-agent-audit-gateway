"""Independent RFC 9162 + AGW epoch-root implementation for the verifier (06 §6-7).

Written separately from the gateway (bottom-up stack construction here, recursive there);
the two meet only in the frozen vectors.
"""

from __future__ import annotations

import hashlib
import struct
from collections.abc import Sequence

ZERO32 = bytes(32)
_EPOCH_TAG = b"\x0cAGW/epoch/v1"


def h_leaf(x: bytes) -> bytes:
    return hashlib.sha256(bytes([0]) + x).digest()


def h_node(a: bytes, b: bytes) -> bytes:
    return hashlib.sha256(bytes([1]) + a + b).digest()


def root_of(leaves: Sequence[bytes]) -> bytes:
    """MTH via a stack of perfect subtrees (equivalent to the RFC's recursive split)."""
    if not leaves:
        raise ValueError("empty tree")
    stack: list[tuple[int, bytes]] = []  # (subtree size, hash)
    for x in leaves:
        stack.append((1, h_leaf(x)))
        while len(stack) >= 2 and stack[-1][0] == stack[-2][0]:
            (s2, b), (_, a) = stack.pop(), stack.pop()
            stack.append((2 * s2, h_node(a, b)))
    acc = stack.pop()[1]
    while stack:  # fold the remaining (decreasing) perfect subtrees right-to-left
        acc = h_node(stack.pop()[1], acc)
    return acc


def inclusion_ok(
    leaf_input: bytes, index: int, size: int, path: Sequence[bytes], expected_root: bytes
) -> bool:
    """RFC 9162 §2.1.3.2 verification."""
    if size <= 0 or index < 0 or index >= size:
        return False
    fn, sn, r = index, size - 1, h_leaf(leaf_input)
    for p in path:
        if len(p) != 32 or sn == 0:
            return False
        if fn % 2 == 1 or fn == sn:
            r = h_node(p, r)
            while fn % 2 == 0 and fn != 0:
                fn //= 2
                sn //= 2
        else:
            r = h_node(r, p)
        fn //= 2
        sn //= 2
    return sn == 0 and r == expected_root


def epoch_root(
    tenant: str,
    epoch_no: int,
    tree_size: int,
    first_seq: int,
    last_seq: int,
    merkle_root: bytes,
    prev_root: bytes,
) -> bytes:
    t = tenant.encode()
    data = (
        _EPOCH_TAG
        + struct.pack(">H", len(t))
        + t
        + struct.pack(">QQQQ", epoch_no, tree_size, first_seq, last_seq)
        + merkle_root
        + prev_root
    )
    return hashlib.sha256(data).digest()
