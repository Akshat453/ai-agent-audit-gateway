"""Generates the Phase 3 Merkle + epoch vectors (06 §9). Run once, review, commit; then FROZEN.

    uv run python packages/schemas/test-vectors/generate_phase3.py --check

Cross-checks: every value is produced by the gateway implementation (agw_gateway.crypto.merkle)
AND must be reproduced by the independent verifier implementation (agw_verifier.merkle); the
script aborts on any disagreement. ``--check`` fails on any difference from committed files.
"""

from __future__ import annotations

import hashlib
import json
import struct
import sys
from pathlib import Path
from typing import Any

from agw_gateway.crypto import merkle as G
from agw_verifier import merkle as V

HERE = Path(__file__).parent / "merkle"
EVENT_TAG = b"\x0cAGW/event/v1"
SIZES = (1, 2, 3, 4, 5, 7, 8)


def leaf_input(i: int) -> bytes:
    """Deterministic, documented leaf inputs: H(TAG("AGW/event/v1") || u64(i))."""
    return hashlib.sha256(EVENT_TAG + struct.pack(">Q", i)).digest()


def tree_vector(n: int) -> dict[str, Any]:
    leaves = [leaf_input(i) for i in range(n)]
    root = G.merkle_root(leaves)
    assert root == V.root_of(leaves), n
    proofs = []
    for i in range(n):
        path = G.audit_path(i, leaves)
        assert V.inclusion_ok(leaves[i], i, n, path, root), (n, i)
        proofs.append({"leaf_index": i, "audit_path": [p.hex() for p in path]})
    return {
        "tree_size": n,
        "leaf_inputs": [x.hex() for x in leaves],
        "leaf_hashes": [G.leaf_hash(x).hex() for x in leaves],
        "root": root.hex(),
        "proofs": proofs,
    }


def negative() -> dict[str, Any]:
    leaves5 = [leaf_input(i) for i in range(5)]
    r5 = G.merkle_root(leaves5)
    p2 = G.audit_path(2, leaves5)
    cases = [
        ("wrong index", leaves5[2], 3, 5, p2, r5),
        ("index >= tree_size", leaves5[2], 5, 5, p2, r5),
        ("truncated path", leaves5[2], 2, 5, p2[:-1], r5),
        ("extra path element", leaves5[2], 2, 5, [*p2, bytes(32)], r5),
        ("swapped siblings", leaves5[2], 2, 5, list(reversed(p2)), r5),
        ("leaf presented already hashed (no 0x00)", G.leaf_hash(leaves5[2]), 2, 5, p2, r5),
        ("wrong leaf", leaves5[1], 2, 5, p2, r5),
        ("wrong root", leaves5[2], 2, 5, p2, bytes(32)),
        ("tree_size 0", leaves5[2], 0, 0, p2, r5),
    ]
    # second preimage: an interior node presented as a leaf (64-byte l0||l1)
    l4 = [leaf_input(i) for i in range(4)]
    lh = [G.leaf_hash(x) for x in l4]
    r4 = G.merkle_root(l4)
    cases.append(
        (
            "interior node as leaf (second preimage)",
            lh[0] + lh[1],
            0,
            2,
            [G.node_hash(lh[2], lh[3])],
            r4,
        )
    )
    out = []
    for name, leaf, idx, size, path, root in cases:
        assert not G.verify_inclusion(leaf, idx, size, path, root), name
        assert not V.inclusion_ok(leaf, idx, size, path, root), name
        out.append(
            {
                "name": name,
                "leaf_input": leaf.hex(),
                "leaf_index": idx,
                "tree_size": size,
                "audit_path": [p.hex() for p in path],
                "root": root.hex(),
            }
        )
    # Paper B last-leaf duplication: [a,b,c] -> same root as [a,b,c,c]; RFC 9162 differs
    a3 = [leaf_input(i) for i in range(3)]
    h3 = [G.leaf_hash(x) for x in a3]
    paper_b_3 = G.node_hash(G.node_hash(h3[0], h3[1]), G.node_hash(h3[2], h3[2]))
    paper_b_4 = G.node_hash(G.node_hash(h3[0], h3[1]), G.node_hash(h3[2], h3[2]))
    rfc3, rfc4 = G.merkle_root(a3), G.merkle_root([*a3, a3[2]])
    assert paper_b_3 == paper_b_4
    assert rfc3 not in (rfc4, paper_b_3)
    return {
        "must_fail": out,
        "duplicate_last_leaf": {
            "leaves_abc": [x.hex() for x in a3],
            "paper_b_root_abc": paper_b_3.hex(),
            "paper_b_root_abcc": paper_b_4.hex(),
            "rfc9162_root_abc": rfc3.hex(),
            "rfc9162_root_abcc": rfc4.hex(),
            "note": "Paper B duplication gives one root for [a,b,c] and [a,b,c,c]; RFC 9162 does not.",
        },
    }


def raw_epoch_input(
    tenant: str, no: int, size: int, first: int, last: int, m: bytes, prev: bytes
) -> bytes:
    t = tenant.encode()
    return (
        b"\x0cAGW/epoch/v1"
        + struct.pack(">H", len(t))
        + t
        + struct.pack(">QQQQ", no, size, first, last)
        + m
        + prev
    )


def epochs() -> tuple[dict[str, Any], dict[str, Any]]:
    tenant, specs = "acme", [(0, 0), (1, 5), (6, 13)]
    prev, chain = bytes(32), []
    for no, (first, last) in enumerate(specs):
        leaves = [leaf_input(s) for s in range(first, last + 1)]
        m = G.merkle_root(leaves)
        size = last - first + 1
        data = G.epoch_root_input(tenant, no, size, first, last, m, prev)
        assert data == raw_epoch_input(tenant, no, size, first, last, m, prev)
        assert len(data) == 111 + len(tenant)
        r = G.epoch_root(tenant, no, size, first, last, m, prev)
        assert (
            r
            == V.epoch_root(tenant, no, size, first, last, m, prev)
            == hashlib.sha256(data).digest()
        )
        chain.append(
            {
                "tenant": tenant,
                "epoch_no": no,
                "tree_size": size,
                "first_seq": first,
                "last_seq": last,
                "merkle_root": m.hex(),
                "prev_root": prev.hex(),
                "hash_input": data.hex(),
                "epoch_root": r.hex(),
            }
        )
        prev = r
    base = chain[1]
    m, p = bytes.fromhex(base["merkle_root"]), bytes.fromhex(base["prev_root"])
    muts = {
        "tenant": ("acmf", 1, 5, 1, 5, m, p),
        "epoch_no": ("acme", 2, 5, 1, 5, m, p),
        "tree_size": ("acme", 1, 4, 1, 5, m, p),
        "first_seq": ("acme", 1, 5, 2, 6, m, p),
        "last_seq": ("acme", 1, 5, 1, 6, m, p),
        "merkle_root": ("acme", 1, 5, 1, 5, bytes(32), p),
        "prev_root": ("acme", 1, 5, 1, 5, m, bytes(32)),
    }
    neg = []
    for field, args in muts.items():
        data = raw_epoch_input(*args)
        r = hashlib.sha256(data).digest().hex()
        assert r != base["epoch_root"]
        neg.append({"mutated_field": field, "hash_input": data.hex(), "epoch_root": r})
    return (
        {
            "description": "3-epoch chain for tenant acme, leaf_input(seq) = H(0x0c'AGW/event/v1' || u64(seq))",
            "epochs": chain,
        },
        {"base_epoch_root": base["epoch_root"], "mutations": neg},
    )


def build() -> dict[str, Any]:
    files: dict[str, Any] = {f"merkle-{n}.json": tree_vector(n) for n in SIZES}
    files["merkle-negative.json"] = negative()
    files["epoch-root.json"], files["epoch-root-negative.json"] = epochs()
    files["tags.json"] = {
        t: (bytes([len(t)]) + t.encode()).hex()
        for t in (
            "AGW/event/v1",
            "AGW/payload/v1",
            "AGW/epoch/v1",
            "AGW/args/v1",
            "AGW/approval/v1",
            "AGW/tenant-key/v1",
            "AGW/request/v1",
            "AGW/apikey/v1",
            "AGW/bundle/v1",
        )
    }
    return files


def main() -> int:
    check, status = "--check" in sys.argv, 0
    for name, data in build().items():
        text = json.dumps(data, indent=1) + "\n"
        path = HERE / name
        if check:
            same = path.exists() and path.read_text() == text
            print(("ok   " if same else "DIFF ") + f"merkle/{name}")
            status |= not same
        else:
            path.write_text(text)
            print(f"wrote merkle/{name}")
    return status


if __name__ == "__main__":
    raise SystemExit(main())
