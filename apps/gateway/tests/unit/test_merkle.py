"""RFC 9162 Merkle + epoch roots (gateway implementation) vs frozen vectors; properties."""

import json
from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from agw_gateway.crypto.merkle import (
    MerkleError,
    audit_path,
    epoch_root,
    epoch_root_input,
    leaf_hash,
    merkle_root,
    node_hash,
    verify_inclusion,
)

pytestmark = pytest.mark.unit

V = Path(__file__).resolve().parents[4] / "packages/schemas/test-vectors/merkle"
SIZES = (1, 2, 3, 4, 5, 7, 8)


@pytest.mark.parametrize("n", SIZES)
def test_tree_vectors(n: int) -> None:
    vec = json.loads((V / f"merkle-{n}.json").read_text())
    leaves = [bytes.fromhex(x) for x in vec["leaf_inputs"]]
    assert [leaf_hash(x).hex() for x in leaves] == vec["leaf_hashes"]
    root = merkle_root(leaves)
    assert root.hex() == vec["root"]
    for p in vec["proofs"]:
        path = audit_path(p["leaf_index"], leaves)
        assert [x.hex() for x in path] == p["audit_path"]
        assert verify_inclusion(leaves[p["leaf_index"]], p["leaf_index"], n, path, root)


def test_negative_vectors_fail() -> None:
    neg = json.loads((V / "merkle-negative.json").read_text())
    for c in neg["must_fail"]:
        ok = verify_inclusion(
            bytes.fromhex(c["leaf_input"]),
            c["leaf_index"],
            c["tree_size"],
            [bytes.fromhex(p) for p in c["audit_path"]],
            bytes.fromhex(c["root"]),
        )
        assert not ok, c["name"]


def test_duplicate_last_leaf_ambiguity_is_avoided() -> None:
    d = json.loads((V / "merkle-negative.json").read_text())["duplicate_last_leaf"]
    abc = [bytes.fromhex(x) for x in d["leaves_abc"]]
    assert d["paper_b_root_abc"] == d["paper_b_root_abcc"]  # Paper B: one root for both lists
    assert merkle_root(abc).hex() == d["rfc9162_root_abc"]
    assert merkle_root([*abc, abc[2]]).hex() == d["rfc9162_root_abcc"]
    assert merkle_root(abc) != merkle_root([*abc, abc[2]])


def test_second_preimage_interior_node_as_leaf_fails() -> None:
    leaves = [bytes([i]) * 32 for i in range(4)]
    lh = [leaf_hash(x) for x in leaves]
    root = merkle_root(leaves)
    # Without domain separation, H(l0||l1) would equal the interior node and verify:
    fake_leaf = lh[0] + lh[1]
    assert not verify_inclusion(fake_leaf, 0, 2, [node_hash(lh[2], lh[3])], root)
    assert leaf_hash(fake_leaf) != node_hash(lh[0], lh[1])


def test_epoch_root_vectors_and_layout() -> None:
    chain = json.loads((V / "epoch-root.json").read_text())["epochs"]
    for e in chain:
        args = (
            e["tenant"],
            e["epoch_no"],
            e["tree_size"],
            e["first_seq"],
            e["last_seq"],
            bytes.fromhex(e["merkle_root"]),
            bytes.fromhex(e["prev_root"]),
        )
        assert epoch_root_input(*args).hex() == e["hash_input"]
        assert len(bytes.fromhex(e["hash_input"])) == 111 + len(e["tenant"])
        assert epoch_root(*args).hex() == e["epoch_root"]
    assert chain[0]["prev_root"] == "00" * 32
    assert all(chain[i]["prev_root"] == chain[i - 1]["epoch_root"] for i in (1, 2))
    neg = json.loads((V / "epoch-root-negative.json").read_text())
    assert all(m["epoch_root"] != neg["base_epoch_root"] for m in neg["mutations"])


def test_empty_and_invalid_inputs_rejected() -> None:
    with pytest.raises(MerkleError):
        merkle_root([])
    with pytest.raises(MerkleError):
        audit_path(0, [])
    with pytest.raises(MerkleError):
        audit_path(3, [b"a", b"b"])
    with pytest.raises(MerkleError):
        epoch_root("acme", 0, 2, 0, 0, bytes(32), bytes(32))  # size inconsistent
    with pytest.raises(MerkleError):
        epoch_root("", 0, 1, 0, 0, bytes(32), bytes(32))
    assert not verify_inclusion(b"x", 0, 0, [], bytes(32))
    assert not verify_inclusion(b"x", 0, 1, [b"short"], leaf_hash(b"x"))


def test_tree_size_alone_is_not_bound_by_the_proof() -> None:
    """06 §6.3: an RFC 9162 path can verify under other claimed sizes - which is why the
    verifier takes tree_size from the authenticated epoch header (bound into R_t)."""
    leaves = [bytes([i]) * 32 for i in range(5)]
    root, path = merkle_root(leaves), audit_path(0, leaves)
    assert [s for s in range(1, 9) if verify_inclusion(leaves[0], 0, s, path, root)] == [5, 6, 7, 8]


def _flip(b: bytes, bit: int) -> bytes:
    a = bytearray(b)
    a[bit // 8 % len(a)] ^= 1 << (bit % 8)
    return bytes(a)


@settings(max_examples=300, deadline=None)
@given(
    st.integers(1, 40).flatmap(lambda n: st.tuples(st.just(n), st.integers(0, n - 1))),
    st.integers(0, 255),
    st.data(),
)
def test_proofs_verify_and_any_bit_flip_fails(
    ni: tuple[int, int], bit: int, data: st.DataObject
) -> None:
    n, i = ni
    leaves = [bytes([k % 256, k // 256]) * 16 for k in range(n)]
    root, path = merkle_root(leaves), audit_path(i, leaves)
    assert verify_inclusion(leaves[i], i, n, path, root)
    assert not verify_inclusion(_flip(leaves[i], bit), i, n, path, root)
    assert not verify_inclusion(leaves[i], i, n, path, _flip(root, bit))
    if path:
        j = data.draw(st.integers(0, len(path) - 1))
        bad = list(path)
        bad[j] = _flip(bad[j], bit)
        assert not verify_inclusion(leaves[i], i, n, bad, root)
    other = i ^ (1 << data.draw(st.integers(0, 6)))
    if other != i:
        assert not verify_inclusion(leaves[i], other, n, path, root)


def test_subtree_root_with_truncated_path_is_rejected() -> None:
    leaves = [bytes([i]) * 32 for i in range(4)]
    lh = [leaf_hash(x) for x in leaves]
    assert not verify_inclusion(leaves[0], 0, 4, [lh[1]], node_hash(lh[0], lh[1]))
