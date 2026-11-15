"""Independent verifier Merkle implementation vs the same frozen vectors."""

import json
from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from agw_verifier.merkle import epoch_root, h_leaf, inclusion_ok, root_of

pytestmark = pytest.mark.unit
V = Path(__file__).resolve().parents[2] / "schemas/test-vectors/merkle"


@pytest.mark.parametrize("n", (1, 2, 3, 4, 5, 7, 8))
def test_tree_vectors(n: int) -> None:
    vec = json.loads((V / f"merkle-{n}.json").read_text())
    leaves = [bytes.fromhex(x) for x in vec["leaf_inputs"]]
    assert [h_leaf(x).hex() for x in leaves] == vec["leaf_hashes"]
    assert root_of(leaves).hex() == vec["root"]
    root = bytes.fromhex(vec["root"])
    for p in vec["proofs"]:
        i = p["leaf_index"]
        assert inclusion_ok(leaves[i], i, n, [bytes.fromhex(x) for x in p["audit_path"]], root)


def test_negative_and_epoch_vectors() -> None:
    for c in json.loads((V / "merkle-negative.json").read_text())["must_fail"]:
        assert not inclusion_ok(
            bytes.fromhex(c["leaf_input"]),
            c["leaf_index"],
            c["tree_size"],
            [bytes.fromhex(p) for p in c["audit_path"]],
            bytes.fromhex(c["root"]),
        ), c["name"]
    for e in json.loads((V / "epoch-root.json").read_text())["epochs"]:
        assert (
            epoch_root(
                e["tenant"],
                e["epoch_no"],
                e["tree_size"],
                e["first_seq"],
                e["last_seq"],
                bytes.fromhex(e["merkle_root"]),
                bytes.fromhex(e["prev_root"]),
            ).hex()
            == e["epoch_root"]
        )
    with pytest.raises(ValueError):
        root_of([])


@settings(max_examples=200, deadline=None)
@given(st.integers(1, 64))
def test_stack_root_equals_recursive_definition(n: int) -> None:
    import hashlib

    leaves = [hashlib.sha256(bytes([k % 256, k // 256])).digest() for k in range(n)]

    def mth(xs: list[bytes]) -> bytes:
        if len(xs) == 1:
            return h_leaf(xs[0])
        k = 1 << ((len(xs) - 1).bit_length() - 1)
        return hashlib.sha256(b"\x01" + mth(xs[:k]) + mth(xs[k:])).digest()

    assert root_of(leaves) == mth(leaves)


def test_subtree_root_with_truncated_path_is_rejected() -> None:
    """Claiming the root of a SUBTREE (with a truncated path) for a bigger tree must fail:
    the final sn == 0 check catches it even though the hashes line up."""
    leaves = [bytes([i]) * 32 for i in range(4)]
    h = [h_leaf(x) for x in leaves]
    import hashlib

    subtree = hashlib.sha256(b"\x01" + h[0] + h[1]).digest()
    assert not inclusion_ok(leaves[0], 0, 4, [h[1]], subtree)


def test_epoch_reparented_onto_other_prev_is_tampered() -> None:
    """An attacker re-roots epoch 1 onto a different prev_root and recomputes R_1 and R_2
    consistently: only the prev-root link exposes it when no trust root is given."""
    from agw_verifier.epochs import verify_epochs

    chain = json.loads((V / "epoch-root.json").read_text())["epochs"]
    recs = [
        {
            k: e[k]
            for k in (
                "tenant",
                "epoch_no",
                "tree_size",
                "first_seq",
                "last_seq",
                "merkle_root",
                "prev_root",
                "epoch_root",
            )
        }
        for e in chain
    ]
    meta = json.dumps({"format": "agw-epochs/v1", "tenant": "acme"})
    assert verify_epochs([meta, *map(json.dumps, recs)]).result == "UNANCHORED"
    recs[1]["prev_root"] = "ab" * 32
    prev = None
    for r in recs[1:]:
        if prev is not None:
            r["prev_root"] = prev
        r["epoch_root"] = epoch_root(
            r["tenant"],
            r["epoch_no"],
            r["tree_size"],
            r["first_seq"],
            r["last_seq"],
            bytes.fromhex(r["merkle_root"]),
            bytes.fromhex(r["prev_root"]),
        ).hex()
        prev = r["epoch_root"]
    res = verify_epochs([meta, *map(json.dumps, recs)])
    assert (res.result, res.reason, res.first_bad_epoch) == (
        "TAMPERED",
        "EPOCH_PREV_ROOT_MISMATCH",
        1,
    )
