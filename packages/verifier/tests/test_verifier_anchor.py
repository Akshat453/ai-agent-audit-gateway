"""Verifier chain checks against a scripted JSON-RPC node (stdlib only; no web3, no Anvil).

Covers the paths the Anvil e2e tests do not: the ``finalized`` block tag, anchors that exist
but are not final, epochs not anchored at all, and an anchored prefix with an unanchored tail.
"""

from __future__ import annotations

import json
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

import pytest

from agw_verifier.anchor import (
    SEL_GET_ANCHOR,
    SEL_NEXT_EPOCH,
    ChainView,
    Rpc,
    check_against_chain,
    make_trust,
)
from agw_verifier.epochs import Result

CONTRACT = "0x" + "ab" * 20
RID = bytes.fromhex("11" * 32)
CODE = bytes.fromhex("6080604052")


class FakeChain:
    """anchors: epoch -> (root hex, tree_size, last_seq, block). latest/finalized: heights."""

    def __init__(self) -> None:
        self.chain_id = 84532
        self.latest = 100
        self.finalized = 50
        self.anchors: dict[int, tuple[str, int, int, int]] = {}

    def answer(self, method: str, params: list[Any]) -> Any:
        if method == "eth_chainId":
            return hex(self.chain_id)
        if method == "eth_getCode":
            return "0x" + CODE.hex()
        if method == "eth_blockNumber":
            return hex(self.latest)
        if method == "eth_getBlockByNumber":
            return {"number": hex(self.finalized if params[0] == "finalized" else self.latest)}
        if method == "eth_call":
            data, block = params[0]["data"][2:], int(params[1], 16)
            visible = {e: a for e, a in self.anchors.items() if a[3] <= block}
            if data.startswith(SEL_NEXT_EPOCH):
                n = max(visible) + 1 if visible else 0
                return "0x" + n.to_bytes(32, "big").hex()
            assert data.startswith(SEL_GET_ANCHOR)
            epoch = int(data[8 + 64 :], 16)
            if epoch not in visible:
                return "0x" + "00" * 160
            root, size, last, bn = visible[epoch]
            words = [bytes.fromhex(root)] + [v.to_bytes(32, "big") for v in (size, last, 0, bn)]
            return "0x" + b"".join(words).hex()
        raise AssertionError(method)


@pytest.fixture
def node() -> Iterator[tuple[FakeChain, str]]:
    chain = FakeChain()

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args: Any) -> None:
            pass

        def do_POST(self) -> None:
            req = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            body = json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": req["id"],
                    "result": chain.answer(req["method"], req["params"]),
                }
            ).encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        yield chain, f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        server.server_close()


def records(n: int) -> list[dict[str, Any]]:
    return [
        {"epoch_no": i, "epoch_root": f"{i + 1:064x}", "tree_size": 2, "last_seq": 2 * i + 1}
        for i in range(n)
    ]


def view(url: str, finality: str = "finalized", **kw: Any) -> ChainView:
    return ChainView(Rpc(url), make_trust(84532, CONTRACT, RID.hex(), finality, **kw))


def run(v: ChainView, recs: list[dict[str, Any]], *, min_epoch: int | None) -> Result:
    res = Result(result="UNANCHORED")
    out: Result = check_against_chain(
        res, recs, v, min_epoch=min_epoch, whole_export=min_epoch is None
    )
    return out


def test_finalized_tag_verifies_and_reports_the_anchor(node: tuple[FakeChain, str]) -> None:
    chain, url = node
    recs = records(3)
    for r in recs:
        chain.anchors[r["epoch_no"]] = (r["epoch_root"], 2, r["last_seq"], 10 + r["epoch_no"])
    res = run(view(url), recs, min_epoch=1)
    assert res.result == "VERIFIED" and res.trusted_epoch == 1
    assert res.anchor == {
        "epoch_no": 1, "block_number": 11, "timestamp": 0, "final_block": 50,
        "finality": "finalized",
    }  # fmt: skip
    assert run(view(url), recs, min_epoch=None).result == "VERIFIED"


def test_anchored_but_not_final(node: tuple[FakeChain, str]) -> None:
    chain, url = node
    recs = records(1)
    chain.anchors[0] = (recs[0]["epoch_root"], 2, 1, 80)  # above the finalized block (50)
    res = run(view(url), recs, min_epoch=0)
    assert (res.result, res.reason) == ("UNANCHORED", "ANCHOR_NOT_FINAL")
    assert run(view(url, "latest"), recs, min_epoch=0).result == "VERIFIED"
    assert run(view(url, "confirmations:21"), recs, min_epoch=0).result == "VERIFIED"
    assert run(view(url, "confirmations:22"), recs, min_epoch=0).reason == "ANCHOR_NOT_FINAL"


def test_not_anchored_and_unanchored_tail(node: tuple[FakeChain, str]) -> None:
    chain, url = node
    recs = records(3)
    assert run(view(url), recs, min_epoch=0).reason == "NOT_ANCHORED"
    chain.anchors[0] = (recs[0]["epoch_root"], 2, 1, 10)
    res = run(view(url), recs, min_epoch=None)
    assert (res.result, res.reason, res.trusted_epoch) == ("UNANCHORED", "TAIL_NOT_ANCHORED", 0)
    # an event in epoch 2 is covered only by an anchor of epoch >= 2
    assert run(view(url), recs, min_epoch=2).reason == "NOT_ANCHORED"


def test_mismatches(node: tuple[FakeChain, str]) -> None:
    chain, url = node
    recs = records(2)
    chain.anchors[0] = (recs[0]["epoch_root"], 3, 1, 10)  # tree size differs
    res = run(view(url), recs, min_epoch=0)
    assert (res.result, res.reason, res.first_bad_epoch) == ("TAMPERED", "ANCHOR_ROOT_MISMATCH", 0)
    chain.anchors[0] = (recs[0]["epoch_root"], 2, 1, 10)
    chain.chain_id = 1
    assert run(view(url), recs, min_epoch=0).reason == "RPC_CHAIN_ID_MISMATCH"
    chain.chain_id = 84532
    bad = view(url, code_sha256="00" * 32)
    assert run(bad, recs, min_epoch=0).reason == "CONTRACT_CODE_MISMATCH"
