"""Generates the Phase 2 vectors (run once, review, commit; then FROZEN).

    uv run --with cbor2 python packages/schemas/test-vectors/generate_phase2.py --check

Independence: every valid CBOR vector is also encoded with cbor2 (canonical=True) and the bytes
must agree; every must-reject vector must be rejected by agw_schemas.cbor.decode. With
``--check`` the script regenerates in memory and fails on any difference from the committed
files (never overwrites). Changing a frozen vector requires an ADR.
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from typing import Any

from agw_schemas.cbor import CanonicalError, decode, encode
from agw_schemas.events import HEADER_MODELS, Payload

HERE = Path(__file__).parent


def typed(v: Any) -> Any:
    if isinstance(v, bytes):
        return {"$bytes": v.hex()}
    if isinstance(v, dict):
        return {k: typed(x) for k, x in v.items()}
    if isinstance(v, list | tuple):
        return [typed(x) for x in v]
    return v


VALID: list[tuple[str, Any]] = [
    ("uint 0", 0),
    ("uint 1", 1),
    ("uint 10", 10),
    ("uint 23", 23),
    ("uint 24", 24),
    ("uint 25", 25),
    ("uint 100", 100),
    ("uint 255", 255),
    ("uint 256", 256),
    ("uint 1000", 1000),
    ("uint 65535", 65535),
    ("uint 65536", 65536),
    ("uint 1000000", 1000000),
    ("uint 2^32-1", 2**32 - 1),
    ("uint 2^32", 2**32),
    ("uint 1000000000000", 1000000000000),
    ("uint 2^64-1", 2**64 - 1),
    ("nint -1", -1),
    ("nint -10", -10),
    ("nint -24", -24),
    ("nint -25", -25),
    ("nint -100", -100),
    ("nint -1000", -1000),
    ("nint -2^63", -(2**63)),
    ("false", False),
    ("true", True),
    ("null", None),
    ("bstr empty", b""),
    ("bstr 01020304", bytes([1, 2, 3, 4])),
    ("bstr 32 zero", bytes(32)),
    ("tstr empty", ""),
    ("tstr a", "a"),
    ("tstr IETF", "IETF"),
    ("tstr quote backslash", '"\\'),
    ("tstr u-umlaut", "ü"),
    ("tstr water", "水"),
    ("tstr no NFC normalization", "é"),
    ("tstr 24 chars", "x" * 24),
    ("array empty", []),
    ("array 1 2 3", [1, 2, 3]),
    ("array nested", [1, [2, 3], [4, 5]]),
    ("array 25 elems", list(range(1, 26))),
    ("map empty", {}),
    ("map a b", {"a": 1, "b": [2, 3]}),
    ("array with map", ["a", {"b": "c"}]),
    ("map five", {"a": "A", "b": "B", "c": "C", "d": "D", "e": "E"}),
    ("map shorter key first", {"b": 1, "aa": 2}),
    ("map bytewise order", {"z": 0, "B": 1, "a": 2}),
    ("map key len 23 before 24", {"y" * 24: 1, "z" * 23: 2}),
    ("map key len 255 before 256", {"q" * 256: 1, "r" * 255: 2}),
    ("map nested sorted", {"outer": {"b": 2, "a": 1}, "id": b"\x00" * 16}),
    ("depth 16", [[[[[[[[[[[[[[[[0]]]]]]]]]]]]]]]]),
]

REJECT: list[tuple[str, str, str]] = [
    ("unsorted keys", "a2616201616102", "KEY_ORDER"),
    ("unsorted by length", "a2626161016162 02".replace(" ", ""), "KEY_ORDER"),
    ("duplicate key", "a2616101616102", "DUPLICATE_KEY"),
    ("non-shortest uint 1-byte", "1805", "NON_SHORTEST"),
    ("non-shortest uint 2-byte", "190005", "NON_SHORTEST"),
    ("non-shortest uint 4-byte", "1a00000005", "NON_SHORTEST"),
    ("non-shortest uint 8-byte", "1b0000000000000005", "NON_SHORTEST"),
    ("non-shortest uint 2-byte 255", "1900ff", "NON_SHORTEST"),
    ("non-shortest nint", "3800", "NON_SHORTEST"),
    ("non-shortest bstr length", "580100", "NON_SHORTEST"),
    ("non-shortest tstr length", "780161", "NON_SHORTEST"),
    ("non-shortest array length", "980100", "NON_SHORTEST"),
    ("non-shortest map length", "b8016161 01".replace(" ", ""), "NON_SHORTEST"),
    ("indefinite array", "9f01ff", "INDEFINITE"),
    ("indefinite map", "bf616101ff", "INDEFINITE"),
    ("indefinite tstr", "7f6161ff", "INDEFINITE"),
    ("indefinite bstr", "5f4101ff", "INDEFINITE"),
    ("lone break", "ff", "INDEFINITE"),
    ("float16", "f93c00", "FLOAT"),
    ("float32", "fa3f800000", "FLOAT"),
    ("float64", "fb3ff0000000000000", "FLOAT"),
    ("undefined", "f7", "UNDEFINED"),
    ("simple 16", "f0", "SIMPLE"),
    ("simple 1-byte", "f818", "SIMPLE"),
    ("tag 1 epoch time", "c100", "TAG"),
    ("tag 37 uuid", "d8255000000000000000000000000000000000", "TAG"),
    ("bignum tag", "c249010000000000000000", "TAG"),
    ("invalid utf-8", "62c328", "UTF8"),
    ("non-text map key", "a10101", "MAP_KEY"),
    ("bstr map key", "a1410001", "MAP_KEY"),
    ("trailing bytes", "0000", "TRAILING"),
    ("truncated uint", "1a0000", "TRUNCATED"),
    ("truncated tstr", "6361", "TRUNCATED"),
    ("reserved ai 28", "1c", "RESERVED"),
    ("nint below -2^63", "3b8000000000000000", "INT_RANGE"),
    ("depth 17", "81" * 17 + "00", "DEPTH"),
]

TAG_EVENT = bytes([12]) + b"AGW/event/v1"
TAG_PAYLOAD = bytes([14]) + b"AGW/payload/v1"
TAG_ARGS = bytes([11]) + b"AGW/args/v1"


def h(prefix: bytes, data: bytes) -> bytes:
    return hashlib.sha256(prefix + data).digest()


def event_vectors() -> dict[str, Any]:
    act, run = (
        bytes.fromhex("0193d0c2000070008000000000000001"),
        bytes.fromhex("0193d0c2000070008000000000000002"),
    )
    args = {"limit": 3, "query": "evidence"}
    args_cbor = encode(args)
    salt = bytes(range(32))
    p0 = Payload(
        salt=salt,
        event=bytes.fromhex("0193d0c2000070008000000000000010"),
        intent={"args": args, "summary": "find docs"},
        context={"sources": []},
    )
    p2 = Payload(
        salt=bytes(32),
        event=bytes.fromhex("0193d0c2000070008000000000000012"),
        execution={"params": args},
    )
    payloads = [p0.to_record(delegation_present=True), p2.to_record()]
    pbytes = [encode(p) for p in payloads]
    pdig = [h(TAG_PAYLOAD, b) for b in pbytes]
    headers = [
        dict(
            tenant="acme",
            seq=0,
            prev=bytes(32),
            id=bytes.fromhex("0193d0c2000070008000000000000010"),
            type="ACTION_REQUESTED",
            ts=1763190000000000,
            actor={"kind": "agent", "id": "agent-1"},
            action=act,
            run=run,
            tool={"id": "public_doc_search", "ver": "1.0.0"},
            env="dev",
            payload={"digest": pdig[0], "len": len(pbytes[0]), "ref": "inline"},
            code={"gw": "0123abc", "agent": "demo/1.0"},
            **{"class": "A2S"},
        ),
        dict(
            tenant="acme",
            seq=1,
            prev=None,
            id=bytes.fromhex("0193d0c2000070008000000000000011"),
            type="POLICY_EVALUATED",
            ts=1763190000000100,
            actor={"kind": "gateway", "id": "agw-gateway"},
            action=act,
            run=run,
            tool={"id": "public_doc_search", "ver": "1.0.0"},
            env="dev",
            risk={"level": "LOW", "score": 0, "rules": [], "cv": "risk-v1"},
            policy={
                "id": "default",
                "ver": 1,
                "effect": "ALLOW",
                "rules": ["allow-low-read"],
                "reasons": [],
                "controls": [],
                "ev": "policy-v1",
            },
            **{"class": "SYS"},
        ),
        dict(
            tenant="acme",
            seq=2,
            prev=None,
            id=bytes.fromhex("0193d0c2000070008000000000000012"),
            type="ACTION_DISPATCHED",
            ts=1763190000000200,
            actor={"kind": "gateway", "id": "agw-gateway"},
            action=act,
            run=run,
            tool={"id": "public_doc_search", "ver": "1.0.0"},
            args=h(TAG_ARGS, args_cbor),
            dispatch={"attempt": 1, "worker": "w1", "cg": "w1/b1"},
            payload={"digest": pdig[1], "len": len(pbytes[1]), "ref": "inline"},
            obs=1763190000000199,
            code={"gw": "0123abc", "adapter": "pkg.Adapter@1.0.0"},
            **{"class": "A2S"},
        ),
    ]
    out, prev = [], bytes(32)
    for hd in headers:
        hd["prev"] = prev
        rec = HEADER_MODELS[hd["type"]].model_validate(hd).to_record()
        cb = encode(rec)
        eh = h(TAG_EVENT, cb)
        out.append({"record": typed(rec), "canonical_hex": cb.hex(), "event_hash": eh.hex()})
        prev = eh
    return {
        "description": "AGW-EVT v1 chain of 3 records; event_hash = SHA256(0x0c 'AGW/event/v1' || canonical)",
        "events": out,
        "payloads": [
            {"payload": typed(p), "canonical_hex": b.hex(), "payload_digest": d.hex()}
            for p, b, d in zip(payloads, pbytes, pdig, strict=True)
        ],
        "args_digest": {
            "args": args,
            "canonical_hex": args_cbor.hex(),
            "digest": h(TAG_ARGS, args_cbor).hex(),
        },
    }


def build() -> dict[str, Any]:
    import cbor2

    valid = []
    for name, value in VALID:
        mine = encode(value)
        theirs = cbor2.dumps(value, canonical=True)
        if mine != theirs:
            raise SystemExit(f"cbor2 disagrees on {name}: {mine.hex()} vs {theirs.hex()}")
        assert decode(mine) == (value if not isinstance(value, tuple) else list(value))
        valid.append({"name": name, "value": typed(value), "hex": mine.hex()})
    reject = []
    for name, hx, code in REJECT:
        try:
            decode(bytes.fromhex(hx))
        except CanonicalError as exc:
            if exc.code != code:
                raise SystemExit(f"{name}: expected {code}, got {exc.code}") from None
        else:
            raise SystemExit(f"{name}: accepted")
        reject.append({"name": name, "hex": hx, "error": code})
    return {
        "cbor/valid.json": {"profile": "AGW-CBOR-v1", "vectors": valid},
        "cbor/reject.json": {"profile": "AGW-CBOR-v1", "vectors": reject},
        "event/event-chain.json": event_vectors(),
    }


def main() -> int:
    check = "--check" in sys.argv
    status = 0
    for rel, data in build().items():
        text = json.dumps(data, indent=1, ensure_ascii=False) + "\n"
        path = HERE / rel
        if check:
            if not path.exists() or path.read_text(encoding="utf-8") != text:
                print(f"DIFF {rel}")
                status = 1
            else:
                print(f"ok   {rel}")
        else:
            path.write_text(text, encoding="utf-8")
            print(f"wrote {rel}")
    return status


if __name__ == "__main__":
    raise SystemExit(main())
