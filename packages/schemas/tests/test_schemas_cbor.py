"""AGW-CBOR-v1 codec (gateway side): frozen vectors, round-trip, rejection, event models."""

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from agw_schemas.cbor import MAX_DEPTH, CanonicalError, decode, encode
from agw_schemas.events import HEADER_MODELS, ActionRequested, Payload, parse_header

pytestmark = pytest.mark.unit

VECTORS = Path(__file__).resolve().parents[1] / "test-vectors"


def untyped(v: Any) -> Any:
    if isinstance(v, dict):
        if set(v) == {"$bytes"}:
            return bytes.fromhex(v["$bytes"])
        return {k: untyped(x) for k, x in v.items()}
    if isinstance(v, list):
        return [untyped(x) for x in v]
    return v


VALID = json.loads((VECTORS / "cbor/valid.json").read_text())["vectors"]
REJECT = json.loads((VECTORS / "cbor/reject.json").read_text())["vectors"]
CHAIN = json.loads((VECTORS / "event/event-chain.json").read_text())


def test_vector_counts() -> None:
    assert len(VALID) >= 40 and len(REJECT) >= 30


@pytest.mark.parametrize("vec", VALID, ids=[v["name"] for v in VALID])
def test_valid_vectors(vec: dict) -> None:
    value = untyped(vec["value"])
    assert encode(value).hex() == vec["hex"]
    assert decode(bytes.fromhex(vec["hex"])) == value


@pytest.mark.parametrize("vec", REJECT, ids=[v["name"] for v in REJECT])
def test_reject_vectors(vec: dict) -> None:
    with pytest.raises(CanonicalError) as exc:
        decode(bytes.fromhex(vec["hex"]))
    assert exc.value.code == vec["error"]


@pytest.mark.parametrize(
    ("value", "code"),
    [
        (1.5, "FLOAT"),
        (float("nan"), "FLOAT"),
        ({"a": 0.0}, "FLOAT"),
        (2**64, "INT_RANGE"),
        (-(2**63) - 1, "INT_RANGE"),
        ({1: "x"}, "MAP_KEY"),
        ({b"k": 1}, "MAP_KEY"),
        ("\ud800", "UTF8"),
        (object(), "TYPE"),
        ([[[[[[[[[[[[[[[[[0]]]]]]]]]]]]]]]]], "DEPTH"),
    ],
)
def test_encoder_rejects(value: Any, code: str) -> None:
    with pytest.raises(CanonicalError) as exc:
        encode(value)
    assert exc.value.code == code


cbor_values = st.recursive(
    st.none()
    | st.booleans()
    | st.integers(min_value=-(2**63), max_value=2**64 - 1)
    | st.binary(max_size=40)
    | st.text(max_size=40),
    lambda c: st.lists(c, max_size=5) | st.dictionaries(st.text(max_size=10), c, max_size=5),
    max_leaves=25,
)


@settings(max_examples=1000, deadline=None)
@given(cbor_values)
def test_roundtrip(value: Any) -> None:
    raw = encode(value)
    assert decode(raw) == value
    assert encode(decode(raw)) == raw


@settings(max_examples=500, deadline=None)
@given(st.binary(max_size=64))
def test_decode_never_accepts_noncanonical(data: bytes) -> None:
    try:
        value = decode(data)
    except CanonicalError:
        return
    assert encode(value) == data  # anything accepted is exactly canonical


@settings(max_examples=300, deadline=None)
@given(st.dictionaries(st.text(max_size=6), st.integers(0, 5), min_size=2, max_size=6))
def test_map_key_order_is_bytewise_of_encoded_keys(d: dict[str, int]) -> None:
    raw = encode(d)
    keys = list(decode(raw))
    assert keys == sorted(keys, key=encode)


def test_depth_limit_constant() -> None:
    assert MAX_DEPTH == 16


def test_event_chain_vectors_reproduce() -> None:
    tag = bytes([12]) + b"AGW/event/v1"
    prev = bytes(32)
    for ev in CHAIN["events"]:
        rec = untyped(ev["record"])
        model = parse_header(rec)
        raw = encode(model.to_record())
        assert raw.hex() == ev["canonical_hex"]
        assert hashlib.sha256(tag + raw).hexdigest() == ev["event_hash"]
        assert rec["prev"] == prev
        prev = bytes.fromhex(ev["event_hash"])
    ptag = bytes([14]) + b"AGW/payload/v1"
    for p in CHAIN["payloads"]:
        raw = encode(untyped(p["payload"]))
        assert raw.hex() == p["canonical_hex"]
        assert hashlib.sha256(ptag + raw).hexdigest() == p["payload_digest"]


def _base(**kw: Any) -> dict[str, Any]:
    d: dict[str, Any] = {
        "tenant": "acme",
        "seq": 0,
        "prev": bytes(32),
        "id": bytes(16),
        "type": "ACTION_REQUESTED",
        "ts": 1,
        "class": "A2S",
        "actor": {"kind": "agent", "id": "a"},
        "action": bytes(16),
        "run": bytes(16),
        "tool": {"id": "t"},
        "env": "dev",
        "payload": {"digest": bytes(32), "len": 1},
    }
    d.update(kw)
    return d


@pytest.mark.parametrize(
    "mutation",
    [
        {"reasoning": "chain of thought"},  # no CoT field exists anywhere
        {"payload": None},  # REQUESTED requires a payload ref
        {"class": "SYS"},  # class is fixed per type
        {"prev": bytes(31)},
        {"seq": -1},
        {"tenant": "Bad_Tenant"},
        {"ts": 1.5},
        {"action": "0193d0c2-0000-7000-8000-000000000001"},  # strict: UUIDs are 16-byte bstr
    ],
)
def test_header_model_rejects(mutation: dict) -> None:
    with pytest.raises(ValueError):
        ActionRequested.model_validate(_base(**mutation))


def test_every_type_has_a_model_and_records_omit_none() -> None:
    assert set(HEADER_MODELS) >= {"ACTION_REQUESTED", "ACTION_OUTCOME_UNKNOWN", "APPROVAL_GRANTED"}
    rec = ActionRequested.model_validate(_base()).to_record()
    assert None not in rec.values() and "approval" not in rec
    assert "reasoning" not in Payload.model_fields
    p = Payload(salt=bytes(32), event=bytes(16), intent={"args": {}}).to_record(
        delegation_present=True
    )
    assert p["delegation"] is None and "execution" not in p
