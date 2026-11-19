"""ADR-0038: the sealed-record view and the stored-copy comparison."""

from __future__ import annotations

import uuid

from agw_gateway.crypto.canonical import encode, to_json_projection
from agw_gateway.evidence.sealed import header_for_display, sealed_header, stored_copy_ok

ACTION = uuid.uuid4()
RECORD = {
    "tenant": "t1",
    "seq": 7,
    "type": "POLICY_EVALUATED",
    "id": uuid.uuid4().bytes,
    "action": ACTION.bytes,
    "prev": b"\x01" * 32,
    "policy": {"effect": "allow", "reasons": ["r1"], "rules": ["A", "B"]},
}
CANON = encode(RECORD)
BODY = to_json_projection(RECORD)


def ok(body: object = BODY, **cols: object) -> bool:
    base: dict[str, object] = {
        "tenant_id": "t1",
        "seq": 7,
        "event_type": "POLICY_EVALUATED",
        "action_id": ACTION,
        "run_id": None,
    }
    base.update(cols)
    return stored_copy_ok(CANON, body, **base)  # type: ignore[arg-type]


def test_sealed_header_is_the_projection_of_the_canonical_bytes() -> None:
    assert sealed_header(CANON) == BODY
    assert header_for_display(CANON) == BODY


def test_undecodable_bytes_show_nothing_not_the_copy() -> None:
    assert sealed_header(CANON + b"\x00") is None
    assert header_for_display(b"\xff\xff") == {}
    assert not stored_copy_ok(CANON + b"\x00", BODY)


def test_matching_copy_and_columns() -> None:
    assert ok()
    assert ok(action_id=str(ACTION))  # text or UUID
    assert stored_copy_ok(CANON, BODY)  # columns not passed are not checked


def test_any_difference_is_a_mismatch() -> None:
    forged = {**BODY, "policy": {**BODY["policy"], "effect": "deny"}}
    assert not ok(forged)
    assert not ok({k: v for k, v in BODY.items() if k != "policy"})
    assert not ok({**BODY, "extra": 1})
    assert not ok(None)
    assert not ok(tenant_id="t2")
    assert not ok(seq=8)
    assert not ok(event_type="ACTION_DENIED")
    assert not ok(action_id=uuid.uuid4())
    assert not ok(action_id=None)  # NULL column but the sealed record names an action
    assert not ok(run_id=uuid.uuid4())  # sealed record names no run
