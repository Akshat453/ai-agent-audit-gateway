"""Phase 5 pure parts: action digest, decision record, signatures, safe rendering (ADR-0027)."""

from __future__ import annotations

import dataclasses
import hashlib
import uuid
from pathlib import Path

import pytest
from hypothesis import given
from hypothesis import strategies as st

from agw_gateway.approvals.binding import (
    ActionBinding,
    DecisionRecord,
    policy_digest,
    render_args,
    signing_message,
    target_resource,
)
from agw_gateway.approvals.service import ApprovalConfig, approval_event_level, us
from agw_gateway.approvals.signing import (
    DecisionSigner,
    SigningKeyUnavailable,
    generate_key_file,
    key_id_for,
    verify_decision,
)
from agw_gateway.crypto.canonical import encode
from agw_gateway.crypto.tags import domain_tag
from agw_gateway.tools.demo import DELETE_RECORD, PUBLIC_DOC_SEARCH, SEND_EMAIL, UPDATE_IAM_ROLE

pytestmark = pytest.mark.unit

AGENT = uuid.UUID("01890000-0000-7000-8000-000000000001")
BINDING = ActionBinding(
    tenant="demo",
    agent_id=AGENT,
    tool_id="send_email",
    tool_version="1.0.0",
    args_digest=bytes(range(32)),
    target=["bob@partner.example"],
    environment="dev",
    policy_id="default",
    policy_version=2,
    policy_digest=b"\x11" * 32,
    risk_policy_digest=b"\x22" * 32,
    risk_level="HIGH",
    delegation_depth=None,
)
RECORD = DecisionRecord(
    tenant="demo",
    approval_id=uuid.UUID("01890000-0000-7000-8000-0000000000aa"),
    action_id=uuid.UUID("01890000-0000-7000-8000-0000000000bb"),
    action_digest=b"\x33" * 32,
    nonce=b"\x44" * 16,
    decision="APPROVED",
    approver_id=uuid.UUID("01890000-0000-7000-8000-0000000000cc"),
    decided_at_us=1_763_200_000_000_000,
    reason="ok",
)


def test_action_digest_is_tagged_sha256_of_canonical_record() -> None:
    expected = hashlib.sha256(domain_tag("AGW/action/v1") + encode(BINDING.record())).digest()
    assert BINDING.digest() == expected
    assert set(BINDING.record()) == {
        "v",
        "tenant",
        "agent_id",
        "tool_id",
        "tool_version",
        "canonical_args_digest",
        "target_resource",
        "environment",
        "policy_id",
        "policy_version",
        "policy_digest",
        "risk_policy_digest",
        "risk_level",
        "delegation_ref",
    }


# Every bound field: changing it MUST change the digest (approve X, execute Y is impossible).
CHANGES = {
    "tenant": "other",
    "agent_id": uuid.UUID("01890000-0000-7000-8000-000000000002"),
    "tool_id": "export_customer_data",
    "tool_version": "1.0.1",
    "args_digest": bytes(32),
    "target": ["eve@attacker.example"],
    "environment": "prod",
    "policy_id": "other",
    "policy_version": 3,
    "policy_digest": b"\x12" * 32,
    "risk_policy_digest": b"\x23" * 32,
    "risk_level": "CRITICAL",
    "delegation_depth": 0,
}


@pytest.mark.parametrize("field", sorted(CHANGES))
def test_every_bound_field_changes_the_digest(field: str) -> None:
    changed = dataclasses.replace(BINDING, **{field: CHANGES[field]})
    assert changed.digest() != BINDING.digest()


def test_target_order_and_type_matter() -> None:
    a = dataclasses.replace(BINDING, target=["a@x.example", "b@x.example"])
    b = dataclasses.replace(BINDING, target=["b@x.example", "a@x.example"])
    c = dataclasses.replace(BINDING, target="a@x.example,b@x.example")
    assert len({a.digest(), b.digest(), c.digest()}) == 3


@given(st.integers(min_value=0, max_value=32), st.integers(min_value=0, max_value=32))
def test_delegation_depth_is_bound(d1: int, d2: int) -> None:
    x = dataclasses.replace(BINDING, delegation_depth=d1).digest()
    y = dataclasses.replace(BINDING, delegation_depth=d2).digest()
    assert (x == y) == (d1 == d2)


def test_target_resource_selection() -> None:
    assert target_resource(UPDATE_IAM_ROLE, {"principal": "ana", "role": "admin"}) == "ana"
    assert target_resource(DELETE_RECORD, {"record_id": "r1"}) == "r1"
    # send_email has no target_field: the destination field is the target.
    assert target_resource(SEND_EMAIL, {"to": ["a@x.example"], "subject": "s"}) == ["a@x.example"]
    assert target_resource(PUBLIC_DOC_SEARCH, {"query": "q", "limit": 3}) is None


def test_policy_digest_ignores_json_key_order_but_not_content() -> None:
    a = {"policy_id": "default", "version": 2, "rules": [{"rule_id": "r", "effect": "DENY"}]}
    b = {"rules": [{"effect": "DENY", "rule_id": "r"}], "version": 2, "policy_id": "default"}
    assert policy_digest(a) == policy_digest(b)
    assert policy_digest(a) != policy_digest({**a, "version": 3})
    assert policy_digest(a) == hashlib.sha256(domain_tag("AGW/policy/v1") + encode(a)).digest()


def test_decision_digest_binds_every_field() -> None:
    base = RECORD.digest()
    assert (
        base
        == hashlib.sha256(domain_tag("AGW/approval-decision/v1") + encode(RECORD.record())).digest()
    )
    for field, value in {
        "tenant": "x",
        "approval_id": uuid.uuid4(),
        "action_id": uuid.uuid4(),
        "action_digest": b"\x00" * 32,
        "nonce": b"\x00" * 16,
        "decision": "REJECTED",
        "approver_id": uuid.uuid4(),
        "decided_at_us": 1,
        "reason": "changed",
    }.items():
        assert dataclasses.replace(RECORD, **{field: value}).digest() != base, field


def test_signature_round_trip_and_tamper_detection() -> None:
    signer = DecisionSigner.from_seed(b"\x07" * 32)
    dd = RECORD.digest()
    sig = signer.sign(dd)
    assert len(sig) == 64
    assert verify_decision(signer.public_raw, dd, sig)
    assert not verify_decision(signer.public_raw, b"\x00" * 32, sig)  # other decision
    assert not verify_decision(signer.public_raw, dd, bytes(64))  # forged signature
    other = DecisionSigner.from_seed(b"\x08" * 32)
    assert not verify_decision(other.public_raw, dd, sig)  # wrong key
    assert not verify_decision(b"\x00" * 31, dd, sig)  # malformed key
    assert signer.key_id == key_id_for(signer.public_raw) and len(signer.key_id) == 16
    assert "07" not in repr(signer)  # never the seed


def test_signing_message_is_domain_separated() -> None:
    dd = RECORD.digest()
    assert signing_message(dd) == domain_tag("AGW/approval-sig/v1") + dd
    with pytest.raises(ValueError):
        signing_message(b"short")


def test_signing_key_file(tmp_path: Path) -> None:
    path = tmp_path / "k" / "approval.key"
    kid = generate_key_file(path)
    assert DecisionSigner.from_file(path).key_id == kid
    assert (path.stat().st_mode & 0o777) == 0o600
    with pytest.raises(FileExistsError):
        generate_key_file(path)  # never overwrites
    bad = tmp_path / "bad.key"
    bad.write_text("not hex")
    with pytest.raises(SigningKeyUnavailable):
        DecisionSigner.from_file(bad)
    with pytest.raises(SigningKeyUnavailable):
        DecisionSigner.from_file(tmp_path / "missing.key")
    with pytest.raises(SigningKeyUnavailable):
        DecisionSigner.from_seed(b"\x01" * 31)


def test_render_args_makes_invisible_characters_visible() -> None:
    # U+202E RIGHT-TO-LEFT OVERRIDE and U+200B ZERO WIDTH SPACE: classic display spoofing.
    rendered = render_args({"to": ["bob@partner.example\u202e\u200bmoc.live"], "subject": "x"})
    assert "\u202e" not in rendered and "\u200b" not in rendered
    assert "\\u202e" in rendered and "\\u200b" in rendered
    assert rendered.isascii()
    assert rendered.index('"subject"') < rendered.index('"to"')  # sorted keys


def test_config_ttl_and_four_eyes() -> None:
    cfg = ApprovalConfig(ttl_seconds={"HIGH": 60}, four_eyes_critical=True)
    assert cfg.ttl("HIGH").total_seconds() == 60
    assert cfg.ttl("MEDIUM").total_seconds() == 900  # default 15 min
    assert cfg.required("CRITICAL") == 2 and cfg.required("HIGH") == 1
    assert ApprovalConfig(ttl_seconds={}, four_eyes_critical=False).required("CRITICAL") == 1


def test_approval_events_seal_at_least_high() -> None:
    assert approval_event_level("LOW") == "HIGH"
    assert approval_event_level("MEDIUM") == "HIGH"
    assert approval_event_level("HIGH") == "HIGH"
    assert approval_event_level("CRITICAL") == "CRITICAL"


def test_us_handles_naive_and_aware() -> None:
    from datetime import UTC, datetime

    aware = datetime(2026, 11, 15, tzinfo=UTC)
    assert us(aware) == us(aware.replace(tzinfo=None)) == 1_794_700_800_000_000
