"""Phase 8 (ADR-0030): delegation token codec + the pure policy/risk hooks."""

from __future__ import annotations

import base64
import os
import uuid
from dataclasses import replace
from datetime import UTC, datetime

import pytest

from agw_gateway.auth.models import AuthenticatedAgent
from agw_gateway.crypto.canonical import decode, encode
from agw_gateway.delegation.constraint import FAILURE_CODES, DelegationConstraint
from agw_gateway.delegation.token import (
    Claims,
    DelegationSigner,
    TokenInvalid,
    parse_and_verify,
)
from agw_gateway.policies.default_policy import DEFAULT_POLICY_V2
from agw_gateway.policies.engine import ReasonCode
from agw_gateway.policies.models import load_policy_document
from agw_gateway.policies.pipeline import decide_action
from agw_gateway.risk.policy import load_risk_policy_toml
from agw_gateway.risk_store import default_risk_policy_text
from agw_gateway.tools.demo import CREATE_TICKET, PUBLIC_DOC_SEARCH, SEND_EMAIL

pytestmark = pytest.mark.unit

SIGNER = DelegationSigner(os.urandom(32))
OTHER = DelegationSigner(os.urandom(32))
KEYS = {SIGNER.key_id: SIGNER.public_raw}


def claims(**over: object) -> Claims:
    base = {
        "delegation_id": uuid.uuid4(),
        "tenant": "t1",
        "issuer": uuid.uuid4(),
        "subject": uuid.uuid4(),
        "depth": 1,
        "parent_hash": None,
        "scopes": ("tools:create_ticket", "tools:public_doc_search"),
        "tools": ("create_ticket", "public_doc_search"),
        "max_risk": "MEDIUM",
        "expires_us": 2_000_000_000_000_000,
        "max_uses": 3,
        "issued_us": 1_000_000_000_000_000,
        "key_id": SIGNER.key_id,
    }
    base.update(over)
    return Claims(**base)  # type: ignore[arg-type]


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def test_roundtrip_and_hash_binds_signature() -> None:
    signed = SIGNER.sign(claims())
    parsed = parse_and_verify(signed.text, KEYS)
    assert parsed.claims == signed.claims
    assert parsed.hash == signed.hash and len(parsed.hash) == 32
    assert "agwd1." not in repr(signed) and signed.text not in repr(signed)


@pytest.mark.parametrize("position", [0, 7, -1])
def test_any_flipped_claims_byte_is_rejected(position: int) -> None:
    signed = SIGNER.sign(claims())
    raw = bytearray(signed.claims_cbor)
    raw[position] ^= 0x01
    forged = f"agwd1.{_b64(bytes(raw))}.{_b64(signed.signature)}"
    with pytest.raises(TokenInvalid):
        parse_and_verify(forged, KEYS)


def test_widened_scopes_resigned_with_another_key_is_rejected() -> None:
    """Forged signature: the attacker re-signs widened claims with its own key and claims
    the gateway's key id."""
    wide = claims(scopes=("admin:all", "tools:delete_record"), tools=("delete_record",))
    cbor = encode(wide.record())
    sig = OTHER._private.sign(b"\x15AGW/delegation-sig/v1" + cbor)
    with pytest.raises(TokenInvalid, match="SIGNATURE"):
        parse_and_verify(f"agwd1.{_b64(cbor)}.{_b64(sig)}", KEYS)


def test_unknown_key_and_bad_encodings_rejected() -> None:
    signed = OTHER.sign(claims(key_id=OTHER.key_id))
    with pytest.raises(TokenInvalid, match="UNKNOWN_KEY"):
        parse_and_verify(signed.text, KEYS)
    good = SIGNER.sign(claims()).text
    for bad in (
        good.replace("agwd1.", "agwd2."),
        good + "=",
        good + ".x",
        "agwd1..",
        "x" * 5000,
        good.replace(".", ". ", 1),
    ):
        with pytest.raises(TokenInvalid):
            parse_and_verify(bad, KEYS)


def test_non_canonical_and_unknown_claim_keys_rejected() -> None:
    signed = SIGNER.sign(claims())
    rec = decode(signed.claims_cbor)
    rec["admin"] = True  # unknown key, validly signed by the real key
    cbor = encode(rec)
    sig = SIGNER._private.sign(b"\x15AGW/delegation-sig/v1" + cbor)
    with pytest.raises(TokenInvalid, match="SHAPE"):
        parse_and_verify(f"agwd1.{_b64(cbor)}.{_b64(sig)}", KEYS)
    # Non-canonical: an integer in a longer-than-necessary encoding.
    noncanon = signed.claims_cbor.replace(b"\x63dep\x01", b"\x63dep\x18\x01")
    assert noncanon != signed.claims_cbor
    sig = SIGNER._private.sign(b"\x15AGW/delegation-sig/v1" + noncanon)
    with pytest.raises(TokenInvalid):
        parse_and_verify(f"agwd1.{_b64(noncanon)}.{_b64(sig)}", KEYS)


@pytest.mark.parametrize(
    "over",
    [
        {"depth": 2},  # depth > 1 needs a parent hash
        {"parent_hash": bytes(32)},  # depth 1 must not have one
        {"scopes": ("b", "a")},  # unsorted
        {"tools": ("Bad Tool",)},
        {"max_risk": "EXTREME"},
        {"max_uses": 0},
        {"expires_us": 1},
        {"depth": 9, "parent_hash": bytes(32)},
    ],
)
def test_claims_invariants(over: dict[str, object]) -> None:
    with pytest.raises(TokenInvalid):
        claims(**over)
    s = uuid.uuid4()
    with pytest.raises(TokenInvalid, match="SELF"):
        claims(issuer=s, subject=s)


# --------------------------------------------------------------------------- pure policy
AGENT = AuthenticatedAgent(
    tenant_id="t1",
    agent_id=uuid.uuid4(),
    name="child",
    scopes=frozenset({"tools:create_ticket", "tools:public_doc_search", "tools:send_email"}),
    trust_tier="standard",
)
POLICY = load_policy_document(DEFAULT_POLICY_V2)
RISK = load_risk_policy_toml(default_risk_policy_text())
OK = DelegationConstraint(
    failure=None,
    depth=1,
    scopes=frozenset({"tools:create_ticket", "tools:public_doc_search"}),
    tools=frozenset({"create_ticket", "public_doc_search"}),
    max_risk="MEDIUM",
)


def decide(tool: object, args: dict[str, object], d: DelegationConstraint | None) -> object:
    return decide_action(
        agent=AGENT,
        tool_id=tool.tool_id,  # type: ignore[attr-defined]
        tool=tool,  # type: ignore[arg-type]
        args=args,
        environment="dev",
        risk_policy=RISK,
        policy=POLICY,
        now=datetime.now(UTC),
        delegation=d,
    )


def test_policy_allows_within_delegation_and_records_verified_depth() -> None:
    dec = decide(PUBLIC_DOC_SEARCH, {"query": "x", "limit": 1}, OK)
    assert dec.effect == "ALLOW"  # type: ignore[attr-defined]
    assert "DELEGATION_VERIFIED" in dec.risk.reasons  # type: ignore[attr-defined]
    assert "DELEGATION_SELF_DECLARED" not in dec.risk.reasons  # type: ignore[attr-defined]
    depth = next(f for f in dec.risk.factor_values if f.name == "delegation_depth")  # type: ignore[attr-defined]
    assert depth.value == "one_hop"


def test_policy_denies_scope_tool_risk_and_every_failure() -> None:
    # child holds tools:send_email itself, but the chain does not delegate it
    no_scope = replace(OK, tools=OK.tools | {"send_email"})
    dec = decide(SEND_EMAIL, {"to": ["a@corp.example"], "subject": "s"}, no_scope)
    assert dec.reasons == (ReasonCode.DELEGATION_SCOPE_MISSING,)  # type: ignore[attr-defined]
    no_tool = replace(OK, tools=frozenset({"public_doc_search"}))
    dec = decide(CREATE_TICKET, {"title": "t", "body": "b"}, no_tool)
    assert dec.reasons == (ReasonCode.DELEGATION_TOOL_NOT_ALLOWED,)  # type: ignore[attr-defined]
    low_cap = replace(OK, max_risk="LOW")  # create_ticket is MEDIUM
    dec = decide(CREATE_TICKET, {"title": "t", "body": "b"}, low_cap)
    assert dec.effect == "DENY"  # type: ignore[attr-defined]
    assert dec.reasons == (ReasonCode.DELEGATION_RISK_EXCEEDED,)  # type: ignore[attr-defined]
    for code in sorted(FAILURE_CODES):
        dec = decide(
            PUBLIC_DOC_SEARCH, {"query": "x", "limit": 1}, DelegationConstraint.failed(code)
        )  # type: ignore[arg-type]
        assert dec.effect == "DENY" and dec.reasons == (ReasonCode(code),)  # type: ignore[attr-defined]


def test_declared_depth_and_token_are_exclusive() -> None:
    with pytest.raises(ValueError, match="exclusive"):
        decide_action(
            agent=AGENT,
            tool_id="public_doc_search",
            tool=PUBLIC_DOC_SEARCH,
            args={"query": "x", "limit": 1},
            environment="dev",
            risk_policy=RISK,
            policy=POLICY,
            now=datetime.now(UTC),
            delegation_depth=1,
            delegation=OK,
        )
