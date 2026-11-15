"""API key format/digest (11 §3) and domain tags (06 §2)."""

import hashlib

import pytest

from agw_gateway.auth.tokens import issue_token, parse_token, token_digest
from agw_gateway.crypto.tags import domain_tag
from agw_gateway.execution.fingerprint import request_fingerprint

pytestmark = pytest.mark.unit


def test_tag_bytes_match_spec_table() -> None:
    assert domain_tag("AGW/apikey/v1").hex() == "0d" + "4147572f6170696b65792f7631"
    assert domain_tag("AGW/request/v1").hex() == "0e" + "4147572f726571756573742f7631"
    with pytest.raises(ValueError):
        domain_tag("x")


def test_issue_parse_digest() -> None:
    tok = issue_token()
    assert len(tok.token) == 64 and tok.token.startswith("agw_")
    assert parse_token(tok.token) == tok.key_id
    assert tok.digest == hashlib.sha256(domain_tag("AGW/apikey/v1") + tok.token.encode()).digest()
    assert token_digest(tok.token) == tok.digest
    assert tok.token not in repr(tok)


@pytest.mark.parametrize(
    "bad",
    [
        "",
        "agw_",
        "agw_ABCDEF0123456789_" + "a" * 43,
        "agw_0123456789abcdef_" + "a" * 42,
        "xyz_0123456789abcdef_" + "a" * 43,
    ],
)
def test_parse_rejects_malformed(bad: str) -> None:
    assert parse_token(bad) is None


def test_request_fingerprint_key_order_independent_and_sensitive() -> None:
    a = request_fingerprint(
        tool="t", tool_version=None, environment="dev", run_id="r", args={"a": 1, "b": 2}
    )
    b = request_fingerprint(
        tool="t", tool_version=None, environment="dev", run_id="r", args={"b": 2, "a": 1}
    )
    c = request_fingerprint(
        tool="t", tool_version=None, environment="dev", run_id="r", args={"a": 1, "b": 3}
    )
    assert a == b != c
    with pytest.raises(ValueError):
        request_fingerprint(
            tool="t", tool_version=None, environment="dev", run_id="r", args={"x": float("nan")}
        )
