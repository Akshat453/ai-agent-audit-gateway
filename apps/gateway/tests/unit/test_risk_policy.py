"""Risk policy documents (ADR-0026): TOML loading fails closed; digest over canonical bytes."""

import hashlib
import re
from collections.abc import Callable

import pytest

from agw_gateway.crypto.canonical import encode, profile_value
from agw_gateway.crypto.tags import RISK_POLICY_TAG, domain_tag
from agw_gateway.risk import RiskPolicyLoadError, load_risk_policy_canonical, load_risk_policy_toml
from agw_gateway.risk_store import default_risk_policy_text

pytestmark = pytest.mark.unit

TEXT = default_risk_policy_text()
POLICY = load_risk_policy_toml(TEXT)


def test_digest_is_domain_tagged_hash_of_canonical_bytes() -> None:
    expected = hashlib.sha256(domain_tag(RISK_POLICY_TAG) + POLICY.canonical_bytes()).digest()
    assert POLICY.digest() == expected
    assert domain_tag(RISK_POLICY_TAG) == bytes([18]) + b"AGW/risk-policy/v1"


def test_formatting_does_not_change_the_digest_but_content_does() -> None:
    reformatted = "\n".join(line.rstrip() + "   " for line in TEXT.splitlines())
    reformatted = re.sub(r"(?m)^#.*$", "# comment changed", reformatted)
    assert load_risk_policy_toml(reformatted).digest() == POLICY.digest()
    bumped = TEXT.replace("version = 1", "version = 2", 1)
    assert load_risk_policy_toml(bumped).digest() != POLICY.digest()
    reweighted = TEXT.replace("[factors.operation]\nweight = 5", "[factors.operation]\nweight = 6")
    assert load_risk_policy_toml(reweighted).digest() != POLICY.digest()


def test_canonical_round_trip_and_tamper_checks() -> None:
    assert load_risk_policy_canonical(POLICY.canonical_bytes(), POLICY.digest()) == POLICY
    with pytest.raises(RiskPolicyLoadError, match="digest"):
        load_risk_policy_canonical(POLICY.canonical_bytes(), bytes(32))
    # Decodes to an equal model but is not the canonical encoding (explicit nulls kept).
    loose = encode(profile_value(POLICY.model_dump(mode="python")))
    digest = hashlib.sha256(domain_tag(RISK_POLICY_TAG) + loose).digest()
    with pytest.raises(RiskPolicyLoadError):
        load_risk_policy_canonical(loose, digest)


def _sub(old: str, new: str) -> Callable[[str], str]:
    def f(text: str) -> str:
        assert old in text, old
        return text.replace(old, new, 1)

    return f


@pytest.mark.parametrize(
    "mutate",
    [
        lambda t: t + "\n[[[",  # not TOML
        _sub("weight = 5", "weight = 5.0"),  # floats are rejected
        _sub("weight = 5", "weight = -1"),
        _sub("[factors.environment]", "[factors.environmentx]"),  # missing + unknown factor
        _sub("prod = 2 }", "prod = 2, mars = 9 }"),  # value outside the vocabulary
        _sub("dev = 0, staging = 1, prod = 2", "dev = 0, staging = 1"),  # value missing
        _sub("dev = 0, staging = 1, prod = 2", "dev = 3, staging = 1, prod = 2"),  # decreasing
        _sub('{ label = "mass", points = 5 }', '{ label = "mass", up_to = 5000, points = 5 }'),
        _sub('{ label = "single", up_to = 1, points = 0 }', '{ label = "single", points = 0 }'),
        _sub(
            '{ label = "few", up_to = 10, points = 1 }', '{ label = "few", up_to = 1, points = 1 }'
        ),
        _sub(
            '{ label = "few", up_to = 10, points = 1 }', '{ label = "few", up_to = 10, points = 9 }'
        ),
        _sub(
            "[factors.volume]       # records / recipients affected (blast radius)\nweight = 5\n",
            "[factors.volume]\nweight = 5\nvalues = { a = 1 }\n",
        ),
        _sub(
            "[factors.operation]\nweight = 5\n", "[factors.operation]\nweight = 5\nbuckets = []\n"
        ),
        _sub("when = { scope_present = false }", "when = {}"),  # empty condition
        _sub(
            'when = { operation = ["delete"], environment = ["prod"] }',
            'when = { operation = ["obliterate"] }',
        ),
        _sub('missing_any = ["tool_sensitivity",', 'missing_any = ["mood",'),
        _sub('effect = "DENY"\nfloor = "HIGH"', ""),  # rule that does nothing
        _sub("MEDIUM = 25", "MEDIUM = 50"),  # thresholds not ascending
        _sub('rule_id = "MR-DELETE-PROD"', 'rule_id = "MR-NO-SCOPE"'),  # duplicate id
        _sub('policy_id = "risk-default"', 'policy_id = "risk-default"\nsurprise = true'),
        _sub('unknown_tool_level = "HIGH"', 'unknown_tool_level = "SEVERE"'),
        _sub('floor = "CRITICAL"', 'effect = "ALLOW"'),  # rules cannot ALLOW
    ],
)
def test_loader_fails_closed(mutate: Callable[[str], str]) -> None:
    with pytest.raises(RiskPolicyLoadError):
        load_risk_policy_toml(mutate(TEXT))


def test_errors_name_locations_not_values() -> None:
    with pytest.raises(RiskPolicyLoadError) as err:
        load_risk_policy_toml(
            TEXT.replace('policy_id = "risk-default"', 'policy_id = "s3cr3t value!"')
        )
    assert "s3cr3t" not in str(err.value)
    assert "policy_id" in str(err.value)
