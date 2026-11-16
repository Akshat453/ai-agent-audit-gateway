"""Risk engine properties (ADR-0026).

* Determinism: the same input gives the same result and the same canonical record bytes,
  also against a freshly re-parsed policy.
* Missing metadata never lowers risk: blanking any subset of factors gives a level (and a
  forced effect, and a decision effect) at least as strict as ANY filled-in value.
"""

from dataclasses import replace

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from agw_gateway.crypto.canonical import encode
from agw_gateway.policies.engine import EvaluationInput
from agw_gateway.policies.engine import evaluate as evaluate_policy
from agw_gateway.risk import RequestContext, evaluate, load_risk_policy_toml
from agw_gateway.risk.policy import FACTOR_VOCAB
from agw_gateway.risk_store import default_risk_policy_text
from agw_gateway.tools.metadata import ToolMetadata

from ..riskkit import NOW, POLICY_V2, RISK_POLICY, agent

pytestmark = pytest.mark.property

FORCE_RANK = {None: 0, "REQUIRE_APPROVAL": 1, "DENY": 2}
EFFECT_RANK = {"ALLOW": 0, "REQUIRE_APPROVAL": 1, "DENY": 2}
LEVELS = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]

contexts = st.builds(
    RequestContext,
    tool_known=st.just(True),
    tool_id=st.sampled_from(["send_email", "export_customer_data", "x_tool"]),
    operation=st.sampled_from(FACTOR_VOCAB["operation"]),
    tool_sensitivity=st.sampled_from(FACTOR_VOCAB["tool_sensitivity"]),
    data_classification=st.sampled_from(FACTOR_VOCAB["data_classification"]),
    reversible=st.booleans(),
    environment=st.sampled_from(FACTOR_VOCAB["environment"]),
    base_risk=st.sampled_from(LEVELS),
    tags=st.frozensets(st.sampled_from(["privilege_change", "credential_access", "other"])),
    has_destination_field=st.booleans(),
    destinations=st.lists(
        st.sampled_from(["a@corp.example", "b@x.example", "s3://k.internal.example/p", "zz"]),
        min_size=1,
        max_size=3,
    ).map(tuple),
    external_effect=st.booleans(),
    volume=st.integers(min_value=0, max_value=50_000),
    delegation_depth=st.integers(min_value=0, max_value=6),
    delegation_declared=st.booleans(),
    agent_trust_tier=st.sampled_from(FACTOR_VOCAB["agent_trust_tier"]),
    scope_present=st.booleans(),
)
MISSABLE = {
    "operation": None,
    "tool_sensitivity": None,
    "data_classification": None,
    "reversible": None,
    "environment": None,
    "base_risk": None,
    "destinations": None,
    "volume": None,
    "delegation_depth": None,
    "agent_trust_tier": None,
}
REPARSED = load_risk_policy_toml(default_risk_policy_text())


@settings(max_examples=500, deadline=None)
@given(contexts)
def test_evaluation_is_deterministic_to_the_byte(c: RequestContext) -> None:
    a, b, c2 = evaluate(c, RISK_POLICY), evaluate(c, RISK_POLICY), evaluate(c, REPARSED)
    assert a == b == c2
    assert encode(a.to_record()) == encode(b.to_record()) == encode(c2.to_record())


def _decision_effect(c: RequestContext) -> str:
    """Policy-v2 effect for a synthetic registered tool built from the context."""
    tool = ToolMetadata(
        tool_id="x_tool",
        version="1.0.0",
        operation_type=c.operation,
        sensitivity=c.tool_sensitivity,
        base_risk=c.base_risk,
        environments_allowed=frozenset({"dev", "staging", "prod", ""}),
        required_scope="tools:x",
        is_idempotent=False,
        external_effect=c.external_effect,
        data_classification=c.data_classification,
        reversible=c.reversible,
        medium_effect="ALLOW",
    )
    return evaluate_policy(
        EvaluationInput(
            agent=agent(frozenset({"tools:x"})),
            tool=tool,
            args_valid=True,
            args={},
            environment=c.environment or "",
            policy=POLICY_V2,
            risk=evaluate(replace(c, tool_id="x_tool"), RISK_POLICY),
            now=NOW,
        )
    ).effect


@settings(max_examples=800, deadline=None)
@given(contexts, st.sets(st.sampled_from(sorted(MISSABLE)), min_size=1))
def test_missing_metadata_never_lowers_risk(c: RequestContext, blank: set[str]) -> None:
    full = evaluate(c, RISK_POLICY)
    missing_ctx = replace(c, **{k: MISSABLE[k] for k in blank})
    missing = evaluate(missing_ctx, RISK_POLICY)
    assert missing.level >= full.level
    assert missing.score >= full.score
    assert FORCE_RANK[missing.forced_effect] >= FORCE_RANK[full.forced_effect]
    assert set(full.matched_rules) <= set(missing.matched_rules) | {"MR-MISSING-META"}
    assert "MR-MISSING-META" in missing.matched_rules or blank <= {"destinations"}
    assert EFFECT_RANK[_decision_effect(missing_ctx)] >= EFFECT_RANK[_decision_effect(c)]
