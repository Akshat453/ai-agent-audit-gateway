"""INV-2 (pure pipeline): for any tool name and any args dict, the decision is ALLOW only if the
tool is registered AND the args validate AND the policy allows it."""

from datetime import UTC, datetime
from typing import Any

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from agw_gateway.policies.pipeline import decide_action
from agw_gateway.tools.demo import demo_tool_specs

from ..riskkit import POLICY_V2, RISK_POLICY, agent

pytestmark = pytest.mark.property

SPECS = {s.meta.tool_id: s for s in demo_tool_specs()}
AGENT = agent(frozenset(s.meta.required_scope for s in SPECS.values()) | {"iam:admin"})

json_scalars = (
    st.none() | st.booleans() | st.integers() | st.text(max_size=30) | st.uuids().map(str)
)
json_values = st.recursive(
    json_scalars,
    lambda c: st.lists(c, max_size=3) | st.dictionaries(st.text(max_size=8), c, max_size=3),
    max_leaves=8,
)
arg_keys = st.sampled_from(
    [
        *("query", "limit", "title", "body", "priority", "record_id", "x", "to", "subject"),
        *("destination", "fields", "principal", "role"),
    ]
) | st.text(max_size=8)
args_strategy = st.dictionaries(arg_keys, json_values, max_size=4)
tool_names = st.sampled_from([*SPECS, "transfer_funds", "PUBLIC_DOC_SEARCH", ""]) | st.text(
    max_size=20
)


def pipeline(tool_name: str, args: Any, env: str) -> tuple[str, bool, bool]:
    spec = SPECS.get(tool_name)
    validated = spec.validate_args(args) if spec else None
    d = decide_action(
        agent=AGENT,
        tool_id=tool_name,
        tool=spec.meta if spec else None,
        args=validated.model_dump(mode="json") if validated else None,
        environment=env,
        risk_policy=RISK_POLICY,
        policy=POLICY_V2,
        now=datetime.now(UTC),
    )
    return d.effect, spec is not None, validated is not None


@settings(max_examples=1500, deadline=None)
@given(tool_names, args_strategy, st.sampled_from(["dev", "staging", "prod"]))
def test_allow_implies_registered_and_valid(tool: str, args: dict, env: str) -> None:
    effect, registered, valid = pipeline(tool, args, env)
    if effect == "ALLOW":
        assert registered and valid
        assert tool != "delete_record"
    if not registered or not valid:
        assert effect == "DENY"


@settings(max_examples=300, deadline=None)
@given(st.text(min_size=1, max_size=256), st.integers(min_value=1, max_value=20))
def test_valid_search_is_allowed_in_dev(query: str, limit: int) -> None:
    assert pipeline("public_doc_search", {"query": query, "limit": limit}, "dev")[0] == "ALLOW"
