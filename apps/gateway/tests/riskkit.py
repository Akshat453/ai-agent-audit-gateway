"""Pure helpers for risk/policy tests (no database)."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from agw_gateway.auth.models import AuthenticatedAgent
from agw_gateway.policies import Decision, load_policy_document
from agw_gateway.policies.default_policy import DEFAULT_POLICY_V2
from agw_gateway.policies.models import PolicyDocument
from agw_gateway.policies.pipeline import decide_action
from agw_gateway.risk import RiskPolicy, load_risk_policy_toml
from agw_gateway.risk_store import default_risk_policy_text
from agw_gateway.tools.demo import demo_tool_specs
from agw_gateway.tools.metadata import ToolMetadata

RISK_POLICY: RiskPolicy = load_risk_policy_toml(default_risk_policy_text())
POLICY_V2: PolicyDocument = load_policy_document(DEFAULT_POLICY_V2)
SPECS = {s.meta.tool_id: s for s in demo_tool_specs()}
ALL_TOOL_SCOPES = frozenset(s.meta.required_scope for s in SPECS.values())
NOW = datetime(2026, 11, 15, tzinfo=UTC)


def agent(
    scopes: frozenset[str] = ALL_TOOL_SCOPES, tier: str | None = "standard", active: bool = True
) -> AuthenticatedAgent:
    return AuthenticatedAgent(
        "demo", uuid.UUID(int=7), "demo-agent", scopes, active=active, trust_tier=tier
    )


def decide(
    tool_id: str,
    args: Any,
    env: str | None = "dev",
    *,
    scopes: frozenset[str] = ALL_TOOL_SCOPES,
    tier: str | None = "standard",
    depth: int | None = None,
    tool: ToolMetadata | None = None,
    policy: PolicyDocument = POLICY_V2,
    risk_policy: RiskPolicy = RISK_POLICY,
    active: bool = True,
) -> Decision:
    """Run the production pipeline. ``tool`` overrides the registered metadata."""
    spec = SPECS.get(tool_id)
    meta = tool if tool is not None else (spec.meta if spec else None)
    validated = spec.validate_args(args) if spec is not None else None
    if tool is not None and spec is None:
        validated_args: Any = args  # synthetic tool: args taken as already validated
    else:
        validated_args = validated.model_dump(mode="json") if validated is not None else None
    return decide_action(
        agent=agent(scopes, tier, active),
        tool_id=tool_id,
        tool=meta,
        args=validated_args,
        environment=env,
        risk_policy=risk_policy,
        policy=policy,
        now=NOW,
        delegation_depth=depth,
    )
