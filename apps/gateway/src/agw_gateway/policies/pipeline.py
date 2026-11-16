"""The pure decision pipeline: risk -> policy -> decision (ADR-0026).

Used by the action service, the labeled-dataset regression (experiments/risk) and the tests,
so all of them exercise exactly the production path. No I/O, clock or randomness: ``now`` and
both immutable policy versions are passed in.
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
from typing import Any

from agw_gateway.auth.models import AuthenticatedAgent
from agw_gateway.policies.engine import Decision, EvaluationInput, evaluate
from agw_gateway.policies.models import PolicyDocument
from agw_gateway.risk import RiskPolicy, build_context
from agw_gateway.risk import evaluate as evaluate_risk
from agw_gateway.tools.metadata import ToolMetadata


def decide_action(
    *,
    agent: AuthenticatedAgent,
    tool_id: str,
    tool: ToolMetadata | None,
    args: Mapping[str, Any] | None,
    environment: str | None,
    risk_policy: RiskPolicy,
    policy: PolicyDocument,
    now: datetime,
    delegation_depth: int | None = None,
) -> Decision:
    """``args`` are the VALIDATED args (JSON mode), or None if validation failed."""
    risk = evaluate_risk(
        build_context(
            tool_id=tool_id,
            tool=tool,
            args=args,
            environment=environment,
            agent_scopes=agent.scopes,
            agent_trust_tier=agent.trust_tier,
            delegation_depth=delegation_depth,
        ),
        risk_policy,
    )
    return evaluate(
        EvaluationInput(
            agent=agent,
            tool=tool,
            args_valid=args is not None,
            args=args,
            environment=environment or "",
            policy=policy,
            risk=risk,
            now=now,
        )
    )
