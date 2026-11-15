"""Policy engine v1 (04 §3-4.4).

Order: system checks (not overridable) -> collect matching rules -> deny-overrides combination
-> mandatory caps. ``matched_rule_ids`` lists every matching rule in document order so an
auditor sees all reasons. Pure function of its explicit inputs: re-running it on recorded
inputs reproduces the decision.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Any, Final, Literal

from agw_gateway.auth.models import AuthenticatedAgent
from agw_gateway.policies.models import PolicyDocument, PolicyRule
from agw_gateway.risk import RiskAssessment, RiskLevel
from agw_gateway.tools.metadata import ToolMetadata

ENGINE_VERSION: Final = "policy-v1"
DecisionEffect = Literal["ALLOW", "DENY", "REQUIRE_APPROVAL"]


class ReasonCode(StrEnum):
    """Stable reason codes. Never contain argument values."""

    TOOL_NOT_REGISTERED = "TOOL_NOT_REGISTERED"
    ARGS_SCHEMA_INVALID = "ARGS_SCHEMA_INVALID"
    ENVIRONMENT_NOT_ALLOWED = "ENVIRONMENT_NOT_ALLOWED"
    SCOPE_MISSING = "SCOPE_MISSING"
    AGENT_DISABLED = "AGENT_DISABLED"
    POLICY_RULE_DENY = "POLICY_RULE_DENY"
    NO_MATCHING_ALLOW = "NO_MATCHING_ALLOW"
    POLICY_REQUIRES_APPROVAL = "POLICY_REQUIRES_APPROVAL"
    CRITICAL_REQUIRES_APPROVAL = "CRITICAL_REQUIRES_APPROVAL"
    HIGH_REQUIRES_APPROVAL = "HIGH_REQUIRES_APPROVAL"


@dataclass(frozen=True)
class EvaluationInput:
    agent: AuthenticatedAgent
    tool: ToolMetadata | None  # None => unknown / disabled tool
    args_valid: bool
    args: Mapping[str, Any] | None  # validated args (None if invalid)
    environment: str  # requested target env
    policy: PolicyDocument  # exact immutable version
    risk: RiskAssessment
    now: datetime  # Phase 4 (approval expiry); unused by v1 rules


@dataclass(frozen=True)
class Decision:
    effect: DecisionEffect
    policy_id: str
    policy_version: int
    matched_rule_ids: tuple[str, ...]
    reasons: tuple[ReasonCode, ...]
    risk: RiskAssessment
    control_ids: tuple[str, ...] = ()
    engine_version: str = ENGINE_VERSION


def _system_check(inp: EvaluationInput) -> tuple[str, ReasonCode] | None:
    """04 §3, evaluated in order; first failure wins."""
    if inp.tool is None:
        return "SYS-TOOL-UNKNOWN", ReasonCode.TOOL_NOT_REGISTERED
    if not inp.args_valid or inp.args is None:
        return "SYS-ARGS-INVALID", ReasonCode.ARGS_SCHEMA_INVALID
    if inp.environment not in inp.tool.environments_allowed:
        return "SYS-ENV-FORBIDDEN", ReasonCode.ENVIRONMENT_NOT_ALLOWED
    if inp.tool.required_scope not in inp.agent.scopes:
        return "SYS-SCOPE-MISSING", ReasonCode.SCOPE_MISSING
    if not inp.agent.active:
        return "SYS-AGENT-DISABLED", ReasonCode.AGENT_DISABLED
    return None


def _matches(rule: PolicyRule, inp: EvaluationInput, tool: ToolMetadata) -> bool:
    m = rule.match
    checks: tuple[tuple[tuple[str, ...] | None, str | None], ...] = (
        (m.tools, tool.tool_id),
        (m.tool_versions, tool.version),
        (m.operation_types, tool.operation_type),
        (m.sensitivities, tool.sensitivity),
        (m.environments, inp.environment),
        (m.risk_levels, inp.risk.level.name),
        (m.agent_ids, str(inp.agent.agent_id)),
    )
    for allowed, actual in checks:
        if allowed is not None and actual not in allowed:
            return False
    return m.scopes_any is None or bool(inp.agent.scopes & set(m.scopes_any))


def evaluate(inp: EvaluationInput) -> Decision:
    policy = inp.policy

    def decide(
        effect: DecisionEffect,
        rule_ids: tuple[str, ...],
        reasons: tuple[ReasonCode, ...],
        controls: tuple[str, ...] = (),
    ) -> Decision:
        return Decision(
            effect=effect,
            policy_id=policy.policy_id,
            policy_version=policy.version,
            matched_rule_ids=rule_ids,
            reasons=reasons,
            risk=inp.risk,
            control_ids=controls,
        )

    failed = _system_check(inp)
    if failed is not None:
        rule_id, reason = failed
        return decide("DENY", (rule_id,), (reason,))
    tool = inp.tool
    assert tool is not None  # noqa: S101  (narrowing; _system_check guarantees it)

    matched = [r for r in policy.rules if _matches(r, inp, tool)]
    rule_ids = tuple(r.rule_id for r in matched)
    controls = tuple(dict.fromkeys(c for r in matched for c in r.control_ids))
    effects = {r.effect for r in matched}

    if "DENY" in effects:
        return decide("DENY", rule_ids, (ReasonCode.POLICY_RULE_DENY,), controls)
    if "REQUIRE_APPROVAL" in effects:
        return decide(
            "REQUIRE_APPROVAL", rule_ids, (ReasonCode.POLICY_REQUIRES_APPROVAL,), controls
        )
    if "ALLOW" not in effects:
        return decide(
            "DENY", (*rule_ids, "default-deny"), (ReasonCode.NO_MATCHING_ALLOW,), controls
        )

    # Mandatory caps (code, not document) - 04 §4.3.
    if inp.risk.level is RiskLevel.CRITICAL:
        return decide(
            "REQUIRE_APPROVAL",
            (*rule_ids, "CAP-CRITICAL-APPROVAL"),
            (ReasonCode.CRITICAL_REQUIRES_APPROVAL,),
            controls,
        )
    if inp.risk.level is RiskLevel.HIGH:
        allow_rules = [r for r in matched if r.effect == "ALLOW"]
        exempt = tool.is_idempotent and all(r.allow_high_without_approval for r in allow_rules)
        if not exempt:
            return decide(
                "REQUIRE_APPROVAL",
                (*rule_ids, "CAP-HIGH-APPROVAL"),
                (ReasonCode.HIGH_REQUIRES_APPROVAL,),
                controls,
            )
    return decide("ALLOW", rule_ids, (), controls)
