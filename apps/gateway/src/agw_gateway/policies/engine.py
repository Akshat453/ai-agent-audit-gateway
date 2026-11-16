"""Policy engine v2 (04 §3-4, ADR-0026): risk -> policy -> decision.

Order:

1. System checks (not overridable): unknown tool, invalid args, forbidden environment,
   missing scope, disabled agent -> DENY.
2. Three sources each propose an effect; the MOST RESTRICTIVE wins (DENY > REQUIRE_APPROVAL >
   ALLOW), so no source can loosen another:
   a. the risk policy's mandatory rules (``risk.forced_effect``);
   b. the policy document's rules, deny-overrides, default DENY when nothing matches;
   c. the per-level default: LOW allow; MEDIUM per tool config (``medium_effect``, missing ->
      approval); HIGH approval (unless the Phase 1 idempotent exemption applies); CRITICAL
      DENY unless a matching ``critical_exception`` rule exists (then still approval).
3. ``matched_rule_ids`` lists every contributing rule so an auditor sees all reasons;
   ``reasons`` lists the reason of every source that produced the final effect.

Pure function of its explicit inputs: re-running it on recorded inputs reproduces the decision.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Any, Final, Literal

from agw_gateway.auth.models import AuthenticatedAgent
from agw_gateway.policies.models import PolicyDocument, PolicyRule
from agw_gateway.risk import RiskLevel, RiskResult
from agw_gateway.tools.metadata import ToolMetadata

ENGINE_VERSION: Final = "policy-v2"
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
    MEDIUM_REQUIRES_APPROVAL = "MEDIUM_REQUIRES_APPROVAL"
    CRITICAL_DENIED = "CRITICAL_DENIED"
    RISK_RULE_DENY = "RISK_RULE_DENY"
    RISK_RULE_REQUIRES_APPROVAL = "RISK_RULE_REQUIRES_APPROVAL"


@dataclass(frozen=True)
class EvaluationInput:
    agent: AuthenticatedAgent
    tool: ToolMetadata | None  # None => unknown / disabled tool
    args_valid: bool
    args: Mapping[str, Any] | None  # validated args (None if invalid)
    environment: str  # requested target env
    policy: PolicyDocument  # exact immutable version
    risk: RiskResult
    now: datetime  # approval expiry (Phase 5); unused by v2 rules


@dataclass(frozen=True)
class Decision:
    effect: DecisionEffect
    policy_id: str
    policy_version: int
    matched_rule_ids: tuple[str, ...]
    reasons: tuple[ReasonCode, ...]
    risk: RiskResult
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


_RANK: Final[dict[str, int]] = {"ALLOW": 0, "REQUIRE_APPROVAL": 1, "DENY": 2}


def _level_default(
    inp: EvaluationInput, tool: ToolMetadata, matched: list[PolicyRule]
) -> tuple[DecisionEffect, str | None, ReasonCode | None]:
    level = inp.risk.level
    if level is RiskLevel.LOW:
        return "ALLOW", None, None
    if level is RiskLevel.MEDIUM:
        if tool.medium_effect == "ALLOW":
            return "ALLOW", None, None
        return "REQUIRE_APPROVAL", "LVL-MEDIUM-APPROVAL", ReasonCode.MEDIUM_REQUIRES_APPROVAL
    if level is RiskLevel.HIGH:
        allow_rules = [r for r in matched if r.effect == "ALLOW"]
        exempt = (
            tool.is_idempotent
            and bool(allow_rules)
            and all(r.allow_high_without_approval for r in allow_rules)
        )
        if exempt:
            return "ALLOW", None, None
        return "REQUIRE_APPROVAL", "CAP-HIGH-APPROVAL", ReasonCode.HIGH_REQUIRES_APPROVAL
    if any(r.critical_exception for r in matched):
        return (
            "REQUIRE_APPROVAL",
            "CAP-CRITICAL-EXCEPTION",
            ReasonCode.CRITICAL_REQUIRES_APPROVAL,
        )
    return "DENY", "CAP-CRITICAL-DENY", ReasonCode.CRITICAL_DENIED


def evaluate(inp: EvaluationInput) -> Decision:
    policy = inp.policy

    failed = _system_check(inp)
    if failed is not None:
        rule_id, reason = failed
        return Decision(
            effect="DENY",
            policy_id=policy.policy_id,
            policy_version=policy.version,
            matched_rule_ids=(rule_id,),
            reasons=(reason,),
            risk=inp.risk,
            control_ids=inp.risk.control_ids,
        )
    tool = inp.tool
    assert tool is not None  # noqa: S101  (narrowing; _system_check guarantees it)

    # (a) risk policy mandatory rules
    risk = inp.risk
    risk_effect: DecisionEffect = risk.forced_effect or "ALLOW"
    risk_reason = (
        ReasonCode.RISK_RULE_DENY
        if risk.forced_effect == "DENY"
        else ReasonCode.RISK_RULE_REQUIRES_APPROVAL
    )

    # (b) policy document, deny-overrides, default deny
    matched = [r for r in policy.rules if _matches(r, inp, tool)]
    doc_ids = [r.rule_id for r in matched]
    effects = {r.effect for r in matched}
    doc_effect: DecisionEffect
    doc_reason: ReasonCode | None = None
    if "DENY" in effects:
        doc_effect, doc_reason = "DENY", ReasonCode.POLICY_RULE_DENY
    elif "REQUIRE_APPROVAL" in effects:
        doc_effect, doc_reason = "REQUIRE_APPROVAL", ReasonCode.POLICY_REQUIRES_APPROVAL
    elif "ALLOW" in effects:
        doc_effect = "ALLOW"
    else:
        doc_effect, doc_reason = "DENY", ReasonCode.NO_MATCHING_ALLOW
        doc_ids.append("default-deny")

    # (c) per-level default
    lvl_effect, lvl_rule, lvl_reason = _level_default(inp, tool, matched)

    final: DecisionEffect = max((risk_effect, doc_effect, lvl_effect), key=lambda e: _RANK[e])
    rule_ids = [*risk.forcing_rules, *doc_ids]
    if lvl_rule is not None:
        rule_ids.append(lvl_rule)
    reasons: list[ReasonCode] = []
    if final != "ALLOW":
        sources: tuple[tuple[DecisionEffect, ReasonCode | None], ...] = (
            (risk_effect, risk_reason),
            (doc_effect, doc_reason),
            (lvl_effect, lvl_reason),
        )
        for effect, why in sources:
            if effect == final and why is not None and why not in reasons:
                reasons.append(why)
    controls = tuple(
        dict.fromkeys([*risk.control_ids, *(c for r in matched for c in r.control_ids)])
    )
    return Decision(
        effect=final,
        policy_id=policy.policy_id,
        policy_version=policy.version,
        matched_rule_ids=tuple(rule_ids),
        reasons=tuple(reasons),
        risk=risk,
        control_ids=controls,
    )
