"""What a connector classification allows for one call (C2, ADR-0035). Pure: consumed by the
policy engine exactly like a delegation constraint.

The engine DENYs on ``failure`` (unclassified, disabled, agent not allowed, argument
constraint violated, approval rule "deny"), and raises the effect to REQUIRE_APPROVAL when the
rule is "always". A classification can only ever make a decision stricter than the risk
pipeline's own result, never looser.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Final, Literal
from uuid import UUID

from agw_gateway.connectors.manifest import ActionClassification

FailureCode = Literal[
    "CONNECTOR_ACTION_UNCLASSIFIED",
    "CONNECTOR_DISABLED",
    "CONNECTOR_AGENT_NOT_ALLOWED",
    "CONNECTOR_ARG_CONSTRAINT",
    "CONNECTOR_ACTION_DENIED",
    "CONNECTOR_CONTENT_DENIED",
]
DEVICE_SCOPE: Final = "coding:device"


@dataclass(frozen=True)
class Assessment:
    """C3 (ADR-0036): what a connector found by inspecting a call's CONTENT before the
    decision (e.g. git_submit_change: the full combined diff through the C1 coding policy).
    ``level`` raises the risk floor, ``deny`` denies, ``facts`` go into the evidence payload
    (digests and shas only, never content)."""

    level: str | None = None
    deny: bool = False
    rule_ids: tuple[str, ...] = ()
    facts: Mapping[str, Any] | None = None
    # A content-driven ask (C1 policy "ask" on the diff): approval by this role; a CRITICAL
    # finding is approvable (four-eyes, step-up) instead of the default CRITICAL deny.
    approver_role: str | None = None
    critical_approval: bool = False


@dataclass(frozen=True)
class ConnectorConstraint:
    failure: FailureCode | None
    approval_always: bool = False
    policy_ref: str = ""  # "cx:<slug>@v<n>" recorded in matched rule ids
    approver_role: str = "approver"
    content_rules: tuple[str, ...] = ()  # C3: rule ids from the content assessment
    critical_exception: bool = False  # C3: CRITICAL by content -> approval, not deny


def evaluate_constraint(
    *,
    slug: str,
    policy_version: int,
    status: str,
    entry: ActionClassification | None,
    agent_id: UUID,
    agent_scopes: frozenset[str],
    args: Mapping[str, Any] | None,
    assessment: Assessment | None = None,
) -> ConnectorConstraint:
    ref = f"cx:{slug}@v{policy_version}"
    rules = assessment.rule_ids if assessment is not None else ()
    if status == "disabled":
        return ConnectorConstraint("CONNECTOR_DISABLED", policy_ref=ref)
    if entry is None:
        return ConnectorConstraint("CONNECTOR_ACTION_UNCLASSIFIED", policy_ref=ref)
    if entry.approval == "deny":
        return ConnectorConstraint("CONNECTOR_ACTION_DENIED", policy_ref=ref)
    allowed = entry.allowed_agents
    if not (
        "*" in allowed
        or ("devices" in allowed and DEVICE_SCOPE in agent_scopes)
        or str(agent_id) in allowed
    ):
        return ConnectorConstraint("CONNECTOR_AGENT_NOT_ALLOWED", policy_ref=ref)
    if args is not None and not args_ok(entry, args):
        return ConnectorConstraint("CONNECTOR_ARG_CONSTRAINT", policy_ref=ref)
    if assessment is not None and assessment.deny:
        return ConnectorConstraint("CONNECTOR_CONTENT_DENIED", policy_ref=ref, content_rules=rules)
    return ConnectorConstraint(
        None,
        approval_always=entry.approval == "always",
        policy_ref=ref,
        approver_role=(
            assessment.approver_role
            if assessment and assessment.approver_role
            else entry.approver_role
        ),
        content_rules=rules,
        critical_exception=bool(assessment and assessment.critical_approval),
    )


def args_ok(entry: ActionClassification, args: Mapping[str, Any]) -> bool:
    for name, c in entry.constraints.items():
        value = args.get(name)
        if value is None:
            continue  # absent optional field; the schema decides whether it is required
        values = value if isinstance(value, list) else [value]
        for v in values:
            text = str(v)
            if c.allowed is not None and text not in c.allowed:
                return False
            if c.pattern is not None and not re.fullmatch(c.pattern, text):
                return False
            if c.max_length is not None and len(text) > c.max_length:
                return False
            if isinstance(v, int) and not isinstance(v, bool):
                if c.min is not None and v < c.min:
                    return False
                if c.max is not None and v > c.max:
                    return False
    return True
