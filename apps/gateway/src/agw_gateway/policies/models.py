"""Policy document model (04 §4.1). Loading fails closed on anything unexpected."""

from __future__ import annotations

import json
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

Effect = Literal["ALLOW", "DENY", "REQUIRE_APPROVAL"]
_ID = r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$"


class PolicyLoadError(ValueError):
    """The policy document is invalid. The gateway must not evaluate with it."""


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class RuleMatch(_Strict):
    """All present fields must match; omitted = wildcard. Unknown fields fail the load."""

    tools: tuple[str, ...] | None = None
    tool_versions: tuple[str, ...] | None = None
    operation_types: tuple[Literal["read", "create", "update", "delete", "execute"], ...] | None = (
        None
    )
    sensitivities: (
        tuple[Literal["public", "internal", "confidential", "restricted"], ...] | None
    ) = None
    environments: tuple[Literal["dev", "staging", "prod"], ...] | None = None
    risk_levels: tuple[Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"], ...] | None = None
    agent_ids: tuple[str, ...] | None = None
    scopes_any: tuple[str, ...] | None = None


class PolicyRule(_Strict):
    rule_id: str = Field(pattern=_ID)
    effect: Effect
    match: RuleMatch = Field(default_factory=RuleMatch)
    control_ids: tuple[str, ...] = ()
    allow_high_without_approval: bool = False
    # Phase 4 (ADR-0026): CRITICAL is DENY unless a matching exception rule exists; even then
    # the result is REQUIRE_APPROVAL, never ALLOW.
    critical_exception: bool = False

    @model_validator(mode="after")
    def _exception_requires_approval(self) -> PolicyRule:
        if self.critical_exception and self.effect != "REQUIRE_APPROVAL":
            raise ValueError("critical_exception rules must have effect REQUIRE_APPROVAL")
        return self


class PolicyDocument(_Strict):
    policy_id: str = Field(pattern=_ID)
    version: int = Field(ge=1)
    default_effect: Literal["DENY"]  # MUST be DENY (ADR-0001); anything else fails the load.
    rules: tuple[PolicyRule, ...]

    @model_validator(mode="after")
    def _unique_rule_ids(self) -> PolicyDocument:
        ids = [r.rule_id for r in self.rules]
        if len(ids) != len(set(ids)):
            raise ValueError("duplicate rule_id")
        return self


def load_policy_document(document: Any) -> PolicyDocument:
    """Validate a stored JSON document (lists are accepted for tuples)."""
    try:
        return PolicyDocument.model_validate_json(json.dumps(document))
    except ValidationError as exc:
        locs = sorted({".".join(str(p) for p in e["loc"]) for e in exc.errors()})
        raise PolicyLoadError("invalid policy document at: " + ", ".join(locs)) from None
