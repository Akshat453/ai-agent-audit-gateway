"""Pure tool metadata (no I/O imports), shared by the registry, risk classifier and policy engine.

Risk-relevant attributes are typed ``str | None`` on purpose: a value that is missing or not in
the known vocabulary is *not* rejected here, it raises risk via ``MR-MISSING-META`` (04 §2.2).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Final, Literal

OperationType = Literal["read", "create", "update", "delete", "execute"]
Sensitivity = Literal["public", "internal", "confidential", "restricted"]
EnvironmentName = Literal["dev", "staging", "prod"]

OPERATION_TYPES: Final = frozenset({"read", "create", "update", "delete", "execute"})
SENSITIVITIES: Final = frozenset({"public", "internal", "confidential", "restricted"})
RISK_LEVEL_NAMES: Final = frozenset({"LOW", "MEDIUM", "HIGH", "CRITICAL"})
ENVIRONMENTS: Final = frozenset({"dev", "staging", "prod"})
DATA_CLASSIFICATIONS: Final = frozenset({"public", "internal", "confidential", "secret", "pii"})
MEDIUM_EFFECTS: Final = frozenset({"ALLOW", "REQUIRE_APPROVAL"})

TOOL_ID_RE: Final = re.compile(r"^[a-z][a-z0-9_]{1,63}$")
SEMVER_RE: Final = re.compile(r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$")


@dataclass(frozen=True)
class ToolMetadata:
    tool_id: str
    version: str
    operation_type: str | None
    sensitivity: str | None
    base_risk: str | None
    environments_allowed: frozenset[str]
    required_scope: str
    is_idempotent: bool
    external_effect: bool
    target_field: str | None = None
    tags: frozenset[str] = field(default_factory=frozenset)
    # Phase 4 risk attributes (04 §2, ADR-0026). Missing => worst value for that factor.
    data_classification: str | None = None  # public < internal < confidential < secret/pii
    reversible: bool | None = None  # can the effect be undone by a normal operation?
    destination_field: str | None = None  # arg holding recipient(s)/destination URL(s)
    volume_field: str | None = None  # arg holding the record/recipient count (int or list)
    medium_effect: str | None = None  # ALLOW | REQUIRE_APPROVAL at MEDIUM (missing => approval)

    def risk_attributes(self) -> dict[str, object]:
        """The Phase 4 attributes as stored in ``tool_registry.risk_attributes``."""
        return {
            "data_classification": self.data_classification,
            "reversible": self.reversible,
            "destination_field": self.destination_field,
            "volume_field": self.volume_field,
            "medium_effect": self.medium_effect,
        }

    def __post_init__(self) -> None:
        if not TOOL_ID_RE.fullmatch(self.tool_id):
            raise ValueError("tool_id must match ^[a-z][a-z0-9_]{1,63}$")
        if not SEMVER_RE.fullmatch(self.version):
            raise ValueError("version must be semver MAJOR.MINOR.PATCH")
        if not self.required_scope:
            raise ValueError("required_scope must be non-empty")
