"""Risk classifier v1 (04 §2).

``level = max(tool.base_risk, score_level, max(mandatory floors that fired))``. Mandatory rules
only ever *raise* the level. Missing or unknown metadata is scored at the most dangerous value
and fires ``MR-MISSING-META`` (floor HIGH). An unregistered tool gets ``HIGH`` +
``MR-MISSING-META`` so its denial still seals promptly (Phase 3).
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum
from typing import Final

from agw_gateway.tools.metadata import (
    OPERATION_TYPES,
    RISK_LEVEL_NAMES,
    SENSITIVITIES,
    ToolMetadata,
)

CLASSIFIER_VERSION: Final = "risk-v1"


class RiskLevel(IntEnum):
    LOW = 0
    MEDIUM = 1
    HIGH = 2
    CRITICAL = 3


_OPERATION_POINTS: Final = {"read": 0, "create": 10, "update": 20, "execute": 30, "delete": 40}
_SENSITIVITY_POINTS: Final = {"public": 0, "internal": 10, "confidential": 25, "restricted": 40}
_ENVIRONMENT_POINTS: Final = {"dev": 0, "staging": 10, "prod": 30}
_EXTERNAL_POINTS: Final = 20
_SENSITIVITY_RANK: Final = {"public": 0, "internal": 1, "confidential": 2, "restricted": 3}


@dataclass(frozen=True)
class RiskAssessment:
    level: RiskLevel
    score: int
    factors: tuple[tuple[str, int], ...]
    mandatory_rule_ids: tuple[str, ...]
    classifier_version: str = CLASSIFIER_VERSION


def score_level(score: int) -> RiskLevel:
    if score < 25:
        return RiskLevel.LOW
    if score < 50:
        return RiskLevel.MEDIUM
    if score < 75:
        return RiskLevel.HIGH
    return RiskLevel.CRITICAL


def _unknown_tool() -> RiskAssessment:
    return RiskAssessment(
        level=RiskLevel.HIGH, score=0, factors=(), mandatory_rule_ids=("MR-MISSING-META",)
    )


def classify(tool: ToolMetadata | None, environment: str) -> RiskAssessment:
    if tool is None:
        return _unknown_tool()

    op_known = tool.operation_type in OPERATION_TYPES
    sens_known = tool.sensitivity in SENSITIVITIES
    base_known = tool.base_risk in RISK_LEVEL_NAMES

    # Unknown values score as the most dangerous value of their factor (fail toward risk).
    op_pts = _OPERATION_POINTS.get(tool.operation_type or "", max(_OPERATION_POINTS.values()))
    sens_pts = _SENSITIVITY_POINTS.get(tool.sensitivity or "", max(_SENSITIVITY_POINTS.values()))
    env_pts = _ENVIRONMENT_POINTS.get(environment, max(_ENVIRONMENT_POINTS.values()))
    ext_pts = _EXTERNAL_POINTS if tool.external_effect else 0
    factors = (
        ("operation_type", op_pts),
        ("sensitivity", sens_pts),
        ("environment", env_pts),
        ("external_effect", ext_pts),
    )
    score = op_pts + sens_pts + env_pts + ext_pts

    fired: list[tuple[str, RiskLevel]] = []
    if tool.operation_type == "delete" and environment == "prod":
        fired.append(("MR-DELETE-PROD", RiskLevel.CRITICAL))
    if tool.tags & {"privilege_change", "credential_access"}:
        fired.append(("MR-PRIVILEGE", RiskLevel.CRITICAL))
    if tool.sensitivity == "restricted" and tool.operation_type != "read":
        fired.append(("MR-RESTRICTED-WRITE", RiskLevel.HIGH))
    sens_rank = _SENSITIVITY_RANK.get(tool.sensitivity or "", 3)
    if tool.external_effect and sens_rank >= _SENSITIVITY_RANK["confidential"]:
        fired.append(("MR-EXTERNAL-TRANSFER", RiskLevel.HIGH))
    if not (op_known and sens_known and base_known):
        fired.append(("MR-MISSING-META", RiskLevel.HIGH))

    base = RiskLevel[tool.base_risk] if tool.base_risk and base_known else RiskLevel.HIGH
    level = max([base, score_level(score), *(floor for _, floor in fired)])
    return RiskAssessment(
        level=level,
        score=score,
        factors=factors,
        mandatory_rule_ids=tuple(rule_id for rule_id, _ in fired),
    )
