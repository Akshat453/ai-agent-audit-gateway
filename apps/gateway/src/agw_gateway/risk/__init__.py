"""Risk classifier v1 (docs/gateway/04 §2). Pure: no I/O, clock, randomness or model calls."""

from agw_gateway.risk.classifier import (
    CLASSIFIER_VERSION,
    RiskAssessment,
    RiskLevel,
    classify,
)

__all__ = ["CLASSIFIER_VERSION", "RiskAssessment", "RiskLevel", "classify"]
