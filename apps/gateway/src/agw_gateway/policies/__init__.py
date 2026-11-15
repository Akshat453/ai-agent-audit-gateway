"""Policy engine v1 (docs/gateway/04 §3-4). Pure: no I/O, clock, randomness or LLM (ADR-0002)."""

from agw_gateway.policies.engine import (
    ENGINE_VERSION,
    Decision,
    EvaluationInput,
    ReasonCode,
    evaluate,
)
from agw_gateway.policies.models import PolicyDocument, PolicyLoadError, load_policy_document

__all__ = [
    "ENGINE_VERSION",
    "Decision",
    "EvaluationInput",
    "PolicyDocument",
    "PolicyLoadError",
    "ReasonCode",
    "evaluate",
    "load_policy_document",
]
