"""AGW event schemas and the AGW-CBOR-v1 profile (normative for the gateway).

The verifier (packages/verifier) deliberately does NOT import this package: it re-implements
the codec and hashing from the spec and is cross-checked against the same frozen vectors in
``packages/schemas/test-vectors/``.
"""

from agw_schemas.events import HEADER_MODELS, MODEL_ONLY_TYPES

PHASE1_EVENT_TYPES: tuple[str, ...] = (
    "ACTION_REQUESTED",
    "POLICY_EVALUATED",
    "ACTION_DENIED",
    "APPROVAL_REQUIRED",
    "ACTION_AUTHORIZED",
    "ACTION_DISPATCHED",
    "ACTION_COMPLETED",
    "ACTION_FAILED",
    "ACTION_OUTCOME_UNKNOWN",
    "SECURITY_VIOLATION",
)

__all__ = ["HEADER_MODELS", "MODEL_ONLY_TYPES", "PHASE1_EVENT_TYPES"]
