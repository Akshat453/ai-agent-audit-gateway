"""AGW event schemas and the AGW-CBOR-v1 profile.

Phase 1 stub. The encoder/validator arrives in Phase 2 (docs/gateway/05 §6, 06), the frozen
test vectors in Phase 3. Event-type names are the only shared contract today.
"""

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
