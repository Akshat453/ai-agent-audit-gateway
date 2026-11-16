"""What a resolved delegation chain allows (ADR-0030 §3). Pure: consumed by the policy engine.

Effective permission is the INTERSECTION over the whole chain, never a union:

* scopes  = child's own scopes ∩ every link's scopes ∩ every issuer's CURRENT scopes
* tools   = ∩ of every link's tool allowlist
* max risk = the minimum over the chain
* expiry, revocation, use counts: every link must be live

``failure`` is set when the chain is unusable (forged, expired, revoked, exhausted, too deep,
not for this agent, an issuer disabled). The engine then DENYs with that reason; nothing else
about the chain is trusted.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final, Literal

FailureCode = Literal[
    "DELEGATION_INVALID",
    "DELEGATION_NOT_FOR_AGENT",
    "DELEGATION_EXPIRED",
    "DELEGATION_REVOKED",
    "DELEGATION_EXHAUSTED",
    "DELEGATION_DEPTH_EXCEEDED",
    "DELEGATION_ISSUER_INACTIVE",
]
FAILURE_CODES: Final[frozenset[str]] = frozenset(FailureCode.__args__)  # type: ignore[attr-defined]


@dataclass(frozen=True)
class DelegationConstraint:
    failure: FailureCode | None
    depth: int
    scopes: frozenset[str] = frozenset()  # chain ∩ (issuers' current scopes); NOT the child's
    tools: frozenset[str] = frozenset()
    max_risk: str = "LOW"

    @classmethod
    def failed(cls, code: FailureCode, depth: int = 0) -> DelegationConstraint:
        return cls(failure=code, depth=depth)
