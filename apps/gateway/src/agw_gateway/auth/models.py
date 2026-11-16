"""The authenticated identity contract (11 §3). Pure; stays the same when mTLS/OIDC arrive."""

from __future__ import annotations

from dataclasses import dataclass
from uuid import UUID


@dataclass(frozen=True)
class AuthenticatedAgent:
    """The ONLY source of agent identity. Never built from request bodies."""

    tenant_id: str
    agent_id: UUID
    name: str
    scopes: frozenset[str]
    active: bool = True
    trust_tier: str | None = None  # trusted | standard | untrusted; None = missing (worst)
    # Phase 8 (ADR-0030): set when the call arrived through an integration (e.g. "mcp:<name>")
    # with an exchanged token. Recorded in the request's context provenance; never authority.
    via: str | None = None
