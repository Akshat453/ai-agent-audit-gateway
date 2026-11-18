"""The authenticated human contract. Pure; unchanged when OIDC replaces local passwords."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Final
from uuid import UUID

# C1 (ADR-0034): coding approvals are routed by path owner to these approving roles.
APPROVING_ROLES: Final = frozenset({"approver", "security", "ledger_lead", "maintainer"})
ROLES: Final = frozenset({"admin", "auditor"}) | APPROVING_ROLES
VIEWER_ROLES: Final = frozenset({"auditor", "admin"}) | APPROVING_ROLES


@dataclass(frozen=True)
class AuthenticatedHuman:
    """The ONLY source of approver identity. Never built from request bodies."""

    tenant_id: str
    human_id: UUID
    username: str
    roles: frozenset[str]
    auth_method: str = "local-password"  # "oidc:<issuer>" later
    # Phase 9 (ADR-0031): when THIS session last re-authenticated (step-up), DB clock.
    stepped_up_at: datetime | None = None
    stepped_up_age_seconds: float | None = None  # computed by the DB at authentication

    def has(self, role: str) -> bool:
        return role in self.roles
