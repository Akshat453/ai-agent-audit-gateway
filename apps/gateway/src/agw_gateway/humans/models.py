"""The authenticated human contract. Pure; unchanged when OIDC replaces local passwords."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Final
from uuid import UUID

ROLES: Final = frozenset({"approver", "admin", "auditor"})


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
