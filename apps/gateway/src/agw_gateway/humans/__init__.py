"""Human identities (approvers, admins, auditors). Separate from agents by construction:
separate table, separate token format, separate ``Authorization: Session`` scheme (ADR-0027).
"""

from agw_gateway.humans.models import ROLES, AuthenticatedHuman
from agw_gateway.humans.service import (
    HumanAuthenticator,
    HumanAuthFailed,
    HumanIdentityProvider,
    IssuedSession,
    hash_password,
)

__all__ = [
    "ROLES",
    "AuthenticatedHuman",
    "HumanAuthFailed",
    "HumanAuthenticator",
    "HumanIdentityProvider",
    "IssuedSession",
    "hash_password",
]
