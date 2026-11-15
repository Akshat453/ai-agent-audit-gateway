"""Agent authentication (11 §3, ADR-0015)."""

from agw_gateway.auth.models import AuthenticatedAgent
from agw_gateway.auth.service import AuthenticationFailed, Authenticator
from agw_gateway.auth.tokens import IssuedToken, issue_token, parse_token, token_digest

__all__ = [
    "AuthenticatedAgent",
    "AuthenticationFailed",
    "Authenticator",
    "IssuedToken",
    "issue_token",
    "parse_token",
    "token_digest",
]
