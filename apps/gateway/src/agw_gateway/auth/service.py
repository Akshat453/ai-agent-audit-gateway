"""Bearer-token authentication (11 §3).

Every failure (missing, malformed, unknown, revoked, expired, disabled agent) raises the same
``AuthenticationFailed`` -> 401 ``UNAUTHENTICATED``: no oracle. Unknown key ids still pay for a
digest + constant-time compare against a dummy so timing does not reveal which ids exist.
"""

from __future__ import annotations

import hmac
import re

from sqlalchemy import Engine, func, select

from agw_gateway.auth.models import AuthenticatedAgent
from agw_gateway.auth.tokens import parse_token, token_digest
from agw_gateway.db import tables as t

EXCHANGED_RE = re.compile(r"^agwx_([0-9a-f]{16})_([A-Za-z0-9_-]{43})$")

_DUMMY_DIGEST = token_digest("agw_0000000000000000_" + "A" * 43)


class AuthenticationFailed(Exception):
    """Uniform authentication failure (no detail by design)."""


class Authenticator:
    def __init__(self, engine: Engine) -> None:
        self._engine = engine

    def authenticate(self, authorization: str | None) -> AuthenticatedAgent:
        if not authorization:
            raise AuthenticationFailed
        scheme, _, token = authorization.partition(" ")
        if scheme.lower() != "bearer" or not token:
            raise AuthenticationFailed
        token = token.strip()
        if token.startswith("agwx_"):
            return self._authenticate_exchanged(token)
        key_id = parse_token(token)
        computed = token_digest(token)
        if key_id is None:
            hmac.compare_digest(_DUMMY_DIGEST, computed)
            raise AuthenticationFailed

        query = (
            select(
                t.agent_credentials.c.key_digest,
                t.agent_credentials.c.revoked_at,
                (
                    t.agent_credentials.c.expires_at.is_(None)
                    | (t.agent_credentials.c.expires_at > func.now())
                ).label("not_expired"),
                t.agents.c.agent_id,
                t.agents.c.tenant_id,
                t.agents.c.name,
                t.agents.c.scopes,
                t.agents.c.status,
                t.agents.c.trust_tier,
                t.agent_credentials.c.audience,
            )
            .join(t.agents, t.agents.c.agent_id == t.agent_credentials.c.agent_id)
            .where(t.agent_credentials.c.key_id == key_id)
        )
        with self._engine.connect() as conn:
            row = conn.execute(query).one_or_none()

        stored = bytes(row.key_digest) if row is not None else _DUMMY_DIGEST
        digest_ok = hmac.compare_digest(stored, computed)
        if (
            row is None
            or not digest_ok
            or row.revoked_at is not None
            or not row.not_expired
            or row.status != "active"
            or row.tenant_id.startswith("_")  # reserved system tenants (ADR-0019)
            # Phase 8: a key bound to another resource (an MCP adapter) is not valid here.
            or row.audience is not None
        ):
            raise AuthenticationFailed
        return AuthenticatedAgent(
            tenant_id=row.tenant_id,
            agent_id=row.agent_id,
            name=row.name,
            scopes=frozenset(row.scopes),
            active=True,
            trust_tier=row.trust_tier,
        )

    def _authenticate_exchanged(self, token: str) -> AuthenticatedAgent:
        """Short-lived token from RFC 8693 exchange (Phase 8). Valid only while it is unexpired,
        its SUBJECT credential is still valid and the integration client is active."""
        m = EXCHANGED_RE.fullmatch(token)
        computed = token_digest(token)
        if m is None:
            hmac.compare_digest(_DUMMY_DIGEST, computed)
            raise AuthenticationFailed
        x, cred, ag, ic = (
            t.exchanged_tokens,
            t.agent_credentials,
            t.agents,
            t.integration_clients,
        )
        query = (
            select(
                x.c.key_digest,
                (x.c.expires_at > func.now()).label("live"),
                cred.c.revoked_at,
                (cred.c.expires_at.is_(None) | (cred.c.expires_at > func.now())).label("cred_live"),
                ag.c.agent_id,
                ag.c.tenant_id,
                ag.c.name,
                ag.c.scopes,
                ag.c.status,
                ag.c.trust_tier,
                ic.c.name.label("client_name"),
                ic.c.status.label("client_status"),
            )
            .join(cred, cred.c.credential_id == x.c.subject_credential_id)
            .join(ag, ag.c.agent_id == x.c.agent_id)
            .join(ic, ic.c.client_id == x.c.client_id)
            .where(x.c.key_id == m.group(1))
        )
        with self._engine.connect() as conn:
            row = conn.execute(query).one_or_none()
        stored = bytes(row.key_digest) if row is not None else _DUMMY_DIGEST
        if (
            not hmac.compare_digest(stored, computed)
            or row is None
            or not row.live
            or row.revoked_at is not None
            or not row.cred_live
            or row.status != "active"
            or row.client_status != "active"
        ):
            raise AuthenticationFailed
        return AuthenticatedAgent(
            tenant_id=row.tenant_id,
            agent_id=row.agent_id,
            name=row.name,
            scopes=frozenset(row.scopes),
            active=True,
            trust_tier=row.trust_tier,
            via=f"mcp:{row.client_name}",
        )
