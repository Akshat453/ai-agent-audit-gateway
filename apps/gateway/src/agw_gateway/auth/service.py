"""Bearer-token authentication (11 §3).

Every failure (missing, malformed, unknown, revoked, expired, disabled agent) raises the same
``AuthenticationFailed`` -> 401 ``UNAUTHENTICATED``: no oracle. Unknown key ids still pay for a
digest + constant-time compare against a dummy so timing does not reveal which ids exist.
"""

from __future__ import annotations

import hmac

from sqlalchemy import Engine, func, select

from agw_gateway.auth.models import AuthenticatedAgent
from agw_gateway.auth.tokens import parse_token, token_digest
from agw_gateway.db import tables as t

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
        ):
            raise AuthenticationFailed
        return AuthenticatedAgent(
            tenant_id=row.tenant_id,
            agent_id=row.agent_id,
            name=row.name,
            scopes=frozenset(row.scopes),
            active=True,
        )
