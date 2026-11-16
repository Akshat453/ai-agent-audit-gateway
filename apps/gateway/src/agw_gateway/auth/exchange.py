"""Integration clients and RFC 8693 token exchange (Phase 8, ADR-0030 §6).

Why: the MCP authorization spec (2026-07-28, "Token Handling") requires an MCP server to
accept only tokens issued FOR IT (audience = its canonical URI) and forbids passing a client's
token through to another API. So:

* An agent that talks MCP holds an AUDIENCE-BOUND key (``agent_credentials.audience`` = the
  MCP adapter's canonical URI). The gateway API refuses such keys (``Authenticator``).
* The MCP adapter is a confidential client (``integration_clients``, token ``agwi_...``)
  registered for exactly that audience. To act, it exchanges the agent's MCP token at the
  gateway's token endpoint (its issuer) for a short-lived gateway token (``agwx_...``,
  <= 15 min, DB CHECK), bound to the subject credential (revoking the agent's key kills it at
  once) and to the client (recorded as ``via`` in the request's context provenance).
* One fixed error for every refusal (no oracle about which check failed).

Token formats: ``agwi_<16 hex key id>_<43 b64url>`` and ``agwx_<16 hex>_<43 b64url>``;
digests ``SHA-256(TAG("AGW/integration-key/v1") || utf8(token))`` and the API-key digest.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import re
import secrets
from dataclasses import dataclass
from datetime import timedelta
from typing import Any, Final
from uuid import UUID

from sqlalchemy import Engine, func, insert, select

from agw_gateway.auth.service import AuthenticationFailed
from agw_gateway.auth.tokens import parse_token, token_digest
from agw_gateway.crypto.tags import INTEGRATION_KEY_TAG, domain_tag
from agw_gateway.db import tables as t
from agw_gateway.execution.errors import ExchangeRefused
from agw_gateway.ids import uuid7

_INTEGRATION_RE: Final = re.compile(r"^agwi_([0-9a-f]{16})_([A-Za-z0-9_-]{43})$")
_PREFIX: Final = domain_tag(INTEGRATION_KEY_TAG)
_DUMMY: Final = bytes(32)
GRANT_TYPE: Final = "urn:ietf:params:oauth:grant-type:token-exchange"
ACCESS_TOKEN_TYPE: Final = "urn:ietf:params:oauth:token-type:access_token"  # noqa: S105


def integration_digest(token: str) -> bytes:
    return hashlib.sha256(_PREFIX + token.encode("utf-8")).digest()


def _secret() -> str:
    return base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode("ascii")


def new_integration_token() -> tuple[str, str, bytes]:
    key_id = secrets.token_hex(8)
    token = f"agwi_{key_id}_{_secret()}"
    return key_id, token, integration_digest(token)


@dataclass(frozen=True)
class IntegrationClient:
    client_id: UUID
    tenant_id: str
    name: str
    audience: str


class TokenExchange:
    def __init__(self, engine: Engine, ttl: timedelta = timedelta(minutes=5)) -> None:
        self._engine = engine
        self._ttl = ttl

    def authenticate_client(self, authorization: str | None) -> IntegrationClient:
        scheme, _, token = (authorization or "").partition(" ")
        token = token.strip()
        m = _INTEGRATION_RE.fullmatch(token) if scheme.lower() == "bearer" else None
        computed = integration_digest(token)
        if m is None:
            hmac.compare_digest(_DUMMY, computed)
            raise AuthenticationFailed
        with self._engine.connect() as conn:
            row = conn.execute(
                select(t.integration_clients).where(t.integration_clients.c.key_id == m.group(1))
            ).one_or_none()
        stored = bytes(row.key_digest) if row is not None else _DUMMY
        if not hmac.compare_digest(stored, computed) or row is None or row.status != "active":
            raise AuthenticationFailed
        return IntegrationClient(row.client_id, row.tenant_id, row.name, row.audience)

    def exchange(self, client: IntegrationClient, form: dict[str, str]) -> dict[str, Any]:
        if (
            form.get("grant_type") != GRANT_TYPE
            or form.get("subject_token_type", ACCESS_TOKEN_TYPE) != ACCESS_TOKEN_TYPE
        ):
            raise ExchangeRefused
        subject = form.get("subject_token", "")
        key_id = parse_token(subject)
        computed = token_digest(subject)
        if key_id is None:
            hmac.compare_digest(_DUMMY, computed)
            raise ExchangeRefused
        with self._engine.begin() as conn:
            row = conn.execute(
                select(
                    t.agent_credentials.c.credential_id,
                    t.agent_credentials.c.key_digest,
                    t.agent_credentials.c.audience,
                    t.agent_credentials.c.revoked_at,
                    t.agent_credentials.c.expires_at,
                    (
                        t.agent_credentials.c.expires_at.is_(None)
                        | (t.agent_credentials.c.expires_at > func.now())
                    ).label("live"),
                    t.agents.c.agent_id,
                    t.agents.c.tenant_id,
                    t.agents.c.status,
                    t.agents.c.scopes,
                    func.now().label("now"),
                )
                .join(t.agents, t.agents.c.agent_id == t.agent_credentials.c.agent_id)
                .where(t.agent_credentials.c.key_id == key_id)
            ).one_or_none()
            stored = bytes(row.key_digest) if row is not None else _DUMMY
            if (
                not hmac.compare_digest(stored, computed)
                or row is None
                or row.revoked_at is not None
                or not row.live
                or row.status != "active"
                or row.tenant_id != client.tenant_id
                # Audience binding (RFC 8707): the token was issued for THIS client's resource.
                or row.audience != client.audience
            ):
                raise ExchangeRefused
            expires = row.now + self._ttl
            if row.expires_at is not None:
                expires = min(expires, row.expires_at)
            new_key_id = secrets.token_hex(8)
            token = f"agwx_{new_key_id}_{_secret()}"
            conn.execute(
                insert(t.exchanged_tokens).values(
                    token_id=uuid7(),
                    key_id=new_key_id,
                    key_digest=token_digest(token),
                    agent_id=row.agent_id,
                    subject_credential_id=row.credential_id,
                    client_id=client.client_id,
                    created_at=row.now,
                    expires_at=expires,
                )
            )
        return {
            "access_token": token,
            "issued_token_type": ACCESS_TOKEN_TYPE,
            "token_type": "Bearer",
            "expires_in": max(1, int((expires - row.now).total_seconds())),
            "sub": str(row.agent_id),
            "scope": " ".join(sorted(row.scopes)),
        }
