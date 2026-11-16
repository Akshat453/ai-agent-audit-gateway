"""Local-password human authentication (dev) behind an OIDC-ready interface (ADR-0027).

* Passwords: Argon2id (``argon2-cffi`` defaults). Unknown usernames still pay for one Argon2
  verification against a dummy hash, so timing does not reveal which usernames exist.
* Sessions: ``agws_<16 hex id>_<43 base64url>`` (256-bit secret). Stored: id + SHA-256(TAG
  ("AGW/session/v1") || token) only. Presented as ``Authorization: Session <token>``: a
  different scheme AND a different prefix from agent keys (``Bearer agw_...``), and looked up
  in a different table, so an agent credential can never authenticate as a human.
* Every failure is the same ``HumanAuthFailed`` (401, no oracle).

``HumanIdentityProvider`` is the seam for OIDC: an implementation maps a validated ID token to
an ``AuthenticatedHuman`` row; the approval code depends only on the protocol.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import re
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Final, Protocol

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from sqlalchemy import Engine, func, insert, select, update

from agw_gateway.crypto.tags import SESSION_TAG, domain_tag
from agw_gateway.db import tables as t
from agw_gateway.humans.models import ROLES, AuthenticatedHuman
from agw_gateway.ids import uuid7

SESSION_SCHEME: Final = "session"
_SESSION_RE: Final = re.compile(r"^agws_([0-9a-f]{16})_([A-Za-z0-9_-]{43})$")
_PREFIX: Final = domain_tag(SESSION_TAG)
_HASHER: Final = PasswordHasher()
_DUMMY_HASH: Final = _HASHER.hash("agw-dummy-password-for-timing")


class HumanAuthFailed(Exception):
    """Uniform human authentication failure (no detail by design)."""


class HumanIdentityProvider(Protocol):
    def authenticate(self, authorization: str | None) -> AuthenticatedHuman: ...


def hash_password(password: str) -> str:
    if len(password) < 12:
        raise ValueError("password must be at least 12 characters")
    return _HASHER.hash(password)


def session_digest(token: str) -> bytes:
    return hashlib.sha256(_PREFIX + token.encode("utf-8")).digest()


@dataclass(frozen=True)
class IssuedSession:
    session_id: str
    token: str  # returned once to the client; never stored or logged
    expires_at: datetime

    def __repr__(self) -> str:
        return f"IssuedSession(session_id={self.session_id!r}, token=<redacted>)"


class HumanAuthenticator:
    def __init__(self, engine: Engine, *, session_ttl: timedelta = timedelta(hours=8)) -> None:
        self._engine = engine
        self._ttl = session_ttl

    # ---------------------------------------------------------------- login
    def login(self, tenant_id: str, username: str, password: str) -> IssuedSession:
        with self._engine.connect() as conn:
            row = conn.execute(
                select(
                    t.humans.c.human_id,
                    t.humans.c.password_hash,
                    t.humans.c.status,
                ).where(t.humans.c.tenant_id == tenant_id, t.humans.c.username == username)
            ).one_or_none()
        stored = row.password_hash if row is not None else _DUMMY_HASH
        ok: bool
        try:
            ok = _HASHER.verify(stored, password)
        except (VerifyMismatchError, VerificationError, InvalidHashError):
            ok = False
        if row is None or not ok or row.status != "active":
            raise HumanAuthFailed
        session_id = secrets.token_hex(8)
        secret = base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode("ascii")
        token = f"agws_{session_id}_{secret}"
        with self._engine.begin() as conn:
            expires_at = conn.execute(
                insert(t.human_sessions)
                .values(
                    session_pk=uuid7(),
                    session_id=session_id,
                    human_id=row.human_id,
                    token_digest=session_digest(token),
                    expires_at=func.now() + self._ttl,
                )
                .returning(t.human_sessions.c.expires_at)
            ).scalar_one()
        return IssuedSession(session_id=session_id, token=token, expires_at=expires_at)

    def logout(self, human: AuthenticatedHuman, authorization: str | None) -> None:
        token = _session_token(authorization)
        if token is None:
            return
        with self._engine.begin() as conn:
            conn.execute(
                update(t.human_sessions)
                .where(
                    t.human_sessions.c.token_digest == session_digest(token),
                    t.human_sessions.c.human_id == human.human_id,
                    t.human_sessions.c.revoked_at.is_(None),
                )
                .values(revoked_at=func.now())
            )

    # ---------------------------------------------------------------- per request
    def authenticate(self, authorization: str | None) -> AuthenticatedHuman:
        token = _session_token(authorization)
        if token is None:
            raise HumanAuthFailed
        m = _SESSION_RE.fullmatch(token)
        computed = session_digest(token)
        if m is None:
            raise HumanAuthFailed
        query = (
            select(
                t.human_sessions.c.token_digest,
                t.human_sessions.c.revoked_at,
                (t.human_sessions.c.expires_at > func.now()).label("live"),
                t.humans.c.human_id,
                t.humans.c.tenant_id,
                t.humans.c.username,
                t.humans.c.roles,
                t.humans.c.status,
                t.human_sessions.c.stepped_up_at,
                func.extract("epoch", func.now() - t.human_sessions.c.stepped_up_at).label(
                    "step_age"
                ),
            )
            .join(t.humans, t.humans.c.human_id == t.human_sessions.c.human_id)
            .where(t.human_sessions.c.session_id == m.group(1))
        )
        with self._engine.connect() as conn:
            row = conn.execute(query).one_or_none()
        stored = bytes(row.token_digest) if row is not None else bytes(32)
        if (
            row is None
            or not hmac.compare_digest(stored, computed)
            or row.revoked_at is not None
            or not row.live
            or row.status != "active"
        ):
            raise HumanAuthFailed
        return AuthenticatedHuman(
            tenant_id=row.tenant_id,
            human_id=row.human_id,
            username=row.username,
            roles=frozenset(row.roles) & ROLES,
            stepped_up_at=row.stepped_up_at,
            stepped_up_age_seconds=float(row.step_age) if row.step_age is not None else None,
        )

    def step_up(self, human: AuthenticatedHuman, authorization: str | None, password: str) -> None:
        """Re-authenticate the CURRENT session with the password (CRITICAL decisions)."""
        token = _session_token(authorization)
        with self._engine.connect() as conn:
            stored = conn.execute(
                select(t.humans.c.password_hash).where(t.humans.c.human_id == human.human_id)
            ).scalar_one_or_none()
        ok: bool
        try:
            ok = bool(_HASHER.verify(stored or _DUMMY_HASH, password))
        except (VerifyMismatchError, VerificationError, InvalidHashError):
            ok = False
        if not ok or stored is None or token is None:
            raise HumanAuthFailed
        with self._engine.begin() as conn:
            conn.execute(
                update(t.human_sessions)
                .where(
                    t.human_sessions.c.token_digest == session_digest(token),
                    t.human_sessions.c.human_id == human.human_id,
                    t.human_sessions.c.revoked_at.is_(None),
                )
                .values(stepped_up_at=func.now())
            )


def _session_token(authorization: str | None) -> str | None:
    if not authorization:
        return None
    scheme, _, token = authorization.partition(" ")
    token = token.strip()
    if scheme.lower() != SESSION_SCHEME or not token:
        return None
    return token
