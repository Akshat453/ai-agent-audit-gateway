"""API key format and digest (11 §3).

Token: ``agw_<key_id>_<secret>``; key_id = 16 lowercase hex chars (public lookup handle),
secret = 43 base64url chars (32 random bytes). Stored: ``key_id`` and
``SHA-256(TAG("AGW/apikey/v1") || utf8(token))`` only. A fast hash is adequate because the
secret has 256 bits of entropy (ADR-0015).
"""

from __future__ import annotations

import base64
import hashlib
import re
import secrets
from dataclasses import dataclass
from typing import Final

from agw_gateway.crypto.tags import APIKEY_TAG, domain_tag

_TOKEN_RE: Final = re.compile(r"^agw_([0-9a-f]{16})_([A-Za-z0-9_-]{43})$")
_APIKEY_PREFIX: Final = domain_tag(APIKEY_TAG)


def token_digest(token: str) -> bytes:
    return hashlib.sha256(_APIKEY_PREFIX + token.encode("utf-8")).digest()


def parse_token(token: str) -> str | None:
    """Return the key_id if the token is well-formed, else None."""
    m = _TOKEN_RE.fullmatch(token)
    return m.group(1) if m else None


@dataclass(frozen=True)
class IssuedToken:
    key_id: str
    token: str  # shown once; never stored or logged
    digest: bytes

    def __repr__(self) -> str:  # never leak the token through repr/logging
        return f"IssuedToken(key_id={self.key_id!r}, token=<redacted>)"


def issue_token() -> IssuedToken:
    key_id = secrets.token_hex(8)
    secret = base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode("ascii")
    token = f"agw_{key_id}_{secret}"
    return IssuedToken(key_id=key_id, token=token, digest=token_digest(token))
