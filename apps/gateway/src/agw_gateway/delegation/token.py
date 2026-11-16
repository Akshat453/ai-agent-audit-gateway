"""Delegation token codec (ADR-0030 §2). Pure: no I/O.

Wire form (URL-safe, no padding)::

    agwd1.<b64url(claims_cbor)>.<b64url(ed25519_signature)>

``claims_cbor`` is AGW-CBOR-v1 (deterministic, RFC 8949 §4.2) of::

    {"v": 1, "id": bstr16, "ten": tenant, "iss": bstr16 issuing (parent) agent,
     "sub": bstr16 child agent, "dep": uint depth (1 = direct from the root agent),
     "par": bstr32 parent token hash (absent at depth 1), "sc": [scope, ...] sorted,
     "tl": [tool_id, ...] sorted, "mr": "LOW"|"MEDIUM"|"HIGH"|"CRITICAL",
     "exp": uint us, "mu": uint max uses, "iat": uint us, "kid": key id}

signature = Ed25519(gateway delegation key, TAG("AGW/delegation-sig/v1") || claims_cbor)
token_hash = SHA-256(TAG("AGW/delegation-token/v1") || claims_cbor || signature)

The signature makes a forged or edited token fail before any database lookup and lets an
auditor check issuance offline. The database row stays authoritative for revocation, use
counts and the CURRENT scopes of every agent in the chain (re-checked at every use).
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import re
from dataclasses import dataclass
from typing import Any, Final
from uuid import UUID

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from agw_gateway.crypto.canonical import CanonicalError, decode, encode
from agw_gateway.crypto.tags import DELEGATION_SIG_TAG, DELEGATION_TOKEN_TAG, domain_tag

PREFIX: Final = "agwd1"
MAX_TOKEN_CHARS: Final = 4096
LEVELS: Final = ("LOW", "MEDIUM", "HIGH", "CRITICAL")
_SIG: Final = domain_tag(DELEGATION_SIG_TAG)
_HASH: Final = domain_tag(DELEGATION_TOKEN_TAG)
_B64: Final = re.compile(r"^[A-Za-z0-9_-]+$")
_SCOPE: Final = re.compile(r"^[A-Za-z0-9_.:\-]{1,128}$")
_TOOL: Final = re.compile(r"^[a-z][a-z0-9_]{1,63}$")
_KEYS: Final = frozenset(
    {"v", "id", "ten", "iss", "sub", "dep", "par", "sc", "tl", "mr", "exp", "mu", "iat", "kid"}
)


class TokenInvalid(ValueError):
    """Malformed, non-canonical, unknown key, or bad signature. The message is a fixed code."""


@dataclass(frozen=True)
class Claims:
    delegation_id: UUID
    tenant: str
    issuer: UUID
    subject: UUID
    depth: int
    parent_hash: bytes | None
    scopes: tuple[str, ...]
    tools: tuple[str, ...]
    max_risk: str
    expires_us: int
    max_uses: int
    issued_us: int
    key_id: str

    def __post_init__(self) -> None:
        if not 1 <= self.depth <= 8:
            raise TokenInvalid("DEPTH_RANGE")
        if (self.depth == 1) != (self.parent_hash is None):
            raise TokenInvalid("PARENT_HASH")
        if self.parent_hash is not None and len(self.parent_hash) != 32:
            raise TokenInvalid("PARENT_HASH")
        if list(self.scopes) != sorted(set(self.scopes)) or not all(
            _SCOPE.fullmatch(s) for s in self.scopes
        ):
            raise TokenInvalid("SCOPES")
        if list(self.tools) != sorted(set(self.tools)) or not all(
            _TOOL.fullmatch(s) for s in self.tools
        ):
            raise TokenInvalid("TOOLS")
        if self.max_risk not in LEVELS:
            raise TokenInvalid("MAX_RISK")
        if not (1 <= self.max_uses <= 1_000_000) or self.expires_us <= self.issued_us:
            raise TokenInvalid("LIMITS")
        if self.issuer == self.subject:
            raise TokenInvalid("SELF_DELEGATION")

    def record(self) -> dict[str, Any]:
        rec: dict[str, Any] = {
            "v": 1,
            "id": self.delegation_id.bytes,
            "ten": self.tenant,
            "iss": self.issuer.bytes,
            "sub": self.subject.bytes,
            "dep": self.depth,
            "sc": list(self.scopes),
            "tl": list(self.tools),
            "mr": self.max_risk,
            "exp": self.expires_us,
            "mu": self.max_uses,
            "iat": self.issued_us,
            "kid": self.key_id,
        }
        if self.parent_hash is not None:
            rec["par"] = self.parent_hash
        return rec

    @classmethod
    def from_record(cls, rec: Any) -> Claims:
        if not isinstance(rec, dict) or set(rec) - _KEYS or rec.get("v") != 1:
            raise TokenInvalid("SHAPE")
        try:
            return cls(
                delegation_id=UUID(bytes=_bytes(rec["id"], 16)),
                tenant=_text(rec["ten"]),
                issuer=UUID(bytes=_bytes(rec["iss"], 16)),
                subject=UUID(bytes=_bytes(rec["sub"], 16)),
                depth=_uint(rec["dep"]),
                parent_hash=_bytes(rec["par"], 32) if "par" in rec else None,
                scopes=tuple(_text(s) for s in _list(rec["sc"])),
                tools=tuple(_text(s) for s in _list(rec["tl"])),
                max_risk=_text(rec["mr"]),
                expires_us=_uint(rec["exp"]),
                max_uses=_uint(rec["mu"]),
                issued_us=_uint(rec["iat"]),
                key_id=_text(rec["kid"]),
            )
        except KeyError:
            raise TokenInvalid("SHAPE") from None


def _bytes(v: Any, n: int) -> bytes:
    if not isinstance(v, bytes) or len(v) != n:
        raise TokenInvalid("SHAPE")
    return v


def _text(v: Any) -> str:
    if not isinstance(v, str) or not 1 <= len(v) <= 128:
        raise TokenInvalid("SHAPE")
    return v


def _uint(v: Any) -> int:
    if not isinstance(v, int) or isinstance(v, bool) or v < 0:
        raise TokenInvalid("SHAPE")
    return v


def _list(v: Any) -> list[Any]:
    if not isinstance(v, list) or len(v) > 64:
        raise TokenInvalid("SHAPE")
    return v


def _b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64d(text: str) -> bytes:
    if not _B64.fullmatch(text):
        raise TokenInvalid("ENCODING")
    try:
        raw = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except (binascii.Error, ValueError):
        raise TokenInvalid("ENCODING") from None
    if _b64e(raw) != text:  # one encoding per token (no padding/alphabet variants)
        raise TokenInvalid("ENCODING")
    return raw


def token_hash(claims_cbor: bytes, signature: bytes) -> bytes:
    return hashlib.sha256(_HASH + claims_cbor + signature).digest()


def key_id_for(public_raw: bytes) -> str:
    return hashlib.sha256(public_raw).hexdigest()[:16]


@dataclass(frozen=True)
class SignedToken:
    claims: Claims
    claims_cbor: bytes
    signature: bytes

    @property
    def text(self) -> str:
        return f"{PREFIX}.{_b64e(self.claims_cbor)}.{_b64e(self.signature)}"

    @property
    def hash(self) -> bytes:
        return token_hash(self.claims_cbor, self.signature)

    def __repr__(self) -> str:  # a bearer-ish capability: never print the token itself
        return f"SignedToken(id={self.claims.delegation_id}, hash={self.hash.hex()[:16]}...)"


class DelegationSigner:
    def __init__(self, seed: bytes) -> None:
        if len(seed) != 32:
            raise ValueError("delegation signing key must be 32 bytes")
        self._private = Ed25519PrivateKey.from_private_bytes(seed)
        self.public_raw = self._private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        self.key_id = key_id_for(self.public_raw)

    def __repr__(self) -> str:
        return f"DelegationSigner(key_id={self.key_id!r})"

    def sign(self, claims: Claims) -> SignedToken:
        if claims.key_id != self.key_id:
            raise ValueError("claims name a different key")
        cbor = encode(claims.record())
        return SignedToken(claims, cbor, self._private.sign(_SIG + cbor))


def parse_and_verify(text: str, public_keys: dict[str, bytes]) -> SignedToken:
    """Strict parse + signature check against the gateway's trusted keys. Raises TokenInvalid."""
    if not isinstance(text, str) or len(text) > MAX_TOKEN_CHARS:
        raise TokenInvalid("ENCODING")
    parts = text.split(".")
    if len(parts) != 3 or parts[0] != PREFIX:
        raise TokenInvalid("ENCODING")
    claims_cbor, signature = _b64d(parts[1]), _b64d(parts[2])
    if len(signature) != 64:
        raise TokenInvalid("SIGNATURE")
    try:
        rec = decode(claims_cbor)  # strict: encode(decode(x)) == x
    except CanonicalError:
        raise TokenInvalid("NON_CANONICAL") from None
    if encode(rec) != claims_cbor:
        raise TokenInvalid("NON_CANONICAL")
    claims = Claims.from_record(rec)
    public = public_keys.get(claims.key_id)
    if public is None:
        raise TokenInvalid("UNKNOWN_KEY")
    try:
        Ed25519PublicKey.from_public_bytes(public).verify(signature, _SIG + claims_cbor)
    except (InvalidSignature, ValueError):
        raise TokenInvalid("SIGNATURE") from None
    return SignedToken(claims, claims_cbor, signature)


def hashes_equal(a: bytes, b: bytes) -> bool:
    return hmac.compare_digest(a, b)
