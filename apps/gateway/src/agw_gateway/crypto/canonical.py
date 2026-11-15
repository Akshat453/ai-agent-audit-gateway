"""Canonical encoding + digests (06 §3-5). The codec itself is AGW-CBOR-v1 in agw_schemas.

All hashes are computed over the exact canonical bytes that are stored, never over a
re-serialized JSONB value (ADR-0005).
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from typing import Any, Final
from uuid import UUID

from pydantic import BaseModel

from agw_gateway.crypto.tags import ARGS_TAG, EVENT_TAG, PAYLOAD_TAG, domain_tag
from agw_schemas.cbor import CanonicalError, decode, encode

ZERO32: Final = bytes(32)
_EVENT: Final = domain_tag(EVENT_TAG)
_PAYLOAD: Final = domain_tag(PAYLOAD_TAG)
_ARGS: Final = domain_tag(ARGS_TAG)

__all__ = [
    "ZERO32",
    "CanonicalError",
    "args_digest",
    "decode",
    "encode",
    "event_hash",
    "json_or_profile",
    "payload_digest",
    "profile_value",
    "to_json_projection",
]


def event_hash(canonical_header: bytes) -> bytes:
    return hashlib.sha256(_EVENT + canonical_header).digest()


def payload_digest(canonical_payload: bytes) -> bytes:
    return hashlib.sha256(_PAYLOAD + canonical_payload).digest()


def profile_value(value: Any) -> Any:
    """Map Python values to profile types: UUID -> 16-byte bstr, tuple -> array.
    Floats and other types are left for the encoder to reject."""
    if isinstance(value, UUID):
        return value.bytes
    if isinstance(value, Mapping):
        return {k: profile_value(v) for k, v in value.items()}
    if isinstance(value, list | tuple):
        return [profile_value(v) for v in value]
    return value


def args_digest(validated: BaseModel) -> bytes:
    """``H(TAG("AGW/args/v1") || cbor(validated_args))`` over the python-mode dump (06 §3)."""
    return hashlib.sha256(
        _ARGS + encode(profile_value(validated.model_dump(mode="python")))
    ).digest()


def json_or_profile(value: Any, key: str) -> dict[str, Any]:
    """``{key: value}`` if representable in the profile, else ``{key+'_json': sorted JSON text}``
    (e.g. raw agent args containing floats). Never silently alters a value."""
    converted = profile_value(value)
    try:
        encode(converted)
    except CanonicalError:
        text = json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str
        )
        return {f"{key}_json": text}
    return {key: converted}


_UUID_KEYS: Final = frozenset({"id", "action", "run"})


def to_json_projection(value: Any, key: str | None = None) -> Any:
    """Derived, NON-authoritative JSON view of a decoded record (05 §7). Never hashed."""
    if isinstance(value, bytes):
        if key in _UUID_KEYS and len(value) == 16:
            return str(UUID(bytes=value))
        return value.hex()
    if isinstance(value, dict):
        return {k: to_json_projection(v, k) for k, v in value.items()}
    if isinstance(value, list):
        return [to_json_projection(v) for v in value]
    return value
