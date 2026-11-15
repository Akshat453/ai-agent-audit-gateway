"""Domain-separation tags (06 §2, ADR-0006). Phase 1 uses only the apikey and request tags."""

from __future__ import annotations

from typing import Final


def domain_tag(tag: str) -> bytes:
    """``TAG(t) = u8(len(utf8(t))) || utf8(t)``; length in [2, 255]."""
    raw = tag.encode("utf-8")
    if not 2 <= len(raw) <= 255:
        raise ValueError("tag length out of range")
    return bytes([len(raw)]) + raw


APIKEY_TAG: Final = "AGW/apikey/v1"
REQUEST_TAG: Final = "AGW/request/v1"
EVENT_TAG: Final = "AGW/event/v1"
PAYLOAD_TAG: Final = "AGW/payload/v1"
ARGS_TAG: Final = "AGW/args/v1"
