"""Read evidence from the SEALED record, and check the stored copies against it (ADR-0038).

``evidence_events`` keeps each record twice: ``canonical_bytes`` (hashed, chained, sealed into
epochs, anchored) and ``body`` (a derived JSON projection for queries, 05 §7), plus indexed
columns (``tenant_id``, ``seq``, ``event_type``, ``action_id``, ``run_id``). Only the canonical
bytes are covered by the hash, so a database superuser could change ``body`` or a column and
every hash check would still pass while a screen showed the edited value.

Therefore:
- screens show :func:`sealed_header` (decoded from the canonical bytes), never ``body``;
- :func:`stored_copy_ok` says whether ``body`` and the columns still equal the sealed record;
  the console and the monitor report a mismatch as TAMPERED.
"""

from __future__ import annotations

from typing import Any, Final
from uuid import UUID

from agw_gateway.crypto.canonical import CanonicalError, decode, to_json_projection


class _Unset:
    pass


UNSET: Final[Any] = _Unset()


def sealed_header(canonical: bytes) -> dict[str, Any] | None:
    """The JSON view of the sealed record, or ``None`` if the bytes do not decode."""
    try:
        record = decode(bytes(canonical))
    except (CanonicalError, ValueError, TypeError, IndexError, KeyError):
        return None
    view = to_json_projection(record)
    return view if isinstance(view, dict) else None


def header_for_display(canonical: bytes) -> dict[str, Any]:
    """What a screen shows: the sealed record. If it does not decode (tampering, flagged by
    the hash check) an empty header, never the unverified ``body`` copy."""
    return sealed_header(canonical) or {}


def _uuid_text(v: Any) -> str | None:
    if v is None:
        return None
    return str(v if isinstance(v, UUID) else UUID(str(v)))


def stored_copy_ok(
    canonical: bytes,
    body: Any,
    *,
    tenant_id: str | None = None,
    seq: int | None = None,
    event_type: str | None = None,
    action_id: Any = UNSET,
    run_id: Any = UNSET,
) -> bool:
    """True iff ``body`` and the given stored columns equal what the sealed record says.

    A column left out is not checked. ``action_id`` / ``run_id`` may be passed as NULL: then
    the sealed record must not name one either.
    """
    header = sealed_header(canonical)
    if header is None or body != header:
        return False
    if tenant_id is not None and header.get("tenant") != tenant_id:
        return False
    if seq is not None and header.get("seq") != int(seq):
        return False
    if event_type is not None and header.get("type") != event_type:
        return False
    if action_id is not UNSET and _uuid_text(action_id) != header.get("action"):
        return False
    return run_id is UNSET or _uuid_text(run_id) == header.get("run")
