"""Payload store interface (05 §5, ADR-0017).

PHASE 2: payloads are stored as **PLAINTEXT** canonical CBOR in ``evidence_payloads``.
Encryption (AES-256-GCM, per-event DEK, ADR-0012) replaces ``PlaintextPayloadStore`` in the
encryption phase behind this same interface; the header commitment (payload.digest over the
plaintext canonical bytes) does not change.
"""

from __future__ import annotations

from typing import Protocol
from uuid import UUID

from sqlalchemy import Connection, insert, select

from agw_gateway.db import tables as t


class PayloadStore(Protocol):
    def store_payload(
        self, conn: Connection, *, tenant_id: str, event_id: UUID, seq: int, plaintext: bytes
    ) -> None: ...

    def load_payload(self, conn: Connection, event_id: UUID) -> bytes | None: ...


class PlaintextPayloadStore:
    """Dev/Phase-2 store: plaintext at rest. NOT for sensitive production data."""

    storage: str = "plaintext"

    def store_payload(
        self, conn: Connection, *, tenant_id: str, event_id: UUID, seq: int, plaintext: bytes
    ) -> None:
        conn.execute(
            insert(t.evidence_payloads).values(
                event_id=event_id,
                tenant_id=tenant_id,
                seq=seq,
                storage=self.storage,
                content=plaintext,
            )
        )

    def load_payload(self, conn: Connection, event_id: UUID) -> bytes | None:
        row = conn.execute(
            select(t.evidence_payloads.c.content).where(t.evidence_payloads.c.event_id == event_id)
        ).scalar_one_or_none()
        return bytes(row) if row is not None else None
