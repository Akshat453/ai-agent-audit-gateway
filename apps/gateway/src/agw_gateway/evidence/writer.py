"""EvidenceWriter: the single append path for lifecycle events (14 §4, 06 §4, ADR-0022).

In the caller's transaction, for a batch of events of one tenant:

1. ``SELECT last_seq, last_hash FROM chain_heads WHERE tenant_id = :t FOR UPDATE`` - the
   per-tenant single-writer lock, held until the caller commits. Commits therefore happen in
   seq order and a rollback returns the seq range (no gaps).
2. For each event: seq = last_seq + 1, prev = last_hash (ZERO32 at genesis); build the payload
   (salted, 05 §5), encode it canonically, store it, put its digest in the header; validate the
   header against its AGW-EVT v1 model; encode it canonically **once**; event_hash =
   H(TAG("AGW/event/v1") || those exact bytes).
3. Insert the event rows (canonical bytes + hash + derived JSON projection) and update the head.

``seq`` is *recording* order: the order in which the gateway committed evidence. It is not
causal order between concurrently dispatched actions (see ``dispatch.cg`` / ``obs``).
"""

from __future__ import annotations

import os
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Final
from uuid import UUID

from pydantic import ValidationError
from sqlalchemy import Connection, insert, select, text

from agw_gateway.crypto.canonical import (
    ZERO32,
    encode,
    event_hash,
    payload_digest,
    to_json_projection,
)
from agw_gateway.db import tables as t
from agw_gateway.evidence.payloads import NoPayloadStore, PayloadStore
from agw_gateway.ids import uuid7
from agw_schemas.events import HEADER_MODELS, MODEL_ONLY_TYPES, Payload

SCHEMA_VERSION: Final = 1
MAX_RECORD_BYTES: Final = 16 * 1024
MAX_PAYLOAD_BYTES: Final = 1024 * 1024
ACTOR_KINDS: Final = frozenset({"agent", "human", "gateway", "system"})
RISK_LEVELS: Final = frozenset({"LOW", "MEDIUM", "HIGH", "CRITICAL"})
GATEWAY_ACTOR_ID: Final = "agw-gateway"
# "delegation" carries the agent-DECLARED depth since Phase 4 (ADR-0026); otherwise it is
# written as an explicit null (Paper B field 8: present, unknown).
PAYLOAD_SECTIONS: Final = frozenset(
    {"intent", "execution", "effects", "context", "approval", "delegation", "disclosure"}
)


class EvidenceSchemaError(ValueError):
    """An event does not conform to AGW-EVT v1 / AGW-PAY v1."""


def now_us() -> int:
    return time.time_ns() // 1000


@dataclass(frozen=True)
class NewEvent:
    type: str
    actor_kind: str
    actor_id: str
    action_id: UUID | None = None
    run_id: UUID | None = None
    agent_id: UUID | None = None
    fields: Mapping[str, Any] = field(default_factory=dict)  # header fields
    payload: Mapping[str, Any] | None = None  # payload sections (sensitive content)
    delegation_present: bool = False
    # Risk level used ONLY to decide seal urgency (ADR-0026). Not part of the hashed header.
    # None + action_id => the action's recorded risk level; None without action => no risk.
    risk_level: str | None = None

    def __post_init__(self) -> None:
        model = HEADER_MODELS.get(self.type)
        if model is None or self.type in MODEL_ONLY_TYPES:
            raise EvidenceSchemaError(f"unknown or not-yet-writable event type {self.type}")
        if self.actor_kind not in ACTOR_KINDS:
            raise EvidenceSchemaError("unknown actor kind")
        allowed = set(model.model_fields) - {
            "v",
            "tenant",
            "seq",
            "prev",
            "id",
            "type",
            "ts",
            "class_",
            "actor",
            "action",
            "run",
            "payload",
        }
        unknown = set(self.fields) - allowed
        if unknown:
            raise EvidenceSchemaError(f"unknown record keys: {sorted(unknown)}")
        if any(v is None for v in self.fields.values()):
            raise EvidenceSchemaError("absent optional fields must be omitted, not null")
        if self.payload is not None and set(self.payload) - PAYLOAD_SECTIONS:
            raise EvidenceSchemaError("unknown payload sections")
        if self.risk_level is not None and self.risk_level not in RISK_LEVELS:
            raise EvidenceSchemaError("unknown risk level")


@dataclass(frozen=True)
class StoredEvent:
    event_id: UUID
    seq: int
    type: str
    event_hash: bytes


class EvidenceWriter:
    def __init__(self, payload_store: PayloadStore | None = None) -> None:
        # Phase 7: no default plaintext store. Without a KEK, events with payloads fail closed.
        self.payloads: PayloadStore = payload_store or NoPayloadStore()

    def append(
        self, conn: Connection, tenant_id: str, events: Sequence[NewEvent]
    ) -> list[StoredEvent]:
        if not events:
            return []
        head = conn.execute(
            text("SELECT last_seq, last_hash FROM chain_heads WHERE tenant_id = :t FOR UPDATE"),
            {"t": tenant_id},
        ).one_or_none()
        if head is None:
            raise LookupError("unknown tenant (no chain head)")
        last_seq, last_hash = int(head.last_seq), bytes(head.last_hash)
        inherited = self._action_risk(conn, events)

        rows: list[dict[str, Any]] = []
        payload_rows: list[tuple[UUID, int, bytes]] = []
        stored: list[StoredEvent] = []
        for ev in events:
            seq = last_seq + 1
            event_id = uuid7()
            header: dict[str, Any] = {
                "tenant": tenant_id,
                "seq": seq,
                "prev": last_hash if seq > 0 else ZERO32,
                "id": event_id.bytes,
                "type": ev.type,
                "ts": now_us(),
                "class": HEADER_MODELS[ev.type].CLASS,
                "actor": {"kind": ev.actor_kind, "id": ev.actor_id},
                **dict(ev.fields),
            }
            if ev.action_id is not None:
                header["action"] = ev.action_id.bytes
            if ev.run_id is not None:
                header["run"] = ev.run_id.bytes
            if ev.payload is not None:
                plaintext = self._payload_bytes(event_id, ev)
                header["payload"] = {
                    "digest": payload_digest(plaintext),
                    "len": len(plaintext),
                    "ref": self.payloads.ref_for(len(plaintext)),
                }
                payload_rows.append((event_id, seq, plaintext))
            try:
                record = HEADER_MODELS[ev.type].model_validate(header).to_record()
            except ValidationError as exc:
                locs = sorted({".".join(str(p) for p in e["loc"]) for e in exc.errors()})
                raise EvidenceSchemaError(f"{ev.type} header invalid at {locs}") from None
            canonical = encode(record)  # encoded exactly once; this is what gets hashed
            if len(canonical) > MAX_RECORD_BYTES:
                raise EvidenceSchemaError("record exceeds 16 KiB")
            digest = event_hash(canonical)
            rows.append(
                {
                    "event_id": event_id,
                    "tenant_id": tenant_id,
                    "seq": seq,
                    "event_type": ev.type,
                    "schema_version": SCHEMA_VERSION,
                    "action_id": ev.action_id,
                    "run_id": ev.run_id,
                    "agent_id": ev.agent_id,
                    "body": to_json_projection(record),
                    "canonical_bytes": canonical,
                    "event_hash": digest,
                    "risk_level": ev.risk_level
                    or (inherited.get(ev.action_id) if ev.action_id is not None else None),
                }
            )
            stored.append(StoredEvent(event_id=event_id, seq=seq, type=ev.type, event_hash=digest))
            last_seq, last_hash = seq, digest

        conn.execute(insert(t.evidence_events), rows)
        for event_id, seq, plaintext in payload_rows:
            self.payloads.store_payload(
                conn, tenant_id=tenant_id, event_id=event_id, seq=seq, plaintext=plaintext
            )
        conn.execute(
            text(
                "UPDATE chain_heads SET last_seq = :s, last_hash = :h, updated_at = now() "
                "WHERE tenant_id = :t"
            ),
            {"s": last_seq, "h": last_hash, "t": tenant_id},
        )
        return stored

    @staticmethod
    def _action_risk(conn: Connection, events: Sequence[NewEvent]) -> dict[UUID, str]:
        ids = {ev.action_id for ev in events if ev.risk_level is None and ev.action_id}
        if not ids:
            return {}
        rows = conn.execute(
            select(t.actions.c.action_id, t.actions.c.risk_level).where(
                t.actions.c.action_id.in_(ids)
            )
        ).all()
        return {r.action_id: r.risk_level for r in rows}

    @staticmethod
    def _payload_bytes(event_id: UUID, ev: NewEvent) -> bytes:
        assert ev.payload is not None  # noqa: S101
        try:
            payload = Payload(salt=os.urandom(32), event=event_id.bytes, **dict(ev.payload))
        except ValidationError as exc:
            raise EvidenceSchemaError("payload invalid") from exc
        plaintext = encode(payload.to_record(delegation_present=ev.delegation_present))
        if len(plaintext) > MAX_PAYLOAD_BYTES:
            raise EvidenceSchemaError("payload exceeds 1 MiB")
        return plaintext
