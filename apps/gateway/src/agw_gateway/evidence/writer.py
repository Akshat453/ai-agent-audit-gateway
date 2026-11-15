"""EvidenceWriter: the single append path for lifecycle events (14 §4).

``append`` allocates a contiguous, gap-free seq range with
``UPDATE tenants SET next_seq = next_seq + n ... RETURNING`` (08 §3, ADR-0018). The row lock is
held until the caller's transaction commits, so commits happen in seq order and a rollback
returns the range. Events are inserted in the caller's transaction, together with the state
change they record (08 §1). Phase 2 swaps the encoding inside this one function (05 §7: JSONB
body with the 05 §4 keys now, ``canonical_bytes`` later).
"""

from __future__ import annotations

import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Final
from uuid import UUID

from sqlalchemy import Connection, insert, text

from agw_gateway.db import tables as t
from agw_gateway.ids import uuid7
from agw_schemas import PHASE1_EVENT_TYPES

SCHEMA_VERSION: Final = 1

EVENT_CLASS: Final[Mapping[str, str]] = {
    "ACTION_REQUESTED": "A2S",
    "POLICY_EVALUATED": "SYS",
    "ACTION_DENIED": "SYS",
    "APPROVAL_REQUIRED": "A2H",
    "ACTION_AUTHORIZED": "SYS",
    "ACTION_DISPATCHED": "A2S",
    "ACTION_COMPLETED": "A2S",
    "ACTION_FAILED": "A2S",
    "ACTION_OUTCOME_UNKNOWN": "SYS",
    "SECURITY_VIOLATION": "SYS",
}

# Optional record keys allowed by AGW-EVT v1 (05 §4). Unknown keys are rejected.
OPTIONAL_KEYS: Final = frozenset(
    {
        "action",
        "run",
        "tool",
        "env",
        "risk",
        "policy",
        "approval",
        "args",
        "dispatch",
        "outcome",
        "payload",
        "refs",
        "code",
        "violation",
    }
)
ACTOR_KINDS: Final = frozenset({"agent", "human", "gateway", "system"})
GATEWAY_ACTOR_ID: Final = "agw-gateway"


class EvidenceSchemaError(ValueError):
    """An event does not conform to AGW-EVT v1 (05 §4)."""


@dataclass(frozen=True)
class NewEvent:
    type: str
    actor_kind: str
    actor_id: str
    action_id: UUID | None = None
    run_id: UUID | None = None
    agent_id: UUID | None = None
    fields: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.type not in PHASE1_EVENT_TYPES:
            raise EvidenceSchemaError(f"unknown event type {self.type}")
        if self.actor_kind not in ACTOR_KINDS:
            raise EvidenceSchemaError("unknown actor kind")
        unknown = set(self.fields) - OPTIONAL_KEYS
        if unknown:
            raise EvidenceSchemaError(f"unknown record keys: {sorted(unknown)}")
        if any(v is None for v in self.fields.values()):
            raise EvidenceSchemaError("absent optional fields must be omitted, not null")


@dataclass(frozen=True)
class StoredEvent:
    event_id: UUID
    seq: int
    type: str


class EvidenceWriter:
    def append(
        self, conn: Connection, tenant_id: str, events: Sequence[NewEvent]
    ) -> list[StoredEvent]:
        if not events:
            return []
        n = len(events)
        first_seq = conn.execute(
            text(
                "UPDATE tenants SET next_seq = next_seq + :n WHERE tenant_id = :tenant "
                "RETURNING next_seq - :n"
            ),
            {"n": n, "tenant": tenant_id},
        ).scalar_one_or_none()
        if first_seq is None:
            raise LookupError("unknown tenant")

        rows: list[dict[str, Any]] = []
        stored: list[StoredEvent] = []
        for offset, ev in enumerate(events):
            seq = int(first_seq) + offset
            event_id = uuid7()
            body = self._body(tenant_id, seq, event_id, ev)
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
                    "body": body,
                    "canonical_bytes": None,  # Phase 2 (14 §8)
                }
            )
            stored.append(StoredEvent(event_id=event_id, seq=seq, type=ev.type))
        conn.execute(insert(t.evidence_events), rows)
        return stored

    @staticmethod
    def _body(tenant_id: str, seq: int, event_id: UUID, ev: NewEvent) -> dict[str, Any]:
        """05 §7 Phase 1 storage form: §4 keys, UUIDs as strings, ``prev`` omitted."""
        body: dict[str, Any] = {
            "v": SCHEMA_VERSION,
            "tenant": tenant_id,
            "seq": seq,
            "id": str(event_id),
            "type": ev.type,
            "ts": time.time_ns() // 1000,
            "class": EVENT_CLASS[ev.type],
            "actor": {"kind": ev.actor_kind, "id": ev.actor_id},
        }
        if ev.action_id is not None:
            body["action"] = str(ev.action_id)
        if ev.run_id is not None:
            body["run"] = str(ev.run_id)
        body.update(ev.fields)
        return body
