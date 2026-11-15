"""Evidence bundles (``agw-bundle/v1``) and epoch exports (``agw-epochs/v1``).

Bundle = everything an offline verifier needs to check ONE event without trusting us:

    {"format": "agw-bundle/v1", "bundle_version": 1, "tenant": t,
     "event": {"event_id", "seq", "header": hex(canonical header), ["payload": hex]},
     "proof": {"epoch_no", "tree_size", "leaf_index", "audit_path": [hex]},
     "epoch": <epoch record of the event's epoch>,
     "epoch_chain": [<epoch records epoch_no+1 .. latest sealed>],
     "trust_root": {"epoch_no", "epoch_root", "source": "local-seal"}}   # informational only

JSON Schema: packages/schemas/bundle/evidence-bundle.v1.schema.json. Proofs are computed on
demand from the sealed rows (ADR-0025). ``trust_root`` is what THIS system claims; a verifier
must get its trusted root out of band (an anchor from Phase 6 on).
"""

from __future__ import annotations

import json
from typing import IO, Any
from uuid import UUID

from sqlalchemy import Connection, select

from agw_gateway.crypto.merkle import audit_path
from agw_gateway.db import tables as t

BUNDLE_FORMAT = "agw-bundle/v1"
EPOCHS_FORMAT = "agw-epochs/v1"


class EventNotFound(LookupError):
    pass


class EventNotSealed(LookupError):
    pass


def epoch_record(row: Any) -> dict[str, Any]:
    return {
        "tenant": row.tenant_id,
        "epoch_no": int(row.epoch_no),
        "tree_size": int(row.tree_size),
        "first_seq": int(row.first_seq),
        "last_seq": int(row.last_seq),
        "merkle_root": bytes(row.merkle_root).hex(),
        "prev_root": bytes(row.prev_root).hex(),
        "epoch_root": bytes(row.epoch_root).hex(),
        "sealed_at": row.sealed_at.isoformat().replace("+00:00", "Z") if row.sealed_at else None,
        "seal_reason": row.seal_reason,
    }


def get_epoch(conn: Connection, tenant_id: str, epoch_no: int | None) -> Any:
    q = select(t.epochs).where(t.epochs.c.tenant_id == tenant_id)
    if epoch_no is None:
        q = q.order_by(t.epochs.c.epoch_no.desc()).limit(1)
    else:
        q = q.where(t.epochs.c.epoch_no == epoch_no)
    return conn.execute(q).one_or_none()


def build_bundle(
    conn: Connection,
    event_id: UUID,
    *,
    tenant_id: str | None,
    include_payload: bool = False,
) -> dict[str, Any]:
    ev = t.evidence_events
    q = select(ev.c.tenant_id, ev.c.seq, ev.c.canonical_bytes).where(ev.c.event_id == event_id)
    if tenant_id is not None:
        q = q.where(ev.c.tenant_id == tenant_id)
    row = conn.execute(q).one_or_none()
    if row is None:
        raise EventNotFound
    tenant, seq = row.tenant_id, int(row.seq)
    epoch = conn.execute(
        select(t.epochs).where(
            t.epochs.c.tenant_id == tenant, t.epochs.c.first_seq <= seq, t.epochs.c.last_seq >= seq
        )
    ).one_or_none()
    if epoch is None:
        raise EventNotSealed
    leaves = [
        bytes(h)
        for h in conn.execute(
            select(ev.c.event_hash)
            .where(ev.c.tenant_id == tenant, ev.c.seq.between(epoch.first_seq, epoch.last_seq))
            .order_by(ev.c.seq)
        ).scalars()
    ]
    index = seq - int(epoch.first_seq)
    later = conn.execute(
        select(t.epochs)
        .where(t.epochs.c.tenant_id == tenant, t.epochs.c.epoch_no > epoch.epoch_no)
        .order_by(t.epochs.c.epoch_no)
    ).all()
    latest = later[-1] if later else epoch
    event: dict[str, Any] = {
        "event_id": str(event_id),
        "seq": seq,
        "header": bytes(row.canonical_bytes).hex(),
    }
    if include_payload:
        content = conn.execute(
            select(t.evidence_payloads.c.content).where(t.evidence_payloads.c.event_id == event_id)
        ).scalar_one_or_none()
        if content is not None:
            event["payload"] = bytes(content).hex()
    return {
        "format": BUNDLE_FORMAT,
        "bundle_version": 1,
        "tenant": tenant,
        "event": event,
        "proof": {
            "epoch_no": int(epoch.epoch_no),
            "tree_size": int(epoch.tree_size),
            "leaf_index": index,
            "audit_path": [p.hex() for p in audit_path(index, leaves)],
        },
        "epoch": epoch_record(epoch),
        "epoch_chain": [epoch_record(r) for r in later],
        "trust_root": {
            "epoch_no": int(latest.epoch_no),
            "epoch_root": bytes(latest.epoch_root).hex(),
            "source": "local-seal",
        },
    }


def export_epochs(conn: Connection, tenant_id: str, out: IO[str]) -> int:
    rows = conn.execute(
        select(t.epochs).where(t.epochs.c.tenant_id == tenant_id).order_by(t.epochs.c.epoch_no)
    ).all()
    out.write(json.dumps({"format": EPOCHS_FORMAT, "tenant": tenant_id, "count": len(rows)}) + "\n")
    for r in rows:
        out.write(json.dumps(epoch_record(r), sort_keys=True) + "\n")
    return len(rows)
