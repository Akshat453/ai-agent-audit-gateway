"""Chain export (``export.jsonl``) for the standalone verifier.

Line 1 is metadata; every further line is one event in seq order:

    {"format": "agw-export/v1", "tenant": ..., "from_seq": a, "to_seq": b, "count": n,
     "payloads": true, "declared_head": {"seq": s, "hash": hex}}
    {"seq": n, "event_id": uuid, "header": hex(canonical header), "event_hash": hex,
     "payload": hex(canonical payload)}            # "payload" only if requested and present

``declared_head`` and every stored ``event_hash`` come from the live system and are NOT
trusted by the verifier: it recomputes everything and only trusts a head passed on its command
line. Exports contain PLAINTEXT payloads in Phase 2 - handle them as sensitive.
"""

from __future__ import annotations

import json
from typing import IO, Any

from sqlalchemy import Engine, func, select

from agw_gateway.db import tables as t

EXPORT_FORMAT = "agw-export/v1"


def export_chain(
    engine: Engine,
    tenant_id: str,
    out: IO[str],
    *,
    from_seq: int = 0,
    to_seq: int | None = None,
    include_payloads: bool = True,
) -> int:
    ev, pl = t.evidence_events, t.evidence_payloads
    with engine.connect() as conn:
        head = conn.execute(
            select(t.chain_heads.c.last_seq, t.chain_heads.c.last_hash).where(
                t.chain_heads.c.tenant_id == tenant_id
            )
        ).one_or_none()
        if head is None:
            raise LookupError("unknown tenant")
        upper = head.last_seq if to_seq is None else min(to_seq, head.last_seq)
        conds = [ev.c.tenant_id == tenant_id, ev.c.seq >= from_seq, ev.c.seq <= upper]
        count = conn.execute(select(func.count()).select_from(ev).where(*conds)).scalar_one()
        meta: dict[str, Any] = {
            "format": EXPORT_FORMAT,
            "tenant": tenant_id,
            "from_seq": from_seq,
            "to_seq": upper,
            "count": count,
            "payloads": include_payloads,
            "declared_head": {"seq": head.last_seq, "hash": bytes(head.last_hash).hex()},
        }
        out.write(json.dumps(meta, sort_keys=True) + "\n")
        cols = [ev.c.seq, ev.c.event_id, ev.c.canonical_bytes, ev.c.event_hash]
        query = select(*cols, pl.c.content) if include_payloads else select(*cols)
        frm = ev.outerjoin(pl, pl.c.event_id == ev.c.event_id) if include_payloads else ev
        result = conn.execution_options(yield_per=500).execute(
            query.select_from(frm).where(*conds).order_by(ev.c.seq)
        )
        written = 0
        for row in result:
            line: dict[str, Any] = {
                "seq": row.seq,
                "event_id": str(row.event_id),
                "header": bytes(row.canonical_bytes).hex(),
                "event_hash": bytes(row.event_hash).hex(),
            }
            if include_payloads and row.content is not None:
                line["payload"] = bytes(row.content).hex()
            out.write(json.dumps(line, sort_keys=True) + "\n")
            written += 1
    return written
