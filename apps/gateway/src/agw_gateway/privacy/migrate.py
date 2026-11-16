"""One-off re-encryption of Phase 2-6 plaintext (Phase 7, ADR-0029 §7).

``python -m agw_gateway.admin migrate-payloads`` on a database at revision 0007:

1. Payloads: every ``evidence_payloads.content`` row without a ``payload_objects`` row is
   checked against its committed header (``payload.digest`` and ``payload.len`` over the exact
   plaintext bytes), encrypted with a fresh DEK (same code path as new events), decrypted again
   and compared byte for byte, all in one transaction per batch. A row whose plaintext does not
   match its header is NOT migrated and is reported: the plaintext stays (and migration 0008
   stays blocked) until an operator investigates. Nothing is ever re-hashed or re-chained.
2. Operational args: ``outbox_jobs.args`` / ``actions.request_args`` (pending work) are sealed
   into ``args_sealed`` / ``request_args_sealed``.

Idempotent and resumable: each batch commits on its own and only picks rows that are not done
yet, so a crash or Ctrl-C loses at most the batch in flight. Then ``alembic upgrade head``
(0008) drops the plaintext columns; it refuses while anything is left.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

from sqlalchemy import Engine, text

from agw_gateway.crypto.canonical import CanonicalError, decode, payload_digest
from agw_gateway.evidence.payloads import EncryptedPayloadStore
from agw_gateway.logs import log
from agw_gateway.privacy.cipher import EnvelopeCipher, ops_context

logger = logging.getLogger("agw.privacy.migrate")


@dataclass
class MigrationReport:
    payloads_encrypted: int = 0
    payloads_verified: int = 0
    dispatch_args_sealed: int = 0
    request_args_sealed: int = 0
    mismatched: list[str] = field(default_factory=list)  # event ids NOT migrated

    @property
    def remaining_blocked(self) -> int:
        return len(self.mismatched)


def migrate_plaintext(
    engine: Engine,
    store: EncryptedPayloadStore,
    cipher: EnvelopeCipher,
    *,
    batch: int = 200,
    max_batches: int | None = None,
) -> MigrationReport:
    rep = MigrationReport()
    batches = 0
    skip: set[str] = set()
    while max_batches is None or batches < max_batches:
        with engine.begin() as conn:
            rows = conn.execute(
                text(
                    """
                    SELECT p.event_id, p.tenant_id, p.seq, p.content, e.canonical_bytes
                      FROM evidence_payloads p
                      JOIN evidence_events e ON e.event_id = p.event_id
                     WHERE p.content IS NOT NULL
                       AND NOT EXISTS (SELECT 1 FROM payload_objects o
                                        WHERE o.event_id = p.event_id)
                       AND NOT (p.event_id::text = ANY(:skip))
                     ORDER BY p.tenant_id, p.seq
                     LIMIT :n
                    """
                ),
                {"n": batch, "skip": list(skip)},
            ).all()
            if not rows:
                break
            for r in rows:
                plaintext = bytes(r.content)
                if not _matches_header(bytes(r.canonical_bytes), plaintext):
                    rep.mismatched.append(str(r.event_id))
                    skip.add(str(r.event_id))
                    continue
                store.store_payload(
                    conn,
                    tenant_id=r.tenant_id,
                    event_id=r.event_id,
                    seq=int(r.seq),
                    plaintext=plaintext,
                )
                rep.payloads_encrypted += 1
                if store.load_payload(conn, r.event_id) != plaintext:  # round trip, same tx
                    raise RuntimeError(f"re-encryption round trip failed for {r.event_id}")
                rep.payloads_verified += 1
        batches += 1
    rep.dispatch_args_sealed = _seal_column(
        engine, cipher, "outbox_jobs", "args", "args_sealed", "dispatch_args", "job_id"
    )
    rep.request_args_sealed = _seal_column(
        engine, cipher, "actions", "request_args", "request_args_sealed", "request_args", None
    )
    for eid in rep.mismatched:
        log(logger, logging.CRITICAL, "plaintext payload does not match its header: NOT migrated",
            event=eid, error_code="PAYLOAD_DIGEST_MISMATCH")  # fmt: skip
    return rep


def _matches_header(canonical_header: bytes, plaintext: bytes) -> bool:
    try:
        ref = decode(canonical_header).get("payload")
    except CanonicalError:
        return False
    return (
        isinstance(ref, dict)
        and ref.get("digest") == payload_digest(plaintext)
        and ref.get("len") == len(plaintext)
    )


def _seal_column(
    engine: Engine,
    cipher: EnvelopeCipher,
    table: str,
    plain: str,
    sealed: str,
    purpose: str,
    pk: str | None,
) -> int:
    key = pk or "action_id"
    done = 0
    with engine.begin() as conn:
        rows = conn.execute(
            text(
                f"SELECT {key} AS k, tenant_id, action_id, {plain} AS v FROM {table} "  # noqa: S608
                f"WHERE {plain} IS NOT NULL AND {sealed} IS NULL FOR UPDATE"
            )
        ).all()
        for r in rows:
            blob = cipher.seal_json(ops_context(r.tenant_id, purpose, r.action_id.bytes), r.v)
            conn.execute(
                text(f"UPDATE {table} SET {sealed} = :b WHERE {key} = :k"),  # noqa: S608
                {"b": blob, "k": r.k},
            )
            done += 1
    return done
