"""Retention and crypto-erasure (Phase 7, ADR-0029 §8; 07 §6).

``RetentionJob.run_once`` deletes payloads past their retention period:
* Policy: the most specific ``retention_policies`` row matching (tenant, tool, payload class)
  wins; "*" is a wildcard. The payload class is the tool's highest non-secret field class
  (``FieldClasses.payload_class``); events without a tool, or of an unknown tool, are
  ``confidential``. No matching policy = keep forever.
* Legal holds (``legal_holds``, unreleased) on the tenant, run, action or event block deletion.
* ``erase`` (also used for erasure requests) deletes, in ONE transaction, the wrapped DEK and the
  ciphertext row, and appends PAYLOAD_DELETED {event, seq, reason, policy} to the tenant chain.
  The MinIO object of a large payload is removed after the commit (a failure leaves an orphan
  for ``collect_orphans``).

What stays: the event header, its payload.digest (salted, so it no longer reveals anything,
ADR-0013), the Merkle proofs and the anchors. The verifier then reports the payload as
unavailable (INCOMPLETE), not TAMPERED.

NOT a legal-compliance claim: copies of wrapped DEKs and ciphertexts in database backups,
replicas, WAL archives and object-store versions remain decryptable while the KEK version that
wrapped them exists. Erasure is complete only after those copies expire, or after rotating the
KEK, re-wrapping every live DEK and destroying the old KEK version. Whether that satisfies a
given legal obligation is for counsel, not for this code.
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import Connection, Engine, func, select, text

from agw_gateway.db import tables as t
from agw_gateway.evidence import EvidenceWriter, NewEvent
from agw_gateway.evidence.blobs import BlobStore, BlobUnavailable
from agw_gateway.evidence.payloads import EncryptedPayloadStore
from agw_gateway.logs import log
from agw_gateway.privacy.classification import DEFAULT
from agw_gateway.tools.registry import ToolRegistry

logger = logging.getLogger("agw.privacy.retention")
RETENTION_ACTOR = "agw-retention"


class LegalHold(Exception):
    pass


@dataclass(frozen=True)
class Policy:
    policy_id: str
    tenant_id: str
    tool_id: str
    classification: str
    retain_days: int

    def matches(self, tenant: str, tool: str, cls: str) -> bool:
        return (
            self.tenant_id in ("*", tenant)
            and self.tool_id in ("*", tool)
            and self.classification in ("*", cls)
        )

    @property
    def specificity(self) -> int:
        return (
            (self.tenant_id != "*") * 4 + (self.tool_id != "*") * 2 + (self.classification != "*")
        )


class RetentionJob:
    def __init__(
        self,
        *,
        engine: Engine,
        store: EncryptedPayloadStore,
        writer: EvidenceWriter,
        registry: ToolRegistry,
        blobs: BlobStore | None = None,
    ) -> None:
        self._engine = engine
        self._store = store
        self._writer = writer
        self._registry = registry
        self._blobs = blobs

    # ---------------------------------------------------------------- policy
    def _policies(self, conn: Connection) -> list[Policy]:
        rows = conn.execute(select(t.retention_policies)).all()
        return [
            Policy(r.policy_id, r.tenant_id, r.tool_id, r.classification, int(r.retain_days))
            for r in rows
        ]

    def _class_of(self, tool_id: str | None, version: str | None) -> str:
        if not tool_id:
            return DEFAULT
        spec = self._registry.get_any(tool_id, version or "")
        return spec.classes.payload_class() if spec is not None else DEFAULT

    @staticmethod
    def _held(conn: Connection, tenant: str, event_id: Any, action: Any, run: Any) -> bool:
        return bool(
            conn.execute(
                text(
                    """
                    SELECT 1 FROM legal_holds
                     WHERE tenant_id = :t AND released_at IS NULL
                       AND (scope = 'tenant'
                            OR (scope = 'event' AND scope_id = :e)
                            OR (scope = 'action' AND scope_id = :a)
                            OR (scope = 'run' AND scope_id = :r))
                     LIMIT 1
                    """
                ),
                {"t": tenant, "e": event_id, "a": action, "r": run},
            ).first()
        )

    # ---------------------------------------------------------------- sweep
    def run_once(self, *, now: datetime | None = None, batch: int = 200) -> int:
        now = now or datetime.now(UTC)
        deleted = 0
        with self._engine.connect() as conn:
            policies = self._policies(conn)
            if not policies:
                return 0
            rows = conn.execute(
                select(
                    t.payload_objects.c.event_id,
                    t.payload_objects.c.tenant_id,
                    t.payload_objects.c.created_at,
                    t.evidence_events.c.action_id,
                    t.evidence_events.c.run_id,
                    # The action's tool (results/outcomes carry no tool in their header).
                    func.coalesce(
                        t.actions.c.tool_id, t.evidence_events.c.body["tool"]["id"].astext
                    ).label("tool_id"),
                    func.coalesce(
                        t.actions.c.tool_version, t.evidence_events.c.body["tool"]["ver"].astext
                    ).label("tool_ver"),
                )
                .join(
                    t.evidence_events,
                    t.evidence_events.c.event_id == t.payload_objects.c.event_id,
                )
                .outerjoin(t.actions, t.actions.c.action_id == t.evidence_events.c.action_id)
                .where(
                    t.payload_objects.c.created_at
                    < now - timedelta(days=min(p.retain_days for p in policies))
                )
                .order_by(t.payload_objects.c.created_at)
                .limit(batch)
            ).all()
        for r in rows:
            cls = self._class_of(r.tool_id, r.tool_ver)
            tool = r.tool_id or "*"
            matching = [p for p in policies if p.matches(r.tenant_id, tool, cls)]
            if not matching:
                continue
            policy = max(matching, key=lambda p: p.specificity)
            if r.created_at >= now - timedelta(days=policy.retain_days):
                continue
            try:
                if self.erase(r.tenant_id, r.event_id, "RETENTION", policy.policy_id):
                    deleted += 1
            except LegalHold:
                continue
        return deleted

    # ---------------------------------------------------------------- erase
    def erase(
        self,
        tenant_id: str,
        event_id: uuid.UUID,
        reason: str = "ERASURE_REQUEST",
        policy_id: str | None = None,
        *,
        actor_kind: str = "system",
        actor_id: str = RETENTION_ACTOR,
    ) -> bool:
        """Crypto-erase one payload. False if it was already gone; LegalHold if held."""
        with self._engine.begin() as conn:
            ev = conn.execute(
                select(
                    t.evidence_events.c.seq,
                    t.evidence_events.c.action_id,
                    t.evidence_events.c.run_id,
                ).where(
                    t.evidence_events.c.event_id == event_id,
                    t.evidence_events.c.tenant_id == tenant_id,
                )
            ).one_or_none()
            if ev is None:
                return False
            # Serialize erasures of one payload on its key row (agw_app may update payload_keys
            # columns, never payload_objects, so the lock is taken there).
            locked = conn.execute(
                select(t.payload_keys.c.event_id)
                .where(t.payload_keys.c.event_id == event_id)
                .with_for_update()
            ).one_or_none()
            exists = conn.execute(
                select(t.payload_objects.c.event_id).where(t.payload_objects.c.event_id == event_id)
            ).one_or_none()
            if locked is None and exists is None:
                return False  # already erased (idempotent)
            if self._held(conn, tenant_id, event_id, ev.action_id, ev.run_id):
                raise LegalHold(str(event_id))
            blob_key = self._store.delete(conn, event_id)
            erasure: dict[str, Any] = {
                "event": event_id.bytes,
                "seq": int(ev.seq),
                "reason": reason,
            }
            if policy_id is not None:
                erasure["policy"] = policy_id
            self._writer.append(
                conn,
                tenant_id,
                [
                    NewEvent(
                        type="PAYLOAD_DELETED",
                        actor_kind=actor_kind,
                        actor_id=actor_id,
                        fields={"erasure": erasure},
                        risk_level="MEDIUM",
                    )
                ],
            )
        if blob_key is not None and self._blobs is not None:
            try:
                self._blobs.delete(blob_key)
            except BlobUnavailable:
                log(logger, logging.WARNING, "blob delete failed; orphan left for GC",
                    error_code="BLOB_ORPHAN")  # fmt: skip
        log(logger, logging.INFO, "payload erased", tenant_id=tenant_id, event=reason)
        return True

    def collect_orphans(self, *, min_age_seconds: float = 600.0) -> int:
        """Delete MinIO objects that no payload row references (rolled-back writes, failed
        post-erasure deletes). Objects younger than ``min_age_seconds`` are left alone: their
        event transaction may still be about to commit."""
        if self._blobs is None:
            return 0
        cutoff = datetime.now(UTC) - timedelta(seconds=min_age_seconds)
        keys = [k for k, modified in self._blobs.list_objects() if modified <= cutoff]
        if not keys:
            return 0
        with self._engine.connect() as conn:
            live = set(
                conn.execute(
                    select(t.payload_objects.c.blob_key).where(
                        t.payload_objects.c.blob_key.in_(keys)
                    )
                ).scalars()
            )
        removed = 0
        for k in keys:
            if k not in live:
                self._blobs.delete(k)
                removed += 1
        return removed
