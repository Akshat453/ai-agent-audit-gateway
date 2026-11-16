"""Selective disclosure (Phase 7, ADR-0029 §6; 07 §5).

Roles (Phase 5 human identities): an AUDITOR registers an X25519 public key; an ADMIN creates a
grant naming that auditor + key, a set of events (explicit ids, or every event of one action),
a purpose, an expiry and a delivery mode; the auditor exports. Never the same human for both
(DB CHECK granted_by <> auditor_id).

Evidence, in the tenant's own chain (sealed promptly: risk HIGH):
* DISCLOSURE_GRANTED: header {grant, auditor, key, mode, scope, exp, n, ids}; the purpose and
  the event list are in the (encrypted) payload. ``ids`` = H(TAG("AGW/disclosure-ids/v1") ||
  cbor(sorted event ids)).
* DISCLOSURE_ACCESSED: every export attempt, allowed or denied (expired, revoked, not the
  grantee, event outside the grant), with outcome {COMPLETED | DENIED, code}. A successful
  export is only returned after its evidence has COMMITTED.

Export bundle per event = the Phase 3/6 evidence bundle (header bytes, inclusion proof, epoch
chain, anchor claim) + ``disclosure``:
* mode ``hpke``: the payload ciphertext + nonce as stored, and the event's DEK sealed to the
  auditor's X25519 key with HPKE (RFC 9180 base mode, DHKEM(X25519, HKDF-SHA256), HKDF-SHA256,
  AES-256-GCM; ``info`` binds tenant, grant, event and recipient key id). The gateway never
  ships plaintext; one event's DEK opens exactly one ciphertext (per-event random DEKs).
* mode ``plaintext``: the decrypted canonical payload (for auditors without key handling;
  the transport is the only protection, so ``hpke`` is the default).
* a payload that no longer exists (retention / erasure) -> ``payload_status: "DELETED"``.
"""

from __future__ import annotations

import hashlib
import logging
import uuid
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from typing import Any, Final

from sqlalchemy import Connection, Engine, insert, select, update

from agw_gateway.crypto.canonical import encode
from agw_gateway.crypto.envelope import (
    ALG,
    HPKE_SUITE_NAME,
    disclosure_info,
    recipient_key_id,
    seal_to_recipient,
)
from agw_gateway.crypto.tags import DISCLOSURE_IDS_TAG, domain_tag
from agw_gateway.db import tables as t
from agw_gateway.evidence import EvidenceWriter, NewEvent
from agw_gateway.evidence.bundle import EventNotSealed, build_bundle
from agw_gateway.evidence.payloads import EncryptedPayloadStore, PayloadUnavailable
from agw_gateway.execution.errors import (
    DisclosureDenied,
    DisclosureInvalid,
    EventNotSealedYet,
    NotFound,
    RoleRequired,
)
from agw_gateway.humans import AuthenticatedHuman
from agw_gateway.ids import uuid7
from agw_gateway.keys import KeyUnavailable
from agw_gateway.logs import log

logger = logging.getLogger("agw.privacy.disclosure")
DISCLOSURE_FORMAT: Final = "agw-disclosure/v1"
EXPORT_FORMAT: Final = "agw-disclosure-export/v1"
MAX_GRANT_SECONDS: Final = 30 * 24 * 3600
_IDS: Final = domain_tag(DISCLOSURE_IDS_TAG)


def ids_digest(event_ids: Sequence[uuid.UUID]) -> bytes:
    return hashlib.sha256(_IDS + encode(sorted(e.bytes for e in event_ids))).digest()


def _us(ts: datetime) -> int:
    return int(ts.timestamp() * 1_000_000)


class DisclosureService:
    def __init__(
        self,
        *,
        engine: Engine,
        writer: EvidenceWriter,
        store: EncryptedPayloadStore | None,
        max_events: int = 200,
    ) -> None:
        self._engine = engine
        self._writer = writer
        self._store = store
        self._max = max_events

    # ---------------------------------------------------------------- auditor keys
    def register_key(self, auditor: AuthenticatedHuman, public_key: bytes) -> dict[str, Any]:
        if not auditor.has("auditor"):
            raise RoleRequired
        if len(public_key) != 32:
            raise DisclosureInvalid
        key_id = recipient_key_id(public_key)
        with self._engine.begin() as conn:
            existing = conn.execute(
                select(t.auditor_keys).where(t.auditor_keys.c.key_id == key_id)
            ).one_or_none()
            if existing is None:
                conn.execute(
                    insert(t.auditor_keys).values(
                        key_id=key_id,
                        tenant_id=auditor.tenant_id,
                        human_id=auditor.human_id,
                        algorithm="X25519",
                        public_key=public_key,
                    )
                )
            elif existing.human_id != auditor.human_id:
                raise DisclosureInvalid
        return {"key_id": key_id, "algorithm": "X25519"}

    # ---------------------------------------------------------------- grants
    def create_grant(
        self,
        admin: AuthenticatedHuman,
        *,
        auditor_id: uuid.UUID,
        auditor_key_id: str,
        event_ids: Sequence[uuid.UUID] | None,
        action_id: uuid.UUID | None,
        purpose: str,
        expires_in_seconds: int,
        delivery: str = "hpke",
    ) -> dict[str, Any]:
        if not admin.has("admin"):
            raise RoleRequired
        if (event_ids is None) == (action_id is None) or not 0 < expires_in_seconds <= (
            MAX_GRANT_SECONDS
        ):
            raise DisclosureInvalid
        if admin.human_id == auditor_id:
            raise DisclosureInvalid  # separation of duties: nobody grants to themselves
        ids = sorted(set(event_ids or ()))
        if event_ids is not None and not 1 <= len(ids) <= self._max:
            raise DisclosureInvalid
        tenant = admin.tenant_id
        grant_id = uuid7()
        expires_at = datetime.now(UTC) + timedelta(seconds=expires_in_seconds)
        with self._engine.begin() as conn:
            auditor = conn.execute(
                select(t.humans).where(
                    t.humans.c.human_id == auditor_id, t.humans.c.tenant_id == tenant
                )
            ).one_or_none()
            key = conn.execute(
                select(t.auditor_keys).where(
                    t.auditor_keys.c.key_id == auditor_key_id,
                    t.auditor_keys.c.human_id == auditor_id,
                    t.auditor_keys.c.revoked_at.is_(None),
                )
            ).one_or_none()
            if (
                auditor is None
                or auditor.status != "active"
                or "auditor" not in auditor.roles
                or key is None
            ):
                raise DisclosureInvalid
            if ids:
                found = conn.execute(
                    select(t.evidence_events.c.event_id).where(
                        t.evidence_events.c.tenant_id == tenant,
                        t.evidence_events.c.event_id.in_(ids),
                    )
                ).scalars()
                if set(found) != set(ids):
                    raise DisclosureInvalid  # unknown or other-tenant event ids
            conn.execute(
                insert(t.disclosure_grants).values(
                    grant_id=grant_id,
                    tenant_id=tenant,
                    auditor_id=auditor_id,
                    auditor_key_id=auditor_key_id,
                    event_ids=ids or None,
                    action_id=action_id,
                    purpose=purpose,
                    delivery=delivery,
                    expires_at=expires_at,
                    granted_by=admin.human_id,
                )
            )
            header: dict[str, Any] = {
                "grant": grant_id.bytes,
                "auditor": auditor_id.bytes,
                "key": auditor_key_id,
                "mode": delivery,
                "scope": "events" if ids else "action",
                "exp": _us(expires_at),
            }
            payload: dict[str, Any] = {"purpose": purpose}
            if ids:
                header["n"] = len(ids)
                header["ids"] = ids_digest(ids)
                payload["event_ids"] = [e.bytes for e in ids]
            else:
                assert action_id is not None  # noqa: S101
                payload["action"] = action_id.bytes
            self._writer.append(
                conn,
                tenant,
                [
                    NewEvent(
                        type="DISCLOSURE_GRANTED",
                        actor_kind="human",
                        actor_id=str(admin.human_id),
                        fields={"disclosure": header},
                        payload={"disclosure": payload},
                        risk_level="HIGH",
                    )
                ],
            )
        log(logger, logging.INFO, "disclosure granted", tenant_id=tenant, status="GRANTED")
        return {
            "grant_id": str(grant_id),
            "expires_at": expires_at.isoformat().replace("+00:00", "Z"),
            "delivery": delivery,
            "scope": "events" if ids else "action",
        }

    def revoke_grant(self, admin: AuthenticatedHuman, grant_id: uuid.UUID) -> None:
        if not admin.has("admin"):
            raise RoleRequired
        with self._engine.begin() as conn:
            n = conn.execute(
                update(t.disclosure_grants)
                .where(
                    t.disclosure_grants.c.grant_id == grant_id,
                    t.disclosure_grants.c.tenant_id == admin.tenant_id,
                    t.disclosure_grants.c.revoked_at.is_(None),
                )
                .values(revoked_at=datetime.now(UTC))
            ).rowcount
        if not n:
            raise NotFound

    # ---------------------------------------------------------------- export
    def export(
        self,
        auditor: AuthenticatedHuman,
        grant_id: uuid.UUID,
        requested: Sequence[uuid.UUID] | None = None,
    ) -> dict[str, Any]:
        with self._engine.connect() as conn:
            g = conn.execute(
                select(t.disclosure_grants, t.auditor_keys.c.public_key)
                .join(
                    t.auditor_keys, t.auditor_keys.c.key_id == t.disclosure_grants.c.auditor_key_id
                )
                .where(
                    t.disclosure_grants.c.grant_id == grant_id,
                    t.disclosure_grants.c.tenant_id == auditor.tenant_id,
                )
            ).one_or_none()
            if g is None:
                raise NotFound
            granted = self._granted_events(conn, g)
            wanted = sorted(set(requested)) if requested else granted
            denial = self._denial(auditor, g, granted, wanted)
            if denial is not None:
                self._record_access(g, auditor, wanted, "DENIED", denial)
                raise DisclosureDenied(denial)
            if len(wanted) > self._max:
                raise DisclosureInvalid
            try:
                bundles = [self._bundle(conn, g, e) for e in wanted]
            except EventNotSealed:
                raise EventNotSealedYet from None
        # Every access is evidence; nothing is returned unless that evidence committed.
        self._record_access(g, auditor, wanted, "COMPLETED", None)
        return {
            "format": EXPORT_FORMAT,
            "grant_id": str(grant_id),
            "tenant": g.tenant_id,
            "delivery": g.delivery,
            "recipient_key_id": g.auditor_key_id,
            "bundles": bundles,
        }

    @staticmethod
    def _granted_events(conn: Connection, g: Any) -> list[uuid.UUID]:
        if g.event_ids is not None:
            return sorted(g.event_ids)
        return sorted(
            conn.execute(
                select(t.evidence_events.c.event_id).where(
                    t.evidence_events.c.tenant_id == g.tenant_id,
                    t.evidence_events.c.action_id == g.action_id,
                )
            ).scalars()
        )

    @staticmethod
    def _denial(
        auditor: AuthenticatedHuman, g: Any, granted: list[uuid.UUID], wanted: list[uuid.UUID]
    ) -> str | None:
        if not auditor.has("auditor"):
            return "ROLE_REQUIRED"
        if g.auditor_id != auditor.human_id:
            return "NOT_GRANTEE"
        if g.revoked_at is not None:
            return "GRANT_REVOKED"
        if g.expires_at <= datetime.now(UTC):
            return "GRANT_EXPIRED"
        if not wanted or not set(wanted) <= set(granted):
            return "EVENT_NOT_GRANTED"
        return None

    def _bundle(self, conn: Connection, g: Any, event_id: uuid.UUID) -> dict[str, Any]:
        bundle = build_bundle(conn, event_id, tenant_id=g.tenant_id)
        d: dict[str, Any] = {
            "format": DISCLOSURE_FORMAT,
            "grant_id": str(g.grant_id),
            "mode": g.delivery,
            "recipient_key_id": g.auditor_key_id,
        }
        if self._store is None:
            raise KeyUnavailable("no KEK configured")
        try:
            sealed = self._store.load_sealed(conn, event_id)
        except PayloadUnavailable as exc:
            if exc.code == "KEK_UNAVAILABLE":
                raise KeyUnavailable("KEK unavailable") from None
            d["payload_status"] = exc.code
            sealed = None
        else:
            if sealed is None:
                d["payload_status"] = "NONE"
        if sealed is not None:
            if g.delivery == "hpke":
                info = disclosure_info(
                    g.tenant_id, g.grant_id.bytes, event_id.bytes, g.auditor_key_id
                )
                d.update(
                    suite=HPKE_SUITE_NAME,
                    alg=ALG,
                    nonce=sealed.nonce.hex(),
                    ciphertext=sealed.ciphertext.hex(),
                    sealed_dek=seal_to_recipient(sealed.dek, bytes(g.public_key), info).hex(),
                    schema_version=sealed.schema_version,
                )
            else:
                d["payload"] = self._store.decrypt(conn, sealed).hex()
                d["payload_status"] = "PLAINTEXT"
        bundle["disclosure"] = d
        return bundle

    def _record_access(
        self,
        g: Any,
        auditor: AuthenticatedHuman,
        events: Sequence[uuid.UUID],
        status: str,
        code: str | None,
    ) -> None:
        header: dict[str, Any] = {
            "grant": g.grant_id.bytes,
            "auditor": auditor.human_id.bytes,
            "key": g.auditor_key_id,
            "mode": g.delivery,
            "scope": "events" if g.event_ids is not None else "action",
            "n": len(events),
        }
        if events:
            header["ids"] = ids_digest(events)
        outcome: dict[str, str] = {"status": status}
        if code is not None:
            outcome["code"] = code
        with self._engine.begin() as conn:
            self._writer.append(
                conn,
                g.tenant_id,
                [
                    NewEvent(
                        type="DISCLOSURE_ACCESSED",
                        actor_kind="human",
                        actor_id=str(auditor.human_id),
                        fields={"disclosure": header, "outcome": outcome},
                        risk_level="HIGH",
                    )
                ],
            )
        log(
            logger,
            logging.WARNING if status == "DENIED" else logging.INFO,
            "disclosure access",
            tenant_id=g.tenant_id,
            status=status,
            error_code=code,
        )
