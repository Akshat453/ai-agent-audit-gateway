"""Payload store (05 §5, 07 §3-4, ADR-0017, ADR-0029).

PHASE 7: ``EncryptedPayloadStore`` replaces the Phase 2 plaintext store behind the same
``store_payload`` / ``load_payload`` interface. The header still commits to
``payload.digest`` over the PLAINTEXT canonical payload (06 §5); only the bytes at rest change.

Per payload, in the event's transaction:
    DEK   = 32 random bytes (one plaintext per DEK, so a random 96-bit nonce is safe)
    ct    = AES-256-GCM(DEK, nonce, plaintext, payload_aad(tenant, event_id, seq, digest, v))
    wrap  = KeyProvider.wrap(DEK, cbor({tenant, event_id}))   -> payload_keys
    ct    -> payload_objects.ciphertext, or MinIO object "<tenant>/<event_id>" when the
             plaintext exceeds the blob threshold (header ``payload.ref = "blob"``).
A KEK (or, for large payloads, MinIO) failure raises, the transaction rolls back and the API
answers 503: no event is ever written with a payload we could not protect.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Final, Protocol
from uuid import UUID

from cryptography.exceptions import InvalidTag
from sqlalchemy import Connection, delete, insert, select, text

from agw_gateway.crypto.canonical import CanonicalError, decode, encode, payload_digest
from agw_gateway.crypto.envelope import (
    ALG,
    decrypt_payload,
    encrypt_payload,
    new_dek,
    payload_aad,
)
from agw_gateway.db import tables as t
from agw_gateway.evidence.blobs import BlobStore
from agw_gateway.keys import KeyProvider, KeyUnavailable, UnwrapFailed, WrappedKey

PAYLOAD_SCHEMA_VERSION: Final = 1
DEFAULT_BLOB_THRESHOLD: Final = 64 * 1024


class PayloadUnavailable(Exception):
    """The payload cannot be produced. ``code``: DELETED, BLOB_MISSING, BLOB_CORRUPT,
    KEY_MISSING, DECRYPT_FAILED, KEK_UNAVAILABLE."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class PayloadStore(Protocol):
    def ref_for(self, plaintext_len: int) -> str: ...

    def store_payload(
        self, conn: Connection, *, tenant_id: str, event_id: UUID, seq: int, plaintext: bytes
    ) -> None: ...

    def load_payload(self, conn: Connection, event_id: UUID) -> bytes | None: ...


def dek_context(tenant: str, event_id: UUID) -> bytes:
    return encode({"tenant": tenant, "event_id": event_id.bytes})


def committed_digest(conn: Connection, event_id: UUID) -> bytes | None:
    """payload.digest from the stored canonical header (the hashed bytes, never the JSONB)."""
    cb = conn.execute(
        select(t.evidence_events.c.canonical_bytes).where(t.evidence_events.c.event_id == event_id)
    ).scalar_one_or_none()
    if cb is None:
        return None
    try:
        ref = decode(bytes(cb)).get("payload")
    except CanonicalError:
        raise PayloadUnavailable("HEADER_UNREADABLE") from None  # the verifier flags the header
    return bytes(ref["digest"]) if isinstance(ref, dict) else None


@dataclass(frozen=True)
class SealedPayload:
    """Ciphertext + the unwrapped DEK of ONE event (for disclosure re-wrapping)."""

    tenant: str
    event_id: UUID
    seq: int
    schema_version: int
    nonce: bytes
    ciphertext: bytes
    dek: bytes


class EncryptedPayloadStore:
    storage: str = "encrypted"

    def __init__(
        self,
        provider: KeyProvider,
        blobs: BlobStore | None = None,
        blob_threshold: int = DEFAULT_BLOB_THRESHOLD,
    ) -> None:
        self.provider = provider
        self.blobs = blobs
        self.blob_threshold = blob_threshold

    def ref_for(self, plaintext_len: int) -> str:
        return (
            "blob" if self.blobs is not None and plaintext_len > self.blob_threshold else "inline"
        )

    # ---------------------------------------------------------------- write
    def store_payload(
        self, conn: Connection, *, tenant_id: str, event_id: UUID, seq: int, plaintext: bytes
    ) -> None:
        digest = payload_digest(plaintext)
        aad = payload_aad(tenant_id, event_id.bytes, seq, digest, PAYLOAD_SCHEMA_VERSION)
        dek = new_dek()
        nonce, ct = encrypt_payload(dek, plaintext, aad)
        wrapped = self.provider.wrap(dek, dek_context(tenant_id, event_id))
        storage = self.ref_for(len(plaintext))
        blob_key = None
        if storage == "blob":
            assert self.blobs is not None  # noqa: S101 - ref_for guarantees it
            blob_key = f"{tenant_id}/{event_id}"
            self.blobs.put(blob_key, ct)  # before COMMIT; a rollback leaves a GC-able orphan
        conn.execute(
            insert(t.payload_objects).values(
                event_id=event_id,
                tenant_id=tenant_id,
                seq=seq,
                schema_version=PAYLOAD_SCHEMA_VERSION,
                alg=ALG,
                nonce=nonce,
                storage=storage,
                ciphertext=ct if storage == "inline" else None,
                blob_key=blob_key,
                ct_len=len(ct),
                ct_sha256=hashlib.sha256(ct).digest(),
                pt_len=len(plaintext),
            )
        )
        conn.execute(
            insert(t.payload_keys).values(
                event_id=event_id,
                tenant_id=tenant_id,
                kek_id=wrapped.kek_id,
                kek_version=wrapped.kek_version,
                wrap_nonce=wrapped.nonce,
                wrapped_dek=wrapped.ciphertext,
            )
        )

    # ---------------------------------------------------------------- read
    def load_sealed(self, conn: Connection, event_id: UUID) -> SealedPayload | None:
        """None if the event never had a payload. Raises PayloadUnavailable if it had one that
        cannot be produced now (deleted, blob gone/altered, key gone)."""
        o = conn.execute(
            select(t.payload_objects).where(t.payload_objects.c.event_id == event_id)
        ).one_or_none()
        if o is None:
            if committed_digest(conn, event_id) is not None:
                raise PayloadUnavailable("DELETED")
            return None
        if o.storage == "blob":
            if self.blobs is None:
                raise PayloadUnavailable("BLOB_MISSING")
            ct = self.blobs.get(o.blob_key)
            if ct is None:
                raise PayloadUnavailable("BLOB_MISSING")
        else:
            ct = bytes(o.ciphertext)
        if len(ct) != o.ct_len or hashlib.sha256(ct).digest() != bytes(o.ct_sha256):
            raise PayloadUnavailable("BLOB_CORRUPT")
        k = conn.execute(
            select(t.payload_keys).where(t.payload_keys.c.event_id == event_id)
        ).one_or_none()
        if k is None:
            raise PayloadUnavailable("KEY_MISSING")
        try:
            dek = self.provider.unwrap(
                WrappedKey(k.kek_id, k.kek_version, bytes(k.wrap_nonce), bytes(k.wrapped_dek)),
                dek_context(o.tenant_id, event_id),
            )
        except KeyUnavailable:
            raise PayloadUnavailable("KEK_UNAVAILABLE") from None
        except UnwrapFailed:
            raise PayloadUnavailable("DECRYPT_FAILED") from None
        return SealedPayload(
            o.tenant_id, event_id, int(o.seq), int(o.schema_version), bytes(o.nonce), ct, dek
        )

    def load_payload(self, conn: Connection, event_id: UUID) -> bytes | None:
        sp = self.load_sealed(conn, event_id)
        if sp is None:
            return None
        return self.decrypt(conn, sp)

    @staticmethod
    def decrypt(conn: Connection, sp: SealedPayload) -> bytes:
        header_digest = committed_digest(conn, sp.event_id)
        if header_digest is None:
            raise PayloadUnavailable("DECRYPT_FAILED")
        aad = payload_aad(sp.tenant, sp.event_id.bytes, sp.seq, header_digest, sp.schema_version)
        try:
            return decrypt_payload(sp.dek, sp.nonce, sp.ciphertext, aad)
        except InvalidTag:
            raise PayloadUnavailable("DECRYPT_FAILED") from None

    # ---------------------------------------------------------------- erase
    def delete(self, conn: Connection, event_id: UUID) -> str | None:
        """Delete the wrapped DEK and the ciphertext row (crypto-erasure). Returns the blob key
        to remove AFTER the transaction commits (a failed removal leaves a GC-able orphan)."""
        blob_key = conn.execute(
            select(t.payload_objects.c.blob_key).where(t.payload_objects.c.event_id == event_id)
        ).scalar_one_or_none()
        conn.execute(delete(t.payload_keys).where(t.payload_keys.c.event_id == event_id))
        conn.execute(delete(t.payload_objects).where(t.payload_objects.c.event_id == event_id))
        return blob_key


class LegacyPlaintextPayloadStore:
    """Phase 2 store (PLAINTEXT ``evidence_payloads.content``). Kept ONLY so the re-encryption
    migration can be tested against real Phase 2 rows on a database at revision 0007; the
    column no longer exists after migration 0008."""

    storage: str = "plaintext"

    def ref_for(self, plaintext_len: int) -> str:
        return "inline"

    def store_payload(
        self, conn: Connection, *, tenant_id: str, event_id: UUID, seq: int, plaintext: bytes
    ) -> None:
        conn.execute(
            text(
                "INSERT INTO evidence_payloads (event_id, tenant_id, seq, storage, content) "
                "VALUES (:e, :t, :s, 'plaintext', :c)"
            ),
            {"e": event_id, "t": tenant_id, "s": seq, "c": plaintext},
        )

    def load_payload(self, conn: Connection, event_id: UUID) -> bytes | None:
        row = conn.execute(
            text("SELECT content FROM evidence_payloads WHERE event_id = :e"), {"e": event_id}
        ).scalar_one_or_none()
        return bytes(row) if row is not None else None


class NoPayloadStore:
    """No KEK configured: any event that carries a payload fails closed (KeyUnavailable)."""

    def ref_for(self, plaintext_len: int) -> str:
        return "inline"

    def store_payload(
        self, conn: Connection, *, tenant_id: str, event_id: UUID, seq: int, plaintext: bytes
    ) -> None:
        raise KeyUnavailable("no KEK configured: payloads cannot be encrypted")

    def load_payload(self, conn: Connection, event_id: UUID) -> bytes | None:
        raise PayloadUnavailable("KEK_UNAVAILABLE")
