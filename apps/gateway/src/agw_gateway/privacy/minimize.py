"""Data minimization before anything is stored (Phase 7, ADR-0029 §4).

* SECRET arg/result fields are replaced by "[REDACTED:sha256:<hex>]" (per-tenant salted, see
  ``crypto.envelope.redaction_marker``) in every evidence payload and API view. The real value
  exists only in the sealed operational copy the tool needs (``privacy/cipher.py``) until
  dispatch.
* Unvalidated agent args (unknown tool, schema violation) cannot be classified, so they are
  NOT stored: only their top-level key names and a salted digest of the raw JSON.
* Results: the agent-visible plaintext copy (``actions.result_public``) keeps only public and
  internal fields; confidential results stay in the encrypted ACTION_COMPLETED payload.

The per-tenant salt is 32 random bytes stored wrapped by the KEK (``tenant_redaction_keys``)
and cached in memory per process.
"""

from __future__ import annotations

import json
import os
import threading
from collections.abc import Mapping
from typing import Any

from sqlalchemy import Connection, select
from sqlalchemy.dialects.postgresql import insert

from agw_gateway.crypto.canonical import CanonicalError, encode, profile_value
from agw_gateway.crypto.envelope import redaction_marker
from agw_gateway.db import tables as t
from agw_gateway.keys import KeyProvider, WrappedKey
from agw_gateway.privacy.classification import PLAINTEXT_OK, FieldClasses

MARKER_PREFIX = "[REDACTED:sha256:"


def _value_bytes(value: Any) -> bytes:
    try:
        return encode(profile_value(value))
    except CanonicalError:
        return json.dumps(value, sort_keys=True, default=str).encode()


def salt_context(tenant: str) -> bytes:
    return encode({"tenant": tenant, "purpose": "redaction-salt"})


class Minimizer:
    def __init__(self, provider: KeyProvider) -> None:
        self._provider = provider
        self._salts: dict[str, bytes] = {}
        self._lock = threading.Lock()

    def salt(self, conn: Connection, tenant: str) -> bytes:
        with self._lock:
            cached = self._salts.get(tenant)
        if cached is not None:
            return cached
        rk = t.tenant_redaction_keys
        row = conn.execute(select(rk).where(rk.c.tenant_id == tenant)).one_or_none()
        if row is None:
            w = self._provider.wrap(os.urandom(32), salt_context(tenant))
            conn.execute(
                insert(rk)
                .values(
                    tenant_id=tenant,
                    kek_id=w.kek_id,
                    kek_version=w.kek_version,
                    wrap_nonce=w.nonce,
                    wrapped_salt=w.ciphertext,
                )
                .on_conflict_do_nothing()
            )
            row = conn.execute(select(rk).where(rk.c.tenant_id == tenant)).one()
        salt = self._provider.unwrap(
            WrappedKey(row.kek_id, row.kek_version, bytes(row.wrap_nonce), bytes(row.wrapped_salt)),
            salt_context(tenant),
        )
        with self._lock:
            self._salts[tenant] = salt
        return salt

    def marker(self, conn: Connection, tenant: str, value: Any) -> str:
        return redaction_marker(self.salt(conn, tenant), _value_bytes(value))

    def args(
        self, conn: Connection, tenant: str, classes: FieldClasses, args: Mapping[str, Any]
    ) -> dict[str, Any]:
        return {
            k: (self.marker(conn, tenant, v) if classes.arg(k) == "secret" else v)
            for k, v in args.items()
        }

    def results(
        self, conn: Connection, tenant: str, classes: FieldClasses, result: Mapping[str, Any]
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        """(for the encrypted effects payload, for the plaintext agent-visible copy)."""
        effects = {
            k: (self.marker(conn, tenant, v) if classes.result(k) == "secret" else v)
            for k, v in result.items()
        }
        visible = {k: v for k, v in result.items() if classes.result(k) in PLAINTEXT_OK}
        return effects, visible

    def unvalidated(self, conn: Connection, tenant: str, raw: Any) -> dict[str, Any]:
        keys = sorted(str(k)[:64] for k in raw) if isinstance(raw, Mapping) else []
        return {"args_unvalidated": {"keys": keys[:100], "digest": self.marker(conn, tenant, raw)}}
