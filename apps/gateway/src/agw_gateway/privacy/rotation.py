"""KEK rotation (Phase 7, ADR-0029 §9; 07 §2).

Rotation = a new KEK version becomes active (local: ``admin gen-kek`` writes ``<id>.v<N+1>.key``
and the process restarts; Vault: ``transit/keys/<k>/rotate``). From then on new DEKs are wrapped
under the new version; every old version remains available for unwrapping, so nothing breaks.

``rewrap_all`` then moves existing wrapped DEKs (and per-tenant redaction salts) to the active
version in idempotent, resumable batches: unwrap under the old version, wrap under the new one,
update ``payload_keys``. Ciphertexts, payload digests, event hashes, Merkle roots and anchors
are untouched: verification never depended on any key. After it reports 0 remaining, the old
KEK version can be destroyed (the step that makes backup copies of old wrapped DEKs useless).

Sealed operational envelopes (outbox / pending-approval args) are short-lived and keep their
old version until the action completes; destroy an old KEK only after those have drained.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import Engine, and_, func, select, update

from agw_gateway.db import tables as t
from agw_gateway.evidence.payloads import dek_context
from agw_gateway.keys import KeyProvider, WrappedKey
from agw_gateway.privacy.minimize import salt_context


def _stale(tbl: Any, provider: KeyProvider, active: int, tenant: str | None) -> Any:
    """Rows wrapped under an OLDER version of THIS provider's KEK (a provider can only unwrap
    its own KEK id; moving between providers, e.g. file -> Vault, is a separate migration)."""
    cond = and_(tbl.c.kek_id == provider.kek_id, tbl.c.kek_version != active)
    return and_(cond, tbl.c.tenant_id == tenant) if tenant is not None else cond


def remaining(engine: Engine, provider: KeyProvider, *, tenant: str | None = None) -> int:
    active = provider.active_version
    with engine.connect() as conn:
        return sum(
            len(
                conn.execute(
                    select(tbl.c.tenant_id).where(_stale(tbl, provider, active, tenant))
                ).all()
            )
            for tbl in (t.payload_keys, t.tenant_redaction_keys)
        )


def rewrap_all(
    engine: Engine, provider: KeyProvider, *, batch: int = 500, tenant: str | None = None
) -> int:
    active = provider.active_version
    done = 0
    while True:
        with engine.begin() as conn:
            rows = conn.execute(
                select(t.payload_keys)
                .where(_stale(t.payload_keys, provider, active, tenant))
                .limit(batch)
                .with_for_update(skip_locked=True)
            ).all()
            for r in rows:
                ctx = dek_context(r.tenant_id, r.event_id)
                dek = provider.unwrap(
                    WrappedKey(r.kek_id, r.kek_version, bytes(r.wrap_nonce), bytes(r.wrapped_dek)),
                    ctx,
                )
                w = provider.wrap(dek, ctx)
                conn.execute(
                    update(t.payload_keys)
                    .where(
                        and_(
                            t.payload_keys.c.event_id == r.event_id,
                            t.payload_keys.c.kek_version == r.kek_version,
                        )
                    )
                    .values(
                        kek_id=w.kek_id,
                        kek_version=w.kek_version,
                        wrap_nonce=w.nonce,
                        wrapped_dek=w.ciphertext,
                        updated_at=func.now(),
                    )
                )
                done += 1
        if not rows:
            break
    with engine.begin() as conn:
        rk = t.tenant_redaction_keys
        for r in conn.execute(select(rk).where(_stale(rk, provider, active, tenant))).all():
            ctx = salt_context(r.tenant_id)
            salt = provider.unwrap(
                WrappedKey(r.kek_id, r.kek_version, bytes(r.wrap_nonce), bytes(r.wrapped_salt)),
                ctx,
            )
            w = provider.wrap(salt, ctx)
            conn.execute(
                update(rk)
                .where(rk.c.tenant_id == r.tenant_id)
                .values(
                    kek_id=w.kek_id,
                    kek_version=w.kek_version,
                    wrap_nonce=w.nonce,
                    wrapped_salt=w.ciphertext,
                    updated_at=func.now(),
                )
            )
            done += 1
    return done
