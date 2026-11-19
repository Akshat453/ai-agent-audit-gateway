"""Fill in the console's readable target for coding actions recorded before migration 0015
(ADR-0041). Operator-only, idempotent, resumable.

For every ``coding_actions`` row without ``target_sealed`` it opens that action's
ACTION_REQUESTED payload (the gateway's own encrypted evidence), takes
``intent.action.targets`` exactly as recorded, applies the SAME redaction and clipping as new
actions (``display_from_targets``), seals it under the KEK and stores the diff COUNTS. The diff
text and file contents are never stored. Evidence is not modified: the payload is only read.
Actions whose payload was erased (retention / erasure) are skipped and stay "not recorded".
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any
from uuid import UUID

from sqlalchemy import Engine, and_, insert, select, update

from agw_gateway.coding.display import diff_summary, display_from_targets
from agw_gateway.crypto.canonical import decode
from agw_gateway.db import tables as t
from agw_gateway.evidence.payloads import EncryptedPayloadStore, PayloadUnavailable
from agw_gateway.privacy.cipher import EnvelopeCipher, ops_context


@dataclass
class BackfillReport:
    filled: int = 0
    no_payload: int = 0
    unreadable: int = 0
    remaining: int = 0


def backfill_targets(
    engine: Engine,
    store: EncryptedPayloadStore,
    cipher: EnvelopeCipher,
    *,
    tenant: str | None = None,
    batch: int = 200,
) -> BackfillReport:
    rep = BackfillReport()
    ca, ev = t.coding_actions, t.evidence_events
    seen: set[UUID] = set()
    while True:
        with engine.begin() as conn:
            q = (
                select(ca.c.action_id, ca.c.tenant_id, ev.c.event_id)
                .join(
                    ev,
                    and_(
                        ev.c.action_id == ca.c.action_id,
                        ev.c.tenant_id == ca.c.tenant_id,
                        ev.c.event_type == "ACTION_REQUESTED",
                    ),
                    isouter=True,
                )
                .where(ca.c.target_sealed.is_(None), ca.c.action_id.not_in(seen or {UUID(int=0)}))
                .order_by(ca.c.action_id)
                .limit(batch)
            )
            if tenant is not None:
                q = q.where(ca.c.tenant_id == tenant)
            rows = conn.execute(q).all()
            if not rows:
                break
            for r in rows:
                seen.add(r.action_id)
                if r.event_id is None:
                    rep.no_payload += 1
                    continue
                try:
                    plaintext = store.load_payload(conn, r.event_id)
                except PayloadUnavailable:
                    rep.unreadable += 1
                    continue
                if plaintext is None:
                    rep.no_payload += 1
                    continue
                intent: dict[str, Any] = decode(plaintext).get("intent") or {}
                action = intent.get("action") or {}
                shown = display_from_targets(
                    dict(action.get("targets") or {}), str(action.get("native_tool") or "") or None
                )
                diff = intent.get("diff")
                summary = diff_summary(diff if isinstance(diff, str) else None)
                conn.execute(
                    update(ca)
                    .where(ca.c.action_id == r.action_id, ca.c.target_sealed.is_(None))
                    .values(
                        target_sealed=cipher.seal_json(
                            ops_context(r.tenant_id, "coding_target", r.action_id.bytes), shown
                        ),
                        diff_files=summary.files if summary else None,
                        diff_added=summary.added if summary else None,
                        diff_removed=summary.removed if summary else None,
                    )
                )
                rep.filled += 1
    with engine.connect() as conn:
        q2 = select(ca.c.action_id).where(ca.c.target_sealed.is_(None))
        if tenant is not None:
            q2 = q2.where(ca.c.tenant_id == tenant)
        rep.remaining = len(conn.execute(q2).all())
    return rep


def backfill_action_repos(
    engine: Engine, store: EncryptedPayloadStore, *, tenant: str | None = None
) -> dict[str, int]:
    """ADR-0042: record the repository of GitHub connector actions decided before 0016, from
    the ``repo`` argument in their own ACTION_REQUESTED payload, else the connector's default
    repository. Idempotent; evidence is only read."""
    full = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
    a, ar, ev, cx = t.actions, t.action_repos, t.evidence_events, t.connectors
    done = {"filled": 0, "skipped": 0}
    with engine.begin() as conn:
        q = (
            select(a.c.action_id, a.c.tenant_id, a.c.tool_id, ev.c.event_id)
            .join(
                ev,
                and_(
                    ev.c.action_id == a.c.action_id,
                    ev.c.tenant_id == a.c.tenant_id,
                    ev.c.event_type == "ACTION_REQUESTED",
                ),
            )
            .outerjoin(ar, ar.c.action_id == a.c.action_id)
            .where(ar.c.action_id.is_(None), a.c.tool_id.like("cx\\_%"))
        )
        if tenant is not None:
            q = q.where(a.c.tenant_id == tenant)
        for r in conn.execute(q).all():
            slug = r.tool_id[3:].split("_", 1)[0]
            cfg_row = conn.execute(
                select(cx.c.type_id, cx.c.config).where(
                    cx.c.tenant_id == r.tenant_id, cx.c.slug == slug
                )
            ).one_or_none()
            if cfg_row is None or cfg_row.type_id != "github":
                continue
            repo: str | None = None
            try:
                plaintext = store.load_payload(conn, r.event_id)
            except PayloadUnavailable:
                plaintext = None
            if plaintext is not None:
                args = (decode(plaintext).get("intent") or {}).get("args") or {}
                if isinstance(args, dict) and isinstance(args.get("repo"), str):
                    repo = args["repo"]
            if repo is None:
                repos = (cfg_row.config or {}).get("repos")
                repo = repos[0] if isinstance(repos, list) and repos else None
            if not isinstance(repo, str) or not full.match(repo):
                done["skipped"] += 1
                continue
            conn.execute(insert(ar).values(action_id=r.action_id, tenant_id=r.tenant_id, repo=repo))
            done["filled"] += 1
    return done
