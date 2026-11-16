"""Reads of the immutable ``policies`` rows (04 §4.1). Returns the validated model AND the
stored document, whose canonical digest is bound into approvals (ADR-0027)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Final

from sqlalchemy import Connection, select

from agw_gateway.db import tables as t
from agw_gateway.policies.models import PolicyDocument, load_policy_document

ACTIVE_POLICY_ID: Final = "default"


@dataclass(frozen=True)
class StoredPolicy:
    document: PolicyDocument
    raw: dict[str, Any]


def load_active_policy(conn: Connection, policy_id: str = ACTIVE_POLICY_ID) -> StoredPolicy:
    """Latest version of ``policy_id``."""
    raw = conn.execute(
        select(t.policies.c.document)
        .where(t.policies.c.policy_id == policy_id)
        .order_by(t.policies.c.version.desc())
        .limit(1)
    ).scalar_one()
    return StoredPolicy(load_policy_document(raw), dict(raw))


def load_policy_version(conn: Connection, policy_id: str, version: int) -> StoredPolicy | None:
    raw = conn.execute(
        select(t.policies.c.document).where(
            t.policies.c.policy_id == policy_id, t.policies.c.version == version
        )
    ).scalar_one_or_none()
    if raw is None:
        return None
    return StoredPolicy(load_policy_document(raw), dict(raw))
