"""Risk policy storage (ADR-0026). The I/O side of the pure ``agw_gateway.risk`` package.

* ``sync_risk_policy`` (startup, like the tool registry sync): insert the configured policy
  file as an immutable row keyed by (policy_id, version). If that version already exists with
  a DIFFERENT digest, startup fails: a version is immutable, a change needs a new version.
* ``RiskPolicyStore.active``: the latest version of the active policy id, rebuilt from the
  stored canonical bytes (re-hashed against the stored digest) and cached per digest.
"""

from __future__ import annotations

import threading
from importlib.resources import files
from pathlib import Path

from sqlalchemy import Engine, select
from sqlalchemy.dialects.postgresql import insert

from agw_gateway.crypto.canonical import decode, to_json_projection
from agw_gateway.db import tables as t
from agw_gateway.risk import (
    RiskPolicy,
    RiskPolicyLoadError,
    load_risk_policy_canonical,
    load_risk_policy_toml,
)

DEFAULT_RISK_POLICY_FILE = "default_risk_policy.toml"


def default_risk_policy_text() -> str:
    return files("agw_gateway.risk").joinpath(DEFAULT_RISK_POLICY_FILE).read_text("utf-8")


def read_risk_policy_file(path: Path | None) -> RiskPolicy:
    text = default_risk_policy_text() if path is None else path.read_text("utf-8")
    return load_risk_policy_toml(text)


def store_risk_policy(engine: Engine, policy: RiskPolicy, created_by: str) -> bytes:
    """Insert-if-absent. Returns the digest. Raises if the version exists with other bytes."""
    canonical = policy.canonical_bytes()
    digest = policy.digest()
    with engine.begin() as conn:
        conn.execute(
            insert(t.risk_policies)
            .values(
                policy_id=policy.policy_id,
                version=policy.version,
                digest=digest,
                canonical=canonical,
                document=to_json_projection(decode(canonical)),
                created_by=created_by,
            )
            .on_conflict_do_nothing()
        )
        stored = conn.execute(
            select(t.risk_policies.c.digest).where(
                t.risk_policies.c.policy_id == policy.policy_id,
                t.risk_policies.c.version == policy.version,
            )
        ).scalar_one()
    if bytes(stored) != digest:
        raise RiskPolicyLoadError(
            f"risk policy {policy.policy_id} v{policy.version} changed without a version bump"
        )
    return digest


def sync_risk_policy(engine: Engine, path: Path | None) -> RiskPolicy:
    policy = read_risk_policy_file(path)
    store_risk_policy(engine, policy, created_by="gateway-startup")
    return policy


class RiskPolicyStore:
    def __init__(self, engine: Engine, policy_id: str) -> None:
        self._engine = engine
        self._policy_id = policy_id
        self._cache: dict[bytes, RiskPolicy] = {}
        self._lock = threading.Lock()

    def active(self) -> RiskPolicy:
        with self._engine.connect() as conn:
            row = conn.execute(
                select(t.risk_policies.c.digest, t.risk_policies.c.canonical)
                .where(t.risk_policies.c.policy_id == self._policy_id)
                .order_by(t.risk_policies.c.version.desc())
                .limit(1)
            ).one_or_none()
        if row is None:
            raise RiskPolicyLoadError(f"no risk policy {self._policy_id!r} stored (fail closed)")
        digest = bytes(row.digest)
        with self._lock:
            cached = self._cache.get(digest)
            if cached is None:
                cached = load_risk_policy_canonical(bytes(row.canonical), digest)
                self._cache[digest] = cached
        return cached
