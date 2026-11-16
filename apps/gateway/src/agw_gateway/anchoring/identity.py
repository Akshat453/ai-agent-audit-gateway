"""Recorder identity and finality levels (ADR-0028). Pure functions, no I/O."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from agw_gateway.crypto.tags import RECORDER_TAG, domain_tag

_TAG = domain_tag(RECORDER_TAG)


def recorder_id(tenant_id: str, deployment_salt: bytes) -> bytes:
    """recorderId = SHA-256(TAG("AGW/recorder/v1") || u16(len(tenant)) || tenant || salt).

    The tenant name never goes on-chain. The 32-byte deployment salt stops an observer from
    confirming a guessed tenant name against the chain (09 §7 noted names were guessable from
    the unsalted tenantKey). Auditors receive the recorder id itself, never the salt.
    """
    t = tenant_id.encode("utf-8")
    if not 1 <= len(t) <= 63:
        raise ValueError("tenant id length out of range")
    if len(deployment_salt) != 32:
        raise ValueError("deployment salt must be 32 bytes")
    return hashlib.sha256(_TAG + len(t).to_bytes(2, "big") + t + deployment_salt).digest()


@dataclass(frozen=True)
class Finality:
    """``included`` | ``confirmations:<N>`` | ``safe`` | ``finalized`` (09 §6)."""

    kind: str
    confirmations: int = 0

    @classmethod
    def parse(cls, spec: str) -> Finality:
        if spec in ("included", "safe", "finalized"):
            return cls(spec)
        kind, _, n = spec.partition(":")
        if kind == "confirmations" and n.isdigit() and int(n) >= 1:
            return cls("confirmations", int(n))
        raise ValueError(f"unknown finality level: {spec!r}")

    @property
    def label(self) -> str:
        return f"confirmations:{self.confirmations}" if self.kind == "confirmations" else self.kind

    def final_block(self, latest: int, tagged: int | None = None) -> int:
        """Highest block number that counts as final. ``tagged`` is the node's answer for the
        ``safe``/``finalized`` block tag; -1 means nothing is final yet."""
        if self.kind == "included":
            return latest
        if self.kind == "confirmations":
            return latest - self.confirmations + 1
        return -1 if tagged is None else tagged
