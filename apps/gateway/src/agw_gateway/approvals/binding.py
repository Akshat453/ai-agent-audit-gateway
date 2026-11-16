"""Action digest and signed approval decision records (Phase 5, ADR-0027). Pure: no I/O.

Action digest (computed once at request time, stored on the action, recomputed from the
stored request at authorization time)::

    action_digest = SHA-256(TAG("AGW/action/v1") || cbor({
        v, tenant, agent_id, tool_id, tool_version, canonical_args_digest, target_resource,
        environment, policy_id, policy_version, policy_digest, risk_policy_digest,
        risk_level, delegation_ref }))

``action_id`` is deliberately NOT in the digest: two identical requests have the same digest,
and it is the approval row (bound to one ``action_id``, single-use nonce) that stops an
approval for one of them from authorizing the other.

Decision record (what an approver's decision attests; Ed25519-signed by the gateway)::

    decision_digest = SHA-256(TAG("AGW/approval-decision/v1") || cbor({
        v, tenant, approval_id, action_id, action_digest, nonce, decision, approver_id,
        decided_at, reason }))
    signature = Ed25519(gateway key, TAG("AGW/approval-sig/v1") || decision_digest)

Signing the tagged 32-byte digest (not the record) lets a verifier check the signature from
the event header alone; the full record is in the event's payload.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Final, Literal
from uuid import UUID

from agw_gateway.crypto.canonical import encode, profile_value
from agw_gateway.crypto.tags import (
    ACTION_TAG,
    APPROVAL_DECISION_TAG,
    APPROVAL_SIG_TAG,
    POLICY_TAG,
    domain_tag,
)
from agw_gateway.tools.metadata import ToolMetadata

_ACTION: Final = domain_tag(ACTION_TAG)
_POLICY: Final = domain_tag(POLICY_TAG)
_DECISION: Final = domain_tag(APPROVAL_DECISION_TAG)
_SIG: Final = domain_tag(APPROVAL_SIG_TAG)

Decision = Literal["APPROVED", "REJECTED"]


def policy_digest(document: Mapping[str, Any]) -> bytes:
    """Digest of a STORED policy document (the JSON exactly as stored, canonically encoded).

    Hashing the stored document rather than a model dump keeps the digest of an existing
    version stable when the policy model later gains optional fields.
    """
    return hashlib.sha256(_POLICY + encode(profile_value(dict(document)))).digest()


def target_resource(meta: ToolMetadata, validated_args: Mapping[str, Any]) -> Any:
    """``args[target_field]``, else ``args[destination_field]``, else None (04 §5).

    Kept as a profile value (string, list of strings, ...) rather than flattened to text, so
    two different targets can never encode to the same bytes.
    """
    for name in (meta.target_field, meta.destination_field):
        if name is not None and name in validated_args:
            return profile_value(validated_args[name])
    return None


@dataclass(frozen=True)
class ActionBinding:
    tenant: str
    agent_id: UUID
    tool_id: str
    tool_version: str
    args_digest: bytes
    target: Any
    environment: str
    policy_id: str
    policy_version: int
    policy_digest: bytes
    risk_policy_digest: bytes
    risk_level: str
    delegation_depth: int | None
    # Phase 8 (ADR-0030): a gateway-verified delegation is bound by id + token hash.
    delegation_id: UUID | None = None
    delegation_hash: bytes | None = None

    def _delegation_ref(self) -> dict[str, Any] | None:
        if self.delegation_id is not None and self.delegation_hash is not None:
            return {
                "id": self.delegation_id.bytes,
                "th": self.delegation_hash,
                "depth": self.delegation_depth,
                "declared_by": "gateway",
            }
        if self.delegation_depth is None:
            return None
        return {"depth": self.delegation_depth, "declared_by": "agent"}

    def record(self) -> dict[str, Any]:
        return {
            "v": 1,
            "tenant": self.tenant,
            "agent_id": self.agent_id.bytes,
            "tool_id": self.tool_id,
            "tool_version": self.tool_version,
            "canonical_args_digest": self.args_digest,
            "target_resource": self.target,
            "environment": self.environment,
            "policy_id": self.policy_id,
            "policy_version": self.policy_version,
            "policy_digest": self.policy_digest,
            "risk_policy_digest": self.risk_policy_digest,
            "risk_level": self.risk_level,
            "delegation_ref": self._delegation_ref(),
        }

    def digest(self) -> bytes:
        return hashlib.sha256(_ACTION + encode(self.record())).digest()


@dataclass(frozen=True)
class DecisionRecord:
    tenant: str
    approval_id: UUID
    action_id: UUID
    action_digest: bytes
    nonce: bytes
    decision: Decision
    approver_id: UUID
    decided_at_us: int
    reason: str

    def record(self) -> dict[str, Any]:
        return {
            "v": 1,
            "tenant": self.tenant,
            "approval_id": self.approval_id.bytes,
            "action_id": self.action_id.bytes,
            "action_digest": self.action_digest,
            "nonce": self.nonce,
            "decision": self.decision,
            "approver_id": self.approver_id.bytes,
            "decided_at": self.decided_at_us,
            "reason": self.reason,
        }

    def digest(self) -> bytes:
        return hashlib.sha256(_DECISION + encode(self.record())).digest()


def signing_message(decision_digest: bytes) -> bytes:
    """The exact bytes the gateway signs for a decision (domain-separated)."""
    if len(decision_digest) != 32:
        raise ValueError("decision digest must be 32 bytes")
    return _SIG + decision_digest


def render_args(validated_args: Mapping[str, Any]) -> str:
    """Safe display form for approvers: sorted keys, ASCII only.

    ``ensure_ascii`` turns every non-ASCII character (bidi overrides, zero-width joiners,
    homoglyphs) into a visible ``\\uXXXX`` escape, so what the approver reads is unambiguous.
    """
    return json.dumps(dict(validated_args), sort_keys=True, ensure_ascii=True, indent=1)
