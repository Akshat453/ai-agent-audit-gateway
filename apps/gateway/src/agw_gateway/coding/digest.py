"""The coding action digest: what a coding approval is bound to (ADR-0034 §5). Pure.

::

    coding_action_digest = SHA-256(TAG("AGW/coding-action/v1") || cbor({
        v: 1, tenant, device, developer, session, kind, type, targets (normalized),
        content {diff?, content?, args?}, policy_id, policy_version, policy_digest, level }))

An identical retry (same session, same normalized targets, same diff, same policy version
and level) has the same digest and can consume the approval exactly once; any change (a
different command, path, diff, a new policy version) gives a different digest and needs a
new approval. The git HEAD is deliberately NOT bound (a commit between the request and the
retry does not change what the action does); it is recorded in the evidence instead.
"""

from __future__ import annotations

import hashlib
from typing import Any, Final
from uuid import UUID

from agw_gateway.coding.globs import PathInvalid, normalize_path
from agw_gateway.coding.model import CodingAction
from agw_gateway.coding.policy import CodingDecision
from agw_gateway.crypto.canonical import encode
from agw_gateway.crypto.tags import CODING_ACTION_TAG, CODING_REPO_TAG, domain_tag

_ACTION: Final = domain_tag(CODING_ACTION_TAG)
_REPO: Final = domain_tag(CODING_REPO_TAG)


def repo_digest(remote_url: str) -> bytes:
    return hashlib.sha256(_REPO + remote_url.encode("utf-8")).digest()


def normalized_targets(action: CodingAction) -> dict[str, Any]:
    t = action.targets
    out: dict[str, Any] = {}
    paths: list[str] = []
    for p in t.paths:
        try:
            paths.append(normalize_path(p, action.workspace_root))
        except PathInvalid:
            paths.append(p)
    if paths:
        out["paths"] = paths
    if t.argv:
        out["argv"] = list(t.argv)
    if t.command is not None:
        out["command"] = t.command
    if t.url is not None:
        out["url"] = t.url
    if t.query is not None:
        out["query"] = t.query
    if t.mcp is not None:
        out["mcp"] = {"tool": t.mcp.tool, **({"server": t.mcp.server} if t.mcp.server else {})}
    return out


def coding_action_digest(
    *,
    tenant: str,
    device: UUID,
    developer: UUID,
    session: UUID,
    action: CodingAction,
    diff_digest: bytes | None,
    decision: CodingDecision,
) -> bytes:
    content: dict[str, Any] = {}
    if diff_digest is not None:
        content["diff"] = diff_digest
    if action.content_digests.content is not None:
        content["content"] = bytes.fromhex(action.content_digests.content)
    if action.content_digests.args is not None:
        content["args"] = bytes.fromhex(action.content_digests.args)
    record = {
        "v": 1,
        "tenant": tenant,
        "device": device.bytes,
        "developer": developer.bytes,
        "session": session.bytes,
        "kind": action.agent_kind,
        "type": action.action_type,
        "targets": normalized_targets(action),
        "content": content,
        "policy_id": decision.policy_id,
        "policy_version": decision.policy_version,
        "policy_digest": decision.policy_digest,
        "level": decision.level,
    }
    return hashlib.sha256(_ACTION + encode(record)).digest()
