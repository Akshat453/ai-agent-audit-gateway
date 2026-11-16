"""Domain-separation tags (06 §2, ADR-0006). One tag per hash type; never reused."""

from __future__ import annotations

from typing import Final


def domain_tag(tag: str) -> bytes:
    """``TAG(t) = u8(len(utf8(t))) || utf8(t)``; length in [2, 255]."""
    raw = tag.encode("utf-8")
    if not 2 <= len(raw) <= 255:
        raise ValueError("tag length out of range")
    return bytes([len(raw)]) + raw


APIKEY_TAG: Final = "AGW/apikey/v1"
REQUEST_TAG: Final = "AGW/request/v1"
EVENT_TAG: Final = "AGW/event/v1"
PAYLOAD_TAG: Final = "AGW/payload/v1"
ARGS_TAG: Final = "AGW/args/v1"
RISK_POLICY_TAG: Final = "AGW/risk-policy/v1"
# Phase 5 (ADR-0027): approvals.
ACTION_TAG: Final = "AGW/action/v1"
POLICY_TAG: Final = "AGW/policy/v1"
APPROVAL_DECISION_TAG: Final = "AGW/approval-decision/v1"
APPROVAL_SIG_TAG: Final = "AGW/approval-sig/v1"
SESSION_TAG: Final = "AGW/session/v1"
# Phase 6 (ADR-0028): on-chain recorder identity (no tenant name on-chain).
RECORDER_TAG: Final = "AGW/recorder/v1"
# Phase 7 (ADR-0029): encryption, redaction and disclosure. AEAD labels are not hash inputs
# but use the same TAG encoding (06 §2).
PAYLOAD_AAD_TAG: Final = "AGW/payload-aad/v1"
DEK_WRAP_TAG: Final = "AGW/dek-wrap-aad/v1"
SEALED_OPS_TAG: Final = "AGW/sealed-ops/v1"
REDACT_TAG: Final = "AGW/redact/v1"
DISCLOSURE_TAG: Final = "AGW/disclosure/v1"
DISCLOSURE_IDS_TAG: Final = "AGW/disclosure-ids/v1"
# Phase 8 (ADR-0030): delegation tokens and integration (MCP) credentials.
DELEGATION_SIG_TAG: Final = "AGW/delegation-sig/v1"
DELEGATION_TOKEN_TAG: Final = "AGW/delegation-token/v1"  # noqa: S105
INTEGRATION_KEY_TAG: Final = "AGW/integration-key/v1"
MONITOR_REPORT_TAG: Final = "AGW/monitor-report/v1"
