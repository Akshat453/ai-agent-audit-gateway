"""Default policy documents. v1 (04 §4.1) is seeded by migration 0001, v2 (ADR-0026) by 0004."""

from __future__ import annotations

from typing import Any, Final

DEFAULT_POLICY_DOCUMENT: Final[dict[str, Any]] = {
    "policy_id": "default",
    "version": 1,
    "default_effect": "DENY",
    "rules": [
        {
            "rule_id": "allow-low-read",
            "effect": "ALLOW",
            "match": {
                "operation_types": ["read"],
                "risk_levels": ["LOW"],
                "environments": ["dev", "staging", "prod"],
            },
        },
        {
            "rule_id": "allow-medium-ticket",
            "effect": "ALLOW",
            "match": {"tools": ["create_ticket"], "risk_levels": ["LOW", "MEDIUM"]},
        },
        {
            "rule_id": "approve-high",
            "effect": "REQUIRE_APPROVAL",
            "match": {"risk_levels": ["HIGH"]},
        },
        {"rule_id": "deny-delete-record", "effect": "DENY", "match": {"tools": ["delete_record"]}},
        {"rule_id": "deny-critical", "effect": "DENY", "match": {"risk_levels": ["CRITICAL"]}},
    ],
}


# v2 (Phase 4): per-level defaults live in code (engine._level_default); the document only
# allows LOW/MEDIUM through, keeps the delete_record ban, and declares the one CRITICAL
# exception (IAM changes outside prod by holders of iam:admin -> still REQUIRE_APPROVAL).
DEFAULT_POLICY_V2: Final[dict[str, Any]] = {
    "policy_id": "default",
    "version": 2,
    "default_effect": "DENY",
    "rules": [
        {
            "rule_id": "allow-low",
            "effect": "ALLOW",
            "match": {"risk_levels": ["LOW"]},
        },
        {
            "rule_id": "allow-medium",
            "effect": "ALLOW",
            "match": {"risk_levels": ["MEDIUM"]},
        },
        {
            "rule_id": "approve-high",
            "effect": "REQUIRE_APPROVAL",
            "match": {"risk_levels": ["HIGH"]},
            "control_ids": ["HITL-APPROVAL"],
        },
        {
            "rule_id": "iam-change-exception",
            "effect": "REQUIRE_APPROVAL",
            "critical_exception": True,
            "match": {
                "tools": ["update_iam_role"],
                "environments": ["dev", "staging"],
                "scopes_any": ["iam:admin"],
            },
            "control_ids": ["HITL-APPROVAL", "SOD-REVIEW"],
        },
        {"rule_id": "deny-delete-record", "effect": "DENY", "match": {"tools": ["delete_record"]}},
    ],
}
