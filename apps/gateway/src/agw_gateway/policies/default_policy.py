"""Default policy document, verbatim from 04 §4.1. Seeded as `default` v1 by migration 0001."""

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
