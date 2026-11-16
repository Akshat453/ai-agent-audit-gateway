"""Phase 4 risk engine + risk-adaptive sealing (ADR-0026).

* ``risk_policies``: immutable, versioned risk policy rows. ``canonical`` holds the AGW-CBOR-v1
  bytes of the validated document; ``digest = SHA-256(TAG("AGW/risk-policy/v1") || canonical)``
  is what POLICY_EVALUATED references. Append-only (same triggers as evidence).
* ``tool_registry.risk_attributes``: the Phase 4 tool risk metadata (data classification,
  reversibility, destination/volume fields, MEDIUM effect). Backfilled for the three Phase 1
  demo tools; any other existing row stays NULL and fails registry sync (fail closed).
* ``agents.trust_tier``: trusted | standard | untrusted. NULL = missing = scored as untrusted.
* ``evidence_events.risk_level``: the risk level of the action an event belongs to, written
  once at insert (rows stay append-only). It is NOT part of the hashed header; it only lets
  the sealer derive risk triggers from durable rows. NULL = no risk (receipts, legacy rows).
* ``epochs.anchor_priority``: ROUTINE | PRIORITY | CRITICAL, for the anchoring phase.
* ``policies``: seeds ``default`` v2 (per-level defaults, CRITICAL exception rule).

Revision ID: 0004_phase4_risk
Revises: 0003_phase3_merkle_epochs
Create Date: 2026-11-15
"""

import json

from alembic import op

revision = "0004_phase4_risk"
down_revision = "0003_phase3_merkle_epochs"
branch_labels = None
depends_on = None

# Frozen copy of agw_gateway.policies.default_policy.DEFAULT_POLICY_V2 (migrations never
# import application code).
DEFAULT_POLICY_V2 = {
    "policy_id": "default",
    "version": 2,
    "default_effect": "DENY",
    "rules": [
        {"rule_id": "allow-low", "effect": "ALLOW", "match": {"risk_levels": ["LOW"]}},
        {"rule_id": "allow-medium", "effect": "ALLOW", "match": {"risk_levels": ["MEDIUM"]}},
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

# Risk attributes of the Phase 1 demo tools (same values as agw_gateway.tools.demo).
DEMO_TOOL_RISK = {
    ("public_doc_search", "1.0.0"): {
        "data_classification": "public",
        "reversible": True,
        "destination_field": None,
        "volume_field": None,
        "medium_effect": "ALLOW",
    },
    ("create_ticket", "1.0.0"): {
        "data_classification": "internal",
        "reversible": True,
        "destination_field": None,
        "volume_field": None,
        "medium_effect": "ALLOW",
    },
    ("delete_record", "1.0.0"): {
        "data_classification": "confidential",
        "reversible": False,
        "destination_field": None,
        "volume_field": None,
        "medium_effect": "REQUIRE_APPROVAL",
    },
}

SQL = """
CREATE TABLE risk_policies (
    policy_id   text NOT NULL,
    version     integer NOT NULL CHECK (version >= 1),
    digest      bytea NOT NULL UNIQUE CHECK (octet_length(digest) = 32),
    canonical   bytea NOT NULL,
    document    jsonb NOT NULL,           -- derived, non-authoritative projection
    created_at  timestamptz NOT NULL DEFAULT now(),
    created_by  text NOT NULL,
    PRIMARY KEY (policy_id, version)
);
CREATE TRIGGER risk_policies_no_update_delete BEFORE UPDATE OR DELETE ON risk_policies
    FOR EACH ROW EXECUTE FUNCTION agw_forbid_mutation();
CREATE TRIGGER risk_policies_no_truncate BEFORE TRUNCATE ON risk_policies
    FOR EACH STATEMENT EXECUTE FUNCTION agw_forbid_mutation();

ALTER TABLE tool_registry ADD COLUMN risk_attributes jsonb NULL;

ALTER TABLE agents ADD COLUMN trust_tier text NULL
    CHECK (trust_tier IN ('trusted', 'standard', 'untrusted'));

ALTER TABLE evidence_events ADD COLUMN risk_level text NULL
    CHECK (risk_level IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL'));
CREATE INDEX evidence_events_pending_risk ON evidence_events (tenant_id, seq)
    WHERE risk_level IN ('HIGH', 'CRITICAL');

ALTER TABLE epochs ADD COLUMN anchor_priority text NOT NULL DEFAULT 'ROUTINE'
    CHECK (anchor_priority IN ('ROUTINE', 'PRIORITY', 'CRITICAL'));

GRANT SELECT, INSERT ON risk_policies TO agw_app;
"""


def upgrade() -> None:
    op.execute(SQL)
    bind = op.get_bind()
    for (tool_id, version), attrs in DEMO_TOOL_RISK.items():
        bind.exec_driver_sql(
            "UPDATE tool_registry SET risk_attributes = %(a)s::jsonb "
            "WHERE tool_id = %(t)s AND version = %(v)s",
            {"a": json.dumps(attrs), "t": tool_id, "v": version},
        )
    bind.exec_driver_sql(
        "INSERT INTO policies (policy_id, version, document, created_by) "
        "VALUES (%(pid)s, %(ver)s, %(doc)s::jsonb, 'migration:0004_phase4_risk')",
        {"pid": "default", "ver": 2, "doc": json.dumps(DEFAULT_POLICY_V2)},
    )


def downgrade() -> None:
    raise RuntimeError("risk policies and evidence columns are evidence; no downgrade")
