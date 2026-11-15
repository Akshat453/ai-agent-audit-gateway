"""Phase 1 core schema: 11 tables, grants, append-only triggers, default policy v1.

Tables per docs/gateway/14 §3. Evidence tables (evidence_events, policies) are append-only by
two independent layers (08 §2): agw_app has no UPDATE/DELETE/TRUNCATE privilege, and triggers
raise for every role that does not disable triggers. Deviation: outbox_jobs.args (ADR-0020).

Revision ID: 0001_phase1_core
Revises:
Create Date: 2026-11-15
"""

import json

from alembic import op

revision = "0001_phase1_core"
down_revision = None
branch_labels = None
depends_on = None

# Frozen copy of docs/gateway/04 §4.1. A unit test asserts it equals
# agw_gateway.policies.default_policy.DEFAULT_POLICY_DOCUMENT.
DEFAULT_POLICY_V1 = {
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

EVENT_TYPES = (
    "ACTION_REQUESTED",
    "POLICY_EVALUATED",
    "ACTION_DENIED",
    "APPROVAL_REQUIRED",
    "ACTION_AUTHORIZED",
    "ACTION_DISPATCHED",
    "ACTION_COMPLETED",
    "ACTION_FAILED",
    "ACTION_OUTCOME_UNKNOWN",
    "SECURITY_VIOLATION",
)

ACTION_STATUSES = (
    "DENIED",
    "PENDING_APPROVAL",
    "AUTHORIZED",
    "DISPATCHED",
    "COMPLETED",
    "FAILED",
    "OUTCOME_UNKNOWN",
)


def _in(values: tuple[str, ...]) -> str:
    return ", ".join(f"'{v}'" for v in values)


SCHEMA_SQL = f"""
CREATE TABLE tenants (
    tenant_id     text PRIMARY KEY CHECK (tenant_id ~ '^[a-z0-9][a-z0-9-]{{0,62}}$'),
    display_name  text NOT NULL,
    next_seq      bigint NOT NULL DEFAULT 0 CHECK (next_seq >= 0),
    created_at    timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE agents (
    agent_id    uuid PRIMARY KEY,
    tenant_id   text NOT NULL REFERENCES tenants(tenant_id),
    name        text NOT NULL,
    scopes      text[] NOT NULL DEFAULT '{{}}',
    status      text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled')),
    created_at  timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, name)
);

CREATE TABLE agent_credentials (
    credential_id  uuid PRIMARY KEY,
    agent_id       uuid NOT NULL REFERENCES agents(agent_id),
    key_id         text NOT NULL UNIQUE CHECK (key_id ~ '^[0-9a-f]{{16}}$'),
    key_digest     bytea NOT NULL CHECK (octet_length(key_digest) = 32),
    created_at     timestamptz NOT NULL DEFAULT now(),
    expires_at     timestamptz NULL,
    revoked_at     timestamptz NULL
);

CREATE TABLE tool_registry (
    tool_id               text NOT NULL,
    version               text NOT NULL,
    operation_type        text NOT NULL
        CHECK (operation_type IN ('read', 'create', 'update', 'delete', 'execute')),
    sensitivity           text NOT NULL
        CHECK (sensitivity IN ('public', 'internal', 'confidential', 'restricted')),
    base_risk             text NOT NULL CHECK (base_risk IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    environments_allowed  text[] NOT NULL,
    required_scope        text NOT NULL,
    is_idempotent         boolean NOT NULL,
    external_effect       boolean NOT NULL,
    target_field          text NULL,
    tags                  text[] NOT NULL DEFAULT '{{}}',
    args_schema           jsonb NOT NULL,
    adapter               text NOT NULL,
    enabled               boolean NOT NULL DEFAULT true,
    registered_at         timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tool_id, version)
);

CREATE TABLE policies (
    policy_id   text NOT NULL,
    version     integer NOT NULL CHECK (version >= 1),
    document    jsonb NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    created_by  text NOT NULL,
    PRIMARY KEY (policy_id, version)
);

CREATE TABLE actions (
    action_id        uuid PRIMARY KEY,
    tenant_id        text NOT NULL REFERENCES tenants(tenant_id),
    agent_id         uuid NOT NULL REFERENCES agents(agent_id),
    run_id           uuid NOT NULL,
    tool_id          text NOT NULL,
    tool_version     text NULL,
    environment      text NOT NULL CHECK (environment IN ('dev', 'staging', 'prod')),
    status           text NOT NULL CHECK (status IN ({_in(ACTION_STATUSES)})),
    decision         text NOT NULL CHECK (decision IN ('ALLOW', 'DENY', 'REQUIRE_APPROVAL')),
    risk_level       text NOT NULL CHECK (risk_level IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    policy_id        text NOT NULL,
    policy_version   integer NOT NULL,
    idempotency_key  text NOT NULL,
    result_public    jsonb NULL,
    error_code       text NULL,
    created_at       timestamptz NOT NULL DEFAULT now(),
    updated_at       timestamptz NOT NULL DEFAULT now(),
    version          integer NOT NULL DEFAULT 1
);
CREATE INDEX actions_agent_run_idx ON actions (agent_id, run_id);

CREATE TABLE evidence_events (
    event_id         uuid PRIMARY KEY,
    tenant_id        text NOT NULL REFERENCES tenants(tenant_id),
    seq              bigint NOT NULL CHECK (seq >= 0),
    event_type       text NOT NULL CHECK (event_type IN ({_in(EVENT_TYPES)})),
    schema_version   smallint NOT NULL DEFAULT 1,
    action_id        uuid NULL,
    run_id           uuid NULL,
    agent_id         uuid NULL,
    occurred_at      timestamptz NOT NULL DEFAULT clock_timestamp(),
    body             jsonb NOT NULL,
    canonical_bytes  bytea NULL,
    UNIQUE (tenant_id, seq)
);
CREATE INDEX evidence_events_action_seq_idx ON evidence_events (action_id, seq);
CREATE INDEX evidence_events_run_seq_idx ON evidence_events (run_id, seq);

CREATE TABLE outbox_jobs (
    job_id            bigserial PRIMARY KEY,
    kind              text NOT NULL CHECK (kind IN ('DISPATCH')),
    tenant_id         text NOT NULL REFERENCES tenants(tenant_id),
    action_id         uuid NULL REFERENCES actions(action_id),
    status            text NOT NULL DEFAULT 'PENDING'
        CHECK (status IN ('PENDING', 'CLAIMED', 'DONE', 'FAILED')),
    available_at      timestamptz NOT NULL DEFAULT now(),
    attempts          integer NOT NULL DEFAULT 0,
    claimed_by        text NULL,
    lease_expires_at  timestamptz NULL,
    last_error_code   text NULL,
    args              jsonb NULL,
    created_at        timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX outbox_jobs_dispatch_action_uq
    ON outbox_jobs (action_id) WHERE kind = 'DISPATCH';
CREATE INDEX outbox_jobs_status_available_idx ON outbox_jobs (status, available_at);

CREATE TABLE idempotency_keys (
    agent_id          uuid NOT NULL REFERENCES agents(agent_id),
    key               text NOT NULL CHECK (key ~ '^[A-Za-z0-9_\\-:.]{{1,128}}$'),
    fingerprint       bytea NOT NULL,
    fingerprint_alg   text NOT NULL,
    action_id         uuid NOT NULL,
    response_status   integer NOT NULL,
    response_body     jsonb NOT NULL,
    created_at        timestamptz NOT NULL DEFAULT now(),
    expires_at        timestamptz NOT NULL,
    PRIMARY KEY (agent_id, key)
);

CREATE SCHEMA demo;
CREATE TABLE demo.tickets (
    ticket_id          uuid PRIMARY KEY,
    title              text NOT NULL,
    body               text NOT NULL,
    priority           text NOT NULL CHECK (priority IN ('low', 'normal', 'high')),
    created_by_action  uuid NOT NULL UNIQUE,
    created_at         timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE demo.records (
    record_id   uuid PRIMARY KEY,
    content     text NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now()
);

-- Append-only enforcement, layer 2 (08 §2): raises for any role that does not disable triggers.
CREATE FUNCTION agw_forbid_mutation() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = TG_TABLE_NAME || ' is append-only';
END
$$;

CREATE TRIGGER evidence_events_no_update_delete
    BEFORE UPDATE OR DELETE ON evidence_events
    FOR EACH ROW EXECUTE FUNCTION agw_forbid_mutation();
CREATE TRIGGER evidence_events_no_truncate
    BEFORE TRUNCATE ON evidence_events
    FOR EACH STATEMENT EXECUTE FUNCTION agw_forbid_mutation();
CREATE TRIGGER policies_no_update_delete
    BEFORE UPDATE OR DELETE ON policies
    FOR EACH ROW EXECUTE FUNCTION agw_forbid_mutation();
CREATE TRIGGER policies_no_truncate
    BEFORE TRUNCATE ON policies
    FOR EACH STATEMENT EXECUTE FUNCTION agw_forbid_mutation();

-- Append-only enforcement, layer 1: least-privilege grants for the runtime role.
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM agw_app;
GRANT SELECT ON tenants TO agw_app;
GRANT UPDATE (next_seq) ON tenants TO agw_app;
GRANT SELECT ON agents, agent_credentials TO agw_app;
GRANT SELECT, INSERT ON tool_registry TO agw_app;
GRANT SELECT, INSERT ON policies TO agw_app;
GRANT SELECT, INSERT ON evidence_events TO agw_app;
GRANT SELECT, INSERT, UPDATE ON actions TO agw_app;
GRANT SELECT, INSERT, UPDATE ON outbox_jobs TO agw_app;
GRANT USAGE, SELECT ON SEQUENCE outbox_jobs_job_id_seq TO agw_app;
GRANT SELECT, INSERT, DELETE ON idempotency_keys TO agw_app;
GRANT USAGE ON SCHEMA demo TO agw_app;
GRANT SELECT, INSERT ON demo.tickets TO agw_app;
GRANT SELECT, DELETE ON demo.records TO agw_app;
"""


def upgrade() -> None:
    op.execute(SCHEMA_SQL)
    bind = op.get_bind()
    bind.exec_driver_sql(
        "INSERT INTO policies (policy_id, version, document, created_by) "
        "VALUES (%(pid)s, %(ver)s, %(doc)s::jsonb, 'migration:0001_phase1_core')",
        {"pid": "default", "ver": 1, "doc": json.dumps(DEFAULT_POLICY_V1)},
    )


def downgrade() -> None:
    # Dropping evidence is never part of a normal workflow; dev only (14 §8).
    op.execute(
        """
        DROP SCHEMA demo CASCADE;
        DROP TABLE idempotency_keys, outbox_jobs, evidence_events, actions, policies,
                   tool_registry, agent_credentials, agents, tenants CASCADE;
        DROP FUNCTION agw_forbid_mutation();
        """
    )
