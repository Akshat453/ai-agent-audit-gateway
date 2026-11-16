"""Phase 8: delegation tokens + integration (MCP) credentials (ADR-0030).

* ``delegation_signing_keys``: the gateway's delegation-token Ed25519 PUBLIC keys; append-only
  (publishing a key never makes it trusted: the configured key file does).
* ``delegations``: one row per issued token. Immutable except ``uses`` (consumed in tx1 of a
  child action) and ``revoked_at``/``revoked_by``. ``uses <= max_uses`` is a CHECK, so a
  concurrent over-use fails in the database, not only in code. Every row references the
  DELEGATION_CREATED event that recorded it.
* ``actions.delegation_id``: the delegation a child action was requested under.
* ``agent_credentials.audience``: NULL = a key for the gateway API itself; otherwise the
  canonical URI of the ONE resource (an MCP adapter) the key is valid at. The gateway API
  refuses audience-bound keys, so an MCP token can never be replayed against it directly.
* ``integration_clients``: confidential clients (the MCP adapter) that may exchange an agent's
  audience-bound token for a short-lived gateway token (RFC 8693 token exchange).
* ``exchanged_tokens``: those short-lived tokens (<= 15 min, CHECK), bound to the subject
  credential (revoking it kills them) and to the client that obtained them (``act``).
* Event types DELEGATION_CREATED, DELEGATION_REVOKED.

Revision ID: 0009_phase8_delegation
Revises: 0008_phase7_drop_plaintext
Create Date: 2026-11-16
"""

from alembic import op

revision = "0009_phase8_delegation"
down_revision = "0008_phase7_drop_plaintext"
branch_labels = None
depends_on = None

SQL = """
CREATE TABLE delegation_signing_keys (
    key_id      text PRIMARY KEY CHECK (key_id ~ '^[0-9a-f]{16}$'),
    algorithm   text NOT NULL CHECK (algorithm = 'Ed25519'),
    public_key  bytea NOT NULL UNIQUE CHECK (octet_length(public_key) = 32),
    created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE TRIGGER delegation_signing_keys_no_update_delete BEFORE UPDATE OR DELETE
    ON delegation_signing_keys FOR EACH ROW EXECUTE FUNCTION agw_forbid_mutation();
CREATE TRIGGER delegation_signing_keys_no_truncate BEFORE TRUNCATE ON delegation_signing_keys
    FOR EACH STATEMENT EXECUTE FUNCTION agw_forbid_mutation();

CREATE TABLE delegations (
    delegation_id         uuid PRIMARY KEY,
    tenant_id             text NOT NULL REFERENCES tenants (tenant_id),
    issuer_agent_id       uuid NOT NULL REFERENCES agents (agent_id),
    child_agent_id        uuid NOT NULL REFERENCES agents (agent_id),
    parent_delegation_id  uuid NULL REFERENCES delegations (delegation_id),
    depth                 smallint NOT NULL CHECK (depth BETWEEN 1 AND 8),
    scopes                text[] NOT NULL,
    tools                 text[] NOT NULL,
    max_risk              text NOT NULL CHECK (max_risk IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    expires_at            timestamptz NOT NULL,
    max_uses              integer NOT NULL CHECK (max_uses >= 1),
    uses                  integer NOT NULL DEFAULT 0 CHECK (uses >= 0 AND uses <= max_uses),
    token_hash            bytea NOT NULL UNIQUE CHECK (octet_length(token_hash) = 32),
    key_id                text NOT NULL REFERENCES delegation_signing_keys (key_id),
    created_event_id      uuid NOT NULL REFERENCES evidence_events (event_id),
    created_event_hash    bytea NOT NULL CHECK (octet_length(created_event_hash) = 32),
    created_at            timestamptz NOT NULL DEFAULT now(),
    revoked_at            timestamptz NULL,
    revoked_by            text NULL,
    CHECK (issuer_agent_id <> child_agent_id),
    CHECK ((depth = 1) = (parent_delegation_id IS NULL)),
    CHECK ((revoked_at IS NULL) = (revoked_by IS NULL))
);
CREATE INDEX delegations_parent_idx ON delegations (parent_delegation_id);
CREATE INDEX delegations_issuer_idx ON delegations (tenant_id, issuer_agent_id);
CREATE TRIGGER delegations_no_delete BEFORE DELETE ON delegations
    FOR EACH ROW EXECUTE FUNCTION agw_forbid_mutation();
CREATE TRIGGER delegations_no_truncate BEFORE TRUNCATE ON delegations
    FOR EACH STATEMENT EXECUTE FUNCTION agw_forbid_mutation();

ALTER TABLE actions ADD COLUMN IF NOT EXISTS delegation_id uuid NULL;
ALTER TABLE actions ADD CONSTRAINT actions_delegation_fk
    FOREIGN KEY (delegation_id) REFERENCES delegations (delegation_id);
CREATE INDEX actions_delegation_idx ON actions (delegation_id) WHERE delegation_id IS NOT NULL;

ALTER TABLE agent_credentials ADD COLUMN IF NOT EXISTS audience text NULL;
ALTER TABLE agent_credentials ADD CONSTRAINT agent_credentials_audience_check
    CHECK (audience ~ '^https?://[^#?]+$');

CREATE TABLE integration_clients (
    client_id   uuid PRIMARY KEY,
    tenant_id   text NOT NULL REFERENCES tenants (tenant_id),
    name        text NOT NULL,
    audience    text NOT NULL CHECK (audience ~ '^https?://[^#?]+$'),
    key_id      text NOT NULL UNIQUE CHECK (key_id ~ '^[0-9a-f]{16}$'),
    key_digest  bytea NOT NULL CHECK (octet_length(key_digest) = 32),
    status      text NOT NULL CHECK (status IN ('active', 'disabled')),
    created_at  timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, name)
);

CREATE TABLE exchanged_tokens (
    token_id               uuid PRIMARY KEY,
    key_id                 text NOT NULL UNIQUE CHECK (key_id ~ '^[0-9a-f]{16}$'),
    key_digest             bytea NOT NULL CHECK (octet_length(key_digest) = 32),
    agent_id               uuid NOT NULL REFERENCES agents (agent_id),
    subject_credential_id  uuid NOT NULL REFERENCES agent_credentials (credential_id),
    client_id              uuid NOT NULL REFERENCES integration_clients (client_id),
    created_at             timestamptz NOT NULL DEFAULT now(),
    expires_at             timestamptz NOT NULL,
    CHECK (expires_at > created_at AND expires_at <= created_at + interval '15 minutes')
);

ALTER TABLE evidence_events DROP CONSTRAINT evidence_events_event_type_check;
ALTER TABLE evidence_events ADD CONSTRAINT evidence_events_event_type_check CHECK (event_type IN (
    'ACTION_REQUESTED', 'POLICY_EVALUATED', 'ACTION_DENIED', 'APPROVAL_REQUIRED',
    'APPROVAL_GRANTED', 'APPROVAL_DENIED', 'APPROVAL_EXPIRED',
    'ACTION_AUTHORIZED', 'ACTION_DISPATCHED', 'ACTION_COMPLETED', 'ACTION_FAILED',
    'ACTION_OUTCOME_UNKNOWN', 'SECURITY_VIOLATION', 'EPOCH_SEALED',
    'DISCLOSURE_GRANTED', 'DISCLOSURE_ACCESSED', 'PAYLOAD_DELETED',
    'DELEGATION_CREATED', 'DELEGATION_REVOKED'));

GRANT SELECT, INSERT ON delegation_signing_keys TO agw_app;
GRANT SELECT, INSERT ON delegations TO agw_app;
GRANT UPDATE (uses, revoked_at, revoked_by) ON delegations TO agw_app;
GRANT SELECT ON integration_clients TO agw_app;
GRANT SELECT, INSERT ON exchanged_tokens TO agw_app;
"""


def upgrade() -> None:
    op.execute(SQL)


def downgrade() -> None:
    raise RuntimeError("delegation evidence references; no downgrade")
