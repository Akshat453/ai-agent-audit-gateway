"""Phase 5: action-bound human approval (ADR-0027).

* ``humans`` / ``human_sessions``: approver identities, separate from agents. Argon2id hashes;
  session tokens stored as SHA-256 digests only. agw_app reads humans, never writes them
  (operators create humans via the admin CLI as agw_migrator).
* ``approvals``: one per REQUIRE_APPROVAL action. Operational state machine
  PENDING -> APPROVED -> CONSUMED | INVALIDATED, PENDING -> REJECTED | EXPIRED.
* ``approval_decisions``: one row per (approval, approver); append-only. Holds the signed
  decision record fields, its digest and the gateway's Ed25519 signature.
* ``approval_uses``: single-use nonces; PK(nonce), append-only. Inserted in the authorizing tx,
  so a second use is a constraint violation even if every other check were bypassed.
* ``approval_signing_keys``: the gateway's decision-signing PUBLIC keys; append-only.
* ``actions``: action_digest (computed once at request time), request_args (validated args of
  a pending action, needed to recompute the digest and to dispatch), delegation_depth,
  risk_policy_digest; status EXPIRED.
* ``evidence_events``: APPROVAL_GRANTED / APPROVAL_DENIED / APPROVAL_EXPIRED become writable.

Revision ID: 0005_phase5_approvals
Revises: 0004_phase4_risk
Create Date: 2026-11-15
"""

from alembic import op

revision = "0005_phase5_approvals"
down_revision = "0004_phase4_risk"
branch_labels = None
depends_on = None

SQL = """
CREATE TABLE humans (
    human_id       uuid PRIMARY KEY,
    tenant_id      text NOT NULL REFERENCES tenants (tenant_id),
    username       text NOT NULL CHECK (username ~ '^[a-z0-9][a-z0-9._-]{0,63}$'),
    password_hash  text NOT NULL CHECK (password_hash LIKE '$argon2id$%'),
    roles          text[] NOT NULL CHECK (roles <@ ARRAY['approver', 'admin', 'auditor']::text[]),
    status         text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled')),
    created_at     timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, username)
);

CREATE TABLE human_sessions (
    session_pk    uuid PRIMARY KEY,
    session_id    text NOT NULL UNIQUE CHECK (session_id ~ '^[0-9a-f]{16}$'),
    human_id      uuid NOT NULL REFERENCES humans (human_id),
    token_digest  bytea NOT NULL CHECK (octet_length(token_digest) = 32),
    created_at    timestamptz NOT NULL DEFAULT now(),
    expires_at    timestamptz NOT NULL,
    revoked_at    timestamptz NULL
);

CREATE TABLE approvals (
    approval_id         uuid PRIMARY KEY,
    tenant_id           text NOT NULL REFERENCES tenants (tenant_id),
    action_id           uuid NOT NULL UNIQUE REFERENCES actions (action_id),
    action_digest       bytea NOT NULL CHECK (octet_length(action_digest) = 32),
    nonce               bytea NOT NULL UNIQUE CHECK (octet_length(nonce) = 16),
    required_role       text NOT NULL DEFAULT 'approver' CHECK (required_role IN ('approver')),
    required_approvals  smallint NOT NULL DEFAULT 1 CHECK (required_approvals BETWEEN 1 AND 2),
    state               text NOT NULL DEFAULT 'PENDING' CHECK (state IN
        ('PENDING', 'APPROVED', 'REJECTED', 'EXPIRED', 'CONSUMED', 'INVALIDATED')),
    state_reason        text NULL,
    requested_at        timestamptz NOT NULL,
    expires_at          timestamptz NOT NULL,
    updated_at          timestamptz NOT NULL DEFAULT now(),
    CHECK (expires_at > requested_at)
);
CREATE INDEX approvals_open_idx ON approvals (state, expires_at)
    WHERE state IN ('PENDING', 'APPROVED');
CREATE INDEX approvals_tenant_state_idx ON approvals (tenant_id, state, requested_at);

CREATE TABLE approval_decisions (
    approval_id      uuid NOT NULL REFERENCES approvals (approval_id),
    approver_id      uuid NOT NULL REFERENCES humans (human_id),
    decision         text NOT NULL CHECK (decision IN ('APPROVED', 'REJECTED')),
    reason           text NOT NULL CHECK (length(reason) <= 1024),
    decided_at_us    bigint NOT NULL CHECK (decided_at_us > 0),
    decision_digest  bytea NOT NULL UNIQUE CHECK (octet_length(decision_digest) = 32),
    signature        bytea NOT NULL CHECK (octet_length(signature) = 64),
    key_id           text NOT NULL,
    PRIMARY KEY (approval_id, approver_id)   -- one decision per approver (four-eyes)
);

CREATE TABLE approval_uses (
    nonce        bytea PRIMARY KEY CHECK (octet_length(nonce) = 16),
    approval_id  uuid NOT NULL UNIQUE REFERENCES approvals (approval_id),
    action_id    uuid NOT NULL UNIQUE REFERENCES actions (action_id),
    used_at      timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE approval_signing_keys (
    key_id      text PRIMARY KEY CHECK (key_id ~ '^[0-9a-f]{16}$'),
    algorithm   text NOT NULL CHECK (algorithm = 'Ed25519'),
    public_key  bytea NOT NULL UNIQUE CHECK (octet_length(public_key) = 32),
    created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TRIGGER approval_decisions_no_update_delete BEFORE UPDATE OR DELETE ON approval_decisions
    FOR EACH ROW EXECUTE FUNCTION agw_forbid_mutation();
CREATE TRIGGER approval_decisions_no_truncate BEFORE TRUNCATE ON approval_decisions
    FOR EACH STATEMENT EXECUTE FUNCTION agw_forbid_mutation();
CREATE TRIGGER approval_uses_no_update_delete BEFORE UPDATE OR DELETE ON approval_uses
    FOR EACH ROW EXECUTE FUNCTION agw_forbid_mutation();
CREATE TRIGGER approval_uses_no_truncate BEFORE TRUNCATE ON approval_uses
    FOR EACH STATEMENT EXECUTE FUNCTION agw_forbid_mutation();
CREATE TRIGGER approval_signing_keys_no_update_delete BEFORE UPDATE OR DELETE
    ON approval_signing_keys FOR EACH ROW EXECUTE FUNCTION agw_forbid_mutation();
CREATE TRIGGER approval_signing_keys_no_truncate BEFORE TRUNCATE ON approval_signing_keys
    FOR EACH STATEMENT EXECUTE FUNCTION agw_forbid_mutation();

ALTER TABLE actions ADD COLUMN action_digest bytea NULL CHECK (octet_length(action_digest) = 32);
ALTER TABLE actions ADD COLUMN request_args jsonb NULL;
ALTER TABLE actions ADD COLUMN delegation_depth integer NULL CHECK (delegation_depth >= 0);
ALTER TABLE actions ADD COLUMN risk_policy_digest bytea NULL
    CHECK (octet_length(risk_policy_digest) = 32);
ALTER TABLE actions DROP CONSTRAINT actions_status_check;
ALTER TABLE actions ADD CONSTRAINT actions_status_check CHECK (status IN (
    'DENIED', 'PENDING_APPROVAL', 'AUTHORIZED', 'DISPATCHED', 'COMPLETED', 'FAILED',
    'OUTCOME_UNKNOWN', 'EXPIRED'));

ALTER TABLE evidence_events DROP CONSTRAINT evidence_events_event_type_check;
ALTER TABLE evidence_events ADD CONSTRAINT evidence_events_event_type_check CHECK (event_type IN (
    'ACTION_REQUESTED', 'POLICY_EVALUATED', 'ACTION_DENIED', 'APPROVAL_REQUIRED',
    'APPROVAL_GRANTED', 'APPROVAL_DENIED', 'APPROVAL_EXPIRED',
    'ACTION_AUTHORIZED', 'ACTION_DISPATCHED', 'ACTION_COMPLETED', 'ACTION_FAILED',
    'ACTION_OUTCOME_UNKNOWN', 'SECURITY_VIOLATION', 'EPOCH_SEALED'));

GRANT SELECT ON humans TO agw_app;
GRANT SELECT, INSERT ON human_sessions TO agw_app;
GRANT UPDATE (revoked_at) ON human_sessions TO agw_app;
GRANT SELECT, INSERT ON approvals TO agw_app;
GRANT UPDATE (state, state_reason, updated_at) ON approvals TO agw_app;
GRANT SELECT, INSERT ON approval_decisions TO agw_app;
GRANT SELECT, INSERT ON approval_uses TO agw_app;
GRANT SELECT, INSERT ON approval_signing_keys TO agw_app;
"""


def upgrade() -> None:
    op.execute(SQL)


def downgrade() -> None:
    raise RuntimeError("approval decisions and nonces are evidence; no downgrade")
