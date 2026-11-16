"""Phase 7: encryption, key management, selective disclosure (ADR-0029).

* ``payload_objects``: AES-256-GCM ciphertext of each event payload (inline, or a MinIO object
  key for payloads > AGW_PAYLOAD_BLOB_THRESHOLD_BYTES) + ciphertext length and SHA-256 (blob
  availability check). Never updated; DELETE only by the retention / erasure path, which
  writes PAYLOAD_DELETED evidence in the same transaction.
* ``payload_keys``: the per-event DEK wrapped by the KEK (kek_id, kek_version). Mutable only in
  the wrapping columns (rotation re-wrap) and deletable (crypto-erasure).
* ``tenant_redaction_keys``: per-tenant 32-byte salt for "[REDACTED:sha256:..]" markers,
  stored wrapped by the KEK.
* ``auditor_keys`` / ``disclosure_grants``: X25519 public keys of auditors and the grants that
  let one auditor export specific events (HPKE re-wrap or plaintext delivery).
* ``retention_policies`` / ``legal_holds``: operator-managed (agw_migrator); read-only for the
  runtime role.
* ``outbox_jobs.args_sealed`` / ``actions.request_args_sealed``: the operational copies of
  tool args, envelope-encrypted (they still carry secrets the tool needs). The plaintext JSONB
  columns are dropped by 0008 once ``admin migrate-payloads`` has converted every row.
* Event types DISCLOSURE_GRANTED, DISCLOSURE_ACCESSED, PAYLOAD_DELETED.

The Phase 2 plaintext column ``evidence_payloads.content`` is still present here; 0008 drops
it after the one-off re-encryption job (it refuses to run while plaintext remains).

Revision ID: 0007_phase7_encryption
Revises: 0006_phase6_anchoring
Create Date: 2026-11-16
"""

from alembic import op

revision = "0007_phase7_encryption"
down_revision = "0006_phase6_anchoring"
branch_labels = None
depends_on = None

SQL = """
CREATE TABLE payload_objects (
    event_id        uuid PRIMARY KEY REFERENCES evidence_events (event_id),
    tenant_id       text NOT NULL REFERENCES tenants (tenant_id),
    seq             bigint NOT NULL,
    schema_version  smallint NOT NULL,
    alg             text NOT NULL CHECK (alg = 'A256GCM'),
    nonce           bytea NOT NULL CHECK (octet_length(nonce) = 12),
    storage         text NOT NULL CHECK (storage IN ('inline', 'blob')),
    ciphertext      bytea NULL,
    blob_key        text NULL,
    ct_len          integer NOT NULL CHECK (ct_len >= 16),
    ct_sha256       bytea NOT NULL CHECK (octet_length(ct_sha256) = 32),
    pt_len          integer NOT NULL CHECK (pt_len >= 0),
    created_at      timestamptz NOT NULL DEFAULT now(),
    CHECK ((storage = 'inline') = (ciphertext IS NOT NULL)),
    CHECK ((storage = 'blob') = (blob_key IS NOT NULL))
);
CREATE INDEX payload_objects_tenant_created_idx ON payload_objects (tenant_id, created_at);
CREATE TRIGGER payload_objects_no_update BEFORE UPDATE ON payload_objects
    FOR EACH ROW EXECUTE FUNCTION agw_forbid_mutation();
CREATE TRIGGER payload_objects_no_truncate BEFORE TRUNCATE ON payload_objects
    FOR EACH STATEMENT EXECUTE FUNCTION agw_forbid_mutation();

CREATE TABLE payload_keys (
    event_id     uuid PRIMARY KEY REFERENCES payload_objects (event_id),
    tenant_id    text NOT NULL,
    kek_id       text NOT NULL,
    kek_version  integer NOT NULL CHECK (kek_version >= 1),
    wrap_nonce   bytea NOT NULL,
    wrapped_dek  bytea NOT NULL,
    created_at   timestamptz NOT NULL DEFAULT now(),
    updated_at   timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX payload_keys_version_idx ON payload_keys (kek_id, kek_version);

CREATE TABLE tenant_redaction_keys (
    tenant_id     text PRIMARY KEY REFERENCES tenants (tenant_id),
    kek_id        text NOT NULL,
    kek_version   integer NOT NULL,
    wrap_nonce    bytea NOT NULL,
    wrapped_salt  bytea NOT NULL,
    created_at    timestamptz NOT NULL DEFAULT now(),
    updated_at    timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE auditor_keys (
    key_id      text PRIMARY KEY CHECK (key_id ~ '^[0-9a-f]{32}$'),
    tenant_id   text NOT NULL REFERENCES tenants (tenant_id),
    human_id    uuid NOT NULL REFERENCES humans (human_id),
    algorithm   text NOT NULL CHECK (algorithm = 'X25519'),
    public_key  bytea NOT NULL CHECK (octet_length(public_key) = 32),
    created_at  timestamptz NOT NULL DEFAULT now(),
    revoked_at  timestamptz NULL
);

CREATE TABLE disclosure_grants (
    grant_id        uuid PRIMARY KEY,
    tenant_id       text NOT NULL REFERENCES tenants (tenant_id),
    auditor_id      uuid NOT NULL REFERENCES humans (human_id),
    auditor_key_id  text NOT NULL REFERENCES auditor_keys (key_id),
    event_ids       uuid[] NULL,
    action_id       uuid NULL,
    purpose         text NOT NULL CHECK (length(purpose) BETWEEN 1 AND 500),
    delivery        text NOT NULL CHECK (delivery IN ('hpke', 'plaintext')),
    expires_at      timestamptz NOT NULL,
    granted_by      uuid NOT NULL REFERENCES humans (human_id),
    created_at      timestamptz NOT NULL DEFAULT now(),
    revoked_at      timestamptz NULL,
    CHECK ((event_ids IS NULL) <> (action_id IS NULL)),
    CHECK (event_ids IS NULL OR cardinality(event_ids) BETWEEN 1 AND 1000),
    CHECK (granted_by <> auditor_id)
);

CREATE TABLE retention_policies (
    policy_id       text PRIMARY KEY CHECK (policy_id ~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}$'),
    tenant_id       text NOT NULL DEFAULT '*',
    tool_id         text NOT NULL DEFAULT '*',
    classification  text NOT NULL DEFAULT '*'
        CHECK (classification IN ('*', 'public', 'internal', 'confidential')),
    retain_days     integer NOT NULL CHECK (retain_days >= 1),
    created_at      timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, tool_id, classification)
);

CREATE TABLE legal_holds (
    hold_id     uuid PRIMARY KEY,
    tenant_id   text NOT NULL REFERENCES tenants (tenant_id),
    scope       text NOT NULL CHECK (scope IN ('tenant', 'run', 'action', 'event')),
    scope_id    uuid NULL,
    reason      text NOT NULL,
    created_by  text NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    released_at timestamptz NULL,
    CHECK ((scope = 'tenant') = (scope_id IS NULL))
);

ALTER TABLE outbox_jobs ADD COLUMN args_sealed bytea NULL;
ALTER TABLE actions ADD COLUMN request_args_sealed bytea NULL;

ALTER TABLE evidence_events DROP CONSTRAINT evidence_events_event_type_check;
ALTER TABLE evidence_events ADD CONSTRAINT evidence_events_event_type_check CHECK (event_type IN (
    'ACTION_REQUESTED', 'POLICY_EVALUATED', 'ACTION_DENIED', 'APPROVAL_REQUIRED',
    'APPROVAL_GRANTED', 'APPROVAL_DENIED', 'APPROVAL_EXPIRED',
    'ACTION_AUTHORIZED', 'ACTION_DISPATCHED', 'ACTION_COMPLETED', 'ACTION_FAILED',
    'ACTION_OUTCOME_UNKNOWN', 'SECURITY_VIOLATION', 'EPOCH_SEALED',
    'DISCLOSURE_GRANTED', 'DISCLOSURE_ACCESSED', 'PAYLOAD_DELETED'));

GRANT SELECT, INSERT, DELETE ON payload_objects TO agw_app;
GRANT SELECT, INSERT, DELETE ON payload_keys TO agw_app;
GRANT UPDATE (kek_id, kek_version, wrap_nonce, wrapped_dek, updated_at) ON payload_keys TO agw_app;
GRANT SELECT, INSERT ON tenant_redaction_keys TO agw_app;
GRANT UPDATE (kek_id, kek_version, wrap_nonce, wrapped_salt, updated_at)
    ON tenant_redaction_keys TO agw_app;
GRANT SELECT, INSERT ON auditor_keys TO agw_app;
GRANT UPDATE (revoked_at) ON auditor_keys TO agw_app;
GRANT SELECT, INSERT ON disclosure_grants TO agw_app;
GRANT UPDATE (revoked_at) ON disclosure_grants TO agw_app;
GRANT SELECT ON retention_policies TO agw_app;
GRANT SELECT ON legal_holds TO agw_app;
"""


def upgrade() -> None:
    op.execute(SQL)


def downgrade() -> None:
    raise RuntimeError("encrypted evidence payloads; no downgrade")
