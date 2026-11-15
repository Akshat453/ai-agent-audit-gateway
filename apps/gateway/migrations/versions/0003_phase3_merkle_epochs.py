"""Phase 3 Merkle epochs: epoch_heads, epochs (tiling enforced in the DB), SEAL outbox jobs.

* ``epochs`` is append-only (same triggers as evidence). A BEFORE INSERT trigger enforces
  06 §7: epoch_no contiguous from 0, first_seq(0) = 0, first_seq(t) = last_seq(t-1) + 1 (no
  gap, no overlap), prev_root = R_{t-1} (ZERO32 for t = 0), tree_size = last - first + 1, and
  last_seq <= the tenant's committed chain head.
* Epoch membership is NOT stored per event: epochs tile the seq range, so an event's epoch is
  the unique epoch with first_seq <= seq <= last_seq (ADR-0025). Evidence rows stay immutable.
* Proofs are computed on demand from sealed data (no proof cache table; ADR-0025).

Revision ID: 0003_phase3_merkle_epochs
Revises: 0002_phase2_flight_recorder
Create Date: 2026-11-15
"""

from alembic import op

revision = "0003_phase3_merkle_epochs"
down_revision = "0002_phase2_flight_recorder"
branch_labels = None
depends_on = None

ZERO32 = "'\\x" + "00" * 32 + "'"

SQL = f"""
CREATE TABLE epoch_heads (
    tenant_id      text PRIMARY KEY REFERENCES tenants(tenant_id),
    next_epoch_no  bigint NOT NULL DEFAULT 0 CHECK (next_epoch_no >= 0),
    sealed_up_to   bigint NOT NULL DEFAULT -1 CHECK (sealed_up_to >= -1),
    last_root      bytea NOT NULL DEFAULT {ZERO32} CHECK (octet_length(last_root) = 32),
    updated_at     timestamptz NOT NULL DEFAULT now()
);
INSERT INTO epoch_heads (tenant_id) SELECT tenant_id FROM tenants;

CREATE TABLE epochs (
    tenant_id    text NOT NULL REFERENCES tenants(tenant_id),
    epoch_no     bigint NOT NULL CHECK (epoch_no >= 0),
    first_seq    bigint NOT NULL CHECK (first_seq >= 0),
    last_seq     bigint NOT NULL,
    tree_size    bigint NOT NULL CHECK (tree_size >= 1),
    merkle_root  bytea NOT NULL CHECK (octet_length(merkle_root) = 32),
    prev_root    bytea NOT NULL CHECK (octet_length(prev_root) = 32),
    epoch_root   bytea NOT NULL CHECK (octet_length(epoch_root) = 32),
    state        text NOT NULL DEFAULT 'SEALED' CHECK (state IN ('SEALED')),
    sealed_at    timestamptz NOT NULL DEFAULT now(),
    seal_reason  text NOT NULL
        CHECK (seal_reason IN ('MAX_EVENTS', 'MAX_AGE', 'RISK_HIGH', 'RISK_CRITICAL', 'MANUAL')),
    PRIMARY KEY (tenant_id, epoch_no),
    UNIQUE (tenant_id, first_seq),
    UNIQUE (tenant_id, last_seq),
    CHECK (tree_size = last_seq - first_seq + 1)
);

CREATE FUNCTION agw_epoch_tiling() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    prev_last bigint;
    prev_root_v bytea;
    head bigint;
BEGIN
    IF NEW.epoch_no = 0 THEN
        IF NEW.first_seq <> 0 OR NEW.prev_root <> {ZERO32}::bytea THEN
            RAISE EXCEPTION USING ERRCODE = 'P0002', MESSAGE = 'epoch 0 must start at seq 0 with prev_root = ZERO32';
        END IF;
    ELSE
        SELECT last_seq, epoch_root INTO prev_last, prev_root_v
          FROM epochs WHERE tenant_id = NEW.tenant_id AND epoch_no = NEW.epoch_no - 1;
        IF NOT FOUND THEN
            RAISE EXCEPTION USING ERRCODE = 'P0002', MESSAGE = 'epochs must be contiguous (previous epoch missing)';
        END IF;
        IF NEW.first_seq <> prev_last + 1 THEN
            RAISE EXCEPTION USING ERRCODE = 'P0002', MESSAGE = 'epochs must tile the seq range (gap or overlap)';
        END IF;
        IF NEW.prev_root <> prev_root_v THEN
            RAISE EXCEPTION USING ERRCODE = 'P0002', MESSAGE = 'prev_root must equal the previous epoch_root';
        END IF;
    END IF;
    SELECT last_seq INTO head FROM chain_heads WHERE tenant_id = NEW.tenant_id;
    IF head IS NULL OR NEW.last_seq > head THEN
        RAISE EXCEPTION USING ERRCODE = 'P0002', MESSAGE = 'cannot seal beyond the committed chain head';
    END IF;
    RETURN NEW;
END
$$;
CREATE TRIGGER epochs_tiling BEFORE INSERT ON epochs FOR EACH ROW EXECUTE FUNCTION agw_epoch_tiling();
CREATE TRIGGER epochs_no_update_delete BEFORE UPDATE OR DELETE ON epochs
    FOR EACH ROW EXECUTE FUNCTION agw_forbid_mutation();
CREATE TRIGGER epochs_no_truncate BEFORE TRUNCATE ON epochs
    FOR EACH STATEMENT EXECUTE FUNCTION agw_forbid_mutation();

ALTER TABLE outbox_jobs DROP CONSTRAINT outbox_jobs_kind_check;
ALTER TABLE outbox_jobs ADD CONSTRAINT outbox_jobs_kind_check CHECK (kind IN ('DISPATCH', 'SEAL'));
ALTER TABLE outbox_jobs
    ADD COLUMN up_to_seq bigint NULL,
    ADD COLUMN seal_reason text NULL,
    ADD CONSTRAINT outbox_jobs_seal_fields CHECK (kind <> 'SEAL' OR (up_to_seq IS NOT NULL AND seal_reason IS NOT NULL));
-- at most one open SEAL job per tenant
CREATE UNIQUE INDEX outbox_jobs_open_seal_uq ON outbox_jobs (tenant_id)
    WHERE kind = 'SEAL' AND status IN ('PENDING', 'CLAIMED');

ALTER TABLE evidence_events DROP CONSTRAINT evidence_events_event_type_check;
ALTER TABLE evidence_events ADD CONSTRAINT evidence_events_event_type_check CHECK (event_type IN (
    'ACTION_REQUESTED', 'POLICY_EVALUATED', 'ACTION_DENIED', 'APPROVAL_REQUIRED',
    'ACTION_AUTHORIZED', 'ACTION_DISPATCHED', 'ACTION_COMPLETED', 'ACTION_FAILED',
    'ACTION_OUTCOME_UNKNOWN', 'SECURITY_VIOLATION', 'EPOCH_SEALED'));

GRANT SELECT ON epoch_heads TO agw_app;
GRANT UPDATE (next_epoch_no, sealed_up_to, last_root, updated_at) ON epoch_heads TO agw_app;
GRANT SELECT, INSERT ON epochs TO agw_app;
"""


def upgrade() -> None:
    op.execute(SQL)


def downgrade() -> None:
    raise RuntimeError("epochs are evidence; no downgrade")
