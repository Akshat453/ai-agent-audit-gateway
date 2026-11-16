"""Phase 6: blockchain anchoring (ADR-0028).

* ``anchor_recorders``: one on-chain recorder per tenant (recorderId = SHA-256(TAG(
  "AGW/recorder/v1") || u16(len) || tenant || deployment_salt)), pinned to one (chain id,
  contract, submitter). Created by operators with the admin CLI (agw_migrator); agw_app can
  only HALT a recorder (equivocation), never re-point it.
* ``anchors``: one row per sealed epoch per recorder, PENDING -> SUBMITTED -> INCLUDED ->
  FINALIZED (+ FAILED). A BEFORE INSERT trigger requires root / tree_size / last_seq to equal
  the sealed epoch, and agw_app has NO update grant on those columns, so the runtime role can
  never anchor a different root for an epoch than the one sealed (reorgs resubmit the same
  root). The signed raw transaction is kept so a resubmission is byte-identical.
* ``outbox_jobs``: DISPATCH jobs of CRITICAL pre-anchored actions wait in WAITING_ANCHOR with
  ``gate_seq`` (the ACTION_AUTHORIZED seq) and ``gate_deadline`` (DB clock); ``gate_anchor``
  records the anchor that released the job (copied into ACTION_DISPATCHED).

Revision ID: 0006_phase6_anchoring
Revises: 0005_phase5_approvals
Create Date: 2026-11-15
"""

from alembic import op

revision = "0006_phase6_anchoring"
down_revision = "0005_phase5_approvals"
branch_labels = None
depends_on = None

SQL = """
CREATE TABLE anchor_recorders (
    tenant_id    text PRIMARY KEY REFERENCES tenants (tenant_id),
    recorder_id  bytea NOT NULL UNIQUE CHECK (octet_length(recorder_id) = 32),
    chain_id     bigint NOT NULL CHECK (chain_id > 0),
    contract     text NOT NULL CHECK (contract ~ '^0x[0-9a-f]{40}$'),
    submitter    text NOT NULL CHECK (submitter ~ '^0x[0-9a-f]{40}$'),
    halted       boolean NOT NULL DEFAULT false,
    halt_reason  text NULL,
    created_at   timestamptz NOT NULL DEFAULT now(),
    updated_at   timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE anchors (
    tenant_id            text NOT NULL,
    epoch_no             bigint NOT NULL CHECK (epoch_no >= 0),
    recorder_id          bytea NOT NULL CHECK (octet_length(recorder_id) = 32),
    root                 bytea NOT NULL CHECK (octet_length(root) = 32),
    tree_size            bigint NOT NULL CHECK (tree_size >= 1),
    last_seq             bigint NOT NULL CHECK (last_seq >= 0),
    priority             text NOT NULL CHECK (priority IN ('ROUTINE', 'PRIORITY', 'CRITICAL')),
    status               text NOT NULL DEFAULT 'PENDING'
        CHECK (status IN ('PENDING', 'SUBMITTED', 'INCLUDED', 'FINALIZED', 'FAILED')),
    chain_id             bigint NOT NULL,
    contract             text NOT NULL,
    submitter            text NULL,
    nonce                bigint NULL,
    tx_hash              bytea NULL CHECK (tx_hash IS NULL OR octet_length(tx_hash) = 32),
    raw_tx               bytea NULL,
    block_number         bigint NULL,
    block_hash           bytea NULL CHECK (block_hash IS NULL OR octet_length(block_hash) = 32),
    gas_used             bigint NULL,
    effective_gas_price  numeric NULL,
    attempts             integer NOT NULL DEFAULT 0,
    resubmissions        integer NOT NULL DEFAULT 0,
    last_error           text NULL,
    sealed_at            timestamptz NULL,
    next_attempt_at      timestamptz NOT NULL DEFAULT now(),
    created_at           timestamptz NOT NULL DEFAULT now(),
    submitted_at         timestamptz NULL,
    included_at          timestamptz NULL,
    finalized_at         timestamptz NULL,
    updated_at           timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, epoch_no),
    FOREIGN KEY (tenant_id, epoch_no) REFERENCES epochs (tenant_id, epoch_no),
    CHECK (status <> 'SUBMITTED' OR (tx_hash IS NOT NULL AND raw_tx IS NOT NULL AND nonce IS NOT NULL)),
    CHECK (status NOT IN ('INCLUDED', 'FINALIZED') OR (block_number IS NOT NULL AND block_hash IS NOT NULL))
);
CREATE INDEX anchors_open_idx ON anchors (status, tenant_id, epoch_no)
    WHERE status IN ('PENDING', 'SUBMITTED', 'INCLUDED');

-- The anchored root is the sealed root, nothing else (09 §6: never a different root).
CREATE FUNCTION agw_anchor_matches_epoch() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE e epochs%ROWTYPE;
BEGIN
    SELECT * INTO e FROM epochs WHERE tenant_id = NEW.tenant_id AND epoch_no = NEW.epoch_no;
    IF NOT FOUND OR e.epoch_root <> NEW.root OR e.tree_size <> NEW.tree_size
       OR e.last_seq <> NEW.last_seq THEN
        RAISE EXCEPTION USING ERRCODE = 'P0002', MESSAGE = 'anchor must carry the sealed epoch root';
    END IF;
    RETURN NEW;
END
$$;
CREATE TRIGGER anchors_match_epoch BEFORE INSERT ON anchors
    FOR EACH ROW EXECUTE FUNCTION agw_anchor_matches_epoch();
CREATE TRIGGER anchors_no_delete BEFORE DELETE ON anchors
    FOR EACH ROW EXECUTE FUNCTION agw_forbid_mutation();
CREATE TRIGGER anchors_no_truncate BEFORE TRUNCATE ON anchors
    FOR EACH STATEMENT EXECUTE FUNCTION agw_forbid_mutation();

ALTER TABLE outbox_jobs DROP CONSTRAINT outbox_jobs_status_check;
ALTER TABLE outbox_jobs ADD CONSTRAINT outbox_jobs_status_check
    CHECK (status IN ('PENDING', 'WAITING_ANCHOR', 'CLAIMED', 'DONE', 'FAILED'));
ALTER TABLE outbox_jobs
    ADD COLUMN gate_seq bigint NULL,
    ADD COLUMN gate_deadline timestamptz NULL,
    ADD COLUMN gate_anchor jsonb NULL,
    ADD CONSTRAINT outbox_jobs_gate_fields CHECK (
        status <> 'WAITING_ANCHOR'
        OR (kind = 'DISPATCH' AND gate_seq IS NOT NULL AND gate_deadline IS NOT NULL));
CREATE INDEX outbox_jobs_waiting_anchor_idx ON outbox_jobs (tenant_id, gate_seq)
    WHERE status = 'WAITING_ANCHOR';

GRANT SELECT ON anchor_recorders TO agw_app;
GRANT UPDATE (halted, halt_reason, updated_at) ON anchor_recorders TO agw_app;
GRANT SELECT, INSERT ON anchors TO agw_app;
GRANT UPDATE (status, submitter, nonce, tx_hash, raw_tx, block_number, block_hash, gas_used,
              effective_gas_price, attempts, resubmissions, last_error, next_attempt_at,
              submitted_at, included_at, finalized_at, updated_at) ON anchors TO agw_app;
"""


def upgrade() -> None:
    op.execute(SQL)


def downgrade() -> None:
    raise RuntimeError("anchors are evidence metadata; no downgrade")
