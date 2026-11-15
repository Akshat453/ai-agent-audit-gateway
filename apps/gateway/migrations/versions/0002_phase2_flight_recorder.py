"""Phase 2 flight recorder: canonical headers, hash chain, chain_heads, evidence_payloads.

* Refuses to run while Phase 1 evidence rows exist (they have NULL canonical_bytes and are
  immutable, so they cannot be backfilled) - unless AGW_ALLOW_DEV_EVIDENCE_RESET=1 and
  AGW_ENV is dev/test, in which case dev evidence and the operational rows that refer to it
  are wiped (docs/gateway/14 §8). Genesis (seq 0, prev = ZERO32) is then the first Phase 2 event.
* Sequence allocation moves from ``tenants.next_seq`` to ``chain_heads`` (ADR-0022).
* ``evidence_payloads`` is append-only like ``evidence_events``. PHASE 2 STORES PLAINTEXT.

Revision ID: 0002_phase2_flight_recorder
Revises: 0001_phase1_core
Create Date: 2026-11-15
"""

import os

from alembic import op

revision = "0002_phase2_flight_recorder"
down_revision = "0001_phase1_core"
branch_labels = None
depends_on = None

RESET_SQL = """
ALTER TABLE evidence_events DISABLE TRIGGER USER;
TRUNCATE evidence_events, outbox_jobs, idempotency_keys, actions, demo.tickets;
ALTER TABLE evidence_events ENABLE TRIGGER USER;
"""

SCHEMA_SQL = """
CREATE TABLE chain_heads (
    tenant_id   text PRIMARY KEY REFERENCES tenants(tenant_id),
    last_seq    bigint NOT NULL DEFAULT -1 CHECK (last_seq >= -1),
    last_hash   bytea NOT NULL DEFAULT '\\x0000000000000000000000000000000000000000000000000000000000000000'
                CHECK (octet_length(last_hash) = 32),
    updated_at  timestamptz NOT NULL DEFAULT now()
);
INSERT INTO chain_heads (tenant_id) SELECT tenant_id FROM tenants;
ALTER TABLE tenants DROP COLUMN next_seq;

ALTER TABLE evidence_events
    ALTER COLUMN canonical_bytes SET NOT NULL,
    ADD COLUMN event_hash bytea NOT NULL CHECK (octet_length(event_hash) = 32),
    ADD CONSTRAINT evidence_events_canonical_size CHECK (octet_length(canonical_bytes) <= 16384);
CREATE INDEX evidence_events_tenant_type_seq_idx ON evidence_events (tenant_id, event_type, seq);
CREATE INDEX evidence_events_agent_seq_idx ON evidence_events (agent_id, seq);

CREATE TABLE evidence_payloads (
    event_id    uuid PRIMARY KEY REFERENCES evidence_events(event_id),
    tenant_id   text NOT NULL REFERENCES tenants(tenant_id),
    seq         bigint NOT NULL,
    storage     text NOT NULL CHECK (storage IN ('plaintext')),   -- Phase 2: PLAINTEXT
    content     bytea NOT NULL CHECK (octet_length(content) <= 1048576),
    created_at  timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, seq)
);
CREATE TRIGGER evidence_payloads_no_update_delete
    BEFORE UPDATE OR DELETE ON evidence_payloads
    FOR EACH ROW EXECUTE FUNCTION agw_forbid_mutation();
CREATE TRIGGER evidence_payloads_no_truncate
    BEFORE TRUNCATE ON evidence_payloads
    FOR EACH STATEMENT EXECUTE FUNCTION agw_forbid_mutation();

GRANT SELECT ON chain_heads TO agw_app;
GRANT UPDATE (last_seq, last_hash, updated_at) ON chain_heads TO agw_app;
GRANT SELECT, INSERT ON evidence_payloads TO agw_app;
"""


def upgrade() -> None:
    bind = op.get_bind()
    phase1_rows = bind.exec_driver_sql("SELECT count(*) FROM evidence_events").scalar_one()
    if phase1_rows:
        allowed = os.environ.get("AGW_ALLOW_DEV_EVIDENCE_RESET") == "1" and os.environ.get(
            "AGW_ENV"
        ) in ("dev", "test")
        if not allowed:
            raise RuntimeError(
                f"evidence_events holds {phase1_rows} Phase 1 rows without canonical_bytes; "
                "they cannot be backfilled (append-only). For dev data only, re-run with "
                "AGW_ALLOW_DEV_EVIDENCE_RESET=1 and AGW_ENV=dev|test to wipe dev evidence."
            )
        op.execute(RESET_SQL)
    op.execute(SCHEMA_SQL)


def downgrade() -> None:
    raise RuntimeError("Phase 2 evidence cannot be downgraded (append-only evidence)")
