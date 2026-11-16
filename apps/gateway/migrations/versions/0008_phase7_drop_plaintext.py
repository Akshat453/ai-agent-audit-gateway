"""Phase 7: drop the plaintext copies (ADR-0029 §7).

Refuses to run while any plaintext remains un-migrated:
* a Phase 2 ``evidence_payloads.content`` row without its ``payload_objects`` ciphertext, or
* an ``outbox_jobs.args`` / ``actions.request_args`` value without its sealed copy.
Run ``python -m agw_gateway.admin migrate-payloads`` (idempotent, resumable, verifies every
digest) and then ``alembic upgrade head`` again. On a fresh database there is nothing to
migrate and this applies directly.

Then drops ``evidence_payloads.content`` (the table stays as the Phase 2 ledger: event id, seq,
storage) and the plaintext JSONB arg columns.

Revision ID: 0008_phase7_drop_plaintext
Revises: 0007_phase7_encryption
Create Date: 2026-11-16
"""

from alembic import op
from sqlalchemy import text

revision = "0008_phase7_drop_plaintext"
down_revision = "0007_phase7_encryption"
branch_labels = None
depends_on = None

GUARD = """
SELECT
  (SELECT count(*) FROM evidence_payloads p
    WHERE p.content IS NOT NULL
      AND NOT EXISTS (SELECT 1 FROM payload_objects o WHERE o.event_id = p.event_id))
  + (SELECT count(*) FROM outbox_jobs WHERE args IS NOT NULL AND args_sealed IS NULL)
  + (SELECT count(*) FROM actions WHERE request_args IS NOT NULL AND request_args_sealed IS NULL)
"""

SQL = """
ALTER TABLE evidence_payloads DROP COLUMN content;
ALTER TABLE outbox_jobs DROP COLUMN args;
ALTER TABLE actions DROP COLUMN request_args;
"""


def upgrade() -> None:
    remaining = op.get_bind().execute(text(GUARD)).scalar_one()
    if remaining:
        raise RuntimeError(
            f"{remaining} plaintext payload/arg rows are not re-encrypted yet: run "
            "`python -m agw_gateway.admin migrate-payloads`, then migrate again"
        )
    op.execute(SQL)


def downgrade() -> None:
    raise RuntimeError("plaintext is gone by design; no downgrade")
