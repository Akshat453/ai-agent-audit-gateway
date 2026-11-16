"""Phase 9: monitoring evidence stream, reconciliation, step-up (ADR-0031).

* The reserved system tenant ``_monitor`` (ADR-0019) with its own chain and epochs: the
  monitor appends VERIFICATION_REPORT events there (Paper A §5 monitoring stream). The tenant
  id CHECK admits exactly this one reserved id; agents can never authenticate into it.
* ``monitor_reports``: one row per verification run (full JSON report + its digest + the
  VERIFICATION_REPORT event id). ``monitor_alerts``: alerts raised by a run. Append-only.
* ``human_sessions.stepped_up_at``: re-authentication time (CRITICAL decisions need a recent
  step-up).
* Event types VERIFICATION_REPORT (SYS) and ACTION_RECONCILED (A2H).

Revision ID: 0010_phase9_monitoring
Revises: 0009_phase8_delegation
Create Date: 2026-11-16
"""

from alembic import op

revision = "0010_phase9_monitoring"
down_revision = "0009_phase8_delegation"
branch_labels = None
depends_on = None

SQL = """
ALTER TABLE tenants DROP CONSTRAINT tenants_tenant_id_check;
ALTER TABLE tenants ADD CONSTRAINT tenants_tenant_id_check
    CHECK (tenant_id = '_monitor' OR tenant_id ~ '^[a-z0-9][a-z0-9-]{0,62}$');
INSERT INTO tenants (tenant_id, display_name) VALUES ('_monitor', 'monitoring evidence stream')
    ON CONFLICT DO NOTHING;
INSERT INTO chain_heads (tenant_id) VALUES ('_monitor') ON CONFLICT DO NOTHING;
INSERT INTO epoch_heads (tenant_id) VALUES ('_monitor') ON CONFLICT DO NOTHING;

CREATE TABLE monitor_reports (
    report_id      uuid PRIMARY KEY,
    tenant_id      text NOT NULL REFERENCES tenants (tenant_id),
    result         text NOT NULL CHECK (result IN ('VERIFIED', 'TAMPERED', 'INCOMPLETE',
                       'UNANCHORED', 'INVALID_PROOF', 'UNTRUSTED_ANCHOR', 'ERROR')),
    first_seq      bigint NULL,
    last_seq       bigint NULL,
    report         jsonb NOT NULL,
    report_digest  bytea NOT NULL CHECK (octet_length(report_digest) = 32),
    event_id       uuid NULL REFERENCES evidence_events (event_id),
    trigger        text NOT NULL CHECK (trigger IN ('schedule', 'manual')),
    requested_by   text NULL,
    created_at     timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX monitor_reports_tenant_idx ON monitor_reports (tenant_id, created_at DESC);

CREATE TABLE monitor_alerts (
    alert_id    uuid PRIMARY KEY,
    tenant_id   text NOT NULL REFERENCES tenants (tenant_id),
    report_id   uuid NULL REFERENCES monitor_reports (report_id),
    kind        text NOT NULL,
    severity    text NOT NULL CHECK (severity IN ('warning', 'critical')),
    detail      jsonb NOT NULL,
    delivered   boolean NOT NULL DEFAULT false,
    created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX monitor_alerts_tenant_idx ON monitor_alerts (tenant_id, created_at DESC);

CREATE TRIGGER monitor_reports_no_update_delete BEFORE UPDATE OR DELETE ON monitor_reports
    FOR EACH ROW EXECUTE FUNCTION agw_forbid_mutation();
CREATE TRIGGER monitor_alerts_no_delete BEFORE DELETE ON monitor_alerts
    FOR EACH ROW EXECUTE FUNCTION agw_forbid_mutation();

-- Dashboard "run verification now": the API (which must not import the verifier) records a
-- request; the worker's monitor picks it up and links the resulting report.
CREATE TABLE monitor_requests (
    request_id    uuid PRIMARY KEY,
    tenant_id     text NOT NULL REFERENCES tenants (tenant_id),
    requested_by  text NOT NULL,
    created_at    timestamptz NOT NULL DEFAULT now(),
    picked_at     timestamptz NULL,
    report_id     uuid NULL REFERENCES monitor_reports (report_id)
);
CREATE INDEX monitor_requests_open_idx ON monitor_requests (created_at) WHERE report_id IS NULL;

ALTER TABLE human_sessions ADD COLUMN IF NOT EXISTS stepped_up_at timestamptz NULL;

ALTER TABLE evidence_events DROP CONSTRAINT evidence_events_event_type_check;
ALTER TABLE evidence_events ADD CONSTRAINT evidence_events_event_type_check CHECK (event_type IN (
    'ACTION_REQUESTED', 'POLICY_EVALUATED', 'ACTION_DENIED', 'APPROVAL_REQUIRED',
    'APPROVAL_GRANTED', 'APPROVAL_DENIED', 'APPROVAL_EXPIRED',
    'ACTION_AUTHORIZED', 'ACTION_DISPATCHED', 'ACTION_COMPLETED', 'ACTION_FAILED',
    'ACTION_OUTCOME_UNKNOWN', 'SECURITY_VIOLATION', 'EPOCH_SEALED',
    'DISCLOSURE_GRANTED', 'DISCLOSURE_ACCESSED', 'PAYLOAD_DELETED',
    'DELEGATION_CREATED', 'DELEGATION_REVOKED',
    'VERIFICATION_REPORT', 'ACTION_RECONCILED'));

GRANT SELECT, INSERT ON monitor_reports TO agw_app;
GRANT SELECT, INSERT ON monitor_alerts TO agw_app;
GRANT UPDATE (delivered) ON monitor_alerts TO agw_app;
GRANT UPDATE (stepped_up_at) ON human_sessions TO agw_app;
GRANT SELECT, INSERT ON monitor_requests TO agw_app;
GRANT UPDATE (picked_at, report_id) ON monitor_requests TO agw_app;
"""


def upgrade() -> None:
    op.execute(SQL)


def downgrade() -> None:
    raise RuntimeError("monitoring evidence references; no downgrade")
