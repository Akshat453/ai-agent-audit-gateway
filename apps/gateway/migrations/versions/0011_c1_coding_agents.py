"""C1: coding-agent integration API (ADR-0034).

* Approving roles for routed coding approvals: ``security``, ``ledger_lead``, ``maintainer``
  (humans.roles and approvals.required_role CHECKs widened; existing rows stay valid).
* ``coding_devices``: a per-developer device key IS an agent credential (agents +
  agent_credentials, so authentication, rate limits and monitoring are the gateway's own);
  this table binds that agent to the developer (a human) it acts for. Admin-issued only.
* ``coding_sessions``: one row per coding session; ``session_id`` is the run id of the
  session's evidence.
* ``coding_actions``: per-action coding metadata (session, digest, correlation id for the
  post-action report). The lifecycle itself is the ordinary ``actions`` row + evidence.

Revision ID: 0011_c1_coding_agents
Revises: 0010_phase9_monitoring
Create Date: 2026-11-18
"""

from alembic import op

revision = "0011_c1_coding_agents"
down_revision = "0010_phase9_monitoring"
branch_labels = None
depends_on = None

ROLE_LIST = "'approver', 'admin', 'auditor', 'security', 'ledger_lead', 'maintainer'"
APPROVING = "'approver', 'security', 'ledger_lead', 'maintainer'"

SQL = f"""
ALTER TABLE humans DROP CONSTRAINT humans_roles_check;
ALTER TABLE humans ADD CONSTRAINT humans_roles_check
    CHECK (roles <@ ARRAY[{ROLE_LIST}]::text[]);
ALTER TABLE approvals DROP CONSTRAINT approvals_required_role_check;
ALTER TABLE approvals ADD CONSTRAINT approvals_required_role_check
    CHECK (required_role IN ({APPROVING}));

CREATE TABLE coding_devices (
    agent_id      uuid PRIMARY KEY REFERENCES agents (agent_id),
    tenant_id     text NOT NULL REFERENCES tenants (tenant_id),
    developer_id  uuid NOT NULL REFERENCES humans (human_id),
    label         text NOT NULL CHECK (label ~ '^[A-Za-z0-9._-]{{1,64}}$'),
    created_at    timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE coding_sessions (
    session_id     uuid PRIMARY KEY,
    tenant_id      text NOT NULL REFERENCES tenants (tenant_id),
    device_id      uuid NOT NULL REFERENCES coding_devices (agent_id),
    developer_id   uuid NOT NULL REFERENCES humans (human_id),
    agent_kind     text NOT NULL CHECK (agent_kind IN
                       ('claude_code', 'codex', 'cursor', 'gemini_cli', 'mcp_generic', 'other')),
    agent_version  text NULL,
    native_session text NULL CHECK (octet_length(native_session) <= 128),
    repo_digest    bytea NULL CHECK (octet_length(repo_digest) = 32),
    head_sha       text NULL CHECK (head_sha ~ '^[0-9a-f]{{40}}([0-9a-f]{{24}})?$'),
    workspace_root text NULL,
    issue_number   integer NULL CHECK (issue_number > 0),
    issue_digest   bytea NULL CHECK (octet_length(issue_digest) = 32),
    status         text NOT NULL DEFAULT 'OPEN' CHECK (status IN ('OPEN', 'ENDED')),
    started_at     timestamptz NOT NULL DEFAULT now(),
    ended_at       timestamptz NULL
);
CREATE INDEX coding_sessions_device_idx ON coding_sessions (device_id, started_at DESC);

CREATE TABLE coding_actions (
    action_id     uuid PRIMARY KEY REFERENCES actions (action_id),
    tenant_id     text NOT NULL REFERENCES tenants (tenant_id),
    session_id    uuid NOT NULL REFERENCES coding_sessions (session_id),
    action_type   text NOT NULL,
    action_digest bytea NOT NULL CHECK (octet_length(action_digest) = 32),
    correlation   text NULL CHECK (octet_length(correlation) <= 128),
    observed_at   timestamptz NULL,
    created_at    timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX coding_actions_digest_idx ON coding_actions (session_id, action_digest);
CREATE INDEX coding_actions_corr_idx ON coding_actions (session_id, correlation);

GRANT SELECT ON coding_devices TO agw_app;
GRANT SELECT, INSERT ON coding_sessions TO agw_app;
GRANT UPDATE (status, ended_at, head_sha) ON coding_sessions TO agw_app;
GRANT SELECT, INSERT ON coding_actions TO agw_app;
GRANT UPDATE (observed_at, correlation) ON coding_actions TO agw_app;
"""


def upgrade() -> None:
    op.execute(SQL)


def downgrade() -> None:
    raise RuntimeError("coding evidence references; no downgrade")
