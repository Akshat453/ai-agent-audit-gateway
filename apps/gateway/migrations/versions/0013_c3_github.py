"""C3: GitHub connector state (ADR-0036).

* ``github_commits``: every commit the gateway pushed for a ``git_submit_change`` action (the
  ground truth of the "AgentGuard evidence" check). Append-only.
* ``github_prs``: PRs the gateway tracks (opened by ``github_pr_create`` or seen by webhook /
  polling) and the last check it published.
* ``github_deliveries``: webhook deliveries (verified or not), for de-duplication and the
  connector's webhook health.
* ``github_tamper_notices``: one PR comment per (PR, monitor report) when evidence fails.

Revision ID: 0013_c3_github
Revises: 0012_c2_connectors
Create Date: 2026-11-18
"""

from alembic import op

revision = "0013_c3_github"
down_revision = "0012_c2_connectors"
branch_labels = None
depends_on = None

SQL = """
CREATE TABLE github_commits (
    repo          text NOT NULL CHECK (repo ~ '^[A-Za-z0-9-]{1,39}/[A-Za-z0-9._-]{1,100}$'),
    sha           text NOT NULL CHECK (sha ~ '^[0-9a-f]{40}$'),
    tenant_id     text NOT NULL REFERENCES tenants (tenant_id),
    connector_id  uuid NOT NULL REFERENCES connectors (connector_id),
    action_id     uuid NOT NULL REFERENCES actions (action_id),
    run_id        uuid NOT NULL,
    session_id    text NULL CHECK (char_length(session_id) <= 64),
    issue_number  integer NULL,
    branch        text NOT NULL,
    tree_sha      text NOT NULL CHECK (tree_sha ~ '^[0-9a-f]{40}$'),
    diff_digest   bytea NOT NULL CHECK (octet_length(diff_digest) = 32),
    pushed_at     timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (repo, sha)
);
CREATE INDEX github_commits_action_idx ON github_commits (action_id);
CREATE TRIGGER github_commits_append_only BEFORE UPDATE OR DELETE ON github_commits
    FOR EACH ROW EXECUTE FUNCTION agw_forbid_mutation();

CREATE TABLE github_prs (
    connector_id   uuid NOT NULL REFERENCES connectors (connector_id),
    repo           text NOT NULL,
    number         integer NOT NULL CHECK (number > 0),
    tenant_id      text NOT NULL REFERENCES tenants (tenant_id),
    run_id         uuid NULL,
    created_by_action uuid NULL REFERENCES actions (action_id),
    branch         text NULL,
    head_sha       text NULL,
    state          text NOT NULL DEFAULT 'open',
    html_url       text NULL,
    check_run_id   bigint NULL,
    check_head_sha text NULL,
    conclusion     text NULL CHECK (conclusion IN ('success', 'failure', 'in_progress')),
    summary        text NULL,
    evaluated_at   timestamptz NULL,
    created_at     timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (connector_id, repo, number)
);
CREATE INDEX github_prs_run_idx ON github_prs (tenant_id, run_id);

CREATE TABLE github_deliveries (
    delivery_id   text PRIMARY KEY CHECK (char_length(delivery_id) <= 100),
    connector_id  uuid NOT NULL REFERENCES connectors (connector_id),
    event         text NOT NULL CHECK (char_length(event) <= 64),
    action        text NULL CHECK (char_length(action) <= 64),
    verified      boolean NOT NULL,
    outcome       text NOT NULL CHECK (char_length(outcome) <= 200),
    received_at   timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX github_deliveries_conn_idx ON github_deliveries (connector_id, received_at DESC);

CREATE TABLE github_tamper_notices (
    connector_id  uuid NOT NULL,
    repo          text NOT NULL,
    number        integer NOT NULL,
    report_id     uuid NOT NULL,
    created_at    timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (connector_id, repo, number, report_id)
);

GRANT SELECT, INSERT ON github_commits TO agw_app;
GRANT SELECT, INSERT ON github_prs TO agw_app;
GRANT UPDATE (run_id, created_by_action, branch, head_sha, state, html_url, check_run_id,
              check_head_sha, conclusion, summary, evaluated_at) ON github_prs TO agw_app;
GRANT SELECT, INSERT ON github_deliveries TO agw_app;
GRANT SELECT, INSERT ON github_tamper_notices TO agw_app;
"""


def upgrade() -> None:
    op.execute(SQL)


def downgrade() -> None:
    raise RuntimeError("github evidence references; no downgrade")
