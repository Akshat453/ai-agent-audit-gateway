"""Repository of each integration action (ADR-0042).

GitHub tool calls arrive through MCP under one run per device and client, so their run does
not tell which repository they touched. ``action_repos`` records it at decision time (the
call's ``repo`` argument, or the connector's default repository), so the console can scope by
repository. Append-only for the runtime role (no UPDATE/DELETE).

Revision ID: 0016_action_repos
Revises: 0015_console_display
Create Date: 2026-11-19
"""

from alembic import op

revision = "0016_action_repos"
down_revision = "0015_console_display"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        CREATE TABLE action_repos (
            action_id  uuid PRIMARY KEY REFERENCES actions (action_id),
            tenant_id  text NOT NULL,
            repo       text NOT NULL CHECK (repo ~ '^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$'),
            created_at timestamptz NOT NULL DEFAULT now()
        );
        CREATE INDEX action_repos_repo_idx ON action_repos (tenant_id, lower(repo));
        GRANT SELECT, INSERT ON action_repos TO agw_app;
        """
    )


def downgrade() -> None:
    op.execute("DROP TABLE action_repos")
