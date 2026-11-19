"""Plain-English console (ADR-0039): what a reviewer may see about a coding action.

``coding_actions.target_sealed``: the action's targets (paths, command, URL, search pattern, MCP
tool), secrets redacted, sealed under the KEK (ops context "coding_target"). Metadata, not
content: file contents and diffs are never stored here, only their counts.

Revision ID: 0015_console_display
Revises: 0014_signup
Create Date: 2026-11-19
"""

from alembic import op

revision = "0015_console_display"
down_revision = "0014_signup"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        ALTER TABLE coding_actions
            ADD COLUMN target_sealed bytea,
            ADD COLUMN diff_files integer CHECK (diff_files >= 0),
            ADD COLUMN diff_added integer CHECK (diff_added >= 0),
            ADD COLUMN diff_removed integer CHECK (diff_removed >= 0);
        """
    )


def downgrade() -> None:
    op.execute(
        "ALTER TABLE coding_actions DROP COLUMN target_sealed, DROP COLUMN diff_files, "
        "DROP COLUMN diff_added, DROP COLUMN diff_removed"
    )
