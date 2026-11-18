"""Self-service sign-up (dev/test only; ``AGW_SIGNUP_ENABLED``).

``agw_signup_tenant`` is the ONLY path by which the runtime role creates a tenant: it creates
the tenant, its genesis chain / epoch heads and its first admin in one transaction, and fails
if the tenant already exists (sign-up never takes over a tenant). The runtime role still has
no INSERT on ``tenants`` or ``humans``.

Revision ID: 0014_signup
Revises: 0013_c3_github
Create Date: 2026-11-18
"""

from alembic import op

revision = "0014_signup"
down_revision = "0013_c3_github"
branch_labels = None
depends_on = None

SQL = """
CREATE FUNCTION agw_signup_tenant(p_tenant text, p_display text, p_human uuid,
                                  p_username text, p_roles text[], p_hash text)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $$
BEGIN
    INSERT INTO tenants (tenant_id, display_name) VALUES (p_tenant, p_display);
    INSERT INTO chain_heads (tenant_id) VALUES (p_tenant);
    INSERT INTO epoch_heads (tenant_id) VALUES (p_tenant);
    INSERT INTO humans (human_id, tenant_id, username, password_hash, roles, status)
        VALUES (p_human, p_tenant, p_username, p_hash, p_roles, 'active');
END $$;
REVOKE ALL ON FUNCTION agw_signup_tenant(text, text, uuid, text, text[], text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION agw_signup_tenant(text, text, uuid, text, text[], text) TO agw_app;
"""


def upgrade() -> None:
    op.execute(SQL)


def downgrade() -> None:
    op.execute("DROP FUNCTION agw_signup_tenant(text, text, uuid, text, text[], text)")
