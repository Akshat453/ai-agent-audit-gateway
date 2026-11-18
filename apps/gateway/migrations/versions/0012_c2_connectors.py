"""C2: connectors, device enrollment, MCP OAuth, repos + tighten-only overlays (ADR-0035).

* ``connectors``: one instance per tenant (non-secret ``config`` JSON, ``credentials_sealed``
  = Phase 7 envelope ciphertext, never selected by any read API). ``connector_actions``: the
  actions a type (or an MCP upstream) offers; descriptions are UNTRUSTED text.
  ``connector_policies``: append-only classification versions; an action with no entry in the
  current version is UNCLASSIFIED and DENIED.
* ``device_enrollments`` (RFC 8628 device authorization) and ``agw_enroll_device``: a SECURITY
  DEFINER function, the ONLY way the runtime role can create an agent. It can create exactly
  one kind: a coding device with fixed scopes bound to an existing active human.
* ``oauth_clients`` / ``oauth_codes`` / ``oauth_tokens``: the MCP authorization server
  (codes and tokens stored as SHA-256 digests only).
* ``repos`` / ``repo_policies`` (append-only) / ``repo_proposals``.
* ``github_manifest_states``: single-use ``state`` for the GitHub App manifest flow.
* Event types CONNECTOR_*, DEVICE_ENROLLED, REPO_POLICY_CHANGED.

Revision ID: 0012_c2_connectors
Revises: 0011_c1_coding_agents
Create Date: 2026-11-18
"""

from alembic import op

revision = "0012_c2_connectors"
down_revision = "0011_c1_coding_agents"
branch_labels = None
depends_on = None

SQL = """
CREATE TABLE connectors (
    connector_id        uuid PRIMARY KEY,
    tenant_id           text NOT NULL REFERENCES tenants (tenant_id),
    type_id             text NOT NULL CHECK (type_id ~ '^[a-z][a-z0-9_]{1,40}$'),
    slug                text NOT NULL CHECK (slug ~ '^[a-z][a-z0-9]{1,23}$'),
    name                text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 120),
    config              jsonb NOT NULL DEFAULT '{}'::jsonb,
    credentials_sealed  bytea NULL,
    credential_version  integer NOT NULL DEFAULT 0 CHECK (credential_version >= 0),
    status              text NOT NULL DEFAULT 'needs_attention'
                            CHECK (status IN ('connected', 'needs_attention', 'disabled')),
    policy_version      integer NOT NULL DEFAULT 0 CHECK (policy_version >= 0),
    last_health         jsonb NULL,
    created_by          uuid NOT NULL REFERENCES humans (human_id),
    created_at          timestamptz NOT NULL DEFAULT now(),
    updated_at          timestamptz NOT NULL DEFAULT now(),
    deleted_at          timestamptz NULL
);
CREATE UNIQUE INDEX connectors_slug_uq ON connectors (tenant_id, slug) WHERE deleted_at IS NULL;

CREATE TABLE connector_actions (
    connector_id    uuid NOT NULL REFERENCES connectors (connector_id),
    name            text NOT NULL CHECK (name ~ '^[a-z][a-z0-9_]{0,35}$'),
    description     text NOT NULL DEFAULT '' CHECK (char_length(description) <= 4000),
    input_schema    jsonb NOT NULL,
    side_effect     text NOT NULL CHECK (side_effect IN ('read', 'write', 'delete', 'execute')),
    suggested_risk  text NOT NULL CHECK (suggested_risk IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    upstream_name   text NULL CHECK (char_length(upstream_name) <= 200),
    created_at      timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (connector_id, name)
);

CREATE TABLE connector_policies (
    connector_id  uuid NOT NULL REFERENCES connectors (connector_id),
    version       integer NOT NULL CHECK (version >= 1),
    document      jsonb NOT NULL,
    digest        bytea NOT NULL CHECK (octet_length(digest) = 32),
    created_by    uuid NOT NULL REFERENCES humans (human_id),
    created_at    timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (connector_id, version)
);
CREATE TRIGGER connector_policies_append_only BEFORE UPDATE OR DELETE ON connector_policies
    FOR EACH ROW EXECUTE FUNCTION agw_forbid_mutation();

CREATE TABLE connector_health (
    check_id      uuid PRIMARY KEY,
    connector_id  uuid NOT NULL REFERENCES connectors (connector_id),
    ok            boolean NOT NULL,
    detail        jsonb NOT NULL,
    checked_at    timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX connector_health_idx ON connector_health (connector_id, checked_at DESC);

CREATE TABLE device_enrollments (
    device_code_hash  bytea PRIMARY KEY CHECK (octet_length(device_code_hash) = 32),
    user_code         text NOT NULL UNIQUE CHECK (user_code ~ '^[BCDFGHJKLMNPQRSTVWXZ]{4}-[BCDFGHJKLMNPQRSTVWXZ]{4}$'),
    tenant_id         text NOT NULL REFERENCES tenants (tenant_id),
    agent_kind        text NOT NULL,
    label             text NOT NULL CHECK (label ~ '^[A-Za-z0-9._-]{1,64}$'),
    status            text NOT NULL DEFAULT 'pending'
                          CHECK (status IN ('pending', 'approved', 'denied', 'issued')),
    expires_at        timestamptz NOT NULL,
    approved_by       uuid NULL REFERENCES humans (human_id),
    device_agent_id   uuid NULL REFERENCES agents (agent_id),
    last_poll_at      timestamptz NULL,
    created_at        timestamptz NOT NULL DEFAULT now()
);

-- The ONLY way agw_app can create an agent: a coding device with FIXED scopes, bound to an
-- existing active human of the same tenant. agw_app has no INSERT on agents/agent_credentials.
CREATE FUNCTION agw_enroll_device(p_tenant text, p_human uuid, p_agent uuid, p_label text,
                                  p_credential uuid, p_key_id text, p_key_digest bytea)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $$
DECLARE v_name text;
BEGIN
    SELECT 'device:' || username || ':' || p_label INTO v_name FROM humans
        WHERE human_id = p_human AND tenant_id = p_tenant AND status = 'active';
    IF v_name IS NULL THEN
        RAISE EXCEPTION 'unknown or inactive developer';
    END IF;
    IF p_label !~ '^[A-Za-z0-9._-]{1,64}$' THEN
        RAISE EXCEPTION 'bad label';
    END IF;
    INSERT INTO agents (agent_id, tenant_id, name, scopes, status, trust_tier)
        VALUES (p_agent, p_tenant, v_name || ':' || substr(p_agent::text, 1, 8),
                ARRAY['coding:device', 'connectors:invoke'], 'active', 'standard');
    INSERT INTO agent_credentials (credential_id, agent_id, key_id, key_digest)
        VALUES (p_credential, p_agent, p_key_id, p_key_digest);
    INSERT INTO coding_devices (agent_id, tenant_id, developer_id, label)
        VALUES (p_agent, p_tenant, p_human, p_label);
END $$;
REVOKE ALL ON FUNCTION agw_enroll_device(text, uuid, uuid, text, uuid, text, bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION agw_enroll_device(text, uuid, uuid, text, uuid, text, bytea) TO agw_app;

-- "Invite people" from the dashboard: an ACTIVE admin of the same tenant may create a human
-- with a subset of the known roles. agw_app still has no INSERT on humans.
CREATE FUNCTION agw_invite_human(p_tenant text, p_admin uuid, p_human uuid, p_username text,
                                 p_roles text[], p_hash text)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM humans WHERE human_id = p_admin AND tenant_id = p_tenant
                   AND status = 'active' AND 'admin' = ANY (roles)) THEN
        RAISE EXCEPTION 'not an active admin of this tenant';
    END IF;
    INSERT INTO humans (human_id, tenant_id, username, password_hash, roles, status)
        VALUES (p_human, p_tenant, p_username, p_hash, p_roles, 'active');
END $$;
REVOKE ALL ON FUNCTION agw_invite_human(text, uuid, uuid, text, text[], text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION agw_invite_human(text, uuid, uuid, text, text[], text) TO agw_app;

CREATE TABLE oauth_clients (
    client_id      text PRIMARY KEY CHECK (char_length(client_id) BETWEEN 8 AND 2048),
    client_name    text NOT NULL DEFAULT '' CHECK (char_length(client_name) <= 200),
    redirect_uris  text[] NOT NULL,
    created_at     timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE oauth_codes (
    code_hash       bytea PRIMARY KEY CHECK (octet_length(code_hash) = 32),
    client_id       text NOT NULL REFERENCES oauth_clients (client_id),
    tenant_id       text NOT NULL REFERENCES tenants (tenant_id),
    human_id        uuid NOT NULL REFERENCES humans (human_id),
    device_agent_id uuid NOT NULL REFERENCES agents (agent_id),
    redirect_uri    text NOT NULL,
    code_challenge  text NOT NULL CHECK (code_challenge ~ '^[A-Za-z0-9_-]{43}$'),
    resource        text NOT NULL,
    scope           text NOT NULL DEFAULT '',
    expires_at      timestamptz NOT NULL,
    used_at         timestamptz NULL
);

CREATE TABLE oauth_tokens (
    token_hash      bytea PRIMARY KEY CHECK (octet_length(token_hash) = 32),
    kind            text NOT NULL CHECK (kind IN ('access', 'refresh')),
    client_id       text NOT NULL REFERENCES oauth_clients (client_id),
    tenant_id       text NOT NULL REFERENCES tenants (tenant_id),
    human_id        uuid NOT NULL REFERENCES humans (human_id),
    device_agent_id uuid NOT NULL REFERENCES agents (agent_id),
    resource        text NOT NULL,
    scope           text NOT NULL DEFAULT '',
    expires_at      timestamptz NOT NULL,
    revoked_at      timestamptz NULL,
    created_at      timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE repos (
    repo_id         uuid PRIMARY KEY,
    tenant_id       text NOT NULL REFERENCES tenants (tenant_id),
    remote_digest   bytea NOT NULL CHECK (octet_length(remote_digest) = 32),
    remote_url      text NOT NULL CHECK (char_length(remote_url) <= 2048),
    name            text NOT NULL CHECK (char_length(name) <= 200),
    registered_by   uuid NOT NULL REFERENCES agents (agent_id),
    policy_version  integer NOT NULL DEFAULT 0,
    agents          jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, remote_digest)
);

CREATE TABLE repo_policies (
    repo_id     uuid NOT NULL REFERENCES repos (repo_id),
    version     integer NOT NULL CHECK (version >= 1),
    overlay     jsonb NOT NULL,
    digest      bytea NOT NULL CHECK (octet_length(digest) = 32),
    source      text NOT NULL CHECK (source IN ('agentguard_yaml', 'proposal')),
    created_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (repo_id, version)
);
CREATE TRIGGER repo_policies_append_only BEFORE UPDATE OR DELETE ON repo_policies
    FOR EACH ROW EXECUTE FUNCTION agw_forbid_mutation();

CREATE TABLE repo_proposals (
    proposal_id   uuid PRIMARY KEY,
    repo_id       uuid NOT NULL REFERENCES repos (repo_id),
    tenant_id     text NOT NULL REFERENCES tenants (tenant_id),
    items         jsonb NOT NULL,
    status        text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'rejected')),
    created_at    timestamptz NOT NULL DEFAULT now(),
    decided_by    uuid NULL REFERENCES humans (human_id),
    decided_at    timestamptz NULL,
    reason        text NULL CHECK (char_length(reason) <= 1000)
);
CREATE INDEX repo_proposals_open_idx ON repo_proposals (tenant_id, created_at) WHERE status = 'pending';

CREATE TABLE github_manifest_states (
    state_hash    bytea PRIMARY KEY CHECK (octet_length(state_hash) = 32),
    tenant_id     text NOT NULL REFERENCES tenants (tenant_id),
    human_id      uuid NOT NULL REFERENCES humans (human_id),
    connector_id  uuid NOT NULL REFERENCES connectors (connector_id),
    purpose       text NOT NULL CHECK (purpose IN ('manifest', 'install')),
    expires_at    timestamptz NOT NULL,
    used_at       timestamptz NULL
);

ALTER TABLE evidence_events DROP CONSTRAINT evidence_events_event_type_check;
ALTER TABLE evidence_events ADD CONSTRAINT evidence_events_event_type_check CHECK (event_type IN (
    'ACTION_REQUESTED', 'POLICY_EVALUATED', 'ACTION_DENIED', 'APPROVAL_REQUIRED',
    'APPROVAL_GRANTED', 'APPROVAL_DENIED', 'APPROVAL_EXPIRED',
    'ACTION_AUTHORIZED', 'ACTION_DISPATCHED', 'ACTION_COMPLETED', 'ACTION_FAILED',
    'ACTION_OUTCOME_UNKNOWN', 'SECURITY_VIOLATION', 'EPOCH_SEALED',
    'DISCLOSURE_GRANTED', 'DISCLOSURE_ACCESSED', 'PAYLOAD_DELETED',
    'DELEGATION_CREATED', 'DELEGATION_REVOKED',
    'VERIFICATION_REPORT', 'ACTION_RECONCILED',
    'CONNECTOR_ADDED', 'CONNECTOR_UPDATED', 'CONNECTOR_ACTION_CLASSIFIED',
    'CONNECTOR_CREDENTIAL_ROTATED', 'CONNECTOR_DISABLED', 'CONNECTOR_DELETED',
    'DEVICE_ENROLLED', 'REPO_POLICY_CHANGED'));

GRANT SELECT, INSERT ON connectors TO agw_app;
GRANT UPDATE (name, config, credentials_sealed, credential_version, status, policy_version,
              last_health, updated_at, deleted_at) ON connectors TO agw_app;
GRANT SELECT, INSERT, DELETE ON connector_actions TO agw_app;
GRANT SELECT, INSERT ON connector_policies TO agw_app;
GRANT SELECT, INSERT ON connector_health TO agw_app;
GRANT SELECT, INSERT ON device_enrollments TO agw_app;
GRANT UPDATE (status, approved_by, device_agent_id, last_poll_at) ON device_enrollments TO agw_app;
GRANT SELECT, INSERT ON oauth_clients TO agw_app;
GRANT SELECT, INSERT ON oauth_codes TO agw_app;
GRANT UPDATE (used_at) ON oauth_codes TO agw_app;
GRANT SELECT, INSERT ON oauth_tokens TO agw_app;
GRANT UPDATE (revoked_at) ON oauth_tokens TO agw_app;
GRANT SELECT, INSERT ON repos TO agw_app;
GRANT UPDATE (policy_version, agents, updated_at, name) ON repos TO agw_app;
GRANT SELECT, INSERT ON repo_policies TO agw_app;
GRANT SELECT, INSERT ON repo_proposals TO agw_app;
GRANT UPDATE (status, decided_by, decided_at, reason) ON repo_proposals TO agw_app;
GRANT SELECT, INSERT ON github_manifest_states TO agw_app;
GRANT UPDATE (used_at) ON github_manifest_states TO agw_app;
"""


def upgrade() -> None:
    op.execute(SQL)


def downgrade() -> None:
    raise RuntimeError("connector evidence references; no downgrade")
