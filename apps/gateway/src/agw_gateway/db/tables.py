"""SQLAlchemy Core mirrors of the Phase 1 schema (DDL lives in migrations/, 14 §3).

Only the columns the application reads or writes are declared. The migration is authoritative.
"""

from __future__ import annotations

from sqlalchemy import (
    ARRAY,
    BigInteger,
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Integer,
    LargeBinary,
    MetaData,
    Numeric,
    SmallInteger,
    Table,
    Text,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID

metadata = MetaData()

tenants = Table(
    "tenants",
    metadata,
    Column("tenant_id", Text, primary_key=True),
    Column("display_name", Text, nullable=False),
    Column("created_at", DateTime(timezone=True)),
)

chain_heads = Table(
    "chain_heads",
    metadata,
    Column("tenant_id", Text, primary_key=True),
    Column("last_seq", BigInteger, nullable=False),
    Column("last_hash", LargeBinary, nullable=False),
    Column("updated_at", DateTime(timezone=True)),
)

agents = Table(
    "agents",
    metadata,
    Column("agent_id", UUID(as_uuid=True), primary_key=True),
    Column("tenant_id", Text, nullable=False),
    Column("name", Text, nullable=False),
    Column("scopes", ARRAY(Text), nullable=False),
    Column("status", Text, nullable=False),
    Column("trust_tier", Text),
    Column("created_at", DateTime(timezone=True)),
)

agent_credentials = Table(
    "agent_credentials",
    metadata,
    Column("credential_id", UUID(as_uuid=True), primary_key=True),
    Column("agent_id", UUID(as_uuid=True), nullable=False),
    Column("key_id", Text, nullable=False),
    Column("key_digest", LargeBinary, nullable=False),
    Column("created_at", DateTime(timezone=True)),
    Column("expires_at", DateTime(timezone=True)),
    Column("revoked_at", DateTime(timezone=True)),
    Column("audience", Text),  # Phase 8: NULL = gateway API; else the one resource it is for
)

tool_registry = Table(
    "tool_registry",
    metadata,
    Column("tool_id", Text, primary_key=True),
    Column("version", Text, primary_key=True),
    Column("operation_type", Text, nullable=False),
    Column("sensitivity", Text, nullable=False),
    Column("base_risk", Text, nullable=False),
    Column("environments_allowed", ARRAY(Text), nullable=False),
    Column("required_scope", Text, nullable=False),
    Column("is_idempotent", Boolean, nullable=False),
    Column("external_effect", Boolean, nullable=False),
    Column("target_field", Text),
    Column("tags", ARRAY(Text), nullable=False),
    Column("risk_attributes", JSONB),
    Column("args_schema", JSONB, nullable=False),
    Column("adapter", Text, nullable=False),
    Column("enabled", Boolean, nullable=False),
    Column("registered_at", DateTime(timezone=True)),
)

policies = Table(
    "policies",
    metadata,
    Column("policy_id", Text, primary_key=True),
    Column("version", Integer, primary_key=True),
    Column("document", JSONB, nullable=False),
    Column("created_at", DateTime(timezone=True)),
    Column("created_by", Text, nullable=False),
)

actions = Table(
    "actions",
    metadata,
    Column("action_id", UUID(as_uuid=True), primary_key=True),
    Column("tenant_id", Text, nullable=False),
    Column("agent_id", UUID(as_uuid=True), nullable=False),
    Column("run_id", UUID(as_uuid=True), nullable=False),
    Column("tool_id", Text, nullable=False),
    Column("tool_version", Text),
    Column("environment", Text, nullable=False),
    Column("status", Text, nullable=False),
    Column("decision", Text, nullable=False),
    Column("risk_level", Text, nullable=False),
    Column("policy_id", Text, nullable=False),
    Column("policy_version", Integer, nullable=False),
    Column("idempotency_key", Text, nullable=False),
    Column("result_public", JSONB),
    Column("error_code", Text),
    Column("created_at", DateTime(timezone=True)),
    Column("updated_at", DateTime(timezone=True)),
    Column("version", Integer, nullable=False),
    # Phase 5 (ADR-0027)
    Column("action_digest", LargeBinary),
    # Phase 7: envelope-encrypted validated args of a pending action (plaintext column dropped).
    Column("request_args_sealed", LargeBinary),
    Column("delegation_depth", Integer),
    Column("risk_policy_digest", LargeBinary),
    Column("delegation_id", UUID(as_uuid=True)),  # Phase 8 (ADR-0030)
)

evidence_events = Table(
    "evidence_events",
    metadata,
    Column("event_id", UUID(as_uuid=True), primary_key=True),
    Column("tenant_id", Text, nullable=False),
    Column("seq", BigInteger, nullable=False),
    Column("event_type", Text, nullable=False),
    Column("schema_version", SmallInteger, nullable=False),
    Column("action_id", UUID(as_uuid=True)),
    Column("run_id", UUID(as_uuid=True)),
    Column("agent_id", UUID(as_uuid=True)),
    Column("occurred_at", DateTime(timezone=True)),
    Column("body", JSONB, nullable=False),
    Column("canonical_bytes", LargeBinary, nullable=False),
    Column("event_hash", LargeBinary, nullable=False),
    Column("risk_level", Text),
)

epoch_heads = Table(
    "epoch_heads",
    metadata,
    Column("tenant_id", Text, primary_key=True),
    Column("next_epoch_no", BigInteger, nullable=False),
    Column("sealed_up_to", BigInteger, nullable=False),
    Column("last_root", LargeBinary, nullable=False),
    Column("updated_at", DateTime(timezone=True)),
)

epochs = Table(
    "epochs",
    metadata,
    Column("tenant_id", Text, primary_key=True),
    Column("epoch_no", BigInteger, primary_key=True),
    Column("first_seq", BigInteger, nullable=False),
    Column("last_seq", BigInteger, nullable=False),
    Column("tree_size", BigInteger, nullable=False),
    Column("merkle_root", LargeBinary, nullable=False),
    Column("prev_root", LargeBinary, nullable=False),
    Column("epoch_root", LargeBinary, nullable=False),
    Column("state", Text, nullable=False),
    Column("sealed_at", DateTime(timezone=True)),
    Column("seal_reason", Text, nullable=False),
    Column("anchor_priority", Text, nullable=False),
)

risk_policies = Table(
    "risk_policies",
    metadata,
    Column("policy_id", Text, primary_key=True),
    Column("version", Integer, primary_key=True),
    Column("digest", LargeBinary, nullable=False),
    Column("canonical", LargeBinary, nullable=False),
    Column("document", JSONB, nullable=False),
    Column("created_at", DateTime(timezone=True)),
    Column("created_by", Text, nullable=False),
)

evidence_payloads = Table(
    "evidence_payloads",
    metadata,
    Column(
        "event_id", UUID(as_uuid=True), ForeignKey("evidence_events.event_id"), primary_key=True
    ),
    Column("tenant_id", Text, nullable=False),
    Column("seq", BigInteger, nullable=False),
    Column("storage", Text, nullable=False),
    Column("created_at", DateTime(timezone=True)),
)  # Phase 2 ledger; the plaintext ``content`` column is dropped by migration 0008

outbox_jobs = Table(
    "outbox_jobs",
    metadata,
    Column("job_id", BigInteger, primary_key=True, autoincrement=True),
    Column("kind", Text, nullable=False),
    Column("tenant_id", Text, nullable=False),
    Column("action_id", UUID(as_uuid=True)),
    Column("status", Text, nullable=False),
    Column("available_at", DateTime(timezone=True)),
    Column("attempts", Integer, nullable=False),
    Column("claimed_by", Text),
    Column("lease_expires_at", DateTime(timezone=True)),
    Column("last_error_code", Text),
    # Phase 7: envelope-encrypted dispatch args (plaintext column dropped by migration 0008).
    Column("args_sealed", LargeBinary),
    Column("up_to_seq", BigInteger),
    Column("seal_reason", Text),
    Column("created_at", DateTime(timezone=True)),
    # Phase 6 (ADR-0028): CRITICAL pre-action anchoring gate.
    Column("gate_seq", BigInteger),
    Column("gate_deadline", DateTime(timezone=True)),
    Column("gate_anchor", JSONB),
)

idempotency_keys = Table(
    "idempotency_keys",
    metadata,
    Column("agent_id", UUID(as_uuid=True), primary_key=True),
    Column("key", Text, primary_key=True),
    Column("fingerprint", LargeBinary, nullable=False),
    Column("fingerprint_alg", Text, nullable=False),
    Column("action_id", UUID(as_uuid=True), nullable=False),
    Column("response_status", Integer, nullable=False),
    Column("response_body", JSONB, nullable=False),
    Column("created_at", DateTime(timezone=True)),
    Column("expires_at", DateTime(timezone=True), nullable=False),
)

# --------------------------------------------------------------------------- Phase 5
humans = Table(
    "humans",
    metadata,
    Column("human_id", UUID(as_uuid=True), primary_key=True),
    Column("tenant_id", Text, nullable=False),
    Column("username", Text, nullable=False),
    Column("password_hash", Text, nullable=False),
    Column("roles", ARRAY(Text), nullable=False),
    Column("status", Text, nullable=False),
    Column("created_at", DateTime(timezone=True)),
)

human_sessions = Table(
    "human_sessions",
    metadata,
    Column("session_pk", UUID(as_uuid=True), primary_key=True),
    Column("session_id", Text, nullable=False),
    Column("human_id", UUID(as_uuid=True), nullable=False),
    Column("token_digest", LargeBinary, nullable=False),
    Column("created_at", DateTime(timezone=True)),
    Column("expires_at", DateTime(timezone=True), nullable=False),
    Column("revoked_at", DateTime(timezone=True)),
    Column("stepped_up_at", DateTime(timezone=True)),  # Phase 9: re-authentication time
)

approvals = Table(
    "approvals",
    metadata,
    Column("approval_id", UUID(as_uuid=True), primary_key=True),
    Column("tenant_id", Text, nullable=False),
    Column("action_id", UUID(as_uuid=True), nullable=False),
    Column("action_digest", LargeBinary, nullable=False),
    Column("nonce", LargeBinary, nullable=False),
    Column("required_role", Text, nullable=False),
    Column("required_approvals", SmallInteger, nullable=False),
    Column("state", Text, nullable=False),
    Column("state_reason", Text),
    Column("requested_at", DateTime(timezone=True), nullable=False),
    Column("expires_at", DateTime(timezone=True), nullable=False),
    Column("updated_at", DateTime(timezone=True)),
)

approval_decisions = Table(
    "approval_decisions",
    metadata,
    Column("approval_id", UUID(as_uuid=True), primary_key=True),
    Column("approver_id", UUID(as_uuid=True), primary_key=True),
    Column("decision", Text, nullable=False),
    Column("reason", Text, nullable=False),
    Column("decided_at_us", BigInteger, nullable=False),
    Column("decision_digest", LargeBinary, nullable=False),
    Column("signature", LargeBinary, nullable=False),
    Column("key_id", Text, nullable=False),
)

approval_uses = Table(
    "approval_uses",
    metadata,
    Column("nonce", LargeBinary, primary_key=True),
    Column("approval_id", UUID(as_uuid=True), nullable=False),
    Column("action_id", UUID(as_uuid=True), nullable=False),
    Column("used_at", DateTime(timezone=True)),
)

approval_signing_keys = Table(
    "approval_signing_keys",
    metadata,
    Column("key_id", Text, primary_key=True),
    Column("algorithm", Text, nullable=False),
    Column("public_key", LargeBinary, nullable=False),
    Column("created_at", DateTime(timezone=True)),
)

demo_tickets = Table(
    "tickets",
    metadata,
    Column("ticket_id", UUID(as_uuid=True), primary_key=True),
    Column("title", Text, nullable=False),
    Column("body", Text, nullable=False),
    Column("priority", Text, nullable=False),
    Column("created_by_action", UUID(as_uuid=True), nullable=False),
    Column("created_at", DateTime(timezone=True)),
    schema="demo",
)

demo_records = Table(
    "records",
    metadata,
    Column("record_id", UUID(as_uuid=True), primary_key=True),
    Column("content", Text, nullable=False),
    Column("created_at", DateTime(timezone=True)),
    schema="demo",
)


# --------------------------------------------------------------------------- Phase 6
anchor_recorders = Table(
    "anchor_recorders",
    metadata,
    Column("tenant_id", Text, primary_key=True),
    Column("recorder_id", LargeBinary, nullable=False),
    Column("chain_id", BigInteger, nullable=False),
    Column("contract", Text, nullable=False),
    Column("submitter", Text, nullable=False),
    Column("halted", Boolean, nullable=False),
    Column("halt_reason", Text),
    Column("created_at", DateTime(timezone=True)),
    Column("updated_at", DateTime(timezone=True)),
)

anchors = Table(
    "anchors",
    metadata,
    Column("tenant_id", Text, primary_key=True),
    Column("epoch_no", BigInteger, primary_key=True),
    Column("recorder_id", LargeBinary, nullable=False),
    Column("root", LargeBinary, nullable=False),
    Column("tree_size", BigInteger, nullable=False),
    Column("last_seq", BigInteger, nullable=False),
    Column("priority", Text, nullable=False),
    Column("status", Text, nullable=False),
    Column("chain_id", BigInteger, nullable=False),
    Column("contract", Text, nullable=False),
    Column("submitter", Text),
    Column("nonce", BigInteger),
    Column("tx_hash", LargeBinary),
    Column("raw_tx", LargeBinary),
    Column("block_number", BigInteger),
    Column("block_hash", LargeBinary),
    Column("gas_used", BigInteger),
    Column("effective_gas_price", Numeric),
    Column("attempts", Integer, nullable=False),
    Column("resubmissions", Integer, nullable=False),
    Column("last_error", Text),
    Column("sealed_at", DateTime(timezone=True)),
    Column("next_attempt_at", DateTime(timezone=True)),
    Column("created_at", DateTime(timezone=True)),
    Column("submitted_at", DateTime(timezone=True)),
    Column("included_at", DateTime(timezone=True)),
    Column("finalized_at", DateTime(timezone=True)),
    Column("updated_at", DateTime(timezone=True)),
)


# --------------------------------------------------------------------------- Phase 7
payload_objects = Table(
    "payload_objects",
    metadata,
    Column("event_id", UUID(as_uuid=True), primary_key=True),
    Column("tenant_id", Text, nullable=False),
    Column("seq", BigInteger, nullable=False),
    Column("schema_version", SmallInteger, nullable=False),
    Column("alg", Text, nullable=False),
    Column("nonce", LargeBinary, nullable=False),
    Column("storage", Text, nullable=False),
    Column("ciphertext", LargeBinary),
    Column("blob_key", Text),
    Column("ct_len", Integer, nullable=False),
    Column("ct_sha256", LargeBinary, nullable=False),
    Column("pt_len", Integer, nullable=False),
    Column("created_at", DateTime(timezone=True)),
)

payload_keys = Table(
    "payload_keys",
    metadata,
    Column("event_id", UUID(as_uuid=True), primary_key=True),
    Column("tenant_id", Text, nullable=False),
    Column("kek_id", Text, nullable=False),
    Column("kek_version", Integer, nullable=False),
    Column("wrap_nonce", LargeBinary, nullable=False),
    Column("wrapped_dek", LargeBinary, nullable=False),
    Column("created_at", DateTime(timezone=True)),
    Column("updated_at", DateTime(timezone=True)),
)

tenant_redaction_keys = Table(
    "tenant_redaction_keys",
    metadata,
    Column("tenant_id", Text, primary_key=True),
    Column("kek_id", Text, nullable=False),
    Column("kek_version", Integer, nullable=False),
    Column("wrap_nonce", LargeBinary, nullable=False),
    Column("wrapped_salt", LargeBinary, nullable=False),
    Column("created_at", DateTime(timezone=True)),
    Column("updated_at", DateTime(timezone=True)),
)

auditor_keys = Table(
    "auditor_keys",
    metadata,
    Column("key_id", Text, primary_key=True),
    Column("tenant_id", Text, nullable=False),
    Column("human_id", UUID(as_uuid=True), nullable=False),
    Column("algorithm", Text, nullable=False),
    Column("public_key", LargeBinary, nullable=False),
    Column("created_at", DateTime(timezone=True)),
    Column("revoked_at", DateTime(timezone=True)),
)

disclosure_grants = Table(
    "disclosure_grants",
    metadata,
    Column("grant_id", UUID(as_uuid=True), primary_key=True),
    Column("tenant_id", Text, nullable=False),
    Column("auditor_id", UUID(as_uuid=True), nullable=False),
    Column("auditor_key_id", Text, nullable=False),
    Column("event_ids", ARRAY(UUID(as_uuid=True))),
    Column("action_id", UUID(as_uuid=True)),
    Column("purpose", Text, nullable=False),
    Column("delivery", Text, nullable=False),
    Column("expires_at", DateTime(timezone=True), nullable=False),
    Column("granted_by", UUID(as_uuid=True), nullable=False),
    Column("created_at", DateTime(timezone=True)),
    Column("revoked_at", DateTime(timezone=True)),
)

retention_policies = Table(
    "retention_policies",
    metadata,
    Column("policy_id", Text, primary_key=True),
    Column("tenant_id", Text, nullable=False),
    Column("tool_id", Text, nullable=False),
    Column("classification", Text, nullable=False),
    Column("retain_days", Integer, nullable=False),
    Column("created_at", DateTime(timezone=True)),
)

legal_holds = Table(
    "legal_holds",
    metadata,
    Column("hold_id", UUID(as_uuid=True), primary_key=True),
    Column("tenant_id", Text, nullable=False),
    Column("scope", Text, nullable=False),
    Column("scope_id", UUID(as_uuid=True)),
    Column("reason", Text, nullable=False),
    Column("created_by", Text, nullable=False),
    Column("created_at", DateTime(timezone=True)),
    Column("released_at", DateTime(timezone=True)),
)


# --------------------------------------------------------------------------- Phase 8 (ADR-0030)
delegation_signing_keys = Table(
    "delegation_signing_keys",
    metadata,
    Column("key_id", Text, primary_key=True),
    Column("algorithm", Text, nullable=False),
    Column("public_key", LargeBinary, nullable=False),
    Column("created_at", DateTime(timezone=True)),
)

delegations = Table(
    "delegations",
    metadata,
    Column("delegation_id", UUID(as_uuid=True), primary_key=True),
    Column("tenant_id", Text, nullable=False),
    Column("issuer_agent_id", UUID(as_uuid=True), nullable=False),
    Column("child_agent_id", UUID(as_uuid=True), nullable=False),
    Column("parent_delegation_id", UUID(as_uuid=True)),
    Column("depth", SmallInteger, nullable=False),
    Column("scopes", ARRAY(Text), nullable=False),
    Column("tools", ARRAY(Text), nullable=False),
    Column("max_risk", Text, nullable=False),
    Column("expires_at", DateTime(timezone=True), nullable=False),
    Column("max_uses", Integer, nullable=False),
    Column("uses", Integer, nullable=False),
    Column("token_hash", LargeBinary, nullable=False),
    Column("key_id", Text, nullable=False),
    Column("created_event_id", UUID(as_uuid=True), nullable=False),
    Column("created_event_hash", LargeBinary, nullable=False),
    Column("created_at", DateTime(timezone=True)),
    Column("revoked_at", DateTime(timezone=True)),
    Column("revoked_by", Text),
)

integration_clients = Table(
    "integration_clients",
    metadata,
    Column("client_id", UUID(as_uuid=True), primary_key=True),
    Column("tenant_id", Text, nullable=False),
    Column("name", Text, nullable=False),
    Column("audience", Text, nullable=False),
    Column("key_id", Text, nullable=False),
    Column("key_digest", LargeBinary, nullable=False),
    Column("status", Text, nullable=False),
    Column("created_at", DateTime(timezone=True)),
)

exchanged_tokens = Table(
    "exchanged_tokens",
    metadata,
    Column("token_id", UUID(as_uuid=True), primary_key=True),
    Column("key_id", Text, nullable=False),
    Column("key_digest", LargeBinary, nullable=False),
    Column("agent_id", UUID(as_uuid=True), nullable=False),
    Column("subject_credential_id", UUID(as_uuid=True), nullable=False),
    Column("client_id", UUID(as_uuid=True), nullable=False),
    Column("created_at", DateTime(timezone=True)),
    Column("expires_at", DateTime(timezone=True), nullable=False),
)


# --------------------------------------------------------------------------- Phase 9 (ADR-0031)
monitor_reports = Table(
    "monitor_reports",
    metadata,
    Column("report_id", UUID(as_uuid=True), primary_key=True),
    Column("tenant_id", Text, nullable=False),
    Column("result", Text, nullable=False),
    Column("first_seq", BigInteger),
    Column("last_seq", BigInteger),
    Column("report", JSONB, nullable=False),
    Column("report_digest", LargeBinary, nullable=False),
    Column("event_id", UUID(as_uuid=True)),
    Column("trigger", Text, nullable=False),
    Column("requested_by", Text),
    Column("created_at", DateTime(timezone=True)),
)

monitor_alerts = Table(
    "monitor_alerts",
    metadata,
    Column("alert_id", UUID(as_uuid=True), primary_key=True),
    Column("tenant_id", Text, nullable=False),
    Column("report_id", UUID(as_uuid=True)),
    Column("kind", Text, nullable=False),
    Column("severity", Text, nullable=False),
    Column("detail", JSONB, nullable=False),
    Column("delivered", Boolean, nullable=False),
    Column("created_at", DateTime(timezone=True)),
)

monitor_requests = Table(
    "monitor_requests",
    metadata,
    Column("request_id", UUID(as_uuid=True), primary_key=True),
    Column("tenant_id", Text, nullable=False),
    Column("requested_by", Text, nullable=False),
    Column("created_at", DateTime(timezone=True)),
    Column("picked_at", DateTime(timezone=True)),
    Column("report_id", UUID(as_uuid=True)),
)

# C1 (ADR-0034): coding-agent integration.
coding_devices = Table(
    "coding_devices",
    metadata,
    Column("agent_id", UUID(as_uuid=True), primary_key=True),
    Column("tenant_id", Text, nullable=False),
    Column("developer_id", UUID(as_uuid=True), nullable=False),
    Column("label", Text, nullable=False),
    Column("created_at", DateTime(timezone=True)),
)

coding_sessions = Table(
    "coding_sessions",
    metadata,
    Column("session_id", UUID(as_uuid=True), primary_key=True),
    Column("tenant_id", Text, nullable=False),
    Column("device_id", UUID(as_uuid=True), nullable=False),
    Column("developer_id", UUID(as_uuid=True), nullable=False),
    Column("agent_kind", Text, nullable=False),
    Column("agent_version", Text),
    Column("native_session", Text),
    Column("repo_digest", LargeBinary),
    Column("head_sha", Text),
    Column("workspace_root", Text),
    Column("issue_number", Integer),
    Column("issue_digest", LargeBinary),
    Column("status", Text, nullable=False),
    Column("started_at", DateTime(timezone=True)),
    Column("ended_at", DateTime(timezone=True)),
)

coding_actions = Table(
    "coding_actions",
    metadata,
    Column("action_id", UUID(as_uuid=True), primary_key=True),
    Column("tenant_id", Text, nullable=False),
    Column("session_id", UUID(as_uuid=True), nullable=False),
    Column("action_type", Text, nullable=False),
    Column("action_digest", LargeBinary, nullable=False),
    Column("correlation", Text),
    Column("observed_at", DateTime(timezone=True)),
    Column("created_at", DateTime(timezone=True)),
    # ADR-0039: what the console shows (redacted targets, sealed under the KEK; diff counts).
    Column("target_sealed", LargeBinary),
    Column("diff_files", Integer),
    Column("diff_added", Integer),
    Column("diff_removed", Integer),
)

# ADR-0042: the repository of each integration (GitHub) action.
action_repos = Table(
    "action_repos",
    metadata,
    Column("action_id", UUID(as_uuid=True), primary_key=True),
    Column("tenant_id", Text, nullable=False),
    Column("repo", Text, nullable=False),
    Column("created_at", DateTime(timezone=True)),
)

# C2 (ADR-0035): connectors, device enrollment, MCP OAuth, repos.
connectors = Table(
    "connectors",
    metadata,
    Column("connector_id", UUID(as_uuid=True), primary_key=True),
    Column("tenant_id", Text, nullable=False),
    Column("type_id", Text, nullable=False),
    Column("slug", Text, nullable=False),
    Column("name", Text, nullable=False),
    Column("config", JSONB, nullable=False),
    Column("credentials_sealed", LargeBinary),
    Column("credential_version", Integer, nullable=False),
    Column("status", Text, nullable=False),
    Column("policy_version", Integer, nullable=False),
    Column("last_health", JSONB),
    Column("created_by", UUID(as_uuid=True), nullable=False),
    Column("created_at", DateTime(timezone=True)),
    Column("updated_at", DateTime(timezone=True)),
    Column("deleted_at", DateTime(timezone=True)),
)

connector_actions = Table(
    "connector_actions",
    metadata,
    Column("connector_id", UUID(as_uuid=True), primary_key=True),
    Column("name", Text, primary_key=True),
    Column("description", Text, nullable=False),
    Column("input_schema", JSONB, nullable=False),
    Column("side_effect", Text, nullable=False),
    Column("suggested_risk", Text, nullable=False),
    Column("upstream_name", Text),
    Column("created_at", DateTime(timezone=True)),
)

connector_policies = Table(
    "connector_policies",
    metadata,
    Column("connector_id", UUID(as_uuid=True), primary_key=True),
    Column("version", Integer, primary_key=True),
    Column("document", JSONB, nullable=False),
    Column("digest", LargeBinary, nullable=False),
    Column("created_by", UUID(as_uuid=True), nullable=False),
    Column("created_at", DateTime(timezone=True)),
)

connector_health = Table(
    "connector_health",
    metadata,
    Column("check_id", UUID(as_uuid=True), primary_key=True),
    Column("connector_id", UUID(as_uuid=True), nullable=False),
    Column("ok", Boolean, nullable=False),
    Column("detail", JSONB, nullable=False),
    Column("checked_at", DateTime(timezone=True)),
)

device_enrollments = Table(
    "device_enrollments",
    metadata,
    Column("device_code_hash", LargeBinary, primary_key=True),
    Column("user_code", Text, nullable=False),
    Column("tenant_id", Text, nullable=False),
    Column("agent_kind", Text, nullable=False),
    Column("label", Text, nullable=False),
    Column("status", Text, nullable=False),
    Column("expires_at", DateTime(timezone=True), nullable=False),
    Column("approved_by", UUID(as_uuid=True)),
    Column("device_agent_id", UUID(as_uuid=True)),
    Column("last_poll_at", DateTime(timezone=True)),
    Column("created_at", DateTime(timezone=True)),
)

oauth_clients = Table(
    "oauth_clients",
    metadata,
    Column("client_id", Text, primary_key=True),
    Column("client_name", Text, nullable=False),
    Column("redirect_uris", ARRAY(Text), nullable=False),
    Column("created_at", DateTime(timezone=True)),
)

oauth_codes = Table(
    "oauth_codes",
    metadata,
    Column("code_hash", LargeBinary, primary_key=True),
    Column("client_id", Text, nullable=False),
    Column("tenant_id", Text, nullable=False),
    Column("human_id", UUID(as_uuid=True), nullable=False),
    Column("device_agent_id", UUID(as_uuid=True), nullable=False),
    Column("redirect_uri", Text, nullable=False),
    Column("code_challenge", Text, nullable=False),
    Column("resource", Text, nullable=False),
    Column("scope", Text, nullable=False),
    Column("expires_at", DateTime(timezone=True), nullable=False),
    Column("used_at", DateTime(timezone=True)),
)

oauth_tokens = Table(
    "oauth_tokens",
    metadata,
    Column("token_hash", LargeBinary, primary_key=True),
    Column("kind", Text, nullable=False),
    Column("client_id", Text, nullable=False),
    Column("tenant_id", Text, nullable=False),
    Column("human_id", UUID(as_uuid=True), nullable=False),
    Column("device_agent_id", UUID(as_uuid=True), nullable=False),
    Column("resource", Text, nullable=False),
    Column("scope", Text, nullable=False),
    Column("expires_at", DateTime(timezone=True), nullable=False),
    Column("revoked_at", DateTime(timezone=True)),
    Column("created_at", DateTime(timezone=True)),
)

repos = Table(
    "repos",
    metadata,
    Column("repo_id", UUID(as_uuid=True), primary_key=True),
    Column("tenant_id", Text, nullable=False),
    Column("remote_digest", LargeBinary, nullable=False),
    Column("remote_url", Text, nullable=False),
    Column("name", Text, nullable=False),
    Column("registered_by", UUID(as_uuid=True), nullable=False),
    Column("policy_version", Integer, nullable=False),
    Column("agents", JSONB, nullable=False),
    Column("created_at", DateTime(timezone=True)),
    Column("updated_at", DateTime(timezone=True)),
)

repo_policies = Table(
    "repo_policies",
    metadata,
    Column("repo_id", UUID(as_uuid=True), primary_key=True),
    Column("version", Integer, primary_key=True),
    Column("overlay", JSONB, nullable=False),
    Column("digest", LargeBinary, nullable=False),
    Column("source", Text, nullable=False),
    Column("created_at", DateTime(timezone=True)),
)

repo_proposals = Table(
    "repo_proposals",
    metadata,
    Column("proposal_id", UUID(as_uuid=True), primary_key=True),
    Column("repo_id", UUID(as_uuid=True), nullable=False),
    Column("tenant_id", Text, nullable=False),
    Column("items", JSONB, nullable=False),
    Column("status", Text, nullable=False),
    Column("created_at", DateTime(timezone=True)),
    Column("decided_by", UUID(as_uuid=True)),
    Column("decided_at", DateTime(timezone=True)),
    Column("reason", Text),
)

github_manifest_states = Table(
    "github_manifest_states",
    metadata,
    Column("state_hash", LargeBinary, primary_key=True),
    Column("tenant_id", Text, nullable=False),
    Column("human_id", UUID(as_uuid=True), nullable=False),
    Column("connector_id", UUID(as_uuid=True), nullable=False),
    Column("purpose", Text, nullable=False),
    Column("expires_at", DateTime(timezone=True), nullable=False),
    Column("used_at", DateTime(timezone=True)),
)

# C3 (ADR-0036): GitHub connector state.
github_commits = Table(
    "github_commits",
    metadata,
    Column("repo", Text, primary_key=True),
    Column("sha", Text, primary_key=True),
    Column("tenant_id", Text, nullable=False),
    Column("connector_id", UUID(as_uuid=True), nullable=False),
    Column("action_id", UUID(as_uuid=True), nullable=False),
    Column("run_id", UUID(as_uuid=True), nullable=False),
    Column("session_id", Text),
    Column("issue_number", Integer),
    Column("branch", Text, nullable=False),
    Column("tree_sha", Text, nullable=False),
    Column("diff_digest", LargeBinary, nullable=False),
    Column("pushed_at", DateTime(timezone=True)),
)

github_prs = Table(
    "github_prs",
    metadata,
    Column("connector_id", UUID(as_uuid=True), primary_key=True),
    Column("repo", Text, primary_key=True),
    Column("number", Integer, primary_key=True),
    Column("tenant_id", Text, nullable=False),
    Column("run_id", UUID(as_uuid=True)),
    Column("created_by_action", UUID(as_uuid=True)),
    Column("branch", Text),
    Column("head_sha", Text),
    Column("state", Text, nullable=False),
    Column("html_url", Text),
    Column("check_run_id", BigInteger),
    Column("check_head_sha", Text),
    Column("conclusion", Text),
    Column("summary", Text),
    Column("evaluated_at", DateTime(timezone=True)),
    Column("created_at", DateTime(timezone=True)),
)

github_deliveries = Table(
    "github_deliveries",
    metadata,
    Column("delivery_id", Text, primary_key=True),
    Column("connector_id", UUID(as_uuid=True), nullable=False),
    Column("event", Text, nullable=False),
    Column("action", Text),
    Column("verified", Boolean, nullable=False),
    Column("outcome", Text, nullable=False),
    Column("received_at", DateTime(timezone=True)),
)

github_tamper_notices = Table(
    "github_tamper_notices",
    metadata,
    Column("connector_id", UUID(as_uuid=True), primary_key=True),
    Column("repo", Text, primary_key=True),
    Column("number", Integer, primary_key=True),
    Column("report_id", UUID(as_uuid=True), primary_key=True),
    Column("created_at", DateTime(timezone=True)),
)
