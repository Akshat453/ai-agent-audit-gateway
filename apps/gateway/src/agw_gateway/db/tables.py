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
