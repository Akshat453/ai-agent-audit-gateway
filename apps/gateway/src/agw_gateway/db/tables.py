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
    Integer,
    LargeBinary,
    MetaData,
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
    Column("next_seq", BigInteger, nullable=False),
    Column("created_at", DateTime(timezone=True)),
)

agents = Table(
    "agents",
    metadata,
    Column("agent_id", UUID(as_uuid=True), primary_key=True),
    Column("tenant_id", Text, nullable=False),
    Column("name", Text, nullable=False),
    Column("scopes", ARRAY(Text), nullable=False),
    Column("status", Text, nullable=False),
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
    Column("canonical_bytes", LargeBinary),
)

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
    Column("args", JSONB),
    Column("created_at", DateTime(timezone=True)),
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
