"""Demo tools: the three Phase 1 tools (14 §1) plus three Phase 4 mocks (ADR-0026)."""

from __future__ import annotations

from agw_gateway.privacy.classification import FieldClasses
from agw_gateway.tools.adapters.create_ticket import CreateTicketAdapter, CreateTicketArgs
from agw_gateway.tools.adapters.delete_record import DeleteRecordAdapter, DeleteRecordArgs
from agw_gateway.tools.adapters.phase4_mocks import (
    ExportCustomerDataAdapter,
    ExportCustomerDataArgs,
    SendEmailAdapter,
    SendEmailArgs,
    UpdateIamRoleAdapter,
    UpdateIamRoleArgs,
)
from agw_gateway.tools.adapters.public_doc_search import (
    PublicDocSearchAdapter,
    PublicDocSearchArgs,
)
from agw_gateway.tools.metadata import ToolMetadata
from agw_gateway.tools.spec import ToolAdapter, ToolSpec

PUBLIC_DOC_SEARCH = ToolMetadata(
    tool_id="public_doc_search",
    version="1.0.0",
    operation_type="read",
    sensitivity="public",
    base_risk="LOW",
    environments_allowed=frozenset({"dev", "staging", "prod"}),
    required_scope="tools:public_doc_search",
    is_idempotent=True,
    external_effect=False,
    data_classification="public",
    reversible=True,
    medium_effect="ALLOW",
)
CREATE_TICKET = ToolMetadata(
    tool_id="create_ticket",
    version="1.0.0",
    operation_type="create",
    sensitivity="internal",
    base_risk="MEDIUM",
    environments_allowed=frozenset({"dev", "staging"}),
    required_scope="tools:create_ticket",
    is_idempotent=False,
    external_effect=False,
    data_classification="internal",
    reversible=True,
    medium_effect="ALLOW",
)
DELETE_RECORD = ToolMetadata(
    tool_id="delete_record",
    version="1.0.0",
    operation_type="delete",
    sensitivity="confidential",
    base_risk="CRITICAL",
    environments_allowed=frozenset({"dev"}),
    required_scope="tools:delete_record",
    is_idempotent=False,
    external_effect=False,
    target_field="record_id",
    data_classification="confidential",
    reversible=False,
    medium_effect="REQUIRE_APPROVAL",
)
SEND_EMAIL = ToolMetadata(
    tool_id="send_email",
    version="1.0.0",
    operation_type="create",
    sensitivity="internal",
    base_risk="LOW",
    environments_allowed=frozenset({"dev", "staging", "prod"}),
    required_scope="tools:send_email",
    is_idempotent=False,
    external_effect=True,
    data_classification="internal",
    reversible=False,
    destination_field="to",
    volume_field="to",
    medium_effect="ALLOW",
)
EXPORT_CUSTOMER_DATA = ToolMetadata(
    tool_id="export_customer_data",
    version="1.0.0",
    operation_type="read",
    sensitivity="confidential",
    base_risk="HIGH",
    environments_allowed=frozenset({"dev", "staging", "prod"}),
    required_scope="tools:export_customer_data",
    is_idempotent=False,
    external_effect=True,
    data_classification="pii",
    reversible=False,
    destination_field="destination",
    volume_field="limit",
    medium_effect="REQUIRE_APPROVAL",
)
UPDATE_IAM_ROLE = ToolMetadata(
    tool_id="update_iam_role",
    version="1.0.0",
    operation_type="update",
    sensitivity="restricted",
    base_risk="HIGH",
    environments_allowed=frozenset({"dev", "staging", "prod"}),
    required_scope="tools:update_iam_role",
    is_idempotent=False,
    external_effect=False,
    target_field="principal",
    tags=frozenset({"privilege_change"}),
    data_classification="secret",
    reversible=True,
    medium_effect="REQUIRE_APPROVAL",
)


def demo_tool_specs(
    *,
    search: ToolAdapter | None = None,
    ticket: ToolAdapter | None = None,
    delete: ToolAdapter | None = None,
    email: ToolAdapter | None = None,
    export: ToolAdapter | None = None,
    iam: ToolAdapter | None = None,
) -> list[ToolSpec]:
    """Adapters are injectable so tests can wrap them in spies."""
    return [
        ToolSpec(
            PUBLIC_DOC_SEARCH,
            PublicDocSearchArgs,
            search or PublicDocSearchAdapter(),
            FieldClasses(
                args={"query": "internal", "limit": "public"},
                results={"results": "public", "count": "public"},
            ),
        ),
        ToolSpec(
            CREATE_TICKET,
            CreateTicketArgs,
            ticket or CreateTicketAdapter(),
            FieldClasses(
                args={"title": "internal", "body": "confidential", "priority": "public"},
                results={"ticket_id": "internal"},
            ),
        ),
        ToolSpec(
            DELETE_RECORD,
            DeleteRecordArgs,
            delete or DeleteRecordAdapter(),
            FieldClasses(args={"record_id": "internal"}, results={"deleted": "public"}),
        ),
        ToolSpec(
            SEND_EMAIL,
            SendEmailArgs,
            email or SendEmailAdapter(),
            FieldClasses(
                args={"to": "confidential", "subject": "confidential", "body": "confidential"},
                results={"queued": "public"},
            ),
        ),
        ToolSpec(
            EXPORT_CUSTOMER_DATA,
            ExportCustomerDataArgs,
            export or ExportCustomerDataAdapter(),
            FieldClasses(
                args={"destination": "confidential", "limit": "internal", "fields": "internal"},
                results={"exported": "public"},
            ),
        ),
        ToolSpec(
            UPDATE_IAM_ROLE,
            UpdateIamRoleArgs,
            iam or UpdateIamRoleAdapter(),
            FieldClasses(
                args={"principal": "confidential", "role": "internal", "grant": "internal"},
                results={"updated": "public"},
            ),
        ),
    ]
