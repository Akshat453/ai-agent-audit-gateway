"""The three Phase 1 demo tools (14 §1)."""

from __future__ import annotations

from agw_gateway.tools.adapters.create_ticket import CreateTicketAdapter, CreateTicketArgs
from agw_gateway.tools.adapters.delete_record import DeleteRecordAdapter, DeleteRecordArgs
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
)


def demo_tool_specs(
    *,
    search: ToolAdapter | None = None,
    ticket: ToolAdapter | None = None,
    delete: ToolAdapter | None = None,
) -> list[ToolSpec]:
    """Adapters are injectable so tests can wrap them in spies."""
    return [
        ToolSpec(PUBLIC_DOC_SEARCH, PublicDocSearchArgs, search or PublicDocSearchAdapter()),
        ToolSpec(CREATE_TICKET, CreateTicketArgs, ticket or CreateTicketAdapter()),
        ToolSpec(DELETE_RECORD, DeleteRecordArgs, delete or DeleteRecordAdapter()),
    ]
