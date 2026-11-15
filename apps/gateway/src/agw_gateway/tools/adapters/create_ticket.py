"""create_ticket 1.0.0: MEDIUM mock write into the local ``demo.tickets`` table.

``created_by_action`` is UNIQUE, so even a re-dispatch could not create a second ticket for the
same action. The tool is still declared non-idempotent: an ambiguous outcome is never retried.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert

from agw_gateway.db import tables as t
from agw_gateway.ids import uuid7
from agw_gateway.tools.spec import ExecutionContext, ToolResult


class CreateTicketArgs(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    title: str = Field(min_length=1, max_length=120)
    body: str = Field(default="", max_length=4000)
    priority: Literal["low", "normal", "high"] = "normal"


class CreateTicketAdapter:
    def execute(self, args: BaseModel, ctx: ExecutionContext) -> ToolResult:
        assert isinstance(args, CreateTicketArgs)  # noqa: S101
        with ctx.engine.begin() as conn:
            conn.execute(
                insert(t.demo_tickets)
                .values(
                    ticket_id=uuid7(),
                    title=args.title,
                    body=args.body,
                    priority=args.priority,
                    created_by_action=ctx.action_id,
                )
                .on_conflict_do_nothing(index_elements=["created_by_action"])
            )
            ticket_id = conn.execute(
                select(t.demo_tickets.c.ticket_id).where(
                    t.demo_tickets.c.created_by_action == ctx.action_id
                )
            ).scalar_one()
        return ToolResult(public={"ticket_id": str(ticket_id)})
