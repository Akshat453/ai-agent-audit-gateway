"""delete_record 1.0.0: CRITICAL delete. Unreachable under the default policy (DENY)."""

from __future__ import annotations

from uuid import UUID

from pydantic import BaseModel, ConfigDict
from sqlalchemy import delete

from agw_gateway.db import tables as t
from agw_gateway.tools.spec import ExecutionContext, ToolResult


class DeleteRecordArgs(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    record_id: UUID


class DeleteRecordAdapter:
    def execute(self, args: BaseModel, ctx: ExecutionContext) -> ToolResult:
        assert isinstance(args, DeleteRecordArgs)  # noqa: S101
        with ctx.engine.begin() as conn:
            deleted = conn.execute(
                delete(t.demo_records).where(t.demo_records.c.record_id == args.record_id)
            ).rowcount
        return ToolResult(public={"deleted": bool(deleted)})
