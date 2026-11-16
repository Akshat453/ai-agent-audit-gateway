"""Phase 4 mock tools (send_email, export_customer_data, update_iam_role).

They exist to exercise the risk engine with realistic metadata. None of them touches a real
system: each appends one JSON line to ``<sandbox>/<tool>.jsonl`` (no argument values beyond
counts and identifiers the agent supplied) and returns a small public result.
"""

from __future__ import annotations

import json
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from agw_gateway.tools.spec import ExecutionContext, ToolResult


class _Args(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)


class SendEmailArgs(_Args):
    to: list[str] = Field(min_length=1, max_length=100_000)
    subject: str = Field(min_length=1, max_length=200)
    body: str = Field(default="", max_length=10_000)


class ExportCustomerDataArgs(_Args):
    destination: str = Field(min_length=3, max_length=2048)  # URL or e-mail address
    limit: int = Field(ge=1, le=10_000_000)  # number of customer records
    fields: list[Literal["id", "name", "email", "phone", "address"]] = Field(min_length=1)


class UpdateIamRoleArgs(_Args):
    principal: str = Field(pattern=r"^[a-z0-9][a-z0-9._@-]{0,127}$")
    role: Literal["viewer", "editor", "admin"]
    grant: bool = True


def _record(ctx: ExecutionContext, tool: str, entry: dict[str, Any]) -> None:
    ctx.sandbox_dir.mkdir(parents=True, exist_ok=True)
    with (ctx.sandbox_dir / f"{tool}.jsonl").open("a", encoding="utf-8") as fh:
        fh.write(json.dumps({"action_id": str(ctx.action_id), **entry}, sort_keys=True) + "\n")


class SendEmailAdapter:
    def execute(self, args: BaseModel, ctx: ExecutionContext) -> ToolResult:
        assert isinstance(args, SendEmailArgs)  # noqa: S101
        _record(ctx, "send_email", {"recipients": len(args.to)})
        return ToolResult(public={"queued": len(args.to)})


class ExportCustomerDataAdapter:
    def execute(self, args: BaseModel, ctx: ExecutionContext) -> ToolResult:
        assert isinstance(args, ExportCustomerDataArgs)  # noqa: S101
        _record(ctx, "export_customer_data", {"records": args.limit, "fields": args.fields})
        return ToolResult(public={"exported": args.limit})


class UpdateIamRoleAdapter:
    def execute(self, args: BaseModel, ctx: ExecutionContext) -> ToolResult:
        assert isinstance(args, UpdateIamRoleArgs)  # noqa: S101
        _record(ctx, "update_iam_role", {"principal": args.principal, "role": args.role})
        return ToolResult(public={"updated": True})
