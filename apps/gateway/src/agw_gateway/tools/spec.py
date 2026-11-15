"""Tool spec and adapter contract (11 §4)."""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol
from uuid import UUID

from pydantic import BaseModel, ValidationError
from sqlalchemy import Engine

from agw_gateway.tools.metadata import ToolMetadata


@dataclass(frozen=True)
class ExecutionContext:
    action_id: UUID
    tenant_id: str
    attempt: int
    engine: Engine
    sandbox_dir: Path
    corpus_dir: Path

    @property
    def idempotency_token(self) -> str:
        """Stable per action, so idempotent adapters can de-duplicate re-dispatches."""
        return str(self.action_id)


@dataclass(frozen=True)
class ToolResult:
    """``public`` is returned to the owning agent by GET /v1/actions/{id}."""

    public: Mapping[str, Any] = field(default_factory=dict)


class ToolAdapter(Protocol):
    def execute(self, args: BaseModel, ctx: ExecutionContext) -> ToolResult: ...


class ToolSpecError(ValueError):
    """A tool definition violates the registry contract (startup error)."""


@dataclass(frozen=True)
class ToolSpec:
    meta: ToolMetadata
    args_model: type[BaseModel]
    adapter: ToolAdapter

    def __post_init__(self) -> None:
        cfg = self.args_model.model_config
        if cfg.get("extra") != "forbid" or cfg.get("strict") is not True:
            raise ToolSpecError(f"{self.meta.tool_id}: args model must be extra='forbid', strict")
        if '"type": "number"' in json.dumps(self.args_model.model_json_schema()):
            # 05 §6 rule 3: no floats in tool args (decimals as canonical strings).
            raise ToolSpecError(f"{self.meta.tool_id}: args model must not declare floats")

    @property
    def key(self) -> tuple[str, str]:
        return (self.meta.tool_id, self.meta.version)

    @property
    def adapter_name(self) -> str:
        declared = getattr(self.adapter, "adapter_name", None)
        if isinstance(declared, str):
            return declared  # wrappers (e.g. test spies) report the wrapped adapter's name
        cls = type(self.adapter)
        return f"{cls.__module__}.{cls.__qualname__}"

    def args_schema(self) -> dict[str, Any]:
        return self.args_model.model_json_schema()

    def validate_args(self, raw: Any) -> BaseModel | None:
        """Strict validation. Returns None on any failure; never surfaces input values."""
        if not isinstance(raw, Mapping):
            return None
        try:
            # JSON-mode strict validation: str -> UUID allowed, "5" -> int rejected.
            return self.args_model.model_validate_json(json.dumps(raw))
        except (ValidationError, TypeError, ValueError):
            return None
