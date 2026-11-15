"""Tool registry (11 §4).

Tools are registered in code. ``sync`` mirrors them into ``tool_registry`` (insert-if-absent,
keyed on (tool_id, version)); a changed spec for an existing version is a startup error. Only
pairs present in code AND enabled in the table are callable. Before ``sync`` nothing is
callable (deny by default).
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from sqlalchemy import Engine, select
from sqlalchemy.dialects.postgresql import insert

from agw_gateway.auth.models import AuthenticatedAgent
from agw_gateway.db import tables as t
from agw_gateway.tools.spec import ToolSpec, ToolSpecError


class AmbiguousToolVersion(LookupError):
    """``tool_version`` omitted but more than one version is enabled (-> 422)."""


class ToolRegistry:
    def __init__(self, specs: Iterable[ToolSpec]) -> None:
        self._specs: dict[tuple[str, str], ToolSpec] = {}
        for spec in specs:
            if spec.key in self._specs:
                raise ToolSpecError(f"duplicate tool registration {spec.key}")
            self._specs[spec.key] = spec
        self._enabled: frozenset[tuple[str, str]] = frozenset()

    # ------------------------------------------------------------------ lookup
    def resolve(self, tool_id: str, version: str | None) -> ToolSpec | None:
        if version is not None:
            key = (tool_id, version)
            return self._specs[key] if key in self._enabled else None
        candidates = [self._specs[k] for k in sorted(self._enabled) if k[0] == tool_id]
        if len(candidates) > 1:
            raise AmbiguousToolVersion(tool_id)
        return candidates[0] if candidates else None

    def callable_for(self, agent: AuthenticatedAgent) -> list[ToolSpec]:
        return [
            self._specs[k]
            for k in sorted(self._enabled)
            if self._specs[k].meta.required_scope in agent.scopes
        ]

    def get_any(self, tool_id: str, version: str) -> ToolSpec | None:
        """Code-registered spec regardless of enablement (executor: tool already authorized)."""
        return self._specs.get((tool_id, version))

    # ------------------------------------------------------------------ sync
    @staticmethod
    def _row(spec: ToolSpec) -> dict[str, Any]:
        m = spec.meta
        return {
            "tool_id": m.tool_id,
            "version": m.version,
            "operation_type": m.operation_type,
            "sensitivity": m.sensitivity,
            "base_risk": m.base_risk,
            "environments_allowed": sorted(m.environments_allowed),
            "required_scope": m.required_scope,
            "is_idempotent": m.is_idempotent,
            "external_effect": m.external_effect,
            "target_field": m.target_field,
            "tags": sorted(m.tags),
            "args_schema": spec.args_schema(),
            "adapter": spec.adapter_name,
        }

    def sync(self, engine: Engine) -> None:
        compare = [c.name for c in t.tool_registry.c if c.name not in {"enabled", "registered_at"}]
        enabled: set[tuple[str, str]] = set()
        with engine.begin() as conn:
            for spec in self._specs.values():
                row = self._row(spec)
                conn.execute(insert(t.tool_registry).values(**row).on_conflict_do_nothing())
                stored = (
                    conn.execute(
                        select(t.tool_registry).where(
                            t.tool_registry.c.tool_id == spec.meta.tool_id,
                            t.tool_registry.c.version == spec.meta.version,
                        )
                    )
                    .one()
                    ._mapping
                )
                changed = [c for c in compare if _norm(stored[c]) != _norm(row[c])]
                if changed:
                    raise ToolSpecError(
                        f"tool {spec.key} changed without a version bump: {', '.join(changed)}"
                    )
                if stored["enabled"]:
                    enabled.add(spec.key)
        self._enabled = frozenset(enabled)


def _norm(value: Any) -> Any:
    if isinstance(value, list | tuple):
        return sorted(value, key=repr)
    return value
