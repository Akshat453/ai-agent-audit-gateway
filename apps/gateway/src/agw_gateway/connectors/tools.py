"""Connector actions as gateway tools (C2, ADR-0035 §4).

``cx_<slug>_<action>`` resolves, per tenant, to a :class:`ConnectorToolSpec` built from the
action's input schema and the connector's CURRENT classification version
(``tool_version = 1.0.<version>``). The spec carries a :class:`ConnectorBinding`; the action
and approval services turn it into a :class:`ConnectorConstraint` for the policy engine, so
the normal identity -> risk -> policy -> approval -> evidence pipeline applies unchanged:

* unclassified action / disabled connector -> DENY (system check);
* classified: the chosen risk is the tool's base risk (the risk engine may raise it, never
  lower it); approval rule "always" forces REQUIRE_APPROVAL, "deny" denies; allowed agents
  and argument constraints are system checks.

A superseded version is not callable (``resolve`` -> None); ``get_any`` still returns it for
an action already authorized under it, unless the connector was disabled or deleted since.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any, Final
from uuid import UUID

from pydantic import BaseModel
from sqlalchemy import Engine, select

from agw_gateway.auth.models import AuthenticatedAgent
from agw_gateway.connectors.constraint import Assessment, ConnectorConstraint, evaluate_constraint
from agw_gateway.connectors.manifest import (
    ActionClassification,
    ActionManifest,
    ClassificationDocument,
    args_model,
    split_tool_id,
    tool_id,
    tool_version,
)
from agw_gateway.connectors.types import CATALOG
from agw_gateway.connectors.types.base import ExecContext
from agw_gateway.db import tables as t
from agw_gateway.privacy.classification import FieldClasses
from agw_gateway.tools.metadata import ToolMetadata
from agw_gateway.tools.spec import ExecutionContext, ToolResult, ToolSpec

INVOKE_SCOPE: Final = "connectors:invoke"
_OPERATION: Final = {"read": "read", "write": "update", "delete": "delete", "execute": "execute"}


@dataclass(frozen=True)
class ConnectorBinding:
    connector_id: UUID
    slug: str
    action: str
    policy_version: int
    status: str
    entry: ActionClassification | None
    type_id: str = ""

    def constraint(
        self,
        agent_id: UUID,
        scopes: frozenset[str],
        args: Mapping[str, Any] | None,
        assessment: Assessment | None = None,
    ) -> ConnectorConstraint:
        return evaluate_constraint(
            assessment=assessment,
            slug=self.slug,
            policy_version=self.policy_version,
            status=self.status,
            entry=self.entry,
            agent_id=agent_id,
            agent_scopes=scopes,
            args=args,
        )


@dataclass(frozen=True)
class ConnectorToolSpec(ToolSpec):
    binding: ConnectorBinding | None = None
    # C3: inspects the call's content before the decision (I/O allowed; e.g. git apply).
    assessor: Callable[[Mapping[str, Any]], Assessment | None] | None = None


def constraint_for(
    spec: ToolSpec | None,
    agent: AuthenticatedAgent,
    args: Mapping[str, Any] | None,
    assessment: Assessment | None = None,
) -> ConnectorConstraint | None:
    if isinstance(spec, ConnectorToolSpec) and spec.binding is not None:
        return spec.binding.constraint(agent.agent_id, agent.scopes, args, assessment)
    return None


class ConnectorAdapter:
    """Executes one connector action: credentials are decrypted for this call only."""

    def __init__(
        self,
        runtime: Any,
        tenant: str,
        connector_id: UUID,
        action: ActionManifest,
        upstream: str | None,
    ) -> None:
        self._runtime, self._tenant, self._cid = runtime, tenant, connector_id
        self._action, self._upstream = action, upstream
        self.adapter_name = f"agw_gateway.connectors.{action.name}"

    def __repr__(self) -> str:  # never expose configuration or credentials
        return f"ConnectorAdapter({self._action.name})"

    def execute(self, args: BaseModel, ctx: ExecutionContext) -> ToolResult:
        row, ctype, config, creds = self._runtime.runtime(self._tenant, self._cid)
        if row.status == "disabled":
            raise RuntimeError("CONNECTOR_DISABLED")
        with ctx.engine.connect() as conn:
            act = conn.execute(
                select(t.actions.c.run_id, t.actions.c.agent_id).where(
                    t.actions.c.action_id == ctx.action_id
                )
            ).one()
        result = ctype.execute(
            ExecContext(
                config=config,
                credentials=creds,
                http=self._runtime.http,
                action=self._action,
                upstream_name=self._upstream,
                tenant=self._tenant,
                connector_id=self._cid,
                action_id=ctx.action_id,
                run_id=act.run_id,
                agent_id=act.agent_id,
                engine=ctx.engine,
            ),
            args.model_dump(mode="json"),
        )
        return ToolResult(public=dict(result))


class ConnectorTools:
    """The registry's dynamic tool source (``ToolRegistry(dynamic=...)``)."""

    def __init__(self, engine: Engine, runtime: Any) -> None:
        self._engine = engine
        self._runtime = runtime

    def _load(
        self, tenant: str, tid: str, version: str | None, *, current_only: bool
    ) -> ToolSpec | None:
        parsed = split_tool_id(tid)
        if parsed is None:
            return None
        slug, action = parsed
        with self._engine.connect() as conn:
            row = conn.execute(
                select(t.connectors).where(
                    t.connectors.c.tenant_id == tenant,
                    t.connectors.c.slug == slug,
                    t.connectors.c.deleted_at.is_(None),
                )
            ).one_or_none()
            if row is None:
                return None
            act = conn.execute(
                select(t.connector_actions).where(
                    t.connector_actions.c.connector_id == row.connector_id,
                    t.connector_actions.c.name == action,
                )
            ).one_or_none()
            if act is None:
                return None
            ver = int(row.policy_version)
            if version is not None:
                if not version.startswith("1.0.") or not version[4:].isdigit():
                    return None
                requested = int(version[4:])
                if requested != ver and (current_only or requested > ver):
                    return None  # superseded classification: not callable any more
                ver = requested
            doc = (
                conn.execute(
                    select(t.connector_policies.c.document).where(
                        t.connector_policies.c.connector_id == row.connector_id,
                        t.connector_policies.c.version == ver,
                    )
                ).scalar_one_or_none()
                if ver > 0
                else None
            )
        if not current_only and row.status == "disabled":
            return None
        entry = ClassificationDocument.model_validate(doc or {}).actions.get(action)
        manifest = ActionManifest(
            name=act.name,
            description=act.description,
            input_schema=act.input_schema,
            side_effect=act.side_effect,
            suggested_risk=act.suggested_risk,
        )
        side = act.side_effect
        ctype = CATALOG.get(row.type_id)
        # Built-in (trusted) types may state reversibility per action (e.g. a push to a
        # feature branch is reversible; a Slack post is not). Upstream text never can.
        hint = (
            next((a for a in ctype.manifest.actions if a.name == action), None) if ctype else None
        )
        reversible = (
            hint.reversible if hint is not None and hint.reversible is not None else side == "read"
        )
        meta = ToolMetadata(
            tool_id=tool_id(slug, action),
            version=tool_version(ver),
            operation_type=_OPERATION[side],
            sensitivity="internal",
            base_risk=entry.risk if entry is not None else "CRITICAL",
            environments_allowed=frozenset(
                hint.environments if hint is not None else ("dev", "staging", "prod")
            ),
            required_scope=INVOKE_SCOPE,
            is_idempotent=side == "read",
            external_effect=side != "read",
            data_classification="internal",
            reversible=reversible,
            medium_effect="ALLOW"
            if entry is not None and entry.approval == "auto"
            else "REQUIRE_APPROVAL",
        )
        results = ctype.result_classes(action, row.config) if ctype is not None else {}
        return ConnectorToolSpec(
            meta=meta,
            args_model=args_model(f"Args_{slug}_{action}", act.input_schema),
            classes=FieldClasses(results=results),  # type: ignore[arg-type]
            adapter=ConnectorAdapter(
                self._runtime, tenant, row.connector_id, manifest, act.upstream_name
            ),
            binding=ConnectorBinding(
                row.connector_id, slug, action, ver, row.status, entry, row.type_id
            ),
            assessor=(
                (lambda args: self._runtime.assess(tenant, row.connector_id, manifest, args))
                if ctype is not None and ctype.assesses(action)
                else None
            ),
        )

    def resolve(self, tenant: str, tool_id: str, version: str | None) -> ToolSpec | None:
        return self._load(tenant, tool_id, version, current_only=True)

    def get_any(self, tenant: str, tool_id: str, version: str) -> ToolSpec | None:
        return self._load(tenant, tool_id, version, current_only=False)

    def callable_for(self, agent: AuthenticatedAgent) -> list[ToolSpec]:
        """Classified, enabled actions this agent may call (what an MCP client lists)."""
        if INVOKE_SCOPE not in agent.scopes:
            return []
        with self._engine.connect() as conn:
            rows = conn.execute(
                select(t.connectors.c.slug, t.connector_actions.c.name)
                .join(
                    t.connector_actions,
                    t.connector_actions.c.connector_id == t.connectors.c.connector_id,
                )
                .where(
                    t.connectors.c.tenant_id == agent.tenant_id,
                    t.connectors.c.deleted_at.is_(None),
                    t.connectors.c.status != "disabled",
                )
                .order_by(t.connectors.c.slug, t.connector_actions.c.name)
            ).all()
        out: list[ToolSpec] = []
        for slug, name in rows:
            spec = self.resolve(agent.tenant_id, tool_id(slug, name), None)
            if spec is None:
                continue
            c = constraint_for(spec, agent, None)
            if c is not None and c.failure is None:
                out.append(spec)
        return out
