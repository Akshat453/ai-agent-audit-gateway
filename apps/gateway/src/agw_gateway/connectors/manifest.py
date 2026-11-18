"""Connector type manifests, the input-schema subset, and classification documents (C2,
ADR-0035). Pure: no I/O.

A connector TYPE (github, slack, http_api, ...) declares a manifest: id, name, category,
auth method, a Pydantic config model, and the actions it can perform with their input schema,
side effect and a SUGGESTED default risk. The suggestion is only a suggestion: every action of
a new connector is UNCLASSIFIED (and denied) until an admin classifies it.

Input schemas are a deliberately small JSON-Schema subset, so an action's arguments can be
validated by a strict, extra-forbidding Pydantic model built from it:

    {"type": "object", "additionalProperties": false, "required": [...],
     "properties": {name: {"type": "string" | "integer" | "boolean" | "array",
                           "items": {"type": "string"}, "maxLength": n, "minLength": n,
                           "enum": [...], "pattern": "...", "minimum": n, "maximum": n,
                           "maxItems": n, "description": "..."}}}

No floats (05 §6), no nesting, no free-form objects.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from typing import Annotated, Any, Final, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, create_model, field_validator

Category = Literal[
    "code_hosting", "agent_client", "tool", "notification", "anchoring", "mcp_upstream"
]
AuthMethod = Literal["github_app", "oauth2", "api_key", "bot_token", "smtp", "webhook", "none"]
SideEffect = Literal["read", "write", "delete", "execute"]
Risk = Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
ApprovalRule = Literal["auto", "always", "deny"]
APPROVER_ROLES: Final = ("approver", "security", "ledger_lead", "maintainer")
ACTION_NAME_RE: Final = re.compile(r"^[a-z][a-z0-9_]{0,35}$")
SLUG_RE: Final = re.compile(r"^[a-z][a-z0-9]{1,23}$")
MAX_PROPERTIES: Final = 32


class ManifestError(ValueError):
    """A manifest, input schema or classification violates the contract."""


class _M(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class ActionManifest(_M):
    name: str
    description: Annotated[str, Field(max_length=4000)] = ""
    input_schema: dict[str, Any]
    side_effect: SideEffect
    suggested_risk: Risk
    # C3: built-in types only (trusted code): reversibility for the risk engine, and the
    # DEFAULT classification PROPOSAL an admin may accept (never applied automatically).
    reversible: bool | None = None
    proposed: dict[str, Any] | None = None
    # Target environments the action may run in (the first is the MCP default). GitHub
    # dev-tools act on feature branches / issues / PRs: "dev"; main is protected by GitHub.
    environments: tuple[Literal["dev", "staging", "prod"], ...] = ("prod", "staging", "dev")

    @field_validator("name")
    @classmethod
    def _name(cls, v: str) -> str:
        if not ACTION_NAME_RE.fullmatch(v):
            raise ValueError("action name must match ^[a-z][a-z0-9_]{0,35}$")
        return v

    @field_validator("input_schema")
    @classmethod
    def _schema(cls, v: dict[str, Any]) -> dict[str, Any]:
        check_input_schema(v)
        return v


class ConnectorManifest(_M):
    id: Annotated[str, Field(pattern=r"^[a-z][a-z0-9_]{1,40}$")]
    name: Annotated[str, Field(max_length=80)]
    category: Category
    auth: AuthMethod
    description: Annotated[str, Field(max_length=1000)] = ""
    actions: tuple[ActionManifest, ...] = ()
    # Actions are discovered at connect time (MCP upstream, admin-defined HTTP actions).
    dynamic_actions: bool = False
    has_health_check: bool = True

    @field_validator("actions")
    @classmethod
    def _unique(cls, v: tuple[ActionManifest, ...]) -> tuple[ActionManifest, ...]:
        names = [a.name for a in v]
        if len(names) != len(set(names)):
            raise ValueError("duplicate action names")
        return v


# --------------------------------------------------------------------------- input schemas
_PROP_KEYS: Final = frozenset(
    {
        "type",
        "items",
        "maxLength",
        "minLength",
        "enum",
        "pattern",
        "minimum",
        "maximum",
        "maxItems",
        "description",
        "title",
    }
)


def check_input_schema(schema: Mapping[str, Any]) -> None:
    if schema.get("type") != "object":
        raise ManifestError("input schema must be an object")
    if set(schema) - {"type", "properties", "required", "additionalProperties", "title"}:
        raise ManifestError("unsupported input schema keyword")
    if schema.get("additionalProperties", False) is not False:
        raise ManifestError("additionalProperties must be false")
    props = schema.get("properties", {})
    if not isinstance(props, dict) or len(props) > MAX_PROPERTIES:
        raise ManifestError("properties must be an object (<= 32)")
    for name, p in props.items():
        if not re.fullmatch(r"^[a-z][a-z0-9_]{0,63}$", str(name)):
            raise ManifestError("property names must be snake_case")
        if not isinstance(p, dict) or set(p) - _PROP_KEYS:
            raise ManifestError(f"unsupported keyword in property {name}")
        kind = p.get("type")
        if kind not in ("string", "integer", "boolean", "array"):
            raise ManifestError(f"property {name}: type must be string|integer|boolean|array")
        if kind == "array" and p.get("items") != {"type": "string"}:
            raise ManifestError(f"property {name}: arrays hold strings only")
        if "pattern" in p:
            try:
                re.compile(p["pattern"])
            except re.error as exc:
                raise ManifestError(f"property {name}: bad pattern") from exc
    required = schema.get("required", [])
    if not isinstance(required, list) or set(required) - set(props):
        raise ManifestError("required lists unknown properties")


def args_model(model_name: str, schema: Mapping[str, Any]) -> type[BaseModel]:
    """A strict, extra-forbidding Pydantic model for one action's input schema."""
    check_input_schema(schema)
    required = set(schema.get("required", []))
    fields: dict[str, Any] = {}
    for name, p in schema.get("properties", {}).items():
        kind = p["type"]
        ann: Any
        if kind == "string":
            ann = Annotated[
                str,
                StringConstraints(
                    max_length=int(p.get("maxLength", 8192)),
                    min_length=int(p.get("minLength", 0)),
                    pattern=p.get("pattern"),
                ),
            ]
            if "enum" in p:
                ann = Literal[tuple(str(e) for e in p["enum"])]
        elif kind == "integer":
            ann = Annotated[int, Field(ge=p.get("minimum"), le=p.get("maximum"))]
        elif kind == "boolean":
            ann = bool
        else:
            ann = Annotated[
                list[Annotated[str, StringConstraints(max_length=8192)]],
                Field(max_length=int(p.get("maxItems", 100))),
            ]
        fields[name] = (ann, ...) if name in required else (ann | None, None)
    return create_model(
        model_name,
        __config__=ConfigDict(extra="forbid", strict=True, frozen=True),
        **fields,
    )


# --------------------------------------------------------------------------- classification
class ArgConstraint(_M):
    """Admin-defined tightening of one argument (never loosens the input schema)."""

    allowed: tuple[str, ...] | None = None  # exact allowlist (strings / ints as text)
    pattern: str | None = None
    max_length: Annotated[int, Field(ge=0)] | None = None
    min: int | None = None
    max: int | None = None

    @field_validator("pattern")
    @classmethod
    def _pattern(cls, v: str | None) -> str | None:
        if v is not None:
            re.compile(v)
        return v


class ActionClassification(_M):
    risk: Risk
    approval: ApprovalRule = "auto"
    approver_role: Literal["approver", "security", "ledger_lead", "maintainer"] = "approver"
    # "*" = any agent with the connectors:invoke scope; "devices" = enrolled developer
    # devices only; otherwise agent ids (UUID strings).
    allowed_agents: tuple[str, ...] = ("devices",)
    constraints: dict[str, ArgConstraint] = {}

    @field_validator("allowed_agents")
    @classmethod
    def _agents(cls, v: tuple[str, ...]) -> tuple[str, ...]:
        if not v:
            raise ValueError("allowed_agents must not be empty (use 'devices' or '*')")
        for a in v:
            if a not in ("*", "devices") and not re.fullmatch(r"^[0-9a-f-]{36}$", a):
                raise ValueError("allowed_agents: '*', 'devices' or agent UUIDs")
        return v


class ClassificationDocument(_M):
    """One immutable version of a connector's classification (connector_policies.document)."""

    actions: dict[str, ActionClassification] = {}


def canonical_digest(value: Any) -> bytes:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(b"\x12AGW/connector/v1\x00" + raw.encode("utf-8")).digest()


def tool_id(slug: str, action: str) -> str:
    return f"cx_{slug}_{action}"


def split_tool_id(tid: str) -> tuple[str, str] | None:
    if not tid.startswith("cx_"):
        return None
    slug, _, action = tid[3:].partition("_")
    if not SLUG_RE.fullmatch(slug) or not ACTION_NAME_RE.fullmatch(action):
        return None
    return slug, action


def tool_version(policy_version: int) -> str:
    """Each classification version is a new tool version: old decisions keep theirs."""
    return f"1.0.{policy_version}"
