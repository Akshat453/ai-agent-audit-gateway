"""Normalized coding action model, schema ``agw.coding-action/1`` (C1, ADR-0034 §2).

Every coding agent's native hook payload is normalized (by the ``agw`` CLI adapters) into this
one shape. The JSON Schema generated from :class:`CodingAction` is committed at
``packages/schemas/coding/coding-action-v1.schema.json`` and checked for drift by a test; the
CLI's normalized output is validated against that file, so the CLI never imports this module.

Never in this model: file contents. Writes carry a **diff** (unified diff, or the agent's own
patch text) next to the action in the decide request; the diff is evaluated by the content
rules and stored ONLY in the encrypted ACTION_REQUESTED payload, never in a header or a log.
"""

from __future__ import annotations

from typing import Annotated, Final, Literal

from pydantic import BaseModel, ConfigDict, Field

SCHEMA_ID: Final = "agw.coding-action/1"
MAX_DIFF_BYTES: Final = 512 * 1024

AgentKind = Literal["claude_code", "codex", "cursor", "gemini_cli", "mcp_generic", "other"]
AGENT_KINDS: Final = ("claude_code", "codex", "cursor", "gemini_cli", "mcp_generic", "other")
ActionType = Literal[
    "file_read",
    "file_write",
    "file_delete",
    "command_exec",
    "search",
    "web_fetch",
    "mcp_call",
    "git_op",
    "unknown",
]
KNOWN_ACTION_TYPES: Final = frozenset(
    {
        "file_read",
        "file_write",
        "file_delete",
        "command_exec",
        "search",
        "web_fetch",
        "mcp_call",
        "git_op",
    }
)
Hex64 = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
GitSha = Annotated[str, Field(pattern=r"^[0-9a-f]{40}([0-9a-f]{24})?$")]
ShortText = Annotated[str, Field(max_length=256)]
PathStr = Annotated[str, Field(min_length=1, max_length=4096)]


class _M(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class Repo(_M):
    remote_url: Annotated[str, Field(max_length=2048)] | None = None
    head_sha: GitSha | None = None


class McpTarget(_M):
    server: ShortText | None = None
    tool: ShortText


class Targets(_M):
    paths: Annotated[list[PathStr], Field(max_length=256)] = []
    argv: Annotated[list[Annotated[str, Field(max_length=8192)]], Field(max_length=1024)] = []
    command: Annotated[str, Field(max_length=65536)] | None = None  # raw shell text
    url: Annotated[str, Field(max_length=4096)] | None = None
    query: Annotated[str, Field(max_length=4096)] | None = None  # search pattern
    mcp: McpTarget | None = None


class ContentDigests(_M):
    """SHA-256 hex of what the CLI saw: the diff it sent, the new content, MCP arguments."""

    diff: Hex64 | None = None
    content: Hex64 | None = None
    args: Hex64 | None = None


class Developer(_M):
    """Informational only: the developer is ALWAYS taken from the device key, never here."""

    name: ShortText | None = None
    email: ShortText | None = None


class CodingAction(_M):
    """One pre-action question from a coding agent, normalized."""

    schema_: Literal["agw.coding-action/1"] = Field(default=SCHEMA_ID, alias="schema")
    session_id: str | None = Field(default=None, max_length=64)
    agent_kind: AgentKind
    agent_version: Annotated[str, Field(pattern=r"^[A-Za-z0-9._/+\-]{1,64}$")] | None = None
    developer: Developer | None = None
    repo: Repo | None = None
    workspace_root: PathStr | None = None
    action_type: ActionType
    native_tool: ShortText | None = None  # the agent's own tool name (Bash, apply_patch, ...)
    targets: Targets = Targets()
    content_digests: ContentDigests = ContentDigests()
    # Set by the CLI when it could not interpret the native payload completely (unknown
    # fields, unknown tool): the policy then never returns allow.
    incomplete: bool = False

    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)
