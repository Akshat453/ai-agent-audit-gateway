"""Agent-client connector types (C2 §2b): Claude Code, Codex, Cursor, Gemini CLI, VS Code
(MCP), Antigravity (MCP), generic MCP client. They have no actions; "Add" shows the
enforcement TIER (from C1's capability table, docs/gateway/coding-agents.md §1) and the exact
setup command, and the enrollment link is issued by the device-enrollment API."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, ClassVar, Final

from pydantic import BaseModel

from agw_gateway.connectors.manifest import ConnectorManifest
from agw_gateway.connectors.types.base import ConnectorType

# Tiers (ADR-0035 §3):
#  enforced  pre-action hooks + a managed/policy mechanism that makes them mandatory
#  hooked    pre-action hooks with a fail-closed option, enforcement only via MDM files
#  advisory  pre-action hooks exist but the user can disable them; failures let actions through
#  mcp_only  no supported pre-action hook: only the gateway's MCP tools are governed
TIERS: Final[dict[str, dict[str, str]]] = {
    "claude_code": {
        "tier": "enforced",
        "why": "PreToolUse hooks; managed-settings allowManagedHooksOnly; onFailure=block",
    },
    "codex": {
        "tier": "enforced",
        "why": "PreToolUse hooks; requirements.toml allow_managed_hooks_only (a killed hook "
        "fails open: no fail-closed switch)",
    },
    "cursor": {
        "tier": "hooked",
        "why": "before* hooks with failClosed; MDM hooks.json; no documented managed-only switch",
    },
    "gemini_cli": {
        "tier": "advisory",
        "why": "BeforeTool hooks; no enforced hooks (users can /hooks disable-all); fails open",
    },
    "vscode": {
        "tier": "mcp_only",
        "why": "MCP tools only (VS Code agent hooks exist in Preview; no AgentGuard adapter yet)",
    },
    "antigravity": {
        "tier": "mcp_only",
        "why": "MCP tools only (Antigravity hooks documented; no AgentGuard adapter yet)",
    },
    "generic_mcp": {"tier": "mcp_only", "why": "MCP tools only"},
}
HOOK_KIND: Final = {
    "claude_code": "claude_code",
    "codex": "codex",
    "cursor": "cursor",
    "gemini_cli": "gemini_cli",
}


def _agent_type(type_id: str, display: str) -> type[ConnectorType]:
    class _Agent(ConnectorType):
        manifest: ClassVar[ConnectorManifest] = ConnectorManifest(
            id=type_id,
            name=display,
            category="agent_client",
            auth="none",
            description=f"{display}: enroll developer devices and connect the agent.",
            has_health_check=False,
        )

        def setup(self, config: BaseModel, gateway_url: str) -> Mapping[str, Any]:
            info = TIERS[type_id]
            hook = HOOK_KIND.get(type_id)
            commands = ["pipx install agw-cli", f"agw login --url {gateway_url}"]
            if hook is not None:
                commands.append(f"agw init --agents {hook}")
            else:
                commands.append("agw init --agents mcp")
            return {
                "tier": info["tier"],
                "tier_reason": info["why"],
                "commands": commands,
                "mcp_url": f"{gateway_url}/mcp",
                "hook_kind": hook,
            }

    _Agent.__name__ = f"{type_id.title().replace('_', '')}Connector"
    return _Agent


AGENT_TYPES: Final[list[type[ConnectorType]]] = [
    _agent_type("claude_code", "Claude Code"),
    _agent_type("codex", "Codex CLI"),
    _agent_type("cursor", "Cursor"),
    _agent_type("gemini_cli", "Gemini CLI"),
    _agent_type("vscode", "VS Code (MCP)"),
    _agent_type("antigravity", "Antigravity (MCP)"),
    _agent_type("generic_mcp", "Generic MCP client"),
]
