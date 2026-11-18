"""Adapter registry: agent kind -> adapter. Later phases (``agw init``) read ``spec`` from here
to generate each agent's hook configuration."""

from __future__ import annotations

from agw_cli.adapters.base import Adapter, AgentSpec, PayloadError, Rendered, Verdict
from agw_cli.adapters.claude_code import ClaudeCodeAdapter
from agw_cli.adapters.codex import CodexAdapter
from agw_cli.adapters.cursor import CursorAdapter
from agw_cli.adapters.gemini_cli import GeminiCliAdapter
from agw_cli.adapters.generic import McpGenericAdapter, OtherAdapter

REGISTRY: dict[str, Adapter] = {
    a.kind: a
    for a in (
        ClaudeCodeAdapter(),
        CodexAdapter(),
        CursorAdapter(),
        GeminiCliAdapter(),
        McpGenericAdapter(),
        OtherAdapter(),
    )
}


def get(kind: str) -> Adapter | None:
    return REGISTRY.get(kind)


__all__ = ["REGISTRY", "Adapter", "AgentSpec", "PayloadError", "Rendered", "Verdict", "get"]
