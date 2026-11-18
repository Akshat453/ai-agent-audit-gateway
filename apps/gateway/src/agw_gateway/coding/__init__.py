"""Coding-agent integration (C1, ADR-0034): a vendor-neutral pre-action API for coding agents.

Kept import-light on purpose: ``approvals.service`` imports ``CODING_TOOL_PREFIX`` from here,
and ``coding.service`` imports the approvals service, so this module must not import either.
"""

from __future__ import annotations

from typing import Final

# Coding actions are recorded as gateway actions whose tool id is ``coding.<action_type>``.
# The agent executes them on the developer's machine (the gateway never dispatches them), so an
# approval of such an action is consumed by the agent's identical retry, not by the outbox.
CODING_TOOL_PREFIX: Final = "coding."
CODING_TOOL_VERSION: Final = "1"


def is_coding_tool(tool_id: str) -> bool:
    return tool_id.startswith(CODING_TOOL_PREFIX)
