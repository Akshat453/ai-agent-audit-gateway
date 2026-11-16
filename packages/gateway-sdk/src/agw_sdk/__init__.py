"""Thin Python client for the AGW gateway. No server internals (import-linter enforced) and no
tool credentials: tools run only inside the gateway."""

from agw_sdk.client import ActionResponse, Client, Delegation, Source, ToolCallResult
from agw_sdk.errors import (
    ApprovalExpired,
    ApprovalRequired,
    Denied,
    GatewayError,
    OutcomeUnknown,
    StillRunning,
    ToolCallError,
    ToolFailed,
)

__all__ = [
    "ActionResponse",
    "ApprovalExpired",
    "ApprovalRequired",
    "Client",
    "Delegation",
    "Denied",
    "GatewayError",
    "OutcomeUnknown",
    "Source",
    "StillRunning",
    "ToolCallError",
    "ToolCallResult",
    "ToolFailed",
]
