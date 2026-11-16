"""Typed outcomes of a tool call through the gateway (Phase 8, ADR-0030 §5).

Every exception carries the ``action_id`` (when one exists) so an agent or operator can look
the action up; none carries argument values or credentials.
"""

from __future__ import annotations

from typing import Any


class GatewayError(Exception):
    """An HTTP-level error from the gateway's uniform error model (11 §2)."""

    def __init__(self, status: int, code: str, message: str, request_id: str | None) -> None:
        super().__init__(f"{status} {code}: {message}")
        self.status = status
        self.code = code
        self.request_id = request_id


class ToolCallError(Exception):
    """Base class: the call was evaluated (an action exists) but produced no result."""

    def __init__(self, action_id: str, status: str, detail: str = "", **info: Any) -> None:
        super().__init__(f"{type(self).__name__}: action {action_id} {status} {detail}".rstrip())
        self.action_id = action_id
        self.status = status
        self.info = info


class Denied(ToolCallError):
    """Policy DENY (at request time, or at re-evaluation after an approval). ``reasons`` are
    the gateway's stable reason codes, e.g. DELEGATION_SCOPE_MISSING. Never retried."""

    @property
    def reasons(self) -> list[str]:
        return list(self.info.get("reasons", []))


class ApprovalRequired(ToolCallError):
    """A human must approve and did not within the wait. NOTHING was executed. The action
    stays pending: call ``Client.wait(action_id)`` later, or give up."""

    @property
    def approval_id(self) -> str | None:
        value = self.info.get("approval_id")
        return str(value) if value else None


class ApprovalExpired(ToolCallError):
    """The approval window closed without enough approvals. Nothing was executed."""


class ToolFailed(ToolCallError):
    """The tool ran (or was refused right before dispatch) and failed. ``error_code`` is a
    sanitized gateway code (e.g. TOOL_ERROR:ConnectionRefusedError, DELEGATION_INVALID)."""

    @property
    def error_code(self) -> str | None:
        value = self.info.get("error_code")
        return str(value) if value else None


class OutcomeUnknown(ToolCallError):
    """The tool may or may not have taken effect (crash / timeout after dispatch). The
    gateway never retries it automatically (ADR-0011); do NOT resubmit a non-idempotent call
    blindly - reconcile first."""


class StillRunning(ToolCallError):
    """The local wait ended while the action was authorized/dispatched. Not a failure: the
    gateway continues; poll ``Client.wait(action_id)``."""
