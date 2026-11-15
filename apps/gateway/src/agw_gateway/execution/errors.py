"""Domain errors raised by the action flow; mapped to the uniform error model in api/errors.py."""

from __future__ import annotations


class GatewayError(Exception):
    code: str = "INTERNAL"
    http_status: int = 500


class RequestInvalid(GatewayError):
    code = "REQUEST_INVALID"
    http_status = 422

    def __init__(self, fields: list[str]) -> None:
        super().__init__("request invalid")
        self.fields = fields  # field NAMES only, never values


class PayloadTooLarge(GatewayError):
    code = "PAYLOAD_TOO_LARGE"
    http_status = 413


class IdempotencyKeyMissing(GatewayError):
    code = "IDEMPOTENCY_KEY_MISSING"
    http_status = 400


class IdempotencyKeyInvalid(GatewayError):
    code = "IDEMPOTENCY_KEY_INVALID"
    http_status = 400


class IdempotencyKeyReused(GatewayError):
    code = "IDEMPOTENCY_KEY_REUSED"
    http_status = 409


class AgentIdMismatch(GatewayError):
    code = "AGENT_ID_MISMATCH"
    http_status = 403


class NotFound(GatewayError):
    code = "NOT_FOUND"
    http_status = 404


class EventNotSealedYet(GatewayError):
    code = "EVENT_NOT_SEALED"
    http_status = 409


class DependencyUnavailable(GatewayError):
    code = "DEPENDENCY_UNAVAILABLE"
    http_status = 503
