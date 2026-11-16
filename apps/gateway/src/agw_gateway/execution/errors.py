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


# --------------------------------------------------------------------------- approvals (Phase 5)
class Forbidden(GatewayError):
    """Authenticated human lacks the required role."""

    code = "FORBIDDEN"
    http_status = 403


class AgentNotPermitted(GatewayError):
    """An AGENT credential was presented to a human-only endpoint (recorded as evidence)."""

    code = "AGENT_NOT_PERMITTED"
    http_status = 403


class ApprovalNotPending(GatewayError):
    code = "APPROVAL_NOT_PENDING"
    http_status = 409


class ApprovalExpired(GatewayError):
    code = "APPROVAL_EXPIRED"
    http_status = 409


class ApprovalStale(GatewayError):
    """The echoed action_digest / nonce differ from the approval's (wrong or stale view)."""

    code = "APPROVAL_STALE"
    http_status = 409


class ApprovalAlreadyDecided(GatewayError):
    """This approver already decided this approval (four-eyes needs a DIFFERENT approver)."""

    code = "APPROVAL_ALREADY_DECIDED"
    http_status = 409


# --------------------------------------------------------------------------- Phase 7
class RoleRequired(GatewayError):
    """The human lacks the role this endpoint needs (admin grants, auditor exports)."""

    code = "ROLE_REQUIRED"
    http_status = 403


class DisclosureInvalid(GatewayError):
    code = "DISCLOSURE_INVALID"
    http_status = 422


class DisclosureDenied(GatewayError):
    """Grant expired / revoked / not this auditor's / event outside the grant. Always
    recorded as DISCLOSURE_ACCESSED{outcome: DENIED, code} before the error is returned."""

    code = "DISCLOSURE_DENIED"
    http_status = 403

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


# --------------------------------------------------------------------------- Phase 8
class DelegationRefused(GatewayError):
    """POST /v1/delegations refused: the requested delegation would exceed what the issuer
    holds (scopes, tools, risk, expiry, depth) or names an unusable parent/child. Nothing is
    issued. ``code`` is one of api/errors.MESSAGES (fixed strings, no request values)."""

    http_status = 403

    def __init__(self, code: str, http_status: int = 403) -> None:
        super().__init__(code)
        self.code = code
        self.http_status = http_status


class DelegationUnavailable(GatewayError):
    """No usable delegation signing key: nothing can be issued or verified (fail closed)."""

    code = "DELEGATION_UNAVAILABLE"
    http_status = 503


class ExchangeRefused(GatewayError):
    """RFC 8693 token exchange refused (one fixed code, no oracle about which check failed)."""

    code = "INVALID_GRANT"
    http_status = 400
