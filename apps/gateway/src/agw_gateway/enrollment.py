"""Device enrollment (C2, ADR-0035 §5): the RFC 8628 device authorization grant behind
``agw login``, plus the device binding used by the MCP OAuth consent.

1. ``agw login`` -> ``POST /v1/device/authorize {tenant, agent_kind, label}`` -> a device code
   (kept secret by the CLI; stored only as SHA-256) and a short user code;
2. the developer opens the dashboard's ``/enroll``, signs in, checks the code, approves;
3. the CLI polls ``POST /v1/device/token`` (``authorization_pending`` / ``slow_down`` /
   ``access_denied`` / ``expired_token``) and, once approved, receives the device key ONCE.

The approving human IS the developer the device acts for. The runtime role cannot create
agents; ``agw_enroll_device`` (SECURITY DEFINER) creates exactly one coding device with fixed
scopes bound to that human. DEVICE_ENROLLED is written in the same transaction.
"""

from __future__ import annotations

import hashlib
import re
import secrets
from datetime import timedelta
from typing import Any, Final, Literal
from uuid import UUID

from sqlalchemy import Connection, Engine, func, insert, select, text, update

from agw_gateway.auth.tokens import issue_token
from agw_gateway.db import tables as t
from agw_gateway.evidence import EvidenceWriter, NewEvent
from agw_gateway.execution.errors import Forbidden, GatewayError, NotFound, RequestInvalid
from agw_gateway.humans.models import AuthenticatedHuman
from agw_gateway.ids import uuid7

USER_CODE_ALPHABET: Final = "BCDFGHJKLMNPQRSTVWXZ"  # no vowels: no accidental words
AGENT_KINDS: Final = frozenset(
    {
        "claude_code",
        "codex",
        "cursor",
        "gemini_cli",
        "vscode",
        "antigravity",
        "generic_mcp",
        "mcp_generic",
        "other",
    }
)
POLL_INTERVAL: Final = 5


class DeviceFlowError(GatewayError):
    """RFC 8628 §3.5 error, returned as ``{"error": <code>}`` with HTTP 400."""

    http_status = 400

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _hash(code: str) -> bytes:
    return hashlib.sha256(b"AGW/device-code/v1\x00" + code.encode()).digest()


def _user_code() -> str:
    pick = "".join(secrets.choice(USER_CODE_ALPHABET) for _ in range(8))
    return f"{pick[:4]}-{pick[4:]}"


def normalize_user_code(raw: str) -> str:
    s = "".join(ch for ch in raw.upper() if ch.isalpha())
    return f"{s[:4]}-{s[4:8]}"


def enroll_device(
    conn: Connection,
    writer: EvidenceWriter,
    *,
    tenant: str,
    human_id: UUID,
    label: str,
    agent_kind: str,
    via: Literal["device_code", "mcp_oauth", "admin"],
) -> tuple[UUID, str]:
    """Create a device (agent + credential + developer binding) and DEVICE_ENROLLED."""
    agent_id = uuid7()
    issued = issue_token()
    conn.execute(
        text("SELECT agw_enroll_device(:t, :h, :a, :l, :c, :k, :d)"),
        {
            "t": tenant,
            "h": human_id,
            "a": agent_id,
            "l": label,
            "c": uuid7(),
            "k": issued.key_id,
            "d": issued.digest,
        },
    )
    writer.append(
        conn,
        tenant,
        [
            NewEvent(
                type="DEVICE_ENROLLED",
                actor_kind="human",
                actor_id=str(human_id),
                agent_id=agent_id,
                fields={"device": {"id": agent_id.bytes, "kind": agent_kind[:32], "via": via}},
                risk_level="HIGH",
            )
        ],
    )
    return agent_id, issued.token


class EnrollmentService:
    def __init__(
        self, *, engine: Engine, writer: EvidenceWriter, verification_uri: str, ttl_seconds: int
    ) -> None:
        self._engine = engine
        self._writer = writer
        self._uri = verification_uri
        self._ttl = timedelta(seconds=ttl_seconds)

    def authorize(self, body: dict[str, Any]) -> dict[str, Any]:
        tenant = str(body.get("tenant", ""))
        kind = str(body.get("agent_kind", "other"))
        label = str(body.get("label", "device"))
        if kind not in AGENT_KINDS:
            raise RequestInvalid(["agent_kind"])
        if not re.fullmatch(r"[A-Za-z0-9._-]{1,64}", label):
            raise RequestInvalid(["label"])
        if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,62}", tenant):
            raise RequestInvalid(["tenant"])
        device_code = secrets.token_urlsafe(32)
        with self._engine.begin() as conn:
            if (
                conn.execute(
                    select(t.tenants.c.tenant_id).where(t.tenants.c.tenant_id == tenant)
                ).first()
                is None
            ):
                raise RequestInvalid(["tenant"])
            for _ in range(5):
                user_code = _user_code()
                taken = conn.execute(
                    select(t.device_enrollments.c.user_code).where(
                        t.device_enrollments.c.user_code == user_code
                    )
                ).first()
                if taken is None:
                    break
            conn.execute(
                insert(t.device_enrollments).values(
                    device_code_hash=_hash(device_code),
                    user_code=user_code,
                    tenant_id=tenant,
                    agent_kind=kind,
                    label=label,
                    status="pending",
                    expires_at=func.now() + self._ttl,
                )
            )
        return {
            "device_code": device_code,
            "user_code": user_code,
            "verification_uri": self._uri,
            "verification_uri_complete": f"{self._uri}?code={user_code}",
            "expires_in": int(self._ttl.total_seconds()),
            "interval": POLL_INTERVAL,
        }

    def token(self, body: dict[str, Any]) -> dict[str, Any]:
        code = body.get("device_code")
        if not isinstance(code, str) or not 10 <= len(code) <= 100:
            raise DeviceFlowError("invalid_request")
        pending: str | None = None  # raised AFTER commit: the poll time must persist
        with self._engine.begin() as conn:
            row = conn.execute(
                select(
                    t.device_enrollments,
                    (t.device_enrollments.c.expires_at <= func.now()).label("expired"),
                    func.extract("epoch", func.now() - t.device_enrollments.c.last_poll_at).label(
                        "since_poll"
                    ),
                )
                .where(t.device_enrollments.c.device_code_hash == _hash(code))
                .with_for_update(of=t.device_enrollments)
            ).one_or_none()
            if row is None or row.status == "issued":
                raise DeviceFlowError("invalid_grant")  # unknown, or the key was already issued
            if row.expired:
                raise DeviceFlowError("expired_token")
            if row.status == "denied":
                raise DeviceFlowError("access_denied")
            too_fast = row.since_poll is not None and float(row.since_poll) < POLL_INTERVAL - 1
            conn.execute(
                update(t.device_enrollments)
                .where(t.device_enrollments.c.device_code_hash == row.device_code_hash)
                .values(last_poll_at=func.now())
            )
            if row.status == "pending":
                pending = "slow_down" if too_fast else "authorization_pending"
        if pending is not None:
            raise DeviceFlowError(pending)
        with self._engine.begin() as conn:
            row = conn.execute(
                select(t.device_enrollments)
                .where(
                    t.device_enrollments.c.device_code_hash == _hash(code),
                    t.device_enrollments.c.status == "approved",
                )
                .with_for_update()
            ).one_or_none()
            if row is None:
                raise DeviceFlowError("invalid_grant")
            assert row.approved_by is not None  # noqa: S101 - approved implies a human
            agent_id, token = enroll_device(
                conn,
                self._writer,
                tenant=row.tenant_id,
                human_id=row.approved_by,
                label=row.label,
                agent_kind=row.agent_kind,
                via="device_code",
            )
            conn.execute(
                update(t.device_enrollments)
                .where(t.device_enrollments.c.device_code_hash == row.device_code_hash)
                .values(status="issued", device_agent_id=agent_id)
            )
            username = conn.execute(
                select(t.humans.c.username).where(t.humans.c.human_id == row.approved_by)
            ).scalar_one()
        # The device key leaves the gateway exactly once, here.
        return {
            "device_key": token,
            "tenant": row.tenant_id,
            "device_id": str(agent_id),
            "developer": username,
            "token_type": "agw-device-key",
        }

    def _pending(self, conn: Connection, human: AuthenticatedHuman, user_code: str) -> Any:
        row = conn.execute(
            select(
                t.device_enrollments, (t.device_enrollments.c.expires_at > func.now()).label("live")
            )
            .where(
                t.device_enrollments.c.user_code == normalize_user_code(user_code),
                t.device_enrollments.c.tenant_id == human.tenant_id,
            )
            .with_for_update(of=t.device_enrollments)
        ).one_or_none()
        if row is None:
            raise NotFound
        return row

    def lookup(self, human: AuthenticatedHuman, user_code: str) -> dict[str, Any]:
        with self._engine.begin() as conn:
            row = self._pending(conn, human, user_code)
        return {
            "user_code": row.user_code,
            "agent_kind": row.agent_kind,
            "label": row.label,
            "status": row.status if row.live or row.status != "pending" else "expired",
            "created_at": row.created_at.isoformat().replace("+00:00", "Z"),
        }

    def decide(self, human: AuthenticatedHuman, user_code: str, approve: bool) -> dict[str, Any]:
        with self._engine.begin() as conn:
            row = self._pending(conn, human, user_code)
            if row.status != "pending" or not row.live:
                raise Forbidden
            conn.execute(
                update(t.device_enrollments)
                .where(t.device_enrollments.c.device_code_hash == row.device_code_hash)
                .values(status="approved" if approve else "denied", approved_by=human.human_id)
            )
        return {"status": "approved" if approve else "denied"}
