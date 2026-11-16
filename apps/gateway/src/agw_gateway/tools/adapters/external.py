"""Real external adapters (Phase 8, ADR-0030 §7). Credentials live ONLY in the gateway runtime.

``public_api_get`` 1.0.0: read-only HTTP GET to an EXACT host[:port] allowlist.
  * The allowlist is enforced twice: in arg validation (a URL outside it is a recorded DENY,
    the adapter never runs) and again in the adapter (defense in depth).
  * https only, except hosts explicitly listed in ``http_allow_plain`` (local test sinks).
  * No redirects (a redirect could leave the allowlist), no proxy from the environment,
    bounded response size, short timeout. No credentials are attached.

``send_email_smtp`` 1.0.0: an APPROVED write through a real SMTP relay. MEDIUM effect is
  REQUIRE_APPROVAL, so every send needs a human approval (or is denied). The relay password
  is a gateway secret (``AGW_SMTP_PASSWORD`` / ``_FILE``); agents never see it. Recipient
  domains can be restricted (``AGW_SMTP_ALLOWED_DOMAINS``). CR/LF in the subject is rejected
  (header injection).
"""

from __future__ import annotations

import hashlib
import json
import smtplib
from collections.abc import Callable
from email.message import EmailMessage
from typing import Any
from urllib.parse import urlsplit

import httpx
from pydantic import BaseModel, ConfigDict, Field, field_validator

from agw_gateway.privacy.classification import FieldClasses
from agw_gateway.tools.metadata import ToolMetadata
from agw_gateway.tools.spec import ExecutionContext, ToolResult, ToolSpec

PUBLIC_API_GET = ToolMetadata(
    tool_id="public_api_get",
    version="1.0.0",
    operation_type="read",
    sensitivity="public",
    base_risk="LOW",
    environments_allowed=frozenset({"dev", "staging", "prod"}),
    required_scope="tools:public_api_get",
    is_idempotent=True,
    external_effect=False,
    data_classification="public",
    reversible=True,
    medium_effect="ALLOW",
)
SEND_EMAIL_SMTP = ToolMetadata(
    tool_id="send_email_smtp",
    version="1.0.0",
    operation_type="create",
    sensitivity="internal",
    base_risk="MEDIUM",
    environments_allowed=frozenset({"dev", "staging", "prod"}),
    required_scope="tools:send_email_smtp",
    is_idempotent=False,
    external_effect=True,
    data_classification="internal",
    reversible=False,
    destination_field="to",
    volume_field="to",
    medium_effect="REQUIRE_APPROVAL",
)


class UrlNotAllowed(RuntimeError):
    """Raised by the adapter if a URL outside the allowlist ever reaches it."""


def url_allowed(url: str, allowlist: frozenset[str], plain: frozenset[str]) -> bool:
    try:
        parts = urlsplit(url)
        port = parts.port  # raises on a malformed port
    except ValueError:
        return False
    if parts.username is not None or parts.password is not None or parts.fragment:
        return False
    host = (parts.hostname or "").lower()
    netloc = host if port is None else f"{host}:{port}"
    if netloc not in allowlist:
        return False
    if parts.scheme == "https":
        return True
    return parts.scheme == "http" and netloc in plain


class _Args(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)


class PublicApiGetArgs(_Args):
    url: str = Field(min_length=8, max_length=2048)


class SendEmailSmtpArgs(_Args):
    to: list[str] = Field(min_length=1, max_length=20)
    subject: str = Field(min_length=1, max_length=200)
    body: str = Field(default="", max_length=10_000)

    @field_validator("subject")
    @classmethod
    def _no_header_injection(cls, v: str) -> str:
        if "\r" in v or "\n" in v:
            raise ValueError("subject must be one line")
        return v

    @field_validator("to")
    @classmethod
    def _addresses(cls, v: list[str]) -> list[str]:
        for addr in v:
            local, _, domain = addr.rpartition("@")
            if (
                not local
                or not domain
                or any(c in addr for c in "\r\n<>,; \t")
                or len(addr) > 254
                or "." not in domain
            ):
                raise ValueError("invalid address")
        return v


def _public_api_args(allowlist: frozenset[str], plain: frozenset[str]) -> type[BaseModel]:
    """Arg model whose validation enforces the deployment's allowlist. Same JSON schema as
    ``PublicApiGetArgs`` (validators are not part of the schema), so the registry spec is
    stable across allowlist changes."""

    class Args(PublicApiGetArgs):
        @field_validator("url")
        @classmethod
        def _allowlisted(cls, v: str) -> str:
            if not url_allowed(v, allowlist, plain):
                raise ValueError("host not allowlisted")
            return v

    Args.__name__ = "PublicApiGetArgs"
    return Args


def _smtp_args(domains: frozenset[str]) -> type[BaseModel]:
    class Args(SendEmailSmtpArgs):
        @field_validator("to")
        @classmethod
        def _allowed_domains(cls, v: list[str]) -> list[str]:
            if domains and any(a.rpartition("@")[2].lower() not in domains for a in v):
                raise ValueError("recipient domain not allowed")
            return v

    Args.__name__ = "SendEmailSmtpArgs"
    return Args


class PublicApiGetAdapter:
    def __init__(
        self,
        allowlist: frozenset[str],
        plain: frozenset[str],
        max_bytes: int,
        timeout: float = 5.0,
    ) -> None:
        self._allow, self._plain, self._max, self._timeout = allowlist, plain, max_bytes, timeout

    def execute(self, args: BaseModel, ctx: ExecutionContext) -> ToolResult:
        assert isinstance(args, PublicApiGetArgs)  # noqa: S101
        if not url_allowed(args.url, self._allow, self._plain):
            raise UrlNotAllowed
        body = bytearray()
        with (
            httpx.Client(follow_redirects=False, trust_env=False, timeout=self._timeout) as c,
            c.stream("GET", args.url, headers={"Accept": "application/json, text/plain"}) as r,
        ):
            for chunk in r.iter_bytes():
                body.extend(chunk)
                if len(body) > self._max:
                    break
            status = r.status_code
            ctype = r.headers.get("content-type", "").split(";")[0].strip()[:100]
        truncated = len(body) > self._max
        raw = bytes(body[: self._max])
        text = raw.decode("utf-8", errors="replace")
        parsed: Any = None
        if ctype == "application/json" and not truncated:
            try:
                parsed = json.loads(text)
            except ValueError:
                parsed = None
        return ToolResult(
            public={
                "status": status,
                "content_type": ctype,
                "sha256": hashlib.sha256(raw).hexdigest(),  # context provenance digest
                "truncated": truncated,
                "body": parsed if parsed is not None else text,
            }
        )


class SmtpSendEmailAdapter:
    def __init__(
        self,
        *,
        host: str,
        port: int,
        starttls: bool,
        username: str | None,
        password: Callable[[], str | None],
        sender: str,
        timeout: float = 5.0,
    ) -> None:
        self._host, self._port, self._tls = host, port, starttls
        self._user, self._password, self._from, self._timeout = username, password, sender, timeout

    def __repr__(self) -> str:  # never expose the relay credentials
        return f"SmtpSendEmailAdapter(host={self._host!r}, port={self._port})"

    def execute(self, args: BaseModel, ctx: ExecutionContext) -> ToolResult:
        assert isinstance(args, SendEmailSmtpArgs)  # noqa: S101
        msg = EmailMessage()
        msg["From"] = self._from
        msg["To"] = ", ".join(args.to)
        msg["Subject"] = args.subject
        msg["Message-ID"] = f"<{ctx.action_id}@agw>"  # one action, one message id
        msg.set_content(args.body)
        with smtplib.SMTP(self._host, self._port, timeout=self._timeout) as smtp:
            if self._tls:
                smtp.starttls()
            if self._user:
                smtp.login(self._user, self._password() or "")
            refused = smtp.send_message(msg)
        return ToolResult(public={"accepted": len(args.to) - len(refused)})


def external_tool_specs(settings: Any) -> list[ToolSpec]:
    """Registered only when configured; otherwise the tools do not exist (DENY: unknown)."""
    specs: list[ToolSpec] = []
    allow = frozenset(h.lower() for h in settings.http_allowlist)
    if allow:
        plain = frozenset(h.lower() for h in settings.http_allow_plain)
        specs.append(
            ToolSpec(
                PUBLIC_API_GET,
                _public_api_args(allow, plain),
                PublicApiGetAdapter(allow, plain, settings.http_max_response_bytes),
                FieldClasses(
                    args={"url": "internal"},
                    results={
                        "status": "public",
                        "content_type": "public",
                        "sha256": "public",
                        "truncated": "public",
                        "body": "internal",
                    },
                ),
            )
        )
    if settings.smtp_host:
        secret = settings.smtp_password
        specs.append(
            ToolSpec(
                SEND_EMAIL_SMTP,
                _smtp_args(frozenset(d.lower() for d in settings.smtp_allowed_domains)),
                SmtpSendEmailAdapter(
                    host=settings.smtp_host,
                    port=settings.smtp_port,
                    starttls=settings.smtp_starttls,
                    username=settings.smtp_username,
                    password=lambda: secret.get_secret_value() if secret is not None else None,
                    sender=settings.smtp_from,
                ),
                FieldClasses(
                    args={"to": "confidential", "subject": "confidential", "body": "confidential"},
                    results={"accepted": "public"},
                ),
            )
        )
    return specs
