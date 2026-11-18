"""Slack and Email connector types (C2 §2c, §2d): notification channels plus one tool action
each (``post_message``, ``send_email``), UNCLASSIFIED until an admin classifies them."""

from __future__ import annotations

import re
import smtplib
import ssl
from collections.abc import Mapping
from email.message import EmailMessage
from typing import Annotated, Any, ClassVar, Literal

from pydantic import BaseModel, Field, SecretStr, field_validator, model_validator

from agw_gateway.connectors.manifest import ActionManifest, ConnectorManifest
from agw_gateway.connectors.ssrf import SafeHttp, SsrfBlocked
from agw_gateway.connectors.types.base import (
    ActionFailed,
    ConnectorType,
    ExecContext,
    Health,
    StrictModel,
)

SLACK_HOSTS = ("hooks.slack.com", "slack.com")
_WEBHOOK_RE = re.compile(r"^https://hooks\.slack\.com/services/[A-Za-z0-9/_-]{10,200}$")


# --------------------------------------------------------------------------- Slack
class SlackConfig(StrictModel):
    default_channel: Annotated[str, Field(pattern=r"^[#@]?[A-Za-z0-9._-]{1,80}$")] | None = None
    notify_on: tuple[
        Literal["approval_required", "security_violation", "connector_change"], ...
    ] = ("approval_required",)


class SlackCredentials(StrictModel):
    # Both secret: an incoming-webhook URL is a bearer credential for the channel.
    webhook_url: SecretStr | None = None
    bot_token: SecretStr | None = None

    @field_validator("webhook_url")
    @classmethod
    def _webhook(cls, v: SecretStr | None) -> SecretStr | None:
        if v is not None and not _WEBHOOK_RE.fullmatch(v.get_secret_value()):
            raise ValueError("webhook_url must be https://hooks.slack.com/services/...")
        return v

    @field_validator("bot_token")
    @classmethod
    def _token(cls, v: SecretStr | None) -> SecretStr | None:
        if v is not None and not v.get_secret_value().startswith("xoxb-"):
            raise ValueError("bot_token must be a bot token (xoxb-...)")
        return v

    @model_validator(mode="after")
    def _one(self) -> SlackCredentials:
        if self.webhook_url is None and self.bot_token is None:
            raise ValueError("a webhook_url or a bot_token is required")
        return self


POST_MESSAGE = ActionManifest(
    name="post_message",
    description="Post a message to a Slack channel (chat.postMessage, bot token).",
    input_schema={
        "type": "object",
        "additionalProperties": False,
        "required": ["channel", "text"],
        "properties": {
            "channel": {"type": "string", "pattern": r"^[#@]?[A-Za-z0-9._-]{1,80}$"},
            "text": {"type": "string", "maxLength": 4000},
        },
    },
    side_effect="write",
    suggested_risk="MEDIUM",
)


class SlackConnector(ConnectorType):
    manifest: ClassVar[ConnectorManifest] = ConnectorManifest(
        id="slack",
        name="Slack",
        category="notification",
        auth="webhook",
        description="Approval and security notifications (incoming webhook); optional bot "
        "token for the post_message action.",
        actions=(POST_MESSAGE,),
    )
    config_model: ClassVar[type[BaseModel]] = SlackConfig
    credential_model: ClassVar[type[BaseModel]] = SlackCredentials

    def health(self, config: BaseModel, creds: BaseModel, http: SafeHttp) -> Health:
        assert isinstance(creds, SlackCredentials)  # noqa: S101
        try:
            if creds.bot_token is not None:
                r = http.request(
                    "POST",
                    "https://slack.com/api/auth.test",
                    allow_hosts=SLACK_HOSTS,
                    headers={"Authorization": f"Bearer {creds.bot_token.get_secret_value()}"},
                )
                body = r.json() if r.status_code == 200 else {}
                if not body.get("ok"):
                    return Health(
                        False, "AUTH_FAILED", {"slack_error": str(body.get("error", ""))[:64]}
                    )
                return Health(True, "OK", {"team": str(body.get("team", ""))[:80]})
            assert creds.webhook_url is not None  # noqa: S101
            r = http.request(
                "POST",
                creds.webhook_url.get_secret_value(),
                allow_hosts=SLACK_HOSTS,
                json={"text": "AgentGuard: connection test"},
            )
            if r.status_code != 200:
                return Health(False, "WEBHOOK_REJECTED", {"status": r.status_code})
            return Health(True, "OK", {})
        except SsrfBlocked as exc:
            return Health(False, f"SSRF_{exc.code}", {})
        except Exception as exc:
            return Health(False, "UNREACHABLE", {"error": type(exc).__name__})

    def result_classes(self, action: str, config: Mapping[str, Any]) -> dict[str, str]:
        return {"ok": "internal", "ts": "internal"}

    def notify(self, creds: BaseModel, http: SafeHttp, text: str) -> bool:
        assert isinstance(creds, SlackCredentials)  # noqa: S101
        if creds.webhook_url is None:
            return False
        r = http.request(
            "POST",
            creds.webhook_url.get_secret_value(),
            allow_hosts=SLACK_HOSTS,
            json={"text": text[:3000]},
        )
        return r.status_code == 200

    def execute(self, ctx: ExecContext, args: Mapping[str, Any]) -> Mapping[str, Any]:
        creds = ctx.credentials
        assert isinstance(creds, SlackCredentials)  # noqa: S101
        if ctx.action.name != "post_message" or creds.bot_token is None:
            raise ActionFailed("BOT_TOKEN_REQUIRED")
        r = ctx.http.request(
            "POST",
            "https://slack.com/api/chat.postMessage",
            allow_hosts=SLACK_HOSTS,
            headers={"Authorization": f"Bearer {creds.bot_token.get_secret_value()}"},
            json={"channel": args["channel"], "text": args["text"]},
        )
        body = r.json() if r.status_code == 200 else {}
        if not body.get("ok"):
            raise ActionFailed("SLACK_ERROR")
        return {"ok": True, "ts": str(body.get("ts", ""))}


# --------------------------------------------------------------------------- Email
class EmailConfig(StrictModel):
    mode: Literal["smtp", "http"]
    from_address: Annotated[str, Field(pattern=r"^[^@\s<>]+@[^@\s<>]+\.[A-Za-z]{2,}$")]
    allowed_domains: tuple[str, ...] = ()  # recipients must be in these domains (empty = any)
    smtp_host: Annotated[str, Field(pattern=r"^[A-Za-z0-9.-]{1,253}$")] | None = None
    smtp_port: Annotated[int, Field(ge=1, le=65535)] = 587
    smtp_username: Annotated[str, Field(max_length=256)] | None = None
    http_url: Annotated[str, Field(pattern=r"^https://[^\s]+$")] | None = None

    @model_validator(mode="after")
    def _mode(self) -> EmailConfig:
        if self.mode == "smtp" and not self.smtp_host:
            raise ValueError("smtp mode needs smtp_host")
        if self.mode == "http" and not self.http_url:
            raise ValueError("http mode needs http_url")
        return self


class EmailCredentials(StrictModel):
    smtp_password: SecretStr | None = None
    api_key: SecretStr | None = None


SEND_EMAIL = ActionManifest(
    name="send_email",
    description="Send an email through the configured SMTP relay or HTTP provider.",
    input_schema={
        "type": "object",
        "additionalProperties": False,
        "required": ["to", "subject", "body"],
        "properties": {
            "to": {"type": "array", "items": {"type": "string"}, "maxItems": 20},
            "subject": {"type": "string", "maxLength": 200, "pattern": r"^[^\r\n]*$"},
            "body": {"type": "string", "maxLength": 20000},
        },
    },
    side_effect="write",
    suggested_risk="HIGH",
)
_ADDR = re.compile(r"^[^@\s<>,;]+@([^@\s<>,;]+\.[A-Za-z]{2,})$")


class EmailConnector(ConnectorType):
    manifest: ClassVar[ConnectorManifest] = ConnectorManifest(
        id="email",
        name="Email",
        category="notification",
        auth="smtp",
        description="Notifications and the send_email action (SMTP or an HTTP provider).",
        actions=(SEND_EMAIL,),
    )
    config_model: ClassVar[type[BaseModel]] = EmailConfig
    credential_model: ClassVar[type[BaseModel]] = EmailCredentials

    def result_classes(self, action: str, config: Mapping[str, Any]) -> dict[str, str]:
        return {"sent": "internal"}

    def health(self, config: BaseModel, creds: BaseModel, http: SafeHttp) -> Health:
        assert isinstance(config, EmailConfig) and isinstance(creds, EmailCredentials)  # noqa: S101
        if config.mode == "http":
            return Health(True, "OK", {"note": "HTTP provider: verified on first send"})
        try:
            with smtplib.SMTP(config.smtp_host or "", config.smtp_port, timeout=10) as s:
                s.starttls(context=ssl.create_default_context())
                if config.smtp_username and creds.smtp_password is not None:
                    s.login(config.smtp_username, creds.smtp_password.get_secret_value())
                s.noop()
            return Health(True, "OK", {})
        except smtplib.SMTPAuthenticationError:
            return Health(False, "AUTH_FAILED", {})
        except Exception as exc:
            return Health(False, "UNREACHABLE", {"error": type(exc).__name__})

    def execute(self, ctx: ExecContext, args: Mapping[str, Any]) -> Mapping[str, Any]:
        config, creds = ctx.config, ctx.credentials
        assert isinstance(config, EmailConfig) and isinstance(creds, EmailCredentials)  # noqa: S101
        to = list(args["to"])
        for addr in to:
            m = _ADDR.fullmatch(addr)
            if m is None:
                raise ActionFailed("RECIPIENT_INVALID")
            if config.allowed_domains and m.group(1).lower() not in config.allowed_domains:
                raise ActionFailed("RECIPIENT_DOMAIN_NOT_ALLOWED")
        if config.mode == "http":
            assert config.http_url is not None  # noqa: S101
            host = config.http_url.split("/")[2]
            headers = {}
            if creds.api_key is not None:
                headers["Authorization"] = f"Bearer {creds.api_key.get_secret_value()}"
            r = ctx.http.request(
                "POST",
                config.http_url,
                allow_hosts=[host],
                headers=headers,
                json={
                    "from": config.from_address,
                    "to": to,
                    "subject": args["subject"],
                    "text": args["body"],
                },
            )
            if not 200 <= r.status_code < 300:
                raise ActionFailed("PROVIDER_REJECTED")
            return {"sent": len(to)}
        msg = EmailMessage()
        msg["From"], msg["To"], msg["Subject"] = config.from_address, ", ".join(to), args["subject"]
        msg.set_content(args["body"])
        with smtplib.SMTP(config.smtp_host or "", config.smtp_port, timeout=15) as s:
            s.starttls(context=ssl.create_default_context())
            if config.smtp_username and creds.smtp_password is not None:
                s.login(config.smtp_username, creds.smtp_password.get_secret_value())
            s.send_message(msg)
        return {"sent": len(to)}
