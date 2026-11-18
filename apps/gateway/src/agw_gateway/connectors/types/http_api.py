"""Generic HTTP API connector (C2 §2e). Admin-defined actions (method + path template + input
schema + response field classification) against a base URL with an EXACT host allowlist,
through :class:`SafeHttp` (https only, no redirects, public IPs only, DNS pinned)."""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Annotated, Any, ClassVar, Literal
from urllib.parse import quote, urlsplit

from pydantic import BaseModel, Field, SecretStr, field_validator, model_validator

from agw_gateway.connectors.manifest import ActionManifest, ConnectorManifest, Risk, SideEffect
from agw_gateway.connectors.ssrf import SafeHttp, SsrfBlocked, check_url
from agw_gateway.connectors.types.base import (
    ActionFailed,
    ConnectorType,
    ExecContext,
    Health,
    StrictModel,
)

_PATH_PARAM = re.compile(r"\{([a-z][a-z0-9_]{0,63})\}")
FieldClass = Literal["public", "internal", "confidential", "secret"]


class HttpActionDef(StrictModel):
    name: Annotated[str, Field(pattern=r"^[a-z][a-z0-9_]{0,35}$")]
    description: Annotated[str, Field(max_length=1000)] = ""
    method: Literal["GET", "POST", "PUT", "PATCH", "DELETE"]
    path_template: Annotated[str, Field(pattern=r"^/[A-Za-z0-9/_.{}-]*$", max_length=512)]
    input_schema: dict[str, Any]
    side_effect: SideEffect
    suggested_risk: Risk = "HIGH"
    # Only listed response fields are returned to the agent, by class; secret/confidential
    # fields are never returned (they are dropped).
    response_fields: dict[str, FieldClass] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _params(self) -> HttpActionDef:
        ActionManifest(
            name=self.name,
            input_schema=self.input_schema,
            side_effect=self.side_effect,
            suggested_risk=self.suggested_risk,
        )
        props = set(self.input_schema.get("properties", {}))
        missing = set(_PATH_PARAM.findall(self.path_template)) - props
        if missing:
            raise ValueError("path template names unknown inputs")
        if self.method == "GET" and self.side_effect != "read":
            raise ValueError("GET actions must be side_effect=read")
        return self


class HttpApiConfig(StrictModel):
    base_url: Annotated[str, Field(max_length=2048)]
    allowed_hosts: tuple[str, ...]
    auth_header_name: Annotated[str, Field(pattern=r"^[A-Za-z0-9-]{1,64}$")] = "Authorization"
    health_path: Annotated[str, Field(pattern=r"^/[A-Za-z0-9/_.-]*$")] | None = None
    actions: tuple[HttpActionDef, ...] = ()

    @field_validator("allowed_hosts")
    @classmethod
    def _hosts(cls, v: tuple[str, ...]) -> tuple[str, ...]:
        if not v:
            raise ValueError("allowed_hosts must list at least one exact host")
        for h in v:
            if not re.fullmatch(r"^[a-z0-9.-]{1,253}(:[0-9]{1,5})?$", h) or "*" in h:
                raise ValueError("allowed_hosts are exact lowercase hostnames (no wildcards)")
        return v

    @model_validator(mode="after")
    def _base(self) -> HttpApiConfig:
        try:
            check_url(self.base_url, self.allowed_hosts)  # https + allowlisted, before any use
        except SsrfBlocked as exc:
            raise ValueError(exc.code) from None
        if urlsplit(self.base_url).query or urlsplit(self.base_url).fragment:
            raise ValueError("base_url must not have a query or fragment")
        names = [a.name for a in self.actions]
        if len(names) != len(set(names)):
            raise ValueError("duplicate action names")
        return self


class HttpApiCredentials(StrictModel):
    auth_header_value: SecretStr | None = None


class HttpApiConnector(ConnectorType):
    manifest: ClassVar[ConnectorManifest] = ConnectorManifest(
        id="http_api",
        name="Generic HTTP API",
        category="tool",
        auth="api_key",
        description="Admin-defined actions against an allowlisted https API.",
        dynamic_actions=True,
    )
    config_model: ClassVar[type[BaseModel]] = HttpApiConfig
    credential_model: ClassVar[type[BaseModel]] = HttpApiCredentials

    def discover(
        self, config: BaseModel, creds: BaseModel, http: SafeHttp
    ) -> list[tuple[ActionManifest, str | None]]:
        assert isinstance(config, HttpApiConfig)  # noqa: S101
        return [
            (
                ActionManifest(
                    name=a.name,
                    description=a.description,
                    input_schema=a.input_schema,
                    side_effect=a.side_effect,
                    suggested_risk=a.suggested_risk,
                ),
                None,
            )
            for a in config.actions
        ]

    def result_classes(self, action: str, config: Mapping[str, Any]) -> dict[str, str]:
        adef = next((a for a in config.get("actions", []) if a.get("name") == action), None)
        fields = (adef or {}).get("response_fields", {})
        return {
            "status": "internal",
            **{k: v for k, v in fields.items() if v in ("public", "internal")},
        }

    def _headers(self, config: HttpApiConfig, creds: BaseModel) -> dict[str, str]:
        assert isinstance(creds, HttpApiCredentials)  # noqa: S101
        if creds.auth_header_value is None:
            return {}
        return {config.auth_header_name: creds.auth_header_value.get_secret_value()}

    def health(self, config: BaseModel, creds: BaseModel, http: SafeHttp) -> Health:
        assert isinstance(config, HttpApiConfig)  # noqa: S101
        if config.health_path is None:
            return Health(True, "OK", {"note": "no health_path configured"})
        try:
            r = http.request(
                "GET",
                config.base_url.rstrip("/") + config.health_path,
                allow_hosts=config.allowed_hosts,
                headers=self._headers(config, creds),
            )
        except SsrfBlocked as exc:
            return Health(False, f"SSRF_{exc.code}", {})
        except Exception as exc:
            return Health(False, "UNREACHABLE", {"error": type(exc).__name__})
        return Health(
            r.status_code < 400,
            "OK" if r.status_code < 400 else "HTTP_ERROR",
            {"status": r.status_code},
        )

    def execute(self, ctx: ExecContext, args: Mapping[str, Any]) -> Mapping[str, Any]:
        config = ctx.config
        assert isinstance(config, HttpApiConfig)  # noqa: S101
        adef = next((a for a in config.actions if a.name == ctx.action.name), None)
        if adef is None:
            raise ActionFailed("ACTION_NOT_DEFINED")
        used = set(_PATH_PARAM.findall(adef.path_template))
        path = _PATH_PARAM.sub(lambda m: quote(str(args[m.group(1)]), safe=""), adef.path_template)
        rest = {k: v for k, v in args.items() if k not in used and v is not None}
        url = config.base_url.rstrip("/") + path
        try:
            if adef.method == "GET":
                r = ctx.http.request(
                    "GET",
                    url,
                    allow_hosts=config.allowed_hosts,
                    headers=self._headers(config, ctx.credentials),
                    params={k: str(v) for k, v in rest.items()},
                )
            else:
                r = ctx.http.request(
                    adef.method,
                    url,
                    allow_hosts=config.allowed_hosts,
                    headers=self._headers(config, ctx.credentials),
                    json=rest,
                )
        except SsrfBlocked as exc:
            raise ActionFailed(f"SSRF_{exc.code}") from None
        if r.status_code >= 400:
            raise ActionFailed(f"HTTP_{r.status_code}")
        try:
            body = r.json()
        except ValueError:
            body = {}
        out: dict[str, Any] = {"status": r.status_code}
        if isinstance(body, dict):
            for name, cls in adef.response_fields.items():
                if cls in ("public", "internal") and name in body:
                    out[name] = body[name]
        return out
