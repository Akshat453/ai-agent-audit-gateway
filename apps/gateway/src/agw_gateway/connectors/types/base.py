"""The connector type contract (C2, ADR-0035 §2).

A type is plain code: a manifest, a Pydantic model for its NON-secret config, a Pydantic model
for its secret credentials (write-only: stored sealed, never returned), a health check / test
connection, an executor for its actions and, for dynamic types, action discovery.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, ClassVar

from pydantic import BaseModel, ConfigDict

from agw_gateway.connectors.manifest import ActionManifest, ConnectorManifest
from agw_gateway.connectors.ssrf import SafeHttp


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class NoConfig(StrictModel):
    pass


class NoCredentials(StrictModel):
    pass


@dataclass(frozen=True)
class Health:
    ok: bool
    code: str  # stable code, e.g. "OK", "AUTH_FAILED", "SSRF_ADDRESS_NOT_PUBLIC"
    detail: Mapping[str, Any] = field(default_factory=dict)  # never secrets

    def as_dict(self) -> dict[str, Any]:
        return {"ok": self.ok, "code": self.code, **dict(self.detail)}


@dataclass(frozen=True)
class ExecContext:
    """What an action needs at execution time (credentials decrypted just for this call)."""

    config: BaseModel
    credentials: BaseModel
    http: SafeHttp
    action: ActionManifest
    upstream_name: str | None = None
    # C3: who/what this call is for (set by the adapter at dispatch; None while assessing).
    tenant: str | None = None
    connector_id: Any = None
    action_id: Any = None
    run_id: Any = None
    agent_id: Any = None
    engine: Any = None


class ActionFailed(Exception):
    """An action could not be completed; ``code`` is a stable, non-sensitive reason."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class ConnectorType:
    manifest: ClassVar[ConnectorManifest]
    config_model: ClassVar[type[BaseModel]] = NoConfig
    credential_model: ClassVar[type[BaseModel]] = NoCredentials
    # Fields of config shown in the UI as secret-looking but stored in config? never: secrets
    # live only in credential_model.

    def health(self, config: BaseModel, creds: BaseModel, http: SafeHttp) -> Health:
        return Health(True, "OK", {"note": "no remote health check for this type"})

    def discover(
        self, config: BaseModel, creds: BaseModel, http: SafeHttp
    ) -> list[tuple[ActionManifest, str | None]]:
        """Dynamic types: (action, upstream name). Static types: the manifest's actions."""
        return [(a, None) for a in self.manifest.actions]

    def execute(self, ctx: ExecContext, args: Mapping[str, Any]) -> Mapping[str, Any]:
        raise ActionFailed("NOT_IMPLEMENTED")

    def assesses(self, action: str) -> bool:
        """C3: does this action inspect its content before the decision (``assess``)?"""
        return False

    def assess(self, ctx: ExecContext, args: Mapping[str, Any]) -> Any:
        """C3: an :class:`~agw_gateway.connectors.constraint.Assessment` (risk floor, deny,
        rule ids, digests) computed from the call's content, BEFORE the policy decision."""
        return None

    def result_classes(self, action: str, config: Mapping[str, Any]) -> dict[str, str]:
        """Phase 7 classes of an action's result fields (unlisted = confidential: kept only in
        the encrypted evidence payload, never returned to the agent)."""
        return {}

    def setup(self, config: BaseModel, gateway_url: str) -> Mapping[str, Any]:
        """Non-secret setup information shown in the UI (snippets, tiers, links)."""
        return {}
