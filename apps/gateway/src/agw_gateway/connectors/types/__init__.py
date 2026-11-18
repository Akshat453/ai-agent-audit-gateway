"""The built-in connector type catalog (C2 §2)."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, ClassVar, Final

from pydantic import BaseModel

from agw_gateway.connectors.manifest import ConnectorManifest
from agw_gateway.connectors.types.agents import AGENT_TYPES
from agw_gateway.connectors.types.base import ConnectorType, Health, StrictModel
from agw_gateway.connectors.types.github import GithubConnector
from agw_gateway.connectors.types.http_api import HttpApiConnector
from agw_gateway.connectors.types.mcp_upstream import McpUpstreamConnector
from agw_gateway.connectors.types.notify import EmailConnector, SlackConnector


class AnchoringConfig(StrictModel):
    """Read-only view of the Phase 6 chain settings (no behaviour change: the anchor worker
    still reads its settings; this type only shows them under Integrations)."""

    chain_id: int | None = None
    contract: str | None = None
    rpc_host: str | None = None  # host only: an RPC URL may carry an API key
    finality: str | None = None
    explorer: str | None = None


class AnchoringConnector(ConnectorType):
    manifest: ClassVar[ConnectorManifest] = ConnectorManifest(
        id="anchoring",
        name="Blockchain anchoring",
        category="anchoring",
        auth="none",
        description="Epoch roots anchored on-chain (Phase 6). Configured by the operator.",
        has_health_check=False,
    )
    config_model: ClassVar[type[BaseModel]] = AnchoringConfig

    def health(self, config: BaseModel, creds: BaseModel, http: Any) -> Health:
        return Health(True, "OK", {"note": "monitored by the anchor worker and the monitor"})

    def setup(self, config: BaseModel, gateway_url: str) -> Mapping[str, Any]:
        return {"read_only": True, "configured_by": "operator settings (AGW_ANCHOR_*)"}


CATALOG: Final[dict[str, ConnectorType]] = {
    t.manifest.id: t
    for t in (
        GithubConnector(),
        SlackConnector(),
        EmailConnector(),
        HttpApiConnector(),
        McpUpstreamConnector(),
        AnchoringConnector(),
        *(cls() for cls in AGENT_TYPES),
    )
}
CREATABLE: Final = frozenset(k for k in CATALOG if k != "anchoring")

__all__ = ["CATALOG", "CREATABLE", "ConnectorType"]
