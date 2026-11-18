"""The GitHub App manifest: polling mode must not ask GitHub for a webhook.

GitHub rejects a manifest whose hook URL is not reachable from the public Internet
("Hook url is not supported because it isn't reachable over the public Internet (localhost)").
"""

from __future__ import annotations

import pytest

from agw_gateway.connectors.types.github import DEFAULT_EVENTS, GithubConfig, manifest_form

pytestmark = pytest.mark.unit
GW, UI, CID = (
    "http://localhost:8088",
    "http://localhost:3000",
    "00000000-0000-0000-0000-000000000001",
)


def _manifest(mode: str) -> dict:
    cfg = GithubConfig(
        owner_type="user", owner="Akshat453", repos=("Akshat453/MintRail",), mode=mode
    )
    return manifest_form(cfg, GW, UI, CID, "AgentGuard GitHub")["manifest"]


def test_polling_mode_has_no_webhook() -> None:
    m = _manifest("polling")
    assert "hook_attributes" not in m and "default_events" not in m
    assert m["redirect_url"] == f"{GW}/v1/connectors/github/manifest-callback"
    assert m["default_permissions"]["checks"] == "write"


def test_webhook_mode_subscribes_the_events() -> None:
    m = _manifest("webhook")
    assert m["hook_attributes"] == {"url": f"{GW}/v1/webhooks/github/{CID}"}
    assert m["default_events"] == list(DEFAULT_EVENTS)
