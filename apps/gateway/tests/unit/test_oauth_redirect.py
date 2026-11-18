"""Redirect URI matching for MCP OAuth (RFC 8252 §7.3 + MCP authorization).

Native clients (Claude Code) register a loopback redirect WITHOUT a port and listen on a random
port at runtime: e.g. CIMD https://claude.ai/oauth/claude-code-client-metadata lists
"http://localhost/callback" and the request uses "http://localhost:55931/callback". For loopback
hosts ONLY the port may differ; everything else is an exact match.
"""

from __future__ import annotations

import pytest

from agw_gateway.mcp_remote.oauth import redirect_matches

pytestmark = pytest.mark.unit
REG = ["http://localhost/callback", "http://127.0.0.1/callback"]


@pytest.mark.parametrize(
    "requested",
    [
        "http://localhost:55931/callback",
        "http://127.0.0.1:33418/callback",
        "http://localhost/callback",
    ],
)
def test_loopback_any_port(requested: str) -> None:
    assert redirect_matches(requested, REG)


def test_ipv6_loopback_any_port() -> None:
    assert redirect_matches("http://[::1]:5000/cb", ["http://[::1]/cb"])


@pytest.mark.parametrize(
    "requested",
    [
        "http://localhost:55931/other",  # path differs
        "http://localhost:55931/callback?x=1",  # query differs
        "https://localhost:55931/callback",  # scheme differs
        "http://evil.example:55931/callback",  # not loopback
        "http://localhost.evil.example/callback",
        "http://127.0.0.2:1/callback",  # a different loopback address than registered
        "http://localhost:55931/callback#frag",
        "http://user@localhost:55931/callback",
    ],
)
def test_everything_else_is_exact(requested: str) -> None:
    assert not redirect_matches(requested, REG)


def test_non_loopback_requires_exact_port() -> None:
    reg = ["https://app.example/cb"]
    assert redirect_matches("https://app.example/cb", reg)
    assert not redirect_matches("https://app.example:8443/cb", reg)
