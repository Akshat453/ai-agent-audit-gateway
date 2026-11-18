"""C2: SSRF protection of the HTTP / MCP-upstream connectors (ADR-0035 §6)."""

from __future__ import annotations

from typing import Any

import httpx
import pytest

from agw_gateway.connectors.ssrf import SafeHttp, SsrfBlocked, check_url, ip_is_public
from agw_gateway.connectors.types.http_api import HttpApiConfig

pytestmark = pytest.mark.unit
ALLOW = ["api.example.com"]


def resolver(*ips: str) -> Any:
    return lambda host, port: list(ips)


@pytest.mark.parametrize(
    "ip",
    [
        "10.0.0.1",
        "172.16.5.4",
        "192.168.1.1",
        "127.0.0.1",
        "169.254.169.254",
        "100.64.0.1",
        "0.0.0.0",
        "224.0.0.1",
        "::1",
        "fe80::1",
        "fc00::1",
        "::ffff:127.0.0.1",
        "::ffff:10.0.0.1",
        "64:ff9b::7f00:1",
        "2002:7f00:1::",
        "240.0.0.1",
        "not-an-ip",
    ],
)
def test_non_public_addresses(ip: str) -> None:
    assert ip_is_public(ip) is False


@pytest.mark.parametrize("ip", ["93.184.216.34", "1.1.1.1", "2606:4700:4700::1111"])
def test_public_addresses(ip: str) -> None:
    assert ip_is_public(ip) is True


@pytest.mark.parametrize(
    ("url", "code"),
    [
        ("http://api.example.com/x", "SCHEME_NOT_HTTPS"),
        ("ftp://api.example.com/x", "SCHEME_NOT_HTTPS"),
        ("https://evil.example.com/x", "HOST_NOT_ALLOWLISTED"),
        ("https://api.example.com.evil.com/x", "HOST_NOT_ALLOWLISTED"),
        ("https://user:pw@api.example.com/x", "USERINFO_NOT_ALLOWED"),
        ("https://api.example.com:8443/x", "HOST_NOT_ALLOWLISTED"),
        ("https://127.0.0.1/x", "HOST_NOT_ALLOWLISTED"),
    ],
)
def test_url_checks(url: str, code: str) -> None:
    with pytest.raises(SsrfBlocked) as exc:
        check_url(url, ALLOW)
    assert exc.value.code == code


def _transport(
    seen: list[httpx.Request], status: int = 200, headers: dict[str, str] | None = None
) -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(status, headers=headers or {}, json={"ok": True})

    return httpx.MockTransport(handler)


def test_private_resolution_is_blocked_before_any_connection() -> None:
    seen: list[httpx.Request] = []
    http = SafeHttp(resolver=resolver("10.1.2.3"), transport=_transport(seen))
    with pytest.raises(SsrfBlocked) as exc:
        http.request("GET", "https://api.example.com/x", allow_hosts=ALLOW)
    assert exc.value.code == "ADDRESS_NOT_PUBLIC" and seen == []


def test_dns_rebinding_any_private_answer_blocks() -> None:
    seen: list[httpx.Request] = []
    http = SafeHttp(resolver=resolver("93.184.216.34", "127.0.0.1"), transport=_transport(seen))
    with pytest.raises(SsrfBlocked):
        http.request("GET", "https://api.example.com/x", allow_hosts=ALLOW)
    assert seen == []


def test_connection_is_pinned_to_the_validated_ip() -> None:
    """A second (rebound) DNS answer is never consulted: the request goes to the IP that was
    checked, with Host and SNI set to the name."""
    answers = iter([["93.184.216.34"], ["127.0.0.1"]])
    seen: list[httpx.Request] = []
    http = SafeHttp(resolver=lambda h, p: next(answers), transport=_transport(seen))
    r = http.request("GET", "https://api.example.com/v1/x?q=1", allow_hosts=ALLOW)
    assert r.status_code == 200
    req = seen[0]
    assert req.url.host == "93.184.216.34" and req.url.path == "/v1/x"
    assert req.headers["host"] == "api.example.com"
    assert req.extensions["sni_hostname"] == "api.example.com"


def test_redirects_are_not_followed() -> None:
    seen: list[httpx.Request] = []
    http = SafeHttp(
        resolver=resolver("93.184.216.34"),
        transport=_transport(seen, 302, {"location": "http://169.254.169.254/"}),
    )
    with pytest.raises(SsrfBlocked) as exc:
        http.request("GET", "https://api.example.com/x", allow_hosts=ALLOW)
    assert exc.value.code == "REDIRECT_NOT_FOLLOWED" and len(seen) == 1


def test_http_api_config_rejects_unsafe_settings() -> None:
    base = {"allowed_hosts": ["api.example.com"], "actions": []}
    with pytest.raises(Exception):
        HttpApiConfig.model_validate({**base, "base_url": "http://api.example.com"})
    with pytest.raises(Exception):
        HttpApiConfig.model_validate({**base, "base_url": "https://other.example.com"})
    with pytest.raises(Exception):
        HttpApiConfig.model_validate(
            {"base_url": "https://api.example.com", "allowed_hosts": ["*.example.com"]}
        )
    ok = HttpApiConfig.model_validate({**base, "base_url": "https://api.example.com/v1"})
    assert ok.allowed_hosts == ("api.example.com",)


@pytest.mark.parametrize("encoding", ["gzip", "deflate"])
def test_compressed_responses_are_decoded_once(encoding: str) -> None:
    """Real APIs (api.github.com) answer gzip. The body is decompressed while reading (the
    size limit applies to the decoded bytes); the returned response must not decode it again."""
    import gzip
    import zlib

    raw = b'{"ok": true}'
    packed = gzip.compress(raw) if encoding == "gzip" else zlib.compress(raw)

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200, headers={"content-encoding": encoding, "content-type": "application/json"},
            content=packed,
        )  # fmt: skip

    http = SafeHttp(resolver=resolver("93.184.216.34"), transport=httpx.MockTransport(handler))
    r = http.request("GET", "https://api.example.com/x", allow_hosts=ALLOW)
    assert r.json() == {"ok": True}
    assert "content-encoding" not in r.headers
