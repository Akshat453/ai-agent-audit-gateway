"""SSRF-safe outbound HTTP for connectors (C2, ADR-0035 §6).

Every outbound connector request goes through :class:`SafeHttp`:

1. **https only**; no userinfo; port 443 unless the allowlist entry names another port.
2. The host must be in the connector's **exact host allowlist** (no wildcards, no suffix match).
3. The host is resolved ONCE; **every** returned address must be globally routable. Private,
   loopback, link-local (incl. 169.254.169.254 metadata), CGNAT, multicast, reserved,
   unspecified and IPv4-mapped/6to4/NAT64 forms of those are refused.
4. The connection goes to the **already validated IP** (the URL host is replaced by the IP;
   ``Host`` and TLS SNI/certificate checks use the original name). A DNS answer that changes
   between check and connect (DNS rebinding) therefore cannot redirect the request.
5. **No redirects** (a 3xx is an error), no proxies from the environment, bounded timeout and
   response size.
"""

from __future__ import annotations

import ipaddress
import socket
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from typing import Any, Final
from urllib.parse import urlsplit, urlunsplit

import httpx

MAX_RESPONSE_BYTES: Final = 2 * 1024 * 1024
Resolver = Callable[[str, int], list[str]]


class SsrfBlocked(Exception):
    """The request was refused before any connection (code names the reason, never the URL)."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def system_resolver(host: str, port: int) -> list[str]:
    infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    return sorted({str(info[4][0]) for info in infos})


def ip_is_public(raw: str) -> bool:
    try:
        ip = ipaddress.ip_address(raw.split("%", 1)[0])
    except ValueError:
        return False
    if isinstance(ip, ipaddress.IPv6Address):
        for embedded in (ip.ipv4_mapped, ip.sixtofour, _nat64(ip)):
            if embedded is not None:
                return ip_is_public(str(embedded))
        if ip.teredo is not None:
            return False
    return bool(
        ip.is_global
        and not ip.is_private
        and not ip.is_loopback
        and not ip.is_link_local
        and not ip.is_multicast
        and not ip.is_reserved
        and not ip.is_unspecified
    )


def _nat64(ip: ipaddress.IPv6Address) -> ipaddress.IPv4Address | None:
    if ip in ipaddress.ip_network("64:ff9b::/96"):
        return ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)
    return None


@dataclass(frozen=True)
class Target:
    host: str
    port: int
    url: str  # the original URL


def check_url(url: str, allow_hosts: Iterable[str]) -> Target:
    parts = urlsplit(url)
    if parts.scheme != "https":
        raise SsrfBlocked("SCHEME_NOT_HTTPS")
    if parts.username or parts.password:
        raise SsrfBlocked("USERINFO_NOT_ALLOWED")
    host = (parts.hostname or "").lower().rstrip(".")
    if not host:
        raise SsrfBlocked("HOST_MISSING")
    port = parts.port or 443
    allowed = {h.lower().rstrip(".") for h in allow_hosts}
    if (host if port == 443 else f"{host}:{port}") not in allowed:
        raise SsrfBlocked("HOST_NOT_ALLOWLISTED")
    return Target(host=host, port=port, url=url)


class SafeHttp:
    def __init__(
        self,
        *,
        resolver: Resolver = system_resolver,
        transport: httpx.BaseTransport | None = None,
        timeout: float = 10.0,
    ) -> None:
        self._resolve = resolver
        self._transport = transport
        self._timeout = timeout

    def pinned_ip(self, target: Target) -> str:
        try:
            ips = self._resolve(target.host, target.port)
        except (OSError, UnicodeError):
            raise SsrfBlocked("DNS_FAILED") from None
        if not ips:
            raise SsrfBlocked("DNS_FAILED")
        if not all(ip_is_public(ip) for ip in ips):
            raise SsrfBlocked("ADDRESS_NOT_PUBLIC")
        return ips[0]

    def request(
        self,
        method: str,
        url: str,
        *,
        allow_hosts: Iterable[str],
        headers: Mapping[str, str] | None = None,
        json: Any = None,
        content: bytes | None = None,
        params: Mapping[str, str] | None = None,
    ) -> httpx.Response:
        target = check_url(url, allow_hosts)
        ip = self.pinned_ip(target)
        parts = urlsplit(url)
        netloc = f"[{ip}]" if ":" in ip else ip
        if target.port != 443:
            netloc = f"{netloc}:{target.port}"
        pinned = urlunsplit(("https", netloc, parts.path or "/", parts.query, ""))
        hdrs = {k: v for k, v in (headers or {}).items() if k.lower() != "host"}
        hdrs["Host"] = target.host if target.port == 443 else f"{target.host}:{target.port}"
        with httpx.Client(
            transport=self._transport,
            follow_redirects=False,
            trust_env=False,
            timeout=self._timeout,
        ) as client:
            req = client.build_request(
                method,
                pinned,
                headers=hdrs,
                json=json,
                content=content,
                params=params,
                extensions={"sni_hostname": target.host},
            )
            resp = client.send(req, stream=True)
            try:
                if 300 <= resp.status_code < 400:
                    raise SsrfBlocked("REDIRECT_NOT_FOLLOWED")
                body = b""
                for chunk in resp.iter_bytes():
                    body += chunk
                    if len(body) > MAX_RESPONSE_BYTES:
                        raise SsrfBlocked("RESPONSE_TOO_LARGE")
            finally:
                resp.close()
        # ``body`` is already DECODED (iter_bytes decompresses gzip/deflate/br): drop the
        # encoding and length headers, or the new Response would decode it a second time.
        out_headers = [
            (k, v)
            for k, v in resp.headers.multi_items()
            if k.lower() not in ("content-encoding", "content-length", "transfer-encoding")
        ]
        return httpx.Response(resp.status_code, headers=out_headers, content=body, request=req)
