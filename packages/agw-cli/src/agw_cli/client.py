"""Gateway HTTP client (standard library only). Every failure mode the hook must fail closed on
raises :class:`GatewayUnavailable`: connection refused, DNS, TLS, timeout, 5xx, non-JSON,
or a response that does not match the expected shape."""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any
from urllib.parse import quote

from agw_cli import __version__
from agw_cli.config import Config

DECISIONS = ("allow", "deny", "ask")


class GatewayUnavailable(Exception):
    """The gateway could not give a usable answer. The caller blocks the action."""


class GatewayRefused(Exception):
    """A well-formed 4xx answer (e.g. session closed, not a device key)."""

    def __init__(self, status: int, code: str) -> None:
        super().__init__(code)
        self.status = status
        self.code = code


class GatewayClient:
    def __init__(self, config: Config) -> None:
        self._cfg = config

    def _call(
        self,
        method: str,
        path: str,
        body: dict[str, Any] | None = None,
        timeout: float | None = None,
    ) -> dict[str, Any]:
        data = json.dumps(body).encode("utf-8") if body is not None else None
        req = urllib.request.Request(  # noqa: S310 - URL scheme checked in config.load
            self._cfg.url + path,
            data=data,
            method=method,
            headers={
                "Authorization": f"Bearer {self._cfg.device_key}",
                "Content-Type": "application/json",
                "Accept": "application/json",
                "User-Agent": f"agw-cli/{__version__}",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout or self._cfg.request_timeout) as resp:  # noqa: S310
                raw = resp.read(4 * 1024 * 1024 + 1)
                status = resp.status
        except urllib.error.HTTPError as exc:
            raw = exc.read(64 * 1024)
            status = exc.code
        except (urllib.error.URLError, TimeoutError, OSError, ValueError) as exc:
            raise GatewayUnavailable(type(exc).__name__) from None
        try:
            parsed = json.loads(raw)
        except (ValueError, UnicodeDecodeError):
            raise GatewayUnavailable("malformed response") from None
        if not isinstance(parsed, dict):
            raise GatewayUnavailable("malformed response")
        if 400 <= status < 500:
            err = parsed.get("error")
            code = err.get("code") if isinstance(err, dict) else None
            if not isinstance(code, str):
                raise GatewayUnavailable("malformed error")
            raise GatewayRefused(status, code)
        if not 200 <= status < 300:
            raise GatewayUnavailable(f"HTTP {status}")
        return parsed

    # ---------------------------------------------------------------- endpoints
    def status(self) -> dict[str, Any]:
        return self._call("GET", "/v1/coding/status")

    def start_session(self, body: dict[str, Any]) -> str:
        resp = self._call("POST", "/v1/coding/sessions", body)
        sid = resp.get("session_id")
        if not isinstance(sid, str) or len(sid) != 36:
            raise GatewayUnavailable("malformed session")
        return sid

    def end_session(self, session_id: str) -> dict[str, Any]:
        return self._call("POST", f"/v1/coding/sessions/{session_id}/end", {})

    def decide(self, body: dict[str, Any]) -> dict[str, Any]:
        resp = self._call("POST", "/v1/coding/decide", body)
        if resp.get("decision") not in DECISIONS or not isinstance(resp.get("action_id"), str):
            raise GatewayUnavailable("malformed decision")
        if resp["decision"] == "ask" and not isinstance(resp.get("approval"), dict):
            raise GatewayUnavailable("malformed decision")
        if not isinstance(resp.get("reason", ""), str):
            raise GatewayUnavailable("malformed decision")
        return resp

    def action_status(self, action_id: str, wait: float) -> dict[str, Any]:
        resp = self._call(
            "GET",
            f"/v1/coding/actions/{action_id}?wait={max(0.0, min(wait, 30.0)):.1f}",
            timeout=self._cfg.request_timeout + wait,
        )
        if not isinstance(resp.get("status"), str):
            raise GatewayUnavailable("malformed status")
        return resp

    def observe(self, body: dict[str, Any]) -> dict[str, Any]:
        return self._call("POST", "/v1/coding/observe", body)

    def register_repo(self, body: dict[str, Any]) -> dict[str, Any]:
        return self._call("POST", "/v1/coding/repos", body)

    def repo_status(self, remote_url: str) -> dict[str, Any]:
        return self._call("GET", f"/v1/coding/repos/status?remote_url={quote(remote_url, safe='')}")


# --------------------------------------------------------------------------- C2: no device key yet
def public_call(
    base_url: str, path: str, body: dict[str, Any], timeout: float = 10.0
) -> tuple[int, dict[str, Any]]:
    """Unauthenticated JSON POST (device authorization flow). Raises GatewayUnavailable on any
    transport or format problem; returns (status, body) otherwise (RFC 8628 errors are 400s)."""
    req = urllib.request.Request(  # noqa: S310 - scheme checked by the caller
        base_url.rstrip("/") + path,
        data=json.dumps(body).encode(),
        method="POST",
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": f"agw-cli/{__version__}",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
            status, raw = resp.status, resp.read(1024 * 1024)
    except urllib.error.HTTPError as exc:
        status, raw = exc.code, exc.read(64 * 1024)
    except (urllib.error.URLError, TimeoutError, OSError, ValueError) as exc:
        raise GatewayUnavailable(type(exc).__name__) from None
    try:
        parsed = json.loads(raw)
    except (ValueError, UnicodeDecodeError):
        raise GatewayUnavailable("malformed response") from None
    if not isinstance(parsed, dict):
        raise GatewayUnavailable("malformed response")
    return status, parsed
