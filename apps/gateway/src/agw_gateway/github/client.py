"""GitHub REST client for the GitHub connector (C3, ADR-0036 §2).

* App JWT (RS256, ``iss`` = client id, else app id; iat now-60, exp now+540) ->
  ``POST /app/installations/{id}/access_tokens`` with ``repositories`` = ONLY the configured
  repos. The installation token lives in process memory (until 5 min before ``expires_at``),
  is never stored, logged or returned, and is dropped on any 401.
* Every call goes through :class:`SafeHttp` (https, ``api.github.com`` only, public IPs, no
  redirects, timeouts) with ``X-GitHub-Api-Version: 2026-03-10``.
* Repository arguments are checked against the connector's configured repos before any call.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Mapping
from datetime import datetime
from typing import Any, Final
from urllib.parse import quote

from agw_gateway.connectors.ssrf import SafeHttp, SsrfBlocked
from agw_gateway.connectors.types.base import ActionFailed
from agw_gateway.connectors.types.github import (
    GITHUB_API_HOSTS,
    GithubConfig,
    GithubCredentials,
    app_jwt,
)

API: Final = "https://api.github.com"
API_VERSION: Final = "2026-03-10"
_TOKENS: dict[str, tuple[str, float]] = {}  # connector id -> (token, valid until, monotonic)
_LOCK = threading.Lock()


def forget_token(key: str) -> None:
    with _LOCK:
        _TOKENS.pop(key, None)


class GithubApi:
    def __init__(self, http: SafeHttp, config: GithubConfig, creds: GithubCredentials, key: str):
        self._http, self._cfg, self._creds, self._key = http, config, creds, key

    # ------------------------------------------------------------------ auth
    def _jwt(self) -> str:
        if self._creds.pem is None or (self._cfg.client_id is None and self._cfg.app_id is None):
            raise ActionFailed("GITHUB_APP_NOT_CONFIGURED")
        issuer = self._cfg.client_id or str(self._cfg.app_id)
        return app_jwt_iss(issuer, self._creds.pem.get_secret_value())

    def token(self) -> str:
        with _LOCK:
            cached = _TOKENS.get(self._key)
            if cached is not None and cached[1] > time.monotonic():
                return cached[0]
        if not self._cfg.installation_ids:
            raise ActionFailed("GITHUB_NOT_INSTALLED")
        names = sorted({r.split("/", 1)[1] for r in self._cfg.repos})
        r = self._raw(
            "POST",
            f"/app/installations/{self._cfg.installation_ids[0]}/access_tokens",
            bearer=self._jwt(),
            json={"repositories": names} if names else None,
        )
        if r.status_code != 201:
            raise ActionFailed(f"GITHUB_TOKEN_{r.status_code}")
        body = r.json()
        token = body.get("token")
        if not isinstance(token, str) or not token:
            raise ActionFailed("GITHUB_TOKEN_MALFORMED")
        ttl = 3000.0
        try:
            exp = datetime.fromisoformat(str(body.get("expires_at")).replace("Z", "+00:00"))
            ttl = max(60.0, exp.timestamp() - time.time() - 300)
        except ValueError:
            pass
        with _LOCK:
            _TOKENS[self._key] = (token, time.monotonic() + ttl)
        return token

    # ------------------------------------------------------------------ calls
    def _raw(
        self,
        method: str,
        path: str,
        *,
        bearer: str,
        json: Any = None,
        params: Mapping[str, str] | None = None,
    ) -> Any:
        try:
            return self._http.request(
                method,
                API + path,
                allow_hosts=GITHUB_API_HOSTS,
                json=json,
                params=params,
                headers={
                    "Authorization": f"Bearer {bearer}",
                    "Accept": "application/vnd.github+json",
                    "X-GitHub-Api-Version": API_VERSION,
                },
            )
        except SsrfBlocked as exc:
            raise ActionFailed(f"SSRF_{exc.code}") from None

    def call(
        self,
        method: str,
        path: str,
        *,
        json: Any = None,
        params: Mapping[str, str] | None = None,
        ok: tuple[int, ...] = (200, 201),
    ) -> Any:
        r = self._raw(method, path, bearer=self.token(), json=json, params=params)
        if r.status_code == 401:
            forget_token(self._key)
        if r.status_code not in ok:
            raise ActionFailed(f"GITHUB_HTTP_{r.status_code}")
        return r.json() if r.content else {}

    def repo(self, requested: str | None) -> str:
        """The repository for a call: one of the configured repos (default: the first)."""
        if not self._cfg.repos:
            raise ActionFailed("GITHUB_NO_REPOS")
        repo = requested or self._cfg.repos[0]
        if repo not in self._cfg.repos:
            raise ActionFailed("REPO_NOT_ALLOWED")
        return repo

    def branch_rules(self, repo: str, branch: str) -> list[Any]:
        """Active ruleset rules for a branch (Metadata read). Empty list = none."""
        body = self.call(
            "GET", f"/repos/{repo}/rules/branches/{quote(branch, safe='')}", ok=(200, 404)
        )
        return body if isinstance(body, list) else []

    def branch(self, repo: str, branch: str) -> dict[str, Any] | None:
        r = self._raw(
            "GET", f"/repos/{repo}/branches/{quote(branch, safe='')}", bearer=self.token()
        )
        if r.status_code == 404:
            return None
        if r.status_code != 200:
            raise ActionFailed(f"GITHUB_HTTP_{r.status_code}")
        body = r.json()
        return body if isinstance(body, dict) else None

    def clone_url(self, repo: str, clone_root: Any = None) -> str:
        if clone_root is not None:  # dev/test only: a local bare repository per owner/name
            return f"file://{clone_root}/{repo}.git"
        return f"https://github.com/{repo}.git"


def app_jwt_iss(issuer: str, pem: str) -> str:
    """``app_jwt`` with a string issuer (client id is recommended by GitHub)."""
    return app_jwt(issuer, pem)


_ = (GithubCredentials,)
