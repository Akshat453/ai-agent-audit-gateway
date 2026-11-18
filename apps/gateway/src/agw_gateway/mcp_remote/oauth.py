"""OAuth 2.1 authorization server for the remote MCP endpoint (C2, ADR-0035 §5).

Follows MCP authorization 2026-07-28 (fetched 2026-11-18):

* Protected Resource Metadata (RFC 9728) at ``/.well-known/oauth-protected-resource`` and the
  path-inserted ``/.well-known/oauth-protected-resource/mcp``; 401 challenges carry
  ``resource_metadata`` and ``scope``.
* Authorization Server Metadata (RFC 8414) at ``/.well-known/oauth-authorization-server`` with
  ``code_challenge_methods_supported: ["S256"]``,
  ``client_id_metadata_document_supported: true`` (CIMD), a DCR ``registration_endpoint`` (RFC
  7591, deprecated in MCP but still used by Cursor/Gemini) and
  ``authorization_response_iss_parameter_supported: true`` (RFC 9207).
* Authorization code + PKCE **S256 only**; exact redirect-URI match (any port for an http
  loopback redirect, RFC 8252 §7.3) (https, or http on
  localhost/127.0.0.1/[::1]); ``resource`` (RFC 8707) REQUIRED and must be this server's
  canonical MCP URI, and the issued tokens are bound to it (audience); ``iss`` in the redirect.
* Short-lived opaque access tokens (``agwm_…``, default 10 min) stored as SHA-256 only;
  refresh tokens rotate on every use and a reused refresh token revokes the whole family.
* The browser step happens in the dashboard (human session): the consent there names the
  client, the developer and the device the token will act as. Each (developer, client) pair
  gets its own device (an agent bound to the developer), so tokens are developer + device bound.
"""

from __future__ import annotations

import base64
import hashlib
import ipaddress
import re
import secrets
from dataclasses import dataclass
from datetime import timedelta
from typing import Any, Final
from urllib.parse import urlencode, urlsplit
from uuid import UUID

from sqlalchemy import Engine, func, insert, select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert

from agw_gateway.auth.models import AuthenticatedAgent
from agw_gateway.connectors.ssrf import SafeHttp, SsrfBlocked
from agw_gateway.db import tables as t
from agw_gateway.enrollment import enroll_device
from agw_gateway.evidence import EvidenceWriter
from agw_gateway.execution.errors import GatewayError
from agw_gateway.humans.models import AuthenticatedHuman

SCOPE: Final = "mcp:tools"
CODE_TTL: Final = timedelta(seconds=120)
TOKEN_RE: Final = re.compile(r"^agwm_[A-Za-z0-9_-]{43}$")
REFRESH_RE: Final = re.compile(r"^agwr_[A-Za-z0-9_-]{43}$")


class OAuthError(GatewayError):
    """RFC 6749 §5.2 error: ``{"error": code}`` with HTTP 400 (401 for invalid_client)."""

    http_status = 400

    def __init__(self, code: str, status: int = 400) -> None:
        super().__init__(code)
        self.code = code
        self.http_status = status


def _h(value: str) -> bytes:
    return hashlib.sha256(b"AGW/oauth/v1\x00" + value.encode()).digest()


_LOOPBACK = frozenset({"localhost", "127.0.0.1", "::1"})


def redirect_matches(requested: str, registered: list[str]) -> bool:
    """Exact match, except that for an http LOOPBACK redirect the port may differ (RFC 8252
    §7.3: native apps listen on an ephemeral port; e.g. Claude Code registers
    "http://localhost/callback" and uses "http://localhost:<random>/callback")."""
    if requested in registered:
        return True
    try:
        req = urlsplit(requested)
        req_port = req.port
    except ValueError:
        return False
    if (
        req.scheme != "http"
        or req.hostname not in _LOOPBACK
        or req.username is not None
        or req.password is not None
        or req.fragment
        or req_port is None
    ):
        return False
    for uri in registered:
        try:
            reg = urlsplit(uri)
        except ValueError:
            continue
        if (
            reg.scheme == "http"
            and reg.hostname == req.hostname
            and reg.username is None
            and not reg.fragment
            and reg.path == req.path
            and reg.query == req.query
        ):
            return True
    return False


def _redirect_ok(uri: str) -> bool:
    try:
        parts = urlsplit(uri)
    except ValueError:
        return False
    if parts.fragment or not parts.hostname:
        return False
    if parts.scheme == "https":
        return True
    if parts.scheme == "http":
        host = parts.hostname
        if host == "localhost":
            return True
        try:
            return ipaddress.ip_address(host).is_loopback
        except ValueError:
            return False
    return False


@dataclass(frozen=True)
class McpPrincipal:
    agent: AuthenticatedAgent
    human_id: UUID
    client_id: str


class OAuthServer:
    def __init__(
        self,
        *,
        engine: Engine,
        writer: EvidenceWriter,
        issuer: str,
        dashboard_url: str,
        http: SafeHttp,
        access_ttl: int,
        refresh_ttl: int,
    ) -> None:
        self._engine = engine
        self._writer = writer
        self.issuer = issuer.rstrip("/")
        self.resource = f"{self.issuer}/mcp"
        self._dashboard = dashboard_url.rstrip("/")
        self._http = http
        self._access = timedelta(seconds=access_ttl)
        self._refresh = timedelta(seconds=refresh_ttl)

    # ------------------------------------------------------------------ metadata
    def protected_resource(self) -> dict[str, Any]:
        return {
            "resource": self.resource,
            "authorization_servers": [self.issuer],
            "scopes_supported": [SCOPE],
            "bearer_methods_supported": ["header"],
            "resource_name": "AgentGuard MCP",
        }

    def metadata(self) -> dict[str, Any]:
        return {
            "issuer": self.issuer,
            "authorization_endpoint": f"{self.issuer}/oauth/authorize",
            "token_endpoint": f"{self.issuer}/oauth/token",
            "registration_endpoint": f"{self.issuer}/oauth/register",
            "revocation_endpoint": f"{self.issuer}/oauth/revoke",
            "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "code_challenge_methods_supported": ["S256"],
            "token_endpoint_auth_methods_supported": ["none"],
            "scopes_supported": [SCOPE],
            "client_id_metadata_document_supported": True,
            "authorization_response_iss_parameter_supported": True,
        }

    def challenge(self, error: str | None = None) -> str:
        parts = [
            f'resource_metadata="{self.issuer}/.well-known/oauth-protected-resource/mcp"',
            f'scope="{SCOPE}"',
        ]
        if error:
            parts.insert(0, f'error="{error}"')
        return "Bearer " + ", ".join(parts)

    # ------------------------------------------------------------------ clients
    def register(self, body: dict[str, Any]) -> dict[str, Any]:
        """RFC 7591 dynamic registration: public clients only (token_endpoint_auth none)."""
        uris = body.get("redirect_uris")
        if (
            not isinstance(uris, list)
            or not 1 <= len(uris) <= 10
            or not all(isinstance(u, str) and len(u) <= 2000 and _redirect_ok(u) for u in uris)
        ):
            raise OAuthError("invalid_redirect_uri")
        if body.get("token_endpoint_auth_method", "none") != "none":
            raise OAuthError("invalid_client_metadata")
        name = str(body.get("client_name", ""))[:200]
        client_id = "agwc_" + secrets.token_urlsafe(24)
        with self._engine.begin() as conn:
            conn.execute(
                insert(t.oauth_clients).values(
                    client_id=client_id, client_name=name, redirect_uris=uris
                )
            )
        return {
            "client_id": client_id,
            "client_name": name,
            "redirect_uris": uris,
            "token_endpoint_auth_method": "none",
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
        }

    def _client(self, client_id: str) -> tuple[str, list[str]]:
        """A registered (DCR) client, or a Client ID Metadata Document fetched SSRF-safely."""
        with self._engine.connect() as conn:
            row = conn.execute(
                select(t.oauth_clients).where(t.oauth_clients.c.client_id == client_id)
            ).one_or_none()
        if row is not None:
            return row.client_name, list(row.redirect_uris)
        parts = urlsplit(client_id)
        if parts.scheme != "https" or not parts.path or parts.path == "/" or not parts.hostname:
            raise OAuthError("invalid_client", 401)
        try:
            r = self._http.request("GET", client_id, allow_hosts=[parts.hostname])
            doc = r.json() if r.status_code == 200 else None
        except (SsrfBlocked, ValueError):
            doc = None
        if (
            not isinstance(doc, dict)
            or doc.get("client_id") != client_id
            or not isinstance(doc.get("redirect_uris"), list)
            or not all(isinstance(u, str) and _redirect_ok(u) for u in doc["redirect_uris"])
        ):
            raise OAuthError("invalid_client", 401)
        name = str(doc.get("client_name", ""))[:200]
        with self._engine.begin() as conn:
            conn.execute(
                pg_insert(t.oauth_clients)
                .values(client_id=client_id, client_name=name, redirect_uris=doc["redirect_uris"])
                .on_conflict_do_nothing()
            )
        return name, list(doc["redirect_uris"])

    # ------------------------------------------------------------------ authorize
    def check_request(self, q: dict[str, str]) -> dict[str, Any]:
        """Validate an authorization request; the dashboard shows the result as consent."""
        if q.get("response_type") != "code":
            raise OAuthError("unsupported_response_type")
        client_id = q.get("client_id", "")
        if not 8 <= len(client_id) <= 2048:
            raise OAuthError("invalid_client", 401)
        name, uris = self._client(client_id)
        redirect = q.get("redirect_uri", "")
        if not redirect_matches(redirect, uris):  # exact, or loopback with any port
            raise OAuthError("invalid_redirect_uri")
        if q.get("code_challenge_method") != "S256" or not re.fullmatch(
            r"[A-Za-z0-9_-]{43}", q.get("code_challenge", "")
        ):
            raise OAuthError("invalid_request")
        if q.get("resource", "").rstrip("/") != self.resource:
            raise OAuthError("invalid_target")
        scope = q.get("scope", SCOPE) or SCOPE
        if set(scope.split()) - {SCOPE}:
            raise OAuthError("invalid_scope")
        return {
            "client_id": client_id,
            "client_name": name,
            "redirect_uri": redirect,
            "code_challenge": q["code_challenge"],
            "state": q.get("state", "")[:500],
            "resource": self.resource,
            "scope": SCOPE,
        }

    def consent_url(self, q: dict[str, str]) -> str:
        self.check_request(q)
        return f"{self._dashboard}/oauth/consent?{urlencode(q)}"

    def approve(self, human: AuthenticatedHuman, q: dict[str, str], allow: bool) -> str:
        """The signed-in developer approved (or denied) in the dashboard: redirect URL with a
        single-use code bound to client, redirect, PKCE challenge, resource and device."""
        req = self.check_request(q)
        sep = "&" if "?" in req["redirect_uri"] else "?"
        if not allow:
            return str(
                req["redirect_uri"]
                + sep
                + urlencode({"error": "access_denied", "state": req["state"], "iss": self.issuer})
            )
        label = "mcp-" + hashlib.sha256(req["client_id"].encode()).hexdigest()[:12]
        code = secrets.token_urlsafe(32)
        with self._engine.begin() as conn:
            device = conn.execute(
                select(t.coding_devices.c.agent_id)
                .join(t.agents, t.agents.c.agent_id == t.coding_devices.c.agent_id)
                .where(
                    t.coding_devices.c.developer_id == human.human_id,
                    t.coding_devices.c.label == label,
                    t.agents.c.status == "active",
                )
            ).scalar_one_or_none()
            if device is None:
                device, _unused_key = enroll_device(
                    conn,
                    self._writer,
                    tenant=human.tenant_id,
                    human_id=human.human_id,
                    label=label,
                    agent_kind="generic_mcp",
                    via="mcp_oauth",
                )
            conn.execute(
                insert(t.oauth_codes).values(
                    code_hash=_h(code),
                    client_id=req["client_id"],
                    tenant_id=human.tenant_id,
                    human_id=human.human_id,
                    device_agent_id=device,
                    redirect_uri=req["redirect_uri"],
                    code_challenge=req["code_challenge"],
                    resource=req["resource"],
                    scope=req["scope"],
                    expires_at=func.now() + CODE_TTL,
                )
            )
        return str(
            req["redirect_uri"]
            + sep
            + urlencode({"code": code, "state": req["state"], "iss": self.issuer})
        )

    # ------------------------------------------------------------------ token
    def _issue(self, conn: Any, row: Any) -> dict[str, Any]:
        access = "agwm_" + secrets.token_urlsafe(32)  # 43 chars
        refresh = "agwr_" + secrets.token_urlsafe(32)
        common = {
            "client_id": row.client_id,
            "tenant_id": row.tenant_id,
            "human_id": row.human_id,
            "device_agent_id": row.device_agent_id,
            "resource": row.resource,
            "scope": row.scope,
        }
        conn.execute(
            insert(t.oauth_tokens).values(
                token_hash=_h(access), kind="access", expires_at=func.now() + self._access, **common
            )
        )
        conn.execute(
            insert(t.oauth_tokens).values(
                token_hash=_h(refresh),
                kind="refresh",
                expires_at=func.now() + self._refresh,
                **common,
            )
        )
        return {
            "access_token": access,
            "token_type": "Bearer",
            "expires_in": int(self._access.total_seconds()),
            "refresh_token": refresh,
            "scope": row.scope,
        }

    def token(self, form: dict[str, str]) -> dict[str, Any]:
        grant = form.get("grant_type")
        if grant == "authorization_code":
            return self._code_grant(form)
        if grant == "refresh_token":
            return self._refresh_grant(form)
        raise OAuthError("unsupported_grant_type")

    def _code_grant(self, form: dict[str, str]) -> dict[str, Any]:
        code, verifier = form.get("code", ""), form.get("code_verifier", "")
        if not code or not re.fullmatch(r"[A-Za-z0-9._~-]{43,128}", verifier):
            raise OAuthError("invalid_request")
        if form.get("resource", self.resource).rstrip("/") != self.resource:
            raise OAuthError("invalid_target")
        with self._engine.begin() as conn:
            row = conn.execute(
                select(t.oauth_codes, (t.oauth_codes.c.expires_at > func.now()).label("live"))
                .where(t.oauth_codes.c.code_hash == _h(code))
                .with_for_update(of=t.oauth_codes)
            ).one_or_none()
            if row is None or row.used_at is not None or not row.live:
                raise OAuthError("invalid_grant")
            conn.execute(
                update(t.oauth_codes)
                .where(t.oauth_codes.c.code_hash == row.code_hash)
                .values(used_at=func.now())
            )
            challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
            if (
                form.get("client_id") == row.client_id
                and form.get("redirect_uri") == row.redirect_uri
                and challenge.rstrip(b"=").decode() == row.code_challenge
            ):
                return self._issue(conn, row)
        # Any failed redemption still burns the code (committed above): no verifier guessing.
        raise OAuthError("invalid_grant")

    def _refresh_grant(self, form: dict[str, str]) -> dict[str, Any]:
        token = form.get("refresh_token", "")
        if not REFRESH_RE.fullmatch(token):
            raise OAuthError("invalid_grant")
        reuse = False
        with self._engine.begin() as conn:
            row = conn.execute(
                select(t.oauth_tokens, (t.oauth_tokens.c.expires_at > func.now()).label("live"))
                .where(t.oauth_tokens.c.token_hash == _h(token), t.oauth_tokens.c.kind == "refresh")
                .with_for_update(of=t.oauth_tokens)
            ).one_or_none()
            if row is None or form.get("client_id") != row.client_id:
                raise OAuthError("invalid_grant")
            if row.revoked_at is not None:
                # Reuse of a rotated refresh token: assume theft, revoke the whole family.
                conn.execute(
                    update(t.oauth_tokens)
                    .where(
                        t.oauth_tokens.c.client_id == row.client_id,
                        t.oauth_tokens.c.human_id == row.human_id,
                        t.oauth_tokens.c.revoked_at.is_(None),
                    )
                    .values(revoked_at=func.now())
                )
                reuse = True  # committed below, THEN refused
            elif not row.live:
                raise OAuthError("invalid_grant")
            else:
                conn.execute(
                    update(t.oauth_tokens)
                    .where(t.oauth_tokens.c.token_hash == row.token_hash)
                    .values(revoked_at=func.now())
                )
                return self._issue(conn, row)
        assert reuse  # noqa: S101
        raise OAuthError("invalid_grant")

    def revoke(self, form: dict[str, str]) -> None:
        token = form.get("token", "")
        with self._engine.begin() as conn:
            conn.execute(
                update(t.oauth_tokens)
                .where(t.oauth_tokens.c.token_hash == _h(token))
                .values(revoked_at=func.now())
            )

    # ------------------------------------------------------------------ resource side
    def authenticate(self, authorization: str | None) -> McpPrincipal | None:
        """Valid, unexpired, unrevoked access token issued FOR this resource, whose device and
        developer are still active. Anything else -> None (the caller answers 401)."""
        if not authorization or not authorization.startswith("Bearer "):
            return None
        token = authorization[7:].strip()
        if not TOKEN_RE.fullmatch(token):
            return None
        with self._engine.connect() as conn:
            row = conn.execute(
                select(
                    t.oauth_tokens,
                    t.agents.c.name,
                    t.agents.c.scopes,
                    t.agents.c.status.label("agent_status"),
                    t.agents.c.trust_tier,
                    t.humans.c.status.label("human_status"),
                )
                .join(t.agents, t.agents.c.agent_id == t.oauth_tokens.c.device_agent_id)
                .join(t.humans, t.humans.c.human_id == t.oauth_tokens.c.human_id)
                .where(
                    t.oauth_tokens.c.token_hash == _h(token),
                    t.oauth_tokens.c.kind == "access",
                    t.oauth_tokens.c.revoked_at.is_(None),
                    t.oauth_tokens.c.expires_at > func.now(),
                )
            ).one_or_none()
        if (
            row is None
            or row.resource != self.resource  # audience: tokens for another resource are refused
            or row.agent_status != "active"
            or row.human_status != "active"
        ):
            return None
        agent = AuthenticatedAgent(
            tenant_id=row.tenant_id,
            agent_id=row.device_agent_id,
            name=row.name,
            scopes=frozenset(row.scopes),
            trust_tier=row.trust_tier,
            via="mcp:remote",
        )
        return McpPrincipal(agent=agent, human_id=row.human_id, client_id=row.client_id)
