"""GitHub connector type (C2 §2a): config, the GitHub App MANIFEST flow and the install step.
Its actions arrive in C3; C2 only registers and installs the App.

Manifest flow (docs.github.com, "Registering a GitHub App from a manifest", fetched
2026-11-18): the browser POSTs a form field ``manifest`` (JSON) to
``https://github.com/settings/apps/new?state=…`` (or ``/organizations/<org>/settings/apps/new``);
GitHub redirects to ``redirect_url?code=…&state=…``; the server converts the code with
``POST https://api.github.com/app-manifests/{code}/conversions`` (201: id, slug, client_id,
client_secret, webhook_secret, pem, html_url, …) within one hour. Install:
``https://github.com/apps/<slug>/installations/new?state=…``; GitHub calls the setup URL with
``installation_id`` (spoofable: it is only recorded, verified by C3 with the App's JWT).
"""

from __future__ import annotations

import base64
import json
import time
from collections.abc import Mapping
from typing import Annotated, Any, ClassVar, Final, Literal

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from pydantic import BaseModel, Field, SecretStr

from agw_gateway.connectors.manifest import ActionManifest, ConnectorManifest
from agw_gateway.connectors.ssrf import SafeHttp, SsrfBlocked
from agw_gateway.connectors.types.base import ConnectorType, Health, StrictModel

GITHUB_API_HOSTS: Final = ("api.github.com",)
# C3's actions (pull requests, checks, contents) need exactly these; nothing else is requested.
DEFAULT_PERMISSIONS: Final = {
    "contents": "write",
    "pull_requests": "write",
    "issues": "write",
    "checks": "write",
    "metadata": "read",
}
DEFAULT_EVENTS: Final = ("pull_request", "check_suite", "issue_comment", "push")
REPO_PROP: Final = {
    "type": "string",
    "pattern": r"^[A-Za-z0-9-]{1,39}/[A-Za-z0-9._-]{1,100}$",
    "description": "owner/name; default: the connector's first repository",
}


def _proposal(risk: str) -> dict[str, Any]:
    return {
        "risk": risk,
        "approval": "auto",
        "approver_role": "maintainer",
        "allowed_agents": ["devices"],
    }


def _schema(required: list[str], **props: Any) -> dict[str, Any]:
    return {
        "type": "object",
        "additionalProperties": False,
        "required": required,
        "properties": {"repo": REPO_PROP, **props},
    }


GITHUB_ACTIONS: Final = (
    ActionManifest(
        environments=("dev",),
        name="github_issue_get",
        side_effect="read",
        suggested_risk="LOW",
        description="Read one GitHub issue (title, body, labels, state). Use this "
        "instead of the gh CLI or curl.",
        proposed=_proposal("LOW"),
        input_schema=_schema(["number"], number={"type": "integer", "minimum": 1}),
    ),
    ActionManifest(
        environments=("dev",),
        name="github_issue_list",
        side_effect="read",
        suggested_risk="LOW",
        description="List issues of the repository.",
        proposed=_proposal("LOW"),
        input_schema=_schema(
            [],
            state={"type": "string", "enum": ["open", "closed", "all"]},
            labels={"type": "string", "maxLength": 200},
            per_page={"type": "integer", "minimum": 1, "maximum": 50},
        ),
    ),
    ActionManifest(
        environments=("dev",),
        name="github_issue_comment",
        side_effect="write",
        suggested_risk="MEDIUM",
        reversible=True,
        proposed=_proposal("MEDIUM"),
        description="Comment on an issue.",
        input_schema=_schema(
            ["number", "body"],
            number={"type": "integer", "minimum": 1},
            body={"type": "string", "maxLength": 20000},
        ),
    ),
    ActionManifest(
        environments=("dev",),
        name="git_submit_change",
        side_effect="write",
        suggested_risk="MEDIUM",
        reversible=True,
        proposed=_proposal("MEDIUM"),
        description="Submit your local commits/changes to a branch on GitHub. ALWAYS use "
        "this instead of `git push` (direct pushes are blocked and fail the AgentGuard "
        "evidence check). Send a git bundle (`git bundle create - <base>..HEAD | base64`) "
        "or a unified diff (`git diff --binary <base>`, base64). Branch: "
        "fix/MR-<issue>-<slug> or feat/MR-<issue>-<slug>. Sensitive changes need a human "
        "approval; retry the identical call once approved.",
        input_schema=_schema(
            ["issue_number", "branch", "base_sha", "change_format", "change"],
            session_id={"type": "string", "maxLength": 64},
            issue_number={"type": "integer", "minimum": 1},
            branch={
                "type": "string",
                "pattern": r"^(fix|feat)/MR-[0-9]{1,9}-[a-z0-9][a-z0-9-]{0,48}$",
            },
            base_sha={"type": "string", "pattern": "^[0-9a-f]{40}$"},
            commit_message={"type": "string", "maxLength": 2000},
            change_format={"type": "string", "enum": ["bundle", "diff"]},
            change={
                "type": "string",
                "maxLength": 190000,
                "description": "base64 of the git bundle or unified diff",
            },
        ),
    ),
    ActionManifest(
        environments=("dev",),
        name="github_pr_create",
        side_effect="write",
        suggested_risk="MEDIUM",
        reversible=True,
        proposed=_proposal("MEDIUM"),
        description="Open a pull request for a branch you submitted with git_submit_change. "
        "The body records the session, approvals and evidence links.",
        input_schema=_schema(
            ["branch", "title", "issue_number"],
            branch={"type": "string", "maxLength": 120},
            base={"type": "string", "maxLength": 120},
            title={"type": "string", "maxLength": 200},
            issue_number={"type": "integer", "minimum": 1},
            draft={"type": "boolean"},
        ),
    ),
    ActionManifest(
        environments=("dev",),
        name="github_pr_comment",
        side_effect="write",
        suggested_risk="MEDIUM",
        reversible=True,
        proposed=_proposal("MEDIUM"),
        description="Comment on a pull request.",
        input_schema=_schema(
            ["number", "body"],
            number={"type": "integer", "minimum": 1},
            body={"type": "string", "maxLength": 20000},
        ),
    ),
    ActionManifest(
        environments=("dev",),
        name="github_pr_status",
        side_effect="read",
        suggested_risk="LOW",
        proposed=_proposal("LOW"),
        description="State of a pull request and its AgentGuard evidence check.",
        input_schema=_schema(["number"], number={"type": "integer", "minimum": 1}),
    ),
)


class GithubConfig(StrictModel):
    owner_type: Literal["user", "org"] = "org"
    owner: Annotated[str, Field(pattern=r"^[A-Za-z0-9-]{1,39}$")] | None = None
    app_id: int | None = None
    app_slug: Annotated[str, Field(pattern=r"^[a-z0-9-]{1,100}$")] | None = None
    client_id: Annotated[str, Field(max_length=100)] | None = None
    html_url: Annotated[str, Field(max_length=500)] | None = None
    installation_ids: tuple[int, ...] = ()
    # C3: the ONLY repositories the installation token is scoped to ("owner/name").
    repos: tuple[
        Annotated[str, Field(pattern=r"^[A-Za-z0-9-]{1,39}/[A-Za-z0-9._-]{1,100}$")], ...
    ] = ()
    mode: Literal["webhook", "polling"] = "webhook"
    protected_branches: tuple[str, ...] = ("main", "master")


class GithubCredentials(StrictModel):
    pem: SecretStr | None = None
    webhook_secret: SecretStr | None = None
    client_secret: SecretStr | None = None


def manifest_form(
    config: GithubConfig, gateway_url: str, dashboard_url: str, connector_id: str, name: str
) -> dict[str, Any]:
    """What the dashboard's "Create GitHub App" button POSTs (action URL + manifest JSON)."""
    base = "https://github.com/settings/apps/new"
    if config.owner_type == "org" and config.owner:
        base = f"https://github.com/organizations/{config.owner}/settings/apps/new"
    manifest = {
        "name": name[:34],
        "url": dashboard_url,
        "hook_attributes": {"url": f"{gateway_url}/v1/webhooks/github/{connector_id}"},
        "redirect_url": f"{gateway_url}/v1/connectors/github/manifest-callback",
        "setup_url": f"{gateway_url}/v1/connectors/github/setup-callback",
        "setup_on_update": True,
        "public": False,
        "default_permissions": DEFAULT_PERMISSIONS,
        "default_events": list(DEFAULT_EVENTS),
        "description": "AgentGuard: governed actions on your repositories.",
    }
    if config.mode == "polling":
        # No webhook: GitHub refuses hook URLs it cannot reach (localhost), and polling
        # mode needs no events. Pull requests are read by the worker instead.
        del manifest["hook_attributes"], manifest["default_events"]
    return {"action": base, "manifest": manifest}


def app_jwt(app_id: int | str, pem: str, now: int | None = None) -> str:
    """RS256 JWT for the GitHub App (iat 60 s back for clock skew, 9-minute lifetime)."""
    key = serialization.load_pem_private_key(pem.encode(), password=None)
    if not isinstance(key, rsa.RSAPrivateKey):
        raise ValueError("GitHub App key must be RSA")
    t = int(now if now is not None else time.time())

    def b64(raw: bytes) -> str:
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

    header = b64(json.dumps({"alg": "RS256", "typ": "JWT"}, separators=(",", ":")).encode())
    claims = b64(
        json.dumps(
            {"iat": t - 60, "exp": t + 540, "iss": str(app_id)}, separators=(",", ":")
        ).encode()
    )
    signing_input = f"{header}.{claims}".encode()
    sig = key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
    return f"{header}.{claims}.{b64(sig)}"


def convert_manifest_code(http: SafeHttp, code: str) -> Mapping[str, Any]:
    r = http.request(
        "POST",
        f"https://api.github.com/app-manifests/{code}/conversions",
        allow_hosts=GITHUB_API_HOSTS,
        headers={"Accept": "application/vnd.github+json"},
    )
    if r.status_code != 201:
        raise ValueError(f"GITHUB_CONVERSION_{r.status_code}")
    body = r.json()
    if not isinstance(body, dict) or not isinstance(body.get("id"), int):
        raise ValueError("GITHUB_CONVERSION_MALFORMED")
    return body


class GithubConnector(ConnectorType):
    manifest: ClassVar[ConnectorManifest] = ConnectorManifest(
        id="github",
        name="GitHub",
        category="code_hosting",
        auth="github_app",
        description="Issues, pull requests, governed pushes and the AgentGuard evidence check "
        "via a GitHub App.",
        actions=GITHUB_ACTIONS,
    )
    config_model: ClassVar[type[BaseModel]] = GithubConfig
    credential_model: ClassVar[type[BaseModel]] = GithubCredentials

    def assesses(self, action: str) -> bool:
        return action == "git_submit_change"

    def assess(self, ctx: Any, args: Mapping[str, Any]) -> Any:
        from agw_gateway.github.actions import assess_submit  # noqa: PLC0415

        return assess_submit(ctx, args)

    def execute(self, ctx: Any, args: Mapping[str, Any]) -> Mapping[str, Any]:
        from agw_gateway.github.actions import execute  # noqa: PLC0415

        return execute(ctx, args)

    def result_classes(self, action: str, config: Mapping[str, Any]) -> dict[str, str]:
        from agw_gateway.github.actions import RESULT_CLASSES  # noqa: PLC0415

        return dict(RESULT_CLASSES.get(action, {}))

    def health(self, config: BaseModel, creds: BaseModel, http: SafeHttp) -> Health:
        assert isinstance(config, GithubConfig) and isinstance(creds, GithubCredentials)  # noqa: S101
        if config.app_id is None or creds.pem is None:
            return Health(False, "APP_NOT_CREATED", {"next": "create the GitHub App"})
        try:
            token = app_jwt(config.app_id, creds.pem.get_secret_value())
            r = http.request(
                "GET",
                "https://api.github.com/app",
                allow_hosts=GITHUB_API_HOSTS,
                headers={
                    "Authorization": f"Bearer {token}",
                    "Accept": "application/vnd.github+json",
                },
            )
        except SsrfBlocked as exc:
            return Health(False, f"SSRF_{exc.code}", {})
        except Exception as exc:
            return Health(False, "UNREACHABLE", {"error": type(exc).__name__})
        if r.status_code != 200:
            return Health(False, "AUTH_FAILED", {"status": r.status_code})
        if not config.installation_ids:
            return Health(False, "NOT_INSTALLED", {"next": "install the App on repositories"})
        return Health(True, "OK", {"installations": len(config.installation_ids)})
