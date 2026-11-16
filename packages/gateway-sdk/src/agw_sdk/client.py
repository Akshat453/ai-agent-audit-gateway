"""Agent-side client (Phase 1; typed calls, delegation and retries in Phase 8, ADR-0030 §5).

* The agent's gateway API key is sent as a Bearer token and never logged or repr'd. The SDK
  holds NO tool credentials: tools run only inside the gateway.
* ``call()`` is one LOGICAL tool call: it generates one Idempotency-Key and reuses it for
  every retry of that call (transport errors, 502/503/504), so a retry can never create a
  second action - the gateway replays the first answer (INV-5).
* Decisions map to exceptions: DENIED -> ``Denied``, still pending after the wait ->
  ``ApprovalRequired``, approval window closed -> ``ApprovalExpired``, FAILED ->
  ``ToolFailed``, OUTCOME_UNKNOWN -> ``OutcomeUnknown``.
"""

from __future__ import annotations

import time
import uuid
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx

from agw_sdk.errors import (
    ApprovalExpired,
    ApprovalRequired,
    Denied,
    GatewayError,
    OutcomeUnknown,
    StillRunning,
    ToolFailed,
)

TERMINAL = frozenset(
    {"DENIED", "PENDING_APPROVAL", "COMPLETED", "FAILED", "OUTCOME_UNKNOWN", "EXPIRED"}
)
FINAL = TERMINAL - {"PENDING_APPROVAL"}  # nothing more can happen to the action
_RETRY_STATUS = frozenset({502, 503, 504})


@dataclass(frozen=True)
class ActionResponse:
    status_code: int
    body: dict[str, Any]
    replayed: bool

    @property
    def action_id(self) -> str:
        return str(self.body["action_id"])

    @property
    def status(self) -> str:
        return str(self.body["status"])


@dataclass(frozen=True)
class Source:
    """Context provenance: content the agent read before acting (e.g. a search hit)."""

    uri: str
    sha256: str


@dataclass(frozen=True)
class ToolCallResult:
    action_id: str
    status: str  # COMPLETED
    result: dict[str, Any]
    decision: dict[str, Any]
    idempotency_key: str
    replayed: bool = False


@dataclass(frozen=True)
class Delegation:
    delegation_id: str
    token: str = field(repr=False)  # a capability: never printed
    token_hash: str
    depth: int
    scopes: tuple[str, ...]
    tools: tuple[str, ...]
    max_risk_level: str
    max_uses: int
    expires_at: str
    created_event_id: str


class Client:
    def __init__(
        self,
        base_url: str,
        token: str,
        *,
        timeout: float = 15.0,
        http_client: httpx.Client | None = None,
        retries: int = 3,
        backoff: float = 0.25,
    ) -> None:
        # The credential is sent per request, so an injected (possibly shared) client is
        # never modified.
        self._auth = {"Authorization": f"Bearer {token}"}
        self._owned = http_client is None
        self._http = http_client or httpx.Client(base_url=base_url.rstrip("/"), timeout=timeout)
        self._retries = max(0, retries)
        self._backoff = backoff

    def __repr__(self) -> str:
        return f"Client(base_url={str(self._http.base_url)!r}, token=<redacted>)"

    def close(self) -> None:
        if self._owned:
            self._http.close()

    def _get(self, url: str, **kw: Any) -> httpx.Response:
        return self._http.get(url, headers=self._auth, **kw)

    def _post(self, url: str, headers: dict[str, str] | None = None, **kw: Any) -> httpx.Response:
        return self._http.post(url, headers={**self._auth, **(headers or {})}, **kw)

    def __enter__(self) -> Client:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    @staticmethod
    def _check(resp: httpx.Response) -> dict[str, Any]:
        try:
            data: dict[str, Any] = resp.json()
        except ValueError:
            data = {}
        if resp.status_code >= 400:
            err = data.get("error", {}) if isinstance(data, dict) else {}
            raise GatewayError(
                resp.status_code,
                err.get("code", "?"),
                err.get("message", ""),
                err.get("request_id"),
            )
        return data

    # ---------------------------------------------------------------- low level
    def submit_action(
        self,
        *,
        run_id: str,
        tool: str,
        args: dict[str, Any],
        environment: str = "dev",
        tool_version: str | None = None,
        idempotency_key: str | None = None,
        intent_summary: str | None = None,
        delegation_depth: int | None = None,
        delegation_token: str | None = None,
        sources: Sequence[Source] = (),
    ) -> ActionResponse:
        """One POST. Retries ONLY with the same Idempotency-Key (safe by construction)."""
        body: dict[str, Any] = {
            "run_id": run_id,
            "tool": tool,
            "environment": environment,
            "args": args,
        }
        if tool_version:
            body["tool_version"] = tool_version
        if intent_summary:
            body["intent"] = {"summary": intent_summary}
        if delegation_token is not None:  # gateway-verified chain (Phase 8)
            body["delegation"] = {"token": delegation_token}
        elif delegation_depth is not None:  # agent-declared; can only raise risk
            body["delegation"] = {"depth": delegation_depth}
        if sources:
            body["context"] = {"sources": [{"uri": s.uri, "sha256": s.sha256} for s in sources]}
        key = idempotency_key or f"sdk-{uuid.uuid4()}"
        attempt = 0
        while True:
            try:
                resp = self._post("/v1/actions", json=body, headers={"Idempotency-Key": key})
            except httpx.TransportError:
                if attempt >= self._retries:
                    raise
            else:
                if resp.status_code not in _RETRY_STATUS or attempt >= self._retries:
                    data = self._check(resp)
                    return ActionResponse(
                        resp.status_code, data, resp.headers.get("Idempotent-Replayed") == "true"
                    )
            attempt += 1
            time.sleep(self._backoff * (2 ** (attempt - 1)))

    def get_action(self, action_id: str) -> dict[str, Any]:
        return self._check(self._get(f"/v1/actions/{action_id}"))

    def wait_for_change(self, action_id: str, *, wait: float = 25.0) -> dict[str, Any]:
        """Long-poll (``?wait=``): returns as soon as the status changes, or after ``wait``."""
        return self._check(
            self._get(f"/v1/actions/{action_id}", params={"wait": wait}, timeout=wait + 10.0)
        )

    def wait_for_final(self, action_id: str, *, timeout: float = 60.0) -> dict[str, Any]:
        """Wait through PENDING_APPROVAL (a human decides) until nothing more can happen."""
        deadline = time.monotonic() + timeout
        action = self.get_action(action_id)
        while action["status"] not in FINAL and time.monotonic() < deadline:
            action = self.wait_for_change(
                action_id, wait=max(0.5, min(25.0, deadline - time.monotonic()))
            )
        return action

    def wait_for_terminal(self, action_id: str, *, timeout: float = 15.0) -> dict[str, Any]:
        deadline = time.monotonic() + timeout
        while True:
            action = self.get_action(action_id)
            if action["status"] in TERMINAL or time.monotonic() > deadline:
                return action
            time.sleep(0.2)

    # ---------------------------------------------------------------- typed call
    def call(
        self,
        tool: str,
        args: dict[str, Any],
        *,
        run_id: str | None = None,
        environment: str = "dev",
        tool_version: str | None = None,
        delegation_token: str | None = None,
        sources: Sequence[Source] = (),
        intent_summary: str | None = None,
        approval_wait: float = 300.0,
        timeout: float = 60.0,
        idempotency_key: str | None = None,
    ) -> ToolCallResult:
        """Submit one logical tool call and wait for its outcome.

        ``approval_wait``: how long to wait for a human approval (0 = raise
        ``ApprovalRequired`` immediately). ``timeout``: how long to wait for execution once
        authorized. Raises the typed exceptions in ``agw_sdk.errors``."""
        key = idempotency_key or f"call-{uuid.uuid4()}"
        submitted = self.submit_action(
            run_id=run_id or str(uuid.uuid4()),
            tool=tool,
            args=args,
            environment=environment,
            tool_version=tool_version,
            idempotency_key=key,
            intent_summary=intent_summary,
            delegation_token=delegation_token,
            sources=sources,
        )
        action_id = submitted.action_id
        decision = dict(submitted.body.get("decision", {}))
        approval_id = (submitted.body.get("approval") or {}).get("approval_id")
        status = submitted.status
        if status == "DENIED":
            raise Denied(action_id, status, reasons=decision.get("reasons", []), decision=decision)
        if status == "PENDING_APPROVAL":
            if approval_wait <= 0:
                raise ApprovalRequired(action_id, status, approval_id=approval_id)
            action = self.wait_for_final(action_id, timeout=approval_wait)
            if action["status"] == "PENDING_APPROVAL":
                raise ApprovalRequired(action_id, "PENDING_APPROVAL", approval_id=approval_id)
        else:
            action = self.wait_for_final(action_id, timeout=timeout)
        return self._outcome(action, key, submitted.replayed, approval_id)

    def wait(self, action_id: str, *, timeout: float = 60.0) -> ToolCallResult:
        """Resume waiting on an earlier call (e.g. after ``ApprovalRequired``)."""
        return self._outcome(self.wait_for_final(action_id, timeout=timeout), "", False, None)

    @staticmethod
    def _outcome(
        action: dict[str, Any], key: str, replayed: bool, approval_id: str | None
    ) -> ToolCallResult:
        action_id, status = str(action["action_id"]), str(action["status"])
        decision = dict(action.get("decision") or {})
        code = action.get("error_code")
        if status == "COMPLETED":
            return ToolCallResult(
                action_id, status, dict(action.get("result") or {}), decision, key, replayed
            )
        if status == "DENIED":
            raise Denied(
                action_id,
                status,
                str(code or ""),
                reasons=[code] if code else decision.get("reasons", []),
                decision=decision,
            )
        if status == "EXPIRED":
            raise ApprovalExpired(action_id, status, str(code or ""))
        if status == "PENDING_APPROVAL":
            raise ApprovalRequired(action_id, status, approval_id=approval_id)
        if status == "FAILED":
            raise ToolFailed(action_id, status, str(code or ""), error_code=code)
        if status == "OUTCOME_UNKNOWN":
            raise OutcomeUnknown(action_id, status, str(code or ""))
        raise StillRunning(action_id, status)

    # ---------------------------------------------------------------- delegation (Phase 8)
    def delegate(
        self,
        *,
        child_agent_id: str,
        scopes: Sequence[str],
        tools: Sequence[str],
        max_risk_level: str,
        expires_in: timedelta,
        max_uses: int,
        purpose: str,
        parent_token: str | None = None,
        run_id: str | None = None,
    ) -> Delegation:
        body: dict[str, Any] = {
            "child_agent_id": child_agent_id,
            "scopes": list(scopes),
            "tools": list(tools),
            "max_risk_level": max_risk_level,
            "expires_at": (datetime.now(UTC) + expires_in).isoformat(),
            "max_uses": max_uses,
            "purpose": purpose,
        }
        if parent_token:
            body["parent_token"] = parent_token
        if run_id:
            body["run_id"] = run_id
        d = self._check(self._post("/v1/delegations", json=body))
        return Delegation(
            delegation_id=d["delegation_id"],
            token=d["token"],
            token_hash=d["token_hash"],
            depth=int(d["depth"]),
            scopes=tuple(d["scopes"]),
            tools=tuple(d["tools"]),
            max_risk_level=d["max_risk_level"],
            max_uses=int(d["max_uses"]),
            expires_at=d["expires_at"],
            created_event_id=d["created_event_id"],
        )

    def revoke_delegation(self, delegation_id: str) -> dict[str, Any]:
        return self._check(self._post(f"/v1/delegations/{delegation_id}/revoke"))

    def delegation_timeline(self, delegation_id: str) -> dict[str, Any]:
        return self._check(self._get(f"/v1/delegations/{delegation_id}/timeline"))

    # ---------------------------------------------------------------- reads
    def list_tools(self) -> list[dict[str, Any]]:
        return list(self._check(self._get("/v1/tools"))["tools"])

    def timeline(self, run_id: str) -> list[dict[str, Any]]:
        return list(self._check(self._get(f"/v1/runs/{run_id}/timeline"))["events"])

    # ---------------------------------------------------------------- evidence (Phase 2/3)
    def events(self, **filters: Any) -> list[dict[str, Any]]:
        params = {k: v for k, v in filters.items() if v is not None}
        if "event_type" in params:
            params["type"] = params.pop("event_type")
        return list(self._check(self._get("/v1/events", params=params))["events"])

    def epoch(self, epoch_no: int | str = "latest") -> dict[str, Any]:
        return self._check(self._get(f"/v1/epochs/{epoch_no}"))

    def proof(self, event_id: str) -> dict[str, Any] | None:
        """Evidence bundle for an event, or None while it is not sealed yet (409)."""
        resp = self._get(f"/v1/events/{event_id}/proof")
        if resp.status_code == 409:
            return None
        return self._check(resp)
