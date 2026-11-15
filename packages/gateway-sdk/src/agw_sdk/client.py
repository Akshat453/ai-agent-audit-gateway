"""Agent-side client. The API key is sent as a Bearer token and never logged or repr'd."""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass
from typing import Any

import httpx

TERMINAL = frozenset({"DENIED", "PENDING_APPROVAL", "COMPLETED", "FAILED", "OUTCOME_UNKNOWN"})


class GatewayError(Exception):
    def __init__(self, status: int, code: str, message: str, request_id: str | None) -> None:
        super().__init__(f"{status} {code}: {message}")
        self.status = status
        self.code = code
        self.request_id = request_id


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


class Client:
    def __init__(self, base_url: str, token: str, *, timeout: float = 15.0) -> None:
        self._http = httpx.Client(
            base_url=base_url.rstrip("/"),
            headers={"Authorization": f"Bearer {token}"},
            timeout=timeout,
        )

    def __repr__(self) -> str:
        return f"Client(base_url={str(self._http.base_url)!r}, token=<redacted>)"

    def close(self) -> None:
        self._http.close()

    def __enter__(self) -> Client:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def _check(self, resp: httpx.Response) -> dict[str, Any]:
        data: dict[str, Any] = resp.json()
        if resp.status_code >= 400:
            err = data.get("error", {})
            raise GatewayError(
                resp.status_code,
                err.get("code", "?"),
                err.get("message", ""),
                err.get("request_id"),
            )
        return data

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
    ) -> ActionResponse:
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
        resp = self._http.post(
            "/v1/actions",
            json=body,
            headers={"Idempotency-Key": idempotency_key or f"sdk-{uuid.uuid4()}"},
        )
        data = self._check(resp)
        return ActionResponse(
            resp.status_code, data, resp.headers.get("Idempotent-Replayed") == "true"
        )

    def get_action(self, action_id: str) -> dict[str, Any]:
        return self._check(self._http.get(f"/v1/actions/{action_id}"))

    def wait_for_terminal(self, action_id: str, *, timeout: float = 15.0) -> dict[str, Any]:
        deadline = time.monotonic() + timeout
        while True:
            action = self.get_action(action_id)
            if action["status"] in TERMINAL or time.monotonic() > deadline:
                return action
            time.sleep(0.2)

    def list_tools(self) -> list[dict[str, Any]]:
        return list(self._check(self._http.get("/v1/tools"))["tools"])

    def timeline(self, run_id: str) -> list[dict[str, Any]]:
        return list(self._check(self._http.get(f"/v1/runs/{run_id}/timeline"))["events"])
