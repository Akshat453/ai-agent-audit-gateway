"""Phase 8 SDK (ADR-0030 §5): one idempotency key per logical call (retries replay, never
duplicate), approval waiting, and the decision -> exception mapping."""

from __future__ import annotations

import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

import httpx
import pytest
from sqlalchemy import Engine, func, select

from agw_gateway.db import tables as t
from agw_sdk import (
    ApprovalExpired,
    ApprovalRequired,
    Client,
    Denied,
    OutcomeUnknown,
    Source,
    StillRunning,
    ToolFailed,
)

from ..approvalkit import EXTERNAL, decide, expire_now, make_humans
from ..delegationkit import delegate, new_agent

pytestmark = pytest.mark.e2e


@contextmanager
def pump(gw: Any) -> Iterator[None]:
    """Run the executor in the background (the gateway's worker, in-process)."""
    stop = threading.Event()

    def loop() -> None:
        while not stop.is_set():
            gw.state.executor.run_once()
            time.sleep(0.02)

    th = threading.Thread(target=loop, daemon=True)
    th.start()
    try:
        yield
    finally:
        stop.set()
        th.join()


def sdk(gw: Any, token: str | None = None, **kw: Any) -> Client:
    return Client("http://testserver", token or gw.world.token, http_client=gw.client, **kw)


class FlakyAfterSend(httpx.BaseTransport):
    """The request REACHES the gateway, then the connection drops before the answer arrives
    (the classic duplicate-execution trap). The first N POSTs fail that way."""

    def __init__(self, inner: httpx.BaseTransport, failures: int) -> None:
        self.inner, self.failures, self.keys = inner, failures, []

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        inner = self.inner.handle_request(request)
        content = inner.read()  # the gateway has fully processed the request at this point
        if request.method == "POST" and request.url.path == "/v1/actions":
            self.keys.append(request.headers["Idempotency-Key"])
            if self.failures > 0:
                self.failures -= 1
                raise httpx.ReadError("connection reset after send", request=request)
        return httpx.Response(inner.status_code, headers=inner.headers, content=content)


def test_retry_after_lost_response_replays_one_action(gw: Any) -> None:
    flaky = FlakyAfterSend(gw.client._transport, failures=2)
    http = httpx.Client(base_url="http://testserver", transport=flaky)
    client = Client("http://testserver", gw.world.token, http_client=http, backoff=0.0)
    with pump(gw):
        out = client.call("test_echo", {"text": "exactly once"}, timeout=10)
    assert out.status == "COMPLETED" and out.result == {"echo": "exactly once"}
    assert len(set(flaky.keys)) == 1 and len(flaky.keys) == 3  # same key on every retry
    assert out.replayed is True
    with gw.engine.connect() as conn:
        n = conn.execute(
            select(func.count())
            .select_from(t.actions)
            .where(
                t.actions.c.agent_id == gw.world.agent_id,
                t.actions.c.idempotency_key == out.idempotency_key,
            )
        ).scalar_one()
    assert n == 1 and len(gw.spies.echo.calls) == 1  # non-idempotent tool ran once


def test_each_logical_call_gets_its_own_key(gw: Any) -> None:
    client = sdk(gw)
    with pump(gw):
        a = client.call("test_echo", {"text": "same args"}, timeout=10)
        b = client.call("test_echo", {"text": "same args"}, timeout=10)
    assert a.idempotency_key != b.idempotency_key and a.action_id != b.action_id
    assert len(gw.spies.echo.calls) == 2


def test_denied_maps_to_exception_with_reasons(gw: Any) -> None:
    with pytest.raises(Denied) as exc:
        sdk(gw).call("delete_record", {"record_id": "00000000-0000-0000-0000-000000000001"})
    assert "deny-delete-record" in exc.value.info["decision"]["matched_rule_ids"]
    assert exc.value.action_id and gw.spies.delete.calls == []


def test_approval_required_then_resume(gw: Any, migrator_engine: Engine) -> None:
    client = sdk(gw)
    with pytest.raises(ApprovalRequired) as exc:
        client.call("send_email", {"to": EXTERNAL, "subject": "s"}, approval_wait=0)
    assert exc.value.approval_id and gw.spies.email.calls == []  # nothing executed
    humans = make_humans(migrator_engine, gw.client, gw.world.tenant_id)
    assert decide(gw, humans, exc.value.approval_id).status_code == 200
    with pump(gw):
        out = client.wait(exc.value.action_id, timeout=10)
    assert out.status == "COMPLETED" and len(gw.spies.email.calls) == 1


def test_call_waits_for_a_human_approval(gw: Any, migrator_engine: Engine) -> None:
    client = sdk(gw)
    humans = make_humans(migrator_engine, gw.client, gw.world.tenant_id)
    result: dict[str, Any] = {}

    def agent() -> None:
        result["out"] = client.call(
            "send_email", {"to": EXTERNAL, "subject": "s"}, approval_wait=20, timeout=10
        )

    with pump(gw):
        th = threading.Thread(target=agent)
        th.start()
        approval_id = None
        for _ in range(100):
            r = gw.client.get("/v1/approvals?state=PENDING", headers=humans.headers("alice"))
            items = r.json()["approvals"]
            if items:
                approval_id = items[0]["approval_id"]
                break
            time.sleep(0.05)
        assert approval_id is not None
        assert decide(gw, humans, approval_id).status_code == 200
        th.join(timeout=30)
    assert result["out"].status == "COMPLETED"


def test_rejected_and_expired_approvals(gw: Any, migrator_engine: Engine) -> None:
    client = sdk(gw)
    humans = make_humans(migrator_engine, gw.client, gw.world.tenant_id)
    with pytest.raises(ApprovalRequired) as exc:
        client.call("send_email", {"to": EXTERNAL, "subject": "a"}, approval_wait=0)
    decide(gw, humans, exc.value.approval_id, decision="REJECT")
    with pytest.raises(Denied):
        client.wait(exc.value.action_id, timeout=2)
    with pytest.raises(ApprovalRequired) as exc2:
        client.call("send_email", {"to": EXTERNAL, "subject": "b"}, approval_wait=0)
    expire_now(migrator_engine, exc2.value.approval_id)
    gw.state.approvals.sweep()
    with pytest.raises(ApprovalExpired):
        client.wait(exc2.value.action_id, timeout=2)


def test_tool_failed_when_delegation_revoked_before_dispatch(
    gw: Any, migrator_engine: Engine
) -> None:
    child_id, child_token = new_agent(migrator_engine, gw.world.tenant_id, "child")
    d = delegate(gw, child_id)
    child = sdk(gw, child_token)
    with pytest.raises(StillRunning) as exc:  # authorized; nothing dispatches it (no pump)
        child.call("create_ticket", {"title": "t", "body": "b"}, delegation_token=d["token"],
                   timeout=0.3)  # fmt: skip
    sdk(gw).revoke_delegation(d["delegation_id"])
    gw.drain()
    with pytest.raises(ToolFailed) as failed:
        child.wait(exc.value.action_id, timeout=2)
    assert failed.value.error_code == "DELEGATION_INVALID" and gw.spies.ticket.calls == []


def test_outcome_unknown_mapping(gw: Any) -> None:
    with pytest.raises(OutcomeUnknown):
        Client._outcome({"action_id": "a", "status": "OUTCOME_UNKNOWN"}, "k", False, None)


def test_sources_are_recorded_as_context_provenance(gw: Any) -> None:
    from ..privacykit import event_id, payload

    client = sdk(gw)
    src = Source("corpus://incident-runbook.md", "ab" * 32)
    with pump(gw):
        out = client.call("test_echo", {"text": "x"}, sources=[src], timeout=10)
    p = payload(gw, event_id(gw, out.action_id, "ACTION_REQUESTED"))
    assert p is not None
    assert p["context"]["sources"] == [{"uri": src.uri, "digest": bytes.fromhex(src.sha256)}]


def test_sdk_never_shows_its_credential(gw: Any) -> None:
    client = sdk(gw)
    assert gw.world.token not in repr(client)
    d = Client("http://x", "agw_0000000000000000_" + "A" * 43)
    assert "agw_" not in repr(d)
