"""Phase 7 canary leak test (ADR-0029 §10): a secret injected into tool args never appears in
logs, metrics, error responses, response headers or evidence headers.

Two canaries per run: SECRET (a field classified ``secret``) and CONF (fields classified
confidential, plus free values in invalid / unknown-tool / malformed requests). Neither may show
up anywhere an operator, a log pipeline or an agent can read without the KEK. (Tracing: only the
OpenTelemetry API is installed, no SDK/exporter; the test asserts that.)
"""

from __future__ import annotations

import importlib.util
import json
import logging
import uuid
from typing import Any

import pytest

from agw_gateway.logs import AllowListJsonFormatter
from agw_gateway.tools.spec import ToolResult

from ..conftest import Gw
from ..privacykit import canary, headers_blob

pytestmark = pytest.mark.e2e


class Capture(logging.Handler):
    """Everything any logger emits: message, args, extra fields and exception text."""

    def __init__(self) -> None:
        super().__init__(level=logging.DEBUG)
        self.chunks: list[str] = []
        self._fmt = AllowListJsonFormatter()
        self._plain = logging.Formatter()

    def emit(self, record: logging.LogRecord) -> None:
        self.chunks.append(self._fmt.format(record))
        self.chunks.append(str(record.msg) + repr(record.args))
        self.chunks.append(repr(getattr(record, "agw_fields", {})))
        if record.exc_info:
            self.chunks.append(self._plain.formatException(record.exc_info))


def test_canary_never_leaks(gw: Gw, migrator_engine: Any) -> None:
    from ..approvalkit import decide, make_humans

    secret, conf = canary("SECRET"), canary("CONF")
    cap = Capture()
    root = logging.getLogger()
    old_level = root.level
    root.addHandler(cap)
    root.setLevel(logging.DEBUG)
    responses: list[Any] = []
    try:
        post = lambda *a, **k: responses.append(gw.post(*a, **k)) or responses[-1]  # noqa: E731
        # 1) allowed, executed: secret arg and secret/confidential results
        post("test_secret_tool", {"endpoint": "e", "api_token": secret, "note": conf})
        gw.drain()

        # 2) the adapter raises with the secret in its message (executor logs the type only)
        def boom(args: Any, ctx: Any) -> ToolResult:
            raise RuntimeError(f"upstream rejected token {args.api_token} for {args.note}")

        gw.spies.secret.behavior = boom
        post("test_secret_tool", {"endpoint": "e", "api_token": secret, "note": conf})
        gw.drain()
        # 3) invalid args, unknown tool, extra envelope field, malformed JSON
        post("public_doc_search", {"query": conf, "limit": secret})
        post("no_such_tool", {"token": secret, "x": conf})
        post("test_echo", {"text": "x"}, reasoning=secret)
        responses.append(
            gw.client.post(
                "/v1/actions",
                content=b'{"tool": "test_echo", "args": {"text": "' + secret.encode() + b'"',
                headers=gw.headers(),
            )
        )
        # 3b) FastAPI-validated bodies (human endpoints): the invalid value is the canary
        responses.append(
            gw.client.post(
                "/v1/auth/login", json={"tenant": secret, "username": conf, "password": secret}
            )
        )
        # 4) idempotency conflict with a different body carrying the canary
        key = f"k-{uuid.uuid4().hex}"
        post("test_echo", {"text": "first"}, key=key)
        post("test_echo", {"text": conf}, key=key)
        # 5) approval path (approver sees confidential args by design; secret stays a marker)
        humans = make_humans(migrator_engine, gw.client, gw.world.tenant_id)
        em = post("send_email", {"to": ["x@partner.example"], "subject": conf, "body": secret})
        decide(gw, humans, em.json()["approval"]["approval_id"])
        gw.drain()
        # 6) agent-visible reads
        for r in list(responses):
            aid = r.json().get("action_id") if r.status_code in (200, 201) else None
            if aid:
                responses.append(gw.client.get(f"/v1/actions/{aid}", headers=gw.headers()))
                responses.append(
                    gw.client.get("/v1/events", params={"action_id": aid}, headers=gw.headers())
                )
        metrics = gw.client.get("/metrics").text
    finally:
        root.removeHandler(cap)
        root.setLevel(old_level)

    assert any(r.status_code == 422 for r in responses)  # error paths really ran
    assert any(r.status_code == 409 for r in responses)
    assert gw.action_status(responses[1].json()["action_id"]) == "FAILED"
    surfaces = {
        "logs": "\n".join(cap.chunks),
        "metrics": metrics,
        "responses": "\n".join(r.text for r in responses),
        "response_headers": "\n".join(json.dumps(dict(r.headers)) for r in responses),
        "evidence_headers": headers_blob(gw).decode("latin-1"),
    }
    assert len(cap.chunks) > 20 and surfaces["evidence_headers"]
    leaks = {
        name: [label for label, v in (("SECRET", secret), ("CONF", conf)) if v in text]
        for name, text in surfaces.items()
    }
    assert leaks == {name: [] for name in surfaces}, leaks
    # Traces: the OpenTelemetry API is present (a FastAPI/Starlette dependency) but no SDK or
    # exporter is configured, so spans go to the no-op proxy provider: nothing to leak into.
    if importlib.util.find_spec("opentelemetry.trace") is not None:
        from opentelemetry import trace

        assert type(trace.get_tracer_provider()).__name__ == "ProxyTracerProvider"
        assert importlib.util.find_spec("opentelemetry.sdk") is None
