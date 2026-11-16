"""OpenTelemetry traces with an attribute ALLOWLIST (Phase 9, ADR-0031 §6).

Off unless ``AGW_OTEL_ENABLED=true`` (then: OTLP/HTTP to ``AGW_OTEL_ENDPOINT``, or the
console). Two layers keep args/results/payloads out of traces:

1. ``span(name, **attrs)`` keeps only allowlisted keys with scalar values (ids, codes,
   enums) - the same allow-list as the structured logs (11 §2).
2. ``AllowlistExporter`` wraps the real exporter and drops every attribute, event and link
   attribute not on the list before anything leaves the process, so a span created by any
   other library cannot leak either.
No automatic HTTP instrumentation is installed (it would record URLs/headers).
"""

from __future__ import annotations

import contextlib
from collections.abc import Iterator, Sequence
from typing import Any, Final

from opentelemetry import trace
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import ReadableSpan, TracerProvider
from opentelemetry.sdk.trace.export import (
    BatchSpanProcessor,
    ConsoleSpanExporter,
    SimpleSpanProcessor,
    SpanExporter,
    SpanExportResult,
)

ALLOWED_ATTRIBUTES: Final = frozenset(
    {
        "agw.request_id",
        "agw.tenant_id",
        "agw.agent_id",
        "agw.human_id",
        "agw.tool_id",
        "agw.action_id",
        "agw.decision",
        "agw.status",
        "agw.risk_level",
        "agw.error_code",
        "agw.result",
        "agw.events_checked",
        "http.method",
        "http.route",
        "http.status_code",
    }
)
_TRACER: Final = "agw"


def _clean(attrs: Any) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for k, v in dict(attrs or {}).items():
        if k in ALLOWED_ATTRIBUTES and isinstance(v, str | int | bool) and len(str(v)) <= 128:
            out[k] = v
    return out


class AllowlistExporter(SpanExporter):
    """Re-creates each span with only allowlisted attributes and no events/links."""

    def __init__(self, inner: SpanExporter) -> None:
        self._inner = inner

    def export(self, spans: Sequence[ReadableSpan]) -> SpanExportResult:
        cleaned = [
            ReadableSpan(
                name=s.name,
                context=s.context,
                parent=s.parent,
                resource=s.resource,
                attributes=_clean(s.attributes),
                events=(),
                links=(),
                kind=s.kind,
                status=s.status,
                start_time=s.start_time,
                end_time=s.end_time,
                instrumentation_scope=s.instrumentation_scope,
            )
            for s in spans
        ]
        return self._inner.export(cleaned)

    def shutdown(self) -> None:
        self._inner.shutdown()

    def force_flush(self, timeout_millis: int = 30000) -> bool:
        return self._inner.force_flush(timeout_millis)


def configure(
    *, enabled: bool, endpoint: str | None = None, service: str = "agw-gateway",
    exporter: SpanExporter | None = None,
) -> TracerProvider | None:  # fmt: skip
    """Install a provider once per process. ``exporter`` (tests) is exported synchronously."""
    if not enabled:
        return None
    provider = TracerProvider(resource=Resource.create({"service.name": service}))
    if exporter is not None:
        provider.add_span_processor(SimpleSpanProcessor(AllowlistExporter(exporter)))
    elif endpoint:
        provider.add_span_processor(
            BatchSpanProcessor(AllowlistExporter(OTLPSpanExporter(endpoint=endpoint)))
        )
    else:
        provider.add_span_processor(BatchSpanProcessor(AllowlistExporter(ConsoleSpanExporter())))
    trace.set_tracer_provider(provider)
    return provider


@contextlib.contextmanager
def span(name: str, **attrs: Any) -> Iterator[Any]:
    """``attrs`` keys use ``_`` for ``.`` (``agw_tool_id`` -> ``agw.tool_id``)."""
    clean = _clean({k.replace("_", ".", 1): v for k, v in attrs.items() if v is not None})
    with trace.get_tracer(_TRACER).start_as_current_span(name, attributes=clean) as s:
        yield s


def set_attrs(s: Any, **attrs: Any) -> None:
    for k, v in _clean(
        {k.replace("_", ".", 1): v for k, v in attrs.items() if v is not None}
    ).items():
        s.set_attribute(k, v)
