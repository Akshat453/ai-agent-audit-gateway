"""Structured logging with a field allow-list (11 §2, threat T24).

Only allow-listed fields are ever emitted. Tool args, arg values, API keys and payloads are
never passed to the logger by gateway code, and this filter drops anything else that slips in.
"""

from __future__ import annotations

import json
import logging
from typing import Any, Final

ALLOWED_FIELDS: Final = frozenset(
    {
        "request_id",
        "agent_id",
        "tenant_id",
        "tool_id",
        "action_id",
        "decision",
        "status",
        "error_code",
        "latency_ms",
        "job_id",
        "worker_id",
        "event",
    }
)


class AllowListJsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        fields = getattr(record, "agw_fields", {})
        out: dict[str, Any] = {
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage() if record.name.startswith("agw") else record.msg,
        }
        out.update({k: v for k, v in fields.items() if k in ALLOWED_FIELDS})
        if record.exc_info and record.exc_info[0] is not None:
            out["exc_type"] = record.exc_info[0].__name__  # type only, never the message
        return json.dumps(out, default=str)


def log(logger: logging.Logger, level: int, msg: str, **fields: Any) -> None:
    safe = {k: v for k, v in fields.items() if k in ALLOWED_FIELDS}
    logger.log(level, msg, extra={"agw_fields": safe})


def configure_logging(level: str) -> None:
    handler = logging.StreamHandler()
    handler.setFormatter(AllowListJsonFormatter())
    root = logging.getLogger("agw")
    root.handlers[:] = [handler]
    root.setLevel(level)
    root.propagate = True
