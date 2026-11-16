"""Gateway tools for LangGraph / LangChain (see package docstring)."""

from __future__ import annotations

import json
import threading
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any

from langchain_core.tools import BaseTool, StructuredTool, ToolException

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

MAX_SOURCES = 64


@dataclass
class Provenance:
    """Content the agent has READ in this run (uri + sha256), attached to later calls."""

    sources: list[Source] = field(default_factory=list)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def observe(self, tool: str, args: dict[str, Any], result: dict[str, Any]) -> None:
        found: list[Source] = []
        for hit in result.get("results", []) if isinstance(result.get("results"), list) else []:
            if isinstance(hit, dict) and _is_hex64(hit.get("sha256")):
                found.append(Source(str(hit.get("uri") or hit.get("id")), str(hit["sha256"])))
        if _is_hex64(result.get("sha256")):
            found.append(Source(str(args.get("url") or f"tool://{tool}"), str(result["sha256"])))
        with self._lock:
            for s in found:
                if s not in self.sources:
                    self.sources.append(s)
            del self.sources[:-MAX_SOURCES]

    def snapshot(self) -> list[Source]:
        with self._lock:
            return list(self.sources)


def _is_hex64(v: Any) -> bool:
    return isinstance(v, str) and len(v) == 64 and all(c in "0123456789abcdef" for c in v)


@dataclass
class GatewayToolkit:
    client: Client
    run_id: str
    delegation_token: str | None = None
    environment: str = "dev"
    approval_wait: float = 300.0
    timeout: float = 60.0
    provenance: Provenance = field(default_factory=Provenance)
    calls: list[dict[str, Any]] = field(default_factory=list)  # outcome log (no arg values)

    def invoke(self, tool: str, args: dict[str, Any]) -> str:
        try:
            out = self.client.call(
                tool,
                args,
                run_id=self.run_id,
                environment=self.environment,
                delegation_token=self.delegation_token,
                sources=self.provenance.snapshot(),
                approval_wait=self.approval_wait,
                timeout=self.timeout,
            )
        except Denied as exc:
            self._log(tool, exc.action_id, "DENIED", exc.reasons)
            raise ToolException(
                f"DENIED by gateway policy (not executed). reasons={exc.reasons} "
                f"action_id={exc.action_id}"
            ) from None
        except ApprovalRequired as exc:
            self._log(tool, exc.action_id, "PENDING_APPROVAL", [])
            raise ToolException(
                "PENDING_APPROVAL: a human must approve this action; it has NOT been executed. "
                f"action_id={exc.action_id}"
            ) from None
        except (ApprovalExpired, ToolFailed, OutcomeUnknown, StillRunning) as exc:
            self._log(tool, exc.action_id, exc.status, [str(exc.info.get("error_code") or "")])
            raise ToolException(f"{exc.status}: action_id={exc.action_id}") from None
        self._log(tool, out.action_id, out.status, [])
        self.provenance.observe(tool, args, out.result)
        return json.dumps({"status": out.status, "action_id": out.action_id, "result": out.result})

    def _log(self, tool: str, action_id: str, status: str, reasons: list[str]) -> None:
        self.calls.append(
            {"tool": tool, "action_id": action_id, "status": status, "reasons": reasons}
        )

    def tools(self, only: Sequence[str] | None = None) -> list[BaseTool]:
        out: list[BaseTool] = []
        for spec in self.client.list_tools():
            name = str(spec["tool_id"])
            if only is not None and name not in only:
                continue
            schema = dict(spec["args_schema"])
            schema.pop("title", None)

            def run(_tool: str = name, **kwargs: Any) -> str:
                return self.invoke(_tool, kwargs)

            out.append(
                StructuredTool.from_function(
                    func=run,
                    name=name,
                    description=(
                        f"{spec['operation_type']} tool '{name}' executed by the audit gateway "
                        "(policy, approvals and evidence apply)."
                    ),
                    args_schema=schema,
                    handle_tool_error=True,  # denials reach the model as tool errors
                )
            )
        return out


def gateway_tools(
    client: Client,
    *,
    run_id: str,
    delegation_token: str | None = None,
    only: Sequence[str] | None = None,
    approval_wait: float = 300.0,
    timeout: float = 60.0,
) -> list[BaseTool]:
    return GatewayToolkit(
        client,
        run_id,
        delegation_token=delegation_token,
        approval_wait=approval_wait,
        timeout=timeout,
    ).tools(only)
