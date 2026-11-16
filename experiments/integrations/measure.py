"""Phase 8 (ADR-0030): integration effort (LOC per adapter) and added latency per tool call.

Same LOW idempotent tool (public_doc_search), same machine, N calls per path:
  direct     the adapter's execute() in-process (no gateway): the baseline
  sdk_decision_only  POST /v1/actions -> ALLOW decision committed (tx1), result not awaited
  sdk        agw_sdk.Client.call over real HTTP (uvicorn) -> gateway -> executor -> adapter
  langgraph  a LangChain StructuredTool from agw_langgraph (-> the SDK path)
  mcp        the MCP SDK's own client -> agw-mcp (streamable HTTP) -> SDK path
"Added latency" = median(path) - median(direct). The gateway path includes everything a
call costs: auth, validation, risk+policy, tx1 (evidence, encryption), the executor's claim /
dispatch / result transactions and the long-poll that returns the result.
Results: experiments/integrations/results/{latency.md,latency.json}. Needs Docker (Postgres).
"""

from __future__ import annotations

import asyncio
import io
import json
import statistics
import sys
import tempfile
import time
import tokenize
import uuid
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "apps" / "gateway"))
N = 60
WARMUP = 5
ARGS = {"query": "retention policy", "limit": 3}


def code_lines(paths: list[Path]) -> tuple[int, int]:
    """(code lines: non-blank, not comments, not docstrings; total lines)."""
    code = total = 0
    for p in paths:
        src = p.read_text()
        total += len(src.splitlines())
        lines: set[int] = set()
        prev = tokenize.INDENT
        for tok in tokenize.generate_tokens(io.StringIO(src).readline):
            if tok.type == tokenize.STRING and prev in (tokenize.INDENT, tokenize.NEWLINE,
                                                         tokenize.DEDENT, tokenize.NL):  # fmt: skip
                prev = tok.type
                continue  # a docstring / bare string statement
            if tok.type not in (tokenize.COMMENT, tokenize.NL, tokenize.NEWLINE, tokenize.INDENT,
                                tokenize.DEDENT, tokenize.ENCODING, tokenize.ENDMARKER):  # fmt: skip
                lines.update(range(tok.start[0], tok.end[0] + 1))
            prev = tok.type
        code += len(lines)
    return code, total


def stats(xs: list[float]) -> dict[str, float]:
    xs = sorted(xs)
    return {
        "median_ms": round(statistics.median(xs) * 1000, 2),
        "p95_ms": round(xs[int(len(xs) * 0.95) - 1] * 1000, 2),
        "min_ms": round(xs[0] * 1000, 2),
    }


def main() -> int:
    from fastapi.testclient import TestClient  # noqa: F401  (imports the stack)
    from langchain_core.tools import BaseTool
    from tests.conftest import CORPUS, init_database, make_settings, start_postgres
    from tests.servekit import free_port, serve

    from agw_gateway.admin import create_integration_client, create_key, ensure_agent, ensure_tenant
    from agw_gateway.api.app import build_state, create_app
    from agw_gateway.db import create_db_engine
    from agw_gateway.tools.adapters.public_doc_search import (
        PublicDocSearchAdapter,
        PublicDocSearchArgs,
    )
    from agw_gateway.tools.spec import ExecutionContext
    from agw_langgraph import gateway_tools
    from agw_mcp import AdapterConfig, build_app
    from agw_sdk import Client

    container = start_postgres()
    try:
        urls = init_database(container)
        app_engine = create_db_engine(urls.app, pool_size=10)
        mig = create_db_engine(urls.migrator, pool_size=2)
        tenant = "t-latency"
        ensure_tenant(mig, tenant, "latency")
        ensure_agent(mig, tenant, "bench", ("tools:public_doc_search",))
        token = create_key(mig, tenant, "bench")
        settings = make_settings(urls.app, Path(tempfile.mkdtemp()), executor_mode="inprocess",
                                 executor_poll_seconds=0.05)  # fmt: skip
        state = build_state(settings, engine=app_engine)
        state.sync()
        results: dict[str, list[float]] = {}

        # direct adapter (baseline)
        adapter, ctx = (
            PublicDocSearchAdapter(),
            ExecutionContext(uuid.uuid4(), tenant, 1, app_engine, Path(tempfile.mkdtemp()), CORPUS),
        )
        args = PublicDocSearchArgs(**ARGS)
        times = []
        for i in range(N + WARMUP):
            t0 = time.perf_counter()
            adapter.execute(args, ctx)
            if i >= WARMUP:
                times.append(time.perf_counter() - t0)
        results["direct"] = times

        port = free_port()
        mcp_url = f"http://127.0.0.1:{port}/mcp"
        with serve(create_app(state, sync_registry=False)) as gw_url:
            client = Client(gw_url, token)
            run = str(uuid.uuid4())

            def timed(fn: Any) -> list[float]:
                out = []
                for i in range(N + WARMUP):
                    t0 = time.perf_counter()
                    fn()
                    if i >= WARMUP:
                        out.append(time.perf_counter() - t0)
                return out

            # decision only: POST /v1/actions until the decision + tx1 evidence are committed
            results["sdk_decision_only"] = timed(
                lambda: client.submit_action(run_id=run, tool="public_doc_search", args=ARGS)
            )
            results["sdk"] = timed(lambda: client.call("public_doc_search", ARGS, run_id=run))
            tool: BaseTool = gateway_tools(client, run_id=run, only=["public_doc_search"])[0]
            results["langgraph"] = timed(lambda: tool.invoke(ARGS))

            cfg = AdapterConfig(gw_url, create_integration_client(mig, tenant, "bench", mcp_url),
                                mcp_url)  # fmt: skip
            mcp_token = create_key(mig, tenant, "bench", audience=mcp_url)
            with serve(build_app(cfg), port=port):
                import httpx2
                from mcp import Client as McpClient
                from mcp.client.streamable_http import streamable_http_client

                async def mcp_bench() -> list[float]:
                    out = []
                    h = {"Authorization": f"Bearer {mcp_token}"}
                    async with (
                        httpx2.AsyncClient(headers=h, timeout=30) as http,
                        McpClient(streamable_http_client(mcp_url, http_client=http)) as c,
                    ):
                        for i in range(N + WARMUP):
                            t0 = time.perf_counter()
                            r = await c.call_tool("public_doc_search", ARGS)
                            assert not r.is_error
                            if i >= WARMUP:
                                out.append(time.perf_counter() - t0)
                    return out

                results["mcp"] = asyncio.run(mcp_bench())
        state.executor.close()
    finally:
        container.stop()

    base = statistics.median(results["direct"])
    sdk = statistics.median(results["sdk"])
    summary = {k: stats(v) for k, v in results.items()}
    for k, v in summary.items():
        v["added_vs_direct_ms"] = round((statistics.median(results[k]) - base) * 1000, 2)
        v["added_vs_sdk_ms"] = round((statistics.median(results[k]) - sdk) * 1000, 2)
    loc = {
        "agw_sdk (client + errors)": code_lines(
            [REPO / "packages/gateway-sdk/src/agw_sdk" / f for f in ("client.py", "errors.py")]
        ),
        "agw_langgraph": code_lines(sorted((REPO / "integrations/langgraph/src").rglob("*.py"))),
        "agw_mcp": code_lines(sorted((REPO / "integrations/mcp/src").rglob("*.py"))),
        "example glue (agentlib graphs + multi_agent)": code_lines(
            [REPO / "examples/agentlib/graphs.py", REPO / "examples/agentlib/multi_agent.py"]
        ),
    }
    out_dir = REPO / "experiments/integrations/results"
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "latency.json").write_text(
        json.dumps(
            {"n": N, "warmup": WARMUP, "summary": summary, "loc": loc, "raw_seconds": results},
            indent=1,
        )
    )
    lines = [
        "# Integration effort and added latency (Phase 8, ADR-0030)",
        "",
        f"`make integration-latency`; N = {N} calls per path after {WARMUP} warm-up calls; one "
        "machine, localhost, Postgres in Docker, executor in-process. Hypothesis-free numbers "
        "for THIS setup only.",
        "",
        "| path | median ms | p95 ms | added vs direct ms | added vs SDK ms |",
        "|---|---|---|---|---|",
        *(
            f"| {k} | {v['median_ms']} | {v['p95_ms']} | {v['added_vs_direct_ms']} | "
            f"{v['added_vs_sdk_ms']} |"
            for k, v in summary.items()
        ),
        "",
        "Reading: the enforcement + evidence cost is `sdk_decision_only`. The rest of a full "
        "call is asynchronous execution plus the result long-poll, whose server loop re-checks "
        "every 0.25 s (`GET /v1/actions/{id}?wait=`), which dominates the full-call numbers. "
        "LangGraph adds no measurable overhead over the SDK; MCP adds one protocol hop.",
        "",
        "| adapter | code lines | total lines (with docs) |",
        "|---|---|---|",
        *(f"| {k} | {c} | {t} |" for k, (c, t) in loc.items()),
    ]
    (out_dir / "latency.md").write_text("\n".join(lines) + "\n")
    print("\n".join(lines))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
