"""FastAPI application factory."""

from __future__ import annotations

import logging
import time
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from datetime import timedelta

from fastapi import FastAPI, Request, Response
from sqlalchemy import Engine

from agw_gateway import __version__
from agw_gateway.api.errors import install_error_handlers, unexpected_error_response
from agw_gateway.api.routes import router
from agw_gateway.api.state import GatewayState
from agw_gateway.auth import Authenticator
from agw_gateway.config import Settings, get_settings
from agw_gateway.db import create_db_engine
from agw_gateway.evidence import EvidenceWriter
from agw_gateway.execution.crash import CrashPoints
from agw_gateway.execution.executor import Executor
from agw_gateway.execution.reconciler import Reconciler
from agw_gateway.execution.runner import BackgroundRunner
from agw_gateway.execution.service import ActionService
from agw_gateway.ids import uuid7
from agw_gateway.logs import configure_logging, log
from agw_gateway.tools.demo import demo_tool_specs
from agw_gateway.tools.registry import ToolRegistry

logger = logging.getLogger("agw.api.access")


def build_state(
    settings: Settings,
    *,
    engine: Engine | None = None,
    registry: ToolRegistry | None = None,
    crash: CrashPoints | None = None,
) -> GatewayState:
    engine = engine or create_db_engine(
        settings.database_url.get_secret_value(),
        connect_timeout=settings.db_connect_timeout_seconds,
    )
    registry = registry or ToolRegistry(demo_tool_specs())
    crash = crash or CrashPoints(settings.env)
    writer = EvidenceWriter()
    executor = Executor(
        engine=engine,
        registry=registry,
        writer=writer,
        crash=crash,
        sandbox_dir=settings.demo_sandbox_dir,
        corpus_dir=settings.demo_corpus_dir,
        lease=timedelta(seconds=settings.lease_seconds),
        adapter_timeout_seconds=settings.adapter_timeout_seconds,
        batch=settings.executor_batch,
    )
    reconciler = Reconciler(engine=engine, registry=registry, writer=writer)
    runner = None
    if settings.executor_mode == "inprocess":
        runner = BackgroundRunner(
            executor,
            reconciler,
            poll_seconds=settings.executor_poll_seconds,
            reconcile_seconds=settings.reconciler_interval_seconds,
        )
    actions = ActionService(
        engine=engine,
        registry=registry,
        writer=writer,
        crash=crash,
        tx1_statement_timeout_ms=settings.tx1_statement_timeout_ms,
        idempotency_ttl=timedelta(hours=settings.idempotency_ttl_hours),
        on_authorized=runner.nudge if runner else None,
    )
    return GatewayState(
        settings=settings,
        engine=engine,
        registry=registry,
        authenticator=Authenticator(engine),
        actions=actions,
        executor=executor,
        reconciler=reconciler,
        crash=crash,
        runner=runner,
    )


def create_app(state: GatewayState | None = None, *, sync_registry: bool = True) -> FastAPI:
    if state is None:
        settings = get_settings()
        configure_logging(settings.log_level)
        state = build_state(settings)

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        if sync_registry:
            state.registry.sync(state.engine)  # changed spec without version bump -> startup error
        if state.runner is not None:
            state.runner.start()
        try:
            yield
        finally:
            if state.runner is not None:
                state.runner.stop()
            state.executor.close()

    app = FastAPI(
        title="AI Agent Audit Gateway",
        version=__version__,
        lifespan=lifespan,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    app.state.agw = state
    install_error_handlers(app)
    app.include_router(router)

    @app.middleware("http")
    async def request_id_mw(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        rid = str(uuid7())
        request.state.request_id = rid
        started = time.perf_counter()
        try:
            response = await call_next(request)
        except Exception as exc:  # fail closed: DB down -> 503, anything else -> 500, no details
            response = unexpected_error_response(request, exc)
        response.headers["X-Request-Id"] = rid
        log(
            logger,
            logging.INFO,
            "request",
            request_id=rid,
            agent_id=getattr(request.state, "agent_id", None),
            status=response.status_code,
            latency_ms=round((time.perf_counter() - started) * 1000, 2),
        )
        return response

    return app
