"""FastAPI application factory."""

from __future__ import annotations

import logging
import time
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from datetime import timedelta

from fastapi import FastAPI, Request, Response
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest
from sqlalchemy import Engine

from agw_gateway import __version__
from agw_gateway.anchoring import AnchorGate, Finality, GatePolicy
from agw_gateway.api.approval_routes import router as approval_router
from agw_gateway.api.dashboard_routes import router as dashboard_router
from agw_gateway.api.delegation_routes import router as delegation_router
from agw_gateway.api.disclosure_routes import router as disclosure_router
from agw_gateway.api.errors import install_error_handlers, unexpected_error_response
from agw_gateway.api.routes import router
from agw_gateway.api.state import GatewayState
from agw_gateway.approvals.service import ApprovalConfig, ApprovalService
from agw_gateway.approvals.signing import DecisionSigner, SigningKeyUnavailable
from agw_gateway.auth import Authenticator
from agw_gateway.auth.exchange import TokenExchange
from agw_gateway.config import Settings, get_settings
from agw_gateway.db import create_db_engine
from agw_gateway.delegation.service import DelegationService, load_delegation_signer
from agw_gateway.evidence import EvidenceWriter
from agw_gateway.evidence.blobs import BlobStore, S3BlobStore
from agw_gateway.evidence.payloads import EncryptedPayloadStore, NoPayloadStore, PayloadStore
from agw_gateway.execution.crash import CrashPoints
from agw_gateway.execution.executor import Executor
from agw_gateway.execution.manual_reconcile import ManualReconciliation
from agw_gateway.execution.reconciler import Reconciler
from agw_gateway.execution.runner import BackgroundRunner
from agw_gateway.execution.service import ActionService
from agw_gateway.humans import HumanAuthenticator
from agw_gateway.ids import uuid7
from agw_gateway.keys import KeyProvider, KeyUnavailable, LocalKeyProvider, VaultTransitKeyProvider
from agw_gateway.logs import configure_logging, log
from agw_gateway.privacy.cipher import EnvelopeCipher
from agw_gateway.privacy.disclosure import DisclosureService
from agw_gateway.privacy.minimize import Minimizer
from agw_gateway.privacy.retention import RetentionJob
from agw_gateway.provenance import resolve_build_commit
from agw_gateway.risk_store import RiskPolicyStore
from agw_gateway.tools.adapters.external import external_tool_specs
from agw_gateway.tools.demo import demo_tool_specs
from agw_gateway.tools.registry import ToolRegistry
from agw_gateway.tracing import configure as configure_tracing
from agw_gateway.tracing import set_attrs, span

logger = logging.getLogger("agw.api.access")


def load_signer(settings: Settings) -> DecisionSigner | None:
    """None -> approval decisions fail closed (503); everything else keeps working."""
    if settings.approval_signing_key_file is None:
        log(logger, logging.WARNING, "approval signing key not configured")
        return None
    try:
        return DecisionSigner.from_file(settings.approval_signing_key_file)
    except SigningKeyUnavailable:
        log(logger, logging.ERROR, "approval signing key unusable", error_code="SIGNING_KEY")
        return None


def load_key_provider(settings: Settings) -> KeyProvider | None:
    """None -> events with payloads fail closed (503); /v1/ready reports not ready."""
    try:
        if settings.key_provider == "vault":
            if not settings.vault_addr or settings.vault_token is None:
                raise KeyUnavailable("vault not configured")
            vault = VaultTransitKeyProvider(
                settings.vault_addr,
                settings.vault_token.get_secret_value(),
                settings.vault_transit_key,
            )
            _ = vault.active_version  # probe once at startup
            return vault
        if settings.kek_dir is None:
            raise KeyUnavailable("AGW_KEK_DIR not set")
        return LocalKeyProvider.from_dir(
            settings.kek_dir, settings.kek_id, settings.kek_active_version
        )
    except KeyUnavailable:
        log(logger, logging.ERROR, "KEK unavailable: payload writes fail closed",
            error_code="KEK_UNAVAILABLE")  # fmt: skip
        return None


def load_blob_store(settings: Settings) -> S3BlobStore | None:
    if settings.blob_endpoint is None:
        return None
    if settings.blob_access_key is None or settings.blob_secret_key is None:
        log(logger, logging.ERROR, "blob store credentials missing", error_code="BLOB_CONFIG")
        return None
    return S3BlobStore(
        endpoint=settings.blob_endpoint,
        access_key=settings.blob_access_key.get_secret_value(),
        secret_key=settings.blob_secret_key.get_secret_value(),
        bucket=settings.blob_bucket,
        secure=settings.blob_secure,
    )


def build_state(
    settings: Settings,
    *,
    engine: Engine | None = None,
    registry: ToolRegistry | None = None,
    crash: CrashPoints | None = None,
    key_provider: KeyProvider | None = None,
    blob_store: BlobStore | None = None,
) -> GatewayState:
    engine = engine or create_db_engine(
        settings.database_url.get_secret_value(),
        connect_timeout=settings.db_connect_timeout_seconds,
    )
    registry = registry or ToolRegistry([*demo_tool_specs(), *external_tool_specs(settings)])
    crash = crash or CrashPoints(settings.env)
    provider = load_key_provider(settings) if key_provider is None else key_provider
    blobs = load_blob_store(settings) if blob_store is None else blob_store
    payloads: PayloadStore = (
        EncryptedPayloadStore(provider, blobs, settings.payload_blob_threshold_bytes)
        if provider is not None
        else NoPayloadStore()
    )
    cipher = EnvelopeCipher(provider) if provider is not None else None
    minimizer = Minimizer(provider) if provider is not None else None
    writer = EvidenceWriter(payloads)
    encrypted = payloads if isinstance(payloads, EncryptedPayloadStore) else None
    disclosure = (
        DisclosureService(
            engine=engine,
            writer=writer,
            store=encrypted,
            max_events=settings.disclosure_max_events,
        )
        if encrypted is not None
        else None
    )
    build_commit = resolve_build_commit(settings.build_commit)
    delegations = DelegationService(
        engine=engine,
        writer=writer,
        registry=registry,
        signer=load_delegation_signer(settings.delegation_signing_key_file),
        max_depth=settings.delegation_max_depth,
        max_ttl=timedelta(seconds=settings.delegation_max_ttl_seconds),
    )
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
        cipher=cipher,
        minimizer=minimizer,
        delegations=delegations,
    )
    reconciler = Reconciler(engine=engine, registry=registry, writer=writer)
    retention = (
        RetentionJob(engine=engine, store=encrypted, writer=writer, registry=registry, blobs=blobs)
        if encrypted is not None
        else None
    )
    risk_policies = RiskPolicyStore(engine, settings.risk_policy_id)
    runners: list[BackgroundRunner] = []

    def nudge_runners() -> None:
        for r in runners:
            r.nudge()

    gate_policy = GatePolicy(
        rules=frozenset(settings.pre_anchor_rules),
        timeout_seconds=settings.critical_anchor_timeout_seconds,
    )
    anchor_gate = AnchorGate(
        engine=engine, writer=writer, finality_label=Finality.parse(settings.anchor_finality).label
    )
    approval_config = ApprovalConfig(
        ttl_seconds={
            "LOW": settings.approval_ttl_seconds_medium,
            "MEDIUM": settings.approval_ttl_seconds_medium,
            "HIGH": settings.approval_ttl_seconds_high,
            "CRITICAL": settings.approval_ttl_seconds_critical,
        },
        four_eyes_critical=settings.approval_four_eyes_critical,
        step_up_levels=frozenset(settings.step_up_levels),
        step_up_window_seconds=settings.step_up_window_seconds,
    )
    approvals = ApprovalService(
        config=approval_config,
        engine=engine,
        registry=registry,
        writer=writer,
        risk_policies=risk_policies,
        signer=load_signer(settings),
        build_commit=build_commit,
        on_authorized=nudge_runners,
        gate=gate_policy,
        cipher=cipher,
        minimizer=minimizer,
        delegations=delegations,
    )
    runner = None
    if settings.executor_mode == "inprocess":
        runner = BackgroundRunner(
            executor,
            reconciler,
            poll_seconds=settings.executor_poll_seconds,
            reconcile_seconds=settings.reconciler_interval_seconds,
            periodic=[
                (settings.approval_sweep_seconds, approvals.sweep),
                (settings.anchor_gate_sweep_seconds, anchor_gate.tick),
                *(
                    [(settings.retention_sweep_seconds, retention.run_once)]
                    if retention is not None
                    else []
                ),
            ],
        )
        runners.append(runner)
    actions = ActionService(
        engine=engine,
        registry=registry,
        writer=writer,
        crash=crash,
        tx1_statement_timeout_ms=settings.tx1_statement_timeout_ms,
        idempotency_ttl=timedelta(hours=settings.idempotency_ttl_hours),
        on_authorized=runner.nudge if runner else None,
        build_commit=build_commit,
        risk_policies=risk_policies,
        gate=gate_policy,
        cipher=cipher,
        minimizer=minimizer,
        delegations=delegations,
        approval_config=approval_config,
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
        approvals=approvals,
        humans=HumanAuthenticator(
            engine, session_ttl=timedelta(minutes=settings.human_session_ttl_minutes)
        ),
        runner=runner,
        anchor_gate=anchor_gate,
        key_provider=provider,
        payloads=payloads,
        disclosure=disclosure,
        retention=retention,
        blobs=blobs,
        cipher=cipher,
        minimizer=minimizer,
        delegations=delegations,
        reconciliation=ManualReconciliation(engine, writer),
        writer=writer,
        exchange=TokenExchange(engine, timedelta(seconds=settings.exchange_token_ttl_seconds)),
    )


def create_app(state: GatewayState | None = None, *, sync_registry: bool = True) -> FastAPI:
    if state is None:
        settings = get_settings()
        configure_logging(settings.log_level)
        configure_tracing(enabled=settings.otel_enabled, endpoint=settings.otel_endpoint)
        state = build_state(settings)

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        if sync_registry:
            state.sync()  # changed tool spec / risk policy without version bump -> startup error
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
    app.include_router(approval_router)
    app.include_router(disclosure_router)
    app.include_router(delegation_router)
    app.include_router(dashboard_router)

    @app.get("/metrics", include_in_schema=False)
    def metrics() -> Response:
        # Operational counters only (bounded enum labels; no ids, args or payloads).
        # Restrict at the network layer in deployments (ADR-0026).
        return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)

    @app.middleware("http")
    async def request_id_mw(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        rid = str(uuid7())
        request.state.request_id = rid
        started = time.perf_counter()
        # Phase 9: one span per request; allowlisted attributes only (tracing.py).
        with span("http.request", http_method=request.method, agw_request_id=rid) as sp:
            try:
                response = await call_next(request)
            except Exception as exc:  # fail closed: DB down -> 503, else 500, no details
                response = unexpected_error_response(request, exc)
            route = request.scope.get("route")
            set_attrs(
                sp,
                http_route=getattr(route, "path", None),
                http_status_code=response.status_code,
                agw_agent_id=getattr(request.state, "agent_id", None),
                agw_human_id=getattr(request.state, "human_id", None),
            )
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
