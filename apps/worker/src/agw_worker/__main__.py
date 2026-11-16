"""``python -m agw_worker``: outbox executor + reconciler + risk-adaptive sealer + approval
expiry sweeper (Phase 5) + anchor worker and CRITICAL anchor-gate sweeper (Phase 6), out of
process. Anchoring runs only if AGW_ANCHOR_RPC_URL is set; the gate sweeper always runs, so a
pre-anchored CRITICAL action fails closed (ANCHOR_TIMEOUT) when nothing anchors it.

Set ``AGW_WORKER_METRICS_PORT`` to expose Prometheus metrics on 127.0.0.1:<port>/metrics.
"""

from __future__ import annotations

import signal
from collections.abc import Callable

from prometheus_client import start_http_server

from agw_gateway.anchoring import Finality
from agw_gateway.api.app import build_state
from agw_gateway.api.state import GatewayState
from agw_gateway.config import Settings, get_settings
from agw_gateway.evidence import EvidenceWriter
from agw_gateway.execution.runner import BackgroundRunner
from agw_gateway.logs import configure_logging
from agw_worker.anchoring import Anchorer, AnchorerConfig
from agw_worker.anchoring.admin import read_key
from agw_worker.anchoring.evm import EvmAnchorBackend
from agw_worker.sealing import Sealer
from agw_worker.sealing.policy import SealPolicy


def build_anchorer(settings: Settings, state: GatewayState) -> Anchorer | None:
    if settings.anchor_rpc_url is None:
        return None
    key = (
        read_key(settings.anchor_submitter_key_file)
        if settings.anchor_submitter_key_file is not None
        else None
    )
    backend = EvmAnchorBackend(
        rpc_url=settings.anchor_rpc_url.get_secret_value(),
        chain_id=int(settings.anchor_chain_id or 0),
        contract=str(settings.anchor_contract),
        private_key=key,
        gas_limit=settings.anchor_gas_limit,
    )
    return Anchorer(
        engine=state.engine,
        backend=backend,
        gate=state.anchor_gate,
        crash=state.crash,
        config=AnchorerConfig(
            finality=Finality.parse(settings.anchor_finality),
            routine_delay_seconds=settings.anchor_routine_delay_seconds,
            max_inflight=settings.anchor_max_inflight,
            rebroadcast_seconds=settings.anchor_rebroadcast_seconds,
            max_attempts=settings.anchor_max_attempts,
            backoff_max_seconds=settings.anchor_backoff_max_seconds,
            alert_age_seconds=settings.anchor_alert_age_seconds,
        ),
    )


def main() -> None:
    settings = get_settings()
    configure_logging(settings.log_level)
    state = build_state(settings)
    state.sync()
    sealer = Sealer(
        engine=state.engine,
        writer=EvidenceWriter(),
        crash=state.crash,
        policy=(
            SealPolicy.adaptive(
                low_max_events=settings.epoch_max_events,
                low_max_age_seconds=settings.epoch_max_age_seconds,
                medium_max_events=settings.epoch_medium_max_events,
                medium_max_age_seconds=settings.epoch_medium_max_age_seconds,
                count_basis=settings.seal_count_basis,
            )
            if settings.seal_adaptive
            else SealPolicy.fixed(settings.epoch_max_events, settings.epoch_max_age_seconds)
        ),
    )
    if settings.worker_metrics_port is not None:
        start_http_server(settings.worker_metrics_port, addr="127.0.0.1")
    periodic: list[tuple[float, Callable[[], object]]] = [
        (settings.sealer_interval_seconds, sealer.tick),
        (settings.approval_sweep_seconds, state.approvals.sweep),
    ]
    if state.retention is not None:
        periodic.append((settings.retention_sweep_seconds, state.retention.run_once))
    if state.anchor_gate is not None:
        periodic.append((settings.anchor_gate_sweep_seconds, state.anchor_gate.sweep_timeouts))
    anchorer = build_anchorer(settings, state)
    if anchorer is not None:
        periodic.append((settings.anchor_poll_seconds, anchorer.tick))
    runner = BackgroundRunner(
        state.executor,
        state.reconciler,
        poll_seconds=min(settings.executor_poll_seconds, settings.sealer_interval_seconds),
        reconcile_seconds=settings.reconciler_interval_seconds,
        periodic=periodic,
    )
    signal.signal(signal.SIGTERM, lambda *_: runner.stop())
    try:
        runner.run_forever()
    except KeyboardInterrupt:
        runner.stop()


if __name__ == "__main__":
    main()
