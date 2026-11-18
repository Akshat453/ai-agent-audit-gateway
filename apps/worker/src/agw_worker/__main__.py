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
from agw_worker.monitoring import Monitor, MonitorConfig
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


def build_monitor(settings: Settings, state: GatewayState) -> Monitor:
    return Monitor(
        engine=state.engine,
        writer=state.writer,
        config=MonitorConfig(
            max_events=settings.monitor_max_events,
            unanchored_alert_seconds=settings.monitor_unanchored_alert_seconds,
            unsealed_alert_seconds=settings.monitor_unsealed_alert_seconds,
            approval_queue_alert_seconds=settings.monitor_approval_queue_alert_seconds,
            alert_cooldown_seconds=settings.monitor_alert_cooldown_seconds,
            webhook_url=settings.monitor_webhook_url,
            webhook_secret=(
                settings.monitor_webhook_secret.get_secret_value()
                if settings.monitor_webhook_secret is not None
                else None
            ),
            chain_rpc_url=(
                settings.anchor_rpc_url.get_secret_value() if settings.anchor_rpc_url else None
            ),
            finality=settings.anchor_finality,
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
            if settings.seal_adaptive and settings.ablation not in ("C3", "C4")
            else SealPolicy.fixed(settings.epoch_max_events, settings.epoch_max_age_seconds)
        ),
    )
    if settings.worker_metrics_port is not None:
        start_http_server(settings.worker_metrics_port, addr="127.0.0.1")
    ab = settings.ablation  # Phase 10 ablation (ADR-0032): C1/C2 do not seal; C3 no anchoring
    periodic: list[tuple[float, Callable[[], object]]] = [
        *([] if ab in ("C1", "C2") else [(settings.sealer_interval_seconds, sealer.tick)]),
        (settings.approval_sweep_seconds, state.approvals.sweep),
    ]
    if state.retention is not None:
        periodic.append((settings.retention_sweep_seconds, state.retention.run_once))
    if state.anchor_gate is not None:
        periodic.append((settings.anchor_gate_sweep_seconds, state.anchor_gate.sweep_timeouts))
    # C3 (ADR-0036): GitHub polling mode (open PRs -> the AgentGuard evidence check).
    periodic.append((settings.github_poll_seconds, state.github_checks.poll_once))
    # Phase 9 (ADR-0031): monitoring evidence stream; dashboard requests are picked up fast.
    monitor = build_monitor(settings, state)
    # C3: a TAMPERED / INCOMPLETE report flips the evidence check of open PRs.
    monitor.on_report = lambda rep: state.github_checks.on_monitor_report(
        rep.tenant, rep.result, rep.report_id
    )
    periodic.append((1.0, monitor.process_requests))
    periodic.append((settings.monitor_interval_seconds, monitor.run_once))
    anchorer = build_anchorer(settings, state) if ab not in ("C1", "C2", "C3") else None
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
