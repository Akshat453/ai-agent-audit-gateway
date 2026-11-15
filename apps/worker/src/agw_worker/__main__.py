"""``python -m agw_worker``: run the outbox executor + reconciler loop out of process."""

from __future__ import annotations

import signal

from agw_gateway.api.app import build_state
from agw_gateway.config import get_settings
from agw_gateway.evidence import EvidenceWriter
from agw_gateway.execution.runner import BackgroundRunner
from agw_gateway.logs import configure_logging
from agw_worker.sealing import Sealer


def main() -> None:
    settings = get_settings()
    configure_logging(settings.log_level)
    state = build_state(settings)
    state.registry.sync(state.engine)
    sealer = Sealer(
        engine=state.engine,
        writer=EvidenceWriter(),
        crash=state.crash,
        max_events=settings.epoch_max_events,
        max_age_seconds=settings.epoch_max_age_seconds,
    )
    runner = BackgroundRunner(
        state.executor,
        state.reconciler,
        poll_seconds=min(settings.executor_poll_seconds, settings.sealer_interval_seconds),
        reconcile_seconds=settings.reconciler_interval_seconds,
        periodic=[(settings.sealer_interval_seconds, sealer.tick)],
    )
    signal.signal(signal.SIGTERM, lambda *_: runner.stop())
    try:
        runner.run_forever()
    except KeyboardInterrupt:
        runner.stop()


if __name__ == "__main__":
    main()
