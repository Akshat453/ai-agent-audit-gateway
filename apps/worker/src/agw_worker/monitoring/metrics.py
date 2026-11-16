"""Monitor metrics (Phase 9). Bounded labels only (result / alert kind): no tenant, ids or
content (ADR-0026 metric rules). Gauges are the values of the most recent tenant checked."""

from __future__ import annotations

from prometheus_client import Counter, Gauge

MONITOR_RUNS = Counter("agw_monitor_runs_total", "Monitor verification runs", ["result"])
MONITOR_ALERTS = Counter("agw_monitor_alerts_total", "Monitor alerts delivered", ["kind"])
MONITOR_OLDEST_UNSEALED = Gauge(
    "agw_monitor_oldest_unsealed_seconds", "Age of the oldest event not yet in an epoch"
)
MONITOR_OLDEST_UNANCHORED = Gauge(
    "agw_monitor_oldest_unanchored_seconds", "Age of the oldest sealed epoch not finalized"
)
MONITOR_OUTCOME_UNKNOWN = Gauge(
    "agw_monitor_outcome_unknown_actions", "Actions in OUTCOME_UNKNOWN awaiting reconciliation"
)
MONITOR_OLDEST_PENDING_APPROVAL = Gauge(
    "agw_monitor_oldest_pending_approval_seconds", "Age of the oldest pending approval"
)
