"""Operational Prometheus metrics (ADR-0026). Labels are bounded enums only: no tenant ids,
agent ids, tool arguments or payloads ever become label values.

Gateway process: ``agw_risk_decisions_total{level, effect}``.
Worker process (sealer): pending events by level, oldest unsealed age, epochs by seal reason.
"""

from __future__ import annotations

from typing import Final

from prometheus_client import Counter, Gauge

LEVELS: Final = ("LOW", "MEDIUM", "HIGH", "CRITICAL")

RISK_DECISIONS: Final = Counter(
    "agw_risk_decisions_total",
    "Policy decisions by risk level and effect",
    ["level", "effect"],
)
PENDING_EVENTS: Final = Gauge(
    "agw_sealer_pending_events",
    "Unsealed evidence events across tenants, by the risk level of their action",
    ["level"],
)
OLDEST_UNSEALED_AGE: Final = Gauge(
    "agw_sealer_oldest_unsealed_age_seconds",
    "Age of the oldest unsealed non-receipt evidence event across tenants",
)
EPOCHS_SEALED: Final = Counter(
    "agw_epochs_sealed_total",
    "Epochs sealed, by seal reason",
    ["seal_reason"],
)

# Phase 5 (ADR-0027). ``result`` is a fixed code set (AUTHORIZED or a denial reason code).
APPROVAL_DECISIONS: Final = Counter(
    "agw_approval_decisions_total",
    "Approver decisions recorded, by decision",
    ["decision"],
)
APPROVAL_AUTHORIZATIONS: Final = Counter(
    "agw_approval_authorizations_total",
    "Dispatch-time approval revalidations, by result",
    ["result"],
)
APPROVALS_EXPIRED: Final = Counter(
    "agw_approvals_expired_total",
    "Approvals expired by the sweeper or at decision time",
)

# Phase 6 (ADR-0028). Anchor statuses and error kinds are fixed code sets.
ANCHOR_TRANSITIONS: Final = Counter(
    "agw_anchor_transitions_total",
    "Anchor state transitions, by new status",
    ["status"],
)
ANCHOR_RPC_ERRORS: Final = Counter(
    "agw_anchor_rpc_errors_total",
    "Anchor worker ticks aborted by an RPC error (retried with backoff)",
)
ANCHOR_RESUBMISSIONS: Final = Counter(
    "agw_anchor_resubmissions_total",
    "Byte-identical re-broadcasts of an anchor transaction (dropped tx, reorg, restart)",
    ["reason"],
)
ANCHOR_EQUIVOCATIONS: Final = Counter(
    "agw_anchor_equivocations_total",
    "Chain already holds a DIFFERENT root for an epoch (recorder halted)",
)
ANCHOR_OLDEST_UNANCHORED_AGE: Final = Gauge(
    "agw_anchor_oldest_unanchored_age_seconds",
    "Age since sealing of the oldest epoch not yet FINALIZED on-chain",
)
ANCHOR_BACKLOG_ALERT: Final = Gauge(
    "agw_anchor_backlog_alert",
    "1 while the oldest unanchored epoch exceeds AGW_ANCHOR_ALERT_AGE_SECONDS",
)
ANCHOR_GATE: Final = Counter(
    "agw_anchor_gate_total",
    "CRITICAL pre-action anchoring gate outcomes",
    ["result"],  # RELEASED | ANCHOR_TIMEOUT
)
