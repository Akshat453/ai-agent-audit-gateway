"""Gateway-side anchoring pieces (Phase 6, ADR-0028): recorder identity, finality levels and
the CRITICAL pre-action anchoring gate. No chain client here: web3 lives in agw_worker."""

from agw_gateway.anchoring.gate import AnchorGate, GatePolicy
from agw_gateway.anchoring.identity import Finality, recorder_id

__all__ = ["AnchorGate", "Finality", "GatePolicy", "recorder_id"]
