"""Risk engine v2 (ADR-0026, Paper A risk-based evidence selection).

Pure: no I/O, clock, randomness or model calls. The policy is data (TOML -> ``RiskPolicy``),
identified by its canonical digest; ``evaluate`` is a deterministic function of its inputs.
"""

from agw_gateway.risk.engine import (
    ENGINE_VERSION,
    FactorValue,
    RequestContext,
    RiskLevel,
    RiskResult,
    build_context,
    evaluate,
)
from agw_gateway.risk.policy import (
    RiskPolicy,
    RiskPolicyLoadError,
    load_risk_policy_canonical,
    load_risk_policy_toml,
)

__all__ = [
    "ENGINE_VERSION",
    "FactorValue",
    "RequestContext",
    "RiskLevel",
    "RiskPolicy",
    "RiskPolicyLoadError",
    "RiskResult",
    "build_context",
    "evaluate",
    "load_risk_policy_canonical",
    "load_risk_policy_toml",
]
