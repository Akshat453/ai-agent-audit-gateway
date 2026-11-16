"""Header field builders shared by tx1 and the approval authorization tx."""

from __future__ import annotations

from typing import Any

from agw_gateway.policies import Decision


def policy_evaluated_fields(tool: dict[str, str], env: str, decision: Decision) -> dict[str, Any]:
    return {
        "tool": tool,
        "env": env,
        "risk": decision.risk.to_record(),
        "policy": {
            "id": decision.policy_id,
            "ver": decision.policy_version,
            "effect": decision.effect,
            "rules": list(decision.matched_rule_ids),
            "reasons": [str(r) for r in decision.reasons],
            "controls": list(decision.control_ids),
            "ev": decision.engine_version,
        },
    }
